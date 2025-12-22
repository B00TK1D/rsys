#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"
#include "src/rsys/intercept/rsys_intercept_limits.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>

#include <sys/eventfd.h>
int rsys_intercept_fs(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  int *cwd_is_local = ctx->cwd_is_local;
  int *cwd_remote_known = ctx->cwd_remote_known;
  char *cwd_remote = ctx->cwd_remote;
  size_t cwd_remote_sz = ctx->cwd_remote_sz;
  struct pending_sys *pend = ctx->pend;

  // chdir(path)
  if (nr == __NR_chdir) {
    uintptr_t path_addr = (uintptr_t)regs->rdi;
    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    // If it targets a local mount, rewrite and run locally.
    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rdi)) {
      (void)rsys_ptrace_setregs_or_die(pid, regs);
      if (cwd_is_local) *cwd_is_local = 1;
      return 0;
    }

    // Otherwise, change cwd on the remote side. We send an absolute, normalized
    // path so correctness does not depend on rsysd's own cwd.
    char abs_cwd[4096];
    if (path[0] == '/') {
      if (normalize_abs_path(abs_cwd, sizeof(abs_cwd), path) < 0) {
        strncpy(abs_cwd, path, sizeof(abs_cwd));
        abs_cwd[sizeof(abs_cwd) - 1] = '\0';
      }
    } else if (cwd_remote_known && *cwd_remote_known && cwd_remote && cwd_remote[0] == '/') {
      if (join_cwd_and_path(abs_cwd, sizeof(abs_cwd), cwd_remote, path) < 0) {
        strncpy(abs_cwd, path, sizeof(abs_cwd));
        abs_cwd[sizeof(abs_cwd) - 1] = '\0';
      }
    } else {
      // Unknown base: best-effort send as-is.
      strncpy(abs_cwd, path, sizeof(abs_cwd));
      abs_cwd[sizeof(abs_cwd) - 1] = '\0';
    }

    uint32_t plen = (uint32_t)strlen(abs_cwd) + 1;
    uint32_t req_len = 4 + plen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, plen);
    memcpy(req + 4, abs_cwd, plen);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_CHDIR, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    if (cwd_is_local && rax == 0) *cwd_is_local = 0;
    if (rax == 0 && cwd_remote && cwd_remote_sz) {
      // Update tracked remote cwd only on success.
      if (abs_cwd[0] == '/' && normalize_abs_path(abs_cwd, sizeof(abs_cwd), abs_cwd) == 0) {
        strncpy(cwd_remote, abs_cwd, cwd_remote_sz);
        cwd_remote[cwd_remote_sz - 1] = '\0';
        if (cwd_remote_known) *cwd_remote_known = 1;
      }
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // fchdir(fd)
  if (nr == __NR_fchdir) {
    int fd_local = (int)regs->rdi;
    int fd_remote = rsys_map_fd(ctx, fd_local);
    if (fd_remote < 0) {
      // local fchdir; assume local mode afterwards
      if (cwd_is_local) *cwd_is_local = 1;
      return 0;
    }

    uint8_t req[8];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_FCHDIR, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);
    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    if (cwd_is_local && rax == 0) *cwd_is_local = 0;
    if (cwd_remote_known && rax == 0) *cwd_remote_known = 0;

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // openat(dirfd, pathname, flags, mode)
  if (nr == __NR_openat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int mode = (int)regs->r10;

    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0; // let it run locally with rewritten pathname
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0; // let it run locally on failure

    // /proc fd-walks must remain local (and /proc/<virtpid>/fd... must be rewritten to /proc/self/fd...).
    {
      int pfl = rsys_procfd_force_local(ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0; // local relative
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;                       // local absolute by policy

    vlog("[rsys] openat(dirfd=%d, path=%s, flags=0x%x, mode=0%o) -> remote\n", dirfd_local, path, flags, mode);

    if (g_read_only) {
      int accmode = flags & O_ACCMODE;
      int wants_write = (accmode == O_WRONLY) || (accmode == O_RDWR);
      int wants_create = (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
#ifdef O_TMPFILE
      // NOTE: O_TMPFILE includes O_DIRECTORY, so (flags & O_TMPFILE) != 0 would
      // incorrectly match normal directory opens. Only block if the full
      // O_TMPFILE bit pattern is present.
      wants_create = wants_create || ((flags & O_TMPFILE) == O_TMPFILE);
#endif
      if (wants_write || wants_create) {
        return rsys_deny_syscall(ctx, nr, EPERM);
      }
    }

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) {
      // dirfd not remote-mapped; keep local
      return 0;
    }

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 28 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_s64(req + 16, (int64_t)mode);
    rsys_put_u32(req + 24, path_len);
    memcpy(req + 28, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_OPENAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);

    int64_t rax = raw_sys_ret(rr, eno);
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->close_local_fd = -1;

    if (rr >= 0) {
      // Create a real local placeholder FD (small, non-colliding) so userland
      // can safely use poll/select/FD_SET, etc. We'll map it to the remote FD on exit.
      pend->has_set_rax = 0; // keep eventfd2 return value
      pend->map_fd_on_exit = 1;
      pend->map_remote_fd = (int)rr;

      regs->orig_rax = __NR_eventfd2;
      regs->rdi = 0; // initval
      regs->rsi = (uint64_t)EFD_CLOEXEC;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] openat -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=<eventfd2>\n", rr, eno);
    } else {
      // Failure: replace syscall with harmless getpid and set error on exit.
      pend->has_set_rax = 1;
      pend->set_rax = rax;
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] openat -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=%" PRId64 "\n", rr, eno, rax);
    }
    return 1;
  }


  // newfstatat(dirfd, pathname, statbuf, flags) -- glibc stat/lstat
  if (nr == __NR_newfstatat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    uintptr_t st_addr = (uintptr_t)regs->rdx;
    int flags = (int)regs->r10;

    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] newfstatat(dirfd=%d, path=%s, flags=0x%x) -> remote\n", dirfd_local, path, flags);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;

    uint32_t req_len = 20 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, path_len);
    memcpy(req + 20, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_NEWFSTATAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] newfstatat -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, st_addr, data, data_len);
    return 1;
  }

  // fstat(fd, statbuf)
  if (nr == __NR_fstat) {
    int fd_local = (int)regs->rdi;
    uintptr_t st_addr = (uintptr_t)regs->rsi;

    int fd_remote = rsys_map_fd(ctx, fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] fstat(fd=%d -> remote_fd=%d)\n", fd_local, fd_remote);

    uint8_t req[8];
    rsys_put_s64(req + 0, (int64_t)fd_remote);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_FSTAT, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] fstat -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, st_addr, data, data_len);
    return 1;
  }

  // statx(dirfd, pathname, flags, mask, statxbuf)
  if (nr == __NR_statx) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    unsigned int mask = (unsigned int)regs->r10;
    uintptr_t stx_addr = (uintptr_t)regs->r8;

    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] statx(dirfd=%d, path=%s, flags=0x%x, mask=0x%x) -> remote\n", dirfd_local, path, flags, mask);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;

    uint32_t req_len = 24 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, mask);
    rsys_put_u32(req + 20, path_len);
    memcpy(req + 24, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_STATX, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] statx -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, stx_addr, data, data_len);
    return 1;
  }

  // getdents64(fd, dirp, count)
  if (nr == __NR_getdents64) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;

    int fd_remote = rsys_map_fd(ctx, fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] getdents64(fd=%d -> remote_fd=%d, count=%zu)\n", fd_local, fd_remote, count);

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)count);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_GETDENTS64, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] getdents64 -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    return 1;
  }

  // access(pathname, mode)
  if (nr == __NR_access) {
    uintptr_t path_addr = (uintptr_t)regs->rdi;
    int mode = (int)regs->rsi;

    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rdi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(ctx, path_addr, (uintptr_t *)&regs->rdi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] access(path=%s, mode=0x%x) -> remote\n", path, mode);

    uint32_t path_len = (uint32_t)strlen(path) + 1;

    uint32_t req_len = 8 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, (uint32_t)mode);
    rsys_put_u32(req + 4, path_len);
    memcpy(req + 8, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_ACCESS, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] access -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // readlinkat(dirfd, pathname, buf, bufsz)
  if (nr == __NR_readlinkat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    uintptr_t buf_addr = (uintptr_t)regs->rdx;
    size_t bufsz = (size_t)regs->r10;

    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] readlinkat(dirfd=%d, path=%s, bufsz=%zu) -> remote\n", dirfd_local, path, bufsz);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;

    uint32_t req_len = 16 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_u32(req + 8, (uint32_t)bufsz);
    rsys_put_u32(req + 12, path_len);
    memcpy(req + 16, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_READLINKAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] readlinkat -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    return 1;
  }

  // unlinkat(dirfd, pathname, flags)
  if (nr == __NR_unlinkat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;

    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] unlinkat(dirfd=%d, path=%s, flags=0x%x) -> remote\n", dirfd_local, path, flags);

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
    }

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 20 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, path_len);
    memcpy(req + 20, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_UNLINKAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] unlinkat -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // mkdirat(dirfd, pathname, mode)
  if (nr == __NR_mkdirat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int mode = (int)regs->rdx;

    if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] mkdirat(dirfd=%d, path=%s, mode=0%o) -> remote\n", dirfd_local, path, mode);

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
    }

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 20 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)mode);
    rsys_put_u32(req + 16, path_len);
    memcpy(req + 20, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_MKDIRAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] mkdirat -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
  if (nr == __NR_renameat2) {
    int olddirfd_local = (int)regs->rdi;
    uintptr_t oldp_addr = (uintptr_t)regs->rsi;
    int newdirfd_local = (int)regs->rdx;
    uintptr_t newp_addr = (uintptr_t)regs->r10;
    unsigned int flags = (unsigned int)regs->r8;

    int remapped = 0;
    if (oldp_addr) remapped |= rsys_maybe_remap_path(ctx, oldp_addr, (uintptr_t *)&regs->rsi);
    if (newp_addr) remapped |= rsys_maybe_remap_path(ctx, newp_addr, (uintptr_t *)&regs->r10);
    if (remapped) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char oldp[4096];
    char newp[4096];
    if (rsys_read_cstring(pid, oldp_addr, oldp, sizeof(oldp)) < 0) return 0;
    if (rsys_read_cstring(pid, newp_addr, newp, sizeof(newp)) < 0) return 0;

    if ((oldp[0] != '/' || newp[0] != '/') && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(oldp, sizeof(oldp), cwd_is_local, cwd_remote_known, cwd_remote);
    maybe_make_remote_abs_path(newp, sizeof(newp), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, oldp, sizeof(oldp));
    rsys_rewrite_proc_self_path(ctx, newp, sizeof(newp));
    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] renameat2(old=%s, new=%s, flags=0x%x) -> remote\n", oldp, newp, flags);

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
    }

    int olddirfd_remote = (olddirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, olddirfd_local);
    int newdirfd_remote = (newdirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, newdirfd_local);
    if (olddirfd_local != AT_FDCWD && olddirfd_remote < 0) return 0;
    if (newdirfd_local != AT_FDCWD && newdirfd_remote < 0) return 0;

    uint32_t old_len = (uint32_t)strlen(oldp) + 1;
    uint32_t new_len = (uint32_t)strlen(newp) + 1;
    uint32_t req_len = 32 + old_len + new_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)olddirfd_remote);
    rsys_put_s64(req + 8, (int64_t)newdirfd_remote);
    rsys_put_s64(req + 16, (int64_t)flags);
    rsys_put_u32(req + 24, old_len);
    rsys_put_u32(req + 28, new_len);
    memcpy(req + 32, oldp, old_len);
    memcpy(req + 32 + old_len, newp, new_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RENAMEAT2, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] renameat2 -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

#ifdef __NR_renameat
  // renameat(olddirfd, oldpath, newdirfd, newpath) -> forwarded via renameat2 with flags=0
  if (nr == __NR_renameat) {
    int olddirfd_local = (int)regs->rdi;
    uintptr_t oldp_addr = (uintptr_t)regs->rsi;
    int newdirfd_local = (int)regs->rdx;
    uintptr_t newp_addr = (uintptr_t)regs->r10;

    int remapped = 0;
    if (oldp_addr) remapped |= rsys_maybe_remap_path(ctx, oldp_addr, (uintptr_t *)&regs->rsi);
    if (newp_addr) remapped |= rsys_maybe_remap_path(ctx, newp_addr, (uintptr_t *)&regs->r10);
    if (remapped) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char oldp[4096];
    char newp[4096];
    if (rsys_read_cstring(pid, oldp_addr, oldp, sizeof(oldp)) < 0) return 0;
    if (rsys_read_cstring(pid, newp_addr, newp, sizeof(newp)) < 0) return 0;

    if ((oldp[0] != '/' || newp[0] != '/') && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(oldp, sizeof(oldp), cwd_is_local, cwd_remote_known, cwd_remote);
    maybe_make_remote_abs_path(newp, sizeof(newp), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, oldp, sizeof(oldp));
    rsys_rewrite_proc_self_path(ctx, newp, sizeof(newp));
    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] renameat(old=%s, new=%s) -> remote\n", oldp, newp);

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
    }

    int olddirfd_remote = (olddirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, olddirfd_local);
    int newdirfd_remote = (newdirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, newdirfd_local);
    if (olddirfd_local != AT_FDCWD && olddirfd_remote < 0) return 0;
    if (newdirfd_local != AT_FDCWD && newdirfd_remote < 0) return 0;

    uint32_t old_len = (uint32_t)strlen(oldp) + 1;
    uint32_t new_len = (uint32_t)strlen(newp) + 1;
    uint32_t req_len = 32 + old_len + new_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)olddirfd_remote);
    rsys_put_s64(req + 8, (int64_t)newdirfd_remote);
    rsys_put_s64(req + 16, 0); // flags
    rsys_put_u32(req + 24, old_len);
    rsys_put_u32(req + 28, new_len);
    memcpy(req + 32, oldp, old_len);
    memcpy(req + 32 + old_len, newp, new_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RENAMEAT2, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }
#endif

#ifdef __NR_rename
  // rename(oldpath, newpath) -> forwarded via renameat2 with AT_FDCWD and flags=0
  if (nr == __NR_rename) {
    uintptr_t oldp_addr = (uintptr_t)regs->rdi;
    uintptr_t newp_addr = (uintptr_t)regs->rsi;

    int remapped = 0;
    if (oldp_addr) remapped |= rsys_maybe_remap_path(ctx, oldp_addr, (uintptr_t *)&regs->rdi);
    if (newp_addr) remapped |= rsys_maybe_remap_path(ctx, newp_addr, (uintptr_t *)&regs->rsi);
    if (remapped) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char oldp[4096];
    char newp[4096];
    if (rsys_read_cstring(pid, oldp_addr, oldp, sizeof(oldp)) < 0) return 0;
    if (rsys_read_cstring(pid, newp_addr, newp, sizeof(newp)) < 0) return 0;

    if ((oldp[0] != '/' || newp[0] != '/') && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(oldp, sizeof(oldp), cwd_is_local, cwd_remote_known, cwd_remote);
    maybe_make_remote_abs_path(newp, sizeof(newp), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(ctx, oldp, sizeof(oldp));
    rsys_rewrite_proc_self_path(ctx, newp, sizeof(newp));
    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] rename(old=%s, new=%s) -> remote\n", oldp, newp);

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
    }

    uint32_t old_len = (uint32_t)strlen(oldp) + 1;
    uint32_t new_len = (uint32_t)strlen(newp) + 1;
    uint32_t req_len = 32 + old_len + new_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)AT_FDCWD);
    rsys_put_s64(req + 8, (int64_t)AT_FDCWD);
    rsys_put_s64(req + 16, 0); // flags
    rsys_put_u32(req + 24, old_len);
    rsys_put_u32(req + 28, new_len);
    memcpy(req + 32, oldp, old_len);
    memcpy(req + 32 + old_len, newp, new_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RENAMEAT2, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }
#endif

  // utimensat(dirfd, pathname, times[2], flags)
  if (nr == __NR_utimensat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    uintptr_t times_addr = (uintptr_t)regs->rdx;
    int flags = (int)regs->r10;

    if (path_addr != 0) {
      if (rsys_maybe_remap_path(ctx, path_addr, (uintptr_t *)&regs->rsi)) {
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        return 0;
      }
    }

    // Special case: pathname == NULL => operate on dirfd (futimens semantics).
    uint32_t path_len = 0;
    char path[4096];

    int dirfd_remote;
    if (path_addr == 0) {
      dirfd_remote = rsys_map_fd(ctx, dirfd_local);
      if (dirfd_remote < 0) return 0;
    } else {
      if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
      if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
      maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
      if (!should_remote_path(path)) return 0;
      dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(ctx, dirfd_local);
      if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;
      path_len = (uint32_t)strlen(path) + 1;
    }

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
    }

    uint32_t has_times = (times_addr != 0) ? 1u : 0u;
    uint32_t req_len = 24 + path_len + (has_times ? 32u : 0u);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");

    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, has_times);
    rsys_put_u32(req + 20, path_len);
    if (path_len) memcpy(req + 24, path, path_len);

    if (has_times) {
      struct timespec ts[2];
      if (rsys_read_mem(pid, &ts[0], times_addr, sizeof(ts)) < 0) {
        free(req);
        return 0;
      }
      uint8_t *tp = req + 24 + path_len;
      rsys_put_s64(tp + 0, (int64_t)ts[0].tv_sec);
      rsys_put_s64(tp + 8, (int64_t)ts[0].tv_nsec);
      rsys_put_s64(tp + 16, (int64_t)ts[1].tv_sec);
      rsys_put_s64(tp + 24, (int64_t)ts[1].tv_nsec);
    }

    vlog("[rsys] utimensat(dirfd=%d -> remote=%d, path=%s, times=%s, flags=0x%x) -> remote\n", dirfd_local, dirfd_remote,
         path_len ? path : "NULL", has_times ? "set" : "NULL", flags);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_UTIMENSAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    vlog("[rsys] utimensat -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }


  return 0;
}
