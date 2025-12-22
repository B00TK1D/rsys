#define _GNU_SOURCE

#include "src/rsys/rsys_internal.h"
#include "src/rsys/rsys_intercept_ctx.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/close_range.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int64_t raw_sys_ret(int64_t raw_ret, int32_t err_no) {
  if (raw_ret == -1) return -(int64_t)err_no;
  return raw_ret;
}

int intercept_syscall(pid_t pid, struct user_regs_struct *regs, int sock, struct fd_map *fm, struct remote_refs *rrefs,
                             const struct mounts *mnts, int *cwd_is_local, int *cwd_remote_known, char *cwd_remote,
                             size_t cwd_remote_sz, int *virt_ids_known, pid_t *virt_pid, pid_t *virt_tid, pid_t *virt_ppid,
                             pid_t *virt_pgid, pid_t *virt_sid, int *local_base, size_t local_base_n, struct epoll_table *ep,
                             struct pending_sys *pend) {
  long nr = (long)regs->orig_rax;
  struct rsys_intercept_ctx ctx = {
      .pid = pid,
      .regs = regs,
      .sock = sock,
      .fm = fm,
      .rrefs = rrefs,
      .mnts = mnts,
      .cwd_is_local = cwd_is_local,
      .cwd_remote_known = cwd_remote_known,
      .cwd_remote = cwd_remote,
      .cwd_remote_sz = cwd_remote_sz,
      .virt_ids_known = virt_ids_known,
      .virt_pid = virt_pid,
      .virt_tid = virt_tid,
      .virt_ppid = virt_ppid,
      .virt_pgid = virt_pgid,
      .virt_sid = virt_sid,
      .local_base = local_base,
      .local_base_n = local_base_n,
      .ep = ep,
      .pend = pend,
  };

  // Virtualized identity syscalls (pid/tid/ppid/etc) so /proc/self coheres with remote /proc.
  // WARNING: this changes what programs observe, and must be kept consistent with /proc rewriting.
  {
    int vrc = rsys_intercept_virtual_ids(&ctx, nr);
    if (vrc) return vrc;
  }

  // Mitigation: if a program calls kill(getpid(), sig) under pid virtualization,
  // translate the virtual "self" pid/tid back to the real local ones so behavior
  // remains sane (e.g. kill(SIGTERM) terminates the process).
  rsys_intercept_translate_kill_targets(&ctx, nr);

  // Helper: rewrite /proc self-references to match remote pid.
  // Helper: detect and force LOCAL semantics for /proc fd-walks.
  //
  // Programs like OpenSSH walk /proc/self/fd (or /proc/<pid>/fd) to close inherited
  // file descriptors. Under PID virtualization, their <pid> may be the remote pid;
  // forwarding these opens to the remote or rewriting them breaks invariants and can
  // cause the program to close the wrong local fds (leading to POLLNVAL/EBADF).
  //
  // Return values:
  // - 0: not a /proc fd-walk path
  // - 1: is a /proc fd-walk path; keep local; no rewrite needed
  // - 2: is a /proc fd-walk path; keep local; argument rewritten to /proc/self/...
  const uint32_t MAX_BLOB = (1u << 20);   // 1MB per call
  const uint32_t MAX_ADDR = 512;          // sockaddr cap
  const uint32_t MAX_CTRL = 64u * 1024u;  // cmsg cap
  const uint32_t MAX_IOV = 128;           // iov count cap

  // Local mount remapping for absolute path arguments.
  // chdir(path)
  if (nr == __NR_chdir) {
    uintptr_t path_addr = (uintptr_t)regs->rdi;
    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    // If it targets a local mount, rewrite and run locally.
    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rdi)) {
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
    int fd_remote = rsys_map_fd(&ctx, fd_local);
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

    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0; // let it run locally with rewritten pathname
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0; // let it run locally on failure

    // /proc fd-walks must remain local (and /proc/<virtpid>/fd... must be rewritten to /proc/self/fd...).
    {
      int pfl = rsys_procfd_force_local(&ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0; // local relative
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(&ctx, path, sizeof(path));
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
        return rsys_deny_syscall(&ctx, nr, EPERM);
      }
    }

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, dirfd_local);
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

  // close(fd)
  if (nr == __NR_close) {
    int fd_local = (int)regs->rdi;
    int removed_any = 0;
    // Remove ALL mappings for this local fd. Stale duplicate entries can occur if
    // a local fd number is reused and an earlier mapping wasn't fully removed.
    // Duplicates can make rsys_map_fd(&ctx, ) return a stale remote fd and break apps (ssh).
    for (;;) {
      int removed_remote = -1;
      if (fdmap_remove_local(fm, fd_local, &removed_remote) < 0) break;
      removed_any = 1;
      if (removed_remote < 0) continue;

      uint32_t refs = rrefs_get(rrefs, removed_remote);
      if (refs == 0) continue;
      uint32_t new_refs = rrefs_dec(rrefs, removed_remote);

      // Last reference: close on remote (best-effort).
      if (new_refs == 0) {
        vlog("[rsys] close(fd=%d -> remote_fd=%d) -> remote\n", fd_local, removed_remote);
        uint8_t req[8];
        rsys_put_s64(req + 0, (int64_t)removed_remote);
        struct rsys_resp resp;
        uint8_t *data = NULL;
        uint32_t data_len = 0;
        (void)rsys_call(sock, RSYS_REQ_CLOSE, req, sizeof(req), &resp, &data, &data_len);
        free(data);
      }
    }

    // If this was not a remote-mapped fd, it is a pure local close; log small fds for debugging.
    if (!removed_any && g_verbose && fd_local >= 0 && fd_local <= 16) {
      vlog("[rsys] close(fd=%d) -> local\n", fd_local);
    }

    // If this is a local epoll fd we are tracking, remove its virtual state.
    if (!removed_any && ep) {
      epoll_table_del(ep, fd_local);
    }

    // Clear local alias tracking for closed fds.
    if (local_base && fd_local >= 0 && (size_t)fd_local < local_base_n) {
      local_base[fd_local] = -1;
    }

    // Let the real close(2) run so placeholder FDs are actually closed.
    return 0;
  }

#ifdef __NR_close_range
  // close_range(first, last, flags)
  if (nr == __NR_close_range) {
    unsigned int first = (unsigned int)regs->rdi;
    unsigned int last = (unsigned int)regs->rsi;
    unsigned int flags = (unsigned int)regs->rdx;
    vlog("[rsys] close_range(first=%u, last=%u, flags=0x%x)\n", first, last, flags);

    // If we're just setting CLOEXEC, the fds remain open; keep mappings.
    if ((flags & CLOSE_RANGE_CLOEXEC) != 0) return 0;

    // Remove mappings for any remote-mapped fds that will be closed.
    for (size_t i = 0; i < fm->n;) {
      int lfd = fm->v[i].local_fd;
      if (lfd >= 0 && (unsigned int)lfd >= first && (unsigned int)lfd <= last) {
        int removed_remote = -1;
        int lfd_to_remove = lfd;
        if (fdmap_remove_local(fm, lfd_to_remove, &removed_remote) == 0) {
          if (removed_remote >= 0) {
            if (rrefs_dec(rrefs, removed_remote) == 0) remote_close_best_effort(sock, removed_remote);
          }
        }
        // fdmap_remove_local compacts array, so don't increment i.
        continue;
      }
      i++;
    }

    // Let kernel perform the actual close_range on local placeholder fds.
    if (local_base && (flags & CLOSE_RANGE_CLOEXEC) == 0) {
      unsigned int stop = last;
      if (stop >= local_base_n) stop = (unsigned int)(local_base_n - 1);
      for (unsigned int fd = first; fd <= stop; fd++) local_base[fd] = -1;
    }
    return 0;
  }
#endif

  // read(fd, buf, count)
  if (nr == __NR_read) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0; // local read

    vlog("[rsys] read(fd=%d -> remote_fd=%d, count=%zu)\n", fd_local, fd_remote, count);

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)count);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_READ, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    vlog("[rsys] read -> raw_ret=%" PRId64 " errno=%d copy_bytes=%u rax=%" PRId64 "\n", rr, eno, data_len, rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    pend->close_local_fd = -1;
    return 1;
  }

  // write(fd, buf, count)
  if (nr == __NR_write) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0; // local write (stdout/stderr)

    if (g_read_only) {
      return rsys_deny_syscall(&ctx, nr, EPERM);
    }

    vlog("[rsys] write(fd=%d -> remote_fd=%d, count=%zu)\n", fd_local, fd_remote, count);

    uint32_t dlen = (count > (1u << 20)) ? (1u << 20) : (uint32_t)count;
    uint32_t req_len = 12 + dlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");

    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, dlen);
    if (rsys_read_mem(pid, req + 12, buf_addr, dlen) < 0) {
      free(req);
      return 0;
    }

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_WRITE, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] write -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // pread64(fd, buf, count, offset)
  if (nr == __NR_pread64) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;
    int64_t off = (int64_t)regs->r10;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] pread64(fd=%d -> remote_fd=%d, count=%zu, off=%" PRId64 ")\n", fd_local, fd_remote, count, off);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)count);
    rsys_put_s64(req + 16, off);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_PREAD64, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] pread64 -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    return 1;
  }

  // pwrite64(fd, buf, count, offset)
  if (nr == __NR_pwrite64) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;
    int64_t off = (int64_t)regs->r10;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    if (g_read_only) {
      return rsys_deny_syscall(&ctx, nr, EPERM);
    }

    vlog("[rsys] pwrite64(fd=%d -> remote_fd=%d, count=%zu, off=%" PRId64 ")\n", fd_local, fd_remote, count, off);

    uint32_t dlen = (count > (1u << 20)) ? (1u << 20) : (uint32_t)count;
    uint32_t req_len = 20 + dlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, off);
    rsys_put_u32(req + 16, dlen);
    if (rsys_read_mem(pid, req + 20, buf_addr, dlen) < 0) {
      free(req);
      return 0;
    }

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_PWRITE64, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] pwrite64 -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // lseek(fd, off, whence)
  if (nr == __NR_lseek) {
    int fd_local = (int)regs->rdi;
    int64_t off = (int64_t)regs->rsi;
    int whence = (int)regs->rdx;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] lseek(fd=%d -> remote_fd=%d, off=%" PRId64 ", whence=%d)\n", fd_local, fd_remote, off, whence);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, off);
    rsys_put_s64(req + 16, (int64_t)whence);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_LSEEK, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] lseek -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // newfstatat(dirfd, pathname, statbuf, flags) -- glibc stat/lstat
  if (nr == __NR_newfstatat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    uintptr_t st_addr = (uintptr_t)regs->rdx;
    int flags = (int)regs->r10;

    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(&ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(&ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] newfstatat(dirfd=%d, path=%s, flags=0x%x) -> remote\n", dirfd_local, path, flags);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, dirfd_local);
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

    int fd_remote = rsys_map_fd(&ctx, fd_local);
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

    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(&ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(&ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] statx(dirfd=%d, path=%s, flags=0x%x, mask=0x%x) -> remote\n", dirfd_local, path, flags, mask);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, dirfd_local);
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

    int fd_remote = rsys_map_fd(&ctx, fd_local);
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

    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rdi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(&ctx, path_addr, (uintptr_t *)&regs->rdi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(&ctx, path, sizeof(path));
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

    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    {
      int pfl = rsys_procfd_force_local(&ctx, path_addr, (uintptr_t *)&regs->rsi);
      if (pfl) {
        if (pfl == 2) {
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        }
        return 0;
      }
    }

    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rsys_rewrite_proc_self_path(&ctx, path, sizeof(path));
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] readlinkat(dirfd=%d, path=%s, bufsz=%zu) -> remote\n", dirfd_local, path, bufsz);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, dirfd_local);
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

    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rsi)) {
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
      return rsys_deny_syscall(&ctx, nr, EPERM);
    }

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, dirfd_local);
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

    if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rsi)) {
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
      return rsys_deny_syscall(&ctx, nr, EPERM);
    }

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, dirfd_local);
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
    if (oldp_addr) remapped |= rsys_maybe_remap_path(&ctx, oldp_addr, (uintptr_t *)&regs->rsi);
    if (newp_addr) remapped |= rsys_maybe_remap_path(&ctx, newp_addr, (uintptr_t *)&regs->r10);
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
    rsys_rewrite_proc_self_path(&ctx, oldp, sizeof(oldp));
    rsys_rewrite_proc_self_path(&ctx, newp, sizeof(newp));
    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] renameat2(old=%s, new=%s, flags=0x%x) -> remote\n", oldp, newp, flags);

    if (g_read_only) {
      return rsys_deny_syscall(&ctx, nr, EPERM);
    }

    int olddirfd_remote = (olddirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, olddirfd_local);
    int newdirfd_remote = (newdirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, newdirfd_local);
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
    if (oldp_addr) remapped |= rsys_maybe_remap_path(&ctx, oldp_addr, (uintptr_t *)&regs->rsi);
    if (newp_addr) remapped |= rsys_maybe_remap_path(&ctx, newp_addr, (uintptr_t *)&regs->r10);
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
    rsys_rewrite_proc_self_path(&ctx, oldp, sizeof(oldp));
    rsys_rewrite_proc_self_path(&ctx, newp, sizeof(newp));
    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] renameat(old=%s, new=%s) -> remote\n", oldp, newp);

    if (g_read_only) {
      return rsys_deny_syscall(&ctx, nr, EPERM);
    }

    int olddirfd_remote = (olddirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, olddirfd_local);
    int newdirfd_remote = (newdirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, newdirfd_local);
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
    if (oldp_addr) remapped |= rsys_maybe_remap_path(&ctx, oldp_addr, (uintptr_t *)&regs->rdi);
    if (newp_addr) remapped |= rsys_maybe_remap_path(&ctx, newp_addr, (uintptr_t *)&regs->rsi);
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
    rsys_rewrite_proc_self_path(&ctx, oldp, sizeof(oldp));
    rsys_rewrite_proc_self_path(&ctx, newp, sizeof(newp));
    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] rename(old=%s, new=%s) -> remote\n", oldp, newp);

    if (g_read_only) {
      return rsys_deny_syscall(&ctx, nr, EPERM);
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
      if (rsys_maybe_remap_path(&ctx, path_addr, (uintptr_t *)&regs->rsi)) {
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        return 0;
      }
    }

    // Special case: pathname == NULL => operate on dirfd (futimens semantics).
    uint32_t path_len = 0;
    char path[4096];

    int dirfd_remote;
    if (path_addr == 0) {
      dirfd_remote = rsys_map_fd(&ctx, dirfd_local);
      if (dirfd_remote < 0) return 0;
    } else {
      if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
      if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
      maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
      if (!should_remote_path(path)) return 0;
      dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : rsys_map_fd(&ctx, dirfd_local);
      if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;
      path_len = (uint32_t)strlen(path) + 1;
    }

    if (g_read_only) {
      return rsys_deny_syscall(&ctx, nr, EPERM);
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

  // uname(buf)
  if (nr == __NR_uname) {
    uintptr_t u_addr = (uintptr_t)regs->rdi;
    vlog("[rsys] uname() -> remote\n");

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_UNAME, NULL, 0, &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len != (uint32_t)sizeof(struct utsname)) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        (void)pending_add_out(pend, u_addr, data, data_len);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // sethostname(name, len)
  if (nr == __NR_sethostname || nr == __NR_setdomainname) {
    uintptr_t name_addr = (uintptr_t)regs->rdi;
    uint32_t nlen = (uint32_t)regs->rsi;
    if (nlen > 4096) nlen = 4096;
    uint8_t *name = NULL;
    if (name_addr && nlen) {
      name = (uint8_t *)malloc(nlen);
      if (!name) die("malloc");
      if (rsys_read_mem(pid, name, name_addr, nlen) < 0) {
        free(name);
        return 0;
      }
    } else {
      nlen = 0;
    }

    uint32_t req_len = 4 + nlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, nlen);
    if (nlen) memcpy(req + 4, name, nlen);
    free(name);

    uint16_t mtype = (nr == __NR_sethostname) ? RSYS_REQ_SETHOSTNAME : RSYS_REQ_SETDOMAINNAME;
    vlog("[rsys] %s(len=%u) -> remote\n", (nr == __NR_sethostname) ? "sethostname" : "setdomainname", nlen);

    if (g_read_only) {
      return rsys_deny_syscall(&ctx, nr, EPERM);
    }

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, mtype, req, req_len, &resp, &data, &data_len) < 0) {
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

  // socket(domain, type, protocol)
  if (nr == __NR_socket) {
    int domain = (int)regs->rdi;
    int type = (int)regs->rsi;
    int protocol = (int)regs->rdx;

    vlog("[rsys] socket(domain=%d, type=%d, proto=%d) -> remote\n", domain, type, protocol);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)domain);
    rsys_put_s64(req + 8, (int64_t)type);
    rsys_put_s64(req + 16, (int64_t)protocol);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SOCKET, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->close_local_fd = -1;

    if (rr >= 0) {
      pend->has_set_rax = 0;
      pend->map_fd_on_exit = 1;
      pend->map_remote_fd = (int)rr;

      regs->orig_rax = __NR_eventfd2;
      regs->rdi = 0;
      regs->rsi = (uint64_t)EFD_CLOEXEC;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] socket -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=<eventfd2>\n", rr, eno);
    } else {
      pend->has_set_rax = 1;
      pend->set_rax = rax;
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] socket -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=%" PRId64 "\n", rr, eno, rax);
    }
    return 1;
  }

  // socketpair(domain, type, protocol, sv[2])
  if (nr == __NR_socketpair) {
    int domain = (int)regs->rdi;
    int type = (int)regs->rsi;
    int protocol = (int)regs->rdx;
    uintptr_t sv_addr = (uintptr_t)regs->r10;

    vlog("[rsys] socketpair(domain=%d, type=%d, proto=%d) -> remote\n", domain, type, protocol);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)domain);
    rsys_put_s64(req + 8, (int64_t)type);
    rsys_put_s64(req + 16, (int64_t)protocol);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SOCKETPAIR, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len != 16) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        int64_t rfd0 = rsys_get_s64(data + 0);
        int64_t rfd1 = rsys_get_s64(data + 8);
        free(data);
        // Allocate two local placeholder FDs via pipe2(), then map them to the remote FDs on exit.
        // We use pipe2 because it returns two real FDs to the tracee.
        pend->has_set_rax = 0; // keep pipe2 return value (0)
        pend->map_fd_pair_on_exit = 1;
        pend->map_remote_fd0 = (int)rfd0;
        pend->map_remote_fd1 = (int)rfd1;
        pend->map_pair_addr = sv_addr;

        int pflags = 0;
#ifdef SOCK_CLOEXEC
        if (type & SOCK_CLOEXEC) pflags |= O_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
        if (type & SOCK_NONBLOCK) pflags |= O_NONBLOCK;
#endif
        regs->orig_rax = __NR_pipe2;
        regs->rdi = (uint64_t)sv_addr;
        regs->rsi = (uint64_t)pflags;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        return 1;
      }
    } else {
      free(data);
    }
    return 1;
  }

  // bind(fd, addr, addrlen)
  if (nr == __NR_bind) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uint32_t addrlen = (uint32_t)regs->rdx;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    if (addrlen > MAX_ADDR) addrlen = MAX_ADDR;
    uint8_t *addr = NULL;
    if (addr_addr && addrlen) {
      addr = (uint8_t *)malloc(addrlen);
      if (!addr) die("malloc");
      if (rsys_read_mem(pid, addr, addr_addr, addrlen) < 0) {
        free(addr);
        return 0;
      }
    }

    uint32_t req_len = 12 + addrlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, addrlen);
    if (addrlen) memcpy(req + 12, addr, addrlen);
    free(addr);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_BIND, req, req_len, &resp, &data, &data_len) < 0) {
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

  // listen(fd, backlog)
  if (nr == __NR_listen) {
    int fd_local = (int)regs->rdi;
    int backlog = (int)regs->rsi;
    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)backlog);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_LISTEN, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
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

  // connect(fd, addr, addrlen)
  if (nr == __NR_connect) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uint32_t addrlen = (uint32_t)regs->rdx;
    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    if (addrlen > MAX_ADDR) addrlen = MAX_ADDR;
    uint8_t *addr = NULL;
    if (addr_addr && addrlen) {
      addr = (uint8_t *)malloc(addrlen);
      if (!addr) die("malloc");
      if (rsys_read_mem(pid, addr, addr_addr, addrlen) < 0) {
        free(addr);
        return 0;
      }
    }

    uint32_t req_len = 12 + addrlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, addrlen);
    if (addrlen) memcpy(req + 12, addr, addrlen);
    free(addr);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_CONNECT, req, req_len, &resp, &data, &data_len) < 0) {
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

  // accept(fd, addr, addrlenp)
  if (nr == __NR_accept || nr == __NR_accept4) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uintptr_t addrlenp = (uintptr_t)regs->rdx;
    int flags = (nr == __NR_accept4) ? (int)regs->r10 : 0;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    uint32_t want_addr = (addr_addr && addrlenp) ? 1u : 0u;
    uint32_t addr_max = 0;
    if (want_addr) {
      uint32_t tmp = 0;
      if (rsys_read_mem(pid, &tmp, addrlenp, sizeof(tmp)) < 0) return 0;
      addr_max = tmp;
      if (addr_max > MAX_ADDR) addr_max = MAX_ADDR;
    }

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, want_addr);
    rsys_put_u32(req + 12, addr_max);
    rsys_put_s64(req + 16, (int64_t)flags);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint16_t mtype = (nr == __NR_accept4) ? RSYS_REQ_ACCEPT4 : RSYS_REQ_ACCEPT;
    if (rsys_call(sock, mtype, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->close_local_fd = -1;

    if (rr >= 0) {
      pend->has_set_rax = 0;
      pend->map_fd_on_exit = 1;
      pend->map_remote_fd = (int)rr;
      regs->orig_rax = __NR_eventfd2;
      regs->rdi = 0;
      regs->rsi = (uint64_t)EFD_CLOEXEC;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    } else {
      pend->has_set_rax = 1;
      pend->set_rax = rax;
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    }

    if (want_addr && rr >= 0) {
      if (data_len < 4) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_addrlen = rsys_get_u32(data + 0);
        if (out_addrlen > addr_max) out_addrlen = addr_max;
        if (4u + out_addrlen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          uint8_t *ab = NULL;
          if (out_addrlen) {
            ab = (uint8_t *)malloc(out_addrlen);
            if (!ab) die("malloc");
            memcpy(ab, data + 4, out_addrlen);
            (void)pending_add_out(pend, addr_addr, ab, out_addrlen);
          }
          uint8_t *lb = (uint8_t *)malloc(4);
          if (!lb) die("malloc");
          memcpy(lb, &out_addrlen, 4);
          (void)pending_add_out(pend, addrlenp, lb, 4);
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // sendto(fd, buf, len, flags, addr, addrlen)
  if (nr == __NR_sendto) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t len = (size_t)regs->rdx;
    int flags = (int)regs->r10;
    uintptr_t addr_addr = (uintptr_t)regs->r8;
    uint32_t addrlen = (uint32_t)regs->r9;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    uint32_t dlen = (len > MAX_BLOB) ? MAX_BLOB : (uint32_t)len;
    uint8_t *data_in = NULL;
    if (dlen) {
      data_in = (uint8_t *)malloc(dlen);
      if (!data_in) die("malloc");
      if (rsys_read_mem(pid, data_in, buf_addr, dlen) < 0) {
        free(data_in);
        return 0;
      }
    }

    if (addrlen > MAX_ADDR) addrlen = MAX_ADDR;
    uint8_t *addr = NULL;
    if (addr_addr && addrlen) {
      addr = (uint8_t *)malloc(addrlen);
      if (!addr) die("malloc");
      if (rsys_read_mem(pid, addr, addr_addr, addrlen) < 0) {
        free(data_in);
        free(addr);
        return 0;
      }
    } else {
      addrlen = 0;
    }

    uint32_t req_len = 24 + dlen + addrlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, dlen);
    rsys_put_u32(req + 20, addrlen);
    if (dlen) memcpy(req + 24, data_in, dlen);
    if (addrlen) memcpy(req + 24 + dlen, addr, addrlen);
    free(data_in);
    free(addr);

    struct rsys_resp resp;
    uint8_t *odata = NULL;
    uint32_t odata_len = 0;
    if (rsys_call(sock, RSYS_REQ_SENDTO, req, req_len, &resp, &odata, &odata_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(odata);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // recvfrom(fd, buf, len, flags, addr, addrlenp)
  if (nr == __NR_recvfrom) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t len = (size_t)regs->rdx;
    int flags = (int)regs->r10;
    uintptr_t addr_addr = (uintptr_t)regs->r8;
    uintptr_t addrlenp = (uintptr_t)regs->r9;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    uint32_t want_addr = (addr_addr && addrlenp) ? 1u : 0u;
    uint32_t addr_max = 0;
    if (want_addr) {
      uint32_t tmp = 0;
      if (rsys_read_mem(pid, &tmp, addrlenp, sizeof(tmp)) < 0) return 0;
      addr_max = tmp;
      if (addr_max > MAX_ADDR) addr_max = MAX_ADDR;
    }

    uint64_t maxlen = (len > MAX_BLOB) ? (uint64_t)MAX_BLOB : (uint64_t)len;
    uint8_t req[32];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)maxlen);
    rsys_put_s64(req + 16, (int64_t)flags);
    rsys_put_u32(req + 24, want_addr);
    rsys_put_u32(req + 28, addr_max);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RECVFROM, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr >= 0) {
      if (data_len < 8) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_dlen = rsys_get_u32(data + 0);
        uint32_t out_alen = rsys_get_u32(data + 4);
        if (8u + out_dlen + out_alen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          if (out_dlen) {
            uint8_t *bb = (uint8_t *)malloc(out_dlen);
            if (!bb) die("malloc");
            memcpy(bb, data + 8, out_dlen);
            (void)pending_add_out(pend, buf_addr, bb, out_dlen);
          }
          if (want_addr) {
            if (out_alen > addr_max) out_alen = addr_max;
            if (out_alen) {
              uint8_t *ab = (uint8_t *)malloc(out_alen);
              if (!ab) die("malloc");
              memcpy(ab, data + 8 + out_dlen, out_alen);
              (void)pending_add_out(pend, addr_addr, ab, out_alen);
            }
            uint8_t *lb = (uint8_t *)malloc(4);
            if (!lb) die("malloc");
            memcpy(lb, &out_alen, 4);
            (void)pending_add_out(pend, addrlenp, lb, 4);
          }
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // shutdown(fd, how)
  if (nr == __NR_shutdown) {
    int fd_local = (int)regs->rdi;
    int how = (int)regs->rsi;
    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)how);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SHUTDOWN, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
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

  // getsockname/getpeername(fd, addr, addrlenp)
  if (nr == __NR_getsockname || nr == __NR_getpeername) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uintptr_t addrlenp = (uintptr_t)regs->rdx;
    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    if (!addr_addr || !addrlenp) return 0;
    uint32_t addr_max = 0;
    if (rsys_read_mem(pid, &addr_max, addrlenp, sizeof(addr_max)) < 0) return 0;
    if (addr_max > MAX_ADDR) addr_max = MAX_ADDR;

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, addr_max);
    rsys_put_u32(req + 12, 0);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint16_t mtype = (nr == __NR_getsockname) ? RSYS_REQ_GETSOCKNAME : RSYS_REQ_GETPEERNAME;
    if (rsys_call(sock, mtype, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len < 4) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_alen = rsys_get_u32(data + 0);
        if (out_alen > addr_max) out_alen = addr_max;
        if (4u + out_alen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          if (out_alen) {
            uint8_t *ab = (uint8_t *)malloc(out_alen);
            if (!ab) die("malloc");
            memcpy(ab, data + 4, out_alen);
            (void)pending_add_out(pend, addr_addr, ab, out_alen);
          }
          uint8_t *lb = (uint8_t *)malloc(4);
          if (!lb) die("malloc");
          memcpy(lb, &out_alen, 4);
          (void)pending_add_out(pend, addrlenp, lb, 4);
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // setsockopt(fd, level, optname, optval, optlen)
  if (nr == __NR_setsockopt) {
    int fd_local = (int)regs->rdi;
    int level = (int)regs->rsi;
    int optname = (int)regs->rdx;
    uintptr_t optval_addr = (uintptr_t)regs->r10;
    uint32_t optlen = (uint32_t)regs->r8;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;
    if (optlen > MAX_CTRL) optlen = MAX_CTRL;

    uint8_t *optval = NULL;
    if (optval_addr && optlen) {
      optval = (uint8_t *)malloc(optlen);
      if (!optval) die("malloc");
      if (rsys_read_mem(pid, optval, optval_addr, optlen) < 0) {
        free(optval);
        return 0;
      }
    } else {
      optlen = 0;
    }

    uint32_t req_len = 28 + optlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)level);
    rsys_put_s64(req + 16, (int64_t)optname);
    rsys_put_u32(req + 24, optlen);
    if (optlen) memcpy(req + 28, optval, optlen);
    free(optval);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SETSOCKOPT, req, req_len, &resp, &data, &data_len) < 0) {
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

  // getsockopt(fd, level, optname, optval, optlenp)
  if (nr == __NR_getsockopt) {
    int fd_local = (int)regs->rdi;
    int level = (int)regs->rsi;
    int optname = (int)regs->rdx;
    uintptr_t optval_addr = (uintptr_t)regs->r10;
    uintptr_t optlenp = (uintptr_t)regs->r8;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;
    if (!optval_addr || !optlenp) return 0;

    uint32_t optlen_max = 0;
    if (rsys_read_mem(pid, &optlen_max, optlenp, sizeof(optlen_max)) < 0) return 0;
    if (optlen_max > MAX_CTRL) optlen_max = MAX_CTRL;

    uint8_t req[28];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)level);
    rsys_put_s64(req + 16, (int64_t)optname);
    rsys_put_u32(req + 24, optlen_max);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_GETSOCKOPT, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len < 4) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_len = rsys_get_u32(data + 0);
        if (out_len > optlen_max) out_len = optlen_max;
        if (4u + out_len != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          if (out_len) {
            uint8_t *ob = (uint8_t *)malloc(out_len);
            if (!ob) die("malloc");
            memcpy(ob, data + 4, out_len);
            (void)pending_add_out(pend, optval_addr, ob, out_len);
          }
          uint8_t *lb = (uint8_t *)malloc(4);
          if (!lb) die("malloc");
          memcpy(lb, &out_len, 4);
          (void)pending_add_out(pend, optlenp, lb, 4);
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // sendmsg(fd, msg, flags)
  if (nr == __NR_sendmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msg_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    struct msghdr mh;
    if (rsys_read_mem(pid, &mh, msg_addr, sizeof(mh)) < 0) return 0;

    uint32_t name_len = (uint32_t)mh.msg_namelen;
    if (name_len > MAX_ADDR) name_len = MAX_ADDR;
    uint32_t ctrl_len = (uint32_t)mh.msg_controllen;
    if (ctrl_len > MAX_CTRL) ctrl_len = MAX_CTRL;
    uint32_t iovcnt = (uint32_t)mh.msg_iovlen;
    if (iovcnt > MAX_IOV) iovcnt = MAX_IOV;

    uint8_t *name = NULL;
    if (mh.msg_name && name_len) {
      name = (uint8_t *)malloc(name_len);
      if (!name) die("malloc");
      if (rsys_read_mem(pid, name, (uintptr_t)mh.msg_name, name_len) < 0) {
        free(name);
        return 0;
      }
    } else {
      name_len = 0;
    }

    uint8_t *ctrl = NULL;
    if (mh.msg_control && ctrl_len) {
      ctrl = (uint8_t *)malloc(ctrl_len);
      if (!ctrl) die("malloc");
      if (rsys_read_mem(pid, ctrl, (uintptr_t)mh.msg_control, ctrl_len) < 0) {
        free(name);
        free(ctrl);
        return 0;
      }
    } else {
      ctrl_len = 0;
    }

    struct iovec *iov = NULL;
    if (mh.msg_iov && iovcnt) {
      iov = (struct iovec *)malloc(iovcnt * sizeof(*iov));
      if (!iov) die("malloc");
      if (rsys_read_mem(pid, iov, (uintptr_t)mh.msg_iov, iovcnt * sizeof(*iov)) < 0) {
        free(name);
        free(ctrl);
        free(iov);
        return 0;
      }
    } else {
      iovcnt = 0;
    }

    uint32_t data_len = 0;
    for (uint32_t i = 0; i < iovcnt; i++) {
      uint64_t add = (uint64_t)iov[i].iov_len;
      if (add > MAX_BLOB) add = MAX_BLOB;
      if (data_len + (uint32_t)add < data_len) break;
      uint64_t newlen = (uint64_t)data_len + add;
      if (newlen > MAX_BLOB) {
        data_len = MAX_BLOB;
        break;
      }
      data_len = (uint32_t)newlen;
    }

    uint8_t *payload_data = NULL;
    if (data_len) {
      payload_data = (uint8_t *)malloc(data_len);
      if (!payload_data) die("malloc");
      uint32_t off = 0;
      for (uint32_t i = 0; i < iovcnt && off < data_len; i++) {
        uint32_t take = (uint32_t)iov[i].iov_len;
        if (take > data_len - off) take = data_len - off;
        if (take && rsys_read_mem(pid, payload_data + off, (uintptr_t)iov[i].iov_base, take) < 0) {
          free(name);
          free(ctrl);
          free(iov);
          free(payload_data);
          return 0;
        }
        off += take;
      }
    }
    free(iov);

    uint32_t req_len = 32 + name_len + ctrl_len + data_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, name_len);
    rsys_put_u32(req + 20, ctrl_len);
    rsys_put_u32(req + 24, data_len);
    rsys_put_u32(req + 28, 0);
    uint32_t o = 32;
    if (name_len) memcpy(req + o, name, name_len), o += name_len;
    if (ctrl_len) memcpy(req + o, ctrl, ctrl_len), o += ctrl_len;
    if (data_len) memcpy(req + o, payload_data, data_len), o += data_len;
    free(name);
    free(ctrl);
    free(payload_data);

    struct rsys_resp resp;
    uint8_t *odata = NULL;
    uint32_t odata_len = 0;
    if (rsys_call(sock, RSYS_REQ_SENDMSG, req, req_len, &resp, &odata, &odata_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(odata);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // sendmmsg(fd, msgvec, vlen, flags)
  if (nr == __NR_sendmmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msgvec_addr = (uintptr_t)regs->rsi;
    uint32_t vlen = (uint32_t)regs->rdx;
    int flags = (int)regs->r10;

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) return 0;

    // Prepare pending state; we'll queue msg_len writes into it.
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;

    if (vlen > 128) vlen = 128;
    if (vlen == 0) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pend->set_rax = 0;
      return 1;
    }

    uint32_t sent = 0;
    for (uint32_t mi = 0; mi < vlen; mi++) {
      struct mmsghdr mm;
      if (rsys_read_mem(pid, &mm, msgvec_addr + (uintptr_t)mi * sizeof(mm), sizeof(mm)) < 0) {
        // If we can't read, fall back to local.
        if (sent == 0) return 0;
        break;
      }

      struct msghdr mh = mm.msg_hdr;

      uint32_t name_len = (uint32_t)mh.msg_namelen;
      if (name_len > MAX_ADDR) name_len = MAX_ADDR;
      uint32_t ctrl_len = (uint32_t)mh.msg_controllen;
      if (ctrl_len > MAX_CTRL) ctrl_len = MAX_CTRL;
      uint32_t iovcnt = (uint32_t)mh.msg_iovlen;
      if (iovcnt > MAX_IOV) iovcnt = MAX_IOV;

      uint8_t *name = NULL;
      if (mh.msg_name && name_len) {
        name = (uint8_t *)malloc(name_len);
        if (!name) die("malloc");
        if (rsys_read_mem(pid, name, (uintptr_t)mh.msg_name, name_len) < 0) {
          free(name);
          if (sent == 0) return 0;
          break;
        }
      } else {
        name_len = 0;
      }

      uint8_t *ctrl = NULL;
      if (mh.msg_control && ctrl_len) {
        ctrl = (uint8_t *)malloc(ctrl_len);
        if (!ctrl) die("malloc");
        if (rsys_read_mem(pid, ctrl, (uintptr_t)mh.msg_control, ctrl_len) < 0) {
          free(name);
          free(ctrl);
          if (sent == 0) return 0;
          break;
        }
      } else {
        ctrl_len = 0;
      }

      struct iovec *iov = NULL;
      if (mh.msg_iov && iovcnt) {
        iov = (struct iovec *)malloc(iovcnt * sizeof(*iov));
        if (!iov) die("malloc");
        if (rsys_read_mem(pid, iov, (uintptr_t)mh.msg_iov, iovcnt * sizeof(*iov)) < 0) {
          free(name);
          free(ctrl);
          free(iov);
          if (sent == 0) return 0;
          break;
        }
      } else {
        iovcnt = 0;
      }

      uint32_t data_len = 0;
      for (uint32_t i = 0; i < iovcnt; i++) {
        uint64_t add = (uint64_t)iov[i].iov_len;
        if (add > MAX_BLOB) add = MAX_BLOB;
        if (data_len + (uint32_t)add < data_len) break;
        uint64_t newlen = (uint64_t)data_len + add;
        if (newlen > MAX_BLOB) {
          data_len = MAX_BLOB;
          break;
        }
        data_len = (uint32_t)newlen;
      }

      uint8_t *payload_data = NULL;
      if (data_len) {
        payload_data = (uint8_t *)malloc(data_len);
        if (!payload_data) die("malloc");
        uint32_t off = 0;
        for (uint32_t i = 0; i < iovcnt && off < data_len; i++) {
          uint32_t take = (uint32_t)iov[i].iov_len;
          if (take > data_len - off) take = data_len - off;
          if (take && rsys_read_mem(pid, payload_data + off, (uintptr_t)iov[i].iov_base, take) < 0) {
            free(name);
            free(ctrl);
            free(iov);
            free(payload_data);
            if (sent == 0) return 0;
            goto sendmmsg_done;
          }
          off += take;
        }
      }
      free(iov);

      uint32_t req_len = 32 + name_len + ctrl_len + data_len;
      uint8_t *req = (uint8_t *)malloc(req_len);
      if (!req) die("malloc");
      rsys_put_s64(req + 0, (int64_t)fd_remote);
      rsys_put_s64(req + 8, (int64_t)flags);
      rsys_put_u32(req + 16, name_len);
      rsys_put_u32(req + 20, ctrl_len);
      rsys_put_u32(req + 24, data_len);
      rsys_put_u32(req + 28, 0);
      uint32_t o = 32;
      if (name_len) memcpy(req + o, name, name_len), o += name_len;
      if (ctrl_len) memcpy(req + o, ctrl, ctrl_len), o += ctrl_len;
      if (data_len) memcpy(req + o, payload_data, data_len), o += data_len;
      free(name);
      free(ctrl);
      free(payload_data);

      struct rsys_resp resp;
      uint8_t *odata = NULL;
      uint32_t odata_len = 0;
      if (rsys_call(sock, RSYS_REQ_SENDMSG, req, req_len, &resp, &odata, &odata_len) < 0) {
        free(req);
        free(odata);
        if (sent == 0) return 0;
        break;
      }
      free(req);
      free(odata);

      int64_t rr = rsys_resp_raw_ret(&resp);
      int32_t eno = rsys_resp_err_no(&resp);
      int64_t rax_one = raw_sys_ret(rr, eno);

      if (rr < 0) {
        if (sent == 0) {
          // First one failed: return the error.
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = rax_one;
          return 1;
        }
        break;
      }

      // Update msg_len for this entry.
      uint32_t msg_len = (uint32_t)rr;
      uint8_t *lb = (uint8_t *)malloc(4);
      if (!lb) die("malloc");
      memcpy(lb, &msg_len, 4);
      uintptr_t len_addr = msgvec_addr + (uintptr_t)mi * sizeof(struct mmsghdr) + offsetof(struct mmsghdr, msg_len);
      (void)pending_add_out(pend, len_addr, lb, 4);
      sent++;
    }

  sendmmsg_done:
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pend->set_rax = (int64_t)sent;
    return 1;
  }

  // recvmmsg(fd, msgvec, vlen, flags, timeout)
  if (nr == __NR_recvmmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msgvec_addr = (uintptr_t)regs->rsi;
    uint32_t vlen = (uint32_t)regs->rdx;
    int flags = (int)regs->r10;
    // NOTE: timeout (regs->r8) is currently ignored (treated as NULL). This is
    // sufficient for netlink dump usage in iproute2, which typically passes NULL.

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    vlog("[rsys] recvmmsg(fd=%d -> remote_fd=%d, vlen=%u, flags=0x%x)\n", fd_local, fd_remote, vlen, flags);
    if (fd_remote < 0) return 0;

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;

    if (vlen > 128) vlen = 128;
    if (vlen == 0) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pend->set_rax = 0;
      return 1;
    }

    uint32_t recvd = 0;
    for (uint32_t mi = 0; mi < vlen; mi++) {
      struct mmsghdr mm;
      uintptr_t mm_addr = msgvec_addr + (uintptr_t)mi * sizeof(mm);
      if (rsys_read_mem(pid, &mm, mm_addr, sizeof(mm)) < 0) {
        if (recvd == 0) return 0;
        break;
      }

      struct msghdr mh = mm.msg_hdr;

      uint32_t name_max = (uint32_t)mh.msg_namelen;
      if (name_max > MAX_ADDR) name_max = MAX_ADDR;
      uint32_t ctrl_max = (uint32_t)mh.msg_controllen;
      if (ctrl_max > MAX_CTRL) ctrl_max = MAX_CTRL;
      uint32_t iovcnt = (uint32_t)mh.msg_iovlen;
      if (iovcnt > MAX_IOV) iovcnt = MAX_IOV;

      struct iovec *iov = NULL;
      if (mh.msg_iov && iovcnt) {
        iov = (struct iovec *)malloc(iovcnt * sizeof(*iov));
        if (!iov) die("malloc");
        if (rsys_read_mem(pid, iov, (uintptr_t)mh.msg_iov, iovcnt * sizeof(*iov)) < 0) {
          free(iov);
          if (recvd == 0) return 0;
          break;
        }
      } else {
        iovcnt = 0;
      }

      uint32_t *iov_lens = NULL;
      uint32_t total_max = 0;
      if (iovcnt) {
        iov_lens = (uint32_t *)malloc(iovcnt * sizeof(*iov_lens));
        if (!iov_lens) die("malloc");
        for (uint32_t i = 0; i < iovcnt; i++) {
          uint64_t l = (uint64_t)iov[i].iov_len;
          if (l > (uint64_t)(MAX_BLOB - total_max)) l = (uint64_t)(MAX_BLOB - total_max);
          iov_lens[i] = (uint32_t)l;
          total_max += (uint32_t)l;
        }
      }

      uint32_t req_len = 32 + (iovcnt * 4);
      uint8_t *req = (uint8_t *)malloc(req_len);
      if (!req) die("malloc");
      rsys_put_s64(req + 0, (int64_t)fd_remote);
      rsys_put_s64(req + 8, (int64_t)flags);
      rsys_put_u32(req + 16, name_max);
      rsys_put_u32(req + 20, ctrl_max);
      rsys_put_u32(req + 24, iovcnt);
      rsys_put_u32(req + 28, 0);
      for (uint32_t i = 0; i < iovcnt; i++) rsys_put_u32(req + 32 + (i * 4), iov_lens[i]);

      struct rsys_resp resp;
      uint8_t *data = NULL;
      uint32_t data_len = 0;
      if (rsys_call(sock, RSYS_REQ_RECVMSG, req, req_len, &resp, &data, &data_len) < 0) {
        free(req);
        free(iov_lens);
        free(iov);
        if (recvd == 0) return 0;
        break;
      }
      free(req);

      int64_t rr = rsys_resp_raw_ret(&resp);
      int32_t eno = rsys_resp_err_no(&resp);
      int64_t rax_one = raw_sys_ret(rr, eno);

      if (rr < 0) {
        free(data);
        free(iov_lens);
        free(iov);
        if (recvd == 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = rax_one;
          return 1;
        }
        break;
      }

      if (data_len < 16) {
        free(data);
        free(iov_lens);
        free(iov);
        if (recvd == 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = -(int64_t)EPROTO;
          return 1;
        }
        break;
      }

      uint32_t out_dlen = rsys_get_u32(data + 0);
      uint32_t out_nlen = rsys_get_u32(data + 4);
      uint32_t out_clen = rsys_get_u32(data + 8);
      uint32_t out_mflags = rsys_get_u32(data + 12);
      if (16u + out_dlen + out_nlen + out_clen != data_len) {
        free(data);
        free(iov_lens);
        free(iov);
        if (recvd == 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = -(int64_t)EPROTO;
          return 1;
        }
        break;
      }

      const uint8_t *dp = data + 16;
      const uint8_t *np = dp + out_dlen;
      const uint8_t *cp = np + out_nlen;

      uint32_t off = 0;
      for (uint32_t i = 0; i < iovcnt && off < out_dlen; i++) {
        uint32_t take = iov_lens ? iov_lens[i] : 0;
        if (take > out_dlen - off) take = out_dlen - off;
        if (take) {
          uint8_t *bb = (uint8_t *)malloc(take);
          if (!bb) die("malloc");
          memcpy(bb, dp + off, take);
          (void)pending_add_out(pend, (uintptr_t)iov[i].iov_base, bb, take);
        }
        off += take;
      }

      if (mh.msg_name && name_max) {
        if (out_nlen > name_max) out_nlen = name_max;
        if (out_nlen) {
          uint8_t *nb = (uint8_t *)malloc(out_nlen);
          if (!nb) die("malloc");
          memcpy(nb, np, out_nlen);
          (void)pending_add_out(pend, (uintptr_t)mh.msg_name, nb, out_nlen);
        }
      }

      if (mh.msg_control && ctrl_max) {
        if (out_clen > ctrl_max) out_clen = ctrl_max;
        if (out_clen) {
          uint8_t *cb = (uint8_t *)malloc(out_clen);
          if (!cb) die("malloc");
          memcpy(cb, cp, out_clen);
          (void)pending_add_out(pend, (uintptr_t)mh.msg_control, cb, out_clen);
        }
      }

      mh.msg_namelen = (socklen_t)out_nlen;
      mh.msg_controllen = (size_t)out_clen;
      mh.msg_flags = (int)out_mflags;
      uint8_t *mhb = (uint8_t *)malloc(sizeof(mh));
      if (!mhb) die("malloc");
      memcpy(mhb, &mh, sizeof(mh));
      (void)pending_add_out(pend, mm_addr + offsetof(struct mmsghdr, msg_hdr), mhb, (uint32_t)sizeof(mh));

      uint32_t msg_len = (uint32_t)rr;
      uint8_t *lb = (uint8_t *)malloc(4);
      if (!lb) die("malloc");
      memcpy(lb, &msg_len, 4);
      (void)pending_add_out(pend, mm_addr + offsetof(struct mmsghdr, msg_len), lb, 4);

      free(data);
      free(iov_lens);
      free(iov);

      recvd++;
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pend->set_rax = (int64_t)recvd;
    return 1;
  }

  // recvmsg(fd, msg, flags)
  if (nr == __NR_recvmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msg_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int fd_remote = rsys_map_fd(&ctx, fd_local);
    vlog("[rsys] recvmsg(fd=%d -> remote_fd=%d, flags=0x%x)\n", fd_local, fd_remote, flags);
    if (fd_remote < 0) return 0;

    struct msghdr mh;
    if (rsys_read_mem(pid, &mh, msg_addr, sizeof(mh)) < 0) {
      vlog("[rsys] recvmsg: failed to read msghdr at 0x%lx (errno=%d)\n", (unsigned long)msg_addr, errno);
      return 0;
    }

    uint32_t name_max = (uint32_t)mh.msg_namelen;
    if (name_max > MAX_ADDR) name_max = MAX_ADDR;
    uint32_t ctrl_max = (uint32_t)mh.msg_controllen;
    if (ctrl_max > MAX_CTRL) ctrl_max = MAX_CTRL;
    uint32_t iovcnt = (uint32_t)mh.msg_iovlen;
    if (iovcnt > MAX_IOV) iovcnt = MAX_IOV;

    struct iovec *iov = NULL;
    if (mh.msg_iov && iovcnt) {
      iov = (struct iovec *)malloc(iovcnt * sizeof(*iov));
      if (!iov) die("malloc");
      if (rsys_read_mem(pid, iov, (uintptr_t)mh.msg_iov, iovcnt * sizeof(*iov)) < 0) {
        vlog("[rsys] recvmsg: failed to read iov at 0x%lx (errno=%d)\n", (unsigned long)(uintptr_t)mh.msg_iov, errno);
        free(iov);
        return 0;
      }
    } else {
      iovcnt = 0;
    }

    uint32_t *iov_lens = NULL;
    uint32_t total_max = 0;
    if (iovcnt) {
      iov_lens = (uint32_t *)malloc(iovcnt * sizeof(*iov_lens));
      if (!iov_lens) die("malloc");
      for (uint32_t i = 0; i < iovcnt; i++) {
        uint64_t l = (uint64_t)iov[i].iov_len;
        if (l > (uint64_t)(MAX_BLOB - total_max)) l = (uint64_t)(MAX_BLOB - total_max);
        iov_lens[i] = (uint32_t)l;
        total_max += (uint32_t)l;
      }
    }

    uint32_t req_len = 32 + (iovcnt * 4);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, name_max);
    rsys_put_u32(req + 20, ctrl_max);
    rsys_put_u32(req + 24, iovcnt);
    rsys_put_u32(req + 28, 0);
    for (uint32_t i = 0; i < iovcnt; i++) rsys_put_u32(req + 32 + (i * 4), iov_lens[i]);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RECVMSG, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      free(iov_lens);
      free(iov);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr >= 0) {
      if (data_len < 16) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_dlen = rsys_get_u32(data + 0);
        uint32_t out_nlen = rsys_get_u32(data + 4);
        uint32_t out_clen = rsys_get_u32(data + 8);
        uint32_t out_mflags = rsys_get_u32(data + 12);
        if (16u + out_dlen + out_nlen + out_clen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          const uint8_t *dp = data + 16;
          const uint8_t *np = dp + out_dlen;
          const uint8_t *cp = np + out_nlen;

          // Scatter data into iov buffers
          uint32_t off = 0;
          for (uint32_t i = 0; i < iovcnt && off < out_dlen; i++) {
            uint32_t take = iov_lens ? iov_lens[i] : 0;
            if (take > out_dlen - off) take = out_dlen - off;
            if (take) {
              uint8_t *bb = (uint8_t *)malloc(take);
              if (!bb) die("malloc");
              memcpy(bb, dp + off, take);
              (void)pending_add_out(pend, (uintptr_t)iov[i].iov_base, bb, take);
            }
            off += take;
          }

          if (mh.msg_name && name_max) {
            if (out_nlen > name_max) out_nlen = name_max;
            if (out_nlen) {
              uint8_t *nb = (uint8_t *)malloc(out_nlen);
              if (!nb) die("malloc");
              memcpy(nb, np, out_nlen);
              (void)pending_add_out(pend, (uintptr_t)mh.msg_name, nb, out_nlen);
            }
          }

          if (mh.msg_control && ctrl_max) {
            if (out_clen > ctrl_max) out_clen = ctrl_max;
            if (out_clen) {
              uint8_t *cb = (uint8_t *)malloc(out_clen);
              if (!cb) die("malloc");
              memcpy(cb, cp, out_clen);
              (void)pending_add_out(pend, (uintptr_t)mh.msg_control, cb, out_clen);
            }
          }

          // Update msghdr lengths/flags in tracee
          mh.msg_namelen = (socklen_t)out_nlen;
          mh.msg_controllen = (size_t)out_clen;
          mh.msg_flags = (int)out_mflags;
          uint8_t *mhb = (uint8_t *)malloc(sizeof(mh));
          if (!mhb) die("malloc");
          memcpy(mhb, &mh, sizeof(mh));
          (void)pending_add_out(pend, msg_addr, mhb, (uint32_t)sizeof(mh));

          free(data);
        }
      }
    } else {
      free(data);
    }

    free(iov_lens);
    free(iov);
    return 1;
  }

  // fcntl(fd, cmd, arg)
  if (nr == __NR_fcntl) {
    int fd_local = (int)regs->rdi;
    int cmd = (int)regs->rsi;
    uint64_t arg = (uint64_t)regs->rdx;
    int fd_remote = rsys_map_fd(&ctx, fd_local);
    vlog("[rsys] fcntl(fd=%d -> remote_fd=%d, cmd=%s/%d, arg=0x%lx)\n", fd_local, fd_remote, rsys_fcntl_cmd_name(cmd), cmd,
         (unsigned long)arg);
    if (fd_remote < 0) return 0;

    // Important: FD flags like FD_CLOEXEC must be applied to the *local* placeholder
    // fds, otherwise they leak across exec in the tracee and can break programs
    // (OpenSSH is particularly sensitive to fd leaks).
    //
    // Since rsysd does not exec, mirroring FD_CLOEXEC to the remote fd is not necessary.
    if (cmd == F_SETFD || cmd == F_GETFD) {
      vlog("[rsys] fcntl(%s) -> local (placeholder)\n", rsys_fcntl_cmd_name(cmd));
      return 0; // let kernel apply to local placeholder
    }

    // Duplication fcntl must be handled locally to produce a real local FD,
    // but we must propagate the remote mapping.
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
      vlog("[rsys] fcntl(%s) -> local dup, map-on-exit to remote_fd=%d\n", rsys_fcntl_cmd_name(cmd), fd_remote);
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->has_set_rax = 0;      // keep kernel's new fd
      pend->map_fd_on_exit = 1;   // map new local fd -> same remote fd
      pend->map_remote_fd = fd_remote;
      return 0; // let kernel execute local fcntl()
    }

    uint32_t has_flock = 0;
    uint32_t flock_len = 0;
    uint8_t *flock_bytes = NULL;
    if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW) {
      has_flock = 1;
      flock_len = (uint32_t)sizeof(struct flock);
      flock_bytes = (uint8_t *)malloc(flock_len);
      if (!flock_bytes) die("malloc");
      if (rsys_read_mem(pid, flock_bytes, (uintptr_t)arg, flock_len) < 0) {
        free(flock_bytes);
        return 0;
      }
    }

    uint32_t req_len = 28 + (has_flock ? flock_len : 0);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)cmd);
    rsys_put_u64(req + 16, arg);
    rsys_put_u32(req + 24, has_flock);
    if (has_flock) memcpy(req + 28, flock_bytes, flock_len);
    free(flock_bytes);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_FCNTL, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (has_flock && cmd == F_GETLK && rr == 0) {
      if (data_len != sizeof(struct flock)) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint8_t *fb = (uint8_t *)malloc(data_len);
        if (!fb) die("malloc");
        memcpy(fb, data, data_len);
        (void)pending_add_out(pend, (uintptr_t)arg, fb, data_len);
        free(data);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // dup/dup2/dup3 on remote-mapped fds: let kernel duplicate the placeholder,
  // but propagate the mapping to the new local fd.
  if (nr == __NR_dup || nr == __NR_dup2 || nr == __NR_dup3) {
    int oldfd = (int)regs->rdi;
    int rfd = rsys_map_fd(&ctx, oldfd);
    if (nr == __NR_dup) {
      vlog("[rsys] dup(oldfd=%d -> remote_fd=%d)\n", oldfd, rfd);
    } else if (nr == __NR_dup2) {
      int newfd = (int)regs->rsi;
      vlog("[rsys] dup2(oldfd=%d -> remote_fd=%d, newfd=%d)\n", oldfd, rfd, newfd);
    } else {
      int newfd = (int)regs->rsi;
      int flags = (int)regs->rdx;
      vlog("[rsys] dup3(oldfd=%d -> remote_fd=%d, newfd=%d, flags=0x%x)\n", oldfd, rfd, newfd, flags);
    }
    if (rfd < 0) return 0;

    if (nr == __NR_dup2 || nr == __NR_dup3) {
      int newfd = (int)regs->rsi;
      if (newfd != oldfd) {
        // dup2/dup3 implicitly close newfd if open. Remove any existing mapping(s).
        fdmap_remove_all_local_and_close(fm, rrefs, sock, newfd);
      }
    }

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->has_set_rax = 0;
    pend->map_fd_on_exit = 1;
    pend->map_remote_fd = rfd;
    return 0; // let kernel run dup*, mapping happens on syscall-exit
  }

  // epoll_create1(flags)
  if (nr == __NR_epoll_create1) {
    int flags = (int)regs->rdi;
    // IMPORTANT: epoll fds must be real epoll instances locally. Returning an eventfd
    // placeholder breaks Go's runtime (epoll_ctl -> EINVAL). We keep the epoll fd
    // local and emulate watching remote fds in userspace (see epoll_ctl/wait).
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->has_set_rax = 0; // keep kernel return value
    pend->track_epoll_create = 1;
    pend->epoll_create_flags = flags;
    return 0; // let kernel create a real epoll fd in the tracee
  }

  // epoll_ctl(epfd, op, fd, event)
  if (nr == __NR_epoll_ctl) {
    int epfd_local = (int)regs->rdi;
    int op = (int)regs->rsi;
    int fd_local = (int)regs->rdx;
    uintptr_t ev_addr = (uintptr_t)regs->r10;
    struct epoll_state *es = ep ? epoll_table_find(ep, epfd_local) : NULL;
    if (!es) {
      // Not a tracked local epoll instance. Fall back to old remote-epoll path (if any).
      int epfd_remote = rsys_map_fd(&ctx, epfd_local);
      int fd_remote = rsys_map_fd(&ctx, fd_local);
      if (epfd_remote < 0 || fd_remote < 0) return 0;

      uint32_t has_ev = (ev_addr != 0 && op != EPOLL_CTL_DEL) ? 1u : 0u;
      uint32_t ev_len = (uint32_t)sizeof(struct epoll_event);
      uint8_t evbuf[sizeof(struct epoll_event)];
      if (has_ev) {
        if (rsys_read_mem(pid, evbuf, ev_addr, ev_len) < 0) return 0;
      }

      uint32_t req_len = 32 + (has_ev ? ev_len : 0);
      uint8_t *req = (uint8_t *)malloc(req_len);
      if (!req) die("malloc");
      rsys_put_s64(req + 0, (int64_t)epfd_remote);
      rsys_put_s64(req + 8, (int64_t)op);
      rsys_put_s64(req + 16, (int64_t)fd_remote);
      rsys_put_u32(req + 24, has_ev);
      rsys_put_u32(req + 28, ev_len);
      if (has_ev) memcpy(req + 32, evbuf, ev_len);

      struct rsys_resp resp;
      uint8_t *data = NULL;
      uint32_t data_len = 0;
      if (rsys_call(sock, RSYS_REQ_EPOLL_CTL, req, req_len, &resp, &data, &data_len) < 0) {
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

    int fd_remote = rsys_map_fd(&ctx, fd_local);
    if (fd_remote < 0) {
      // Local fd; let the kernel manage it in the tracee.
      return 0;
    }

    // Remote fd: store interest locally; do NOT call kernel epoll_ctl on the placeholder.
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    if (op != EPOLL_CTL_DEL) {
      if (!ev_addr) return rsys_deny_syscall(&ctx, nr, EINVAL);
      if (rsys_read_mem(pid, &ev, ev_addr, sizeof(ev)) < 0) return 0;
      if (epoll_watch_upsert(es, fd_local, fd_remote, ev.events, ev.data.u64) < 0) {
        return rsys_deny_syscall(&ctx, nr, ENOMEM);
      }
    } else {
      epoll_watch_del(es, fd_local);
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = 0;
    return 1;

  }

  // epoll_wait(epfd, events, maxevents, timeout)
  if (nr == __NR_epoll_wait) {
    int epfd_local = (int)regs->rdi;
    uintptr_t evs_addr = (uintptr_t)regs->rsi;
    int maxevents = (int)regs->rdx;
    int timeout = (int)regs->r10;
    struct epoll_state *es = ep ? epoll_table_find(ep, epfd_local) : NULL;
    if (es && es->n > 0) {
      if (maxevents <= 0) return 0;
      if ((uint32_t)maxevents > 4096u) maxevents = 4096;

      // We'll synthesize results: local events (via duplicated epfd) + remote readiness (via ppoll).
      struct epoll_event out[4096];
      int out_n = 0;

      int timeout_infinite = (timeout < 0);
      int64_t remaining_ms = timeout_infinite ? -1 : (int64_t)timeout;
      int64_t slice_ms = 50;
      if (!timeout_infinite && remaining_ms < slice_ms) slice_ms = remaining_ms;
      if (timeout == 0) slice_ms = 0;

      for (;;) {
        // Local events: duplicate epfd into tracer and do epoll_wait(0).
        int pidfd = rsys_pidfd_open_self(&ctx);
        if (pidfd >= 0) {
          int epfd_dup = rsys_pidfd_getfd(pidfd, epfd_local);
          close(pidfd);
          if (epfd_dup >= 0) {
            int nloc = epoll_wait(epfd_dup, out, maxevents, 0);
            close(epfd_dup);
            if (nloc > 0) out_n = nloc;
          }
        }

        // Remote readiness for remote-watched fds.
        if (out_n < maxevents) {
          size_t nw = es->n;
          uint32_t req_len = 32 + (uint32_t)nw * 16;
          uint8_t *req = (uint8_t *)malloc(req_len);
          if (!req) die("malloc");
          rsys_put_u32(req + 0, (uint32_t)nw);
          rsys_put_u32(req + 4, 1u); // has timeout
          rsys_put_u32(req + 8, 0u); // no sigmask
          rsys_put_u32(req + 12, 0u);
          rsys_put_s64(req + 16, (int64_t)(slice_ms / 1000));
          rsys_put_s64(req + 24, (int64_t)((slice_ms % 1000) * 1000000LL));
          uint32_t off = 32;
          for (uint32_t i = 0; i < (uint32_t)nw; i++) {
            rsys_put_s64(req + off + 0, (int64_t)es->w[i].remote_fd);
            rsys_put_u32(req + off + 8, (uint32_t)rsys_epoll_to_poll(es->w[i].events));
            rsys_put_u32(req + off + 12, 0);
            off += 16;
          }
          struct rsys_resp resp;
          uint8_t *data = NULL;
          uint32_t data_len = 0;
          int ok = (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) == 0);
          free(req);
          if (ok && rsys_resp_raw_ret(&resp) >= 0 && data_len == 4u + (uint32_t)nw * 4u && rsys_get_u32(data + 0) == (uint32_t)nw) {
            for (uint32_t i = 0; i < (uint32_t)nw && out_n < maxevents; i++) {
              uint16_t pre = (uint16_t)rsys_get_u32(data + 4 + i * 4);
              if (!pre) continue;
              uint32_t got = rsys_poll_to_epoll(pre);
              uint32_t report = (got & es->w[i].events) | (got & (EPOLLERR | EPOLLHUP));
#ifdef EPOLLRDHUP
              report |= (got & EPOLLRDHUP);
#endif
              if (!report) continue;
              out[out_n].events = report;
              out[out_n].data.u64 = es->w[i].data;
              out_n++;
            }
          }
          free(data);
        }

        if (out_n > 0 || timeout == 0) break;
        if (!timeout_infinite) {
          remaining_ms -= slice_ms;
          if (remaining_ms <= 0) break;
          if (remaining_ms < slice_ms) slice_ms = remaining_ms;
        }
        if (slice_ms < 500) slice_ms *= 2;
      }

      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->set_rax = out_n;
      if (out_n > 0) {
        uint32_t blen = (uint32_t)out_n * (uint32_t)sizeof(struct epoll_event);
        uint8_t *bb = (uint8_t *)malloc(blen);
        if (!bb) die("malloc");
        memcpy(bb, out, blen);
        (void)pending_add_out(pend, evs_addr, bb, blen);
      }
      return 1;
    }

    // Not a local-virtual epoll. Fall back to remote-epoll path if epfd is remote-mapped.
    int epfd_remote = rsys_map_fd(&ctx, epfd_local);
    if (epfd_remote < 0) return 0;
    if (maxevents < 0) return 0;
    if ((uint32_t)maxevents > 4096u) maxevents = 4096;

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)epfd_remote);
    rsys_put_s64(req + 8, (int64_t)maxevents);
    rsys_put_s64(req + 16, (int64_t)timeout);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_EPOLL_WAIT, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr > 0) {
      uint32_t need = (uint32_t)rr * (uint32_t)sizeof(struct epoll_event);
      if (need != data_len) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        (void)pending_add_out(pend, evs_addr, data, data_len);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)
  if (nr == __NR_epoll_pwait) {
    int epfd_local = (int)regs->rdi;
    uintptr_t evs_addr = (uintptr_t)regs->rsi;
    int maxevents = (int)regs->rdx;
    int timeout = (int)regs->r10;
    uintptr_t sig_addr = (uintptr_t)regs->r8;
    uint64_t sigsz = (uint64_t)regs->r9;
    // Virtual epoll handling for local epoll fds (Go runtime uses epoll_pwait).
    struct epoll_state *es = ep ? epoll_table_find(ep, epfd_local) : NULL;
    if (es && es->n > 0) {
      if (maxevents <= 0) return 0;
      if ((uint32_t)maxevents > 4096u) maxevents = 4096;

      struct epoll_event out[4096];
      int out_n = 0;

      int timeout_infinite = (timeout < 0);
      int64_t remaining_ms = timeout_infinite ? -1 : (int64_t)timeout;
      int64_t slice_ms = 50;
      if (!timeout_infinite && remaining_ms < slice_ms) slice_ms = remaining_ms;
      if (timeout == 0) slice_ms = 0;

      for (;;) {
        // Local events: duplicate epfd into tracer and do epoll_wait(0).
        int pidfd = rsys_pidfd_open_self(&ctx);
        if (pidfd >= 0) {
          int epfd_dup = rsys_pidfd_getfd(pidfd, epfd_local);
          close(pidfd);
          if (epfd_dup >= 0) {
            int nloc = epoll_wait(epfd_dup, out, maxevents, 0);
            close(epfd_dup);
            if (nloc > 0) out_n = nloc;
          }
        }

        // Remote readiness for remote-watched fds.
        if (out_n < maxevents) {
          size_t nw = es->n;
          uint32_t req_len = 32 + (uint32_t)nw * 16;
          uint8_t *req = (uint8_t *)malloc(req_len);
          if (!req) die("malloc");
          rsys_put_u32(req + 0, (uint32_t)nw);
          rsys_put_u32(req + 4, 1u); // has timeout
          rsys_put_u32(req + 8, 0u); // no sigmask (best-effort)
          rsys_put_u32(req + 12, 0u);
          rsys_put_s64(req + 16, (int64_t)(slice_ms / 1000));
          rsys_put_s64(req + 24, (int64_t)((slice_ms % 1000) * 1000000LL));
          uint32_t off = 32;
          for (uint32_t i = 0; i < (uint32_t)nw; i++) {
            rsys_put_s64(req + off + 0, (int64_t)es->w[i].remote_fd);
            rsys_put_u32(req + off + 8, (uint32_t)rsys_epoll_to_poll(es->w[i].events));
            rsys_put_u32(req + off + 12, 0);
            off += 16;
          }
          struct rsys_resp resp;
          uint8_t *data = NULL;
          uint32_t data_len = 0;
          int ok = (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) == 0);
          free(req);
          if (ok && rsys_resp_raw_ret(&resp) >= 0 && data_len == 4u + (uint32_t)nw * 4u && rsys_get_u32(data + 0) == (uint32_t)nw) {
            for (uint32_t i = 0; i < (uint32_t)nw && out_n < maxevents; i++) {
              uint16_t pre = (uint16_t)rsys_get_u32(data + 4 + i * 4);
              if (!pre) continue;
              uint32_t got = rsys_poll_to_epoll(pre);
              uint32_t report = (got & es->w[i].events) | (got & (EPOLLERR | EPOLLHUP));
#ifdef EPOLLRDHUP
              report |= (got & EPOLLRDHUP);
#endif
              if (!report) continue;
              out[out_n].events = report;
              out[out_n].data.u64 = es->w[i].data;
              out_n++;
            }
          }
          free(data);
        }

        if (out_n > 0 || timeout == 0) break;
        if (!timeout_infinite) {
          remaining_ms -= slice_ms;
          if (remaining_ms <= 0) break;
          if (remaining_ms < slice_ms) slice_ms = remaining_ms;
        }
        if (slice_ms < 500) slice_ms *= 2;
      }

      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->set_rax = out_n;
      if (out_n > 0) {
        uint32_t blen = (uint32_t)out_n * (uint32_t)sizeof(struct epoll_event);
        uint8_t *bb = (uint8_t *)malloc(blen);
        if (!bb) die("malloc");
        memcpy(bb, out, blen);
        (void)pending_add_out(pend, evs_addr, bb, blen);
      }
      return 1;
    }

    // Fallback: remote epoll_pwait if epfd is remote-mapped.
    int epfd_remote = rsys_map_fd(&ctx, epfd_local);
    if (epfd_remote < 0) return 0;
    if (maxevents < 0) return 0;
    if ((uint32_t)maxevents > 4096u) maxevents = 4096;
    if (sigsz > 128) sigsz = 128;

    uint8_t sigmask[128];
    if (sig_addr && sigsz) {
      if (rsys_read_mem(pid, sigmask, sig_addr, (size_t)sigsz) < 0) return 0;
    } else {
      sigsz = 0;
    }

    uint32_t req_len = 28 + (uint32_t)sigsz;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)epfd_remote);
    rsys_put_s64(req + 8, (int64_t)maxevents);
    rsys_put_s64(req + 16, (int64_t)timeout);
    rsys_put_u32(req + 24, (uint32_t)sigsz);
    if (sigsz) memcpy(req + 28, sigmask, (size_t)sigsz);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_EPOLL_PWAIT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr > 0) {
      uint32_t need = (uint32_t)rr * (uint32_t)sizeof(struct epoll_event);
      if (need != data_len) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        (void)pending_add_out(pend, evs_addr, data, data_len);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // ppoll(fds, nfds, tmo_p, sigmask, sigsetsize)
  if (nr == __NR_ppoll) {
    uintptr_t fds_addr = (uintptr_t)regs->rdi;
    uint64_t nfds = (uint64_t)regs->rsi;
    uintptr_t tmo_addr = (uintptr_t)regs->rdx;
    uintptr_t sig_addr = (uintptr_t)regs->r10;
    uint64_t sigsz = (uint64_t)regs->r8;

    if (nfds > 4096) nfds = 4096;
    if (nfds == 0) return 0;

    struct pollfd *pfds = (struct pollfd *)malloc((size_t)nfds * sizeof(*pfds));
    if (!pfds) die("malloc");
    if (rsys_read_mem(pid, pfds, fds_addr, (size_t)nfds * sizeof(*pfds)) < 0) {
      free(pfds);
      return 0;
    }

    int any_remote = 0;
    int any_local = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
      if (pfds[i].fd < 0) continue;
      if (rsys_map_fd(&ctx, pfds[i].fd) >= 0) any_remote = 1;
      else any_local = 1;
    }
    if (!any_remote) {
      free(pfds);
      return 0;
    }

    struct timespec tmo;
    uint32_t has_tmo = (tmo_addr != 0) ? 1u : 0u;
    if (has_tmo) {
      if (rsys_read_mem(pid, &tmo, tmo_addr, sizeof(tmo)) < 0) {
        free(pfds);
        return 0;
      }
    }

    uint32_t has_sig = (sig_addr != 0 && sigsz != 0) ? 1u : 0u;
    if (sigsz > 128) sigsz = 128;
    uint8_t sigmask[128];
    if (has_sig) {
      if (rsys_read_mem(pid, sigmask, sig_addr, (size_t)sigsz) < 0) {
        free(pfds);
        return 0;
      }
    }

    // Mixed local+remote ppoll. If there are no local fds, do a single remote call.
    int timeout_infinite = !has_tmo;
    int64_t remaining_ns = -1;
    if (has_tmo) remaining_ns = (int64_t)tmo.tv_sec * 1000000000LL + (int64_t)tmo.tv_nsec;
    int64_t slice_ns = any_local ? (50 * 1000000LL) : remaining_ns;

    for (;;) {
      // Local readiness check (0 timeout) for local-only fds.
      struct pollfd *lp = NULL;
      uint16_t *lp_rev = NULL;
      uint16_t *rp_rev = NULL;
      if (any_local) {
        lp = (struct pollfd *)malloc((size_t)nfds * sizeof(*lp));
        if (!lp) die("malloc");
        memcpy(lp, pfds, (size_t)nfds * sizeof(*lp));
        int pidfd = rsys_pidfd_open_self(&ctx);
        int *dups = NULL;
        if (pidfd >= 0) {
          dups = (int *)malloc((size_t)nfds * sizeof(*dups));
          if (!dups) die("malloc");
          for (size_t i = 0; i < (size_t)nfds; i++) dups[i] = -1;
        }
        for (size_t i = 0; i < (size_t)nfds; i++) {
          if (lp[i].fd < 0) continue;
          if (rsys_map_fd(&ctx, lp[i].fd) >= 0) lp[i].fd = -1;
          // Poll tracee-local fds by duplicating them into this process.
          if (lp[i].fd >= 0) {
            if (pidfd >= 0 && dups) {
              int dupfd = rsys_pidfd_getfd(pidfd, lp[i].fd);
              if (dupfd >= 0) {
                dups[i] = dupfd;
                lp[i].fd = dupfd;
              } else {
                // Treat as invalid (matches poll(2) behaviour).
                lp[i].revents = POLLNVAL;
                lp[i].fd = -1;
              }
            } else {
              // No pidfd_getfd available: best-effort poll only true stdio.
              int base = rsys_base_fd_local(&ctx, lp[i].fd);
              if (!(base == 0 || base == 1 || base == 2)) lp[i].fd = -1;
              else lp[i].fd = base;
            }
          }
          if (lp[i].revents != POLLNVAL) lp[i].revents = 0;
        }
        (void)poll(lp, (nfds_t)nfds, 0);
        if (g_verbose && nfds <= 64) {
          lp_rev = (uint16_t *)malloc((size_t)nfds * sizeof(*lp_rev));
          if (!lp_rev) die("malloc");
          for (size_t i = 0; i < (size_t)nfds; i++) lp_rev[i] = (uint16_t)lp[i].revents;
        }
        if (dups) {
          for (size_t i = 0; i < (size_t)nfds; i++) {
            if (dups[i] >= 0) close(dups[i]);
          }
          free(dups);
        }
        if (pidfd >= 0) close(pidfd);
      }

      int64_t use_ns = timeout_infinite ? slice_ns : slice_ns;
      if (!timeout_infinite && remaining_ns < use_ns) use_ns = remaining_ns;
      if (!timeout_infinite && use_ns < 0) use_ns = 0;

      uint64_t use_sec = (uint64_t)(use_ns / 1000000000LL);
      uint64_t use_nsec = (uint64_t)(use_ns % 1000000000LL);

      uint32_t req_len = 32 + (uint32_t)nfds * 16 + (has_sig ? (uint32_t)sigsz : 0);
      uint8_t *req = (uint8_t *)malloc(req_len);
      if (!req) die("malloc");
      rsys_put_u32(req + 0, (uint32_t)nfds);
      // If we have any local fds to multiplex with, we MUST use a finite remote timeout
      // (a slice), even when the overall timeout is infinite, otherwise we can block
      // forever in the remote ppoll() and miss local stdin readiness.
      uint32_t req_has_tmo = (uint32_t)((!timeout_infinite || any_local) ? 1u : 0u);
      rsys_put_u32(req + 4, req_has_tmo);
      rsys_put_u32(req + 8, has_sig);
      rsys_put_u32(req + 12, (uint32_t)sigsz);
      rsys_put_s64(req + 16, (int64_t)use_sec);
      rsys_put_s64(req + 24, (int64_t)use_nsec);
      uint32_t off = 32;
      for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
        int rfd = (pfds[i].fd < 0) ? -1 : rsys_map_fd(&ctx, pfds[i].fd);
        rsys_put_s64(req + off + 0, (int64_t)rfd);
        rsys_put_u32(req + off + 8, (uint32_t)(uint16_t)pfds[i].events);
        rsys_put_u32(req + off + 12, 0);
        off += 16;
      }
      if (has_sig) memcpy(req + off, sigmask, (size_t)sigsz);

      struct rsys_resp resp;
      uint8_t *data = NULL;
      uint32_t data_len = 0;
      int ok = (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) == 0);
      free(req);

      for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = 0;
      if (ok && rsys_resp_raw_ret(&resp) >= 0 && data_len == 4u + (uint32_t)nfds * 4u && rsys_get_u32(data + 0) == (uint32_t)nfds) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = (short)(uint16_t)rsys_get_u32(data + 4 + i * 4);
      }
      if (g_verbose && nfds <= 64) {
        rp_rev = (uint16_t *)malloc((size_t)nfds * sizeof(*rp_rev));
        if (!rp_rev) die("malloc");
        for (size_t i = 0; i < (size_t)nfds; i++) rp_rev[i] = (uint16_t)pfds[i].revents;
      }
      free(data);

      if (lp) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
          if (lp[i].fd >= 0) pfds[i].revents |= lp[i].revents;
        }
        free(lp);
        lp = NULL;
      }

      int ready_cnt = 0;
      for (uint32_t i = 0; i < (uint32_t)nfds; i++) if (pfds[i].revents) ready_cnt++;

      if (g_verbose && nfds <= 64) {
        int has_nval = 0;
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
          if ((pfds[i].revents & POLLNVAL) != 0) {
            has_nval = 1;
            break;
          }
        }
        if (has_nval) {
          vlog("[rsys] ppoll: POLLNVAL observed (nfds=%" PRIu64 ", any_local=%d, any_remote=%d, ready=%d)\n", nfds, any_local, any_remote,
               ready_cnt);
          for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
            int lfd = pfds[i].fd;
            int rfd = (lfd < 0) ? -1 : rsys_map_fd(&ctx, lfd);
            uint16_t ev = (uint16_t)pfds[i].events;
            uint16_t rr = rp_rev ? rp_rev[i] : 0;
            uint16_t lr = lp_rev ? lp_rev[i] : 0;
            uint16_t fr = (uint16_t)pfds[i].revents;
            if ((fr & POLLNVAL) != 0) {
              vlog("[rsys]   i=%u lfd=%d rfd=%d events=0x%x remote_revents=0x%x local_revents=0x%x final_revents=0x%x\n", i, lfd, rfd, ev, rr,
                   lr, fr);
            }
          }
        }
      }

      free(lp_rev);
      free(rp_rev);
      lp_rev = NULL;
      rp_rev = NULL;

      if (ready_cnt > 0 || (has_tmo && remaining_ns <= 0) || (!any_local)) {
        regs->orig_rax = __NR_getpid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        pending_clear(pend);
        pend->active = 1;
        pend->nr = nr;
        pend->set_rax = ready_cnt;
        uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
        if (!wb) die("malloc");
        memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
        (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
        free(pfds);
        return 1;
      }

      if (has_tmo) {
        remaining_ns -= use_ns;
        if (remaining_ns <= 0) continue;
      }
      if (slice_ns < 500 * 1000000LL) slice_ns *= 2;
    }
  }

  // poll(fds, nfds, timeout_ms) -> forwarded via ppoll protocol
  if (nr == __NR_poll) {
    uintptr_t fds_addr = (uintptr_t)regs->rdi;
    uint64_t nfds = (uint64_t)regs->rsi;
    int timeout_ms = (int)regs->rdx;

    if (nfds > 4096) nfds = 4096;
    if (nfds == 0) return 0;

    struct pollfd *pfds = (struct pollfd *)malloc((size_t)nfds * sizeof(*pfds));
    if (!pfds) die("malloc");
    if (rsys_read_mem(pid, pfds, fds_addr, (size_t)nfds * sizeof(*pfds)) < 0) {
      free(pfds);
      return 0;
    }

    int any_remote = 0;
    int any_local = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
      if (pfds[i].fd < 0) continue;
      if (rsys_map_fd(&ctx, pfds[i].fd) >= 0) any_remote = 1;
      else any_local = 1;
    }
    if (!any_remote) {
      free(pfds);
      return 0;
    }

    int timeout_infinite = (timeout_ms < 0);
    int64_t remaining_ns = timeout_infinite ? -1 : (int64_t)timeout_ms * 1000000LL;
    int64_t slice_ns = any_local ? (50 * 1000000LL) : remaining_ns;

    for (;;) {
      struct pollfd *lp = NULL;
      uint16_t *lp_rev = NULL;
      uint16_t *rp_rev = NULL;
      if (any_local) {
        lp = (struct pollfd *)malloc((size_t)nfds * sizeof(*lp));
        if (!lp) die("malloc");
        memcpy(lp, pfds, (size_t)nfds * sizeof(*lp));
        int pidfd = rsys_pidfd_open_self(&ctx);
        int *dups = NULL;
        if (pidfd >= 0) {
          dups = (int *)malloc((size_t)nfds * sizeof(*dups));
          if (!dups) die("malloc");
          for (size_t i = 0; i < (size_t)nfds; i++) dups[i] = -1;
        }
        for (size_t i = 0; i < (size_t)nfds; i++) {
          if (lp[i].fd < 0) continue;
          if (rsys_map_fd(&ctx, lp[i].fd) >= 0) lp[i].fd = -1;
          if (lp[i].fd >= 0) {
            if (pidfd >= 0 && dups) {
              int dupfd = rsys_pidfd_getfd(pidfd, lp[i].fd);
              if (dupfd >= 0) {
                dups[i] = dupfd;
                lp[i].fd = dupfd;
              } else {
                lp[i].revents = POLLNVAL;
                lp[i].fd = -1;
              }
            } else {
              int base = rsys_base_fd_local(&ctx, lp[i].fd);
              if (!(base == 0 || base == 1 || base == 2)) lp[i].fd = -1;
              else lp[i].fd = base;
            }
          }
          if (lp[i].revents != POLLNVAL) lp[i].revents = 0;
        }
        (void)poll(lp, (nfds_t)nfds, 0);
        if (g_verbose && nfds <= 64) {
          lp_rev = (uint16_t *)malloc((size_t)nfds * sizeof(*lp_rev));
          if (!lp_rev) die("malloc");
          for (size_t i = 0; i < (size_t)nfds; i++) lp_rev[i] = (uint16_t)lp[i].revents;
        }
        if (dups) {
          for (size_t i = 0; i < (size_t)nfds; i++) {
            if (dups[i] >= 0) close(dups[i]);
          }
          free(dups);
        }
        if (pidfd >= 0) close(pidfd);
      }

      int64_t use_ns = timeout_infinite ? slice_ns : slice_ns;
      if (!timeout_infinite && remaining_ns < use_ns) use_ns = remaining_ns;
      if (!timeout_infinite && use_ns < 0) use_ns = 0;

      uint64_t use_sec = (uint64_t)(use_ns / 1000000000LL);
      uint64_t use_nsec = (uint64_t)(use_ns % 1000000000LL);

      uint32_t req_len = 32 + (uint32_t)nfds * 16;
      uint8_t *req = (uint8_t *)malloc(req_len);
      if (!req) die("malloc");
      rsys_put_u32(req + 0, (uint32_t)nfds);
      // If we have any local fds to multiplex with, we MUST use a finite remote timeout
      // (a slice), even when the overall timeout is infinite, otherwise we can block
      // forever in the remote ppoll() and miss local readiness.
      uint32_t req_has_tmo = (uint32_t)((!timeout_infinite || any_local) ? 1u : 0u);
      rsys_put_u32(req + 4, req_has_tmo);
      rsys_put_u32(req + 8, 0);
      rsys_put_u32(req + 12, 0);
      rsys_put_s64(req + 16, (int64_t)use_sec);
      rsys_put_s64(req + 24, (int64_t)use_nsec);
      uint32_t off = 32;
      for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
        int rfd = (pfds[i].fd < 0) ? -1 : rsys_map_fd(&ctx, pfds[i].fd);
        rsys_put_s64(req + off + 0, (int64_t)rfd);
        rsys_put_u32(req + off + 8, (uint32_t)(uint16_t)pfds[i].events);
        rsys_put_u32(req + off + 12, 0);
        off += 16;
      }

      struct rsys_resp resp;
      uint8_t *data = NULL;
      uint32_t data_len = 0;
      int ok = (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) == 0);
      free(req);

      for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = 0;
      if (ok && rsys_resp_raw_ret(&resp) >= 0 && data_len == 4u + (uint32_t)nfds * 4u && rsys_get_u32(data + 0) == (uint32_t)nfds) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = (short)(uint16_t)rsys_get_u32(data + 4 + i * 4);
      }
      if (g_verbose && nfds <= 64) {
        rp_rev = (uint16_t *)malloc((size_t)nfds * sizeof(*rp_rev));
        if (!rp_rev) die("malloc");
        for (size_t i = 0; i < (size_t)nfds; i++) rp_rev[i] = (uint16_t)pfds[i].revents;
      }
      free(data);

      if (lp) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
          if (lp[i].fd >= 0) pfds[i].revents |= lp[i].revents;
        }
        free(lp);
        lp = NULL;
      }

      int ready_cnt = 0;
      for (uint32_t i = 0; i < (uint32_t)nfds; i++) if (pfds[i].revents) ready_cnt++;
      if (g_verbose && nfds <= 64) {
        int has_nval = 0;
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
          if ((pfds[i].revents & POLLNVAL) != 0) {
            has_nval = 1;
            break;
          }
        }
        if (has_nval) {
          vlog("[rsys] poll: POLLNVAL observed (nfds=%" PRIu64 ", any_local=%d, any_remote=%d, ready=%d)\n", nfds, any_local, any_remote, ready_cnt);
          for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
            int lfd = pfds[i].fd;
            int rfd = (lfd < 0) ? -1 : rsys_map_fd(&ctx, lfd);
            uint16_t ev = (uint16_t)pfds[i].events;
            uint16_t rr = rp_rev ? rp_rev[i] : 0;
            uint16_t lr = lp_rev ? lp_rev[i] : 0;
            uint16_t fr = (uint16_t)pfds[i].revents;
            if ((fr & POLLNVAL) != 0) {
              vlog("[rsys]   i=%u lfd=%d rfd=%d events=0x%x remote_revents=0x%x local_revents=0x%x final_revents=0x%x\n", i, lfd, rfd, ev, rr, lr,
                   fr);
            }
          }
        }
      }

      free(lp_rev);
      free(rp_rev);
      lp_rev = NULL;
      rp_rev = NULL;
      if (ready_cnt > 0 || timeout_ms == 0 || (!any_local)) {
        regs->orig_rax = __NR_getpid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        pending_clear(pend);
        pend->active = 1;
        pend->nr = nr;
        pend->set_rax = ready_cnt;
        uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
        if (!wb) die("malloc");
        memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
        (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
        free(pfds);
        return 1;
      }

      if (!timeout_infinite) {
        remaining_ns -= use_ns;
        if (remaining_ns <= 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pending_clear(pend);
          pend->active = 1;
          pend->nr = nr;
          pend->set_rax = 0;
          uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
          if (!wb) die("malloc");
          memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
          (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
          free(pfds);
          return 1;
        }
      }
      if (slice_ns < 500 * 1000000LL) slice_ns *= 2;
    }
  }

  return 0;
}
