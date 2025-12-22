#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"
#include "src/rsys/intercept/rsys_intercept_limits.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <linux/close_range.h>
#include <unistd.h>

int rsys_intercept_io(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct fd_map *fm = ctx->fm;
  struct remote_refs *rrefs = ctx->rrefs;
  int *local_base = ctx->local_base;
  size_t local_base_n = ctx->local_base_n;
  uint32_t *portfw_fd = ctx->portfw_fd;
  size_t portfw_fd_n = ctx->portfw_fd_n;
  struct epoll_table *ep = ctx->ep;
  struct pending_sys *pend = ctx->pend;

  // close(fd)
  if (nr == __NR_close) {
    int fd_local = (int)regs->rdi;
    int removed_any = 0;
    // Remove ALL mappings for this local fd. Stale duplicate entries can occur if
    // a local fd number is reused and an earlier mapping wasn't fully removed.
    // Duplicates can make rsys_map_fd(ctx, ) return a stale remote fd and break apps (ssh).
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
    if (portfw_fd && fd_local >= 0 && (size_t)fd_local < portfw_fd_n) {
      portfw_fd[fd_local] = 0;
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
    if (portfw_fd && (flags & CLOSE_RANGE_CLOEXEC) == 0) {
      unsigned int stop = last;
      if (stop >= portfw_fd_n) stop = (unsigned int)(portfw_fd_n - 1);
      for (unsigned int fd = first; fd <= stop; fd++) portfw_fd[fd] = 0;
    }
    return 0;
  }
#endif

  // read(fd, buf, count)
  if (nr == __NR_read) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;

    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
    if (fd_remote < 0) return 0; // local write (stdout/stderr)

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
    if (fd_remote < 0) return 0;

    if (g_read_only) {
      return rsys_deny_syscall(ctx, nr, EPERM);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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


  return 0;
}
