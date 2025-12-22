#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

int rsys_intercept_fcntl(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct fd_map *fm = ctx->fm;
  struct remote_refs *rrefs = ctx->rrefs;
  struct pending_sys *pend = ctx->pend;

  // fcntl(fd, cmd, arg)
  if (nr == __NR_fcntl) {
    int fd_local = (int)regs->rdi;
    int cmd = (int)regs->rsi;
    uint64_t arg = (uint64_t)regs->rdx;
    int fd_remote = rsys_map_fd(ctx, fd_local);
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
    int rfd = rsys_map_fd(ctx, oldfd);
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


  return 0;
}
