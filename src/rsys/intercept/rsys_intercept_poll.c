#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"
#include "src/rsys/intercept/rsys_intercept_limits.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int rsys_intercept_poll(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct pending_sys *pend = ctx->pend;

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
      if (rsys_map_fd(ctx, pfds[i].fd) >= 0) any_remote = 1;
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
        int pidfd = rsys_pidfd_open_self(ctx);
        int *dups = NULL;
        if (pidfd >= 0) {
          dups = (int *)malloc((size_t)nfds * sizeof(*dups));
          if (!dups) die("malloc");
          for (size_t i = 0; i < (size_t)nfds; i++) dups[i] = -1;
        }
        for (size_t i = 0; i < (size_t)nfds; i++) {
          if (lp[i].fd < 0) continue;
          if (rsys_map_fd(ctx, lp[i].fd) >= 0) lp[i].fd = -1;
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
              int base = rsys_base_fd_local(ctx, lp[i].fd);
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
        int rfd = (pfds[i].fd < 0) ? -1 : rsys_map_fd(ctx, pfds[i].fd);
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
            int rfd = (lfd < 0) ? -1 : rsys_map_fd(ctx, lfd);
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
      if (rsys_map_fd(ctx, pfds[i].fd) >= 0) any_remote = 1;
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
        int pidfd = rsys_pidfd_open_self(ctx);
        int *dups = NULL;
        if (pidfd >= 0) {
          dups = (int *)malloc((size_t)nfds * sizeof(*dups));
          if (!dups) die("malloc");
          for (size_t i = 0; i < (size_t)nfds; i++) dups[i] = -1;
        }
        for (size_t i = 0; i < (size_t)nfds; i++) {
          if (lp[i].fd < 0) continue;
          if (rsys_map_fd(ctx, lp[i].fd) >= 0) lp[i].fd = -1;
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
              int base = rsys_base_fd_local(ctx, lp[i].fd);
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
        int rfd = (pfds[i].fd < 0) ? -1 : rsys_map_fd(ctx, pfds[i].fd);
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
            int rfd = (lfd < 0) ? -1 : rsys_map_fd(ctx, lfd);
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
