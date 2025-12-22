#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"
#include "src/rsys/intercept/rsys_intercept_limits.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

int rsys_intercept_epoll(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct epoll_table *ep = ctx->ep;
  struct pending_sys *pend = ctx->pend;

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
      int epfd_remote = rsys_map_fd(ctx, epfd_local);
      int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
    if (fd_remote < 0) {
      // Local fd; let the kernel manage it in the tracee.
      return 0;
    }

    // Remote fd: store interest locally; do NOT call kernel epoll_ctl on the placeholder.
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    if (op != EPOLL_CTL_DEL) {
      if (!ev_addr) return rsys_deny_syscall(ctx, nr, EINVAL);
      if (rsys_read_mem(pid, &ev, ev_addr, sizeof(ev)) < 0) return 0;
      if (epoll_watch_upsert(es, fd_local, fd_remote, ev.events, ev.data.u64) < 0) {
        return rsys_deny_syscall(ctx, nr, ENOMEM);
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
        int pidfd = rsys_pidfd_open_self(ctx);
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
    int epfd_remote = rsys_map_fd(ctx, epfd_local);
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
        int pidfd = rsys_pidfd_open_self(ctx);
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
    int epfd_remote = rsys_map_fd(ctx, epfd_local);
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


  return 0;
}
