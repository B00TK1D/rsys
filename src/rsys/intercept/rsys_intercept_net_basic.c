#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"
#include "src/rsys/intercept/rsys_intercept_limits.h"

#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <sys/eventfd.h>
int rsys_intercept_net_basic(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct pending_sys *pend = ctx->pend;
  const uint32_t MAX_BLOB = RSYS_MAX_BLOB;
  const uint32_t MAX_ADDR = RSYS_MAX_ADDR;
  const uint32_t MAX_CTRL = RSYS_MAX_CTRL;

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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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
    int fd_remote = rsys_map_fd(ctx, fd_local);
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
    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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
    int fd_remote = rsys_map_fd(ctx, fd_local);
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
    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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


  return 0;
}
