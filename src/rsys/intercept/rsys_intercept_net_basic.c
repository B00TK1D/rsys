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

static int rsys_rewrite_sockaddr_port(struct rsys_intercept_ctx *ctx, uintptr_t *reg_ptr, const void *addr, uint32_t addrlen,
                                      uint16_t new_port_host) {
  if (!ctx || !ctx->regs || !reg_ptr || !addr || addrlen < 4u) return -1;
  if (addrlen > RSYS_MAX_ADDR) addrlen = RSYS_MAX_ADDR;
  uint8_t buf[RSYS_MAX_ADDR];
  memcpy(buf, addr, addrlen);
  uint16_t fam = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
  if (fam != AF_INET && fam != AF_INET6) return -1;
  uint16_t np = htons(new_port_host);
  memcpy(buf + 2, &np, 2);

  uintptr_t scratch = (uintptr_t)((ctx->regs->rsp - 0x5000) & ~(uintptr_t)0xFul);
  if (rsys_write_mem(ctx->pid, scratch, buf, addrlen) < 0) return -1;
  *reg_ptr = scratch;
  return 0;
}

static int rsys_sockaddr_get_port_host(const void *addr, uint32_t addrlen, uint16_t *out_port) {
  if (!addr || addrlen < 4u || !out_port) return 0;
  const uint8_t *b = (const uint8_t *)addr;
  uint16_t fam = (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
  if (fam != AF_INET && fam != AF_INET6) return 0;
  uint16_t pn = 0;
  memcpy(&pn, b + 2, 2);
  *out_port = ntohs(pn);
  return 1;
}

int rsys_intercept_net_basic(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct port_forwards const *pfw_cfg = ctx->pfw_cfg;
  uint32_t *portfw_fd = ctx->portfw_fd;
  size_t portfw_fd_n = ctx->portfw_fd_n;
  struct pending_sys *pend = ctx->pend;
  const uint32_t MAX_BLOB = RSYS_MAX_BLOB;
  const uint32_t MAX_ADDR = RSYS_MAX_ADDR;
  const uint32_t MAX_CTRL = RSYS_MAX_CTRL;

  // socket(domain, type, protocol)
  if (nr == __NR_socket) {
    int domain = (int)regs->rdi;
    int type = (int)regs->rsi;
    int protocol = (int)regs->rdx;

    vlog("[rsys] socket(domain=%d, type=%d, proto=%d) -> remote (local placeholder)\n", domain, type, protocol);

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
    if (rr >= 0) {
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->has_set_rax = 0;     // keep kernel local socket fd (placeholder)
      pend->map_fd_on_exit = 1;  // map local_fd -> remote_fd on syscall exit
      pend->map_remote_fd = (int)rr;
      pend->close_remote_on_fail = 1;
      pend->close_remote_fd = (int)rr;
      // Let the real socket(2) run in the tracee to produce a real socket fd,
      // so we can later choose to run bind/listen locally for port forwarding.
      return 0;
    }

    // Failure: replace syscall with harmless getpid and set error on exit.
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->has_set_rax = 1;
    pend->set_rax = rax;
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    vlog("[rsys] socket -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=%" PRId64 "\n", rr, eno, rax);
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

    // Port forwarding: if the bind targets a forwarded remote port, run bind locally instead.
    if (addr && addrlen >= 4u && pfw_cfg && pfw_cfg->n > 0) {
      uint16_t remote_port = 0;
      if (rsys_sockaddr_get_port_host(addr, addrlen, &remote_port)) {
        uint16_t local_port = 0;
        if (remote_port != 0 && portfw_lookup_local(pfw_cfg, remote_port, &local_port)) {
          vlog("[rsys] bind(fd=%d, port=%u) -> local (portfw to local_port=%u)\n", fd_local, (unsigned)remote_port, (unsigned)local_port);
          // Drop remote mapping for this socket: it is becoming a local listener.
          fdmap_remove_all_local_and_close(ctx->fm, ctx->rrefs, sock, fd_local);
          if (portfw_fd && fd_local >= 0 && (size_t)fd_local < portfw_fd_n) portfw_fd[fd_local] = 0;

          // Rewrite port in sockaddr (don't mutate original memory).
          if (local_port != remote_port) {
            if (rsys_rewrite_sockaddr_port(ctx, (uintptr_t *)&regs->rsi, addr, addrlen, local_port) == 0) {
              regs->rdx = (uint64_t)addrlen;
              if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
            }
          }

          pending_clear(pend);
          pend->active = 1;
          pend->nr = nr;
          pend->has_set_rax = 0; // keep local bind return value
          pend->mark_portfw_on_exit = 1;
          pend->mark_portfw_fd = fd_local;
          pend->mark_portfw_local = local_port;
          pend->mark_portfw_remote = remote_port;
          free(addr);
          return 0; // let kernel bind locally
        }
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
    if (fd_remote < 0) {
      // If this is a local forwarded listening socket, let kernel do getsockname
      // but rewrite the returned port back to the "remote" port for transparency.
      if (nr == __NR_getsockname && portfw_fd && fd_local >= 0 && (size_t)fd_local < portfw_fd_n && portfw_fd[fd_local] != 0) {
        uint32_t enc = portfw_fd[fd_local];
        uint16_t lp = (uint16_t)(enc >> 16);
        uint16_t rp = (uint16_t)(enc & 0xFFFFu);
        pending_clear(pend);
        pend->active = 1;
        pend->nr = nr;
        pend->has_set_rax = 0; // keep local return, we'll only patch memory
        pend->rewrite_getsockname_on_exit = 1;
        pend->rewrite_getsockname_addr = addr_addr;
        pend->rewrite_getsockname_addrlenp = addrlenp;
        pend->rewrite_getsockname_local = lp;
        pend->rewrite_getsockname_remote = rp;
      }
      return 0;
    }

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
