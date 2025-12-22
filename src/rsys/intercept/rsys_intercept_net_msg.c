#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"
#include "src/rsys/intercept/rsys_intercept_limits.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

int rsys_intercept_net_msg(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct pending_sys *pend = ctx->pend;
  const uint32_t MAX_BLOB = RSYS_MAX_BLOB;
  const uint32_t MAX_ADDR = RSYS_MAX_ADDR;
  const uint32_t MAX_CTRL = RSYS_MAX_CTRL;
  const uint32_t MAX_IOV = RSYS_MAX_IOV;

  // sendmsg(fd, msg, flags)
  if (nr == __NR_sendmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msg_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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

    int fd_remote = rsys_map_fd(ctx, fd_local);
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
    int fd_remote = rsys_map_fd(ctx, fd_local);
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


  return 0;
}
