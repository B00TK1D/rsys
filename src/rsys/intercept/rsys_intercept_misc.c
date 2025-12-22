#define _GNU_SOURCE

#include "src/rsys/intercept/rsys_intercept_dispatch.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

int rsys_intercept_misc(struct rsys_intercept_ctx *ctx, long nr) {
  pid_t pid = ctx->pid;
  struct user_regs_struct *regs = ctx->regs;
  int sock = ctx->sock;
  struct pending_sys *pend = ctx->pend;

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
      return rsys_deny_syscall(ctx, nr, EPERM);
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


  return 0;
}
