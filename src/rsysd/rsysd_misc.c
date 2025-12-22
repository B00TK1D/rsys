#include "src/rsysd/rsysd_internal.h"

#include <limits.h>
#include <pwd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

extern char **environ;

int rsysd_handle_misc(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  (void)p;
  struct rsys_resp resp;

  if (type == RSYS_REQ_UNAME) {
    if (require_len(len, 0) < 0) return -1;
    struct utsname u;
    int err;
    int64_t r = do_syscall_ret(__NR_uname, (long)&u, 0, 0, 0, 0, 0, &err);
    if (r == 0) {
      uint32_t dlen = (uint32_t)sizeof(u);
      uint32_t out_len = (uint32_t)sizeof(resp) + dlen;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, dlen);
      memcpy(out, &resp, sizeof(resp));
      memcpy(out + sizeof(resp), &u, sizeof(u));
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      return (rc < 0) ? -1 : 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_SETHOSTNAME || type == RSYS_REQ_SETDOMAINNAME) {
    if (require_len(len, 4) < 0) return -1;
    uint32_t nlen = rsys_get_u32(p + 0);
    if (nlen > 4096) nlen = 4096;
    if (require_blob(len, 4, nlen) < 0) return -1;
    const char *name = (const char *)(p + 4);
    int err;
    long nr = (type == RSYS_REQ_SETHOSTNAME) ? __NR_sethostname : __NR_setdomainname;
    int64_t r = do_syscall_ret(nr, (long)name, (long)nlen, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_GETENV) {
    if (require_len(len, 0) < 0) return -1;

    // Return environment as NUL-separated "KEY=VAL\0..." bytes (like /proc/self/environ).
    size_t total = 0;
    for (char **ep = environ; ep && *ep; ep++) {
      total += strlen(*ep) + 1;
      if (total > (1u << 20)) { // 1MB cap
        total = (1u << 20);
        break;
      }
    }

    uint32_t dlen = (uint32_t)total;
    uint32_t out_len = (uint32_t)sizeof(resp) + dlen;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");

    rsys_resp_set(&resp, 0, 0, dlen);
    memcpy(out, &resp, sizeof(resp));

    uint8_t *w = out + sizeof(resp);
    size_t left = total;
    for (char **ep = environ; ep && *ep && left; ep++) {
      size_t n = strlen(*ep) + 1;
      if (n > left) n = left;
      memcpy(w, *ep, n);
      w += n;
      left -= n;
    }

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    return (rc < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_GETIDS) {
    if (require_len(len, 0) < 0) return -1;
    pid_t pid = getpid();
    pid_t ppid = getppid();
    pid_t tid = (pid_t)syscall(__NR_gettid);
    pid_t pgid = getpgrp();
    pid_t sid = getsid(0);
    uint8_t out[sizeof(resp) + 5 * 8];
    rsys_resp_set(&resp, 0, 0, 5 * 8);
    memcpy(out, &resp, sizeof(resp));
    rsys_put_s64(out + sizeof(resp) + 0, (int64_t)pid);
    rsys_put_s64(out + sizeof(resp) + 8, (int64_t)tid);
    rsys_put_s64(out + sizeof(resp) + 16, (int64_t)ppid);
    rsys_put_s64(out + sizeof(resp) + 24, (int64_t)pgid);
    rsys_put_s64(out + sizeof(resp) + 32, (int64_t)sid);
    if (rsys_send_msg(cfd, type, out, (uint32_t)sizeof(out)) < 0) return -1;
    return 1;
  }

  return 0;
}

