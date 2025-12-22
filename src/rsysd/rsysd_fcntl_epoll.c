#include "src/rsysd/rsysd_internal.h"

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int rsysd_handle_fcntl_epoll(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  struct rsys_resp resp;

  if (type == RSYS_REQ_FCNTL) {
    if (require_len(len, 28) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t cmd = rsys_get_s64(p + 8);
    uint64_t arg = rsys_get_u64(p + 16);
    uint32_t has_flock = rsys_get_u32(p + 24);
    struct flock fl;
    void *argp = (void *)(uintptr_t)arg;
    if (has_flock) {
      if (require_blob(len, 28, (uint32_t)sizeof(fl)) < 0) return -1;
      memcpy(&fl, p + 28, sizeof(fl));
      argp = &fl;
    }
    int err;
    int64_t r = do_syscall_ret(__NR_fcntl, (long)fd, (long)cmd, (long)argp, 0, 0, 0, &err);
    if (has_flock && cmd == F_GETLK && r == 0) {
      uint32_t out_len = (uint32_t)sizeof(resp) + (uint32_t)sizeof(fl);
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, (uint32_t)sizeof(fl));
      memcpy(out, &resp, sizeof(resp));
      memcpy(out + sizeof(resp), &fl, sizeof(fl));
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      return (rc < 0) ? -1 : 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_EPOLL_CREATE1) {
    if (require_len(len, 8) < 0) return -1;
    int64_t flags = rsys_get_s64(p + 0);
    int err;
    int64_t r = do_syscall_ret(__NR_epoll_create1, (long)flags, 0, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_EPOLL_CTL) {
    if (require_len(len, 32) < 0) return -1;
    int64_t epfd = rsys_get_s64(p + 0);
    int64_t op = rsys_get_s64(p + 8);
    int64_t fd = rsys_get_s64(p + 16);
    uint32_t has_ev = rsys_get_u32(p + 24);
    uint32_t ev_len = rsys_get_u32(p + 28);
    struct epoll_event ev;
    struct epoll_event *evp = NULL;
    if (has_ev) {
      if (ev_len != sizeof(ev)) {
        errno = EPROTO;
        return -1;
      }
      if (require_blob(len, 32, ev_len) < 0) return -1;
      memcpy(&ev, p + 32, sizeof(ev));
      evp = &ev;
    }
    int err;
    int64_t r = do_syscall_ret(__NR_epoll_ctl, (long)epfd, (long)op, (long)fd, (long)evp, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_EPOLL_WAIT) {
    if (require_len(len, 24) < 0) return -1;
    int64_t epfd = rsys_get_s64(p + 0);
    int64_t maxevents = rsys_get_s64(p + 8);
    int64_t timeout = rsys_get_s64(p + 16);
    if (maxevents < 0) maxevents = 0;
    if (maxevents > 4096) maxevents = 4096;

    struct epoll_event *evs = NULL;
    if (maxevents) {
      evs = (struct epoll_event *)malloc((size_t)maxevents * sizeof(*evs));
      if (!evs) die("malloc");
    }
    int err;
    int64_t r = do_syscall_ret(__NR_epoll_wait, (long)epfd, (long)evs, (long)maxevents, (long)timeout, 0, 0, &err);
    if (r > 0) {
      uint32_t dlen = (uint32_t)r * (uint32_t)sizeof(*evs);
      uint32_t out_len = (uint32_t)sizeof(resp) + dlen;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, dlen);
      memcpy(out, &resp, sizeof(resp));
      memcpy(out + sizeof(resp), evs, dlen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(evs);
      return (rc < 0) ? -1 : 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(evs);
    return (rc < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_EPOLL_PWAIT) {
    if (require_len(len, 28) < 0) return -1;
    int64_t epfd = rsys_get_s64(p + 0);
    int64_t maxevents = rsys_get_s64(p + 8);
    int64_t timeout = rsys_get_s64(p + 16);
    uint32_t sigsz = rsys_get_u32(p + 24);
    if (maxevents < 0) maxevents = 0;
    if (maxevents > 4096) maxevents = 4096;
    if (sigsz > 128) sigsz = 128;
    if (require_blob(len, 28, sigsz) < 0) return -1;
    const void *sigp = sigsz ? (const void *)(p + 28) : NULL;

    struct epoll_event *evs = NULL;
    if (maxevents) {
      evs = (struct epoll_event *)malloc((size_t)maxevents * sizeof(*evs));
      if (!evs) die("malloc");
    }
    int err;
    int64_t r = do_syscall_ret(__NR_epoll_pwait, (long)epfd, (long)evs, (long)maxevents, (long)timeout, (long)sigp, (long)sigsz,
                              &err);
    if (r > 0) {
      uint32_t dlen = (uint32_t)r * (uint32_t)sizeof(*evs);
      uint32_t out_len = (uint32_t)sizeof(resp) + dlen;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, dlen);
      memcpy(out, &resp, sizeof(resp));
      memcpy(out + sizeof(resp), evs, dlen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(evs);
      return (rc < 0) ? -1 : 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(evs);
    return (rc < 0) ? -1 : 1;
  }

  return 0;
}

