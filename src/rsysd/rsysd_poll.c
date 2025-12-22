#include "src/rsysd/rsysd_internal.h"

#include <poll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int rsysd_handle_poll(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  struct rsys_resp resp;

  if (type == RSYS_REQ_PPOLL) {
    if (require_len(len, 32) < 0) return -1;
    uint32_t nfds = rsys_get_u32(p + 0);
    uint32_t has_tmo = rsys_get_u32(p + 4);
    uint32_t has_sig = rsys_get_u32(p + 8);
    uint32_t sigsz = rsys_get_u32(p + 12);
    int64_t tsec = rsys_get_s64(p + 16);
    int64_t tnsec = rsys_get_s64(p + 24);
    if (nfds > 4096) nfds = 4096;

    uint32_t need = 32 + nfds * 16 + (has_sig ? sigsz : 0);
    if (require_len(len, need) < 0) return -1;

    struct pollfd *pfds = NULL;
    if (nfds) {
      pfds = (struct pollfd *)calloc(nfds, sizeof(*pfds));
      if (!pfds) die("calloc");
    }
    uint32_t off = 32;
    for (uint32_t i = 0; i < nfds; i++) {
      int64_t fd = rsys_get_s64(p + off + 0);
      uint32_t events = rsys_get_u32(p + off + 8);
      pfds[i].fd = (int)fd;
      pfds[i].events = (short)(uint16_t)events;
      pfds[i].revents = 0;
      off += 16;
    }

    struct timespec ts;
    struct timespec *tsp = NULL;
    if (has_tmo) {
      ts.tv_sec = (time_t)tsec;
      ts.tv_nsec = (long)tnsec;
      tsp = &ts;
    }

    void *sigp = NULL;
    if (has_sig && sigsz) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
      sigp = (void *)(p + 32 + nfds * 16);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    }

    int err;
    int64_t r = do_syscall_ret(__NR_ppoll, (long)pfds, (long)nfds, (long)tsp, (long)sigp, (long)sigsz, 0, &err);
    if (r >= 0) {
      uint32_t payload_len = 4 + nfds * 4;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp) + 0, nfds);
      for (uint32_t i = 0; i < nfds; i++) {
        rsys_put_u32(out + sizeof(resp) + 4 + i * 4, (uint32_t)(uint16_t)pfds[i].revents);
      }
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(pfds);
      return (rc < 0) ? -1 : 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(pfds);
    return (rc < 0) ? -1 : 1;
  }

  return 0;
}

