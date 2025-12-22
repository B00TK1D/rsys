#include "src/rsys/rsys_internal.h"

#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int connect_tcp(const char *host, const char *port_str) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = NULL;
  int rc = getaddrinfo(host, port_str, &hints, &res);
  if (rc != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
    return -1;
  }

  int fd = -1;
  for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

int rsys_call(int sock, uint16_t type, const uint8_t *req, uint32_t req_len, struct rsys_resp *out_resp,
                     uint8_t **out_data, uint32_t *out_data_len) {
  if (rsys_send_msg(sock, type, req, req_len) < 0) return -1;

  struct rsys_hdr h;
  if (rsys_recv_hdr(sock, &h) < 0) return -1;
  uint16_t rtype = rsys_hdr_type(&h);
  uint32_t rlen = rsys_hdr_len(&h);
  if (rtype != type || rlen < sizeof(struct rsys_resp)) {
    errno = EPROTO;
    return -1;
  }

  uint8_t *buf = (uint8_t *)malloc(rlen);
  if (!buf) return -1;
  if (rsys_recv_all(sock, buf, rlen) < 0) {
    free(buf);
    return -1;
  }

  memcpy(out_resp, buf, sizeof(*out_resp));
  uint32_t dlen = rsys_resp_data_len(out_resp);
  if (sizeof(struct rsys_resp) + dlen != rlen) {
    free(buf);
    errno = EPROTO;
    return -1;
  }

  *out_data_len = dlen;
  if (dlen) {
    *out_data = (uint8_t *)malloc(dlen);
    if (!*out_data) {
      free(buf);
      return -1;
    }
    memcpy(*out_data, buf + sizeof(struct rsys_resp), dlen);
  } else {
    *out_data = NULL;
  }
  free(buf);
  return 0;
}

void remote_chdir_best_effort(int sock, const char *path) {
  if (!path || path[0] != '/') return;
  uint32_t plen = (uint32_t)strlen(path) + 1;
  if (plen > 4096) return;

  uint32_t req_len = 4 + plen;
  uint8_t *req = (uint8_t *)malloc(req_len);
  if (!req) return;
  rsys_put_u32(req + 0, plen);
  memcpy(req + 4, path, plen);

  struct rsys_resp resp;
  uint8_t *data = NULL;
  uint32_t data_len = 0;
  if (rsys_call(sock, RSYS_REQ_CHDIR, req, req_len, &resp, &data, &data_len) < 0) {
    free(req);
    return;
  }
  free(req);
  free(data);
}

void remote_close_best_effort(int sock, int remote_fd) {
  uint8_t req[8];
  rsys_put_s64(req + 0, (int64_t)remote_fd);
  struct rsys_resp resp;
  uint8_t *data = NULL;
  uint32_t data_len = 0;
  if (rsys_call(sock, RSYS_REQ_CLOSE, req, sizeof(req), &resp, &data, &data_len) < 0) return;
  free(data);
}
