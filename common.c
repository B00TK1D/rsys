#define _GNU_SOURCE
#include "common.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int send_all(int fd, const void *p, size_t n) {
  const uint8_t *b = (const uint8_t *)p;
  size_t off = 0;
  while (off < n) {
    ssize_t r = (ssize_t)syscall(SYS_sendto, fd, b + off, n - off, MSG_NOSIGNAL, NULL, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    off += (size_t)r;
  }
  return 0;
}

static int recv_all(int fd, void *p, size_t n) {
  uint8_t *b = (uint8_t *)p;
  size_t off = 0;
  while (off < n) {
    ssize_t r = (ssize_t)syscall(SYS_recvfrom, fd, b + off, n - off, 0, NULL, NULL);
    if (r == 0) return -1;
    if (r < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    off += (size_t)r;
  }
  return 0;
}

int rsys_send_frame(int fd, uint16_t type, const void *payload, uint32_t len) {
  struct rsys_hdr h;
  h.magic = htonl(RSYS_MAGIC);
  h.version = htons(RSYS_VERSION);
  h.type = htons(type);
  h.len = htonl(len);

  if (send_all(fd, &h, sizeof(h)) < 0) return -1;
  if (len > 0 && payload) {
    if (send_all(fd, payload, len) < 0) return -1;
  }
  return 0;
}

int rsys_recv_frame(int fd, uint16_t *type_out, void *buf, uint32_t buf_cap, uint32_t *len_out) {
  struct rsys_hdr h;
  if (recv_all(fd, &h, sizeof(h)) < 0) return -1;

  uint32_t magic = ntohl(h.magic);
  uint16_t version = ntohs(h.version);
  uint16_t type = ntohs(h.type);
  uint32_t len = ntohl(h.len);

  if (magic != RSYS_MAGIC || version != RSYS_VERSION) return -1;
  if (len > buf_cap) return -1;
  if (len > 0) {
    if (recv_all(fd, buf, len) < 0) return -1;
  }

  if (type_out) *type_out = type;
  if (len_out) *len_out = len;
  return 0;
}

int rsys_connect_tcp(const char *ip, const char *port) {
  if (!ip || !port) return -1;

  char ipbuf[256];
  if (ip[0] == '[') {
    size_t n = strnlen(ip, sizeof(ipbuf));
    if (n < 3 || n >= sizeof(ipbuf)) return -1;
    if (ip[n - 1] != ']') return -1;
    memcpy(ipbuf, ip + 1, n - 2);
    ipbuf[n - 2] = '\0';
    ip = ipbuf;
  }

  char *end = NULL;
  unsigned long p = strtoul(port, &end, 10);
  if (!end || *end != '\0' || p == 0 || p > 65535ul) return -1;

  struct sockaddr_storage ss;
  socklen_t slen = 0;
  memset(&ss, 0, sizeof(ss));

  struct in_addr in4;
  if (inet_pton(AF_INET, ip, &in4) == 1) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons((uint16_t)p);
    sin->sin_addr = in4;
    slen = (socklen_t)sizeof(*sin);
  } else {
    struct in6_addr in6;
    if (inet_pton(AF_INET6, ip, &in6) != 1) return -1;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons((uint16_t)p);
    sin6->sin6_addr = in6;
    slen = (socklen_t)sizeof(*sin6);
  }

  int fd = (int)syscall(SYS_socket, ss.ss_family, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  if (syscall(SYS_connect, fd, (const struct sockaddr *)&ss, slen) != 0) {
    int e = errno;
    (void)syscall(SYS_close, fd);
    errno = e;
    return -1;
  }

  return fd;
}

int rsys_rpc(int fd,
             uint16_t op,
             const void *req,
             uint32_t req_len,
             void *resp_buf,
             uint32_t resp_cap,
             uint32_t *resp_len_out) {
  if (rsys_send_frame(fd, op, req, req_len) != 0) return -1;
  uint16_t rtype = 0;
  uint32_t rlen = 0;
  if (rsys_recv_frame(fd, &rtype, resp_buf, resp_cap, &rlen) != 0) return -1;
  if (rtype != (uint16_t)(op | RSYS_TYPE_RESP_FLAG)) return -1;
  if (resp_len_out) *resp_len_out = rlen;
  return 0;
}
