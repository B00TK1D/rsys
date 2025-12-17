#pragma once

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <endian.h>
#include <sys/types.h>

// Simple framed protocol over TCP.
// All integer fields are big-endian on the wire.

#define RSYS_MAGIC 0x52535953u // 'RSYS'
#define RSYS_VERSION 1u

enum rsys_msg_type {
  RSYS_REQ_OPENAT = 1,
  RSYS_REQ_CLOSE = 2,
  RSYS_REQ_READ = 3,
  RSYS_REQ_WRITE = 4,
  RSYS_REQ_PREAD64 = 5,
  RSYS_REQ_PWRITE64 = 6,
  RSYS_REQ_LSEEK = 7,
  RSYS_REQ_NEWFSTATAT = 8,
  RSYS_REQ_FSTAT = 9,
  RSYS_REQ_STATX = 10,
  RSYS_REQ_GETDENTS64 = 11,
  RSYS_REQ_ACCESS = 12,
  RSYS_REQ_READLINKAT = 13,
  RSYS_REQ_UNLINKAT = 14,
  RSYS_REQ_MKDIRAT = 15,
  RSYS_REQ_RENAMEAT2 = 16,
  RSYS_REQ_UTIMENSAT = 17,

  // Network / socket / readiness syscalls
  RSYS_REQ_SOCKET = 100,
  RSYS_REQ_SOCKETPAIR = 101,
  RSYS_REQ_BIND = 102,
  RSYS_REQ_LISTEN = 103,
  RSYS_REQ_ACCEPT = 104,
  RSYS_REQ_ACCEPT4 = 105,
  RSYS_REQ_CONNECT = 106,
  RSYS_REQ_SHUTDOWN = 107,
  RSYS_REQ_GETSOCKNAME = 108,
  RSYS_REQ_GETPEERNAME = 109,
  RSYS_REQ_SETSOCKOPT = 110,
  RSYS_REQ_GETSOCKOPT = 111,
  RSYS_REQ_SENDTO = 112,
  RSYS_REQ_RECVFROM = 113,
  RSYS_REQ_SENDMSG = 114,
  RSYS_REQ_RECVMSG = 115,
  RSYS_REQ_FCNTL = 116,
  RSYS_REQ_EPOLL_CREATE1 = 117,
  RSYS_REQ_EPOLL_CTL = 118,
  RSYS_REQ_EPOLL_WAIT = 119,
  RSYS_REQ_PPOLL = 120,
  RSYS_REQ_EPOLL_PWAIT = 121,
};

struct rsys_hdr {
  uint32_t magic_be;
  uint16_t version_be;
  uint16_t type_be;
  uint32_t len_be; // payload length
};

static inline uint16_t rsys_htobe16_u16(uint16_t v) { return htobe16(v); }
static inline uint32_t rsys_htobe32_u32(uint32_t v) { return htobe32(v); }
static inline uint64_t rsys_htobe64_u64(uint64_t v) { return htobe64(v); }
static inline uint16_t rsys_be16toh_u16(uint16_t v) { return be16toh(v); }
static inline uint32_t rsys_be32toh_u32(uint32_t v) { return be32toh(v); }
static inline uint64_t rsys_be64toh_u64(uint64_t v) { return be64toh(v); }

static inline void rsys_hdr_init(struct rsys_hdr *h, uint16_t type, uint32_t len) {
  h->magic_be = rsys_htobe32_u32(RSYS_MAGIC);
  h->version_be = rsys_htobe16_u16(RSYS_VERSION);
  h->type_be = rsys_htobe16_u16(type);
  h->len_be = rsys_htobe32_u32(len);
}

// Common response header for all requests.
// raw_ret: syscall return value (>=0) or -1 (like libc wrappers).
// err_no: errno value if raw_ret == -1, else 0.
// data_len: trailing data bytes length.
struct rsys_resp {
  int64_t raw_ret_be;
  int32_t err_no_be;
  uint32_t data_len_be;
};

static inline void rsys_resp_set(struct rsys_resp *r, int64_t raw_ret, int32_t err_no, uint32_t data_len) {
  r->raw_ret_be = (int64_t)rsys_htobe64_u64((uint64_t)raw_ret);
  r->err_no_be = (int32_t)rsys_htobe32_u32((uint32_t)err_no);
  r->data_len_be = rsys_htobe32_u32(data_len);
}

static inline int64_t rsys_resp_raw_ret(const struct rsys_resp *r) {
  return (int64_t)rsys_be64toh_u64((uint64_t)r->raw_ret_be);
}

static inline int32_t rsys_resp_err_no(const struct rsys_resp *r) {
  return (int32_t)rsys_be32toh_u32((uint32_t)r->err_no_be);
}

static inline uint32_t rsys_resp_data_len(const struct rsys_resp *r) {
  return rsys_be32toh_u32(r->data_len_be);
}

static inline int rsys_send_all(int fd, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;
  while (len) {
    ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 0;
}

static inline int rsys_recv_all(int fd, void *buf, size_t len) {
  uint8_t *p = (uint8_t *)buf;
  while (len) {
    ssize_t n = recv(fd, p, len, 0);
    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 0;
}

static inline int rsys_send_msg(int fd, uint16_t type, const void *payload, uint32_t len) {
  struct rsys_hdr h;
  rsys_hdr_init(&h, type, len);
  if (rsys_send_all(fd, &h, sizeof(h)) < 0) return -1;
  if (len && rsys_send_all(fd, payload, len) < 0) return -1;
  return 0;
}

static inline int rsys_recv_hdr(int fd, struct rsys_hdr *h) {
  if (rsys_recv_all(fd, h, sizeof(*h)) < 0) return -1;
  uint32_t magic = rsys_be32toh_u32(h->magic_be);
  uint16_t ver = rsys_be16toh_u16(h->version_be);
  if (magic != RSYS_MAGIC || ver != RSYS_VERSION) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static inline uint16_t rsys_hdr_type(const struct rsys_hdr *h) { return rsys_be16toh_u16(h->type_be); }
static inline uint32_t rsys_hdr_len(const struct rsys_hdr *h) { return rsys_be32toh_u32(h->len_be); }

// Helpers for encoding fixed-width integers into a byte buffer.
static inline void rsys_put_u64(uint8_t *dst, uint64_t v) {
  uint64_t be = rsys_htobe64_u64(v);
  memcpy(dst, &be, sizeof(be));
}
static inline void rsys_put_u32(uint8_t *dst, uint32_t v) {
  uint32_t be = rsys_htobe32_u32(v);
  memcpy(dst, &be, sizeof(be));
}
static inline void rsys_put_s64(uint8_t *dst, int64_t v) { rsys_put_u64(dst, (uint64_t)v); }
static inline void rsys_put_s32(uint8_t *dst, int32_t v) { rsys_put_u32(dst, (uint32_t)v); }

static inline uint64_t rsys_get_u64(const uint8_t *src) {
  uint64_t be;
  memcpy(&be, src, sizeof(be));
  return rsys_be64toh_u64(be);
}
static inline uint32_t rsys_get_u32(const uint8_t *src) {
  uint32_t be;
  memcpy(&be, src, sizeof(be));
  return rsys_be32toh_u32(be);
}
static inline int64_t rsys_get_s64(const uint8_t *src) { return (int64_t)rsys_get_u64(src); }
static inline int32_t rsys_get_s32(const uint8_t *src) { return (int32_t)rsys_get_u32(src); }
