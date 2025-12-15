#pragma once

#include <stdint.h>
#include <stddef.h>

#define RSYS_MAGIC 0x52535953u /* 'RSYS' */
#define RSYS_VERSION 1

#define RSYS_TYPE_RESP_FLAG 0x8000u

enum rsys_op {
  /* Control */
  RSYS_OP_HELLO = 0,

  /* Filesystem */
  RSYS_OP_OPEN = 1,
  RSYS_OP_OPENAT = 2,
  RSYS_OP_CLOSE = 3,
  RSYS_OP_READ = 4,
  RSYS_OP_WRITE = 5,
  RSYS_OP_PREAD = 6,
  RSYS_OP_PWRITE = 7,
  RSYS_OP_LSEEK = 8,
  RSYS_OP_STAT = 9,
  RSYS_OP_LSTAT = 10,
  RSYS_OP_FSTAT = 11,
  RSYS_OP_FSTATAT = 12,
  RSYS_OP_MKDIR = 13,
  RSYS_OP_MKDIRAT = 14,
  RSYS_OP_CHDIR = 15,
  RSYS_OP_FCHDIR = 16,
  RSYS_OP_GETDENTS64 = 17,
  RSYS_OP_UNLINK = 18,
  RSYS_OP_UNLINKAT = 19,

  /* Networking */
  RSYS_OP_SOCKET = 20,
  RSYS_OP_CONNECT = 21,
  RSYS_OP_SEND = 22,
  RSYS_OP_RECV = 23,
  RSYS_OP_SENDTO = 24,
  RSYS_OP_RECVFROM = 25,
  RSYS_OP_SHUTDOWN = 26,
  RSYS_OP_GETSOCKNAME = 27,
  RSYS_OP_GETPEERNAME = 28,
  RSYS_OP_BIND = 29,
  RSYS_OP_GETSOCKOPT = 30,
  RSYS_OP_SETSOCKOPT = 31,
  RSYS_OP_SENDMSG = 32,
  RSYS_OP_RECVMSG = 33,
  RSYS_OP_RMDIR = 34,
  RSYS_OP_POLL = 35,
  RSYS_OP_FCNTL = 36,
  RSYS_OP_IOCTL_INT = 37,
  RSYS_OP_UNAME = 38,
  RSYS_OP_GETHOSTNAME = 39,
  RSYS_OP_SETHOSTNAME = 40,
  RSYS_OP_SYSINFO = 42,

  /* FD management */
  RSYS_OP_DUP = 41,

  /* Newer Linux syscalls (used by modern glibc/procps) */
  RSYS_OP_OPENAT2 = 43,
  RSYS_OP_STATX = 44,
};

struct rsys_hdr {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t len; /* payload length in bytes */
};

int rsys_send_frame(int fd, uint16_t type, const void *payload, uint32_t len);
int rsys_recv_frame(int fd, uint16_t *type_out, void *buf, uint32_t buf_cap, uint32_t *len_out);

/* Connect using only numeric IPv4/IPv6 literals (no DNS). */
int rsys_connect_tcp(const char *ip, const char *port);

/* Send request frame, receive matching response frame. */
int rsys_rpc(int fd,
             uint16_t op,
             const void *req,
             uint32_t req_len,
             void *resp_buf,
             uint32_t resp_cap,
             uint32_t *resp_len_out);
