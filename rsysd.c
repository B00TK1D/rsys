#define _GNU_SOURCE

#include "rsys_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

static int g_verbose = 0;

static void vlog(const char *fmt, ...) {
  if (!g_verbose) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

static const char *type_name(uint16_t type) {
  switch (type) {
    case RSYS_REQ_OPENAT: return "openat";
    case RSYS_REQ_CLOSE: return "close";
    case RSYS_REQ_READ: return "read";
    case RSYS_REQ_WRITE: return "write";
    case RSYS_REQ_PREAD64: return "pread64";
    case RSYS_REQ_PWRITE64: return "pwrite64";
    case RSYS_REQ_LSEEK: return "lseek";
    case RSYS_REQ_NEWFSTATAT: return "newfstatat";
    case RSYS_REQ_FSTAT: return "fstat";
    case RSYS_REQ_STATX: return "statx";
    case RSYS_REQ_GETDENTS64: return "getdents64";
    case RSYS_REQ_ACCESS: return "access";
    case RSYS_REQ_READLINKAT: return "readlinkat";
    case RSYS_REQ_UNLINKAT: return "unlinkat";
    case RSYS_REQ_MKDIRAT: return "mkdirat";
    case RSYS_REQ_RENAMEAT2: return "renameat2";
    case RSYS_REQ_UTIMENSAT: return "utimensat";
    case RSYS_REQ_SOCKET: return "socket";
    case RSYS_REQ_SOCKETPAIR: return "socketpair";
    case RSYS_REQ_BIND: return "bind";
    case RSYS_REQ_LISTEN: return "listen";
    case RSYS_REQ_ACCEPT: return "accept";
    case RSYS_REQ_ACCEPT4: return "accept4";
    case RSYS_REQ_CONNECT: return "connect";
    case RSYS_REQ_SHUTDOWN: return "shutdown";
    case RSYS_REQ_GETSOCKNAME: return "getsockname";
    case RSYS_REQ_GETPEERNAME: return "getpeername";
    case RSYS_REQ_SETSOCKOPT: return "setsockopt";
    case RSYS_REQ_GETSOCKOPT: return "getsockopt";
    case RSYS_REQ_SENDTO: return "sendto";
    case RSYS_REQ_RECVFROM: return "recvfrom";
    case RSYS_REQ_SENDMSG: return "sendmsg";
    case RSYS_REQ_RECVMSG: return "recvmsg";
    case RSYS_REQ_FCNTL: return "fcntl";
    case RSYS_REQ_EPOLL_CREATE1: return "epoll_create1";
    case RSYS_REQ_EPOLL_CTL: return "epoll_ctl";
    case RSYS_REQ_EPOLL_WAIT: return "epoll_wait";
    case RSYS_REQ_EPOLL_PWAIT: return "epoll_pwait";
    case RSYS_REQ_PPOLL: return "ppoll";
    case RSYS_REQ_UNAME: return "uname";
    case RSYS_REQ_SETHOSTNAME: return "sethostname";
    case RSYS_REQ_SETDOMAINNAME: return "setdomainname";
    case RSYS_REQ_GETENV: return "getenv";
    case RSYS_REQ_CHDIR: return "chdir";
    case RSYS_REQ_FCHDIR: return "fchdir";
    default: return "unknown";
  }
}

static int require_len(uint32_t len, uint32_t need) {
  if (len < need) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int require_blob(uint32_t len, uint32_t off, uint32_t blob_len) {
  if (off > len || blob_len > len - off) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int64_t do_syscall_ret(long nr, long a1, long a2, long a3, long a4, long a5, long a6, int *out_errno) {
  errno = 0;
  long ret = syscall(nr, a1, a2, a3, a4, a5, a6);
  if (ret == -1) {
    *out_errno = errno;
    return -1;
  }
  *out_errno = 0;
  return (int64_t)ret;
}

static int handle_one(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  struct rsys_resp resp;

  vlog("[rsysd] req type=%u (%s) len=%u\n", type, type_name(type), len);

  if (type == RSYS_REQ_OPENAT) {
    // payload: s64 dirfd, s64 flags, s64 mode, u32 path_len, bytes path
    if (require_len(len, 28) < 0) return -1;
    int64_t dirfd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    int64_t mode = rsys_get_s64(p + 16);
    uint32_t path_len = rsys_get_u32(p + 24);
    if (require_blob(len, 28, path_len) < 0) return -1;
    const char *path = (const char *)(p + 28);
    if (path[path_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_openat, (long)dirfd, (long)path, (long)flags, (long)mode, 0, 0, &err);
    vlog("[rsysd] openat(%ld, %s, 0x%lx, 0%lo) -> %" PRId64 " errno=%d\n", (long)dirfd, path, (long)flags,
         (unsigned long)mode, r, err);
    rsys_resp_set(&resp, r, err, 0);
    if (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) return -1;
    return 0;
  }

  if (type == RSYS_REQ_CLOSE) {
    if (require_len(len, 8) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int err;
    int64_t r = do_syscall_ret(__NR_close, (long)fd, 0, 0, 0, 0, 0, &err);
    vlog("[rsysd] close(%ld) -> %" PRId64 " errno=%d\n", (long)fd, r, err);
    rsys_resp_set(&resp, r, err, 0);
    if (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) return -1;
    return 0;
  }

  if (type == RSYS_REQ_READ) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint64_t count = rsys_get_u64(p + 8);

    uint8_t *buf = NULL;
    if (count > (1u << 20)) count = (1u << 20); // cap to 1MB per call
    if (count) {
      buf = (uint8_t *)malloc((size_t)count);
      if (!buf) die("malloc");
    }

    int err;
    int64_t r = do_syscall_ret(__NR_read, (long)fd, (long)buf, (long)count, 0, 0, 0, &err);
    uint32_t data_len = (r > 0) ? (uint32_t)r : 0;
    vlog("[rsysd] read(%ld, %llu) -> %" PRId64 " errno=%d\n", (long)fd, (unsigned long long)count, r, err);

    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), buf, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    free(buf);
    return rc;
  }

  if (type == RSYS_REQ_WRITE) {
    if (require_len(len, 12) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint32_t data_len = rsys_get_u32(p + 8);
    if (require_blob(len, 12, data_len) < 0) return -1;
    const uint8_t *data = p + 12;

    int err;
    int64_t r = do_syscall_ret(__NR_write, (long)fd, (long)data, (long)data_len, 0, 0, 0, &err);
    vlog("[rsysd] write(%ld, %u) -> %" PRId64 " errno=%d\n", (long)fd, data_len, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_PREAD64) {
    if (require_len(len, 24) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint64_t count = rsys_get_u64(p + 8);
    int64_t off = rsys_get_s64(p + 16);

    if (count > (1u << 20)) count = (1u << 20);
    uint8_t *buf = NULL;
    if (count) {
      buf = (uint8_t *)malloc((size_t)count);
      if (!buf) die("malloc");
    }

    int err;
    int64_t r = do_syscall_ret(__NR_pread64, (long)fd, (long)buf, (long)count, (long)off, 0, 0, &err);
    uint32_t data_len = (r > 0) ? (uint32_t)r : 0;
    vlog("[rsysd] pread64(%ld, %llu, off=%" PRId64 ") -> %" PRId64 " errno=%d\n", (long)fd, (unsigned long long)count,
         off, r, err);
    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), buf, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    free(buf);
    return rc;
  }

  if (type == RSYS_REQ_PWRITE64) {
    if (require_len(len, 20) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t off = rsys_get_s64(p + 8);
    uint32_t data_len = rsys_get_u32(p + 16);
    if (require_blob(len, 20, data_len) < 0) return -1;
    const uint8_t *data = p + 20;

    int err;
    int64_t r = do_syscall_ret(__NR_pwrite64, (long)fd, (long)data, (long)data_len, (long)off, 0, 0, &err);
    vlog("[rsysd] pwrite64(%ld, %u, off=%" PRId64 ") -> %" PRId64 " errno=%d\n", (long)fd, data_len, off, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_LSEEK) {
    if (require_len(len, 24) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t off = rsys_get_s64(p + 8);
    int64_t whence = rsys_get_s64(p + 16);

    int err;
    int64_t r = do_syscall_ret(__NR_lseek, (long)fd, (long)off, (long)whence, 0, 0, 0, &err);
    vlog("[rsysd] lseek(%ld, off=%" PRId64 ", whence=%" PRId64 ") -> %" PRId64 " errno=%d\n", (long)fd, off, whence, r,
         err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_NEWFSTATAT) {
    if (require_len(len, 20) < 0) return -1;
    int64_t dirfd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t path_len = rsys_get_u32(p + 16);
    if (require_blob(len, 20, path_len) < 0) return -1;
    const char *path = (const char *)(p + 20);
    if (path[path_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    struct stat st;
    int err;
    int64_t r = do_syscall_ret(__NR_newfstatat, (long)dirfd, (long)path, (long)&st, (long)flags, 0, 0, &err);
    uint32_t data_len = (r == 0) ? (uint32_t)sizeof(st) : 0;
    vlog("[rsysd] newfstatat(%ld, %s, flags=0x%lx) -> %" PRId64 " errno=%d\n", (long)dirfd, path, (long)flags, r, err);
    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), &st, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    return rc;
  }

  if (type == RSYS_REQ_FSTAT) {
    if (require_len(len, 8) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    struct stat st;
    int err;
    int64_t r = do_syscall_ret(__NR_fstat, (long)fd, (long)&st, 0, 0, 0, 0, &err);
    uint32_t data_len = (r == 0) ? (uint32_t)sizeof(st) : 0;
    vlog("[rsysd] fstat(%ld) -> %" PRId64 " errno=%d\n", (long)fd, r, err);
    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), &st, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    return rc;
  }

  if (type == RSYS_REQ_STATX) {
    // payload: s64 dirfd, s64 flags, u32 mask, u32 path_len, bytes path
    if (require_len(len, 24) < 0) return -1;
    int64_t dirfd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t mask = rsys_get_u32(p + 16);
    uint32_t path_len = rsys_get_u32(p + 20);
    if (require_blob(len, 24, path_len) < 0) return -1;
    const char *path = (const char *)(p + 24);
    if (path[path_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    struct statx stx;
    int err;
    int64_t r = do_syscall_ret(__NR_statx, (long)dirfd, (long)path, (long)flags, (long)mask, (long)&stx, 0, &err);
    uint32_t data_len = (r == 0) ? (uint32_t)sizeof(stx) : 0;
    vlog("[rsysd] statx(%ld, %s, flags=0x%lx, mask=0x%x) -> %" PRId64 " errno=%d\n", (long)dirfd, path, (long)flags, mask,
         r, err);
    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), &stx, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    return rc;
  }

  if (type == RSYS_REQ_GETDENTS64) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint64_t count = rsys_get_u64(p + 8);

    if (count > (1u << 20)) count = (1u << 20);
    uint8_t *buf = NULL;
    if (count) {
      buf = (uint8_t *)malloc((size_t)count);
      if (!buf) die("malloc");
    }

    int err;
    int64_t r = do_syscall_ret(__NR_getdents64, (long)fd, (long)buf, (long)count, 0, 0, 0, &err);
    uint32_t data_len = (r > 0) ? (uint32_t)r : 0;
    vlog("[rsysd] getdents64(%ld, %llu) -> %" PRId64 " errno=%d\n", (long)fd, (unsigned long long)count, r, err);
    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), buf, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    free(buf);
    return rc;
  }

  if (type == RSYS_REQ_ACCESS) {
    if (require_len(len, 8) < 0) return -1;
    uint32_t mode = rsys_get_u32(p + 0);
    uint32_t path_len = rsys_get_u32(p + 4);
    if (require_blob(len, 8, path_len) < 0) return -1;
    const char *path = (const char *)(p + 8);
    if (path[path_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_access, (long)path, (long)mode, 0, 0, 0, 0, &err);
    vlog("[rsysd] access(%s, mode=0x%x) -> %" PRId64 " errno=%d\n", path, mode, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_READLINKAT) {
    if (require_len(len, 16) < 0) return -1;
    int64_t dirfd = rsys_get_s64(p + 0);
    uint32_t buf_sz = rsys_get_u32(p + 8);
    uint32_t path_len = rsys_get_u32(p + 12);
    if (require_blob(len, 16, path_len) < 0) return -1;
    const char *path = (const char *)(p + 16);
    if (path[path_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    if (buf_sz > (1u << 20)) buf_sz = (1u << 20);
    char *buf = NULL;
    if (buf_sz) {
      buf = (char *)malloc(buf_sz);
      if (!buf) die("malloc");
    }

    int err;
    int64_t r = do_syscall_ret(__NR_readlinkat, (long)dirfd, (long)path, (long)buf, (long)buf_sz, 0, 0, &err);
    uint32_t data_len = (r > 0) ? (uint32_t)r : 0;
    vlog("[rsysd] readlinkat(%ld, %s, bufsz=%u) -> %" PRId64 " errno=%d\n", (long)dirfd, path, buf_sz, r, err);
    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), buf, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    free(buf);
    return rc;
  }

  if (type == RSYS_REQ_UNLINKAT) {
    if (require_len(len, 20) < 0) return -1;
    int64_t dirfd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t path_len = rsys_get_u32(p + 16);
    if (require_blob(len, 20, path_len) < 0) return -1;
    const char *path = (const char *)(p + 20);
    if (path[path_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_unlinkat, (long)dirfd, (long)path, (long)flags, 0, 0, 0, &err);
    vlog("[rsysd] unlinkat(%ld, %s, flags=0x%lx) -> %" PRId64 " errno=%d\n", (long)dirfd, path, (long)flags, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_MKDIRAT) {
    if (require_len(len, 20) < 0) return -1;
    int64_t dirfd = rsys_get_s64(p + 0);
    int64_t mode = rsys_get_s64(p + 8);
    uint32_t path_len = rsys_get_u32(p + 16);
    if (require_blob(len, 20, path_len) < 0) return -1;
    const char *path = (const char *)(p + 20);
    if (path[path_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_mkdirat, (long)dirfd, (long)path, (long)mode, 0, 0, 0, &err);
    vlog("[rsysd] mkdirat(%ld, %s, mode=0%lo) -> %" PRId64 " errno=%d\n", (long)dirfd, path, (unsigned long)mode, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_RENAMEAT2) {
    // payload: s64 olddirfd, s64 newdirfd, s64 flags, u32 old_len, u32 new_len, bytes old, bytes new
    if (require_len(len, 32) < 0) return -1;
    int64_t olddirfd = rsys_get_s64(p + 0);
    int64_t newdirfd = rsys_get_s64(p + 8);
    int64_t flags = rsys_get_s64(p + 16);
    uint32_t old_len = rsys_get_u32(p + 24);
    uint32_t new_len = rsys_get_u32(p + 28);
    if (require_blob(len, 32, old_len) < 0) return -1;
    if (require_blob(len, 32 + old_len, new_len) < 0) return -1;
    const char *oldp = (const char *)(p + 32);
    const char *newp = (const char *)(p + 32 + old_len);
    if (oldp[old_len - 1] != '\0' || newp[new_len - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_renameat2, (long)olddirfd, (long)oldp, (long)newdirfd, (long)newp,
                              (long)flags, 0, &err);
    vlog("[rsysd] renameat2(%ld, %s, %ld, %s, flags=0x%lx) -> %" PRId64 " errno=%d\n", (long)olddirfd, oldp, (long)newdirfd,
         newp, (long)flags, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_UTIMENSAT) {
    // payload: s64 dirfd, s64 flags, u32 has_times, u32 path_len, bytes path (optional), [4*s64 times]
    if (require_len(len, 24) < 0) return -1;
    int64_t dirfd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t has_times = rsys_get_u32(p + 16);
    uint32_t path_len = rsys_get_u32(p + 20);
    const char *path = NULL;
    const uint8_t *tp = p + 24;
    uint32_t left = len - 24;

    if (path_len != 0) {
      if (require_blob(len, 24, path_len) < 0) return -1;
      path = (const char *)(p + 24);
      if (path[path_len - 1] != '\0') {
        errno = EPROTO;
        return -1;
      }
      tp = p + 24 + path_len;
      left = len - (24 + path_len);
    }

    struct timespec ts[2];
    struct timespec *tsp = NULL;
    if (has_times) {
      if (left < 32) {
        errno = EPROTO;
        return -1;
      }
      ts[0].tv_sec = (time_t)rsys_get_s64(tp + 0);
      ts[0].tv_nsec = (long)rsys_get_s64(tp + 8);
      ts[1].tv_sec = (time_t)rsys_get_s64(tp + 16);
      ts[1].tv_nsec = (long)rsys_get_s64(tp + 24);
      tsp = ts;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_utimensat, (long)dirfd, (long)path, (long)tsp, (long)flags, 0, 0, &err);
    vlog("[rsysd] utimensat(%ld, %s, times=%s, flags=0x%lx) -> %" PRId64 " errno=%d\n", (long)dirfd, path ? path : "NULL",
         has_times ? "set" : "NULL", (long)flags, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_SOCKET) {
    if (require_len(len, 24) < 0) return -1;
    int64_t domain = rsys_get_s64(p + 0);
    int64_t stype = rsys_get_s64(p + 8);
    int64_t proto = rsys_get_s64(p + 16);
    int err;
    int64_t r = do_syscall_ret(__NR_socket, (long)domain, (long)stype, (long)proto, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_SOCKETPAIR) {
    if (require_len(len, 24) < 0) return -1;
    int64_t domain = rsys_get_s64(p + 0);
    int64_t stype = rsys_get_s64(p + 8);
    int64_t proto = rsys_get_s64(p + 16);
    int sv[2] = {-1, -1};
    int err;
    int64_t r = do_syscall_ret(__NR_socketpair, (long)domain, (long)stype, (long)proto, (long)sv, 0, 0, &err);
    if (r == 0) {
      uint8_t out[sizeof(resp) + 16];
      rsys_resp_set(&resp, r, err, 16);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_s64(out + sizeof(resp) + 0, (int64_t)sv[0]);
      rsys_put_s64(out + sizeof(resp) + 8, (int64_t)sv[1]);
      return rsys_send_msg(cfd, type, out, (uint32_t)sizeof(out));
    }
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_BIND || type == RSYS_REQ_CONNECT) {
    if (require_len(len, 12) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint32_t addrlen = rsys_get_u32(p + 8);
    if (require_blob(len, 12, addrlen) < 0) return -1;
    const void *addr = addrlen ? (const void *)(p + 12) : NULL;

    int err;
    long nr = (type == RSYS_REQ_BIND) ? __NR_bind : __NR_connect;
    int64_t r = do_syscall_ret(nr, (long)fd, (long)addr, (long)addrlen, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_LISTEN) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t backlog = rsys_get_s64(p + 8);
    int err;
    int64_t r = do_syscall_ret(__NR_listen, (long)fd, (long)backlog, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_ACCEPT || type == RSYS_REQ_ACCEPT4) {
    if (require_len(len, 24) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint32_t want_addr = rsys_get_u32(p + 8);
    uint32_t addr_max = rsys_get_u32(p + 12);
    int64_t flags = rsys_get_s64(p + 16);

    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)addr_max;
    struct sockaddr *sap = want_addr ? (struct sockaddr *)&ss : NULL;
    socklen_t *slenp = want_addr ? &slen : NULL;

    int err;
    int64_t r;
    if (type == RSYS_REQ_ACCEPT4) {
      r = do_syscall_ret(__NR_accept4, (long)fd, (long)sap, (long)slenp, (long)flags, 0, 0, &err);
    } else {
      r = do_syscall_ret(__NR_accept, (long)fd, (long)sap, (long)slenp, 0, 0, 0, &err);
    }

    if (r >= 0 && want_addr) {
      uint32_t out_alen = (uint32_t)slen;
      uint32_t out_len = (uint32_t)sizeof(resp) + 4 + out_alen;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, 4 + out_alen);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp), out_alen);
      if (out_alen) memcpy(out + sizeof(resp) + 4, &ss, out_alen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      return rc;
    }

    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_SENDTO) {
    if (require_len(len, 24) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t dlen = rsys_get_u32(p + 16);
    uint32_t alen = rsys_get_u32(p + 20);
    if (require_blob(len, 24, dlen + alen) < 0) return -1;
    const uint8_t *data = p + 24;
    const void *addr = (alen ? (const void *)(p + 24 + dlen) : NULL);

    int err;
    int64_t r = do_syscall_ret(__NR_sendto, (long)fd, (long)data, (long)dlen, (long)flags, (long)addr, (long)alen, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_RECVFROM) {
    if (require_len(len, 32) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint64_t maxlen = rsys_get_u64(p + 8);
    int64_t flags = rsys_get_s64(p + 16);
    uint32_t want_addr = rsys_get_u32(p + 24);
    uint32_t addr_max = rsys_get_u32(p + 28);

    if (maxlen > (1u << 20)) maxlen = (1u << 20);
    uint8_t *buf = NULL;
    if (maxlen) {
      buf = (uint8_t *)malloc((size_t)maxlen);
      if (!buf) die("malloc");
    }

    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)addr_max;
    struct sockaddr *sap = want_addr ? (struct sockaddr *)&ss : NULL;
    socklen_t *slenp = want_addr ? &slen : NULL;

    int err;
    int64_t r = do_syscall_ret(__NR_recvfrom, (long)fd, (long)buf, (long)maxlen, (long)flags, (long)sap, (long)slenp, &err);
    if (r >= 0) {
      uint32_t out_dlen = (r > 0) ? (uint32_t)r : 0;
      uint32_t out_alen = want_addr ? (uint32_t)slen : 0;
      uint32_t payload_len = 8 + out_dlen + out_alen;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp) + 0, out_dlen);
      rsys_put_u32(out + sizeof(resp) + 4, out_alen);
      if (out_dlen) memcpy(out + sizeof(resp) + 8, buf, out_dlen);
      if (out_alen) memcpy(out + sizeof(resp) + 8 + out_dlen, &ss, out_alen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(buf);
      return rc;
    }

    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(buf);
    return rc;
  }

  if (type == RSYS_REQ_SHUTDOWN) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t how = rsys_get_s64(p + 8);
    int err;
    int64_t r = do_syscall_ret(__NR_shutdown, (long)fd, (long)how, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_GETSOCKNAME || type == RSYS_REQ_GETPEERNAME) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint32_t addr_max = rsys_get_u32(p + 8);

    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)addr_max;
    int err;
    long nr = (type == RSYS_REQ_GETSOCKNAME) ? __NR_getsockname : __NR_getpeername;
    int64_t r = do_syscall_ret(nr, (long)fd, (long)&ss, (long)&slen, 0, 0, 0, &err);
    if (r == 0) {
      uint32_t out_alen = (uint32_t)slen;
      uint32_t payload_len = 4 + out_alen;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp), out_alen);
      if (out_alen) memcpy(out + sizeof(resp) + 4, &ss, out_alen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      return rc;
    }
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_SETSOCKOPT) {
    if (require_len(len, 28) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t level = rsys_get_s64(p + 8);
    int64_t optname = rsys_get_s64(p + 16);
    uint32_t optlen = rsys_get_u32(p + 24);
    if (require_blob(len, 28, optlen) < 0) return -1;
    const void *optval = optlen ? (const void *)(p + 28) : NULL;
    int err;
    int64_t r = do_syscall_ret(__NR_setsockopt, (long)fd, (long)level, (long)optname, (long)optval, (long)optlen, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_GETSOCKOPT) {
    if (require_len(len, 28) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t level = rsys_get_s64(p + 8);
    int64_t optname = rsys_get_s64(p + 16);
    uint32_t optlen_max = rsys_get_u32(p + 24);
    if (optlen_max > 64u * 1024u) optlen_max = 64u * 1024u;
    uint8_t *optval = NULL;
    if (optlen_max) {
      optval = (uint8_t *)malloc(optlen_max);
      if (!optval) die("malloc");
    }
    socklen_t olen = (socklen_t)optlen_max;
    int err;
    int64_t r = do_syscall_ret(__NR_getsockopt, (long)fd, (long)level, (long)optname, (long)optval, (long)&olen, 0, &err);
    if (r == 0) {
      uint32_t out_lenv = (uint32_t)olen;
      uint32_t payload_len = 4 + out_lenv;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp), out_lenv);
      if (out_lenv) memcpy(out + sizeof(resp) + 4, optval, out_lenv);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(optval);
      return rc;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(optval);
    return rc;
  }

  if (type == RSYS_REQ_SENDMSG) {
    if (require_len(len, 32) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t name_len = rsys_get_u32(p + 16);
    uint32_t ctrl_len = rsys_get_u32(p + 20);
    uint32_t data_len = rsys_get_u32(p + 24);
    if (require_blob(len, 32, name_len + ctrl_len + data_len) < 0) return -1;

    const uint8_t *bp = p + 32;
    const void *name = name_len ? (const void *)bp : NULL;
    const void *ctrl = ctrl_len ? (const void *)(bp + name_len) : NULL;
    const void *data = data_len ? (const void *)(bp + name_len + ctrl_len) : NULL;

    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
// syscall(2) does not mutate these input buffers, but the struct fields are non-const.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    mh.msg_name = (void *)name;
    mh.msg_namelen = (socklen_t)name_len;
    mh.msg_control = (void *)ctrl;
    mh.msg_controllen = (size_t)ctrl_len;
    struct iovec iov;
    if (data_len) {
      iov.iov_base = (void *)data;
      iov.iov_len = (size_t)data_len;
      mh.msg_iov = &iov;
      mh.msg_iovlen = 1;
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    int err;
    int64_t r = do_syscall_ret(__NR_sendmsg, (long)fd, (long)&mh, (long)flags, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_RECVMSG) {
    if (require_len(len, 32) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t name_max = rsys_get_u32(p + 16);
    uint32_t ctrl_max = rsys_get_u32(p + 20);
    uint32_t iovcnt = rsys_get_u32(p + 24);
    if (iovcnt > 128) iovcnt = 128;
    if (require_blob(len, 32, iovcnt * 4) < 0) return -1;

    uint32_t total_max = 0;
    for (uint32_t i = 0; i < iovcnt; i++) {
      uint32_t l = rsys_get_u32(p + 32 + i * 4);
      if (l > (1u << 20) - total_max) l = (1u << 20) - total_max;
      total_max += l;
    }

    uint8_t *dbuf = NULL;
    if (total_max) {
      dbuf = (uint8_t *)malloc(total_max);
      if (!dbuf) die("malloc");
    }
    uint8_t *nbuf = NULL;
    if (name_max) {
      nbuf = (uint8_t *)malloc(name_max);
      if (!nbuf) die("malloc");
    }
    uint8_t *cbuf = NULL;
    if (ctrl_max) {
      cbuf = (uint8_t *)malloc(ctrl_max);
      if (!cbuf) die("malloc");
    }

    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_name = nbuf;
    mh.msg_namelen = (socklen_t)name_max;
    mh.msg_control = cbuf;
    mh.msg_controllen = (size_t)ctrl_max;
    struct iovec iov;
    if (total_max) {
      iov.iov_base = dbuf;
      iov.iov_len = (size_t)total_max;
      mh.msg_iov = &iov;
      mh.msg_iovlen = 1;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_recvmsg, (long)fd, (long)&mh, (long)flags, 0, 0, 0, &err);
    if (r >= 0) {
      uint32_t out_dlen = (r > 0) ? (uint32_t)r : 0;
      uint32_t out_nlen = (uint32_t)mh.msg_namelen;
      if (out_nlen > name_max) out_nlen = name_max;
      uint32_t out_clen = (uint32_t)mh.msg_controllen;
      if (out_clen > ctrl_max) out_clen = ctrl_max;
      uint32_t out_mflags = (uint32_t)mh.msg_flags;
      uint32_t payload_len = 16 + out_dlen + out_nlen + out_clen;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp) + 0, out_dlen);
      rsys_put_u32(out + sizeof(resp) + 4, out_nlen);
      rsys_put_u32(out + sizeof(resp) + 8, out_clen);
      rsys_put_u32(out + sizeof(resp) + 12, out_mflags);
      uint8_t *wp = out + sizeof(resp) + 16;
      if (out_dlen) memcpy(wp, dbuf, out_dlen), wp += out_dlen;
      if (out_nlen) memcpy(wp, nbuf, out_nlen), wp += out_nlen;
      if (out_clen) memcpy(wp, cbuf, out_clen), wp += out_clen;
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(dbuf);
      free(nbuf);
      free(cbuf);
      return rc;
    }

    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(dbuf);
    free(nbuf);
    free(cbuf);
    return rc;
  }

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
      return rc;
    }
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_EPOLL_CREATE1) {
    if (require_len(len, 8) < 0) return -1;
    int64_t flags = rsys_get_s64(p + 0);
    int err;
    int64_t r = do_syscall_ret(__NR_epoll_create1, (long)flags, 0, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
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
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
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
      return rc;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(evs);
    return rc;
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
    int64_t r = do_syscall_ret(__NR_epoll_pwait, (long)epfd, (long)evs, (long)maxevents, (long)timeout, (long)sigp,
                              (long)sigsz, &err);
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
      return rc;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(evs);
    return rc;
  }

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
      return rc;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(pfds);
    return rc;
  }

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
      return rc;
    }
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
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
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
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
    return rc;
  }

  if (type == RSYS_REQ_CHDIR) {
    if (require_len(len, 4) < 0) return -1;
    uint32_t plen = rsys_get_u32(p + 0);
    if (plen > 4096) plen = 4096;
    if (require_blob(len, 4, plen) < 0) return -1;
    const char *path = (const char *)(p + 4);
    if (plen == 0 || path[plen - 1] != '\0') {
      errno = EPROTO;
      return -1;
    }
    int err;
    int64_t r = do_syscall_ret(__NR_chdir, (long)path, 0, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  if (type == RSYS_REQ_FCHDIR) {
    if (require_len(len, 8) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int err;
    int64_t r = do_syscall_ret(__NR_fchdir, (long)fd, 0, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return rsys_send_msg(cfd, type, &resp, sizeof(resp));
  }

  errno = ENOSYS;
  return -1;
}

static void serve_client(int cfd) {
  for (;;) {
    struct rsys_hdr h;
    if (rsys_recv_hdr(cfd, &h) < 0) break;
    uint16_t type = rsys_hdr_type(&h);
    uint32_t len = rsys_hdr_len(&h);

    uint8_t *payload = NULL;
    if (len) {
      payload = (uint8_t *)malloc(len);
      if (!payload) die("malloc");
      if (rsys_recv_all(cfd, payload, len) < 0) {
        free(payload);
        break;
      }
    }

    if (handle_one(cfd, type, payload ? payload : (const uint8_t *)"", len) < 0) {
      if (g_verbose) perror("[rsysd] handle_one");
      free(payload);
      break;
    }
    free(payload);
  }
  close(cfd);
}

int main(int argc, char **argv) {
  int argi = 1;
  if (argc > 1 && strcmp(argv[1], "-v") == 0) {
    g_verbose = 1;
    argi++;
  }
  if (argc - argi < 1) {
    fprintf(stderr, "usage: %s [-v] <port>\n", argv[0]);
    return 2;
  }

  int port = atoi(argv[argi]);
  if (port <= 0 || port > 65535) {
    fprintf(stderr, "invalid port\n");
    return 2;
  }

  signal(SIGPIPE, SIG_IGN);

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) die("socket");

  int one = 1;
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) die("setsockopt");

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
  if (listen(s, 16) < 0) die("listen");
  vlog("[rsysd] listening on 0.0.0.0:%d\n", port);

  for (;;) {
    int cfd = accept(s, NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      die("accept");
    }

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
      close(s);

      // Each client gets its own worker process. Ensure a predictable initial
      // working directory for relative remote operations (AT_FDCWD + relative paths).
      // If rsysd is started by a service manager, its inherited cwd can be something
      // surprising (e.g., /bin), which makes commands like `ls` appear to "start" in
      // the wrong directory until the user manually `cd`s.
      const char *home = getenv("HOME");
      if (!(home && home[0] == '/')) home = NULL;
      if (!home) {
        struct passwd pw, *pwp = NULL;
        char buf[16384];
        if (getpwuid_r(getuid(), &pw, buf, sizeof(buf), &pwp) == 0 && pwp && pwp->pw_dir && pwp->pw_dir[0] == '/') {
          home = pwp->pw_dir;
        }
      }
      if (home) {
        if (chdir(home) < 0) {
          // Ignore: keep inherited cwd if home is unusable.
        }
      }
      // Keep PWD consistent with the actual process cwd for shells that rely on it.
      char cwd[PATH_MAX];
      if (getcwd(cwd, sizeof(cwd)) != NULL) {
        (void)setenv("PWD", cwd, 1);
      }

      vlog("[rsysd] client connected\n");
      serve_client(cfd);
      _exit(0);
    }
    close(cfd);
  }
}
