#include "src/rsysd/rsysd_internal.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int rsysd_handle_fs(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  struct rsys_resp resp;

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
    return 1;
  }

  if (type == RSYS_REQ_CLOSE) {
    if (require_len(len, 8) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int err;
    int64_t r = do_syscall_ret(__NR_close, (long)fd, 0, 0, 0, 0, 0, &err);
    vlog("[rsysd] close(%ld) -> %" PRId64 " errno=%d\n", (long)fd, r, err);
    rsys_resp_set(&resp, r, err, 0);
    if (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) return -1;
    return 1;
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
    return (rc < 0) ? -1 : 1;
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
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
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
    vlog("[rsysd] pread64(%ld, %llu, off=%" PRId64 ") -> %" PRId64 " errno=%d\n", (long)fd, (unsigned long long)count, off,
         r, err);
    rsys_resp_set(&resp, r, err, data_len);

    uint32_t out_len = (uint32_t)sizeof(resp) + data_len;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) die("malloc");
    memcpy(out, &resp, sizeof(resp));
    if (data_len) memcpy(out + sizeof(resp), buf, data_len);

    int rc = rsys_send_msg(cfd, type, out, out_len);
    free(out);
    free(buf);
    return (rc < 0) ? -1 : 1;
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
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_LSEEK) {
    if (require_len(len, 24) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t off = rsys_get_s64(p + 8);
    int64_t whence = rsys_get_s64(p + 16);

    int err;
    int64_t r = do_syscall_ret(__NR_lseek, (long)fd, (long)off, (long)whence, 0, 0, 0, &err);
    vlog("[rsysd] lseek(%ld, off=%" PRId64 ", whence=%" PRId64 ") -> %" PRId64 " errno=%d\n", (long)fd, off, whence, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
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
    return (rc < 0) ? -1 : 1;
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
    return (rc < 0) ? -1 : 1;
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
    return (rc < 0) ? -1 : 1;
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
    return (rc < 0) ? -1 : 1;
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
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
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
    return (rc < 0) ? -1 : 1;
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
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
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
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
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
    int64_t r = do_syscall_ret(__NR_renameat2, (long)olddirfd, (long)oldp, (long)newdirfd, (long)newp, (long)flags, 0, &err);
    vlog("[rsysd] renameat2(%ld, %s, %ld, %s, flags=0x%lx) -> %" PRId64 " errno=%d\n", (long)olddirfd, oldp, (long)newdirfd,
         newp, (long)flags, r, err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
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
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
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
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_FCHDIR) {
    if (require_len(len, 8) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int err;
    int64_t r = do_syscall_ret(__NR_fchdir, (long)fd, 0, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  return 0;
}

