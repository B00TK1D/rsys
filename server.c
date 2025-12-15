#define _GNU_SOURCE
#include "common.h"

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static int g_trace = 0;
static int g_lfd = -1;

static pthread_mutex_t g_clients_mu = PTHREAD_MUTEX_INITIALIZER;
static int *g_clients = NULL;
static size_t g_clients_n = 0;
static size_t g_clients_cap = 0;

static void on_sigint(int sig) {
  (void)sig;
  g_stop = 1;
  /* close() is async-signal-safe; this breaks accept() promptly. */
  if (g_lfd >= 0) {
    close(g_lfd);
    g_lfd = -1;
  }
}

static int listen_tcp(const char *port) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  struct addrinfo *res = NULL;
  int rc = getaddrinfo(NULL, port, &hints, &res);
  if (rc != 0) return -1;

  int fd = -1;
  for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
      close(fd);
      fd = -1;
      continue;
    }
    if (listen(fd, 128) != 0) {
      close(fd);
      fd = -1;
      continue;
    }
    break;
  }

  freeaddrinfo(res);
  return fd;
}

struct client_ctx {
  int fd;
};

static void clients_add(int fd) {
  pthread_mutex_lock(&g_clients_mu);
  if (g_clients_n == g_clients_cap) {
    size_t ncap = g_clients_cap ? (g_clients_cap * 2) : 64;
    int *n = (int *)realloc(g_clients, ncap * sizeof(*n));
    if (n) {
      g_clients = n;
      g_clients_cap = ncap;
    }
  }
  if (g_clients_n < g_clients_cap) g_clients[g_clients_n++] = fd;
  pthread_mutex_unlock(&g_clients_mu);
}

static void clients_del(int fd) {
  pthread_mutex_lock(&g_clients_mu);
  for (size_t i = 0; i < g_clients_n; i++) {
    if (g_clients[i] == fd) {
      g_clients[i] = g_clients[g_clients_n - 1];
      g_clients_n--;
      break;
    }
  }
  pthread_mutex_unlock(&g_clients_mu);
}

static void clients_close_all(void) {
  pthread_mutex_lock(&g_clients_mu);
  for (size_t i = 0; i < g_clients_n; i++) {
    if (g_clients[i] >= 0) close(g_clients[i]);
    g_clients[i] = -1;
  }
  g_clients_n = 0;
  pthread_mutex_unlock(&g_clients_mu);
}

struct fdent {
  int fd;
  int in_use;
};

struct client_state {
  struct fdent *ents;
  size_t cap;
  int cwd_fd; /* per-client working directory (O_DIRECTORY fd) */
  int last_was_chdir;
};

static void state_init(struct client_state *st) {
  memset(st, 0, sizeof(*st));
  st->cwd_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (st->cwd_fd < 0) st->cwd_fd = -1;
  st->last_was_chdir = 0;
}

static void state_close_all(struct client_state *st) {
  if (!st) return;
  if (st->cwd_fd >= 0) {
    close(st->cwd_fd);
    st->cwd_fd = -1;
  }
  for (size_t i = 0; i < st->cap; i++) {
    if (st->ents[i].in_use) {
      close(st->ents[i].fd);
      st->ents[i].in_use = 0;
      st->ents[i].fd = -1;
    }
  }
  free(st->ents);
  st->ents = NULL;
  st->cap = 0;
}

static int is_abs_path(const char *p) {
  return (p && p[0] == '/');
}

static uint32_t alloc_handle(struct client_state *st, int fd) {
  if (fd < 0) return 0;
  for (size_t i = 0; i < st->cap; i++) {
    if (!st->ents[i].in_use) {
      st->ents[i].in_use = 1;
      st->ents[i].fd = fd;
      return (uint32_t)(i + 1);
    }
  }
  size_t ncap = st->cap ? (st->cap * 2) : 64;
  struct fdent *n = (struct fdent *)realloc(st->ents, ncap * sizeof(*n));
  if (!n) return 0;
  for (size_t i = st->cap; i < ncap; i++) {
    n[i].fd = -1;
    n[i].in_use = 0;
  }
  st->ents = n;
  size_t idx = st->cap;
  st->cap = ncap;
  st->ents[idx].in_use = 1;
  st->ents[idx].fd = fd;
  return (uint32_t)(idx + 1);
}

static int get_fd(struct client_state *st, uint32_t handle) {
  if (!handle) {
    errno = EBADF;
    return -1;
  }
  size_t idx = (size_t)handle - 1;
  if (idx >= st->cap || !st->ents[idx].in_use) {
    errno = EBADF;
    return -1;
  }
  return st->ents[idx].fd;
}

static int close_handle(struct client_state *st, uint32_t handle) {
  size_t idx = (size_t)handle - 1;
  if (!handle || idx >= st->cap || !st->ents[idx].in_use) {
    errno = EBADF;
    return -1;
  }
  int fd = st->ents[idx].fd;
  st->ents[idx].in_use = 0;
  st->ents[idx].fd = -1;
  return close(fd);
}

static int rd_u32(const uint8_t **pp, const uint8_t *end, uint32_t *out) {
  if ((size_t)(end - *pp) < 4) return -1;
  uint32_t v;
  memcpy(&v, *pp, 4);
  *pp += 4;
  *out = be32toh(v);
  return 0;
}

static int rd_i32(const uint8_t **pp, const uint8_t *end, int32_t *out) {
  uint32_t u;
  if (rd_u32(pp, end, &u) != 0) return -1;
  *out = (int32_t)u;
  return 0;
}

static int rd_u64(const uint8_t **pp, const uint8_t *end, uint64_t *out) {
  if ((size_t)(end - *pp) < 8) return -1;
  uint64_t v;
  memcpy(&v, *pp, 8);
  *pp += 8;
  *out = be64toh(v);
  return 0;
}

static int rd_i64(const uint8_t **pp, const uint8_t *end, int64_t *out) {
  uint64_t u;
  if (rd_u64(pp, end, &u) != 0) return -1;
  *out = (int64_t)u;
  return 0;
}

static uint8_t *wr_u32(uint8_t *p, uint32_t v) {
  v = htobe32(v);
  memcpy(p, &v, 4);
  return p + 4;
}

static uint8_t *wr_i32(uint8_t *p, int32_t v) {
  return wr_u32(p, (uint32_t)v);
}

static uint8_t *wr_u64(uint8_t *p, uint64_t v) {
  v = htobe64(v);
  memcpy(p, &v, 8);
  return p + 8;
}

static uint8_t *wr_i64(uint8_t *p, int64_t v) {
  return wr_u64(p, (uint64_t)v);
}

static uint32_t make_resp_int(uint8_t *out, size_t cap, int64_t rc, int32_t err) {
  if (cap < (8 + 4 + 4)) return 0;
  uint8_t *p = out;
  p = wr_i64(p, rc);
  p = wr_i32(p, err);
  p = wr_u32(p, 0); /* data_len */
  return (uint32_t)(p - out);
}

static uint32_t make_resp_data(uint8_t *out, size_t cap, int64_t rc, int32_t err, const void *data, uint32_t data_len) {
  if (cap < (8 + 4 + 4 + data_len)) return 0;
  uint8_t *p = out;
  p = wr_i64(p, rc);
  p = wr_i32(p, err);
  p = wr_u32(p, data_len);
  if (data_len) memcpy(p, data, data_len);
  p += data_len;
  return (uint32_t)(p - out);
}

static void *client_thread(void *arg) {
  struct client_ctx *ctx = (struct client_ctx *)arg;
  int fd = ctx->fd;
  free(ctx);

  struct client_state st;
  state_init(&st);

  uint8_t req[512 * 1024];
  uint8_t resp[512 * 1024];

  while (!g_stop) {
    uint16_t op = 0;
    uint32_t len = 0;
    if (rsys_recv_frame(fd, &op, req, (uint32_t)sizeof(req), &len) != 0) break;

    const uint8_t *p = req;
    const uint8_t *end = req + len;
    uint32_t rlen = 0;
    int32_t err = 0;
    int64_t rc = -1;

    switch (op) {
      case RSYS_OP_HELLO: {
        /* Minimal feature negotiation for forward compatibility.
         *
         * Request: empty (or ignored)
         * Response data: u32 server_version, u32 max_op_supported
         */
        uint8_t data[8];
        uint8_t *w = data;
        w = wr_u32(w, RSYS_VERSION);
        w = wr_u32(w, RSYS_OP_STATX);
        err = 0;
        rc = 0;
        rlen = make_resp_data(resp, sizeof(resp), rc, err, data, (uint32_t)(w - data));
      } break;

      case RSYS_OP_OPEN: {
        uint32_t flags = 0, mode = 0, path_len = 0;
        if (rd_u32(&p, end, &flags) != 0 || rd_u32(&p, end, &mode) != 0 || rd_u32(&p, end, &path_len) != 0) {
          err = EPROTO;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if ((size_t)(end - p) < path_len) {
          err = EPROTO;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';

        int realfd;
        if (is_abs_path(path)) {
          if (flags & (uint32_t)O_CREAT) realfd = open(path, (int)flags, (mode_t)mode);
          else realfd = open(path, (int)flags);
        } else {
          int base = (st.cwd_fd >= 0) ? st.cwd_fd : AT_FDCWD;
          if (flags & (uint32_t)O_CREAT) realfd = openat(base, path, (int)flags, (mode_t)mode);
          else realfd = openat(base, path, (int)flags);
        }
        if (realfd < 0) {
          err = errno;
          rc = -1;
        } else {
          uint32_t h = alloc_handle(&st, realfd);
          if (!h) {
            err = ENOMEM;
            rc = -1;
            close(realfd);
          } else {
            rc = (int64_t)h;
            err = 0;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_OPENAT: {
        int32_t dir_is_handle = 0;
        uint32_t dir_handle = 0;
        int32_t dirfd = AT_FDCWD;
        uint32_t flags = 0, mode = 0, path_len = 0;
        if (rd_i32(&p, end, &dir_is_handle) != 0) goto proto_err;
        if (dir_is_handle) {
          if (rd_u32(&p, end, &dir_handle) != 0) goto proto_err;
        } else {
          if (rd_i32(&p, end, &dirfd) != 0) goto proto_err;
        }
        if (rd_u32(&p, end, &flags) != 0 || rd_u32(&p, end, &mode) != 0 || rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;

        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';

        int use_dirfd = dirfd;
        if (dir_is_handle) use_dirfd = get_fd(&st, dir_handle);
        else if (use_dirfd == AT_FDCWD && st.cwd_fd >= 0) use_dirfd = st.cwd_fd;
        if (use_dirfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        int realfd;
        if (flags & (uint32_t)O_CREAT) realfd = openat(use_dirfd, path, (int)flags, (mode_t)mode);
        else realfd = openat(use_dirfd, path, (int)flags);
        if (realfd < 0) {
          err = errno;
          rc = -1;
        } else {
          uint32_t h = alloc_handle(&st, realfd);
          if (!h) {
            err = ENOMEM;
            rc = -1;
            close(realfd);
          } else {
            rc = (int64_t)h;
            err = 0;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_OPENAT2: {
        int32_t dir_is_handle = 0;
        uint32_t dir_handle = 0;
        int32_t dirfd = AT_FDCWD;
        uint64_t how_flags = 0, how_mode = 0, how_resolve = 0;
        uint32_t path_len = 0;
        if (rd_i32(&p, end, &dir_is_handle) != 0) goto proto_err;
        if (dir_is_handle) {
          if (rd_u32(&p, end, &dir_handle) != 0) goto proto_err;
        } else {
          if (rd_i32(&p, end, &dirfd) != 0) goto proto_err;
        }
        if (rd_u64(&p, end, &how_flags) != 0 || rd_u64(&p, end, &how_mode) != 0 || rd_u64(&p, end, &how_resolve) != 0 ||
            rd_u32(&p, end, &path_len) != 0)
          goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;

        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';

        int use_dirfd = dirfd;
        if (dir_is_handle) use_dirfd = get_fd(&st, dir_handle);
        else if (use_dirfd == AT_FDCWD && st.cwd_fd >= 0) use_dirfd = st.cwd_fd;
        if (use_dirfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        struct open_how how;
        memset(&how, 0, sizeof(how));
        how.flags = how_flags;
        how.mode = how_mode;
        how.resolve = how_resolve;

        int realfd = (int)syscall(SYS_openat2, use_dirfd, path, &how, sizeof(how));
        if (realfd < 0) {
          err = errno;
          rc = -1;
        } else {
          uint32_t h = alloc_handle(&st, realfd);
          if (!h) {
            err = ENOMEM;
            rc = -1;
            close(realfd);
          } else {
            rc = (int64_t)h;
            err = 0;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_CLOSE: {
        uint32_t h = 0;
        if (rd_u32(&p, end, &h) != 0) goto proto_err;
        int rr = close_handle(&st, h);
        if (rr < 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_READ: {
        uint32_t h = 0, count = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u32(&p, end, &count) != 0) goto proto_err;
        int rfd = get_fd(&st, h);
        if (rfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (count > (uint32_t)(sizeof(resp) - (8 + 4 + 4))) count = (uint32_t)(sizeof(resp) - (8 + 4 + 4));
        ssize_t n = read(rfd, resp + (8 + 4 + 4), count);
        if (n < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = (int64_t)n;
          /* Fill header in front of data we already wrote. */
          uint8_t *w = resp;
          w = wr_i64(w, rc);
          w = wr_i32(w, err);
          w = wr_u32(w, (uint32_t)n);
          rlen = (uint32_t)((8 + 4 + 4) + (uint32_t)n);
        }
      } break;

      case RSYS_OP_PREAD: {
        uint32_t h = 0, count = 0;
        uint64_t off = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u64(&p, end, &off) != 0 || rd_u32(&p, end, &count) != 0) goto proto_err;
        int rfd = get_fd(&st, h);
        if (rfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (count > (uint32_t)(sizeof(resp) - (8 + 4 + 4))) count = (uint32_t)(sizeof(resp) - (8 + 4 + 4));
        ssize_t n = pread(rfd, resp + (8 + 4 + 4), count, (off_t)off);
        if (n < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = (int64_t)n;
          uint8_t *w = resp;
          w = wr_i64(w, rc);
          w = wr_i32(w, err);
          w = wr_u32(w, (uint32_t)n);
          rlen = (uint32_t)((8 + 4 + 4) + (uint32_t)n);
        }
      } break;

      case RSYS_OP_WRITE: {
        uint32_t h = 0, count = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u32(&p, end, &count) != 0) goto proto_err;
        if ((size_t)(end - p) < count) goto proto_err;
        int wfd = get_fd(&st, h);
        if (wfd < 0) {
          err = errno;
          rc = -1;
        } else {
          ssize_t n = write(wfd, p, count);
          if (n < 0) {
            err = errno;
            rc = -1;
          } else {
            err = 0;
            rc = (int64_t)n;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_PWRITE: {
        uint32_t h = 0, count = 0;
        uint64_t off = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u64(&p, end, &off) != 0 || rd_u32(&p, end, &count) != 0) goto proto_err;
        if ((size_t)(end - p) < count) goto proto_err;
        int wfd = get_fd(&st, h);
        if (wfd < 0) {
          err = errno;
          rc = -1;
        } else {
          ssize_t n = pwrite(wfd, p, count, (off_t)off);
          if (n < 0) {
            err = errno;
            rc = -1;
          } else {
            err = 0;
            rc = (int64_t)n;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_LSEEK: {
        uint32_t h = 0;
        int64_t off = 0;
        uint32_t whence = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i64(&p, end, &off) != 0 || rd_u32(&p, end, &whence) != 0) goto proto_err;
        int lfd = get_fd(&st, h);
        if (lfd < 0) {
          err = errno;
          rc = -1;
        } else {
          off_t n = lseek(lfd, (off_t)off, (int)whence);
          if (n == (off_t)-1) {
            err = errno;
            rc = -1;
          } else {
            err = 0;
            rc = (int64_t)n;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_STAT:
      case RSYS_OP_LSTAT: {
        uint32_t path_len = 0;
        if (rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';
        struct stat stbuf;
        int rr;
        if (is_abs_path(path)) {
          rr = (op == RSYS_OP_LSTAT) ? lstat(path, &stbuf) : stat(path, &stbuf);
        } else {
          int base = (st.cwd_fd >= 0) ? st.cwd_fd : AT_FDCWD;
          int fl = (op == RSYS_OP_LSTAT) ? AT_SYMLINK_NOFOLLOW : 0;
          rr = fstatat(base, path, &stbuf, fl);
        }
        if (rr != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, &stbuf, (uint32_t)sizeof(stbuf));
        }
      } break;

      case RSYS_OP_FSTAT: {
        uint32_t h = 0;
        if (rd_u32(&p, end, &h) != 0) goto proto_err;
        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        struct stat stbuf;
        if (fstat(sfd, &stbuf) != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, &stbuf, (uint32_t)sizeof(stbuf));
        }
      } break;

      case RSYS_OP_FSTATAT: {
        int32_t dir_is_handle = 0;
        uint32_t dir_handle = 0;
        int32_t dirfd = AT_FDCWD;
        uint32_t flags = 0, path_len = 0;
        if (rd_i32(&p, end, &dir_is_handle) != 0) goto proto_err;
        if (dir_is_handle) {
          if (rd_u32(&p, end, &dir_handle) != 0) goto proto_err;
        } else {
          if (rd_i32(&p, end, &dirfd) != 0) goto proto_err;
        }
        if (rd_u32(&p, end, &flags) != 0 || rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';

        int use_dirfd = dirfd;
        if (dir_is_handle) use_dirfd = get_fd(&st, dir_handle);
        else if (use_dirfd == AT_FDCWD && st.cwd_fd >= 0) use_dirfd = st.cwd_fd;
        if (use_dirfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        struct stat stbuf;
        if (fstatat(use_dirfd, path, &stbuf, (int)flags) != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, &stbuf, (uint32_t)sizeof(stbuf));
        }
      } break;

      case RSYS_OP_STATX: {
        int32_t dir_is_handle = 0;
        uint32_t dir_handle = 0;
        int32_t dirfd = AT_FDCWD;
        uint32_t flags = 0, mask = 0, path_len = 0;
        if (rd_i32(&p, end, &dir_is_handle) != 0) goto proto_err;
        if (dir_is_handle) {
          if (rd_u32(&p, end, &dir_handle) != 0) goto proto_err;
        } else {
          if (rd_i32(&p, end, &dirfd) != 0) goto proto_err;
        }
        if (rd_u32(&p, end, &flags) != 0 || rd_u32(&p, end, &mask) != 0 || rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;

        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';

        int use_dirfd = dirfd;
        if (dir_is_handle) use_dirfd = get_fd(&st, dir_handle);
        else if (use_dirfd == AT_FDCWD && st.cwd_fd >= 0) use_dirfd = st.cwd_fd;
        if (use_dirfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        struct statx sx;
        memset(&sx, 0, sizeof(sx));
        int rr = (int)syscall(SYS_statx, use_dirfd, path, (int)flags, (unsigned int)mask, &sx);
        if (rr != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, &sx, (uint32_t)sizeof(sx));
        }
      } break;

      case RSYS_OP_MKDIR: {
        uint32_t mode = 0, path_len = 0;
        if (rd_u32(&p, end, &mode) != 0 || rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';
        if (g_trace) fprintf(stderr, "RSYS_OP_MKDIR path='%s' mode=%o\n", path, (unsigned)mode);
        int rr;
        if (is_abs_path(path)) rr = mkdir(path, (mode_t)mode);
        else {
          int base = (st.cwd_fd >= 0) ? st.cwd_fd : AT_FDCWD;
          rr = mkdirat(base, path, (mode_t)mode);
        }

        /* Heuristic for tools (like coreutils mkdir -p) that effectively "walk" path components
         * by changing cwd via direct syscalls that LD_PRELOAD can't see. If the last operation
         * was a chdir/fchdir and we just attempted to create a single path component, follow it.
         */
        if (!is_abs_path(path) && st.last_was_chdir && st.cwd_fd >= 0 && strchr(path, '/') == NULL) {
          int nfd = openat(st.cwd_fd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
          if (nfd >= 0) {
            close(st.cwd_fd);
            st.cwd_fd = nfd;
          }
        }
        st.last_was_chdir = 0;

        if (rr != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_MKDIRAT: {
        int32_t dir_is_handle = 0;
        uint32_t dir_handle = 0;
        int32_t dirfd = AT_FDCWD;
        uint32_t mode = 0, path_len = 0;
        if (rd_i32(&p, end, &dir_is_handle) != 0) goto proto_err;
        if (dir_is_handle) {
          if (rd_u32(&p, end, &dir_handle) != 0) goto proto_err;
        } else {
          if (rd_i32(&p, end, &dirfd) != 0) goto proto_err;
        }
        if (rd_u32(&p, end, &mode) != 0 || rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';
        if (g_trace) fprintf(stderr, "RSYS_OP_MKDIRAT dir_is_handle=%d dirfd=%d handle=%u path='%s' mode=%o\n", dir_is_handle, dirfd, dir_handle, path, (unsigned)mode);

        int use_dirfd = dirfd;
        if (dir_is_handle) use_dirfd = get_fd(&st, dir_handle);
        else if (use_dirfd == AT_FDCWD && st.cwd_fd >= 0) use_dirfd = st.cwd_fd;
        if (use_dirfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (mkdirat(use_dirfd, path, (mode_t)mode) != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_CHDIR: {
        uint32_t path_len = 0;
        if (rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';
        if (g_trace) fprintf(stderr, "RSYS_OP_CHDIR path='%s'\n", path);

        int newfd;
        if (is_abs_path(path)) {
          newfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        } else {
          int base = (st.cwd_fd >= 0) ? st.cwd_fd : AT_FDCWD;
          newfd = openat(base, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        }
        if (newfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (st.cwd_fd >= 0) close(st.cwd_fd);
        st.cwd_fd = newfd;
        st.last_was_chdir = 1;
        err = 0;
        rc = 0;
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_FCHDIR: {
        uint32_t h = 0;
        if (rd_u32(&p, end, &h) != 0) goto proto_err;
        if (g_trace) fprintf(stderr, "RSYS_OP_FCHDIR handle=%u\n", h);
        int dfd = get_fd(&st, h);
        if (dfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        int newfd = dup(dfd);
        if (newfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (st.cwd_fd >= 0) close(st.cwd_fd);
        st.cwd_fd = newfd;
        st.last_was_chdir = 1;
        err = 0;
        rc = 0;
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_GETDENTS64: {
        uint32_t h = 0, count = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u32(&p, end, &count) != 0) goto proto_err;
        int dfd = get_fd(&st, h);
        if (dfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (count > (uint32_t)(sizeof(resp) - (8 + 4 + 4))) count = (uint32_t)(sizeof(resp) - (8 + 4 + 4));
        long n = syscall(SYS_getdents64, dfd, resp + (8 + 4 + 4), count);
        if (n < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = (int64_t)n;
          uint8_t *w = resp;
          w = wr_i64(w, rc);
          w = wr_i32(w, err);
          w = wr_u32(w, (uint32_t)n);
          rlen = (uint32_t)((8 + 4 + 4) + (uint32_t)n);
        }
      } break;

      case RSYS_OP_UNLINK: {
        uint32_t path_len = 0;
        if (rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';
        int rr;
        if (is_abs_path(path)) rr = unlink(path);
        else {
          int base = (st.cwd_fd >= 0) ? st.cwd_fd : AT_FDCWD;
          rr = unlinkat(base, path, 0);
        }
        if (rr != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_UNLINKAT: {
        int32_t dir_is_handle = 0;
        uint32_t dir_handle = 0;
        int32_t dirfd = AT_FDCWD;
        uint32_t flags = 0, path_len = 0;
        if (rd_i32(&p, end, &dir_is_handle) != 0) goto proto_err;
        if (dir_is_handle) {
          if (rd_u32(&p, end, &dir_handle) != 0) goto proto_err;
        } else {
          if (rd_i32(&p, end, &dirfd) != 0) goto proto_err;
        }
        if (rd_u32(&p, end, &flags) != 0 || rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';

        int use_dirfd = dirfd;
        if (dir_is_handle) use_dirfd = get_fd(&st, dir_handle);
        else if (use_dirfd == AT_FDCWD && st.cwd_fd >= 0) use_dirfd = st.cwd_fd;
        if (use_dirfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        int rr = unlinkat(use_dirfd, path, (int)flags);
        if (rr != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_RMDIR: {
        uint32_t path_len = 0;
        if (rd_u32(&p, end, &path_len) != 0) goto proto_err;
        if ((size_t)(end - p) < path_len) goto proto_err;
        char path[4096];
        if (path_len >= sizeof(path)) {
          err = ENAMETOOLONG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        memcpy(path, p, path_len);
        path[path_len] = '\0';
        int rr;
        if (is_abs_path(path)) rr = rmdir(path);
        else {
          int base = (st.cwd_fd >= 0) ? st.cwd_fd : AT_FDCWD;
          rr = unlinkat(base, path, AT_REMOVEDIR);
        }
        if (rr != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_POLL: {
        int32_t timeout_ms = 0;
        uint32_t n = 0;
        if (rd_i32(&p, end, &timeout_ms) != 0 || rd_u32(&p, end, &n) != 0) goto proto_err;
        if (n > 4096) {
          err = E2BIG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        struct pollfd *pfds = (struct pollfd *)calloc((size_t)n, sizeof(*pfds));
        if (!pfds && n) {
          err = ENOMEM;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        for (uint32_t i = 0; i < n; i++) {
          uint32_t h = 0, events = 0;
          if (rd_u32(&p, end, &h) != 0 || rd_u32(&p, end, &events) != 0) {
            free(pfds);
            goto proto_err;
          }
          int fd2 = get_fd(&st, h);
          if (fd2 < 0) {
            pfds[i].fd = -1;
            pfds[i].events = 0;
            pfds[i].revents = 0;
          } else {
            pfds[i].fd = fd2;
            pfds[i].events = (short)events;
            pfds[i].revents = 0;
          }
        }
        int rr = poll(pfds, (nfds_t)n, timeout_ms);
        if (rr < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          free(pfds);
          break;
        }
        /* data: u32 n, then u32 revents[n] */
        uint8_t tmp[4 + 4096 * 4];
        uint8_t *w = tmp;
        w = wr_u32(w, n);
        for (uint32_t i = 0; i < n; i++) w = wr_u32(w, (uint32_t)(uint16_t)pfds[i].revents);
        free(pfds);
        err = 0;
        rc = (int64_t)rr;
        rlen = make_resp_data(resp, sizeof(resp), rc, err, tmp, (uint32_t)(w - tmp));
      } break;

      case RSYS_OP_FCNTL: {
        uint32_t h = 0;
        int32_t cmd = 0;
        int64_t farg = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &cmd) != 0 || rd_i64(&p, end, &farg) != 0) goto proto_err;
        int fd2 = get_fd(&st, h);
        if (fd2 < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        long rr = fcntl(fd2, cmd, (long)farg);
        if (rr < 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = (int64_t)rr;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_IOCTL_INT: {
        uint32_t h = 0;
        uint64_t ioreq = 0;
        int32_t val = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u64(&p, end, &ioreq) != 0 || rd_i32(&p, end, &val) != 0) goto proto_err;
        int fd2 = get_fd(&st, h);
        if (fd2 < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        int v = val;
        int rr = ioctl(fd2, (unsigned long)ioreq, &v);
        if (rr != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          uint8_t tmp[4];
          uint8_t *w = tmp;
          w = wr_i32(w, (int32_t)v);
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, tmp, (uint32_t)(w - tmp));
        }
      } break;

      case RSYS_OP_UNAME: {
        struct utsname u;
        if (uname(&u) != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, &u, (uint32_t)sizeof(u));
        }
      } break;

      case RSYS_OP_GETHOSTNAME: {
        uint32_t cap = 0;
        if (rd_u32(&p, end, &cap) != 0) goto proto_err;
        if (cap == 0) {
          err = EINVAL;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (cap > 4096) cap = 4096;
        char buf[4096];
        if (gethostname(buf, (size_t)cap) != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          /* gethostname may not NUL-terminate if truncated; enforce NUL for safe transfer */
          buf[cap - 1] = '\0';
          uint32_t n = (uint32_t)strnlen(buf, cap);
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, buf, n);
        }
      } break;

      case RSYS_OP_SETHOSTNAME: {
        uint32_t hlen = 0;
        if (rd_u32(&p, end, &hlen) != 0) goto proto_err;
        if ((size_t)(end - p) < hlen) goto proto_err;
        if (hlen == 0 || hlen > 255) {
          err = EINVAL;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        char name[256];
        memcpy(name, p, hlen);
        name[hlen] = '\0';
        if (sethostname(name, (size_t)hlen) != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_SYSINFO: {
        struct sysinfo si;
        if (sysinfo(&si) != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, &si, (uint32_t)sizeof(si));
        }
      } break;

      case RSYS_OP_SOCKET: {
        int32_t domain = 0, type = 0, proto = 0;
        if (rd_i32(&p, end, &domain) != 0 || rd_i32(&p, end, &type) != 0 || rd_i32(&p, end, &proto) != 0) goto proto_err;
        int s = socket(domain, type, proto);
        if (s < 0) {
          err = errno;
          rc = -1;
        } else {
          uint32_t h = alloc_handle(&st, s);
          if (!h) {
            err = ENOMEM;
            rc = -1;
            close(s);
          } else {
            err = 0;
            rc = (int64_t)h;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_CONNECT: {
        uint32_t h = 0, alen = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u32(&p, end, &alen) != 0) goto proto_err;
        if ((size_t)(end - p) < alen) goto proto_err;
        int cfd = get_fd(&st, h);
        if (cfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        int rr = connect(cfd, (const struct sockaddr *)p, (socklen_t)alen);
        if (rr != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_BIND: {
        uint32_t h = 0, alen = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u32(&p, end, &alen) != 0) goto proto_err;
        if ((size_t)(end - p) < alen) goto proto_err;
        int bfd = get_fd(&st, h);
        if (bfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        int rr = bind(bfd, (const struct sockaddr *)p, (socklen_t)alen);
        if (rr != 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = 0;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_SEND: {
        uint32_t h = 0, dlen = 0;
        int32_t flags = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &flags) != 0 || rd_u32(&p, end, &dlen) != 0) goto proto_err;
        if ((size_t)(end - p) < dlen) goto proto_err;
        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
        } else {
          ssize_t n = send(sfd, p, dlen, flags);
          if (n < 0) {
            err = errno;
            rc = -1;
          } else {
            err = 0;
            rc = (int64_t)n;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_SENDTO: {
        uint32_t h = 0, alen = 0, dlen = 0;
        int32_t flags = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &flags) != 0 || rd_u32(&p, end, &alen) != 0) goto proto_err;
        if ((size_t)(end - p) < alen) goto proto_err;
        const void *addrp = p;
        p += alen;
        if (rd_u32(&p, end, &dlen) != 0) goto proto_err;
        if ((size_t)(end - p) < dlen) goto proto_err;

        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
        } else {
          ssize_t n = sendto(sfd,
                             p,
                             dlen,
                             flags,
                             (alen ? (const struct sockaddr *)addrp : NULL),
                             (socklen_t)alen);
          if (n < 0) {
            err = errno;
            rc = -1;
          } else {
            err = 0;
            rc = (int64_t)n;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_RECV: {
        uint32_t h = 0, want = 0;
        int32_t flags = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &flags) != 0 || rd_u32(&p, end, &want) != 0) goto proto_err;
        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (want > (uint32_t)(sizeof(resp) - (8 + 4 + 4))) want = (uint32_t)(sizeof(resp) - (8 + 4 + 4));
        ssize_t n = recv(sfd, resp + (8 + 4 + 4), want, flags);
        if (n < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = (int64_t)n;
          uint8_t *w = resp;
          w = wr_i64(w, rc);
          w = wr_i32(w, err);
          w = wr_u32(w, (uint32_t)n);
          rlen = (uint32_t)((8 + 4 + 4) + (uint32_t)n);
        }
      } break;

      case RSYS_OP_RECVFROM: {
        uint32_t h = 0, want = 0, addr_cap = 0;
        int32_t flags = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &flags) != 0 || rd_u32(&p, end, &want) != 0 || rd_u32(&p, end, &addr_cap) != 0) goto proto_err;
        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        if (want > (uint32_t)(sizeof(resp) - (8 + 4 + 4 + 4))) want = (uint32_t)(sizeof(resp) - (8 + 4 + 4 + 4));
        if (addr_cap > 4096) addr_cap = 4096;

        struct sockaddr_storage ss;
        socklen_t slen = (socklen_t)addr_cap;
        memset(&ss, 0, sizeof(ss));

        /* Layout: [i64 rc][i32 err][u32 data_len][u32 addr_len][addr bytes][payload bytes] */
        uint8_t *payload_out = resp + (8 + 4 + 4 + 4) + addr_cap;
        uint32_t max_payload = (uint32_t)(sizeof(resp) - (8 + 4 + 4 + 4) - addr_cap);
        if (want > max_payload) want = max_payload;

        ssize_t n = recvfrom(sfd, payload_out, want, flags, (struct sockaddr *)&ss, &slen);
        if (n < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = (int64_t)n;
          uint8_t *w = resp;
          w = wr_i64(w, rc);
          w = wr_i32(w, err);
          uint32_t data_len = 4u + (uint32_t)slen + (uint32_t)n;
          w = wr_u32(w, data_len);
          w = wr_u32(w, (uint32_t)slen);
          memcpy(w, &ss, (size_t)slen);
          w += (uint32_t)slen;
          /* payload already written at payload_out, but payload_out might not be adjacent */
          memmove(w, payload_out, (size_t)n);
          w += (uint32_t)n;
          rlen = (uint32_t)(w - resp);
        }
      } break;

      case RSYS_OP_GETSOCKOPT: {
        uint32_t h = 0, optcap = 0;
        int32_t level = 0, optname = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &level) != 0 || rd_i32(&p, end, &optname) != 0 || rd_u32(&p, end, &optcap) != 0) goto proto_err;
        if (optcap > 4096) optcap = 4096;
        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        uint8_t bufopt[4096];
        socklen_t olen = (socklen_t)optcap;
        int rr = getsockopt(sfd, level, optname, bufopt, &olen);
        if (rr != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          uint8_t tmp[4 + 4096];
          uint8_t *w = tmp;
          w = wr_u32(w, (uint32_t)olen);
          memcpy(w, bufopt, (size_t)olen);
          w += (uint32_t)olen;
          err = 0;
          rc = 0;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, tmp, (uint32_t)(w - tmp));
        }
      } break;

      case RSYS_OP_SETSOCKOPT: {
        uint32_t h = 0, optlen = 0;
        int32_t level = 0, optname = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &level) != 0 || rd_i32(&p, end, &optname) != 0 || rd_u32(&p, end, &optlen) != 0) goto proto_err;
        if ((size_t)(end - p) < optlen) goto proto_err;
        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
        } else {
          int rr = setsockopt(sfd, level, optname, p, (socklen_t)optlen);
          if (rr != 0) {
            err = errno;
            rc = -1;
          } else {
            err = 0;
            rc = 0;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_SENDMSG: {
        uint32_t h = 0, name_len = 0, iovcnt = 0;
        int32_t flags = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &flags) != 0 || rd_u32(&p, end, &name_len) != 0) goto proto_err;
        if ((size_t)(end - p) < name_len) goto proto_err;
        const void *namep = NULL;
        if (name_len) namep = p;
        p += name_len;
        if (rd_u32(&p, end, &iovcnt) != 0) goto proto_err;
        if (iovcnt > 128) {
          err = E2BIG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        uint32_t lens[128];
        uint64_t total = 0;
        for (uint32_t i = 0; i < iovcnt; i++) {
          uint32_t l = 0;
          if (rd_u32(&p, end, &l) != 0) goto proto_err;
          lens[i] = l;
          total += l;
          if (total > (64ull * 1024ull * 1024ull)) {
            err = E2BIG;
            rc = -1;
            rlen = make_resp_int(resp, sizeof(resp), rc, err);
            goto sendmsg_done;
          }
        }
        if ((uint64_t)(end - p) < total) goto proto_err;

        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        struct iovec iov[128];
        const uint8_t *dp = p;
        for (uint32_t i = 0; i < iovcnt; i++) {
          iov[i].iov_base = (void *)(uintptr_t)dp;
          iov[i].iov_len = (size_t)lens[i];
          dp += lens[i];
        }
        struct msghdr mh;
        memset(&mh, 0, sizeof(mh));
        mh.msg_name = (void *)(uintptr_t)namep;
        mh.msg_namelen = (socklen_t)name_len;
        mh.msg_iov = iov;
        mh.msg_iovlen = (size_t)iovcnt;
        mh.msg_control = NULL;
        mh.msg_controllen = 0;

        ssize_t n = sendmsg(sfd, &mh, flags);
        if (n < 0) {
          err = errno;
          rc = -1;
        } else {
          err = 0;
          rc = (int64_t)n;
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      sendmsg_done:
      } break;

      case RSYS_OP_RECVMSG: {
        uint32_t h = 0, name_cap = 0, iovcnt = 0, control_cap = 0;
        int32_t flags = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &flags) != 0 || rd_u32(&p, end, &name_cap) != 0) goto proto_err;
        if (rd_u32(&p, end, &control_cap) != 0 || rd_u32(&p, end, &iovcnt) != 0) goto proto_err;
        if (control_cap != 0) {
          err = ENOTSUP;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        if (name_cap > 4096) name_cap = 4096;
        if (iovcnt > 128) {
          err = E2BIG;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        uint32_t lens[128];
        uint64_t total = 0;
        for (uint32_t i = 0; i < iovcnt; i++) {
          uint32_t l = 0;
          if (rd_u32(&p, end, &l) != 0) goto proto_err;
          lens[i] = l;
          total += l;
          if (total > (64ull * 1024ull * 1024ull)) {
            err = E2BIG;
            rc = -1;
            rlen = make_resp_int(resp, sizeof(resp), rc, err);
            goto recvmsg_done;
          }
        }

        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        uint8_t namebuf[4096];
        struct iovec iov[128];

        uint8_t *payload = (uint8_t *)malloc((size_t)total);
        if (!payload && total) {
          err = ENOMEM;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        uint8_t *cur = payload;
        for (uint32_t i = 0; i < iovcnt; i++) {
          iov[i].iov_base = cur;
          iov[i].iov_len = (size_t)lens[i];
          cur += lens[i];
        }

        struct msghdr mh;
        memset(&mh, 0, sizeof(mh));
        mh.msg_name = name_cap ? namebuf : NULL;
        mh.msg_namelen = (socklen_t)name_cap;
        mh.msg_iov = iov;
        mh.msg_iovlen = (size_t)iovcnt;
        mh.msg_control = NULL;
        mh.msg_controllen = 0;

        ssize_t n = recvmsg(sfd, &mh, flags);
        if (n < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = (int64_t)n;
          uint32_t nlen = (uint32_t)mh.msg_namelen;
          if (nlen > name_cap) nlen = name_cap;

          /* data = [u32 name_len][name bytes][payload bytes (rc bytes)] */
          uint32_t need = 4u + nlen + (uint32_t)n;
          if (need > (uint32_t)(sizeof(resp) - (8 + 4 + 4))) {
            /* Truncate defensively */
            uint32_t max_payload = (uint32_t)(sizeof(resp) - (8 + 4 + 4) - 4u - nlen);
            if ((uint32_t)n > max_payload) n = (ssize_t)max_payload;
            rc = (int64_t)n;
            need = 4u + nlen + (uint32_t)n;
          }

          uint8_t tmp_hdr[4 + 4096];
          uint8_t *w = tmp_hdr;
          w = wr_u32(w, nlen);
          memcpy(w, namebuf, nlen);
          w += nlen;

          /* Build response directly: header+tmp_hdr + payload bytes. */
          uint8_t *outp = resp;
          outp = wr_i64(outp, rc);
          outp = wr_i32(outp, err);
          outp = wr_u32(outp, need);
          memcpy(outp, tmp_hdr, (size_t)(w - tmp_hdr));
          outp += (uint32_t)(w - tmp_hdr);
          if (n > 0) memcpy(outp, payload, (size_t)n);
          outp += (uint32_t)n;
          rlen = (uint32_t)(outp - resp);
        }

        free(payload);
      recvmsg_done:
        ;
      } break;

      case RSYS_OP_SHUTDOWN: {
        uint32_t h = 0;
        int32_t how = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_i32(&p, end, &how) != 0) goto proto_err;
        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
        } else {
          int rr = shutdown(sfd, how);
          if (rr != 0) {
            err = errno;
            rc = -1;
          } else {
            err = 0;
            rc = 0;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      case RSYS_OP_GETSOCKNAME:
      case RSYS_OP_GETPEERNAME: {
        uint32_t h = 0, addr_cap = 0;
        if (rd_u32(&p, end, &h) != 0 || rd_u32(&p, end, &addr_cap) != 0) goto proto_err;
        if (addr_cap > 4096) addr_cap = 4096;

        int sfd = get_fd(&st, h);
        if (sfd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }

        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        socklen_t slen = (socklen_t)addr_cap;

        int rr = (op == RSYS_OP_GETSOCKNAME)
                     ? getsockname(sfd, (struct sockaddr *)&ss, &slen)
                     : getpeername(sfd, (struct sockaddr *)&ss, &slen);
        if (rr != 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
        } else {
          err = 0;
          rc = 0;
          /* data = [u32 addr_len][addr bytes] */
          uint8_t tmp[4 + 4096];
          uint8_t *w = tmp;
          w = wr_u32(w, (uint32_t)slen);
          memcpy(w, &ss, (size_t)slen);
          w += (uint32_t)slen;
          rlen = make_resp_data(resp, sizeof(resp), rc, err, tmp, (uint32_t)(w - tmp));
        }
      } break;

      case RSYS_OP_DUP: {
        uint32_t h = 0;
        if (rd_u32(&p, end, &h) != 0) goto proto_err;
        int ofd = get_fd(&st, h);
        if (ofd < 0) {
          err = errno;
          rc = -1;
          rlen = make_resp_int(resp, sizeof(resp), rc, err);
          break;
        }
        int nfd = dup(ofd);
        if (nfd < 0) {
          err = errno;
          rc = -1;
        } else {
          uint32_t nh = alloc_handle(&st, nfd);
          if (!nh) {
            err = ENOMEM;
            rc = -1;
            close(nfd);
          } else {
            err = 0;
            rc = (int64_t)nh;
          }
        }
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
      } break;

      default:
        err = ENOSYS;
        rc = -1;
        rlen = make_resp_int(resp, sizeof(resp), rc, err);
        break;
    }

    if (rlen == 0) break;
    if (rsys_send_frame(fd, (uint16_t)(op | RSYS_TYPE_RESP_FLAG), resp, rlen) != 0) break;
    continue;

  proto_err:
    err = EPROTO;
    rc = -1;
    rlen = make_resp_int(resp, sizeof(resp), rc, err);
    if (rlen == 0) break;
    if (rsys_send_frame(fd, (uint16_t)(op | RSYS_TYPE_RESP_FLAG), resp, rlen) != 0) break;
  }

  state_close_all(&st);
  clients_del(fd);
  close(fd);
  return NULL;
}

static void usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <listen_port>\n", argv0);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    usage(argv[0]);
    return 2;
  }

  const char *tr = getenv("RSYS_TRACE");
  g_trace = (tr && tr[0] == '1');

  signal(SIGINT, on_sigint);
  signal(SIGTERM, on_sigint);

  g_lfd = listen_tcp(argv[1]);
  if (g_lfd < 0) {
    perror("listen");
    return 1;
  }

  fprintf(stderr, "Listening on 0.0.0.0:%s...\n", argv[1]);
  fflush(stderr);

  while (!g_stop) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int cfd = accept(g_lfd, (struct sockaddr *)&ss, &slen);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      if (g_stop) break;
      perror("accept");
      break;
    }

    clients_add(cfd);

    struct client_ctx *ctx = (struct client_ctx *)calloc(1, sizeof(*ctx));
    ctx->fd = cfd;

    pthread_t th;
    if (pthread_create(&th, NULL, client_thread, ctx) != 0) {
      clients_del(cfd);
      close(cfd);
      free(ctx);
      continue;
    }
    pthread_detach(th);
  }

  clients_close_all();
  if (g_lfd >= 0) close(g_lfd);
  g_lfd = -1;
  return 0;
}
