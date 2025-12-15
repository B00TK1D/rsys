#define _GNU_SOURCE
#include "common.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <sys/sysinfo.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <poll.h>
#include <unistd.h>

/* Some programs bypass libc wrappers and call syscall(SYS_*) directly.
 * We interpose syscall() for a small set of syscalls that must be remoteized.
 */
typedef long (*syscall_f)(long number, ...);
static syscall_f real_syscall(void) {
  static syscall_f f = NULL;
  if (!f) f = (syscall_f)dlsym(RTLD_NEXT, "syscall");
  return f;
}

static int g_fd = -1; /* control socket */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_inhook = 0;
static int g_debug = 0;

static void dbg(const char *s) {
  if (!g_debug || !s) return;
  (void)syscall(SYS_write, 2, s, strlen(s));
  (void)syscall(SYS_write, 2, "\n", 1);
}

static void warn_stderr(const char *s) {
  if (!s) return;
  (void)syscall(SYS_write, 2, s, strlen(s));
  (void)syscall(SYS_write, 2, "\n", 1);
}

static int path_force_local(const char *path) {
  if (!path) return 0;
  /* Some APIs (getlogin, ttyname, etc.) depend on *this* process' controlling TTY.
   * That cannot be virtualized remotely, so keep these device paths local.
   */
  if (strcmp(path, "/dev/tty") == 0) return 1;
  if (strncmp(path, "/dev/pts/", 9) == 0) return 1;
  if (strcmp(path, "/dev/console") == 0) return 1;
  /* Keep process-introspection paths local: they describe *this* process on the client. */
  if (strncmp(path, "/proc/self/", 10) == 0) return 1;
  if (strncmp(path, "/proc/thread-self/", 17) == 0) return 1;
  return 0;
}

struct fdmap_ent {
  uint32_t handle;
  uint8_t in_use;
};

static struct fdmap_ent *g_map = NULL;
static size_t g_map_cap = 0;

static int map_ensure(int fd) {
  if (fd < 0) return -1;
  size_t need = (size_t)fd + 1;
  if (need <= g_map_cap) return 0;
  size_t ncap = g_map_cap ? g_map_cap : 128;
  while (ncap < need) ncap *= 2;
  struct fdmap_ent *n = (struct fdmap_ent *)realloc(g_map, ncap * sizeof(*n));
  if (!n) return -1;
  for (size_t i = g_map_cap; i < ncap; i++) {
    n[i].handle = 0;
    n[i].in_use = 0;
  }
  g_map = n;
  g_map_cap = ncap;
  return 0;
}

static int map_get_nolock(int fd, uint32_t *handle_out) {
  if (fd < 0 || (size_t)fd >= g_map_cap) return 0;
  if (!g_map[fd].in_use) return 0;
  if (handle_out) *handle_out = g_map[fd].handle;
  return 1;
}

static void map_set_nolock(int fd, uint32_t handle) {
  if (map_ensure(fd) != 0) return;
  g_map[fd].handle = handle;
  g_map[fd].in_use = 1;
}

static void map_del_nolock(int fd) {
  if (fd < 0 || (size_t)fd >= g_map_cap) return;
  g_map[fd].handle = 0;
  g_map[fd].in_use = 0;
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

static int rpc(uint16_t op, const void *req, uint32_t req_len, uint8_t *resp, uint32_t resp_cap, uint32_t *resp_len_out) {
  if (g_fd < 0) return -1;
  if (g_inhook) return -1;
  g_inhook = 1;
  pthread_mutex_lock(&g_lock);
  int ok = rsys_rpc(g_fd, op, req, req_len, resp, resp_cap, resp_len_out);
  pthread_mutex_unlock(&g_lock);
  g_inhook = 0;
  if (ok != 0) {
    dbg("rsys: rpc failed; disconnecting");
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0) {
      (void)syscall(SYS_close, g_fd);
      g_fd = -1;
    }
    pthread_mutex_unlock(&g_lock);
    return -1;
  }
  return 0;
}

static int parse_resp(const uint8_t *resp, uint32_t len, int64_t *rc_out, int32_t *err_out, const uint8_t **data_out, uint32_t *data_len_out) {
  const uint8_t *p = resp;
  const uint8_t *end = resp + len;
  int64_t rc = -1;
  int32_t err = EPROTO;
  uint32_t dlen = 0;
  if (rd_i64(&p, end, &rc) != 0) return -1;
  if (rd_i32(&p, end, &err) != 0) return -1;
  if (rd_u32(&p, end, &dlen) != 0) return -1;
  if ((size_t)(end - p) < dlen) return -1;
  if (rc_out) *rc_out = rc;
  if (err_out) *err_out = err;
  if (data_out) *data_out = p;
  if (data_len_out) *data_len_out = dlen;
  return 0;
}

static int alloc_placeholder_fd(void) {
  int fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (fd < 0) return -1;

  /* Ensure we never hand out 0/1/2 as placeholders. */
  if (fd <= 2) {
    int saved = errno;
    for (int newfd = 3; newfd < 1024; newfd++) {
      errno = 0;
      int n = (int)syscall(SYS_dup3, fd, newfd, O_CLOEXEC);
      if (n >= 0) {
        (void)syscall(SYS_close, fd);
        errno = saved;
        return n;
      }
      if (errno == EINTR) {
        newfd--;
        continue;
      }
      if (errno == EBUSY) continue;
      break;
    }
    (void)syscall(SYS_close, fd);
    errno = EMFILE;
    return -1;
  }

  return fd;
}

/* ---------------- Remote DIR implementation (for ls/readdir) ---------------- */

#define RSYS_DIR_MAGIC 0x52535944u /* 'RSYD' */

struct rsys_DIR {
  uint32_t magic;
  int fd;            /* local placeholder fd (mapped to remote handle) */
  uint32_t handle;   /* remote handle */
  uint8_t buf[64 * 1024];
  size_t buf_len;
  size_t buf_pos;
  struct dirent de;
  struct dirent64 de64;
};

struct linux_dirent64_packed {
  uint64_t d_ino;
  int64_t d_off;
  uint16_t d_reclen;
  uint8_t d_type;
  char d_name[];
} __attribute__((packed));

static int is_remote_fd(int fd, uint32_t *h_out) {
  if (fd < 0 || fd == g_fd) return 0;
  pthread_mutex_lock(&g_lock);
  int ok = map_get_nolock(fd, h_out);
  pthread_mutex_unlock(&g_lock);
  return ok;
}

/* ---------------- Remote epoll implementation (for curl/ssl) ---------------- */

#define RSYS_EP_MAGIC 0x52535945u /* 'RSYE' */

struct rsys_ep_item {
  int fd;             /* local fd as seen by process */
  uint32_t handle;    /* remote handle (if remote) */
  uint32_t events;    /* epoll events mask */
  uint64_t data_u64;  /* epoll_event.data.u64 */
  int in_use;
};

struct rsys_ep {
  uint32_t magic;
  int epfd;
  struct rsys_ep_item *items;
  size_t n;
  size_t cap;
};

static pthread_mutex_t g_ep_mu = PTHREAD_MUTEX_INITIALIZER;
static struct rsys_ep *g_eps = NULL;
static size_t g_eps_n = 0;
static size_t g_eps_cap = 0;

static struct rsys_ep *ep_get(int epfd) {
  for (size_t i = 0; i < g_eps_n; i++) {
    if (g_eps[i].magic == RSYS_EP_MAGIC && g_eps[i].epfd == epfd) return &g_eps[i];
  }
  return NULL;
}

static int ep_ensure_item(struct rsys_ep *ep, size_t idx) {
  if (idx < ep->cap) return 0;
  size_t ncap = ep->cap ? ep->cap * 2 : 64;
  while (ncap <= idx) ncap *= 2;
  struct rsys_ep_item *n = (struct rsys_ep_item *)realloc(ep->items, ncap * sizeof(*n));
  if (!n) return -1;
  for (size_t i = ep->cap; i < ncap; i++) {
    memset(&n[i], 0, sizeof(n[i]));
    n[i].fd = -1;
    n[i].handle = 0;
    n[i].events = 0;
    n[i].data_u64 = 0;
    n[i].in_use = 0;
  }
  ep->items = n;
  ep->cap = ncap;
  return 0;
}

static int ep_add_or_mod(struct rsys_ep *ep, int fd, uint32_t events, uint64_t data_u64) {
  /* Find existing. */
  for (size_t i = 0; i < ep->n; i++) {
    if (ep->items[i].in_use && ep->items[i].fd == fd) {
      ep->items[i].events = events;
      ep->items[i].data_u64 = data_u64;
      uint32_t h = 0;
      if (is_remote_fd(fd, &h)) ep->items[i].handle = h;
      else ep->items[i].handle = 0;
      return 0;
    }
  }
  /* Append. */
  if (ep_ensure_item(ep, ep->n) != 0) return -1;
  ep->items[ep->n].in_use = 1;
  ep->items[ep->n].fd = fd;
  ep->items[ep->n].events = events;
  ep->items[ep->n].data_u64 = data_u64;
  uint32_t h = 0;
  if (is_remote_fd(fd, &h)) ep->items[ep->n].handle = h;
  else ep->items[ep->n].handle = 0;
  ep->n++;
  return 0;
}

static int ep_del(struct rsys_ep *ep, int fd) {
  for (size_t i = 0; i < ep->n; i++) {
    if (ep->items[i].in_use && ep->items[i].fd == fd) {
      ep->items[i] = ep->items[ep->n - 1];
      ep->n--;
      return 0;
    }
  }
  errno = ENOENT;
  return -1;
}

static uint32_t ep_to_poll(uint32_t epev) {
  uint32_t pe = 0;
  if (epev & EPOLLIN) pe |= POLLIN;
  if (epev & EPOLLOUT) pe |= POLLOUT;
  if (epev & EPOLLPRI) pe |= POLLPRI;
  return pe;
}

static uint32_t poll_to_ep(uint32_t pev, uint32_t requested) {
  uint32_t ev = 0;
  if (pev & POLLIN) ev |= EPOLLIN;
  if (pev & POLLOUT) ev |= EPOLLOUT;
  if (pev & POLLPRI) ev |= EPOLLPRI;
  if (pev & POLLERR) ev |= EPOLLERR;
  if (pev & POLLHUP) ev |= EPOLLHUP;
  /* If edge-triggered requested, preserve it; it is bookkeeping-only for us. */
  if (requested & EPOLLET) ev |= EPOLLET;
  return ev;
}

static int rsys_dir_fill(struct rsys_DIR *d) {
  d->buf_pos = 0;
  d->buf_len = 0;

  uint8_t req[16];
  uint8_t *p = req;
  p = wr_u32(p, d->handle);
  p = wr_u32(p, (uint32_t)sizeof(d->buf));

  uint8_t resp[8 + 4 + 4 + sizeof(d->buf)];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_GETDENTS64, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return -1;
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if ((uint32_t)rc64 == 0) return 0; /* EOF */
  if (dlen > sizeof(d->buf)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(d->buf, data, dlen);
  d->buf_len = dlen;
  return 1;
}

static struct dirent *rsys_dir_next(struct rsys_DIR *d) {
  for (;;) {
    if (d->buf_pos >= d->buf_len) {
      int r = rsys_dir_fill(d);
      if (r <= 0) return NULL; /* EOF or error (errno set) */
    }
    if (d->buf_pos + sizeof(struct linux_dirent64_packed) > d->buf_len) {
      errno = EPROTO;
      return NULL;
    }
    struct linux_dirent64_packed *ent = (struct linux_dirent64_packed *)(void *)(d->buf + d->buf_pos);
    uint16_t reclen = ent->d_reclen;
    if (reclen < offsetof(struct linux_dirent64_packed, d_name) + 1) {
      errno = EPROTO;
      return NULL;
    }
    if (d->buf_pos + reclen > d->buf_len) {
      errno = EPROTO;
      return NULL;
    }
    d->buf_pos += reclen;

    /* Copy into stable storage. */
    memset(&d->de, 0, sizeof(d->de));
    d->de.d_ino = (ino_t)ent->d_ino;
    d->de.d_off = (off_t)ent->d_off;
    d->de.d_type = ent->d_type;
    size_t nlen = strnlen(ent->d_name, (size_t)reclen - offsetof(struct linux_dirent64_packed, d_name));
    if (nlen >= sizeof(d->de.d_name)) nlen = sizeof(d->de.d_name) - 1;
    memcpy(d->de.d_name, ent->d_name, nlen);
    d->de.d_name[nlen] = '\0';
    d->de.d_reclen = (unsigned short)(offsetof(struct dirent, d_name) + nlen + 1);
    return &d->de;
  }
}

static struct dirent64 *rsys_dir_next64(struct rsys_DIR *d) {
  struct dirent *e = rsys_dir_next(d);
  if (!e) return NULL;
  memset(&d->de64, 0, sizeof(d->de64));
  d->de64.d_ino = (ino64_t)e->d_ino;
  d->de64.d_off = (off64_t)e->d_off;
  d->de64.d_type = e->d_type;
  size_t nlen = strnlen(e->d_name, sizeof(d->de64.d_name) - 1);
  memcpy(d->de64.d_name, e->d_name, nlen);
  d->de64.d_name[nlen] = '\0';
  d->de64.d_reclen = (unsigned short)(offsetof(struct dirent64, d_name) + nlen + 1);
  return &d->de64;
}

__attribute__((constructor)) static void rsys_init(void) {
  const char *dbg_env = getenv("RSYS_DEBUG");
  g_debug = (dbg_env && dbg_env[0] == '1');
  const char *ip = getenv("RSYS_SERVER");
  const char *port = getenv("RSYS_PORT");
  if (!ip || !port) return;

  g_fd = rsys_connect_tcp(ip, port);
  if (g_fd < 0) {
    dbg("rsys: connect failed");
    return;
  }

  /* Feature negotiation: ensure server supports required ops. */
  {
    uint8_t resp[64];
    uint32_t rlen = 0;
    if (rpc(RSYS_OP_HELLO, NULL, 0, resp, (uint32_t)sizeof(resp), &rlen) != 0) {
      warn_stderr("rsys: connected server is too old/incompatible (no HELLO); disable remote syscalls");
      (void)syscall(SYS_close, g_fd);
      g_fd = -1;
      return;
    }
    int64_t rc64 = -1;
    int32_t err = 0;
    const uint8_t *data = NULL;
    uint32_t dlen = 0;
    if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
      warn_stderr("rsys: connected server sent invalid HELLO response; disable remote syscalls");
      (void)syscall(SYS_close, g_fd);
      g_fd = -1;
      return;
    }
    if (rc64 != 0 || err != 0 || dlen < 8) {
      if (rc64 < 0 && err == ENOSYS) {
        warn_stderr("rsys: connected server does not implement HELLO (ENOSYS). You are running an old rsysd; rebuild/restart rsysd.");
      } else {
        warn_stderr("rsys: connected server rejected HELLO; disable remote syscalls");
      }
      (void)syscall(SYS_close, g_fd);
      g_fd = -1;
      return;
    }
    const uint8_t *p = data;
    const uint8_t *end = data + dlen;
    uint32_t server_ver = 0, max_op = 0;
    if (rd_u32(&p, end, &server_ver) != 0 || rd_u32(&p, end, &max_op) != 0) {
      warn_stderr("rsys: connected server HELLO parse failed; disable remote syscalls");
      (void)syscall(SYS_close, g_fd);
      g_fd = -1;
      return;
    }
    if (server_ver != RSYS_VERSION || max_op < RSYS_OP_SYSINFO) {
      warn_stderr("rsys: connected server lacks required features; rebuild/restart rsysd");
      (void)syscall(SYS_close, g_fd);
      g_fd = -1;
      return;
    }
  }

  /* Sync server-side cwd to the client's cwd for correct relative-path behavior. */
  {
    char cwd[4096];
    long n = syscall(SYS_getcwd, cwd, sizeof(cwd));
    if (n > 0 && n < (long)sizeof(cwd)) {
      size_t len = (size_t)n;
      /* syscall(SYS_getcwd) returns a NUL-terminated string; don't send the NUL. */
      if (len > 0 && cwd[len - 1] == '\0') len--;
      uint8_t req[4096 + 8];
      uint8_t *p = req;
      p = wr_u32(p, (uint32_t)len);
      memcpy(p, cwd, len);
      p += len;
      uint8_t resp[128];
      uint32_t rlen = 0;
      (void)rpc(RSYS_OP_CHDIR, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen);
    }
  }

  dbg("rsys: connected");
}

__attribute__((destructor)) static void rsys_fini(void) {
  if (g_fd >= 0) (void)syscall(SYS_close, g_fd);
  g_fd = -1;
}

// ---------------- Helpers to call real libc ----------------

typedef int (*open_f)(const char *, int, ...);
typedef int (*openat_f)(int, const char *, int, ...);
typedef ssize_t (*read_f)(int, void *, size_t);
typedef ssize_t (*write_f)(int, const void *, size_t);
typedef ssize_t (*pread_f)(int, void *, size_t, off_t);
typedef ssize_t (*pwrite_f)(int, const void *, size_t, off_t);
typedef off_t (*lseek_f)(int, off_t, int);
typedef int (*close_f)(int);
typedef int (*openat2_f)(int, const char *, const struct open_how *, size_t);
typedef int (*statx_f)(int, const char *, int, unsigned int, struct statx *);
typedef int (*socket_f)(int, int, int);
typedef int (*connect_f)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*send_f)(int, const void *, size_t, int);
typedef ssize_t (*recv_f)(int, void *, size_t, int);
typedef ssize_t (*sendto_f)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_f)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef int (*getsockname_f)(int, struct sockaddr *, socklen_t *);
typedef int (*getpeername_f)(int, struct sockaddr *, socklen_t *);
typedef int (*shutdown_f)(int, int);
typedef int (*dup_f)(int);
typedef int (*stat_f)(const char *, struct stat *);
typedef int (*lstat_f)(const char *, struct stat *);
typedef int (*fstat_f)(int, struct stat *);
typedef int (*fstatat_f)(int, const char *, struct stat *, int);
typedef int (*mkdir_f)(const char *, mode_t);
typedef int (*mkdirat_f)(int, const char *, mode_t);
typedef int (*chdir_f)(const char *);
typedef int (*fchdir_f)(int);
typedef ssize_t (*getdents64_f)(int, void *, size_t);
typedef int (*unlink_f)(const char *);
typedef int (*unlinkat_f)(int, const char *, int);
typedef int (*rmdir_f)(const char *);
typedef int (*poll_f)(struct pollfd *, nfds_t, int);
typedef DIR *(*opendir_f)(const char *);
typedef DIR *(*opendir64_f)(const char *);
typedef DIR *(*fdopendir_f)(int);
typedef struct dirent *(*readdir_f)(DIR *);
typedef struct dirent64 *(*readdir64_f)(DIR *);
typedef int (*closedir_f)(DIR *);
typedef int (*dirfd_f)(DIR *);
typedef void (*rewinddir_f)(DIR *);
typedef int (*epoll_create_f)(int);
typedef int (*epoll_create1_f)(int);
typedef int (*epoll_ctl_f)(int, int, int, struct epoll_event *);
typedef int (*epoll_wait_f)(int, struct epoll_event *, int, int);
typedef int (*epoll_pwait_f)(int, struct epoll_event *, int, int, const sigset_t *);
typedef int (*fcntl_f)(int, int, ...);
typedef int (*fcntl64_f)(int, int, ...);
typedef int (*ioctl_f)(int, unsigned long, ...);
typedef int (*uname_f)(struct utsname *);
typedef int (*gethostname_f)(char *, size_t);
typedef int (*sethostname_f)(const char *, size_t);
typedef char *(*getlogin_f)(void);
typedef int (*getlogin_r_f)(char *, size_t);
typedef int (*sysinfo_f)(struct sysinfo *);
typedef struct passwd *(*getpwuid_f)(uid_t);
typedef int (*getpwuid_r_f)(uid_t, struct passwd *, char *, size_t, struct passwd **);
typedef int (*unlink_f)(const char *);
typedef int (*unlinkat_f)(int, const char *, int);
typedef int (*rmdir_f)(const char *);
typedef int (*poll_f)(struct pollfd *, nfds_t, int);
typedef int (*bind_f)(int, const struct sockaddr *, socklen_t);
typedef int (*getsockopt2_f)(int, int, int, void *, socklen_t *);
typedef int (*setsockopt2_f)(int, int, int, const void *, socklen_t);
typedef ssize_t (*sendmsg_f)(int, const struct msghdr *, int);
typedef ssize_t (*recvmsg_f)(int, struct msghdr *, int);

static open_f real_open(void) {
  static open_f f = NULL;
  if (!f) f = (open_f)dlsym(RTLD_NEXT, "open");
  return f;
}
static openat_f real_openat(void) {
  static openat_f f = NULL;
  if (!f) f = (openat_f)dlsym(RTLD_NEXT, "openat");
  return f;
}
static openat2_f real_openat2(void) {
  static openat2_f f = NULL;
  if (!f) f = (openat2_f)dlsym(RTLD_NEXT, "openat2");
  return f;
}
static statx_f real_statx(void) {
  static statx_f f = NULL;
  if (!f) f = (statx_f)dlsym(RTLD_NEXT, "statx");
  return f;
}
static read_f real_read(void) {
  static read_f f = NULL;
  if (!f) f = (read_f)dlsym(RTLD_NEXT, "read");
  return f;
}
static write_f real_write(void) {
  static write_f f = NULL;
  if (!f) f = (write_f)dlsym(RTLD_NEXT, "write");
  return f;
}
static pread_f real_pread(void) {
  static pread_f f = NULL;
  if (!f) f = (pread_f)dlsym(RTLD_NEXT, "pread");
  return f;
}
static pwrite_f real_pwrite(void) {
  static pwrite_f f = NULL;
  if (!f) f = (pwrite_f)dlsym(RTLD_NEXT, "pwrite");
  return f;
}
static lseek_f real_lseek(void) {
  static lseek_f f = NULL;
  if (!f) f = (lseek_f)dlsym(RTLD_NEXT, "lseek");
  return f;
}
static close_f real_close(void) {
  static close_f f = NULL;
  if (!f) f = (close_f)dlsym(RTLD_NEXT, "close");
  return f;
}
static socket_f real_socket(void) {
  static socket_f f = NULL;
  if (!f) f = (socket_f)dlsym(RTLD_NEXT, "socket");
  return f;
}
static connect_f real_connect(void) {
  static connect_f f = NULL;
  if (!f) f = (connect_f)dlsym(RTLD_NEXT, "connect");
  return f;
}
static send_f real_send(void) {
  static send_f f = NULL;
  if (!f) f = (send_f)dlsym(RTLD_NEXT, "send");
  return f;
}
static recv_f real_recv(void) {
  static recv_f f = NULL;
  if (!f) f = (recv_f)dlsym(RTLD_NEXT, "recv");
  return f;
}
static sendto_f real_sendto(void) {
  static sendto_f f = NULL;
  if (!f) f = (sendto_f)dlsym(RTLD_NEXT, "sendto");
  return f;
}
static recvfrom_f real_recvfrom(void) {
  static recvfrom_f f = NULL;
  if (!f) f = (recvfrom_f)dlsym(RTLD_NEXT, "recvfrom");
  return f;
}
static getsockname_f real_getsockname(void) {
  static getsockname_f f = NULL;
  if (!f) f = (getsockname_f)dlsym(RTLD_NEXT, "getsockname");
  return f;
}
static getpeername_f real_getpeername(void) {
  static getpeername_f f = NULL;
  if (!f) f = (getpeername_f)dlsym(RTLD_NEXT, "getpeername");
  return f;
}
static shutdown_f real_shutdown(void) {
  static shutdown_f f = NULL;
  if (!f) f = (shutdown_f)dlsym(RTLD_NEXT, "shutdown");
  return f;
}
static dup_f real_dup(void) {
  static dup_f f = NULL;
  if (!f) f = (dup_f)dlsym(RTLD_NEXT, "dup");
  return f;
}
static stat_f real_stat(void) {
  static stat_f f = NULL;
  if (!f) f = (stat_f)dlsym(RTLD_NEXT, "stat");
  return f;
}
static lstat_f real_lstat(void) {
  static lstat_f f = NULL;
  if (!f) f = (lstat_f)dlsym(RTLD_NEXT, "lstat");
  return f;
}
static fstat_f real_fstat(void) {
  static fstat_f f = NULL;
  if (!f) f = (fstat_f)dlsym(RTLD_NEXT, "fstat");
  return f;
}
static fstatat_f real_fstatat(void) {
  static fstatat_f f = NULL;
  if (!f) f = (fstatat_f)dlsym(RTLD_NEXT, "fstatat");
  if (!f) f = (fstatat_f)dlsym(RTLD_NEXT, "newfstatat");
  return f;
}
static mkdir_f real_mkdir(void) {
  static mkdir_f f = NULL;
  if (!f) f = (mkdir_f)dlsym(RTLD_NEXT, "mkdir");
  return f;
}
static mkdirat_f real_mkdirat(void) {
  static mkdirat_f f = NULL;
  if (!f) f = (mkdirat_f)dlsym(RTLD_NEXT, "mkdirat");
  return f;
}
static chdir_f real_chdir(void) {
  static chdir_f f = NULL;
  if (!f) f = (chdir_f)dlsym(RTLD_NEXT, "chdir");
  return f;
}
static fchdir_f real_fchdir(void) {
  static fchdir_f f = NULL;
  if (!f) f = (fchdir_f)dlsym(RTLD_NEXT, "fchdir");
  return f;
}
static getdents64_f real_getdents64(void) {
  static getdents64_f f = NULL;
  if (!f) f = (getdents64_f)dlsym(RTLD_NEXT, "getdents64");
  if (!f) f = (getdents64_f)dlsym(RTLD_NEXT, "__getdents64");
  return f;
}
static unlink_f real_unlink(void) {
  static unlink_f f = NULL;
  if (!f) f = (unlink_f)dlsym(RTLD_NEXT, "unlink");
  return f;
}
static unlinkat_f real_unlinkat(void) {
  static unlinkat_f f = NULL;
  if (!f) f = (unlinkat_f)dlsym(RTLD_NEXT, "unlinkat");
  return f;
}
static rmdir_f real_rmdir(void) {
  static rmdir_f f = NULL;
  if (!f) f = (rmdir_f)dlsym(RTLD_NEXT, "rmdir");
  return f;
}
static poll_f real_poll(void) {
  static poll_f f = NULL;
  if (!f) f = (poll_f)dlsym(RTLD_NEXT, "poll");
  return f;
}
static opendir_f real_opendir(void) {
  static opendir_f f = NULL;
  if (!f) f = (opendir_f)dlsym(RTLD_NEXT, "opendir");
  return f;
}
static opendir64_f real_opendir64(void) {
  static opendir64_f f = NULL;
  if (!f) f = (opendir64_f)dlsym(RTLD_NEXT, "opendir64");
  return f;
}
static fdopendir_f real_fdopendir(void) {
  static fdopendir_f f = NULL;
  if (!f) f = (fdopendir_f)dlsym(RTLD_NEXT, "fdopendir");
  return f;
}
static readdir_f real_readdir(void) {
  static readdir_f f = NULL;
  if (!f) f = (readdir_f)dlsym(RTLD_NEXT, "readdir");
  return f;
}
static readdir64_f real_readdir64(void) {
  static readdir64_f f = NULL;
  if (!f) f = (readdir64_f)dlsym(RTLD_NEXT, "readdir64");
  return f;
}
static closedir_f real_closedir(void) {
  static closedir_f f = NULL;
  if (!f) f = (closedir_f)dlsym(RTLD_NEXT, "closedir");
  return f;
}
static dirfd_f real_dirfd(void) {
  static dirfd_f f = NULL;
  if (!f) f = (dirfd_f)dlsym(RTLD_NEXT, "dirfd");
  return f;
}
static rewinddir_f real_rewinddir(void) {
  static rewinddir_f f = NULL;
  if (!f) f = (rewinddir_f)dlsym(RTLD_NEXT, "rewinddir");
  return f;
}
static epoll_create_f real_epoll_create(void) {
  static epoll_create_f f = NULL;
  if (!f) f = (epoll_create_f)dlsym(RTLD_NEXT, "epoll_create");
  return f;
}
static epoll_create1_f real_epoll_create1(void) {
  static epoll_create1_f f = NULL;
  if (!f) f = (epoll_create1_f)dlsym(RTLD_NEXT, "epoll_create1");
  return f;
}
static epoll_ctl_f real_epoll_ctl(void) {
  static epoll_ctl_f f = NULL;
  if (!f) f = (epoll_ctl_f)dlsym(RTLD_NEXT, "epoll_ctl");
  return f;
}
static epoll_wait_f real_epoll_wait(void) {
  static epoll_wait_f f = NULL;
  if (!f) f = (epoll_wait_f)dlsym(RTLD_NEXT, "epoll_wait");
  return f;
}
static epoll_pwait_f real_epoll_pwait(void) {
  static epoll_pwait_f f = NULL;
  if (!f) f = (epoll_pwait_f)dlsym(RTLD_NEXT, "epoll_pwait");
  return f;
}
static fcntl_f real_fcntl(void) {
  static fcntl_f f = NULL;
  if (!f) f = (fcntl_f)dlsym(RTLD_NEXT, "fcntl");
  return f;
}
static ioctl_f real_ioctl(void) {
  static ioctl_f f = NULL;
  if (!f) f = (ioctl_f)dlsym(RTLD_NEXT, "ioctl");
  return f;
}
static uname_f real_uname(void) {
  static uname_f f = NULL;
  if (!f) f = (uname_f)dlsym(RTLD_NEXT, "uname");
  return f;
}
static gethostname_f real_gethostname(void) {
  static gethostname_f f = NULL;
  if (!f) f = (gethostname_f)dlsym(RTLD_NEXT, "gethostname");
  return f;
}
static sethostname_f real_sethostname(void) {
  static sethostname_f f = NULL;
  if (!f) f = (sethostname_f)dlsym(RTLD_NEXT, "sethostname");
  return f;
}
static getlogin_f real_getlogin(void) {
  static getlogin_f f = NULL;
  if (!f) f = (getlogin_f)dlsym(RTLD_NEXT, "getlogin");
  return f;
}
static getlogin_r_f real_getlogin_r(void) {
  static getlogin_r_f f = NULL;
  if (!f) f = (getlogin_r_f)dlsym(RTLD_NEXT, "getlogin_r");
  return f;
}
static sysinfo_f real_sysinfo(void) {
  static sysinfo_f f = NULL;
  if (!f) f = (sysinfo_f)dlsym(RTLD_NEXT, "sysinfo");
  return f;
}
static getpwuid_f real_getpwuid(void) {
  static getpwuid_f f = NULL;
  if (!f) f = (getpwuid_f)dlsym(RTLD_NEXT, "getpwuid");
  return f;
}
static getpwuid_r_f real_getpwuid_r(void) {
  static getpwuid_r_f f = NULL;
  if (!f) f = (getpwuid_r_f)dlsym(RTLD_NEXT, "getpwuid_r");
  return f;
}
static bind_f real_bind(void) {
  static bind_f f = NULL;
  if (!f) f = (bind_f)dlsym(RTLD_NEXT, "bind");
  return f;
}
static getsockopt2_f real_getsockopt2(void) {
  static getsockopt2_f f = NULL;
  if (!f) f = (getsockopt2_f)dlsym(RTLD_NEXT, "getsockopt");
  return f;
}
static setsockopt2_f real_setsockopt2(void) {
  static setsockopt2_f f = NULL;
  if (!f) f = (setsockopt2_f)dlsym(RTLD_NEXT, "setsockopt");
  return f;
}
static sendmsg_f real_sendmsg(void) {
  static sendmsg_f f = NULL;
  if (!f) f = (sendmsg_f)dlsym(RTLD_NEXT, "sendmsg");
  return f;
}
static recvmsg_f real_recvmsg(void) {
  static recvmsg_f f = NULL;
  if (!f) f = (recvmsg_f)dlsym(RTLD_NEXT, "recvmsg");
  return f;
}

int open(const char *pathname, int flags, ...) {
  if (g_inhook || g_fd < 0) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
      va_list ap;
      va_start(ap, flags);
      mode = (mode_t)va_arg(ap, int);
      va_end(ap);
      return real_open()(pathname, flags, mode);
    }
    return real_open()(pathname, flags);
  }
  if (path_force_local(pathname)) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
      va_list ap;
      va_start(ap, flags);
      mode = (mode_t)va_arg(ap, int);
      va_end(ap);
      return real_open()(pathname, flags, mode);
    }
    return real_open()(pathname, flags);
  }

  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }

  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  uint8_t req[4096 + 64];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)flags);
  p = wr_u32(p, (uint32_t)mode);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_OPEN, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    /* Fallback to local on transport failure. */
    if (flags & O_CREAT) return real_open()(pathname, flags, mode);
    return real_open()(pathname, flags);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }

  int lfd = alloc_placeholder_fd();
  if (lfd < 0) {
    /* Best-effort: close remote handle to avoid leak. */
    uint8_t creq[8];
    uint8_t *q = creq;
    q = wr_u32(q, (uint32_t)rc64);
    uint32_t dummy = 0;
    (void)rpc(RSYS_OP_CLOSE, creq, (uint32_t)(q - creq), resp, (uint32_t)sizeof(resp), &dummy);
    errno = EMFILE;
    return -1;
  }

  pthread_mutex_lock(&g_lock);
  map_set_nolock(lfd, (uint32_t)rc64);
  pthread_mutex_unlock(&g_lock);
  return lfd;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
  if (g_inhook || g_fd < 0) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
      va_list ap;
      va_start(ap, flags);
      mode = (mode_t)va_arg(ap, int);
      va_end(ap);
      return real_openat()(dirfd, pathname, flags, mode);
    }
    return real_openat()(dirfd, pathname, flags);
  }
  if (path_force_local(pathname)) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
      va_list ap;
      va_start(ap, flags);
      mode = (mode_t)va_arg(ap, int);
      va_end(ap);
      return real_openat()(dirfd, pathname, flags, mode);
    }
    return real_openat()(dirfd, pathname, flags);
  }

  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }

  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  uint32_t dir_handle = 0;
  int dir_is_remote = 0;
  pthread_mutex_lock(&g_lock);
  dir_is_remote = map_get_nolock(dirfd, &dir_handle);
  pthread_mutex_unlock(&g_lock);
  if (!dir_is_remote && dirfd != AT_FDCWD) {
    /* A non-remote dirfd is meaningless on the server. */
    if (flags & O_CREAT) return real_openat()(dirfd, pathname, flags, mode);
    return real_openat()(dirfd, pathname, flags);
  }

  uint8_t req[4096 + 96];
  uint8_t *p = req;
  p = wr_i32(p, dir_is_remote ? 1 : 0);
  if (dir_is_remote) p = wr_u32(p, dir_handle);
  else p = wr_i32(p, dirfd);
  p = wr_u32(p, (uint32_t)flags);
  p = wr_u32(p, (uint32_t)mode);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_OPENAT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    if (flags & O_CREAT) return real_openat()(dirfd, pathname, flags, mode);
    return real_openat()(dirfd, pathname, flags);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }

  int lfd = alloc_placeholder_fd();
  if (lfd < 0) {
    uint8_t creq[8];
    uint8_t *q = creq;
    q = wr_u32(q, (uint32_t)rc64);
    uint32_t dummy = 0;
    (void)rpc(RSYS_OP_CLOSE, creq, (uint32_t)(q - creq), resp, (uint32_t)sizeof(resp), &dummy);
    errno = EMFILE;
    return -1;
  }
  pthread_mutex_lock(&g_lock);
  map_set_nolock(lfd, (uint32_t)rc64);
  pthread_mutex_unlock(&g_lock);
  return lfd;
}

int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size) {
  /* If libc provided openat2, use it for local fallback when needed. */
  if (g_inhook || g_fd < 0 || !real_openat2()) {
    if (real_openat2()) return real_openat2()(dirfd, pathname, how, size);
    errno = ENOSYS;
    return -1;
  }
  if (path_force_local(pathname)) return real_openat2()(dirfd, pathname, how, size);
  if (!how || size < sizeof(*how)) return real_openat2()(dirfd, pathname, how, size);

  /* dirfd handling mirrors openat()/fstatat(): remote only works for AT_FDCWD or remote-mapped dirfds. */
  uint32_t dir_handle = 0;
  int dir_is_remote = 0;
  pthread_mutex_lock(&g_lock);
  dir_is_remote = map_get_nolock(dirfd, &dir_handle);
  pthread_mutex_unlock(&g_lock);
  if (!dir_is_remote && dirfd != AT_FDCWD) return real_openat2()(dirfd, pathname, how, size);

  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  /* Try remote OPENAT2 first. If server doesn't support it, fall back to local openat2. */
  uint8_t req[4096 + 128];
  uint8_t *p = req;
  p = wr_i32(p, dir_is_remote ? 1 : 0);
  if (dir_is_remote) p = wr_u32(p, dir_handle);
  else p = wr_i32(p, dirfd);
  p = wr_u64(p, (uint64_t)how->flags);
  p = wr_u64(p, (uint64_t)how->mode);
  p = wr_u64(p, (uint64_t)how->resolve);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_OPENAT2, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_openat2()(dirfd, pathname, how, size);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    if (err == ENOSYS) return real_openat2()(dirfd, pathname, how, size);
    errno = err ? err : EIO;
    return -1;
  }

  int lfd = alloc_placeholder_fd();
  if (lfd < 0) {
    /* Best-effort close remote handle */
    uint8_t creq[8];
    uint8_t *q = creq;
    q = wr_u32(q, (uint32_t)rc64);
    uint32_t dummy = 0;
    (void)rpc(RSYS_OP_CLOSE, creq, (uint32_t)(q - creq), resp, (uint32_t)sizeof(resp), &dummy);
    errno = EMFILE;
    return -1;
  }
  pthread_mutex_lock(&g_lock);
  map_set_nolock(lfd, (uint32_t)rc64);
  pthread_mutex_unlock(&g_lock);
  return lfd;
}

int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *stx) {
  if (g_inhook || g_fd < 0) {
    if (real_statx()) return real_statx()(dirfd, pathname, flags, mask, stx);
    return (int)real_syscall()(SYS_statx, dirfd, pathname, flags, mask, stx);
  }
  if (path_force_local(pathname)) {
    if (real_statx()) return real_statx()(dirfd, pathname, flags, mask, stx);
    return (int)real_syscall()(SYS_statx, dirfd, pathname, flags, mask, stx);
  }

  uint32_t dir_handle = 0;
  int dir_is_remote = 0;
  pthread_mutex_lock(&g_lock);
  dir_is_remote = map_get_nolock(dirfd, &dir_handle);
  pthread_mutex_unlock(&g_lock);
  if (!dir_is_remote && dirfd != AT_FDCWD) {
    if (real_statx()) return real_statx()(dirfd, pathname, flags, mask, stx);
    return (int)real_syscall()(SYS_statx, dirfd, pathname, flags, mask, stx);
  }

  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  uint8_t req[4096 + 128];
  uint8_t *p = req;
  p = wr_i32(p, dir_is_remote ? 1 : 0);
  if (dir_is_remote) p = wr_u32(p, dir_handle);
  else p = wr_i32(p, dirfd);
  p = wr_u32(p, (uint32_t)flags);
  p = wr_u32(p, (uint32_t)mask);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_STATX, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    if (real_statx()) return real_statx()(dirfd, pathname, flags, mask, stx);
    return (int)real_syscall()(SYS_statx, dirfd, pathname, flags, mask, stx);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    if (err == ENOSYS) {
      if (real_statx()) return real_statx()(dirfd, pathname, flags, mask, stx);
      return (int)real_syscall()(SYS_statx, dirfd, pathname, flags, mask, stx);
    }
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen != sizeof(*stx)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(stx, data, sizeof(*stx));
  return 0;
}

ssize_t read(int fd, void *buf, size_t count) {
  if (fd >= 0 && fd <= 2) return real_read()(fd, buf, count);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_read()(fd, buf, count);

  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_read()(fd, buf, count);

  uint8_t req[16];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u32(p, (uint32_t)count);

  uint8_t resp[512 * 1024];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_READ, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_read()(fd, buf, count);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen > 0 && buf) memcpy(buf, data, dlen);
  return (ssize_t)rc64;
}

ssize_t write(int fd, const void *buf, size_t count) {
  if (fd >= 0 && fd <= 2) return real_write()(fd, buf, count);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_write()(fd, buf, count);

  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_write()(fd, buf, count);

  if (count > (512u * 1024u)) count = (512u * 1024u);
  uint8_t req_hdr[16];
  uint8_t *p = req_hdr;
  p = wr_u32(p, h);
  p = wr_u32(p, (uint32_t)count);

  /* Build request into a single contiguous buffer. */
  uint8_t req[16 + 512 * 1024];
  memcpy(req, req_hdr, (size_t)(p - req_hdr));
  if (count && buf) memcpy(req + (p - req_hdr), buf, count);
  uint32_t req_len = (uint32_t)((p - req_hdr) + count);

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_WRITE, req, req_len, resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_write()(fd, buf, count);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return (ssize_t)rc64;
}

int close(int fd) {
  if (fd >= 0 && fd <= 2) return real_close()(fd);
  if (g_inhook || fd == g_fd) return real_close()(fd);

  /* If this is a tracked epoll fd, drop the registry entry. */
  pthread_mutex_lock(&g_ep_mu);
  struct rsys_ep *ep = ep_get(fd);
  if (ep) {
    free(ep->items);
    ep->items = NULL;
    ep->n = 0;
    ep->cap = 0;
    ep->magic = 0;
    ep->epfd = -1;
    /* compact g_eps */
    size_t idx = (size_t)(ep - g_eps);
    if (idx < g_eps_n) {
      g_eps[idx] = g_eps[g_eps_n - 1];
      g_eps_n--;
    }
  }
  pthread_mutex_unlock(&g_ep_mu);

  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  if (is_remote) map_del_nolock(fd);
  pthread_mutex_unlock(&g_lock);

  int lrc = real_close()(fd);
  if (!is_remote || g_fd < 0) return lrc;

  uint8_t req[8];
  uint8_t *p = req;
  p = wr_u32(p, h);
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_CLOSE, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return lrc;
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) return lrc;
  if (rc64 < 0) errno = err ? err : EIO;
  return (int)rc64;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
  if (fd >= 0 && fd <= 2) return real_pread()(fd, buf, count, offset);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_pread()(fd, buf, count, offset);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_pread()(fd, buf, count, offset);

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u64(p, (uint64_t)offset);
  p = wr_u32(p, (uint32_t)count);

  uint8_t resp[512 * 1024];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_PREAD, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_pread()(fd, buf, count, offset);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen > 0 && buf) memcpy(buf, data, dlen);
  return (ssize_t)rc64;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
  if (fd >= 0 && fd <= 2) return real_pwrite()(fd, buf, count, offset);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_pwrite()(fd, buf, count, offset);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_pwrite()(fd, buf, count, offset);

  if (count > (512u * 1024u)) count = (512u * 1024u);
  uint8_t req[32 + 512 * 1024];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u64(p, (uint64_t)offset);
  p = wr_u32(p, (uint32_t)count);
  if (count && buf) memcpy(p, buf, count);
  p += count;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_PWRITE, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_pwrite()(fd, buf, count, offset);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return (ssize_t)rc64;
}

off_t lseek(int fd, off_t offset, int whence) {
  if (fd >= 0 && fd <= 2) return real_lseek()(fd, offset, whence);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_lseek()(fd, offset, whence);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_lseek()(fd, offset, whence);

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i64(p, (int64_t)offset);
  p = wr_u32(p, (uint32_t)whence);
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_LSEEK, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_lseek()(fd, offset, whence);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return (off_t)-1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return (off_t)-1;
  }
  return (off_t)rc64;
}

// ---------------- stat-family wrappers ----------------

int stat(const char *pathname, struct stat *st) {
  if (g_inhook || g_fd < 0) return real_stat()(pathname, st);
  if (path_force_local(pathname)) return real_stat()(pathname, st);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }
  uint8_t req[4096 + 16];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_STAT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_stat()(pathname, st);
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen != sizeof(*st)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(st, data, sizeof(*st));
  return 0;
}

int lstat(const char *pathname, struct stat *st) {
  if (g_inhook || g_fd < 0) return real_lstat()(pathname, st);
  if (path_force_local(pathname)) return real_lstat()(pathname, st);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }
  uint8_t req[4096 + 16];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_LSTAT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_lstat()(pathname, st);
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen != sizeof(*st)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(st, data, sizeof(*st));
  return 0;
}

int fstat(int fd, struct stat *st) {
  if (fd >= 0 && fd <= 2) return real_fstat()(fd, st);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_fstat()(fd, st);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_fstat()(fd, st);
  uint8_t req[8];
  uint8_t *p = req;
  p = wr_u32(p, h);
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_FSTAT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_fstat()(fd, st);
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen != sizeof(*st)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(st, data, sizeof(*st));
  return 0;
}

int fstatat(int dirfd, const char *pathname, struct stat *st, int flags) {
  if (g_inhook || g_fd < 0) return real_fstatat()(dirfd, pathname, st, flags);
  if (path_force_local(pathname)) return real_fstatat()(dirfd, pathname, st, flags);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  uint32_t dir_handle = 0;
  int dir_is_remote = 0;
  pthread_mutex_lock(&g_lock);
  dir_is_remote = map_get_nolock(dirfd, &dir_handle);
  pthread_mutex_unlock(&g_lock);
  if (!dir_is_remote && dirfd != AT_FDCWD) {
    /* A non-remote dirfd is meaningless on the server. */
    return real_fstatat()(dirfd, pathname, st, flags);
  }

  uint8_t req[4096 + 64];
  uint8_t *p = req;
  p = wr_i32(p, dir_is_remote ? 1 : 0);
  if (dir_is_remote) p = wr_u32(p, dir_handle);
  else p = wr_i32(p, dirfd);
  p = wr_u32(p, (uint32_t)flags);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_FSTATAT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_fstatat()(dirfd, pathname, st, flags);
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen != sizeof(*st)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(st, data, sizeof(*st));
  return 0;
}

int mkdir(const char *pathname, mode_t mode) {
  if (g_inhook || g_fd < 0) return real_mkdir()(pathname, mode);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  uint8_t req[4096 + 16];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)mode);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_MKDIR, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_mkdir()(pathname, mode);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {
  if (g_inhook || g_fd < 0) return real_mkdirat()(dirfd, pathname, mode);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  uint32_t dir_handle = 0;
  int dir_is_remote = 0;
  if (!(dirfd >= 0 && dirfd <= 2)) {
    pthread_mutex_lock(&g_lock);
    dir_is_remote = map_get_nolock(dirfd, &dir_handle);
    pthread_mutex_unlock(&g_lock);
  }
  if (!dir_is_remote && dirfd != AT_FDCWD) {
    /* A non-remote dirfd is meaningless on the server. */
    return real_mkdirat()(dirfd, pathname, mode);
  }

  uint8_t req[4096 + 64];
  uint8_t *p = req;
  p = wr_i32(p, dir_is_remote ? 1 : 0);
  if (dir_is_remote) p = wr_u32(p, dir_handle);
  else p = wr_i32(p, dirfd);
  p = wr_u32(p, (uint32_t)mode);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_MKDIRAT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_mkdirat()(dirfd, pathname, mode);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int chdir(const char *path) {
  /* If remote is active, virtualize cwd on the server. Do not require local chdir to succeed. */
  if (g_inhook || g_fd < 0) return real_chdir()(path);
  size_t path_len = strnlen(path, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }
  uint8_t req[4096 + 16];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, path, path_len);
  p += path_len;
  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_CHDIR, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_chdir()(path);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int fchdir(int fd) {
  if (fd >= 0 && fd <= 2) return real_fchdir()(fd);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_fchdir()(fd);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_fchdir()(fd);

  uint8_t req[8];
  uint8_t *p = req;
  p = wr_u32(p, h);
  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_FCHDIR, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_fchdir()(fd);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

/* glibc compat symbols used by some binaries */
int __xstat(int ver, const char *path, struct stat *st) { (void)ver; return stat(path, st); }
int __lxstat(int ver, const char *path, struct stat *st) { (void)ver; return lstat(path, st); }
int __fxstat(int ver, int fd, struct stat *st) { (void)ver; return fstat(fd, st); }
int __fxstatat(int ver, int dirfd, const char *path, struct stat *st, int flags) { (void)ver; return fstatat(dirfd, path, st, flags); }

/* Some libcs/binaries may call internal-prefixed entrypoints. */
int __chdir(const char *path) { return chdir(path); }
int __fchdir(int fd) { return fchdir(fd); }
int __mkdir(const char *path, mode_t mode) { return mkdir(path, mode); }
int __mkdirat(int dirfd, const char *path, mode_t mode) { return mkdirat(dirfd, path, mode); }
int __unlink(const char *path) { return unlink(path); }
int __unlinkat(int dirfd, const char *path, int flags) { return unlinkat(dirfd, path, flags); }
int __rmdir(const char *path) { return rmdir(path); }
int __uname(struct utsname *buf) { return uname(buf); }
int __gethostname(char *name, size_t len) { return gethostname(name, len); }
int __sethostname(const char *name, size_t len) { return sethostname(name, len); }

ssize_t getdents64(int fd, void *dirp, size_t count) {
  if (fd >= 0 && fd <= 2) return real_getdents64()(fd, dirp, count);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_getdents64()(fd, dirp, count);

  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(fd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_getdents64()(fd, dirp, count);

  uint8_t req[16];
  uint8_t *p = req;
  p = wr_u32(p, h);
  const size_t cap = (size_t)(512u * 1024u);
  if (count > cap) count = cap;
  p = wr_u32(p, (uint32_t)count);

  uint8_t resp[512 * 1024];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_GETDENTS64, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_getdents64()(fd, dirp, count);
  }

  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen) memcpy(dirp, data, dlen);
  return (ssize_t)rc64;
}

ssize_t __getdents64(int fd, void *dirp, size_t count) { return getdents64(fd, dirp, count); }

int unlink(const char *pathname) {
  if (g_inhook || g_fd < 0) return real_unlink()(pathname);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }
  uint8_t req[4096 + 16];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;
  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_UNLINK, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_unlink()(pathname);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int unlinkat(int dirfd, const char *pathname, int flags) {
  if (g_inhook || g_fd < 0) return real_unlinkat()(dirfd, pathname, flags);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }

  uint32_t dir_handle = 0;
  int dir_is_remote = 0;
  if (!(dirfd >= 0 && dirfd <= 2) && dirfd >= 0) {
    pthread_mutex_lock(&g_lock);
    dir_is_remote = map_get_nolock(dirfd, &dir_handle);
    pthread_mutex_unlock(&g_lock);
  }
  if (!dir_is_remote && dirfd != AT_FDCWD) return real_unlinkat()(dirfd, pathname, flags);

  uint8_t req[4096 + 64];
  uint8_t *p = req;
  p = wr_i32(p, dir_is_remote ? 1 : 0);
  if (dir_is_remote) p = wr_u32(p, dir_handle);
  else p = wr_i32(p, dirfd);
  p = wr_u32(p, (uint32_t)flags);
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;

  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_UNLINKAT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_unlinkat()(dirfd, pathname, flags);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int rmdir(const char *pathname) {
  if (g_inhook || g_fd < 0) return real_rmdir()(pathname);
  size_t path_len = strnlen(pathname, 4096);
  if (path_len >= 4096) {
    errno = ENAMETOOLONG;
    return -1;
  }
  uint8_t req[4096 + 16];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)path_len);
  memcpy(p, pathname, path_len);
  p += path_len;
  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_RMDIR, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_rmdir()(pathname);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  if (g_inhook || g_fd < 0) return real_poll()(fds, nfds, timeout);
  if (!fds || nfds == 0) return real_poll()(fds, nfds, timeout);

  uint32_t *handles = (uint32_t *)calloc((size_t)nfds, sizeof(uint32_t));
  if (!handles) return real_poll()(fds, nfds, timeout);

  nfds_t remote_n = 0;
  for (nfds_t i = 0; i < nfds; i++) {
    int fd = fds[i].fd;
    fds[i].revents = 0;
    if (fd < 0 || (fd >= 0 && fd <= 2) || fd == g_fd) continue;
    pthread_mutex_lock(&g_lock);
    uint32_t h = 0;
    int is_remote = map_get_nolock(fd, &h);
    pthread_mutex_unlock(&g_lock);
    if (is_remote) {
      handles[i] = h;
      remote_n++;
    }
  }

  if (remote_n == 0) {
    free(handles);
    return real_poll()(fds, nfds, timeout);
  }

  uint64_t start_ns = 0;
  if (timeout > 0) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    start_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
  }

  for (;;) {
    int ready = 0;

    int local_ready = real_poll()(fds, nfds, 0);
    if (local_ready > 0) ready += local_ready;

    {
      uint8_t *req = (uint8_t *)malloc((size_t)(8 + (size_t)nfds * 8));
      if (req) {
        uint8_t *p = req;
        p = wr_i32(p, 0);
        p = wr_u32(p, (uint32_t)nfds);
        for (nfds_t i = 0; i < nfds; i++) {
          p = wr_u32(p, handles[i]);
          p = wr_u32(p, (uint32_t)(uint16_t)fds[i].events);
        }
        uint8_t resp[8192];
        uint32_t rlen = 0;
        if (rpc(RSYS_OP_POLL, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) == 0) {
          int64_t rc64 = -1;
          int32_t err = 0;
          const uint8_t *data = NULL;
          uint32_t dlen = 0;
          if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) == 0 && rc64 >= 0 && err == 0) {
            const uint8_t *dp = data;
            const uint8_t *end = data + dlen;
            uint32_t nn = 0;
            if (rd_u32(&dp, end, &nn) == 0 && nn == (uint32_t)nfds) {
              for (nfds_t i = 0; i < nfds; i++) {
                uint32_t rev = 0;
                if (rd_u32(&dp, end, &rev) != 0) break;
                if (handles[i] != 0) fds[i].revents |= (short)(rev & 0xffffu);
              }
              if (rc64 > 0) ready += (int)rc64;
            }
          }
        }
        free(req);
      }
    }

    if (ready > 0) {
      free(handles);
      return ready;
    }
    if (timeout == 0) {
      free(handles);
      return 0;
    }

    struct timespec sl;
    sl.tv_sec = 0;
    sl.tv_nsec = 50 * 1000 * 1000;
    nanosleep(&sl, NULL);

    if (timeout > 0) {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
      uint64_t elapsed_ms = (now_ns - start_ns) / 1000000ull;
      if ((int)elapsed_ms >= timeout) {
        free(handles);
        return 0;
      }
    }
  }
}

// ---------------- Networking wrappers ----------------

int socket(int domain, int type, int protocol) {
  /* Keep AF_UNIX local: it represents client-local services (NSS, systemd, etc.). */
  if (domain == AF_UNIX || domain == AF_LOCAL) return real_socket()(domain, type, protocol);
  if (g_inhook || g_fd < 0) return real_socket()(domain, type, protocol);

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_i32(p, domain);
  p = wr_i32(p, type);
  p = wr_i32(p, protocol);
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_SOCKET, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_socket()(domain, type, protocol);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }

  int lfd = alloc_placeholder_fd();
  if (lfd < 0) {
    errno = EMFILE;
    return -1;
  }
  pthread_mutex_lock(&g_lock);
  map_set_nolock(lfd, (uint32_t)rc64);
  pthread_mutex_unlock(&g_lock);
  return lfd;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_connect()(sockfd, addr, addrlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_connect()(sockfd, addr, addrlen);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_connect()(sockfd, addr, addrlen);

  if (!addr) {
    errno = EFAULT;
    return -1;
  }
  if (addrlen > 4096) {
    errno = EINVAL;
    return -1;
  }
  uint8_t req[4096 + 32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u32(p, (uint32_t)addrlen);
  memcpy(p, addr, addrlen);
  p += addrlen;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_CONNECT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_connect()(sockfd, addr, addrlen);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_bind()(sockfd, addr, addrlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_bind()(sockfd, addr, addrlen);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_bind()(sockfd, addr, addrlen);

  if (!addr) {
    errno = EFAULT;
    return -1;
  }
  if (addrlen > 4096) {
    errno = EINVAL;
    return -1;
  }

  uint8_t req[4096 + 32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u32(p, (uint32_t)addrlen);
  memcpy(p, addr, addrlen);
  p += addrlen;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_BIND, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_bind()(sockfd, addr, addrlen);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_getsockopt2()(sockfd, level, optname, optval, optlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_getsockopt2()(sockfd, level, optname, optval, optlen);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_getsockopt2()(sockfd, level, optname, optval, optlen);

  uint32_t cap = 0;
  if (optlen) cap = (uint32_t)(*optlen);
  if (cap > 4096) cap = 4096;

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, level);
  p = wr_i32(p, optname);
  p = wr_u32(p, cap);

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_GETSOCKOPT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_getsockopt2()(sockfd, level, optname, optval, optlen);
  }

  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  const uint8_t *dp = data;
  const uint8_t *end = data + dlen;
  uint32_t olen = 0;
  if (rd_u32(&dp, end, &olen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if ((size_t)(end - dp) < olen) {
    errno = EPROTO;
    return -1;
  }
  if (optval && cap) {
    uint32_t to_copy = olen;
    if (to_copy > cap) to_copy = cap;
    memcpy(optval, dp, to_copy);
  }
  if (optlen) *optlen = (socklen_t)olen;
  return 0;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_setsockopt2()(sockfd, level, optname, optval, optlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_setsockopt2()(sockfd, level, optname, optval, optlen);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_setsockopt2()(sockfd, level, optname, optval, optlen);

  if ((uint32_t)optlen > 4096) {
    errno = EINVAL;
    return -1;
  }
  uint8_t req[4096 + 32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, level);
  p = wr_i32(p, optname);
  p = wr_u32(p, (uint32_t)optlen);
  if (optlen && optval) memcpy(p, optval, (size_t)optlen);
  p += (uint32_t)optlen;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_SETSOCKOPT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_setsockopt2()(sockfd, level, optname, optval, optlen);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  if (sockfd >= 0 && sockfd <= 2) return real_sendmsg()(sockfd, msg, flags);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_sendmsg()(sockfd, msg, flags);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_sendmsg()(sockfd, msg, flags);
  if (!msg) {
    errno = EFAULT;
    return -1;
  }
  if (msg->msg_control && msg->msg_controllen) {
    errno = ENOTSUP;
    return -1;
  }
  if (msg->msg_iovlen > 128) {
    errno = E2BIG;
    return -1;
  }
  uint32_t name_len = (uint32_t)msg->msg_namelen;
  if (name_len > 4096) {
    errno = EINVAL;
    return -1;
  }
  uint32_t iovcnt = (uint32_t)msg->msg_iovlen;
  uint64_t total = 0;
  for (uint32_t i = 0; i < iovcnt; i++) {
    total += (uint64_t)msg->msg_iov[i].iov_len;
    if (total > (64ull * 1024ull * 1024ull)) {
      errno = E2BIG;
      return -1;
    }
  }
  uint8_t *req = (uint8_t *)malloc((size_t)(64 + name_len + 4 + (iovcnt * 4u) + total));
  if (!req) {
    errno = ENOMEM;
    return -1;
  }
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, flags);
  p = wr_u32(p, name_len);
  if (name_len && msg->msg_name) memcpy(p, msg->msg_name, name_len);
  p += name_len;
  p = wr_u32(p, iovcnt);
  for (uint32_t i = 0; i < iovcnt; i++) p = wr_u32(p, (uint32_t)msg->msg_iov[i].iov_len);
  for (uint32_t i = 0; i < iovcnt; i++) {
    size_t l = msg->msg_iov[i].iov_len;
    if (l) memcpy(p, msg->msg_iov[i].iov_base, l);
    p += l;
  }
  uint8_t resp[8192];
  uint32_t rlen = 0;
  int rpc_ok = rpc(RSYS_OP_SENDMSG, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen);
  free(req);
  if (rpc_ok != 0) return real_sendmsg()(sockfd, msg, flags);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return (ssize_t)rc64;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  if (sockfd >= 0 && sockfd <= 2) return real_recvmsg()(sockfd, msg, flags);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_recvmsg()(sockfd, msg, flags);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_recvmsg()(sockfd, msg, flags);
  if (!msg) {
    errno = EFAULT;
    return -1;
  }
  if (msg->msg_control && msg->msg_controllen) {
    errno = ENOTSUP;
    return -1;
  }
  if (msg->msg_iovlen > 128) {
    errno = E2BIG;
    return -1;
  }
  uint32_t name_cap = (uint32_t)msg->msg_namelen;
  if (name_cap > 4096) name_cap = 4096;
  uint32_t iovcnt = (uint32_t)msg->msg_iovlen;
  uint8_t req[32 + (128 * 4)];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, flags);
  p = wr_u32(p, name_cap);
  p = wr_u32(p, 0); /* control_cap unsupported */
  p = wr_u32(p, iovcnt);
  for (uint32_t i = 0; i < iovcnt; i++) p = wr_u32(p, (uint32_t)msg->msg_iov[i].iov_len);
  uint8_t resp[512 * 1024];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_RECVMSG, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_recvmsg()(sockfd, msg, flags);
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  const uint8_t *dp = data;
  const uint8_t *end = data + dlen;
  uint32_t got_name_len = 0;
  if (rd_u32(&dp, end, &got_name_len) != 0) {
    errno = EPROTO;
    return -1;
  }
  if ((size_t)(end - dp) < got_name_len) {
    errno = EPROTO;
    return -1;
  }
  if (msg->msg_name && msg->msg_namelen) {
    uint32_t to_copy = got_name_len;
    if (to_copy > name_cap) to_copy = name_cap;
    memcpy(msg->msg_name, dp, to_copy);
  }
  msg->msg_namelen = (socklen_t)got_name_len;
  dp += got_name_len;
  size_t remain = (size_t)rc64;
  for (uint32_t i = 0; i < iovcnt && remain; i++) {
    size_t cap2 = msg->msg_iov[i].iov_len;
    size_t n = cap2 < remain ? cap2 : remain;
    if ((size_t)(end - dp) < n) {
      errno = EPROTO;
      return -1;
    }
    memcpy(msg->msg_iov[i].iov_base, dp, n);
    dp += n;
    remain -= n;
  }
  msg->msg_flags = 0;
  msg->msg_controllen = 0;
  return (ssize_t)rc64;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  if (sockfd >= 0 && sockfd <= 2) return real_send()(sockfd, buf, len, flags);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_send()(sockfd, buf, len, flags);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_send()(sockfd, buf, len, flags);

  if (len > (512u * 1024u)) len = (512u * 1024u);
  uint8_t req[32 + 512 * 1024];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, flags);
  p = wr_u32(p, (uint32_t)len);
  if (len && buf) memcpy(p, buf, len);
  p += len;
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_SEND, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_send()(sockfd, buf, len, flags);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return (ssize_t)rc64;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  if (sockfd >= 0 && sockfd <= 2) return real_recv()(sockfd, buf, len, flags);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_recv()(sockfd, buf, len, flags);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_recv()(sockfd, buf, len, flags);

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, flags);
  p = wr_u32(p, (uint32_t)len);

  uint8_t resp[512 * 1024];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_RECV, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_recv()(sockfd, buf, len, flags);
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen > 0 && buf) memcpy(buf, data, dlen);
  return (ssize_t)rc64;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_sendto()(sockfd, buf, len, flags, dest_addr, addrlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_sendto()(sockfd, buf, len, flags, dest_addr, addrlen);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_sendto()(sockfd, buf, len, flags, dest_addr, addrlen);

  if (addrlen > 4096) {
    errno = EINVAL;
    return -1;
  }
  if (len > (512u * 1024u)) len = (512u * 1024u);

  uint8_t req[64 + 4096 + 512 * 1024];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, flags);
  p = wr_u32(p, (uint32_t)addrlen);
  if (addrlen) memcpy(p, dest_addr, (size_t)addrlen);
  p += (uint32_t)addrlen;
  p = wr_u32(p, (uint32_t)len);
  if (len && buf) memcpy(p, buf, len);
  p += (uint32_t)len;

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_SENDTO, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_sendto()(sockfd, buf, len, flags, dest_addr, addrlen);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return (ssize_t)rc64;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_recvfrom()(sockfd, buf, len, flags, src_addr, addrlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_recvfrom()(sockfd, buf, len, flags, src_addr, addrlen);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_recvfrom()(sockfd, buf, len, flags, src_addr, addrlen);

  uint32_t addr_cap = 0;
  if (src_addr && addrlen) addr_cap = (uint32_t)(*addrlen);
  if (addr_cap > 4096) addr_cap = 4096;

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, flags);
  p = wr_u32(p, (uint32_t)len);
  p = wr_u32(p, addr_cap);

  uint8_t resp[512 * 1024];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_RECVFROM, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_recvfrom()(sockfd, buf, len, flags, src_addr, addrlen);
  }

  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }

  /* data = [u32 addr_len][addr bytes][payload bytes] */
  const uint8_t *dp = data;
  const uint8_t *dend = data + dlen;
  uint32_t addr_len = 0;
  if (rd_u32(&dp, dend, &addr_len) != 0) {
    errno = EPROTO;
    return -1;
  }
  if ((size_t)(dend - dp) < addr_len) {
    errno = EPROTO;
    return -1;
  }
  const uint8_t *addr_bytes = dp;
  dp += addr_len;
  uint32_t pay_len = (uint32_t)(dend - dp);
  if (buf && pay_len) memcpy(buf, dp, pay_len);
  if (src_addr && addrlen) {
    uint32_t to_copy = addr_len;
    if (to_copy > addr_cap) to_copy = addr_cap;
    memcpy(src_addr, addr_bytes, to_copy);
    *addrlen = (socklen_t)addr_len;
  }
  return (ssize_t)rc64;
}

int shutdown(int sockfd, int how) {
  if (sockfd >= 0 && sockfd <= 2) return real_shutdown()(sockfd, how);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_shutdown()(sockfd, how);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_shutdown()(sockfd, how);
  uint8_t req[16];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, how);
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_SHUTDOWN, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_shutdown()(sockfd, how);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_getsockname()(sockfd, addr, addrlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_getsockname()(sockfd, addr, addrlen);

  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_getsockname()(sockfd, addr, addrlen);

  uint32_t cap = 0;
  if (addrlen) cap = (uint32_t)(*addrlen);
  if (cap > 4096) cap = 4096;

  uint8_t req[16];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u32(p, cap);

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_GETSOCKNAME, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_getsockname()(sockfd, addr, addrlen);
  }

  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }

  /* data = [u32 addr_len][addr bytes] */
  const uint8_t *dp = data;
  const uint8_t *dend = data + dlen;
  uint32_t alen = 0;
  if (rd_u32(&dp, dend, &alen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if ((size_t)(dend - dp) < alen) {
    errno = EPROTO;
    return -1;
  }
  if (addr && cap) {
    uint32_t to_copy = alen;
    if (to_copy > cap) to_copy = cap;
    memcpy(addr, dp, to_copy);
  }
  if (addrlen) *addrlen = (socklen_t)alen;
  return 0;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (sockfd >= 0 && sockfd <= 2) return real_getpeername()(sockfd, addr, addrlen);
  if (g_inhook || g_fd < 0 || sockfd == g_fd) return real_getpeername()(sockfd, addr, addrlen);

  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(sockfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_getpeername()(sockfd, addr, addrlen);

  uint32_t cap = 0;
  if (addrlen) cap = (uint32_t)(*addrlen);
  if (cap > 4096) cap = 4096;

  uint8_t req[16];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u32(p, cap);

  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_GETPEERNAME, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_getpeername()(sockfd, addr, addrlen);
  }

  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }

  const uint8_t *dp = data;
  const uint8_t *dend = data + dlen;
  uint32_t alen = 0;
  if (rd_u32(&dp, dend, &alen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if ((size_t)(dend - dp) < alen) {
    errno = EPROTO;
    return -1;
  }
  if (addr && cap) {
    uint32_t to_copy = alen;
    if (to_copy > cap) to_copy = cap;
    memcpy(addr, dp, to_copy);
  }
  if (addrlen) *addrlen = (socklen_t)alen;
  return 0;
}

int dup(int oldfd) {
  if (oldfd >= 0 && oldfd <= 2) return real_dup()(oldfd);
  if (g_inhook || g_fd < 0 || oldfd == g_fd) return real_dup()(oldfd);
  uint32_t h = 0;
  pthread_mutex_lock(&g_lock);
  int is_remote = map_get_nolock(oldfd, &h);
  pthread_mutex_unlock(&g_lock);
  if (!is_remote) return real_dup()(oldfd);

  uint8_t req[8];
  uint8_t *p = req;
  p = wr_u32(p, h);
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_DUP, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) return real_dup()(oldfd);
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  int lfd = alloc_placeholder_fd();
  if (lfd < 0) {
    errno = EMFILE;
    return -1;
  }
  pthread_mutex_lock(&g_lock);
  map_set_nolock(lfd, (uint32_t)rc64);
  pthread_mutex_unlock(&g_lock);
  return lfd;
}

DIR *opendir(const char *name) {
  if (g_inhook || g_fd < 0) return real_opendir()(name);
  int fd = open(name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return NULL;
  uint32_t h = 0;
  if (!is_remote_fd(fd, &h)) {
    /* Not remote: use libc opendir and close our fd. */
    close(fd);
    return real_opendir()(name);
  }
  struct rsys_DIR *d = (struct rsys_DIR *)calloc(1, sizeof(*d));
  if (!d) {
    close(fd);
    errno = ENOMEM;
    return NULL;
  }
  d->magic = RSYS_DIR_MAGIC;
  d->fd = fd;
  d->handle = h;
  return (DIR *)(void *)d;
}

DIR *opendir64(const char *name) {
  if (g_inhook || g_fd < 0) return real_opendir64()(name);
  return opendir(name);
}

DIR *fdopendir(int fd) {
  if (g_inhook || g_fd < 0) return real_fdopendir()(fd);
  uint32_t h = 0;
  if (!is_remote_fd(fd, &h)) return real_fdopendir()(fd);
  struct rsys_DIR *d = (struct rsys_DIR *)calloc(1, sizeof(*d));
  if (!d) {
    errno = ENOMEM;
    return NULL;
  }
  d->magic = RSYS_DIR_MAGIC;
  d->fd = fd;
  d->handle = h;
  return (DIR *)(void *)d;
}

struct dirent *readdir(DIR *dirp) {
  struct rsys_DIR *d = (struct rsys_DIR *)(void *)dirp;
  if (d->magic != RSYS_DIR_MAGIC) return real_readdir()(dirp);
  return rsys_dir_next(d);
}

struct dirent64 *readdir64(DIR *dirp) {
  struct rsys_DIR *d = (struct rsys_DIR *)(void *)dirp;
  if (d->magic != RSYS_DIR_MAGIC) return real_readdir64()(dirp);
  return rsys_dir_next64(d);
}

int closedir(DIR *dirp) {
  struct rsys_DIR *d = (struct rsys_DIR *)(void *)dirp;
  if (d->magic != RSYS_DIR_MAGIC) return real_closedir()(dirp);
  int fd = d->fd;
  d->magic = 0;
  free(d);
  return close(fd);
}

int dirfd(DIR *dirp) {
  struct rsys_DIR *d = (struct rsys_DIR *)(void *)dirp;
  if (d->magic != RSYS_DIR_MAGIC) return real_dirfd()(dirp);
  return d->fd;
}

void rewinddir(DIR *dirp) {
  struct rsys_DIR *d = (struct rsys_DIR *)(void *)dirp;
  if (d->magic != RSYS_DIR_MAGIC) {
    real_rewinddir()(dirp);
    return;
  }
  (void)lseek(d->fd, 0, SEEK_SET);
  d->buf_len = 0;
  d->buf_pos = 0;
}

int epoll_create(int size) {
  if (g_inhook || g_fd < 0) return real_epoll_create()(size);
  int epfd = real_epoll_create()(size);
  if (epfd < 0) return epfd;
  pthread_mutex_lock(&g_ep_mu);
  if (g_eps_n == g_eps_cap) {
    size_t ncap = g_eps_cap ? g_eps_cap * 2 : 16;
    struct rsys_ep *n = (struct rsys_ep *)realloc(g_eps, ncap * sizeof(*n));
    if (n) {
      g_eps = n;
      g_eps_cap = ncap;
    }
  }
  if (g_eps_n < g_eps_cap) {
    struct rsys_ep *ep = &g_eps[g_eps_n++];
    memset(ep, 0, sizeof(*ep));
    ep->magic = RSYS_EP_MAGIC;
    ep->epfd = epfd;
    ep->items = NULL;
    ep->n = 0;
    ep->cap = 0;
  }
  pthread_mutex_unlock(&g_ep_mu);
  return epfd;
}

int epoll_create1(int flags) {
  if (g_inhook || g_fd < 0) return real_epoll_create1()(flags);
  int epfd = real_epoll_create1()(flags);
  if (epfd < 0) return epfd;
  pthread_mutex_lock(&g_ep_mu);
  if (g_eps_n == g_eps_cap) {
    size_t ncap = g_eps_cap ? g_eps_cap * 2 : 16;
    struct rsys_ep *n = (struct rsys_ep *)realloc(g_eps, ncap * sizeof(*n));
    if (n) {
      g_eps = n;
      g_eps_cap = ncap;
    }
  }
  if (g_eps_n < g_eps_cap) {
    struct rsys_ep *ep = &g_eps[g_eps_n++];
    memset(ep, 0, sizeof(*ep));
    ep->magic = RSYS_EP_MAGIC;
    ep->epfd = epfd;
    ep->items = NULL;
    ep->n = 0;
    ep->cap = 0;
  }
  pthread_mutex_unlock(&g_ep_mu);
  return epfd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
  if (g_inhook || g_fd < 0) return real_epoll_ctl()(epfd, op, fd, event);
  pthread_mutex_lock(&g_ep_mu);
  struct rsys_ep *ep = ep_get(epfd);
  pthread_mutex_unlock(&g_ep_mu);
  if (!ep) return real_epoll_ctl()(epfd, op, fd, event);

  if (op == EPOLL_CTL_DEL) {
    pthread_mutex_lock(&g_ep_mu);
    int rc = ep_del(ep, fd);
    pthread_mutex_unlock(&g_ep_mu);
    if (rc != 0) return -1;
    return 0;
  }

  if (!event) {
    errno = EFAULT;
    return -1;
  }
  pthread_mutex_lock(&g_ep_mu);
  int rc = ep_add_or_mod(ep, fd, (uint32_t)event->events, event->data.u64);
  pthread_mutex_unlock(&g_ep_mu);
  if (rc != 0) {
    errno = ENOMEM;
    return -1;
  }
  return 0;
}

static int rsys_epoll_wait_impl(int epfd, struct epoll_event *events, int maxevents, int timeout) {
  if (maxevents <= 0) {
    errno = EINVAL;
    return -1;
  }
  pthread_mutex_lock(&g_ep_mu);
  struct rsys_ep *ep = ep_get(epfd);
  pthread_mutex_unlock(&g_ep_mu);
  if (!ep) return real_epoll_wait()(epfd, events, maxevents, timeout);

  /* Build local/remote watch lists snapshot */
  pthread_mutex_lock(&g_ep_mu);
  size_t n = ep->n;
  struct rsys_ep_item *items = NULL;
  if (n) {
    items = (struct rsys_ep_item *)malloc(n * sizeof(*items));
    if (!items) {
      pthread_mutex_unlock(&g_ep_mu);
      errno = ENOMEM;
      return -1;
    }
    memcpy(items, ep->items, n * sizeof(*items));
  }
  pthread_mutex_unlock(&g_ep_mu);

  /* Determine remote/local counts */
  size_t remote_n = 0, local_n = 0;
  for (size_t i = 0; i < n; i++) {
    if (!items[i].in_use) continue;
    if (items[i].handle) remote_n++;
    else local_n++;
  }

  /* Time-slice if mixed */
  uint64_t start_ns = 0;
  if (timeout > 0) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    start_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
  }

  for (;;) {
    int out_n = 0;

    /* Local poll */
    if (local_n) {
      struct pollfd *pf = (struct pollfd *)calloc(local_n, sizeof(*pf));
      if (pf) {
        size_t j = 0;
        for (size_t i = 0; i < n; i++) {
          if (!items[i].in_use || items[i].handle) continue;
          pf[j].fd = items[i].fd;
          pf[j].events = (short)ep_to_poll(items[i].events);
          pf[j].revents = 0;
          j++;
        }
        (void)real_poll()(pf, (nfds_t)local_n, 0);
        j = 0;
        for (size_t i = 0; i < n && out_n < maxevents; i++) {
          if (!items[i].in_use || items[i].handle) continue;
          short rev = pf[j].revents;
          if (rev) {
            events[out_n].events = poll_to_ep((uint32_t)(uint16_t)rev, items[i].events);
            events[out_n].data.u64 = items[i].data_u64;
            out_n++;
          }
          j++;
        }
        free(pf);
      }
    }

    /* Remote poll */
    if (remote_n && out_n < maxevents) {
      uint8_t *req = (uint8_t *)malloc(8 + remote_n * 8);
      if (req) {
        uint8_t *p = req;
        p = wr_i32(p, 0);
        p = wr_u32(p, (uint32_t)remote_n);
        for (size_t i = 0; i < n; i++) {
          if (!items[i].in_use || !items[i].handle) continue;
          p = wr_u32(p, items[i].handle);
          p = wr_u32(p, ep_to_poll(items[i].events));
        }
        uint8_t resp[8192];
        uint32_t rlen = 0;
        if (rpc(RSYS_OP_POLL, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) == 0) {
          int64_t rc64 = -1;
          int32_t err = 0;
          const uint8_t *data = NULL;
          uint32_t dlen = 0;
          if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) == 0 && rc64 >= 0 && err == 0) {
            const uint8_t *dp = data;
            const uint8_t *end = data + dlen;
            uint32_t nn = 0;
            if (rd_u32(&dp, end, &nn) == 0 && nn == (uint32_t)remote_n) {
              /* Apply revents back in the same remote iteration order */
              size_t ridx = 0;
              for (size_t i = 0; i < n && out_n < maxevents; i++) {
                if (!items[i].in_use || !items[i].handle) continue;
                uint32_t rev = 0;
                if (rd_u32(&dp, end, &rev) != 0) break;
                if (rev) {
                  events[out_n].events = poll_to_ep(rev, items[i].events);
                  events[out_n].data.u64 = items[i].data_u64;
                  out_n++;
                }
                ridx++;
              }
            }
          }
        }
        free(req);
      }
    }

    if (out_n > 0) {
      free(items);
      return out_n;
    }

    if (timeout == 0) {
      free(items);
      return 0;
    }

    /* Sleep a bit, then retry */
    struct timespec sl = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
    nanosleep(&sl, NULL);

    if (timeout > 0) {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
      uint64_t elapsed_ms = (now_ns - start_ns) / 1000000ull;
      if ((int)elapsed_ms >= timeout) {
        free(items);
        return 0;
      }
    }
  }
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
  if (g_inhook || g_fd < 0) return real_epoll_wait()(epfd, events, maxevents, timeout);
  return rsys_epoll_wait_impl(epfd, events, maxevents, timeout);
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask) {
  (void)sigmask;
  if (g_inhook || g_fd < 0) return real_epoll_pwait()(epfd, events, maxevents, timeout, sigmask);
  return rsys_epoll_wait_impl(epfd, events, maxevents, timeout);
}

int fcntl(int fd, int cmd, ...) {
  va_list ap;
  va_start(ap, cmd);
  long arg = 0;
  /* Many cmds take a 3rd arg; reading it unconditionally is fine for the ones we care about. */
  arg = va_arg(ap, long);
  va_end(ap);

  if (fd >= 0 && fd <= 2) return real_fcntl()(fd, cmd, arg);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_fcntl()(fd, cmd, arg);

  uint32_t h = 0;
  if (!is_remote_fd(fd, &h)) return real_fcntl()(fd, cmd, arg);

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_i32(p, cmd);
  p = wr_i64(p, (int64_t)arg);
  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_FCNTL, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_fcntl()(fd, cmd, arg);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return (int)rc64;
}

int fcntl64(int fd, int cmd, ...) {
  va_list ap;
  va_start(ap, cmd);
  long arg = va_arg(ap, long);
  va_end(ap);
  /* Route through fcntl() wrapper. */
  return fcntl(fd, cmd, arg);
}

int ioctl(int fd, unsigned long request, ...) {
  va_list ap;
  va_start(ap, request);
  void *argp = va_arg(ap, void *);
  va_end(ap);

  if (fd >= 0 && fd <= 2) return real_ioctl()(fd, request, argp);
  if (g_inhook || g_fd < 0 || fd == g_fd) return real_ioctl()(fd, request, argp);

  uint32_t h = 0;
  if (!is_remote_fd(fd, &h)) return real_ioctl()(fd, request, argp);

  /* Minimal int* ioctl support (curl uses FIONBIO; others may use FIONREAD). */
  if (!argp) return real_ioctl()(fd, request, argp);
  int inout = *(int *)argp;

  uint8_t req[32];
  uint8_t *p = req;
  p = wr_u32(p, h);
  p = wr_u64(p, (uint64_t)request);
  p = wr_i32(p, (int32_t)inout);
  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_IOCTL_INT, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_ioctl()(fd, request, argp);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen == 4) {
    const uint8_t *dp = data;
    const uint8_t *end = data + dlen;
    int32_t outv = 0;
    if (rd_i32(&dp, end, &outv) == 0) *(int *)argp = (int)outv;
  }
  return 0;
}

int uname(struct utsname *buf) {
  if (g_inhook || g_fd < 0) return real_uname()(buf);
  if (!buf) {
    errno = EFAULT;
    return -1;
  }
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_UNAME, NULL, 0, resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_uname()(buf);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen != sizeof(*buf)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(buf, data, sizeof(*buf));
  return 0;
}

int gethostname(char *name, size_t len) {
  if (g_inhook || g_fd < 0) return real_gethostname()(name, len);
  if (len > 4096) len = 4096;
  uint8_t req[8];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)len);
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_GETHOSTNAME, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_gethostname()(name, len);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  size_t to_copy = dlen;
  if (to_copy >= len) to_copy = len - 1;
  memcpy(name, data, to_copy);
  name[to_copy] = '\0';
  return 0;
}

int sethostname(const char *name, size_t len) {
  if (g_inhook || g_fd < 0) return real_sethostname()(name, len);
  if (len == 0 || len > 255) { errno = EINVAL; return -1; }
  uint8_t req[256 + 8];
  uint8_t *p = req;
  p = wr_u32(p, (uint32_t)len);
  memcpy(p, name, len);
  p += len;
  uint8_t resp[256];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_SETHOSTNAME, req, (uint32_t)(p - req), resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_sethostname()(name, len);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  if (parse_resp(resp, rlen, &rc64, &err, NULL, NULL) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  return 0;
}

char *getlogin(void) {
  errno = 0;
  if (real_getlogin()) {
    char *s = real_getlogin()();
    if (s) {
      errno = 0;
      return s;
    }
  }

  /* If there is no controlling TTY (ENXIO), provide a best-effort name so tools like `w`
   * don't abort. Prefer passwd name for current euid, fall back to numeric uid.
   */
  static __thread char buf[64];
  uid_t uid = geteuid();
  struct passwd pw;
  struct passwd *out = NULL;
  char tmp[4096];
  if (getpwuid_r(uid, &pw, tmp, sizeof(tmp), &out) == 0 && out && out->pw_name) {
    snprintf(buf, sizeof(buf), "%s", out->pw_name);
    errno = 0;
    return buf;
  }
  snprintf(buf, sizeof(buf), "%u", (unsigned)uid);
  errno = 0;
  return buf;
}

int getlogin_r(char *name, size_t len) {
  if (len == 0) return ERANGE;
  if (real_getlogin_r()) {
    int rc = real_getlogin_r()(name, len);
    if (rc == 0) return 0;
  }
  const char *s = getlogin();
  size_t n = strnlen(s, len);
  if (n >= len) return ERANGE;
  memcpy(name, s, n + 1);
  return 0;
}

char *__getlogin(void) { return getlogin(); }
int __getlogin_r(char *name, size_t len) { return getlogin_r(name, len); }
char *__libc_getlogin(void) { return getlogin(); }
int __libc_getlogin_r(char *name, size_t len) { return getlogin_r(name, len); }

/* Some binaries use internal-prefixed entrypoints. */
int __statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *stx) {
  return statx(dirfd, pathname, flags, mask, stx);
}

int sysinfo(struct sysinfo *info) {
  if (g_inhook || g_fd < 0) return real_sysinfo()(info);
  if (!info) {
    errno = EFAULT;
    return -1;
  }
  uint8_t resp[8192];
  uint32_t rlen = 0;
  if (rpc(RSYS_OP_SYSINFO, NULL, 0, resp, (uint32_t)sizeof(resp), &rlen) != 0) {
    return real_sysinfo()(info);
  }
  int64_t rc64 = -1;
  int32_t err = 0;
  const uint8_t *data = NULL;
  uint32_t dlen = 0;
  if (parse_resp(resp, rlen, &rc64, &err, &data, &dlen) != 0) {
    errno = EPROTO;
    return -1;
  }
  if (rc64 < 0) {
    errno = err ? err : EIO;
    return -1;
  }
  if (dlen != sizeof(*info)) {
    errno = EPROTO;
    return -1;
  }
  memcpy(info, data, sizeof(*info));
  return 0;
}

struct passwd *getpwuid(uid_t uid) {
  if (g_inhook || g_fd < 0) return real_getpwuid()(uid);
  struct passwd *pw = real_getpwuid()(uid);
  if (pw) return pw;

  /* Best-effort fallback: avoid hard failures in tools like `w`. */
  static __thread struct passwd fake;
  static __thread char namebuf[32];
  snprintf(namebuf, sizeof(namebuf), "%u", (unsigned)uid);
  memset(&fake, 0, sizeof(fake));
  fake.pw_name = namebuf;
  fake.pw_uid = uid;
  fake.pw_gid = (gid_t)-1;
  errno = 0;
  return &fake;
}

int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
  if (g_inhook || g_fd < 0) return real_getpwuid_r()(uid, pwd, buf, buflen, result);
  int rc = real_getpwuid_r()(uid, pwd, buf, buflen, result);
  if (rc == 0 && *result) return 0;
  if (buflen == 0) return rc;

  /* Best-effort fallback: synthesize a minimal passwd entry. */
  char tmp[32];
  int n = snprintf(tmp, sizeof(tmp), "%u", (unsigned)uid);
  if (n < 0 || (size_t)n + 1 > buflen) return ERANGE;
  memcpy(buf, tmp, (size_t)n + 1);
  memset(pwd, 0, sizeof(*pwd));
  pwd->pw_name = buf;
  pwd->pw_uid = uid;
  pwd->pw_gid = (gid_t)-1;
  *result = pwd;
  errno = 0;
  return 0;
}

long syscall(long number, ...) {
  va_list ap;
  va_start(ap, number);
  long a1 = va_arg(ap, long);
  long a2 = va_arg(ap, long);
  long a3 = va_arg(ap, long);
  long a4 = va_arg(ap, long);
  long a5 = va_arg(ap, long);
  long a6 = va_arg(ap, long);
  va_end(ap);

  if (g_inhook) return real_syscall()(number, a1, a2, a3, a4, a5, a6);

  if (number == SYS_sysinfo) {
    int rc = sysinfo((struct sysinfo *)(uintptr_t)a1);
    if (rc != 0) return -1;
    return 0;
  }

  if (number == SYS_openat2) {
    return (long)openat2((int)a1, (const char *)(uintptr_t)a2, (const struct open_how *)(uintptr_t)a3, (size_t)a4);
  }
  if (number == SYS_statx) {
    return (long)statx((int)a1, (const char *)(uintptr_t)a2, (int)a3, (unsigned int)a4, (struct statx *)(uintptr_t)a5);
  }

  return real_syscall()(number, a1, a2, a3, a4, a5, a6);
}

/* 64-bit alias symbols used by some binaries */
int open64(const char *pathname, int flags, ...) {
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
    return open(pathname, flags, mode);
  }
  return open(pathname, flags);
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
    return openat(dirfd, pathname, flags, mode);
  }
  return openat(dirfd, pathname, flags);
}

ssize_t pread64(int fd, void *buf, size_t count, off_t offset) { return pread(fd, buf, count, offset); }
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) { return pwrite(fd, buf, count, offset); }
off_t lseek64(int fd, off_t offset, int whence) { return lseek(fd, offset, whence); }
