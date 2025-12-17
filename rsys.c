#define _GNU_SOURCE

#include "rsys_protocol.h"
#include "rsys_tracee_mem.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

#if !defined(__x86_64__)
#error "rsys currently supports x86_64 only"
#endif

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

// Forward decl (used by env helpers before definition).
static int rsys_call(int sock, uint16_t type, const uint8_t *req, uint32_t req_len, struct rsys_resp *out_resp,
                     uint8_t **out_data, uint32_t *out_data_len);

static void usage(FILE *out, const char *argv0) {
  fprintf(out,
          "usage: %s [options] <server_ip_or_host> <port> <prog> [args...]\n"
          "\n"
          "Remote syscall forwarding client.\n"
          "\n"
          "options:\n"
          "  -v           verbose logging\n"
          "  -e           use local environment for the traced program\n"
          "  -E           use remote environment for the traced program (default)\n"
          "  -h, -?, --help  show this help\n",
          argv0);
}

static int fetch_remote_env(int sock, uint8_t **out_blob, uint32_t *out_len) {
  struct rsys_resp resp;
  uint8_t *data = NULL;
  uint32_t data_len = 0;
  if (rsys_call(sock, RSYS_REQ_GETENV, NULL, 0, &resp, &data, &data_len) < 0) return -1;
  int64_t rr = rsys_resp_raw_ret(&resp);
  int32_t eno = rsys_resp_err_no(&resp);
  if (rr == -1) {
    free(data);
    errno = (eno != 0) ? eno : EIO;
    return -1;
  }
  *out_blob = data;
  *out_len = data_len;
  return 0;
}

static char **envp_from_nul_blob(uint8_t *blob, uint32_t len) {
  if (!blob || len == 0) {
    char **envp = (char **)calloc(1, sizeof(char *));
    return envp;
  }
  if (blob[len - 1] != '\0') {
    // Ensure termination.
    uint8_t *nb = (uint8_t *)realloc(blob, (size_t)len + 1);
    if (!nb) return NULL;
    nb[len] = '\0';
    blob = nb;
    len++;
  }
  size_t n = 0;
  for (uint32_t i = 0; i < len; i++) {
    if (blob[i] == '\0') n++;
  }
  char **envp = (char **)calloc(n + 1, sizeof(char *));
  if (!envp) return NULL;
  size_t idx = 0;
  char *p = (char *)blob;
  char *end = (char *)blob + len;
  while (p < end) {
    size_t sl = strlen(p);
    if (sl == 0) break;
    envp[idx++] = p;
    p += sl + 1;
  }
  envp[idx] = NULL;
  return envp;
}

struct fd_map_ent {
  int local_fd;
  int remote_fd;
};

struct remote_ref_ent {
  int remote_fd;
  uint32_t refs;
};

struct remote_refs {
  struct remote_ref_ent *v;
  size_t n;
  size_t cap;
};

static void rrefs_init(struct remote_refs *r) {
  r->v = NULL;
  r->n = 0;
  r->cap = 0;
}

static uint32_t rrefs_get(const struct remote_refs *r, int remote_fd) {
  for (size_t i = 0; i < r->n; i++) {
    if (r->v[i].remote_fd == remote_fd) return r->v[i].refs;
  }
  return 0;
}

static int rrefs_inc(struct remote_refs *r, int remote_fd) {
  for (size_t i = 0; i < r->n; i++) {
    if (r->v[i].remote_fd == remote_fd) {
      r->v[i].refs++;
      return 0;
    }
  }
  if (r->n == r->cap) {
    size_t ncap = r->cap ? (r->cap * 2) : 16;
    void *nv = realloc(r->v, ncap * sizeof(*r->v));
    if (!nv) return -1;
    r->v = (struct remote_ref_ent *)nv;
    r->cap = ncap;
  }
  r->v[r->n++] = (struct remote_ref_ent){.remote_fd = remote_fd, .refs = 1};
  return 0;
}

// Returns the new refcount (0 means removed).
static uint32_t rrefs_dec(struct remote_refs *r, int remote_fd) {
  for (size_t i = 0; i < r->n; i++) {
    if (r->v[i].remote_fd == remote_fd) {
      if (r->v[i].refs > 1) {
        r->v[i].refs--;
        return r->v[i].refs;
      }
      r->v[i] = r->v[r->n - 1];
      r->n--;
      return 0;
    }
  }
  return 0;
}

struct fd_map {
  struct fd_map_ent *v;
  size_t n;
  size_t cap;
  int next_local;
};

static void fdmap_init(struct fd_map *m) {
  m->v = NULL;
  m->n = 0;
  m->cap = 0;
  m->next_local = 100000; // fake fds start high
}

static int fdmap_find_remote(const struct fd_map *m, int local_fd) {
  for (size_t i = 0; i < m->n; i++) {
    if (m->v[i].local_fd == local_fd) return m->v[i].remote_fd;
  }
  return -1;
}

static int fdmap_add_remote(struct fd_map *m, struct remote_refs *rrefs, int remote_fd) {
  if (m->n == m->cap) {
    size_t ncap = m->cap ? (m->cap * 2) : 16;
    struct fd_map_ent *nv = (struct fd_map_ent *)realloc(m->v, ncap * sizeof(*nv));
    if (!nv) return -1;
    m->v = nv;
    m->cap = ncap;
  }
  int lfd = m->next_local++;
  m->v[m->n++] = (struct fd_map_ent){.local_fd = lfd, .remote_fd = remote_fd};
  if (rrefs_inc(rrefs, remote_fd) < 0) {
    // Roll back mapping on failure to track refs.
    m->n--;
    return -1;
  }
  return lfd;
}

static int fdmap_remove_local(struct fd_map *m, int local_fd, int *out_remote_fd) {
  for (size_t i = 0; i < m->n; i++) {
    if (m->v[i].local_fd == local_fd) {
      if (out_remote_fd) *out_remote_fd = m->v[i].remote_fd;
      m->v[i] = m->v[m->n - 1];
      m->n--;
      return 0;
    }
  }
  return -1;
}

static int fdmap_clone(struct fd_map *dst, const struct fd_map *src, struct remote_refs *rrefs) {
  dst->v = NULL;
  dst->n = 0;
  dst->cap = 0;
  dst->next_local = src->next_local;
  if (src->n == 0) return 0;
  dst->v = (struct fd_map_ent *)malloc(src->n * sizeof(*dst->v));
  if (!dst->v) return -1;
  dst->cap = src->n;
  dst->n = src->n;
  memcpy(dst->v, src->v, src->n * sizeof(*dst->v));
  for (size_t i = 0; i < dst->n; i++) {
    if (rrefs_inc(rrefs, dst->v[i].remote_fd) < 0) {
      // Roll back ref increments already made.
      for (size_t j = 0; j < i; j++) (void)rrefs_dec(rrefs, dst->v[j].remote_fd);
      free(dst->v);
      dst->v = NULL;
      dst->n = 0;
      dst->cap = 0;
      return -1;
    }
  }
  return 0;
}

static int connect_tcp(const char *host, const char *port_str) {
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

static int rsys_call(int sock, uint16_t type, const uint8_t *req, uint32_t req_len, struct rsys_resp *out_resp,
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

static int64_t raw_sys_ret(int64_t raw_ret, int32_t err_no) {
  if (raw_ret == -1) return -(int64_t)err_no;
  return raw_ret;
}

// To keep dynamically-linked executables working without emulating mmap-on-remote-fd,
// we DO NOT remote opens/stats of common loader/library paths.
static int should_remote_path(const char *path) {
  if (!path) return 0;
  if (path[0] != '/') return 1; // relative paths: treat as remote (matches client cwd semantics poorly, but ok for now)

  const char *local_prefixes[] = {
      "/lib/", "/usr/lib/", "/usr/lib64/", "/lib64/", "/etc/ld.so", "/proc/self/", "/dev/", NULL,
  };
  for (int i = 0; local_prefixes[i]; i++) {
    size_t n = strlen(local_prefixes[i]);
    if (strncmp(path, local_prefixes[i], n) == 0) return 0;
  }
  return 1;
}

struct pending_sys {
  int active;
  long nr;

  // For emulation on syscall-exit
  int64_t set_rax;

  // Buffers to write into tracee on exit (supports multiple writes)
  struct out_write {
    uintptr_t addr;
    uint8_t *bytes;
    uint32_t len;
  } * outs;
  size_t outs_n;
  size_t outs_cap;

  // If the syscall used a fake local fd, remember it for close cleanup.
  int close_local_fd;
};

static void pending_clear(struct pending_sys *p) {
  p->active = 0;
  p->nr = 0;
  p->set_rax = 0;
  if (p->outs) {
    for (size_t i = 0; i < p->outs_n; i++) {
      free(p->outs[i].bytes);
    }
    free(p->outs);
  }
  p->outs = NULL;
  p->outs_n = 0;
  p->outs_cap = 0;
  p->close_local_fd = -1;
}

static int pending_add_out(struct pending_sys *p, uintptr_t addr, uint8_t *bytes, uint32_t len) {
  if (!bytes || len == 0) {
    free(bytes);
    return 0;
  }
  if (p->outs_n == p->outs_cap) {
    size_t ncap = p->outs_cap ? (p->outs_cap * 2) : 4;
    void *nv = realloc(p->outs, ncap * sizeof(*p->outs));
    if (!nv) return -1;
    p->outs = (struct out_write *)nv;
    p->outs_cap = ncap;
  }
  p->outs[p->outs_n++] = (struct out_write){.addr = addr, .bytes = bytes, .len = len};
  return 0;
}

static int intercept_syscall(pid_t pid, struct user_regs_struct *regs, int sock, struct fd_map *fm, struct remote_refs *rrefs,
                             struct pending_sys *pend) {
  long nr = (long)regs->orig_rax;

  // Helpers to map local fd to remote fd
  auto int map_fd(int local) {
    return fdmap_find_remote(fm, local);
  }

  const uint32_t MAX_BLOB = (1u << 20);   // 1MB per call
  const uint32_t MAX_ADDR = 512;          // sockaddr cap
  const uint32_t MAX_CTRL = 64u * 1024u;  // cmsg cap
  const uint32_t MAX_IOV = 128;           // iov count cap

  // openat(dirfd, pathname, flags, mode)
  if (nr == __NR_openat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int mode = (int)regs->r10;

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0; // let it run locally on failure
    if (!should_remote_path(path)) return 0; // local

    vlog("[rsys] openat(dirfd=%d, path=%s, flags=0x%x, mode=0%o) -> remote\n", dirfd_local, path, flags, mode);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) {
      // dirfd not remote-mapped; keep local
      return 0;
    }

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 28 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_s64(req + 16, (int64_t)mode);
    rsys_put_u32(req + 24, path_len);
    memcpy(req + 28, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_OPENAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);

    int64_t rax = raw_sys_ret(rr, eno);
    if (rr >= 0) {
      int local_fake = fdmap_add_remote(fm, rrefs, (int)rr);
      if (local_fake < 0) {
        // best effort: close remote
        uint8_t creq[8];
        rsys_put_s64(creq + 0, rr);
        struct rsys_resp cresp;
        uint8_t *cdata = NULL;
        uint32_t cdlen = 0;
        (void)rsys_call(sock, RSYS_REQ_CLOSE, creq, sizeof(creq), &cresp, &cdata, &cdlen);
        free(cdata);
        rax = -ENOMEM;
      } else {
        rax = local_fake;
      }
    }

    vlog("[rsys] openat -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=%" PRId64 "\n", rr, eno, rax);

    // Replace syscall with harmless getpid and set on exit.
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    pend->close_local_fd = -1;
    return 1;
  }

  // close(fd)
  if (nr == __NR_close) {
    int fd_local = (int)regs->rdi;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0; // local close

    uint32_t refs = rrefs_get(rrefs, fd_remote);
    if (refs == 0) return 0; // inconsistent; fall back to local

    // If this isn't the last reference, we can emulate close(2) locally by removing the mapping for this process only.
    if (refs > 1) {
      int removed_remote = -1;
      if (fdmap_remove_local(fm, fd_local, &removed_remote) < 0) return 0;
      (void)rrefs_dec(rrefs, removed_remote);

      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->set_rax = 0;
      pend->close_local_fd = -1;
      return 1;
    }

    // Last reference: close on remote, and only remove mapping if that succeeds.
    vlog("[rsys] close(fd=%d -> remote_fd=%d) -> remote\n", fd_local, fd_remote);
    uint8_t req[8];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_CLOSE, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);
    int64_t rr_ret = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr_ret, eno);
    if (rr_ret == 0) {
      int removed_remote = -1;
      if (fdmap_remove_local(fm, fd_local, &removed_remote) == 0) {
        (void)rrefs_dec(rrefs, removed_remote);
      }
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    pend->close_local_fd = -1;
    return 1;
  }

  // read(fd, buf, count)
  if (nr == __NR_read) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0; // local read

    vlog("[rsys] read(fd=%d -> remote_fd=%d, count=%zu)\n", fd_local, fd_remote, count);

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)count);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_READ, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    vlog("[rsys] read -> raw_ret=%" PRId64 " errno=%d copy_bytes=%u rax=%" PRId64 "\n", rr, eno, data_len, rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    pend->close_local_fd = -1;
    return 1;
  }

  // write(fd, buf, count)
  if (nr == __NR_write) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0; // local write (stdout/stderr)

    vlog("[rsys] write(fd=%d -> remote_fd=%d, count=%zu)\n", fd_local, fd_remote, count);

    uint32_t dlen = (count > (1u << 20)) ? (1u << 20) : (uint32_t)count;
    uint32_t req_len = 12 + dlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");

    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, dlen);
    if (rsys_read_mem(pid, req + 12, buf_addr, dlen) < 0) {
      free(req);
      return 0;
    }

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_WRITE, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] write -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // pread64(fd, buf, count, offset)
  if (nr == __NR_pread64) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;
    int64_t off = (int64_t)regs->r10;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] pread64(fd=%d -> remote_fd=%d, count=%zu, off=%" PRId64 ")\n", fd_local, fd_remote, count, off);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)count);
    rsys_put_s64(req + 16, off);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_PREAD64, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] pread64 -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    return 1;
  }

  // pwrite64(fd, buf, count, offset)
  if (nr == __NR_pwrite64) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;
    int64_t off = (int64_t)regs->r10;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] pwrite64(fd=%d -> remote_fd=%d, count=%zu, off=%" PRId64 ")\n", fd_local, fd_remote, count, off);

    uint32_t dlen = (count > (1u << 20)) ? (1u << 20) : (uint32_t)count;
    uint32_t req_len = 20 + dlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, off);
    rsys_put_u32(req + 16, dlen);
    if (rsys_read_mem(pid, req + 20, buf_addr, dlen) < 0) {
      free(req);
      return 0;
    }

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_PWRITE64, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] pwrite64 -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // lseek(fd, off, whence)
  if (nr == __NR_lseek) {
    int fd_local = (int)regs->rdi;
    int64_t off = (int64_t)regs->rsi;
    int whence = (int)regs->rdx;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] lseek(fd=%d -> remote_fd=%d, off=%" PRId64 ", whence=%d)\n", fd_local, fd_remote, off, whence);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, off);
    rsys_put_s64(req + 16, (int64_t)whence);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_LSEEK, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] lseek -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // newfstatat(dirfd, pathname, statbuf, flags) -- glibc stat/lstat
  if (nr == __NR_newfstatat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    uintptr_t st_addr = (uintptr_t)regs->rdx;
    int flags = (int)regs->r10;

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] newfstatat(dirfd=%d, path=%s, flags=0x%x) -> remote\n", dirfd_local, path, flags);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 20 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, path_len);
    memcpy(req + 20, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_NEWFSTATAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] newfstatat -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, st_addr, data, data_len);
    return 1;
  }

  // fstat(fd, statbuf)
  if (nr == __NR_fstat) {
    int fd_local = (int)regs->rdi;
    uintptr_t st_addr = (uintptr_t)regs->rsi;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] fstat(fd=%d -> remote_fd=%d)\n", fd_local, fd_remote);

    uint8_t req[8];
    rsys_put_s64(req + 0, (int64_t)fd_remote);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_FSTAT, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] fstat -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, st_addr, data, data_len);
    return 1;
  }

  // statx(dirfd, pathname, flags, mask, statxbuf)
  if (nr == __NR_statx) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    unsigned int mask = (unsigned int)regs->r10;
    uintptr_t stx_addr = (uintptr_t)regs->r8;

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] statx(dirfd=%d, path=%s, flags=0x%x, mask=0x%x) -> remote\n", dirfd_local, path, flags, mask);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 24 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, mask);
    rsys_put_u32(req + 20, path_len);
    memcpy(req + 24, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_STATX, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] statx -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, stx_addr, data, data_len);
    return 1;
  }

  // getdents64(fd, dirp, count)
  if (nr == __NR_getdents64) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t count = (size_t)regs->rdx;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    vlog("[rsys] getdents64(fd=%d -> remote_fd=%d, count=%zu)\n", fd_local, fd_remote, count);

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)count);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_GETDENTS64, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] getdents64 -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    return 1;
  }

  // access(pathname, mode)
  if (nr == __NR_access) {
    uintptr_t path_addr = (uintptr_t)regs->rdi;
    int mode = (int)regs->rsi;

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] access(path=%s, mode=0x%x) -> remote\n", path, mode);

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 8 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, (uint32_t)mode);
    rsys_put_u32(req + 4, path_len);
    memcpy(req + 8, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_ACCESS, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] access -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // readlinkat(dirfd, pathname, buf, bufsz)
  if (nr == __NR_readlinkat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    uintptr_t buf_addr = (uintptr_t)regs->rdx;
    size_t bufsz = (size_t)regs->r10;

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] readlinkat(dirfd=%d, path=%s, bufsz=%zu) -> remote\n", dirfd_local, path, bufsz);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 16 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_u32(req + 8, (uint32_t)bufsz);
    rsys_put_u32(req + 12, path_len);
    memcpy(req + 16, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_READLINKAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] readlinkat -> rax=%" PRId64 " copy_bytes=%u\n", rax, data_len);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    (void)pending_add_out(pend, buf_addr, data, data_len);
    return 1;
  }

  // unlinkat(dirfd, pathname, flags)
  if (nr == __NR_unlinkat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] unlinkat(dirfd=%d, path=%s, flags=0x%x) -> remote\n", dirfd_local, path, flags);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 20 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, path_len);
    memcpy(req + 20, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_UNLINKAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] unlinkat -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // mkdirat(dirfd, pathname, mode)
  if (nr == __NR_mkdirat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int mode = (int)regs->rdx;

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] mkdirat(dirfd=%d, path=%s, mode=0%o) -> remote\n", dirfd_local, path, mode);

    int dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
    if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;

    uint32_t path_len = (uint32_t)strlen(path) + 1;
    uint32_t req_len = 20 + path_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)mode);
    rsys_put_u32(req + 16, path_len);
    memcpy(req + 20, path, path_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_MKDIRAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] mkdirat -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
  if (nr == __NR_renameat2) {
    int olddirfd_local = (int)regs->rdi;
    uintptr_t oldp_addr = (uintptr_t)regs->rsi;
    int newdirfd_local = (int)regs->rdx;
    uintptr_t newp_addr = (uintptr_t)regs->r10;
    unsigned int flags = (unsigned int)regs->r8;

    char oldp[4096];
    char newp[4096];
    if (rsys_read_cstring(pid, oldp_addr, oldp, sizeof(oldp)) < 0) return 0;
    if (rsys_read_cstring(pid, newp_addr, newp, sizeof(newp)) < 0) return 0;

    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] renameat2(old=%s, new=%s, flags=0x%x) -> remote\n", oldp, newp, flags);

    int olddirfd_remote = (olddirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(olddirfd_local);
    int newdirfd_remote = (newdirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(newdirfd_local);
    if (olddirfd_local != AT_FDCWD && olddirfd_remote < 0) return 0;
    if (newdirfd_local != AT_FDCWD && newdirfd_remote < 0) return 0;

    uint32_t old_len = (uint32_t)strlen(oldp) + 1;
    uint32_t new_len = (uint32_t)strlen(newp) + 1;
    uint32_t req_len = 32 + old_len + new_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)olddirfd_remote);
    rsys_put_s64(req + 8, (int64_t)newdirfd_remote);
    rsys_put_s64(req + 16, (int64_t)flags);
    rsys_put_u32(req + 24, old_len);
    rsys_put_u32(req + 28, new_len);
    memcpy(req + 32, oldp, old_len);
    memcpy(req + 32 + old_len, newp, new_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RENAMEAT2, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));

    vlog("[rsys] renameat2 -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // utimensat(dirfd, pathname, times[2], flags)
  if (nr == __NR_utimensat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    uintptr_t times_addr = (uintptr_t)regs->rdx;
    int flags = (int)regs->r10;

    // Special case: pathname == NULL => operate on dirfd (futimens semantics).
    uint32_t path_len = 0;
    char path[4096];

    int dirfd_remote;
    if (path_addr == 0) {
      dirfd_remote = map_fd(dirfd_local);
      if (dirfd_remote < 0) return 0;
    } else {
      if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
      if (!should_remote_path(path)) return 0;
      dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
      if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;
      path_len = (uint32_t)strlen(path) + 1;
    }

    uint32_t has_times = (times_addr != 0) ? 1u : 0u;
    uint32_t req_len = 24 + path_len + (has_times ? 32u : 0u);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");

    rsys_put_s64(req + 0, (int64_t)dirfd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, has_times);
    rsys_put_u32(req + 20, path_len);
    if (path_len) memcpy(req + 24, path, path_len);

    if (has_times) {
      struct timespec ts[2];
      if (rsys_read_mem(pid, &ts[0], times_addr, sizeof(ts)) < 0) {
        free(req);
        return 0;
      }
      uint8_t *tp = req + 24 + path_len;
      rsys_put_s64(tp + 0, (int64_t)ts[0].tv_sec);
      rsys_put_s64(tp + 8, (int64_t)ts[0].tv_nsec);
      rsys_put_s64(tp + 16, (int64_t)ts[1].tv_sec);
      rsys_put_s64(tp + 24, (int64_t)ts[1].tv_nsec);
    }

    vlog("[rsys] utimensat(dirfd=%d -> remote=%d, path=%s, times=%s, flags=0x%x) -> remote\n", dirfd_local, dirfd_remote,
         path_len ? path : "NULL", has_times ? "set" : "NULL", flags);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_UTIMENSAT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    vlog("[rsys] utimensat -> rax=%" PRId64 "\n", rax);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // uname(buf)
  if (nr == __NR_uname) {
    uintptr_t u_addr = (uintptr_t)regs->rdi;
    vlog("[rsys] uname() -> remote\n");

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_UNAME, NULL, 0, &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len != (uint32_t)sizeof(struct utsname)) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        (void)pending_add_out(pend, u_addr, data, data_len);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // sethostname(name, len)
  if (nr == __NR_sethostname || nr == __NR_setdomainname) {
    uintptr_t name_addr = (uintptr_t)regs->rdi;
    uint32_t nlen = (uint32_t)regs->rsi;
    if (nlen > 4096) nlen = 4096;
    uint8_t *name = NULL;
    if (name_addr && nlen) {
      name = (uint8_t *)malloc(nlen);
      if (!name) die("malloc");
      if (rsys_read_mem(pid, name, name_addr, nlen) < 0) {
        free(name);
        return 0;
      }
    } else {
      nlen = 0;
    }

    uint32_t req_len = 4 + nlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, nlen);
    if (nlen) memcpy(req + 4, name, nlen);
    free(name);

    uint16_t mtype = (nr == __NR_sethostname) ? RSYS_REQ_SETHOSTNAME : RSYS_REQ_SETDOMAINNAME;
    vlog("[rsys] %s(len=%u) -> remote\n", (nr == __NR_sethostname) ? "sethostname" : "setdomainname", nlen);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, mtype, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // socket(domain, type, protocol)
  if (nr == __NR_socket) {
    int domain = (int)regs->rdi;
    int type = (int)regs->rsi;
    int protocol = (int)regs->rdx;

    vlog("[rsys] socket(domain=%d, type=%d, proto=%d) -> remote\n", domain, type, protocol);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)domain);
    rsys_put_s64(req + 8, (int64_t)type);
    rsys_put_s64(req + 16, (int64_t)protocol);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SOCKET, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);
    if (rr >= 0) {
      int local_fake = fdmap_add_remote(fm, rrefs, (int)rr);
      if (local_fake < 0) {
        // best-effort close remote
        uint8_t creq[8];
        rsys_put_s64(creq + 0, rr);
        struct rsys_resp cresp;
        uint8_t *cdata = NULL;
        uint32_t cdlen = 0;
        (void)rsys_call(sock, RSYS_REQ_CLOSE, creq, sizeof(creq), &cresp, &cdata, &cdlen);
        free(cdata);
        rax = -ENOMEM;
      } else {
        rax = local_fake;
      }
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // socketpair(domain, type, protocol, sv[2])
  if (nr == __NR_socketpair) {
    int domain = (int)regs->rdi;
    int type = (int)regs->rsi;
    int protocol = (int)regs->rdx;
    uintptr_t sv_addr = (uintptr_t)regs->r10;

    vlog("[rsys] socketpair(domain=%d, type=%d, proto=%d) -> remote\n", domain, type, protocol);

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)domain);
    rsys_put_s64(req + 8, (int64_t)type);
    rsys_put_s64(req + 16, (int64_t)protocol);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SOCKETPAIR, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len != 16) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        int64_t rfd0 = rsys_get_s64(data + 0);
        int64_t rfd1 = rsys_get_s64(data + 8);
        free(data);
        int lfd0 = fdmap_add_remote(fm, rrefs, (int)rfd0);
        int lfd1 = fdmap_add_remote(fm, rrefs, (int)rfd1);
        if (lfd0 < 0 || lfd1 < 0) {
          pend->set_rax = -ENOMEM;
        } else {
          uint8_t *sv = (uint8_t *)malloc(8);
          if (!sv) {
            pend->set_rax = -ENOMEM;
          } else {
            int32_t a = lfd0;
            int32_t b = lfd1;
            memcpy(sv + 0, &a, 4);
            memcpy(sv + 4, &b, 4);
            (void)pending_add_out(pend, sv_addr, sv, 8);
          }
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // bind(fd, addr, addrlen)
  if (nr == __NR_bind) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uint32_t addrlen = (uint32_t)regs->rdx;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    if (addrlen > MAX_ADDR) addrlen = MAX_ADDR;
    uint8_t *addr = NULL;
    if (addr_addr && addrlen) {
      addr = (uint8_t *)malloc(addrlen);
      if (!addr) die("malloc");
      if (rsys_read_mem(pid, addr, addr_addr, addrlen) < 0) {
        free(addr);
        return 0;
      }
    }

    uint32_t req_len = 12 + addrlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, addrlen);
    if (addrlen) memcpy(req + 12, addr, addrlen);
    free(addr);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_BIND, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // listen(fd, backlog)
  if (nr == __NR_listen) {
    int fd_local = (int)regs->rdi;
    int backlog = (int)regs->rsi;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)backlog);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_LISTEN, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // connect(fd, addr, addrlen)
  if (nr == __NR_connect) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uint32_t addrlen = (uint32_t)regs->rdx;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    if (addrlen > MAX_ADDR) addrlen = MAX_ADDR;
    uint8_t *addr = NULL;
    if (addr_addr && addrlen) {
      addr = (uint8_t *)malloc(addrlen);
      if (!addr) die("malloc");
      if (rsys_read_mem(pid, addr, addr_addr, addrlen) < 0) {
        free(addr);
        return 0;
      }
    }

    uint32_t req_len = 12 + addrlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, addrlen);
    if (addrlen) memcpy(req + 12, addr, addrlen);
    free(addr);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_CONNECT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // accept(fd, addr, addrlenp)
  if (nr == __NR_accept || nr == __NR_accept4) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uintptr_t addrlenp = (uintptr_t)regs->rdx;
    int flags = (nr == __NR_accept4) ? (int)regs->r10 : 0;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    uint32_t want_addr = (addr_addr && addrlenp) ? 1u : 0u;
    uint32_t addr_max = 0;
    if (want_addr) {
      uint32_t tmp = 0;
      if (rsys_read_mem(pid, &tmp, addrlenp, sizeof(tmp)) < 0) return 0;
      addr_max = tmp;
      if (addr_max > MAX_ADDR) addr_max = MAX_ADDR;
    }

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, want_addr);
    rsys_put_u32(req + 12, addr_max);
    rsys_put_s64(req + 16, (int64_t)flags);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint16_t mtype = (nr == __NR_accept4) ? RSYS_REQ_ACCEPT4 : RSYS_REQ_ACCEPT;
    if (rsys_call(sock, mtype, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);
    if (rr >= 0) {
      int local_fake = fdmap_add_remote(fm, rrefs, (int)rr);
      if (local_fake < 0) {
        rax = -ENOMEM;
      } else {
        rax = local_fake;
      }
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (want_addr && rr >= 0) {
      if (data_len < 4) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_addrlen = rsys_get_u32(data + 0);
        if (out_addrlen > addr_max) out_addrlen = addr_max;
        if (4u + out_addrlen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          uint8_t *ab = NULL;
          if (out_addrlen) {
            ab = (uint8_t *)malloc(out_addrlen);
            if (!ab) die("malloc");
            memcpy(ab, data + 4, out_addrlen);
            (void)pending_add_out(pend, addr_addr, ab, out_addrlen);
          }
          uint8_t *lb = (uint8_t *)malloc(4);
          if (!lb) die("malloc");
          memcpy(lb, &out_addrlen, 4);
          (void)pending_add_out(pend, addrlenp, lb, 4);
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // sendto(fd, buf, len, flags, addr, addrlen)
  if (nr == __NR_sendto) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t len = (size_t)regs->rdx;
    int flags = (int)regs->r10;
    uintptr_t addr_addr = (uintptr_t)regs->r8;
    uint32_t addrlen = (uint32_t)regs->r9;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    uint32_t dlen = (len > MAX_BLOB) ? MAX_BLOB : (uint32_t)len;
    uint8_t *data_in = NULL;
    if (dlen) {
      data_in = (uint8_t *)malloc(dlen);
      if (!data_in) die("malloc");
      if (rsys_read_mem(pid, data_in, buf_addr, dlen) < 0) {
        free(data_in);
        return 0;
      }
    }

    if (addrlen > MAX_ADDR) addrlen = MAX_ADDR;
    uint8_t *addr = NULL;
    if (addr_addr && addrlen) {
      addr = (uint8_t *)malloc(addrlen);
      if (!addr) die("malloc");
      if (rsys_read_mem(pid, addr, addr_addr, addrlen) < 0) {
        free(data_in);
        free(addr);
        return 0;
      }
    } else {
      addrlen = 0;
    }

    uint32_t req_len = 24 + dlen + addrlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, dlen);
    rsys_put_u32(req + 20, addrlen);
    if (dlen) memcpy(req + 24, data_in, dlen);
    if (addrlen) memcpy(req + 24 + dlen, addr, addrlen);
    free(data_in);
    free(addr);

    struct rsys_resp resp;
    uint8_t *odata = NULL;
    uint32_t odata_len = 0;
    if (rsys_call(sock, RSYS_REQ_SENDTO, req, req_len, &resp, &odata, &odata_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(odata);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // recvfrom(fd, buf, len, flags, addr, addrlenp)
  if (nr == __NR_recvfrom) {
    int fd_local = (int)regs->rdi;
    uintptr_t buf_addr = (uintptr_t)regs->rsi;
    size_t len = (size_t)regs->rdx;
    int flags = (int)regs->r10;
    uintptr_t addr_addr = (uintptr_t)regs->r8;
    uintptr_t addrlenp = (uintptr_t)regs->r9;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    uint32_t want_addr = (addr_addr && addrlenp) ? 1u : 0u;
    uint32_t addr_max = 0;
    if (want_addr) {
      uint32_t tmp = 0;
      if (rsys_read_mem(pid, &tmp, addrlenp, sizeof(tmp)) < 0) return 0;
      addr_max = tmp;
      if (addr_max > MAX_ADDR) addr_max = MAX_ADDR;
    }

    uint64_t maxlen = (len > MAX_BLOB) ? (uint64_t)MAX_BLOB : (uint64_t)len;
    uint8_t req[32];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u64(req + 8, (uint64_t)maxlen);
    rsys_put_s64(req + 16, (int64_t)flags);
    rsys_put_u32(req + 24, want_addr);
    rsys_put_u32(req + 28, addr_max);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RECVFROM, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr >= 0) {
      if (data_len < 8) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_dlen = rsys_get_u32(data + 0);
        uint32_t out_alen = rsys_get_u32(data + 4);
        if (8u + out_dlen + out_alen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          if (out_dlen) {
            uint8_t *bb = (uint8_t *)malloc(out_dlen);
            if (!bb) die("malloc");
            memcpy(bb, data + 8, out_dlen);
            (void)pending_add_out(pend, buf_addr, bb, out_dlen);
          }
          if (want_addr) {
            if (out_alen > addr_max) out_alen = addr_max;
            if (out_alen) {
              uint8_t *ab = (uint8_t *)malloc(out_alen);
              if (!ab) die("malloc");
              memcpy(ab, data + 8 + out_dlen, out_alen);
              (void)pending_add_out(pend, addr_addr, ab, out_alen);
            }
            uint8_t *lb = (uint8_t *)malloc(4);
            if (!lb) die("malloc");
            memcpy(lb, &out_alen, 4);
            (void)pending_add_out(pend, addrlenp, lb, 4);
          }
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // shutdown(fd, how)
  if (nr == __NR_shutdown) {
    int fd_local = (int)regs->rdi;
    int how = (int)regs->rsi;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)how);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SHUTDOWN, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // getsockname/getpeername(fd, addr, addrlenp)
  if (nr == __NR_getsockname || nr == __NR_getpeername) {
    int fd_local = (int)regs->rdi;
    uintptr_t addr_addr = (uintptr_t)regs->rsi;
    uintptr_t addrlenp = (uintptr_t)regs->rdx;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    if (!addr_addr || !addrlenp) return 0;
    uint32_t addr_max = 0;
    if (rsys_read_mem(pid, &addr_max, addrlenp, sizeof(addr_max)) < 0) return 0;
    if (addr_max > MAX_ADDR) addr_max = MAX_ADDR;

    uint8_t req[16];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_u32(req + 8, addr_max);
    rsys_put_u32(req + 12, 0);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint16_t mtype = (nr == __NR_getsockname) ? RSYS_REQ_GETSOCKNAME : RSYS_REQ_GETPEERNAME;
    if (rsys_call(sock, mtype, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len < 4) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_alen = rsys_get_u32(data + 0);
        if (out_alen > addr_max) out_alen = addr_max;
        if (4u + out_alen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          if (out_alen) {
            uint8_t *ab = (uint8_t *)malloc(out_alen);
            if (!ab) die("malloc");
            memcpy(ab, data + 4, out_alen);
            (void)pending_add_out(pend, addr_addr, ab, out_alen);
          }
          uint8_t *lb = (uint8_t *)malloc(4);
          if (!lb) die("malloc");
          memcpy(lb, &out_alen, 4);
          (void)pending_add_out(pend, addrlenp, lb, 4);
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // setsockopt(fd, level, optname, optval, optlen)
  if (nr == __NR_setsockopt) {
    int fd_local = (int)regs->rdi;
    int level = (int)regs->rsi;
    int optname = (int)regs->rdx;
    uintptr_t optval_addr = (uintptr_t)regs->r10;
    uint32_t optlen = (uint32_t)regs->r8;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;
    if (optlen > MAX_CTRL) optlen = MAX_CTRL;

    uint8_t *optval = NULL;
    if (optval_addr && optlen) {
      optval = (uint8_t *)malloc(optlen);
      if (!optval) die("malloc");
      if (rsys_read_mem(pid, optval, optval_addr, optlen) < 0) {
        free(optval);
        return 0;
      }
    } else {
      optlen = 0;
    }

    uint32_t req_len = 28 + optlen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)level);
    rsys_put_s64(req + 16, (int64_t)optname);
    rsys_put_u32(req + 24, optlen);
    if (optlen) memcpy(req + 28, optval, optlen);
    free(optval);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_SETSOCKOPT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // getsockopt(fd, level, optname, optval, optlenp)
  if (nr == __NR_getsockopt) {
    int fd_local = (int)regs->rdi;
    int level = (int)regs->rsi;
    int optname = (int)regs->rdx;
    uintptr_t optval_addr = (uintptr_t)regs->r10;
    uintptr_t optlenp = (uintptr_t)regs->r8;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;
    if (!optval_addr || !optlenp) return 0;

    uint32_t optlen_max = 0;
    if (rsys_read_mem(pid, &optlen_max, optlenp, sizeof(optlen_max)) < 0) return 0;
    if (optlen_max > MAX_CTRL) optlen_max = MAX_CTRL;

    uint8_t req[28];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)level);
    rsys_put_s64(req + 16, (int64_t)optname);
    rsys_put_u32(req + 24, optlen_max);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_GETSOCKOPT, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr == 0) {
      if (data_len < 4) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_len = rsys_get_u32(data + 0);
        if (out_len > optlen_max) out_len = optlen_max;
        if (4u + out_len != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          if (out_len) {
            uint8_t *ob = (uint8_t *)malloc(out_len);
            if (!ob) die("malloc");
            memcpy(ob, data + 4, out_len);
            (void)pending_add_out(pend, optval_addr, ob, out_len);
          }
          uint8_t *lb = (uint8_t *)malloc(4);
          if (!lb) die("malloc");
          memcpy(lb, &out_len, 4);
          (void)pending_add_out(pend, optlenp, lb, 4);
          free(data);
        }
      }
    } else {
      free(data);
    }
    return 1;
  }

  // sendmsg(fd, msg, flags)
  if (nr == __NR_sendmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msg_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    struct msghdr mh;
    if (rsys_read_mem(pid, &mh, msg_addr, sizeof(mh)) < 0) return 0;

    uint32_t name_len = (uint32_t)mh.msg_namelen;
    if (name_len > MAX_ADDR) name_len = MAX_ADDR;
    uint32_t ctrl_len = (uint32_t)mh.msg_controllen;
    if (ctrl_len > MAX_CTRL) ctrl_len = MAX_CTRL;
    uint32_t iovcnt = (uint32_t)mh.msg_iovlen;
    if (iovcnt > MAX_IOV) iovcnt = MAX_IOV;

    uint8_t *name = NULL;
    if (mh.msg_name && name_len) {
      name = (uint8_t *)malloc(name_len);
      if (!name) die("malloc");
      if (rsys_read_mem(pid, name, (uintptr_t)mh.msg_name, name_len) < 0) {
        free(name);
        return 0;
      }
    } else {
      name_len = 0;
    }

    uint8_t *ctrl = NULL;
    if (mh.msg_control && ctrl_len) {
      ctrl = (uint8_t *)malloc(ctrl_len);
      if (!ctrl) die("malloc");
      if (rsys_read_mem(pid, ctrl, (uintptr_t)mh.msg_control, ctrl_len) < 0) {
        free(name);
        free(ctrl);
        return 0;
      }
    } else {
      ctrl_len = 0;
    }

    struct iovec *iov = NULL;
    if (mh.msg_iov && iovcnt) {
      iov = (struct iovec *)malloc(iovcnt * sizeof(*iov));
      if (!iov) die("malloc");
      if (rsys_read_mem(pid, iov, (uintptr_t)mh.msg_iov, iovcnt * sizeof(*iov)) < 0) {
        free(name);
        free(ctrl);
        free(iov);
        return 0;
      }
    } else {
      iovcnt = 0;
    }

    uint32_t data_len = 0;
    for (uint32_t i = 0; i < iovcnt; i++) {
      uint64_t add = (uint64_t)iov[i].iov_len;
      if (add > MAX_BLOB) add = MAX_BLOB;
      if (data_len + (uint32_t)add < data_len) break;
      uint64_t newlen = (uint64_t)data_len + add;
      if (newlen > MAX_BLOB) {
        data_len = MAX_BLOB;
        break;
      }
      data_len = (uint32_t)newlen;
    }

    uint8_t *payload_data = NULL;
    if (data_len) {
      payload_data = (uint8_t *)malloc(data_len);
      if (!payload_data) die("malloc");
      uint32_t off = 0;
      for (uint32_t i = 0; i < iovcnt && off < data_len; i++) {
        uint32_t take = (uint32_t)iov[i].iov_len;
        if (take > data_len - off) take = data_len - off;
        if (take && rsys_read_mem(pid, payload_data + off, (uintptr_t)iov[i].iov_base, take) < 0) {
          free(name);
          free(ctrl);
          free(iov);
          free(payload_data);
          return 0;
        }
        off += take;
      }
    }
    free(iov);

    uint32_t req_len = 32 + name_len + ctrl_len + data_len;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, name_len);
    rsys_put_u32(req + 20, ctrl_len);
    rsys_put_u32(req + 24, data_len);
    rsys_put_u32(req + 28, 0);
    uint32_t o = 32;
    if (name_len) memcpy(req + o, name, name_len), o += name_len;
    if (ctrl_len) memcpy(req + o, ctrl, ctrl_len), o += ctrl_len;
    if (data_len) memcpy(req + o, payload_data, data_len), o += data_len;
    free(name);
    free(ctrl);
    free(payload_data);

    struct rsys_resp resp;
    uint8_t *odata = NULL;
    uint32_t odata_len = 0;
    if (rsys_call(sock, RSYS_REQ_SENDMSG, req, req_len, &resp, &odata, &odata_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(odata);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // recvmsg(fd, msg, flags)
  if (nr == __NR_recvmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msg_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    struct msghdr mh;
    if (rsys_read_mem(pid, &mh, msg_addr, sizeof(mh)) < 0) return 0;

    uint32_t name_max = (uint32_t)mh.msg_namelen;
    if (name_max > MAX_ADDR) name_max = MAX_ADDR;
    uint32_t ctrl_max = (uint32_t)mh.msg_controllen;
    if (ctrl_max > MAX_CTRL) ctrl_max = MAX_CTRL;
    uint32_t iovcnt = (uint32_t)mh.msg_iovlen;
    if (iovcnt > MAX_IOV) iovcnt = MAX_IOV;

    struct iovec *iov = NULL;
    if (mh.msg_iov && iovcnt) {
      iov = (struct iovec *)malloc(iovcnt * sizeof(*iov));
      if (!iov) die("malloc");
      if (rsys_read_mem(pid, iov, (uintptr_t)mh.msg_iov, iovcnt * sizeof(*iov)) < 0) {
        free(iov);
        return 0;
      }
    } else {
      iovcnt = 0;
    }

    uint32_t *iov_lens = NULL;
    uint32_t total_max = 0;
    if (iovcnt) {
      iov_lens = (uint32_t *)malloc(iovcnt * sizeof(*iov_lens));
      if (!iov_lens) die("malloc");
      for (uint32_t i = 0; i < iovcnt; i++) {
        uint64_t l = (uint64_t)iov[i].iov_len;
        if (l > (uint64_t)(MAX_BLOB - total_max)) l = (uint64_t)(MAX_BLOB - total_max);
        iov_lens[i] = (uint32_t)l;
        total_max += (uint32_t)l;
      }
    }

    uint32_t req_len = 32 + (iovcnt * 4);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)flags);
    rsys_put_u32(req + 16, name_max);
    rsys_put_u32(req + 20, ctrl_max);
    rsys_put_u32(req + 24, iovcnt);
    rsys_put_u32(req + 28, 0);
    for (uint32_t i = 0; i < iovcnt; i++) rsys_put_u32(req + 32 + (i * 4), iov_lens[i]);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_RECVMSG, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      free(iov_lens);
      free(iov);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr >= 0) {
      if (data_len < 16) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_dlen = rsys_get_u32(data + 0);
        uint32_t out_nlen = rsys_get_u32(data + 4);
        uint32_t out_clen = rsys_get_u32(data + 8);
        uint32_t out_mflags = rsys_get_u32(data + 12);
        if (16u + out_dlen + out_nlen + out_clen != data_len) {
          free(data);
          pend->set_rax = -EPROTO;
        } else {
          const uint8_t *dp = data + 16;
          const uint8_t *np = dp + out_dlen;
          const uint8_t *cp = np + out_nlen;

          // Scatter data into iov buffers
          uint32_t off = 0;
          for (uint32_t i = 0; i < iovcnt && off < out_dlen; i++) {
            uint32_t take = iov_lens ? iov_lens[i] : 0;
            if (take > out_dlen - off) take = out_dlen - off;
            if (take) {
              uint8_t *bb = (uint8_t *)malloc(take);
              if (!bb) die("malloc");
              memcpy(bb, dp + off, take);
              (void)pending_add_out(pend, (uintptr_t)iov[i].iov_base, bb, take);
            }
            off += take;
          }

          if (mh.msg_name && name_max) {
            if (out_nlen > name_max) out_nlen = name_max;
            if (out_nlen) {
              uint8_t *nb = (uint8_t *)malloc(out_nlen);
              if (!nb) die("malloc");
              memcpy(nb, np, out_nlen);
              (void)pending_add_out(pend, (uintptr_t)mh.msg_name, nb, out_nlen);
            }
          }

          if (mh.msg_control && ctrl_max) {
            if (out_clen > ctrl_max) out_clen = ctrl_max;
            if (out_clen) {
              uint8_t *cb = (uint8_t *)malloc(out_clen);
              if (!cb) die("malloc");
              memcpy(cb, cp, out_clen);
              (void)pending_add_out(pend, (uintptr_t)mh.msg_control, cb, out_clen);
            }
          }

          // Update msghdr lengths/flags in tracee
          mh.msg_namelen = (socklen_t)out_nlen;
          mh.msg_controllen = (size_t)out_clen;
          mh.msg_flags = (int)out_mflags;
          uint8_t *mhb = (uint8_t *)malloc(sizeof(mh));
          if (!mhb) die("malloc");
          memcpy(mhb, &mh, sizeof(mh));
          (void)pending_add_out(pend, msg_addr, mhb, (uint32_t)sizeof(mh));

          free(data);
        }
      }
    } else {
      free(data);
    }

    free(iov_lens);
    free(iov);
    return 1;
  }

  // fcntl(fd, cmd, arg)
  if (nr == __NR_fcntl) {
    int fd_local = (int)regs->rdi;
    int cmd = (int)regs->rsi;
    uint64_t arg = (uint64_t)regs->rdx;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    uint32_t has_flock = 0;
    uint32_t flock_len = 0;
    uint8_t *flock_bytes = NULL;
    if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW) {
      has_flock = 1;
      flock_len = (uint32_t)sizeof(struct flock);
      flock_bytes = (uint8_t *)malloc(flock_len);
      if (!flock_bytes) die("malloc");
      if (rsys_read_mem(pid, flock_bytes, (uintptr_t)arg, flock_len) < 0) {
        free(flock_bytes);
        return 0;
      }
    }

    uint32_t req_len = 28 + (has_flock ? flock_len : 0);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    rsys_put_s64(req + 8, (int64_t)cmd);
    rsys_put_u64(req + 16, arg);
    rsys_put_u32(req + 24, has_flock);
    if (has_flock) memcpy(req + 28, flock_bytes, flock_len);
    free(flock_bytes);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_FCNTL, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (has_flock && cmd == F_GETLK && rr == 0) {
      if (data_len != sizeof(struct flock)) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        uint8_t *fb = (uint8_t *)malloc(data_len);
        if (!fb) die("malloc");
        memcpy(fb, data, data_len);
        (void)pending_add_out(pend, (uintptr_t)arg, fb, data_len);
        free(data);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // epoll_create1(flags)
  if (nr == __NR_epoll_create1) {
    int flags = (int)regs->rdi;
    uint8_t req[8];
    rsys_put_s64(req + 0, (int64_t)flags);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_EPOLL_CREATE1, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);
    if (rr >= 0) {
      int local_fake = fdmap_add_remote(fm, rrefs, (int)rr);
      if (local_fake < 0) rax = -ENOMEM;
      else rax = local_fake;
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // epoll_ctl(epfd, op, fd, event)
  if (nr == __NR_epoll_ctl) {
    int epfd_local = (int)regs->rdi;
    int op = (int)regs->rsi;
    int fd_local = (int)regs->rdx;
    uintptr_t ev_addr = (uintptr_t)regs->r10;

    int epfd_remote = map_fd(epfd_local);
    int fd_remote = map_fd(fd_local);
    if (epfd_remote < 0 || fd_remote < 0) return 0;

    uint32_t has_ev = (ev_addr != 0 && op != EPOLL_CTL_DEL) ? 1u : 0u;
    uint32_t ev_len = (uint32_t)sizeof(struct epoll_event);
    uint8_t evbuf[sizeof(struct epoll_event)];
    if (has_ev) {
      if (rsys_read_mem(pid, evbuf, ev_addr, ev_len) < 0) return 0;
    }

    uint32_t req_len = 32 + (has_ev ? ev_len : 0);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)epfd_remote);
    rsys_put_s64(req + 8, (int64_t)op);
    rsys_put_s64(req + 16, (int64_t)fd_remote);
    rsys_put_u32(req + 24, has_ev);
    rsys_put_u32(req + 28, ev_len);
    if (has_ev) memcpy(req + 32, evbuf, ev_len);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_EPOLL_CTL, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // epoll_wait(epfd, events, maxevents, timeout)
  if (nr == __NR_epoll_wait) {
    int epfd_local = (int)regs->rdi;
    uintptr_t evs_addr = (uintptr_t)regs->rsi;
    int maxevents = (int)regs->rdx;
    int timeout = (int)regs->r10;
    int epfd_remote = map_fd(epfd_local);
    if (epfd_remote < 0) return 0;
    if (maxevents < 0) return 0;
    if ((uint32_t)maxevents > 4096u) maxevents = 4096;

    uint8_t req[24];
    rsys_put_s64(req + 0, (int64_t)epfd_remote);
    rsys_put_s64(req + 8, (int64_t)maxevents);
    rsys_put_s64(req + 16, (int64_t)timeout);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_EPOLL_WAIT, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr > 0) {
      uint32_t need = (uint32_t)rr * (uint32_t)sizeof(struct epoll_event);
      if (need != data_len) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        (void)pending_add_out(pend, evs_addr, data, data_len);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)
  if (nr == __NR_epoll_pwait) {
    int epfd_local = (int)regs->rdi;
    uintptr_t evs_addr = (uintptr_t)regs->rsi;
    int maxevents = (int)regs->rdx;
    int timeout = (int)regs->r10;
    uintptr_t sig_addr = (uintptr_t)regs->r8;
    uint64_t sigsz = (uint64_t)regs->r9;

    int epfd_remote = map_fd(epfd_local);
    if (epfd_remote < 0) return 0;
    if (maxevents < 0) return 0;
    if ((uint32_t)maxevents > 4096u) maxevents = 4096;
    if (sigsz > 128) sigsz = 128;

    uint8_t sigmask[128];
    if (sig_addr && sigsz) {
      if (rsys_read_mem(pid, sigmask, sig_addr, (size_t)sigsz) < 0) return 0;
    } else {
      sigsz = 0;
    }

    uint32_t req_len = 28 + (uint32_t)sigsz;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_s64(req + 0, (int64_t)epfd_remote);
    rsys_put_s64(req + 8, (int64_t)maxevents);
    rsys_put_s64(req + 16, (int64_t)timeout);
    rsys_put_u32(req + 24, (uint32_t)sigsz);
    if (sigsz) memcpy(req + 28, sigmask, (size_t)sigsz);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_EPOLL_PWAIT, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr > 0) {
      uint32_t need = (uint32_t)rr * (uint32_t)sizeof(struct epoll_event);
      if (need != data_len) {
        free(data);
        pend->set_rax = -EPROTO;
      } else {
        (void)pending_add_out(pend, evs_addr, data, data_len);
      }
    } else {
      free(data);
    }
    return 1;
  }

  // ppoll(fds, nfds, tmo_p, sigmask, sigsetsize)
  if (nr == __NR_ppoll) {
    uintptr_t fds_addr = (uintptr_t)regs->rdi;
    uint64_t nfds = (uint64_t)regs->rsi;
    uintptr_t tmo_addr = (uintptr_t)regs->rdx;
    uintptr_t sig_addr = (uintptr_t)regs->r10;
    uint64_t sigsz = (uint64_t)regs->r8;

    if (nfds > 4096) nfds = 4096;
    if (nfds == 0) return 0;

    struct pollfd *pfds = (struct pollfd *)malloc((size_t)nfds * sizeof(*pfds));
    if (!pfds) die("malloc");
    if (rsys_read_mem(pid, pfds, fds_addr, (size_t)nfds * sizeof(*pfds)) < 0) {
      free(pfds);
      return 0;
    }

    // If any fd is remote, require all >=0 fds are remote-mapped.
    int any_remote = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
      if (pfds[i].fd < 0) continue;
      if (map_fd(pfds[i].fd) >= 0) any_remote = 1;
    }
    if (any_remote) {
      for (size_t i = 0; i < (size_t)nfds; i++) {
        if (pfds[i].fd < 0) continue;
        if (map_fd(pfds[i].fd) < 0) {
          free(pfds);
          return 0;
        }
      }
    } else {
      free(pfds);
      return 0;
    }

    struct timespec tmo;
    uint32_t has_tmo = (tmo_addr != 0) ? 1u : 0u;
    if (has_tmo) {
      if (rsys_read_mem(pid, &tmo, tmo_addr, sizeof(tmo)) < 0) {
        free(pfds);
        return 0;
      }
    }

    uint32_t has_sig = (sig_addr != 0 && sigsz != 0) ? 1u : 0u;
    if (sigsz > 128) sigsz = 128;
    uint8_t sigmask[128];
    if (has_sig) {
      if (rsys_read_mem(pid, sigmask, sig_addr, (size_t)sigsz) < 0) {
        free(pfds);
        return 0;
      }
    }

    uint32_t req_len = 32 + (uint32_t)nfds * 16 + (has_sig ? (uint32_t)sigsz : 0);
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, (uint32_t)nfds);
    rsys_put_u32(req + 4, has_tmo);
    rsys_put_u32(req + 8, has_sig);
    rsys_put_u32(req + 12, (uint32_t)sigsz);
    if (has_tmo) {
      rsys_put_s64(req + 16, (int64_t)tmo.tv_sec);
      rsys_put_s64(req + 24, (int64_t)tmo.tv_nsec);
    } else {
      rsys_put_s64(req + 16, 0);
      rsys_put_s64(req + 24, 0);
    }
    uint32_t off = 32;
    for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
      int rfd = (pfds[i].fd < 0) ? -1 : map_fd(pfds[i].fd);
      rsys_put_s64(req + off + 0, (int64_t)rfd);
      rsys_put_u32(req + off + 8, (uint32_t)(uint16_t)pfds[i].events);
      rsys_put_u32(req + off + 12, 0);
      off += 16;
    }
    if (has_sig) {
      memcpy(req + off, sigmask, (size_t)sigsz);
      off += (uint32_t)sigsz;
    }
    (void)off;

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      free(pfds);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr >= 0) {
      if (data_len != 4u + (uint32_t)nfds * 4u) {
        free(data);
        free(pfds);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_n = rsys_get_u32(data + 0);
        if (out_n != (uint32_t)nfds) {
          free(data);
          free(pfds);
          pend->set_rax = -EPROTO;
        } else {
          for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
            pfds[i].revents = (short)(uint16_t)rsys_get_u32(data + 4 + i * 4);
          }
          uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
          if (!wb) die("malloc");
          memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
          (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
          free(data);
          free(pfds);
        }
      }
    } else {
      free(data);
      free(pfds);
    }
    return 1;
  }

  // poll(fds, nfds, timeout_ms) -> forwarded via ppoll protocol
  if (nr == __NR_poll) {
    uintptr_t fds_addr = (uintptr_t)regs->rdi;
    uint64_t nfds = (uint64_t)regs->rsi;
    int timeout_ms = (int)regs->rdx;

    if (nfds > 4096) nfds = 4096;
    if (nfds == 0) return 0;

    struct pollfd *pfds = (struct pollfd *)malloc((size_t)nfds * sizeof(*pfds));
    if (!pfds) die("malloc");
    if (rsys_read_mem(pid, pfds, fds_addr, (size_t)nfds * sizeof(*pfds)) < 0) {
      free(pfds);
      return 0;
    }

    int any_remote = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
      if (pfds[i].fd < 0) continue;
      if (map_fd(pfds[i].fd) >= 0) any_remote = 1;
    }
    if (any_remote) {
      for (size_t i = 0; i < (size_t)nfds; i++) {
        if (pfds[i].fd < 0) continue;
        if (map_fd(pfds[i].fd) < 0) {
          free(pfds);
          return 0;
        }
      }
    } else {
      free(pfds);
      return 0;
    }

    uint32_t has_tmo = (timeout_ms >= 0) ? 1u : 0u;
    int64_t tsec = 0;
    int64_t tnsec = 0;
    if (has_tmo) {
      tsec = timeout_ms / 1000;
      tnsec = (int64_t)(timeout_ms % 1000) * 1000000LL;
    }

    uint32_t req_len = 32 + (uint32_t)nfds * 16;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, (uint32_t)nfds);
    rsys_put_u32(req + 4, has_tmo);
    rsys_put_u32(req + 8, 0);  // has_sig
    rsys_put_u32(req + 12, 0); // sigsetsize
    rsys_put_s64(req + 16, tsec);
    rsys_put_s64(req + 24, tnsec);
    uint32_t off = 32;
    for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
      int rfd = (pfds[i].fd < 0) ? -1 : map_fd(pfds[i].fd);
      rsys_put_s64(req + off + 0, (int64_t)rfd);
      rsys_put_u32(req + off + 8, (uint32_t)(uint16_t)pfds[i].events);
      rsys_put_u32(req + off + 12, 0);
      off += 16;
    }

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      free(pfds);
      return 0;
    }
    free(req);

    int64_t rr = rsys_resp_raw_ret(&resp);
    int32_t eno = rsys_resp_err_no(&resp);
    int64_t rax = raw_sys_ret(rr, eno);

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;

    if (rr >= 0) {
      if (data_len != 4u + (uint32_t)nfds * 4u) {
        free(data);
        free(pfds);
        pend->set_rax = -EPROTO;
      } else {
        uint32_t out_n = rsys_get_u32(data + 0);
        if (out_n != (uint32_t)nfds) {
          free(data);
          free(pfds);
          pend->set_rax = -EPROTO;
        } else {
          for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
            pfds[i].revents = (short)(uint16_t)rsys_get_u32(data + 4 + i * 4);
          }
          uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
          if (!wb) die("malloc");
          memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
          (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
          free(data);
          free(pfds);
        }
      }
    } else {
      free(data);
      free(pfds);
    }
    return 1;
  }

  return 0;
}

struct fd_table {
  struct fd_map map;
  uint32_t refs;
};

static void remote_close_best_effort(int sock, int remote_fd) {
  uint8_t req[8];
  rsys_put_s64(req + 0, (int64_t)remote_fd);
  struct rsys_resp resp;
  uint8_t *data = NULL;
  uint32_t data_len = 0;
  if (rsys_call(sock, RSYS_REQ_CLOSE, req, sizeof(req), &resp, &data, &data_len) < 0) return;
  free(data);
}

static struct fd_table *fdtable_new(void) {
  struct fd_table *t = (struct fd_table *)calloc(1, sizeof(*t));
  if (!t) return NULL;
  fdmap_init(&t->map);
  t->refs = 1;
  return t;
}

static struct fd_table *fdtable_fork_clone(const struct fd_table *parent, struct remote_refs *rrefs) {
  struct fd_table *t = (struct fd_table *)calloc(1, sizeof(*t));
  if (!t) return NULL;
  t->refs = 1;
  if (fdmap_clone(&t->map, &parent->map, rrefs) < 0) {
    free(t);
    return NULL;
  }
  return t;
}

static void fdtable_ref(struct fd_table *t) { t->refs++; }

static void fdtable_unref(struct fd_table *t, int sock, struct remote_refs *rrefs) {
  if (!t) return;
  if (--t->refs != 0) return;
  for (size_t i = 0; i < t->map.n; i++) {
    int rfd = t->map.v[i].remote_fd;
    if (rrefs_dec(rrefs, rfd) == 0) remote_close_best_effort(sock, rfd);
  }
  free(t->map.v);
  free(t);
}

struct proc_state {
  pid_t pid;
  int in_syscall;
  int sig_to_deliver;
  struct pending_sys pend;
  struct fd_table *fdt;
};

struct proc_tab {
  struct proc_state *v;
  size_t n;
  size_t cap;
};

static struct proc_state *proctab_find(struct proc_tab *t, pid_t pid) {
  for (size_t i = 0; i < t->n; i++) {
    if (t->v[i].pid == pid) return &t->v[i];
  }
  return NULL;
}

static struct proc_state *proctab_add(struct proc_tab *t, pid_t pid, struct fd_table *fdt) {
  if (t->n == t->cap) {
    size_t ncap = t->cap ? (t->cap * 2) : 8;
    void *nv = realloc(t->v, ncap * sizeof(*t->v));
    if (!nv) return NULL;
    t->v = (struct proc_state *)nv;
    t->cap = ncap;
  }
  struct proc_state *ps = &t->v[t->n++];
  memset(ps, 0, sizeof(*ps));
  ps->pid = pid;
  ps->in_syscall = 0;
  ps->sig_to_deliver = 0;
  ps->pend.outs = NULL;
  pending_clear(&ps->pend);
  ps->fdt = fdt;
  return ps;
}

static void proctab_del(struct proc_tab *t, pid_t pid, int sock, struct remote_refs *rrefs) {
  for (size_t i = 0; i < t->n; i++) {
    if (t->v[i].pid == pid) {
      pending_clear(&t->v[i].pend);
      fdtable_unref(t->v[i].fdt, sock, rrefs);
      t->v[i] = t->v[t->n - 1];
      t->n--;
      return;
    }
  }
}

int main(int argc, char **argv) {
  int argi = 1;
  int use_remote_env = 1; // default
  while (argi < argc) {
    const char *a = argv[argi];
    if (strcmp(a, "-v") == 0) {
      g_verbose = 1;
      argi++;
      continue;
    }
    if (strcmp(a, "-e") == 0) {
      use_remote_env = 0;
      argi++;
      continue;
    }
    if (strcmp(a, "-E") == 0) {
      use_remote_env = 1;
      argi++;
      continue;
    }
    if (strcmp(a, "-h") == 0 || strcmp(a, "-?") == 0 || strcmp(a, "--help") == 0) {
      usage(stdout, argv[0]);
      return 0;
    }
    break;
  }
  if (argc - argi < 3) {
    usage(stderr, argv[0]);
    return 2;
  }

  const char *host = argv[argi + 0];
  const char *port = argv[argi + 1];

  int sock = connect_tcp(host, port);
  if (sock < 0) die("connect");
  vlog("[rsys] connected to %s:%s\n", host, port);

  uint8_t *remote_env_blob = NULL;
  uint32_t remote_env_len = 0;
  char **remote_envp = NULL;
  if (use_remote_env) {
    if (fetch_remote_env(sock, &remote_env_blob, &remote_env_len) < 0) die("fetch_remote_env");
    remote_envp = envp_from_nul_blob(remote_env_blob, remote_env_len);
    if (!remote_envp) die("envp_from_nul_blob");
  }

  // Fork tracee
  pid_t child = fork();
  if (child < 0) die("fork");

  if (child == 0) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) _exit(127);
    raise(SIGSTOP);
    if (use_remote_env) {
      execvpe(argv[argi + 2], &argv[argi + 2], remote_envp);
    } else {
      execvp(argv[argi + 2], &argv[argi + 2]);
    }
    _exit(127);
  }

  int status;
  if (waitpid(child, &status, 0) < 0) die("waitpid");
  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "tracee did not stop\n");
    return 1;
  }

  // Note: We intentionally do NOT enable PTRACE_O_TRACEEXEC here.
  // With PTRACE_SYSCALL, the extra exec event stop can desynchronize a simple
  // entry/exit syscall-stop state machine. Fork/clone/vfork are sufficient to
  // keep tracing descendants spawned by shells.
  long opts =
      PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
  if (ptrace(PTRACE_SETOPTIONS, child, 0, (void *)opts) < 0) die("PTRACE_SETOPTIONS");

  struct remote_refs rr;
  rrefs_init(&rr);

  struct fd_table *root_fdt = fdtable_new();
  if (!root_fdt) die("calloc");

  struct proc_tab procs;
  memset(&procs, 0, sizeof(procs));
  if (!proctab_add(&procs, child, root_fdt)) die("realloc");

  if (ptrace(PTRACE_SYSCALL, child, 0, 0) < 0) die("PTRACE_SYSCALL");

  while (procs.n) {
    pid_t pid = waitpid(-1, &status, __WALL);
    if (pid < 0) {
      if (errno == EINTR) continue;
      die("waitpid");
    }

    struct proc_state *ps = proctab_find(&procs, pid);
    if (!ps) {
      // Unknown pid; best effort: keep it running without signal.
      (void)ptrace(PTRACE_SYSCALL, pid, 0, 0);
      continue;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      proctab_del(&procs, pid, sock, &rr);
      continue;
    }
    if (!WIFSTOPPED(status)) continue;

    int sig = WSTOPSIG(status);
    int deliver = 0;

    if (sig == (SIGTRAP | 0x80)) {
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) die("PTRACE_GETREGS");

      if (!ps->in_syscall) {
        (void)intercept_syscall(pid, &regs, sock, &ps->fdt->map, &rr, &ps->pend);
        ps->in_syscall = 1;
      } else {
        if (ps->pend.active) {
          for (size_t i = 0; i < ps->pend.outs_n; i++) {
            if (ps->pend.outs[i].bytes && ps->pend.outs[i].len) {
              (void)rsys_write_mem(pid, ps->pend.outs[i].addr, ps->pend.outs[i].bytes, ps->pend.outs[i].len);
            }
          }

          regs.rax = (uint64_t)ps->pend.set_rax;
          if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) die("PTRACE_SETREGS");
          pending_clear(&ps->pend);
        }
        ps->in_syscall = 0;
      }
    } else if (sig == SIGTRAP) {
      unsigned event = (unsigned)status >> 16;
      if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
        unsigned long msg = 0;
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) < 0) die("PTRACE_GETEVENTMSG");
        pid_t newpid = (pid_t)msg;

        struct fd_table *child_fdt = NULL;
        if (event == PTRACE_EVENT_CLONE) {
          // Likely a thread: share the same fd table mapping.
          fdtable_ref(ps->fdt);
          child_fdt = ps->fdt;
        } else {
          child_fdt = fdtable_fork_clone(ps->fdt, &rr);
          if (!child_fdt) die("calloc");
        }

        if (!proctab_add(&procs, newpid, child_fdt)) die("realloc");
        // The new tracee will report an initial SIGSTOP to the tracer; we will
        // resume it from the main wait loop. Avoid racing with short-lived
        // children by not issuing ptrace commands here.
      }
      // Do not forward SIGTRAP into the tracee.
      deliver = 0;
    } else if (sig == SIGSTOP) {
      // Don't forward initial/ptrace SIGSTOP into the tracee.
      deliver = 0;
    } else {
      deliver = sig;
    }

    if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)(uintptr_t)deliver) < 0) die("PTRACE_SYSCALL");
  }

  close(sock);
  free(rr.v);
  free(procs.v);
  free(remote_envp);
  free(remote_env_blob);
  return 0;
}
