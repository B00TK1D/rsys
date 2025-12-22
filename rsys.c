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
#include <sys/eventfd.h>
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
static int g_read_only = 0;

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
          "  -v, --verbose          verbose logging\n"
          "  -m, --mount SRC:DST     expose local SRC at path DST (may be repeated)\n"
          "  -R, --read-only         block remote filesystem mutations\n"
          "  -e                     use local environment for the traced program\n"
          "  -E                     use remote environment for the traced program (default)\n"
          "  -h, -?, --help         show this help\n",
          argv0);
}

struct mount_map {
  char *local;         // local source prefix
  char *exposed;       // path seen by tracee
  size_t local_len;
  size_t exposed_len;
};

struct mounts {
  struct mount_map *v;
  size_t n;
  size_t cap;
};

static void mounts_init(struct mounts *m) {
  m->v = NULL;
  m->n = 0;
  m->cap = 0;
}

static void mounts_free(struct mounts *m) {
  if (!m) return;
  for (size_t i = 0; i < m->n; i++) {
    free(m->v[i].local);
    free(m->v[i].exposed);
  }
  free(m->v);
  m->v = NULL;
  m->n = 0;
  m->cap = 0;
}

static void trim_trailing_slashes(char *s) {
  size_t n = strlen(s);
  while (n > 1 && s[n - 1] == '/') {
    s[n - 1] = '\0';
    n--;
  }
}

static int mounts_add(struct mounts *m, const char *spec) {
  // spec: /local/path:/exposed/path
  const char *colon = strchr(spec, ':');
  if (!colon) return -1;
  size_t llen = (size_t)(colon - spec);
  size_t elen = strlen(colon + 1);
  if (llen == 0 || elen == 0) return -1;
  if (spec[0] != '/' || colon[1] != '/') return -1;

  char *l = (char *)malloc(llen + 1);
  char *e = (char *)malloc(elen + 1);
  if (!l || !e) {
    free(l);
    free(e);
    return -1;
  }
  memcpy(l, spec, llen);
  l[llen] = '\0';
  memcpy(e, colon + 1, elen + 1);
  trim_trailing_slashes(l);
  trim_trailing_slashes(e);

  if (m->n == m->cap) {
    size_t ncap = m->cap ? (m->cap * 2) : 4;
    void *nv = realloc(m->v, ncap * sizeof(*m->v));
    if (!nv) {
      free(l);
      free(e);
      return -1;
    }
    m->v = (struct mount_map *)nv;
    m->cap = ncap;
  }
  m->v[m->n++] = (struct mount_map){.local = l, .exposed = e, .local_len = strlen(l), .exposed_len = strlen(e)};
  return 0;
}

static int mount_translate_alloc(const struct mounts *m, const char *path, char **out_local) {
  *out_local = NULL;
  if (!m || m->n == 0 || !path) return 0;
  if (path[0] != '/') return 0;

  // Longest-prefix match on exposed path.
  const struct mount_map *best = NULL;
  for (size_t i = 0; i < m->n; i++) {
    const struct mount_map *mm = &m->v[i];
    size_t n = mm->exposed_len;
    if (strncmp(path, mm->exposed, n) != 0) continue;
    if (path[n] != '\0' && path[n] != '/') continue;
    if (!best || n > best->exposed_len) best = mm;
  }
  if (!best) return 0;

  const char *suffix = path + best->exposed_len;
  size_t slen = strlen(suffix);
  size_t outlen = best->local_len + slen;
  char *lp = (char *)malloc(outlen + 1);
  if (!lp) return -1;
  memcpy(lp, best->local, best->local_len);
  memcpy(lp + best->local_len, suffix, slen + 1);
  *out_local = lp;
  return 1;
}

static int rewrite_path_arg(pid_t pid, const struct user_regs_struct *regs, uintptr_t *reg_ptr, const char *new_path) {
  // IMPORTANT: don't overwrite the tracee's original string in-place.
  // Programs (like bash) may reuse that buffer for later operations; if we mutate it,
  // we can change user-visible behavior (e.g. cd target path).
  size_t new_len = strlen(new_path) + 1;

  // Scratch below current stack pointer.
  uintptr_t scratch = (uintptr_t)((regs->rsp - 0x4000) & ~(uintptr_t)0xFul);
  if (rsys_write_mem(pid, scratch, new_path, new_len) < 0) return -1;
  *reg_ptr = scratch;
  return 0;
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

static const char *envp_get_value(char **envp, const char *key) {
  if (!envp || !key) return NULL;
  size_t klen = strlen(key);
  for (size_t i = 0; envp[i]; i++) {
    const char *s = envp[i];
    if (strncmp(s, key, klen) == 0 && s[klen] == '=') return s + klen + 1;
  }
  return NULL;
}

static int normalize_abs_path(char *out, size_t out_sz, const char *abs_path) {
  if (!out || out_sz == 0 || !abs_path || abs_path[0] != '/') return -1;

  const char *segs[512];
  size_t seg_lens[512];
  size_t nsegs = 0;

  const char *p = abs_path;
  while (*p) {
    while (*p == '/') p++;
    if (!*p) break;
    const char *start = p;
    while (*p && *p != '/') p++;
    size_t len = (size_t)(p - start);
    if (len == 1 && start[0] == '.') continue;
    if (len == 2 && start[0] == '.' && start[1] == '.') {
      if (nsegs) nsegs--;
      continue;
    }
    if (nsegs >= (sizeof(segs) / sizeof(segs[0]))) return -1;
    segs[nsegs] = start;
    seg_lens[nsegs] = len;
    nsegs++;
  }

  size_t w = 0;
  out[w++] = '/';
  if (nsegs == 0) {
    out[w] = '\0';
    return 0;
  }
  for (size_t i = 0; i < nsegs; i++) {
    if (i != 0) {
      if (w + 1 >= out_sz) return -1;
      out[w++] = '/';
    }
    if (w + seg_lens[i] + 1 > out_sz) return -1;
    memcpy(out + w, segs[i], seg_lens[i]);
    w += seg_lens[i];
  }
  out[w] = '\0';
  return 0;
}

static int join_cwd_and_path(char *out, size_t out_sz, const char *cwd_abs, const char *path) {
  if (!out || out_sz == 0 || !cwd_abs || cwd_abs[0] != '/' || !path) return -1;
  if (path[0] == '/') return normalize_abs_path(out, out_sz, path);

  char tmp[8192];
  size_t cwd_len = strlen(cwd_abs);
  size_t path_len = strlen(path);
  if (cwd_len == 0) cwd_abs = "/", cwd_len = 1;

  size_t need = cwd_len + 1 + path_len + 1;
  if (need > sizeof(tmp)) return -1;
  memcpy(tmp, cwd_abs, cwd_len);
  tmp[cwd_len] = '/';
  memcpy(tmp + cwd_len + 1, path, path_len);
  tmp[cwd_len + 1 + path_len] = '\0';

  return normalize_abs_path(out, out_sz, tmp);
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

static int fdmap_add_existing(struct fd_map *m, struct remote_refs *rrefs, int local_fd, int remote_fd) {
  if (local_fd < 0) return -1;
  if (m->n == m->cap) {
    size_t ncap = m->cap ? (m->cap * 2) : 16;
    struct fd_map_ent *nv = (struct fd_map_ent *)realloc(m->v, ncap * sizeof(*nv));
    if (!nv) return -1;
    m->v = nv;
    m->cap = ncap;
  }
  m->v[m->n++] = (struct fd_map_ent){.local_fd = local_fd, .remote_fd = remote_fd};
  if (rrefs_inc(rrefs, remote_fd) < 0) {
    m->n--;
    return -1;
  }
  return 0;
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

static void remote_chdir_best_effort(int sock, const char *path) {
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

static void maybe_make_remote_abs_path(char *path, size_t path_sz, const int *cwd_is_local, const int *cwd_remote_known,
                                       const char *cwd_remote) {
  if (!path || path_sz == 0) return;
  if (path[0] == '/') return;
  if (cwd_is_local && *cwd_is_local) return;
  if (!cwd_remote_known || !*cwd_remote_known) return;
  if (!cwd_remote || cwd_remote[0] != '/') return;
  char ap[4096];
  if (join_cwd_and_path(ap, sizeof(ap), cwd_remote, path) == 0) {
    strncpy(path, ap, path_sz);
    path[path_sz - 1] = '\0';
  }
}

struct pending_sys {
  int active;
  long nr;

  // For emulation on syscall-exit
  int has_set_rax;
  int64_t set_rax;

  // For syscalls we rewrite to create a local placeholder FD:
  // - map_fd_on_exit: map regs->rax (local fd) to map_remote_fd after syscall exits
  int map_fd_on_exit;
  int map_remote_fd;

  // For syscalls we rewrite to create a local placeholder FD pair via pipe2():
  // - map_fd_pair_on_exit: map two local fds from map_pair_addr to remote fds.
  int map_fd_pair_on_exit;
  int map_remote_fd0;
  int map_remote_fd1;
  uintptr_t map_pair_addr;

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
  p->has_set_rax = 1;
  p->set_rax = 0;
  p->map_fd_on_exit = 0;
  p->map_remote_fd = -1;
  p->map_fd_pair_on_exit = 0;
  p->map_remote_fd0 = -1;
  p->map_remote_fd1 = -1;
  p->map_pair_addr = 0;
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
                             const struct mounts *mnts, int *cwd_is_local, int *cwd_remote_known, char *cwd_remote,
                             size_t cwd_remote_sz, int *virt_ids_known, pid_t *virt_pid, pid_t *virt_tid, pid_t *virt_ppid,
                             pid_t *virt_pgid, pid_t *virt_sid, struct pending_sys *pend) {
  long nr = (long)regs->orig_rax;

  auto int deny_syscall_ep(pid_t tpid, struct user_regs_struct *tregs, struct pending_sys *tpend, long orig_nr, int err) {
    tregs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, tpid, 0, tregs) < 0) die("PTRACE_SETREGS");
    pending_clear(tpend);
    tpend->active = 1;
    tpend->nr = orig_nr;
    tpend->set_rax = -(int64_t)err;
    return 1;
  }

  // Helpers to map local fd to remote fd
  auto int map_fd(int local) {
    return fdmap_find_remote(fm, local);
  }

  // Virtualized identity syscalls (pid/tid/ppid/etc) so /proc/self coheres with remote /proc.
  // WARNING: this changes what programs observe, and must be kept consistent with /proc rewriting.
  if (virt_ids_known && *virt_ids_known) {
    if (nr == __NR_getpid) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->set_rax = (int64_t)(virt_pid ? *virt_pid : 0);
      return 1;
    }
    if (nr == __NR_gettid) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->set_rax = (int64_t)(virt_tid ? *virt_tid : 0);
      return 1;
    }
    if (nr == __NR_getppid) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->set_rax = (int64_t)(virt_ppid ? *virt_ppid : 0);
      return 1;
    }
#ifdef __NR_getpgrp
    if (nr == __NR_getpgrp) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pending_clear(pend);
      pend->active = 1;
      pend->nr = nr;
      pend->set_rax = (int64_t)(virt_pgid ? *virt_pgid : 0);
      return 1;
    }
#endif
#ifdef __NR_getpgid
    if (nr == __NR_getpgid) {
      pid_t q = (pid_t)regs->rdi;
      if (q == 0 || (virt_pid && q == *virt_pid)) {
        regs->orig_rax = __NR_getpid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        pending_clear(pend);
        pend->active = 1;
        pend->nr = nr;
        pend->set_rax = (int64_t)(virt_pgid ? *virt_pgid : 0);
        return 1;
      }
      // Not self: let it run locally (may not match remote).
    }
#endif
#ifdef __NR_getsid
    if (nr == __NR_getsid) {
      pid_t q = (pid_t)regs->rdi;
      if (q == 0 || (virt_pid && q == *virt_pid)) {
        regs->orig_rax = __NR_getpid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        pending_clear(pend);
        pend->active = 1;
        pend->nr = nr;
        pend->set_rax = (int64_t)(virt_sid ? *virt_sid : 0);
        return 1;
      }
      // Not self: let it run locally.
    }
#endif
  }

  // Mitigation: if a program calls kill(getpid(), sig) under pid virtualization,
  // translate the virtual "self" pid/tid back to the real local ones so behavior
  // remains sane (e.g. kill(SIGTERM) terminates the process).
  if (virt_ids_known && *virt_ids_known) {
    if (nr == __NR_kill) {
      pid_t target = (pid_t)regs->rdi;
      if (virt_pid && target == *virt_pid) {
        regs->rdi = (uint64_t)pid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      }
    }
#ifdef __NR_tgkill
    if (nr == __NR_tgkill) {
      pid_t tgid = (pid_t)regs->rdi;
      pid_t tid = (pid_t)regs->rsi;
      if (virt_pid && tgid == *virt_pid) regs->rdi = (uint64_t)pid;
      if (virt_tid && tid == *virt_tid) regs->rsi = (uint64_t)pid; // best-effort: treat as self
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    }
#endif
#ifdef __NR_tkill
    if (nr == __NR_tkill) {
      pid_t tid = (pid_t)regs->rdi;
      if (virt_tid && tid == *virt_tid) {
        regs->rdi = (uint64_t)pid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      }
    }
#endif
  }

  // Helper: rewrite /proc self-references to match remote pid.
  auto void rewrite_proc_self_path(char *path, size_t path_sz) {
    if (!path || path_sz == 0) return;
    if (!virt_ids_known || !*virt_ids_known) return;
    if (!virt_pid || *virt_pid <= 0) return;
    if (path[0] != '/') return;
    if (strncmp(path, "/proc/", 6) != 0) return;

    // /proc/self[/...]
    if (strncmp(path, "/proc/self", 10) == 0 && (path[10] == '\0' || path[10] == '/')) {
      char out[4096];
      snprintf(out, sizeof(out), "/proc/%d%s", (int)*virt_pid, path + 10);
      strncpy(path, out, path_sz);
      path[path_sz - 1] = '\0';
      return;
    }
    // /proc/thread-self[/...]
    if (strncmp(path, "/proc/thread-self", 16) == 0 && (path[16] == '\0' || path[16] == '/')) {
      char out[4096];
      snprintf(out, sizeof(out), "/proc/%d%s", (int)*virt_pid, path + 16);
      strncpy(path, out, path_sz);
      path[path_sz - 1] = '\0';
      return;
    }
    // /proc/<localpid>[/...] -> /proc/<virt_pid>[/...]
    const char *p = path + 6;
    char *end = NULL;
    long lp = strtol(p, &end, 10);
    if (end && end > p && (end[0] == '\0' || end[0] == '/')) {
      if ((pid_t)lp == pid) {
        char out[4096];
        snprintf(out, sizeof(out), "/proc/%d%s", (int)*virt_pid, end);
        strncpy(path, out, path_sz);
        path[path_sz - 1] = '\0';
      }
    }
  }

  const uint32_t MAX_BLOB = (1u << 20);   // 1MB per call
  const uint32_t MAX_ADDR = 512;          // sockaddr cap
  const uint32_t MAX_CTRL = 64u * 1024u;  // cmsg cap
  const uint32_t MAX_IOV = 128;           // iov count cap

  // Local mount remapping for absolute path arguments.
  auto int maybe_remap_path(uintptr_t addr, uintptr_t *reg_ptr) {
    if (!addr) return 0;
    char path[4096];
    if (rsys_read_cstring(pid, addr, path, sizeof(path)) < 0) return 0;
    char *lp = NULL;
    int tr = mount_translate_alloc(mnts, path, &lp);
    if (tr <= 0) {
      free(lp);
      return 0;
    }
    int rc = rewrite_path_arg(pid, regs, reg_ptr, lp);
    if (rc == 0) {
      vlog("[rsys] mount map: %s -> %s\n", path, lp);
    }
    free(lp);
    return (rc == 0) ? 1 : 0;
  }

  // chdir(path)
  if (nr == __NR_chdir) {
    uintptr_t path_addr = (uintptr_t)regs->rdi;
    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;

    // If it targets a local mount, rewrite and run locally.
    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rdi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      if (cwd_is_local) *cwd_is_local = 1;
      return 0;
    }

    // Otherwise, change cwd on the remote side. We send an absolute, normalized
    // path so correctness does not depend on rsysd's own cwd.
    char abs_cwd[4096];
    if (path[0] == '/') {
      if (normalize_abs_path(abs_cwd, sizeof(abs_cwd), path) < 0) {
        strncpy(abs_cwd, path, sizeof(abs_cwd));
        abs_cwd[sizeof(abs_cwd) - 1] = '\0';
      }
    } else if (cwd_remote_known && *cwd_remote_known && cwd_remote && cwd_remote[0] == '/') {
      if (join_cwd_and_path(abs_cwd, sizeof(abs_cwd), cwd_remote, path) < 0) {
        strncpy(abs_cwd, path, sizeof(abs_cwd));
        abs_cwd[sizeof(abs_cwd) - 1] = '\0';
      }
    } else {
      // Unknown base: best-effort send as-is.
      strncpy(abs_cwd, path, sizeof(abs_cwd));
      abs_cwd[sizeof(abs_cwd) - 1] = '\0';
    }

    uint32_t plen = (uint32_t)strlen(abs_cwd) + 1;
    uint32_t req_len = 4 + plen;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) die("malloc");
    rsys_put_u32(req + 0, plen);
    memcpy(req + 4, abs_cwd, plen);

    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_CHDIR, req, req_len, &resp, &data, &data_len) < 0) {
      free(req);
      return 0;
    }
    free(req);
    free(data);

    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    if (cwd_is_local && rax == 0) *cwd_is_local = 0;
    if (rax == 0 && cwd_remote && cwd_remote_sz) {
      // Update tracked remote cwd only on success.
      if (abs_cwd[0] == '/' && normalize_abs_path(abs_cwd, sizeof(abs_cwd), abs_cwd) == 0) {
        strncpy(cwd_remote, abs_cwd, cwd_remote_sz);
        cwd_remote[cwd_remote_sz - 1] = '\0';
        if (cwd_remote_known) *cwd_remote_known = 1;
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

  // fchdir(fd)
  if (nr == __NR_fchdir) {
    int fd_local = (int)regs->rdi;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) {
      // local fchdir; assume local mode afterwards
      if (cwd_is_local) *cwd_is_local = 1;
      return 0;
    }

    uint8_t req[8];
    rsys_put_s64(req + 0, (int64_t)fd_remote);
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_FCHDIR, req, sizeof(req), &resp, &data, &data_len) < 0) return 0;
    free(data);
    int64_t rax = raw_sys_ret(rsys_resp_raw_ret(&resp), rsys_resp_err_no(&resp));
    if (cwd_is_local && rax == 0) *cwd_is_local = 0;
    if (cwd_remote_known && rax == 0) *cwd_remote_known = 0;

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->set_rax = rax;
    return 1;
  }

  // openat(dirfd, pathname, flags, mode)
  if (nr == __NR_openat) {
    int dirfd_local = (int)regs->rdi;
    uintptr_t path_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int mode = (int)regs->r10;

    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0; // let it run locally with rewritten pathname
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0; // let it run locally on failure
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0; // local relative
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rewrite_proc_self_path(path, sizeof(path));
    if (!should_remote_path(path)) return 0;                       // local absolute by policy

    vlog("[rsys] openat(dirfd=%d, path=%s, flags=0x%x, mode=0%o) -> remote\n", dirfd_local, path, flags, mode);

    if (g_read_only) {
      int accmode = flags & O_ACCMODE;
      int wants_write = (accmode == O_WRONLY) || (accmode == O_RDWR);
      int wants_create = (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
#ifdef O_TMPFILE
      // NOTE: O_TMPFILE includes O_DIRECTORY, so (flags & O_TMPFILE) != 0 would
      // incorrectly match normal directory opens. Only block if the full
      // O_TMPFILE bit pattern is present.
      wants_create = wants_create || ((flags & O_TMPFILE) == O_TMPFILE);
#endif
      if (wants_write || wants_create) {
        return deny_syscall_ep(pid, regs, pend, nr, EPERM);
      }
    }

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
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->close_local_fd = -1;

    if (rr >= 0) {
      // Create a real local placeholder FD (small, non-colliding) so userland
      // can safely use poll/select/FD_SET, etc. We'll map it to the remote FD on exit.
      pend->has_set_rax = 0; // keep eventfd2 return value
      pend->map_fd_on_exit = 1;
      pend->map_remote_fd = (int)rr;

      regs->orig_rax = __NR_eventfd2;
      regs->rdi = 0; // initval
      regs->rsi = (uint64_t)EFD_CLOEXEC;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] openat -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=<eventfd2>\n", rr, eno);
    } else {
      // Failure: replace syscall with harmless getpid and set error on exit.
      pend->has_set_rax = 1;
      pend->set_rax = rax;
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] openat -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=%" PRId64 "\n", rr, eno, rax);
    }
    return 1;
  }

  // close(fd)
  if (nr == __NR_close) {
    int fd_local = (int)regs->rdi;
    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0; // local close

    uint32_t refs = rrefs_get(rrefs, fd_remote);
    if (refs == 0) return 0; // inconsistent; fall back to local

    // Always remove the mapping for this local fd, so fd reuse won't confuse us.
    int removed_remote = -1;
    if (fdmap_remove_local(fm, fd_local, &removed_remote) < 0) return 0;
    uint32_t new_refs = rrefs_dec(rrefs, removed_remote);

    // Last reference: close on remote (best-effort).
    if (new_refs == 0) {
      vlog("[rsys] close(fd=%d -> remote_fd=%d) -> remote\n", fd_local, fd_remote);
      uint8_t req[8];
      rsys_put_s64(req + 0, (int64_t)fd_remote);
      struct rsys_resp resp;
      uint8_t *data = NULL;
      uint32_t data_len = 0;
      (void)rsys_call(sock, RSYS_REQ_CLOSE, req, sizeof(req), &resp, &data, &data_len);
      free(data);
    }

    // Let the real close(2) run so placeholder FDs are actually closed.
    return 0;
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

    if (g_read_only) {
      return deny_syscall_ep(pid, regs, pend, nr, EPERM);
    }

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

    if (g_read_only) {
      return deny_syscall_ep(pid, regs, pend, nr, EPERM);
    }

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

    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rewrite_proc_self_path(path, sizeof(path));
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

    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rewrite_proc_self_path(path, sizeof(path));
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

    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rdi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rewrite_proc_self_path(path, sizeof(path));
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

    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    rewrite_proc_self_path(path, sizeof(path));
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

    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] unlinkat(dirfd=%d, path=%s, flags=0x%x) -> remote\n", dirfd_local, path, flags);

    if (g_read_only) {
      return deny_syscall_ep(pid, regs, pend, nr, EPERM);
    }

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

    if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rsi)) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char path[4096];
    if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
    if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
    if (!should_remote_path(path)) return 0;

    vlog("[rsys] mkdirat(dirfd=%d, path=%s, mode=0%o) -> remote\n", dirfd_local, path, mode);

    if (g_read_only) {
      return deny_syscall_ep(pid, regs, pend, nr, EPERM);
    }

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

    int remapped = 0;
    if (oldp_addr) remapped |= maybe_remap_path(oldp_addr, (uintptr_t *)&regs->rsi);
    if (newp_addr) remapped |= maybe_remap_path(newp_addr, (uintptr_t *)&regs->r10);
    if (remapped) {
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      return 0;
    }

    char oldp[4096];
    char newp[4096];
    if (rsys_read_cstring(pid, oldp_addr, oldp, sizeof(oldp)) < 0) return 0;
    if (rsys_read_cstring(pid, newp_addr, newp, sizeof(newp)) < 0) return 0;

    if ((oldp[0] != '/' || newp[0] != '/') && cwd_is_local && *cwd_is_local) return 0;
    maybe_make_remote_abs_path(oldp, sizeof(oldp), cwd_is_local, cwd_remote_known, cwd_remote);
    maybe_make_remote_abs_path(newp, sizeof(newp), cwd_is_local, cwd_remote_known, cwd_remote);
    if (!should_remote_path(oldp) && !should_remote_path(newp)) return 0;

    vlog("[rsys] renameat2(old=%s, new=%s, flags=0x%x) -> remote\n", oldp, newp, flags);

    if (g_read_only) {
      return deny_syscall_ep(pid, regs, pend, nr, EPERM);
    }

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

    if (path_addr != 0) {
      if (maybe_remap_path(path_addr, (uintptr_t *)&regs->rsi)) {
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        return 0;
      }
    }

    // Special case: pathname == NULL => operate on dirfd (futimens semantics).
    uint32_t path_len = 0;
    char path[4096];

    int dirfd_remote;
    if (path_addr == 0) {
      dirfd_remote = map_fd(dirfd_local);
      if (dirfd_remote < 0) return 0;
    } else {
      if (rsys_read_cstring(pid, path_addr, path, sizeof(path)) < 0) return 0;
      if (path[0] != '/' && cwd_is_local && *cwd_is_local) return 0;
      maybe_make_remote_abs_path(path, sizeof(path), cwd_is_local, cwd_remote_known, cwd_remote);
      if (!should_remote_path(path)) return 0;
      dirfd_remote = (dirfd_local == AT_FDCWD) ? AT_FDCWD : map_fd(dirfd_local);
      if (dirfd_local != AT_FDCWD && dirfd_remote < 0) return 0;
      path_len = (uint32_t)strlen(path) + 1;
    }

    if (g_read_only) {
      return deny_syscall_ep(pid, regs, pend, nr, EPERM);
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

    if (g_read_only) {
      return deny_syscall_ep(pid, regs, pend, nr, EPERM);
    }

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
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->close_local_fd = -1;

    if (rr >= 0) {
      pend->has_set_rax = 0;
      pend->map_fd_on_exit = 1;
      pend->map_remote_fd = (int)rr;

      regs->orig_rax = __NR_eventfd2;
      regs->rdi = 0;
      regs->rsi = (uint64_t)EFD_CLOEXEC;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] socket -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=<eventfd2>\n", rr, eno);
    } else {
      pend->has_set_rax = 1;
      pend->set_rax = rax;
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      vlog("[rsys] socket -> raw_ret=%" PRId64 " errno=%d mapped_local_fd=%" PRId64 "\n", rr, eno, rax);
    }
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
        // Allocate two local placeholder FDs via pipe2(), then map them to the remote FDs on exit.
        // We use pipe2 because it returns two real FDs to the tracee.
        pend->has_set_rax = 0; // keep pipe2 return value (0)
        pend->map_fd_pair_on_exit = 1;
        pend->map_remote_fd0 = (int)rfd0;
        pend->map_remote_fd1 = (int)rfd1;
        pend->map_pair_addr = sv_addr;

        int pflags = 0;
#ifdef SOCK_CLOEXEC
        if (type & SOCK_CLOEXEC) pflags |= O_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
        if (type & SOCK_NONBLOCK) pflags |= O_NONBLOCK;
#endif
        regs->orig_rax = __NR_pipe2;
        regs->rdi = (uint64_t)sv_addr;
        regs->rsi = (uint64_t)pflags;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        return 1;
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
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->close_local_fd = -1;

    if (rr >= 0) {
      pend->has_set_rax = 0;
      pend->map_fd_on_exit = 1;
      pend->map_remote_fd = (int)rr;
      regs->orig_rax = __NR_eventfd2;
      regs->rdi = 0;
      regs->rsi = (uint64_t)EFD_CLOEXEC;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    } else {
      pend->has_set_rax = 1;
      pend->set_rax = rax;
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    }

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

  // sendmmsg(fd, msgvec, vlen, flags)
  if (nr == __NR_sendmmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msgvec_addr = (uintptr_t)regs->rsi;
    uint32_t vlen = (uint32_t)regs->rdx;
    int flags = (int)regs->r10;

    int fd_remote = map_fd(fd_local);
    if (fd_remote < 0) return 0;

    // Prepare pending state; we'll queue msg_len writes into it.
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;

    if (vlen > 128) vlen = 128;
    if (vlen == 0) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pend->set_rax = 0;
      return 1;
    }

    uint32_t sent = 0;
    for (uint32_t mi = 0; mi < vlen; mi++) {
      struct mmsghdr mm;
      if (rsys_read_mem(pid, &mm, msgvec_addr + (uintptr_t)mi * sizeof(mm), sizeof(mm)) < 0) {
        // If we can't read, fall back to local.
        if (sent == 0) return 0;
        break;
      }

      struct msghdr mh = mm.msg_hdr;

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
          if (sent == 0) return 0;
          break;
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
          if (sent == 0) return 0;
          break;
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
          if (sent == 0) return 0;
          break;
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
            if (sent == 0) return 0;
            goto sendmmsg_done;
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
        free(odata);
        if (sent == 0) return 0;
        break;
      }
      free(req);
      free(odata);

      int64_t rr = rsys_resp_raw_ret(&resp);
      int32_t eno = rsys_resp_err_no(&resp);
      int64_t rax_one = raw_sys_ret(rr, eno);

      if (rr < 0) {
        if (sent == 0) {
          // First one failed: return the error.
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = rax_one;
          return 1;
        }
        break;
      }

      // Update msg_len for this entry.
      uint32_t msg_len = (uint32_t)rr;
      uint8_t *lb = (uint8_t *)malloc(4);
      if (!lb) die("malloc");
      memcpy(lb, &msg_len, 4);
      uintptr_t len_addr = msgvec_addr + (uintptr_t)mi * sizeof(struct mmsghdr) + offsetof(struct mmsghdr, msg_len);
      (void)pending_add_out(pend, len_addr, lb, 4);
      sent++;
    }

  sendmmsg_done:
    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pend->set_rax = (int64_t)sent;
    return 1;
  }

  // recvmmsg(fd, msgvec, vlen, flags, timeout)
  if (nr == __NR_recvmmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msgvec_addr = (uintptr_t)regs->rsi;
    uint32_t vlen = (uint32_t)regs->rdx;
    int flags = (int)regs->r10;
    // NOTE: timeout (regs->r8) is currently ignored (treated as NULL). This is
    // sufficient for netlink dump usage in iproute2, which typically passes NULL.

    int fd_remote = map_fd(fd_local);
    vlog("[rsys] recvmmsg(fd=%d -> remote_fd=%d, vlen=%u, flags=0x%x)\n", fd_local, fd_remote, vlen, flags);
    if (fd_remote < 0) return 0;

    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;

    if (vlen > 128) vlen = 128;
    if (vlen == 0) {
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
      pend->set_rax = 0;
      return 1;
    }

    uint32_t recvd = 0;
    for (uint32_t mi = 0; mi < vlen; mi++) {
      struct mmsghdr mm;
      uintptr_t mm_addr = msgvec_addr + (uintptr_t)mi * sizeof(mm);
      if (rsys_read_mem(pid, &mm, mm_addr, sizeof(mm)) < 0) {
        if (recvd == 0) return 0;
        break;
      }

      struct msghdr mh = mm.msg_hdr;

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
          if (recvd == 0) return 0;
          break;
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
        if (recvd == 0) return 0;
        break;
      }
      free(req);

      int64_t rr = rsys_resp_raw_ret(&resp);
      int32_t eno = rsys_resp_err_no(&resp);
      int64_t rax_one = raw_sys_ret(rr, eno);

      if (rr < 0) {
        free(data);
        free(iov_lens);
        free(iov);
        if (recvd == 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = rax_one;
          return 1;
        }
        break;
      }

      if (data_len < 16) {
        free(data);
        free(iov_lens);
        free(iov);
        if (recvd == 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = -(int64_t)EPROTO;
          return 1;
        }
        break;
      }

      uint32_t out_dlen = rsys_get_u32(data + 0);
      uint32_t out_nlen = rsys_get_u32(data + 4);
      uint32_t out_clen = rsys_get_u32(data + 8);
      uint32_t out_mflags = rsys_get_u32(data + 12);
      if (16u + out_dlen + out_nlen + out_clen != data_len) {
        free(data);
        free(iov_lens);
        free(iov);
        if (recvd == 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pend->set_rax = -(int64_t)EPROTO;
          return 1;
        }
        break;
      }

      const uint8_t *dp = data + 16;
      const uint8_t *np = dp + out_dlen;
      const uint8_t *cp = np + out_nlen;

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

      mh.msg_namelen = (socklen_t)out_nlen;
      mh.msg_controllen = (size_t)out_clen;
      mh.msg_flags = (int)out_mflags;
      uint8_t *mhb = (uint8_t *)malloc(sizeof(mh));
      if (!mhb) die("malloc");
      memcpy(mhb, &mh, sizeof(mh));
      (void)pending_add_out(pend, mm_addr + offsetof(struct mmsghdr, msg_hdr), mhb, (uint32_t)sizeof(mh));

      uint32_t msg_len = (uint32_t)rr;
      uint8_t *lb = (uint8_t *)malloc(4);
      if (!lb) die("malloc");
      memcpy(lb, &msg_len, 4);
      (void)pending_add_out(pend, mm_addr + offsetof(struct mmsghdr, msg_len), lb, 4);

      free(data);
      free(iov_lens);
      free(iov);

      recvd++;
    }

    regs->orig_rax = __NR_getpid;
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    pend->set_rax = (int64_t)recvd;
    return 1;
  }

  // recvmsg(fd, msg, flags)
  if (nr == __NR_recvmsg) {
    int fd_local = (int)regs->rdi;
    uintptr_t msg_addr = (uintptr_t)regs->rsi;
    int flags = (int)regs->rdx;
    int fd_remote = map_fd(fd_local);
    vlog("[rsys] recvmsg(fd=%d -> remote_fd=%d, flags=0x%x)\n", fd_local, fd_remote, flags);
    if (fd_remote < 0) return 0;

    struct msghdr mh;
    if (rsys_read_mem(pid, &mh, msg_addr, sizeof(mh)) < 0) {
      vlog("[rsys] recvmsg: failed to read msghdr at 0x%lx (errno=%d)\n", (unsigned long)msg_addr, errno);
      return 0;
    }

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
        vlog("[rsys] recvmsg: failed to read iov at 0x%lx (errno=%d)\n", (unsigned long)(uintptr_t)mh.msg_iov, errno);
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
    pending_clear(pend);
    pend->active = 1;
    pend->nr = nr;
    pend->close_local_fd = -1;
    if (rr >= 0) {
      pend->has_set_rax = 0;
      pend->map_fd_on_exit = 1;
      pend->map_remote_fd = (int)rr;
      regs->orig_rax = __NR_eventfd2;
      regs->rdi = 0;
      regs->rsi = (uint64_t)EFD_CLOEXEC;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    } else {
      pend->has_set_rax = 1;
      pend->set_rax = rax;
      regs->orig_rax = __NR_getpid;
      if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
    }
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

    int any_remote = 0;
    int any_local = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
      if (pfds[i].fd < 0) continue;
      if (map_fd(pfds[i].fd) >= 0) any_remote = 1;
      else any_local = 1;
    }
    if (!any_remote) {
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

    // Mixed local+remote ppoll. If there are no local fds, do a single remote call.
    int timeout_infinite = !has_tmo;
    int64_t remaining_ns = -1;
    if (has_tmo) remaining_ns = (int64_t)tmo.tv_sec * 1000000000LL + (int64_t)tmo.tv_nsec;
    int64_t slice_ns = any_local ? (50 * 1000000LL) : remaining_ns;

    for (;;) {
      // Local readiness check (0 timeout) for local-only fds.
      struct pollfd *lp = NULL;
      if (any_local) {
        lp = (struct pollfd *)malloc((size_t)nfds * sizeof(*lp));
        if (!lp) die("malloc");
        memcpy(lp, pfds, (size_t)nfds * sizeof(*lp));
        for (size_t i = 0; i < (size_t)nfds; i++) {
          if (lp[i].fd < 0) continue;
          if (map_fd(lp[i].fd) >= 0) lp[i].fd = -1;
          lp[i].revents = 0;
        }
        (void)poll(lp, (nfds_t)nfds, 0);
      }

      int64_t use_ns = timeout_infinite ? slice_ns : slice_ns;
      if (!timeout_infinite && remaining_ns < use_ns) use_ns = remaining_ns;
      if (!timeout_infinite && use_ns < 0) use_ns = 0;

      uint64_t use_sec = (uint64_t)(use_ns / 1000000000LL);
      uint64_t use_nsec = (uint64_t)(use_ns % 1000000000LL);

      uint32_t req_len = 32 + (uint32_t)nfds * 16 + (has_sig ? (uint32_t)sigsz : 0);
      uint8_t *req = (uint8_t *)malloc(req_len);
      if (!req) die("malloc");
      rsys_put_u32(req + 0, (uint32_t)nfds);
      // If we have any local fds to multiplex with, we MUST use a finite remote timeout
      // (a slice), even when the overall timeout is infinite, otherwise we can block
      // forever in the remote ppoll() and miss local stdin readiness.
      uint32_t req_has_tmo = (uint32_t)((!timeout_infinite || any_local) ? 1u : 0u);
      rsys_put_u32(req + 4, req_has_tmo);
      rsys_put_u32(req + 8, has_sig);
      rsys_put_u32(req + 12, (uint32_t)sigsz);
      rsys_put_s64(req + 16, (int64_t)use_sec);
      rsys_put_s64(req + 24, (int64_t)use_nsec);
      uint32_t off = 32;
      for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
        int rfd = (pfds[i].fd < 0) ? -1 : map_fd(pfds[i].fd);
        rsys_put_s64(req + off + 0, (int64_t)rfd);
        rsys_put_u32(req + off + 8, (uint32_t)(uint16_t)pfds[i].events);
        rsys_put_u32(req + off + 12, 0);
        off += 16;
      }
      if (has_sig) memcpy(req + off, sigmask, (size_t)sigsz);

      struct rsys_resp resp;
      uint8_t *data = NULL;
      uint32_t data_len = 0;
      int ok = (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) == 0);
      free(req);

      for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = 0;
      if (ok && rsys_resp_raw_ret(&resp) >= 0 && data_len == 4u + (uint32_t)nfds * 4u && rsys_get_u32(data + 0) == (uint32_t)nfds) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = (short)(uint16_t)rsys_get_u32(data + 4 + i * 4);
      }
      free(data);

      if (lp) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
          if (lp[i].fd >= 0) pfds[i].revents |= lp[i].revents;
        }
        free(lp);
      }

      int ready_cnt = 0;
      for (uint32_t i = 0; i < (uint32_t)nfds; i++) if (pfds[i].revents) ready_cnt++;

      if (ready_cnt > 0 || (has_tmo && remaining_ns <= 0) || (!any_local)) {
        regs->orig_rax = __NR_getpid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        pending_clear(pend);
        pend->active = 1;
        pend->nr = nr;
        pend->set_rax = ready_cnt;
        uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
        if (!wb) die("malloc");
        memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
        (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
        free(pfds);
        return 1;
      }

      if (has_tmo) {
        remaining_ns -= use_ns;
        if (remaining_ns <= 0) continue;
      }
      if (slice_ns < 500 * 1000000LL) slice_ns *= 2;
    }
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
    int any_local = 0;
    for (size_t i = 0; i < (size_t)nfds; i++) {
      if (pfds[i].fd < 0) continue;
      if (map_fd(pfds[i].fd) >= 0) any_remote = 1;
      else any_local = 1;
    }
    if (!any_remote) {
      free(pfds);
      return 0;
    }

    int timeout_infinite = (timeout_ms < 0);
    int64_t remaining_ns = timeout_infinite ? -1 : (int64_t)timeout_ms * 1000000LL;
    int64_t slice_ns = any_local ? (50 * 1000000LL) : remaining_ns;

    for (;;) {
      struct pollfd *lp = NULL;
      if (any_local) {
        lp = (struct pollfd *)malloc((size_t)nfds * sizeof(*lp));
        if (!lp) die("malloc");
        memcpy(lp, pfds, (size_t)nfds * sizeof(*lp));
        for (size_t i = 0; i < (size_t)nfds; i++) {
          if (lp[i].fd < 0) continue;
          if (map_fd(lp[i].fd) >= 0) lp[i].fd = -1;
          lp[i].revents = 0;
        }
        (void)poll(lp, (nfds_t)nfds, 0);
      }

      int64_t use_ns = timeout_infinite ? slice_ns : slice_ns;
      if (!timeout_infinite && remaining_ns < use_ns) use_ns = remaining_ns;
      if (!timeout_infinite && use_ns < 0) use_ns = 0;

      uint64_t use_sec = (uint64_t)(use_ns / 1000000000LL);
      uint64_t use_nsec = (uint64_t)(use_ns % 1000000000LL);

      uint32_t req_len = 32 + (uint32_t)nfds * 16;
      uint8_t *req = (uint8_t *)malloc(req_len);
      if (!req) die("malloc");
      rsys_put_u32(req + 0, (uint32_t)nfds);
      // If we have any local fds to multiplex with, we MUST use a finite remote timeout
      // (a slice), even when the overall timeout is infinite, otherwise we can block
      // forever in the remote ppoll() and miss local readiness.
      uint32_t req_has_tmo = (uint32_t)((!timeout_infinite || any_local) ? 1u : 0u);
      rsys_put_u32(req + 4, req_has_tmo);
      rsys_put_u32(req + 8, 0);
      rsys_put_u32(req + 12, 0);
      rsys_put_s64(req + 16, (int64_t)use_sec);
      rsys_put_s64(req + 24, (int64_t)use_nsec);
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
      int ok = (rsys_call(sock, RSYS_REQ_PPOLL, req, req_len, &resp, &data, &data_len) == 0);
      free(req);

      for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = 0;
      if (ok && rsys_resp_raw_ret(&resp) >= 0 && data_len == 4u + (uint32_t)nfds * 4u && rsys_get_u32(data + 0) == (uint32_t)nfds) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) pfds[i].revents = (short)(uint16_t)rsys_get_u32(data + 4 + i * 4);
      }
      free(data);

      if (lp) {
        for (uint32_t i = 0; i < (uint32_t)nfds; i++) {
          if (lp[i].fd >= 0) pfds[i].revents |= lp[i].revents;
        }
        free(lp);
      }

      int ready_cnt = 0;
      for (uint32_t i = 0; i < (uint32_t)nfds; i++) if (pfds[i].revents) ready_cnt++;
      if (ready_cnt > 0 || timeout_ms == 0 || (!any_local)) {
        regs->orig_rax = __NR_getpid;
        if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
        pending_clear(pend);
        pend->active = 1;
        pend->nr = nr;
        pend->set_rax = ready_cnt;
        uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
        if (!wb) die("malloc");
        memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
        (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
        free(pfds);
        return 1;
      }

      if (!timeout_infinite) {
        remaining_ns -= use_ns;
        if (remaining_ns <= 0) {
          regs->orig_rax = __NR_getpid;
          if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
          pending_clear(pend);
          pend->active = 1;
          pend->nr = nr;
          pend->set_rax = 0;
          uint8_t *wb = (uint8_t *)malloc((size_t)nfds * sizeof(*pfds));
          if (!wb) die("malloc");
          memcpy(wb, pfds, (size_t)nfds * sizeof(*pfds));
          (void)pending_add_out(pend, fds_addr, wb, (uint32_t)((size_t)nfds * sizeof(*pfds)));
          free(pfds);
          return 1;
        }
      }
      if (slice_ns < 500 * 1000000LL) slice_ns *= 2;
    }
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
  // Virtualized remote identity (pid/tid/ppid/pgid/sid) for /proc coherence.
  int virt_ids_known;
  pid_t virt_pid;
  pid_t virt_tid;
  pid_t virt_ppid;
  pid_t virt_pgid;
  pid_t virt_sid;
  int cwd_is_local; // when set, treat relative path ops as local
  int cwd_remote_known;
  char cwd_remote[4096]; // normalized absolute path for remote-relative resolution
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
  ps->virt_ids_known = 0;
  ps->virt_pid = 0;
  ps->virt_tid = 0;
  ps->virt_ppid = 0;
  ps->virt_pgid = 0;
  ps->virt_sid = 0;
  ps->cwd_is_local = 0;
  ps->cwd_remote_known = 1;
  strncpy(ps->cwd_remote, "/", sizeof(ps->cwd_remote));
  ps->cwd_remote[sizeof(ps->cwd_remote) - 1] = '\0';
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
  struct mounts mnts;
  mounts_init(&mnts);
  while (argi < argc) {
    const char *a = argv[argi];
    if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
      g_verbose = 1;
      argi++;
      continue;
    }
    if (strcmp(a, "-m") == 0 || strcmp(a, "--mount") == 0) {
      if (argi + 1 >= argc) {
        fprintf(stderr, "missing argument for %s\n", a);
        mounts_free(&mnts);
        return 2;
      }
      if (mounts_add(&mnts, argv[argi + 1]) < 0) {
        fprintf(stderr, "invalid mount spec: %s\n", argv[argi + 1]);
        mounts_free(&mnts);
        return 2;
      }
      argi += 2;
      continue;
    }
    if (strcmp(a, "-R") == 0 || strcmp(a, "--read-only") == 0) {
      g_read_only = 1;
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
    mounts_free(&mnts);
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
  // Even when not using remote env for exec, we still fetch it so we can pick a
  // sensible initial remote working directory (otherwise rsysd's inherited cwd,
  // e.g. /bin, becomes the default for relative remote syscalls like `ls`).
  {
    if (fetch_remote_env(sock, &remote_env_blob, &remote_env_len) < 0) die("fetch_remote_env");
    remote_envp = envp_from_nul_blob(remote_env_blob, remote_env_len);
    if (!remote_envp) die("envp_from_nul_blob");
  }

  // Initialize remote cwd to something predictable.
  // Prefer HOME. If that is missing but USER=root, use /root. Otherwise fall back to PWD.
  const char *home = envp_get_value(remote_envp, "HOME");
  const char *user = envp_get_value(remote_envp, "USER");
  const char *pwd = envp_get_value(remote_envp, "PWD");
  const char *init_cwd = NULL;
  if (home && home[0] == '/') {
    init_cwd = home;
  } else if (user && strcmp(user, "root") == 0) {
    init_cwd = "/root";
  } else if (pwd && pwd[0] == '/') {
    init_cwd = pwd;
  } else {
    init_cwd = "/";
  }
  vlog("[rsys] init remote cwd: %s\n", init_cwd);
  remote_chdir_best_effort(sock, init_cwd);

  // Fetch remote identity (pid/tid/ppid/pgid/sid) for PID/proc virtualization.
  pid_t remote_pid = 0, remote_tid = 0, remote_ppid = 0, remote_pgid = 0, remote_sid = 0;
  int remote_ids_ok = 0;
  {
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_GETIDS, NULL, 0, &resp, &data, &data_len) == 0 && rsys_resp_raw_ret(&resp) == 0 &&
        rsys_resp_err_no(&resp) == 0 && data_len == 5u * 8u) {
      remote_pid = (pid_t)rsys_get_s64(data + 0);
      remote_tid = (pid_t)rsys_get_s64(data + 8);
      remote_ppid = (pid_t)rsys_get_s64(data + 16);
      remote_pgid = (pid_t)rsys_get_s64(data + 24);
      remote_sid = (pid_t)rsys_get_s64(data + 32);
      if (remote_pid > 0) remote_ids_ok = 1;
      vlog("[rsys] remote ids: pid=%d tid=%d ppid=%d pgid=%d sid=%d\n", (int)remote_pid, (int)remote_tid, (int)remote_ppid,
           (int)remote_pgid, (int)remote_sid);
    }
    free(data);
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
  struct proc_state *root_ps = proctab_add(&procs, child, root_fdt);
  if (!root_ps) die("realloc");
  if (remote_ids_ok) {
    root_ps->virt_ids_known = 1;
    root_ps->virt_pid = remote_pid;
    root_ps->virt_tid = (remote_tid > 0) ? remote_tid : remote_pid;
    root_ps->virt_ppid = remote_ppid;
    root_ps->virt_pgid = remote_pgid;
    root_ps->virt_sid = remote_sid;
  }
  // Seed per-process remote cwd tracking for relative path resolution.
  {
    char norm[4096];
    if (normalize_abs_path(norm, sizeof(norm), init_cwd) == 0) {
      strncpy(root_ps->cwd_remote, norm, sizeof(root_ps->cwd_remote));
      root_ps->cwd_remote[sizeof(root_ps->cwd_remote) - 1] = '\0';
      root_ps->cwd_remote_known = 1;
    }
  }

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
        (void)intercept_syscall(pid, &regs, sock, &ps->fdt->map, &rr, &mnts, &ps->cwd_is_local, &ps->cwd_remote_known,
                                ps->cwd_remote, sizeof(ps->cwd_remote), &ps->virt_ids_known, &ps->virt_pid, &ps->virt_tid,
                                &ps->virt_ppid, &ps->virt_pgid, &ps->virt_sid, &ps->pend);
        ps->in_syscall = 1;
      } else {
        if (ps->pend.active) {
          for (size_t i = 0; i < ps->pend.outs_n; i++) {
            if (ps->pend.outs[i].bytes && ps->pend.outs[i].len) {
              (void)rsys_write_mem(pid, ps->pend.outs[i].addr, ps->pend.outs[i].bytes, ps->pend.outs[i].len);
            }
          }

          // If we created placeholder FD(s), map them to remote FD(s) on syscall exit.
          if (ps->pend.map_fd_on_exit && (int64_t)regs.rax >= 0) {
            int local_fd = (int)regs.rax;
            int remote_fd = ps->pend.map_remote_fd;
            vlog("[rsys] map placeholder fd=%d -> remote_fd=%d\n", local_fd, remote_fd);
            if (fdmap_add_existing(&ps->fdt->map, &rr, local_fd, remote_fd) < 0) {
              remote_close_best_effort(sock, remote_fd);
              regs.rax = (uint64_t)(-(int64_t)ENOMEM);
              ps->pend.has_set_rax = 1;
              ps->pend.set_rax = -(int64_t)ENOMEM;
            }
          }

          if (ps->pend.map_fd_pair_on_exit && (int64_t)regs.rax >= 0) {
            int32_t sv[2] = {-1, -1};
            if (ps->pend.map_pair_addr) {
              (void)rsys_read_mem(pid, sv, (uintptr_t)ps->pend.map_pair_addr, sizeof(sv));
              if (sv[0] >= 0) {
                if (fdmap_add_existing(&ps->fdt->map, &rr, sv[0], ps->pend.map_remote_fd0) < 0) {
                  remote_close_best_effort(sock, ps->pend.map_remote_fd0);
                  ps->pend.has_set_rax = 1;
                  ps->pend.set_rax = -(int64_t)ENOMEM;
                  regs.rax = (uint64_t)ps->pend.set_rax;
                }
              }
              if (sv[1] >= 0) {
                if (fdmap_add_existing(&ps->fdt->map, &rr, sv[1], ps->pend.map_remote_fd1) < 0) {
                  remote_close_best_effort(sock, ps->pend.map_remote_fd1);
                  ps->pend.has_set_rax = 1;
                  ps->pend.set_rax = -(int64_t)ENOMEM;
                  regs.rax = (uint64_t)ps->pend.set_rax;
                }
              }
            }
          }

          if (ps->pend.has_set_rax) regs.rax = (uint64_t)ps->pend.set_rax;
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

        struct proc_state *nps = proctab_add(&procs, newpid, child_fdt);
        if (!nps) die("realloc");
        nps->virt_ids_known = ps->virt_ids_known;
        nps->virt_pid = ps->virt_pid;
        nps->virt_tid = ps->virt_tid;
        nps->virt_ppid = ps->virt_ppid;
        nps->virt_pgid = ps->virt_pgid;
        nps->virt_sid = ps->virt_sid;
        nps->cwd_is_local = ps->cwd_is_local;
        nps->cwd_remote_known = ps->cwd_remote_known;
        strncpy(nps->cwd_remote, ps->cwd_remote, sizeof(nps->cwd_remote));
        nps->cwd_remote[sizeof(nps->cwd_remote) - 1] = '\0';
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
  mounts_free(&mnts);
  return 0;
}
