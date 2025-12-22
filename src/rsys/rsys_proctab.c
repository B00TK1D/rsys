#include "src/rsys/rsys_internal.h"

#include <stdlib.h>
#include <string.h>

struct fd_table *fdtable_new(void) {
  struct fd_table *t = (struct fd_table *)calloc(1, sizeof(*t));
  if (!t) return NULL;
  fdmap_init(&t->map);
  t->refs = 1;
  for (size_t i = 0; i < 4096; i++) t->local_base[i] = (int)i;
  for (size_t i = 0; i < 4096; i++) t->portfw[i] = 0;
  epoll_table_init(&t->ep);
  return t;
}

struct fd_table *fdtable_fork_clone(const struct fd_table *parent, struct remote_refs *rrefs) {
  struct fd_table *t = (struct fd_table *)calloc(1, sizeof(*t));
  if (!t) return NULL;
  t->refs = 1;
  if (fdmap_clone(&t->map, &parent->map, rrefs) < 0) {
    free(t);
    return NULL;
  }
  memcpy(t->local_base, parent->local_base, sizeof(t->local_base));
  memcpy(t->portfw, parent->portfw, sizeof(t->portfw));
  // Fork: child gets a copy of the local epoll table.
  epoll_table_init(&t->ep);
  for (size_t i = 0; i < parent->ep.n; i++) {
    (void)epoll_table_add(&t->ep, parent->ep.v[i].epfd_local);
    struct epoll_state *dst = epoll_table_find(&t->ep, parent->ep.v[i].epfd_local);
    const struct epoll_state *src = &parent->ep.v[i];
    if (dst && src && src->n) {
      dst->w = (struct epoll_watch *)malloc(src->n * sizeof(*dst->w));
      if (!dst->w) die("malloc");
      memcpy(dst->w, src->w, src->n * sizeof(*dst->w));
      dst->n = src->n;
      dst->cap = src->n;
    }
  }
  return t;
}

void fdtable_ref(struct fd_table *t) { t->refs++; }

void fdtable_unref(struct fd_table *t, int sock, struct remote_refs *rrefs) {
  if (!t) return;
  if (--t->refs != 0) return;
  for (size_t i = 0; i < t->map.n; i++) {
    int rfd = t->map.v[i].remote_fd;
    if (rrefs_dec(rrefs, rfd) == 0) remote_close_best_effort(sock, rfd);
  }
  for (size_t i = 0; i < t->ep.n; i++) epoll_state_free(&t->ep.v[i]);
  free(t->ep.v);
  free(t->map.v);
  free(t);
}


struct proc_state *proctab_find(struct proc_tab *t, pid_t pid) {
  for (size_t i = 0; i < t->n; i++) {
    if (t->v[i].pid == pid) return &t->v[i];
  }
  return NULL;
}

struct proc_state *proctab_add(struct proc_tab *t, pid_t pid, struct fd_table *fdt) {
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

void proctab_del(struct proc_tab *t, pid_t pid, int sock, struct remote_refs *rrefs) {
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
