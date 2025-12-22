#include "src/rsys/rsys_internal.h"

#include <stdlib.h>
#include <string.h>

void rrefs_init(struct remote_refs *r) {
  r->v = NULL;
  r->n = 0;
  r->cap = 0;
}

uint32_t rrefs_get(const struct remote_refs *r, int remote_fd) {
  for (size_t i = 0; i < r->n; i++) {
    if (r->v[i].remote_fd == remote_fd) return r->v[i].refs;
  }
  return 0;
}

int rrefs_inc(struct remote_refs *r, int remote_fd) {
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
uint32_t rrefs_dec(struct remote_refs *r, int remote_fd) {
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

void fdmap_init(struct fd_map *m) {
  m->v = NULL;
  m->n = 0;
  m->cap = 0;
  m->next_local = 100000; // fake fds start high
}

int fdmap_find_remote(const struct fd_map *m, int local_fd) {
  for (size_t i = 0; i < m->n; i++) {
    if (m->v[i].local_fd == local_fd) return m->v[i].remote_fd;
  }
  return -1;
}

int fdmap_add_existing(struct fd_map *m, struct remote_refs *rrefs, int local_fd, int remote_fd) {
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

void fdmap_remove_all_local_and_close(struct fd_map *m, struct remote_refs *rrefs, int sock, int local_fd) {
  for (;;) {
    int removed_remote = -1;
    if (fdmap_remove_local(m, local_fd, &removed_remote) < 0) break;
    if (removed_remote >= 0) {
      if (rrefs_dec(rrefs, removed_remote) == 0) {
        remote_close_best_effort(sock, removed_remote);
      }
    }
  }
}

int fdmap_remove_local(struct fd_map *m, int local_fd, int *out_remote_fd) {
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

int fdmap_clone(struct fd_map *dst, const struct fd_map *src, struct remote_refs *rrefs) {
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
