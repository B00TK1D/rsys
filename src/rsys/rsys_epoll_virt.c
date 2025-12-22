#include "src/rsys/rsys_internal.h"

#include <stdlib.h>
#include <string.h>

void epoll_table_init(struct epoll_table *t) {
  memset(t, 0, sizeof(*t));
}

struct epoll_state *epoll_table_find(struct epoll_table *t, int epfd_local) {
  if (!t) return NULL;
  for (size_t i = 0; i < t->n; i++) {
    if (t->v[i].epfd_local == epfd_local) return &t->v[i];
  }
  return NULL;
}

void epoll_state_free(struct epoll_state *s) {
  if (!s) return;
  free(s->w);
  s->w = NULL;
  s->n = 0;
  s->cap = 0;
  s->epfd_local = -1;
}

void epoll_table_del(struct epoll_table *t, int epfd_local) {
  if (!t) return;
  for (size_t i = 0; i < t->n; i++) {
    if (t->v[i].epfd_local == epfd_local) {
      epoll_state_free(&t->v[i]);
      t->v[i] = t->v[t->n - 1];
      t->n--;
      return;
    }
  }
}

int epoll_table_add(struct epoll_table *t, int epfd_local) {
  if (!t) return -1;
  if (epoll_table_find(t, epfd_local)) return 0;
  if (t->n == t->cap) {
    size_t ncap = t->cap ? (t->cap * 2) : 8;
    void *nv = realloc(t->v, ncap * sizeof(*t->v));
    if (!nv) return -1;
    t->v = (struct epoll_state *)nv;
    t->cap = ncap;
  }
  struct epoll_state *s = &t->v[t->n++];
  memset(s, 0, sizeof(*s));
  s->epfd_local = epfd_local;
  s->w = NULL;
  s->n = 0;
  s->cap = 0;
  return 0;
}

int epoll_watch_upsert(struct epoll_state *s, int local_fd, int remote_fd, uint32_t events, uint64_t data) {
  if (!s) return -1;
  for (size_t i = 0; i < s->n; i++) {
    if (s->w[i].local_fd == local_fd) {
      s->w[i].remote_fd = remote_fd;
      s->w[i].events = events;
      s->w[i].data = data;
      return 0;
    }
  }
  if (s->n == s->cap) {
    size_t ncap = s->cap ? (s->cap * 2) : 8;
    void *nv = realloc(s->w, ncap * sizeof(*s->w));
    if (!nv) return -1;
    s->w = (struct epoll_watch *)nv;
    s->cap = ncap;
  }
  s->w[s->n++] = (struct epoll_watch){.local_fd = local_fd, .remote_fd = remote_fd, .events = events, .data = data};
  return 0;
}

void epoll_watch_del(struct epoll_state *s, int local_fd) {
  if (!s) return;
  for (size_t i = 0; i < s->n; i++) {
    if (s->w[i].local_fd == local_fd) {
      s->w[i] = s->w[s->n - 1];
      s->n--;
      return;
    }
  }
}

