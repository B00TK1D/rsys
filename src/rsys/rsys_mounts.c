#include "src/rsys/rsys_internal.h"

#include <stdlib.h>
#include <string.h>

void mounts_init(struct mounts *m) {
  m->v = NULL;
  m->n = 0;
  m->cap = 0;
}

void mounts_free(struct mounts *m) {
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

int mounts_add(struct mounts *m, const char *spec) {
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

int mount_translate_alloc(const struct mounts *m, const char *path, char **out_local) {
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
