#include "src/rsys/rsys_internal.h"

#include <string.h>

int normalize_abs_path(char *out, size_t out_sz, const char *abs_path) {
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

int join_cwd_and_path(char *out, size_t out_sz, const char *cwd_abs, const char *path) {
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

int should_remote_path(const char *path) {
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

void maybe_make_remote_abs_path(char *path, size_t path_sz, const int *cwd_is_local, const int *cwd_remote_known,
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

