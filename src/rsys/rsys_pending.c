#include "src/rsys/rsys_internal.h"

#include <stdlib.h>

void pending_clear(struct pending_sys *p) {
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
  p->track_epoll_create = 0;
  p->epoll_create_flags = 0;
}

int pending_add_out(struct pending_sys *p, uintptr_t addr, uint8_t *bytes, uint32_t len) {
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
