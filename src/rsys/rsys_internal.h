#pragma once

#define _GNU_SOURCE

#include "rsys_protocol.h"
#include "rsys_tracee_mem.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/user.h>

#if !defined(__x86_64__)
#error "rsys currently supports x86_64 only"
#endif

extern int g_verbose;
extern int g_read_only;
extern int g_interactive_tty;

void die(const char *msg);
void vlog(const char *fmt, ...);

// A small subset of the monolith is still quite coupled; we keep the original
// struct definitions in a single internal header for now.

struct mount_map {
  char *local;   // local source prefix
  char *exposed; // path seen by tracee
  size_t local_len;
  size_t exposed_len;
};

struct mounts {
  struct mount_map *v;
  size_t n;
  size_t cap;
};

void mounts_init(struct mounts *m);
void mounts_free(struct mounts *m);
int mounts_add(struct mounts *m, const char *spec);
int mount_translate_alloc(const struct mounts *m, const char *path, char **out_local);

// Port forwarding: treat bind/listen on selected remote ports as local.
// Spec syntax: -p PORT or -p LOCAL:REMOTE (may be repeated)
struct port_forward {
  uint16_t local_port;
  uint16_t remote_port;
};
struct port_forwards {
  struct port_forward *v;
  size_t n;
  size_t cap;
};
void portfw_init(struct port_forwards *p);
void portfw_free(struct port_forwards *p);
int portfw_add(struct port_forwards *p, const char *spec);
int portfw_lookup_local(const struct port_forwards *p, uint16_t remote_port, uint16_t *out_local_port);

// RPC helpers.
int connect_tcp(const char *host, const char *port_str);
int rsys_call(int sock, uint16_t type, const uint8_t *req, uint32_t req_len, struct rsys_resp *out_resp, uint8_t **out_data,
              uint32_t *out_data_len);
void remote_chdir_best_effort(int sock, const char *path);
void remote_close_best_effort(int sock, int remote_fd);

// Env helpers.
int fetch_remote_env(int sock, uint8_t **out_blob, uint32_t *out_len);
char **envp_from_nul_blob(uint8_t *blob, uint32_t len);
const char *envp_get_value(char **envp, const char *key);

// Path helpers.
int normalize_abs_path(char *out, size_t out_sz, const char *abs_path);
int join_cwd_and_path(char *out, size_t out_sz, const char *cwd_abs, const char *path);
int should_remote_path(const char *path);
void maybe_make_remote_abs_path(char *path, size_t path_sz, const int *cwd_is_local, const int *cwd_remote_known, const char *cwd_remote);

// FD mapping & refcounting.
struct remote_ref_ent {
  int remote_fd;
  uint32_t refs;
};
struct remote_refs {
  struct remote_ref_ent *v;
  size_t n;
  size_t cap;
};
void rrefs_init(struct remote_refs *r);
uint32_t rrefs_get(const struct remote_refs *r, int remote_fd);
int rrefs_inc(struct remote_refs *r, int remote_fd);
uint32_t rrefs_dec(struct remote_refs *r, int remote_fd);

struct fd_map_ent {
  int local_fd;
  int remote_fd;
};
struct fd_map {
  struct fd_map_ent *v;
  size_t n;
  size_t cap;
  int next_local;
};
void fdmap_init(struct fd_map *m);
int fdmap_find_remote(const struct fd_map *m, int local_fd);
int fdmap_add_existing(struct fd_map *m, struct remote_refs *rrefs, int local_fd, int remote_fd);
void fdmap_remove_all_local_and_close(struct fd_map *m, struct remote_refs *rrefs, int sock, int local_fd);
int fdmap_remove_local(struct fd_map *m, int local_fd, int *out_remote_fd);
int fdmap_clone(struct fd_map *dst, const struct fd_map *src, struct remote_refs *rrefs);

// Pending syscall state.
struct pending_sys {
  int active;
  long nr;

  int has_set_rax;
  int64_t set_rax;

  int map_fd_on_exit;
  int map_remote_fd;

  int map_fd_pair_on_exit;
  int map_remote_fd0;
  int map_remote_fd1;
  uintptr_t map_pair_addr;

  // If set, close this remote fd on syscall-exit when syscall failed (regs.rax < 0).
  int close_remote_on_fail;
  int close_remote_fd;

  // For local bind(2) on a forwarded port: if bind succeeds, mark fd as forwarded.
  int mark_portfw_on_exit;
  int mark_portfw_fd;
  uint16_t mark_portfw_local;
  uint16_t mark_portfw_remote;

  // For local getsockname(2) on forwarded listening sockets: rewrite returned port.
  int rewrite_getsockname_on_exit;
  uintptr_t rewrite_getsockname_addr;
  uintptr_t rewrite_getsockname_addrlenp;
  uint16_t rewrite_getsockname_local;
  uint16_t rewrite_getsockname_remote;

  struct out_write {
    uintptr_t addr;
    uint8_t *bytes;
    uint32_t len;
  } * outs;
  size_t outs_n;
  size_t outs_cap;

  int close_local_fd;

  int track_epoll_create;
  int epoll_create_flags;
};

void pending_clear(struct pending_sys *p);
int pending_add_out(struct pending_sys *p, uintptr_t addr, uint8_t *bytes, uint32_t len);

// Epoll virtualization (tracee local epolls + remote watch table).
struct epoll_watch {
  int local_fd;
  int remote_fd;
  uint32_t events;
  uint64_t data;
};
struct epoll_state {
  int epfd_local;
  struct epoll_watch *w;
  size_t n;
  size_t cap;
};
struct epoll_table {
  struct epoll_state *v;
  size_t n;
  size_t cap;
};

void epoll_table_init(struct epoll_table *t);
struct epoll_state *epoll_table_find(struct epoll_table *t, int epfd_local);
void epoll_state_free(struct epoll_state *s);
void epoll_table_del(struct epoll_table *t, int epfd_local);
int epoll_table_add(struct epoll_table *t, int epfd_local);
int epoll_watch_upsert(struct epoll_state *s, int local_fd, int remote_fd, uint32_t events, uint64_t data);
void epoll_watch_del(struct epoll_state *s, int local_fd);

// Process table / fd tables (for fork/clone).
struct fd_table {
  int refs;
  struct fd_map map;
  struct epoll_table ep;
  int local_base[4096];
  // Per-fd port forwarding state: 0 means none, otherwise (local<<16 | remote).
  uint32_t portfw[4096];
};
struct proc_state {
  pid_t pid;
  int in_syscall;
  int sig_to_deliver;
  int virt_ids_known;
  pid_t virt_pid;
  pid_t virt_tid;
  pid_t virt_ppid;
  pid_t virt_pgid;
  pid_t virt_sid;
  int cwd_is_local;
  int cwd_remote_known;
  char cwd_remote[4096];
  struct fd_table *fdt;
  struct pending_sys pend;
};
struct proc_tab {
  struct proc_state *v;
  size_t n;
  size_t cap;
};

struct fd_table *fdtable_new(void);
struct fd_table *fdtable_fork_clone(const struct fd_table *parent, struct remote_refs *rrefs);
void fdtable_ref(struct fd_table *t);
void fdtable_unref(struct fd_table *t, int sock, struct remote_refs *rrefs);
struct proc_state *proctab_find(struct proc_tab *t, pid_t pid);
struct proc_state *proctab_add(struct proc_tab *t, pid_t pid, struct fd_table *fdt);
void proctab_del(struct proc_tab *t, pid_t pid, int sock, struct remote_refs *rrefs);

// Syscall interception.
int intercept_syscall(pid_t pid, struct user_regs_struct *regs, int sock, struct fd_map *fm, struct remote_refs *rrefs,
                      const struct mounts *mnts, int *cwd_is_local, int *cwd_remote_known, char *cwd_remote, size_t cwd_remote_sz,
                      int *virt_ids_known, pid_t *virt_pid, pid_t *virt_tid, pid_t *virt_ppid, pid_t *virt_pgid, pid_t *virt_sid,
                      int *local_base, size_t local_base_sz, uint32_t *portfw_fd, size_t portfw_fd_n,
                      const struct port_forwards *pfw_cfg, struct epoll_table *ep, struct pending_sys *pend);

