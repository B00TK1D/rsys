#pragma once

#include "src/rsys/rsys_internal.h"

struct rsys_intercept_ctx {
  pid_t pid;
  struct user_regs_struct *regs;
  int sock;

  struct fd_map *fm;
  struct remote_refs *rrefs;
  const struct mounts *mnts;

  int *cwd_is_local;
  int *cwd_remote_known;
  char *cwd_remote;
  size_t cwd_remote_sz;

  int *virt_ids_known;
  pid_t *virt_pid;
  pid_t *virt_tid;
  pid_t *virt_ppid;
  pid_t *virt_pgid;
  pid_t *virt_sid;

  int *local_base;
  size_t local_base_n;

  struct epoll_table *ep;
  struct pending_sys *pend;
};

// Helpers used by interception code.
int rsys_ptrace_setregs_or_die(pid_t pid, struct user_regs_struct *regs);

int rsys_deny_syscall(struct rsys_intercept_ctx *ctx, long orig_nr, int err);
int rsys_map_fd(struct rsys_intercept_ctx *ctx, int local);
int rsys_base_fd_local(struct rsys_intercept_ctx *ctx, int fd);
int rsys_pidfd_open_self(struct rsys_intercept_ctx *ctx);
int rsys_pidfd_getfd(int pidfd, int target_fd);
const char *rsys_fcntl_cmd_name(int cmd);
uint16_t rsys_epoll_to_poll(uint32_t e);
uint32_t rsys_poll_to_epoll(uint16_t r);

int rsys_rewrite_path_arg(struct rsys_intercept_ctx *ctx, uintptr_t *reg_ptr, const char *new_path);
void rsys_rewrite_proc_self_path(struct rsys_intercept_ctx *ctx, char *path, size_t path_sz);
int rsys_procfd_force_local(struct rsys_intercept_ctx *ctx, uintptr_t addr, uintptr_t *reg_ptr);
int rsys_maybe_remap_path(struct rsys_intercept_ctx *ctx, uintptr_t addr, uintptr_t *reg_ptr);

// Prelude logic
int rsys_intercept_virtual_ids(struct rsys_intercept_ctx *ctx, long nr);
void rsys_intercept_translate_kill_targets(struct rsys_intercept_ctx *ctx, long nr);

