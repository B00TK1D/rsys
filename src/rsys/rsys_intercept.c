#define _GNU_SOURCE

#include "src/rsys/rsys_internal.h"
#include "src/rsys/rsys_intercept_ctx.h"
#include "src/rsys/intercept/rsys_intercept_dispatch.h"

int intercept_syscall(pid_t pid, struct user_regs_struct *regs, int sock, struct fd_map *fm, struct remote_refs *rrefs,
                      const struct mounts *mnts, int *cwd_is_local, int *cwd_remote_known, char *cwd_remote, size_t cwd_remote_sz,
                      int *virt_ids_known, pid_t *virt_pid, pid_t *virt_tid, pid_t *virt_ppid, pid_t *virt_pgid, pid_t *virt_sid,
                      int *local_base, size_t local_base_n, struct epoll_table *ep, struct pending_sys *pend) {
  long nr = (long)regs->orig_rax;

  struct rsys_intercept_ctx ctx = {
      .pid = pid,
      .regs = regs,
      .sock = sock,
      .fm = fm,
      .rrefs = rrefs,
      .mnts = mnts,
      .cwd_is_local = cwd_is_local,
      .cwd_remote_known = cwd_remote_known,
      .cwd_remote = cwd_remote,
      .cwd_remote_sz = cwd_remote_sz,
      .virt_ids_known = virt_ids_known,
      .virt_pid = virt_pid,
      .virt_tid = virt_tid,
      .virt_ppid = virt_ppid,
      .virt_pgid = virt_pgid,
      .virt_sid = virt_sid,
      .local_base = local_base,
      .local_base_n = local_base_n,
      .ep = ep,
      .pend = pend,
  };

  // Virtualized identity syscalls (pid/tid/ppid/etc) so /proc/self coheres with remote /proc.
  // WARNING: this changes what programs observe, and must be kept consistent with /proc rewriting.
  {
    int vrc = rsys_intercept_virtual_ids(&ctx, nr);
    if (vrc) return vrc;
  }

  // Mitigation: if a program calls kill(getpid(), sig) under pid virtualization,
  // translate the virtual \"self\" pid/tid back to the real local ones so behavior
  // remains sane (e.g. kill(SIGTERM) terminates the process).
  rsys_intercept_translate_kill_targets(&ctx, nr);

  return rsys_intercept_dispatch(&ctx, nr);
}

