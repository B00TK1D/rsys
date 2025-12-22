#define _GNU_SOURCE

#include "src/rsys/rsys_intercept_ctx.h"

#include <sys/ptrace.h>
#include <sys/syscall.h>

int rsys_intercept_virtual_ids(struct rsys_intercept_ctx *ctx, long nr) {
  if (!ctx || !ctx->virt_ids_known || !*ctx->virt_ids_known) return 0;

  // Virtualized identity syscalls (pid/tid/ppid/etc) so /proc/self coheres with remote /proc.
  // WARNING: this changes what programs observe, and must be kept consistent with /proc rewriting.
  if (nr == __NR_getpid) {
    ctx->regs->orig_rax = __NR_getpid;
    (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
    pending_clear(ctx->pend);
    ctx->pend->active = 1;
    ctx->pend->nr = nr;
    ctx->pend->set_rax = (int64_t)(ctx->virt_pid ? *ctx->virt_pid : 0);
    return 1;
  }

  if (nr == __NR_gettid) {
    ctx->regs->orig_rax = __NR_getpid;
    (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
    pending_clear(ctx->pend);
    ctx->pend->active = 1;
    ctx->pend->nr = nr;
    ctx->pend->set_rax = (int64_t)(ctx->virt_tid ? *ctx->virt_tid : 0);
    return 1;
  }

  if (nr == __NR_getppid) {
    ctx->regs->orig_rax = __NR_getpid;
    (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
    pending_clear(ctx->pend);
    ctx->pend->active = 1;
    ctx->pend->nr = nr;
    ctx->pend->set_rax = (int64_t)(ctx->virt_ppid ? *ctx->virt_ppid : 0);
    return 1;
  }

#ifdef __NR_getpgrp
  if (!g_interactive_tty && nr == __NR_getpgrp) {
    ctx->regs->orig_rax = __NR_getpid;
    (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
    pending_clear(ctx->pend);
    ctx->pend->active = 1;
    ctx->pend->nr = nr;
    ctx->pend->set_rax = (int64_t)(ctx->virt_pgid ? *ctx->virt_pgid : 0);
    return 1;
  }
#endif

#ifdef __NR_getpgid
  if (!g_interactive_tty && nr == __NR_getpgid) {
    pid_t q = (pid_t)ctx->regs->rdi;
    if (q == 0 || (ctx->virt_pid && q == *ctx->virt_pid)) {
      ctx->regs->orig_rax = __NR_getpid;
      (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
      pending_clear(ctx->pend);
      ctx->pend->active = 1;
      ctx->pend->nr = nr;
      ctx->pend->set_rax = (int64_t)(ctx->virt_pgid ? *ctx->virt_pgid : 0);
      return 1;
    }
    // Not self: let it run locally (may not match remote).
  }
#endif

#ifdef __NR_getsid
  if (!g_interactive_tty && nr == __NR_getsid) {
    pid_t q = (pid_t)ctx->regs->rdi;
    if (q == 0 || (ctx->virt_pid && q == *ctx->virt_pid)) {
      ctx->regs->orig_rax = __NR_getpid;
      (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
      pending_clear(ctx->pend);
      ctx->pend->active = 1;
      ctx->pend->nr = nr;
      ctx->pend->set_rax = (int64_t)(ctx->virt_sid ? *ctx->virt_sid : 0);
      return 1;
    }
    // Not self: let it run locally.
  }
#endif

  return 0;
}

void rsys_intercept_translate_kill_targets(struct rsys_intercept_ctx *ctx, long nr) {
  if (!ctx || !ctx->virt_ids_known || !*ctx->virt_ids_known) return;

  // Mitigation: if a program calls kill(getpid(), sig) under pid virtualization,
  // translate the virtual "self" pid/tid back to the real local ones so behavior
  // remains sane (e.g. kill(SIGTERM) terminates the process).
  if (nr == __NR_kill) {
    pid_t target = (pid_t)ctx->regs->rdi;
    if (ctx->virt_pid && target == *ctx->virt_pid) {
      ctx->regs->rdi = (uint64_t)ctx->pid;
      (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
    }
  }

#ifdef __NR_tgkill
  if (nr == __NR_tgkill) {
    pid_t tgid = (pid_t)ctx->regs->rdi;
    pid_t tid = (pid_t)ctx->regs->rsi;
    if (ctx->virt_pid && tgid == *ctx->virt_pid) ctx->regs->rdi = (uint64_t)ctx->pid;
    if (ctx->virt_tid && tid == *ctx->virt_tid) ctx->regs->rsi = (uint64_t)ctx->pid; // best-effort: treat as self
    (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
  }
#endif

#ifdef __NR_tkill
  if (nr == __NR_tkill) {
    pid_t tid = (pid_t)ctx->regs->rdi;
    if (ctx->virt_tid && tid == *ctx->virt_tid) {
      ctx->regs->rdi = (uint64_t)ctx->pid;
      (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
    }
  }
#endif
}

