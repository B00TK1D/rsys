#define _GNU_SOURCE

#include "src/rsys/rsys_intercept_ctx.h"

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

int rsys_ptrace_setregs_or_die(pid_t pid, struct user_regs_struct *regs) {
  if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) die("PTRACE_SETREGS");
  return 0;
}

int rsys_deny_syscall(struct rsys_intercept_ctx *ctx, long orig_nr, int err) {
  ctx->regs->orig_rax = __NR_getpid;
  (void)rsys_ptrace_setregs_or_die(ctx->pid, ctx->regs);
  pending_clear(ctx->pend);
  ctx->pend->active = 1;
  ctx->pend->nr = orig_nr;
  ctx->pend->set_rax = -(int64_t)err;
  return 1;
}

int rsys_map_fd(struct rsys_intercept_ctx *ctx, int local) { return fdmap_find_remote(ctx->fm, local); }

int rsys_base_fd_local(struct rsys_intercept_ctx *ctx, int fd) {
  if (!ctx->local_base || ctx->local_base_n == 0) return fd;
  if (fd < 0 || (size_t)fd >= ctx->local_base_n) return fd;
  int cur = fd;
  for (int it = 0; it < 8; it++) {
    int nxt = ctx->local_base[cur];
    if (nxt < 0) return cur;
    if (nxt == cur) return cur;
    if (nxt < 0 || (size_t)nxt >= ctx->local_base_n) return nxt;
    cur = nxt;
  }
  return cur;
}

int rsys_pidfd_open_self(struct rsys_intercept_ctx *ctx) {
#ifdef __NR_pidfd_open
  return (int)syscall(__NR_pidfd_open, (int)ctx->pid, 0);
#else
  (void)ctx;
  return -1;
#endif
}

int rsys_pidfd_getfd(int pidfd, int target_fd) {
#if defined(__NR_pidfd_getfd)
  return (int)syscall(__NR_pidfd_getfd, pidfd, target_fd, 0);
#else
  (void)pidfd;
  (void)target_fd;
  return -1;
#endif
}

const char *rsys_fcntl_cmd_name(int cmd) {
  switch (cmd) {
    case F_DUPFD: return "F_DUPFD";
    case F_DUPFD_CLOEXEC: return "F_DUPFD_CLOEXEC";
    case F_GETFD: return "F_GETFD";
    case F_SETFD: return "F_SETFD";
    case F_GETFL: return "F_GETFL";
    case F_SETFL: return "F_SETFL";
    case F_GETLK: return "F_GETLK";
    case F_SETLK: return "F_SETLK";
    case F_SETLKW: return "F_SETLKW";
    default: return "F_?";
  }
}

uint16_t rsys_epoll_to_poll(uint32_t e) {
  uint16_t p = 0;
  if ((e & EPOLLIN) != 0) p |= POLLIN;
  if ((e & EPOLLOUT) != 0) p |= POLLOUT;
  if ((e & EPOLLPRI) != 0) p |= POLLPRI;
#ifdef EPOLLRDHUP
  if ((e & EPOLLRDHUP) != 0) p |= POLLRDHUP;
#endif
  return p;
}

uint32_t rsys_poll_to_epoll(uint16_t r) {
  uint32_t e = 0;
  if ((r & POLLIN) != 0) e |= EPOLLIN;
  if ((r & POLLOUT) != 0) e |= EPOLLOUT;
  if ((r & POLLPRI) != 0) e |= EPOLLPRI;
  if ((r & POLLHUP) != 0) e |= EPOLLHUP;
  if ((r & POLLERR) != 0) e |= EPOLLERR;
#ifdef POLLRDHUP
  if ((r & POLLRDHUP) != 0) e |= EPOLLRDHUP;
#endif
  if ((r & POLLNVAL) != 0) e |= EPOLLERR;
  return e;
}

int rsys_rewrite_path_arg(struct rsys_intercept_ctx *ctx, uintptr_t *reg_ptr, const char *new_path) {
  if (!ctx || !ctx->regs || !reg_ptr || !new_path) return -1;

  // IMPORTANT: don't overwrite the tracee's original string in-place.
  // Programs (like bash) may reuse that buffer for later operations; if we mutate it,
  // we can change user-visible behavior (e.g. cd target path).
  size_t new_len = strlen(new_path) + 1;

  // Scratch below current stack pointer.
  uintptr_t scratch = (uintptr_t)((ctx->regs->rsp - 0x4000) & ~(uintptr_t)0xFul);
  if (rsys_write_mem(ctx->pid, scratch, new_path, new_len) < 0) return -1;
  *reg_ptr = scratch;
  return 0;
}

void rsys_rewrite_proc_self_path(struct rsys_intercept_ctx *ctx, char *path, size_t path_sz) {
  if (!ctx || !path || path_sz == 0) return;
  if (!ctx->virt_ids_known || !*ctx->virt_ids_known) return;
  if (!ctx->virt_pid || *ctx->virt_pid <= 0) return;
  if (path[0] != '/') return;
  if (strncmp(path, "/proc/", 6) != 0) return;

  // Do NOT rewrite /proc/.../fd or /proc/.../fdinfo. Many programs (notably OpenSSH)
  // walk /proc/self/fd to close inherited fds. If we rewrite this to the remote PID,
  // they will close the wrong local fds and corrupt their own state.
  if (strncmp(path, "/proc/self/fd", 13) == 0 && (path[13] == '\0' || path[13] == '/')) return;
  if (strncmp(path, "/proc/self/fdinfo", 17) == 0 && (path[17] == '\0' || path[17] == '/')) return;
  if (strncmp(path, "/proc/thread-self/fd", 20) == 0 && (path[20] == '\0' || path[20] == '/')) return;
  if (strncmp(path, "/proc/thread-self/fdinfo", 24) == 0 && (path[24] == '\0' || path[24] == '/')) return;

  // /proc/self[/...]
  if (strncmp(path, "/proc/self", 10) == 0 && (path[10] == '\0' || path[10] == '/')) {
    char out[4096];
    snprintf(out, sizeof(out), "/proc/%d%s", (int)*ctx->virt_pid, path + 10);
    strncpy(path, out, path_sz);
    path[path_sz - 1] = '\0';
    return;
  }
  // /proc/thread-self[/...]
  if (strncmp(path, "/proc/thread-self", 16) == 0 && (path[16] == '\0' || path[16] == '/')) {
    char out[4096];
    snprintf(out, sizeof(out), "/proc/%d%s", (int)*ctx->virt_pid, path + 16);
    strncpy(path, out, path_sz);
    path[path_sz - 1] = '\0';
    return;
  }
  // /proc/<localpid>[/...] -> /proc/<virt_pid>[/...]
  const char *p = path + 6;
  char *end = NULL;
  long lp = strtol(p, &end, 10);
  if (end && end > p && (end[0] == '\0' || end[0] == '/')) {
    if ((pid_t)lp == ctx->pid) {
      // Same fd-walk exclusion for /proc/<pid>/fd[/...] and /proc/<pid>/fdinfo[/...]
      if (strcmp(end, "/fd") == 0 || strncmp(end, "/fd/", 4) == 0) return;
      if (strcmp(end, "/fdinfo") == 0 || strncmp(end, "/fdinfo/", 8) == 0) return;
      char out[4096];
      snprintf(out, sizeof(out), "/proc/%d%s", (int)*ctx->virt_pid, end);
      strncpy(path, out, path_sz);
      path[path_sz - 1] = '\0';
    }
  }
}

int rsys_procfd_force_local(struct rsys_intercept_ctx *ctx, uintptr_t addr, uintptr_t *reg_ptr) {
  if (!ctx || !addr) return 0;
  char in[4096];
  if (rsys_read_cstring(ctx->pid, addr, in, sizeof(in)) < 0) return 0;
  if (in[0] != '/' || strncmp(in, "/proc/", 6) != 0) return 0;

  // Direct self/thread-self fd enumerations.
  if (strncmp(in, "/proc/self/fd", 13) == 0 && (in[13] == '\0' || in[13] == '/')) return 1;
  if (strncmp(in, "/proc/self/fdinfo", 17) == 0 && (in[17] == '\0' || in[17] == '/')) return 1;
  if (strncmp(in, "/proc/thread-self/fd", 20) == 0 && (in[20] == '\0' || in[20] == '/')) return 1;
  if (strncmp(in, "/proc/thread-self/fdinfo", 24) == 0 && (in[24] == '\0' || in[24] == '/')) return 1;

  // Numeric /proc/<pid>/fd... or /proc/<pid>/fdinfo...
  const char *p = in + 6;
  char *end = NULL;
  long n = strtol(p, &end, 10);
  if (!(end && end > p)) return 0;
  if (!(end[0] == '\0' || end[0] == '/')) return 0;

  int is_fd = (strcmp(end, "/fd") == 0) || (strncmp(end, "/fd/", 4) == 0);
  int is_fdinfo = (strcmp(end, "/fdinfo") == 0) || (strncmp(end, "/fdinfo/", 8) == 0);
  if (!is_fd && !is_fdinfo) return 0;

  // If PID matches local pid, keep local with no rewrite.
  if ((pid_t)n == ctx->pid) return 1;

  // If PID matches virtual pid, rewrite to /proc/self/...
  if (ctx->virt_ids_known && *ctx->virt_ids_known && ctx->virt_pid && *ctx->virt_pid > 0 && (pid_t)n == *ctx->virt_pid) {
    char out[4096];
    snprintf(out, sizeof(out), "/proc/self%s", end);
    if (rsys_rewrite_path_arg(ctx, reg_ptr, out) == 0) {
      vlog("[rsys] force-local procfd: %s -> %s\n", in, out);
    }
    return 2;
  }

  // Unknown PID: still better to keep local (it refers to local process namespace).
  return 1;
}

int rsys_maybe_remap_path(struct rsys_intercept_ctx *ctx, uintptr_t addr, uintptr_t *reg_ptr) {
  if (!ctx || !addr) return 0;
  char path[4096];
  if (rsys_read_cstring(ctx->pid, addr, path, sizeof(path)) < 0) return 0;
  char *lp = NULL;
  int tr = mount_translate_alloc(ctx->mnts, path, &lp);
  if (tr <= 0) {
    free(lp);
    return 0;
  }
  int rc = rsys_rewrite_path_arg(ctx, reg_ptr, lp);
  if (rc == 0) {
    vlog("[rsys] mount map: %s -> %s\n", path, lp);
  }
  free(lp);
  return (rc == 0) ? 1 : 0;
}

