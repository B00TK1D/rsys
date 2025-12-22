#define _GNU_SOURCE

#include "src/rsys/rsys.h"
#include "src/rsys/rsys_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <linux/close_range.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int g_verbose = 0;
int g_read_only = 0;
int g_interactive_tty = 0;

static void usage(FILE *out, const char *argv0) {
  fprintf(out,
          "usage: %s [options] <server_ip_or_host> <port> <prog> [args...]\n"
          "\n"
          "Remote syscall forwarding client.\n"
          "\n"
          "options:\n"
          "  -v, --verbose          verbose logging\n"
          "  -m, --mount SRC:DST     expose local SRC at path DST (may be repeated)\n"
          "  -p PORT|LOCAL:REMOTE   forward remote listen port to local port (may be repeated)\n"
          "  -R, --read-only         block remote filesystem mutations\n"
          "  -e                     use local environment for the traced program\n"
          "  -E                     use remote environment for the traced program (default)\n"
          "  -h, -?, --help         show this help\n",
          argv0);
}

int rsys_main(int argc, char **argv) {
  int argi = 1;
  int use_remote_env = 1; // default
  struct mounts mnts;
  mounts_init(&mnts);
  struct port_forwards pfw;
  portfw_init(&pfw);
  while (argi < argc) {
    const char *a = argv[argi];
    if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
      g_verbose = 1;
      argi++;
      continue;
    }
    if (strcmp(a, "-m") == 0 || strcmp(a, "--mount") == 0) {
      if (argi + 1 >= argc) {
        fprintf(stderr, "missing argument for %s\n", a);
        mounts_free(&mnts);
        return 2;
      }
      if (mounts_add(&mnts, argv[argi + 1]) < 0) {
        fprintf(stderr, "invalid mount spec: %s\n", argv[argi + 1]);
        mounts_free(&mnts);
        return 2;
      }
      argi += 2;
      continue;
    }
    if (strcmp(a, "-p") == 0) {
      if (argi + 1 >= argc) {
        fprintf(stderr, "missing argument for %s\n", a);
        portfw_free(&pfw);
        mounts_free(&mnts);
        return 2;
      }
      if (portfw_add(&pfw, argv[argi + 1]) < 0) {
        fprintf(stderr, "invalid port forward spec: %s\n", argv[argi + 1]);
        portfw_free(&pfw);
        mounts_free(&mnts);
        return 2;
      }
      argi += 2;
      continue;
    }
    if (strcmp(a, "-R") == 0 || strcmp(a, "--read-only") == 0) {
      g_read_only = 1;
      argi++;
      continue;
    }
    if (strcmp(a, "-e") == 0) {
      use_remote_env = 0;
      argi++;
      continue;
    }
    if (strcmp(a, "-E") == 0) {
      use_remote_env = 1;
      argi++;
      continue;
    }
    if (strcmp(a, "-h") == 0 || strcmp(a, "-?") == 0 || strcmp(a, "--help") == 0) {
      usage(stdout, argv[0]);
      return 0;
    }
    break;
  }
  if (argc - argi < 3) {
    fprintf(stderr, "missing required arguments: <server_ip_or_host> <port> <prog> [args...]\n");
    fprintf(stderr, "note: `-p` configures port forwarding, not the rsysd server port.\n");
    usage(stderr, argv[0]);
    portfw_free(&pfw);
    mounts_free(&mnts);
    return 2;
  }

  const char *host = argv[argi + 0];
  const char *port = argv[argi + 1];

  int sock = connect_tcp(host, port);
  if (sock < 0) die("connect");
  vlog("[rsys] connected to %s:%s\n", host, port);
  g_interactive_tty = isatty(0);

  uint8_t *remote_env_blob = NULL;
  uint32_t remote_env_len = 0;
  char **remote_envp = NULL;
  // Even when not using remote env for exec, we still fetch it so we can pick a
  // sensible initial remote working directory (otherwise rsysd's inherited cwd,
  // e.g. /bin, becomes the default for relative remote syscalls like `ls`).
  {
    if (fetch_remote_env(sock, &remote_env_blob, &remote_env_len) < 0) die("fetch_remote_env");
    remote_envp = envp_from_nul_blob(remote_env_blob, remote_env_len);
    if (!remote_envp) die("envp_from_nul_blob");
  }

  // Initialize remote cwd to something predictable.
  // Prefer HOME. If that is missing but USER=root, use /root. Otherwise fall back to PWD.
  const char *home = envp_get_value(remote_envp, "HOME");
  const char *user = envp_get_value(remote_envp, "USER");
  const char *pwd = envp_get_value(remote_envp, "PWD");
  const char *init_cwd = NULL;
  if (home && home[0] == '/') {
    init_cwd = home;
  } else if (user && strcmp(user, "root") == 0) {
    init_cwd = "/root";
  } else if (pwd && pwd[0] == '/') {
    init_cwd = pwd;
  } else {
    init_cwd = "/";
  }
  vlog("[rsys] init remote cwd: %s\n", init_cwd);
  remote_chdir_best_effort(sock, init_cwd);

  // Fetch remote identity (pid/tid/ppid/pgid/sid) for PID/proc virtualization.
  pid_t remote_pid = 0, remote_tid = 0, remote_ppid = 0, remote_pgid = 0, remote_sid = 0;
  int remote_ids_ok = 0;
  {
    struct rsys_resp resp;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    if (rsys_call(sock, RSYS_REQ_GETIDS, NULL, 0, &resp, &data, &data_len) == 0 && rsys_resp_raw_ret(&resp) == 0 &&
        rsys_resp_err_no(&resp) == 0 && data_len == 5u * 8u) {
      remote_pid = (pid_t)rsys_get_s64(data + 0);
      remote_tid = (pid_t)rsys_get_s64(data + 8);
      remote_ppid = (pid_t)rsys_get_s64(data + 16);
      remote_pgid = (pid_t)rsys_get_s64(data + 24);
      remote_sid = (pid_t)rsys_get_s64(data + 32);
      if (remote_pid > 0) remote_ids_ok = 1;
      vlog("[rsys] remote ids: pid=%d tid=%d ppid=%d pgid=%d sid=%d\n", (int)remote_pid, (int)remote_tid, (int)remote_ppid,
           (int)remote_pgid, (int)remote_sid);
    }
    free(data);
  }

  // Fork tracee
  pid_t child = fork();
  if (child < 0) die("fork");

  if (child == 0) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) _exit(127);
    raise(SIGSTOP);
    if (use_remote_env) {
      execvpe(argv[argi + 2], &argv[argi + 2], remote_envp);
    } else {
      execvp(argv[argi + 2], &argv[argi + 2]);
    }
    _exit(127);
  }

  int status;
  if (waitpid(child, &status, 0) < 0) die("waitpid");
  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "tracee did not stop\n");
    return 1;
  }

  // Note: We intentionally do NOT enable PTRACE_O_TRACEEXEC here.
  // With PTRACE_SYSCALL, the extra exec event stop can desynchronize a simple
  // entry/exit syscall-stop state machine. Fork/clone/vfork are sufficient to
  // keep tracing descendants spawned by shells.
  long opts =
      PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
  if (ptrace(PTRACE_SETOPTIONS, child, 0, (void *)opts) < 0) die("PTRACE_SETOPTIONS");

  struct remote_refs rr;
  rrefs_init(&rr);

  struct fd_table *root_fdt = fdtable_new();
  if (!root_fdt) die("calloc");

  struct proc_tab procs;
  memset(&procs, 0, sizeof(procs));
  struct proc_state *root_ps = proctab_add(&procs, child, root_fdt);
  if (!root_ps) die("realloc");
  if (remote_ids_ok) {
    root_ps->virt_ids_known = 1;
    root_ps->virt_pid = remote_pid;
    root_ps->virt_tid = (remote_tid > 0) ? remote_tid : remote_pid;
    root_ps->virt_ppid = remote_ppid;
    root_ps->virt_pgid = remote_pgid;
    root_ps->virt_sid = remote_sid;
  }
  // Seed per-process remote cwd tracking for relative path resolution.
  {
    char norm[4096];
    if (normalize_abs_path(norm, sizeof(norm), init_cwd) == 0) {
      strncpy(root_ps->cwd_remote, norm, sizeof(root_ps->cwd_remote));
      root_ps->cwd_remote[sizeof(root_ps->cwd_remote) - 1] = '\0';
      root_ps->cwd_remote_known = 1;
    }
  }

  if (ptrace(PTRACE_SYSCALL, child, 0, 0) < 0) die("PTRACE_SYSCALL");

  while (procs.n) {
    pid_t pid = waitpid(-1, &status, __WALL);
    if (pid < 0) {
      if (errno == EINTR) continue;
      die("waitpid");
    }

    struct proc_state *ps = proctab_find(&procs, pid);
    if (!ps) {
      // Unknown pid; best effort: keep it running without signal.
      (void)ptrace(PTRACE_SYSCALL, pid, 0, 0);
      continue;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      proctab_del(&procs, pid, sock, &rr);
      continue;
    }
    if (!WIFSTOPPED(status)) continue;

    int sig = WSTOPSIG(status);
    int deliver = 0;

    if (sig == (SIGTRAP | 0x80)) {
      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) die("PTRACE_GETREGS");

      if (!ps->in_syscall) {
        (void)intercept_syscall(pid, &regs, sock, &ps->fdt->map, &rr, &mnts, &ps->cwd_is_local, &ps->cwd_remote_known,
                                ps->cwd_remote, sizeof(ps->cwd_remote), &ps->virt_ids_known, &ps->virt_pid, &ps->virt_tid,
                                &ps->virt_ppid, &ps->virt_pgid, &ps->virt_sid, ps->fdt->local_base, 4096, ps->fdt->portfw, 4096,
                                &pfw, &ps->fdt->ep, &ps->pend);
        ps->in_syscall = 1;
      } else {
        if (ps->pend.active) {
          int64_t sysret = (int64_t)regs.rax;
          for (size_t i = 0; i < ps->pend.outs_n; i++) {
            if (ps->pend.outs[i].bytes && ps->pend.outs[i].len) {
              (void)rsys_write_mem(pid, ps->pend.outs[i].addr, ps->pend.outs[i].bytes, ps->pend.outs[i].len);
            }
          }

          // If a syscall failed after we created a remote fd, close it (best-effort).
          if (ps->pend.close_remote_on_fail && sysret < 0 && ps->pend.close_remote_fd >= 0) {
            remote_close_best_effort(sock, ps->pend.close_remote_fd);
          }

          // Track local epoll instances created by the tracee.
          if (ps->pend.track_epoll_create && sysret >= 0) {
            int epfd_local = (int)sysret;
            if (epoll_table_add(&ps->fdt->ep, epfd_local) == 0) {
              vlog("[rsys] epoll_create1 -> local epfd=%d (virtual remote watches enabled)\n", epfd_local);
            }
          }

          // If we created placeholder FD(s), map them to remote FD(s) on syscall exit.
          if (ps->pend.map_fd_on_exit && sysret >= 0) {
            int local_fd = (int)sysret;
            int remote_fd = ps->pend.map_remote_fd;
            vlog("[rsys] map placeholder fd=%d -> remote_fd=%d\n", local_fd, remote_fd);
            // If the local fd number is being reused, ensure no stale mapping remains.
            fdmap_remove_all_local_and_close(&ps->fdt->map, &rr, sock, local_fd);
            // Clear local alias for this fd (it is now a remote-mapped placeholder).
            if (local_fd >= 0 && local_fd < 4096) ps->fdt->local_base[local_fd] = -1;
            if (fdmap_add_existing(&ps->fdt->map, &rr, local_fd, remote_fd) < 0) {
              remote_close_best_effort(sock, remote_fd);
              regs.rax = (uint64_t)(-(int64_t)ENOMEM);
              ps->pend.has_set_rax = 1;
              ps->pend.set_rax = -(int64_t)ENOMEM;
            }
          }

          if (ps->pend.map_fd_pair_on_exit && sysret >= 0) {
            int32_t sv[2] = {-1, -1};
            if (ps->pend.map_pair_addr) {
              (void)rsys_read_mem(pid, sv, (uintptr_t)ps->pend.map_pair_addr, sizeof(sv));
              if (sv[0] >= 0) {
                fdmap_remove_all_local_and_close(&ps->fdt->map, &rr, sock, sv[0]);
                if (sv[0] < 4096) ps->fdt->local_base[sv[0]] = -1;
                if (fdmap_add_existing(&ps->fdt->map, &rr, sv[0], ps->pend.map_remote_fd0) < 0) {
                  remote_close_best_effort(sock, ps->pend.map_remote_fd0);
                  ps->pend.has_set_rax = 1;
                  ps->pend.set_rax = -(int64_t)ENOMEM;
                  regs.rax = (uint64_t)ps->pend.set_rax;
                }
              }
              if (sv[1] >= 0) {
                fdmap_remove_all_local_and_close(&ps->fdt->map, &rr, sock, sv[1]);
                if (sv[1] < 4096) ps->fdt->local_base[sv[1]] = -1;
                if (fdmap_add_existing(&ps->fdt->map, &rr, sv[1], ps->pend.map_remote_fd1) < 0) {
                  remote_close_best_effort(sock, ps->pend.map_remote_fd1);
                  ps->pend.has_set_rax = 1;
                  ps->pend.set_rax = -(int64_t)ENOMEM;
                  regs.rax = (uint64_t)ps->pend.set_rax;
                }
              }
            }
          }

          // If a local bind succeeded on a forwarded port, record per-fd mapping for later getsockname rewriting.
          if (ps->pend.mark_portfw_on_exit && sysret == 0) {
            int lfd = ps->pend.mark_portfw_fd;
            if (lfd >= 0 && lfd < 4096) {
              uint32_t enc = ((uint32_t)ps->pend.mark_portfw_local << 16) | (uint32_t)ps->pend.mark_portfw_remote;
              ps->fdt->portfw[lfd] = enc;
              vlog("[rsys] portfw: fd=%d remote_port=%u -> local_port=%u\n", lfd, (unsigned)ps->pend.mark_portfw_remote,
                   (unsigned)ps->pend.mark_portfw_local);
            }
          }

          // For local getsockname on forwarded sockets, rewrite returned port to remote_port.
          if (ps->pend.rewrite_getsockname_on_exit && sysret == 0) {
            uint32_t alen = 0;
            if (ps->pend.rewrite_getsockname_addr && ps->pend.rewrite_getsockname_addrlenp &&
                rsys_read_mem(pid, &alen, ps->pend.rewrite_getsockname_addrlenp, sizeof(alen)) == 0) {
              if (alen > 128u) alen = 128u;
              uint8_t sb[128];
              if (alen >= 2u && rsys_read_mem(pid, sb, ps->pend.rewrite_getsockname_addr, (size_t)alen) == 0) {
                uint16_t fam = (uint16_t)(sb[0] | ((uint16_t)sb[1] << 8));
                if (fam == AF_INET && alen >= 4u) {
                  // sockaddr_in: port at offset 2
                  uint16_t rp = htons(ps->pend.rewrite_getsockname_remote);
                  memcpy(sb + 2, &rp, 2);
                  (void)rsys_write_mem(pid, ps->pend.rewrite_getsockname_addr, sb, (size_t)alen);
                } else if (fam == AF_INET6 && alen >= 4u) {
                  // sockaddr_in6: port at offset 2
                  uint16_t rp = htons(ps->pend.rewrite_getsockname_remote);
                  memcpy(sb + 2, &rp, 2);
                  (void)rsys_write_mem(pid, ps->pend.rewrite_getsockname_addr, sb, (size_t)alen);
                }
              }
            }
          }

          if (ps->pend.has_set_rax) regs.rax = (uint64_t)ps->pend.set_rax;
          if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) die("PTRACE_SETREGS");
          pending_clear(&ps->pend);
        }

      // Track local fd aliasing for dup'd stdio (even when the dup syscalls were not intercepted).
      if (g_verbose) {
        long onr = (long)regs.orig_rax;
        long ret = (long)regs.rax;
        if ((onr == __NR_dup || onr == __NR_dup2 || onr == __NR_dup3) && ret >= 0) {
          int oldfd = (int)regs.rdi;
          int newfd = (onr == __NR_dup) ? (int)ret : (int)regs.rsi;
          // Only track aliases for local fds (not remote-mapped placeholders).
          if (oldfd >= 0 && oldfd < 4096 && newfd >= 0 && newfd < 4096) {
            if (fdmap_find_remote(&ps->fdt->map, oldfd) < 0) {
              int base = ps->fdt->local_base[oldfd];
              if (base < 0) base = oldfd;
              ps->fdt->local_base[newfd] = base;
              // Propagate port-forward state across dup for local fds.
              if (ps->fdt->portfw[oldfd] != 0) ps->fdt->portfw[newfd] = ps->fdt->portfw[oldfd];
              vlog("[rsys] local alias: fd=%d -> base=%d (from dup)\n", newfd, base);
            }
          }
        }
      }
        ps->in_syscall = 0;
      }
    } else if (sig == SIGTRAP) {
      unsigned event = (unsigned)status >> 16;
      if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
        unsigned long msg = 0;
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) < 0) die("PTRACE_GETEVENTMSG");
        pid_t newpid = (pid_t)msg;

        struct fd_table *child_fdt = NULL;
        if (event == PTRACE_EVENT_CLONE) {
          // Likely a thread: share the same fd table mapping.
          fdtable_ref(ps->fdt);
          child_fdt = ps->fdt;
        } else {
          child_fdt = fdtable_fork_clone(ps->fdt, &rr);
          if (!child_fdt) die("calloc");
        }

        struct proc_state *nps = proctab_add(&procs, newpid, child_fdt);
        if (!nps) die("realloc");
        nps->virt_ids_known = ps->virt_ids_known;
        nps->virt_pid = ps->virt_pid;
        nps->virt_tid = ps->virt_tid;
        nps->virt_ppid = ps->virt_ppid;
        nps->virt_pgid = ps->virt_pgid;
        nps->virt_sid = ps->virt_sid;
        nps->cwd_is_local = ps->cwd_is_local;
        nps->cwd_remote_known = ps->cwd_remote_known;
        strncpy(nps->cwd_remote, ps->cwd_remote, sizeof(nps->cwd_remote));
        nps->cwd_remote[sizeof(nps->cwd_remote) - 1] = '\0';
        // The new tracee will report an initial SIGSTOP to the tracer; we will
        // resume it from the main wait loop. Avoid racing with short-lived
        // children by not issuing ptrace commands here.
      }
      // Do not forward SIGTRAP into the tracee.
      deliver = 0;
    } else if (sig == SIGSTOP) {
      // Don't forward initial/ptrace SIGSTOP into the tracee.
      deliver = 0;
    } else {
      deliver = sig;
    }

    if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)(uintptr_t)deliver) < 0) die("PTRACE_SYSCALL");
  }

  close(sock);
  free(rr.v);
  free(procs.v);
  free(remote_envp);
  free(remote_env_blob);
  portfw_free(&pfw);
  mounts_free(&mnts);
  return 0;
}
