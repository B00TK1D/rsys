#define _GNU_SOURCE
#include "common.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <server_ip> <server_port> <program> [args...]\n", argv0);
  fprintf(stderr, "Note: <program> is resolved via PATH (like a normal shell).\n");
}

static int get_self_dir(char out[PATH_MAX]) {
  char exe[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if (n < 0) return -1;
  exe[n] = '\0';
  char *slash = strrchr(exe, '/');
  if (!slash) return -1;
  *slash = '\0';
  snprintf(out, PATH_MAX, "%s", exe);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    usage(argv[0]);
    return 2;
  }

  const char *ip = argv[1];
  const char *port = argv[2];
  char **prog_argv = &argv[3];

  char selfdir[PATH_MAX];
  if (get_self_dir(selfdir) != 0) {
    fprintf(stderr, "failed to determine executable directory\n");
    return 1;
  }

  char so_path[PATH_MAX];
  {
    int n = snprintf(so_path, sizeof(so_path), "%s/%s", selfdir, "librsyspreload.so");
    if (n < 0 || (size_t)n >= sizeof(so_path)) {
      fprintf(stderr, "preload path too long\n");
      return 1;
    }
  }

  setenv("RSYS_SERVER", ip, 1);
  setenv("RSYS_PORT", port, 1);

  const char *old = getenv("LD_PRELOAD");
  if (old && old[0]) {
    size_t need = strlen(so_path) + 1 + strlen(old) + 1;
    char *buf = (char *)malloc(need);
    if (!buf) {
      fprintf(stderr, "out of memory\n");
      return 1;
    }
    snprintf(buf, need, "%s:%s", so_path, old);
    setenv("LD_PRELOAD", buf, 1);
    free(buf);
  } else {
    setenv("LD_PRELOAD", so_path, 1);
  }

  execvp(prog_argv[0], prog_argv);
  fprintf(stderr, "execvp(%s) failed: %s\n", prog_argv[0], strerror(errno));
  return 127;
}
