#include "src/rsysd/rsysd.h"
#include "src/rsysd/rsysd_internal.h"

#include <limits.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int g_verbose = 0;

static void serve_client(int cfd) {
  for (;;) {
    struct rsys_hdr h;
    if (rsys_recv_hdr(cfd, &h) < 0) break;
    uint16_t type = rsys_hdr_type(&h);
    uint32_t len = rsys_hdr_len(&h);

    uint8_t *payload = NULL;
    if (len) {
      payload = (uint8_t *)malloc(len);
      if (!payload) die("malloc");
      if (rsys_recv_all(cfd, payload, len) < 0) {
        free(payload);
        break;
      }
    }

    if (rsysd_handle_request(cfd, type, payload ? payload : (const uint8_t *)"", len) < 0) {
      if (g_verbose) perror("[rsysd] handle_request");
      free(payload);
      break;
    }
    free(payload);
  }
  close(cfd);
}

int rsysd_main(int argc, char **argv) {
  int argi = 1;
  if (argc > 1 && strcmp(argv[1], "-v") == 0) {
    g_verbose = 1;
    argi++;
  }
  if (argc - argi < 1) {
    fprintf(stderr, "usage: %s [-v] <port>\n", argv[0]);
    return 2;
  }

  int port = atoi(argv[argi]);
  if (port <= 0 || port > 65535) {
    fprintf(stderr, "invalid port\n");
    return 2;
  }

  signal(SIGPIPE, SIG_IGN);

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) die("socket");

  int one = 1;
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) die("setsockopt");

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
  if (listen(s, 16) < 0) die("listen");
  vlog("[rsysd] listening on 0.0.0.0:%d\n", port);

  for (;;) {
    int cfd = accept(s, NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      die("accept");
    }

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
      close(s);

      // Each client gets its own worker process. Ensure a predictable initial
      // working directory for relative remote operations (AT_FDCWD + relative paths).
      // If rsysd is started by a service manager, its inherited cwd can be something
      // surprising (e.g., /bin), which makes commands like `ls` appear to "start" in
      // the wrong directory until the user manually `cd`s.
      const char *home = getenv("HOME");
      if (!(home && home[0] == '/')) home = NULL;
      if (!home) {
        struct passwd pw, *pwp = NULL;
        char buf[16384];
        if (getpwuid_r(getuid(), &pw, buf, sizeof(buf), &pwp) == 0 && pwp && pwp->pw_dir && pwp->pw_dir[0] == '/') {
          home = pwp->pw_dir;
        }
      }
      if (home) {
        if (chdir(home) < 0) {
          // Ignore: keep inherited cwd if home is unusable.
        }
      }
      // Keep PWD consistent with the actual process cwd for shells that rely on it.
      char cwd[PATH_MAX];
      if (getcwd(cwd, sizeof(cwd)) != NULL) {
        (void)setenv("PWD", cwd, 1);
      }

      vlog("[rsysd] client connected\n");
      serve_client(cfd);
      _exit(0);
    }
    close(cfd);
  }
}

