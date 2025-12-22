#include "src/rsys/rsys_internal.h"

#include <stdarg.h>
#include <stdlib.h>

void die(const char *msg) {
  perror(msg);
  exit(1);
}

void vlog(const char *fmt, ...) {
  if (!g_verbose) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

