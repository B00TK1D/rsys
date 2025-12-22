#include "src/rsysd/rsysd_internal.h"

#include <sys/syscall.h>
#include <unistd.h>

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

const char *type_name(uint16_t type) {
  switch (type) {
    case RSYS_REQ_OPENAT: return "openat";
    case RSYS_REQ_CLOSE: return "close";
    case RSYS_REQ_READ: return "read";
    case RSYS_REQ_WRITE: return "write";
    case RSYS_REQ_PREAD64: return "pread64";
    case RSYS_REQ_PWRITE64: return "pwrite64";
    case RSYS_REQ_LSEEK: return "lseek";
    case RSYS_REQ_NEWFSTATAT: return "newfstatat";
    case RSYS_REQ_FSTAT: return "fstat";
    case RSYS_REQ_STATX: return "statx";
    case RSYS_REQ_GETDENTS64: return "getdents64";
    case RSYS_REQ_ACCESS: return "access";
    case RSYS_REQ_READLINKAT: return "readlinkat";
    case RSYS_REQ_UNLINKAT: return "unlinkat";
    case RSYS_REQ_MKDIRAT: return "mkdirat";
    case RSYS_REQ_RENAMEAT2: return "renameat2";
    case RSYS_REQ_UTIMENSAT: return "utimensat";
    case RSYS_REQ_SOCKET: return "socket";
    case RSYS_REQ_SOCKETPAIR: return "socketpair";
    case RSYS_REQ_BIND: return "bind";
    case RSYS_REQ_LISTEN: return "listen";
    case RSYS_REQ_ACCEPT: return "accept";
    case RSYS_REQ_ACCEPT4: return "accept4";
    case RSYS_REQ_CONNECT: return "connect";
    case RSYS_REQ_SHUTDOWN: return "shutdown";
    case RSYS_REQ_GETSOCKNAME: return "getsockname";
    case RSYS_REQ_GETPEERNAME: return "getpeername";
    case RSYS_REQ_SETSOCKOPT: return "setsockopt";
    case RSYS_REQ_GETSOCKOPT: return "getsockopt";
    case RSYS_REQ_SENDTO: return "sendto";
    case RSYS_REQ_RECVFROM: return "recvfrom";
    case RSYS_REQ_SENDMSG: return "sendmsg";
    case RSYS_REQ_RECVMSG: return "recvmsg";
    case RSYS_REQ_FCNTL: return "fcntl";
    case RSYS_REQ_EPOLL_CREATE1: return "epoll_create1";
    case RSYS_REQ_EPOLL_CTL: return "epoll_ctl";
    case RSYS_REQ_EPOLL_WAIT: return "epoll_wait";
    case RSYS_REQ_EPOLL_PWAIT: return "epoll_pwait";
    case RSYS_REQ_PPOLL: return "ppoll";
    case RSYS_REQ_UNAME: return "uname";
    case RSYS_REQ_SETHOSTNAME: return "sethostname";
    case RSYS_REQ_SETDOMAINNAME: return "setdomainname";
    case RSYS_REQ_GETENV: return "getenv";
    case RSYS_REQ_GETIDS: return "getids";
    case RSYS_REQ_CHDIR: return "chdir";
    case RSYS_REQ_FCHDIR: return "fchdir";
    default: return "unknown";
  }
}

int require_len(uint32_t len, uint32_t need) {
  if (len < need) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

int require_blob(uint32_t len, uint32_t off, uint32_t blob_len) {
  if (off > len || blob_len > len - off) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

int64_t do_syscall_ret(long nr, long a1, long a2, long a3, long a4, long a5, long a6, int *out_errno) {
  errno = 0;
  long ret = syscall(nr, a1, a2, a3, a4, a5, a6);
  if (ret == -1) {
    *out_errno = errno;
    return -1;
  }
  *out_errno = 0;
  return (int64_t)ret;
}

