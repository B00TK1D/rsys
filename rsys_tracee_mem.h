#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>

static inline int rsys_read_mem(pid_t pid, void *dst, uintptr_t src_addr, size_t len) {
  if (len == 0) return 0;

  struct iovec local = {.iov_base = dst, .iov_len = len};
  struct iovec remote = {.iov_base = (void *)src_addr, .iov_len = len};
  ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (n == (ssize_t)len) return 0;

  // Fallback to ptrace word reads.
  size_t off = 0;
  errno = 0;
  while (off < len) {
    long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(src_addr + off), NULL);
    if (word == -1 && errno) return -1;
    size_t chunk = sizeof(long);
    if (off + chunk > len) chunk = len - off;
    memcpy((uint8_t *)dst + off, &word, chunk);
    off += chunk;
  }
  return 0;
}

static inline int rsys_write_mem(pid_t pid, uintptr_t dst_addr, const void *src, size_t len) {
  if (len == 0) return 0;

  // iovec uses a non-const iov_base, but we don't mutate src.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
  struct iovec local = {.iov_base = (void *)src, .iov_len = len};
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
  struct iovec remote = {.iov_base = (void *)dst_addr, .iov_len = len};
  ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
  if (n == (ssize_t)len) return 0;

  // Fallback to ptrace word writes.
  size_t off = 0;
  while (off < len) {
    long word = 0;
    size_t chunk = sizeof(long);
    if (off + chunk > len) chunk = len - off;

    if (chunk != sizeof(long)) {
      // Read-modify-write for tail.
      errno = 0;
      long old = ptrace(PTRACE_PEEKDATA, pid, (void *)(dst_addr + off), NULL);
      if (old == -1 && errno) return -1;
      memcpy(&word, &old, sizeof(long));
    }
    memcpy(&word, (const uint8_t *)src + off, chunk);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)(dst_addr + off), (void *)word) < 0) return -1;
    off += chunk;
  }
  return 0;
}

// Reads a NUL-terminated string at addr (up to max_len-1), always NUL-terminates dst.
static inline int rsys_read_cstring(pid_t pid, uintptr_t addr, char *dst, size_t max_len) {
  if (max_len == 0) {
    errno = EINVAL;
    return -1;
  }
  size_t off = 0;
  while (off + 1 < max_len) {
    char c;
    if (rsys_read_mem(pid, &c, addr + off, 1) < 0) return -1;
    dst[off++] = c;
    if (c == '\0') return 0;
  }
  dst[max_len - 1] = '\0';
  errno = ENAMETOOLONG;
  return -1;
}
