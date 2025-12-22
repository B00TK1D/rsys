#include "src/rsysd/rsysd_internal.h"

#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

int rsysd_handle_net_msg(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  struct rsys_resp resp;

  if (type == RSYS_REQ_SENDMSG) {
    if (require_len(len, 32) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t name_len = rsys_get_u32(p + 16);
    uint32_t ctrl_len = rsys_get_u32(p + 20);
    uint32_t data_len = rsys_get_u32(p + 24);
    if (require_blob(len, 32, name_len + ctrl_len + data_len) < 0) return -1;

    const uint8_t *bp = p + 32;
    const void *name = name_len ? (const void *)bp : NULL;
    const void *ctrl = ctrl_len ? (const void *)(bp + name_len) : NULL;
    const void *data = data_len ? (const void *)(bp + name_len + ctrl_len) : NULL;

    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
// syscall(2) does not mutate these input buffers, but the struct fields are non-const.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
    mh.msg_name = (void *)name;
    mh.msg_namelen = (socklen_t)name_len;
    mh.msg_control = (void *)ctrl;
    mh.msg_controllen = (size_t)ctrl_len;
    struct iovec iov;
    if (data_len) {
      iov.iov_base = (void *)data;
      iov.iov_len = (size_t)data_len;
      mh.msg_iov = &iov;
      mh.msg_iovlen = 1;
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    int err;
    int64_t r = do_syscall_ret(__NR_sendmsg, (long)fd, (long)&mh, (long)flags, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_RECVMSG) {
    if (require_len(len, 32) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t name_max = rsys_get_u32(p + 16);
    uint32_t ctrl_max = rsys_get_u32(p + 20);
    uint32_t iovcnt = rsys_get_u32(p + 24);
    if (iovcnt > 128) iovcnt = 128;
    if (require_blob(len, 32, iovcnt * 4) < 0) return -1;

    uint32_t total_max = 0;
    for (uint32_t i = 0; i < iovcnt; i++) {
      uint32_t l = rsys_get_u32(p + 32 + i * 4);
      if (l > (1u << 20) - total_max) l = (1u << 20) - total_max;
      total_max += l;
    }

    uint8_t *dbuf = NULL;
    if (total_max) {
      dbuf = (uint8_t *)malloc(total_max);
      if (!dbuf) die("malloc");
    }
    uint8_t *nbuf = NULL;
    if (name_max) {
      nbuf = (uint8_t *)malloc(name_max);
      if (!nbuf) die("malloc");
    }
    uint8_t *cbuf = NULL;
    if (ctrl_max) {
      cbuf = (uint8_t *)malloc(ctrl_max);
      if (!cbuf) die("malloc");
    }

    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_name = nbuf;
    mh.msg_namelen = (socklen_t)name_max;
    mh.msg_control = cbuf;
    mh.msg_controllen = (size_t)ctrl_max;
    struct iovec iov;
    if (total_max) {
      iov.iov_base = dbuf;
      iov.iov_len = (size_t)total_max;
      mh.msg_iov = &iov;
      mh.msg_iovlen = 1;
    }

    int err;
    int64_t r = do_syscall_ret(__NR_recvmsg, (long)fd, (long)&mh, (long)flags, 0, 0, 0, &err);
    if (g_verbose && r < 0) {
      int so_type = 0;
      socklen_t sl = sizeof(so_type);
      int gs = getsockopt((int)fd, SOL_SOCKET, SO_TYPE, &so_type, &sl);
      vlog("[rsysd] recvmsg(fd=%" PRId64 ", flags=0x%" PRIx64 ") -> %" PRId64 " errno=%d so_type=%d gs_errno=%d\n", fd,
           (uint64_t)flags, r, err, so_type, (gs == 0) ? 0 : errno);
    }
    if (r >= 0) {
      // recvmsg() can return a length larger than the provided buffer when MSG_TRUNC
      // is used (common with netlink MSG_PEEK|MSG_TRUNC). Only copy what we actually
      // received into our buffer (total_max), but keep the original return value.
      uint32_t out_dlen = (r > 0) ? (uint32_t)r : 0;
      if (out_dlen > total_max) out_dlen = total_max;
      uint32_t out_nlen = (uint32_t)mh.msg_namelen;
      if (out_nlen > name_max) out_nlen = name_max;
      uint32_t out_clen = (uint32_t)mh.msg_controllen;
      if (out_clen > ctrl_max) out_clen = ctrl_max;
      uint32_t out_mflags = (uint32_t)mh.msg_flags;
      uint32_t payload_len = 16 + out_dlen + out_nlen + out_clen;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp) + 0, out_dlen);
      rsys_put_u32(out + sizeof(resp) + 4, out_nlen);
      rsys_put_u32(out + sizeof(resp) + 8, out_clen);
      rsys_put_u32(out + sizeof(resp) + 12, out_mflags);
      uint8_t *wp = out + sizeof(resp) + 16;
      if (out_dlen) memcpy(wp, dbuf, out_dlen), wp += out_dlen;
      if (out_nlen) memcpy(wp, nbuf, out_nlen), wp += out_nlen;
      if (out_clen) memcpy(wp, cbuf, out_clen), wp += out_clen;
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(dbuf);
      free(nbuf);
      free(cbuf);
      return (rc < 0) ? -1 : 1;
    }

    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(dbuf);
    free(nbuf);
    free(cbuf);
    return (rc < 0) ? -1 : 1;
  }

  return 0;
}

