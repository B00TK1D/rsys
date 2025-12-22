#include "src/rsysd/rsysd_internal.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int rsysd_handle_net_basic(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  struct rsys_resp resp;

  if (type == RSYS_REQ_SOCKET) {
    if (require_len(len, 24) < 0) return -1;
    int64_t domain = rsys_get_s64(p + 0);
    int64_t stype = rsys_get_s64(p + 8);
    int64_t proto = rsys_get_s64(p + 16);
    int err;
    int64_t r = do_syscall_ret(__NR_socket, (long)domain, (long)stype, (long)proto, 0, 0, 0, &err);
    if (g_verbose) {
      if (r >= 0) {
        int so_type = 0;
        socklen_t sl = sizeof(so_type);
        int gs = getsockopt((int)r, SOL_SOCKET, SO_TYPE, &so_type, &sl);
        vlog("[rsysd] socket(domain=%" PRId64 ", type=%" PRId64 ", proto=%" PRId64
             ") -> fd=%" PRId64 " so_type=%d gs_errno=%d\n",
             domain, stype, proto, r, so_type, (gs == 0) ? 0 : errno);
      } else {
        vlog("[rsysd] socket(domain=%" PRId64 ", type=%" PRId64 ", proto=%" PRId64 ") -> %" PRId64 " errno=%d\n", domain, stype,
             proto, r, err);
      }
    }
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_SOCKETPAIR) {
    if (require_len(len, 24) < 0) return -1;
    int64_t domain = rsys_get_s64(p + 0);
    int64_t stype = rsys_get_s64(p + 8);
    int64_t proto = rsys_get_s64(p + 16);
    int sv[2] = {-1, -1};
    int err;
    int64_t r = do_syscall_ret(__NR_socketpair, (long)domain, (long)stype, (long)proto, (long)sv, 0, 0, &err);
    if (r == 0) {
      uint8_t out[sizeof(resp) + 16];
      rsys_resp_set(&resp, r, err, 16);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_s64(out + sizeof(resp) + 0, (int64_t)sv[0]);
      rsys_put_s64(out + sizeof(resp) + 8, (int64_t)sv[1]);
      if (rsys_send_msg(cfd, type, out, (uint32_t)sizeof(out)) < 0) return -1;
      return 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_BIND || type == RSYS_REQ_CONNECT) {
    if (require_len(len, 12) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint32_t addrlen = rsys_get_u32(p + 8);
    if (require_blob(len, 12, addrlen) < 0) return -1;
    const void *addr = addrlen ? (const void *)(p + 12) : NULL;

    int err;
    long nr = (type == RSYS_REQ_BIND) ? __NR_bind : __NR_connect;
    int64_t r = do_syscall_ret(nr, (long)fd, (long)addr, (long)addrlen, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_LISTEN) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t backlog = rsys_get_s64(p + 8);
    int err;
    int64_t r = do_syscall_ret(__NR_listen, (long)fd, (long)backlog, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_ACCEPT || type == RSYS_REQ_ACCEPT4) {
    if (require_len(len, 24) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint32_t want_addr = rsys_get_u32(p + 8);
    uint32_t addr_max = rsys_get_u32(p + 12);
    int64_t flags = rsys_get_s64(p + 16);

    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)addr_max;
    struct sockaddr *sap = want_addr ? (struct sockaddr *)&ss : NULL;
    socklen_t *slenp = want_addr ? &slen : NULL;

    int err;
    int64_t r;
    if (type == RSYS_REQ_ACCEPT4) {
      r = do_syscall_ret(__NR_accept4, (long)fd, (long)sap, (long)slenp, (long)flags, 0, 0, &err);
    } else {
      r = do_syscall_ret(__NR_accept, (long)fd, (long)sap, (long)slenp, 0, 0, 0, &err);
    }

    if (r >= 0 && want_addr) {
      uint32_t out_alen = (uint32_t)slen;
      uint32_t out_len = (uint32_t)sizeof(resp) + 4 + out_alen;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, 4 + out_alen);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp), out_alen);
      if (out_alen) memcpy(out + sizeof(resp) + 4, &ss, out_alen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      return (rc < 0) ? -1 : 1;
    }

    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_SENDTO) {
    if (require_len(len, 24) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t flags = rsys_get_s64(p + 8);
    uint32_t dlen = rsys_get_u32(p + 16);
    uint32_t alen = rsys_get_u32(p + 20);
    if (require_blob(len, 24, dlen + alen) < 0) return -1;
    const uint8_t *data = p + 24;
    const void *addr = (alen ? (const void *)(p + 24 + dlen) : NULL);

    int err;
    int64_t r = do_syscall_ret(__NR_sendto, (long)fd, (long)data, (long)dlen, (long)flags, (long)addr, (long)alen, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_RECVFROM) {
    if (require_len(len, 32) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint64_t maxlen = rsys_get_u64(p + 8);
    int64_t flags = rsys_get_s64(p + 16);
    uint32_t want_addr = rsys_get_u32(p + 24);
    uint32_t addr_max = rsys_get_u32(p + 28);

    if (maxlen > (1u << 20)) maxlen = (1u << 20);
    uint8_t *buf = NULL;
    if (maxlen) {
      buf = (uint8_t *)malloc((size_t)maxlen);
      if (!buf) die("malloc");
    }

    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)addr_max;
    struct sockaddr *sap = want_addr ? (struct sockaddr *)&ss : NULL;
    socklen_t *slenp = want_addr ? &slen : NULL;

    int err;
    int64_t r = do_syscall_ret(__NR_recvfrom, (long)fd, (long)buf, (long)maxlen, (long)flags, (long)sap, (long)slenp, &err);
    if (r >= 0) {
      uint32_t out_dlen = (r > 0) ? (uint32_t)r : 0;
      uint32_t out_alen = want_addr ? (uint32_t)slen : 0;
      uint32_t payload_len = 8 + out_dlen + out_alen;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp) + 0, out_dlen);
      rsys_put_u32(out + sizeof(resp) + 4, out_alen);
      if (out_dlen) memcpy(out + sizeof(resp) + 8, buf, out_dlen);
      if (out_alen) memcpy(out + sizeof(resp) + 8 + out_dlen, &ss, out_alen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(buf);
      return (rc < 0) ? -1 : 1;
    }

    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(buf);
    return (rc < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_SHUTDOWN) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t how = rsys_get_s64(p + 8);
    int err;
    int64_t r = do_syscall_ret(__NR_shutdown, (long)fd, (long)how, 0, 0, 0, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_GETSOCKNAME || type == RSYS_REQ_GETPEERNAME) {
    if (require_len(len, 16) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    uint32_t addr_max = rsys_get_u32(p + 8);

    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)addr_max;
    int err;
    long nr = (type == RSYS_REQ_GETSOCKNAME) ? __NR_getsockname : __NR_getpeername;
    int64_t r = do_syscall_ret(nr, (long)fd, (long)&ss, (long)&slen, 0, 0, 0, &err);
    if (r == 0) {
      uint32_t out_alen = (uint32_t)slen;
      uint32_t payload_len = 4 + out_alen;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp), out_alen);
      if (out_alen) memcpy(out + sizeof(resp) + 4, &ss, out_alen);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      return (rc < 0) ? -1 : 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_SETSOCKOPT) {
    if (require_len(len, 28) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t level = rsys_get_s64(p + 8);
    int64_t optname = rsys_get_s64(p + 16);
    uint32_t optlen = rsys_get_u32(p + 24);
    if (require_blob(len, 28, optlen) < 0) return -1;
    const void *optval = optlen ? (const void *)(p + 28) : NULL;
    int err;
    int64_t r =
        do_syscall_ret(__NR_setsockopt, (long)fd, (long)level, (long)optname, (long)optval, (long)optlen, 0, &err);
    rsys_resp_set(&resp, r, err, 0);
    return (rsys_send_msg(cfd, type, &resp, sizeof(resp)) < 0) ? -1 : 1;
  }

  if (type == RSYS_REQ_GETSOCKOPT) {
    if (require_len(len, 28) < 0) return -1;
    int64_t fd = rsys_get_s64(p + 0);
    int64_t level = rsys_get_s64(p + 8);
    int64_t optname = rsys_get_s64(p + 16);
    uint32_t optlen_max = rsys_get_u32(p + 24);
    if (optlen_max > 64u * 1024u) optlen_max = 64u * 1024u;
    uint8_t *optval = NULL;
    if (optlen_max) {
      optval = (uint8_t *)malloc(optlen_max);
      if (!optval) die("malloc");
    }
    socklen_t olen = (socklen_t)optlen_max;
    int err;
    int64_t r =
        do_syscall_ret(__NR_getsockopt, (long)fd, (long)level, (long)optname, (long)optval, (long)&olen, 0, &err);
    if (r == 0) {
      uint32_t out_lenv = (uint32_t)olen;
      uint32_t payload_len = 4 + out_lenv;
      uint32_t out_len = (uint32_t)sizeof(resp) + payload_len;
      uint8_t *out = (uint8_t *)malloc(out_len);
      if (!out) die("malloc");
      rsys_resp_set(&resp, r, err, payload_len);
      memcpy(out, &resp, sizeof(resp));
      rsys_put_u32(out + sizeof(resp), out_lenv);
      if (out_lenv) memcpy(out + sizeof(resp) + 4, optval, out_lenv);
      int rc = rsys_send_msg(cfd, type, out, out_len);
      free(out);
      free(optval);
      return (rc < 0) ? -1 : 1;
    }
    rsys_resp_set(&resp, r, err, 0);
    int rc = rsys_send_msg(cfd, type, &resp, sizeof(resp));
    free(optval);
    return (rc < 0) ? -1 : 1;
  }

  return 0;
}

