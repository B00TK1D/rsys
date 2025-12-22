#include "src/rsysd/rsysd_internal.h"

int rsysd_handle_request(int cfd, uint16_t type, const uint8_t *p, uint32_t len) {
  vlog("[rsysd] req type=%u (%s) len=%u\n", type, type_name(type), len);

  int rc;
  rc = rsysd_handle_fs(cfd, type, p, len);
  if (rc != 0) return (rc < 0) ? -1 : 0;

  rc = rsysd_handle_net_basic(cfd, type, p, len);
  if (rc != 0) return (rc < 0) ? -1 : 0;

  rc = rsysd_handle_net_msg(cfd, type, p, len);
  if (rc != 0) return (rc < 0) ? -1 : 0;

  rc = rsysd_handle_fcntl_epoll(cfd, type, p, len);
  if (rc != 0) return (rc < 0) ? -1 : 0;

  rc = rsysd_handle_poll(cfd, type, p, len);
  if (rc != 0) return (rc < 0) ? -1 : 0;

  rc = rsysd_handle_misc(cfd, type, p, len);
  if (rc != 0) return (rc < 0) ? -1 : 0;

  errno = ENOSYS;
  return -1;
}

