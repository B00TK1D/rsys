#include "src/rsys/intercept/rsys_intercept_dispatch.h"

int rsys_intercept_dispatch(struct rsys_intercept_ctx *ctx, long nr) {
  int rc;

  // Keep the same rough ordering as the original monolithic intercept function:
  // fs cwd/path semantics first, then fd lifecycle, then io, misc identity, net, fcntl/dup, epoll, poll.
  rc = rsys_intercept_fs(ctx, nr);
  if (rc) return rc;

  rc = rsys_intercept_io(ctx, nr);
  if (rc) return rc;

  rc = rsys_intercept_misc(ctx, nr);
  if (rc) return rc;

  rc = rsys_intercept_net_basic(ctx, nr);
  if (rc) return rc;

  rc = rsys_intercept_net_msg(ctx, nr);
  if (rc) return rc;

  rc = rsys_intercept_fcntl(ctx, nr);
  if (rc) return rc;

  rc = rsys_intercept_epoll(ctx, nr);
  if (rc) return rc;

  rc = rsys_intercept_poll(ctx, nr);
  if (rc) return rc;

  return 0;
}

