#pragma once

#include "src/rsys/rsys_intercept_ctx.h"

// Returns:
// - 0: not handled (let tracee syscall run locally)
// - 1: handled (syscall rewritten / remote-called; pending set)
// - -1: fatal error (errno set)
int rsys_intercept_dispatch(struct rsys_intercept_ctx *ctx, long nr);

int rsys_intercept_fs(struct rsys_intercept_ctx *ctx, long nr);
int rsys_intercept_io(struct rsys_intercept_ctx *ctx, long nr);
int rsys_intercept_net_basic(struct rsys_intercept_ctx *ctx, long nr);
int rsys_intercept_net_msg(struct rsys_intercept_ctx *ctx, long nr);
int rsys_intercept_fcntl(struct rsys_intercept_ctx *ctx, long nr);
int rsys_intercept_epoll(struct rsys_intercept_ctx *ctx, long nr);
int rsys_intercept_poll(struct rsys_intercept_ctx *ctx, long nr);
int rsys_intercept_misc(struct rsys_intercept_ctx *ctx, long nr);

