#pragma once

#define _GNU_SOURCE

#include "rsys_protocol.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int g_verbose;

void die(const char *msg);
void vlog(const char *fmt, ...);
const char *type_name(uint16_t type);

int require_len(uint32_t len, uint32_t need);
int require_blob(uint32_t len, uint32_t off, uint32_t blob_len);

int64_t do_syscall_ret(long nr, long a1, long a2, long a3, long a4, long a5, long a6, int *out_errno);

// Group handlers: return 1 if handled, 0 if not handled, -1 on error.
int rsysd_handle_fs(int cfd, uint16_t type, const uint8_t *p, uint32_t len);
int rsysd_handle_net_basic(int cfd, uint16_t type, const uint8_t *p, uint32_t len);
int rsysd_handle_net_msg(int cfd, uint16_t type, const uint8_t *p, uint32_t len);
int rsysd_handle_fcntl_epoll(int cfd, uint16_t type, const uint8_t *p, uint32_t len);
int rsysd_handle_poll(int cfd, uint16_t type, const uint8_t *p, uint32_t len);
int rsysd_handle_misc(int cfd, uint16_t type, const uint8_t *p, uint32_t len);

int rsysd_handle_request(int cfd, uint16_t type, const uint8_t *p, uint32_t len);

