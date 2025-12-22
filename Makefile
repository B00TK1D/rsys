CC ?= gcc
CPPFLAGS ?= -I. -Isrc
CFLAGS ?= -O2 -g -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
LDFLAGS ?=

BIN = rsys rsysd

RSYS_SRCS := $(wildcard src/rsys/rsys_*.c)
RSYSD_SRCS := $(wildcard src/rsysd/rsysd_*.c)

all: $(BIN)

rsys: rsys.c rsys_protocol.h rsys_tracee_mem.h $(RSYS_SRCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ rsys.c $(RSYS_SRCS) $(LDFLAGS)

rsysd: rsysd.c rsys_protocol.h $(RSYSD_SRCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ rsysd.c $(RSYSD_SRCS) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
