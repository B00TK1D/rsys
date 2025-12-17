CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
LDFLAGS ?=

BIN = rsys rsysd

all: $(BIN)

rsys: rsys.c rsys_protocol.h rsys_tracee_mem.h
	$(CC) $(CFLAGS) -o $@ rsys.c $(LDFLAGS)

rsysd: rsysd.c rsys_protocol.h
	$(CC) $(CFLAGS) -o $@ rsysd.c $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
