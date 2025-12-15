CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wpointer-arith -Wcast-qual -Wwrite-strings
LDFLAGS ?=

.PHONY: all clean

all: rsysd rsys librsyspreload.so

rsysd: server.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -pthread

rsys: client.o common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

librsyspreload.so: preload.o common.o
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(LDFLAGS) -ldl -pthread

%.o: %.c common.h
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

clean:
	rm -f *.o rsysd rsys librsyspreload.so
