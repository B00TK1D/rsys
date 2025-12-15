## rsys

`rsys` is a remote-syscall preload shim + server.

A target program runs with `LD_PRELOAD=./librsyspreload.so`; selected filesystem and networking syscalls are **executed on the server** over a TCP control connection.

### Build

```bash
make
```

### Run

Start the syscall server (listens on a TCP port):

```bash
./rsysd 5555
```

Run a program with remote syscalls enabled:

```bash
./rsys 127.0.0.1 5555 cat /etc/hostname
```

The server address is passed via environment variables:

- `RSYS_SERVER`: server IP (numeric IPv4/IPv6 literal)
- `RSYS_PORT`: server port
- `RSYS_DEBUG=1`: prints connection/RPC failures to stderr

### Implemented remote operations

- **Filesystem**: `open`, `openat`, `close`, `read`, `write`, `pread`, `pwrite`, `lseek`, `stat`, `lstat`, `fstat`, `fstatat`, `mkdir`, `mkdirat`, `chdir`, `fchdir`
- **Networking**: `socket`, `connect`, `bind`, `send`, `recv`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`, `getsockname`, `getpeername`, `getsockopt`, `setsockopt`
- **FD management**: `dup`

### Notes

- Only file descriptors created by the preload shim are treated as remote; existing process FDs (stdin/stdout/stderr, etc.) continue to behave locally.
- The client/server must run on compatible Linux ABIs for `struct stat` (this project currently ships the native `struct stat` bytes over the wire).
- `rsysd` supports `RSYS_TRACE=1` for debugging RPC operations.
