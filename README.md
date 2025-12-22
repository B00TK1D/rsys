# rsys

`rsys` is a remote syscall forwarding client/server for Linux. It runs a program locally under `ptrace` and forwards effect-creating syscalls (file and network I/O, readiness, and a few identity/environment helpers) to a remote `rsysd` over TCP, so the program behaves as if it were running on the remote host.

## Build

Requirements: a Linux x86_64 machine with a C toolchain.

```bash
make
```

This produces two binaries in the repository root:
- `rsys`: client (traces a local program and forwards syscalls)
- `rsysd`: server (executes forwarded syscalls)

## Run

Start the server on the remote host:

```bash
./rsysd 5555
```

Run a program via the client (connects to `rsysd` and execs the program locally):

```bash
./rsys 192.0.2.10 5555 ls -la
```

Enable verbose logging:

```bash
./rsys -v 192.0.2.10 5555 curl https://example.com/
```

Expose a local path at a different path for the traced program (repeatable):

```bash
./rsys -m /home/me/project:/mnt/project 192.0.2.10 5555 ls /mnt/project
```

Client options (see `rsys -h` for the authoritative list):
- `-v, --verbose`: verbose logging
- `-m, --mount SRC:DST`: expose local `SRC` at path `DST`
- `-p PORT|LOCAL:REMOTE`: forward remote listen port to local port
- `-R, --read-only`: block remote filesystem mutations
- `-e`: use local environment for the traced program
- `-E`: use remote environment for the traced program (default)

Server options:
- `-v`: verbose logging

## Project structure

- `rsys.c`, `rsysd.c`: tiny `main()` wrappers.
- `rsys_protocol.h`: wire protocol framing + integer encoding helpers.
- `rsys_tracee_mem.h`: helpers to read/write tracee memory (`process_vm_*` with `ptrace` fallback).
- `src/rsys/`: client implementation modules (ptrace loop, fd mapping, rpc, env/path helpers, etc).
  - `src/rsys/intercept/`: per-domain syscall interception/forwarding code + dispatcher.
- `src/rsysd/`: server implementation modules (dispatch + grouped syscall handlers + server loop).

