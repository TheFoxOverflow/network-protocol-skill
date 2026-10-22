# Transport & I/O patterns

The socket/OS layer. These are the correct mechanics that the rules in SKILL.md and the
bugs in `references/pitfalls.md` refer to. Examples are Python/pseudocode;
`assets/cross-language-notes.md` maps them to Go/Rust/C/Node, and
`assets/framed_protocol.py` is a complete runnable version.

## Table of contents

1. [The two essential loops: read_exactly and write_all](#1-the-two-essential-loops)
2. [Connection lifecycle (client & server)](#2-connection-lifecycle)
3. [Blocking vs non-blocking vs async](#3-blocking-vs-non-blocking-vs-async)
4. [Event loops: select/poll/epoll/kqueue](#4-event-loops)
5. [Timeouts and deadlines](#5-timeouts-and-deadlines)
6. [Graceful shutdown](#6-graceful-shutdown)
7. [TCP tuning](#7-tcp-tuning)
8. [UDP specifics](#8-udp-specifics)
9. [Concurrency models](#9-concurrency-models)
10. [Resource management](#10-resource-management)
11. [Platform differences](#11-platform-differences)
12. [IPv6, dual-stack, and name resolution](#12-ipv6-dual-stack-and-name-resolution)

---

## 1. The two essential loops

Because `recv` returns *up to* N bytes (0 = EOF) and `send` may take fewer than offered,
**every** stream protocol needs these two helpers (pitfalls §2).

```python
def read_exactly(sock, n):
    """Read exactly n bytes or raise. b"" from recv means the peer closed (EOF)."""
    chunks, remaining = [], n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("peer closed mid-message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def write_all(sock, data):
    """Write all bytes, looping over short writes. (Python: sock.sendall does this.)"""
    view, total = memoryview(data), 0
    while total < len(data):
        sent = sock.send(view[total:])
        if sent == 0:
            raise ConnectionError("connection broken (send returned 0)")
        total += sent
```

For non-blocking/async sockets you don't loop synchronously — instead you keep a buffer and
resume when the OS signals readiness (§3–4), but the same "up to N / fewer than offered"
truths hold. The incremental parser in `assets/framed_protocol.py` is written so the *same*
parsing code works for blocking and async.

## 2. Connection lifecycle

**Server:**
```python
ls = socket.socket(AF_INET, SOCK_STREAM)
ls.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)   # rebind through TIME_WAIT (pitfalls §5.3)
ls.bind((host, port))
ls.listen(backlog)
while running:
    try:
        conn, addr = ls.accept()
    except OSError as e:
        if e.errno in (EMFILE, ENFILE):      # fd exhaustion: back off, don't spin
            time.sleep(0.05); continue
        if e.errno in (ECONNABORTED, EINTR):
            continue                         # transient; keep the loop alive
        raise
    handle_in_new_task(conn)                 # never block the accept loop (pitfalls §6.1)
```

**Client:**
```python
sock = socket.socket(AF_INET, SOCK_STREAM)
sock.settimeout(connect_timeout)            # connect needs its own timeout (pitfalls §8.1)
sock.connect((host, port))                  # may need retry-with-backoff at startup (§5.5)
sock.settimeout(io_timeout)
```

Set `TCP_NODELAY` for latency-sensitive request/response (pitfalls §7.3), and a per-call
or deadline-based timeout for all subsequent I/O.

## 3. Blocking vs non-blocking vs async

- **Blocking + a thread/goroutine per connection:** simplest to reason about; each
  connection's read/write loop blocks independently. Scales to thousands of connections
  with goroutines (Go) or OS threads (heavier). Use `read_exactly`/`write_all` directly.
- **Non-blocking + event loop:** one thread multiplexes many sockets via select/poll/epoll.
  Calls return immediately; `EAGAIN`/`EWOULDBLOCK` means "not ready, try later" — **not** an
  error (pitfalls §6.2). You maintain per-connection read/write buffers and parser state.
- **Async runtime** (asyncio, tokio, Node, Go's runtime): the runtime hides the event loop;
  you write near-sequential code with `await`. Backpressure is expressed through the API
  (await the write/`drain`).

Rule: **never do a blocking call on the event-loop thread** (I/O, DNS, `connect`, disk).
Offload to a thread pool or use the async variant.

## 4. Event loops

- **`select`:** portable but limited by `FD_SETSIZE` (~1024) and O(n) scans. Avoid for many
  connections (pitfalls §6.4).
- **`poll`:** no fd-count limit; still O(n). Fine for moderate counts.
- **`epoll` (Linux) / `kqueue` (BSD/macOS) / IOCP (Windows):** scalable to many thousands of
  connections.
- **Level-triggered (default, recommended):** you're notified while a socket is ready;
  forgiving.
- **Edge-triggered (`EPOLLET`):** notified only on a readiness *transition* — you **must**
  drain `recv`/`send` until `EAGAIN`, or you'll stall (pitfalls §6.3).
- **Writability:** only register for "writable" when you have queued outbound data, and
  unregister when the queue drains — otherwise the loop spins at 100% CPU.

## 5. Timeouts and deadlines

Three distinct knobs (pitfalls §8.1, §8.4):
- **Connect timeout:** bound how long `connect` waits.
- **Per-read idle timeout:** if no bytes arrive within T, the peer is likely dead.
- **Total operation deadline:** bound the whole request/response, independent of per-read
  timeouts (otherwise many small reads each under the idle timeout can run forever).

Mechanisms: socket `SO_RCVTIMEO`/`SO_SNDTIMEO` or `settimeout`; an event loop's timer; an
async `deadline`/`timeout` wrapper. On timeout, fail the operation and clean up the
connection. Coordinate the idle timeout with the heartbeat interval (idle ≈ 2–3× heartbeat).

## 6. Graceful shutdown

To avoid losing the final bytes (pitfalls §5.2):

```python
def graceful_close(sock):
    try:
        sock.shutdown(socket.SHUT_WR)   # send FIN: "I'm done writing"
        # optionally drain remaining inbound until EOF so the peer can finish:
        sock.settimeout(drain_timeout)
        while sock.recv(4096):
            pass
    except OSError:
        pass
    finally:
        sock.close()                    # always close, even on error paths (rule 10)
```

Avoid `SO_LINGER` with timeout 0 unless you intend an abortive reset (RST). Decide and
document who closes first (that side pays the `TIME_WAIT`, pitfalls §5.3).

## 7. TCP tuning

- **`TCP_NODELAY`:** disable Nagle for latency-sensitive small messages (pitfalls §7.3).
  Leave Nagle on for bulk throughput. Best of all: send each message in one `write`.
- **`SO_KEEPALIVE` + `TCP_KEEPIDLE`/`KEEPINTVL`/`KEEPCNT`:** OS-level dead-peer detection;
  defaults are often hours, so tune them or use app heartbeats (pitfalls §5.1).
- **`SO_REUSEADDR`:** servers, to rebind through `TIME_WAIT`. **`SO_REUSEPORT`:** to spread
  accepts across processes (different purpose).
- **`SO_RCVBUF`/`SO_SNDBUF`:** socket buffer sizes; the OS usually auto-tunes — change only
  with evidence.
- **`SO_NOSIGPIPE` (macOS/BSD)** or `MSG_NOSIGNAL` per send (Linux): avoid `SIGPIPE`
  (pitfalls §7.1).

## 8. UDP specifics

```python
us = socket.socket(AF_INET, SOCK_DGRAM)
us.bind((host, port))
data, peer = us.recvfrom(65535)          # one call = one datagram (boundaries preserved)
```
- Size the receive buffer for the **maximum** datagram (up to 65507 bytes IPv4) or you'll
  truncate (pitfalls §11.2); check `MSG_TRUNC`.
- Keep sent datagrams ≲1200 bytes to avoid fragmentation on the public internet (pitfalls
  §11.3).
- `connect()` on a UDP socket sets a default peer and enables receiving ICMP errors and
  source filtering — it does not create a connection.
- Track peers yourself; UDP is connectionless (pitfalls §11.5).
- Don't reply larger than the request to unverified sources (amplification, pitfalls §11.4).

## 9. Concurrency models

- **Thread/goroutine per connection:** each connection owned by one task; blocking loops are
  fine. Simple; watch total thread count with OS threads.
- **Single-threaded event loop:** one thread, many sockets; no per-connection locking needed
  but one slow handler blocks all — keep handlers non-blocking.
- **Worker pool / sharded loops:** N event loops across cores, each owning a subset of
  connections.
- **Never share one socket across threads without synchronization** (pitfalls §6.6): give
  each socket a single owner, or serialize writes through a queue/lock. Keep per-connection
  parser state owned by exactly one task.

## 10. Resource management

- **Close every fd on every path** — success, error, exception (rule 10). Use RAII
  (C++/Rust), `defer` (Go), `with`/context managers (Python), try/finally.
- **Bound everything the peer can grow:** receive buffer, outbound queue, number of
  concurrent connections, in-flight requests (pitfalls §9). A peer must not be able to make
  you allocate without limit.
- **Watch the fd limit** (`ulimit -n`): under load you can hit `EMFILE`; back off and shed,
  don't crash (pitfalls §5.5).
- **Set `O_CLOEXEC`/`SOCK_CLOEXEC`** so child processes don't inherit your sockets
  (pitfalls §7.4).

## 11. Platform differences

- **Errors:** POSIX uses `errno`/`EAGAIN`/`EWOULDBLOCK`/`EINTR`/`EPIPE`; **Windows/Winsock**
  uses `WSAGetLastError`/`WSAEWOULDBLOCK` and requires `WSAStartup`. Don't hard-code POSIX
  constants on Windows.
- **Signals:** `SIGPIPE`/`EINTR` are POSIX concepts; Windows has neither.
- **Readiness APIs:** epoll (Linux), kqueue (BSD/macOS), IOCP/completion-based (Windows).
  IOCP is *completion*-based (the OS tells you an op finished), not *readiness*-based.
- **Recommendation:** use a cross-platform async runtime/library (tokio, asyncio, libuv,
  Boost.Asio, Go runtime) rather than coding to one OS's primitives, unless you have a
  specific reason.

## 12. IPv6, dual-stack, and name resolution

A protocol that only works over IPv4 is incomplete in 2026; a client that assumes one
address per hostname hangs on real networks. The rules:

- **Never assume an address family.** Resolve with `getaddrinfo` (Python:
  `socket.getaddrinfo`; Go: the resolver inside `net.Dial`; C: `getaddrinfo(3)`) and
  iterate over *all* returned addresses — v6 and v4 — attempting connections until one
  succeeds. A hostname commonly resolves to several addresses, and the first may be
  unreachable while the rest are fine; connecting only to the first is a classic
  "works for me" bug. Python's `socket.create_connection` and Go's `net.Dial` already do
  this iteration for you.
- **Servers: bind dual-stack deliberately.** An `AF_INET6` socket bound to `::` can accept
  both v6 and v4 clients (v4 arrives as v4-mapped `::ffff:a.b.c.d` addresses), controlled
  by the `IPV6_V6ONLY` socket option — whose *default differs by OS* (Linux usually off =
  dual-stack; Windows and some BSDs on = v6-only). Set it explicitly rather than
  inheriting the platform default, or bind two sockets (one per family) for full control.
- **Normalize peer addresses before comparing or rate-limiting.** The same v4 client can
  appear as `1.2.3.4` on a v4 socket and `::ffff:1.2.3.4` on a dual-stack socket. If you
  key per-IP limits, logs, or ACLs on the raw string (as the reference server's per-IP cap
  does), map v4-mapped v6 addresses back to plain v4 first — otherwise limits silently
  split across two keys.
- **Don't parse or store addresses in v4-shaped fields.** Wire formats, logs, and configs
  need to hold both `a.b.c.d` and full v6 forms (and v6 literals in URLs need brackets:
  `[2001:db8::1]:9000`). Reserving 4 bytes for "the IP" is a versioning trap (design §5).
- **Connect concurrently when latency matters ("happy eyeballs").** Broken or slow IPv6
  paths exist; serial v6-then-v4 attempts add seconds. The Happy Eyeballs approach (RFC
  8305) races v6 with a slightly delayed v4 attempt and keeps whichever wins — browsers
  and modern runtimes do this; long-lived clients with strict connect budgets should too,
  or at least keep per-attempt connect timeouts short so fallback is fast (§5).
- **Test both families.** Loopback tests on `127.0.0.1` alone never exercise the v6 path;
  run the suite against `::1` too, and against a hostname that resolves to both. The MTU
  differs as well (v6 minimum is 1280 bytes, and there is no on-path fragmentation), which
  is one more reason for the ≲1200-byte UDP guidance (pitfalls §11.3).
