# Cross-language notes

`assets/framed_protocol.py` and the reference files use Python for examples, but the
**patterns** are language-independent. This file translates each defensive pattern into
Go, Rust, C, and Node.js, and lists the traps specific to each language's networking API.

Use it when you (or the user) are implementing the protocol in a language other than
Python. The pitfall numbers below refer to `references/pitfalls.md`.

## Table of contents

1. [Read exactly N bytes (pitfalls §2)](#1-read-exactly-n-bytes)
2. [Write all bytes (pitfalls §2)](#2-write-all-bytes)
3. [Big-endian header encode/decode (pitfalls §3)](#3-big-endian-header-encodedecode)
4. [Length-prefixed framing with a bound (pitfalls §1, §4)](#4-length-prefixed-framing-with-a-bound)
5. [Timeouts and deadlines (pitfalls §8)](#5-timeouts-and-deadlines)
6. [Avoiding SIGPIPE / handling broken pipe (pitfalls §7)](#6-avoiding-sigpipe)
7. [Guaranteed cleanup on every path (pitfalls §5)](#7-guaranteed-cleanup)
8. [Backpressure / flow control (pitfalls §9)](#8-backpressure)
9. [Per-language trap list](#9-per-language-trap-list)

---

## 1. Read exactly N bytes

`recv`/`read` returns *up to* N bytes; a return of 0 means the peer closed. Loop until you
have all N, and treat a short final read as a real (truncated-stream) error.

**Go** — use the standard helper, do not write your own:
```go
buf := make([]byte, n)
if _, err := io.ReadFull(conn, buf); err != nil {
    // io.ErrUnexpectedEOF means the stream ended mid-message
    return err
}
```

**Rust**:
```rust
let mut buf = vec![0u8; n];
stream.read_exact(&mut buf)?; // Err(UnexpectedEof) if the stream ends early
```

**C** — there is no helper; the loop is yours to write, and EINTR must be retried:
```c
ssize_t read_exactly(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, (char *)buf + got, n - got, 0);
        if (r == 0) return 0;                 // peer closed (EOF)
        if (r < 0) {
            if (errno == EINTR) continue;     // interrupted: retry
            return -1;                        // real error
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}
```

**Node.js** — you do **not** read N bytes directly. The `'data'` event hands you whatever
arrived (an arbitrary-sized `Buffer`). Accumulate into a buffer and slice out frames as
they complete (see §4). Never assume one `'data'` event equals one message.

---

## 2. Write all bytes

`send`/`write` may accept fewer bytes than offered. Loop from an offset until everything
is gone.

**Go** — `conn.Write` already loops internally and only returns early on error, so a plain
`Write` is sufficient:
```go
if _, err := conn.Write(frame); err != nil {
    return err
}
```

**Rust** — `write_all` loops for you:
```rust
stream.write_all(&frame)?;
```

**C** — loop on the offset; retry EINTR; on a non-blocking socket handle EAGAIN by waiting
for writability:
```c
ssize_t write_all(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, (const char *)buf + sent, n - sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;                        // EAGAIN on non-blocking: poll() then retry
        }
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}
```

**Node.js** — `socket.write(buf)` buffers internally and returns a boolean. `false` means
the internal buffer is full: stop writing and wait for `'drain'` (this is backpressure,
§8). It does not drop data, but ignoring the return value lets memory grow unbounded.

---

## 3. Big-endian header encode/decode

Always serialize multi-byte integers explicitly in network byte order. Never copy a
struct's raw memory onto the wire (padding/endianness/size differ per platform — pitfalls §3).

**Go**:
```go
import "encoding/binary"

var hdr [4]byte
binary.BigEndian.PutUint32(hdr[:], length)
// decode:
length := binary.BigEndian.Uint32(hdr[:])
```

**Rust**:
```rust
let hdr: [u8; 4] = length.to_be_bytes();
// decode:
let length = u32::from_be_bytes(hdr);
// (the `byteorder` crate offers read_u32::<BigEndian> over a Read if you prefer)
```

**C** — convert each field with `htonl`/`htons` (and `ntohl`/`ntohs` on decode); write
fields one at a time, never `write(fd, &struct, sizeof struct)`:
```c
uint32_t net_len = htonl(length);
memcpy(p, &net_len, 4); p += 4;
// decode:
uint32_t length = ntohl(net_len);
```

**Node.js**:
```js
const hdr = Buffer.alloc(4);
hdr.writeUInt32BE(length, 0);
// decode:
const length = buf.readUInt32BE(0);
```

---

## 4. Length-prefixed framing with a bound

Read the fixed header, validate `length <= MAX` **before** allocating, then read exactly
that many payload bytes. This single pattern prevents short-read bugs (§1) and
length-field memory/DoS bugs (§4) at once.

**Go** — clean because `io.ReadFull` does the looping:
```go
func readFrame(r io.Reader) ([]byte, error) {
    var hdr [4]byte
    if _, err := io.ReadFull(r, hdr[:]); err != nil {
        return nil, err
    }
    n := binary.BigEndian.Uint32(hdr[:])
    if n > maxPayload {                      // bound BEFORE allocating
        return nil, fmt.Errorf("frame too large: %d", n)
    }
    payload := make([]byte, n)
    if _, err := io.ReadFull(r, payload); err != nil {
        return nil, err
    }
    return payload, nil
}
```

**Rust** (`tokio`):
```rust
use tokio::io::AsyncReadExt;

let mut hdr = [0u8; 4];
stream.read_exact(&mut hdr).await?;
let n = u32::from_be_bytes(hdr) as usize;
if n > MAX_PAYLOAD {                          // bound BEFORE allocating
    return Err(/* frame too large */);
}
let mut payload = vec![0u8; n];
stream.read_exact(&mut payload).await?;
```
For production, prefer `tokio_util::codec::LengthDelimitedCodec` instead of hand-rolling.

**C** — read header with `read_exactly`, check the bound, then read the body:
```c
unsigned char hdr[4];
if (read_exactly(fd, hdr, 4) <= 0) return -1;
uint32_t n = ntohl(*(uint32_t *)hdr);
if (n > MAX_PAYLOAD) return -1;               // bound BEFORE allocating
unsigned char *payload = malloc(n);
if (!payload) return -1;
if (read_exactly(fd, payload, n) <= 0) { free(payload); return -1; }
```

**Node.js** — accumulate across `'data'` events; emit every complete frame in the buffer:
```js
let acc = Buffer.alloc(0);
socket.on('data', (chunk) => {
  acc = Buffer.concat([acc, chunk]);
  while (acc.length >= 4) {
    const n = acc.readUInt32BE(0);
    if (n > MAX_PAYLOAD) { socket.destroy(); return; } // bound the length
    if (acc.length < 4 + n) break;            // full frame not here yet
    const payload = acc.subarray(4, 4 + n);
    acc = acc.subarray(4 + n);                // keep the remainder
    handleFrame(payload);
  }
});
```
The `while` loop matters: a single `'data'` chunk can contain several frames *and* a
partial one. (See pitfalls §1 for the same bug in every language.)

---

## 5. Timeouts and deadlines

Every blocking network operation needs a timeout, and a whole request needs an overall
deadline (pitfalls §8). Prefer absolute deadlines so retries don't reset the clock.

**Go** — deadlines are absolute and per-connection; set before each blocking call:
```go
conn.SetDeadline(time.Now().Add(30 * time.Second)) // read+write
// or context with a deadline for the whole operation:
ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
defer cancel()
```

**Rust** (`tokio`) — wrap any future:
```rust
use tokio::time::{timeout, Duration};
let frame = timeout(Duration::from_secs(30), read_frame(&mut stream)).await??;
```

**C** — either `setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)`, or pass a timeout to `poll`/`select`
and compute the remaining time against an absolute deadline:
```c
struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
```

**Node.js** — `socket.setTimeout(ms)` fires an `'timeout'` event but does **not** close the
socket; you must `socket.destroy()` yourself in the handler:
```js
socket.setTimeout(30000);
socket.on('timeout', () => socket.destroy(new Error('idle timeout')));
```

---

## 6. Avoiding SIGPIPE

Writing to a peer that has closed its read side raises SIGPIPE, which by default kills the
process (pitfalls §7). On Windows this signal does not exist.

- **Go**: handled for you — a write to a broken connection returns an error, no signal.
- **Rust**: the standard library installs `SIG_IGN` for SIGPIPE at startup; broken writes
  surface as `BrokenPipe` errors. (If you replace the runtime startup, restore that.)
- **C**: pass `MSG_NOSIGNAL` to every `send` (Linux), or set the `SO_NOSIGPIPE` socket
  option (macOS/BSD), or install `signal(SIGPIPE, SIG_IGN)` once at startup and check
  `errno == EPIPE`.
- **Node.js**: no SIGPIPE; a write to a dead socket emits an `'error'` event. Always attach
  an `'error'` listener or an unhandled error will crash the process.

---

## 7. Guaranteed cleanup

Every socket and buffer must be released on **every** exit path, including errors and early
returns (pitfalls §5). Use the language's scope-exit mechanism rather than manual closes.

**Go**:
```go
conn, err := net.Dial("tcp", addr)
if err != nil { return err }
defer conn.Close()   // runs on every return, including panics that are recovered
```

**Rust** — RAII closes the socket when it goes out of scope; usually you write nothing. For
a *graceful* shutdown, do it explicitly before drop:
```rust
use tokio::io::AsyncWriteExt;
stream.shutdown().await?; // sends FIN; the socket still closes on drop regardless
```

**C** — the perennial leak source. Close on every branch; a single `goto cleanup` label is
the conventional fix:
```c
int fd = socket(...);
if (do_thing(fd) < 0) goto cleanup;
/* ... */
cleanup:
    close(fd);
```

**Node.js** — attach `'error'` and `'close'` handlers; call `socket.destroy()` on failure
so the FD and timers are released:
```js
socket.on('error', () => socket.destroy());
socket.on('close', () => { /* clear timers / state here */ });
```

---

## 8. Backpressure

A fast producer must not outrun a slow consumer, or memory grows without bound (pitfalls §9).

- **Go**: backpressure is built into blocking `Write` — it returns only when the data is
  handed to the kernel, so a slow peer naturally slows your sender. With buffered channels
  between goroutines, a bounded channel provides the same effect; an unbounded queue does not.
- **Rust** (`tokio`): `write_all().await` suspends until the data is accepted. Between tasks,
  use a **bounded** `mpsc::channel(capacity)`; `send().await` waits when the channel is full.
- **C**: on a non-blocking socket, `send` returns `EAGAIN` when the send buffer is full —
  that *is* the backpressure signal. Stop reading from your source and re-enable the write
  event; do not spin retrying the send.
- **Node.js**: `socket.write()` returning `false` is the signal — stop and wait for
  `'drain'`. With streams, `readable.pipe(writable)` wires this up automatically. Setting a
  sane `highWaterMark` controls the buffer threshold.

---

## 9. Per-language trap list

**Go**
- `conn.Read` can return `n > 0` **and** a non-nil error in the same call; process the `n`
  bytes before handling the error.
- A goroutine blocked in `Read` is only unblocked by a deadline or a `Close` from elsewhere
  — set deadlines so readers can't hang forever.
- `defer conn.Close()` inside a per-connection function is correct; `defer` in a loop body
  is not — it stacks until the function returns.

**Rust**
- With `tokio`, every read/write/timeout is a future that must be `.await`ed; forgetting the
  `.await` silently does nothing.
- `read_exact` on a closed stream returns `UnexpectedEof` — distinguish "clean close at a
  frame boundary" from "truncated mid-frame" by *where* you were in parsing.
- Use the `LengthDelimitedCodec` / `Framed` machinery instead of byte-level loops where you can.

**C**
- `read`/`write` are not the same as `recv`/`send` for sockets on all platforms; prefer the
  socket calls and always pass the right flags.
- Always retry `EINTR`; always handle `EAGAIN`/`EWOULDBLOCK` on non-blocking sockets;
  always bound any length before `malloc`.
- `*(uint32_t *)ptr` casts assume alignment and host byte order — use `memcpy` into a local
  plus `ntohl`, and never dereference an unaligned wire pointer.

**Node.js**
- The `'data'` event delivers arbitrary chunk boundaries: one event may be half a frame or
  three frames. Buffer-and-slice (§4) is mandatory; this is the single most common Node
  protocol bug.
- Always attach an `'error'` handler to every socket and server, or one network error
  crashes the whole process.
- `setTimeout` and `write()===false` do not act on their own — you must `destroy()` on
  timeout and wait for `'drain'` on backpressure.
- `Buffer.concat` on every chunk is O(n²) for large messages; for high throughput keep a
  list of chunks (or a ring buffer) and join once a full frame is present.

---

Whatever the language: frame explicitly, read fully, write fully, encode big-endian, bound
before you allocate, put a timeout on everything, and release on every path. The syntax
changes; the discipline does not.
