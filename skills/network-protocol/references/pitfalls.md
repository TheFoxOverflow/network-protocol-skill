# Network programming pitfalls — the bug catalog

This is the concrete catalog of bugs that actually bite in network code. Each entry has:
**Symptom** (how it shows up, usually intermittently), **Cause**, **Wrong vs Right**, and
**Catch it** (how to test/detect). Consult this while writing or reviewing any
byte-handling code.

Examples are in Python or language-neutral pseudocode; see
`assets/cross-language-notes.md` for Go/Rust/C/Node equivalents of the patterns.

## Table of contents

1. [Framing & message boundaries](#1-framing--message-boundaries)
2. [Partial I/O (short reads and writes)](#2-partial-io-short-reads-and-writes)
3. [Byte order & encoding](#3-byte-order--encoding)
4. [Length fields & memory safety](#4-length-fields--memory-safety)
5. [Connection lifecycle](#5-connection-lifecycle)
6. [Blocking, non-blocking & concurrency](#6-blocking-non-blocking--concurrency)
7. [OS & signal gotchas](#7-os--signal-gotchas)
8. [Timeouts, retries & idempotency](#8-timeouts-retries--idempotency)
9. [Buffering, flow control & backpressure](#9-buffering-flow-control--backpressure)
10. [State machine & protocol logic](#10-state-machine--protocol-logic)
11. [UDP-specific](#11-udp-specific)
12. [Versioning & evolution](#12-versioning--evolution)

---

## 1. Framing & message boundaries

### 1.1 Assuming one `recv` returns exactly one message
**Symptom:** Works in testing and on localhost; in production two messages arrive glued
together, or one message arrives split across two reads and is parsed as garbage.
**Cause:** TCP is a byte stream. The OS coalesces or splits writes freely; `send`
boundaries are not preserved. There is no such thing as "a message" at the TCP layer.

```python
# WRONG — treats each recv as a complete message
data = sock.recv(4096)
msg = parse(data)          # breaks the moment two messages coalesce or one splits
```
```python
# RIGHT — frame messages (length prefix) and extract complete ones from a buffer
buffer.extend(sock.recv(4096))
while len(buffer) >= HEADER_LEN:
    length = int.from_bytes(buffer[:4], "big")
    if length > MAX_PAYLOAD:                 # rule 4: bound before trusting
        raise ProtocolError("frame too large")
    if len(buffer) < HEADER_LEN + length:
        break                                # incomplete; wait for more bytes
    msg = parse(buffer[HEADER_LEN:HEADER_LEN + length])
    del buffer[:HEADER_LEN + length]
    handle(msg)
```
**Catch it:** Feed the parser two messages concatenated in one buffer, and one message
split byte-by-byte across many feeds. Both must yield exactly the right messages. See
`references/testing.md`.

### 1.2 Delimiter framing without escaping
**Symptom:** A payload that happens to contain the delimiter (e.g. `\n` or `\0`) splits a
message in two, or lets an attacker inject a fake boundary.
**Cause:** Using a delimiter byte for framing but allowing that byte in the payload.
**Right:** Either use length-prefix framing (no escaping needed), or byte-stuff/escape the
delimiter (e.g. COBS, or `\` escaping), or restrict the payload to an alphabet that
excludes the delimiter (e.g. base64 for binary in a line protocol). Decide explicitly.
**Catch it:** Fuzz with payloads full of the delimiter byte.

### 1.3 Reading a fixed-size header without looping
**Symptom:** Rare malformed-header errors under load or over WAN.
**Cause:** `recv(HEADER_LEN)` can return fewer than `HEADER_LEN` bytes (see §2).
**Right:** Use a `read_exactly(n)` loop (§2.1) for the header, then for the body.

### 1.4 Mixing line-based text framing with binary payloads
**Symptom:** Binary bodies containing `\r`/`\n` corrupt the line parser.
**Cause:** Reusing a text/line reader for binary data.
**Right:** Use a length-prefixed binary frame, or encode the binary (base64) inside the
text protocol. Don't read binary with `readline`.

---

## 2. Partial I/O (short reads and writes)

### 2.1 Short reads — `recv` returns fewer bytes than requested
**Symptom:** Truncated messages, "missing tail", parse errors that vanish on retry.
**Cause:** `recv(n)` returns *up to* `n` bytes — whatever is available now. `0`/empty means
the peer closed (EOF).

```python
# WRONG
header = sock.recv(HEADER_LEN)          # may return 1..HEADER_LEN bytes, or b""
```
```python
# RIGHT
def read_exactly(sock, n):
    chunks, remaining = [], n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:                    # b"" => peer closed mid-message
            raise ConnectionError("peer closed before sending all expected bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
```
**Catch it:** A fake socket whose `recv` returns 1 byte per call must not break anything.

### 2.2 Short writes — `send` accepts fewer bytes than offered
**Symptom:** Occasional corruption, only with large messages or slow/congested peers.
**Cause:** `send(buf)` may transmit fewer than `len(buf)` bytes (kernel send buffer full).
The return value is how many it took.

```python
# WRONG
sock.send(data)                          # silently drops the tail when buffer is full
```
```python
# RIGHT
def write_all(sock, data):
    view, total = memoryview(data), 0
    while total < len(data):
        sent = sock.send(view[total:])
        if sent == 0:
            raise ConnectionError("connection broken (send returned 0)")
        total += sent
# (Python's sock.sendall does exactly this — prefer it. Go: use io.Copy / a full-write
#  loop; many languages' bare write() share this footgun.)
```
**Catch it:** A fake socket whose `send` accepts 1 byte per call must still deliver
everything; assert the receiver sees the full message.

### 2.3 Treating EOF as "no data yet" → busy loop or hang
**Symptom:** 100% CPU spin, or a hang, after the peer disconnects.
**Cause:** Not distinguishing `recv() == 0` (orderly close, EOF) from "nothing available".
On a **blocking** socket, `b""` means EOF — stop. On a **non-blocking** socket, "nothing
available" is signaled by `EAGAIN`/`EWOULDBLOCK` (an exception or error), *not* by `b""`.
**Right:** On EOF, finish/close. On `EAGAIN`, wait for readability (select/poll) — don't
spin.

---

## 3. Byte order & encoding

### 3.1 Endianness
**Symptom:** Integers are correct between two same-architecture machines, wrong (byte-
swapped) when a different-endian or differently-compiled peer connects.
**Cause:** Writing integers in host byte order. Hosts differ; the wire must not.
**Right:** Always serialize multi-byte integers in a fixed byte order — big-endian is the
network convention. `int.to_bytes(4, "big")` / `htonl` / `binary.BigEndian` /
`u32::to_be_bytes`. Document it in the spec.
**Catch it:** Golden hex vectors in tests (e.g. the integer `1` must serialize to
`00 00 00 01`), checked on every CI run.

### 3.2 Dumping a struct straight to the wire (padding & layout)
**Symptom:** Field offsets disagree between compilers, architectures, or language
implementations; subtle corruption.
**Cause:** `memcpy(&struct, buf, sizeof struct)` — compilers insert alignment padding and
choose endianness; `sizeof` and layout are **not** portable or stable.
**Right:** Serialize field by field with explicit widths and byte order. Never rely on
`sizeof` of a struct for a wire size. In C use `__attribute__((packed))` only as a last
resort and still fix endianness; in general, write an explicit encode/decode.

### 3.3 Fixed-width vs native integer types
**Symptom:** A field that's 4 bytes on one platform is 8 on another (`long`), shifting
every subsequent field.
**Cause:** Using native types (`int`, `long`, `size_t`) for wire fields.
**Right:** Use explicit-width types for everything on the wire (`uint32_t`, `int64`,
`u16`). Decide signedness explicitly (a length should be unsigned).

### 3.4 Text encoding and embedded NULs
**Symptom:** Mojibake, truncation at a `\0`, or a parser crash on non-UTF-8 input.
**Cause:** Assuming ASCII, assuming NUL-terminated strings, or not validating UTF-8.
**Right:** Specify the encoding (UTF-8). Length-prefix strings rather than NUL-terminating
(payloads may contain `\0`). **Validate** that decoded text is well-formed before use;
reject or replace invalid sequences per a documented rule.

### 3.5 Floating point and "just send the bytes"
**Symptom:** NaN/precision/representation mismatches across languages.
**Cause:** Ad-hoc float serialization.
**Right:** Use IEEE-754 with a defined byte order (e.g. pack as big-endian `double`), or
avoid floats on the wire (send scaled integers / decimal strings) when exactness matters.

---

## 4. Length fields & memory safety

### 4.1 Trusting a length field → unbounded allocation (DoS)
**Symptom:** A single crafted packet causes a multi-gigabyte allocation and OOM/crash.
**Cause:** Reading a length from the wire and allocating/awaiting that many bytes without
a bound. This is a trivial denial-of-service.

```python
# WRONG
length = read_u32(sock)
buf = bytearray(length)                  # attacker sends 0xFFFFFFFF → 4 GiB allocation
```
```python
# RIGHT
length = read_u32(sock)
if length > MAX_PAYLOAD:                  # documented hard cap, e.g. 8 MiB
    raise ProtocolError(f"length {length} exceeds max {MAX_PAYLOAD}")
buf = read_exactly(sock, length)
```
**Catch it:** Send a frame whose length field is huge but with no body; assert the server
rejects it promptly without allocating.

### 4.2 Integer overflow computing total size
**Symptom:** Buffer smaller than expected; out-of-bounds write (memory-unsafe languages)
or silent truncation.
**Cause:** `header_len + payload_len` overflows a fixed-width integer, wrapping to a small
value.
**Right:** Bound `payload_len` to `MAX_PAYLOAD` *before* any arithmetic, and/or use
checked/widening arithmetic. Validate offsets and counts against the actual buffer size.

### 4.3 Off-by-one and self-referential lengths
**Symptom:** Every message is shifted by N bytes; or the length seems "almost right".
**Cause:** Ambiguity about what the length covers: payload only? header+payload? does it
include the length field itself?
**Right:** Define it once, unambiguously, in the spec ("`length` = number of payload bytes
following the 12-byte header, not including the header"). Encode and decode to that exact
definition; add a golden vector that pins it.

### 4.4 Allocating before validating
**Symptom:** Memory pressure from malformed inputs even when they're ultimately rejected.
**Cause:** Reserving buffers/objects based on attacker-controlled counts before checking
them.
**Right:** Validate type, version, length, and counts first; allocate only after the
values pass bounds checks. Prefer streaming over buffering when payloads can be large.

---

## 5. Connection lifecycle

### 5.1 Half-open connections go undetected
**Symptom:** A "connected" socket that never delivers data and never errors — peer was
unplugged, NAT timed out, or the host crashed without sending `FIN`.
**Cause:** TCP gives no timely notification when the peer silently disappears; a socket
with no traffic can sit forever.
**Right:** Add an application-level heartbeat (ping/pong) with an idle timeout, and/or
enable TCP keepalive (`SO_KEEPALIVE` plus tuned `TCP_KEEPIDLE`/`KEEPINTVL`/`KEEPCNT` —
defaults are often hours). App-level heartbeats are the only portable, timely mechanism.
**Catch it:** In a test, pause the peer process (`SIGSTOP`) or drop its packets with a
firewall rule; assert the idle timeout fires.

### 5.2 `close()` vs `shutdown()` — losing buffered data
**Symptom:** The last message before closing is sometimes lost.
**Cause:** `close()` may discard unsent/unacked data depending on `SO_LINGER`, and abruptly
tears down.
**Right:** For a graceful close: `shutdown(SHUT_WR)` to signal "no more writes" (sends
`FIN`), keep reading until you get EOF (so the peer can finish), then `close()`. Don't set
`SO_LINGER` to 0 unless you intentionally want an abortive RST.

### 5.3 `TIME_WAIT` and "Address already in use" on restart
**Symptom:** A server can't rebind its port for a minute or two after restarting; or
`bind` fails with `EADDRINUSE`.
**Cause:** The side that closes first enters `TIME_WAIT` (2×MSL) to absorb stray packets.
**Right:** Set `SO_REUSEADDR` on the listening socket before `bind` (standard for servers).
Understand `SO_REUSEPORT` (load-balancing across processes) separately. Don't "fix"
`TIME_WAIT` by lowering MSL globally.

### 5.4 Detecting disconnect only on write
**Symptom:** You learn the peer is gone only when you try to send (and get `EPIPE`/`RST`),
not while you're waiting to read.
**Cause:** A blocked `read` won't necessarily wake on peer loss (see §5.1).
**Right:** Combine read timeouts/heartbeats with proper write-error handling; don't rely on
either alone.

### 5.5 Accept loop and listener bring-up races
**Symptom:** Client gets connection refused at startup; server crashes when `accept`
returns an error.
**Cause:** Client connecting before the server `listen`s; or treating a transient `accept`
error (`ECONNABORTED`, `EMFILE`) as fatal.
**Right:** Sequence startup (or have the client retry connect with backoff). In the accept
loop, handle per-connection errors without killing the loop; on `EMFILE` (fd exhaustion)
back off rather than spin.

---

## 6. Blocking, non-blocking & concurrency

### 6.1 A blocking call stalls the whole event loop
**Symptom:** One slow peer freezes all connections.
**Cause:** A blocking `recv`/`send`/DNS/`connect` on a single-threaded event loop.
**Right:** Use non-blocking sockets with select/poll/epoll/kqueue (or async runtime), or a
thread/goroutine per connection. Never do blocking I/O on the event-loop thread.

### 6.2 `EAGAIN`/`EWOULDBLOCK` treated as a fatal error
**Symptom:** Non-blocking connections randomly drop under load.
**Cause:** On a non-blocking socket, "would block" is normal, not an error.
**Right:** On `EAGAIN`/`EWOULDBLOCK`, register for readability/writability and try again
later. Only real errors should tear down the connection.

### 6.3 Edge-triggered epoll/kqueue not drained
**Symptom:** Connections "stick" — data sits unread until more arrives.
**Cause:** Edge-triggered notification fires once per readiness transition; if you don't
read until `EAGAIN`, you miss the rest.
**Right:** With edge-triggered mode, loop `recv`/`send` until `EAGAIN`. (Level-triggered is
more forgiving — prefer it unless you need ET.) Only register for *writability* when you
actually have queued data, and unregister when the queue drains, or you'll spin.

### 6.4 `select` and `FD_SETSIZE`
**Symptom:** Corruption or crashes once fd numbers exceed ~1024.
**Cause:** `select`'s fd_set is fixed-size (often 1024).
**Right:** Use `poll`/`epoll`/`kqueue` for many connections.

### 6.5 Write–write deadlock
**Symptom:** Both peers hang, each blocked in `send`, with full buffers.
**Cause:** Both sides write a lot without reading; both kernel send buffers and the peers'
receive buffers fill; both `send` calls block forever. A classic, easy to hit in
request/response code that doesn't drain.
**Right:** Always read concurrently with writing (separate read loop, non-blocking I/O, or
async). Apply flow control. Don't design a protocol where both sides bulk-send before
either reads.

### 6.6 Sharing one socket across threads without synchronization
**Symptom:** Interleaved/corrupted frames; race conditions.
**Cause:** Two threads `send` on the same socket and their byte streams interleave; or
shared parser state is mutated concurrently.
**Right:** Give each socket a single owning task, or serialize writes through a lock/queue.
Keep per-connection parser state owned by one thread. Run a race detector (§testing).

### 6.7 Reentrancy in callbacks
**Symptom:** State corruption when a message handler triggers another send/parse that
re-enters the parser.
**Cause:** Mutating buffer/state while iterating it inside a callback.
**Right:** Fully extract a complete message from the buffer before calling its handler;
don't let handlers mutate the in-progress parse buffer.

---

## 7. OS & signal gotchas

### 7.1 `SIGPIPE` kills the process on write to a closed socket
**Symptom:** The process silently dies the instant a client disconnects mid-write (Unix).
**Cause:** Writing to a socket whose peer closed its read end raises `SIGPIPE`, whose
default action is to terminate the process.
**Right:** Ignore it once at startup (`signal(SIGPIPE, SIG_IGN)`), or pass `MSG_NOSIGNAL`
to each `send` (Linux), or set `SO_NOSIGPIPE` (macOS/BSD). Then handle the resulting
`EPIPE`/`BrokenPipeError` normally. (Python ignores SIGPIPE by default and raises
`BrokenPipeError`; Go ignores it for you. C does not — you must.)

### 7.2 `EINTR` — interrupted system calls
**Symptom:** Random failures correlated with signals (e.g. `SIGCHLD`, window resize,
timers).
**Cause:** Slow syscalls (`recv`, `send`, `connect`, `accept`, `poll`) can return `-1`
with `errno == EINTR` when a signal arrives.
**Right:** Retry on `EINTR`. (Python ≥3.5 auto-retries per PEP 475; C/Rust-libc and some
others do not — wrap the call in a retry loop, or use `SA_RESTART` where appropriate.)

### 7.3 Nagle's algorithm vs delayed ACK → latency spikes
**Symptom:** Small request/response round-trips inexplicably take ~40 ms.
**Cause:** Nagle's algorithm holds small writes waiting for an ACK; the peer's delayed-ACK
holds the ACK waiting for data — they deadlock briefly.
**Right:** For latency-sensitive request/response protocols, set `TCP_NODELAY` to disable
Nagle. Don't disable it blindly for bulk-throughput protocols where coalescing helps.
Better still: write each message in one `send` rather than many tiny writes.

### 7.4 Inherited file descriptors across fork/exec
**Symptom:** A child process keeps a port/connection alive; fd leaks; security exposure.
**Cause:** fds are inherited across `fork`/`exec` unless marked close-on-exec.
**Right:** Set `O_CLOEXEC`/`FD_CLOEXEC` (or `SOCK_CLOEXEC`) on sockets you don't want
children to inherit.

### 7.5 Platform error-code and API differences
**Symptom:** Code that works on Linux fails on Windows/macOS.
**Cause:** Winsock uses `WSAGetLastError`/`WSAEWOULDBLOCK` (not `errno`/`EAGAIN`), requires
`WSAStartup`, has no `SIGPIPE`, and uses IOCP rather than epoll; BSD/macOS uses kqueue.
**Right:** Abstract the platform layer or use a cross-platform library/runtime; don't
hard-code `errno` constants.

---

## 8. Timeouts, retries & idempotency

### 8.1 No timeout anywhere
**Symptom:** Threads/connections hang forever; the system wedges and needs a restart.
**Cause:** Blocking I/O with no deadline; a vanished peer never wakes you.
**Right:** Set timeouts on connect, read, and write, plus an overall operation deadline.
Distinguish them: a connect timeout, a per-read idle timeout, and a total deadline are
different knobs. On timeout, fail the operation and clean up.

### 8.2 Retrying non-idempotent operations
**Symptom:** Duplicate charges, double-sends, doubled side effects after a flaky network.
**Cause:** A request times out *after* the server processed it; the client retries; the
op runs twice.
**Right:** Make operations idempotent (client-supplied idempotency key / request ID that
the server dedups), or only auto-retry operations that are safe to repeat. Define the
delivery semantics (at-least-once vs at-most-once vs exactly-once) in the protocol.

### 8.3 Retry storms / thundering herd
**Symptom:** A brief outage turns into a sustained overload as everyone retries in lockstep.
**Cause:** Fixed-interval retries with no jitter; all clients retry simultaneously.
**Right:** Exponential backoff **with jitter**, a cap on attempts, and ideally a circuit
breaker. Never tight-loop retry.

### 8.4 Timeout values that are wrong in either direction
**Symptom:** Spurious failures (too aggressive) or slow failure detection (too loose).
**Cause:** Guessed constants; one timeout used for everything.
**Right:** Base timeouts on measured latencies/percentiles; separate connect/read/total;
make them configurable. Heartbeat interval and idle timeout should be coordinated (idle
timeout ≈ 2–3× heartbeat interval).

---

## 9. Buffering, flow control & backpressure

### 9.1 Unbounded receive buffer
**Symptom:** Memory grows without limit when a peer floods or sends a never-completing
frame.
**Cause:** Appending to a reassembly buffer with no cap.
**Right:** Cap the buffer (≥ max frame size plus a margin). If a single frame would exceed
the cap, reject and close. Never let the peer dictate your memory use.

### 9.2 Unbounded write/send queue for a slow peer
**Symptom:** Producer outruns a slow consumer; the outbound queue grows until OOM.
**Cause:** Queuing outgoing messages with no limit when the socket isn't draining.
**Right:** Apply backpressure: bound the outbound queue and, when full, block the producer,
drop per a documented policy, or signal flow control. In async/stream APIs, respect the
`writable`/`drain`/high-water-mark mechanism instead of buffering unboundedly.

### 9.3 Ignoring backpressure in stream APIs
**Symptom:** Memory blowup in Node.js/async code that "writes as fast as it can".
**Cause:** Ignoring the return value of `write()` / the `drain` event / `await writer`.
**Right:** Pause production when the sink is full; resume on drain. (Node: heed
`stream.write()` returning `false`; Rust/tokio: `await` the write/`flush`; Go: a bounded
channel naturally backpressures.)

### 9.4 Reassembly buffer never trimmed
**Symptom:** Slow memory growth even under normal load.
**Cause:** Extracting messages by copying but never freeing the consumed prefix.
**Right:** Delete/advance past consumed bytes after each extracted message; reuse buffers.

---

## 10. State machine & protocol logic

### 10.1 Accepting messages in the wrong state
**Symptom:** A peer sends `DATA` before `HELLO`, or two `HELLO`s, and the server does
something undefined.
**Cause:** No explicit state machine; handlers assume the happy ordering.
**Right:** Define states and allowed transitions. In each state, accept only valid message
types; on an unexpected one, send a protocol error and close. Document the state diagram.

### 10.2 Not handling unknown / future message types
**Symptom:** A newer peer sending a new message type crashes an older peer; can't evolve.
**Cause:** Assuming the set of message types is fixed and exhaustive.
**Right:** Define the rule for unknown types up front: ignore-and-continue (forward
compatibility) or error-and-close, per the message class. Reserve ranges for future use.

### 10.3 Handshake race when both sides speak first
**Symptom:** In a symmetric/peer-to-peer protocol, both peers send their opening message
simultaneously and the logic assumes a strict initiator/responder order.
**Cause:** Designing a half-duplex handshake for a full-duplex reality.
**Right:** Make the handshake tolerate simultaneous opens (define a tie-break, e.g. by
node ID), or designate initiator/responder explicitly.

### 10.4 Message replay within a session
**Symptom:** An old captured message, re-sent, is accepted again.
**Cause:** No sequence numbers / nonces within the session.
**Right:** Include monotonically increasing sequence numbers or nonces; reject
out-of-window or duplicate values. (See `references/security.md` for cross-session replay.)

---

## 11. UDP-specific

### 11.1 Assuming UDP is reliable / ordered / deduplicated
**Symptom:** Lost, reordered, or duplicated datagrams break the app.
**Cause:** UDP guarantees none of these.
**Right:** If you need reliability/ordering, either use TCP/QUIC, or build sequence numbers
+ ACKs + retransmission + dedup yourself (and reconsider using QUIC instead — it's a lot
to get right).

### 11.2 Datagram truncation
**Symptom:** Large datagrams silently lose their tail.
**Cause:** `recvfrom` into a buffer smaller than the datagram truncates it; extra bytes are
discarded (`MSG_TRUNC` flags it).
**Right:** Size the receive buffer for the maximum datagram (up to 65507 bytes for IPv4
UDP), or negotiate a smaller max. Check for truncation.

### 11.3 MTU / fragmentation
**Symptom:** Datagrams larger than the path MTU are fragmented and far more likely to be
dropped; or `EMSGSIZE` with don't-fragment set.
**Cause:** Sending datagrams bigger than the path can carry without IP fragmentation.
**Right:** Keep datagrams small — a payload around **1200 bytes** is widely safe on the
public internet (the value QUIC uses). Do path-MTU discovery only if you need larger.

### 11.4 Amplification and spoofed sources
**Symptom:** Your UDP service is abused to flood a victim (reflection/amplification DDoS).
**Cause:** Replying with more bytes than the request, to an unverified (spoofable) source
address.
**Right:** Don't send large responses before verifying the source (require a handshake /
return a small cookie the client must echo). Never let response size exceed request size
for unverified peers.

### 11.5 Forgetting UDP has no connection
**Symptom:** Confusion about "disconnect", or receiving datagrams from unexpected peers.
**Cause:** UDP is connectionless; `connect()` on a UDP socket only sets a default
destination and filters source, it doesn't establish a connection.
**Right:** Track peers explicitly. Use `connect()` on a UDP socket to receive ICMP errors
and filter sources when talking to a single peer.

### 11.6 Retransmitting over UDP with no congestion control
**Symptom:** Works on the LAN; over a real (lossy, shared) path throughput collapses,
loss climbs the harder the sender tries, and other traffic on the link starves.
**Cause:** Reliability was bolted onto UDP (sequence numbers + retransmission) with a
fixed timer and no send-rate limit. Loss triggers retransmits, retransmits add load,
load causes more loss — the congestion-collapse feedback loop. TCP performs congestion
control for you; raw UDP performs none, and a fixed retransmission timer is wrong on
every network except the one it was tuned on.
**Wrong:** Retransmit every unACKed datagram after a constant 100 ms, with no cap on
datagrams in flight.
**Right:** Bound in-flight data with a congestion window (AIMD + slow start), derive the
retransmission timeout from measured RTT with exponential backoff (Karn's rule for
samples), and pace sends across the RTT — the full mechanics are in
protocol-design.md §10. Or use QUIC, which ships all of this.
**Catch it:** Test under `tc netem` loss *with a competing TCP flow* (testing §7): your
protocol must back off and share the link, not fight the loss.

### 11.7 Broadcast/multicast surprises
**Symptom:** Broadcast or multicast datagrams silently never arrive, arrive only on one
interface, or a sender receives its own traffic and loops.
**Cause:** Broadcast needs `SO_BROADCAST` set on the sender; multicast needs an explicit
group join (`IP_ADD_MEMBERSHIP`) on *each* interface you expect to receive on, TTL/scope
control (`IP_MULTICAST_TTL`), and loopback awareness (`IP_MULTICAST_LOOP`). Routers don't
forward broadcasts, and cloud VPCs (AWS, GCP) drop broadcast and most multicast entirely —
discovery designs that rely on them fail off-LAN.
**Right:** Set the required socket options explicitly; join groups per interface; keep
multicast for same-L2/lab use and prefer a rendezvous/registry service for discovery in
cloud environments. Everything here is still plain UDP — the datagram-size and
amplification rules (§11.2–11.4) apply unchanged.

---

## 12. Versioning & evolution

### 12.1 No version field
**Symptom:** You can't change the protocol without breaking every deployed peer.
**Cause:** Shipping v1 with no version marker and no extension mechanism.
**Right:** Put a protocol identifier (magic) and version in the handshake from day one.
Negotiate the highest mutually supported version.

### 12.2 Breaking wire compatibility
**Symptom:** New and old peers mis-parse each other after a "small" change.
**Cause:** Reordering fields, changing a field's type/width/meaning, or repurposing a
reserved value.
**Right:** Only add fields in backward-compatible ways. Prefer a self-describing format
(TLV, or a schema system like Protobuf with field numbers) so unknown fields can be
skipped. Never reuse a removed field's tag for a new meaning.

### 12.3 Not skipping unknown fields/extensions
**Symptom:** An older peer chokes on an extension a newer peer added.
**Cause:** Strict parsing that errors on anything unrecognized.
**Right:** Make unknown TLV options skippable (length lets you jump past them). Define
which extensions are "must-understand" (error if unknown) vs "optional" (ignore if
unknown), e.g. via a critical-bit, like TLS/IP options do.

---

## Quick mental model

When you read a byte from the network, that byte was chosen by an adversary who has read
your source code, wants to crash you, exhaust your memory, or make you do something twice.
Every rule above is a consequence of taking that seriously while also accepting that the
*transport* itself (not just the peer) will split, merge, delay, drop, duplicate, and
reorder your data.
