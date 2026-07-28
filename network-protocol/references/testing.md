# Testing network code by provoking the failures

Network bugs survive normal testing because the happy path doesn't exercise them. The
strategy here is to **deliberately provoke** partial I/O, weird chunk boundaries, loss,
reordering, hostile input, and slow peers — in deterministic tests — instead of hoping
production won't. Treat the failure modes in `references/pitfalls.md` as a test plan.

## Table of contents

1. [Test the parser independently of sockets](#1-test-the-parser-independently-of-sockets)
2. [Chunk-boundary tests (the highest-value tests)](#2-chunk-boundary-tests)
3. [Golden wire-format vectors](#3-golden-wire-format-vectors)
4. [Property-based testing](#4-property-based-testing)
5. [Fuzzing the parser](#5-fuzzing-the-parser)
6. [Fault injection with a fake transport](#6-fault-injection-with-a-fake-transport)
7. [Network condition simulation](#7-network-condition-simulation)
8. [Timeout, liveness & reconnection tests](#8-timeout-liveness--reconnection-tests)
9. [Concurrency & race tests](#9-concurrency--race-tests)
10. [Backpressure & DoS tests](#10-backpressure--dos-tests)
11. [Interop, soak & observability](#11-interop-soak--observability)
12. [Minimum test suite](#12-minimum-test-suite)

---

## 1. Test the parser independently of sockets

Most protocol *logic* bugs live in the parser and state machine, not in the socket calls.
Make both pure (bytes in → messages/actions out, no I/O) so you can test them exhaustively
without a network. The incremental `FrameReader` in `assets/framed_protocol.py` is written
exactly this way: you `feed(bytes)` and pull complete frames; tests drive it directly.

## 2. Chunk-boundary tests

These catch the #1 and #2 bug classes (framing and partial I/O, pitfalls §1–2) and are the
cheapest high-value tests you can write.

- **One byte at a time:** encode a message, then feed the parser the bytes **one at a time**.
  After the last byte, exactly one complete message must appear; before it, none.
- **Two (or more) messages in one buffer:** concatenate several encoded messages and feed
  them in a single chunk. The parser must yield each message correctly, in order.
- **Message split across two reads:** feed the first K bytes, assert nothing parses, feed the
  rest, assert it parses.
- **Random split points:** for each test message, split it at every possible boundary (or
  many random boundaries) and assert identical results. A property test (below) generalizes
  this.

```python
def test_one_byte_at_a_time():
    frame = encode_frame(MSG_DATA, b"hello world")
    reader = FrameReader()
    out = []
    for b in frame:                       # feed single bytes
        reader.feed(bytes([b]))
        out += list(reader.read_frames())
    assert len(out) == 1 and out[0][2] == b"hello world"

def test_two_in_one_buffer():
    reader = FrameReader()
    reader.feed(encode_frame(MSG_DATA, b"a") + encode_frame(MSG_DATA, b"bb"))
    out = list(reader.read_frames())
    assert [f[2] for f in out] == [b"a", b"bb"]
```

If these two tests pass for arbitrary inputs, you've eliminated the most common production
network bug before it ships.

## 3. Golden wire-format vectors

Pin the exact bytes so the wire format can't change silently (catches endianness,
self-referential length, and accidental layout changes — pitfalls §3, §4.3).

- Check in a handful of `(message, exact hex)` pairs. Encoding the message must produce the
  hex; decoding the hex must produce the message.
- Include edge values: zero-length payload, max-length payload, integer `1` (proves
  big-endian), all-bits-set fields.
- Run on every CI build. A diff here is a deliberate, reviewable protocol change.

```python
GOLDEN = [
    (("DATA", b""),        bytes.fromhex("4e50524f 01 02 0000 00000000")),
    (("DATA", b"\x01"),    bytes.fromhex("4e50524f 01 02 0000 00000001 01")),
]  # magic 'NPRO', ver 01, type 02, flags 0000, len, payload
```

## 4. Property-based testing

Use a property-testing library (Hypothesis, proptest, QuickCheck, gopter) to assert
invariants over *generated* inputs:

- **Round-trip:** `parse(encode(m)) == m` for any valid message `m`.
- **No crash on arbitrary bytes:** `parse(arbitrary_bytes)` either returns a value or a
  clean protocol error — it never panics, hangs, over-allocates, or reads out of bounds.
- **Chunk-invariance:** feeding `encode(m)` to the incremental parser in any chunking yields
  the same single message.
- **Idempotence/canonicality:** `encode(parse(encode(m))) == encode(m)` (stable encoding).

## 5. Fuzzing the parser

Fuzzing finds the malformed inputs you didn't think of — the crashes, hangs, and giant
allocations from hostile data (pitfalls §4, §6.7, §10).

- Tools: libFuzzer/AFL++ (C/C++/Rust), `cargo fuzz`, Go native fuzzing (`go test -fuzz`),
  Atheris (Python), Jazzer (JVM).
- Target the **pure parser** (bytes → message), which makes fuzzing fast and reproducible.
- Seed the corpus with real/golden messages; let the fuzzer mutate from there. **Structure-
  aware** fuzzing (e.g. via Arbitrary) reaches deeper than random bytes.
- Detect both **crashes** and **hangs** (an infinite loop on malformed input is a DoS), and
  watch memory (a length-driven huge allocation is a finding — pitfalls §4.1).
- Add any crashing input to a regression corpus.

## 6. Fault injection with a fake transport

Replace the real socket with a controllable stub so integration tests can reproduce
transport misbehavior deterministically. A good fake can:

- **short reads / short writes:** return/accept 1 byte (or a random small count) per call —
  proves your loops handle partial I/O (pitfalls §2).
- **EOF mid-message:** close after delivering a partial frame — proves clean error, no hang.
- **delay / stall:** pause before delivering — exercises timeouts (§8).
- **drop / reorder / duplicate / truncate / corrupt:** for datagram protocols especially
  (pitfalls §11), and for reliability layers built over UDP.
- **`EAGAIN`/`EINTR`:** for non-blocking/event-loop code paths (pitfalls §6.2, §7.2).

```python
class ShortReadSocket:
    """Wraps real bytes; recv returns at most 1 byte per call to provoke partial reads."""
    def __init__(self, data): self.data = bytearray(data)
    def recv(self, n):
        if not self.data: return b""      # EOF
        b, self.data = bytes(self.data[:1]), self.data[1:]
        return b
# A protocol built on read_exactly/write_all must pass all tests through this socket.
```

## 7. Network condition simulation

Test against realistic adverse conditions, ideally on the loopback so it runs in CI:

- **Linux `tc`/`netem`:** inject latency, jitter, packet loss, reordering, duplication, and
  corruption on an interface. The closest thing to "the real internet" in a test.
- **Toxiproxy:** a programmable TCP proxy that adds latency, bandwidth limits, slow-close,
  and connection cuts — scriptable from tests, cross-platform.
- **`comcast` / clumsy (Windows):** convenience wrappers for similar effects.
- Run your full integration suite under: 1–5% loss, added latency, and reordering. Bugs
  that only appear "over the real network" (pitfalls §11, §1) reproduce here.

## 8. Timeout, liveness & reconnection tests

- **Vanished peer:** `SIGSTOP` the peer process, or drop its packets with a firewall rule,
  and assert your idle timeout/heartbeat fires within the expected window (pitfalls §5.1,
  §8.1). A frozen peer is different from a closed one — test both.
- **Abrupt kill:** `SIGKILL` the peer mid-message; assert clean error and cleanup, not a
  hang or `SIGPIPE` crash (pitfalls §7.1).
- **Reconnection/backoff:** take the server down and bring it back; assert the client
  reconnects with exponential backoff + jitter and resumes correctly, without a retry storm
  (pitfalls §8.3).
- **Half-open:** simulate a route blackhole (firewall DROP) so no FIN arrives; assert
  detection via heartbeat.

## 9. Concurrency & race tests

- Run under a **race detector**: Go `-race`, C/C++/Rust **ThreadSanitizer**, Java's
  concurrency tooling. Many socket-sharing and shared-state bugs (pitfalls §6.6) only show
  up here.
- **Many concurrent connections:** hundreds/thousands simultaneously; assert no fd leak,
  no memory growth, correct per-connection isolation.
- **Write–write deadlock probe:** have both sides bulk-send without reading and assert your
  design/flow-control prevents the deadlock (pitfalls §6.5).
- **Leak checks:** track open fds and memory before/after a load run; they must return to
  baseline.

## 10. Backpressure & DoS tests

Turn the security section into tests (`references/security.md` §7):

- **Slow consumer, fast producer:** assert outbound memory stays bounded (backpressure
  works), not unbounded growth (pitfalls §9.2).
- **Giant length field:** send a frame claiming a huge payload; assert prompt rejection with
  no large allocation (pitfalls §4.1).
- **Slowloris:** open many connections that trickle bytes; assert timeouts/limits reclaim
  them.
- **Decompression bomb:** if you decompress, feed a bomb; assert the output-size cap stops
  it.
- **Flood:** open connections/requests past your limits; assert graceful shedding with an
  error, not a crash.

## 11. Interop, soak & observability

- **Interop / conformance:** test your implementation against an independent one (another
  language, or a reference). Different implementations expose assumptions a single codebase
  shares. Capture traffic with **Wireshark/tcpdump** to inspect actual bytes when something
  disagrees.
- **Soak / long-running:** run for hours/days under steady load; watch for slow leaks
  (buffers never trimmed — pitfalls §9.4), fd creep, and latency drift.
- **Load testing:** measure throughput and tail latency at target concurrency; verify
  timeouts and limits behave under stress.
- **Observability for debugging:** log state-machine transitions, give each connection a
  stable ID, expose metrics (active connections, queue depths, error rates), and keep a way
  to capture packets. When a network bug is reported, the actual bytes + the state at the
  time are what you need.

## 12. Minimum test suite

If you do nothing else, do these — they cover the highest-probability production failures:

1. **One-byte-at-a-time** parser test (framing + partial reads).
2. **Two-messages-in-one-buffer** parser test (framing).
3. **Short-write** delivery test through a 1-byte-per-call fake socket (partial writes).
4. **Golden hex vectors** for a few messages incl. edge sizes (wire-format stability,
   endianness).
5. **Arbitrary-bytes-don't-crash** test, ideally fuzzed (hostile input, bounded allocation).
6. **Idle-timeout fires** when the peer is frozen (liveness, missing-timeout class).

Everything above (simulation, fault injection, concurrency, DoS, interop, soak) raises
confidence further, but these six catch the bugs that most often reach production.
