# Protocol design

How to design the wire format and semantics *before* writing I/O code. Decisions here
prevent whole classes of bugs that are painful to fix later. Write the result down — a
diagram and a field-by-field spec — because undocumented protocols drift and rot.

## Table of contents

1. [Choosing a transport](#1-choosing-a-transport)
2. [Message framing](#2-message-framing)
3. [Header design](#3-header-design)
4. [Serialization](#4-serialization)
5. [Versioning & negotiation](#5-versioning--negotiation)
6. [State machine & handshake](#6-state-machine--handshake)
7. [Request/response correlation & multiplexing](#7-requestresponse-correlation--multiplexing)
8. [Keepalive & liveness](#8-keepalive--liveness)
9. [Flow control & backpressure](#9-flow-control--backpressure)
10. [Reliability over UDP (if you must)](#10-reliability-over-udp-if-you-must)
11. [Error signaling](#11-error-signaling)
12. [Writing the spec](#12-writing-the-spec)

---

## 1. Choosing a transport

Pick based on the delivery semantics you actually need, not habit.

| Need | Use |
|---|---|
| Reliable, ordered byte stream; simplest | **TCP** |
| Reliable, ordered, encrypted, multiplexed, low HOL blocking, connection migration | **QUIC** (over UDP) |
| Lowest latency, can tolerate loss; small messages; real-time media/games | **UDP** (+ your own minimal reliability if needed) |
| Browser-reachable, message-oriented over HTTP infra | **WebSocket** |
| Same-host IPC | **Unix domain socket** (stream or datagram) |
| Encryption on top of TCP | **TLS** over TCP |

Key factors: reliability/ordering requirements; latency vs throughput; NAT/firewall
traversal (UDP often blocked; TCP/443 usually open; QUIC sometimes blocked); need for
multiplexing without head-of-line blocking (→ QUIC over TCP); browser reach (→ WebSocket);
and how much you're willing to reimplement (→ favor QUIC/TLS over rolling your own).

**Default recommendation:** TCP+TLS for most application protocols; QUIC when you need
multiplexed streams or are tempted to build reliability over UDP; bare UDP only for
real-time/loss-tolerant cases.

## 2. Message framing

TCP and Unix stream sockets deliver a byte stream with **no message boundaries** — you
must impose framing. (UDP/QUIC-datagram preserve datagram boundaries, so framing is
implicit, but truncation still applies — see pitfalls §11.2.)

Three strategies:

### Length-prefixed (recommended default)
Each message = a fixed-size length field followed by exactly that many payload bytes.
- **Pros:** simple, no escaping, parser knows exactly how much to read, easy to bound.
- **Choices to nail down:**
  - Width of the length field: `u16` (≤64 KiB), `u32` (≤4 GiB — common), `u64` (rarely
    needed). Smaller width = cheaper but caps message size; pick per your max size.
  - Byte order: big-endian.
  - **What the length covers:** define precisely (e.g. "payload bytes only, excluding the
    header"). Pin it with a golden vector.
  - **Maximum payload:** a hard cap (e.g. 8 MiB) enforced *before* allocating (pitfalls
    §4.1). Document it; reject anything larger.

```
Frame := Header Payload
Header := magic(4) version(1) type(1) flags(2) length:u32(4)   # 12 bytes, big-endian
Payload := length bytes
```

### Delimiter-based
A sentinel (e.g. `\n`, or `\r\n` for line protocols) marks message ends.
- **Pros:** human-readable/debuggable for text protocols; streamable.
- **Cons:** the delimiter must not appear in the payload — requires escaping/byte-stuffing
  (e.g. COBS) or an alphabet restriction (e.g. base64). Easy to get wrong (pitfalls §1.2).
- Use for line-oriented text protocols; avoid for arbitrary binary.

### Fixed-length records
Every message is the same size.
- **Pros:** trivial framing.
- **Cons:** wasteful or impossible for variable data; brittle to evolve.
- Use only for genuinely fixed-shape data (e.g. a stream of identical sensor samples).

### Self-describing / TLV (Type-Length-Value)
Each element carries its type and length; great for extensibility (skip unknown types).
Often combined with an outer length-prefixed frame. Use when the protocol must evolve and
carry optional fields.

## 3. Header design

A typical binary message header (all multi-byte fields big-endian) might contain:

- **Magic / protocol identifier** (e.g. 4 bytes): lets a peer reject wrong-protocol or
  garbage connections immediately, and helps tools identify traffic.
- **Version** (1–2 bytes): for negotiation and evolution. Include from day one.
- **Message type** (1–2 bytes): discriminates the payload. Reserve ranges for future use.
- **Flags** (1–2 bytes): bitfield for booleans (e.g. compressed, last-in-stream,
  must-understand). Reserve unused bits and require them zero.
- **Length** (2/4/8 bytes): payload size, bounded (above).
- **Optional:** message/correlation ID (for multiplexing, §7), checksum (only if you
  don't have TLS/QUIC integrity — usually unnecessary over TLS), stream ID, sequence
  number.

Keep the header fixed-size when possible (simpler `read_exactly`), or make it
length-described if it must be extensible. Document every field, its width, and its byte
order.

## 4. Serialization

How payload fields become bytes. **Strongly prefer an existing schema/serialization system
over hand-rolling** (see SKILL.md "Strongly consider not hand-rolling"):

| Option | When |
|---|---|
| **Protocol Buffers** | Schema evolution, cross-language, mature tooling; the safe default for structured messages. Field numbers let you add/deprecate fields safely. |
| **FlatBuffers / Cap'n Proto** | Zero-copy reads, very low latency, large messages accessed partially. |
| **MessagePack / CBOR** | Compact, schema-less, JSON-like; good when you want flexibility without a schema. |
| **JSON / text** | Human-readable, easy debugging, ubiquitous; larger and slower; fine for low-rate or human-facing protocols. |
| **Hand-rolled binary** | Only when you need exact control of the bytes and have a reason; apply all pitfalls rules. |

If you hand-roll: explicit widths, big-endian, length-prefix variable-length fields
(strings, arrays), validate every field and count against bounds, and never dump a struct
to the wire (pitfalls §3.2). Specify encoding (UTF-8) and how to handle invalid input.

**Canonical encoding:** if you ever sign/hash messages, define a single canonical byte
representation; otherwise two encoders may produce different bytes for the same logical
message and break signatures.

## 5. Versioning & negotiation

Design for evolution from the start — you will need to change the protocol.

- **Carry a version** in the handshake (and optionally per message). Negotiate the highest
  version both sides support.
- **Feature/capability negotiation:** exchange supported features/extensions in the
  handshake so each side knows what the other understands.
- **Must-ignore-unknown rule:** define how a peer treats unknown message types / fields /
  options. Forward compatibility usually means "skip unknown optional things, continue."
  Mark some as "must-understand" (error if unknown) using a critical bit (like TLS/IP
  options) when correctness depends on them.
- **Reserved fields/bits/ranges:** reserve space now (require reserved bits = 0) so you can
  add later without breaking parsers.
- **Never repurpose** a removed field's tag/number/meaning; allocate a new one (pitfalls
  §12.2).
- **Deprecation:** plan how old versions are sunset; support N and N-1 during transitions.

## 6. State machine & handshake

Model the connection as an explicit state machine. This is the difference between a
protocol that handles unexpected input gracefully and one with undefined behavior.

- **Enumerate states** (e.g. `INIT → HANDSHAKING → READY → CLOSING → CLOSED`).
- **Define allowed transitions** and which message types are valid in each state. In every
  state, an unexpected message type → send a protocol error and close (pitfalls §10.1).
- **Handshake:** typically `HELLO` (version, capabilities, auth/nonce) ⇄ `HELLO_ACK`
  (negotiated version, server nonce). Decide initiator/responder, or tolerate simultaneous
  opens with a tie-break (pitfalls §10.3).
- **Half-close semantics:** define what `BYE`/`FIN` means and how each side drains
  in-flight messages before closing (pitfalls §5.2).
- **Draw the diagram** and keep it in the spec.

Implement the state machine as a pure unit that takes (state, event) → (new state, actions)
with no I/O inside it, so it's exhaustively testable (see `references/testing.md`).

## 7. Request/response correlation & multiplexing

If multiple requests can be in flight on one connection (pipelining/multiplexing):

- Give each request a **correlation ID**; responses echo it so the client can match them.
- Without IDs you're limited to strict request-then-response ordering (simpler but blocks
  pipelining).
- **Head-of-line blocking:** on a single TCP connection, one slow/large response blocks
  everything behind it. If that matters, use independent streams (QUIC) or multiple
  connections. Design the protocol to allow interleaving (frame responses, don't require
  whole-message ordering).
- Define limits on concurrent in-flight requests per connection (relates to flow control).

## 8. Keepalive & liveness

Detecting a dead or vanished peer is not automatic (pitfalls §5.1).

- **Application-level heartbeat:** periodic `PING` answered by `PONG`. If no traffic
  (including PONG) arrives within an idle timeout, declare the peer dead and close.
- **Coordinate the constants:** idle timeout ≈ 2–3× heartbeat interval to tolerate one
  lost heartbeat.
- **TCP keepalive** (`SO_KEEPALIVE`) is a backstop but defaults to hours; tune it or rely
  on app heartbeats for timely detection.
- Heartbeats also keep NAT/firewall mappings alive on long-lived idle connections.

## 9. Flow control & backpressure

Decide what happens when one side is faster than the other, so neither side OOMs
(pitfalls §9).

- **Bounded buffers** on both receive and send sides.
- **Credit/window scheme** (optional, for high-throughput protocols): the receiver grants
  the sender a number of bytes/messages it may send; the sender stops when credit is
  exhausted and resumes when more is granted. This is a sliding window: as the receiver
  consumes data it returns credit, and the window slides forward. It is how HTTP/2 and
  QUIC do per-stream flow control.
- At minimum, rely on TCP's own flow control and **don't queue unboundedly** above it:
  block the producer or apply policy when your application queue is full.
- Define behavior under overload: backpressure, shed load (reject with an error), or drop
  per a documented policy — but never grow memory without bound.

Keep the two "don't overwhelm" mechanisms distinct: **flow control** protects the
*receiver* (its buffers), **congestion control** protects the *network path* (queues in
routers and links you don't own). Over TCP you inherit both. Over UDP you inherit
neither, and must provide both — see §10. A protocol can have perfect flow control and
still melt a link because nothing limits its sending rate to what the path can carry.

## 10. Reliability over UDP (if you must)

If you genuinely need UDP but also need reliability/ordering, you are reimplementing a
transport. Strongly consider **QUIC** instead. If you proceed, you need at least:

- **Sequence numbers** on every datagram.
- **Acknowledgments** (cumulative and/or selective) from the receiver. Selective ACKs
  (report exactly which ranges arrived) avoid retransmitting data the peer already has
  when a single datagram in the middle is lost.
- **Retransmission** on loss, with a **retransmission timeout** derived from measured RTT
  (and exponential backoff) — see the mechanics below.
- **Duplicate detection** and **reordering** buffers on the receiver.
- **Congestion control** (don't flood the network) and **flow control** — see below;
  skipping this is not an option for anything that leaves a lab network.
- **Connection establishment** with anti-spoofing (a handshake / cookie) to avoid
  amplification abuse (pitfalls §11.4).
- **Path MTU** awareness; keep datagrams ≲1200 bytes (pitfalls §11.3).

This is a large amount of subtle work; treat building it as a last resort.

### RTT estimation and the retransmission timeout (RTO)

A fixed retransmission timer is wrong on every network but the one you tested on. Measure
and adapt, the way TCP does:

- Keep a **smoothed RTT** and a **variance** estimate, updated per ACK sample
  (exponentially weighted moving averages):
  `SRTT ← (1−α)·SRTT + α·sample` and `RTTVAR ← (1−β)·RTTVAR + β·|SRTT − sample|`
  with the classic α=1/8, β=1/4. Then `RTO = SRTT + 4·RTTVAR`, clamped to a sane floor
  (e.g. ≥200 ms) and ceiling.
- **Don't sample retransmitted packets** (Karn's rule): if a datagram was sent twice, an
  ACK for it is ambiguous — you can't tell which transmission it answers, so it must not
  update SRTT.
- **Back off exponentially** on each successive timeout of the same datagram (double the
  RTO, up to a cap), and reset after a fresh ACK. A timeout that doesn't back off *is* a
  retry storm against a congested path (pitfalls §8, §11.6).

### Congestion control: the minimum viable discipline

Why this is mandatory: without it, loss → retransmit → more load → more loss. That
feedback loop is **congestion collapse**, it takes down the path for everyone sharing it,
and it is exactly what pre-congestion-control TCP did to the 1986 Internet. A protocol
without congestion control is also brutally unfair to every TCP/QUIC flow sharing the
bottleneck, and networks (and reviewers) treat it as hostile. The minimum viable scheme is
what TCP calls **AIMD** with a slow start:

- Maintain a **congestion window** (cwnd): the number of bytes/datagrams allowed in flight
  (sent but not yet ACKed). Never have more than `min(cwnd, flow-control window)`
  outstanding — the network's limit and the receiver's limit are separate constraints.
- **Slow start:** begin small (a few datagrams) and grow cwnd by one datagram per ACKed
  datagram (i.e. double per RTT) until the first loss or a threshold.
- **Additive increase:** past the threshold, grow gently (≈ +1 datagram per RTT).
- **Multiplicative decrease:** on loss, cut cwnd (halving is the classic choice) and set
  the threshold to the new value; on an RTO (severe signal), fall back to slow start.
- **Pace** sends across the RTT instead of blasting the whole window as one burst; bursts
  overflow shallow router queues even when the average rate is fine.
- Treat **loss as the congestion signal** (and back off), optionally reacting to **ECN**
  marks where available. Latency-sensitive designs can use delay-based signals (the BBR
  family), but don't invent your own scheme — implement a published one.

If all of this sounds like a lot: it is, and it's the strongest argument on this page for
using **QUIC**, which ships modern loss recovery and congestion control (NewReno/CUBIC/BBR
implementations) instead of hand-rolling them. Hand-rolled congestion control is a
last-resort item and must be validated against packet loss and competing traffic
(testing §7; `tc netem` with loss and a parallel TCP flow).

Congestion control is not only a UDP concern, by the way: even over TCP, an *application*
that retries aggressively on timeouts adds load exactly when the system is least able to
take it — that's why retries need exponential backoff, jitter, and caps (pitfalls §8;
production-readiness §6).

## 11. Error signaling

Decide how errors are communicated, in-protocol, rather than only by closing the socket.

- **Error messages / codes:** a dedicated `ERROR` message type with a numeric code and an
  optional human-readable reason lets the peer distinguish "you sent garbage" from "I'm
  overloaded" from "auth failed."
- **Define a code space** and reserve ranges; document each code's meaning and whether the
  connection survives it (recoverable) or must close (fatal).
- **Don't leak internals** in error text to untrusted peers (pitfalls/security): generic
  messages outward, detail in your logs.
- **Always also handle abrupt closure** — a peer may just vanish without sending an error.

## 12. Writing the spec

Produce, and keep with the code:

- A **frame/header diagram** with byte offsets and widths.
- A **field-by-field description**: type, width, byte order, units, valid ranges, meaning,
  and exactly what `length` covers.
- The **message-type table** with reserved ranges.
- The **state diagram** and transition table.
- **Versioning/extension rules** (must-understand vs ignorable).
- **Limits:** max message size, max concurrent requests, timeouts, heartbeat interval.
- **Golden examples:** a few messages as annotated hex, which double as test vectors
  (`references/testing.md`).

A precise spec is what makes independent implementations interoperate and what makes the
tests in `references/testing.md` meaningful.
