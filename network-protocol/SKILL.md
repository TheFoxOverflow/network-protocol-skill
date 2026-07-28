---
name: network-protocol
description: >-
  Use whenever the user wants to design, implement, review, or debug a network
  protocol or client/server wire communication over TCP, UDP, QUIC, TLS, WebSockets,
  Unix domain, or raw sockets — framing, binary/wire formats, RPC, handshakes, message
  formats. Also use to capture and analyze protocol traffic on the wire (tcpdump,
  Wireshark/tshark, scapy, custom dissectors); to deploy or troubleshoot a protocol in
  cloud and orchestrated networks (AWS VPC, GCP networking, Kubernetes and CNI, load
  balancers, MTU, NAT); and as a study aid for networking certifications (CCNA,
  subnetting, OSI/TCP-IP, routing and switching). Trigger on debugging symptoms too:
  messages merged or split, partial reads/writes, hangs that never time out,
  intermittent corruption, works-on-localhost-fails-over-the-network, undetected
  connection drops, or memory blowups under load. Do NOT use it for pure HTTP-REST-API
  calls with an existing client library or front-end fetch(), where no custom protocol
  is involved.
---

# Network protocol design & implementation

## What this skill is for

Designing and implementing protocols correctly is hard for one specific reason:
**the failure modes are invisible in the happy path.** Code that merges two messages
into one buffer, trusts a length field, or never sets a timeout will pass review, pass
unit tests, and demo perfectly on `localhost` — then corrupt data or hang the moment it
meets a real network with partial reads, slow peers, reordered packets, or a malicious
client.

This skill front-loads those failure modes. It contains a catalog of the bugs that
actually bite, the design decisions that avoid whole bug classes, defensive
implementation patterns, a security model for untrusted peers, a testing strategy that
*provokes* the failures instead of hoping they don't happen, the operational layer that
makes a correct protocol actually production-ready, and a final review checklist. There
is also a production-grade reference library with a full test suite.

The goal is a result that is genuinely production-ready, not merely correct on the happy
path: framed and bounded, defended against hostile peers, observable, gracefully
degrading under load, and safe to deploy and evolve.

Beyond designing and building a protocol, this skill also helps you **observe** one on the
wire (packet capture and analysis with tcpdump, Wireshark, and Python), **deploy** one
into real cloud and Kubernetes networks (where load balancers, NAT, MTU, and firewalls
change the rules), and **learn** networking fundamentals for certifications like the CCNA.
See "Additional capabilities" below.

Treat every byte from the network as written by an adversary who has read your code.

## The golden rules (these prevent the majority of real bugs)

Internalize these before writing any byte-handling code. Each one maps to a bug class
that is otherwise nearly guaranteed.

1. **TCP is a byte stream, not a message stream.** There are no message boundaries on
   the wire. One `send` does not equal one `recv`. You **must** add your own framing
   (length prefix or delimiter). Assuming "one read = one message" is the single most
   common network bug.
2. **`recv`/`read` returns *up to* N bytes, and `0` means EOF.** It routinely returns
   fewer bytes than you asked for. Always loop until you have what you need; treat a
   `0`/empty return as the peer closing, not as "try again".
3. **`send`/`write` may accept fewer bytes than you offered.** Always loop until the
   whole buffer is written (or use the language's `sendall`/`write_all` equivalent).
4. **Never trust a length or count from the wire.** Bound it against a hard maximum
   *before* allocating or waiting for that many bytes. An unbounded length field is a
   one-line denial-of-service.
5. **Every operation that touches the network needs a timeout / deadline.** Without one,
   a stalled or vanished peer hangs you forever. "It hung and never recovered" is
   almost always a missing timeout.
6. **Define byte order explicitly.** Serialize multi-byte integers as big-endian
   (network byte order) — never `memcpy` a struct to the wire (padding and endianness
   are not portable).
7. **Make the parser incremental.** Bytes arrive in arbitrary chunk sizes. The parser
   must accept a 1-byte chunk or a 10-message chunk and behave identically. Buffer,
   then extract complete messages.
8. **Separate the three layers.** Parsing (bytes ⇄ structures), protocol logic (the
   state machine), and I/O (sockets) must be separate units. Mixing them makes the
   logic untestable and hides bugs.
9. **Validate before you act.** Check every field — type, length, range, state-validity —
   before doing anything with it. Fail fast and explicitly on malformed input.
10. **Clean up on every path.** Close sockets and free buffers on success, on error, and
    on exception. Bound your read and write buffers so a flooding or stalled peer can't
    exhaust memory.

If you remember nothing else, remember rules 1–5. They account for most production
incidents in hand-written network code.

## Strongly consider not hand-rolling

Before implementing from scratch, check whether an existing, battle-tested layer fits.
Hand-written wire code is a bug farm; reuse eliminates entire categories at once.

- **Serialization / schema:** Protocol Buffers, FlatBuffers, Cap'n Proto, MessagePack,
  or CBOR give you schema evolution, canonical encoding, and validated parsers for free.
  Prefer one of these over a hand-rolled binary format unless you have a concrete reason.
- **Reliable + encrypted + multiplexed transport:** **QUIC** (over UDP) gives you
  streams, TLS 1.3, loss recovery, flow control, and no cross-stream head-of-line
  blocking. If you're about to reimplement reliability on top of UDP, use QUIC instead.
- **Encryption / auth:** Always TLS (or a vetted library like libsodium/Noise). Never
  invent crypto, and never disable certificate verification "to make it work."
- **Framing over a stream:** length-prefixed framing is simple enough to write, but many
  ecosystems have a ready codec (e.g. `tokio_util` length-delimited, Netty
  `LengthFieldBasedFrameDecoder`). Use them when available.

Hand-roll only the genuinely custom part, and apply the rules above to it.

## Workflow for building a protocol from scratch

Follow these steps in order. Read the linked reference file at each step.

1. **Clarify requirements.** Pin down, ideally with the user, the answers that drive
   every later decision:
   - Transport constraints: must traverse NAT/firewalls? need low latency or high
     throughput? one connection or many?
   - Delivery semantics needed: reliable + ordered (→ TCP/QUIC) or
     latency-over-reliability (→ UDP)? at-least-once vs at-most-once vs exactly-once?
   - Message shapes and sizes: typical and maximum message size? request/response,
     streaming, pub/sub, or fire-and-forget?
   - Who initiates, and how many peers? client→server, peer-to-peer, multiplexed?
   - Trust and security: is the peer trusted? is the network trusted? what's the auth
     model? (Almost always: assume neither is trusted.)
   - Longevity and interop: will the protocol need to evolve? must multiple languages or
     versions interoperate? (Almost always yes — so version it from day one.)
   If the user hasn't specified these, state the assumptions you're making and proceed;
   don't block, but make the assumptions explicit so they can be corrected.

2. **Design the wire format and semantics.** Read **`references/protocol-design.md`**.
   Decide framing, header layout, serialization, versioning/negotiation, the state
   machine, keepalive, flow and congestion control, and error signaling. Write the format
   down (a diagram or grammar) — undocumented protocols rot and drift.

3. **Implement with the defensive patterns.** Read **`references/transport-and-io.md`**
   for the socket-layer patterns (correct read/write loops, blocking vs non-blocking vs
   async, timeouts, connection lifecycle, OS gotchas like SIGPIPE/EINTR/Nagle). Use
   **`assets/framed_protocol.py`** as a correct, runnable starting point and
   **`assets/cross-language-notes.md`** to translate the patterns to Go, Rust, C, or
   Node.js.

4. **Make it safe against hostile peers.** Read **`references/security.md`**. Add TLS,
   authentication, replay protection, input bounds, and DoS resistance (untrusted
   lengths, decompression bombs, slowloris, amplification). Skipping this is only
   acceptable for a closed, fully-trusted environment — and say so explicitly if you do.

5. **Test by provoking the failures.** Read **`references/testing.md`**. At minimum:
   test the parser independently of sockets; feed it the same message split into 1-byte
   chunks *and* two messages in one buffer; fuzz the parser; inject short reads/writes,
   delays, drops, reordering, truncation, and mid-message closes; and check golden
   wire-format vectors so the format can't silently change.
   **`assets/test_protocol.py`** is a working suite that already does all of this against
   the reference library — adapt it to your format rather than starting from nothing.

6. **Make it production-ready, not just correct.** Read
   **`references/production-readiness.md`**. Add observability (structured logs with a
   connection id, metrics, health/readiness), a hard connection cap with load shedding, a
   separate handshake timeout, graceful drain on SIGTERM, computed resource ceilings,
   externalized limits, a version-rollout plan, and load/soak/fault testing. A protocol
   that is correct on the bench but unobservable, unbounded, or undeployable is not done.
   **`assets/framed_protocol.py`** demonstrates the cap, load shedding, graceful drain, and
   metrics counters.

7. **Run the review checklist before declaring done.** Read
   **`references/review-checklist.md`** and confirm each item, including the production
   section. This is the final gate — it catches the rules above that are easy to forget
   under deadline.

Throughout, when implementing or reviewing any byte-handling code, consult
**`references/pitfalls.md`** — the concrete bug catalog with wrong/right examples and
how to catch each one.

## When debugging existing network code

Jump straight to **`references/pitfalls.md`** and match the symptom:

| Symptom | Most likely cause | Pitfalls section |
|---|---|---|
| Messages merged together or split apart | No framing / assuming 1 recv = 1 message | Framing & boundaries |
| Truncated or short reads; missing tail bytes | Not looping on `recv`; partial read | Partial I/O |
| Occasional garbled integers / fields | Endianness or struct-padding on the wire | Byte order & encoding |
| Huge memory spike or OOM under load | Unbounded length field or unbounded buffer | Length fields; Backpressure |
| Hang that never returns | Missing timeout; write-write deadlock | Timeouts; Concurrency |
| Process dies on client disconnect | `SIGPIPE` on write to closed socket | OS & signal gotchas |
| "Connection" stays up after peer is gone | No keepalive/heartbeat; half-open undetected | Connection lifecycle |
| Works locally, fails over real network | Latency/loss/reordering exposes a happy-path bug | Testing; UDP-specific |
| UDP throughput collapses under loss; link lags for everyone | Retransmission with no congestion control / fixed timer | UDP-specific §11.6; design §10 |
| IPv6-only clients can't connect; v4 works | IPv4-only bind (`0.0.0.0`) / no dual-stack | transport §12 |
| Duplicated side effects after a retry | Retrying a non-idempotent op | Timeouts & idempotency |

When logs and reasoning aren't enough, **capture the traffic** and look at the actual
bytes — see **`references/packet-analysis.md`**. Many of the bugs above have a visible
signature on the wire (two messages in one TCP segment, a message split across segments, a
RST from an idle-timing-out load balancer), and the capture is the ground truth when your
logs and the network disagree.

## Additional capabilities

Beyond designing and implementing a protocol, this skill covers three adjacent areas. Read
the linked file when the task calls for it.

- **Observe a protocol on the wire** — **`references/packet-analysis.md`**. Capture with
  `tcpdump`, analyze in Wireshark/`tshark`, script with `scapy`/`pyshark`, and decode a
  custom binary protocol with a Wireshark dissector (`assets/npro.lua` dissects the
  reference format and shows correct TCP desegmentation). Covers capture vs display
  filters, following streams, capturing in containers/Kubernetes, and decrypting TLS for
  debugging via `SSLKEYLOGFILE`.
- **Deploy a protocol in cloud and Kubernetes networks** —
  **`references/cloud-and-orchestration.md`**. How AWS VPC, GCP networking, and Kubernetes
  CNIs change your assumptions: L4 vs L7 load balancers, LB idle timeouts that kill
  long-lived connections (and the heartbeat that prevents it), overlay MTU, recovering the
  real client IP (PROXY protocol) so per-IP limits work, NetworkPolicies, and graceful
  drain wired to SIGTERM. `assets/k8s-deployment.yaml` is a worked manifest for the
  reference server.
- **Learn networking for certifications (CCNA, Network+)** —
  **`references/learning-mode.md`**. A study-partner mode: teach-then-test with hints, the
  CCNA 200-301 domain map, core topics (OSI/TCP-IP, subnetting, TCP/UDP, VLANs, routing,
  NAT, ACLs) connected back to the rest of this skill, and a runnable subnetting drill
  (`assets/subnetting_practice.py`).

## Reference map

- **`references/pitfalls.md`** — The bug catalog. Every common network bug with symptom,
  root cause, wrong vs right code, and how to test for it. Consult constantly.
- **`references/protocol-design.md`** — Designing the protocol itself: transport choice,
  framing, headers, serialization, versioning/negotiation, state machines, keepalive,
  flow control vs congestion control, reliability-over-UDP (RTT/RTO estimation, AIMD,
  pacing), error signaling.
- **`references/transport-and-io.md`** — The socket/OS layer: read/write loops,
  blocking vs non-blocking vs async, event loops, timeouts, connection lifecycle,
  graceful shutdown, TCP tuning, UDP specifics, platform differences, IPv6/dual-stack
  and name resolution.
- **`references/security.md`** — Untrusted peers and networks: TLS/mTLS, auth, replay
  protection, integrity, constant-time comparison, input validation, and DoS resistance.
- **`references/testing.md`** — How to provoke the failures: parser-level tests, chunk-
  boundary tests, fuzzing, property tests, fault injection, network simulation, soak and
  load tests, interop and golden vectors.
- **`references/production-readiness.md`** — The operational layer that makes a correct
  protocol production-ready: observability (logs/metrics/tracing/health), connection caps
  and load shedding, graceful drain, resource governance, configuration, reliability,
  version rollout, and load/soak/chaos testing.
- **`references/packet-analysis.md`** — Observing a protocol on the wire: tcpdump capture,
  Wireshark/tshark analysis, scapy/pyshark scripting, writing a Wireshark dissector,
  capturing in containers/Kubernetes, decrypting TLS for debugging, and a symptom→cause
  table for wire-level diagnosis.
- **`references/cloud-and-orchestration.md`** — Deploying a protocol in AWS VPC, GCP, and
  Kubernetes/CNI networks: L4 vs L7 load balancers, idle timeouts, overlay MTU, real
  client IP / PROXY protocol, NetworkPolicies, health probes, and graceful drain on
  SIGTERM, with a deployment checklist.
- **`references/learning-mode.md`** — A networking-certification study partner (CCNA,
  Network+): teach-then-test approach, the CCNA 200-301 domain map, core topics connected
  to the rest of the skill, the subnetting method, and how to run a practice session.
- **`references/review-checklist.md`** — A concrete pre-ship checklist, including a
  production-readiness section; the final gate.
- **`assets/framed_protocol.py`** — A production-grade, single-module reference *library*:
  a bounded, length-prefixed framed protocol over TCP with a typed exception hierarchy,
  an O(n) incremental parser, thread-safe sends, version negotiation, optional TLS/mTLS
  (encryption plus certificate- and hostname-verified peer authentication), per-message
  and per-handshake deadlines (slowloris defense), and a server with global and per-IP
  connection caps, load shedding, and graceful drain. Runnable
  (`python3 framed_protocol.py` for a loopback demo).
- **`assets/test_protocol.py`** — A working test suite for the library (runs under pytest
  or standalone): chunk-boundary, golden vectors, bounds, fuzz, fault injection, the O(n)
  parser, the slow-body deadline, per-IP shedding, handshake negotiation, and live TLS and
  mutual-TLS round-trips (including rejection of an untrusted server and of a client with
  no certificate). Adapt it to your format.
- **`assets/pyproject.toml`** — Packaging and tooling config (pytest, mypy, ruff) so the
  reference builds, type-checks, and lints as a real project.
- **`assets/cross-language-notes.md`** — The same defensive patterns in Go, Rust, C, and
  Node.js.
- **`assets/npro.lua`** — A Wireshark/tshark dissector for the reference wire format,
  demonstrating correct TCP desegmentation for a custom protocol.
- **`assets/k8s-deployment.yaml`** — A worked Kubernetes manifest (Deployment, L4 Service,
  NetworkPolicy) for the reference server, with probes, graceful-drain grace period, and a
  preStop hook.
- **`assets/subnetting_practice.py`** — A runnable subnetting drill for certification
  study (generates and checks problems; `--selftest` verifies it headlessly).
