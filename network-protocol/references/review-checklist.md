# Pre-ship review checklist

Run through this before declaring a protocol implementation done. Each item maps to a bug
class in `references/pitfalls.md`. Confirm each one explicitly — these are exactly the
things that are easy to forget under deadline and expensive to find in production.

Use it as a gate: if an item doesn't apply, say *why* it doesn't, rather than skipping
silently.

## Framing & parsing
- [ ] Messages are framed (length-prefix or delimiter); the code does **not** assume one
      `recv` = one message. (pitfalls §1.1)
- [ ] The parser is **incremental**: it handles a 1-byte chunk and many-messages-in-one-
      chunk identically. There's a test proving both. (pitfalls §1.1, §7; testing §2)
- [ ] If delimiter framing is used, the delimiter is escaped or excluded from payloads.
      (pitfalls §1.2)
- [ ] What the `length` field covers is defined unambiguously and pinned by a golden vector.
      (pitfalls §4.3; testing §3)

## Partial I/O
- [ ] All reads use a `read_exactly`-style loop; `recv == 0`/empty is treated as EOF.
      (pitfalls §2.1, §2.3)
- [ ] All writes loop over short writes (or use `sendall`/`write_all`). (pitfalls §2.2)

## Encoding
- [ ] Multi-byte integers use a fixed byte order (big-endian); no struct is dumped raw to
      the wire. (pitfalls §3.1, §3.2)
- [ ] Wire fields use explicit-width types with defined signedness. (pitfalls §3.3)
- [ ] Text encoding is specified (UTF-8) and validated; strings are length-prefixed, not
      NUL-terminated. (pitfalls §3.4)

## Memory safety & untrusted input
- [ ] Every length/count/offset from the wire is bounded against a hard maximum **before**
      allocating or awaiting that many bytes. (pitfalls §4.1; security §6–7)
- [ ] Size arithmetic can't overflow (bounds applied first / checked arithmetic). (pitfalls
      §4.2)
- [ ] Every field is validated (type, range, flags, state-legality) before it's acted on.
      (pitfalls §10.1; security §6)
- [ ] Reserved bits/values are required to be zero/unused and rejected otherwise. (design §5)

## Connection lifecycle & liveness
- [ ] A timeout/deadline exists on connect, read, and write; nothing can hang forever.
      (pitfalls §8.1; transport §5)
- [ ] An application-level heartbeat (or tuned TCP keepalive) detects a vanished/half-open
      peer within a bounded time. (pitfalls §5.1; design §8)
- [ ] Graceful shutdown uses `shutdown` then drains before `close`; the final message isn't
      lost. (pitfalls §5.2; transport §6)
- [ ] Server sets `SO_REUSEADDR`; restart doesn't fail on `EADDRINUSE`. (pitfalls §5.3)
- [ ] The accept loop survives per-connection errors and backs off on fd exhaustion.
      (pitfalls §5.5)

## OS & signals (POSIX)
- [ ] `SIGPIPE` can't kill the process (ignored globally, `MSG_NOSIGNAL`, or `SO_NOSIGPIPE`);
      `EPIPE` is handled. (pitfalls §7.1)
- [ ] Slow syscalls are retried on `EINTR` (or the runtime does it). (pitfalls §7.2)
- [ ] `TCP_NODELAY` is set for latency-sensitive request/response. (pitfalls §7.3)
- [ ] Sockets are `CLOEXEC` if child processes shouldn't inherit them. (pitfalls §7.4)

## Concurrency
- [ ] No blocking I/O on an event-loop thread. (pitfalls §6.1)
- [ ] `EAGAIN`/`EWOULDBLOCK` is treated as "retry later", not fatal. (pitfalls §6.2)
- [ ] Edge-triggered loops drain until `EAGAIN`; writability is registered only when there's
      queued data. (pitfalls §6.3)
- [ ] No socket is written from multiple threads without serialization; per-connection state
      has a single owner. (pitfalls §6.6)
- [ ] The design can't deadlock with both sides writing without reading. (pitfalls §6.5)
- [ ] Tested under a race detector. (testing §9)

## Backpressure & resources
- [ ] Receive buffer is bounded; an over-large frame is rejected, not buffered forever.
      (pitfalls §9.1)
- [ ] Outbound queue is bounded; a slow peer produces backpressure, not unbounded memory.
      (pitfalls §9.2, §9.3)
- [ ] Consumed bytes are freed from the reassembly buffer. (pitfalls §9.4)
- [ ] Every fd/socket is closed on all paths (success, error, exception). (transport §10)
- [ ] Concurrent connections, in-flight requests, and per-peer resources are capped.
      (security §7)

## Versioning & evolution
- [ ] A protocol identifier (magic) and version are in the handshake; versions are
      negotiated. (pitfalls §12.1; design §5)
- [ ] Unknown message types/fields have defined handling (ignore vs error per class).
      (pitfalls §10.2, §12.3)
- [ ] Changes are backward-compatible; no field tag/meaning is repurposed. (pitfalls §12.2)

## Security (unless a closed, fully-trusted environment — state it if so)
- [ ] TLS (or QUIC) is used; certificate chain **and** hostname are verified; verification
      is never disabled. (security §1)
- [ ] Authentication happens over the encrypted channel before privileged actions; secrets
      aren't sent in plaintext. (security §2)
- [ ] Secret/token/MAC comparisons are constant-time. (security §5)
- [ ] Replay is mitigated (nonces/sequence numbers/timestamps as appropriate). (security §4)
- [ ] DoS vectors are handled: bounded allocation, decompression-bomb cap, slowloris
      timeouts, UDP amplification prevention, algorithmic-complexity safety. (security §7)
- [ ] Text protocols sanitize control characters; framing is unambiguous (no smuggling).
      (security §8)
- [ ] Errors fail closed; outward error messages are generic; secrets aren't logged.
      (security §9)

## UDP (if applicable)
- [ ] No assumption of reliability/ordering/dedup; sequence/ack/retransmit/dedup added if
      needed (or QUIC used). (pitfalls §11.1)
- [ ] Receive buffer sized for the max datagram; truncation is detected. (pitfalls §11.2)
- [ ] Datagrams kept ≲1200 bytes to avoid fragmentation. (pitfalls §11.3)
- [ ] No larger-than-request replies to unverified sources; handshake/cookie first.
      (pitfalls §11.4)
- [ ] If retransmitting over UDP: congestion window (AIMD + slow start), RTT-derived RTO
      with exponential backoff (Karn's rule), and pacing — or QUIC instead; validated
      under netem loss alongside a competing TCP flow. (pitfalls §11.6; design §10)
- [ ] Flow control (receiver limit) and congestion control (network limit) both bound the
      data in flight, as separate constraints. (design §9–10)
- [ ] Broadcast/multicast (if used): required socket options set, groups joined per
      interface, and no reliance on them off-LAN / in cloud VPCs. (pitfalls §11.7)

## Addressing & resolution
- [ ] Clients resolve via getaddrinfo and try all returned addresses (v6 and v4), with
      short per-attempt connect timeouts. (transport §12)
- [ ] Server binding is deliberately dual-stack or per-family; IPV6_V6ONLY is set
      explicitly, not inherited from the platform default. (transport §12)
- [ ] Per-IP limits, logs, and ACLs normalize v4-mapped v6 addresses to one key.
      (transport §12)
- [ ] Wire format, config, and logs can hold IPv6 addresses; v6 literals bracketed in
      URLs. (transport §12; design §5)
- [ ] Tests run against ::1 as well as 127.0.0.1. (transport §12)

## Production readiness & operations (unless a one-off / closed internal tool — say so)
- [ ] Structured logs carry a connection/correlation id; payloads and secrets are never
      logged; error logs are rate-limited. (production-readiness §2)
- [ ] Metrics are exported: open connections, buffered bytes, frames/bytes in/out, errors
      by category, shed count, and a latency histogram. (production-readiness §2)
- [ ] Liveness and readiness are distinct signals; readiness flips to "not ready" on drain.
      (production-readiness §2-3)
- [ ] A hard connection cap sheds excess load (fast reject), rather than queueing unbounded
      work; per-source limits considered. (production-readiness §3)
- [ ] A separate, short handshake timeout guards against slowloris, distinct from the
      steady-state idle timeout. (production-readiness §3; security §7)
- [ ] Graceful drain on SIGTERM: stop accepting, finish in-flight to a deadline, then exit.
      (production-readiness §3)
- [ ] The total memory ceiling (`max_connections × (max_payload + queue)`) is computed and
      fits; the fd cap sits below `ulimit -n`. (production-readiness §4)
- [ ] All limits and timeouts are configuration with safe defaults, validated at startup.
      (production-readiness §5)
- [ ] Retries are backoff+jitter on idempotent operations only; clean-close vs timeout vs
      protocol-error are handled distinctly. (production-readiness §6; pitfalls §8)
- [ ] A version-rollout plan exists (negotiated versions, readers-before-writers,
      reversible). (production-readiness §7)
- [ ] Load test (including beyond the cap), soak test for leaks, and a network-fault test
      have been run. (production-readiness §8; testing §7, §10)
- [ ] Startup logs the effective config; alerts and a symptom→first-check runbook exist.
      (production-readiness §9)

## Spec & tests
- [ ] A written spec exists: frame diagram, field table, message types, state diagram,
      limits, versioning rules, golden examples. (design §12)
- [ ] The minimum test suite passes: one-byte-at-a-time, two-in-one-buffer, short-write,
      golden vectors, arbitrary-bytes-don't-crash, idle-timeout-fires. (testing §12)
- [ ] Integration tests run under simulated loss/latency/reordering. (testing §7)
