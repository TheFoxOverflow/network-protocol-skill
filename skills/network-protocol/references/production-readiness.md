# Production readiness

A protocol can be *correct* — frames right, bounds enforced, timeouts everywhere — and
still not be *production-ready*. Correctness is about the bytes; production readiness is
about running the thing under real load, real failures, and real operators at 3 a.m. This
file covers the layer that the other references don't: observability, lifecycle at scale,
resource governance, rollout, and load/soak testing.

Read this at **step 6 of the workflow**, after the implementation is correct and tested,
and reflect its items in `references/review-checklist.md`. The patterns here are
language-independent; `assets/framed_protocol.py` demonstrates several (connection cap,
load shedding, graceful drain, metrics counters).

## Table of contents

1. [Correct ≠ production-ready](#1-correct--production-ready)
2. [Observability](#2-observability)
3. [Connection lifecycle at scale](#3-connection-lifecycle-at-scale)
4. [Resource governance](#4-resource-governance)
5. [Configuration and limits](#5-configuration-and-limits)
6. [Reliability and failure handling](#6-reliability-and-failure-handling)
7. [Versioning and rollout in production](#7-versioning-and-rollout-in-production)
8. [Capacity, load, and soak testing](#8-capacity-load-and-soak-testing)
9. [Operability and the runbook](#9-operability-and-the-runbook)
10. [Production-readiness gate](#10-production-readiness-gate)

---

## 1. Correct ≠ production-ready

The implementation references get you a protocol that does the right thing when it runs.
Production adds questions they don't answer: When it breaks at 2 a.m., can the on-call
person *see* why? When traffic is 10× the test load, does it degrade gracefully or fall
over? When you deploy a new version, do old and new peers still talk? When a peer is
malicious or just buggy, can one connection starve the other thousands? Those are the
subjects below. None of them are optional for something users depend on.

## 2. Observability

If you cannot see it, you cannot operate it. Build in three signals from the start —
retrofitting them after an incident is too late.

**Structured logging.** Log connection lifecycle events (accept, handshake result, close
with reason), protocol errors with the *category* (framing vs oversize vs reserved-bits),
and slow operations — as structured key/value records, not free text, so they're
queryable. Attach a **connection id** (and, if you have one, a request/correlation id) to
every line so a single session can be reconstructed. Critically:

- **Never log payloads or secrets.** Log sizes, types, and counts — not message bodies,
  tokens, or keys (security §9). A payload dump is both a privacy leak and a log-volume
  bomb.
- **Rate-limit error logs.** A peer that sends garbage in a loop must not let your logs
  (or your log bill) grow without bound. Sample or aggregate repeated errors.
- Log the **effective configuration and limits at startup** (see §5) so an operator can
  confirm what's actually running.

**Metrics.** Export the numbers that tell you health at a glance and feed alerts (§9).
At minimum:

| Kind | Metric | Why it matters |
|---|---|---|
| Gauge | open connections | Saturation against the cap; the load-shedding warning sign |
| Gauge | reassembly/queue bytes buffered | Backpressure building; memory risk (§4) |
| Counter | frames in/out, bytes in/out | Throughput, and the denominator for error rate |
| Counter | errors by category | Framing/oversize/timeout/handshake — each means something different |
| Counter | connections shed at cap | You're undersized, or under attack |
| Histogram | frame size | Set/validate `max_payload`; spot anomalies |
| Histogram | handshake + request latency (p50/p95/p99) | Tail latency is where users feel pain |

The reference `Server` keeps simple counters (`accepted`, `rejected_over_cap`,
`handshake_failures`, `handler_errors`); a real deployment wires these to Prometheus,
StatsD, OpenTelemetry, or equivalent.

**Tracing / correlation.** For multi-hop systems, propagate a trace or correlation id so
a request can be followed across services. Reserve a place for it now — a header field, a
handshake attribute, or a metadata frame — even if you only wire up full tracing later.
Retrofitting an id into a frozen wire format is painful (§7).

**Health and readiness.** Expose a *liveness* signal (the process is up) separate from a
*readiness* signal (it's bound, past warm-up, and below its connection cap). Load
balancers and orchestrators need readiness to route correctly and to drain on shutdown
(§3).

## 3. Connection lifecycle at scale

**Accept-loop hygiene.** The accept loop must outlive any single connection: wrap
`accept()` so a per-connection failure is logged and skipped, and back off briefly on fd
exhaustion (EMFILE/ENFILE) instead of spinning (§5.5; the reference `Server` does both).

**Connection cap + load shedding.** Set a hard maximum on concurrent connections and
**shed** excess load — reject a new peer quickly (a short error then close) rather than
queueing unbounded work that you can't service. An accepted-but-starved connection is
worse than a fast rejection: the client can retry elsewhere or back off. Queueing without
a bound just moves the failure to memory exhaustion. Consider **per-IP / per-identity
limits** too, so one source can't consume every slot.

**Handshake timeout (anti-slowloris).** Bound the handshake with its own short timeout,
separate from the steady-state idle timeout. An attacker who connects and then sends one
byte per minute must not hold a slot indefinitely (security §7). The reference applies
`handshake_timeout` during the handshake, then relaxes to `idle_timeout`.

**Graceful drain on shutdown.** On SIGTERM (rolling deploy, autoscale-down):

1. Flip readiness to "not ready" so the load balancer stops sending new connections.
2. Stop accepting (close the listener).
3. Let in-flight handlers finish, up to a **drain deadline**.
4. Past the deadline, close the stragglers and exit.

Skipping this drops in-flight requests on every single deploy — a self-inflicted error
spike. The reference `Server.shutdown()` + `_drain()` implements stop-accepting-then-wait;
wire it to signals with `install_signal_handlers` from the main thread.

**Zero-downtime restart.** Use `SO_REUSEADDR` (and `SO_REUSEPORT` where you want kernel
load-balancing across processes) so a new instance can bind while the old drains. For true
zero-downtime, start the new instance, let it become ready, then drain the old.

## 4. Resource governance

Every resource a peer can cause you to consume must have a ceiling.

- **File descriptors.** Each connection is an fd; the connection cap (§3) must sit *below*
  the process `ulimit -n`, with headroom for listeners, logs, and upstreams. Raise the
  ulimit deliberately and document it.
- **Memory.** Bound per-connection buffers (`max_payload`), the number of in-flight
  requests, and any outbound queue. The total memory ceiling is roughly
  `max_connections × (max_payload + queue_bound)` — compute it and make sure it fits.
  Unbounded anything is an OOM waiting for the right traffic (§4.1, §9).
- **CPU.** A bounded worker pool (or event loop) caps concurrency so a spike can't spawn
  unbounded threads/tasks. Watch for **algorithmic-complexity** traps where a small
  hostile message causes large work (security §7).
- **Time as a budget.** Treat timeouts as budgets, not just safety nets: a request that
  fans out to N upstreams must divide an overall deadline among them, not stack N full
  timeouts (transport §5). Propagate the remaining budget downstream.
- **Backpressure end to end.** When a consumer is slow, the slowness must propagate back
  to the producer (blocking send, bounded queue, `write()→false`/drain), never silently
  buffer (§9). A bound that triggers backpressure is the goal, not a bug.

## 5. Configuration and limits

- **Externalize the limits.** `max_payload`, all timeouts, `max_connections`, backlog, and
  buffer bounds belong in configuration with safe defaults, not as magic numbers welded
  into the code. You *will* need to tune them per environment without a code change.
- **Validate config at startup and fail fast.** A nonsensical config (idle timeout shorter
  than heartbeat interval, cap above the fd ulimit) should refuse to start with a clear
  message, not misbehave under load.
- **Document every limit and its rationale**, including what a client sees when it's hit
  (which error, whether to retry). Undocumented limits become mystery incidents.
- **Safe defaults.** Defaults should be safe for a hostile internet (conservative sizes
  and timeouts, security on), with relaxation an explicit opt-in — not the reverse.

## 6. Reliability and failure handling

- **Retries with backoff + jitter, on idempotent operations only.** Retrying a
  non-idempotent operation duplicates its effect (§8). Make operations idempotent (request
  ids / idempotency keys) so a retry after an ambiguous timeout is safe, and cap retries
  with exponential backoff *plus jitter* to avoid synchronized retry storms.
- **Circuit breaking / load shedding outward.** When an upstream is failing, stop hammering
  it — open a breaker and fail fast — so you don't convert one slow dependency into total
  collapse. Shed your own load (§3) before you fall over.
- **Distinguish failure modes.** "Peer closed cleanly", "we timed out", and "peer sent
  garbage" need different handling: a clean close may be normal, a timeout may be
  retryable, malformed input is a protocol error to log and drop. The reference's exception
  hierarchy (`ConnectionClosed` / `ProtocolTimeout` / `ProtocolError`) exists for exactly
  this routing.
- **Graceful degradation.** Decide ahead of time what a partial failure looks like: serve
  stale data, drop optional features, or shed low-priority traffic — rather than failing
  the whole request.

## 7. Versioning and rollout in production

The wire format *will* change. Plan for two versions running at once during every deploy.

- **Negotiate versions in the handshake** (the reference exchanges a `[min,max]` range and
  picks the highest common version). A peer must never assume the other side's version.
- **Never make a breaking wire change in a single deploy.** Roll out in compatible steps:
  teach everyone to *read* the new form before anyone *writes* it; add fields as optional
  with safe defaults; gate new behavior behind a negotiated version or feature flag.
- **Readers before writers.** Deploy the version that understands a new message type first,
  across the whole fleet, before any instance emits it. Otherwise old instances reject
  traffic mid-rollout.
- **Canary and watch the metrics.** Roll the new version to a small slice first; watch
  error-by-category and latency before continuing. Keep the change reversible — be able to
  roll back without a wire-incompatibility.
- **Reserve space for evolution now.** A version byte, reserved flag bits required to be
  zero, and a length-prefixed extensible header cost almost nothing today and are the
  difference between a smooth migration and a flag day later (design §5).

## 8. Capacity, load, and soak testing

Functional tests prove correctness; these prove it survives production.

- **Load test to the knee.** Drive increasing connection and request rates until latency
  degrades; that knee is your real capacity. Measure throughput **and** tail latency
  (p99), not averages — the tail is what users feel. Test *at and beyond* the connection
  cap to confirm load shedding behaves (fast rejection, not collapse).
- **Soak test for leaks.** Run at steady load for hours/days and watch fd count, memory,
  and buffer gauges for slow upward drift. Leaks and unbounded buffers are invisible in a
  60-second test and obvious in a 6-hour one (testing §10).
- **Chaos / fault injection in the large.** Beyond unit-level short reads, inject real
  network conditions between hosts: latency, loss, reordering, and bandwidth limits with
  `tc`/`netem`, and connection-level faults (cut, freeze, slow) with a proxy like Toxiproxy
  (testing §6-7). Kill the peer mid-message; freeze it with SIGSTOP to confirm timeouts and
  heartbeats fire.
- **Benchmark and track regressions.** Record p50/p99 latency and throughput as numbers you
  re-check each release, so a performance regression is caught before users find it.

## 9. Operability and the runbook

- **Startup log.** Emit the effective config and limits, the bound address, and the build
  version — the first thing an operator checks.
- **Alerts worth paging on.** Error rate by category over a threshold; p99 latency over
  budget; open connections approaching the cap; buffered bytes approaching the memory
  ceiling; a spike in handshake failures (possible attack or a bad rollout); connections
  shed at cap (undersized or under attack).
- **Symptom → first check.** Pre-write the obvious diagnoses so on-call doesn't start from
  zero: hangs → which timeout isn't set / a write-write deadlock (pitfalls §6.5, §8);
  memory climb → unbounded buffer or missing backpressure (§4, §9); error spike right after
  a deploy → version incompatibility (§7); CPU spike on small input → algorithmic-complexity
  attack (security §7).
- **Rollback path.** Know how to roll back the protocol version safely (it must stay
  wire-compatible with the still-deployed peers, §7) and have it rehearsed, not theoretical.

## 10. Production-readiness gate

Before declaring it production-ready, confirm — and add these to the review checklist:

- [ ] Structured logs with a connection/correlation id; no payloads or secrets logged;
      error logs rate-limited. (§2)
- [ ] Metrics exported: open connections, buffered bytes, frames/bytes, errors by category,
      shed count, latency histogram. (§2)
- [ ] Liveness and readiness signals are distinct; readiness flips on drain. (§2-3)
- [ ] Hard connection cap with load shedding; per-source limits considered. (§3)
- [ ] Separate, short handshake timeout (anti-slowloris) plus steady-state idle timeout. (§3)
- [ ] Graceful drain on SIGTERM: stop accepting, finish in-flight to a deadline, then exit. (§3)
- [ ] Total memory ceiling computed (`max_connections × (max_payload + queue)`) and fits;
      fd cap below `ulimit -n`. (§4)
- [ ] All limits and timeouts are configuration with safe defaults; config validated at
      startup. (§5)
- [ ] Retries are backoff+jitter on idempotent ops only; failure modes routed distinctly. (§6)
- [ ] Versions negotiated; rollout plan is readers-before-writers and reversible. (§7)
- [ ] Load test (incl. beyond the cap), soak test for leaks, and network-fault test all run. (§8)
- [ ] Startup logs effective config; alerts and a symptom→check runbook exist. (§9)

If an item legitimately doesn't apply (e.g. a single-client internal tool), say *why*
rather than skipping it silently.
