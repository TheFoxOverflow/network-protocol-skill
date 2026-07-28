# Security for untrusted peers and networks

Assume the network is hostile (eavesdroppers, tamperers, spoofers) and the peer is hostile
(has read your code, wants to crash you, exhaust your resources, or trigger duplicate
actions). Skipping this is only acceptable in a closed, fully-trusted environment — and if
you do, say so explicitly.

**Threat model and residual risk.** The defenses here (and in `assets/framed_protocol.py`,
which implements TLS/mTLS via `make_server_tls_context`/`make_client_tls_context`, bounded
allocation, an O(n) parser, per-message/per-handshake deadlines, and global + per-IP
connection caps) raise the bar substantially against a remote attacker who can send
arbitrary bytes and open many connections. They are **not** a guarantee of
invulnerability: security still depends on correct key and certificate management, the
secrecy of private keys, the soundness of TLS/OpenSSL and the runtime, your application's
authn/authz and business logic, and the security of the hosts themselves. Treat "harden
against the realistic threat model + defense in depth" as the goal, not "unbreakable".

## Table of contents

1. [Encrypt with TLS — don't invent crypto](#1-encrypt-with-tls)
2. [Authentication](#2-authentication)
3. [Integrity](#3-integrity)
4. [Replay protection](#4-replay-protection)
5. [Constant-time comparison](#5-constant-time-comparison)
6. [Input validation as security](#6-input-validation-as-security)
7. [Denial-of-service resistance](#7-denial-of-service-resistance)
8. [Text-protocol injection & smuggling](#8-text-protocol-injection--smuggling)
9. [Secure defaults & operational hygiene](#9-secure-defaults--operational-hygiene)

---

## 1. Encrypt with TLS

Never design your own encryption or key exchange. Use **TLS** (1.2+; prefer 1.3) over TCP,
or **QUIC** (which is TLS 1.3 built in), or a vetted protocol library (Noise, libsodium).

The single most common TLS bug is **disabling certificate verification** to "make it work":

```python
# WRONG — disables the entire point of TLS; vulnerable to trivial MITM
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```
```python
# RIGHT — verify the certificate chain AND the hostname
ctx = ssl.create_default_context()          # verification + hostname check ON by default
sock = ctx.wrap_socket(raw_sock, server_hostname=host)
```

- **Validate the certificate chain and the hostname.** Hostname verification is separate
  from chain validation; both are required.
- **mTLS (mutual TLS):** for service-to-service auth, have both sides present and verify
  certificates.
- **Layering:** TLS gives you a secure byte stream; your framing (length-prefix, etc.) sits
  *inside* the TLS stream exactly as it would over plain TCP. With TLS/QUIC you generally do
  **not** need your own checksums or MACs — the transport provides integrity.
- **Cipher selection:** rely on the library's modern defaults; don't enable legacy
  protocols/ciphers. Prefer forward-secret suites (the defaults in TLS 1.3).

## 2. Authentication

- **Exchange credentials in the handshake**, over TLS — never send plaintext secrets over
  an unencrypted channel.
- **Prefer asymmetric / token-based auth** (mTLS certs, signed tokens, API keys exchanged
  over TLS) over sending raw passwords.
- **Channel binding:** where supported, bind the auth to the TLS session so a stolen token
  can't be replayed on a different connection.
- **Authenticate before acting:** don't perform privileged operations (or large allocations)
  for an unauthenticated peer.
- **Don't leak which factor failed** (e.g. "unknown user" vs "bad password") to untrusted
  peers; return a generic auth failure.

## 3. Integrity

- Over TLS/QUIC, integrity is provided — you usually need nothing more.
- Over a plain channel where you can't use TLS, use an **AEAD** cipher (e.g.
  ChaCha20-Poly1305, AES-GCM) or a proper **MAC** (HMAC). Never roll your own MAC, and use
  **encrypt-then-MAC** or an AEAD rather than MAC-then-encrypt.
- A plain CRC/checksum detects *accidental* corruption only; it is **not** security against
  a tamperer (they recompute it). Use it only for non-adversarial error detection, and only
  where TLS/QUIC isn't already covering you.

## 4. Replay protection

An attacker can capture and re-send valid ciphertext/messages.

- **Within a session:** include monotonically increasing sequence numbers or per-message
  nonces; reject duplicates or out-of-window values (pitfalls §10.4). AEAD with a unique
  nonce per message also defeats reordering/replay if you check the counter.
- **Across sessions / for authentication:** include a server-provided random **nonce** /
  challenge in the handshake so a captured handshake can't be replayed; or a **timestamp**
  with a bounded acceptance window plus a seen-nonce cache to reject duplicates inside the
  window.
- **Idempotency** (pitfalls §8.2) limits the damage of replays of state-changing operations
  even when other defenses miss.

## 5. Constant-time comparison

Comparing secrets (tokens, MACs, passwords) with a normal byte comparison leaks length and
content via timing (it returns early on the first mismatch), enabling a timing attack.

```python
# WRONG — early-exit comparison leaks timing
if received_token == expected_token: ...
```
```python
# RIGHT — constant-time
import hmac
if hmac.compare_digest(received_token, expected_token): ...
```
Equivalents: Go `crypto/subtle.ConstantTimeCompare`, Rust `subtle`/`ring`, Node
`crypto.timingSafeEqual`. Use them for every secret comparison.

## 6. Input validation as security

Every field from the wire is attacker-controlled. Validate **before** acting (rule 9):

- **Bound all lengths, counts, and offsets** against hard maxima before allocating or
  indexing (pitfalls §4) — the most important single DoS defense.
- **Range-check enums / types / flags;** reject reserved values and non-zero reserved bits.
- **Validate state-legality:** is this message type allowed in the current protocol state?
  (pitfalls §10.1)
- **Canonicalize and validate text** (UTF-8 well-formedness, no embedded NULs where
  forbidden, no control characters where they could inject) before use.
- **Validate offsets/indices against the actual buffer length** in memory-unsafe languages
  to prevent out-of-bounds access.
- **Fail closed:** on anything malformed, reject and (usually) close, rather than guessing.

## 7. Denial-of-service resistance

A single peer must not be able to exhaust your CPU, memory, or fds.

- **Untrusted length → bounded allocation / streaming** (pitfalls §4.1). Hard cap on message
  size, enforced before allocating.
- **Decompression bombs:** if you accept compressed data, bound the *decompressed* output
  size and stop decompressing past the limit. A few KB can expand to many GB.
- **Slowloris / slow-read / slow-write:** a peer that sends/reads one byte at a time ties up
  a connection indefinitely. Defend with per-connection idle and total-operation timeouts
  (§transport-and-io §5), a minimum-throughput requirement, and a cap on concurrent
  connections.
- **Connection / request floods:** limit concurrent connections per source, total
  connections, and in-flight requests per connection; apply rate limiting; shed load with an
  explicit error rather than falling over.
- **Amplification (UDP):** never send a response larger than the request to an unverified
  source; require a handshake/cookie first (pitfalls §11.4).
- **Algorithmic-complexity attacks:** untrusted input that drives hashing (hash-flooding),
  regex (catastrophic backtracking), or quadratic parsing can burn CPU. Use
  collision-resistant/seeded hash maps, avoid backtracking regex on untrusted input, and
  keep parsing linear.
- **Per-peer accounting:** track and bound the resources each peer consumes so one peer
  can't starve others.

## 8. Text-protocol injection & smuggling

For text/line-based protocols:

- **CRLF / header injection:** if user-controlled data is placed into a line-structured
  message without sanitization, an attacker can inject `\r\n` and forge new lines/headers.
  Reject or escape control characters in any field that becomes part of the framing.
- **Request smuggling:** if two parties disagree about message length (e.g. a length field
  vs a delimiter, or duplicate length indicators), an attacker can desynchronize them.
  Define exactly one authoritative framing and reject ambiguous/duplicate length signals.

## 9. Secure defaults & operational hygiene

- **Fail closed**, not open: errors and unknowns deny rather than allow.
- **Don't log secrets** (tokens, keys, passwords, full payloads with PII).
- **Generic errors outward, detail inward:** untrusted peers get a generic error; full
  detail goes to your logs/metrics.
- **Least privilege:** authenticate and authorize before performing privileged actions or
  expensive work.
- **Keep crypto current:** disable deprecated TLS versions/ciphers; rely on maintained
  libraries and update them.
- If proxying/forwarding requests, beware **SSRF / confused-deputy**: validate and restrict
  destinations a peer can make you connect to.
