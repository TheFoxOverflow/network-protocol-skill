# network-protocol

A Claude skill for designing, implementing, reviewing and debugging network protocols
and client/server wire communication over TCP, UDP, QUIC, TLS, WebSockets, Unix domain
and raw sockets.

Author: [TheFoxOverflow](https://github.com/TheFoxOverflow) ·
Repository: <https://github.com/TheFoxOverflow/network-protocol-skill> · License: MIT

## What it does

- **Design & implement**: framing, binary wire formats, RPC, handshakes, versioning,
  timeouts, backpressure and the defensive patterns that keep a protocol safe against
  hostile peers.
- **Debug**: spots the common failure modes such as merged or split messages, partial
  reads and writes, hangs that never time out, intermittent corruption, connections
  that drop without anyone noticing, and code that works on localhost but fails over a
  real network.
- **Review**: a production-readiness and security checklist for protocol code.
- **Observe**: packet capture and analysis with tcpdump, Wireshark/tshark, scapy and
  custom Lua dissectors.
- **Deploy**: troubleshooting in cloud and orchestrated networks (AWS VPC, GCP,
  Kubernetes/CNI, load balancers, MTU, NAT).
- **Learn**: a study aid for networking certifications (CCNA, subnetting, OSI/TCP-IP,
  routing and switching).

The skill ships a reference Python implementation of a framed protocol with a test
suite, a Wireshark dissector, a Kubernetes deployment example and a subnetting practice
script under `skills/network-protocol/assets/`.

## Installation

### As a Claude Code plugin

```
/plugin marketplace add TheFoxOverflow/network-protocol-skill
/plugin install network-protocol
```

### As a plain skill

Copy (or symlink) `skills/network-protocol/` into your skills directory:

```bash
# project-level
cp -r skills/network-protocol .claude/skills/

# user-level (available in every project)
cp -r skills/network-protocol ~/.claude/skills/
```

Claude loads the skill on its own when you work on socket or protocol code, analyze
captures, or study networking topics. No further setup is required.

## Repository layout

```
.claude-plugin/plugin.json          plugin manifest
skills/network-protocol/
  SKILL.md                          entry point: golden rules, workflow, symptom table
  references/
    pitfalls.md                     bug catalog with wrong/right code
    protocol-design.md              framing, headers, versioning, state machines, UDP reliability
    transport-and-io.md             socket layer: read/write loops, timeouts, async, IPv6
    security.md                     TLS/mTLS, auth, replay protection, DoS resistance
    testing.md                      chunk-boundary tests, fuzzing, fault injection, golden vectors
    production-readiness.md         observability, connection caps, graceful drain, rollout
    packet-analysis.md              tcpdump, Wireshark/tshark, scapy, dissectors, TLS decryption
    cloud-and-orchestration.md      AWS/GCP/Kubernetes networking, LB idle timeouts, PROXY protocol
    learning-mode.md                CCNA / Network+ study partner
    review-checklist.md             pre-ship checklist
  assets/
    framed_protocol.py              reference library: bounded length-prefixed protocol over TCP
    test_protocol.py                test suite for the reference library
    pyproject.toml                  pytest / mypy / ruff config
    cross-language-notes.md         the same patterns in Go, Rust, C and Node.js
    npro.lua                        Wireshark dissector for the reference format
    k8s-deployment.yaml             Kubernetes manifest for the reference server
    subnetting_practice.py          subnetting drill for certification study
```

## Running the reference code

```bash
cd skills/network-protocol/assets
python3 framed_protocol.py                  # loopback demo
python3 -m pytest test_protocol.py          # test suite (needs pytest; TLS tests need cryptography)
python3 subnetting_practice.py --selftest   # verify the subnetting drill
```

Requires Python 3.10+. The reference library itself has no third-party dependencies.

## Contributing

Issues and pull requests are welcome. If you add a pitfall, please include the symptom,
the root cause, a wrong/right example and a test that provokes it, following the
format in `references/pitfalls.md`.
