# Learning mode — networking certification helper (CCNA and friends)

This mode turns the skill into a study partner for networking fundamentals and
certifications (Cisco CCNA 200-301, CompTIA Network+, and the general theory behind them).
It is for *learning*, so the approach is different from the rest of the skill: explain
concepts clearly, then practice with active recall rather than just handing over answers.

It also connects the theory to the hands-on parts of this skill: the OSI layers map onto
"which layer is your protocol" (`references/protocol-design.md`), TCP/UDP behavior is the
source of half the bugs in `references/pitfalls.md`, MTU shows up in
`references/cloud-and-orchestration.md`, and you can watch every concept on the wire with
`references/packet-analysis.md`. Theory sticks better when you can see it in a capture.

`assets/subnetting_practice.py` is a runnable subnetting drill (generates random problems
and checks answers, pure standard library).

## How to use this mode

- **Teach, then test.** When the learner asks about a topic, give a crisp explanation with
  a concrete example, then offer a practice question. Don't just dump facts.
- **Hint before answer.** On a practice question, if they're stuck or wrong, give a hint
  and let them try again before revealing the full solution. Reaching the answer
  themselves is what builds recall.
- **Explain the wrong answer.** When they miss one, explain *why* the wrong choice is
  tempting and what distinguishes the right one — the misconception is the thing to fix.
- **Use scenarios, not just definitions.** "A host in VLAN 10 can't reach the gateway —
  walk through what you'd check" teaches more than "define a VLAN".
- **Active recall and spacing.** Revisit earlier topics in later questions; ask the learner
  to explain a concept back in their own words.

State the honest caveat when relevant: this is a study aid, not official courseware, and a
language model can be wrong on specifics (exact command syntax, current exam blueprint).
Verify against official Cisco material and practice on real or simulated gear.

## CCNA 200-301 domain map

The exam is organized into six domains; use this to structure study and to locate a topic.

1. **Network Fundamentals** — OSI and TCP/IP models; cabling and interfaces; IPv4
   addressing and **subnetting**; IPv6 addressing; TCP vs UDP; switching/routing concepts.
2. **Network Access** — VLANs and trunking (802.1Q); inter-switch links; **Spanning Tree
   Protocol** (loop prevention); EtherChannel (link aggregation); wireless fundamentals
   (APs, WLCs, SSIDs).
3. **IP Connectivity** — the routing table and route selection (longest prefix match,
   administrative distance, metric); static routing; **OSPF** (single-area) fundamentals;
   first-hop redundancy concepts.
4. **IP Services** — **NAT/PAT**; DHCP and DNS; NTP; SNMP and syslog; QoS concepts;
   SSH for device management.
5. **Security Fundamentals** — access control concepts; **ACLs**; Layer 2 security (port
   security, DHCP snooping, dynamic ARP inspection); VPNs at a concept level; AAA.
6. **Automation and Programmability** — controller-based vs traditional networking; SDN
   concepts; REST APIs; data formats (JSON); config management (Ansible/Puppet/Chef)
   at a conceptual level.

## Core topics, briefly (and where they connect)

- **OSI vs TCP/IP model.** Seven layers (Physical, Data Link, Network, Transport, Session,
  Presentation, Application) vs the practical four-layer TCP/IP stack. The point for this
  skill: your custom protocol lives at the application layer *on top of* L4 (TCP/UDP), and
  the famous "TCP is a byte stream" rule (pitfalls §1) is a Transport-layer fact you build
  framing on top of.
- **Encapsulation.** Each layer wraps the one above (segment → packet → frame → bits). A
  capture (packet-analysis §3) literally shows these headers nested — the best way to make
  encapsulation concrete.
- **IPv4 addressing and subnetting.** Network vs host bits, masks, CIDR; computing network
  address, broadcast, and usable host range; subnetting and VLSM. This is the highest-yield
  CCNA skill and the most worth drilling — use the practice asset below.
- **TCP vs UDP.** TCP: connection-oriented, reliable, ordered, flow- and congestion-
  controlled (the three-way handshake, sequence/ACK numbers). UDP: connectionless,
  unreliable, no ordering — you add what you need (pitfalls §11). Knowing *why* TCP behaves
  as it does explains the partial-read and framing pitfalls directly.
- **VLANs, trunking, STP.** VLANs segment a switch into broadcast domains; 802.1Q tags
  frames on trunks; STP prevents loops by blocking redundant links. Mostly L2 context for
  the rest.
- **Routing.** How a router chooses a path: longest-prefix match first, then administrative
  distance between sources, then metric within a protocol. Static vs dynamic (OSPF).
- **NAT/PAT.** Translating private to public addresses (and many-to-one via ports). This is
  the same NAT that complicates cloud deployments and hides the client IP
  (cloud-and-orchestration §4) — theory and practice meet here.
- **ACLs.** Permit/deny rules matched top-down; the basis of the default-deny firewalls in
  every cloud (cloud-and-orchestration §5–7).

## Subnetting: the method

Subnetting is mechanical once you internalize the steps; speed comes from practice.

1. **Know the mask ↔ prefix ↔ block size.** A `/n` mask has `n` network bits. In the
   "interesting" octet, the block size is `256 − mask_octet`. Example: `/26` → mask
   `255.255.255.192`, interesting octet 192, block size 64. Subnets step by 64 in that
   octet: .0, .64, .128, .192.
2. **Find the network the host falls in.** Round the host's interesting octet down to the
   nearest multiple of the block size. `192.168.1.100/26`, block 64 → 100 falls in the .64
   subnet → network `192.168.1.64`.
3. **Broadcast = next network − 1.** `.64` block of size 64 → broadcast `192.168.1.127`.
4. **Usable host range** is network+1 .. broadcast−1 (for `/24`–`/30`). Here `.65`–`.126`.
5. **Counts.** Usable hosts per subnet = `2^host_bits − 2`. Subnets created when borrowing
   `b` bits = `2^b`. (`/31` is a special 2-host point-to-point case; `/32` is a single host.)

Drill all five until they're automatic for any prefix — that's the asset's job.

## Running a practice session

Use `assets/subnetting_practice.py`:

```bash
python3 subnetting_practice.py              # interactive quiz with hints
python3 subnetting_practice.py --selftest   # verify the generator/checker (no input)
```

Beyond subnetting, you can ask this mode to: generate practice questions on any domain
above, run a timed mini-quiz, explain a missed concept, walk a troubleshooting scenario
("no connectivity between two VLANs — diagnose"), or quiz you on command output.

## Hands-on (the theory only sticks if you touch it)

- **Cisco Packet Tracer** or **GNS3 / CML** to build and break topologies safely.
- **A real capture** of your own traffic (packet-analysis §2) to *see* the three-way
  handshake, ARP, DHCP, DNS, and your own frames — pairing the cert theory with real bytes
  is the fastest way to make it permanent.
- Configure SSH, an ACL, a static route, and a DHCP pool on a virtual device; type the
  commands rather than reading them.

Treat the exam blueprint as the source of truth for scope, this mode as a tutor for
understanding, and hands-on labs as where it becomes real.
