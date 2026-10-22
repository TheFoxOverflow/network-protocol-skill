# Packet capture and analysis (tcpdump, Wireshark, Python)

When logs aren't enough, look at the actual bytes on the wire. Packet capture is the
ground truth: it shows you exactly what was sent, in what order, with what timing — which
is the fastest way to resolve "is this our bug or the network's?" This file covers the
three tools you'll reach for and how they fit together, plus a ready-made Wireshark
dissector for the reference protocol in `assets/npro.lua`.

Capture is a debugging aid that complements `references/pitfalls.md`: many bugs there have
a visible signature on the wire (a framing bug shows two messages in one segment; a
partial-read bug shows a message split across segments that the app mishandled). Use the
symptom table at the end to jump from what you see to the likely cause.

## Table of contents

1. [Which tool, when](#1-which-tool-when)
2. [tcpdump — capture](#2-tcpdump--capture)
3. [Wireshark and tshark — analyze](#3-wireshark-and-tshark--analyze)
4. [Reading your own protocol: a Wireshark dissector](#4-reading-your-own-protocol-a-wireshark-dissector)
5. [Python: scapy, pyshark, raw sockets](#5-python-scapy-pyshark-raw-sockets)
6. [TLS and capture](#6-tls-and-capture)
7. [Capturing in containers and Kubernetes](#7-capturing-in-containers-and-kubernetes)
8. [Symptom → what to look for](#8-symptom--what-to-look-for)

---

## 1. Which tool, when

- **tcpdump** — capture on a server, headless, over SSH; lightweight; write a `.pcap` for
  later. The right tool to *grab* traffic where it happens.
- **Wireshark** — interactive analysis on your laptop: open the `.pcap`, follow streams,
  decode fields, read expert warnings. The right tool to *understand* traffic.
- **tshark** — Wireshark's CLI: same dissectors, scriptable, good for automation and for
  pulling specific fields out of a capture in a pipeline.
- **scapy / Python** — when you need to *craft*, *replay*, or *programmatically analyze*
  packets: build a malformed frame to test your parser, replay a captured exchange, or
  extract a custom field at scale.

Typical workflow: reproduce the issue while capturing with **tcpdump** → copy the `.pcap`
to your machine → analyze in **Wireshark** → if you need to script it, **tshark** or
**scapy**.

## 2. tcpdump — capture

`tcpdump` filters use BPF (Berkeley Packet Filter) syntax — this is a **capture filter**
(decides what's recorded), distinct from a Wireshark **display filter** (decides what's
shown). Keep captures small and targeted.

```bash
# Capture on a specific interface, a specific host+port, don't resolve names (-n),
# write raw packets to a file (-w) with full payload (-s 0 = no snaplen truncation).
sudo tcpdump -i eth0 -n -s 0 -w capture.pcap 'tcp port 9000 and host 10.0.0.5'

# Print to the terminal instead, with verbose decoding and ASCII+hex payload (-A / -X).
sudo tcpdump -i eth0 -n -X 'tcp port 9000'

# Loopback traffic (a local client+server) is on the loopback interface, not eth0:
sudo tcpdump -i lo -n 'tcp port 9000'

# Ring buffer for long-running capture: 10 files of 100 MB, oldest overwritten — so you
# can leave it running until the rare bug reproduces without filling the disk.
sudo tcpdump -i eth0 -n -s 0 -w cap.pcap -C 100 -W 10 'tcp port 9000'

# Only packets with payload (drop empty ACKs) — TCP data segments only:
sudo tcpdump -i eth0 -n 'tcp port 9000 and (tcp[tcpflags] & tcp-push != 0)'
```

Key flags: `-i` interface (`any` captures all, but loses some link detail), `-n` no DNS,
`-s 0` capture the whole packet (older defaults truncated to 68/96 bytes and hid your
payload), `-w file` write pcap, `-r file` read it back, `-c N` stop after N packets.
Common BPF primitives: `host`, `net`, `port`, `portrange`, `src`/`dst`, combined with
`and`/`or`/`not`. Capturing requires root (or `CAP_NET_RAW`).

## 3. Wireshark and tshark — analyze

Open the `.pcap` in Wireshark. The highest-value features:

- **Display filters** (different syntax from capture filters): `tcp.port == 9000`,
  `tcp.flags.reset == 1`, `tcp.analysis.retransmission`, `tcp.len > 0`,
  `ip.addr == 10.0.0.5`. Wireshark flags problems for you under
  `tcp.analysis.flags` (retransmissions, zero-window, out-of-order, duplicate ACKs).
- **Follow → TCP Stream**: reassembles one connection's bytes in each direction — the
  single most useful view for a custom protocol. You see the actual application byte
  stream, which is exactly what your parser sees.
- **Decode As…**: tell Wireshark to apply a dissector (e.g. your Lua one, or TLS) to a
  port it doesn't recognize.
- **Statistics → Conversations / I/O Graph / Expert Information**: who talked to whom, how
  throughput evolved, and a categorized list of anomalies (warnings/errors/notes).

tshark for the command line and automation:

```bash
# Read a capture and print a custom protocol's fields (after loading a dissector).
tshark -r capture.pcap -Y 'tcp.port == 9000' -T fields -e frame.number -e tcp.len -e npro.type

# Live capture + decode on a port using your Lua dissector (see §4):
tshark -i eth0 -d tcp.port==9000,npro -O npro -Y 'npro'

# Show TCP retransmissions only — a quick health check of the path.
tshark -r capture.pcap -Y 'tcp.analysis.retransmission'
```

## 4. Reading your own protocol: a Wireshark dissector

Wireshark only decodes protocols it knows. For a custom wire format you write a
**dissector** so capture shows your fields (type, flags, length, payload) instead of an
opaque blob. A Lua dissector needs no build and drops into Wireshark's plugins folder.

`assets/npro.lua` is a complete, commented dissector for the reference protocol in
`assets/framed_protocol.py` (magic `NPRO`, 1-byte version, 1-byte type, 2-byte flags,
4-byte length, then payload). The single most important detail it demonstrates:

- **TCP desegmentation.** Because TCP is a byte stream (golden rule 1), one frame can span
  several TCP segments, or several frames can share one segment. A correct dissector sets
  `pinfo.desegment_len` to ask Wireshark for more bytes when the declared length isn't all
  present yet — the *exact same* "buffer until you have a whole message" logic your
  application parser must implement. A dissector that assumes one segment = one message has
  the same bug this skill warns about, just in Lua.

Install it by copying to the Wireshark plugins directory (Help → About → Folders shows the
path; typically `~/.local/lib/wireshark/plugins/` on Linux or
`%APPDATA%\Wireshark\plugins\` on Windows), then reload Lua plugins or restart. Use
*Decode As → NPRO* on your port, or it auto-binds to the port set in the script.

For production protocols, a heuristic dissector (recognizes the magic instead of a fixed
port) is more robust; the asset notes how to register one.

## 5. Python: scapy, pyshark, raw sockets

Use Python when you need to generate or process packets programmatically.

**scapy** — craft, sniff, and dissect:
```python
from scapy.all import sniff, wrpcap, TCP, raw

# Sniff 100 packets on a port and save them (needs root / CAP_NET_RAW).
pkts = sniff(iface="eth0", filter="tcp port 9000", count=100)
wrpcap("out.pcap", pkts)

# Pull the application payload out of each data segment for your own parsing.
for p in pkts:
    if TCP in p and p[TCP].payload:
        segment = bytes(p[TCP].payload)   # feed this to your FrameReader-style parser
```
scapy is also ideal for **adversarial testing**: build a frame with a bogus length field
or truncated body and send it to your server to confirm it rejects it cleanly (pairs with
the fuzzing in `references/testing.md`).

**pyshark** — drive tshark's dissectors from Python (so your Lua dissector's fields are
available as attributes):
```python
import pyshark
cap = pyshark.FileCapture("capture.pcap", display_filter="npro")
for pkt in cap:
    print(pkt.npro.type, pkt.npro.length)   # fields named by your dissector
```

**Raw sockets / stdlib** — when you only need to *write* a pcap of frames you already have
(e.g. from a test), the stdlib is enough: write the 24-byte pcap global header and a
16-byte per-record header before each packet. No dependency, fully portable — useful for
turning a reproduced exchange into a `.pcap` you can open in Wireshark.

Choose by task: scapy to craft/replay, pyshark to reuse Wireshark dissection in Python,
raw stdlib to emit pcap without dependencies.

## 6. TLS and capture

If the connection is TLS (as it should be in production, security §1), the captured
payload is **ciphertext** — you'll see the TLS handshake and then encrypted records, not
your frames. Two honest options:

- **For debugging only**, have the client (or server) export session keys via the
  `SSLKEYLOGFILE` environment variable and point Wireshark at that keylog file
  (Preferences → Protocols → TLS → (Pre)-Master-Secret log filename). Wireshark then
  decrypts the stream and your dissector runs on the plaintext. Python's `ssl` can write
  this with `SSLContext.keylog_filename`. **Never** enable this in production — it defeats
  the encryption.
- **Capture at the plaintext boundary** instead — e.g. on the loopback side of a local TLS
  terminator, or before the client wraps the socket. Often simpler and safer than handling
  keys.

Do not try to "capture around" TLS by disabling verification or downgrading — that's the
anti-pattern security §1 exists to prevent.

## 7. Capturing in containers and Kubernetes

- The traffic you want may be in a **different network namespace** (the container's), so
  `tcpdump` on the host's `eth0` won't see it. Run tcpdump *inside* the pod/container, or
  use `nsenter`/`kubectl debug` to enter the pod's network namespace.
- `kubectl debug -it <pod> --image=nicolaka/netshoot --target=<container>` attaches an
  ephemeral container sharing the pod's network namespace, with tcpdump/tshark available.
- Remember overlay networks change what you see: with a VXLAN CNI you may capture the
  encapsulated outer packets on the node and the inner packets inside the pod. See
  `references/cloud-and-orchestration.md` for the MTU/overlay implications.

## 8. Symptom → what to look for

| On the wire you see… | Likely cause | Where to look |
|---|---|---|
| Two of your messages inside one TCP segment | Receiver assumes 1 segment = 1 message | pitfalls §1.1; Follow TCP Stream |
| One message split across segments, app mishandles tail | Missing read loop / partial read | pitfalls §2.1 |
| Many retransmissions, growing RTT | Real packet loss / congestion on the path | `tcp.analysis.retransmission` |
| `RST` right after connect | Server rejected/closed; or LB/firewall reset | pitfalls §5; cloud §LB/firewall |
| Connection idle, then `RST` from a middlebox | LB/NAT idle timeout shorter than your heartbeat | design §8; cloud §LB idle timeout |
| Zero-window / stalled sender | Receiver not draining; backpressure | pitfalls §9 |
| Garbled field values in your dissector | Endianness / struct padding on the wire | pitfalls §3 |
| Large frame never completes; body trickles in | Slow-body peer (or undersized MTU fragmenting) | security §7; cloud §MTU |
| TLS handshake then a fatal alert | Cert/hostname/mTLS verification failed | security §1-2 |

When the capture and your logs disagree, the capture is right — it's the bytes that
actually crossed the wire.
