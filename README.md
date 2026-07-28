# network-protocol

An Agent Skill for designing, building, reviewing, and debugging network protocols. The
focus is on the bugs that slip past code review and unit tests and only show up in
production, like messages that arrive merged or split, hangs with no timeout, and memory
blowups under load.

It also covers three related jobs: looking at a protocol on the wire, deploying one into
cloud and Kubernetes networks, and studying networking for certs like the CCNA.

Works with Claude and with Gemini. The skill folder is the same for both, since `SKILL.md`
is an open format that several agent tools read the same way.

## What you get

A reference library that is built like real code, not a demo:

- Length-prefixed framing with an O(n) incremental parser
- A typed exception hierarchy, so "peer left" and "we timed out" and "peer sent garbage"
  are handled separately
- Optional TLS and mutual TLS with certificate and hostname checks
- Per-message and per-handshake deadlines
- A server with global and per-IP connection limits, load shedding, and graceful drain
- 26 tests that run under `pytest` or on their own

Plus documentation that covers the parts people usually skip: a catalog of real bugs,
congestion control and flow control, IPv6 and dual-stack, security against hostile peers,
production readiness, and a pre-ship checklist.

## Contents

```
network-protocol/
├── SKILL.md                      # entry point, read first
├── references/
│   ├── pitfalls.md               # the bug catalog
│   ├── protocol-design.md        # framing, versioning, flow and congestion control
│   ├── transport-and-io.md       # socket layer, timeouts, IPv6 and dual-stack
│   ├── security.md               # TLS, auth, replay, DoS resistance
│   ├── testing.md                # how to provoke the failures
│   ├── production-readiness.md   # observability, caps, drain, rollout
│   ├── packet-analysis.md        # tcpdump, Wireshark, scapy
│   ├── cloud-and-orchestration.md# AWS VPC, GCP, Kubernetes and CNI
│   ├── learning-mode.md          # CCNA study partner
│   └── review-checklist.md       # the final gate
└── assets/
    ├── framed_protocol.py        # the reference library
    ├── test_protocol.py          # 26 tests
    ├── pyproject.toml            # packaging, pytest, mypy, ruff
    ├── cross-language-notes.md   # same patterns in Go, Rust, C, Node.js
    ├── npro.lua                  # Wireshark dissector
    ├── k8s-deployment.yaml       # Kubernetes manifest
    └── subnetting_practice.py    # subnetting drill
```

## Install for Claude

### claude.ai (browser, desktop, mobile)

1. Turn on code execution and file creation under Settings, then Capabilities. Skills
   won't run without it. On Team and Enterprise an owner enables this and Skills at the
   organization level first.
2. Get `network-protocol.zip` from Releases, or build it yourself from the repo root:
   ```bash
   zip -r network-protocol.zip network-protocol
   ```
   The ZIP root has to be the `network-protocol/` folder itself. Check with
   `unzip -l network-protocol.zip | head`, where the first entry should be
   `network-protocol/SKILL.md`.
3. Open Customize, then Skills, click "+", then "+ Create skill", and upload the ZIP.
4. Make sure the toggle next to the skill is on.

### Claude Code

No ZIP needed, it reads from the filesystem:

```bash
mkdir -p ~/.claude/skills && cp -r network-protocol ~/.claude/skills/   # all projects
mkdir -p .claude/skills && cp -r network-protocol .claude/skills/       # one project
```

Check with `/skills` inside a session.

## Install for Gemini

### Gemini CLI

```bash
mkdir -p ~/.gemini/skills && cp -r network-protocol ~/.gemini/skills/   # all projects
mkdir -p .gemini/skills && cp -r network-protocol .gemini/skills/       # one project
```

Check with `/skills list`. Use `/skills reload` if you added it while a session was open.

### Gemini Enterprise

Open Skills in the navigation menu, click Import, and upload `network-protocol.zip`.

One thing to watch: the Enterprise docs call the prompt file `skill.md` in lowercase,
while the standard name used here is `SKILL.md`. If the import rejects the package, rename
it and zip again.

### Not a good fit: consumer Gems

Gems in the normal Gemini app are single saved prompts with a length limit and no file
structure, so a multi-file skill does not map onto them without collapsing it into one
shortened prompt and losing the references and the runnable code.

## Using it

You don't call the skill by hand. The agent reads its description and loads it when your
request matches. Some things you can say:

- "Design a binary RPC protocol between a Python client and a Go server, around 10k msgs/s."
- "My TCP server hangs now and then. Here's the code."
- "Messages sometimes arrive merged together over TCP. Why, and how do I fix it?"
- "How do I capture and decode my custom protocol in Wireshark?"
- "My long-lived connections drop after a few minutes behind an AWS NLB."
- "Quiz me on subnetting for the CCNA."

You can also name it directly, for example "Use the network-protocol skill to review this
parser for DoS issues."

## Try the code locally

Python 3.10 or newer, standard library only. The TLS tests have one optional dependency.

```bash
cd network-protocol/assets
python3 framed_protocol.py                  # loopback demo
python3 test_protocol.py                    # 26 tests, no pytest needed
python3 subnetting_practice.py --selftest   # subnetting drill self-check
```

The Wireshark dissector goes in your Wireshark Personal Lua Plugins folder (Help, then
About Wireshark, then Folders), then use Decode As and pick NPRO. The Kubernetes manifest
can be checked with `kubectl apply --dry-run=client -f assets/k8s-deployment.yaml`.

## A note on security

The library is hardened against a realistic threat model: a peer that sends arbitrary
bytes and opens many connections. Lengths are bounded before allocation, the parser cannot
be made quadratic, unauthenticated peers can buffer only a few KB, deadlines defeat slow
dribble attacks, one IP cannot take every slot, and TLS gives encryption and peer
authentication.

That is a strong baseline, not a guarantee. Security still depends on your key and
certificate management, the soundness of TLS and the runtime, your own authorization
logic, and the security of the hosts. Treat it as defense in depth, not as unbreakable.

## License

MIT, see LICENSE. Adapt the wire format, message types, and handshake to fit your case.
The part worth keeping is the structure and the defensive patterns.

## Notes

This is a community skill, not official Anthropic or Google material. The learning mode is
a study aid, so check exact command syntax and the current exam blueprint against official
sources. Product steps describe the Skills features as of mid-2026 and can change.
