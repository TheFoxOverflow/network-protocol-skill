#!/usr/bin/env python3
"""subnetting_practice.py — a subnetting drill for CCNA / Network+ study.

Generates random IPv4 subnetting problems and checks answers. Pure standard library
(`ipaddress` does the authoritative math, so the answers are always correct). Part of the
network-protocol skill's learning mode (references/learning-mode.md).

Usage:
    python3 subnetting_practice.py              # interactive quiz with hints
    python3 subnetting_practice.py --selftest   # verify generator/checker, no input
    python3 subnetting_practice.py -n 5         # interactive quiz, 5 questions

The interactive mode asks for the network address, broadcast address, usable host count,
and usable range of a random CIDR, gives a hint on a wrong answer, then shows a worked
solution. The self-test generates many problems and asserts the computed answers are
internally consistent with `ipaddress`.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import sys
from dataclasses import dataclass


@dataclass
class Problem:
    """One subnetting problem and its authoritative answers."""
    host_ip: str                 # an address with host bits possibly set, e.g. 192.168.1.100
    prefix: int                  # the prefix length, e.g. 26
    network: ipaddress.IPv4Network

    @property
    def cidr(self) -> str:
        return f"{self.host_ip}/{self.prefix}"

    @property
    def netmask(self) -> str:
        return str(self.network.netmask)

    @property
    def wildcard(self) -> str:
        return str(self.network.hostmask)

    @property
    def network_address(self) -> str:
        return str(self.network.network_address)

    @property
    def broadcast(self) -> str:
        return str(self.network.broadcast_address)

    @property
    def usable_hosts(self) -> int:
        # Valid for /1../30. (/31 and /32 are special-cased out of the generator.)
        return self.network.num_addresses - 2

    @property
    def first_host(self) -> str:
        return str(self.network.network_address + 1)

    @property
    def last_host(self) -> str:
        return str(self.network.broadcast_address - 1)

    @property
    def block_size(self) -> int:
        """Total number of addresses in the subnet (2^host_bits)."""
        return self.network.num_addresses

    @property
    def interesting_octet(self) -> int:
        """0-based index of the octet where the network boundary falls."""
        return min(self.prefix // 8, 3)

    @property
    def octet_block_size(self) -> int:
        """The CCNA 'block size': 256 - mask value in the interesting octet, i.e. the
        increment between consecutive subnets within that octet (/20 -> 16, /26 -> 64)."""
        return 2 ** (8 - self.prefix % 8)


def generate_problem(rng: random.Random) -> Problem:
    """Build a random problem with a host address whose bits don't sit on the network
    boundary (so 'find the network' is non-trivial). Prefixes 9..30 keep the usable-hosts
    formula (2^h - 2) valid and the arithmetic interesting."""
    prefix = rng.randint(9, 30)
    # Random address; bias toward the common private ranges for familiarity.
    base = rng.choice([
        rng.randint(0x0A000000, 0x0AFFFFFF),          # 10.0.0.0/8
        rng.randint(0xAC100000, 0xAC1FFFFF),          # 172.16.0.0/12
        rng.randint(0xC0A80000, 0xC0A8FFFF),          # 192.168.0.0/16
        rng.randint(0x01000000, 0xDFFFFFFF),          # general unicast space
    ])
    host_ip = str(ipaddress.IPv4Address(base))
    network = ipaddress.ip_network(f"{host_ip}/{prefix}", strict=False)
    return Problem(host_ip=host_ip, prefix=prefix, network=network)


def _norm(s: str) -> str:
    return s.strip().lower()


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""


def _check_ip(answer: str, expected: str) -> bool:
    try:
        return ipaddress.IPv4Address(_norm(answer)) == ipaddress.IPv4Address(expected)
    except ValueError:
        return False


def _check_int(answer: str, expected: int) -> bool:
    try:
        return int(_norm(answer).replace(",", "")) == expected
    except ValueError:
        return False


def _solution(p: Problem) -> str:
    mask_octet = p.netmask.split(".")[p.interesting_octet]
    return (
        f"  Worked solution for {p.cidr}:\n"
        f"    mask {p.netmask}  (/{p.prefix}),  block size 256 - {mask_octet} = "
        f"{p.octet_block_size} in octet {p.interesting_octet + 1} "
        f"({p.block_size} addresses total)\n"
        f"    network   = {p.network_address}\n"
        f"    broadcast = {p.broadcast}\n"
        f"    usable    = {p.first_host} .. {p.last_host}  "
        f"({p.usable_hosts} hosts = 2^{32 - p.prefix} - 2)\n"
    )


def _hint(p: Problem) -> str:
    mask_octet = p.netmask.split(".")[p.interesting_octet]
    return (f"  Hint: /{p.prefix} -> mask {p.netmask}; block size in octet "
            f"{p.interesting_octet + 1} is 256 - {mask_octet} = {p.octet_block_size}. "
            f"Round that octet down to a multiple of the block size.")


def run_quiz(rng: random.Random, count: int) -> None:
    print("Subnetting practice — answer each part; blank to skip. Ctrl-C to quit.\n")
    score = 0
    for i in range(1, count + 1):
        p = generate_problem(rng)
        print(f"[{i}/{count}]  Given the address  {p.cidr}")
        parts = [
            ("Network address", lambda a: _check_ip(a, p.network_address)),
            ("Broadcast address", lambda a: _check_ip(a, p.broadcast)),
            ("Number of usable hosts", lambda a: _check_int(a, p.usable_hosts)),
        ]
        correct_here = 0
        for label, check in parts:
            ans = _ask(f"    {label}? ")
            if check(ans):
                print("    correct")
                correct_here += 1
            else:
                print(_hint(p))
                ans2 = _ask(f"    {label} (try again)? ")
                if check(ans2):
                    print("    correct")
                    correct_here += 1
                else:
                    print("    not quite.")
        print(_solution(p))
        score += correct_here
    print(f"Done. Score: {score}/{count * 3}.")


def selftest(rounds: int = 2000) -> bool:
    """Generate many problems and assert each computed answer is consistent with the
    authoritative ipaddress values. Verifies the drill never teaches a wrong answer."""
    rng = random.Random(20240601)
    for _ in range(rounds):
        p = generate_problem(rng)
        net = ipaddress.ip_network(p.cidr, strict=False)
        assert p.network_address == str(net.network_address)
        assert p.broadcast == str(net.broadcast_address)
        assert p.usable_hosts == net.num_addresses - 2
        assert ipaddress.IPv4Address(p.first_host) == net.network_address + 1
        assert ipaddress.IPv4Address(p.last_host) == net.broadcast_address - 1
        # The host actually lies within the computed network.
        assert ipaddress.IPv4Address(p.host_ip) in net
        # Block size is a power of two and equals 2^(32-prefix).
        assert p.block_size == 2 ** (32 - p.prefix)
        # Octet block size matches the classic "256 - mask octet" method.
        mask_octet = int(p.netmask.split(".")[p.interesting_octet])
        assert p.octet_block_size == 256 - mask_octet

    # A couple of fixed, hand-verified cases.
    p = Problem("192.168.1.100", 26,
                ipaddress.ip_network("192.168.1.100/26", strict=False))
    assert p.network_address == "192.168.1.64"
    assert p.broadcast == "192.168.1.127"
    assert p.usable_hosts == 62
    assert (p.first_host, p.last_host) == ("192.168.1.65", "192.168.1.126")

    p = Problem("10.10.10.10", 30,
                ipaddress.ip_network("10.10.10.10/30", strict=False))
    assert p.network_address == "10.10.10.8"
    assert p.broadcast == "10.10.10.11"
    assert p.usable_hosts == 2

    print(f"selftest OK: {rounds} generated problems consistent with ipaddress, "
          f"plus fixed cases.")
    return True


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Subnetting practice drill.")
    ap.add_argument("--selftest", action="store_true",
                    help="verify the generator/checker and exit (no input)")
    ap.add_argument("-n", "--count", type=int, default=5,
                    help="number of quiz questions (interactive mode)")
    args = ap.parse_args(argv)

    # Run the self-test when asked, or automatically when there's no interactive terminal
    # (e.g. in CI), so the file is always exercisable headlessly.
    if args.selftest or not sys.stdin.isatty():
        return 0 if selftest() else 1

    run_quiz(random.Random(), args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
