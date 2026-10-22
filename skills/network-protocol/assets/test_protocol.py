#!/usr/bin/env python3
"""Test suite for framed_protocol.py.

Runs under pytest (`pytest test_protocol.py`) and also standalone with no dependencies
(`python3 test_protocol.py`) via the runner at the bottom. The tests deliberately
*provoke* the failures that naive framing code hides (testing §2): byte-at-a-time
chunking, several frames in one buffer, oversized lengths, arbitrary garbage, short
reads, and a full loopback round-trip including version negotiation and load shedding.
"""

from __future__ import annotations

import contextlib
import random
import socket
import threading
import time

import framed_protocol as fp
from framed_protocol import (
    Connection, Frame, FrameReader, MsgType, Server, ServerConfig,
    FramingError, PayloadTooLarge, ReservedBitsError, HandshakeError,
    ConnectionClosed, encode_frame, connect, echo_handler,
)


# --------------------------------------------------------------------------------------
# Small helper so the file needs no pytest import to run.
# --------------------------------------------------------------------------------------
@contextlib.contextmanager
def expect(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


# ======================================================================================
# Framing: the core correctness properties
# ======================================================================================
def test_round_trip():
    r = FrameReader()
    r.feed(encode_frame(MsgType.DATA, b"hello world"))
    frames = list(r.read_frames())
    assert len(frames) == 1
    assert frames[0] == Frame(int(MsgType.DATA), 0, b"hello world")


def test_one_byte_at_a_time():
    # The test naive "one recv == one message" code fails (§1.1).
    r = FrameReader()
    out = []
    for b in encode_frame(MsgType.DATA, b"split me"):
        r.feed(bytes([b]))
        out.extend(r.read_frames())
    assert [f.payload for f in out] == [b"split me"]


def test_two_messages_in_one_buffer():
    r = FrameReader()
    r.feed(encode_frame(MsgType.DATA, b"a") + encode_frame(MsgType.PING, b""))
    out = list(r.read_frames())
    assert [f.payload for f in out] == [b"a", b""]
    assert [f.msg_type for f in out] == [int(MsgType.DATA), int(MsgType.PING)]


def test_message_split_across_two_feeds():
    blob = encode_frame(MsgType.DATA, b"abcdefghij")
    cut = 7
    r = FrameReader()
    r.feed(blob[:cut])
    assert list(r.read_frames()) == []          # nothing complete yet
    r.feed(blob[cut:])
    assert [f.payload for f in r.read_frames()] == [b"abcdefghij"]


def test_zero_length_payload():
    r = FrameReader()
    r.feed(encode_frame(MsgType.PING, b""))
    assert list(r.read_frames())[0].payload == b""


def test_many_frames_streamed_in_random_chunks():
    payloads = [bytes([i]) * (i * 3) for i in range(40)]
    blob = b"".join(encode_frame(MsgType.DATA, p) for p in payloads)
    rng = random.Random(1234)
    r = FrameReader()
    out = []
    i = 0
    while i < len(blob):
        step = rng.randint(1, 50)
        r.feed(blob[i:i + step])
        out.extend(r.read_frames())
        i += step
    assert [f.payload for f in out] == payloads


# ======================================================================================
# Bounds and rejection of hostile input
# ======================================================================================
def test_oversized_length_rejected_before_body():
    r = FrameReader()
    # Just the header, claiming a body one byte over the cap. Must reject immediately,
    # before waiting for or allocating the body (§4.1).
    r.feed(fp.HEADER.pack(fp.MAGIC, fp.PROTOCOL_VERSION, MsgType.DATA, 0, fp.MAX_PAYLOAD + 1))
    with expect(PayloadTooLarge):
        list(r.read_frames())


def test_bad_magic_rejected():
    r = FrameReader()
    r.feed(fp.HEADER.pack(b"XXXX", fp.PROTOCOL_VERSION, MsgType.DATA, 0, 0))
    with expect(FramingError):
        list(r.read_frames())


def test_reserved_flags_rejected():
    r = FrameReader()
    r.feed(fp.HEADER.pack(fp.MAGIC, fp.PROTOCOL_VERSION, MsgType.DATA, 0x0001, 0))
    with expect(ReservedBitsError):
        list(r.read_frames())


def test_feed_backstop_overflow():
    # A caller that feeds far past the ceiling without draining is stopped (§9.1).
    r = FrameReader(max_payload=1024)
    with expect(PayloadTooLarge):
        r.feed(b"\x00" * (fp.HEADER.size + 1024 + fp.RECV_CHUNK + 1))


def test_encode_rejects_oversized_payload():
    with expect(PayloadTooLarge):
        encode_frame(MsgType.DATA, b"\x00" * (fp.MAX_PAYLOAD + 1))


# ======================================================================================
# Golden wire-format vectors — pin the byte layout so it can't change silently (§3, testing §3)
# ======================================================================================
def test_golden_vectors():
    # magic 4E5052 4F = "NPRO", version 01, type 03 (DATA), flags 0000, length 00000005,
    # payload "hello".
    expected = bytes.fromhex("4e50524f0103000000000005") + b"hello"
    assert encode_frame(MsgType.DATA, b"hello") == expected

    # Empty PING: type 04, length 0.
    expected_ping = bytes.fromhex("4e50524f0104000000000000")
    assert encode_frame(MsgType.PING, b"") == expected_ping


# ======================================================================================
# Property / fuzz: arbitrary bytes must never crash the parser with an unexpected
# exception — only the declared protocol errors are allowed (testing §4-5).
# ======================================================================================
def test_arbitrary_bytes_never_crash():
    rng = random.Random(99)
    for _ in range(2000):
        n = rng.randint(0, 64)
        data = bytes(rng.getrandbits(8) for _ in range(n))
        r = FrameReader(max_payload=4096)
        try:
            r.feed(data)
            list(r.read_frames())
        except (FramingError, PayloadTooLarge, ReservedBitsError):
            pass                                # acceptable, declared failures
        # any other exception propagates and fails the test


def test_round_trip_property_random_frames():
    rng = random.Random(7)
    types = [MsgType.DATA, MsgType.PING, MsgType.PONG, MsgType.HELLO]
    for _ in range(500):
        mt = rng.choice(types)
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
        r = FrameReader()
        r.feed(encode_frame(mt, payload))
        frames = list(r.read_frames())
        assert len(frames) == 1
        assert frames[0].msg_type == int(mt)
        assert frames[0].payload == payload


# ======================================================================================
# Fault injection: a socket that dribbles bytes a few at a time must still assemble whole
# frames correctly (§2.1, testing §6).
# ======================================================================================
class DribbleSocket:
    """A fake socket that returns at most `step` bytes per recv and records sends."""

    def __init__(self, inbound: bytes, step: int = 3):
        self._in = inbound
        self._pos = 0
        self._step = step
        self.sent = bytearray()

    def settimeout(self, _t):   # noqa: D401 - fake
        pass

    def setsockopt(self, *_a):
        pass

    def recv(self, n):
        if self._pos >= len(self._in):
            return b""                          # EOF
        end = min(self._pos + min(n, self._step), len(self._in))
        chunk = self._in[self._pos:end]
        self._pos = end
        return chunk

    def sendall(self, data):
        self.sent.extend(data)

    def shutdown(self, _how):
        pass

    def close(self):
        pass

    def getpeername(self):
        return ("fake", 0)


def test_connection_assembles_across_short_reads():
    inbound = (encode_frame(MsgType.DATA, b"abcdef")
               + encode_frame(MsgType.PING, b"\x09\x09"))
    conn = Connection(DribbleSocket(inbound, step=1))   # one byte per recv: worst case
    f1 = conn.recv()
    f2 = conn.recv()
    assert f1.payload == b"abcdef" and f1.msg_type == int(MsgType.DATA)
    assert f2.payload == b"\x09\x09" and f2.msg_type == int(MsgType.PING)
    with expect(ConnectionClosed):
        conn.recv()                                     # EOF after the two frames


# ======================================================================================
# Handshake / version negotiation (no sockets needed: drive both sides over a pair).
# ======================================================================================
def _socketpair_conns():
    a, b = socket.socketpair()
    return Connection(a), Connection(b)


def test_handshake_negotiates_version():
    cli_sock, srv_sock = _socketpair_conns()
    result = {}

    def server_side():
        result["srv"] = fp.perform_server_handshake(srv_sock)

    t = threading.Thread(target=server_side)
    t.start()
    chosen = fp.perform_client_handshake(cli_sock)
    t.join(2.0)
    assert chosen == fp.PROTOCOL_VERSION
    assert result["srv"] == fp.PROTOCOL_VERSION
    cli_sock.close()
    srv_sock.close()


def test_handshake_rejects_non_hello_first_frame():
    cli_sock, srv_sock = _socketpair_conns()
    # Client sends DATA instead of HELLO; server must reject.
    cli_sock.send(MsgType.DATA, b"surprise")
    with expect(HandshakeError):
        fp.perform_server_handshake(srv_sock)
    cli_sock.close()
    srv_sock.close()


# ======================================================================================
# Integration: a real loopback server, echo + ping + graceful close, and load shedding.
# ======================================================================================
@contextlib.contextmanager
def running_server(**cfg):
    server = Server(ServerConfig(host="127.0.0.1", port=0, **cfg), echo_handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    for _ in range(100):
        if server.address[1]:
            break
        time.sleep(0.02)
    try:
        yield server
    finally:
        server.shutdown()
        t.join(3.0)


def test_loopback_echo_ping_close():
    with running_server(max_connections=8) as server:
        host, port = server.address
        client = connect(host, port)
        assert client.peer_version == fp.PROTOCOL_VERSION
        client.send(MsgType.DATA, b"roundtrip")
        assert client.recv().payload == b"roundtrip"
        client.send(MsgType.PING, b"zz")
        pong = client.recv()
        assert pong.msg_type == int(MsgType.PONG) and pong.payload == b"zz"
        client.send(MsgType.BYE)
        client.close()
        time.sleep(0.1)
        assert server.metrics.accepted >= 1


def test_load_shedding_over_cap():
    # Cap of 1: the second concurrent client should be shed with an ERROR, not queued.
    with running_server(max_connections=1) as server:
        host, port = server.address
        first = connect(host, port)                     # holds the only slot
        first.send(MsgType.DATA, b"hold")
        assert first.recv().payload == b"hold"
        # Second connection: handshake should fail because the server sheds us.
        with expect(HandshakeError):
            connect(host, port, connect_timeout=2.0, idle_timeout=2.0)
        assert server.metrics.rejected_over_cap >= 1
        first.send(MsgType.BYE)
        first.close()


def test_per_ip_cap_sheds_second_connection():
    # One IP must not consume every slot: cap per-IP at 1, both from 127.0.0.1.
    with running_server(max_connections=8, max_connections_per_ip=1) as server:
        host, port = server.address
        first = connect(host, port)
        first.send(MsgType.DATA, b"x")
        assert first.recv().payload == b"x"
        with expect((HandshakeError, ConnectionClosed)):
            connect(host, port, connect_timeout=2.0, idle_timeout=2.0)
        assert server.metrics.rejected_per_ip >= 1
        first.send(MsgType.BYE)
        first.close()


# ======================================================================================
# Slow-body slowloris: the overall message deadline must fire even though each byte
# arrives within the idle window (the idle timeout alone can't catch this).
# ======================================================================================
class SlowSocket:
    """Returns the header one byte at a time after a small delay, then trickles body
    bytes forever — a frame that never completes in time."""

    def __init__(self, header: bytes, delay: float = 0.01):
        self._pending = bytearray(header)
        self._delay = delay

    def settimeout(self, _t):
        pass

    def setsockopt(self, *_a):
        pass

    def recv(self, _n):
        time.sleep(self._delay)
        if self._pending:
            b = bytes(self._pending[:1])
            del self._pending[:1]
            return b
        return b"\x00"                                   # endless trickle

    def shutdown(self, _how):
        pass

    def close(self):
        pass

    def getpeername(self):
        return ("slow", 0)


def test_message_deadline_fires_on_slow_body():
    # Declare a 1000-byte body but never deliver it in time.
    header = fp.HEADER.pack(fp.MAGIC, fp.PROTOCOL_VERSION, MsgType.DATA, 0, 1000)
    conn = Connection(SlowSocket(header, delay=0.01),
                      idle_timeout=5.0, message_timeout=0.15)
    with expect(fp.ProtocolTimeout):
        conn.recv()


# ======================================================================================
# Cursor parser stays correct (and O(n)) with very many tiny frames in one buffer.
# ======================================================================================
def test_many_tiny_frames_in_one_buffer():
    n = 20000
    blob = encode_frame(MsgType.PING, b"") * n
    r = FrameReader()
    r.feed(blob)
    count = sum(1 for _ in r.read_frames())
    assert count == n
    assert r.buffered_bytes == 0


# ======================================================================================
# TLS — encryption + server authentication, and mutual TLS (client authentication).
# Certificates are generated on the fly with `cryptography`; skipped if it's unavailable.
# ======================================================================================
def _make_tls_materials():
    """Generate a CA, a server cert (SAN: localhost), and a client cert; return paths."""
    import datetime
    import tempfile
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    tmp = tempfile.mkdtemp(prefix="npframe-tls-")
    now = datetime.datetime.now(datetime.timezone.utc)

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def write(name, key_obj, cert_obj):
        kp = f"{tmp}/{name}-key.pem"
        cp = f"{tmp}/{name}-cert.pem"
        with open(kp, "wb") as f:
            f.write(key_obj.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        with open(cp, "wb") as f:
            f.write(cert_obj.public_bytes(serialization.Encoding.PEM))
        return cp, kp

    ca_key = key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "npframe Test CA")])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    ca_path, _ = write("ca", ca_key, ca_cert)

    def signed(name, common, san=None):
        k = key()
        b = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)]))
             .issuer_name(ca_cert.subject)
             .public_key(k.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=1)))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        return write(name, k, b.sign(ca_key, hashes.SHA256()))

    server_cert, server_key = signed("server", "localhost", san="localhost")
    client_cert, client_key = signed("client", "test-client")
    return {
        "ca": ca_path,
        "server_cert": server_cert, "server_key": server_key,
        "client_cert": client_cert, "client_key": client_key,
    }


_TLS = None


def _tls():
    global _TLS
    if _TLS is None:
        try:
            import cryptography  # noqa: F401
        except ImportError:
            return None
        _TLS = _make_tls_materials()
    return _TLS


def test_tls_round_trip():
    mat = _tls()
    if mat is None:
        print("(skipped: cryptography not installed)")
        return
    server_ctx = fp.make_server_tls_context(mat["server_cert"], mat["server_key"])
    with running_server(max_connections=8, tls=server_ctx) as server:
        _host, port = server.address
        client_ctx = fp.make_client_tls_context(ca_file=mat["ca"])
        client = connect("127.0.0.1", port, tls=client_ctx, server_hostname="localhost")
        client.send(MsgType.DATA, b"secret")
        assert client.recv().payload == b"secret"
        client.send(MsgType.BYE)
        client.close()


def test_tls_client_rejects_untrusted_server():
    mat = _tls()
    if mat is None:
        print("(skipped: cryptography not installed)")
        return
    server_ctx = fp.make_server_tls_context(mat["server_cert"], mat["server_key"])
    with running_server(max_connections=8, tls=server_ctx) as server:
        _host, port = server.address
        # A client that does NOT trust our private CA must refuse the server cert.
        import ssl as _ssl
        empty_ctx = _ssl.create_default_context()       # system trust only
        empty_ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
        with expect((_ssl.SSLError, ConnectionClosed, OSError)):
            connect("127.0.0.1", port, tls=empty_ctx, server_hostname="localhost",
                    connect_timeout=3.0, idle_timeout=3.0)


def test_mtls_round_trip_with_client_cert():
    mat = _tls()
    if mat is None:
        print("(skipped: cryptography not installed)")
        return
    server_ctx = fp.make_server_tls_context(
        mat["server_cert"], mat["server_key"],
        require_client_cert=True, ca_file=mat["ca"])
    with running_server(max_connections=8, tls=server_ctx) as server:
        _host, port = server.address
        client_ctx = fp.make_client_tls_context(
            ca_file=mat["ca"], client_cert=mat["client_cert"], client_key=mat["client_key"])
        client = connect("127.0.0.1", port, tls=client_ctx, server_hostname="localhost")
        client.send(MsgType.DATA, b"authed")
        assert client.recv().payload == b"authed"
        client.send(MsgType.BYE)
        client.close()


def test_mtls_rejects_client_without_cert():
    mat = _tls()
    if mat is None:
        print("(skipped: cryptography not installed)")
        return
    server_ctx = fp.make_server_tls_context(
        mat["server_cert"], mat["server_key"],
        require_client_cert=True, ca_file=mat["ca"])
    with running_server(max_connections=8, tls=server_ctx) as server:
        _host, port = server.address
        # No client cert presented: the TLS handshake itself must reject us before any
        # protocol byte is exchanged.
        client_ctx = fp.make_client_tls_context(ca_file=mat["ca"])
        import ssl as _ssl
        with expect((_ssl.SSLError, ConnectionClosed, OSError)):
            client = connect("127.0.0.1", port, tls=client_ctx,
                             server_hostname="localhost",
                             connect_timeout=3.0, idle_timeout=3.0)
            # Some stacks surface the rejection only on first use:
            client.send(MsgType.DATA, b"x")
            client.recv()
        # The server records the failure in its handler thread; the client can observe the
        # TLS alert before that runs, so poll briefly rather than reading instantly.
        deadline = time.monotonic() + 2.0
        while server.metrics.handshake_failures < 1 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.metrics.handshake_failures >= 1


# ======================================================================================
# Standalone runner (no pytest required).
# ======================================================================================
def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        try:
            t()
        except Exception as exc:                         # noqa: BLE001 - report and continue
            print(f"FAIL  {t.__name__}: {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"ok    {t.__name__}")
    print(f"\n{passed}/{len(tests)} tests passed")
    return passed == len(tests)


if __name__ == "__main__":
    import sys
    sys.exit(0 if _run_all() else 1)
