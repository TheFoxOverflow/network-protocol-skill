#!/usr/bin/env python3
"""npframe — a production-grade, length-prefixed framed protocol over TCP.

This is a single-module *reference library*, not a toy. It is meant to be copied into a
project and adapted: the wire format, the handshake, and the message types are examples,
but the structure, the bounds, and the failure handling are production-shaped and should
be preserved. Each defensive measure references the bug it prevents
(see references/pitfalls.md §x.y and references/production-readiness.md).

Layers, kept strictly separate so each is testable in isolation (golden rule 8):
  * Framing          : FrameReader / encode_frame  — bytes <-> frames, no sockets.
  * I/O              : Connection                   — read/write loops, timeouts, locks.
  * TLS              : make_*_tls_context           — encryption, server + (m)TLS client auth.
  * Handshake/logic  : perform_*_handshake          — version negotiation, no raw bytes.
  * Server           : Server                       — accept loop, concurrency + per-IP
                                                       caps, load shedding, graceful drain.

Security posture (see references/security.md and references/pitfalls.md): every length is
bounded before allocation; the reassembly parser is O(n) and can't be made quadratic by
hostile chunking; an unauthenticated peer can buffer only a few KB and hold a slot only
briefly; per-message and per-handshake deadlines defeat slow-dribble slowloris; one source
IP can't take every slot; and TLS (optionally mutual) provides encryption and peer
authentication with certificate + hostname verification that is never disabled. This is a
strong baseline, not a guarantee of invulnerability — read the threat-model notes in
references/security.md and supply your own authn/authz, key management, and TLS material.

The module configures no logging and installs no signal handlers on import; an
application owns those. Run `python3 framed_protocol.py` for a self-contained loopback
demo; run `pytest test_protocol.py` for the test suite.
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Iterator, Optional

logger = logging.getLogger("npframe")

# ======================================================================================
# Wire format
# ======================================================================================
# Header: 12 bytes, big-endian / network byte order. We serialize each field explicitly;
# we never memcpy a struct to the wire (padding and endianness are not portable, §3.2).
#
#   offset  size  field
#   0       4     magic     b"NPRO"   reject wrong-protocol / desynced peers immediately
#   4       1     version   protocol version, for negotiation and evolution (§12.1)
#   5       1     type      message type (see MsgType); kept as int so unknown types
#                           don't crash the parser (§10.2)
#   6       2     flags     reserved bitfield; MUST be 0 in version 1 (§design-5)
#   8       4     length    PAYLOAD byte count, NOT including the header
#   12      ...   payload   exactly `length` bytes
#
HEADER = struct.Struct("!4sBBHI")
assert HEADER.size == 12

MAGIC = b"NPRO"

PROTOCOL_VERSION = 1  # the version this build speaks
MIN_SUPPORTED_VERSION = 1  # oldest peer version we still interoperate with

# Hard cap enforced BEFORE allocating or awaiting bytes. An unbounded length field is a
# one-line denial-of-service (§4.1). Tune to your largest legitimate message.
MAX_PAYLOAD = 8 * 1024 * 1024  # 8 MiB

# Bytes pulled from the socket per syscall. Bounds one read; the reassembly buffer is
# bounded separately by the per-frame length check in FrameReader (§9.1).
RECV_CHUNK = 64 * 1024


class MsgType(IntEnum):
    HELLO = 1  # client -> server: offered version range
    HELLO_ACK = 2  # server -> client: chosen version
    DATA = 3  # either way: application payload
    PING = 4  # liveness probe (§5.1)
    PONG = 5  # liveness response
    BYE = 6  # graceful goodbye
    ERROR = 7  # protocol/application error; payload is a short UTF-8 reason


@dataclass(frozen=True)
class Frame:
    """One parsed frame. `msg_type` stays an int so unknown/future types are representable
    without raising; the protocol layer decides how to treat them (§10.2)."""

    msg_type: int
    flags: int
    payload: bytes


# ======================================================================================
# Exception hierarchy — callers can distinguish "peer misbehaved" from "peer left" from
# "we timed out". Production code routes these very differently (metrics, retries, logs).
# ======================================================================================
class ProtocolError(Exception):
    """Base: the peer sent something malformed or out-of-spec. Fail closed (security §6)."""


class FramingError(ProtocolError):
    """Bad magic or a desynchronized stream — the bytes are not our protocol."""


class PayloadTooLarge(ProtocolError):
    """A length field (or the reassembly buffer) exceeded the configured maximum (§4.1)."""


class ReservedBitsError(ProtocolError):
    """Reserved header bits were set; reject so they can be defined later (§design-5)."""


class HandshakeError(ProtocolError):
    """The handshake failed: wrong first message, or no common version (§12.1)."""


class ConnectionClosed(Exception):
    """The peer closed the connection. Not necessarily an error (e.g. after BYE)."""


class ProtocolTimeout(Exception):
    """An operation exceeded its deadline (§8.1). Distinct from a clean close."""


# ======================================================================================
# Encoding
# ======================================================================================
def encode_frame(
    msg_type: int, payload: bytes = b"", flags: int = 0, version: int = PROTOCOL_VERSION
) -> bytes:
    """Serialize one frame. Bound the size on the SEND side too: an upstream bug must not
    emit a frame the peer is then forced to reject (§4.1)."""
    if len(payload) > MAX_PAYLOAD:
        raise PayloadTooLarge(f"payload {len(payload)} B exceeds MAX_PAYLOAD {MAX_PAYLOAD} B")
    if not 0 <= flags <= 0xFFFF:
        raise ValueError(f"flags out of range: {flags}")
    return HEADER.pack(MAGIC, version, int(msg_type), flags, len(payload)) + payload


# ======================================================================================
# Incremental parser — the heart of correct framing. Touches no socket, so the same
# parser is used for blocking, non-blocking, and async I/O, and is unit-tested by feeding
# bytes directly (testing §1-2). Tolerates any chunking (§1.1).
# ======================================================================================
class FrameReader:
    """Feed arbitrary byte chunks; pull out complete frames.

    Contract: call ``feed(data)`` with whatever arrived, then drain with
    ``read_frames()``. The security-critical bound is the per-frame ``length`` check in
    ``read_frames`` — an oversized frame is rejected the instant its header is parsed, so
    a hostile peer can never make us buffer more than one chunk past the cap. ``feed``
    adds a cheap backstop in case a caller forgets to drain.
    """

    def __init__(self, max_payload: int = MAX_PAYLOAD) -> None:
        self._buf = bytearray()
        self._pos = 0  # parse cursor; bytes before it are consumed
        self._max_payload = max_payload
        # Backstop ceiling: one max-size in-progress frame plus one transport chunk. A
        # well-behaved transport that drains after each feed never approaches this.
        self._hard_ceiling = HEADER.size + max_payload + RECV_CHUNK

    def set_max_payload(self, max_payload: int) -> None:
        """Change the size cap mid-stream. Used to keep the cap tiny during an
        unauthenticated handshake, then relax it once the peer is trusted (security §7)."""
        self._max_payload = max_payload
        self._hard_ceiling = HEADER.size + max_payload + RECV_CHUNK

    def feed(self, data: bytes) -> None:
        # Bound on UNCONSUMED bytes; the security-critical per-frame check is in
        # read_frames. This backstop stops a caller that forgets to drain (§9.1).
        if (len(self._buf) - self._pos) + len(data) > self._hard_ceiling:
            raise PayloadTooLarge("reassembly buffer overflow; drain frames after each feed (§9.1)")
        # Reclaim the consumed prefix now, once per feed, rather than on every frame.
        # Deleting per-frame would make parsing O(n^2) when many small frames arrive in
        # one buffer — a CPU-exhaustion vector on hostile input (security §7).
        if self._pos:
            del self._buf[: self._pos]
            self._pos = 0
        self._buf.extend(data)

    def read_frames(self) -> Iterator[Frame]:
        """Yield every complete frame currently buffered, then stop (never blocks).
        Advances a cursor instead of deleting per frame; the consumed prefix is reclaimed
        on the next feed, keeping parsing O(n) (§9.4)."""
        while True:
            if len(self._buf) - self._pos < HEADER.size:
                return  # need a full header first
            magic, _version, msg_type, flags, length = HEADER.unpack_from(self._buf, self._pos)

            # Validate every field BEFORE acting on it (golden rule 9; security §6).
            if magic != MAGIC:
                raise FramingError(f"bad magic {magic!r} (wrong protocol or desync)")
            if length > self._max_payload:  # bound BEFORE awaiting the body
                raise PayloadTooLarge(f"frame length {length} exceeds max {self._max_payload}")
            if flags != 0:
                raise ReservedBitsError(f"reserved flags must be 0, got {flags:#06x}")

            total = HEADER.size + length
            if len(self._buf) - self._pos < total:
                return  # body incomplete; await more
            start = self._pos + HEADER.size
            payload = bytes(self._buf[start : self._pos + total])
            self._pos += total  # consume; prefix freed on next feed
            yield Frame(int(msg_type), flags, payload)

    @property
    def buffered_bytes(self) -> int:
        """Unconsumed bytes — export as a backpressure metric (production-readiness §2)."""
        return len(self._buf) - self._pos


# ======================================================================================
# I/O layer — correct read/write loops, deadlines, and thread-safe sends. Kept free of
# protocol logic so it can be reused for any message semantics (golden rule 8).
# ======================================================================================
class Connection:
    """A framed connection over one socket.

    Threading: ``send`` is serialized by an internal lock, so multiple producer threads
    may send safely. ``recv`` is NOT safe to call from multiple threads; give each
    connection a single reader (§6.6).
    """

    def __init__(
        self,
        sock: socket.socket,
        *,
        idle_timeout: float = 60.0,
        message_timeout: Optional[float] = None,
        max_payload: int = MAX_PAYLOAD,
        peer_version: int = PROTOCOL_VERSION,
    ) -> None:
        self._sock = sock
        self._reader = FrameReader(max_payload)
        self._send_lock = threading.Lock()
        self._closed = False
        self.peer_version = peer_version
        self._idle_timeout = idle_timeout
        # Overall wall-clock budget to assemble ONE frame. The idle timeout only bounds
        # inactivity between bytes, so a peer dribbling one byte just inside each idle
        # window can hold a slot forever while sending a body arbitrarily slowly
        # (a slow-body slowloris). message_timeout caps the total and defeats it. None =
        # rely on idle only; set it generously above max_payload / min-expected-bandwidth.
        self._message_timeout = message_timeout
        # Idle deadline so a stalled or vanished peer can't hang us forever (§8.1).
        self._sock.settimeout(idle_timeout)
        # Disable Nagle: for small request/response messages the Nagle/delayed-ACK
        # interaction can add ~40 ms of latency (§7.3). Best-effort: the same Connection
        # is used over TCP and over Unix domain sockets, where TCP_NODELAY is meaningless
        # and raises — tuning a transport must never be a hard failure.
        try:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def set_max_payload(self, max_payload: int) -> None:
        """Relax (or tighten) the frame-size cap mid-stream — e.g. after a successful
        handshake promotes a peer from untrusted to trusted (security §7)."""
        self._reader.set_max_payload(max_payload)

    def set_timeouts(self, idle_timeout: float, message_timeout: Optional[float] = None) -> None:
        """Change the timeouts mid-stream. Used to run the handshake under a short, strict
        budget and then relax to steady-state values once the peer is trusted."""
        self._idle_timeout = idle_timeout
        self._message_timeout = message_timeout
        try:
            self._sock.settimeout(idle_timeout)
        except OSError:
            pass

    @property
    def peername(self) -> str:
        try:
            return "%s:%d" % self._sock.getpeername()[:2]
        except OSError:
            return "<disconnected>"

    def send(self, msg_type: int, payload: bytes = b"", flags: int = 0) -> None:
        """Encode and write one whole frame. One frame per write keeps Nagle irrelevant
        and avoids interleaving between concurrent senders (held under the lock)."""
        frame = encode_frame(msg_type, payload, flags)
        with self._send_lock:
            if self._closed:
                raise ConnectionClosed("send on a closed connection")
            try:
                self._sock.sendall(frame)  # loops over short writes (§2.2)
            except (socket.timeout, TimeoutError) as exc:
                raise ProtocolTimeout("send timed out") from exc
            except ssl.SSLError as exc:
                self._closed = True
                raise ConnectionClosed(f"TLS error on send: {exc}") from exc
            except OSError as exc:
                self._closed = True
                raise ConnectionClosed(f"send failed: {exc}") from exc

    def recv(self) -> Frame:
        """Return the next complete frame, reading from the socket only when the buffer
        has no full frame. Buffered frames are returned without a syscall (correct
        framing: one recv != one message, §1.1).

        Enforces both the per-recv idle timeout and, if configured, an overall deadline on
        the time to assemble this one frame (slow-body slowloris defense)."""
        deadline = (
            time.monotonic() + self._message_timeout if self._message_timeout is not None else None
        )
        try:
            while True:
                for frame in self._reader.read_frames():
                    return frame
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProtocolTimeout("message assembly exceeded its deadline")
                    # Never block a single recv past either the idle window or the deadline.
                    try:
                        self._sock.settimeout(min(self._idle_timeout, remaining))
                    except OSError:
                        pass
                try:
                    data = self._sock.recv(RECV_CHUNK)
                except (socket.timeout, TimeoutError) as exc:
                    raise ProtocolTimeout("recv timed out (idle peer?)") from exc
                except ssl.SSLError as exc:
                    raise ConnectionClosed(f"TLS error: {exc}") from exc
                except OSError as exc:
                    raise ConnectionClosed(f"recv failed: {exc}") from exc
                if not data:  # b"" => clean EOF (§2.3)
                    raise ConnectionClosed("peer closed connection")
                self._reader.feed(data)
        finally:
            # Restore the steady idle timeout so a near-deadline read can't shorten the
            # timeout seen by a following send() or close() on this socket.
            if deadline is not None:
                try:
                    self._sock.settimeout(self._idle_timeout)
                except OSError:
                    pass

    @property
    def buffered_bytes(self) -> int:
        return self._reader.buffered_bytes

    def close(self) -> None:
        """Graceful shutdown: half-close (send FIN), drain the peer's remaining bytes so
        the last message isn't lost to an abortive reset, then close. Idempotent and
        safe on every path (golden rule 10; §5.2)."""
        with self._send_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_WR)
            self._sock.settimeout(2.0)
            while self._sock.recv(RECV_CHUNK):
                pass
        except OSError:
            pass
        finally:
            try:
                self._sock.close()
            except OSError:
                pass


# ======================================================================================
# Handshake — version negotiation, expressed in terms of frames (no raw byte handling).
# Wire form of HELLO/HELLO_ACK payload: two bytes [min_version, max_version].
# ======================================================================================
def perform_client_handshake(
    conn: Connection,
    *,
    min_version: int = MIN_SUPPORTED_VERSION,
    max_version: int = PROTOCOL_VERSION,
) -> int:
    """Drive the client side; return the negotiated version or raise HandshakeError."""
    conn.send(MsgType.HELLO, bytes([min_version, max_version]))
    frame = conn.recv()
    if frame.msg_type == MsgType.ERROR:
        raise HandshakeError(f"server rejected handshake: {frame.payload!r}")
    if frame.msg_type != MsgType.HELLO_ACK or len(frame.payload) != 1:
        raise HandshakeError(f"unexpected handshake reply: type={frame.msg_type}")
    chosen = frame.payload[0]
    if not min_version <= chosen <= max_version:
        raise HandshakeError(f"server chose unsupported version {chosen}")
    conn.peer_version = chosen
    return chosen


def perform_server_handshake(
    conn: Connection,
    *,
    min_version: int = MIN_SUPPORTED_VERSION,
    max_version: int = PROTOCOL_VERSION,
) -> int:
    """Drive the server side; return the negotiated version or raise HandshakeError.
    The first frame from a fresh peer MUST be HELLO with a [min,max] range (§10.1)."""
    frame = conn.recv()
    if frame.msg_type != MsgType.HELLO or len(frame.payload) != 2:
        conn.send(MsgType.ERROR, b"expected HELLO")
        raise HandshakeError(f"first frame was not a valid HELLO: type={frame.msg_type}")
    peer_min, peer_max = frame.payload[0], frame.payload[1]
    if peer_min > peer_max:
        conn.send(MsgType.ERROR, b"malformed version range")
        raise HandshakeError(f"client sent inverted version range {peer_min}..{peer_max}")
    # Choose the highest version both sides support.
    chosen = min(max_version, peer_max)
    if chosen < max(min_version, peer_min):
        conn.send(MsgType.ERROR, b"no common version")
        raise HandshakeError(
            f"no overlap: server {min_version}..{max_version}, client {peer_min}..{peer_max}"
        )
    conn.send(MsgType.HELLO_ACK, bytes([chosen]))
    conn.peer_version = chosen
    return chosen


# ======================================================================================
# TLS — encryption, server authentication, and (optionally) mutual authentication.
#
# This is the most important security layer: without it the protocol is exposed to
# passive eavesdropping and active man-in-the-middle, and anyone who can reach the port
# can speak it. The defaults below verify certificates and hostnames and refuse anything
# below TLS 1.2. NEVER disable verification "to make it work" (security §1).
# ======================================================================================
def make_client_tls_context(
    *,
    ca_file: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
) -> ssl.SSLContext:
    """Build a client context that verifies the server's certificate chain AND hostname.

    ``ca_file`` trusts a private CA (omit to use the system trust store). Provide
    ``client_cert``/``client_key`` for mutual TLS, where the server also authenticates us.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx.check_hostname = True  # verify the cert matches the hostname
    ctx.verify_mode = ssl.CERT_REQUIRED  # reject unverified / self-signed peers
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # no SSLv3/TLS1.0/1.1
    if client_cert:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return ctx


def make_server_tls_context(
    cert_file: str,
    key_file: str,
    *,
    require_client_cert: bool = False,
    ca_file: Optional[str] = None,
) -> ssl.SSLContext:
    """Build a server context presenting ``cert_file``/``key_file``.

    For mutual TLS set ``require_client_cert=True`` and pass ``ca_file`` (the CA that signs
    client certs); the TLS handshake then *rejects any client without a valid certificate*
    before a single protocol byte is exchanged — strong, transport-level authentication.
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        if ca_file:
            ctx.load_verify_locations(cafile=ca_file)
    return ctx


# ======================================================================================
# Client entry point
# ======================================================================================
def connect(
    host: str,
    port: int,
    *,
    connect_timeout: float = 10.0,
    idle_timeout: float = 60.0,
    message_timeout: Optional[float] = None,
    max_payload: int = MAX_PAYLOAD,
    tls: Optional[ssl.SSLContext] = None,
    server_hostname: Optional[str] = None,
) -> Connection:
    """Open a connection, optionally wrap it in TLS, perform the handshake, and return a
    READY Connection.

    A short connect timeout fails fast on an unreachable host, distinct from the longer
    idle timeout used once established (§8.1). When ``tls`` is given, ``server_hostname``
    is required and is checked against the server certificate — passing the bare IP or
    None defeats verification, so we refuse it.
    """
    sock = socket.create_connection((host, port), timeout=connect_timeout)
    try:
        if tls is not None:
            if not server_hostname:
                raise ValueError("server_hostname is required for TLS (hostname verification)")
            sock = tls.wrap_socket(sock, server_side=False, server_hostname=server_hostname)
        conn = Connection(
            sock,
            idle_timeout=idle_timeout,
            message_timeout=message_timeout,
            max_payload=max_payload,
        )
        perform_client_handshake(conn)
        return conn
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise


# ======================================================================================
# Server — accept loop, bounded concurrency with load shedding, graceful drain.
# ======================================================================================
@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 0  # 0 = ephemeral; read back with Server.address
    backlog: int = 128
    max_connections: int = 1000  # hard global cap; excess peers are shed, not queued
    max_connections_per_ip: int = 50  # per-source cap so one IP can't take every slot
    idle_timeout: float = 60.0  # per-connection inactivity deadline (§8.1)
    message_timeout: float = 120.0  # overall budget to assemble one frame (slow-body guard)
    handshake_timeout: float = 10.0  # slowloris guard during TLS + protocol handshake
    handshake_max_payload: int = 4096  # tiny cap until a peer is authenticated (security §7)
    max_payload: int = MAX_PAYLOAD  # frame-size cap once past the handshake
    drain_timeout: float = 30.0  # how long shutdown() waits for in-flight handlers
    tls: Optional[ssl.SSLContext] = None  # set via make_server_tls_context for encryption/auth


# A handler is called once with a READY (post-handshake) connection. It owns the
# connection until it returns; the server closes it afterwards on every path.
Handler = Callable[[Connection], None]


@dataclass
class _ServerMetrics:
    """Minimal counters a real deployment would export to its metrics backend
    (production-readiness §2). Plain ints guarded by the GIL for this reference; use an
    atomic/locked counter if you split them across processes."""

    accepted: int = 0
    rejected_over_cap: int = 0
    rejected_per_ip: int = 0
    handshake_failures: int = 0
    handler_errors: int = 0
    closed: int = 0


class Server:
    """A thread-per-connection server with a hard concurrency cap and graceful drain.

    Thread-per-connection is the simplest model that is correct under load; for very high
    fan-out prefer an async/event-loop design (transport §3-4). The cap, the load
    shedding, the accept-loop error survival, and the drain are the production-relevant
    parts and translate directly to other models.
    """

    def __init__(self, config: ServerConfig, handler: Handler) -> None:
        self._cfg = config
        self._handler = handler
        self._stop = threading.Event()
        self._listener: Optional[socket.socket] = None
        self._slots = threading.BoundedSemaphore(config.max_connections)
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._per_ip: dict[str, int] = {}  # concurrent connections per source IP
        self._per_ip_lock = threading.Lock()
        self.metrics = _ServerMetrics()
        self._address: tuple[str, int] = (config.host, config.port)

    @property
    def address(self) -> tuple[str, int]:
        """The bound (host, port); valid after start()/serve_forever() has bound."""
        return self._address

    def _bind(self) -> socket.socket:
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Rebind through TIME_WAIT so a fast restart doesn't fail with EADDRINUSE (§5.3).
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((self._cfg.host, self._cfg.port))
        ls.listen(self._cfg.backlog)
        # Wake accept() periodically so the stop flag is observed promptly during drain.
        ls.settimeout(0.5)
        self._listener = ls
        self._address = ls.getsockname()[:2]
        logger.info(
            "listening on %s:%d (tls=%s, max_conn=%d, per_ip=%d, max_payload=%d B)",
            self._address[0],
            self._address[1],
            self._cfg.tls is not None,
            self._cfg.max_connections,
            self._cfg.max_connections_per_ip,
            self._cfg.max_payload,
        )
        return ls

    def serve_forever(self) -> None:
        """Accept and serve until shutdown() is called. Survives per-connection errors;
        a single bad client never takes down the loop (§5.5)."""
        ls = self._bind()
        try:
            while not self._stop.is_set():
                try:
                    sock, addr = ls.accept()
                except socket.timeout:
                    continue  # periodic wakeup; re-check stop
                except OSError as exc:
                    if self._stop.is_set():
                        break
                    # EMFILE/ENFILE: out of file descriptors. Don't spin; back off and
                    # keep the existing connections alive (§5.5).
                    logger.warning("accept() failed: %s; backing off", exc)
                    time.sleep(0.1)
                    continue

                # Load shedding: if we're at the global cap, reject immediately rather
                # than queueing unbounded work (production-readiness §3).
                if not self._slots.acquire(blocking=False):
                    self.metrics.rejected_over_cap += 1
                    logger.warning("at connection cap; shedding %s:%d", *addr[:2])
                    self._shed(sock)
                    continue

                # Per-source cap: one IP must not be able to consume every slot (a single
                # attacker, or a misbehaving client behind one NAT) (security §7).
                ip = addr[0]
                if not self._reserve_ip(ip):
                    self._slots.release()
                    self.metrics.rejected_per_ip += 1
                    logger.warning("per-IP cap reached for %s; shedding", ip)
                    self._shed(sock)
                    continue

                self.metrics.accepted += 1
                t = threading.Thread(target=self._serve_conn, args=(sock, addr), daemon=True)
                with self._workers_lock:
                    self._workers.add(t)
                t.start()
        finally:
            try:
                ls.close()
            except OSError:
                pass
            self._drain()

    def _reserve_ip(self, ip: str) -> bool:
        with self._per_ip_lock:
            n = self._per_ip.get(ip, 0)
            if n >= self._cfg.max_connections_per_ip:
                return False
            self._per_ip[ip] = n + 1
            return True

    def _release_ip(self, ip: str) -> None:
        with self._per_ip_lock:
            n = self._per_ip.get(ip, 0) - 1
            if n <= 0:
                self._per_ip.pop(ip, None)
            else:
                self._per_ip[ip] = n

    def _shed(self, sock: socket.socket) -> None:
        """Reject an over-cap peer and close, fast. Under TLS we just close (the peer
        expects a TLS handshake, not a plaintext frame). Best-effort; never blocks long."""
        try:
            if self._cfg.tls is None:
                sock.settimeout(1.0)
                sock.sendall(encode_frame(MsgType.ERROR, b"server busy"))
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _serve_conn(self, sock: socket.socket, addr: tuple) -> None:
        ip = addr[0]
        peer = "%s:%d" % (addr[0], addr[1])
        conn: Optional[Connection] = None
        try:
            # 1) TLS handshake first (if configured), bounded by handshake_timeout so a
            #    slow or bogus TLS client can't hold a slot. With require_client_cert,
            #    this step also *authenticates* the peer — an unauthenticated client never
            #    reaches the protocol layer (security §1-2).
            try:
                sock.settimeout(self._cfg.handshake_timeout)
                if self._cfg.tls is not None:
                    sock = self._cfg.tls.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, socket.timeout, TimeoutError, OSError) as exc:
                self.metrics.handshake_failures += 1
                logger.info("TLS handshake with %s failed: %s", peer, exc)
                return

            # 2) Protocol handshake under a TINY payload cap and the short handshake
            #    budget — an unauthenticated peer can make us buffer only a few KB and
            #    hold a slot only briefly (security §7). Relax both once it's trusted.
            conn = Connection(
                sock,
                idle_timeout=self._cfg.handshake_timeout,
                message_timeout=self._cfg.handshake_timeout,
                max_payload=self._cfg.handshake_max_payload,
            )
            try:
                version = perform_server_handshake(conn)
            except (ProtocolError, ProtocolTimeout, ConnectionClosed) as exc:
                self.metrics.handshake_failures += 1
                logger.info("handshake with %s failed: %s", peer, exc)
                return
            conn.set_max_payload(self._cfg.max_payload)
            conn.set_timeouts(self._cfg.idle_timeout, self._cfg.message_timeout)
            logger.debug("handshake ok with %s (version %d)", peer, version)

            # 3) Application handler owns the connection until it returns.
            self._handler(conn)
        except ConnectionClosed:
            pass  # normal peer departure
        except ProtocolError as exc:
            self.metrics.handler_errors += 1
            logger.info("protocol error from %s: %s", peer, exc)
        except ProtocolTimeout:
            logger.info("timeout for %s", peer)
        except Exception:  # never let one connection crash
            self.metrics.handler_errors += 1  # the process (§5.5)
            logger.exception("unexpected error serving %s", peer)
        finally:
            if conn is not None:
                conn.close()
            else:
                try:
                    sock.close()
                except OSError:
                    pass
            self.metrics.closed += 1
            self._slots.release()
            self._release_ip(ip)
            with self._workers_lock:
                self._workers.discard(threading.current_thread())

    def shutdown(self) -> None:
        """Signal the accept loop to stop. serve_forever() then drains in-flight handlers.
        Safe to call from a signal handler or another thread."""
        self._stop.set()

    def _drain(self) -> None:
        """Wait (up to drain_timeout) for in-flight handlers to finish. Survivors are
        daemon threads, so the process can still exit; we log what's still busy."""
        deadline = time.monotonic() + self._cfg.drain_timeout
        while time.monotonic() < deadline:
            with self._workers_lock:
                remaining = [t for t in self._workers if t.is_alive()]
            if not remaining:
                break
            logger.info("draining: %d connection(s) still in flight", len(remaining))
            time.sleep(0.2)
        logger.info(
            "server stopped (accepted=%d shed_cap=%d shed_ip=%d handshake_fail=%d errors=%d)",
            self.metrics.accepted,
            self.metrics.rejected_over_cap,
            self.metrics.rejected_per_ip,
            self.metrics.handshake_failures,
            self.metrics.handler_errors,
        )


def install_signal_handlers(server: Server) -> None:
    """Wire SIGTERM/SIGINT to a graceful shutdown. Must be called from the main thread
    (a Python limitation). Optional: an application may manage signals itself."""
    import signal

    def _handler(signum: int, _frame: object) -> None:
        logger.info("received signal %d; shutting down gracefully", signum)
        server.shutdown()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


# ======================================================================================
# An example handler: handshake-then-echo with liveness, suitable as a starting point.
# ======================================================================================
def echo_handler(conn: Connection) -> None:
    """Echo DATA, answer PING with PONG, stop on BYE. Reject anything else and close —
    in a real handler, dispatch on msg_type to your application logic (§10.1)."""
    while True:
        frame = conn.recv()
        if frame.msg_type == MsgType.DATA:
            conn.send(MsgType.DATA, frame.payload)
        elif frame.msg_type == MsgType.PING:
            conn.send(MsgType.PONG, frame.payload)
        elif frame.msg_type == MsgType.BYE:
            return
        else:
            conn.send(MsgType.ERROR, b"unexpected message type")
            return


# ======================================================================================
# Self-contained loopback demo (run: python3 framed_protocol.py).
# The real tests live in test_protocol.py.
# ======================================================================================
def _demo() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    server = Server(ServerConfig(host="127.0.0.1", port=0, max_connections=8), echo_handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Wait for the bind to complete.
    for _ in range(50):
        host, port = server.address
        if port:
            break
        time.sleep(0.02)

    client = connect("127.0.0.1", port)
    print(f"handshake ok; negotiated version {client.peer_version}")

    client.send(MsgType.DATA, b"the quick brown fox")
    echo = client.recv()
    assert echo.msg_type == MsgType.DATA and echo.payload == b"the quick brown fox"
    print(f"echo ok: {echo.payload!r}")

    client.send(MsgType.PING, b"\x01\x02")
    pong = client.recv()
    assert pong.msg_type == MsgType.PONG and pong.payload == b"\x01\x02"
    print("ping/pong ok")

    client.send(MsgType.BYE)
    client.close()
    server.shutdown()
    t.join(2.0)
    print("graceful close ok")
    print("DEMO OK")


if __name__ == "__main__":
    _demo()
