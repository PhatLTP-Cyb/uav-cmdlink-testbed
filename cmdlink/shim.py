"""Link shim: sits at each end of the radio link and (optionally) protects every datagram.

    GCS app  <-UDP->  gcs shim  <-- untrusted link (relay / attacker) -->  vehicle shim  <-UDP/TCP->  autopilot

Modes
  plain    : bytes forwarded unchanged (baseline)
  mavsign  : bytes forwarded unchanged; MAVLink 2 signing is done by the endpoints themselves
  ascon    : Ascon-AEAD128 per datagram, static pre-shared key, timestamp sequence numbers
  kem      : ML-KEM-768 + ML-DSA-44 handshake per session, then Ascon-AEAD128 with counters

Usage
  python -m cmdlink.shim --role gcs     --mode kem --app-port 14550 --link-bind 14551 --link-peer 127.0.0.1:14552
  python -m cmdlink.shim --role vehicle --mode kem --link-bind 14554 --vehicle udp:127.0.0.1:14560
On SIGTERM/SIGINT it prints one JSON line of statistics and exits.
"""
from __future__ import annotations

import argparse
import json
import secrets
import selectors
import signal
import socket
import sys
import time
from collections import Counter

from . import crypto as C

RAW_MODES = ("plain", "mavsign")


def parse_addr(s: str) -> tuple[str, int]:
    host, port = s.rsplit(":", 1)
    return host, int(port)


class VehiclePort:
    """Connection to the autopilot: 'udp:host:port' (we send to it) or 'tcp:host:port' (SITL serial0)."""

    def __init__(self, url: str):
        kind, rest = url.split(":", 1)
        self.addr = parse_addr(rest)
        self.tcp = kind == "tcp"
        if self.tcp:
            self.sock = socket.create_connection(self.addr, timeout=10)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)

    def send(self, data: bytes) -> None:
        if self.tcp:
            self.sock.sendall(data)
        else:
            self.sock.sendto(data, self.addr)

    def recv(self) -> bytes:
        return self.sock.recv(65535)


class Shim:
    def __init__(self, args):
        self.role, self.mode = args.role, args.mode
        self.stats = Counter()
        self.handshake_ms = None
        self.channel: C.SecureChannel | None = None
        self.keys = C.load_keys() if self.mode in ("ascon", "kem") else {}
        if self.mode == "ascon":
            self.channel = C.psk_channel(bytes.fromhex(self.keys["psk"]), self.role)

        self.link = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.link.bind(("127.0.0.1", args.link_bind))
        self.link_peer = parse_addr(args.link_peer) if args.link_peer else None

        self.sel = selectors.DefaultSelector()
        self.sel.register(self.link, selectors.EVENT_READ, "link")
        if self.role == "gcs":
            self.app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.app.bind(("127.0.0.1", args.app_port))
            self.app_peer = None
            self.sel.register(self.app, selectors.EVENT_READ, "local")
        else:
            self.vehicle = VehiclePort(args.vehicle)
            self.sel.register(self.vehicle.sock, selectors.EVENT_READ, "local")

        # handshake state
        self.cn = self.sn = None
        self.pending: C.SecureChannel | None = None
        self.kem_init_frame = None
        self.hs_start = None
        self.last_hs_tx = self.pending_since = 0.0
        self.running = True

    # ---------------------------------------------------------------- local side
    def local_send(self, data: bytes) -> None:
        if self.role == "gcs":
            if self.app_peer:
                self.app.sendto(data, self.app_peer)
        else:
            self.vehicle.send(data)

    def on_local(self, sock) -> None:
        if self.role == "gcs":
            data, self.app_peer = self.app.recvfrom(65535)
        else:
            data = self.vehicle.recv()
            if not data:
                raise ConnectionError("vehicle closed the connection")
        self.stats["local_in"] += 1
        if self.mode in RAW_MODES:
            out = data
        elif self.channel is None:
            self.stats["dropped_no_session"] += 1
            return
        else:
            out = self.channel.seal(data)
        if self.link_peer:
            self.link.sendto(out, self.link_peer)
            self.stats["link_out"] += 1
            self.stats["link_out_bytes"] += len(out)

    # ---------------------------------------------------------------- link side
    def on_link(self) -> None:
        frame, addr = self.link.recvfrom(65535)
        if self.role == "vehicle":
            self.link_peer = addr  # reply to whoever forwards GCS traffic to us
        self.stats["link_in"] += 1
        if self.mode in RAW_MODES:
            self.local_send(frame)
            return
        t = frame[0] if frame else -1
        if t == C.T_DATA:
            if self.channel is None:
                self.stats["dropped_no_session"] += 1
                return
            pt, why = self.channel.open(frame)
            if pt is None:
                self.stats["rejected_" + why] += 1
                return
            self.local_send(pt)
        elif self.mode == "kem" and t in (C.T_HELLO, C.T_CHALLENGE, C.T_KEM_INIT, C.T_KEM_ACK):
            self.on_handshake(t, frame, addr)
        else:
            self.stats["rejected_unprotected"] += 1  # e.g. raw MAVLink injected by an attacker

    def on_handshake(self, t: int, frame: bytes, addr) -> None:
        if self.role == "vehicle":
            if t == C.T_HELLO and len(frame) == 17:
                self.cn, self.sn = frame[1:], secrets.token_bytes(16)
                self.link.sendto(bytes([C.T_CHALLENGE]) + self.sn, addr)
            elif t == C.T_KEM_INIT and self.sn is not None:
                t0 = time.perf_counter()
                ch = C.vehicle_kem_accept(frame, bytes.fromhex(self.keys["vehicle_kem_dk"]),
                                          bytes.fromhex(self.keys["gcs_dsa_pk"]), self.cn, self.sn)
                if ch is None:
                    self.stats["rejected_handshake"] += 1
                    return
                self.stats["hs_vehicle_us"] = int((time.perf_counter() - t0) * 1e6)
                self.channel, self.sn = ch, None  # challenge is single use
                self.stats["sessions"] += 1
                self.link.sendto(C.kem_ack(ch), addr)
        else:
            if t == C.T_CHALLENGE and self.cn is not None and self.pending is None and len(frame) == 17:
                self.sn = frame[1:]
                self.kem_init_frame, self.pending = C.gcs_kem_init(
                    bytes.fromhex(self.keys["vehicle_kem_ek"]), bytes.fromhex(self.keys["gcs_dsa_sk"]), self.cn, self.sn)
                self.link.sendto(self.kem_init_frame, self.link_peer)
                self.last_hs_tx = self.pending_since = time.monotonic()
            elif t == C.T_KEM_ACK and self.pending is not None and C.kem_ack_valid(self.pending, frame):
                self.channel, self.pending = self.pending, None
                self.handshake_ms = round((time.perf_counter() - self.hs_start) * 1000, 1)
                print(json.dumps({"event": "session_established", "handshake_ms": self.handshake_ms}), flush=True)

    def tick(self) -> None:
        """GCS side drives the handshake and retransmits if a message was lost."""
        if self.role != "gcs" or self.mode != "kem" or self.channel is not None:
            return
        now = time.monotonic()
        if now - self.last_hs_tx < 1.0:
            return
        self.last_hs_tx = now
        if self.pending is not None and now - self.pending_since > 3.0:
            self.pending = None  # vehicle never confirmed (e.g. challenge mismatch): start over
        if self.pending is not None:
            self.link.sendto(self.kem_init_frame, self.link_peer)
        else:
            self.hs_start = time.perf_counter()  # measured from the HELLO that completes
            self.cn = secrets.token_bytes(16)
            self.link.sendto(bytes([C.T_HELLO]) + self.cn, self.link_peer)

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        while self.running:
            self.tick()
            for key, _ in self.sel.select(timeout=0.1):
                try:
                    self.on_link() if key.data == "link" else self.on_local(key.fileobj)
                except (BlockingIOError, ConnectionRefusedError):
                    pass
        out = {"role": self.role, "mode": self.mode, "handshake_ms": self.handshake_ms, **self.stats}
        print(json.dumps(out), flush=True)

    def stop(self, *_):
        self.running = False


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--role", choices=["gcs", "vehicle"], required=True)
    p.add_argument("--mode", choices=["plain", "mavsign", "ascon", "kem"], required=True)
    p.add_argument("--app-port", type=int, default=14550, help="GCS role: UDP port the GCS application sends to")
    p.add_argument("--link-bind", type=int, required=True)
    p.add_argument("--link-peer", help="GCS role: where protected frames are sent (relay or vehicle shim)")
    p.add_argument("--vehicle", default="udp:127.0.0.1:14560", help="vehicle role: udp:host:port or tcp:host:port")
    Shim(p.parse_args(argv)).run()


if __name__ == "__main__":
    sys.exit(main())
