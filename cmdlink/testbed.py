"""Run attack scenarios and benchmarks over the four link configurations.

  python -m cmdlink.testbed attacks --modes plain mavsign ascon kem
  python -m cmdlink.testbed bench   --modes plain mavsign ascon kem --n 500
  python -m cmdlink.testbed crypto-bench
  python -m cmdlink.testbed provision-signing --url tcp:127.0.0.1:5760    # SITL only, once

Topology (all on 127.0.0.1):
  GCS app -> :14550 gcs shim :14551 -> :14552 relay :14553 -> :14554 vehicle shim -> vehicle
  vehicle = mock vehicle on udp :14560 (default) or ArduPilot SITL (--vehicle tcp:127.0.0.1:5760)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

import psutil

from .mav import COPTER_MODES, GCS_COMPID, GCS_SYSID, MODE_NAMES, VEH_COMPID, VEH_SYSID, mavlink2, mavutil
from .crypto import load_keys

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
MODES = ["plain", "mavsign", "ascon", "kem"]


class Stack:
    """Starts vehicle (mock), vehicle shim, relay and GCS shim as separate processes."""

    def __init__(self, mode: str, vehicle: str | None):
        self.mode, self.vehicle_url = mode, vehicle
        self.procs: dict[str, subprocess.Popen] = {}

    def _spawn(self, name, *args):
        self.procs[name] = subprocess.Popen([sys.executable, "-m", *args], cwd=ROOT, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True)

    def __enter__(self):
        load_keys()  # generate once, before processes race to do it
        if self.vehicle_url is None:
            sig = ["--signing"] if self.mode == "mavsign" else []
            self._spawn("vehicle", "cmdlink.mock_vehicle", "--listen", "udpin:127.0.0.1:14560", *sig)
            time.sleep(0.4)
        self._spawn("vehicle_shim", "cmdlink.shim", "--role", "vehicle", "--mode", self.mode, "--link-bind", "14554",
                    "--vehicle", self.vehicle_url or "udp:127.0.0.1:14560")
        self._spawn("relay", "cmdlink.relay")
        self._spawn("gcs_shim", "cmdlink.shim", "--role", "gcs", "--mode", self.mode, "--app-port", "14550",
                    "--link-bind", "14551", "--link-peer", "127.0.0.1:14552")
        time.sleep(0.8)
        for n, p in self.procs.items():
            if p.poll() is not None:
                raise RuntimeError(f"{n} exited early: {p.stderr.read()}")
        return self

    def cpu_seconds(self, names) -> float:
        total = 0.0
        for n in names:
            if n in self.procs and self.procs[n].poll() is None:
                t = psutil.Process(self.procs[n].pid).cpu_times()
                total += t.user + t.system
        return total

    def __exit__(self, *exc):
        self.final = {}
        for n, p in self.procs.items():
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for n, p in self.procs.items():
            try:
                out, err = p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                out, err = p.communicate()
            lines = [l for l in out.splitlines() if l.startswith("{")]
            self.final[n] = json.loads(lines[-1]) if lines else {"stderr": err[-500:]}


def relay_ctl(cmd: str) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(cmd.encode(), ("127.0.0.1", 14599))
    data, _ = s.recvfrom(65535)
    return json.loads(data)


class Gcs:
    def __init__(self, mode: str):
        self.conn = mavutil.mavlink_connection("udpout:127.0.0.1:14550", source_system=GCS_SYSID,
                                               source_component=GCS_COMPID)
        if mode == "mavsign":
            key = bytes.fromhex(load_keys()["mavlink_signing_key"])
            self.conn.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=lambda mav, mid: False)
        self.mode = None

    def connect(self, timeout=30) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.conn.mav.heartbeat_send(mavlink2.MAV_TYPE_GCS, mavlink2.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            m = self.conn.recv_match(type="HEARTBEAT", blocking=True, timeout=0.5)
            if m and m.get_srcSystem() == VEH_SYSID:
                self.mode = m.custom_mode
                return True
        return False

    def set_mode(self, name: str, timeout=2.0) -> bool:
        self.conn.mav.command_long_send(VEH_SYSID, VEH_COMPID, mavlink2.MAV_CMD_DO_SET_MODE, 0,
                                        mavlink2.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, COPTER_MODES[name], 0, 0, 0, 0, 0)
        return self._ack(mavlink2.MAV_CMD_DO_SET_MODE, timeout) is not None

    def _ack(self, command, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            m = self.conn.recv_match(type="COMMAND_ACK", blocking=True, timeout=end - time.monotonic())
            if m and m.command == command:
                return m
        return None

    def current_mode(self, settle=1.5) -> int | None:
        """Mode reported by the latest vehicle heartbeat received within `settle` seconds."""
        end, mode = time.monotonic() + settle, None
        while time.monotonic() < end:
            m = self.conn.recv_match(type="HEARTBEAT", blocking=True, timeout=end - time.monotonic())
            if m and m.get_srcSystem() == VEH_SYSID:
                mode = m.custom_mode
        return mode

    def ping(self) -> float | None:
        t0 = time.perf_counter()
        self.conn.mav.command_long_send(VEH_SYSID, VEH_COMPID, mavlink2.MAV_CMD_REQUEST_MESSAGE, 0,
                                        mavlink2.MAVLINK_MSG_ID_SYS_STATUS, 0, 0, 0, 0, 0, 0)
        return (time.perf_counter() - t0) * 1000 if self._ack(mavlink2.MAV_CMD_REQUEST_MESSAGE, 1.0) else None


def name(m):
    return MODE_NAMES.get(m, str(m))


# ------------------------------------------------------------------ attacks

def run_attacks(mode: str, vehicle: str | None) -> list[dict]:
    rows = []
    with Stack(mode, vehicle) as st:
        g = Gcs(mode)
        if not g.connect():
            raise RuntimeError(f"[{mode}] no heartbeat from vehicle through the link")

        # 1. replay: capture a legitimate LAND command, later resend it while the vehicle is in GUIDED
        relay_ctl("mark_start")
        ok1 = g.set_mode("LAND")
        relay_ctl("mark_stop")
        ok2 = g.set_mode("GUIDED")
        before = g.current_mode()
        n = relay_ctl("replay_marked")["replayed"]
        after = g.current_mode()
        rows.append(dict(mode=mode, attack="replay", legit_commands_ok=ok1 and ok2, mode_before=name(before),
                         mode_after=name(after), attack_succeeded=after == COPTER_MODES["LAND"],
                         detail=f"{n} datagrams replayed"))

        # 2. injection: forged, unsigned DO_SET_MODE(LAND) with the GCS's system/component ids
        g.set_mode("GUIDED")
        before = g.current_mode()
        relay_ctl("inject_land")
        after = g.current_mode()
        rows.append(dict(mode=mode, attack="injection", legit_commands_ok=True, mode_before=name(before),
                         mode_after=name(after), attack_succeeded=after == COPTER_MODES["LAND"],
                         detail="spoofed sysid 255 / compid 190"))

        # 3. tampering: operator asks for LOITER, attacker rewrites it in flight to LAND
        g.set_mode("GUIDED")
        before = g.current_mode()
        relay_ctl("tamper_on")
        acked = g.set_mode("LOITER")
        time.sleep(0.3)
        relay_ctl("tamper_off")
        after = g.current_mode()
        rows.append(dict(mode=mode, attack="tampering", legit_commands_ok=acked, mode_before=name(before),
                         mode_after=name(after), attack_succeeded=after == COPTER_MODES["LAND"],
                         detail="DO_SET_MODE LOITER rewritten to LAND"))
    for r in rows:
        r["rejections_whole_run"] = {k: v for k, v in {**st.final.get("vehicle_shim", {}), **st.final.get("vehicle", {})}.items()
                           if k.startswith("rejected")}
    return rows


# ------------------------------------------------------------------ benchmark

def run_bench(mode: str, vehicle: str | None, n: int) -> dict:
    with Stack(mode, vehicle) as st:
        g = Gcs(mode)
        t_conn = time.perf_counter()
        if not g.connect():
            raise RuntimeError(f"[{mode}] no heartbeat")
        connect_ms = (time.perf_counter() - t_conn) * 1000
        for _ in range(20):
            g.ping()  # warm-up
        relay_ctl("reset_stats")
        names = ["gcs_shim", "vehicle_shim", "vehicle"]
        cpu0, own0 = st.cpu_seconds(names), time.process_time()
        rtts, lost = [], 0
        for _ in range(n):
            r = g.ping()
            (rtts.append(r) if r is not None else None)
            lost += r is None
        cpu1, own1 = st.cpu_seconds(names), time.process_time()
        rs = relay_ctl("stats")
    q = statistics.quantiles(rtts, n=20)
    gcs_shim = st.final.get("gcs_shim", {})
    return dict(mode=mode, n=n, lost=lost,
                rtt_mean_ms=round(statistics.mean(rtts), 3), rtt_p50_ms=round(statistics.median(rtts), 3),
                rtt_p95_ms=round(q[18], 3),
                g2v_bytes_per_pkt=round(rs.get("g2v_bytes", 0) / max(rs.get("g2v_pkts", 1), 1), 1),
                v2g_bytes_per_pkt=round(rs.get("v2g_bytes", 0) / max(rs.get("v2g_pkts", 1), 1), 1),
                cpu_ms_per_cmd=round((cpu1 - cpu0 + own1 - own0) * 1000 / n, 3),
                handshake_ms=gcs_shim.get("handshake_ms"), connect_ms=round(connect_ms, 1))


def crypto_bench(reps: int = 50) -> list[dict]:
    from . import crypto as C
    from .ascon_aead import ascon_decrypt, ascon_encrypt
    from kyber_py.ml_kem import ML_KEM_768
    from dilithium_py.ml_dsa import ML_DSA_44
    import hashlib
    import hmac
    k = load_keys()
    ek, dk = bytes.fromhex(k["vehicle_kem_ek"]), bytes.fromhex(k["vehicle_kem_dk"])
    pk, sk = bytes.fromhex(k["gcs_dsa_pk"]), bytes.fromhex(k["gcs_dsa_sk"])
    msg, key, nonce = bytes(45), bytes(16), bytes(16)  # 45 B = a MAVLink 2 COMMAND_LONG
    ct = ascon_encrypt(key, nonce, b"", msg)
    _, kct = ML_KEM_768.encaps(ek)
    sig = ML_DSA_44.sign(sk, b"x")

    def t(fn, r=reps):
        t0 = time.perf_counter()
        for _ in range(r):
            fn()
        return (time.perf_counter() - t0) / r * 1e6

    rows = [
        ("HMAC-SHA256 (MAVLink signing primitive), 45 B", t(lambda: hmac.new(bytes(32), msg, hashlib.sha256).digest(), 2000)),
        ("Ascon-AEAD128 encrypt, 45 B", t(lambda: ascon_encrypt(key, nonce, b"", msg), 500)),
        ("Ascon-AEAD128 decrypt, 45 B", t(lambda: ascon_decrypt(key, nonce, b"", ct), 500)),
        ("ML-KEM-768 encaps", t(lambda: ML_KEM_768.encaps(ek))),
        ("ML-KEM-768 decaps", t(lambda: ML_KEM_768.decaps(dk, kct))),
        ("ML-DSA-44 sign", t(lambda: ML_DSA_44.sign(sk, b"x"), 10)),
        ("ML-DSA-44 verify", t(lambda: ML_DSA_44.verify(pk, b"x", sig), 20)),
    ]
    return [{"operation": n, "us_per_op": round(v, 1)} for n, v in rows]


def provision_signing(url: str):
    """Send SETUP_SIGNING to the autopilot directly (not through the link) so it stores the key."""
    key = bytes.fromhex(load_keys()["mavlink_signing_key"])
    c = mavutil.mavlink_connection(url, source_system=GCS_SYSID, source_component=GCS_COMPID)
    c.wait_heartbeat(timeout=30)
    ts = int((time.time() - 1420070400) * 1e5)  # 10 us units since 2015-01-01, as MAVLink signing defines
    c.mav.setup_signing_send(VEH_SYSID, VEH_COMPID, list(key), ts)
    print("SETUP_SIGNING sent; ArduPilot now rejects unsigned commands on this link.")


def write_csv(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def plot_bench(rows: list[dict], path: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.6))
    labels = [r["mode"] for r in rows]
    for ax, key, title in zip(axes, ["rtt_p50_ms", "g2v_bytes_per_pkt", "cpu_ms_per_cmd"],
                              ["Command RTT, median (ms)", "Bytes per GCS->vehicle datagram", "CPU per command (ms)"]):
        ax.bar(labels, [r[key] for r in rows], color="#3b6ea5")
        ax.set_title(title, fontsize=10)
        ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for c in ("attacks", "bench"):
        s = sub.add_parser(c)
        s.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
        s.add_argument("--vehicle", help="e.g. tcp:127.0.0.1:5760 for SITL; default = mock vehicle")
        if c == "bench":
            s.add_argument("--n", type=int, default=500)
    sub.add_parser("crypto-bench")
    s = sub.add_parser("provision-signing")
    s.add_argument("--url", default="tcp:127.0.0.1:5760")
    a = p.parse_args(argv)
    tag = "sitl" if getattr(a, "vehicle", None) else "mock"

    if a.cmd == "attacks":
        rows = [r for m in a.modes for r in run_attacks(m, a.vehicle)]
        for r in rows:
            print(f"{r['mode']:8} {r['attack']:10} succeeded={str(r['attack_succeeded']):5} "
                  f"{r['mode_before']}->{r['mode_after']}  legit_ok={r['legit_commands_ok']}  {r['rejections_whole_run']}")
        for r in rows:
            r["rejections_whole_run"] = json.dumps(r["rejections_whole_run"])
        write_csv(RESULTS / f"attacks_{tag}.csv", rows)
    elif a.cmd == "bench":
        rows = [run_bench(m, a.vehicle, a.n) for m in a.modes]
        for r in rows:
            print(json.dumps(r))
        write_csv(RESULTS / f"bench_{tag}.csv", rows)
        plot_bench(rows, RESULTS / f"bench_{tag}.png")
    elif a.cmd == "crypto-bench":
        rows = crypto_bench()
        for r in rows:
            print(f"{r['operation']:48} {r['us_per_op']:>12,.1f} us")
        write_csv(RESULTS / "crypto_bench.csv", rows)
    else:
        provision_signing(a.url)


if __name__ == "__main__":
    main()
