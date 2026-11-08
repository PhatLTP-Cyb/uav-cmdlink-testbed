"""Minimal MAVLink 2 vehicle for running the testbed without ArduPilot SITL.

It behaves like ArduCopter for the commands the scenarios use:
  * HEARTBEAT at 2 Hz carrying the current custom mode
  * COMMAND_LONG MAV_CMD_DO_SET_MODE (176)      -> change mode, COMMAND_ACK accepted
  * COMMAND_LONG MAV_CMD_REQUEST_MESSAGE (512)  -> COMMAND_ACK accepted (used as a ping)
With --signing it enforces MAVLink 2 signing like ArduPilot does once a key is set:
unsigned or badly signed packets are dropped, and replayed timestamps are rejected.

Prints one JSON line of statistics on SIGTERM.
"""
from __future__ import annotations

import argparse
import json
import signal
import time
from collections import Counter

from .crypto import load_keys
from .mav import COPTER_MODES, VEH_COMPID, VEH_SYSID, mavlink2, mavutil


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--listen", default="udpin:127.0.0.1:14560")
    p.add_argument("--signing", action="store_true")
    a = p.parse_args(argv)

    conn = mavutil.mavlink_connection(a.listen, source_system=VEH_SYSID, source_component=VEH_COMPID)
    stats = Counter()
    if a.signing:
        key = bytes.fromhex(load_keys()["mavlink_signing_key"])
        conn.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=lambda mav, msg_id: False)

    mode = COPTER_MODES["STABILIZE"]
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last_hb = 0.0
    while running:
        now = time.monotonic()
        if now - last_hb > 0.5:  # silently skipped by pymavlink until a peer has been heard
            conn.mav.heartbeat_send(mavlink2.MAV_TYPE_QUADROTOR, mavlink2.MAV_AUTOPILOT_ARDUPILOTMEGA,
                                    mavlink2.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode, mavlink2.MAV_STATE_STANDBY)
            last_hb = now
        msg = conn.recv_msg()
        if msg is None:
            time.sleep(0.001)
            continue
        mtype = msg.get_type()
        if mtype == "BAD_DATA":
            reason = getattr(msg, "reason", "")
            stats["rejected_" + ("signature" if "ignature" in reason else "bad_data")] += 1
            continue
        if mtype != "COMMAND_LONG" or msg.target_system != VEH_SYSID:
            continue
        if msg.command == mavlink2.MAV_CMD_DO_SET_MODE:
            mode = int(msg.param2)
            stats["mode_changes"] += 1
            result = mavlink2.MAV_RESULT_ACCEPTED
        elif msg.command == mavlink2.MAV_CMD_REQUEST_MESSAGE:
            result = mavlink2.MAV_RESULT_ACCEPTED
        else:
            result = mavlink2.MAV_RESULT_UNSUPPORTED
        stats["commands_accepted"] += 1
        conn.mav.command_ack_send(msg.command, result, 0, 0, msg.get_srcSystem(), msg.get_srcComponent())
    print(json.dumps({"role": "mock_vehicle", "final_mode": mode, **stats}), flush=True)


if __name__ == "__main__":
    main()
