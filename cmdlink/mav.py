"""Shared MAVLink 2 helpers (forces MAVLink 2, which message signing requires)."""
import os

os.environ.setdefault("MAVLINK20", "1")
os.environ.setdefault("MAVLINK_DIALECT", "ardupilotmega")

from pymavlink import mavutil  # noqa: E402
from pymavlink.dialects.v20 import ardupilotmega as mavlink2  # noqa: E402

GCS_SYSID, GCS_COMPID = 255, 190
VEH_SYSID, VEH_COMPID = 1, 1

# ArduCopter custom flight modes used by the scenarios
COPTER_MODES = {"STABILIZE": 0, "GUIDED": 4, "LOITER": 5, "RTL": 6, "LAND": 9}
MODE_NAMES = {v: k for k, v in COPTER_MODES.items()}


def command_long_bytes(srcsys: int, srccomp: int, command: int, params, seq: int = 0) -> bytes:
    """Pack an (unsigned) COMMAND_LONG exactly as an attacker without the key would."""
    packer = mavlink2.MAVLink(None, srcSystem=srcsys, srcComponent=srccomp)
    packer.seq = seq
    p = list(params) + [0] * (7 - len(params))
    msg = mavlink2.MAVLink_command_long_message(VEH_SYSID, VEH_COMPID, command, 0, *p)
    return msg.pack(packer)
