"""Cryptographic building blocks for the protected command link.

Frame layout on the wire (one UDP datagram):

    DATA       0x01 | seq (8 bytes, big endian) | Ascon-AEAD128(ciphertext || tag)
    HELLO      0x10 | client_nonce (16)
    CHALLENGE  0x11 | server_nonce (16)
    KEM_INIT   0x12 | ML-KEM-768 ciphertext (1088) | ML-DSA-44 signature (2420)
    KEM_ACK    0x13 | Ascon-AEAD128("ok") under the vehicle->GCS key, seq 0

Nonce for DATA frames = direction (1 byte) || 7 zero bytes || seq (8 bytes).
Associated data = the 9-byte header (type || seq), so the header cannot be altered.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .ascon_aead import ascon_decrypt, ascon_encrypt

T_DATA, T_HELLO, T_CHALLENGE, T_KEM_INIT, T_KEM_ACK = 0x01, 0x10, 0x11, 0x12, 0x13
DIR_G2V, DIR_V2G = 0, 1
HDR_LEN, TAG_LEN = 9, 16
KEM_CT_LEN, DSA_SIG_LEN = 1088, 2420
PROTO_LABEL = b"uav-cmdlink-v1"

# PSK mode uses a nanosecond timestamp as sequence number; frames older than this are dropped.
PSK_FRESHNESS_NS = 5_000_000_000


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def nonce_for(direction: int, seq: int) -> bytes:
    return bytes([direction]) + bytes(7) + seq.to_bytes(8, "big")


class ReplayWindow:
    """Sliding-window anti-replay check (same idea as IPsec ESP, RFC 4303)."""

    def __init__(self, size: int = 64):
        self.size = size
        self.highest = 0
        self.bitmap = 0  # bit i set => (highest - i) already seen

    def check(self, seq: int) -> bool:
        if seq == 0:
            return False
        if seq > self.highest:
            return True
        offset = self.highest - seq
        return offset < self.size and not (self.bitmap >> offset) & 1

    def update(self, seq: int) -> None:
        if seq > self.highest:
            shift = seq - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.size) - 1) if shift < self.size else 1
            self.highest = seq
        else:
            self.bitmap |= 1 << (self.highest - seq)


class RejectReason:
    AUTH = "auth_fail"
    REPLAY = "replay"
    STALE = "stale"
    MALFORMED = "malformed"


@dataclass
class ChannelKeys:
    send_key: bytes
    recv_key: bytes
    send_dir: int
    recv_dir: int


class SecureChannel:
    """Encrypts/decrypts DATA frames for one direction pair.

    counter mode   : seq = 1, 2, 3 ... (fresh keys every session, used after ML-KEM handshake)
    timestamp mode : seq = time.time_ns(), strictly increasing (static PSK, survives restarts)
    """

    def __init__(self, keys: ChannelKeys, timestamp_seq: bool):
        self.k = keys
        self.timestamp_seq = timestamp_seq
        self.next_seq = 1
        self.window = ReplayWindow()

    def _new_seq(self) -> int:
        if self.timestamp_seq:
            seq = max(time.time_ns(), self.next_seq)
        else:
            seq = self.next_seq
        self.next_seq = seq + 1
        return seq

    def seal(self, plaintext: bytes) -> bytes:
        seq = self._new_seq()
        hdr = bytes([T_DATA]) + seq.to_bytes(8, "big")
        return hdr + ascon_encrypt(self.k.send_key, nonce_for(self.k.send_dir, seq), hdr, plaintext)

    def open(self, frame: bytes) -> tuple[bytes | None, str | None]:
        if len(frame) < HDR_LEN + TAG_LEN or frame[0] != T_DATA:
            return None, RejectReason.MALFORMED
        hdr = frame[:HDR_LEN]
        seq = int.from_bytes(hdr[1:], "big")
        if self.timestamp_seq and seq < time.time_ns() - PSK_FRESHNESS_NS:
            return None, RejectReason.STALE
        if not self.window.check(seq):
            return None, RejectReason.REPLAY
        pt = ascon_decrypt(self.k.recv_key, nonce_for(self.k.recv_dir, seq), hdr, frame[HDR_LEN:])
        if pt is None:
            return None, RejectReason.AUTH
        self.window.update(seq)  # only after the tag verified
        return pt, None


def psk_channel(psk: bytes, role: str) -> SecureChannel:
    g2v = hkdf(psk, b"", PROTO_LABEL + b" psk g2v", 16)
    v2g = hkdf(psk, b"", PROTO_LABEL + b" psk v2g", 16)
    return SecureChannel(_orient(g2v, v2g, role), timestamp_seq=True)


def _orient(g2v: bytes, v2g: bytes, role: str) -> ChannelKeys:
    if role == "gcs":
        return ChannelKeys(g2v, v2g, DIR_G2V, DIR_V2G)
    return ChannelKeys(v2g, g2v, DIR_V2G, DIR_G2V)


# ---------------------------------------------------------------- ML-KEM handshake

def _kem():
    from kyber_py.ml_kem import ML_KEM_768
    return ML_KEM_768


def _dsa():
    from dilithium_py.ml_dsa import ML_DSA_44
    return ML_DSA_44


def transcript(cn: bytes, sn: bytes, ct: bytes) -> bytes:
    return PROTO_LABEL + b" kem" + cn + sn + hashlib.sha256(ct).digest()


def session_keys(shared: bytes, cn: bytes, sn: bytes, ct: bytes, role: str) -> SecureChannel:
    okm = hkdf(shared, cn + sn, hashlib.sha256(transcript(cn, sn, ct)).digest(), 32)
    return SecureChannel(_orient(okm[:16], okm[16:], role), timestamp_seq=False)


def gcs_kem_init(vehicle_ek: bytes, gcs_dsa_sk: bytes, cn: bytes, sn: bytes) -> tuple[bytes, SecureChannel]:
    """GCS side: encapsulate to the pinned vehicle key and sign the transcript."""
    shared, ct = _kem().encaps(vehicle_ek)
    sig = _dsa().sign(gcs_dsa_sk, transcript(cn, sn, ct))
    frame = bytes([T_KEM_INIT]) + ct + sig
    return frame, session_keys(shared, cn, sn, ct, "gcs")


def vehicle_kem_accept(frame: bytes, vehicle_dk: bytes, gcs_dsa_pk: bytes, cn: bytes, sn: bytes) -> SecureChannel | None:
    """Vehicle side: verify the GCS signature (GCS authentication), then decapsulate."""
    if len(frame) != 1 + KEM_CT_LEN + DSA_SIG_LEN:
        return None
    ct, sig = frame[1:1 + KEM_CT_LEN], frame[1 + KEM_CT_LEN:]
    if not _dsa().verify(gcs_dsa_pk, transcript(cn, sn, ct), sig):
        return None
    shared = _kem().decaps(vehicle_dk, ct)
    return session_keys(shared, cn, sn, ct, "vehicle")


def kem_ack(ch: SecureChannel) -> bytes:
    hdr = bytes([T_KEM_ACK])
    return hdr + ascon_encrypt(ch.k.send_key, nonce_for(ch.k.send_dir, 0), hdr, b"ok")


def kem_ack_valid(ch: SecureChannel, frame: bytes) -> bool:
    hdr = frame[:1]
    return ascon_decrypt(ch.k.recv_key, nonce_for(ch.k.recv_dir, 0), hdr, frame[1:]) == b"ok"


# ---------------------------------------------------------------- key material

KEYFILE = Path(__file__).resolve().parent.parent / "keys" / "testbed_keys.json"


def generate_keys(path: Path = KEYFILE) -> dict:
    ek, dk = _kem().keygen()
    pk, sk = _dsa().keygen()
    keys = {
        "psk": secrets.token_hex(16),
        "mavlink_signing_key": secrets.token_hex(32),
        "vehicle_kem_ek": ek.hex(), "vehicle_kem_dk": dk.hex(),
        "gcs_dsa_pk": pk.hex(), "gcs_dsa_sk": sk.hex(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(keys, indent=1))
    os.chmod(path, 0o600)
    return keys


def load_keys(path: Path = KEYFILE) -> dict:
    if not path.exists():
        return generate_keys(path)
    return json.loads(path.read_text())
