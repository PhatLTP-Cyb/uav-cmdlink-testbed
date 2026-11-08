"""Unit tests: Ascon-AEAD128 against the official KAT, replay window, PSK and ML-KEM channels."""
import time
from pathlib import Path

import pytest

from cmdlink import crypto as C
from cmdlink.ascon_aead import ascon_decrypt, ascon_encrypt

KAT = Path(__file__).parent / "vectors" / "LWC_AEAD_KAT_128_128.txt"


def kat_entries():
    entry = {}
    for line in KAT.read_text().splitlines():
        if not line.strip():
            if entry:
                yield entry
            entry = {}
            continue
        k, _, v = line.partition(" = ")
        entry[k.strip()] = v.strip()
    if entry:
        yield entry


def test_ascon_aead128_official_kat():
    n = 0
    for e in kat_entries():
        key, nonce, pt, ad, ct = (bytes.fromhex(e[k]) for k in ("Key", "Nonce", "PT", "AD", "CT"))
        assert ascon_encrypt(key, nonce, ad, pt) == ct, e["Count"]
        assert ascon_decrypt(key, nonce, ad, ct) == pt
        n += 1
    assert n == 1089


def test_replay_window():
    w = C.ReplayWindow(8)
    for s in (1, 2, 5):
        assert w.check(s); w.update(s)
    assert not w.check(5) and not w.check(2)
    assert w.check(3)            # late but unseen
    w.update(20)
    assert not w.check(5)        # fell out of the window
    assert not w.check(0)


def test_psk_channel_roundtrip_and_attacks():
    psk = bytes(range(16))
    g, v = C.psk_channel(psk, "gcs"), C.psk_channel(psk, "vehicle")
    f = g.seal(b"hello vehicle")
    assert v.open(f) == (b"hello vehicle", None)
    assert v.open(f) == (None, C.RejectReason.REPLAY)
    f2 = bytearray(g.seal(b"x" * 30)); f2[12] ^= 1
    assert v.open(bytes(f2)) == (None, C.RejectReason.AUTH)
    # a frame sealed by the GCS must not be accepted back by the GCS (reflection)
    assert g.open(g.seal(b"reflect"))[0] is None
    # stale timestamp
    old = bytes([C.T_DATA]) + (time.time_ns() - 10**10).to_bytes(8, "big") + bytes(20)
    assert v.open(old) == (None, C.RejectReason.STALE)


def test_kem_handshake():
    keys = C.generate_keys(Path("/tmp/_cmdlink_test_keys.json"))
    ek, dk = bytes.fromhex(keys["vehicle_kem_ek"]), bytes.fromhex(keys["vehicle_kem_dk"])
    pk, sk = bytes.fromhex(keys["gcs_dsa_pk"]), bytes.fromhex(keys["gcs_dsa_sk"])
    cn, sn = b"c" * 16, b"s" * 16
    frame, gch = C.gcs_kem_init(ek, sk, cn, sn)
    vch = C.vehicle_kem_accept(frame, dk, pk, cn, sn)
    assert vch is not None and C.kem_ack_valid(gch, C.kem_ack(vch))
    assert vch.open(gch.seal(b"cmd"))[0] == b"cmd"
    assert gch.open(vch.seal(b"ack"))[0] == b"ack"
    # replayed KEM_INIT against a fresh challenge is rejected (signature covers the server nonce)
    assert C.vehicle_kem_accept(frame, dk, pk, cn, b"t" * 16) is None
    # attacker without the GCS signing key cannot open a session
    _, other_sk = C._dsa().keygen()
    bad, _ = C.gcs_kem_init(ek, other_sk, cn, sn)
    assert C.vehicle_kem_accept(bad, dk, pk, cn, sn) is None
