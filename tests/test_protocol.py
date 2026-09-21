"""Tests for the YD.LO1 pure codec.

Vectors are synthetic on purpose: a real state ciphertext plus the real uuid
would embed a live lock's AES key in the repo. The CRC is checked against its
standard published value, and everything else is validated by round-trip.
"""

import os
import sys

from Crypto.Cipher import AES

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from wyze_lock_classic_local import protocol as p  # noqa: E402


def test_crc16_arc_standard_check_value():
    # CRC-16/ARC of b"123456789" is 0xBB3D per the standard catalogue.
    assert p.crc16_arc(b"123456789") == 0xBB3D
    assert p.crc16_arc(b"") == 0x0000


def test_l1_round_trip():
    body = bytes.fromhex("96001234")
    frame = p.pack_l1(body, seq=0x0102, flags=p.L1_FLAG_DATA)
    assert frame[0] == p.L1_MAGIC
    parsed = p.parse_l1(frame)
    assert parsed.complete
    assert parsed.flags == p.L1_FLAG_DATA
    assert parsed.seq == 0x0102
    assert parsed.body == body


def test_l1_rejects_bad_magic():
    try:
        p.parse_l1(b"\x00" * 8)
    except ValueError:
        return
    raise AssertionError("expected ValueError on bad magic")


def test_l1_rejects_bad_crc():
    frame = bytearray(p.pack_l1(b"\x01\x02\x03", seq=1))
    frame[-1] ^= 0xFF  # corrupt the body so the CRC no longer matches
    try:
        p.parse_l1(bytes(frame))
    except ValueError:
        return
    raise AssertionError("expected ValueError on bad CRC")


def test_l1_incomplete_frame_flagged_not_crc_checked():
    body = b"\xaa" * 20
    full = p.pack_l1(body, seq=1)
    partial = full[:15]  # header + only part of the body
    parsed = p.parse_l1(partial)
    assert parsed.complete is False


def test_l2_round_trip():
    tlvs = {0x03: bytes.fromhex("6ab0186a"), 0x05: (999).to_bytes(2, "big")}
    body = p.pack_l2(0x96, tlvs)
    cmd, flags, out = p.parse_l2(body)
    assert cmd == 0x96
    assert flags == 0
    assert out == tlvs


def test_state_decode_locked_and_unlocked():
    uuid = "0123456789abcdef0123456789abcdef"
    key = p.state_key(uuid)
    assert key == b"0123456789abcdef"  # last 16 chars of the uuid, lowercased

    def make(status, ts):
        plain = bytes([status]) + ts.to_bytes(4, "big") + b"\x00" * 6 + b"loock"
        return AES.new(key, AES.MODE_ECB).encrypt(plain)

    locked = p.decode_state(uuid, make(p.STATE_LOCKED, 1789904485))
    assert locked.locked is True
    assert locked.status_byte == p.STATE_LOCKED
    assert locked.timestamp == 1789904485

    unlocked = p.decode_state(uuid, make(p.STATE_UNLOCKED, 1789928099))
    assert unlocked.locked is False
    assert unlocked.timestamp == 1789928099


def test_build_hello_structure():
    uuid = "0123456789abcdef0123456789abcdef"
    ct = p.build_hello(uuid)
    assert len(ct) == 16
    pt = AES.new(p.state_key(uuid), AES.MODE_ECB).decrypt(ct)
    assert pt == b"1" + b"0" * 10 + b"loock"


def test_decode_battery():
    uuid = "0123456789abcdef0123456789abcdef"
    plain = bytes([100]) + (1789932325).to_bytes(4, "big") + b"\x00" * 6 + b"loock"
    ct = AES.new(p.state_key(uuid), AES.MODE_ECB).encrypt(plain)
    assert p.decode_battery(uuid, ct) == 100


def test_challenge_request_is_wellformed():
    frame = p.build_challenge_request()
    parsed = p.parse_l1(frame)
    cmd, _flags, tlvs = p.parse_l2(parsed.body)
    assert cmd == p.L2_CMD_REQUEST_CHALLENGE
    assert tlvs[0x0A] == b"\x27"


def test_extract_challenge():
    nonce = bytes(range(16))
    body = p.pack_l2(p.L2_CMD_CHALLENGE, {p.TAG_CHALLENGE: nonce})
    assert p.extract_challenge(body) == nonce


def test_lock_unlock_frame_structure_and_answer():
    ble_token = "0123456789abcdefFEDCBA9876543210"  # 32 chars; [16:] is the key
    ble_id = 1001
    challenge = bytes(range(16))

    frame = p.build_lock_unlock(ble_id, ble_token, challenge, lock=True, seq=2)
    parsed = p.parse_l1(frame)
    cmd, _flags, tlvs = p.parse_l2(parsed.body)
    assert cmd == p.L2_CMD_LOCK_UNLOCK
    assert tlvs[0x05] == ble_id.to_bytes(2, "big")
    assert len(tlvs[0x04]) == 16
    # Trailer TLVs present.
    assert tlvs[0xF4] == b"\x01"

    # The answer is AES-ECB(token[16:], challenge) XOR magic; invert it back.
    key = ble_token[16:].encode()
    magic = bytes(a ^ b for a, b in zip(tlvs[0x04], p._MAGIC_LOCK))
    assert AES.new(key, AES.MODE_ECB).decrypt(magic) == challenge


def test_lock_and_unlock_magics_differ():
    ble_token = "0123456789abcdefFEDCBA9876543210"
    challenge = bytes(16)
    lock_frame = p.build_lock_unlock(1, ble_token, challenge, lock=True)
    unlock_frame = p.build_lock_unlock(1, ble_token, challenge, lock=False)
    assert lock_frame != unlock_frame
