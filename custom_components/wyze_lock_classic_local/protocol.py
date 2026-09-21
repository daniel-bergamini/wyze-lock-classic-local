"""Pure codec for the Wyze Lock Classic (YD.LO1) BLE protocol.

No I/O — every function here is pure bytes-in/bytes-out so it can be unit
tested without hardware. Transport (bleak) lives elsewhere.

The lock speaks a Yunding/"loock" house protocol over two layers:

- **L1** framing:  ``0xAB | flags | len(2 BE) | crc(2 BE) | seq(2 BE) | body``
  where ``crc`` is CRC-16/ARC over the body and ``len`` is the body length.
- **L2** command:  ``cmd | flags | [tag | len(2 BE) | value]…`` — a one-byte
  command, a flags byte, then TLV entries.

The **state/read** path is solved and validated: state characteristics are
AES-ECB blocks keyed by the last 16 ASCII chars of the lock's cloud uuid,
decrypting to ``status | ts | pad | "loock"`` (see decode_state).

The **actuation** path is the challenge-response over the Nordic UART service
(confirmed against a real app unlock that changed state on the wire):

1. Write the ``00002250`` hello block first (``build_hello`` — a session
   prime, not actuation on its own).
2. Send ``build_challenge_request()`` (seq 0) to the NUS write char.
3. The lock replies with an L1 ACK then a ``0x86`` challenge; pull the nonce
   with ``extract_challenge``.
4. Send ``build_ack`` (echoing the challenge frame's seq) then
   ``build_lock_unlock(ble_id, ble_token, challenge, lock)``.

``ble_id``/``ble_token`` come from the cloud BLE-token endpoint (once, reusable;
the nonce gives freshness). The answer is ``AES-ECB(ble_token[16:], nonce)``
XOR a per-command magic — verified byte-for-byte against real traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from Crypto.Cipher import AES

# --- GATT ------------------------------------------------------------------
# Nordic UART Service. Note: the write characteristic is …0002 and the notify
# characteristic is …0003 (some references name these "TX"/"RX" the other way
# round — trust the direction, not the label).
NUS_WRITE_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NUS_NOTIFY_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

# "loock" house-protocol state service; …2220 is the authoritative lock state.
LOCK_STATE_UUID = "00002220-0000-6b63-6f6c-2e6b636f6f6c"
# …2250 is the write sink for the lock/unlock command (see build_command).
LOCK_CMD_UUID = "00002250-0000-6b63-6f6c-2e6b636f6f6c"
# Standard Battery Level characteristic, but the value is AES-ECB encrypted
# (uuid key) like the lock state, not a plain 0-100 byte.
BATTERY_UUID = "00002a19-0000-1000-8000-00805f9b34fb"

# --- L1 framing ------------------------------------------------------------
L1_MAGIC = 0xAB
L1_HEADER_LEN = 8

# L1 flag values seen on the wire.
L1_FLAG_NONE = 0x00
L1_FLAG_ACK = 0x08      # client -> lock acknowledgement
L1_FLAG_LOCK_ACK = 0x48  # lock -> client acknowledgement
L1_FLAG_DATA = 0x40      # lock -> client data frame

# --- L2 commands / tags ----------------------------------------------------
L2_CMD_REQUEST_CHALLENGE = 0x91
L2_CMD_CHALLENGE = 0x86       # lock -> client, carries the nonce
L2_CMD_LOCK_UNLOCK = 0x04     # client -> lock, and the lock's result echo
TAG_CHALLENGE = 0xD2          # nonce tag inside a 0x86 frame

# Per-command magic XORed into the encrypted nonce; tail is ASCII "loock".
# Both CONFIRMED against real app traffic: build_lock_unlock reproduces the
# app's lock (0x02) and unlock (0x01) frames byte-for-byte, and the lock's
# state characteristic changed accordingly on the wire.
_MAGIC_UNLOCK = bytes.fromhex("01000000000000000000006c6f6f636b")
_MAGIC_LOCK = bytes.fromhex("02000000000000000000006c6f6f636b")

# State-characteristic status byte (characteristic 0x2220).
STATE_LOCKED = 0x01
STATE_UNLOCKED = 0x02


def crc16_arc(data: bytes) -> int:
    """CRC-16/ARC (poly 0xA001 reflected, init 0x0000, no final xor)."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def pack_l1(body: bytes, seq: int, flags: int = L1_FLAG_NONE) -> bytes:
    """Wrap an L2 body (or empty bytes, for an ACK) in an L1 frame."""
    return b"".join(
        (
            bytes([L1_MAGIC, flags]),
            len(body).to_bytes(2, "big"),
            crc16_arc(body).to_bytes(2, "big"),
            seq.to_bytes(2, "big"),
            body,
        )
    )


@dataclass(frozen=True)
class L1Frame:
    flags: int
    seq: int
    body: bytes
    complete: bool  # False if the declared length exceeds the bytes present


def parse_l1(data: bytes) -> L1Frame:
    """Parse one L1 frame. Raises ValueError on a bad magic or CRC.

    ``complete`` is False when the body is shorter than the header's length
    field — i.e. the frame spans multiple BLE notifications and more bytes are
    expected. The CRC is only checked once the body is fully present.
    """
    if len(data) < L1_HEADER_LEN or data[0] != L1_MAGIC:
        raise ValueError("not an L1 frame")
    flags = data[1]
    length = int.from_bytes(data[2:4], "big")
    frame_crc = int.from_bytes(data[4:6], "big")
    seq = int.from_bytes(data[6:8], "big")
    body = data[L1_HEADER_LEN:]
    if len(body) < length:
        return L1Frame(flags=flags, seq=seq, body=body, complete=False)
    body = body[:length]
    if crc16_arc(body) != frame_crc:
        raise ValueError(f"CRC mismatch: frame 0x{frame_crc:04x} != 0x{crc16_arc(body):04x}")
    return L1Frame(flags=flags, seq=seq, body=body, complete=True)


def pack_l2(cmd: int, tlvs: Dict[int, bytes], flags: int = 0) -> bytes:
    """Build an L2 command body from a command id and TLV entries."""
    out = bytearray((cmd, flags))
    for tag, value in tlvs.items():
        out.append(tag)
        out += len(value).to_bytes(2, "big")
        out += value
    return bytes(out)


def parse_l2(body: bytes) -> Tuple[int, int, Dict[int, bytes]]:
    """Parse an L2 body into ``(cmd, flags, {tag: value})``."""
    cmd, flags = body[0], body[1]
    tlvs: Dict[int, bytes] = {}
    pos = 2
    while pos + 3 <= len(body):
        tag = body[pos]
        length = int.from_bytes(body[pos + 1 : pos + 3], "big")
        tlvs[tag] = body[pos + 3 : pos + 3 + length]
        pos += 3 + length
    return cmd, flags, tlvs


def state_key(lock_uuid: str) -> bytes:
    """AES key for the state characteristics: last 16 ASCII chars of the uuid."""
    return lock_uuid[-16:].lower().encode()


@dataclass(frozen=True)
class LockState:
    locked: bool
    status_byte: int
    timestamp: int  # unix seconds of the last state change


def decode_state(lock_uuid: str, ciphertext: bytes) -> LockState:
    """Decrypt and parse a state characteristic value (e.g. 0x2220).

    Layout after decryption: ``status | ts(4 BE) | pad | "loock"``.
    """
    plain = AES.new(state_key(lock_uuid), AES.MODE_ECB).decrypt(ciphertext)
    status = plain[0]
    return LockState(
        locked=status == STATE_LOCKED,
        status_byte=status,
        timestamp=int.from_bytes(plain[1:5], "big"),
    )


def decode_battery(lock_uuid: str, ciphertext: bytes) -> int:
    """Decrypt the battery characteristic (0x2a19) and return the percent.

    Same AES-ECB(uuid key) scheme as the state path; byte 0 of the plaintext is
    the battery level (0-100), followed by a timestamp and the "loock" marker.
    """
    plain = AES.new(state_key(lock_uuid), AES.MODE_ECB).decrypt(ciphertext)
    return plain[0]


def build_hello(lock_uuid: str) -> bytes:
    """Build the 16-byte ``00002250`` session-prime block the app sends first.

    Plaintext ``"1" + "0"*10 + "loock"`` encrypted AES-ECB under the uuid key,
    written before the challenge-response handshake. Confirmed constant: the app
    sends this same ``"1"`` block for BOTH lock and unlock — the action lives in
    the challenge magic, not here. Sending it alone does not actuate.
    """
    return AES.new(state_key(lock_uuid), AES.MODE_ECB).encrypt(b"1" + b"0" * 10 + b"loock")


# --- Challenge-response actuation (Nordic UART) -----------------------------
# Confirmed as the YD.LO1 lock/unlock path against real traffic. The earlier
# belief that the lock rejects this was a probe bug: the request must use seq 0
# and follow the build_hello() prime.

def build_challenge_request(seq: int = 0) -> bytes:
    """L1 frame asking the lock to issue a challenge nonce. seq 0 (see notes)."""
    return pack_l1(pack_l2(L2_CMD_REQUEST_CHALLENGE, {0x0A: b"\x27"}), seq=seq)


def extract_challenge(l2_body: bytes) -> bytes:
    """Pull the nonce out of a lock's 0x86 challenge frame body."""
    cmd, _flags, tlvs = parse_l2(l2_body)
    if cmd != L2_CMD_CHALLENGE or TAG_CHALLENGE not in tlvs:
        raise ValueError("not a challenge frame")
    return tlvs[TAG_CHALLENGE]


def _answer_challenge(ble_token: str, challenge: bytes, magic: bytes) -> bytes:
    encrypted = AES.new(ble_token[16:].encode(), AES.MODE_ECB).encrypt(challenge)
    return bytes(a ^ b for a, b in zip(encrypted, magic))


def build_lock_unlock(
    ble_id: int, ble_token: str, challenge: bytes, lock: bool, seq: int = 2
) -> bytes:
    """L1 frame that locks (``lock=True``) or unlocks in response to a challenge.

    ``ble_id`` and ``ble_token`` come from the cloud BLE-token endpoint;
    ``challenge`` is the nonce from the lock's 0x86 frame.
    """
    magic = _MAGIC_LOCK if lock else _MAGIC_UNLOCK
    answer = _answer_challenge(ble_token, challenge, magic)
    body = (
        pack_l2(L2_CMD_LOCK_UNLOCK, {0x05: ble_id.to_bytes(2, "big"), 0x04: answer})
        + bytes.fromhex("ad000100f4000101f7000101")
    )
    return pack_l1(body, seq=seq)


def build_ack(seq: int) -> bytes:
    """L1 acknowledgement frame (empty body) for a given sequence number."""
    return pack_l1(b"", seq=seq, flags=L1_FLAG_ACK)
