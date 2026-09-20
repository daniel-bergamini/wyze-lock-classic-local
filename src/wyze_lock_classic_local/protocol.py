"""Pure codec for the Wyze Lock Classic (YD.LO1) BLE protocol.

No I/O — every function here is pure bytes-in/bytes-out so it can be unit
tested without hardware. Transport (bleak) lives elsewhere.

The lock speaks a Yunding/"loock" house protocol over two layers:

- **L1** framing:  ``0xAB | flags | len(2 BE) | crc(2 BE) | seq(2 BE) | body``
  where ``crc`` is CRC-16/ARC over the body and ``len`` is the body length.
- **L2** command:  ``cmd | flags | [tag | len(2 BE) | value]…`` — a one-byte
  command, a flags byte, then TLV entries.

Both the read and the actuate paths are plain AES-ECB keyed by the last 16
ASCII chars of the lock's cloud uuid — no cloud token, no challenge-response:

- **State/notify** characteristics decrypt to ``status | ts | pad | "loock"``.
- **Lock/unlock** is a single 16-byte block written to ``00002250``, the
  plaintext being an action digit + ``"0"`` padding + ``"loock"`` (e.g.
  ``b"10000000000loock"`` to unlock). Observed static on the wire (no nonce or
  counter), so it is effectively a fixed per-lock command.

This was derived from live YD.LO1 traffic (an HCI capture of the Wyze app
actuating the lock) and validated against it. The L1/L2 framing helpers below
are the shared Yunding framing (confirmed against the cloud BLE-token ``buf``);
the YD.LO1 *actuation* path does not use them — that is the Bolt's approach,
which this lock rejects (see project notes). They are kept for parsing the
cloud ``buf`` and any future enrollment work.
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

# Per-command magic constants XORed into the encrypted nonce. Tail is the ASCII
# "loock" (Yunding's lock brand); the leading byte selects the action.
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


# Action digit at byte 0 of the command plaintext. Confirmed: '1' unlocks (seen
# on the wire, left the lock unlocked). '2' = lock is the matching value by
# analogy to the Bolt's raw 0x01/0x02 magics, not yet confirmed on hardware.
COMMAND_UNLOCK = b"1"
COMMAND_LOCK = b"2"


def build_command(lock_uuid: str, lock: bool) -> bytes:
    """Build the 16-byte block to write to ``LOCK_CMD_UUID`` to (un)lock.

    Plaintext is ``<action> + "0"*10 + "loock"`` encrypted AES-ECB under the
    same uuid-derived key as the state path. Warning: this ACTUATES the deadbolt.
    """
    action = COMMAND_LOCK if lock else COMMAND_UNLOCK
    plaintext = action + b"0" * 10 + b"loock"
    return AES.new(state_key(lock_uuid), AES.MODE_ECB).encrypt(plaintext)


# --- Bolt (YD_BT1) challenge-response — NOT used by the YD.LO1 --------------
# The YD.LO1 rejects this handshake (it drops the connection on the challenge
# request); its actuation path is build_command() above. These are retained for
# reference and for the shared framing only.

def build_challenge_request(seq: int = 1) -> bytes:
    """L1 frame that asks the lock to issue a challenge nonce. Non-actuating."""
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
