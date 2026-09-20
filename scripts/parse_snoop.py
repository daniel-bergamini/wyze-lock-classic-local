#!/usr/bin/env python3
"""Parse a btsnoop HCI log and print the ATT traffic to/from the lock.

Reassembles L2CAP over ACL, extracts ATT writes and notifications, maps the
GATT handles to characteristic UUIDs (from a gatt_dump.json), and decodes the
L1/L2 frames with the project codec. Read-only analysis of a capture file; it
touches no hardware.

    python scripts/parse_snoop.py captures/btsnooz_hci.log \
        --handles captures/gatt_dump.json
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from typing import Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from wyze_lock_classic_local import protocol as p  # noqa: E402

ATT_CID = 0x0004
ATT_WRITE_REQ = 0x12
ATT_WRITE_CMD = 0x52
ATT_NOTIFY = 0x1B
ATT_INDICATE = 0x1D


def load_handle_map(path: Optional[str]) -> Dict[int, str]:
    if not path or not os.path.exists(path):
        return {}
    j = json.load(open(path))
    out: Dict[int, str] = {}
    for svc in j.get("services", []):
        for c in svc.get("characteristics", []):
            if "handle" in c:
                out[c["handle"]] = c["uuid"]
    return out


def check_truncation(data: bytes) -> None:
    """Warn if this is a truncated (btsnooz/bugreport) capture.

    The snoop embedded in an ``adb bugreport`` caps ``incl_len`` well below
    ``orig_len`` — it keeps packet headers and discards payloads. That is fatal
    for reading protocol frames: the actual ATT values (and any crypto) are
    gone. A usable capture is the full ``btsnoop_hci.log`` written by the
    "Bluetooth HCI snoop log" developer option, pulled with ``adb pull``, not
    extracted from a bugreport.
    """
    if data[:8] != b"btsnoop\x00":
        return
    pos, acl_seen, acl_trunc, max_incl = 16, 0, 0, 0
    while pos + 24 <= len(data):
        orig_len, incl_len = struct.unpack_from(">II", data, pos)
        pkt = data[pos + 24 : pos + 24 + incl_len]
        pos += 24 + incl_len
        if pkt[:1] == b"\x02":
            acl_seen += 1
            max_incl = max(max_incl, incl_len)
            if incl_len < orig_len:
                acl_trunc += 1
    if acl_seen and acl_trunc / acl_seen > 0.3:
        print(
            f"WARNING: {acl_trunc}/{acl_seen} ACL packets are TRUNCATED "
            f"(max {max_incl} bytes captured). This looks like a bugreport "
            "'btsnooz' log, which discards packet payloads. Frame contents "
            "cannot be recovered. Capture the FULL btsnoop_hci.log instead "
            "(developer option + adb pull, not adb bugreport).\n",
            file=sys.stderr,
        )


def iter_btsnoop(data: bytes):
    """Yield (direction, h4_payload) per record. direction: 'tx' or 'rx'."""
    if data[:8] != b"btsnoop\x00":
        raise ValueError("not a btsnoop file")
    pos = 16  # 8 magic + 4 version + 4 datalink
    while pos + 24 <= len(data):
        orig_len, incl_len, flags, _drops = struct.unpack_from(">IIII", data, pos)
        pos += 16
        pos += 8  # timestamp
        pkt = data[pos : pos + incl_len]
        pos += incl_len
        # btsnoop flags bit0: 1 = received (controller->host), 0 = sent
        direction = "rx" if (flags & 0x1) else "tx"
        yield direction, pkt


def att_messages(data: bytes):
    """Yield (direction, opcode, att_handle, value) for ATT writes/notifies.

    L2CAP is reassembled per (connection, direction): notifications (rx) and
    writes (tx) share a connection handle and would corrupt a single buffer.
    """
    pending: Dict = {}
    for direction, pkt in iter_btsnoop(data):
        if not pkt or pkt[0] != 0x02 or len(pkt) < 5:  # H4 ACL only
            continue
        handle_flags, acl_len = struct.unpack_from("<HH", pkt, 1)
        conn = handle_flags & 0x0FFF
        pb = (handle_flags >> 12) & 0x3
        acl_payload = pkt[5 : 5 + acl_len]
        key = (conn, direction)

        if pb == 0x1 and key in pending:  # continuation of an existing PDU
            pending[key]["buf"].extend(acl_payload)
        else:  # start of a new L2CAP PDU
            if len(acl_payload) < 4:
                continue
            l2_len, cid = struct.unpack_from("<HH", acl_payload, 0)
            pending[key] = {"cid": cid, "need": l2_len, "buf": bytearray(acl_payload[4:])}

        st = pending.get(key)
        if not st or len(st["buf"]) < st["need"]:
            continue
        frame = bytes(st["buf"][: st["need"]])
        cid_now = st["cid"]
        del pending[key]

        if cid_now != ATT_CID or len(frame) < 3:
            continue
        opcode = frame[0]
        if opcode in (ATT_WRITE_REQ, ATT_WRITE_CMD, ATT_NOTIFY, ATT_INDICATE):
            att_handle = struct.unpack_from("<H", frame, 1)[0]
            yield direction, opcode, att_handle, frame[3:]


OPCODE_NAME = {
    ATT_WRITE_REQ: "write-req",
    ATT_WRITE_CMD: "write-cmd",
    ATT_NOTIFY: "notify",
    ATT_INDICATE: "indicate",
}


def describe_frame(value: bytes) -> str:
    """Best-effort L1/L2 decode of a value payload."""
    try:
        frame = p.parse_l1(value)
    except ValueError:
        return ""
    bits = [f"L1 flags=0x{frame.flags:02x} seq={frame.seq}"]
    if not frame.complete:
        return bits[0] + " (partial)"
    if frame.body:
        try:
            cmd, l2flags, tlvs = p.parse_l2(frame.body)
            tlv_desc = " ".join(f"{hex(k)}={v.hex()}" for k, v in tlvs.items())
            bits.append(f"L2 cmd=0x{cmd:02x} [{tlv_desc}]")
        except Exception:  # noqa: BLE001
            bits.append(f"body={frame.body.hex()}")
    return "  ".join(bits)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("snoop", help="path to the btsnoop file")
    ap.add_argument("--handles", help="gatt_dump.json for handle->uuid mapping")
    ap.add_argument("--only-handles", help="comma-separated att handles (hex) to keep")
    args = ap.parse_args()

    handle_map = load_handle_map(args.handles)
    keep = None
    if args.only_handles:
        keep = {int(h, 16) for h in args.only_handles.split(",")}

    data = open(args.snoop, "rb").read()
    check_truncation(data)
    n = 0
    for direction, opcode, handle, value in att_messages(data):
        # ATT value handle is char handle + 1 for the CCCD; the characteristic
        # value handle equals the declared handle in most stacks. Map both.
        uuid = handle_map.get(handle) or handle_map.get(handle - 1) or "?"
        short = uuid.split("-")[0] if uuid != "?" else f"h0x{handle:04x}"
        if keep and handle not in keep:
            continue
        arrow = "-->" if direction == "tx" else "<--"
        decoded = describe_frame(value)
        n += 1
        print(f"{arrow} [{OPCODE_NAME.get(opcode, hex(opcode))}] {short} h=0x{handle:04x} "
              f"len={len(value)}")
        print(f"      {value.hex()}")
        if decoded:
            print(f"      {decoded}")
    print(f"\n{n} ATT write/notify messages")


if __name__ == "__main__":
    main()
