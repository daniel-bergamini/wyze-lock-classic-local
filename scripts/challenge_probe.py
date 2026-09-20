#!/usr/bin/env python3
"""Stage 2a: request a challenge from the lock and capture the reply.

This is the FIRST thing in the project that writes to the lock, but it is
deliberately NON-ACTUATING: it sends only the challenge-request frame
(``cmd 0x91``) and reads back whatever the lock replies. It never builds or
sends a lock/unlock command -- there is no actuation code path in this file at
all, by design. Its purpose is to prove the handshake and the codec against
real hardware without moving the bolt.

    python scripts/challenge_probe.py --address AA:BB:CC:DD:EE:FF

Needs bleak (scripts/requirements.txt) and the pure codec in
src/wyze_lock_classic_local/protocol.py.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak_retry_connector import establish_connection
except ImportError:
    sys.exit("bleak / bleak-retry-connector not importable; see scripts/requirements.txt")

from wyze_lock_classic_local import protocol as p


async def probe(address: str, write_response: bool = False) -> Dict[str, Any]:
    device: Optional[BLEDevice] = await BleakScanner.find_device_by_address(address, timeout=15.0)
    if device is None:
        sys.exit(f"Device {address} not found; is it in range? (try gatt_dump.py --scan)")

    frames: List[Dict[str, Any]] = []
    raw: List[Dict[str, Any]] = []
    challenge: Dict[str, Any] = {}
    t0 = time.monotonic()
    pending: Dict[str, bytearray] = {}
    disconnected = asyncio.Event()

    def _on_disconnect(_c: Any) -> None:
        print("    ! lock dropped the connection")
        disconnected.set()

    print(f"Connecting to {device.address} ({device.name!r})...")
    client = await establish_connection(
        BleakClient, device, device.name or address, disconnected_callback=_on_disconnect
    )

    def _on_notify(sender: Any, data: bytearray) -> None:
        dt = round(time.monotonic() - t0, 3)
        uuid = getattr(sender, "uuid", str(sender))
        raw.append({"t": dt, "uuid": uuid, "hex": data.hex()})
        print(f"    notify +{dt}s [{uuid}]: {data.hex()}")
        buf = pending.setdefault(uuid, bytearray())
        buf.extend(data)
        try:
            frame = p.parse_l1(bytes(buf))
        except ValueError as err:
            print(f"      (not an L1 frame on this channel: {err})")
            buf.clear()
            return
        if not frame.complete:
            print("      (partial L1 frame, waiting for more)")
            return
        buf.clear()
        entry = {"t": dt, "flags": frame.flags, "seq": frame.seq, "body": frame.body.hex()}
        if frame.flags == p.L1_FLAG_LOCK_ACK:
            entry["kind"] = "lock-ack"
        elif frame.flags == p.L1_FLAG_DATA and frame.body:
            cmd, l2flags, tlvs = p.parse_l2(frame.body)
            entry["kind"] = f"data cmd=0x{cmd:02x}"
            entry["tlvs"] = {hex(k): v.hex() for k, v in tlvs.items()}
            if cmd == p.L2_CMD_CHALLENGE and p.TAG_CHALLENGE in tlvs:
                nonce = tlvs[p.TAG_CHALLENGE]
                challenge["hex"] = nonce.hex()
                challenge["len"] = len(nonce)
                print(f"      >>> CHALLENGE received: {nonce.hex()} ({len(nonce)} bytes)")
        frames.append(entry)
        print(f"      parsed: flags=0x{frame.flags:02x} seq={frame.seq} {entry.get('kind','?')}")

    try:
        # Subscribe to every notify characteristic, not just NUS: the YD.LO1
        # has an extra loock command service (00004000/…0003) the Bolt lacks,
        # and the challenge reply may arrive there instead.
        subscribed = []
        for service in client.services:
            for char in service.characteristics:
                if "notify" in char.properties:
                    try:
                        await client.start_notify(char.uuid, _on_notify)
                        subscribed.append(char.uuid)
                    except Exception as err:  # noqa: BLE001
                        print(f"    subscribe {char.uuid} failed: {err}")
        print(f"Subscribed to {len(subscribed)} notify characteristic(s).")
        req = p.build_challenge_request()
        print(f"Writing challenge request (NON-actuating, response={write_response}): {req.hex()}")
        await client.write_gatt_char(p.NUS_WRITE_UUID, req, response=write_response)
        try:
            await asyncio.wait_for(disconnected.wait(), timeout=15)
        except asyncio.TimeoutError:
            pass
        if not disconnected.is_set():
            try:
                await client.stop_notify(p.NUS_NOTIFY_UUID)
            except Exception:  # noqa: BLE001
                pass
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return {
        "address": device.address,
        "request_hex": p.build_challenge_request().hex(),
        "raw_notifications": raw,
        "frames": frames,
        "challenge": challenge,
        "disconnected_early": disconnected.is_set(),
    }


async def main_async(args: argparse.Namespace) -> None:
    result = await probe(args.address, write_response=args.write_response)
    print()
    if result["challenge"]:
        print(f"SUCCESS: challenge = {result['challenge']['hex']} "
              f"({result['challenge']['len']} bytes). Handshake works; no bolt moved.")
    else:
        print("No challenge captured. See raw notifications above.")
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
        print(f"Written to {args.out}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--address", required=True, help="BLE address of the lock")
    ap.add_argument("--out", help="write the captured result as JSON")
    ap.add_argument("--write-response", action="store_true", help="use acknowledged writes")
    main_async_args = ap.parse_args()
    asyncio.run(main_async(main_async_args))


if __name__ == "__main__":
    main()
