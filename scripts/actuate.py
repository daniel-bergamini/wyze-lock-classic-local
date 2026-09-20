#!/usr/bin/env python3
"""Stage 3: actuate the lock via the full challenge-response handshake.

THIS MOVES THE PHYSICAL DEADBOLT. Mirrors the Wyze app's sequence:

  1. write the 00002250 hello/prime block
  2. subscribe to the NUS notify char
  3. write the challenge request (seq 0)
  4. receive the lock's ACK + 0x86 challenge (nonce)
  5. send our ACK, then the lock/unlock frame answering the nonce
  6. read state back to confirm

ble_id / ble_token are read from the cloud probe dump by uuid (gitignored),
or pass them explicitly. --action is required (no default).

    python scripts/actuate.py --address AA:BB:CC:DD:EE:FF \
        --uuid 0123456789abcdef0123456789abcdef --action unlock
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from bleak import BleakClient, BleakScanner
    from bleak_retry_connector import establish_connection
except ImportError:
    sys.exit("bleak / bleak-retry-connector not importable; see scripts/requirements.txt")

from wyze_lock_classic_local import protocol as p


def load_token(uuid: str, dump_path: str):
    j = json.load(open(dump_path))
    for dev in j.get("devices", []):
        src = dev.get("sources", {}).get("lock/v1/ble/token", {})
        for k, v in src.items():
            if isinstance(v, dict) and v.get("token", {}).get("uuid") == uuid:
                return v["token"]["id"], v["_decrypted_token"]
    raise SystemExit(f"no ble token for uuid {uuid} in {dump_path}")


async def read_state(client, uuid):
    return p.decode_state(uuid, await client.read_gatt_char(p.LOCK_STATE_UUID))


async def run(address, uuid, ble_id, ble_token, lock, dump_path):
    if ble_id is None or ble_token is None:
        ble_id, ble_token = load_token(uuid, dump_path)

    device = await BleakScanner.find_device_by_address(address, timeout=15.0)
    if device is None:
        sys.exit(f"Device {address} not found; is it in range?")
    print(f"Connecting to {device.address} ({device.name!r})...")
    client = await establish_connection(BleakClient, device, device.name or address)

    rx = bytearray()
    done = asyncio.Event()
    result = {"stage": "init", "sent_answer": False}

    async def send(frame):
        await client.write_gatt_char(p.NUS_WRITE_UUID, frame, response=False)

    def on_notify(_s, data):
        rx.extend(data)
        try:
            frame = p.parse_l1(bytes(rx))
        except ValueError:
            rx.clear()
            return
        if not frame.complete:
            return
        rx.clear()
        if frame.flags == p.L1_FLAG_LOCK_ACK:
            print(f"    <- lock ACK (seq {frame.seq})")
            return
        if frame.flags == p.L1_FLAG_DATA and frame.body:
            cmd, _f, tlvs = p.parse_l2(frame.body)
            print(f"    <- data cmd=0x{cmd:02x} seq={frame.seq} "
                  + " ".join(f"{hex(k)}={v.hex()}" for k, v in tlvs.items()))
            if cmd == p.L2_CMD_CHALLENGE and p.TAG_CHALLENGE in tlvs and not result["sent_answer"]:
                nonce = tlvs[p.TAG_CHALLENGE]
                result["sent_answer"] = True
                answer = p.build_lock_unlock(ble_id, ble_token, nonce, lock=lock, seq=1)
                print(f"    -> ACK + {'LOCK' if lock else 'UNLOCK'} answer to nonce {nonce.hex()}")
                asyncio.create_task(send(p.build_ack(frame.seq)))
                asyncio.create_task(send(answer))
            elif cmd == p.L2_CMD_LOCK_UNLOCK:
                print("    <- lock/unlock RESULT received")
                done.set()

    try:
        before = await read_state(client, uuid)
        print(f"BEFORE: {'LOCKED' if before.locked else 'UNLOCKED'} (0x{before.status_byte:02x})")

        await client.start_notify(p.NUS_NOTIFY_UUID, on_notify)
        print(f"-> hello (00002250, action={'lock' if lock else 'unlock'})")
        await client.write_gatt_char(p.LOCK_CMD_UUID, p.build_hello(uuid, lock=lock), response=False)
        await asyncio.sleep(0.3)
        print("-> challenge request (seq 0)")
        await send(p.build_challenge_request(seq=0))

        try:
            await asyncio.wait_for(done.wait(), timeout=10)
        except asyncio.TimeoutError:
            print("    (no result frame within 10s)")

        await asyncio.sleep(1.5)
        after = await read_state(client, uuid)
        print(f"AFTER:  {'LOCKED' if after.locked else 'UNLOCKED'} (0x{after.status_byte:02x})")
        if after.status_byte != before.status_byte:
            print(f"\nActuated: 0x{before.status_byte:02x} -> 0x{after.status_byte:02x}.")
        else:
            print("\nNo state change (already in that state, or command not accepted).")
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--address", required=True)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--action", required=True, choices=["lock", "unlock"])
    ap.add_argument("--ble-id", type=int)
    ap.add_argument("--ble-token")
    ap.add_argument("--dump", default=os.path.join(
        os.path.dirname(__file__), "..", "tools", "wyze_probe_dump.json"))
    a = ap.parse_args()
    asyncio.run(run(a.address, a.uuid, a.ble_id, a.ble_token, a.action == "lock", a.dump))


if __name__ == "__main__":
    main()
