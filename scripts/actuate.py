#!/usr/bin/env python3
"""Stage 3: actuate the lock over BLE. THIS MOVES THE PHYSICAL DEADBOLT.

Reads the current state, writes one AES-ECB command block to the loock write
characteristic (00002250), then reads the state back to confirm the effect.
The command is built by the project codec from the lock's uuid; no cloud call.

    python scripts/actuate.py --address AA:BB:CC:DD:EE:FF \
        --uuid 0123456789abcdef0123456789abcdef --action unlock

--action is required (no default) so nothing actuates by accident. 'unlock' is
the confirmed command; 'lock' is still a hypothesis (see project notes).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from bleak import BleakClient, BleakScanner
    from bleak_retry_connector import establish_connection
except ImportError:
    sys.exit("bleak / bleak-retry-connector not importable; see scripts/requirements.txt")

from wyze_lock_classic_local import protocol as p


async def read_state(client, uuid):
    raw = await client.read_gatt_char(p.LOCK_STATE_UUID)
    st = p.decode_state(uuid, raw)
    return st, raw


async def run(address: str, uuid: str, lock: bool) -> None:
    device = await BleakScanner.find_device_by_address(address, timeout=15.0)
    if device is None:
        sys.exit(f"Device {address} not found; is it in range?")
    print(f"Connecting to {device.address} ({device.name!r})...")
    client = await establish_connection(BleakClient, device, device.name or address)
    try:
        before, raw_before = await read_state(client, uuid)
        print(f"BEFORE: {'LOCKED' if before.locked else 'UNLOCKED'} "
              f"(status=0x{before.status_byte:02x}, ts={before.timestamp})  raw={raw_before.hex()}")

        cmd = p.build_command(uuid, lock=lock)
        action = "LOCK" if lock else "UNLOCK"
        print(f"WRITING {action} command to {p.LOCK_CMD_UUID}: {cmd.hex()}")
        await client.write_gatt_char(p.LOCK_CMD_UUID, cmd, response=False)

        await asyncio.sleep(2.0)
        after, raw_after = await read_state(client, uuid)
        print(f"AFTER:  {'LOCKED' if after.locked else 'UNLOCKED'} "
              f"(status=0x{after.status_byte:02x}, ts={after.timestamp})  raw={raw_after.hex()}")

        if after.status_byte != before.status_byte:
            print(f"\nState changed: 0x{before.status_byte:02x} -> 0x{after.status_byte:02x}. "
                  "Command accepted and actuated.")
        elif after.timestamp != before.timestamp:
            print(f"\nStatus byte unchanged but timestamp advanced "
                  f"({before.timestamp} -> {after.timestamp}): command accepted, "
                  "lock was already in that state.")
        else:
            print("\nNo change detected. Command may have been rejected.")
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--address", required=True)
    ap.add_argument("--uuid", required=True, help="lock cloud uuid (32 hex chars)")
    ap.add_argument("--action", required=True, choices=["lock", "unlock"])
    args = ap.parse_args()
    asyncio.run(run(args.address, args.uuid, lock=args.action == "lock"))


if __name__ == "__main__":
    main()
