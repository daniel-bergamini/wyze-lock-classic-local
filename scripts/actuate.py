#!/usr/bin/env python3
"""Actuate / read the lock via the WyzeLockClassic transport. MOVES THE BOLT.

A thin CLI over src/wyze_lock_classic_local/device.py so the library gets
exercised against real hardware. ble_id / ble_token are read from the cloud
probe dump by uuid (gitignored), or passed explicitly.

    python scripts/actuate.py --address AA:BB:CC:DD:EE:FF \
        --uuid 0123456789abcdef0123456789abcdef --action unlock
    python scripts/actuate.py --address ... --uuid ... --action state
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from wyze_lock_classic_local.device import WyzeLockClassic
except ImportError as err:
    sys.exit(f"cannot import transport ({err}); need bleak — see scripts/requirements.txt")


def load_token(uuid: str, dump_path: str):
    for dev in json.load(open(dump_path)).get("devices", []):
        for v in dev.get("sources", {}).get("lock/v1/ble/token", {}).values():
            if isinstance(v, dict) and v.get("token", {}).get("uuid") == uuid:
                return v["token"]["id"], v["_decrypted_token"]
    raise SystemExit(f"no ble token for uuid {uuid} in {dump_path}")


async def main_async(args):
    ble_id, ble_token = args.ble_id, args.ble_token
    if ble_id is None or ble_token is None:
        ble_id, ble_token = load_token(args.uuid, args.dump)

    lock = WyzeLockClassic(args.uuid, ble_id, ble_token)
    if args.action == "state":
        st = await lock.async_get_state(address=args.address)
    else:
        print(f"Actuating: {args.action} (this moves the bolt)...")
        st = await lock.async_set(args.action == "lock", address=args.address)
    print(f"State: {'LOCKED' if st.locked else 'UNLOCKED'} "
          f"(status=0x{st.status_byte:02x}, ts={st.timestamp})")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--address", required=True)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--action", required=True, choices=["lock", "unlock", "state"])
    ap.add_argument("--ble-id", type=int)
    ap.add_argument("--ble-token")
    ap.add_argument("--dump", default=os.path.join(
        os.path.dirname(__file__), "..", "tools", "wyze_probe_dump.json"))
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
