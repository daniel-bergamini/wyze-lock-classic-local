#!/usr/bin/env python3
"""Read-only BLE GATT recon for a Wyze Lock (YD.LO1).

Connects to one lock by BLE address, enumerates every service and
characteristic it exposes, and reads whatever characteristics allow reads.
It never writes to a characteristic and never subscribes to notifications
unless --notify is passed explicitly -- per this repo's convention, nothing
touches the lock beyond a plain read until the protocol is confirmed. This is
throwaway recon tooling, not the codec: findings go into PROTOCOL.md once
confirmed, and the real codec lives in src/wyze_lock_classic_local/ once one
exists.

Known UUIDs worth comparing the dump against, from the Wyze Lock Bolt
(YD_BT1) codec in ha-wyzeapi's ydble_utils.py / const.py. The YD.LO1 predates
the Bolt by years, so treat these as things to check for, not things to
assume are present:

    Nordic UART Service (stock nRF5x profile, not Wyze-specific):
        6e400001-b5a3-f393-e0a9-e50e24dcca9e  service
        6e400002-b5a3-f393-e0a9-e50e24dcca9e  RX (write)
        6e400003-b5a3-f393-e0a9-e50e24dcca9e  TX (notify)
    Bolt lock-state characteristic:
        00002220-0000-6b63-6f6c-2e6b636f6f6c  (tail bytes spell "loock.lock")

Usage:

    python scripts/gatt_dump.py --scan
    python scripts/gatt_dump.py --scan --name-filter wyze
    python scripts/gatt_dump.py --address AA:BB:CC:DD:EE:FF
    python scripts/gatt_dump.py --address AA:BB:CC:DD:EE:FF --out dump.json

Needs bleak + bleak-retry-connector (scripts/requirements.txt) and a real
Bluetooth adapter -- this uses bleak's default local-adapter backend, not an
ESPHome proxy. The eventual HA integration is what has to be proxy-compatible;
this is a one-off recon script run by hand near the lock.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any, Dict, List, Optional

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak_retry_connector import establish_connection
except ImportError:
    sys.exit(
        "bleak / bleak-retry-connector are not importable. Install them with:\n"
        "  pip install -r scripts/requirements.txt\n"
        "(a venv is recommended; these are BLE-local recon deps only -- they\n"
        "must never become a dependency of tools/key_probe.py)."
    )

# Bolt (YD_BT1) UUIDs, for cross-reference only -- see module docstring.
KNOWN_UUIDS = {
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART Service",
    "6e400002-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART RX (write) -- Bolt",
    "6e400003-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART TX (notify) -- Bolt",
    "00002220-0000-6b63-6f6c-2e6b636f6f6c": "Bolt lock-state characteristic",
}


async def scan(timeout: float, name_filter: Optional[str]) -> None:
    print(f"Scanning for {timeout:.0f}s...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    if not devices:
        print("No BLE advertisements seen. Check adapter permissions and that "
              "the lock is powered/awake.")
        return

    for address, (device, adv) in sorted(devices.items()):
        name = device.name or adv.local_name or ""
        if name_filter and name_filter.lower() not in name.lower():
            continue
        uuids = ", ".join(adv.service_uuids) or "(none advertised)"
        print(f"  {address}  rssi={adv.rssi:>4}  name={name!r}")
        print(f"    service uuids: {uuids}")


async def dump_device(address: str, do_read: bool, do_notify: bool) -> Dict[str, Any]:
    device: Optional[BLEDevice] = await BleakScanner.find_device_by_address(
        address, timeout=15.0
    )
    if device is None:
        sys.exit(
            f"Could not find a BLE device at {address}. Make sure it's in "
            "range and advertising (try --scan first)."
        )

    result: Dict[str, Any] = {
        "address": device.address,
        "name": device.name,
        "services": [],
        "notifications": [],
    }

    disconnected = asyncio.Event()
    t0 = time.monotonic()

    def _on_disconnect(_c: Any) -> None:
        print("    ! lock dropped the connection")
        disconnected.set()

    print(f"Connecting to {device.address} ({device.name!r})...")
    client: BleakClient = await establish_connection(
        BleakClient, device, device.name or address, disconnected_callback=_on_disconnect
    )

    try:
        notify_started: List[str] = []
        for service in client.services:
            svc_entry: Dict[str, Any] = {
                "uuid": service.uuid,
                "known_as": KNOWN_UUIDS.get(service.uuid.lower()),
                "characteristics": [],
            }
            for char in service.characteristics:
                char_entry: Dict[str, Any] = {
                    "uuid": char.uuid,
                    "known_as": KNOWN_UUIDS.get(char.uuid.lower()),
                    "handle": char.handle,
                    "properties": list(char.properties),
                    "descriptors": [d.uuid for d in char.descriptors],
                }

                if do_read and "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        char_entry["value_hex"] = value.hex()
                        char_entry["value_len"] = len(value)
                    except Exception as err:  # noqa: BLE001 - recon: record, keep going
                        char_entry["read_error"] = f"{type(err).__name__}: {err}"

                if do_notify and "notify" in char.properties:
                    # bleak >=3.0 passes the characteristic object as arg 1, older
                    # versions passed an int handle; we bind the uuid instead of
                    # reading it off arg 1, so either works.
                    def _on_notify(_sender: Any, data: bytearray, _uuid=char.uuid) -> None:
                        hexval = data.hex()
                        print(f"    notify {_uuid}: {hexval}")
                        result["notifications"].append(
                            {"uuid": _uuid, "t": round(time.monotonic() - t0, 3), "hex": hexval}
                        )

                    try:
                        await client.start_notify(char.uuid, _on_notify)
                        notify_started.append(char.uuid)
                        char_entry["notify_started"] = True
                    except Exception as err:  # noqa: BLE001
                        char_entry["notify_error"] = f"{type(err).__name__}: {err}"

                svc_entry["characteristics"].append(char_entry)
            result["services"].append(svc_entry)

        if notify_started:
            listen_s = 30
            print(f"Listening for notifications on {len(notify_started)} "
                  f"characteristic(s) for up to {listen_s}s (Ctrl+C to stop early)...")
            try:
                await asyncio.wait_for(disconnected.wait(), timeout=listen_s)
            except asyncio.TimeoutError:
                pass
            for uuid in notify_started:
                if disconnected.is_set():
                    break
                try:
                    await client.stop_notify(uuid)
                except Exception as err:  # noqa: BLE001 - cleanup best-effort
                    print(f"    stop_notify {uuid} failed: {type(err).__name__}: {err}")

        result["disconnected_early"] = disconnected.is_set()
        return result
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001 - already gone
            pass


def report(dump: Dict[str, Any]) -> None:
    print(f"\n=== {dump['name']!r} ({dump['address']}) ===")
    for service in dump["services"]:
        known = f"  [{service['known_as']}]" if service["known_as"] else ""
        print(f"\nService {service['uuid']}{known}")
        for char in service["characteristics"]:
            known = f"  [{char['known_as']}]" if char["known_as"] else ""
            props = ",".join(char["properties"])
            print(f"  Characteristic {char['uuid']}  ({props}){known}")
            if "value_hex" in char:
                raw = bytes.fromhex(char["value_hex"])
                ascii_hint = ""
                if raw and all(32 <= b < 127 for b in raw):
                    ascii_hint = f"  ascii={raw.decode('ascii')!r}"
                print(f"    value ({char['value_len']} bytes): {char['value_hex']}{ascii_hint}")
            if "read_error" in char:
                print(f"    read failed: {char['read_error']}")
            if char.get("notify_started"):
                print("    notifications enabled (see log above for any pushed values)")
            if "notify_error" in char:
                print(f"    notify failed: {char['notify_error']}")

    hits = [
        s["known_as"] for s in dump["services"] if s["known_as"]
    ] + [
        c["known_as"]
        for s in dump["services"]
        for c in s["characteristics"]
        if c["known_as"]
    ]
    print()
    if hits:
        print(f"Matches known Bolt (YD_BT1) UUIDs: {', '.join(hits)}")
    else:
        print("No overlap with known Bolt (YD_BT1) UUIDs -- YD.LO1 likely uses "
              "a different transport. Record the full UUID list in PROTOCOL.md.")


async def main_async(args: argparse.Namespace) -> None:
    if args.scan:
        await scan(args.timeout, args.name_filter)
        return

    if not args.address:
        sys.exit("Pass --address AA:BB:CC:DD:EE:FF (or --scan to find it first).")

    dump = await dump_device(args.address, do_read=not args.no_read, do_notify=args.notify)
    report(dump)

    if args.out:
        with open(args.out, "w") as handle:
            json.dump(dump, handle, indent=2, sort_keys=True)
        print(f"\nFull dump written to {args.out}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--scan", action="store_true", help="list nearby BLE devices and exit")
    parser.add_argument("--name-filter", help="case-insensitive substring filter for --scan")
    parser.add_argument("--timeout", type=float, default=10.0, help="scan duration in seconds")
    parser.add_argument("--address", help="BLE address of the lock to dump")
    parser.add_argument("--no-read", action="store_true", help="skip reading readable characteristics")
    parser.add_argument(
        "--notify",
        action="store_true",
        help="also enable notifications on notify-capable characteristics for 10s "
        "(this is a GATT write to enable delivery, unlike everything else this "
        "script does -- off by default to stay strictly read-only)",
    )
    parser.add_argument("--out", help="write the full dump as JSON to this path")
    args = parser.parse_args()

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
