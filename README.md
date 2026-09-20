# wyze-lock-classic-local

Local-only Home Assistant integration for the **original Wyze Lock (YD.LO1)** over
Bluetooth Low Energy. No cloud dependency for the HA-facing control path.

## Status

**Pre-alpha / protocol research.** Nothing here works yet. This repo currently
exists to hold notes as the BLE protocol gets reverse engineered. See
[`PROTOCOL.md`](PROTOCOL.md) for findings as they land.

## Why this exists

The YD.LO1 is the **original** Wyze Lock (2019/2020), distinct from the newer
**Wyze Lock Bolt (YD_BT1)**, which already has a working local BLE integration
at [`willdatrill2007/Wyze-Lock-Bolt-Local`](https://github.com/willdatrill2007/Wyze-Lock-Bolt-Local).
That repo's protocol notes are a useful reference point (AES-ECB payloads, a
`cool.knob` service UUID, challenge-response commands) but the YD.LO1 predates
the Bolt by several years and should not be assumed to share the same wire
format — verify everything independently.

The YD.LO1 also has a Zigbee radio and can join a ZHA/Z2M network directly,
bypassing Wyze entirely. That's not the goal here — the Wyze app/cloud path
stays intact (household preference) and this project targets the BLE side
purely as an additive local control option for HA, running underneath /
alongside the existing `ha-wyzeapi` cloud integration and Wyze's own BLE use.

## Non-goals

- Not replacing the Wyze app or its cloud control.
- Not touching the lock's Zigbee radio/pairing.
- Not aiming for feature parity with the Wyze app (auto-unlock, sharing, etc.)
  — HA-side lock/unlock/state/battery is the target surface.

## Requirements (once functional)

- Home Assistant with a working Bluetooth integration (local adapter or
  ESPHome Bluetooth proxy) — no proxy-specific work should be needed if this
  is built on `bleak` + `bleak-retry-connector` correctly.
- Per-device local key material, extraction method TBD (see below).

## Key extraction — open question

The Bolt integration gets its local keys by calling Wyze's cloud API **once**
via `wyzeapy` and pulling key fields out of the device-info response. Whether
the same trick works for YD.LO1 (i.e., whether Wyze's API returns a comparable
secret for this older model) is the first thing to confirm before doing any
APK work. See `tools/` for the probe script once that's written.

## Repo layout (planned)

```
src/wyze_lock_classic_local/
  protocol.py   pure codec: encode commands, decode notify payloads (no I/O)
  device.py     bleak + bleak-retry-connector transport (proxy-compatible)
  monitor.py    read-only CLI: scan, connect, dump GATT, print decoded state
tools/
  key_probe.py  one-shot Wyze API call to check for extractable key material
scripts/
  gatt_dump.py  throwaway service/characteristic enumeration (read-only)
tests/
custom_components/wyze_lock_classic_local/   # HA integration, built only after protocol works
PROTOCOL.md     # findings: UUIDs, encryption, command formats, as discovered
```

## Development order

1. Confirm or rule out cloud-sourced keys (`tools/key_probe.py`).
2. If no cloud shortcut: decompile current Wyze Android APK (jadx), locate the
   lock BLE handling code, extract service/characteristic UUIDs and crypto
   scheme into `PROTOCOL.md`.
3. Cross-check against live GATT traffic (nRF Connect) during app-driven
   lock/unlock.
4. Implement `protocol.py` as a pure codec, unit-testable without hardware.
5. Implement `device.py` transport, validate against the real lock with
   `monitor.py` before writing any HA-facing code.
6. Only then build `custom_components/wyze_lock_classic_local/`.

## Disclaimer

Not affiliated with or endorsed by Wyze Labs. Entirely reverse-engineered.
Use at your own risk — this locks and unlocks a physical door.