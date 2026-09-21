# wyze-lock-classic-local

Local-only Home Assistant integration for the **original Wyze Lock (YD.LO1)** over
Bluetooth Low Energy. No cloud dependency for the HA-facing control path.

## Status

**Working in Home Assistant.** The BLE protocol is fully reverse-engineered and
hardware-validated, and the integration runs live on HAOS over an ESPHome
Bluetooth proxy: lock/unlock, lock-state, and battery level, with a one-time
cloud fetch for per-lock key material (reusable — no cloud round trip at control
time). The confirmed wire format is in [`PROTOCOL.md`](PROTOCOL.md); the pure
codec + transport are in
[`src/wyze_lock_classic_local/`](src/wyze_lock_classic_local/), and the Home
Assistant integration in [`custom_components/`](custom_components/).

## Installation (HACS)

Not in the default HACS store — add it as a HACS **custom repository**:

1. HACS → the **⋮** menu (top right) → **Custom repositories**.
2. Add `https://github.com/daniel-bergamini/wyze-lock-classic-local`, category
   **Integration**.
3. Find "Wyze Lock Classic (Local BLE)" in HACS and install it.
4. Restart Home Assistant.
5. Settings → Devices & Services → **Add Integration** → "Wyze Lock Classic".
   Enter your Wyze email/password and a developer API key from
   <https://developer-api-console.wyze.com/> (used once to fetch each lock's BLE
   key; control is Bluetooth-local afterward).

Requires the built-in Bluetooth integration with an adapter or ESPHome
Bluetooth Proxy in range of each lock.

## Why this exists

The YD.LO1 is the **original** Wyze Lock (2019/2020), distinct from the newer
**Wyze Lock Bolt (YD_BT1)**, which already has a working local BLE integration
at [`willdatrill2007/Wyze-Lock-Bolt-Local`](https://github.com/willdatrill2007/Wyze-Lock-Bolt-Local).
That repo's protocol notes are a useful reference point (AES-ECB payloads, a
Nordic UART transport, challenge-response commands) but the YD.LO1 predates
the Bolt by several years and should not be assumed to share the same wire
format — verify everything independently.

Both locks are built by **Yunding (YD)**, whose own smart-lock brand is
**Loock** — the Bolt's state characteristic UUID
`00002220-0000-6b63-6f6c-2e6b636f6f6c` has tail bytes that spell `loock.lock`
byte-reversed. So the BLE stack is likely a Yunding/Loock house protocol
rather than anything Wyze designed, which makes published Loock RE work a
relevant search avenue.

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
- Per-device local key material, fetched once from the Wyze cloud (see below).

## Key extraction — solved (cloud)

The Bolt integration gets its local keys by calling Wyze's cloud API **once**
via `wyzeapy` and pulling key fields out of the response. The same trick
works for the YD.LO1: `tools/key_probe.py` confirmed that Wyze's lock backend
(`yd-saas-toc.wyzecam.com/openapi/lock/v1/ble/token`) returns per-device BLE
key material for this model too. `wyzeapy` only calls that endpoint for the
Bolt, but that check is client-side — the server answers for a YD.LO1 uuid
just fine.

That means no APK decompilation is needed for key material, and it also means
local BLE control still needs **one** authenticated cloud call to bootstrap —
the same shape as Home Assistant's `august` integration, which fetches an
offline key from the cloud and hands it to the `yalexs-ble` library.

## Repo layout (planned)

```
src/wyze_lock_classic_local/
  protocol.py   pure codec: encode commands, decode notify payloads (no I/O) [exists]
  device.py     bleak + bleak-retry-connector transport (proxy-compatible) [exists]
  monitor.py    read-only CLI: scan, connect, dump GATT, print decoded state
tools/
  key_probe.py  one-shot Wyze API call to check for extractable key material
scripts/
  gatt_dump.py  throwaway service/characteristic enumeration (read-only) [exists]
tests/
custom_components/wyze_lock_classic_local/   # HA integration, built only after protocol works
PROTOCOL.md     # findings: UUIDs, encryption, command formats, as discovered
```

## Development order

1. ~~Confirm or rule out cloud-sourced keys (`tools/key_probe.py`).~~
   **Done — the cloud hands out BLE key material for YD.LO1.**
2. **← current step.** Dump the lock's GATT table read-only
   (`scripts/gatt_dump.py`) and see whether the transport matches the Bolt's
   (Nordic UART + a `loock.lock` state characteristic) or is something else.
3. Only if the GATT dump is inconclusive: decompile the Wyze Android APK
   (jadx) for the lock BLE handling code, and/or cross-check against live
   traffic (nRF Connect) during app-driven lock/unlock. No longer needed for
   *key material*, only for the wire format.
4. ~~Implement `protocol.py` as a pure codec, unit-testable without hardware.~~
   **Done — codec written and validated against real captured frames + state;
   see [`PROTOCOL.md`](PROTOCOL.md). Lock/unlock confirmed live both directions.**
5. ~~Implement `device.py` transport, validate against the real lock.~~
   **Done — WyzeLockClassic drives state read + lock/unlock over BLE, validated
   live both directions.**
6. ~~Build `custom_components/wyze_lock_classic_local/`.~~ **Done (v0.1.0) —
   config-flow HA integration for HAOS + Bluetooth proxy: fetches reusable BLE
   tokens once from the Wyze cloud, then polls state and serves lock/unlock
   over the proxy. Needs live testing in HA.**

## Disclaimer

Not affiliated with or endorsed by Wyze Labs. Entirely reverse-engineered.
Use at your own risk — this locks and unlocks a physical door.