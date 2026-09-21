"""BLE transport for the Wyze Lock Classic (YD.LO1).

Wraps the pure codec in ``protocol.py`` with a ``bleak`` client. Written to be
Bluetooth-proxy compatible: it drives everything through
``bleak_retry_connector.establish_connection`` and standard GATT
reads/writes/notifications, with no adapter-local assumptions (no raw HCI, no
bonding, no MTU tricks). ``establish_connection(pair=False)`` — it never
pair-bonds, so it runs alongside the Wyze app.

Credentials: ``uuid`` comes from the lock's cloud record; ``ble_id`` and
``ble_token`` come once from the Wyze BLE-token endpoint and are then reusable
(the per-attempt challenge provides freshness). Fetching them is a cloud
concern handled elsewhere; this module is BLE-local only.

Usage (standalone, resolves the address itself)::

    lock = WyzeLockClassic(uuid, ble_id, ble_token)
    state = await lock.async_get_state(address="AA:BB:CC:DD:EE:FF")
    await lock.async_set(True, address="AA:BB:CC:DD:EE:FF")   # lock

In Home Assistant, pass a ``BLEDevice`` from the bluetooth integration instead
of an address so the proxy/adapter selection is HA's to make.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional, TypeVar

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection

from . import protocol as p

_LOGGER = logging.getLogger(__name__)

# How long to wait for the handshake result and the follow-up state change.
_RESULT_TIMEOUT = 10.0
_STATE_TIMEOUT = 6.0

# Transient BLE failures (notably ESP-proxy "error 133") are common; retry the
# whole connect+operation with a fresh connection and a little backoff.
_ATTEMPTS = 4
_BACKOFF = 0.6

_T = TypeVar("_T")


class WyzeLockError(Exception):
    """A BLE operation on the lock failed."""


class WyzeLockClassic:
    """Local BLE control for one YD.LO1 lock."""

    def __init__(self, uuid: str, ble_id: int, ble_token: str) -> None:
        self._uuid = uuid
        self._ble_id = ble_id
        self._ble_token = ble_token

    async def _resolve(self, device: Optional[BLEDevice], address: Optional[str]) -> BLEDevice:
        if device is not None:
            return device
        if address is None:
            raise WyzeLockError("pass either a BLEDevice or an address")
        found = await BleakScanner.find_device_by_address(address, timeout=15.0)
        if found is None:
            raise WyzeLockError(f"lock {address} not found (out of range or not advertising)")
        return found

    async def _connect(self, device: BLEDevice) -> BleakClient:
        return await establish_connection(BleakClient, device, device.name or str(device.address))

    async def _with_client(
        self,
        device: Optional[BLEDevice],
        address: Optional[str],
        work: Callable[[BleakClient], Awaitable[_T]],
    ) -> _T:
        """Resolve, connect, run ``work``, and disconnect — retrying transient
        BLE errors (e.g. ESP-proxy error 133) with a fresh connection each
        time. Always raises WyzeLockError on final failure."""
        last: Optional[Exception] = None
        for attempt in range(_ATTEMPTS):
            try:
                dev = await self._resolve(device, address)
                client = await self._connect(dev)
            except (BleakError, WyzeLockError, TimeoutError) as err:
                last = err
                await asyncio.sleep(_BACKOFF * (attempt + 1))
                continue
            try:
                return await work(client)
            except (BleakError, TimeoutError, WyzeLockError) as err:
                last = err
            finally:
                await self._safe_disconnect(client)
            await asyncio.sleep(_BACKOFF * (attempt + 1))
        raise WyzeLockError(f"BLE operation failed after {_ATTEMPTS} attempts: {last}") from last

    async def async_get_state(
        self,
        *,
        device: Optional[BLEDevice] = None,
        address: Optional[str] = None,
    ) -> p.LockState:
        """Connect, read the lock-state characteristic, and return decoded state."""
        async def _read(client: BleakClient) -> p.LockState:
            raw = await client.read_gatt_char(p.LOCK_STATE_UUID)
            return p.decode_state(self._uuid, raw)

        return await self._with_client(device, address, _read)

    async def async_set(
        self,
        lock: bool,
        *,
        device: Optional[BLEDevice] = None,
        address: Optional[str] = None,
    ) -> p.LockState:
        """Lock (``True``) or unlock (``False``) via the challenge-response, then
        return the confirmed new state."""
        return await self._with_client(device, address, lambda c: self._handshake(c, lock))

    async def async_lock(self, **kw) -> p.LockState:
        return await self.async_set(True, **kw)

    async def async_unlock(self, **kw) -> p.LockState:
        return await self.async_set(False, **kw)

    async def _handshake(self, client: BleakClient, lock: bool) -> p.LockState:
        loop = asyncio.get_running_loop()
        rx = bytearray()
        got_result = asyncio.Event()
        got_state = asyncio.Event()
        new_state: dict = {}
        answered = {"done": False}

        async def send(frame: bytes) -> None:
            await client.write_gatt_char(p.NUS_WRITE_UUID, frame, response=False)

        def on_nus(_sender, data: bytearray) -> None:
            rx.extend(data)
            try:
                frame = p.parse_l1(bytes(rx))
            except ValueError:
                rx.clear()
                return
            if not frame.complete:
                return
            rx.clear()
            if frame.flags == p.L1_FLAG_DATA and frame.body:
                cmd, _flags, tlvs = p.parse_l2(frame.body)
                if cmd == p.L2_CMD_CHALLENGE and p.TAG_CHALLENGE in tlvs and not answered["done"]:
                    answered["done"] = True
                    nonce = tlvs[p.TAG_CHALLENGE]
                    answer = p.build_lock_unlock(self._ble_id, self._ble_token, nonce, lock=lock, seq=1)
                    loop.create_task(send(p.build_ack(frame.seq)))
                    loop.create_task(send(answer))
                elif cmd == p.L2_CMD_LOCK_UNLOCK:
                    got_result.set()

        def on_state(_sender, data: bytearray) -> None:
            try:
                new_state["state"] = p.decode_state(self._uuid, bytes(data))
            except Exception:  # noqa: BLE001
                return
            got_state.set()

        await client.start_notify(p.LOCK_STATE_UUID, on_state)
        await client.start_notify(p.NUS_NOTIFY_UUID, on_nus)

        # Session prime, then request the challenge (seq 0 — required).
        await client.write_gatt_char(p.LOCK_CMD_UUID, p.build_hello(self._uuid), response=False)
        await asyncio.sleep(0.3)
        await send(p.build_challenge_request(seq=0))

        try:
            await asyncio.wait_for(got_result.wait(), timeout=_RESULT_TIMEOUT)
        except asyncio.TimeoutError as err:
            raise WyzeLockError("no result from lock (handshake did not complete)") from err

        # The bolt throws after the result; the new state arrives as a
        # notification a moment later.
        try:
            await asyncio.wait_for(got_state.wait(), timeout=_STATE_TIMEOUT)
        except asyncio.TimeoutError:
            pass

        if "state" in new_state:
            return new_state["state"]
        return await self._read_state_fallback(client)

    async def _read_state_fallback(self, client: BleakClient) -> p.LockState:
        raw = await client.read_gatt_char(p.LOCK_STATE_UUID)
        return p.decode_state(self._uuid, raw)

    @staticmethod
    async def _safe_disconnect(client: BleakClient) -> None:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001 - already gone
            pass
