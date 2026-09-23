"""State coordinator: polls one lock over BLE via the vendored transport."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .cloud import LockCredentials
from .const import DOMAIN, UPDATE_INTERVAL
from .device import WyzeLockClassic, WyzeLockError

_LOGGER = logging.getLogger(__name__)


@dataclass
class LockData:
    """Everything the entities need from one poll."""

    locked: bool
    battery: int | None
    door_open: bool | None  # None = uncalibrated / unknown


class WyzeLockCoordinator(DataUpdateCoordinator[LockData]):
    """Polls lock state + battery and serves lock/unlock, all over the BT proxy."""

    def __init__(self, hass: HomeAssistant, creds: LockCredentials) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {creds.nickname}",
            update_interval=UPDATE_INTERVAL,
        )
        self.creds = creds
        self._lock = WyzeLockClassic(creds.uuid, creds.ble_id, creds.ble_token)

    def update_credentials(self, creds: LockCredentials) -> None:
        """Swap in refreshed cloud credentials (e.g. a rotated BLE token)."""
        self.creds = creds
        self._lock = WyzeLockClassic(creds.uuid, creds.ble_id, creds.ble_token)

    def _ble_device(self) -> bluetooth.BLEDevice:
        device = bluetooth.async_ble_device_from_address(
            self.hass, self.creds.address, connectable=True
        )
        if device is None:
            raise UpdateFailed(
                f"{self.creds.nickname} ({self.creds.address}) not reachable — "
                "no connectable Bluetooth adapter/proxy in range."
            )
        return device

    async def _async_update_data(self) -> LockData:
        try:
            state, battery, door_open = await self._lock.async_read_status(device=self._ble_device())
        except WyzeLockError as err:
            raise UpdateFailed(str(err)) from err
        return LockData(locked=state.locked, battery=battery, door_open=door_open)

    async def async_set(self, lock: bool) -> None:
        """Lock/unlock, then push the confirmed new state to entities."""
        try:
            state = await self._lock.async_set(lock, device=self._ble_device())
        except WyzeLockError as err:
            raise UpdateFailed(str(err)) from err
        prev = self.data
        self.async_set_updated_data(
            LockData(
                locked=state.locked,
                battery=prev.battery if prev else None,
                door_open=prev.door_open if prev else None,
            )
        )
