"""State coordinator: polls one lock over BLE via the vendored transport."""

from __future__ import annotations

import logging

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .cloud import LockCredentials
from .const import DOMAIN, UPDATE_INTERVAL
from .device import WyzeLockClassic, WyzeLockError
from .protocol import LockState

_LOGGER = logging.getLogger(__name__)


class WyzeLockCoordinator(DataUpdateCoordinator[LockState]):
    """Polls lock state and serves lock/unlock, all over the BT proxy."""

    def __init__(self, hass: HomeAssistant, creds: LockCredentials) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {creds.nickname}",
            update_interval=UPDATE_INTERVAL,
        )
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

    async def _async_update_data(self) -> LockState:
        try:
            return await self._lock.async_get_state(device=self._ble_device())
        except WyzeLockError as err:
            raise UpdateFailed(str(err)) from err

    async def async_set(self, lock: bool) -> None:
        """Lock/unlock, then push the confirmed new state to entities."""
        try:
            state = await self._lock.async_set(lock, device=self._ble_device())
        except WyzeLockError as err:
            raise UpdateFailed(str(err)) from err
        self.async_set_updated_data(state)
