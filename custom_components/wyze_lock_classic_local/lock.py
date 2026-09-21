"""Lock entity backed by the BLE coordinator."""

from __future__ import annotations

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import WyzeLockCoordinator


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinators: list[WyzeLockCoordinator] = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(WyzeLockEntity(c) for c in coordinators)


class WyzeLockEntity(CoordinatorEntity[WyzeLockCoordinator], LockEntity):
    _attr_has_entity_name = True
    _attr_name = None

    def __init__(self, coordinator: WyzeLockCoordinator) -> None:
        super().__init__(coordinator)
        creds = coordinator.creds
        self._attr_unique_id = creds.uuid
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, creds.uuid)},
            name=creds.nickname,
            manufacturer="Wyze / Yunding",
            model="YD.LO1",
            sw_version=creds.sw_version,
            hw_version=creds.hw_version,
            serial_number=creds.serial,
            connections={(CONNECTION_BLUETOOTH, creds.address)},
        )

    @property
    def is_locked(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.locked

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data is not None

    async def async_lock(self, **kwargs) -> None:
        await self.coordinator.async_set(True)

    async def async_unlock(self, **kwargs) -> None:
        await self.coordinator.async_set(False)
