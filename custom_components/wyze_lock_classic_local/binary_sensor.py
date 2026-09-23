"""Door-position binary sensor backed by the BLE coordinator."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
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
    async_add_entities(WyzeLockDoorSensor(c) for c in coordinators)


class WyzeLockDoorSensor(CoordinatorEntity[WyzeLockCoordinator], BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Door"
    _attr_device_class = BinarySensorDeviceClass.DOOR

    def __init__(self, coordinator: WyzeLockCoordinator) -> None:
        super().__init__(coordinator)
        creds = coordinator.creds
        self._attr_unique_id = f"{creds.uuid}_door"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, creds.uuid)},
            connections={(CONNECTION_BLUETOOTH, creds.address)},
        )

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.door_open

    @property
    def available(self) -> bool:
        # Unknown (uncalibrated) door detection reports None — surface as
        # unavailable rather than a misleading "closed".
        return (
            super().available
            and self.coordinator.data is not None
            and self.coordinator.data.door_open is not None
        )
