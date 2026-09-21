"""Battery sensor backed by the BLE coordinator."""

from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory
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
    async_add_entities(WyzeLockBatterySensor(c) for c in coordinators)


class WyzeLockBatterySensor(CoordinatorEntity[WyzeLockCoordinator], SensorEntity):
    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: WyzeLockCoordinator) -> None:
        super().__init__(coordinator)
        creds = coordinator.creds
        self._attr_unique_id = f"{creds.uuid}_battery"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, creds.uuid)},
            connections={(CONNECTION_BLUETOOTH, creds.address)},
        )

    @property
    def native_value(self) -> int | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.battery

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.coordinator.data is not None
            and self.coordinator.data.battery is not None
        )
