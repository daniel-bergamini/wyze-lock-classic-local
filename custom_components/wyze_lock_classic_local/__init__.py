"""Wyze Lock Classic (Local BLE) — setup.

At setup we do one cloud round trip to fetch each YD.LO1 lock's reusable BLE
credentials, then everything is BLE-local: a per-lock coordinator polls state
and serves lock/unlock over the Bluetooth proxy. Re-fetching each startup means
a rotated cloud token heals on restart.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from .cloud import authenticate, fetch_locks
from .const import CONF_API_KEY, CONF_EMAIL, CONF_KEY_ID, CONF_PASSWORD, DOMAIN, PLATFORMS
from .coordinator import WyzeLockCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = entry.data
    try:
        client = await authenticate(
            data[CONF_EMAIL], data[CONF_PASSWORD], data[CONF_KEY_ID], data[CONF_API_KEY]
        )
        locks = await fetch_locks(client)
    except Exception as err:  # noqa: BLE001
        # Credentials issues should trigger reauth; transient cloud failures
        # should retry. We cannot always tell them apart from wyzeapy, so treat
        # login-shaped errors as auth failures.
        msg = str(err).lower()
        if "login" in msg or "auth" in msg or "password" in msg or "2fa" in msg:
            raise ConfigEntryAuthFailed(str(err)) from err
        raise ConfigEntryNotReady(f"Wyze cloud bootstrap failed: {err}") from err

    if not locks:
        raise ConfigEntryNotReady("No YD.LO1 locks found on this Wyze account.")

    coordinators: list[WyzeLockCoordinator] = []
    for creds in locks:
        coordinator = WyzeLockCoordinator(hass, creds)
        await coordinator.async_config_entry_first_refresh()
        coordinators.append(coordinator)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinators
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
