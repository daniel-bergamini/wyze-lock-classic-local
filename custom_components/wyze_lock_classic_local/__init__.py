"""Wyze Lock Classic (Local BLE) — setup.

At setup we do one cloud round trip to fetch each YD.LO1 lock's reusable BLE
credentials, then everything is BLE-local: a per-lock coordinator polls state
and serves lock/unlock over the Bluetooth proxy.

The fetched BLE tokens are long-lived and reusable, so we cache the last-good
set per lock in the config entry. If a later startup can't reach the Wyze cloud,
we fall back to the cache and keep working fully offline; a successful fetch
refreshes it (healing a rotated token).
"""

from __future__ import annotations

import functools
import logging
from dataclasses import asdict, fields

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from .cloud import LockCredentials, fetch_locks_blocking
from .const import CONF_API_KEY, CONF_EMAIL, CONF_KEY_ID, CONF_PASSWORD, DOMAIN, PLATFORMS
from .coordinator import WyzeLockCoordinator

_LOGGER = logging.getLogger(__name__)

# Key under entry.data holding the cached per-lock BLE credentials.
_CACHE_KEY = "cached_locks"


def _cached_locks(entry: ConfigEntry) -> list[LockCredentials]:
    """Rebuild cached LockCredentials, tolerating schema drift across versions."""
    raw = entry.data.get(_CACHE_KEY) or []
    known = {f.name for f in fields(LockCredentials)}
    return [LockCredentials(**{k: v for k, v in item.items() if k in known}) for item in raw]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = entry.data
    try:
        # wyzeapy does blocking SSL/cert work; keep it off the event loop.
        locks = await hass.async_add_executor_job(
            functools.partial(
                fetch_locks_blocking,
                data[CONF_EMAIL],
                data[CONF_PASSWORD],
                data[CONF_KEY_ID],
                data[CONF_API_KEY],
            )
        )
    except Exception as err:  # noqa: BLE001
        # Cloud unreachable (or bad creds): fall back to the cached BLE tokens if
        # we have them, so control keeps working entirely offline.
        cached = _cached_locks(entry)
        if cached:
            _LOGGER.warning(
                "Wyze cloud fetch failed (%s); using cached BLE keys for %d lock(s)",
                err,
                len(cached),
            )
            locks = cached
        else:
            # Nothing cached to fall back on — surface the problem.
            msg = str(err).lower()
            if any(t in msg for t in ("login", "auth", "password", "2fa")):
                raise ConfigEntryAuthFailed(str(err)) from err
            raise ConfigEntryNotReady(f"Wyze cloud bootstrap failed: {err}") from err
    else:
        if not locks:
            raise ConfigEntryNotReady("No YD.LO1 locks found on this Wyze account.")
        # Refresh the cache with the freshly fetched tokens.
        hass.config_entries.async_update_entry(
            entry, data={**data, _CACHE_KEY: [asdict(lock) for lock in locks]}
        )

    coordinators: list[WyzeLockCoordinator] = []
    for creds in locks:
        coordinator = WyzeLockCoordinator(hass, creds)
        # Don't block setup (or fail it) if one lock is out of BLE range — do a
        # non-raising first poll; unreachable locks come online on a later poll.
        await coordinator.async_refresh()
        coordinators.append(coordinator)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinators
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
