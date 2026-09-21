"""Wyze Lock Classic (Local BLE) — setup.

Each YD.LO1 lock is controlled entirely over BLE at runtime; the only cloud use
is fetching per-lock BLE credentials (a reusable token/id). Those are cached in
the config entry, so:

- With a cache present, we come up **immediately** on the cached keys and refresh
  from the cloud in the **background** (self-healing a rotated token without ever
  blocking startup on the cloud).
- With no cache (first setup), we must fetch synchronously; that's the only time
  a cloud outage can block setup.
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


def _store_cache(hass: HomeAssistant, entry: ConfigEntry, locks: list[LockCredentials]) -> None:
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, _CACHE_KEY: [asdict(lock) for lock in locks]}
    )


def _fetch(hass: HomeAssistant, entry: ConfigEntry):
    data = entry.data
    return hass.async_add_executor_job(
        functools.partial(
            fetch_locks_blocking,
            data[CONF_EMAIL],
            data[CONF_PASSWORD],
            data[CONF_KEY_ID],
            data[CONF_API_KEY],
        )
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    cached = _cached_locks(entry)

    if cached:
        # Fast path: come up on cached keys now, refresh in the background.
        locks = cached
        refresh_in_background = True
    else:
        # First setup: we have nothing cached, so the cloud fetch must succeed.
        try:
            locks = await _fetch(hass, entry)
        except Exception as err:  # noqa: BLE001
            msg = str(err).lower()
            if any(t in msg for t in ("login", "auth", "password", "2fa")):
                raise ConfigEntryAuthFailed(str(err)) from err
            raise ConfigEntryNotReady(f"Wyze cloud bootstrap failed: {err}") from err
        if not locks:
            raise ConfigEntryNotReady("No YD.LO1 locks found on this Wyze account.")
        _store_cache(hass, entry, locks)
        refresh_in_background = False

    coordinators: list[WyzeLockCoordinator] = []
    for creds in locks:
        coordinator = WyzeLockCoordinator(hass, creds)
        # Don't block setup (or fail it) if one lock is out of BLE range — do a
        # non-raising first poll; unreachable locks come online on a later poll.
        await coordinator.async_refresh()
        coordinators.append(coordinator)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinators
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    if refresh_in_background:
        entry.async_create_background_task(
            hass, _refresh_tokens(hass, entry, coordinators), f"{DOMAIN}_token_refresh"
        )
    return True


async def _refresh_tokens(
    hass: HomeAssistant, entry: ConfigEntry, coordinators: list[WyzeLockCoordinator]
) -> None:
    """Refresh cloud tokens after a cached-key startup; update anything that
    changed. Best-effort — a cloud failure just leaves the cache in place."""
    try:
        fresh = await _fetch(hass, entry)
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("Background token refresh failed; keeping cached keys: %s", err)
        return
    if not fresh:
        return

    _store_cache(hass, entry, fresh)
    by_uuid = {c.creds.uuid: c for c in coordinators}
    for creds in fresh:
        coord = by_uuid.get(creds.uuid)
        if coord is None:
            _LOGGER.info(
                "New Wyze lock '%s' on the account; reload the integration to add it",
                creds.nickname,
            )
            continue
        if (creds.ble_id, creds.ble_token) != (coord.creds.ble_id, coord.creds.ble_token):
            _LOGGER.info("Refreshed BLE token for '%s'", creds.nickname)
            coord.update_credentials(creds)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
