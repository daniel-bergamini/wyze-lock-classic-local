"""Constants for the Wyze Lock Classic (Local BLE) integration."""

from __future__ import annotations

from datetime import timedelta

from homeassistant.const import Platform

DOMAIN = "wyze_lock_classic_local"
PLATFORMS = [Platform.LOCK]

CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_KEY_ID = "key_id"
CONF_API_KEY = "api_key"

# State is polled; a lock/unlock also refreshes it immediately. The lock drops
# idle connections, so we do not hold one open between polls.
UPDATE_INTERVAL = timedelta(seconds=300)
