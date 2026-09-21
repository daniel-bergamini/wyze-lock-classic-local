"""One-time Wyze cloud bootstrap: fetch each YD.LO1 lock's BLE credentials.

This is the only part of the integration that touches the network, and it runs
only at setup (and on token refresh) — never during BLE control. It mirrors
tools/key_probe.py: authenticate with wyzeapy, then hand-roll the Ford
``/openapi/lock/v1/ble/token`` call because wyzeapy gates that endpoint behind a
client-side ``product_model == "YD_BT1"`` check that the *server* does not
enforce.

Returns, per lock: the cloud ``uuid`` (state/command key material derives from
it), the real BLE connect address (the cloud stores the MAC byte-reversed),
and the reusable ``ble_id`` / ``ble_token`` for the challenge-response.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import List, Optional

from wyzeapy import Wyzeapy
from wyzeapy.const import FORD_APP_SECRET
from wyzeapy.payload_factory import ford_create_payload
from wyzeapy.utils import wyze_decrypt_cbc

MODEL = "YD.LO1"
_BLE_TOKEN_PATH = "/openapi/lock/v1/ble/token"
_BLE_TOKEN_URL = f"https://yd-saas-toc.wyzecam.com{_BLE_TOKEN_PATH}"


@dataclass
class LockCredentials:
    uuid: str
    address: str  # BLE connect address (MAC, byte-reversed from the cloud value)
    ble_id: int
    ble_token: str
    nickname: str
    sw_version: Optional[str] = None
    hw_version: Optional[str] = None
    serial: Optional[str] = None


def _mac_to_address(cloud_mac: str) -> str:
    """The cloud stores the BLE MAC byte-reversed and without colons."""
    b = [cloud_mac[i : i + 2] for i in range(0, len(cloud_mac), 2)]
    return ":".join(reversed(b)).upper()


async def _authenticate(
    email: str, password: str, key_id: str, api_key: str, twofa_code: Optional[str] = None
) -> Wyzeapy:
    """Log in. Raises TwoFactorAuthenticationEnabled if a 2FA code is needed."""
    client = await Wyzeapy.create()
    if twofa_code:
        # login() must have been attempted first to arm the 2FA flow.
        await client.login(email, password, key_id, api_key)
        await client.login_with_2fa(twofa_code)
    else:
        await client.login(email, password, key_id, api_key)
    return client


def login_blocking(
    email: str, password: str, key_id: str, api_key: str, twofa_code: Optional[str] = None
) -> None:
    """Verify credentials. Blocking — run via hass.async_add_executor_job.

    wyzeapy builds its SSL context and loads cert files synchronously, so this
    must run off the HA event loop. Raises on bad credentials, and
    TwoFactorAuthenticationEnabled if a 2FA code is needed.
    """
    asyncio.run(_authenticate(email, password, key_id, api_key, twofa_code))


def fetch_locks_blocking(
    email: str, password: str, key_id: str, api_key: str
) -> List[LockCredentials]:
    """Authenticate and return every YD.LO1 lock's BLE credentials. Blocking —
    run via hass.async_add_executor_job (see login_blocking)."""
    return asyncio.run(_authenticate_and_fetch(email, password, key_id, api_key))


async def _authenticate_and_fetch(
    email: str, password: str, key_id: str, api_key: str
) -> List[LockCredentials]:
    client = await _authenticate(email, password, key_id, api_key)
    return await _fetch_locks(client)


async def _fetch_locks(client: Wyzeapy) -> List[LockCredentials]:
    """Return BLE credentials for every YD.LO1 lock on the account."""
    service = await client.lock_service
    devices = await service.get_object_list()
    creds: List[LockCredentials] = []

    for device in devices:
        if getattr(device, "product_model", None) != MODEL:
            continue
        uuid = device.mac.split(".")[-1]

        info = await service._get_lock_info(device)
        hardware = info["device"]["hardware_info"]
        versions = hardware.get("versions", {})

        await service._auth_lib.refresh_if_should()
        payload = ford_create_payload(
            service._auth_lib.token.access_token, {"uuid": uuid}, _BLE_TOKEN_PATH, "get"
        )
        resp = await service._auth_lib.get(_BLE_TOKEN_URL, params=payload)
        token = resp["token"]
        ble_token = wyze_decrypt_cbc(FORD_APP_SECRET[:16], token["token"])

        creds.append(
            LockCredentials(
                uuid=uuid,
                address=_mac_to_address(hardware["mac"]),
                ble_id=token["id"],
                ble_token=ble_token,
                nickname=getattr(device, "nickname", uuid),
                sw_version=versions.get("ble_version") or versions.get("app_version"),
                hw_version=versions.get("hardware_version"),
                serial=hardware.get("sn"),
            )
        )
    return creds
