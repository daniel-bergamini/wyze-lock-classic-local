"""Config flow: collect Wyze credentials and verify them."""

from __future__ import annotations

import functools
from typing import Any

import voluptuous as vol
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .cloud import login_blocking
from .const import CONF_API_KEY, CONF_EMAIL, CONF_KEY_ID, CONF_PASSWORD, DOMAIN

try:
    from wyzeapy.exceptions import TwoFactorAuthenticationEnabled
except ImportError:  # pragma: no cover - only at runtime with wyzeapy present
    class TwoFactorAuthenticationEnabled(Exception):
        ...


_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_KEY_ID): str,
        vol.Required(CONF_API_KEY): str,
    }
)


class WyzeLockClassicConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._creds: dict[str, str] = {}

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """A Wyze Lock advertised nearby — prompt to set up the account.

        One config entry (the Wyze account) manages every lock, so if we are
        already configured there is nothing to add. Otherwise fall through to
        the credentials step; setup then pulls in all locks, including this one.
        We key the discovery flow on the domain so multiple advertising locks
        raise a single setup prompt, not one per lock.
        """
        if self._async_current_entries():
            return self.async_abort(reason="already_configured")
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        self.context["title_placeholders"] = {"name": discovery_info.name or "Wyze Lock"}
        return await self.async_step_user()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            self._creds = user_input
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
            self._abort_if_unique_id_configured()
            try:
                await self.hass.async_add_executor_job(
                    functools.partial(
                        login_blocking,
                        user_input[CONF_EMAIL],
                        user_input[CONF_PASSWORD],
                        user_input[CONF_KEY_ID],
                        user_input[CONF_API_KEY],
                    )
                )
            except TwoFactorAuthenticationEnabled:
                return await self.async_step_2fa()
            except Exception:  # noqa: BLE001
                errors["base"] = "cannot_connect"
            else:
                return self._create()
        return self.async_show_form(step_id="user", data_schema=_USER_SCHEMA, errors=errors)

    async def async_step_2fa(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await self.hass.async_add_executor_job(
                    functools.partial(
                        login_blocking,
                        self._creds[CONF_EMAIL],
                        self._creds[CONF_PASSWORD],
                        self._creds[CONF_KEY_ID],
                        self._creds[CONF_API_KEY],
                        user_input["code"],
                    )
                )
            except Exception:  # noqa: BLE001
                errors["base"] = "invalid_2fa"
            else:
                return self._create()
        return self.async_show_form(
            step_id="2fa",
            data_schema=vol.Schema({vol.Required("code"): str}),
            errors=errors,
        )

    def _create(self) -> ConfigFlowResult:
        return self.async_create_entry(title=self._creds[CONF_EMAIL], data=self._creds)
