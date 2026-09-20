#!/usr/bin/env python3
"""One-shot Wyze cloud probe: does the API hand out key material for a YD.LO1?

This is the *only* thing in this repo that touches the network. It authenticates
once with wyzeapy, pulls every raw response it can get for the original Wyze Lock
(product_model YD.LO1), and scans them for anything that looks like a per-device
secret -- mirroring how the Wyze Lock Bolt project sources its local keys.

Four sources are dumped, in increasing order of likely payoff. The fourth,
/openapi/lock/v1/ble/token, is the one that matters: it is confirmed to hand out
BLE key material for the Bolt, and wyzeapy's "is this a YD_BT1" check before
calling it is client-side only. See probe_ble_token().

It reads and dumps; it never writes anything back to the account or the lock.

Credentials come from the environment (or interactive prompts):

    WYZE_EMAIL      account email
    WYZE_PASSWORD   account password
    WYZE_KEY_ID     key id   from https://developer-api-console.wyze.com/
    WYZE_API_KEY    api key  from the same place

wyzeapy requires the developer key pair; email/password alone will not
authenticate. If the account has 2FA enabled the script prompts for the code.

Usage:

    tools/wyze-probe/bin/python tools/key_probe.py
    tools/wyze-probe/bin/python tools/key_probe.py --out /tmp/probe.json
    tools/wyze-probe/bin/python tools/key_probe.py --model YD_BT1 --stdout

The dump is written to a file (default ./wyze_probe_dump.json, gitignored)
rather than stdout, because it is secrets-adjacent by construction. Access and
refresh tokens are redacted before anything is written.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from getpass import getpass
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    from wyzeapy import Wyzeapy
    from wyzeapy.const import FORD_APP_SECRET
    from wyzeapy.exceptions import TwoFactorAuthenticationEnabled
    from wyzeapy.payload_factory import ford_create_payload
    from wyzeapy.utils import wyze_decrypt_cbc
    from wyzeapy.wyze_auth_lib import Token
except ImportError:  # pragma: no cover - environment problem, not a code path
    sys.exit(
        "wyzeapy is not importable, or is too old (need >= 0.6.1 for the BLE\n"
        "token endpoint, which needs Python >= 3.11).\n"
        "\n"
        "Run this with the probe venv's interpreter, not a bare `python`:\n"
        "  tools/.venv/bin/python tools/key_probe.py\n"
        "\n"
        "This must run inside WSL/Linux. Windows python.exe cannot use the\n"
        "venv even via a \\\\wsl.localhost\\... path -- it is a different\n"
        "interpreter with its own site-packages.\n"
        "\n"
        "To rebuild the venv from scratch:\n"
        "  uv venv --python 3.12 tools/.venv\n"
        "  uv pip install --python tools/.venv/bin/python -r tools/requirements.txt"
    )

DEFAULT_MODEL = "YD.LO1"
DEFAULT_OUT = "wyze_probe_dump.json"

# Field names worth flagging regardless of what their value looks like.
SUSPICIOUS_KEY = re.compile(
    r"secret|passwd|password|_key|key_|^key$|aes|crypt|cipher|token|nonce|salt|"
    r"seed|cert|priv|auth|pin|uuid|mac_?key|bind",
    re.IGNORECASE,
)

# Values worth flagging regardless of what they are called.
HEX_BLOB = re.compile(r"^[0-9a-fA-F]{16,}$")
B64_BLOB = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

# Redacted before the dump is written -- these are session credentials, not
# device key material, and there is no reason to persist them.
REDACT_KEY = re.compile(r"access_token|refresh_token|^password$|apikey|api_key", re.IGNORECASE)
REDACTED = "<redacted by key_probe>"


def uuid_candidates(mac: str) -> List[str]:
    """Every plausible 'uuid' spelling for the Ford lock endpoints.

    wyzeapy is inconsistent here -- _get_lock_info sends mac.split(".")[2] while
    _get_lock_ble_token sends the full mac. Since YD.LO1's mac format is not
    known to match YD_BT1's, try each form rather than risk a false negative
    that looks like "the cloud has no key for this device".
    """
    seen: List[str] = []
    for candidate in (mac, mac.split(".")[-1], mac.replace(".", ""), mac.split(".")[2] if mac.count(".") >= 2 else None):
        if candidate and candidate not in seen:
            seen.append(candidate)
    return seen


async def probe_ble_token(service: Any, device: Any) -> Dict[str, Any]:
    """Ask the Ford backend for this lock's BLE token.

    This is the highest-value call in the probe. wyzeapy's LockService.update()
    only calls it when product_model == "YD_BT1", but that gate is client-side
    -- nothing proves the *server* refuses a YD.LO1. If it answers, local BLE
    key extraction is solved with no APK work at all.

    Errors are captured rather than raised: a refusal body ("not supported",
    an ErrNo) is itself the finding, so we record it instead of aborting.

    Called directly rather than via BaseService._get_lock_ble_token so we can
    bypass that YD_BT1 gate, try several uuid spellings, and keep error bodies.
    """
    url_path = "/openapi/lock/v1/ble/token"
    url = f"https://yd-saas-toc.wyzecam.com{url_path}"
    results: Dict[str, Any] = {}

    for uuid in uuid_candidates(device.mac):
        try:
            await service._auth_lib.refresh_if_should()
            payload = ford_create_payload(
                service._auth_lib.token.access_token, {"uuid": uuid}, url_path, "get"
            )
            # Deliberately no check_for_errors_lock() -- we want the error body.
            response = await service._auth_lib.get(url, params=payload)
        except Exception as err:  # noqa: BLE001 - probe: record and keep going
            results[uuid] = {"_probe_error": f"{type(err).__name__}: {err}"}
            print(f"  ble/token uuid={uuid!r}: {type(err).__name__}: {err}")
            continue

        results[uuid] = response
        errno = response.get("ErrNo") if isinstance(response, dict) else None
        token_info = (response or {}).get("token") if isinstance(response, dict) else None

        if token_info:
            print(f"  ble/token uuid={uuid!r}: GOT A TOKEN (ErrNo={errno})")
            enc = token_info.get("token")
            if isinstance(enc, str) and enc:
                try:
                    plaintext = wyze_decrypt_cbc(FORD_APP_SECRET[:16], enc)
                    results[uuid]["_decrypted_token"] = plaintext
                    print(f"    decrypted -> {plaintext!r}")
                    print(f"    ble_id    -> {token_info.get('id')!r}")
                except Exception as err:  # noqa: BLE001
                    results[uuid]["_decrypt_error"] = f"{type(err).__name__}: {err}"
                    print(f"    decrypt failed: {type(err).__name__}: {err}")
        else:
            print(f"  ble/token uuid={uuid!r}: no token (ErrNo={errno}) {str(response)[:120]}")

    return results


def walk(node: Any, path: str = "$") -> Iterator[Tuple[str, Any]]:
    """Yield (json-ish path, value) for every leaf in a nested structure."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, f"{path}[{index}]")
    else:
        yield path, node


def redact(node: Any, key: Optional[str] = None) -> Any:
    """Copy a structure with session-credential fields blanked out."""
    if isinstance(node, dict):
        return {k: redact(v, k) for k, v in node.items()}
    if isinstance(node, list):
        return [redact(v, key) for v in node]
    if key is not None and REDACT_KEY.search(key) and isinstance(node, str) and node:
        return REDACTED
    return node


def find_candidates(source: str, payload: Any) -> List[Dict[str, Any]]:
    """Flag leaves that look like key material, by name or by value shape."""
    candidates: List[Dict[str, Any]] = []
    for path, value in walk(payload):
        leaf = path.rsplit(".", 1)[-1]
        reasons: List[str] = []

        if SUSPICIOUS_KEY.search(leaf) or leaf == "_decrypted_token":
            reasons.append("field name")

        if isinstance(value, str) and value:
            if HEX_BLOB.match(value):
                nbytes = len(value) // 2
                note = f"hex, {len(value)} chars"
                if len(value) % 2 == 0:
                    note += f" = {nbytes} bytes"
                    if nbytes in (16, 24, 32):
                        note += " (AES key length!)"
                reasons.append(note)
            elif B64_BLOB.match(value) and not value.isalpha() and not value.isdigit():
                reasons.append(f"base64-ish, {len(value)} chars")

        if reasons:
            # Session credentials are flagged (the field name matches) but never
            # carried into the candidate list -- candidates are printed and
            # written out, and redact() only walks the raw sources.
            shown = REDACTED if REDACT_KEY.search(leaf) and isinstance(value, str) else value
            candidates.append(
                {"source": source, "path": path, "value": shown, "why": ", ".join(reasons)}
            )
    return candidates


def credential(name: str, prompt: str, secret: bool = False) -> str:
    value = os.environ.get(name)
    if value:
        return value
    if not sys.stdin.isatty():
        sys.exit(f"{name} is not set and stdin is not a tty; cannot prompt for {prompt}.")
    value = getpass(f"{prompt}: ") if secret else input(f"{prompt}: ")
    if not value:
        sys.exit(f"No {prompt} given.")
    return value


async def authenticate() -> Wyzeapy:
    email = credential("WYZE_EMAIL", "Wyze email")
    password = credential("WYZE_PASSWORD", "Wyze password", secret=True)
    key_id = credential("WYZE_KEY_ID", "Wyze developer key id")
    api_key = credential("WYZE_API_KEY", "Wyze developer api key", secret=True)

    client = await Wyzeapy.create()
    try:
        await client.login(email, password, key_id, api_key)
    except TwoFactorAuthenticationEnabled:
        if not sys.stdin.isatty():
            sys.exit("Account has 2FA enabled and stdin is not a tty; run interactively.")
        code = input("2FA verification code: ").strip()
        token: Token = await client.login_with_2fa(code)
        if token is None:
            sys.exit("2FA login did not return a token.")
    return client


async def probe(model: str) -> Dict[str, Any]:
    client = await authenticate()
    service = await client.lock_service  # a BaseService subclass; has the raw calls

    devices = await service.get_object_list()
    inventory = [
        {
            "nickname": getattr(d, "nickname", None),
            "product_model": getattr(d, "product_model", None),
            "product_type": getattr(d, "product_type", None),
            "mac": getattr(d, "mac", None),
        }
        for d in devices
    ]
    print(f"Account has {len(devices)} device(s):")
    for entry in inventory:
        print(f"  {entry['product_model']:<12} {entry['product_type']:<14} {entry['nickname']}")

    matches = [d for d in devices if getattr(d, "product_model", None) == model]
    if not matches:
        sys.exit(
            f"\nNo device with product_model == {model!r} on this account. "
            "Pass --model to probe a different one."
        )
    if len(matches) > 1:
        print(f"\n{len(matches)} devices match {model}; probing all of them.")

    dump: Dict[str, Any] = {"model": model, "inventory": inventory, "devices": []}

    for device in matches:
        print(f"\nProbing {getattr(device, 'nickname', '?')} ({device.mac})")
        sources: Dict[str, Any] = {}

        # 1. The device-list entry, unparsed. This is the README's get_devices().
        sources["get_object_list.raw_dict"] = device.raw_dict

        # 2. The generic device-info endpoint.
        try:
            sources["get_device_Info"] = await service._get_device_info(device)
        except Exception as err:  # noqa: BLE001 - probe: record failures, keep going
            sources["get_device_Info"] = {"_probe_error": f"{type(err).__name__}: {err}"}
            print(f"  get_device_Info failed: {type(err).__name__}: {err}")

        # 3. The lock-product backend (yd-saas-toc /openapi/lock/v1/info).
        try:
            sources["lock/v1/info"] = await service._get_lock_info(device)
        except Exception as err:  # noqa: BLE001
            sources["lock/v1/info"] = {"_probe_error": f"{type(err).__name__}: {err}"}
            print(f"  lock/v1/info failed: {type(err).__name__}: {err}")

        # 4. The Ford BLE-token endpoint -- the whole ballgame. See docstring.
        sources["lock/v1/ble/token"] = await probe_ble_token(service, device)

        candidates: List[Dict[str, Any]] = []
        for name, payload in sources.items():
            candidates.extend(find_candidates(name, payload))

        dump["devices"].append(
            {
                "mac": getattr(device, "mac", None),
                "nickname": getattr(device, "nickname", None),
                "sources": sources,
                "candidates": candidates,
            }
        )

    return dump


def report(dump: Dict[str, Any]) -> None:
    for device in dump["devices"]:
        print(f"\n=== {device['nickname']} ({device['mac']}) ===")
        for name, payload in device["sources"].items():
            leaves = sum(1 for _ in walk(payload))
            print(f"  {name}: {leaves} leaf value(s)")

        candidates = device["candidates"]
        if not candidates:
            print("\n  No key-material candidates found.")
            continue

        print(f"\n  {len(candidates)} candidate(s):")
        for c in candidates:
            value = c["value"]
            shown = value if not isinstance(value, str) or len(value) <= 80 else value[:77] + "..."
            print(f"    [{c['source']}] {c['path']}")
            print(f"      {shown!r}  ({c['why']})")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"product_model to probe (default {DEFAULT_MODEL})")
    parser.add_argument("--out", default=DEFAULT_OUT, help=f"where to write the JSON dump (default {DEFAULT_OUT})")
    parser.add_argument("--stdout", action="store_true", help="also print the full dump to stdout")
    args = parser.parse_args()

    dump = await probe(args.model)
    report(dump)

    safe = redact(dump)
    with open(args.out, "w") as handle:
        json.dump(safe, handle, indent=2, sort_keys=True, default=str)
    print(f"\nFull dump written to {args.out} (session tokens redacted, gitignored).")

    if args.stdout:
        print(json.dumps(safe, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    asyncio.run(main())
