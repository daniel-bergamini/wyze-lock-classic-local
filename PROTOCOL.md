# YD.LO1 (original Wyze Lock) — BLE protocol

Clean specification of the Bluetooth Low Energy protocol for the **original
Wyze Lock** (`product_model` `YD.LO1`), the ODM Yunding/"Loock" `XNLL901`.
Everything here was reverse-engineered from live traffic and **validated
against real hardware** — state decoding cross-checked against the cloud API to
the second, and lock/unlock both driven end-to-end from an independent
implementation (`src/wyze_lock_classic_local/`). The messy research trail lives
in `CLAUDE.md`; this file is the confirmed result.

> Not the **Wyze Lock Bolt** (`YD_BT1`), which is a different, newer product.
> The two share framing and some conventions but differ in the actuation path.

Per-device secrets below are shown as placeholders. Two you need:

- `UUID` — the lock's 32-hex-char cloud identifier (from the Wyze API). Its
  last 16 characters, lowercased and taken as ASCII bytes, are the AES key for
  everything except the actuation answer.
- `BLE_TOKEN` / `BLE_ID` — reusable credentials from the cloud, needed only to
  answer the actuation challenge. See [Cloud bootstrap](#cloud-bootstrap).

## Transport & addressing

- Standard BLE GATT. No pairing, bonding, or link encryption is used or
  required (`pair=False`); the lock accepts an unauthenticated connection and
  authenticates at the application layer instead. This lets the integration run
  alongside the Wyze app.
- The lock **drops idle connections** after tens of seconds and accepts one
  central at a time. Connect, do the operation, disconnect.
- **Connect address:** the cloud reports the BLE MAC (`hardware_info.mac`)
  **byte-reversed and without separators**. Reverse the byte order to get the
  advertised address, e.g. cloud `FFEEDDCCBBAA` → `AA:BB:CC:DD:EE:FF`.

## GATT layout

| Service | UUID | Purpose |
|---|---|---|
| Device Information | `0000180a-…` | Plaintext strings (manufacturer, `XNLL901`, serial, versions) |
| Nordic UART (NUS) | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` | Actuation transport |
| Loock state | `00002500-0000-6b63-6f6c-2e6b636f6f6c` | State + command-write |

Characteristics used:

| UUID | Props | Role |
|---|---|---|
| `6e400002-b5a3-f393-e0a9-e50e24dcca9e` | write | NUS **write** (client → lock) |
| `6e400003-b5a3-f393-e0a9-e50e24dcca9e` | notify | NUS **notify** (lock → client) |
| `00002220-0000-6b63-6f6c-2e6b636f6f6c` | read, notify | Authoritative **lock state** |
| `00002250-0000-6b63-6f6c-2e6b636f6f6c` | write | Session **hello** sink |

The UUID tail bytes `6b 63 6f 6c 2e 6b 63 6f 6f 6c` are ASCII `loock.lock`
reversed — Yunding's lock brand, not Wyze-specific.

> Note on handles: some GATT stacks report the *declaration* handle; ATT
> operations use the *value* handle (declaration + 1). Address characteristics
> by UUID to avoid the off-by-one.

## State (read path)

The lock-state characteristic `00002220` is a single 16-byte **AES-128-ECB**
block. Key = `ASCII(UUID[-16:].lower())` (16 bytes). No cloud token needed.

Decrypted layout (16 bytes):

```
byte 0      status       0x01 = LOCKED, 0x02 = UNLOCKED
bytes 1..4  timestamp    uint32 big-endian, unix seconds of the last change
bytes 5..10 padding      zero
bytes 11..15 "loock"     ASCII 6c 6f 6f 63 6b (integrity/marker)
```

Example: `02 6aafc665 000000000000 6c6f6f636b` → unlocked, changed at
`0x6aafc665`. Reads are deterministic (ECB, no IV): the same state+timestamp
yields the same ciphertext.

Other characteristics in the service (`2208/2210/2212/2222/2230`) use the same
key and a similar `status | ts | … | "loock"` shape and carry auxiliary status
(e.g. `2222` tracks the door sensor); only `2220` is needed for lock state.

## Actuation (lock / unlock)

A challenge-response over NUS. All frames use two nested layers.

### L1 framing

```
0xAB | flags(1) | length(2 BE) | crc(2 BE) | seq(2 BE) | body
```

- `length` = body length; `crc` = **CRC-16/ARC** (poly `0xA001` reflected, init
  `0x0000`, no final XOR) over the body.
- A single logical frame may span multiple ATT writes/notifications;
  reassemble by `length`.
- `flags`: `0x00` client data, `0x40` lock data, `0x08` client ACK, `0x48`
  lock ACK.

### L2 body

```
cmd(1) | flags(1) | [ tag(1) | length(2 BE) | value ]…
```

Relevant commands: `0x91` challenge request, `0x86` challenge (lock → client),
`0x04` lock/unlock (and the lock's result echo). Tag `0xD2` carries the nonce.

### Sequence

1. **Hello.** Write a 16-byte block to `00002250`: `AES-ECB(UUID[-16:],
   "1" + "0"*10 + "loock")`. Constant for both directions; a session prime, not
   the action. (Skipping this, or using the wrong `seq` below, makes the lock
   drop the connection.)
2. **Request challenge.** NUS-write `pack_l1(pack_l2(0x91, {0x0A: 0x27}),
   seq=0)`. **`seq` must be 0.**
3. Lock replies with an L1 ACK (`flags 0x48`), then a challenge: L1 `flags
   0x40`, L2 `cmd 0x86`, tag `0xD2` = 16-byte nonce.
4. **Answer.** NUS-write an ACK (`flags 0x08`, echoing the challenge frame's
   `seq`), then `pack_l1(l2_answer, seq=1)` where the L2 answer is:

   ```
   cmd 0x04, flags 0x00,
     tag 0x05 (2 bytes) = BLE_ID, big-endian
     tag 0x04 (16 bytes) = ANSWER
     tag 0xAD (1) = 00,  tag 0xF4 (1) = 01,  tag 0xF7 (1) = 01
   ```

   `ANSWER = AES-ECB(ASCII(BLE_TOKEN[16:]), nonce) XOR MAGIC`, where:

   ```
   unlock MAGIC = 01 00 00 00 00 00 00 00 00 00 00 6c 6f 6f 63 6b
   lock   MAGIC = 02 00 00 00 00 00 00 00 00 00 00 6c 6f 6f 63 6b
   ```

   The AES key is the **second 16 ASCII characters** of the decrypted
   `BLE_TOKEN` (a 32-char string) — *not* the UUID key used elsewhere.
5. Lock ACKs, then sends a result (`cmd 0x04`, tag `0x77` = the action echo:
   `01` unlock / `02` lock — this is not a success/failure code).
6. The bolt throws, and ~1–2 s later the new state arrives as a **notification**
   on `00002220`. Subscribe and wait for it rather than reading immediately.

Both magics are confirmed: an independent builder reproduces the app's lock and
unlock frames byte-for-byte, and `00002220` tracks each operation.

## Cloud bootstrap

Actuation needs `BLE_ID` and `BLE_TOKEN`, fetched **once** (reusable; the nonce
provides per-attempt freshness — no cloud round trip at control time):

```
GET https://yd-saas-toc.wyzecam.com/openapi/lock/v1/ble/token
    signed with ford_create_payload(access_token, {"uuid": UUID}, path, "get")
```

`response["token"]["id"]` = `BLE_ID`; `BLE_TOKEN = wyze_decrypt_cbc(
FORD_APP_SECRET[:16], response["token"]["token"])` (AES-CBC, key
`MD5(FORD_APP_SECRET[:16])`, IV `0123456789ABCDEF`). The endpoint is gated
client-side on `product_model == "YD_BT1"` in `wyzeapy`, but the **server does
not enforce it** — it answers for a `YD.LO1` uuid. The `UUID` itself comes from
the device list / `openapi/lock/v1/info`.

## Security notes

- The connection is unauthenticated and unencrypted at the link layer; auth is
  the app-layer challenge-response.
- The actuation answer is bound to a fresh per-attempt nonce, so answers are not
  replayable. However, **the state key and the `00002250` hello derive only
  from the UUID**, and the hello/command padding carries no counter — so state
  is readable and the hello is replayable by anyone who knows the (not very
  secret) UUID. Possession of `BLE_TOKEN` is what gates actuation.
- This is a discontinued 2019 device; these are observations, not an
  endorsement of the design.

## Reference implementation

`src/wyze_lock_classic_local/protocol.py` (pure codec, unit-tested) and
`device.py` (BLE transport). `scripts/actuate.py` drives them against a lock.
