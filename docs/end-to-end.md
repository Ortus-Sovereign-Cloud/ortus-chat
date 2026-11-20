# End-to-end rooms: the wire format

An administrator allows end-to-end rooms (`PATCH /chat/policy {encryptedRooms: true}`).
In such a room the server keeps only what it cannot read. The format below
uses primitives every client has: WebCrypto in browsers, CryptoKit on iOS,
`java.security` / Tink on Android. Algorithm name: `ortus.p256-aes-gcm.v1`.

Base64 below is standard base64 with padding, except in JWKs (base64url,
as JWK defines).

## Devices

Each device of a person makes an ECDH key pair on P-256 and keeps the
private half on the device (not extractable in browsers; the Secure
Enclave or Keychain on iOS; Android Keystore). It tells the server its
public half once:

    PUT /api/v1/chat/devices/{device}
    {"publicKey": {"kty": "EC", "crv": "P-256", "x": "…", "y": "…"}}

`device` is 1–64 letters, digits, `-` or `_`, chosen by the device. A
device keeps its key: another key under the same id is refused (409). A
person has at most ten devices; the oldest makes way.

## Room keys

A room key is 32 random bytes used with AES-256-GCM. Versions count from 1.
The room's owner's device makes version 1 when the room has none.

    GET /api/v1/chat/rooms/{room}/devices
    → {"devices": [{"user": "@id:server", "device", "publicKey", "versions": [1]}], "latest": 1}

For each member's device lacking the latest version, a device that holds it
wraps it:

1. Make an ephemeral P-256 key pair `e`.
2. `z` = ECDH(`e`.private, device public key), 32 bytes.
3. `k` = HKDF-SHA-256(ikm = `z`, salt = 32 zero bytes,
   info = UTF-8 of `ortus room key|{room}|{version}|{user}|{device}`), 32 bytes.
4. `iv` = 12 random bytes; `c` = AES-256-GCM(`k`, `iv`, room key), no additional data.

and sends:

    POST /api/v1/chat/rooms/{room}/keys
    {"fromDevice": "…", "keys": [{"user", "device", "version",
      "wrapped": {"algorithm": "ortus.p256-aes-gcm.v1", "epk": {JWK of e.public},
                  "iv": base64(iv), "ciphertext": base64(c)}}]}

A key already given to a device stays as it is. A device reads its keys
with `GET /api/v1/chat/rooms/{room}/keys/{device}` and unwraps with its
private key and `epk` (steps 2–3, then decrypt).

`room` is the room's Ortus id (as in the paths), `user` the member's Matrix
id, `device` the receiving device's id: binding them in `info` means a
wrapped key cannot be moved to another room, person or device.

## Messages

    plaintext = UTF-8 JSON {"body": "the text"}
    iv = 12 random bytes
    ciphertext = AES-256-GCM(room key of `version`, iv, plaintext,
                             additional data = UTF-8 of "{room}|{version}")

    POST /api/v1/chat/rooms/{room}/sealed
    {"version", "device": sender's device, "iv": base64, "ciphertext": base64, "thread": optional root id}

Messages come back like any other with `"text": ""` and
`"sealed": {"algorithm", "version", "device", "iv", "ciphertext"}`.

## What the server does not do in these rooms

Plain messages, edits, Drive links and other apps' posts are refused;
nothing is indexed for search; no decisions are recorded; the room is not
shared over federation; a legal hold does not keep its messages from
retention. Reactions, membership and timing stay visible to the server.
