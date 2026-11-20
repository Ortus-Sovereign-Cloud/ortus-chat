# End-to-end rooms: the wire format

An administrator allows end-to-end rooms (`PATCH /chat/policy {encryptedRooms: true}`).
In such a room the server keeps only what it cannot read. The cryptography
is Matrix's: Olm (`m.olm.v1.curve25519-aes-sha2`) between devices and
Megolm (`m.megolm.v1.aes-sha2`) for room messages, so the browser
(`web/src/olm.ts`, on WebCrypto) and the phones (vodozemac) read each
other. `tests/olm_interop.rs` checks the browser's implementation against
vodozemac in CI.

Keys and ciphertexts are unpadded standard base64, as in Matrix. JSON is
signed Matrix's way: Ed25519 over the canonical JSON without `signatures`
and `unsigned`, under `signatures.{user id}.{"ed25519:" + device}`.

## Devices

A device makes a Curve25519 identity key and an Ed25519 signing key, and
publishes them with signed one-time keys:

    PUT /api/v1/chat/devices/{device}
    {"deviceKeys": {"user_id": "@id:server", "device_id": "{device}",
                    "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                    "keys": {"curve25519:{device}": "…", "ed25519:{device}": "…"},
                    "signatures": {…}},
     "oneTimeKeys": {"signed_curve25519:{id}": {"key": "…", "signatures": {…}}}}
    → {"oneTimeKeyCount": n}

The server checks the person, the device id and both signatures; a device
keeps its keys (other keys under the same id are refused), and a
Curve25519 key belongs to one device only. A person has at most ten devices
(the oldest makes way) and a device at most 100 one-time keys. A device
also publishes one fallback key (`"fallbackKeys"`, signed, with
`"fallback": true`), given out when its one-time keys have run out and not
removed. Clients keep about twenty-five one-time keys published, topping up
from the count the inbox reports.

## Sharing a room session

A sending device has one outbound Megolm session per room. It makes a new
one when a member has left (they keep what came before), when someone new
has come (they read from then on), after 100 messages, or after a week. It
shares the session key **at index 0**, so a member's new device reads the
whole session; a newcomer gets only sessions made after they came.
Sessions go to joined and invited members' devices (an invited person reads
the device list to check who sent them a key).

    GET  /api/v1/chat/rooms/{room}/devices                → members' (joined and invited) device keys
    POST /api/v1/chat/rooms/{room}/claim {devices: [{user, device}]} → one one-time key each (or the fallback key), given out once; a few a minute per device

Clients check each device's self-signature and remember its keys on
first sight (trust on first use; a device whose keys change is no longer
given room keys). The device list comes from the server: a server that adds
a device to someone is not detected in V1 (no cross-signing yet). Clients reuse an Olm session to a device, or start one
from a claimed one-time key, whose signature they check. Then they send
the room key:

    POST /api/v1/chat/rooms/{room}/to-device
    {"fromDevice": "…", "messages": [{"user", "device",
      "content": {"algorithm": "m.olm.v1.curve25519-aes-sha2", "sender_key": "{our curve25519}",
                  "ciphertext": {"{their curve25519}": {"type": 0 | 1, "body": "…"}}}}]}

The Olm plaintext is:

    {"type": "m.room_key",
     "content": {"algorithm": "m.megolm.v1.aes-sha2", "room_id": "!…:server",
                 "session_id": "…", "session_key": "…", "org.ortus.room": "{room}"},
     "sender": "@…", "sender_device": "…", "keys": {"ed25519": "{sender's}"},
     "recipient": "@…", "recipient_keys": {"ed25519": "{recipient's}"}}

A device reads its messages with `GET /api/v1/chat/devices/{device}/inbox`
and removes them with `POST …/inbox/done {ids}`; the server answers each
to-device request with the messages it kept (`stored`), and a sender counts
a device as given the key only then. Each sender may have 200 messages
waiting for a device. A device takes a room key only when:

- the recipient fields are its own;
- the sender is the person the server names;
- the Olm session is that `sender_key`'s (its identity key);
- that device's published keys match the Olm `sender_key` and `keys.ed25519`;
- the session key's own signature holds and matches `session_id`.

## Messages

The Megolm plaintext is
`{"type": "m.room.message", "content": {"msgtype": "m.text", "body": "…"}, "room_id": "!…:server"}`,
with `"m.relates_to": {"rel_type": "m.thread", "event_id": root}` in the
content for a thread reply.
It is sent as:

    POST /api/v1/chat/rooms/{room}/sealed
    {"algorithm": "m.megolm.v1.aes-sha2", "sender_key": "…", "ciphertext": "…",
     "session_id": "…", "device_id": "{one of the sender's devices}", "thread": optional root id}

Messages come back like any other, with `"text": ""` and
`"sealed": {"algorithm", "sender_key", "ciphertext", "session_id", "device_id"}`.

A device opens one only when all of these hold:

- the session came from the device whose `sender_key` the message names
  (sessions are kept by sender key and session id);
- that device belongs to the message's sender;
- the plaintext's `room_id` is the room's, and its thread is the message's;
- no other message used the same session index (a replay).

A browser that has seen a room end-to-end encrypted never sends to it in
the clear afterwards, whatever the server says.

## What the server does not do in these rooms

Plain messages, edits, Drive links and other apps' posts are refused;
nothing is indexed for search; no decisions are recorded; the room is not
shared over federation; a legal hold does not keep its messages from
retention. Reactions, membership, timing and who sends to whom stay
visible to the server.
