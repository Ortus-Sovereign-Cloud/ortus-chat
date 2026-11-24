# End-to-end rooms on the phones: the design

V1 shows end-to-end rooms locked on the phones. This is how the phones
open them. Decided 2026-11-24: build on **matrix-sdk-crypto** (Apache-2.0,
the Matrix Foundation's Rust crypto state machine on vodozemac, used by
Element X), not on raw vodozemac, so device tracking, Olm session
handling, Megolm sharing and rotation, replay checks and, later, key
backup and verification are code that is already reviewed and in use.

## The shape

One small Rust crate, `ortus-e2e` (in this repository, `phones/e2e/`),
wraps an `OlmMachine` and speaks Ortus's REST API for it. It is built
once, with UniFFI bindings, into an XCFramework for iOS and an AAR for
Android by this repository's CI (a release asset per chat commit); the
phone repositories pin that asset by checksum, as they pin WebRTC. The
phones only call:

    open(store_dir, user, device) / room_messages(room, items) -> plain texts
    send(room, text, thread?) / inbox() / forget()

and give it an HTTP function (their own authenticated client), so the
crate holds no session token and the transport stays the phones'.

## The adapter (OlmMachine requests -> Ortus)

matrix-sdk-crypto works with Matrix sync shapes; Ortus's API is
room-scoped. The crate maps one to the other:

| OlmMachine asks | Ortus call |
|---|---|
| KeysUpload (device keys, one-time keys, fallback key) | `PUT /chat/devices/{device}` |
| KeysQuery for users | `GET /chat/rooms/{room}/devices` for the room being sent to; answered in `/keys/query` shape for those users |
| KeysClaim | `POST /chat/rooms/{room}/claim` |
| ToDevice (room keys) | `POST /chat/rooms/{room}/to-device` |
| RoomMessage (encrypted) | `POST /chat/rooms/{room}/sealed` |
| sync changes: to-device events, one-time key counts | `GET /chat/devices/{device}/inbox`, then `…/inbox/done` |

Keys are asked per room, so the crate always knows the room a request is
for: it shares keys only inside `share_room_key(room, members)`, which it
calls with the room's members from `GET /chat/rooms/{room}`.

Matrix ids: `@{user id}:{server}` and `!{room id}:{server}`, as the
browser already uses (`org.ortus.room` in the room key carries Ortus's id).

## Differences from the browser to settle in code

- **Session sharing index.** The browser shares a session at index 0, so a
  person's new device reads the whole session. matrix-sdk-crypto shares
  from the current index. Phones receiving a key at index 0 are fine; a
  phone *sending* shares from the current index: a person's device added
  later reads only from then on. Acceptable for V1; documented in the
  wire format.
- **Rotation.** `EncryptionSettings`: 100 messages, one week, and on a
  member leaving (the SDK does this on device or member changes), the
  same as the browser.
- **Trust.** The browser trusts on first use and stops sending to a device
  whose keys change. matrix-sdk-crypto's default shares with unverified
  devices; set it to refuse devices whose identity keys changed
  (`CollectStrategy` with identity-based exclusion where available), and
  keep a TOFU list in the crate's store.
- **Storage.** The SDK's SQLite store, in the app's protected container
  (iOS: complete-until-first-unlock file protection, excluded from
  backup; Android: no-backup directory), its passphrase in the Keychain /
  Android Keystore.

## Later (needs server and browser work too)

Key backup (`room_keys` endpoints, a recovery key), cross-signing and
device verification (QR or emoji), so a server adding a device to someone
is detected. Each needs new chat endpoints and the browser to take part;
they are a second step, not V1 of phones in end-to-end rooms.

## Tests

- The crate against vodozemac and against the browser's `olm.ts` (as
  `tests/olm_interop.rs` does): a phone and a browser in one room read each
  other, in both directions, threads included.
- The failure cases of the wire format (wrong recipient, a device's keys
  changed, a replayed index) are refused.
- On the phones: UI tests that an end-to-end room opens, sends and shows a
  reply from the browser (the program's stories run both).
