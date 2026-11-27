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

## Stage 1, as built (2026-11-25)

`phones/e2e` (`ortus-e2e`, its own Cargo workspace and lock),
`phones/e2e/ffi` (`ortus-e2e-ffi`, the UniFFI layer) and `phones/e2e/bindgen`
(UniFFI's generator, a build tool). CI's `phones`
workflow builds `OrtusE2EFFI.xcframework.zip` (aarch64-apple-ios, and
aarch64-apple-ios-sim with x86_64-apple-ios in one simulator library),
`OrtusE2E-swift.zip`, `ortus-e2e-jniLibs.zip` (arm64-v8a, armeabi-v7a,
x86_64; 16 KB pages) and `ortus-e2e-kotlin.zip` (package `org.ortus.e2e`),
with SHA-256 sums, as workflow artifacts.

The API (Swift and Kotlin names from UniFFI; every call blocks, call it off
the main thread):

    OrtusE2e.open(storeDir, passphrase, user, device, serverName, transport)
    inbox() -> Inbox {messages, roomKeys}
    decrypt(room, messageJson) -> Opened {text, thread?, fromBackup}   // the message as the chat API gives it
    send(room, text, thread?) -> message id
    forget()
    protocol Transport { http(method, path, body?) -> HttpResponse {status, body} }   // path under /api/v1, JSON text

Errors: `Transport`, `Server {status, body}`, `Store`, `Invalid`,
`Refused {reason}`, `Forgotten`.

### Decided in code, and where it differs from the design above

- **The room's own Megolm session is the crate's, not the SDK's.** The
  browser takes a room key only with `org.ortus.room` in it, and the SDK's
  `share_room_key` builds the `m.room_key` content itself (four fields, its
  extra fields private). So the crate keeps its outbound session
  (vodozemac's `GroupSession`, pickled in the store, encrypted), rotates it
  as the browser does (100 messages, a week, someone left, someone came),
  and sends the key at **index 0** over the SDK's Olm sessions
  (`Device::encrypt_event_raw`, sessions from `get_missing_sessions` and
  the claim call). This also settles "session sharing index": phones share
  at index 0 like browsers; there is no difference left to document. The SDK
  still does device keys, one-time and fallback keys, device tracking, Olm,
  room keys received and decryption; `RoomMessage` and `share_room_key` are
  not used.
- **Trust on first use** is the crate's: each device's `curve|ed` is kept
  on first sight; a device whose keys differ, whose self-signature fails, or
  whose Curve25519 key another device names, is left out of the SDK's
  key-query answers, given no room key, and its messages are refused.
- **Checks on top of the SDK's.** The SDK checks the Olm recipient and
  sender, the session key's signature and the plaintext's room. The crate
  also refuses a message when its session is not the `sender_key` it
  names, when that key and the session's Ed25519 key are not a (first-seen)
  device of the message's sender, when the sealed thread is not the
  message's (the cleartext event the SDK sees carries no relation, so the
  SDK cannot copy one in), and when another message used the same session
  index (kept in the store).
- **Matrix ids.** `@{user id in lower case}:{server}` as `store::mxid`. The
  room's Matrix id is **not** `!{room id}:{server}`: it is the room's own
  `roomId` (`!{random}:{server}`), which the crate reads from
  `GET /chat/rooms/{room}`.
- **Device list.** Ortus has no feed of device changes: each time the crate
  reads a room's devices (on every send; for opening, at most every 30 s,
  and again when a sender's device is not known) it marks those people
  changed for the SDK and answers its key query from that list.
- **Keys upload.** `PUT /chat/devices/{device}` carries `deviceKeys` every
  time (the SDK sends them only at first); `open` publishes them again, in
  case the server let the device go (a person's eleventh device). The SDK's
  one-time key names are base64 (`+`, `/`), which the server refuses: they
  are mapped to `-` and `_` (a name is a label; a key is found by itself).
- **To-device the SDK sends on its own** (a new Olm session after a broken
  one) goes through a room shared with the recipient, when there is one;
  key requests and forwarding are off.
- **Partly kept keys.** A device whose to-device message the server did not
  keep (`stored`) is not counted as given the key, and gets it with the
  next message, as in the browser.
- **`forget()`** deletes the store's files on the phone only. The server
  has no call to remove a device's keys; it keeps them until the person's
  eleventh device makes it go.
- **Tests run the server in another process.** matrix-sdk-sqlite 0.19.1
  uses rusqlite 0.40 and ortus-core rusqlite 0.41; both link `sqlite3`, so
  one binary cannot hold both. `phones/e2e/tests` start
  `examples/e2e_host.rs`, which is the app in process exactly as `tests/`
  run it (`tests/common`, SQLite and PostgreSQL with S3), and talk to it
  over stdin and stdout. The browser side is `web/src/e2e.ts` itself under
  Node (`web/interop/e2e-peer.ts`, with ortus-kit's `call` bridged to the
  same server and IndexedDB in memory).

### The tests (`cargo test -p ortus-e2e`, in `ci/check.sh`)

- `two_phones_read_each_other_threads_included`: a message and thread
  replies both ways; the server keeps no text; one's own messages open; the
  session is kept, changes after 100 messages (an index from the middle of
  the old one still opens) and when someone leaves (who gets nothing).
- `a_phone_and_the_browser_read_each_other`: the phone's room key and
  messages opened by the browser's Sealer, the browser's by the phone,
  threads included, both orders of Olm session; moved out of its thread is
  refused.
- `what_the_wire_format_refuses_is_refused`: a room key for another
  recipient (with a control that the same key for this device opens), a
  replayed index, a message moved into a thread, given to another sender or
  to another room, and a device whose keys the server changed (no room key
  for it when a newcomer brings a new session; what it seals is refused for
  not being the sender's device).

## Licences: the owner's decision

**2026-11-25: the owner allows MPL-2.0 for unmodified dependencies of the
phone encryption library (phones/e2e) only; the server stays Apache/MIT.**

`deny.toml` names each crate (`[[licenses.exceptions]]`), with no blanket
allow, so MPL stays refused everywhere else (`ci/licence-gate-selftest.sh`
still proves it; the server's own dependency tree has no MPL crate):

- matrix-sdk-crypto 0.19.1 (itself Apache-2.0) needs, not optionally,
  `as_variant`, `eyeball`, `readlock`, `readlock-tokio`, and through
  matrix-sdk-common `eyeball-im`, `imbl`, `imbl-sized-chunks`;
- UniFFI 0.32.2: `uniffi`, `uniffi_core`, `uniffi_macros`,
  `uniffi_internal_macros`, `uniffi_meta`, `uniffi_pipeline`, `uniffi_udl`,
  `uniffi_bindgen`.

**RUSTSEC-2026-0459 is ignored** in `deny.toml`: matrix-sdk-sqlite 0.19.1
pins rusqlite 0.40, whose `libsqlite3-sys` 0.38.2 bundles SQLite 3.53.2,
which "can return uninitialized page-cache memory when a process opens a
database file together with a sibling write-ahead-log (-wal) file whose page
size differs from the database's". Local only: the crafted file would have
to be inside the app's own storage. matrix-rust-sdk's main moved to
rusqlite 0.41.1 on 2026-11-09 (18757f7e08ec), not released yet; revisit
when it is (that release would also end the `links` clash, so the tests
could run the app in their own process).

The binding generator (`phones/e2e/bindgen`, UniFFI's CLI) is a build tool,
not shipped: it is its own workspace outside the library's graph and its
`cargo deny` check, because its template engine needs `basic-toml`,
unmaintained (RUSTSEC-2026-0374).

## Stage 2

The FFI's error fields are `detail`, not `message`: Kotlin's exceptions
already have a `message`, and UniFFI's Kotlin did not compile with it.

- The phones build the library themselves from the chat commit they pin
  (no releases to publish): their CI checks out ortus-chat at the pin and
  runs the same build as `phones.yml`; bindings and library come from one
  build.
- iOS (ortus-ios): add the XCFramework and `OrtusE2E.swift`; the store
  directory in Application Support with complete-until-first-unlock file
  protection, excluded from backup; the passphrase random, in the Keychain
  (after first unlock, this device only); `Transport` on the app's
  authenticated URLSession (synchronous: call the crate off the main
  thread).
- Android (ortus-android): add `jniLibs` and the Kotlin file, and JNA
  (`net.java.dev.jna:jna`, `@aar`) which UniFFI's Kotlin needs; the store
  in `noBackupFilesDir`; the passphrase wrapped by an Android Keystore key.
- `user` and `serverName` from `me` of `GET /chat/rooms`
  (`@{user}:{serverName}`); a device id made once per install (letters and
  digits) and kept with the passphrase.
- Rooms: `inbox()` on opening an end-to-end room and on a live update;
  `decrypt` each message with `sealed`; show a refused one as "cannot be
  opened" (never its text); `send` for the composer; pin rooms once seen
  encrypted, as the browser does, and never send them in the clear.
- Sign-out: `forget()`. It asks the server to drop the device
  (`DELETE /chat/devices/:device`: its keys, one-time and fallback keys and
  waiting messages) and deletes the store; offline, the phone forgets
  anyway and the server drops the device when the person's eleventh
  replaces it.
- UI tests: an end-to-end room opens, sends, and shows a reply from the
  browser.

### Stage 2, as built (2026-11-25)

Both phones open and seal end-to-end rooms (ortus-android 7398eab,
ortus-ios 3cc2652, against ortus 6544d58 with chat bb172b2).

- Each phone's `ci/e2e-lib.sh` builds the library from source at the chat
  commit the pinned program names, into `.deps/e2e` (not in git): Android
  `.so` files for arm64-v8a, armeabi-v7a and x86_64 (16 KB pages) with the
  Kotlin bindings; iOS an XCFramework with the Swift bindings, as a module
  of its own (`OrtusE2E`). CI keeps `.deps/e2e` per pin. Their LICENSES.md
  list the crates inside (generated, checked in CI).
- The store: Android `noBackupFilesDir/e2e/<user>`, passphrase sealed by
  the Keystore (`Store`); iOS Application Support `e2e/<user>`, protected
  until first unlock and excluded from backup, passphrase in the Keychain
  (after first unlock, this device only). A store that does not open makes
  a new device (new id, new passphrase).
- One thread (Android) or serial queue (iOS) of its own runs every call.
  The library's HTTP goes straight to the server: not the offline cache,
  not the outbox.
- The kits refuse `say` for a room seen as end-to-end (`SealedRoom`), so
  nothing in the clear can leave the phone, offline outbox included; the
  server refuses it too.
- Messages that do not open show "cannot be opened on this phone", never
  their ciphertext; Android logs the library's reason (`ortus-e2e`).
- Sign-out calls `forget()`.
- Tests: the kits (no network), and on the emulator and simulator against a
  real Ortus: another device of the same person (the library in the test
  process, signed in with the owner's session) writes in a room; the phone
  opens it; what the phone writes opens on the other device; the server
  keeps no text. The browser's side is covered by the crate's interop
  tests (`olm_interop.rs`, `rooms.rs`).
- Not yet: live updates in a sealed room (it loads on opening and after
  sending, as plain rooms on the phones do), threads in sealed rooms on
  the phones, and the notification extension (which never opens the
  store: a sealed message's notification has no text).

## Trust (built: see e2e-trust-and-backup.md)

Key backup with a recovery key (set up on a phone or in the browser, with
the organisation's escrow copy), cross-signing, and device verification by
QR code or emoji, so a server adding a device to someone is shown as
unverified in every room it is in.

## Tests

- The crate against vodozemac and against the browser's `olm.ts` (as
  `tests/olm_interop.rs` does): a phone and a browser in one room read each
  other, in both directions, threads included.
- The failure cases of the wire format (wrong recipient, a device's keys
  changed, a replayed index) are refused.
- On the phones: UI tests that an end-to-end room opens, sends and shows a
  reply from the browser (the program's stories run both).
