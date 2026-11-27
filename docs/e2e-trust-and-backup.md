# End-to-end rooms: device verification and key backup

Stage 3 of end-to-end rooms (after the browser, then the phones). The
owner's decisions of 26 November 2026:

- **Recovery**: each person holds a recovery key, and the organisation
  keeps an escrow copy, so history can be recovered for a person (for
  example for compliance).
- **Unverified devices**: rooms warn and still send to them. Today's
  devices keep working; nothing breaks on the day this ships.
- **Verification**: a QR code between two devices where one has a camera,
  emoji to compare where not.

The shape follows Matrix, so the phones' library (matrix-sdk-crypto) does
the cryptography there and the browser speaks the same formats (written by
hand on WebCrypto, as `olm.ts` is: no new dependency in the web client).

## What it guards against

Today a person's devices are trusted on first use: a server that adds a
device to someone (valid keys, made by the server) gets room keys from
everyone. After this stage:

- a person's own devices are signed by their **self-signing key**; a
  device without that signature shows as unverified to everyone, with a
  warning in every room it is in;
- people who verified each other sign each other's **master key** with
  their **user-signing key**; a changed master key shows as a warning;
- the server never holds a private key in the clear: cross-signing keys
  and the backup key live in **secret storage**, encrypted on the device
  with a key derived from the recovery key, and with the organisation's
  escrow key;
- a backup whose key the server swapped is refused before any room key is
  uploaded to it: the backup's public key must be signed by the person's
  master key or one of their verified devices.

## Keys

- **Cross-signing** (Ed25519): master, self-signing (signed by master),
  user-signing (signed by master). Made on the person's first device that
  sets up recovery; private parts in secret storage.
- **Recovery key**: 32 random bytes, shown once as Matrix's base58 groups
  (`EsT…`), or derived from a passphrase (PBKDF2, as Matrix). It is the
  secret storage key (`m.secret_storage.v1.aes-hmac-sha2`).
- **Escrow**: the organisation's X25519 public key in chat's policy (set
  by an administrator, whose browser makes the pair and gives the private
  half as a file to keep offline: the server never sees it). Each
  person's recovery key is also sealed to it, in the backup's own
  format (`curve25519-aes-sha2`, libolm's PkEncryption: an ephemeral
  Curve25519 key, ECDH, HKDF-SHA-256, AES-256-CBC, and its truncated
  HMAC-SHA-256 MAC), and stored as their account data `ortus.escrow`. With the private half, an
  administrator can open a person's secret storage. The escrow is shown to
  people when they set up recovery ("your organisation can recover your
  history"), with the key's fingerprint and who set it.
  The key is **signed and pinned** (the owner's decision of 27 November
  2026, after the security review: a server serving its own key would
  otherwise open everyone's history). The administrator's browser signs
  `{user_id, usage: ["ortus.escrow"], public_key}` with their master key
  (Matrix's canonical-JSON signature, as cross-signing); the server keeps
  it only from an administrator, as themselves, signed by their current
  master key, and serves it with the signer's master key as this person
  sees it (`signerMaster`, with their own user-signing signature on it if
  they verified the signer). Browsers and phones check the signature and
  the shape before sealing, refuse a key no administrator signed ("ask
  them to make it again"), say whether the signer is the person, someone
  they verified, or not verified by them, seal only to the key the person
  was shown, and keep the key they accepted: a different one later is said
  to have changed.
- **Backup** (`m.megolm_backup.v1.curve25519-aes-sha2`): a Curve25519 key
  pair; each room key is encrypted to the public half and uploaded; the
  private half is in secret storage. `auth_data` carries the public key
  and signatures (master key, devices).

## Server (ortus-chat)

New tables (migration 10): `chat_cross_signing` (user, kind, key JSON),
`chat_key_signatures` (signer user and key, target user and key,
signature), `chat_account_data` (user, type, content), `chat_backup_versions`
(user, version, algorithm, auth data, etag, deleted), `chat_backup_keys`
(user, version, room, session, data, first index, forwarded count,
verified).

Routes (signed in, own data only unless said):

- `PUT /chat/cross-signing` `{master, selfSigning, userSigning}`: the first
  upload is free; replacing a master key needs a recent sign-in (step-up),
  and drops the signatures made with or on the old one.
- `POST /chat/signatures` `{user: {keyId: signedObject}}`: each signature
  is checked against the signer's published key before it is kept.
- `GET /chat/rooms/:room/devices` (existing) adds, per member, their
  master and self-signing keys and the signatures on their devices; and
  the caller's own user-signing key and the master keys it signed.
- `GET`/`PUT /chat/account-data/:type`: the person's secret storage and
  escrow blobs (opaque to the server; at most 64 KB each).
- `POST /chat/backup/version` `{algorithm, authData}`, `GET` (the current),
  `DELETE /chat/backup/version/:v`; `PUT`/`GET /chat/backup/keys?version=`
  (`{rooms: {room: {sessions: {sessionId: keyData}}}}`); a key is replaced
  only by a better one (Matrix's rules: verified, lower first index, fewer
  forwards).
- `PATCH /chat/policy` `{escrow}` (administrators): the escrow object
  signed by the caller's current master key, or null to take it away (the
  old `{escrowKey: ""}` still takes it away; a new key unsigned is
  refused); a change needs a recent sign-in. `GET /chat/policy` gives
  everyone `escrow` (with `signerMaster`), `escrowKey` (the public key, to
  show) and `escrowUnsigned`.

## Browser (ortus-chat web)

- Settings › Security gets **Recovery**: set up (makes cross-signing,
  signs this device, makes the backup, shows the recovery key once, seals
  it to the escrow), enter the recovery key on a new device (opens secret
  storage: cross-signing private keys and the backup key; restores the
  backup; signs this device).
- **Verification**: to-device `m.key.verification.*` messages over the
  existing to-device routes. SAS (`m.sas.v1`: X25519, HKDF-SHA-256, the
  64 emoji) first; QR (`m.qr_code.scan.v1`, `m.reciprocate.v1`) shown on
  the browser and scanned by a phone.
- Rooms show a shield per member: verified (cross-signed), unverified
  device, changed identity; sending still goes to every device.
- New room keys are backed up as they are made and received.

## Phones (ortus-chat phones/e2e and the apps)

matrix-sdk-crypto does cross-signing, secret storage, backups and
verification; the adapter maps its requests (`SigningKeysUpload`,
`SignatureUpload`, `KeysBackup`, verification to-device messages) to the
routes above, and the FFI exposes: recovery state, set up recovery (gives
the recovery key), recover with a key, start or accept a verification,
its emoji, confirm, and scan or show a QR code. The apps: Settings ›
Recovery, a shield on rooms and members, the verification sheets.

## As built (26 November 2026)

- Server (chat c6078f1 and after): every route above, and
  `POST /chat/verification` (typed to-device messages to one's own devices
  or to someone sharing a room), `GET /chat/keys?user=` (their devices and
  master key, for verifying), `GET /chat/admin/escrow?email=` (an
  administrator takes a person's sealed escrow copy; recorded).
- Browser: recovery set up (Recovery in a sealed room), recovery on a new
  browser, room keys backed up as they come, the escrow copy, a warning
  with the room's unverified devices and Verify, verification by emoji
  (Matrix's m.sas.v1, written on WebCrypto); Admin › Chat with the escrow
  key and a person's recovery key opened from their copy.
- Phones: recovery set up on the phone (the same formats: the browser
  recovers with a phone's key, and the escrow copy opens to it) or
  recovered with the key; the warning, with Verify on each unverified
  device (another person's or one's own); verification by emoji or QR code
  (scan the other device's code, show this phone's), all by
  matrix-sdk-crypto.
- QR codes (`m.qr_code.show.v1`, `m.qr_code.scan.v1`, `m.reciprocate.v1`):
  the browser shows a code (`web/src/qr.ts`, written by hand: byte mode,
  level M) when the other device can scan, and emoji stay a choice; what is
  signed once the code is scanned is fixed when the code is made (the keys
  it shows), and only after the person confirms the other device scanned
  it. Phones scan (the code's raw bytes: the payload is binary) and show.
- Tests: the formats against matrix-sdk-crypto (`trust_interop.rs`), the
  browser and a phone on a real server (`trust_phone.rs`: the phone
  restores the browser's backup, both show the same emoji and finish;
  `trust_more.rs`: recovery set up on a phone, opened by the browser and
  by the escrow key; the browser's code, read back by an independent
  decoder (rqrr) and scanned by a phone; a phone verifying another
  person's device), the browser flows (`recovery`, `escrow`, `verify`
  specs), the server's checks (`tests/trust.rs`).
- Messages opened with a room key restored from the backup are shown as
  "sender could not be confirmed": the backup is not authenticated (the
  server knows its public key and can write entries to it), so what an
  entry says of its sender is a claim. The phones' crate marks them
  (`Opened.from_backup`, for the apps to show; false again once the
  sender's own key for that session arrives over Olm), and takes an entry
  only under its session's own id (its Ed25519 key), so no entry stands in
  for another session (`phones/e2e/tests/backup.rs`).
- The escrow key signed and pinned (27 November 2026): `PATCH
  /chat/policy {escrow}` takes the signed object only (exact shape, the
  caller as `user_id`, their current master key's signature, kept with
  that one signature); `GET` serves it with `signerMaster`, and serves a
  key kept from before (or one whose signer's master key changed since) as
  `escrow: null, escrowUnsigned: true`, which set-up refuses and Admin ›
  Chat shows as "make it again". The browser (`Sealer.escrowInfo()`,
  `setUpRecovery(acceptedEscrowKey)`, `signWithMaster`) and the phones
  (`escrow_info()`, `set_up_recovery(accepted_escrow_key)`) check it the
  same way before anything is made, and keep the accepted key (IndexedDB;
  the crypto store's custom values). Set-up with an escrow goes on only
  with the key the person was shown. Admin › Chat makes the key only in a
  browser holding the master key (recovery set up or entered there).
  Tests: `tests/trust.rs` (unsigned, another's or an old master key's
  signature refused; served with the signer's master key; a key from
  before served as unsigned), `escrow.spec` (the key changing while the
  person looks is refused until they look again), `trust_more.rs` (a key
  the server swapped in is refused; a changed key refused until accepted).
- Not yet: the browser scanning a phone's code (no camera API it can rely
  on: a phone shows its code to another phone, and emoji between a phone
  and a browser work both ways).

## Order and tests

1. **Server**: the routes with their checks (a signature that does not
   verify is refused; another person's data is never served or changed;
   replacing a master key needs step-up; a worse backup key does not
   replace a better one).
2. **Browser**: cross-signing, recovery and backup; then SAS; then QR.
   Interop with vodozemac and matrix-sdk-crypto in `tests/` as for Olm.
3. **Phones**: the crate's adapter and FFI (its tests run the server and
   the browser's code, as `rooms.rs` does); then the apps.
4. **Escrow**: the administrator's key (made in the browser), sealing on
   setup, and an administrator's recovery of a person's history.

The acceptance tests that matter most:

- a device the server adds for someone (valid keys, not signed by their
  self-signing key) shows as unverified in every member's room view;
- a backup whose public key is not signed by the person's master key or a
  verified device of theirs is refused before any key is uploaded;
- the recovery key, the cross-signing private keys and the backup private
  key never reach the server unencrypted (the server's stored blobs are
  checked to hold none of them);
- with the escrow private key, an administrator opens a person's backup;
  without it, nobody but the person does.
