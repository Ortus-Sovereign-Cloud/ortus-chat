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
  person's recovery key is also sealed to it (ECDH + HKDF + AES-GCM) and
  stored as their account data `ortus.escrow`. With the private half, an
  administrator can open a person's secret storage. The escrow is shown to
  people when they set up recovery ("your organisation can recover your
  history").
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
- `PATCH /chat/policy` `{escrowKey}` (administrators); `GET /chat/policy`
  gives it to everyone.

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
