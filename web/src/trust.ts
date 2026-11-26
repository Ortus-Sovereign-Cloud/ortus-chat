// Trust in end-to-end rooms (docs/e2e-trust-and-backup.md), on WebCrypto
// in Matrix's formats, so the phones' library (matrix-sdk-crypto) reads
// what the browser writes: the recovery key, secret storage
// (m.secret_storage.v1.aes-hmac-sha2), cross-signing key objects, room-key
// backup encryption (m.megolm_backup.v1.curve25519-aes-sha2) and the
// organisation's escrow copy. No DOM and no storage here: plain TypeScript
// syntax, so Node runs it as it is (the interop tests).
import { b64, canonical, concat, unb64, type Bytes } from "./olm.js";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

function random(n: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// ---- the recovery key ------------------------------------------------------

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PREFIX = [0x8b, 0x01];

function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = BASE58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

function unbase58(text: string): Bytes | null {
  let n = 0n;
  for (const c of text) {
    const i = BASE58.indexOf(c);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of text) {
    if (c !== "1") break;
    out.unshift(0);
  }
  return new Uint8Array(out);
}

/** The recovery key as people see it: Matrix's base58, in groups of four. */
export function encodeRecoveryKey(key: Uint8Array): string {
  const body = concat(new Uint8Array(PREFIX), key);
  let parity = 0;
  for (const b of body) parity ^= b;
  return base58(concat(body, new Uint8Array([parity]))).replace(/(.{4})/g, "$1 ").trim();
}

/** The recovery key's 32 bytes, or null when it was mistyped. */
export function decodeRecoveryKey(text: string): Bytes | null {
  const bytes = unbase58(text.replace(/\s+/g, ""));
  if (!bytes || bytes.length !== 35 || bytes[0] !== PREFIX[0] || bytes[1] !== PREFIX[1]) return null;
  let parity = 0;
  for (const b of bytes) parity ^= b;
  return parity === 0 ? bytes.slice(2, 34) : null;
}

export function newRecoveryKey(): Bytes {
  return random(32);
}

// ---- secret storage -------------------------------------------------------

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: string, length: number): Promise<Bytes> {
  const key = await subtle.importKey("raw", new Uint8Array(ikm), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(salt), info: enc.encode(info) }, key, length * 8));
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Bytes> {
  const k = await subtle.importKey("raw", new Uint8Array(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, new Uint8Array(data)));
}

async function aesCtr(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Bytes> {
  const k = await subtle.importKey("raw", new Uint8Array(key), "AES-CTR", false, ["encrypt"]);
  return new Uint8Array(await subtle.encrypt({ name: "AES-CTR", counter: new Uint8Array(iv), length: 64 }, k, new Uint8Array(data)));
}

export interface StoredSecret {
  iv: string;
  ciphertext: string;
  mac: string;
}

/** A secret (text) sealed with the secret storage key, as `name`. */
export async function encryptSecret(key: Uint8Array, name: string, secret: string, ivIn?: Uint8Array): Promise<StoredSecret> {
  const keys = await hkdf(new Uint8Array(32), key, name, 64);
  const iv = ivIn ? new Uint8Array(ivIn) : random(16);
  iv[8]! &= 0x7f;
  const ciphertext = await aesCtr(keys.slice(0, 32), iv, enc.encode(secret));
  const mac = await hmac(keys.slice(32), ciphertext);
  return { iv: b64(iv), ciphertext: b64(ciphertext), mac: b64(mac) };
}

export async function decryptSecret(key: Uint8Array, name: string, stored: StoredSecret): Promise<string | null> {
  const keys = await hkdf(new Uint8Array(32), key, name, 64);
  const ciphertext = unb64(stored.ciphertext);
  const mac = await hmac(keys.slice(32), ciphertext);
  if (b64(mac) !== stored.mac.replace(/=+$/, "")) return null;
  return dec.decode(await aesCtr(keys.slice(0, 32), unb64(stored.iv), ciphertext));
}

/** The key's description (account data m.secret_storage.key.<id>): its MAC proves a typed key is the one. */
export async function keyDescription(key: Uint8Array, name = "Recovery key"): Promise<Record<string, unknown>> {
  const check = await encryptSecret(key, "", "\0".repeat(32));
  return { algorithm: "m.secret_storage.v1.aes-hmac-sha2", name, iv: check.iv, mac: check.mac };
}

/** Whether `key` is the one a description was made with. */
export async function keyMatches(key: Uint8Array, description: { iv: string; mac: string }): Promise<boolean> {
  const check = await encryptSecret(key, "", "\0".repeat(32), unb64(description.iv));
  return check.mac === description.mac.replace(/=+$/, "");
}

// ---- keys from seeds (so they can be kept in secret storage) --------------

const ED25519_PKCS8 = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
const X25519_PKCS8 = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20];

export interface SeedKey {
  seed: Bytes;
  privateKey: CryptoKey;
  publicKey: Bytes;
}

async function fromSeed(seed: Uint8Array, prefix: number[], algorithm: string, usages: KeyUsage[]): Promise<SeedKey> {
  const pkcs8 = concat(new Uint8Array(prefix), seed);
  const extractable = await subtle.importKey("pkcs8", pkcs8, { name: algorithm }, true, usages);
  const jwk = await subtle.exportKey("jwk", extractable);
  const privateKey = await subtle.importKey("pkcs8", pkcs8, { name: algorithm }, false, usages);
  return { seed: new Uint8Array(seed), privateKey, publicKey: unb64(jwk.x ?? "") };
}

/** An Ed25519 key from its 32-byte seed (cross-signing keys). */
export function ed25519FromSeed(seed: Uint8Array): Promise<SeedKey> {
  return fromSeed(seed, ED25519_PKCS8, "Ed25519", ["sign"]);
}

/** A Curve25519 key from its 32 bytes (the backup key). */
export function x25519FromSeed(seed: Uint8Array): Promise<SeedKey> {
  return fromSeed(seed, X25519_PKCS8, "X25519", ["deriveBits"]);
}

// ---- cross-signing --------------------------------------------------------

export interface CrossSigning {
  master: SeedKey;
  selfSigning: SeedKey;
  userSigning: SeedKey;
}

export async function newCrossSigning(): Promise<CrossSigning> {
  return {
    master: await ed25519FromSeed(random(32)),
    selfSigning: await ed25519FromSeed(random(32)),
    userSigning: await ed25519FromSeed(random(32)),
  };
}

export function keyId(key: SeedKey): string {
  return `ed25519:${b64(key.publicKey)}`;
}

async function signWith(value: Record<string, unknown>, user: string, key: SeedKey): Promise<Record<string, unknown>> {
  const { signatures, unsigned, ...rest } = value;
  const sig = b64(new Uint8Array(await subtle.sign({ name: "Ed25519" }, key.privateKey, enc.encode(canonical(rest)))));
  const all = { ...((signatures as Record<string, Record<string, string>>) ?? {}) };
  all[user] = { ...(all[user] ?? {}), [keyId(key)]: sig };
  return { ...value, signatures: all, ...(unsigned === undefined ? {} : { unsigned }) };
}

function crossKey(user: string, usage: string, key: SeedKey): Record<string, unknown> {
  return { user_id: user, usage: [usage], keys: { [keyId(key)]: b64(key.publicKey) } };
}

/** The upload for PUT /chat/cross-signing: the master signs the other two. */
export async function crossSigningUpload(user: string, keys: CrossSigning): Promise<Record<string, unknown>> {
  return {
    master: crossKey(user, "master", keys.master),
    selfSigning: await signWith(crossKey(user, "self_signing", keys.selfSigning), user, keys.master),
    userSigning: await signWith(crossKey(user, "user_signing", keys.userSigning), user, keys.master),
  };
}

/** A device's keys (as the server has them) signed by one's self-signing key. */
export function signDevice(user: string, deviceKeys: Record<string, unknown>, selfSigning: SeedKey): Promise<Record<string, unknown>> {
  return signWith(deviceKeys, user, selfSigning);
}

/** Another person's master key signed by one's user-signing key (verified them). */
export function signUser(user: string, theirMaster: Record<string, unknown>, userSigning: SeedKey): Promise<Record<string, unknown>> {
  return signWith(theirMaster, user, userSigning);
}

/** Signs any object with a key (the backup's auth data with the master key). */
export function signObject(user: string, value: Record<string, unknown>, key: SeedKey): Promise<Record<string, unknown>> {
  return signWith(value, user, key);
}

// ---- the backup and the escrow (curve25519-aes-sha2) ---------------------

export interface Sealed {
  ephemeral: string;
  ciphertext: string;
  mac: string;
}

async function sealParts(shared: Uint8Array): Promise<{ aesKey: Bytes; macKey: Bytes; iv: Bytes }> {
  const keys = await hkdf(new Uint8Array(32), shared, "", 80);
  return { aesKey: keys.slice(0, 32), macKey: keys.slice(32, 64), iv: keys.slice(64, 80) };
}

/**
 * Seals text to a Curve25519 public key, as Matrix's backup does: an
 * ephemeral key, ECDH, HKDF (80 bytes: AES key, MAC key, IV), AES-CBC; the
 * MAC is Matrix's (HMAC-SHA-256 of nothing, 8 bytes), kept for interop.
 */
export async function seal(publicKey: Uint8Array, plaintext: string): Promise<Sealed> {
  const pair = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const ephemeral = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const theirs = await subtle.importKey("raw", new Uint8Array(publicKey), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: theirs }, pair.privateKey, 256));
  const { aesKey, macKey, iv } = await sealParts(shared);
  const k = await subtle.importKey("raw", aesKey, "AES-CBC", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, k, enc.encode(plaintext)));
  const mac = (await hmac(macKey, new Uint8Array(0))).slice(0, 8);
  return { ephemeral: b64(ephemeral), ciphertext: b64(ciphertext), mac: b64(mac) };
}

export async function unseal(key: SeedKey, sealed: Sealed): Promise<string | null> {
  const theirs = await subtle.importKey("raw", unb64(sealed.ephemeral), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: theirs }, key.privateKey, 256));
  const { aesKey, macKey, iv } = await sealParts(shared);
  const mac = (await hmac(macKey, new Uint8Array(0))).slice(0, 8);
  if (b64(mac) !== sealed.mac.replace(/=+$/, "")) return null;
  const k = await subtle.importKey("raw", aesKey, "AES-CBC", false, ["decrypt"]);
  try {
    return dec.decode(await subtle.decrypt({ name: "AES-CBC", iv }, k, unb64(sealed.ciphertext)));
  } catch {
    return null;
  }
}

/** A room key for the backup: Matrix's exported session, sealed to the backup key. */
export async function backupRoomKey(
  backupPublicKey: Uint8Array,
  session: { roomId: string; sessionId: string; senderKey: string; sessionKey: string; firstIndex: number; signingKey: string },
  verified: boolean,
): Promise<Record<string, unknown>> {
  const exported = {
    algorithm: "m.megolm.v1.aes-sha2",
    sender_key: session.senderKey,
    sender_claimed_keys: { ed25519: session.signingKey },
    forwarding_curve25519_key_chain: [],
    session_key: session.sessionKey,
  };
  return {
    first_message_index: session.firstIndex,
    forwarded_count: 0,
    is_verified: verified,
    session_data: await seal(backupPublicKey, JSON.stringify(exported)),
  };
}
