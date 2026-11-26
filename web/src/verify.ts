// Verification by emoji (Matrix's m.sas.v1), on WebCrypto: the
// commitment, the short authentication string from the shared secret, and
// the MACs over the keys each side vouches for (hkdf-hmac-sha256.v2). The
// messages go over /chat/verification; e2e.ts runs the exchange. No DOM
// here: plain TypeScript syntax, so Node runs it (the interop tests).
import { b64, canonical, concat, unb64, type Bytes } from "./olm.js";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

export const SAS = "m.sas.v1";
export const KEY_AGREEMENT = "curve25519-hkdf-sha256";
export const HASH = "sha256";
export const MAC = "hkdf-hmac-sha256.v2";

/** The 64 emoji of Matrix's SAS, by number (shown with their own names by screen readers). */
export const EMOJI = [
  "🐶", "🐱", "🦁", "🐎", "🦄", "🐷", "🐘", "🐰", "🐼", "🐓", "🐧", "🐢", "🐟", "🐙", "🦋", "🌷",
  "🌳", "🌵", "🍄", "🌏", "🌙", "☁️", "🔥", "🍌", "🍎", "🍓", "🌽", "🍕", "🎂", "❤️", "😀", "🤖",
  "🎩", "👓", "🔧", "🎅", "👍", "☂️", "⌛", "⏰", "🎁", "💡", "📕", "✏️", "📎", "✂️", "🔒", "🔑",
  "🔨", "☎️", "🏁", "🚂", "🚲", "✈️", "🚀", "🏆", "⚽", "🎸", "🎺", "🔔", "⚓", "🎧", "📁", "📌",
];

export interface Ephemeral {
  privateKey: CryptoKey;
  publicKey: string;
}

export async function ephemeral(): Promise<Ephemeral> {
  const pair = (await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: b64(new Uint8Array(await subtle.exportKey("raw", pair.publicKey))) };
}

export async function shared(ours: Ephemeral, theirs: string): Promise<Bytes> {
  const pub = await subtle.importKey("raw", unb64(theirs), { name: "X25519" }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, ours.privateKey, 256));
}

async function hkdf(ikm: Uint8Array, info: string, length: number): Promise<Bytes> {
  const key = await subtle.importKey("raw", new Uint8Array(ikm), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) }, key, length * 8));
}

/** The accepting side's commitment to its key: sha256 over its key and the start message. */
export async function commitment(publicKey: string, start: Record<string, unknown>): Promise<string> {
  return b64(new Uint8Array(await subtle.digest("SHA-256", enc.encode(publicKey + canonical(start)))));
}

export interface Side {
  user: string;
  device: string;
  key: string;
}

/** The seven emoji (their numbers) both sides compare. */
export async function emoji(secret: Uint8Array, starting: Side, accepting: Side, transaction: string): Promise<number[]> {
  const info = `MATRIX_KEY_VERIFICATION_SAS|${starting.user}|${starting.device}|${starting.key}|${accepting.user}|${accepting.device}|${accepting.key}|${transaction}`;
  const bytes = await hkdf(secret, info, 6);
  let bits = 0n;
  for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  // The first 42 of the 48 bits, six at a time.
  return Array.from({ length: 7 }, (_, i) => Number((bits >> BigInt(42 - 6 * i)) & 63n));
}

/** One MAC of hkdf-hmac-sha256.v2: over a key (or the list of key ids, as "KEY_IDS"). */
export async function mac(secret: Uint8Array, me: { user: string; device: string }, them: { user: string; device: string }, transaction: string, keyId: string, input: string): Promise<string> {
  const info = `MATRIX_KEY_VERIFICATION_MAC${me.user}${me.device}${them.user}${them.device}${transaction}${keyId}`;
  const key = await hkdf(secret, info, 32);
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(new Uint8Array(await subtle.sign("HMAC", k, enc.encode(input))));
}

/** The mac message's content for the keys one vouches for: {keyId: publicKey}. */
export async function macContent(secret: Uint8Array, me: { user: string; device: string }, them: { user: string; device: string }, transaction: string, keys: Record<string, string>): Promise<{ mac: Record<string, string>; keys: string }> {
  const out: Record<string, string> = {};
  for (const [id, key] of Object.entries(keys)) out[id] = await mac(secret, me, them, transaction, id, key);
  const ids = Object.keys(keys).sort().join(",");
  return { mac: out, keys: await mac(secret, me, them, transaction, "KEY_IDS", ids) };
}

/**
 * Checks the other side's mac message: the list of key ids, then each key
 * it names against the key known for it. Answers the key ids that hold, or
 * null when anything does not.
 */
export async function checkMac(
  secret: Uint8Array,
  me: { user: string; device: string },
  them: { user: string; device: string },
  transaction: string,
  content: { mac?: Record<string, string>; keys?: string },
  known: Record<string, string>,
): Promise<string[] | null> {
  const macs = content.mac ?? {};
  const ids = Object.keys(macs).sort();
  if (!ids.length || content.keys !== (await mac(secret, them, me, transaction, "KEY_IDS", ids.join(",")))) return null;
  for (const id of ids) {
    const key = known[id];
    if (!key || macs[id] !== (await mac(secret, them, me, transaction, id, key))) return null;
  }
  return ids;
}

export function transactionId(): string {
  return b64(globalThis.crypto.getRandomValues(new Uint8Array(12))).replace(/[^A-Za-z0-9]/g, "");
}

export { concat };
