// Olm (m.olm.v1.curve25519-aes-sha2) and Megolm (m.megolm.v1.aes-sha2) on
// WebCrypto, in Matrix's wire format, so browsers talk with any client
// built on vodozemac or libolm (the phones). No DOM and no storage here:
// state is plain objects holding bytes and CryptoKeys, which the caller
// keeps (IndexedDB in browsers). Plain TypeScript syntax only, so Node
// runs this file as it is (the interop test).

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

export type Bytes = Uint8Array<ArrayBuffer>;

// ---- encodings -----------------------------------------------------------

export function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/, "");
}

export function unb64(text: string): Bytes {
  const t = text.replace(/-/g, "+").replace(/_/g, "/");
  const s = atob(t + "===".slice((t.length + 3) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

function varint(n: number): Bytes {
  const out: number[] = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  out.push(n);
  return new Uint8Array(out);
}

/** The fields of a protobuf-style message: tag → bytes or number. */
function fields(data: Uint8Array, start: number, end: number): Map<number, Bytes | number> {
  const out = new Map<number, Bytes | number>();
  let i = start;
  const read = (): number => {
    let n = 0;
    let mul = 1;
    for (;;) {
      if (i >= end) throw new Error("truncated");
      const b = data[i++]!;
      n += (b & 0x7f) * mul;
      if (!(b & 0x80)) return n;
      mul *= 128;
      if (mul > 2 ** 35) throw new Error("varint too long");
    }
  };
  while (i < end) {
    const key = read();
    const tag = key >> 3;
    const type = key & 7;
    if (type === 0) out.set(tag, read());
    else if (type === 2) {
      const len = read();
      if (i + len > end) throw new Error("truncated");
      out.set(tag, data.slice(i, i + len));
      i += len;
    } else throw new Error("unknown field type");
  }
  return out;
}

function bytesField(m: Map<number, Bytes | number>, tag: number): Bytes {
  const v = m.get(tag);
  if (!(v instanceof Uint8Array)) throw new Error(`missing field ${tag}`);
  return v;
}

function field(tag: number, value: Uint8Array): Bytes {
  return concat(new Uint8Array([(tag << 3) | 2]), varint(value.length), value);
}

// ---- primitives ----------------------------------------------------------

export interface X25519 {
  privateKey: CryptoKey;
  publicKey: Bytes;
}

export async function x25519(): Promise<X25519> {
  const pair = (await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await subtle.exportKey("raw", pair.publicKey)) };
}

async function dh(ours: CryptoKey, theirs: Uint8Array): Promise<Bytes> {
  const pub = await subtle.importKey("raw", new Uint8Array(theirs), { name: "X25519" }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, ours, 256));
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: string, length: number): Promise<Bytes> {
  const key = await subtle.importKey("raw", new Uint8Array(ikm), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(salt), info: enc.encode(info) }, key, length * 8));
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Bytes> {
  const k = await subtle.importKey("raw", new Uint8Array(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, new Uint8Array(data)));
}

async function aes(key: Uint8Array, iv: Uint8Array, data: Uint8Array, encrypt: boolean): Promise<Bytes> {
  const k = await subtle.importKey("raw", new Uint8Array(key), "AES-CBC", false, [encrypt ? "encrypt" : "decrypt"]);
  const op = encrypt ? subtle.encrypt.bind(subtle) : subtle.decrypt.bind(subtle);
  return new Uint8Array(await op({ name: "AES-CBC", iv: new Uint8Array(iv) }, k, new Uint8Array(data)));
}

export interface Ed25519 {
  privateKey: CryptoKey;
  publicKey: Bytes;
}

export async function ed25519(): Promise<Ed25519> {
  const pair = (await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await subtle.exportKey("raw", pair.publicKey)) };
}

export async function sign(key: CryptoKey, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.sign({ name: "Ed25519" }, key, new Uint8Array(data)));
}

export async function verify(publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  try {
    const k = await subtle.importKey("raw", new Uint8Array(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, k, new Uint8Array(signature), new Uint8Array(data));
  } catch {
    return false;
  }
}

/** Matrix's canonical JSON: keys sorted, no spaces. */
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .filter((k) => o[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Signs a JSON object the Matrix way (without its signatures and unsigned). */
export async function signJson<T extends Record<string, unknown>>(value: T, entity: string, keyId: string, key: CryptoKey): Promise<T> {
  const { signatures, unsigned, ...rest } = value as Record<string, unknown>;
  const sig = b64(await sign(key, enc.encode(canonical(rest))));
  const all = { ...((signatures as Record<string, Record<string, string>>) ?? {}) };
  all[entity] = { ...(all[entity] ?? {}), [keyId]: sig };
  return { ...value, signatures: all, ...(unsigned === undefined ? {} : { unsigned }) };
}

export async function verifyJson(value: Record<string, unknown>, entity: string, keyId: string, publicKey: Uint8Array): Promise<boolean> {
  const sig = (value.signatures as Record<string, Record<string, string>> | undefined)?.[entity]?.[keyId];
  if (!sig) return false;
  const { signatures: _s, unsigned: _u, ...rest } = value;
  return verify(publicKey, unb64(sig), enc.encode(canonical(rest)));
}

// ---- Olm -----------------------------------------------------------------

const MAC_LENGTH = 8;
// Messages skipped in one chain: bounded, so a forged message cannot make
// the browser hash for long.
const MAX_SKIP = 200;

interface SenderChain {
  ratchet: X25519;
  chainKey: Bytes;
  index: number;
}

interface ReceiverChain {
  ratchetKey: Bytes;
  chainKey: Bytes;
  index: number;
}

export interface OlmSession {
  /** Their identity key (Curve25519). */
  theirIdentity: Bytes;
  rootKey: Bytes;
  sender: SenderChain | null;
  receivers: ReceiverChain[];
  skipped: { ratchetKey: Bytes; index: number; messageKey: Bytes }[];
  /** While they have not answered: the pre-key fields of each message. */
  preKey: { oneTimeKey: Bytes; baseKey: Bytes; identityKey: Bytes } | null;
  /** The base key that started it (to know a repeated pre-key message). */
  baseKey: Bytes;
}

export interface OlmMessage {
  type: 0 | 1;
  body: string;
}

async function messageKeys(messageKey: Uint8Array): Promise<{ aesKey: Bytes; macKey: Bytes; iv: Bytes }> {
  const k = await hkdf(new Uint8Array(32), messageKey, "OLM_KEYS", 80);
  return { aesKey: k.slice(0, 32), macKey: k.slice(32, 64), iv: k.slice(64, 80) };
}

async function nextChain(chainKey: Uint8Array): Promise<{ messageKey: Bytes; chainKey: Bytes }> {
  return { messageKey: await hmac(chainKey, new Uint8Array([1])), chainKey: await hmac(chainKey, new Uint8Array([2])) };
}

/** Starts a session to a device from its identity key and one of its one-time keys. */
export async function outboundSession(ours: X25519, theirIdentity: Uint8Array, theirOneTimeKey: Uint8Array): Promise<OlmSession> {
  const base = await x25519();
  const secret = concat(await dh(ours.privateKey, theirOneTimeKey), await dh(base.privateKey, theirIdentity), await dh(base.privateKey, theirOneTimeKey));
  const derived = await hkdf(new Uint8Array(0), secret, "OLM_ROOT", 64);
  return {
    theirIdentity: new Uint8Array(theirIdentity),
    rootKey: derived.slice(0, 32),
    sender: { ratchet: await x25519(), chainKey: derived.slice(32, 64), index: 0 },
    receivers: [],
    skipped: [],
    preKey: { oneTimeKey: new Uint8Array(theirOneTimeKey), baseKey: base.publicKey, identityKey: ours.publicKey },
    baseKey: base.publicKey,
  };
}

export async function olmEncrypt(session: OlmSession, plaintext: string): Promise<OlmMessage> {
  if (!session.sender) {
    // Our turn after theirs: a new ratchet key.
    const theirs = session.receivers[0];
    if (!theirs) throw new Error("no chain to answer");
    const ratchet = await x25519();
    const derived = await hkdf(session.rootKey, await dh(ratchet.privateKey, theirs.ratchetKey), "OLM_RATCHET", 64);
    session.rootKey = derived.slice(0, 32);
    session.sender = { ratchet, chainKey: derived.slice(32, 64), index: 0 };
  }
  const s = session.sender;
  const { messageKey, chainKey } = await nextChain(s.chainKey);
  const index = s.index;
  s.chainKey = chainKey;
  s.index += 1;
  const keys = await messageKeys(messageKey);
  const ciphertext = await aes(keys.aesKey, keys.iv, enc.encode(plaintext), true);
  const body = concat(new Uint8Array([3]), field(1, s.ratchet.publicKey), new Uint8Array([0x10]), varint(index), field(4, ciphertext));
  const message = concat(body, (await hmac(keys.macKey, body)).slice(0, MAC_LENGTH));
  if (!session.preKey) return { type: 1, body: b64(message) };
  const p = session.preKey;
  const pre = concat(new Uint8Array([3]), field(1, p.oneTimeKey), field(2, p.baseKey), field(3, p.identityKey), field(4, message));
  return { type: 0, body: b64(pre) };
}

/** The fields of a pre-key message. */
export function preKeyFields(body: string): { oneTimeKey: Bytes; baseKey: Bytes; identityKey: Bytes; message: Bytes } {
  const data = unb64(body);
  if (data[0] !== 3) throw new Error("unknown version");
  const f = fields(data, 1, data.length);
  return { oneTimeKey: bytesField(f, 1), baseKey: bytesField(f, 2), identityKey: bytesField(f, 3), message: bytesField(f, 4) };
}

/** A session from a device's first (pre-key) message, with its plaintext. */
export async function inboundSession(ours: X25519, oneTimeKey: X25519, body: string): Promise<{ session: OlmSession; plaintext: string }> {
  const p = preKeyFields(body);
  if (!same(p.oneTimeKey, oneTimeKey.publicKey)) throw new Error("another one-time key");
  const secret = concat(await dh(oneTimeKey.privateKey, p.identityKey), await dh(ours.privateKey, p.baseKey), await dh(oneTimeKey.privateKey, p.baseKey));
  const derived = await hkdf(new Uint8Array(0), secret, "OLM_ROOT", 64);
  const inner = parseMessage(p.message);
  const session: OlmSession = {
    theirIdentity: p.identityKey,
    rootKey: derived.slice(0, 32),
    sender: null,
    receivers: [{ ratchetKey: inner.ratchetKey, chainKey: derived.slice(32, 64), index: 0 }],
    skipped: [],
    preKey: null,
    baseKey: p.baseKey,
  };
  const plaintext = await olmDecryptMessage(session, p.message);
  return { session, plaintext };
}

function parseMessage(data: Uint8Array): { ratchetKey: Bytes; index: number; ciphertext: Bytes; body: Bytes; mac: Bytes } {
  if (data.length < 1 + MAC_LENGTH || data[0] !== 3) throw new Error("unknown version");
  const end = data.length - MAC_LENGTH;
  const f = fields(data, 1, end);
  const index = f.get(2);
  if (typeof index !== "number") throw new Error("missing index");
  return { ratchetKey: bytesField(f, 1), index, ciphertext: bytesField(f, 4), body: data.slice(0, end), mac: data.slice(end) };
}

/** Whether a pre-key message belongs to this session (a repeat before they answered). */
export function matchesPreKey(session: OlmSession, body: string): boolean {
  try {
    return same(preKeyFields(body).baseKey, session.baseKey);
  } catch {
    return false;
  }
}

export async function olmDecrypt(session: OlmSession, message: OlmMessage): Promise<string> {
  const data = message.type === 0 ? preKeyFields(message.body).message : unb64(message.body);
  return olmDecryptMessage(session, data);
}

async function olmDecryptMessage(session: OlmSession, data: Uint8Array): Promise<string> {
  const m = parseMessage(data);
  const open = async (messageKey: Uint8Array): Promise<string> => {
    const keys = await messageKeys(messageKey);
    if (!same((await hmac(keys.macKey, m.body)).slice(0, MAC_LENGTH), m.mac)) throw new Error("bad mac");
    return new TextDecoder().decode(await aes(keys.aesKey, keys.iv, m.ciphertext, false));
  };
  // A key kept for a message that arrived out of order.
  const skippedAt = session.skipped.findIndex((k) => k.index === m.index && same(k.ratchetKey, m.ratchetKey));
  if (skippedAt >= 0) {
    const text = await open(session.skipped[skippedAt]!.messageKey);
    session.skipped.splice(skippedAt, 1);
    session.preKey = null;
    return text;
  }
  let chain = session.receivers.find((c) => same(c.ratchetKey, m.ratchetKey));
  let rootKey = session.rootKey;
  let fresh = false;
  if (!chain) {
    // Their new ratchet key: a new receiving chain (kept only if the MAC holds).
    if (!session.sender) throw new Error("unknown chain");
    const derived = await hkdf(session.rootKey, await dh(session.sender.ratchet.privateKey, m.ratchetKey), "OLM_RATCHET", 64);
    rootKey = derived.slice(0, 32);
    chain = { ratchetKey: m.ratchetKey, chainKey: derived.slice(32, 64), index: 0 };
    fresh = true;
  }
  if (m.index < chain.index) throw new Error("message key already used");
  if (m.index - chain.index > MAX_SKIP) throw new Error("too far ahead");
  let chainKey = chain.chainKey;
  const skipped: { ratchetKey: Bytes; index: number; messageKey: Bytes }[] = [];
  for (let i = chain.index; i < m.index; i++) {
    const n = await nextChain(chainKey);
    skipped.push({ ratchetKey: m.ratchetKey, index: i, messageKey: n.messageKey });
    chainKey = n.chainKey;
  }
  const n = await nextChain(chainKey);
  const text = await open(n.messageKey);
  // It holds: keep the new state.
  chain.chainKey = n.chainKey;
  chain.index = m.index + 1;
  if (fresh) {
    session.rootKey = rootKey;
    session.receivers.unshift(chain);
    session.receivers = session.receivers.slice(0, 5);
    session.sender = null;
  }
  session.skipped = [...session.skipped, ...skipped].slice(-40);
  session.preKey = null;
  return text;
}

// ---- Megolm --------------------------------------------------------------

export interface MegolmRatchet {
  parts: Bytes; // R0..R3, 128 bytes
  index: number;
}

export interface MegolmOutbound {
  ratchet: MegolmRatchet;
  signing: Ed25519;
}

export interface MegolmInbound {
  /** The earliest ratchet known (to read messages from there on). */
  ratchet: MegolmRatchet;
  signingKey: Bytes;
}

const SEEDS = [0, 1, 2, 3];

async function rehash(parts: Bytes, from: number, to: number): Promise<void> {
  const out = await hmac(parts.slice(from * 32, from * 32 + 32), new Uint8Array([SEEDS[to]!]));
  parts.set(out, to * 32);
}

async function advance(r: MegolmRatchet): Promise<void> {
  let mask = 0x00ffffff;
  let h = 0;
  r.index = (r.index + 1) >>> 0;
  while (h < 4) {
    if (!(r.index & mask)) break;
    h++;
    mask >>>= 8;
  }
  for (let i = 3; i >= h; i--) await rehash(r.parts, h, i);
}

async function advanceTo(r: MegolmRatchet, to: number): Promise<void> {
  for (let j = 0; j < 4; j++) {
    const shift = (3 - j) * 8;
    const mask = (0xffffffff << shift) >>> 0;
    let steps = ((to >>> shift) - (r.index >>> shift)) & 0xff;
    if (steps === 0) {
      if (to < r.index) steps = 0x100;
      else continue;
    }
    while (steps > 1) {
      await rehash(r.parts, j, j);
      steps--;
    }
    for (let k = 3; k >= j; k--) await rehash(r.parts, j, k);
    r.index = (to & mask) >>> 0;
  }
}

export async function megolmOutbound(): Promise<MegolmOutbound> {
  const parts = globalThis.crypto.getRandomValues(new Uint8Array(128));
  return { ratchet: { parts, index: 0 }, signing: await ed25519() };
}

export function sessionId(signingKey: Uint8Array): string {
  return b64(signingKey);
}

/** The key others import to read from the ratchet's current index on. */
export async function sessionKey(s: MegolmOutbound, at: MegolmRatchet = s.ratchet): Promise<string> {
  const index = new Uint8Array(4);
  new DataView(index.buffer).setUint32(0, at.index);
  const body = concat(new Uint8Array([2]), index, at.parts, s.signing.publicKey);
  return b64(concat(body, await sign(s.signing.privateKey, body)));
}

export async function megolmInbound(key: string): Promise<MegolmInbound> {
  const data = unb64(key);
  if (data.length !== 1 + 4 + 128 + 32 + 64 || data[0] !== 2) throw new Error("not a session key");
  const signingKey = data.slice(133, 165);
  if (!(await verify(signingKey, data.slice(165), data.slice(0, 165)))) throw new Error("the session key's signature does not hold");
  return { ratchet: { parts: data.slice(5, 133), index: new DataView(data.buffer, data.byteOffset + 1, 4).getUint32(0) }, signingKey };
}

/**
 * A session as Matrix exports it (for backups and key export): version 1,
 * the index, the ratchet and the signing key, not signed (the backup's own
 * signature vouches for it).
 */
export function exportSessionKey(s: MegolmInbound): string {
  const index = new Uint8Array(4);
  new DataView(index.buffer).setUint32(0, s.ratchet.index);
  return b64(concat(new Uint8Array([1]), index, s.ratchet.parts, s.signingKey));
}

/** Whether an earlier session runs on to a later one: the same signing key,
 * and its ratchet, advanced, is the later one's. */
export async function leadsTo(earlier: MegolmInbound, later: MegolmInbound): Promise<boolean> {
  if (!same(earlier.signingKey, later.signingKey) || earlier.ratchet.index > later.ratchet.index) return false;
  const r: MegolmRatchet = { parts: new Uint8Array(earlier.ratchet.parts), index: earlier.ratchet.index };
  if (later.ratchet.index > r.index) await advanceTo(r, later.ratchet.index);
  return same(r.parts, later.ratchet.parts);
}

/** A session from Matrix's export format (a backup's). */
export function importSessionKey(key: string): MegolmInbound {
  const data = unb64(key);
  if (data.length !== 1 + 4 + 128 + 32 || data[0] !== 1) throw new Error("not an exported session key");
  return { ratchet: { parts: data.slice(5, 133), index: new DataView(data.buffer, data.byteOffset + 1, 4).getUint32(0) }, signingKey: data.slice(133, 165) };
}

async function megolmKeys(parts: Uint8Array): Promise<{ aesKey: Bytes; macKey: Bytes; iv: Bytes }> {
  const k = await hkdf(new Uint8Array(32), parts, "MEGOLM_KEYS", 80);
  return { aesKey: k.slice(0, 32), macKey: k.slice(32, 64), iv: k.slice(64, 80) };
}

export async function megolmEncrypt(s: MegolmOutbound, plaintext: string): Promise<string> {
  const keys = await megolmKeys(s.ratchet.parts);
  const ciphertext = await aes(keys.aesKey, keys.iv, enc.encode(plaintext), true);
  const body = concat(new Uint8Array([3, 0x08]), varint(s.ratchet.index), field(2, ciphertext));
  const withMac = concat(body, (await hmac(keys.macKey, body)).slice(0, MAC_LENGTH));
  const out = concat(withMac, await sign(s.signing.privateKey, withMac));
  await advance(s.ratchet);
  return b64(out);
}

export async function megolmDecrypt(s: MegolmInbound, ciphertext: string): Promise<{ plaintext: string; index: number }> {
  const data = unb64(ciphertext);
  if (data.length < 1 + MAC_LENGTH + 64 || data[0] !== 3) throw new Error("unknown version");
  const signed = data.slice(0, data.length - 64);
  if (!(await verify(s.signingKey, data.slice(data.length - 64), signed))) throw new Error("the signature does not hold");
  const end = signed.length - MAC_LENGTH;
  const f = fields(signed, 1, end);
  const index = f.get(1);
  if (typeof index !== "number") throw new Error("missing index");
  if (index < s.ratchet.index) throw new Error("before this session key");
  const r: MegolmRatchet = { parts: new Uint8Array(s.ratchet.parts), index: s.ratchet.index };
  if (index > r.index) await advanceTo(r, index);
  const keys = await megolmKeys(r.parts);
  if (!same((await hmac(keys.macKey, signed.slice(0, end))).slice(0, MAC_LENGTH), signed.slice(end))) throw new Error("bad mac");
  return { plaintext: new TextDecoder().decode(await aes(keys.aesKey, keys.iv, bytesField(f, 2), false)), index };
}
