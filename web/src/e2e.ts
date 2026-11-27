// End-to-end rooms in the browser, in Matrix's shapes (olm.ts does the
// cryptography; docs/end-to-end.md has the wire format). This device has
// Curve25519 and Ed25519 identity keys, one-time keys and a fallback key;
// it shares its Megolm session for a room with every member's device over
// Olm, seals messages with it, and opens what members' devices sealed.
// Everything is kept in IndexedDB: the device's identity and one-time keys
// as CryptoKeys that cannot be read out; the cross-signing and backup seeds
// sealed with such a key (AES-GCM), which guards them at rest only (script
// on this origin can still use it); room sessions as plain bytes. One
// operation at a time per person, across tabs too.
import { call } from "ortus-kit";
import * as olm from "./olm.js";
import * as trust from "./trust.js";
import * as sas from "./verify.js";
import { qrCode } from "./qr.js";

export const OLM = "m.olm.v1.curve25519-aes-sha2";
export const MEGOLM = "m.megolm.v1.aes-sha2";

export interface Sealed {
  algorithm: string;
  sender_key: string;
  ciphertext: string;
  session_id: string;
  device_id: string;
}

interface Account {
  device: string;
  identity: olm.X25519;
  signing: olm.Ed25519;
  oneTimeKeys: Record<string, olm.X25519>;
  /** The fallback keys still accepted (the newest first). */
  fallback: olm.X25519[];
  next: number;
}

interface Device {
  user: string;
  device: string;
  curve: string;
  ed: string;
}

interface Outbound {
  id: string;
  session: olm.MegolmOutbound;
  /** The key at index 0: members' new devices read the session's history. */
  initialKey: string;
  sharedWith: string[];
  /** The keys of each device the session was sent to (user|device: curve|ed). */
  sentTo?: Record<string, string>;
  created: number;
  count: number;
}

interface Inbound {
  session: olm.MegolmInbound;
  senderUser: string;
  /** The Ed25519 key of the device that made the session (for backups). */
  signing?: string;
  /** Taken from the backup, which anyone with its public key can add to:
   * the sender is not confirmed until the key comes from them over Olm. */
  fromBackup?: boolean;
}

/** An opened message: its text, and whether its key came from the backup only. */
export interface Opened {
  text: string;
  fromBackup: boolean;
}

/** This browser's cross-signing keys and backup key (seeds), after recovery was set up or used; kept sealed (Wrapped). */
interface Trust {
  master: string;
  selfSigning: string;
  userSigning: string;
  backup?: string;
  /** The backup version whose auth data the master key signed. */
  version?: string;
}

/** A device this browser gave a room key to: its keys (curve|ed), and when. */
interface Sent {
  keys: string;
  at: number;
}
const SENT_FOR = 7 * 86_400_000;

/** Trust sealed with this browser's non-extractable AES-GCM key. */
interface Wrapped {
  iv: Uint8Array;
  data: ArrayBuffer;
}

/** Where recovery stands: set up for the person, and opened on this browser. */
export interface RecoveryState {
  set: boolean;
  here: boolean;
  escrow: boolean;
}

/** The organisation's escrow key, as set-up shows it before the person confirms. */
export interface EscrowInfo {
  /** The X25519 public key (unpadded base64) recovery keys are sealed to. */
  key: string;
  /** The key in groups of four, for an administrator to confirm. */
  fingerprint: string;
  /** Who signed it (their Matrix id). */
  signer: string;
  /** you: signed by this person's own master key; verified: by someone this person verified; unverified: neither. */
  signerStatus: "you" | "verified" | "unverified";
  /** Not the key this browser accepted at the last set-up. */
  changed: boolean;
}

/** Set-up refuses an escrow key no administrator signed. */
export const ESCROW_UNSIGNED = "The organisation's escrow key is not signed by an administrator: ask them to make it again.";
/** Set-up refuses an escrow key other than the one the person was shown. */
export const ESCROW_NOT_ACCEPTED = "The organisation's escrow key is not the one you were shown: look at it again.";

/** An escrow key's fingerprint: its first 24 characters in groups of four. */
export function escrowFingerprint(key: string): string {
  return (key.slice(0, 24).match(/.{1,4}/g) ?? []).join(" ");
}

/** A verification (by QR code or emoji), as the screen shows it. */
export interface VerificationView {
  id: string;
  /** The other person (oneself, for one's own other device). */
  user: string;
  device?: string;
  /**
   * requested: we asked; incoming: they ask; qr: our code is shown for the
   * other device to scan (or emoji instead, or theirs scanned); ready: no
   * code here, the other device shows one (scan it, or emoji); scanned:
   * the other device scanned ours (does it say so?); waiting: keys are
   * being agreed, or the other device is to confirm we scanned its code;
   * emoji: compare; done; unsigned: the keys matched but nothing could be
   * vouched for here (this browser holds no keys, or they had none to
   * sign); cancelled.
   */
  state: "requested" | "incoming" | "qr" | "ready" | "scanned" | "waiting" | "emoji" | "done" | "unsigned" | "cancelled";
  emoji?: number[];
  /** The code's modules, dark when true, while it is shown. */
  qr?: boolean[][];
  /** The other device shows a code this browser's camera can scan (Sealer.scanCode). */
  canScan?: boolean;
  /** We scanned the other device's code: it is to say so on its screen. */
  scannedTheirs?: boolean;
  reason?: string;
}

/** The ways this browser verifies: emoji, showing a QR code to the other
 * device's camera, and (with a camera of its own) scanning the other's. */
const QR_SHOW = "m.qr_code.show.v1";
const QR_SCAN = "m.qr_code.scan.v1";
const RECIPROCATE = "m.reciprocate.v1";

/** Said when a scanned code's keys are not the ones the server has (the verification stops). */
export const CODE_MISMATCH = "The code's keys are not the ones the server has.";

/** The parts of a verification code (Matrix's format: MATRIX, 2, the mode, the transaction, two keys, a secret). */
export function parseCode(bytes: Uint8Array): { mode: number; id: string; first: Uint8Array; second: Uint8Array; secret: Uint8Array } | null {
  const head = new TextEncoder().encode("MATRIX");
  if (bytes.length < 10 || !head.every((b, i) => bytes[i] === b) || bytes[6] !== 0x02 || bytes[7]! > 2) return null;
  const length = (bytes[8]! << 8) | bytes[9]!;
  const at = 10 + length;
  // The secret: at least 8 bytes (Matrix's minimum).
  if (bytes.length < at + 64 + 8) return null;
  let id: string;
  try {
    id = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(10, at));
  } catch {
    return null;
  }
  return { mode: bytes[7]!, id, first: bytes.slice(at, at + 32), second: bytes.slice(at + 32, at + 64), secret: bytes.slice(at + 64) };
}

/** What a shown code vouches for, fixed when it was made: what is signed once the other device scanned it. */
interface ShownCode {
  secret: string;
  /** Their master key (another person), their device's keys (one's own other device), or nothing to sign (this browser does not hold the keys). */
  sign: { kind: "master"; keyId: string; key: string; object: Record<string, unknown> } | { kind: "device"; object: Record<string, unknown> } | { kind: "none" };
}

interface Verification {
  view: VerificationView;
  /** We sent the request. */
  started: boolean;
  /** We sent the emoji's start message (the starting side of m.sas.v1). */
  sasStarted?: boolean;
  theirMethods?: string[];
  code?: ShownCode;
  /** Their code, scanned here: what it proved, signed once they say done. */
  scanned?: ShownCode["sign"];
  start?: Record<string, unknown>;
  commitment?: string;
  ours?: sas.Ephemeral;
  theirKey?: string;
  secret?: Uint8Array;
  confirmed?: boolean;
  theirMac?: { mac?: Record<string, string>; keys?: string };
  macSent?: boolean;
  vouched?: string[];
}

/** Secrets kept in secret storage (Matrix's names). */
const SECRETS = { master: "m.cross_signing.master", selfSigning: "m.cross_signing.self_signing", userSigning: "m.cross_signing.user_signing", backup: "m.megolm_backup.v1" } as const;
const BACKUP = "m.megolm_backup.v1.curve25519-aes-sha2";

const enc = (s: string): string => encodeURIComponent(s);

// ---- IndexedDB -------------------------------------------------------------

let opened: Promise<IDBDatabase> | null = null;
function db(): Promise<IDBDatabase> {
  opened ??= new Promise((resolve, reject) => {
    const r = indexedDB.open("ortus-chat-olm", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("state");
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  return opened;
}

async function get<T>(key: string): Promise<T | undefined> {
  const d = await db();
  return new Promise((resolve, reject) => {
    const r = d.transaction("state").objectStore("state").get(key);
    r.onsuccess = () => resolve(r.result as T | undefined);
    r.onerror = () => reject(r.error);
  });
}

async function put(key: string, value: unknown): Promise<void> {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction("state", "readwrite");
    t.objectStore("state").put(value, key);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

/** Every kept value whose key starts with `prefix`. */
async function entries<T>(prefix: string): Promise<[string, T][]> {
  const d = await db();
  const keys = await new Promise<IDBValidKey[]>((resolve, reject) => {
    const r = d.transaction("state").objectStore("state").getAllKeys();
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  const out: [string, T][] = [];
  for (const k of keys) {
    if (typeof k !== "string" || !k.startsWith(prefix)) continue;
    const v = await get<T>(k);
    if (v !== undefined) out.push([k, v]);
  }
  return out;
}

function deviceId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(10)), (b) => String.fromCharCode(65 + (b % 26))).join("");
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Whether an exported session key (a backup's) is the session with that
 * id: a Megolm session's id is its Ed25519 signing key. */
function matchesId(exported: string, sessionId: string): boolean {
  try {
    return sameBytes(olm.importSessionKey(exported).signingKey, olm.unb64(sessionId));
  } catch {
    return false;
  }
}

/** A cross-signing key object's one Ed25519 key: the user's, for that one
 * use, its id the key itself (Matrix's shape); null otherwise. */
function crossKey(o: unknown, user: string, usage: string): [string, olm.Bytes] | null {
  if (!o || typeof o !== "object") return null;
  const k = o as { user_id?: unknown; usage?: unknown; keys?: unknown };
  if (k.user_id !== user || !Array.isArray(k.usage) || k.usage.length !== 1 || k.usage[0] !== usage) return null;
  if (!k.keys || typeof k.keys !== "object") return null;
  const keys = Object.entries(k.keys as Record<string, unknown>);
  if (keys.length !== 1) return null;
  const [id, value] = keys[0]!;
  if (typeof value !== "string" || id !== `ed25519:${value}`) return null;
  const bytes = olm.unb64(value);
  return bytes.length === 32 ? [id, bytes] : null;
}

/** A device's keys as published: its own (user and device), signed by its
 * own Ed25519 key. Answers that key, or null. */
async function selfSigned(o: Record<string, unknown> | undefined, user: string, device: string): Promise<string | null> {
  const k = o as { user_id?: string; device_id?: string; keys?: Record<string, string> } | undefined;
  const ed = k?.keys?.[`ed25519:${device}`];
  if (!o || !ed || typeof ed !== "string" || k.user_id !== user || k.device_id !== device) return null;
  return (await olm.verifyJson(o, user, `ed25519:${device}`, olm.unb64(ed))) ? ed : null;
}

/** End-to-end rooms for one person on this browser. */
export class Sealer {
  private published = false;
  /** One operation at a time in this tab (and across tabs: a lock). */
  private chain: Promise<unknown> = Promise.resolve();
  private opened = new Map<string, Opened>();
  private readonly me: string;
  /** How many sessions from the backup the sender's own key has confirmed (the screen reopens its messages). */
  confirmed = 0;

  constructor(me: string) {
    this.me = me;
  }

  private run<T>(f: () => Promise<T>): Promise<T> {
    const locked = (): Promise<T> => (navigator.locks ? navigator.locks.request(`ortus-olm:${this.me}`, f) : f());
    const next = this.chain.catch(() => undefined).then(locked);
    this.chain = next;
    return next;
  }

  private key(kind: string, rest: string): string {
    return `${kind}:${this.me}:${rest}`;
  }

  /** This device: made once, its keys published, one-time keys topped up. */
  ready(): Promise<void> {
    return this.run(async () => {
      await this.account();
    });
  }

  /** The account, read afresh (another tab may have changed it). */
  private async account(): Promise<Account> {
    let a = await get<Account>(this.key("account", ""));
    if (!a) {
      a = { device: deviceId(), identity: await olm.x25519(), signing: await olm.ed25519(), oneTimeKeys: {}, fallback: [], next: 0 };
      await put(this.key("account", ""), a);
    }
    if (!this.published) {
      const r = await this.upload(a, {}, null);
      await this.topUp(a, r.oneTimeKeyCount, r.fallbackKey);
      this.published = true;
    }
    return a;
  }

  private async upload(a: Account, oneTimeKeys: Record<string, unknown>, fallback: Record<string, unknown> | null): Promise<{ oneTimeKeyCount: number; fallbackKey: boolean }> {
    const keys = await olm.signJson(
      {
        user_id: this.me,
        device_id: a.device,
        algorithms: [OLM, MEGOLM],
        keys: { [`curve25519:${a.device}`]: olm.b64(a.identity.publicKey), [`ed25519:${a.device}`]: olm.b64(a.signing.publicKey) },
      },
      this.me,
      `ed25519:${a.device}`,
      a.signing.privateKey,
    );
    return call<{ oneTimeKeyCount: number; fallbackKey: boolean }>("PUT", `/chat/devices/${a.device}`, { deviceKeys: keys, oneTimeKeys, fallbackKeys: fallback ?? {} });
  }

  /** Keeps about twenty-five one-time keys published, and a fallback key. */
  private async topUp(a: Account, count: number, hasFallback: boolean): Promise<void> {
    if (count >= 10 && hasFallback) return;
    const out: Record<string, unknown> = {};
    for (let i = count; i < 25; i++) {
      const k = await olm.x25519();
      const id = `K${(a.next++).toString(36).toUpperCase()}`;
      a.oneTimeKeys[olm.b64(k.publicKey)] = k;
      out[`signed_curve25519:${id}`] = await olm.signJson({ key: olm.b64(k.publicKey) }, this.me, `ed25519:${a.device}`, a.signing.privateKey);
    }
    let fallback: Record<string, unknown> | null = null;
    if (!hasFallback) {
      const k = await olm.x25519();
      a.fallback = [k, ...a.fallback].slice(0, 2);
      fallback = { [`signed_curve25519:F${(a.next++).toString(36).toUpperCase()}`]: await olm.signJson({ key: olm.b64(k.publicKey), fallback: true }, this.me, `ed25519:${a.device}`, a.signing.privateKey) };
    }
    await put(this.key("account", ""), a);
    await this.upload(a, out, fallback);
  }

  /** Members' devices with keys that are signed by themselves and, once
   * seen, never change (trust on first use). */
  private async devices(room: string): Promise<Device[]> {
    const r = await call<{ devices: { user: string; device: string; deviceKeys: Record<string, unknown> }[] }>("GET", `/chat/rooms/${enc(room)}/devices`);
    const out: Device[] = [];
    for (const d of r.devices) {
      const k = d.deviceKeys as { user_id?: string; device_id?: string; keys?: Record<string, string> };
      const curve = k.keys?.[`curve25519:${d.device}`];
      const ed = k.keys?.[`ed25519:${d.device}`];
      if (!curve || !ed || k.user_id !== d.user || k.device_id !== d.device) continue;
      if (!(await olm.verifyJson(d.deviceKeys, d.user, `ed25519:${d.device}`, olm.unb64(ed)))) continue;
      const seen = this.key("seen", `${d.user}|${d.device}`);
      const before = await get<string>(seen);
      if (before && before !== `${curve}|${ed}`) continue;
      if (!before) await put(seen, `${curve}|${ed}`);
      out.push({ user: d.user, device: d.device, curve, ed });
    }
    // A Curve25519 key belongs to one device: two naming it are both refused.
    return out.filter((d) => out.filter((o) => o.curve === d.curve).length === 1);
  }

  /** Room keys sent to this device: opened, checked and kept. */
  private async inbox(a: Account): Promise<void> {
    const r = await call<{
      messages: { id: string; sender: string; senderDevice: string; type?: string; content: { sender_key?: string; ciphertext?: Record<string, olm.OlmMessage> } & Record<string, unknown> }[];
      oneTimeKeyCount: number;
      fallbackKey: boolean;
    }>("GET", `/chat/devices/${a.device}/inbox`);
    const mine = olm.b64(a.identity.publicKey);
    const roomDevices = new Map<string, Device[] | null>();
    const done: string[] = [];
    const verifications: typeof r.messages = [];
    for (const m of r.messages) {
      let keep = true;
      if (m.type && m.type !== "m.room.encrypted") {
        if (m.type.startsWith("m.key.verification.")) verifications.push(m);
        done.push(m.id);
        continue;
      }
      try {
        const theirs = m.content.sender_key ?? "";
        const theirKey = olm.unb64(theirs);
        const message = m.content.ciphertext?.[mine];
        if (!message || theirKey.length !== 32) continue;
        const sessionsKey = this.key("olm", `${m.sender}|${m.senderDevice}`);
        const sessions = ((await get<olm.OlmSession[]>(sessionsKey)) ?? []).filter((s) => sameBytes(s.theirIdentity, theirKey));
        let plaintext: string | null = null;
        let used: olm.X25519 | null = null;
        // The newest few sessions only (each try costs work).
        for (const s of sessions.slice(0, 3)) {
          if (message.type === 0 && !olm.matchesPreKey(s, message.body)) continue;
          try {
            plaintext = await olm.olmDecrypt(s, message);
            break;
          } catch {
            // Another session.
          }
        }
        if (plaintext === null && message.type === 0) {
          const pre = olm.preKeyFields(message.body);
          // The session is the sender's own identity key's.
          if (!sameBytes(pre.identityKey, theirKey)) continue;
          const one = olm.b64(pre.oneTimeKey);
          const otk = a.oneTimeKeys[one] ?? a.fallback.find((f) => olm.b64(f.publicKey) === one);
          if (!otk) continue;
          const created = await olm.inboundSession(a.identity, otk, message.body);
          sessions.unshift(created.session);
          plaintext = created.plaintext;
          if (a.oneTimeKeys[one]) used = otk;
        }
        if (plaintext === null) continue;
        const p = JSON.parse(plaintext) as {
          type?: string;
          sender?: string;
          recipient?: string;
          keys?: { ed25519?: string };
          recipient_keys?: { ed25519?: string };
          content?: { algorithm?: string; room_id?: string; session_id?: string; session_key?: string; "org.ortus.room"?: string };
        };
        const c = p.content ?? {};
        const room = c["org.ortus.room"];
        // Meant for this device, from the device the server names, whose
        // published keys (checked by their signature) are the session's.
        if (p.type !== "m.room_key" || !room || p.recipient !== this.me || p.recipient_keys?.ed25519 !== olm.b64(a.signing.publicKey) || p.sender !== m.sender) continue;
        if (!roomDevices.has(room)) roomDevices.set(room, await this.devices(room).catch(() => null));
        const known = roomDevices.get(room);
        if (!known) {
          // The room's devices could not be read: kept for the next time.
          keep = false;
          continue;
        }
        const sender = known.find((d) => d.user === m.sender && d.device === m.senderDevice);
        if (!sender || sender.curve !== theirs || sender.ed !== p.keys?.ed25519) continue;
        // It holds: the one-time key goes, then the session is kept.
        if (used) {
          delete a.oneTimeKeys[olm.b64(used.publicKey)];
          await put(this.key("account", ""), a);
        }
        await put(sessionsKey, sessions.slice(0, 5));
        if (c.algorithm !== MEGOLM || !c.session_key || !c.session_id) continue;
        const inbound = await olm.megolmInbound(c.session_key);
        if (olm.sessionId(inbound.signingKey) !== c.session_id) continue;
        // A session is its sender's: stored under the sender's key, never
        // overwritten by another sender.
        const where = this.key("in", `${room}|${theirs}|${c.session_id}`);
        // One from the backup gives way to the sender's own, which confirms
        // it: its earlier start is kept when it runs on to this one.
        const had = await get<Inbound>(where);
        if (!had || had.fromBackup || (had.senderUser === m.sender && had.session.ratchet.index > inbound.ratchet.index)) {
          const session = had?.fromBackup && (await olm.leadsTo(had.session, inbound)) ? had.session : inbound;
          await put(where, { session, senderUser: m.sender, signing: p.keys?.ed25519 } satisfies Inbound);
          if (had?.fromBackup) {
            this.opened.clear();
            this.confirmed++;
          }
          if (c.room_id) await this.backUp([{ roomId: c.room_id, room, senderKey: theirs, sessionId: c.session_id, inbound: session, signingKey: p.keys?.ed25519 ?? "" }]).catch(() => undefined);
        }
      } catch {
        // A message this device cannot open: dropped.
      } finally {
        if (keep) done.push(m.id);
      }
    }
    if (done.length) await call("POST", `/chat/devices/${a.device}/inbox/done`, { ids: done });
    for (const m of verifications) await this.onVerificationMessage(a, m.type ?? "", m.sender, m.senderDevice, m.content).catch(() => undefined);
    await this.topUp(a, r.oneTimeKeyCount, r.fallbackKey);
  }

  /** Takes in room keys sent to this device, and gives this device's room
   * session to members' devices that lack it. */
  sync(room: string, roomId: string): Promise<void> {
    return this.run(async () => {
      const a = await this.account();
      await this.inbox(a);
      await this.share(a, room, roomId);
    });
  }

  private async share(a: Account, room: string, roomId: string): Promise<Outbound> {
    const devices = await this.devices(room);
    const users = new Set(devices.map((d) => d.user));
    const where = this.key("out", room);
    let out = await get<Outbound>(where);
    // A new session when someone left (they keep what was before), when
    // someone new came (they read from now on), and now and then.
    const sharedUsers = new Set(out?.sharedWith.map((k) => k.split("|")[0]!) ?? []);
    const left = [...sharedUsers].some((u) => !users.has(u));
    const came = !!out && out.count > 0 && [...users].some((u) => u !== this.me && !sharedUsers.has(u));
    // A device it went to is gone (signed out, or hidden): a new one, so
    // the warning does not keep naming it and it reads nothing new.
    const listed = new Set(devices.map((d) => `${d.user}|${d.device}`));
    const gone = Object.keys(out?.sentTo ?? {}).some((k) => !listed.has(k));
    if (!out || left || came || gone || out.count >= 100 || Date.now() - out.created > 7 * 86_400_000) {
      const session = await olm.megolmOutbound();
      const initialKey = await olm.sessionKey(session);
      out = { id: olm.sessionId(session.signing.publicKey), session, initialKey, sharedWith: [], created: Date.now(), count: 0 };
      const inbound = await olm.megolmInbound(initialKey);
      await put(this.key("in", `${room}|${olm.b64(a.identity.publicKey)}|${out.id}`), { session: inbound, senderUser: this.me, signing: olm.b64(a.signing.publicKey) } satisfies Inbound);
      await put(where, out);
      await this.backUp([{ roomId, room, senderKey: olm.b64(a.identity.publicKey), sessionId: out.id, inbound, signingKey: olm.b64(a.signing.publicKey) }]).catch(() => undefined);
    }
    const current = out;
    const targets = devices.filter((d) => !(d.user === this.me && d.device === a.device) && !current.sharedWith.includes(`${d.user}|${d.device}`));
    if (!targets.length) return current;
    // An Olm session to each device (to its identity key): kept from
    // before, or new from a one-time key of theirs.
    const sessions = new Map<string, olm.OlmSession[]>();
    for (const t of targets) {
      const list = (await get<olm.OlmSession[]>(this.key("olm", `${t.user}|${t.device}`))) ?? [];
      sessions.set(`${t.user}|${t.device}`, list.filter((s) => sameBytes(s.theirIdentity, olm.unb64(t.curve))));
    }
    const lacking = targets.filter((t) => !sessions.get(`${t.user}|${t.device}`)!.length);
    if (lacking.length) {
      const claimed = await call<{ oneTimeKeys: Record<string, Record<string, Record<string, Record<string, unknown>>>> }>("POST", `/chat/rooms/${enc(room)}/claim`, { devices: lacking.map((t) => ({ user: t.user, device: t.device })) });
      for (const t of lacking) {
        const keys = claimed.oneTimeKeys[t.user]?.[t.device];
        const one = keys && Object.values(keys)[0];
        if (!one || typeof one.key !== "string" || !(await olm.verifyJson(one, t.user, `ed25519:${t.device}`, olm.unb64(t.ed)))) continue;
        sessions.get(`${t.user}|${t.device}`)!.unshift(await olm.outboundSession(a.identity, olm.unb64(t.curve), olm.unb64(one.key)));
      }
    }
    const messages = [];
    const meant: string[] = [];
    for (const t of targets) {
      const s = sessions.get(`${t.user}|${t.device}`)![0];
      if (!s) continue;
      const payload = {
        type: "m.room_key",
        content: { algorithm: MEGOLM, room_id: roomId, session_id: current.id, session_key: current.initialKey, "org.ortus.room": room },
        sender: this.me,
        sender_device: a.device,
        keys: { ed25519: olm.b64(a.signing.publicKey) },
        recipient: t.user,
        recipient_keys: { ed25519: t.ed },
      };
      const sealed = await olm.olmEncrypt(s, JSON.stringify(payload));
      messages.push({ user: t.user, device: t.device, content: { algorithm: OLM, sender_key: olm.b64(a.identity.publicKey), ciphertext: { [t.curve]: sealed } } });
      meant.push(`${t.user}|${t.device}`);
      // Recorded before it leaves (whatever the server answers): the
      // room's warning covers every device the key went to.
      current.sentTo = { ...current.sentTo, [`${t.user}|${t.device}`]: `${t.curve}|${t.ed}` };
    }
    for (const [target, list] of sessions) await put(this.key("olm", target), list.slice(0, 5));
    if (messages.length) {
      await put(where, current);
      // Per room, apart from the session (a new one keeps it): what the
      // server answers never takes a device off; a week after its last
      // key it goes (a session is used for a week at most).
      const sentKey = this.key("sent", room);
      const sent = (await get<Record<string, Sent>>(sentKey)) ?? {};
      const now = Date.now();
      for (const k of meant) sent[k] = { keys: current.sentTo![k]!, at: now };
      for (const [k, x] of Object.entries(sent)) if (now - x.at > SENT_FOR) delete sent[k];
      await put(sentKey, sent);
      // Shared with a device only once the server has kept its message.
      const r = await call<{ stored: number[] }>("POST", `/chat/rooms/${enc(room)}/to-device`, { fromDevice: a.device, messages });
      current.sharedWith = [...current.sharedWith, ...r.stored.map((i) => meant[i]!).filter(Boolean)];
      await put(where, current);
    }
    return current;
  }

  /** Seals a message with this device's room session and sends it. */
  send(room: string, roomId: string, text: string, thread?: string): Promise<void> {
    return this.run(async () => {
      const a = await this.account();
      const out = await this.share(a, room, roomId);
      // The thread is inside the seal, so the server cannot move it.
      const content: Record<string, unknown> = { msgtype: "m.text", body: text };
      if (thread) content["m.relates_to"] = { rel_type: "m.thread", event_id: thread };
      const ciphertext = await olm.megolmEncrypt(out.session, JSON.stringify({ type: "m.room.message", content, room_id: roomId }));
      out.count++;
      await put(this.key("out", room), out);
      await call("POST", `/chat/rooms/${enc(room)}/sealed`, { algorithm: MEGOLM, sender_key: olm.b64(a.identity.publicKey), ciphertext, session_id: out.id, device_id: a.device, thread });
    });
  }

  /** A sealed message's text, or null when this device cannot open it or
   * it is not what it says (sender, room, thread, a replay); fromBackup when
   * only the backup vouches for its key (anyone can add to a backup). */
  open(room: string, roomId: string, s: Sealed, sender: string, event: string, thread: string | null): Promise<Opened | null> {
    const cacheKey = `${event}|${room}|${sender}|${s.sender_key}|${s.session_id}|${thread ?? ""}|${s.ciphertext}`;
    const cached = this.opened.get(cacheKey);
    if (cached !== undefined) return Promise.resolve(cached);
    return this.run(async () => {
      if (s.algorithm !== MEGOLM) return null;
      const rec = (await get<Inbound>(this.key("in", `${room}|${s.sender_key}|${s.session_id}`))) ?? (await this.restored(room, roomId, s, sender));
      // The session must be the sender's own device's.
      if (!rec || rec.senderUser !== sender) return null;
      try {
        const { plaintext, index } = await olm.megolmDecrypt(rec.session, s.ciphertext);
        const p = JSON.parse(plaintext) as { type?: string; room_id?: string; content?: { body?: unknown; "m.relates_to"?: { rel_type?: string; event_id?: string } } };
        if (p.type !== "m.room.message" || p.room_id !== roomId || typeof p.content?.body !== "string") return null;
        const rel = p.content["m.relates_to"];
        if ((rel?.rel_type === "m.thread" ? rel.event_id : null) !== (thread ?? null)) return null;
        // One message per index: the same ciphertext again is a replay.
        const seenKey = this.key("idx", `${room}|${s.sender_key}|${s.session_id}|${index}`);
        const seen = await get<string>(seenKey);
        if (seen && seen !== event) return null;
        if (!seen) await put(seenKey, event);
        const opened: Opened = { text: p.content.body, fromBackup: !!rec.fromBackup };
        // Not kept while from the backup: the sender's key may confirm it.
        if (!opened.fromBackup) this.opened.set(cacheKey, opened);
        return opened;
      } catch {
        return null;
      }
    });
  }


  // ---- trust: recovery, cross-signing, backup (docs/e2e-trust-and-backup.md)

  /** This browser's AES-GCM key for the trust seeds: made once, kept in
   * IndexedDB as a CryptoKey that cannot be read out. */
  private async wrapping(): Promise<CryptoKey> {
    const where = this.key("wrap", "");
    let k = await get<CryptoKey>(where);
    if (!k) {
      k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      await put(where, k);
    }
    return k;
  }

  private async saveTrust(t: Trust): Promise<void> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await this.wrapping(), new TextEncoder().encode(JSON.stringify(t)));
    await put(this.key("trust", ""), { iv, data } satisfies Wrapped);
  }

  /** The trust seeds, opened; one kept in the clear before is sealed now. */
  private async loadTrust(): Promise<Trust | undefined> {
    const v = await get<Trust | Wrapped>(this.key("trust", ""));
    if (!v) return undefined;
    if ("master" in v) {
      await this.saveTrust(v);
      return v;
    }
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(v.iv) }, await this.wrapping(), v.data);
    return JSON.parse(new TextDecoder().decode(plain)) as Trust;
  }

  private async trustKeys(): Promise<{ t: Trust; master: trust.SeedKey; selfSigning: trust.SeedKey; userSigning: trust.SeedKey; backup?: trust.SeedKey } | null> {
    const t = await this.loadTrust();
    if (!t) return null;
    return {
      t,
      master: await trust.ed25519FromSeed(olm.unb64(t.master)),
      selfSigning: await trust.ed25519FromSeed(olm.unb64(t.selfSigning)),
      userSigning: await trust.ed25519FromSeed(olm.unb64(t.userSigning)),
      backup: t.backup ? await trust.x25519FromSeed(olm.unb64(t.backup)) : undefined,
    };
  }

  /** Where recovery stands for this person and this browser. */
  recoveryState(): Promise<RecoveryState> {
    return this.run(async () => {
      const set = await call<{ key?: string }>("GET", "/chat/account-data/m.secret_storage.default_key").then((d) => !!d.key, () => false);
      const escrow = await call<{ key?: string }>("GET", "/chat/account-data/ortus.escrow").then((d) => !!d.key, () => false);
      return { set, here: !!(await get(this.key("trust", ""))), escrow };
    });
  }

  /** This device's keys (as published) signed by the self-signing key. */
  private async signThisDevice(a: Account, selfSigning: trust.SeedKey): Promise<void> {
    const deviceKeys = {
      user_id: this.me,
      device_id: a.device,
      algorithms: [OLM, MEGOLM],
      keys: { [`curve25519:${a.device}`]: olm.b64(a.identity.publicKey), [`ed25519:${a.device}`]: olm.b64(a.signing.publicKey) },
    };
    const signed = await trust.signDevice(this.me, deviceKeys, selfSigning);
    const r = await call<{ kept: number }>("POST", "/chat/signatures", { [this.me]: { [a.device]: signed } });
    if (r.kept !== 1) throw new Error("this device could not be signed");
  }

  /**
   * The organisation's escrow from the policy, checked: signed by its
   * signer's master key (as the server serves it to this person), for the
   * escrow and nothing else. Null when there is none; an error when there
   * is a key nobody (or no master key) signed.
   */
  private async escrow(): Promise<EscrowInfo | null> {
    const policy = await call<{ escrowKey?: string | null; escrow?: Record<string, unknown> | null; escrowUnsigned?: boolean }>("GET", "/chat/policy");
    if (!policy.escrow) {
      if (policy.escrowKey || policy.escrowUnsigned) throw new Error(ESCROW_UNSIGNED);
      return null;
    }
    const { signerMaster, ...escrow } = policy.escrow;
    const signer = escrow.user_id;
    const key = escrow.public_key;
    const fields = Object.keys(escrow).sort().join(",");
    const usage = escrow.usage;
    const shaped =
      typeof signer === "string" &&
      typeof key === "string" &&
      fields === "public_key,signatures,usage,user_id" &&
      Array.isArray(usage) &&
      usage.length === 1 &&
      usage[0] === "ortus.escrow" &&
      /^[A-Za-z0-9+/]{43}$/.test(key);
    const master = shaped ? crossKey(signerMaster, signer, "master") : null;
    if (!shaped || !master || !(await olm.verifyJson(escrow, signer, master[0], master[1]))) throw new Error(ESCROW_UNSIGNED);
    const mine = await this.trustKeys().catch(() => null);
    let signerStatus: EscrowInfo["signerStatus"] = "unverified";
    if (mine && signer === this.me && sameBytes(master[1], mine.master.publicKey)) signerStatus = "you";
    else if (mine && signer !== this.me && (await olm.verifyJson(signerMaster as Record<string, unknown>, this.me, trust.keyId(mine.userSigning), mine.userSigning.publicKey))) signerStatus = "verified";
    const pinned = await get<string>(this.key("escrow", ""));
    return { key, fingerprint: escrowFingerprint(key), signer, signerStatus, changed: pinned !== undefined && pinned !== key };
  }

  /** The organisation's escrow key, to show before set-up; null when there is none. Throws when it is not signed. */
  escrowInfo(): Promise<EscrowInfo | null> {
    return this.run(() => this.escrow());
  }

  /** Whether this browser holds the person's master key (recovery set up or entered here). */
  async hasMasterKey(): Promise<boolean> {
    return !!(await this.loadTrust().catch(() => undefined));
  }

  /** An object signed with this person's master key (the escrow an administrator makes). */
  signWithMaster(value: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.run(async () => {
      const mine = await this.trustKeys();
      if (!mine) throw new Error("This browser does not hold your master key: set up recovery here first.");
      return trust.signObject(this.me, value, mine.master);
    });
  }

  /**
   * Sets recovery up for the person (on their first device): cross-signing
   * keys, this device signed, a backup signed by the master key, the
   * secrets in secret storage under a new recovery key, and its escrow copy
   * when the organisation has an escrow key. With an escrow, set-up goes on
   * only for the key the person was shown (`acceptedEscrowKey`), and never
   * for one no administrator signed. Answers the recovery key, to show once.
   */
  setUpRecovery(acceptedEscrowKey?: string): Promise<string> {
    return this.run(async () => {
      // The escrow first: refused before anything is made.
      const escrow = await this.escrow();
      if (escrow && escrow.key !== acceptedEscrowKey) throw new Error(ESCROW_NOT_ACCEPTED);
      const a = await this.account();
      const recovery = trust.newRecoveryKey();
      const cross = await trust.newCrossSigning();
      await call("PUT", "/chat/cross-signing", await trust.crossSigningUpload(this.me, cross));
      await this.signThisDevice(a, cross.selfSigning);
      const backup = await trust.x25519FromSeed(crypto.getRandomValues(new Uint8Array(32)));
      const authData = await trust.signObject(this.me, { public_key: olm.b64(backup.publicKey) }, cross.master);
      const { version } = await call<{ version: string }>("POST", "/chat/backup/version", { algorithm: BACKUP, authData });
      const keyId = olm.b64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^A-Za-z0-9]/g, "");
      await call("PUT", `/chat/account-data/m.secret_storage.key.${keyId}`, await trust.keyDescription(recovery));
      const seeds = { master: cross.master.seed, selfSigning: cross.selfSigning.seed, userSigning: cross.userSigning.seed, backup: backup.seed };
      for (const [k, name] of Object.entries(SECRETS)) {
        const secret = await trust.encryptSecret(recovery, name, olm.b64(seeds[k as keyof typeof seeds]));
        await call("PUT", `/chat/account-data/${name}`, { encrypted: { [keyId]: secret } });
      }
      const text = trust.encodeRecoveryKey(recovery);
      if (escrow) {
        await call("PUT", "/chat/account-data/ortus.escrow", { key: escrow.key, sealed: await trust.seal(olm.unb64(escrow.key), text) });
      }
      // The default key last: a set-up cut half-way is not taken for one that finished.
      await call("PUT", "/chat/account-data/m.secret_storage.default_key", { key: keyId });
      await this.saveTrust({ master: olm.b64(cross.master.seed), selfSigning: olm.b64(cross.selfSigning.seed), userSigning: olm.b64(cross.userSigning.seed), backup: olm.b64(backup.seed), version } satisfies Trust);
      // The escrow key accepted here: a different one later is said to have changed.
      if (escrow) await put(this.key("escrow", ""), escrow.key);
      await this.backUpAll();
      return text;
    });
  }

  /**
   * Recovery on this browser with the recovery key: the secrets open, this
   * device is signed, and the backup (only one the master key signed) is
   * restored. Answers how many room keys came back; null when the key is
   * not the person's.
   */
  recover(text: string): Promise<number | null> {
    return this.run(async () => {
      const a = await this.account();
      const recovery = trust.decodeRecoveryKey(text);
      if (!recovery) return null;
      const { key: keyId } = await call<{ key: string }>("GET", "/chat/account-data/m.secret_storage.default_key");
      const description = await call<{ iv: string; mac: string }>("GET", `/chat/account-data/m.secret_storage.key.${keyId}`);
      if (!(await trust.keyMatches(recovery, description))) return null;
      const seeds: Record<string, string> = {};
      for (const [k, name] of Object.entries(SECRETS)) {
        const stored = await call<{ encrypted: Record<string, trust.StoredSecret> }>("GET", `/chat/account-data/${name}`).catch(() => null);
        const secret = stored?.encrypted?.[keyId];
        const opened = secret ? await trust.decryptSecret(recovery, name, secret) : null;
        if (opened) seeds[k] = opened;
      }
      if (!seeds.master || !seeds.selfSigning || !seeds.userSigning) return null;
      const master = await trust.ed25519FromSeed(olm.unb64(seeds.master));
      await this.signThisDevice(a, await trust.ed25519FromSeed(olm.unb64(seeds.selfSigning)));
      const t: Trust = { master: seeds.master, selfSigning: seeds.selfSigning, userSigning: seeds.userSigning };
      let restored = 0;
      const current = await call<{ version: string; algorithm: string; authData: Record<string, unknown> }>("GET", "/chat/backup/version").catch(() => null);
      // A backup is used only when the master key signed its key: a backup
      // the server swapped gets nothing, and gives nothing back.
      if (seeds.backup && current && current.algorithm === BACKUP && (await olm.verifyJson(current.authData, this.me, trust.keyId(master), master.publicKey))) {
        const backup = await trust.x25519FromSeed(olm.unb64(seeds.backup));
        if (current.authData.public_key === olm.b64(backup.publicKey)) {
          t.backup = seeds.backup;
          t.version = current.version;
          const keys = await call<{ rooms: Record<string, { sessions: Record<string, { session_data: trust.Sealed }> }> }>("GET", `/chat/backup/keys?version=${encodeURIComponent(current.version)}`);
          for (const [roomId, r] of Object.entries(keys.rooms)) {
            for (const [sessionId, k] of Object.entries(r.sessions)) {
              const plain = await trust.unseal(backup, k.session_data);
              if (!plain) continue;
              const exported = JSON.parse(plain) as { sender_key?: string; session_key?: string };
              if (!exported.sender_key || !exported.session_key || !matchesId(exported.session_key, sessionId)) continue;
              await put(this.key("bk", `${roomId}|${exported.sender_key}|${sessionId}`), exported.session_key);
              restored++;
            }
          }
        }
      }
      await this.saveTrust(t);
      return restored;
    });
  }

  /** A session from the backup, taken once its id is its own signing key and
   * its sender key is the sender's device in the room. Anyone with the
   * backup's public key can add to it, so it stays marked as from the backup. */
  private async restored(room: string, roomId: string, s: Sealed, sender: string): Promise<Inbound | undefined> {
    const exported = await get<string>(this.key("bk", `${roomId}|${s.sender_key}|${s.session_id}`));
    if (!exported || !matchesId(exported, s.session_id)) return undefined;
    const devices = await this.devices(room).catch(() => []);
    if (!devices.some((d) => d.user === sender && d.curve === s.sender_key)) return undefined;
    const rec: Inbound = { session: olm.importSessionKey(exported), senderUser: sender, fromBackup: true };
    await put(this.key("in", `${room}|${s.sender_key}|${s.session_id}`), rec);
    return rec;
  }

  /** Room keys into the backup, when this browser has its key and the master key signed it. */
  private async backUp(sessions: { roomId: string; room: string; senderKey: string; sessionId: string; inbound: olm.MegolmInbound; signingKey: string }[]): Promise<void> {
    const keys = await this.trustKeys();
    if (!keys?.backup || !keys.t.version || !sessions.length) return;
    const rooms: Record<string, { sessions: Record<string, unknown> }> = {};
    for (const x of sessions) {
      const data = await trust.backupRoomKey(
        keys.backup.publicKey,
        { roomId: x.roomId, sessionId: x.sessionId, senderKey: x.senderKey, sessionKey: olm.exportSessionKey(x.inbound), firstIndex: x.inbound.ratchet.index, signingKey: x.signingKey },
        false,
      );
      (rooms[x.roomId] ??= { sessions: {} }).sessions[x.sessionId] = data;
    }
    await call("PUT", `/chat/backup/keys?version=${encodeURIComponent(keys.t.version)}`, { rooms });
  }

  /** Every room key this browser holds, into the backup (after setting it up). */
  private async backUpAll(): Promise<void> {
    const all = await entries<Inbound>(this.key("in", ""));
    const a = await this.account();
    const out: Parameters<Sealer["backUp"]>[0] = [];
    for (const [k, rec] of all) {
      const [room, senderKey, sessionId] = k.slice(this.key("in", "").length).split("|");
      if (!room || !senderKey || !sessionId) continue;
      const info = await call<{ room?: { roomId?: string }; roomId?: string }>("GET", `/chat/rooms/${enc(room)}`).catch(() => null);
      const roomId = info?.room?.roomId ?? info?.roomId;
      if (!roomId) continue;
      out.push({ roomId, room, senderKey, sessionId, inbound: rec.session, signingKey: rec.signing ?? (senderKey === olm.b64(a.identity.publicKey) ? olm.b64(a.signing.publicKey) : "") });
    }
    for (let i = 0; i < out.length; i += 200) await this.backUp(out.slice(i, i + 200));
  }

  /**
   * Who in a room is not vouched for: devices their owner did not sign with
   * a self-signing key their master key signed (and, for others, a master
   * key this person did not verify). Every device this browser gave a room
   * key to this past week counts too: one missing from this answer, or with
   * other keys in it, is not vouched for (the server cannot share with a
   * device it hides from the warning). Rooms warn about them; messages
   * still go to them (the owner's decision). Fails when the room's devices
   * cannot be read (the screen says it could not check).
   */
  unverified(room: string): Promise<{ user: string; device: string }[]> {
    return this.run(async () => {
      const r = await call<{ devices: { user: string; device: string; deviceKeys: Record<string, unknown> }[]; crossSigning?: Record<string, { master?: Record<string, unknown>; selfSigning?: Record<string, unknown> }> }>("GET", `/chat/rooms/${enc(room)}/devices`);
      const cross = r.crossSigning ?? {};
      const mine = await this.trustKeys();
      const out: { user: string; device: string }[] = [];
      const flagged = new Set<string>();
      const flag = (user: string, device: string): void => {
        if (flagged.has(`${user}|${device}`)) return;
        flagged.add(`${user}|${device}`);
        out.push({ user, device });
      };
      // Every device given a room key here this past week; from before
      // that was recorded, the current session's (without their keys).
      const session = await get<Outbound>(this.key("out", room));
      const sent: Record<string, string> = Object.fromEntries((session?.sharedWith ?? []).map((k) => [k, ""]));
      const now = Date.now();
      for (const [k, x] of Object.entries((await get<Record<string, Sent>>(this.key("sent", room))) ?? {})) if (now - x.at <= SENT_FOR) sent[k] = x.keys;
      const listed = new Set<string>();
      for (const d of r.devices) {
        listed.add(`${d.user}|${d.device}`);
        let ok = false;
        try {
          ok = await this.vouched(d, cross[d.user], mine, sent[`${d.user}|${d.device}`]);
        } catch {
          // Keys that cannot be read are not vouched for.
        }
        if (!ok) flag(d.user, d.device);
      }
      for (const k of Object.keys(sent)) {
        if (listed.has(k)) continue;
        const at = k.lastIndexOf("|");
        flag(k.slice(0, at), k.slice(at + 1));
      }
      return out;
    });
  }

  /** One device of a room's answer: its own keys (as given the room key, when
   * it was), signed by a self-signing key its owner's master key signed, the
   * master key one's own or one this person verified. */
  private async vouched(
    d: { user: string; device: string; deviceKeys: Record<string, unknown> },
    keys: { master?: Record<string, unknown>; selfSigning?: Record<string, unknown> } | undefined,
    mine: Awaited<ReturnType<Sealer["trustKeys"]>>,
    sentKeys: string | undefined,
  ): Promise<boolean> {
    const ed = await selfSigned(d.deviceKeys, d.user, d.device);
    if (!ed) return false;
    const curve = (d.deviceKeys.keys as Record<string, string> | undefined)?.[`curve25519:${d.device}`];
    if (sentKeys && sentKeys !== `${curve}|${ed}`) return false;
    const master = crossKey(keys?.master, d.user, "master");
    const ssk = crossKey(keys?.selfSigning, d.user, "self_signing");
    if (!mine || !master || !ssk || !keys?.master || !keys.selfSigning) return false;
    if (!(await olm.verifyJson(keys.selfSigning, d.user, master[0], master[1]))) return false;
    if (!(await olm.verifyJson(d.deviceKeys, d.user, ssk[0], ssk[1]))) return false;
    if (d.user === this.me) return sameBytes(master[1], mine.master.publicKey);
    return olm.verifyJson(keys.master, this.me, trust.keyId(mine.userSigning), mine.userSigning.publicKey);
  }


  // ---- verification by emoji (verify.ts) ------------------------------------

  private verifications = new Map<string, Verification>();
  /** Told whenever a verification changes (the screen shows it). */
  onVerification?: (v: VerificationView) => void;
  /** This browser can scan the other device's code (it has a camera API; the screen asks for the camera). */
  camera = typeof navigator !== "undefined" && typeof navigator.mediaDevices?.getUserMedia === "function";

  private methods(): string[] {
    return this.camera ? [sas.SAS, QR_SHOW, QR_SCAN, RECIPROCATE] : [sas.SAS, QR_SHOW, RECIPROCATE];
  }

  private changed(v: Verification): void {
    this.onVerification?.({ ...v.view, emoji: v.view.emoji ? [...v.view.emoji] : undefined });
  }

  private async sendVerification(a: Account, user: string, device: string, type: string, content: Record<string, unknown>): Promise<void> {
    await call("POST", "/chat/verification", { user, device, fromDevice: a.device, type, content });
  }

  /** Looks for verification messages (and room keys) for this device. */
  pollVerifications(): Promise<void> {
    return this.run(async () => {
      const a = await this.account();
      await this.inbox(a);
    });
  }

  /** Starts verifying someone (oneself: one's other devices). Answers its id. */
  verify(user: string): Promise<string> {
    return this.run(async () => {
      const a = await this.account();
      const id = sas.transactionId();
      const v: Verification = { view: { id, user, state: "requested" }, started: true };
      this.verifications.set(id, v);
      await this.sendVerification(a, user, "*", "m.key.verification.request", { from_device: a.device, methods: this.methods(), transaction_id: id, timestamp: Date.now() });
      this.changed(v);
      return id;
    });
  }

  /** Says yes to someone's request. */
  acceptVerification(id: string): Promise<void> {
    return this.run(async () => {
      const v = this.verifications.get(id);
      if (!v || v.view.state !== "incoming" || !v.view.device) return;
      const a = await this.account();
      v.view.state = "waiting";
      await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.ready", { from_device: a.device, methods: this.methods(), transaction_id: id });
      v.view.canScan = this.camera && !!v.theirMethods?.includes(QR_SHOW);
      // Their camera can read a code: show one (emoji stay a choice); they
      // show one: scan it, or emoji; else they start the emoji.
      if (v.theirMethods?.includes(QR_SCAN)) await this.showCode(a, v);
      else if (v.view.canScan) v.view.state = "ready";
      this.changed(v);
    });
  }

  /** Emoji, chosen over the codes. */
  startEmoji(id: string): Promise<void> {
    return this.run(async () => {
      const v = this.verifications.get(id);
      if (!v || (v.view.state !== "qr" && v.view.state !== "ready") || !v.view.device) return;
      await this.startSas(await this.account(), v);
      this.changed(v);
    });
  }

  private async startSas(a: Account, v: Verification): Promise<void> {
    if (!v.view.device) return;
    v.view.state = "waiting";
    v.view.qr = undefined;
    v.code = undefined;
    v.sasStarted = true;
    v.start = { from_device: a.device, method: sas.SAS, key_agreement_protocols: [sas.KEY_AGREEMENT], hashes: [sas.HASH], message_authentication_codes: [sas.MAC], short_authentication_string: ["emoji", "decimal"], transaction_id: v.view.id };
    await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.start", v.start);
  }

  /**
   * The QR code for the other device's camera (Matrix's format: MATRIX, 2,
   * the mode, the transaction, two keys, a secret). Another person: our
   * master key and theirs. One's own other device: our master key and that
   * device's key when this browser holds the keys; else this device's key
   * and the master key. What will be signed is fixed here, with the keys
   * the code shows. Without the keys a code needs, emoji are used.
   */
  private async showCode(a: Account, v: Verification): Promise<void> {
    const device = v.view.device;
    if (!device) return;
    const mine = await this.trustKeys();
    const keys = await call<{ devices?: { device: string; deviceKeys: Record<string, unknown> }[]; crossSigning?: Record<string, { master?: Record<string, unknown> }> }>("GET", `/chat/keys?user=${enc(v.view.user)}`);
    // A master key only in Matrix's shape (the person's, for that use).
    const masterOf = (user: string): [string, string] | null => {
      try {
        const k = crossKey(keys.crossSigning?.[user]?.master, user, "master");
        return k ? [k[0], olm.b64(k[1])] : null;
      } catch {
        return null;
      }
    };
    const plain = (o: Record<string, unknown>) => {
      const c = { ...o };
      delete c.signatures;
      delete c.unsigned;
      return c;
    };
    let mode: number;
    let first: string;
    let second: string;
    let sign: ShownCode["sign"];
    if (v.view.user !== this.me) {
      const master = keys.crossSigning?.[v.view.user]?.master;
      const theirs = masterOf(v.view.user);
      if (!mine || !master || !theirs) return this.emojiInstead(a, v);
      mode = 0;
      first = olm.b64(mine.master.publicKey);
      second = theirs[1];
      sign = { kind: "master", keyId: theirs[0], key: theirs[1], object: plain(master) };
    } else {
      const d = keys.devices?.find((x) => x.device === device);
      // Only keys the device signed itself are shown, and signed later.
      const ed = d ? await selfSigned(d.deviceKeys, this.me, device).catch(() => null) : null;
      if (mine && d && ed) {
        mode = 1;
        first = olm.b64(mine.master.publicKey);
        second = ed;
        sign = { kind: "device", object: plain(d.deviceKeys) };
      } else {
        const master = masterOf(this.me);
        if (!master) return this.emojiInstead(a, v);
        mode = 2;
        first = olm.b64(a.signing.publicKey);
        second = master[1];
        sign = { kind: "none" };
      }
    }
    const secret = crypto.getRandomValues(new Uint8Array(16));
    const id = new TextEncoder().encode(v.view.id);
    const bytes = sas.concat(
      new TextEncoder().encode("MATRIX"),
      new Uint8Array([0x02, mode, id.length >> 8, id.length & 0xff]),
      id,
      olm.unb64(first),
      olm.unb64(second),
      secret,
    );
    v.code = { secret: olm.b64(secret), sign };
    v.view.qr = qrCode(bytes);
    v.view.state = "qr";
  }

  /** No code possible here (this browser lacks the keys one needs): theirs
   * to scan, if they show one; else emoji, started here. */
  private async emojiInstead(a: Account, v: Verification): Promise<void> {
    if (v.view.canScan) v.view.state = "ready";
    else await this.startSas(a, v);
  }

  /**
   * The other device's code, scanned here (its bytes, from qrscan.ts).
   * False when it is not a code for this verification (scanning goes on).
   * Its keys are checked as matrix-sdk-crypto checks them: mode 0 (another
   * person) their master key, then ours; mode 1 (one's own device that
   * trusts the master key) our master key, then this device's key; mode 2
   * (one's own device that does not) that device's key, then our master
   * key. A mismatch stops the verification. Then the secret goes back
   * (m.reciprocate.v1), and what the code proved (their master key, or
   * their device in mode 2; nothing new in mode 1, where the other device
   * vouches for this one) is signed when they say done.
   */
  scanCode(id: string, bytes: Uint8Array): Promise<boolean> {
    return this.run(async () => {
      const v = this.verifications.get(id);
      const code = parseCode(bytes);
      if (!v || !code || code.id !== id || !v.view.device || !v.view.canScan || (v.view.state !== "qr" && v.view.state !== "ready")) return false;
      const a = await this.account();
      const device = v.view.device;
      const other = v.view.user;
      const own = other === this.me;
      if (own === (code.mode === 0)) return this.cancel(a, v, "m.key_mismatch", CODE_MISMATCH).then(() => true);
      const mine = await this.trustKeys();
      type Keys = { devices?: { device: string; deviceKeys: Record<string, unknown> }[]; crossSigning?: Record<string, { master?: Record<string, unknown> }> };
      const theirs = await call<Keys>("GET", `/chat/keys?user=${enc(other)}`);
      const masterOf = (keys: Keys, user: string): [string, Uint8Array, Record<string, unknown>] | null => {
        try {
          const o = keys.crossSigning?.[user]?.master;
          const k = crossKey(o, user, "master");
          return k && o ? [k[0], k[1], o] : null;
        } catch {
          return null;
        }
      };
      // Our master key: the one this browser holds, else the server's.
      const ourMaster = mine?.master.publicKey ?? (own ? masterOf(theirs, this.me) : masterOf(await call<Keys>("GET", `/chat/keys?user=${enc(this.me)}`), this.me))?.[1];
      const theirMaster = masterOf(theirs, other);
      const plain = (o: Record<string, unknown>) => {
        const c = { ...o };
        delete c.signatures;
        delete c.unsigned;
        return c;
      };
      let sign: ShownCode["sign"] | null = null;
      if (code.mode === 0) {
        if (theirMaster && ourMaster && sameBytes(code.first, theirMaster[1]) && sameBytes(code.second, ourMaster))
          sign = { kind: "master", keyId: theirMaster[0], key: olm.b64(theirMaster[1]), object: plain(theirMaster[2]) };
      } else if (code.mode === 1) {
        if (ourMaster && sameBytes(code.first, ourMaster) && sameBytes(code.second, a.signing.publicKey)) sign = { kind: "none" };
      } else {
        // Only a key the device signed itself is taken as its key.
        const d = theirs.devices?.find((x) => x.device === device);
        const ed = d ? await selfSigned(d.deviceKeys, this.me, device).catch(() => null) : null;
        if (d && ed && ourMaster && sameBytes(code.first, olm.unb64(ed)) && sameBytes(code.second, ourMaster)) sign = { kind: "device", object: plain(d.deviceKeys) };
      }
      if (!sign) {
        await this.cancel(a, v, "m.key_mismatch", CODE_MISMATCH);
        return true;
      }
      await this.sendVerification(a, other, device, "m.key.verification.start", { from_device: a.device, method: RECIPROCATE, secret: olm.b64(code.secret), transaction_id: id });
      // Our own code is no longer the one in play.
      v.code = undefined;
      v.view.qr = undefined;
      v.scanned = sign;
      v.view.scannedTheirs = true;
      v.view.state = "waiting";
      this.changed(v);
      return true;
    });
  }

  /** What a code proved, signed with this browser's keys: how many signatures the server kept. */
  private async signProved(sign: ShownCode["sign"], user: string, device: string): Promise<number> {
    const mine = await this.trustKeys();
    if (mine && sign.kind === "device") {
      return (await call<{ kept: number }>("POST", "/chat/signatures", { [this.me]: { [device]: await trust.signDevice(this.me, sign.object, mine.selfSigning) } })).kept;
    }
    if (mine && sign.kind === "master") {
      return (await call<{ kept: number }>("POST", "/chat/signatures", { [user]: { [sign.key]: await trust.signUser(this.me, sign.object, mine.userSigning) } })).kept;
    }
    return 0;
  }

  /** The other device scanned the code and says so on its screen: whether it does. */
  confirmScanned(id: string, yes: boolean): Promise<void> {
    return this.run(async () => {
      const v = this.verifications.get(id);
      if (!v || v.view.state !== "scanned" || !v.code || !v.view.device) return;
      const a = await this.account();
      if (!yes) return this.cancel(a, v, "m.key_mismatch", "The other device did not confirm the code.");
      const kept = await this.signProved(v.code.sign, v.view.user, v.view.device);
      // The other side may still vouch for this device: it hears done.
      await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.done", { transaction_id: id });
      v.view.state = kept > 0 ? "done" : "unsigned";
      v.code = undefined;
      this.changed(v);
    });
  }

  /** The person says whether the emoji are the same on both screens. */
  confirmEmoji(id: string, same: boolean): Promise<void> {
    return this.run(async () => {
      const v = this.verifications.get(id);
      if (!v || v.view.state !== "emoji" || !v.secret || !v.view.device) return;
      const a = await this.account();
      if (!same) return this.cancel(a, v, "m.mismatched_sas", "The emoji were not the same.");
      v.confirmed = true;
      const keys: Record<string, string> = { [`ed25519:${a.device}`]: olm.b64(a.signing.publicKey) };
      const mine = await this.trustKeys();
      if (mine) keys[trust.keyId(mine.master)] = olm.b64(mine.master.publicKey);
      const content = await sas.macContent(v.secret, { user: this.me, device: a.device }, { user: v.view.user, device: v.view.device }, id, keys);
      await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.mac", { transaction_id: id, ...content });
      v.macSent = true;
      v.view.state = "waiting";
      this.changed(v);
      await this.finish(a, v);
    });
  }

  cancelVerification(id: string): Promise<void> {
    return this.run(async () => {
      const v = this.verifications.get(id);
      if (v && v.view.state !== "done" && v.view.state !== "unsigned" && v.view.state !== "cancelled") await this.cancel(await this.account(), v, "m.user", "Cancelled.");
    });
  }

  private async cancel(a: Account, v: Verification, code: string, reason: string): Promise<void> {
    v.view.state = "cancelled";
    v.view.reason = reason;
    if (v.view.device) await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.cancel", { transaction_id: v.view.id, code, reason }).catch(() => undefined);
    this.changed(v);
  }

  private async onVerificationMessage(a: Account, type: string, sender: string, senderDevice: string, c: Record<string, unknown>): Promise<void> {
    const id = typeof c.transaction_id === "string" ? c.transaction_id : "";
    if (!id) return;
    let v = this.verifications.get(id);
    if (type === "m.key.verification.request") {
      if (v || !(c.methods as string[] | undefined)?.includes(sas.SAS)) return;
      v = { view: { id, user: sender, device: senderDevice, state: "incoming" }, started: false, theirMethods: (c.methods as string[] | undefined) ?? [] };
      this.verifications.set(id, v);
      return this.changed(v);
    }
    // Every later message is the other side's, from the device it began with.
    if (!v || v.view.user !== sender || (v.view.device && v.view.device !== senderDevice)) return;
    if (type === "m.key.verification.cancel") {
      v.view.state = "cancelled";
      v.view.reason = typeof c.reason === "string" ? c.reason : "";
      return this.changed(v);
    }
    if (type === "m.key.verification.ready" && v.started && v.view.state === "requested") {
      v.view.device = senderDevice;
      v.view.state = "waiting";
      v.theirMethods = (c.methods as string[] | undefined) ?? [];
      v.view.canScan = this.camera && v.theirMethods.includes(QR_SHOW);
      // Their camera can read a code: show one, emoji stay a choice; they
      // show one: scan it, or emoji; else emoji now.
      if (v.theirMethods.includes(QR_SCAN)) await this.showCode(a, v);
      else if (v.view.canScan) v.view.state = "ready";
      else await this.startSas(a, v);
      return this.changed(v);
    }
    if (type === "m.key.verification.start" && c.method === RECIPROCATE) {
      // They scanned our code: the secret it held must come back.
      if (v.view.state !== "qr" || !v.code) return;
      const got = typeof c.secret === "string" ? c.secret.replace(/=+$/, "") : "";
      if (got !== v.code.secret.replace(/=+$/, "")) return this.cancel(a, v, "m.key_mismatch", "The scanned code was not this one.");
      v.view.state = "scanned";
      v.view.qr = undefined;
      return this.changed(v);
    }
    if (type === "m.key.verification.start" && !v.sasStarted && !v.scanned && (v.view.state === "waiting" || v.view.state === "qr" || v.view.state === "ready")) {
      v.view.state = "waiting";
      v.view.qr = undefined;
      v.code = undefined;
      if (c.method !== sas.SAS || !(c.key_agreement_protocols as string[] | undefined)?.includes(sas.KEY_AGREEMENT) || !(c.message_authentication_codes as string[] | undefined)?.includes(sas.MAC)) return this.cancel(a, v, "m.unknown_method", "Not a way this device verifies.");
      v.start = c;
      v.ours = await sas.ephemeral();
      const accept = { transaction_id: id, method: sas.SAS, key_agreement_protocol: sas.KEY_AGREEMENT, hash: sas.HASH, message_authentication_code: sas.MAC, short_authentication_string: ["emoji", "decimal"], commitment: await sas.commitment(v.ours.publicKey, c) };
      await this.sendVerification(a, sender, senderDevice, "m.key.verification.accept", accept);
      return;
    }
    if (type === "m.key.verification.accept" && v.sasStarted && typeof c.commitment === "string") {
      v.commitment = c.commitment;
      v.ours = await sas.ephemeral();
      await this.sendVerification(a, sender, senderDevice, "m.key.verification.key", { transaction_id: id, key: v.ours.publicKey });
      return;
    }
    if (type === "m.key.verification.key" && typeof c.key === "string" && v.ours && !v.theirKey) {
      v.theirKey = c.key;
      if (v.sasStarted) {
        // The other side committed to its key before it saw ours.
        if (!v.start || v.commitment !== (await sas.commitment(c.key, v.start))) return this.cancel(a, v, "m.mismatched_commitment", "The keys did not match what was promised.");
      } else {
        await this.sendVerification(a, sender, senderDevice, "m.key.verification.key", { transaction_id: id, key: v.ours.publicKey });
      }
      v.secret = await sas.shared(v.ours, c.key);
      const me = { user: this.me, device: a.device, key: v.ours.publicKey };
      const them = { user: sender, device: senderDevice, key: c.key };
      v.view.emoji = await sas.emoji(v.secret, v.sasStarted ? me : them, v.sasStarted ? them : me, id);
      v.view.state = "emoji";
      return this.changed(v);
    }
    if (type === "m.key.verification.mac" && v.secret) {
      v.theirMac = c as Verification["theirMac"];
      return this.finish(a, v);
    }
    if (type === "m.key.verification.done" && v.scanned && v.view.state === "waiting") {
      // They confirmed we scanned their code: sign what it proved, say done.
      const kept = await this.signProved(v.scanned, v.view.user, senderDevice);
      v.scanned = undefined;
      await this.sendVerification(a, sender, senderDevice, "m.key.verification.done", { transaction_id: id });
      v.view.state = kept > 0 ? "done" : "unsigned";
      return this.changed(v);
    }
  }

  /** Both sides vouched: check theirs, sign what was verified, say done. */
  private async finish(a: Account, v: Verification): Promise<void> {
    if (!v.secret || !v.theirMac || !v.confirmed || !v.macSent || !v.view.device || v.view.state === "done" || v.view.state === "unsigned") return;
    const keys = await call<{ devices?: { device: string; deviceKeys: Record<string, unknown> }[]; crossSigning?: Record<string, { master?: Record<string, unknown> }> }>("GET", `/chat/keys?user=${enc(v.view.user)}`);
    const device = keys.devices?.find((d) => d.device === v.view.device);
    const known: Record<string, string> = {};
    // The device's key only from keys it signed itself; the master key only
    // in Matrix's shape. What is signed below is these same objects.
    const ed = device ? await selfSigned(device.deviceKeys, v.view.user, v.view.device).catch(() => null) : null;
    if (ed) known[`ed25519:${v.view.device}`] = ed;
    const master = keys.crossSigning?.[v.view.user]?.master;
    let masterKey: [string, string] | null = null;
    try {
      const k = crossKey(master, v.view.user, "master");
      if (k) masterKey = [k[0], olm.b64(k[1])];
    } catch {
      // Not a master key.
    }
    if (masterKey) known[masterKey[0]] = masterKey[1];
    const vouched = await sas.checkMac(v.secret, { user: this.me, device: a.device }, { user: v.view.user, device: v.view.device }, v.view.id, v.theirMac, known);
    if (!vouched || !vouched.includes(`ed25519:${v.view.device}`)) return this.cancel(a, v, "m.key_mismatch", "The keys are not the ones the server has.");
    v.vouched = vouched;
    const mine = await this.trustKeys();
    let kept = 0;
    if (mine && device && ed) {
      if (v.view.user === this.me) {
        // One's own device: signed with one's self-signing key.
        const plain = { ...device.deviceKeys };
        delete plain.signatures;
        delete plain.unsigned;
        kept = (await call<{ kept: number }>("POST", "/chat/signatures", { [this.me]: { [v.view.device]: await trust.signDevice(this.me, plain, mine.selfSigning) } })).kept;
      } else if (master && masterKey && vouched.includes(masterKey[0])) {
        // Someone else: their master key, with one's user-signing key.
        const plain = { ...master };
        delete plain.signatures;
        delete plain.unsigned;
        kept = (await call<{ kept: number }>("POST", "/chat/signatures", { [v.view.user]: { [masterKey[1]]: await trust.signUser(this.me, plain, mine.userSigning) } })).kept;
      }
    }
    // Done for the other side either way (our keys matched: it may vouch
    // for this device); here, done only when something was vouched for.
    await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.done", { transaction_id: v.view.id });
    v.view.state = kept > 0 ? "done" : "unsigned";
    this.changed(v);
  }

  /** Rooms this browser has seen end-to-end encrypted: never sent to in
   * the clear afterwards, whatever the server says. */
  pin(room: string): Promise<void> {
    return this.run(async () => {
      const key = this.key("pinned", "");
      const rooms = (await get<string[]>(key)) ?? [];
      if (!rooms.includes(room)) await put(key, [...rooms, room]);
    });
  }

  async pinned(room: string): Promise<boolean> {
    return ((await get<string[]>(this.key("pinned", ""))) ?? []).includes(room);
  }
}
