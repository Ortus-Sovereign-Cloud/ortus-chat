// End-to-end rooms in the browser, in Matrix's shapes (olm.ts does the
// cryptography; docs/end-to-end.md has the wire format). This device has
// Curve25519 and Ed25519 identity keys, one-time keys and a fallback key;
// it shares its Megolm session for a room with every member's device over
// Olm, seals messages with it, and opens what members' devices sealed.
// Everything is kept in IndexedDB, private keys as CryptoKeys that cannot
// be read out. One operation at a time per person, across tabs too.
import { call } from "ortus-kit";
import * as olm from "./olm.js";
import * as trust from "./trust.js";
import * as sas from "./verify.js";

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
  created: number;
  count: number;
}

interface Inbound {
  session: olm.MegolmInbound;
  senderUser: string;
  /** The Ed25519 key of the device that made the session (for backups). */
  signing?: string;
}

/** This browser's cross-signing keys and backup key (seeds), after recovery was set up or used. */
interface Trust {
  master: string;
  selfSigning: string;
  userSigning: string;
  backup?: string;
  /** The backup version whose auth data the master key signed. */
  version?: string;
}

/** Where recovery stands: set up for the person, and opened on this browser. */
export interface RecoveryState {
  set: boolean;
  here: boolean;
  escrow: boolean;
}

/** A verification by emoji, as the screen shows it. */
export interface VerificationView {
  id: string;
  /** The other person (oneself, for one's own other device). */
  user: string;
  device?: string;
  /** requested: we asked; incoming: they ask; waiting: keys are being agreed; emoji: compare; done; cancelled. */
  state: "requested" | "incoming" | "waiting" | "emoji" | "done" | "cancelled";
  emoji?: number[];
  reason?: string;
}

interface Verification {
  view: VerificationView;
  started: boolean;
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

/** End-to-end rooms for one person on this browser. */
export class Sealer {
  private published = false;
  /** One operation at a time in this tab (and across tabs: a lock). */
  private chain: Promise<unknown> = Promise.resolve();
  private opened = new Map<string, string>();
  private readonly me: string;

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
        const had = await get<Inbound>(where);
        if (!had || (had.senderUser === m.sender && had.session.ratchet.index > inbound.ratchet.index)) {
          await put(where, { session: inbound, senderUser: m.sender, signing: p.keys?.ed25519 } satisfies Inbound);
          if (c.room_id) await this.backUp([{ roomId: c.room_id, room, senderKey: theirs, sessionId: c.session_id, inbound, signingKey: p.keys?.ed25519 ?? "" }]).catch(() => undefined);
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
    if (!out || left || came || out.count >= 100 || Date.now() - out.created > 7 * 86_400_000) {
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
    }
    for (const [target, list] of sessions) await put(this.key("olm", target), list.slice(0, 5));
    if (messages.length) {
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
   * it is not what it says (sender, room, thread, a replay). */
  open(room: string, roomId: string, s: Sealed, sender: string, event: string, thread: string | null): Promise<string | null> {
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
        this.opened.set(cacheKey, p.content.body);
        return p.content.body;
      } catch {
        return null;
      }
    });
  }


  // ---- trust: recovery, cross-signing, backup (docs/e2e-trust-and-backup.md)

  private async trustKeys(): Promise<{ t: Trust; master: trust.SeedKey; selfSigning: trust.SeedKey; userSigning: trust.SeedKey; backup?: trust.SeedKey } | null> {
    const t = await get<Trust>(this.key("trust", ""));
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
      return { set, here: !!(await get<Trust>(this.key("trust", ""))), escrow };
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
   * Sets recovery up for the person (on their first device): cross-signing
   * keys, this device signed, a backup signed by the master key, the
   * secrets in secret storage under a new recovery key, and its escrow copy
   * when the organisation has an escrow key. Answers the recovery key, to
   * show once.
   */
  setUpRecovery(): Promise<string> {
    return this.run(async () => {
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
      await call("PUT", "/chat/account-data/m.secret_storage.default_key", { key: keyId });
      const text = trust.encodeRecoveryKey(recovery);
      const policy = await call<{ escrowKey?: string | null }>("GET", "/chat/policy");
      if (policy.escrowKey) {
        await call("PUT", "/chat/account-data/ortus.escrow", { key: policy.escrowKey, sealed: await trust.seal(olm.unb64(policy.escrowKey), text) });
      }
      await put(this.key("trust", ""), { master: olm.b64(cross.master.seed), selfSigning: olm.b64(cross.selfSigning.seed), userSigning: olm.b64(cross.userSigning.seed), backup: olm.b64(backup.seed), version } satisfies Trust);
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
              if (!exported.sender_key || !exported.session_key) continue;
              await put(this.key("bk", `${roomId}|${exported.sender_key}|${sessionId}`), exported.session_key);
              restored++;
            }
          }
        }
      }
      await put(this.key("trust", ""), t);
      return restored;
    });
  }

  /** A session from the backup, taken once its sender key is checked to be the sender's device in the room. */
  private async restored(room: string, roomId: string, s: Sealed, sender: string): Promise<Inbound | undefined> {
    const exported = await get<string>(this.key("bk", `${roomId}|${s.sender_key}|${s.session_id}`));
    if (!exported) return undefined;
    const devices = await this.devices(room).catch(() => []);
    if (!devices.some((d) => d.user === sender && d.curve === s.sender_key)) return undefined;
    const rec: Inbound = { session: olm.importSessionKey(exported), senderUser: sender };
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
   * key this person did not verify). Rooms warn about them; messages still
   * go to them (the owner's decision).
   */
  unverified(room: string): Promise<{ user: string; device: string }[]> {
    return this.run(async () => {
      const r = await call<{ devices: { user: string; device: string; deviceKeys: Record<string, unknown> }[]; crossSigning: Record<string, { master?: Record<string, unknown>; selfSigning?: Record<string, unknown> }> }>("GET", `/chat/rooms/${enc(room)}/devices`);
      const mine = await this.trustKeys();
      const out: { user: string; device: string }[] = [];
      for (const d of r.devices) {
        const keys = r.crossSigning[d.user];
        const key = (o?: Record<string, unknown>): [string, Uint8Array] | null => {
          const k = Object.entries((o?.keys as Record<string, string>) ?? {})[0];
          return k ? [k[0], olm.unb64(k[1])] : null;
        };
        const master = key(keys?.master);
        const ssk = key(keys?.selfSigning);
        let ok = !!(master && ssk && keys?.selfSigning && (await olm.verifyJson(keys.selfSigning, d.user, master[0], master[1])) && (await olm.verifyJson(d.deviceKeys, d.user, ssk[0], ssk[1])));
        if (ok && master && keys?.master) {
          // Their master key: one's own, or one this person verified.
          if (d.user === this.me) ok = !!mine && trust.keyId(mine.master) === master[0];
          else ok = !!mine && (await olm.verifyJson(keys.master, this.me, trust.keyId(mine.userSigning), mine.userSigning.publicKey));
        }
        if (!ok) out.push({ user: d.user, device: d.device });
      }
      return out;
    });
  }


  // ---- verification by emoji (verify.ts) ------------------------------------

  private verifications = new Map<string, Verification>();
  /** Told whenever a verification changes (the screen shows it). */
  onVerification?: (v: VerificationView) => void;

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
      await this.sendVerification(a, user, "*", "m.key.verification.request", { from_device: a.device, methods: [sas.SAS], transaction_id: id, timestamp: Date.now() });
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
      await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.ready", { from_device: a.device, methods: [sas.SAS], transaction_id: id });
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
      if (v && v.view.state !== "done" && v.view.state !== "cancelled") await this.cancel(await this.account(), v, "m.user", "Cancelled.");
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
      v = { view: { id, user: sender, device: senderDevice, state: "incoming" }, started: false };
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
      v.start = { from_device: a.device, method: sas.SAS, key_agreement_protocols: [sas.KEY_AGREEMENT], hashes: [sas.HASH], message_authentication_codes: [sas.MAC], short_authentication_string: ["emoji", "decimal"], transaction_id: id };
      await this.sendVerification(a, sender, senderDevice, "m.key.verification.start", v.start);
      return this.changed(v);
    }
    if (type === "m.key.verification.start" && !v.started && v.view.state === "waiting") {
      if (c.method !== sas.SAS || !(c.key_agreement_protocols as string[] | undefined)?.includes(sas.KEY_AGREEMENT) || !(c.message_authentication_codes as string[] | undefined)?.includes(sas.MAC)) return this.cancel(a, v, "m.unknown_method", "Not a way this device verifies.");
      v.start = c;
      v.ours = await sas.ephemeral();
      const accept = { transaction_id: id, method: sas.SAS, key_agreement_protocol: sas.KEY_AGREEMENT, hash: sas.HASH, message_authentication_code: sas.MAC, short_authentication_string: ["emoji", "decimal"], commitment: await sas.commitment(v.ours.publicKey, c) };
      await this.sendVerification(a, sender, senderDevice, "m.key.verification.accept", accept);
      return;
    }
    if (type === "m.key.verification.accept" && v.started && typeof c.commitment === "string") {
      v.commitment = c.commitment;
      v.ours = await sas.ephemeral();
      await this.sendVerification(a, sender, senderDevice, "m.key.verification.key", { transaction_id: id, key: v.ours.publicKey });
      return;
    }
    if (type === "m.key.verification.key" && typeof c.key === "string" && v.ours && !v.theirKey) {
      v.theirKey = c.key;
      if (v.started) {
        // The other side committed to its key before it saw ours.
        if (!v.start || v.commitment !== (await sas.commitment(c.key, v.start))) return this.cancel(a, v, "m.mismatched_commitment", "The keys did not match what was promised.");
      } else {
        await this.sendVerification(a, sender, senderDevice, "m.key.verification.key", { transaction_id: id, key: v.ours.publicKey });
      }
      v.secret = await sas.shared(v.ours, c.key);
      const me = { user: this.me, device: a.device, key: v.ours.publicKey };
      const them = { user: sender, device: senderDevice, key: c.key };
      v.view.emoji = await sas.emoji(v.secret, v.started ? me : them, v.started ? them : me, id);
      v.view.state = "emoji";
      return this.changed(v);
    }
    if (type === "m.key.verification.mac" && v.secret) {
      v.theirMac = c as Verification["theirMac"];
      return this.finish(a, v);
    }
    if (type === "m.key.verification.done") return;
  }

  /** Both sides vouched: check theirs, sign what was verified, say done. */
  private async finish(a: Account, v: Verification): Promise<void> {
    if (!v.secret || !v.theirMac || !v.confirmed || !v.macSent || !v.view.device || v.view.state === "done") return;
    const keys = await call<{ devices: { device: string; deviceKeys: Record<string, unknown> }[]; crossSigning: Record<string, { master?: Record<string, unknown> }> }>("GET", `/chat/keys?user=${enc(v.view.user)}`);
    const device = keys.devices.find((d) => d.device === v.view.device);
    const known: Record<string, string> = {};
    const ed = (device?.deviceKeys.keys as Record<string, string> | undefined)?.[`ed25519:${v.view.device}`];
    if (ed) known[`ed25519:${v.view.device}`] = ed;
    const master = keys.crossSigning[v.view.user]?.master;
    const masterKey = Object.entries((master?.keys as Record<string, string>) ?? {})[0];
    if (masterKey) known[masterKey[0]] = masterKey[1];
    const vouched = await sas.checkMac(v.secret, { user: this.me, device: a.device }, { user: v.view.user, device: v.view.device }, v.view.id, v.theirMac, known);
    if (!vouched || !vouched.includes(`ed25519:${v.view.device}`)) return this.cancel(a, v, "m.key_mismatch", "The keys are not the ones the server has.");
    v.vouched = vouched;
    const mine = await this.trustKeys();
    if (mine && device) {
      if (v.view.user === this.me) {
        // One's own device: signed with one's self-signing key.
        const plain = { ...device.deviceKeys };
        delete plain.signatures;
        delete plain.unsigned;
        await call("POST", "/chat/signatures", { [this.me]: { [v.view.device]: await trust.signDevice(this.me, plain, mine.selfSigning) } });
      } else if (master && masterKey && vouched.includes(masterKey[0])) {
        // Someone else: their master key, with one's user-signing key.
        const plain = { ...master };
        delete plain.signatures;
        delete plain.unsigned;
        await call("POST", "/chat/signatures", { [v.view.user]: { [masterKey[1]]: await trust.signUser(this.me, plain, mine.userSigning) } });
      }
    }
    await this.sendVerification(a, v.view.user, v.view.device, "m.key.verification.done", { transaction_id: v.view.id });
    v.view.state = "done";
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
