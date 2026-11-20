// End-to-end rooms in the browser, in Matrix's shapes (olm.ts does the
// cryptography; docs/end-to-end.md has the wire format). This device has
// Curve25519 and Ed25519 identity keys and one-time keys; it shares its
// Megolm session for a room with every member's device over Olm, seals
// messages with it, and opens what members' devices sealed. Everything is
// kept in IndexedDB, private keys as CryptoKeys that cannot be read out.
import { call } from "ortus-kit";
import * as olm from "./olm.js";

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
  senderKey: string;
  senderUser: string;
}

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

function deviceId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(10)), (b) => String.fromCharCode(65 + (b % 26))).join("");
}

/** End-to-end rooms for one person on this browser. */
export class Sealer {
  private account: Account | null = null;
  private published = false;
  /** One operation at a time: sessions and ratchets are not shared state. */
  private chain: Promise<unknown> = Promise.resolve();
  private opened = new Map<string, string>();
  private readonly me: string;

  constructor(me: string) {
    this.me = me;
  }

  private run<T>(f: () => Promise<T>): Promise<T> {
    const next = this.chain.catch(() => undefined).then(f);
    this.chain = next;
    return next;
  }

  private key(kind: string, rest: string): string {
    return `${kind}:${this.me}:${rest}`;
  }

  /** This device: made once, its keys published, one-time keys topped up. */
  ready(): Promise<void> {
    return this.run(async () => {
      await this.readyNow();
    });
  }

  private async readyNow(): Promise<Account> {
    let a = this.account ?? (await get<Account>(this.key("account", "")));
    if (!a) {
      a = { device: deviceId(), identity: await olm.x25519(), signing: await olm.ed25519(), oneTimeKeys: {}, next: 0 };
      await put(this.key("account", ""), a);
    }
    this.account = a;
    if (!this.published) {
      const r = await this.upload(a, {});
      if (r < 20) await this.topUp(a, 25 - r);
      this.published = true;
    }
    return a;
  }

  private async upload(a: Account, oneTimeKeys: Record<string, unknown>): Promise<number> {
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
    const r = await call<{ oneTimeKeyCount: number }>("PUT", `/chat/devices/${a.device}`, { deviceKeys: keys, oneTimeKeys });
    return r.oneTimeKeyCount;
  }

  private async topUp(a: Account, n: number): Promise<void> {
    const out: Record<string, unknown> = {};
    for (let i = 0; i < n; i++) {
      const k = await olm.x25519();
      const id = `AAA${(a.next++).toString(36).toUpperCase()}`;
      a.oneTimeKeys[olm.b64(k.publicKey)] = k;
      out[`signed_curve25519:${id}`] = await olm.signJson({ key: olm.b64(k.publicKey) }, this.me, `ed25519:${a.device}`, a.signing.privateKey);
    }
    await put(this.key("account", ""), a);
    await this.upload(a, out);
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
    return out;
  }

  /** Room keys sent to this device: opened, checked and kept. */
  private async inbox(a: Account): Promise<void> {
    const r = await call<{ messages: { id: string; sender: string; senderDevice: string; content: { sender_key?: string; ciphertext?: Record<string, olm.OlmMessage> } }[] }>("GET", `/chat/devices/${a.device}/inbox`);
    if (!r.messages.length) return;
    const mine = olm.b64(a.identity.publicKey);
    const roomDevices = new Map<string, Device[]>();
    let usedOneTimeKeys = 0;
    for (const m of r.messages) {
      try {
        const theirs = m.content.sender_key ?? "";
        const message = m.content.ciphertext?.[mine];
        if (!message) continue;
        const sessionsKey = this.key("olm", theirs);
        const sessions = (await get<olm.OlmSession[]>(sessionsKey)) ?? [];
        let plaintext: string | null = null;
        for (const s of sessions) {
          if (message.type === 0 && !olm.matchesPreKey(s, message.body)) continue;
          try {
            plaintext = await olm.olmDecrypt(s, message);
            break;
          } catch {
            // Another session.
          }
        }
        if (plaintext === null && message.type === 0) {
          const otk = a.oneTimeKeys[olm.b64(olm.preKeyFields(message.body).oneTimeKey)];
          if (!otk) continue;
          const created = await olm.inboundSession(a.identity, otk, message.body);
          delete a.oneTimeKeys[olm.b64(otk.publicKey)];
          usedOneTimeKeys++;
          sessions.unshift(created.session);
          plaintext = created.plaintext;
        }
        await put(sessionsKey, sessions.slice(0, 10));
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
        if (!roomDevices.has(room)) roomDevices.set(room, await this.devices(room).catch(() => []));
        const sender = roomDevices.get(room)!.find((d) => d.user === m.sender && d.device === m.senderDevice);
        if (!sender || sender.curve !== theirs || sender.ed !== p.keys?.ed25519) continue;
        if (c.algorithm !== MEGOLM || !c.session_key || !c.session_id) continue;
        const inbound = await olm.megolmInbound(c.session_key);
        if (olm.sessionId(inbound.signingKey) !== c.session_id) continue;
        const where = this.key("in", `${room}|${c.session_id}`);
        const had = await get<Inbound>(where);
        if (!had || had.session.ratchet.index > inbound.ratchet.index) await put(where, { session: inbound, senderKey: theirs, senderUser: m.sender } satisfies Inbound);
      } catch {
        // A message this device cannot open: dropped.
      }
    }
    await put(this.key("account", ""), a);
    await call("POST", `/chat/devices/${a.device}/inbox/done`, { ids: r.messages.map((m) => m.id) });
    if (usedOneTimeKeys) await this.topUp(a, usedOneTimeKeys);
  }

  /** Takes in room keys sent to this device, and gives this device's room
   * session to members' devices that lack it. */
  sync(room: string, roomId: string): Promise<void> {
    return this.run(async () => {
      const a = await this.readyNow();
      await this.inbox(a);
      await this.share(a, room, roomId);
    });
  }

  private async share(a: Account, room: string, roomId: string): Promise<Outbound> {
    const devices = await this.devices(room);
    const users = new Set(devices.map((d) => d.user));
    const where = this.key("out", room);
    let out = await get<Outbound>(where);
    // A new session when someone left (they keep only what was before),
    // and now and then.
    const left = out?.sharedWith.some((k) => !users.has(k.split("|")[0]!));
    if (!out || left || out.count >= 100 || Date.now() - out.created > 7 * 86_400_000) {
      const session = await olm.megolmOutbound();
      const initialKey = await olm.sessionKey(session);
      out = { id: olm.sessionId(session.signing.publicKey), session, initialKey, sharedWith: [], created: Date.now(), count: 0 };
      await put(this.key("in", `${room}|${out.id}`), { session: await olm.megolmInbound(initialKey), senderKey: olm.b64(a.identity.publicKey), senderUser: this.me } satisfies Inbound);
      await put(where, out);
    }
    const current = out;
    const targets = devices.filter((d) => !(d.user === this.me && d.device === a.device) && !current.sharedWith.includes(`${d.user}|${d.device}`));
    if (!targets.length) return current;
    // An Olm session to each device: kept from before, or new from a
    // one-time key of theirs.
    const sessions = new Map<string, olm.OlmSession[]>();
    for (const t of targets) sessions.set(t.curve, (await get<olm.OlmSession[]>(this.key("olm", t.curve))) ?? []);
    const lacking = targets.filter((t) => !sessions.get(t.curve)!.length);
    if (lacking.length) {
      const claimed = await call<{ oneTimeKeys: Record<string, Record<string, Record<string, Record<string, unknown>>>> }>("POST", `/chat/rooms/${enc(room)}/claim`, { devices: lacking.map((t) => ({ user: t.user, device: t.device })) });
      for (const t of lacking) {
        const keys = claimed.oneTimeKeys[t.user]?.[t.device];
        const one = keys && Object.values(keys)[0];
        if (!one || typeof one.key !== "string" || !(await olm.verifyJson(one, t.user, `ed25519:${t.device}`, olm.unb64(t.ed)))) continue;
        sessions.get(t.curve)!.unshift(await olm.outboundSession(a.identity, olm.unb64(t.curve), olm.unb64(one.key)));
      }
    }
    const messages = [];
    const given: string[] = [];
    for (const t of targets) {
      const s = sessions.get(t.curve)![0];
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
      given.push(`${t.user}|${t.device}`);
    }
    for (const [curve, list] of sessions) await put(this.key("olm", curve), list.slice(0, 10));
    if (messages.length) await call("POST", `/chat/rooms/${enc(room)}/to-device`, { fromDevice: a.device, messages });
    current.sharedWith = [...current.sharedWith, ...given];
    await put(where, current);
    return current;
  }

  /** Seals a message with this device's room session and sends it. */
  send(room: string, roomId: string, text: string, thread?: string): Promise<void> {
    return this.run(async () => {
      const a = await this.readyNow();
      const out = await this.share(a, room, roomId);
      const ciphertext = await olm.megolmEncrypt(out.session, JSON.stringify({ type: "m.room.message", content: { msgtype: "m.text", body: text }, room_id: roomId }));
      out.count++;
      await put(this.key("out", room), out);
      await call("POST", `/chat/rooms/${enc(room)}/sealed`, { algorithm: MEGOLM, sender_key: olm.b64(a.identity.publicKey), ciphertext, session_id: out.id, device_id: a.device, thread });
    });
  }

  /** A sealed message's text, or null when this device cannot open it. */
  open(room: string, roomId: string, s: Sealed, sender: string): Promise<string | null> {
    const cached = this.opened.get(s.ciphertext);
    if (cached !== undefined) return Promise.resolve(cached);
    return this.run(async () => {
      if (s.algorithm !== MEGOLM) return null;
      const rec = await get<Inbound>(this.key("in", `${room}|${s.session_id}`));
      // The session must be the sender's own device's.
      if (!rec || rec.senderKey !== s.sender_key || rec.senderUser !== sender) return null;
      try {
        const { plaintext } = await olm.megolmDecrypt(rec.session, s.ciphertext);
        const p = JSON.parse(plaintext) as { type?: string; room_id?: string; content?: { body?: unknown } };
        if (p.type !== "m.room.message" || p.room_id !== roomId || typeof p.content?.body !== "string") return null;
        this.opened.set(s.ciphertext, p.content.body);
        return p.content.body;
      } catch {
        return null;
      }
    });
  }

  /** Rooms this browser has seen end-to-end encrypted: never sent to in
   * the clear afterwards, whatever the server says. */
  async pin(room: string): Promise<void> {
    const key = this.key("pinned", "");
    const rooms = (await get<string[]>(key)) ?? [];
    if (!rooms.includes(room)) await put(key, [...rooms, room]);
  }

  async pinned(room: string): Promise<boolean> {
    return ((await get<string[]>(this.key("pinned", ""))) ?? []).includes(room);
  }
}
