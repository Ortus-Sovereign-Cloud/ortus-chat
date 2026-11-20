// End-to-end rooms in the browser (wire format: docs/end-to-end.md).
// This device's ECDH P-256 key is made here and kept in IndexedDB with
// its private half not extractable; room keys (AES-256-GCM) are wrapped
// for each member's device with an ephemeral ECDH key and HKDF-SHA-256,
// and messages are sealed with the room key. The server sees none of it
// in the clear.
import { call } from "ortus-kit";

export const ALGORITHM = "ortus.p256-aes-gcm.v1";

export interface Sealed {
  algorithm: string;
  version: number;
  device: string;
  iv: string;
  ciphertext: string;
}

interface Wrapped {
  algorithm: string;
  epk: JsonWebKey;
  iv: string;
  ciphertext: string;
}

interface Device {
  id: string;
  privateKey: CryptoKey;
  publicJwk: JsonWebKey;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(text: string): Uint8Array<ArrayBuffer> {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function publicOnly(k: JsonWebKey): JsonWebKey {
  return { kty: "EC", crv: "P-256", x: k.x, y: k.y };
}

function random(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

// IndexedDB: one record per person on this browser.
function store(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("ortus-chat-e2e", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("devices");
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

async function read(key: string): Promise<Device | undefined> {
  const db = await store();
  return new Promise((resolve, reject) => {
    const r = db.transaction("devices").objectStore("devices").get(key);
    r.onsuccess = () => resolve(r.result as Device | undefined);
    r.onerror = () => reject(r.error);
  });
}

async function write(key: string, device: Device): Promise<void> {
  const db = await store();
  return new Promise((resolve, reject) => {
    const t = db.transaction("devices", "readwrite");
    t.objectStore("devices").put(device, key);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

/** The key that unwraps or wraps one room key for one device. */
async function wrapping(privateKey: CryptoKey, publicJwk: JsonWebKey, info: string, use: KeyUsage): Promise<CryptoKey> {
  const other = await crypto.subtle.importKey("jwk", publicOnly(publicJwk), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: other }, privateKey, 256);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode(info) }, base, { name: "AES-GCM", length: 256 }, false, [use]);
}

function keyInfo(room: string, version: number, user: string, device: string): string {
  return `ortus room key|${room}|${version}|${user}|${device}`;
}

/** End-to-end rooms for one person on this browser. */
export class Sealer {
  private device: Device | null = null;
  /** Room keys this device holds: room → version → key. */
  private keys = new Map<string, Map<number, CryptoKey>>();

  constructor(private readonly me: string) {}

  /** This device, made and told to the server the first time. */
  async ready(): Promise<Device> {
    if (this.device) return this.device;
    const name = `device:${this.me}`;
    let d = await read(name).catch(() => undefined);
    if (!d) {
      const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      const id = Array.from(random(8), (b) => b.toString(16).padStart(2, "0")).join("");
      d = { id, privateKey: pair.privateKey, publicJwk: publicOnly(await crypto.subtle.exportKey("jwk", pair.publicKey)) };
      await write(name, d);
    }
    await call("PUT", `/chat/devices/${d.id}`, { publicKey: d.publicJwk });
    this.device = d;
    return d;
  }

  /** Takes the room keys given to this device, makes the first one if
   * the room has none (its owner only, so there is one first key), and
   * gives what it holds to members' devices that lack it. */
  async sync(room: string, owner: boolean): Promise<void> {
    // One at a time per room: two at once would each make a first key.
    const before = this.running.get(room) ?? Promise.resolve();
    const run = before.catch(() => undefined).then(() => this.syncNow(room, owner));
    this.running.set(room, run);
    return run;
  }

  private running = new Map<string, Promise<void>>();

  private async syncNow(room: string, owner: boolean): Promise<void> {
    const d = await this.ready();
    const mine = await call<{ keys: { version: number; wrapped: Wrapped }[] }>("GET", `/chat/rooms/${encodeURIComponent(room)}/keys/${d.id}`);
    const held = this.keys.get(room) ?? new Map<number, CryptoKey>();
    for (const k of mine.keys) {
      if (held.has(k.version)) continue;
      try {
        const unwrap = await wrapping(d.privateKey, k.wrapped.epk, keyInfo(room, k.version, this.me, d.id), "decrypt");
        const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(k.wrapped.iv) }, unwrap, unb64(k.wrapped.ciphertext));
        held.set(k.version, await crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]));
      } catch {
        // A key this device cannot open: left aside.
      }
    }
    this.keys.set(room, held);
    const devices = await call<{ devices: { user: string; device: string; publicKey: JsonWebKey; versions: number[] }[]; latest: number }>("GET", `/chat/rooms/${encodeURIComponent(room)}/devices`);
    let version = devices.latest;
    let made = false;
    if (version === 0) {
      if (!owner) return;
      version = 1;
      made = true;
      held.set(1, await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]));
    }
    const key = held.get(version);
    if (!key) return;
    const raw = await crypto.subtle.exportKey("raw", key);
    const give = [];
    for (const t of devices.devices) {
      if (t.versions.includes(version)) continue;
      const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      const wrap = await wrapping(eph.privateKey, t.publicKey, keyInfo(room, version, t.user, t.device), "encrypt");
      const iv = random(12);
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrap, raw);
      give.push({ user: t.user, device: t.device, version, wrapped: { algorithm: ALGORITHM, epk: publicOnly(await crypto.subtle.exportKey("jwk", eph.publicKey)), iv: b64(iv), ciphertext: b64(ciphertext) } });
    }
    if (give.length) await call("POST", `/chat/rooms/${encodeURIComponent(room)}/keys`, { fromDevice: d.id, keys: give });
    if (made) {
      // Another of my devices may have made one at the same moment: the
      // key the server kept for this device is the room's.
      held.delete(1);
      await this.syncNow(room, false);
    }
  }

  /** Whether this device can write in the room. */
  canSeal(room: string): boolean {
    return (this.keys.get(room)?.size ?? 0) > 0;
  }

  /** Seals a message and sends it. */
  async send(room: string, text: string, thread?: string): Promise<void> {
    const d = await this.ready();
    const held = this.keys.get(room);
    const version = held ? Math.max(...held.keys()) : 0;
    const key = held?.get(version);
    if (!key) throw new Error("no room key");
    const iv = random(12);
    const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`${room}|${version}`) }, key, enc.encode(JSON.stringify({ body: text })));
    await call("POST", `/chat/rooms/${encodeURIComponent(room)}/sealed`, { version, device: d.id, iv: b64(iv), ciphertext: b64(sealed), thread });
  }

  /** A sealed message's text, or null when this device cannot open it. */
  async open(room: string, s: Sealed): Promise<string | null> {
    const key = this.keys.get(room)?.get(s.version);
    if (!key || s.algorithm !== ALGORITHM) return null;
    try {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(s.iv), additionalData: enc.encode(`${room}|${s.version}`) }, key, unb64(s.ciphertext));
      const body = (JSON.parse(dec.decode(plain)) as { body?: unknown }).body;
      return typeof body === "string" ? body : null;
    } catch {
      return null;
    }
  }
}
