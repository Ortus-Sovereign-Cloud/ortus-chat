// The browser's end-to-end rooms (src/e2e.ts, its Sealer, as it is; and
// src/qrscan.ts reading the phones' codes drawn as a camera sees them) as one
// side of a conversation with the phones' crate (phones/e2e/tests drive it
// over stdin and stdout, one JSON object per line). ortus-kit is
// kit-bridge.ts here, and IndexedDB a small one in memory. Run by Node 23.5
// or later, which strips the types.
import { registerHooks } from "node:module";
import { next, say } from "./lines.ts";

const here = new URL(".", import.meta.url);
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "ortus-kit") return { url: new URL("kit-bridge.ts", here).href, shortCircuit: true };
    // The app imports its own modules as .js (the bundler's way).
    if (specifier.startsWith("./") && specifier.endsWith(".js") && context.parentURL?.includes("/src/"))
      return nextResolve(specifier.replace(/\.js$/, ".ts"), context);
    return nextResolve(specifier, context);
  },
});

// IndexedDB: what e2e.ts uses of it, kept in memory.
function request<T>(f: () => T): { result?: T; error?: unknown; onsuccess?: () => void; onerror?: () => void } {
  const r: { result?: T; error?: unknown; onsuccess?: () => void; onerror?: () => void } = {};
  queueMicrotask(() => {
    try {
      r.result = f();
      r.onsuccess?.();
    } catch (e) {
      r.error = e;
      r.onerror?.();
    }
  });
  return r;
}
const stores = new Map<string, Map<unknown, unknown>>();
const copy = (v: unknown): unknown => {
  try {
    return structuredClone(v);
  } catch {
    return v;
  }
};
const database = {
  createObjectStore(name: string) {
    stores.set(name, new Map());
  },
  transaction(name: string) {
    const t: { oncomplete?: () => void; onerror?: () => void; objectStore: (n: string) => unknown } = {
      objectStore: (n: string) => ({
        get: (key: unknown) => request(() => copy(stores.get(n)!.get(key))),
        getAllKeys: () => request(() => [...stores.get(n)!.keys()]),
        put: (value: unknown, key: unknown) => {
          stores.get(n)!.set(key, copy(value));
          queueMicrotask(() => t.oncomplete?.());
          return request(() => key);
        },
      }),
    };
    void name;
    return t;
  },
};
(globalThis as any).indexedDB = {
  open() {
    const r: { result?: unknown; onupgradeneeded?: () => void; onsuccess?: () => void } = {};
    queueMicrotask(() => {
      r.result = database;
      if (!stores.has("state")) r.onupgradeneeded?.();
      r.onsuccess?.();
    });
    return r;
  },
};

const { Sealer } = await import("../src/e2e.ts");
const { decodeQr } = await import("../src/qrscan.ts");
const { render } = await import("./render.ts");
const { b64 } = await import("../src/olm.ts");

/** A code's modules (`width` a row, dark when true) as a camera sees them, read back by the browser's scanner. */
function scan(c: Record<string, any>): Uint8Array | null {
  const width = c.width as number;
  const flat = c.modules as boolean[];
  const rows = Array.from({ length: width }, (_, y) => flat.slice(y * width, (y + 1) * width));
  return decodeQr(render(rows, { scale: c.scale ?? 5, angle: c.angle ?? 9, skew: c.skew ?? 0.02, noise: c.noise ?? 20, seed: 7 }));
}

const first = await next();
const sealer = new Sealer(first.me);
// The latest of each verification, as the screen would show it.
const views = new Map<string, unknown>();
sealer.onVerification = (v) => views.set(v.id, v);
say({ result: "ready" });
for (;;) {
  const c = await next();
  try {
    if (c.cmd === "ready") {
      await sealer.ready();
      say({ result: null });
    } else if (c.cmd === "sync") {
      await sealer.sync(c.room, c.roomId);
      say({ result: null });
    } else if (c.cmd === "send") {
      await sealer.send(c.room, c.roomId, c.text, c.thread ?? undefined);
      say({ result: null });
    } else if (c.cmd === "open") {
      // The text only (the phones' tests read it as before).
      say({ result: (await sealer.open(c.room, c.roomId, c.message.sealed, c.message.sender, c.message.id, c.message.thread ?? null))?.text ?? null });
    } else if (c.cmd === "setUpRecovery") {
      // The escrow key the person accepted (as escrowInfo showed it), if any.
      say({ result: await sealer.setUpRecovery(c.accepted ?? undefined) });
    } else if (c.cmd === "escrowInfo") {
      say({ result: await sealer.escrowInfo() });
    } else if (c.cmd === "signWithMaster") {
      say({ result: await sealer.signWithMaster(c.value) });
    } else if (c.cmd === "unverified") {
      say({ result: await sealer.unverified(c.room) });
    } else if (c.cmd === "verify") {
      say({ result: await sealer.verify(c.user) });
    } else if (c.cmd === "poll") {
      await sealer.pollVerifications();
      say({ result: [...views.values()] });
    } else if (c.cmd === "accept") {
      await sealer.acceptVerification(c.id);
      say({ result: null });
    } else if (c.cmd === "confirm") {
      await sealer.confirmEmoji(c.id, c.same);
      say({ result: null });
    } else if (c.cmd === "recover") {
      say({ result: await sealer.recover(c.key) });
    } else if (c.cmd === "recoveryState") {
      say({ result: await sealer.recoveryState() });
    } else if (c.cmd === "emoji") {
      await sealer.startEmoji(c.id);
      say({ result: null });
    } else if (c.cmd === "confirmScanned") {
      await sealer.confirmScanned(c.id, c.yes);
      say({ result: null });
    } else if (c.cmd === "camera") {
      // The page has a camera (Node has none): it offers to scan codes.
      sealer.camera = !!c.on;
      say({ result: null });
    } else if (c.cmd === "decode") {
      const bytes = scan(c);
      say({ result: bytes ? b64(bytes) : null });
    } else if (c.cmd === "scanCode") {
      const bytes = scan(c);
      if (!bytes) throw new Error("the code was not read");
      say({ result: await sealer.scanCode(c.id, bytes) });
    } else if (c.cmd === "quit") {
      process.exit(0);
    }
  } catch (e) {
    say({ error: String(e) });
  }
}
