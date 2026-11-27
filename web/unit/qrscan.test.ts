// The QR scanner (src/qrscan.ts) against the encoder (src/qr.ts): random
// payloads the size of Matrix's verification codes and larger, at every
// level, drawn at several scales, turned, in perspective, with noise, and
// read back exactly; Reed-Solomon to its limit; format bits damaged. The
// phones' tests read codes another encoder made (the qrcode crate's).
// Run by Node 23.5 or later (it strips the types): `npm test`.
import { registerHooks } from "node:module";
import assert from "node:assert/strict";
import { test } from "node:test";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith("./") && specifier.endsWith(".js") && context.parentURL?.includes("/src/"))
      return nextResolve(specifier.replace(/\.js$/, ".ts"), context);
    return nextResolve(specifier, context);
  },
});

const { qrCode, ECC } = await import("../src/qr.ts");
const { decodeQr, decodeGrid, correct } = await import("../src/qrscan.ts");
const { render, random } = await import("../interop/render.ts");

const LEVELS = ["L", "M", "Q", "H"] as const;

function payload(rnd: () => number, length: number): Uint8Array {
  const b = new Uint8Array(length);
  for (let i = 0; i < length; i++) b[i] = Math.floor(rnd() * 256);
  // As a verification code begins.
  b.set(new TextEncoder().encode("MATRIX\x02").subarray(0, Math.min(7, length)));
  return b;
}

test("random payloads drawn turned, in perspective and with noise are read back exactly", () => {
  const rnd = random(20261127);
  for (let k = 0; k < 32; k++) {
    const level = LEVELS[k % 4]!;
    const bytes = payload(rnd, 50 + Math.floor(rnd() * 251));
    const modules = qrCode(bytes, level);
    const angle = (5 + rnd() * 10) * (rnd() < 0.5 ? -1 : 1);
    const look = { scale: 3 + rnd() * 4, angle, skew: rnd() * 0.05, noise: 25, seed: k + 1 };
    const got = decodeQr(render(modules, look));
    assert.ok(got, `case ${k}: ${bytes.length} bytes, level ${level}, version ${(modules.length - 17) / 4}, ${JSON.stringify(look)}: not read`);
    assert.deepEqual(got, bytes, `case ${k}`);
  }
});

test("every version from 1 to 15 is read, straight and at a slant", () => {
  const rnd = random(7);
  for (let ver = 1; ver <= 15; ver++) {
    // The longest byte payload level M holds at this version (and so the version itself).
    let length = 1;
    for (let step = 256; step >= 1; step >>= 1) if (qrCode(new Uint8Array(length + step), "M").length <= ver * 4 + 17) length += step;
    const bytes = payload(rnd, length);
    const modules = qrCode(bytes, "M");
    assert.equal(modules.length, ver * 4 + 17);
    for (const look of [{ scale: 4 }, { scale: 5.5, angle: 12, skew: 0.04, noise: 20, seed: ver }]) {
      assert.deepEqual(decodeQr(render(modules, look)), bytes, `version ${ver}, ${JSON.stringify(look)}`);
    }
  }
});

test("a frame without a code reads as nothing", () => {
  const rnd = random(3);
  const w = 320;
  const data = new Uint8ClampedArray(w * w * 4).map((_, i) => (i % 4 === 3 ? 255 : 100 + rnd() * 60));
  assert.equal(decodeQr({ width: w, height: w, data }), null);
  assert.equal(decodeQr({ width: 10, height: 10, data: new Uint8Array(100) }), null);
});

test("grey frames (one byte a pixel) are read too", () => {
  const bytes = payload(random(11), 120);
  const rgba = render(qrCode(bytes), { scale: 4, angle: 8 });
  const grey = new Uint8Array(rgba.width * rgba.height).map((_, i) => rgba.data[i * 4]!);
  assert.deepEqual(decodeQr({ width: rgba.width, height: rgba.height, data: grey }), bytes);
});

test("Reed-Solomon corrects up to half its codewords and no more", () => {
  const rnd = random(5);
  for (let ver = 1; ver <= 15; ver++) {
    for (const level of LEVELS) {
      const ecc = ECC[level][ver]!;
      // A valid block: data, then its error-correction codewords.
      const data = Array.from({ length: 30 }, () => Math.floor(rnd() * 256));
      const block = encodeBlock(data, ecc);
      assert.deepEqual(correct(Uint8Array.from(block), ecc), Uint8Array.from(block));
      const t = Math.floor(ecc / 2);
      const broken = Uint8Array.from(block);
      const at = new Set<number>();
      while (at.size < t) at.add(Math.floor(rnd() * block.length));
      for (const i of at) broken[i]! ^= 1 + Math.floor(rnd() * 255);
      assert.deepEqual(correct(broken, ecc), Uint8Array.from(block), `${ecc} codewords, ${t} errors`);
      // One more than it can: given up, or (rarely) another valid block, never the damaged one passed as good.
      at.add([...Array(block.length).keys()].find((i) => !at.has(i))!);
      const worse = Uint8Array.from(block);
      for (const i of at) worse[i]! ^= 0x5a;
      const r = correct(worse, ecc);
      if (r) assert.notDeepEqual(r, worse);
    }
  }
});

test("codes with damaged codewords and format bits are still read", () => {
  const rnd = random(9);
  for (const level of LEVELS) {
    const bytes = payload(rnd, 90);
    const modules = qrCode(bytes, level);
    const n = modules.length;
    // Three format bits wrong in each copy.
    for (const [x, y] of [
      [8, 0],
      [8, 2],
      [3, 8],
      [n - 1, 8],
      [n - 4, 8],
      [8, n - 2],
    ] as const)
      modules[y]![x] = !modules[y]![x];
    // A few data modules wrong (each costs at most one codeword).
    for (let i = 0; i < 4; i++) {
      const x = 9 + Math.floor(rnd() * (n - 18));
      const y = 9 + Math.floor(rnd() * (n - 18));
      modules[y]![x] = !modules[y]![x];
    }
    assert.deepEqual(decodeGrid(modules), bytes, `level ${level}`);
    assert.deepEqual(decodeQr(render(modules, { scale: 4, angle: -7, noise: 15 })), bytes, `level ${level}, drawn`);
  }
});

/** A Reed-Solomon block as the encoder makes one (its divisor and remainder, written again here). */
function encodeBlock(data: number[], ecc: number): number[] {
  const mul = (x: number, y: number) => {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xff;
  };
  const div = new Array<number>(ecc).fill(0);
  div[ecc - 1] = 1;
  let root = 1;
  for (let i = 0; i < ecc; i++) {
    for (let j = 0; j < ecc; j++) {
      div[j] = mul(div[j]!, root);
      if (j + 1 < ecc) div[j]! ^= div[j + 1]!;
    }
    root = mul(root, 2);
  }
  const rem = new Array<number>(ecc).fill(0);
  for (const b of data) {
    const f = b ^ rem.shift()!;
    rem.push(0);
    div.forEach((c, i) => (rem[i]! ^= mul(c, f)));
  }
  return [...data, ...rem];
}
