// QR codes read from a camera's frames (ISO/IEC 18004), for verification:
// the Matrix payload is binary, and the browser's own BarcodeDetector gives
// text (lossy for bytes) and is missing on Linux and Windows desktops. So,
// written here (no dependency in the web client, as qr.ts and olm.ts): a
// local threshold, the three finder patterns (1:1:3:1:1 runs), the version
// from their distance, the alignment pattern from version 2, a perspective
// transform, the grid sampled, format and version information (the nearest
// valid code), unmasking, the codewords in their zigzag, the blocks
// de-interleaved, Reed-Solomon over GF(256) (Berlekamp-Massey and Forney),
// every level (L, M, Q, H), and the segments read back as raw bytes (byte
// mode; numeric, alphanumeric, ECI and kanji are tolerated). No DOM: plain
// TypeScript, so Node tests it. Mirror images are not read.
import { BLOCKS, ECC, FORMAT_BITS, functionModules, rawModules, type Level } from "./qr.js";

/** A frame: RGBA (4 bytes a pixel, as a canvas's ImageData) or grey (1 byte a pixel). */
export interface Frame {
  width: number;
  height: number;
  data: ArrayLike<number>;
}

interface Point {
  x: number;
  y: number;
}

/** Dark pixels (1) of a frame. */
interface Bits {
  w: number;
  h: number;
  d: Uint8Array;
}

const dark = (b: Bits, x: number, y: number): boolean => b.d[y * b.w + x] === 1;

// ---- binarizing ---------------------------------------------------------------

function luminance(f: Frame): Uint8Array {
  const n = f.width * f.height;
  const out = new Uint8Array(n);
  const d = f.data;
  if (d.length >= n * 4) {
    for (let i = 0; i < n; i++) out[i] = (d[i * 4]! * 77 + d[i * 4 + 1]! * 150 + d[i * 4 + 2]! * 29) >> 8;
  } else {
    for (let i = 0; i < n; i++) out[i] = d[i]!;
  }
  return out;
}

/**
 * A local threshold (as ZXing's hybrid binarizer): the mean of each 8×8
 * block, flat blocks taken as light unless their neighbours are darker,
 * each pixel against the average of the 5×5 blocks around its own.
 */
function localThreshold(g: Uint8Array, w: number, h: number): Bits {
  const B = 8;
  const sw = Math.ceil(w / B);
  const sh = Math.ceil(h / B);
  const points = new Float64Array(sw * sh);
  for (let by = 0; by < sh; by++) {
    const y0 = Math.min(by * B, h - B);
    for (let bx = 0; bx < sw; bx++) {
      const x0 = Math.min(bx * B, w - B);
      let sum = 0;
      let min = 255;
      let max = 0;
      for (let y = y0; y < y0 + B; y++) {
        for (let x = x0; x < x0 + B; x++) {
          const p = g[y * w + x]!;
          sum += p;
          if (p < min) min = p;
          if (p > max) max = p;
        }
      }
      let avg = sum / (B * B);
      if (max - min <= 24) {
        avg = min / 2;
        if (by > 0 && bx > 0) {
          const near = (points[(by - 1) * sw + bx]! + 2 * points[by * sw + bx - 1]! + points[(by - 1) * sw + bx - 1]!) / 4;
          if (min < near) avg = near;
        }
      }
      points[by * sw + bx] = avg;
    }
  }
  const d = new Uint8Array(w * h);
  for (let by = 0; by < sh; by++) {
    const y0 = Math.min(by * B, h - B);
    const top = Math.min(Math.max(by, 2), sh - 3);
    for (let bx = 0; bx < sw; bx++) {
      const x0 = Math.min(bx * B, w - B);
      const side = Math.min(Math.max(bx, 2), sw - 3);
      let sum = 0;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) sum += points[(top + dy) * sw + side + dx]!;
      const t = sum / 25;
      for (let y = y0; y < y0 + B; y++) for (let x = x0; x < x0 + B; x++) d[y * w + x] = g[y * w + x]! <= t ? 1 : 0;
    }
  }
  return { w, h, d };
}

/** One threshold for the whole frame (Otsu's), for small or evenly lit frames. */
function globalThreshold(g: Uint8Array, w: number, h: number): Bits {
  const hist = new Float64Array(256);
  for (const p of g) hist[p]!++;
  const total = g.length;
  let sumAll = 0;
  for (let i = 0; i < 256; i++) sumAll += i * hist[i]!;
  let sumB = 0;
  let wB = 0;
  let best = 0;
  let t = 127;
  for (let i = 0; i < 256; i++) {
    wB += hist[i]!;
    if (wB === 0) continue;
    const wF = total - wB;
    if (wF === 0) break;
    sumB += i * hist[i]!;
    const mB = sumB / wB;
    const mF = (sumAll - sumB) / wF;
    const between = wB * wF * (mB - mF) * (mB - mF);
    if (between > best) {
      best = between;
      t = i;
    }
  }
  const d = new Uint8Array(w * h);
  for (let i = 0; i < g.length; i++) d[i] = g[i]! <= t ? 1 : 0;
  return { w, h, d };
}

// ---- finder patterns ----------------------------------------------------------

interface Finder extends Point {
  size: number;
  count: number;
}

function crossRatio(c: number[]): boolean {
  let total = 0;
  for (const n of c) {
    if (n === 0) return false;
    total += n;
  }
  if (total < 7) return false;
  const m = total / 7;
  const v = m / 2;
  return Math.abs(m - c[0]!) < v && Math.abs(m - c[1]!) < v && Math.abs(3 * m - c[2]!) < 3 * v && Math.abs(m - c[3]!) < v && Math.abs(m - c[4]!) < v;
}

const centerFromEnd = (c: number[], end: number): number => end - c[4]! - c[3]! - c[2]! / 2;

/** Along one line through (x, y) in direction (dx, dy): the pattern's centre on it, or NaN. */
function crossCheck(b: Bits, x: number, y: number, dx: number, dy: number, maxCount: number, originalTotal: number): number {
  const c = [0, 0, 0, 0, 0];
  const at = (k: number): boolean | null => {
    const px = x + dx * k;
    const py = y + dy * k;
    if (px < 0 || py < 0 || px >= b.w || py >= b.h) return null;
    return dark(b, px, py);
  };
  let k = 0;
  while (at(k) === true) c[2]!++, k--;
  if (at(k) === null) return NaN;
  while (at(k) === false && c[1]! <= maxCount) c[1]!++, k--;
  if (at(k) === null || c[1]! > maxCount) return NaN;
  while (at(k) === true && c[0]! <= maxCount) c[0]!++, k--;
  if (c[0]! > maxCount) return NaN;
  k = 1;
  while (at(k) === true) c[2]!++, k++;
  if (at(k) === null) return NaN;
  while (at(k) === false && c[3]! < maxCount) c[3]!++, k++;
  if (at(k) === null || c[3]! >= maxCount) return NaN;
  while (at(k) === true && c[4]! < maxCount) c[4]!++, k++;
  if (c[4]! >= maxCount) return NaN;
  const total = c.reduce((s, n) => s + n, 0);
  if (5 * Math.abs(total - originalTotal) >= 2 * originalTotal) return NaN;
  return crossRatio(c) ? centerFromEnd(c, k) : NaN;
}

/** Every finder pattern seen: rows scanned for 1:1:3:1:1, checked down and across. */
function findFinders(b: Bits): Finder[] {
  const found: Finder[] = [];
  const skip = b.h > 360 ? 2 : 1;
  const consider = (c: number[], y: number, end: number) => {
    const total = c.reduce((s, n) => s + n, 0);
    let cx = centerFromEnd(c, end);
    const cy = crossCheck(b, Math.floor(cx), y, 0, 1, c[2]!, total);
    if (Number.isNaN(cy)) return;
    // Vertically: the offset found is relative to y.
    const yy = y + cy;
    const hx = crossCheck(b, Math.floor(cx), Math.floor(yy), 1, 0, c[2]!, total);
    if (Number.isNaN(hx)) return;
    cx = Math.floor(cx) + hx;
    const size = total / 7;
    for (const f of found) {
      if (Math.abs(yy - f.y) <= size && Math.abs(cx - f.x) <= size) {
        const diff = Math.abs(size - f.size);
        if (diff <= 1 || diff <= f.size) {
          const n = f.count + 1;
          f.x = (f.x * f.count + cx) / n;
          f.y = (f.y * f.count + yy) / n;
          f.size = (f.size * f.count + size) / n;
          f.count = n;
          return;
        }
      }
    }
    found.push({ x: cx, y: yy, size, count: 1 });
  };
  for (let y = skip - 1; y < b.h; y += skip) {
    const c = [0, 0, 0, 0, 0];
    let state = 0;
    for (let x = 0; x < b.w; x++) {
      if (dark(b, x, y)) {
        if ((state & 1) === 1) state++;
        c[state]!++;
      } else if ((state & 1) === 0) {
        if (state === 4) {
          if (crossRatio(c)) consider(c, y, x);
          c[0] = c[2]!;
          c[1] = c[3]!;
          c[2] = c[4]!;
          c[3] = 1;
          c[4] = 0;
          state = 3;
        } else {
          state++;
          c[state]!++;
        }
      } else {
        c[state]!++;
      }
    }
    if (state === 4 && crossRatio(c)) consider(c, y, b.w);
  }
  return found;
}

const dist = (a: Point, b: Point): number => Math.hypot(a.x - b.x, a.y - b.y);

/** Three patterns as top left, top right and bottom left (the right angle at the top left). */
function order(p: [Finder, Finder, Finder]): [Finder, Finder, Finder] {
  const [p0, p1, p2] = p;
  const d01 = dist(p0, p1);
  const d12 = dist(p1, p2);
  const d02 = dist(p0, p2);
  let a: Finder;
  let tl: Finder;
  let c: Finder;
  if (d12 >= d01 && d12 >= d02) [tl, a, c] = [p0, p1, p2];
  else if (d02 >= d12 && d02 >= d01) [tl, a, c] = [p1, p0, p2];
  else [tl, a, c] = [p2, p0, p1];
  // a is bottom left and c top right when turning from c to a about tl is clockwise on screen.
  if ((c.x - tl.x) * (a.y - tl.y) - (c.y - tl.y) * (a.x - tl.x) < 0) [a, c] = [c, a];
  return [tl, c, a];
}

/** Likely triples of patterns: similar sizes, a right isosceles triangle; best first. */
function triples(found: Finder[]): [Finder, Finder, Finder][] {
  const top = [...found].sort((a, b) => b.count - a.count).slice(0, 12);
  const out: { t: [Finder, Finder, Finder]; score: number }[] = [];
  for (let i = 0; i < top.length; i++) {
    for (let j = i + 1; j < top.length; j++) {
      for (let k = j + 1; k < top.length; k++) {
        const t = order([top[i]!, top[j]!, top[k]!]);
        const sizes = t.map((f) => f.size);
        const ratio = Math.max(...sizes) / Math.min(...sizes);
        if (ratio > 1.6) continue;
        const [tl, tr, bl] = t;
        const a = dist(tl, tr);
        const b = dist(tl, bl);
        const size = (sizes[0]! + sizes[1]! + sizes[2]!) / 3;
        // At least version 1 apart (14 modules between centres), at most 40's.
        if (Math.min(a, b) < 10 * size || Math.max(a, b) > 180 * size) continue;
        const sides = Math.abs(a - b) / Math.max(a, b);
        const hyp = Math.abs(dist(tr, bl) - Math.hypot(a, b)) / Math.hypot(a, b);
        if (sides > 0.5 || hyp > 0.4) continue;
        out.push({ t, score: sides + hyp + (ratio - 1) - Math.min(t[0].count, t[1].count, t[2].count) / 1000 });
      }
    }
  }
  return out.sort((x, y) => x.score - y.score).map((x) => x.t);
}

// ---- geometry -----------------------------------------------------------------

/** From a black-white-black run along a line from (x0, y0) toward (x1, y1): its length, or NaN. */
function runLength(b: Bits, x0: number, y0: number, x1: number, y1: number): number {
  let fromX = Math.floor(x0);
  let fromY = Math.floor(y0);
  let toX = Math.floor(x1);
  let toY = Math.floor(y1);
  const steep = Math.abs(toY - fromY) > Math.abs(toX - fromX);
  if (steep) [fromX, fromY, toX, toY] = [fromY, fromX, toY, toX];
  const dx = Math.abs(toX - fromX);
  const dy = Math.abs(toY - fromY);
  let error = -dx / 2;
  const xstep = fromX < toX ? 1 : -1;
  const ystep = fromY < toY ? 1 : -1;
  let state = 0;
  const xLimit = toX + xstep;
  for (let x = fromX, y = fromY; x !== xLimit; x += xstep) {
    const rx = steep ? y : x;
    const ry = steep ? x : y;
    if (rx < 0 || ry < 0 || rx >= b.w || ry >= b.h) return NaN;
    if ((state === 1) === dark(b, rx, ry)) {
      if (state === 2) return Math.hypot(x - fromX, y - fromY);
      state++;
    }
    error += dy;
    if (error > 0) {
      if (y === toY) break;
      y += ystep;
      error -= dx;
    }
  }
  return state === 2 ? Math.hypot(toX + xstep - fromX, toY - fromY) : NaN;
}

/** A finder pattern's width (7 modules) measured toward another point and away from it. */
function runBothWays(b: Bits, from: Point, to: Point): number {
  let r = runLength(b, from.x, from.y, to.x, to.y);
  let scale = 1;
  let ox = from.x - (to.x - from.x);
  if (ox < 0) {
    scale = from.x / (from.x - ox);
    ox = 0;
  } else if (ox >= b.w) {
    scale = (b.w - 1 - from.x) / (ox - from.x);
    ox = b.w - 1;
  }
  let oy = from.y - (to.y - from.y) * scale;
  scale = 1;
  if (oy < 0) {
    scale = from.y / (from.y - oy);
    oy = 0;
  } else if (oy >= b.h) {
    scale = (b.h - 1 - from.y) / (oy - from.y);
    oy = b.h - 1;
  }
  ox = from.x + (ox - from.x) * scale;
  r += runLength(b, from.x, from.y, ox, oy);
  return r - 1;
}

function moduleSizeOneWay(b: Bits, p: Point, q: Point): number {
  const a = runBothWays(b, p, q);
  const c = runBothWays(b, q, p);
  if (Number.isNaN(a)) return c / 7;
  if (Number.isNaN(c)) return a / 7;
  return (a + c) / 14;
}

/** A projective map from the code's module coordinates to the frame's pixels. */
export type Homography = (u: number, v: number) => Point;

/** The projective map taking four points `from` to four points `to` (solved directly). */
export function homography(from: Point[], to: Point[]): Homography | null {
  // h0..h7: x = (h0 u + h1 v + h2) / (h6 u + h7 v + 1), y = (h3 u + h4 v + h5) / (…).
  const m: number[][] = [];
  for (let i = 0; i < 4; i++) {
    const { x: u, y: v } = from[i]!;
    const { x, y } = to[i]!;
    m.push([u, v, 1, 0, 0, 0, -u * x, -v * x, x]);
    m.push([0, 0, 0, u, v, 1, -u * y, -v * y, y]);
  }
  for (let c = 0; c < 8; c++) {
    let p = c;
    for (let r = c + 1; r < 8; r++) if (Math.abs(m[r]![c]!) > Math.abs(m[p]![c]!)) p = r;
    if (Math.abs(m[p]![c]!) < 1e-12) return null;
    [m[c], m[p]] = [m[p]!, m[c]!];
    const row = m[c]!;
    for (let r = 0; r < 8; r++) {
      if (r === c) continue;
      const f = m[r]![c]! / row[c]!;
      if (f === 0) continue;
      for (let k = c; k < 9; k++) m[r]![k]! -= f * row[k]!;
    }
  }
  const h = m.map((row, i) => row[8]! / row[i]!);
  const [h0, h1, h2, h3, h4, h5, h6, h7] = h as [number, number, number, number, number, number, number, number];
  return (u, v) => {
    const z = h6 * u + h7 * v + 1;
    return { x: (h0 * u + h1 * v + h2) / z, y: (h3 * u + h4 * v + h5) / z };
  };
}

/**
 * The bottom-right alignment pattern near where the finders put it: the
 * best match of its 5×5 modules (dark centre, light ring, dark ring) in a
 * widening window, nearest the estimate among equals.
 */
function findAlignment(b: Bits, est: Point, ux: Point, uy: Point, size: number): Point | null {
  // How many of the 25 modules match (any count under 23 is as good as none:
  // given up after three misses).
  const score = (px: number, py: number): number => {
    let s = 0;
    let misses = 0;
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        const x = Math.floor(px + dx * ux.x + dy * uy.x);
        const y = Math.floor(py + dx * ux.y + dy * uy.y);
        if (x < 0 || y < 0 || x >= b.w || y >= b.h) return -1;
        if (dark(b, x, y) === (Math.max(Math.abs(dx), Math.abs(dy)) !== 1)) s++;
        else if (++misses > 2) return 0;
      }
    }
    return s;
  };
  for (const allowance of [4, 8, 16]) {
    const r = allowance * size;
    const step = Math.max(1, Math.floor(size / 3));
    let best = -1;
    let at: Point | null = null;
    let bestD = Infinity;
    for (let y = est.y - r; y <= est.y + r; y += step) {
      for (let x = est.x - r; x <= est.x + r; x += step) {
        const s = score(x, y);
        const d = Math.hypot(x - est.x, y - est.y);
        if (s > best || (s === best && d < bestD)) {
          best = s;
          bestD = d;
          at = { x, y };
        }
      }
    }
    if (!at || best < 23) continue;
    // Refined: the middle of the best matches near the one found.
    let sx = 0;
    let sy = 0;
    let n = 0;
    const local = Math.ceil(size);
    let top = -1;
    for (let y = Math.floor(at.y - local); y <= at.y + local; y++) for (let x = Math.floor(at.x - local); x <= at.x + local; x++) top = Math.max(top, score(x, y));
    for (let y = Math.floor(at.y - local); y <= at.y + local; y++) {
      for (let x = Math.floor(at.x - local); x <= at.x + local; x++) {
        if (score(x, y) === top) {
          sx += x;
          sy += y;
          n++;
        }
      }
    }
    return { x: sx / n + 0.5, y: sy / n + 0.5 };
  }
  return null;
}

/** The grid of `dim` modules under a map, or null when it leaves the frame. */
function sample(b: Bits, dim: number, map: Homography): boolean[][] | null {
  const out: boolean[][] = [];
  for (let r = 0; r < dim; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < dim; c++) {
      const p = map(c + 0.5, r + 0.5);
      let x = Math.floor(p.x);
      let y = Math.floor(p.y);
      if (x < -2 || y < -2 || x > b.w + 1 || y > b.h + 1 || Number.isNaN(x) || Number.isNaN(y)) return null;
      x = Math.min(Math.max(x, 0), b.w - 1);
      y = Math.min(Math.max(y, 0), b.h - 1);
      row.push(dark(b, x, y));
    }
    out.push(row);
  }
  return out;
}

/** The code three finder patterns frame, tried at the likely sizes; null when none reads. */
function decodeAt(b: Bits, t: [Finder, Finder, Finder]): Uint8Array | null {
  const [tl, tr, bl] = t;
  let size = (moduleSizeOneWay(b, tl, tr) + moduleSizeOneWay(b, tl, bl)) / 2;
  if (!(size >= 1)) size = (tl.size + tr.size + bl.size) / 3;
  const across = (Math.round(dist(tl, tr) / size) + Math.round(dist(tl, bl) / size)) / 2 + 7;
  const near = Math.round((across - 1) / 4) * 4 + 1;
  const dims = [near, near - 4, near + 4, near - 8, near + 8].filter((d) => d >= 21 && d <= 177);
  const tried = new Set<number>();
  while (dims.length) {
    const dim = dims.shift()!;
    if (tried.has(dim)) continue;
    tried.add(dim);
    const ver = (dim - 17) / 4;
    const between = dim - 7;
    const ux = { x: (tr.x - tl.x) / between, y: (tr.y - tl.y) / between };
    const uy = { x: (bl.x - tl.x) / between, y: (bl.y - tl.y) / between };
    const corners = [
      { x: 3.5, y: 3.5 },
      { x: dim - 3.5, y: 3.5 },
      { x: 3.5, y: dim - 3.5 },
    ];
    const guess = { x: tr.x + bl.x - tl.x, y: tr.y + bl.y - tl.y };
    const parallelogram = homography([...corners, { x: dim - 3.5, y: dim - 3.5 }], [tl, tr, bl, guess]);
    // The version and format information sit by the finders, where any map
    // is close: a wrong size is put right, or skipped, before the search
    // for the alignment pattern.
    const first = parallelogram && sample(b, dim, parallelogram);
    if (!first) continue;
    // Version 7 and up says its version: a wrong guess is resampled.
    if (ver >= 7) {
      const said = readVersion(first);
      if (said && said !== ver) {
        if (!tried.has(said * 4 + 17)) dims.unshift(said * 4 + 17);
        continue;
      }
    }
    if (!readFormat(first)) continue;
    const grids: (() => boolean[][] | null)[] = [];
    let aligned = false;
    if (ver >= 2) {
      const est = { x: tl.x + (between - 3) * (ux.x + uy.x), y: tl.y + (between - 3) * (ux.y + uy.y) };
      const al = findAlignment(b, est, ux, uy, size);
      const m = al && homography([...corners, { x: dim - 6.5, y: dim - 6.5 }], [tl, tr, bl, al]);
      if (m) {
        aligned = true;
        grids.push(() => sample(b, dim, m));
      }
    }
    // Without an alignment pattern the fourth corner is guessed: where a
    // parallelogram puts it, then (a slanted version 1 or 2) the points around it.
    grids.push(() => first);
    if (!aligned && ver <= 2) {
      const offsets: [number, number][] = [];
      for (let dy = -3; dy <= 3; dy++) for (let dx = -3; dx <= 3; dx++) if (dx || dy) offsets.push([dx / 2, dy / 2]);
      offsets.sort((p, q) => Math.hypot(...p) - Math.hypot(...q));
      for (const [dx, dy] of offsets) {
        const m = homography([...corners, { x: dim - 3.5, y: dim - 3.5 }], [tl, tr, bl, { x: guess.x + dx * ux.x + dy * uy.x, y: guess.y + dx * ux.y + dy * uy.y }]);
        if (m) grids.push(() => sample(b, dim, m));
      }
    }
    for (const grid of grids) {
      const g = grid();
      const bytes = g && decodeGrid(g);
      if (bytes) return bytes;
    }
  }
  return null;
}

// ---- the symbol ---------------------------------------------------------------

const popcount = (x: number): number => {
  let n = 0;
  for (; x; x &= x - 1) n++;
  return n;
};

const FORMATS: { bits: number; level: Level; mask: number }[] = [];
for (const level of ["L", "M", "Q", "H"] as const) {
  for (let mask = 0; mask < 8; mask++) {
    const data = (FORMAT_BITS[level] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    FORMATS.push({ bits: ((data << 10) | rem) ^ 0x5412, level, mask });
  }
}

/** Format information: both copies, the nearest valid code (up to 3 bits wrong). */
function readFormat(g: boolean[][]): { level: Level; mask: number } | null {
  const n = g.length;
  const at = (x: number, y: number): number => (g[y]![x] ? 1 : 0);
  let a = 0;
  let b = 0;
  for (let i = 0; i <= 5; i++) a |= at(8, i) << i;
  a |= at(8, 7) << 6;
  a |= at(8, 8) << 7;
  a |= at(7, 8) << 8;
  for (let i = 9; i < 15; i++) a |= at(14 - i, 8) << i;
  for (let i = 0; i < 8; i++) b |= at(n - 1 - i, 8) << i;
  for (let i = 8; i < 15; i++) b |= at(8, n - 15 + i) << i;
  let best: (typeof FORMATS)[number] | null = null;
  let bestD = 4;
  for (const f of FORMATS) {
    const d = Math.min(popcount(f.bits ^ a), popcount(f.bits ^ b));
    if (d < bestD) {
      bestD = d;
      best = f;
    }
  }
  return best && { level: best.level, mask: best.mask };
}

/** Version information (7 and up): both copies, the nearest valid code. */
function readVersion(g: boolean[][]): number | null {
  const n = g.length;
  let a = 0;
  let b = 0;
  for (let i = 0; i < 18; i++) {
    const p = n - 11 + (i % 3);
    const q = Math.floor(i / 3);
    if (g[q]?.[p]) a |= 1 << i;
    if (g[p]?.[q]) b |= 1 << i;
  }
  let best: number | null = null;
  let bestD = 4;
  for (let v = 7; v <= 40; v++) {
    let rem = v;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (v << 12) | rem;
    const d = Math.min(popcount(bits ^ a), popcount(bits ^ b));
    if (d < bestD) {
      bestD = d;
      best = v;
    }
  }
  return best;
}

function masked(m: number, x: number, y: number): boolean {
  switch (m) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

/** The payload of a code's modules (rows, dark when true, no quiet zone), or null. */
export function decodeGrid(g: boolean[][]): Uint8Array | null {
  const n = g.length;
  if (n < 21 || n > 177 || (n - 17) % 4 !== 0 || g.some((row) => row.length !== n)) return null;
  const ver = (n - 17) / 4;
  const format = readFormat(g);
  if (!format) return null;
  const fixed = functionModules(ver);
  // The codewords, in the zigzag the encoder wrote them.
  const raw = Math.floor(rawModules(ver) / 8);
  const words = new Uint8Array(raw);
  let i = 0;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < n; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? n - 1 - vert : vert;
        if (fixed[y]![x] || i >= raw * 8) continue;
        if (g[y]![x] !== masked(format.mask, x, y)) words[i >>> 3]! |= 0x80 >>> (i & 7);
        i++;
      }
    }
  }
  // The blocks, de-interleaved: short blocks first, each with its error correction.
  const blocks = BLOCKS[format.level][ver]!;
  const ecc = ECC[format.level][ver]!;
  const shortBlocks = blocks - (raw % blocks);
  const shortLen = Math.floor(raw / blocks);
  const lists: number[][] = Array.from({ length: blocks }, () => []);
  let k = 0;
  for (let p = 0; p <= shortLen; p++) {
    for (let j = 0; j < blocks; j++) {
      if (p === shortLen - ecc && j < shortBlocks) continue;
      lists[j]!.push(words[k++]!);
    }
  }
  const data: number[] = [];
  for (const block of lists) {
    const fixedBlock = correct(Uint8Array.from(block), ecc);
    if (!fixedBlock) return null;
    for (let p = 0; p < block.length - ecc; p++) data.push(fixedBlock[p]!);
  }
  return segments(data, ver);
}

// ---- Reed-Solomon over GF(256), 0x11D ------------------------------------------

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
}
const gmul = (a: number, b: number): number => (a && b ? EXP[LOG[a]! + LOG[b]!]! : 0);
const ginv = (a: number): number => EXP[255 - LOG[a]!]!;
/** A polynomial (lowest power first) at x. */
const evalPoly = (p: number[], x: number): number => {
  let y = 0;
  for (let i = p.length - 1; i >= 0; i--) y = gmul(y, x) ^ p[i]!;
  return y;
};

function syndromes(r: Uint8Array, ecc: number): number[] {
  const n = r.length;
  const s: number[] = [];
  for (let j = 0; j < ecc; j++) {
    // r(α^j), r[0] the highest power.
    let y = 0;
    const a = EXP[j % 255]!;
    for (let i = 0; i < n; i++) y = gmul(y, a) ^ r[i]!;
    s.push(y);
  }
  return s;
}

/**
 * A block (data then `ecc` error-correction codewords) with its errors
 * corrected, up to ecc/2 of them; null when there are more (as far as can
 * be told). Berlekamp-Massey for the locator, Chien's search, Forney.
 */
export function correct(block: Uint8Array, ecc: number): Uint8Array | null {
  const n = block.length;
  const s = syndromes(block, ecc);
  if (s.every((x) => x === 0)) return block;
  let c = [1];
  let prev = [1];
  let l = 0;
  let shift = 1;
  let last = 1;
  for (let r = 0; r < ecc; r++) {
    let d = s[r]!;
    for (let i = 1; i <= l; i++) d ^= gmul(c[i] ?? 0, s[r - i]!);
    if (d === 0) {
      shift++;
      continue;
    }
    const coef = gmul(d, ginv(last));
    const next = c.slice();
    for (let i = 0; i < prev.length; i++) {
      while (next.length <= i + shift) next.push(0);
      next[i + shift]! ^= gmul(coef, prev[i]!);
    }
    if (2 * l <= r) {
      l = r + 1 - l;
      prev = c;
      last = d;
      shift = 1;
    } else {
      shift++;
    }
    c = next;
  }
  while (c.length > 1 && c[c.length - 1] === 0) c.pop();
  if (l * 2 > ecc || c.length - 1 !== l) return null;
  // Ω = S Λ mod x^ecc; Λ' the formal derivative.
  const omega = new Array<number>(ecc).fill(0);
  for (let i = 0; i < ecc; i++) for (let j = 0; j < c.length && i + j < ecc; j++) omega[i + j]! ^= gmul(s[i]!, c[j]!);
  const deriv: number[] = [];
  for (let i = 1; i < c.length; i++) deriv.push(i % 2 === 1 ? c[i]! : 0);
  const out = Uint8Array.from(block);
  let found = 0;
  for (let i = 0; i < n; i++) {
    const power = n - 1 - i;
    const xinv = EXP[(255 - (power % 255)) % 255]!;
    if (evalPoly(c, xinv) !== 0) continue;
    const den = evalPoly(deriv, xinv);
    if (den === 0) return null;
    out[i]! ^= gmul(EXP[power % 255]!, gmul(evalPoly(omega, xinv), ginv(den)));
    found++;
  }
  if (found !== l) return null;
  return syndromes(out, ecc).every((x) => x === 0) ? out : null;
}

// ---- segments -----------------------------------------------------------------

const ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/** The data codewords' segments as bytes (digits and letters as ASCII). */
function segments(data: number[], ver: number): Uint8Array | null {
  const total = data.length * 8;
  let at = 0;
  const read = (n: number): number | null => {
    if (at + n > total) return null;
    let v = 0;
    for (let i = 0; i < n; i++, at++) v = (v << 1) | ((data[at >>> 3]! >>> (7 - (at & 7))) & 1);
    return v;
  };
  const size = ver <= 9 ? 0 : ver <= 26 ? 1 : 2;
  const out: number[] = [];
  for (;;) {
    if (total - at < 4) break;
    const mode = read(4)!;
    if (mode === 0) break;
    if (mode === 0b0100) {
      const count = read([8, 16, 16][size]!);
      if (count === null) return null;
      for (let i = 0; i < count; i++) {
        const b = read(8);
        if (b === null) return null;
        out.push(b);
      }
    } else if (mode === 0b0001) {
      let count = read([10, 12, 14][size]!);
      if (count === null) return null;
      while (count > 0) {
        const digits = Math.min(count, 3);
        const v = read([0, 4, 7, 10][digits]!);
        if (v === null) return null;
        for (const ch of String(v).padStart(digits, "0")) out.push(ch.charCodeAt(0));
        count -= digits;
      }
    } else if (mode === 0b0010) {
      let count = read([9, 11, 13][size]!);
      if (count === null) return null;
      while (count > 0) {
        if (count >= 2) {
          const v = read(11);
          if (v === null || v >= 45 * 45) return null;
          out.push(ALNUM.charCodeAt(Math.floor(v / 45)), ALNUM.charCodeAt(v % 45));
          count -= 2;
        } else {
          const v = read(6);
          if (v === null || v >= 45) return null;
          out.push(ALNUM.charCodeAt(v));
          count--;
        }
      }
    } else if (mode === 0b1000) {
      // Kanji, back to Shift JIS.
      const count = read([8, 10, 12][size]!);
      if (count === null) return null;
      for (let i = 0; i < count; i++) {
        const v = read(13);
        if (v === null) return null;
        const two = (Math.floor(v / 0xc0) << 8) | v % 0xc0;
        const sj = two + (two < 0x1f00 ? 0x8140 : 0xc140);
        out.push(sj >> 8, sj & 0xff);
      }
    } else if (mode === 0b0111) {
      // ECI: its designator is skipped (the bytes are what they are).
      const first = read(8);
      if (first === null) return null;
      if ((first & 0xc0) === 0x80) read(8);
      else if ((first & 0xe0) === 0xc0) read(16);
    } else if (mode === 0b0011) {
      read(16);
    } else if (mode === 0b0101) {
      // FNC1, first position: nothing to read.
    } else if (mode === 0b1001) {
      read(8);
    } else {
      return null;
    }
  }
  return Uint8Array.from(out);
}

// ---- the frame ----------------------------------------------------------------

/** The bytes of the QR code in a frame, or null when none is read. */
export function decodeQr(frame: Frame): Uint8Array | null {
  const { width: w, height: h } = frame;
  if (w < 21 || h < 21) return null;
  const g = luminance(frame);
  const ways = w >= 40 && h >= 40 ? [localThreshold, globalThreshold] : [globalThreshold];
  for (const way of ways) {
    const b = way(g, w, h);
    for (const t of triples(findFinders(b)).slice(0, 8)) {
      const bytes = decodeAt(b, t);
      if (bytes) return bytes;
    }
  }
  return null;
}
