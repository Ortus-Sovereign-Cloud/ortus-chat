// QR codes for verification (ISO/IEC 18004): bytes in byte mode, error
// correction level M (the others for tests), the smallest version that
// holds them, the mask with the lowest penalty. Written here (no dependency
// in the web client, as olm.ts); the phones' tests read its codes back with
// an independent decoder, and qrscan.ts reads codes with the same tables.
// No DOM: plain TypeScript, so Node runs it.

export type Level = "L" | "M" | "Q" | "H";

/** Error-correction codewords per block, by level and version (1–40). */
export const ECC: Record<Level, readonly number[]> = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
};
/** Error-correction blocks, by level and version. */
export const BLOCKS: Record<Level, readonly number[]> = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
};
/** Each level's two format bits. */
export const FORMAT_BITS: Record<Level, number> = { L: 1, M: 0, Q: 3, H: 2 };

/** The modules that hold data and error correction (with the remainder bits). */
export function rawModules(ver: number): number {
  let n = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const align = Math.floor(ver / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (ver >= 7) n -= 36;
  }
  return n;
}

function dataCodewords(ver: number, level: Level): number {
  return Math.floor(rawModules(ver) / 8) - ECC[level][ver]! * BLOCKS[level][ver]!;
}

function alignmentPositions(ver: number): number[] {
  if (ver === 1) return [];
  const align = Math.floor(ver / 7) + 2;
  const size = ver * 4 + 17;
  const step = Math.floor((ver * 8 + align * 3 + 5) / (align * 4 - 4)) * 2;
  const out = [6];
  for (let pos = size - 7; out.length < align; pos -= step) out.splice(1, 0, pos);
  return out;
}

// ---- Reed-Solomon over GF(2^8), polynomial 0x11D ----------------------------

function mul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function divisor(degree: number): number[] {
  const out = new Array<number>(degree).fill(0);
  out[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < out.length; j++) {
      out[j] = mul(out[j]!, root);
      if (j + 1 < out.length) out[j]! ^= out[j + 1]!;
    }
    root = mul(root, 0x02);
  }
  return out;
}

function remainder(data: number[], div: number[]): number[] {
  const out = div.map(() => 0);
  for (const b of data) {
    const factor = b ^ (out.shift() as number);
    out.push(0);
    div.forEach((c, i) => (out[i] = out[i]! ^ mul(c, factor)));
  }
  return out;
}

// ---- the symbol --------------------------------------------------------------

class Grid {
  readonly ver: number;
  readonly size: number;
  readonly dark: boolean[][];
  readonly fixed: boolean[][];
  readonly level: Level;

  constructor(ver: number, level: Level = "M") {
    this.ver = ver;
    this.level = level;
    this.size = ver * 4 + 17;
    this.dark = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.fixed = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }

  set(x: number, y: number, dark: boolean): void {
    this.dark[y]![x] = dark;
    this.fixed[y]![x] = true;
  }

  patterns(): void {
    const n = this.size;
    for (let i = 0; i < n; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    for (const [cx, cy] of [[3, 3], [n - 4, 3], [3, n - 4]] as const) {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const x = cx + dx;
          const y = cy + dy;
          const d = Math.max(Math.abs(dx), Math.abs(dy));
          if (x >= 0 && x < n && y >= 0 && y < n) this.set(x, y, d !== 2 && d !== 4);
        }
      }
    }
    const pos = alignmentPositions(this.ver);
    const last = pos.length - 1;
    pos.forEach((px, i) =>
      pos.forEach((py, j) => {
        if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
        for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) this.set(px + dx, py + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }),
    );
    this.format(0);
    this.version();
  }

  format(mask: number): void {
    const data = (FORMAT_BITS[this.level] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const bit = (i: number) => ((bits >>> i) & 1) !== 0;
    const n = this.size;
    for (let i = 0; i <= 5; i++) this.set(8, i, bit(i));
    this.set(8, 7, bit(6));
    this.set(8, 8, bit(7));
    this.set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) this.set(n - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) this.set(8, n - 15 + i, bit(i));
    this.set(8, n - 8, true);
  }

  version(): void {
    if (this.ver < 7) return;
    let rem = this.ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0;
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, dark);
      this.set(b, a, dark);
    }
  }

  codewords(data: number[]): void {
    const n = this.size;
    let i = 0;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < n; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? n - 1 - vert : vert;
          if (!this.fixed[y]![x] && i < data.length * 8) {
            this.dark[y]![x] = ((data[i >>> 3]! >>> (7 - (i & 7))) & 1) !== 0;
            i++;
          }
        }
      }
    }
  }

  mask(m: number): void {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (this.fixed[y]![x]) continue;
        const flip = [
          (x + y) % 2 === 0,
          y % 2 === 0,
          x % 3 === 0,
          (x + y) % 3 === 0,
          (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
          ((x * y) % 2) + ((x * y) % 3) === 0,
          (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
          (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
        ][m];
        if (flip) this.dark[y]![x] = !this.dark[y]![x];
      }
    }
  }

  /** The standard's penalty: runs, 2×2 blocks, finder-like patterns, balance. */
  penalty(): number {
    const n = this.size;
    let p = 0;
    const lines: boolean[][] = [];
    for (let i = 0; i < n; i++) {
      lines.push(this.dark[i]!);
      lines.push(this.dark.map((row) => row[i]!));
    }
    const finder = [true, false, true, true, true, false, true];
    for (const line of lines) {
      let run = 1;
      for (let i = 1; i <= n; i++) {
        if (i < n && line[i] === line[i - 1]) run++;
        else {
          if (run >= 5) p += 3 + (run - 5);
          run = 1;
        }
      }
      for (let i = 0; i + 7 <= n; i++) {
        if (!finder.every((d, k) => line[i + k] === d)) continue;
        const light = (from: number) => [0, 1, 2, 3].every((k) => from + k < 0 || from + k >= n || !line[from + k]);
        if (light(i - 4)) p += 40;
        if (light(i + 7)) p += 40;
      }
    }
    for (let y = 0; y + 1 < n; y++) {
      for (let x = 0; x + 1 < n; x++) {
        const c = this.dark[y]![x];
        if (c === this.dark[y]![x + 1] && c === this.dark[y + 1]![x] && c === this.dark[y + 1]![x + 1]) p += 3;
      }
    }
    const dark = this.dark.reduce((s, row) => s + row.filter(Boolean).length, 0);
    const total = n * n;
    p += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
    return p;
  }
}

/** Which modules of a version's symbol are its patterns, format and version (not data). */
export function functionModules(ver: number): boolean[][] {
  const g = new Grid(ver);
  g.patterns();
  return g.fixed;
}

/** A QR code of `bytes`: rows of modules, dark when true (no quiet zone). Level M unless asked. */
export function qrCode(bytes: Uint8Array, level: Level = "M"): boolean[][] {
  let ver = 1;
  for (; ver <= 40; ver++) {
    const countBits = ver <= 9 ? 8 : 16;
    if (4 + countBits + bytes.length * 8 <= dataCodewords(ver, level) * 8 && bytes.length < 1 << countBits) break;
  }
  if (ver > 40) throw new Error("too long for a QR code");
  const capacity = dataCodewords(ver, level) * 8;
  const bits: number[] = [];
  const put = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4);
  put(bytes.length, ver <= 9 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, capacity - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  const data: number[] = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  for (let pad = 0xec; data.length < capacity / 8; pad ^= 0xec ^ 0x11) data.push(pad);

  // Blocks, each with its error correction, interleaved.
  const blocks = BLOCKS[level][ver]!;
  const eccLen = ECC[level][ver]!;
  const raw = Math.floor(rawModules(ver) / 8);
  const shortBlocks = blocks - (raw % blocks);
  const shortLen = Math.floor(raw / blocks);
  const div = divisor(eccLen);
  const all: number[][] = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < shortBlocks ? 0 : 1));
    k += dat.length;
    const ecc = remainder(dat, div);
    if (i < shortBlocks) dat.push(0);
    all.push(dat.concat(ecc));
  }
  const out: number[] = [];
  for (let i = 0; i < all[0]!.length; i++) {
    all.forEach((block, j) => {
      if (i !== shortLen - eccLen || j >= shortBlocks) out.push(block[i]!);
    });
  }

  let best: Grid | null = null;
  let bestPenalty = Infinity;
  for (let m = 0; m < 8; m++) {
    const s = new Grid(ver, level);
    s.patterns();
    s.codewords(out);
    s.mask(m);
    s.format(m);
    const p = s.penalty();
    if (p < bestPenalty) {
      best = s;
      bestPenalty = p;
    }
  }
  return (best as Grid).dark.map((row) => [...row]);
}
