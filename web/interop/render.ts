// A QR code's modules drawn as a camera might see them, for the scanner's
// tests: a quiet zone, a scale, a turn, a perspective, noise, on a grey
// background; RGBA, as a canvas gives. Plain TypeScript (Node runs it).
import { homography, type Frame } from "../src/qrscan.ts";

export interface Look {
  /** Pixels per module. */
  scale: number;
  /** Degrees. */
  angle?: number;
  /** How far each corner moves (a fraction of the code's side). */
  skew?: number;
  /** Up to this much added to or taken from each pixel. */
  noise?: number;
  seed?: number;
}

/** A small deterministic generator (mulberry32). */
export function random(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function render(modules: boolean[][], look: Look): Frame {
  const rnd = random(look.seed ?? 1);
  const quiet = 4;
  const n = modules.length;
  const side = n + 2 * quiet;
  const px = side * look.scale;
  const size = Math.ceil(px * 1.5);
  const c = size / 2;
  const turn = ((look.angle ?? 0) * Math.PI) / 180;
  const skew = (look.skew ?? 0) * px;
  // The code's corners on the frame: turned about the middle, each moved a little.
  const corners = [
    [-1, -1],
    [1, -1],
    [1, 1],
    [-1, 1],
  ].map(([sx, sy]) => {
    const x = (sx! * px) / 2;
    const y = (sy! * px) / 2;
    return {
      x: c + x * Math.cos(turn) - y * Math.sin(turn) + (rnd() * 2 - 1) * skew,
      y: c + x * Math.sin(turn) + y * Math.cos(turn) + (rnd() * 2 - 1) * skew,
    };
  });
  const back = homography(corners, [
    { x: 0, y: 0 },
    { x: side, y: 0 },
    { x: side, y: side },
    { x: 0, y: side },
  ]);
  if (!back) throw new Error("degenerate");
  const data = new Uint8ClampedArray(size * size * 4);
  const noise = look.noise ?? 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      // Four samples a pixel: edges come out grey, as a lens makes them.
      let v = 0;
      for (const [ox, oy] of [
        [0.25, 0.25],
        [0.75, 0.25],
        [0.25, 0.75],
        [0.75, 0.75],
      ]) {
        const p = back(x + ox!, y + oy!);
        let shade = 150 + (40 * y) / size; // the background, lit unevenly
        if (p.x >= 0 && p.y >= 0 && p.x < side && p.y < side) {
          const mx = Math.floor(p.x) - quiet;
          const my = Math.floor(p.y) - quiet;
          shade = modules[my]?.[mx] ? 35 : 225;
        }
        v += shade / 4;
      }
      v += (rnd() * 2 - 1) * noise;
      const i = (y * size + x) * 4;
      data[i] = data[i + 1] = data[i + 2] = v;
      data[i + 3] = 255;
    }
  }
  return { width: size, height: size, data };
}
