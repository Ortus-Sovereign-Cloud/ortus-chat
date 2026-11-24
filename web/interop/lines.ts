// One JSON object per line over stdin and stdout, shared by the end-to-end
// peer and its stand-in for ortus-kit (one reader for both).
import { createInterface } from "node:readline";

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();

export async function next(): Promise<Record<string, any>> {
  const r = await lines.next();
  if (r.done) throw new Error("stdin closed");
  return JSON.parse(r.value);
}

export function say(v: unknown): void {
  process.stdout.write(JSON.stringify(v) + "\n");
}
