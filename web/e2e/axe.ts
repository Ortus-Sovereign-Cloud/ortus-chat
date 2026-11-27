// axe-core (WCAG 2.0–2.2, A and AA) on a page, inside shadow roots too.
// Test-only: axe-core is MPL-2.0 and never ships in the program.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { Page } from "@playwright/test";

const AXE = readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

/** The page's WCAG failures, one line each (empty when it passes). axe
 * goes in by evaluation, which the page's CSP does not stop. */
export async function axe(page: Page): Promise<string[]> {
  if (!(await page.evaluate(() => "axe" in window))) await page.evaluate(AXE);
  return page.evaluate(async (tags) => {
    const run = (window as unknown as { axe: { run: (c: Document, o: object) => Promise<{ violations: { id: string; help: string; nodes: { target: unknown[] }[] }[] }> } }).axe.run;
    const { violations } = await run(document, { runOnly: { type: "tag", values: tags } });
    return violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => JSON.stringify(n.target)).slice(0, 3).join(", ")})`);
  }, TAGS);
}
