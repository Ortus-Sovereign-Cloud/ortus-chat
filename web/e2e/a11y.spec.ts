// WCAG 2.2 AA with axe on chat: desktop and phone, light and dark. One
// test, one page: chat allows a person only a few live streams at once.
// The page's CSP forbids inline scripts; the test bypasses it to put axe in.
import { expect, test } from "@playwright/test";
import { axe } from "./axe.js";

test.use({ bypassCSP: true });

test("chat passes axe: desktop and phone, light and dark", async ({ page }) => {
  const failures: string[] = [];
  for (const [name, size] of [["desktop", { width: 1440, height: 900 }], ["phone", { width: 390, height: 844 }]] as const) {
    for (const scheme of ["light", "dark"] as const) {
      await page.setViewportSize(size);
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto("/chat");
      // Live streams keep the network busy: wait for the screen instead.
      await page.locator("main#content > *").first().waitFor();
      await page.waitForTimeout(1000);
      failures.push(...(await axe(page)).map((f) => `${name} ${scheme}: ${f}`));
    }
  }
  expect(failures).toEqual([]);
});
