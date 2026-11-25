// WCAG 2.2 AA with axe on chat: desktop and phone, light and dark. One
// test, one page: chat allows a person only a few live streams at once.
// The page's CSP forbids inline scripts; the test bypasses it to put axe in.
import { expect, test } from "@playwright/test";
import { axe } from "./axe.js";

test.use({ bypassCSP: true });

test("chat passes axe: desktop and phone, light and dark", async ({ page: owner, browser }) => {
  // A person of its own: chat's live streams are counted per person, and
  // the other tests are the owner.
  const r = await owner.request.post("/api/v1/admin/users", { headers: { "X-Requested-With": "ortus" }, data: { email: `axe-${Date.now()}@ministry.example`, name: "Irena Axe" } });
  expect(r.status()).toBe(200);
  const link = new URL((await r.json()).link);
  const page = await (await browser.newContext({ storageState: { cookies: [], origins: [] }, bypassCSP: true })).newPage();
  await page.goto(link.pathname + link.hash);
  await expect(page).toHaveURL(/\/welcome$/);
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
  await page.context().close();
});
