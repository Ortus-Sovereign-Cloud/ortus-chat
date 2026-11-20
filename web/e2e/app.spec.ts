// Chat opens in the shell in six languages, right to left in Arabic.
import { expect, test } from "@playwright/test";
import ar from "../src/locales/ar.js";
import de from "../src/locales/de.js";
import en from "../src/locales/en.js";
import fr from "../src/locales/fr.js";
import pl from "../src/locales/pl.js";
import uk from "../src/locales/uk.js";

for (const [code, texts, dir] of [["en", en, "ltr"], ["pl", pl, "ltr"], ["uk", uk, "ltr"], ["de", de, "ltr"], ["fr", fr, "ltr"], ["ar", ar, "rtl"]] as const) {
  test(`chat opens in ${code}`, async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    await page.addInitScript((c) => localStorage.setItem("ortus.locale", c), code);
    // A channel, so its header shows: invite, and share with partners
    // (federation is on).
    const made = await page.request.post("/api/v1/chat/rooms", { headers: { "X-Requested-With": "ortus" }, data: { kind: "channel", name: `lang-${code}-${Date.now()}` } });
    expect(made.status()).toBe(200);
    await page.goto(`/chat?room=${(await made.json()).id}`);
    const main = page.locator("ortus-chat-main");
    await expect(main.getByRole("heading", { level: 3, name: texts.channels as string })).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("dir", dir);
    await expect(main.getByRole("button", { name: texts.shareWithPartners as string })).toBeVisible();
    await expect(main.getByRole("button", { name: texts.inviteButton as string, exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  });
}
