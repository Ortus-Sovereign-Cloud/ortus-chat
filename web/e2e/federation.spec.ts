// Sharing a channel with partner organisations (Matrix federation), and
// inviting from the channel's header.
import { expect, test } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

test("a channel is shared with partners and invites from its header", async ({ page, browser }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const email = `anna-${Date.now()}@ministry.example`;
  const r = await page.request.post("/api/v1/admin/users", { headers, data: { email, name: "Anna Kowalska" } });
  expect(r.status()).toBe(200);
  const link = new URL((await r.json()).link);
  const anna = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  await anna.goto(link.pathname + link.hash);
  await expect(anna).toHaveURL(/\/welcome$/);

  const made = await page.request.post("/api/v1/chat/rooms", { headers, data: { kind: "channel", name: `partners-${Date.now()}` } });
  const id = (await made.json()).id as string;
  await page.goto(`/chat?room=${id}`);
  const olena = page.locator("ortus-chat-main");
  await olena.getByRole("button", { name: en.shareWithPartners }).click();
  const shared = olena.getByText(en.sharedWithPartners);
  await expect(shared).toBeVisible();
  await expect(olena.locator(".shared code")).toHaveText(/^!.+:/);
  await expect(olena.getByRole("button", { name: en.shareWithPartners })).toHaveCount(0);

  await olena.getByRole("button", { name: en.inviteButton, exact: true }).click();
  const field = olena.getByLabel(en.invite);
  await expect(field).toHaveAttribute("placeholder", en.addressesOrPartners);
  await field.fill(email);
  await olena.locator("form.invite").getByRole("button", { name: en.inviteButton }).click();
  await expect(olena.locator("form.invite")).toHaveCount(0);

  await anna.goto(`/chat?room=${id}`);
  await expect(anna.locator("ortus-chat-main").getByText(en.youAreInvited)).toBeVisible();
  expect(errors).toEqual([]);
});
