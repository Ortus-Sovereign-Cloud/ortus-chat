// Chat (WebChat) between two people: a channel, an invitation, messages
// arriving live, a thread with a recorded decision, a reaction.
import { expect, test, type Page } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

async function newcomer(owner: Page, name: string, email: string, browser: import("@playwright/test").Browser): Promise<Page> {
  const r = await owner.request.post("/api/v1/admin/users", { headers, data: { email, name } });
  expect(r.status()).toBe(200);
  const link = new URL((await r.json()).link);
  const page = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  await page.goto(link.pathname + link.hash);
  await expect(page).toHaveURL(/\/welcome$/);
  return page;
}

test("two people talk in a channel and record a decision", async ({ page, browser }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const marek = await newcomer(page, "Marek Nowak", `marek-${Date.now()}@ministry.example`, browser);
  const marekEmail = await marek.evaluate(async () => (await (await fetch("/api/v1/me", { headers: { "X-Requested-With": "ortus" } })).json()).email);

  // Olena makes #flood-response and invites Marek.
  await page.goto("/chat");
  const olena = page.locator("ortus-chat-main");
  await olena.getByRole("button", { name: en.newChannel }).first().click();
  const dialog = olena.getByRole("dialog", { name: en.newChannel });
  await dialog.getByLabel(en.channelName).fill("flood-response");
  await dialog.getByLabel(en.topic).fill("River levels and shelters");
  await dialog.getByLabel(en.invite).fill(marekEmail);
  await dialog.getByRole("button", { name: en.create }).click();
  await expect(olena.getByRole("heading", { level: 1 })).toHaveText("# flood-response");

  // Marek accepts and sees what Olena writes, as she writes it.
  await marek.goto("/chat");
  const his = marek.locator("ortus-chat-main");
  await his.getByRole("button", { name: /flood-response/ }).click();
  await his.getByRole("button", { name: en.join }).click();
  await expect(his.getByRole("textbox", { name: /Message/ })).toBeVisible();
  const box = olena.getByRole("textbox", { name: /Message/ });
  await box.fill("Water level at the bridge gauge is 4.2 m and rising. Do we close the road now?");
  await box.press("Enter");
  const alert = his.getByRole("region", { name: en.messages }).getByRole("article", { name: "Message from Olena Hrytsenko" });
  await expect(alert).toContainText("4.2 m and rising");

  // A thread: Marek answers, Olena records the decision.
  await alert.hover();
  await alert.getByRole("button", { name: en.replyInThread }).click();
  const thread = his.getByRole("complementary", { name: en.thread });
  await thread.getByRole("textbox", { name: en.replyToThread }).fill("Yes. Forecast says another 30 cm by noon.");
  await thread.getByRole("button", { name: en.reply }).click();
  await expect(olena.getByRole("button", { name: "1 reply" })).toBeVisible();
  await olena.getByRole("button", { name: "1 reply" }).click();
  const hers = olena.getByRole("complementary", { name: en.thread });
  await expect(hers).toContainText("Forecast says another 30 cm");
  await hers.getByRole("textbox", { name: en.replyToThread }).fill("Agreed. Closing R-12 at 11:30, Marek owns comms.");
  await hers.getByLabel(en.recordAsDecision).check();
  await hers.getByRole("button", { name: en.reply }).click();
  await expect(hers.getByRole("note")).toContainText(en.decisionRecorded);
  await expect(thread.getByRole("note")).toContainText("Closing R-12 at 11:30", { timeout: 10_000 });

  // A reaction reaches the other side.
  await alert.hover();
  await alert.getByRole("button", { name: "React with 👍" }).click();
  await expect(olena.getByRole("region", { name: en.messages }).getByRole("button", { name: "👍 from 1 person" })).toBeVisible({ timeout: 10_000 });
  await page.screenshot({ path: "test-results/chat.png" });
  expect(errors).toEqual([]);
  await marek.context().close();
});

test("rooms that could not be loaded say so and can be loaded again", async ({ page }) => {
  // The rooms fail to load: the screen says so, not "no rooms yet".
  await page.route("**/api/v1/chat/rooms", (route) => route.fulfill({ status: 503, contentType: "application/json", body: "{}" }));
  await page.goto("/chat");
  const chat = page.locator("ortus-chat-main");
  await expect(chat.getByRole("alert")).toHaveText(en.roomsFailed);
  await expect(chat.getByText(en.noRoom)).toHaveCount(0);
  // Back again: trying again shows the rooms.
  await page.unroute("**/api/v1/chat/rooms");
  await chat.getByRole("button", { name: en.tryAgain }).click();
  await expect(chat.getByRole("alert")).toHaveCount(0);
});
