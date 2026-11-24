// Chat on a phone-sized screen: one pane at a time. The room list first;
// a room replaces it with a back button; a thread replaces the room.
import { expect, test, type Page } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

test.use({ viewport: { width: 390, height: 844 } });

// The whole width the shell gives the app (all of it with a bottom bar; a
// core with the side rail keeps the rail).
async function full(page: Page, box: { width: number } | null): Promise<void> {
  const app = (await page.locator("ortus-chat-main").boundingBox())!;
  expect(box!.width).toBeGreaterThan(app.width - 2);
}

async function fits(page: Page): Promise<void> {
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
}

test("on a phone chat shows the rooms, then a room, then its thread, with back buttons", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const name = `phone-${Date.now()}`;
  const made = await page.request.post("/api/v1/chat/rooms", { headers, data: { kind: "channel", name, topic: "Shelters and roads" } });
  expect(made.status()).toBe(200);
  const room = (await made.json()).id as string;
  const first = await page.request.post(`/api/v1/chat/rooms/${room}/messages`, { headers, data: { text: "The river gauge at the bridge reads 4.2 m and is still rising. Do we close the road now?" } });
  expect(first.status()).toBe(200);
  const root = (await first.json()).id as string;
  const reply = await page.request.post(`/api/v1/chat/rooms/${room}/messages`, { headers, data: { text: "Yes: the forecast says another 30 cm by noon.", thread: root } });
  expect(reply.status()).toBe(200);

  await page.goto("/chat");
  const chat = page.locator("ortus-chat-main");
  const rooms = chat.getByRole("complementary", { name: en.rooms });
  const main = chat.locator("main");
  // The list, alone.
  await expect(rooms.getByRole("button", { name: new RegExp(name) })).toBeVisible();
  await expect(main).toBeHidden();
  await fits(page);
  await page.screenshot({ path: "test-results/phone-rooms.png" });

  // A room: full width, the list gone, a back button.
  await rooms.getByRole("button", { name: new RegExp(name) }).click();
  await expect(chat.getByRole("heading", { level: 1 })).toHaveText(`# ${name}`);
  await expect(rooms).toBeHidden();
  await full(page, await main.boundingBox());
  await expect(chat.getByRole("textbox", { name: /Message/ })).toBeVisible();
  await page.mouse.move(0, 843);
  await fits(page);
  await page.screenshot({ path: "test-results/phone-room.png" });

  // A message's actions fit on the screen.
  const message = chat.getByRole("article", { name: /Message from/ }).first();
  await message.focus();
  const actions = message.getByRole("toolbar", { name: en.messageActions });
  await expect(actions).toBeVisible();
  const box = (await actions.boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(390);
  await fits(page);
  await page.screenshot({ path: "test-results/phone-actions.png" });

  // Its thread replaces the room; back returns to the room.
  await chat.getByRole("button", { name: "1 reply" }).click();
  const thread = chat.getByRole("complementary", { name: en.thread });
  await expect(thread).toContainText("another 30 cm");
  await expect(main).toBeHidden();
  await full(page, await thread.boundingBox());
  await fits(page);
  await page.screenshot({ path: "test-results/phone-thread.png" });
  await thread.getByRole("button", { name: en.back }).click();
  await expect(thread).toBeHidden();
  await expect(main).toBeVisible();

  // Back from the room to the list.
  await main.getByRole("button", { name: en.back }).click();
  await expect(rooms).toBeVisible();
  await expect(main).toBeHidden();

  // A dialog fits.
  await chat.getByRole("button", { name: en.newChannel }).first().click();
  const dialog = chat.getByRole("dialog", { name: en.newChannel });
  await expect(dialog).toBeVisible();
  const d = (await dialog.boundingBox())!;
  expect(d.x).toBeGreaterThanOrEqual(0);
  expect(d.x + d.width).toBeLessThanOrEqual(390);
  await fits(page);
  await page.screenshot({ path: "test-results/phone-dialog.png" });
  expect(errors).toEqual([]);
});
