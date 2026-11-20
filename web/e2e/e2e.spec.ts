// End-to-end rooms: messages sealed in the browser, opened by members'
// devices, never readable on the server; a member's new device is given
// the room key by a device that has it.
import { expect, test } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

test("an end-to-end room: sealed in the browser, opened by members' devices", async ({ page, browser }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  expect((await page.request.patch("/api/v1/chat/policy", { headers, data: { encryptedRooms: true } })).status()).toBe(200);

  const email = `marek-${Date.now()}@ministry.example`;
  const made = await page.request.post("/api/v1/admin/users", { headers, data: { email, name: "Marek Nowak" } });
  const link = new URL((await made.json()).link);
  const marek = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  marek.on("pageerror", (e) => errors.push(e.message));
  await marek.goto(link.pathname + link.hash);
  await expect(marek).toHaveURL(/\/welcome$/);
  // His browser makes its device key on his first visit to chat.
  const device = marek.waitForResponse((r) => r.url().includes("/api/v1/chat/devices/") && r.status() === 200);
  await marek.goto("/chat");
  await device;

  const room = await page.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `sealed-${Date.now()}`, encrypted: true, members: [email] } });
  expect(room.status()).toBe(200);
  const id = (await room.json()).id as string;

  // Olena's browser makes the room key and gives it to both devices.
  await page.goto(`/chat?room=${id}`);
  const olena = page.locator("ortus-chat-main");
  await expect(olena.getByText(en.endToEnd)).toBeVisible();
  await olena.getByRole("textbox", { name: /Message/ }).fill("Sealed hello");
  await olena.getByRole("textbox", { name: /Message/ }).press("Enter");
  await expect(olena.getByText("Sealed hello")).toBeVisible();

  // The server keeps only ciphertext.
  const kept = await (await page.request.get(`/api/v1/chat/rooms/${id}/messages`, { headers })).text();
  expect(kept).not.toContain("Sealed hello");
  expect(kept).toContain("ciphertext");

  // Marek joins and reads it; his answer reaches Olena.
  await marek.goto(`/chat?room=${id}`);
  const his = marek.locator("ortus-chat-main");
  await his.getByRole("button", { name: en.join }).click();
  await expect(his.getByText("Sealed hello")).toBeVisible();
  await his.getByRole("textbox", { name: /Message/ }).fill("Sealed reply");
  await his.getByRole("textbox", { name: /Message/ }).press("Enter");
  await expect(olena.getByText("Sealed reply")).toBeVisible();

  // Olena on a new browser: locked at first, then given the key by her
  // other browser, which is open on the room.
  const second = await (await browser.newContext({ storageState: await page.context().storageState() })).newPage();
  await second.goto(`/chat?room=${id}`);
  await expect(second.locator("ortus-chat-main").getByText("Sealed hello")).toBeVisible({ timeout: 20_000 });
  expect(errors).toEqual([]);
});
