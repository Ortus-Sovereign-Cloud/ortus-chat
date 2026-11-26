// Recovery for end-to-end rooms: the first browser sets it up (the
// recovery key shown once; cross-signing keys; its room keys backed up);
// a new browser of the same person, with no browser open to give it the
// room key, is warned about as unverified, enters the recovery key, reads
// the history from the backup, and is vouched for afterwards.
import { expect, test } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

test("recovery: a new browser reads the history with the recovery key, and is vouched for", async ({ page: owner, browser }) => {
  const errors: string[] = [];
  expect((await owner.request.patch("/api/v1/chat/policy", { headers, data: { encryptedRooms: true } })).status()).toBe(200);
  // A person of her own: her devices are only the ones this test makes.
  const made = await owner.request.post("/api/v1/admin/users", { headers, data: { email: `irena-${Date.now()}@ministry.example`, name: "Irena Kovalenko" } });
  expect(made.status()).toBe(200);
  const link = new URL((await made.json()).link);
  const page = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(link.pathname + link.hash);
  await expect(page).toHaveURL(/\/welcome$/);
  const room = await page.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `recover-${Date.now()}`, encrypted: true } });
  const id = (await room.json()).id as string;

  // The first browser writes, then sets recovery up.
  await page.goto(`/chat?room=${id}`);
  const first = page.locator("ortus-chat-main");
  await first.getByRole("textbox", { name: /Message/ }).fill("Before the new laptop");
  await first.getByRole("textbox", { name: /Message/ }).press("Enter");
  await expect(first.getByText("Before the new laptop")).toBeVisible();
  await first.getByRole("button", { name: en.recovery, exact: true }).click();
  const dialog = first.getByRole("dialog", { name: en.recoveryTitle });
  await dialog.getByRole("button", { name: en.recoverySetUp }).click();
  const key = (await dialog.getByTestId("recovery-key").textContent())?.trim() ?? "";
  expect(key).toMatch(/^Es/);
  await dialog.getByRole("button", { name: en.recoverySaved }).click();
  // The key never reaches the server as it is.
  const stored = await (await page.request.get("/api/v1/chat/account-data/m.cross_signing.master", { headers })).text();
  expect(stored).not.toContain(key.replace(/\s/g, ""));
  const state = await page.context().storageState();
  await page.close();

  // A new browser: no room key yet (nobody open to give it), and seen as unverified.
  const second = await (await browser.newContext({ storageState: state })).newPage();
  second.on("pageerror", (e) => errors.push(e.message));
  await second.goto(`/chat?room=${id}`);
  const chat = second.locator("ortus-chat-main");
  // Not recovered here, it vouches for none of her devices (itself included).
  await expect(chat.getByRole("status").filter({ hasText: en.unverifiedDevices.replace("{count}", "2") })).toBeVisible({ timeout: 20_000 });
  await expect(chat.getByText("Before the new laptop")).toHaveCount(0);

  // The recovery key: wrong first, then right.
  await chat.getByRole("button", { name: en.recovery, exact: true }).click();
  const asking = chat.getByRole("dialog", { name: en.recoveryTitle });
  await asking.getByLabel(en.recoveryKeyLabel).fill("EsTx not a key at all");
  await asking.getByRole("button", { name: en.recoveryEnter }).click();
  await expect(asking.getByRole("status")).toHaveText(en.recoveryWrong);
  await asking.getByLabel(en.recoveryKeyLabel).fill(key);
  await asking.getByRole("button", { name: en.recoveryEnter }).click();
  await expect(asking.getByRole("status")).toContainText(en.recoveryRestored.split("{count}")[0]!.trim());
  await asking.getByRole("button", { name: en.close }).click();
  await expect(chat.getByText("Before the new laptop")).toBeVisible({ timeout: 20_000 });

  // Vouched for now: the warning goes.
  await second.reload();
  await expect(second.locator("ortus-chat-main").getByText("Before the new laptop")).toBeVisible({ timeout: 20_000 });
  await expect(second.locator("ortus-chat-main").getByRole("status").filter({ hasText: "⚠" })).toHaveCount(0);
  expect(errors).toEqual([]);
  await second.context().close();
});
