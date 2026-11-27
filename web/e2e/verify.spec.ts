// Verification by emoji between two browsers of one person: the first
// (recovery set up) warns about the second; it asks, the second accepts,
// both show the same seven emoji and both say they match; the second is
// then signed by the first's self-signing key, and the warning goes.
import { expect, test, type Page } from "@playwright/test";
import en from "../src/locales/en.js";
import { axe } from "./axe.js";

const headers = { "X-Requested-With": "ortus" };

test("two browsers of one person verify each other by emoji", async ({ page: owner, browser }) => {
  const errors: string[] = [];
  expect((await owner.request.patch("/api/v1/chat/policy", { headers, data: { encryptedRooms: true } })).status()).toBe(200);
  const made = await owner.request.post("/api/v1/admin/users", { headers, data: { email: `oksana-${Date.now()}@ministry.example`, name: "Oksana Lysenko" } });
  const link = new URL((await made.json()).link);
  const first = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  first.on("pageerror", (e) => errors.push(e.message));
  await first.goto(link.pathname + link.hash);
  await expect(first).toHaveURL(/\/welcome$/);
  const room = await first.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `verify-${Date.now()}`, encrypted: true } });
  const url = `/chat?room=${(await room.json()).id}`;

  // The first browser sets recovery up.
  await first.goto(url);
  const a = first.locator("ortus-chat-main");
  await a.getByRole("button", { name: en.recovery, exact: true }).click();
  const setUp = a.getByRole("dialog", { name: en.recoveryTitle });
  await setUp.getByRole("button", { name: en.recoverySetUp }).click();
  await expect(setUp.getByTestId("recovery-key")).toBeVisible();
  expect(await axe(first), "the recovery key shown").toEqual([]);
  await setUp.getByRole("button", { name: en.recoverySaved }).click();

  // A second browser: the first sees it as unverified.
  const second = await (await browser.newContext({ storageState: await first.context().storageState() })).newPage();
  second.on("pageerror", (e) => errors.push(e.message));
  await second.goto(url);
  const b = second.locator("ortus-chat-main");
  await expect(b.getByText(en.endToEnd)).toBeVisible();
  await first.reload();
  const warning = a.getByRole("button", { name: new RegExp(en.unverifiedDevices.replace("{count}", "1")) });
  await expect(warning).toBeVisible({ timeout: 20_000 });

  // The first asks, the second accepts.
  await warning.click();
  await expect(a.getByRole("dialog", { name: en.unverifiedTitle })).toBeVisible();
  expect(await axe(first), "the unverified devices").toEqual([]);
  await a.getByRole("dialog", { name: en.unverifiedTitle }).getByRole("button", { name: en.verify }).click();
  const theirs = b.getByRole("dialog", { name: en.verifyTitle });
  await expect(theirs.getByRole("button", { name: en.verifyAccept })).toBeVisible({ timeout: 20_000 });
  expect(await axe(second), "a request to verify").toEqual([]);
  await theirs.getByRole("button", { name: en.verifyAccept }).click();

  // Both can scan (a camera API) and show codes: the first chooses emoji.
  const ours = a.getByRole("dialog", { name: en.verifyTitle });
  await ours.getByRole("button", { name: en.verifyUseEmoji }).click({ timeout: 20_000 });

  // The same emoji on both screens; both say so.
  const emojiOf = async (p: Page, dialog: typeof ours) => {
    await expect(dialog.getByTestId("verify-emoji")).toBeVisible({ timeout: 20_000 });
    return (await dialog.getByTestId("verify-emoji").textContent())?.trim();
  };
  const shown = await emojiOf(first, ours);
  expect(shown).toBeTruthy();
  expect(await emojiOf(second, theirs)).toBe(shown);
  expect(await axe(first), "the emoji").toEqual([]);
  await ours.getByRole("button", { name: en.verifySame }).click();
  await theirs.getByRole("button", { name: en.verifySame }).click();
  await expect(ours.getByRole("status")).toHaveText(en.verifyDone, { timeout: 20_000 });
  // The second holds no keys of the person's (recovery is not open there):
  // it vouches for nothing, and says so; the first signed it.
  await expect(theirs.getByRole("status")).toHaveText(en.verifyUnsigned, { timeout: 20_000 });

  // Vouched for: the first's warning goes.
  await first.reload();
  await expect(a.getByText(en.endToEnd)).toBeVisible();
  await expect(a.getByRole("button", { name: /⚠/ })).toHaveCount(0, { timeout: 20_000 });
  expect(errors).toEqual([]);
  await first.context().close();
  await second.context().close();
});

// The warning and the sharing read the room's devices separately: a device
// the server shows when keys are shared and hides from the warning is
// still named, from what this browser recorded when it gave the key.
test("a device given the room key and then hidden by the server is still warned about", async ({ page: owner, browser }) => {
  const errors: string[] = [];
  expect((await owner.request.patch("/api/v1/chat/policy", { headers, data: { encryptedRooms: true } })).status()).toBe(200);
  const made = await owner.request.post("/api/v1/admin/users", { headers, data: { email: `taras-${Date.now()}@ministry.example`, name: "Taras Melnyk" } });
  const link = new URL((await made.json()).link);
  const first = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  first.on("pageerror", (e) => errors.push(e.message));
  await first.goto(link.pathname + link.hash);
  await expect(first).toHaveURL(/\/welcome$/);
  const room = await first.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `hidden-${Date.now()}`, encrypted: true } });
  const id = (await room.json()).id as string;
  const url = `/chat?room=${id}`;

  // The first browser sets recovery up (it vouches for itself).
  await first.goto(url);
  const a = first.locator("ortus-chat-main");
  await a.getByRole("button", { name: en.recovery, exact: true }).click();
  const setUp = a.getByRole("dialog", { name: en.recoveryTitle });
  await setUp.getByRole("button", { name: en.recoverySetUp }).click();
  await expect(setUp.getByTestId("recovery-key")).toBeVisible();
  await setUp.getByRole("button", { name: en.recoverySaved }).click();
  const own = ((await (await first.request.get(`/api/v1/chat/rooms/${encodeURIComponent(id)}/devices`, { headers })).json()).devices as { device: string }[]).map((d) => d.device);
  expect(own).toHaveLength(1);

  // A second browser; the first gives it the room key with a message.
  const second = await (await browser.newContext({ storageState: await first.context().storageState() })).newPage();
  second.on("pageerror", (e) => errors.push(e.message));
  await second.goto(url);
  await expect(second.locator("ortus-chat-main").getByText(en.endToEnd)).toBeVisible();
  await first.reload();
  const warning = a.getByRole("button", { name: new RegExp(en.unverifiedDevices.replace("{count}", "1")) });
  await expect(warning).toBeVisible({ timeout: 20_000 });
  await a.getByRole("textbox", { name: /Message/ }).fill("Given to both");
  await a.getByRole("textbox", { name: /Message/ }).press("Enter");
  await expect(a.getByText("Given to both")).toBeVisible();

  // From now on the server's answer leaves the second browser out.
  await first.route("**/chat/rooms/*/devices", async (route) => {
    // A request the page dropped (a reload) has nothing to answer.
    try {
      const response = await route.fetch();
      const body = await response.json();
      body.devices = (body.devices as { device: string }[]).filter((d) => own.includes(d.device));
      await route.fulfill({ response, json: body });
    } catch {
      await route.abort().catch(() => undefined);
    }
  });
  await first.reload();
  await expect(a.getByText(en.endToEnd)).toBeVisible();
  await expect(warning).toBeVisible({ timeout: 20_000 });
  // Still there after the screen has looked again (a few polls).
  await first.waitForTimeout(8_000);
  await expect(warning).toBeVisible();
  expect(errors).toEqual([]);
  await first.context().close();
  await second.context().close();
});
