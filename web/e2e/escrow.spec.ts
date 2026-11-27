// The organisation's escrow: an administrator (the owner) sets up recovery
// in a sealed room (so this browser holds her master key), then makes the escrow key
// in the browser, signed with that master key (its private half
// downloaded, never sent). A person who then sets up recovery sees the
// key's fingerprint and who set it, and leaves a sealed copy; a key that
// changed after they saw it is refused until they look again. The
// administrator opens the copy with the file, and gets the same recovery
// key the person was shown.
import { readFile } from "node:fs/promises";
import { expect, test, type Browser, type Page } from "@playwright/test";
import en from "../src/locales/en.js";
import { axe } from "./axe.js";

const headers = { "X-Requested-With": "ortus" };
/** As the screens show it: the first 24 characters in groups of four. */
const escrowFingerprint = (key: string): string => (key.slice(0, 24).match(/.{1,4}/g) ?? []).join(" ");

/** Someone invited by the owner, signed in in a browser of their own. */
async function invited(owner: Page, browser: Browser, name: string): Promise<{ page: Page; email: string }> {
  const email = `${name.split(" ")[0]!.toLowerCase()}-${Date.now()}@ministry.example`;
  const made = await owner.request.post("/api/v1/admin/users", { headers, data: { email, name } });
  expect(made.status()).toBe(200);
  const link = new URL((await made.json()).link);
  const page = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  await page.goto(link.pathname + link.hash);
  await expect(page).toHaveURL(/\/welcome$/);
  return { page, email };
}

async function sealedRoom(page: Page): Promise<void> {
  const room = await page.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `escrow-${Date.now()}`, encrypted: true } });
  await page.goto(`/chat?room=${(await room.json()).id}`);
}

/** Makes the escrow key in Admin › Chat: the downloaded file. */
async function makeEscrow(page: Page, file: string): Promise<{ public: string; private: string }> {
  const admin = page.locator("ortus-chat-admin");
  const [download] = await Promise.all([page.waitForEvent("download"), admin.getByRole("button", { name: en.escrowMake }).click()]);
  await download.saveAs(file);
  const escrow = JSON.parse(await readFile(file, "utf8")) as { kind: string; public: string; private: string };
  expect(escrow.kind).toBe("ortus-escrow-key");
  await expect(admin.getByRole("status")).toHaveText(en.escrowMade);
  await expect(admin.getByTestId("escrow-fingerprint")).toHaveText(escrowFingerprint(escrow.public));
  return escrow;
}

test("an administrator recovers a person's recovery key with the escrow file", async ({ page: owner, browser }) => {
  const errors: string[] = [];
  owner.on("pageerror", (e) => errors.push(e.message));
  expect((await owner.request.patch("/api/v1/chat/policy", { headers, data: { encryptedRooms: true } })).status()).toBe(200);

  // Without a master key in this browser, no escrow key is made.
  await owner.goto("/admin/chat");
  const ownerAdmin = owner.locator("ortus-chat-admin");
  await expect(ownerAdmin.getByRole("heading", { name: en.escrowTitle })).toBeVisible();
  await expect(ownerAdmin.getByLabel(en.endToEndRoomsAllowed)).toBeChecked();
  await ownerAdmin.getByRole("button", { name: en.escrowMake }).click();
  await expect(ownerAdmin.getByRole("status")).toHaveText(en.escrowNoMaster);

  // She sets up recovery in a sealed room first, then makes the key (the
  // owner: her session from set-up is a strong sign-in, as changing the
  // escrow key asks).
  const page = owner;
  await sealedRoom(page);
  const adminChat = page.locator("ortus-chat-main");
  await adminChat.getByRole("button", { name: en.recovery, exact: true }).click();
  const adminDialog = adminChat.getByRole("dialog", { name: en.recoveryTitle });
  await adminDialog.getByRole("button", { name: en.recoverySetUp }).click();
  await expect(adminDialog.getByTestId("recovery-key")).toBeVisible();
  await adminDialog.getByRole("button", { name: en.recoverySaved }).click();
  await page.goto("/admin/chat");
  const admin = page.locator("ortus-chat-admin");
  const first = await makeEscrow(page, test.info().outputPath("first-escrow-key.json"));
  // The server has the public half only, signed by her master key.
  const policy = await (await page.request.get("/api/v1/chat/policy", { headers })).json();
  expect(policy.escrowKey).toBe(first.public);
  expect(policy.escrow.public_key).toBe(first.public);
  expect(policy.escrow.signerMaster.usage).toEqual(["master"]);
  expect(policy.escrowUnsigned).toBe(false);
  expect(JSON.stringify(policy)).not.toContain(first.private);
  expect(await axe(page), "the escrow key, administered").toEqual([]);

  // A person opens recovery: the key's fingerprint and who set it.
  const { page: person, email } = await invited(owner, browser, "Taras Melnyk");
  person.on("pageerror", (e) => errors.push(e.message));
  await sealedRoom(person);
  const chat = person.locator("ortus-chat-main");
  await chat.getByRole("button", { name: en.recovery, exact: true }).click();
  const dialog = chat.getByRole("dialog", { name: en.recoveryTitle });
  const shown = dialog.getByTestId("recovery-escrow");
  await expect(shown).toContainText(escrowFingerprint(first.public));
  await expect(shown).toContainText(`(${en.escrowSignerUnverified})`);
  await expect(dialog.getByText(en.recoveryEscrowChanged)).toHaveCount(0);
  expect(await axe(person), "recovery with the escrow key shown").toEqual([]);

  // Meanwhile the key changes: what she was shown is not what set-up would use.
  expect((await page.request.patch("/api/v1/chat/policy", { headers, data: { escrow: null } })).status()).toBe(200);
  await page.reload();
  const file = test.info().outputPath("ortus-escrow-key.json");
  const escrow = await makeEscrow(page, file);
  expect(escrow.public).not.toBe(first.public);
  await dialog.getByRole("button", { name: en.recoverySetUp }).click();
  await expect(dialog.getByRole("status")).toHaveText(en.recoveryEscrowNotShown);
  await expect(shown).toContainText(escrowFingerprint(escrow.public));
  // Looked at again, it goes on.
  await dialog.getByRole("button", { name: en.recoverySetUp }).click();
  const key = (await dialog.getByTestId("recovery-key").textContent())?.trim() ?? "";
  expect(key).toMatch(/^Es/);
  await expect(dialog.getByText(en.recoveryEscrow)).toBeVisible();
  await dialog.getByRole("button", { name: en.recoverySaved }).click();

  // The administrator opens it with the file.
  await page.reload();
  await admin.getByLabel(en.email).fill(email);
  await admin.getByLabel(en.escrowFile).setInputFiles(file);
  await admin.getByRole("button", { name: en.escrowRecover }).click();
  await expect(admin.getByTestId("escrowed-key")).toHaveText(key);
  expect(errors).toEqual([]);
  await person.context().close();
});
