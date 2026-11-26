// The organisation's escrow: an administrator makes the escrow key in the
// browser (its private half downloaded, never sent); a person who then
// sets up recovery leaves a sealed copy; the administrator opens it with
// the file, and gets the same recovery key the person was shown.
import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

test("an administrator recovers a person's recovery key with the escrow file", async ({ page, browser }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/admin/chat");
  const admin = page.locator("ortus-chat-admin");
  await expect(admin.getByRole("heading", { name: en.escrowTitle })).toBeVisible();
  await expect(admin.getByLabel(en.endToEndRoomsAllowed)).toBeVisible();
  await admin.getByLabel(en.endToEndRoomsAllowed).check();
  const [download] = await Promise.all([page.waitForEvent("download"), admin.getByRole("button", { name: en.escrowMake }).click()]);
  const file = test.info().outputPath("ortus-escrow-key.json");
  await download.saveAs(file);
  const escrow = JSON.parse(await readFile(file, "utf8")) as { kind: string; public: string; private: string };
  expect(escrow.kind).toBe("ortus-escrow-key");
  await expect(admin.getByRole("status")).toHaveText(en.escrowMade);
  // The server has the public half only.
  const policy = await (await page.request.get("/api/v1/chat/policy", { headers })).json();
  expect(policy.escrowKey).toBe(escrow.public);
  expect(JSON.stringify(policy)).not.toContain(escrow.private);

  // A person sets up recovery.
  const email = `taras-${Date.now()}@ministry.example`;
  const made = await page.request.post("/api/v1/admin/users", { headers, data: { email, name: "Taras Melnyk" } });
  const link = new URL((await made.json()).link);
  const person = await (await browser.newContext({ storageState: { cookies: [], origins: [] } })).newPage();
  person.on("pageerror", (e) => errors.push(e.message));
  await person.goto(link.pathname + link.hash);
  await expect(person).toHaveURL(/\/welcome$/);
  const room = await person.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `escrow-${Date.now()}`, encrypted: true } });
  await person.goto(`/chat?room=${(await room.json()).id}`);
  const chat = person.locator("ortus-chat-main");
  await chat.getByRole("button", { name: en.recovery, exact: true }).click();
  const dialog = chat.getByRole("dialog", { name: en.recoveryTitle });
  await dialog.getByRole("button", { name: en.recoverySetUp }).click();
  const key = (await dialog.getByTestId("recovery-key").textContent())?.trim() ?? "";
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
