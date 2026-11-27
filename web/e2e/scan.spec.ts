// Verification by QR code between two browsers of one person, the camera
// a fake one (a canvas stream showing the other screen's code, turned a
// little): the first (recovery set up) scans the code the second shows;
// the second says it was scanned; the first vouches for the second, and
// the warning goes. The frames go through the page's own decoder (qrscan.ts).
import { expect, test } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

/** A camera that films whatever code __showToCamera is given (the modules of an SVG path). */
function fakeCamera(): void {
  const canvas = document.createElement("canvas");
  canvas.width = 640;
  canvas.height = 480;
  const context = canvas.getContext("2d")!;
  let squares: [number, number][] = [];
  let side = 0;
  (window as unknown as { __showToCamera: (d: string, size: number) => void }).__showToCamera = (d, size) => {
    squares = [...d.matchAll(/M(\d+) (\d+)/g)].map((m) => [Number(m[1]), Number(m[2])]);
    side = size;
  };
  const draw = () => {
    context.fillStyle = "#777";
    context.fillRect(0, 0, 640, 480);
    if (side) {
      const scale = 400 / side;
      context.save();
      context.translate(320, 240);
      context.rotate(0.1);
      context.translate(-200, -200);
      context.fillStyle = "#fff";
      context.fillRect(0, 0, 400, 400);
      context.fillStyle = "#000";
      for (const [x, y] of squares) context.fillRect(x * scale, y * scale, scale + 0.5, scale + 0.5);
      context.restore();
    }
  };
  window.setInterval(draw, 50);
  navigator.mediaDevices.getUserMedia = async () => {
    draw();
    return canvas.captureStream(15);
  };
}

test("a browser scans the code another browser of the person shows", async ({ page: owner, browser }) => {
  const errors: string[] = [];
  expect((await owner.request.patch("/api/v1/chat/policy", { headers, data: { encryptedRooms: true } })).status()).toBe(200);
  const made = await owner.request.post("/api/v1/admin/users", { headers, data: { email: `mykola-${Date.now()}@ministry.example`, name: "Mykola Shevchuk" } });
  const link = new URL((await made.json()).link);
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  await context.addInitScript(fakeCamera);
  const first = await context.newPage();
  first.on("pageerror", (e) => errors.push(e.message));
  await first.goto(link.pathname + link.hash);
  await expect(first).toHaveURL(/\/welcome$/);
  const room = await first.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `scan-${Date.now()}`, encrypted: true } });
  const url = `/chat?room=${(await room.json()).id}`;

  // The first browser sets recovery up.
  await first.goto(url);
  const a = first.locator("ortus-chat-main");
  await a.getByRole("button", { name: en.recovery, exact: true }).click();
  const setUp = a.getByRole("dialog", { name: en.recoveryTitle });
  await setUp.getByRole("button", { name: en.recoverySetUp }).click();
  await expect(setUp.getByTestId("recovery-key")).toBeVisible();
  await setUp.getByRole("button", { name: en.recoverySaved }).click();

  // A second browser, unverified.
  const second = await (await browser.newContext({ storageState: await context.storageState() })).newPage();
  second.on("pageerror", (e) => errors.push(e.message));
  await second.goto(url);
  const b = second.locator("ortus-chat-main");
  await expect(b.getByText(en.endToEnd)).toBeVisible();
  await first.reload();
  const warning = a.getByRole("button", { name: new RegExp(en.unverifiedDevices.replace("{count}", "1")) });
  await expect(warning).toBeVisible({ timeout: 20_000 });
  await warning.click();
  await a.getByRole("dialog", { name: en.unverifiedTitle }).getByRole("button", { name: en.verify }).click();
  const theirs = b.getByRole("dialog", { name: en.verifyTitle });
  await theirs.getByRole("button", { name: en.verifyAccept }).click({ timeout: 20_000 });

  // The second shows its code; the first's camera films it.
  const code = theirs.getByTestId("verify-qr");
  await expect(code).toBeVisible({ timeout: 20_000 });
  const [d, size] = await code.evaluate((svg) => [svg.querySelector("path")!.getAttribute("d")!, Number(svg.getAttribute("viewBox")!.split(" ")[2])] as const);
  await first.evaluate(([d, size]) => (window as unknown as { __showToCamera: (d: string, size: number) => void }).__showToCamera(d, size), [d, size] as const);
  const ours = a.getByRole("dialog", { name: en.verifyTitle });
  await ours.getByRole("button", { name: en.verifyScanTheirs }).click({ timeout: 20_000 });
  await expect(ours.getByTestId("verify-camera")).toBeVisible();
  await expect(ours.getByRole("status")).toHaveText(en.verifyScannedWait, { timeout: 20_000 });
  // The camera is off once the code is taken.
  await expect(ours.getByTestId("verify-camera")).toHaveCount(0);

  // The second says it was scanned; both finish, the first vouching for the second.
  await theirs.getByRole("button", { name: en.verifyScannedYes }).click({ timeout: 20_000 });
  await expect(theirs.getByRole("status")).toHaveText(en.verifyUnsigned, { timeout: 20_000 });
  await expect(ours.getByRole("status")).toHaveText(en.verifyDone, { timeout: 20_000 });
  await first.reload();
  await expect(a.getByText(en.endToEnd)).toBeVisible();
  await expect(a.getByRole("button", { name: /⚠/ })).toHaveCount(0, { timeout: 20_000 });
  expect(errors).toEqual([]);
  await context.close();
  await second.context().close();
});

test("a refused camera is said, and emoji stay a choice", async ({ page: owner, browser }) => {
  const made = await owner.request.post("/api/v1/admin/users", { headers, data: { email: `halyna-${Date.now()}@ministry.example`, name: "Halyna Bondar" } });
  const link = new URL((await made.json()).link);
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  await context.addInitScript(() => {
    navigator.mediaDevices.getUserMedia = async () => {
      throw new DOMException("Permission denied", "NotAllowedError");
    };
  });
  const first = await context.newPage();
  await first.goto(link.pathname + link.hash);
  await expect(first).toHaveURL(/\/welcome$/);
  expect((await owner.request.patch("/api/v1/chat/policy", { headers, data: { encryptedRooms: true } })).status()).toBe(200);
  const room = await first.request.post("/api/v1/chat/rooms", { headers, data: { kind: "private", name: `refused-${Date.now()}`, encrypted: true } });
  const url = `/chat?room=${(await room.json()).id}`;
  await first.goto(url);
  const a = first.locator("ortus-chat-main");
  await a.getByRole("button", { name: en.recovery, exact: true }).click();
  const setUp = a.getByRole("dialog", { name: en.recoveryTitle });
  await setUp.getByRole("button", { name: en.recoverySetUp }).click();
  await setUp.getByRole("button", { name: en.recoverySaved }).click();
  const second = await (await browser.newContext({ storageState: await context.storageState() })).newPage();
  await second.goto(url);
  const b = second.locator("ortus-chat-main");
  await expect(b.getByText(en.endToEnd)).toBeVisible();
  await first.reload();
  const warning = a.getByRole("button", { name: new RegExp(en.unverifiedDevices.replace("{count}", "1")) });
  await expect(warning).toBeVisible({ timeout: 20_000 });
  await warning.click();
  await a.getByRole("dialog", { name: en.unverifiedTitle }).getByRole("button", { name: en.verify }).click();
  await b.getByRole("dialog", { name: en.verifyTitle }).getByRole("button", { name: en.verifyAccept }).click({ timeout: 20_000 });
  const ours = a.getByRole("dialog", { name: en.verifyTitle });
  await ours.getByRole("button", { name: en.verifyScanTheirs }).click({ timeout: 20_000 });
  await expect(ours.getByText(en.verifyCameraRefused)).toBeVisible();
  await expect(ours.getByRole("button", { name: en.verifyUseEmoji })).toBeVisible();
  await context.close();
  await second.context().close();
});
