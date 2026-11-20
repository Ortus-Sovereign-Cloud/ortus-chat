// An alert source posts into a channel through its hook: the bell shows
// it, and opening it lands in the channel, on the alert.
import { expect, request, test } from "@playwright/test";
import en from "../src/locales/en.js";

const headers = { "X-Requested-With": "ortus" };

test("a gauge alert rings the bell and opens its channel", async ({ page, baseURL }) => {
  const made = await page.request.post("/api/v1/chat/rooms", { headers, data: { kind: "channel", name: `gauges-${Date.now()}` } });
  const room = (await made.json()).id as string;
  const hook = await (await page.request.post(`/api/v1/chat/rooms/${room}/hooks`, { headers, data: { name: "River Authority alerts" } })).json();
  // The outside system: no session, no browser.
  const outside = await request.newContext({ baseURL });
  const posted = await outside.post(new URL(hook.url).pathname, { data: { text: "Gauge at the bridge passed 4.2 m", alert: true } });
  expect(posted.status()).toBe(200);

  await page.goto("/drive");
  await page.getByRole("button", { name: /Notifications, \d+ unread/ }).click();
  const panel = page.getByRole("dialog", { name: "Notifications" });
  await panel.getByRole("button", { name: /Alerts/ }).click();
  await panel.getByRole("link", { name: /Gauge at the bridge passed 4\.2 m/ }).click();
  await expect(page).toHaveURL(new RegExp(`/chat\\?room=${room}`));
  const chat = page.locator("ortus-chat-main");
  await expect(chat.getByText("Gauge at the bridge passed 4.2 m")).toBeVisible();
  await expect(chat.getByText(en.alert, { exact: true })).toBeVisible();
  await expect(chat.getByText("River Authority alerts")).toBeVisible();
});
