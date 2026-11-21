// The chat card of the start page (ortus-chat-today, from today.js): the
// conversations with unread messages, each a link, and the way into Chat.
import { expect, test } from "@playwright/test";
import en from "../src/locales/en.js";

test("the start page's chat card lists unread conversations", async ({ page }) => {
  await page.goto("/chat");
  await page.evaluate(async () => {
    const card = "/assets/apps/chat/today.js";
    await import(/* @vite-ignore */ card);
    document.body.append(document.createElement("ortus-chat-today"));
  });
  const card = page.locator("ortus-chat-today").getByRole("region", { name: en.chat });
  await expect(card.getByRole("link", { name: en.todayOpen })).toHaveAttribute("href", "/chat");
  const rooms = ((await (await page.request.get("/api/v1/chat/rooms")).json()) as { rooms: { id: string; unread: number; state: string }[] }).rooms;
  const waiting = rooms.filter((r) => r.unread > 0 || r.state === "invite");
  if (waiting.length) {
    await expect(card.getByRole("link").first()).toHaveAttribute("href", `/chat?room=${encodeURIComponent(waiting[0]!.id)}`);
  } else {
    await expect(card).toContainText(en.todayAllRead);
  }
});
