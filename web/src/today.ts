// The chat card on the start page (ortus-chat-today, from
// /assets/apps/chat/today.js): the conversations with unread messages.
import { LitElement, LocalizeController, call, css, customElement, html, nothing, state } from "ortus-kit";
import { ready, t } from "./i18n.js";

await ready;

interface Room {
  id: string;
  kind: "channel" | "private" | "direct";
  name: string;
  state: string;
  unread: number;
  with?: string[];
}

interface Person {
  name: string;
  email?: string;
  local: boolean;
}

@customElement("ortus-chat-today")
export class OrtusChatToday extends LitElement {
  static override styles = css`
    :host {
      display: block;
    }
    section {
      padding: 20px;
      border-radius: 18px;
      border: 1px solid var(--ortus-line);
      background: var(--ortus-surface);
    }
    header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      margin-block-end: 12px;
    }
    h2 {
      margin: 0;
      font-size: 17px;
      font-weight: 600;
    }
    .count {
      color: var(--ortus-accent);
      font-size: 14px;
      font-weight: 600;
    }
    ul {
      margin: 0;
      padding: 0;
      list-style: none;
    }
    li a {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px;
      margin-inline: -8px;
      border-radius: 10px;
      color: inherit;
      text-decoration: none;
    }
    li a:hover,
    li a:focus-visible {
      background: var(--ortus-hover);
    }
    .hash {
      display: grid;
      place-items: center;
      inline-size: 32px;
      block-size: 32px;
      border-radius: 9px;
      background: var(--ortus-surface-2);
      color: var(--ortus-text-2);
    }
    .name {
      flex: 1;
      min-inline-size: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 14px;
      font-weight: 600;
    }
    .badge {
      min-inline-size: 20px;
      padding: 1px 7px;
      border-radius: 999px;
      background: var(--ortus-accent);
      color: var(--ortus-bg);
      font-size: 12px;
      font-weight: 700;
      text-align: center;
    }
    .quiet {
      margin: 0;
      color: var(--ortus-text-2);
      font-size: 14px;
    }
    footer {
      margin-block-start: 12px;
      font-size: 14px;
    }
    footer a {
      color: var(--ortus-accent);
    }
  `;

  private readonly localize = new LocalizeController(this);
  @state() private rooms: Room[] = [];
  @state() private people: Record<string, Person> = {};
  @state() private loaded = false;

  override connectedCallback(): void {
    super.connectedCallback();
    void call<{ rooms: Room[]; people: Record<string, Person> }>("GET", "/chat/rooms")
      .then((r) => {
        this.rooms = r.rooms.filter((x) => x.unread > 0 || x.state === "invite");
        this.people = r.people;
      })
      .catch(() => undefined)
      .finally(() => (this.loaded = true));
  }

  private name(room: Room): string {
    if (room.kind !== "direct") return room.name;
    return (room.with ?? []).map((id) => this.people[id]?.name ?? id).join(", ");
  }

  override render() {
    if (!this.loaded) return nothing;
    const total = this.rooms.reduce((n, r) => n + r.unread, 0);
    return html`
      <section aria-labelledby="chat-today">
        <header>
          <h2 id="chat-today">${t(this.localize, "chat")}</h2>
          ${total ? html`<span class="count">${t(this.localize, "unread", { count: total })}</span>` : nothing}
        </header>
        ${this.rooms.length
          ? html`<ul>
              ${this.rooms.slice(0, 5).map((room) => {
                const other = room.kind === "direct" ? room.with?.[0] : undefined;
                const person = other ? this.people[other] : undefined;
                return html`<li>
                  <a href=${`/chat?room=${encodeURIComponent(room.id)}`}>
                    ${other
                      ? html`<ortus-avatar size="32" radius="9" .name=${this.name(room)} .user=${person?.local ? other : ""}></ortus-avatar>`
                      : html`<span class="hash" aria-hidden="true">${room.kind === "private" ? "🔒" : "#"}</span>`}
                    <span class="name" dir="auto">${this.name(room)}</span>
                    ${room.state === "invite" ? html`<small>${t(this.localize, "invited")}</small>` : html`<span class="badge">${room.unread}</span>`}
                  </a>
                </li>`;
              })}
            </ul>`
          : html`<p class="quiet">${t(this.localize, "todayAllRead")}</p>`}
        <footer><a href="/chat">${t(this.localize, "todayOpen")}</a></footer>
      </section>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ortus-chat-today": OrtusChatToday;
  }
}
