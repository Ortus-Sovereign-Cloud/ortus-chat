// Chat (board WebChat): channels and direct messages on the side, the
// open room in the middle, a thread on the right with its recorded
// decision, which can become a task. Everything new arrives live.
import { ApiError, LitElement, LocalizeController, call, controls, css, customElement, html, nothing, state, type TemplateResult } from "ortus-kit";
import { t } from "./i18n.js";

interface RoomItem {
  id: string;
  kind: "channel" | "private" | "direct";
  name: string;
  topic: string;
  label: string | null;
  state: string;
  unread: number;
  lastSeq: number;
  encrypted: boolean;
  federated: boolean;
  with?: string[];
}

interface Member {
  id: string;
  state: string;
  role: string;
}

interface Person {
  name: string;
  email?: string;
  local: boolean;
}

interface Message {
  id: string;
  room: string;
  seq: number;
  sender: string;
  user: string | null;
  thread: string | null;
  text: string;
  mentions: string[] | null;
  at: number;
  editedAt: number | null;
  deleted: boolean;
  decision: number | null;
  replies: number | null;
  reactions: { key: string; who: string[] }[];
  file: { id: string; name: string; mime: string } | null;
}

const TONES = ["#a5b4ff", "#f9b77a", "#6ee0d0", "#d4f27a", "#ffa39a", "#eceef3"];
const REACTIONS = ["👍", "❤️", "🎉", "✅"];

function tone(text: string): string {
  let h = 0;
  for (const c of text) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return TONES[h % TONES.length]!;
}

function initials(name: string): string {
  const w = name.replace(/^@/, "").split(/[\s@.:]+/).filter(Boolean);
  return ((w[0]?.[0] ?? "?") + (w.length > 1 ? (w[1]?.[0] ?? "") : "")).toUpperCase();
}

function lang(): string {
  return document.documentElement.lang || "en";
}

function hm(ms: number): string {
  return new Intl.DateTimeFormat(lang(), { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(ms));
}

@customElement("ortus-chat-main")
export class OrtusChatMain extends LitElement {
  static override styles = [
    controls,
    css`
      :host {
        display: grid;
        grid-template-columns: 250px minmax(0, 1fr) auto;
        block-size: 100vh;
        color: var(--ortus-text);
      }
      aside.rooms {
        display: flex;
        flex-direction: column;
        gap: 4px;
        padding: 16px;
        border-inline-end: 1px solid var(--ortus-line);
        overflow-y: auto;
      }
      .head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-block-end: 18px;
      }
      .head strong {
        font-size: 16px;
      }
      .icon {
        display: grid;
        place-items: center;
        inline-size: 40px;
        block-size: 40px;
        border-radius: 12px;
        border: 1px solid var(--ortus-line-strong);
        background: none;
        color: var(--ortus-text);
        cursor: pointer;
        font: inherit;
      }
      h3 {
        margin-block: 14px 6px;
        padding-inline: 8px;
        font-size: 13px;
        font-weight: 500;
        color: var(--ortus-text-3);
      }
      .room {
        display: flex;
        align-items: center;
        gap: 10px;
        padding-block: 9px;
        padding-inline: 10px;
        border-radius: 12px;
        border: 1px solid transparent;
        background: none;
        color: var(--ortus-text-2);
        font: inherit;
        font-size: 15px;
        text-align: start;
        cursor: pointer;
      }
      .room[aria-current="true"] {
        border-color: var(--ortus-line-strong);
        background: var(--ortus-surface);
        color: var(--ortus-text);
      }
      .room.unread {
        color: var(--ortus-text);
        font-weight: 700;
      }
      .room .hash {
        color: var(--ortus-text-3);
      }
      .room .badge {
        margin-inline-start: auto;
        min-inline-size: 22px;
        padding-inline: 6px;
        border-radius: 999px;
        background: var(--ortus-accent);
        color: #0a0b10;
        font-size: 12px;
        font-weight: 700;
        text-align: center;
      }
      .avatar {
        display: grid;
        place-items: center;
        flex: none;
        inline-size: 28px;
        block-size: 28px;
        border-radius: 8px;
        color: #0a0b10;
        font-size: 11px;
        font-weight: 700;
      }
      .avatar.big {
        inline-size: 40px;
        block-size: 40px;
        border-radius: 10px;
        font-size: 13px;
      }
      main {
        display: grid;
        grid-template-rows: auto minmax(0, 1fr) auto;
        min-inline-size: 0;
      }
      main > header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding-block: 16px;
        padding-inline: 28px;
        border-block-end: 1px solid var(--ortus-line);
      }
      main > header h1 {
        margin: 0;
        font-size: 18px;
      }
      .label {
        padding-block: 3px;
        padding-inline: 8px;
        border-radius: 6px;
        font-family: var(--ortus-mono, monospace);
        font-size: 12px;
        background: color-mix(in srgb, var(--ortus-orange) 18%, transparent);
        color: var(--ortus-orange);
      }
      .muted {
        color: var(--ortus-text-3);
        font-size: 14px;
      }
      .e2e {
        margin-inline-start: auto;
        color: var(--ortus-teal);
        font-size: 14px;
      }
      .feed {
        display: flex;
        flex-direction: column;
        gap: 4px;
        padding-block: 16px;
        padding-inline: 28px;
        overflow-y: auto;
      }
      .msg {
        position: relative;
        display: grid;
        grid-template-columns: 40px minmax(0, 1fr);
        gap: 14px;
        padding-block: 10px;
        padding-inline: 8px;
        border-radius: 12px;
      }
      .msg:hover,
      .msg:focus-within {
        background: var(--ortus-surface);
      }
      .who {
        display: flex;
        gap: 8px;
        align-items: baseline;
      }
      textarea {
        font: inherit;
      }
      input[type="checkbox"] {
        flex: none;
        inline-size: 18px;
        block-size: 18px;
        margin: 0;
        padding: 0;
        accent-color: var(--ortus-accent);
      }
      .msg .who strong {
        font-size: 16px;
      }
      .msg p {
        margin-block: 4px 0;
        font-size: 16px;
        line-height: 1.5;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
      }
      .msg p.gone {
        color: var(--ortus-text-3);
        font-style: italic;
      }
      .mention {
        color: var(--ortus-accent);
        font-weight: 600;
      }
      .actions {
        position: absolute;
        inset-block-start: -14px;
        inset-inline-end: 12px;
        display: none;
        gap: 2px;
        padding: 4px;
        border-radius: 10px;
        border: 1px solid var(--ortus-line-strong);
        background: var(--ortus-surface-2);
      }
      .msg:hover .actions,
      .msg:focus-within .actions {
        display: flex;
      }
      .actions button {
        border: 0;
        background: none;
        color: var(--ortus-text-2);
        font: inherit;
        font-size: 13px;
        padding-block: 4px;
        padding-inline: 8px;
        border-radius: 6px;
        cursor: pointer;
      }
      .actions button:hover {
        background: var(--ortus-hover);
      }
      .reactions {
        display: flex;
        gap: 6px;
        margin-block-start: 6px;
      }
      .reactions button {
        padding-block: 2px;
        padding-inline: 8px;
        border-radius: 999px;
        border: 1px solid var(--ortus-line-strong);
        background: none;
        color: var(--ortus-text);
        font: inherit;
        font-size: 13px;
        cursor: pointer;
      }
      .reactions button.mine {
        border-color: var(--ortus-accent);
      }
      .replies {
        margin-block-start: 6px;
        border: 0;
        background: none;
        padding: 0;
        color: var(--ortus-accent);
        font: inherit;
        font-size: 14px;
        cursor: pointer;
      }
      .file {
        display: inline-flex;
        gap: 12px;
        align-items: center;
        margin-block-start: 8px;
        padding: 10px;
        padding-inline-end: 18px;
        border-radius: 12px;
        border: 1px solid var(--ortus-line-strong);
        color: var(--ortus-text);
        text-decoration: none;
      }
      .file i {
        display: grid;
        place-items: center;
        inline-size: 36px;
        block-size: 36px;
        border-radius: 8px;
        background: color-mix(in srgb, var(--ortus-teal) 18%, transparent);
        color: var(--ortus-teal);
        font-style: normal;
        font-size: 11px;
        font-weight: 700;
      }
      .day {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-block: 8px;
        color: var(--ortus-text-3);
        font-size: 13px;
      }
      .day::before,
      .day::after {
        content: "";
        flex: 1;
        border-block-start: 1px solid var(--ortus-line);
      }
      form.compose {
        display: grid;
        gap: 8px;
        margin-block: 0 24px;
        margin-inline: 28px;
        padding: 14px;
        border-radius: 18px;
        border: 1px solid var(--ortus-line-strong);
        background: var(--ortus-surface);
      }
      form.compose textarea {
        border: 0;
        background: none;
        color: var(--ortus-text);
        font: inherit;
        font-size: 16px;
        resize: none;
        outline: none;
      }
      .compose .row {
        display: flex;
        gap: 6px;
        align-items: center;
      }
      .compose .send {
        margin-inline-start: auto;
      }
      .typing {
        min-block-size: 18px;
        margin-inline: 36px;
        color: var(--ortus-text-3);
        font-size: 13px;
      }
      aside.thread {
        display: grid;
        grid-template-rows: auto minmax(0, 1fr) auto;
        inline-size: 320px;
        border-inline-start: 1px solid var(--ortus-line);
      }
      aside.thread header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-block: 18px;
        padding-inline: 20px;
        border-block-end: 1px solid var(--ortus-line);
      }
      aside.thread header h2 {
        margin: 0;
        font-size: 16px;
      }
      .thread .list {
        display: grid;
        align-content: start;
        gap: 16px;
        padding: 20px;
        overflow-y: auto;
      }
      .thread .post strong {
        font-size: 15px;
      }
      .thread .post p {
        margin-block: 4px 0;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
      }
      .decision {
        display: grid;
        gap: 6px;
        padding: 16px;
        border-radius: 14px;
        border: 1px solid var(--ortus-line-strong);
        background: color-mix(in srgb, var(--ortus-accent) 8%, transparent);
      }
      .decision small {
        color: var(--ortus-accent);
        font-weight: 600;
      }
      .thread form {
        display: grid;
        gap: 8px;
        padding: 16px;
        border-block-start: 1px solid var(--ortus-line);
      }
      .thread form label {
        display: flex;
        gap: 8px;
        align-items: center;
        font-size: 13px;
        color: var(--ortus-text-2);
      }
      .wide {
        inline-size: 100%;
      }
      .empty {
        display: grid;
        place-content: center;
        gap: 12px;
        text-align: center;
        color: var(--ortus-text-3);
      }
      dialog {
        inline-size: min(520px, 94vw);
        padding: 0;
        border-radius: 22px;
        border: 1px solid var(--ortus-line-strong);
        background: var(--ortus-surface);
        color: var(--ortus-text);
      }
      dialog::backdrop {
        background: rgb(0 0 0 / 0.55);
      }
      dialog form {
        display: grid;
        gap: 14px;
        padding: 26px;
      }
      dialog h2 {
        margin: 0;
        font-size: 20px;
      }
      dialog label {
        display: grid;
        gap: 6px;
        font-size: 13px;
        color: var(--ortus-text-2);
      }
      dialog ul {
        display: grid;
        gap: 6px;
        margin: 0;
        padding: 0;
        list-style: none;
        max-block-size: 300px;
        overflow-y: auto;
      }
      .error {
        margin: 0;
        color: var(--ortus-red);
        font-size: 14px;
      }
    `,
  ];

  private readonly localize = new LocalizeController(this);
  @state() private rooms: RoomItem[] = [];
  @state() private people: Record<string, Person> = {};
  @state() private me = "";
  @state() private current: string | null = null;
  @state() private members: Member[] = [];
  @state() private messages: Message[] = [];
  @state() private thread: string | null = null;
  @state() private threadMessages: Message[] = [];
  @state() private typing: Record<string, string[]> = {};
  @state() private error = "";
  @state() private creating: "channel" | "private" | "direct" | null = null;
  @state() private directory: RoomItem[] | null = null;
  @state() private taskFor: Message | null = null;
  @state() private projects: { id: string; name: string }[] = [];
  @state() private taskMade = "";
  @state() private files: { id: string; name: string; mime: string; kind?: string }[] | null = null;
  @state() private tasksInstalled = false;
  private events: EventSource | null = null;
  private lastTyping = 0;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.start();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.events?.close();
  }

  private async start(): Promise<void> {
    await this.loadRooms();
    const p = new URLSearchParams(location.search);
    const room = p.get("room") ?? this.rooms.find((r) => r.state === "join")?.id ?? null;
    if (room) await this.open(room, p.get("thread") ?? undefined);
    call<{ apps: { id: string }[] }>("GET", "/apps")
      .then((r) => (this.tasksInstalled = r.apps.some((a) => a.id === "tasks")))
      .catch(() => undefined);
    this.listen();
  }

  private listen(): void {
    this.events = new EventSource("/api/v1/chat/events");
    // After a break the stream starts afresh: read again what may have
    // been missed in between.
    let opened = false;
    this.events.addEventListener("open", () => {
      if (opened) void this.catchUp();
      opened = true;
    });
    this.events.addEventListener("event", (e) => void this.onEvent(JSON.parse((e as MessageEvent).data)));
    this.events.addEventListener("room", () => void this.loadRooms());
    this.events.addEventListener("typing", (e) => {
      const m = JSON.parse((e as MessageEvent).data) as { room: string; who: string[] };
      this.typing = { ...this.typing, [m.room]: m.who };
    });
  }

  private async onEvent(m: { room: string; seq: number; id: string; kind: string; thread: string | null; about: string | null }): Promise<void> {
    if (m.room !== this.current) {
      await this.loadRooms();
      return;
    }
    if (m.kind === "m.room.message") {
      const one = await call<Message>("GET", `/chat/messages/${encodeURIComponent(m.id)}`).catch(() => null);
      if (!one) return;
      if (!one.thread && !this.messages.some((x) => x.id === one.id)) this.messages = [...this.messages, one];
      if (one.thread) {
        if (this.thread === one.thread && !this.threadMessages.some((x) => x.id === one.id)) this.threadMessages = [...this.threadMessages, one];
        await this.refresh(one.thread);
      }
      this.markRead(m.seq);
    } else if (m.kind === "m.room.member") {
      // Someone joined, left or was invited.
      const info = await call<{ members: Member[]; people: Record<string, Person> }>("GET", `/chat/rooms/${encodeURIComponent(m.room)}`).catch(() => null);
      if (info) {
        this.members = info.members;
        this.people = { ...this.people, ...info.people };
      }
    } else if (m.about) {
      await this.refresh(m.about);
    }
  }

  private async catchUp(): Promise<void> {
    await this.loadRooms();
    const room = this.current;
    if (!room) return;
    const list = await call<{ messages: Message[]; people: Record<string, Person> }>("GET", `/chat/rooms/${encodeURIComponent(room)}/messages`).catch(() => null);
    if (list && room === this.current) {
      this.people = { ...this.people, ...list.people };
      this.messages = list.messages;
    }
    if (this.thread) await this.openThread(this.thread);
  }

  /** One message again (after a reply, an edit, a reaction). */
  private async refresh(id: string): Promise<void> {
    const one = await call<Message>("GET", `/chat/messages/${encodeURIComponent(id)}`).catch(() => null);
    if (!one) return;
    this.messages = this.messages.map((x) => (x.id === id ? one : x));
    this.threadMessages = this.threadMessages.map((x) => (x.id === id ? one : x));
  }

  private async loadRooms(): Promise<void> {
    const r = await call<{ rooms: RoomItem[]; people: Record<string, Person>; me: string }>("GET", "/chat/rooms");
    this.rooms = r.rooms;
    this.people = { ...this.people, ...r.people };
    this.me = r.me;
  }

  private room(): RoomItem | undefined {
    return this.rooms.find((r) => r.id === this.current);
  }

  private async open(id: string, thread?: string): Promise<void> {
    this.error = "";
    this.current = id;
    this.thread = null;
    const url = new URL(location.href);
    url.searchParams.set("room", id);
    url.searchParams.delete("thread");
    url.searchParams.delete("message");
    history.replaceState(null, "", url);
    const [info, list] = await Promise.all([
      call<{ members: Member[]; people: Record<string, Person>; state: string }>("GET", `/chat/rooms/${encodeURIComponent(id)}`),
      call<{ messages: Message[]; people: Record<string, Person> }>("GET", `/chat/rooms/${encodeURIComponent(id)}/messages`),
    ]);
    this.members = info.members;
    this.people = { ...this.people, ...info.people, ...list.people };
    this.messages = list.messages;
    if (thread) await this.openThread(thread);
    const last = this.room()?.lastSeq;
    if (last) this.markRead(last);
    await this.updateComplete;
    this.scrollDown();
  }

  private scrollDown(): void {
    const feed = this.renderRoot.querySelector(".feed");
    if (feed) feed.scrollTop = feed.scrollHeight;
  }

  private markRead(seq: number): void {
    const room = this.current;
    if (!room || this.room()?.state !== "join") return;
    void call("POST", `/chat/rooms/${encodeURIComponent(room)}/read`, { seq })
      .then(() => (this.rooms = this.rooms.map((r) => (r.id === room ? { ...r, unread: 0, lastSeq: Math.max(r.lastSeq, seq) } : r))))
      .catch(() => undefined);
  }

  private async openThread(id: string): Promise<void> {
    this.thread = id;
    this.taskMade = "";
    const r = await call<{ messages: Message[]; people: Record<string, Person> }>("GET", `/chat/rooms/${encodeURIComponent(this.current!)}/messages?thread=${encodeURIComponent(id)}`);
    this.people = { ...this.people, ...r.people };
    this.threadMessages = r.messages;
  }

  private name(id: string): string {
    return this.people[id]?.name ?? id;
  }

  private roomName(r: RoomItem): string {
    if (r.kind === "direct") return (r.with ?? []).map((w) => this.name(w)).join(", ") || t(this.localize, "directMessage");
    return r.name;
  }

  /** Mentioned colleagues: "@Name" written for members of the room. */
  private mentions(text: string): string[] {
    const out: string[] = [];
    for (const m of this.members) {
      const p = this.people[m.id];
      if (p?.email && text.includes(`@${p.name.split(" ")[0]}`)) out.push(p.email);
    }
    return out;
  }

  private async send(e: Event, thread?: string): Promise<void> {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const box = form.querySelector("textarea")!;
    const decision = (form.querySelector("input.decision") as HTMLInputElement | null)?.checked ?? false;
    const text = box.value.trim();
    if (!text || !this.current) return;
    try {
      await call("POST", `/chat/rooms/${encodeURIComponent(this.current)}/messages`, { text, thread, mentions: this.mentions(text), decision });
      box.value = "";
      if (thread) await this.openThread(thread);
      else {
        const list = await call<{ messages: Message[]; people: Record<string, Person> }>("GET", `/chat/rooms/${encodeURIComponent(this.current)}/messages`);
        this.messages = list.messages;
        await this.updateComplete;
        this.scrollDown();
      }
    } catch (err) {
      this.error = err instanceof ApiError ? err.message : String(err);
    }
  }

  private keydown(e: KeyboardEvent): void {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      (e.target as HTMLTextAreaElement).form?.requestSubmit();
      return;
    }
    if (this.current && Date.now() - this.lastTyping > 3000) {
      this.lastTyping = Date.now();
      void call("POST", `/chat/rooms/${encodeURIComponent(this.current)}/typing`).catch(() => undefined);
    }
  }

  private async react(m: Message, key: string): Promise<void> {
    const one = await call<Message>("POST", `/chat/messages/${encodeURIComponent(m.id)}/reactions`, { key });
    this.messages = this.messages.map((x) => (x.id === m.id ? { ...x, reactions: one.reactions } : x));
    this.threadMessages = this.threadMessages.map((x) => (x.id === m.id ? { ...x, reactions: one.reactions } : x));
  }

  private async edit(m: Message): Promise<void> {
    const text = prompt(t(this.localize, "editMessage"), m.text);
    if (text === null || !text.trim()) return;
    await call("PATCH", `/chat/messages/${encodeURIComponent(m.id)}`, { text });
    await this.refresh(m.id);
  }

  private async deleteMessage(m: Message): Promise<void> {
    if (!confirm(t(this.localize, "deleteSure"))) return;
    await call("DELETE", `/chat/messages/${encodeURIComponent(m.id)}`);
    await this.refresh(m.id);
  }

  private async createRoom(e: Event): Promise<void> {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const get = (n: string) => (form.elements.namedItem(n) as HTMLInputElement | null)?.value ?? "";
    try {
      const r = await call<{ id: string }>("POST", "/chat/rooms", {
        kind: this.creating,
        name: get("name"),
        topic: get("topic"),
        members: get("members").split(/[\s,;]+/).filter(Boolean),
        encrypted: (form.elements.namedItem("encrypted") as HTMLInputElement | null)?.checked ?? false,
      });
      this.creating = null;
      await this.loadRooms();
      await this.open(r.id);
    } catch (err) {
      this.error = err instanceof ApiError ? err.message : String(err);
    }
  }

  private async browse(): Promise<void> {
    this.directory = (await call<{ rooms: RoomItem[] }>("GET", "/chat/directory")).rooms;
  }

  private async join(id: string): Promise<void> {
    await call("POST", `/chat/rooms/${encodeURIComponent(id)}/join`);
    this.directory = null;
    await this.loadRooms();
    await this.open(id);
  }

  private async startTask(m: Message): Promise<void> {
    this.taskFor = m;
    this.projects = (await call<{ projects: { id: string; name: string }[] }>("GET", "/tasks/projects").catch(() => ({ projects: [] }))).projects;
  }

  private async makeTask(e: Event): Promise<void> {
    e.preventDefault();
    const m = this.taskFor;
    if (!m) return;
    const form = e.target as HTMLFormElement;
    const get = (n: string) => (form.elements.namedItem(n) as HTMLInputElement | HTMLSelectElement | null)?.value ?? "";
    try {
      const due = get("due");
      const made = await call<{ id: string }>("POST", "/tasks/tasks", {
        project: get("project"),
        title: get("title"),
        notes: m.text,
        assignee: get("assignee") || undefined,
        dueAt: due ? new Date(due).getTime() : undefined,
        source: `/chat?room=${encodeURIComponent(m.room)}&thread=${encodeURIComponent(m.thread ?? m.id)}`,
      });
      this.taskMade = made.id;
      this.taskFor = null;
    } catch (err) {
      this.error = err instanceof ApiError ? err.message : String(err);
    }
  }

  private async pickFile(): Promise<void> {
    const r = await call<{ items: { id: string; name: string; mime: string; kind: string }[] }>("GET", "/drive/items").catch(() => ({ items: [] }));
    this.files = r.items.filter((i) => i.kind !== "folder");
  }

  private async sendFile(id: string): Promise<void> {
    if (!this.current) return;
    this.files = null;
    await call("POST", `/chat/rooms/${encodeURIComponent(this.current)}/messages`, { text: "", file: id });
    const list = await call<{ messages: Message[] }>("GET", `/chat/rooms/${encodeURIComponent(this.current)}/messages`);
    this.messages = list.messages;
  }

  private avatar(id: string, big = false): TemplateResult {
    const n = this.name(id);
    return html`<span class="avatar ${big ? "big" : ""}" aria-hidden="true" .style=${`background: ${tone(n)}`}>${initials(n)}</span>`;
  }

  private body(m: Message): TemplateResult {
    if (m.deleted) return html`<p class="gone">${t(this.localize, "deleted")}</p>`;
    // @Name of a mentioned person stands out.
    const names = (m.mentions ?? []).map((id) => `@${this.name(id).split(" ")[0]}`);
    const parts = names.length ? m.text.split(new RegExp(`(${names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`)) : [m.text];
    return html`<p>${parts.map((p) => (names.includes(p) ? html`<span class="mention">${p}</span>` : p))}${m.editedAt ? html` <small class="muted">${t(this.localize, "edited")}</small>` : nothing}</p>`;
  }

  private message(m: Message, inThread = false): TemplateResult {
    const mine = m.sender === this.me;
    return html`<article class=${inThread ? "post" : "msg"} aria-label=${t(this.localize, "messageFrom", { who: this.name(m.sender) })}>
      ${inThread ? nothing : this.avatar(m.sender, true)}
      <div>
        <div class="who"><strong>${mine && inThread ? t(this.localize, "you") : this.name(m.sender)}</strong><span class="muted">${hm(m.at)}</span></div>
        ${m.decision && inThread
          ? html`<div class="decision" role="note"><small>${t(this.localize, "decisionRecorded")}</small>${this.body(m)}</div>`
          : this.body(m)}
        ${m.file ? html`<a class="file" href=${`/drive?file=${encodeURIComponent(m.file.id)}`}><i>${(m.file.name.split(".").pop() ?? "").slice(0, 4).toUpperCase()}</i><span>${m.file.name}</span></a>` : nothing}
        ${m.reactions.length
          ? html`<div class="reactions">${m.reactions.map((r) => html`<button class=${r.who.includes(this.me) ? "mine" : ""} aria-label=${t(this.localize, "reactedWith", { key: r.key, count: r.who.length })} @click=${() => this.react(m, r.key)}>${r.key} ${r.who.length}</button>`)}</div>`
          : nothing}
        ${!inThread && m.replies ? html`<button class="replies" @click=${() => this.openThread(m.id)}>${t(this.localize, "replies", { count: m.replies })}</button>` : nothing}
        ${m.decision && inThread && this.tasksInstalled
          ? html`<button class="button wide" @click=${() => this.startTask(m)}>${t(this.localize, "turnIntoTask")}</button>${this.taskMade ? html`<a href=${`/tasks?task=${encodeURIComponent(this.taskMade)}`}>${t(this.localize, "taskMade")}</a>` : nothing}`
          : nothing}
      </div>
      ${m.deleted || inThread
        ? nothing
        : html`<div class="actions" role="toolbar" aria-label=${t(this.localize, "messageActions")}>
            ${REACTIONS.map((k) => html`<button aria-label=${t(this.localize, "reactWith", { key: k })} @click=${() => this.react(m, k)}>${k}</button>`)}
            <button @click=${() => this.openThread(m.id)}>${t(this.localize, "replyInThread")}</button>
            ${mine ? html`<button @click=${() => this.edit(m)}>${t(this.localize, "edit")}</button><button @click=${() => this.deleteMessage(m)}>${t(this.localize, "delete")}</button>` : nothing}
          </div>`}
    </article>`;
  }

  private dialogs(): TemplateResult {
    return html`${this.creating
        ? html`<dialog open aria-label=${t(this.localize, this.creating === "direct" ? "newDirect" : "newChannel")}>
            <form @submit=${this.createRoom}>
              <h2>${t(this.localize, this.creating === "direct" ? "newDirect" : "newChannel")}</h2>
              ${this.creating !== "direct"
                ? html`<label>${t(this.localize, "channelName")}<input class="input" name="name" required /></label>
                    <label>${t(this.localize, "topic")}<input class="input" name="topic" /></label>
                    <label><span><input type="checkbox" .checked=${this.creating === "private"} @change=${(e: Event) => (this.creating = (e.target as HTMLInputElement).checked ? "private" : "channel")} /> ${t(this.localize, "privateChannel")}</span></label>`
                : nothing}
              <label>${t(this.localize, this.creating === "direct" ? "withWhom" : "invite")}<input class="input" name="members" ?required=${this.creating === "direct"} placeholder=${t(this.localize, "addresses")} /></label>
              ${this.error ? html`<p class="error" role="alert">${this.error}</p>` : nothing}
              <div class="row"><button type="button" class="button" @click=${() => ((this.creating = null), (this.error = ""))}>${t(this.localize, "cancel")}</button> <button class="button primary">${t(this.localize, "create")}</button></div>
            </form>
          </dialog>`
        : nothing}
      ${this.directory
        ? html`<dialog open aria-label=${t(this.localize, "browseChannels")}>
            <form @submit=${(e: Event) => e.preventDefault()}>
              <h2>${t(this.localize, "browseChannels")}</h2>
              <ul>
                ${this.directory.map((r) => html`<li class="row"><span># ${r.name} <small class="muted">${r.topic}</small></span> <button type="button" class="button" @click=${() => this.join(r.id)}>${t(this.localize, "join")}</button></li>`)}
              </ul>
              <button type="button" class="button" @click=${() => (this.directory = null)}>${t(this.localize, "close")}</button>
            </form>
          </dialog>`
        : nothing}
      ${this.taskFor
        ? html`<dialog open aria-label=${t(this.localize, "turnIntoTask")}>
            <form @submit=${this.makeTask}>
              <h2>${t(this.localize, "turnIntoTask")}</h2>
              <label>${t(this.localize, "taskTitle")}<input class="input" name="title" required .value=${this.taskFor.text.slice(0, 200)} /></label>
              <label>${t(this.localize, "project")}<select class="input" name="project" required>${this.projects.map((p) => html`<option value=${p.id}>${p.name}</option>`)}</select></label>
              <label>${t(this.localize, "assignee")}<input class="input" name="assignee" type="email" placeholder=${t(this.localize, "address")} /></label>
              <label>${t(this.localize, "due")}<input class="input" name="due" type="datetime-local" /></label>
              ${this.projects.length ? nothing : html`<p class="error">${t(this.localize, "noProjects")}</p>`}
              ${this.error ? html`<p class="error" role="alert">${this.error}</p>` : nothing}
              <div class="row"><button type="button" class="button" @click=${() => (this.taskFor = null)}>${t(this.localize, "cancel")}</button> <button class="button primary" ?disabled=${!this.projects.length}>${t(this.localize, "create")}</button></div>
            </form>
          </dialog>`
        : nothing}
      ${this.files
        ? html`<dialog open aria-label=${t(this.localize, "fromDrive")}>
            <form @submit=${(e: Event) => e.preventDefault()}>
              <h2>${t(this.localize, "fromDrive")}</h2>
              <ul>${this.files.map((f) => html`<li><button type="button" class="button wide" @click=${() => this.sendFile(f.id)}>${f.name}</button></li>`)}</ul>
              ${this.files.length ? nothing : html`<p class="muted">${t(this.localize, "noFiles")}</p>`}
              <button type="button" class="button" @click=${() => (this.files = null)}>${t(this.localize, "cancel")}</button>
            </form>
          </dialog>`
        : nothing}`;
  }

  override render() {
    const room = this.room();
    const channels = this.rooms.filter((r) => r.kind !== "direct");
    const directs = this.rooms.filter((r) => r.kind === "direct");
    const typing = (this.current && this.typing[this.current]) || [];
    const root = this.threadMessages.find((m) => m.id === this.thread);
    const roomItem = (r: RoomItem) =>
      html`<button class="room ${r.unread ? "unread" : ""}" aria-current=${r.id === this.current ? "true" : "false"} @click=${() => this.open(r.id)}>
        ${r.kind === "direct" ? this.avatar(r.with?.[0] ?? r.id) : html`<span class="hash" aria-hidden="true">${r.kind === "private" ? "🔒" : "#"}</span>`}
        <span>${this.roomName(r)}</span>
        ${r.state === "invite" ? html`<small class="muted">${t(this.localize, "invited")}</small>` : r.unread ? html`<span class="badge" aria-label=${t(this.localize, "unread", { count: r.unread })}>${r.unread}</span>` : nothing}
      </button>`;
    return html`<aside class="rooms" aria-label=${t(this.localize, "rooms")}>
        <div class="head"><strong>${t(this.localize, "chat")}</strong><button class="icon" aria-label=${t(this.localize, "newChannel")} @click=${() => (this.creating = "channel")}>+</button></div>
        <h3>${t(this.localize, "channels")}</h3>
        ${channels.map(roomItem)}
        <button class="room" @click=${this.browse}><span class="hash">+</span>${t(this.localize, "browseChannels")}</button>
        <h3>${t(this.localize, "directMessages")}</h3>
        ${directs.map(roomItem)}
        <button class="room" @click=${() => (this.creating = "direct")}><span class="hash">+</span>${t(this.localize, "newDirect")}</button>
      </aside>
      <main>
        ${room
          ? html`<header>
                <h1>${room.kind === "direct" ? this.roomName(room) : `# ${room.name}`}</h1>
                ${room.label ? html`<span class="label">${room.label.toUpperCase()}</span>` : nothing}
                <span class="muted">${t(this.localize, "members", { count: this.members.filter((m) => m.state === "join").length })}</span>
                ${room.encrypted ? html`<span class="e2e">🔒 ${t(this.localize, "endToEnd")}</span>` : nothing}
              </header>
              <section class="feed" aria-label=${t(this.localize, "messages")}>
                ${room.state === "invite"
                  ? html`<div class="empty"><p>${t(this.localize, "youAreInvited")}</p><button class="button primary" @click=${() => this.join(room.id)}>${t(this.localize, "join")}</button></div>`
                  : this.messages.map((m) => this.message(m))}
              </section>
              <div>
                <p class="typing" aria-live="polite">${typing.length ? t(this.localize, "typing", { who: typing.map((w) => this.name(w)).join(", ") }) : ""}</p>
                ${room.state === "join"
                  ? html`<form class="compose" @submit=${(e: Event) => this.send(e)}>
                      <textarea rows="2" aria-label=${t(this.localize, "messageTo", { room: this.roomName(room) })} placeholder=${t(this.localize, "messageTo", { room: room.kind === "direct" ? this.roomName(room) : `# ${room.name}` })} @keydown=${this.keydown}></textarea>
                      <div class="row">
                        <button type="button" class="icon" aria-label=${t(this.localize, "fromDrive")} @click=${this.pickFile}>
                          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 12.5 12.6 20.9a5.5 5.5 0 0 1-7.8-7.8l8.5-8.5a3.7 3.7 0 0 1 5.2 5.2l-8.5 8.5a1.8 1.8 0 0 1-2.6-2.6l7.8-7.8" /></svg>
                        </button>
                        <button class="icon send" aria-label=${t(this.localize, "send")}>→</button>
                      </div>
                      ${this.error ? html`<p class="error" role="alert">${this.error}</p>` : nothing}
                    </form>`
                  : nothing}
              </div>`
          : html`<div class="empty"><p>${t(this.localize, "noRoom")}</p><button class="button primary" @click=${() => (this.creating = "channel")}>${t(this.localize, "newChannel")}</button></div>`}
      </main>
      ${this.thread
        ? html`<aside class="thread" aria-label=${t(this.localize, "thread")}>
            <header><h2>${t(this.localize, "thread")}</h2><button class="icon" aria-label=${t(this.localize, "close")} @click=${() => (this.thread = null)}>×</button></header>
            <div class="list">${root ? this.message(root, true) : nothing}${this.threadMessages.filter((m) => m.id !== this.thread).map((m) => this.message(m, true))}</div>
            ${room?.state === "join"
              ? html`<form @submit=${(e: Event) => this.send(e, this.thread!)}>
                  <textarea class="input" rows="2" aria-label=${t(this.localize, "replyToThread")} placeholder=${t(this.localize, "replyToThread")} @keydown=${this.keydown}></textarea>
                  <label><input type="checkbox" class="decision" /> ${t(this.localize, "recordAsDecision")}</label>
                  <button class="button primary">${t(this.localize, "reply")}</button>
                </form>`
              : nothing}
          </aside>`
        : nothing}
      ${this.dialogs()}`;
  }
}
