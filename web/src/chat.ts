// Chat (board WebChat): channels and direct messages on the side, the
// open room in the middle, a thread on the right with its recorded
// decision, which can become a task. Everything new arrives live.
import { ApiError, LitElement, LocalizeController, call, controls, css, customElement, html, nothing, state, type TemplateResult } from "ortus-kit";
import { ESCROW_NOT_ACCEPTED, ESCROW_UNSIGNED, Sealer, type EscrowInfo, type RecoveryState, type Sealed, type VerificationView } from "./e2e.js";
import { EMOJI } from "./verify.js";
import { decodeQr } from "./qrscan.js";

/** A verification QR code as SVG: dark modules on white, with the quiet zone (cameras need both, in any theme). */
function qrSvg(modules: boolean[][], label: string) {
  const n = modules.length;
  const size = n + 8;
  let d = "";
  modules.forEach((row, y) => row.forEach((dark, x) => dark && (d += `M${x + 4} ${y + 4}h1v1h-1z`)));
  return html`<svg class="qr" data-testid="verify-qr" role="img" aria-label=${label} viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">
    <rect width=${size} height=${size} fill="#fff"></rect><path d=${d} fill="#000"></path>
  </svg>`;
}
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
  roomId?: string;
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
  /** An end-to-end room's message as the server keeps it. */
  sealed?: Sealed | null;
  /** A sealed message this device cannot open. */
  locked?: boolean;
  /** Opened with a key from the backup only: the sender is not confirmed. */
  fromBackup?: boolean;
  /** Posted by an incoming hook (an alert source). */
  hook?: { name: string; alert: boolean } | null;
}

const TONES = ["#a5b4ff", "#f9b77a", "#6ee0d0", "#d4f27a", "#ffa39a", "#eceef3"];
const REACTIONS = ["👍", "❤️", "🎉", "✅"];

/** The back button's arrow; it points the other way right to left. */
const backArrow = html`<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M15 18l-6-6 6-6" /></svg>`;

function tone(text: string): string {
  let h = 0;
  for (const c of text) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return TONES[h % TONES.length]!;
}


function lang(): string {
  return document.documentElement.lang || "en";
}

function hm(ms: number): string {
  return new Intl.DateTimeFormat(lang(), { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(ms));
}

/** The focused element, inside shadow roots too. */
function deepFocus(): HTMLElement | null {
  let a = document.activeElement;
  while (a?.shadowRoot?.activeElement) a = a.shadowRoot.activeElement;
  return a instanceof HTMLElement ? a : null;
}

@customElement("ortus-chat-main")
export class OrtusChatMain extends LitElement {
  static override styles = [
    controls,
    css`
      :host {
        display: grid;
        grid-template-columns: 250px minmax(0, 1fr) auto;
        block-size: var(--ortus-screen, 100vh);
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
      main.inviting {
        grid-template-rows: auto auto minmax(0, 1fr) auto;
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
      .alert-chip {
        padding-block: 2px;
        padding-inline: 8px;
        margin-inline-end: 6px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        background: rgb(255 122 110 / 0.15);
        color: #ff9a92;
      }
      .shared {
        color: var(--ortus-teal);
        font-size: 14px;
      }
      .shared code {
        font-family: var(--ortus-mono, monospace);
        font-size: 12px;
        color: var(--ortus-text-3);
        user-select: all;
      }
      main > header a.button {
        text-decoration: none;
        display: inline-flex;
        align-items: center;
      }
      main > header > :nth-child(1 of .button) {
        margin-inline-start: auto;
      }
      form.invite {
        display: flex;
        align-items: end;
        flex-wrap: wrap;
        gap: 12px;
        padding-block: 12px;
        padding-inline: 28px;
        border-block-end: 1px solid var(--ortus-line);
      }
      form.invite label {
        display: grid;
        gap: 4px;
        flex: 1;
        font-size: 14px;
      }
      .e2e {
        margin-inline-start: auto;
        color: var(--ortus-teal);
        font-size: 14px;
      }
      .unverified {
        border: 0;
        background: none;
        padding: 0;
        color: var(--ortus-amber, #f5a35b);
        font: inherit;
        font-size: 14px;
        cursor: pointer;
        text-decoration: underline;
      }
      .qr {
        display: block;
        width: min(280px, 100%);
        height: auto;
        margin: 8px auto;
        border-radius: 8px;
      }
      .scan {
        display: block;
        width: min(320px, 100%);
        aspect-ratio: 4 / 3;
        margin: 8px auto;
        border-radius: 8px;
        background: #000;
        object-fit: cover;
      }
      .emoji {
        display: flex;
        gap: 12px;
        font-size: 36px;
        flex-wrap: wrap;
      }
      .recovery-key {
        display: block;
        padding: 12px;
        border-radius: 10px;
        background: var(--ortus-surface-2, rgb(255 255 255 / 0.06));
        font-family: ui-monospace, monospace;
        font-size: 15px;
        word-spacing: 6px;
        user-select: all;
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
      .msg p.from-backup {
        font-size: 13px;
      }
      .unchecked {
        color: var(--ortus-amber, #f5a35b);
        font-size: 14px;
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
      .compose:focus-within {
        outline: 2px solid var(--ortus-accent, #8c9eff);
        outline-offset: 2px;
      }
      dialog.ask {
        inline-size: min(440px, calc(100vw - 32px));
        padding: 20px;
        border-radius: 16px;
        border: 1px solid var(--ortus-line-strong);
        background: var(--ortus-surface);
        color: var(--ortus-text);
      }
      dialog.ask::backdrop {
        background: rgba(0, 0, 0, 0.6);
      }
      dialog.ask h2 {
        margin: 0 0 12px;
        font-size: 18px;
      }
      dialog.ask textarea {
        inline-size: 100%;
        min-block-size: 96px;
        box-sizing: border-box;
        font: inherit;
      }
      .ask-actions {
        display: flex;
        gap: 8px;
        justify-content: end;
        margin-block-start: 12px;
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
      .back {
        display: none;
      }
      .back svg:dir(rtl) {
        transform: scaleX(-1);
      }
      /* A phone-sized screen: one pane at a time, the room list first; a
         room replaces it (with a back button), a thread replaces the room. */
      @media (max-width: 720px) {
        :host {
          grid-template-columns: minmax(0, 1fr);
        }
        :host([detail]) aside.rooms,
        :host([threaded]) main,
        :host(:not([detail])) main,
        :host(:not([detail])) aside.thread {
          display: none;
        }
        .back {
          display: grid;
          flex: none;
        }
        .icon {
          inline-size: 44px;
          block-size: 44px;
        }
        .button {
          block-size: 44px;
        }
        .room {
          min-block-size: 44px;
        }
        main > header {
          flex-wrap: wrap;
          gap: 8px;
          padding-block: 10px;
          padding-inline: 12px;
        }
        main > header h1 {
          flex: 1;
          min-inline-size: 0;
          overflow-wrap: anywhere;
        }
        main > header > :nth-child(1 of .button) {
          margin-inline-start: 0;
        }
        .e2e {
          margin-inline-start: 0;
        }
        form.invite {
          padding-inline: 12px;
        }
        .feed {
          padding-inline: 8px;
        }
        .avatar.big {
          inline-size: 32px;
          block-size: 32px;
        }
        .msg {
          grid-template-columns: 32px minmax(0, 1fr);
          gap: 10px;
        }
        /* A tapped message shows its actions under it, not over the one above. */
        .actions {
          position: static;
          grid-column: 2;
          flex-wrap: wrap;
        }
        .actions button {
          min-block-size: 44px;
          min-inline-size: 44px;
        }
        form.compose {
          margin-block: 0 12px;
          margin-inline: 12px;
        }
        .typing,
        .label {
          margin-inline: 16px;
        }
        aside.thread {
          inline-size: auto;
          border-inline-start: 0;
        }
        aside.thread header {
          justify-content: start;
          gap: 12px;
          padding-block: 10px;
          padding-inline: 12px;
        }
        aside.thread .close {
          display: none;
        }
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
  /** Why the rooms could not be loaded (shown only while none are on screen). */
  @state() private roomsFailed = "";
  @state() private creating: "channel" | "private" | "direct" | null = null;
  @state() private directory: RoomItem[] | null = null;
  @state() private taskFor: Message | null = null;
  @state() private projects: { id: string; name: string }[] = [];
  @state() private taskMade = "";
  @state() private files: { id: string; name: string; mime: string; kind?: string }[] | null = null;
  @state() private tasksInstalled = false;
  /** Whether this installation federates (Matrix). */
  @state() private federation = false;
  @state() private inviting = false;
  /** On a phone: the open room (or its thread) instead of the room list. */
  @state() private detail = false;
  /** Whether calls are installed, and how many are in the open room's call. */
  @state() private callsInstalled = false;
  @state() private inCall = 0;
  /** End-to-end trust: devices in the open sealed room nobody vouched for, and recovery. */
  @state() private unverified: { user: string; device: string }[] = [];
  /** The sealer's count of confirmed backup sessions when messages were last opened. */
  private confirmedSeen = 0;
  /** The open sealed room's devices could not be checked. */
  @state() private devicesUnchecked = false;
  @state() private recovery: RecoveryState | null = null;
  @state() private recoveryOpen = false;
  @state() private recoveryKey = "";
  @state() private recoveryNote = "";
  @state() private recoveryBusy = false;
  /** The organisation's escrow as set-up will use it, shown before the person confirms. */
  @state() private escrow: EscrowInfo | null = null;
  /** The escrow is being read: set-up waits for what it will show. */
  @state() private escrowLoading = false;
  /** The verification on screen (by emoji), and the list of who is not vouched for. */
  @state() private verification: VerificationView | null = null;
  @state() private unverifiedOpen = false;
  private verifier = 0;
  /** The camera, while the other device's code is scanned (its tracks always stopped after). */
  @state() private scanning = "";
  @state() private scanNote = "";
  private stream: MediaStream | null = null;
  private scanTimer = 0;
  /** End-to-end rooms on this browser. */
  private sealer: Sealer | null = null;
  private events: EventSource | null = null;
  private lastTyping = 0;

  private started = false;

  override connectedCallback(): void {
    super.connectedCallback();
    // The shell may move the element: it carries on as it was.
    if (this.started) {
      if (!this.events) this.listen();
      return;
    }
    this.started = true;
    void this.start();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    // Only a real departure closes the stream.
    window.setTimeout(() => {
      if (this.isConnected) return;
      this.events?.close();
      this.events = null;
      window.clearInterval(this.poller);
      this.poller = 0;
      window.clearInterval(this.verifier);
      this.verifier = 0;
      this.stopScan();
    }, 0);
  }

  private async start(): Promise<void> {
    await this.openFirst();
    call<{ federation?: boolean; encryptedRooms?: boolean }>("GET", "/chat/policy")
      .then((r) => {
        this.federation = !!r.federation;
        // This device's key, so members can give it room keys.
        if (r.encryptedRooms || this.rooms.some((x) => x.encrypted)) void this.sealer?.ready().catch(() => undefined);
      })
      .catch(() => undefined);
    call<{ apps: { id: string }[] }>("GET", "/apps")
      .then((r) => {
        this.tasksInstalled = r.apps.some((a) => a.id === "tasks");
        this.callsInstalled = r.apps.some((a) => a.id === "calls");
        if (this.callsInstalled && this.current) void this.loadCall(this.current);
      })
      .catch(() => undefined);
    this.listen();
  }

  private poller = 0;

  private listen(): void {
    // Besides the stream, a look every few seconds: nothing is missed
    // even when a proxy or a network holds the stream back.
    if (!this.poller) {
      this.poller = window.setInterval(() => void this.poll(), 4000);
    }
    if (!this.isConnected || this.events) return;
    this.events = new EventSource("/api/v1/chat/events");
    // After a break the stream starts afresh: read again what may have
    // been missed in between.
    let opened = false;
    this.events.addEventListener("open", () => {
      if (opened) void this.catchUp();
      opened = true;
    });
    this.events.addEventListener("event", (e) => void this.onEvent(JSON.parse((e as MessageEvent).data)));
    this.events.addEventListener("room", (e) => {
      const m = JSON.parse((e as MessageEvent).data) as { room: string };
      // The open room itself may have moved on meanwhile.
      if (m.room === this.current) void this.catchUp();
      else void this.loadRooms();
    });
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
    this.shown = Math.max(this.shown, m.seq);
    if (m.kind === "m.room.message") {
      const fetched = await call<Message>("GET", `/chat/messages/${encodeURIComponent(m.id)}`).catch(() => null);
      if (!fetched) return;
      const [one] = await this.reveal([fetched]);
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
        // A new member's devices get the room key; a key may have come.
        if (this.room()?.encrypted) await this.syncKeys(m.room);
      }
    } else if (m.kind === "ortus.call") {
      // A call started or ended in this room.
      await this.loadCall(m.room);
    } else if (m.about) {
      await this.refresh(m.about);
    }
  }

  private async loadCall(room: string): Promise<void> {
    if (!this.callsInstalled) return;
    const r = await call<{ call: { sessions: unknown[] } | null }>("GET", `/calls/rooms/${encodeURIComponent(room)}`).catch(() => null);
    if (room === this.current) this.inCall = r?.call?.sessions.length ?? 0;
  }

  /** Loads of a room's messages: only the newest is shown. */
  private loads = 0;

  private async loadMessages(room: string): Promise<void> {
    const n = ++this.loads;
    const list = await call<{ messages: Message[]; people: Record<string, Person> }>("GET", `/chat/rooms/${encodeURIComponent(room)}/messages`).catch(() => null);
    if (!list || n !== this.loads || room !== this.current) return;
    const messages = await this.reveal(list.messages);
    if (n !== this.loads || room !== this.current) return;
    this.people = { ...this.people, ...list.people };
    this.messages = messages;
  }

  /** The room's last event this screen has taken in. */
  private shown = 0;

  private async poll(): Promise<void> {
    if (!this.isConnected) return;
    // A list that never loaded: the rooms and the room to open, as at the start.
    if (this.roomsFailed) await this.openFirst();
    else await this.loadRooms().catch(() => undefined);
    const now = this.room()?.lastSeq ?? 0;
    if (this.current && now > this.shown) await this.catchUp();
    if (this.current && this.room()?.encrypted && this.room()?.state === "join") {
      // Members' new devices get the room key from this one; this one may
      // have been given it meanwhile.
      await this.syncKeys(this.current);
      // Locked ones may open now; ones from the backup may be confirmed.
      if (this.messages.some((m) => m.locked) || (this.messages.some((m) => m.fromBackup) && (this.sealer?.confirmed ?? 0) !== this.confirmedSeen)) await this.loadMessages(this.current);
    }
  }

  private async catchUp(): Promise<void> {
    await this.loadRooms();
    const room = this.current;
    if (!room) return;
    this.shown = Math.max(this.shown, this.room()?.lastSeq ?? 0);
    await this.loadMessages(room);
    if (this.thread) await this.openThread(this.thread);
  }

  /** One message again (after a reply, an edit, a reaction). */
  private async refresh(id: string): Promise<void> {
    const fetched = await call<Message>("GET", `/chat/messages/${encodeURIComponent(id)}`).catch(() => null);
    if (!fetched) return;
    const [one] = await this.reveal([fetched]);
    if (!one) return;
    this.messages = this.messages.map((x) => (x.id === id ? one : x));
    this.threadMessages = this.threadMessages.map((x) => (x.id === id ? one : x));
  }

  /** The rooms, then the room the address names (or the first one joined). */
  private async openFirst(): Promise<void> {
    try {
      await this.loadRooms();
    } catch {
      return;
    }
    const p = new URLSearchParams(location.search);
    const room = p.get("room") ?? this.rooms.find((r) => r.state === "join")?.id ?? null;
    // On a phone the list comes first, unless the address names a room.
    if (room) await this.open(room, p.get("thread") ?? undefined, p.has("room"));
  }

  private async loadRooms(): Promise<void> {
    let r: { rooms: RoomItem[]; people: Record<string, Person>; me: string };
    try {
      r = await call<{ rooms: RoomItem[]; people: Record<string, Person>; me: string }>("GET", "/chat/rooms");
    } catch (err) {
      // Rooms already on screen stay; a list never loaded says it failed,
      // so a failure never looks like having no rooms.
      if (!this.rooms.length) this.roomsFailed = t(this.localize, "roomsFailed");
      throw err;
    }
    this.roomsFailed = "";
    this.rooms = r.rooms;
    this.people = { ...this.people, ...r.people };
    if (r.me !== this.me || !this.sealer) {
      this.sealer = new Sealer(r.me);
      this.sealer.onVerification = (v) => {
        this.verification = v;
        // The camera only while their code can still be scanned.
        if (this.scanning && (v.id !== this.scanning || (v.state !== "qr" && v.state !== "ready"))) this.stopScan();
        if (v.state === "done" && this.current) void this.syncKeys(this.current);
      };
      // Verification requests come to this device as to-device messages.
      window.clearInterval(this.verifier);
      this.verifier = window.setInterval(() => void this.sealer?.pollVerifications().catch(() => undefined), 3000);
    }
    this.me = r.me;
  }

  private room(): RoomItem | undefined {
    return this.rooms.find((r) => r.id === this.current);
  }

  private async open(id: string, thread?: string, show = true): Promise<void> {
    this.error = "";
    this.current = id;
    this.detail = show;
    this.inCall = 0;
    void this.loadCall(id);
    this.thread = null;
    const url = new URL(location.href);
    url.searchParams.set("room", id);
    url.searchParams.delete("thread");
    url.searchParams.delete("message");
    history.replaceState(null, "", url);
    const [info] = await Promise.all([
      call<{ members: Member[]; people: Record<string, Person>; state: string }>("GET", `/chat/rooms/${encodeURIComponent(id)}`).catch(() => null),
      this.loadMessages(id),
    ]);
    if (!info) {
      // Invited to a private room: it opens once joined.
      this.members = [];
      this.messages = [];
      return;
    }
    this.members = info.members;
    this.people = { ...this.people, ...info.people };
    if (this.room()?.encrypted && this.room()?.state === "join") {
      await this.syncKeys(id);
      await this.loadMessages(id);
    }
    this.shown = this.room()?.lastSeq ?? 0;
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

  /** Room keys for this device, and for members' devices that lack them. */
  private async syncKeys(room: string): Promise<void> {
    const roomId = this.rooms.find((r) => r.id === room)?.roomId;
    if (!roomId) return;
    void this.sealer?.pin(room).catch(() => undefined);
    await this.sealer?.sync(room, roomId).catch(() => undefined);
    if (this.current === room && this.sealer) {
      // Not knowing is said, never taken as nobody unverified.
      try {
        this.unverified = await this.sealer.unverified(room);
        this.devicesUnchecked = false;
      } catch {
        this.unverified = [];
        this.devicesUnchecked = true;
      }
      this.recovery = await this.sealer.recoveryState().catch(() => null);
    }
  }

  /** Set-up's refusals of the escrow, in the person's language. */
  private escrowError(e: unknown): string {
    const message = e instanceof Error ? e.message : String(e);
    if (message === ESCROW_UNSIGNED) return t(this.localize, "recoveryEscrowUnsigned");
    if (message === ESCROW_NOT_ACCEPTED) return t(this.localize, "recoveryEscrowNotShown");
    return message;
  }

  private async openRecovery(): Promise<void> {
    this.recoveryOpen = true;
    await this.loadEscrow();
  }

  /** The escrow to show before set-up (none, or why set-up would be refused). */
  private async loadEscrow(): Promise<void> {
    this.escrow = null;
    if (!this.sealer || this.recovery?.set) return;
    this.escrowLoading = true;
    try {
      this.escrow = await this.sealer.escrowInfo();
    } catch (e) {
      this.recoveryNote = this.escrowError(e);
    } finally {
      this.escrowLoading = false;
    }
  }

  private async setUpRecovery(): Promise<void> {
    if (!this.sealer) return;
    this.recoveryBusy = true;
    this.recoveryNote = "";
    try {
      this.recoveryKey = await this.sealer.setUpRecovery(this.escrow?.key);
      this.recovery = await this.sealer.recoveryState();
    } catch (e) {
      this.recoveryNote = e instanceof ApiError ? e.message : this.escrowError(e);
      // The escrow changed meanwhile: show the one set-up would use now.
      if (e instanceof Error && e.message === ESCROW_NOT_ACCEPTED) {
        const note = this.recoveryNote;
        await this.loadEscrow();
        this.recoveryNote = note;
      }
    } finally {
      this.recoveryBusy = false;
    }
  }

  private escrowLines() {
    const e = this.escrow;
    if (!e) return nothing;
    const status = t(this.localize, e.signerStatus === "you" ? "escrowSignerYou" : e.signerStatus === "verified" ? "escrowSignerVerified" : "escrowSignerUnverified");
    const name = e.signer === this.me ? t(this.localize, "escrowSignerYou") : (this.people[e.signer]?.name ?? e.signer);
    return html`<p data-testid="recovery-escrow">${t(this.localize, "recoveryEscrowInfo", { fingerprint: e.fingerprint, name, status })}</p>
      ${e.changed ? html`<p class="note" role="alert">${t(this.localize, "recoveryEscrowChanged")}</p>` : nothing}`;
  }

  private async recoverWithKey(e: Event): Promise<void> {
    e.preventDefault();
    if (!this.sealer) return;
    const typed = ((e.target as HTMLFormElement).elements.namedItem("recoveryKey") as HTMLInputElement).value;
    this.recoveryBusy = true;
    this.recoveryNote = "";
    try {
      const count = await this.sealer.recover(typed);
      this.recoveryNote = count === null ? t(this.localize, "recoveryWrong") : t(this.localize, "recoveryRestored", { count });
      this.recovery = await this.sealer.recoveryState();
      if (count !== null && this.current) await this.loadMessages(this.current);
    } catch (err) {
      this.recoveryNote = err instanceof ApiError ? err.message : String(err);
    } finally {
      this.recoveryBusy = false;
    }
  }

  /**
   * Scans the other device's code: the back camera, a frame every 150 ms
   * (at most 800 pixels a side) read by qrscan.ts, until a code of this
   * verification is taken, or the dialog moves on or closes.
   */
  private async startScan(id: string): Promise<void> {
    this.stopScan();
    this.scanNote = "";
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
    } catch (e) {
      this.scanNote = t(this.localize, (e as { name?: string })?.name === "NotAllowedError" ? "verifyCameraRefused" : "verifyCameraFailed");
      return;
    }
    const v = this.verification;
    if (!v || v.id !== id || (v.state !== "qr" && v.state !== "ready")) {
      stream.getTracks().forEach((track) => track.stop());
      return;
    }
    this.stream = stream;
    this.scanning = id;
    await this.updateComplete;
    const video = this.renderRoot.querySelector<HTMLVideoElement>("video.scan");
    if (!video || this.stream !== stream) return this.stopScan();
    video.srcObject = stream;
    await video.play().catch(() => undefined);
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d", { willReadFrequently: true });
    const tick = async (): Promise<void> => {
      this.scanTimer = 0;
      if (this.stream !== stream) return;
      if (context && video.readyState >= 2 && video.videoWidth > 0) {
        const scale = Math.min(1, 800 / Math.max(video.videoWidth, video.videoHeight));
        canvas.width = Math.round(video.videoWidth * scale);
        canvas.height = Math.round(video.videoHeight * scale);
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        const bytes = decodeQr(context.getImageData(0, 0, canvas.width, canvas.height));
        if (bytes) {
          if (await this.sealer?.scanCode(id, bytes).catch(() => false)) return this.stopScan();
          this.scanNote = t(this.localize, "verifyScanOther");
        }
      }
      if (this.stream === stream) this.scanTimer = window.setTimeout(() => void tick(), 150);
    };
    void tick();
  }

  private stopScan(): void {
    window.clearTimeout(this.scanTimer);
    this.scanTimer = 0;
    this.stream?.getTracks().forEach((track) => track.stop());
    this.stream = null;
    this.scanning = "";
  }

  /** Scanning the other device's code: the camera, or the button that opens it. */
  private scanPart(v: VerificationView) {
    if (!v.canScan) return nothing;
    const note = this.scanNote ? html`<p role="status" class="note">${this.scanNote}</p>` : nothing;
    if (this.scanning === v.id)
      return html`<p>${t(this.localize, "verifyScanLead")}</p>
        <video class="scan" data-testid="verify-camera" aria-label=${t(this.localize, "verifyCameraLabel")} muted playsinline></video>
        ${note}
        <div class="row"><button type="button" class="button" @click=${() => this.stopScan()}>${t(this.localize, "verifyScanStop")}</button></div>`;
    return html`${note}<div class="row"><button type="button" class="button" @click=${() => void this.startScan(v.id)}>${t(this.localize, "verifyScanTheirs")}</button></div>`;
  }

  private verifyDialogs() {
    const v = this.verification;
    const name = (user: string) => (user === this.me ? t(this.localize, "yourOtherDevice") : (this.people[user]?.name ?? user));
    const unverifiedUsers = [...new Set(this.unverified.map((d) => d.user))];
    return html`${this.unverifiedOpen
      ? html`<dialog class="modal" aria-label=${t(this.localize, "unverifiedTitle")} @close=${() => (this.unverifiedOpen = false)}>
          <form method="dialog">
            <h2>${t(this.localize, "unverifiedTitle")}</h2>
            <p>${t(this.localize, "unverifiedLead")}</p>
            <ul>
              ${unverifiedUsers.map(
                (user) => html`<li class="row"><span>${user === this.me ? t(this.localize, "yourDevices") : (this.people[user]?.name ?? user)} · ${this.unverified.filter((d) => d.user === user).map((d) => d.device).join(", ")}</span>
                  <button type="button" class="button" @click=${() => ((this.unverifiedOpen = false), void this.sealer?.verify(user))}>${t(this.localize, "verify")}</button></li>`,
              )}
            </ul>
            <button class="button">${t(this.localize, "close")}</button>
          </form>
        </dialog>`
      : nothing}${v
      ? html`<dialog class="modal" aria-label=${t(this.localize, "verifyTitle")} @close=${() => {
          this.stopScan();
          this.scanNote = "";
          if (this.verification && this.verification.state !== "done" && this.verification.state !== "unsigned" && this.verification.state !== "cancelled") void this.sealer?.cancelVerification(this.verification.id);
          this.verification = null;
        }}>
          <form method="dialog">
            <h2>${t(this.localize, "verifyTitle")}</h2>
            ${v.state === "requested"
              ? html`<p role="status">${t(this.localize, "verifyRequested", { name: name(v.user) })}</p>`
              : v.state === "incoming"
                ? html`<p>${t(this.localize, "verifyIncoming", { name: name(v.user) })}</p>
                    <div class="row"><button class="button">${t(this.localize, "verifyDecline")}</button>
                    <button type="button" class="button primary" @click=${() => void this.sealer?.acceptVerification(v.id)}>${t(this.localize, "verifyAccept")}</button></div>`
                : v.state === "qr" && v.qr
                  ? html`${this.scanning === v.id
                        ? nothing
                        : html`<p>${t(this.localize, "verifyScanThis")}</p>
                            ${qrSvg(v.qr, t(this.localize, "verifyCodeLabel"))}`}
                      ${this.scanPart(v)}
                      <div class="row"><button type="button" class="button" @click=${() => void this.sealer?.startEmoji(v.id)}>${t(this.localize, "verifyUseEmoji")}</button></div>`
                : v.state === "ready"
                  ? html`<p>${t(this.localize, "verifyChoose")}</p>
                      ${this.scanPart(v)}
                      <div class="row"><button type="button" class="button" @click=${() => void this.sealer?.startEmoji(v.id)}>${t(this.localize, "verifyUseEmoji")}</button></div>`
                : v.state === "scanned"
                  ? html`<p>${t(this.localize, "verifyScanned")}</p>
                      <div class="row"><button type="button" class="button" @click=${() => void this.sealer?.confirmScanned(v.id, false)}>${t(this.localize, "verifyScannedNo")}</button>
                      <button type="button" class="button primary" @click=${() => void this.sealer?.confirmScanned(v.id, true)}>${t(this.localize, "verifyScannedYes")}</button></div>`
                : v.state === "waiting"
                  ? html`<p role="status">${t(this.localize, v.scannedTheirs ? "verifyScannedWait" : "verifyWaiting")}</p>`
                  : v.state === "emoji"
                    ? html`<p>${t(this.localize, "verifyCompare")}</p>
                        <p class="emoji" data-testid="verify-emoji">${(v.emoji ?? []).map((n) => html`<span>${EMOJI[n]}</span>`)}</p>
                        <div class="row"><button type="button" class="button" @click=${() => void this.sealer?.confirmEmoji(v.id, false)}>${t(this.localize, "verifyDifferent")}</button>
                        <button type="button" class="button primary" @click=${() => void this.sealer?.confirmEmoji(v.id, true)}>${t(this.localize, "verifySame")}</button></div>`
                    : v.state === "done"
                      ? html`<p role="status">${t(this.localize, "verifyDone")}</p>`
                      : v.state === "unsigned"
                        ? html`<p role="status">${t(this.localize, "verifyUnsigned")}</p>`
                      : html`<p role="status">${t(this.localize, "verifyCancelled", { reason: v.reason ?? "" })}</p>`}
            ${v.state === "done" || v.state === "unsigned" || v.state === "cancelled" || v.state === "requested" || v.state === "waiting" || v.state === "qr" || v.state === "ready" ? html`<button class="button">${t(this.localize, "close")}</button>` : nothing}
          </form>
        </dialog>`
      : nothing}`;
  }

  private recoveryDialog() {
    if (!this.recoveryOpen) return nothing;
    const r = this.recovery;
    const close = () => ((this.recoveryOpen = false), (this.recoveryKey = ""), (this.recoveryNote = ""), (this.escrow = null));
    return html`<dialog class="modal recovery" aria-label=${t(this.localize, "recoveryTitle")} @close=${close}>
      <form method="dialog" @submit=${(e: Event) => (r?.set && !r.here ? this.recoverWithKey(e) : undefined)}>
        <h2>${t(this.localize, "recoveryTitle")}</h2>
        ${this.recoveryKey
          ? html`<p>${t(this.localize, "recoveryKeyShown")}</p>
              <p><code class="recovery-key" data-testid="recovery-key">${this.recoveryKey}</code></p>
              ${r?.escrow ? html`<p class="muted">${t(this.localize, "recoveryEscrow")}</p>` : nothing}
              <div class="row"><button type="button" class="button primary" @click=${close}>${t(this.localize, "recoverySaved")}</button></div>`
          : !r?.set
            ? html`<p>${t(this.localize, "recoverySetUpLead")}</p>
                ${this.escrowLines()}
                <div class="row"><button type="button" class="button" @click=${close}>${t(this.localize, "cancel")}</button>
                <button type="button" class="button primary" ?disabled=${this.recoveryBusy || this.escrowLoading} @click=${() => void this.setUpRecovery()}>${t(this.localize, "recoverySetUp")}</button></div>`
            : !r.here
              ? html`<p>${t(this.localize, "recoveryEnterLead")}</p>
                  <label>${t(this.localize, "recoveryKeyLabel")}<input class="input" name="recoveryKey" autocomplete="off" spellcheck="false" required /></label>
                  <div class="row"><button type="button" class="button" @click=${close}>${t(this.localize, "cancel")}</button>
                  <button class="button primary" ?disabled=${this.recoveryBusy}>${t(this.localize, "recoveryEnter")}</button></div>`
              : html`<p>${t(this.localize, "recoveryHere")}</p>
                  <div class="row"><button type="button" class="button" @click=${() => (close(), void this.sealer?.verify(this.me))}>${t(this.localize, "verifyMine")}</button>
                  <button type="button" class="button primary" @click=${close}>${t(this.localize, "close")}</button></div>`}
        ${this.recoveryNote ? html`<p role="status" class="note">${this.recoveryNote}</p>` : nothing}
      </form>
    </dialog>`;
  }

  /** Sealed messages opened on this device (or marked as not readable). */
  private async reveal(list: Message[]): Promise<Message[]> {
    const sealer = this.sealer;
    this.confirmedSeen = sealer?.confirmed ?? 0;
    return Promise.all(
      list.map(async (m) => {
        if (!m.sealed || m.deleted || !sealer) return m;
        const roomId = this.rooms.find((r) => r.id === m.room)?.roomId ?? "";
        const opened = await sealer.open(m.room, roomId, m.sealed, m.sender, m.id, m.thread);
        return opened === null ? { ...m, text: "", locked: true, fromBackup: false } : { ...m, text: opened.text, locked: false, fromBackup: opened.fromBackup };
      }),
    );
  }

  private async openThread(id: string): Promise<void> {
    this.thread = id;
    this.taskMade = "";
    const r = await call<{ messages: Message[]; people: Record<string, Person> }>("GET", `/chat/rooms/${encodeURIComponent(this.current!)}/messages?thread=${encodeURIComponent(id)}`);
    this.people = { ...this.people, ...r.people };
    this.threadMessages = await this.reveal(r.messages);
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
    // The room as it was when sending began (switching rooms meanwhile
    // must not send it elsewhere).
    const current = this.current;
    const room = this.room();
    if (!text || !current || !room) return;
    try {
      if (room.encrypted) {
        if (!this.sealer || !room.roomId) throw new Error(t(this.localize, "noRoomKey"));
        await this.sealer.send(current, room.roomId, text, thread);
      } else {
        // A room this browser saw sealed is never written to in the clear.
        if (await this.sealer?.pinned(current).catch(() => false)) throw new Error(t(this.localize, "notSealed"));
        await call("POST", `/chat/rooms/${encodeURIComponent(current)}/messages`, { text, thread, mentions: this.mentions(text), decision });
      }
      box.value = "";
      if (thread) await this.openThread(thread);
      else if (this.current === current) {
        await this.loadMessages(current);
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

  /** Editing or deleting a message asks in a dialog of its own. */
  @state() private asking: { kind: "edit" | "delete"; m: Message; text: string } | null = null;

  private async edit(m: Message): Promise<void> {
    this.asking = { kind: "edit", m, text: m.text };
    await this.updateComplete;
    this.renderRoot.querySelector<HTMLDialogElement>("dialog.ask")?.showModal();
  }

  private async deleteMessage(m: Message): Promise<void> {
    this.asking = { kind: "delete", m, text: "" };
    await this.updateComplete;
    this.renderRoot.querySelector<HTMLDialogElement>("dialog.ask")?.showModal();
  }

  private closeAsk(): void {
    this.renderRoot.querySelector<HTMLDialogElement>("dialog.ask")?.close();
    this.asking = null;
  }

  private async answerAsk(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    const asked = this.asking;
    if (!asked) return;
    this.closeAsk();
    if (asked.kind === "delete") {
      await call("DELETE", `/chat/messages/${encodeURIComponent(asked.m.id)}`);
      await this.refresh(asked.m.id);
      return;
    }
    if (!asked.text.trim() || asked.text === asked.m.text) return;
    await this.saveEdit(asked.m, asked.text);
  }

  private askDialog() {
    const a = this.asking;
    if (!a) return nothing;
    return html`<dialog class="ask" aria-labelledby="ask-title" @cancel=${() => (this.asking = null)}>
      <form method="dialog" @submit=${this.answerAsk}>
        <h2 id="ask-title">${t(this.localize, a.kind === "edit" ? "editMessage" : "deleteSure")}</h2>
        ${a.kind === "edit"
          ? html`<textarea aria-label=${t(this.localize, "editMessage")} .value=${a.text} @input=${(e: InputEvent) => (this.asking = { ...a, text: (e.target as HTMLTextAreaElement).value })}></textarea>`
          : nothing}
        <div class="ask-actions">
          <button type="button" @click=${() => this.closeAsk()}>${t(this.localize, "cancel")}</button>
          <button type="submit" class=${a.kind === "delete" ? "danger" : "primary"}>${t(this.localize, a.kind === "edit" ? "save" : "delete")}</button>
        </div>
      </form>
    </dialog>`;
  }

  private async saveEdit(m: Message, text: string): Promise<void> {
    if (await this.sealer?.pinned(m.room).catch(() => false)) {
      this.error = t(this.localize, "notSealed");
      return;
    }
    await call("PATCH", `/chat/messages/${encodeURIComponent(m.id)}`, { text });
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

  private isOwner(): boolean {
    return this.members.some((m) => m.id === this.me && m.role === "owner");
  }

  private async share(id: string): Promise<void> {
    this.error = "";
    try {
      await call("POST", `/chat/rooms/${encodeURIComponent(id)}/share`);
      await this.loadRooms();
    } catch (e) {
      this.error = (e as Error).message;
    }
  }

  private async invite(e: Event, id: string): Promise<void> {
    e.preventDefault();
    const field = (e.target as HTMLFormElement).elements.namedItem("people") as HTMLInputElement;
    const people = field.value.split(",").map((a) => a.trim()).filter(Boolean);
    if (!people.length) return;
    this.error = "";
    try {
      await call("PATCH", `/chat/rooms/${encodeURIComponent(id)}`, { invite: people });
      this.inviting = false;
      await this.open(id);
    } catch (err) {
      this.error = (err as Error).message;
    }
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
    // A link is plain text: never into a room this browser saw sealed.
    if (this.room()?.encrypted || (await this.sealer?.pinned(this.current).catch(() => false))) {
      this.error = t(this.localize, "notSealed");
      return;
    }
    await call("POST", `/chat/rooms/${encodeURIComponent(this.current)}/messages`, { text: "", file: id });
    await this.loadMessages(this.current);
  }

  private avatar(id: string, big = false): TemplateResult {
    const n = this.name(id);
    const person = this.people[id];
    return html`<ortus-avatar class="avatar ${big ? "big" : ""}" aria-hidden="true" .style=${`background: ${tone(n)}`} .name=${n} .user=${person?.local ? id : ""} .email=${person?.local ? (person.email ?? "") : ""}></ortus-avatar>`;
  }

  private body(m: Message): TemplateResult {
    if (m.deleted) return html`<p class="gone">${t(this.localize, "deleted")}</p>`;
    if (m.locked) return html`<p class="gone">🔒 ${t(this.localize, "cannotRead")}</p>`;
    if (m.hook?.alert) return html`<p><span class="alert-chip">${t(this.localize, "alert")}</span> ${m.text}</p>`;
    // @Name of a mentioned person stands out.
    const names = (m.mentions ?? []).map((id) => `@${this.name(id).split(" ")[0]}`);
    const parts = names.length ? m.text.split(new RegExp(`(${names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`)) : [m.text];
    return html`<p>${parts.map((p) => (names.includes(p) ? html`<span class="mention">${p}</span>` : p))}${m.editedAt ? html` <small class="muted">${t(this.localize, "edited")}</small>` : nothing}</p>${m.fromBackup ? html`<p class="gone from-backup">${t(this.localize, "fromBackup")}</p>` : nothing}`;
  }

  private message(m: Message, inThread = false): TemplateResult {
    const mine = m.sender === this.me;
    // Focusable, so its actions (shown on hover) are reached from the keyboard too.
    return html`<article class=${inThread ? "post" : "msg"} tabindex="0" aria-label=${t(this.localize, "messageFrom", { who: this.name(m.sender) })}>
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
            ${mine ? html`${m.sealed ? nothing : html`<button @click=${() => this.edit(m)}>${t(this.localize, "edit")}</button>`}<button @click=${() => this.deleteMessage(m)}>${t(this.localize, "delete")}</button>` : nothing}
          </div>`}
    </article>`;
  }

  private dialogs(): TemplateResult {
    return html`${this.recoveryDialog()}${this.verifyDialogs()}${this.creating
        ? html`<dialog class="modal" aria-label=${t(this.localize, this.creating === "direct" ? "newDirect" : "newChannel")} @close=${() => ((this.creating = null), (this.error = ""))}>
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
        ? html`<dialog class="modal" aria-label=${t(this.localize, "browseChannels")} @close=${() => (this.directory = null)}>
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
        ? html`<dialog class="modal" aria-label=${t(this.localize, "turnIntoTask")} @close=${() => ((this.taskFor = null), (this.error = ""))}>
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
        ? html`<dialog class="modal" aria-label=${t(this.localize, "fromDrive")} @close=${() => (this.files = null)}>
            <form @submit=${(e: Event) => e.preventDefault()}>
              <h2>${t(this.localize, "fromDrive")}</h2>
              <ul>${this.files.map((f) => html`<li><button type="button" class="button wide" @click=${() => this.sendFile(f.id)}>${f.name}</button></li>`)}</ul>
              ${this.files.length ? nothing : html`<p class="muted">${t(this.localize, "noFiles")}</p>`}
              <button type="button" class="button" @click=${() => (this.files = null)}>${t(this.localize, "cancel")}</button>
            </form>
          </dialog>`
        : nothing}`;
  }

  /** What had focus before a dialog opened. */
  private opener: HTMLElement | null = null;

  override updated(): void {
    // A dialog that just appeared opens as a modal: focus moves into it,
    // the page behind is inert and Escape closes it.
    const shown = this.renderRoot.querySelectorAll<HTMLDialogElement>("dialog.modal");
    for (const d of shown) {
      if (d.open) continue;
      this.opener ??= deepFocus();
      d.showModal();
    }
    // Closed by a button, not by Escape: focus goes back where it was.
    if (!shown.length && this.opener) {
      const back = this.opener;
      this.opener = null;
      if (back.isConnected) back.focus();
    }
  }

  override willUpdate(): void {
    // Phone-sized screens show one pane: the attribute says which (CSS).
    this.toggleAttribute("detail", this.detail && !!this.current);
    this.toggleAttribute("threaded", !!this.thread);
  }

  /** On a phone: back from the room to the list. */
  private back(): void {
    this.detail = false;
    this.thread = null;
  }

  override render() {
    return html`${this.page()}${this.askDialog()}`;
  }

  private page() {
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
      <main class=${this.inviting && room && room.kind !== "direct" ? "inviting" : ""}>
        ${room
          ? html`<header>
                <button class="icon back" aria-label=${t(this.localize, "back")} @click=${this.back}>${backArrow}</button>
                <h1>${room.kind === "direct" ? this.roomName(room) : `# ${room.name}`}</h1>
                ${room.label ? html`<span class="label">${room.label.toUpperCase()}</span>` : nothing}
                <span class="muted">${t(this.localize, "members", { count: this.members.filter((m) => m.state === "join").length })}</span>
                ${room.encrypted ? html`<span class="e2e">🔒 ${t(this.localize, "endToEnd")}</span>` : nothing}
                ${room.encrypted && this.devicesUnchecked
                  ? html`<span role="status" class="unchecked">⚠ ${t(this.localize, "devicesUnchecked")}</span>`
                  : nothing}
                ${room.encrypted && this.unverified.length
                  ? html`<span role="status"><button class="unverified" title=${this.unverified.map((d) => `${this.people[d.user]?.name ?? d.user} · ${d.device}`).join("\n")} @click=${() => (this.unverifiedOpen = true)}>⚠ ${t(this.localize, "unverifiedDevices", { count: this.unverified.length })}</button></span>`
                  : nothing}
                ${room.encrypted ? html`<button class="button" @click=${() => void this.openRecovery()}>${t(this.localize, "recovery")}</button>` : nothing}
                ${room.federated
                  ? html`<span class="shared">${t(this.localize, "sharedWithPartners")} <code>${room.roomId ?? ""}</code></span>`
                  : this.federation && room.kind !== "direct" && !room.encrypted && this.isOwner()
                    ? html`<button class="button" @click=${() => this.share(room.id)}>${t(this.localize, "shareWithPartners")}</button>`
                    : nothing}
                ${this.callsInstalled && room.state === "join" && !room.encrypted
                  ? html`<a class="button ${this.inCall ? "primary" : ""}" href=${`/calls?room=${encodeURIComponent(room.id)}`}>${this.inCall ? t(this.localize, "joinCall", { count: this.inCall }) : t(this.localize, "callButton")}</a>`
                  : nothing}
                ${room.kind !== "direct" && room.state === "join"
                  ? html`<button class="button" @click=${() => (this.inviting = !this.inviting)}>${t(this.localize, "inviteButton")}</button>`
                  : nothing}
              </header>
              ${this.inviting && room.kind !== "direct"
                ? html`<form class="invite" @submit=${(e: Event) => this.invite(e, room.id)}>
                    <label>${t(this.localize, "invite")}<input class="input" name="people" required placeholder=${room.federated ? t(this.localize, "addressesOrPartners") : t(this.localize, "addresses")} /></label>
                    <button class="button primary">${t(this.localize, "inviteButton")}</button>
                    ${this.error ? html`<p class="error" role="alert">${this.error}</p>` : nothing}
                  </form>`
                : nothing}
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
                        ${room.encrypted ? nothing : html`<button type="button" class="icon" aria-label=${t(this.localize, "fromDrive")} @click=${this.pickFile}>
                          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 12.5 12.6 20.9a5.5 5.5 0 0 1-7.8-7.8l8.5-8.5a3.7 3.7 0 0 1 5.2 5.2l-8.5 8.5a1.8 1.8 0 0 1-2.6-2.6l7.8-7.8" /></svg>
                        </button>`}
                        <button class="icon send" aria-label=${t(this.localize, "send")}>→</button>
                      </div>
                      ${this.error ? html`<p class="error" role="alert">${this.error}</p>` : nothing}
                    </form>`
                  : nothing}
              </div>`
          : this.roomsFailed
            ? html`<div class="empty"><p class="error" role="alert">${this.roomsFailed}</p><button class="button primary" @click=${() => void this.openFirst()}>${t(this.localize, "tryAgain")}</button></div>`
            : html`<div class="empty"><p>${t(this.localize, "noRoom")}</p><button class="button primary" @click=${() => (this.creating = "channel")}>${t(this.localize, "newChannel")}</button></div>`}
      </main>
      ${this.thread
        ? html`<aside class="thread" aria-label=${t(this.localize, "thread")}>
            <header>
              <button class="icon back" aria-label=${t(this.localize, "back")} @click=${() => (this.thread = null)}>${backArrow}</button>
              <h2>${t(this.localize, "thread")}</h2>
              <button class="icon close" aria-label=${t(this.localize, "close")} @click=${() => (this.thread = null)}>×</button>
            </header>
            <div class="list">${root ? this.message(root, true) : nothing}${this.threadMessages.filter((m) => m.id !== this.thread).map((m) => this.message(m, true))}</div>
            ${room?.state === "join"
              ? html`<form @submit=${(e: Event) => this.send(e, this.thread!)}>
                  <textarea class="input" rows="2" aria-label=${t(this.localize, "replyToThread")} placeholder=${t(this.localize, "replyToThread")} @keydown=${this.keydown}></textarea>
                  ${room?.encrypted ? nothing : html`<label><input type="checkbox" class="decision" /> ${t(this.localize, "recordAsDecision")}</label>`}
                  <button class="button primary">${t(this.localize, "reply")}</button>
                </form>`
              : nothing}
          </aside>`
        : nothing}
      ${this.dialogs()}`;
  }
}
