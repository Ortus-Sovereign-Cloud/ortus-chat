// Admin › Chat: whether end-to-end rooms may be made, the organisation's
// escrow key (made in this browser: the server keeps only its public half;
// the private half is a file the administrator keeps offline), and a
// person's recovery key opened from their escrow copy with that file.
import { LitElement, LocalizeController, ApiError, call, controls, css, customElement, html, nothing, state } from "ortus-kit";
import { ready, t } from "./i18n.js";
import { b64, unb64 } from "./olm.js";
import { unseal, x25519FromSeed, type Sealed } from "./trust.js";

await ready;

interface EscrowFile {
  kind: "ortus-escrow-key";
  public: string;
  private: string;
}

@customElement("ortus-chat-admin")
export class OrtusChatAdmin extends LitElement {
  static override styles = [
    controls,
    css`
      :host {
        display: block;
      }
      section {
        margin-block-end: 32px;
      }
      h2 {
        font-size: 18px;
        margin-block: 0 8px;
      }
      p {
        color: var(--ortus-text-2);
        max-inline-size: 64ch;
      }
      .row {
        display: flex;
        gap: 12px;
        align-items: center;
        flex-wrap: wrap;
        margin-block: 12px;
      }
      code {
        font-family: ui-monospace, monospace;
        word-break: break-all;
      }
      .key {
        display: block;
        padding: 12px;
        border-radius: 10px;
        background: var(--ortus-surface-2, rgb(255 255 255 / 0.06));
        font-size: 15px;
        word-spacing: 6px;
        user-select: all;
      }
    `,
  ];

  private readonly localize = new LocalizeController(this);
  @state() private encryptedRooms = false;
  @state() private escrowKey: string | null = null;
  @state() private note = "";
  @state() private recovered = "";
  @state() private busy = false;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    const p = await call<{ encryptedRooms: boolean; escrowKey?: string | null }>("GET", "/chat/policy");
    this.encryptedRooms = p.encryptedRooms;
    this.escrowKey = p.escrowKey ?? null;
  }

  private async setRooms(e: Event): Promise<void> {
    const on = (e.target as HTMLInputElement).checked;
    await call("PATCH", "/chat/policy", { encryptedRooms: on });
    await this.load();
  }

  /** A new escrow key: its private half goes to a file here, never to the server. */
  private async makeEscrow(): Promise<void> {
    this.busy = true;
    this.note = "";
    try {
      const key = await x25519FromSeed(crypto.getRandomValues(new Uint8Array(32)));
      const file: EscrowFile = { kind: "ortus-escrow-key", public: b64(key.publicKey), private: b64(key.seed) };
      const url = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = "ortus-escrow-key.json";
      a.click();
      URL.revokeObjectURL(url);
      await call("PATCH", "/chat/policy", { escrowKey: file.public });
      await this.load();
      this.note = t(this.localize, "escrowMade");
    } catch (e) {
      this.note = e instanceof ApiError ? e.message : String(e);
    } finally {
      this.busy = false;
    }
  }

  /** A person's recovery key, from their escrow copy and the escrow file. */
  private async recover(e: Event): Promise<void> {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const email = (form.elements.namedItem("email") as HTMLInputElement).value.trim();
    const picked = (form.elements.namedItem("escrowFile") as HTMLInputElement).files?.[0];
    this.recovered = "";
    this.note = "";
    if (!picked) return;
    this.busy = true;
    try {
      const file = JSON.parse(await picked.text()) as Partial<EscrowFile>;
      if (file.kind !== "ortus-escrow-key" || !file.private) throw new Error(t(this.localize, "escrowNotAFile"));
      const key = await x25519FromSeed(unb64(file.private));
      const copy = await call<{ key: string; sealed: Sealed }>("GET", `/chat/admin/escrow?email=${encodeURIComponent(email)}`);
      if (copy.key !== b64(key.publicKey)) throw new Error(t(this.localize, "escrowOtherKey"));
      const opened = await unseal(key, copy.sealed);
      if (!opened) throw new Error(t(this.localize, "escrowOtherKey"));
      this.recovered = opened;
    } catch (err) {
      this.note = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err);
    } finally {
      this.busy = false;
    }
  }

  override render() {
    return html`
      <section>
        <h2>${t(this.localize, "endToEndRooms")}</h2>
        <p>${t(this.localize, "endToEndRoomsLead")}</p>
        <label class="row"><input type="checkbox" .checked=${this.encryptedRooms} @change=${this.setRooms} /> ${t(this.localize, "endToEndRoomsAllowed")}</label>
      </section>
      <section>
        <h2>${t(this.localize, "escrowTitle")}</h2>
        <p>${t(this.localize, "escrowLead")}</p>
        ${this.escrowKey
          ? html`<p>${t(this.localize, "escrowSet")} <code>${this.escrowKey.slice(0, 12)}…</code></p>`
          : html`<div class="row"><button class="button primary" ?disabled=${this.busy} @click=${this.makeEscrow}>${t(this.localize, "escrowMake")}</button></div>`}
      </section>
      ${this.escrowKey
        ? html`<section>
            <h2>${t(this.localize, "escrowRecoverTitle")}</h2>
            <p>${t(this.localize, "escrowRecoverLead")}</p>
            <form @submit=${this.recover}>
              <div class="row">
                <label>${t(this.localize, "email")} <input class="input" name="email" type="email" required /></label>
                <label>${t(this.localize, "escrowFile")} <input name="escrowFile" type="file" accept="application/json,.json" required /></label>
                <button class="button" ?disabled=${this.busy}>${t(this.localize, "escrowRecover")}</button>
              </div>
            </form>
            ${this.recovered ? html`<p>${t(this.localize, "escrowRecovered")}</p><code class="key" data-testid="escrowed-key">${this.recovered}</code>` : nothing}
          </section>`
        : nothing}
      ${this.note ? html`<p role="status">${this.note}</p>` : nothing}
    `;
  }
}
