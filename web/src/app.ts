// The chat client: the element the shell shows at /chat.
import { LitElement, css, customElement, html } from "ortus-kit";
import "./chat.js";
import { ready } from "./i18n.js";

await ready;

@customElement("ortus-chat-app")
export class OrtusChatApp extends LitElement {
  static override styles = css`
    :host {
      display: block;
    }
  `;

  override render() {
    return html`<ortus-chat-main></ortus-chat-main>`;
  }
}
