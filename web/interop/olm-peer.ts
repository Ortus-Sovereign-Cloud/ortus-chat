// The browser's Olm and Megolm (src/olm.ts) as one side of a conversation
// with vodozemac (tests/olm_interop.rs drives it over stdin and stdout,
// one JSON object per line). Run by Node, which strips the types.
import { createInterface } from "node:readline";
import * as olm from "../src/olm.ts";

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
async function next(): Promise<Record<string, any>> {
  const r = await lines.next();
  if (r.done) throw new Error("stdin closed");
  return JSON.parse(r.value);
}
function say(v: unknown): void {
  process.stdout.write(JSON.stringify(v) + "\n");
}

const identity = await olm.x25519();
const otk = await olm.x25519();
say({ alice: { curve: olm.b64(identity.publicKey), otk: olm.b64(otk.publicKey) } });

const { bob } = await next();
const session = await olm.outboundSession(identity, olm.unb64(bob.curve), olm.unb64(bob.otk));
const group = await olm.megolmOutbound();
const key = await olm.sessionKey(group);
const toBob = await olm.olmEncrypt(session, JSON.stringify({ type: "m.room_key", content: { session_key: key, session_id: olm.sessionId(group.signing.publicKey) } }));
const second = await olm.olmEncrypt(session, "second pre-key message");
say({ olm: toBob, olm2: second, megolm: await olm.megolmEncrypt(group, "room hello") });

const answer = await next();
const fromBob = JSON.parse(await olm.olmDecrypt(session, answer.reply));
const inbound = await olm.megolmInbound(fromBob.content.session_key);
const room = await olm.megolmDecrypt(inbound, answer.megolm);
const theirs = await olm.inboundSession(identity, otk, answer.prekey.body);
// After their answer: our next message is on a new ratchet key.
const after = await olm.olmEncrypt(session, "after the ratchet step");
await olm.megolmEncrypt(group, "index one, never sent");
say({ room: room.plaintext, roomIndex: room.index, prekey: theirs.plaintext, after, megolm2: await olm.megolmEncrypt(group, "index two"), back: await olm.olmEncrypt(theirs.session, "answer on their session") });
process.exit(0);
