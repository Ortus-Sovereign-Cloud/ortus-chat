// The browser's trust code (src/trust.ts, as it is) for the phones' crate
// tests: `make` prints what a browser writes (a recovery key with its
// description and a secret in secret storage, cross-signing keys, a room
// key sealed to a backup key, an escrow copy); `unseal <seed> <sealed>`
// opens what the crate sealed. Run by Node 23.5 or later (it strips types).
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith("./") && specifier.endsWith(".js") && context.parentURL?.includes("/src/"))
      return nextResolve(specifier.replace(/\.js$/, ".ts"), context);
    return nextResolve(specifier, context);
  },
});

const t = await import("../src/trust.ts");
const { b64, unb64 } = await import("../src/olm.ts");

const [command, ...args] = process.argv.slice(2);
if (command === "make") {
  const recovery = t.newRecoveryKey();
  const user = "@olena:ortus.test";
  const cross = await t.newCrossSigning();
  const backup = await t.x25519FromSeed(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const escrow = await t.x25519FromSeed(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const session = { roomId: "!r:ortus.test", sessionId: "S1", senderKey: "sender", sessionKey: "AQID", firstIndex: 0, signingKey: "signing" };
  const recoveryText = t.encodeRecoveryKey(recovery);
  const out = {
    recoveryText,
    recoveryBytes: b64(recovery),
    roundTrip: b64(t.decodeRecoveryKey(recoveryText) ?? new Uint8Array()),
    mistyped: t.decodeRecoveryKey(recoveryText.slice(0, -1) + (recoveryText.endsWith("a") ? "b" : "a")),
    description: await t.keyDescription(recovery),
    masterSeed: b64(cross.master.seed),
    secret: await t.encryptSecret(recovery, "m.cross_signing.master", b64(cross.master.seed)),
    crossSigning: await t.crossSigningUpload(user, cross),
    masterPublic: b64(cross.master.publicKey),
    backupSeed: b64(backup.seed),
    backupPublic: b64(backup.publicKey),
    roomKey: await t.backupRoomKey(backup.publicKey, session, true),
    escrowSeed: b64(escrow.seed),
    escrowed: await t.seal(escrow.publicKey, recoveryText),
  };
  // The browser opens its own seals and secrets too.
  if ((await t.unseal(escrow, out.escrowed)) !== recoveryText) throw new Error("escrow round trip");
  if ((await t.decryptSecret(recovery, "m.cross_signing.master", out.secret)) !== out.masterSeed) throw new Error("secret round trip");
  if (!(await t.keyMatches(recovery, out.description as { iv: string; mac: string }))) throw new Error("key check");
  console.log(JSON.stringify(out));
} else if (command === "unseal") {
  const key = await t.x25519FromSeed(unb64(args[0] ?? ""));
  console.log(JSON.stringify({ plaintext: await t.unseal(key, JSON.parse(args[1] ?? "{}")) }));
} else {
  throw new Error(`unknown command ${command}`);
}
