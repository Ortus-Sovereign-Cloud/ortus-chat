//! The browser's Olm and Megolm (web/src/olm.ts, run by Node) against
//! vodozemac, the implementation the phones use: pre-key and normal Olm
//! messages both ways, the ratchet step after an answer, a second pre-key
//! message before the answer, and Megolm both ways with a skipped index.
//! Needs Node 22.6 or later (it runs the TypeScript as it is).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use vodozemac::megolm::{
    GroupSession, InboundGroupSession, MegolmMessage, SessionConfig as GroupConfig, SessionKey,
};
use vodozemac::olm::{Account, OlmMessage, SessionConfig};
use vodozemac::Curve25519PublicKey;

fn olm_message(v: &Value) -> OlmMessage {
    let body = vodozemac::base64_decode(v["body"].as_str().unwrap()).unwrap();
    OlmMessage::from_parts(v["type"].as_u64().unwrap() as usize, &body).unwrap()
}

fn olm_json(m: &OlmMessage) -> Value {
    let (kind, body) = m.to_parts();
    json!({"type": kind, "body": vodozemac::base64_encode(body)})
}

#[test]
fn the_browsers_olm_and_megolm_talk_with_vodozemac() {
    let web = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("web");
    let mut node = Command::new("node")
        .arg("interop/olm-peer.ts")
        .current_dir(&web)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node");
    let mut to_node = node.stdin.take().unwrap();
    let mut from_node = BufReader::new(node.stdout.take().unwrap()).lines();
    let mut read = || -> Value {
        serde_json::from_str(&from_node.next().expect("a line from node").unwrap()).unwrap()
    };

    let alice = read()["alice"].clone();
    let alice_curve = Curve25519PublicKey::from_base64(alice["curve"].as_str().unwrap()).unwrap();
    let alice_otk = Curve25519PublicKey::from_base64(alice["otk"].as_str().unwrap()).unwrap();

    let mut bob = Account::new();
    bob.generate_one_time_keys(1);
    let bob_otk = *bob.one_time_keys().values().next().unwrap();
    bob.mark_keys_as_published();
    writeln!(
        to_node,
        "{}",
        json!({"bob": {"curve": bob.curve25519_key().to_base64(), "otk": bob_otk.to_base64()}})
    )
    .unwrap();

    // Alice's pre-key message starts a session; it carries her room key.
    let first = read();
    let OlmMessage::PreKey(pre) = olm_message(&first["olm"]) else {
        panic!("a pre-key message")
    };
    let created = bob
        .create_inbound_session(SessionConfig::version_1(), alice_curve, &pre)
        .expect("vodozemac takes the browser's pre-key message");
    let mut session = created.session;
    let payload: Value = serde_json::from_slice(&created.plaintext).unwrap();
    assert_eq!("m.room_key", payload["type"]);
    // Her second message, sent before any answer, is a pre-key message too.
    let second = olm_message(&first["olm2"]);
    assert!(matches!(second, OlmMessage::PreKey(_)));
    assert_eq!(
        b"second pre-key message".to_vec(),
        session.decrypt(&second).unwrap()
    );

    let key = SessionKey::from_base64(payload["content"]["session_key"].as_str().unwrap()).unwrap();
    let mut inbound = InboundGroupSession::new(&key, GroupConfig::version_1());
    let room = inbound
        .decrypt(&MegolmMessage::from_base64(first["megolm"].as_str().unwrap()).unwrap())
        .expect("vodozemac reads the browser's Megolm");
    assert_eq!(b"room hello".to_vec(), room.plaintext);
    assert_eq!(0, room.message_index);

    // Bob answers on the session (a normal message), sends his own room
    // key and a room message, and starts a session of his own to Alice.
    let mut group = GroupSession::new(GroupConfig::version_1());
    let reply = session.encrypt(json!({"type": "m.room_key", "content": {"session_key": group.session_key().to_base64()}}).to_string()).unwrap();
    assert!(matches!(reply, OlmMessage::Normal(_)));
    let megolm = group.encrypt("bob room").to_base64();
    let mut his = bob
        .create_outbound_session(SessionConfig::version_1(), alice_curve, alice_otk)
        .unwrap();
    let prekey = his.encrypt("pre from bob").unwrap();
    writeln!(
        to_node,
        "{}",
        json!({"reply": olm_json(&reply), "megolm": megolm, "prekey": olm_json(&prekey)})
    )
    .unwrap();

    let last = read();
    assert_eq!(
        "bob room", last["room"],
        "the browser reads vodozemac's Megolm"
    );
    assert_eq!(0, last["roomIndex"]);
    assert_eq!(
        "pre from bob", last["prekey"],
        "the browser takes vodozemac's pre-key message"
    );
    let after = olm_message(&last["after"]);
    assert!(
        matches!(after, OlmMessage::Normal(_)),
        "no pre-key once answered"
    );
    assert_eq!(
        b"after the ratchet step".to_vec(),
        session.decrypt(&after).unwrap()
    );
    let skipped = inbound
        .decrypt(&MegolmMessage::from_base64(last["megolm2"].as_str().unwrap()).unwrap())
        .unwrap();
    assert_eq!(
        (b"index two".to_vec(), 2),
        (skipped.plaintext, skipped.message_index)
    );
    assert_eq!(
        b"answer on their session".to_vec(),
        his.decrypt(&olm_message(&last["back"])).unwrap()
    );
    drop(to_node);
    let _ = node.wait();
}
