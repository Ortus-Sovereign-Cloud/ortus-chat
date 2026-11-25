//! ortus-e2e against the chat server (tests/common): two phones in an
//! end-to-end room read each other, threads included; a phone and the
//! browser's own implementation (web/src/e2e.ts under Node) read each other
//! both ways; room sessions change after 100 messages and when someone
//! leaves or comes; and what the wire format says a device refuses is
//! refused (a room key for someone else, a device whose keys changed, a
//! replayed index, a message moved to another thread or another sender).

mod common;

use common::{Browser, Person, Phone, World};
use ortus_e2e::{canonical, enc, Error, MEGOLM, OLM};
use serde_json::{json, Value};
use vodozemac::megolm::{GroupSession, SessionConfig as GroupConfig};
use vodozemac::olm::{Account, SessionConfig};
use vodozemac::Curve25519PublicKey;

fn read(w: &World, p: &Phone, room: &str, id: &str) -> Result<(String, Option<String>), Error> {
    let m = w.message(&p.person, id);
    p.e2e
        .decrypt(room, &m.to_string())
        .map(|o| (o.text, o.thread))
}

fn session_of(w: &World, who: &Person, id: &str) -> String {
    w.message(who, id)["sealed"]["session_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn inbox_len(w: &World, who: &Person, device: &str) -> usize {
    w.ok(who, "GET", &format!("/chat/devices/{device}/inbox"), None)["messages"]
        .as_array()
        .unwrap()
        .len()
}

#[test]
fn two_phones_read_each_other_threads_included() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let marek = w.person("marek@ministry.example", false);
        let (room, _) = w.sealed_room(&olena, &[(&marek, "marek@ministry.example")]);
        let a = w.phone(&olena, "PHONEA");
        let b = w.phone(&marek, "PHONEB");

        let first = a.e2e.send(&room, "Hello from the phone", None).unwrap();
        let stored = w.message(&olena, &first);
        assert_eq!("", stored["text"], "{n}: the server keeps no text");
        assert_eq!(MEGOLM, stored["sealed"]["algorithm"], "{n}");
        let got = b.e2e.inbox().unwrap();
        assert_eq!(1, got.room_keys, "{n}: the room key came");
        assert_eq!(
            ("Hello from the phone".to_string(), None),
            read(&w, &b, &room, &first).unwrap(),
            "{n}"
        );
        assert_eq!(
            ("Hello from the phone".to_string(), None),
            read(&w, &a, &room, &first).unwrap(),
            "{n}: one's own"
        );
        assert_eq!(
            0,
            inbox_len(&w, &marek, "PHONEB"),
            "{n}: taken in, gone from the server"
        );

        // A reply in the thread, both ways.
        let reply = b.e2e.send(&room, "In the thread", Some(&first)).unwrap();
        assert_eq!(first, w.message(&olena, &reply)["thread"], "{n}");
        assert_eq!(
            ("In the thread".to_string(), Some(first.clone())),
            read(&w, &a, &room, &reply).unwrap(),
            "{n}"
        );
        let again = a.e2e.send(&room, "Thanks", Some(&first)).unwrap();
        assert_eq!(
            ("Thanks".to_string(), Some(first.clone())),
            read(&w, &b, &room, &again).unwrap(),
            "{n}"
        );
        assert_eq!(
            session_of(&w, &olena, &first),
            session_of(&w, &olena, &again),
            "{n}: the session is kept"
        );

        // After 100 messages, a new session (which the other phone reads).
        let mut sent = vec![again];
        for i in 3..=100 {
            sent.push(a.e2e.send(&room, &format!("message {i}"), None).unwrap());
        }
        let last = sent.last().unwrap();
        assert_eq!(
            session_of(&w, &olena, &first),
            session_of(&w, &olena, last),
            "{n}: 100 in one session"
        );
        let next = a.e2e.send(&room, "the 101st", None).unwrap();
        assert_ne!(
            session_of(&w, &olena, &first),
            session_of(&w, &olena, &next),
            "{n}: a new one after 100"
        );
        assert_eq!("the 101st", read(&w, &b, &room, &next).unwrap().0, "{n}");
        // An index from the middle of the first session (never read before).
        assert_eq!(
            "message 57",
            read(&w, &b, &room, &sent[55]).unwrap().0,
            "{n}"
        );

        // Someone leaves: a new session, which they are not given.
        w.ok(
            &marek,
            "POST",
            &format!("/chat/rooms/{}/leave", enc(&room)),
            None,
        );
        let after = a.e2e.send(&room, "after marek left", None).unwrap();
        assert_ne!(
            session_of(&w, &olena, &next),
            session_of(&w, &olena, &after),
            "{n}: a new one when someone left"
        );
        assert_eq!(
            0,
            inbox_len(&w, &marek, "PHONEB"),
            "{n}: nothing for one who left"
        );
        assert_eq!(
            "after marek left",
            read(&w, &a, &room, &after).unwrap().0,
            "{n}"
        );

        // Signing out: the phone forgets its keys, the server its device.
        let listed = |w: &World| {
            w.ok(
                &olena,
                "GET",
                &format!("/chat/rooms/{}/devices", enc(&room)),
                None,
            )
            .to_string()
        };
        assert!(listed(&w).contains("PHONEA"), "{n}");
        a.e2e.forget().unwrap();
        assert_eq!(
            Err(Error::Forgotten),
            a.e2e.send(&room, "after signing out", None).map(|_| ()),
            "{n}"
        );
        assert!(
            !listed(&w).contains("PHONEA"),
            "{n}: the server dropped the device"
        );
    }
}

#[test]
fn a_phone_and_the_browser_read_each_other() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let marek = w.person("marek@ministry.example", false);
        let (room, room_id) = w.sealed_room(&olena, &[(&marek, "marek@ministry.example")]);
        let phone = w.phone(&olena, "PHONEA");
        let mut browser = Browser::start(&w, &marek);
        browser.ask(json!({"cmd": "ready"}));

        // The phone shares its session (index 0, with Ortus's room id) over
        // Olm to the browser's one-time key; the browser opens it.
        let from_phone = phone.e2e.send(&room, "From the phone", None).unwrap();
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        let open = |b: &mut Browser, id: &str| {
            b.ask(json!({"cmd": "open", "room": room, "roomId": room_id, "message": w.message(&marek, id)}))
        };
        assert_eq!(
            "From the phone",
            open(&mut browser, &from_phone),
            "{n}: the browser reads the phone"
        );

        // The browser's session (to the phone's one-time key) and message.
        browser.ask(json!({"cmd": "send", "room": room, "roomId": room_id, "text": "From the browser", "thread": from_phone}));
        let page = w.ok(
            &olena,
            "GET",
            &format!(
                "/chat/rooms/{}/messages?thread={}",
                enc(&room),
                enc(&from_phone)
            ),
            None,
        );
        let from_browser = page["messages"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|m| m["user"].is_string() && m["sender"] == marek.me.as_str())
            .map(|m| m["id"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("{n}: the browser's reply: {page}"));
        assert_eq!(
            ("From the browser".to_string(), Some(from_phone.clone())),
            read(&w, &phone, &room, &from_browser).unwrap(),
            "{n}: the phone reads the browser, in the thread"
        );

        // The phone answers in the thread; then the browser's second
        // message (on its Olm session, now answered) is read too.
        let answer = phone
            .e2e
            .send(&room, "Answer in the thread", Some(&from_phone))
            .unwrap();
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        assert_eq!("Answer in the thread", open(&mut browser, &answer), "{n}");
        browser.ask(json!({"cmd": "send", "room": room, "roomId": room_id, "text": "Second from the browser"}));
        let page = w.ok(
            &olena,
            "GET",
            &format!("/chat/rooms/{}/messages", enc(&room)),
            None,
        );
        let second = page["messages"]
            .as_array()
            .unwrap()
            .iter()
            .rfind(|m| m["sender"] == marek.me.as_str() && m["thread"].is_null())
            .map(|m| m["id"].as_str().unwrap().to_string())
            .unwrap();
        assert_eq!(
            ("Second from the browser".to_string(), None),
            read(&w, &phone, &room, &second).unwrap(),
            "{n}"
        );

        // What the browser sealed in a thread does not open out of it.
        let mut moved = w.message(&olena, &from_browser);
        moved["thread"] = Value::Null;
        assert!(
            phone.e2e.decrypt(&room, &moved.to_string()).is_err(),
            "{n}: moved out of its thread"
        );
        drop(browser);
    }
}

/// A device of `who` that the test drives itself (a server or a person
/// that lies), with vodozemac.
struct Forged {
    account: Account,
    device: String,
}

fn signed(account: &Account, mut value: Value, user: &str, device: &str) -> Value {
    let sig = account.sign(canonical(&value)).to_base64();
    value["signatures"] = json!({ user: { format!("ed25519:{device}"): sig } });
    value
}

fn device_keys(account: &Account, user: &str, device: &str) -> Value {
    signed(
        account,
        json!({"user_id": user, "device_id": device, "algorithms": [OLM, MEGOLM],
               "keys": {format!("curve25519:{device}"): account.curve25519_key().to_base64(),
                        format!("ed25519:{device}"): account.ed25519_key().to_base64()}}),
        user,
        device,
    )
}

fn forged(w: &World, who: &Person, device: &str) -> Forged {
    let account = Account::new();
    w.ok(
        who,
        "PUT",
        &format!("/chat/devices/{device}"),
        Some(json!({"deviceKeys": device_keys(&account, &who.me, device)})),
    );
    Forged {
        account,
        device: device.into(),
    }
}

/// Sends `to`'s device a room key over Olm from the forged device, with
/// the recipient it names; answers the Megolm session.
#[allow(clippy::too_many_arguments)]
fn forge_room_key(
    w: &World,
    who: &Person,
    f: &mut Forged,
    room: &str,
    room_id: &str,
    to: &Person,
    to_device: &str,
    recipient: &str,
) -> GroupSession {
    let devices = w.ok(
        who,
        "GET",
        &format!("/chat/rooms/{}/devices", enc(room)),
        None,
    );
    let theirs = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["user"] == to.me.as_str() && d["device"] == to_device)
        .unwrap()["deviceKeys"]["keys"]
        .clone();
    let curve = theirs[format!("curve25519:{to_device}")]
        .as_str()
        .unwrap()
        .to_string();
    let ed = theirs[format!("ed25519:{to_device}")]
        .as_str()
        .unwrap()
        .to_string();
    let claimed = w.ok(
        who,
        "POST",
        &format!("/chat/rooms/{}/claim", enc(room)),
        Some(json!({"devices": [{"user": to.me, "device": to_device}]})),
    );
    let one = claimed["oneTimeKeys"][&to.me][to_device]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();
    let mut olm = f
        .account
        .create_outbound_session(
            SessionConfig::version_1(),
            Curve25519PublicKey::from_base64(&curve).unwrap(),
            Curve25519PublicKey::from_base64(&one).unwrap(),
        )
        .unwrap();
    let group = GroupSession::new(GroupConfig::version_1());
    let payload = json!({"type": "m.room_key",
        "content": {"algorithm": MEGOLM, "room_id": room_id, "session_id": group.session_id(),
                    "session_key": group.session_key().to_base64(), "org.ortus.room": room},
        "sender": who.me, "sender_device": f.device, "keys": {"ed25519": f.account.ed25519_key().to_base64()},
        "recipient": recipient, "recipient_keys": {"ed25519": ed}});
    let (kind, body) = olm.encrypt(payload.to_string()).unwrap().to_parts();
    let r = w.ok(
        who,
        "POST",
        &format!("/chat/rooms/{}/to-device", enc(room)),
        Some(json!({"fromDevice": f.device,
        "messages": [{"user": to.me, "device": to_device, "content": {"algorithm": OLM,
            "sender_key": f.account.curve25519_key().to_base64(),
            "ciphertext": {curve: {"type": kind, "body": vodozemac::base64_encode(body)}}}}]})),
    );
    assert_eq!(json!([0]), r["stored"]);
    group
}

fn forge_message(
    w: &World,
    who: &Person,
    f: &Forged,
    room: &str,
    room_id: &str,
    group: &mut GroupSession,
    text: &str,
) -> String {
    let plaintext = json!({"type": "m.room.message", "content": {"msgtype": "m.text", "body": text}, "room_id": room_id});
    let m = w.ok(who, "POST", &format!("/chat/rooms/{}/sealed", enc(room)), Some(json!({"algorithm": MEGOLM,
        "sender_key": f.account.curve25519_key().to_base64(), "ciphertext": group.encrypt(plaintext.to_string()).to_base64(),
        "session_id": group.session_id(), "device_id": f.device})));
    m["id"].as_str().unwrap().to_string()
}

fn refused(r: Result<(String, Option<String>), Error>) -> bool {
    matches!(r, Err(Error::Refused(_)))
}

#[test]
fn what_the_wire_format_refuses_is_refused() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let marek = w.person("marek@ministry.example", false);
        let anna = w.person("anna@ministry.example", false);
        let (room, room_id) = w.sealed_room(&olena, &[(&marek, "marek@ministry.example")]);
        let a = w.phone(&olena, "PHONEA");
        let b = w.phone(&marek, "PHONEB");
        let c = w.phone(&anna, "PHONEC");

        // A room key meant for someone else is not taken; the same key
        // meant for this device is (so the refusal is the recipient's).
        let mut evil = forged(&w, &marek, "EVIL");
        let mut group = forge_room_key(
            &w, &marek, &mut evil, &room, &room_id, &olena, "PHONEA", &anna.me,
        );
        let id = forge_message(
            &w,
            &marek,
            &evil,
            &room,
            &room_id,
            &mut group,
            "for someone else",
        );
        assert!(
            refused(read(&w, &a, &room, &id)),
            "{n}: a room key for another recipient"
        );
        let mut good = forged(&w, &marek, "GOOD");
        let mut group = forge_room_key(
            &w, &marek, &mut good, &room, &room_id, &olena, "PHONEA", &olena.me,
        );
        let id = forge_message(&w, &marek, &good, &room, &room_id, &mut group, "for olena");
        assert_eq!(
            "for olena",
            read(&w, &a, &room, &id).unwrap().0,
            "{n}: the control"
        );

        // A replayed index: the server stores the same ciphertext again.
        let sent = a.e2e.send(&room, "Pay 10 euros", None).unwrap();
        assert_eq!("Pay 10 euros", read(&w, &b, &room, &sent).unwrap().0, "{n}");
        let original = w.message(&olena, &sent)["sealed"].clone();
        let replay = w.ok(
            &olena,
            "POST",
            &format!("/chat/rooms/{}/sealed", enc(&room)),
            Some(json!({"algorithm": MEGOLM,
            "sender_key": original["sender_key"], "ciphertext": original["ciphertext"],
            "session_id": original["session_id"], "device_id": original["device_id"]})),
        );
        assert!(
            refused(read(&w, &b, &room, replay["id"].as_str().unwrap())),
            "{n}: a replayed index"
        );
        assert_eq!(
            "Pay 10 euros",
            read(&w, &b, &room, &sent).unwrap().0,
            "{n}: the first stays readable"
        );

        // A message moved to a thread, or given to another sender.
        let mut m = w.message(&marek, &sent);
        m["thread"] = json!(id);
        assert!(
            matches!(b.e2e.decrypt(&room, &m.to_string()), Err(Error::Refused(_))),
            "{n}: moved into a thread"
        );
        let mut m = w.message(&marek, &sent);
        m["sender"] = json!(marek.me);
        assert!(
            matches!(b.e2e.decrypt(&room, &m.to_string()), Err(Error::Refused(_))),
            "{n}: another sender"
        );
        // A message of another room.
        let (other, _) = w.sealed_room(&olena, &[(&marek, "marek@ministry.example")]);
        assert!(
            b.e2e
                .decrypt(&other, &w.message(&marek, &sent).to_string())
                .is_err(),
            "{n}: another room"
        );

        // A device whose keys change (a server that lies: the database is
        // changed under it) is no longer given room keys, and what it
        // seals is not opened.
        assert_eq!(0, inbox_len(&w, &marek, "PHONEB"), "{n}");
        let mut new_keys = Forged {
            account: Account::new(),
            device: "PHONEB".into(),
        };
        let keys = device_keys(&new_keys.account, &marek.me, "PHONEB");
        assert_eq!(
            1,
            w.sql(
                "UPDATE chat_devices SET curve = $1, keys = $2 WHERE device = $3",
                &[
                    new_keys.account.curve25519_key().to_base64().as_str(),
                    keys.to_string().as_str(),
                    "PHONEB"
                ]
            ),
            "{n}"
        );
        // Someone new comes: a new session, given to them, not to the changed device.
        w.ok(
            &olena,
            "PATCH",
            &format!("/chat/rooms/{}", enc(&room)),
            Some(json!({"invite": ["anna@ministry.example"]})),
        );
        w.ok(
            &anna,
            "POST",
            &format!("/chat/rooms/{}/join", enc(&room)),
            None,
        );
        let after = a.e2e.send(&room, "After the change", None).unwrap();
        assert_ne!(
            session_of(&w, &olena, &sent),
            session_of(&w, &olena, &after),
            "{n}: a new session"
        );
        assert_eq!(
            "After the change",
            read(&w, &c, &room, &after).unwrap().0,
            "{n}: the newcomer reads it"
        );
        assert_eq!(
            0,
            inbox_len(&w, &marek, "PHONEB"),
            "{n}: no room key for the changed device"
        );
        let mut group = forge_room_key(
            &w,
            &marek,
            &mut new_keys,
            &room,
            &room_id,
            &olena,
            "PHONEA",
            &olena.me,
        );
        let id = forge_message(
            &w,
            &marek,
            &new_keys,
            &room,
            &room_id,
            &mut group,
            "from the changed device",
        );
        // The key came and opens the message: what refuses it is the check
        // of the sender's device (its keys are not the ones first seen).
        let why = format!("{:?}", read(&w, &a, &room, &id));
        assert!(
            why.contains("not a device of the sender"),
            "{n}: a device whose keys changed: {why}"
        );
    }
}
