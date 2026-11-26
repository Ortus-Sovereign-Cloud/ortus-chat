//! Trust between the browser (web/src/e2e.ts) and a phone (this crate), on
//! a real server: the browser sets recovery up and writes; a new phone
//! cannot read that, recovers with the recovery key, and reads it from the
//! backup; then the browser and the phone verify each other by emoji (the
//! same seven on both) and both finish.

mod common;

use common::{Browser, World};
use ortus_e2e::enc;
use serde_json::{json, Value};

/// A verification of `id` in a list (the browser's or the phone's).
fn find<'a>(list: &'a [Value], id: &str) -> Option<&'a Value> {
    list.iter().find(|v| v["id"] == id)
}

#[test]
fn recovery_and_verification_between_the_browser_and_a_phone() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let (room, room_id) = w.sealed_room(&olena, &[]);
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        browser.ask(
            json!({"cmd": "send", "room": room, "roomId": room_id, "text": "Before the phone"}),
        );
        let page = w.ok(
            &olena,
            "GET",
            &format!("/chat/rooms/{}/messages", enc(&room)),
            None,
        );
        let before = page["messages"].as_array().unwrap().last().unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Recovery set up in the browser; its room key goes to the backup.
        let key = browser
            .ask(json!({"cmd": "setUpRecovery"}))
            .as_str()
            .unwrap()
            .to_string();
        assert!(key.starts_with("Es"), "{n}: {key}");

        // A new phone: nobody gave it the room key.
        let phone = w.phone(&olena, "PHONEA");
        let message = w.message(&olena, &before).to_string();
        assert!(phone.e2e.decrypt(&room, &message).is_err(), "{n}: not yet");
        assert!(!phone.e2e.recovery_state().unwrap().here, "{n}");
        assert!(
            phone.e2e.recover("EsTx not the key").is_err(),
            "{n}: a wrong key"
        );
        let restored = phone.e2e.recover(&key).expect("recovery with the key");
        assert!(restored >= 1, "{n}: room keys from the backup: {restored}");
        assert!(phone.e2e.recovery_state().unwrap().here, "{n}");
        assert_eq!(
            "Before the phone",
            phone.e2e.decrypt(&room, &message).unwrap().text,
            "{n}: read from the backup"
        );
        // Recovered, the phone vouches for the browser (signed at set-up), and itself.
        assert_eq!(
            Vec::<(String, String)>::new(),
            phone.e2e.unverified(&room).unwrap(),
            "{n}"
        );

        // Verification by emoji: the browser asks the phone.
        let me = w.ok(&olena, "GET", "/chat/rooms", None)["me"]
            .as_str()
            .unwrap()
            .to_string();
        let id = browser
            .ask(json!({"cmd": "verify", "user": me}))
            .as_str()
            .unwrap()
            .to_string();
        let mut phone_emoji = Vec::new();
        let mut browser_emoji = Vec::new();
        let mut accepted = false;
        for _ in 0..40 {
            let theirs = browser.ask(json!({"cmd": "poll"}));
            let ours: Vec<Value> = phone
                .e2e
                .verifications()
                .unwrap()
                .into_iter()
                .map(|v| json!({"id": v.id, "state": v.state, "emoji": v.emoji}))
                .collect();
            if let Some(v) = find(&ours, &id) {
                if v["state"] == "incoming" && !accepted {
                    phone.e2e.accept_verification(&id).unwrap();
                    accepted = true;
                }
                if v["state"] == "emoji" {
                    phone_emoji = v["emoji"].as_array().unwrap().clone();
                }
            }
            if let Some(v) = find(theirs.as_array().unwrap(), &id) {
                // The phone's camera could read a code; this test compares emoji.
                if v["state"] == "qr" {
                    browser.ask(json!({"cmd": "emoji", "id": id}));
                }
                if v["state"] == "emoji" {
                    browser_emoji = v["emoji"].as_array().unwrap().clone();
                }
            }
            if !phone_emoji.is_empty() && !browser_emoji.is_empty() {
                break;
            }
        }
        assert_eq!(7, phone_emoji.len(), "{n}: the phone shows emoji");
        assert_eq!(browser_emoji, phone_emoji, "{n}: the same seven on both");
        phone.e2e.confirm_verification(&id, true).unwrap();
        browser.ask(json!({"cmd": "confirm", "id": id, "same": true}));
        let mut done = (false, false);
        for _ in 0..40 {
            let theirs = browser.ask(json!({"cmd": "poll"}));
            let ours = phone.e2e.verifications().unwrap();
            done.0 = find(theirs.as_array().unwrap(), &id).is_some_and(|v| v["state"] == "done");
            done.1 = ours.iter().any(|v| v.id == id && v.state == "done");
            if done.0 && done.1 {
                break;
            }
        }
        assert_eq!((true, true), done, "{n}: both finish");
        assert_eq!(
            json!([]),
            browser.ask(json!({"cmd": "unverified", "room": room})),
            "{n}: the browser vouches for the phone"
        );
    }
}
