//! What a partner server may do in a room Ortus hosts, with a partner key
//! planted (no peer needed), on both shapes: through /send only messages
//! from joined members and their own leaving are taken; a join that skips
//! send_join, a state change (power levels) and a stranger's message are
//! refused; Ortus fields in a partner's message are dropped.

mod common;

use std::sync::Arc;

use ortus_chat::matrix::{self, SigningKey};
use ortus_core::auth::accounts::Role;
use ortus_core::instance::testing_auth::signed_in;
use ortus_core::runtime::block_on;
use rust_web_server::test_client::TestClient;
use serde_json::{json, Value};

fn call<A: rust_web_server::application::Application>(
    client: &TestClient<A>,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (i16, Value) {
    let url = format!("/api/v1{path}");
    let mut r = if method == "GET" {
        client.get(&url)
    } else {
        client.post(&url)
    };
    r = r
        .header("Authorization", &format!("Bearer {token}"))
        .header("X-Requested-With", "ortus");
    if let Some(b) = body {
        r = r
            .header("Content-Type", "application/json")
            .body_bytes(b.to_string().into_bytes());
    }
    let response = r.send();
    (
        response.status(),
        serde_json::from_slice(response.body_bytes()).unwrap_or(Value::Null),
    )
}

const EVIL: &str = "evil.test";

fn event(
    key: &SigningKey,
    room_id: &str,
    kind: &str,
    sender: &str,
    state_key: Option<&str>,
    content: Value,
) -> (String, Value) {
    let mut e = json!({"type": kind, "room_id": room_id, "sender": sender, "content": content, "origin_server_ts": ortus_core::program::now_ms(), "depth": 100, "prev_events": [], "auth_events": []});
    if let Some(k) = state_key {
        e["state_key"] = json!(k);
    }
    let id = matrix::seal_event(&mut e, EVIL, key);
    (id, e)
}

/// A transaction from the partner, signed with its planted key.
fn send(
    instance: &Arc<ortus_core::instance::Instance>,
    key: &SigningKey,
    txn: &str,
    pdus: Vec<Value>,
) {
    let me = ortus_chat::store::server_name(instance);
    let uri = format!("/_matrix/federation/v1/send/{txn}");
    let body = json!({"origin": EVIL, "origin_server_ts": ortus_core::program::now_ms(), "pdus": pdus, "edus": []});
    let signed =
        json!({"method": "PUT", "uri": uri, "origin": EVIL, "destination": me, "content": body});
    let sig = key.sign(matrix::canonical(&signed).as_bytes());
    let request = rust_web_server::request::Request {
        method: "PUT".into(),
        request_uri: uri,
        http_version: "HTTP/1.1".into(),
        headers: vec![
            rust_web_server::header::Header {
                name: "Authorization".into(),
                value: format!(
                    "X-Matrix origin=\"{EVIL}\",destination=\"{me}\",key=\"{}\",sig=\"{sig}\"",
                    key.id
                )
                .into(),
            },
            rust_web_server::header::Header {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
        ],
        body: matrix::canonical(&body).into_bytes().into(),
    };
    block_on(ortus_chat::federation::routes::answer(instance, request));
}

fn member_state(
    instance: &ortus_core::instance::Instance,
    room: &str,
    who: &str,
) -> Option<String> {
    block_on(ortus_chat::store::members(instance.store.as_ref(), room))
        .unwrap()
        .into_iter()
        .find(|(m, _, _, _)| m == who)
        .map(|(_, _, st, _)| st)
}

#[test]
fn partners_send_messages_and_leave_nothing_else() {
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let s = instance.store.as_ref();
        let now = ortus_core::program::now_ms();
        block_on(s.execute(
            "INSERT INTO core_partners (domain, name, channels, added_at) VALUES ($1, $2, $3, $4)",
            &[EVIL.into(), "Evil".into(), "chat".into(), now.into()],
        ))
        .unwrap();
        let key = SigningKey::from_seed("ed25519:k", &[7u8; 32]).unwrap();
        block_on(s.execute("INSERT INTO chat_fed_remote_keys (server, key_id, public, valid_until) VALUES ($1, $2, $3, $4)", &[EVIL.into(), key.id.as_str().into(), key.public().into(), (now + 86_400_000).into()])).unwrap();

        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Owner);
        let make = |kind: &str, n: &str| {
            let (status, room) = call(
                &client,
                &olena,
                "POST",
                "/chat/rooms",
                Some(json!({"kind": kind, "name": n})),
            );
            assert_eq!(200, status, "{name}: {room}");
            let room = block_on(ortus_chat::store::room(s, room["id"].as_str().unwrap()))
                .unwrap()
                .unwrap();
            block_on(ortus_chat::federation::rooms::share(&instance, &room)).unwrap();
            block_on(ortus_chat::store::room(s, &room.id))
                .unwrap()
                .unwrap()
        };
        let private = make("private", "inner");
        let channel = make("channel", "open");
        let mallory = format!("@mallory:{EVIL}");

        // A join through /send: refused (joins go through send_join).
        let (_, join) = event(
            &key,
            &private.room_id,
            "m.room.member",
            &mallory,
            Some(&mallory),
            json!({"membership": "join"}),
        );
        send(&instance, &key, "t1", vec![join]);
        assert_eq!(
            None,
            member_state(&instance, &private.id, &mallory),
            "{name}: joined a private room through /send"
        );

        // Mallory joined the channel properly; she then tries to take power.
        block_on(async {
            let mut tx = s.begin().await.unwrap();
            ortus_chat::store::set_member(
                tx.as_mut(),
                &channel.id,
                &mallory,
                None,
                "join",
                "member",
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        });
        let power_before = block_on(s.query(
            "SELECT event_id FROM chat_room_state WHERE room = $1 AND kind = 'm.room.power_levels'",
            &[channel.id.as_str().into()],
        ))
        .unwrap()[0]
            .text(0)
            .unwrap()
            .to_string();
        let (_, power) = event(
            &key,
            &channel.room_id,
            "m.room.power_levels",
            &mallory,
            Some(""),
            json!({"users": {mallory.clone(): 100}}),
        );
        let (_, rules) = event(
            &key,
            &channel.room_id,
            "m.room.join_rules",
            &mallory,
            Some(""),
            json!({"join_rule": "public"}),
        );
        send(&instance, &key, "t2", vec![power, rules]);
        let power_after = block_on(s.query(
            "SELECT event_id FROM chat_room_state WHERE room = $1 AND kind = 'm.room.power_levels'",
            &[channel.id.as_str().into()],
        ))
        .unwrap()[0]
            .text(0)
            .unwrap()
            .to_string();
        assert_eq!(
            power_before, power_after,
            "{name}: a partner changed the power levels"
        );

        // Her message is taken, without Ortus fields; a stranger's is not.
        let (said, message) = event(
            &key,
            &channel.room_id,
            "m.room.message",
            &mallory,
            None,
            json!({"msgtype": "m.text", "body": "hello from evil", "ortus.file": {"id": "f1", "name": "x"}, "ortus.sealed": {"ciphertext": "x"}}),
        );
        let (_, stranger) = event(
            &key,
            &channel.room_id,
            "m.room.message",
            &format!("@eve:{EVIL}"),
            None,
            json!({"msgtype": "m.text", "body": "not a member"}),
        );
        send(&instance, &key, "t3", vec![message, stranger]);
        let kept = block_on(ortus_chat::store::event(s, &said))
            .unwrap()
            .expect("the member's message");
        assert_eq!("hello from evil", kept.body, "{name}");
        assert!(
            kept.content.get("ortus.file").is_none() && kept.content.get("ortus.sealed").is_none(),
            "{name}: {}",
            kept.content
        );
        let strangers = block_on(s.query(
            "SELECT COUNT(*) FROM chat_events WHERE body = 'not a member'",
            &[],
        ))
        .unwrap();
        assert_eq!(Some(0), strangers[0].int(0), "{name}");

        // The same transaction again is taken once.
        let (again, repeat) = event(
            &key,
            &channel.room_id,
            "m.room.message",
            &mallory,
            None,
            json!({"msgtype": "m.text", "body": "once"}),
        );
        send(&instance, &key, "t4", vec![repeat.clone()]);
        send(&instance, &key, "t4", vec![repeat]);
        let once = block_on(s.query(
            "SELECT COUNT(*) FROM chat_events WHERE event_id = $1",
            &[again.as_str().into()],
        ))
        .unwrap();
        assert_eq!(Some(1), once[0].int(0), "{name}");

        // She leaves.
        let (_, leave) = event(
            &key,
            &channel.room_id,
            "m.room.member",
            &mallory,
            Some(&mallory),
            json!({"membership": "leave"}),
        );
        send(&instance, &key, "t5", vec![leave]);
        assert_ne!(
            Some("join".to_string()),
            member_state(&instance, &channel.id, &mallory),
            "{name}: she left"
        );
    }
}

#[test]
fn server_names_are_names() {
    use ortus_chat::federation::valid_server_name as ok;
    for good in [
        "matrix.org",
        "peer.test:8448",
        "1.2.3.4",
        "1.2.3.4:8448",
        "[::1]:8448",
        "a-b.example",
    ] {
        assert!(ok(good), "{good}");
    }
    for bad in [
        "evil.tld/.partner.tld",
        "evil.tld#.partner.tld",
        "evil?.x",
        "a@b.c",
        "127.1",
        "0x7f000001",
        "2130706433",
        "10.1",
        "x..y",
        ".x",
        "x.",
        "host:99999",
        "host:",
        "",
    ] {
        assert!(!ok(bad), "{bad}");
    }
}

#[test]
fn a_redacted_copy_takes_its_edits_with_it() {
    for (name, instance, _keep) in common::installations() {
        let s = instance.store.as_ref();
        let original = json!({"type": "m.room.message", "room_id": "!r:x", "sender": "@a:x", "content": {"msgtype": "m.text", "body": "secret plan"}, "depth": 1});
        let edit = json!({"type": "m.room.message", "room_id": "!r:x", "sender": "@a:x", "content": {"msgtype": "m.text", "body": "* new secret", "m.new_content": {"body": "new secret"}, "m.relates_to": {"rel_type": "m.replace", "event_id": "$orig_1"}}, "depth": 2});
        block_on(async {
            let mut tx = s.begin().await.unwrap();
            ortus_chat::federation::rooms::store_in(tx.as_mut(), "room1", "$orig_1", &original)
                .await
                .unwrap();
            ortus_chat::federation::rooms::store_in(tx.as_mut(), "room1", "$edit_1", &edit)
                .await
                .unwrap();
            ortus_chat::federation::rooms::redact_copy(tx.as_mut(), "$orig_1")
                .await
                .unwrap();
            tx.commit().await.unwrap();
        });
        let rows =
            block_on(s.query("SELECT pdu FROM chat_pdus WHERE room = 'room1'", &[])).unwrap();
        let all: String = rows
            .iter()
            .map(|r| r.text(0).unwrap_or_default().to_string())
            .collect();
        assert!(!all.contains("secret"), "{name}: {all}");
    }
}
