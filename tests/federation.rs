//! Federation with an independent Matrix server (Dendrite, started by
//! `ci/matrix-peer.sh`, whose settings this test reads): a person of the
//! partner joins a room Ortus shares, messages travel both ways, and the
//! policy holds (no partner, or a label that denies partners: no join).
//! Skipped without `ORTUS_TEST_MATRIX`; `ORTUS_REQUIRE_MATRIX=1` makes a
//! missing peer a failure (CI). Each run needs a fresh peer (the script
//! starts one): a peer keeps its back-off for servers it could not reach.

mod common;

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ortus_core::auth::accounts::Role;
use ortus_core::instance::testing_auth::signed_in;
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
    let mut r = match method {
        "GET" => client.get(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        _ => client.post(&url),
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

/// A plain HTTP request to the peer's client API.
fn peer(method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (u16, Value) {
    let base = std::env::var("ORTUS_TEST_MATRIX").unwrap();
    let host = base.trim_start_matches("http://").trim_end_matches('/');
    let mut stream = std::net::TcpStream::connect(host).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Chunked bodies: the JSON is between the chunk sizes.
    let json = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut out = String::new();
        let mut rest = rest;
        while let Some((size, after)) = rest.split_once("\r\n") {
            let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if n == 0 || after.len() < n {
                break;
            }
            out.push_str(&after[..n]);
            rest = after[n..].trim_start_matches("\r\n");
        }
        out
    } else {
        rest.to_string()
    };
    (status, serde_json::from_str(&json).unwrap_or(Value::Null))
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(45) {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn a_partner_joins_a_shared_room_and_messages_travel_both_ways() {
    if std::env::var("ORTUS_TEST_MATRIX").is_err() {
        assert!(
            std::env::var("ORTUS_REQUIRE_MATRIX").is_err(),
            "ORTUS_REQUIRE_MATRIX is set but no Matrix peer (ci/matrix-peer.sh)"
        );
        eprintln!("skipped: no ORTUS_TEST_MATRIX");
        return;
    }
    let peer_server = std::env::var("ORTUS_TEST_MATRIX_SERVER").unwrap();
    let (_, login) = peer(
        "POST",
        "/_matrix/client/v3/login",
        None,
        Some(
            json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": std::env::var("ORTUS_TEST_MATRIX_USER").unwrap()}, "password": std::env::var("ORTUS_TEST_MATRIX_PASSWORD").unwrap()}),
        ),
    );
    let bob_token = login["access_token"]
        .as_str()
        .expect("the peer's user signs in")
        .to_string();
    let bob = login["user_id"].as_str().unwrap().to_string();

    for (n, (name, instance, _keep)) in common::installations().into_iter().enumerate() {
        // One server name per installation: the peer keeps its view of
        // each (and its back-off while a listener is stopped).
        let server = format!("ortus{}.test", n + 1);
        std::env::set_var("ORTUS_MATRIX_SERVER_NAME", &server);
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        // The federation listener, as the web role runs it.
        let (stop_tx, stop) = tokio::sync::watch::channel(false);
        let listening = Arc::clone(&instance);
        let task = ortus_core::runtime::io()
            .spawn(async move { ortus_chat::federation::listener::run(listening, stop).await });
        std::thread::sleep(Duration::from_millis(500));

        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Owner);
        let (status, room) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(json!({"kind": "channel", "name": format!("Partners {name}")})),
        );
        assert_eq!(200, status, "{name}: {room}");
        let id = room["id"].as_str().unwrap().to_string();
        let (status, shared) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{id}/share"),
            None,
        );
        assert_eq!(200, status, "{name}: {shared}");
        let room_id =
            ortus_core::runtime::block_on(ortus_chat::store::room(instance.store.as_ref(), &id))
                .unwrap()
                .unwrap()
                .room_id;
        let join_path = format!(
            "/_matrix/client/v3/join/{}?server_name={server}",
            enc(&room_id)
        );

        // Not a partner yet: the peer cannot join.
        let (status, refused) = peer("POST", &join_path, Some(&bob_token), Some(json!({})));
        assert!(
            status >= 400,
            "{name}: joined without being a partner: {refused}"
        );

        let (status, added) = call(
            &client,
            &olena,
            "POST",
            "/admin/policy/partners",
            Some(json!({"domain": peer_server, "name": "Peer", "channels": ["chat"]})),
        );
        assert_eq!(200, status, "{name}: {added}");

        // A SECRET room is never shared with partners.
        let (_, secret) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(json!({"kind": "channel", "name": format!("Secret {name}"), "label": "secret"})),
        );
        let secret_id = secret["id"].as_str().unwrap().to_string();
        call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{secret_id}/share"),
            None,
        );
        let secret_room = ortus_core::runtime::block_on(ortus_chat::store::room(
            instance.store.as_ref(),
            &secret_id,
        ))
        .unwrap()
        .unwrap()
        .room_id;
        let (status, refused) = peer(
            "POST",
            &format!(
                "/_matrix/client/v3/join/{}?server_name={server}",
                enc(&secret_room)
            ),
            Some(&bob_token),
            Some(json!({})),
        );
        assert!(status >= 400, "{name}: joined a SECRET room: {refused}");

        // A partner: the peer's person joins, Ortus sees them.
        let (status, joined) = peer("POST", &join_path, Some(&bob_token), Some(json!({})));
        assert_eq!(200, status, "{name}: {joined}");
        wait_for("the member in Ortus", || {
            let members = ortus_core::runtime::block_on(ortus_chat::store::members(
                instance.store.as_ref(),
                &id,
            ))
            .unwrap();
            members
                .iter()
                .any(|(m, _, state, _)| *m == bob && state == "join")
        });

        // From the peer to Ortus.
        let (status, sent) = peer(
            "PUT",
            &format!(
                "/_matrix/client/v3/rooms/{}/send/m.room.message/t{}",
                enc(&room_id),
                ortus_core::program::now_ms()
            ),
            Some(&bob_token),
            Some(json!({"msgtype": "m.text", "body": format!("Hello from the partner {name}")})),
        );
        assert_eq!(200, status, "{name}: {sent}");
        wait_for("the partner's message in Ortus", || {
            let (_, messages) = call(
                &client,
                &olena,
                "GET",
                &format!("/chat/rooms/{id}/messages"),
                None,
            );
            messages
                .to_string()
                .contains(&format!("Hello from the partner {name}"))
        });

        // From Ortus to the peer.
        let (status, _) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{id}/messages"),
            Some(json!({"text": format!("Hello from Ortus {name}")})),
        );
        assert_eq!(200, status, "{name}");
        ortus_core::runtime::block_on(ortus_chat::federation::rooms::drain(&instance)).unwrap();
        wait_for("the Ortus message at the peer", || {
            let (_, messages) = peer(
                "GET",
                &format!(
                    "/_matrix/client/v3/rooms/{}/messages?dir=b&limit=20",
                    enc(&room_id)
                ),
                Some(&bob_token),
                None,
            );
            messages
                .to_string()
                .contains(&format!("Hello from Ortus {name}"))
        });

        // Relabelled SECRET: nothing more goes to the partner.
        ortus_core::runtime::block_on(instance.store.execute(
            "UPDATE chat_rooms SET label = 'secret' WHERE id = $1",
            &[id.as_str().into()],
        ))
        .unwrap();
        let (status, _) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{id}/messages"),
            Some(json!({"text": "Not for partners"})),
        );
        assert_eq!(200, status, "{name}");
        let queued = ortus_core::runtime::block_on(
            instance
                .store
                .query("SELECT COUNT(*) FROM chat_fed_outbox", &[]),
        )
        .unwrap();
        assert_eq!(
            Some(0),
            queued[0].int(0),
            "{name}: nothing queued for a SECRET room"
        );

        // Every outside call is listed.
        let calls = ortus_core::runtime::block_on(instance.store.query(
            "SELECT COUNT(*) FROM core_outbound WHERE purpose = $1",
            &["chat federation".into()],
        ))
        .unwrap();
        assert!(
            calls[0].int(0).unwrap_or(0) > 0,
            "{name}: federation calls are listed"
        );

        stop_tx.send(true).unwrap();
        let _ = ortus_core::runtime::block_on(task);
    }
}
