//! Incoming hooks and notifications on both shapes: a channel's owner
//! makes a hook (a member may not); an outside system posts through its
//! address with no session; an alert notifies everyone in the channel and
//! opens the channel; a mention notifies the person mentioned; a removed
//! hook takes nothing more; end-to-end rooms take no hooks.

mod common;

use std::sync::Arc;

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
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
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

/// An outside system's post: no session, no browser header.
fn hook_post<A: rust_web_server::application::Application>(
    client: &TestClient<A>,
    url: &str,
    body: Value,
) -> i16 {
    let path = &url[url.find("/api/v1/").unwrap()..];
    client
        .post(path)
        .header("Content-Type", "application/json")
        .body_bytes(body.to_string().into_bytes())
        .send()
        .status()
}

#[test]
fn hooks_post_alerts_and_mentions_notify() {
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Member);
        let marek = signed_in(&instance, "marek@ministry.example", Role::Member);
        let (_, room) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(
                json!({"kind": "channel", "name": "flood-response", "members": ["marek@ministry.example"]}),
            ),
        );
        let room = room["id"].as_str().unwrap().to_string();
        assert_eq!(
            200,
            call(
                &client,
                &marek,
                "POST",
                &format!("/chat/rooms/{room}/join"),
                None
            )
            .0,
            "{name}"
        );

        // Only the owner (or an administrator) makes hooks.
        assert_eq!(
            403,
            call(
                &client,
                &marek,
                "POST",
                &format!("/chat/rooms/{room}/hooks"),
                Some(json!({"name": "Gauge"}))
            )
            .0,
            "{name}"
        );
        let (status, hook) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/hooks"),
            Some(json!({"name": "River Authority alerts"})),
        );
        assert_eq!(200, status, "{name}: {hook}");
        let url = hook["url"].as_str().unwrap().to_string();
        let (_, hooks) = call(
            &client,
            &olena,
            "GET",
            &format!("/chat/rooms/{room}/hooks"),
            None,
        );
        assert!(
            !hooks.to_string().contains(url.rsplit('/').next().unwrap()),
            "{name}: the address is not shown again"
        );

        // An alert through it: a message from the hook, and everyone hears.
        assert_eq!(
            200,
            hook_post(
                &client,
                &url,
                json!({"text": "Gauge at the bridge passed 4.2 m", "alert": true})
            ),
            "{name}"
        );
        assert_eq!(
            404,
            hook_post(&client, "/api/v1/chat/hooks/nonsense", json!({"text": "x"})),
            "{name}"
        );
        let (_, messages) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/messages"),
            None,
        );
        let alert = messages["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["text"] == "Gauge at the bridge passed 4.2 m")
            .cloned()
            .expect("the alert in the channel");
        assert_eq!(
            "River Authority alerts",
            messages["people"][alert["sender"].as_str().unwrap()]["name"],
            "{name}"
        );
        for who in [&olena, &marek] {
            let (_, notes) = call(&client, who, "GET", "/notifications", None);
            let n = notes["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["kind"] == "alert")
                .cloned()
                .expect("an alert notification");
            assert_eq!("Gauge at the bridge passed 4.2 m", n["title"], "{name}");
            assert!(
                n["path"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("/chat?room={room}")),
                "{name}: it opens the channel"
            );
        }

        // A mention notifies the one mentioned (not the writer).
        call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/messages"),
            Some(
                json!({"text": "@Marek can you check the school?", "mentions": ["marek@ministry.example"]}),
            ),
        );
        let (_, his) = call(&client, &marek, "GET", "/notifications", None);
        let mention = his["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["kind"] == "mention")
            .cloned()
            .expect("a mention");
        assert_eq!("mention", mention["key"], "{name}");
        assert_eq!("#flood-response", mention["args"]["where"], "{name}");
        let (_, hers) = call(&client, &olena, "GET", "/notifications", None);
        assert!(
            !hers["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["kind"] == "mention"),
            "{name}"
        );

        // Removed: nothing more through it.
        let id = hook["id"].as_str().unwrap();
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "DELETE",
                &format!("/chat/rooms/{room}/hooks/{id}"),
                None
            )
            .0,
            "{name}"
        );
        assert_eq!(
            404,
            hook_post(&client, &url, json!({"text": "after"})),
            "{name}"
        );

        // End-to-end rooms take none.
        call(
            &client,
            &olena,
            "PATCH",
            "/chat/policy",
            Some(json!({"encryptedRooms": true})),
        );
        let olena_owner = signed_in(&instance, "owner@ministry.example", Role::Owner);
        call(
            &client,
            &olena_owner,
            "PATCH",
            "/chat/policy",
            Some(json!({"encryptedRooms": true})),
        );
        let (_, sealed) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(json!({"kind": "private", "name": "sealed", "encrypted": true})),
        );
        if let Some(sid) = sealed["id"].as_str() {
            assert_eq!(
                400,
                call(
                    &client,
                    &olena,
                    "POST",
                    &format!("/chat/rooms/{sid}/hooks"),
                    Some(json!({"name": "x"}))
                )
                .0,
                "{name}"
            );
        }
    }
}
