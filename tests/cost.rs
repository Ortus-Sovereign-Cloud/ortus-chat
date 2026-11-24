//! A page of messages costs the same few database statements however many
//! messages, senders, replies and reactions it shows (the core's
//! `Server-Timing`, ORTUS_SERVER_TIMING). It was three or more statements
//! a message.

mod common;

use std::sync::Arc;

use ortus_core::auth::accounts::Role;
use ortus_core::instance::testing_auth::signed_in;
use rust_web_server::test_client::TestClient;
use serde_json::{json, Value};

fn statements(timing: &str) -> u32 {
    let (_, rest) = timing.split_once("desc=\"").expect(timing);
    rest.split(' ').next().unwrap().parse().unwrap()
}

#[test]
fn a_page_of_messages_costs_the_same_for_five_or_sixty() {
    std::env::set_var("ORTUS_SERVER_TIMING", "1");
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let people: Vec<String> = (0..4)
            .map(|i| signed_in(&instance, &format!("p{i}@ministry.example"), Role::Member))
            .collect();
        let send = |token: &str, path: &str, body: Value| -> Value {
            let r = client
                .post(&format!("/api/v1{path}"))
                .header("Authorization", &format!("Bearer {token}"))
                .header("X-Requested-With", "ortus")
                .header("Content-Type", "application/json")
                .body_bytes(body.to_string().into_bytes())
                .send();
            assert_eq!(200, r.status(), "{name}: {path}: {}", r.body_text());
            serde_json::from_slice(r.body_bytes()).unwrap_or(Value::Null)
        };
        let members: Vec<String> = (1..4).map(|i| format!("p{i}@ministry.example")).collect();
        let room = send(
            &people[0],
            "/chat/rooms",
            json!({"kind": "channel", "name": "cost", "members": members}),
        )["id"]
            .as_str()
            .unwrap()
            .to_string();
        for p in &people[1..] {
            send(p, &format!("/chat/rooms/{room}/join"), json!({}));
        }
        let mut written = 0;
        let mut write = |n: usize| {
            for _ in 0..n {
                let who = &people[written % people.len()];
                let m = send(
                    who,
                    &format!("/chat/rooms/{room}/messages"),
                    json!({"text": format!("message {written}")}),
                );
                let id = m["id"].as_str().unwrap().to_string();
                let encoded = id.replace('$', "%24");
                send(
                    &people[(written + 1) % people.len()],
                    &format!("/chat/messages/{encoded}/reactions"),
                    json!({"key": "👍"}),
                );
                send(
                    &people[(written + 2) % people.len()],
                    &format!("/chat/rooms/{room}/messages"),
                    json!({"text": "a reply", "thread": id}),
                );
                written += 1;
            }
        };
        let read = || -> (usize, u32) {
            let r = client
                .get(&format!("/api/v1/chat/rooms/{room}/messages"))
                .header("Authorization", &format!("Bearer {}", people[0]))
                .header("X-Requested-With", "ortus")
                .send();
            assert_eq!(200, r.status(), "{name}: {}", r.body_text());
            let page: Value = serde_json::from_slice(r.body_bytes()).unwrap();
            let timing = r
                .header("Server-Timing")
                .expect("Server-Timing")
                .to_string();
            (
                page["messages"].as_array().unwrap().len(),
                statements(&timing),
            )
        };
        write(5);
        let (few, small) = read();
        write(55);
        let (many, large) = read();
        assert!(few >= 5 && many >= 60, "{name}: {few} then {many} messages");
        assert_eq!(
            small, large,
            "{name}: statements for {few} and {many} messages"
        );
        assert!(large <= 12, "{name}: {large} statements");
    }
}
