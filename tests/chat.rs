//! Chat on both shapes: channels, private channels and direct messages;
//! messages, threads, reactions, edits and deletions; unread counts and
//! read markers; search for members only; the Chat service; the policy
//! for end-to-end rooms; retention and forgetting a person.

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

#[test]
fn channels_threads_reactions_and_unread() {
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Owner);
        let marek = signed_in(&instance, "marek@ministry.example", Role::Member);
        let anna = signed_in(&instance, "anna@ministry.example", Role::Member);
        let sam = signed_in(&instance, "sam@ministry.example", Role::Member);
        let id_of = |e: &str| {
            ortus_core::runtime::block_on(ortus_core::auth::accounts::by_email(
                instance.store.as_ref(),
                e,
            ))
            .unwrap()
            .unwrap()
            .id
        };

        // A channel Olena makes; Marek is invited, Anna joins from the directory.
        let (status, ch) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(
                json!({"kind": "channel", "name": "#flood-response", "topic": "River levels and shelters", "members": ["marek@ministry.example"]}),
            ),
        );
        assert_eq!(200, status, "{name}: {ch}");
        let room = ch["id"].as_str().unwrap().to_string();
        assert_eq!(json!("flood-response"), ch["name"], "{name}");
        assert!(ch["roomId"].as_str().unwrap().starts_with('!'), "{name}");
        let (_, rooms) = call(&client, &marek, "GET", "/chat/rooms", None);
        assert_eq!(
            json!("invite"),
            rooms["rooms"][0]["state"],
            "{name}: {rooms}"
        );
        assert_eq!(
            403,
            call(
                &client,
                &marek,
                "POST",
                &format!("/chat/rooms/{room}/messages"),
                Some(json!({"text": "hi"}))
            )
            .0,
            "{name}"
        );
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
        let (_, dir) = call(&client, &anna, "GET", "/chat/directory", None);
        assert_eq!(1, dir["rooms"].as_array().unwrap().len(), "{name}");
        assert_eq!(
            200,
            call(
                &client,
                &anna,
                "POST",
                &format!("/chat/rooms/{room}/join"),
                None
            )
            .0,
            "{name}"
        );

        // A message, a thread under it, a mention, a reaction.
        let (status, alert) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/messages"),
            Some(json!({"text": "Gauge at Bridge 3 is at 4.1 m and rising."})),
        );
        assert_eq!(200, status, "{name}: {alert}");
        let root = alert["id"].as_str().unwrap().to_string();
        call(
            &client,
            &marek,
            "POST",
            &format!("/chat/rooms/{room}/messages"),
            Some(json!({"text": "Close R-12?", "thread": root})),
        );
        let (_, reply) = call(
            &client,
            &anna,
            "POST",
            &format!("/chat/rooms/{room}/messages"),
            Some(
                json!({"text": "Agreed, @Marek please do it.", "thread": root, "mentions": ["marek@ministry.example"]}),
            ),
        );
        assert!(
            reply["mentions"][0].as_str().unwrap().starts_with('@'),
            "{name}: {reply}"
        );
        let (_, top) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/messages"),
            None,
        );
        assert_eq!(
            1,
            top["messages"].as_array().unwrap().len(),
            "{name}: {top}"
        );
        assert_eq!(json!(2), top["messages"][0]["replies"], "{name}");
        let (_, thread) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/messages?thread={root}"),
            None,
        );
        assert_eq!(3, thread["messages"].as_array().unwrap().len(), "{name}");
        let (_, r) = call(
            &client,
            &marek,
            "POST",
            &format!("/chat/messages/{root}/reactions"),
            Some(json!({"key": "👍"})),
        );
        assert_eq!(json!("👍"), r["reactions"][0]["key"], "{name}: {r}");
        let (_, r) = call(
            &client,
            &marek,
            "POST",
            &format!("/chat/messages/{root}/reactions"),
            Some(json!({"key": "👍"})),
        );
        assert_eq!(
            0,
            r["reactions"].as_array().unwrap().len(),
            "{name}: taken back"
        );
        // A thread hangs off a message of the same room only.
        let (_, other) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(json!({"kind": "private", "name": "leads"})),
        );
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "POST",
                &format!("/chat/rooms/{}/messages", other["id"].as_str().unwrap()),
                Some(json!({"text": "x", "thread": root}))
            )
            .0,
            "{name}"
        );

        // Unread: Anna's reply came after Marek wrote (writing marks read).
        let (_, mine) = call(&client, &marek, "GET", "/chat/rooms", None);
        let entry = mine["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == json!(room))
            .unwrap()
            .clone();
        assert_eq!(json!(1), entry["unread"], "{name}: {entry}");
        call(
            &client,
            &marek,
            "POST",
            &format!("/chat/rooms/{room}/read"),
            Some(json!({"seq": entry["lastSeq"]})),
        );
        let (_, mine) = call(&client, &marek, "GET", "/chat/rooms", None);
        assert_eq!(
            json!(0),
            mine["rooms"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == json!(room))
                .unwrap()["unread"],
            "{name}"
        );

        // Edits and deletions are the sender's own.
        assert_eq!(
            403,
            call(
                &client,
                &marek,
                "PATCH",
                &format!("/chat/messages/{root}"),
                Some(json!({"text": "edited"}))
            )
            .0,
            "{name}"
        );
        let (_, edited) = call(
            &client,
            &olena,
            "PATCH",
            &format!("/chat/messages/{root}"),
            Some(json!({"text": "Gauge at Bridge 3 is at 4.2 m and rising."})),
        );
        assert!(edited["editedAt"].is_i64(), "{name}");

        // A private channel and a direct message stay among their people.
        assert_eq!(
            404,
            call(
                &client,
                &sam,
                "GET",
                &format!("/chat/rooms/{}", other["id"].as_str().unwrap()),
                None
            )
            .0,
            "{name}"
        );
        let (_, dm) = call(
            &client,
            &marek,
            "POST",
            "/chat/rooms",
            Some(json!({"kind": "direct", "members": ["anna@ministry.example"]})),
        );
        let (_, again) = call(
            &client,
            &anna,
            "POST",
            "/chat/rooms",
            Some(json!({"kind": "direct", "members": ["marek@ministry.example"]})),
        );
        assert_eq!(dm["id"], again["id"], "{name}: one direct room per pair");
        call(
            &client,
            &marek,
            "POST",
            &format!("/chat/rooms/{}/messages", dm["id"].as_str().unwrap()),
            Some(json!({"text": "Can you take the night shift?"})),
        );
        assert_eq!(
            404,
            call(
                &client,
                &sam,
                "GET",
                &format!("/chat/rooms/{}/messages", dm["id"].as_str().unwrap()),
                None
            )
            .0,
            "{name}"
        );

        // Search: members find messages; outsiders of a private room do not.
        let find = |who: &str, q: &str| {
            ortus_core::runtime::block_on(ortus_core::search::search(
                &instance,
                &id_of(who),
                &ortus_core::search::Query::parse(q),
                10,
            ))
            .unwrap()
            .len()
        };
        assert_eq!(1, find("marek@ministry.example", "night shift"), "{name}");
        assert_eq!(0, find("sam@ministry.example", "night shift"), "{name}");
        assert_eq!(1, find("anna@ministry.example", "Bridge"), "{name}");

        // Deleted: empty, gone from search.
        let (_, dmmsgs) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{}/messages", dm["id"].as_str().unwrap()),
            None,
        );
        let night = dmmsgs["messages"][0]["id"].as_str().unwrap().to_string();
        assert_eq!(
            200,
            call(
                &client,
                &marek,
                "DELETE",
                &format!("/chat/messages/{night}"),
                None
            )
            .0,
            "{name}"
        );
        assert_eq!(0, find("marek@ministry.example", "night shift"), "{name}");

        // The Chat service: another app posts as a person to a channel by name.
        let chat = ortus_core::runtime::block_on(
            instance
                .services
                .get::<dyn ortus_core::interfaces::Chat>(&instance.switches),
        )
        .unwrap();
        let posted = ortus_core::runtime::block_on(chat.post(
            &id_of("olena@ministry.example"),
            "#flood-response",
            "Flood response plan 2026 is filed as record 0114-033.",
        ))
        .unwrap();
        assert!(posted.path.starts_with("/chat?room="), "{name}");
        assert!(
            ortus_core::runtime::block_on(chat.post(
                &id_of("sam@ministry.example"),
                "#flood-response",
                "x"
            ))
            .is_err(),
            "{name}: not a member"
        );

        // End-to-end rooms only when an administrator allows them.
        let (status, _) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(json!({"kind": "private", "name": "secret", "encrypted": true})),
        );
        assert_eq!(403, status, "{name}");
        assert_eq!(
            403,
            call(
                &client,
                &marek,
                "PATCH",
                "/chat/policy",
                Some(json!({"encryptedRooms": true}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PATCH",
                "/chat/policy",
                Some(json!({"encryptedRooms": true}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "POST",
                "/chat/rooms",
                Some(json!({"kind": "private", "name": "secret", "encrypted": true}))
            )
            .0,
            "{name}"
        );

        // Anna leaves the organisation: her messages are emptied, her
        // memberships gone; the thread stays.
        let anna_id = id_of("anna@ministry.example");
        ortus_core::runtime::block_on(async {
            let mut tx = instance.store.begin().await.unwrap();
            for app in instance.apps.iter() {
                app.forget_user(
                    tx.as_mut(),
                    &anna_id,
                    &ortus_core::retention::Rules::default(),
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        });
        let (_, thread) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/messages?thread={root}"),
            None,
        );
        let annas = thread["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["user"] == json!(anna_id))
            .unwrap()
            .clone();
        assert_eq!(
            (json!(""), json!(true)),
            (annas["text"].clone(), annas["deleted"].clone()),
            "{name}"
        );

        // Retention: with chat kept one day, older messages go unless on hold.
        ortus_core::runtime::block_on(instance.store.execute(
            "UPDATE chat_events SET origin_ts = origin_ts - 3 * 86400000",
            &[],
        ))
        .unwrap();
        let rules = ortus_core::retention::Rules {
            days: [("chat".to_string(), Some(1))].into(),
            held_channels: [format!("chat:room:{room}")].into(),
            now: ortus_core::program::now_ms(),
            ..Default::default()
        };
        let gone = ortus_core::runtime::block_on(async {
            let mut tx = instance.store.begin().await.unwrap();
            let mut n = 0;
            for app in instance.apps.iter() {
                n += app.purge(tx.as_mut(), &rules).await.unwrap();
            }
            tx.commit().await.unwrap();
            n
        });
        assert!(gone >= 1, "{name}");
        let (_, kept) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/messages"),
            None,
        );
        assert_eq!(
            2,
            kept["messages"].as_array().unwrap().len(),
            "{name}: the held channel keeps its messages"
        );
        // A phone's outbox sends a message twice (its first answer was
        // lost): with the same client id it is one message.
        let once = json!({"text": "Sandbags at the north gate.", "client_id": "phone-outbox-1"});
        let (_, first) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/messages"),
            Some(once.clone()),
        );
        let (status, again) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/messages"),
            Some(once),
        );
        assert_eq!(200, status, "{name}: {again}");
        assert_eq!(first["id"], again["id"], "{name}: one message");
        assert_eq!(true, again["again"], "{name}");
    }
}
