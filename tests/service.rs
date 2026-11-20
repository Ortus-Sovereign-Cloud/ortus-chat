//! The Chat interface other apps use, on both shapes: a room as a member
//! sees it (none for someone outside it), and notices from apps (only
//! "ortus." kinds, only from members).

mod common;

use std::sync::Arc;

use ortus_core::auth::accounts::Role;
use ortus_core::instance::testing_auth::signed_in;
use ortus_core::runtime::block_on;
use rust_web_server::test_client::TestClient;
use serde_json::{json, Value};

#[test]
fn other_apps_see_rooms_and_leave_notices() {
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Owner);
        signed_in(&instance, "anna@ministry.example", Role::Member);
        let r = client
            .post("/api/v1/chat/rooms")
            .header("Authorization", &format!("Bearer {olena}"))
            .header("X-Requested-With", "ortus")
            .header("Content-Type", "application/json")
            .body_bytes(
                json!({"kind": "private", "name": "flood-response"})
                    .to_string()
                    .into_bytes(),
            )
            .send();
        let room: Value = serde_json::from_slice(r.body_bytes()).unwrap();
        let room = room["id"].as_str().unwrap().to_string();
        let id_of = |e: &str| {
            block_on(ortus_core::auth::accounts::by_email(
                instance.store.as_ref(),
                e,
            ))
            .unwrap()
            .unwrap()
            .id
        };
        let (olena_id, anna_id) = (
            id_of("olena@ministry.example"),
            id_of("anna@ministry.example"),
        );
        let chat = block_on(
            instance
                .services
                .get::<dyn ortus_core::interfaces::Chat>(&instance.switches),
        )
        .unwrap();

        let seen = block_on(chat.room(&olena_id, &room))
            .unwrap()
            .expect("a member sees the room");
        assert_eq!(
            ("flood-response", "private", false),
            (seen.name.as_str(), seen.kind.as_str(), seen.encrypted),
            "{name}"
        );
        assert_eq!(vec![olena_id.clone()], seen.members, "{name}");
        assert!(
            block_on(chat.room(&anna_id, &room)).unwrap().is_none(),
            "{name}: not hers"
        );

        assert!(
            block_on(chat.notice(&olena_id, &room, "ortus.call", "c1")).is_ok(),
            "{name}"
        );
        assert!(
            block_on(chat.notice(&olena_id, &room, "m.room.message", "x")).is_err(),
            "{name}: not a message"
        );
        assert!(
            block_on(chat.notice(&anna_id, &room, "ortus.call", "c1")).is_err(),
            "{name}: not a member"
        );
        let kept = block_on(instance.store.query(
            "SELECT COUNT(*) FROM chat_events WHERE room = $1 AND kind = 'ortus.call'",
            &[room.as_str().into()],
        ))
        .unwrap();
        assert_eq!(Some(1), kept[0].int(0), "{name}");
    }
}
