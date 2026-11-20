//! End-to-end rooms on both shapes: devices say their public keys, a room
//! key is given wrapped for each member's device, messages are kept
//! sealed; nothing readable goes in (not a person's text, not an app's
//! post, not an edit), search finds nothing, and a hold does not keep
//! sealed messages from retention.

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
        "PUT" => client.put(&url),
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

/// A P-256 public key in JWK form (the server checks its shape only).
fn jwk(n: u8) -> Value {
    let x: String = std::iter::repeat_n(char::from(b'A' + n), 43).collect();
    let y: String = std::iter::repeat_n(char::from(b'a' + n), 43).collect();
    json!({"kty": "EC", "crv": "P-256", "x": x, "y": y})
}

fn wrapped(n: u8) -> Value {
    json!({"algorithm": "ortus.p256-aes-gcm.v1", "epk": jwk(n), "iv": "AAAAAAAAAAAAAAAA", "ciphertext": "c2VhbGVkIHJvb20ga2V5IGJ5dGVzIGdvIGhlcmUhIQ=="})
}

#[test]
fn sealed_rooms_keep_nothing_readable() {
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Owner);
        let marek = signed_in(&instance, "marek@ministry.example", Role::Member);
        let anna = signed_in(&instance, "anna@ministry.example", Role::Member);
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
        let (status, room) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(
                json!({"kind": "private", "name": "sealed", "encrypted": true, "members": ["marek@ministry.example"]}),
            ),
        );
        assert_eq!(200, status, "{name}: {room}");
        let room = room["id"].as_str().unwrap().to_string();
        let (_, me) = call(&client, &olena, "GET", "/chat/rooms", None);
        let olena_mx = me["me"].as_str().unwrap().to_string();
        let (_, info) = call(&client, &olena, "GET", &format!("/chat/rooms/{room}"), None);
        let marek_mx = info["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] != olena_mx)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        // Plain text is refused, by people and by apps.
        let (status, _) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/messages"),
            Some(json!({"text": "in the clear"})),
        );
        assert_eq!(400, status, "{name}");
        let chat = ortus_core::runtime::block_on(
            instance
                .services
                .get::<dyn ortus_core::interfaces::Chat>(&instance.switches),
        )
        .unwrap();
        let olena_id = ortus_core::runtime::block_on(ortus_core::auth::accounts::by_email(
            instance.store.as_ref(),
            "olena@ministry.example",
        ))
        .unwrap()
        .unwrap()
        .id;
        assert!(
            ortus_core::runtime::block_on(chat.post(&olena_id, &room, "a record was filed"))
                .is_err(),
            "{name}: an app posts into a sealed room"
        );

        // Devices: public keys only.
        let mut private = jwk(0);
        private["d"] = json!("secret");
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/devices/laptop",
                Some(json!({"publicKey": private}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/devices/laptop",
                Some(json!({"publicKey": jwk(0)}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/devices/laptop",
                Some(json!({"publicKey": jwk(0)}))
            )
            .0,
            "{name}: saying it again"
        );
        assert_eq!(
            409,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/devices/laptop",
                Some(json!({"publicKey": jwk(1)}))
            )
            .0,
            "{name}: a device keeps its key"
        );
        assert_eq!(
            200,
            call(
                &client,
                &marek,
                "PUT",
                "/chat/devices/phone",
                Some(json!({"publicKey": jwk(2)}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &anna,
                "PUT",
                "/chat/devices/desk",
                Some(json!({"publicKey": jwk(3)}))
            )
            .0,
            "{name}"
        );

        let (status, devices) = call(
            &client,
            &olena,
            "GET",
            &format!("/chat/rooms/{room}/devices"),
            None,
        );
        assert_eq!(200, status, "{name}");
        assert_eq!(
            2,
            devices["devices"].as_array().unwrap().len(),
            "{name}: members' devices only: {devices}"
        );
        assert_eq!(0, devices["latest"], "{name}");
        // Not a member: nothing.
        assert_eq!(
            404,
            call(
                &client,
                &anna,
                "GET",
                &format!("/chat/rooms/{room}/devices"),
                None
            )
            .0,
            "{name}"
        );

        // The room key, wrapped for each device; a version too far ahead
        // is refused, a non-member is skipped.
        let (status, _) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/keys"),
            Some(
                json!({"fromDevice": "laptop", "keys": [{"user": olena_mx, "device": "laptop", "version": 3, "wrapped": wrapped(4)}]}),
            ),
        );
        assert_eq!(400, status, "{name}");
        let (status, given) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/keys"),
            Some(json!({"fromDevice": "laptop", "keys": [
                {"user": olena_mx, "device": "laptop", "version": 1, "wrapped": wrapped(4)},
                {"user": marek_mx, "device": "phone", "version": 1, "wrapped": wrapped(5)},
                {"user": "@anna:elsewhere", "device": "desk", "version": 1, "wrapped": wrapped(6)},
            ]})),
        );
        assert_eq!(200, status, "{name}: {given}");
        assert_eq!(2, given["given"], "{name}");
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
        let (_, his) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/keys/phone"),
            None,
        );
        assert_eq!(1, his["keys"].as_array().unwrap().len(), "{name}");
        assert_eq!("laptop", his["keys"][0]["fromDevice"], "{name}");
        let (_, theirs) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/keys/laptop"),
            None,
        );
        assert_eq!(
            0,
            theirs["keys"].as_array().unwrap().len(),
            "{name}: only one's own devices' keys"
        );

        // Sealed messages: kept as they are, with no text.
        let (status, sealed) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/sealed"),
            Some(
                json!({"version": 1, "device": "laptop", "iv": "AAAAAAAAAAAAAAAA", "ciphertext": "Y2lwaGVydGV4dCBvbmx5"}),
            ),
        );
        assert_eq!(200, status, "{name}: {sealed}");
        assert_eq!("", sealed["text"], "{name}");
        assert_eq!(
            "Y2lwaGVydGV4dCBvbmx5", sealed["sealed"]["ciphertext"],
            "{name}"
        );
        let (status, _) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/sealed"),
            Some(json!({"version": 1, "device": "laptop", "iv": "not base64!", "ciphertext": "x"})),
        );
        assert_eq!(400, status, "{name}");
        let id = sealed["id"].as_str().unwrap();
        let (status, _) = call(
            &client,
            &olena,
            "PATCH",
            &format!("/chat/messages/{}", id.replace('$', "%24")),
            Some(json!({"text": "now readable"})),
        );
        assert_eq!(400, status, "{name}: a sealed message is not edited");
        let (_, listed) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/messages"),
            None,
        );
        assert_eq!(1, listed["messages"].as_array().unwrap().len(), "{name}");
        let (_, found) = call(
            &client,
            &olena,
            "GET",
            "/search?q=Y2lwaGVydGV4dCBvbmx5",
            None,
        );
        assert!(
            !found.to_string().contains(id),
            "{name}: sealed rooms are not searched"
        );

        // A hold does not keep sealed messages.
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
        ortus_core::runtime::block_on(async {
            let mut tx = instance.store.begin().await.unwrap();
            for app in instance.apps.iter() {
                app.purge(tx.as_mut(), &rules).await.unwrap();
            }
            tx.commit().await.unwrap();
        });
        let (_, left) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/messages"),
            None,
        );
        assert_eq!(
            0,
            left["messages"].as_array().unwrap().len(),
            "{name}: {left}"
        );
    }
}
