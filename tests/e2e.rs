//! End-to-end rooms on both shapes, with real keys from vodozemac (the
//! phones' library): devices publish signed device keys and one-time keys
//! (unsigned or someone else's are refused), a member's one-time key is
//! claimed once, Olm to-device messages wait for their device until taken
//! in, Megolm-sealed messages are kept as they are; nothing readable goes
//! in (a person's text, an app's post, an edit), search finds nothing, and
//! a hold does not keep sealed messages from retention.

mod common;

use std::sync::Arc;

use ortus_chat::matrix::canonical;
use ortus_core::auth::accounts::Role;
use ortus_core::instance::testing_auth::signed_in;
use ortus_core::runtime::block_on;
use rust_web_server::test_client::TestClient;
use serde_json::{json, Value};
use vodozemac::megolm::{GroupSession, SessionConfig as GroupConfig};
use vodozemac::olm::{Account, SessionConfig};
use vodozemac::Curve25519PublicKey;

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

/// Signs JSON the Matrix way with a vodozemac account.
fn signed(account: &Account, mut value: Value, user: &str, device: &str) -> Value {
    let sig = account.sign(canonical(&value)).to_base64();
    value["signatures"] = json!({ user: { format!("ed25519:{device}"): sig } });
    value
}

fn device_keys(account: &Account, user: &str, device: &str) -> Value {
    signed(
        account,
        json!({"user_id": user, "device_id": device, "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
               "keys": {format!("curve25519:{device}"): account.curve25519_key().to_base64(), format!("ed25519:{device}"): account.ed25519_key().to_base64()}}),
        user,
        device,
    )
}

fn one_time_keys(account: &mut Account, n: usize, user: &str, device: &str) -> Value {
    account.generate_one_time_keys(n);
    let mut out = serde_json::Map::new();
    for (id, key) in account.one_time_keys() {
        let id: String = id
            .to_base64()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        out.insert(
            format!("signed_curve25519:{id}"),
            signed(account, json!({"key": key.to_base64()}), user, device),
        );
    }
    account.mark_keys_as_published();
    Value::Object(out)
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
        let mx = |token: &str| {
            call(&client, token, "GET", "/chat/rooms", None).1["me"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (olena_mx, marek_mx, anna_mx) = (mx(&olena), mx(&marek), mx(&anna));
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

        // Plain text is refused, by people and by apps.
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "POST",
                &format!("/chat/rooms/{room}/messages"),
                Some(json!({"text": "in the clear"}))
            )
            .0,
            "{name}"
        );
        let chat = block_on(
            instance
                .services
                .get::<dyn ortus_core::interfaces::Chat>(&instance.switches),
        )
        .unwrap();
        let olena_id = block_on(ortus_core::auth::accounts::by_email(
            instance.store.as_ref(),
            "olena@ministry.example",
        ))
        .unwrap()
        .unwrap()
        .id;
        assert!(
            block_on(chat.post(&olena_id, &room, "a record was filed")).is_err(),
            "{name}: an app posts into a sealed room"
        );

        // Devices: signed by themselves, for their own person and id.
        let mut laptop = Account::new();
        let mut phone = Account::new();
        let stranger = Account::new();
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/devices/LAPTOP",
                Some(json!({"deviceKeys": device_keys(&laptop, &marek_mx, "LAPTOP")}))
            )
            .0,
            "{name}: another person's id"
        );
        let mut forged = device_keys(&laptop, &olena_mx, "LAPTOP");
        forged["signatures"] = device_keys(&stranger, &olena_mx, "LAPTOP")["signatures"].clone();
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/devices/LAPTOP",
                Some(json!({"deviceKeys": forged}))
            )
            .0,
            "{name}: signed by another key"
        );
        let otks = one_time_keys(&mut laptop, 2, &olena_mx, "LAPTOP");
        let (status, up) = call(
            &client,
            &olena,
            "PUT",
            "/chat/devices/LAPTOP",
            Some(
                json!({"deviceKeys": device_keys(&laptop, &olena_mx, "LAPTOP"), "oneTimeKeys": otks}),
            ),
        );
        assert_eq!(200, status, "{name}: {up}");
        assert_eq!(2, up["oneTimeKeyCount"], "{name}");
        assert_eq!(
            409,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/devices/LAPTOP",
                Some(json!({"deviceKeys": device_keys(&stranger, &olena_mx, "LAPTOP")}))
            )
            .0,
            "{name}: a device keeps its keys"
        );
        let unsigned = json!({"signed_curve25519:XX": {"key": phone.curve25519_key().to_base64()}});
        assert_eq!(400, call(&client, &marek, "PUT", "/chat/devices/PHONE", Some(json!({"deviceKeys": device_keys(&phone, &marek_mx, "PHONE"), "oneTimeKeys": unsigned}))).0, "{name}: an unsigned one-time key");
        let phone_otks = one_time_keys(&mut phone, 3, &marek_mx, "PHONE");
        assert_eq!(200, call(&client, &marek, "PUT", "/chat/devices/PHONE", Some(json!({"deviceKeys": device_keys(&phone, &marek_mx, "PHONE"), "oneTimeKeys": phone_otks}))).0, "{name}");
        let desk = Account::new();
        assert_eq!(
            200,
            call(
                &client,
                &anna,
                "PUT",
                "/chat/devices/DESK",
                Some(json!({"deviceKeys": device_keys(&desk, &anna_mx, "DESK")}))
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
            "{name}: not a member"
        );

        // One-time keys are given out once each; non-members get none.
        let claim = json!({"devices": [{"user": marek_mx, "device": "PHONE"}, {"user": anna_mx, "device": "DESK"}]});
        let (_, first) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/claim"),
            Some(claim.clone()),
        );
        let (_, second) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/claim"),
            Some(claim),
        );
        let key_of = |v: &Value| {
            v["oneTimeKeys"][&marek_mx]["PHONE"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()["key"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_ne!(key_of(&first), key_of(&second), "{name}");
        assert!(first["oneTimeKeys"].get(&anna_mx).is_none(), "{name}");

        // An Olm message to Marek's phone waits there until taken in.
        let otk = Curve25519PublicKey::from_base64(&key_of(&first)).unwrap();
        let mut olm = laptop
            .create_outbound_session(SessionConfig::version_1(), phone.curve25519_key(), otk)
            .unwrap();
        let (kind, body) = olm.encrypt("{\"type\":\"m.room_key\"}").unwrap().to_parts();
        let content = json!({"algorithm": "m.olm.v1.curve25519-aes-sha2", "sender_key": laptop.curve25519_key().to_base64(), "ciphertext": {phone.curve25519_key().to_base64(): {"type": kind, "body": vodozemac::base64_encode(body)}}});
        assert_eq!(400, call(&client, &olena, "POST", &format!("/chat/rooms/{room}/to-device"), Some(json!({"fromDevice": "LAPTOP", "messages": [{"user": marek_mx, "device": "PHONE", "content": {"algorithm": "plain", "text": "hi"}}]}))).0, "{name}");
        assert_eq!(400, call(&client, &olena, "POST", &format!("/chat/rooms/{room}/to-device"), Some(json!({"fromDevice": "NOTMINE", "messages": [{"user": marek_mx, "device": "PHONE", "content": content}]}))).0, "{name}");
        let (_, sent) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/to-device"),
            Some(
                json!({"fromDevice": "LAPTOP", "messages": [{"user": marek_mx, "device": "PHONE", "content": content}, {"user": anna_mx, "device": "DESK", "content": content}]}),
            ),
        );
        assert_eq!(1, sent["sent"], "{name}: only to members");
        let (_, inbox) = call(&client, &marek, "GET", "/chat/devices/PHONE/inbox", None);
        let waiting = inbox["messages"].as_array().unwrap();
        assert_eq!(1, waiting.len(), "{name}");
        assert_eq!(olena_mx, waiting[0]["sender"], "{name}");
        assert_eq!("LAPTOP", waiting[0]["senderDevice"], "{name}");
        assert_eq!(
            0,
            call(&client, &olena, "GET", "/chat/devices/PHONE/inbox", None).1["messages"]
                .as_array()
                .unwrap()
                .len(),
            "{name}: one's own devices only"
        );
        let id = waiting[0]["id"].clone();
        call(
            &client,
            &marek,
            "POST",
            "/chat/devices/PHONE/inbox/done",
            Some(json!({"ids": [id]})),
        );
        assert_eq!(
            0,
            call(&client, &marek, "GET", "/chat/devices/PHONE/inbox", None).1["messages"]
                .as_array()
                .unwrap()
                .len(),
            "{name}"
        );

        // Megolm-sealed messages: kept as they are, with no text.
        let mut group = GroupSession::new(GroupConfig::version_1());
        let sealed = json!({"algorithm": "m.megolm.v1.aes-sha2", "sender_key": laptop.curve25519_key().to_base64(), "ciphertext": group.encrypt("{}").to_base64(), "session_id": group.session_id(), "device_id": "LAPTOP"});
        let (status, kept) = call(
            &client,
            &olena,
            "POST",
            &format!("/chat/rooms/{room}/sealed"),
            Some(sealed.clone()),
        );
        assert_eq!(200, status, "{name}: {kept}");
        assert_eq!("", kept["text"], "{name}");
        assert_eq!(sealed["ciphertext"], kept["sealed"]["ciphertext"], "{name}");
        let mut not_mine = sealed.clone();
        not_mine["device_id"] = json!("PHONE");
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "POST",
                &format!("/chat/rooms/{room}/sealed"),
                Some(not_mine)
            )
            .0,
            "{name}: another person's device"
        );
        let event = kept["id"].as_str().unwrap();
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PATCH",
                &format!("/chat/messages/{}", event.replace('$', "%24")),
                Some(json!({"text": "now readable"}))
            )
            .0,
            "{name}"
        );
        let (_, found) = call(&client, &olena, "GET", "/search?q=megolm", None);
        assert!(
            !found.to_string().contains(event),
            "{name}: sealed rooms are not searched"
        );

        // A hold does not keep sealed messages.
        block_on(instance.store.execute(
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
        block_on(async {
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
