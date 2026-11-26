//! Trust in end-to-end rooms, on both shapes, with real Ed25519 keys:
//! cross-signing keys are this person's and signed by their master key; a
//! signature is kept only when it verifies and signs the object the server
//! has; a room's devices carry who vouches for whom, and a device the
//! person did not sign carries no self-signing signature; account data and
//! backups are one's own; a worse copy of a room key does not replace a
//! better one; only administrators set the escrow key.

mod common;

use std::sync::Arc;

use ortus_chat::matrix::canonical;
use ortus_core::auth::accounts::Role;
use ortus_core::instance::testing_auth::signed_in;
use rust_web_server::test_client::TestClient;
use serde_json::{json, Value};
use vodozemac::olm::Account;
use vodozemac::Ed25519SecretKey;

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

/// Signs JSON the Matrix way (without its signatures and unsigned) and adds
/// the signature to those it has.
fn sign(key: &Ed25519SecretKey, mut value: Value, user: &str, key_id: &str) -> Value {
    let mut plain = value.as_object().cloned().unwrap();
    plain.remove("signatures");
    plain.remove("unsigned");
    let sig = key
        .sign(canonical(&Value::Object(plain)).as_bytes())
        .to_base64();
    value["signatures"][user][key_id] = json!(sig);
    value
}

fn cross_key(user: &str, usage: &str, key: &Ed25519SecretKey) -> Value {
    let public = key.public_key().to_base64();
    json!({"user_id": user, "usage": [usage], "keys": {format!("ed25519:{public}"): public}})
}

fn device_keys(account: &Account, user: &str, device: &str) -> Value {
    let value = json!({"user_id": user, "device_id": device, "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
           "keys": {format!("curve25519:{device}"): account.curve25519_key().to_base64(), format!("ed25519:{device}"): account.ed25519_key().to_base64()}});
    let sig = account.sign(canonical(&value)).to_base64();
    let mut value = value;
    value["signatures"] = json!({ user: { format!("ed25519:{device}"): sig } });
    value
}

/// A person's cross-signing keys, uploaded: (master, self-signing, user-signing).
struct Identity {
    master: Ed25519SecretKey,
    ssk: Ed25519SecretKey,
    usk: Ed25519SecretKey,
}

impl Identity {
    fn new() -> Self {
        Identity {
            master: Ed25519SecretKey::new(),
            ssk: Ed25519SecretKey::new(),
            usk: Ed25519SecretKey::new(),
        }
    }
    fn id(key: &Ed25519SecretKey) -> String {
        format!("ed25519:{}", key.public_key().to_base64())
    }
    fn upload(&self, user: &str) -> Value {
        let m = Self::id(&self.master);
        json!({
            "master": cross_key(user, "master", &self.master),
            "selfSigning": sign(&self.master, cross_key(user, "self_signing", &self.ssk), user, &m),
            "userSigning": sign(&self.master, cross_key(user, "user_signing", &self.usk), user, &m),
        })
    }
}

#[test]
fn trust_and_backup() {
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Owner);
        let marek = signed_in(&instance, "marek@ministry.example", Role::Member);
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PATCH",
                "/chat/policy",
                Some(json!({"encryptedRooms": true}))
            )
            .0
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
        assert_eq!(
            200,
            call(
                &client,
                &marek,
                "POST",
                &format!("/chat/rooms/{room}/join"),
                None
            )
            .0
        );
        let mx = |token: &str| {
            call(&client, token, "GET", "/chat/rooms", None).1["me"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (olena_mx, marek_mx) = (mx(&olena), mx(&marek));

        // Devices: Olena's laptop and phone, Marek's laptop.
        let (laptop, phone, his) = (Account::new(), Account::new(), Account::new());
        for (token, account, user, device) in [
            (&olena, &laptop, &olena_mx, "LAPTOP"),
            (&olena, &phone, &olena_mx, "PHONE"),
            (&marek, &his, &marek_mx, "HIS"),
        ] {
            assert_eq!(
                200,
                call(
                    &client,
                    token,
                    "PUT",
                    &format!("/chat/devices/{device}"),
                    Some(json!({"deviceKeys": device_keys(account, user, device)}))
                )
                .0,
                "{name}"
            );
        }

        // Cross-signing keys: this person's, signed by their master key.
        let hers = Identity::new();
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/cross-signing",
                Some(hers.upload(&marek_mx))
            )
            .0,
            "{name}: another person's"
        );
        let mut unsigned = hers.upload(&olena_mx);
        unsigned["selfSigning"] = cross_key(&olena_mx, "self_signing", &hers.ssk);
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/cross-signing",
                Some(unsigned)
            )
            .0,
            "{name}: a self-signing key the master did not sign"
        );
        let (status, set) = call(
            &client,
            &olena,
            "PUT",
            "/chat/cross-signing",
            Some(hers.upload(&olena_mx)),
        );
        assert_eq!(200, status, "{name}: {set}");
        let his_identity = Identity::new();
        assert_eq!(
            200,
            call(
                &client,
                &marek,
                "PUT",
                "/chat/cross-signing",
                Some(his_identity.upload(&marek_mx))
            )
            .0,
            "{name}"
        );

        // Signatures: her self-signing key on her laptop is kept; on a
        // device that is not hers, or a forged one, it is not.
        let ssk_id = Identity::id(&hers.ssk);
        let on_laptop = sign(
            &hers.ssk,
            device_keys(&laptop, &olena_mx, "LAPTOP"),
            &olena_mx,
            &ssk_id,
        );
        let (status, out) = call(
            &client,
            &olena,
            "POST",
            "/chat/signatures",
            Some(json!({ &olena_mx: { "LAPTOP": on_laptop } })),
        );
        assert_eq!(
            (200, 1),
            (status, out["kept"].as_i64().unwrap_or(0)),
            "{name}: {out}"
        );
        let forged = sign(
            &Ed25519SecretKey::new(),
            device_keys(&phone, &olena_mx, "PHONE"),
            &olena_mx,
            &ssk_id,
        );
        let (_, out) = call(
            &client,
            &olena,
            "POST",
            "/chat/signatures",
            Some(json!({ &olena_mx: { "PHONE": forged } })),
        );
        assert_eq!(
            0,
            out["kept"].as_i64().unwrap(),
            "{name}: a forged signature: {out}"
        );
        let not_hers = sign(
            &hers.ssk,
            device_keys(&his, &marek_mx, "HIS"),
            &olena_mx,
            &ssk_id,
        );
        let (_, out) = call(
            &client,
            &olena,
            "POST",
            "/chat/signatures",
            Some(json!({ &marek_mx: { "HIS": not_hers } })),
        );
        assert_eq!(
            0,
            out["kept"].as_i64().unwrap(),
            "{name}: another person's device: {out}"
        );
        let other_keys = sign(
            &hers.ssk,
            device_keys(&Account::new(), &olena_mx, "PHONE"),
            &olena_mx,
            &ssk_id,
        );
        let (_, out) = call(
            &client,
            &olena,
            "POST",
            "/chat/signatures",
            Some(json!({ &olena_mx: { "PHONE": other_keys } })),
        );
        assert_eq!(
            0,
            out["kept"].as_i64().unwrap(),
            "{name}: keys that are not the device's: {out}"
        );

        // She verifies Marek: her user-signing key on his master key.
        let his_master = cross_key(&marek_mx, "master", &his_identity.master);
        let his_master_id = his_identity.master.public_key().to_base64();
        let vouched = sign(&hers.usk, his_master, &olena_mx, &Identity::id(&hers.usk));
        let (_, out) = call(
            &client,
            &olena,
            "POST",
            "/chat/signatures",
            Some(json!({ &marek_mx: { &his_master_id: vouched } })),
        );
        assert_eq!(1, out["kept"].as_i64().unwrap(), "{name}: {out}");

        // The room's devices say who vouches for whom: her laptop is signed,
        // her phone (as if the server had added it) is not; she sees her
        // signature on Marek's master key, he does not see it as his.
        let (_, devices) = call(
            &client,
            &olena,
            "GET",
            &format!("/chat/rooms/{room}/devices"),
            None,
        );
        let device = |id: &str| {
            devices["devices"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["device"] == id)
                .unwrap()
                .clone()
        };
        assert!(
            device("LAPTOP")["deviceKeys"]["signatures"][&olena_mx][&ssk_id].is_string(),
            "{name}: {devices}"
        );
        assert!(
            device("PHONE")["deviceKeys"]["signatures"][&olena_mx][&ssk_id].is_null(),
            "{name}: an unsigned device"
        );
        assert!(
            devices["crossSigning"][&olena_mx]["userSigning"].is_object(),
            "{name}: her own user-signing key"
        );
        assert!(
            devices["crossSigning"][&marek_mx]["master"]["signatures"][&olena_mx]
                [Identity::id(&hers.usk)]
            .is_string(),
            "{name}: {devices}"
        );
        assert!(
            devices["crossSigning"][&marek_mx]["userSigning"].is_null(),
            "{name}: not his user-signing key"
        );
        let (_, his_view) = call(
            &client,
            &marek,
            "GET",
            &format!("/chat/rooms/{room}/devices"),
            None,
        );
        assert!(
            his_view["crossSigning"][&olena_mx]["userSigning"].is_null(),
            "{name}"
        );

        // Account data: one's own only.
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/account-data/m.secret_storage.default_key",
                Some(json!({"key": "abc"}))
            )
            .0
        );
        assert_eq!(
            "abc",
            call(
                &client,
                &olena,
                "GET",
                "/chat/account-data/m.secret_storage.default_key",
                None
            )
            .1["key"],
            "{name}"
        );
        assert_eq!(
            404,
            call(
                &client,
                &marek,
                "GET",
                "/chat/account-data/m.secret_storage.default_key",
                None
            )
            .0,
            "{name}: not his"
        );
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/account-data/m.x",
                Some(json!("not an object"))
            )
            .0
        );

        // Backup: a version, keys, a better copy replaces a worse one only.
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "POST",
                "/chat/backup/version",
                Some(json!({"algorithm": "other", "authData": {"public_key": "x"}}))
            )
            .0
        );
        let public = "A".repeat(43);
        let (status, made) = call(
            &client,
            &olena,
            "POST",
            "/chat/backup/version",
            Some(
                json!({"algorithm": "m.megolm_backup.v1.curve25519-aes-sha2", "authData": {"public_key": public}}),
            ),
        );
        assert_eq!(200, status, "{name}: {made}");
        let version = made["version"].as_str().unwrap().to_string();
        let key = |index: i64, verified: bool, tag: &str| json!({"rooms": {&room: {"sessions": {"S1": {"first_message_index": index, "forwarded_count": 0, "is_verified": verified, "session_data": {"ciphertext": tag, "ephemeral": "e", "mac": "m"}}}}}});
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PUT",
                &format!("/chat/backup/keys?version={version}"),
                Some(key(5, false, "first"))
            )
            .0
        );
        call(
            &client,
            &olena,
            "PUT",
            &format!("/chat/backup/keys?version={version}"),
            Some(key(9, false, "worse")),
        );
        let kept = |token: &str| {
            call(
                &client,
                token,
                "GET",
                &format!("/chat/backup/keys?version={version}"),
                None,
            )
            .1
        };
        assert_eq!(
            "first",
            kept(&olena)["rooms"][&room]["sessions"]["S1"]["session_data"]["ciphertext"],
            "{name}: a worse copy"
        );
        call(
            &client,
            &olena,
            "PUT",
            &format!("/chat/backup/keys?version={version}"),
            Some(key(9, true, "verified")),
        );
        assert_eq!(
            "verified",
            kept(&olena)["rooms"][&room]["sessions"]["S1"]["session_data"]["ciphertext"],
            "{name}: a verified copy"
        );
        assert_eq!(
            403,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/backup/keys?version=999",
                Some(key(1, true, "x"))
            )
            .0,
            "{name}: not the current version"
        );
        assert!(
            kept(&marek)["rooms"].as_object().unwrap().is_empty(),
            "{name}: not his backup"
        );
        assert_eq!(
            404,
            call(&client, &marek, "GET", "/chat/backup/version", None).0
        );
        assert_eq!(
            1,
            call(&client, &olena, "GET", "/chat/backup/version", None).1["count"],
            "{name}"
        );

        // The escrow key: administrators set it, everyone reads it.
        let escrow = "B".repeat(43);
        assert_eq!(
            403,
            call(
                &client,
                &marek,
                "PATCH",
                "/chat/policy",
                Some(json!({"escrowKey": escrow}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            400,
            call(
                &client,
                &olena,
                "PATCH",
                "/chat/policy",
                Some(json!({"escrowKey": "short"}))
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
                Some(json!({"escrowKey": escrow}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            escrow,
            call(&client, &marek, "GET", "/chat/policy", None).1["escrowKey"],
            "{name}"
        );
        assert_eq!(
            true,
            call(&client, &marek, "GET", "/chat/policy", None).1["encryptedRooms"],
            "{name}: the other setting stays"
        );

        // The escrow copy: an administrator takes a person's, once they made one.
        let marek_escrow = "/chat/admin/escrow?email=marek@ministry.example";
        assert_eq!(
            404,
            call(&client, &olena, "GET", marek_escrow, None).0,
            "{name}: none yet"
        );
        assert_eq!(200, call(&client, &marek, "PUT", "/chat/account-data/ortus.escrow", Some(json!({"key": escrow, "sealed": {"ephemeral": "e", "ciphertext": "c", "mac": "m"}}))).0);
        let (status, copy) = call(&client, &olena, "GET", marek_escrow, None);
        assert_eq!(
            (200, "c"),
            (
                status,
                copy["sealed"]["ciphertext"].as_str().unwrap_or_default()
            ),
            "{name}: {copy}"
        );
        assert_eq!(
            403,
            call(
                &client,
                &marek,
                "GET",
                "/chat/admin/escrow?email=olena@ministry.example",
                None
            )
            .0,
            "{name}: administrators only"
        );
    }
}
