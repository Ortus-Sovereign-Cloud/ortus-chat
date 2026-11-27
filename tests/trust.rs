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

/// The organisation's escrow key, signed by an administrator's master key.
fn escrow_object(user: &str, public: &str, master: &Ed25519SecretKey) -> Value {
    sign(
        master,
        json!({"user_id": user, "usage": ["ortus.escrow"], "public_key": public}),
        user,
        &Identity::id(master),
    )
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

        // The escrow key: administrators set it, signed by their current
        // master key; everyone reads it, with the signer's master key.
        let escrow = "B".repeat(43);
        let signed = escrow_object(&olena_mx, &escrow, &hers.master);
        let patch =
            |token: &str, body: Value| call(&client, token, "PATCH", "/chat/policy", Some(body));
        assert_eq!(403, patch(&marek, json!({"escrow": signed})).0, "{name}");
        assert_eq!(
            400,
            patch(&olena, json!({"escrowKey": escrow})).0,
            "{name}: a new key unsigned"
        );
        let mut short = escrow_object(&olena_mx, "short", &hers.master);
        short["public_key"] = json!("short");
        assert_eq!(400, patch(&olena, json!({"escrow": short})).0, "{name}");
        assert_eq!(
            400,
            patch(
                &olena,
                json!({"escrow": escrow_object(&olena_mx, &escrow, &his_identity.master)})
            )
            .0,
            "{name}: not her master key"
        );
        assert_eq!(
            400,
            patch(
                &olena,
                json!({"escrow": escrow_object(&marek_mx, &escrow, &hers.master)})
            )
            .0,
            "{name}: signed as someone else"
        );
        let mut extra = escrow_object(&olena_mx, &escrow, &hers.master);
        extra["note"] = json!("more");
        assert_eq!(
            400,
            patch(&olena, json!({"escrow": extra})).0,
            "{name}: a field more"
        );
        let mut forged = signed.clone();
        forged["public_key"] = json!("C".repeat(43));
        assert_eq!(
            400,
            patch(&olena, json!({"escrow": forged})).0,
            "{name}: the key changed after signing"
        );
        let (status, out) = patch(&olena, json!({"escrow": signed}));
        assert_eq!(200, status, "{name}: {out}");
        let (_, policy) = call(&client, &marek, "GET", "/chat/policy", None);
        assert_eq!(escrow, policy["escrowKey"], "{name}");
        assert_eq!(json!(false), policy["escrowUnsigned"], "{name}");
        let served = &policy["escrow"];
        assert_eq!(escrow, served["public_key"], "{name}: {policy}");
        assert_eq!(
            signed["signatures"], served["signatures"],
            "{name}: as signed"
        );
        assert_eq!(
            cross_key(&olena_mx, "master", &hers.master)["keys"],
            served["signerMaster"]["keys"],
            "{name}: her master key, to check it with"
        );
        assert_eq!(json!(["master"]), served["signerMaster"]["usage"], "{name}");
        assert_eq!(olena_mx, served["signerMaster"]["user_id"], "{name}");
        assert_eq!(
            true,
            call(&client, &marek, "GET", "/chat/policy", None).1["encryptedRooms"],
            "{name}: the other setting stays"
        );

        // Verification messages: to one's own other devices, or to someone
        // one shares a room with; carried with their type.
        let anna = signed_in(&instance, "anna@ministry.example", Role::Member);
        let anna_mx = mx(&anna);
        let annas = Account::new();
        assert_eq!(
            200,
            call(
                &client,
                &anna,
                "PUT",
                "/chat/devices/ANNA",
                Some(json!({"deviceKeys": device_keys(&annas, &anna_mx, "ANNA")}))
            )
            .0
        );
        let start = json!({"transaction_id": "T1", "method": "m.sas.v1", "from_device": "LAPTOP"});
        let send = |token: &str, user: &str, device: &str, kind: &str| {
            call(
                &client,
                token,
                "POST",
                "/chat/verification",
                Some(
                    json!({"user": user, "device": device, "fromDevice": "LAPTOP", "type": kind, "content": start}),
                ),
            )
        };
        let (status, out) = send(&olena, &olena_mx, "*", "m.key.verification.request");
        assert_eq!(
            (200, 1),
            (status, out["sent"].as_i64().unwrap_or(0)),
            "{name}: her other device, not this one: {out}"
        );
        let inbox = call(&client, &olena, "GET", "/chat/devices/PHONE/inbox", None).1;
        let got = inbox["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["type"] == "m.key.verification.request")
            .cloned();
        assert_eq!(
            Some("T1"),
            got.as_ref()
                .and_then(|m| m["content"]["transaction_id"].as_str()),
            "{name}: {inbox}"
        );
        assert_eq!(
            200,
            send(&olena, &marek_mx, "HIS", "m.key.verification.start").0,
            "{name}: they share a room"
        );
        assert_eq!(
            403,
            send(&olena, &anna_mx, "ANNA", "m.key.verification.start").0,
            "{name}: no shared room"
        );
        assert_eq!(
            400,
            send(&olena, &marek_mx, "HIS", "m.room.encrypted").0,
            "{name}: verification types only"
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

        // Marek vouched for her: the master key served to him with the escrow carries his signature.
        let vouched = sign(
            &his_identity.usk,
            cross_key(&olena_mx, "master", &hers.master),
            &marek_mx,
            &Identity::id(&his_identity.usk),
        );
        let master_id = hers.master.public_key().to_base64();
        let (status, out) = call(
            &client,
            &marek,
            "POST",
            "/chat/signatures",
            Some(json!({ &olena_mx: { &master_id: vouched } })),
        );
        assert_eq!(
            (200, 1),
            (status, out["kept"].as_i64().unwrap_or(0)),
            "{name}: {out}"
        );
        let (_, policy) = call(&client, &marek, "GET", "/chat/policy", None);
        assert!(
            policy["escrow"]["signerMaster"]["signatures"][&marek_mx]
                [Identity::id(&his_identity.usk)]
            .is_string(),
            "{name}: {policy}"
        );
        // The same signed key again needs nothing; removing it takes it away.
        assert_eq!(200, patch(&olena, json!({"escrow": signed})).0, "{name}");

        // A new master key: the escrow its old one signed is unsigned now,
        // and a new escrow signed by the old one is refused.
        let next = Identity::new();
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PUT",
                "/chat/cross-signing",
                Some(next.upload(&olena_mx))
            )
            .0,
            "{name}"
        );
        let (_, policy) = call(&client, &marek, "GET", "/chat/policy", None);
        assert!(policy["escrow"].is_null(), "{name}: {policy}");
        assert_eq!(json!(true), policy["escrowUnsigned"], "{name}");
        assert_eq!(escrow, policy["escrowKey"], "{name}: still shown");
        let other = "D".repeat(43);
        assert_eq!(
            400,
            patch(
                &olena,
                json!({"escrow": escrow_object(&olena_mx, &other, &hers.master)})
            )
            .0,
            "{name}: signed by a master key that is not hers any more"
        );
        assert_eq!(
            200,
            patch(
                &olena,
                json!({"escrow": escrow_object(&olena_mx, &other, &next.master)})
            )
            .0,
            "{name}"
        );
        assert_eq!(
            json!(false),
            call(&client, &marek, "GET", "/chat/policy", None).1["escrowUnsigned"],
            "{name}"
        );

        // A key kept before escrows were signed: served as unsigned.
        sql(
            &instance,
            "DELETE FROM chat_settings WHERE name IN ('escrow', 'escrow_signer')",
            &[],
        );
        let (_, policy) = call(&client, &marek, "GET", "/chat/policy", None);
        assert!(policy["escrow"].is_null(), "{name}: {policy}");
        assert_eq!(json!(true), policy["escrowUnsigned"], "{name}");
        assert_eq!(other, policy["escrowKey"], "{name}");
        // Removing: null, or the old empty key.
        assert_eq!(200, patch(&olena, json!({"escrowKey": ""})).0, "{name}");
        let (_, policy) = call(&client, &marek, "GET", "/chat/policy", None);
        assert!(
            policy["escrowKey"].is_null() && policy["escrow"].is_null(),
            "{name}: {policy}"
        );
        assert_eq!(json!(false), policy["escrowUnsigned"], "{name}");
        assert_eq!(
            200,
            patch(
                &olena,
                json!({"escrow": escrow_object(&olena_mx, &other, &next.master)})
            )
            .0,
            "{name}"
        );
        assert_eq!(200, patch(&olena, json!({"escrow": null})).0, "{name}");
        assert!(
            call(&client, &marek, "GET", "/chat/policy", None).1["escrowKey"].is_null(),
            "{name}"
        );
    }
}

/// Runs SQL straight on the store: rows of a query as [text, int], or none.
fn sql(instance: &ortus_core::instance::Instance, query: &str, params: &[&str]) -> Vec<Value> {
    let params: Vec<ortus_core::storage::Value> = params.iter().map(|p| (*p).into()).collect();
    let store = instance.store.as_ref();
    if !query.starts_with("SELECT") {
        ortus_core::runtime::block_on(store.execute(query, &params)).unwrap();
        return Vec::new();
    }
    ortus_core::runtime::block_on(store.query(query, &params))
        .unwrap()
        .iter()
        .map(|r| json!([r.text(0), r.int(0)]))
        .collect()
}

fn user_id(instance: &ortus_core::instance::Instance, email: &str) -> String {
    ortus_core::runtime::block_on(ortus_core::people::id_by_email(
        instance.store.as_ref(),
        email,
    ))
    .unwrap()
    .unwrap()
}

/// What a person uploads is kept as signed and checked, malformed
/// signatures break nobody's view, a forgotten device takes its
/// signatures with it, what one person keeps is capped, and the escrow
/// needs a recent, strong sign-in.
#[test]
fn trust_limits_and_step_up() {
    for (name, instance, _keep) in common::installations() {
        for app in instance.apps.clone() {
            app.provide(&instance, &instance.services);
        }
        let client = TestClient::new(ortus_core::app(Arc::clone(&instance)));
        let olena = signed_in(&instance, "olena@ministry.example", Role::Owner);
        let marek = signed_in(&instance, "marek@ministry.example", Role::Member);
        let (olena_id, marek_id) = (
            user_id(&instance, "olena@ministry.example"),
            user_id(&instance, "marek@ministry.example"),
        );
        call(
            &client,
            &olena,
            "PATCH",
            "/chat/policy",
            Some(json!({"encryptedRooms": true})),
        );
        let (_, room) = call(
            &client,
            &olena,
            "POST",
            "/chat/rooms",
            Some(
                json!({"kind": "private", "name": "sealed", "encrypted": true, "members": ["marek@ministry.example"]}),
            ),
        );
        let room = room["id"].as_str().unwrap().to_string();
        call(
            &client,
            &marek,
            "POST",
            &format!("/chat/rooms/{room}/join"),
            None,
        );
        let mx = |token: &str| {
            call(&client, token, "GET", "/chat/rooms", None).1["me"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (olena_mx, marek_mx) = (mx(&olena), mx(&marek));
        let (laptop, his) = (Account::new(), Account::new());
        for (token, account, user, device) in [
            (&olena, &laptop, &olena_mx, "LAPTOP"),
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

        // Cross-signing keys are kept as signed: anything else in what was
        // signed is refused, signatures that are not the master key's go.
        let hers = Identity::new();
        let mut extra = hers.upload(&olena_mx);
        extra["master"]["note"] = json!("more");
        assert_eq!(
            400,
            call(&client, &olena, "PUT", "/chat/cross-signing", Some(extra)).0,
            "{name}: a field that is not signed"
        );
        let eve = format!("@eve:{}", olena_mx.split(':').nth(1).unwrap());
        let mut upload = hers.upload(&olena_mx);
        upload["master"]["signatures"] = json!({ &eve: { "ed25519:EVE": "forged" } });
        upload["selfSigning"]["signatures"][&eve] = json!({ "ed25519:EVE": "forged" });
        upload["userSigning"]["signatures"][&olena_mx]["ed25519:OTHER"] = json!(1);
        let (status, out) = call(&client, &olena, "PUT", "/chat/cross-signing", Some(upload));
        assert_eq!(200, status, "{name}: {out}");
        let his_identity = Identity::new();
        let mut upload = his_identity.upload(&marek_mx);
        upload["master"]["signatures"] = json!(1);
        assert_eq!(
            200,
            call(&client, &marek, "PUT", "/chat/cross-signing", Some(upload)).0,
            "{name}: a malformed signatures field is dropped"
        );
        let (status, mine) = call(
            &client,
            &olena,
            "GET",
            &format!("/chat/keys?user={olena_mx}"),
            None,
        );
        assert_eq!(200, status, "{name}: {mine}");
        let me = &mine["crossSigning"][&olena_mx];
        assert!(me["master"]["signatures"][&eve].is_null(), "{name}: {mine}");
        assert!(
            me["selfSigning"]["signatures"][&eve].is_null(),
            "{name}: {mine}"
        );
        assert!(
            me["userSigning"]["signatures"][&olena_mx]["ed25519:OTHER"].is_null(),
            "{name}: {mine}"
        );
        assert!(
            me["selfSigning"]["signatures"][&olena_mx][Identity::id(&hers.master)].is_string(),
            "{name}: the master key's signature stays: {mine}"
        );

        // She vouches for Marek; his master key as kept from before (a
        // non-object signatures field, a forged one) breaks nothing.
        let his_master_id = his_identity.master.public_key().to_base64();
        let vouched = sign(
            &hers.usk,
            cross_key(&marek_mx, "master", &his_identity.master),
            &olena_mx,
            &Identity::id(&hers.usk),
        );
        let (_, out) = call(
            &client,
            &olena,
            "POST",
            "/chat/signatures",
            Some(json!({ &marek_mx: { &his_master_id: vouched } })),
        );
        assert_eq!(1, out["kept"].as_i64().unwrap(), "{name}: {out}");
        for broken in [
            json!(1),
            json!("x"),
            json!({ &olena_mx: 1 }),
            json!({ &eve: { "ed25519:EVE": "forged" } }),
        ] {
            let mut kept = cross_key(&marek_mx, "master", &his_identity.master);
            kept["signatures"] = broken;
            sql(
                &instance,
                "UPDATE chat_cross_signing SET key = $1 WHERE user_id = $2 AND kind = 'master'",
                &[&kept.to_string(), &marek_id],
            );
            let (status, devices) = call(
                &client,
                &olena,
                "GET",
                &format!("/chat/rooms/{room}/devices"),
                None,
            );
            assert_eq!(200, status, "{name}: {devices}");
            let master = &devices["crossSigning"][&marek_mx]["master"];
            assert!(
                master["signatures"][&olena_mx][Identity::id(&hers.usk)].is_string(),
                "{name}: {devices}"
            );
            assert!(master["signatures"][&eve].is_null(), "{name}: {devices}");
            assert_eq!(
                200,
                call(
                    &client,
                    &olena,
                    "GET",
                    &format!("/chat/keys?user={marek_mx}"),
                    None
                )
                .0,
                "{name}"
            );
        }

        // A device forgotten takes the signatures on it: the same id with
        // new keys is not signed.
        let ssk_id = Identity::id(&hers.ssk);
        let on_laptop = sign(
            &hers.ssk,
            device_keys(&laptop, &olena_mx, "LAPTOP"),
            &olena_mx,
            &ssk_id,
        );
        let (_, out) = call(
            &client,
            &olena,
            "POST",
            "/chat/signatures",
            Some(json!({ &olena_mx: { "LAPTOP": on_laptop } })),
        );
        assert_eq!(1, out["kept"].as_i64().unwrap(), "{name}: {out}");
        assert_eq!(
            200,
            call(&client, &olena, "DELETE", "/chat/devices/LAPTOP", None).0
        );
        assert!(
            sql(
                &instance,
                "SELECT target_key FROM chat_key_signatures WHERE target_user = $1 AND target_key = 'LAPTOP'",
                &[&olena_id],
            )
            .is_empty(),
            "{name}: its signatures went"
        );
        let new_laptop = Account::new();
        call(
            &client,
            &olena,
            "PUT",
            "/chat/devices/LAPTOP",
            Some(json!({"deviceKeys": device_keys(&new_laptop, &olena_mx, "LAPTOP")})),
        );
        let (_, devices) = call(
            &client,
            &olena,
            "GET",
            &format!("/chat/rooms/{room}/devices"),
            None,
        );
        let laptop_now = devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["device"] == "LAPTOP")
            .cloned()
            .unwrap();
        assert!(
            laptop_now["deviceKeys"]["signatures"][&olena_mx][&ssk_id].is_null(),
            "{name}: {laptop_now}"
        );

        // Account data: at most 50 types per person; one kept can change.
        let anna = signed_in(&instance, "anna@ministry.example", Role::Member);
        for n in 0..50 {
            assert_eq!(
                200,
                call(
                    &client,
                    &anna,
                    "PUT",
                    &format!("/chat/account-data/t.{n}"),
                    Some(json!({"n": n}))
                )
                .0,
                "{name}"
            );
        }
        let (status, out) = call(
            &client,
            &anna,
            "PUT",
            "/chat/account-data/t.50",
            Some(json!({"n": 50})),
        );
        assert_eq!(
            (413, "storage_limit"),
            (status, out["error"]["code"].as_str().unwrap_or_default()),
            "{name}: {out}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &anna,
                "PUT",
                "/chat/account-data/t.0",
                Some(json!({"n": "again"}))
            )
            .0,
            "{name}: one already kept"
        );

        // Backups: the newest ten are kept, a number is never used twice.
        let new_version = || {
            let (status, made) = call(
                &client,
                &marek,
                "POST",
                "/chat/backup/version",
                Some(
                    json!({"algorithm": "m.megolm_backup.v1.curve25519-aes-sha2", "authData": {"public_key": "A".repeat(43)}}),
                ),
            );
            assert_eq!(200, status, "{name}: {made}");
            made["version"].as_str().unwrap().to_string()
        };
        let key = |session: &str| json!({"rooms": {&room: {"sessions": {session: {"first_message_index": 0, "forwarded_count": 0, "is_verified": true, "session_data": {"ciphertext": "c", "ephemeral": "e", "mac": "m"}}}}}});
        let first = new_version();
        assert_eq!(
            200,
            call(
                &client,
                &marek,
                "PUT",
                &format!("/chat/backup/keys?version={first}"),
                Some(key("S1"))
            )
            .0
        );
        for _ in 0..11 {
            new_version();
        }
        assert!(
            call(
                &client,
                &marek,
                "GET",
                &format!("/chat/backup/keys?version={first}"),
                None
            )
            .1["rooms"]
                .as_object()
                .unwrap()
                .is_empty(),
            "{name}: the oldest went"
        );
        let kept = sql(
            &instance,
            "SELECT CAST(COUNT(*) AS BIGINT) FROM chat_backup_versions WHERE user_id = $1",
            &[&marek_id],
        );
        assert_eq!(json!(10), kept[0][1], "{name}");
        let last = new_version();
        assert_eq!(
            200,
            call(
                &client,
                &marek,
                "DELETE",
                &format!("/chat/backup/version/{last}"),
                None
            )
            .0
        );
        let after = new_version();
        assert!(
            after.parse::<i64>().unwrap() > last.parse::<i64>().unwrap(),
            "{name}: {after} after {last}"
        );

        // Room keys in one backup: at most 100000, and a refused upload
        // keeps none of its keys.
        sql(
            &instance,
            &format!("INSERT INTO chat_backup_keys (user_id, version, room, session, data, first_index, forwarded, verified) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 99999) SELECT $1, {after}, 'R', 'S' || CAST(i AS TEXT), '{{}}', 0, 0, 0 FROM n"),
            &[&marek_id],
        );
        let two = json!({"rooms": {&room: {"sessions": {
            "N1": key("N1")["rooms"][&room]["sessions"]["N1"],
            "N2": key("N2")["rooms"][&room]["sessions"]["N2"],
        }}}});
        let (status, out) = call(
            &client,
            &marek,
            "PUT",
            &format!("/chat/backup/keys?version={after}"),
            Some(two),
        );
        assert_eq!(413, status, "{name}: {out}");
        assert_eq!(
            99999,
            call(&client, &marek, "GET", "/chat/backup/version", None).1["count"],
            "{name}: nothing of it kept"
        );

        // The escrow: changing its key and taking a copy need a recent,
        // strong sign-in; the same key again does not.
        let weak = ortus_core::runtime::block_on(ortus_core::auth::sessions::start(
            instance.store.as_ref(),
            &olena_id,
            "password",
            "",
            "",
            ortus_core::auth::sessions::Lifetime::default(),
            ortus_core::program::now_ms(),
        ))
        .unwrap();
        let escrow = "B".repeat(43);
        let signed = escrow_object(&olena_mx, &escrow, &hers.master);
        let (status, out) = call(
            &client,
            &weak,
            "PATCH",
            "/chat/policy",
            Some(json!({"escrow": signed})),
        );
        assert_eq!(
            (403, "step_up"),
            (status, out["error"]["code"].as_str().unwrap_or_default()),
            "{name}: {out}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &olena,
                "PATCH",
                "/chat/policy",
                Some(json!({"escrow": signed}))
            )
            .0,
            "{name}"
        );
        assert_eq!(
            200,
            call(
                &client,
                &weak,
                "PATCH",
                "/chat/policy",
                Some(json!({"escrow": signed, "encryptedRooms": true}))
            )
            .0,
            "{name}: no change to the key"
        );
        let (status, out) = call(
            &client,
            &weak,
            "PATCH",
            "/chat/policy",
            Some(json!({"escrow": null})),
        );
        assert_eq!(
            (403, "step_up"),
            (status, out["error"]["code"].as_str().unwrap_or_default()),
            "{name}: taking it away is a change: {out}"
        );
        assert_eq!(200, call(&client, &marek, "PUT", "/chat/account-data/ortus.escrow", Some(json!({"key": escrow, "sealed": {"ephemeral": "e", "ciphertext": "c", "mac": "m"}}))).0);
        let marek_escrow = "/chat/admin/escrow?email=marek@ministry.example";
        let (status, out) = call(&client, &weak, "GET", marek_escrow, None);
        assert_eq!(
            (403, "step_up"),
            (status, out["error"]["code"].as_str().unwrap_or_default()),
            "{name}: {out}"
        );
        let taken = |instance: &ortus_core::instance::Instance| {
            sql(
                instance,
                "SELECT CAST(COUNT(*) AS BIGINT) FROM core_audit WHERE action = 'chat.escrow_copy_taken'",
                &[],
            )[0][1]
                .clone()
        };
        assert_eq!(json!(0), taken(&instance), "{name}");
        assert_eq!(200, call(&client, &olena, "GET", marek_escrow, None).0);
        assert_eq!(json!(1), taken(&instance), "{name}: recorded");
        // Unrecorded, the copy does not leave.
        sql(&instance, "DROP TABLE core_audit_head", &[]);
        let (status, out) = call(&client, &olena, "GET", marek_escrow, None);
        assert_eq!(500, status, "{name}: {out}");
        assert!(out["sealed"].is_null(), "{name}: {out}");
    }
}
