//! Messages opened with room keys from the backup, on a real server. The
//! backup is not authenticated: the server knows its public key and can
//! write entries to it. So an entry is taken only under its session's own
//! id, and a message opened with a key from the backup says so
//! (`from_backup`), as its sender could not be confirmed; one opened with
//! the key its sender gave over Olm does not, nor the phone's own.

mod common;

use common::World;
use ortus_e2e::{enc, Error, MEGOLM};
use serde_json::{json, Value};
use vodozemac::megolm::{GroupSession, InboundGroupSession, SessionConfig};
use vodozemac::pk_encryption::PkEncryption;
use vodozemac::Curve25519PublicKey;

/// A backup entry, as the server could write one: `group`'s key claimed to
/// be the device `curve`/`ed`'s, filed under `session_id`.
fn forged_entry(public: &str, group: &GroupSession, curve: &str, ed: &str) -> Value {
    let exported = InboundGroupSession::new(&group.session_key(), SessionConfig::version_1())
        .export_at(0)
        .unwrap()
        .to_base64();
    let room_key = json!({"algorithm": MEGOLM, "sender_key": curve, "session_key": exported,
        "sender_claimed_keys": {"ed25519": ed}, "forwarding_curve25519_key_chain": []});
    let sealed = PkEncryption::from_key(Curve25519PublicKey::from_base64(public).unwrap())
        .encrypt(room_key.to_string().as_bytes())
        .unwrap();
    json!({"first_message_index": 0, "forwarded_count": 0, "is_verified": true,
        "session_data": {"ephemeral": sealed.ephemeral_key.to_base64(),
            "ciphertext": vodozemac::base64_encode(&sealed.ciphertext),
            "mac": vodozemac::base64_encode(&sealed.mac)}})
}

#[test]
fn backup_keys_open_as_unconfirmed_and_forged_ones_are_skipped() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let taras = w.person("taras@ministry.example", false);
        let (room, room_id) = w.sealed_room(&olena, &[(&taras, "taras@ministry.example")]);
        let a = w.phone(&olena, "PHONEA");
        let t = w.phone(&taras, "PHONET");
        let open = |p: &common::Phone, id: &str| {
            p.e2e.decrypt(&room, &w.message(&p.person, id).to_string())
        };

        // Directly: the phone's own message, and Taras's key over Olm.
        let own = a.e2e.send(&room, "Olena's own", None).unwrap();
        let o = open(&a, &own).unwrap();
        assert!(!o.from_backup, "{n}: own message");
        let before = t.e2e.send(&room, "Before the new phone", None).unwrap();
        let o = open(&a, &before).unwrap();
        assert_eq!("Before the new phone", o.text, "{n}");
        assert!(!o.from_backup, "{n}: shared by Taras");

        // Recovery on phone A; its room keys go to the backup.
        let key = a.e2e.set_up_recovery().expect("set up");
        a.e2e.verifications().unwrap();

        // A new phone of Olena's: Taras has not shared with it yet.
        let b = w.phone(&olena, "PHONEB");

        // The server writes two entries claiming Taras's phone: one under
        // another session's id, one under its own.
        let devices = w.ok(
            &olena,
            "GET",
            &format!("/chat/rooms/{}/devices", enc(&room)),
            None,
        );
        let keys = devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["user"] == taras.me.as_str() && d["device"] == "PHONET")
            .unwrap()["deviceKeys"]["keys"]
            .clone();
        let curve = keys["curve25519:PHONET"].as_str().unwrap().to_string();
        let ed = keys["ed25519:PHONET"].as_str().unwrap().to_string();
        let info = w.ok(&olena, "GET", "/chat/backup/version", None);
        let version = info["version"].as_str().unwrap().to_string();
        let public = info["authData"]["public_key"].as_str().unwrap().to_string();
        let mut misfiled = GroupSession::new(SessionConfig::version_1());
        let other_id = GroupSession::new(SessionConfig::version_1()).session_id();
        let mut claimed = GroupSession::new(SessionConfig::version_1());
        w.ok(
            &olena,
            "PUT",
            &format!("/chat/backup/keys?version={}", enc(&version)),
            Some(json!({"rooms": {&room_id: {"sessions": {
                (&other_id): forged_entry(&public, &misfiled, &curve, &ed),
                (claimed.session_id()): forged_entry(&public, &claimed, &curve, &ed),
            }}}})),
        );
        let post = |group: &mut GroupSession, session_id: &str, text: &str| {
            let plain = json!({"type": "m.room.message",
                "content": {"msgtype": "m.text", "body": text}, "room_id": room_id});
            w.ok(
                &taras,
                "POST",
                &format!("/chat/rooms/{}/sealed", enc(&room)),
                Some(json!({"algorithm": MEGOLM, "sender_key": curve,
                    "ciphertext": group.encrypt(plain.to_string()).to_base64(),
                    "session_id": session_id, "device_id": "PHONET"})),
            )["id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let misfiled_id = misfiled.session_id();
        let forged_misfiled = post(&mut misfiled, &other_id, "Forged under another id");
        let claimed_id = claimed.session_id();
        let forged_claimed = post(&mut claimed, &claimed_id, "Forged under its own id");

        // Phone B recovers.
        let restored = b.e2e.recover(&key).expect("recovery");
        assert!(restored >= 2, "{n}: restored {restored}");
        let o = open(&b, &before).unwrap();
        assert_eq!("Before the new phone", o.text, "{n}");
        assert!(o.from_backup, "{n}: from the backup, not from Taras");
        assert!(open(&b, &own).unwrap().from_backup, "{n}: phone A's, too");
        assert!(
            matches!(open(&b, &forged_misfiled), Err(Error::Refused(_))),
            "{n}: an entry under another session's id is skipped ({misfiled_id})"
        );
        let o = open(&b, &forged_claimed).unwrap();
        assert_eq!("Forged under its own id", o.text, "{n}");
        assert!(o.from_backup, "{n}: its sender could not be confirmed");

        // Taras writes again, and so shares his key with phone B himself.
        let after = t.e2e.send(&room, "After the new phone", None).unwrap();
        b.e2e.inbox().unwrap();
        let o = open(&b, &after).unwrap();
        assert_eq!("After the new phone", o.text, "{n}");
        assert!(!o.from_backup, "{n}: Taras's key, from Taras");
        // It is the session of the message before (a new device of a member
        // already there gets the room's session, at index 0): the key from
        // Taras replaces the backup's, and that message is confirmed now.
        let session = |id: &str| w.message(&olena, id)["sealed"]["session_id"].clone();
        assert_eq!(session(&before), session(&after), "{n}");
        assert!(!open(&b, &before).unwrap().from_backup, "{n}: Taras's now");
    }
}
