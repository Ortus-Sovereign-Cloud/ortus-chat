//! Matrix federation's exact parts: canonical JSON, content and reference
//! hashes, redaction (room version 10), and Ed25519 signing of JSON and
//! of events. No networking here; the federation module uses these.

pub mod canonical;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub use canonical::canonical;

pub const ROOM_VERSION: &str = "10";

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Unpadded base64, standard or URL-safe, read leniently (padding either
/// way, stray trailing bits allowed), as Matrix servers read it.
pub fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::{
        general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig,
    };
    let config = GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    let standard = GeneralPurpose::new(&base64::alphabet::STANDARD, config);
    let url = GeneralPurpose::new(&base64::alphabet::URL_SAFE, config);
    standard.decode(text).or_else(|_| url.decode(text)).ok()
}

/// A server's signing key.
pub struct SigningKey {
    pub id: String,
    pair: Ed25519KeyPair,
}

impl SigningKey {
    pub fn from_seed(id: &str, seed: &[u8]) -> Result<Self, String> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| "bad Ed25519 seed")?;
        Ok(SigningKey {
            id: id.to_string(),
            pair,
        })
    }

    pub fn public(&self) -> String {
        b64(self.pair.public_key().as_ref())
    }

    pub fn sign(&self, message: &[u8]) -> String {
        b64(self.pair.sign(message).as_ref())
    }
}

/// Signs JSON as `server`: over its canonical form without `signatures`
/// and `unsigned`, added under signatures.server.key_id.
pub fn sign_json(value: &mut Value, server: &str, key: &SigningKey) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let signatures = obj.remove("signatures");
    let unsigned = obj.remove("unsigned");
    let sig = key.sign(canonical(&Value::Object(obj.clone())).as_bytes());
    let mut all = signatures
        .and_then(|s| s.as_object().cloned())
        .unwrap_or_default();
    let mut mine = all
        .get(server)
        .and_then(|s| s.as_object().cloned())
        .unwrap_or_default();
    mine.insert(key.id.clone(), json!(sig));
    all.insert(server.to_string(), Value::Object(mine));
    obj.insert("signatures".into(), Value::Object(all));
    if let Some(u) = unsigned {
        obj.insert("unsigned".into(), u);
    }
}

/// Whether `server`'s key `key_id` (public key, unpadded base64) signed it.
pub fn verify_json(value: &Value, server: &str, key_id: &str, public: &str) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    let Some(sig) = obj
        .get("signatures")
        .and_then(|s| s.get(server))
        .and_then(|s| s.get(key_id))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let (Some(sig), Some(public)) = (unb64(sig), unb64(public)) else {
        return false;
    };
    let mut copy = obj.clone();
    copy.remove("signatures");
    copy.remove("unsigned");
    UnparsedPublicKey::new(&ED25519, public)
        .verify(canonical(&Value::Object(copy)).as_bytes(), &sig)
        .is_ok()
}

/// The keys an event keeps when redacted (room version 10).
const KEEP: [&str; 13] = [
    "event_id",
    "type",
    "room_id",
    "sender",
    "state_key",
    "content",
    "hashes",
    "signatures",
    "depth",
    "prev_events",
    "auth_events",
    "origin_server_ts",
    "membership",
];

/// An event as redaction leaves it (room version 10).
pub fn redact(event: &Value) -> Value {
    let Some(obj) = event.as_object() else {
        return Value::Null;
    };
    let mut out = Map::new();
    for (k, v) in obj {
        if KEEP.contains(&k.as_str()) || k == "origin" || k == "prev_state" {
            out.insert(k.clone(), v.clone());
        }
    }
    let kind = obj.get("type").and_then(Value::as_str).unwrap_or_default();
    let keep: &[&str] = match kind {
        "m.room.member" => &["membership", "join_authorised_via_users_server"],
        "m.room.create" => &["creator"],
        "m.room.join_rules" => &["join_rule", "allow"],
        "m.room.power_levels" => &[
            "ban",
            "events",
            "events_default",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
        ],
        "m.room.history_visibility" => &["history_visibility"],
        _ => &[],
    };
    let content = obj
        .get("content")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let kept: Map<String, Value> = content
        .into_iter()
        .filter(|(k, _)| keep.contains(&k.as_str()))
        .collect();
    out.insert("content".into(), Value::Object(kept));
    Value::Object(out)
}

/// The content hash of an event (sha256 over it without unsigned,
/// signatures and hashes).
pub fn content_hash(event: &Value) -> String {
    let mut copy = event.as_object().cloned().unwrap_or_default();
    for k in ["unsigned", "signatures", "hashes"] {
        copy.remove(k);
    }
    b64(&Sha256::digest(canonical(&Value::Object(copy)).as_bytes()))
}

/// An event's id from its reference hash (room versions 4 and later).
pub fn event_id(event: &Value) -> String {
    let mut red = redact(event).as_object().cloned().unwrap_or_default();
    red.remove("signatures");
    red.remove("unsigned");
    red.remove("event_id");
    format!(
        "${}",
        b64url(&Sha256::digest(canonical(&Value::Object(red)).as_bytes()))
    )
}

/// Hashes and signs an event as this server; answers its id.
pub fn seal_event(event: &mut Value, server: &str, key: &SigningKey) -> String {
    let hash = content_hash(event);
    event["hashes"] = json!({"sha256": hash});
    // The signature is over the redacted event.
    let mut red = redact(event);
    if let Some(o) = red.as_object_mut() {
        o.remove("signatures");
    }
    sign_json(&mut red, server, key);
    event["signatures"] = red["signatures"].clone();
    event_id(event)
}

/// Whether an event is signed by `server` with that key, over its
/// redacted form, and its content hash matches.
pub fn check_event(event: &Value, server: &str, key_id: &str, public: &str) -> bool {
    let hash_ok = event["hashes"]["sha256"].as_str() == Some(content_hash(event).as_str());
    hash_ok && verify_json(&redact(event), server, key_id, public)
}
