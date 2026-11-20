//! This server's Ed25519 key (made once, kept sealed) and the keys of
//! partner servers (fetched from them, checked, kept until they expire).

use ortus_core::instance::Instance;
use serde_json::{json, Value};

use crate::matrix::{self, SigningKey};
use crate::store::{now, server_name};

/// How long others may trust our key list.
const VALID_FOR: i64 = 7 * 86_400_000;

/// This server's signing key, made the first time it is needed.
pub async fn ours(instance: &Instance) -> Result<SigningKey, String> {
    let s = instance.store.as_ref();
    let row = s
        .query(
            "SELECT key_id, seed_sealed FROM chat_fed_keys ORDER BY created_at LIMIT 1",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    if let Some(r) = row.first() {
        let seed = instance
            .keys
            .open(r.text(1).unwrap_or_default().as_bytes())?;
        return SigningKey::from_seed(r.text(0).unwrap_or_default(), &seed);
    }
    let mut seed = [0u8; 32];
    aws_lc_rs::rand::fill(&mut seed).map_err(|_| "no randomness")?;
    let id = format!("ed25519:{}", ortus_core::auth::random_hex(3));
    // Two first users at once: one key wins, both use it.
    let _ = s
        .execute(
            "INSERT INTO chat_fed_keys (key_id, seed_sealed, created_at) VALUES ($1, $2, $3)",
            &[
                id.as_str().into(),
                instance.keys.seal(&seed).into(),
                now().into(),
            ],
        )
        .await;
    Box::pin(ours(instance)).await
}

/// The key list others fetch: our current key, signed by itself.
pub async fn server_keys(instance: &Instance) -> Result<Value, String> {
    let key = ours(instance).await?;
    let name = server_name(instance);
    let mut doc = json!({
        "server_name": name,
        "valid_until_ts": now() + VALID_FOR,
        "old_verify_keys": {},
        "verify_keys": { key.id.clone(): { "key": key.public() } },
    });
    matrix::sign_json(&mut doc, &name, &key);
    Ok(doc)
}

/// A partner server's public key, from the cache or fetched from it.
pub async fn remote(instance: &Instance, server: &str, key_id: &str) -> Result<String, String> {
    let s = instance.store.as_ref();
    if let Some(r) = s
        .query(
            "SELECT public FROM chat_fed_remote_keys WHERE server = $1 AND key_id = $2 AND valid_until > $3",
            &[server.into(), key_id.into(), now().into()],
        )
        .await
        .map_err(|e| e.to_string())?
        .first()
    {
        return Ok(r.text(0).unwrap_or_default().to_string());
    }
    // Never fetch from a server that is not a partner.
    if !super::partner(instance, server).await {
        return Err(format!("{server} is not a partner allowed chat"));
    }
    // A key that could not be had is not asked for again for a minute
    // (anyone can name a key id in a request).
    static MISSES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    let misses = MISSES.get_or_init(Default::default);
    let miss_key = format!("{server} {key_id}");
    if misses
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&miss_key)
        .is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(60))
    {
        return Err(format!("{server} has no key {key_id}"));
    }
    let found = fetch(instance, server, key_id).await;
    if found.is_err() {
        let mut m = misses.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 10_000 {
            m.clear();
        }
        m.insert(miss_key, std::time::Instant::now());
    }
    found
}

async fn fetch(instance: &Instance, server: &str, key_id: &str) -> Result<String, String> {
    let s = instance.store.as_ref();
    let doc = super::client::get_json(instance, server, "/_matrix/key/v2/server", false).await?;
    if doc["server_name"].as_str() != Some(server) {
        return Err("the key list names another server".into());
    }
    let valid_until = doc["valid_until_ts"]
        .as_i64()
        .unwrap_or(0)
        .min(now() + VALID_FOR);
    if valid_until <= now() {
        return Err("the key list has expired".into());
    }
    let keys = doc["verify_keys"].as_object().cloned().unwrap_or_default();
    let mut found = None;
    for (id, v) in &keys {
        let public = v["key"].as_str().unwrap_or_default();
        // Each key must sign the list itself.
        if !matrix::verify_json(&doc, server, id, public) {
            continue;
        }
        let _ = s
            .execute(
                "DELETE FROM chat_fed_remote_keys WHERE server = $1 AND key_id = $2",
                &[server.into(), id.as_str().into()],
            )
            .await;
        let _ = s
            .execute(
                "INSERT INTO chat_fed_remote_keys (server, key_id, public, valid_until) VALUES ($1, $2, $3, $4)",
                &[server.into(), id.as_str().into(), public.into(), valid_until.into()],
            )
            .await;
        if id == key_id {
            found = Some(public.to_string());
        }
    }
    found.ok_or_else(|| format!("{server} has no key {key_id}"))
}

/// Whether `server` signed this JSON with one of its keys.
pub async fn verify_from(instance: &Instance, value: &Value, server: &str) -> bool {
    let Some(sigs) = value["signatures"][server].as_object() else {
        return false;
    };
    for key_id in sigs.keys() {
        if let Ok(public) = remote(instance, server, key_id).await {
            if matrix::verify_json(value, server, key_id, &public) {
                return true;
            }
        }
    }
    false
}

/// Whether an event is signed by `server` (over its redacted form) with
/// its content hash intact.
pub async fn check_event_from(instance: &Instance, event: &Value, server: &str) -> bool {
    let Some(sigs) = event["signatures"][server].as_object() else {
        return false;
    };
    for key_id in sigs.keys() {
        if let Ok(public) = remote(instance, server, key_id).await {
            if matrix::check_event(event, server, key_id, &public) {
                return true;
            }
        }
    }
    false
}
