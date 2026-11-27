//! Trust in end-to-end rooms (docs/e2e-trust-and-backup.md): a person's
//! cross-signing keys (master, self-signing, user-signing), the signatures
//! they make on their devices and on other people's master keys, their
//! account data (secret storage and the escrow copy: opaque here) and
//! their room-key backup. The server keeps public keys and signatures,
//! checks every signature before keeping it, and holds no private key in
//! the clear.

use std::collections::HashMap;
use std::sync::Arc;

use ortus_core::api::{answer, body, ok, ApiError, Method, Route};
use ortus_core::auth::Access;
use ortus_core::instance::Instance;
use ortus_core::storage::{AsyncStore, BoxFuture, Migration};
use rust_web_server::prelude::*;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::matrix;
use crate::store::{self, now};

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 10,
    name: "end-to-end trust: cross-signing keys, signatures, account data, key backup",
    sql: "CREATE TABLE chat_cross_signing (
        user_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        public TEXT NOT NULL,
        key TEXT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, kind)
    );
    CREATE TABLE chat_key_signatures (
        signer_user TEXT NOT NULL,
        signer_key TEXT NOT NULL,
        target_user TEXT NOT NULL,
        target_key TEXT NOT NULL,
        signature TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (signer_user, signer_key, target_user, target_key)
    );
    CREATE INDEX chat_key_signatures_target ON chat_key_signatures (target_user, target_key);
    CREATE TABLE chat_account_data (
        user_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        content TEXT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, kind)
    );
    CREATE TABLE chat_backup_versions (
        user_id TEXT NOT NULL,
        version BIGINT NOT NULL,
        algorithm TEXT NOT NULL,
        auth_data TEXT NOT NULL,
        etag BIGINT NOT NULL,
        deleted BIGINT,
        PRIMARY KEY (user_id, version)
    );
    CREATE TABLE chat_backup_keys (
        user_id TEXT NOT NULL,
        version BIGINT NOT NULL,
        room TEXT NOT NULL,
        session TEXT NOT NULL,
        data TEXT NOT NULL,
        first_index BIGINT NOT NULL,
        forwarded BIGINT NOT NULL,
        verified BIGINT NOT NULL,
        PRIMARY KEY (user_id, version, room, session)
    )",
}];

/// The backup algorithm (Matrix's).
pub const BACKUP: &str = "m.megolm_backup.v1.curve25519-aes-sha2";
const MAX_DATA: usize = 64 * 1024;
const MAX_KEYS_PER_UPLOAD: usize = 1000;
/// What one person may keep: account data types, backups not deleted, and
/// room keys in one backup.
const MAX_ACCOUNT_TYPES: i64 = 50;
const MAX_BACKUP_VERSIONS: usize = 10;
const MAX_BACKUP_KEYS: i64 = 100_000;

fn mx(instance: &Instance, user: &str) -> String {
    store::mxid(user, &store::server_name(instance))
}

fn bad(message: &str) -> ApiError {
    ApiError::bad_request(message.to_string())
}

/// More than one person may keep of something.
fn full(message: &str) -> ApiError {
    ApiError {
        status: 413,
        code: "storage_limit",
        message: message.to_string(),
    }
}

/// The one Ed25519 key of a cross-signing key object: (key id, public).
fn ed25519(key: &Value) -> Option<(String, String)> {
    let keys = key["keys"].as_object()?;
    if keys.len() != 1 {
        return None;
    }
    let (id, public) = keys.iter().next()?;
    let public = public.as_str()?;
    (id == &format!("ed25519:{public}") && public.len() == 43)
        .then(|| (id.clone(), public.to_string()))
}

/// A cross-signing key rebuilt from its signed fields (user_id, usage and
/// one Ed25519 key): (fields, key id, public). An upload with anything
/// else in what was signed is refused.
fn signed_fields(key: &Value, owner: &str, usage: &str) -> Option<(Value, String, String)> {
    if key["user_id"] != owner || key["usage"] != json!([usage]) {
        return None;
    }
    let (id, public) = ed25519(key)?;
    let fields = json!({"user_id": owner, "usage": [usage], "keys": {id.clone(): public}});
    (plain(key) == fields).then_some((fields, id, public))
}

/// A kept cross-signing key as served: its signed fields, and the master
/// key's signature on it when `by` is the master key's id. Other
/// signatures are served only from those the server checked.
fn served(key: &Value, owner: &str, by: Option<&str>) -> Value {
    let mut out = plain(key);
    if let Some(by) = by {
        if let Some(sig) = key["signatures"][owner][by].as_str() {
            out["signatures"] = json!({ owner: { by: sig } });
        }
    }
    out
}

/// A person's cross-signing key of a kind, as kept.
async fn cross_key(s: &dyn AsyncStore, user: &str, kind: &str) -> Result<Option<Value>, ApiError> {
    Ok(s.query(
        "SELECT key FROM chat_cross_signing WHERE user_id = $1 AND kind = $2",
        &[user.into(), kind.into()],
    )
    .await?
    .first()
    .and_then(|r| r.text(0).and_then(|t| serde_json::from_str(t).ok())))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CrossSigning {
    master: Value,
    #[serde(default)]
    self_signing: Option<Value>,
    #[serde(default)]
    user_signing: Option<Value>,
}

/// The person's cross-signing keys. A first master key is free; another
/// one needs a recent sign-in, and what was signed with or on the old keys
/// goes.
async fn put_cross_signing(
    request: &Request,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let session = ortus_core::auth::current(request, instance)
        .await
        .ok_or_else(ApiError::sign_in)?;
    let me = session.user.clone();
    let input: CrossSigning = body(request)?;
    let my = mx(instance, &me.id);
    let s = instance.store.as_ref();
    // Only the signed fields are kept: the master key without signatures
    // (others come through POST /chat/signatures, checked), the other two
    // with the master key's signature only.
    let Some((master, master_id, master_public)) = signed_fields(&input.master, &my, "master")
    else {
        return Err(bad(
            "The master key is this person's one Ed25519 key, for usage master, and nothing else.",
        ));
    };
    let mut kept = vec![("master", master, master_public.clone())];
    for (kind, key) in [
        ("self_signing", &input.self_signing),
        ("user_signing", &input.user_signing),
    ] {
        if let Some(key) = key {
            let Some((mut fields, _, public)) = signed_fields(key, &my, kind) else {
                return Err(bad("A self-signing or user-signing key is this person's one Ed25519 key, for its usage, and nothing else."));
            };
            if !matrix::verify_json(key, &my, &master_id, &master_public) {
                return Err(bad(
                    "A self-signing or user-signing key is signed by the master key.",
                ));
            }
            let sig = key["signatures"][&my][&master_id].clone();
            fields["signatures"] = json!({ &my: { &master_id: sig } });
            kept.push((kind, fields, public));
        }
    }
    let old = cross_key(s, &me.id, "master").await?;
    let replacing = old
        .as_ref()
        .and_then(ed25519)
        .is_some_and(|(_, p)| p != master_public);
    if replacing {
        ortus_core::auth::step_up::require(s, &session).await?;
    }
    let mut tx = s.begin().await?;
    if replacing {
        // A new identity: everything signed with or on the old keys goes.
        for kind in ["master", "self_signing", "user_signing"] {
            tx.execute(
                "DELETE FROM chat_cross_signing WHERE user_id = $1 AND kind = $2",
                &[me.id.as_str().into(), kind.into()],
            )
            .await?;
        }
        tx.execute("DELETE FROM chat_key_signatures WHERE signer_user = $1 OR (target_user = $1 AND target_key NOT IN (SELECT device FROM chat_devices WHERE user_id = $1))", &[me.id.as_str().into()])
            .await?;
    }
    for (kind, key, public) in &kept {
        let previous = cross_key_tx(&mut *tx, &me.id, kind).await?;
        if previous
            .as_ref()
            .and_then(ed25519)
            .is_some_and(|(_, p)| &p != public)
        {
            // A new self-signing or user-signing key: its old signatures go.
            if let Some((old_id, _)) = previous.as_ref().and_then(ed25519) {
                tx.execute(
                    "DELETE FROM chat_key_signatures WHERE signer_user = $1 AND signer_key = $2",
                    &[me.id.as_str().into(), old_id.as_str().into()],
                )
                .await?;
            }
        }
        tx.execute(
            "DELETE FROM chat_cross_signing WHERE user_id = $1 AND kind = $2",
            &[me.id.as_str().into(), (*kind).into()],
        )
        .await?;
        tx.execute(
            "INSERT INTO chat_cross_signing (user_id, kind, public, key, updated_at) VALUES ($1, $2, $3, $4, $5)",
            &[me.id.as_str().into(), (*kind).into(), public.as_str().into(), key.to_string().into(), now().into()],
        )
        .await?;
    }
    tx.commit().await?;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.cross_signing_set", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .with(json!({"master": master_public, "replaced": replacing})),
    )
    .await;
    Ok(ok(&json!({"master": master_public, "replaced": replacing})))
}

async fn cross_key_tx(
    tx: &mut dyn ortus_core::storage::AsyncTx,
    user: &str,
    kind: &str,
) -> Result<Option<Value>, ApiError> {
    Ok(tx
        .query(
            "SELECT key FROM chat_cross_signing WHERE user_id = $1 AND kind = $2",
            &[user.into(), (*kind).into()],
        )
        .await?
        .first()
        .and_then(|r| r.text(0).and_then(|t| serde_json::from_str(t).ok())))
}

/// The signed fields of an object, without signatures and unsigned.
fn plain(value: &Value) -> Value {
    let mut copy = value.as_object().cloned().unwrap_or_default();
    copy.remove("signatures");
    copy.remove("unsigned");
    Value::Object(copy)
}

/// Signatures made by the person: on their own devices (with their
/// self-signing key), on their own master key (with one of their devices),
/// and on other people's master keys (with their user-signing key). Each
/// is checked, and the signed object must be the one the server has.
async fn post_signatures(
    request: &Request,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let input: Map<String, Value> = body(request)?;
    let my = mx(instance, &me.id);
    let s = instance.store.as_ref();
    let ssk = cross_key(s, &me.id, "self_signing")
        .await?
        .and_then(|k| ed25519(&k));
    let usk = cross_key(s, &me.id, "user_signing")
        .await?
        .and_then(|k| ed25519(&k));
    let mut kept = 0;
    let mut failures = Map::new();
    let server = store::server_name(instance);
    for (target_mx, objects) in &input {
        let Some(objects) = objects.as_object() else {
            continue;
        };
        let target_user = target_mx
            .strip_prefix('@')
            .and_then(|r| r.strip_suffix(&format!(":{server}")))
            .map(str::to_string);
        for (target_key, object) in objects.iter().take(100) {
            let result: Result<(String, String), &str> = async {
                let target_user = target_user.clone().ok_or("not a person of this server")?;
                let own = target_user == me.id;
                // The object as the server has it, and who may sign it with what.
                let (have, signers): (Value, Vec<(String, String)>) = if own {
                    if let Some(device) = device_keys(s, &me.id, target_key).await {
                        (device, ssk.clone().into_iter().collect())
                    } else if let Some(master) = cross_key(s, &me.id, "master")
                        .await
                        .ok()
                        .flatten()
                        .filter(|m| ed25519(m).is_some_and(|(_, p)| &p == target_key))
                    {
                        // The own master key, signed by one of one's devices.
                        let devices = own_device_keys(s, &me.id).await;
                        (master, devices)
                    } else {
                        return Err("no such device or master key");
                    }
                } else {
                    let master = cross_key(s, &target_user, "master")
                        .await
                        .ok()
                        .flatten()
                        .ok_or("no master key")?;
                    if !ed25519(&master).is_some_and(|(_, p)| &p == target_key) {
                        return Err("not their master key");
                    }
                    (master, usk.clone().into_iter().collect())
                };
                if plain(object) != plain(&have) {
                    return Err("the signed object is not the one kept");
                }
                for (key_id, public) in signers {
                    if matrix::verify_json(object, &my, &key_id, &public) {
                        let sig = object["signatures"][&my][&key_id]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        return Ok((key_id, sig));
                    }
                }
                Err("not signed by a key that may sign it")
            }
            .await;
            match result {
                Ok((signer_key, sig)) => {
                    let target_user = target_user.clone().unwrap_or_default();
                    s.execute(
                        "DELETE FROM chat_key_signatures WHERE signer_user = $1 AND signer_key = $2 AND target_user = $3 AND target_key = $4",
                        &[me.id.as_str().into(), signer_key.as_str().into(), target_user.as_str().into(), target_key.as_str().into()],
                    )
                    .await?;
                    s.execute(
                        "INSERT INTO chat_key_signatures (signer_user, signer_key, target_user, target_key, signature, at) VALUES ($1, $2, $3, $4, $5, $6)",
                        &[me.id.as_str().into(), signer_key.as_str().into(), target_user.as_str().into(), target_key.as_str().into(), sig.as_str().into(), now().into()],
                    )
                    .await?;
                    kept += 1;
                }
                Err(why) => {
                    failures
                        .entry(target_mx.clone())
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .map(|m| m.insert(target_key.clone(), json!({"error": why})));
                }
            }
        }
    }
    Ok(ok(&json!({"kept": kept, "failures": failures})))
}

async fn device_keys(s: &dyn AsyncStore, user: &str, device: &str) -> Option<Value> {
    s.query(
        "SELECT keys FROM chat_devices WHERE user_id = $1 AND device = $2",
        &[user.into(), device.into()],
    )
    .await
    .ok()?
    .first()
    .and_then(|r| r.text(0).and_then(|t| serde_json::from_str(t).ok()))
}

/// A person's devices' Ed25519 keys: (key id, public).
async fn own_device_keys(s: &dyn AsyncStore, user: &str) -> Vec<(String, String)> {
    s.query(
        "SELECT device, keys FROM chat_devices WHERE user_id = $1",
        &[user.into()],
    )
    .await
    .unwrap_or_default()
    .iter()
    .filter_map(|r| {
        let device = r.text(0)?;
        let keys: Value = serde_json::from_str(r.text(1)?).ok()?;
        let id = format!("ed25519:{device}");
        Some((id.clone(), keys["keys"][&id].as_str()?.to_string()))
    })
    .collect()
}

/// Adds the kept signatures on (user, key) to a signed object: those by
/// its owner and those by `viewer`.
async fn with_signatures(
    s: &dyn AsyncStore,
    instance: &Instance,
    object: Value,
    user: &str,
    key: &str,
    viewer: &str,
) -> Value {
    let rows: Signatures = s
        .query(
            "SELECT signer_user, signer_key, signature FROM chat_key_signatures WHERE target_user = $1 AND target_key = $2 AND (signer_user = $1 OR signer_user = $3)",
            &[user.into(), key.into(), viewer.into()],
        )
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|r| Some((r.text(0)?.to_string(), r.text(1)?.to_string(), r.text(2)?.to_string())))
        .collect();
    add_signatures(instance, object, &rows)
}

/// Kept signatures: (signer, signer's key, signature).
type Signatures = Vec<(String, String, String)>;

/// A signed object with these kept signatures (signer, signer's key,
/// signature) added.
fn add_signatures(
    instance: &Instance,
    mut object: Value,
    rows: &[(String, String, String)],
) -> Value {
    if rows.is_empty() {
        return object;
    }
    // Whatever shape it was kept in, never a panic: a signatures field
    // that is not an object counts as none.
    let Some(map) = object.as_object_mut() else {
        return object;
    };
    let all = map.entry("signatures").or_insert_with(|| json!({}));
    if !all.is_object() {
        *all = json!({});
    }
    for (signer, signer_key, sig) in rows {
        let Some(all) = all.as_object_mut() else {
            break;
        };
        let by = all.entry(mx(instance, signer)).or_insert_with(|| json!({}));
        if !by.is_object() {
            *by = json!({});
        }
        if let Some(by) = by.as_object_mut() {
            by.insert(signer_key.clone(), json!(sig));
        }
    }
    object
}

/// The trust part of a room's devices, for `viewer`: each member's master
/// and self-signing keys (with the viewer's signatures on their master),
/// the signatures on their devices, and the viewer's own user-signing key.
pub async fn for_devices(
    instance: &Instance,
    viewer: &str,
    members: &[String],
    devices: &mut [Value],
) -> Value {
    let s = instance.store.as_ref();
    // Two queries for the whole room, not a few per member and device:
    // everyone's cross-signing keys, and the signatures on their keys by
    // themselves or by the viewer.
    let mut cross: HashMap<(String, String), Value> = HashMap::new();
    let mut signatures: HashMap<(String, String), Signatures> = HashMap::new();
    for chunk in members.chunks(256) {
        let (list, values) = ortus_core::storage::any_of(1, chunk);
        for r in s
            .query(
                &format!(
                    "SELECT user_id, kind, key FROM chat_cross_signing WHERE user_id IN ({list})"
                ),
                &values,
            )
            .await
            .unwrap_or_default()
        {
            if let (Some(user), Some(kind), Some(key)) = (
                r.text(0),
                r.text(1),
                r.text(2).and_then(|t| serde_json::from_str(t).ok()),
            ) {
                cross.insert((user.to_string(), kind.to_string()), key);
            }
        }
        let (list, mut values) = ortus_core::storage::any_of(2, chunk);
        values.insert(0, viewer.into());
        for r in s
            .query(
                &format!("SELECT target_user, target_key, signer_user, signer_key, signature FROM chat_key_signatures WHERE target_user IN ({list}) AND (signer_user = target_user OR signer_user = $1)"),
                &values,
            )
            .await
            .unwrap_or_default()
        {
            if let (Some(user), Some(key), Some(signer), Some(signer_key), Some(sig)) = (r.text(0), r.text(1), r.text(2), r.text(3), r.text(4)) {
                signatures
                    .entry((user.to_string(), key.to_string()))
                    .or_default()
                    .push((signer.to_string(), signer_key.to_string(), sig.to_string()));
            }
        }
    }
    let signed_on = |user: &str, key: &str| {
        signatures
            .get(&(user.to_string(), key.to_string()))
            .map(Vec::as_slice)
            .unwrap_or_default()
    };
    let mut people = Map::new();
    let mut seen = std::collections::HashSet::new();
    for user in members {
        if !seen.insert(user) {
            continue;
        }
        let owner = mx(instance, user);
        let mut keys = Map::new();
        let master = cross.get(&(user.clone(), "master".into()));
        let master_id = master.and_then(ed25519);
        if let Some(key) = master {
            let public = master_id.clone().map(|(_, p)| p).unwrap_or_default();
            let key = served(key, &owner, None);
            keys.insert(
                "master".into(),
                add_signatures(instance, key, signed_on(user, &public)),
            );
        }
        let by = master_id.as_ref().map(|(id, _)| id.as_str());
        let mut kinds = vec![("self_signing", "selfSigning")];
        if user == viewer {
            kinds.push(("user_signing", "userSigning"));
        }
        for (kind, name) in kinds {
            if let Some(key) = cross.get(&(user.clone(), kind.to_string())) {
                keys.insert(name.into(), served(key, &owner, by));
            }
        }
        if !keys.is_empty() {
            people.insert(owner, Value::Object(keys));
        }
    }
    for d in devices.iter_mut() {
        let (Some(user), Some(device)) = (
            d["userId"].as_str().map(str::to_string),
            d["device"].as_str().map(str::to_string),
        ) else {
            continue;
        };
        let keys = d["deviceKeys"].take();
        d["deviceKeys"] = add_signatures(instance, keys, signed_on(&user, &device));
        if let Some(obj) = d.as_object_mut() {
            obj.remove("userId");
        }
    }
    Value::Object(people)
}

// ---- account data ---------------------------------------------------------

fn account_kind(kind: &str) -> Result<&str, ApiError> {
    let ok = !kind.is_empty()
        && kind.len() <= 200
        && kind
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-:".contains(c));
    if ok {
        Ok(kind)
    } else {
        Err(bad("An account data type is letters, digits and . _ - :"))
    }
}

async fn get_account_data(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let kind = account_kind(params.get("type").unwrap_or_default())?;
    let rows = instance
        .store
        .query(
            "SELECT content FROM chat_account_data WHERE user_id = $1 AND kind = $2",
            &[me.id.as_str().into(), kind.into()],
        )
        .await?;
    let content = rows
        .first()
        .and_then(|r| r.text(0))
        .ok_or_else(|| ApiError::not_found("Not there."))?;
    Ok(ok(
        &serde_json::from_str::<Value>(content).unwrap_or(Value::Null)
    ))
}

async fn put_account_data(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let kind = account_kind(params.get("type").unwrap_or_default())?;
    let content: Value = body(request)?;
    let text = content.to_string();
    if !content.is_object() || text.len() > MAX_DATA {
        return Err(bad("Account data is a JSON object of at most 64 KB."));
    }
    let s = instance.store.as_ref();
    let mut tx = s.begin().await?;
    let others = tx
        .query(
            "SELECT CAST(COUNT(*) AS BIGINT) FROM chat_account_data WHERE user_id = $1 AND kind <> $2",
            &[me.id.as_str().into(), kind.into()],
        )
        .await?
        .first()
        .and_then(|r| r.int(0))
        .unwrap_or(0);
    if others >= MAX_ACCOUNT_TYPES {
        return Err(full("At most 50 types of account data per person."));
    }
    tx.execute(
        "DELETE FROM chat_account_data WHERE user_id = $1 AND kind = $2",
        &[me.id.as_str().into(), kind.into()],
    )
    .await?;
    tx.execute(
        "INSERT INTO chat_account_data (user_id, kind, content, updated_at) VALUES ($1, $2, $3, $4)",
        &[me.id.as_str().into(), kind.into(), text.as_str().into(), now().into()],
    )
    .await?;
    tx.commit().await?;
    Ok(ok(&json!({})))
}

// ---- key backup -----------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewVersion {
    algorithm: String,
    auth_data: Value,
}

async fn current_version(
    s: &dyn AsyncStore,
    user: &str,
) -> Result<Option<(i64, String, Value, i64)>, ApiError> {
    Ok(s.query(
        "SELECT version, algorithm, auth_data, etag FROM chat_backup_versions WHERE user_id = $1 AND deleted IS NULL ORDER BY version DESC LIMIT 1",
        &[user.into()],
    )
    .await?
    .first()
    .and_then(|r| {
        Some((
            r.int(0)?,
            r.text(1)?.to_string(),
            serde_json::from_str(r.text(2)?).ok()?,
            r.int(3)?,
        ))
    }))
}

async fn post_version(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let input: NewVersion = body(request)?;
    let public = input.auth_data["public_key"].as_str().unwrap_or_default();
    if input.algorithm != BACKUP
        || public.len() != 43
        || input.auth_data.to_string().len() > MAX_DATA
    {
        return Err(bad(
            "A backup is m.megolm_backup.v1.curve25519-aes-sha2 with its public key.",
        ));
    }
    let s = instance.store.as_ref();
    // Two made at once may pick the same number: the one that loses tries
    // again with the next.
    for _ in 0..5 {
        let mut tx = s.begin().await?;
        let next = tx
            .query("SELECT CAST(COALESCE(MAX(version), 0) AS BIGINT) FROM chat_backup_versions WHERE user_id = $1", &[me.id.as_str().into()])
            .await?
            .first()
            .and_then(|r| r.int(0))
            .unwrap_or(0)
            + 1;
        let made = tx
            .execute(
                "INSERT INTO chat_backup_versions (user_id, version, algorithm, auth_data, etag) VALUES ($1, $2, $3, $4, 0) ON CONFLICT (user_id, version) DO NOTHING",
                &[me.id.as_str().into(), next.into(), input.algorithm.as_str().into(), input.auth_data.to_string().into()],
            )
            .await?;
        if made == 0 {
            tx.rollback().await?;
            continue;
        }
        // Deleted backups older than this one go (this one keeps the
        // number taken), and only the newest few are kept.
        tx.execute(
            "DELETE FROM chat_backup_versions WHERE user_id = $1 AND version < $2 AND deleted IS NOT NULL",
            &[me.id.as_str().into(), next.into()],
        )
        .await?;
        let old: Vec<i64> = tx
            .query(
                "SELECT version FROM chat_backup_versions WHERE user_id = $1 AND deleted IS NULL ORDER BY version DESC",
                &[me.id.as_str().into()],
            )
            .await?
            .iter()
            .skip(MAX_BACKUP_VERSIONS)
            .filter_map(|r| r.int(0))
            .collect();
        for version in old {
            for sql in [
                "DELETE FROM chat_backup_keys WHERE user_id = $1 AND version = $2",
                "DELETE FROM chat_backup_versions WHERE user_id = $1 AND version = $2",
            ] {
                tx.execute(sql, &[me.id.as_str().into(), version.into()])
                    .await?;
            }
        }
        tx.commit().await?;
        return Ok(ok(&json!({"version": next.to_string()})));
    }
    Err(ApiError::conflict(
        "Another backup was being made at the same time: try again.",
    ))
}

async fn version_json(
    s: &dyn AsyncStore,
    user: &str,
    (version, algorithm, auth_data, etag): (i64, String, Value, i64),
) -> Result<Value, ApiError> {
    let count = s
        .query(
            "SELECT CAST(COUNT(*) AS BIGINT) FROM chat_backup_keys WHERE user_id = $1 AND version = $2",
            &[user.into(), version.into()],
        )
        .await?
        .first()
        .and_then(|r| r.int(0))
        .unwrap_or(0);
    Ok(
        json!({"version": version.to_string(), "algorithm": algorithm, "authData": auth_data, "etag": etag.to_string(), "count": count}),
    )
}

async fn get_version(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let s = instance.store.as_ref();
    let current = current_version(s, &me.id)
        .await?
        .ok_or_else(|| ApiError::not_found("Not there."))?;
    Ok(ok(&version_json(s, &me.id, current).await?))
}

async fn delete_version(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let version: i64 = params
        .get("version")
        .unwrap_or_default()
        .parse()
        .map_err(|_| bad("A backup version is a number."))?;
    let s = instance.store.as_ref();
    let mut tx = s.begin().await?;
    tx.execute(
        "UPDATE chat_backup_versions SET deleted = $3 WHERE user_id = $1 AND version = $2",
        &[me.id.as_str().into(), version.into(), now().into()],
    )
    .await?;
    tx.execute(
        "DELETE FROM chat_backup_keys WHERE user_id = $1 AND version = $2",
        &[me.id.as_str().into(), version.into()],
    )
    .await?;
    tx.commit().await?;
    Ok(ok(&json!({})))
}

/// How good a copy of a room key is: verified, first index, forwards.
type Rank = (bool, i64, i64);

/// Whether `new` is a better copy of a room key than `old` (Matrix's
/// rules): verified first, then the lower first index, then fewer forwards.
fn better(new: Rank, old: Rank) -> bool {
    if new.0 != old.0 {
        return new.0;
    }
    if new.1 != old.1 {
        return new.1 < old.1;
    }
    new.2 < old.2
}

async fn put_keys(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let version: i64 = crate::api::query(request, "version")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad("Which backup version: ?version="))?;
    let input: Value = body(request)?;
    let s = instance.store.as_ref();
    let current = current_version(s, &me.id)
        .await?
        .ok_or_else(|| ApiError::not_found("Not there."))?;
    let wrong = || ApiError {
        status: 403,
        code: "wrong_backup_version",
        message: "That is not the current backup version.".into(),
    };
    if current.0 != version {
        return Err(wrong());
    }
    // One transaction: a refused upload leaves nothing behind. Taking the
    // backup's row first makes uploads to it wait for each other.
    let mut tx = s.begin().await?;
    tx.execute(
        "UPDATE chat_backup_versions SET etag = etag WHERE user_id = $1 AND version = $2 AND deleted IS NULL",
        &[me.id.as_str().into(), version.into()],
    )
    .await?;
    let newest = tx
        .query(
            "SELECT CAST(MAX(version) AS BIGINT) FROM chat_backup_versions WHERE user_id = $1 AND deleted IS NULL",
            &[me.id.as_str().into()],
        )
        .await?
        .first()
        .and_then(|r| r.int(0));
    if newest != Some(version) {
        return Err(wrong());
    }
    let mut count = tx
        .query(
            "SELECT CAST(COUNT(*) AS BIGINT) FROM chat_backup_keys WHERE user_id = $1 AND version = $2",
            &[me.id.as_str().into(), version.into()],
        )
        .await?
        .first()
        .and_then(|r| r.int(0))
        .unwrap_or(0);
    // The upload's keys, then the copies already kept of them in a few
    // queries (not one per key), then the better ones written in a few.
    let mut uploaded: Vec<(String, String, String, Rank)> = Vec::new();
    for (room, r) in input["rooms"].as_object().into_iter().flatten() {
        for (session, data) in r["sessions"].as_object().into_iter().flatten() {
            if uploaded.len() >= MAX_KEYS_PER_UPLOAD {
                return Err(bad("At most a thousand room keys at once."));
            }
            let text = data["session_data"].to_string();
            if !data["session_data"].is_object() || text.len() > MAX_DATA {
                continue;
            }
            let new = (
                data["is_verified"].as_bool().unwrap_or(false),
                data["first_message_index"].as_i64().unwrap_or(i64::MAX),
                data["forwarded_count"].as_i64().unwrap_or(i64::MAX),
            );
            uploaded.push((room.clone(), session.clone(), text, new));
        }
    }
    let sessions: Vec<&str> = uploaded
        .iter()
        .map(|(_, session, _, _)| session.as_str())
        .collect();
    let mut kept: HashMap<(String, String), Rank> = HashMap::new();
    for chunk in sessions.chunks(256) {
        let (list, mut values) = ortus_core::storage::any_of(3, chunk);
        values.splice(0..0, [me.id.as_str().into(), version.into()]);
        for r in tx
            .query(
                &format!("SELECT room, session, verified, first_index, forwarded FROM chat_backup_keys WHERE user_id = $1 AND version = $2 AND session IN ({list})"),
                &values,
            )
            .await?
        {
            if let (Some(room), Some(session)) = (r.text(0), r.text(1)) {
                kept.insert(
                    (room.to_string(), session.to_string()),
                    (r.int(2).unwrap_or(0) != 0, r.int(3).unwrap_or(0), r.int(4).unwrap_or(0)),
                );
            }
        }
    }
    let mut better_ones = Vec::new();
    for (room, session, text, new) in &uploaded {
        let old = kept.get(&(room.clone(), session.clone())).copied();
        if old.is_some_and(|old| !better(*new, old)) {
            continue;
        }
        if old.is_none() {
            count += 1;
            if count > MAX_BACKUP_KEYS {
                return Err(full("At most 100000 room keys in one backup."));
            }
        }
        better_ones.push((room, session, text, new));
    }
    let changed = better_ones.len();
    for chunk in better_ones.chunks(100) {
        let mut rows = Vec::new();
        let mut values: Vec<ortus_core::storage::Value> =
            vec![me.id.as_str().into(), version.into()];
        for (room, session, text, new) in chunk {
            let n = values.len();
            rows.push(format!(
                "($1, $2, ${}, ${}, ${}, ${}, ${}, ${})",
                n + 1,
                n + 2,
                n + 3,
                n + 4,
                n + 5,
                n + 6
            ));
            values.extend([
                room.as_str().into(),
                session.as_str().into(),
                text.as_str().into(),
                new.1.into(),
                new.2.into(),
                i64::from(new.0).into(),
            ]);
        }
        tx.execute(
            &format!("INSERT INTO chat_backup_keys (user_id, version, room, session, data, first_index, forwarded, verified) VALUES {} ON CONFLICT (user_id, version, room, session) DO UPDATE SET data = excluded.data, first_index = excluded.first_index, forwarded = excluded.forwarded, verified = excluded.verified", rows.join(", ")),
            &values,
        )
        .await?;
    }
    if changed > 0 {
        tx.execute(
            "UPDATE chat_backup_versions SET etag = etag + 1 WHERE user_id = $1 AND version = $2",
            &[me.id.as_str().into(), version.into()],
        )
        .await?;
    }
    tx.commit().await?;
    let after = current_version(s, &me.id)
        .await?
        .ok_or_else(|| ApiError::not_found("Not there."))?;
    Ok(ok(&version_json(s, &me.id, after).await?))
}

async fn get_keys(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let version: i64 = crate::api::query(request, "version")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad("Which backup version: ?version="))?;
    let rows = instance
        .store
        .query(
            "SELECT room, session, data, first_index, forwarded, verified FROM chat_backup_keys WHERE user_id = $1 AND version = $2",
            &[me.id.as_str().into(), version.into()],
        )
        .await?;
    let mut rooms = Map::new();
    for r in &rows {
        let (Some(room), Some(session), Some(data)) = (r.text(0), r.text(1), r.text(2)) else {
            continue;
        };
        let entry = rooms
            .entry(room.to_string())
            .or_insert_with(|| json!({"sessions": {}}));
        entry["sessions"][session] = json!({
            "session_data": serde_json::from_str::<Value>(data).unwrap_or(Value::Null),
            "first_message_index": r.int(3), "forwarded_count": r.int(4), "is_verified": r.int(5).unwrap_or(0) != 0,
        });
    }
    Ok(ok(&json!({"rooms": rooms})))
}

// ---- verification messages -------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Verification {
    /// The person's Matrix id.
    user: String,
    /// One of their devices, or "*" for all of them (a request).
    device: String,
    from_device: String,
    #[serde(rename = "type")]
    kind: String,
    content: Value,
}

/// Someone's devices' keys and master key, for verifying them (oneself, or
/// someone one shares a room with), with the viewer's signatures on them.
async fn get_keys_of(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let server = store::server_name(instance);
    let user = crate::api::query(request, "user")
        .and_then(|u| {
            u.strip_prefix('@')
                .and_then(|r| r.strip_suffix(&format!(":{server}")))
                .map(str::to_string)
        })
        .ok_or_else(|| bad("Whose keys: ?user=@person:server"))?;
    let s = instance.store.as_ref();
    if user != me.id && !shares_room(s, &me.id, &user).await? {
        return Err(ApiError::forbidden());
    }
    let mut devices: Vec<Value> = s
        .query("SELECT device, keys FROM chat_devices WHERE user_id = $1 ORDER BY created_at", &[user.as_str().into()])
        .await?
        .iter()
        .map(|r| json!({"device": r.text(0), "deviceKeys": serde_json::from_str::<Value>(r.text(1).unwrap_or("null")).unwrap_or(Value::Null), "userId": user}))
        .collect();
    let cross_signing = for_devices(
        instance,
        &me.id,
        &[user.clone(), me.id.clone()],
        &mut devices,
    )
    .await;
    Ok(ok(
        &json!({"devices": devices, "crossSigning": cross_signing}),
    ))
}

async fn shares_room(s: &dyn AsyncStore, a: &str, b: &str) -> Result<bool, ApiError> {
    Ok(!s
        .query(
            "SELECT 1 FROM chat_members x JOIN chat_members y ON x.room = y.room WHERE x.user_id = $1 AND y.user_id = $2 AND x.state IN ('join', 'invite') AND y.state IN ('join', 'invite') LIMIT 1",
            &[a.into(), b.into()],
        )
        .await?
        .is_empty())
}

/// A verification message (m.key.verification.*) to one's own devices, or
/// to someone one shares a room with: not sealed (Matrix's way), carried
/// with its type, under the same allowance per sender as room keys.
async fn post_verification(
    request: &Request,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let input: Verification = body(request)?;
    crate::e2e::my_device(instance, &me.id, &input.from_device).await?;
    let text = input.content.to_string();
    if !input.kind.starts_with("m.key.verification.")
        || input.kind.len() > 64
        || !input.content.is_object()
        || text.len() > 16 * 1024
    {
        return Err(bad(
            "A verification message is an m.key.verification.* object of at most 16 KB.",
        ));
    }
    let server = store::server_name(instance);
    let user = input
        .user
        .strip_prefix('@')
        .and_then(|r| r.strip_suffix(&format!(":{server}")))
        .ok_or_else(|| bad("Verification is with people of this server."))?
        .to_string();
    let s = instance.store.as_ref();
    if user != me.id && !shares_room(s, &me.id, &user).await? {
        return Err(ApiError::forbidden());
    }
    let devices: Vec<String> = s
        .query(
            "SELECT device FROM chat_devices WHERE user_id = $1",
            &[user.as_str().into()],
        )
        .await?
        .iter()
        .filter_map(|r| r.text(0).map(str::to_string))
        .filter(|d| input.device == "*" || *d == input.device)
        .filter(|d| !(user == me.id && *d == input.from_device))
        .collect();
    let sender = crate::e2e::me_mx(instance, &me.id);
    let wrapped =
        json!({"ortus.verification": {"type": input.kind, "content": input.content}}).to_string();
    let mut sent = 0;
    for device in &devices {
        let pending = s
            .query(
                "SELECT COUNT(*) FROM chat_to_device WHERE user_id = $1 AND device = $2 AND sender = $3",
                &[user.as_str().into(), device.as_str().into(), sender.as_str().into()],
            )
            .await?
            .first()
            .and_then(|r| r.int(0))
            .unwrap_or(0);
        if pending >= crate::e2e::MAX_PENDING_PER_SENDER {
            continue;
        }
        s.execute(
            "INSERT INTO chat_to_device (id, user_id, device, sender, sender_device, content, at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[format!("tv{}", ortus_core::auth::random_hex(12)).into(), user.as_str().into(), device.as_str().into(), sender.as_str().into(), input.from_device.as_str().into(), wrapped.as_str().into(), now().into()],
        )
        .await?;
        sent += 1;
    }
    Ok(ok(&json!({"sent": sent})))
}

// ---- the organisation's escrow ----------------------------------------------

/**
 * A person's escrow copy (their recovery key sealed to the organisation's
 * escrow key), for an administrator whose browser holds the escrow
 * private key: only the sealed copy leaves the server, and each time it
 * does is recorded.
 */
async fn get_escrow(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let session = ortus_core::auth::current(request, instance)
        .await
        .ok_or_else(ApiError::sign_in)?;
    let me = session.user.clone();
    if me.role < ortus_core::auth::accounts::Role::Admin {
        return Err(ApiError::forbidden());
    }
    let s = instance.store.as_ref();
    ortus_core::auth::step_up::require(s, &session).await?;
    let email = crate::api::query(request, "email").unwrap_or_default();
    let user = ortus_core::people::id_by_email(s, email.trim())
        .await?
        .ok_or_else(|| ApiError::not_found("Nobody here has that address."))?;
    let rows = s
        .query(
            "SELECT content FROM chat_account_data WHERE user_id = $1 AND kind = 'ortus.escrow'",
            &[user.as_str().into()],
        )
        .await?;
    let content = rows
        .first()
        .and_then(|r| r.text(0))
        .ok_or_else(|| ApiError::not_found("This person has no escrow copy: they have not set up recovery since the escrow key was made."))?;
    // Recorded before the copy leaves; unrecorded, it does not.
    let event =
        ortus_core::audit::Event::new("chat.escrow_copy_taken", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .on(&user);
    if let Err(e) = ortus_core::audit::record(s, &event, now()).await {
        eprintln!("ortus-chat: audit: could not record {}: {e}", event.action);
        return Err(ApiError::internal());
    }
    Ok(ok(
        &serde_json::from_str::<Value>(content).unwrap_or(Value::Null)
    ))
}

/// What the escrow object's signature covers: the organisation's escrow
/// key, for usage ortus.escrow, made by this administrator.
pub const ESCROW_USAGE: &str = "ortus.escrow";

/// An administrator's signed escrow object, checked: exactly user_id (the
/// caller), usage, an X25519 public key and the caller's current master
/// key's signature. Answers it as kept (that one signature) and its key.
pub async fn signed_escrow(
    instance: &Instance,
    user: &str,
    escrow: &Value,
) -> Result<(Value, String), ApiError> {
    let shape = || {
        bad("The escrow is {user_id, usage: [\"ortus.escrow\"], public_key, signatures}, signed by your master key.")
    };
    let owner = mx(instance, user);
    let obj = escrow.as_object().ok_or_else(shape)?;
    let mut fields: Vec<&str> = obj.keys().map(String::as_str).collect();
    fields.sort_unstable();
    if fields != ["public_key", "signatures", "usage", "user_id"]
        || obj["user_id"] != owner.as_str()
        || obj["usage"] != json!([ESCROW_USAGE])
    {
        return Err(shape());
    }
    let public = obj["public_key"].as_str().unwrap_or_default().to_string();
    if public.len() != 43
        || !public
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    {
        return Err(bad(
            "The escrow key is a Curve25519 public key (unpadded base64).",
        ));
    }
    let master = cross_key(instance.store.as_ref(), user, "master")
        .await?
        .and_then(|m| ed25519(&m))
        .ok_or_else(|| bad("Set up recovery first: the escrow is signed by your master key."))?;
    if !matrix::verify_json(escrow, &owner, &master.0, &master.1) {
        return Err(bad("The escrow is not signed by your current master key."));
    }
    let sig = escrow["signatures"][&owner][&master.0].clone();
    let kept = json!({"user_id": owner, "usage": [ESCROW_USAGE], "public_key": public, "signatures": { &owner: { &master.0: sig } }});
    Ok((kept, public))
}

/// A kept escrow object as served to `viewer`, with its signer's master key
/// (`signerMaster`: its signatures by the signer and by the viewer); None
/// when the signer's current master key does not verify it any more.
pub async fn served_escrow(
    instance: &Instance,
    signer: &str,
    escrow: &Value,
    viewer: &str,
) -> Option<Value> {
    let s = instance.store.as_ref();
    let owner = mx(instance, signer);
    let key = cross_key(s, signer, "master").await.ok().flatten()?;
    let (id, public) = ed25519(&key)?;
    if escrow["user_id"] != owner.as_str() || !matrix::verify_json(escrow, &owner, &id, &public) {
        return None;
    }
    let master = with_signatures(
        s,
        instance,
        served(&key, &owner, None),
        signer,
        &public,
        viewer,
    )
    .await;
    let mut out = escrow.clone();
    out["signerMaster"] = master;
    Some(out)
}

// ---- routes ---------------------------------------------------------------

macro_rules! handler {
    ($name:ident, $f:ident) => {
        fn $name(
            request: Request,
            _: PathParams,
            _: ConnectionInfo,
            instance: Arc<Instance>,
        ) -> BoxFuture<'static, Response> {
            Box::pin(async move { answer(&request, $f(&request, &instance).await) })
        }
    };
    ($name:ident, $f:ident, params) => {
        fn $name(
            request: Request,
            params: PathParams,
            _: ConnectionInfo,
            instance: Arc<Instance>,
        ) -> BoxFuture<'static, Response> {
            Box::pin(async move { answer(&request, $f(&request, &params, &instance).await) })
        }
    };
}

handler!(h_put_cross_signing, put_cross_signing);
handler!(h_post_signatures, post_signatures);
handler!(h_get_account_data, get_account_data, params);
handler!(h_put_account_data, put_account_data, params);
handler!(h_post_version, post_version);
handler!(h_get_version, get_version);
handler!(h_delete_version, delete_version, params);
handler!(h_put_keys, put_keys);
handler!(h_get_keys, get_keys);
handler!(h_get_escrow, get_escrow);
handler!(h_post_verification, post_verification);
handler!(h_get_keys_of, get_keys_of);

pub fn routes() -> Vec<Route> {
    let route = |method, path, id, summary, handler| Route {
        method,
        path,
        id,
        tag: "chat",
        summary,
        access: Access::Signed,
        response: crate::api::object,
        handler,
    };
    vec![
        route(Method::Put, "/chat/cross-signing", "chatCrossSigning", "My cross-signing keys: {master, selfSigning, userSigning}; a new master key needs a recent sign-in.", h_put_cross_signing),
        route(Method::Post, "/chat/signatures", "chatSignatures", "Signatures I made, checked before they are kept: {user: {keyId: signedObject}}.", h_post_signatures),
        route(Method::Get, "/chat/account-data/:type", "chatAccountData", "My account data of a type (secret storage, the escrow copy).", h_get_account_data),
        route(Method::Put, "/chat/account-data/:type", "chatAccountDataSet", "Sets my account data of a type: a JSON object of at most 64 KB.", h_put_account_data),
        route(Method::Post, "/chat/backup/version", "chatBackupNew", "A new room-key backup: {algorithm, authData}.", h_post_version),
        route(Method::Get, "/chat/backup/version", "chatBackup", "My current room-key backup, with how many keys it holds.", h_get_version),
        route(Method::Delete, "/chat/backup/version/:version", "chatBackupDelete", "Deletes a backup and its keys.", h_delete_version),
        route(Method::Put, "/chat/backup/keys", "chatBackupKeysSet", "Room keys into my current backup (?version=): {rooms: {room: {sessions: {id: keyData}}}}; a key is replaced only by a better copy.", h_put_keys),
        route(Method::Get, "/chat/backup/keys", "chatBackupKeys", "The room keys in a backup of mine (?version=).", h_get_keys),
        route(Method::Post, "/chat/verification", "chatVerification", "A verification message to my own devices or to someone I share a room with: {user, device (or *), fromDevice, type, content}.", h_post_verification),
        route(Method::Get, "/chat/keys", "chatKeysOf", "Someone's devices' keys and master key, for verifying them (?user=): oneself, or someone I share a room with.", h_get_keys_of),
        route(Method::Get, "/chat/admin/escrow", "chatEscrowCopy", "An administrator takes a person's escrow copy (?email=): their recovery key sealed to the organisation's escrow key; recorded.", h_get_escrow),
    ]
}
