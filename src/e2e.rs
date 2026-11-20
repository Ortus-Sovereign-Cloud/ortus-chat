//! End-to-end rooms (when an administrator allows them), in Matrix's own
//! shapes, so browsers (web/src/olm.ts) and the phones (vodozemac) read
//! each other: each device has Curve25519 and Ed25519 identity keys
//! (signed device keys) and publishes signed one-time keys; a sender's
//! device shares its Megolm room session with each member's device over
//! Olm (to-device messages); messages are Megolm-sealed. The server keeps
//! only public keys, one-time keys until claimed, to-device messages until
//! read, and sealed messages. It indexes nothing of these rooms, records no
//! decisions in them, lets no app post into them, does not federate them,
//! and its legal hold does not keep their messages. docs/end-to-end.md has
//! the wire format.

use std::sync::Arc;

use ortus_core::api::{answer, body, ok, ApiError, Method, Route};
use ortus_core::auth::Access;
use ortus_core::instance::Instance;
use ortus_core::storage::{AsyncStore, BoxFuture, Migration};
use rust_web_server::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{joined, signed};
use crate::matrix;
use crate::store::{self, now, NewEvent};

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 5,
    name: "end-to-end rooms: device keys, one-time keys, to-device messages",
    sql: "CREATE TABLE chat_devices (
        user_id TEXT NOT NULL,
        device TEXT NOT NULL,
        keys TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, device)
    );
    CREATE TABLE chat_one_time_keys (
        user_id TEXT NOT NULL,
        device TEXT NOT NULL,
        key_id TEXT NOT NULL,
        key TEXT NOT NULL,
        PRIMARY KEY (user_id, device, key_id)
    );
    CREATE TABLE chat_to_device (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device TEXT NOT NULL,
        sender TEXT NOT NULL,
        sender_device TEXT NOT NULL,
        content TEXT NOT NULL,
        at BIGINT NOT NULL
    );
    CREATE INDEX chat_to_device_for ON chat_to_device (user_id, device, at)",
}];

pub const OLM: &str = "m.olm.v1.curve25519-aes-sha2";
pub const MEGOLM: &str = "m.megolm.v1.aes-sha2";
const MAX_DEVICES: usize = 10;
const MAX_ONE_TIME_KEYS: i64 = 100;
const MAX_SEALED: usize = 64 * 1024;

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn key32(v: &Value) -> Option<&str> {
    v.as_str()
        .filter(|k| matrix::unb64(k).is_some_and(|b| b.len() == 32))
}

fn b64ish(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

async fn encrypted_room(
    instance: &Instance,
    user: &str,
    id: &str,
) -> Result<store::Room, ApiError> {
    let room = joined(instance, user, id).await?;
    if !room.encrypted {
        return Err(ApiError::bad_request(
            "This room is not end-to-end encrypted.",
        ));
    }
    Ok(room)
}

fn me_mx(instance: &Instance, user: &str) -> String {
    store::mxid(user, &store::server_name(instance))
}

async fn one_time_count(s: &dyn AsyncStore, user: &str, device: &str) -> i64 {
    s.query(
        "SELECT COUNT(*) FROM chat_one_time_keys WHERE user_id = $1 AND device = $2",
        &[user.into(), device.into()],
    )
    .await
    .ok()
    .and_then(|r| r.first().and_then(|r| r.int(0)))
    .unwrap_or(0)
}

#[derive(Deserialize)]
struct Upload {
    #[serde(rename = "deviceKeys")]
    device_keys: Value,
    #[serde(rename = "oneTimeKeys", default)]
    one_time_keys: serde_json::Map<String, Value>,
}

/// A device of mine publishes its signed device keys (once; a device
/// keeps its keys) and signed one-time keys.
async fn put_device(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let device = params.get("device").unwrap_or_default();
    if !valid_id(device) {
        return Err(ApiError::bad_request(
            "A device id is letters, digits, - and _.",
        ));
    }
    let input: Upload = body(request)?;
    let mx = me_mx(instance, &me.id);
    let k = &input.device_keys;
    let curve = key32(&k["keys"][format!("curve25519:{device}")]);
    let ed = key32(&k["keys"][format!("ed25519:{device}")]).map(str::to_string);
    let algorithms = k["algorithms"].as_array().cloned().unwrap_or_default();
    let shaped = k["user_id"] == mx.as_str()
        && k["device_id"] == device
        && k["keys"].as_object().is_some_and(|o| o.len() == 2)
        && algorithms.iter().any(|a| a == OLM)
        && algorithms.iter().any(|a| a == MEGOLM)
        && curve.is_some()
        && ed
            .as_deref()
            .is_some_and(|ed| matrix::verify_json(k, &mx, &format!("ed25519:{device}"), ed));
    let Some(ed) = ed.filter(|_| shaped) else {
        return Err(ApiError::bad_request("Device keys are this person's and this device's, with Curve25519 and Ed25519 keys, signed by the device."));
    };
    // The signed fields as they were signed, nothing more.
    let kept = json!({"user_id": mx, "device_id": device, "algorithms": k["algorithms"], "keys": k["keys"], "signatures": {mx.clone(): {format!("ed25519:{device}"): k["signatures"][&mx][format!("ed25519:{device}")]}}});
    let s = instance.store.as_ref();
    let mine = s
        .query(
            "SELECT device, keys FROM chat_devices WHERE user_id = $1 ORDER BY created_at",
            &[me.id.as_str().into()],
        )
        .await?;
    match mine.iter().find(|r| r.text(0) == Some(device)) {
        Some(r) => {
            let had: Value =
                serde_json::from_str(r.text(1).unwrap_or("null")).unwrap_or(Value::Null);
            if had["keys"] != k["keys"] {
                return Err(ApiError {
                    status: 409,
                    code: "device_keys",
                    message: "This device already has other keys.".into(),
                });
            }
        }
        None => {
            if mine.len() >= MAX_DEVICES {
                // The oldest device makes way (a person's browsers come and go).
                let oldest = mine[0].text(0).unwrap_or_default().to_string();
                forget_device(s, &me.id, &oldest).await?;
            }
            s.execute(
                "INSERT INTO chat_devices (user_id, device, keys, created_at) VALUES ($1, $2, $3, $4)",
                &[me.id.as_str().into(), device.into(), kept.to_string().into(), now().into()],
            )
            .await?;
        }
    }
    let mut have = one_time_count(s, &me.id, device).await;
    for (id, key) in &input.one_time_keys {
        let Some(key_id) = id
            .strip_prefix("signed_curve25519:")
            .filter(|k| valid_id(k))
        else {
            return Err(ApiError::bad_request(
                "One-time keys are signed_curve25519.",
            ));
        };
        if key32(&key["key"]).is_none()
            || !matrix::verify_json(key, &mx, &format!("ed25519:{device}"), &ed)
        {
            return Err(ApiError::bad_request(
                "A one-time key is signed by its device.",
            ));
        }
        if have >= MAX_ONE_TIME_KEYS {
            break;
        }
        let one = json!({"key": key["key"], "signatures": key["signatures"]});
        let exists = !s
            .query("SELECT 1 FROM chat_one_time_keys WHERE user_id = $1 AND device = $2 AND key_id = $3", &[me.id.as_str().into(), device.into(), key_id.into()])
            .await?
            .is_empty();
        if exists {
            continue;
        }
        s.execute(
            "INSERT INTO chat_one_time_keys (user_id, device, key_id, key) VALUES ($1, $2, $3, $4)",
            &[
                me.id.as_str().into(),
                device.into(),
                key_id.into(),
                one.to_string().into(),
            ],
        )
        .await?;
        have += 1;
    }
    Ok(ok(
        &json!({"device": device, "oneTimeKeyCount": one_time_count(s, &me.id, device).await}),
    ))
}

async fn forget_device(s: &dyn AsyncStore, user: &str, device: &str) -> Result<(), ApiError> {
    for sql in [
        "DELETE FROM chat_devices WHERE user_id = $1 AND device = $2",
        "DELETE FROM chat_one_time_keys WHERE user_id = $1 AND device = $2",
        "DELETE FROM chat_to_device WHERE user_id = $1 AND device = $2",
    ] {
        s.execute(sql, &[user.into(), device.into()]).await?;
    }
    Ok(())
}

/// The members' (joined or invited) devices, with their signed keys.
async fn devices(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let rows = instance
        .store
        .query(
            "SELECT m.member, d.device, d.keys FROM chat_devices d JOIN chat_members m ON m.user_id = d.user_id AND m.room = $1 AND m.state IN ('join', 'invite') ORDER BY m.member, d.created_at",
            &[room.id.as_str().into()],
        )
        .await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| json!({"user": r.text(0), "device": r.text(1), "deviceKeys": serde_json::from_str::<Value>(r.text(2).unwrap_or("null")).unwrap_or(Value::Null)}))
        .collect();
    Ok(ok(&json!({"devices": list})))
}

/// The member (joined or invited) behind a Matrix id, with their user id.
async fn member_user(
    instance: &Instance,
    room: &str,
    mx: &str,
) -> Result<Option<String>, ApiError> {
    Ok(store::members(instance.store.as_ref(), room)
        .await?
        .into_iter()
        .find(|(m, _, st, _)| m == mx && (st == "join" || st == "invite"))
        .and_then(|(_, u, _, _)| u))
}

#[derive(Deserialize)]
struct Claim {
    devices: Vec<Target>,
}

#[derive(Deserialize)]
struct Target {
    user: String,
    device: String,
}

/// Takes one one-time key of each named member device (each key is given
/// out once).
async fn claim(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let input: Claim = body(request)?;
    if input.devices.len() > 200 {
        return Err(ApiError::bad_request("Too many devices at once."));
    }
    let s = instance.store.as_ref();
    let mut out = serde_json::Map::new();
    for t in &input.devices {
        let Some(user) = member_user(instance, &room.id, &t.user).await? else {
            continue;
        };
        // Two claims at once: the delete decides who has the key.
        for _ in 0..5 {
            let row = s
                .query("SELECT key_id, key FROM chat_one_time_keys WHERE user_id = $1 AND device = $2 ORDER BY key_id LIMIT 1", &[user.as_str().into(), t.device.as_str().into()])
                .await?;
            let Some(r) = row.first() else { break };
            let key_id = r.text(0).unwrap_or_default().to_string();
            let gone = s
                .execute("DELETE FROM chat_one_time_keys WHERE user_id = $1 AND device = $2 AND key_id = $3", &[user.as_str().into(), t.device.as_str().into(), key_id.as_str().into()])
                .await?;
            if gone == 1 {
                let key: Value =
                    serde_json::from_str(r.text(1).unwrap_or("null")).unwrap_or(Value::Null);
                let entry = out.entry(t.user.clone()).or_insert_with(|| json!({}));
                entry[&t.device] = json!({ format!("signed_curve25519:{key_id}"): key });
                break;
            }
        }
    }
    Ok(ok(&json!({"oneTimeKeys": out})))
}

#[derive(Deserialize)]
struct ToDevice {
    #[serde(rename = "fromDevice")]
    from_device: String,
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct Message {
    user: String,
    device: String,
    content: Value,
}

async fn my_device(instance: &Instance, user: &str, device: &str) -> Result<(), ApiError> {
    let found = !instance
        .store
        .query(
            "SELECT 1 FROM chat_devices WHERE user_id = $1 AND device = $2",
            &[user.into(), device.into()],
        )
        .await?
        .is_empty();
    if found {
        Ok(())
    } else {
        Err(ApiError::bad_request("Publish this device's keys first."))
    }
}

/// Olm messages from one of my devices to members' devices (a room key).
async fn send_to_device(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let input: ToDevice = body(request)?;
    my_device(instance, &me.id, &input.from_device).await?;
    if input.messages.len() > 500 {
        return Err(ApiError::bad_request("Too many messages at once."));
    }
    let s = instance.store.as_ref();
    let sender = me_mx(instance, &me.id);
    let mut sent = 0;
    for m in &input.messages {
        let c = &m.content;
        let shaped = c["algorithm"] == OLM
            && key32(&c["sender_key"]).is_some()
            && c["ciphertext"].as_object().is_some_and(|o| {
                o.len() == 1
                    && o.values().all(|v| {
                        matches!(v["type"].as_u64(), Some(0 | 1))
                            && v["body"].as_str().is_some_and(|b| b64ish(b, MAX_SEALED))
                    })
            });
        if !shaped {
            return Err(ApiError::bad_request(
                "A to-device message is one Olm message.",
            ));
        }
        let Some(user) = member_user(instance, &room.id, &m.user).await? else {
            continue;
        };
        let known = !s
            .query(
                "SELECT 1 FROM chat_devices WHERE user_id = $1 AND device = $2",
                &[user.as_str().into(), m.device.as_str().into()],
            )
            .await?
            .is_empty();
        if !known {
            continue;
        }
        let pending = s
            .query(
                "SELECT COUNT(*) FROM chat_to_device WHERE user_id = $1 AND device = $2",
                &[user.as_str().into(), m.device.as_str().into()],
            )
            .await?
            .first()
            .and_then(|r| r.int(0))
            .unwrap_or(0);
        if pending >= 1000 {
            continue;
        }
        s.execute(
            "INSERT INTO chat_to_device (id, user_id, device, sender, sender_device, content, at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[format!("td{}", ortus_core::auth::random_hex(12)).into(), user.as_str().into(), m.device.as_str().into(), sender.as_str().into(), input.from_device.as_str().into(), c.to_string().into(), now().into()],
        )
        .await?;
        sent += 1;
    }
    Ok(ok(&json!({"sent": sent})))
}

/// What waits for one of my devices, oldest first.
async fn inbox(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let device = params.get("device").unwrap_or_default();
    let rows = instance
        .store
        .query("SELECT id, sender, sender_device, content FROM chat_to_device WHERE user_id = $1 AND device = $2 ORDER BY at, id LIMIT 100", &[me.id.as_str().into(), device.into()])
        .await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| json!({"id": r.text(0), "sender": r.text(1), "senderDevice": r.text(2), "content": serde_json::from_str::<Value>(r.text(3).unwrap_or("null")).unwrap_or(Value::Null)}))
        .collect();
    Ok(ok(&json!({"messages": list})))
}

#[derive(Deserialize)]
struct Done {
    ids: Vec<String>,
}

/// Messages a device has taken in go.
async fn inbox_done(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let device = params.get("device").unwrap_or_default();
    let input: Done = body(request)?;
    for id in input.ids.iter().take(500) {
        instance
            .store
            .execute(
                "DELETE FROM chat_to_device WHERE id = $1 AND user_id = $2 AND device = $3",
                &[id.as_str().into(), me.id.as_str().into(), device.into()],
            )
            .await?;
    }
    Ok(ok(&json!({"done": input.ids.len().min(500)})))
}

#[derive(Deserialize)]
struct Sealed {
    algorithm: String,
    sender_key: String,
    ciphertext: String,
    session_id: String,
    device_id: String,
    thread: Option<String>,
}

/// A Megolm-sealed message: the server keeps it as it is, with no text.
async fn say_sealed(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let input: Sealed = body(request)?;
    if input.algorithm != MEGOLM
        || key32(&json!(input.sender_key)).is_none()
        || key32(&json!(input.session_id)).is_none()
        || !b64ish(&input.ciphertext, MAX_SEALED)
    {
        return Err(ApiError::bad_request(
            "A sealed message is one Megolm message.",
        ));
    }
    my_device(instance, &me.id, &input.device_id).await?;
    let s = instance.store.as_ref();
    let thread = match input.thread.as_deref() {
        Some(t) => {
            let root = store::event(s, t)
                .await?
                .ok_or_else(|| ApiError::not_found("There is no such message."))?;
            if root.room != room.id || root.thread_root.is_some() {
                return Err(ApiError::bad_request(
                    "A thread starts at a message of this room.",
                ));
            }
            Some(root.event_id)
        }
        None => None,
    };
    let sender = me_mx(instance, &me.id);
    let content = json!({
        "msgtype": "m.text", "body": "",
        "ortus.sealed": {"algorithm": MEGOLM, "sender_key": input.sender_key, "ciphertext": input.ciphertext, "session_id": input.session_id, "device_id": input.device_id},
    });
    let mut tx = s.begin().await?;
    let (_, event_id) = store::add_event(
        tx.as_mut(),
        &NewEvent {
            room: &room.id,
            event_id: None,
            sender: &sender,
            sender_user: Some(&me.id),
            kind: "m.room.message",
            thread_root: thread.as_deref(),
            body: "",
            content: &content,
            origin_ts: now(),
        },
    )
    .await?;
    tx.commit().await?;
    let e = store::event(s, &event_id)
        .await?
        .ok_or_else(ApiError::internal)?;
    Ok(ok(&store::event_json(&e, None, &[])))
}

crate::api::with_params!(h_put_device, put_device);
crate::api::with_params!(h_devices, devices);
crate::api::with_params!(h_claim, claim);
crate::api::with_params!(h_send_to_device, send_to_device);
crate::api::with_params!(h_inbox, inbox);
crate::api::with_params!(h_inbox_done, inbox_done);
crate::api::with_params!(h_say_sealed, say_sealed);

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
        route(Method::Put, "/chat/devices/:device", "chatDevice", "A device of mine publishes its signed device keys and one-time keys: {deviceKeys, oneTimeKeys}.", h_put_device),
        route(Method::Get, "/chat/devices/:device/inbox", "chatInbox", "Olm messages waiting for one of my devices.", h_inbox),
        route(Method::Post, "/chat/devices/:device/inbox/done", "chatInboxDone", "Messages a device has taken in: {ids}.", h_inbox_done),
        route(Method::Get, "/chat/rooms/:room/devices", "chatRoomDevices", "An end-to-end room's members' devices with their signed keys.", h_devices),
        route(Method::Post, "/chat/rooms/:room/claim", "chatClaimKeys", "Takes one one-time key of each member device: {devices: [{user, device}]}.", h_claim),
        route(Method::Post, "/chat/rooms/:room/to-device", "chatToDevice", "Olm messages to members' devices: {fromDevice, messages: [{user, device, content}]}.", h_send_to_device),
        route(Method::Post, "/chat/rooms/:room/sealed", "chatSaySealed", "A Megolm-sealed message: {algorithm, sender_key, ciphertext, session_id, device_id, thread}.", h_say_sealed),
    ]
}

/// A forgotten person's devices, keys and waiting messages go.
pub async fn forget(
    tx: &mut dyn ortus_core::storage::AsyncTx,
    user: &str,
) -> ortus_core::storage::StoreResult<()> {
    for sql in [
        "DELETE FROM chat_devices WHERE user_id = $1",
        "DELETE FROM chat_one_time_keys WHERE user_id = $1",
        "DELETE FROM chat_to_device WHERE user_id = $1",
    ] {
        tx.execute(sql, &[user.into()]).await?;
    }
    Ok(())
}
