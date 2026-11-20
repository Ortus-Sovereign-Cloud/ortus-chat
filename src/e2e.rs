//! End-to-end rooms (when an administrator allows them): the server keeps
//! only what it cannot read. Each device of a person has an ECDH P-256 key
//! made on the device (its private half never leaves it); a room key
//! (AES-256-GCM) is made by a member's device and wrapped for each
//! member's device; messages are sealed with it on the device. The server
//! stores devices' public keys, wrapped room keys and sealed messages; it
//! indexes nothing of these rooms, records no decisions in them, lets no
//! app post into them, does not federate them, and its legal hold does not
//! keep their messages. The wire format is in docs/end-to-end.md.

use std::sync::Arc;

use ortus_core::api::{answer, body, ok, ApiError, Method, Route};
use ortus_core::auth::Access;
use ortus_core::instance::Instance;
use ortus_core::storage::{BoxFuture, Migration};
use rust_web_server::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{joined, signed};
use crate::store::{self, now, NewEvent};

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 5,
    name: "end-to-end rooms: devices and wrapped room keys",
    sql: "CREATE TABLE chat_devices (
        user_id TEXT NOT NULL,
        device TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, device)
    );
    CREATE TABLE chat_room_keys (
        room TEXT NOT NULL,
        user_id TEXT NOT NULL,
        device TEXT NOT NULL,
        version BIGINT NOT NULL,
        wrapped TEXT NOT NULL,
        from_user TEXT NOT NULL,
        from_device TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (room, user_id, device, version)
    )",
}];

/// The algorithm messages and wrapped keys name.
pub const ALGORITHM: &str = "ortus.p256-aes-gcm.v1";
const MAX_DEVICES: usize = 10;
const MAX_SEALED: usize = 64 * 1024;

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn b64ish(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

/// A public key as a JWK: P-256, x and y only (never a private part).
fn public_jwk(v: &Value) -> Option<Value> {
    let (x, y) = (v["x"].as_str()?, v["y"].as_str()?);
    (v["kty"] == "EC"
        && v["crv"] == "P-256"
        && v.get("d").is_none()
        && b64ish(x, 64)
        && b64ish(y, 64))
    .then(|| json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
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

#[derive(Deserialize)]
struct Device {
    #[serde(rename = "publicKey")]
    public_key: Value,
}

/// A device of mine says its public key (once; a device keeps its key).
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
    let input: Device = body(request)?;
    let key = public_jwk(&input.public_key)
        .ok_or_else(|| ApiError::bad_request("A device key is a P-256 public key (JWK)."))?;
    let s = instance.store.as_ref();
    let mine = s
        .query(
            "SELECT device, public_key FROM chat_devices WHERE user_id = $1",
            &[me.id.as_str().into()],
        )
        .await?;
    if let Some(r) = mine.iter().find(|r| r.text(0) == Some(device)) {
        if r.text(1) != Some(key.to_string().as_str()) {
            return Err(ApiError {
                status: 409,
                code: "device_key",
                message: "This device already has another key.".into(),
            });
        }
        return Ok(ok(&json!({"device": device})));
    }
    if mine.len() >= MAX_DEVICES {
        // The oldest device makes way (a person's browsers come and go).
        s.execute(
            "DELETE FROM chat_devices WHERE user_id = $1 AND device = (SELECT device FROM chat_devices WHERE user_id = $1 ORDER BY created_at LIMIT 1)",
            &[me.id.as_str().into()],
        )
        .await?;
    }
    s.execute(
        "INSERT INTO chat_devices (user_id, device, public_key, created_at) VALUES ($1, $2, $3, $4)",
        &[me.id.as_str().into(), device.into(), key.to_string().into(), now().into()],
    )
    .await?;
    Ok(ok(&json!({"device": device})))
}

/// The devices of a room's members (joined or invited), each with the
/// room key versions it already has.
async fn devices(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let s = instance.store.as_ref();
    let rows = s
        .query(
            "SELECT d.user_id, d.device, d.public_key, m.member FROM chat_devices d JOIN chat_members m ON m.user_id = d.user_id AND m.room = $1 AND m.state IN ('join', 'invite') ORDER BY d.user_id, d.created_at",
            &[room.id.as_str().into()],
        )
        .await?;
    let have = s
        .query(
            "SELECT user_id, device, version FROM chat_room_keys WHERE room = $1",
            &[room.id.as_str().into()],
        )
        .await?;
    let latest = have.iter().filter_map(|r| r.int(2)).max().unwrap_or(0);
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            let (user, device) = (r.text(0).unwrap_or_default(), r.text(1).unwrap_or_default());
            let versions: Vec<i64> = have.iter().filter(|h| h.text(0) == Some(user) && h.text(1) == Some(device)).filter_map(|h| h.int(2)).collect();
            json!({"user": r.text(3), "device": device, "publicKey": serde_json::from_str::<Value>(r.text(2).unwrap_or("null")).unwrap_or(Value::Null), "versions": versions})
        })
        .collect();
    Ok(ok(
        &json!({"devices": list, "latest": latest, "algorithm": ALGORITHM}),
    ))
}

#[derive(Deserialize)]
struct Keys {
    #[serde(rename = "fromDevice")]
    from_device: String,
    keys: Vec<WrappedKey>,
}

#[derive(Deserialize)]
struct WrappedKey {
    /// The member's Matrix id.
    user: String,
    device: String,
    version: i64,
    wrapped: Value,
}

/// A member's device gives the room key to members' devices (wrapped for
/// each); a key already given stays as it is.
async fn give_keys(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let input: Keys = body(request)?;
    if input.keys.len() > 500 {
        return Err(ApiError::bad_request("Too many keys at once."));
    }
    let s = instance.store.as_ref();
    let mine = !s
        .query(
            "SELECT 1 FROM chat_devices WHERE user_id = $1 AND device = $2",
            &[me.id.as_str().into(), input.from_device.as_str().into()],
        )
        .await?
        .is_empty();
    if !mine {
        return Err(ApiError::bad_request("Say this device's key first."));
    }
    let members = store::members(s, &room.id).await?;
    let latest = s
        .query(
            "SELECT MAX(version) FROM chat_room_keys WHERE room = $1",
            &[room.id.as_str().into()],
        )
        .await?
        .first()
        .and_then(|r| r.int(0))
        .unwrap_or(0);
    let mut given = 0;
    let mut tx = s.begin().await?;
    for k in &input.keys {
        let w = &k.wrapped;
        let shaped = w["algorithm"] == ALGORITHM
            && public_jwk(&w["epk"]).is_some()
            && w["iv"].as_str().is_some_and(|v| b64ish(v, 32))
            && w["ciphertext"].as_str().is_some_and(|v| b64ish(v, 128));
        // A new version is at most one past the newest (a new key after a
        // member leaves); a member and a device of theirs.
        let Some(user) = members
            .iter()
            .find(|(m, _, st, _)| *m == k.user && (st == "join" || st == "invite"))
            .and_then(|(_, u, _, _)| u.clone())
        else {
            continue;
        };
        if !shaped || k.version < 1 || k.version > latest + 1 || !valid_id(&k.device) {
            return Err(ApiError::bad_request(
                "A wrapped key is not in the expected form.",
            ));
        }
        let exists = !tx
            .query(
                "SELECT 1 FROM chat_room_keys WHERE room = $1 AND user_id = $2 AND device = $3 AND version = $4",
                &[room.id.as_str().into(), user.as_str().into(), k.device.as_str().into(), k.version.into()],
            )
            .await?
            .is_empty();
        let device_known = !tx
            .query(
                "SELECT 1 FROM chat_devices WHERE user_id = $1 AND device = $2",
                &[user.as_str().into(), k.device.as_str().into()],
            )
            .await?
            .is_empty();
        if exists || !device_known {
            continue;
        }
        tx.execute(
            "INSERT INTO chat_room_keys (room, user_id, device, version, wrapped, from_user, from_device, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[room.id.as_str().into(), user.as_str().into(), k.device.as_str().into(), k.version.into(), w.to_string().into(), me.id.as_str().into(), input.from_device.as_str().into(), now().into()],
        )
        .await?;
        given += 1;
    }
    tx.commit().await?;
    Ok(ok(&json!({"given": given})))
}

/// The room keys given to one of my devices, with who gave them (their
/// device's public key, so the device can tell a key from a member).
async fn my_keys(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let device = params.get("device").unwrap_or_default();
    let rows = instance
        .store
        .query(
            "SELECT version, wrapped, from_user, from_device FROM chat_room_keys WHERE room = $1 AND user_id = $2 AND device = $3 ORDER BY version",
            &[room.id.as_str().into(), me.id.as_str().into(), device.into()],
        )
        .await?;
    let keys: Vec<Value> = rows
        .iter()
        .map(|r| json!({"version": r.int(0), "wrapped": serde_json::from_str::<Value>(r.text(1).unwrap_or("null")).unwrap_or(Value::Null), "fromUser": r.text(2), "fromDevice": r.text(3)}))
        .collect();
    Ok(ok(&json!({"keys": keys})))
}

#[derive(Deserialize)]
struct Sealed {
    version: i64,
    device: String,
    iv: String,
    ciphertext: String,
    thread: Option<String>,
}

/// A sealed message: the server keeps it as it is, with no text.
async fn say_sealed(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = encrypted_room(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let input: Sealed = body(request)?;
    if input.version < 1
        || !valid_id(&input.device)
        || !b64ish(&input.iv, 32)
        || !b64ish(&input.ciphertext, MAX_SEALED)
    {
        return Err(ApiError::bad_request(
            "A sealed message is not in the expected form.",
        ));
    }
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
    let sender = store::mxid(&me.id, &store::server_name(instance));
    let content = json!({
        "msgtype": "m.text", "body": "",
        "ortus.sealed": {"algorithm": ALGORITHM, "version": input.version, "device": input.device, "iv": input.iv, "ciphertext": input.ciphertext},
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
crate::api::with_params!(h_give_keys, give_keys);
crate::api::with_params!(h_my_keys, my_keys);
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
        route(Method::Put, "/chat/devices/:device", "chatDevice", "A device of mine says its end-to-end public key: {publicKey: P-256 JWK}.", h_put_device),
        route(Method::Get, "/chat/rooms/:room/devices", "chatRoomDevices", "An end-to-end room's members' devices and the room key versions each has.", h_devices),
        route(Method::Post, "/chat/rooms/:room/keys", "chatGiveKeys", "Gives the room key, wrapped for each device: {fromDevice, keys: [{user, device, version, wrapped}]}.", h_give_keys),
        route(Method::Get, "/chat/rooms/:room/keys/:device", "chatMyKeys", "The room keys given to one of my devices.", h_my_keys),
        route(Method::Post, "/chat/rooms/:room/sealed", "chatSaySealed", "A sealed message in an end-to-end room: {version, device, iv, ciphertext, thread}.", h_say_sealed),
    ]
}
