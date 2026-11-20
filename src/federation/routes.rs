//! The server-server API this server answers: its keys and version, and
//! for the shared rooms it hosts: joins (make_join, send_join), incoming
//! transactions, and the events, state and history a partner asks for.
//! Every request but the key list must be signed by a partner allowed
//! chat; every room must be shared and its label must allow that partner.

use std::sync::Arc;

use ortus_core::instance::Instance;
use rust_web_server::prelude::*;
use serde_json::{json, Value};

use super::{client, keys, rooms};
use crate::matrix;
use crate::store::{self, now, server_name, NewEvent, Room};

fn json_response(
    status: &'static rust_web_server::response::StatusCodeReasonPhrase,
    body: &Value,
) -> Response {
    let headers = vec![rust_web_server::header::Header {
        name: "Content-Type".into(),
        value: "application/json".into(),
    }];
    let content = rust_web_server::range::Range::get_content_range(
        body.to_string().into_bytes(),
        "application/json".to_string(),
    );
    Response::get_response(status, Some(headers), Some(vec![content]))
}

fn ok(body: &Value) -> Response {
    json_response(STATUS_CODE_REASON_PHRASE.n200_ok, body)
}

fn error(
    status: &'static rust_web_server::response::StatusCodeReasonPhrase,
    code: &str,
    message: &str,
) -> Response {
    json_response(status, &json!({"errcode": code, "error": message}))
}

fn forbidden(message: &str) -> Response {
    error(
        STATUS_CODE_REASON_PHRASE.n403_forbidden,
        "M_FORBIDDEN",
        message,
    )
}

fn not_found() -> Response {
    error(
        STATUS_CODE_REASON_PHRASE.n404_not_found,
        "M_NOT_FOUND",
        "Not found",
    )
}

fn decode(part: &str) -> String {
    ortus_core::form::decode(part)
}

fn query(uri: &str, name: &str) -> Option<String> {
    uri.split_once('?')?.1.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then(|| decode(v))
    })
}

/// A shared room hosted here that `origin` may take part in.
#[allow(clippy::result_large_err)]
async fn room_for(instance: &Instance, room_id: &str, origin: &str) -> Result<Room, Response> {
    let room = store::room_by_matrix_id(instance.store.as_ref(), room_id)
        .await
        .ok()
        .flatten()
        .filter(|r| r.federated && !r.encrypted)
        .ok_or_else(not_found)?;
    if !super::may_share(instance, &room.created_by, &room, origin).await {
        return Err(forbidden("This room is not shared with your organisation."));
    }
    Ok(room)
}

pub async fn answer(instance: &Arc<Instance>, request: Request) -> Response {
    let uri = request.request_uri.clone();
    let path = uri.split('?').next().unwrap_or_default().to_string();
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let method = request.method.to_ascii_uppercase();
    // Unsigned: the key list and the version.
    match (method.as_str(), parts.as_slice()) {
        ("GET", ["_matrix", "key", "v2", "server", ..]) => {
            return match keys::server_keys(instance).await {
                Ok(doc) => ok(&doc),
                Err(_) => error(
                    STATUS_CODE_REASON_PHRASE.n500_internal_server_error,
                    "M_UNKNOWN",
                    "No key",
                ),
            };
        }
        ("GET", ["_matrix", "federation", "v1", "version"]) => {
            return ok(&json!({"server": {"name": "Ortus", "version": ortus_core::VERSION}}));
        }
        _ => {}
    }
    let body: Option<Value> = if request.body.as_bytes().is_empty() {
        None
    } else {
        serde_json::from_slice(request.body.as_bytes()).ok()
    };
    let auth = request
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("authorization"))
        .map(|h| h.value.to_string());
    let origin = match client::check_request(
        instance,
        &method,
        &uri,
        auth.as_deref(),
        body.as_ref(),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("chat: federation: refused {method} {path}: {e}");
            return error(
                STATUS_CODE_REASON_PHRASE.n401_unauthorized,
                "M_UNAUTHORIZED",
                "The request is not signed by a partner server.",
            );
        }
    };
    match (method.as_str(), parts.as_slice()) {
        ("GET", ["_matrix", "federation", "v1", "make_join", room_id, user_id]) => {
            make_join(instance, &decode(room_id), &decode(user_id), &origin).await
        }
        ("PUT", ["_matrix", "federation", "v2", "send_join", room_id, event_id]) => {
            send_join(
                instance,
                &decode(room_id),
                &decode(event_id),
                &origin,
                body.unwrap_or(Value::Null),
            )
            .await
        }
        ("PUT", ["_matrix", "federation", "v1", "send", txn]) => {
            transaction(instance, &origin, &decode(txn), body.unwrap_or(Value::Null)).await
        }
        ("GET", ["_matrix", "federation", "v1", "event", event_id]) => {
            event(instance, &decode(event_id), &origin).await
        }
        ("GET", ["_matrix", "federation", "v1", "state_ids", room_id]) => {
            state(instance, &decode(room_id), &origin, true).await
        }
        ("GET", ["_matrix", "federation", "v1", "state", room_id]) => {
            state(instance, &decode(room_id), &origin, false).await
        }
        ("GET", ["_matrix", "federation", "v1", "backfill", room_id]) => {
            backfill(instance, &decode(room_id), &origin, &uri).await
        }
        ("POST", ["_matrix", "federation", "v1", "get_missing_events", room_id]) => {
            missing(
                instance,
                &decode(room_id),
                &origin,
                body.unwrap_or(Value::Null),
            )
            .await
        }
        ("GET", ["_matrix", "federation", "v1", "query", "profile"]) => {
            profile(instance, &uri, &origin).await
        }
        _ => error(
            STATUS_CODE_REASON_PHRASE.n404_not_found,
            "M_UNRECOGNIZED",
            "Unrecognised request",
        ),
    }
}

async fn make_join(instance: &Instance, room_id: &str, user_id: &str, origin: &str) -> Response {
    if super::server_of(user_id) != Some(origin) {
        return forbidden("That person is not of your server.");
    }
    let room = match room_for(instance, room_id, origin).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !may_join(instance, &room, user_id).await {
        return forbidden("Only invited people join this room.");
    }
    let s = instance.store.as_ref();
    let auth = rooms::auth_for(
        s,
        &room.id,
        "m.room.member",
        user_id,
        Some(user_id),
        Some("join"),
    )
    .await;
    let tips = s
        .query("SELECT event_id, depth FROM chat_pdus WHERE room = $1 AND depth = (SELECT MAX(depth) FROM chat_pdus WHERE room = $1) LIMIT 10", &[room.id.as_str().into()])
        .await
        .unwrap_or_default();
    let depth = tips.first().and_then(|r| r.int(1)).unwrap_or(0) + 1;
    let prev: Vec<String> = tips
        .iter()
        .filter_map(|r| r.text(0).map(str::to_string))
        .collect();
    ok(&json!({
        "room_version": matrix::ROOM_VERSION,
        "event": {
            "type": "m.room.member", "room_id": room.room_id, "sender": user_id, "state_key": user_id,
            "content": {"membership": "join"}, "origin_server_ts": now(), "depth": depth,
            "prev_events": prev, "auth_events": auth,
        },
    }))
}

async fn send_join(
    instance: &Instance,
    room_id: &str,
    event_id: &str,
    origin: &str,
    event: Value,
) -> Response {
    let room = match room_for(instance, room_id, origin).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !may_join(
        instance,
        &room,
        event["sender"].as_str().unwrap_or_default(),
    )
    .await
    {
        return forbidden("Only invited people join this room.");
    }
    if store::members(instance.store.as_ref(), &room.id)
        .await
        .map(|m| m.len())
        .unwrap_or(usize::MAX)
        >= store::MAX_MEMBERS as usize
    {
        return forbidden("The room is full.");
    }
    let sender = event["sender"].as_str().unwrap_or_default().to_string();
    let good = event["type"] == "m.room.member"
        && event["content"]["membership"] == "join"
        && event["state_key"].as_str() == Some(sender.as_str())
        && event["room_id"].as_str() == Some(room_id)
        && super::server_of(&sender) == Some(origin)
        && matrix::event_id(&event) == event_id
        && keys::check_event_from(instance, &event, origin).await;
    if !good {
        return forbidden("That join is not valid.");
    }
    if let Err(e) = rooms::store(instance, &room.id, event_id, &event).await {
        return error(
            STATUS_CODE_REASON_PHRASE.n500_internal_server_error,
            "M_UNKNOWN",
            &e,
        );
    }
    joined(instance, &room, &sender, "join").await;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.partner_joined", ortus_core::audit::Outcome::Done)
            .by(&sender)
            .on(&room.id)
            .with(json!({"server": origin})),
    )
    .await;
    let _ = rooms::queue(instance, &room.id, event_id).await;
    let (state, chain) = rooms::state_and_chain(instance, &room.id)
        .await
        .unwrap_or_default();
    let mut servers = rooms::servers(instance, &room.id).await;
    servers.push(server_name(instance));
    ok(
        &json!({"origin": server_name(instance), "state": state, "auth_chain": chain, "event": event, "members_omitted": false, "servers_in_room": servers}),
    )
}

/// A partner's person joined or left: the room's members, and a notice
/// for open screens.
async fn joined(instance: &Instance, room: &Room, member: &str, state: &str) {
    let s = instance.store.as_ref();
    if let Ok(mut tx) = s.begin().await {
        let state = if state == "join" { "join" } else { "leave" };
        let _ = store::set_member(tx.as_mut(), &room.id, member, None, state, "member").await;
        let content = json!({"about": member});
        let _ = store::add_event(
            tx.as_mut(),
            &NewEvent {
                room: &room.id,
                event_id: None,
                sender: member,
                sender_user: None,
                kind: "m.room.member",
                thread_root: None,
                body: "",
                content: &content,
                origin_ts: now(),
            },
        )
        .await;
        let _ = tx.commit().await;
    }
}

/// A partner's transaction: each event checked and kept, once.
async fn transaction(instance: &Instance, origin: &str, txn: &str, body: Value) -> Response {
    let s = instance.store.as_ref();
    let seen = s
        .query(
            "SELECT 1 FROM chat_fed_txns WHERE origin = $1 AND txn_id = $2",
            &[origin.into(), txn.into()],
        )
        .await
        .map(|r| !r.is_empty())
        .unwrap_or(false);
    if seen {
        return ok(&json!({"pdus": {}}));
    }
    let pdus = body["pdus"].as_array().cloned().unwrap_or_default();
    if pdus.len() > 50 || body["edus"].as_array().is_some_and(|e| e.len() > 100) {
        return error(
            STATUS_CODE_REASON_PHRASE.n400_bad_request,
            "M_TOO_LARGE",
            "At most 50 events and 100 notices a transaction.",
        );
    }
    let mut results = serde_json::Map::new();
    for pdu in pdus {
        let id = matrix::event_id(&pdu);
        let outcome = match take(instance, origin, &id, &pdu).await {
            Ok(()) => json!({}),
            Err(e) => json!({"error": e}),
        };
        results.insert(id, outcome);
    }
    // Recorded once handled: a transaction that failed half way is taken
    // again when it is sent again (each event is kept once by its id).
    let _ = s
        .execute(
            "INSERT INTO chat_fed_txns (origin, txn_id, at) VALUES ($1, $2, $3)",
            &[origin.into(), txn.into(), now().into()],
        )
        .await;
    ok(&json!({"pdus": results}))
}

/// One event from a partner: theirs, signed, in a shared room they may be
/// in, from someone who is in it.
async fn take(instance: &Instance, origin: &str, id: &str, pdu: &Value) -> Result<(), String> {
    let room_id = pdu["room_id"].as_str().ok_or("no room")?;
    let room = room_for(instance, room_id, origin)
        .await
        .map_err(|_| "this room is not shared with you".to_string())?;
    // Matrix's limits: 64 KiB an event, integers within 2^53.
    if pdu.to_string().len() > 65_536 {
        return Err("the event is too big".into());
    }
    if !pdu["depth"]
        .as_i64()
        .is_some_and(|d| (0..=(1i64 << 53)).contains(&d))
    {
        return Err("the depth is not valid".into());
    }
    let sender = pdu["sender"].as_str().ok_or("no sender")?.to_string();
    if super::server_of(&sender) != Some(origin) {
        return Err("the sender is not of your server".into());
    }
    if !keys::check_event_from(instance, pdu, origin).await {
        return Err("the signature or hash does not hold".into());
    }
    let s = instance.store.as_ref();
    if !s
        .query("SELECT 1 FROM chat_pdus WHERE event_id = $1", &[id.into()])
        .await
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Ok(());
    }
    let kind = pdu["type"].as_str().unwrap_or_default();
    let member = store::members(s, &room.id)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .any(|(m, _, st, _)| m == sender && st == "join");
    if !member {
        return Err("the sender is not in the room".into());
    }
    // What a partner may send in a room Ortus hosts: messages, and leaving.
    // Joins come only through send_join (which checks invitations), and
    // partners change no other state (power levels, join rules, name).
    match (kind, pdu.get("state_key")) {
        ("m.room.message", None) => {
            let content = &pdu["content"];
            let body: String = content["body"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take(store::MAX_TEXT)
                .collect();
            // Only what Matrix says about a message: no Ortus fields
            // (files, sealed text) from outside.
            let mut kept = serde_json::Map::new();
            for key in [
                "msgtype",
                "body",
                "m.relates_to",
                "m.mentions",
                "format",
                "formatted_body",
            ] {
                if let Some(v) = content.get(key) {
                    kept.insert(key.to_string(), v.clone());
                }
            }
            let content = Value::Object(kept);
            // A thread root must be a message of this room.
            let mut thread = None;
            if content["m.relates_to"]["rel_type"] == "m.thread" {
                if let Some(root) = content["m.relates_to"]["event_id"].as_str() {
                    if let Ok(Some(e)) = store::event(s, root).await {
                        if e.room == room.id && e.thread_root.is_none() {
                            thread = Some(e.event_id);
                        }
                    }
                }
            }
            let ts = pdu["origin_server_ts"]
                .as_i64()
                .unwrap_or_else(now)
                .min(now() + 60_000);
            rooms::store(instance, &room.id, id, pdu).await?;
            let mut tx = s.begin().await.map_err(|e| e.to_string())?;
            store::add_event(
                tx.as_mut(),
                &NewEvent {
                    room: &room.id,
                    event_id: Some(id),
                    sender: &sender,
                    sender_user: None,
                    kind: "m.room.message",
                    thread_root: thread.as_deref(),
                    body: &body,
                    content: &content,
                    origin_ts: ts,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            tx.commit().await.map_err(|e| e.to_string())?;
            crate::index::message(instance, &room, id).await;
            Ok(())
        }
        ("m.room.member", Some(key))
            if key.as_str() == Some(sender.as_str()) && pdu["content"]["membership"] == "leave" =>
        {
            rooms::store(instance, &room.id, id, pdu).await?;
            joined(instance, &room, &sender, "leave").await;
            Ok(())
        }
        _ => Err("partners send messages and leave; nothing else is taken".into()),
    }
}

/// Whether `origin` has someone in the room (to read its events).
async fn in_room(instance: &Instance, room: &Room, origin: &str) -> bool {
    rooms::servers(instance, &room.id)
        .await
        .iter()
        .any(|s| s == origin)
}

async fn event(instance: &Instance, event_id: &str, origin: &str) -> Response {
    let s = instance.store.as_ref();
    let Some(r) = s
        .query(
            "SELECT room, pdu FROM chat_pdus WHERE event_id = $1",
            &[event_id.into()],
        )
        .await
        .ok()
        .and_then(|r| r.into_iter().next())
    else {
        return not_found();
    };
    let Ok(Some(room)) = store::room(s, r.text(0).unwrap_or_default()).await else {
        return not_found();
    };
    if !in_room(instance, &room, origin).await
        || room_for(instance, &room.room_id, origin).await.is_err()
    {
        return forbidden("Not in that room.");
    }
    let pdu: Value = serde_json::from_str(r.text(1).unwrap_or("null")).unwrap_or(Value::Null);
    ok(&json!({"origin": server_name(instance), "origin_server_ts": now(), "pdus": [pdu]}))
}

async fn state(instance: &Instance, room_id: &str, origin: &str, ids_only: bool) -> Response {
    let room = match room_for(instance, room_id, origin).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !in_room(instance, &room, origin).await {
        return forbidden("Not in that room.");
    }
    let (state, chain) = rooms::state_and_chain(instance, &room.id)
        .await
        .unwrap_or_default();
    if ids_only {
        let ids = |v: &[Value]| v.iter().map(matrix::event_id).collect::<Vec<_>>();
        ok(&json!({"pdu_ids": ids(&state), "auth_chain_ids": ids(&chain)}))
    } else {
        ok(&json!({"pdus": state, "auth_chain": chain}))
    }
}

async fn backfill(instance: &Instance, room_id: &str, origin: &str, uri: &str) -> Response {
    let room = match room_for(instance, room_id, origin).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !in_room(instance, &room, origin).await {
        return forbidden("Not in that room.");
    }
    let limit: i64 = query(uri, "limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(20)
        .clamp(1, 100);
    let from = query(uri, "v").unwrap_or_default();
    let s = instance.store.as_ref();
    let depth = s
        .query(
            "SELECT depth FROM chat_pdus WHERE event_id = $1",
            &[from.as_str().into()],
        )
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.int(0)))
        .unwrap_or(i64::MAX);
    let rows = s.query("SELECT pdu FROM chat_pdus WHERE room = $1 AND depth <= $2 ORDER BY depth DESC LIMIT $3", &[room.id.as_str().into(), depth.into(), limit.into()]).await.unwrap_or_default();
    let pdus: Vec<Value> = rows
        .iter()
        .filter_map(|r| serde_json::from_str(r.text(0).unwrap_or("null")).ok())
        .collect();
    ok(&json!({"origin": server_name(instance), "origin_server_ts": now(), "pdus": pdus}))
}

async fn missing(instance: &Instance, room_id: &str, origin: &str, body: Value) -> Response {
    let room = match room_for(instance, room_id, origin).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !in_room(instance, &room, origin).await {
        return forbidden("Not in that room.");
    }
    let limit = body["limit"].as_i64().unwrap_or(10).clamp(1, 50);
    let s = instance.store.as_ref();
    let mut low = 0;
    for id in body["earliest_events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .take(20)
    {
        if let Some(d) = s
            .query(
                "SELECT depth FROM chat_pdus WHERE event_id = $1",
                &[id.as_str().unwrap_or_default().into()],
            )
            .await
            .ok()
            .and_then(|r| r.first().and_then(|r| r.int(0)))
        {
            low = low.max(d);
        }
    }
    let rows = s
        .query(
            "SELECT pdu FROM chat_pdus WHERE room = $1 AND depth > $2 ORDER BY depth LIMIT $3",
            &[room.id.as_str().into(), low.into(), limit.into()],
        )
        .await
        .unwrap_or_default();
    let events: Vec<Value> = rows
        .iter()
        .filter_map(|r| serde_json::from_str(r.text(0).unwrap_or("null")).ok())
        .collect();
    ok(&json!({"events": events}))
}

/// A person's name, only for someone in a shared room with that server.
async fn profile(instance: &Instance, uri: &str, origin: &str) -> Response {
    let user = query(uri, "user_id").unwrap_or_default();
    let server = server_name(instance);
    let Some(local) = user
        .strip_prefix('@')
        .and_then(|u| u.strip_suffix(&format!(":{server}")))
    else {
        return not_found();
    };
    let s = instance.store.as_ref();
    let rooms = s
        .query("SELECT r.id FROM chat_members m JOIN chat_rooms r ON r.id = m.room WHERE m.user_id = $1 AND m.state = 'join' AND r.federated = 1", &[local.into()])
        .await
        .unwrap_or_default();
    let mut shared = false;
    for r in rooms {
        if rooms::servers(instance, r.text(0).unwrap_or_default())
            .await
            .iter()
            .any(|s| s == origin)
        {
            shared = true;
            break;
        }
    }
    if !shared {
        return not_found();
    }
    match ortus_core::auth::accounts::by_id(s, local).await {
        Ok(Some(u)) => ok(&json!({"displayname": u.name})),
        _ => not_found(),
    }
}

/// A channel is open to partners' people; a private channel only to
/// those invited.
async fn may_join(instance: &Instance, room: &Room, user: &str) -> bool {
    room.kind == "channel"
        || store::members(instance.store.as_ref(), &room.id)
            .await
            .unwrap_or_default()
            .iter()
            .any(|(m, _, state, _)| m == user && (state == "invite" || state == "join"))
}
