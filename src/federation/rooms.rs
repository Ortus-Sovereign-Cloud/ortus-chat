//! A shared room as Matrix events (room version 10): its initial state
//! made when it is first shared, an event for each new message or member,
//! kept in `chat_pdus` with the room's current state in `chat_room_state`,
//! and sent to the other servers in the room from an outbox.

use ortus_core::instance::Instance;
use ortus_core::storage::AsyncStore;
use serde_json::{json, Value};

use crate::matrix;
use crate::store::{self, now, server_name, Room};

/// The room's latest events (the ones nothing follows yet), at most ten,
/// and the next depth.
async fn tips(s: &dyn AsyncStore, room: &str) -> Result<(Vec<String>, i64), String> {
    let rows = s
        .query("SELECT event_id, depth FROM chat_pdus WHERE room = $1 AND depth = (SELECT MAX(depth) FROM chat_pdus WHERE room = $1) LIMIT 10", &[room.into()])
        .await
        .map_err(|e| e.to_string())?;
    let depth = rows.first().and_then(|r| r.int(1)).unwrap_or(0);
    Ok((
        rows.iter()
            .filter_map(|r| r.text(0).map(str::to_string))
            .collect(),
        depth + 1,
    ))
}

async fn state_id(s: &dyn AsyncStore, room: &str, kind: &str, key: &str) -> Option<String> {
    s.query(
        "SELECT event_id FROM chat_room_state WHERE room = $1 AND kind = $2 AND state_key = $3",
        &[room.into(), kind.into(), key.into()],
    )
    .await
    .ok()?
    .first()
    .and_then(|r| r.text(0).map(str::to_string))
}

/// The auth events of a new event (room version 10 rules).
pub async fn auth_for(
    s: &dyn AsyncStore,
    room: &str,
    kind: &str,
    sender: &str,
    state_key: Option<&str>,
    membership: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    if kind == "m.room.create" {
        return out;
    }
    for (k, key) in [
        ("m.room.create", ""),
        ("m.room.power_levels", ""),
        ("m.room.member", sender),
    ] {
        if let Some(id) = state_id(s, room, k, key).await {
            out.push(id);
        }
    }
    if kind == "m.room.member" {
        if let Some(target) = state_key.filter(|t| *t != sender) {
            if let Some(id) = state_id(s, room, "m.room.member", target).await {
                out.push(id);
            }
        }
        if matches!(membership, Some("join") | Some("invite")) {
            if let Some(id) = state_id(s, room, "m.room.join_rules", "").await {
                out.push(id);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// A new event of ours, sealed; answers (id, event). Not stored yet.
pub async fn build(
    instance: &Instance,
    room: &Room,
    kind: &str,
    state_key: Option<&str>,
    sender: &str,
    content: Value,
) -> Result<(String, Value), String> {
    let s = instance.store.as_ref();
    let (prev, depth) = tips(s, &room.id).await?;
    let auth = auth_for(
        s,
        &room.id,
        kind,
        sender,
        state_key,
        content["membership"].as_str(),
    )
    .await;
    let mut event = json!({
        "type": kind, "room_id": room.room_id, "sender": sender, "content": content,
        "origin_server_ts": now(), "depth": depth, "prev_events": prev, "auth_events": auth,
    });
    if let Some(k) = state_key {
        event["state_key"] = json!(k);
    }
    let key = super::keys::ours(instance).await?;
    let id = matrix::seal_event(&mut event, &server_name(instance), &key);
    Ok((id, event))
}

/// Keeps an event (ours or a partner's) and, for state, the room's state.
pub async fn store(instance: &Instance, room: &str, id: &str, event: &Value) -> Result<(), String> {
    let s = instance.store.as_ref();
    let mut tx = s.begin().await.map_err(|e| e.to_string())?;
    let there = !tx
        .query("SELECT 1 FROM chat_pdus WHERE event_id = $1", &[id.into()])
        .await
        .map_err(|e| e.to_string())?
        .is_empty();
    if !there {
        tx.execute(
            "INSERT INTO chat_pdus (event_id, room, pdu, depth, kind, state_key, sender, received_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[id.into(), room.into(), event.to_string().into(), event["depth"].as_i64().unwrap_or(0).into(), event["type"].as_str().unwrap_or_default().into(), store::opt(event["state_key"].as_str()), event["sender"].as_str().unwrap_or_default().into(), now().into()],
        )
        .await
        .map_err(|e| e.to_string())?;
        if let Some(key) = event["state_key"].as_str() {
            let kind = event["type"].as_str().unwrap_or_default();
            tx.execute(
                "DELETE FROM chat_room_state WHERE room = $1 AND kind = $2 AND state_key = $3",
                &[room.into(), kind.into(), key.into()],
            )
            .await
            .map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO chat_room_state (room, kind, state_key, event_id) VALUES ($1, $2, $3, $4)", &[room.into(), kind.into(), key.into(), id.into()]).await.map_err(|e| e.to_string())?;
        }
    }
    tx.commit().await.map_err(|e| e.to_string())
}

/// Shares a room: its Matrix state is made once (create, the creator
/// joined, power levels, public join for partners, shared history, name,
/// the local members joined).
pub async fn share(instance: &Instance, room: &Room) -> Result<(), String> {
    let s = instance.store.as_ref();
    if state_id(s, &room.id, "m.room.create", "").await.is_some() {
        return Ok(());
    }
    let server = server_name(instance);
    let creator = store::mxid(&room.created_by, &server);
    let steps: Vec<(&str, Option<String>, Value)> = vec![
        (
            "m.room.create",
            Some(String::new()),
            json!({"creator": creator, "room_version": matrix::ROOM_VERSION}),
        ),
        (
            "m.room.member",
            Some(creator.clone()),
            json!({"membership": "join"}),
        ),
        (
            "m.room.power_levels",
            Some(String::new()),
            json!({"users": {creator.clone(): 100}, "users_default": 0, "events_default": 0, "state_default": 50, "ban": 50, "kick": 50, "redact": 50, "invite": 0, "events": {"m.room.name": 50, "m.room.power_levels": 100}}),
        ),
        (
            "m.room.join_rules",
            Some(String::new()),
            json!({"join_rule": if room.kind == "channel" { "public" } else { "invite" }}),
        ),
        (
            "m.room.history_visibility",
            Some(String::new()),
            json!({"history_visibility": "shared"}),
        ),
        (
            "m.room.name",
            Some(String::new()),
            json!({"name": room.name}),
        ),
    ];
    for (kind, key, content) in steps {
        let (id, ev) = build(instance, room, kind, key.as_deref(), &creator, content).await?;
        store(instance, &room.id, &id, &ev).await?;
    }
    for (member, user, state, _) in store::members(s, &room.id)
        .await
        .map_err(|e| e.to_string())?
    {
        if state == "join" && user.is_some() && member != creator {
            let (id, ev) = build(
                instance,
                room,
                "m.room.member",
                Some(&member),
                &member,
                json!({"membership": "join"}),
            )
            .await?;
            store(instance, &room.id, &id, &ev).await?;
        }
    }
    s.execute(
        "UPDATE chat_rooms SET federated = 1 WHERE id = $1",
        &[room.id.as_str().into()],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// The other servers in a room (from the members who are not ours).
pub async fn servers(instance: &Instance, room: &str) -> Vec<String> {
    let me = server_name(instance);
    let mut out: Vec<String> = store::members(instance.store.as_ref(), room)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, user, state, _)| user.is_none() && state == "join")
        .filter_map(|(m, _, _, _)| m.split_once(':').map(|(_, s)| s.to_string()))
        .filter(|s| *s != me)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Queues an event of ours to every other server in its room.
pub async fn queue(instance: &Instance, room: &str, id: &str) -> Result<(), String> {
    let s = instance.store.as_ref();
    let Some(r) = store::room(s, room).await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    for server in servers(instance, room).await {
        // The label decides at each send: a room relabelled so that it
        // may not go to this partner stops going there.
        if !super::may_share(instance, &r.created_by, &r, &server).await {
            continue;
        }
        s.execute(
            "INSERT INTO chat_fed_outbox (id, destination, event_id, attempts, next_at) VALUES ($1, $2, $3, 0, $4)",
            &[format!("o{}", ortus_core::auth::random_hex(10)).into(), server.as_str().into(), id.into(), now().into()],
        )
        .await
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// A local message in a shared room: its Matrix event, made before the
/// message is kept so both carry the same id.
pub async fn message_event(
    instance: &Instance,
    room: &Room,
    sender: &str,
    content: &Value,
) -> Result<Option<(String, Value)>, String> {
    if !super::enabled() || !room.federated {
        return Ok(None);
    }
    build(
        instance,
        room,
        "m.room.message",
        None,
        sender,
        content.clone(),
    )
    .await
    .map(Some)
}

/// After a local event is kept: its Matrix event is kept and sent.
pub async fn local_event(instance: &Instance, room: &str, event_id: &str) -> Result<(), String> {
    let s = instance.store.as_ref();
    let Some(r) = store::room(s, room).await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    if !r.federated {
        return Ok(());
    }
    if s.query(
        "SELECT 1 FROM chat_pdus WHERE event_id = $1",
        &[event_id.into()],
    )
    .await
    .map_err(|e| e.to_string())?
    .is_empty()
    {
        return Ok(());
    }
    queue(instance, room, event_id).await
}

/// A local person joins or leaves a shared room: their member event.
pub async fn membership(
    instance: &Instance,
    room: &Room,
    member: &str,
    state: &str,
) -> Result<(), String> {
    if !super::enabled() || !room.federated {
        return Ok(());
    }
    let (id, ev) = build(
        instance,
        room,
        "m.room.member",
        Some(member),
        member,
        json!({"membership": state}),
    )
    .await?;
    store(instance, &room.id, &id, &ev).await?;
    queue(instance, &room.id, &id).await
}

/// Sends what is due in the outbox, one transaction per server; failures
/// wait longer each time and give up after a day of tries.
pub async fn drain(instance: &Instance) -> Result<(), String> {
    if !super::enabled() {
        return Ok(());
    }
    let s = instance.store.as_ref();
    let due = s
        .query("SELECT id, destination, event_id, attempts FROM chat_fed_outbox WHERE next_at <= $1 ORDER BY next_at LIMIT 200", &[now().into()])
        .await
        .map_err(|e| e.to_string())?;
    let mut by_server: std::collections::BTreeMap<String, Vec<(String, String, i64)>> =
        Default::default();
    for r in due {
        by_server
            .entry(r.text(1).unwrap_or_default().to_string())
            .or_default()
            .push((
                r.text(0).unwrap_or_default().to_string(),
                r.text(2).unwrap_or_default().to_string(),
                r.int(3).unwrap_or(0),
            ));
    }
    for (server, items) in by_server {
        let mut pdus = Vec::new();
        for (_, event_id, _) in &items {
            if let Some(r) = s
                .query(
                    "SELECT pdu FROM chat_pdus WHERE event_id = $1",
                    &[event_id.as_str().into()],
                )
                .await
                .map_err(|e| e.to_string())?
                .first()
            {
                pdus.push(
                    serde_json::from_str::<Value>(r.text(0).unwrap_or("{}")).unwrap_or(Value::Null),
                );
            }
        }
        let txn = format!("{}{}", now(), ortus_core::auth::random_hex(4));
        let body = json!({"origin": server_name(instance), "origin_server_ts": now(), "pdus": pdus, "edus": []});
        let result = super::client::put_json(
            instance,
            &server,
            &format!("/_matrix/federation/v1/send/{txn}"),
            &body,
        )
        .await;
        for (id, _, attempts) in items {
            if result.is_ok() || attempts >= 20 {
                let _ = s
                    .execute(
                        "DELETE FROM chat_fed_outbox WHERE id = $1",
                        &[id.as_str().into()],
                    )
                    .await;
            } else {
                let wait = (5_000i64 << attempts.min(10)).min(3_600_000);
                let _ = s.execute("UPDATE chat_fed_outbox SET attempts = attempts + 1, next_at = $1 WHERE id = $2", &[(now() + wait).into(), id.as_str().into()]).await;
            }
        }
        if let Err(e) = result {
            eprintln!("chat: federation to {server}: {e}");
        }
    }
    Ok(())
}

/// A room's current state events and their auth chain (for a joining
/// server).
pub async fn state_and_chain(
    instance: &Instance,
    room: &str,
) -> Result<(Vec<Value>, Vec<Value>), String> {
    let s = instance.store.as_ref();
    let rows = s
        .query("SELECT p.pdu FROM chat_room_state st JOIN chat_pdus p ON p.event_id = st.event_id WHERE st.room = $1", &[room.into()])
        .await
        .map_err(|e| e.to_string())?;
    let state: Vec<Value> = rows
        .iter()
        .filter_map(|r| serde_json::from_str(r.text(0).unwrap_or("null")).ok())
        .collect();
    // The auth chain: every event the state's auth events reach.
    let mut seen = std::collections::BTreeSet::new();
    let mut queue: Vec<String> = state
        .iter()
        .flat_map(|e| e["auth_events"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let mut chain = Vec::new();
    while let Some(id) = queue.pop() {
        if !seen.insert(id.clone()) || seen.len() > 10_000 {
            continue;
        }
        if let Some(r) = s
            .query(
                "SELECT pdu FROM chat_pdus WHERE event_id = $1",
                &[id.as_str().into()],
            )
            .await
            .map_err(|e| e.to_string())?
            .first()
        {
            let ev: Value =
                serde_json::from_str(r.text(0).unwrap_or("null")).unwrap_or(Value::Null);
            queue.extend(
                ev["auth_events"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|v| v.as_str().map(str::to_string)),
            );
            chain.push(ev);
        }
    }
    Ok((state, chain))
}

/// Invites a partner's person into a shared room: the invitation, signed
/// by us, is countersigned by their server, then kept and told to the
/// room's other servers.
pub async fn invite_remote(
    instance: &Instance,
    room: &Room,
    sender: &str,
    target: &str,
) -> Result<(), String> {
    let server = target
        .rsplit_once(':')
        .map(|(_, s)| s.to_string())
        .ok_or("not a Matrix id")?;
    if !room.federated {
        return Err("the room is not shared".into());
    }
    if !super::may_share(instance, &room.created_by, room, &server).await {
        return Err(format!("this room may not be shared with {server}"));
    }
    let (id, event) = build(
        instance,
        room,
        "m.room.member",
        Some(target),
        sender,
        json!({"membership": "invite"}),
    )
    .await?;
    let s = instance.store.as_ref();
    let mut stripped = Vec::new();
    for kind in ["m.room.create", "m.room.join_rules", "m.room.name"] {
        if let Some(sid) = state_id(s, &room.id, kind, "").await {
            if let Some(r) = s
                .query(
                    "SELECT pdu FROM chat_pdus WHERE event_id = $1",
                    &[sid.as_str().into()],
                )
                .await
                .map_err(|e| e.to_string())?
                .first()
            {
                let ev: Value =
                    serde_json::from_str(r.text(0).unwrap_or("null")).unwrap_or(Value::Null);
                stripped.push(json!({"type": ev["type"], "state_key": ev["state_key"], "sender": ev["sender"], "content": ev["content"]}));
            }
        }
    }
    let path = format!(
        "/_matrix/federation/v2/invite/{}/{}",
        enc(&room.room_id),
        enc(&id)
    );
    let answer = super::client::put_json(instance, &server, &path, &json!({"event": event, "room_version": matrix::ROOM_VERSION, "invite_room_state": stripped})).await?;
    let signed = answer["event"].clone();
    if matrix::event_id(&signed) != id
        || !super::keys::check_event_from(instance, &signed, &server).await
    {
        return Err("the invitation came back changed or unsigned".into());
    }
    store(instance, &room.id, &id, &signed).await?;
    let mut tx = s.begin().await.map_err(|e| e.to_string())?;
    store::set_member(tx.as_mut(), &room.id, target, None, "invite", "member")
        .await
        .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    queue(instance, &room.id, &id).await
}

/// Percent-encodes a path segment.
pub fn enc(part: &str) -> String {
    part.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
