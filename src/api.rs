//! The chat API: rooms (channels anyone in the organisation may join,
//! private channels by invitation, direct messages), their messages and
//! threads, reactions, edits and deletions, read markers, decisions.

use std::sync::Arc;

use ortus_core::api::{answer, body, ok, ApiError, Method, Route};
use ortus_core::auth::accounts::{self, User};
use ortus_core::auth::Access;
use ortus_core::instance::Instance;
use ortus_core::storage::BoxFuture;
use rust_web_server::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::store::{self, now, NewEvent, Room};

pub(crate) async fn signed(request: &Request, instance: &Arc<Instance>) -> Result<User, ApiError> {
    Ok(ortus_core::auth::current(request, instance)
        .await
        .ok_or_else(ApiError::sign_in)?
        .user)
}

pub(crate) fn clean(text: &str, max: usize) -> String {
    text.trim()
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max)
        .collect()
}

/// A message's id from the path (event ids start with `$`, which
/// clients write as %24).
pub(crate) fn message_param(params: &PathParams) -> String {
    ortus_core::form::decode(params.get("message").unwrap_or_default())
}

pub(crate) fn query(request: &Request, name: &str) -> Option<String> {
    let q = request.request_uri.split_once('?')?.1;
    q.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then(|| ortus_core::form::decode(v))
    })
}

async fn colleague(instance: &Instance, email: &str) -> Result<User, ApiError> {
    accounts::by_email(instance.store.as_ref(), &email.trim().to_ascii_lowercase())
        .await?
        .filter(|u| u.state != accounts::State::Unverified)
        .ok_or_else(|| ApiError::bad_request(format!("{} is not a colleague.", email.trim())))
}

/// Names of the people a screen shows, by Matrix id.
pub(crate) async fn people(instance: &Instance, ids: impl IntoIterator<Item = String>) -> Value {
    let server = store::server_name(instance);
    let mut out = serde_json::Map::new();
    for id in ids {
        if out.contains_key(&id) {
            continue;
        }
        let local = id
            .strip_prefix('@')
            .and_then(|x| x.strip_suffix(&format!(":{server}")));
        let found = match local {
            Some(uid) => accounts::by_id(instance.store.as_ref(), uid)
                .await
                .ok()
                .flatten()
                .map(|u| json!({"name": u.name, "email": u.email, "local": true})),
            None => None,
        };
        // A hook's messages show its name.
        let found = match found {
            Some(f) => Some(f),
            None => crate::hooks::name_of(instance, &id)
                .await
                .map(|name| json!({"name": name, "local": true, "hook": true})),
        };
        out.insert(
            id.clone(),
            found.unwrap_or_else(|| json!({"name": id, "local": false})),
        );
    }
    Value::Object(out)
}

/// A room the person may read: joined, or a public channel.
pub(crate) async fn readable(
    instance: &Instance,
    user: &str,
    id: &str,
) -> Result<(Room, Option<String>), ApiError> {
    let s = instance.store.as_ref();
    let room = store::room(s, id)
        .await?
        .ok_or_else(|| ApiError::not_found("There is no such room."))?;
    let state = store::membership(s, id, user).await?.map(|m| m.0);
    if state.as_deref() == Some("join")
        || (room.kind == "channel" && state.as_deref() != Some("ban"))
    {
        Ok((room, state))
    } else {
        Err(ApiError::not_found("There is no such room."))
    }
}

/// A room the person has joined (to write in it).
pub(crate) async fn joined(instance: &Instance, user: &str, id: &str) -> Result<Room, ApiError> {
    let (room, state) = readable(instance, user, id).await?;
    if state.as_deref() == Some("join") {
        Ok(room)
    } else {
        Err(ApiError::forbidden())
    }
}

fn room_json(r: &Room, state: Option<&str>, unread: i64) -> Value {
    json!({
        "id": r.id, "roomId": r.room_id, "kind": r.kind, "name": r.name, "topic": r.topic, "label": r.label,
        "federated": r.federated, "encrypted": r.encrypted, "state": state, "unread": unread, "lastSeq": r.last_seq,
    })
}

async fn list(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let s = instance.store.as_ref();
    let mut rooms = Vec::new();
    for (room, state, read) in store::rooms_of(s, &me.id).await? {
        // Unread: messages by others after one's marker.
        let unread = s
            .query(
                "SELECT COUNT(*) FROM chat_events WHERE room = $1 AND seq > $2 AND kind = 'm.room.message' AND deleted_at IS NULL AND (sender_user IS NULL OR sender_user <> $3)",
                &[room.id.as_str().into(), read.into(), me.id.as_str().into()],
            )
            .await?
            .first()
            .and_then(|r| r.int(0))
            .unwrap_or(0);
        // A direct message is named after the other person.
        let mut v = room_json(&room, Some(&state), unread);
        if room.kind == "direct" {
            let others: Vec<String> = store::members(s, &room.id)
                .await?
                .into_iter()
                .filter(|m| m.1.as_deref() != Some(me.id.as_str()))
                .map(|m| m.0)
                .collect();
            v["with"] = json!(others);
        }
        rooms.push(v);
    }
    let mut ids = Vec::new();
    for r in &rooms {
        for w in r["with"].as_array().into_iter().flatten() {
            ids.push(w.as_str().unwrap_or_default().to_string());
        }
    }
    Ok(ok(
        &json!({ "rooms": rooms, "people": people(instance, ids).await, "me": store::mxid(&me.id, &store::server_name(instance)) }),
    ))
}

async fn directory(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    signed(request, instance).await?;
    let list: Vec<Value> = store::directory(instance.store.as_ref())
        .await?
        .iter()
        .map(|r| room_json(r, None, 0))
        .collect();
    Ok(ok(&json!({ "rooms": list })))
}

#[derive(Deserialize)]
struct NewRoom {
    #[serde(default)]
    name: String,
    #[serde(default)]
    topic: String,
    /// channel, private or direct.
    kind: String,
    #[serde(default)]
    members: Vec<String>,
    label: Option<String>,
    #[serde(default)]
    encrypted: bool,
}

async fn create(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let input: NewRoom = body(request)?;
    if !matches!(input.kind.as_str(), "channel" | "private" | "direct") {
        return Err(ApiError::bad_request(
            "A room is a channel, private or direct.",
        ));
    }
    let name = clean(input.name.trim_start_matches('#'), 80);
    if input.kind != "direct" && name.is_empty() {
        return Err(ApiError::bad_request("Give the channel a name."));
    }
    if input.members.len() as i64 > store::MAX_MEMBERS {
        return Err(ApiError::bad_request("Too many people."));
    }
    let mut others = Vec::new();
    for e in &input.members {
        let u = colleague(instance, e).await?;
        if u.id != me.id && !others.iter().any(|o: &User| o.id == u.id) {
            others.push(u);
        }
    }
    if input.kind == "direct" && others.len() != 1 {
        return Err(ApiError::bad_request(
            "A direct message is with one person.",
        ));
    }
    if input.encrypted && !crate::policy::encrypted_rooms_allowed(instance).await {
        return Err(ApiError {
            status: 403,
            code: "policy",
            message: "End-to-end rooms are not allowed here.".into(),
        });
    }
    let s = instance.store.as_ref();
    let server = store::server_name(instance);
    // One direct room per pair.
    if input.kind == "direct" {
        let other = &others[0];
        if let Some(r) = s
            .query(
                "SELECT r.id FROM chat_rooms r JOIN chat_members a ON a.room = r.id AND a.user_id = $1 JOIN chat_members b ON b.room = r.id AND b.user_id = $2 WHERE r.kind = 'direct'",
                &[me.id.as_str().into(), other.id.as_str().into()],
            )
            .await?
            .first()
        {
            let id = r.text(0).unwrap_or_default().to_string();
            return get_room_of(instance, &me, &id).await;
        }
    }
    let label = input
        .label
        .as_deref()
        .map(|l| clean(l, 60))
        .filter(|l| !l.is_empty());
    let mut tx = s.begin().await?;
    let (id, _) = store::create_room(
        tx.as_mut(),
        &server,
        &input.kind,
        &name,
        &clean(&input.topic, 500),
        label.as_deref(),
        &me.id,
        input.encrypted,
    )
    .await?;
    store::set_member(
        tx.as_mut(),
        &id,
        &store::mxid(&me.id, &server),
        Some(&me.id),
        "join",
        "owner",
    )
    .await?;
    for o in &others {
        // In a direct message both are in; others are invited.
        let state = if input.kind == "direct" {
            "join"
        } else {
            "invite"
        };
        store::set_member(
            tx.as_mut(),
            &id,
            &store::mxid(&o.id, &server),
            Some(&o.id),
            state,
            "member",
        )
        .await?;
    }
    tx.commit().await?;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.room_created", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .on(&id)
            .with(json!({"kind": input.kind, "name": name})),
    )
    .await;
    get_room_of(instance, &me, &id).await
}

async fn get_room_of(instance: &Instance, me: &User, id: &str) -> Result<Response, ApiError> {
    let (room, state) = readable(instance, &me.id, id).await?;
    let members = store::members(instance.store.as_ref(), &room.id).await?;
    let mut v = room_json(&room, state.as_deref(), 0);
    v["members"] = json!(members
        .iter()
        .map(|(m, _, st, role)| json!({"id": m, "state": st, "role": role}))
        .collect::<Vec<_>>());
    v["people"] = people(instance, members.into_iter().map(|m| m.0)).await;
    Ok(ok(&v))
}

async fn get_room(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    get_room_of(instance, &me, params.get("room").unwrap_or_default()).await
}

#[derive(Deserialize)]
struct RoomChange {
    name: Option<String>,
    topic: Option<String>,
    #[serde(default)]
    invite: Vec<String>,
}

async fn change_room(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    if room.kind == "direct" {
        return Err(ApiError::bad_request(
            "A direct message has no name or members to change.",
        ));
    }
    let input: RoomChange = body(request)?;
    let s = instance.store.as_ref();
    let server = store::server_name(instance);
    let mut invited = Vec::new();
    // People of partner servers, by their Matrix ids ("@bob:partner.example").
    let mut outside = Vec::new();
    for e in &input.invite {
        let e = e.trim();
        if e.starts_with('@') && e.split_once(':').is_some_and(|(_, host)| host != server) {
            if crate::federation::server_of(e).is_none() {
                return Err(ApiError::bad_request(
                    "That is not a Matrix id (@name:server).",
                ));
            }
            outside.push(e.to_ascii_lowercase());
        } else {
            invited.push(colleague(instance, e).await?);
        }
    }
    if !outside.is_empty() && !room.federated {
        return Err(ApiError::bad_request("Share the room with partners first."));
    }
    if store::members(s, &room.id).await?.len() + invited.len() + outside.len()
        > store::MAX_MEMBERS as usize
    {
        return Err(ApiError::bad_request("Too many people."));
    }
    let mut tx = s.begin().await?;
    if let Some(n) = input
        .name
        .as_deref()
        .map(|n| clean(n.trim_start_matches('#'), 80))
        .filter(|n| !n.is_empty())
    {
        tx.execute(
            "UPDATE chat_rooms SET name = $1 WHERE id = $2",
            &[n.as_str().into(), room.id.as_str().into()],
        )
        .await?;
    }
    if let Some(t) = input.topic.as_deref() {
        tx.execute(
            "UPDATE chat_rooms SET topic = $1 WHERE id = $2",
            &[clean(t, 500).into(), room.id.as_str().into()],
        )
        .await?;
    }
    // Who is newly invited (someone already in or invited is not again).
    let mut newly = Vec::new();
    for u in &invited {
        let current = tx
            .query(
                "SELECT state FROM chat_members WHERE room = $1 AND user_id = $2",
                &[room.id.as_str().into(), u.id.as_str().into()],
            )
            .await?;
        if !matches!(
            current.first().and_then(|r| r.text(0)),
            Some("join") | Some("invite")
        ) {
            newly.push(u.id.clone());
            store::set_member(
                tx.as_mut(),
                &room.id,
                &store::mxid(&u.id, &server),
                Some(&u.id),
                "invite",
                "member",
            )
            .await?;
        }
    }
    tx.commit().await?;
    // In a shared room a colleague's invitation is a Matrix event too (their
    // later join rests on it).
    for u in &newly {
        let _ = crate::federation::rooms::invite_local(
            instance,
            &room,
            &store::mxid(&me.id, &server),
            &store::mxid(u, &server),
        )
        .await;
    }
    for target in &outside {
        if let Err(e) = crate::federation::rooms::invite_remote(
            instance,
            &room,
            &store::mxid(&me.id, &server),
            target,
        )
        .await
        {
            return Err(ApiError {
                status: 409,
                code: "invite_refused",
                message: format!("{target} could not be invited: {e}"),
            });
        }
        ortus_core::auth::audit(
            instance,
            ortus_core::audit::Event::new("chat.partner_invited", ortus_core::audit::Outcome::Done)
                .by(&me.id)
                .on(&room.id)
                .with(json!({"who": target})),
        )
        .await;
    }
    get_room_of(instance, &me, &room.id).await
}

/// Joins a public channel, or accepts an invitation.
async fn join(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let id = params.get("room").unwrap_or_default();
    let s = instance.store.as_ref();
    let room = store::room(s, id)
        .await?
        .ok_or_else(|| ApiError::not_found("There is no such room."))?;
    let state = store::membership(s, id, &me.id).await?.map(|m| m.0);
    if room.kind != "channel"
        && state.as_deref() != Some("invite")
        && state.as_deref() != Some("join")
    {
        return Err(ApiError::not_found("There is no such room."));
    }
    let server = store::server_name(instance);
    let mut tx = s.begin().await?;
    store::set_member(
        tx.as_mut(),
        id,
        &store::mxid(&me.id, &server),
        Some(&me.id),
        "join",
        "member",
    )
    .await?;
    tx.commit().await?;
    notice(
        instance,
        id,
        "m.room.member",
        &store::mxid(&me.id, &server),
        &me.id,
    )
    .await?;
    if let Ok(Some(r)) = store::room(s, id).await {
        let _ = crate::federation::rooms::membership(
            instance,
            &r,
            &store::mxid(&me.id, &server),
            "join",
        )
        .await;
    }
    get_room_of(instance, &me, id).await
}

async fn leave(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let id = params.get("room").unwrap_or_default();
    let s = instance.store.as_ref();
    store::room(s, id)
        .await?
        .ok_or_else(|| ApiError::not_found("There is no such room."))?;
    // Only someone in the room (or invited to it) leaves it.
    let state = store::membership(s, id, &me.id).await?.map(|m| m.0);
    if !matches!(state.as_deref(), Some("join") | Some("invite")) {
        return Err(ApiError::not_found("There is no such room."));
    }
    let mut tx = s.begin().await?;
    tx.execute(
        "UPDATE chat_members SET state = 'leave' WHERE room = $1 AND user_id = $2",
        &[id.into(), me.id.as_str().into()],
    )
    .await?;
    tx.commit().await?;
    notice(
        instance,
        id,
        "m.room.member",
        &store::mxid(&me.id, &store::server_name(instance)),
        &me.id,
    )
    .await?;
    if let Ok(Some(r)) = store::room(s, id).await {
        let _ = crate::federation::rooms::membership(
            instance,
            &r,
            &store::mxid(&me.id, &store::server_name(instance)),
            "leave",
        )
        .await;
    }
    Ok(ok(&json!({ "left": id })))
}

/// A change to a message, as an event of the room, so that everyone's
/// open screens hear of it (the live stream sends the room's events).
pub(crate) async fn notice(
    instance: &Instance,
    room: &str,
    kind: &str,
    about: &str,
    user: &str,
) -> Result<(), ApiError> {
    let sender = store::mxid(user, &store::server_name(instance));
    let content = json!({"about": about});
    let mut tx = instance.store.begin().await?;
    store::add_event(
        tx.as_mut(),
        &NewEvent {
            room,
            event_id: None,
            sender: &sender,
            sender_user: Some(user),
            kind,
            thread_root: None,
            body: "",
            content: &content,
            origin_ts: now(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Shares a room with partner organisations (Matrix federation): its
/// owner or an administrator. Partners' people may then join it; the
/// room's label still decides, for each partner, whether it may.
async fn share(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let owner = store::membership(instance.store.as_ref(), &room.id, &me.id)
        .await?
        .is_some_and(|m| m.1 == "owner");
    if !owner && me.role < ortus_core::auth::accounts::Role::Admin {
        return Err(ApiError::forbidden());
    }
    if !crate::federation::enabled() {
        return Err(ApiError {
            status: 409,
            code: "federation_off",
            message: "Federation is not set up on this installation.".into(),
        });
    }
    if room.kind == "direct" || room.encrypted {
        return Err(ApiError::bad_request(
            "Direct and end-to-end rooms stay inside.",
        ));
    }
    crate::federation::rooms::share(instance, &room)
        .await
        .map_err(|_| ApiError::internal())?;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.room_shared", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .on(&room.id)
            .with(json!({"roomId": room.room_id})),
    )
    .await;
    get_room_of(instance, &me, &room.id).await
}

/// One message as the room shows it (after a change).
async fn message(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let s = instance.store.as_ref();
    let e = store::event(s, &message_param(params))
        .await?
        .filter(|e| e.kind == "m.room.message")
        .ok_or_else(|| ApiError::not_found("There is no such message."))?;
    readable(instance, &me.id, &e.room).await?;
    let ids = vec![e.event_id.clone()];
    let threads = store::thread_counts(s, &e.room, &ids).await?;
    let reactions = store::reactions(s, &ids).await?;
    Ok(ok(&store::event_json(
        &e,
        threads.get(&e.event_id).copied(),
        reactions.get(&e.event_id).map(Vec::as_slice).unwrap_or(&[]),
    )))
}

async fn messages(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let (room, _) = readable(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let thread = query(request, "thread");
    let before = query(request, "before").and_then(|b| b.parse().ok());
    let s = instance.store.as_ref();
    let list = store::page(s, &room.id, thread.as_deref(), before, 60).await?;
    let ids: Vec<String> = list.iter().map(|e| e.event_id.clone()).collect();
    let threads = if thread.is_none() {
        store::thread_counts(s, &room.id, &ids).await?
    } else {
        Default::default()
    };
    let reactions = store::reactions(s, &ids).await?;
    let senders: Vec<String> = list.iter().map(|e| e.sender.clone()).collect();
    let out: Vec<Value> = list
        .iter()
        .map(|e| {
            store::event_json(
                e,
                threads.get(&e.event_id).copied(),
                reactions.get(&e.event_id).map(Vec::as_slice).unwrap_or(&[]),
            )
        })
        .collect();
    Ok(ok(
        &json!({ "messages": out, "people": people(instance, senders).await }),
    ))
}

#[derive(Deserialize)]
struct Say {
    text: String,
    /// The message this answers in a thread.
    thread: Option<String>,
    /// Addresses of people mentioned.
    #[serde(default)]
    mentions: Vec<String>,
    /// The message records the thread's decision.
    #[serde(default)]
    decision: bool,
    /// A Drive file the message points to (by its id).
    file: Option<String>,
}

/// Sends a message as a person; also used by other apps (the Chat service).
pub(crate) async fn send(
    instance: &Instance,
    me: &User,
    room: &Room,
    text: &str,
    thread: Option<&str>,
    mentions: &[String],
) -> Result<Value, ApiError> {
    // Nothing readable goes into an end-to-end room (an app's post either).
    if room.encrypted {
        return Err(ApiError::bad_request(
            "This room is end-to-end encrypted: send through its encrypted route.",
        ));
    }
    let text = clean(text, store::MAX_TEXT);
    if text.is_empty() {
        return Err(ApiError::bad_request("Write something."));
    }
    let s = instance.store.as_ref();
    if let Some(root) = thread {
        // Threads hang off a top-level message of the same room.
        let root_event = store::event(s, root)
            .await?
            .filter(|e| e.room == room.id && e.thread_root.is_none())
            .ok_or_else(|| ApiError::bad_request("That thread is not in this room."))?;
        let _ = root_event;
    }
    let server = store::server_name(instance);
    let mut mentioned = Vec::new();
    let mut to_tell = Vec::new();
    for m in mentions.iter().take(50) {
        if let Ok(u) = colleague(instance, m).await {
            // Each person once, however often named.
            if to_tell.contains(&u.id) {
                continue;
            }
            mentioned.push(store::mxid(&u.id, &server));
            to_tell.push(u.id);
        }
    }
    let sender = store::mxid(&me.id, &server);
    let mut content =
        json!({"msgtype": "m.text", "body": text, "m.mentions": {"user_ids": mentioned}});
    if let Some(root) = thread {
        content["m.relates_to"] = json!({"rel_type": "m.thread", "event_id": root});
    }
    // In a shared room the message is a Matrix event first: both carry
    // its id.
    let federated = crate::federation::rooms::message_event(instance, room, &sender, &content)
        .await
        .map_err(|_| ApiError::internal())?;
    let mut tx = s.begin().await?;
    let (seq, event_id) = store::add_event(
        tx.as_mut(),
        &NewEvent {
            room: &room.id,
            event_id: federated.as_ref().map(|(id, _)| id.as_str()),
            sender: &sender,
            sender_user: Some(&me.id),
            kind: "m.room.message",
            thread_root: thread,
            body: &text,
            content: &content,
            origin_ts: now(),
        },
    )
    .await?;
    // Writing marks the room read up to here.
    tx.execute(
        "DELETE FROM chat_reads WHERE room = $1 AND user_id = $2",
        &[room.id.as_str().into(), me.id.as_str().into()],
    )
    .await?;
    tx.execute(
        "INSERT INTO chat_reads (room, user_id, seq) VALUES ($1, $2, $3)",
        &[room.id.as_str().into(), me.id.as_str().into(), seq.into()],
    )
    .await?;
    tx.commit().await?;
    // The people mentioned hear of it (if they are in the room).
    let members = store::members(s, &room.id).await.unwrap_or_default();
    for user in to_tell.iter().filter(|u| **u != me.id) {
        if !members
            .iter()
            .any(|(_, u, st, _)| u.as_deref() == Some(user.as_str()) && st == "join")
        {
            continue;
        }
        let place = if room.kind == "direct" {
            me.name.clone()
        } else {
            format!("#{}", room.name)
        };
        let notice = ortus_core::notify::Notice {
            app: "chat",
            kind: ortus_core::notify::Kind::Mention,
            title: &format!("{} mentioned you in {place}", me.name),
            detail: "",
            path: &format!("/chat?room={}&message={event_id}", room.id),
            key: Some("mention"),
            args: json!({"who": me.name, "where": place}),
        };
        let _ = ortus_core::notify::add(s, user, &notice).await;
    }
    crate::index::message(instance, room, &event_id).await;
    if let Some((id, pdu)) = &federated {
        let _ = crate::federation::rooms::store(instance, &room.id, id, pdu).await;
    }
    crate::federation::outbound(instance, &room.id, &event_id).await;
    let e = store::event(s, &event_id)
        .await?
        .ok_or_else(ApiError::internal)?;
    Ok(store::event_json(&e, None, &[]))
}

async fn say(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let input: Say = body(request)?;
    if room.encrypted {
        return Err(ApiError::bad_request(
            "This room is end-to-end encrypted: send through its encrypted route.",
        ));
    }
    if input.decision && input.thread.is_none() {
        return Err(ApiError::bad_request("A decision is recorded in a thread."));
    }
    // A Drive file goes as a link the sender can open (the drive decides
    // who else may).
    let file = match input.file.as_deref() {
        Some(id) => {
            let drive = instance
                .services
                .get::<dyn ortus_core::interfaces::Drive>(&instance.switches)
                .await
                .map_err(|_| ApiError::not_installed("drive"))?;
            let item = drive
                .describe(&me.id, id)
                .await
                .map_err(|_| ApiError::internal())?
                .ok_or_else(|| ApiError::not_found("There is no such file."))?;
            Some(json!({"id": item.id, "name": item.name, "mime": item.mime}))
        }
        None => None,
    };
    let text = if input.text.trim().is_empty() {
        file.as_ref()
            .map(|f| f["name"].as_str().unwrap_or_default().to_string())
            .unwrap_or_default()
    } else {
        input.text.clone()
    };
    let mut v = send(
        instance,
        &me,
        &room,
        &text,
        input.thread.as_deref(),
        &input.mentions,
    )
    .await?;
    if let Some(f) = file {
        let id = v["id"].as_str().unwrap_or_default().to_string();
        let s = instance.store.as_ref();
        if let Some(e) = store::event(s, &id).await? {
            let mut content = e.content.clone();
            content["ortus.file"] = f.clone();
            s.execute(
                "UPDATE chat_events SET content = $1 WHERE event_id = $2",
                &[content.to_string().into(), id.as_str().into()],
            )
            .await?;
        }
        v["file"] = f;
    }
    if input.decision {
        // Recorded: who and when, audited, and found in search.
        let id = v["id"].as_str().unwrap_or_default().to_string();
        let at = now();
        instance
            .store
            .execute(
                "UPDATE chat_events SET decision = $1 WHERE event_id = $2",
                &[at.into(), id.as_str().into()],
            )
            .await?;
        ortus_core::auth::audit(
            instance,
            ortus_core::audit::Event::new("chat.decision_recorded", ortus_core::audit::Outcome::Done)
                .by(&me.id)
                .on(&room.id)
                .with(json!({"message": id, "thread": input.thread, "text": input.text.chars().take(300).collect::<String>()})),
        )
        .await;
        v["decision"] = json!(at);
    }
    Ok(ok(&v))
}

/// A message the person sent (to edit or delete it), in a room they are in.
async fn own_message(instance: &Instance, me: &User, id: &str) -> Result<store::Event, ApiError> {
    let s = instance.store.as_ref();
    let e = store::event(s, id)
        .await?
        .ok_or_else(|| ApiError::not_found("There is no such message."))?;
    joined(instance, &me.id, &e.room).await?;
    if e.sender_user.as_deref() != Some(me.id.as_str()) {
        return Err(ApiError::forbidden());
    }
    if e.deleted_at.is_some() {
        return Err(ApiError::conflict("That message was deleted."));
    }
    if e.kind != "m.room.message" {
        return Err(ApiError::not_found("There is no such message."));
    }
    Ok(e)
}

#[derive(Deserialize)]
struct Edit {
    text: String,
}

async fn edit(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let e = own_message(instance, &me, &message_param(params)).await?;
    let room = store::room(instance.store.as_ref(), &e.room)
        .await?
        .ok_or_else(ApiError::internal)?;
    if room.encrypted {
        return Err(ApiError::bad_request(
            "A sealed message is not edited: delete it and send it again.",
        ));
    }
    let input: Edit = body(request)?;
    let text = clean(&input.text, store::MAX_TEXT);
    if text.is_empty() {
        return Err(ApiError::bad_request(
            "Write something, or delete the message.",
        ));
    }
    let mut content = e.content.clone();
    content["body"] = json!(text);
    instance
        .store
        .execute(
            "UPDATE chat_events SET body = $1, content = $2, edited_at = $3 WHERE event_id = $4",
            &[
                text.as_str().into(),
                content.to_string().into(),
                now().into(),
                e.event_id.as_str().into(),
            ],
        )
        .await?;
    notice(instance, &e.room, "ortus.edited", &e.event_id, &me.id).await?;
    crate::index::message(instance, &room, &e.event_id).await;
    let me_mx = store::mxid(&me.id, &store::server_name(instance));
    let _ = crate::federation::rooms::edited(instance, &room, &me_mx, &e.event_id, &text).await;
    let e = store::event(instance.store.as_ref(), &e.event_id)
        .await?
        .ok_or_else(ApiError::internal)?;
    Ok(ok(&store::event_json(&e, None, &[])))
}

async fn delete(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let e = own_message(instance, &me, &message_param(params)).await?;
    let s = instance.store.as_ref();
    let mut tx = s.begin().await?;
    tx.execute(
        "UPDATE chat_events SET body = '', content = '{}', deleted_at = $1 WHERE event_id = $2",
        &[now().into(), e.event_id.as_str().into()],
    )
    .await?;
    tx.execute(
        "DELETE FROM chat_reactions WHERE event_id = $1",
        &[e.event_id.as_str().into()],
    )
    .await?;
    ortus_core::search::remove_in(tx.as_mut(), s.engine(), "chat", &e.event_id).await?;
    tx.commit().await?;
    if let Some(room) = store::room(s, &e.room).await? {
        let me_mx = store::mxid(&me.id, &store::server_name(instance));
        let _ = crate::federation::rooms::deleted(instance, &room, &me_mx, &e.event_id).await;
    }
    notice(instance, &e.room, "m.room.redaction", &e.event_id, &me.id).await?;
    Ok(ok(&json!({ "deleted": e.event_id })))
}

#[derive(Deserialize)]
struct React {
    key: String,
}

async fn react(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let s = instance.store.as_ref();
    let e = store::event(s, &message_param(params))
        .await?
        .ok_or_else(|| ApiError::not_found("There is no such message."))?;
    joined(instance, &me.id, &e.room).await?;
    let input: React = body(request)?;
    let key: String = input
        .key
        .chars()
        .filter(|c| !c.is_control())
        .take(16)
        .collect();
    if key.trim().is_empty() || e.deleted_at.is_some() {
        return Err(ApiError::bad_request("Pick a reaction."));
    }
    let member = store::mxid(&me.id, &store::server_name(instance));
    let mut tx = s.begin().await?;
    // Choosing it again takes it back.
    let gone = tx
        .execute(
            "DELETE FROM chat_reactions WHERE event_id = $1 AND member = $2 AND reaction = $3",
            &[
                e.event_id.as_str().into(),
                member.as_str().into(),
                key.as_str().into(),
            ],
        )
        .await?;
    if gone == 0 {
        let count = tx
            .query(
                "SELECT COUNT(*) FROM chat_reactions WHERE event_id = $1 AND member = $2",
                &[e.event_id.as_str().into(), member.as_str().into()],
            )
            .await?
            .first()
            .and_then(|r| r.int(0))
            .unwrap_or(0);
        if count >= 20 {
            return Err(ApiError::bad_request("Too many reactions."));
        }
        tx.execute(
            "INSERT INTO chat_reactions (event_id, member, reaction, at) VALUES ($1, $2, $3, $4)",
            &[
                e.event_id.as_str().into(),
                member.as_str().into(),
                key.as_str().into(),
                now().into(),
            ],
        )
        .await?;
    }
    tx.commit().await?;
    // Others see reactions arrive.
    notice(instance, &e.room, "ortus.reactions", &e.event_id, &me.id).await?;
    let reactions = store::reactions(s, std::slice::from_ref(&e.event_id)).await?;
    Ok(ok(&store::event_json(
        &e,
        None,
        reactions.get(&e.event_id).map(Vec::as_slice).unwrap_or(&[]),
    )))
}

#[derive(Deserialize)]
struct Read {
    seq: i64,
}

async fn read(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let input: Read = body(request)?;
    let seq = input.seq.clamp(0, room.last_seq);
    let s = instance.store.as_ref();
    let mut tx = s.begin().await?;
    let current = tx
        .query(
            "SELECT seq FROM chat_reads WHERE room = $1 AND user_id = $2",
            &[room.id.as_str().into(), me.id.as_str().into()],
        )
        .await?
        .first()
        .and_then(|r| r.int(0))
        .unwrap_or(0);
    if seq > current {
        tx.execute(
            "DELETE FROM chat_reads WHERE room = $1 AND user_id = $2",
            &[room.id.as_str().into(), me.id.as_str().into()],
        )
        .await?;
        tx.execute(
            "INSERT INTO chat_reads (room, user_id, seq) VALUES ($1, $2, $3)",
            &[room.id.as_str().into(), me.id.as_str().into(), seq.into()],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(ok(&json!({ "read": seq.max(current) })))
}

macro_rules! plain {
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
}
macro_rules! with_params {
    ($name:ident, $f:ident) => {
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
pub(crate) use with_params;

plain!(h_list, list);
plain!(h_directory, directory);
plain!(h_create, create);
with_params!(h_room, get_room);
with_params!(h_change_room, change_room);
with_params!(h_join, join);
with_params!(h_leave, leave);
with_params!(h_messages, messages);
with_params!(h_say, say);
with_params!(h_edit, edit);
with_params!(h_delete, delete);
with_params!(h_react, react);
with_params!(h_read, read);
with_params!(h_message, message);
with_params!(h_share, share);

pub(crate) fn object() -> Value {
    json!({"type": "object"})
}

pub fn routes() -> Vec<Route> {
    let route = |method, path, id, summary, handler| Route {
        method,
        path,
        id,
        tag: "chat",
        summary,
        access: Access::Signed,
        response: object,
        handler,
    };
    vec![
        route(Method::Get, "/chat/rooms", "chatRooms", "One's rooms (joined or invited) with unread counts, newest activity first.", h_list as ortus_core::api::Handler),
        route(Method::Get, "/chat/directory", "chatDirectory", "The organisation's channels anyone may join.", h_directory),
        route(Method::Post, "/chat/rooms", "chatCreate", "A new room: {kind: channel|private|direct, name, topic, members: [address], label, encrypted}.", h_create),
        route(Method::Get, "/chat/rooms/:room", "chatRoom", "A room with its members.", h_room),
        route(Method::Patch, "/chat/rooms/:room", "chatRoomChange", "Renames a room, changes its topic, invites people by address.", h_change_room),
        route(Method::Post, "/chat/rooms/:room/join", "chatJoin", "Joins a channel, or accepts an invitation.", h_join),
        route(Method::Post, "/chat/rooms/:room/share", "chatShare", "Shares a room with partner organisations over Matrix (its owner or an administrator); partners' people may then join it by its room id.", h_share),
        route(Method::Post, "/chat/rooms/:room/leave", "chatLeave", "Leaves a room.", h_leave),
        route(Method::Get, "/chat/rooms/:room/messages", "chatMessages", "A page of messages (?before=seq), or one thread's (?thread=event).", h_messages),
        route(Method::Post, "/chat/rooms/:room/messages", "chatSend", "Sends a message: {text, thread, mentions: [address], decision (records the thread's decision)}.", h_say),
        route(Method::Get, "/chat/messages/:message", "chatMessage", "One message with its reactions and replies.", h_message),
        route(Method::Patch, "/chat/messages/:message", "chatEdit", "Edits one's message: {text}.", h_edit),
        route(Method::Delete, "/chat/messages/:message", "chatDelete", "Deletes one's message.", h_delete),
        route(Method::Post, "/chat/messages/:message/reactions", "chatReact", "Adds a reaction, or takes it back: {key}.", h_react),
        route(Method::Post, "/chat/rooms/:room/read", "chatRead", "Marks the room read up to {seq}.", h_read),
    ]
}
