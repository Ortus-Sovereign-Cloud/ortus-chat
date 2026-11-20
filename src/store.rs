//! The chat store. Rooms (channels, private channels, direct messages)
//! and their events are kept the way Matrix names them, so a room can be
//! shared with other servers: a room id `!…:server`, event ids `$…`,
//! people as `@…:server`. Messages are events of type `m.room.message`;
//! a thread is the events whose root is one message; a decision is a
//! message marked as one.

use ortus_core::storage::{AsyncStore, AsyncTx, Migration, Row, StoreResult, Value};
use serde_json::{json, Value as Json};

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "rooms, members, events, reactions, read markers, decisions",
    sql: "CREATE TABLE chat_rooms (
        id TEXT PRIMARY KEY,
        room_id TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        topic TEXT NOT NULL,
        label TEXT,
        created_by TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        federated BIGINT NOT NULL,
        encrypted BIGINT NOT NULL,
        last_seq BIGINT NOT NULL
    );
    CREATE TABLE chat_members (
        room TEXT NOT NULL,
        member TEXT NOT NULL,
        user_id TEXT,
        state TEXT NOT NULL,
        role TEXT NOT NULL,
        since BIGINT NOT NULL,
        PRIMARY KEY (room, member)
    );
    CREATE INDEX chat_members_user ON chat_members (user_id, state);
    CREATE TABLE chat_events (
        room TEXT NOT NULL,
        seq BIGINT NOT NULL,
        event_id TEXT NOT NULL UNIQUE,
        sender TEXT NOT NULL,
        sender_user TEXT,
        kind TEXT NOT NULL,
        thread_root TEXT,
        body TEXT NOT NULL,
        content TEXT NOT NULL,
        origin_ts BIGINT NOT NULL,
        edited_at BIGINT,
        deleted_at BIGINT,
        decision BIGINT,
        PRIMARY KEY (room, seq)
    );
    CREATE INDEX chat_events_thread ON chat_events (room, thread_root, seq);
    CREATE TABLE chat_reactions (
        event_id TEXT NOT NULL,
        member TEXT NOT NULL,
        reaction TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (event_id, member, reaction)
    );
    CREATE TABLE chat_reads (
        room TEXT NOT NULL,
        user_id TEXT NOT NULL,
        seq BIGINT NOT NULL,
        PRIMARY KEY (room, user_id)
    )",
}];

/// A message's text at most, in characters.
pub const MAX_TEXT: usize = 20_000;
/// People in one room at most.
pub const MAX_MEMBERS: i64 = 5000;

pub fn now() -> i64 {
    ortus_core::program::now_ms()
}

fn random(n: usize) -> String {
    ortus_core::auth::random_hex(n)
}

/// This server's name (the host people's and rooms' ids end in).
pub fn server_name(instance: &ortus_core::instance::Instance) -> String {
    // Set once, before the first room: every id carries it.
    if let Ok(name) = std::env::var("ORTUS_MATRIX_SERVER_NAME") {
        if !name.trim().is_empty() {
            return name.trim().to_ascii_lowercase();
        }
    }
    // The public host without its port (a port in the name would pin
    // federation to that port).
    let url = &instance.config.public_url;
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or_default();
    let host: String = match host.strip_prefix('[') {
        // An IPv6 address keeps its brackets.
        Some(rest) => rest
            .split_once(']')
            .map(|(ip, _)| format!("[{ip}]"))
            .unwrap_or_else(|| host.to_string()),
        None => match host.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                h.to_string()
            }
            _ => host.to_string(),
        },
    };
    if host.is_empty() {
        "localhost".into()
    } else {
        host.to_ascii_lowercase()
    }
}

/// A person of this server as Matrix names them.
pub fn mxid(user_id: &str, server: &str) -> String {
    format!("@{}:{server}", user_id.to_ascii_lowercase())
}

pub fn new_room_id(server: &str) -> String {
    format!("!{}:{server}", random(9))
}

pub fn new_event_id() -> String {
    format!("${}", random(16))
}

pub struct Room {
    pub id: String,
    pub room_id: String,
    pub kind: String,
    pub name: String,
    pub topic: String,
    pub label: Option<String>,
    pub created_by: String,
    pub federated: bool,
    pub encrypted: bool,
    pub last_seq: i64,
}

const ROOM: &str = "SELECT id, room_id, kind, name, topic, label, created_by, federated, encrypted, last_seq FROM chat_rooms";

fn room_of(r: &Row) -> Room {
    Room {
        id: r.text(0).unwrap_or_default().into(),
        room_id: r.text(1).unwrap_or_default().into(),
        kind: r.text(2).unwrap_or_default().into(),
        name: r.text(3).unwrap_or_default().into(),
        topic: r.text(4).unwrap_or_default().into(),
        label: r.text(5).map(str::to_string),
        created_by: r.text(6).unwrap_or_default().into(),
        federated: r.int(7).unwrap_or(0) != 0,
        encrypted: r.int(8).unwrap_or(0) != 0,
        last_seq: r.int(9).unwrap_or(0),
    }
}

pub async fn room(s: &dyn AsyncStore, id: &str) -> StoreResult<Option<Room>> {
    Ok(s.query(&format!("{ROOM} WHERE id = $1"), &[id.into()])
        .await?
        .first()
        .map(room_of))
}

pub async fn room_by_matrix_id(s: &dyn AsyncStore, room_id: &str) -> StoreResult<Option<Room>> {
    Ok(
        s.query(&format!("{ROOM} WHERE room_id = $1"), &[room_id.into()])
            .await?
            .first()
            .map(room_of),
    )
}

/// A person's state in a room: join, invite, leave (or none).
pub async fn membership(
    s: &dyn AsyncStore,
    room: &str,
    user: &str,
) -> StoreResult<Option<(String, String)>> {
    Ok(s.query(
        "SELECT state, role FROM chat_members WHERE room = $1 AND user_id = $2",
        &[room.into(), user.into()],
    )
    .await?
    .first()
    .map(|r| {
        (
            r.text(0).unwrap_or_default().to_string(),
            r.text(1).unwrap_or_default().to_string(),
        )
    }))
}

/// Rooms someone has joined or is invited to, newest activity first.
pub async fn rooms_of(s: &dyn AsyncStore, user: &str) -> StoreResult<Vec<(Room, String, i64)>> {
    Ok(s
        .query(
            "SELECT r.id, r.room_id, r.kind, r.name, r.topic, r.label, r.created_by, r.federated, r.encrypted, r.last_seq, m.state, COALESCE(rd.seq, 0)
             FROM chat_rooms r JOIN chat_members m ON m.room = r.id
             LEFT JOIN chat_reads rd ON rd.room = r.id AND rd.user_id = m.user_id
             WHERE m.user_id = $1 AND m.state IN ('join', 'invite') ORDER BY r.last_seq DESC, r.name",
            &[user.into()],
        )
        .await?
        .iter()
        .map(|r| (room_of(r), r.text(10).unwrap_or_default().to_string(), r.int(11).unwrap_or(0)))
        .collect())
}

/// Public channels anyone in the organisation may join.
pub async fn directory(s: &dyn AsyncStore) -> StoreResult<Vec<Room>> {
    Ok(
        s.query(&format!("{ROOM} WHERE kind = 'channel' ORDER BY name"), &[])
            .await?
            .iter()
            .map(room_of)
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn create_room(
    tx: &mut dyn AsyncTx,
    server: &str,
    kind: &str,
    name: &str,
    topic: &str,
    label: Option<&str>,
    creator: &str,
    encrypted: bool,
) -> StoreResult<(String, String)> {
    let id = format!("c{}", random(10));
    let room_id = new_room_id(server);
    tx.execute(
        "INSERT INTO chat_rooms (id, room_id, kind, name, topic, label, created_by, created_at, federated, encrypted, last_seq) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, 0)",
        &[id.as_str().into(), room_id.as_str().into(), kind.into(), name.into(), topic.into(), opt(label), creator.into(), now().into(), i64::from(encrypted).into()],
    )
    .await?;
    Ok((id, room_id))
}

pub fn opt(v: Option<&str>) -> Value {
    v.map_or(Value::Null, Into::into)
}

/// Sets someone's membership (a local person: their user id too).
pub async fn set_member(
    tx: &mut dyn AsyncTx,
    room: &str,
    member: &str,
    user: Option<&str>,
    state: &str,
    role: &str,
) -> StoreResult<()> {
    tx.execute(
        "DELETE FROM chat_members WHERE room = $1 AND member = $2",
        &[room.into(), member.into()],
    )
    .await?;
    tx.execute(
        "INSERT INTO chat_members (room, member, user_id, state, role, since) VALUES ($1, $2, $3, $4, $5, $6)",
        &[room.into(), member.into(), opt(user), state.into(), role.into(), now().into()],
    )
    .await?;
    Ok(())
}

pub async fn members(
    s: &dyn AsyncStore,
    room: &str,
) -> StoreResult<Vec<(String, Option<String>, String, String)>> {
    Ok(s.query("SELECT member, user_id, state, role FROM chat_members WHERE room = $1 AND state IN ('join', 'invite') ORDER BY since", &[room.into()])
        .await?
        .iter()
        .map(|r| (r.text(0).unwrap_or_default().into(), r.text(1).map(str::to_string), r.text(2).unwrap_or_default().into(), r.text(3).unwrap_or_default().into()))
        .collect())
}

pub struct NewEvent<'a> {
    pub room: &'a str,
    pub event_id: Option<&'a str>,
    pub sender: &'a str,
    pub sender_user: Option<&'a str>,
    pub kind: &'a str,
    pub thread_root: Option<&'a str>,
    pub body: &'a str,
    pub content: &'a Json,
    pub origin_ts: i64,
}

/// Adds an event at the room's next place; answers (seq, event id).
pub async fn add_event(tx: &mut dyn AsyncTx, e: &NewEvent<'_>) -> StoreResult<(i64, String)> {
    // The room row is the lock: one writer at a time takes the next number.
    tx.execute(
        "UPDATE chat_rooms SET last_seq = last_seq + 1 WHERE id = $1",
        &[e.room.into()],
    )
    .await?;
    let seq = tx
        .query(
            "SELECT last_seq FROM chat_rooms WHERE id = $1",
            &[e.room.into()],
        )
        .await?
        .first()
        .and_then(|r| r.int(0))
        .unwrap_or(1);
    let event_id = e.event_id.map(str::to_string).unwrap_or_else(new_event_id);
    tx.execute(
        "INSERT INTO chat_events (room, seq, event_id, sender, sender_user, kind, thread_root, body, content, origin_ts) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[e.room.into(), seq.into(), event_id.as_str().into(), e.sender.into(), opt(e.sender_user), e.kind.into(), opt(e.thread_root), e.body.into(), e.content.to_string().into(), e.origin_ts.into()],
    )
    .await?;
    Ok((seq, event_id))
}

pub const EVENT: &str = "SELECT room, seq, event_id, sender, sender_user, kind, thread_root, body, content, origin_ts, edited_at, deleted_at, decision FROM chat_events";

pub struct Event {
    pub room: String,
    pub seq: i64,
    pub event_id: String,
    pub sender: String,
    pub sender_user: Option<String>,
    pub kind: String,
    pub thread_root: Option<String>,
    pub body: String,
    pub content: Json,
    pub origin_ts: i64,
    pub edited_at: Option<i64>,
    pub deleted_at: Option<i64>,
    pub decision: Option<i64>,
}

pub fn event_of(r: &Row) -> Event {
    Event {
        room: r.text(0).unwrap_or_default().into(),
        seq: r.int(1).unwrap_or(0),
        event_id: r.text(2).unwrap_or_default().into(),
        sender: r.text(3).unwrap_or_default().into(),
        sender_user: r.text(4).map(str::to_string),
        kind: r.text(5).unwrap_or_default().into(),
        thread_root: r.text(6).map(str::to_string),
        body: r.text(7).unwrap_or_default().into(),
        content: serde_json::from_str(r.text(8).unwrap_or("{}")).unwrap_or(Json::Null),
        origin_ts: r.int(9).unwrap_or(0),
        edited_at: r.int(10),
        deleted_at: r.int(11),
        decision: r.int(12),
    }
}

pub async fn event(s: &dyn AsyncStore, event_id: &str) -> StoreResult<Option<Event>> {
    Ok(
        s.query(&format!("{EVENT} WHERE event_id = $1"), &[event_id.into()])
            .await?
            .first()
            .map(event_of),
    )
}

/// A page of a room's top-level messages (or one thread's), newest last.
pub async fn page(
    s: &dyn AsyncStore,
    room: &str,
    thread: Option<&str>,
    before: Option<i64>,
    limit: i64,
) -> StoreResult<Vec<Event>> {
    let before = before.unwrap_or(i64::MAX);
    let rows = match thread {
        Some(root) => {
            s.query(
                &format!("{EVENT} WHERE room = $1 AND (thread_root = $2 OR event_id = $2) AND seq < $3 AND kind = 'm.room.message' ORDER BY seq DESC LIMIT $4"),
                &[room.into(), root.into(), before.into(), limit.into()],
            )
            .await?
        }
        None => {
            s.query(
                &format!("{EVENT} WHERE room = $1 AND thread_root IS NULL AND seq < $2 AND kind = 'm.room.message' ORDER BY seq DESC LIMIT $3"),
                &[room.into(), before.into(), limit.into()],
            )
            .await?
        }
    };
    let mut out: Vec<Event> = rows.iter().map(event_of).collect();
    out.reverse();
    Ok(out)
}

/// Events after `seq` in rooms the person is in (the live stream).
pub async fn since(
    s: &dyn AsyncStore,
    user: &str,
    room: &str,
    seq: i64,
) -> StoreResult<Vec<Event>> {
    let _ = user;
    Ok(s.query(
        &format!("{EVENT} WHERE room = $1 AND seq > $2 ORDER BY seq LIMIT 200"),
        &[room.into(), seq.into()],
    )
    .await?
    .iter()
    .map(event_of)
    .collect())
}

/// Replies per thread root, and the latest reply's time.
pub async fn thread_counts(
    s: &dyn AsyncStore,
    room: &str,
    roots: &[String],
) -> StoreResult<std::collections::HashMap<String, (i64, i64)>> {
    let mut out = std::collections::HashMap::new();
    for root in roots {
        if let Some(r) = s
            .query(
                "SELECT CAST(COUNT(*) AS BIGINT), CAST(COALESCE(MAX(origin_ts), 0) AS BIGINT) FROM chat_events WHERE room = $1 AND thread_root = $2 AND deleted_at IS NULL",
                &[room.into(), root.as_str().into()],
            )
            .await?
            .first()
        {
            let n = r.int(0).unwrap_or(0);
            if n > 0 {
                out.insert(root.clone(), (n, r.int(1).unwrap_or(0)));
            }
        }
    }
    Ok(out)
}

/// Reactions per event: (reaction, members).
pub async fn reactions(
    s: &dyn AsyncStore,
    ids: &[String],
) -> StoreResult<std::collections::HashMap<String, Vec<(String, Vec<String>)>>> {
    let mut out: std::collections::HashMap<String, Vec<(String, Vec<String>)>> =
        std::collections::HashMap::new();
    for id in ids {
        for r in s
            .query(
                "SELECT reaction, member FROM chat_reactions WHERE event_id = $1 ORDER BY at",
                &[id.as_str().into()],
            )
            .await?
        {
            let (k, m) = (
                r.text(0).unwrap_or_default().to_string(),
                r.text(1).unwrap_or_default().to_string(),
            );
            let list = out.entry(id.clone()).or_default();
            match list.iter_mut().find(|(x, _)| *x == k) {
                Some((_, who)) => who.push(m),
                None => list.push((k, vec![m])),
            }
        }
    }
    Ok(out)
}

pub fn event_json(
    e: &Event,
    threads: Option<(i64, i64)>,
    reactions: &[(String, Vec<String>)],
) -> Json {
    json!({
        "id": e.event_id, "room": e.room, "seq": e.seq, "sender": e.sender, "user": e.sender_user,
        "thread": e.thread_root,
        "text": if e.deleted_at.is_some() { "" } else { e.body.as_str() },
        "mentions": e.content["m.mentions"]["user_ids"],
        "at": e.origin_ts, "editedAt": e.edited_at, "deleted": e.deleted_at.is_some(),
        "decision": e.decision,
        "file": if e.deleted_at.is_some() { Json::Null } else { e.content["ortus.file"].clone() },
        "sealed": if e.deleted_at.is_some() { Json::Null } else { e.content["ortus.sealed"].clone() },
        "hook": e.content["ortus.hook"].clone(),
        "replies": threads.map(|t| t.0), "lastReply": threads.map(|t| t.1),
        "reactions": reactions.iter().map(|(k, who)| json!({"key": k, "who": who})).collect::<Vec<_>>(),
    })
}

/// Chat's retention: messages past the chat period go, unless their room
/// or their sender is on hold. A hold does not keep an end-to-end room's
/// messages (the organisation cannot read them).
pub async fn purge(tx: &mut dyn AsyncTx, rules: &ortus_core::retention::Rules) -> StoreResult<u64> {
    let Some(Some(days)) = rules.days.get("chat").copied() else {
        return Ok(0);
    };
    let before = rules.now - days * 86_400_000;
    let engine = crate::index::engine_of(tx).await;
    let mut n = 0;
    // Oldest first, a page at a time; messages kept by a hold stay in
    // place, so the next page starts after them.
    let mut kept = 0i64;
    for _ in 0..10 {
        let rows = tx
            .query("SELECT e.room, e.event_id, e.sender_user, e.origin_ts, r.encrypted FROM chat_events e JOIN chat_rooms r ON r.id = e.room WHERE e.origin_ts < $1 AND e.kind = 'm.room.message' ORDER BY e.origin_ts, e.event_id LIMIT 1000 OFFSET $2", &[before.into(), kept.into()])
            .await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            let (room, id, user, at) = (
                r.text(0).unwrap_or_default().to_string(),
                r.text(1).unwrap_or_default().to_string(),
                r.text(2).map(str::to_string),
                r.int(3).unwrap_or(0),
            );
            let people: Vec<&str> = user.iter().map(String::as_str).collect();
            let sealed = r.int(4).unwrap_or(0) != 0;
            let due = if sealed {
                rules.may_purge("chat", at, &[], None)
            } else {
                rules.may_purge("chat", at, &people, Some(&format!("chat:room:{room}")))
            };
            if !due {
                kept += 1;
                continue;
            }
            tx.execute(
                "DELETE FROM chat_reactions WHERE event_id = $1",
                &[id.as_str().into()],
            )
            .await?;
            tx.execute(
                "DELETE FROM chat_events WHERE event_id = $1",
                &[id.as_str().into()],
            )
            .await?;
            ortus_core::search::remove_in(tx, engine, "chat", &id).await?;
            crate::federation::rooms::redact_copy(tx, &id).await?;
            n += 1;
        }
    }
    Ok(n)
}

/// A person's account goes: their memberships, reactions and read
/// markers; their messages are emptied (a channel's thread stays readable
/// around them), unless the room is on hold.
pub async fn forget(
    tx: &mut dyn AsyncTx,
    user: &str,
    rules: &ortus_core::retention::Rules,
) -> StoreResult<()> {
    let rooms: Vec<String> = tx
        .query(
            "SELECT DISTINCT room FROM chat_events WHERE sender_user = $1",
            &[user.into()],
        )
        .await?
        .iter()
        .filter_map(|r| r.text(0).map(str::to_string))
        .collect();
    for room in rooms {
        let sealed = tx
            .query(
                "SELECT encrypted FROM chat_rooms WHERE id = $1",
                &[room.as_str().into()],
            )
            .await?
            .first()
            .and_then(|r| r.int(0))
            .unwrap_or(0)
            != 0;
        if !sealed && rules.held_channels.contains(&format!("chat:room:{room}")) {
            continue;
        }
        // Out of search and out of what partners can ask for.
        let engine = crate::index::engine_of(tx).await;
        let theirs: Vec<String> = tx
            .query(
                "SELECT event_id FROM chat_events WHERE room = $1 AND sender_user = $2",
                &[room.as_str().into(), user.into()],
            )
            .await?
            .iter()
            .filter_map(|r| r.text(0).map(str::to_string))
            .collect();
        for id in &theirs {
            ortus_core::search::remove_in(tx, engine, "chat", id).await?;
            crate::federation::rooms::redact_copy(tx, id).await?;
        }
        tx.execute(
            "UPDATE chat_events SET body = '', content = '{}', deleted_at = $1 WHERE room = $2 AND sender_user = $3",
            &[now().into(), room.as_str().into(), user.into()],
        )
        .await?;
    }
    // Their Matrix ids, to find their reactions.
    let ids: Vec<String> = tx
        .query(
            "SELECT DISTINCT member FROM chat_members WHERE user_id = $1",
            &[user.into()],
        )
        .await?
        .iter()
        .filter_map(|r| r.text(0).map(str::to_string))
        .collect();
    for id in ids {
        tx.execute(
            "DELETE FROM chat_reactions WHERE member = $1",
            &[id.as_str().into()],
        )
        .await?;
    }
    for sql in [
        "DELETE FROM chat_members WHERE user_id = $1",
        "DELETE FROM chat_reads WHERE user_id = $1",
    ] {
        tx.execute(sql, &[user.into()]).await?;
    }
    crate::e2e::forget(tx, user).await?;
    Ok(())
}
