//! Live delivery: one stream per person (server-sent events) with the new
//! events of every room they are in, new rooms and invitations, and who
//! is typing. Read from the database, so it works on every node.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use ortus_core::api::{answer, ApiError, Method, Route};
use ortus_core::auth::Access;
use ortus_core::instance::Instance;
use ortus_core::storage::{BoxFuture, Migration};
use rust_web_server::prelude::*;
use rust_web_server::sse::{SseEvent, SseStream};
use serde_json::json;

use crate::store;

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 3,
    name: "who is typing",
    sql: "CREATE TABLE chat_typing (
        room TEXT NOT NULL,
        user_id TEXT NOT NULL,
        until BIGINT NOT NULL,
        PRIMARY KEY (room, user_id)
    )",
}];

/// With PostgreSQL, every program's live streams hear of a new event or
/// someone typing (`ortus_core::changes`), delivered when it commits.
pub const WAKE_MIGRATIONS: &[Migration] = &[Migration {
    version: 8,
    name: "wake live streams",
    sql: "{{postgres}} CREATE OR REPLACE FUNCTION chat_wake() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN PERFORM pg_notify(''ortus_changes'', ''chat''); RETURN NULL; END';
    {{postgres}} CREATE TRIGGER chat_events_wake AFTER INSERT OR UPDATE ON chat_events FOR EACH STATEMENT EXECUTE FUNCTION chat_wake();
    {{postgres}} CREATE TRIGGER chat_typing_wake AFTER INSERT OR DELETE ON chat_typing FOR EACH STATEMENT EXECUTE FUNCTION chat_wake();
    {{postgres}} CREATE TRIGGER chat_members_wake AFTER INSERT OR UPDATE ON chat_members FOR EACH STATEMENT EXECUTE FUNCTION chat_wake()",
}, Migration {
    version: 9,
    name: "messages sent again by their client id",
    sql: "CREATE TABLE chat_client_ids (
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (user_id, client_id)
    )",
}];

/// Streams open per person at most.
const MAX_STREAMS: usize = 10;

/// Each person's open streams, oldest first: (id, told to end).
type Streams = HashMap<String, Vec<(u64, Arc<AtomicBool>)>>;
static STREAMS: LazyLock<Mutex<Streams>> = LazyLock::new(Default::default);
static NEXT: AtomicU64 = AtomicU64::new(1);

/// One open stream of a person; it lets its place go when dropped.
struct Open {
    user: String,
    id: u64,
    ended: Arc<AtomicBool>,
}

impl Open {
    /// A place for a new stream. At the cap the person's oldest stream is
    /// told to end (a page closed a moment ago is still counted until its
    /// next ping fails): the window just opened is the one in use.
    fn take(user: &str) -> Open {
        let mut all = STREAMS.lock().unwrap_or_else(|e| e.into_inner());
        let mine = all.entry(user.to_string()).or_default();
        let live: Vec<_> = mine
            .iter()
            .filter(|(_, e)| !e.load(Ordering::Relaxed))
            .collect();
        if live.len() >= MAX_STREAMS {
            live[0].1.store(true, Ordering::Relaxed);
        }
        let open = Open {
            user: user.to_string(),
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            ended: Arc::new(AtomicBool::new(false)),
        };
        mine.push((open.id, Arc::clone(&open.ended)));
        open
    }

    /// Told to make way for a newer stream of the same person.
    fn ended(&self) -> bool {
        self.ended.load(Ordering::Relaxed)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        let mut all = STREAMS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mine) = all.get_mut(&self.user) {
            mine.retain(|(id, _)| *id != self.id);
            if mine.is_empty() {
                all.remove(&self.user);
            }
        }
    }
}

fn events(_request: &Request, instance: Arc<Instance>, user: String) -> Response {
    let open = Open::take(&user);
    let (sender, response) = SseStream::new().keep_alive(Duration::from_secs(15)).start();
    ortus_core::runtime::io().spawn(async move {
        let open = open;
        let started = store::now();
        let mut known: HashMap<String, i64> = HashMap::new();
        let mut typing_seen: HashMap<String, String> = HashMap::new();
        let mut first = true;
        let mut pinged = started;
        loop {
            if open.ended() {
                return;
            }
            let s = instance.store.as_ref();
            let rooms = match store::rooms_of(s, &user).await {
                Ok(r) => r,
                Err(e) => {
                    // A busy moment of the database: try again shortly.
                    eprintln!("chat: events of {user}: {e}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };
            for (room, state, _) in &rooms {
                let was = known.get(&room.id).copied();
                if was.is_none() {
                    // A room this stream did not know: on the first look the
                    // screen has just read it; found later (a new room, an
                    // invitation, or a slow loop), what happened since the
                    // stream began is still news.
                    let since = if first {
                        room.last_seq
                    } else {
                        s.query(
                            "SELECT CAST(COALESCE(MAX(seq), 0) AS BIGINT) FROM chat_events WHERE room = $1 AND origin_ts < $2",
                            &[room.id.as_str().into(), started.into()],
                        )
                        .await
                        .ok()
                        .and_then(|r| r.first().and_then(|r| r.int(0)))
                        .unwrap_or(room.last_seq)
                    };
                    known.insert(room.id.clone(), since);
                    if !first && sender.send_async(SseEvent::data(json!({"room": room.id, "state": state}).to_string()).event_type("room")).await.is_err() {
                        return;
                    }
                    if first || since >= room.last_seq {
                        continue;
                    }
                }
                let from = known.get(&room.id).copied().unwrap_or(0);
                if state == "join" && room.last_seq > from {
                    let list = match store::since(s, &user, &room.id, from).await {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("chat: events of {user} in {}: {e}", room.id);
                            continue;
                        }
                    };
                    for e in &list {
                        let data = json!({"room": room.id, "seq": e.seq, "id": e.event_id, "kind": e.kind, "thread": e.thread_root, "about": e.content["about"], "sender": e.sender});
                        if sender.send_async(SseEvent::data(data.to_string()).event_type("event")).await.is_err() {
                            return;
                        }
                        known.insert(room.id.clone(), e.seq);
                    }
                }
            }
            // Who is typing, per room, when it changes.
            if let Ok(rows) = s
                .query(
                    "SELECT t.room, t.user_id FROM chat_typing t JOIN chat_members m ON m.room = t.room AND m.user_id = $1 AND m.state = 'join' WHERE t.until > $2 AND t.user_id <> $1 ORDER BY t.room, t.user_id",
                    &[user.as_str().into(), store::now().into()],
                )
                .await
            {
                let mut now_typing: HashMap<String, Vec<String>> = HashMap::new();
                for r in rows {
                    now_typing.entry(r.text(0).unwrap_or_default().to_string()).or_default().push(r.text(1).unwrap_or_default().to_string());
                }
                let rooms_now: Vec<String> = now_typing.keys().cloned().chain(typing_seen.keys().cloned()).collect();
                for room in rooms_now {
                    let who = now_typing.get(&room).cloned().unwrap_or_default();
                    let key = who.join(",");
                    if typing_seen.get(&room) != Some(&key) {
                        let server = store::server_name(&instance);
                        let ids: Vec<String> = who.iter().map(|u| store::mxid(u, &server)).collect();
                        if sender.send_async(SseEvent::data(json!({"room": room, "who": ids}).to_string()).event_type("typing")).await.is_err() {
                            return;
                        }
                        if key.is_empty() {
                            typing_seen.remove(&room);
                        } else {
                            typing_seen.insert(room, key);
                        }
                    }
                }
            }
            first = false;
            if store::now() - pinged > 2_000 {
                pinged = store::now();
                if sender.comment("ping").is_err() {
                    return;
                }
            }
            if store::now() - started > 600_000 {
                return;
            }
            // Until something changes in chat (or a few seconds, for typing
            // that runs out on its own).
            ortus_core::changes::wait("chat", Duration::from_secs(3)).await;
        }
    });
    response
}

fn h_events(
    request: Request,
    _: PathParams,
    _: ConnectionInfo,
    instance: Arc<Instance>,
) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match crate::api::signed(&request, &instance).await {
            Ok(me) => events(&request, instance, me.id),
            Err(e) => answer(&request, Err::<Response, _>(e)),
        }
    })
}

async fn typing(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let room = crate::api::joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    let s = instance.store.as_ref();
    let mut tx = s.begin().await?;
    tx.execute(
        "DELETE FROM chat_typing WHERE (room = $1 AND user_id = $2) OR until < $3",
        &[
            room.id.as_str().into(),
            me.id.as_str().into(),
            (store::now() - 60_000).into(),
        ],
    )
    .await?;
    tx.execute(
        "INSERT INTO chat_typing (room, user_id, until) VALUES ($1, $2, $3)",
        &[
            room.id.as_str().into(),
            me.id.as_str().into(),
            (store::now() + 5_000).into(),
        ],
    )
    .await?;
    tx.commit().await?;
    ortus_core::changes::wake_soon("chat");
    Ok(ortus_core::api::ok(&json!({})))
}

crate::api::with_params!(h_typing, typing);

pub fn routes() -> Vec<Route> {
    vec![
        Route { method: Method::Get, path: "/chat/events", id: "chatEvents", tag: "chat", summary: "Server-sent events: `event` (a room's new event: message, reply, edit, deletion, reaction), `room` (a new room or invitation), `typing`.", access: Access::Signed, response: crate::api::object, handler: h_events },
        Route { method: Method::Post, path: "/chat/rooms/:room/typing", id: "chatTyping", tag: "chat", summary: "The person is typing in a room (for five seconds).", access: Access::Signed, response: crate::api::object, handler: h_typing },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_the_cap_the_oldest_stream_makes_way() {
        let user = "streams-test-user";
        let first: Vec<Open> = (0..MAX_STREAMS).map(|_| Open::take(user)).collect();
        assert!(first.iter().all(|o| !o.ended()), "room for ten");
        let newest = Open::take(user);
        assert!(first[0].ended(), "the oldest is told to end");
        assert!(
            first[1..].iter().all(|o| !o.ended()) && !newest.ended(),
            "only the oldest"
        );
        // A twelfth: the next oldest still running makes way, not the one told already.
        let twelfth = Open::take(user);
        assert!(first[1].ended() && !twelfth.ended());
        drop(first);
        drop(newest);
        drop(twelfth);
        assert!(
            !STREAMS.lock().unwrap().contains_key(user),
            "all places given back"
        );
    }
}
