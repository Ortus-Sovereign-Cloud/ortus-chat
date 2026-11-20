//! Live delivery: one stream per person (server-sent events) with the new
//! events of every room they are in, new rooms and invitations, and who
//! is typing. Read from the database, so it works on every node.

use std::collections::HashMap;
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

/// Streams open per person at most.
const MAX_STREAMS: usize = 10;

static STREAMS: LazyLock<Mutex<HashMap<String, usize>>> = LazyLock::new(Default::default);

struct Open(String);

impl Open {
    fn take(user: &str) -> Option<Open> {
        let mut all = STREAMS.lock().unwrap_or_else(|e| e.into_inner());
        let n = all.entry(user.to_string()).or_insert(0);
        if *n >= MAX_STREAMS {
            return None;
        }
        *n += 1;
        Some(Open(user.to_string()))
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        let mut all = STREAMS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = all.get_mut(&self.0) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                all.remove(&self.0);
            }
        }
    }
}

fn events(request: &Request, instance: Arc<Instance>, user: String) -> Response {
    let Some(open) = Open::take(&user) else {
        return answer(
            request,
            Err::<Response, _>(ApiError::too_many("Too many open chat windows.")),
        );
    };
    let (sender, response) = SseStream::new().keep_alive(Duration::from_secs(15)).start();
    ortus_core::runtime::io().spawn(async move {
        let _open = open;
        let started = store::now();
        let mut known: HashMap<String, i64> = HashMap::new();
        let mut typing_seen: HashMap<String, String> = HashMap::new();
        let mut first = true;
        let mut pinged = started;
        loop {
            let s = instance.store.as_ref();
            let Ok(rooms) = store::rooms_of(s, &user).await else { return };
            for (room, state, _) in &rooms {
                let was = known.get(&room.id).copied();
                if was.is_none() {
                    known.insert(room.id.clone(), room.last_seq);
                    if !first && sender.send_async(SseEvent::data(json!({"room": room.id, "state": state}).to_string()).event_type("room")).await.is_err() {
                        return;
                    }
                    continue;
                }
                let from = was.unwrap_or(0);
                if state == "join" && room.last_seq > from {
                    let Ok(list) = store::since(s, &user, &room.id, from).await else { return };
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
            tokio::time::sleep(Duration::from_millis(400)).await;
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
    Ok(ortus_core::api::ok(&json!({})))
}

crate::api::with_params!(h_typing, typing);

pub fn routes() -> Vec<Route> {
    vec![
        Route { method: Method::Get, path: "/chat/events", id: "chatEvents", tag: "chat", summary: "Server-sent events: `event` (a room's new event: message, reply, edit, deletion, reaction), `room` (a new room or invitation), `typing`.", access: Access::Signed, response: crate::api::object, handler: h_events },
        Route { method: Method::Post, path: "/chat/rooms/:room/typing", id: "chatTyping", tag: "chat", summary: "The person is typing in a room (for five seconds).", access: Access::Signed, response: crate::api::object, handler: h_typing },
    ]
}
