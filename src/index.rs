//! Chat in search: a message's text, found by the members of its room
//! (the entry belongs to the room, "chat:room:<id>", not to a person, so
//! forgetting the room's creator keeps everyone else's messages findable).
//! End-to-end rooms are never indexed.

use ortus_core::instance::Instance;
use ortus_core::storage::Migration;
use serde_json::json;

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 6,
    name: "search entries belong to their room",
    sql: "UPDATE core_search SET owner = 'chat:room:' || (SELECT room FROM chat_events WHERE chat_events.event_id = core_search.id) WHERE app = 'chat' AND EXISTS (SELECT 1 FROM chat_events WHERE chat_events.event_id = core_search.id)",
}];

use crate::store::{self, Room};

pub async fn message(instance: &Instance, room: &Room, event_id: &str) {
    if room.encrypted {
        return;
    }
    let s = instance.store.as_ref();
    let Ok(Some(e)) = store::event(s, event_id).await else {
        return;
    };
    if e.deleted_at.is_some() || e.kind != "m.room.message" {
        return;
    }
    let title = if room.kind == "direct" {
        String::new()
    } else {
        format!("#{}", room.name)
    };
    let entry = ortus_core::search::Entry {
        app: "chat",
        id: &e.event_id,
        owner: &owner(&room.id),
        title: &title,
        body: &e.body,
        meta: json!({"path": format!("/chat?room={}&message={}", room.id, e.event_id), "kind": "message", "from": e.sender}),
        at: e.origin_ts,
    };
    let _ = ortus_core::search::index(s, &entry).await;
}

/// The search owner of a room's messages.
pub fn owner(room: &str) -> String {
    format!("chat:room:{room}")
}

/// The rooms the person is in, as search owners.
pub async fn owners_for(instance: &Instance, user: &str) -> Vec<String> {
    store::rooms_of(instance.store.as_ref(), user)
        .await
        .map(|rs| {
            rs.into_iter()
                .filter(|(_, st, _)| st == "join")
                .map(|(r, _, _)| owner(&r.id))
                .collect()
        })
        .unwrap_or_default()
}

/// The database a transaction is on: one statement both run, whose answer
/// differs ("1" on SQLite, "true" on PostgreSQL); no statement may fail
/// inside a transaction.
pub async fn engine_of(tx: &mut dyn ortus_core::storage::AsyncTx) -> ortus_core::storage::Engine {
    let text = tx
        .query("SELECT CAST(1 = 1 AS TEXT)", &[])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.text(0).map(str::to_string)));
    if text.as_deref() == Some("true") {
        ortus_core::storage::Engine::Postgres
    } else {
        ortus_core::storage::Engine::Sqlite
    }
}

/// Of these messages, those in rooms the person is in (or public channels).
pub async fn visible(instance: &Instance, user: &str, ids: Vec<String>) -> Vec<String> {
    let s = instance.store.as_ref();
    let mut out = Vec::new();
    for id in ids {
        if let Ok(Some(e)) = store::event(s, &id).await {
            if e.deleted_at.is_none() && crate::api::readable(instance, user, &e.room).await.is_ok()
            {
                out.push(id);
            }
        }
    }
    out
}
