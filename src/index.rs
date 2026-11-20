//! Chat in search: a message's text, found by the members of its room
//! (the entry is the room creator's; the app vouches for the members).
//! End-to-end rooms are never indexed.

use ortus_core::instance::Instance;
use serde_json::json;

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
        owner: &room.created_by,
        title: &title,
        body: &e.body,
        meta: json!({"path": format!("/chat?room={}&message={}", room.id, e.event_id), "kind": "message", "from": e.sender}),
        at: e.origin_ts,
    };
    let _ = ortus_core::search::index(s, &entry).await;
}

/// Creators of rooms the person is in.
pub async fn owners_for(instance: &Instance, user: &str) -> Vec<String> {
    store::rooms_of(instance.store.as_ref(), user)
        .await
        .map(|rs| {
            rs.into_iter()
                .filter(|(_, st, _)| st == "join")
                .map(|(r, _, _)| r.created_by)
                .filter(|o| o != user)
                .collect()
        })
        .unwrap_or_default()
}

/// Of these messages, those in rooms the person is in (or public channels).
pub async fn visible(instance: &Instance, user: &str, ids: Vec<String>) -> Vec<String> {
    let s = instance.store.as_ref();
    let mut out = Vec::new();
    for id in ids {
        if let Ok(Some(e)) = store::event(s, &id).await {
            if crate::api::readable(instance, user, &e.room).await.is_ok() {
                out.push(id);
            }
        }
    }
    out
}
