//! Incoming hooks: an outside system (a river gauge, a monitoring tool)
//! posts into a channel through a secret address. A room's owner (or an
//! administrator) makes one; its address is shown once and only its hash
//! is kept. A post is `{text, alert}`: the text becomes a message from the
//! hook, and an alert also notifies everyone in the room (the bell's
//! Alerts). Not in end-to-end rooms (the server would write in the clear).

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
    version: 7,
    name: "incoming hooks",
    sql: "CREATE TABLE chat_hooks (
        id TEXT PRIMARY KEY,
        room TEXT NOT NULL,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at BIGINT NOT NULL
    );
    CREATE UNIQUE INDEX chat_hooks_token ON chat_hooks (token_hash)",
}];

fn hash(token: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The Matrix id a hook's messages come from.
pub fn sender(id: &str, server: &str) -> String {
    format!("@hook-{id}:{server}")
}

/// A hook's name, by its sender id (for the screens).
pub async fn name_of(instance: &Instance, mx: &str) -> Option<String> {
    let id = mx.strip_prefix("@hook-")?.split_once(':')?.0;
    instance
        .store
        .query("SELECT name FROM chat_hooks WHERE id = $1", &[id.into()])
        .await
        .ok()?
        .first()
        .and_then(|r| r.text(0).map(str::to_string))
}

async fn may_manage(
    instance: &Instance,
    user: &ortus_core::auth::accounts::User,
    room: &store::Room,
) -> Result<(), ApiError> {
    let owner = store::membership(instance.store.as_ref(), &room.id, &user.id)
        .await?
        .is_some_and(|m| m.1 == "owner");
    if owner || user.role >= ortus_core::auth::accounts::Role::Admin {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

#[derive(Deserialize)]
struct NewHook {
    name: String,
}

async fn create(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    may_manage(instance, &me, &room).await?;
    if room.encrypted || room.kind == "direct" {
        return Err(ApiError::bad_request(
            "Hooks post into channels that are not end-to-end.",
        ));
    }
    let input: NewHook = body(request)?;
    let name: String = input
        .name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    if name.is_empty() {
        return Err(ApiError::bad_request("A hook has a name."));
    }
    let id = format!("h{}", ortus_core::auth::random_hex(8));
    let token = ortus_core::auth::random_hex(24);
    instance
        .store
        .execute(
            "INSERT INTO chat_hooks (id, room, name, token_hash, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            &[id.as_str().into(), room.id.as_str().into(), name.as_str().into(), hash(&token).into(), me.id.as_str().into(), now().into()],
        )
        .await?;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.hook_made", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .on(&room.id)
            .with(json!({"hook": id, "name": name})),
    )
    .await;
    // The address is shown once.
    Ok(ok(
        &json!({"id": id, "name": name, "url": format!("{}/api/v1/chat/hooks/{token}", instance.config.public_url.trim_end_matches('/'))}),
    ))
}

async fn list(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    may_manage(instance, &me, &room).await?;
    let rows = instance
        .store
        .query(
            "SELECT id, name, created_at FROM chat_hooks WHERE room = $1 ORDER BY created_at",
            &[room.id.as_str().into()],
        )
        .await?;
    let hooks: Vec<Value> = rows
        .iter()
        .map(|r| json!({"id": r.text(0), "name": r.text(1), "createdAt": r.int(2)}))
        .collect();
    Ok(ok(&json!({"hooks": hooks})))
}

async fn remove_hook(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let me = signed(request, instance).await?;
    let room = joined(instance, &me.id, params.get("room").unwrap_or_default()).await?;
    may_manage(instance, &me, &room).await?;
    let id = params.get("hook").unwrap_or_default();
    instance
        .store
        .execute(
            "DELETE FROM chat_hooks WHERE id = $1 AND room = $2",
            &[id.into(), room.id.as_str().into()],
        )
        .await?;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.hook_removed", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .on(&room.id)
            .with(json!({"hook": id})),
    )
    .await;
    Ok(ok(&json!({"removed": id})))
}

#[derive(Deserialize)]
struct Post {
    text: String,
    #[serde(default)]
    alert: bool,
}

/// Posts per hook a minute (per node).
fn allowed(hook: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static SEEN: OnceLock<Mutex<HashMap<String, Vec<Instant>>>> = OnceLock::new();
    let mut seen = SEEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if seen.len() > 10_000 {
        seen.clear();
    }
    let list = seen.entry(hook.to_string()).or_default();
    list.retain(|t| t.elapsed() < Duration::from_secs(60));
    if list.len() >= 60 {
        return false;
    }
    list.push(Instant::now());
    true
}

/// An outside system posts through a hook's address.
async fn post(
    request: &Request,
    params: &PathParams,
    instance: &Arc<Instance>,
) -> Result<Response, ApiError> {
    let token = params.get("token").unwrap_or_default();
    let s = instance.store.as_ref();
    let row = s
        .query(
            "SELECT id, room, name FROM chat_hooks WHERE token_hash = $1",
            &[hash(token).into()],
        )
        .await?;
    let Some(r) = row.first() else {
        return Err(ApiError::not_found("There is no such hook."));
    };
    let (id, room_id, name) = (
        r.text(0).unwrap_or_default().to_string(),
        r.text(1).unwrap_or_default().to_string(),
        r.text(2).unwrap_or_default().to_string(),
    );
    if !allowed(&id) {
        return Err(ApiError {
            status: 429,
            code: "slow_down",
            message: "Too many posts: at most 60 a minute.".into(),
        });
    }
    let room = store::room(s, &room_id)
        .await?
        .ok_or_else(|| ApiError::not_found("There is no such hook."))?;
    if room.encrypted {
        return Err(ApiError::bad_request("The room is end-to-end encrypted."));
    }
    let input: Post = body(request)?;
    let text: String = input
        .text
        .trim()
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(4000)
        .collect();
    if text.is_empty() {
        return Err(ApiError::bad_request("Say something."));
    }
    let server = store::server_name(instance);
    let from = sender(&id, &server);
    let content = json!({"msgtype": if input.alert { "m.notice" } else { "m.text" }, "body": text, "ortus.hook": {"name": name, "alert": input.alert}});
    // Read before the transaction (a store query inside it waits for it
    // on SQLite).
    let members = if input.alert {
        store::members(s, &room.id).await?
    } else {
        Vec::new()
    };
    let mut tx = s.begin().await?;
    let (_, event_id) = store::add_event(
        tx.as_mut(),
        &NewEvent {
            room: &room.id,
            event_id: None,
            sender: &from,
            sender_user: None,
            kind: "m.room.message",
            thread_root: None,
            body: &text,
            content: &content,
            origin_ts: now(),
        },
    )
    .await?;
    if input.alert {
        // Everyone in the room hears of an alert.
        let path = format!("/chat?room={}&message={event_id}", room.id);
        for (_, user, state, _) in members {
            let Some(user) = user.filter(|_| state == "join") else {
                continue;
            };
            let notice = ortus_core::notify::Notice {
                app: "chat",
                kind: ortus_core::notify::Kind::Alert,
                title: &text,
                detail: "",
                path: &path,
                key: None,
                args: json!({"from": name, "where": format!("#{}", room.name)}),
            };
            ortus_core::notify::add_in(tx.as_mut(), &user, &notice).await?;
        }
    }
    tx.commit().await?;
    crate::index::message(instance, &room, &event_id).await;
    crate::federation::outbound(instance, &room.id, &event_id).await;
    Ok(ok(&json!({"id": event_id})))
}

crate::api::with_params!(h_create, create);
crate::api::with_params!(h_list, list);
crate::api::with_params!(h_remove, remove_hook);
crate::api::with_params!(h_post, post);

pub fn routes() -> Vec<Route> {
    let route = |method, path, id, summary, access, handler| Route {
        method,
        path,
        id,
        tag: "chat",
        summary,
        access,
        response: crate::api::object,
        handler,
    };
    vec![
        route(Method::Post, "/chat/rooms/:room/hooks", "chatHookMake", "Makes an incoming hook for a channel (its owner or an administrator): {name}; gives its address once.", Access::Signed, h_create),
        route(Method::Get, "/chat/rooms/:room/hooks", "chatHooks", "A channel's incoming hooks.", Access::Signed, h_list),
        route(Method::Delete, "/chat/rooms/:room/hooks/:hook", "chatHookRemove", "Removes an incoming hook.", Access::Signed, h_remove),
        route(Method::Post, "/chat/hooks/:token", "chatHookPost", "An outside system posts through a hook: {text, alert}; an alert notifies everyone in the channel.", Access::Header, h_post),
    ]
}
