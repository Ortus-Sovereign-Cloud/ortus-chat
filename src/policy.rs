//! The chat policy an administrator sets: whether end-to-end rooms may be
//! made (they are then outside search, records and legal hold).

use std::sync::Arc;

use ortus_core::api::{answer, body, ok, ApiError, Method, Route};
use ortus_core::auth::accounts::Role;
use ortus_core::auth::Access;
use ortus_core::instance::Instance;
use ortus_core::storage::{BoxFuture, Migration};
use rust_web_server::prelude::*;
use serde::Deserialize;
use serde_json::json;

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 2,
    name: "chat policy",
    sql: "CREATE TABLE chat_settings (
        name TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )",
}];

pub async fn encrypted_rooms_allowed(instance: &Instance) -> bool {
    instance
        .store
        .query(
            "SELECT value FROM chat_settings WHERE name = 'encrypted_rooms'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.text(0).map(|v| v == "allowed")))
        .unwrap_or(false)
}

async fn get(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    crate::api::signed(request, instance).await?;
    Ok(ok(
        &json!({ "encryptedRooms": encrypted_rooms_allowed(instance).await }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Change {
    encrypted_rooms: bool,
}

async fn set(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    if me.role < Role::Admin {
        return Err(ApiError::forbidden());
    }
    let input: Change = body(request)?;
    let s = instance.store.as_ref();
    let mut tx = s.begin().await?;
    tx.execute(
        "DELETE FROM chat_settings WHERE name = 'encrypted_rooms'",
        &[],
    )
    .await?;
    tx.execute(
        "INSERT INTO chat_settings (name, value) VALUES ('encrypted_rooms', $1)",
        &[if input.encrypted_rooms {
            "allowed"
        } else {
            "off"
        }
        .into()],
    )
    .await?;
    tx.commit().await?;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.policy_changed", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .with(json!({"encryptedRooms": input.encrypted_rooms})),
    )
    .await;
    get(request, instance).await
}

fn h_get(
    request: Request,
    _: PathParams,
    _: ConnectionInfo,
    instance: Arc<Instance>,
) -> BoxFuture<'static, Response> {
    Box::pin(async move { answer(&request, get(&request, &instance).await) })
}
fn h_set(
    request: Request,
    _: PathParams,
    _: ConnectionInfo,
    instance: Arc<Instance>,
) -> BoxFuture<'static, Response> {
    Box::pin(async move { answer(&request, set(&request, &instance).await) })
}

pub fn routes() -> Vec<Route> {
    vec![
        Route {
            method: Method::Get,
            path: "/chat/policy",
            id: "chatPolicy",
            tag: "chat",
            summary: "Whether end-to-end rooms may be made.",
            access: Access::Signed,
            response: crate::api::object,
            handler: h_get,
        },
        Route {
            method: Method::Patch,
            path: "/chat/policy",
            id: "chatPolicyChange",
            tag: "chat",
            summary: "An administrator allows end-to-end rooms or not: {encryptedRooms}.",
            access: Access::Signed,
            response: crate::api::object,
            handler: h_set,
        },
    ]
}
