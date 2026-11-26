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

/// The organisation's escrow key (X25519, unpadded base64): people's
/// recovery keys are also sealed to it (docs/e2e-trust-and-backup.md).
pub async fn escrow_key(instance: &Instance) -> Option<String> {
    instance
        .store
        .query(
            "SELECT value FROM chat_settings WHERE name = 'escrow_key'",
            &[],
        )
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.text(0).map(str::to_string)))
}

async fn get(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    crate::api::signed(request, instance).await?;
    Ok(ok(
        &json!({ "encryptedRooms": encrypted_rooms_allowed(instance).await, "escrowKey": escrow_key(instance).await, "federation": crate::federation::enabled(), "server": crate::store::server_name(instance) }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Change {
    #[serde(default)]
    encrypted_rooms: Option<bool>,
    /// The escrow key's public half ("" takes it away).
    #[serde(default)]
    escrow_key: Option<String>,
}

async fn set(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    if me.role < Role::Admin {
        return Err(ApiError::forbidden());
    }
    let input: Change = body(request)?;
    if let Some(key) = &input.escrow_key {
        let shaped = key.is_empty()
            || (key.len() == 43
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
        if !shaped {
            return Err(ApiError::bad_request(
                "The escrow key is a Curve25519 public key (unpadded base64).",
            ));
        }
    }
    let s = instance.store.as_ref();
    let mut tx = s.begin().await?;
    if let Some(allowed) = input.encrypted_rooms {
        tx.execute(
            "DELETE FROM chat_settings WHERE name = 'encrypted_rooms'",
            &[],
        )
        .await?;
        tx.execute(
            "INSERT INTO chat_settings (name, value) VALUES ('encrypted_rooms', $1)",
            &[if allowed { "allowed" } else { "off" }.into()],
        )
        .await?;
    }
    if let Some(key) = &input.escrow_key {
        tx.execute("DELETE FROM chat_settings WHERE name = 'escrow_key'", &[])
            .await?;
        if !key.is_empty() {
            tx.execute(
                "INSERT INTO chat_settings (name, value) VALUES ('escrow_key', $1)",
                &[key.as_str().into()],
            )
            .await?;
        }
    }
    tx.commit().await?;
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.policy_changed", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .with(json!({"encryptedRooms": input.encrypted_rooms, "escrowKey": input.escrow_key})),
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
            summary: "Whether end-to-end rooms may be made, and the organisation's escrow key.",
            access: Access::Signed,
            response: crate::api::object,
            handler: h_get,
        },
        Route {
            method: Method::Patch,
            path: "/chat/policy",
            id: "chatPolicyChange",
            tag: "chat",
            summary: "An administrator allows end-to-end rooms or not, and sets the organisation's escrow key: {encryptedRooms, escrowKey}.",
            access: Access::Signed,
            response: crate::api::object,
            handler: h_set,
        },
    ]
}
