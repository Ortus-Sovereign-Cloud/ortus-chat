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
use serde_json::{json, Value};

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
    setting(instance, "escrow_key").await
}

async fn setting(instance: &Instance, name: &str) -> Option<String> {
    instance
        .store
        .query(
            "SELECT value FROM chat_settings WHERE name = $1",
            &[name.into()],
        )
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.text(0).map(str::to_string)))
}

/// The escrow as kept: the signed object and its signer (account id).
/// A key kept before escrows were signed has neither.
async fn escrow_signed(instance: &Instance) -> Option<(Value, String)> {
    let object = setting(instance, "escrow").await?;
    let signer = setting(instance, "escrow_signer").await?;
    Some((serde_json::from_str(&object).ok()?, signer))
}

async fn get(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let me = crate::api::signed(request, instance).await?;
    let key = escrow_key(instance).await;
    // The signed escrow, with its signer's master key as this viewer sees
    // it; a key nobody signed (or whose signer's master key changed since)
    // is served as unsigned: set-up refuses it.
    let escrow = match escrow_signed(instance).await {
        Some((object, signer)) => {
            crate::trust::served_escrow(instance, &signer, &object, &me.id).await
        }
        None => None,
    };
    let unsigned = key.is_some() && escrow.is_none();
    Ok(ok(
        &json!({ "encryptedRooms": encrypted_rooms_allowed(instance).await, "escrowKey": key, "escrow": escrow, "escrowUnsigned": unsigned, "federation": crate::federation::enabled(), "server": crate::store::server_name(instance) }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Change {
    #[serde(default)]
    encrypted_rooms: Option<bool>,
    /// Only "" (takes the escrow away): a new key comes signed, in `escrow`.
    #[serde(default)]
    escrow_key: Option<String>,
    /// The escrow signed by the administrator's master key; null takes it away.
    #[serde(default, deserialize_with = "present")]
    escrow: Option<Value>,
}

/// A field that is there, null included (Some(Null)).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

async fn set(request: &Request, instance: &Arc<Instance>) -> Result<Response, ApiError> {
    let session = ortus_core::auth::current(request, instance)
        .await
        .ok_or_else(ApiError::sign_in)?;
    let me = session.user.clone();
    if me.role < Role::Admin {
        return Err(ApiError::forbidden());
    }
    let input: Change = body(request)?;
    // What becomes of the escrow: None (unchanged), Some(None) (taken
    // away) or Some(Some((signed object, public key))).
    let change: Option<Option<(Value, String)>> =
        match (&input.escrow, &input.escrow_key) {
            (Some(Value::Null), _) => Some(None),
            (Some(escrow), _) => Some(Some(
                crate::trust::signed_escrow(instance, &me.id, escrow).await?,
            )),
            (None, Some(key)) if key.is_empty() => Some(None),
            (None, Some(_)) => return Err(ApiError::bad_request(
                "A new escrow key is signed by an administrator's master key: send it as escrow.",
            )),
            (None, None) => None,
        };
    let s = instance.store.as_ref();
    // Whoever holds the escrow key's private half can open everyone's
    // recovery keys: changing it needs a recent, strong sign-in. The same
    // signed key again does not.
    if let Some(next) = &change {
        let now = escrow_signed(instance).await.map(|(o, _)| o);
        let had_key = escrow_key(instance).await.is_some();
        let same = match next {
            None => !had_key,
            Some((object, _)) => now.as_ref() == Some(object),
        };
        if !same {
            ortus_core::auth::step_up::require(s, &session).await?;
        }
    }
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
    if let Some(next) = &change {
        tx.execute(
            "DELETE FROM chat_settings WHERE name IN ('escrow_key', 'escrow', 'escrow_signer')",
            &[],
        )
        .await?;
        if let Some((object, public)) = next {
            for (name, value) in [
                ("escrow_key", public.clone()),
                ("escrow", object.to_string()),
                ("escrow_signer", me.id.clone()),
            ] {
                tx.execute(
                    "INSERT INTO chat_settings (name, value) VALUES ($1, $2)",
                    &[name.into(), value.as_str().into()],
                )
                .await?;
            }
        }
    }
    tx.commit().await?;
    let escrow_key = change
        .as_ref()
        .map(|c| c.as_ref().map(|(_, k)| k.clone()).unwrap_or_default());
    ortus_core::auth::audit(
        instance,
        ortus_core::audit::Event::new("chat.policy_changed", ortus_core::audit::Outcome::Done)
            .by(&me.id)
            .with(json!({"encryptedRooms": input.encrypted_rooms, "escrowKey": escrow_key})),
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
            summary: "Whether end-to-end rooms may be made, and the organisation's escrow: the object an administrator signed, with their master key (signerMaster); escrowUnsigned for a key nobody signed.",
            access: Access::Signed,
            response: crate::api::object,
            handler: h_get,
        },
        Route {
            method: Method::Patch,
            path: "/chat/policy",
            id: "chatPolicyChange",
            tag: "chat",
            summary: "An administrator allows end-to-end rooms or not, and sets the organisation's escrow key, signed by their master key: {encryptedRooms, escrow: {user_id, usage, public_key, signatures} or null}.",
            access: Access::Signed,
            response: crate::api::object,
            handler: h_set,
        },
    ]
}
