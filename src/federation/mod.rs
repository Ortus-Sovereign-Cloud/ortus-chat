//! Matrix federation: rooms shared with the servers of partner
//! organisations. Deny by default: nothing is fetched from, sent to or
//! taken from a server that is not a partner allowed chat (Sovereignty),
//! and a room's label must allow sharing with that partner.
//!
//! It runs only when a certificate is set for the federation listener
//! (`ORTUS_FEDERATION_TLS_CERT`, `_KEY`); the listener is on
//! `ORTUS_FEDERATION_LISTEN` (default 0.0.0.0:8448). Other servers'
//! certificates are checked against the public authorities and
//! `ORTUS_FEDERATION_CA` (a PEM file) when set. In this version Ortus
//! hosts the shared rooms; people of the partner join them.

pub mod client;
pub mod keys;
pub mod listener;
pub mod rooms;
pub mod routes;

use ortus_core::instance::Instance;
use ortus_core::storage::Migration;

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 4,
    name: "federation: keys, events, room state, servers, transactions, outbox",
    sql: "CREATE TABLE chat_fed_keys (
        key_id TEXT PRIMARY KEY,
        seed_sealed TEXT NOT NULL,
        created_at BIGINT NOT NULL
    );
    CREATE TABLE chat_fed_remote_keys (
        server TEXT NOT NULL,
        key_id TEXT NOT NULL,
        public TEXT NOT NULL,
        valid_until BIGINT NOT NULL,
        PRIMARY KEY (server, key_id)
    );
    CREATE TABLE chat_pdus (
        event_id TEXT PRIMARY KEY,
        room TEXT NOT NULL,
        pdu TEXT NOT NULL,
        depth BIGINT NOT NULL,
        kind TEXT NOT NULL,
        state_key TEXT,
        sender TEXT NOT NULL,
        received_at BIGINT NOT NULL
    );
    CREATE INDEX chat_pdus_room ON chat_pdus (room, depth);
    CREATE TABLE chat_room_state (
        room TEXT NOT NULL,
        kind TEXT NOT NULL,
        state_key TEXT NOT NULL,
        event_id TEXT NOT NULL,
        PRIMARY KEY (room, kind, state_key)
    );
    CREATE TABLE chat_fed_txns (
        origin TEXT NOT NULL,
        txn_id TEXT NOT NULL,
        at BIGINT NOT NULL,
        PRIMARY KEY (origin, txn_id)
    );
    CREATE TABLE chat_fed_outbox (
        id TEXT PRIMARY KEY,
        destination TEXT NOT NULL,
        event_id TEXT NOT NULL,
        attempts BIGINT NOT NULL,
        next_at BIGINT NOT NULL
    );
    CREATE INDEX chat_fed_outbox_next ON chat_fed_outbox (next_at)",
}];

/// Whether this installation federates (a listener certificate is set).
pub fn enabled() -> bool {
    std::env::var("ORTUS_FEDERATION_TLS_CERT").is_ok_and(|v| !v.trim().is_empty())
}

/// Whether `server` is a partner allowed chat.
pub async fn partner(instance: &Instance, server: &str) -> bool {
    let host = server.rsplit_once(':').map_or(server, |(h, p)| {
        if p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            server
        }
    });
    ortus_core::policy::is_partner(
        instance.store.as_ref(),
        host,
        ortus_core::policy::Channel::Chat,
    )
    .await
    .unwrap_or(false)
}

/// Whether a room's label lets it be shared with `server` (decided and
/// audited by the core's one policy function).
pub async fn may_share(
    instance: &Instance,
    actor: &str,
    room: &crate::store::Room,
    server: &str,
) -> bool {
    let audience = ortus_core::policy::Audience::Outside(server.to_string());
    let object = format!("chat:room:{}", room.id);
    let ask = ortus_core::policy::Ask {
        actor,
        action: ortus_core::policy::Action::Share,
        label: room.label.as_deref(),
        audience: &audience,
        channel: ortus_core::policy::Channel::Chat,
        object: &object,
        reason: None,
    };
    matches!(
        ortus_core::policy::decide(instance, &ask).await,
        Ok(ortus_core::policy::Decision::Allow { .. })
    )
}

/// Sends a new local event to the servers in its room, when it is shared.
pub async fn outbound(instance: &Instance, room: &str, event_id: &str) {
    if !enabled() {
        return;
    }
    let _ = rooms::local_event(instance, room, event_id).await;
}
