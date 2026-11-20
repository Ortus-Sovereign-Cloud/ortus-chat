//! Matrix federation (slice 8.4 and 8.5): rooms shared with other
//! servers. Until a room is shared, nothing leaves.

use ortus_core::instance::Instance;

/// Sends a new local event to the servers in its room, when it is shared.
pub async fn outbound(instance: &Instance, room: &str, event_id: &str) {
    let _ = (instance, room, event_id);
}
