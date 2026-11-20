//! The `Chat` service other apps use to tell a channel something (a record
//! filed, a task done), as the person who did it.

use std::sync::Weak;

use ortus_core::instance::Instance;
use ortus_core::interfaces::ItemRef;
use ortus_core::storage::BoxFuture;

pub struct Service {
    pub instance: Weak<Instance>,
}

impl ortus_core::interfaces::Chat for Service {
    fn post<'a>(
        &'a self,
        user: &'a str,
        channel: &'a str,
        text: &'a str,
    ) -> BoxFuture<'a, Result<ItemRef, String>> {
        Box::pin(async move {
            let instance = self.instance.upgrade().ok_or("stopping")?;
            let me = ortus_core::auth::accounts::by_id(instance.store.as_ref(), user)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("no such person")?;
            // The channel by its id, or by its name ("#flood-response").
            let s = instance.store.as_ref();
            let id = match crate::store::room(s, channel).await.map_err(|e| e.to_string())? {
                Some(r) => r.id,
                None => s
                    .query("SELECT id FROM chat_rooms WHERE name = $1 AND kind <> 'direct' ORDER BY created_at LIMIT 1", &[channel.trim_start_matches('#').into()])
                    .await
                    .map_err(|e| e.to_string())?
                    .first()
                    .and_then(|r| r.text(0).map(str::to_string))
                    .ok_or("no such channel")?,
            };
            let room = crate::api::joined(&instance, &me.id, &id)
                .await
                .map_err(|e| e.message)?;
            let v = crate::api::send(&instance, &me, &room, text, None, &[])
                .await
                .map_err(|e| e.message)?;
            let event = v["id"].as_str().unwrap_or_default().to_string();
            Ok(ItemRef {
                app: "chat".into(),
                id: event.clone(),
                path: format!("/chat?room={}&message={event}", room.id),
            })
        })
    }
}
