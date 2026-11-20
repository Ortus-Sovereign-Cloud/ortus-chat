//! Chat: channels and threads, Matrix federation, end-to-end rooms by policy.
//!
//! An Ortus app crate: it depends on `ortus-core` only and hands its apps
//! to a program through [`apps`].

pub mod api;
pub mod federation;
pub mod index;
pub mod live;
pub mod policy;
pub mod service;
pub mod store;

use std::sync::Arc;

use ortus_core::app::{App, AppInfo, Group};
use ortus_core::instance::Instance;
use ortus_core::retention::Rules;
use ortus_core::storage::{AsyncTx, BoxFuture, Migration};

/// The built web client (web/dist).
#[derive(rust_embed::RustEmbed)]
#[folder = "web/dist"]
struct Web;

static MIGRATIONS: std::sync::LazyLock<Vec<Migration>> = std::sync::LazyLock::new(|| {
    let mut all = store::MIGRATIONS.to_vec();
    all.extend_from_slice(policy::MIGRATIONS);
    all.extend_from_slice(live::MIGRATIONS);
    all
});

/// The chat app.
pub struct Chat;

impl App for Chat {
    fn info(&self) -> AppInfo {
        AppInfo {
            id: "chat",
            group: Group::Communicate,
            path: "/chat",
            order: 2,
        }
    }

    fn migrations(&self) -> &'static [Migration] {
        MIGRATIONS.as_slice()
    }

    fn routes(&self) -> Vec<ortus_core::api::Route> {
        let mut all = api::routes();
        all.extend(live::routes());
        all.extend(policy::routes());
        all
    }

    fn provide(&self, instance: &Arc<Instance>, services: &ortus_core::services::Services) {
        let chat: Arc<dyn ortus_core::interfaces::Chat> = Arc::new(service::Service {
            instance: Arc::downgrade(instance),
        });
        services.provide("chat", chat);
    }

    fn search_owners<'a>(
        &'a self,
        instance: &'a Instance,
        user: &'a str,
    ) -> BoxFuture<'a, Vec<String>> {
        Box::pin(index::owners_for(instance, user))
    }

    fn search_allowed<'a>(
        &'a self,
        instance: &'a Instance,
        user: &'a str,
        ids: Vec<String>,
    ) -> BoxFuture<'a, Vec<String>> {
        Box::pin(index::visible(instance, user, ids))
    }

    fn purge<'a>(
        &'a self,
        tx: &'a mut dyn AsyncTx,
        rules: &'a Rules,
    ) -> BoxFuture<'a, Result<u64, String>> {
        Box::pin(async move { store::purge(tx, rules).await.map_err(|e| e.to_string()) })
    }

    fn forget_user<'a>(
        &'a self,
        tx: &'a mut dyn AsyncTx,
        user_id: &'a str,
        rules: &'a Rules,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            store::forget(tx, user_id, rules)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn web_file(&self, path: &str) -> Option<std::borrow::Cow<'static, [u8]>> {
        Web::get(path).map(|file| file.data)
    }
}

/// The apps of this crate, for a program to run.
pub fn apps() -> Vec<Arc<dyn App>> {
    vec![Arc::new(Chat)]
}
