//! Chat: channels and threads, Matrix federation, end-to-end rooms by policy.
//!
//! An Ortus app crate: it depends on `ortus-core` only and hands its apps
//! to a program through [`apps`].

use std::sync::Arc;

use ortus_core::app::{App, AppInfo, Group};

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
}

/// The apps of this crate, for a program to run.
pub fn apps() -> Vec<Arc<dyn App>> {
    vec![Arc::new(Chat)]
}
