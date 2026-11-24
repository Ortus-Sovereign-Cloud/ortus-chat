//! ortus-e2e for Swift and Kotlin (UniFFI): the phones open their store,
//! give an HTTP function signed in as the person, and call `inbox`,
//! `decrypt`, `send` and `forget`. Every call blocks until done: the apps
//! call it off their main thread.

use std::fmt;
use std::sync::Arc;

uniffi::setup_scaffolding!();

/// An answer of the phone's HTTP client.
#[derive(uniffi::Record)]
pub struct HttpResponse {
    pub status: u16,
    /// The body's text (JSON).
    pub body: String,
}

#[derive(Debug, uniffi::Error)]
pub enum TransportError {
    /// No answer (offline, a timeout).
    Failed { message: String },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Failed { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for TransportError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        TransportError::Failed { message: e.reason }
    }
}

/// The phone's HTTP client, signed in as the person. `path` is under
/// `/api/v1` (`/chat/rooms/r1/devices`); `body` is JSON text.
#[uniffi::export(with_foreign)]
pub trait Transport: Send + Sync {
    fn http(
        &self,
        method: String,
        path: String,
        body: Option<String>,
    ) -> Result<HttpResponse, TransportError>;
}

struct Bridge(Arc<dyn Transport>);

impl ortus_e2e::Transport for Bridge {
    fn http(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
        self.0
            .http(method.into(), path.into(), body.map(str::to_string))
            .map(|r| (r.status, r.body))
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, uniffi::Error)]
pub enum E2eError {
    /// The HTTP function gave no answer.
    Transport { message: String },
    /// The server answered with an error.
    Server { status: u16, body: String },
    /// The store could not be opened, read or written (a wrong passphrase).
    Store { message: String },
    /// What was asked does not hold.
    Invalid { message: String },
    /// A message this device does not open, and why.
    Refused { reason: String },
    /// After `forget()`.
    Forgotten,
}

impl fmt::Display for E2eError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            E2eError::Transport { message } => write!(f, "no answer: {message}"),
            E2eError::Server { status, body } => write!(f, "the server answered {status}: {body}"),
            E2eError::Store { message } => write!(f, "the store: {message}"),
            E2eError::Invalid { message } => write!(f, "{message}"),
            E2eError::Refused { reason } => write!(f, "not opened: {reason}"),
            E2eError::Forgotten => write!(f, "this device was forgotten"),
        }
    }
}

impl std::error::Error for E2eError {}

impl From<ortus_e2e::Error> for E2eError {
    fn from(e: ortus_e2e::Error) -> Self {
        use ortus_e2e::Error as E;
        match e {
            E::Transport(message) => E2eError::Transport { message },
            E::Server { status, body } => E2eError::Server { status, body },
            E::Store(message) => E2eError::Store { message },
            E::Invalid(message) => E2eError::Invalid { message },
            E::Refused(reason) => E2eError::Refused { reason },
            E::Forgotten => E2eError::Forgotten,
        }
    }
}

/// A message opened.
#[derive(uniffi::Record)]
pub struct Opened {
    pub text: String,
    /// The root message of its thread, as sealed by its sender.
    pub thread: Option<String>,
}

/// What `inbox()` took in.
#[derive(uniffi::Record)]
pub struct Inbox {
    pub messages: u32,
    pub room_keys: u32,
}

/// End-to-end rooms for one person on this phone.
#[derive(uniffi::Object)]
pub struct OrtusE2e {
    inner: ortus_e2e::E2e,
}

#[uniffi::export]
impl OrtusE2e {
    /// Opens (or makes) this device's keys in `store_dir` (the app's
    /// protected, not backed-up directory), encrypted with `passphrase`
    /// (kept in the Keychain or the Android Keystore), and publishes them.
    /// `user` is the person's Ortus id and `server_name` the server's
    /// Matrix name: `me` of `GET /chat/rooms` is `@{user}:{server_name}`.
    #[uniffi::constructor]
    pub fn open(
        store_dir: String,
        passphrase: String,
        user: String,
        device: String,
        server_name: String,
        transport: Arc<dyn Transport>,
    ) -> Result<Arc<Self>, E2eError> {
        let inner = ortus_e2e::E2e::open(
            std::path::Path::new(&store_dir),
            &passphrase,
            &user,
            &device,
            &server_name,
            Arc::new(Bridge(transport)),
        )?;
        Ok(Arc::new(OrtusE2e { inner }))
    }

    /// Takes in the room keys waiting for this device and tops its
    /// one-time keys up (on opening a room, and now and then).
    pub fn inbox(&self) -> Result<Inbox, E2eError> {
        let i = self.inner.inbox()?;
        Ok(Inbox {
            messages: i.messages,
            room_keys: i.room_keys,
        })
    }

    /// Opens one message of `room`, given as the chat API gives it (with
    /// `id`, `sender`, `thread` and `sealed`).
    pub fn decrypt(&self, room: String, message_json: String) -> Result<Opened, E2eError> {
        let o = self.inner.decrypt(&room, &message_json)?;
        Ok(Opened {
            text: o.text,
            thread: o.thread,
        })
    }

    /// Seals and sends `text` (in `thread`), giving members' devices this
    /// device's room key first. Answers the message's id.
    pub fn send(
        &self,
        room: String,
        text: String,
        thread: Option<String>,
    ) -> Result<String, E2eError> {
        Ok(self.inner.send(&room, &text, thread.as_deref())?)
    }

    /// Deletes this device's keys and sessions from the phone.
    pub fn forget(&self) -> Result<(), E2eError> {
        Ok(self.inner.forget()?)
    }
}
