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
    Failed { detail: String },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Failed { detail } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for TransportError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        TransportError::Failed { detail: e.reason }
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
    Transport { detail: String },
    /// The server answered with an error.
    Server { status: u16, body: String },
    /// The store could not be opened, read or written (a wrong passphrase).
    Store { detail: String },
    /// What was asked does not hold.
    Invalid { detail: String },
    /// A message this device does not open, and why.
    Refused { reason: String },
    /// After `forget()`.
    Forgotten,
}

impl fmt::Display for E2eError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            E2eError::Transport { detail } => write!(f, "no answer: {detail}"),
            E2eError::Server { status, body } => write!(f, "the server answered {status}: {body}"),
            E2eError::Store { detail } => write!(f, "the store: {detail}"),
            E2eError::Invalid { detail } => write!(f, "{detail}"),
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
            E::Transport(detail) => E2eError::Transport { detail },
            E::Server { status, body } => E2eError::Server { status, body },
            E::Store(detail) => E2eError::Store { detail },
            E::Invalid(detail) => E2eError::Invalid { detail },
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
    /// Its room key came from the key backup, not from the sender: show the
    /// sender as one that could not be confirmed.
    pub from_backup: bool,
}

/// What `inbox()` took in.
#[derive(uniffi::Record)]
pub struct Inbox {
    pub messages: u32,
    pub room_keys: u32,
}

/// Where recovery stands: set up for the person, and opened on this phone.
#[derive(uniffi::Record)]
pub struct RecoveryState {
    pub set: bool,
    pub here: bool,
}

/// The organisation's escrow key, shown before recovery is set up:
/// "Your organisation can recover your history. Escrow key {fingerprint},
/// set by {signer} ({signer_status})", and that it changed when `changed`.
#[derive(uniffi::Record)]
pub struct EscrowInfo {
    /// The X25519 public key: pass it to `set_up_recovery` once the person saw it.
    pub key: String,
    /// The key's first 24 characters in groups of four.
    pub fingerprint: String,
    /// Who signed it (their Matrix id).
    pub signer: String,
    /// you, verified (by this person) or unverified.
    pub signer_status: String,
    /// Not the key accepted at this phone's last set-up.
    pub changed: bool,
}

/// A device nobody vouched for.
#[derive(uniffi::Record)]
pub struct DeviceRef {
    pub user: String,
    pub device: String,
}

/// A verification by emoji, as the screen shows it.
#[derive(uniffi::Record)]
pub struct VerificationView {
    pub id: String,
    pub user: String,
    pub device: Option<String>,
    /// requested, incoming, ready (choose: scan, show or emoji), qr (this
    /// phone's code is shown), scanned (the other device scanned it: did it
    /// say so?), waiting, emoji, done or cancelled.
    pub state: String,
    /// The seven emoji's numbers in Matrix's table, when there are some to compare.
    pub emoji: Vec<u8>,
    /// The other device shows a code this phone can scan.
    pub can_scan: bool,
    /// The other device can scan a code this phone shows.
    pub can_show: bool,
}

/// A QR code to draw: `width` × `width` modules, dark when true, row by row.
#[derive(uniffi::Record)]
pub struct QrImage {
    pub width: u32,
    pub modules: Vec<bool>,
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
            from_backup: o.from_backup,
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
    /// Where recovery stands for this person and this phone.
    pub fn recovery_state(&self) -> Result<RecoveryState, E2eError> {
        let r = self.inner.recovery_state()?;
        Ok(RecoveryState {
            set: r.set,
            here: r.here,
        })
    }

    /// Recovery here with the recovery key: answers how many room keys came
    /// back from the backup; Invalid when it is not the person's key.
    pub fn recover(&self, recovery_key: String) -> Result<u32, E2eError> {
        Ok(self.inner.recover(&recovery_key)?)
    }

    /// The organisation's escrow key, to show before set-up: none when
    /// there is none; Invalid when no administrator signed it (set-up is
    /// refused: they make it again).
    pub fn escrow_info(&self) -> Result<Option<EscrowInfo>, E2eError> {
        Ok(self.inner.escrow_info()?.map(|e| EscrowInfo {
            key: e.key,
            fingerprint: e.fingerprint,
            signer: e.signer,
            signer_status: e.signer_status,
            changed: e.changed,
        }))
    }

    /// Sets recovery up from this phone (nobody set it up yet): the
    /// recovery key, to show once. With an escrow, `accepted_escrow_key` is
    /// the key `escrow_info` showed the person; another (or none) is refused.
    pub fn set_up_recovery(&self, accepted_escrow_key: Option<String>) -> Result<String, E2eError> {
        Ok(self.inner.set_up_recovery(accepted_escrow_key)?)
    }

    /// Asks one device (a row of a room's unverified devices) to verify: its id.
    pub fn verify_device(&self, user: String, device: String) -> Result<String, E2eError> {
        Ok(self.inner.verify_device(&user, &device)?)
    }

    /// Emoji, chosen over a QR code.
    pub fn start_emoji(&self, id: String) -> Result<(), E2eError> {
        Ok(self.inner.start_emoji(&id)?)
    }

    /// The other device's code as the camera read it: its bytes, or its
    /// data codewords (iOS's error-corrected payload, ZXing's raw bytes).
    pub fn scan_qr(&self, id: String, scanned: Vec<u8>) -> Result<(), E2eError> {
        Ok(self.inner.scan_qr(&id, &scanned)?)
    }

    /// This phone's code, for the other device to scan.
    pub fn show_qr(&self, id: String) -> Result<QrImage, E2eError> {
        let q = self.inner.show_qr(&id)?;
        Ok(QrImage {
            width: q.width,
            modules: q.modules,
        })
    }

    /// Whether the other device said it scanned this phone's code.
    pub fn confirm_scanned(&self, id: String, yes: bool) -> Result<(), E2eError> {
        Ok(self.inner.confirm_scanned(&id, yes)?)
    }

    /// The room's devices nobody vouched for (rooms warn; messages still go).
    pub fn unverified(&self, room: String) -> Result<Vec<DeviceRef>, E2eError> {
        Ok(self
            .inner
            .unverified(&room)?
            .into_iter()
            .map(|(user, device)| DeviceRef { user, device })
            .collect())
    }

    /// Takes in what came for this device and moves verifications on (the
    /// screen calls it every few seconds while one is open).
    pub fn verifications(&self) -> Result<Vec<VerificationView>, E2eError> {
        Ok(self
            .inner
            .verifications()?
            .into_iter()
            .map(|v| VerificationView {
                id: v.id,
                user: v.user,
                device: v.device,
                state: v.state,
                emoji: v.emoji,
                can_scan: v.can_scan,
                can_show: v.can_show,
            })
            .collect())
    }

    /// Asks the person's other devices to verify with this one: its id.
    pub fn verify_own_devices(&self) -> Result<String, E2eError> {
        Ok(self.inner.verify_own_devices()?)
    }

    pub fn accept_verification(&self, id: String) -> Result<(), E2eError> {
        Ok(self.inner.accept_verification(&id)?)
    }

    /// Whether the emoji are the same on both screens.
    pub fn confirm_verification(&self, id: String, same: bool) -> Result<(), E2eError> {
        Ok(self.inner.confirm_verification(&id, same)?)
    }

    pub fn cancel_verification(&self, id: String) -> Result<(), E2eError> {
        Ok(self.inner.cancel_verification(&id)?)
    }

    pub fn forget(&self) -> Result<(), E2eError> {
        Ok(self.inner.forget()?)
    }
}
