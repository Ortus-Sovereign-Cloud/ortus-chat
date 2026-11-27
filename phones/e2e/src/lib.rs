//! End-to-end rooms on the phones (docs/phones-end-to-end.md): an
//! `OlmMachine` of matrix-sdk-crypto, kept in its SQLite store under a
//! passphrase, speaking Ortus's room-scoped chat API (docs/end-to-end.md)
//! through an HTTP function the phone gives it, so the crate holds no
//! session token.
//!
//! The SDK does the Olm side: device keys, one-time and fallback keys,
//! device tracking, Olm sessions (claimed keys, pre-key messages), room
//! keys received and the Megolm sessions they make, and decryption. A
//! device's own Megolm session for a room is this crate's (vodozemac, which
//! the SDK is built on), because Ortus's room keys carry `org.ortus.room`,
//! which the SDK's `share_room_key` cannot add, and because Ortus shares a
//! session at index 0, as browsers do. The crate sends that room key over
//! the SDK's Olm sessions (`Device::encrypt_event_raw`).
//!
//! On top of what the SDK checks (recipient, sender, Olm sender key, the
//! session key's signature, the plaintext's room), a message opens only when
//! the session is the one of a device of the message's sender, whose keys
//! are the ones this device saw first (trust on first use), when its thread
//! is the message's, and when no other message used its index.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use matrix_sdk_crypto::olm::{InboundGroupSession, SenderData};
use matrix_sdk_crypto::store::types::Changes;
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, ToDeviceRequest};
use matrix_sdk_crypto::types::EventEncryptionAlgorithm;
use matrix_sdk_crypto::vodozemac::megolm::{
    GroupSession, GroupSessionPickle, MegolmMessage, SessionConfig,
};
use matrix_sdk_crypto::vodozemac::{Ed25519PublicKey, Ed25519Signature};
use matrix_sdk_crypto::{
    CollectStrategy, DecryptionSettings, EncryptionSyncChanges, OlmMachine, OlmMachineBuilder,
    TrustRequirement,
};
use matrix_sdk_sqlite::SqliteCryptoStore;
use ruma::api::client::keys::{claim_keys, get_keys, upload_keys};
use ruma::api::client::sync::sync_events::DeviceLists;
use ruma::api::client::to_device::send_event_to_device;
use ruma::encryption::{DeviceKeys, OneTimeKey};
use ruma::serde::Raw;
use ruma::{
    OneTimeKeyAlgorithm, OwnedDeviceId, OwnedOneTimeKeyId, OwnedRoomId, OwnedUserId, RoomId, UInt,
    UserId,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const OLM: &str = "m.olm.v1.curve25519-aes-sha2";
pub const MEGOLM: &str = "m.megolm.v1.aes-sha2";

/// A new room session after this many messages, as the browser.
pub const ROTATE_MESSAGES: u32 = 100;
/// … or after this long.
pub const ROTATE_MS: u64 = 7 * 86_400_000;
/// A room's device list is read again after this long.
const DEVICES_FRESH: Duration = Duration::from_secs(30);

/// The phone's HTTP client, signed in as the person: `path` is under
/// `/api/v1` (`/chat/rooms/r1/devices`), `body` is JSON text. It answers
/// with the status and the body's text, or says why there was no answer.
pub trait Transport: Send + Sync {
    fn http(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> std::result::Result<(u16, String), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The phone's HTTP function gave no answer.
    Transport(String),
    /// The server answered with an error.
    Server { status: u16, body: String },
    /// The store could not be opened, read or written (a wrong passphrase).
    Store(String),
    /// What was asked does not hold (a bad device id, a room that is not
    /// end-to-end encrypted, an account of another person in the store).
    Invalid(String),
    /// A message this device does not open, and why.
    Refused(String),
    /// After `forget()`.
    Forgotten,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "no answer: {e}"),
            Error::Server { status, body } => write!(f, "the server answered {status}: {body}"),
            Error::Store(e) => write!(f, "the store: {e}"),
            Error::Invalid(e) => write!(f, "{e}"),
            Error::Refused(e) => write!(f, "not opened: {e}"),
            Error::Forgotten => write!(f, "this device was forgotten"),
        }
    }
}

impl std::error::Error for Error {}

mod trust;
pub use trust::{qr_payload, QrImage, RecoveryState, VerificationView};

pub type Result<T> = std::result::Result<T, Error>;

fn store_err(e: impl fmt::Display) -> Error {
    Error::Store(e.to_string())
}

/// A message opened: its text and the thread it is in (inside the seal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub text: String,
    pub thread: Option<String>,
    /// Its room key came from the key backup (or another import), not from
    /// the sender over Olm: the backup is not authenticated (the server
    /// knows its public key and can write to it), so who sent it is a claim
    /// that could not be confirmed. Show it as such. False once the sender's
    /// own key for the session has come.
    pub from_backup: bool,
}

/// What `inbox()` took in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inbox {
    /// To-device messages read (and removed from the server).
    pub messages: u32,
    /// Room keys among them that were taken.
    pub room_keys: u32,
}

/// A person of this server as Matrix names them, as the server does
/// (`store::mxid`): the user id in lower case.
pub fn mxid(user: &str, server_name: &str) -> String {
    format!("@{}:{server_name}", user.to_ascii_lowercase())
}

/// The server's rule for device ids (and one-time key ids).
pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The SDK names one-time keys in standard base64 (`+` and `/` can come);
/// the server takes letters, digits, `-` and `_`. The name is only a label:
/// a key is found by itself.
pub fn key_id_for_server(id: &str) -> String {
    id.chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// One path segment.
pub fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Matrix's canonical JSON: keys sorted, no spaces.
pub fn canonical(v: &Value) -> String {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical(&o[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

/// Whether JSON is signed Matrix's way by `entity`'s `key_id` with `ed`.
pub fn verify_json(value: &Value, entity: &str, key_id: &str, ed: &str) -> bool {
    let Some(sig) = value["signatures"][entity][key_id].as_str() else {
        return false;
    };
    let (Ok(key), Ok(sig)) = (
        Ed25519PublicKey::from_base64(ed),
        Ed25519Signature::from_base64(sig),
    ) else {
        return false;
    };
    let mut rest = value.clone();
    if let Some(o) = rest.as_object_mut() {
        o.remove("signatures");
        o.remove("unsigned");
    }
    key.verify(canonical(&rest).as_bytes(), &sig).is_ok()
}

/// When a room's session gives way to a new one, as the browser decides:
/// someone it was shared with has left (they keep what came before),
/// someone new has come (they read from then on), 100 messages, a week.
pub fn needs_new_session(
    shared_users: &HashSet<String>,
    users_now: &HashSet<String>,
    me: &str,
    count: u32,
    age_ms: u64,
) -> bool {
    let left = shared_users.iter().any(|u| !users_now.contains(u));
    let came = count > 0
        && users_now
            .iter()
            .any(|u| u != me && !shared_users.contains(u));
    left || came || count >= ROTATE_MESSAGES || age_ms > ROTATE_MS
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A member's device as this device knows it: self-signed, unchanged since
/// first seen, its Curve25519 key its own.
#[derive(Clone, Debug)]
struct Known {
    user: String,
    device: String,
    curve: String,
    ed: String,
    keys: Value,
}

struct RoomState {
    room_id: OwnedRoomId,
    devices: Vec<Known>,
    read_at: Option<Instant>,
}

/// This device's own session in a room.
#[derive(Serialize, Deserialize)]
struct Outbound {
    pickle: GroupSessionPickle,
    id: String,
    /// The key at index 0: members' new devices read the whole session.
    initial_key: String,
    /// `user|device` the key was given to (the server kept the message).
    shared_with: Vec<String>,
    created: u64,
    count: u32,
}

struct Inner {
    machine: OlmMachine,
    transport: Arc<dyn Transport>,
    me: OwnedUserId,
    device: OwnedDeviceId,
    rooms: HashMap<String, RoomState>,
    /// The latest devices read of each person (the same in every room).
    devices: HashMap<String, Vec<Known>>,
    /// A room each person was seen in (Olm messages the SDK sends on its
    /// own go through it).
    user_room: HashMap<String, String>,
    /// People's cross-signing keys as the server gave them (by Matrix id):
    /// master, selfSigning and (one's own) userSigning.
    cross: HashMap<String, Value>,
    /// People who sent this device verification messages.
    verifying: HashSet<OwnedUserId>,
}

/// End-to-end rooms for one person on one phone.
pub struct E2e {
    rt: tokio::runtime::Runtime,
    store_dir: PathBuf,
    inner: Mutex<Option<Inner>>,
}

impl E2e {
    /// Opens (or makes) this device's keys in `store_dir`, encrypted with
    /// `passphrase`, and publishes them. `user` is the person's Ortus id,
    /// `server_name` this server's Matrix name (the part after `:` in
    /// `me` of `GET /chat/rooms`).
    pub fn open(
        store_dir: &Path,
        passphrase: &str,
        user: &str,
        device: &str,
        server_name: &str,
        transport: Arc<dyn Transport>,
    ) -> Result<E2e> {
        if !valid_id(device) {
            return Err(Error::Invalid(
                "A device id is letters, digits, - and _.".into(),
            ));
        }
        let me = UserId::parse(mxid(user, server_name))
            .map_err(|e| Error::Invalid(format!("not a Matrix user id: {e}")))?;
        let device: OwnedDeviceId = device.into();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(store_err)?;
        let inner = rt.block_on(async {
            std::fs::create_dir_all(store_dir).map_err(store_err)?;
            let store = SqliteCryptoStore::open(store_dir, Some(passphrase))
                .await
                .map_err(store_err)?;
            let machine = OlmMachineBuilder::new(&me, &device)
                .with_crypto_store(store)
                .build()
                .await
                .map_err(|e| Error::Invalid(e.to_string()))?;
            let mut inner = Inner {
                machine,
                transport,
                me,
                device,
                rooms: HashMap::new(),
                devices: HashMap::new(),
                user_room: HashMap::new(),
                cross: HashMap::new(),
                verifying: HashSet::new(),
            };
            inner.publish().await?;
            Ok::<_, Error>(inner)
        })?;
        Ok(E2e {
            rt,
            store_dir: store_dir.to_path_buf(),
            inner: Mutex::new(Some(inner)),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Inner>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// This device's Matrix user id and device id.
    pub fn whoami(&self) -> Result<(String, String)> {
        let guard = self.lock();
        let inner = guard.as_ref().ok_or(Error::Forgotten)?;
        Ok((inner.me.to_string(), inner.device.to_string()))
    }

    /// Reads and takes in the to-device messages waiting for this device
    /// (room keys), and keeps its one-time keys topped up.
    pub fn inbox(&self) -> Result<Inbox> {
        let mut guard = self.lock();
        let inner = guard.as_mut().ok_or(Error::Forgotten)?;
        self.rt.block_on(inner.inbox())
    }

    /// Opens a message of `room` (the message JSON as the chat API gives
    /// it: `id`, `sender`, `thread`, `sealed`).
    pub fn decrypt(&self, room: &str, message_json: &str) -> Result<Opened> {
        let message: Value = serde_json::from_str(message_json)
            .map_err(|e| Error::Invalid(format!("not a message: {e}")))?;
        let mut guard = self.lock();
        let inner = guard.as_mut().ok_or(Error::Forgotten)?;
        self.rt.block_on(inner.decrypt(room, &message))
    }

    /// Seals `text` (in `thread`, a root message's id) and sends it,
    /// sharing this device's room session with members' devices that lack
    /// it first. Answers the new message's id.
    pub fn send(&self, room: &str, text: &str, thread: Option<&str>) -> Result<String> {
        let mut guard = self.lock();
        let inner = guard.as_mut().ok_or(Error::Forgotten)?;
        self.rt.block_on(inner.send(room, text, thread))
    }

    fn with<T>(
        &self,
        f: impl for<'a> FnOnce(
            &'a mut Inner,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + 'a>>,
    ) -> Result<T> {
        let mut guard = self.lock();
        let inner = guard.as_mut().ok_or(Error::Forgotten)?;
        self.rt.block_on(f(inner))
    }

    /// Where recovery stands: set up for the person, and opened on this phone.
    pub fn recovery_state(&self) -> Result<RecoveryState> {
        self.with(|i| Box::pin(i.recovery_state()))
    }

    /// Recovery on this phone with the recovery key: the cross-signing keys
    /// open, this device is signed, and the backup (one the master key
    /// signed) is restored and kept up. Answers how many room keys came back.
    pub fn recover(&self, recovery_key: &str) -> Result<u32> {
        let key = recovery_key.to_string();
        self.with(move |i| Box::pin(async move { i.recover(&key).await }))
    }

    /// Sets recovery up from this phone (nobody set it up yet): answers the
    /// recovery key, to show once.
    pub fn set_up_recovery(&self) -> Result<String> {
        self.with(|i| Box::pin(i.set_up_recovery()))
    }

    /// Asks one device (another person's, or one's own) to verify.
    pub fn verify_device(&self, user: &str, device: &str) -> Result<String> {
        let (user, device) = (user.to_string(), device.to_string());
        self.with(move |i| Box::pin(async move { i.verify_device(&user, &device).await }))
    }

    /// Emoji, chosen over a QR code.
    pub fn start_emoji(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.with(move |i| Box::pin(async move { i.start_emoji(&id).await }))
    }

    /// The other device's QR code, as the camera read it.
    pub fn scan_qr(&self, id: &str, scanned: &[u8]) -> Result<()> {
        let (id, scanned) = (id.to_string(), scanned.to_vec());
        self.with(move |i| Box::pin(async move { i.scan_qr(&id, &scanned).await }))
    }

    /// This phone's QR code, for the other device to scan.
    pub fn show_qr(&self, id: &str) -> Result<QrImage> {
        let id = id.to_string();
        self.with(move |i| Box::pin(async move { i.show_qr(&id).await }))
    }

    /// Whether the other device said it scanned this phone's code.
    pub fn confirm_scanned(&self, id: &str, yes: bool) -> Result<()> {
        let id = id.to_string();
        self.with(move |i| Box::pin(async move { i.confirm_scanned(&id, yes).await }))
    }

    /// A room's devices nobody vouched for: (person, device).
    pub fn unverified(&self, room: &str) -> Result<Vec<(String, String)>> {
        let room = room.to_string();
        self.with(move |i| Box::pin(async move { i.unverified(&room).await }))
    }

    /// Takes in what came for this device and moves verifications on:
    /// how each stands (the screen polls it).
    pub fn verifications(&self) -> Result<Vec<VerificationView>> {
        self.with(|i| Box::pin(i.verifications()))
    }

    /// Asks one's own other devices to verify with this one.
    pub fn verify_own_devices(&self) -> Result<String> {
        self.with(|i| Box::pin(i.verify_own_devices()))
    }

    pub fn accept_verification(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.with(move |i| Box::pin(async move { i.accept_verification(&id).await }))
    }

    /// The person says whether the emoji are the same on both screens.
    pub fn confirm_verification(&self, id: &str, same: bool) -> Result<()> {
        let id = id.to_string();
        self.with(move |i| Box::pin(async move { i.confirm_verification(&id, same).await }))
    }

    pub fn cancel_verification(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        self.with(move |i| Box::pin(async move { i.cancel_verification(&id).await }))
    }

    /// Forgets this device: the server is asked to drop its published
    /// keys and waiting messages (offline, it stays until the person's
    /// eleventh device replaces it), and its keys and sessions are deleted
    /// from the phone.
    pub fn forget(&self) -> Result<()> {
        let mut guard = self.lock();
        if let Some(inner) = guard.take() {
            let path = format!("/chat/devices/{}", enc(inner.device.as_str()));
            // Signing out goes on without an answer: the phone forgets anyway.
            let _ = self.rt.block_on(inner.http("DELETE", &path, None));
            // The store's pool is let go inside its runtime.
            let _in = self.rt.enter();
            drop(inner);
        }
        if let Ok(entries) = std::fs::read_dir(&self.store_dir) {
            for e in entries.flatten() {
                if e.file_name()
                    .to_string_lossy()
                    .starts_with("matrix-sdk-crypto")
                {
                    std::fs::remove_file(e.path()).map_err(store_err)?;
                }
            }
        }
        Ok(())
    }
}

impl Drop for E2e {
    fn drop(&mut self) {
        let inner = self.lock().take();
        let _in = self.rt.enter();
        drop(inner);
    }
}

fn decryption_settings() -> DecryptionSettings {
    // Who may send is checked here (trust on first use), not by
    // cross-signing, which Ortus does not have yet.
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

impl Inner {
    async fn http(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let text = body.map(|b| b.to_string());
        let (status, answer) = self
            .transport
            .http(method, path, text.as_deref())
            .map_err(Error::Transport)?;
        if !(200..300).contains(&status) {
            return Err(Error::Server {
                status,
                body: answer,
            });
        }
        if answer.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&answer)
            .map_err(|e| Error::Transport(format!("not JSON from {path}: {e}")))
    }

    async fn custom<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let raw = self
            .machine
            .store()
            .get_custom_value(key)
            .await
            .map_err(store_err)?;
        Ok(raw.and_then(|b| serde_json::from_slice(&b).ok()))
    }

    async fn set_custom<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(store_err)?;
        self.machine
            .store()
            .set_custom_value(key, bytes)
            .await
            .map_err(store_err)
    }

    /// This device's signed device keys, as the server keeps them.
    async fn own_device_keys(&self) -> Result<Value> {
        let own = self
            .machine
            .get_device(&self.me, &self.device, None)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Store("this device is not in its store".into()))?;
        serde_json::to_value(own.as_device_keys()).map_err(store_err)
    }

    /// Publishes this device's keys (again: the server may have let the
    /// device go) and tops its one-time keys up.
    async fn publish(&mut self) -> Result<()> {
        let uploaded = self.process(None).await?;
        if !uploaded {
            let keys = self.own_device_keys().await?;
            let r = self
                .http(
                    "PUT",
                    &format!("/chat/devices/{}", enc(self.device.as_str())),
                    Some(json!({"deviceKeys": keys, "oneTimeKeys": {}, "fallbackKeys": {}})),
                )
                .await?;
            self.counts(&r, Vec::new()).await?;
            self.process(None).await?;
        }
        Ok(())
    }

    /// Gives the SDK the server's one-time key count, a fallback key's
    /// presence and to-device messages; answers the room keys taken.
    async fn counts(
        &self,
        r: &Value,
        events: Vec<Raw<ruma::events::AnyToDeviceEvent>>,
    ) -> Result<u32> {
        let mut counts = BTreeMap::new();
        let n = r["oneTimeKeyCount"].as_u64().unwrap_or(0);
        counts.insert(
            OneTimeKeyAlgorithm::SignedCurve25519,
            UInt::new(n).unwrap_or_default(),
        );
        let fallback: Vec<OneTimeKeyAlgorithm> = if r["fallbackKey"] == true {
            vec![OneTimeKeyAlgorithm::SignedCurve25519]
        } else {
            Vec::new()
        };
        let lists = DeviceLists::default();
        let (_, keys) = self
            .machine
            .receive_sync_changes(
                EncryptionSyncChanges {
                    to_device_events: events,
                    changed_devices: &lists,
                    one_time_keys_counts: &counts,
                    unused_fallback_keys: Some(&fallback),
                    next_batch_token: None,
                },
                &decryption_settings(),
            )
            .await
            .map_err(store_err)?;
        Ok(keys.len() as u32)
    }

    /// Sends what the SDK asks to send, through Ortus's calls. Answers
    /// whether keys were uploaded.
    async fn process(&mut self, room: Option<&str>) -> Result<bool> {
        let mut uploaded = false;
        // A person the server says nothing of stays asked about: a few
        // rounds, not forever.
        for _ in 0..4 {
            let requests = self.machine.outgoing_requests().await.map_err(store_err)?;
            if requests.is_empty() {
                break;
            }
            for r in requests {
                let id = r.request_id().to_owned();
                match r.request() {
                    AnyOutgoingRequest::KeysUpload(u) => {
                        let response = self.upload(u).await?;
                        self.machine
                            .mark_request_as_sent(&id, &response)
                            .await
                            .map_err(store_err)?;
                        uploaded = true;
                    }
                    AnyOutgoingRequest::KeysQuery(q) => {
                        let response = self.keys_query(q.device_keys.keys());
                        self.machine
                            .mark_request_as_sent(&id, &response)
                            .await
                            .map_err(store_err)?;
                    }
                    AnyOutgoingRequest::KeysClaim(c) => {
                        let wanted: Vec<(String, String)> = c
                            .one_time_keys
                            .iter()
                            .flat_map(|(u, d)| {
                                d.keys().map(move |d| (u.to_string(), d.to_string()))
                            })
                            .collect();
                        let response = self.claim(room, &wanted).await?;
                        self.machine
                            .mark_request_as_sent(&id, &response)
                            .await
                            .map_err(store_err)?;
                    }
                    AnyOutgoingRequest::ToDeviceRequest(t)
                        if Self::outgoing_kind(r.request()).is_some() =>
                    {
                        self.forward_verification(t).await?;
                        self.machine
                            .mark_request_as_sent(&id, &send_event_to_device::v3::Response::new())
                            .await
                            .map_err(store_err)?;
                    }
                    AnyOutgoingRequest::SignatureUpload(u) => {
                        self.upload_signatures(&u.signed_keys).await?;
                        self.machine
                            .mark_request_as_sent(
                                &id,
                                &ruma::api::client::keys::upload_signatures::v3::Response::new(),
                            )
                            .await
                            .map_err(store_err)?;
                    }
                    AnyOutgoingRequest::ToDeviceRequest(t) => {
                        self.forward(t).await?;
                        self.machine
                            .mark_request_as_sent(&id, &send_event_to_device::v3::Response::new())
                            .await
                            .map_err(store_err)?;
                    }
                    // Cross-signing and room messages are not asked for
                    // (no verification yet; rooms are sealed here).
                    _ => {}
                }
            }
        }
        Ok(uploaded)
    }

    async fn upload(&self, u: &upload_keys::v3::Request) -> Result<upload_keys::v3::Response> {
        let keys = match &u.device_keys {
            Some(k) => serde_json::to_value(k).map_err(store_err)?,
            None => self.own_device_keys().await?,
        };
        let rename = |m: &BTreeMap<OwnedOneTimeKeyId, Raw<OneTimeKey>>| -> Value {
            let mut out = serde_json::Map::new();
            for (id, key) in m {
                let name = key_id_for_server(id.key_name().as_str());
                out.insert(
                    format!("signed_curve25519:{name}"),
                    serde_json::from_str(key.json().get()).unwrap_or(Value::Null),
                );
            }
            Value::Object(out)
        };
        let r = self
            .http(
                "PUT",
                &format!("/chat/devices/{}", enc(self.device.as_str())),
                Some(json!({"deviceKeys": keys, "oneTimeKeys": rename(&u.one_time_keys), "fallbackKeys": rename(&u.fallback_keys)})),
            )
            .await?;
        let mut counts = BTreeMap::new();
        counts.insert(
            OneTimeKeyAlgorithm::SignedCurve25519,
            UInt::new(r["oneTimeKeyCount"].as_u64().unwrap_or(0)).unwrap_or_default(),
        );
        Ok(upload_keys::v3::Response::new(counts))
    }

    /// The devices of the people asked about, as last read from a room's
    /// list (this device's own when none was read yet).
    fn keys_query<'a>(
        &self,
        users: impl Iterator<Item = &'a OwnedUserId>,
    ) -> get_keys::v3::Response {
        let mut response = get_keys::v3::Response::new();
        for user in users {
            let mut devices = BTreeMap::new();
            match self.devices.get(user.as_str()) {
                Some(list) => {
                    for d in list {
                        if let Ok(raw) = serde_json::from_value::<Raw<DeviceKeys>>(d.keys.clone()) {
                            devices.insert(OwnedDeviceId::from(d.device.as_str()), raw);
                        }
                    }
                }
                None => continue,
            }
            response.device_keys.insert(user.clone(), devices);
            let keys = self
                .cross
                .get(user.as_str())
                .cloned()
                .unwrap_or(Value::Null);
            if let Ok(k) = serde_json::from_value(keys["master"].clone()) {
                response.master_keys.insert(user.clone(), k);
            }
            if let Ok(k) = serde_json::from_value(keys["selfSigning"].clone()) {
                response.self_signing_keys.insert(user.clone(), k);
            }
            if let Ok(k) = serde_json::from_value(keys["userSigning"].clone()) {
                response.user_signing_keys.insert(user.clone(), k);
            }
        }
        response
    }

    async fn claim(
        &self,
        room: Option<&str>,
        wanted: &[(String, String)],
    ) -> Result<claim_keys::v3::Response> {
        let mut out: BTreeMap<
            OwnedUserId,
            BTreeMap<OwnedDeviceId, BTreeMap<OwnedOneTimeKeyId, Raw<OneTimeKey>>>,
        > = BTreeMap::new();
        let Some(room) = room.or_else(|| {
            wanted
                .first()
                .and_then(|(u, _)| self.user_room.get(u))
                .map(String::as_str)
        }) else {
            return Ok(claim_keys::v3::Response::new(out));
        };
        let devices: Vec<Value> = wanted
            .iter()
            .map(|(u, d)| json!({"user": u, "device": d}))
            .collect();
        let r = self
            .http(
                "POST",
                &format!("/chat/rooms/{}/claim", enc(room)),
                Some(json!({"devices": devices})),
            )
            .await?;
        if let Some(users) = r["oneTimeKeys"].as_object() {
            for (user, devices) in users {
                let Ok(user) = UserId::parse(user.as_str()) else {
                    continue;
                };
                for (device, keys) in devices.as_object().into_iter().flatten() {
                    for (id, key) in keys.as_object().into_iter().flatten() {
                        let (Ok(id), Ok(key)) = (
                            OwnedOneTimeKeyId::try_from(id.as_str()),
                            serde_json::from_value::<Raw<OneTimeKey>>(key.clone()),
                        ) else {
                            continue;
                        };
                        out.entry(user.clone())
                            .or_default()
                            .entry(OwnedDeviceId::from(device.as_str()))
                            .or_default()
                            .insert(id, key);
                    }
                }
            }
        }
        Ok(claim_keys::v3::Response::new(out))
    }

    /// Olm messages the SDK sends on its own (a new session after one that
    /// broke): through a room shared with their recipient, when there is one.
    async fn forward(&self, t: &ToDeviceRequest) -> Result<()> {
        if t.event_type.to_string() != "m.room.encrypted" {
            return Ok(());
        }
        let mut by_room: HashMap<String, Vec<Value>> = HashMap::new();
        for (user, devices) in &t.messages {
            let Some(room) = self.user_room.get(user.as_str()) else {
                continue;
            };
            for (device, content) in devices {
                let ruma::to_device::DeviceIdOrAllDevices::DeviceId(device) = device else {
                    continue;
                };
                let content: Value =
                    serde_json::from_str(content.json().get()).unwrap_or(Value::Null);
                by_room
                    .entry(room.clone())
                    .or_default()
                    .push(json!({"user": user, "device": device, "content": content}));
            }
        }
        for (room, messages) in by_room {
            self.http(
                "POST",
                &format!("/chat/rooms/{}/to-device", enc(&room)),
                Some(json!({"fromDevice": self.device.as_str(), "messages": messages})),
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn take_inbox(&mut self) -> Result<Inbox> {
        self.inbox().await
    }

    /// Tells the SDK these people's devices (or cross-signing keys) changed.
    pub(crate) async fn changed(&mut self, users: &[OwnedUserId]) -> Result<()> {
        self.machine
            .update_tracked_users(users.iter().map(|u| u.as_ref()))
            .await
            .map_err(store_err)?;
        let mut lists = DeviceLists::default();
        lists.changed = users.to_vec();
        self.machine
            .receive_sync_changes(
                EncryptionSyncChanges {
                    to_device_events: Vec::new(),
                    changed_devices: &lists,
                    one_time_keys_counts: &BTreeMap::new(),
                    unused_fallback_keys: None,
                    next_batch_token: None,
                },
                &decryption_settings(),
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn inbox(&mut self) -> Result<Inbox> {
        let r = self
            .http(
                "GET",
                &format!("/chat/devices/{}/inbox", enc(self.device.as_str())),
                None,
            )
            .await?;
        let messages = r["messages"].as_array().cloned().unwrap_or_default();
        // Verification messages: their senders' keys first, so the SDK knows
        // the device that speaks.
        let senders: HashSet<String> = messages
            .iter()
            .filter(|m| {
                m["type"]
                    .as_str()
                    .is_some_and(|t| t.starts_with("m.key.verification."))
            })
            .filter_map(|m| m["sender"].as_str().map(str::to_string))
            .collect();
        for sender in senders {
            self.note_verifying(&sender);
            self.read_keys_of(&sender).await?;
            self.process(None).await?;
        }
        let mut events = Vec::new();
        let mut ids = Vec::new();
        for m in &messages {
            ids.push(m["id"].clone());
            // Olm messages are m.room.encrypted; verification messages come
            // with their own type (m.key.verification.*).
            let kind = m["type"].as_str().unwrap_or("m.room.encrypted");
            let event = json!({"type": kind, "sender": m["sender"], "content": m["content"]});
            if let Ok(raw) = serde_json::from_value(event) {
                events.push(raw);
            }
        }
        let room_keys = self.counts(&r, events).await?;
        // Taken in (or not to be opened by this device ever): they go.
        if !ids.is_empty() {
            self.http(
                "POST",
                &format!("/chat/devices/{}/inbox/done", enc(self.device.as_str())),
                Some(json!({"ids": ids})),
            )
            .await?;
        }
        self.process(None).await?;
        Ok(Inbox {
            messages: messages.len() as u32,
            room_keys,
        })
    }

    /// The room's Matrix id and its members' devices (read again when
    /// `fresh` or after a while), told to the SDK.
    async fn room(&mut self, room: &str, fresh: bool) -> Result<OwnedRoomId> {
        if !self.rooms.contains_key(room) {
            let r = self
                .http("GET", &format!("/chat/rooms/{}", enc(room)), None)
                .await?;
            let info = if r["room"].is_object() {
                &r["room"]
            } else {
                &r
            };
            if info["encrypted"] != true {
                return Err(Error::Invalid(
                    "This room is not end-to-end encrypted.".into(),
                ));
            }
            let room_id = info["roomId"]
                .as_str()
                .and_then(|s| RoomId::parse(s).ok())
                .ok_or_else(|| Error::Invalid("The room has no Matrix id.".into()))?;
            self.rooms.insert(
                room.to_string(),
                RoomState {
                    room_id,
                    devices: Vec::new(),
                    read_at: None,
                },
            );
        }
        let state = &self.rooms[room];
        let room_id = state.room_id.clone();
        if !fresh && state.read_at.is_some_and(|t| t.elapsed() < DEVICES_FRESH) {
            return Ok(room_id);
        }
        let r = self
            .http("GET", &format!("/chat/rooms/{}/devices", enc(room)), None)
            .await?;
        let mut known = Vec::new();
        for d in r["devices"].as_array().into_iter().flatten() {
            if let Some(k) = self.check_device(d).await? {
                known.push(k);
            }
        }
        if let Some(people) = r["crossSigning"].as_object() {
            for (who, keys) in people {
                self.cross.insert(who.clone(), keys.clone());
            }
        }
        // A Curve25519 key is one device's: two naming it are both refused.
        let all = known.clone();
        known.retain(|d| all.iter().filter(|o| o.curve == d.curve).count() == 1);
        let mut by_user: HashMap<String, Vec<Known>> = HashMap::new();
        for d in &known {
            by_user.entry(d.user.clone()).or_default().push(d.clone());
        }
        let users: Vec<OwnedUserId> = r["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d["user"].as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .filter_map(|u| UserId::parse(u).ok())
            .collect();
        for u in &users {
            self.devices.insert(
                u.to_string(),
                by_user.remove(u.as_str()).unwrap_or_default(),
            );
            self.user_room.insert(u.to_string(), room.to_string());
        }
        if let Some(s) = self.rooms.get_mut(room) {
            s.devices = known;
            s.read_at = Some(Instant::now());
        }
        // Ortus has no feed of device changes: the room's people are asked
        // about each time their list is read.
        self.machine
            .update_tracked_users(users.iter().map(|u| u.as_ref()))
            .await
            .map_err(store_err)?;
        let mut lists = DeviceLists::default();
        lists.changed = users;
        self.machine
            .receive_sync_changes(
                EncryptionSyncChanges {
                    to_device_events: Vec::new(),
                    changed_devices: &lists,
                    one_time_keys_counts: &BTreeMap::new(),
                    unused_fallback_keys: None,
                    next_batch_token: None,
                },
                &decryption_settings(),
            )
            .await
            .map_err(store_err)?;
        self.process(Some(room)).await?;
        Ok(room_id)
    }

    /// A device of the list, when its keys are its own (self-signed) and
    /// the ones first seen (trust on first use).
    async fn check_device(&self, d: &Value) -> Result<Option<Known>> {
        let (Some(user), Some(device)) = (d["user"].as_str(), d["device"].as_str()) else {
            return Ok(None);
        };
        let k = &d["deviceKeys"];
        let (Some(curve), Some(ed)) = (
            k["keys"][format!("curve25519:{device}")].as_str(),
            k["keys"][format!("ed25519:{device}")].as_str(),
        ) else {
            return Ok(None);
        };
        if k["user_id"] != user
            || k["device_id"] != device
            || !verify_json(k, user, &format!("ed25519:{device}"), ed)
        {
            return Ok(None);
        }
        let seen_key = format!("ortus.seen.{user}|{device}");
        let now = format!("{curve}|{ed}");
        match self.custom::<String>(&seen_key).await? {
            Some(before) if before != now => return Ok(None),
            Some(_) => {}
            None => self.set_custom(&seen_key, &now).await?,
        }
        Ok(Some(Known {
            user: user.into(),
            device: device.into(),
            curve: curve.into(),
            ed: ed.into(),
            keys: k.clone(),
        }))
    }

    async fn send(&mut self, room: &str, text: &str, thread: Option<&str>) -> Result<String> {
        let room_id = self.room(room, true).await?;
        let ours = self.machine.identity_keys();
        let me = self.me.to_string();
        let devices = self.rooms[room].devices.clone();
        let users: HashSet<String> = devices.iter().map(|d| d.user.clone()).collect();
        let out_key = format!("ortus.out.{room}");
        let mut out: Option<Outbound> = self.custom(&out_key).await?;
        let renew = match &out {
            None => true,
            Some(o) => {
                let shared: HashSet<String> = o
                    .shared_with
                    .iter()
                    .filter_map(|k| k.split('|').next().map(str::to_string))
                    .collect();
                needs_new_session(
                    &shared,
                    &users,
                    &me,
                    o.count,
                    now_ms().saturating_sub(o.created),
                )
            }
        };
        if renew {
            let session = GroupSession::new(SessionConfig::version_1());
            let key = session.session_key();
            // This device reads its own messages too.
            let inbound = InboundGroupSession::new(
                ours.curve25519,
                ours.ed25519,
                &room_id,
                &key,
                SenderData::unknown(),
                None,
                EventEncryptionAlgorithm::MegolmV1AesSha2,
                None,
                false,
            )
            .map_err(store_err)?;
            self.machine
                .store()
                .save_changes(Changes {
                    inbound_group_sessions: vec![inbound],
                    ..Default::default()
                })
                .await
                .map_err(store_err)?;
            out = Some(Outbound {
                id: session.session_id(),
                initial_key: key.to_base64(),
                pickle: session.pickle(),
                shared_with: Vec::new(),
                created: now_ms(),
                count: 0,
            });
        }
        let mut out = out.ok_or_else(|| Error::Store("no session".into()))?;
        let targets: Vec<Known> = devices
            .into_iter()
            .filter(|d| !(d.user == me && d.device == self.device.as_str()))
            .filter(|d| {
                !out.shared_with
                    .contains(&format!("{}|{}", d.user, d.device))
            })
            .collect();
        if !targets.is_empty() {
            self.share(room, &room_id, &mut out, &targets).await?;
        }
        self.set_custom(&out_key, &out).await?;
        // The thread is inside the seal, so the server cannot move it.
        let mut content = json!({"msgtype": "m.text", "body": text});
        if let Some(t) = thread {
            content["m.relates_to"] = json!({"rel_type": "m.thread", "event_id": t});
        }
        let plaintext = json!({"type": "m.room.message", "content": content, "room_id": room_id});
        let mut session = GroupSession::from_pickle(out.pickle);
        let ciphertext = session.encrypt(plaintext.to_string()).to_base64();
        out.pickle = session.pickle();
        out.count += 1;
        let session_id = out.id.clone();
        self.set_custom(&out_key, &out).await?;
        let r = self
            .http(
                "POST",
                &format!("/chat/rooms/{}/sealed", enc(room)),
                Some(json!({"algorithm": MEGOLM, "sender_key": ours.curve25519.to_base64(), "ciphertext": ciphertext,
                            "session_id": session_id, "device_id": self.device.as_str(), "thread": thread})),
            )
            .await?;
        Ok(r["id"].as_str().unwrap_or_default().to_string())
    }

    /// Gives the room key (at index 0, with Ortus's room id) to the
    /// devices that lack it, over Olm: an Olm session to each, from before
    /// or from one of their one-time keys.
    async fn share(
        &mut self,
        room: &str,
        room_id: &RoomId,
        out: &mut Outbound,
        targets: &[Known],
    ) -> Result<()> {
        let users: Vec<OwnedUserId> = targets
            .iter()
            .filter_map(|t| UserId::parse(t.user.as_str()).ok())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        if let Some((id, request)) = self
            .machine
            .get_missing_sessions(users.iter().map(|u| u.as_ref()))
            .await
            .map_err(store_err)?
        {
            let wanted: Vec<(String, String)> = request
                .one_time_keys
                .iter()
                .flat_map(|(u, d)| d.keys().map(move |d| (u.to_string(), d.to_string())))
                .collect();
            let response = self.claim(Some(room), &wanted).await?;
            self.machine
                .mark_request_as_sent(&id, &response)
                .await
                .map_err(store_err)?;
        }
        let content = json!({"algorithm": MEGOLM, "room_id": room_id, "session_id": out.id,
                             "session_key": out.initial_key, "org.ortus.room": room});
        let mut messages = Vec::new();
        let mut meant = Vec::new();
        for t in targets {
            let Ok(user) = UserId::parse(t.user.as_str()) else {
                continue;
            };
            let device: OwnedDeviceId = t.device.as_str().into();
            let Some(d) = self
                .machine
                .get_device(&user, &device, None)
                .await
                .map_err(store_err)?
            else {
                continue;
            };
            // The SDK's view of the device must be the one checked here.
            if d.curve25519_key().map(|k| k.to_base64()).as_deref() != Some(t.curve.as_str())
                || d.ed25519_key().map(|k| k.to_base64()).as_deref() != Some(t.ed.as_str())
            {
                continue;
            }
            let Ok(sealed) = d
                .encrypt_event_raw("m.room_key", &content, CollectStrategy::AllDevices)
                .await
            else {
                continue;
            };
            let sealed: Value = serde_json::from_str(sealed.json().get()).unwrap_or(Value::Null);
            messages.push(json!({"user": t.user, "device": t.device, "content": sealed}));
            meant.push(format!("{}|{}", t.user, t.device));
        }
        if messages.is_empty() {
            return Ok(());
        }
        // Shared with a device only once the server has kept its message.
        let r = self
            .http(
                "POST",
                &format!("/chat/rooms/{}/to-device", enc(room)),
                Some(json!({"fromDevice": self.device.as_str(), "messages": messages})),
            )
            .await?;
        for i in r["stored"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
        {
            if let Some(m) = meant.get(i as usize) {
                out.shared_with.push(m.clone());
            }
        }
        Ok(())
    }

    async fn decrypt(&mut self, room: &str, m: &Value) -> Result<Opened> {
        let refused = |why: &str| Err(Error::Refused(why.into()));
        let s = &m["sealed"];
        let (Some(id), Some(sender)) = (m["id"].as_str(), m["sender"].as_str()) else {
            return refused("not a message");
        };
        if s["algorithm"] != MEGOLM {
            return refused("not a Megolm message");
        }
        let (Some(sender_key), Some(session_id), Some(ciphertext)) = (
            s["sender_key"].as_str(),
            s["session_id"].as_str(),
            s["ciphertext"].as_str(),
        ) else {
            return refused("not a Megolm message");
        };
        let thread = m["thread"].as_str().map(str::to_string);
        let room_id = self.room(room, false).await?;
        // The cleartext carries no relation: the thread is the seal's own.
        let event = json!({
            "type": "m.room.encrypted", "event_id": id, "sender": sender, "room_id": room_id,
            "origin_server_ts": m["at"].as_u64().unwrap_or(0),
            "content": {"algorithm": MEGOLM, "sender_key": sender_key, "ciphertext": ciphertext,
                        "session_id": session_id, "device_id": s["device_id"]},
        });
        let raw: Raw<_> =
            serde_json::from_value(event).map_err(|e| Error::Refused(e.to_string()))?;
        let mut result = self
            .machine
            .decrypt_room_event(&raw, &room_id, &decryption_settings())
            .await;
        if result.is_err() {
            // A room key that came since: once more after the inbox.
            self.inbox().await?;
            result = self
                .machine
                .decrypt_room_event(&raw, &room_id, &decryption_settings())
                .await;
        }
        let decrypted = match result {
            Ok(d) => d,
            Err(e) => return refused(&e.to_string()),
        };
        // The session must be the one of the sender key the message names …
        let session = self
            .machine
            .store()
            .get_inbound_group_session(&room_id, session_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Refused("no session".into()))?;
        if session.sender_key().to_base64() != sender_key {
            return refused("the session is another device's");
        }
        let ed = session
            .signing_keys()
            .get(&ruma::DeviceKeyAlgorithm::Ed25519)
            .and_then(|k| k.ed25519())
            .map(|k| k.to_base64())
            .unwrap_or_default();
        // … and of a device of the sender, with the keys first seen.
        let ours = self.machine.identity_keys();
        let own = sender == self.me.as_str()
            && sender_key == ours.curve25519.to_base64()
            && ed == ours.ed25519.to_base64();
        if !own {
            let mut found = self.sender_device(room, sender, sender_key, &ed);
            if !found {
                self.room(room, true).await?;
                found = self.sender_device(room, sender, sender_key, &ed);
            }
            if !found {
                return refused("the session is not a device of the sender's");
            }
        }
        let plain: Value = serde_json::from_str(decrypted.event.json().get())
            .map_err(|e| Error::Refused(e.to_string()))?;
        let Some(text) = plain["content"]["body"].as_str() else {
            return refused("no text");
        };
        if plain["type"] != "m.room.message" {
            return refused("not a message");
        }
        let rel = &plain["content"]["m.relates_to"];
        let sealed_thread = if rel["rel_type"] == "m.thread" {
            rel["event_id"].as_str().map(str::to_string)
        } else {
            None
        };
        if sealed_thread != thread {
            return refused("the message was moved to another thread");
        }
        // One message per index: the same ciphertext again is a replay.
        let index = MegolmMessage::from_base64(ciphertext)
            .map_err(|e| Error::Refused(e.to_string()))?
            .message_index();
        let seen_key = format!("ortus.idx.{room_id}|{sender_key}|{session_id}|{index}");
        match self.custom::<String>(&seen_key).await? {
            Some(e) if e != id => return refused("a replay of another message"),
            Some(_) => {}
            None => self.set_custom(&seen_key, &id.to_string()).await?,
        }
        Ok(Opened {
            text: text.to_string(),
            thread,
            from_backup: session.has_been_imported(),
        })
    }

    fn sender_device(&self, room: &str, sender: &str, curve: &str, ed: &str) -> bool {
        self.rooms.get(room).is_some_and(|s| {
            s.devices
                .iter()
                .any(|d| d.user == sender && d.curve == curve && d.ed == ed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_as_the_server_and_the_browser_make_them() {
        assert_eq!("@ab12:chat.example", mxid("AB12", "chat.example"));
        assert!(valid_id("PHONE_1-a"));
        assert!(!valid_id("a/b") && !valid_id("") && !valid_id(&"a".repeat(65)));
        // The SDK's base64 key names become names the server takes.
        assert_eq!("AAAAAAAAAA-_", key_id_for_server("AAAAAAAAAA+/"));
        assert!(valid_id(&key_id_for_server("AAAAAAAAAB+")));
        assert_eq!("r%2F1%20x", enc("r/1 x"));
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = json!({"b": 1, "a": {"d": [1, "x"], "c": null}});
        assert_eq!(r#"{"a":{"c":null,"d":[1,"x"]},"b":1}"#, canonical(&v));
    }

    #[test]
    fn a_new_session_as_the_browser_decides() {
        let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<HashSet<_>>();
        let (me, both) = ("@a:x", set(&["@a:x", "@b:x"]));
        assert!(!needs_new_session(&both, &both, me, 5, 1000));
        // Someone left; someone came (once the session was used).
        assert!(needs_new_session(&both, &set(&["@a:x"]), me, 5, 1000));
        assert!(needs_new_session(&set(&["@a:x"]), &both, me, 1, 1000));
        assert!(!needs_new_session(&set(&["@a:x"]), &both, me, 0, 1000));
        // 100 messages, a week.
        assert!(needs_new_session(&both, &both, me, ROTATE_MESSAGES, 1000));
        assert!(needs_new_session(&both, &both, me, 1, ROTATE_MS + 1));
    }
}
