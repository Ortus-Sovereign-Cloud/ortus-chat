//! Trust on the phone (docs/e2e-trust-and-backup.md), by matrix-sdk-crypto:
//! recovery with the recovery key (secret storage opens the cross-signing
//! keys and the backup key; this device is signed; the backup, only one the
//! master key signed, is restored and kept up), who in a room is not
//! vouched for, and verification by emoji with other devices (the browser's
//! or another phone's). The server routes are chat's trust.rs.

use std::collections::BTreeMap;

use matrix_sdk_crypto::backups::DecryptionError;
use matrix_sdk_crypto::matrix_sdk_qrcode::QrVerificationData;
use matrix_sdk_crypto::olm::ExportedRoomKey;
use matrix_sdk_crypto::secret_storage::{AesHmacSha2EncryptedData, SecretStorageKey};
use matrix_sdk_crypto::store::types::{BackupDecryptionKey, CrossSigningKeyExport};
use matrix_sdk_crypto::types::requests::{
    AnyOutgoingRequest, OutgoingVerificationRequest, ToDeviceRequest,
};
use matrix_sdk_crypto::{Verification, VerificationRequest};
use ruma::api::client::backup::add_backup_keys;
use ruma::api::client::keys::upload_signatures;
use ruma::events::key::verification::VerificationMethod;
use ruma::events::secret::request::SecretName;
use ruma::events::secret_storage::key::{
    SecretStorageEncryptionAlgorithm, SecretStorageKeyEventContent,
    SecretStorageV1AesHmacSha2Properties,
};
use ruma::serde::Base64;
use ruma::{OwnedRoomId, OwnedUserId, UInt, UserId};
use serde_json::{json, Value};

use crate::{enc, Error, Inner, Result};

/// Where recovery stands for this person and this phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryState {
    /// Recovery was set up (on some device of theirs).
    pub set: bool,
    /// This phone holds the cross-signing keys (recovered here).
    pub here: bool,
}

/// A verification (by QR code or emoji), as the screen shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationView {
    pub id: String,
    pub user: String,
    pub device: Option<String>,
    /// requested, incoming, ready (choose: scan, show or emoji), qr (our
    /// code is shown), scanned (the other device scanned ours: did it say
    /// so?), waiting, emoji, done, cancelled.
    pub state: String,
    /// The seven emoji's numbers (Matrix's table), when there are some to compare.
    pub emoji: Vec<u8>,
    /// The other device shows a code this phone can scan.
    pub can_scan: bool,
    /// The other device can scan a code this phone shows.
    pub can_show: bool,
}

/// A QR code to show: `width` × `width` modules, dark when true, row by row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrImage {
    pub width: u32,
    pub modules: Vec<bool>,
}

/// The ways this phone verifies: emoji, and QR codes both ways.
const METHODS: [VerificationMethod; 4] = [
    VerificationMethod::SasV1,
    VerificationMethod::QrCodeScanV1,
    VerificationMethod::QrCodeShowV1,
    VerificationMethod::ReciprocateV1,
];

/// The bytes a verification QR code holds, from what a scanner gives: the
/// bytes themselves (they begin with MATRIX), or the code's data codewords
/// (iOS's error-corrected payload, ZXing's raw bytes): one byte-mode
/// segment, its length in 8 bits (versions 1 to 9) or 16 (10 to 40).
pub fn qr_payload(scanned: &[u8]) -> Option<Vec<u8>> {
    if scanned.starts_with(b"MATRIX") {
        return Some(scanned.to_vec());
    }
    let bit = |i: usize| -> Option<u32> {
        scanned
            .get(i / 8)
            .map(|b| u32::from((b >> (7 - i % 8)) & 1))
    };
    let read = |at: usize, n: usize| -> Option<u32> {
        (0..n).try_fold(0u32, |acc, k| Some((acc << 1) | bit(at + k)?))
    };
    let mut at = 0;
    let mut mode = read(at, 4)?;
    if mode == 0b0111 {
        // An ECI designator (one byte here) before the data.
        at += 12;
        mode = read(at, 4)?;
    }
    if mode != 0b0100 {
        return None;
    }
    at += 4;
    for count_bits in [8, 16] {
        let Some(n) = read(at, count_bits) else {
            continue;
        };
        let start = at + count_bits;
        let bytes: Option<Vec<u8>> = (0..n as usize)
            .map(|k| read(start + 8 * k, 8).map(|b| b as u8))
            .collect();
        if let Some(b) = bytes.filter(|b| b.starts_with(b"MATRIX")) {
            return Some(b);
        }
    }
    None
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    Base64::<ruma::serde::base64::Standard, Vec<u8>>::parse(text)
        .ok()
        .map(|b| b.into_inner())
}

const SECRETS: [(SecretName, &str); 4] = [
    (SecretName::CrossSigningMasterKey, "m.cross_signing.master"),
    (
        SecretName::CrossSigningSelfSigningKey,
        "m.cross_signing.self_signing",
    ),
    (
        SecretName::CrossSigningUserSigningKey,
        "m.cross_signing.user_signing",
    ),
    (SecretName::RecoveryKey, "m.megolm_backup.v1"),
];

impl Inner {
    async fn account_data(&self, kind: &str) -> Option<Value> {
        self.http("GET", &format!("/chat/account-data/{}", enc(kind)), None)
            .await
            .ok()
    }

    /// Someone's devices and cross-signing keys from the server, kept for
    /// the SDK's key queries; the SDK is told they changed.
    pub(crate) async fn read_keys_of(&mut self, user: &str) -> Result<()> {
        let r = self
            .http("GET", &format!("/chat/keys?user={}", enc(user)), None)
            .await?;
        let mut known = Vec::new();
        for d in r["devices"].as_array().into_iter().flatten() {
            let mut d = d.clone();
            d["user"] = json!(user);
            if let Some(k) = self.check_device(&d).await? {
                known.push(k);
            }
        }
        self.devices.insert(user.to_string(), known);
        if let Some(people) = r["crossSigning"].as_object() {
            for (who, keys) in people {
                self.cross.insert(who.clone(), keys.clone());
            }
        }
        if let Ok(u) = UserId::parse(user) {
            self.changed(&[u]).await?;
        }
        Ok(())
    }

    pub(crate) async fn recovery_state(&mut self) -> Result<RecoveryState> {
        let set = self
            .account_data("m.secret_storage.default_key")
            .await
            .is_some_and(|d| d["key"].is_string());
        let status = self.machine.cross_signing_status().await;
        // Keys made here count only when they are the person's on the
        // server: a set-up that stopped half-way, then finished elsewhere,
        // leaves keys here that are nobody's (the recovery key is asked for).
        let held = status.has_master && status.has_self_signing && status.has_user_signing;
        Ok(RecoveryState {
            set,
            here: set && held && self.master_is_the_servers().await?,
        })
    }

    /// The master key this phone holds is the one the server has for the person.
    async fn master_is_the_servers(&self) -> Result<bool> {
        let Some(seed) = self
            .machine
            .export_cross_signing_keys()
            .await
            .map_err(crate::store_err)?
            .and_then(|k| k.master_key.clone())
        else {
            return Ok(false);
        };
        let Ok(secret) = vodozemac::Ed25519SecretKey::from_base64(&seed) else {
            return Ok(false);
        };
        let ours = secret.public_key().to_base64();
        let me = self.me.to_string();
        let r = self
            .http("GET", &format!("/chat/keys?user={}", enc(&me)), None)
            .await?;
        let theirs = r["crossSigning"][&me]["master"]["keys"]
            .as_object()
            .and_then(|k| k.values().next())
            .and_then(|v| v.as_str())
            .map(|k| k.trim_end_matches('=').to_string());
        Ok(theirs.as_deref() == Some(ours.trim_end_matches('=')))
    }

    /// Sets recovery up from this phone (the person's first device to do
    /// so): cross-signing keys, this device signed, a backup the master key
    /// signed, the secrets in secret storage under a new recovery key, and
    /// its escrow copy when the organisation has an escrow key. The same
    /// formats as the browser's. Answers the recovery key, to show once.
    pub(crate) async fn set_up_recovery(&mut self) -> Result<String> {
        let me = self.me.to_string();
        if self.recovery_state().await?.set {
            return Err(Error::Invalid("Recovery is already set up for you.".into()));
        }
        self.read_keys_of(&me).await?;
        let theirs = self
            .cross
            .get(&me)
            .and_then(|k| k["master"]["keys"].as_object().cloned());
        let status = self.machine.cross_signing_status().await;
        if theirs.is_some_and(|k| !k.is_empty())
            && !(status.has_master && self.master_is_the_servers().await?)
        {
            // Another device made cross-signing keys: recovery is theirs to finish.
            return Err(Error::Invalid(
                "Recovery is being set up on another device.".into(),
            ));
        }
        // Never a reset: an identity made here before (an upload refused)
        // is uploaded again.
        let boot = self
            .machine
            .bootstrap_cross_signing(false)
            .await
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let keys = &boot.upload_signing_keys_req;
        let body = json!({
            "master": serde_json::to_value(&keys.master_key).map_err(crate::store_err)?,
            "selfSigning": serde_json::to_value(&keys.self_signing_key).map_err(crate::store_err)?,
            "userSigning": serde_json::to_value(&keys.user_signing_key).map_err(crate::store_err)?,
        });
        self.http("PUT", "/chat/cross-signing", Some(body)).await?;
        self.upload_signatures(&boot.upload_signatures_req.signed_keys)
            .await?;
        self.read_keys_of(&me).await?;
        self.process(None).await?;

        // The backup, signed by the master key and this device.
        let backup = BackupDecryptionKey::new();
        let mut info = backup.to_backup_info();
        self.machine
            .backup_machine()
            .sign_backup(&mut info)
            .await
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let info = serde_json::to_value(&info).map_err(crate::store_err)?;
        let made = self
            .http(
                "POST",
                "/chat/backup/version",
                Some(json!({"algorithm": info["algorithm"], "authData": info["auth_data"]})),
            )
            .await?;
        let version = made["version"].as_str().unwrap_or_default().to_string();
        self.machine
            .backup_machine()
            .save_decryption_key(Some(backup.clone()), Some(version.clone()))
            .await
            .map_err(crate::store_err)?;
        let public = backup.megolm_v1_public_key();
        public.set_version(version.clone());
        self.machine
            .backup_machine()
            .enable_backup_v1(public)
            .await
            .map_err(crate::store_err)?;

        // Secret storage under the recovery key; the default key last, so a
        // set-up that stops half-way is not taken for one that finished.
        let key = SecretStorageKey::new();
        let key_id = key.key_id().to_string();
        let description = serde_json::to_value(key.event_content()).map_err(crate::store_err)?;
        self.http(
            "PUT",
            &format!(
                "/chat/account-data/{}",
                enc(&format!("m.secret_storage.key.{key_id}"))
            ),
            Some(description),
        )
        .await?;
        let export = self
            .machine
            .export_cross_signing_keys()
            .await
            .map_err(crate::store_err)?
            .ok_or_else(|| Error::Invalid("The cross-signing keys are missing.".into()))?;
        let seeds = [
            export.master_key.clone(),
            export.self_signing_key.clone(),
            export.user_signing_key.clone(),
            Some(backup.to_base64()),
        ];
        for ((name, kind), seed) in SECRETS.into_iter().zip(seeds) {
            let seed = seed.ok_or_else(|| Error::Invalid(format!("{kind} is missing.")))?;
            let sealed = key.encrypt(seed.into_bytes(), &name);
            let stored = json!({"encrypted": {key_id.clone(): {
                "iv": Base64::<ruma::serde::base64::Standard, _>::new(sealed.iv.to_vec()).encode(),
                "ciphertext": sealed.ciphertext.encode(),
                "mac": Base64::<ruma::serde::base64::Standard, _>::new(sealed.mac.to_vec()).encode(),
            }}});
            self.http(
                "PUT",
                &format!("/chat/account-data/{}", enc(kind)),
                Some(stored),
            )
            .await?;
        }
        let text = key.to_base58();
        // The organisation's escrow copy, as the browser seals it.
        // Not reached, not set up: never without the escrow copy the organisation asked for.
        let policy = self.http("GET", "/chat/policy", None).await?;
        if let Some(escrow) = policy["escrowKey"].as_str() {
            let public = vodozemac::Curve25519PublicKey::from_base64(escrow)
                .map_err(|e| Error::Invalid(format!("the escrow key: {e}")))?;
            let m = vodozemac::pk_encryption::PkEncryption::from_key(public)
                .encrypt(text.as_bytes())
                .map_err(|e| Error::Invalid(format!("the escrow key: {e}")))?;
            let b64 =
                |b: &[u8]| Base64::<ruma::serde::base64::Standard, _>::new(b.to_vec()).encode();
            self.http(
                "PUT",
                "/chat/account-data/ortus.escrow",
                Some(json!({"key": escrow, "sealed": {
                    "ephemeral": m.ephemeral_key.to_base64(),
                    "ciphertext": b64(&m.ciphertext),
                    "mac": b64(&m.mac),
                }})),
            )
            .await?;
        }
        self.http(
            "PUT",
            "/chat/account-data/m.secret_storage.default_key",
            Some(json!({"key": key_id})),
        )
        .await?;
        // Every room key this phone holds, into the backup.
        for _ in 0..100 {
            if !self.back_up_some().await? {
                break;
            }
        }
        Ok(text)
    }

    /// Recovery here with the recovery key. Answers how many room keys came
    /// back from the backup; Invalid when the key is not the person's.
    pub(crate) async fn recover(&mut self, typed: &str) -> Result<u32> {
        let wrong = || Error::Invalid("That is not your recovery key.".into());
        let default = self
            .account_data("m.secret_storage.default_key")
            .await
            .ok_or_else(wrong)?;
        let key_id = default["key"].as_str().ok_or_else(wrong)?.to_string();
        let description = self
            .account_data(&format!("m.secret_storage.key.{key_id}"))
            .await
            .ok_or_else(wrong)?;
        let (Some(iv), Some(mac)) = (
            description["iv"].as_str().and_then(unb64),
            description["mac"].as_str().and_then(unb64),
        ) else {
            return Err(wrong());
        };
        let content = SecretStorageKeyEventContent::new(
            key_id.clone(),
            SecretStorageEncryptionAlgorithm::V1AesHmacSha2(
                SecretStorageV1AesHmacSha2Properties::new(
                    Some(Base64::new(iv)),
                    Some(Base64::new(mac)),
                ),
            ),
        );
        let key =
            SecretStorageKey::from_account_data(typed.trim(), content).map_err(|_| wrong())?;
        let mut secrets = BTreeMap::new();
        for (name, kind) in SECRETS {
            let Some(stored) = self.account_data(kind).await else {
                continue;
            };
            let s = &stored["encrypted"][&key_id];
            let (Some(iv), Some(ciphertext), Some(mac)) = (
                s["iv"].as_str().and_then(unb64),
                s["ciphertext"].as_str().and_then(unb64),
                s["mac"].as_str().and_then(unb64),
            ) else {
                continue;
            };
            let (Ok(iv), Ok(mac)) = (iv.try_into(), mac.try_into()) else {
                continue;
            };
            let data = AesHmacSha2EncryptedData {
                iv,
                ciphertext: Base64::new(ciphertext),
                mac,
            };
            if let Ok(plain) = key.decrypt(&data, &name) {
                secrets.insert(kind, String::from_utf8_lossy(&plain).to_string());
            }
        }
        // The person's own identity, from the server, before importing its keys.
        let me = self.me.to_string();
        self.read_keys_of(&me).await?;
        self.process(None).await?;
        let export = CrossSigningKeyExport {
            master_key: secrets.get("m.cross_signing.master").cloned(),
            self_signing_key: secrets.get("m.cross_signing.self_signing").cloned(),
            user_signing_key: secrets.get("m.cross_signing.user_signing").cloned(),
        };
        self.machine
            .import_cross_signing_keys(export)
            .await
            .map_err(|e| Error::Invalid(format!("the cross-signing keys: {e}")))?;
        // This device, signed by the self-signing key.
        if let Some(device) = self
            .machine
            .get_device(&self.me, &self.device, None)
            .await
            .map_err(crate::store_err)?
        {
            let upload = device
                .verify()
                .await
                .map_err(|e| Error::Invalid(e.to_string()))?;
            self.upload_signatures(&upload.signed_keys).await?;
        }
        // The backup: only one the master key (or a verified device) signed.
        let mut restored = 0;
        if let Some(seed) = secrets.get("m.megolm_backup.v1") {
            let decryption = BackupDecryptionKey::from_base64(seed)
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if let Ok(info) = self.http("GET", "/chat/backup/version", None).await {
                let version = info["version"].as_str().unwrap_or_default().to_string();
                let backup_info = serde_json::from_value(
                    json!({"algorithm": info["algorithm"], "auth_data": info["authData"]}),
                )
                .map_err(crate::store_err)?;
                let verified = self
                    .machine
                    .backup_machine()
                    .verify_backup(backup_info, false)
                    .await
                    .map_err(crate::store_err)?;
                let public = decryption.megolm_v1_public_key();
                if verified.trusted()
                    && info["authData"]["public_key"].as_str() == Some(public.to_base64().as_str())
                {
                    self.machine
                        .backup_machine()
                        .save_decryption_key(Some(decryption.clone()), Some(version.clone()))
                        .await
                        .map_err(crate::store_err)?;
                    public.set_version(version.clone());
                    self.machine
                        .backup_machine()
                        .enable_backup_v1(public)
                        .await
                        .map_err(crate::store_err)?;
                    restored = self.restore(&decryption, &version).await?;
                }
            }
        }
        Ok(restored)
    }

    async fn restore(&self, key: &BackupDecryptionKey, version: &str) -> Result<u32> {
        let r = self
            .http(
                "GET",
                &format!("/chat/backup/keys?version={}", enc(version)),
                None,
            )
            .await?;
        let mut keys = Vec::new();
        for (room, data) in r["rooms"].as_object().into_iter().flatten() {
            let Ok(room) = OwnedRoomId::try_from(room.as_str()) else {
                continue;
            };
            for (session, k) in data["sessions"].as_object().into_iter().flatten() {
                let Ok(sealed) = serde_json::from_value(k["session_data"].clone()) else {
                    continue;
                };
                let opened: std::result::Result<_, DecryptionError> =
                    key.decrypt_session_data(sealed);
                if let Ok(room_key) = opened {
                    keys.push(ExportedRoomKey::from_backed_up_room_key(
                        room.clone(),
                        session.clone(),
                        room_key,
                    ));
                }
            }
        }
        let result = self
            .machine
            .store()
            .import_room_keys(keys, Some(version), |_, _| {})
            .await
            .map_err(crate::store_err)?;
        Ok(result.imported_count as u32)
    }

    pub(crate) async fn upload_signatures(
        &self,
        signed: &BTreeMap<OwnedUserId, upload_signatures::v3::SignedKeys>,
    ) -> Result<()> {
        let body = serde_json::to_value(signed).map_err(crate::store_err)?;
        self.http("POST", "/chat/signatures", Some(body)).await?;
        Ok(())
    }

    /// Room keys into the backup, when this phone has its key (after recovery).
    pub(crate) async fn back_up(&self) -> Result<()> {
        self.back_up_some().await.map(|_| ())
    }

    /// One batch of room keys into the backup: whether there was one.
    async fn back_up_some(&self) -> Result<bool> {
        let Some((id, request)) = self
            .machine
            .backup_machine()
            .backup()
            .await
            .map_err(crate::store_err)?
        else {
            return Ok(false);
        };
        let rooms = serde_json::to_value(&request.rooms).map_err(crate::store_err)?;
        let r = self
            .http(
                "PUT",
                &format!("/chat/backup/keys?version={}", enc(&request.version)),
                Some(json!({"rooms": rooms})),
            )
            .await?;
        let count = UInt::new(r["count"].as_u64().unwrap_or(0)).unwrap_or_default();
        let response = add_backup_keys::v3::Response::new(
            r["etag"].as_str().unwrap_or_default().to_string(),
            count,
        );
        self.machine
            .mark_request_as_sent(&id, &response)
            .await
            .map_err(crate::store_err)?;
        Ok(true)
    }

    /// The room's devices nobody vouched for (their owner's self-signing
    /// key did not sign them, or the owner is someone not verified).
    pub(crate) async fn unverified(&mut self, room: &str) -> Result<Vec<(String, String)>> {
        self.room(room, true).await?;
        let mut out = Vec::new();
        let devices = self
            .rooms
            .get(room)
            .map(|s| s.devices.clone())
            .unwrap_or_default();
        for d in devices {
            let Ok(user) = UserId::parse(d.user.as_str()) else {
                continue;
            };
            let device = self
                .machine
                .get_device(&user, d.device.as_str().into(), None)
                .await
                .map_err(crate::store_err)?;
            if !device.is_some_and(|x| x.is_verified()) {
                out.push((d.user.clone(), d.device.clone()));
            }
        }
        Ok(out)
    }

    // ---- verification -----------------------------------------------------

    fn requests(&self) -> Vec<VerificationRequest> {
        let mut users: Vec<OwnedUserId> = self.verifying.iter().cloned().collect();
        users.push(self.me.clone());
        users.sort();
        users.dedup();
        users
            .iter()
            .flat_map(|u| self.machine.get_verification_requests(u))
            .collect()
    }

    fn view(&self, r: &VerificationRequest) -> VerificationView {
        let user = r.other_user().to_string();
        let device = r.other_device_id().map(|d| d.to_string());
        let id = r.flow_id().as_str().to_string();
        let theirs = r.their_supported_methods().unwrap_or_default();
        let can_scan = theirs.contains(&VerificationMethod::QrCodeShowV1);
        let can_show = theirs.contains(&VerificationMethod::QrCodeScanV1);
        let flow = self.machine.get_verification(r.other_user(), &id);
        let (state, emoji) = match &flow {
            _ if r.is_cancelled() || flow.as_ref().is_some_and(|f| f.is_cancelled()) => {
                ("cancelled", Vec::new())
            }
            _ if r.is_done() || flow.as_ref().is_some_and(|f| f.is_done()) => ("done", Vec::new()),
            Some(Verification::SasV1(sas)) => match sas.emoji_index() {
                Some(e) => ("emoji", e.to_vec()),
                None => ("waiting", Vec::new()),
            },
            Some(Verification::QrV1(qr)) => {
                if qr.reciprocated() {
                    // We scanned theirs: the other device confirms.
                    ("waiting", Vec::new())
                } else if qr.has_been_scanned() && !qr.has_been_confirmed() {
                    ("scanned", Vec::new())
                } else if qr.has_been_confirmed() {
                    ("waiting", Vec::new())
                } else {
                    ("qr", Vec::new())
                }
            }
            _ if !r.we_started() && !r.is_ready() => ("incoming", Vec::new()),
            _ if r.we_started() && !r.is_ready() => ("requested", Vec::new()),
            _ if r.is_ready() => ("ready", Vec::new()),
            _ => ("waiting", Vec::new()),
        };
        VerificationView {
            id,
            user,
            device,
            state: state.into(),
            emoji,
            can_scan,
            can_show,
        }
    }

    async fn send_verification(&mut self, request: OutgoingVerificationRequest) -> Result<()> {
        if let OutgoingVerificationRequest::ToDevice(t) = request {
            self.forward_verification(&t).await?;
        }
        Ok(())
    }

    /// Verification messages the SDK makes, through chat's verification route.
    pub(crate) async fn forward_verification(&self, t: &ToDeviceRequest) -> Result<()> {
        let kind = t.event_type.to_string();
        for (user, devices) in &t.messages {
            for (device, content) in devices {
                let device = match device {
                    ruma::to_device::DeviceIdOrAllDevices::DeviceId(d) => d.to_string(),
                    ruma::to_device::DeviceIdOrAllDevices::AllDevices => "*".to_string(),
                };
                let content: Value =
                    serde_json::from_str(content.json().get()).map_err(crate::store_err)?;
                self.http(
                    "POST",
                    "/chat/verification",
                    Some(json!({"user": user, "device": device, "fromDevice": self.device.as_str(), "type": kind, "content": content})),
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Takes in what came, moves each verification on, and answers how they stand.
    pub(crate) async fn verifications(&mut self) -> Result<Vec<VerificationView>> {
        self.take_inbox().await?;
        for r in self.requests() {
            let id = r.flow_id().as_str().to_string();
            // Ours, and the other side said ready: start the emoji, unless
            // a QR code is possible (the person chooses: scan, show or emoji).
            let theirs = r.their_supported_methods().unwrap_or_default();
            let qr = theirs.contains(&VerificationMethod::QrCodeShowV1)
                || theirs.contains(&VerificationMethod::QrCodeScanV1);
            if r.we_started()
                && r.is_ready()
                && !qr
                && self.machine.get_verification(r.other_user(), &id).is_none()
            {
                if let Ok(Some((_, start))) = r.start_sas().await {
                    self.send_verification(start).await?;
                }
            }
            // Theirs, started: accept the emoji.
            if let Some(Verification::SasV1(sas)) =
                self.machine.get_verification(r.other_user(), &id)
            {
                if !sas.we_started() && !sas.has_been_accepted() && !sas.is_cancelled() {
                    if let Some(accept) = sas.accept() {
                        self.send_verification(accept).await?;
                    }
                }
            }
        }
        self.flush().await?;
        Ok(self.requests().iter().map(|r| self.view(r)).collect())
    }

    /// Asks one's own other devices to verify with this one.
    pub(crate) async fn verify_own_devices(&mut self) -> Result<String> {
        let me = self.me.to_string();
        self.read_keys_of(&me).await?;
        self.process(None).await?;
        let identity = self
            .machine
            .get_identity(&self.me, None)
            .await
            .map_err(crate::store_err)?
            .and_then(|i| i.own())
            .ok_or_else(|| Error::Invalid("Recovery is not set up for you yet.".into()))?;
        let (request, outgoing) = identity
            .request_verification_with_methods(METHODS.to_vec())
            .await
            .map_err(crate::store_err)?;
        self.send_verification(outgoing).await?;
        Ok(request.flow_id().as_str().to_string())
    }

    /// Asks one device of someone (another person, or one's own) to verify
    /// with this one: a row of a room's unverified devices.
    pub(crate) async fn verify_device(&mut self, user: &str, device: &str) -> Result<String> {
        let user_id = UserId::parse(user).map_err(|_| Error::Invalid("No such person.".into()))?;
        self.read_keys_of(user).await?;
        if user != self.me.as_str() {
            let me = self.me.to_string();
            self.read_keys_of(&me).await?;
        }
        self.process(None).await?;
        let d = self
            .machine
            .get_device(&user_id, device.into(), None)
            .await
            .map_err(crate::store_err)?
            .ok_or_else(|| Error::Invalid("No such device.".into()))?;
        let (request, outgoing) = d.request_verification_with_methods(METHODS.to_vec());
        self.note_verifying(user);
        self.send_verification(outgoing).await?;
        Ok(request.flow_id().as_str().to_string())
    }

    /// The emoji, chosen over a QR code.
    pub(crate) async fn start_emoji(&mut self, id: &str) -> Result<()> {
        let r = self.request(id)?;
        if let Some((_, start)) = r.start_sas().await.map_err(crate::store_err)? {
            self.send_verification(start).await?;
        }
        Ok(())
    }

    /// The other device's QR code, scanned here (what the scanner gave:
    /// the bytes, or the code's data codewords).
    pub(crate) async fn scan_qr(&mut self, id: &str, scanned: &[u8]) -> Result<()> {
        let r = self.request(id)?;
        let other = r.other_user().to_string();
        let me = self.me.to_string();
        self.read_keys_of(&other).await?;
        if other != me {
            self.read_keys_of(&me).await?;
        }
        self.process(None).await?;
        let bytes = qr_payload(scanned)
            .ok_or_else(|| Error::Invalid("That is not a verification code.".into()))?;
        let data = QrVerificationData::from_bytes(bytes)
            .map_err(|_| Error::Invalid("That is not a verification code.".into()))?;
        let r = self.request(id)?;
        let qr = r
            .scan_qr_code(data)
            .await
            .map_err(|e| Error::Invalid(format!("The code does not match: {e}")))?
            .ok_or_else(|| Error::Invalid("This verification cannot use a code now.".into()))?;
        if let Some(reciprocate) = qr.reciprocate() {
            self.send_verification(reciprocate).await?;
        }
        Ok(())
    }

    /// This phone's QR code for the other device to scan (made once).
    pub(crate) async fn show_qr(&mut self, id: &str) -> Result<QrImage> {
        let r = self.request(id)?;
        let other = r.other_user().to_string();
        let me = self.me.to_string();
        self.read_keys_of(&other).await?;
        if other != me {
            self.read_keys_of(&me).await?;
        }
        self.process(None).await?;
        let r = self.request(id)?;
        let qr = match self.machine.get_verification(r.other_user(), id) {
            Some(Verification::QrV1(qr)) => *qr,
            _ => r
                .generate_qr_code()
                .await
                .map_err(crate::store_err)?
                .ok_or_else(|| Error::Invalid("This verification cannot show a code.".into()))?,
        };
        let code = qr.to_qr_code().map_err(|e| Error::Invalid(e.to_string()))?;
        let width = code.width() as u32;
        let modules = code
            .to_colors()
            .into_iter()
            .map(|c| c == matrix_sdk_crypto::matrix_sdk_qrcode::qrcode::Color::Dark)
            .collect();
        Ok(QrImage { width, modules })
    }

    /// The other device scanned this phone's code and says so (or not).
    pub(crate) async fn confirm_scanned(&mut self, id: &str, yes: bool) -> Result<()> {
        let r = self.request(id)?;
        let Some(Verification::QrV1(qr)) = self.machine.get_verification(r.other_user(), id) else {
            return Err(Error::Invalid("Nothing was scanned.".into()));
        };
        let out = if yes {
            qr.confirm_scanning()
        } else {
            qr.cancel_with_code(ruma::events::key::verification::cancel::CancelCode::KeyMismatch)
        };
        if let Some(out) = out {
            self.send_verification(out).await?;
        }
        self.flush().await
    }

    fn request(&self, id: &str) -> Result<VerificationRequest> {
        self.requests()
            .into_iter()
            .find(|r| r.flow_id().as_str() == id)
            .ok_or_else(|| Error::Invalid("No such verification.".into()))
    }

    pub(crate) async fn accept_verification(&mut self, id: &str) -> Result<()> {
        let r = self.request(id)?;
        let user = r.other_user().to_string();
        self.read_keys_of(&user).await?;
        self.process(None).await?;
        if let Some(ready) = r.accept_with_methods(METHODS.to_vec()) {
            self.send_verification(ready).await?;
        }
        Ok(())
    }

    pub(crate) async fn confirm_verification(&mut self, id: &str, same: bool) -> Result<()> {
        let r = self.request(id)?;
        let Some(Verification::SasV1(sas)) = self.machine.get_verification(r.other_user(), id)
        else {
            return Err(Error::Invalid("There are no emoji to compare yet.".into()));
        };
        if !same {
            if let Some(cancel) = sas.cancel_with_code(
                ruma::events::key::verification::cancel::CancelCode::MismatchedSas,
            ) {
                self.send_verification(cancel).await?;
            }
            return Ok(());
        }
        let (requests, signatures) = sas.confirm().await.map_err(crate::store_err)?;
        for outgoing in requests {
            self.send_verification(outgoing).await?;
        }
        if let Some(upload) = signatures {
            self.upload_signatures(&upload.signed_keys).await?;
        }
        self.flush().await
    }

    pub(crate) async fn cancel_verification(&mut self, id: &str) -> Result<()> {
        let r = self.request(id)?;
        if let Some(cancel) = r.cancel() {
            self.send_verification(cancel).await?;
        }
        Ok(())
    }

    /// What the SDK still wants sent (signatures after a verification, backups).
    pub(crate) async fn flush(&mut self) -> Result<()> {
        self.process(None).await?;
        self.back_up().await
    }

    pub(crate) fn note_verifying(&mut self, sender: &str) {
        if let Ok(u) = UserId::parse(sender) {
            self.verifying.insert(u);
        }
    }

    pub(crate) fn outgoing_kind(r: &AnyOutgoingRequest) -> Option<&ToDeviceRequest> {
        match r {
            AnyOutgoingRequest::ToDeviceRequest(t)
                if t.event_type.to_string().starts_with("m.key.verification.") =>
            {
                Some(t)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::qr_payload;

    /// Data codewords as a scanner gives them: byte mode, the count, the
    /// bytes, a terminator, padding.
    fn codewords(payload: &[u8], count_bits: usize) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::new();
        let mut put = |v: u32, n: usize| (0..n).rev().for_each(|i| bits.push(((v >> i) & 1) as u8));
        put(0b0100, 4);
        put(payload.len() as u32, count_bits);
        payload.iter().for_each(|b| put(u32::from(*b), 8));
        put(0, 4);
        while !bits.len().is_multiple_of(8) {
            bits.push(0);
        }
        let mut out: Vec<u8> = bits
            .chunks(8)
            .map(|c| c.iter().fold(0, |a, b| (a << 1) | b))
            .collect();
        out.extend([0xec, 0x11, 0xec]);
        out
    }

    #[test]
    fn reads_the_bytes_from_what_a_scanner_gives() {
        let payload = b"MATRIX\x02\x00\x00\x02ab0123456789012345678901234567890123456789012345678901234567890123secret!!";
        assert_eq!(Some(payload.to_vec()), qr_payload(payload));
        assert_eq!(Some(payload.to_vec()), qr_payload(&codewords(payload, 8)));
        assert_eq!(Some(payload.to_vec()), qr_payload(&codewords(payload, 16)));
        assert_eq!(None, qr_payload(&codewords(b"not a verification", 8)));
        assert_eq!(None, qr_payload(b""));
    }
}
