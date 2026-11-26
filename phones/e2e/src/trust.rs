//! Trust on the phone (docs/e2e-trust-and-backup.md), by matrix-sdk-crypto:
//! recovery with the recovery key (secret storage opens the cross-signing
//! keys and the backup key; this device is signed; the backup, only one the
//! master key signed, is restored and kept up), who in a room is not
//! vouched for, and verification by emoji with other devices (the browser's
//! or another phone's). The server routes are chat's trust.rs.

use std::collections::BTreeMap;

use matrix_sdk_crypto::backups::DecryptionError;
use matrix_sdk_crypto::olm::ExportedRoomKey;
use matrix_sdk_crypto::secret_storage::{AesHmacSha2EncryptedData, SecretStorageKey};
use matrix_sdk_crypto::store::types::{BackupDecryptionKey, CrossSigningKeyExport};
use matrix_sdk_crypto::types::requests::{
    AnyOutgoingRequest, OutgoingVerificationRequest, ToDeviceRequest,
};
use matrix_sdk_crypto::{Verification, VerificationRequest};
use ruma::api::client::backup::add_backup_keys;
use ruma::api::client::keys::upload_signatures;
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

/// A verification by emoji, as the screen shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationView {
    pub id: String,
    pub user: String,
    pub device: Option<String>,
    /// requested, incoming, waiting, emoji, done, cancelled (as the browser's).
    pub state: String,
    /// The seven emoji's numbers (Matrix's table), when there are some to compare.
    pub emoji: Vec<u8>,
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
        Ok(RecoveryState {
            set,
            here: status.has_master && status.has_self_signing && status.has_user_signing,
        })
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
        let Some((id, request)) = self
            .machine
            .backup_machine()
            .backup()
            .await
            .map_err(crate::store_err)?
        else {
            return Ok(());
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
        Ok(())
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
        let sas = match self.machine.get_verification(r.other_user(), &id) {
            Some(Verification::SasV1(s)) => Some(s),
            _ => None,
        };
        let (state, emoji) = if r.is_cancelled() || sas.as_ref().is_some_and(|s| s.is_cancelled()) {
            ("cancelled", Vec::new())
        } else if r.is_done() || sas.as_ref().is_some_and(|s| s.is_done()) {
            ("done", Vec::new())
        } else if let Some(e) = sas.as_ref().and_then(|s| s.emoji_index()) {
            ("emoji", e.to_vec())
        } else if !r.we_started() && !r.is_ready() && sas.is_none() {
            ("incoming", Vec::new())
        } else if r.we_started() && !r.is_ready() {
            ("requested", Vec::new())
        } else {
            ("waiting", Vec::new())
        };
        VerificationView {
            id,
            user,
            device,
            state: state.into(),
            emoji,
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
            // Ours, and the other side said ready: start the emoji.
            if r.we_started()
                && r.is_ready()
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
            .request_verification()
            .await
            .map_err(crate::store_err)?;
        self.send_verification(outgoing).await?;
        Ok(request.flow_id().as_str().to_string())
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
        if let Some(ready) = r.accept() {
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
