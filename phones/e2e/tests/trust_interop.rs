//! The browser's trust code (web/src/trust.ts, run by Node) against
//! matrix-sdk-crypto and vodozemac, the phones' side: the recovery key and
//! secret storage the browser writes open with the SDK's SecretStorageKey;
//! a room key it backs up opens with the SDK's BackupDecryptionKey; its
//! cross-signing keys are signed by its master key; and what vodozemac
//! seals to a backup key (as the phones back up) opens in the browser.

use std::path::Path;
use std::process::Command;

use matrix_sdk_crypto::secret_storage::{AesHmacSha2EncryptedData, SecretStorageKey};
use matrix_sdk_crypto::store::types::BackupDecryptionKey;
use ruma::events::secret::request::SecretName;
use ruma::events::secret_storage::key::{
    SecretStorageEncryptionAlgorithm, SecretStorageKeyEventContent,
    SecretStorageV1AesHmacSha2Properties,
};
use ruma::serde::Base64;
use serde_json::{json, Value};
use vodozemac::pk_encryption::PkEncryption;
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

fn web() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web")
}

fn node(args: &[&str]) -> Value {
    let out = Command::new("node")
        .arg("interop/trust-peer.ts")
        .args(args)
        .current_dir(web())
        .output()
        .expect("node");
    assert!(
        out.status.success(),
        "node: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json from node")
}

fn unb64(text: &str) -> Vec<u8> {
    Base64::<ruma::serde::base64::Standard, Vec<u8>>::parse(text)
        .expect("base64")
        .into_inner()
}

fn b64(bytes: &[u8]) -> String {
    Base64::<ruma::serde::base64::Standard, Vec<u8>>::new(bytes.to_vec()).encode()
}

#[test]
fn the_browsers_trust_formats_are_matrixs() {
    let made = node(&["make"]);
    assert_eq!(
        made["recoveryBytes"], made["roundTrip"],
        "the recovery key reads back"
    );
    assert!(
        made["mistyped"].is_null(),
        "a mistyped recovery key is refused"
    );
    assert!(
        made["recoveryText"].as_str().unwrap().starts_with("Es"),
        "Matrix's recovery key: {}",
        made["recoveryText"]
    );

    // Secret storage: the SDK takes the typed recovery key against the
    // browser's key description, and opens the browser's secret.
    let description = &made["description"];
    assert_eq!(
        "m.secret_storage.v1.aes-hmac-sha2",
        description["algorithm"]
    );
    let content = SecretStorageKeyEventContent::new(
        "K1".into(),
        SecretStorageEncryptionAlgorithm::V1AesHmacSha2(SecretStorageV1AesHmacSha2Properties::new(
            Some(Base64::new(unb64(description["iv"].as_str().unwrap()))),
            Some(Base64::new(unb64(description["mac"].as_str().unwrap()))),
        )),
    );
    let key = SecretStorageKey::from_account_data(made["recoveryText"].as_str().unwrap(), content)
        .expect("the SDK takes the browser's recovery key");
    let secret = &made["secret"];
    let data = AesHmacSha2EncryptedData {
        iv: unb64(secret["iv"].as_str().unwrap()).try_into().unwrap(),
        ciphertext: Base64::new(unb64(secret["ciphertext"].as_str().unwrap())),
        mac: unb64(secret["mac"].as_str().unwrap()).try_into().unwrap(),
    };
    let opened = key
        .decrypt(&data, &SecretName::CrossSigningMasterKey)
        .expect("the SDK opens the browser's secret");
    assert_eq!(
        made["masterSeed"].as_str().unwrap().as_bytes(),
        opened.as_slice()
    );

    // Cross-signing: the self-signing and user-signing keys are signed by
    // the master key, over Matrix's canonical JSON.
    let master = Ed25519PublicKey::from_base64(made["masterPublic"].as_str().unwrap()).unwrap();
    let master_id = format!("ed25519:{}", made["masterPublic"].as_str().unwrap());
    for kind in ["selfSigning", "userSigning"] {
        let mut key = made["crossSigning"][kind].clone();
        let sig = key["signatures"]["@olena:ortus.test"][&master_id]
            .as_str()
            .unwrap()
            .to_string();
        key.as_object_mut().unwrap().remove("signatures");
        let signature = Ed25519Signature::from_base64(&sig).unwrap();
        master
            .verify(ortus_e2e::canonical(&key).as_bytes(), &signature)
            .unwrap_or_else(|e| panic!("{kind} is signed by the master key: {e}"));
    }

    // The backup: the SDK opens a room key the browser backed up.
    let backup = BackupDecryptionKey::from_base64(made["backupSeed"].as_str().unwrap()).unwrap();
    let sealed = &made["roomKey"]["session_data"];
    let plaintext = backup
        .decrypt_v1(
            sealed["ephemeral"].as_str().unwrap(),
            sealed["mac"].as_str().unwrap(),
            sealed["ciphertext"].as_str().unwrap(),
        )
        .expect("the SDK opens the browser's backup");
    let room_key: Value = serde_json::from_str(&plaintext).unwrap();
    assert_eq!("AQID", room_key["session_key"]);
    assert_eq!("m.megolm.v1.aes-sha2", room_key["algorithm"]);

    // And the other way: what vodozemac seals (as the phones back up, and
    // as the escrow copy is made) opens in the browser.
    let public = Curve25519PublicKey::from_base64(made["backupPublic"].as_str().unwrap()).unwrap();
    let message = PkEncryption::from_key(public)
        .encrypt(b"{\"session_key\":\"from the phone\"}")
        .expect("sealed");
    let sealed = json!({"ephemeral": message.ephemeral_key.to_base64(), "mac": b64(&message.mac), "ciphertext": b64(&message.ciphertext)});
    let opened = node(&[
        "unseal",
        made["backupSeed"].as_str().unwrap(),
        &sealed.to_string(),
    ]);
    assert_eq!(
        "{\"session_key\":\"from the phone\"}", opened["plaintext"],
        "the browser opens the phone's backup"
    );
}
