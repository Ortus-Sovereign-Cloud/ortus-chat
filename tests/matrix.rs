//! The Matrix exact parts against the specification's own examples
//! (appendices "Signing JSON" and "Signing Events"), and round trips.

use ortus_chat::matrix::{self, SigningKey};
use serde_json::json;

fn key() -> SigningKey {
    let seed = matrix::unb64("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1").unwrap();
    SigningKey::from_seed("ed25519:1", &seed).unwrap()
}

#[test]
fn signing_json_matches_the_specification() {
    let mut empty = json!({});
    matrix::sign_json(&mut empty, "domain", &key());
    assert_eq!(
        json!({"signatures": {"domain": {"ed25519:1": "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"}}}),
        empty
    );
    let mut two = json!({"one": 1, "two": "Two"});
    matrix::sign_json(&mut two, "domain", &key());
    assert_eq!(
        "KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw",
        two["signatures"]["domain"]["ed25519:1"]
    );
    assert!(matrix::verify_json(
        &two,
        "domain",
        "ed25519:1",
        &key().public()
    ));
    two["two"] = json!("Changed");
    assert!(!matrix::verify_json(
        &two,
        "domain",
        "ed25519:1",
        &key().public()
    ));
}

#[test]
fn signing_events_matches_the_specification() {
    let mut event = json!({
        "room_id": "!x:domain",
        "sender": "@a:domain",
        "origin": "domain",
        "origin_server_ts": 1000000,
        "signatures": {},
        "hashes": {},
        "type": "X",
        "content": {},
        "prev_events": [],
        "auth_events": [],
        "depth": 3,
        "unsigned": {"age_ts": 1000000}
    });
    matrix::seal_event(&mut event, "domain", &key());
    assert_eq!(
        "5jM4wQpv6lnBo7CLIghJuHdW+s2CMBJPUOGOC89ncos",
        event["hashes"]["sha256"]
    );
    assert_eq!(
        "KxwGjPSDEtvnFgU00fwFz+l6d2pJM6XBIaMEn81SXPTRl16AqLAYqfIReFGZlHi5KLjAWbOoMszkwsQma+lYAg",
        event["signatures"]["domain"]["ed25519:1"]
    );
    assert!(matrix::check_event(
        &event,
        "domain",
        "ed25519:1",
        &key().public()
    ));
    // A changed content breaks the hash; a redaction keeps the signature.
    let mut changed = event.clone();
    changed["content"] = json!({"body": "x"});
    assert!(!matrix::check_event(
        &changed,
        "domain",
        "ed25519:1",
        &key().public()
    ));
}

#[test]
fn canonical_json_is_sorted_and_compact() {
    let v = json!({"b": 2, "a": {"z": [1, "\u{1}", "é"], "c": null}, "": true});
    assert_eq!(
        r#"{"":true,"a":{"c":null,"z":[1,"\u0001","é"]},"b":2}"#,
        matrix::canonical(&v)
    );
    // The specification's example.
    let v = json!({"auth": {"success": true, "mxid": "@john.doe:example.com", "profile": {"display_name": "John Doe", "three_pids": [{"medium": "email", "address": "john.doe@example.org"}, {"medium": "msisdn", "address": "123456789"}]}}});
    assert_eq!(
        r#"{"auth":{"mxid":"@john.doe:example.com","profile":{"display_name":"John Doe","three_pids":[{"address":"john.doe@example.org","medium":"email"},{"address":"123456789","medium":"msisdn"}]},"success":true}}"#,
        matrix::canonical(&v)
    );
}

#[test]
fn event_ids_are_reference_hashes() {
    let mut event = json!({"room_id": "!r:a", "sender": "@u:a", "origin_server_ts": 1, "type": "m.room.message", "content": {"body": "hi", "msgtype": "m.text"}, "prev_events": [], "auth_events": [], "depth": 1});
    let id = matrix::seal_event(&mut event, "a", &key());
    assert!(id.starts_with('$') && !id.contains('=') && !id.contains('/') && !id.contains('+'));
    // Redacting the content does not change the id.
    let mut redacted = matrix::redact(&event);
    redacted["signatures"] = event["signatures"].clone();
    assert_eq!(id, matrix::event_id(&redacted));
}
