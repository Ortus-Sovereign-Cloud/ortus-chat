//! Trust started on a phone, on a real server, with the browser's code:
//! recovery set up on a phone (the browser recovers with its key, and the
//! organisation's escrow copy opens to it); a QR code the browser shows,
//! read back by an independent decoder and scanned by a phone; a phone
//! verifying another person's device; two people's requests with one id,
//! neither acted on.

mod common;

use common::{Browser, Person, Phone, World};
use ortus_e2e::enc;
use serde_json::{json, Value};

/// The browser's verifications (as its screen has them).
fn browser_view(browser: &mut Browser, id: &str) -> Option<Value> {
    let all = browser.ask(json!({"cmd": "poll"}));
    all.as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .cloned()
}

fn phone_state(phone: &Phone, id: &str) -> Option<ortus_e2e::VerificationView> {
    phone
        .e2e
        .verifications()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
}

/// The QR code's modules as the browser draws them, photographed (a
/// quiet zone, eight pixels a module) and decoded by rqrr: the bytes.
fn read_code(modules: &Value) -> Vec<u8> {
    let rows: Vec<Vec<bool>> = modules
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r.as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_bool().unwrap())
                .collect()
        })
        .collect();
    let n = rows.len();
    let scale = 8;
    let side = (n + 8) * scale;
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(side, side, |x, y| {
        let (mx, my) = ((x / scale) as isize - 4, (y / scale) as isize - 4);
        let dark = mx >= 0
            && my >= 0
            && (mx as usize) < n
            && (my as usize) < n
            && rows[my as usize][mx as usize];
        if dark {
            0
        } else {
            255
        }
    });
    let grids = img.detect_grids();
    assert_eq!(1, grids.len(), "one code in the picture");
    let mut bytes = Vec::new();
    grids[0].decode_to(&mut bytes).expect("the code decodes");
    bytes
}

/// The person's devices on the server other than `not`.
fn other_device(w: &World, who: &Person, me: &str, not: &str) -> String {
    let keys = w.ok(who, "GET", &format!("/chat/keys?user={}", enc(me)), None);
    keys["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["device"].as_str().unwrap().to_string())
        .find(|d| d != not)
        .expect("another device")
}

#[test]
fn recovery_set_up_on_a_phone_opens_in_the_browser_and_in_escrow() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let (room, _) = w.sealed_room(&olena, &[]);
        // The organisation's escrow key (its private half stays with the administrator).
        let escrow = vodozemac::Curve25519SecretKey::new();
        let escrow_public = vodozemac::Curve25519PublicKey::from(&escrow);
        w.ok(
            &olena,
            "PATCH",
            "/chat/policy",
            Some(json!({"escrowKey": escrow_public.to_base64()})),
        );

        let phone = w.phone(&olena, "PHONEA");
        let sent = phone.e2e.send(&room, "Written on the phone", None).unwrap();
        assert!(!phone.e2e.recovery_state().unwrap().set, "{n}");
        let key = phone.e2e.set_up_recovery().expect("set up on the phone");
        assert!(key.starts_with("Es"), "{n}: {key}");
        let state = phone.e2e.recovery_state().unwrap();
        assert!(state.set && state.here, "{n}: {state:?}");
        assert!(phone.e2e.set_up_recovery().is_err(), "{n}: only once");

        // The escrow copy opens to the recovery key with the private half.
        let copy = w.ok(&olena, "GET", "/chat/account-data/ortus.escrow", None);
        let sealed = &copy["sealed"];
        let unb64 = |k: &str| -> Vec<u8> {
            let s = sealed[k].as_str().unwrap().trim_end_matches('=');
            vodozemac::base64_decode(s).unwrap()
        };
        let message = vodozemac::pk_encryption::Message {
            ciphertext: unb64("ciphertext"),
            mac: unb64("mac"),
            ephemeral_key: vodozemac::Curve25519PublicKey::from_base64(
                sealed["ephemeral"].as_str().unwrap(),
            )
            .unwrap(),
        };
        let opened = vodozemac::pk_encryption::PkDecryption::from_key(escrow)
            .decrypt(&message)
            .expect("the escrow copy opens");
        assert_eq!(
            key.as_bytes(),
            opened.as_slice(),
            "{n}: escrow holds the key"
        );

        // A new browser recovers with the phone's key and reads the phone's message.
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        assert_eq!(
            Value::Null,
            browser.ask(json!({"cmd": "recover", "key": "EsTx not the key"})),
            "{n}: a wrong key"
        );
        let restored = browser.ask(json!({"cmd": "recover", "key": key}));
        assert!(restored.as_u64().unwrap() >= 1, "{n}: restored {restored}");
        let state = browser.ask(json!({"cmd": "recoveryState"}));
        assert_eq!(json!(true), state["here"], "{n}");
        assert_eq!(json!(true), state["escrow"], "{n}");
        let room_id = w.ok(&olena, "GET", &format!("/chat/rooms/{}", enc(&room)), None);
        let room_id = room_id["room"]["roomId"]
            .as_str()
            .or(room_id["roomId"].as_str())
            .unwrap()
            .to_string();
        let opened = browser.ask(
            json!({"cmd": "open", "room": room, "roomId": room_id, "message": w.message(&olena, &sent)}),
        );
        assert_eq!(
            "Written on the phone", opened,
            "{n}: from the phone's backup: {opened}"
        );
        // Both vouch for each other through the phone's keys.
        assert_eq!(
            json!([]),
            browser.ask(json!({"cmd": "unverified", "room": room})),
            "{n}"
        );
        assert_eq!(
            Vec::<(String, String)>::new(),
            phone.e2e.unverified(&room).unwrap(),
            "{n}"
        );
    }
}

#[test]
fn a_qr_code_the_browser_shows_is_scanned_by_a_phone() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let (room, room_id) = w.sealed_room(&olena, &[]);
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        let key = browser
            .ask(json!({"cmd": "setUpRecovery"}))
            .as_str()
            .unwrap()
            .to_string();
        // A phone that has not recovered: nobody vouches for it yet.
        let phone = w.phone(&olena, "PHONEQ");
        phone.e2e.inbox().unwrap();
        let unverified = browser.ask(json!({"cmd": "unverified", "room": room}));
        assert!(
            unverified
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["device"] == "PHONEQ"),
            "{n}: {unverified}"
        );
        let _ = key;

        let me = olena.me.clone();
        let id = browser
            .ask(json!({"cmd": "verify", "user": me}))
            .as_str()
            .unwrap()
            .to_string();
        let mut accepted = false;
        let mut code = Value::Null;
        for _ in 0..40 {
            if let Some(v) = phone_state(&phone, &id) {
                if v.state == "incoming" && !accepted {
                    phone.e2e.accept_verification(&id).unwrap();
                    accepted = true;
                }
            }
            if let Some(v) = browser_view(&mut browser, &id) {
                if v["state"] == "qr" {
                    code = v["qr"].clone();
                    break;
                }
            }
        }
        assert!(code.is_array(), "{n}: the browser shows a code");
        let phone_view = phone_state(&phone, &id).unwrap();
        assert_eq!("ready", phone_view.state, "{n}: the phone chooses");
        assert!(phone_view.can_scan, "{n}: and can scan");

        let bytes = read_code(&code);
        assert!(bytes.starts_with(b"MATRIX\x02\x01"), "{n}: self, keys held");
        phone.e2e.scan_qr(&id, &bytes).expect("the phone scans");
        let mut scanned = false;
        for _ in 0..40 {
            if browser_view(&mut browser, &id).is_some_and(|v| v["state"] == "scanned") {
                scanned = true;
                break;
            }
            phone.e2e.verifications().unwrap();
        }
        assert!(scanned, "{n}: the browser hears the code was scanned");
        browser.ask(json!({"cmd": "confirmScanned", "id": id, "yes": true}));
        let mut done = (false, false);
        for _ in 0..40 {
            done.0 = browser_view(&mut browser, &id).is_some_and(|v| v["state"] == "done");
            done.1 = phone_state(&phone, &id).is_some_and(|v| v.state == "done");
            if done.0 && done.1 {
                break;
            }
        }
        assert_eq!((true, true), done, "{n}: both finish");
        assert_eq!(
            json!([]),
            browser.ask(json!({"cmd": "unverified", "room": room})),
            "{n}: the browser vouches for the phone"
        );
    }
}

#[test]
fn a_phone_verifies_another_persons_device() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let taras = w.person("taras@ministry.example", false);
        let (room, room_id) = w.sealed_room(&olena, &[(&taras, "taras@ministry.example")]);
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        browser.ask(json!({"cmd": "setUpRecovery"}));
        let phone = w.phone(&taras, "PHONET");
        phone
            .e2e
            .set_up_recovery()
            .expect("taras sets up on his phone");
        phone.e2e.inbox().unwrap();

        let unverified = phone.e2e.unverified(&room).unwrap();
        let olena_me = olena.me.clone();
        let device = other_device(&w, &olena, &olena_me, "");
        assert!(
            unverified.contains(&(olena_me.clone(), device.clone())),
            "{n}: {unverified:?}"
        );
        let id = phone.e2e.verify_device(&olena_me, &device).unwrap();
        let mut accepted = false;
        let mut emoji = (Vec::new(), Vec::new());
        let mut started = false;
        for _ in 0..60 {
            if let Some(v) = browser_view(&mut browser, &id) {
                if v["state"] == "incoming" && !accepted {
                    browser.ask(json!({"cmd": "accept", "id": id}));
                    accepted = true;
                }
                if v["state"] == "emoji" {
                    emoji.0 = v["emoji"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|e| e.as_u64().unwrap() as u8)
                        .collect();
                }
            }
            if let Some(v) = phone_state(&phone, &id) {
                // The browser shows a code; this test compares emoji instead.
                if v.state == "ready" && !started {
                    phone.e2e.start_emoji(&id).unwrap();
                    started = true;
                }
                if v.state == "emoji" {
                    emoji.1 = v.emoji.clone();
                }
            }
            if !emoji.0.is_empty() && !emoji.1.is_empty() {
                break;
            }
        }
        assert_eq!(7, emoji.1.len(), "{n}: the phone shows emoji");
        assert_eq!(emoji.0, emoji.1, "{n}: the same seven");
        phone.e2e.confirm_verification(&id, true).unwrap();
        browser.ask(json!({"cmd": "confirm", "id": id, "same": true}));
        let mut done = (false, false);
        for _ in 0..40 {
            done.0 = browser_view(&mut browser, &id).is_some_and(|v| v["state"] == "done");
            done.1 = phone_state(&phone, &id).is_some_and(|v| v.state == "done");
            if done.0 && done.1 {
                break;
            }
        }
        assert_eq!((true, true), done, "{n}: both finish");
        let unverified = phone.e2e.unverified(&room).unwrap();
        assert!(
            !unverified.iter().any(|(u, _)| u == &olena_me),
            "{n}: taras vouches for olena: {unverified:?}"
        );
        let theirs = browser.ask(json!({"cmd": "unverified", "room": room}));
        assert!(
            !theirs
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["device"] == "PHONET"),
            "{n}: olena vouches for taras's phone: {theirs}"
        );
    }
}

/// The server's transport, except that one call (method and path) fails
/// once, as a phone losing its connection half-way.
struct FailOnce {
    inner: std::sync::Arc<dyn ortus_e2e::Transport>,
    method: &'static str,
    path: &'static str,
    failed: std::sync::atomic::AtomicBool,
}

impl ortus_e2e::Transport for FailOnce {
    fn http(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
        if method == self.method
            && path == self.path
            && !self.failed.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Err("offline".into());
        }
        self.inner.http(method, path, body)
    }
}

fn failing_once(
    w: &World,
    who: &Person,
    method: &'static str,
    path: &'static str,
) -> std::sync::Arc<dyn ortus_e2e::Transport> {
    std::sync::Arc::new(FailOnce {
        inner: w.transport(who),
        method,
        path,
        failed: std::sync::atomic::AtomicBool::new(false),
    })
}

#[test]
fn a_set_up_cut_half_way_is_finished_or_given_way() {
    for w in World::all() {
        let n = &w.name;
        // Cut after the cross-signing keys and the backup went up: tried again, it finishes.
        let olena = w.person("olena@ministry.example", true);
        let (room, _) = w.sealed_room(&olena, &[]);
        let phone = w.phone_via(
            &olena,
            "PHONEA",
            failing_once(&w, &olena, "PUT", "/chat/account-data/m.megolm_backup.v1"),
        );
        let sent = phone.e2e.send(&room, "Before the cut", None).unwrap();
        assert!(phone.e2e.set_up_recovery().is_err(), "{n}: cut");
        let state = phone.e2e.recovery_state().unwrap();
        assert!(!state.set && !state.here, "{n}: not set up: {state:?}");
        let key = phone.e2e.set_up_recovery().expect("tried again");
        assert!(phone.e2e.recovery_state().unwrap().here, "{n}");
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        let restored = browser.ask(json!({"cmd": "recover", "key": key}));
        assert!(restored.as_u64().unwrap() >= 1, "{n}: {restored}");
        let _ = sent;

        // Cut the same way, then set up in a browser instead: the phone's
        // keys are nobody's, and it asks for the recovery key.
        let taras = w.person("taras@ministry.example", true);
        let phone = w.phone_via(
            &taras,
            "PHONET",
            failing_once(&w, &taras, "PUT", "/chat/account-data/m.megolm_backup.v1"),
        );
        assert!(phone.e2e.set_up_recovery().is_err(), "{n}: cut");
        let mut browser = Browser::start(&w, &taras);
        browser.ask(json!({"cmd": "ready"}));
        let key = browser.ask(json!({"cmd": "setUpRecovery"}));
        let Some(key) = key.as_str() else {
            panic!("{n}: the browser sets up: {key}");
        };
        let state = phone.e2e.recovery_state().unwrap();
        assert!(
            state.set && !state.here,
            "{n}: the phone's keys are not the person's: {state:?}"
        );
        phone
            .e2e
            .recover(key)
            .expect("recovers with the browser's key");
        assert!(phone.e2e.recovery_state().unwrap().here, "{n}");

        // The escrow key cannot be read: nothing is set up without its copy.
        let iryna = w.person("iryna@ministry.example", true);
        let phone = w.phone_via(
            &iryna,
            "PHONEI",
            failing_once(&w, &iryna, "GET", "/chat/policy"),
        );
        assert!(
            phone.e2e.set_up_recovery().is_err(),
            "{n}: no policy, no set-up"
        );
        assert!(!phone.e2e.recovery_state().unwrap().set, "{n}");
        assert!(phone.e2e.set_up_recovery().is_ok(), "{n}: tried again");
    }
}

/// A verification request, as `from`'s device `device` would send one to
/// Olena's phone, with the id its sender chose.
fn request_to(w: &World, from: &Person, device: &str, to: &Person, id: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    w.ok(
        from,
        "POST",
        "/chat/verification",
        Some(
            json!({"user": to.me, "device": "PHONEA", "fromDevice": device,
            "type": "m.key.verification.request",
            "content": {"from_device": device, "methods": ["m.sas.v1"],
                "timestamp": now, "transaction_id": id}}),
        ),
    );
}

#[test]
fn two_verifications_with_one_id_are_neither_acted_on() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let taras = w.person("taras@ministry.example", false);
        let marek = w.person("marek@ministry.example", false);
        w.sealed_room(
            &olena,
            &[
                (&taras, "taras@ministry.example"),
                (&marek, "marek@ministry.example"),
            ],
        );
        let phone = w.phone(&olena, "PHONEA");
        let _t = w.phone(&taras, "PHONET");
        let _m = w.phone(&marek, "PHONEM");

        // One request: listed, and its id names it.
        request_to(&w, &taras, "PHONET", &olena, "ONLYONE");
        let state = phone_state(&phone, "ONLYONE").map(|v| (v.user, v.state));
        assert_eq!(
            Some((taras.me.clone(), "incoming".to_string())),
            state,
            "{n}"
        );

        // Two people's requests with one id: neither is listed nor acted on.
        request_to(&w, &taras, "PHONET", &olena, "THESAME");
        request_to(&w, &marek, "PHONEM", &olena, "THESAME");
        let listed = phone.e2e.verifications().unwrap();
        assert!(listed.iter().all(|v| v.id != "THESAME"), "{n}: {listed:?}");
        assert!(listed.iter().any(|v| v.id == "ONLYONE"), "{n}: {listed:?}");
        assert!(
            matches!(
                phone.e2e.accept_verification("THESAME"),
                Err(ortus_e2e::Error::Refused(_))
            ),
            "{n}: ambiguous"
        );
        phone.e2e.accept_verification("ONLYONE").unwrap();
    }
}
