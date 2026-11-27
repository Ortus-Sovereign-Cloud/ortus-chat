//! The browser scanning a phone's QR code (m.qr_code.scan.v1 on the
//! browser's side): the phone's code (matrix-sdk-crypto's, made by the
//! qrcode crate) drawn as a camera sees it, read by the browser's own
//! decoder (web/src/qrscan.ts) and scanned by its Sealer, on a real server.
//! All three of Matrix's modes: one's own new phone (2), one's own phone
//! holding the keys (1), another person's phone (0). And codes another
//! encoder made, at every level, read back exactly.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use common::{repo, Browser, Phone, World};
use matrix_sdk_crypto::matrix_sdk_qrcode::qrcode::{Color, EcLevel, QrCode, Version};
use ortus_e2e::{enc, QrImage};
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

/// The phone's code as the browser's camera reads it: the bytes.
fn read_by_browser(browser: &mut Browser, code: &QrImage) -> Vec<u8> {
    let read = browser.ask(json!({"cmd": "decode", "width": code.width, "modules": code.modules}));
    vodozemac::base64_decode(read.as_str().expect("the browser reads the phone's code")).unwrap()
}

/// Once both sides are ready (the phone accepting when asked): the
/// browser can scan, and the phone can show its code.
fn until_ready(browser: &mut Browser, phone: &Phone, id: &str, name: &str) {
    let mut accepted = false;
    let mut ready = false;
    for _ in 0..40 {
        if let Some(v) = phone_state(phone, id) {
            if v.state == "incoming" && !accepted {
                phone.e2e.accept_verification(id).unwrap();
                accepted = true;
            }
        }
        if browser_view(browser, id).is_some_and(|v| v["canScan"] == true) {
            ready = true;
            break;
        }
    }
    assert!(ready, "{name}: the browser can scan the phone's code");
    let p = phone_state(phone, id).unwrap();
    assert_eq!("ready", p.state, "{name}: the phone chooses");
    assert!(p.can_show, "{name}: and can show its code");
}

/// The browser scans the phone's code; the phone sees it scanned and says
/// so; both finish. The browser's final state.
fn scan_and_finish(
    browser: &mut Browser,
    phone: &Phone,
    id: &str,
    code: &QrImage,
    name: &str,
) -> String {
    let taken = browser
        .ask(json!({"cmd": "scanCode", "id": id, "width": code.width, "modules": code.modules}));
    assert_eq!(json!(true), taken, "{name}: the browser takes the code");
    let mut confirmed = false;
    let mut states = (String::new(), String::new());
    for _ in 0..40 {
        if let Some(v) = phone_state(phone, id) {
            if v.state == "scanned" && !confirmed {
                phone.e2e.confirm_scanned(id, true).unwrap();
                confirmed = true;
            }
            states.1 = v.state;
        }
        if let Some(v) = browser_view(browser, id) {
            states.0 = v["state"].as_str().unwrap_or("").to_string();
        }
        if (states.0 == "done" || states.0 == "unsigned") && states.1 == "done" {
            break;
        }
    }
    assert!(confirmed, "{name}: the phone saw its code scanned");
    assert_eq!("done", states.1, "{name}: the phone finishes");
    states.0
}

#[test]
fn the_browser_scans_a_new_phones_code_and_vouches_for_it() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let (room, room_id) = w.sealed_room(&olena, &[]);
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        browser.ask(json!({"cmd": "setUpRecovery"}));
        browser.ask(json!({"cmd": "camera", "on": true}));
        // A phone that has not recovered: it does not trust the master key.
        let phone = w.phone(&olena, "PHONES");
        phone.e2e.inbox().unwrap();

        let id = browser
            .ask(json!({"cmd": "verify", "user": olena.me}))
            .as_str()
            .unwrap()
            .to_string();
        until_ready(&mut browser, &phone, &id, n);
        let code = phone.e2e.show_qr(&id).expect("the phone shows a code");
        assert!(
            read_by_browser(&mut browser, &code).starts_with(b"MATRIX\x02\x02"),
            "{n}: mode 2, the phone not trusting the master key"
        );
        let end = scan_and_finish(&mut browser, &phone, &id, &code, n);
        assert_eq!("done", end, "{n}: the browser signed the phone");
        assert_eq!(
            json!([]),
            browser.ask(json!({"cmd": "unverified", "room": room})),
            "{n}: the browser vouches for the phone"
        );
    }
}

#[test]
fn a_phone_holding_the_keys_vouches_for_the_browser_that_scanned_its_code() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let (room, room_id) = w.sealed_room(&olena, &[]);
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        browser.ask(json!({"cmd": "camera", "on": true}));
        let phone = w.phone(&olena, "PHONEK");
        phone
            .e2e
            .set_up_recovery(None)
            .expect("olena sets up on her phone");
        phone.e2e.inbox().unwrap();
        let me = olena.me.clone();
        let keys = w.ok(
            &olena,
            "GET",
            &format!("/chat/keys?user={}", enc(&me)),
            None,
        );
        let browser_device = keys["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["device"].as_str().unwrap().to_string())
            .find(|d| d != "PHONEK")
            .expect("the browser's device");
        assert!(
            phone
                .e2e
                .unverified(&room)
                .unwrap()
                .contains(&(me.clone(), browser_device.clone())),
            "{n}: the browser is not vouched for yet"
        );

        let id = browser
            .ask(json!({"cmd": "verify", "user": me}))
            .as_str()
            .unwrap()
            .to_string();
        until_ready(&mut browser, &phone, &id, n);
        let code = phone.e2e.show_qr(&id).unwrap();
        assert!(
            read_by_browser(&mut browser, &code).starts_with(b"MATRIX\x02\x01"),
            "{n}: mode 1, the phone trusting the master key"
        );
        // The browser holds no keys: it vouches for nothing; the phone does.
        let end = scan_and_finish(&mut browser, &phone, &id, &code, n);
        assert_eq!("unsigned", end, "{n}");
        let unverified = phone.e2e.unverified(&room).unwrap();
        assert!(
            !unverified.contains(&(me.clone(), browser_device.clone())),
            "{n}: the phone vouches for the browser: {unverified:?}"
        );
    }
}

#[test]
fn the_browser_scans_another_persons_phone_and_both_vouch() {
    for w in World::all() {
        let n = &w.name;
        let olena = w.person("olena@ministry.example", true);
        let taras = w.person("taras@ministry.example", false);
        let (room, room_id) = w.sealed_room(&olena, &[(&taras, "taras@ministry.example")]);
        let mut browser = Browser::start(&w, &olena);
        browser.ask(json!({"cmd": "ready"}));
        browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
        browser.ask(json!({"cmd": "setUpRecovery"}));
        browser.ask(json!({"cmd": "camera", "on": true}));
        let phone = w.phone(&taras, "PHONEO");
        phone
            .e2e
            .set_up_recovery(None)
            .expect("taras sets up on his phone");
        phone.e2e.inbox().unwrap();
        let olena_me = olena.me.clone();
        let keys = w.ok(
            &olena,
            "GET",
            &format!("/chat/keys?user={}", enc(&olena_me)),
            None,
        );
        let device = keys["devices"][0]["device"].as_str().unwrap().to_string();

        // The phone asks; the browser accepts, shows its code and can scan the phone's.
        let id = phone.e2e.verify_device(&olena_me, &device).unwrap();
        let mut ready = false;
        for _ in 0..40 {
            if let Some(v) = browser_view(&mut browser, &id) {
                if v["state"] == "incoming" {
                    browser.ask(json!({"cmd": "accept", "id": id}));
                }
                if v["canScan"] == true {
                    ready = true;
                    break;
                }
            }
        }
        assert!(ready, "{n}: the browser can scan");
        assert!(
            phone_state(&phone, &id).is_some_and(|v| v.state == "ready" && v.can_show),
            "{n}"
        );
        let code = phone.e2e.show_qr(&id).unwrap();
        assert!(
            read_by_browser(&mut browser, &code).starts_with(b"MATRIX\x02\x00"),
            "{n}: mode 0, another person"
        );
        let end = scan_and_finish(&mut browser, &phone, &id, &code, n);
        assert_eq!("done", end, "{n}: the browser signed taras's master key");
        let theirs = browser.ask(json!({"cmd": "unverified", "room": room}));
        assert!(
            !theirs
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["device"] == "PHONEO"),
            "{n}: olena vouches for taras's phone: {theirs}"
        );
        let unverified = phone.e2e.unverified(&room).unwrap();
        assert!(
            !unverified.iter().any(|(u, _)| u == &olena_me),
            "{n}: taras vouches for olena: {unverified:?}"
        );
    }
}

#[test]
fn a_code_whose_keys_are_not_the_servers_stops_the_verification() {
    let w = World::all().into_iter().next().unwrap();
    let n = &w.name;
    let olena = w.person("olena@ministry.example", true);
    let (room, room_id) = w.sealed_room(&olena, &[]);
    let mut browser = Browser::start(&w, &olena);
    browser.ask(json!({"cmd": "ready"}));
    browser.ask(json!({"cmd": "sync", "room": room, "roomId": room_id}));
    browser.ask(json!({"cmd": "setUpRecovery"}));
    browser.ask(json!({"cmd": "camera", "on": true}));
    let phone = w.phone(&olena, "PHONEX");
    phone.e2e.inbox().unwrap();
    let id = browser
        .ask(json!({"cmd": "verify", "user": olena.me}))
        .as_str()
        .unwrap()
        .to_string();
    until_ready(&mut browser, &phone, &id, n);
    let bytes = read_by_browser(&mut browser, &phone.e2e.show_qr(&id).unwrap());
    // A code of another verification is passed over (scanning goes on).
    let mut other = bytes.clone();
    other[10] ^= 1;
    let elsewhere = QrCode::with_error_correction_level(&other, EcLevel::L).unwrap();
    let taken = browser.ask(json!({"cmd": "scanCode", "id": id, "width": elsewhere.width(), "modules": dark(&elsewhere)}));
    assert_eq!(json!(false), taken, "{n}");
    // The phone's code with its device key changed by one bit: stopped.
    let mut forged = bytes;
    let at = 10 + usize::from(forged[8]) * 256 + usize::from(forged[9]);
    forged[at] ^= 1;
    let forged = QrCode::with_error_correction_level(&forged, EcLevel::L).unwrap();
    let taken = browser.ask(
        json!({"cmd": "scanCode", "id": id, "width": forged.width(), "modules": dark(&forged)}),
    );
    assert_eq!(json!(true), taken, "{n}");
    let v = browser_view(&mut browser, &id).unwrap();
    assert_eq!("cancelled", v["state"], "{n}: {v}");
    assert!(
        phone_state(&phone, &id).is_some_and(|v| v.state == "cancelled"),
        "{n}: the phone hears it"
    );
}

fn dark(code: &QrCode) -> Vec<bool> {
    code.to_colors()
        .into_iter()
        .map(|c| c == Color::Dark)
        .collect()
}

/// Codes the qrcode crate made (another encoder: its own tables, masks and
/// segments, digits and letters packed as such), at every level and from
/// version 1 to past 15, drawn at a slant and read back by the browser's
/// decoder exactly. No server: the browser's peer alone.
#[test]
fn the_browsers_decoder_reads_another_encoders_codes() {
    let mut node = Command::new("node")
        .arg("interop/e2e-peer.ts")
        .current_dir(repo().join("web"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("node");
    let mut to = node.stdin.take().unwrap();
    let mut from = BufReader::new(node.stdout.take().unwrap()).lines();
    let mut ask = |v: Value| -> Value {
        writeln!(to, "{v}").unwrap();
        to.flush().unwrap();
        serde_json::from_str(&from.next().expect("a line").unwrap()).unwrap()
    };
    assert_eq!("ready", ask(json!({"me": "@decoder:ortus.test"}))["result"]);
    let mut seed = 0x2545_f491_u32;
    let mut byte = move || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        (seed >> 24) as u8
    };
    let mut versions = Vec::new();
    for level in [EcLevel::L, EcLevel::M, EcLevel::Q, EcLevel::H] {
        for length in [12, 40, 90, 150, 220, 300] {
            let mut data: Vec<u8> = (0..length).map(|_| byte()).collect();
            data[..7].copy_from_slice(b"MATRIX\x02");
            // Digits and capitals in the middle: segments other than bytes.
            if length >= 90 {
                data[20..50].copy_from_slice(b"012345678901234567890123456789");
                data[50..70].copy_from_slice(b"ORTUS VERIFY CODE 42");
            }
            let code = QrCode::with_error_correction_level(&data, level).unwrap();
            if let Version::Normal(v) = code.version() {
                versions.push(v);
            }
            let read = ask(
                json!({"cmd": "decode", "width": code.width(), "modules": dark(&code), "angle": -11, "skew": 0.03}),
            );
            let got = read["result"].as_str().unwrap_or_else(|| {
                panic!(
                    "{level:?}, {length} bytes, {:?}: not read: {read}",
                    code.version()
                )
            });
            assert_eq!(
                data,
                vodozemac::base64_decode(got).unwrap(),
                "{level:?}, {length} bytes, {:?}",
                code.version()
            );
        }
    }
    assert!(
        versions.contains(&1)
            && versions.iter().any(|v| *v >= 7)
            && versions.iter().any(|v| *v >= 15),
        "{versions:?}"
    );
    writeln!(to, "{}", json!({"cmd": "quit"})).unwrap();
    let _ = node.wait();
}
