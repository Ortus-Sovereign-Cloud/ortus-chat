//! The chat app in process, on every installation the tests have
//! (tests/common), answering over stdin and stdout, one JSON object per
//! line: the phones' end-to-end crate (phones/e2e) is tested against it.
//! That crate cannot link this one (matrix-sdk-sqlite and ortus-core pin
//! different SQLite bindings), so its tests run this and ask:
//!
//!     {"user": {"install": 0, "email": "…", "role": "owner" | "member"}} → {"token", "me"}
//!     {"http": {"install": 0, "token": "…", "method", "path", "body"}} → {"status", "body"}
//!     {"sql": {"install": 0, "sql": "…", "params": ["…"]}} → {"rows"} (a server that lies)
//!
//! It first says {"installations": [names]}.

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::{BufRead, Write};
use std::sync::Arc;

use ortus_core::auth::accounts::Role;
use ortus_core::instance::testing_auth::signed_in;
use ortus_core::runtime::block_on;
use rust_web_server::test_client::TestClient;
use serde_json::{json, Value};

type Call = Box<dyn Fn(&str, &str, &str, Option<&Value>) -> (i16, Value)>;

fn caller<A: rust_web_server::application::Application + 'static>(client: TestClient<A>) -> Call {
    Box::new(move |token, method, path, body| {
        let url = format!("/api/v1{path}");
        let mut r = match method {
            "GET" => client.get(&url),
            "PATCH" => client.patch(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            _ => client.post(&url),
        };
        r = r
            .header("Authorization", &format!("Bearer {token}"))
            .header("X-Requested-With", "ortus");
        if let Some(b) = body {
            r = r
                .header("Content-Type", "application/json")
                .body_bytes(b.to_string().into_bytes());
        }
        let response = r.send();
        (
            response.status(),
            serde_json::from_slice(response.body_bytes()).unwrap_or(Value::Null),
        )
    })
}

fn main() {
    let installations = common::installations();
    let mut hosts = Vec::new();
    for (_, instance, _) in &installations {
        for app in instance.apps.clone() {
            app.provide(instance, &instance.services);
        }
        hosts.push(caller(TestClient::new(ortus_core::app(Arc::clone(
            instance,
        )))));
    }
    let names: Vec<&str> = installations.iter().map(|i| i.0).collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", json!({ "installations": names })).unwrap();
    out.flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let ask: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        let answer = if let Some(u) = ask.get("user") {
            let i = u["install"].as_u64().unwrap_or(0) as usize;
            let role = if u["role"] == "owner" {
                Role::Owner
            } else {
                Role::Member
            };
            let token = signed_in(
                &installations[i].1,
                u["email"].as_str().unwrap_or_default(),
                role,
            );
            let me = hosts[i](&token, "GET", "/chat/rooms", None).1["me"].clone();
            json!({"token": token, "me": me})
        } else if let Some(h) = ask.get("http") {
            let i = h["install"].as_u64().unwrap_or(0) as usize;
            let body = h.get("body").filter(|b| !b.is_null());
            let (status, body) = hosts[i](
                h["token"].as_str().unwrap_or_default(),
                h["method"].as_str().unwrap_or("GET"),
                h["path"].as_str().unwrap_or("/"),
                body,
            );
            json!({"status": status, "body": body})
        } else if let Some(q) = ask.get("sql") {
            let i = q["install"].as_u64().unwrap_or(0) as usize;
            let params: Vec<ortus_core::storage::Value> = q["params"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| p.as_str().unwrap_or_default().into())
                .collect();
            let rows = block_on(
                installations[i]
                    .1
                    .store
                    .execute(q["sql"].as_str().unwrap_or_default(), &params),
            )
            .unwrap();
            json!({ "rows": rows })
        } else {
            json!({"error": "unknown ask"})
        };
        writeln!(out, "{answer}").unwrap();
        out.flush().unwrap();
    }
}
