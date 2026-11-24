//! The chat server for these tests: the app in process in the repository's
//! `examples/e2e_host.rs` (on SQLite, and on PostgreSQL with S3 when the
//! environment has them, as the repository's tests), asked over its stdin
//! and stdout. This crate cannot link the app itself: matrix-sdk-sqlite and
//! ortus-core pin different SQLite bindings. The browser is the app's own
//! `web/src/e2e.ts`, run by Node (`web/interop/e2e-peer.ts`).

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Lines, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ortus_e2e::{E2e, Transport};
use serde_json::{json, Value};

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Pipe {
    child: Child,
    to: ChildStdin,
    from: Lines<BufReader<ChildStdout>>,
}

impl Pipe {
    fn spawn(mut command: Command) -> Pipe {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn");
        let to = child.stdin.take().unwrap();
        let from = BufReader::new(child.stdout.take().unwrap()).lines();
        Pipe { child, to, from }
    }

    fn read(&mut self) -> Value {
        let line = self.from.next().expect("a line").unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}"))
    }

    fn write(&mut self, v: &Value) {
        writeln!(self.to, "{v}").unwrap();
        self.to.flush().unwrap();
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The chat server (every installation the environment allows).
pub struct Host {
    pipe: Mutex<Pipe>,
    pub installations: Vec<String>,
}

impl Host {
    pub fn start() -> Arc<Host> {
        let repo = repo();
        let target = std::env::var("ORTUS_E2E_HOST_TARGET")
            .map(PathBuf::from)
            .unwrap_or_else(|_| repo.join("target"));
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "--quiet", "--example", "e2e_host"])
            .current_dir(&repo)
            .env("CARGO_TARGET_DIR", &target)
            .status()
            .expect("cargo build");
        assert!(status.success(), "the chat server example builds");
        let mut pipe = Pipe::spawn(Command::new(target.join("debug/examples/e2e_host")));
        let first = pipe.read();
        let installations = first["installations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect();
        Arc::new(Host {
            pipe: Mutex::new(pipe),
            installations,
        })
    }

    pub fn ask(&self, v: Value) -> Value {
        let mut p = self.pipe.lock().unwrap_or_else(|e| e.into_inner());
        p.write(&v);
        p.read()
    }
}

/// A signed-in person of one installation.
#[derive(Clone)]
pub struct Person {
    pub token: String,
    pub me: String,
}

impl Person {
    /// Their Ortus id and the server's Matrix name.
    pub fn ids(&self) -> (String, String) {
        let (user, server) = self.me[1..].split_once(':').unwrap();
        (user.to_string(), server.to_string())
    }
}

#[derive(Clone)]
pub struct World {
    pub host: Arc<Host>,
    pub install: usize,
    pub name: String,
}

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A store directory removed when dropped.
pub struct Dir(pub PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn dir() -> Dir {
    let path = std::env::temp_dir().join(format!(
        "ortus-e2e-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&path).unwrap();
    Dir(path)
}

struct HostTransport {
    host: Arc<Host>,
    install: usize,
    token: String,
}

impl Transport for HostTransport {
    fn http(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
        let body: Value = body
            .map(|b| serde_json::from_str(b).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or(Value::Null);
        let r = self.host.ask(
            json!({"http": {"install": self.install, "token": self.token,
            "method": method, "path": path, "body": body}}),
        );
        Ok((
            r["status"].as_u64().unwrap_or(0) as u16,
            r["body"].to_string(),
        ))
    }
}

/// A phone: the crate, its store and the person it is signed in as.
pub struct Phone {
    pub e2e: E2e,
    pub dir: Dir,
    pub person: Person,
}

impl World {
    pub fn all() -> Vec<World> {
        let host = Host::start();
        host.installations
            .iter()
            .enumerate()
            .map(|(install, name)| World {
                host: Arc::clone(&host),
                install,
                name: name.clone(),
            })
            .collect()
    }

    pub fn person(&self, email: &str, owner: bool) -> Person {
        let r = self
            .host
            .ask(json!({"user": {"install": self.install, "email": email,
            "role": if owner { "owner" } else { "member" }}}));
        Person {
            token: r["token"].as_str().unwrap().into(),
            me: r["me"].as_str().unwrap().into(),
        }
    }

    pub fn call(
        &self,
        who: &Person,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let r = self
            .host
            .ask(json!({"http": {"install": self.install, "token": who.token,
            "method": method, "path": path, "body": body}}));
        (r["status"].as_u64().unwrap() as u16, r["body"].clone())
    }

    pub fn ok(&self, who: &Person, method: &str, path: &str, body: Option<Value>) -> Value {
        let (status, body) = self.call(who, method, path, body);
        assert!(
            (200..300).contains(&status),
            "{}: {method} {path}: {status} {body}",
            self.name
        );
        body
    }

    pub fn sql(&self, sql: &str, params: &[&str]) -> u64 {
        self.host
            .ask(json!({"sql": {"install": self.install, "sql": sql, "params": params}}))["rows"]
            .as_u64()
            .unwrap()
    }

    pub fn transport(&self, who: &Person) -> Arc<dyn Transport> {
        Arc::new(HostTransport {
            host: Arc::clone(&self.host),
            install: self.install,
            token: who.token.clone(),
        })
    }

    pub fn phone(&self, who: &Person, device: &str) -> Phone {
        let dir = dir();
        let (user, server) = who.ids();
        let e2e = E2e::open(
            &dir.0,
            "a passphrase",
            &user,
            device,
            &server,
            self.transport(who),
        )
        .unwrap_or_else(|e| panic!("{}: open: {e}", self.name));
        Phone {
            e2e,
            dir,
            person: who.clone(),
        }
    }

    /// End-to-end rooms allowed, and one made by `owner` with `members`
    /// (who join): its Ortus id and its Matrix id.
    pub fn sealed_room(&self, owner: &Person, members: &[(&Person, &str)]) -> (String, String) {
        self.ok(
            owner,
            "PATCH",
            "/chat/policy",
            Some(json!({"encryptedRooms": true})),
        );
        let emails: Vec<&str> = members.iter().map(|m| m.1).collect();
        let room = self.ok(
            owner,
            "POST",
            "/chat/rooms",
            Some(
                json!({"kind": "private", "name": "sealed", "encrypted": true, "members": emails}),
            ),
        );
        let id = room["id"].as_str().unwrap().to_string();
        for (p, _) in members {
            self.ok(p, "POST", &format!("/chat/rooms/{id}/join"), None);
        }
        (id, room["roomId"].as_str().unwrap().to_string())
    }

    pub fn message(&self, who: &Person, id: &str) -> Value {
        self.ok(
            who,
            "GET",
            &format!("/chat/messages/{}", ortus_e2e::enc(id)),
            None,
        )
    }
}

/// The browser's Sealer (web/src/e2e.ts) under Node, for one person.
pub struct Browser {
    pipe: Pipe,
    world: World,
    person: Person,
}

impl Browser {
    pub fn start(world: &World, person: &Person) -> Browser {
        let web = repo().join("web");
        let mut command = Command::new("node");
        command.arg("interop/e2e-peer.ts").current_dir(&web);
        let mut b = Browser {
            pipe: Pipe::spawn(command),
            world: world.clone(),
            person: person.clone(),
        };
        b.pipe.write(&json!({"me": person.me}));
        assert_eq!("ready", b.pipe.read()["result"]);
        b
    }

    /// One command; the browser's calls are answered from the server
    /// meanwhile.
    pub fn ask(&mut self, cmd: Value) -> Value {
        self.pipe.write(&cmd);
        loop {
            let r = self.pipe.read();
            if let Some(h) = r.get("http") {
                let body = Some(h["body"].clone()).filter(|b| !b.is_null());
                let (status, body) = self.world.call(
                    &self.person,
                    h["method"].as_str().unwrap(),
                    h["path"].as_str().unwrap(),
                    body,
                );
                self.pipe.write(&json!({"status": status, "body": body}));
                continue;
            }
            if let Some(e) = r.get("error") {
                panic!("{}: the browser: {e}", self.world.name);
            }
            return r["result"].clone();
        }
    }
}
