//! Requests to partner servers: where a server name leads (its
//! `.well-known` delegation, else port 8448), signed with this server's
//! key (the X-Matrix scheme), over TLS checked against the public
//! authorities and `ORTUS_FEDERATION_CA`. Every request is written to the
//! list of outside calls (Sovereignty).

use std::sync::OnceLock;
use std::time::Duration;

use ortus_core::instance::Instance;
use serde_json::{json, Value};

use crate::matrix;
use crate::store::server_name;

fn http() -> Result<reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let ca = std::env::var("ORTUS_FEDERATION_CA")
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok());
            let tls = ortus_core::http::tls_config(ca.as_deref())?;
            let mut b = reqwest::Client::builder()
                .tls_backend_preconfigured(tls)
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                // No pooled connections: requests come from more than one
                // runtime (the web role's and the jobs').
                .pool_max_idle_per_host(0);
            // Tests name where a server is ("peer.test=127.0.0.1:8448,...").
            if let Ok(map) = std::env::var("ORTUS_FEDERATION_HOSTS") {
                for pair in map.split(',') {
                    if let Some((name, addr)) = pair.split_once('=') {
                        if let Ok(addr) = addr.trim().parse::<std::net::SocketAddr>() {
                            b = b.resolve(name.trim(), addr);
                        }
                    }
                }
            }
            b.build().map_err(|e| e.to_string())
        })
        .clone()
}

/// Where a server's federation API answers: "https://host:port".
pub async fn base(server: &str) -> Result<String, String> {
    static CACHE: OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
    > = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some((b, at)) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(server) {
        if at.elapsed() < Duration::from_secs(3600) {
            return Ok(b.clone());
        }
    }
    let found = if server
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
    {
        format!("https://{server}")
    } else {
        // Delegation, then the default port.
        match http()?
            .get(format!("https://{server}/.well-known/matrix/server"))
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => match r
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| v["m.server"].as_str().map(str::to_string))
            {
                Some(to) if to.contains(':') => format!("https://{to}"),
                Some(to) => format!("https://{to}:8448"),
                None => format!("https://{server}:8448"),
            },
            _ => format!("https://{server}:8448"),
        }
    };
    cache.lock().unwrap_or_else(|e| e.into_inner()).insert(
        server.to_string(),
        (found.clone(), std::time::Instant::now()),
    );
    Ok(found)
}

/// The X-Matrix authorisation for a request to `destination`.
pub async fn authorization(
    instance: &Instance,
    method: &str,
    uri: &str,
    destination: &str,
    content: Option<&Value>,
) -> Result<String, String> {
    let key = super::keys::ours(instance).await?;
    let origin = server_name(instance);
    let mut doc =
        json!({"method": method, "uri": uri, "origin": origin, "destination": destination});
    if let Some(c) = content {
        doc["content"] = c.clone();
    }
    let sig = key.sign(matrix::canonical(&doc).as_bytes());
    Ok(format!(
        "X-Matrix origin=\"{origin}\",destination=\"{destination}\",key=\"{}\",sig=\"{sig}\"",
        key.id
    ))
}

async fn send(
    instance: &Instance,
    server: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<&Value>,
    signed: bool,
) -> Result<Value, String> {
    if !super::partner(instance, server).await {
        return Err(format!("{server} is not a partner allowed chat"));
    }
    let url = format!("{}{path}", base(server).await?);
    ortus_core::outbound::note(instance.store.as_ref(), "chat federation", &url).await;
    let mut req = http()?
        .request(method.clone(), &url)
        .header("User-Agent", "Ortus");
    if signed {
        req = req.header(
            "Authorization",
            authorization(instance, method.as_str(), path, server, body).await?,
        );
    }
    if let Some(b) = body {
        req = req
            .header("Content-Type", "application/json")
            .body(matrix::canonical(b));
    }
    let r = req.send().await.map_err(|e| format!("{server}: {e}"))?;
    let status = r.status();
    let text = r.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "{server} answered {status}: {}",
            text.chars().take(300).collect::<String>()
        ));
    }
    serde_json::from_str(&text).map_err(|e| format!("{server}: {e}"))
}

pub async fn get_json(
    instance: &Instance,
    server: &str,
    path: &str,
    signed: bool,
) -> Result<Value, String> {
    send(instance, server, reqwest::Method::GET, path, None, signed).await
}

pub async fn put_json(
    instance: &Instance,
    server: &str,
    path: &str,
    body: &Value,
) -> Result<Value, String> {
    send(
        instance,
        server,
        reqwest::Method::PUT,
        path,
        Some(body),
        true,
    )
    .await
}

/// The parts of an X-Matrix authorisation header.
pub struct XMatrix {
    pub origin: String,
    pub destination: Option<String>,
    pub key: String,
    pub sig: String,
}

pub fn parse_authorization(header: &str) -> Option<XMatrix> {
    let rest = header.trim().strip_prefix("X-Matrix")?.trim();
    let mut origin = None;
    let mut destination = None;
    let mut key = None;
    let mut sig = None;
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "origin" => origin = Some(v),
            "destination" => destination = Some(v),
            "key" => key = Some(v),
            "sig" => sig = Some(v),
            _ => {}
        }
    }
    Some(XMatrix {
        origin: origin?,
        destination,
        key: key?,
        sig: sig?,
    })
}

/// Checks an incoming request's X-Matrix authorisation; answers the
/// requesting server's name.
pub async fn check_request(
    instance: &Instance,
    method: &str,
    uri: &str,
    header: Option<&str>,
    body: Option<&Value>,
) -> Result<String, String> {
    let x = parse_authorization(header.ok_or("no authorisation")?)
        .ok_or("an unreadable authorisation")?;
    let me = server_name(instance);
    if x.destination.as_deref().is_some_and(|d| d != me) {
        return Err("the request is for another server".into());
    }
    if !super::partner(instance, &x.origin).await {
        return Err(format!("{} is not a partner allowed chat", x.origin));
    }
    let public = super::keys::remote(instance, &x.origin, &x.key).await?;
    let mut doc = json!({"method": method, "uri": uri, "origin": x.origin, "destination": me});
    if let Some(b) = body {
        doc["content"] = b.clone();
    }
    let ok = match (matrix::unb64(&x.sig), matrix::unb64(&public)) {
        (Some(sig), Some(public)) => {
            aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, public)
                .verify(matrix::canonical(&doc).as_bytes(), &sig)
                .is_ok()
        }
        _ => false,
    };
    if ok {
        Ok(x.origin)
    } else {
        Err("the signature does not hold".into())
    }
}
