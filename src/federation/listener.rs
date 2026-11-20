//! The federation listener (the "federation" task of the web role):
//! Matrix's server-server API with TLS on `ORTUS_FEDERATION_LISTEN`
//! (default 0.0.0.0:8448), only when `ORTUS_FEDERATION_TLS_CERT` and
//! `_KEY` are set. Its own port keeps `/_matrix/` off the web port (which
//! serves only Ortus's paths). Connection handling is the calendar's DAV
//! listener's: bounded heads, bodies, time and connections per address.

use std::sync::Arc;
use std::time::Duration;

use ortus_core::instance::Instance;
use rust_web_server::header::Header;
use rust_web_server::prelude::*;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 4 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(60);
const MAX_CONNECTIONS: usize = 500;
/// Connections from one address at a time.
const MAX_PER_ADDRESS: usize = 32;
/// A whole request (head and body) must arrive within this.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

fn tls() -> Option<Arc<tokio_rustls::rustls::ServerConfig>> {
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert = std::env::var("ORTUS_FEDERATION_TLS_CERT").ok()?;
    let key = std::env::var("ORTUS_FEDERATION_TLS_KEY").ok()?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert)
        .ok()?
        .filter_map(Result::ok)
        .collect();
    let key = PrivateKeyDer::from_pem_file(&key).ok()?;
    let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| eprintln!("ortus: chat: the federation certificate: {e}"))
    .ok()?;
    Some(Arc::new(config))
}

/// The role task: the federation listener, when a certificate is set.
pub fn run(
    instance: Arc<Instance>,
    mut stop: ortus_core::app::Stop,
) -> ortus_core::storage::BoxFuture<'static, Result<(), String>> {
    Box::pin(async move {
        let Some(config) = tls() else {
            // No certificate: no federation; the task waits to stop.
            let _ = stop.changed().await;
            return Ok(());
        };
        let addr =
            std::env::var("ORTUS_FEDERATION_LISTEN").unwrap_or_else(|_| "0.0.0.0:8448".into());
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("federation on {addr}: {e}"))?;
        println!("ortus: chat: Matrix federation on {addr}");
        serve(instance, listener, &mut stop, Some(config)).await
    })
}

/// Accepts connections until `stop` turns true.
pub async fn serve(
    instance: Arc<Instance>,
    listener: TcpListener,
    stop: &mut ortus_core::app::Stop,
    tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
) -> Result<(), String> {
    let open = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let per_address: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>> =
        Arc::default();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, peer)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let Ok(permit) = Arc::clone(&open).try_acquire_owned() else { continue };
                // No one address takes every connection.
                {
                    let mut counts = per_address.lock().unwrap_or_else(|e| e.into_inner());
                    let count = counts.entry(peer.ip()).or_insert(0);
                    if *count >= MAX_PER_ADDRESS {
                        continue;
                    }
                    *count += 1;
                }
                let (instance, tls, counts) = (Arc::clone(&instance), tls.clone(), Arc::clone(&per_address));
                tokio::spawn(async move {
                    let _permit = permit;
                    let _leave = Leave(counts, peer.ip());
                    let stream: Box<dyn Stream> = match tls {
                        Some(config) => match tokio::time::timeout(Duration::from_secs(30), tokio_rustls::TlsAcceptor::from(config).accept(socket)).await {
                            Ok(Ok(s)) => Box::new(s),
                            _ => return,
                        },
                        None => Box::new(socket),
                    };
                    let _ = connection(instance, stream, peer).await;
                });
            }
            _ = stop.changed() => return Ok(()),
        }
    }
}

/// Counts a connection off its address when it ends.
struct Leave(
    Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
    std::net::IpAddr,
);

impl Drop for Leave {
    fn drop(&mut self) {
        let mut counts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.1) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.1);
            }
        }
    }
}

/// One connection: requests one after another while the client keeps it.
async fn connection(
    instance: Arc<Instance>,
    stream: Box<dyn Stream>,
    peer: std::net::SocketAddr,
) -> Result<(), String> {
    let mut reader = BufReader::new(stream);
    loop {
        let Some((method, target, version, headers, body)) =
            tokio::time::timeout(REQUEST_DEADLINE, read_request(&mut reader))
                .await
                .map_err(|_| "too slow")??
        else {
            return Ok(());
        };
        let find = |name: &str| {
            headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| h.value.to_string())
        };
        let keep = version == "HTTP/1.1"
            && !find("connection").is_some_and(|c| c.eq_ignore_ascii_case("close"));
        let request = Request {
            method: method.clone(),
            request_uri: target.clone(),
            http_version: version.clone(),
            headers,
            body: body.into(),
        };
        let response = route(&instance, request.clone(), peer).await;
        let bytes = Response::generate_response(response, request);
        let writer = reader.get_mut();
        tokio::time::timeout(IDLE, async {
            writer.write_all(&bytes).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| "too slow")?
        .map_err(|e| e.to_string())?;
        if !keep {
            return Ok(());
        }
    }
}

/// One request read: method, target, version, headers and body, or
/// `None` when the client closed the connection between requests.
#[allow(clippy::type_complexity)]
async fn read_request(
    mut reader: &mut BufReader<Box<dyn Stream>>,
) -> Result<Option<(String, String, String, Vec<Header>, Vec<u8>)>, String> {
    {
        // The head: the request line and headers.
        let mut head = Vec::new();
        loop {
            let mut line = Vec::new();
            let read = tokio::time::timeout(
                IDLE,
                (&mut reader)
                    .take((MAX_HEAD - head.len()) as u64 + 1)
                    .read_until(b'\n', &mut line),
            )
            .await
            .map_err(|_| "idle")?
            .map_err(|e| e.to_string())?;
            if read == 0 {
                return Ok(None);
            }
            head.extend_from_slice(&line);
            if head.len() > MAX_HEAD {
                return Err("head too big".into());
            }
            if line == b"\r\n" || line == b"\n" {
                if head.len() <= 2 {
                    head.clear();
                    continue;
                }
                break;
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut parts = request_line.split_whitespace();
        let (method, target, version) = (
            parts.next().unwrap_or_default().to_ascii_uppercase(),
            parts.next().unwrap_or_default().to_string(),
            parts.next().unwrap_or("HTTP/1.1").to_string(),
        );
        let headers: Vec<Header> = lines
            .filter(|l| !l.is_empty())
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| Header {
                name: n.trim().to_string().into(),
                value: v.trim().to_string().into(),
            })
            .collect();
        let find = |name: &str| {
            headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| h.value.to_string())
        };
        // The body: by length, or chunked.
        let mut body = Vec::new();
        if find("transfer-encoding").is_some_and(|t| t.to_ascii_lowercase().contains("chunked")) {
            loop {
                let mut size_line = String::new();
                tokio::time::timeout(IDLE, (&mut reader).take(1024).read_line(&mut size_line))
                    .await
                    .map_err(|_| "idle")?
                    .map_err(|e| e.to_string())?;
                let digits = size_line.trim().split(';').next().unwrap_or("0").trim();
                if digits.is_empty() || digits.len() > 8 {
                    return Err("bad chunk".into());
                }
                let size = usize::from_str_radix(digits, 16).map_err(|_| "bad chunk")?;
                if size == 0 {
                    let mut end = String::new();
                    let _ =
                        tokio::time::timeout(IDLE, (&mut reader).take(1024).read_line(&mut end))
                            .await;
                    break;
                }
                if size > MAX_BODY - body.len() {
                    return Err("body too big".into());
                }
                let before = body.len();
                tokio::time::timeout(IDLE, (&mut reader).take(size as u64).read_to_end(&mut body))
                    .await
                    .map_err(|_| "idle")?
                    .map_err(|e| e.to_string())?;
                if body.len() - before != size {
                    return Err("short chunk".into());
                }
                let mut crlf = [0u8; 2];
                tokio::time::timeout(IDLE, reader.read_exact(&mut crlf))
                    .await
                    .map_err(|_| "idle")?
                    .map_err(|e| e.to_string())?;
            }
        } else if let Some(length) = find("content-length") {
            let length: usize = length.trim().parse().map_err(|_| "bad length")?;
            if length > MAX_BODY {
                return Err("body too big".into());
            }
            tokio::time::timeout(
                IDLE,
                (&mut reader).take(length as u64).read_to_end(&mut body),
            )
            .await
            .map_err(|_| "idle")?
            .map_err(|e| e.to_string())?;
            if body.len() != length {
                return Err("short body".into());
            }
        }
        Ok(Some((method, target, version, headers, body)))
    }
}

async fn route(instance: &Arc<Instance>, request: Request, peer: std::net::SocketAddr) -> Response {
    let _ = peer;
    super::routes::answer(instance, request).await
}
