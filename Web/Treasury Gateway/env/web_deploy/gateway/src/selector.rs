use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::Uri;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

const SCRATCH_CAP: usize = 512;
const NONCE_PREVIEW_BYTES: usize = 4;

type Scratch = Box<[u8; SCRATCH_CAP]>;
type TenantPools = HashMap<String, Vec<Scratch>>;

#[derive(Clone)]
#[allow(clippy::vec_box)]
pub struct SelectorEngine {
    pools: Arc<Mutex<TenantPools>>,
}

pub struct RouteTrace {
    pub tenant: String,
    pub path: String,
    pub nonce_preview_hex: String,
}

pub struct DeferredTrace {
    tenant: String,
    path: String,
    nonce: &'static [u8],
}

pub struct ParsedSelector<'a> {
    pub tenant: &'a str,
    pub path: &'a str,
    pub nonce: &'a [u8],
}

impl SelectorEngine {
    pub fn new(snapshot_url: Option<String>, refresh_interval: Duration) -> Self {
        let engine = Self {
            pools: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Some(url) = snapshot_url {
            let engine = engine.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok(body) = fetch_http_body(&url).await {
                        engine.store_snapshot(&body);
                    }
                    sleep(refresh_interval).await;
                }
            });
        }

        engine
    }

    pub fn trace(&self, raw_header: &[u8]) -> RouteTrace {
        self.defer_trace(raw_header).finish()
    }

    pub fn defer_trace(&self, raw_header: &[u8]) -> DeferredTrace {
        let tenant_key = tenant_key(raw_header);
        let mut scratch = self.checkout(&tenant_key);
        let raw_len = raw_header.len().min(SCRATCH_CAP);
        scratch[..raw_len].copy_from_slice(&raw_header[..raw_len]);

        let (tenant, path, nonce) = {
            let raw = &scratch[..raw_len];
            let parsed = unsafe { parse_route_selector(raw, SCRATCH_CAP) };
            let nonce = unsafe { std::mem::transmute::<&[u8], &'static [u8]>(parsed.nonce) };
            (parsed.tenant.to_string(), parsed.path.to_string(), nonce)
        };

        self.checkin(tenant_key, scratch);

        DeferredTrace {
            tenant,
            path,
            nonce,
        }
    }

    fn store_snapshot(&self, body: &[u8]) {
        let snapshot = body[..body.len().min(SCRATCH_CAP)].to_vec();

        let mut pools = self.pools.lock().expect("selector pool lock poisoned");
        for pool in pools.values_mut() {
            for scratch in pool.iter_mut() {
                scratch.fill(0);
                scratch[..snapshot.len()].copy_from_slice(&snapshot);
            }
        }
    }

    fn checkout(&self, tenant: &str) -> Box<[u8; SCRATCH_CAP]> {
        let mut pools = self.pools.lock().expect("selector pool lock poisoned");
        let pool = pools.entry(tenant.to_string()).or_default();
        let mut scratch = pool.pop().unwrap_or_else(|| Box::new([0_u8; SCRATCH_CAP]));
        scratch.fill(0);
        scratch
    }

    fn checkin(&self, tenant: String, scratch: Box<[u8; SCRATCH_CAP]>) {
        self.pools
            .lock()
            .expect("selector pool lock poisoned")
            .entry(tenant)
            .or_default()
            .push(scratch);
    }
}

impl DeferredTrace {
    pub fn finish(self) -> RouteTrace {
        RouteTrace {
            tenant: self.tenant,
            path: self.path,
            nonce_preview_hex: hex(self.nonce),
        }
    }
}

unsafe fn parse_route_selector(raw: &[u8], scratch_cap: usize) -> ParsedSelector<'_> {
    let first = memchr::memchr(b':', raw).unwrap_or(raw.len());
    let second = if first < raw.len() {
        memchr::memchr(b':', &raw[first + 1..])
            .map(|index| index + first + 1)
            .unwrap_or(raw.len())
    } else {
        raw.len()
    };

    let tenant_end = first.min(raw.len());
    let path_start = first.saturating_add(1).min(raw.len());
    let path_end = second.min(raw.len());
    let nonce_start = second.saturating_add(1);
    let nonce_len = scratch_cap
        .saturating_sub(nonce_start)
        .min(NONCE_PREVIEW_BYTES);

    let tenant = unsafe { std::str::from_utf8_unchecked(&raw[..tenant_end]) };
    let path = unsafe { std::str::from_utf8_unchecked(&raw[path_start..path_end]) };
    let nonce = if nonce_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(raw.as_ptr().add(nonce_start), nonce_len) }
    };

    ParsedSelector {
        tenant,
        path,
        nonce,
    }
}

pub fn trace_json(trace: &RouteTrace) -> Bytes {
    Bytes::from(format!(
        "{{\"tenant\":\"{}\",\"path\":\"{}\",\"nonce_preview_hex\":\"{}\"}}\n",
        json_escape(&trace.tenant),
        json_escape(&trace.path),
        trace.nonce_preview_hex
    ))
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push(' '),
            ch => out.push(ch),
        }
    }
    out
}

fn tenant_key(raw: &[u8]) -> String {
    let end = memchr::memchr(b':', raw).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

async fn fetch_http_body(url: &str) -> Result<Vec<u8>, IoError> {
    let uri = url
        .parse::<Uri>()
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    if uri.scheme_str() != Some("http") {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "selector snapshot URL must use http",
        ));
    }

    let authority = uri
        .authority()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "snapshot URL missing authority"))?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(80);
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let mut stream = TcpStream::connect(target).await?;
    let request =
        format!("GET {path_and_query} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let body_start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "snapshot response missing body"))?;
    Ok(response[body_start..].to_vec())
}
