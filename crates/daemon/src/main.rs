//! Local HTTP/JSON daemon: a thin-client backend for a browser UI.
//!
//! The daemon never holds keys for anyone else and never exposes plaintext
//! without the local identity. It is intentionally dependency-light: a small
//! hand-written HTTP/1.1 server over the same crates the CLI uses.
//!
//! Endpoints (all JSON unless noted):
//!   GET  /                         -> embedded browser UI
//!   GET  /api/id                   -> local public keys
//!   GET  /api/contacts             -> contacts (with devices)
//!   POST /api/contacts             -> add a contact device
//!   GET  /api/drops?lat&lng&ring   -> list drops (optionally near a point)
//!   POST /api/drops                -> create a drop
//!   GET  /api/drops/{id}           -> drop metadata
//!   POST /api/drops/{id}/open      -> decrypt a drop
//!   GET  /api/log/{id}/verify      -> signature + inclusion + STH checks
#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::too_many_arguments
)]

use std::fs;
use std::path::{Path, PathBuf};

use keepstone_core::{
    content_root, sha256, CellId, DropBody, DropId, Mode, SealedContentKey, SignedDrop, WrappedKey,
    MIN_TAGS, PROTOCOL_VERSION,
};
use keepstone_crypto::kdf::derive_tag;
use keepstone_crypto::{
    stream, CryptoSuite, HybridKeypair, HybridPublic, Identity, MlDsaKeypair, SealedKey,
};
use keepstone_log::{merkle, SignedTreeHead};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const INDEX_HTML: &str = include_str!("../web/index.html");
const MAX_REQUEST: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// HTTP/1.1 (minimal: Content-Length bodies, Connection: close)
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty request",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            header_end = position + 4;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or("/").to_owned();

    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let (path, query) = split_target(&target);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(Request {
        method,
        path,
        query,
        body,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn split_target(target: &str) -> (String, Vec<(String, String)>) {
    match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), parse_query(query)),
        None => (target.to_owned(), Vec::new()),
    }
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (percent_decode(key), percent_decode(value)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(&input[index + 1..index + 3], 16) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: &[(String, String)], key: &str) -> Option<String> {
    query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
        body.len()
    )
    .into_bytes();
    head.extend_from_slice(body);
    stream.write_all(&head).await
}

// ---------------------------------------------------------------------------
// Server + routing
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let mut data_dir = PathBuf::from("./.keepstone-data");
    let mut listen = "127.0.0.1:8787".to_owned();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => data_dir = PathBuf::from(args.next().unwrap_or_default()),
            "--listen" => listen = args.next().unwrap_or(listen),
            other => eprintln!("ignoring unknown argument: {other}"),
        }
    }
    if let Err(error) = fs::create_dir_all(&data_dir) {
        eprintln!("cannot create {}: {error}", data_dir.display());
        std::process::exit(1);
    }

    let listener = TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|error| panic!("bind {listen}: {error}"));
    println!(
        "keepstone daemon on http://{listen}  (data: {})",
        data_dir.display()
    );

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let data_dir = data_dir.clone();
        tokio::spawn(async move {
            let response = match read_request(&mut stream).await {
                Ok(request) => route(&data_dir, &request),
                Err(_) => Response::json(400, &json!({ "error": "bad request" })),
            };
            let _ = respond(
                &mut stream,
                response.status,
                response.content_type,
                &response.body,
            )
            .await;
        });
    }
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).unwrap_or_default(),
        }
    }
    fn error(status: u16, message: &str) -> Self {
        Self::json(status, &json!({ "error": message }))
    }
    fn html(body: &str) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }
}

fn route(dir: &Path, request: &Request) -> Response {
    if request.method == "OPTIONS" {
        return Response::json(200, &json!({ "ok": true }));
    }
    let path = request.path.as_str();
    match (request.method.as_str(), path) {
        ("GET", "/") | ("GET", "/index.html") => Response::html(INDEX_HTML),
        ("GET", "/api/id") => match api_id(dir) {
            Ok(value) => Response::json(200, &value),
            Err(error) => Response::error(500, &error),
        },
        ("GET", "/api/contacts") => match api_contacts(dir) {
            Ok(value) => Response::json(200, &value),
            Err(error) => Response::error(500, &error),
        },
        ("POST", "/api/contacts") => match api_add_contact(dir, &request.body) {
            Ok(value) => Response::json(200, &value),
            Err(error) => Response::error(400, &error),
        },
        ("GET", "/api/drops") => match api_list_drops(dir, &request.query) {
            Ok(value) => Response::json(200, &value),
            Err(error) => Response::error(500, &error),
        },
        ("POST", "/api/drops") => match api_create_drop(dir, &request.body) {
            Ok(value) => Response::json(201, &value),
            Err(error) => Response::error(400, &error),
        },
        _ => route_with_id(dir, request),
    }
}

fn route_with_id(dir: &Path, request: &Request) -> Response {
    let Some(rest) = request.path.strip_prefix("/api/drops/") else {
        if let Some(id) = request.path.strip_prefix("/api/log/") {
            let id = id.strip_suffix("/verify").unwrap_or(id);
            return match api_verify(dir, id) {
                Ok(value) => Response::json(200, &value),
                Err(error) => Response::error(400, &error),
            };
        }
        return Response::error(404, "not found");
    };

    if let Some(id) = rest.strip_suffix("/open") {
        return match api_open_drop(dir, id) {
            Ok(value) => Response::json(200, &value),
            Err(error) => Response::error(400, &error),
        };
    }
    match api_drop_meta(dir, rest) {
        Ok(value) => Response::json(200, &value),
        Err(error) => Response::error(404, &error),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn api_id(dir: &Path) -> Result<Value, String> {
    let identity = load_identity(dir)?;
    let hybrid = load_hybrid(dir)?;
    Ok(json!({
        "signing": hex::encode(identity.signing_public()),
        "ecdh": hex::encode(identity.ecdh_public()),
        "hybrid": hex::encode(hybrid_public_bytes(&hybrid)),
    }))
}

fn api_contacts(dir: &Path) -> Result<Value, String> {
    let contacts = load_contacts(dir)?;
    let items: Vec<Value> = contacts
        .iter()
        .map(|(name, signing, ecdh, hybrid)| {
            json!({
                "name": name,
                "signing": hex::encode(signing),
                "ecdh": hex::encode(ecdh),
                "hybrid": hybrid.as_ref().map(hex::encode),
            })
        })
        .collect();
    Ok(json!({ "contacts": items }))
}

fn api_add_contact(dir: &Path, body: &[u8]) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or("name required")?;
    let signing = value
        .get("signing")
        .and_then(Value::as_str)
        .ok_or("signing required")?;
    let ecdh = value
        .get("ecdh")
        .and_then(Value::as_str)
        .ok_or("ecdh required")?;
    let hybrid = value.get("hybrid").and_then(Value::as_str);
    add_contact(dir, name, signing, ecdh, hybrid)?;
    Ok(json!({ "ok": true }))
}

fn api_list_drops(dir: &Path, query: &[(String, String)]) -> Result<Value, String> {
    let lat = query_param(query, "lat").and_then(|v| v.parse::<f64>().ok());
    let lng = query_param(query, "lng").and_then(|v| v.parse::<f64>().ok());
    let ring = query_param(query, "ring")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(2);
    let drops = list_drops(dir, lat.zip(lng), ring)?;
    Ok(json!({ "drops": drops }))
}

fn api_drop_meta(dir: &Path, id_text: &str) -> Result<Value, String> {
    let id = DropId::from_hex(id_text).map_err(|e| e.to_string())?;
    let raw = fs::read(drop_path(dir, &id)).map_err(|_| "no such drop".to_owned())?;
    let signed = SignedDrop::decode(&raw).map_err(|e| e.to_string())?;
    let body = signed.body().map_err(|e| e.to_string())?;
    Ok(drop_json(&id, &body, signed.sig_kind))
}

fn api_create_drop(dir: &Path, body: &[u8]) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let to: Vec<String> = value
        .get("to")
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if to.is_empty() {
        return Err("at least one recipient (`to`) is required".to_owned());
    }
    let lat = value.get("lat").and_then(Value::as_f64).unwrap_or(0.0);
    let lng = value.get("lng").and_then(Value::as_f64).unwrap_or(0.0);
    let res = value.get("res").and_then(Value::as_u64).unwrap_or(9) as u8;
    let ring = value.get("ring").and_then(Value::as_u64).unwrap_or(2) as u32;
    let suite = value
        .get("suite")
        .and_then(Value::as_str)
        .unwrap_or("classical");
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .ok_or("message required")?;

    let id = create_drop(dir, &to, lat, lng, res, ring, message.as_bytes(), suite)?;
    Ok(json!({ "id": id.to_hex() }))
}

fn api_open_drop(dir: &Path, id_text: &str) -> Result<Value, String> {
    let plaintext = open_drop(dir, id_text)?;
    Ok(match String::from_utf8(plaintext) {
        Ok(text) => json!({ "text": text }),
        Err(error) => json!({ "hex": hex::encode(error.into_bytes()) }),
    })
}

fn api_verify(dir: &Path, id_text: &str) -> Result<Value, String> {
    verify_log(dir, id_text)
}

// ---------------------------------------------------------------------------
// Storage helpers (data-dir format shared with the CLI)
// ---------------------------------------------------------------------------

fn hex32(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim()).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "expected 32 bytes".to_owned())
}

fn load_identity(dir: &Path) -> Result<Identity, String> {
    let text = fs::read_to_string(dir.join("identity.txt"))
        .map_err(|_| "no identity; run `keepstone keygen`".to_owned())?;
    let mut lines = text.lines();
    let signing = hex32(lines.next().unwrap_or_default())?;
    let ecdh = hex32(lines.next().unwrap_or_default())?;
    Ok(Identity::from_secret_bytes(&signing, &ecdh))
}

fn load_hybrid(dir: &Path) -> Result<HybridKeypair, String> {
    let text =
        fs::read_to_string(dir.join("hybrid.txt")).map_err(|_| "no hybrid key".to_owned())?;
    let bytes = hex::decode(text.trim()).map_err(|e| e.to_string())?;
    let arr: [u8; 96] = bytes
        .try_into()
        .map_err(|_| "expected 96 bytes".to_owned())?;
    HybridKeypair::from_secret_bytes(&arr).map_err(|e| e.to_string())
}

fn load_mldsa(dir: &Path) -> Result<MlDsaKeypair, String> {
    let text = fs::read_to_string(dir.join("mldsa.txt")).map_err(|_| "no ML-DSA key".to_owned())?;
    let bytes = hex::decode(text.trim()).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "expected 32 bytes".to_owned())?;
    MlDsaKeypair::from_seed(&seed).map_err(|e| e.to_string())
}

fn hybrid_public_bytes(keypair: &HybridKeypair) -> Vec<u8> {
    let public: HybridPublic = keypair.public();
    let mut out = public.x25519.to_vec();
    out.extend_from_slice(&public.kem);
    out
}

/// `(name, signing, ecdh, hybrid)`
type Contact = (String, [u8; 32], [u8; 32], Option<Vec<u8>>);

fn load_contacts(dir: &Path) -> Result<Vec<Contact>, String> {
    let text = fs::read_to_string(dir.join("contacts.txt")).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(signing), Some(ecdh)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let hybrid = match parts.next() {
            Some("-") | None => None,
            Some(value) => Some(hex::decode(value).map_err(|e| e.to_string())?),
        };
        out.push((name.to_owned(), hex32(signing)?, hex32(ecdh)?, hybrid));
    }
    Ok(out)
}

fn add_contact(
    dir: &Path,
    name: &str,
    signing: &str,
    ecdh: &str,
    hybrid: Option<&str>,
) -> Result<(), String> {
    let signing = hex32(signing)?;
    let ecdh = hex32(ecdh)?;
    let hybrid = match hybrid {
        Some(value) => Some(hex::decode(value).map_err(|e| e.to_string())?),
        None => None,
    };
    let path = dir.join("contacts.txt");
    let mut existing = fs::read_to_string(&path).unwrap_or_default();
    existing.push_str(&format!(
        "{name} {} {} {}\n",
        hex::encode(signing),
        hex::encode(ecdh),
        hybrid.map(hex::encode).unwrap_or_else(|| "-".to_owned())
    ));
    fs::write(&path, existing).map_err(|e| e.to_string())
}

fn drops_dir(dir: &Path) -> PathBuf {
    dir.join("drops")
}
fn chunks_dir(dir: &Path, id: &DropId) -> PathBuf {
    dir.join("chunks").join(id.to_hex())
}
fn drop_path(dir: &Path, id: &DropId) -> PathBuf {
    drops_dir(dir).join(format!("{}.signed", id.to_hex()))
}

fn drop_json(id: &DropId, body: &DropBody, sig_kind: u8) -> Value {
    json!({
        "id": id.to_hex(),
        "cell": body.cell,
        "ring": body.ring,
        "chunks": body.chunk_count,
        "created": body.created_at,
        "expiry": body.expiry,
        "suite": body.suite,
        "sig_kind": sig_kind,
    })
}

fn list_drops(dir: &Path, near: Option<(f64, f64)>, ring: u32) -> Result<Vec<Value>, String> {
    let entries = match fs::read_dir(drops_dir(dir)) {
        Ok(entries) => entries,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("signed") {
            continue;
        }
        let Ok(raw) = fs::read(&path) else { continue };
        let Ok(signed) = SignedDrop::decode(&raw) else {
            continue;
        };
        let Ok(body) = signed.body() else { continue };
        let id = signed.id();
        if let Some((lat, lng)) = near {
            let Ok(cell) = CellId::parse_hex(&body.cell) else {
                continue;
            };
            let Ok(ours) = CellId::from_lat_lng(lat, lng, cell.resolution()) else {
                continue;
            };
            if !ours.ring(ring).contains(&cell) {
                continue;
            }
        }
        out.push(drop_json(&id, &body, signed.sig_kind));
    }
    Ok(out)
}

fn create_drop(
    dir: &Path,
    to: &[String],
    lat: f64,
    lng: f64,
    res: u8,
    ring: u32,
    plaintext: &[u8],
    suite: &str,
) -> Result<DropId, String> {
    let identity = load_identity(dir)?;
    let contacts = load_contacts(dir)?;
    let hybrid_mode = suite.eq_ignore_ascii_case("hybrid");

    let mut recipients = Vec::new();
    for name in to {
        let matching: Vec<_> = contacts
            .iter()
            .filter(|(contact, ..)| contact == name)
            .collect();
        if matching.is_empty() {
            return Err(format!("unknown contact `{name}`"));
        }
        for (_, _, ecdh, hybrid) in matching {
            if hybrid_mode && hybrid.is_none() {
                return Err(format!("device for `{name}` has no hybrid key"));
            }
            recipients.push((*ecdh, hybrid.clone()));
        }
    }

    let mut content_key = [0u8; 32];
    OsRng.fill_bytes(&mut content_key);
    let (framing, chunks) = stream::encrypt(&content_key, plaintext).map_err(|e| e.to_string())?;
    let root = content_root(&chunks);

    let mut drop_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut drop_nonce);

    let suite_id = if hybrid_mode {
        CryptoSuite::Hybrid25519MlKem768.id()
    } else {
        CryptoSuite::Classical25519.id()
    };
    let mut wrapped_keys = Vec::new();
    for (ecdh, hybrid) in &recipients {
        let sealed = if hybrid_mode {
            let bytes = hybrid.as_ref().ok_or("recipient has no hybrid key")?;
            if bytes.len() != 32 + 1184 {
                return Err("bad hybrid key length".to_owned());
            }
            let x25519: [u8; 32] = bytes[..32]
                .try_into()
                .map_err(|_| "bad hybrid key".to_owned())?;
            let public = HybridPublic {
                x25519,
                kem: bytes[32..].to_vec(),
            };
            SealedContentKey::Hybrid(
                keepstone_crypto::hybrid::seal(&content_key, &public).map_err(|e| e.to_string())?,
            )
        } else {
            SealedContentKey::Classical(
                SealedKey::seal(&content_key, ecdh).map_err(|e| e.to_string())?,
            )
        };
        let tag = derive_tag(ecdh, &drop_nonce).map_err(|e| e.to_string())?;
        wrapped_keys.push(WrappedKey { tag, sealed });
    }

    let mut rng = OsRng;
    while wrapped_keys.len() < MIN_TAGS {
        let mut decoy_tag = [0u8; 8];
        let mut ephemeral_public = [0u8; 32];
        let mut nonce = [0u8; 24];
        let mut ciphertext = vec![0u8; 48];
        rng.fill_bytes(&mut decoy_tag);
        rng.fill_bytes(&mut ephemeral_public);
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut ciphertext);
        wrapped_keys.push(WrappedKey {
            tag: decoy_tag,
            sealed: SealedContentKey::Classical(SealedKey {
                ephemeral_public,
                nonce,
                ciphertext,
            }),
        });
    }
    wrapped_keys.shuffle(&mut rng);

    let signer = identity.signing_public();
    let pow_nonce = keepstone_core::pow::mine(&signer, &root, &drop_nonce);
    let cell = CellId::from_lat_lng(lat, lng, res).map_err(|e| e.to_string())?;
    let now = now_unix();
    let body = DropBody {
        version: PROTOCOL_VERSION,
        suite: suite_id,
        cell: cell.to_hex(),
        ring,
        created_at: now,
        expiry: 0,
        mode: Mode::Capability.id(),
        chunk_size: u32::try_from(stream::DEFAULT_CHUNK_SIZE).map_err(|e| e.to_string())?,
        chunk_count: framing.total,
        content_root: root,
        prefix: framing.prefix,
        drop_nonce,
        pow_nonce,
        wrapped_keys,
    };

    let signed = if hybrid_mode {
        let ml_dsa = load_mldsa(dir)?;
        SignedDrop::sign_hybrid(&identity, &ml_dsa, &body).map_err(|e| e.to_string())?
    } else {
        SignedDrop::sign(&identity, &body)
    };
    let id = signed.id();

    let chunk_dir = chunks_dir(dir, &id);
    fs::create_dir_all(&chunk_dir).map_err(|e| e.to_string())?;
    for (index, chunk) in chunks.iter().enumerate() {
        fs::write(chunk_dir.join(format!("{index}.bin")), chunk).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(drops_dir(dir)).ok();
    fs::write(drop_path(dir, &id), &signed.raw).map_err(|e| e.to_string())?;
    append_log_entry(dir, &signed.raw)?;
    Ok(id)
}

fn open_drop(dir: &Path, id_text: &str) -> Result<Vec<u8>, String> {
    let identity = load_identity(dir)?;
    let id = DropId::from_hex(id_text).map_err(|e| e.to_string())?;
    let raw = fs::read(drop_path(dir, &id)).map_err(|_| "no such drop".to_owned())?;
    let signed = SignedDrop::decode(&raw).map_err(|e| e.to_string())?;
    signed
        .verify()
        .map_err(|_| "signature invalid".to_owned())?;
    let body = signed.body().map_err(|e| e.to_string())?;
    if !body.pow_ok(&signed.signer) {
        return Err("proof-of-work invalid".to_owned());
    }

    let our_tag =
        derive_tag(&identity.ecdh_public(), &body.drop_nonce).map_err(|e| e.to_string())?;
    let ecdh_secret = identity.ecdh_secret_bytes();
    let mut hybrid: Option<HybridKeypair> = None;
    let mut content_key = None;
    for wrapped in &body.wrapped_keys {
        if wrapped.tag != our_tag {
            continue;
        }
        match &wrapped.sealed {
            SealedContentKey::Classical(sealed) => {
                if let Ok(key) = sealed.open(&ecdh_secret) {
                    content_key = Some(key);
                    break;
                }
            }
            SealedContentKey::Hybrid(sealed) => {
                if hybrid.is_none() {
                    hybrid = Some(load_hybrid(dir)?);
                }
                if let Some(keypair) = hybrid.as_ref() {
                    if let Ok(key) = keypair.open(sealed) {
                        content_key = Some(key);
                        break;
                    }
                }
            }
        }
    }
    let content_key = content_key.ok_or("drop is not addressed to this device")?;

    let mut chunks = Vec::new();
    for index in 0..body.chunk_count {
        let path = chunks_dir(dir, &id).join(format!("{index}.bin"));
        chunks.push(fs::read(&path).map_err(|_| format!("missing chunk {index}"))?);
    }
    let framing = stream::Framing {
        prefix: body.prefix,
        total: body.chunk_count,
    };
    stream::decrypt(&content_key, &framing, &chunks).map_err(|_| "decryption failed".to_owned())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log_dir(dir: &Path) -> PathBuf {
    dir.join("log")
}

fn append_log_entry(dir: &Path, raw: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    fs::create_dir_all(log_dir(dir)).map_err(|e| e.to_string())?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir(dir).join("entries.bin"))
        .map_err(|e| e.to_string())?;
    let len = u32::try_from(raw.len()).map_err(|e| e.to_string())?;
    file.write_all(&len.to_be_bytes())
        .map_err(|e| e.to_string())?;
    file.write_all(raw).map_err(|e| e.to_string())
}

fn load_log_entries(dir: &Path) -> Result<Vec<Vec<u8>>, String> {
    let bytes = match fs::read(log_dir(dir).join("entries.bin")) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Vec::new()),
    };
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    while cursor + 4 <= bytes.len() {
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[cursor..cursor + 4]);
        cursor += 4;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if cursor + len > bytes.len() {
            break;
        }
        entries.push(bytes[cursor..cursor + len].to_vec());
        cursor += len;
    }
    Ok(entries)
}

fn log_identity(dir: &Path) -> Result<Identity, String> {
    let path = log_dir(dir).join("key.txt");
    if let Ok(text) = fs::read_to_string(&path) {
        let mut lines = text.lines();
        let signing = hex32(lines.next().unwrap_or_default())?;
        let ecdh = hex32(lines.next().unwrap_or_default())?;
        return Ok(Identity::from_secret_bytes(&signing, &ecdh));
    }
    let identity = Identity::generate();
    fs::create_dir_all(log_dir(dir)).ok();
    fs::write(
        &path,
        format!(
            "{}\n{}\n",
            hex::encode(identity.signing_secret_bytes()),
            hex::encode(identity.ecdh_secret_bytes())
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(identity)
}

fn verify_log(dir: &Path, id_text: &str) -> Result<Value, String> {
    let id = DropId::from_hex(id_text).map_err(|e| e.to_string())?;
    let raw = fs::read(drop_path(dir, &id)).map_err(|_| "no such drop".to_owned())?;
    let signed = SignedDrop::decode(&raw).map_err(|e| e.to_string())?;
    let signature = signed.verify().is_ok();
    let entries = load_log_entries(dir)?;
    let leaves: Vec<merkle::Hash> = entries.iter().map(|e| merkle::leaf_hash(e)).collect();
    let index = entries
        .iter()
        .position(|e| sha256(e) == *id.as_bytes())
        .ok_or("drop is not in the local log")?;
    let tree_size = leaves.len();
    let root = merkle::mth(&leaves);
    let proof = merkle::inclusion_proof(&leaves, index).map_err(|e| e.to_string())?;
    let inclusion = merkle::verify_inclusion(&leaves[index], index, tree_size, &proof, &root);
    let log = log_identity(dir)?;
    let sth = SignedTreeHead::sign(&log, tree_size as u64, root, now_unix());
    Ok(json!({
        "signature": signature,
        "inclusion": inclusion,
        "sth": sth.verify().is_ok(),
        "tree_size": tree_size,
        "leaf_index": index,
        "root": hex::encode(root),
        "sig_kind": signed.sig_kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keepstone-daemon-test-{}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write the same data-dir files the CLI's `keygen` would, plus a self-contact.
    fn seed_identity(dir: &Path) {
        let identity = Identity::generate();
        fs::write(
            dir.join("identity.txt"),
            format!(
                "{}\n{}\n",
                hex::encode(identity.signing_secret_bytes()),
                hex::encode(identity.ecdh_secret_bytes())
            ),
        )
        .unwrap();
        let hybrid = HybridKeypair::generate();
        fs::write(
            dir.join("hybrid.txt"),
            hex::encode(hybrid.to_secret_bytes()),
        )
        .unwrap();
        fs::write(
            dir.join("mldsa.txt"),
            hex::encode(MlDsaKeypair::generate().to_seed()),
        )
        .unwrap();
        let mut hybrid_public = hybrid.public().x25519.to_vec();
        hybrid_public.extend_from_slice(&hybrid.public().kem);
        fs::write(
            dir.join("contacts.txt"),
            format!(
                "me {} {} {}\n",
                hex::encode(identity.signing_public()),
                hex::encode(identity.ecdh_public()),
                hex::encode(hybrid_public)
            ),
        )
        .unwrap();
    }

    fn request(method: &str, path: &str, body: Value) -> Request {
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            query: Vec::new(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn json(response: &Response) -> Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    #[test]
    fn create_list_open_verify_round_trip() {
        let dir = temp_dir("roundtrip");
        seed_identity(&dir);

        let created = route(
            &dir,
            &request(
                "POST",
                "/api/drops",
                json!({ "to": ["me"], "lat": 51.5, "lng": -0.12, "suite": "hybrid", "message": "hello" }),
            ),
        );
        assert_eq!(created.status, 201);
        let id = json(&created)["id"].as_str().unwrap().to_owned();

        let list = route(
            &dir,
            &Request {
                method: "GET".to_owned(),
                path: "/api/drops".to_owned(),
                query: vec![
                    ("lat".to_owned(), "51.5".to_owned()),
                    ("lng".to_owned(), "-0.12".to_owned()),
                    ("ring".to_owned(), "3".to_owned()),
                ],
                body: Vec::new(),
            },
        );
        assert_eq!(json(&list)["drops"].as_array().unwrap().len(), 1);

        let opened = route(
            &dir,
            &request("POST", &format!("/api/drops/{id}/open"), json!({})),
        );
        assert_eq!(json(&opened)["text"].as_str().unwrap(), "hello");

        let verified = route(
            &dir,
            &request("GET", &format!("/api/log/{id}/verify"), json!({})),
        );
        let verified = json(&verified);
        assert_eq!(verified["signature"], true);
        assert_eq!(verified["inclusion"], true);
        assert_eq!(verified["sig_kind"], 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn classical_drops_also_work() {
        let dir = temp_dir("classical");
        seed_identity(&dir);
        let created = route(
            &dir,
            &request(
                "POST",
                "/api/drops",
                json!({ "to": ["me"], "lat": 0.0, "lng": 0.0, "suite": "classical", "message": "plain" }),
            ),
        );
        assert_eq!(created.status, 201);
        let id = json(&created)["id"].as_str().unwrap().to_owned();
        let opened = route(
            &dir,
            &request("POST", &format!("/api/drops/{id}/open"), json!({})),
        );
        assert_eq!(json(&opened)["text"].as_str().unwrap(), "plain");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_and_contacts_endpoints() {
        let dir = temp_dir("id");
        seed_identity(&dir);
        let id = json(&route(&dir, &request("GET", "/api/id", json!({}))));
        assert_eq!(id["signing"].as_str().unwrap().len(), 64);
        let contacts = json(&route(&dir, &request("GET", "/api/contacts", json!({}))));
        assert_eq!(contacts["contacts"].as_array().unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_without_recipients_is_rejected() {
        let dir = temp_dir("noreci");
        seed_identity(&dir);
        let response = route(
            &dir,
            &request(
                "POST",
                "/api/drops",
                json!({ "lat": 0.0, "lng": 0.0, "message": "x" }),
            ),
        );
        assert_eq!(response.status, 400);
        let _ = fs::remove_dir_all(&dir);
    }
}
