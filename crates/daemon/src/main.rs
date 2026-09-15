//! Local HTTP/JSON daemon: a thin-client backend for a browser UI.
//!
//! The daemon never holds keys for anyone else and never exposes plaintext
//! without the local identity. It is intentionally dependency-light: a small
//! hand-written HTTP/1.1 server over the shared `keepstone-store` library.
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
//!
//! With `--token` (or `KEEPSTONE_TOKEN`), all `/api/*` routes require
//! `Authorization: Bearer <token>`.
#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::too_many_arguments
)]

use std::path::PathBuf;

use keepstone_core::DropId;
use keepstone_store::Store;
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
    headers: Vec<(String, String)>,
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

    let headers: Vec<(String, String)> = headers
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();

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
        headers,
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
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type, authorization\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
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
    let mut token = std::env::var("KEEPSTONE_TOKEN").ok();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => data_dir = PathBuf::from(args.next().unwrap_or_default()),
            "--listen" => listen = args.next().unwrap_or(listen),
            "--token" => token = args.next(),
            other => eprintln!("ignoring unknown argument: {other}"),
        }
    }
    let store = match Store::open(&data_dir) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("cannot open {}: {error}", data_dir.display());
            std::process::exit(1);
        }
    };

    let listener = TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|error| panic!("bind {listen}: {error}"));
    println!(
        "keepstone daemon on http://{listen}  (data: {}){}",
        store.root().display(),
        if token.is_some() {
            "  [token auth enabled]"
        } else {
            ""
        }
    );

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let store = store.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let response = match read_request(&mut stream).await {
                Ok(request) => route(&store, &request, token.as_deref()),
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

fn authorized(request: &Request, expected: &str) -> bool {
    let expected = format!("Bearer {expected}");
    request
        .headers
        .iter()
        .any(|(name, value)| name == "authorization" && value == &expected)
}

fn route(store: &Store, request: &Request, token: Option<&str>) -> Response {
    if request.method == "OPTIONS" {
        return Response::json(200, &json!({ "ok": true }));
    }
    if request.path.starts_with("/api/") {
        if let Some(expected) = token {
            if !authorized(request, expected) {
                return Response::error(401, "unauthorized");
            }
        }
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => Response::html(INDEX_HTML),
        ("GET", "/api/id") => api(api_id(store)),
        ("GET", "/api/contacts") => api(api_contacts(store)),
        ("POST", "/api/contacts") => api_status(api_add_contact(store, &request.body), 200),
        ("GET", "/api/drops") => api(api_list_drops(store, &request.query)),
        ("POST", "/api/drops") => api_status(api_create_drop(store, &request.body), 201),
        _ => route_with_id(store, request),
    }
}

fn route_with_id(store: &Store, request: &Request) -> Response {
    let Some(rest) = request.path.strip_prefix("/api/drops/") else {
        if let Some(id) = request.path.strip_prefix("/api/log/") {
            let id = id.strip_suffix("/verify").unwrap_or(id);
            return api(api_verify(store, id));
        }
        return Response::error(404, "not found");
    };
    if let Some(id) = rest.strip_suffix("/open") {
        return api(api_open_drop(store, id));
    }
    api_status(api_drop_meta(store, rest), 200)
}

/// Map a handler result to a 200/201 response or a 400.
fn api(result: Result<Value, String>) -> Response {
    api_status(result, 200)
}

fn api_status(result: Result<Value, String>, ok: u16) -> Response {
    match result {
        Ok(value) => Response::json(ok, &value),
        Err(error) => Response::error(400, &error),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn api_id(store: &Store) -> Result<Value, String> {
    let identity = store.identity().map_err(|e| e.to_string())?;
    let hybrid = store.hybrid_public_bytes().map_err(|e| e.to_string())?;
    Ok(json!({
        "signing": hex::encode(identity.signing_public()),
        "ecdh": hex::encode(identity.ecdh_public()),
        "hybrid": hex::encode(hybrid),
    }))
}

fn api_contacts(store: &Store) -> Result<Value, String> {
    let contacts = store.contacts().map_err(|e| e.to_string())?;
    let items: Vec<Value> = contacts
        .iter()
        .map(|contact| {
            json!({
                "name": contact.name,
                "signing": hex::encode(contact.signing),
                "ecdh": hex::encode(contact.ecdh),
                "hybrid": contact.hybrid.as_ref().map(hex::encode),
            })
        })
        .collect();
    Ok(json!({ "contacts": items }))
}

fn api_add_contact(store: &Store, body: &[u8]) -> Result<Value, String> {
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
    store
        .add_contact(name, signing, ecdh, hybrid)
        .map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true }))
}

fn api_list_drops(store: &Store, query: &[(String, String)]) -> Result<Value, String> {
    let lat = query_param(query, "lat").and_then(|v| v.parse::<f64>().ok());
    let lng = query_param(query, "lng").and_then(|v| v.parse::<f64>().ok());
    let ring = query_param(query, "ring")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(2);
    let drops = store
        .list_drops(lat.zip(lng), ring)
        .map_err(|e| e.to_string())?;
    let items: Vec<Value> = drops
        .iter()
        .map(|drop| {
            json!({
                "id": drop.id.to_hex(),
                "cell": drop.cell,
                "ring": drop.ring,
                "chunks": drop.chunks,
                "created": drop.created,
                "expiry": drop.expiry,
                "suite": drop.suite,
                "sig_kind": drop.sig_kind,
            })
        })
        .collect();
    Ok(json!({ "drops": items }))
}

fn api_drop_meta(store: &Store, id_text: &str) -> Result<Value, String> {
    let id = DropId::from_hex(id_text).map_err(|e| e.to_string())?;
    let (signed, body) = store.read_drop(&id).map_err(|e| e.to_string())?;
    Ok(json!({
        "id": id.to_hex(),
        "cell": body.cell,
        "ring": body.ring,
        "chunks": body.chunk_count,
        "created": body.created_at,
        "expiry": body.expiry,
        "suite": body.suite,
        "sig_kind": signed.sig_kind,
    }))
}

fn api_create_drop(store: &Store, body: &[u8]) -> Result<Value, String> {
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
    let lat = value.get("lat").and_then(Value::as_f64).unwrap_or(0.0);
    let lng = value.get("lng").and_then(Value::as_f64).unwrap_or(0.0);
    let res = value.get("res").and_then(Value::as_u64).unwrap_or(9) as u8;
    let ring = value.get("ring").and_then(Value::as_u64).unwrap_or(2) as u32;
    let ttl = value.get("ttl").and_then(Value::as_u64).unwrap_or(0);
    let suite = value
        .get("suite")
        .and_then(Value::as_str)
        .unwrap_or("classical");
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .ok_or("message required")?;

    let created = store
        .create_drop(&to, lat, lng, res, ring, ttl, suite, message.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(json!({ "id": created.id.to_hex() }))
}

fn api_open_drop(store: &Store, id_text: &str) -> Result<Value, String> {
    let id = DropId::from_hex(id_text).map_err(|e| e.to_string())?;
    let plaintext = store.open_drop(&id).map_err(|e| e.to_string())?;
    Ok(match String::from_utf8(plaintext) {
        Ok(text) => json!({ "text": text }),
        Err(error) => json!({ "hex": hex::encode(error.into_bytes()) }),
    })
}

fn api_verify(store: &Store, id_text: &str) -> Result<Value, String> {
    let id = DropId::from_hex(id_text).map_err(|e| e.to_string())?;
    let verification = store.verify(&id).map_err(|e| e.to_string())?;
    Ok(json!({
        "signature": verification.signature,
        "inclusion": verification.inclusion,
        "sth": verification.sth,
        "tree_size": verification.tree_size,
        "leaf_index": verification.leaf_index,
        "root": hex::encode(verification.root),
        "sig_kind": verification.sig_kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keepstone-daemon-test-{}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// A store with an identity and a self-contact.
    fn store_with_self(tag: &str) -> Store {
        let store = Store::open(temp_dir(tag)).unwrap();
        let identity = store.keygen().unwrap();
        let hybrid = hex::encode(store.hybrid_public_bytes().unwrap());
        store
            .add_contact(
                "me",
                &hex::encode(identity.signing_public()),
                &hex::encode(identity.ecdh_public()),
                Some(&hybrid),
            )
            .unwrap();
        store
    }

    fn request(method: &str, path: &str, body: Value) -> Request {
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            query: Vec::new(),
            headers: Vec::new(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn handle(store: &Store, request: &Request) -> Response {
        route(store, request, None)
    }

    fn json(response: &Response) -> Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    #[test]
    fn create_list_open_verify_round_trip() {
        let store = store_with_self("roundtrip");
        let created = handle(
            &store,
            &request(
                "POST",
                "/api/drops",
                json!({ "to": ["me"], "lat": 51.5, "lng": -0.12, "suite": "hybrid", "message": "hello" }),
            ),
        );
        assert_eq!(created.status, 201);
        let id = json(&created)["id"].as_str().unwrap().to_owned();

        let list = handle(
            &store,
            &Request {
                method: "GET".to_owned(),
                path: "/api/drops".to_owned(),
                query: vec![
                    ("lat".to_owned(), "51.5".to_owned()),
                    ("lng".to_owned(), "-0.12".to_owned()),
                    ("ring".to_owned(), "3".to_owned()),
                ],
                headers: Vec::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(json(&list)["drops"].as_array().unwrap().len(), 1);

        let opened = handle(
            &store,
            &request("POST", &format!("/api/drops/{id}/open"), json!({})),
        );
        assert_eq!(json(&opened)["text"].as_str().unwrap(), "hello");

        let verified = handle(
            &store,
            &request("GET", &format!("/api/log/{id}/verify"), json!({})),
        );
        let verified = json(&verified);
        assert_eq!(verified["signature"], true);
        assert_eq!(verified["inclusion"], true);
        assert_eq!(verified["sig_kind"], 2);

        let _ = fs::remove_dir_all(store.root());
    }

    #[test]
    fn classical_drops_also_work() {
        let store = store_with_self("classical");
        let created = handle(
            &store,
            &request(
                "POST",
                "/api/drops",
                json!({ "to": ["me"], "lat": 0.0, "lng": 0.0, "suite": "classical", "message": "plain" }),
            ),
        );
        assert_eq!(created.status, 201);
        let id = json(&created)["id"].as_str().unwrap().to_owned();
        let opened = handle(
            &store,
            &request("POST", &format!("/api/drops/{id}/open"), json!({})),
        );
        assert_eq!(json(&opened)["text"].as_str().unwrap(), "plain");
        let _ = fs::remove_dir_all(store.root());
    }

    #[test]
    fn identity_and_contacts_endpoints() {
        let store = store_with_self("id");
        let id = json(&handle(&store, &request("GET", "/api/id", json!({}))));
        assert_eq!(id["signing"].as_str().unwrap().len(), 64);
        let contacts = json(&handle(&store, &request("GET", "/api/contacts", json!({}))));
        assert_eq!(contacts["contacts"].as_array().unwrap().len(), 1);
        let _ = fs::remove_dir_all(store.root());
    }

    #[test]
    fn create_without_recipients_is_rejected() {
        let store = store_with_self("noreci");
        let response = handle(
            &store,
            &request(
                "POST",
                "/api/drops",
                json!({ "lat": 0.0, "lng": 0.0, "message": "x" }),
            ),
        );
        assert_eq!(response.status, 400);
        let _ = fs::remove_dir_all(store.root());
    }

    #[test]
    fn token_auth_is_enforced() {
        let store = store_with_self("auth");
        let authed = {
            let mut request = request("GET", "/api/id", json!({}));
            request
                .headers
                .push(("authorization".to_owned(), "Bearer secret".to_owned()));
            request
        };
        assert_eq!(route(&store, &authed, Some("secret")).status, 200);
        assert_eq!(
            route(
                &store,
                &request("GET", "/api/id", json!({})),
                Some("secret")
            )
            .status,
            401
        );
        let wrong = {
            let mut request = request("GET", "/api/id", json!({}));
            request
                .headers
                .push(("authorization".to_owned(), "Bearer nope".to_owned()));
            request
        };
        assert_eq!(route(&store, &wrong, Some("secret")).status, 401);
        assert_eq!(
            handle(&store, &request("GET", "/api/id", json!({}))).status,
            200
        );
        let _ = fs::remove_dir_all(store.root());
    }
}
