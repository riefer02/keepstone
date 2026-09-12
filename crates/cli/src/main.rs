//! `keepstone` — the reference command-line client (milestone M1).
//!
//! Runs entirely offline against a local data directory. It implements the
//! capability-drop flow end to end: keygen → contacts → drop create (chunked
//! encryption + sealed content key + signed envelope + transparency log) →
//! drop open → proof verification.
#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_arguments,
    clippy::type_complexity
)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use keepstone_core::{
    content_root, sha256, CellId, DropBody, DropId, Mode, SignedDrop, PROTOCOL_VERSION,
};
use keepstone_crypto::{stream, CryptoSuite, Identity, SealedKey};
use keepstone_log::{merkle, SignedTreeHead};
use keepstone_node::{Clock, SystemClock};
use rand::rngs::OsRng;
use rand::RngCore;

/// Keepstone reference client.
#[derive(Debug, Parser)]
#[command(name = "keepstone", version, about = "Encrypted geospatial dead drops")]
struct Cli {
    /// Data directory for keys, contacts, drops, and the local log.
    #[arg(
        long,
        global = true,
        env = "KEEPSTONE_DATA",
        default_value = "./.keepstone-data"
    )]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new device identity.
    Keygen,
    /// Print this device's public keys.
    Id,
    /// Add a contact (public keys, exchanged out of band).
    ContactAdd {
        /// Petname for the contact.
        name: String,
        /// Contact's Ed25519 public key (hex).
        signing: String,
        /// Contact's X25519 public key (hex).
        ecdh: String,
    },
    /// List known contacts.
    ContactList,
    /// Create an encrypted drop at a location.
    DropCreate {
        /// Recipient contact name.
        #[arg(long)]
        to: String,
        /// Latitude.
        #[arg(long, allow_hyphen_values = true)]
        lat: f64,
        /// Longitude.
        #[arg(long, allow_hyphen_values = true)]
        lng: f64,
        /// H3 resolution (0-15).
        #[arg(long, default_value_t = 9)]
        res: u8,
        /// Delivery k-ring radius.
        #[arg(long, default_value_t = 2)]
        ring: u32,
        /// Inline message payload.
        #[arg(long, conflicts_with = "file")]
        message: Option<String>,
        /// File payload.
        #[arg(long, conflicts_with = "message")]
        file: Option<PathBuf>,
        /// Time-to-live in seconds (0 = never expires).
        #[arg(long, default_value_t = 0)]
        ttl: u64,
    },
    /// Open (decrypt) a drop by id.
    DropOpen {
        /// Drop id (hex).
        id: String,
        /// Write plaintext to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List drops, optionally filtered to those near a location.
    DropList {
        /// Latitude for a proximity filter.
        #[arg(long, requires = "lng", allow_hyphen_values = true)]
        lat: Option<f64>,
        /// Longitude for a proximity filter.
        #[arg(long, requires = "lat", allow_hyphen_values = true)]
        lng: Option<f64>,
        /// k-ring radius for the proximity filter.
        #[arg(long, default_value_t = 2)]
        ring: u32,
    },
    /// Verify a drop's signature, log inclusion, and the log's signed tree head.
    LogVerify {
        /// Drop id (hex).
        id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    fs::create_dir_all(&cli.data_dir)
        .with_context(|| format!("creating {}", cli.data_dir.display()))?;

    match cli.command {
        Command::Keygen => keygen(&cli.data_dir),
        Command::Id => print_id(&cli.data_dir),
        Command::ContactAdd {
            name,
            signing,
            ecdh,
        } => contact_add(&cli.data_dir, &name, &signing, &ecdh),
        Command::ContactList => contact_list(&cli.data_dir),
        Command::DropCreate {
            to,
            lat,
            lng,
            res,
            ring,
            message,
            file,
            ttl,
        } => drop_create(&cli.data_dir, &to, lat, lng, res, ring, message, file, ttl),
        Command::DropOpen { id, out } => drop_open(&cli.data_dir, &id, out.as_deref()),
        Command::DropList { lat, lng, ring } => drop_list(&cli.data_dir, lat, lng, ring),
        Command::LogVerify { id } => log_verify(&cli.data_dir, &id),
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

fn identity_path(dir: &Path) -> PathBuf {
    dir.join("identity.txt")
}

fn save_identity(dir: &Path, identity: &Identity) -> Result<()> {
    let contents = format!(
        "{}\n{}\n",
        hex::encode(identity.signing_secret_bytes()),
        hex::encode(identity.ecdh_secret_bytes())
    );
    fs::write(identity_path(dir), contents).context("writing identity")?;
    Ok(())
}

fn load_identity(dir: &Path) -> Result<Identity> {
    let text = fs::read_to_string(identity_path(dir))
        .context("no identity found; run `keepstone keygen` first")?;
    let mut lines = text.lines();
    let signing = hex32(lines.next().ok_or_else(|| anyhow!("missing signing key"))?)?;
    let ecdh = hex32(lines.next().ok_or_else(|| anyhow!("missing ecdh key"))?)?;
    Ok(Identity::from_secret_bytes(&signing, &ecdh))
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text.trim()).context("decoding hex")?;
    bytes.try_into().map_err(|_| anyhow!("expected 32 bytes"))
}

fn keygen(dir: &Path) -> Result<()> {
    if identity_path(dir).exists() {
        bail!(
            "identity already exists at {}",
            identity_path(dir).display()
        );
    }
    let identity = Identity::generate();
    save_identity(dir, &identity)?;
    println!("identity created");
    println!("  signing: {}", hex::encode(identity.signing_public()));
    println!("  ecdh:    {}", hex::encode(identity.ecdh_public()));
    Ok(())
}

fn print_id(dir: &Path) -> Result<()> {
    let identity = load_identity(dir)?;
    println!("signing: {}", hex::encode(identity.signing_public()));
    println!("ecdh:    {}", hex::encode(identity.ecdh_public()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

fn contacts_path(dir: &Path) -> PathBuf {
    dir.join("contacts.txt")
}

fn contact_add(dir: &Path, name: &str, signing: &str, ecdh: &str) -> Result<()> {
    let signing = hex32(signing)?;
    let ecdh = hex32(ecdh)?;
    if name.contains(char::is_whitespace) {
        bail!("contact name must not contain whitespace");
    }
    let mut existing = fs::read_to_string(contacts_path(dir)).unwrap_or_default();
    if existing.lines().any(|l| l.starts_with(&format!("{name} "))) {
        bail!("contact `{name}` already exists");
    }
    existing.push_str(&format!(
        "{name} {} {}\n",
        hex::encode(signing),
        hex::encode(ecdh)
    ));
    fs::write(contacts_path(dir), existing).context("writing contacts")?;
    println!("contact `{name}` added");
    Ok(())
}

fn load_contacts(dir: &Path) -> Result<Vec<(String, [u8; 32], [u8; 32])>> {
    let text = fs::read_to_string(contacts_path(dir)).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(signing), Some(ecdh)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        out.push((name.to_owned(), hex32(signing)?, hex32(ecdh)?));
    }
    Ok(out)
}

fn contact_list(dir: &Path) -> Result<()> {
    let contacts = load_contacts(dir)?;
    if contacts.is_empty() {
        println!("(no contacts)");
        return Ok(());
    }
    for (name, signing, ecdh) in contacts {
        println!(
            "{name}\n  signing: {}\n  ecdh:    {}",
            hex::encode(signing),
            hex::encode(ecdh)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Drops
// ---------------------------------------------------------------------------

fn drops_dir(dir: &Path) -> PathBuf {
    dir.join("drops")
}

fn chunks_dir(dir: &Path, id: &DropId) -> PathBuf {
    dir.join("chunks").join(id.to_hex())
}

fn drop_path(dir: &Path, id: &DropId) -> PathBuf {
    drops_dir(dir).join(format!("{}.signed", id.to_hex()))
}

fn drop_create(
    dir: &Path,
    to: &str,
    lat: f64,
    lng: f64,
    res: u8,
    ring: u32,
    message: Option<String>,
    file: Option<PathBuf>,
    ttl: u64,
) -> Result<()> {
    let identity = load_identity(dir)?;
    let contacts = load_contacts(dir)?;
    let (_, _signing, recipient_ecdh) = contacts
        .iter()
        .find(|(name, _, _)| name == to)
        .cloned()
        .ok_or_else(|| anyhow!("unknown contact `{to}`; add them with `contact-add`"))?;

    let plaintext = match (message, file) {
        (Some(message), None) => message.into_bytes(),
        (None, Some(path)) => {
            fs::read(&path).with_context(|| format!("reading payload {}", path.display()))?
        }
        (None, None) => bail!("provide --message or --file"),
        (Some(_), Some(_)) => bail!("provide only one of --message or --file"),
    };

    // Per-drop content key — the actual lock.
    let mut content_key = [0u8; 32];
    OsRng.fill_bytes(&mut content_key);

    // Chunked, authenticated encryption.
    let (framing, chunks) = stream::encrypt(&content_key, &plaintext)?;
    let root = content_root(&chunks);

    // Seal the content key to the recipient's device key.
    let sealed = SealedKey::seal(&content_key, &recipient_ecdh)?;

    let cell = CellId::from_lat_lng(lat, lng, res)?;
    let now = SystemClock.now_unix();
    let expiry = if ttl == 0 { 0 } else { now.saturating_add(ttl) };

    let body = DropBody {
        version: PROTOCOL_VERSION,
        suite: CryptoSuite::default_suite().id(),
        cell: cell.to_hex(),
        ring,
        created_at: now,
        expiry,
        mode: Mode::Capability.id(),
        chunk_size: u32::try_from(stream::DEFAULT_CHUNK_SIZE)?,
        chunk_count: framing.total,
        content_root: root,
        prefix: framing.prefix,
        wrapped_keys: vec![keepstone_core::WrappedKey {
            recipient: recipient_ecdh,
            sealed,
        }],
    };

    let signed = SignedDrop::sign(&identity, &body);
    let id = signed.id();

    // Persist ciphertext chunks + the signed envelope.
    let chunk_dir = chunks_dir(dir, &id);
    fs::create_dir_all(&chunk_dir).with_context(|| format!("creating {}", chunk_dir.display()))?;
    for (index, chunk) in chunks.iter().enumerate() {
        fs::write(chunk_dir.join(format!("{index}.bin")), chunk).context("writing chunk")?;
    }
    fs::create_dir_all(drops_dir(dir)).ok();
    fs::write(drop_path(dir, &id), &signed.raw).context("writing drop")?;

    // Append to the local transparency log.
    append_log_entry(dir, &signed.raw)?;

    println!("drop created");
    println!("  id:      {id}");
    println!("  cell:    {}", cell.to_hex());
    println!("  chunks:  {}", framing.total);
    println!("  bytes:   {}", plaintext.len());
    Ok(())
}

fn load_chunks(dir: &Path, id: &DropId, count: u32) -> Result<Vec<Vec<u8>>> {
    let chunk_dir = chunks_dir(dir, id);
    let mut chunks = Vec::with_capacity(count as usize);
    for index in 0..count {
        let path = chunk_dir.join(format!("{index}.bin"));
        chunks.push(fs::read(&path).with_context(|| format!("reading {}", path.display()))?);
    }
    Ok(chunks)
}

fn drop_open(dir: &Path, id_text: &str, out: Option<&Path>) -> Result<()> {
    let identity = load_identity(dir)?;
    let id = DropId::from_hex(id_text)?;
    let raw = fs::read(drop_path(dir, &id)).with_context(|| format!("no such drop: {id_text}"))?;
    let signed = SignedDrop::decode(&raw)?;
    signed.verify().context("drop signature invalid")?;
    let body = signed.body()?;

    let wrapped = body
        .wrapped_keys
        .iter()
        .find(|w| w.recipient == identity.ecdh_public())
        .ok_or_else(|| anyhow!("this drop is not addressed to this device"))?;

    let content_key = wrapped
        .sealed
        .open(&identity.ecdh_secret_bytes())
        .context("could not unseal content key")?;

    let chunks = load_chunks(dir, &id, body.chunk_count)?;
    let framing = stream::Framing {
        prefix: body.prefix,
        total: body.chunk_count,
    };
    let plaintext = stream::decrypt(&content_key, &framing, &chunks)
        .context("decryption failed (wrong key or corrupted chunks)")?;

    if let Some(path) = out {
        fs::write(path, &plaintext).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {} bytes to {}", plaintext.len(), path.display());
    } else {
        use std::io::Write as _;
        std::io::stdout().write_all(&plaintext)?;
        println!();
    }
    Ok(())
}

fn drop_list(dir: &Path, lat: Option<f64>, lng: Option<f64>, ring: u32) -> Result<()> {
    let entries = match fs::read_dir(drops_dir(dir)) {
        Ok(entries) => entries,
        Err(_) => {
            println!("(no drops)");
            return Ok(());
        }
    };

    let mut rows = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("signed") {
            continue;
        }
        let raw = fs::read(&path)?;
        let Ok(signed) = SignedDrop::decode(&raw) else {
            continue;
        };
        let id = signed.id();
        let Ok(body) = signed.body() else {
            continue;
        };
        if let (Some(lat), Some(lng)) = (lat, lng) {
            let cell = CellId::parse_hex(&body.cell)?;
            let ours = CellId::from_lat_lng(lat, lng, cell.resolution())?;
            if !ours.ring(ring).contains(&cell) {
                continue;
            }
        }
        rows.push((id, body));
    }

    if rows.is_empty() {
        println!("(no drops)");
        return Ok(());
    }
    for (id, body) in rows {
        let expiry = if body.expiry == 0 {
            "never".to_owned()
        } else {
            body.expiry.to_string()
        };
        println!(
            "{id}  cell={} ring={} chunks={} created={} expiry={}",
            body.cell, body.ring, body.chunk_count, body.created_at, expiry
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Local transparency log
// ---------------------------------------------------------------------------

fn log_dir(dir: &Path) -> PathBuf {
    dir.join("log")
}

fn log_entries_path(dir: &Path) -> PathBuf {
    log_dir(dir).join("entries.bin")
}

fn append_log_entry(dir: &Path, raw: &[u8]) -> Result<()> {
    use std::io::Write as _;
    fs::create_dir_all(log_dir(dir)).context("creating log dir")?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_entries_path(dir))
        .context("opening log")?;
    file.write_all(&u32::try_from(raw.len())?.to_be_bytes())?;
    file.write_all(raw)?;
    Ok(())
}

fn load_log_entries(dir: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = match fs::read(log_entries_path(dir)) {
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

fn log_identity(dir: &Path) -> Result<Identity> {
    let path = log_dir(dir).join("key.txt");
    if let Ok(text) = fs::read_to_string(&path) {
        let mut lines = text.lines();
        let signing = hex32(lines.next().ok_or_else(|| anyhow!("bad log key"))?)?;
        let ecdh = hex32(lines.next().ok_or_else(|| anyhow!("bad log key"))?)?;
        return Ok(Identity::from_secret_bytes(&signing, &ecdh));
    }
    let identity = Identity::generate();
    fs::create_dir_all(log_dir(dir)).context("creating log dir")?;
    fs::write(
        &path,
        format!(
            "{}\n{}\n",
            hex::encode(identity.signing_secret_bytes()),
            hex::encode(identity.ecdh_secret_bytes())
        ),
    )?;
    Ok(identity)
}

fn log_verify(dir: &Path, id_text: &str) -> Result<()> {
    let id = DropId::from_hex(id_text)?;
    let raw = fs::read(drop_path(dir, &id)).with_context(|| format!("no such drop: {id_text}"))?;
    let signed = SignedDrop::decode(&raw)?;
    signed.verify().context("drop signature invalid")?;

    let entries = load_log_entries(dir)?;
    let leaves: Vec<merkle::Hash> = entries.iter().map(|e| merkle::leaf_hash(e)).collect();
    let index = entries
        .iter()
        .position(|e| sha256(e) == *id.as_bytes())
        .ok_or_else(|| anyhow!("drop is not present in the local log"))?;
    let tree_size = leaves.len();
    let root = merkle::mth(&leaves);
    let proof = merkle::inclusion_proof(&leaves, index)?;
    let included = merkle::verify_inclusion(&leaves[index], index, tree_size, &proof, &root);

    let log = log_identity(dir)?;
    let sth = SignedTreeHead::sign(&log, tree_size as u64, root, SystemClock.now_unix());
    let sth_ok = sth.verify().is_ok();

    println!("signature:   ok");
    println!("inclusion:   {}", if included { "ok" } else { "FAILED" });
    println!("tree size:   {tree_size}");
    println!("leaf index:  {index}");
    println!("merkle root: {}", hex::encode(root));
    println!("sth:         {}", if sth_ok { "ok" } else { "FAILED" });
    if !included || !sth_ok {
        bail!("verification failed");
    }
    Ok(())
}
