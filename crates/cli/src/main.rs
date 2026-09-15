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
    content_root, sha256, CellId, DropBody, DropId, Mode, SealedContentKey, SignedDrop, WrappedKey,
    MIN_TAGS, PROTOCOL_VERSION,
};
use keepstone_crypto::kdf::derive_tag;
use keepstone_crypto::{
    stream, CryptoSuite, HybridKeypair, HybridPublic, Identity, MlDsaKeypair, SealedKey,
};
use keepstone_log::{anchor, merkle, Anchor, SignedTreeHead};
use keepstone_node::{net, Clock, MemoryStore, Storage, SystemClock};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use std::sync::{Arc, Mutex};

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
        /// Contact's hybrid public key (hex, 32-byte X25519 || ML-KEM-768 EK). Optional.
        hybrid: Option<String>,
    },
    /// List known contacts.
    ContactList,
    /// Create an encrypted drop at a location.
    DropCreate {
        /// Recipient contact name. Repeat `--to` for multiple recipients.
        #[arg(long = "to", required = true)]
        to: Vec<String>,
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
        /// Crypto suite: `classical` (default) or `hybrid` (post-quantum).
        #[arg(long, default_value = "classical")]
        suite: String,
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
    /// Anchor the current tree head for a drop into the local anchor chain.
    LogAnchor {
        /// Drop id (hex).
        id: String,
    },
    /// Verify the local anchor chain.
    LogAnchors,
    /// Serve local drops to peers over TCP (reference M2 transport).
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:7777")]
        listen: String,
    },
    /// Fetch a drop and its chunks from a peer by id.
    Fetch {
        /// Peer address, e.g. `127.0.0.1:7777`.
        peer: String,
        /// Drop id (hex).
        id: String,
    },
    /// Push a local drop to a peer for storage (federated relay).
    Push {
        /// Peer address, e.g. `127.0.0.1:7777`.
        peer: String,
        /// Drop id (hex).
        id: String,
    },
    /// Serve drops to peers over libp2p (QUIC + TCP).
    P2pServe {
        /// Multiaddr to listen on.
        #[arg(long, default_value = "/ip4/127.0.0.1/tcp/7778")]
        listen: String,
    },
    /// Fetch a drop and its chunks from a libp2p peer by multiaddr.
    P2pFetch {
        /// Peer multiaddr, e.g. `/ip4/127.0.0.1/tcp/7778`.
        peer: String,
        /// Drop id (hex).
        id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
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
            hybrid,
        } => contact_add(&cli.data_dir, &name, &signing, &ecdh, hybrid.as_deref()),
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
            suite,
        } => drop_create(
            &cli.data_dir,
            &to,
            lat,
            lng,
            res,
            ring,
            message,
            file,
            ttl,
            &suite,
        ),
        Command::DropOpen { id, out } => drop_open(&cli.data_dir, &id, out.as_deref()),
        Command::DropList { lat, lng, ring } => drop_list(&cli.data_dir, lat, lng, ring),
        Command::LogVerify { id } => log_verify(&cli.data_dir, &id),
        Command::LogAnchor { id } => log_anchor(&cli.data_dir, &id),
        Command::LogAnchors => log_anchors(&cli.data_dir),
        Command::Serve { listen } => serve(&cli.data_dir, &listen).await,
        Command::Fetch { peer, id } => fetch(&cli.data_dir, &peer, &id).await,
        Command::Push { peer, id } => push(&cli.data_dir, &peer, &id).await,
        Command::P2pServe { listen } => p2p_serve(&cli.data_dir, &listen).await,
        Command::P2pFetch { peer, id } => p2p_fetch(&cli.data_dir, &peer, &id).await,
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
    let hybrid = HybridKeypair::generate();
    save_hybrid(dir, &hybrid)?;
    save_mldsa(dir, &MlDsaKeypair::generate())?;
    println!("identity created");
    println!("  signing: {}", hex::encode(identity.signing_public()));
    println!("  ecdh:    {}", hex::encode(identity.ecdh_public()));
    println!("  hybrid:  {}", hex::encode(hybrid_public_bytes(&hybrid)));
    Ok(())
}

fn print_id(dir: &Path) -> Result<()> {
    let identity = load_identity(dir)?;
    let hybrid = load_or_create_hybrid(dir)?;
    println!("signing: {}", hex::encode(identity.signing_public()));
    println!("ecdh:    {}", hex::encode(identity.ecdh_public()));
    println!("hybrid:  {}", hex::encode(hybrid_public_bytes(&hybrid)));
    Ok(())
}

fn hybrid_path(dir: &Path) -> PathBuf {
    dir.join("hybrid.txt")
}

fn hybrid_public_bytes(keypair: &HybridKeypair) -> Vec<u8> {
    let public: HybridPublic = keypair.public();
    let mut out = Vec::with_capacity(public.x25519.len() + public.kem.len());
    out.extend_from_slice(&public.x25519);
    out.extend_from_slice(&public.kem);
    out
}

fn save_hybrid(dir: &Path, keypair: &HybridKeypair) -> Result<()> {
    fs::write(hybrid_path(dir), hex::encode(keypair.to_secret_bytes()))
        .context("writing hybrid key")?;
    Ok(())
}

fn load_hybrid(dir: &Path) -> Result<HybridKeypair> {
    let text = fs::read_to_string(hybrid_path(dir))
        .context("no hybrid key found; regenerate the identity")?;
    let bytes = hex::decode(text.trim()).context("decoding hybrid key")?;
    let arr: [u8; 96] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 96-byte hybrid key"))?;
    Ok(HybridKeypair::from_secret_bytes(&arr)?)
}

fn load_or_create_hybrid(dir: &Path) -> Result<HybridKeypair> {
    if hybrid_path(dir).exists() {
        load_hybrid(dir)
    } else {
        let keypair = HybridKeypair::generate();
        save_hybrid(dir, &keypair)?;
        Ok(keypair)
    }
}

fn hybrid_public_from_bytes(bytes: &[u8]) -> Result<HybridPublic> {
    if bytes.len() != 32 + 1184 {
        bail!("hybrid public key must be 32 + 1184 bytes");
    }
    let x25519: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| anyhow!("bad hybrid x25519"))?;
    Ok(HybridPublic {
        x25519,
        kem: bytes[32..].to_vec(),
    })
}

fn mldsa_path(dir: &Path) -> PathBuf {
    dir.join("mldsa.txt")
}

fn save_mldsa(dir: &Path, keypair: &MlDsaKeypair) -> Result<()> {
    fs::write(mldsa_path(dir), hex::encode(keypair.to_seed())).context("writing ML-DSA seed")?;
    Ok(())
}

fn load_mldsa(dir: &Path) -> Result<MlDsaKeypair> {
    let text = fs::read_to_string(mldsa_path(dir))
        .context("no ML-DSA key found; regenerate the identity")?;
    let bytes = hex::decode(text.trim()).context("decoding ML-DSA seed")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte ML-DSA seed"))?;
    Ok(MlDsaKeypair::from_seed(&seed)?)
}

fn load_or_create_mldsa(dir: &Path) -> Result<MlDsaKeypair> {
    if mldsa_path(dir).exists() {
        load_mldsa(dir)
    } else {
        let keypair = MlDsaKeypair::generate();
        save_mldsa(dir, &keypair)?;
        Ok(keypair)
    }
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

fn contacts_path(dir: &Path) -> PathBuf {
    dir.join("contacts.txt")
}

fn contact_add(
    dir: &Path,
    name: &str,
    signing: &str,
    ecdh: &str,
    hybrid: Option<&str>,
) -> Result<()> {
    let signing = hex32(signing)?;
    let ecdh = hex32(ecdh)?;
    let hybrid = match hybrid {
        Some(value) => Some(hex::decode(value).context("decoding hybrid contact key")?),
        None => None,
    };
    if name.contains(char::is_whitespace) {
        bail!("contact name must not contain whitespace");
    }
    let mut existing = fs::read_to_string(contacts_path(dir)).unwrap_or_default();
    let device_line = format!("{name} {} {} ", hex::encode(signing), hex::encode(ecdh));
    if existing.lines().any(|l| l.starts_with(&device_line)) {
        bail!("contact `{name}` already has this device");
    }
    existing.push_str(&format!(
        "{name} {} {} {}\n",
        hex::encode(signing),
        hex::encode(ecdh),
        hybrid.map(hex::encode).unwrap_or_else(|| "-".to_owned())
    ));
    fs::write(contacts_path(dir), existing).context("writing contacts")?;
    println!("contact `{name}` added");
    Ok(())
}

/// `(name, signing, ecdh, hybrid_public?)`
type Contact = (String, [u8; 32], [u8; 32], Option<Vec<u8>>);

fn load_contacts(dir: &Path) -> Result<Vec<Contact>> {
    let text = fs::read_to_string(contacts_path(dir)).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(signing), Some(ecdh)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let hybrid = match parts.next() {
            Some("-") | None => None,
            Some(value) => Some(hex::decode(value).context("decoding hybrid contact key")?),
        };
        out.push((name.to_owned(), hex32(signing)?, hex32(ecdh)?, hybrid));
    }
    Ok(out)
}

fn contact_list(dir: &Path) -> Result<()> {
    let contacts = load_contacts(dir)?;
    if contacts.is_empty() {
        println!("(no contacts)");
        return Ok(());
    }
    // Group devices by contact name, preserving first-seen order.
    let mut names: Vec<String> = Vec::new();
    for (name, ..) in &contacts {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    for name in names {
        let signing = contacts
            .iter()
            .find(|(n, ..)| n == &name)
            .map(|(_, signing, ..)| *signing)
            .unwrap_or([0u8; 32]);
        println!("{name}\n  signing: {}", hex::encode(signing));
        for (_, _, ecdh, hybrid) in contacts.iter().filter(|(n, ..)| n == &name) {
            println!("  device:  {}", hex::encode(ecdh));
            if let Some(hybrid) = hybrid {
                println!("    hybrid: {}", hex::encode(hybrid));
            }
        }
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
    to: &[String],
    lat: f64,
    lng: f64,
    res: u8,
    ring: u32,
    message: Option<String>,
    file: Option<PathBuf>,
    ttl: u64,
    suite: &str,
) -> Result<()> {
    let identity = load_identity(dir)?;
    let contacts = load_contacts(dir)?;

    let hybrid_mode = suite.eq_ignore_ascii_case("hybrid");
    if !hybrid_mode && !suite.eq_ignore_ascii_case("classical") {
        bail!("unknown suite `{suite}` (expected `classical` or `hybrid`)");
    }

    // Resolve every recipient device (multi-recipient + multi-device).
    let mut recipients = Vec::new();
    for name in to {
        let matching: Vec<_> = contacts
            .iter()
            .filter(|(contact, _, _, _)| contact == name)
            .collect();
        if matching.is_empty() {
            bail!("unknown contact `{name}`; add them with `contact-add`");
        }
        for (_, _, ecdh, hybrid) in matching {
            if hybrid_mode && hybrid.is_none() {
                bail!("a device for `{name}` has no hybrid key; re-add it with a hybrid key");
            }
            recipients.push((*ecdh, hybrid.clone()));
        }
    }

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

    // Per-drop nonce binds recipient tags to this drop only.
    let mut drop_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut drop_nonce);

    // Seal the content key to each recipient, located by a short tag.
    let suite_id = if hybrid_mode {
        CryptoSuite::Hybrid25519MlKem768.id()
    } else {
        CryptoSuite::Classical25519.id()
    };
    let mut wrapped_keys = Vec::with_capacity(recipients.len().max(MIN_TAGS));
    for (ecdh, hybrid) in &recipients {
        let sealed = if hybrid_mode {
            let public = hybrid_public_from_bytes(
                hybrid
                    .as_ref()
                    .ok_or_else(|| anyhow!("a recipient has no hybrid key"))?,
            )?;
            SealedContentKey::Hybrid(keepstone_crypto::hybrid::seal(&content_key, &public)?)
        } else {
            SealedContentKey::Classical(SealedKey::seal(&content_key, ecdh)?)
        };
        let tag = derive_tag(ecdh, &drop_nonce)?;
        wrapped_keys.push(WrappedKey { tag, sealed });
    }

    // Pad with decoys so the recipient count is not revealed in the clear.
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

    let cell = CellId::from_lat_lng(lat, lng, res)?;
    let now = SystemClock.now_unix();
    let expiry = if ttl == 0 { 0 } else { now.saturating_add(ttl) };

    let body = DropBody {
        version: PROTOCOL_VERSION,
        suite: suite_id,
        cell: cell.to_hex(),
        ring,
        created_at: now,
        expiry,
        mode: Mode::Capability.id(),
        chunk_size: u32::try_from(stream::DEFAULT_CHUNK_SIZE)?,
        chunk_count: framing.total,
        content_root: root,
        prefix: framing.prefix,
        drop_nonce,
        pow_nonce,
        wrapped_keys,
    };

    let signed = if hybrid_mode {
        let ml_dsa = load_or_create_mldsa(dir)?;
        SignedDrop::sign_hybrid(&identity, &ml_dsa, &body)?
    } else {
        SignedDrop::sign(&identity, &body)
    };
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
    if !body.pow_ok(&signed.signer) {
        bail!("drop proof-of-work invalid");
    }

    let our_tag = derive_tag(&identity.ecdh_public(), &body.drop_nonce)?;
    let ecdh_secret = identity.ecdh_secret_bytes();
    let mut hybrid: Option<HybridKeypair> = None;
    let mut unsealed = None;
    for wrapped in &body.wrapped_keys {
        if wrapped.tag != our_tag {
            continue;
        }
        match &wrapped.sealed {
            SealedContentKey::Classical(sealed) => {
                if let Ok(key) = sealed.open(&ecdh_secret) {
                    unsealed = Some(key);
                    break;
                }
            }
            SealedContentKey::Hybrid(sealed) => {
                if hybrid.is_none() {
                    hybrid = Some(load_hybrid(dir)?);
                }
                if let Some(keypair) = hybrid.as_ref() {
                    if let Ok(key) = keypair.open(sealed) {
                        unsealed = Some(key);
                        break;
                    }
                }
            }
        }
    }
    let content_key =
        unsealed.ok_or_else(|| anyhow!("this drop is not addressed to this device"))?;

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
    let body = signed.body()?;
    if !body.pow_ok(&signed.signer) {
        bail!("drop proof-of-work invalid");
    }

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

    let kind = if signed.sig_kind == keepstone_core::SIG_HYBRID {
        "hybrid (Ed25519 + ML-DSA-65)"
    } else {
        "Ed25519"
    };
    println!("signature:   ok ({kind})");
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

// ---------------------------------------------------------------------------
// Anchoring (M4): append-only hash chain over signed tree heads
// ---------------------------------------------------------------------------

fn anchors_path(dir: &Path) -> PathBuf {
    log_dir(dir).join("anchors.txt")
}

fn load_receipts(dir: &Path) -> Result<Vec<anchor::AnchorReceipt>> {
    let text = match fs::read_to_string(anchors_path(dir)) {
        Ok(text) => text,
        Err(_) => return Ok(Vec::new()),
    };
    let mut receipts = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(size), Some(root), Some(stamp), Some(previous), Some(link)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        receipts.push(anchor::AnchorReceipt {
            anchor: "local-hashchain".to_owned(),
            tree_size: size.parse().context("anchor tree size")?,
            root: hex32(root)?,
            anchored_at: stamp.parse().context("anchor timestamp")?,
            previous: hex32(previous)?,
            link: hex32(link)?,
        });
    }
    Ok(receipts)
}

fn save_receipts(dir: &Path, receipts: &[anchor::AnchorReceipt]) -> Result<()> {
    fs::create_dir_all(log_dir(dir)).ok();
    let mut text = String::new();
    for receipt in receipts {
        text.push_str(&format!(
            "{} {} {} {} {}\n",
            receipt.tree_size,
            hex::encode(receipt.root),
            receipt.anchored_at,
            hex::encode(receipt.previous),
            hex::encode(receipt.link)
        ));
    }
    fs::write(anchors_path(dir), text).context("writing anchors")?;
    Ok(())
}

fn log_anchor(dir: &Path, id_text: &str) -> Result<()> {
    let id = DropId::from_hex(id_text)?;
    let entries = load_log_entries(dir)?;
    let leaves: Vec<merkle::Hash> = entries.iter().map(|e| merkle::leaf_hash(e)).collect();
    if !entries.iter().any(|e| sha256(e) == *id.as_bytes()) {
        bail!("drop is not present in the local log");
    }
    let tree_size = u64::try_from(leaves.len())?;
    let root = merkle::mth(&leaves);
    let log = log_identity(dir)?;
    let sth = SignedTreeHead::sign(&log, tree_size, root, SystemClock.now_unix());
    sth.verify().context("tree head invalid")?;

    let mut receipts = load_receipts(dir)?;
    let links: Vec<[u8; 32]> = receipts.iter().map(|r| r.link).collect();
    let mut chain = anchor::HashChainAnchor::from_links(links);
    let receipt = chain.submit(sth.tree_size, &sth.root, sth.timestamp);
    receipts.push(receipt.clone());
    save_receipts(dir, &receipts)?;

    println!("anchored");
    println!("  drop:      {id}");
    println!("  tree size: {}", receipt.tree_size);
    println!("  root:      {}", hex::encode(receipt.root));
    println!("  anchor:    {}", receipt.anchor);
    println!("  link:      {}", hex::encode(receipt.link));
    println!("  anchors:   {}", receipts.len());
    Ok(())
}

fn log_anchors(dir: &Path) -> Result<()> {
    let receipts = load_receipts(dir)?;
    if receipts.is_empty() {
        println!("(no anchors)");
        return Ok(());
    }
    let ok = anchor::verify_receipts(&receipts);
    println!("anchors:     {}", receipts.len());
    println!("chain:       {}", if ok { "ok" } else { "FAILED" });
    if let Some(last) = receipts.last() {
        println!("latest link: {}", hex::encode(last.link));
    }
    if !ok {
        bail!("anchor chain verification failed");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Peer transport (M2 reference): serve + fetch over TCP
// ---------------------------------------------------------------------------

fn load_store(dir: &Path) -> Result<MemoryStore> {
    let mut store = MemoryStore::new();
    if let Ok(entries) = fs::read_dir(drops_dir(dir)) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("signed") {
                continue;
            }
            let raw = fs::read(&path)?;
            store.put_drop(DropId::of(&raw), raw);
        }
    }
    if let Ok(entries) = fs::read_dir(dir.join("chunks")) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(id) = DropId::from_hex(name) else {
                continue;
            };
            if let Ok(files) = fs::read_dir(&path) {
                for file in files.flatten() {
                    let chunk_path = file.path();
                    let Some(stem) = chunk_path.file_stem().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    let Ok(index) = stem.parse::<u32>() else {
                        continue;
                    };
                    store.put_chunk(id, index, fs::read(&chunk_path)?);
                }
            }
        }
    }
    Ok(store)
}

async fn serve(dir: &Path, listen: &str) -> Result<()> {
    let store = Arc::new(Mutex::new(load_store(dir)?));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    println!("serving drops on {listen} (ciphertext only)");
    net::serve(listener, store).await;
    Ok(())
}

async fn fetch(dir: &Path, peer: &str, id_text: &str) -> Result<()> {
    let id = DropId::from_hex(id_text)?;
    let raw = net::fetch(peer, id)
        .await
        .with_context(|| format!("fetching {id_text} from {peer}"))?
        .ok_or_else(|| anyhow!("peer does not have drop {id_text}"))?;

    let signed = SignedDrop::decode(&raw)?;
    signed.verify().context("peer sent an invalid signature")?;
    let body = signed.body()?;
    if !body.pow_ok(&signed.signer) {
        bail!("peer sent a drop with invalid proof-of-work");
    }

    fs::create_dir_all(drops_dir(dir)).ok();
    fs::write(drop_path(dir, &id), &raw).context("writing fetched drop")?;
    let chunk_dir = chunks_dir(dir, &id);
    fs::create_dir_all(&chunk_dir).ok();

    let mut received = 0u32;
    for index in 0..body.chunk_count {
        let chunk = net::fetch_chunk(peer, id, index)
            .await
            .with_context(|| format!("fetching chunk {index}"))?
            .ok_or_else(|| anyhow!("peer is missing chunk {index}"))?;
        fs::write(chunk_dir.join(format!("{index}.bin")), chunk)?;
        received += 1;
    }

    // Record the fetched drop in the local transparency log too.
    append_log_entry(dir, &raw).ok();

    println!("fetched {id} ({received} chunks) from {peer}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Federated relay: push a local drop to a peer
// ---------------------------------------------------------------------------

async fn push(dir: &Path, peer: &str, id_text: &str) -> Result<()> {
    let id = DropId::from_hex(id_text)?;
    let raw = fs::read(drop_path(dir, &id)).with_context(|| format!("no such drop: {id_text}"))?;
    let signed = SignedDrop::decode(&raw)?;
    let body = signed.body()?;

    if !net::push_drop(peer, raw).await? {
        bail!("peer rejected the drop");
    }
    let mut chunks = 0u32;
    for index in 0..body.chunk_count {
        let path = chunks_dir(dir, &id).join(format!("{index}.bin"));
        let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if !net::push_chunk(peer, id, index, data).await? {
            bail!("peer rejected chunk {index}");
        }
        chunks += 1;
    }
    println!("pushed {id} to {peer} ({chunks} chunks, stored as ciphertext)");
    Ok(())
}

// ---------------------------------------------------------------------------
// libp2p transport (M2b)
// ---------------------------------------------------------------------------

fn parse_multiaddr(text: &str) -> Result<keepstone_p2p::Multiaddr> {
    text.parse()
        .map_err(|_| anyhow!("invalid multiaddr: {text}"))
}

async fn p2p_serve(dir: &Path, listen: &str) -> Result<()> {
    let addr = parse_multiaddr(listen)?;
    let store = Arc::new(Mutex::new(load_store(dir)?));
    println!("libp2p serving on {listen} (QUIC + TCP, ciphertext only)");
    keepstone_p2p::serve(addr, store).await?;
    Ok(())
}

async fn p2p_fetch(dir: &Path, peer: &str, id_text: &str) -> Result<()> {
    let addr = parse_multiaddr(peer)?;
    let id = DropId::from_hex(id_text)?;

    let raw = keepstone_p2p::fetch_drop(addr.clone(), id)
        .await?
        .ok_or_else(|| anyhow!("peer does not have drop {id_text}"))?;
    let signed = SignedDrop::decode(&raw)?;
    signed.verify().context("peer sent an invalid signature")?;
    let body = signed.body()?;
    if !body.pow_ok(&signed.signer) {
        bail!("peer sent a drop with invalid proof-of-work");
    }

    fs::create_dir_all(drops_dir(dir)).ok();
    fs::write(drop_path(dir, &id), &raw).context("writing fetched drop")?;
    let chunk_dir = chunks_dir(dir, &id);
    fs::create_dir_all(&chunk_dir).ok();

    let mut received = 0u32;
    for index in 0..body.chunk_count {
        let chunk = keepstone_p2p::fetch_chunk(addr.clone(), id, index)
            .await?
            .ok_or_else(|| anyhow!("peer is missing chunk {index}"))?;
        fs::write(chunk_dir.join(format!("{index}.bin")), chunk)?;
        received += 1;
    }

    append_log_entry(dir, &raw).ok();
    println!("fetched {id} ({received} chunks) via libp2p from {peer}");
    Ok(())
}
