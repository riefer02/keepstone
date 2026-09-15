//! Shared data-directory operations.
//!
//! Both the CLI and the browser-client daemon use this crate, so the on-disk
//! layout and the create/open/verify logic live in exactly one place.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

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
use thiserror::Error;

/// Errors from store operations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// No identity is present in the data directory.
    #[error("no identity found; run `keepstone keygen` first")]
    NoIdentity,
    /// No hybrid key is present.
    #[error("no hybrid key found; regenerate the identity")]
    NoHybrid,
    /// No ML-DSA key is present.
    #[error("no ML-DSA key found; regenerate the identity")]
    NoMlDsa,
    /// A named item was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// Input was malformed.
    #[error("invalid: {0}")]
    Invalid(String),
    /// A cryptographic operation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] keepstone_crypto::CryptoError),
    /// A core (encoding/addressing) operation failed.
    #[error("core: {0}")]
    Core(#[from] keepstone_core::CoreError),
    /// An I/O operation failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A log operation failed.
    #[error("log: {0}")]
    Log(#[from] keepstone_log::LogError),
}

type Result<T> = std::result::Result<T, StoreError>;

/// A contact device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Petname.
    pub name: String,
    /// Ed25519 public key.
    pub signing: [u8; 32],
    /// X25519 public key.
    pub ecdh: [u8; 32],
    /// Hybrid public key bytes (`x25519 || ml-kem ek`), if known.
    pub hybrid: Option<Vec<u8>>,
}

/// The result of creating a drop.
#[derive(Clone, Debug)]
pub struct CreatedDrop {
    /// Drop id.
    pub id: DropId,
    /// H3 cell (hex).
    pub cell: String,
    /// Number of chunks.
    pub chunks: u32,
    /// Plaintext length.
    pub bytes: usize,
    /// Crypto suite id.
    pub suite: u8,
    /// Signature kind.
    pub sig_kind: u8,
}

/// A summary of a stored drop.
#[derive(Clone, Debug)]
pub struct DropSummary {
    /// Drop id.
    pub id: DropId,
    /// H3 cell (hex).
    pub cell: String,
    /// Delivery ring.
    pub ring: u32,
    /// Number of chunks.
    pub chunks: u32,
    /// Creation time.
    pub created: u64,
    /// Expiry (0 = never).
    pub expiry: u64,
    /// Crypto suite id.
    pub suite: u8,
    /// Signature kind.
    pub sig_kind: u8,
}

/// The result of verifying a drop against the local log.
#[derive(Clone, Debug)]
pub struct Verification {
    /// Signature valid.
    pub signature: bool,
    /// Included in the local log.
    pub inclusion: bool,
    /// The freshly signed tree head verifies.
    pub sth: bool,
    /// Tree size.
    pub tree_size: usize,
    /// Leaf index.
    pub leaf_index: usize,
    /// Merkle root.
    pub root: [u8; 32],
    /// Signature kind.
    pub sig_kind: u8,
}

/// A node's data directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open (creating if needed) a data directory.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`] if directories cannot be created.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The data-directory root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    // -- paths -------------------------------------------------------------

    /// Path to a drop's signed envelope.
    #[must_use]
    pub fn drop_path(&self, id: &DropId) -> PathBuf {
        self.root
            .join("drops")
            .join(format!("{}.signed", id.to_hex()))
    }

    /// Directory holding a drop's ciphertext chunks.
    #[must_use]
    pub fn chunk_dir(&self, id: &DropId) -> PathBuf {
        self.root.join("chunks").join(id.to_hex())
    }

    fn identity_path(&self) -> PathBuf {
        self.root.join("identity.txt")
    }
    fn hybrid_path(&self) -> PathBuf {
        self.root.join("hybrid.txt")
    }
    fn mldsa_path(&self) -> PathBuf {
        self.root.join("mldsa.txt")
    }
    fn contacts_path(&self) -> PathBuf {
        self.root.join("contacts.txt")
    }
    fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }
    fn entries_path(&self) -> PathBuf {
        self.log_dir().join("entries.bin")
    }

    /// Whether an identity exists.
    #[must_use]
    pub fn has_identity(&self) -> bool {
        self.identity_path().exists()
    }

    // -- identity ----------------------------------------------------------

    /// Generate and persist a full identity (signing, ecdh, hybrid, ML-DSA).
    ///
    /// # Errors
    /// Returns [`StoreError::Invalid`] if an identity already exists, or I/O
    /// errors on write.
    pub fn keygen(&self) -> Result<Identity> {
        if self.has_identity() {
            return Err(StoreError::Invalid("identity already exists".to_owned()));
        }
        let identity = Identity::generate();
        self.save_identity(&identity)?;
        self.save_hybrid(&HybridKeypair::generate())?;
        self.save_mldsa(&MlDsaKeypair::generate())?;
        Ok(identity)
    }

    /// Save the Ed25519/X25519 identity.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`] on failure.
    pub fn save_identity(&self, identity: &Identity) -> Result<()> {
        fs::write(
            self.identity_path(),
            format!(
                "{}\n{}\n",
                hex::encode(identity.signing_secret_bytes()),
                hex::encode(identity.ecdh_secret_bytes())
            ),
        )?;
        Ok(())
    }

    /// Load the identity.
    ///
    /// # Errors
    /// Returns [`StoreError::NoIdentity`] or [`StoreError::Invalid`].
    pub fn identity(&self) -> Result<Identity> {
        let text = fs::read_to_string(self.identity_path()).map_err(|_| StoreError::NoIdentity)?;
        let mut lines = text.lines();
        let signing = hex32(lines.next().unwrap_or_default())?;
        let ecdh = hex32(lines.next().unwrap_or_default())?;
        Ok(Identity::from_secret_bytes(&signing, &ecdh))
    }

    /// Save a hybrid keypair.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`].
    pub fn save_hybrid(&self, keypair: &HybridKeypair) -> Result<()> {
        fs::write(self.hybrid_path(), hex::encode(keypair.to_secret_bytes()))?;
        Ok(())
    }

    /// Load the hybrid keypair.
    ///
    /// # Errors
    /// Returns [`StoreError::NoHybrid`] or [`StoreError::Invalid`].
    pub fn hybrid(&self) -> Result<HybridKeypair> {
        let text = fs::read_to_string(self.hybrid_path()).map_err(|_| StoreError::NoHybrid)?;
        let bytes =
            hex::decode(text.trim()).map_err(|_| StoreError::Invalid("hybrid hex".into()))?;
        let array: [u8; 96] = bytes
            .try_into()
            .map_err(|_| StoreError::Invalid("hybrid length".into()))?;
        HybridKeypair::from_secret_bytes(&array).map_err(StoreError::Crypto)
    }

    /// Load the hybrid keypair, generating one if absent.
    ///
    /// # Errors
    /// Returns [`StoreError`] on failure.
    pub fn hybrid_or_create(&self) -> Result<HybridKeypair> {
        if self.hybrid_path().exists() {
            self.hybrid()
        } else {
            let keypair = HybridKeypair::generate();
            self.save_hybrid(&keypair)?;
            Ok(keypair)
        }
    }

    /// The hybrid public key bytes for this node.
    ///
    /// # Errors
    /// Returns [`StoreError`] on failure.
    pub fn hybrid_public_bytes(&self) -> Result<Vec<u8>> {
        let public: HybridPublic = self.hybrid_or_create()?.public();
        let mut out = public.x25519.to_vec();
        out.extend_from_slice(&public.kem);
        Ok(out)
    }

    /// Save the ML-DSA seed.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`].
    pub fn save_mldsa(&self, keypair: &MlDsaKeypair) -> Result<()> {
        fs::write(self.mldsa_path(), hex::encode(keypair.to_seed()))?;
        Ok(())
    }

    /// Load the ML-DSA keypair.
    ///
    /// # Errors
    /// Returns [`StoreError::NoMlDsa`] or [`StoreError::Invalid`].
    pub fn mldsa(&self) -> Result<MlDsaKeypair> {
        let text = fs::read_to_string(self.mldsa_path()).map_err(|_| StoreError::NoMlDsa)?;
        let bytes =
            hex::decode(text.trim()).map_err(|_| StoreError::Invalid("mldsa hex".into()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| StoreError::Invalid("mldsa seed length".into()))?;
        MlDsaKeypair::from_seed(&seed).map_err(StoreError::Crypto)
    }

    /// Load the ML-DSA keypair, generating one if absent.
    ///
    /// # Errors
    /// Returns [`StoreError`] on failure.
    pub fn mldsa_or_create(&self) -> Result<MlDsaKeypair> {
        if self.mldsa_path().exists() {
            self.mldsa()
        } else {
            let keypair = MlDsaKeypair::generate();
            self.save_mldsa(&keypair)?;
            Ok(keypair)
        }
    }

    // -- contacts ----------------------------------------------------------

    /// Load all contacts (a name may appear multiple times for multiple devices).
    ///
    /// # Errors
    /// Returns [`StoreError::Invalid`] on malformed entries.
    pub fn contacts(&self) -> Result<Vec<Contact>> {
        let text = fs::read_to_string(self.contacts_path()).unwrap_or_default();
        let mut out = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let (Some(name), Some(signing), Some(ecdh)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let hybrid = match parts.next() {
                Some("-") | None => None,
                Some(value) => Some(
                    hex::decode(value).map_err(|_| StoreError::Invalid("contact hybrid".into()))?,
                ),
            };
            out.push(Contact {
                name: name.to_owned(),
                signing: hex32(signing)?,
                ecdh: hex32(ecdh)?,
                hybrid,
            });
        }
        Ok(out)
    }

    /// Add a contact device (deduplicated by signing+ecdh).
    ///
    /// # Errors
    /// Returns [`StoreError::Invalid`] on bad hex or a duplicate device.
    pub fn add_contact(
        &self,
        name: &str,
        signing: &str,
        ecdh: &str,
        hybrid: Option<&str>,
    ) -> Result<()> {
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(StoreError::Invalid(
                "contact name must be non-empty and have no whitespace".into(),
            ));
        }
        let signing = hex32(signing)?;
        let ecdh = hex32(ecdh)?;
        let hybrid = match hybrid {
            Some(value) => {
                Some(hex::decode(value).map_err(|_| StoreError::Invalid("hybrid hex".into()))?)
            }
            None => None,
        };
        let mut existing = fs::read_to_string(self.contacts_path()).unwrap_or_default();
        let prefix = format!("{name} {} {} ", hex::encode(signing), hex::encode(ecdh));
        if existing.lines().any(|line| line.starts_with(&prefix)) {
            return Err(StoreError::Invalid(format!(
                "contact `{name}` already has this device"
            )));
        }
        existing.push_str(&format!(
            "{name} {} {} {}\n",
            hex::encode(signing),
            hex::encode(ecdh),
            hybrid.map(hex::encode).unwrap_or_else(|| "-".to_owned())
        ));
        fs::write(self.contacts_path(), existing)?;
        Ok(())
    }

    // -- drops -------------------------------------------------------------

    /// Create a drop addressed to the given contacts (each device gets a key).
    ///
    /// # Errors
    /// Returns [`StoreError`] on unknown contacts, bad parameters, or I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn create_drop(
        &self,
        to: &[String],
        lat: f64,
        lng: f64,
        res: u8,
        ring: u32,
        ttl: u64,
        suite: &str,
        plaintext: &[u8],
    ) -> Result<CreatedDrop> {
        if to.is_empty() {
            return Err(StoreError::Invalid(
                "at least one recipient is required".into(),
            ));
        }
        if !suite.eq_ignore_ascii_case("classical") && !suite.eq_ignore_ascii_case("hybrid") {
            return Err(StoreError::Invalid(format!("unknown suite `{suite}`")));
        }
        let hybrid_mode = suite.eq_ignore_ascii_case("hybrid");
        let identity = self.identity()?;
        let contacts = self.contacts()?;

        let mut recipients = Vec::new();
        for name in to {
            let matching: Vec<&Contact> = contacts.iter().filter(|c| &c.name == name).collect();
            if matching.is_empty() {
                return Err(StoreError::Invalid(format!("unknown contact `{name}`")));
            }
            for contact in matching {
                if hybrid_mode && contact.hybrid.is_none() {
                    return Err(StoreError::Invalid(format!(
                        "device for `{name}` has no hybrid key"
                    )));
                }
                recipients.push((contact.ecdh, contact.hybrid.clone()));
            }
        }

        let mut content_key = [0u8; 32];
        OsRng.fill_bytes(&mut content_key);
        let (framing, chunks) = stream::encrypt(&content_key, plaintext)?;
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
                let bytes = hybrid
                    .as_ref()
                    .ok_or_else(|| StoreError::Invalid("recipient has no hybrid key".into()))?;
                SealedContentKey::Hybrid(keepstone_crypto::hybrid::seal(
                    &content_key,
                    &hybrid_public_from_bytes(bytes)?,
                )?)
            } else {
                SealedContentKey::Classical(SealedKey::seal(&content_key, ecdh)?)
            };
            let tag = derive_tag(ecdh, &drop_nonce)?;
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
        let cell = CellId::from_lat_lng(lat, lng, res)?;
        let now = now_unix();
        let body = DropBody {
            version: PROTOCOL_VERSION,
            suite: suite_id,
            cell: cell.to_hex(),
            ring,
            created_at: now,
            expiry: if ttl == 0 { 0 } else { now.saturating_add(ttl) },
            mode: Mode::Capability.id(),
            chunk_size: u32::try_from(stream::DEFAULT_CHUNK_SIZE)
                .map_err(|_| StoreError::Invalid("chunk size".into()))?,
            chunk_count: framing.total,
            content_root: root,
            prefix: framing.prefix,
            drop_nonce,
            pow_nonce,
            wrapped_keys,
        };

        let signed = if hybrid_mode {
            let ml_dsa = self.mldsa_or_create()?;
            SignedDrop::sign_hybrid(&identity, &ml_dsa, &body)?
        } else {
            SignedDrop::sign(&identity, &body)
        };
        let id = signed.id();

        let chunk_dir = self.chunk_dir(&id);
        fs::create_dir_all(&chunk_dir)?;
        for (index, chunk) in chunks.iter().enumerate() {
            fs::write(chunk_dir.join(format!("{index}.bin")), chunk)?;
        }
        fs::create_dir_all(self.root.join("drops")).ok();
        fs::write(self.drop_path(&id), &signed.raw)?;
        self.append_log_entry(&signed.raw)?;

        Ok(CreatedDrop {
            id,
            cell: body.cell,
            chunks: framing.total,
            bytes: plaintext.len(),
            suite: suite_id,
            sig_kind: signed.sig_kind,
        })
    }

    /// Open (decrypt) a drop by id.
    ///
    /// # Errors
    /// Returns [`StoreError`] on a missing/corrupt drop, wrong recipient, or
    /// decryption failure.
    pub fn open_drop(&self, id: &DropId) -> Result<Vec<u8>> {
        let identity = self.identity()?;
        let raw = fs::read(self.drop_path(id)).map_err(|_| StoreError::NotFound(id.to_hex()))?;
        let signed = SignedDrop::decode(&raw).map_err(StoreError::Core)?;
        signed
            .verify()
            .map_err(|_| StoreError::Invalid("signature invalid".into()))?;
        let body = signed.body()?;
        if !body.pow_ok(&signed.signer) {
            return Err(StoreError::Invalid("proof-of-work invalid".into()));
        }

        let our_tag = derive_tag(&identity.ecdh_public(), &body.drop_nonce)?;
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
                        hybrid = Some(self.hybrid()?);
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
        let content_key = content_key
            .ok_or_else(|| StoreError::Invalid("drop is not addressed to this device".into()))?;

        let mut chunks = Vec::with_capacity(body.chunk_count as usize);
        for index in 0..body.chunk_count {
            let path = self.chunk_dir(id).join(format!("{index}.bin"));
            chunks
                .push(fs::read(&path).map_err(|_| StoreError::NotFound(format!("chunk {index}")))?);
        }
        let framing = stream::Framing {
            prefix: body.prefix,
            total: body.chunk_count,
        };
        stream::decrypt(&content_key, &framing, &chunks)
            .map_err(|_| StoreError::Invalid("decryption failed".into()))
    }

    /// List stored drops, optionally filtered to those near a point.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`] only on unexpected failures.
    pub fn list_drops(&self, near: Option<(f64, f64)>, ring: u32) -> Result<Vec<DropSummary>> {
        let entries = match fs::read_dir(self.root.join("drops")) {
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
            out.push(DropSummary {
                id: signed.id(),
                cell: body.cell,
                ring: body.ring,
                chunks: body.chunk_count,
                created: body.created_at,
                expiry: body.expiry,
                suite: body.suite,
                sig_kind: signed.sig_kind,
            });
        }
        Ok(out)
    }

    /// Decode a drop file without opening it.
    ///
    /// # Errors
    /// Returns [`StoreError`] on a missing or malformed drop.
    pub fn read_drop(&self, id: &DropId) -> Result<(SignedDrop, DropBody)> {
        let raw = fs::read(self.drop_path(id)).map_err(|_| StoreError::NotFound(id.to_hex()))?;
        let signed = SignedDrop::decode(&raw).map_err(StoreError::Core)?;
        let body = signed.body()?;
        Ok((signed, body))
    }

    // -- transparency log --------------------------------------------------

    /// Append a drop envelope to the local log.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`] on failure.
    pub fn append_log_entry(&self, raw: &[u8]) -> Result<()> {
        use std::io::Write as _;
        fs::create_dir_all(self.log_dir())?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.entries_path())?;
        let len =
            u32::try_from(raw.len()).map_err(|_| StoreError::Invalid("entry length".into()))?;
        file.write_all(&len.to_be_bytes())?;
        file.write_all(raw)?;
        Ok(())
    }

    /// Load the local log's entries.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`] on read failure.
    pub fn log_entries(&self) -> Result<Vec<Vec<u8>>> {
        let bytes = match fs::read(self.entries_path()) {
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

    /// Load (or create) the local log's signing identity.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`] on failure.
    pub fn log_identity(&self) -> Result<Identity> {
        let path = self.log_dir().join("key.txt");
        if let Ok(text) = fs::read_to_string(&path) {
            let mut lines = text.lines();
            let signing = hex32(lines.next().unwrap_or_default())?;
            let ecdh = hex32(lines.next().unwrap_or_default())?;
            return Ok(Identity::from_secret_bytes(&signing, &ecdh));
        }
        let identity = Identity::generate();
        fs::create_dir_all(self.log_dir())?;
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

    /// The log's current signed tree head.
    ///
    /// # Errors
    /// Returns [`StoreError`] on failure.
    pub fn signed_tree_head(&self) -> Result<SignedTreeHead> {
        let entries = self.log_entries()?;
        let leaves: Vec<merkle::Hash> = entries.iter().map(|e| merkle::leaf_hash(e)).collect();
        let root = merkle::mth(&leaves);
        let log = self.log_identity()?;
        Ok(SignedTreeHead::sign(
            &log,
            u64::try_from(leaves.len()).unwrap_or(u64::MAX),
            root,
            now_unix(),
        ))
    }

    /// Verify a drop's signature, inclusion, and tree head.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the drop is missing, malformed, or absent from
    /// the local log.
    pub fn verify(&self, id: &DropId) -> Result<Verification> {
        let (signed, _body) = self.read_drop(id)?;
        let signature = signed.verify().is_ok();
        let entries = self.log_entries()?;
        let leaves: Vec<merkle::Hash> = entries.iter().map(|e| merkle::leaf_hash(e)).collect();
        let index = entries
            .iter()
            .position(|e| sha256(e) == *id.as_bytes())
            .ok_or_else(|| StoreError::NotFound("drop is not in the local log".into()))?;
        let tree_size = leaves.len();
        let root = merkle::mth(&leaves);
        let proof = merkle::inclusion_proof(&leaves, index)?;
        let inclusion = merkle::verify_inclusion(&leaves[index], index, tree_size, &proof, &root);
        let log = self.log_identity()?;
        let sth = SignedTreeHead::sign(&log, tree_size as u64, root, now_unix());
        Ok(Verification {
            signature,
            inclusion,
            sth: sth.verify().is_ok(),
            tree_size,
            leaf_index: index,
            root,
            sig_kind: signed.sig_kind,
        })
    }
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text.trim()).map_err(|_| StoreError::Invalid("hex".into()))?;
    bytes
        .try_into()
        .map_err(|_| StoreError::Invalid("expected 32 bytes".into()))
}

fn hybrid_public_from_bytes(bytes: &[u8]) -> Result<HybridPublic> {
    if bytes.len() != 32 + 1184 {
        return Err(StoreError::Invalid(
            "hybrid public key must be 32 + 1184 bytes".into(),
        ));
    }
    let x25519: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| StoreError::Invalid("hybrid x25519".into()))?;
    Ok(HybridPublic {
        x25519,
        kem: bytes[32..].to_vec(),
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keepstone-store-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn store_with_self(tag: &str) -> (Store, String) {
        let store = Store::open(temp(tag)).unwrap();
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
        (store, hybrid)
    }

    #[test]
    fn create_open_verify_round_trip() {
        let (store, _) = store_with_self("roundtrip");
        for suite in ["classical", "hybrid"] {
            let created = store
                .create_drop(
                    &["me".to_owned()],
                    51.5,
                    -0.12,
                    9,
                    2,
                    0,
                    suite,
                    b"hello store",
                )
                .unwrap();
            assert_eq!(store.open_drop(&created.id).unwrap(), b"hello store");
            let verification = store.verify(&created.id).unwrap();
            assert!(verification.signature);
            assert!(verification.inclusion);
            assert!(verification.sth);
        }
        let _ = fs::remove_dir_all(store.root());
    }

    #[test]
    fn list_filters_by_proximity() {
        let (store, _) = store_with_self("list");
        store
            .create_drop(
                &["me".to_owned()],
                51.5007,
                -0.1246,
                9,
                2,
                0,
                "classical",
                b"near",
            )
            .unwrap();
        store
            .create_drop(&["me".to_owned()], 40.0, -3.0, 9, 2, 0, "classical", b"far")
            .unwrap();
        let near = store.list_drops(Some((51.5007, -0.1246)), 1).unwrap();
        assert_eq!(near.len(), 1);
        let all = store.list_drops(None, 0).unwrap();
        assert_eq!(all.len(), 2);
        let _ = fs::remove_dir_all(store.root());
    }

    #[test]
    fn duplicate_device_is_rejected() {
        let (store, _) = store_with_self("dup");
        let identity = store.identity().unwrap();
        let result = store.add_contact(
            "me",
            &hex::encode(identity.signing_public()),
            &hex::encode(identity.ecdh_public()),
            None,
        );
        assert!(result.is_err());
        let _ = fs::remove_dir_all(store.root());
    }
}
