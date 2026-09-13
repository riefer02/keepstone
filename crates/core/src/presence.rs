//! Witness presence certificates for place-locked drops.
//!
//! Location is **best-effort defense in depth**, never a confidentiality
//! guarantee. A claimant asks nearby witnesses to attest that they observed the
//! claimant in a cell; a threshold of distinct, valid attestations forms a
//! `PresenceCert`. Over IP, round-trip timing is weak evidence, so the RTT is
//! recorded only as a coarse bucket.
//!
//! Custodians release Shamir shares only when presented a valid certificate.

use keepstone_crypto::{verify, Identity};

use crate::cbor::{Decoder, Encoder};
use crate::error::CoreError;

/// Domain-separation context for presence attestations.
pub const PRESENCE_CONTEXT: &[u8] = b"keepstone/v1/presence";

/// Default number of witness attestations required.
pub const DEFAULT_THRESHOLD: usize = 3;

/// A claimant's request to be witnessed in a cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceRequest {
    /// H3 cell (hex).
    pub cell: String,
    /// Random nonce (replay protection).
    pub nonce: [u8; 16],
    /// Claimant's Ed25519 public key.
    pub claimant: [u8; 32],
    /// Expiry (Unix seconds; 0 = no expiry).
    pub expiry: u64,
}

impl PresenceRequest {
    /// Decode from canonical CBOR.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, CoreError> {
        let mut dec = Decoder::new(bytes);
        if dec.array()? != 4 {
            return Err(CoreError::Cbor("presence request arity"));
        }
        let cell = dec.text()?.to_owned();
        let nonce = dec.bytes_fixed::<16>()?;
        let claimant = dec.bytes_fixed::<32>()?;
        let expiry = dec.uint()?;
        dec.finish()?;
        Ok(Self {
            cell,
            nonce,
            claimant,
            expiry,
        })
    }

    /// Encode as canonical CBOR.
    #[must_use]
    pub fn to_canonical(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.array(4);
        enc.text(&self.cell);
        enc.bytes(&self.nonce);
        enc.bytes(&self.claimant);
        enc.uint(self.expiry);
        enc.into_bytes()
    }
}

/// One witness's attestation that the claimant was present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceAttestation {
    /// H3 cell (hex).
    pub cell: String,
    /// The request nonce.
    pub nonce: [u8; 16],
    /// Claimant's Ed25519 public key.
    pub claimant: [u8; 32],
    /// Coarse round-trip-time bucket (weak evidence over IP).
    pub rtt_bucket: u8,
    /// Witness's Unix timestamp.
    pub timestamp: u64,
    /// Witness's Ed25519 public key.
    pub witness: [u8; 32],
    /// Witness's signature over the attestation input.
    pub signature: [u8; 64],
}

/// The exact bytes a witness signs.
#[must_use]
pub fn attestation_input(
    cell: &str,
    nonce: &[u8; 16],
    claimant: &[u8; 32],
    rtt_bucket: u8,
    timestamp: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PRESENCE_CONTEXT.len() + 4 + cell.len() + 16 + 32 + 1 + 8);
    out.extend_from_slice(PRESENCE_CONTEXT);
    out.extend_from_slice(&u32::try_from(cell.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(cell.as_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(claimant);
    out.push(rtt_bucket);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

impl PresenceAttestation {
    /// A witness signs a request.
    #[must_use]
    pub fn sign(
        witness: &Identity,
        request: &PresenceRequest,
        rtt_bucket: u8,
        timestamp: u64,
    ) -> Self {
        let input = attestation_input(
            &request.cell,
            &request.nonce,
            &request.claimant,
            rtt_bucket,
            timestamp,
        );
        Self {
            cell: request.cell.clone(),
            nonce: request.nonce,
            claimant: request.claimant,
            rtt_bucket,
            timestamp,
            witness: witness.signing_public(),
            signature: witness.sign(&input),
        }
    }

    /// Verify the witness signature.
    ///
    /// # Errors
    /// Returns [`CoreError::Verify`] on failure.
    pub fn verify(&self) -> Result<(), CoreError> {
        verify(
            &self.witness,
            &attestation_input(
                &self.cell,
                &self.nonce,
                &self.claimant,
                self.rtt_bucket,
                self.timestamp,
            ),
            &self.signature,
        )
        .map_err(|_| CoreError::Verify)
    }

    /// Encode as canonical CBOR.
    #[must_use]
    pub fn to_canonical(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.array(7);
        enc.text(&self.cell);
        enc.bytes(&self.nonce);
        enc.bytes(&self.claimant);
        enc.uint(u64::from(self.rtt_bucket));
        enc.uint(self.timestamp);
        enc.bytes(&self.witness);
        enc.bytes(&self.signature);
        enc.into_bytes()
    }

    /// Decode from canonical CBOR.
    ///
    /// # Errors
    /// Returns [`CoreError::Cbor`] on malformed input.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, CoreError> {
        let mut dec = Decoder::new(bytes);
        if dec.array()? != 7 {
            return Err(CoreError::Cbor("attestation arity"));
        }
        let cell = dec.text()?.to_owned();
        let nonce = dec.bytes_fixed::<16>()?;
        let claimant = dec.bytes_fixed::<32>()?;
        let rtt_bucket = u8::try_from(dec.uint()?).map_err(|_| CoreError::Cbor("rtt"))?;
        let timestamp = dec.uint()?;
        let witness = dec.bytes_fixed::<32>()?;
        let signature = dec.bytes_fixed::<64>()?;
        dec.finish()?;
        Ok(Self {
            cell,
            nonce,
            claimant,
            rtt_bucket,
            timestamp,
            witness,
            signature,
        })
    }
}

/// A certificate: a request plus a set of witness attestations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceCert {
    /// The original request.
    pub request: PresenceRequest,
    /// Witness attestations.
    pub attestations: Vec<PresenceAttestation>,
}

impl PresenceCert {
    /// Verify the certificate: every attestation matches the request, has a
    /// valid signature, and has a distinct witness; the count must meet
    /// `threshold`.
    ///
    /// # Errors
    /// Returns [`CoreError`] on any failure.
    pub fn verify(&self, threshold: usize) -> Result<(), CoreError> {
        if self.attestations.len() < threshold || threshold == 0 {
            return Err(CoreError::Invalid("insufficient attestations"));
        }
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(self.attestations.len());
        for attestation in &self.attestations {
            if attestation.cell != self.request.cell
                || attestation.nonce != self.request.nonce
                || attestation.claimant != self.request.claimant
            {
                return Err(CoreError::Invalid("attestation does not match request"));
            }
            attestation.verify()?;
            if seen.contains(&attestation.witness) {
                return Err(CoreError::Invalid("duplicate witness"));
            }
            seen.push(attestation.witness);
        }
        Ok(())
    }

    /// Verify and additionally check that the request has not expired at `now`.
    ///
    /// # Errors
    /// Returns [`CoreError`] on failure or expiry.
    pub fn verify_at(&self, threshold: usize, now: u64) -> Result<(), CoreError> {
        if self.request.expiry != 0 && now > self.request.expiry {
            return Err(CoreError::Invalid("presence request expired"));
        }
        self.verify(threshold)
    }

    /// The number of distinct witnesses.
    #[must_use]
    pub fn witness_count(&self) -> usize {
        self.attestations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(cell: &str, expiry: u64) -> PresenceRequest {
        PresenceRequest {
            cell: cell.to_owned(),
            nonce: [1u8; 16],
            claimant: Identity::generate().signing_public(),
            expiry,
        }
    }

    fn cert(request: &PresenceRequest, witnesses: usize) -> PresenceCert {
        let attestations = (0..witnesses)
            .map(|i| {
                let witness = Identity::generate();
                PresenceAttestation::sign(
                    &witness,
                    request,
                    u8::try_from(i).unwrap(),
                    1_700_000_000,
                )
            })
            .collect();
        PresenceCert {
            request: request.clone(),
            attestations,
        }
    }

    #[test]
    fn threshold_certificate_verifies() {
        let request = request("8928308280fffff", 0);
        let cert = cert(&request, 3);
        cert.verify(3).unwrap();
        assert_eq!(cert.witness_count(), 3);
    }

    #[test]
    fn too_few_witnesses_fail() {
        let request = request("8928308280fffff", 0);
        let cert = cert(&request, 2);
        assert!(cert.verify(3).is_err());
    }

    #[test]
    fn duplicate_witness_is_rejected() {
        let request = request("8928308280fffff", 0);
        let witness = Identity::generate();
        let one = PresenceAttestation::sign(&witness, &request, 0, 10);
        let duplicate = PresenceAttestation::sign(&witness, &request, 1, 11);
        let cert = PresenceCert {
            request,
            attestations: vec![one, duplicate],
        };
        assert!(cert.verify(2).is_err());
    }

    #[test]
    fn attestations_round_trip_and_detect_tampering() {
        let request = request("8928308280fffff", 0);
        let witness = Identity::generate();
        let attestation = PresenceAttestation::sign(&witness, &request, 2, 99);
        let bytes = attestation.to_canonical();
        assert_eq!(
            PresenceAttestation::from_canonical(&bytes).unwrap(),
            attestation
        );

        let mut tampered = attestation;
        tampered.rtt_bucket = 9;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn expired_certificate_fails_at_time_check() {
        let request = request("8928308280fffff", 100);
        let cert = cert(&request, 3);
        assert!(cert.verify_at(3, 50).is_ok());
        assert!(cert.verify_at(3, 200).is_err());
    }

    #[test]
    fn mismatched_cell_is_rejected() {
        let request = request("8928308280fffff", 0);
        let witness = Identity::generate();
        let mut attestation = PresenceAttestation::sign(&witness, &request, 0, 1);
        attestation.cell = "different".to_owned();
        let cert = PresenceCert {
            request,
            attestations: vec![attestation],
        };
        assert!(cert.verify(1).is_err());
    }
}
