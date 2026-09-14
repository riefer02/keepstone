//! Property-based tests for the core wire format.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use keepstone_core::{
    cbor::Encoder, DropBody, DropId, Mode, SealedContentKey, SignedDrop, WrappedKey,
    PROTOCOL_VERSION,
};
use keepstone_crypto::{CryptoSuite, HybridSealed, Identity, SealedKey};
use proptest::prelude::*;

fn arb_bytes<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    any::<[u8; N]>()
}

fn arb_sealed() -> impl Strategy<Value = SealedContentKey> {
    prop_oneof![
        (
            arb_bytes::<32>(),
            arb_bytes::<24>(),
            proptest::collection::vec(any::<u8>(), 0..64),
        )
            .prop_map(|(ephemeral_public, nonce, ciphertext)| {
                SealedContentKey::Classical(SealedKey {
                    ephemeral_public,
                    nonce,
                    ciphertext,
                })
            }),
        (
            arb_bytes::<32>(),
            proptest::collection::vec(any::<u8>(), 0..64),
            arb_bytes::<24>(),
            proptest::collection::vec(any::<u8>(), 0..64),
        )
            .prop_map(|(ephemeral_x25519, kem_ciphertext, nonce, ciphertext)| {
                SealedContentKey::Hybrid(HybridSealed {
                    ephemeral_x25519,
                    kem_ciphertext,
                    nonce,
                    ciphertext,
                })
            }),
    ]
}

fn arb_wrapped() -> impl Strategy<Value = WrappedKey> {
    (arb_bytes::<8>(), arb_sealed()).prop_map(|(tag, sealed)| WrappedKey { tag, sealed })
}

fn arb_body() -> impl Strategy<Value = DropBody> {
    (
        any::<String>(),
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<u32>(),
        any::<u32>(),
        arb_bytes::<32>(),
        arb_bytes::<20>(),
        arb_bytes::<16>(),
        any::<u64>(),
        proptest::collection::vec(arb_wrapped(), 0..4),
    )
        .prop_map(
            |(
                cell,
                ring,
                created_at,
                expiry,
                chunk_size,
                chunk_count,
                content_root,
                prefix,
                drop_nonce,
                pow_nonce,
                wrapped_keys,
            )| DropBody {
                version: PROTOCOL_VERSION,
                suite: CryptoSuite::Classical25519.id(),
                cell,
                ring,
                created_at,
                expiry,
                mode: Mode::Capability.id(),
                chunk_size,
                chunk_count,
                content_root,
                prefix,
                drop_nonce,
                pow_nonce,
                wrapped_keys,
            },
        )
}

proptest! {
    /// Canonical encoding is deterministic: a successful decode re-encodes to
    /// the exact same bytes.
    #[test]
    fn decode_is_canonical_or_rejected(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(body) = DropBody::from_canonical(&bytes) {
            prop_assert_eq!(body.to_canonical(), bytes);
        }
    }

    #[test]
    fn bodies_round_trip(body in arb_body()) {
        let bytes = body.to_canonical();
        prop_assert_eq!(DropBody::from_canonical(&bytes).unwrap(), body);
    }

    #[test]
    fn signed_drops_preserve_bytes_and_verify(body in arb_body()) {
        let identity = Identity::generate();
        let drop = SignedDrop::sign(&identity, &body);
        drop.verify().unwrap();
        // Identity is the hash of the exact transmitted bytes.
        prop_assert_eq!(drop.id(), DropId::of(&drop.raw));
        // Decoding the exact bytes reproduces the object and still verifies.
        let decoded = SignedDrop::decode(&drop.raw).unwrap();
        prop_assert_eq!(decoded.id(), drop.id());
        decoded.verify().unwrap();
        prop_assert_eq!(decoded.body().unwrap(), body);
    }

    /// A canonical envelope must not be re-encodable into a different byte
    /// sequence while still verifying (the 64-encoding trap).
    #[test]
    fn envelope_bytes_are_stable(body in arb_body()) {
        let identity = Identity::generate();
        let drop = SignedDrop::sign(&identity, &body);
        let reencoded = SignedDrop::decode(&drop.raw).unwrap().raw;
        prop_assert_eq!(reencoded, drop.raw);
    }

    #[test]
    fn cbor_encoder_never_panics(value in any::<u64>()) {
        let mut enc = Encoder::new();
        enc.uint(value);
        prop_assert!(!enc.into_bytes().is_empty());
    }
}
