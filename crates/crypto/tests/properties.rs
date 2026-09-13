//! Property-based tests for the cryptographic core.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use keepstone_crypto::{aead, shamir, stream, Identity, SealedKey};
use proptest::prelude::*;

proptest! {
    #[test]
    fn aead_round_trips(key: [u8; 32], nonce: [u8; 24], message in proptest::collection::vec(any::<u8>(), 0..512)) {
        let ciphertext = aead::seal(&key, &nonce, b"aad", &message).unwrap();
        prop_assert_eq!(aead::open(&key, &nonce, b"aad", &ciphertext).unwrap(), message);
    }

    #[test]
    fn chunked_stream_round_trips(key: [u8; 32], length in 0usize..200_000) {
        let plaintext = vec![0x5Au8; length];
        let (framing, chunks) = stream::encrypt(&key, &plaintext).unwrap();
        prop_assert_eq!(stream::decrypt(&key, &framing, &chunks).unwrap(), plaintext);
    }

    #[test]
    fn any_chunk_tamper_is_detected(key: [u8; 32], length in 1usize..70_000) {
        let plaintext = vec![1u8; length];
        let (framing, mut chunks) = stream::encrypt(&key, &plaintext).unwrap();
        chunks[0][0] ^= 0x01;
        prop_assert!(stream::decrypt(&key, &framing, &chunks).is_err());
    }

    #[test]
    fn sealed_keys_open_only_for_the_recipient(secret_a: [u8; 32], secret_b: [u8; 32]) {
        // Reject degenerate all-zero secrets that produce invalid keys.
        prop_assume!(secret_a != [0u8; 32] && secret_b != [0u8; 32] && secret_a != secret_b);
        let a = Identity::from_secret_bytes(&[1u8; 32], &secret_a);
        let b = Identity::from_secret_bytes(&[2u8; 32], &secret_b);
        let content_key = [5u8; 32];
        let sealed = SealedKey::seal(&content_key, &a.ecdh_public()).unwrap();
        prop_assert_eq!(sealed.open(&a.ecdh_secret_bytes()).unwrap(), content_key);
        prop_assert!(sealed.open(&b.ecdh_secret_bytes()).is_err());
    }

    #[test]
    fn shamir_reconstructs_at_threshold(secret in proptest::collection::vec(any::<u8>(), 1..48)) {
        let shares = shamir::split(&secret, 3, 5).unwrap();
        let subset = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        prop_assert_eq!(shamir::combine(&subset).unwrap(), secret);
    }
}
