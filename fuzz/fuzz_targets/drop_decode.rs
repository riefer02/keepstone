#![no_main]
//! Fuzz the drop envelope decoder and the canonical-encoding invariant.
use keepstone_core::{DropBody, SignedDrop};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decoding untrusted bytes must never panic.
    if let Ok(signed) = SignedDrop::decode(data) {
        // The identity is the hash of the exact bytes; verification must not panic.
        let _ = signed.verify();
        let _ = signed.id();
        if let Ok(body) = signed.body() {
            // Canonical re-encoding is idempotent: decode(encode(body)) == body.
            let encoded = body.to_canonical();
            if let Ok(again) = DropBody::from_canonical(&encoded) {
                assert_eq!(again, body);
            }
        }
    }
    let _ = DropBody::from_canonical(data);
});
