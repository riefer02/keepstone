#![no_main]
//! Fuzz the presence request and attestation decoders.
use keepstone_core::presence::{PresenceAttestation, PresenceRequest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = PresenceRequest::from_canonical(data);
    let _ = PresenceAttestation::from_canonical(data);
});
