#![no_main]
//! Fuzz the peer protocol decoder.
use keepstone_node::protocol::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data);
});
