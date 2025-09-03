#![no_main]
use libfuzzer_sys::fuzz_target;
use mx-bls-rs::Signature;

fuzz_target!(|data: &[u8]| {
    let _sig = Signature::from_serialized(data);
});
