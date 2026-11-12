//! The `*_checked` functions must apply the same input checks as
//! mx-chain-crypto-go (`BlsSingleSigner`, `BlsMultiSignerKOSK`).
//!
//! Some cases switch off the process-wide order check, so every test in this
//! file takes `LOCK` and they run one at a time.

use std::sync::{Mutex, MutexGuard};

use multiversx_bls::{BlsError, G1, G2, SecretKey};

static LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// On the curve, outside the prime-order subgroup (generated with mx-chain-crypto-go).
const NON_SUBGROUP_G1: &str = "e65ae93fa21ebd97bf76e6642d8027004bc943d3cb45540966871d8203316f4d0a50b95a43b1025bb555d0f219adaf19";
const NON_SUBGROUP_G2: &str = "759b315dab54de3600b5813d2426487576e7e74dcf77aacdc69b852fda386f99a456a2f0b2291f5fad818c49a3caf5191c4bcd9f5c6747bb322b48453cbbe078d505b84cfd59d17d25978d3b466fb82ba4bfc337de22fb5593a466d44270aa03";

const MSG: &[u8] = b"message";

fn key(hex: &str) -> SecretKey {
    SecretKey::from_hex_str(hex).unwrap()
}

/// Deserializes with the order check switched off, then restores it.
fn non_subgroup_points() -> (G1, G2) {
    // SAFETY: every test in this file holds LOCK, and no other test binary
    // shares this process.
    unsafe {
        G1::verify_signature_order(false);
        G2::verify_public_key_order(false);
    }
    let sig = G1::from_serialized(&hex::decode(NON_SUBGROUP_G1).unwrap());
    let pk = G2::from_serialized(&hex::decode(NON_SUBGROUP_G2).unwrap());
    // SAFETY: as above.
    unsafe {
        G1::verify_signature_order(true);
        G2::verify_public_key_order(true);
    }
    (sig.unwrap(), pk.unwrap())
}

#[test]
fn sign_and_verify_valid() {
    let _l = lock();
    let sk = key("1234");
    let pk = sk.get_public_key();
    let sig = sk.sign_checked(MSG).unwrap();

    assert_eq!(sig, sk.sign(MSG));
    assert!(sig.is_valid_point());
    assert!(pk.is_valid_point());
    assert!(sig.verify_checked(&pk, MSG));
    assert!(!sig.verify_checked(&pk, b"other message"));
}

#[test]
fn empty_message_is_rejected() {
    let _l = lock();
    let sk = key("1234");
    let pk = sk.get_public_key();

    assert_eq!(sk.sign_checked(b""), Err(BlsError::InvalidData));

    // The raw functions accept the empty message; the checked ones must not.
    let sig = sk.sign(b"");
    assert!(sig.verify(pk, b""));
    assert!(!sig.verify_checked(&pk, b""));
    assert!(sig.fast_aggregate_verify(&[pk], b""));
    assert!(!sig.fast_aggregate_verify_checked(&[pk], b""));
}

#[test]
fn zero_secret_key_cannot_sign() {
    let _l = lock();
    let zero = SecretKey::from_serialized(&[0u8; 32]).unwrap();

    assert!(zero.sign(MSG).is_zero());
    assert_eq!(zero.sign_checked(MSG), Err(BlsError::InvalidData));
}

#[test]
fn identity_points_are_rejected() {
    let _l = lock();
    let sk = key("1234");
    let pk = sk.get_public_key();
    let sig = sk.sign(MSG);
    let identity_sig = G1::default();
    let identity_pk = G2::default();

    assert!(!identity_sig.is_valid_point());
    assert!(!identity_pk.is_valid_point());
    assert!(!identity_sig.verify_checked(&pk, MSG));
    assert!(!sig.verify_checked(&identity_pk, MSG));
    assert!(!identity_sig.verify_checked(&identity_pk, MSG));
}

#[test]
fn non_subgroup_points_are_rejected_even_with_order_check_off() {
    let _l = lock();
    let (bad_sig, bad_pk) = non_subgroup_points();
    let sk = key("1234");
    let pk = sk.get_public_key();
    let sig = sk.sign(MSG);

    assert!(!bad_sig.is_valid_point());
    assert!(!bad_pk.is_valid_point());
    assert!(!bad_sig.verify_checked(&pk, MSG));
    assert!(!sig.verify_checked(&bad_pk, MSG));
    assert_eq!(G1::aggregate_checked(&[sig, bad_sig]), Err(BlsError::InvalidData));
}

#[test]
fn aggregate_and_fast_aggregate_verify() {
    let _l = lock();
    let keys: Vec<SecretKey> = ["11", "22", "33"].into_iter().map(key).collect();
    let pks: Vec<G2> = keys.iter().map(SecretKey::get_public_key).collect();
    let sigs: Vec<G1> = keys.iter().map(|k| k.sign(MSG)).collect();

    let aggregated = G1::aggregate_checked(&sigs).unwrap();
    let mut expected = G1::default();
    expected.aggregate(&sigs);
    assert_eq!(aggregated, expected);

    assert!(aggregated.fast_aggregate_verify_checked(&pks, MSG));
    assert!(!aggregated.fast_aggregate_verify_checked(&pks[..2], MSG));
    assert!(!aggregated.fast_aggregate_verify_checked(&[], MSG));
}

#[test]
fn aggregate_checked_rejects_empty_and_identity() {
    let _l = lock();
    let sig = key("1234").sign(MSG);

    assert_eq!(G1::aggregate_checked(&[]), Err(BlsError::InvalidData));
    assert_eq!(G1::aggregate_checked(&[sig, G1::default()]), Err(BlsError::InvalidData));
}
