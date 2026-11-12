//! Each public entry point must initialise the C library itself.
//!
//! Initialisation is process-wide, so every case has to be the *first* call in
//! a fresh process. The `init_cases` test re-runs this test binary once per
//! case, selecting the case through an environment variable that only the
//! `child` test reads.

use std::process::Command;

use multiversx_bls::{BlsError, G1, G2, SecretKey};

const CASE_VAR: &str = "MULTIVERSX_BLS_INIT_CASE";

/// Serialized signature that lies on the curve but outside the prime-order subgroup.
const NON_SUBGROUP_G1: &str = "e65ae93fa21ebd97bf76e6642d8027004bc943d3cb45540966871d8203316f4d0a50b95a43b1025bb555d0f219adaf19";

fn run_case(case: &str) {
    match case {
        "g1_is_zero" => assert!(G1::default().is_zero()),
        "g1_is_valid" => assert!(G1::default().is_valid()),
        "g2_is_zero" => assert!(G2::default().is_zero()),
        "g2_is_valid" => assert!(G2::default().is_valid()),
        // Disabling order verification before anything else must stick,
        // instead of being reset by the lazy initialisation that follows.
        "signature_order_toggle_first" => {
            // SAFETY: the child process runs this single test on one thread.
            unsafe { G1::verify_signature_order(false) };
            let sig = G1::from_serialized(&hex::decode(NON_SUBGROUP_G1).unwrap());
            // SAFETY: as above.
            unsafe { G1::verify_signature_order(true) };
            let sig = sig.expect("order check was disabled, deserialization must succeed");
            assert!(!sig.is_valid_order());
        }
        "public_key_order_toggle_first" => {
            // Only checks that the call itself is safe as the first call.
            // SAFETY: the child process runs this single test on one thread.
            unsafe { G2::verify_public_key_order(true) };
            let pk = SecretKey::from_hex_str("2").unwrap().get_public_key();
            assert!(G2::from_serialized(&pk.serialize().unwrap()).is_ok());
        }
        // The documented default: a fresh process rejects non-subgroup points.
        "order_check_on_by_default" => {
            let sig = G1::from_serialized(&hex::decode(NON_SUBGROUP_G1).unwrap());
            assert_eq!(sig, Err(BlsError::InvalidData));
        }
        other => panic!("unknown case {other}"),
    }
}

const CASES: &[&str] = &[
    "g1_is_zero",
    "g1_is_valid",
    "g2_is_zero",
    "g2_is_valid",
    "signature_order_toggle_first",
    "public_key_order_toggle_first",
    "order_check_on_by_default",
];

#[test]
fn child() {
    if let Ok(case) = std::env::var(CASE_VAR) {
        run_case(&case);
    }
}

#[test]
fn init_cases() {
    let exe = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    for case in CASES {
        let out = Command::new(&exe)
            .args(["--exact", "child", "--test-threads=1"])
            .env(CASE_VAR, case)
            .output()
            .unwrap();
        if !out.status.success() {
            failures.push(format!(
                "{case}: {}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "failed cases:\n{}",
        failures.join("\n")
    );
}
