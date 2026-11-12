# multiversx-bls audit — 2026-11-11

Scope: the whole repository at `cb113a0` (`multiversx-bls` 0.2.1), compared with the BLS implementation the MultiversX node runs: `mx-chain-crypto-go v1.3.3` (`signing/mcl/...`), which `mx-chain-go` links against `herumi/bls-go-binary v1.37.0`.

## Summary

The cryptographic output matches Go exactly. The problems are in the Rust wrapper around the C library: one memory-safety bug reachable from safe code, process-wide settings exposed as safe functions, a build script that fails in some workspace layouts, and no checked sign/verify API equivalent to Go's.

## Differential test against Go

A Go program running the real `mx-chain-crypto-go v1.3.3` code (`BlsSingleSigner`, `BlsMultiSignerKOSK`, key generator) produced test cases and accept/reject decisions. A Rust program replayed them through this crate, used as a path dependency.

Result: **176 checks, 0 mismatches.**

- Public keys, signatures (messages of 1 to 4096 bytes) and KOSK aggregates of 1, 2, 7, 63 and 400 signers are byte-identical, and `fast_aggregate_verify` agrees.
- Signature and public-key decoding accept and reject the same inputs: valid, identity, all-zero, all-`0xff`, non-subgroup point, truncated, extended, and flipped flag/data bits.
- Secret-key decoding agrees for 0, 1, r−1, r, all-`0xff`, 31 and 33 bytes.
- Both reject an identity signature with an identity public key, and a KOSK aggregate over the cancelling keys {P, −P} with an identity signature.

### Library provenance and version

- All five archives in `executors/` are byte-identical (SHA-256) to the `bls-go-binary v1.28.2` release.
- `mx-chain-go` resolves `bls-go-binary` to **v1.37.0**. The C headers of the two versions are ABI-compatible and the differential test found no behaviour difference, but the crate should move to v1.37.0 to match the node.

## Findings

| # | Severity | Status | Finding |
|---|---|---|---|
| 1 | High | Fixed | Calls into the C library before initialisation segfault in safe Rust |
| 2 | Medium | Open | `blsInit` failure is ignored |
| 3 | Medium | Open | Order-verification toggles are global, unsynchronised and misdocumented |
| 4 | Medium | Open | `build.rs` breaks when the crate is a workspace member in a subdirectory |
| 5 | Medium | Open | No checked sign/verify API matching Go |
| 6 | Low | Open | `G2::set_str` ignores errors and leaves a corrupted point |
| 7 | Low | Open | FFI declarations don't match the C header |
| 8 | Low | Open | Secret-key hygiene |
| 9 | Low | Open | Public point fields allow unchecked points |
| 10 | Low | Open | `aggregate(&[])` keeps a stale value |
| 11 | Info | Open | Only the KOSK aggregation scheme is supported |
| 12 | Info | Open | API cleanup items |

### 1. Calls before initialisation segfault (High)

`G1::is_zero`, `G1::is_valid`, `G2::is_zero` and `G2::is_valid` called `mclBnG1_*`/`mclBnG2_*` without `INIT.call_once(init_library)`. When one of them was the first call in a process, the process crashed with SIGSEGV (exit 139), even for `G1::default().is_zero()`. This is undefined behaviour reachable from safe code. The existing tests didn't catch it because another test always initialised the library first.

`G1::verify_signature_order` and `G2::verify_public_key_order` also skipped initialisation. Called first, their setting was silently undone when `blsInit` later ran and reset order verification to its default.

Fix: every one of these functions now initialises the library first; `tests/init.rs` runs each case in a fresh process.

### 2. `blsInit` failure is ignored (Medium)

`init()` returns `blsInit(...) == 0`, but `init_library` discards it ([src/init.rs](src/init.rs)). If initialisation fails (for example a compile-time constant mismatch with the static library), every later call runs against an uninitialised curve. Go panics in the same situation (`suiteBLS12_381.go`, `blsInit`).

Recommendation: panic with a clear message when `blsInit` returns non-zero.

### 3. Order-verification toggles (Medium)

`G1::verify_signature_order` and `G2::verify_public_key_order` are safe functions that write process-wide C state without synchronisation.

- After `verify_signature_order(false)`, `G1::from_serialized` accepts points outside the prime-order subgroup in every thread of the process (confirmed: `is_valid = true`, `is_valid_order = false`).
- Writing the flag while another thread deserialises is a data race in C.
- The README says the default is "disabled". It is **enabled**: the C header says `default 1`, and a fresh process rejects non-subgroup points.

Go never disables these checks and additionally checks `IsValidOrder()` explicitly before verifying.

Recommendation: remove the toggles or make them `unsafe` with documented consequences, and fix the README.

### 4. `build.rs` link path (Medium)

`cargo:rustc-link-search=native=./executors` is resolved relative to rustc's working directory, which is the workspace root for workspace members. Building the crate as a member at `vendor/bls/` fails with `could not find native static library bls384_256_arm_macos`.

Related:
- No `links = "..."` key in `Cargo.toml`, so Cargo can't detect a second crate linking the same herumi symbols.
- `("arm", "linux")` (32-bit) is mapped to the aarch64 archive; `("arm", "macos")` is not a real target.
- No `cargo:rerun-if-changed` lines, so the build script reruns on any file change.

Recommendation: build the path from `CARGO_MANIFEST_DIR`, add a `links` key, drop the 32-bit `arm` arms.

### 5. No checked sign/verify API (Medium)

Go's `BlsSingleSigner` adds checks around the raw C calls:

- `Sign` rejects an empty message and a zero or invalid secret key.
- `Verify` rejects an empty message and signature, and requires both the public key and the signature to be non-zero, valid and in the subgroup.

The Rust API exposes only the raw calls. `SecretKey::sign` with a zero key returns the identity signature without error, and empty messages are signed and verified. Under default settings raw `verify` agreed with Go on every tested input, so this is a missing safeguard rather than a current exploit. It becomes one if order checks are disabled (finding 3).

Downstream, `mx-sdk-rs/chain/vm/src/crypto_functions_bls.rs` re-implements Go's checks itself and wraps every call in a global `BLS_MUTEX`.

Recommendation: add `verify_strict`/checked `sign` functions that mirror Go, so consumers don't each re-implement them.

### 6. `G2::set_str` ignores errors (Low)

The return code of `mclBnG2_setStr` is discarded ([src/g2.rs](src/g2.rs)). With invalid input the point is left partially overwritten and invalid (`is_valid = false`), and `serialize()` still succeeds on it.

Recommendation: return `Result<(), BlsError>`.

### 7. FFI declarations don't match the C header (Low)

In [src/bls_api.rs](src/bls_api.rs):

- `blsInit(int, int)` is declared with `usize` parameters.
- `mclBn_getFrByteSize` / `mclBn_getFpByteSize` return `int` but are declared to return `usize`.
- `mclBnG1_isZero`, `mclBnG1_isValid`, `mclBnG2_isZero`, `mclBnG2_isValid` return `int` but are declared to return `u8`.
- `blsSecretKeySetByCSPRNG` returns `int` (0 on success) but is declared to return nothing.

This works on current 64-bit little-endian ABIs but is undefined behaviour in Rust. Use `std::ffi::c_int`.

### 8. Secret-key hygiene (Low)

`SecretKey` derives `Copy` and `Debug` (printing the key's internal limbs) and is never zeroed on drop. Recommendation: remove `Copy`, redact `Debug`, zero on drop. This is a breaking change.

### 9. Public point fields (Low)

`G1` and `G2` expose `pub x, y, z` in the C library's internal (Montgomery) representation. Callers can build points that never went through validation, and the internal layout becomes part of the public API.

### 10. `aggregate(&[])` (Low)

`G1::aggregate` returns early on an empty slice and leaves the previous value in place. Go's `Sign.Aggregate` passes `n = 0` to C, which sets the result to the identity.

### 11. KOSK only (Info)

Only the KOSK aggregation scheme (active on mainnet) can be implemented with this crate. The older no-KOSK scheme (`signing/mcl/multisig/bls.go`) needs scalar multiplication of points, which isn't exposed, so early-epoch aggregate signatures can't be verified.

### 12. API cleanup (Info)

- `GT` is exported but nothing can produce one (no pairing function).
- `G2::deserialize` and `G2::deserialize_g2` behave identically (confirmed by the differential test).
- `G1::verify` takes the 288-byte `G2` by value.

## Tests and CI

- No negative tests: invalid encodings, non-subgroup points, identity points, invalid secret keys.
- No test vectors produced by the Go implementation; the origin of `tests/*.txt` isn't documented.
- Test vector files are opened with paths relative to the current directory.
- CI doesn't cover Linux arm64 or macOS x86_64 (`macos-latest` is arm64).

## Positives

- Bundled archives are verifiably the upstream release.
- Decoding requires the whole buffer to be consumed, exactly like the Go binding.
- Initialisation is guarded by `std::sync::Once`.
- `cargo test` and `cargo clippy --all-targets -- -D warnings` pass.

## Recommended order of work

1. Initialise before every C call (done), and panic if `blsInit` fails.
2. Remove or make `unsafe` the order toggles; fix the README default.
3. Fix `build.rs` (`CARGO_MANIFEST_DIR`, `links`).
4. Add checked sign/verify matching Go.
5. Correct FFI types, make `set_str` return `Result`, harden `SecretKey`.
6. Commit the Go-generated vectors as tests and run them in CI; upgrade the archives to v1.37.0.
