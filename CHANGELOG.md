# Change Log

This file contains a centralizes a trace of all published crate versions, with their changes in short.

## [Unreleased]

- Fixes a segfault when `G1`/`G2` `is_zero` or `is_valid` was the first call in a process: they now initialise the library first.
- `verify_signature_order` and `verify_public_key_order` now initialise the library first, so a setting made before any other call is no longer silently reset.
- Panics if the C library fails to initialise, instead of continuing on an uninitialised curve.
- **Breaking:** `G1::verify_signature_order` and `G2::verify_public_key_order` are now `unsafe fn`. They change a process-wide, unsynchronised setting in the C library; disabling it makes deserialization accept points outside the prime-order subgroup in every thread. Documentation now states the check is enabled by default (it was wrongly described as disabled).


## [multiversx-bls 0.2.1] - 2026-05-27

- Fixes Windows build: correctly links the Windows AMD64 static library and conditionally links `stdc++` only for the GNU toolchain.
- Upgraded to edition 2024.


## [multiversx-bls 0.2.0] - 2025-09-16

- Adds new functionality to the `SecretKey` type: `is_zero` and `is_valid`. This allows users to check if a secret key is valid or zero


## [multiversx-bls 0.1.0] - 2025-09-04

- First version, forked from `herumi/bls-eth-rust`, but completely reworked.
