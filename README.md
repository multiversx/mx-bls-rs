# multiversx-bls for Rust

This is a wrapper library of [bls](https://github.com/herumi/bls/), that bridges the functionality with MultiversX [crypto packages](https://github.com/multiversx/mx-chain-crypto-go).

## Spec Name

multiversx-bls | Spec Name|
------|-----------------|
G1|Signature|
G2|Public Key|

## Checked functions

The `*_checked` functions and `is_valid_point` apply the same input checks as the MultiversX node ([mx-chain-crypto-go](https://github.com/multiversx/mx-chain-crypto-go) `BlsSingleSigner` and `BlsMultiSignerKOSK`). Prefer them over the raw functions, which pass inputs straight to the C library.

| Rust | mx-chain-crypto-go | Rejects |
|---|---|---|
| `G1::is_valid_point`, `G2::is_valid_point` | `IsSigValidPoint`, `IsPubKeyPointValid` | identity, outside the prime-order subgroup, not on the curve |
| `SecretKey::sign_checked` | `BlsSingleSigner.Sign` | empty message; zero or invalid key |
| `G1::verify_checked` | `BlsSingleSigner.Verify` | empty message; public key or signature that is not a valid point |
| `G1::aggregate_checked` | `BlsMultiSignerKOSK.AggregateSignatures` | no signatures; any signature that is not a valid point |
| `G1::fast_aggregate_verify_checked` | `BlsMultiSignerKOSK.VerifyAggregatedSig` | empty message; no public keys |

Like the node, `fast_aggregate_verify_checked` does not check the public keys themselves: under the KOSK scheme they must already be validated, registered keys.

## G1 - Signature

`is_valid_point(&self) -> bool`

- Checks that self is not the identity, is in the prime-order subgroup and is on the curve.

`verify_checked(&self, public_key: &G2, msg: &[u8]) -> bool`

- Checks if self is a valid signature of message for the given public key, with the node's input checks.

`fast_aggregate_verify_checked(&self, public_keys: &[G2], msg: &[u8]) -> bool`

- Checks if self is a valid aggregated signature of message for multiple public keys, with the node's input checks.

`aggregate_checked(sigs: &[G1]) -> Result<G1, BlsError>`

- Aggregates signatures, with the node's input checks:
  - The aggregated signature if successful;
  - Return `BlsError::InvalidData` if `sigs` is empty or any signature is not a valid point.

`verify(&self, public_key: G2, msg: &[u8]) -> bool`

- Checks if self is a valid signature of message for the given public key. No input checks.

`fast_aggregate_verify(&self, public_keys: &[G2], msg: &[u8]) -> bool`

- Checks if self is a valid aggregated signature of message for multiple public keys. No input checks.

`add_assign(&mut self, signature: G1)`

- Adds another signature to self (signature aggregation).

`is_valid_order(&self) -> bool`

- Checks if self is a valid signature of the correct group order.

`aggregate(&mut self, sigs: &[G1])`

- Sets self as the aggregated signature of signatures.

`is_zero(&self) -> bool`

- Checks if self is the point at infinity (zero element).

`is_valid(&self) -> bool`

- Checks if self is a valid G1 element.

`unsafe fn verify_signature_order(verify: bool)`

- Enables or disables the subgroup (order) check during signature deserialization:
  - `true`: check enabled (default);
  - `false`: check disabled; deserialization accepts points outside the prime-order subgroup.
- The setting is process-wide and not synchronised: it affects every thread, and no other thread may call into the crate while it runs.

`deserialize(&mut self, buf: &[u8]) -> bool`

- Deserialize a signature from an array of bytes.

`from_serialized(buf: &[u8]) -> Result<Self, BlsError>`

- Creates a new G1 element from a serialized buffer:
  - G1 if successful;
  - Return `BlsError::InvalidData` on failure.

`serialize(&self) -> Result<Vec<u8>, BlsError>`

- Serializes the signature into a vector of bytes:
  - A vector of bytes if successful;
  - Return `BlsError::SerializeError` on failure.

## G2 - Public Key

`is_valid_point(&self) -> bool`

- Checks that self is not the identity, is in the prime-order subgroup and is on the curve.

`add_assign(&mut self, public_key: G2)`

- Adds another public key to self.

`is_valid_order(&self) -> bool`

- Checks if self is a valid public key of the correct group order.

`set_str(&mut self, s: &str)`

- Sets the G2 element from a **base-10** string.

`deserialize_g2(&mut self, buf: &[u8]) -> bool`

- Deserializes a G2 element from a byte buffer.

`is_zero(&self) -> bool`

- Checks if self is the point at infinity (zero element).

`is_valid(&self) -> bool`

- Checks if self is a valid G2 element.

`unsafe fn verify_public_key_order(verify: bool)`

- Enables or disables the subgroup (order) check during public key deserialization:
  - `true`: check enabled (default);
  - `false`: check disabled; deserialization accepts points outside the prime-order subgroup.
- The setting is process-wide and not synchronised: it affects every thread, and no other thread may call into the crate while it runs.

`serialize(&self) -> Result<Vec<u8>, BlsError>`

- Serializes the public key into a byte array.
  - A vector of bytes if successful;
  - Return `BlsError::SerializeError` on failure.

`deserialize(&mut self, buf: &[u8]) -> bool`

- Deserializes a public key from a byte array.

`from_serialized(buf: &[u8]) -> Result<Self, BlsError>`

- Creates a new G2 element from a serialized buffer:
  - Returns G2 if successful;
  - Returns `BlsError::InvalidData` otherwise.

## Secret Key

`set_by_csprng(&mut self)`

- Initializes the secret key using a cryptographically secure random number generator (CSPRNG). Panics if the generated key is zero.

`set_hex_str(&mut self, s: &str) -> bool`

- Sets the secret key from a hexadecimal string.

`from_hex_str(s: &str) -> Result<SecretKey, BlsError>`

- Creates a new secret key from a hexadecimal string:
  - Returns SecretKey if valid;
  - Returns `BlsError::InvalidData` if invalid.

`get_public_key(&self) -> G2`

- Derives the public key (G2) corresponding to this secret key.

`sign_checked(&self, msg: &[u8]) -> Result<G1, BlsError>`

- Generates a signature (G1) of the given message, with the node's input checks:
  - The signature if successful;
  - Return `BlsError::InvalidData` if the message is empty or the key is zero or invalid.

`sign(&self, msg: &[u8]) -> G1`

- Generates a signature (G1) of the given message.

`deserialize(&mut self, buf: &[u8]) -> bool`

- Deserializes a secret key from a byte array. Returns true if successful and length matches.

`from_serialized(buf: &[u8]) -> Result<Self, BlsError>`

- Creates a new secret key from serialized data:
  - Returns SecretKey if valid;
  - Returns `BlsError::InvalidData` if invalid.

`serialize(&self) -> Result<Vec<u8>, BlsError>`

- Serializes the secret key into a byte array:
  - A vector of bytes if successful;
  - Return `BlsError::SerializeError` on failure.

## Executors

- Executors are extracted from [bls-go-binary](https://github.com/herumi/bls-go-binary), version `v1.28.2`.

## Usage

Example: creating a public key from a vector of bytes.

```rust
let buffer = [0; 96];

let mut public_key = G2::default();

if !public_key.deserialize_g2(&buffer) {
    return Err(BlsError::InvalidData);
}
```

Example: creating a signature from a vector of bytes.

```rust
let buffer = [0; 48];

let mut sign = G1::default();

if !sign.deserialize(&buffer) {
    return Err(BlsError::InvalidData);
}
```

Example: verifying a BLS signature with a single public key and message.

```rust
fn verify_signature(signature: &G1, public_key: &G2, message: &[u8]) -> bool {
    signature.verify_checked(public_key, message)
}
```

## Acknowledgements

This repository originated as a fork of [herumi/bls-eth-rust](https://github.com/herumi/bls-eth-rust) by MITSUNARI Shigeo, a Rust wrapper around the [herumi/bls](https://github.com/herumi/bls) C library. The original implementation provided the foundational FFI bindings and BLS primitives that this library builds upon.

The codebase has since been substantially rewritten — Ethereum-specific logic was removed, the API was restructured into dedicated modules, and the library was tailored to MultiversX's requirements. The fork has been detached from the upstream repository to reflect this divergence.
