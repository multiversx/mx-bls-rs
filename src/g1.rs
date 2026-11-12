use crate::constants::MCLBN_FP_UNIT_SIZE;
use crate::g2::G2;
use crate::init::{INIT, init_library};
use crate::{BlsError, bls_api::*};

/// signature type
#[derive(Default, Debug, Clone, Copy, Eq)]
#[repr(C)]
pub struct G1 {
    pub x: [u64; MCLBN_FP_UNIT_SIZE],
    pub y: [u64; MCLBN_FP_UNIT_SIZE],
    pub z: [u64; MCLBN_FP_UNIT_SIZE],
}

impl PartialEq for G1 {
    /// return true if `self` is equal to `rhs`
    fn eq(&self, rhs: &Self) -> bool {
        INIT.call_once(init_library);
        unsafe { blsSignatureIsEqual(self, rhs) == 1 }
    }
}

impl G1 {
    /// Returns true if `self` is usable as a signature: not the identity,
    /// in the prime-order subgroup, and on the curve.
    ///
    /// Same as `IsSigValidPoint` in mx-chain-crypto-go.
    pub fn is_valid_point(&self) -> bool {
        !self.is_zero() && self.is_valid_order() && self.is_valid()
    }

    /// Verifies `self` as a signature of `msg` by `public_key`, with the same
    /// checks as `BlsSingleSigner.Verify` in mx-chain-crypto-go.
    ///
    /// Returns false if `msg` is empty, or if `public_key` or `self` is not a
    /// valid point (see `G2::is_valid_point` and `G1::is_valid_point`).
    /// Unlike [`G1::verify`], the subgroup checks hold even when order
    /// verification on deserialization has been disabled.
    pub fn verify_checked(&self, public_key: &G2, msg: &[u8]) -> bool {
        !msg.is_empty()
            && public_key.is_valid_point()
            && self.is_valid_point()
            && self.verify(*public_key, msg)
    }

    /// Verifies `self` as an aggregated signature of `msg` by all
    /// `public_keys`, with the same checks as
    /// `BlsMultiSignerKOSK.VerifyAggregatedSig` in mx-chain-crypto-go.
    ///
    /// Returns false if `msg` or `public_keys` is empty. Like Go, it does not
    /// check the points themselves: under the KOSK scheme the public keys must
    /// already be validated, registered keys.
    pub fn fast_aggregate_verify_checked(&self, public_keys: &[G2], msg: &[u8]) -> bool {
        !msg.is_empty() && self.fast_aggregate_verify(public_keys, msg)
    }

    /// Aggregates `sigs` into one signature, with the same checks as
    /// `BlsMultiSignerKOSK.AggregateSignatures` in mx-chain-crypto-go.
    ///
    /// Returns `BlsError::InvalidData` if `sigs` is empty or any signature is
    /// not a valid point (see `G1::is_valid_point`).
    pub fn aggregate_checked(sigs: &[G1]) -> Result<G1, BlsError> {
        if sigs.is_empty() || !sigs.iter().all(G1::is_valid_point) {
            return Err(BlsError::InvalidData);
        }

        let mut aggregated = G1::default();
        aggregated.aggregate(sigs);
        Ok(aggregated)
    }

    /// return true if `self` is valid signature of `msg` for `public_key`
    ///
    /// No input checks: prefer [`G1::verify_checked`], which matches the node.
    pub fn verify(&self, public_key: G2, msg: &[u8]) -> bool {
        INIT.call_once(init_library);
        unsafe { blsVerify(self, &public_key, msg.as_ptr(), msg.len()) == 1 }
    }

    /// return true if `self` is a valid signature of `msg` for `public keys`
    /// * `public_keys` - array of public key
    /// * `msg` - message
    ///
    /// Prefer [`G1::fast_aggregate_verify_checked`], which matches the node.
    pub fn fast_aggregate_verify(&self, public_keys: &[G2], msg: &[u8]) -> bool {
        INIT.call_once(init_library);
        if public_keys.is_empty() {
            return false;
        }

        unsafe {
            blsFastAggregateVerify(
                self,
                public_keys.as_ptr(),
                public_keys.len(),
                msg.as_ptr(),
                msg.len(),
            ) == 1
        }
    }

    /// add a signature to `self`
    pub fn add_assign(&mut self, signature: G1) {
        INIT.call_once(init_library);
        unsafe {
            blsSignatureAdd(self, &signature);
        }
    }

    /// return true if `self` has the valid order
    pub fn is_valid_order(&self) -> bool {
        INIT.call_once(init_library);
        unsafe { blsSignatureIsValidOrder(self) == 1 }
    }

    /// set the aggregated signature of `sigs`
    /// * `sigs` - signatures to be aggregated
    pub fn aggregate(&mut self, sigs: &[G1]) {
        INIT.call_once(init_library);
        if sigs.is_empty() {
            return;
        }

        unsafe {
            blsAggregateSignature(self, sigs.as_ptr(), sigs.len());
        }
    }

    /// Checks if the `G1` element is the point at infinity (zero element).
    ///
    /// This function determines whether the `G1` element represented by `self`
    /// is the zero element, which is the identity element in the group.
    ///
    /// # Returns
    /// `true` if the `G1` element is the zero element, otherwise `false`.
    pub fn is_zero(&self) -> bool {
        INIT.call_once(init_library);
        unsafe { mclBnG1_isZero(self) == 1 }
    }

    /// Checks if the `G1` element is valid.
    ///
    /// This function determines whether the `G1` element represented by `self`
    /// is valid according to the cryptographic library's requirements.
    ///
    /// # Returns
    /// `true` if the `G1` element is valid, otherwise `false`.
    pub fn is_valid(&self) -> bool {
        INIT.call_once(init_library);
        unsafe { mclBnG1_isValid(self) == 1 }
    }

    /// Enables or disables the subgroup (order) check that signature
    /// deserialization performs. Enabled by default.
    ///
    /// The setting is process-wide: it changes how every `G1` is deserialized,
    /// in every thread, including by other crates using this one. With the
    /// check disabled, `deserialize` and `from_serialized` accept points
    /// outside the prime-order subgroup; check them with `is_valid_order`.
    ///
    /// # Safety
    /// The setting is a global variable in the C library, written without
    /// synchronisation. The caller must ensure no other thread is calling
    /// into this crate while it runs.
    pub unsafe fn verify_signature_order(verify: bool) {
        INIT.call_once(init_library);
        unsafe { blsSignatureVerifyOrder(verify as i32) }
    }

    /// return true if `buf` is deserialized successfully
    /// * `buf` - serialized data by `serialize`
    pub fn deserialize(&mut self, buf: &[u8]) -> bool {
        INIT.call_once(init_library);
        let n = unsafe { blsSignatureDeserialize(self, buf.as_ptr(), buf.len()) };

        n > 0 && n == buf.len()
    }

    /// return deserialized `buf`
    pub fn from_serialized(buf: &[u8]) -> Result<Self, BlsError> {
        let mut v = Self::default();
        if v.deserialize(buf) {
            return Ok(v);
        }

        Err(crate::BlsError::InvalidData)
    }

    /// return serialized byte array
    pub fn serialize(&self) -> Result<Vec<u8>, BlsError> {
        INIT.call_once(init_library);

        let size = unsafe { mclBn_getFpByteSize() };
        let mut buf = vec![0u8; size];

        let n = unsafe { blsSignatureSerialize(buf.as_mut_ptr(), size, self) };
        if n == 0 {
            return Err(BlsError::SerializeError);
        }

        buf.truncate(n);

        Ok(buf)
    }
}
