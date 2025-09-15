use crate::g1::G1;
use crate::g2::G2;
use crate::gt::GT;
use crate::secret_key::SecretKey;

unsafe extern "C" {
    pub unsafe fn blsInit(curve: usize, compiledTimeVar: usize) -> i32;

    pub unsafe fn mclBnFr_isZero(secret_key: *const SecretKey) -> i32;
    pub unsafe fn mclBnFr_isValid(secret_key: *const SecretKey) -> i32;
    pub unsafe fn mclBn_getFrByteSize() -> usize;
    pub unsafe fn mclBn_getFpByteSize() -> usize;
    pub unsafe fn mclBnG2_setStr(x: *mut G2, buf: *const u8, buf_size: usize, io_mode: i32) -> i32;
    pub unsafe fn mclBnG2_deserialize(x: *mut G2, buf: *const u8, buf_size: usize) -> usize;
    pub unsafe fn mclBnG2_isZero(x: *const G2) -> u8;
    pub unsafe fn mclBnG2_isValid(x: *const G2) -> u8;

    pub unsafe fn mclBnG1_isZero(x: *const G1) -> u8;
    pub unsafe fn mclBnG1_isValid(x: *const G1) -> u8;

    pub unsafe fn blsSecretKeySetByCSPRNG(x: *mut SecretKey);
    pub unsafe fn blsSecretKeySetHexStr(x: *mut SecretKey, buf: *const u8, buf_size: usize) -> i32;
    pub unsafe fn blsGetPublicKey(y: *mut G2, x: *const SecretKey);
    pub unsafe fn blsSignatureVerifyOrder(do_verify: i32);
    pub unsafe fn blsSignatureIsValidOrder(sig: *const G1) -> i32;
    pub unsafe fn blsPublicKeyVerifyOrder(do_verify: i32);
    pub unsafe fn blsPublicKeyIsValidOrder(public_key: *const G2) -> i32;

    pub unsafe fn blsSign(
        sig: *mut G1,
        secret_key: *const SecretKey,
        msg: *const u8,
        msg_len: usize,
    );
    pub unsafe fn blsVerify(
        sig: *const G1,
        public_key: *const G2,
        msg: *const u8,
        msg_len: usize,
    ) -> i32;
    pub unsafe fn blsFastAggregateVerify(
        sig: *const G1,
        public_key: *const G2,
        public_keys_len: usize,
        msg: *const u8,
        msg_len: usize,
    ) -> i32;

    pub unsafe fn blsAggregateSignature(
        aggregate_sig: *mut G1,
        signature: *const G1,
        signatures_len: usize,
    );

    pub unsafe fn blsSecretKeyIsEqual(lhs: *const SecretKey, rhs: *const SecretKey) -> i32;
    pub unsafe fn blsPublicKeyIsEqual(lhs: *const G2, rhs: *const G2) -> i32;
    pub unsafe fn blsSignatureIsEqual(lhs: *const G1, rhs: *const G1) -> i32;

    pub unsafe fn blsSecretKeySerialize(
        buf: *mut u8,
        max_buf_len: usize,
        x: *const SecretKey,
    ) -> usize;
    pub unsafe fn blsPublicKeySerialize(buf: *mut u8, max_buf_len: usize, x: *const G2) -> usize;
    pub unsafe fn blsSignatureSerialize(buf: *mut u8, max_buf_len: usize, x: *const G1) -> usize;

    pub unsafe fn blsSecretKeyDeserialize(
        x: *mut SecretKey,
        buf: *const u8,
        buf_len: usize,
    ) -> usize;
    pub unsafe fn blsPublicKeyDeserialize(x: *mut G2, buf: *const u8, buf_len: usize) -> usize;
    pub unsafe fn blsSignatureDeserialize(x: *mut G1, buf: *const u8, buf_len: usize) -> usize;

    pub unsafe fn blsPublicKeyAdd(public_key_1: *mut G2, public_key_2: *const G2);
    pub unsafe fn blsSignatureAdd(signature_1: *mut G1, signature_2: *const G1);

    pub unsafe fn mclBnGT_isEqual(lhs: *const GT, rhs: *const GT) -> i32;
}
