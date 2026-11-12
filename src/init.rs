use std::sync::Once;

use crate::bls_api::blsInit;
use crate::constants::MCLBN_COMPILED_TIME_VAR;

enum CurveType {
    BLS12_381 = 5,
}

// Used to call blsInit only once.
pub static INIT: Once = Once::new();

/// Initialises the C library for BLS12-381.
///
/// # Panics
/// Panics if `blsInit` fails, which means the bundled static library does not
/// match this crate. Continuing would run every later call on an uninitialised
/// curve. The panic poisons `INIT`, so every later call panics as well.
pub fn init_library() {
    if let Err(code) = init(CurveType::BLS12_381) {
        panic!(
            "BLS12-381 initialisation failed: blsInit returned {code}; \
             the bundled static library does not match this crate"
        );
    }
}

fn init(curve_type: CurveType) -> Result<(), i32> {
    match unsafe { blsInit(curve_type as usize, MCLBN_COMPILED_TIME_VAR) } {
        0 => Ok(()),
        code => Err(code),
    }
}
