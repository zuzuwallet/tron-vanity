//! Checks that agree before a wallet is treated as valid.
//!
//! The independent path starts from the raw scalar. `k256` derives the
//! uncompressed public key, `sha3::Keccak256` hashes it, `bitcoin_hashes`
//! checksums it, and `bs58` encodes the 25-byte payload. A mismatch is fatal.
//! This function does not print
//! the key.
//!
//! A failure to seed the libsecp256k1 context is `Error::Rng`. It is not
//! reported as a fatal wallet mismatch.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::error::Error;
use crate::independent::independent_address;
use crate::tron::{encode_payload, KeyEngine};

/// Require this crate and the independent stack to agree on `address`.
pub fn confirm_match(key: &[u8; 32], address: &str) -> Result<(), Error> {
    let outcome = catch_unwind(AssertUnwindSafe(|| confirm_match_inner(key, address)));
    match outcome {
        Ok(result) => result,
        Err(_) => Err(Error::VerificationFailed),
    }
}

fn confirm_match_inner(key: &[u8; 32], address: &str) -> Result<(), Error> {
    let engine = KeyEngine::new()?;
    let candidate = engine
        .candidate(key)
        .map_err(|_| Error::VerificationFailed)?;
    let ours = encode_payload(&candidate.payload);
    if ours != address {
        return Err(Error::VerificationFailed);
    }
    let (public_key, id, independent) = independent_address(key)?;
    if public_key != candidate.public_key
        || id != candidate.account_id
        || independent != address
        || independent != ours
    {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}
