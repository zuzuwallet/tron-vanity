//! Mainnet account-address derivation.
//!
//! The search path is libsecp256k1, `tiny-keccak`, `sha2`, and this crate's
//! Base58Check. The independent check uses `bitcoin_hashes` and `bs58` instead.

mod base58;
pub(crate) mod hash;
mod hexkey;
mod keys;
mod prefix;
mod uint;

pub use hexkey::{decode_hex_key, encode_hex_key};
pub(crate) use keys::{account_id_from_uncompressed, encode_payload};
pub use keys::{address_from_id, KeyEngine, ADDRESS_TEXT_LEN, PAYLOAD_LEN};
pub(crate) use prefix::SEARCH_COUNTER_HEADROOM;
pub use prefix::{
    group_digits, median_attempts, validate_prefix, PrefixEstimate, CONFIRMATION_THRESHOLD,
    MAX_PREFIX_LEN,
};
