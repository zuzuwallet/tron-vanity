//! Offline TRON mainnet account vanity generator.
//!
//! This crate does not use `unsafe`. The search derives uncompressed secp256k1
//! keys with libsecp256k1 and hashes them with `tiny-keccak` (Keccak-256, not
//! SHA3-256). The independent check uses `k256`, `sha3::Keccak256`,
//! `bitcoin_hashes`, and `bs58` without its checksum feature.
//! The hand-written pieces are Base58Check and the wallet wiring.
//!
//! The result is one standalone account key. It is not a BIP-39 or BIP-44
//! wallet, and it is not a contract address.

#![forbid(unsafe_code)]

pub mod error;
mod hexutil;
pub mod independent;
pub mod search;
pub mod secret;
pub mod self_test;
pub mod tron;
pub mod verify;
pub mod wallet;

pub use error::Error;
pub use search::{counter_would_overflow, search, SearchHit, COUNTER_HEADROOM, MAX_THREADS};
pub use secret::{SecretBytes, SecretString};
pub use self_test::run_self_tests;
pub use tron::{
    address_from_id, encode_hex_key, group_digits, validate_prefix, KeyEngine, PrefixEstimate,
    CONFIRMATION_THRESHOLD, MAX_PREFIX_LEN,
};
pub use verify::confirm_match;
pub use wallet::{
    check_new_passphrase, check_passphrase, open_and_verify, write_encrypted_wallet, KdfParams,
    OpenedWallet, MIN_NEW_PASSPHRASE_CHARS,
};
