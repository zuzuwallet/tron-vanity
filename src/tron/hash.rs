// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keccak-256 and the Base58Check checksum.
//!
//! TRON hashes the 64-byte public key with Keccak-256 (domain byte `0x01`),
//! the same hash Ethereum uses. NIST SHA3-256 uses domain byte `0x06` and is
//! a different function. This module's Keccak implementation is `tiny-keccak`
//! with only the `keccak` feature. SHA3-256 below is the `sha3` crate and
//! exists so a mix-up fails the tests.
//!
//! The checksum is the first 4 bytes of SHA-256(SHA-256(payload)), from `sha2`.

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn checksum4(payload: &[u8]) -> [u8; 4] {
    let second = sha256(&sha256(payload));
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

/// NIST SHA3-256. This is not the TRON address hash.
pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    let digest = sha3::Sha3_256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::{keccak256, sha256, sha3_256};

    #[test]
    fn sha256_of_empty_is_the_nist_vector() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn keccak256_of_empty_and_abc_are_not_sha3() {
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(
            hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_ne!(keccak256(b""), sha3_256(b""));
        assert_ne!(keccak256(b"abc"), sha3_256(b"abc"));
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
