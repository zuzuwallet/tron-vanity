//! Uncompressed secp256k1 keys and mainnet account payloads.
//!
//! The search uses libsecp256k1. `k256` is only used by the independent check.
//! `SecretKey::from_slice` rejects 0 and scalars at or above the curve order.
//! This crate does not reduce a candidate modulo the order.
//!
//! The 21-byte account address is `0x41` followed by the last 20 bytes of
//! Keccak-256 of the 64-byte `X||Y`. java-tron `sha3omit12` copies Keccak
//! bytes `[11..32)` and overwrites byte 0 with `0x41`, which leaves
//! `hash[12..32]`. Hashing the 65-byte form, or using SHA3-256, is rejected
//! by the tests. The Developer Hub states that those 20 bytes are the
//! Ethereum address of the same public key.

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::tron::base58::base58check_encode;
use crate::tron::hash::{checksum4, keccak256};

/// Mainnet, Shasta, and Nile address prefix. The legacy `0xa0` byte is not used.
pub const ADDRESS_PREFIX: u8 = 0x41;
pub const ADDRESS_TEXT_LEN: usize = 34;
pub const PAYLOAD_LEN: usize = 25;
pub(crate) const BODY_LEN: usize = 21;
pub(crate) const HASH_LEN: usize = 20;

/// One worker's libsecp256k1 context.
///
/// The `rand` feature stays off. `new` draws 32 bytes from `getrandom` and
/// passes them to `seeded_randomize`. That is libsecp256k1's recommended
/// blinding for secret-key operations, including public-key generation. The
/// seed buffer is wiped after the call. The context keeps the blinding state.
/// The context is not re-seeded per candidate.
pub struct KeyEngine {
    secp: Secp256k1<secp256k1::SignOnly>,
}

/// Borrows the one `SecretKey` and overwrites it on drop.
///
/// `SecretKey` is `Copy`, so a wrapper that owned another `SecretKey` would
/// copy the scalar and leave the first value in place. This guard only holds
/// a reference. `non_secure_erase` writes `[1u8; 32]`, not zeros. Compiler
/// copies, registers, and copies inside public-key generation can remain.
struct EraseGuard<'a>(&'a mut SecretKey);

impl Drop for EraseGuard<'_> {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl KeyEngine {
    pub fn new() -> Result<Self, Error> {
        let mut secp = Secp256k1::signing_only();
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice()).map_err(|_| Error::Rng)?;
        secp.seeded_randomize(&seed);
        Ok(Self { secp })
    }

    pub fn candidate(&self, key: &[u8; 32]) -> Result<Candidate, Error> {
        let mut secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        let guard = EraseGuard(&mut secret);
        let public = PublicKey::from_secret_key(&self.secp, guard.0);
        drop(guard);
        let public_key = public.serialize_uncompressed();
        if public_key.len() != 65 || public_key[0] != 0x04 {
            return Err(Error::InvalidKey);
        }
        let account_id = account_id_from_xy(&public_key[1..])?;
        Ok(Candidate {
            public_key,
            account_id,
            payload: payload_from_id(&account_id),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub public_key: [u8; 65],
    pub account_id: [u8; 20],
    pub payload: [u8; PAYLOAD_LEN],
}

fn account_id_from_xy(xy: &[u8]) -> Result<[u8; HASH_LEN], Error> {
    if xy.len() != 64 {
        return Err(Error::InvalidKey);
    }
    Ok(last20(&keccak256(xy)))
}

fn last20(digest: &[u8; 32]) -> [u8; HASH_LEN] {
    let mut id = [0u8; HASH_LEN];
    id.copy_from_slice(&digest[12..]);
    id
}

pub fn payload_from_id(id: &[u8; HASH_LEN]) -> [u8; PAYLOAD_LEN] {
    let mut body = [0u8; BODY_LEN];
    body[0] = ADDRESS_PREFIX;
    body[1..].copy_from_slice(id);
    let sum = checksum4(&body);
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..BODY_LEN].copy_from_slice(&body);
    payload[BODY_LEN..].copy_from_slice(&sum);
    payload
}

pub fn encode_payload(payload: &[u8; PAYLOAD_LEN]) -> String {
    base58check_encode(&payload[..BODY_LEN])
}

/// Address text for a 20-byte account id.
pub fn address_from_id(id: &[u8; HASH_LEN]) -> String {
    encode_payload(&payload_from_id(id))
}

/// Account id from a 65-byte uncompressed key. The leading `0x04` is not hashed.
pub fn account_id_from_uncompressed(public_key: &[u8; 65]) -> Result<[u8; HASH_LEN], Error> {
    if public_key[0] != 0x04 {
        return Err(Error::InvalidKey);
    }
    account_id_from_xy(&public_key[1..])
}

#[cfg(test)]
mod tests {
    use super::{account_id_from_uncompressed, address_from_id, last20, KeyEngine, ADDRESS_PREFIX};
    use crate::tron::hash::{keccak256, sha3_256};

    #[test]
    fn prefix_byte_is_mainnet() {
        assert_eq!(ADDRESS_PREFIX, 0x41);
    }

    #[test]
    fn generator_key_matches_the_sec2_point_and_tron_address() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let candidate = KeyEngine::new().unwrap().candidate(&key).unwrap();
        assert_eq!(
            hex(&candidate.public_key),
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        assert_eq!(
            hex(&candidate.account_id),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
        assert_eq!(
            address_from_id(&candidate.account_id),
            "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"
        );
        assert_eq!(candidate.payload[0], 0x41);
        assert_eq!(&candidate.payload[1..21], candidate.account_id.as_slice());

        let digest = keccak256(&candidate.public_key[1..]);
        assert_ne!(&digest[11..31], candidate.account_id.as_slice());
        let with_prefix = last20(&keccak256(&candidate.public_key));
        assert_eq!(
            hex(&with_prefix),
            "7d6e99bb8abf8cc013bb0e912d0b176596fe7b88"
        );
        assert_ne!(with_prefix, candidate.account_id);
        let sha3_id = last20(&sha3_256(&candidate.public_key[1..]));
        assert_eq!(hex(&sha3_id), "0502987e630ea7ebb2bf1d84a65a727109385bcf");
        assert_ne!(sha3_id, candidate.account_id);
    }

    #[test]
    fn two_times_the_generator_is_the_sec2_point() {
        let mut key = [0u8; 32];
        key[31] = 2;
        let candidate = KeyEngine::new().unwrap().candidate(&key).unwrap();
        assert_eq!(
            hex(&candidate.public_key),
            "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
        );
    }

    #[test]
    fn published_tronweb_public_key_matches_the_documented_address() {
        let public_key = hex65(
            "04FFFA899E5EAEB8DB1AA583A96D598DDBAB6DDC0D24B4FD8948E740D7D8E828AC8F177D3937960DE6E2567CECD7E899130DA921EA3B90F0A8FEF24E9D1670A0C1",
        );
        let id = account_id_from_uncompressed(&public_key).unwrap();
        assert_eq!(hex(&id), "edc66496a39744fea631a598cbae4b7d6a728aa7");
        assert_eq!(address_from_id(&id), "TXeSp72o5r185cmeGxFDkdCZFdJS1TAyHw");
    }

    #[test]
    fn zero_and_the_curve_order_are_rejected() {
        let engine = KeyEngine::new().unwrap();
        assert!(engine.candidate(&[0u8; 32]).is_err());
        let order = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert!(engine.candidate(&order).is_err());
    }

    #[test]
    fn os_csprng_draws_are_32_bytes_and_differ() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        getrandom::getrandom(&mut first).unwrap();
        getrandom::getrandom(&mut second).unwrap();
        assert_ne!(first, [0u8; 32]);
        assert_ne!(first, second);
    }

    fn hex65(text: &str) -> [u8; 65] {
        hex_vec(text).try_into().unwrap()
    }

    fn hex32(text: &str) -> [u8; 32] {
        hex_vec(text).try_into().unwrap()
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

    fn hex_vec(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
