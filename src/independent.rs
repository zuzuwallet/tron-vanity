//! Independent account-address derivation.
//!
//! `k256` derives the uncompressed secp256k1 point. `sha3::Keccak256` hashes
//! the 64-byte X||Y. `bitcoin_hashes` computes the double SHA-256 checksum.
//! `bs58` encodes the 25-byte payload and does not hash it. None of those
//! steps call this crate's Base58Check, `tiny-keccak`, `sha2`, or libsecp256k1.
//!
//! `k256::SecretKey` is `elliptic_curve::SecretKey<Secp256k1>`. k256 0.13 has
//! no `zeroize` Cargo feature. The type still implements `ZeroizeOnDrop`, and
//! its `Drop` zeroizes the scalar. It is not `Copy`. An explicit `drop` runs
//! after the public bytes are copied. Compiler, register, and internal
//! temporary copies can remain. The caller's `SecretBytes` is the buffer this
//! crate wipes.

use bitcoin_hashes::sha256;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256};

use crate::error::Error;
use crate::tron::ADDRESS_TEXT_LEN;

/// Uncompressed SEC1 public key from `k256`.
pub fn k256_uncompressed(key: &[u8; 32]) -> Result<[u8; 65], Error> {
    let secret = k256::SecretKey::from_slice(key).map_err(|_| Error::VerificationFailed)?;
    let point = secret.public_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        drop(secret);
        return Err(Error::VerificationFailed);
    }
    let mut public_key = [0u8; 65];
    public_key.copy_from_slice(bytes);
    drop(secret);
    Ok(public_key)
}

/// Last 20 bytes of Keccak-256 from `sha3`, not SHA3-256.
pub fn keccak_last20(data: &[u8]) -> [u8; 20] {
    let digest = Keccak256::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

/// SHA-256 from `bitcoin_hashes`, not from `sha2`.
pub fn bitcoin_sha256(data: &[u8]) -> [u8; 32] {
    *sha256::Hash::hash(data).as_byte_array()
}

/// First 4 bytes of SHA-256(SHA-256(body)), from `bitcoin_hashes`.
fn checksum4(body: &[u8]) -> [u8; 4] {
    let first = bitcoin_sha256(body);
    let second = bitcoin_sha256(&first);
    let mut out = [0u8; 4];
    out.copy_from_slice(&second[..4]);
    out
}

/// Mainnet account text. `bs58` only encodes; it does not compute the checksum.
pub fn reference_base58(id: &[u8; 20]) -> Result<String, Error> {
    let mut payload = [0u8; 25];
    payload[0] = 0x41;
    payload[1..21].copy_from_slice(id);
    let sum = checksum4(&payload[..21]);
    payload[21..].copy_from_slice(&sum);
    let text = bs58::encode(payload).into_string();
    if text.len() != ADDRESS_TEXT_LEN || !text.starts_with('T') {
        return Err(Error::VerificationFailed);
    }
    Ok(text)
}

/// Public key, account id, and address, all from the independent stack.
pub fn independent_address(key: &[u8; 32]) -> Result<([u8; 65], [u8; 20], String), Error> {
    let public_key = k256_uncompressed(key)?;
    let id = keccak_last20(&public_key[1..]);
    let address = reference_base58(&id)?;
    Ok((public_key, id, address))
}

/// Account id and address from a published uncompressed public key.
pub fn independent_from_uncompressed(public_key: &[u8; 65]) -> Result<([u8; 20], String), Error> {
    if public_key[0] != 0x04 {
        return Err(Error::VerificationFailed);
    }
    let id = keccak_last20(&public_key[1..]);
    let address = reference_base58(&id)?;
    Ok((id, address))
}
