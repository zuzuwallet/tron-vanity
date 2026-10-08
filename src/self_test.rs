//! Known-answer tests. A failure aborts before any search or wallet write.
//!
//! Vectors:
//! - Keccak-256("") and Keccak-256("abc"), and SHA3-256("") as a negative check
//! - SEC 1 generator, private key 1, uncompressed public key
//! - the Ethereum address of that key, which the TRON Developer Hub identifies
//!   as the 20 bytes after `0x41`
//! - the Base58Check form of that address, accepted only when libsecp256k1 /
//!   tiny-keccak / `sha2` and `k256` / `sha3::Keccak256` / `bitcoin_hashes` / `bs58` agree
//! - the TronWeb createAccount example's published uncompressed public key
//!   and address. The current page redacts the scalar, so this check does not
//!   use a private key
//! - Developer Hub hex `418840E6C55B9ADA326D211D818C34A994AECED808` and
//!   `TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL`
//!
//! `TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC` was not printed by java-tron. It is
//! private key 1 under the protocol rules, locked only when both stacks agree.

use crate::error::Error;
use crate::independent::{
    bitcoin_sha256, independent_address, independent_from_uncompressed, reference_base58,
};
use crate::tron::hash::{keccak256, sha3_256};
use crate::tron::{account_id_from_uncompressed, address_from_id, validate_prefix, KeyEngine};
use crate::verify::confirm_match;

const GENERATOR_PUBKEY: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const GENERATOR_ID: &str = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";
const GENERATOR_ADDRESS: &str = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";
const HASH_WITH_04: &str = "7d6e99bb8abf8cc013bb0e912d0b176596fe7b88";
const SHA3_ID: &str = "0502987e630ea7ebb2bf1d84a65a727109385bcf";

const TRONWEB_PUBKEY: &str = "04FFFA899E5EAEB8DB1AA583A96D598DDBAB6DDC0D24B4FD8948E740D7D8E828AC8F177D3937960DE6E2567CECD7E899130DA921EA3B90F0A8FEF24E9D1670A0C1";
const TRONWEB_ID: &str = "edc66496a39744fea631a598cbae4b7d6a728aa7";
const TRONWEB_ADDRESS: &str = "TXeSp72o5r185cmeGxFDkdCZFdJS1TAyHw";

const DOCS_BODY: &str = "418840E6C55B9ADA326D211D818C34A994AECED808";
const DOCS_ADDRESS: &str = "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL";

pub fn run_self_tests() -> Result<(), Error> {
    check_hashes()?;
    check_generator()?;
    check_tronweb_pubkey()?;
    check_docs_pair()?;
    check_prefix_targets()?;
    Ok(())
}

fn check_hashes() -> Result<(), Error> {
    if hex(&keccak256(b"")) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
        return Err(Error::SelfTest("Keccak-256 empty-string vector mismatch"));
    }
    if hex(&keccak256(b"abc")) != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    {
        return Err(Error::SelfTest("Keccak-256 abc vector mismatch"));
    }
    if hex(&sha3_256(b"")) != "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" {
        return Err(Error::SelfTest("SHA3-256 empty-string vector mismatch"));
    }
    if keccak256(b"") == sha3_256(b"") {
        return Err(Error::SelfTest("Keccak-256 and SHA3-256 were the same"));
    }
    // FIPS 180-4 empty-string digest. Compared with the constant, not with `sha2`.
    if hex(&bitcoin_sha256(b""))
        != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    {
        return Err(Error::SelfTest(
            "independent SHA-256 empty-string vector mismatch",
        ));
    }
    Ok(())
}

fn randomized_engine() -> Result<KeyEngine, Error> {
    KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize the libsecp256k1 context"))
}

fn check_generator() -> Result<(), Error> {
    let mut key = [0u8; 32];
    key[31] = 1;
    let candidate = randomized_engine()?
        .candidate(&key)
        .map_err(|_| Error::SelfTest("generator scalar was rejected"))?;
    if hex(&candidate.public_key) != GENERATOR_PUBKEY {
        return Err(Error::SelfTest("generator public key mismatch"));
    }
    if hex(&candidate.account_id) != GENERATOR_ID {
        return Err(Error::SelfTest("generator account id mismatch"));
    }
    let with_prefix = {
        let mut id = [0u8; 20];
        id.copy_from_slice(&keccak256(&candidate.public_key)[12..]);
        id
    };
    if hex(&with_prefix) != HASH_WITH_04 || with_prefix == candidate.account_id {
        return Err(Error::SelfTest(
            "hashing the 0x04 prefix did not change the account id",
        ));
    }
    let sha3_id = {
        let mut id = [0u8; 20];
        id.copy_from_slice(&sha3_256(&candidate.public_key[1..])[12..]);
        id
    };
    if hex(&sha3_id) != SHA3_ID || sha3_id == candidate.account_id {
        return Err(Error::SelfTest("SHA3-256 did not disagree with Keccak-256"));
    }
    let address = address_from_id(&candidate.account_id);
    if address != GENERATOR_ADDRESS {
        return Err(Error::SelfTest("generator address mismatch"));
    }
    let (public_key, id, independent) = independent_address(&key)?;
    if public_key != candidate.public_key || id != candidate.account_id || independent != address {
        return Err(Error::SelfTest(
            "independent stack disagreed on private key 1",
        ));
    }
    confirm_match(&key, GENERATOR_ADDRESS)?;
    Ok(())
}

fn check_tronweb_pubkey() -> Result<(), Error> {
    let public_key = parse_hex65(TRONWEB_PUBKEY)?;
    let id = account_id_from_uncompressed(&public_key)
        .map_err(|_| Error::SelfTest("TronWeb public key was rejected"))?;
    if hex(&id) != TRONWEB_ID {
        return Err(Error::SelfTest("TronWeb account id mismatch"));
    }
    if address_from_id(&id) != TRONWEB_ADDRESS {
        return Err(Error::SelfTest("TronWeb address mismatch"));
    }
    let (independent_id, independent) = independent_from_uncompressed(&public_key)?;
    if independent_id != id || independent != TRONWEB_ADDRESS {
        return Err(Error::SelfTest(
            "independent stack disagreed on the TronWeb public key",
        ));
    }
    Ok(())
}

fn check_docs_pair() -> Result<(), Error> {
    let body = parse_hex(DOCS_BODY)?;
    if body.len() != 21 || body[0] != 0x41 {
        return Err(Error::SelfTest(
            "documented address body has the wrong shape",
        ));
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(&body[1..]);
    if address_from_id(&id) != DOCS_ADDRESS {
        return Err(Error::SelfTest("documented Base58Check mismatch"));
    }
    if reference_base58(&id)? != DOCS_ADDRESS {
        return Err(Error::SelfTest(
            "independent Base58Check disagreed on the documented address",
        ));
    }
    Ok(())
}

fn check_prefix_targets() -> Result<(), Error> {
    let estimate = validate_prefix("THZZZ")?;
    if estimate.expected != 4_553_521 || estimate.median != 3_156_260 {
        return Err(Error::SelfTest("THZZZ difficulty changed"));
    }
    if estimate.vanity_portion() != "HZZZ" {
        return Err(Error::SelfTest("THZZZ vanity portion changed"));
    }
    for prefix in ["TZuZu", "ZuZu", "tZuZu", "T0", "Tz", "TZZ"] {
        if validate_prefix(prefix).is_ok() {
            return Err(Error::SelfTest("an impossible prefix was accepted"));
        }
    }
    Ok(())
}

fn parse_hex65(text: &str) -> Result<[u8; 65], Error> {
    let bytes = parse_hex(text)?;
    bytes
        .try_into()
        .map_err(|_| Error::SelfTest("public key vector has the wrong length"))
}

fn parse_hex(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::SelfTest("hex vector has an odd length"));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .map_err(|_| Error::SelfTest("hex vector is not hexadecimal"))
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::run_self_tests;

    #[test]
    fn known_answers_pass() {
        run_self_tests().unwrap();
    }
}
