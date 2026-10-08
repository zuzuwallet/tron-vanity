// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prefix checks for mainnet account addresses.
//!
//! Every such address is the Base58Check encoding of a 25-byte payload:
//! `[0x41] || account id || checksum`. That payload is an integer in
//! `[0x41 << 192, 0x41 << 192 + 2^192)`. Both ends encode to 34 characters.
//! The only character shared by the whole interval is `T`.
//!
//! The second character is not uniform. Only 25 Base58 symbols occur there,
//! `9` through `Z` in alphabet order. `9` and `Z` are partial. A requested
//! prefix is converted to the same integer interval, intersected with the
//! version-byte interval, and compared as 25-byte big-endian bounds. The
//! checksum stays inside those bounds. Base58 text is produced only after a
//! payload lands in the interval, and the text must still start with the prefix.
//!
//! `expected` is `round(2^192 / overlap)` under a model that treats every
//! 25-byte payload with the version prefix as equally likely, which is the
//! same as treating the 20-byte id as uniform and the checksum as an
//! independent 32-bit field. It is not a proof that Keccak-256 is uniform,
//! and it is not a promise of wall-clock time.

use crate::error::Error;
use crate::tron::base58::{alphabet_index, base58_decode};
use crate::tron::keys::{ADDRESS_PREFIX, ADDRESS_TEXT_LEN, PAYLOAD_LEN};
use crate::tron::uint::U256;

pub(crate) const SEARCH_COUNTER_HEADROOM: u64 = 1_048_576;
pub const CONFIRMATION_THRESHOLD: u64 = 1_000_000_000;
pub const MAX_PREFIX_LEN: usize = ADDRESS_TEXT_LEN;

const ERR_EMPTY: &str = "prefix is empty";
const ERR_T: &str = "this mode generates mainnet account addresses, which start with T";
const ERR_ALPHABET: &str = "prefix uses a character outside Base58 (0, O, I, and l are excluded)";
const ERR_SECOND: &str = "no mainnet address has this prefix; the second character can only be 9ABCDEFGHJKLMNPQRSTUVWXYZ";
const ERR_IMPOSSIBLE: &str = "no mainnet address has this prefix; account addresses run from T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR through TZJozAg1ruapycCicgz31GxvYJ1FvTVysk, and a prefix beginning with TZ only continues through TZJozA";
const ERR_LONG: &str = "prefix is longer than a 34-character account address";
const ERR_RANGE: &str = "prefix is too rare for the attempt counter";
const ERR_FULL: &str =
    "a full 34-character address is one key out of 2^160 and does not fit the attempt counter";

/// Second characters that occur in the version-byte interval.
const LEGAL_SECOND: &[u8] = b"9ABCDEFGHJKLMNPQRSTUVWXYZ";

/// A prefix that can occur, plus the inclusive 25-byte payload bounds.
#[derive(Clone, PartialEq, Eq)]
pub struct PrefixEstimate {
    prefix: String,
    pub expected: u64,
    pub median: u64,
    low: [u8; PAYLOAD_LEN],
    high: [u8; PAYLOAD_LEN],
}

impl PrefixEstimate {
    pub fn as_str(&self) -> &str {
        &self.prefix
    }

    /// Characters after the fixed leading `T`.
    pub fn vanity_portion(&self) -> &str {
        self.prefix.strip_prefix('T').unwrap_or("")
    }

    pub fn display_vanity(&self) -> &str {
        let vanity = self.vanity_portion();
        if vanity.is_empty() {
            "(none)"
        } else {
            vanity
        }
    }

    /// `58^(vanity length)`, labeled by the caller as an approximation.
    pub fn per_character_approximation(&self) -> String {
        let width = self.vanity_portion().len();
        format!("58^{width} = {}", group_digits(&pow58_decimal(width)))
    }

    pub fn needs_large_search_confirmation(&self) -> bool {
        self.expected >= CONFIRMATION_THRESHOLD
    }

    /// Inclusive bounds. Fixed width makes byte order the same as integer order.
    pub fn contains_payload(&self, payload: &[u8; PAYLOAD_LEN]) -> bool {
        payload.as_slice() >= self.low.as_slice() && payload.as_slice() <= self.high.as_slice()
    }

    pub fn display_attempts(&self) -> String {
        group_digits(&self.expected.to_string())
    }

    pub fn display_median(&self) -> String {
        group_digits(&self.median.to_string())
    }
}

impl std::fmt::Debug for PrefixEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixEstimate")
            .field("prefix", &self.prefix)
            .field("expected", &self.expected)
            .field("median", &self.median)
            .finish()
    }
}

pub fn validate_prefix(prefix: &str) -> Result<PrefixEstimate, Error> {
    if prefix.is_empty() {
        return Err(Error::Prefix(ERR_EMPTY));
    }
    if prefix.len() > MAX_PREFIX_LEN {
        return Err(Error::Prefix(ERR_LONG));
    }
    if prefix.bytes().any(|byte| alphabet_index(byte).is_none()) {
        return Err(Error::Prefix(ERR_ALPHABET));
    }
    if !prefix.starts_with('T') {
        return Err(Error::Prefix(ERR_T));
    }
    if prefix.len() >= 2 && !LEGAL_SECOND.contains(&prefix.as_bytes()[1]) {
        return Err(Error::Prefix(ERR_SECOND));
    }
    if prefix.len() == ADDRESS_TEXT_LEN {
        return reject_full_address(prefix);
    }

    let (text_low, text_high) = prefix_integer_span(prefix)?;
    let (version_low, version_high) = version_bounds();
    let low = text_low.max(version_low);
    let high = text_high.min(version_high);
    if low > high {
        return Err(Error::Prefix(ERR_IMPOSSIBLE));
    }
    let overlap = high
        .sub(low)
        .checked_add(U256::ONE)
        .ok_or(Error::Prefix(ERR_RANGE))?;
    let expected = U256::pow2(192)
        .div_round_u64(overlap)
        .ok_or(Error::Prefix(ERR_RANGE))?;
    if expected == 0 || expected > u64::MAX - SEARCH_COUNTER_HEADROOM {
        return Err(Error::Prefix(ERR_RANGE));
    }
    let low_bytes = low
        .to_payload_bytes()
        .ok_or(Error::Prefix(ERR_IMPOSSIBLE))?;
    let high_bytes = high
        .to_payload_bytes()
        .ok_or(Error::Prefix(ERR_IMPOSSIBLE))?;
    Ok(PrefixEstimate {
        prefix: prefix.to_owned(),
        expected,
        median: median_attempts(expected),
        low: low_bytes,
        high: high_bytes,
    })
}

/// `ln(2) * expected`, rounded to the nearest integer.
///
/// Values through `2^63` are exact in `f64` well enough for the displayed
/// median. The product is not an exact rational.
pub fn median_attempts(expected: u64) -> u64 {
    if expected <= 1 {
        return expected;
    }
    let median = (expected as f64) * std::f64::consts::LN_2;
    median.round() as u64
}

pub fn group_digits(digits: &str) -> String {
    if digits.is_empty() {
        return String::new();
    }
    if digits.len() > 15 {
        let exponent = digits.len() - 1;
        let mut mantissa = String::new();
        mantissa.push(digits.as_bytes()[0] as char);
        mantissa.push('.');
        let fraction: String = digits.chars().skip(1).take(3).collect();
        mantissa.push_str(&fraction);
        return format!("{mantissa}e{exponent}");
    }
    let mut grouped = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped.chars().rev().collect()
}

fn pow58_decimal(exp: usize) -> String {
    let mut digits = vec![1u8];
    for _ in 0..exp {
        let mut carry = 0u16;
        for digit in &mut digits {
            let acc = u16::from(*digit) * 58 + carry;
            *digit = (acc % 10) as u8;
            carry = acc / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits
        .iter()
        .rev()
        .map(|digit| (b'0' + digit) as char)
        .collect()
}

fn reject_full_address(prefix: &str) -> Result<PrefixEstimate, Error> {
    let payload = crate::tron::base58::base58check_decode(prefix)
        .map_err(|_| Error::Prefix(ERR_IMPOSSIBLE))?;
    if payload.len() == 21 && payload[0] == ADDRESS_PREFIX {
        Err(Error::Prefix(ERR_FULL))
    } else {
        Err(Error::Prefix(ERR_IMPOSSIBLE))
    }
}

fn prefix_integer_span(prefix: &str) -> Result<(U256, U256), Error> {
    let pad = ADDRESS_TEXT_LEN - prefix.len();
    let mut low_text = String::with_capacity(ADDRESS_TEXT_LEN);
    let mut high_text = String::with_capacity(ADDRESS_TEXT_LEN);
    low_text.push_str(prefix);
    high_text.push_str(prefix);
    low_text.extend(std::iter::repeat_n('1', pad));
    high_text.extend(std::iter::repeat_n('z', pad));
    let low = decode_u256(&low_text)?;
    let high = decode_u256(&high_text)?;
    if low > high {
        return Err(Error::Prefix(ERR_IMPOSSIBLE));
    }
    Ok((low, high))
}

fn version_bounds() -> (U256, U256) {
    let low = U256::from_be_bytes(&[ADDRESS_PREFIX])
        .expect("prefix byte fits")
        .shl(192)
        .expect("version prefix fits in 256 bits");
    let high = low
        .checked_add(U256::pow2(192))
        .expect("version max fits")
        .sub(U256::ONE);
    (low, high)
}

fn decode_u256(text: &str) -> Result<U256, Error> {
    let bytes = base58_decode(text).map_err(|_| Error::Prefix(ERR_IMPOSSIBLE))?;
    U256::from_be_bytes(bytes.as_slice()).ok_or(Error::Prefix(ERR_IMPOSSIBLE))
}

#[cfg(test)]
mod tests {
    use super::{
        group_digits, median_attempts, pow58_decimal, validate_prefix, version_bounds,
        ERR_ALPHABET, ERR_FULL, ERR_IMPOSSIBLE, ERR_LONG, ERR_RANGE, ERR_SECOND, ERR_T,
        LEGAL_SECOND,
    };
    use crate::error::Error;
    use crate::tron::base58::{base58_encode, ALPHABET};
    use crate::tron::keys::{address_from_id, KeyEngine, ADDRESS_TEXT_LEN};
    use crate::tron::uint::U256;

    const VERSION_TEXT_MIN: &str = "T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR";
    const VERSION_TEXT_MAX: &str = "TZJozAg1ruapycCicgz31GxvYJ1FvTVysk";

    #[test]
    fn version_text_covers_exactly_t() {
        let (low, high) = version_bounds();
        let low_text = base58_encode(&low.to_payload_bytes().unwrap());
        let high_text = base58_encode(&high.to_payload_bytes().unwrap());
        assert_eq!(low_text, VERSION_TEXT_MIN);
        assert_eq!(high_text, VERSION_TEXT_MAX);
        assert_eq!(low_text.len(), ADDRESS_TEXT_LEN);
        assert_eq!(high_text.len(), ADDRESS_TEXT_LEN);
        assert!(low_text.starts_with("T9"));
        assert!(high_text.starts_with("TZJ"));
        assert_eq!(high.sub(low).checked_add(U256::ONE), Some(U256::pow2(192)));
    }

    #[test]
    fn thzzz_uses_the_version_range_not_58_to_the_4() {
        let estimate = validate_prefix("THZZZ").unwrap();
        assert_eq!(estimate.vanity_portion(), "HZZZ");
        assert_eq!(estimate.display_vanity(), "HZZZ");
        assert_eq!(estimate.expected, 4_553_521);
        assert_eq!(estimate.median, 3_156_260);
        assert_eq!(estimate.display_attempts(), "4,553,521");
        assert_eq!(estimate.display_median(), "3,156,260");
        assert_eq!(estimate.per_character_approximation(), "58^4 = 11,316,496");
        assert_ne!(estimate.expected, 11_316_496);
        assert!(!estimate.needs_large_search_confirmation());
        assert_eq!(median_attempts(4_553_521), 3_156_260);
        assert_eq!(pow58_decimal(0), "1");
        assert_eq!(pow58_decimal(1), "58");
        assert_eq!(pow58_decimal(4), "11316496");
    }

    #[test]
    fn shorter_interior_prefixes_match_the_same_model() {
        assert_eq!(validate_prefix("T").unwrap().expected, 1);
        assert_eq!(validate_prefix("T").unwrap().display_vanity(), "(none)");
        assert_eq!(
            validate_prefix("T").unwrap().per_character_approximation(),
            "58^0 = 1"
        );
        assert_eq!(validate_prefix("TH").unwrap().expected, 23);
        assert_eq!(validate_prefix("TH").unwrap().median, 16);
        assert_eq!(validate_prefix("THZ").unwrap().expected, 1_354);
        assert_eq!(validate_prefix("THZZ").unwrap().expected, 78_509);
        let edge_low = validate_prefix("T9").unwrap();
        let edge_high = validate_prefix("TZ").unwrap();
        assert_ne!(edge_low.expected, 23);
        assert_ne!(edge_high.expected, 23);
        assert!(edge_high.expected > validate_prefix("TH").unwrap().expected);
        assert!(validate_prefix("TZJ").is_ok());
        assert_eq!(
            validate_prefix("TZK").unwrap_err(),
            Error::Prefix(ERR_IMPOSSIBLE)
        );
        assert_eq!(
            validate_prefix("TZZ").unwrap_err(),
            Error::Prefix(ERR_IMPOSSIBLE)
        );
        assert_eq!(
            validate_prefix("TZuZu").unwrap_err(),
            Error::Prefix(ERR_IMPOSSIBLE)
        );
        assert!(validate_prefix("TZuZu")
            .unwrap_err()
            .to_string()
            .contains(VERSION_TEXT_MAX));
    }

    #[test]
    fn fixed_t_prefix_matches_every_address() {
        let estimate = validate_prefix("T").unwrap();
        assert_eq!(estimate.expected, 1);
        assert_eq!(estimate.median, 1);
        assert!(!estimate.needs_large_search_confirmation());
    }

    #[test]
    fn edge_and_interior_lengths_match_the_counter_limit() {
        let interior = validate_prefix("THVVVVVVVVVV").unwrap();
        assert_eq!(interior.expected, 10_054_102_514_374_869_639);
        assert!(interior.expected <= u64::MAX - super::SEARCH_COUNTER_HEADROOM);
        assert!(interior.needs_large_search_confirmation());
        assert_eq!(
            validate_prefix("THVVVVVVVVVVV").unwrap_err(),
            Error::Prefix(ERR_RANGE)
        );
    }

    #[test]
    fn second_character_acceptance_matches_the_version_interval() {
        for byte in ALPHABET {
            let prefix = format!("T{}", *byte as char);
            let result = validate_prefix(&prefix);
            if LEGAL_SECOND.contains(byte) {
                assert!(result.is_ok(), "{}", *byte as char);
            } else {
                assert_eq!(result.unwrap_err(), Error::Prefix(ERR_SECOND));
            }
        }
    }

    #[test]
    fn impossible_prefixes_name_the_reason() {
        assert_eq!(
            validate_prefix("").unwrap_err(),
            Error::Prefix(super::ERR_EMPTY)
        );
        assert_eq!(validate_prefix("ZuZu").unwrap_err(), Error::Prefix(ERR_T));
        assert_eq!(validate_prefix("tZuZu").unwrap_err(), Error::Prefix(ERR_T));
        assert_eq!(
            validate_prefix("Tz").unwrap_err(),
            Error::Prefix(ERR_SECOND)
        );
        assert_eq!(
            validate_prefix("T0").unwrap_err(),
            Error::Prefix(ERR_ALPHABET)
        );
        assert_eq!(
            validate_prefix("THZZZ0").unwrap_err(),
            Error::Prefix(ERR_ALPHABET)
        );
        assert_eq!(
            validate_prefix(&"T".repeat(40)).unwrap_err(),
            Error::Prefix(ERR_LONG)
        );
    }

    #[test]
    fn generator_prefixes_agree_with_base58_text() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let candidate = KeyEngine::new().unwrap().candidate(&key).unwrap();
        let address = address_from_id(&candidate.account_id);
        assert_eq!(address, "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC");
        for length in 1..=12 {
            let estimate = validate_prefix(&address[..length]).unwrap();
            assert!(
                estimate.contains_payload(&candidate.payload),
                "length {length}"
            );
            assert!(address.starts_with(estimate.as_str()));
        }
        assert_eq!(
            validate_prefix(&address[..13]).unwrap_err(),
            Error::Prefix(ERR_RANGE)
        );
        assert_eq!(
            validate_prefix(&address).unwrap_err(),
            Error::Prefix(ERR_FULL)
        );
        let mut damaged = address.clone();
        damaged.pop();
        damaged.push('t');
        assert_eq!(
            validate_prefix(&damaged).unwrap_err(),
            Error::Prefix(ERR_IMPOSSIBLE)
        );
        let other = validate_prefix("THZZZ").unwrap();
        assert!(!other.contains_payload(&candidate.payload));
        assert!(!address.starts_with(other.as_str()));
    }

    #[test]
    fn grouped_digits_stop_at_fifteen() {
        assert_eq!(group_digits("4553521"), "4,553,521");
        assert_eq!(group_digits("10054102514374869639"), "1.005e19");
    }
}
