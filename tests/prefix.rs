// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use tron_vanity::{validate_prefix, Error};

#[test]
fn thzzz_is_the_documented_interior_target() {
    let estimate = validate_prefix("THZZZ").unwrap();
    assert_eq!(estimate.as_str(), "THZZZ");
    assert_eq!(estimate.vanity_portion(), "HZZZ");
    assert_eq!(estimate.expected, 4_553_521);
    assert_eq!(estimate.median, 3_156_260);
    assert_eq!(estimate.per_character_approximation(), "58^4 = 11,316,496");
}

#[test]
fn tzuzu_is_outside_the_mainnet_range() {
    let err = validate_prefix("TZuZu").unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR"),
        "{text}"
    );
    assert!(
        text.contains("TZJozAg1ruapycCicgz31GxvYJ1FvTVysk"),
        "{text}"
    );
}

#[test]
fn rejected_prefixes_explain_themselves() {
    let cases = [
        ("ZuZu", "start with T"),
        ("tZuZu", "start with T"),
        ("T0", "Base58"),
        ("Tz", "9ABCDEFGHJKLMNPQRSTUVWXYZ"),
        ("TZZ", "TZJozA"),
        ("THZZZTHZZZTHZZZTHZZZTHZZZTHZZZTHZZZ", "34-character"),
    ];
    for (prefix, needle) in cases {
        let err = validate_prefix(prefix).unwrap_err();
        assert!(matches!(err, Error::Prefix(_)), "{prefix}: {err}");
        assert!(err.to_string().contains(needle), "{prefix}: {err}");
    }
}
