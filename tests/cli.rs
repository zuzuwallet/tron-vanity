// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::process::Command;

fn bin() -> std::path::PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_tron_vanity") {
        return std::path::PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_tron-vanity") {
        return std::path::PathBuf::from(path);
    }
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("tron-vanity");
    path
}

#[test]
fn self_test_command_passes() {
    let output = Command::new(bin()).arg("self-test").output().unwrap();
    assert!(
        output.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Cryptographic self-tests: PASS"));
    assert!(!stdout.contains("Private key:"));
}

#[test]
fn tzuzu_creates_no_wallet() {
    let dir = scratch("tzuzu");
    let output = Command::new(bin())
        .arg("generate")
        .arg("TZuZu")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TZJozAg1ruapycCicgz31GxvYJ1FvTVysk"),
        "{stderr}"
    );
    assert!(
        stderr.contains("T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR"),
        "{stderr}"
    );
    assert!(!stderr.contains("Private key:"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("FOUND"));
    assert!(!stdout.contains("Address:"));
    assert!(!stdout.contains("Cryptographic self-tests"));
    assert!(!dir.join("TZuZu-wallet.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn non_t_and_non_alphabet_prefixes_create_no_wallet() {
    let dir = scratch("reject");
    for (prefix, needle) in [("ZuZu", "start with T"), ("T0", "Base58")] {
        let output = Command::new(bin())
            .args(["generate", prefix])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{prefix}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(needle), "{prefix}: {stderr}");
        assert!(!stderr.contains("Private key:"));
        assert!(!dir.join(format!("{prefix}-wallet.json")).exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_threads_creates_no_wallet() {
    let dir = scratch("threads");
    let output = Command::new(bin())
        .args(["generate", "THZZZ", "--threads", "0"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid thread count"));
    assert!(!dir.join("THZZZ-wallet.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

fn scratch(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tron-vanity-cli-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
