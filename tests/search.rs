// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tron_vanity::{
    confirm_match, counter_would_overflow, search, Error, COUNTER_HEADROOM, MAX_THREADS,
};

#[test]
fn counter_saturates_before_wrapping() {
    assert!(!counter_would_overflow(0));
    assert!(!counter_would_overflow(u64::MAX - COUNTER_HEADROOM - 1));
    assert!(counter_would_overflow(u64::MAX - COUNTER_HEADROOM));
    assert!(counter_would_overflow(u64::MAX));
    assert_eq!(MAX_THREADS, 256);
}

#[test]
fn preset_cancel_does_no_work() {
    let cancel = Arc::new(AtomicBool::new(true));
    let err = search("T", 4, cancel, |_, _| {}).unwrap_err();
    match err {
        Error::Cancelled { attempts } => assert_eq!(attempts, 0),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn prefix_t_stops_every_worker() {
    let cancel = Arc::new(AtomicBool::new(false));
    let hit = search("T", 4, Arc::clone(&cancel), |_, _| {}).unwrap();
    assert!(hit.address.starts_with('T'));
    assert_eq!(hit.address.len(), 34);
    assert!(hit.attempts > 0);
    assert!(hit.attempts < 10_000);
    assert!(cancel.load(Ordering::Acquire));
    let rendered = format!("{hit:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("Private key:"));
    confirm_match(hit.key.as_bytes(), &hit.address).unwrap();
}

#[test]
fn cancel_during_thzzz_returns_cancelled() {
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancel);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        flag.store(true, Ordering::Release);
    });
    let err = search("THZZZ", 2, cancel, |_, _| {}).unwrap_err();
    match err {
        Error::Cancelled { attempts } => assert!(attempts < 1_000_000),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn thread_count_is_checked() {
    let cancel = Arc::new(AtomicBool::new(false));
    assert_eq!(
        search("T", 0, Arc::clone(&cancel), |_, _| {}).unwrap_err(),
        Error::Threads
    );
    assert_eq!(
        search("T", MAX_THREADS + 1, cancel, |_, _| {}).unwrap_err(),
        Error::Threads
    );
}
