//! Memory-bound regressions.
//!
//! Two bugs already shipped in this area and both were invisible to ordinary
//! functional tests:
//!
//! 1. Decrypt buffered the entire plaintext in RAM to gate publication behind
//!    the signature policy. Correct output, unbounded memory.
//! 2. The armor cap was a length check applied AFTER `read_to_end`, so the
//!    allocation it existed to prevent had already happened. It read exactly
//!    like a memory bound and was not one.
//!
//! Both are only detectable by watching resident memory, so these tests watch
//! it. They sample `/proc/PID/status` `VmHWM`, which measures the real child.
//! Do NOT use `ru_maxrss` on a fork()+exec child here: it spans the
//! pre-exec state and reports the parent's copied pages, which inflated an
//! earlier measurement of this very code by roughly 3x.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_anubis")
}

/// Peak resident set of a child, in KiB, sampled while it runs.
fn peak_kib(child: &std::process::Child) -> u64 {
    let path = format!("/proc/{}/status", child.id());
    let mut hw = 0;
    if let Ok(text) = std::fs::read_to_string(&path) {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kb: u64 = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                hw = hw.max(kb);
            }
        }
    }
    hw
}

fn watch_to_completion(mut child: std::process::Child) -> (u64, bool) {
    let mut hw = 0;
    loop {
        hw = hw.max(peak_kib(&child));
        match child.try_wait() {
            Ok(Some(status)) => return (hw, status.success()),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
            Err(_) => return (hw, false),
        }
    }
}

/// A private HOME per test. The label matters: tests run in parallel and a
/// shared PID-derived path let one test's cleanup delete another's vault.
fn home(label: &str) -> std::path::PathBuf {
    let h = std::env::temp_dir().join(format!("anubis-mem-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&h);
    std::fs::create_dir_all(&h).unwrap();
    h
}

/// Feeding a huge armored blob must not scale memory with the input.
///
/// The pre-fix implementation read the whole stream before checking its
/// length, so this test would have tracked the full input.
#[test]
fn hostile_armor_does_not_scale_memory() {
    let h = home("armor");
    let mut child = Command::new(bin())
        .args(["decrypt", "-o", "-", "-"])
        .env("HOME", &h)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    // Write far more than the 16 MiB cap. The child should refuse long
    // before consuming it, so a broken pipe here is the expected outcome.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(b"-----BEGIN ANUBIS ENCRYPTED FILE-----\n");
        let line = [b'A'; 64];
        for _ in 0..1_500_000 {
            let mut row = Vec::with_capacity(65);
            row.extend_from_slice(&line);
            row.push(b'\n');
            if stdin.write_all(&row).is_err() {
                return;
            }
        }
    });

    let (hw, ok) = watch_to_completion(child);
    let _ = writer.join();

    assert!(!ok, "oversized armored input must be refused");
    // Cap is 16 MiB; the bounded read plus process baseline lands near 20 MiB.
    // 64 MiB leaves generous headroom while still failing loudly if the cap
    // ever regresses to a post-read length assertion.
    assert!(
        hw < 64 * 1024,
        "peak RSS {hw} KiB suggests the armor cap is not bounding the read"
    );
    let _ = std::fs::remove_dir_all(&h);
}

/// Decrypting a large container must not scale memory with the file.
#[test]
fn large_decrypt_is_constant_memory() {
    let h = home("decrypt");
    let run = |args: &[&str]| -> String {
        let out = Command::new(bin())
            .args(args)
            .env("HOME", &h)
            .output()
            .expect("run");
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    let kg = run(&["keygen", "--json", "--name", "default"]);
    let recipient = serde_json::from_str::<serde_json::Value>(&kg).unwrap()["recipient"]
        .as_str()
        .unwrap()
        .to_string();

    // 64 MiB is large enough that buffering would be unmistakable and small
    // enough to keep the suite quick.
    let plain = h.join("big.bin");
    // Write without ever allocating the whole payload in this parent test
    // process. Some kernels carry a forked parent's VmHWM across exec; holding
    // this payload here made the child's high-water mark intermittently look
    // like buffering even when the CLI stayed constant-memory.
    let mut plain_file = std::fs::File::create(&plain).unwrap();
    std::io::copy(&mut std::io::repeat(7).take(64 << 20), &mut plain_file).unwrap();
    plain_file.flush().unwrap();
    drop(plain_file);
    let sealed = h.join("big.anubis");

    let out = Command::new(bin())
        .args([
            "encrypt",
            "-r",
            &recipient,
            "--sign",
            "-o",
            sealed.to_str().unwrap(),
            "--force",
            plain.to_str().unwrap(),
        ])
        .env("HOME", &h)
        .output()
        .expect("encrypt");
    assert!(out.status.success(), "encrypt failed");

    // `inspect -` has no length metadata. It must consume the complete stream
    // to count payload bytes and bind the content ID, but its memory must not
    // grow with that stream.
    let inspect_input = std::fs::File::open(&sealed).expect("open sealed input");
    let inspect_child = Command::new(bin())
        .args(["inspect", "-"])
        .env("HOME", &h)
        .stdin(Stdio::from(inspect_input))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn inspect");
    let (inspect_hw, inspect_ok) = watch_to_completion(inspect_child);
    assert!(inspect_ok, "inspect from unknown-length stdin failed");
    assert!(
        inspect_hw < 32 * 1024,
        "peak RSS {inspect_hw} KiB while inspecting stdin suggests container buffering"
    );

    let restored = h.join("big.out");
    let child = Command::new(bin())
        .args([
            "decrypt",
            "-o",
            restored.to_str().unwrap(),
            "--force",
            sealed.to_str().unwrap(),
        ])
        .env("HOME", &h)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn decrypt");
    let (hw, ok) = watch_to_completion(child);

    assert!(ok, "decrypt failed");
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        std::fs::read(&plain).unwrap(),
        "round trip differs"
    );
    // Measured baseline is ~3.2 MiB regardless of size; 32 MiB catches a
    // reversion to whole-plaintext buffering without being flaky.
    assert!(
        hw < 32 * 1024,
        "peak RSS {hw} KiB while decrypting 64 MiB suggests plaintext buffering"
    );
    let _ = std::fs::remove_dir_all(&h);
}
