//! Regression: the address book must survive a write/read round trip.
//!
//! `anubis recipient add` once wrote a file its own parser rejected, which
//! broke `status`, `recipient list` and `recipient remove` together. A real
//! ANUBIS recipient is ~2573 characters, so the value length is the part
//! worth defending.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_anubis")
}

/// Run the CLI against a private HOME so the developer's vault is untouched.
fn run(home: &std::path::Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(bin())
        .args(args)
        .env("HOME", home)
        .output()
        .expect("spawn anubis");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn address_book_survives_a_full_round_trip() {
    let home = std::env::temp_dir().join(format!("anubis-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();

    let (ok, out) = run(&home, &["keygen", "--json", "--name", "default"]);
    assert!(ok, "keygen failed: {out}");
    let recipient = serde_json::from_str::<serde_json::Value>(&out).unwrap()["recipient"]
        .as_str()
        .unwrap()
        .to_string();
    // The value that broke the parser is long; make sure it still is.
    assert!(recipient.len() > 2000, "recipient unexpectedly short");

    let (ok, out) = run(
        &home,
        &["recipient", "add", "--json", "--label", "alice", &recipient],
    );
    assert!(ok, "recipient add failed: {out}");

    // Every consumer of recipients.toml must still work after the write.
    let (ok, out) = run(&home, &["recipient", "list", "--json"]);
    assert!(ok, "recipient list failed after add: {out}");
    assert!(out.contains("alice"), "label missing: {out}");

    let (ok, out) = run(&home, &["status", "--json"]);
    assert!(ok, "status failed after add: {out}");
    let status: serde_json::Value = serde_json::from_str(&out).unwrap();
    let book = status["recipients"].as_array().unwrap();
    assert_eq!(book.len(), 1);
    assert_eq!(book[0]["label"], "alice");
    // The key must survive byte-for-byte, not merely be present.
    assert_eq!(book[0]["key"].as_str().unwrap(), recipient);

    let (ok, out) = run(&home, &["recipient", "remove", "--json", "--label", "alice"]);
    assert!(ok, "recipient remove failed: {out}");
    let (ok, out) = run(&home, &["status", "--json"]);
    assert!(ok, "status failed after remove: {out}");
    let status: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(status["recipients"].as_array().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn encrypt_decrypt_through_an_address_book_label() {
    let home = std::env::temp_dir().join(format!("anubis-it2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();

    let (ok, out) = run(&home, &["keygen", "--json", "--name", "default"]);
    assert!(ok, "keygen failed: {out}");
    let recipient = serde_json::from_str::<serde_json::Value>(&out).unwrap()["recipient"]
        .as_str()
        .unwrap()
        .to_string();
    let (ok, _) = run(
        &home,
        &["recipient", "add", "--json", "--label", "bob", &recipient],
    );
    assert!(ok);

    let plain = home.join("msg.txt");
    let sealed = home.join("msg.anubis");
    let opened = home.join("msg.out");
    std::fs::write(&plain, b"resolved through the address book").unwrap();

    // Encrypting by LABEL exercises the read path that the bug broke.
    let (ok, out) = run(
        &home,
        &[
            "encrypt",
            "--json",
            "-r",
            "bob",
            "--sign",
            "-o",
            sealed.to_str().unwrap(),
            plain.to_str().unwrap(),
        ],
    );
    assert!(ok, "encrypt by label failed: {out}");

    let (ok, out) = run(
        &home,
        &[
            "decrypt",
            "--json",
            "-o",
            opened.to_str().unwrap(),
            sealed.to_str().unwrap(),
        ],
    );
    assert!(ok, "decrypt failed: {out}");
    assert_eq!(
        std::fs::read(&opened).unwrap(),
        b"resolved through the address book"
    );

    let _ = std::fs::remove_dir_all(&home);
}
