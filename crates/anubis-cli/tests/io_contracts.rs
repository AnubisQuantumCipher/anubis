//! CLI stream, cancellation, and content-identity contracts.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_anubis")
}

fn private_home(label: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!(
        "anubis-io-contracts-{}-{label}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("create private home");
    home
}

fn run(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("HOME", home)
        .output()
        .expect("run anubis")
}

fn json_line(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().last().expect("JSON output line");
    serde_json::from_str(line).expect("valid JSON output")
}

fn generated_identity(home: &std::path::Path) -> (String, String) {
    let keygen = run(home, &["--json", "keygen"]);
    assert!(
        keygen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let recipient = json_line(&keygen)["recipient"]
        .as_str()
        .expect("recipient")
        .to_owned();
    let identity = std::fs::read_to_string(home.join(".config/anubis/identities/default.key"))
        .expect("read disposable identity")
        .lines()
        .find(|line| line.starts_with("ANUBIS-SECRET-KEY-1"))
        .expect("identity line")
        .to_owned();
    (recipient, identity)
}

fn assert_no_sidecar(directory: &std::path::Path, destination: &std::path::Path) {
    let prefix = format!(
        ".{}.",
        destination
            .file_name()
            .expect("destination filename")
            .to_string_lossy()
    );
    assert!(
        std::fs::read_dir(directory)
            .expect("read output directory")
            .filter_map(Result::ok)
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(&prefix)),
        "failed operation must remove its temporary sidecar"
    );
}

#[cfg(unix)]
#[test]
fn direct_cli_setup_keeps_config_and_state_parents_private() {
    use std::os::unix::fs::PermissionsExt;

    let home = private_home("private-layout");
    let keygen = run(&home, &["--json", "keygen"]);
    assert!(
        keygen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    for directory in [
        home.join(".config/anubis"),
        home.join(".config/anubis/identities"),
        home.join(".local/state/anubis"),
    ] {
        let mode = std::fs::metadata(&directory)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "{} must be private", directory.display());
    }

    let audit = home.join(".local/state/anubis/audit.jsonl");
    let audit_mode = std::fs::metadata(&audit)
        .expect("audit metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(audit_mode, 0o600, "audit log must be private");

    std::fs::remove_dir_all(home).expect("remove private home");
}

#[cfg(unix)]
#[test]
fn direct_encryption_keeps_a_fresh_audit_directory_private_and_refuses_a_symlinked_log() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let donor_home = private_home("audit-donor");
    let (recipient, _) = generated_identity(&donor_home);
    let home = private_home("audit-direct-encrypt");
    let state = home.join(".local/state/anubis");
    std::fs::create_dir_all(&state).expect("create state path");
    let sentinel = home.join("audit-sentinel");
    std::fs::write(&sentinel, b"must remain unchanged").expect("write sentinel");
    symlink(&sentinel, state.join("audit.jsonl")).expect("plant audit symlink");

    let input = home.join("plain.txt");
    let output = home.join("sealed.anubis");
    std::fs::write(&input, b"audit hardening canary").expect("write plaintext");
    let encryption = run(
        &home,
        &[
            "encrypt",
            "-r",
            &recipient,
            "-o",
            output.to_str().expect("output path"),
            input.to_str().expect("input path"),
        ],
    );
    assert!(
        encryption.status.success(),
        "encryption failed: {}",
        String::from_utf8_lossy(&encryption.stderr)
    );
    let mode = std::fs::metadata(&state)
        .expect("state metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "audit state directory must be private");
    assert_eq!(
        std::fs::read(&sentinel).expect("read sentinel"),
        b"must remain unchanged",
        "audit append followed a planted symlink"
    );

    std::fs::remove_file(state.join("audit.jsonl")).expect("remove audit symlink");
    std::fs::hard_link(&sentinel, state.join("audit.jsonl")).expect("plant audit hard link");
    let second_output = home.join("sealed-again.anubis");
    let second = run(
        &home,
        &[
            "encrypt",
            "-r",
            &recipient,
            "-o",
            second_output.to_str().expect("second output path"),
            input.to_str().expect("input path"),
        ],
    );
    assert!(
        second.status.success(),
        "encryption with a planted audit hard link failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        std::fs::read(&sentinel).expect("read sentinel after hard link"),
        b"must remain unchanged",
        "audit append followed a planted hard link"
    );

    let symlink_home = private_home("audit-state-symlink");
    let external_state = symlink_home.join("external-state");
    std::fs::create_dir_all(&external_state).expect("create external state");
    std::fs::create_dir_all(symlink_home.join(".local/state")).expect("create state parent");
    symlink(&external_state, symlink_home.join(".local/state/anubis"))
        .expect("plant state symlink");
    let symlink_input = symlink_home.join("plain.txt");
    let symlink_output = symlink_home.join("sealed.anubis");
    std::fs::write(&symlink_input, b"state symlink canary").expect("write symlink plaintext");
    let through_symlink = run(
        &symlink_home,
        &[
            "encrypt",
            "-r",
            &recipient,
            "-o",
            symlink_output.to_str().expect("symlink output path"),
            symlink_input.to_str().expect("symlink input path"),
        ],
    );
    assert!(
        through_symlink.status.success(),
        "audit refusal must not fail encryption: {}",
        String::from_utf8_lossy(&through_symlink.stderr)
    );
    assert!(
        !external_state.join("audit.jsonl").exists(),
        "audit append followed a symlinked state directory"
    );

    std::fs::remove_dir_all(home).expect("remove test home");
    std::fs::remove_dir_all(symlink_home).expect("remove symlink test home");
    std::fs::remove_dir_all(donor_home).expect("remove donor home");
}

#[test]
fn secret_identity_arguments_are_redacted_from_output_and_audit() {
    let home = private_home("secret-redaction");
    let (recipient, identity) = generated_identity(&home);
    let input = home.join("plain.txt");
    let output = home.join("sealed.anubis");
    std::fs::write(&input, b"redaction canary").expect("write plaintext");

    // A capability marker embedded after an otherwise-valid prefix must not
    // bypass the public-name gate. This used to create a key file whose name,
    // JSON result, and audit summary all reflected the complete secret.
    let prefixed_secret_name = format!("x{identity}");
    let keygen = run(
        &home,
        &["--json", "keygen", "--name", &prefixed_secret_name],
    );
    assert!(
        !keygen.status.success(),
        "prefixed secret identity was accepted as a public name"
    );
    let keygen_text = format!(
        "{}{}",
        String::from_utf8_lossy(&keygen.stdout),
        String::from_utf8_lossy(&keygen.stderr)
    );
    assert!(
        !keygen_text.contains(&identity),
        "prefixed secret identity reached keygen diagnostics"
    );

    let recipient_add = run(
        &home,
        &[
            "--json",
            "recipient",
            "add",
            "--label",
            &prefixed_secret_name,
            &recipient,
        ],
    );
    assert!(
        !recipient_add.status.success(),
        "prefixed secret identity was accepted as a recipient label"
    );
    let recipient_add_text = format!(
        "{}{}",
        String::from_utf8_lossy(&recipient_add.stdout),
        String::from_utf8_lossy(&recipient_add.stderr)
    );
    assert!(
        !recipient_add_text.contains(&identity),
        "prefixed secret identity reached recipient-add diagnostics"
    );

    // Status must also defend against a capability-bearing filename already
    // present in an older or externally modified identity directory.
    let identities = home.join(".config/anubis/identities");
    std::fs::copy(
        identities.join("default.key"),
        identities.join(format!("{prefixed_secret_name}.key")),
    )
    .expect("create legacy secret-named identity fixture");
    let status = run(&home, &["--json", "status"]);
    assert!(status.status.success(), "status failed on legacy fixture");
    let status_text = String::from_utf8_lossy(&status.stdout);
    assert!(
        !status_text.contains(&identity),
        "secret identity from an existing filename reached status output"
    );

    let encryption = run(
        &home,
        &[
            "--json",
            "encrypt",
            "-r",
            &identity,
            "-o",
            output.to_str().expect("output path"),
            input.to_str().expect("input path"),
        ],
    );
    assert!(
        !encryption.status.success(),
        "secret recipient was accepted"
    );
    let encryption_text = format!(
        "{}{}",
        String::from_utf8_lossy(&encryption.stdout),
        String::from_utf8_lossy(&encryption.stderr)
    );
    assert!(
        !encryption_text.contains(&identity),
        "secret identity reached encrypt diagnostics"
    );

    let verification = run(
        &home,
        &[
            "--json",
            "verify",
            "--signer",
            &identity,
            input.to_str().expect("input path"),
        ],
    );
    assert!(
        !verification.status.success(),
        "secret signer pin was accepted"
    );
    let verification_text = format!(
        "{}{}",
        String::from_utf8_lossy(&verification.stdout),
        String::from_utf8_lossy(&verification.stderr)
    );
    assert!(
        !verification_text.contains(&identity),
        "secret identity reached verify diagnostics"
    );

    let decryption = run(
        &home,
        &[
            "--json",
            "decrypt",
            "--signer",
            &identity,
            "-o",
            output.to_str().expect("output path"),
            input.to_str().expect("input path"),
        ],
    );
    assert!(
        !decryption.status.success(),
        "secret signer pin was accepted"
    );
    let decryption_text = format!(
        "{}{}",
        String::from_utf8_lossy(&decryption.stdout),
        String::from_utf8_lossy(&decryption.stderr)
    );
    assert!(
        !decryption_text.contains(&identity),
        "secret identity reached decrypt diagnostics"
    );

    let typed_parser_failure = run(
        &home,
        &[
            "decrypt",
            "--expect-content-id",
            &identity,
            "-o",
            output.to_str().expect("output path"),
            input.to_str().expect("input path"),
        ],
    );
    assert!(
        !typed_parser_failure.status.success(),
        "secret content-ID value was accepted"
    );
    let parser_text = format!(
        "{}{}",
        String::from_utf8_lossy(&typed_parser_failure.stdout),
        String::from_utf8_lossy(&typed_parser_failure.stderr)
    );
    assert!(
        !parser_text.contains(&identity),
        "secret identity reached clap diagnostics"
    );

    let control_parser_failure = run(
        &home,
        &[
            "decrypt",
            "--expect-content-id",
            "not-a-content-id\nFORGED-SUCCESS",
            "-o",
            output.to_str().expect("output path"),
            input.to_str().expect("input path"),
        ],
    );
    assert!(!control_parser_failure.status.success());
    let control_parser_text = format!(
        "{}{}",
        String::from_utf8_lossy(&control_parser_failure.stdout),
        String::from_utf8_lossy(&control_parser_failure.stderr)
    );
    assert!(
        !control_parser_text.contains("FORGED-SUCCESS"),
        "control-bearing argument injected a diagnostic line"
    );

    // A capability-looking string in a structured result path is still a
    // capability leak. The operation succeeds, but JSON and audit output must
    // carry only the redaction marker.
    let secret_named_input = home.join(format!("{identity}.txt"));
    let safe_output = home.join("safe-output.anubis");
    std::fs::write(&secret_named_input, b"structured path redaction canary")
        .expect("write secret-named input");
    let successful = run(
        &home,
        &[
            "--json",
            "encrypt",
            "-r",
            &recipient,
            "-o",
            safe_output.to_str().expect("safe output path"),
            secret_named_input
                .to_str()
                .expect("secret-named input path"),
        ],
    );
    assert!(
        successful.status.success(),
        "secret-named path encryption failed: {}",
        String::from_utf8_lossy(&successful.stderr)
    );
    let successful_text = format!(
        "{}{}",
        String::from_utf8_lossy(&successful.stdout),
        String::from_utf8_lossy(&successful.stderr)
    );
    assert!(
        !successful_text.contains(&identity),
        "secret identity reached successful structured output"
    );
    assert!(
        successful_text.contains("<redacted-anubis-identity>"),
        "successful structured output did not mark the redaction"
    );

    let audit = std::fs::read_to_string(home.join(".local/state/anubis/audit.jsonl"))
        .expect("read audit log");
    assert!(
        !audit.contains(&identity),
        "secret identity reached persistent audit data"
    );
    std::fs::remove_dir_all(home).expect("remove test home");
}

#[cfg(unix)]
#[test]
fn human_result_paths_escape_terminal_controls() {
    let home = private_home("terminal-path");
    let (recipient, _) = generated_identity(&home);
    let input = home.join("plain\u{1b}[2J\ninjected.txt");
    let output = home.join("sealed.anubis");
    std::fs::write(&input, b"terminal path canary").expect("write plaintext");
    let encryption = run(
        &home,
        &[
            "encrypt",
            "-r",
            &recipient,
            "-o",
            output.to_str().expect("output path"),
            input.to_str().expect("input path"),
        ],
    );
    assert!(
        encryption.status.success(),
        "encryption failed: {}",
        String::from_utf8_lossy(&encryption.stderr)
    );
    let stdout = String::from_utf8_lossy(&encryption.stdout);
    assert!(
        !stdout.contains('\u{1b}'),
        "raw escape reached terminal output"
    );
    assert!(
        !stdout.contains("\ninjected.txt"),
        "pathname newline split terminal output"
    );
    assert!(
        stdout.contains("\\n") && stdout.contains("\\u{1b}"),
        "terminal controls were not rendered visibly: {stdout:?}"
    );
    std::fs::remove_dir_all(home).expect("remove test home");
}

#[cfg(unix)]
#[test]
fn sigterm_unwinds_and_removes_named_output_sidecar() {
    let home = private_home("sigterm-cleanup");
    let keygen = run(&home, &["--json", "keygen"]);
    assert!(keygen.status.success(), "keygen failed");
    let recipient = json_line(&keygen)["recipient"]
        .as_str()
        .expect("recipient")
        .to_owned();

    let destination = home.join("cancelled.anubis");
    let mut child = Command::new(bin())
        .args([
            "encrypt",
            "-r",
            &recipient,
            "-o",
            destination.to_str().expect("destination path"),
            "-",
        ])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cancellable encryption");

    let prefix = format!(
        ".{}.",
        destination
            .file_name()
            .expect("destination filename")
            .to_string_lossy()
    );
    let sidecar_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let exists = std::fs::read_dir(&home)
            .expect("read output directory")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix));
        if exists {
            break;
        }
        if let Some(status) = child.try_wait().expect("poll encryption") {
            panic!("encryption exited before creating its sidecar: {status}");
        }
        if std::time::Instant::now() >= sidecar_deadline {
            child.kill().expect("kill timed-out encryption");
            let _ = child.wait();
            panic!("encryption did not create its sidecar before timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let pid = child.id().to_string();
    let signalled = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send SIGTERM");
    assert!(signalled.success(), "kill command failed");

    // signal-hook installs SA_RESTART. Wake the pending stdin read so the
    // cancellation-aware reader reaches its post-read flag check and unwinds.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"wake cancelled read");
    }

    let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll cancelled encryption") {
            break status;
        }
        if std::time::Instant::now() >= exit_deadline {
            child.kill().expect("kill stuck encryption");
            let _ = child.wait();
            panic!("SIGTERM did not make encryption unwind before timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    };

    assert!(!status.success(), "cancelled encryption must exit nonzero");
    assert!(
        !destination.exists(),
        "cancelled encryption must not publish ciphertext"
    );
    assert_no_sidecar(&home, &destination);
    std::fs::remove_dir_all(home).expect("remove private home");
}

#[cfg(unix)]
#[test]
fn sigterm_unwinds_and_removes_plaintext_sidecar() {
    let home = private_home("sigterm-plaintext-cleanup");
    let keygen = run(&home, &["--json", "keygen"]);
    assert!(keygen.status.success(), "keygen failed");
    let recipient = json_line(&keygen)["recipient"]
        .as_str()
        .expect("recipient")
        .to_owned();

    let plaintext = home.join("secret.txt");
    let sealed = home.join("secret.anubis");
    // Multiple full chunks make provisional decryption write authenticated
    // plaintext into the private sidecar while stdin remains open waiting to
    // learn whether the final chunk really is final.
    std::fs::write(&plaintext, vec![b'P'; anubis_crypto::stream::CHUNK * 3])
        .expect("write plaintext");
    let encryption = run(
        &home,
        &[
            "encrypt",
            "-r",
            &recipient,
            "-o",
            sealed.to_str().expect("sealed path"),
            plaintext.to_str().expect("plaintext path"),
        ],
    );
    assert!(
        encryption.status.success(),
        "fixture encryption failed: {}",
        String::from_utf8_lossy(&encryption.stderr)
    );
    let container = std::fs::read(&sealed).expect("read container");
    assert!(!container.is_empty(), "fixture container must not be empty");

    let destination = home.join("cancelled-plaintext.out");
    let mut child = Command::new(bin())
        .args([
            "decrypt",
            "-o",
            destination.to_str().expect("destination path"),
            "-",
        ])
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cancellable decryption");
    let mut stdin = child.stdin.take().expect("decryption stdin");
    stdin
        .write_all(&container)
        .expect("write container while keeping stdin open");

    let prefix = format!(
        ".{}.",
        destination
            .file_name()
            .expect("destination filename")
            .to_string_lossy()
    );
    let sidecar_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let contains_plaintext = std::fs::read_dir(&home)
            .expect("read output directory")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .any(|entry| entry.metadata().is_ok_and(|metadata| metadata.len() > 0));
        if contains_plaintext {
            break;
        }
        if let Some(status) = child.try_wait().expect("poll decryption") {
            panic!("decryption exited before creating its sidecar: {status}");
        }
        if std::time::Instant::now() >= sidecar_deadline {
            child.kill().expect("kill timed-out decryption");
            let _ = child.wait();
            panic!("decryption did not write provisional plaintext before timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let pid = child.id().to_string();
    let signalled = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send SIGTERM");
    assert!(signalled.success(), "kill command failed");
    drop(stdin);

    let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll cancelled decryption") {
            break status;
        }
        if std::time::Instant::now() >= exit_deadline {
            child.kill().expect("kill stuck decryption");
            let _ = child.wait();
            panic!("SIGTERM did not make decryption unwind before timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    };

    assert!(!status.success(), "cancelled decryption must exit nonzero");
    assert!(
        !destination.exists(),
        "cancelled decryption must not publish plaintext"
    );
    assert_no_sidecar(&home, &destination);
    std::fs::remove_dir_all(home).expect("remove private home");
}

#[test]
fn json_payload_stdout_is_rejected_without_writing_stdout() {
    let home = private_home("stdout-rejection");
    let cases: &[&[&str]] = &[
        &["--json", "encrypt", "-r", "unused", "-o", "-", "missing"],
        &["--json", "encrypt", "-r", "unused", "-"],
        &["--json", "decrypt", "-o", "-", "missing"],
        &["--json", "decrypt", "-"],
    ];

    for args in cases {
        let output = run(&home, args);
        assert!(!output.status.success(), "must reject {args:?}");
        assert!(
            output.stdout.is_empty(),
            "payload stdout must be empty for {args:?}: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--json cannot be combined"),
            "diagnostic must be on stderr for {args:?}"
        );
    }

    std::fs::remove_dir_all(home).expect("remove private home");
}

#[test]
fn inspect_verify_and_decrypt_report_the_same_content_id() {
    let home = private_home("content-id");
    let keygen = run(&home, &["--json", "keygen"]);
    assert!(keygen.status.success(), "keygen failed");
    let recipient = json_line(&keygen)["recipient"]
        .as_str()
        .expect("recipient")
        .to_owned();

    let plain = home.join("message.txt");
    let sealed = home.join("message.anubis");
    let opened = home.join("message.out");
    std::fs::write(&plain, b"content identity binds the whole container").expect("write plaintext");

    let encrypt = run(
        &home,
        &[
            "--json",
            "encrypt",
            "-r",
            &recipient,
            "--sign",
            "-o",
            sealed.to_str().expect("sealed path"),
            plain.to_str().expect("plain path"),
        ],
    );
    assert!(
        encrypt.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&encrypt.stderr)
    );

    let sealed_input = std::fs::File::open(&sealed).expect("open container");
    let inspect = Command::new(bin())
        .args(["--json", "inspect", "-"])
        .env("HOME", &home)
        .stdin(Stdio::from(sealed_input))
        .output()
        .expect("inspect from stdin");
    assert!(inspect.status.success(), "inspect failed");
    let inspect_json = json_line(&inspect);

    let armored = home.join("message.anubis.txt");
    let binary = std::fs::read(&sealed).expect("read binary container");
    std::fs::write(&armored, anubis_crypto::armor::encode(&binary)).expect("write armor");
    let inspect_armor = run(
        &home,
        &["--json", "inspect", armored.to_str().expect("armored path")],
    );
    assert!(inspect_armor.status.success(), "armored inspect failed");
    let inspect_armor_json = json_line(&inspect_armor);

    let verify = run(
        &home,
        &["--json", "verify", sealed.to_str().expect("sealed path")],
    );
    assert!(verify.status.success(), "verify failed");
    let verify_json = json_line(&verify);

    // Stdout plaintext must remain bounded and unpublished when private
    // disk-backed staging cannot be created. Never fall back to a Vec whose
    // size is controlled by the encrypted input.
    let invalid_temp_dir = home.join("not-a-temp-directory");
    std::fs::write(&invalid_temp_dir, b"regular file").expect("create invalid temp path");
    let spill_failure = Command::new(bin())
        .args(["decrypt", "-o", "-", sealed.to_str().expect("sealed path")])
        .env("HOME", &home)
        .env("TMPDIR", &invalid_temp_dir)
        .output()
        .expect("run decrypt with unavailable spill directory");
    assert!(
        !spill_failure.status.success(),
        "unavailable stdout staging must fail closed"
    );
    assert!(
        spill_failure.stdout.is_empty(),
        "spill creation failure must publish no plaintext"
    );
    assert!(
        String::from_utf8_lossy(&spill_failure.stderr)
            .contains("private disk-backed staging for plaintext output on stdout"),
        "spill failure must explain the fail-closed boundary"
    );

    let decrypt = run(
        &home,
        &[
            "--json",
            "decrypt",
            "--require-signature",
            "-o",
            opened.to_str().expect("opened path"),
            sealed.to_str().expect("sealed path"),
        ],
    );
    assert!(decrypt.status.success(), "decrypt failed");
    let decrypt_json = json_line(&decrypt);

    let content_id = inspect_json["content_id"]
        .as_str()
        .expect("inspect content_id");
    assert_eq!(content_id.len(), 128);
    assert!(
        content_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "content_id must be lowercase hexadecimal"
    );
    assert_eq!(verify_json["content_id"], content_id);
    assert_eq!(decrypt_json["content_id"], content_id);
    assert_eq!(inspect_armor_json["content_id"], content_id);
    assert_eq!(
        std::fs::read(&opened).expect("read plaintext"),
        std::fs::read(&plain).expect("read original")
    );

    let bound_path = home.join("bound.out");
    let uppercase_content_id = content_id.to_ascii_uppercase();
    let bound = run(
        &home,
        &[
            "decrypt",
            "--expect-content-id",
            &uppercase_content_id,
            "-o",
            bound_path.to_str().expect("bound path"),
            sealed.to_str().expect("sealed path"),
        ],
    );
    assert!(bound.status.success(), "matching content ID must pass");
    assert_eq!(
        std::fs::read(&bound_path).expect("read bound plaintext"),
        std::fs::read(&plain).expect("read original")
    );

    let mut mismatched_bytes = content_id.as_bytes().to_vec();
    let first = mismatched_bytes.first_mut().expect("content ID byte");
    *first = if *first == b'0' { b'1' } else { b'0' };
    let mismatched_content_id = String::from_utf8(mismatched_bytes).expect("ASCII content ID");
    let mismatch_path = home.join("mismatch.out");
    let mismatch = run(
        &home,
        &[
            "decrypt",
            "--expect-content-id",
            &mismatched_content_id,
            "-o",
            mismatch_path.to_str().expect("mismatch path"),
            sealed.to_str().expect("sealed path"),
        ],
    );
    assert!(
        !mismatch.status.success(),
        "mismatched content ID must fail"
    );
    assert!(
        !mismatch_path.exists(),
        "content ID mismatch must not publish plaintext"
    );
    assert_no_sidecar(&home, &mismatch_path);

    // Fail after plaintext has been staged by corrupting the signature
    // trailer. The destination and its private sidecar must both disappear.
    let mut corrupted = binary;
    let last = corrupted.last_mut().expect("container byte");
    *last = !*last;
    let corrupt_path = home.join("corrupt.anubis");
    let rejected_path = home.join("rejected.out");
    std::fs::write(&corrupt_path, corrupted).expect("write corrupt container");

    let corrupt_inspect = run(
        &home,
        &[
            "--json",
            "inspect",
            corrupt_path.to_str().expect("corrupt path"),
        ],
    );
    assert!(corrupt_inspect.status.success(), "corrupt inspect failed");
    let corrupt_inspect_json = json_line(&corrupt_inspect);
    let false_verify = run(
        &home,
        &[
            "--json",
            "verify",
            corrupt_path.to_str().expect("corrupt path"),
        ],
    );
    assert!(
        !false_verify.status.success(),
        "false signature verdict must exit nonzero"
    );
    let false_verify_json = json_line(&false_verify);
    assert_eq!(false_verify_json["kind"], "verify");
    assert_eq!(false_verify_json["ok"], false);
    assert_eq!(false_verify_json["signed"], true);
    assert_eq!(false_verify_json["signature_ok"], false);
    assert_eq!(
        false_verify_json["content_id"], corrupt_inspect_json["content_id"],
        "false verdict must bind the exact corrupt container"
    );
    assert_eq!(
        false_verify_json["signer_fingerprint"], verify_json["signer_fingerprint"],
        "false verdict must retain the embedded signer"
    );

    // A bad signature remains the primary verdict even when the operator also
    // supplied a different signer pin. Never describe invalid bytes as a
    // valid signature by the wrong key.
    let signer = verify_json["signer_fingerprint"]
        .as_str()
        .expect("signer fingerprint");
    let mut wrong_pin = signer.as_bytes().to_vec();
    let first_hex = wrong_pin
        .iter_mut()
        .find(|byte| **byte != b'-')
        .expect("fingerprint hexadecimal digit");
    *first_hex = if *first_hex == b'0' { b'1' } else { b'0' };
    let wrong_pin = String::from_utf8(wrong_pin).expect("ASCII fingerprint");
    let false_pinned_verify = run(
        &home,
        &[
            "verify",
            "--signer",
            &wrong_pin,
            corrupt_path.to_str().expect("corrupt path"),
        ],
    );
    assert!(!false_pinned_verify.status.success());
    let false_pinned_error = String::from_utf8_lossy(&false_pinned_verify.stderr);
    assert!(false_pinned_error.contains("signature did not verify"));
    assert!(!false_pinned_error.contains("signature is valid but by"));

    let rejected = run(
        &home,
        &[
            "decrypt",
            "-o",
            rejected_path.to_str().expect("rejected path"),
            corrupt_path.to_str().expect("corrupt path"),
        ],
    );
    assert!(!rejected.status.success(), "corrupt signature must fail");
    assert!(
        !rejected_path.exists(),
        "failed decrypt must not publish plaintext"
    );
    assert_no_sidecar(&home, &rejected_path);

    let malformed_path = home.join("malformed.anubis");
    std::fs::write(&malformed_path, b"not an ANUBIS container").expect("write malformed input");
    let malformed_verify = run(
        &home,
        &[
            "--json",
            "verify",
            malformed_path.to_str().expect("malformed path"),
        ],
    );
    assert!(
        !malformed_verify.status.success(),
        "malformed verify must fail"
    );
    let malformed_json = json_line(&malformed_verify);
    assert_eq!(malformed_json["signature_ok"], serde_json::Value::Null);
    assert_eq!(malformed_json["content_id"], serde_json::Value::Null);
    assert_eq!(
        malformed_json["signer_fingerprint"],
        serde_json::Value::Null
    );

    let invalid = run(
        &home,
        &[
            "decrypt",
            "--expect-content-id",
            "not-a-content-id",
            sealed.to_str().expect("sealed path"),
        ],
    );
    assert!(!invalid.status.success(), "malformed content ID must fail");
    assert!(
        String::from_utf8_lossy(&invalid.stderr).contains("exactly 128 hexadecimal characters"),
        "malformed content ID must have a precise diagnostic"
    );

    std::fs::remove_dir_all(home).expect("remove private home");
}

#[test]
fn v4_refuses_before_v3_identity_access_or_plaintext_staging() {
    let home = private_home("v4-dispatch-refusal");
    let binary_path = home.join("future.anubis");
    let armored_path = home.join("future.anubis.txt");
    let future = format!(
        "{}\nfuture v4 bytes must never reach v3\n",
        anubis_crypto::container::V4_MAGIC
    );
    std::fs::write(&binary_path, future.as_bytes()).expect("write v4 binary fixture");
    std::fs::write(
        &armored_path,
        anubis_crypto::armor::encode(future.as_bytes()),
    )
    .expect("write v4 armored fixture");

    for source in [&binary_path, &armored_path] {
        for command in ["inspect", "verify"] {
            let output = run(&home, &[command, source.to_str().expect("fixture path")]);
            assert!(!output.status.success(), "{command} accepted v4 input");
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("refusing to reinterpret it as ANUBIS/v3"),
                "{command} did not report the exact downgrade refusal: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let destination = home.join(format!(
            "{}.plaintext",
            source.file_name().expect("fixture name").to_string_lossy()
        ));
        let output = run(
            &home,
            &[
                "decrypt",
                "-o",
                destination.to_str().expect("destination path"),
                source.to_str().expect("fixture path"),
            ],
        );
        assert!(!output.status.success(), "decrypt accepted v4 input");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("refusing to reinterpret it as ANUBIS/v3"),
            "decrypt did not report the exact downgrade refusal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!destination.exists(), "v4 refusal published plaintext");
        assert_no_sidecar(&home, &destination);
    }

    assert!(
        !home.join(".config/anubis/identities").exists(),
        "v4 refusal touched the v3 identity store"
    );
    std::fs::remove_dir_all(home).expect("remove private home");
}
