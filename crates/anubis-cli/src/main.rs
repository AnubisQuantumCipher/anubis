//! ANUBIS - hybrid post-quantum file encryption.

#![forbid(unsafe_code)]

mod audit;
mod io;
mod paths;

use anubis_crypto::format::{self, EncryptOptions};
use anubis_crypto::keys::{Identity, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const SUITE_KEM: &str = "X25519+ML-KEM-1024";
const SUITE_SIG: &str = "ML-DSA-87";
const SUITE_AEAD: &str = "ChaCha20-Poly1305";
const SUITE_KDF: &str = "HKDF-SHA512";

#[derive(Parser)]
#[command(
    name = "anubis",
    version,
    about = "Hybrid post-quantum file encryption (X25519 + ML-KEM-1024)",
    long_about = None
)]
struct Cli {
    /// Emit machine-readable JSON on stdout.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new identity.
    Keygen {
        #[arg(long, default_value = "default")]
        name: String,
        /// Overwrite an existing identity of the same name.
        #[arg(long)]
        force: bool,
    },
    /// Encrypt a file. Use `-` for stdin/stdout.
    Encrypt {
        /// Recipient key (anubis1...) or a label from the address book.
        #[arg(short = 'r', long = "recipient")]
        recipients: Vec<String>,
        /// File of recipients, one per line; blank lines and `#` ignored.
        #[arg(short = 'R', long = "recipients-file")]
        recipients_file: Vec<PathBuf>,
        /// Sign the file with an identity's ML-DSA-87 key.
        #[arg(long)]
        sign: bool,
        #[arg(long, default_value = "default")]
        identity: String,
        /// ASCII-armor the output for email or copy-paste.
        #[arg(short = 'a', long)]
        armor: bool,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        input: PathBuf,
    },
    /// Decrypt a file. Use `-` for stdin/stdout. Armor is detected.
    Decrypt {
        #[arg(long)]
        identity: Option<String>,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        /// Fail unless the container carries a valid signature.
        #[arg(long)]
        require_signature: bool,
        /// Fail unless it is signed by this signer fingerprint.
        /// Implies --require-signature.
        #[arg(long, value_name = "FINGERPRINT")]
        signer: Option<String>,
        /// Fail unless the decoded container has this exact SHA-512 content ID.
        #[arg(long, value_name = "SHA512_HEX")]
        expect_content_id: Option<ExpectedContentId>,
        input: PathBuf,
    },
    /// Show a file's header without decrypting it.
    Inspect { input: PathBuf },
    /// Check a file's signature. Needs no key and decrypts nothing.
    Verify {
        /// Require this exact signer fingerprint (ANUBIS-FP form).
        #[arg(long)]
        signer: Option<String>,
        input: PathBuf,
    },
    /// Summarise the vault.
    Status,
    /// Manage the recipient address book.
    Recipient {
        #[command(subcommand)]
        action: RecipientAction,
    },
    /// Emit a shell completion script.
    Completions {
        /// bash, zsh, fish, elvish or powershell.
        shell: clap_complete::Shell,
    },
}

#[derive(Clone)]
struct ExpectedContentId(format::ContentId);

impl std::str::FromStr for ExpectedContentId {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if value.len() != 128 {
            return Err("content ID must contain exactly 128 hexadecimal characters".into());
        }

        let mut decoded = [0u8; 64];
        for (slot, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let high = hex_nibble(pair[0])
                .ok_or_else(|| "content ID contains a non-hexadecimal character".to_string())?;
            let low = hex_nibble(pair[1])
                .ok_or_else(|| "content ID contains a non-hexadecimal character".to_string())?;
            *slot = (high << 4) | low;
        }
        Ok(Self(decoded))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Subcommand)]
enum RecipientAction {
    List,
    Add {
        #[arg(long)]
        label: String,
        key: String,
    },
    Remove {
        #[arg(long)]
        label: String,
    },
}

/// A failure whose machine-readable record has already been printed.
///
/// `verify` emits one `kind:"verify"` object that carries the whole verdict,
/// including the failure cases. Wrapping its error in this tells `main` to set
/// the exit status without printing a second JSON object, so `--json verify`
/// output is always exactly one document.
#[derive(Debug)]
struct VerifyFailed(anyhow::Error);

impl std::fmt::Display for VerifyFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for VerifyFailed {}

fn main() {
    if let Err(error) = io::install_termination_handler() {
        eprintln!("anubis: {error:#}");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    if let Err(e) = validate_stream_contract(&cli) {
        // Payload stdout must stay a byte stream. In particular, do not emit
        // the usual JSON error object here: that would turn a safely rejected
        // command into a corrupt payload that happens to describe its error.
        eprintln!("anubis: {e:#}");
        std::process::exit(1);
    }
    let json = cli.json;
    match run(&cli) {
        Ok(()) => {}
        Err(e) => {
            let reported = e.downcast_ref::<VerifyFailed>().is_some();
            if json {
                if !reported {
                    let obj = json!({"kind": "result", "ok": false, "error": e.to_string()});
                    println!("{obj}");
                }
            } else {
                eprintln!("anubis: {e:#}");
            }
            std::process::exit(1);
        }
    }
}

/// Reject modes in which machine records and payload bytes would own the same
/// stream. This is checked before opening input, resolving keys, or producing
/// progress, so every rejection leaves payload stdout empty.
fn validate_stream_contract(cli: &Cli) -> Result<()> {
    if !cli.json {
        return Ok(());
    }

    let payload_stdout = match &cli.command {
        Command::Encrypt { input, output, .. } | Command::Decrypt { input, output, .. } => output
            .as_deref()
            .map_or_else(|| input == Path::new("-"), |path| path == Path::new("-")),
        _ => false,
    };

    if payload_stdout {
        bail!(
            "--json cannot be combined with encrypt/decrypt payload output on stdout; use -o FILE for the payload or omit --json"
        );
    }
    Ok(())
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Keygen { name, force } => cmd_keygen(cli.json, name, *force),
        Command::Encrypt {
            recipients,
            recipients_file,
            sign,
            identity,
            armor,
            output,
            force,
            input,
        } => cmd_encrypt(
            cli.json,
            recipients,
            recipients_file,
            *sign,
            identity,
            *armor,
            output.as_deref(),
            *force,
            input,
        ),
        Command::Decrypt {
            identity,
            output,
            force,
            require_signature,
            signer,
            expect_content_id,
            input,
        } => cmd_decrypt(
            cli.json,
            identity.as_deref(),
            output.as_deref(),
            *force,
            *require_signature,
            signer.as_deref(),
            expect_content_id.as_ref(),
            input,
        ),
        Command::Inspect { input } => cmd_inspect(cli.json, input),
        Command::Verify { signer, input } => cmd_verify(cli.json, signer.as_deref(), input),
        Command::Status => cmd_status(cli.json),
        Command::Recipient { action } => cmd_recipient(cli.json, action),
        Command::Completions { shell } => {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            clap_complete::generate(*shell, &mut cmd, "anubis", &mut std::io::stdout());
            Ok(())
        }
    }
}

// ------------------------------------------------------------------ keygen

fn cmd_keygen(json: bool, name: &str, force: bool) -> Result<()> {
    paths::ensure_dirs()?;
    let path = paths::identity_path(name)?;
    if path.exists() && !force {
        bail!(
            "identity '{name}' already exists at {}; pass --force to replace it",
            path.display()
        );
    }

    let id = Identity::generate().map_err(|e| anyhow!("{e}"))?;
    let encoded = id.encode().map_err(|e| anyhow!("{e}"))?;
    let recipient = id.to_recipient().map_err(|e| anyhow!("{e}"))?;
    let rec_str = recipient.encode().map_err(|e| anyhow!("{e}"))?;
    let created = audit::now_iso();

    let body = format!(
        "# ANUBIS identity: {name}\n# created: {created}\n# recipient: {rec_str}\n{encoded}\n"
    );
    write_secret(&path, body.as_bytes(), force)?;

    audit::append(&audit::Record {
        ts: created.clone(),
        op: "keygen".into(),
        path: path.display().to_string(),
        out: None,
        bytes: 0,
        ms: 0,
        ok: true,
        signed: true,
        recipients: 0,
        error: None,
        summary: format!("generated identity '{name}' ({})", recipient.fingerprint()),
    });

    if json {
        println!(
            "{}",
            json!({
                "kind": "keygen",
                "name": name,
                "path": path.display().to_string(),
                "recipient": rec_str,
                "fingerprint": recipient.fingerprint(),
                "created": created,
                "signing": true,
            })
        );
    } else {
        println!("Identity '{name}' written to {}", path.display());
        println!("Fingerprint: {}", recipient.fingerprint());
        println!("Recipient:   {rec_str}");
    }
    Ok(())
}

/// Write secret key material.
///
/// Creating at 0600 rather than writing then chmod-ing matters: the previous
/// order left the private key on disk at the umask default for the duration
/// of the write, which is world-readable on a typical system.
fn write_secret(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    io::write_atomic(path, bytes, force)
}

// ------------------------------------------------------------------ helpers

fn load_identity(name: &str) -> Result<Identity> {
    let path = paths::identity_path(name)?;
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "no identity '{name}' at {} (run: anubis keygen --name {name})",
            path.display()
        )
    })?;
    parse_identity(&text)
}

fn parse_identity(text: &str) -> Result<Identity> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        return Identity::decode(line).map_err(|e| anyhow!("{e}"));
    }
    bail!("identity file contains no key line")
}

/// Every identity in the vault, for trial decryption.
fn all_identities() -> Result<Vec<(String, Identity)>> {
    let dir = paths::identities_dir()?;
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut entries: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(std::result::Result::ok)
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for e in entries {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("key") {
            continue;
        }
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        if let Ok(id) = parse_identity(&text) {
            out.push((stem.to_string(), id));
        }
    }
    Ok(out)
}

/// Resolve a recipient given either a literal key or an address-book label.
fn resolve_recipient(spec: &str) -> Result<Recipient> {
    if spec.starts_with("anubis1") {
        return Recipient::decode(spec).map_err(|e| anyhow!("{e}"));
    }
    let book = paths::load_recipients()?;
    let key = book
        .get(spec)
        .ok_or_else(|| anyhow!("no recipient labelled '{spec}' in the address book"))?;
    Recipient::decode(key).map_err(|e| anyhow!("{e}"))
}

struct Progress {
    json: bool,
    op: &'static str,
    total: u64,
    last: u64,
}

impl Progress {
    fn tick(&mut self, done: u64) {
        if !self.json || self.total == 0 {
            return;
        }
        // Report at most once per 4 MiB to keep the stream readable.
        if done.saturating_sub(self.last) < 4 << 20 && done < self.total {
            return;
        }
        self.last = done;
        let pct = (done as f64 / self.total as f64) * 100.0;
        println!(
            "{}",
            json!({"kind":"progress","op":self.op,"done":done,"total":self.total,
                   "pct":(pct * 100.0).round() / 100.0})
        );
        let _ = std::io::stdout().flush();
    }
}

/// Parse a recipients file: one key per line, `#` comments and blanks
/// ignored. Labels are not resolved here; a file holds literal keys.
fn read_recipients_file(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading recipients file {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if !t.starts_with("anubis1") {
            bail!(
                "{}:{}: expected a recipient beginning 'anubis1'",
                path.display(),
                i + 1
            );
        }
        out.push(t.to_string());
    }
    Ok(out)
}

// ----------------------------------------------------------------- encrypt

#[allow(clippy::too_many_arguments)]
fn cmd_encrypt(
    json: bool,
    recipient_specs: &[String],
    recipient_files: &[PathBuf],
    sign: bool,
    identity: &str,
    armor: bool,
    output: Option<&Path>,
    force: bool,
    input: &Path,
) -> Result<()> {
    let started = Instant::now();
    let src = io::Source::parse(input);

    let sink = match output {
        Some(p) => io::Sink::parse(p),
        None => match &src {
            io::Source::Stdin => io::Sink::Stdout,
            io::Source::File(p) => {
                let mut s = p.as_os_str().to_os_string();
                s.push(if armor { ".anubis.txt" } else { ".anubis" });
                io::Sink::File(PathBuf::from(s))
            }
        },
    };

    let mut count = 0usize;
    let result = (|| -> Result<u64> {
        let mut specs: Vec<String> = recipient_specs.to_vec();
        for f in recipient_files {
            specs.extend(read_recipients_file(f)?);
        }
        if specs.is_empty() {
            bail!("at least one --recipient or --recipients-file is required");
        }
        sink.guard(force)?;
        sink.guard_binary(armor)?;

        // Resolve, then drop duplicates: encrypting twice to the same key
        // only wastes 2228 header bytes.
        let mut recipients = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for spec in &specs {
            let r = resolve_recipient(spec)?;
            if seen.insert(r.to_payload()) {
                recipients.push(r);
            }
        }
        count = recipients.len();

        let signer = if sign {
            Some(load_identity(identity)?)
        } else {
            None
        };
        let opts = EncryptOptions {
            recipients: &recipients,
            signer: signer.as_ref(),
        };

        let total = src.len().unwrap_or(0);
        let mut prog = Progress {
            json,
            op: "encrypt",
            total,
            last: 0,
        };
        let mut reader = src.open()?;

        if armor {
            const CAP: usize = anubis_crypto::armor::MAX_ARMOR_BYTES;
            // Cheap lower bound first, so a huge input is refused before it is
            // encrypted into memory. Armoring never shrinks and base64 costs
            // at least 4/3, so plaintext alone already exceeding 3/4 of the
            // cap cannot possibly fit.
            if let Some(n) = src.len()
                && (n as usize).saturating_mul(4) / 3 > CAP
            {
                bail!(
                    "{n} bytes is too large to armor (armored output would exceed the {CAP} byte limit); omit --armor for binary output"
                );
            }
            // Armor cannot stream; build the container, then wrap it.
            let mut raw = io::CappedVec::new(CAP);
            let n = format::encrypt(&opts, &mut reader, &mut raw, |d| prog.tick(d))
                .map_err(|e| anyhow!("{e}"))?;
            let raw = raw.into_inner();
            let text = anubis_crypto::armor::encode(&raw);
            // Exact check against the SAME quantity decrypt measures. Checking
            // the plaintext length here instead would leave a band where
            // encrypt succeeds and the result can never be decrypted.
            if text.len() > CAP {
                bail!(
                    "armored output would be {} bytes, over the {CAP} byte limit; omit --armor for binary output",
                    text.len()
                );
            }
            sink.write_all(text.as_bytes(), force)?;
            Ok(n)
        } else {
            match &sink {
                io::Sink::File(p) => {
                    // The RAII temporary is created with `create_new` -- which
                    // refuses to follow a planted symlink -- and at 0600, so
                    // ciphertext is never briefly world-readable under a loose
                    // umask. Its final commit rechecks the no-clobber policy
                    // atomically rather than trusting the earlier guard.
                    let tmp = io::NamedTemp::create_beside(p)?;
                    let mut w = std::io::BufWriter::new(tmp);
                    let n = format::encrypt(&opts, &mut reader, &mut w, |d| prog.tick(d))
                        .map_err(|e| anyhow!("{e}"))?;
                    w.flush()?;
                    // Fail loudly if the bytes never reached the disk. A
                    // rename over unsynced data is how a full disk turns into
                    // a container that exists and cannot be decrypted.
                    let tmp = w.into_inner().map_err(|e| anyhow!("{e}"))?;
                    tmp.sync_all().context("syncing ciphertext")?;
                    tmp.commit(p, force)?;
                    Ok(n)
                }
                io::Sink::Stdout => {
                    let stdout = std::io::stdout();
                    let mut w = std::io::BufWriter::new(io::CancelWriter::new(stdout.lock()));
                    let n = format::encrypt(&opts, &mut reader, &mut w, |d| prog.tick(d))
                        .map_err(|e| anyhow!("{e}"))?;
                    w.flush()?;
                    Ok(n)
                }
            }
        }
    })();

    let ms = started.elapsed().as_millis() as u64;
    emit_result(
        json,
        "encrypt",
        &src.label(),
        Some(&sink.label()),
        sign,
        count,
        ms,
        result,
    )
}

// ----------------------------------------------------------------- decrypt

mod staged_output {
    use super::*;

    /// Private plaintext output that has not yet passed caller policy.
    ///
    /// This type implements staging only.  It intentionally has no publication
    /// method, so a refactor cannot commit a file or write stdout before converting
    /// it into [`PolicyAuthorized`].
    pub(super) struct StagedOutput(StagedKind);

    enum StagedKind {
        File {
            writer: std::io::BufWriter<io::NamedTemp>,
            destination: PathBuf,
        },
        /// An unlinked spill file for stdout. Constant memory, and it still gates
        /// publication because nothing reaches stdout until the whole container
        /// and caller policy have succeeded.
        Stdout(std::io::BufWriter<std::fs::File>),
    }

    /// A stage whose policy verdict succeeded.  The private field means
    /// [`authorize_stage`] is the only constructor.
    pub(super) struct PolicyAuthorized<S>(S);

    fn authorize_stage<S, E>(
        stage: S,
        policy: core::result::Result<(), E>,
    ) -> core::result::Result<PolicyAuthorized<S>, E> {
        policy?;
        Ok(PolicyAuthorized(stage))
    }

    #[cfg(kani)]
    mod publication_proofs {
        use super::*;

        #[derive(Default)]
        struct Probe {
            published: bool,
        }

        impl PolicyAuthorized<Probe> {
            fn publish(mut self) -> Probe {
                self.0.published = true;
                self.0
            }
        }

        /// The exact CLI policy gate yields publication authority only on `Ok`.
        /// This does not prove that the caller constructed the right policy.
        #[kani::proof]
        fn only_successful_policy_yields_cli_publication_capability() {
            let denied = authorize_stage(Probe::default(), Err::<(), u8>(1));
            assert!(denied.is_err());

            let allowed = authorize_stage(Probe::default(), Ok::<(), u8>(()));
            assert!(allowed.is_ok());
            let probe = allowed.unwrap().publish();
            assert!(probe.published);
        }
    }

    impl StagedOutput {
        pub(super) fn create(sink: &io::Sink) -> Result<Self> {
            match sink {
                io::Sink::File(destination) => Ok(Self(StagedKind::File {
                    writer: std::io::BufWriter::new(io::NamedTemp::create_beside(destination)?),
                    destination: destination.clone(),
                })),
                io::Sink::Stdout => Ok(Self(StagedKind::Stdout(std::io::BufWriter::new(
                    io::spill_file().context(
                        "creating private disk-backed staging for plaintext output on stdout",
                    )?,
                )))),
            }
        }

        pub(super) fn writer(&mut self) -> &mut dyn Write {
            match &mut self.0 {
                StagedKind::File { writer, .. } => writer,
                StagedKind::Stdout(writer) => writer,
            }
        }

        pub(super) fn authorize(self, policy: Result<()>) -> Result<PolicyAuthorized<Self>> {
            authorize_stage(self, policy)
        }
    }

    impl PolicyAuthorized<StagedOutput> {
        /// The only plaintext publication capability in the CLI decrypt path.
        pub(super) fn publish(self, force: bool) -> Result<()> {
            match self.0.0 {
                StagedKind::File {
                    writer,
                    destination,
                } => {
                    let tmp = writer.into_inner().map_err(|e| anyhow!("{e}"))?;
                    tmp.sync_all().context("syncing plaintext")?;
                    tmp.commit(&destination, force)?;
                }
                StagedKind::Stdout(writer) => {
                    let mut file = writer.into_inner().map_err(|e| anyhow!("{e}"))?;
                    // The spill file is already unlinked, so failing here leaves
                    // nothing behind and emits nothing.
                    io::check_cancelled()?;
                    file.rewind()?;
                    let mut stdout = io::CancelWriter::new(std::io::stdout().lock());
                    std::io::copy(&mut file, &mut stdout)?;
                    stdout.flush()?;
                }
            }
            Ok(())
        }
    }
}

use staged_output::StagedOutput;

#[allow(clippy::too_many_arguments)]
fn cmd_decrypt(
    json: bool,
    identity: Option<&str>,
    output: Option<&Path>,
    force: bool,
    require_signature: bool,
    signer_pin: Option<&str>,
    expected_content_id: Option<&ExpectedContentId>,
    input: &Path,
) -> Result<()> {
    let started = Instant::now();
    let src = io::Source::parse(input);

    let sink = match output {
        Some(p) => io::Sink::parse(p),
        None => match &src {
            io::Source::Stdin => io::Sink::Stdout,
            io::Source::File(p) => {
                let s = p.to_string_lossy();
                let stem = s
                    .strip_suffix(".anubis.txt")
                    .or_else(|| s.strip_suffix(".anubis"))
                    .unwrap_or("plaintext.out");
                io::Sink::File(PathBuf::from(stem))
            }
        },
    };

    let mut signed = false;
    let mut signer_fp: Option<String> = None;
    let mut content_id: Option<format::ContentId> = None;
    let result = (|| -> Result<u64> {
        sink.guard(force)?;

        let ids: Vec<Identity> = match identity {
            Some(name) => vec![load_identity(name)?],
            None => {
                let all = all_identities()?;
                if all.is_empty() {
                    bail!("no identities found (run: anubis keygen)");
                }
                all.into_iter().map(|(_, id)| id).collect()
            }
        };

        let total = src.len().unwrap_or(0);
        let mut prog = Progress {
            json,
            op: "decrypt",
            total,
            last: 0,
        };

        let mut probe = [0u8; 512];
        let mut reader = src.open()?;
        let n = fill(&mut reader, &mut probe)?;
        let head = &probe[..n];
        let armored = anubis_crypto::armor::looks_armored(head);

        // Stream into private staging and obtain the publication capability
        // only after cryptography and caller policy both succeed. Buffering in
        // memory would gate publication too but would scale with plaintext;
        // these disk-backed stages keep memory bounded.
        let mut out = StagedOutput::create(&sink)?;

        let dec = {
            let mut w = out.writer();
            let r = if armored {
                let raw = read_armored(head, &mut reader)?;
                let len = raw.len() as u64;
                format::decrypt_provisional(&ids, &raw[..], len, &mut w, |d| prog.tick(d))
            } else {
                let joined = head.chain(reader);
                match src.len() {
                    Some(len) => {
                        format::decrypt_provisional(&ids, joined, len, &mut w, |d| prog.tick(d))
                    }
                    None => format::decrypt_unsized_provisional(&ids, joined, &mut w, |d| {
                        prog.tick(d);
                    }),
                }
            };
            r.map_err(|e| anyhow!("{e}"))?
        };

        signed = dec.verified_key.is_some();
        content_id = Some(dec.content_id);
        signer_fp = dec
            .verified_key
            .as_ref()
            .map(|k| anubis_crypto::keys::fingerprint(k));

        // Signature policy is enforced BEFORE any plaintext is published.
        // A valid signature by an unknown key is not the same as a signature
        // by the key you expected, so --signer pins the specific signer.
        let policy = (|| -> Result<()> {
            if let Some(want) = expected_content_id {
                let got = content_id
                    .as_ref()
                    .expect("successful decryption always has a content ID");
                let equal = bool::from(<[u8] as subtle::ConstantTimeEq>::ct_eq(
                    got.as_slice(),
                    want.0.as_slice(),
                ));
                if !equal {
                    bail!(
                        "container content ID {} does not match expected {}",
                        content_id_hex(got),
                        content_id_hex(&want.0)
                    );
                }
            }
            if (require_signature || signer_pin.is_some()) && !signed {
                bail!(
                    "container is unsigned and a signature was required \
                     (--require-signature / --signer)"
                );
            }
            if let Some(want) = signer_pin {
                let got = signer_fp.as_deref().unwrap_or("");
                let want_n = want.trim().to_ascii_uppercase().replace('-', "");
                let got_n = got.replace('-', "");
                // Constant time is not strictly required -- a fingerprint is a
                // hash of a public key -- but a variable-time compare on a
                // security decision is a thing reviewers rightly stop on.
                let eq = want_n.len() == got_n.len()
                    && bool::from(<[u8] as subtle::ConstantTimeEq>::ct_eq(
                        want_n.as_bytes(),
                        got_n.as_bytes(),
                    ));
                if !eq {
                    bail!("signed by {got}, not the pinned signer {want}");
                }
            }
            Ok(())
        })();

        let authorized = out.authorize(policy)?;
        authorized.publish(force)?;
        Ok(dec.bytes)
    })();

    let ms = started.elapsed().as_millis() as u64;
    emit_result_signed(
        json,
        "decrypt",
        &src.label(),
        Some(&sink.label()),
        signed,
        signer_fp.as_deref(),
        content_id.as_ref(),
        0,
        ms,
        result,
    )
}

/// Read an armored container, bounding the read itself.
///
/// The bound must be applied DURING the read. Reading to the end and then
/// checking the length is not a memory bound: the allocation the cap exists
/// to prevent has already happened. `+ 1` makes "exactly at the cap"
/// distinguishable from "over it".
fn read_armored<R: Read>(head: &[u8], reader: &mut R) -> Result<Vec<u8>> {
    const CAP: usize = anubis_crypto::armor::MAX_ARMOR_BYTES;
    let mut rest = Vec::from(head);
    reader
        .take((CAP + 1 - rest.len().min(CAP)) as u64)
        .read_to_end(&mut rest)?;
    if rest.len() > CAP {
        bail!("armored input exceeds {CAP} bytes; use binary for large files");
    }
    let text = String::from_utf8(rest).map_err(|_| anyhow!("armored input is not valid UTF-8"))?;
    anubis_crypto::armor::decode(&text).map_err(|e| anyhow!("{e}"))
}

/// Read until the buffer is full or input ends.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn content_id_hex(content_id: &format::ContentId) -> String {
    let mut encoded = String::with_capacity(content_id.len().saturating_mul(2));
    for byte in content_id {
        std::fmt::Write::write_fmt(&mut encoded, format_args!("{byte:02x}"))
            .expect("writing to a String cannot fail");
    }
    encoded
}

#[allow(clippy::too_many_arguments)]
fn emit_result(
    json: bool,
    op: &str,
    input: &str,
    out: Option<&String>,
    signed: bool,
    recipients: usize,
    ms: u64,
    result: Result<u64>,
) -> Result<()> {
    emit_result_signed(
        json, op, input, out, signed, None, None, recipients, ms, result,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_result_signed(
    json: bool,
    op: &str,
    input: &str,
    out: Option<&String>,
    signed: bool,
    signer: Option<&str>,
    content_id: Option<&format::ContentId>,
    recipients: usize,
    ms: u64,
    result: Result<u64>,
) -> Result<()> {
    let ts = audit::now_iso();
    match result {
        Ok(bytes) => {
            let summary = format!(
                "{op} {input} ({bytes} bytes{})",
                match (signed, signer) {
                    (true, Some(fp)) => format!(", signed by {fp}"),
                    (true, None) => ", signed".into(),
                    (false, _) => String::new(),
                }
            );
            audit::append(&audit::Record {
                ts,
                op: op.into(),
                path: input.to_string(),
                out: out.cloned(),
                bytes,
                ms,
                ok: true,
                signed,
                recipients,
                error: None,
                summary,
            });
            if json {
                println!(
                    "{}",
                    json!({"kind":"result","op":op,"ok":true,
                    "path":input,
                    "out":out,
                    "bytes":bytes,"ms":ms,"signed":signed,
                    "signer_fingerprint":signer,
                    "content_id":content_id.map(content_id_hex),
                    "recipients":recipients,"error":null,
                    // A successful decrypt means the header MAC verified;
                    // reaching this point is only possible after that check.
                    "header_mac_ok": if op == "decrypt" { json!(true) } else { json!(null) },
                    // And the same reasoning for the signature: a signed
                    // container cannot decrypt successfully unless its
                    // signature verified first. Unsigned stays null --
                    // nothing was checked, so nothing passed -- and
                    // encrypt stays null because making a signature is
                    // not checking one.
                    "signature_ok": if op == "decrypt" && signed {
                        json!(true)
                    } else {
                        json!(null)
                    }})
                );
            } else {
                // Attribution matters: "signature verified" without naming the
                // signer invites the reader to assume it was someone they trust.
                let note = match (signed, signer) {
                    (true, Some(fp)) if op == "decrypt" => {
                        format!(", signature verified, signer {fp}")
                    }
                    (true, _) if op == "encrypt" => ", signed".into(),
                    (true, _) => ", signature verified".into(),
                    (false, _) => String::new(),
                };
                let line = format!(
                    "{op}: {input} -> {} ({bytes} bytes, {ms} ms{note})",
                    out.map_or("", |s| s.as_str()),
                );
                // Human output moves to stderr when the payload owns stdout.
                if out.is_some_and(|s| s == "-") {
                    eprintln!("{line}");
                } else {
                    println!("{line}");
                }
            }
            Ok(())
        }
        Err(e) => {
            let msg = format!("{e:#}");
            audit::append(&audit::Record {
                ts,
                op: op.into(),
                path: input.to_string(),
                out: None,
                bytes: 0,
                ms,
                ok: false,
                signed,
                recipients,
                error: Some(msg.clone()),
                summary: format!("{op} FAILED on {input}: {msg}"),
            });
            Err(e)
        }
    }
}

// ----------------------------------------------------------------- inspect

fn cmd_inspect(json: bool, input: &Path) -> Result<()> {
    let src = io::Source::parse(input);

    // Inspect must understand everything decrypt accepts, or a user who can
    // decrypt an armored container cannot inspect it.
    let mut probe = [0u8; 512];
    let mut reader = src.open()?;
    let n = fill(&mut reader, &mut probe)?;
    let head = &probe[..n];

    if json {
        let info = if anubis_crypto::armor::looks_armored(head) {
            let raw = read_armored(head, &mut reader)?;
            let len = raw.len() as u64;
            format::inspect_with_content_id(&raw[..], len).map_err(|e| anyhow!("{e}"))?
        } else {
            let joined = head.chain(reader);
            match src.len() {
                Some(len) => {
                    format::inspect_with_content_id(joined, len).map_err(|e| anyhow!("{e}"))?
                }
                None => format::inspect_unsized(joined).map_err(|e| anyhow!("{e}"))?,
            }
        };
        println!(
            "{}",
            json!({
                "kind": "inspect",
                "path": src.label(),
                "format": info.format,
                "stanzas": [{"type": format::STANZA_HYBRID, "recipients": info.recipients}],
                "recipients": info.recipients,
                "signed": info.signed,
                "signer_fingerprint": info.verifying_key.as_ref()
                    .map(|k| anubis_crypto::keys::fingerprint(k)),
                "content_id": content_id_hex(&info.content_id),
                "header_bytes": info.header_bytes,
                "payload_bytes": info.payload_bytes,
                "chunks": info.chunks,
                "header_mac_ok": null,
                // Present but unchecked. JSON inspection reads the whole
                // payload to bind content_id, but deliberately does not perform
                // ML-DSA verification -- run `anubis verify` for that answer.
                // Null keeps "not checked here" distinct from "checked and passed".
                "signature_ok": null,
            })
        );
        return Ok(());
    }

    let info = if anubis_crypto::armor::looks_armored(head) {
        let raw = read_armored(head, &mut reader)?;
        let len = raw.len() as u64;
        format::inspect(&raw[..], len).map_err(|e| anyhow!("{e}"))?
    } else {
        let joined = head.chain(reader);
        match src.len() {
            Some(len) => format::inspect(joined, len).map_err(|e| anyhow!("{e}"))?,
            None => format::inspect_unsized(joined)
                .map(Into::into)
                .map_err(|e| anyhow!("{e}"))?,
        }
    };
    println!("format:      {}", info.format);
    println!("recipients:  {}", info.recipients);
    println!("signed:      {}", info.signed);
    if let Some(k) = &info.verifying_key {
        println!("signer:      {}", anubis_crypto::keys::fingerprint(k));
    }
    println!("header:      {} bytes", info.header_bytes);
    println!(
        "payload:     {} bytes in {} chunks",
        info.payload_bytes, info.chunks
    );
    println!("\nHeader authenticity is only verifiable with a key; run decrypt to check it.");
    if info.signed {
        println!("The signature is present but NOT checked here; run `anubis verify` to check it.");
    }
    Ok(())
}

/// Does an operator-supplied fingerprint name this key?
///
/// Separators are cosmetic (FORMAT.md 11.4), so a pin typed without dashes is
/// the same pin. The comparison is constant time: a fingerprint is a hash of a
/// public key and leaks nothing, but a variable-time compare on a security
/// decision is a thing reviewers rightly stop on, and `decrypt` has always
/// done it this way. Both commands now call this, so they cannot drift.
fn fp_matches(want: &str, got: &str) -> bool {
    let want_n = want.trim().to_ascii_uppercase().replace('-', "");
    let got_n = got.trim().to_ascii_uppercase().replace('-', "");
    want_n.len() == got_n.len()
        && bool::from(<[u8] as subtle::ConstantTimeEq>::ct_eq(
            want_n.as_bytes(),
            got_n.as_bytes(),
        ))
}

// ------------------------------------------------------------------ verify

/// Check a container's signature without a key.
///
/// The signature covers `SHA-512(header || payload ciphertext)` and the
/// verifying key travels in the header, so this needs no identity and
/// decrypts nothing. It is the command a third party runs on a container they
/// cannot read, to establish that the holder of a particular ML-DSA-87 key
/// produced these exact bytes.
///
/// Exit status is the answer: 0 only when a signature is present and valid.
/// An unsigned container exits non-zero, because "nothing to check" is not a
/// pass -- any recipient can strip a signature, so its absence says nothing
/// about whether the sender signed.
fn cmd_verify(json: bool, want_signer: Option<&str>, input: &Path) -> Result<()> {
    let src = io::Source::parse(input);

    let mut probe = [0u8; 512];
    let mut reader = src.open()?;
    let n = fill(&mut reader, &mut probe)?;
    let head = &probe[..n];

    // Armor and pipes both have to be resolved to a known length first: the
    // payload span is computed by subtracting the header and the fixed
    // trailer from the total.
    let info = if anubis_crypto::armor::looks_armored(head) {
        let raw = read_armored(head, &mut reader)?;
        let len = raw.len() as u64;
        format::verify_report(&raw[..], len)
    } else {
        let joined = head.chain(reader);
        match src.len() {
            Some(len) => format::verify_report(joined, len),
            // A pipe has no length. Stream it through the delay buffer rather
            // than reading it into memory: this command is pointed at
            // containers from strangers, and "buffer whatever arrives" is an
            // unauthenticated memory-exhaustion invitation on exactly the
            // input that deserves it least.
            None => format::verify_unsized_report(joined),
        }
    };

    let info = match info {
        Ok(info) => info,
        Err(e) => {
            // Cryptographic mismatches are returned as bound reports above.
            // Reaching this branch means the check could not be made at all:
            // malformed or structurally truncated input has no signer/content
            // verdict, and must remain null rather than being called invalid.
            if json {
                // The verify record IS this command's result record; main must
                // not print a second one after it. A consumer parsing stdout
                // as one document would otherwise fail on exactly the outcomes
                // this command exists to report.
                println!(
                    "{}",
                    json!({
                        "kind": "verify",
                        "path": src.label(),
                        "ok": false,
                        "format": null,
                        "signed": null,
                        "signature_ok": null,
                        "signer_fingerprint": null,
                        "content_id": null,
                        "signer_pinned": want_signer,
                        "signer_matches": null,
                        "recipients": null,
                        "header_bytes": null,
                        "payload_bytes": null,
                        "chunks": null,
                        "header_mac_ok": null,
                        "error": e.to_string(),
                    })
                );
            }
            return Err(VerifyFailed(anyhow!("{e}")).into());
        }
    };

    let fp = info
        .verifying_key
        .as_ref()
        .map(|k| anubis_crypto::keys::fingerprint(k));

    // Pinning is checked after the cryptography, and a mismatch is a failure
    // even though the signature itself is sound: the caller asked whether a
    // specific key signed this, and the answer is no.
    let pin_ok = match (want_signer, fp.as_deref()) {
        (None, _) => true,
        (Some(want), Some(have)) => fp_matches(want, have),
        (Some(_), None) => false,
    };

    let ok = info.signature_ok == Some(true) && pin_ok;
    let verdict_error = if info.signature_ok == Some(false) {
        Some("signature verification failed")
    } else if !info.signed {
        Some("container is not signed")
    } else if !pin_ok {
        Some("signature signer does not match pinned signer")
    } else {
        None
    };

    if json {
        println!(
            "{}",
            json!({
                "kind": "verify",
                "path": src.label(),
                "ok": ok,
                "format": info.format,
                "signed": info.signed,
                "signature_ok": info.signature_ok,
                "signer_fingerprint": fp,
                "content_id": content_id_hex(&info.content_id),
                "signer_pinned": want_signer,
                "signer_matches": want_signer.map(|_| pin_ok),
                "recipients": info.recipients,
                "header_bytes": info.header_bytes,
                "payload_bytes": info.payload_bytes,
                "chunks": info.chunks,
                "error": verdict_error,
                // The header MAC is keyed from the file key, so this command
                // -- which holds no key -- structurally cannot check it.
                "header_mac_ok": null,
            })
        );
    } else if !info.signed {
        println!("signature:   ABSENT");
        println!("\nThis container carries no signature. That is not the same as");
        println!("unsigned-by-the-sender: any recipient can strip a signature, so");
        println!("absence carries no information. Require one up front instead.");
    } else if info.signature_ok == Some(false) {
        println!("signature:   INVALID (ML-DSA-87)");
        println!("signer:      {}", fp.as_deref().unwrap_or("--"));
        println!(
            "payload:     {} bytes in {} chunks",
            info.payload_bytes, info.chunks
        );
        println!("\nThe container bytes and embedded signer are identified, but the");
        println!("signature does not authenticate those bytes.");
    } else {
        println!("signature:   VALID (ML-DSA-87)");
        println!("signer:      {}", fp.as_deref().unwrap_or("--"));
        println!(
            "payload:     {} bytes in {} chunks",
            info.payload_bytes, info.chunks
        );
        if let Some(want) = want_signer {
            println!(
                "pinned:      {}",
                if pin_ok { "MATCHES" } else { "MISMATCH" }
            );
            let _ = want;
        }
        println!("\nA valid signature proves the holder of that key produced these exact");
        println!("bytes. It does not say who that is: compare the fingerprint against a");
        println!("value you confirmed out of band.");
    }

    // Exit status is derived from `ok` -- the same value the JSON reports --
    // so the two can never disagree. Deriving it from `signed` instead would
    // key success on a signature being PRESENT rather than VALID, which is the
    // precise confusion this command exists to end.
    if ok {
        return Ok(());
    }
    if !info.signed {
        return Err(VerifyFailed(anyhow!("container is not signed")).into());
    }
    if info.signature_ok == Some(false) {
        return Err(VerifyFailed(anyhow!("signature did not verify")).into());
    }
    if !pin_ok {
        return Err(VerifyFailed(anyhow!(
            "signature is valid but by {}, not the pinned signer",
            fp.as_deref().unwrap_or("an unknown key")
        ))
        .into());
    }
    Err(VerifyFailed(anyhow!("signature verification produced no verdict")).into())
}

// ------------------------------------------------------------------ status

fn cmd_status(json: bool) -> Result<()> {
    let mut identities = Vec::new();
    for (name, id) in all_identities()? {
        let rec = id.to_recipient().map_err(|e| anyhow!("{e}"))?;
        let path = paths::identity_path(&name)?;
        let created = std::fs::metadata(&path)
            .and_then(|m| m.created().or_else(|_| m.modified()))
            .map(|t| {
                let dt: chrono::DateTime<chrono::Utc> = t.into();
                dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            })
            .unwrap_or_default();
        identities.push(json!({
            "name": name,
            "path": path.display().to_string(),
            "recipient": rec.encode().map_err(|e| anyhow!("{e}"))?,
            "fingerprint": rec.fingerprint(),
            "signing_fingerprint": anubis_crypto::keys::fingerprint(
                id.verifying_key().encode().as_slice(),
            ),
            "created": created,
            "signing": true,
        }));
    }

    let mut recipients = Vec::new();
    for (label, key) in paths::load_recipients()? {
        let fp = Recipient::decode(&key)
            .map(|r| r.fingerprint())
            .unwrap_or_else(|_| "invalid".into());
        recipients.push(json!({"label": label, "key": key, "fingerprint": fp}));
    }

    let recent: Vec<_> = audit::recent(25)?
        .into_iter()
        .map(|r| {
            json!({"ts": r.ts, "op": r.op, "path": r.path, "out": r.out,
                   "bytes": r.bytes, "ms": r.ms, "ok": r.ok, "signed": r.signed,
                   "recipients": r.recipients, "error": r.error})
        })
        .collect();
    let (enc, dec, failed) = audit::counts()?;

    let obj = json!({
        "kind": "status",
        "status_schema": "anubis-status/assurance-v1",
        "version": env!("CARGO_PKG_VERSION"),
        "suite": {
            "kem": SUITE_KEM,
            "sig": SUITE_SIG,
            "aead": SUITE_AEAD,
            "kdf": SUITE_KDF,
            // Kept for consumers of the original status schema. This means
            // only that algorithms are specified by those publications; the
            // explicit fields below carry the validation boundary.
            "fips": ["203", "204"],
            "nist_standards": ["FIPS 203", "FIPS 204"],
            "pq_security_category": 5,
            "algorithm_profile": "portable-v3",
            "approved_only_mode": false,
            "fips_140_3_validated": false,
            "fips_140_3_certificate": null,
            "pure_rust": true,
            "format": format::MAGIC,
        },
        "identities": identities,
        "recipients": recipients,
        "recent": recent,
        "counts": {"encrypt": enc, "decrypt": dec, "failed": failed},
        "generated": audit::now_iso(),
    });

    if json {
        println!("{obj}");
    } else {
        println!("ANUBIS {}", env!("CARGO_PKG_VERSION"));
        println!("suite:       {SUITE_KEM} / {SUITE_SIG} / {SUITE_AEAD}");
        println!("format:      {}", format::MAGIC);
        println!("assurance:   Category 5 PQ parameters; not FIPS 140-3 validated");
        println!(
            "identities:  {}",
            obj["identities"].as_array().map_or(0, Vec::len)
        );
        println!(
            "recipients:  {}",
            obj["recipients"].as_array().map_or(0, Vec::len)
        );
        println!("operations:  {enc} encrypted, {dec} decrypted, {failed} failed");
    }
    Ok(())
}

// --------------------------------------------------------------- recipient

fn cmd_recipient(json: bool, action: &RecipientAction) -> Result<()> {
    match action {
        RecipientAction::List => {
            let book = paths::load_recipients()?;
            if json {
                let items: Vec<_> = book
                    .iter()
                    .map(|(label, key)| {
                        let fp = Recipient::decode(key)
                            .map(|r| r.fingerprint())
                            .unwrap_or_else(|_| "invalid".into());
                        json!({"label": label, "key": key, "fingerprint": fp})
                    })
                    .collect();
                println!("{}", json!({"kind": "recipients", "recipients": items}));
            } else {
                for (label, key) in &book {
                    let fp = Recipient::decode(key)
                        .map(|r| r.fingerprint())
                        .unwrap_or_else(|_| "invalid".into());
                    println!("{label:<16} {fp}");
                    println!("{:<16} {key}", "");
                }
            }
            Ok(())
        }
        RecipientAction::Add { label, key } => {
            paths::check_name(label)?;
            let rec = Recipient::decode(key).map_err(|e| anyhow!("{e}"))?;
            let mut book = paths::load_recipients()?;
            book.insert(label.clone(), key.clone());
            paths::save_recipients(&book)?;
            if json {
                println!(
                    "{}",
                    json!({"kind":"result","op":"recipient.add","ok":true,
                           "label":label,"fingerprint":rec.fingerprint(),"error":null})
                );
            } else {
                println!("added '{label}' ({})", rec.fingerprint());
            }
            Ok(())
        }
        RecipientAction::Remove { label } => {
            let mut book = paths::load_recipients()?;
            if book.remove(label).is_none() {
                bail!("no recipient labelled '{label}'");
            }
            paths::save_recipients(&book)?;
            if json {
                println!(
                    "{}",
                    json!({"kind":"result","op":"recipient.remove","ok":true,
                           "label":label,"error":null})
                );
            } else {
                println!("removed '{label}'");
            }
            Ok(())
        }
    }
}
