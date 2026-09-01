//! The append-only operation log.
//!
//! Each line is one JSON object. The `summary` and `ok` fields exist so
//! SIA, an external memory daemon such as SIA, can tail the stream as a custom sense
//! and turn encryption activity into recallable memory. See the SIA section
//! of the README.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub ts: String,
    pub op: String,
    pub path: String,
    #[serde(default)]
    pub out: Option<String>,
    pub bytes: u64,
    pub ms: u64,
    pub ok: bool,
    #[serde(default)]
    pub signed: bool,
    #[serde(default)]
    pub recipients: usize,
    #[serde(default)]
    pub error: Option<String>,
    /// Human-readable one-liner. This is the field SIA indexes.
    pub summary: String,
}

pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn open_log(read: bool, append: bool, create: bool) -> std::io::Result<File> {
    crate::paths::ensure_state_dir().map_err(std::io::Error::other)?;
    let path = crate::paths::audit_path().map_err(std::io::Error::other)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(read).append(append).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::other("audit path is not a regular file"));
        }
        if metadata.nlink() != 1 {
            return Err(std::io::Error::other("audit path must not be hard-linked"));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let file = options.open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("audit path is not a regular file"));
        }
        Ok(file)
    }
}

fn read_log() -> Result<Option<String>> {
    let mut file = match open_log(true, false, false) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(Some(text))
}

/// Append one record. Never fails the operation it is recording.
pub fn append(rec: &Record) {
    let Ok(line) = serde_json::to_string(rec) else {
        return;
    };
    // 0600 explicitly, not whatever the umask happens to be. This file names
    // every path that has ever been encrypted or decrypted on this machine --
    // no key material, but a map of what the operator considered worth
    // protecting, which is not something to leave world readable.
    if let Ok(mut f) = open_log(false, true, true) {
        let _ = writeln!(f, "{line}");
    }
}

/// Read the most recent `limit` records, newest first.
pub fn recent(limit: usize) -> Result<Vec<Record>> {
    let Some(text) = read_log()? else {
        return Ok(Vec::new());
    };
    let mut out: Vec<Record> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Record>(l).ok())
        .collect();
    out.reverse();
    out.truncate(limit);
    Ok(out)
}

/// Totals across the whole log.
pub fn counts() -> Result<(usize, usize, usize)> {
    let Some(text) = read_log()? else {
        return Ok((0, 0, 0));
    };
    let mut enc = 0;
    let mut dec = 0;
    let mut failed = 0;
    for line in text.lines() {
        let Ok(r) = serde_json::from_str::<Record>(line) else {
            continue;
        };
        if !r.ok {
            failed += 1;
        } else if r.op == "encrypt" {
            enc += 1;
        } else if r.op == "decrypt" {
            dec += 1;
        }
    }
    Ok((enc, dec, failed))
}
