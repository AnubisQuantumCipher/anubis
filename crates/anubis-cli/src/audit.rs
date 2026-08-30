//! The append-only operation log.
//!
//! Each line is one JSON object. The `summary` and `ok` fields exist so
//! SIA, this machine's memory daemon, can tail the stream as a custom sense
//! and turn encryption activity into recallable memory. See the SIA section
//! of the README.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::Write;

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

/// Append one record. Never fails the operation it is recording.
pub fn append(rec: &Record) {
    let Ok(path) = crate::paths::audit_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(line) = serde_json::to_string(rec) else {
        return;
    };
    // 0600 explicitly, not whatever the umask happens to be. This file names
    // every path that has ever been encrypted or decrypted on this machine --
    // no key material, but a map of what the operator considered worth
    // protecting, which is not something to leave world readable.
    let mut open = std::fs::OpenOptions::new();
    open.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    if let Ok(mut f) = open.open(&path) {
        let _ = writeln!(f, "{line}");
    }
}

/// Read the most recent `limit` records, newest first.
pub fn recent(limit: usize) -> Result<Vec<Record>> {
    let path = crate::paths::audit_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)?;
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
    let path = crate::paths::audit_path()?;
    if !path.exists() {
        return Ok((0, 0, 0));
    }
    let text = std::fs::read_to_string(&path)?;
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
