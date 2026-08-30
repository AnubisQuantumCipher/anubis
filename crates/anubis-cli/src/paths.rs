//! Filesystem layout and the recipient address book.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// `~/.config/anubis`
pub fn config_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config").join("anubis"))
}

/// `~/.config/anubis/identities`
pub fn identities_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("identities"))
}

/// `~/.local/state/anubis`
pub fn state_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("anubis"))
}

pub fn audit_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("audit.jsonl"))
}

pub fn recipients_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("recipients.toml"))
}

/// Create the directory tree, keeping secrets at mode 0700.
pub fn ensure_dirs() -> Result<()> {
    let ids = identities_dir()?;
    std::fs::create_dir_all(&ids).with_context(|| format!("creating {}", ids.display()))?;
    std::fs::create_dir_all(state_dir()?)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&ids)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&ids, perms)?;
    }
    Ok(())
}

/// Validate a name used as a filename component.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("name must be non-empty and use only letters, digits, '-' or '_'");
    }
    Ok(())
}

pub fn identity_path(name: &str) -> Result<PathBuf> {
    check_name(name)?;
    Ok(identities_dir()?.join(format!("{name}.key")))
}

/// On-disk shape of the address book.
///
/// Declared once as a serde type so the reader and writer cannot disagree.
/// Hand-formatting the TOML and parsing it back through `toml::Value` is what
/// previously produced a file the tool could write but not read.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Book {
    #[serde(default)]
    recipients: BTreeMap<String, String>,
}

/// Load the recipient address book.
pub fn load_recipients() -> Result<BTreeMap<String, String>> {
    let path = recipients_path()?;
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let book: Book =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(book.recipients)
}

/// Write the recipient address book atomically.
pub fn save_recipients(map: &BTreeMap<String, String>) -> Result<()> {
    ensure_dirs()?;
    let book = Book {
        recipients: map.clone(),
    };
    let body = toml::to_string_pretty(&book).context("serialising recipients")?;
    let text = format!("# ANUBIS recipient address book\n{body}");

    let path = recipients_path()?;
    // Through the same atomic, symlink-refusing, 0600 helper as everything
    // else. The hand-rolled temporary this replaces sat at a fixed and fully
    // predictable path and was created without O_EXCL.
    crate::io::write_atomic(&path, text.as_bytes())?;
    Ok(())
}
