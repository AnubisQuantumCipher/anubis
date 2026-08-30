//! Input and output plumbing, including `-` for stdin/stdout and armor.

use anyhow::{Context, Result, bail};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

/// Where bytes come from.
pub enum Source {
    File(PathBuf),
    Stdin,
}

/// Where bytes go.
pub enum Sink {
    File(PathBuf),
    Stdout,
}

impl Source {
    pub fn parse(spec: &Path) -> Self {
        if spec.as_os_str() == "-" {
            Self::Stdin
        } else {
            Self::File(spec.to_path_buf())
        }
    }

    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::File(p) => p.display().to_string(),
            Self::Stdin => "-".into(),
        }
    }

    /// Byte length when knowable. Pipes return `None`.
    pub fn len(&self) -> Option<u64> {
        match self {
            Self::File(p) => std::fs::metadata(p).ok().map(|m| m.len()),
            Self::Stdin => None,
        }
    }

    pub fn open(&self) -> Result<Box<dyn Read>> {
        match self {
            Self::File(p) => Ok(Box::new(
                std::fs::File::open(p).with_context(|| format!("reading {}", p.display()))?,
            )),
            Self::Stdin => Ok(Box::new(std::io::stdin().lock())),
        }
    }
}

impl Sink {
    pub fn parse(spec: &Path) -> Self {
        if spec.as_os_str() == "-" {
            Self::Stdout
        } else {
            Self::File(spec.to_path_buf())
        }
    }

    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::File(p) => p.display().to_string(),
            Self::Stdout => "-".into(),
        }
    }

    /// Refuse to clobber an existing file unless forced.
    pub fn guard(&self, force: bool) -> Result<()> {
        if let Self::File(p) = self
            && p.exists()
            && !force
        {
            bail!("{} already exists; pass --force to overwrite", p.display());
        }
        Ok(())
    }

    /// Refuse to spray binary at a terminal.
    pub fn guard_binary(&self, armored: bool) -> Result<()> {
        if matches!(self, Self::Stdout) && !armored && std::io::stdout().is_terminal() {
            bail!(
                "refusing to write binary ciphertext to a terminal; \
                 redirect to a file, pipe it, or pass --armor"
            );
        }
        Ok(())
    }

    pub fn write_all(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::File(p) => {
                write_atomic(p, bytes)?;
            }
            Self::Stdout => {
                let mut out = std::io::stdout().lock();
                out.write_all(bytes)?;
                out.flush()?;
            }
        }
        Ok(())
    }
}

/// Write via a temporary file and rename, so a failure never leaves a
/// half-written output in place of real data.
///
/// The temporary is created with `create_new` at mode 0600. `create_new`
/// refuses to follow an existing symlink, and creating at 0600 rather than
/// chmod-ing afterwards closes the window in which the content is readable
/// under a permissive umask. Output therefore lands at 0600: plaintext from
/// a decryption tool is sensitive by default.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_beside(path);
    // A stale temporary from a crashed run must not block the write.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all().context("syncing temporary")?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("finalising {}", path.display()))?;
    Ok(())
}

/// Create a fresh temporary file beside `path`, at mode 0600.
///
/// `create_new` refuses to follow a pre-planted symlink, and creating at
/// 0600 avoids the window where content is readable under a loose umask.
pub fn create_secure_temp(path: &Path) -> Result<(std::fs::File, PathBuf)> {
    let tmp = tmp_beside(path);
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    Ok((f, tmp))
}

/// An unlinked scratch file in the temp directory.
///
/// Created then immediately unlinked, so the descriptor stays usable while
/// the file has no name: nothing is visible to other processes and nothing
/// survives a crash. Used to hold plaintext destined for stdout so that
/// output stays constant-memory while still being withheld until the whole
/// container has verified.
pub fn spill_file() -> Result<std::fs::File> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(".anubis-spill.{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    std::fs::remove_file(&path).ok();
    Ok(f)
}

/// A temporary path in the same directory, so the rename stays on one
/// filesystem and therefore stays atomic.
#[must_use]
pub fn tmp_beside(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("out")),
    );
    name.push(format!(".{}.partial", std::process::id()));
    path.with_file_name(name)
}
