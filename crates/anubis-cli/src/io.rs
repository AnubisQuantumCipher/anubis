//! Input and output plumbing, including `-` for stdin/stdout and armor.

use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static TERMINATION_REQUESTED: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Install cooperative process-termination handling.
///
/// The signal handler performs only an atomic store. Regular Rust control flow
/// observes the flag at I/O and publication boundaries, returns an error, and
/// lets owned [`NamedTemp`] values drop normally instead of bypassing cleanup.
pub fn install_termination_handler() -> Result<()> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag))
        .context("installing SIGTERM handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))
        .context("installing SIGINT handler")?;
    TERMINATION_REQUESTED
        .set(flag)
        .map_err(|_| anyhow::anyhow!("termination handler was already installed"))?;
    Ok(())
}

/// Fail at a normal Rust boundary after a termination request.
pub fn check_cancelled() -> std::io::Result<()> {
    if TERMINATION_REQUESTED
        .get()
        .is_some_and(|flag| flag.load(Ordering::SeqCst))
    {
        // `Read::read_to_end` and `Write::write_all` retry Interrupted
        // automatically. Returning that kind here would turn cancellation
        // into a hot loop at exactly the boundary that should unwind and
        // drop private temporaries.
        Err(std::io::Error::other("operation cancelled by signal"))
    } else {
        Ok(())
    }
}

/// Reader that turns a signal flag into an ordinary error so destructors run.
struct CancelReader<R> {
    inner: R,
}

impl<R: Read> Read for CancelReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        check_cancelled()?;
        let result = self.inner.read(buf);
        check_cancelled()?;
        result
    }
}

/// Writer that turns a signal flag into an ordinary error so destructors run.
pub struct CancelWriter<W> {
    inner: W,
}

impl<W> CancelWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> Write for CancelWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        check_cancelled()?;
        let result = self.inner.write(buf);
        check_cancelled()?;
        result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        check_cancelled()?;
        let result = self.inner.flush();
        check_cancelled()?;
        result
    }
}

/// In-memory writer with a hard byte ceiling.
///
/// Armor is necessarily materialized before encoding, but hostile or
/// unknown-length input must not turn that requirement into unbounded growth.
pub struct CappedVec {
    bytes: Vec<u8>,
    cap: usize,
}

impl CappedVec {
    pub fn new(cap: usize) -> Self {
        Self {
            bytes: Vec::new(),
            cap,
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for CappedVec {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        check_cancelled()?;
        if buf.len() > self.cap.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(format!(
                "buffered output exceeds the {} byte limit",
                self.cap
            )));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        check_cancelled()
    }
}

/// Where bytes come from.
pub enum Source {
    File(PathBuf),
    Stdin,
}

/// One opened input and the length observed from that same handle.
///
/// Keeping these together prevents a pathname replacement between `open` and
/// `metadata` from making format geometry describe different bytes than the
/// reader actually supplies.
pub struct OpenedSource {
    pub reader: Box<dyn Read>,
    pub len: Option<u64>,
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

    /// Open the input once and bind any known length to that exact handle.
    pub fn open(&self) -> Result<OpenedSource> {
        let (inner, len): (Box<dyn Read>, Option<u64>) = match self {
            Self::File(p) => {
                let file =
                    std::fs::File::open(p).with_context(|| format!("reading {}", p.display()))?;
                let len = file
                    .metadata()
                    .with_context(|| format!("reading metadata for {}", p.display()))?
                    .len();
                (Box::new(file), Some(len))
            }
            Self::Stdin => (Box::new(std::io::stdin().lock()), None),
        };
        Ok(OpenedSource {
            reader: Box::new(CancelReader { inner }),
            len,
        })
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

    pub fn write_all(&self, bytes: &[u8], force: bool) -> Result<()> {
        match self {
            Self::File(p) => {
                write_atomic(p, bytes, force)?;
            }
            Self::Stdout => {
                let mut out = CancelWriter::new(std::io::stdout().lock());
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
/// The temporary is exclusively created and kept private through publication:
/// mode 0600 on Unix, and a handle that denies read/write sharing on Windows.
/// `create_new` refuses to follow an existing symlink. Plaintext from a
/// decryption tool is sensitive by default.
pub fn write_atomic(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut tmp = NamedTemp::create_beside(path)?;
    tmp.write_all(bytes)
        .with_context(|| format!("writing {}", tmp.path().display()))?;
    tmp.sync_all().context("syncing temporary")?;
    tmp.commit(path, force)
}

/// An exclusively created, same-directory temporary removed on every exit.
///
/// The object owns the pathname as well as the descriptor. Until `commit`
/// succeeds, dropping it removes only the name this process created. In
/// particular, creation never deletes a predictable pre-existing pathname.
pub struct NamedTemp {
    file: Option<File>,
    path: PathBuf,
    published: bool,
}

fn unlink_path(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

impl NamedTemp {
    pub fn create_beside(destination: &Path) -> Result<Self> {
        loop {
            let path = temp_candidate(destination);
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                opts.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE);
            }
            match opts.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        path,
                        published: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(e).with_context(|| format!("creating {}", path.display()));
                }
            }
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        check_cancelled()?;
        self.file
            .as_ref()
            .expect("temporary file is open")
            .sync_all()?;
        check_cancelled()
    }

    /// Remove this process-owned name without closing the underlying handle.
    ///
    /// Keeping the handle live is security-significant on Windows: it denies
    /// read/write sharing until `remove_file` has made the sidecar unavailable
    /// by name. Closing first would create a close-to-remove disclosure race.
    fn unlink_owned_with(
        &mut self,
        unlink: &impl Fn(&Path) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        unlink(&self.path)?;
        self.path.clear();
        Ok(())
    }

    fn unlink_owned(&mut self) -> std::io::Result<()> {
        self.unlink_owned_with(&unlink_path)
    }

    fn discard_with(&mut self, unlink: impl Fn(&Path) -> std::io::Result<()>) {
        if self.unlink_owned_with(&unlink).is_err() {
            // Once no-replace publication has created a second hard link,
            // truncating through this handle would also destroy the published
            // destination. Scrubbing is therefore restricted to staging data
            // which has never been published.
            if !self.published {
                if let Some(file) = self.file.as_ref() {
                    let _ = file.set_len(0);
                    let _ = file.sync_all();
                }
            }
            let _ = self.unlink_owned_with(&unlink);
        }
    }

    /// Publish this temporary at `destination`.
    ///
    /// Without `force`, `hard_link` is the portable atomic no-replace
    /// primitive: creating the destination link either wins as one operation
    /// or reports that a competing file already exists. We deliberately do
    /// not fall back to an existence check followed by `rename`, because that
    /// would restore the clobber race this helper exists to close.
    pub fn commit(mut self, destination: &Path, force: bool) -> Result<()> {
        check_cancelled()?;

        if force {
            std::fs::rename(&self.path, destination)
                .with_context(|| format!("finalising {}", destination.display()))?;
            self.path.clear();
            return Ok(());
        }

        match std::fs::hard_link(&self.path, destination) {
            Ok(()) => {
                // From this point on, the open inode is legitimate output and
                // must never be scrubbed merely because sidecar cleanup fails.
                self.published = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                bail!(
                    "{} already exists; pass --force to overwrite",
                    destination.display()
                );
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "atomically publishing {} without replacement",
                        destination.display()
                    )
                });
            }
        }

        self.unlink_owned()
            .with_context(|| format!("removing temporary {}", self.path.display()))?;
        Ok(())
    }
}

impl Write for NamedTemp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        check_cancelled()?;
        let result = self
            .file
            .as_mut()
            .expect("temporary file is open")
            .write(buf);
        check_cancelled()?;
        result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        check_cancelled()?;
        self.file
            .as_mut()
            .expect("temporary file is open")
            .flush()?;
        check_cancelled()
    }
}

impl Drop for NamedTemp {
    fn drop(&mut self) {
        // The File field is intentionally left in place and closes only after
        // this Drop implementation returns.
        self.discard_with(unlink_path);
    }
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
    let destination = dir.join("anubis-spill");
    let mut tmp = NamedTemp::create_beside_with_read(&destination)?;
    tmp.unlink_owned()
        .with_context(|| format!("unlinking spill file {}", tmp.path.display()))?;
    Ok(tmp.file.take().expect("spill file is open"))
}

impl NamedTemp {
    fn create_beside_with_read(destination: &Path) -> Result<Self> {
        loop {
            let path = temp_candidate(destination);
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                opts.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE);
            }
            match opts.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        path,
                        published: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(e).with_context(|| format!("creating {}", path.display()));
                }
            }
        }
    }
}

/// A fresh temporary candidate in the destination directory, so publication
/// stays on one filesystem. Collisions are skipped, never removed.
fn temp_candidate(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    temp_candidate_for(path, sequence)
}

fn temp_candidate_for(path: &Path, sequence: u64) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("out")),
    );
    name.push(format!(".{}.{sequence}.partial", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_dir(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("anubis-cli-io-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test directory");
        path
    }

    #[test]
    fn drop_removes_owned_temporary() {
        let _guard = TEST_LOCK.lock().expect("lock tests");
        let dir = test_dir("drop-cleanup");
        let destination = dir.join("result");
        let path = {
            let mut tmp = NamedTemp::create_beside(&destination).expect("create temp");
            tmp.write_all(b"secret").expect("write temp");
            tmp.path().to_path_buf()
        };
        assert!(!path.exists(), "dropping a temp must remove its sidecar");
        std::fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn unlink_owned_removes_name_before_handle_closes() {
        let _guard = TEST_LOCK.lock().expect("lock tests");
        let dir = test_dir("unlink-before-close");
        let destination = dir.join("result");
        let mut tmp = NamedTemp::create_beside(&destination).expect("create temp");
        tmp.write_all(b"secret").expect("write temp");
        let path = tmp.path().to_path_buf();

        tmp.unlink_owned().expect("unlink owned name");

        assert!(!path.exists(), "the sidecar name must already be gone");
        assert!(
            tmp.file.is_some(),
            "the protected handle must still be live"
        );
        tmp.write_all(b"still open")
            .expect("the handle remains usable until drop");
        drop(tmp);
        std::fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn failed_sidecar_unlink_after_publication_never_truncates_destination() {
        let _guard = TEST_LOCK.lock().expect("lock tests");
        let dir = test_dir("published-cleanup-failure");
        let destination = dir.join("result");
        let mut tmp = NamedTemp::create_beside(&destination).expect("create temp");
        let payload = b"verified plaintext";
        tmp.write_all(payload).expect("write temp");
        std::fs::hard_link(tmp.path(), &destination).expect("publish hard link");
        tmp.published = true;

        tmp.discard_with(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected unlink failure",
            ))
        });

        assert_eq!(
            std::fs::read(&destination).expect("read published destination"),
            payload,
            "cleanup failure must not scrub the published inode"
        );
        assert!(tmp.file.is_some(), "the publication handle remains live");
        tmp.unlink_owned().expect("remove sidecar after injection");
        drop(tmp);
        std::fs::remove_file(destination).expect("remove destination");
        std::fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn no_replace_commit_preserves_competing_file_and_cleans_temp() {
        let _guard = TEST_LOCK.lock().expect("lock tests");
        let dir = test_dir("no-replace");
        let destination = dir.join("result");
        let mut tmp = NamedTemp::create_beside(&destination).expect("create temp");
        tmp.write_all(b"ours").expect("write temp");
        tmp.sync_all().expect("sync temp");
        let temp_path = tmp.path().to_path_buf();

        std::fs::write(&destination, b"competitor").expect("create competing destination");
        let error = tmp
            .commit(&destination, false)
            .expect_err("no-replace commit must reject a competing file");

        assert!(error.to_string().contains("--force"));
        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"competitor"
        );
        assert!(!temp_path.exists(), "failed commit must clean its sidecar");
        std::fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn force_commit_replaces_destination() {
        let _guard = TEST_LOCK.lock().expect("lock tests");
        let dir = test_dir("force");
        let destination = dir.join("result");
        std::fs::write(&destination, b"old").expect("seed destination");

        write_atomic(&destination, b"new", true).expect("force replacement");

        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"new"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&destination)
                    .expect("destination metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn preexisting_temp_candidate_is_never_deleted() {
        let _guard = TEST_LOCK.lock().expect("lock tests");
        let dir = test_dir("preexisting-temp");
        let destination = dir.join("result");
        let sequence = TEMP_SEQUENCE.load(Ordering::Relaxed);
        let planted = temp_candidate_for(&destination, sequence);
        std::fs::write(&planted, b"do not touch").expect("plant colliding temp");

        let created = NamedTemp::create_beside(&destination).expect("create owned temp");

        assert_ne!(created.path(), planted);
        assert_eq!(
            std::fs::read(&planted).expect("read planted temp"),
            b"do not touch"
        );
        drop(created);
        assert!(planted.exists(), "foreign temporary must remain untouched");
        std::fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn capped_vec_refuses_growth_past_its_ceiling() {
        let allowed = b"fits";
        let mut output = CappedVec::new(allowed.len());
        output.write_all(allowed).expect("write at ceiling");

        let error = output
            .write_all(b"!")
            .expect_err("write past ceiling must fail");

        assert!(error.to_string().contains("limit"));
        assert_eq!(output.bytes, allowed);
    }

    #[test]
    fn opened_file_length_stays_bound_to_the_open_handle() {
        let _guard = TEST_LOCK.lock().expect("lock tests");
        let dir = test_dir("opened-source-binding");
        let input = dir.join("input.anubis");
        let replacement = dir.join("replacement.anubis");
        let original = b"original bytes";
        std::fs::write(&input, original).expect("write original");

        let mut opened = Source::File(input.clone()).open().expect("open source");
        std::fs::write(&replacement, b"different replacement length").expect("write replacement");
        std::fs::rename(&replacement, &input).expect("replace pathname");

        assert_eq!(opened.len, Some(original.len() as u64));
        let mut observed = Vec::new();
        opened
            .reader
            .read_to_end(&mut observed)
            .expect("read opened source");
        assert_eq!(observed, original);

        std::fs::remove_dir_all(dir).expect("remove test directory");
    }
}
