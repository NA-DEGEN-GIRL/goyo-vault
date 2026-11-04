//! The few POSIX calls the lib needs on Linux and Android (the Android app),
//! declared here against the C library so that no crate is added: the
//! kernel's CSPRNG through the getrandom(2) system call, opens that never
//! follow a symlink, and the fsync of a folder after a rename. Windows
//! builds compile none of this; their code stays in the cfg(windows) arms.
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// `O_NOFOLLOW`: a symlink at the last component fails the open (ELOOP)
/// instead of being followed. Its value differs between architectures.
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const O_NOFOLLOW: i32 = 0o400_000;
/// `O_NONBLOCK`: a FIFO planted under a vault name cannot hang the open.
const O_NONBLOCK: i32 = 0o4000;

/// The number of the getrandom(2) system call.
#[cfg(target_arch = "aarch64")]
const SYS_GETRANDOM: std::ffi::c_long = 278;
#[cfg(target_arch = "x86_64")]
const SYS_GETRANDOM: std::ffi::c_long = 318;
#[cfg(target_arch = "arm")]
const SYS_GETRANDOM: std::ffi::c_long = 384;
#[cfg(target_arch = "x86")]
const SYS_GETRANDOM: std::ffi::c_long = 355;
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "x86"
)))]
compile_error!("goyo_vault: getrandom(2) and O_NOFOLLOW are only defined for arm and x86");

unsafe extern "C" {
    /// Bionic and glibc both export syscall(2). Calling getrandom through
    /// it needs no minimum API level (bionic's getrandom() wrapper is API
    /// 28+), and Android's app seccomp filter allows the call itself.
    fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
}

/// Fills `out` from the kernel CSPRNG (getrandom(2), flags 0: it blocks
/// until the kernel pool was seeded once, and never returns weaker bytes).
/// An interrupted call is repeated; any other error fails, with no fallback
/// to /dev/urandom or anything else.
pub(crate) fn getrandom(out: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < out.len() {
        let rest = &mut out[filled..];
        // SAFETY: the kernel writes at most rest.len() bytes into rest.
        let n = unsafe { syscall(SYS_GETRANDOM, rest.as_mut_ptr(), rest.len(), 0u32) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let n = usize::try_from(n).map_err(|_| io::Error::other("getrandom"))?;
        if n == 0 || n > rest.len() {
            return Err(io::Error::other("getrandom"));
        }
        filled += n;
    }
    Ok(())
}

/// Opens `path` for reading without following a symlink at its last
/// component and without blocking on a FIFO: the caller then checks what it
/// opened through the handle (`File::metadata` is fstat), so the file cannot
/// be swapped between the check and the read. The Windows code does the
/// same with FILE_FLAG_OPEN_REPARSE_POINT.
pub(crate) fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
}

/// Opens `path` read-write, creating it (0600) when missing, without
/// following a symlink at its last component and without blocking on a
/// FIFO: goyo-sync's per-folder pass lock (`helper.lock`), whose handle is
/// then checked to be a single-link regular file.
pub(crate) fn open_lock_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
}

/// Flushes the folder that holds `path`, so a rename into it survives a
/// power cut (a rename is only folder metadata). Errors are returned for
/// the caller to ignore or not; some file systems refuse fsync of a folder.
pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

/// The last write time of `m` in FILETIME units (100 ns since 1601), the
/// unit the Windows code reads, so that both order temp files alike.
pub(crate) fn filetime(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    const EPOCH_1601: i64 = 11_644_473_600;
    let secs = m.mtime().saturating_add(EPOCH_1601).max(0) as u64;
    let nanos = m.mtime_nsec().clamp(0, 999_999_999) as u64;
    secs.saturating_mul(10_000_000).saturating_add(nanos / 100)
}
