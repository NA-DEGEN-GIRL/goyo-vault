//! Files in `<vault>.sync\`, the only channel between goyo-vault.exe and
//! goyo-sync.exe. Each file has one writer, and every write is a new file
//! renamed into place. Local, bounded I/O only: no network, no child
//! processes, no RNG.
//!
//! Any open handle on a file, even one without access rights, makes
//! `MoveFileExW(REPLACE_EXISTING)` onto it fail with error 5, while a
//! directory listing does not. So changes are detected from directory
//! listings alone, and every replace-writer retries.
use crate::vault::MAX_FILE;
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// The app's next upload; written by the app, read by the helper.
pub const OUTGOING: &str = "outgoing.goyosync";
/// The newest server copy; written by the helper, read by the app.
pub const INCOMING: &str = "incoming.goyosync";
/// Helper health for display; written by the helper, read by the app.
pub const STATUS: &str = "status";
/// The helper's own bookkeeping (see [`HelperState`]).
pub const HELPER_STATE: &str = "helper.state";
/// Held with `File::try_lock` so only one helper pass runs per folder.
pub const HELPER_LOCK: &str = "helper.lock";
pub const TEMP_SUFFIX: &str = ".goyotmp";
/// Temp-file prefixes each side may remove. Neither touches the other's, so
/// a cleanup can never delete a file the other process is about to rename.
pub const APP_TEMPS: [&str; 2] = ["outgoing.goyosync.", "pre-merge-"];
pub const HELPER_TEMPS: [&str; 3] = ["incoming.goyosync.", "status.", "helper.state."];

pub const OUTGOING_MAGIC: &[u8; 8] = b"GOYOSOU1";
pub const INCOMING_MAGIC: &[u8; 8] = b"GOYOSIN1";
/// The only vault format that is synced.
pub const VAULT_MAGIC: &[u8; 8] = b"GOYOVA02";
/// Smallest GOYOVA02 file: 48-byte header, 32-byte empty plaintext, tag.
pub const MIN_VAULT: usize = 96;
/// Magic and one u64 in front of the vault file.
pub const WRAP_HEADER: usize = 16;
pub const MAX_WRAPPED: usize = WRAP_HEADER + MAX_FILE;
pub const MAX_STATUS: usize = 512;
pub const MAX_HELPER_STATE: usize = 4096;
const PRE_MERGE: &str = "pre-merge-";
const RETRIES: u32 = 3;
const RETRY_WAIT: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileError {
    Missing,
    /// Another handle is open on the file (Windows errors 5 and 32). The
    /// caller keeps its data and tries again on its next loop.
    Busy,
    TooLarge,
    Io,
}
fn classify(e: &io::Error) -> FileError {
    match e.raw_os_error() {
        Some(5 | 32) => FileError::Busy,
        _ if e.kind() == io::ErrorKind::NotFound => FileError::Missing,
        _ => FileError::Io,
    }
}

/// `<vault file name>.sync` next to the vault, e.g. `vault.goyo.sync`.
pub fn sync_dir(vault: &Path) -> Option<PathBuf> {
    let mut name = vault.file_name()?.to_owned();
    name.push(".sync");
    Some(vault.with_file_name(name))
}
/// Whether `path` is a real directory. A junction or symlink could point the
/// sync files anywhere, for example next to the key file, so it is refused.
pub fn usable_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !reparse_point(&m))
}
#[cfg(windows)]
fn reparse_point(m: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
}
#[cfg(not(windows))]
fn reparse_point(m: &fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

/// Name of the app's safety copy before a mass delete. Ten digits keep name
/// order equal to time order.
pub fn pre_merge_name(unix: u64) -> String {
    format!("{PRE_MERGE}{unix:010}.goyo")
}
/// The safety copies in `dir`, oldest first.
pub fn pre_merge_copies(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_ascii_lowercase();
            let digits = name.strip_prefix(PRE_MERGE)?.strip_suffix(".goyo")?;
            let ok = digits.len() == 10 && digits.bytes().all(|b| b.is_ascii_digit());
            (ok && e.file_type().is_ok_and(|t| t.is_file())).then(|| (name, e.path()))
        })
        .collect();
    found.sort();
    found.into_iter().map(|(_, path)| path).collect()
}

/// What a directory listing says about a file. Every replace is a new file,
/// so its creation time changes even when size and content do not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stamp {
    len: u64,
    created: SystemTime,
    modified: SystemTime,
}
/// The stamp of `dir\name`, or None if it is missing or a directory. Read
/// from the directory listing only (`DirEntry::metadata` uses the find data
/// on Windows): opening or even stat-ing the file would hold a handle that
/// makes the writer's replace fail. Windows names ignore case. A symlink or
/// junction is reported, not followed, so the reader's own checks (the
/// helper's upload gate, [`read_bounded`]) see it and refuse it.
pub fn stamp(dir: &Path, name: &str) -> Option<Stamp> {
    let entry = fs::read_dir(dir)
        .ok()?
        .flatten()
        .find(|e| e.file_name().eq_ignore_ascii_case(name))?;
    let m = entry.metadata().ok()?;
    if m.is_dir() {
        return None;
    }
    Some(Stamp {
        len: m.len(),
        created: m.created().unwrap_or(UNIX_EPOCH),
        modified: m.modified().unwrap_or(UNIX_EPOCH),
    })
}

/// Reads at most `max` bytes of a regular file. The handle, although shared
/// for read, write and delete, makes the other side's replace fail until it
/// closes; that writer retries later, so keep it open only for the read.
/// A symlink, junction or directory at `path` is refused as `Io`, never
/// followed: a planted link must not make either program open, or block
/// reading, something else (a pipe, a device, a key file). It is not `Busy`
/// because it stays until someone removes it.
pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, FileError> {
    let f = open_plain(path)?;
    if f.metadata().map_err(|e| classify(&e))?.len() > max as u64 {
        return Err(FileError::TooLarge);
    }
    let mut b = Vec::new();
    f.take((max as u64).saturating_add(1))
        .read_to_end(&mut b)
        .map_err(|e| classify(&e))?;
    if b.len() > max {
        return Err(FileError::TooLarge);
    }
    Ok(b)
}
/// Opens `path` itself, not what a link there points to, and only if it is
/// a regular file.
#[cfg(windows)]
fn open_plain(path: &Path) -> Result<File, FileError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS: a link opens
    // as itself and a directory opens at all, so both can be told apart.
    // Sharing stays read, write and delete, as for any std open.
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000 | 0x0200_0000)
        .open(path)
        .map_err(|e| classify(&e))?;
    let attributes = f.metadata().map_err(|e| classify(&e))?.file_attributes();
    // FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    if attributes & 0x410 != 0 {
        return Err(FileError::Io);
    }
    Ok(f)
}
#[cfg(not(windows))]
fn open_plain(path: &Path) -> Result<File, FileError> {
    let m = fs::symlink_metadata(path).map_err(|e| classify(&e))?;
    if !m.file_type().is_file() {
        return Err(FileError::Io);
    }
    File::open(path).map_err(|e| classify(&e))
}

static TEMPS: AtomicU64 = AtomicU64::new(0);
/// `<name>.<pid>-<nanos>-<n>.goyotmp`: unique without an RNG, since process
/// IDs are unique among running processes and the counter within one.
fn temp_name(name: &OsStr) -> OsString {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = TEMPS.fetch_add(1, Ordering::Relaxed);
    let mut temp = name.to_owned();
    temp.push(format!(
        ".{:x}-{nanos:x}-{n:x}{TEMP_SUFFIX}",
        std::process::id()
    ));
    temp
}
/// Replaces `path` with `bytes` through a synced temp file in the same
/// folder, so a reader sees the old or the new file, never a mix. A reader's
/// open handle makes the rename fail; after three 50 ms retries this returns
/// `Busy` and leaves the old file as it was. It never writes in place.
pub fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    let name = path.file_name().ok_or(FileError::Io)?;
    let temp = path.with_file_name(temp_name(name));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|_| FileError::Io)?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| FileError::Io)?;
        drop(f);
        let mut tries = 0;
        loop {
            match rename_over(&temp, path) {
                Ok(()) => return Ok(()),
                Err(5 | 32) if tries < RETRIES => {
                    tries += 1;
                    std::thread::sleep(RETRY_WAIT);
                }
                Err(5 | 32) => return Err(FileError::Busy),
                Err(_) => return Err(FileError::Io),
            }
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
/// The Windows error code on failure.
#[cfg(windows)]
fn rename_over(temp: &Path, target: &Path) -> Result<(), u32> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        fn GetLastError() -> u32;
    }
    let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    if from[..from.len() - 1].contains(&0) || to[..to.len() - 1].contains(&0) {
        return Err(87); // ERROR_INVALID_PARAMETER
    }
    // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}
#[cfg(not(windows))]
fn rename_over(temp: &Path, target: &Path) -> Result<(), u32> {
    fs::rename(temp, target).map_err(|_| 0)
}
/// Removes this side's leftover temp files from `dir` (`prefixes` is
/// [`APP_TEMPS`] or [`HELPER_TEMPS`]) and returns how many. Call it only
/// while this process has no replace of those files in flight.
pub fn remove_own_temps(dir: &Path, prefixes: &[&str]) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        let own = prefixes
            .iter()
            .any(|p| name.starts_with(&p.to_ascii_lowercase()));
        if own
            && name.ends_with(TEMP_SUFFIX)
            && e.file_type().is_ok_and(|t| t.is_file())
            && fs::remove_file(e.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// `GOYOVA` and two digits from `03` up: written by a newer Goyo Vault. The
/// magic is public, so telling it apart reveals nothing.
pub fn newer_vault_format(bytes: &[u8]) -> bool {
    match bytes.get(..8) {
        Some([b'G', b'O', b'Y', b'O', b'V', b'A', a, b])
            if a.is_ascii_digit() && b.is_ascii_digit() =>
        {
            (a - b'0') * 10 + (b - b'0') >= 3
        }
        _ => false,
    }
}
fn synced_vault(vault: &[u8]) -> bool {
    (MIN_VAULT..=MAX_FILE).contains(&vault.len()) && vault.starts_with(VAULT_MAGIC)
}
fn wrap(magic: &[u8; 8], number: u64, vault: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WRAP_HEADER + vault.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&number.to_le_bytes());
    out.extend_from_slice(vault);
    out
}
fn unwrapped<'a>(magic: &[u8; 8], bytes: &'a [u8]) -> Option<(u64, &'a [u8])> {
    if !(WRAP_HEADER + MIN_VAULT..=MAX_WRAPPED).contains(&bytes.len()) || &bytes[..8] != magic {
        return None;
    }
    let number = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Some((number, &bytes[WRAP_HEADER..]))
}
/// `GOYOSOU1 · base · vault`: an upload made from server version `base`
/// (0 = none merged yet). Only a GOYOVA02 file can be wrapped, so a key file
/// (GOYOKE, 128 or 148 bytes) never can.
pub fn render_outgoing(base: u64, vault: &[u8]) -> Option<Vec<u8>> {
    synced_vault(vault).then(|| wrap(OUTGOING_MAGIC, base, vault))
}
/// `(base, vault)`. The helper also checks the vault ID it pinned.
pub fn parse_outgoing(bytes: &[u8]) -> Option<(u64, &[u8])> {
    unwrapped(OUTGOING_MAGIC, bytes).filter(|(_, vault)| vault.starts_with(VAULT_MAGIC))
}
/// `GOYOSIN1 · version · vault`: the exact server bytes of `version` (≥ 1).
pub fn render_incoming(version: u64, vault: &[u8]) -> Option<Vec<u8>> {
    (version >= 1 && synced_vault(vault)).then(|| wrap(INCOMING_MAGIC, version, vault))
}
/// `(version, vault)`. The inner magic is left to the reader: the app must
/// see a newer GOYOVA0x to stop syncing, and decryption refuses the rest.
pub fn parse_incoming(bytes: &[u8]) -> Option<(u64, &[u8])> {
    unwrapped(INCOMING_MAGIC, bytes).filter(|(version, _)| *version >= 1)
}

/// The helper's state in the status file. The app shows fixed localized
/// strings chosen by it, never text from the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncState {
    Ok,
    Idle,
    Offline,
    Auth,
    HostKey,
    NoSsh,
    Server,
    Refused,
    Config,
    Update,
}
impl SyncState {
    pub const ALL: [SyncState; 10] = [
        Self::Ok,
        Self::Idle,
        Self::Offline,
        Self::Auth,
        Self::HostKey,
        Self::NoSsh,
        Self::Server,
        Self::Refused,
        Self::Config,
        Self::Update,
    ];
    pub fn token(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Idle => "idle",
            Self::Offline => "offline",
            Self::Auth => "auth",
            Self::HostKey => "hostkey",
            Self::NoSsh => "nossh",
            Self::Server => "server",
            Self::Refused => "refused",
            Self::Config => "config",
            Self::Update => "update",
        }
    }
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.token() == token)
    }
}
/// The status file. A value that is missing or invalid stays unknown:
/// 0 for the times (a heartbeat of 0 reads as "helper off"), None for state.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SyncStatus {
    /// Unix seconds; the helper rewrites the file at least every 60 s.
    pub heartbeat: u64,
    /// Unix seconds of the last valid server reply, or 0.
    pub contact: u64,
    pub state: Option<SyncState>,
}
const STATUS_HEADER: &str = "goyo-sync-status 1";
pub fn render_status(heartbeat: u64, contact: u64, state: SyncState) -> Vec<u8> {
    format!(
        "{STATUS_HEADER}\nheartbeat={heartbeat}\ncontact={contact}\nstate={}\n",
        state.token()
    )
    .into_bytes()
}
/// Strict and positional: ASCII, LF, the header, then heartbeat, contact and
/// state in that order. Junk, oversize or another header gives all unknown.
pub fn parse_status(bytes: &[u8]) -> SyncStatus {
    let mut status = SyncStatus::default();
    let Some(text) = ascii(bytes, MAX_STATUS) else {
        return status;
    };
    let mut lines = text.split('\n');
    if lines.next() != Some(STATUS_HEADER) {
        return status;
    }
    status.heartbeat = field(&mut lines, "heartbeat=")
        .and_then(decimal)
        .unwrap_or(0);
    status.contact = field(&mut lines, "contact=").and_then(decimal).unwrap_or(0);
    status.state = field(&mut lines, "state=").and_then(SyncState::from_token);
    status
}
/// Missing, Busy and Io are passed on so the caller can tell "no helper"
/// from a read that raced the helper's replace. Oversize reads as junk.
pub fn read_status(dir: &Path) -> Result<SyncStatus, FileError> {
    match read_bounded(&dir.join(STATUS), MAX_STATUS) {
        Ok(bytes) => Ok(parse_status(&bytes)),
        Err(FileError::TooLarge) => Ok(SyncStatus::default()),
        Err(e) => Err(e),
    }
}

/// `helper.state`: what the helper already did for one vault.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HelperState {
    /// Pinned vault ID, from a valid outgoing or incoming header.
    pub id: Option<[u8; 16]>,
    /// Server version of the blob in incoming (0 = none).
    pub server: u64,
    /// SHA-256 of that blob.
    pub head: Option<[u8; 32]>,
    /// SHA-256 of the last outgoing file handled: pushed, found landed, or
    /// dead by conflict.
    pub done: Option<[u8; 32]>,
    /// SHA-256 of the last outgoing file refused by the gate or the server.
    pub rejected: Option<[u8; 32]>,
}
const STATE_HEADER: &str = "goyo-sync-state 1";
pub fn render_helper_state(s: &HelperState) -> Vec<u8> {
    fn opt<const N: usize>(v: Option<[u8; N]>) -> String {
        v.map_or_else(|| "-".into(), |v| hex(&v))
    }
    format!(
        "{STATE_HEADER}\nid={}\nserver={}\nhead={}\ndone={}\nrejected={}\n",
        opt(s.id),
        s.server,
        opt(s.head),
        opt(s.done),
        opt(s.rejected),
    )
    .into_bytes()
}
/// None unless the bytes are exactly what [`render_helper_state`] writes.
/// The helper then re-derives the state from incoming and outgoing; a wrong
/// state only costs a redundant request, never data.
pub fn parse_helper_state(bytes: &[u8]) -> Option<HelperState> {
    fn optional<const N: usize>(s: &str) -> Option<Option<[u8; N]>> {
        if s == "-" {
            Some(None)
        } else {
            parse_hex(s).map(Some)
        }
    }
    let text = ascii(bytes, MAX_HELPER_STATE)?.strip_suffix('\n')?;
    let mut lines = text.split('\n');
    if lines.next()? != STATE_HEADER {
        return None;
    }
    let state = HelperState {
        id: optional(field(&mut lines, "id=")?)?,
        server: decimal(field(&mut lines, "server=")?)?,
        head: optional(field(&mut lines, "head=")?)?,
        done: optional(field(&mut lines, "done=")?)?,
        rejected: optional(field(&mut lines, "rejected=")?)?,
    };
    lines.next().is_none().then_some(state)
}
pub fn read_helper_state(dir: &Path) -> Option<HelperState> {
    parse_helper_state(&read_bounded(&dir.join(HELPER_STATE), MAX_HELPER_STATE).ok()?)
}

fn ascii(bytes: &[u8], max: usize) -> Option<&str> {
    if bytes.len() > max || !bytes.is_ascii() {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}
fn field<'a>(lines: &mut std::str::Split<'a, char>, key: &str) -> Option<&'a str> {
    lines.next()?.strip_prefix(key)
}
/// Plain decimal u64: no sign, no spaces, no overflow.
pub(crate) fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}
/// Lowercase hex, as written in the state file, the log and the CLI.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}
/// Exactly `2 * N` lowercase hex digits.
pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let s = s.as_bytes();
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (o, [hi, lo]) in out.iter_mut().zip(s.as_chunks::<2>().0) {
        *o = (digit(*hi)? << 4) | digit(*lo)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A fresh folder under %TEMP%, removed with everything in it.
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let name = temp_name(OsStr::new("goyo-syncfile"));
            let p = std::env::temp_dir().join(name);
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn file(&self, n: &str) -> PathBuf {
            self.0.join(n)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn vault(len: usize) -> Vec<u8> {
        let mut v = Vec::from(*VAULT_MAGIC);
        v.extend_from_slice(&[7; 16]);
        v.resize(len, 0xA5);
        v
    }
    fn temps(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(TEMP_SUFFIX))
            .collect()
    }

    #[test]
    fn wrappers_round_trip_within_bounds() {
        for len in [MIN_VAULT, 4096, MAX_FILE] {
            let v = vault(len);
            let out = render_outgoing(0, &v).unwrap();
            assert_eq!(
                (out.len(), &out[..8]),
                (WRAP_HEADER + len, &OUTGOING_MAGIC[..])
            );
            assert_eq!(parse_outgoing(&out), Some((0, &v[..])));
            let inc = render_incoming(42, &v).unwrap();
            assert_eq!(parse_incoming(&inc), Some((42, &v[..])));
            // Neither wrapper passes as the other.
            assert_eq!(parse_incoming(&out), None);
            assert_eq!(parse_outgoing(&inc), None);
        }
        let long = vault(MAX_FILE + 1);
        for len in [0, 8, MIN_VAULT - 1, MAX_FILE + 1] {
            let v = &long[..len];
            assert_eq!(render_outgoing(1, v), None, "{len}");
            assert_eq!(render_incoming(1, v), None, "{len}");
            assert_eq!(parse_outgoing(&wrap(OUTGOING_MAGIC, 1, v)), None, "{len}");
            assert_eq!(parse_incoming(&wrap(INCOMING_MAGIC, 1, v)), None, "{len}");
        }
        assert_eq!(parse_outgoing(&long[..WRAP_HEADER - 1]), None);
        let v = vault(MIN_VAULT);
        // Version 0 means "nothing fetched"; it is never written or accepted.
        assert_eq!(render_incoming(0, &v), None);
        assert_eq!(parse_incoming(&wrap(INCOMING_MAGIC, 0, &v)), None);
        let max = wrap(OUTGOING_MAGIC, u64::MAX, &v);
        assert_eq!(parse_outgoing(&max), Some((u64::MAX, &v[..])));
        let mut bad = render_outgoing(3, &v).unwrap();
        bad[7] = b'2';
        assert_eq!(parse_outgoing(&bad), None);
        // Key files and other formats are never wrapped for upload.
        for magic in [b"GOYOKE01", b"GOYOKE02", b"GOYOVA01", b"GOYOVA03"] {
            let mut other = vault(148);
            other[..8].copy_from_slice(magic);
            assert_eq!(render_outgoing(1, &other), None);
            assert_eq!(render_incoming(1, &other), None);
            assert_eq!(parse_outgoing(&wrap(OUTGOING_MAGIC, 1, &other)), None);
        }
        // The app must see a newer format in incoming to stop syncing.
        let mut newer = vault(200);
        newer[..8].copy_from_slice(b"GOYOVA03");
        let wrapped = wrap(INCOMING_MAGIC, 9, &newer);
        assert_eq!(parse_incoming(&wrapped), Some((9, &newer[..])));
    }
    #[test]
    fn newer_formats_are_recognized() {
        for magic in [b"GOYOVA03", b"GOYOVA10", b"GOYOVA99"] {
            assert!(newer_vault_format(magic), "{magic:?}");
        }
        for magic in [
            &b"GOYOVA01"[..],
            b"GOYOVA02",
            b"GOYOVA00",
            b"GOYOVAx3",
            b"GOYOKE03",
            b"GOYOVA0",
        ] {
            assert!(!newer_vault_format(magic), "{magic:?}");
        }
    }
    #[test]
    fn status_parser_falls_back_to_unknown() {
        for state in SyncState::ALL {
            let bytes = render_status(1_792_000_000, 1_791_999_000, state);
            assert!(bytes.len() <= MAX_STATUS);
            let want = SyncStatus {
                heartbeat: 1_792_000_000,
                contact: 1_791_999_000,
                state: Some(state),
            };
            assert_eq!(parse_status(&bytes), want);
            assert_eq!(SyncState::from_token(state.token()), Some(state));
        }
        let unknown = SyncStatus::default();
        let good = "goyo-sync-status 1\nheartbeat=5\ncontact=0\nstate=ok\n";
        assert_eq!(parse_status(good.as_bytes()).state, Some(SyncState::Ok));
        assert_eq!(
            parse_status(&good.as_bytes()[..good.len() - 1]).heartbeat,
            5
        );
        for junk in [
            "",
            "garbage",
            "goyo-sync-status 2\nheartbeat=5\ncontact=0\nstate=ok\n",
            "goyo-sync-status 1\r\nheartbeat=5\r\ncontact=0\r\nstate=ok\r\n",
            " goyo-sync-status 1\nheartbeat=5\ncontact=0\nstate=ok\n",
            "goyo-sync-status 1\nheartbeat=5\ncontact=0\nstate=\u{c624}\n",
        ] {
            assert_eq!(parse_status(junk.as_bytes()), unknown, "{junk:?}");
        }
        let oversize = format!("{good}{}", " ".repeat(MAX_STATUS));
        assert_eq!(parse_status(oversize.as_bytes()), unknown);
        // A bad line leaves only its own value unknown.
        let huge = "heartbeat=18446744073709551616\ncontact=7\nstate=ok";
        let padded = "heartbeat=000000000000000000005\ncontact=7\nstate=idle";
        let cases = [
            (huge, (0, 7, Some(SyncState::Ok))),
            (
                "heartbeat=+5\ncontact=-1\nstate=auth",
                (0, 0, Some(SyncState::Auth)),
            ),
            ("heartbeat=5\ncontact=7\nstate=OK", (5, 7, None)),
            ("heartbeat=5\ncontact=7\nstate=synced", (5, 7, None)),
            ("heartbeat=5\ncontact=7\nstate=ok \n", (5, 7, None)),
            (
                "contact=7\nheartbeat=5\nstate=ok",
                (0, 0, Some(SyncState::Ok)),
            ),
            ("heartbeat=5", (5, 0, None)),
            (padded, (0, 7, Some(SyncState::Idle))),
            (
                "heartbeat=5\ncontact=7\nstate=hostkey\nx=1",
                (5, 7, Some(SyncState::HostKey)),
            ),
        ];
        for (body, (heartbeat, contact, state)) in cases {
            let text = format!("goyo-sync-status 1\n{body}");
            let want = SyncStatus {
                heartbeat,
                contact,
                state,
            };
            assert_eq!(parse_status(text.as_bytes()), want, "{body:?}");
        }
    }
    #[test]
    fn helper_state_parser_is_all_or_nothing() {
        let full = HelperState {
            id: Some([0xAB; 16]),
            server: u64::MAX,
            head: Some([1; 32]),
            done: Some([0xF0; 32]),
            rejected: Some([0; 32]),
        };
        for s in [HelperState::default(), full] {
            let bytes = render_helper_state(&s);
            assert!(bytes.len() <= MAX_HELPER_STATE);
            assert_eq!(parse_helper_state(&bytes), Some(s));
        }
        let text = String::from_utf8(render_helper_state(&full)).unwrap();
        assert!(text.contains(&format!("id={}\n", "ab".repeat(16))));
        let default = String::from_utf8(render_helper_state(&HelperState::default())).unwrap();
        assert_eq!(
            default,
            "goyo-sync-state 1\nid=-\nserver=0\nhead=-\ndone=-\nrejected=-\n"
        );
        let broken = [
            String::new(),
            "junk".into(),
            default.trim_end().into(), // no final LF
            default.replace("server=0", "server=18446744073709551616"),
            default.replace("server=0", "server=-1"),
            default.replace("id=-", &format!("id={}", "AB".repeat(16))),
            default.replace("id=-", &format!("id={}", "ab".repeat(15))),
            default.replace("head=-", &format!("head={}", "0".repeat(63))),
            default.replace("done=-", "done=?"),
            default.replace("done=-\nrejected=-", "rejected=-\ndone=-"),
            default.replace("state 1", "state 2"),
            default.replace("rejected=-\n", ""),
            format!("{default}extra=1\n"),
            default.replace('\n', "\r\n"),
            format!("{default}{}", "#".repeat(MAX_HELPER_STATE)),
        ];
        for b in broken {
            assert_eq!(parse_helper_state(b.as_bytes()), None, "{b:?}");
        }
        let t = Temp::new();
        assert_eq!(read_helper_state(&t.0), None);
        replace_file(&t.file(HELPER_STATE), &render_helper_state(&full)).unwrap();
        assert_eq!(read_helper_state(&t.0), Some(full));
    }
    #[test]
    fn hex_round_trip() {
        let bytes: [u8; 16] = std::array::from_fn(|i| (i * 17) as u8);
        let text = hex(&bytes);
        assert_eq!(text, "00112233445566778899aabbccddeeff");
        assert_eq!(parse_hex::<16>(&text), Some(bytes));
        assert_eq!(parse_hex::<16>(&text.to_uppercase()), None);
        assert_eq!(parse_hex::<16>(&text[1..]), None);
        assert_eq!(parse_hex::<8>(&text), None);
        assert_eq!(parse_hex::<1>("g0"), None);
    }
    #[test]
    fn stamp_changes_on_every_replace() {
        let t = Temp::new();
        assert_eq!(stamp(&t.0, INCOMING), None);
        assert_eq!(stamp(&t.file("missing-folder"), INCOMING), None);
        let mut seen: Vec<Stamp> = Vec::new();
        for _ in 0..5 {
            // Same size and content each time: only the new file shows.
            replace_file(&t.file(INCOMING), b"same bytes").unwrap();
            let s = stamp(&t.0, INCOMING).unwrap();
            assert!(!seen.contains(&s), "{s:?} repeated");
            // Reading changes nothing a listing reports.
            assert_eq!(fs::read(t.file(INCOMING)).unwrap(), b"same bytes");
            assert_eq!(stamp(&t.0, INCOMING), Some(s));
            seen.push(s);
        }
        // Names match without regard to case, as Windows resolves them.
        fs::write(t.file("STATUS"), b"x").unwrap();
        assert!(stamp(&t.0, STATUS).is_some());
        fs::create_dir(t.file(OUTGOING)).unwrap();
        assert_eq!(stamp(&t.0, OUTGOING), None);
        assert!(temps(&t.0).is_empty());
    }
    /// The rule the whole design rests on: polling stamps never holds a
    /// handle on the file, so it never makes the writer's replace fail.
    /// Each rename is tried once, so a retry cannot hide a failure; a poller
    /// that used `fs::metadata` instead fails about a quarter of them.
    #[cfg(windows)]
    #[test]
    fn polling_stamps_never_blocks_a_replace() {
        use std::sync::atomic::AtomicBool;
        let t = Temp::new();
        let target = t.file(INCOMING);
        fs::write(&target, b"0").unwrap();
        let stop = AtomicBool::new(false);
        let (failed, polls) = std::thread::scope(|s| {
            let poller = s.spawn(|| {
                let mut polls = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    assert!(stamp(&t.0, INCOMING).is_some());
                    polls += 1;
                }
                polls
            });
            let mut failed = Vec::new();
            for i in 0..300u32 {
                let temp = t.file(&format!("{INCOMING}.{i}{TEMP_SUFFIX}"));
                fs::write(&temp, i.to_le_bytes()).unwrap();
                if let Err(code) = rename_over(&temp, &target) {
                    failed.push(code);
                    let _ = fs::remove_file(&temp);
                }
            }
            stop.store(true, Ordering::Relaxed);
            (failed, poller.join().unwrap())
        });
        assert!(polls >= 100, "only {polls} polls ran alongside");
        assert_eq!(failed, [], "renames failed while stamps were polled");
    }
    /// A reader's open handle blocks the rename. The writer then reports
    /// Busy and leaves the old file and no temp behind.
    #[cfg(windows)]
    #[test]
    fn replace_reports_busy_while_a_handle_is_open() {
        let t = Temp::new();
        let target = t.file(OUTGOING);
        replace_file(&target, b"first").unwrap();
        let reader = File::open(&target).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(replace_file(&target, b"second"), Err(FileError::Busy));
        assert!(started.elapsed() >= RETRY_WAIT * RETRIES);
        assert_eq!(fs::read(&target).unwrap(), b"first");
        assert!(temps(&t.0).is_empty());
        drop(reader);
        replace_file(&target, b"second").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        assert!(temps(&t.0).is_empty());
        // A missing folder is an I/O error, not Busy.
        let gone = t.file("gone").join(OUTGOING);
        assert_eq!(replace_file(&gone, b"x"), Err(FileError::Io));
    }
    #[test]
    fn bounded_reads() {
        let t = Temp::new();
        let p = t.file(STATUS);
        assert_eq!(read_bounded(&p, 4), Err(FileError::Missing));
        assert_eq!(read_status(&t.0), Err(FileError::Missing));
        fs::write(&p, b"1234").unwrap();
        assert_eq!(read_bounded(&p, 4).unwrap(), b"1234");
        assert_eq!(read_bounded(&p, 3), Err(FileError::TooLarge));
        fs::write(&p, vec![b'a'; MAX_STATUS + 1]).unwrap();
        assert_eq!(read_status(&t.0), Ok(SyncStatus::default()));
        replace_file(&p, &render_status(9, 8, SyncState::Offline)).unwrap();
        assert_eq!(read_status(&t.0).unwrap().state, Some(SyncState::Offline));
    }
    #[test]
    fn temps_are_unique_and_each_side_removes_only_its_own() {
        let a = temp_name(OsStr::new(OUTGOING));
        let b = temp_name(OsStr::new(OUTGOING));
        assert_ne!(a, b);
        let a = a.to_string_lossy();
        let middle = &a[OUTGOING.len() + 1..a.len() - TEMP_SUFFIX.len()];
        let parts: Vec<&str> = middle.split('-').collect();
        assert_eq!(parts.len(), 3, "{a}");
        assert!(parts.iter().all(|p| u128::from_str_radix(p, 16).is_ok()));
        assert_eq!(parts[0], format!("{:x}", std::process::id()));

        let t = Temp::new();
        let app = [
            "outgoing.goyosync.1-2-3.goyotmp",
            "OUTGOING.GOYOSYNC.4-5-6.GOYOTMP",
            "pre-merge-1792000000.goyo.0123abcd.goyotmp",
        ];
        let helper = [
            "incoming.goyosync.1-2-3.goyotmp",
            "status.1-2-3.goyotmp",
            "helper.state.1-2-3.goyotmp",
        ];
        let kept = [
            OUTGOING,
            INCOMING,
            STATUS,
            "pre-merge-1792000000.goyo",
            "outgoing.goyosync.1-2-3.goyotmp.txt",
            "vault.goyo.0123.goyotmp",
        ];
        for n in app.iter().chain(&helper).chain(&kept) {
            fs::write(t.file(n), b"x").unwrap();
        }
        fs::create_dir(t.file("status.dir.goyotmp")).unwrap();
        assert_eq!(remove_own_temps(&t.0, &APP_TEMPS), app.len());
        assert!(app.iter().all(|n| !t.file(n).exists()));
        assert!(helper.iter().chain(&kept).all(|n| t.file(n).exists()));
        assert_eq!(remove_own_temps(&t.0, &HELPER_TEMPS), helper.len());
        assert!(helper.iter().all(|n| !t.file(n).exists()));
        assert!(kept.iter().all(|n| t.file(n).exists()));
        assert!(t.file("status.dir.goyotmp").is_dir());
        assert_eq!(remove_own_temps(&t.file("missing"), &APP_TEMPS), 0);
    }
    #[test]
    fn folder_and_copy_names() {
        let v = Path::new(r"D:\GoyoVault\vault.goyo");
        let dir = PathBuf::from(r"D:\GoyoVault\vault.goyo.sync");
        assert_eq!(sync_dir(v), Some(dir));
        assert_eq!(sync_dir(Path::new(r"D:\")), None);
        assert_eq!(pre_merge_name(1_792_000_000), "pre-merge-1792000000.goyo");
        assert_eq!(pre_merge_name(5), "pre-merge-0000000005.goyo");
        let t = Temp::new();
        for n in [
            pre_merge_name(1_792_000_300),
            pre_merge_name(5),
            pre_merge_name(1_792_000_000),
            "pre-merge-123.goyo".into(),
            "pre-merge-1792000000.goyo.1-2-3.goyotmp".into(),
            "pre-merge-179200000x.goyo".into(),
        ] {
            fs::write(t.file(&n), b"x").unwrap();
        }
        fs::create_dir(t.file(&pre_merge_name(1))).unwrap();
        let names: Vec<String> = pre_merge_copies(&t.0)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let want = [5, 1_792_000_000, 1_792_000_300].map(pre_merge_name);
        assert_eq!(names, want);
    }
    /// Makes `link` a junction to `target` the way `mklink /J` does,
    /// without starting a process.
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                device: *mut std::ffi::c_void,
                code: u32,
                input: *const u8,
                input_len: u32,
                output: *mut u8,
                output_len: u32,
                returned: *mut u32,
                overlapped: *mut std::ffi::c_void,
            ) -> i32;
        }
        fs::create_dir(link).unwrap();
        // FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
        let dir = OpenOptions::new()
            .write(true)
            .custom_flags(0x0020_0000 | 0x0200_0000)
            .open(link)
            .unwrap();
        let substitute: Vec<u16> = OsStr::new(r"\??\")
            .encode_wide()
            .chain(target.as_os_str().encode_wide())
            .collect();
        let print: Vec<u16> = target.as_os_str().encode_wide().collect();
        let names = 2 * (substitute.len() + print.len() + 2);
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xA000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
        buf.extend_from_slice(&((8 + names) as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        // Substitute name offset and length, then print name offset and length.
        let offsets = [
            0,
            2 * substitute.len(),
            2 * (substitute.len() + 1),
            2 * print.len(),
        ];
        for n in offsets {
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        }
        for c in substitute.iter().chain(&[0]).chain(&print).chain(&[0]) {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                dir.as_raw_handle(),
                0x0009_00A4, // FSCTL_SET_REPARSE_POINT
                buf.as_ptr(),
                buf.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    }
    #[cfg(windows)]
    #[test]
    fn only_a_plain_folder_is_usable() {
        let t = Temp::new();
        let real = t.file("vault.goyo.sync");
        fs::create_dir(&real).unwrap();
        assert!(usable_dir(&real));
        assert!(!usable_dir(&t.file("missing.sync")));
        fs::write(t.file("file.sync"), b"x").unwrap();
        assert!(!usable_dir(&t.file("file.sync")));
        let elsewhere = t.file("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let link = t.file("other.goyo.sync");
        junction(&link, &elsewhere);
        // The junction works as a folder, yet is refused.
        fs::write(link.join(STATUS), b"x").unwrap();
        assert!(elsewhere.join(STATUS).exists());
        assert!(fs::metadata(&link).unwrap().is_dir());
        assert!(!usable_dir(&link));
        fs::remove_dir(&link).unwrap();
        assert!(elsewhere.join(STATUS).exists());
        // A junction at a sync file name is listed as itself, not as the
        // folder it points to, so the helper's gate gets to refuse it.
        junction(&t.file(OUTGOING), &elsewhere);
        let s = stamp(&t.0, OUTGOING).unwrap();
        assert_eq!(s.len, 0);
        assert_eq!(
            read_bounded(&t.file(OUTGOING), MAX_WRAPPED),
            Err(FileError::Io)
        );
        fs::remove_dir(t.file(OUTGOING)).unwrap();
        assert!(elsewhere.join(STATUS).exists());
    }
    /// Readers open a sync file itself, never what a link there points to,
    /// and read only regular files. A link or folder at the name is `Io`, not
    /// `Busy`: it is not a writer that will be done in a moment.
    #[cfg(windows)]
    #[test]
    fn reads_never_follow_links() {
        use std::os::windows::fs::OpenOptionsExt;
        let t = Temp::new();
        let elsewhere = t.file("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let status = render_status(9, 8, SyncState::Ok);
        fs::write(elsewhere.join(STATUS), &status).unwrap();
        // A junction, even one to a folder holding a valid file of that name.
        junction(&t.file(STATUS), &elsewhere);
        assert_eq!(
            read_bounded(&t.file(STATUS), MAX_STATUS),
            Err(FileError::Io)
        );
        assert_eq!(read_status(&t.0), Err(FileError::Io));
        fs::remove_dir(t.file(STATUS)).unwrap();
        // A plain folder.
        fs::create_dir(t.file(INCOMING)).unwrap();
        assert_eq!(
            read_bounded(&t.file(INCOMING), MAX_WRAPPED),
            Err(FileError::Io)
        );
        // A file symlink, where Windows lets this account make one (developer
        // mode or an elevated prompt): refused unread; a writer replaces the
        // link itself, never its target.
        let target = elsewhere.join(STATUS);
        let link = t.file(STATUS);
        if std::os::windows::fs::symlink_file(&target, &link).is_ok() {
            assert_eq!(read_bounded(&link, MAX_STATUS), Err(FileError::Io));
            assert_eq!(read_status(&t.0), Err(FileError::Io));
            let state = render_helper_state(&HelperState::default());
            fs::write(t.file("state-target"), &state).unwrap();
            std::os::windows::fs::symlink_file(t.file("state-target"), t.file(HELPER_STATE))
                .unwrap();
            assert_eq!(read_helper_state(&t.0), None);
            replace_file(&link, b"replaced").unwrap();
            assert_eq!(read_bounded(&link, MAX_STATUS).unwrap(), b"replaced");
            assert_eq!(fs::read(&target).unwrap(), status);
        }
        // A regular file still reads while another program holds it open
        // for writing: sharing is unchanged.
        let p = t.file(OUTGOING);
        fs::write(&p, b"plain").unwrap();
        let writer = OpenOptions::new().write(true).open(&p).unwrap();
        assert_eq!(read_bounded(&p, 5).unwrap(), b"plain");
        drop(writer);
        // A file someone holds without sharing is still Busy (try again).
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&p)
            .unwrap();
        assert_eq!(read_bounded(&p, 5), Err(FileError::Busy));
        drop(held);
        fs::remove_file(&p).unwrap();
        assert_eq!(read_bounded(&p, 5), Err(FileError::Missing));
    }
}
