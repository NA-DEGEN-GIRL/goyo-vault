//! Temp-candidate recovery (spec §5.12). A save cut off by a power loss, a
//! pulled USB stick or a FAT/exFAT replace that deleted the old file first
//! can leave the only full copy of a vault or key file in
//! `<name>.<32 hex>.goyotmp` next to it (see atomic_write). An unlock takes
//! such a copy back when the file itself is missing or unparseable, and
//! after a successful unlock deletes the copies that hold nothing the
//! opened files lack. Every other temp file stays, as in 0.8.
use super::{
    Contents, DataRef, FileLock, Format, KEY_MAGIC, KEY_MAGIC_NO_OTP, MAX_FILE, Session, TOO_LARGE,
    decode_data, flush, publish, read_bounded,
};
use crate::crypto::Result;
use std::{
    cmp::Reverse,
    fs,
    path::{Path, PathBuf},
};

/// Largest key file read before any password.
pub(super) const KEY_LIMIT: usize = 1024;
/// Recovery looks at no more temp files than this per file, newest first,
/// so a folder full of planted ones costs little.
pub(super) const MAX_CANDIDATES: usize = 4;

/// What an unlock took back from temp files an interrupted save left, for
/// the status line (`Session::take_recovery`).
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Recovery {
    /// The vault file was missing and came back from a temp file (rule iii).
    pub vault: bool,
    /// The key file came from this temp file, which could not get the key
    /// file's name back: the session uses it, and the user renames it after
    /// locking (rule i).
    pub key_kept: Option<PathBuf>,
}

/// A temp file that may be the only full copy of the file it is named after.
pub(super) struct Candidate {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    /// Last write time (FILETIME, 100 ns units).
    pub written: u64,
}
/// The temp files an interrupted save of `path` may have left: named
/// `<name>.<32 lowercase hex>.goyotmp`, in the same folder, each a regular
/// file (no folder, link or other reparse point) with a single name and at
/// most `limit` bytes. At most MAX_CANDIDATES, newest first.
pub(super) fn candidates(path: &Path, limit: usize) -> Vec<Candidate> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    // The listing's times only order the work; the ones read through each
    // opened file decide.
    let mut named: Vec<_> = entries
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(|n| temp_of(n, name)))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    named.sort_by_key(|(time, _)| Reverse(*time));
    let mut found: Vec<Candidate> = named
        .into_iter()
        .filter_map(|(_, path)| open_candidate(&path, limit))
        .take(MAX_CANDIDATES)
        .collect();
    found.sort_by_key(|c| Reverse(c.written));
    found
}
/// Whether `file` is `<name>.<32 lowercase hex>.goyotmp`, the name
/// atomic_write gives its temp files. Windows names ignore case.
fn temp_of(file: &str, name: &str) -> bool {
    let Some(rest) = file.get(name.len()..) else {
        return false;
    };
    let hex = rest
        .strip_prefix('.')
        .and_then(|r| r.strip_suffix(".goyotmp"));
    file[..name.len()].to_lowercase() == name.to_lowercase()
        && hex.is_some_and(|h| {
            h.len() == 32 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}
#[cfg(windows)]
fn open_candidate(path: &Path, limit: usize) -> Option<Candidate> {
    use std::{io::Read, os::windows::fs::OpenOptionsExt};
    // FILE_FLAG_OPEN_REPARSE_POINT: a link is opened as itself, not
    // followed, and then refused by its attributes. Checked and read
    // through one handle, so the file cannot be swapped in between.
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)
        .ok()?;
    let info = super::file_info(&f).ok()?;
    let size = (u64::from(info.size_hi) << 32) | u64::from(info.size_lo);
    // FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    if info.attributes & 0x410 != 0 || info.links != 1 || size > limit as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    f.take(limit as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= limit).then(|| Candidate {
        path: path.to_owned(),
        bytes,
        written: (u64::from(info.times[5]) << 32) | u64::from(info.times[4]),
    })
}
#[cfg(not(windows))]
fn open_candidate(_path: &Path, _limit: usize) -> Option<Candidate> {
    None
}

/// What a key file states before any password.
pub(super) struct KeyHead {
    pub id: [u8; 16],
    /// Change counter, the first sort key between copies; key files of 0.8
    /// have none and count as 0.
    pub epoch: u64,
}
/// The header of a key file of a known format and length; None for
/// anything else, a newer format included.
pub(super) fn key_head(data: &[u8]) -> Option<KeyHead> {
    let known = matches!(
        (data.len(), data.get(..8)),
        (148, Some(m)) if m == KEY_MAGIC
    ) || matches!(
        (data.len(), data.get(..8)),
        (128, Some(m)) if m == KEY_MAGIC_NO_OTP
    );
    known.then(|| KeyHead {
        id: data[8..24].try_into().unwrap(),
        epoch: 0,
    })
}
/// A key file magic this build does not know (GOYOK…): a newer build wrote
/// it. It is not damaged, so no temp file ever takes its place.
fn newer_key(data: &[u8]) -> bool {
    data.get(..8).is_some_and(|magic| {
        magic.starts_with(b"GOYOK") && magic != KEY_MAGIC && magic != KEY_MAGIC_NO_OTP
    })
}
/// A key file as an unlock finds it.
pub(super) enum KeyRead {
    /// A key file of a known or newer format, read in full.
    Found(Vec<u8>),
    /// Missing (`replace` false) or unparseable (`replace` true): a temp
    /// file may stand in (rule i). `before` is what the unlock did with it
    /// before recovery existed: an error, or bytes that fail to decrypt.
    Lost {
        replace: bool,
        before: Result<Vec<u8>>,
    },
}
/// Reads the key file at `path`. An error is a key file that is there but
/// cannot be read (in use, no permission), or one too large to read that
/// starts like a newer build's: no temp file replaces that.
pub(super) fn read_key(path: &Path) -> Result<KeyRead> {
    match read_bounded(path, KEY_LIMIT) {
        Ok(b) if key_head(&b).is_some() || newer_key(&b) => Ok(KeyRead::Found(b)),
        Ok(b) => Ok(KeyRead::Lost {
            replace: true,
            before: Ok(b),
        }),
        Err(e) if e == TOO_LARGE => match magic(path) {
            Some(m) if !newer_key(&m) => Ok(KeyRead::Lost {
                replace: true,
                before: Err(e),
            }),
            _ => Err(e),
        },
        Err(e) if !path.exists() => Ok(KeyRead::Lost {
            replace: false,
            before: Err(e),
        }),
        Err(e) => Err(e),
    }
}
/// The first 8 bytes of the file at `path` (fewer if it is shorter).
fn magic(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut head = Vec::with_capacity(8);
    fs::File::open(path)
        .ok()?
        .take(8)
        .read_to_end(&mut head)
        .ok()?;
    Some(head)
}
/// The vault IDs a key file next to `vault` may belong to: the one in the
/// vault file's header or, while the vault file is missing, those of its
/// temp files. Headers are public, so this reveals nothing.
pub(super) fn vault_ids(vault: &Path) -> Vec<[u8; 16]> {
    if let Some(id) = super::vault_id(vault) {
        return vec![id];
    }
    if vault.exists() {
        return Vec::new();
    }
    let mut ids: Vec<[u8; 16]> = candidates(vault, MAX_FILE)
        .iter()
        .filter_map(|c| super::data_header(&c.bytes))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}
/// Rule (i): the temp file to read for a missing or unparseable key file:
/// one that parses as a key file of a vault in `ids`, with the highest
/// epoch, then the newest.
pub(super) fn key_candidate(ids: &[[u8; 16]], key: &Path) -> Option<Candidate> {
    candidates(key, KEY_LIMIT)
        .into_iter()
        .filter_map(|c| {
            let head = key_head(&c.bytes)?;
            ids.contains(&head.id).then_some((head.epoch, c))
        })
        .max_by(|(a, x), (b, y)| a.cmp(b).then(x.written.cmp(&y.written)))
        .map(|(_, c)| c)
}
/// Rule (i), after a successful unlock: gives the temp file it read the key
/// file's name, then flushes it. The key file is replaced only while it is
/// still unparseable; one that parses again stays. False if the name could
/// not be given back.
pub(super) fn restore_key(temp: &Path, key: &Path) -> bool {
    let Ok(_lock) = FileLock::acquire(key) else {
        return false;
    };
    let replace = match read_key(key) {
        Ok(KeyRead::Lost { replace, .. }) => replace,
        _ => return false,
    };
    if publish(temp, key, replace).is_err() {
        return false;
    }
    flush(key);
    true
}
/// Rule (iii): the copy of a missing vault file to take back. Only copies
/// that decrypt under this vault's current key count, so a planted copy
/// under an older key is never taken. The highest `generation` of a v2
/// copy wins, else the newest v1 copy.
pub(super) fn vault_candidate(
    vault: &Path,
    id: &[u8; 16],
    key: &[u8; 32],
) -> Option<(PathBuf, Format, Contents)> {
    candidates(vault, MAX_FILE)
        .into_iter()
        .filter_map(|c| {
            let (format, contents) = decode_data(id, key, &c.bytes).ok()?;
            let rank = (format == Format::V2, contents.generation, c.written);
            Some((rank, c.path, format, contents))
        })
        .max_by_key(|(rank, ..)| *rank)
        .map(|(_, path, format, contents)| (path, format, contents))
}
/// Rule (iv), after a successful unlock of `s` with the key file `key`:
/// deletes the temp files of this vault's key file (the key file in use
/// opened, so they are older or unfinished writes of it) and the vault's
/// temp files whose contents the vault file already holds. Every other
/// temp file stays.
pub(super) fn clean(s: &Session, key: &Path) {
    let stale: Vec<PathBuf> = candidates(key, KEY_LIMIT)
        .into_iter()
        .filter(|c| c.path != s.key_path && key_head(&c.bytes).is_some_and(|h| h.id == s.id))
        .map(|c| c.path)
        .collect();
    // The key file's lock keeps this off a password change running in
    // another window; taken only when there is something to delete.
    if !stale.is_empty()
        && let Ok(_lock) = FileLock::acquire(key)
    {
        for path in stale {
            let _ = fs::remove_file(path);
        }
    }
    for c in candidates(&s.path, MAX_FILE) {
        if decode_data(&s.id, &s.key, &c.bytes)
            .is_ok_and(|(format, contents)| format == s.format && same(contents.view(), s.data()))
        {
            let _ = fs::remove_file(&c.path);
        }
    }
}
/// The same entries (IDs, parents and text), tombstones and counters; the
/// OTP watermark `last` does not count. `seen` does: a copy that knew a
/// later server version still says something the file does not.
fn same(a: DataRef, b: DataRef) -> bool {
    a.generation == b.generation
        && a.seen == b.seen
        && a.tombstones == b.tombstones
        && a.entries.len() == b.entries.len()
        && a.entries
            .iter()
            .zip(b.entries)
            .all(|(x, y)| x.id == y.id && x.parent == y.parent && x.same_content(y))
}
