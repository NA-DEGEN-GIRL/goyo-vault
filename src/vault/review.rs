//! The merge log `goyo-vault.merges\<vault id>.log` (spec v3 §5.13; feature
//! `security-key`): per PC, never synced, in the anchor's folder. This is
//! its core: the file, written under the anchor's lock through a temp file
//! and a rename, and the review markers. A removal for a loss makes the
//! post-removal review due with an `R` line written before anything is
//! installed (S0r, `pass_login_gate`), so the review stays due when the
//! anchor is deleted, reset or LRU-dropped ("Due is durable"); the review
//! done writes a `D` line. Every `R` line carries the earlier of its own
//! date and that of a review already due, and the reader returns the
//! earliest `R` date after the last `D`, so a second loss never narrows the
//! window (S45-3 #4). The provenance lines of merges, the cap and the
//! S-REVIEW list come later: this core keeps every other line as it is,
//! skips it when it reads the markers, and writes none.
//!
//! The log is unauthenticated: whoever can write the anchor's folder can
//! erase lines. It only makes a review due where a removal for a loss
//! landed on this PC; the docs say so (§13).
use super::{Session, anchor, anchor::Failure, flush, keyfile::Tombstone, publish};
use crate::crypto::{self, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

/// The log's folder in the anchor's folder.
const FOLDER: &str = "goyo-vault.merges";
/// The first line of a version-3 log.
const VERSION: &str = "goyo-vault-merges 3";
/// Largest log read or written (spec §5.13: 512 KiB per vault).
const LIMIT: usize = 512 * 1024;
/// A loss on a day nobody knows: the earliest of every date.
pub(super) const UNKNOWN: &str = "unknown";

/// The earlier of two loss dates (`yyyymmdd`); `unknown` counts as the
/// earliest.
pub(super) fn earlier<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a == UNKNOWN || (b != UNKNOWN && a <= b) {
        a
    } else {
        b
    }
}
/// A loss date as the anchor and the log write it.
fn loss_date(s: &str) -> bool {
    s == UNKNOWN || (s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()))
}
/// The loss date of a tombstone's loss mark (spec §4.1): the day counted
/// from 1970-01-01 plus 2, 1 for an unknown day; None for 0, a removal that
/// was no loss (a retirement, keys off).
fn mark_date(mark: u16) -> Option<String> {
    match mark {
        0 => None,
        1 => Some(UNKNOWN.to_owned()),
        m => Some(crate::fido::stamp(u64::from(m - 2) * 86_400)[..8].to_owned()),
    }
}
/// The review a removal of this PC's keys `removed` makes due (spec
/// §5.13): the earliest loss date their tombstones in `tombs` carry; None
/// when none of them was removed for a loss. The marks decide, not a file's
/// own `loss` field: a later write carries the removal's mark along.
pub(super) fn loss_of(removed: &[[u8; 16]], tombs: &[Tombstone]) -> Option<String> {
    tombs
        .iter()
        .filter(|t| removed.contains(&t.credhash))
        .filter_map(|t| mark_date(t.loss_mark()))
        .reduce(|a, b| earlier(&a, &b).to_owned())
}

fn path(dir: &Path, id: &[u8; 16]) -> PathBuf {
    dir.join(FOLDER).join(format!("{}.log", anchor::hex(id)))
}
/// `<vault id>.log.<16 lowercase hex>.tmp`, the names `append` gives its
/// temp files.
fn temps(dir: &Path, id: &[u8; 16]) -> Vec<PathBuf> {
    let start = format!("{}.log.", anchor::hex(id));
    let named = |name: &str| {
        name.strip_prefix(start.as_str())
            .and_then(|r| r.strip_suffix(".tmp"))
            .is_some_and(|h| {
                h.len() == 16 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
    };
    fs::read_dir(dir.join(FOLDER))
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_str().is_some_and(named))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}
/// What a log's bytes are: its lines after the version line, or a later
/// version's file (or one over LIMIT), which is never rewritten.
fn lines_of(bytes: &[u8]) -> std::result::Result<Vec<&[u8]>, Failure> {
    if bytes.len() > LIMIT {
        return Err(Failure::Newer);
    }
    let mut parts: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    if parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    if let Some(first) = parts.first() {
        let version = std::str::from_utf8(first)
            .ok()
            .and_then(|l| l.strip_prefix("goyo-vault-merges "))
            .and_then(|v| v.parse::<u64>().ok());
        match version {
            Some(v) if v > 3 => return Err(Failure::Newer),
            Some(3) => {
                parts.remove(0);
            }
            _ => {}
        }
    }
    Ok(parts.into_iter().filter(|p| !p.is_empty()).collect())
}
/// The review the markers hold: the earliest `R` date after the last `D`.
/// Lines this core cannot read (and the provenance lines) are skipped.
fn due_in(lines: &[&[u8]]) -> Option<String> {
    let mut due: Option<&str> = None;
    for line in lines {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let mut words = line.split(' ');
        let time = words.next().unwrap_or_default();
        if time.is_empty() || !time.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        match (words.next(), words.next(), words.next()) {
            (Some("R"), Some(date), None) if loss_date(date) => {
                due = Some(due.map_or(date, |d| earlier(d, date)));
            }
            (Some("D"), None, None) => due = None,
            _ => {}
        }
    }
    due.map(str::to_owned)
}
/// The log as it is: its file, else its newest whole temp file (the last
/// write was cut off before its rename), else none. Links and files with a
/// second name read as none, as in the anchor.
fn read(dir: &Path, id: &[u8; 16]) -> std::result::Result<Option<Vec<u8>>, Failure> {
    match anchor::open_plain(&path(dir, id)) {
        Ok(Some(bytes)) => return Ok(Some(bytes)),
        Ok(None) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Failure::Io),
    }
    Ok(newest_temp(dir, id).map(|(_, bytes)| bytes))
}
/// The newest temp file that is a whole version-3 log.
fn newest_temp(dir: &Path, id: &[u8; 16]) -> Option<(PathBuf, Vec<u8>)> {
    temps(dir, id)
        .into_iter()
        .filter_map(|path| {
            let time = fs::symlink_metadata(&path).ok()?.modified().ok()?;
            let bytes = anchor::open_plain(&path).ok()??;
            let whole = bytes.starts_with(VERSION.as_bytes())
                && bytes.get(VERSION.len()) == Some(&b'\n')
                && bytes.last() == Some(&b'\n')
                && lines_of(&bytes).is_ok();
            whole.then_some((time, path, bytes))
        })
        .max_by_key(|(time, ..)| *time)
        .map(|(_, path, bytes)| (path, bytes))
}
/// The review due in the log of vault `id` (spec §5.13), read without the
/// lock; None when none is due or the log cannot be read.
pub(super) fn due(dir: &Path, id: &[u8; 16]) -> Option<String> {
    let bytes = read(dir, id).ok()??;
    due_in(&lines_of(&bytes).ok()?)
}
/// Adds the line `make` returns, from the markers as they are, to the log
/// of vault `id`: under the anchor's lock, waiting at most `wait`; the log
/// read again under it (a missing file taken back from its newest whole
/// temp file), a temp file written and synced, then renamed over the log.
/// Leftover temp files are deleted only under the lock. Returns what
/// `make` returned beside the line.
fn append<T>(
    dir: &Path,
    id: &[u8; 16],
    wait: std::time::Duration,
    make: impl FnOnce(Option<String>) -> (String, T),
) -> std::result::Result<T, Failure> {
    fs::create_dir_all(dir.join(FOLDER)).map_err(|_| Failure::Io)?;
    let _lock = anchor::lock(dir, wait)?;
    let main = path(dir, id);
    let old = match anchor::open_plain(&main) {
        Ok(Some(bytes)) => bytes,
        // A link, a folder or a file with a second name: no log of this
        // build's, never written through.
        Ok(None) => return Err(Failure::Io),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match newest_temp(dir, id) {
            Some((temp, bytes)) => {
                publish(&temp, &main, false).map_err(|_| Failure::Io)?;
                flush(&main);
                bytes
            }
            None => Vec::new(),
        },
        Err(_) => return Err(Failure::Io),
    };
    if main.exists() {
        for temp in temps(dir, id) {
            let _ = fs::remove_file(temp);
        }
    }
    let lines = lines_of(&old)?;
    let (line, out) = make(due_in(&lines));
    let mut bytes = Vec::with_capacity(old.len() + VERSION.len() + line.len() + 2);
    bytes.extend_from_slice(VERSION.as_bytes());
    bytes.push(b'\n');
    for l in &lines {
        bytes.extend_from_slice(l);
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(line.as_bytes());
    bytes.push(b'\n');
    if bytes.len() > LIMIT {
        return Err(Failure::Io);
    }
    let suffix = crypto::random::<8>().map_err(|_| Failure::Io)?;
    let temp = dir.join(FOLDER).join(format!(
        "{}.log.{}.tmp",
        anchor::hex(id),
        anchor::hex(suffix.as_slice())
    ));
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        f.write_all(&bytes)?;
        f.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
        return Err(Failure::Io);
    }
    #[cfg(test)]
    if super::point("log_synced").is_err() {
        return Err(Failure::Crash);
    }
    if publish(&temp, &main, true).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(Failure::Io);
    }
    flush(&main);
    for temp in temps(dir, id) {
        let _ = fs::remove_file(temp);
    }
    Ok(out)
}
/// Writes an `R` line (spec §5.13, S0r): the review due from `loss`, or
/// from the earliest date of a review already due, the anchor's
/// (`anchor_due`) or the log's own. Returns the date written.
pub(super) fn mark_due(
    dir: &Path,
    id: &[u8; 16],
    loss: &str,
    anchor_due: Option<&str>,
    now: u64,
) -> std::result::Result<String, Failure> {
    append(dir, id, anchor::LOCK_WAIT, |in_log| {
        let mut date = loss.to_owned();
        for due in anchor_due.map(str::to_owned).into_iter().chain(in_log) {
            date = earlier(&due, &date).to_owned();
        }
        (format!("{now} R {date}"), date)
    })
}
/// Writes a `D` line: the review was done.
pub(super) fn mark_done(dir: &Path, id: &[u8; 16], now: u64) -> std::result::Result<(), Failure> {
    append(dir, id, anchor::LOCK_WAIT, |_| (format!("{now} D"), ()))
}

impl Session {
    /// The post-removal review due on this PC for this vault (spec §5.13),
    /// with its loss date (`yyyymmdd` or `unknown`): S-REVIEW is shown at
    /// every unlock until it is done, and the vault outgoing waits for it.
    pub fn review_due(&self) -> Option<&str> {
        self.review_due.as_deref()
    }
    /// [확인함] (`REVIEW_OK`, spec §5.13): the review done, in the anchor
    /// (its `review` line) and in the merge log (a `D` line); then the
    /// vault outgoing that waited for it. While either still says due, the
    /// review stays due.
    pub fn review_done(&mut self) -> Result<()> {
        if self.review_due.is_none() {
            return Ok(());
        }
        let dir = self.anchor.dir.clone().ok_or(super::ANCHOR_FAILED)?;
        self.anchor_strict(&mut |lines| {
            if let Some(r) = lines.review.as_mut() {
                r.due = false;
            }
            true
        })?;
        mark_done(&dir, &self.id, crate::otp::now()?).map_err(failed)?;
        self.review_due = None;
        if let Some(link) = self.sync.as_mut() {
            link.mark_due();
        }
        self.flush_outgoing();
        Ok(())
    }
    /// S0r (spec §5.5, §5.13; S45-2 #11): the merge log's `R` line for a
    /// removal for a loss, before anything is installed. Returns the date
    /// written, which the session's review takes at Commit.
    pub(super) fn review_store(&mut self, loss: &str) -> Result<String> {
        let dir = self.anchor.dir.clone().ok_or(super::ANCHOR_FAILED)?;
        let due = self.due_known();
        mark_due(&dir, &self.id, loss, due.as_deref(), crate::otp::now()?).map_err(failed)
    }
    /// The review this session, or the anchor's `review` line, already
    /// holds due: the earlier date.
    fn due_known(&self) -> Option<String> {
        let line = self
            .anchor
            .lines
            .review
            .as_ref()
            .filter(|r| r.due)
            .map(|r| r.loss.clone());
        match (line, self.review_due.clone()) {
            (Some(a), Some(b)) => Some(earlier(&a, &b).to_owned()),
            (a, b) => a.or(b),
        }
    }
    /// The review becomes due in the session (spec §5.13), keeping the
    /// earlier date of one already due.
    pub(super) fn review_now(&mut self, loss: &str) {
        self.review_due = Some(match self.review_due.as_deref() {
            Some(due) => earlier(due, loss).to_owned(),
            None => loss.to_owned(),
        });
    }
    /// The review due at an unlock (spec §5.13 "Due is durable"): the
    /// anchor's `review` line says due, or the merge log's last review
    /// marker is `R`; the earlier date.
    pub(super) fn review_load(&mut self) {
        let in_log = self.anchor.dir.as_deref().and_then(|d| due(d, &self.id));
        if let Some(loss) = in_log {
            self.review_now(&loss);
        }
        if let Some(loss) = self.due_known() {
            self.review_now(&loss);
        }
    }
}
/// The text of a merge log that could not be written.
fn failed(f: Failure) -> &'static str {
    match f {
        #[cfg(test)]
        Failure::Crash => super::SIMULATED_CRASH,
        Failure::Newer => anchor::ANCHOR_NEWER,
        _ => super::ANCHOR_FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh folder standing for `%LOCALAPPDATA%\GoyoVault`.
    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "goyo-merges-{:x}",
                u128::from_le_bytes(*crypto::random::<16>().unwrap())
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn log(&self, id: &[u8; 16]) -> String {
            String::from_utf8(fs::read(path(&self.0, id)).unwrap()).unwrap()
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Spec §5.13 (S45-3 #4, I14's two-loss case): every `R` line carries
    /// the earlier of its date and a due one, and the reader returns the
    /// earliest `R` date after the last `D`; unknown is the earliest; a `D`
    /// ends the review; lines this core cannot read are kept and skipped.
    #[test]
    fn the_window_only_grows_and_a_d_line_ends_it() {
        let d = Dir::new();
        let (id, other) = ([7; 16], [8; 16]);
        assert_eq!(due(&d.0, &id), None);
        assert_eq!(
            mark_due(&d.0, &id, "20261001", None, 100),
            Ok("20261001".into())
        );
        assert_eq!(
            mark_due(&d.0, &id, "20261020", None, 200),
            Ok("20261001".into())
        );
        assert_eq!(due(&d.0, &id).as_deref(), Some("20261001"));
        // The anchor's due line counts first, when it is earlier.
        assert_eq!(
            mark_due(&d.0, &id, "20261020", Some("20260930"), 250),
            Ok("20260930".into())
        );
        assert_eq!(due(&d.0, &id).as_deref(), Some("20260930"));
        // The log's earlier date counts beside a later one of the anchor.
        assert_eq!(
            mark_due(&d.0, &id, "20261105", Some("20261020"), 260),
            Ok("20260930".into())
        );
        // Another vault's log is its own.
        assert_eq!(due(&d.0, &other), None);
        mark_done(&d.0, &id, 300).unwrap();
        assert_eq!(due(&d.0, &id), None);
        assert_eq!(
            mark_due(&d.0, &id, "20261105", None, 400),
            Ok("20261105".into())
        );
        assert_eq!(mark_due(&d.0, &id, UNKNOWN, None, 500), Ok(UNKNOWN.into()));
        assert_eq!(
            mark_due(&d.0, &id, "20261201", None, 600),
            Ok(UNKNOWN.into())
        );
        assert_eq!(due(&d.0, &id).as_deref(), Some(UNKNOWN));
        // A provenance line of a later stage, and junk, are kept and
        // skipped.
        let p = path(&d.0, &id);
        let mut text = d.log(&id);
        text.push_str("700 12 + 00112233445566778899aabbccddeeff\nnot a line\n800 R 2026\n");
        fs::write(&p, &text).unwrap();
        assert_eq!(due(&d.0, &id).as_deref(), Some(UNKNOWN));
        mark_done(&d.0, &id, 900).unwrap();
        let log = d.log(&id);
        assert!(log.starts_with("goyo-vault-merges 3\n100 R 20261001\n"));
        assert!(log.contains("\nnot a line\n") && log.ends_with("\n900 D\n"));
        assert_eq!(due(&d.0, &id), None);
        // A later `R` after an earlier one (written by another version, or
        // by hand): the reader still returns the earliest.
        fs::write(&p, "goyo-vault-merges 3\n1 R 20261001\n2 R 20261020\n").unwrap();
        assert_eq!(due(&d.0, &id).as_deref(), Some("20261001"));
        // Loss marks: day + 2, 1 unknown, 0 none.
        let t = |c: u8, mark: u64| Tombstone {
            credhash: [c; 16],
            removed: 5 | mark << 48,
        };
        let day = 20_453 + 2; // 2025-12-31
        let tombs = [t(1, day), t(2, 0), t(3, day - 30)];
        assert_eq!(loss_of(&[[1; 16]], &tombs).as_deref(), Some("20251231"));
        assert_eq!(
            loss_of(&[[1; 16], [3; 16]], &tombs).as_deref(),
            Some("20251201")
        );
        assert_eq!(loss_of(&[[2; 16]], &tombs), None);
        assert_eq!(loss_of(&[[1; 16]], &[t(1, 1)]).as_deref(), Some(UNKNOWN));
    }

    /// The log's file rules (spec §5.13): a missing file is taken back from
    /// its newest whole temp file under the lock, which is also the only
    /// time a leftover temp is deleted; a later version's file is never
    /// rewritten; a write waits for the anchor's lock.
    #[test]
    fn the_log_is_written_like_the_anchor() {
        let d = Dir::new();
        let id = [9; 16];
        mark_due(&d.0, &id, "20261001", None, 100).unwrap();
        let p = path(&d.0, &id);
        let whole = fs::read(&p).unwrap();
        let temp = d.0.join(FOLDER).join(format!(
            "{}.log.{}.tmp",
            anchor::hex(&id),
            "0123456789abcdef"
        ));
        let cut = d.0.join(FOLDER).join(format!(
            "{}.log.{}.tmp",
            anchor::hex(&id),
            "fedcba9876543210"
        ));
        fs::write(&temp, &whole).unwrap();
        fs::write(&cut, &whole[..whole.len() - 3]).unwrap();
        fs::remove_file(&p).unwrap();
        assert_eq!(due(&d.0, &id).as_deref(), Some("20261001"));
        mark_done(&d.0, &id, 200).unwrap();
        assert_eq!(d.log(&id), "goyo-vault-merges 3\n100 R 20261001\n200 D\n");
        assert!(temps(&d.0, &id).is_empty());
        // A later version: never rewritten, read as nothing due.
        fs::write(&p, "goyo-vault-merges 4\n100 R 20261001\n").unwrap();
        assert_eq!(
            mark_due(&d.0, &id, "20261001", None, 300),
            Err(Failure::Newer)
        );
        assert_eq!(due(&d.0, &id), None);
        assert_eq!(d.log(&id), "goyo-vault-merges 4\n100 R 20261001\n");
        // The anchor's lock held by another process: busy, nothing written.
        fs::write(&p, "goyo-vault-merges 3\n").unwrap();
        let _held = anchor::hold_lock(&d.0);
        let busy = append(&d.0, &id, std::time::Duration::ZERO, |_| ("1 D".into(), ()));
        assert_eq!(busy, Err(Failure::Busy));
        assert_eq!(d.log(&id), "goyo-vault-merges 3\n");
    }
}
