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
//! window (S45-3 #4). The provenance lines (stage 5): every merge of an
//! incoming copy in a session with security keys and vault sync writes one
//! line per change it brought in before the merged vault is saved; the log
//! keeps at most 4,000 of them (the oldest before a due review's window go
//! first, and a `!` line says when lines inside it had to go); S-REVIEW
//! lists the lines from the day before the loss on. Lines this build cannot
//! read are kept and skipped.
//!
//! The log is unauthenticated: whoever can write the anchor's folder can
//! erase lines. It only makes a review due where a removal for a loss
//! landed on this PC; the docs say so (§13).
use super::{Entry, EntryId, Session, anchor, anchor::Failure, flush, keyfile::Tombstone, publish};
use crate::crypto::{self, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
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
/// Most entry lines kept per vault (spec §5.13).
const ENTRY_LINES: usize = 4_000;
const DAY: u64 = 86_400;

/// The Unix seconds of a day's start (UTC), from `YYYY-MM-DD` or
/// `YYYYMMDD`; None for anything else, or for a day that does not exist.
pub fn day_of(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits: String = text.chars().filter(|c| *c != '-').collect();
    let dashed = text.len() == 10 && text.as_bytes()[4] == b'-' && text.as_bytes()[7] == b'-';
    if digits.len() != 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text.len() != 8 && !dashed {
        return None;
    }
    let (y, m, d): (u64, u64, u64) = (
        digits[..4].parse().ok()?,
        digits[4..6].parse().ok()?,
        digits[6..].parse().ok()?,
    );
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let secs = (era * 146_097 + doe).checked_sub(719_468)? * DAY;
    // 2026-02-31 and the like come back as another day.
    (crate::fido::stamp(secs)[..8] == digits).then_some(secs)
}
/// A time as the review list shows it: `YYYY-MM-DD HH:MM` (UTC).
pub fn shown_time(secs: u64) -> String {
    let s = crate::fido::stamp(secs);
    format!(
        "{}-{}-{} {}:{}",
        &s[..4],
        &s[4..6],
        &s[6..8],
        &s[9..11],
        &s[11..13]
    )
}
/// The first second a review with this loss date lists: the day before
/// the loss; 0 (the whole log) when the day is unknown.
fn window_start(loss: &str) -> u64 {
    day_of(loss).map_or(0, |d| d.saturating_sub(DAY))
}

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
    append_lines(dir, id, wait, None, |due| {
        let (line, out) = make(due);
        (vec![line], out)
    })
}
/// `append` for any number of lines, with the cap (spec §5.13): over
/// ENTRY_LINES entry lines or LIMIT bytes, the oldest entry lines before
/// the window of a due review (the earlier of `anchor_due` and the log's
/// own; with none due, before the last `D`) go first; when lines inside the
/// window must go, the oldest go and a `!` line records the time before
/// which lines are missing.
fn append_lines<T>(
    dir: &Path,
    id: &[u8; 16],
    wait: std::time::Duration,
    anchor_due: Option<&str>,
    make: impl FnOnce(Option<String>) -> (Vec<String>, T),
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
    let (added, out) = make(due_in(&lines));
    let mut all: Vec<Vec<u8>> = lines.iter().map(|l| l.to_vec()).collect();
    all.extend(added.into_iter().map(String::into_bytes));
    let all = capped(all, anchor_due);
    let mut bytes = Vec::with_capacity(old.len() + VERSION.len() + 64);
    bytes.extend_from_slice(VERSION.as_bytes());
    bytes.push(b'\n');
    for l in &all {
        bytes.extend_from_slice(l);
        bytes.push(b'\n');
    }
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
/// The time of an entry line (`+`, `~`, `=` or `-`); None for any other.
fn entry_time(line: &[u8]) -> Option<u64> {
    let line = std::str::from_utf8(line).ok()?;
    let mut words = line.split(' ');
    let time = words.next()?.parse().ok()?;
    words.next()?.parse::<u64>().ok()?;
    matches!(words.next()?, "+" | "~" | "=" | "-").then_some(time)
}
/// The lines with the cap applied (see append_lines).
fn capped(mut all: Vec<Vec<u8>>, anchor_due: Option<&str>) -> Vec<Vec<u8>> {
    let size = |all: &[Vec<u8>]| VERSION.len() + 1 + all.iter().map(|l| l.len() + 1).sum::<usize>();
    let entries = |all: &[Vec<u8>]| all.iter().filter(|l| entry_time(l).is_some()).count();
    // Room for the `!` line.
    let over = |all: &[Vec<u8>]| entries(all) > ENTRY_LINES || size(all) + 48 > LIMIT;
    if !over(&all) {
        return all;
    }
    let refs: Vec<&[u8]> = all.iter().map(Vec::as_slice).collect();
    let due = match (due_in(&refs), anchor_due) {
        (Some(a), Some(b)) => Some(earlier(&a, b).to_owned()),
        (a, b) => a.or(b.map(str::to_owned)),
    };
    let start = match due {
        Some(loss) => window_start(&loss),
        // None due: what came before the last review done goes first.
        None => all
            .iter()
            .filter_map(|l| {
                let (time, rest) = std::str::from_utf8(l).ok()?.split_once(' ')?;
                (rest == "D").then(|| time.parse::<u64>().ok()).flatten()
            })
            .max()
            .unwrap_or(0),
    };
    let mut lost: Option<u64> = None;
    for inside in [false, true] {
        while over(&all) {
            let oldest = all
                .iter()
                .enumerate()
                .filter_map(|(i, l)| entry_time(l).map(|t| (t, i)))
                .filter(|(t, _)| inside || *t < start)
                .min();
            let Some((time, i)) = oldest else {
                break;
            };
            all.remove(i);
            if inside {
                lost = Some(lost.map_or(time + 1, |l| l.max(time + 1)));
            }
        }
    }
    if let Some(before) = lost {
        let now = crate::otp::now().unwrap_or(before);
        all.push(format!("{now} ! {before}").into_bytes());
    }
    all
}
/// One change a merge brought in (spec §5.13), as its log line says it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Brought {
    /// `+`: a new entry.
    New(EntryId),
    /// `~`: a new ID replacing `parent`, an edit made on another PC.
    Edit(EntryId, EntryId),
    /// `=`: other content now under an ID the local copy had; the local
    /// text moved to the second ID, or was dropped.
    Replaced(EntryId, Option<EntryId>),
    /// `-`: a deletion.
    Deleted(EntryId),
}
impl Brought {
    fn line(&self, now: u64, version: u64) -> String {
        let h = |id: &EntryId| anchor::hex(id);
        match self {
            Self::New(id) => format!("{now} {version} + {}", h(id)),
            Self::Edit(id, parent) => format!("{now} {version} ~ {} {}", h(id), h(parent)),
            Self::Replaced(id, moved) => {
                let moved = moved.as_ref().map_or_else(|| "-".to_owned(), h);
                format!("{now} {version} = {} {moved}", h(id))
            }
            Self::Deleted(id) => format!("{now} {version} - {}", h(id)),
        }
    }
    /// A line's time and change; None for any other line.
    fn parse(line: &[u8]) -> Option<(u64, Self)> {
        fn id(s: &str) -> Option<EntryId> {
            let b = s.as_bytes();
            if b.len() != 32 || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return None;
            }
            let mut out = [0u8; 16];
            for (i, o) in out.iter_mut().enumerate() {
                *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
            }
            Some(out)
        }
        let line = std::str::from_utf8(line).ok()?;
        let w: Vec<&str> = line.split(' ').collect();
        let time = w.first()?.parse().ok()?;
        w.get(1)?.parse::<u64>().ok()?;
        let what = match (*w.get(2)?, w.len()) {
            ("+", 4) => Self::New(id(w[3])?),
            ("~", 5) => Self::Edit(id(w[3])?, id(w[4])?),
            ("=", 5) if w[4] == "-" => Self::Replaced(id(w[3])?, None),
            ("=", 5) => Self::Replaced(id(w[3])?, Some(id(w[4])?)),
            ("-", 4) => Self::Deleted(id(w[3])?),
            _ => return None,
        };
        Some((time, what))
    }
    /// Lines with the same entry ID and operation are shown once.
    fn key(&self) -> (EntryId, u8) {
        match self {
            Self::New(id) => (*id, b'+'),
            Self::Edit(id, _) => (*id, b'~'),
            Self::Replaced(id, _) => (*id, b'='),
            Self::Deleted(id) => (*id, b'-'),
        }
    }
}
/// What a merge brought in (spec §5.13), comparing the local copy before
/// it with the result by entry ID and content: other content under a local
/// ID (`=`, with where the local text went), entries new to this PC (`+`,
/// or `~` for an edit's new ID), and deletions of local entries (`-`; not
/// for the parent of an edit, which its `~` line already names).
pub(super) fn brought(
    before: &[Entry],
    dead_before: &[EntryId],
    after: &[Entry],
    dead_after: &[EntryId],
) -> Vec<Brought> {
    let old: BTreeMap<EntryId, &Entry> = before.iter().map(|e| (e.id, e)).collect();
    let mut out = Vec::new();
    let mut moved_to: BTreeSet<EntryId> = BTreeSet::new();
    for e in after {
        if let Some(local) = old.get(&e.id)
            && !local.same_content(e)
        {
            let moved = after
                .iter()
                .find(|m| m.parent == e.id && !old.contains_key(&m.id) && m.same_content(local))
                .map(|m| m.id);
            moved_to.extend(moved);
            out.push(Brought::Replaced(e.id, moved));
        }
    }
    let mut parents: BTreeSet<EntryId> = BTreeSet::new();
    for e in after {
        if old.contains_key(&e.id) || moved_to.contains(&e.id) {
            continue;
        }
        if e.parent == [0; 16] {
            out.push(Brought::New(e.id));
        } else {
            parents.insert(e.parent);
            out.push(Brought::Edit(e.id, e.parent));
        }
    }
    let dead: BTreeSet<&EntryId> = dead_before.iter().collect();
    for t in dead_after {
        if !dead.contains(t) && old.contains_key(t) && !parents.contains(t) {
            out.push(Brought::Deleted(*t));
        }
    }
    out
}
/// Writes the lines of one merge (spec §5.13) before the merged vault is
/// saved, waiting at most LOCK_WAIT for the lock.
pub(super) fn record(
    dir: &Path,
    id: &[u8; 16],
    now: u64,
    version: u64,
    brought: &[Brought],
    anchor_due: Option<&str>,
) -> std::result::Result<(), Failure> {
    let lines = brought.iter().map(|b| b.line(now, version)).collect();
    append_lines(dir, id, anchor::LOCK_WAIT, anchor_due, |_| (lines, ()))
}
/// The log's changes from `start` on, each (entry ID, operation) once, and
/// the latest time before which a `!` line says lines are missing, when it
/// lies after `start`.
fn since(dir: &Path, id: &[u8; 16], start: u64) -> (Vec<(u64, Brought)>, Option<u64>) {
    let Some(bytes) = read(dir, id).ok().flatten() else {
        return (Vec::new(), None);
    };
    let Ok(lines) = lines_of(&bytes) else {
        return (Vec::new(), None);
    };
    let mut seen: BTreeSet<(EntryId, u8)> = BTreeSet::new();
    let mut out = Vec::new();
    let mut lost: Option<u64> = None;
    for line in lines {
        if let Some((time, what)) = Brought::parse(line) {
            if time >= start && seen.insert(what.key()) {
                out.push((time, what));
            }
            continue;
        }
        let text = std::str::from_utf8(line).unwrap_or("");
        let mut w = text.split(' ');
        if let (Some(_), Some("!"), Some(before), None) = (w.next(), w.next(), w.next(), w.next())
            && let Ok(before) = before.parse::<u64>()
            && before > start
        {
            lost = Some(lost.map_or(before, |l| l.max(before)));
        }
    }
    (out, lost)
}

/// What a row of the review list is (spec §5.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReviewChange {
    /// A new entry ("새 항목").
    New,
    /// An entry edited on another PC ("고친 항목").
    Edited,
    /// Another PC's content under an ID this PC had (S-REVIEW-REPLACED).
    Replaced,
    /// This PC's own text, which the merge moved to a new ID.
    Moved,
    /// An entry deleted on another PC.
    Deleted,
}
/// One row of the review list: the change, the entry's current title and
/// its index in the open vault when it is live here, and the local merge
/// time.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReviewRow {
    pub change: ReviewChange,
    pub title: Option<String>,
    pub index: Option<usize>,
    pub time: u64,
}
/// The review list (spec §5.13): `=` rows first (each followed by the row
/// of the moved local text), then the rest in log order, and the time
/// before which the cap dropped lines inside the window (S-REVIEW-TRUNC).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ReviewList {
    pub rows: Vec<ReviewRow>,
    pub truncated: Option<u64>,
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
    /// The review list (spec §5.13) for the loss on day `loss` (its Unix
    /// seconds, as `day_of` gives them; None for an unknown day, which lists
    /// the whole log): every logged change from the day before on, with the
    /// entry's current title where it is live.
    pub fn review_list(&self, loss: Option<u64>) -> ReviewList {
        let Some(dir) = self.anchor.dir.as_deref() else {
            return ReviewList::default();
        };
        let start = loss.map_or(0, |d| d.saturating_sub(DAY));
        let (logged, truncated) = since(dir, &self.id, start);
        let row = |change, id: &EntryId, time: u64| {
            let index = self.entries.iter().position(|e| e.id == *id);
            ReviewRow {
                change,
                title: index.map(|i| self.entries[i].title.to_string()),
                index,
                time,
            }
        };
        let mut rows = Vec::new();
        for (time, what) in &logged {
            if let Brought::Replaced(id, moved) = what {
                rows.push(row(ReviewChange::Replaced, id, *time));
                if let Some(m) = moved {
                    rows.push(row(ReviewChange::Moved, m, *time));
                }
            }
        }
        for (time, what) in &logged {
            match what {
                Brought::New(id) => rows.push(row(ReviewChange::New, id, *time)),
                Brought::Edit(id, _) => rows.push(row(ReviewChange::Edited, id, *time)),
                Brought::Deleted(_) => rows.push(ReviewRow {
                    change: ReviewChange::Deleted,
                    title: None,
                    index: None,
                    time: *time,
                }),
                Brought::Replaced(..) => {}
            }
        }
        ReviewList { rows, truncated }
    }
    /// Whether this session's merges are logged (spec §5.13): a key file
    /// with security keys (only a session with vault sync on merges).
    pub(super) fn logs_merges(&self) -> bool {
        self.key_file.needs_security_key()
    }
    /// The lines of a merge that brought `brought` in from server version
    /// `version`, written before the merged vault is saved: Err leaves the
    /// merge unsaved, and it runs again at the next poll.
    pub(super) fn log_merge(
        &self,
        version: u64,
        brought: &[Brought],
    ) -> std::result::Result<(), ()> {
        if brought.is_empty() {
            return Ok(());
        }
        let dir = self.anchor.dir.as_deref().ok_or(())?;
        let now = crate::otp::now().map_err(|_| ())?;
        let due = self.due_known();
        record(dir, &self.id, now, version, brought, due.as_deref()).map_err(|_| ())
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

    /// Days as the loss date field and the anchor give them (spec §5.13).
    #[test]
    fn days_are_read_strictly() {
        assert_eq!(day_of("2026-10-29"), Some(1_793_232_000));
        assert_eq!(day_of(" 20261029 "), Some(1_793_232_000));
        assert_eq!(day_of("1970-01-01"), Some(0));
        assert_eq!(shown_time(1_793_232_000 + 3_661), "2026-10-29 01:01");
        for bad in [
            "",
            "2026-02-31",
            "2026/10/29",
            "2026-1-029",
            "1969-12-31",
            "20261",
            "unknown",
            "2026-10-29-",
        ] {
            assert_eq!(day_of(bad), None, "{bad}");
        }
    }

    fn entry(id: u8, parent: u8, text: &str) -> Entry {
        let mut e = Entry::new(text.into(), "kind".into(), text.into(), String::new()).unwrap();
        e.id = [id; 16];
        e.parent = [parent; 16];
        e
    }
    /// Spec §5.13 (round 2, finding 6): what a merge brought in, by ID and
    /// content: other text under a local ID (`=`, with where the local
    /// text moved), a new entry (`+`), an edit's new ID (`~`, its parent no
    /// deletion of its own) and a deletion (`-`); the lines read back once
    /// each, in the review list's order, from the day before the loss on.
    #[test]
    fn merges_are_logged_by_id_and_content() {
        let before = [entry(1, 0, "one"), entry(2, 0, "two"), entry(3, 0, "three")];
        let after = [
            entry(2, 0, "!injected"),
            entry(9, 2, "two"),
            entry(3, 0, "three"),
            entry(4, 0, "four"),
            entry(5, 3, "three, edited"),
        ];
        let got = brought(&before, &[], &after, &[[1; 16], [3; 16]]);
        assert_eq!(
            got,
            [
                Brought::Replaced([2; 16], Some([9; 16])),
                Brought::New([4; 16]),
                Brought::Edit([5; 16], [3; 16]),
                Brought::Deleted([1; 16]),
            ]
        );
        // Nothing new: no line.
        assert!(brought(&before, &[], &before, &[]).is_empty());
        let d = Dir::new();
        let id = [6; 16];
        record(&d.0, &id, 1_000, 7, &got, None).unwrap();
        // A retried merge logs again; the reader shows each line once.
        record(&d.0, &id, 2_000, 7, &got, None).unwrap();
        let log = d.log(&id);
        assert!(log.contains(&format!(
            "\n1000 7 = {} {}\n",
            anchor::hex(&[2; 16]),
            anchor::hex(&[9; 16])
        )));
        let (lines, lost) = since(&d.0, &id, 0);
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|(t, _)| *t == 1_000));
        assert_eq!(lost, None);
        assert!(since(&d.0, &id, 1_001).0.iter().all(|(t, _)| *t == 2_000));
        // The markers still read as before.
        mark_due(&d.0, &id, UNKNOWN, None, 3_000).unwrap();
        assert_eq!(due(&d.0, &id).as_deref(), Some(UNKNOWN));
    }
    /// The cap (spec §5.13; S45-3 #4): over 4,000 entry lines, those before
    /// a due review's window go first with no `!` line; when lines inside
    /// it must go, the oldest go and a `!` line says before when lines are
    /// missing, which the reader reports for the window.
    #[test]
    fn the_log_is_capped_outside_the_window_first() {
        let d = Dir::new();
        let id = [5; 16];
        let lines = |from: u32, n: u32| -> Vec<Brought> {
            (from..from + n)
                .map(|i| {
                    let mut e = [0u8; 16];
                    e[..4].copy_from_slice(&i.to_le_bytes());
                    Brought::New(e)
                })
                .collect()
        };
        // Due from 1970-01-05: the window starts on its day before.
        let due = Some("19700105");
        let start = 3 * DAY;
        record(&d.0, &id, 100, 1, &lines(0, 3_000), due).unwrap();
        record(&d.0, &id, 300_000, 2, &lines(3_000, 1_010), due).unwrap();
        let entries = |d: &Dir| d.log(&id).lines().filter(|l| l.contains(" + ")).count();
        assert_eq!(entries(&d), ENTRY_LINES);
        assert!(!d.log(&id).contains(" ! "));
        assert_eq!(since(&d.0, &id, start).0.len(), 1_010);
        record(&d.0, &id, 400_000, 3, &lines(4_010, 3_000), due).unwrap();
        assert_eq!(entries(&d), ENTRY_LINES);
        let (kept, lost) = since(&d.0, &id, start);
        assert_eq!(kept.len(), ENTRY_LINES);
        assert_eq!(lost, Some(300_001));
        // With no review due, what came before the last `D` goes first.
        let other = [4; 16];
        record(&d.0, &other, 100, 1, &lines(0, 3_990), None).unwrap();
        mark_done(&d.0, &other, 200).unwrap();
        record(&d.0, &other, 300, 2, &lines(5_000, 20), None).unwrap();
        let log = d.log(&other);
        assert!(!log.contains(" ! ") && log.contains("\n200 D\n"));
        assert_eq!(since(&d.0, &other, 0).0.len(), ENTRY_LINES);
        assert_eq!(since(&d.0, &other, 300).0.len(), 20);
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
