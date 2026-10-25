//! The vault side of sync. goyo-vault.exe has no network code: it merges the
//! server copy that goyo-sync.exe leaves in `<vault>.sync\incoming.goyosync`
//! and leaves its own state in `outgoing.goyosync` for the helper to upload.
//! Everything here is local, bounded file I/O on the app's timer. A sync
//! problem never fails an unlock or a save; it shows as a badge or a notice.
//! No Korean text: the app turns `SyncNotice` and `SyncBadge` into its own.
use super::{
    Contents, DataRef, Entry, EntryId, Format, Session, atomic_write, decode_data, encode_data,
    newer_format, plain_size,
};
use crate::{
    merge::{self, MergeError, MergeReport},
    otp,
    syncfile::{self, FileError, INCOMING, OUTGOING, Stamp, SyncState, SyncStatus},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// A heartbeat older than this means the helper is not running.
const HEARTBEAT_STALE: u64 = 180;
/// The status file is read on every 5th poll (10 s); it only picks a badge.
const STATUS_EVERY: u32 = 5;
/// Polls without an outgoing write after a failed one. Each Busy write holds
/// the UI thread for about 150 ms of retries, so a handle that stays open
/// (a scanner, an editor) costs that at most every third poll.
const BUSY_SKIP: u32 = 2;
/// Pre-merge safety copies: the newest three always stay, and any other
/// younger than 30 days while there are at most 20 in all.
const KEEP_COPIES: usize = 3;
const MAX_COPIES: usize = 20;
const COPY_DAYS: u64 = 30;
/// The last time a ten-digit copy name can hold.
const LAST_COPY_TIME: u64 = 9_999_999_999;

/// The word in front of the file name on the "open" pill.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncBadge {
    /// This PC's live entries and deletions equal the newest server copy the
    /// helper fetched, checked with the key. The helper's word never gives it.
    Synced,
    /// Changes wait for the helper or the server.
    Uploading,
    /// No status file, or none rewritten in the last 3 minutes.
    HelperOff,
    /// The helper cannot reach the server (offline, auth, hostkey, nossh or
    /// server in its status).
    Offline,
    /// Something needs the user: a rollback, a bad or newer server copy, a
    /// merge over the limits (for the rest of the session), or a status of
    /// refused, config or update.
    Warning,
}

/// One status-line message. The app picks the localized text and tone; the
/// data here fills its `{}` slots.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SyncNotice {
    /// Never produced here: the app shows it after `enable_sync`.
    SyncOn,
    Merged {
        added: usize,
        removed: usize,
    },
    /// Entries edited on two PCs, or other text under one ID, kept in both
    /// versions. Never a title: the status line is a window text that other
    /// programs can read.
    Conflicts(usize),
    /// Merges since the last safety copy lost many entries; `file` is the
    /// copy of the state before the first of them, relative to the vault's
    /// folder, e.g. `vault.goyo.sync\pre-merge-1792000000.goyo`.
    MassDelete {
        removed: usize,
        file: String,
    },
    Rollback,
    BadIncoming,
    /// The server copy belongs to another vault: the sync folder must be
    /// reset (docs/SYNC.md).
    ForeignIncoming,
    TooLarge,
    NewerFormat,
    KeyInFolder,
    /// The check code, `XXXX-XXXX-XXXX-XXXX`; given once per session.
    Synced {
        code: String,
    },
    HelperOff,
    Offline,
    HostKey,
    Auth,
    HelperError,
}
impl SyncNotice {
    /// Lower wins when one event has several.
    fn rank(&self) -> u8 {
        match self {
            Self::Rollback => 0,
            Self::BadIncoming | Self::ForeignIncoming => 1,
            Self::TooLarge => 2,
            Self::NewerFormat | Self::KeyInFolder => 3,
            Self::MassDelete { .. } => 4,
            Self::Conflicts(_) => 5,
            Self::Merged { .. } => 6,
            Self::HostKey | Self::Auth | Self::HelperError | Self::Offline | Self::HelperOff => 7,
            Self::Synced { .. } => 8,
            Self::SyncOn => 9,
        }
    }
    /// Whether the helper's status file causes this notice.
    fn is_status(&self) -> bool {
        matches!(
            self,
            Self::HelperOff
                | Self::Offline
                | Self::HostKey
                | Self::Auth
                | Self::HelperError
                | Self::NewerFormat
        )
    }
}
/// Keeps the higher-precedence notice of an event.
fn offer(slot: &mut Option<SyncNotice>, notice: SyncNotice) {
    if slot.as_ref().is_none_or(|s| notice.rank() < s.rank()) {
        *slot = Some(notice);
    }
}

/// What one `Session::poll_sync` changed for the window.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SyncEvent {
    /// Entries were added, removed or replaced: indices may have moved.
    pub list_changed: bool,
    pub notice: Option<SyncNotice>,
    /// `Session::badge` differs from the last poll or edit.
    pub badge_changed: bool,
}

/// The session's link to an existing `<vault>.sync` folder.
pub(crate) struct SyncLink {
    dir: PathBuf,
    /// The incoming file last handled; another stamp means a new file.
    in_stamp: Option<Stamp>,
    /// Server version of the incoming last merged or repaired, 0 for none:
    /// the base of the next upload.
    merged_version: u64,
    /// The live IDs and tombstones equal those of the newest incoming.
    verified: bool,
    /// This PC's state still has to be written to outgoing.
    outgoing_due: bool,
    /// Polls left before outgoing is written again after a failed write.
    busy_skip: u32,
    /// A rollback, a bad or newer incoming, or a merge over a limit was
    /// seen: the badge stays Warning for the session.
    warned: bool,
    /// Incoming is in a newer format: nothing more is merged or uploaded.
    halted: bool,
    /// The last merge was over a limit; an edit may make it fit.
    too_large: bool,
    /// The incoming whose pre-merge copy is written, and the copy's name, so
    /// a merge retried after a failed vault write makes no second copy.
    copied_for: Option<(Stamp, String)>,
    /// Entries lost by merges since the last safety copy, and the state
    /// before the first of them, encrypted like the vault: losses in small
    /// steps add up, and the copy they lead to holds every one.
    losses: Option<(usize, Vec<u8>)>,
    /// The status file at its last read; None while it is missing.
    status: Option<SyncStatus>,
    /// The status notice last shown, so each is shown once per change.
    issue: Option<SyncNotice>,
    polls: u32,
    code_shown: bool,
    /// The badge after the last poll or edit, for `SyncEvent::badge_changed`.
    last_badge: Option<SyncBadge>,
}
pub(super) enum Attach {
    /// No usable folder: not set up, or not a plain directory.
    Absent,
    /// The key file is inside the folder; it must never be next to what the
    /// helper uploads.
    KeyInFolder,
    Linked(Box<SyncLink>),
}
impl SyncLink {
    /// Links to `<vault>.sync` if it is a plain directory that does not hold
    /// the key file. Only the helper creates the folder.
    pub(super) fn attach(vault: &Path, key_path: &Path) -> Attach {
        let Some(dir) = syncfile::sync_dir(vault).filter(|d| syncfile::usable_dir(d)) else {
            return Attach::Absent;
        };
        match key_inside(key_path, &dir) {
            None => return Attach::Absent,
            Some(true) => return Attach::KeyInFolder,
            Some(false) => {}
        }
        let mut link = SyncLink {
            dir,
            in_stamp: None,
            merged_version: 0,
            verified: false,
            outgoing_due: false,
            busy_skip: 0,
            warned: false,
            halted: false,
            too_large: false,
            copied_for: None,
            losses: None,
            status: None,
            issue: None,
            polls: 0,
            code_shown: false,
            last_badge: None,
        };
        link.read_status();
        Attach::Linked(Box::new(link))
    }
    /// Takes the link into use. Nothing of ours is being written yet, so any
    /// temp file of ours is a leftover. Not done in `attach`: an unlock
    /// changes nothing on disk before the OTP code passed.
    fn start(self) -> Self {
        syncfile::remove_own_temps(&self.dir, &syncfile::APP_TEMPS);
        self
    }
    /// A Busy read keeps the previous view: the helper was replacing it.
    fn read_status(&mut self) {
        match syncfile::read_status(&self.dir) {
            Ok(status) => self.status = Some(status),
            Err(FileError::Busy) => {}
            Err(_) => self.status = None,
        }
    }
    fn badge(&self, now: u64) -> SyncBadge {
        use SyncState as S;
        let state = self.status.and_then(|s| s.state);
        if self.warned || matches!(state, Some(S::Refused | S::Config | S::Update)) {
            SyncBadge::Warning
        } else if self.helper_off(now) {
            SyncBadge::HelperOff
        } else if matches!(
            state,
            Some(S::Offline | S::Auth | S::HostKey | S::NoSsh | S::Server)
        ) {
            SyncBadge::Offline
        } else if self.verified {
            SyncBadge::Synced
        } else {
            SyncBadge::Uploading
        }
    }
    /// A heartbeat far in the future is stale too: one written before the
    /// clock was set back would otherwise hide a stopped helper.
    fn helper_off(&self, now: u64) -> bool {
        self.status.is_none_or(|s| {
            s.heartbeat.saturating_add(HEARTBEAT_STALE) < now
                || s.heartbeat > now.saturating_add(HEARTBEAT_STALE)
        })
    }
    /// The notice the status file calls for, in the badge's order.
    fn status_notice(&self, now: u64) -> Option<SyncNotice> {
        use SyncState as S;
        match self.status.and_then(|s| s.state) {
            Some(S::Update) => return Some(SyncNotice::NewerFormat),
            Some(S::Refused | S::Config) => return Some(SyncNotice::HelperError),
            _ if self.helper_off(now) => return Some(SyncNotice::HelperOff),
            _ => {}
        }
        match self.status.and_then(|s| s.state)? {
            S::Offline => Some(SyncNotice::Offline),
            S::Auth => Some(SyncNotice::Auth),
            S::HostKey => Some(SyncNotice::HostKey),
            S::NoSsh | S::Server => Some(SyncNotice::HelperError),
            _ => None,
        }
    }
    /// Offers the status notice if it differs from the last one shown.
    fn offer_status(&mut self, notice: &mut Option<SyncNotice>, now: u64) {
        match self.status_notice(now) {
            None => self.issue = None,
            Some(issue) if Some(&issue) != self.issue.as_ref() => offer(notice, issue),
            Some(_) => {}
        }
    }
    /// Remembers what the chosen notice told, so it is not told again. A
    /// status notice that lost to another one is offered again later.
    fn told(&mut self, notice: &Option<SyncNotice>) {
        match notice {
            Some(SyncNotice::Synced { .. }) => self.code_shown = true,
            Some(n) if n.is_status() => self.issue = Some(n.clone()),
            _ => {}
        }
    }
    /// Reads and judges incoming as of `stamp` against `local`.
    fn fetch(&self, stamp: Stamp, id: &[u8; 16], key: &[u8; 32], local: DataRef) -> Fetched {
        let Ok(now) = otp::now() else {
            return Fetched::Retry;
        };
        let bytes = match syncfile::read_bounded(&self.dir.join(INCOMING), syncfile::MAX_WRAPPED) {
            Ok(bytes) => bytes,
            Err(FileError::Missing) => return Fetched::Missing,
            // The helper is replacing it: read the new file next time.
            Err(FileError::Busy | FileError::Io) => return Fetched::Retry,
            Err(FileError::TooLarge) => Vec::new(),
        };
        let got = |version, verdict| {
            Fetched::Got(Arrival {
                stamp,
                version,
                verdict,
            })
        };
        let Some((version, blob)) = syncfile::parse_incoming(&bytes) else {
            return got(0, Verdict::Damaged);
        };
        if newer_format(blob) {
            return got(version, Verdict::Newer);
        }
        if blob[8..24] != id[..] {
            return got(version, Verdict::Foreign);
        }
        // A v1 file was never on a server: someone put it there.
        let verdict = match decode_data(id, key, blob) {
            Ok((Format::V2, remote)) => match merge::merge(key, local, remote, now / 30) {
                Ok((merged, report)) => Verdict::Merged(merged, report),
                Err(MergeError::TooLarge) => Verdict::TooLarge,
            },
            Ok((Format::V1, _)) | Err(_) => Verdict::Unreadable,
        };
        got(version, verdict)
    }
}
/// Whether the key file is in `dir` or below it, comparing final paths
/// without regard to case, as Windows does. None if `dir` cannot be resolved.
fn key_inside(key_path: &Path, dir: &Path) -> Option<bool> {
    let dir = fs::canonicalize(dir).ok()?;
    let parent = key_path.parent().unwrap_or(key_path);
    let parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
    Some(lower(&parent).starts_with(lower(&dir)))
}

/// What incoming held.
enum Fetched {
    /// No file yet: the helper fetched nothing.
    Missing,
    /// Not readable now; the next poll tries again.
    Retry,
    Got(Arrival),
}
struct Arrival {
    stamp: Stamp,
    version: u64,
    verdict: Verdict,
}
enum Verdict {
    /// GOYOVA03 or later: sync stops for this session.
    Newer,
    /// No valid wrapper: ignored. Its version means nothing, so no repair
    /// is pushed over it.
    Damaged,
    /// Another vault's copy (e.g. a new vault at a synced path): ignored,
    /// and nothing is pushed over it.
    Foreign,
    /// This vault's ID, but it fails authentication (or is v1): ignored, and
    /// this PC's state is pushed over that server version.
    Unreadable,
    /// The merge would exceed a limit: nothing changes.
    TooLarge,
    Merged(Contents, MergeReport),
}

/// What `Session::load` found in the sync folder before the OTP check.
pub(super) struct Pending {
    link: Option<Box<SyncLink>>,
    fetched: Option<Fetched>,
    key_in_folder: bool,
}
impl Pending {
    /// Links and reads incoming for a login. A restore writes a new file and
    /// a new vault has no copies, so neither links here.
    pub(super) fn find(
        login: bool,
        vault: &Path,
        key_path: &Path,
        format: Format,
        id: &[u8; 16],
        key: &[u8; 32],
        local: DataRef,
    ) -> Self {
        let mut pending = Self {
            link: None,
            fetched: None,
            key_in_folder: false,
        };
        if !login {
            return pending;
        }
        match SyncLink::attach(vault, key_path) {
            Attach::Absent => {}
            Attach::KeyInFolder => pending.key_in_folder = true,
            // A v1 vault does not sync yet; `sync_offer` asks first.
            Attach::Linked(_) if format == Format::V1 => {}
            Attach::Linked(link) => {
                pending.fetched = Some(match syncfile::stamp(&link.dir, INCOMING) {
                    None => Fetched::Missing,
                    Some(stamp) => link.fetch(stamp, id, key, local),
                });
                pending.link = Some(link);
            }
        }
        pending
    }
    /// The OTP watermark to check the code against: the merged one, so a code
    /// another PC used is refused once that PC's content has synced here.
    pub(super) fn last(&self, local: u64) -> u64 {
        match &self.fetched {
            Some(Fetched::Got(Arrival {
                verdict: Verdict::Merged(merged, _),
                ..
            })) => merged.last.max(local),
            _ => local,
        }
    }
}

/// What applying an incoming file did.
struct Taken {
    wrote: bool,
    list_changed: bool,
}

impl Session {
    /// The badge for the pill, or None when this vault does not sync. Read it
    /// after unlocking, after `enable_sync`, `put` and `delete`, and whenever
    /// `poll_sync` says it changed.
    pub fn badge(&self) -> Option<SyncBadge> {
        Some(self.sync.as_ref()?.badge(now_secs()))
    }
    /// The notice for the line shown after unlocking, once.
    pub fn take_unlock_notice(&mut self) -> Option<SyncNotice> {
        self.unlock_notice.take()
    }
    /// Whether to offer turning sync on: the vault is v1 and the helper made
    /// its folder, which does not hold the key file.
    pub fn sync_offer(&self) -> bool {
        self.format == Format::V1
            && syncfile::sync_dir(&self.path)
                .filter(|d| syncfile::usable_dir(d))
                .is_some_and(|d| key_inside(&self.key_path, &d) == Some(false))
    }
    /// Code over the live entries, text included, and the tombstones,
    /// `XXXX-XXXX-XXXX-XXXX`: equal on two PCs means equal contents.
    pub fn check_code(&self) -> String {
        merge::check_code(&self.key, &self.entries, &self.tombstones)
    }
    /// Call every 2 s while the vault list is shown and no dialog is open: it
    /// merges a new server copy (changing `entries`), retries the upload and
    /// reads the helper's status. None when there is nothing to show.
    pub fn poll_sync(&mut self) -> Option<SyncEvent> {
        let mut notice = None;
        if let Some(refused) = self.connect() {
            offer(&mut notice, refused);
        }
        let Some(mut link) = self.sync.take() else {
            return notice.map(|n| SyncEvent {
                notice: Some(n),
                ..SyncEvent::default()
            });
        };
        let list_changed = self.poll_link(&mut link, &mut notice);
        link.told(&notice);
        let badge = link.badge(now_secs());
        let badge_changed = link.last_badge != Some(badge);
        link.last_badge = Some(badge);
        self.sync = Some(link);
        let event = SyncEvent {
            list_changed,
            notice,
            badge_changed,
        };
        (event != SyncEvent::default()).then_some(event)
    }
    fn poll_link(&mut self, link: &mut SyncLink, notice: &mut Option<SyncNotice>) -> bool {
        link.polls = link.polls.wrapping_add(1);
        let mut list_changed = false;
        if !link.halted {
            let mut upload = true;
            let stamp = syncfile::stamp(&link.dir, INCOMING);
            // The server copy is gone (the folder was reset): offer this
            // state again so a fresh helper pins the vault, and stop
            // claiming "Synced" against a copy that no longer exists.
            if stamp.is_none() && link.in_stamp.is_some() {
                link.in_stamp = None;
                (link.verified, link.outgoing_due) = (false, true);
            }
            if let Some(stamp) = stamp.filter(|s| link.in_stamp != Some(*s))
                && let Fetched::Got(arrival) = link.fetch(stamp, &self.id, &self.key, self.data())
            {
                match self.take(link, arrival, notice) {
                    Ok(taken) => list_changed = taken.list_changed,
                    // Not saved: the same file is merged again next time,
                    // and nothing is uploaded meanwhile. A newer server copy
                    // is not in this PC's state, so it is not "Synced".
                    Err(()) => (upload, link.verified) = (false, false),
                }
            }
            if upload && link.outgoing_due {
                if link.busy_skip > 0 {
                    link.busy_skip -= 1;
                } else {
                    self.write_outgoing(link);
                }
            }
        }
        if link.polls.is_multiple_of(STATUS_EVERY) {
            link.read_status();
            link.offer_status(notice, now_secs());
        }
        list_changed
    }
    /// Applies a judged incoming file. A merge that changes anything is saved
    /// first, after a safety copy if the merges since the last copy lost
    /// many entries. Err if either write failed: then nothing changed and
    /// `in_stamp` stays, so the same file is tried again.
    fn take(
        &mut self,
        link: &mut SyncLink,
        arrival: Arrival,
        notice: &mut Option<SyncNotice>,
    ) -> Result<Taken, ()> {
        let Arrival {
            stamp,
            version,
            verdict,
        } = arrival;
        let mut taken = Taken {
            wrote: false,
            list_changed: false,
        };
        // `verified` speaks of the newest incoming only: one that is not
        // merged leaves it false.
        match verdict {
            Verdict::Newer => {
                (link.halted, link.warned, link.verified) = (true, true, false);
                offer(notice, SyncNotice::NewerFormat);
            }
            Verdict::Damaged => {
                (link.warned, link.verified) = (true, false);
                offer(notice, SyncNotice::BadIncoming);
            }
            Verdict::Foreign => {
                (link.warned, link.verified) = (true, false);
                offer(notice, SyncNotice::ForeignIncoming);
            }
            Verdict::Unreadable => {
                link.warned = true;
                // Our state replaces the bad head: CAS from its version.
                link.merged_version = version;
                (link.verified, link.outgoing_due) = (false, true);
                offer(notice, SyncNotice::BadIncoming);
            }
            Verdict::TooLarge => {
                (link.warned, link.too_large, link.verified) = (true, true, false);
                offer(notice, SyncNotice::TooLarge);
            }
            Verdict::Merged(mut merged, report) => {
                // Every entry here whose ID does not hold its text afterwards
                // is lost, whatever the merge made of it: deleted or edited on
                // another PC, or pushed off its ID by other text. The merge's
                // own count is a floor.
                let lost = lost(&self.entries, &merged.entries).max(report.removed);
                let since = link.losses.as_ref().map_or(0, |(n, _)| *n) + lost;
                let len = self.entries.len();
                let mass = lost > 0 && (since >= 5 || (since >= 2 && since * 5 >= len));
                // This merge starts a run of losses: the state before it.
                let start = if lost > 0 && link.losses.is_none() {
                    Some(
                        encode_data(&self.id, &self.key, Format::V2, self.data())
                            .map_err(|_| ())?,
                    )
                } else {
                    None
                };
                let mut copy = None;
                if mass {
                    copy = match &link.copied_for {
                        Some((s, name)) if *s == stamp => Some(name.clone()),
                        _ => {
                            let earlier = link.losses.as_ref().map(|(_, before)| before);
                            let before = earlier.or(start.as_ref()).ok_or(())?;
                            let name = pre_merge_copy(&link.dir, before)?;
                            link.copied_for = Some((stamp, name.clone()));
                            Some(name)
                        }
                    };
                }
                // The OTP watermark of this session may be newer (unlock).
                merged.last = merged.last.max(self.last);
                if report.changed {
                    let bytes = encode_data(&self.id, &self.key, Format::V2, merged.view())
                        .map_err(|_| ())?;
                    atomic_write(&self.path, &bytes, true).map_err(|_| ())?;
                    taken.wrote = true;
                }
                // Counted only once saved: a retried merge would count twice.
                link.losses = match (copy.is_some(), link.losses.take()) {
                    (true, _) => None,
                    (false, Some((_, before))) => Some((since, before)),
                    (false, None) => start.map(|before| (lost, before)),
                };
                taken.list_changed = !same_list(&self.entries, &merged.entries);
                let Contents {
                    last,
                    generation,
                    seen,
                    entries,
                    tombstones,
                } = merged;
                (self.last, self.generation, self.seen) = (last, generation, seen);
                (self.entries, self.tombstones) = (entries, tombstones);
                // Before any outgoing write: the next upload builds on it.
                link.merged_version = version;
                link.too_large = false;
                if report.needs_push {
                    (link.verified, link.outgoing_due) = (false, true);
                } else {
                    (link.verified, link.outgoing_due) = (true, false);
                    // Holds nothing the server copy lacks.
                    let _ = fs::remove_file(link.dir.join(OUTGOING));
                }
                if report.rollback {
                    link.warned = true;
                    offer(notice, SyncNotice::Rollback);
                }
                if let Some(file) = copy {
                    offer(
                        notice,
                        SyncNotice::MassDelete {
                            removed: since,
                            file,
                        },
                    );
                }
                if report.conflicts > 0 {
                    offer(notice, SyncNotice::Conflicts(report.conflicts));
                }
                if report.added > 0 || lost > 0 {
                    let added = report.added;
                    offer(
                        notice,
                        SyncNotice::Merged {
                            added,
                            removed: lost,
                        },
                    );
                }
                if link.verified && !link.code_shown {
                    offer(
                        notice,
                        SyncNotice::Synced {
                            code: self.check_code(),
                        },
                    );
                }
            }
        }
        link.in_stamp = Some(stamp);
        Ok(taken)
    }
    /// Writes outgoing from the current state, unless outgoing already offers
    /// it. A failure pauses the next writes for a few polls, keeps it due and
    /// stays silent, since the vault file already holds the state. A folder
    /// that is gone (deleting it turns sync off) or was replaced by a link is
    /// not written to at all.
    fn write_outgoing(&self, link: &mut SyncLink) {
        if !syncfile::usable_dir(&link.dir) {
            return;
        }
        // A server that keeps refusing an upload would otherwise get a new
        // one, and so learn of it, at every unlock.
        if self.offered(link) {
            (link.outgoing_due, link.busy_skip) = (false, 0);
            return;
        }
        let Ok(blob) = encode_data(&self.id, &self.key, Format::V2, self.data()) else {
            return;
        };
        match write_outgoing(&link.dir, link.merged_version, &blob, &self.id) {
            Ok(()) => (link.outgoing_due, link.busy_skip) = (false, 0),
            Err(_) => link.busy_skip = BUSY_SKIP,
        }
    }
    /// Whether outgoing already holds this state, made from the same server
    /// version: the same entries, IDs and text, and the same tombstones. The
    /// OTP watermark and the counters do not count, as they are never
    /// uploaded alone. Any doubt (missing, busy, unreadable, another size)
    /// means no.
    fn offered(&self, link: &SyncLink) -> bool {
        let path = link.dir.join(OUTGOING);
        let Ok(bytes) = syncfile::read_bounded(&path, syncfile::MAX_WRAPPED) else {
            return false;
        };
        let Some((base, blob)) = syncfile::parse_outgoing(&bytes) else {
            return false;
        };
        let size = plain_size(Format::V2, &self.entries, self.tombstones.len()) + 64;
        if base != link.merged_version || blob.len() != size {
            return false;
        }
        let Ok((Format::V2, held)) = decode_data(&self.id, &self.key, blob) else {
            return false;
        };
        let dead = |t: &[EntryId]| t.iter().copied().collect::<BTreeSet<_>>();
        held.entries.len() == self.entries.len()
            && lost(&self.entries, &held.entries) == 0
            && dead(&held.tombstones) == dead(&self.tombstones)
    }
    /// After `enable_sync` saved the vault: link to the folder and, for a
    /// vault just made v2, offer its state as the first upload, made from no
    /// server version (base 0). The helper learns the head from the server.
    pub(super) fn start_sync(&mut self, converted: bool) {
        let _ = self.connect();
        if converted && let Some(link) = self.sync.as_mut() {
            link.outgoing_due = true;
        }
        self.flush_outgoing();
    }
    /// Links a v2 session to a sync folder the helper made since. Gives the
    /// KeyInFolder notice once if the key file is inside it.
    fn connect(&mut self) -> Option<SyncNotice> {
        if self.sync.is_some() || self.sync_refused || self.format != Format::V2 {
            return None;
        }
        match SyncLink::attach(&self.path, &self.key_path) {
            Attach::Absent => None,
            Attach::KeyInFolder => {
                self.sync_refused = true;
                Some(SyncNotice::KeyInFolder)
            }
            Attach::Linked(link) => {
                let mut link = (*link).start();
                // Nothing fetched yet: offer this state, made from no
                // server version (base 0).
                link.outgoing_due = syncfile::stamp(&link.dir, INCOMING).is_none();
                self.sync = Some(link);
                None
            }
        }
    }
    /// Takes what `Pending::find` found once the OTP code passed. Returns
    /// whether the vault file was written; outgoing is not, it comes after
    /// the vault file (`flush_outgoing`).
    pub(super) fn settle(&mut self, pending: Pending) -> bool {
        let mut notice = None;
        if pending.key_in_folder {
            self.sync_refused = true;
            offer(&mut notice, SyncNotice::KeyInFolder);
        }
        let mut wrote = false;
        if let Some(link) = pending.link {
            let mut link = (*link).start();
            match pending.fetched {
                Some(Fetched::Missing) => link.outgoing_due = true,
                Some(Fetched::Got(arrival)) => {
                    // If unsaved, the unmerged state opens and the next
                    // poll merges again.
                    if let Ok(taken) = self.take(&mut link, arrival, &mut notice) {
                        wrote = taken.wrote;
                    }
                }
                Some(Fetched::Retry) | None => {}
            }
            link.offer_status(&mut notice, now_secs());
            link.told(&notice);
            self.sync = Some(link);
        }
        self.unlock_notice = notice;
        wrote
    }
    /// Writes outgoing if due. A failure keeps it due for the next poll.
    pub(super) fn flush_outgoing(&mut self) {
        if let Some(mut link) = self.sync.take() {
            if link.outgoing_due && !link.halted {
                self.write_outgoing(&mut link);
            }
            self.sync = Some(link);
        }
    }
    /// After a saved put or delete: upload the new state.
    pub(super) fn after_edit(&mut self) {
        let Some(mut link) = self.sync.take() else {
            return;
        };
        if !link.halted {
            (link.verified, link.outgoing_due) = (false, true);
            // A merge refused as too large may fit now.
            if link.too_large {
                link.in_stamp = None;
            }
            self.write_outgoing(&mut link);
            link.last_badge = Some(link.badge(now_secs()));
        }
        self.sync = Some(link);
    }
}

/// Gate 1 of three that keep the key file off the server: only a GOYOVA02
/// file of this vault, fresh from `encode_data`, is offered for upload.
fn write_outgoing(dir: &Path, base: u64, blob: &[u8], id: &[u8; 16]) -> Result<(), FileError> {
    if !blob.starts_with(syncfile::VAULT_MAGIC) || blob.get(8..24) != Some(&id[..]) {
        return Err(FileError::Io);
    }
    let bytes = syncfile::render_outgoing(base, blob).ok_or(FileError::Io)?;
    syncfile::replace_file(&dir.join(OUTGOING), &bytes)
}
/// Same entries, IDs and text, in the same order.
fn same_list(a: &[Entry], b: &[Entry]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.id == y.id && x.same_content(y))
}
/// Entries of `before` whose ID does not hold their text in `after`.
fn lost(before: &[Entry], after: &[Entry]) -> usize {
    let after: BTreeMap<EntryId, &Entry> = after.iter().map(|e| (e.id, e)).collect();
    before
        .iter()
        .filter(|e| after.get(&e.id).is_none_or(|a| !a.same_content(e)))
        .count()
}
/// Saves `before`, a vault file of the state before merges that lost many
/// entries, into the sync folder where Restore can open it. The newest
/// three copies stay, and any other younger than 30 days while there are
/// at most 20, so a run of merges that each make a copy cannot push out one
/// that matters within a month. Returns its path from the vault's folder.
fn pre_merge_copy(dir: &Path, before: &[u8]) -> Result<String, ()> {
    // Names sort by time; a new copy sorts last even if the clock went back.
    let newest = syncfile::pre_merge_copies(dir)
        .last()
        .and_then(|p| copy_time(p));
    let now = now_secs();
    let time = match newest {
        Some(n) if n >= now && n < LAST_COPY_TIME => n + 1,
        _ => now,
    };
    let name = syncfile::pre_merge_name(time);
    atomic_write(&dir.join(&name), before, false).map_err(|_| ())?;
    // Newest first, each with the number of copies newer than it.
    for (newer, old) in syncfile::pre_merge_copies(dir).iter().rev().enumerate() {
        let young = copy_time(old).is_some_and(|t| t.saturating_add(COPY_DAYS * 86_400) > now);
        if newer >= KEEP_COPIES && (newer >= MAX_COPIES || !young) {
            let _ = fs::remove_file(old);
        }
    }
    let folder = Path::new(dir.file_name().unwrap_or_default());
    Ok(folder.join(name).to_string_lossy().into_owned())
}
/// The time in a safety copy's name.
fn copy_time(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    name.strip_prefix("pre-merge-")?
        .strip_suffix(".goyo")?
        .parse()
        .ok()
}
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Two simulated PCs with real sessions sharing one synthetic key, and a
/// stand-in for the server and the helpers. Saving needs Windows.
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        crypto::{self, AUTH_ERROR},
        syncwire::sha256,
        vault::{NO_ID, Provision, derived_id, encode_key},
    };
    use std::{
        collections::BTreeSet,
        fs::{File, OpenOptions},
        os::windows::fs::OpenOptionsExt,
    };

    const PASS: &str = "a long synthetic password";

    /// A fresh folder under %TEMP% with one folder per PC, removed with all
    /// in it. Declared first, so the sessions and their locks go before it.
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "goyo-sync-{:x}",
                u128::from_le_bytes(*crypto::random::<16>().unwrap())
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn pc(&self, name: &str) -> Pc {
            let p = self.0.join(name);
            fs::create_dir(&p).unwrap();
            Pc(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    /// One PC's GoyoVault folder.
    struct Pc(PathBuf);
    impl Pc {
        fn vault(&self) -> PathBuf {
            self.0.join("vault.goyo")
        }
        fn key(&self) -> PathBuf {
            self.0.join("vault.goyokey")
        }
        fn dir(&self) -> PathBuf {
            self.0.join("vault.goyo.sync")
        }
        /// What goyo-sync does first: make the folder and report itself.
        fn helper(&self) {
            fs::create_dir(self.dir()).unwrap();
            self.status(SyncState::Ok);
        }
        fn status(&self, state: SyncState) {
            let now = now_secs();
            let bytes = syncfile::render_status(now, now, state);
            syncfile::replace_file(&self.dir().join(syncfile::STATUS), &bytes).unwrap();
        }
        fn unlock(&self) -> Session {
            Session::unlock(&self.vault(), &self.key(), PASS, "").unwrap()
        }
        /// Wrapped by hand, so a test can deliver what the helper never would.
        fn incoming(&self, version: u64, blob: &[u8]) {
            let mut wrapped = syncfile::INCOMING_MAGIC.to_vec();
            wrapped.extend_from_slice(&version.to_le_bytes());
            wrapped.extend_from_slice(blob);
            syncfile::replace_file(&self.dir().join(INCOMING), &wrapped).unwrap();
        }
        fn outgoing(&self) -> Option<(u64, Vec<u8>)> {
            let bytes = fs::read(self.dir().join(OUTGOING)).ok()?;
            let (base, blob) = syncfile::parse_outgoing(&bytes).unwrap();
            Some((base, blob.to_vec()))
        }
        fn copies(&self) -> Vec<String> {
            let copies = syncfile::pre_merge_copies(&self.dir()).into_iter();
            copies
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        }
    }
    /// The server and every PC's helper, reduced to what the app sees:
    /// numbered copies, compare-and-swap on the outgoing base, and the head
    /// written to a PC's incoming.
    #[derive(Default)]
    struct Server {
        versions: Vec<Vec<u8>>,
        done: BTreeSet<[u8; 32]>,
        /// A hostile server that answers every upload with a conflict and
        /// its current head, so the head never moves.
        frozen: bool,
    }
    impl Server {
        fn head(&self) -> u64 {
            self.versions.len() as u64
        }
        /// One helper pass for `pc`. Like goyo-sync, it tries each outgoing
        /// file once.
        fn pass(&mut self, pc: &Pc) {
            if let Ok(bytes) = fs::read(pc.dir().join(OUTGOING))
                && self.done.insert(sha256(&bytes))
            {
                let (base, blob) = syncfile::parse_outgoing(&bytes).unwrap();
                // Otherwise a conflict: this upload is dead, and the app
                // merges the head instead.
                if base == self.head() && !self.frozen {
                    self.versions.push(blob.to_vec());
                }
            }
            if let Some(head) = self.versions.last() {
                let wrapped = syncfile::render_incoming(self.head(), head).unwrap();
                if fs::read(pc.dir().join(INCOMING)).ok().as_ref() != Some(&wrapped) {
                    syncfile::replace_file(&pc.dir().join(INCOMING), &wrapped).unwrap();
                }
            }
        }
    }
    fn entry(title: &str, secret: &str) -> Entry {
        Entry::new(title.into(), "kind".into(), secret.into(), String::new()).unwrap()
    }
    fn titles(s: &Session) -> Vec<String> {
        listed(&s.entries)
    }
    /// `title=secret` of each entry, sorted.
    fn listed(entries: &[Entry]) -> Vec<String> {
        let mut t: Vec<String> = entries
            .iter()
            .map(|e| format!("{}={}", *e.title, *e.secret))
            .collect();
        t.sort();
        t
    }
    /// Merges reorder entries, so tests look them up by title.
    fn find(s: &Session, title: &str) -> usize {
        s.entries.iter().position(|e| *e.title == title).unwrap()
    }
    fn open(s: &Session, blob: &[u8]) -> Contents {
        decode_data(&s.id, &s.key, blob).unwrap().1
    }
    fn saved(s: &Session) -> Contents {
        open(s, &fs::read(&s.path).unwrap())
    }
    type Sets = (BTreeSet<EntryId>, BTreeSet<EntryId>);
    /// Live IDs and tombstones: what syncing must agree on.
    fn sets(entries: &[Entry], tombstones: &[EntryId]) -> Sets {
        let live = entries.iter().map(Entry::id).collect();
        (live, tombstones.iter().copied().collect())
    }
    fn state(c: &Contents) -> Sets {
        sets(&c.entries, &c.tombstones)
    }
    fn local(s: &Session) -> Sets {
        sets(&s.entries, &s.tombstones)
    }
    fn link(s: &Session) -> &SyncLink {
        s.sync.as_ref().unwrap()
    }
    /// Polls once, reading the status file this time.
    fn status_poll(s: &mut Session) -> Option<SyncEvent> {
        s.sync.as_mut().unwrap().polls = STATUS_EVERY - 1;
        s.poll_sync()
    }
    fn synced(s: &Session) -> Option<SyncNotice> {
        Some(SyncNotice::Synced {
            code: s.check_code(),
        })
    }
    fn event(notice: Option<SyncNotice>, badge_changed: bool) -> Option<SyncEvent> {
        let event = SyncEvent {
            list_changed: false,
            notice,
            badge_changed,
        };
        (event != SyncEvent::default()).then_some(event)
    }
    /// PC A turns sync on with `n` entries and uploads them. PC B gets the
    /// key "by USB" and the vault from the server through Restore, then
    /// links. Both end verified on server version 1.
    fn pair(t: &Temp, server: &mut Server, n: usize) -> (Pc, Session, Pc, Session) {
        let (a, b) = (t.pc("a"), t.pc("b"));
        let p = Provision::new().unwrap();
        let mut sa = p.finish(&a.vault(), &a.key(), PASS, None).unwrap();
        for i in 0..n {
            sa.put(None, entry(&format!("entry {i}"), "secret"))
                .unwrap();
        }
        a.helper();
        assert!(sa.sync_offer());
        sa.enable_sync().unwrap();
        assert_eq!(a.outgoing().unwrap().0, 0);
        server.pass(&a);
        assert_eq!(server.head(), 1);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, synced(&sa));
        assert!(ev.badge_changed && !ev.list_changed);
        assert!(a.outgoing().is_none());

        fs::copy(a.key(), b.key()).unwrap();
        let fetched = b.0.join("from-server.goyo");
        fs::write(&fetched, &server.versions[0]).unwrap();
        let restored = Session::restore(&fetched, &b.key(), &b.vault(), PASS, "").unwrap();
        assert_eq!(restored.format(), Format::V2);
        drop(restored);
        b.helper();
        let mut sb = b.unlock();
        // Nothing fetched yet: B offers its copy, made from no version.
        assert_eq!(sb.take_unlock_notice(), None);
        assert_eq!(b.outgoing().unwrap().0, 0);
        server.pass(&b);
        assert_eq!(server.head(), 1);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, synced(&sb));
        assert_eq!(sb.check_code(), sa.check_code());
        assert!(b.outgoing().is_none());
        (a, sa, b, sb)
    }

    #[test]
    fn two_pcs_converge() {
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert_eq!(sb.badge(), Some(SyncBadge::Synced));

        // A edits: the vault file is saved, then outgoing made from v1.
        let old = sa.entry_id(0).unwrap();
        sa.put(Some(0), entry("entry 0", "edited")).unwrap();
        assert_eq!(sa.badge(), Some(SyncBadge::Uploading));
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 1);
        assert_eq!(state(&open(&sa, &blob)), state(&saved(&sa)));
        assert_eq!(state(&saved(&sa)), local(&sa));
        server.pass(&a);
        assert_eq!(sa.poll_sync(), event(None, true));
        assert!(a.outgoing().is_none());
        // B pulls; a selection can follow the edit.
        server.pass(&b);
        let ev = sb.poll_sync().unwrap();
        let merged = SyncNotice::Merged {
            added: 1,
            removed: 1,
        };
        assert_eq!(ev.notice, Some(merged));
        assert!(ev.list_changed && !ev.badge_changed);
        assert_eq!(titles(&sb), titles(&sa));
        let new = sa.entry_id(0).unwrap();
        assert_eq!(sb.successor(&old), sb.entry_index(&new));
        assert_eq!(state(&saved(&sb)), local(&sb));

        // Both edit entry 1 and B adds one; A's upload lands first.
        let (i, j) = (find(&sa, "entry 1"), find(&sb, "entry 1"));
        sa.put(Some(i), entry("entry 1", "by A")).unwrap();
        sb.put(Some(j), entry("entry 1", "by B")).unwrap();
        sb.put(None, entry("added", "by B")).unwrap();
        server.pass(&a);
        server.pass(&b);
        assert_eq!(server.head(), 3);
        // Counted, never named: the status line is readable by other programs.
        let conflict = SyncNotice::Conflicts(1);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(conflict.clone()));
        assert!(ev.list_changed);
        // Merged and saved, then uploaded from the version it merged.
        assert_eq!(b.outgoing().unwrap().0, 3);
        assert_eq!(state(&saved(&sb)), local(&sb));
        server.pass(&b);
        assert_eq!(server.head(), 4);
        assert_eq!(sb.poll_sync(), event(None, true));
        server.pass(&a);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(conflict));
        assert!(ev.list_changed && ev.badge_changed);
        assert_eq!(titles(&sa), titles(&sb));
        assert_eq!(sa.entries.len(), 4);
        assert_eq!(sa.check_code(), sb.check_code());
        assert_eq!(state(&saved(&sa)), state(&saved(&sb)));

        // Converged: more rounds make no server version and no event.
        for _ in 0..3 {
            server.pass(&a);
            server.pass(&b);
            assert_eq!(sa.poll_sync(), None);
            assert_eq!(sb.poll_sync(), None);
        }
        assert_eq!(server.head(), 4);
        assert!(a.outgoing().is_none() && b.outgoing().is_none());

        // A newer server copy that cannot be saved yet is not "Synced"
        // meanwhile, though the copy before it was.
        sb.put(None, entry("late", "by B")).unwrap();
        server.pass(&b);
        server.pass(&a);
        let held = File::open(a.vault()).unwrap();
        assert_eq!(sa.poll_sync(), event(None, true));
        assert_eq!(sa.badge(), Some(SyncBadge::Uploading));
        assert_eq!(sa.entries.len(), 4);
        drop(held);
        let ev = sa.poll_sync().unwrap();
        let merged = SyncNotice::Merged {
            added: 1,
            removed: 0,
        };
        assert_eq!(ev.notice, Some(merged));
        assert!(ev.list_changed && ev.badge_changed);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert_eq!(sa.check_code(), sb.check_code());
    }

    #[test]
    fn merges_over_a_limit_wait_for_room() {
        let t = Temp::new();
        let a = t.pc("a");
        let p = Provision::new().unwrap();
        fs::write(a.key(), encode_key(&p.id, &p.key, None, PASS).unwrap()).unwrap();
        // Entries with distinct IDs; `tag` tells the two PCs' apart.
        let made = |tag: u8, n: usize| -> Vec<Entry> {
            (0..n)
                .map(|i| {
                    let mut e = entry(&format!("{tag}-{i}"), "secret");
                    let mut id = [tag; 16];
                    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    e.set_ids(id, NO_ID);
                    e
                })
                .collect()
        };
        let encode = |entries: &[Entry]| {
            let d = DataRef {
                last: 0,
                generation: 1,
                seen: 0,
                entries,
                tombstones: &[],
            };
            encode_data(&p.id, &p.key, Format::V2, d).unwrap()
        };
        // Together 1001 entries: one more than a vault holds.
        let vault = encode(&made(1, 501));
        fs::write(a.vault(), &vault).unwrap();
        a.helper();
        a.incoming(3, &encode(&made(2, 500)));
        let mut s = a.unlock();
        assert_eq!(s.take_unlock_notice(), Some(SyncNotice::TooLarge));
        assert_eq!(s.badge(), Some(SyncBadge::Warning));
        // Nothing changed, saved or uploaded; polling does not try again.
        assert_eq!(s.entries.len(), 501);
        assert_eq!(fs::read(a.vault()).unwrap(), vault);
        assert!(a.outgoing().is_none() && !link(&s).verified);
        assert_eq!(s.poll_sync(), event(None, true));
        assert!(a.outgoing().is_none());

        // A delete makes room: it is uploaded at once, and the next poll
        // merges, saves and uploads from the version merged.
        s.delete(0).unwrap();
        assert_eq!(a.outgoing().unwrap().0, 0);
        let ev = s.poll_sync().unwrap();
        let merged = SyncNotice::Merged {
            added: 500,
            removed: 0,
        };
        assert_eq!(ev.notice, Some(merged));
        assert!(ev.list_changed && !ev.badge_changed);
        assert_eq!(s.entries.len(), 1000);
        assert_eq!(state(&saved(&s)), local(&s));
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 3);
        assert_eq!(state(&open(&s, &blob)), local(&s));
        // The warning stays for the session.
        assert_eq!(s.badge(), Some(SyncBadge::Warning));
    }

    #[test]
    fn unlock_merges_before_the_otp_check() {
        let t = Temp::new();
        let (a, b) = (t.pc("a"), t.pc("b"));
        let p = Provision::new().unwrap();
        let code = |step: u64| format!("{:06}", otp::code(p.otp.as_slice(), step, 6));
        // Both PCs hold the same synced vault; no code was used yet.
        let key = encode_key(&p.id, &p.key, Some(&p.otp), PASS).unwrap();
        let mut first = entry("mail", "one");
        first.set_ids([5; 16], NO_ID);
        let d = DataRef {
            last: 0,
            generation: 1,
            seen: 0,
            entries: std::slice::from_ref(&first),
            tombstones: &[],
        };
        let vault = encode_data(&p.id, &p.key, Format::V2, d).unwrap();
        for pc in [&a, &b] {
            fs::write(pc.key(), &key).unwrap();
            fs::write(pc.vault(), &vault).unwrap();
            pc.helper();
        }
        let now = otp::now().unwrap() / 30;
        let mut sa = Session::unlock(&a.vault(), &a.key(), PASS, &code(now)).unwrap();
        let used = sa.last;
        assert!(used >= now);
        // A's next content change carries the used step to the server.
        sa.put(None, entry("bank", "two")).unwrap();
        let (_, blob) = a.outgoing().unwrap();
        assert_eq!(open(&sa, &blob).last, used);
        b.incoming(1, &blob);

        // B merges before checking the code, so A's code is refused there,
        // and nothing is saved: no vault, no upload, no copy.
        let before = fs::read(b.vault()).unwrap();
        let refused = Session::unlock(&b.vault(), &b.key(), PASS, &code(used));
        assert_eq!(refused.err(), Some(AUTH_ERROR));
        assert_eq!(fs::read(b.vault()).unwrap(), before);
        assert!(b.outgoing().is_none() && b.copies().is_empty());

        // The next code opens it, merged and saved with that code used.
        let mut sb = Session::unlock(&b.vault(), &b.key(), PASS, &code(used + 1)).unwrap();
        assert_eq!(sb.last, used + 1);
        assert_eq!(titles(&sb), titles(&sa));
        let file = saved(&sb);
        assert_eq!(file.last, used + 1);
        assert_eq!(state(&file), local(&sb));
        let merged = SyncNotice::Merged {
            added: 1,
            removed: 0,
        };
        assert_eq!(sb.take_unlock_notice(), Some(merged));
        assert_eq!(sb.take_unlock_notice(), None);
        // Equal to the server copy: verified, nothing to upload.
        assert!(link(&sb).verified && link(&sb).merged_version == 1);
        assert!(b.outgoing().is_none());
        assert_eq!(sb.badge(), Some(SyncBadge::Synced));
    }

    #[test]
    fn unlock_never_fails_because_of_sync() {
        let t = Temp::new();
        let a = t.pc("a");
        let p = Provision::new().unwrap();
        let mut s = p.finish(&a.vault(), &a.key(), PASS, None).unwrap();
        s.put(None, entry("mail", "one")).unwrap();
        // Turned on before the helper made its folder: v2, not linked.
        s.enable_sync().unwrap();
        assert!(s.sync.is_none() && s.badge().is_none());
        assert_eq!(s.poll_sync(), None);
        // The folder appears while the vault is open: linked, and the state
        // offered with base 0.
        a.helper();
        assert_eq!(s.poll_sync(), event(None, true));
        assert_eq!(s.badge(), Some(SyncBadge::Uploading));
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 0);
        assert_eq!(state(&open(&s, &blob)), local(&s));
        let good = fs::read(a.vault()).unwrap();
        drop(s);
        fs::remove_file(a.dir().join(OUTGOING)).unwrap();

        // No incoming yet: the unlock offers the state with base 0.
        let mut s = a.unlock();
        assert_eq!(s.take_unlock_notice(), None);
        assert_eq!(a.outgoing().unwrap().0, 0);
        drop(s);
        fs::remove_file(a.dir().join(OUTGOING)).unwrap();

        // Another vault's copy: ignored and reported. Its version says
        // nothing about this vault, so nothing is pushed over it.
        let other = Provision::new().unwrap();
        let empty = DataRef {
            last: 0,
            generation: 1,
            seen: 0,
            entries: &[],
            tombstones: &[],
        };
        let foreign = encode_data(&other.id, &other.key, Format::V2, empty).unwrap();
        a.incoming(4, &foreign);
        let mut s = a.unlock();
        assert_eq!(s.take_unlock_notice(), Some(SyncNotice::ForeignIncoming));
        assert_eq!(s.badge(), Some(SyncBadge::Warning));
        assert_eq!(link(&s).merged_version, 0);
        assert!(a.outgoing().is_none());
        assert_eq!(titles(&s), ["mail=one"]);
        drop(s);

        // This vault's copy, damaged: ignored, and this PC's state is pushed
        // over that version.
        let mut bad = good.clone();
        bad[60] ^= 1;
        a.incoming(7, &bad);
        let mut s = a.unlock();
        assert_eq!(s.take_unlock_notice(), Some(SyncNotice::BadIncoming));
        assert_eq!(link(&s).merged_version, 7);
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 7);
        assert_eq!(state(&open(&s, &blob)), local(&s));
        drop(s);
        fs::remove_file(a.dir().join(OUTGOING)).unwrap();

        // A newer format stops sync for the session: no upload, even after
        // an edit, while the vault still opens and saves.
        let mut newer = good.clone();
        newer[..8].copy_from_slice(b"GOYOVA03");
        a.incoming(8, &newer);
        let mut s = a.unlock();
        assert_eq!(s.take_unlock_notice(), Some(SyncNotice::NewerFormat));
        assert!(link(&s).halted);
        s.put(None, entry("bank", "two")).unwrap();
        assert!(a.outgoing().is_none());
        assert_eq!(saved(&s).entries.len(), 2);
        assert_eq!(s.badge(), Some(SyncBadge::Warning));
        drop(s);

        // Incoming that cannot be read right now (the helper is replacing
        // it): opened unmerged, merged by the next poll.
        let current = fs::read(a.vault()).unwrap();
        a.incoming(9, &current);
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(a.dir().join(INCOMING))
            .unwrap();
        let mut s = a.unlock();
        assert_eq!(s.take_unlock_notice(), None);
        assert!(link(&s).in_stamp.is_none() && !link(&s).verified);
        drop(held);
        let ev = s.poll_sync().unwrap();
        assert_eq!(ev.notice, synced(&s));
        assert_eq!(link(&s).merged_version, 9);
        assert_eq!(s.badge(), Some(SyncBadge::Synced));
        drop(s);

        // The key file inside the sync folder: no link, told once.
        let inside = a.dir().join("vault.goyokey");
        fs::rename(a.key(), &inside).unwrap();
        let mut s = Session::unlock(&a.vault(), &inside, PASS, "").unwrap();
        assert_eq!(s.take_unlock_notice(), Some(SyncNotice::KeyInFolder));
        assert!(s.sync.is_none() && s.badge().is_none() && !s.sync_offer());
        assert_eq!(s.poll_sync(), None);
    }

    #[test]
    fn poll_saves_merges_before_uploading() {
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 6);
        // B deletes five entries; A meanwhile adds one of its own.
        for _ in 0..5 {
            sb.delete(0).unwrap();
        }
        server.pass(&b);
        assert_eq!(server.head(), 2);
        sa.put(None, entry("local", "from A")).unwrap();
        assert_eq!(a.outgoing().unwrap().0, 1);
        server.pass(&a);
        assert_eq!(server.head(), 2);
        // Older safety copies; only the newest three stay.
        for time in [1, 2, 3] {
            fs::write(a.dir().join(syncfile::pre_merge_name(time)), b"old").unwrap();
        }
        let (before, upload, stamp) = (titles(&sa), a.outgoing(), link(&sa).in_stamp);

        // The vault file is held open, so the merge cannot be saved: it is
        // kept back, retried with the same incoming, and nothing is uploaded.
        let held = File::open(a.vault()).unwrap();
        for _ in 0..2 {
            let ev = sa.poll_sync();
            assert!(ev.is_none_or(|e| e.notice.is_none() && !e.list_changed));
            assert_eq!(link(&sa).in_stamp, stamp);
            assert_eq!(titles(&sa), before);
            assert_eq!(a.outgoing(), upload);
        }
        // One safety copy for that incoming, however often it is retried.
        let copies = a.copies();
        assert_eq!(copies.len(), 3);
        assert_eq!(copies[..2], [2, 3].map(syncfile::pre_merge_name));
        let copy = open(&sa, &fs::read(a.dir().join(&copies[2])).unwrap());
        assert_eq!(copy.entries.len(), 7);
        assert_eq!(state(&copy), local(&sa));
        drop(held);

        let ev = sa.poll_sync().unwrap();
        let file = format!("vault.goyo.sync\\{}", copies[2]);
        let mass = SyncNotice::MassDelete { removed: 5, file };
        assert_eq!(ev.notice, Some(mass));
        assert!(ev.list_changed);
        assert_eq!(a.copies(), copies);
        assert_eq!(titles(&sa), ["entry 5=secret", "local=from A"]);
        // Saved, then uploaded from the version just merged.
        assert_eq!(state(&saved(&sa)), local(&sa));
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 2);
        assert_eq!(state(&open(&sa, &blob)), local(&sa));
        assert_ne!(link(&sa).in_stamp, stamp);

        server.pass(&a);
        assert_eq!(server.head(), 3);
        assert_eq!(sa.poll_sync().unwrap().notice, None);
        assert!(link(&sa).verified && a.outgoing().is_none());
        server.pass(&b);
        let merged = SyncNotice::Merged {
            added: 1,
            removed: 0,
        };
        assert_eq!(sb.poll_sync().unwrap().notice, Some(merged));
        assert_eq!(sa.check_code(), sb.check_code());
        // Merges that remove few entries make no copy.
        assert_eq!(a.copies(), copies);
        assert!(b.copies().is_empty());
    }

    #[test]
    fn busy_outgoing_is_retried_quietly() {
        let t = Temp::new();
        let a = t.pc("a");
        let p = Provision::new().unwrap();
        let mut s = p.finish(&a.vault(), &a.key(), PASS, None).unwrap();
        s.put(None, entry("mail", "one")).unwrap();
        a.helper();
        s.enable_sync().unwrap();
        let first = a.outgoing().unwrap();
        assert_eq!(s.poll_sync(), event(None, true));

        // The helper (or a scanner) holds outgoing open: the edit is saved
        // and the upload waits, without an error.
        let held = File::open(a.dir().join(OUTGOING)).unwrap();
        s.put(None, entry("bank", "two")).unwrap();
        assert_eq!(saved(&s).entries.len(), 2);
        assert_eq!(a.outgoing(), Some(first.clone()));
        assert!(link(&s).outgoing_due && link(&s).busy_skip == BUSY_SKIP);
        // Quiet polls without a try, then one more try.
        for skip in (0..BUSY_SKIP).rev() {
            assert_eq!(s.poll_sync(), None);
            assert_eq!(link(&s).busy_skip, skip);
        }
        assert_eq!(s.poll_sync(), None);
        assert_eq!(link(&s).busy_skip, BUSY_SKIP);
        assert_eq!(a.outgoing(), Some(first));
        drop(held);
        for _ in 0..BUSY_SKIP {
            assert_eq!(s.poll_sync(), None);
            assert!(link(&s).outgoing_due);
        }
        assert_eq!(s.poll_sync(), None);
        assert!(!link(&s).outgoing_due);
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 0);
        assert_eq!(state(&open(&s, &blob)), local(&s));

        // Deleting the folder turns sync off: edits are saved, and the app
        // neither writes there nor makes the folder again.
        fs::remove_dir_all(a.dir()).unwrap();
        s.put(None, entry("card", "three")).unwrap();
        assert_eq!(saved(&s).entries.len(), 3);
        for _ in 0..STATUS_EVERY {
            let _ = s.poll_sync();
        }
        assert!(!a.dir().exists() && link(&s).outgoing_due);
        assert_eq!(s.badge(), Some(SyncBadge::HelperOff));
        // Once the helper makes it again, the state is offered at once.
        a.helper();
        let _ = s.poll_sync();
        assert!(!link(&s).outgoing_due);
        let (_, blob) = a.outgoing().unwrap();
        assert_eq!(state(&open(&s, &blob)), local(&s));
    }

    /// A sync folder reset while the vault is open (how a user re-pins the
    /// helper): the server copy is gone, so the app offers its state again
    /// instead of still showing "Synced" to a helper that fetches nothing.
    #[test]
    fn a_reset_folder_is_offered_again() {
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, _b, _sb) = pair(&t, &mut server, 2);
        let _ = status_poll(&mut sa);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert!(a.outgoing().is_none());
        fs::remove_dir_all(a.dir()).unwrap();
        a.helper();
        a.status(SyncState::Idle);
        let _ = status_poll(&mut sa);
        assert_eq!(sa.badge(), Some(SyncBadge::Uploading));
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 1);
        assert_eq!(state(&open(&sa, &blob)), local(&sa));
    }

    #[test]
    fn bad_or_old_server_copies_warn() {
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        sb.put(None, entry("from B", "x")).unwrap();
        server.pass(&b);
        server.pass(&a);
        sa.poll_sync().unwrap();
        let (seen, kept) = (sa.seen, titles(&sa));
        assert_eq!(seen, open(&sa, &server.versions[1]).generation);

        // The server replays version 1: nothing here changes; it warns and
        // pushes this state over that version again.
        a.incoming(1, &server.versions[0]);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::Rollback));
        assert!(ev.badge_changed && !ev.list_changed);
        assert_eq!(sa.badge(), Some(SyncBadge::Warning));
        assert_eq!(titles(&sa), kept);
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 1);
        assert_eq!(state(&open(&sa, &blob)), local(&sa));
        assert!(open(&sa, &blob).generation > seen);

        // A damaged head: ignored, and repaired from its version.
        let mut bad = server.versions[1].clone();
        let end = bad.len() - 1;
        bad[end] ^= 1;
        a.incoming(5, &bad);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::BadIncoming));
        assert_eq!(link(&sa).merged_version, 5);
        assert_eq!(a.outgoing().unwrap().0, 5);
        // A broken wrapper says nothing about a version: no repair.
        let junk = [syncfile::INCOMING_MAGIC.as_slice(), &[0; 8], &[1; 200]].concat();
        syncfile::replace_file(&a.dir().join(INCOMING), &junk).unwrap();
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::BadIncoming));
        assert_eq!(link(&sa).merged_version, 5);
        // An authentic v1 file was never uploaded by a PC: repaired too.
        let v1 = encode_data(&sa.id, &sa.key, Format::V1, sa.data()).unwrap();
        a.incoming(6, &v1);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::BadIncoming));
        assert_eq!(a.outgoing().unwrap().0, 6);
        assert_eq!(titles(&sa), kept);
        // A newer format halts sync for the session.
        let mut newer = server.versions[1].clone();
        newer[..8].copy_from_slice(b"GOYOVA03");
        a.incoming(7, &newer);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::NewerFormat));
        assert!(link(&sa).halted);
        fs::remove_file(a.dir().join(OUTGOING)).unwrap();
        a.incoming(8, &server.versions[1]);
        sa.put(None, entry("after", "halt")).unwrap();
        for _ in 0..3 {
            assert_eq!(sa.poll_sync(), None);
        }
        assert!(a.outgoing().is_none());
        assert_eq!(link(&sa).merged_version, 6);
        assert_eq!(sa.badge(), Some(SyncBadge::Warning));
    }

    #[test]
    fn status_picks_the_badge() {
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut s, _b, _sb) = pair(&t, &mut server, 1);
        assert_eq!(status_poll(&mut s), None);
        // Each status notice once per change; "Synced" needs verification.
        let cases = [
            (
                SyncState::Offline,
                SyncBadge::Offline,
                Some(SyncNotice::Offline),
            ),
            (SyncState::Offline, SyncBadge::Offline, None),
            (SyncState::Auth, SyncBadge::Offline, Some(SyncNotice::Auth)),
            (
                SyncState::HostKey,
                SyncBadge::Offline,
                Some(SyncNotice::HostKey),
            ),
            (
                SyncState::NoSsh,
                SyncBadge::Offline,
                Some(SyncNotice::HelperError),
            ),
            (SyncState::Server, SyncBadge::Offline, None),
            (SyncState::Idle, SyncBadge::Synced, None),
            (
                SyncState::Refused,
                SyncBadge::Warning,
                Some(SyncNotice::HelperError),
            ),
            (SyncState::Config, SyncBadge::Warning, None),
            (
                SyncState::Update,
                SyncBadge::Warning,
                Some(SyncNotice::NewerFormat),
            ),
            (SyncState::Ok, SyncBadge::Synced, None),
        ];
        let mut badge = SyncBadge::Synced;
        for (state, want, notice) in cases {
            a.status(state);
            assert_eq!(
                status_poll(&mut s),
                event(notice, want != badge),
                "{state:?}"
            );
            assert_eq!(s.badge(), Some(want), "{state:?}");
            badge = want;
        }
        // An old heartbeat, or no status file: the helper is off.
        let old = now_secs() - HEARTBEAT_STALE - 5;
        let stale = syncfile::render_status(old, old, SyncState::Ok);
        syncfile::replace_file(&a.dir().join(syncfile::STATUS), &stale).unwrap();
        let off = event(Some(SyncNotice::HelperOff), true);
        assert_eq!(status_poll(&mut s), off);
        fs::remove_file(a.dir().join(syncfile::STATUS)).unwrap();
        assert_eq!(status_poll(&mut s), None);
        assert_eq!(s.badge(), Some(SyncBadge::HelperOff));
        // A heartbeat far ahead (written before the clock was set back) does
        // not hide a stopped helper either.
        let ahead = now_secs() + 86_400;
        let future = syncfile::render_status(ahead, ahead, SyncState::Ok);
        syncfile::replace_file(&a.dir().join(syncfile::STATUS), &future).unwrap();
        assert_eq!(status_poll(&mut s), None);
        assert_eq!(s.badge(), Some(SyncBadge::HelperOff));
        // A read that races the helper's replace keeps the previous view.
        a.status(SyncState::Ok);
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(a.dir().join(syncfile::STATUS))
            .unwrap();
        assert_eq!(status_poll(&mut s), None);
        assert_eq!(s.badge(), Some(SyncBadge::HelperOff));
        drop(held);
        assert_eq!(status_poll(&mut s), event(None, true));
        assert_eq!(s.badge(), Some(SyncBadge::Synced));
        // An edit is not verified until its upload comes back.
        s.put(None, entry("new", "x")).unwrap();
        assert_eq!(s.badge(), Some(SyncBadge::Uploading));
        // Between status reads the file is not looked at.
        a.status(SyncState::Offline);
        assert_eq!(s.poll_sync(), None);
        assert_eq!(s.badge(), Some(SyncBadge::Uploading));
    }

    #[test]
    fn enable_sync_links_and_uploads() {
        let t = Temp::new();
        let a = t.pc("a");
        let p = Provision::new().unwrap();
        let mut s = p.finish(&a.vault(), &a.key(), PASS, None).unwrap();
        for value in ["one", "one"] {
            s.put(None, entry("mail", value)).unwrap();
        }
        assert!(!s.sync_offer());
        a.helper();
        assert!(s.sync_offer());
        // Not before the user agreed: a v1 vault neither links nor uploads.
        assert_eq!(s.poll_sync(), None);
        s.put(None, entry("mail", "two")).unwrap();
        assert_eq!(s.poll_sync(), None);
        assert!(s.sync.is_none() && s.badge().is_none() && a.outgoing().is_none());
        let (_, v1) = decode_data(&p.id, &p.key, &fs::read(a.vault()).unwrap()).unwrap();
        // A failed save leaves it v1, unlinked, with nothing to upload.
        let actual = s.path.clone();
        s.path = a.0.join("missing").join("vault.goyo");
        assert!(s.enable_sync().is_err());
        assert_eq!(s.format(), Format::V1);
        assert!(s.sync.is_none() && s.badge().is_none());
        assert!(a.outgoing().is_none());
        s.path = actual;
        assert!(s.sync_offer());

        s.enable_sync().unwrap();
        assert!(!s.sync_offer());
        assert_eq!(s.badge(), Some(SyncBadge::Uploading));
        // The first upload holds the derived v1 IDs and count 1, is made
        // from no version, and equals the vault file.
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 0);
        let (format, up) = decode_data(&p.id, &p.key, &blob).unwrap();
        assert_eq!(format, Format::V2);
        assert_eq!(up.generation, 1);
        let ids: Vec<EntryId> = up.entries.iter().map(Entry::id).collect();
        assert_eq!(ids, v1.entries.iter().map(Entry::id).collect::<Vec<_>>());
        assert_eq!(state(&up), state(&saved(&s)));
        drop(s);

        // A v1 vault whose key file is inside the folder is not offered
        // sync, and the unlock says why.
        let c = t.pc("c");
        c.helper();
        let inside = c.dir().join("vault.goyokey");
        let q = Provision::new().unwrap();
        let s = q.finish(&c.vault(), &inside, PASS, None).unwrap();
        assert!(!s.sync_offer());
        drop(s);
        let mut s = Session::unlock(&c.vault(), &inside, PASS, "").unwrap();
        assert_eq!(s.take_unlock_notice(), Some(SyncNotice::KeyInFolder));
        assert!(!s.sync_offer() && s.badge().is_none());
    }

    /// A key holder puts a server copy with smaller text under every live
    /// ID, once also deleting the IDs the real texts would move to. On the
    /// open PC and on the closed one, every real text is either dropped or
    /// moved, so each PC keeps a safety copy first and says so, instead of
    /// "both versions were kept".
    #[test]
    fn a_takeover_under_the_same_ids_makes_a_copy() {
        for drop_moved in [true, false] {
            let t = Temp::new();
            let mut server = Server::default();
            let (a, mut sa, b, sb) = pair(&t, &mut server, 6);
            drop(sb);
            let real = titles(&sa);
            let mut forged = open(&sa, &server.versions[0]);
            for e in &mut forged.entries {
                if drop_moved {
                    let id2 = derived_id(&sa.key, b"goyo dup\0", &e.id, e.fields());
                    forged.tombstones.push(id2);
                }
                *e.secret = "a".into(); // sorts before "secret"
            }
            forged.generation += 1;
            let blob = encode_data(&sa.id, &sa.key, Format::V2, forged.view()).unwrap();
            server.versions.push(blob);

            server.pass(&a);
            let ev = sa.poll_sync().unwrap();
            let copies = a.copies();
            assert_eq!(copies.len(), 1);
            let file = format!("vault.goyo.sync\\{}", copies[0]);
            let mass = SyncNotice::MassDelete { removed: 6, file };
            assert_eq!(ev.notice, Some(mass));
            assert!(ev.list_changed);
            let copy = open(&sa, &fs::read(a.dir().join(&copies[0])).unwrap());
            assert_eq!(listed(&copy.entries), real);
            let kept = titles(&sa).iter().filter(|t| real.contains(t)).count();
            assert_eq!(kept, if drop_moved { 0 } else { 6 });
            assert_eq!(state(&saved(&sa)), local(&sa));

            // The closed PC merges it at the unlock: the same.
            server.pass(&b);
            let mut sb = b.unlock();
            let copies = b.copies();
            assert_eq!(copies.len(), 1);
            let file = format!("vault.goyo.sync\\{}", copies[0]);
            let mass = SyncNotice::MassDelete { removed: 6, file };
            assert_eq!(sb.take_unlock_notice(), Some(mass));
            assert_eq!(titles(&sb), titles(&sa));
        }
    }

    /// Deletions from another PC in small steps add up within a session:
    /// the fifth single one makes the safety copy, and it holds the state
    /// before the first of them.
    #[test]
    fn small_losses_add_up_to_a_copy() {
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 30);
        let all = titles(&sa);
        let mut delete_one = |sa: &mut Session| {
            sb.delete(0).unwrap();
            server.pass(&b);
            sb.poll_sync();
            server.pass(&a);
            sa.poll_sync().unwrap()
        };
        let one = SyncNotice::Merged {
            added: 0,
            removed: 1,
        };
        for _ in 0..4 {
            assert_eq!(delete_one(&mut sa).notice, Some(one.clone()));
            assert!(a.copies().is_empty());
        }
        let ev = delete_one(&mut sa);
        let copies = a.copies();
        assert_eq!(copies.len(), 1);
        let file = format!("vault.goyo.sync\\{}", copies[0]);
        let mass = SyncNotice::MassDelete { removed: 5, file };
        assert_eq!(ev.notice, Some(mass));
        assert_eq!(sa.entries.len(), 25);
        let copy = open(&sa, &fs::read(a.dir().join(&copies[0])).unwrap());
        assert_eq!(copy.entries.len(), 30);
        assert_eq!(listed(&copy.entries), all);
        // Counted again from zero after the copy.
        assert_eq!(delete_one(&mut sa).notice, Some(one));
        assert_eq!(a.copies(), copies);
    }

    /// Safety copies younger than 30 days stay, up to 20, and the newest
    /// three always do: a run of merges that each make a copy cannot push
    /// out the one that matters within a month.
    #[test]
    fn safety_copies_stay_for_a_month() {
        let t = Temp::new();
        let day = 86_400;
        let names = |dir: &Path| -> Vec<u64> {
            syncfile::pre_merge_copies(dir)
                .iter()
                .map(|p| copy_time(p).unwrap())
                .collect()
        };
        let made = |copy: String| -> u64 { copy_time(Path::new(&copy)).unwrap() };
        // Two older than 30 days go; the young ones stay.
        let dir = t.0.join("ages");
        fs::create_dir(&dir).unwrap();
        let now = now_secs();
        let ages = [45, 31, 29, 20, 10, 5, 1].map(|d| now - d * day);
        for time in ages {
            fs::write(dir.join(syncfile::pre_merge_name(time)), b"old").unwrap();
        }
        let new = made(pre_merge_copy(&dir, b"new").unwrap());
        assert_eq!(names(&dir), [&ages[2..], &[new][..]].concat());
        assert_eq!(
            fs::read(dir.join(syncfile::pre_merge_name(new))).unwrap(),
            b"new"
        );
        // No more than 20, however young.
        let dir = t.0.join("many");
        fs::create_dir(&dir).unwrap();
        let young: Vec<u64> = (1..=25).rev().map(|h| now - h * 3600).collect();
        for &time in &young {
            fs::write(dir.join(syncfile::pre_merge_name(time)), b"old").unwrap();
        }
        let new = made(pre_merge_copy(&dir, b"new").unwrap());
        assert_eq!(names(&dir), [&young[6..], &[new][..]].concat());
        // The newest three, however old.
        let dir = t.0.join("old");
        fs::create_dir(&dir).unwrap();
        let old = [100, 90, 80].map(|d| now - d * day);
        for time in old {
            fs::write(dir.join(syncfile::pre_merge_name(time)), b"old").unwrap();
        }
        let new = made(pre_merge_copy(&dir, b"new").unwrap());
        assert_eq!(names(&dir), [&old[1..], &[new][..]].concat());
    }

    /// A server that stops taking uploads but keeps serving its last copy:
    /// the upload waiting for it stays as it is, so unlocks give the helper
    /// nothing new to send and the server cannot tell when the vault opens.
    /// It goes up once the server moves again.
    #[test]
    fn a_frozen_server_learns_no_unlocks() {
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        server.frozen = true;
        sa.put(None, entry("new", "by A")).unwrap();
        let upload = fs::read(a.dir().join(OUTGOING)).unwrap();
        let stamp = syncfile::stamp(&a.dir(), OUTGOING);
        server.pass(&a);
        assert_eq!(server.head(), 1);
        assert_eq!(sa.poll_sync(), None);
        drop(sa);
        let tried = server.done.len();
        for _ in 0..3 {
            let mut s = a.unlock();
            assert_eq!(s.take_unlock_notice(), None);
            assert_eq!(s.badge(), Some(SyncBadge::Uploading));
            assert_eq!(fs::read(a.dir().join(OUTGOING)).unwrap(), upload);
            assert_eq!(syncfile::stamp(&a.dir(), OUTGOING), stamp);
            server.pass(&a);
            assert_eq!(server.done.len(), tried, "a new upload to try");
            for _ in 0..3 {
                let ev = s.poll_sync();
                assert!(ev.is_none_or(|e| e.notice.is_none() && !e.list_changed));
            }
            assert_eq!(fs::read(a.dir().join(OUTGOING)).unwrap(), upload);
        }
        // Another PC's upload moves the head: A merges it and uploads anew.
        server.frozen = false;
        sb.put(None, entry("other", "by B")).unwrap();
        server.pass(&b);
        assert_eq!(server.head(), 2);
        let mut sa = a.unlock();
        assert_eq!(a.outgoing().unwrap().0, 1);
        server.pass(&a);
        let ev = sa.poll_sync().unwrap();
        let merged = SyncNotice::Merged {
            added: 1,
            removed: 0,
        };
        assert_eq!(ev.notice, Some(merged));
        assert_eq!(a.outgoing().unwrap().0, 2);
        server.pass(&a);
        assert_eq!(server.head(), 3);
        sa.poll_sync();
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert!(a.outgoing().is_none());
    }
}
