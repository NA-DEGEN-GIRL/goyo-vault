//! The vault side of sync. goyo-vault.exe has no network code: it merges the
//! server copy that goyo-sync.exe leaves in `<vault>.sync\incoming.goyosync`
//! and leaves its own state in `outgoing.goyosync` for the helper to upload.
//! Everything here is local, bounded file I/O on the app's timer. A sync
//! problem never fails an unlock or a save; it shows as a badge or a notice.
//! No Korean text: the app turns `SyncNotice` and `SyncBadge` into its own.
//!
//! A server copy is judged by the key its header names before anything else
//! (spec v3 §7.1): one under this session's current key is merged, one under
//! an older key of this PC's is pushed over unmerged, and one under a key
//! this PC does not hold, or at a newer or forked key-file state, halts sync
//! until a key file arrives (`key_halt`). Only a copy under the current key
//! that does not open is repaired, as 0.8 did.
use super::{
    Contents, DataRef, Entry, EntryId, Format, Header, KEYED_OVERHEAD, LEGACY_OVERHEAD, Session,
    VAULT_DAMAGED, atomic_write, decode_data,
    keyfile::{self, Bundle, KeyState},
    newer_format, plain_size, read_header, sha256,
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
/// How far above this PC's `generation` the count of a copy that is pushed
/// over without a merge may lie and still count (spec v3 §7.1, I-S10): an
/// honest copy is ahead only by its PC's edits and merges since, while one
/// under an old key has attacker-chosen counters.
const GEN_WINDOW: u64 = 1 << 16;

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
    /// merge over the limits (for the rest of the session), a server copy
    /// that halts sync or a local rollback (while either holds), or a status
    /// of refused, config, update, oldserver or keyfile.
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
    /// The server's script refused this vault's format (`oldserver`): it is
    /// older than 0.9.0 and must be updated. Changes stay on this PC.
    OldServer,
    /// The server refused the upload because its key file for the vault
    /// does not match this copy (`keyfile`): another PC changed the keys.
    KeyBehind,
    /// The server copy is under a key this PC does not hold, at a later
    /// key-file state: another PC changed the keys, and sync halts until
    /// this PC has its key file (spec v3 §7.4). `hardware`: that key file
    /// needs a security key, which this build cannot open. Given once per
    /// session.
    KeyChanged {
        hardware: bool,
    },
    /// Two PCs changed the keys apart: a copy under a key this PC does not
    /// hold at no later state, or under the current key at this PC's epoch
    /// with another state. Sync halts until an adopt joins them.
    KeyFork,
    /// The server copy names an older key of this PC's but does not open
    /// with it: damaged or forged. Sync halts.
    OldKeyDamaged,
    /// The key file is an older state of this PC's (a local rollback): no
    /// server copy is merged or pushed over, and no halt is told, until the
    /// user confirms it or takes the newer key file. Given once per session.
    RollbackHeld,
    /// The server copy is under the current key at a later key-file state:
    /// another PC's key file is newer. Sync halts.
    NewerKeyFile,
    /// A server copy under an older key was replaced by this PC's state,
    /// unmerged (D2): a PC that has not taken the new key file wrote it, or
    /// someone with an old key copy.
    OldKeyReplaced,
}
impl SyncNotice {
    /// Lower wins when one event has several.
    fn rank(&self) -> u8 {
        match self {
            Self::Rollback => 0,
            Self::BadIncoming
            | Self::ForeignIncoming
            | Self::KeyChanged { .. }
            | Self::KeyFork
            | Self::OldKeyDamaged
            | Self::RollbackHeld => 1,
            Self::TooLarge | Self::NewerKeyFile | Self::OldKeyReplaced => 2,
            Self::NewerFormat | Self::KeyInFolder => 3,
            Self::MassDelete { .. } => 4,
            Self::Conflicts(_) => 5,
            Self::Merged { .. } => 6,
            Self::HostKey
            | Self::Auth
            | Self::HelperError
            | Self::Offline
            | Self::HelperOff
            | Self::OldServer
            | Self::KeyBehind => 7,
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
                | Self::OldServer
                | Self::KeyBehind
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

/// A server copy that halts sync, as the head override names it (spec v3
/// §7.5a): its server version, the key-file epoch its header states (0 for
/// a GOYOVA01/02 copy) and the key ID it names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HaltedHead {
    pub version: u64,
    pub epoch: u64,
    pub key_id: [u8; 16],
    /// The copy's bytes, so the override pushes over exactly this one.
    sha: [u8; 32],
}
impl HaltedHead {
    /// The first 8 hex digits of the key ID, as S-OVERRIDE-HEAD shows them.
    pub fn key_prefix(&self) -> String {
        self.key_id[..4]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }
}
/// Why a server copy halts sync (spec v3 §7.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Halt {
    /// Under a key this PC does not hold. `newer`: its header states a later
    /// epoch than this PC's key file; `hardware`: its writer's key file
    /// needs a security key.
    UnknownKey { newer: bool, hardware: bool },
    /// Under an older key of this PC's, and it does not open with it.
    OldKeyDamaged,
    /// Under the current key at a later epoch.
    NewerKeyFile,
    /// Under the current key at this PC's epoch with another state.
    KeyFork,
}
impl Halt {
    fn notice(self) -> SyncNotice {
        match self {
            // This build cannot take a security-key file at any epoch, so a
            // fork's advice to take it would mislead.
            Self::UnknownKey { hardware: true, .. } => SyncNotice::KeyChanged { hardware: true },
            Self::UnknownKey { newer: true, .. } => SyncNotice::KeyChanged { hardware: false },
            Self::UnknownKey { newer: false, .. } | Self::KeyFork => SyncNotice::KeyFork,
            Self::OldKeyDamaged => SyncNotice::OldKeyDamaged,
            Self::NewerKeyFile => SyncNotice::NewerKeyFile,
        }
    }
}
/// The server copy that halts sync, and why.
struct Halting {
    halt: Halt,
    head: HaltedHead,
}

/// The session's link to an existing `<vault>.sync` folder.
pub(crate) struct SyncLink {
    dir: PathBuf,
    /// The incoming file last handled; another stamp means a new file.
    in_stamp: Option<Stamp>,
    /// Server version of the incoming last merged, repaired or pushed over,
    /// 0 for none: the base of the next upload.
    merged_version: u64,
    /// The live IDs and tombstones equal those of the newest incoming, and
    /// it is under the current key at this key file's state.
    verified: bool,
    /// This PC's state still has to be written to outgoing.
    outgoing_due: bool,
    /// Polls left before outgoing is written again after a failed write.
    busy_skip: u32,
    /// The last poll found no incoming file where there was one. While a
    /// file is replaced, a listing can show neither name for a moment, so
    /// only a second poll in a row takes the folder for reset.
    incoming_gone: bool,
    /// A rollback, a bad or newer incoming, or a merge over a limit was
    /// seen: the badge stays Warning for the session.
    warned: bool,
    /// Incoming is in a newer format: nothing more is merged or uploaded.
    halted: bool,
    /// `key_halt` (spec v3 §7.2): the newest server copy waits for a key
    /// file this PC lacks. No outgoing is written, while new incoming files
    /// are still read, so the halt lifts by itself once a copy merges. Never
    /// persisted: every unlock derives it again (I-S4).
    halt: Option<Halting>,
    /// The server copy the user chose to push over (spec v3 §7.5a), by its
    /// version and bytes: its halt is a push for the rest of this session,
    /// and only its (a reset server may number another copy the same).
    override_head: Option<HaltedHead>,
    /// KeyChanged was told since the last halt lifted, RollbackHeld in this
    /// session: each once.
    key_changed_told: bool,
    rollback_told: bool,
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
            incoming_gone: false,
            warned: false,
            halted: false,
            halt: None,
            override_head: None,
            key_changed_told: false,
            rollback_told: false,
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
    /// This PC's state is to be uploaded and no longer counts as verified.
    pub(super) fn mark_due(&mut self) {
        (self.outgoing_due, self.verified) = (true, false);
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
    /// `held`: a local rollback holds the session (spec v3 §5.10).
    fn badge(&self, now: u64, held: bool) -> SyncBadge {
        use SyncState as S;
        let state = self.status.and_then(|s| s.state);
        if self.warned
            || self.halt.is_some()
            || held
            || matches!(
                state,
                Some(S::Refused | S::Config | S::Update | S::OldServer | S::KeyFile)
            )
        {
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
            Some(S::OldServer) => return Some(SyncNotice::OldServer),
            Some(S::KeyFile) => return Some(SyncNotice::KeyBehind),
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
    /// No server copy halts sync any more: the next halt is told again, so
    /// KeyChanged is once per halt (spec v3 §7.4).
    fn lift(&mut self) {
        if self.halt.take().is_some() {
            self.key_changed_told = false;
        }
    }
    /// Remembers what the chosen notice told, so it is not told again. A
    /// status notice that lost to another one is offered again later.
    fn told(&mut self, notice: &Option<SyncNotice>) {
        match notice {
            Some(SyncNotice::Synced { .. }) => self.code_shown = true,
            Some(SyncNotice::KeyChanged { .. }) => self.key_changed_told = true,
            Some(SyncNotice::RollbackHeld) => self.rollback_told = true,
            Some(n) if n.is_status() => self.issue = Some(n.clone()),
            _ => {}
        }
    }
    /// Reads and judges incoming as of `stamp` against `local`, a state of
    /// `own`.
    fn fetch(&self, stamp: Stamp, own: Own, local: DataRef) -> Fetched {
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
        let header = match read_header(blob) {
            Ok((_, header)) => Some(header),
            Err(e) if e == VAULT_DAMAGED => return got(version, Verdict::Damaged),
            // No vault format: decryption refuses it below, as in 0.8.
            Err(_) => None,
        };
        if blob[8..24] != own.id[..] {
            return got(version, Verdict::Foreign);
        }
        got(version, own.judge(header, version, blob, local, now))
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
/// What a server copy is to this session (spec v3 §7.1).
enum Verdict {
    /// GOYOVA05 or later: sync stops for this session.
    Newer,
    /// No valid wrapper, or a GOYOVA03/04 header outside the grammar:
    /// ignored. Its version means nothing, so no repair is pushed over it.
    Damaged,
    /// Another vault's copy (e.g. a new vault at a synced path): ignored,
    /// and nothing is pushed over it.
    Foreign,
    /// Under the current key, but it fails authentication or is v1, or it
    /// is in no vault format at all, so no key change made it: ignored, and
    /// this PC's state is pushed over that server version (0.8's repair,
    /// now only within the same key: the `sync.rs:558` fix).
    Unreadable,
    /// The merge would exceed a limit: nothing changes.
    TooLarge,
    /// Under the current key at this key file's state or a lower epoch.
    Merged(Contents, MergeReport),
    /// Under an older key of this PC's, and authentic (D2): never merged,
    /// and this PC's state is pushed over it. The copy's `generation`, which
    /// counts only within GEN_WINDOW, and whether it holds anything this
    /// PC's state lacks, which the push-over then replaces.
    OlderKey(u64, bool),
    /// Never merged and never pushed over: a key file must come first.
    Halt(Halt, HaltedHead),
    /// A copy that would be merged while a local rollback holds: left as it
    /// is (spec v3 §5.10, S23-1 #4).
    Held,
}

/// What incoming copies are judged against: the vault ID, the session's keys
/// and its key file's key IDs and state.
#[derive(Clone, Copy)]
pub(super) struct Own<'a> {
    pub id: &'a [u8; 16],
    pub keys: &'a Bundle,
    /// A KF2 key file's key IDs, in the order of `keys`; None for a 0.8 key
    /// file, which lists none.
    pub ids: Option<&'a [[u8; 16]]>,
    /// The key file's state; a 0.8 key file's is epoch 0 and its legacy tag.
    pub state: KeyState,
    /// A local rollback holds: nothing is merged (spec v3 §5.10).
    pub hold: bool,
}
impl Own<'_> {
    /// What a vault file of this session adds to its plaintext.
    fn overhead(&self) -> usize {
        if self.ids.is_some() {
            KEYED_OVERHEAD
        } else {
            LEGACY_OVERHEAD
        }
    }
    /// The index in `keys` of the key a copy with `header` is under, from
    /// its public header (spec v3 §7.1): 0 is the current key, any other an
    /// older one, None a key this PC does not hold. A GOYOVA01/02 copy is
    /// under the ID key, the last; a 0.8 key file holds one key, which a
    /// GOYOVA03/04 copy names by its key ID.
    fn index(&self, header: &Header) -> Option<usize> {
        match (self.ids, header) {
            (_, Header::Legacy) => Some(self.keys.keys().len().saturating_sub(1)),
            (Some(ids), Header::Keyed { key_id, .. }) => ids
                .iter()
                .position(|i| i == key_id)
                .filter(|i| *i < self.keys.keys().len()),
            (None, Header::Keyed { key_id, .. }) => {
                (*key_id == keyfile::key_id(self.id, self.keys.current())).then_some(0)
            }
        }
    }
    /// The verdict on `blob`, server version `version`, with the vault ID of
    /// this vault and `header` (None: in no vault format): by the class of
    /// its key first, then by its key-file state (spec v3 §7.1).
    fn judge(
        &self,
        header: Option<Header>,
        version: u64,
        blob: &[u8],
        local: DataRef,
        now: u64,
    ) -> Verdict {
        let Some(header) = header else {
            return Verdict::Unreadable;
        };
        let keys = self.keys.keys();
        let halt = |halt| {
            let (epoch, key_id) = match header {
                Header::Keyed { key_id, state, .. } => (state.epoch, key_id),
                Header::Legacy => (0, keyfile::key_id(self.id, self.keys.id_key())),
            };
            let head = HaltedHead {
                version,
                epoch,
                key_id,
                sha: sha256(blob),
            };
            Verdict::Halt(halt, head)
        };
        let index = match self.index(&header) {
            Some(index) => index,
            None => {
                let (newer, hardware) = match header {
                    Header::Keyed { state, flags, .. } => {
                        (state.epoch > self.state.epoch, flags & 1 != 0)
                    }
                    Header::Legacy => (false, false),
                };
                return halt(Halt::UnknownKey { newer, hardware });
            }
        };
        // An older key: decrypted for the classification only, never merged.
        if index > 0 {
            return match decode_data(self.id, &keys[index], self.keys.id_key(), blob) {
                Ok((Format::V2, _, copy)) => Verdict::OlderKey(copy.generation, adds(&copy, local)),
                _ => halt(Halt::OldKeyDamaged),
            };
        }
        let (header, remote) =
            match decode_data(self.id, self.keys.current(), self.keys.id_key(), blob) {
                Ok((Format::V2, header, remote)) => (header, remote),
                // A v1 file was never on a server: someone put it there.
                Ok((Format::V1, ..)) | Err(_) => return Verdict::Unreadable,
            };
        // A GOYOVA01/02 copy states no key-file state: epoch 0, with a 0.8
        // key file's own tag, so a 0.8 session merges it as 0.8 did.
        let theirs = match header {
            Header::Keyed { state, .. } => state,
            Header::Legacy => KeyState {
                epoch: 0,
                tag: self.state.tag,
            },
        };
        if theirs.epoch > self.state.epoch {
            return halt(Halt::NewerKeyFile);
        }
        if theirs.epoch == self.state.epoch && theirs.tag != self.state.tag {
            return halt(Halt::KeyFork);
        }
        if self.hold {
            return Verdict::Held;
        }
        match merge::merge(self.keys.id_key(), local, remote, now / 30, self.overhead()) {
            Ok((mut merged, mut report)) => {
                // A copy at a lower epoch gets this PC's state back, so its
                // PC learns it is behind (spec v3 §7.3); an upload always
                // counts above the copy it replaces.
                if theirs.epoch < self.state.epoch && !report.needs_push {
                    let Some(generation) = merged.generation.checked_add(1) else {
                        return Verdict::TooLarge;
                    };
                    merged.generation = generation;
                    (report.changed, report.needs_push) = (true, true);
                }
                Verdict::Merged(merged, report)
            }
            Err(MergeError::TooLarge) => Verdict::TooLarge,
        }
    }
    /// The `generation` of `blob` when it opens under the key its header
    /// names, which this PC holds: what a head override counts above.
    fn readable(&self, blob: &[u8]) -> Option<u64> {
        let (_, header) = read_header(blob).ok()?;
        let key = self.keys.keys().get(self.index(&header)?)?;
        match decode_data(self.id, key, self.keys.id_key(), blob) {
            Ok((Format::V2, _, copy)) => Some(copy.generation),
            _ => None,
        }
    }
}
/// Whether `copy` holds anything `local` lacks: a live entry that is
/// neither live there with the same text nor deleted there, or a deletion
/// it has not made. What a push-over of an older-key copy would replace.
fn adds(copy: &Contents, local: DataRef) -> bool {
    let dead: BTreeSet<EntryId> = local.tombstones.iter().copied().collect();
    let live: BTreeMap<EntryId, &Entry> = local.entries.iter().map(|e| (e.id, e)).collect();
    copy.entries.iter().any(|e| match live.get(&e.id) {
        Some(l) => !l.same_content(e),
        None => !dead.contains(&e.id),
    }) || copy.tombstones.iter().any(|t| !dead.contains(t))
}
/// The `generation` of this PC's state when it is pushed over a copy at
/// `theirs` without a merge (spec v3 §7.1, I-S10): above both, but the
/// copy's counts only within GEN_WINDOW above `own`, and nothing overflows.
/// `seen` stays: it counts only merged copies.
fn pushed_over(own: u64, theirs: u64) -> u64 {
    let counted = if theirs <= own.saturating_add(GEN_WINDOW) {
        theirs
    } else {
        own
    };
    own.max(counted).saturating_add(1)
}

/// What `Session::load` found in the sync folder before the OTP check.
pub(super) struct Pending {
    link: Option<Box<SyncLink>>,
    fetched: Option<Fetched>,
    key_in_folder: bool,
}
impl Pending {
    /// Links and reads incoming for a login. A restore writes a new file and
    /// a new vault has no copies, so neither links here. `own.hold`: a login
    /// of an older state of this PC (a local rollback) links but reads
    /// nothing, so nothing is merged (spec v3 §5.2 step 6).
    pub(super) fn find(
        login: bool,
        vault: &Path,
        key_path: &Path,
        format: Format,
        own: Own,
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
            Attach::Linked(link) if own.hold => pending.link = Some(link),
            Attach::Linked(link) => {
                pending.fetched = Some(match syncfile::stamp(&link.dir, INCOMING) {
                    None => Fetched::Missing,
                    Some(stamp) => link.fetch(stamp, own, local),
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
        Some(self.sync.as_ref()?.badge(now_secs(), self.local_rollback))
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
    /// `XXXX-XXXX-XXXX-XXXX`: equal on two PCs means equal contents. Under a
    /// KF2 key file it covers the key file's state too, so it is equal only
    /// once both PCs hold the same key file (spec v3 §4.8).
    pub fn check_code(&self) -> String {
        let state = self.key_file.header().map(|_| self.key_state);
        merge::check_code(self.keys.id_key(), &self.entries, &self.tombstones, state)
    }
    /// What incoming copies are judged against.
    fn own(&self) -> Own<'_> {
        Own {
            id: &self.id,
            keys: &self.keys,
            ids: self.key_file.header().map(|h| h.key_ids.as_slice()),
            state: self.key_state,
            hold: self.local_rollback,
        }
    }
    /// Call every 2 s while the vault list is shown and no dialog is open: it
    /// merges a new server copy (changing `entries`), retries the upload and
    /// reads the helper's status. None when there is nothing to show.
    pub fn poll_sync(&mut self) -> Option<SyncEvent> {
        // The unlock could not save the vault file under the current key.
        if self.resave_due {
            let _ = self.save();
        }
        // What a key change left to finish (spec §5.5 S2, §5.10).
        self.retry_key_temp();
        self.retry_anchor();
        let mut notice = None;
        let unlinked = self.sync.is_none();
        if let Some(refused) = self.connect() {
            offer(&mut notice, refused);
        }
        let Some(mut link) = self.sync.take() else {
            return notice.map(|n| SyncEvent {
                notice: Some(n),
                ..SyncEvent::default()
            });
        };
        // A link made just now has looked at the folder: its next look is
        // the next poll's.
        let list_changed = !unlinked && self.poll_link(&mut link, &mut notice);
        link.told(&notice);
        let badge = link.badge(now_secs(), self.local_rollback);
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
            // claiming "Synced" against a copy that no longer exists. The
            // helper replaces incoming by a rename, and a listing in that
            // moment can show neither name: only a second poll in a row
            // without it counts.
            // The unlock or the link that found no incoming waits for this
            // second look as well before it offers this state.
            let gone = stamp.is_none() && (link.in_stamp.is_some() || link.incoming_gone);
            if gone && link.incoming_gone {
                link.in_stamp = None;
                (link.verified, link.outgoing_due) = (false, true);
                // No copy is left to halt on.
                link.lift();
            }
            link.incoming_gone = gone && link.in_stamp.is_some();
            // New server copies are read during a halt too, so it lifts by
            // itself (spec v3 §7.2).
            if let Some(stamp) = stamp.filter(|s| link.in_stamp != Some(*s))
                && let Fetched::Got(arrival) = link.fetch(stamp, self.own(), self.data())
            {
                match self.take(link, arrival, notice) {
                    Ok(taken) => list_changed = taken.list_changed,
                    // Not saved: the same file is merged again next time,
                    // and nothing is uploaded meanwhile. A newer server copy
                    // is not in this PC's state, so it is not "Synced".
                    Err(()) => (upload, link.verified) = (false, false),
                }
            }
            // Nothing goes up while a server copy halts sync, nor during a
            // local rollback (spec v3 §7.2, §5.10, S23-1 #4).
            if upload && link.outgoing_due && link.halt.is_none() && !self.local_rollback {
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
    /// many entries; so is the raised count of a push-over. Err if a write
    /// failed: then nothing changed and `in_stamp` stays, so the same file
    /// is tried again.
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
            // A head that names no key replaced the one that halted: nothing
            // is left to override, and nothing is pushed over it (spec v3
            // §7.2).
            Verdict::Newer => {
                (link.halted, link.warned, link.verified) = (true, true, false);
                link.lift();
                offer(notice, SyncNotice::NewerFormat);
            }
            Verdict::Damaged => {
                (link.warned, link.verified) = (true, false);
                link.lift();
                offer(notice, SyncNotice::BadIncoming);
            }
            Verdict::Foreign => {
                (link.warned, link.verified) = (true, false);
                link.lift();
                offer(notice, SyncNotice::ForeignIncoming);
            }
            // A local rollback merges nothing, pushes over nothing and asks
            // for no key file: the server copy is most likely this PC's own
            // newer state, and whoever put the older pair back may know its
            // key (spec v3 §7.1 I-S8, S23-3 #5). Told once per session.
            Verdict::Unreadable
            | Verdict::TooLarge
            | Verdict::Merged(..)
            | Verdict::OlderKey(..)
            | Verdict::Halt(..)
            | Verdict::Held
                if self.local_rollback =>
            {
                link.verified = false;
                if !link.rollback_told {
                    offer(notice, SyncNotice::RollbackHeld);
                }
            }
            Verdict::Held => link.verified = false,
            // A halt belongs to the copy that caused it: a later head that is
            // repaired, pushed over or merged replaces it (spec v3 §7.2).
            Verdict::Unreadable => {
                link.warned = true;
                // Our state replaces the bad head: CAS from its version.
                link.merged_version = version;
                link.lift();
                (link.verified, link.outgoing_due) = (false, true);
                offer(notice, SyncNotice::BadIncoming);
            }
            Verdict::TooLarge => {
                (link.warned, link.too_large, link.verified) = (true, true, false);
                link.lift();
                offer(notice, SyncNotice::TooLarge);
            }
            // D2: pushed over unmerged, from its version, counting above it.
            Verdict::OlderKey(theirs, adds) => {
                let generation = pushed_over(self.generation, theirs);
                let data = DataRef {
                    generation,
                    ..self.data()
                };
                let bytes = self.encode_as(Format::V2, data).map_err(|_| ())?;
                self.write(&bytes).map_err(|_| ())?;
                (self.generation, taken.wrote) = (generation, true);
                // A copy that holds nothing this PC lacks needs no word, such
                // as this PC's own upload from before its key change: nothing
                // of another PC's is replaced.
                if adds {
                    offer(notice, SyncNotice::OldKeyReplaced);
                }
                link.merged_version = version;
                link.lift();
                (link.verified, link.outgoing_due) = (false, true);
            }
            // The head the user chose to push over (spec v3 §7.5a), read
            // again: still a push, and its count was raised then.
            Verdict::Halt(_, head) if link.override_head.as_ref() == Some(&head) => {
                (link.merged_version, link.halt) = (version, None);
                (link.verified, link.outgoing_due) = (false, true);
            }
            Verdict::Halt(halt, head) => {
                link.verified = false;
                link.halt = Some(Halting { halt, head });
                let told =
                    matches!(halt.notice(), SyncNotice::KeyChanged { .. }) && link.key_changed_told;
                if !told {
                    offer(notice, halt.notice());
                }
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
                    Some(self.encode_as(Format::V2, self.data()).map_err(|_| ())?)
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
                    let bytes = self.encode_as(Format::V2, merged.view()).map_err(|_| ())?;
                    self.write(&bytes).map_err(|_| ())?;
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
                // Before any outgoing write: the next upload builds on it. A
                // copy under the current key at no later state lifts a halt.
                link.merged_version = version;
                link.too_large = false;
                link.lift();
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
        let Ok(blob) = self.encode_as(Format::V2, self.data()) else {
            return;
        };
        match write_outgoing(&link.dir, link.merged_version, &blob, &self.id) {
            Ok(()) => (link.outgoing_due, link.busy_skip) = (false, 0),
            Err(_) => link.busy_skip = BUSY_SKIP,
        }
    }
    /// Whether outgoing already holds this state, made from the same server
    /// version under the same header (magic, key ID, key-file state and
    /// flags): the same entries, IDs and text, and the same tombstones. The
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
        let header = self.header();
        let size = plain_size(Format::V2, &self.entries, self.tombstones.len()) + header.overhead();
        if base != link.merged_version || blob.len() != size {
            return false;
        }
        let Ok((Format::V2, held_header, held)) =
            decode_data(&self.id, self.keys.current(), self.keys.id_key(), blob)
        else {
            return false;
        };
        if held_header != header {
            return false;
        }
        let dead = |t: &[EntryId]| t.iter().copied().collect::<BTreeSet<_>>();
        held.entries.len() == self.entries.len()
            && lost(&self.entries, &held.entries) == 0
            && dead(&held.tombstones) == dead(&self.tombstones)
    }
    /// Whether this synced vault may not hold the server's newest state:
    /// not verified against it, or the helper is not running (spec §7.5,
    /// the Unverified gate).
    pub(super) fn sync_unverified(&self) -> bool {
        self.sync
            .as_ref()
            .is_some_and(|link| !link.verified || link.helper_off(now_secs()))
    }
    /// The halt that gates a key change (spec v3 §7.5): Some(true) when its
    /// notice was KeyFork (two PCs changed the keys apart), Some(false) for
    /// any other halt.
    pub(super) fn sync_halt(&self) -> Option<bool> {
        let halting = self.sync.as_ref()?.halt.as_ref()?;
        Some(halting.halt.notice() == SyncNotice::KeyFork)
    }
    /// The server copy that halts sync, which the head override
    /// (`KEY_OVERRIDE_HEAD`) would push over (spec v3 §7.5a). None while
    /// nothing halts, and during a local rollback: the hold wins, so the
    /// override is not offered then (S23-3 #5).
    pub fn halted_head(&self) -> Option<HaltedHead> {
        if self.local_rollback {
            return None;
        }
        let halting = self.sync.as_ref()?.halt.as_ref()?;
        Some(halting.head.clone())
    }
    /// P3 of the head override (spec v3 §7.5a), once the Reauth passed and
    /// the hold was checked: incoming must still be exactly `head`, which
    /// still halts, else Ok(false) and nothing is written. Its halt becomes
    /// a push for this session: this PC's state is written over that server
    /// version, which stays in the server's history. A head that opens under
    /// a key this PC holds counts below what replaces it, as a push-over of
    /// an older-key copy does.
    pub(super) fn push_over_head(&mut self, head: &HaltedHead) -> crate::crypto::Result<bool> {
        let Some(mut link) = self.sync.take() else {
            return Ok(false);
        };
        let result = self.push_over(&mut link, head);
        self.sync = Some(link);
        result
    }
    fn push_over(&mut self, link: &mut SyncLink, head: &HaltedHead) -> crate::crypto::Result<bool> {
        let Ok(bytes) = syncfile::read_bounded(&link.dir.join(INCOMING), syncfile::MAX_WRAPPED)
        else {
            return Ok(false);
        };
        let Some((version, blob)) = syncfile::parse_incoming(&bytes) else {
            return Ok(false);
        };
        let halted = link.halt.as_ref().map(|h| &h.head);
        if version != head.version || sha256(blob) != head.sha || halted != Some(head) {
            return Ok(false);
        }
        if let Some(theirs) = self.own().readable(blob) {
            let generation = pushed_over(self.generation, theirs);
            let data = DataRef {
                generation,
                ..self.data()
            };
            let bytes = self.encode_as(Format::V2, data)?;
            self.write(&bytes)?;
            self.generation = generation;
        }
        link.override_head = Some(head.clone());
        link.lift();
        link.merged_version = version;
        (link.verified, link.outgoing_due) = (false, true);
        self.write_outgoing(link);
        link.last_badge = Some(link.badge(now_secs(), self.local_rollback));
        Ok(true)
    }
    /// A key change made a new state, or a local rollback ended: every
    /// verdict is derived again at the next poll, and a halt lifts until a
    /// copy halts again (spec v3 §5.5 Commit, §7.2, I-S4).
    pub(super) fn relink(&mut self) {
        if let Some(link) = self.sync.as_mut() {
            (link.in_stamp, link.verified, link.incoming_gone) = (None, false, false);
            link.lift();
        }
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
                // Nothing fetched yet: this state is offered, made from no
                // server version (base 0), once the next poll finds no
                // incoming either.
                link.incoming_gone = syncfile::stamp(&link.dir, INCOMING).is_none();
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
                // Offered at the first poll that finds none either: a listing
                // made while the helper replaces incoming can show neither
                // name.
                Some(Fetched::Missing) => link.incoming_gone = true,
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
    /// Writes outgoing if due. A failure keeps it due for the next poll. A
    /// halt or a local rollback keeps it due, unwritten.
    pub(super) fn flush_outgoing(&mut self) {
        if let Some(mut link) = self.sync.take() {
            if link.outgoing_due && !link.halted && link.halt.is_none() && !self.local_rollback {
                self.write_outgoing(&mut link);
            }
            self.sync = Some(link);
        }
    }
    /// After a saved put or delete: upload the new state. A halt or a local
    /// rollback keeps it due, unwritten (spec v3 §7.2, §5.10).
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
            if link.halt.is_none() && !self.local_rollback {
                self.write_outgoing(&mut link);
            }
            link.last_badge = Some(link.badge(now_secs(), self.local_rollback));
        }
        self.sync = Some(link);
    }
}

/// Gate 1 of three that keep the key file off the server: only a GOYOVA02
/// or GOYOVA04 file of this vault, fresh from `encode_data`, is offered for
/// upload.
fn write_outgoing(dir: &Path, base: u64, blob: &[u8], id: &[u8; 16]) -> Result<(), FileError> {
    if !syncfile::is_sync_vault(blob) || blob.get(8..24) != Some(&id[..]) {
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
        vault::{
            Acks, Adopted, Change, Consent, GAP_KEPT, Gate, GatePass, KeyNotice, LOCAL_ROLLBACK,
            NO_ID, Provision, Rekeyed, SIMULATED_CRASH, Source, UnionPassword, VaultClass, anchor,
            derived_id, encode_data, encode_key,
            keyfile::{KeyFile, Kind, Plan, Spec, key_code, key_id, parse, seal},
            prepare, set_anchor_dir,
        },
    };
    use std::{
        collections::BTreeSet,
        fs::{File, OpenOptions},
        os::windows::fs::OpenOptionsExt,
    };
    use zeroize::Zeroizing;

    const PASS: &str = "a long synthetic password";
    const NEW: &str = "a new synthetic password";
    const OTHER: &str = "another synthetic password";

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
            set_anchor_dir(Some(p.join("anchor")));
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
            set_anchor_dir(None);
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    /// One PC's GoyoVault folder, with its own anchor folder: every call this
    /// harness makes for the PC takes its anchor (spec §5.10).
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
        /// Every call from now on is this PC's: its anchor folder.
        fn here(&self) {
            set_anchor_dir(Some(self.0.join("anchor")));
        }
        fn unlock(&self) -> Session {
            self.unlock_with(PASS)
        }
        fn unlock_with(&self, password: &str) -> Session {
            self.here();
            Session::unlock(&self.vault(), &self.key(), password, "").unwrap()
        }
        /// This PC's key file, brought "by USB" into `to`'s folder.
        fn key_to(&self, to: &Pc) -> PathBuf {
            let usb = to.0.join("usb.goyokey");
            fs::copy(self.key(), &usb).unwrap();
            usb
        }
        fn anchor(&self) -> Vec<u8> {
            fs::read(self.0.join("anchor").join("goyo-vault.keys")).unwrap_or_default()
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
        decode_data(&s.id, s.keys.current(), s.keys.id_key(), blob)
            .unwrap()
            .2
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
        a.here();
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
        b.here();
        let restored = Session::restore(&fetched, &b.key(), &b.vault(), PASS, "").unwrap();
        assert_eq!(restored.format(), Format::V2);
        drop(restored);
        b.helper();
        let mut sb = b.unlock();
        // Nothing fetched yet: B offers its copy, made from no version, at
        // the first poll that finds no incoming either.
        assert_eq!(sb.take_unlock_notice(), None);
        assert!(b.outgoing().is_none());
        let _ = sb.poll_sync();
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
            encode_data(&p.id, &p.key, &Header::Legacy, Format::V2, d).unwrap()
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        let vault = encode_data(&p.id, &p.key, &Header::Legacy, Format::V2, d).unwrap();
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        // offered with base 0 at the next poll that finds no incoming either.
        a.helper();
        assert_eq!(s.poll_sync(), event(None, true));
        assert_eq!(s.badge(), Some(SyncBadge::Uploading));
        assert!(a.outgoing().is_none());
        let _ = s.poll_sync();
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 0);
        assert_eq!(state(&open(&s, &blob)), local(&s));
        let good = fs::read(a.vault()).unwrap();
        drop(s);
        fs::remove_file(a.dir().join(OUTGOING)).unwrap();

        // No incoming yet: the first poll that finds none either offers the
        // state with base 0.
        let mut s = a.unlock();
        assert_eq!(s.take_unlock_notice(), None);
        assert!(a.outgoing().is_none());
        let _ = s.poll_sync();
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
        let foreign =
            encode_data(&other.id, &other.key, &Header::Legacy, Format::V2, empty).unwrap();
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
        newer[..8].copy_from_slice(b"GOYOVA05");
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, _b, _sb) = pair(&t, &mut server, 2);
        let _ = status_poll(&mut sa);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert!(a.outgoing().is_none());
        fs::remove_dir_all(a.dir()).unwrap();
        a.helper();
        a.status(SyncState::Idle);
        // One poll without the server copy could be the moment the helper
        // replaces it; the second in a row is a reset.
        let _ = status_poll(&mut sa);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert!(a.outgoing().is_none());
        let _ = sa.poll_sync();
        assert_eq!(sa.badge(), Some(SyncBadge::Uploading));
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 1);
        assert_eq!(state(&open(&sa, &blob)), local(&sa));
    }
    /// The helper replaces incoming by a rename, and a folder listing in that
    /// moment can show neither name. One poll that sees no incoming is no
    /// reset: 0.8 took it for one, dropped "Synced" and uploaded this PC's
    /// state again over the server copy it had just merged.
    #[test]
    fn a_moment_without_incoming_is_no_reset() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, _b, _sb) = pair(&t, &mut server, 2);
        let _ = status_poll(&mut sa);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        let incoming = a.dir().join(INCOMING);
        let held = fs::read(&incoming).unwrap();
        fs::remove_file(&incoming).unwrap();
        assert_eq!(sa.poll_sync(), None);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert!(a.outgoing().is_none());
        // The new name is there at the next poll: the same server copy,
        // merged again with nothing to add, and nothing uploaded.
        fs::write(&incoming, &held).unwrap();
        let _ = sa.poll_sync();
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert!(a.outgoing().is_none());
        assert_eq!(server.head(), 1);
    }

    #[test]
    fn bad_or_old_server_copies_warn() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        let v1 = sa.encode_as(Format::V1, sa.data()).unwrap();
        a.incoming(6, &v1);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::BadIncoming));
        assert_eq!(a.outgoing().unwrap().0, 6);
        assert_eq!(titles(&sa), kept);
        // A newer format halts sync for the session.
        let mut newer = server.versions[1].clone();
        newer[..8].copy_from_slice(b"GOYOVA05");
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
            // A server script older than 0.9.0, and a server key file this
            // copy does not match: Warning, with their own notice (spec §7.6).
            (
                SyncState::OldServer,
                SyncBadge::Warning,
                Some(SyncNotice::OldServer),
            ),
            (SyncState::OldServer, SyncBadge::Warning, None),
            (
                SyncState::KeyFile,
                SyncBadge::Warning,
                Some(SyncNotice::KeyBehind),
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        let (_, _, v1) = decode_data(&p.id, &p.key, &p.key, &fs::read(a.vault()).unwrap()).unwrap();
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
        let (format, _, up) = decode_data(&p.id, &p.key, &p.key, &blob).unwrap();
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        for drop_moved in [true, false] {
            let t = Temp::new();
            let mut server = Server::default();
            let (a, mut sa, b, sb) = pair(&t, &mut server, 6);
            drop(sb);
            let real = titles(&sa);
            let mut forged = open(&sa, &server.versions[0]);
            for e in &mut forged.entries {
                if drop_moved {
                    let id2 = derived_id(sa.keys.id_key(), b"goyo dup\0", &e.id, e.fields());
                    forged.tombstones.push(id2);
                }
                *e.secret = "a".into(); // sorts before "secret"
            }
            forged.generation += 1;
            let blob = sa.encode_as(Format::V2, forged.view()).unwrap();
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
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

    /// The same moment at an unlock: one listing without incoming waits for
    /// the first poll before this PC's state is offered, so the helper's
    /// rename uploads nothing (the server would learn of the unlock) and its
    /// copy still merges; with incoming really gone, this state is offered
    /// at that poll (spec §2.18 #62).
    #[test]
    fn an_unlock_without_incoming_waits_for_a_second_look() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (_a, _sa, b, sb) = pair(&t, &mut server, 2);
        drop(sb);
        let incoming = b.dir().join(INCOMING);
        let held = fs::read(&incoming).unwrap();
        fs::remove_file(&incoming).unwrap();
        let mut sb = b.unlock();
        assert!(b.outgoing().is_none());
        fs::write(&incoming, &held).unwrap();
        let _ = sb.poll_sync();
        assert!(b.outgoing().is_none());
        assert_eq!(sb.badge(), Some(SyncBadge::Synced));
        drop(sb);
        fs::remove_file(&incoming).unwrap();
        let mut sb = b.unlock();
        assert!(b.outgoing().is_none());
        let _ = sb.poll_sync();
        assert_eq!(b.outgoing().unwrap().0, 0);
    }

    /// A password change of `s` from `from` to `to` (spec v3 §5.5), the gate
    /// answered yes.
    fn change(s: &mut Session, from: &str, to: &str) -> Rekeyed {
        let r = s.reauth(from, None, None).unwrap();
        let to = Change::Password(Zeroizing::new(to.to_owned()));
        s.rekey(r, Vec::new(), to, Consent::default(), true)
            .unwrap()
    }
    /// "새 열쇠 파일 받기" (spec v3 §5.8) of the key file at `other`, which
    /// `password` opens, as the flow makes it: checked, opened, previewed and
    /// written with the defaults, and yes to S-ADOPT-BOTHPASS where asked.
    fn adopt(s: &mut Session, own: &str, other: &Path, password: &str) -> Adopted {
        let r = s.reauth(own, None, None).unwrap();
        let file = KeyFile::read(other).unwrap();
        let check = s
            .adopt_check(&file, Source::File(other.to_owned()))
            .unwrap();
        let opened = s.adopt_open(&r, &file, Some(password)).unwrap();
        let plan = s
            .adopt_preview(&r, &file, opened, &check, GatePass::none(&check), None)
            .unwrap();
        let acks = Acks {
            password_only: false,
            union_password: UnionPassword::Other,
            both_passwords: plan.preview().both_passwords,
        };
        s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
            .unwrap()
    }
    /// The content part of the check code: 0.8's code, without the key-file
    /// state a KF2 session adds (spec v3 §4.8).
    fn content(s: &Session) -> String {
        merge::check_code(s.keys.id_key(), &s.entries, &s.tombstones, None)
    }
    fn code_of(s: &Session) -> keyfile::Code {
        key_code(&s.id, s.keys.current(), s.key_state)
    }
    /// A third PC that gets the key file `key` "by USB" and the server's head
    /// through Restore, then links and merges it, like B in `pair`.
    fn join(t: &Temp, server: &mut Server, key: &[u8], name: &str) -> (Pc, Session) {
        let c = t.pc(name);
        fs::write(c.key(), key).unwrap();
        let fetched = c.0.join("from-server.goyo");
        fs::write(&fetched, server.versions.last().unwrap()).unwrap();
        c.here();
        drop(Session::restore(&fetched, &c.key(), &c.vault(), PASS, "").unwrap());
        c.helper();
        let mut sc = c.unlock();
        server.pass(&c);
        let _ = sc.poll_sync();
        assert_eq!(sc.badge(), Some(SyncBadge::Synced));
        (c, sc)
    }
    /// Rounds of each PC's helper pass and poll, in this order.
    fn rounds(server: &mut Server, pcs: &mut [(&Pc, &mut Session)], n: usize) {
        for _ in 0..n {
            for (pc, s) in pcs.iter_mut() {
                server.pass(pc);
                let _ = s.poll_sync();
            }
        }
    }
    /// A server copy of a vault of `id` under `dk` with `header` in
    /// `format`, holding `entries` and `tombstones` at `generation`;
    /// `broken`: its last byte flipped, so it does not authenticate.
    #[allow(clippy::too_many_arguments)]
    fn copy_of(
        id: &[u8; 16],
        dk: &[u8; 32],
        header: Header,
        format: Format,
        entries: &[Entry],
        tombstones: &[EntryId],
        generation: u64,
        broken: bool,
    ) -> Vec<u8> {
        let d = DataRef {
            last: 0,
            generation,
            seen: 0,
            entries,
            tombstones,
        };
        let mut blob = encode_data(id, dk, &header, format, d).unwrap();
        if broken {
            let end = blob.len() - 1;
            blob[end] ^= 1;
        }
        blob
    }
    fn keyed(id: &[u8; 16], dk: &[u8; 32], state: KeyState, flags: u8) -> Header {
        Header::Keyed {
            key_id: key_id(id, dk),
            state,
            flags,
        }
    }
    fn halt_of(s: &Session) -> Option<Halt> {
        link(s).halt.as_ref().map(|h| h.halt)
    }

    /// What a server copy did to the session that unlocked with it.
    #[derive(Clone, PartialEq, Eq, Debug)]
    enum Want {
        /// Merged, and this PC's state uploaded from its version.
        Merge,
        /// Not opened, and this PC's state pushed over its version (0.8's
        /// repair, now only under the current key).
        Repair,
        /// Under an older key: pushed over unmerged (D2).
        PushOver,
        /// Sync halts with this notice: no merge, no upload.
        Halt(SyncNotice),
        /// Ignored, with this notice: no merge, no upload, no halt.
        Ignored(SyncNotice),
    }

    /// Every row of spec v3 §7.1 for a 0.8 session and a KF2 one (§14.6-1,
    /// -9, -10, -13, -15): a server copy is judged by the key its header
    /// names first. Only a copy under the current key is merged, or repaired
    /// when it does not open (the `sync.rs:558` fix); one under an older key
    /// that opens is pushed over unmerged, and every other copy halts sync:
    /// nothing is merged (I-S1), and no outgoing is written, across 50 polls
    /// and an edit (I-S2). The older class does not exist for a 0.8 session,
    /// whose only key is the ID key.
    #[test]
    fn copies_are_judged_by_their_key_first() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        for kf2 in [false, true] {
            let t = Temp::new();
            let a = t.pc("a");
            a.here();
            let p = Provision::new().unwrap();
            let mut s = p.finish(&a.vault(), &a.key(), PASS, None).unwrap();
            s.put(None, entry("mine", "secret")).unwrap();
            a.helper();
            s.enable_sync().unwrap();
            // Two password changes: the current key, an older one and the
            // ID key, at epoch 2.
            let password = if kf2 {
                assert_eq!(change(&mut s, PASS, OTHER), Rekeyed::Done);
                assert_eq!(change(&mut s, OTHER, NEW), Rekeyed::Done);
                NEW
            } else {
                PASS
            };
            let (id, own, gen0) = (s.id, s.key_state(), s.generation);
            let keys = s.keys.keys().to_vec();
            let (current, id_key) = (keys[0], *keys.last().unwrap());
            let mine = s.entries.clone();
            // A legacy session's check code is 0.8's (§14.6-15).
            assert_eq!(s.check_code() == content(&s), !kf2);
            drop(s);
            let vault = fs::read(a.vault()).unwrap();
            let _ = fs::remove_file(a.dir().join(OUTGOING));
            let mut theirs = entry("theirs", "x");
            theirs.set_ids([2; 16], NO_ID);
            let theirs = [theirs];
            let copy = |dk: &[u8; 32], header: Header, format: Format, broken: bool| {
                copy_of(&id, dk, header, format, &theirs, &[], 7, broken)
            };
            let state = |epoch: u64, tag: [u8; 16]| KeyState { epoch, tag };
            let random = [0x5c; 32];
            let unknown = |epoch, flags| keyed(&id, &random, state(epoch, [3; 16]), flags);
            let halt = Want::Halt;
            // A GOYOVA03/04 header states an epoch of 1 at least.
            let at_own = if kf2 { own } else { state(1, own.tag) };
            let mut cases: Vec<(&str, Vec<u8>, Want)> = vec![
                (
                    "current, v2",
                    match kf2 {
                        true => copy(&current, keyed(&id, &current, own, 0), Format::V2, false),
                        false => copy(&current, Header::Legacy, Format::V2, false),
                    },
                    Want::Merge,
                ),
                (
                    "current, v2, fails",
                    match kf2 {
                        true => copy(&current, keyed(&id, &current, own, 0), Format::V2, true),
                        false => copy(&current, Header::Legacy, Format::V2, true),
                    },
                    Want::Repair,
                ),
                (
                    "current, v1",
                    match kf2 {
                        true => copy(&current, keyed(&id, &current, own, 0), Format::V1, false),
                        false => copy(&current, Header::Legacy, Format::V1, false),
                    },
                    Want::Repair,
                ),
                (
                    "current, v1, fails",
                    match kf2 {
                        true => copy(&current, keyed(&id, &current, own, 0), Format::V1, true),
                        false => copy(&current, Header::Legacy, Format::V1, true),
                    },
                    Want::Repair,
                ),
                // GOYOVA03/04 under the current key's ID: a 0.8 session's
                // too (§14.6-9, -10).
                (
                    "current key ID, garbage",
                    copy(&current, keyed(&id, &current, at_own, 0), Format::V2, true),
                    Want::Repair,
                ),
                (
                    "current key ID, v1",
                    copy(&current, keyed(&id, &current, at_own, 0), Format::V1, false),
                    Want::Repair,
                ),
                // A later key-file state under the current key.
                (
                    "current, later epoch",
                    copy(
                        &current,
                        keyed(&id, &current, state(own.epoch + 1, own.tag), 0),
                        Format::V2,
                        false,
                    ),
                    halt(SyncNotice::NewerKeyFile),
                ),
                (
                    "unknown, later epoch",
                    copy(&random, unknown(own.epoch + 1, 0), Format::V2, false),
                    halt(SyncNotice::KeyChanged { hardware: false }),
                ),
                (
                    "unknown, later epoch, fails",
                    copy(&random, unknown(own.epoch + 1, 0), Format::V2, true),
                    halt(SyncNotice::KeyChanged { hardware: false }),
                ),
                (
                    "unknown, later epoch, v1",
                    copy(&random, unknown(own.epoch + 1, 0), Format::V1, false),
                    halt(SyncNotice::KeyChanged { hardware: false }),
                ),
                (
                    "unknown, security key",
                    copy(&random, unknown(own.epoch + 1, 1), Format::V2, false),
                    halt(SyncNotice::KeyChanged { hardware: true }),
                ),
                (
                    "newer format",
                    {
                        let mut b = copy(&current, Header::Legacy, Format::V2, false);
                        b[..8].copy_from_slice(b"GOYOVA05");
                        b
                    },
                    Want::Ignored(SyncNotice::NewerFormat),
                ),
                (
                    "header outside the grammar",
                    {
                        let header = keyed(&id, &current, at_own, 0);
                        let mut b = copy(&current, header, Format::V2, false);
                        b[65] = 1;
                        b
                    },
                    Want::Ignored(SyncNotice::BadIncoming),
                ),
                // In no vault format: no key change made it.
                (
                    "no vault format",
                    {
                        let mut b = copy(&current, Header::Legacy, Format::V2, false);
                        b[..8].copy_from_slice(b"GOYOVA00");
                        b
                    },
                    Want::Repair,
                ),
            ];
            if kf2 {
                let older = keys[1];
                let lower = state(own.epoch - 1, [4; 16]);
                cases.extend([
                    // An unknown key at no later state: two PCs changed
                    // the keys apart.
                    (
                        "unknown, same epoch",
                        copy(&random, unknown(own.epoch, 0), Format::V2, false),
                        halt(SyncNotice::KeyFork),
                    ),
                    (
                        "current, same epoch, another tag",
                        copy(
                            &current,
                            keyed(&id, &current, state(own.epoch, [9; 16]), 0),
                            Format::V2,
                            false,
                        ),
                        halt(SyncNotice::KeyFork),
                    ),
                    // A security-key copy at no later state: this build
                    // cannot take its key file, so no fork advice either
                    // (spec §2.18 #58).
                    (
                        "unknown, security key, same epoch",
                        copy(&random, unknown(own.epoch, 1), Format::V2, false),
                        halt(SyncNotice::KeyChanged { hardware: true }),
                    ),
                    (
                        "unknown, security key, lower epoch",
                        copy(&random, unknown(own.epoch - 1, 1), Format::V2, false),
                        halt(SyncNotice::KeyChanged { hardware: true }),
                    ),
                    // A lower epoch merges as a lagging copy (§14.6-13).
                    (
                        "current, lower epoch",
                        copy(&current, keyed(&id, &current, lower, 0), Format::V2, false),
                        Want::Merge,
                    ),
                    (
                        "older, v2",
                        copy(&older, keyed(&id, &older, lower, 0), Format::V2, false),
                        Want::PushOver,
                    ),
                    // GOYOVA02 under the ID key of a converted vault.
                    (
                        "ID key, v2",
                        copy(&id_key, Header::Legacy, Format::V2, false),
                        Want::PushOver,
                    ),
                    (
                        "older, v2, fails",
                        copy(&older, keyed(&id, &older, lower, 0), Format::V2, true),
                        halt(SyncNotice::OldKeyDamaged),
                    ),
                    (
                        "older, v1",
                        copy(&older, keyed(&id, &older, lower, 0), Format::V1, false),
                        halt(SyncNotice::OldKeyDamaged),
                    ),
                    (
                        "older, v1, fails",
                        copy(&older, keyed(&id, &older, lower, 0), Format::V1, true),
                        halt(SyncNotice::OldKeyDamaged),
                    ),
                    (
                        "ID key, v2, fails",
                        copy(&id_key, Header::Legacy, Format::V2, true),
                        halt(SyncNotice::OldKeyDamaged),
                    ),
                    (
                        "ID key, v1",
                        copy(&id_key, Header::Legacy, Format::V1, false),
                        halt(SyncNotice::OldKeyDamaged),
                    ),
                ]);
            } else {
                // A 0.8 session at a GOYOVA04 of a key change: no repair
                // and no newer-format stop, a halt (§14.6-10).
                cases.push((
                    "unknown key ID, epoch 1",
                    copy(&random, unknown(1, 0), Format::V2, true),
                    halt(SyncNotice::KeyChanged { hardware: false }),
                ));
            }
            for (n, (what, blob, want)) in cases.into_iter().enumerate() {
                let version = 10 + n as u64;
                let case = format!("kf2={kf2} {what}");
                fs::write(a.vault(), &vault).unwrap();
                a.incoming(version, &blob);
                let mut s = a.unlock_with(password);
                let notice = s.take_unlock_notice();
                let l = link(&s);
                match &want {
                    Want::Merge => {
                        assert_eq!(titles(&s), ["mine=secret", "theirs=x"], "{case}");
                        assert_eq!(l.merged_version, version, "{case}");
                        assert!(halt_of(&s).is_none(), "{case}");
                        assert_eq!(a.outgoing().unwrap().0, version, "{case}");
                    }
                    Want::Repair => {
                        assert_eq!(notice, Some(SyncNotice::BadIncoming), "{case}");
                        assert_eq!(s.entries.len(), mine.len(), "{case}");
                        assert_eq!(l.merged_version, version, "{case}");
                        let (base, up) = a.outgoing().unwrap();
                        assert_eq!(base, version, "{case}");
                        assert_eq!(state_of(&open(&s, &up)), local(&s), "{case}");
                    }
                    Want::PushOver => {
                        assert_eq!(notice, Some(SyncNotice::OldKeyReplaced), "{case}");
                        assert_eq!(s.entries.len(), mine.len(), "{case}");
                        assert_eq!(s.generation, gen0.max(7) + 1, "{case}");
                        let (base, up) = a.outgoing().unwrap();
                        assert_eq!(base, version, "{case}");
                        let up = open(&s, &up);
                        assert_eq!(state_of(&up), local(&s), "{case}");
                        assert_eq!(up.generation, s.generation, "{case}");
                        assert_eq!(saved(&s).generation, s.generation, "{case}");
                    }
                    Want::Halt(n) => {
                        assert_eq!(notice.as_ref(), Some(n), "{case}");
                        assert_eq!(l.merged_version, 0, "{case}");
                        assert!(halt_of(&s).is_some() && !l.verified, "{case}");
                        assert_eq!(s.badge(), Some(SyncBadge::Warning), "{case}");
                    }
                    Want::Ignored(n) => {
                        assert_eq!(notice.as_ref(), Some(n), "{case}");
                        assert_eq!(l.merged_version, 0, "{case}");
                        assert!(halt_of(&s).is_none(), "{case}");
                    }
                }
                // Nothing of a halt is written anywhere (I-S4).
                if matches!(want, Want::Halt(_) | Want::Ignored(_)) {
                    assert_eq!(s.entries.len(), mine.len(), "{case}");
                    assert!(a.outgoing().is_none(), "{case}");
                    assert_eq!(fs::read(a.vault()).unwrap(), vault, "{case}");
                }
                // A halt, or a newer format, keeps an edit on this PC: it
                // is saved, and nothing goes up.
                if matches!(want, Want::Halt(_) | Want::Ignored(SyncNotice::NewerFormat)) {
                    s.put(None, entry("edit", "y")).unwrap();
                    for _ in 0..50 {
                        let _ = s.poll_sync();
                    }
                    assert!(a.outgoing().is_none(), "{case}");
                    assert_eq!(saved(&s).entries.len(), mine.len() + 1, "{case}");
                    assert_eq!(s.max_epoch(), own.epoch, "{case}");
                }
                // A copy at a lower epoch is answered, so its PC learns it
                // is behind, and is no "Synced" (§14.6-13, -15).
                if what == "current, lower epoch" {
                    assert!(!link(&s).verified, "{case}");
                    assert_ne!(s.badge(), Some(SyncBadge::Synced), "{case}");
                }
                drop(s);
                let _ = fs::remove_file(a.dir().join(OUTGOING));
            }
            // The same contents at a lower epoch: still answered, counted
            // above the copy it replaces.
            if kf2 {
                fs::write(a.vault(), &vault).unwrap();
                let lower = state(own.epoch - 1, [4; 16]);
                let blob = copy_of(
                    &id,
                    &current,
                    keyed(&id, &current, lower, 0),
                    Format::V2,
                    &mine,
                    &[],
                    gen0,
                    false,
                );
                a.incoming(40, &blob);
                let s = a.unlock_with(password);
                let (base, up) = a.outgoing().unwrap();
                assert_eq!(base, 40);
                assert_eq!(open(&s, &up).generation, gen0 + 1);
                assert_eq!(saved(&s).generation, gen0 + 1);
                assert!(!link(&s).verified);
            }
        }
    }
    fn state_of(c: &Contents) -> Sets {
        state(c)
    }

    /// Walkthrough §7.7-1 and §14.6-4 and -12. A changes the password and
    /// uploads under its new key, though the contents did not change. B's
    /// upload made before that never lands (I-S5); B halts, and none of its
    /// edits goes up across many polls while each is saved on B. B takes A's
    /// key file by USB as a successor, merges and uploads, and A merges B's
    /// edits. The content part of the check code stays through the change;
    /// the whole codes, and the key codes, agree once both PCs hold the same
    /// key file.
    #[test]
    fn a_password_change_halts_the_other_pc_until_it_adopts() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        let before = content(&sa);
        assert_eq!(sa.check_code(), before);
        sb.put(None, entry("from B", "early")).unwrap();
        assert_eq!(b.outgoing().unwrap().0, 1);
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        assert_eq!(content(&sa), before);
        assert_ne!(sa.check_code(), before);
        // Uploaded again under the new key, from the version it holds.
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!((base, &blob[..8]), (1, &b"GOYOVA04"[..]));
        server.pass(&a);
        assert_eq!(server.head(), 2);
        let _ = sa.poll_sync();
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert!(a.outgoing().is_none());

        // B's upload from version 1 loses; B halts on A's copy.
        server.pass(&b);
        assert_eq!(server.head(), 2);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
        assert_eq!(sb.badge(), Some(SyncBadge::Warning));
        assert_eq!(titles(&sb).len(), 3);
        assert_eq!(sb.password_change(), Ok(Some(Gate::KeyHalt)));
        for i in 0..3 {
            sb.put(None, entry(&format!("from B {i}"), "x")).unwrap();
        }
        let old = b.outgoing();
        for _ in 0..50 {
            server.pass(&b);
            let ev = sb.poll_sync();
            assert!(ev.is_none_or(|e| e.notice.is_none()));
        }
        assert_eq!(b.outgoing(), old);
        assert_eq!(server.head(), 2);
        assert_eq!(saved(&sb).entries.len(), 6);

        // B takes A's key file: a successor, chained under B's key.
        let usb = a.key_to(&b);
        let adopted = adopt(&mut sb, PASS, &usb, NEW);
        assert_eq!(adopted.state, sa.key_state());
        assert_eq!(adopted.code, code_of(&sa));
        assert!(halt_of(&sb).is_none());
        rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 3);
        assert_eq!(server.head(), 3);
        assert_eq!(titles(&sa), titles(&sb));
        assert_eq!(sa.entries.len(), 6);
        assert_eq!(sa.check_code(), sb.check_code());
        assert_eq!(content(&sa), content(&sb));
        assert_eq!(code_of(&sa), code_of(&sb));
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        assert_eq!(sb.badge(), Some(SyncBadge::Synced));
        // Every copy on the server is the vault's, and B's copy of the old
        // key never landed.
        for v in &server.versions[1..] {
            assert_eq!(&v[..8], b"GOYOVA04");
        }
        // Nothing about the halt was kept: a new unlock is synced.
        drop(sb);
        let sb = b.unlock_with(NEW);
        assert!(halt_of(&sb).is_none());
    }

    /// KeyChanged is told once per halt, not once per session (spec §2.18
    /// #56): B takes A's new key file, which lifts its halt, and when A
    /// changes the password again, B's next poll halts and says so again.
    #[test]
    fn a_second_key_change_is_told_again() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        for (from, to) in [(PASS, NEW), (NEW, OTHER)] {
            assert_eq!(change(&mut sa, from, to), Rekeyed::Done);
            server.pass(&a);
            let _ = sa.poll_sync();
            server.pass(&b);
            let ev = sb.poll_sync().unwrap();
            assert_eq!(
                ev.notice,
                Some(SyncNotice::KeyChanged { hardware: false }),
                "{to}"
            );
            assert!(halt_of(&sb).is_some());
            let usb = a.key_to(&b);
            adopt(&mut sb, from, &usb, to);
            assert!(halt_of(&sb).is_none());
            rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 3);
            assert_eq!(sb.badge(), Some(SyncBadge::Synced), "{to}");
        }
    }

    /// The first unlock after this PC's own password change, before the
    /// helper took its upload: the server's head is this PC's copy from
    /// before the change, under the older key. It is pushed over with no
    /// word, as it holds nothing this PC lacks; OldKeyReplaced is for a
    /// copy that does (spec §2.18 #59).
    #[test]
    fn this_pcs_own_older_key_copy_is_replaced_without_a_word() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, _b, _sb) = pair(&t, &mut server, 2);
        // An entry deleted after the merge is no news either.
        sa.delete(find(&sa, "entry 0")).unwrap();
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        drop(sa);
        assert_eq!(server.head(), 1);
        let mut sa = a.unlock_with(NEW);
        assert_eq!(sa.take_unlock_notice(), None);
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(base, 1);
        assert_eq!(state(&open(&sa, &blob)), local(&sa));
        server.pass(&a);
        assert_eq!(server.head(), 2);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, synced(&sa));
    }

    /// A halt belongs to the server copy that caused it (spec v3 §7.2): when
    /// the newest copy names no key (here a damaged one) or the sync folder
    /// is reset, nothing is left to override, and after a reset this PC's
    /// state goes up again (spec §2.18 #61).
    #[test]
    fn a_halt_ends_with_its_head() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        server.pass(&a);
        server.pass(&b);
        let _ = sb.poll_sync();
        assert!(sb.halted_head().is_some());
        let incoming = b.dir().join(INCOMING);
        let halting = fs::read(&incoming).unwrap();
        // A damaged head: a GOYOVA04 header outside the grammar.
        let current = *sb.keys.current();
        let state = KeyState {
            epoch: 1,
            tag: sb.key_state.tag,
        };
        let header = keyed(&sb.id, &current, state, 0);
        let mut damaged = copy_of(&sb.id, &current, header, Format::V2, &[], &[], 9, false);
        damaged[65] = 1;
        b.incoming(3, &damaged);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::BadIncoming));
        assert!(sb.halted_head().is_none() && sb.sync_halt().is_none());
        assert!(b.outgoing().is_none());
        // The halting head again, then a reset folder.
        fs::write(&incoming, &halting).unwrap();
        let _ = sb.poll_sync();
        assert!(sb.halted_head().is_some());
        fs::remove_file(&incoming).unwrap();
        let _ = sb.poll_sync();
        assert!(sb.halted_head().is_some());
        let _ = sb.poll_sync();
        assert!(sb.halted_head().is_none());
        assert_eq!(b.outgoing().unwrap().0, 1);
    }

    /// Walkthrough §7.7-2: A writes its new key file onto the stick both PCs
    /// use. B opens with it; its vault file is under the old key and is not
    /// the one the change replaced, so only the user's yes (S-OLDER) opens
    /// it, and then it merges A's copy and uploads B's edit.
    #[test]
    fn a_shared_key_file_opens_the_other_pcs_vault_after_a_yes() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        sb.put(None, entry("from B", "offline")).unwrap();
        let _ = fs::remove_file(b.dir().join(OUTGOING));
        drop(sb);
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        server.pass(&a);
        fs::copy(a.key(), b.key()).unwrap();
        server.pass(&b);
        b.here();
        let prepared = prepare(&b.vault(), &b.key()).unwrap();
        let VaultClass::Older { sha } = prepared.check().vault else {
            panic!("not an older vault file: {:?}", prepared.check());
        };
        let now = otp::now().unwrap();
        let mut sb = Session::login(prepared, NEW, "", now, Some(sha)).unwrap();
        assert!(sb.take_key_notices().contains(&KeyNotice::OlderAccepted));
        assert_eq!(titles(&sb).len(), 3);
        rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 2);
        assert_eq!(titles(&sa), titles(&sb));
        assert_eq!(sa.check_code(), sb.check_code());
        assert!(titles(&sa).contains(&"from B=offline".to_owned()));
    }

    /// Walkthrough §7.7-3 and §14.6-5: B's upload under the old key lands
    /// before A's under its new one. A pushes over that copy without merging
    /// it, so nothing of it reaches A; B halts, takes A's key file, and its
    /// edit comes back from B's vault.
    #[test]
    fn a_race_pushes_the_older_key_copy_over_unmerged() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        let victim = sb.entry_id(0).unwrap();
        sb.delete(0).unwrap();
        sb.put(None, entry("from B", "raced")).unwrap();
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        let (before, seen) = (local(&sa), sa.seen);
        server.pass(&b);
        assert_eq!(server.head(), 2);
        let pushed = server.versions[1].clone();
        let theirs = open_with(&sa.id, sa.keys.id_key(), &pushed);
        server.pass(&a);
        assert_eq!(server.head(), 2);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::OldKeyReplaced));
        assert!(!ev.list_changed);
        // No entry and no tombstone of it reached A.
        assert_eq!(local(&sa), before);
        assert!(!sa.tombstones.contains(&victim));
        assert_eq!(sa.seen, seen);
        assert!(sa.generation > theirs.generation);
        let (base, up) = a.outgoing().unwrap();
        assert_eq!(base, 2);
        assert_eq!(open(&sa, &up).generation, sa.generation);
        server.pass(&a);
        assert_eq!(server.head(), 3);
        server.pass(&b);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
        let usb = a.key_to(&b);
        adopt(&mut sb, PASS, &usb, NEW);
        rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 3);
        assert_eq!(titles(&sa), titles(&sb));
        assert!(titles(&sa).contains(&"from B=raced".to_owned()));
        assert!(sa.tombstones.contains(&victim));
        assert_eq!(sa.check_code(), sb.check_code());
        // The pushed-over copy stays in the server's history.
        assert_eq!(server.versions[1], pushed);
    }

    /// Walkthrough §7.7-4 and §14.6-24, with three PCs: A and B change the
    /// password from the same state. B halts on A's copy (KeyFork), and no
    /// PC uploads across 50 polls. B takes A's key file: a fork, joined in a
    /// union under a fresh key with the ID key last; A takes the union back
    /// as a successor, and so does C, which never changed its key file. No
    /// entry is duplicated, the content part of the check codes stays, and
    /// a backup made before either change still restores on every PC. With
    /// the same new password on both, no choice is asked and A's own
    /// password opens the union. Each PC kept its own anchor, and nothing
    /// went to the real one (§14.6 harness).
    #[test]
    fn a_fork_is_joined_by_two_adopts() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        for same in [false, true] {
            let t = Temp::new();
            let mut server = Server::default();
            let (a, mut sa, b, mut sb) = pair(&t, &mut server, 3);
            let (c, mut sc) = join(&t, &mut server, &fs::read(a.key()).unwrap(), "c");
            let k0 = *sa.keys.id_key();
            let before = (content(&sa), local(&sa));
            let backup = t.0.join("before.goyo");
            sa.backup(&backup).unwrap();
            let pb = if same { NEW } else { OTHER };
            assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
            assert_eq!(change(&mut sb, PASS, pb), Rekeyed::Done);
            let (dk_a, dk_b) = (*sa.keys.current(), *sb.keys.current());
            server.pass(&a);
            server.pass(&b);
            assert_eq!(server.head(), 2);
            let ev = sb.poll_sync().unwrap();
            assert_eq!(ev.notice, Some(SyncNotice::KeyFork));
            assert_eq!(sb.password_change(), Ok(Some(Gate::KeyFork)));
            let _ = sa.poll_sync();
            server.pass(&c);
            let ev = sc.poll_sync().unwrap();
            assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
            for _ in 0..50 {
                rounds(
                    &mut server,
                    &mut [(&a, &mut sa), (&b, &mut sb), (&c, &mut sc)],
                    1,
                );
            }
            assert_eq!(server.head(), 2);
            assert!(halt_of(&sb).is_some() && halt_of(&sc).is_some());

            // B joins A's file in a union under a fresh key.
            let usb = a.key_to(&b);
            let union = adopt(&mut sb, pb, &usb, NEW);
            assert_eq!(union.state.epoch, 2);
            assert_eq!(sb.keys.keys().len(), 4);
            assert_eq!(sb.keys.keys()[1..], [dk_b, dk_a, k0]);
            assert_eq!(*sb.keys.id_key(), k0);
            rounds(&mut server, &mut [(&b, &mut sb)], 2);
            assert_eq!(server.head(), 3);
            // A halts on the union's copy and takes the union back.
            server.pass(&a);
            let ev = sa.poll_sync().unwrap();
            assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
            let usb = b.key_to(&a);
            let taken = adopt(&mut sa, NEW, &usb, NEW);
            assert_eq!(taken.state, union.state);
            // C, still on the shared state's line, takes it as well.
            let usb = b.key_to(&c);
            adopt(&mut sc, PASS, &usb, NEW);
            rounds(
                &mut server,
                &mut [(&a, &mut sa), (&b, &mut sb), (&c, &mut sc)],
                3,
            );
            assert_eq!(server.head(), 3);
            for s in [&sa, &sb, &sc] {
                assert_eq!((content(s), local(s)), before);
                assert_eq!(s.check_code(), sb.check_code());
                assert_eq!(code_of(s), code_of(&sb));
                assert_eq!(s.badge(), Some(SyncBadge::Synced));
                assert_eq!(*s.keys.id_key(), k0);
            }
            // A backup from before both changes restores with the union.
            for (pc, name) in [(&a, "ra.goyo"), (&b, "rb.goyo"), (&c, "rc.goyo")] {
                pc.here();
                let restored =
                    Session::restore(&backup, &pc.key(), &pc.0.join(name), NEW, "").unwrap();
                assert_eq!(local(&restored), before.1);
            }
            // Three anchors, one per PC; none in the real folder.
            assert!(!a.anchor().is_empty() && a.anchor() != b.anchor());
            assert!(!c.anchor().is_empty() && c.anchor() != b.anchor());
            let hex: String = sa.id.iter().map(|x| format!("{x:02x}")).collect();
            if let Some(base) = std::env::var_os("LOCALAPPDATA") {
                let real = PathBuf::from(base)
                    .join("GoyoVault")
                    .join("goyo-vault.keys");
                let text = fs::read(real).unwrap_or_default();
                assert!(!String::from_utf8_lossy(&text).contains(&hex));
            }
        }
        // With no folder set, a debug build keeps its own default.
        let set = set_anchor_dir(None);
        if std::env::var_os("LOCALAPPDATA").is_some() {
            let dir = anchor::locate().unwrap();
            assert_eq!(dir.file_name().unwrap(), "GoyoVault-debug");
        }
        set_anchor_dir(set);
    }

    /// Walkthrough §7.7-6 and §14.6-6, -9 and -18. Someone with an old key
    /// copy uploads a copy under it that deletes every entry, with counters
    /// as large as they get. It is pushed over and never merged, and A's
    /// count moves at most GEN_WINDOW + 1 (I-S10): A stays editable, and B,
    /// up to date, merges A's heads with no TooLarge and no Rollback. Garbage
    /// under the old key's ID halts only, until the head override pushes
    /// over it.
    #[test]
    fn old_key_copies_are_pushed_over_or_halt() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 3);
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        server.pass(&a);
        let _ = sa.poll_sync();
        server.pass(&b);
        let _ = sb.poll_sync();
        let usb = a.key_to(&b);
        adopt(&mut sb, PASS, &usb, NEW);
        rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 2);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        let (id, k0) = (sa.id, *sa.keys.id_key());
        let k0_header = keyed(
            &id,
            &k0,
            KeyState {
                epoch: 1,
                tag: [7; 16],
            },
            0,
        );
        let dead: Vec<EntryId> = sa.entries.iter().map(Entry::id).collect();
        let kept = titles(&sa);
        for n in 0..4 {
            let own = sa.generation;
            let theirs = [
                u64::MAX,
                u64::MAX - 1,
                own + GEN_WINDOW + 1,
                own + GEN_WINDOW,
            ][n];
            let header = if n % 2 == 0 {
                k0_header
            } else {
                Header::Legacy
            };
            let forged = copy_of(&id, &k0, header, Format::V2, &[], &dead, theirs, false);
            server.versions.push(forged);
            let seen = sa.seen;
            server.pass(&a);
            let ev = sa.poll_sync().unwrap();
            assert_eq!(ev.notice, Some(SyncNotice::OldKeyReplaced), "{n}");
            assert_eq!(titles(&sa), kept, "{n}");
            let want = if n == 3 {
                own + GEN_WINDOW + 1
            } else {
                own + 1
            };
            assert_eq!((sa.generation, sa.seen), (want, seen), "{n}");
            server.pass(&a);
            let ev = sb.poll_sync();
            server.pass(&b);
            let ev = ev.into_iter().chain(sb.poll_sync()).collect::<Vec<_>>();
            for e in ev {
                assert!(
                    !matches!(e.notice, Some(SyncNotice::TooLarge | SyncNotice::Rollback)),
                    "{n}: {e:?}"
                );
            }
            assert_eq!(titles(&sb), kept, "{n}");
            assert_eq!(sb.generation, sa.generation, "{n}");
        }
        // Still editable.
        sa.put(None, entry("after", "forgery")).unwrap();
        sa.delete(find(&sa, "after")).unwrap();
        rounds(&mut server, &mut [(&a, &mut sa), (&b, &mut sb)], 2);
        assert_eq!(sa.check_code(), sb.check_code());

        // Garbage under the old key's ID: a halt only, until overridden.
        let mut garbage = copy_of(&id, &k0, k0_header, Format::V2, &[], &[], 1, false);
        let end = garbage.len() - 1;
        garbage[end] ^= 1;
        server.versions.push(garbage);
        let version = server.head();
        server.pass(&a);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::OldKeyDamaged));
        sa.put(None, entry("held", "back")).unwrap();
        for _ in 0..5 {
            server.pass(&a);
            let _ = sa.poll_sync();
        }
        assert_eq!(server.head(), version);
        let head = sa.head_to_override().unwrap();
        assert_eq!((head.version, head.epoch), (version, 1));
        assert_eq!(head.key_prefix().len(), 8);
        let r = sa.reauth(NEW, None, None).unwrap();
        sa.override_head(r, &head).unwrap();
        assert_eq!(a.outgoing().unwrap().0, version);
        rounds(&mut server, &mut [(&a, &mut sa), (&b, &mut sb)], 2);
        assert_eq!(server.head(), version + 1);
        assert_eq!(titles(&sb), titles(&sa));
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
    }

    /// Walkthrough §7.7-7 and §14.6-14: a key change of a synced vault cut
    /// off anywhere. The next unlock completes it or drops it, and then the
    /// server copy under the old key is pushed over or merged. The server
    /// never holds content the vault file lacks.
    #[test]
    fn an_interrupted_rotation_uploads_nothing_the_vault_file_lacks() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        for point in ["S1.done", "S2v", "S3.renamed", "S3v", "S4", "S5"] {
            let t = Temp::new();
            let mut server = Server::default();
            let (a, mut sa, _b, _sb) = pair(&t, &mut server, 2);
            sa.put(None, entry("late", "edit")).unwrap();
            let _ = fs::remove_file(a.dir().join(OUTGOING));
            let r = sa.reauth(PASS, None, None).unwrap();
            crate::vault::CRASH.with(|c| c.set(Some(point)));
            let to = Change::Password(Zeroizing::new(NEW.to_owned()));
            let result = sa.rekey(r, Vec::new(), to, Consent::default(), true);
            assert_eq!(result, Err(SIMULATED_CRASH), "{point}");
            drop(sa);
            let landed = point != "S1.done";
            let mut sa = a.unlock_with(if landed { NEW } else { PASS });
            let lacks = |sa: &Session, server: &Server| {
                let file = saved(sa);
                server.versions.iter().any(|v| {
                    let c = sa.keys.keys().iter().find_map(|k| {
                        decode_data(&sa.id, k, sa.keys.id_key(), v)
                            .ok()
                            .map(|c| c.2)
                    });
                    c.is_some_and(|c| {
                        c.entries
                            .iter()
                            .any(|e| !file.entries.iter().any(|f| f.id == e.id))
                    })
                })
            };
            for _ in 0..3 {
                assert!(!lacks(&sa, &server), "{point}");
                server.pass(&a);
                let _ = sa.poll_sync();
            }
            assert!(!lacks(&sa, &server), "{point}");
            let head = server.versions.last().unwrap();
            assert_eq!(state(&open(&sa, head)), local(&sa), "{point}");
            assert_eq!(sa.badge(), Some(SyncBadge::Synced), "{point}");
            let magic: &[u8] = if landed { b"GOYOVA04" } else { b"GOYOVA02" };
            assert_eq!(&head[..8], magic, "{point}");
        }
    }

    /// Walkthrough §7.7-11 and §14.6-16: A changes the password, uploads and
    /// is gone. B and C halt. On B the head override, after a Reauth, pushes
    /// B's state over exactly that head, which stays in the server history;
    /// C then merges B's copy. A head that changed after the question is not
    /// pushed, nothing is kept for a later unlock or another version, and a
    /// forged head with a random key ID is cleared the same way. When A
    /// comes back, it pushes over B's copy as an older-key one, B halts, and
    /// takes A's key file: nothing is lost.
    #[test]
    fn the_pc_that_changed_the_keys_is_gone() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        let (c, mut sc) = join(&t, &mut server, &fs::read(a.key()).unwrap(), "c");
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        sa.put(None, entry("from A", "lost?")).unwrap();
        server.pass(&a);
        assert_eq!(server.head(), 2);
        drop(sa);
        for (pc, s) in [(&b, &mut sb), (&c, &mut sc)] {
            server.pass(pc);
            let ev = s.poll_sync().unwrap();
            assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
            assert_eq!(s.halted_head().unwrap().version, 2);
        }
        sb.put(None, entry("from B", "kept")).unwrap();
        let head = sb.head_to_override().unwrap();
        assert_eq!((head.version, head.epoch), (2, 1));
        // A Reauth of another session does not do.
        let other = sc.reauth(PASS, None, None).unwrap();
        assert!(sb.override_head(other, &head).is_err());
        assert!(b.outgoing().is_none());
        // A forged head lands meanwhile: the named one is not pushed over.
        let id = sb.id;
        let random = [0x6d; 32];
        let forged_header = keyed(
            &id,
            &random,
            KeyState {
                epoch: 9,
                tag: [1; 16],
            },
            0,
        );
        let forged = copy_of(&id, &random, forged_header, Format::V2, &[], &[], 3, false);
        server.versions.push(forged.clone());
        server.pass(&b);
        let r = sb.reauth(PASS, None, None).unwrap();
        assert!(sb.override_head(r, &head).is_err());
        assert!(b.outgoing().is_none());
        // The forged one halts too, told no second time, and is cleared.
        assert_eq!(sb.poll_sync().and_then(|e| e.notice), None);
        let head = sb.head_to_override().unwrap();
        assert_eq!((head.version, head.epoch), (3, 9));
        let r = sb.reauth(PASS, None, None).unwrap();
        sb.override_head(r, &head).unwrap();
        assert_eq!(b.outgoing().unwrap().0, 3);
        assert!(sb.halted_head().is_none());
        server.pass(&b);
        assert_eq!(server.head(), 4);
        assert_eq!(server.versions[2], forged);
        // C merges B's copy: under its own key, at its state.
        server.pass(&c);
        let _ = sc.poll_sync();
        assert!(halt_of(&sc).is_none());
        assert_eq!(titles(&sc), titles(&sb));
        assert_eq!(sc.badge(), Some(SyncBadge::Synced));
        let _ = sb.poll_sync();
        assert_eq!(sb.badge(), Some(SyncBadge::Synced));

        // An override never applies to another version.
        let other_forged = copy_of(&id, &random, forged_header, Format::V2, &[], &[], 4, false);
        server.versions.push(other_forged.clone());
        server.pass(&b);
        let _ = sb.poll_sync();
        assert_eq!(sb.halted_head().unwrap().version, 5);
        assert!(b.outgoing().is_none());
        // Nor to another copy under the overridden number: a server reset
        // and seeded again numbers its copies anew.
        let renumbered = copy_of(&id, &random, forged_header, Format::V2, &[], &[], 5, false);
        b.incoming(3, &renumbered);
        let _ = sb.poll_sync();
        assert_eq!(sb.halted_head().unwrap().version, 3);
        assert!(b.outgoing().is_none());
        // Nothing is kept: a new unlock with the overridden head halts.
        drop(sb);
        b.incoming(3, &forged);
        let mut sb = b.unlock();
        assert_eq!(
            sb.take_unlock_notice(),
            Some(SyncNotice::KeyChanged { hardware: false })
        );
        assert_eq!(sb.halted_head().unwrap().version, 3);
        drop(sb);
        server.versions.pop();
        b.incoming(4, server.versions.last().unwrap());

        // A comes back: B's copy is under an older key there.
        let mut sa = a.unlock_with(NEW);
        server.pass(&a);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::OldKeyReplaced));
        server.pass(&a);
        assert_eq!(server.head(), 5);
        let mut sb = b.unlock();
        server.pass(&b);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
        let usb = a.key_to(&b);
        adopt(&mut sb, PASS, &usb, NEW);
        rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 3);
        assert_eq!(titles(&sa), titles(&sb));
        for kept in ["from A=lost?", "from B=kept"] {
            assert!(titles(&sa).contains(&kept.to_owned()), "{kept}");
        }
    }

    /// Spec v3 §7.5 and §14.6-11: a key change on a halted, forked or
    /// unverified vault asks first, the strongest question first. Going on
    /// over a halt makes a fork that two adopts join.
    #[test]
    fn key_changes_ask_while_a_server_copy_halts() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        assert_eq!(sb.password_change(), Ok(None));
        // Not verified, or no helper: the Unverified question.
        sb.put(None, entry("unsent", "x")).unwrap();
        assert_eq!(sb.password_change(), Ok(Some(Gate::Unverified)));
        server.pass(&b);
        let _ = sb.poll_sync();
        assert_eq!(sb.password_change(), Ok(None));
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        // A's upload loses to B's; A pushes over B's copy under the old key.
        server.pass(&a);
        let ev = sa.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::OldKeyReplaced));
        server.pass(&a);
        assert_eq!(server.head(), 3);
        server.pass(&b);
        let _ = sb.poll_sync();
        let change_b = Change::Password(Zeroizing::new(OTHER.to_owned()));
        assert_eq!(sb.rekey_gate(&change_b), Some(Gate::KeyHalt));
        // Asked and refused: nothing written.
        let key = fs::read(b.key()).unwrap();
        let r = sb.reauth(PASS, None, None).unwrap();
        let refused = sb.rekey(r, Vec::new(), change_b, Consent::default(), false);
        assert_eq!(refused, Err(Gate::KeyHalt.question()));
        assert_eq!(fs::read(b.key()).unwrap(), key);
        // Answered yes: B changes its key anyway, and is now on a fork.
        assert_eq!(change(&mut sb, PASS, OTHER), Rekeyed::Done);
        assert!(halt_of(&sb).is_none());
        server.pass(&b);
        assert_eq!(server.head(), 3);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::KeyFork));
        assert_eq!(sb.password_change(), Ok(Some(Gate::KeyFork)));
        let usb = a.key_to(&b);
        adopt(&mut sb, OTHER, &usb, NEW);
        rounds(&mut server, &mut [(&b, &mut sb)], 2);
        server.pass(&a);
        let _ = sa.poll_sync();
        let usb = b.key_to(&a);
        adopt(&mut sa, NEW, &usb, NEW);
        rounds(&mut server, &mut [(&a, &mut sa), (&b, &mut sb)], 3);
        assert_eq!(sa.check_code(), sb.check_code());
        assert!(titles(&sa).contains(&"unsent=x".to_owned()));
    }

    /// Spec v3 §7.1 and §14.6-7, -8 (I-S6): under the current key, a later
    /// key-file state halts and a forked one at the same epoch halts. Neither
    /// is merged nor pushed over across 50 polls, and `max_epoch` never
    /// rises from a server copy. A copy at this state merges again, which
    /// lifts the halt by itself.
    #[test]
    fn a_newer_or_forked_state_under_the_current_key_halts() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        server.pass(&a);
        server.pass(&b);
        let _ = sb.poll_sync();
        let usb = a.key_to(&b);
        adopt(&mut sb, PASS, &usb, NEW);
        rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 2);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        let (id, dk, own) = (sa.id, *sa.keys.current(), sa.key_state());
        let mut extra = entry("planted", "x");
        extra.set_ids([8; 16], NO_ID);
        for (state, notice) in [
            (
                KeyState {
                    epoch: own.epoch + 1,
                    tag: own.tag,
                },
                SyncNotice::NewerKeyFile,
            ),
            (
                KeyState {
                    epoch: own.epoch,
                    tag: [5; 16],
                },
                SyncNotice::KeyFork,
            ),
        ] {
            let mut entries = sa.entries.clone();
            entries.push(extra.clone());
            let blob = copy_of(
                &id,
                &dk,
                keyed(&id, &dk, state, 0),
                Format::V2,
                &entries,
                &[],
                sa.generation + 1,
                false,
            );
            server.versions.push(blob);
            let version = server.head();
            server.pass(&a);
            let ev = sa.poll_sync().unwrap();
            assert_eq!(ev.notice, Some(notice.clone()));
            for _ in 0..50 {
                server.pass(&a);
                let _ = sa.poll_sync();
            }
            assert_eq!(server.head(), version);
            assert!(!titles(&sa).contains(&"planted=x".to_owned()));
            assert_eq!((sa.max_epoch(), sa.key_state()), (own.epoch, own));
            assert_eq!(sa.badge(), Some(SyncBadge::Warning));
            // A copy at this state lands over it: the halt lifts.
            let mut lifts = entry(&format!("{notice:?}"), "lifts");
            lifts.set_ids([state.tag[0].wrapping_add(16); 16], NO_ID);
            let mut entries = sa.entries.clone();
            entries.push(lifts);
            let blob = copy_of(
                &id,
                &dk,
                keyed(&id, &dk, own, 0),
                Format::V2,
                &entries,
                &sa.tombstones,
                sa.generation + 2,
                false,
            );
            server.versions.push(blob);
            server.pass(&a);
            let ev = sa.poll_sync().unwrap();
            assert!(matches!(
                ev.notice,
                Some(SyncNotice::Merged { added: 1, .. })
            ));
            assert!(halt_of(&sa).is_none());
            assert!(!titles(&sa).contains(&"planted=x".to_owned()));
            assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        }
        drop(sb);
    }

    /// Walkthrough §7.7-8: the server script is older than 0.9.0. A keeps
    /// working locally; once the script is updated, A's copy lands and B
    /// halts until it takes A's key file.
    #[test]
    fn an_old_server_script_holds_the_upload() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 1);
        assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
        // The head this PC merged before its change: pushed over silently.
        assert_eq!(sa.poll_sync().and_then(|e| e.notice), None);
        assert_eq!(a.outgoing().unwrap().0, 1);
        a.status(SyncState::OldServer);
        let ev = status_poll(&mut sa).unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::OldServer));
        assert_eq!(sa.badge(), Some(SyncBadge::Warning));
        sa.put(None, entry("local", "only")).unwrap();
        assert_eq!(saved(&sa).entries.len(), 2);
        a.status(SyncState::Ok);
        server.pass(&a);
        assert_eq!(server.head(), 2);
        server.pass(&b);
        let ev = sb.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
        let usb = a.key_to(&b);
        adopt(&mut sb, PASS, &usb, NEW);
        rounds(&mut server, &mut [(&b, &mut sb), (&a, &mut sa)], 2);
        assert_eq!(titles(&sa), titles(&sb));
    }

    /// §14.6-17 and -22 (S23-1 #4, S23-2 #5, S23-3 #5): K1 and V1 from before
    /// this PC's second key change are put back. The server copy, this PC's
    /// own under the newer key, is neither merged nor pushed over and asks
    /// for no key file: RollbackHeld, once, and never KeyChanged. The head
    /// override is not offered, and its P1 and P3 refuse; nothing goes up
    /// across 50 polls. A copy under K1's key at K1's state is not merged,
    /// not even one already in incoming at the unlock, which does not read
    /// it. After [이 열쇠 파일이 맞습니다] the link is rebuilt and the head
    /// halts as usual, with the override offered; after an adopt of the
    /// newer key file instead, that copy is pushed over unmerged.
    #[test]
    fn a_local_rollback_holds_every_server_copy() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        for confirm in [true, false] {
            let t = Temp::new();
            let mut server = Server::default();
            let (a, mut sa, _b, _sb) = pair(&t, &mut server, 2);
            assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
            server.pass(&a);
            let _ = sa.poll_sync();
            let (k1, v1) = (fs::read(a.key()).unwrap(), fs::read(a.vault()).unwrap());
            let (id, dk1, state1) = (sa.id, *sa.keys.current(), sa.key_state());
            let generation = sa.generation;
            assert_eq!(change(&mut sa, NEW, OTHER), Rekeyed::Done);
            server.pass(&a);
            let _ = sa.poll_sync();
            assert_eq!(server.head(), 3);
            let k2 = t.0.join("k2.goyokey");
            fs::copy(a.key(), &k2).unwrap();
            drop(sa);
            fs::write(a.key(), &k1).unwrap();
            fs::write(a.vault(), &v1).unwrap();
            // Planted by whoever put the pair back: deletes every entry.
            let dead: Vec<EntryId> = open_with(&id, &dk1, &v1)
                .entries
                .iter()
                .map(Entry::id)
                .collect();
            let mut planted = entry("planted", "x");
            planted.set_ids([8; 16], NO_ID);
            let blob = copy_of(
                &id,
                &dk1,
                keyed(&id, &dk1, state1, 0),
                Format::V2,
                std::slice::from_ref(&planted),
                &dead,
                generation + 5,
                false,
            );
            a.incoming(9, &blob);
            let mut sa = a.unlock_with(NEW);
            assert!(sa.local_rollback());
            assert!(
                sa.take_key_notices()
                    .contains(&KeyNotice::LocalRollback { old: 2, new: 1 })
            );
            assert_eq!(sa.take_unlock_notice(), None);
            assert_eq!(fs::read(a.vault()).unwrap(), v1);
            assert!(a.copies().is_empty());
            let ev = sa.poll_sync().unwrap();
            assert_eq!(ev.notice, Some(SyncNotice::RollbackHeld));
            assert_eq!(sa.badge(), Some(SyncBadge::Warning));
            assert_eq!(titles(&sa).len(), 2);
            assert_eq!(fs::read(a.vault()).unwrap(), v1);
            // This PC's own newer head: held, told no second time.
            server.pass(&a);
            assert_eq!(sa.poll_sync().and_then(|e| e.notice), None);
            assert!(sa.halted_head().is_none());
            let refused = sa.head_to_override().unwrap_err();
            assert_eq!(refused, LOCAL_ROLLBACK);
            let blob3 = server.versions[2].clone();
            let head = HaltedHead {
                version: 3,
                epoch: 2,
                key_id: [0; 16],
                sha: sha256(&blob3),
            };
            let r = sa.reauth(NEW, None, None).unwrap();
            assert_eq!(sa.override_head(r, &head), Err(LOCAL_ROLLBACK));
            sa.put(None, entry("local", "edit")).unwrap();
            for _ in 0..50 {
                server.pass(&a);
                let _ = sa.poll_sync();
            }
            assert!(a.outgoing().is_none());
            assert_eq!(server.head(), 3);
            assert!(a.copies().is_empty());
            if confirm {
                let r = sa.reauth(NEW, None, None).unwrap();
                sa.confirm_key_file(r).unwrap();
                server.pass(&a);
                let ev = sa.poll_sync().unwrap();
                assert_eq!(ev.notice, Some(SyncNotice::KeyChanged { hardware: false }));
                let head = sa.halted_head().unwrap();
                assert_eq!((head.version, head.epoch), (3, 2));
            } else {
                // The newer key file from a key backup: a successor.
                a.incoming(9, &blob);
                adopt(&mut sa, NEW, &k2, OTHER);
                assert!(!sa.local_rollback());
                let ev = sa.poll_sync().unwrap();
                assert_eq!(ev.notice, Some(SyncNotice::OldKeyReplaced));
                rounds(&mut server, &mut [(&a, &mut sa)], 3);
                for v in &server.versions {
                    for k in sa.keys.keys() {
                        if let Ok((_, _, c)) = decode_data(&id, k, sa.keys.id_key(), v) {
                            assert!(!listed(&c.entries).contains(&"planted=x".to_owned()));
                        }
                    }
                }
                let head = open(&sa, server.versions.last().unwrap());
                assert!(!listed(&head.entries).contains(&"planted=x".to_owned()));
                assert_eq!(state(&head), local(&sa));
                assert!(titles(&sa).contains(&"local=edit".to_owned()));
            }
            assert!(!titles(&sa).contains(&"planted=x".to_owned()));
        }
    }
    fn open_with(id: &[u8; 16], dk: &[u8; 32], blob: &[u8]) -> Contents {
        decode_data(id, dk, dk, blob).unwrap().2
    }

    /// §14.6-21 (S23-1 #6, S23-2 #1), three PCs on the same key: C uploads a
    /// copy at generation 20 that B merges, while A's change is under way.
    /// A's upload loses, and A pushes over C's copy counting above it, so B
    /// merges A's head after taking its key file with no Rollback notice.
    /// Out of GEN_WINDOW, C's count does not count: A uploads at its own + 1
    /// with `seen` unchanged, and stays editable.
    #[test]
    fn a_push_over_counts_above_the_copy_it_replaces() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        for theirs in [20, u64::MAX - 1, u64::MAX] {
            let t = Temp::new();
            let mut server = Server::default();
            let (a, mut sa, b, mut sb) = pair(&t, &mut server, 2);
            let (c, sc) = join(&t, &mut server, &fs::read(a.key()).unwrap(), "c");
            assert_eq!(change(&mut sa, PASS, NEW), Rekeyed::Done);
            let (own, seen) = (sa.generation, sa.seen);
            assert!(own < 20);
            let data = DataRef {
                generation: theirs,
                ..sc.data()
            };
            let blob = sc.encode_as(Format::V2, data).unwrap();
            server.versions.push(blob);
            server.pass(&b);
            let _ = sb.poll_sync();
            assert_eq!(sb.seen, theirs);
            server.pass(&a);
            // C's copy holds nothing A lacks: replaced with no word (spec
            // §2.18 #59).
            assert_eq!(sa.poll_sync().and_then(|e| e.notice), None);
            let want = if theirs == 20 { 21 } else { own + 1 };
            assert_eq!((sa.generation, sa.seen), (want, seen));
            server.pass(&a);
            assert_eq!(open(&sa, server.versions.last().unwrap()).generation, want);
            server.pass(&b);
            let _ = sb.poll_sync();
            let usb = a.key_to(&b);
            adopt(&mut sb, PASS, &usb, NEW);
            let ev = sb.poll_sync();
            assert_eq!(titles(&sb), titles(&sa));
            if theirs == 20 {
                assert!(ev.is_none_or(|e| e.notice != Some(SyncNotice::Rollback)));
                assert!(!link(&sb).warned);
                assert_eq!(sb.seen, 21);
            }
            sa.put(None, entry("still", "editable")).unwrap();
            for _ in 0..3 {
                server.pass(&b);
                let _ = sb.poll_sync();
                server.pass(&a);
                let ev = sa.poll_sync();
                assert!(ev.is_none_or(|e| e.notice != Some(SyncNotice::Rollback)));
            }
            assert!(!link(&sa).warned);
            drop(sc);
            drop(c);
        }
    }
    /// Two PCs on one KF2 key file (one a later build wrote) sync as two on a
    /// 0.8 key file do, with GOYOVA04 copies under the current key that carry
    /// the key file's state: gate 1 offers them, the other PC merges them,
    /// and an unchanged state is not offered again (spec §4.4, §7.6, I-S3).
    #[test]
    fn kf2_sessions_sync_goyova04_copies() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, b) = (t.pc("a"), t.pc("b"));
        let (id, dk1, dk0) = ([0x53; 16], [0x91; 32], [0x90; 32]);
        let spec = Spec {
            vault_id: id,
            epoch: 2,
            kind: Kind::Password,
            next: 1,
            pw_id: [8; 16],
            loss: 0,
            tombstones: Vec::new(),
            resume: [0; 32],
        };
        let bundle = Bundle::new(&[dk1, dk0], None).unwrap();
        let (key, _) = seal(&spec, &bundle, PASS, Plan::PasswordOnly).unwrap();
        let header = Header::Keyed {
            key_id: key_id(&id, &dk1),
            state: parse(&key).unwrap().state(),
            flags: 0,
        };
        let d = DataRef {
            last: 0,
            generation: 0,
            seen: 0,
            entries: &[],
            tombstones: &[],
        };
        let vault = encode_data(&id, &dk1, &header, Format::V2, d).unwrap();
        for pc in [&a, &b] {
            fs::write(pc.key(), &key).unwrap();
            fs::write(pc.vault(), &vault).unwrap();
            pc.helper();
        }
        let mut sa = a.unlock();
        sa.put(None, entry("from a", "secret")).unwrap();
        let (base, blob) = a.outgoing().unwrap();
        assert_eq!(
            (base, read_header(&blob).unwrap()),
            (0, (Format::V2, header))
        );
        assert_eq!(&blob[..8], b"GOYOVA04");
        server.pass(&a);
        server.pass(&b);
        let mut sb = b.unlock();
        assert_eq!(titles(&sb), ["from a=secret"]);
        assert_eq!(link(&sb).merged_version, 1);
        sb.put(None, entry("from b", "x")).unwrap();
        server.pass(&b);
        server.pass(&a);
        sa.poll_sync();
        assert_eq!(titles(&sa), ["from a=secret", "from b=x"]);
        assert_eq!(titles(&sa), titles(&sb));
        assert_eq!(sa.check_code(), sb.check_code());
        // A merge that changed nothing here offers nothing new.
        let before = a.outgoing();
        server.pass(&a);
        sa.poll_sync();
        assert_eq!(a.outgoing(), before);
        for v in &server.versions {
            assert_eq!(read_header(v).unwrap(), (Format::V2, header));
        }
        assert_eq!(server.head(), 2);
    }
    /// A merge saved by a poll that hits the replace gap: the session writes
    /// the vault file no more, so the app locks and the next unlock takes
    /// the merge back from the temp file (spec §5.7).
    #[test]
    fn a_poll_whose_save_hits_the_gap_writes_no_more() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let mut server = Server::default();
        let (a, mut sa, b, mut sb) = pair(&t, &mut server, 1);
        sa.put(None, entry("from a", "secret")).unwrap();
        server.pass(&a);
        server.pass(&b);
        crate::vault::CRASH.with(|c| c.set(Some("gap")));
        sb.poll_sync();
        assert!(sb.gap_kept());
        assert!(!b.vault().exists());
        // Nothing reaches the vault file or the server from this session.
        assert_eq!(sb.put(None, entry("lost", "x")), Err(GAP_KEPT));
        sb.poll_sync();
        assert!(b.outgoing().is_none() && !b.vault().exists());
        drop(sb);
        let sb = b.unlock();
        assert_eq!(titles(&sb), titles(&sa));
    }
}
