//! Key-file sync, the app's side (spec v3 §7.8-§7.20 as §2.23 simplified
//! it; security-key build only): the key view `kview` that goyo-sync.exe
//! keeps in the sync folder, how this PC classifies the server's key file
//! in it (§7.14), the anchor's `ks` with its pending tests, pin, drop and
//! self-heal, the request table and gate 1, the only writer of the key
//! request `kreq` (§7.11), the holds that follow (KeySyncGone, a pending
//! gate, a refused or forked server file), the prune request (§7.19) and
//! what the Keys screen shows. Nothing here talks to a server, and nothing
//! here is authenticated (R33): a wrong `kview` only makes this PC hold,
//! ask, or write a request the server refuses; installing anything takes an
//! attended accept (`adopt` with `Source::Server`).
use super::{
    Session,
    anchor::{self, GateState, Ks, VaultLine},
    gate::{self, GateKind},
    keyfile::{EPOCH_SILENT, EPOCH_WINDOW, KeyFile, KeyState, Kind, Magic, is_sync_key_file},
    sha256,
    sync::{SyncLink, SyncNotice, key_inside},
};
use crate::{
    crypto::Result,
    syncfile::{
        self, FileError, KEY_REQUEST, KEY_VIEW, KeyOutcome, KeyRequest, KeyView, MAX_KEY_REQUEST,
        MAX_KEY_VIEW, PRUNE_REQUEST, RecordKind, Stamp,
    },
};
use std::{fs, path::Path};

/// A helper that wrote `features=keys` within this many seconds counts as
/// running (spec §7.9, §7.16 KeySyncHelper).
const HELPER_FRESH: u64 = 600;

/// §7.9's preconditions of turning key-file sync on, in their order.
pub const KEYSYNC_PIN: &str = "PIN 없이 등록한 보안 키 {list}을(를) 빼고 PIN으로 다시 등록하세요(보안 키를 끄고 PIN 사용으로 다시 켜기).";
pub const KEYSYNC_NOSYNC: &str = "열쇠 파일 동기화는 이 금고의 동기화를 켠 뒤에만 켤 수 있습니다.";
pub const KEYSYNC_NOTRANSPORT: &str = "이 Windows에서는 보안 키의 연결 방식을 확인할 수 없어 열쇠 파일 동기화를 켤 수 없습니다. Windows를 업데이트하세요.";
pub const KEYSYNC_NOHELPER: &str = "열쇠 파일 동기화를 지원하는 goyo-sync(보안 키 빌드)가 최근 10분 동안 응답하지 않았습니다. 그 goyo-sync를 실행한 뒤 다시 하세요.";
pub const KEYSYNC_OFF_PENDING: &str = "서버의 열쇠 파일 삭제가 끝난 뒤 다시 켜세요. (goyo-sync(보안 키 빌드)가 실행 중이어야 하고, 이 PC의 서버 연결이 이 금고의 열쇠 파일 요청을 받아야 합니다.)";
pub const KEYSYNC_TAKEN: &str =
    "서버에 이미 이 금고의 열쇠 파일이 있습니다(다른 PC에서 켬). 그 파일을 받으세요.";
pub const KEYSYNC_NOLINE: &str = "서버가 이 PC의 연결에서 이 금고의 열쇠 파일 동기화를 허용하지 않습니다. 서버 관리자가 이 PC의 강제 명령에 serve --key-sync=<금고 ID>를 넣어야 합니다.";
pub const KEYSYNC_ASKING: &str =
    "goyo-sync가 아직 서버의 열쇠 파일을 확인하지 않았습니다. 잠시 뒤 다시 하세요.";
pub const KEYSYNC_FLOOR: &str = "서버의 열쇠 파일 기록이 비정상적으로 큽니다. 서버 관리자가 data/<id>/k/를 지워야 합니다. 이 PC의 동기화 폴더가 바뀌었을 수도 있습니다(그 폴더의 incoming.goyokeysync를 지우면 goyo-sync가 다시 받습니다).";
pub const KEYSYNC_HALTED: &str = "동기화가 멈춰 있거나 받을 열쇠 파일이 기다리고 있어 열쇠 파일 동기화를 켤 수 없습니다. 먼저 그것을 해결하세요.";
pub const KEYSYNC_NOT_ON: &str = "이 열쇠 파일은 열쇠 파일 동기화를 쓰지 않습니다.";
pub const KEYSYNC_NOT_GONE: &str = "서버에 이 금고의 열쇠 파일이 있어 다시 올릴 필요가 없습니다.";
/// KeyFileRefused's reasons that only this module gives.
pub const USER_DROPPED: &str = "사용자가 받지 않음";
/// The kind-9 merge's other file did not open (spec §5.8).
pub const FORGED_LINK: &str = "위조된 연결";
pub const TOO_FAR: &str = "수정 번호가 너무 큼";
/// A pending gate holds every key change but the lost-key flow and the off
/// (spec §7.5 GatePending, no override).
pub const GATE_PENDING: &str = "받기 전에 확인할 열쇠 변경이 서버에 있습니다. 먼저 [받기…]로 잃어버린 키를 고르거나 코드를 입력하세요. 그 변경을 받지 않으려면 [받지 않기…]를 누르세요.";
/// The rotation gate KeyFileReady (spec §7.5).
pub const KEYFILE_READY: &str =
    "먼저 서버의 새 열쇠 파일을 받으세요. 그래도 바꾸면 두 열쇠 파일이 갈라집니다.";
/// [받기…] with nothing on the server to take.
pub const NO_CANDIDATE: &str = "서버에 받을 열쇠 파일이 없습니다.";
/// S-SUPERSEDE-HEAD (spec §9.3; S6-1 #2): a vault copy on the server that
/// is not under the candidate's own state halts sync; the head override
/// lifts it first.
pub const SUPERSEDE_HEAD: &str = "서버의 최신 금고 사본(수정 {epoch}, 열쇠 {key})이 다시 올리려는 열쇠 파일과 맞지 않아 아무것도 하지 않았습니다. 그 사본을 쓴 PC를 더 쓸 수 없는 것이 확실할 때만 먼저 '서버 사본을 이 PC 상태로 덮어쓰기…'를 하고 다시 하세요.";
/// "열쇠 변경 자동 적용 (이 서버를 믿음)" (spec §2.30) is only for a key
/// file that syncs through the server, on a PC that confirmed it.
pub const AUTO_NOT_SYNCED: &str = "열쇠 변경 자동 적용은 열쇠 파일 동기화를 쓰는 금고에서, 이 PC가 열쇠 파일을 확인한 뒤에만 켤 수 있습니다.";
/// The server's file is no longer a change the supersede serves.
pub const NOT_SUPERSEDABLE: &str = "서버의 열쇠 파일은 이제 이 PC 상태로 다시 올려 대신할 수 있는 변경이 아닙니다. '열쇠 관리'를 다시 확인하세요.";
/// A server file that this flow cannot take (a fork, a refused file).
pub const NOT_A_SUCCESSOR: &str = "서버의 열쇠 파일은 이 PC가 받거나 합칠 수 있는 파일이 아닙니다. 다른 PC에서 바꾼 것이 맞다면 그 PC의 열쇠 파일을 USB로 가져와 '새 열쇠 파일 받기'로 받으세요.";

/// How this PC classifies the server's key file (spec §7.14).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyClass {
    /// This PC's own state: the key file is verified.
    Equal,
    /// A state this PC held, merged or superseded: uploaded over (row 6).
    Stale,
    /// Written on top of this PC's state by a holder of its data key; a
    /// carry when this PC added a key or record the file lacks (the accept
    /// is then a union). `gate`: what the user must answer first.
    Successor { carry: bool, gate: Option<GateKind> },
    /// Not on top of this PC's state: halts until a join.
    KeyFork,
    /// An older state that a local rollback put back: never taken.
    KeyRollback,
    /// A public check failed: halts (KeyFileRefused{reason}).
    Refused(&'static str),
    /// Not readable as a key file (BadKeyIncoming): ignored.
    Bad,
    /// This session has no security keys: only a hardware session judges
    /// the server's file (spec §7.16 "They keep watching").
    Unjudged,
}

/// The server's top record as this session judged it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) enum Top {
    /// No view: `kview` missing or malformed.
    #[default]
    Unknown,
    /// The server holds no record (`seq` 0).
    Empty,
    Cut {
        seq: u64,
        floor: u64,
        damaged: bool,
    },
    Key {
        seq: u64,
        generation: u64,
        state: KeyState,
        class: KeyClass,
    },
}

/// What the deletion line of the Keys screen says (spec §7.11; only for
/// this PC's own off).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Deletion {
    /// `off.L` pending: "대기 중 (goyo-sync가 처리합니다)".
    Pending,
    /// `off.?`: waits for a view in an unlocked session.
    PendingNoView,
    /// This PC's line serves no key ops.
    NoKeyOps,
    /// The poll that dropped the settled `off.L`, with the server's record.
    Answered(u64),
}
/// What an off of key-file sync asks of the server (spec §7.16 step 6,
/// S6R2 #22).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OffRequest {
    /// `off.<L>`: the CUT is requested.
    Deletes,
    /// `off.?`: requested once goyo-sync has seen the server, in an
    /// unlocked session.
    AfterView,
    /// `-`: nothing on the server to delete.
    Nothing,
}
/// The server's key file waiting for this PC (spec §7.15).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Waiting {
    pub epoch: u64,
    pub class: KeyClass,
    /// Its gate is stored as pending in the anchor (GatePending).
    pub pending_gate: bool,
    /// [다른 PC가 없어 이 PC 상태로 올리기…] may be offered (§7.15a).
    pub supersede: bool,
}
/// What the Keys screen shows of key-file sync (spec §9.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct KeySyncView {
    /// The key file is GOYOKS01.
    pub on: bool,
    /// The vault syncs, so the option can be offered at all.
    pub synced: bool,
    /// KeySyncGone: [열쇠 파일 다시 올리기].
    pub gone: bool,
    pub deletion: Option<Deletion>,
    pub waiting: Option<Waiting>,
    /// S-KEYUP-REFUSED: the server refused this PC's key file.
    pub refused_upload: bool,
    /// This PC's line serves no key ops (`kview.line = 1`).
    pub no_key_ops: bool,
    /// A helper with `features=keys` answered within 10 minutes.
    pub helper: bool,
    /// The epoch of a pending gate whose candidate is not the server's top
    /// (no longer served): [받지 않기…] still ends it (§7.15a).
    pub stale_gate: Option<u64>,
    /// The rollout reminder is on: [모든 PC 확인 완료] (§7.18).
    pub rollout: bool,
    /// "열쇠 변경 자동 적용 (이 서버를 믿음)" is on for this vault on this
    /// PC (spec §2.30).
    pub auto_apply: bool,
}

/// The key side of a sync link (spec §7.10-§7.12): what this session last
/// read of `kview` and `kreq`, and what it derived. Never persisted.
#[derive(Default)]
pub(super) struct KeyLink {
    /// `kview`'s stamp at its last read, and whether it was read at all.
    stamp: Option<Stamp>,
    read: bool,
    /// Whether G2 was open when the top was judged: a pick that failed
    /// since (S-GATE-G2FAIL) judges it again, so a waiting candidate shows
    /// the gate it now needs.
    g2: bool,
    /// The view as read; None when missing or malformed.
    view: Option<KeyView>,
    pub(super) top: Top,
    /// `kreq`'s stamp after the last read or write of it.
    req_stamp: Option<Stamp>,
    /// `key_req_due`: a write or deletion of `kreq` failed; every poll
    /// re-evaluates the table until one succeeds (S6R1 #17).
    due: bool,
    /// The table is evaluated at the next poll.
    eval: bool,
    /// The holds of merges and vault outgoing at the last poll.
    pub(super) held: bool,
    /// The poll of this session dropped this PC's settled `off.L`.
    dropped: Option<u64>,
    /// The key notice last told, so each is told once per change.
    told: Option<SyncNotice>,
    /// The drop of this PC's settled `off.L` was told (once per session).
    deleted_told: bool,
    /// KeySyncOff's and KeysOff's snapshot of `ks′` (§7.16 step 2), kept
    /// across a rekey that wrote nothing (S6R2 #7).
    pub(super) off: Option<Ks>,
}
impl KeyLink {
    /// A well-formed view with `line` 0.
    fn line0(&self) -> Option<&KeyView> {
        self.view.as_ref().filter(|v| v.line == 0)
    }
    /// Remembers the key notice the poll told.
    pub(super) fn told(&mut self, notice: &SyncNotice) {
        self.deleted_told |= matches!(notice, SyncNotice::KeySyncDeleted { .. });
        self.told = Some(notice.clone());
    }
    /// `kview` changed, or was never read, since this poll's read of it.
    pub(super) fn moved(&self, dir: &Path) -> bool {
        !self.read || syncfile::stamp(dir, KEY_VIEW) != self.stamp
    }
    /// Everything is derived again at the next poll (a key change, an
    /// unlock).
    pub(super) fn again(&mut self) {
        (self.stamp, self.read, self.eval) = (None, false, true);
    }
}

/// SHA-256 of the 32-byte request CUT(`base`): `kview.answered` of its
/// answer.
fn cut_sha(base: u64) -> [u8; 32] {
    sha256(&syncfile::render_key_request(&KeyRequest::cut(base)))
}
/// Whether `ks` still waits for the server (spec §7.11 "Pending tests").
fn ks_pending(ks: Ks, view: Option<&KeyView>, top: Top) -> bool {
    let line0 = view.filter(|v| v.line == 0);
    match ks {
        Ks::None => false,
        Ks::OffUnknown => true,
        Ks::Off(l) => {
            let Some(v) = line0 else {
                return true;
            };
            let answered = v.outcome == KeyOutcome::Applied && v.answered == Some(cut_sha(l));
            let later = match top {
                Top::Cut {
                    seq,
                    damaged: false,
                    ..
                } => seq > l,
                Top::Key { generation, .. } => generation > l,
                _ => false,
            };
            !(answered || later)
        }
        Ks::On(c) => {
            line0.is_none_or(|v| v.seq == c && matches!(top, Top::Cut { .. } | Top::Empty))
        }
    }
}
/// A request is a CUT: the magic and its op byte (a planted or damaged one
/// counts too).
fn is_cut(bytes: &[u8]) -> bool {
    bytes.len() >= 9 && &bytes[..8] == syncfile::KEY_REQUEST_MAGIC && bytes[8] == 2
}

/// What the request table wants of `kreq` (spec §7.11).
#[derive(Clone, PartialEq, Eq, Debug)]
enum Want {
    /// Row 0: left exactly as it is.
    Keep,
    /// Rows 3 and 4: left as it is, unless it is a CUT.
    KeepNoCut,
    Delete,
    Write(Vec<u8>),
}

/// Gate 1's proof (spec §7.11): the GOYOKS01 bytes this session opened
/// through a security key's S-wrap at unlock or Reauth, or wrote and read
/// back itself (R2 + S2v). Built only by `Session::verified_ks`, so a
/// password-only or GOYOKH01 file never reaches `kreq`.
pub(super) struct VerifiedKs<'a>(&'a [u8]);

impl Session {
    /// Whether `change` goes ahead while a server candidate waits for its
    /// gate (spec §7.5): the lost-key flow, and the off of key-file sync
    /// (KeySyncOff, and KeysOff of a GOYOKS01 key file), whose CUT ends the
    /// candidate's generation.
    pub(super) fn passes_gate_pending(&self, change: &super::Change) -> bool {
        use super::Change;
        match change {
            Change::Remove { loss, .. } => loss.is_some(),
            Change::KeySyncOff => true,
            Change::KeysOff => self.ks01(),
            // What ends the gate it would meet (spec §7.15a).
            Change::Supersede { .. } => true,
            _ => false,
        }
    }
    /// Gate 1, items 1-3: the session's own key file bytes, never read
    /// again from disk, when they are a sync key file of this vault. A
    /// session holds a GOYOKS01 key file only as one it opened through a
    /// security key's S-wrap (unlock, Reauth) or one its own key change
    /// built, verified (R2) and read back (S2v): no other path sets
    /// `key_file` to such bytes. A Restore uploads nothing.
    pub(super) fn verified_ks(&self) -> Option<VerifiedKs<'_>> {
        let bytes = self.key_file.bytes();
        (!self.restored && is_sync_key_file(bytes, &self.id).is_some()).then_some(VerifiedKs(bytes))
    }
    /// The magic of this session's key file.
    pub fn key_magic(&self) -> Option<Magic> {
        self.key_file.magic()
    }
    /// §7.9's preconditions of turning key-file sync on (or of the
    /// re-upload) that the session decides, before any question. The key
    /// view is read again first: the last poll may be up to 2 s old (and
    /// none runs while a dialog is open), so it may still hold an answer
    /// the server has since changed (a --key-sync line just added).
    pub fn keysync_ready(&mut self) -> Result<()> {
        if let Some(mut link) = self.sync.take() {
            self.read_keys(&mut link);
            self.sync = Some(link);
        }
        self.keysync_on_check().map(|_| ())
    }
    /// [받지 않기…] after S-GATE-DROP's yes (spec §7.15a): the pending
    /// candidate is remembered as dropped, so it is never offered again
    /// and the key channel halts on it (KeyFileRefused{"사용자가 받지
    /// 않음"}) until a different file arrives.
    pub fn drop_gate(&mut self) -> Result<()> {
        let g = self.pending_gate().cloned().ok_or(NO_CANDIDATE)?;
        self.anchor_strict(&mut |lines| match lines.gate.as_mut() {
            Some(line)
                if line.state == GateState::Pending
                    && (line.epoch, line.tag) == (g.epoch, g.tag) =>
            {
                line.state = GateState::Dropped;
                true
            }
            _ => false,
        })?;
        if let Some(mut link) = self.sync.take() {
            link.keys.again();
            self.read_keys(&mut link);
            self.update_holds(&mut link);
            self.sync = Some(link);
        }
        Ok(())
    }
    /// Whether this session's key file is GOYOKS01.
    pub(super) fn ks01(&self) -> bool {
        self.key_file.magic() == Some(Magic::Ks01)
    }
    /// The confirmed line's `ks`.
    fn ks(&self) -> Ks {
        self.anchor
            .lines
            .vault
            .as_ref()
            .map_or(Ks::None, |v| v.state.ks)
    }
    /// The gate line of a server candidate waiting for its gate.
    fn pending_gate(&self) -> Option<&anchor::GateLine> {
        self.anchor
            .lines
            .gate
            .as_ref()
            .filter(|g| g.state == GateState::Pending)
    }
    /// Reads `kview` again when its stamp changed (a Busy read keeps the
    /// last view: the helper is replacing it) and judges its top for this
    /// session's state. True when what it holds changed.
    pub(super) fn read_keys(&self, link: &mut SyncLink) -> bool {
        let stamp = syncfile::stamp(&link.dir, KEY_VIEW);
        let g2 = self.g2_open();
        if link.keys.read && stamp == link.keys.stamp && g2 == link.keys.g2 {
            return false;
        }
        let view = match stamp {
            None => None,
            Some(_) => match syncfile::read_bounded(&link.dir.join(KEY_VIEW), MAX_KEY_VIEW) {
                Ok(bytes) => syncfile::parse_key_view(&bytes, &self.id),
                Err(FileError::Busy) => return false,
                Err(_) => None,
            },
        };
        let top = self.judge_top(view.as_ref(), self.anchor.lines.vault.as_ref());
        let changed = !link.keys.read || view != link.keys.view || top != link.keys.top;
        link.keys.stamp = stamp;
        link.keys.read = true;
        link.keys.g2 = g2;
        link.keys.view = view;
        link.keys.top = top;
        if changed {
            link.keys.eval = true;
        }
        changed
    }
    /// The top record of `view` as this session judges it, its key record
    /// classified against `line` (spec §7.14).
    fn judge_top(&self, view: Option<&KeyView>, line: Option<&VaultLine>) -> Top {
        let Some(v) = view else {
            return Top::Unknown;
        };
        let Some(record) = v.top(&self.id) else {
            return Top::Empty;
        };
        match record.kind {
            RecordKind::Cut => Top::Cut {
                seq: record.number,
                floor: record.floor,
                damaged: record.damaged,
            },
            RecordKind::Key => {
                let path = Path::new(KEY_VIEW);
                let none = KeyState {
                    epoch: record.floor,
                    tag: [0; 16],
                };
                let (state, class) = match KeyFile::from_bytes(path, record.payload.to_vec()) {
                    Ok(file) => match file.header() {
                        Some(h) => (h.state(), self.classify_unopened(&file, line)),
                        None => (none, KeyClass::Bad),
                    },
                    Err(_) => (none, KeyClass::Bad),
                };
                Top::Key {
                    seq: record.number,
                    generation: record.generation,
                    state,
                    class,
                }
            }
        }
    }
    /// §7.14 with the app's record of merges whose other file did not open
    /// (spec §5.8, S6-2 #5): such a file, while it stays the incoming, is
    /// Refused{"위조된 연결"} instead of a KeyFork.
    fn classify_unopened(&self, other: &KeyFile, line: Option<&VaultLine>) -> KeyClass {
        match self.classify(other, line) {
            KeyClass::KeyFork
                if other
                    .header()
                    .is_some_and(|t| super::serverkey::merge_unopened(&self.id, t.state())) =>
            {
                KeyClass::Refused(FORGED_LINK)
            }
            class => class,
        }
    }
    /// §7.14: how the server's key file `other` stands against this PC's
    /// key file and its confirmed line `line`. Public bytes only: no touch,
    /// no Argon2.
    pub(super) fn classify(&self, other: &KeyFile, line: Option<&VaultLine>) -> KeyClass {
        let Some(own) = self.key_file.header().filter(|h| h.magic.hardware()) else {
            return KeyClass::Unjudged;
        };
        let Some(t) = other.header() else {
            return KeyClass::Bad;
        };
        if is_sync_key_file(other.bytes(), &self.id).is_none() {
            return KeyClass::Bad;
        }
        // Rule A's window (review finding 1): never used anywhere.
        if t.epoch > self.max_epoch.saturating_add(EPOCH_WINDOW) {
            return KeyClass::Refused(TOO_FAR);
        }
        let state = t.state();
        if state == own.state() {
            return KeyClass::Equal;
        }
        // A file this PC dropped at its gate stays refused (§7.15a).
        if let Some(g) = self.anchor.lines.gate.as_ref()
            && g.state == GateState::Dropped
            && (g.epoch, g.tag) == (state.epoch, state.tag)
        {
            return KeyClass::Refused(USER_DROPPED);
        }
        // E1.
        if t.otp() != own.otp() {
            return KeyClass::Refused(gate::UNEXPLAINED);
        }
        let superseded = self.anchor.lines.gate.as_ref().is_some_and(|g| {
            g.state == GateState::Superseded && (g.epoch, g.tag) == (state.epoch, state.tag)
        });
        let merged = line.is_some_and(|l| l.merged_state(state));
        if t.epoch < own.epoch && (line.is_some_and(|l| l.state.had(state)) || superseded || merged)
        {
            return KeyClass::Stale;
        }
        let chained = other.chain_ok(self.keys.current());
        let fork = !chained
            || t.epoch < own.epoch
            || (t.epoch == own.epoch && t.key_ids.first() == own.key_ids.first());
        let gated = self.gated_epoch();
        let checked = match gate::public_checks(&self.key_file, line, other, fork, chained, gated) {
            Ok(c) => c,
            Err(reason) => return KeyClass::Refused(reason),
        };
        // P4 is never relaxed here (only fork option 1 behind G1 takes such
        // a file, through "새 열쇠 파일 받기").
        if checked.removed_authorizer.is_some() {
            return KeyClass::Refused(gate::REMOVED_AUTHORIZER);
        }
        let confirmed = line.map_or(0, |l| l.state.epoch);
        if t.epoch < own.epoch {
            return KeyClass::KeyFork;
        }
        if t.epoch < self.max_epoch {
            return if t.epoch < confirmed {
                KeyClass::KeyRollback
            } else {
                KeyClass::KeyFork
            };
        }
        if fork || t.epoch < confirmed {
            return KeyClass::KeyFork;
        }
        let carry = !checked.missing_pairs.is_empty() || !checked.gates.kept.is_empty();
        let g = &checked.gates;
        let needed = if carry {
            // A carry is a union (§5.8): G1 also for a silent jump.
            let g1 = !g.added.is_empty() || !g.unknown.is_empty() || g.policy || g.slot || g.jump;
            if g1 {
                Some(GateKind::G1)
            } else if !g.removed.is_empty() {
                Some(GateKind::G2)
            } else {
                None
            }
        } else {
            g.needed()
        };
        let gate = match needed {
            Some(GateKind::G2) if !self.g2_open() => Some(GateKind::G1),
            other => other,
        };
        KeyClass::Successor { carry, gate }
    }
    /// The anchor's `gated` epoch that a silent jump counts from.
    pub(super) fn gated_epoch(&self) -> Option<u64> {
        match self.anchor.lines.vault.as_ref() {
            Some(l) if l.state.flags.t || !l.state.hardware() => Some(l.state.gated),
            _ => None,
        }
    }
    /// G2 is still allowed on this PC for this vault.
    fn g2_open(&self) -> bool {
        !self.g2_spent.get() && gate::g2_allowed(&self.anchor.lines)
    }
    /// The KeySyncGone condition (request-table row 9 on a GOYOKS01
    /// session): a line-0 view whose top is a cut or none, and no consented
    /// "on" of this PC waiting to land on it (row 8).
    fn gone(&self, link: &SyncLink) -> bool {
        self.gone_with(link, self.ks())
    }
    /// The same for the line whose `ks` is `ks`.
    fn gone_with(&self, link: &SyncLink, ks: Ks) -> bool {
        let Some(v) = link.keys.line0() else {
            return false;
        };
        self.ks01()
            && matches!(link.keys.top, Top::Cut { .. } | Top::Empty)
            && !matches!(ks, Ks::On(c) if c == v.seq)
    }
    /// Whether the key channel holds merges and the vault outgoing (spec
    /// §7.20): a pending gate (I-S9), a forked or refused server file, and
    /// the KeySyncGone hold. A gated successor on top holds by its class
    /// too, before its pending line is stored: at unlock, which stores no
    /// line, and after an anchor write that failed.
    pub(super) fn key_hold(&self, link: &SyncLink) -> bool {
        self.key_hold_with(link, self.ks(), self.pending_gate().is_some())
    }
    /// The same for the line whose `ks` is `ks`, with a pending gate or
    /// not: at S4 of a key change the committed entry's (§7.11).
    fn key_hold_with(&self, link: &SyncLink, ks: Ks, gate: bool) -> bool {
        if gate || self.gone_with(link, ks) {
            return true;
        }
        matches!(
            link.keys.top,
            Top::Key {
                class: KeyClass::KeyFork
                    | KeyClass::Refused(_)
                    | KeyClass::Successor { gate: Some(_), .. },
                ..
            }
        )
    }
    /// The key channel's halt of key changes (spec §7.5): a forked server
    /// file (Some(true)) or a refused one (Some(false)).
    pub(super) fn key_halt(&self) -> Option<bool> {
        match self.sync.as_ref()?.keys.top {
            Top::Key {
                class: KeyClass::KeyFork,
                ..
            } => Some(true),
            Top::Key {
                class: KeyClass::Refused(_),
                ..
            } => Some(false),
            _ => None,
        }
    }
    /// The server's top as judged, when this vault syncs.
    pub(super) fn key_top(&self) -> Top {
        self.sync.as_ref().map_or(Top::Unknown, |l| l.keys.top)
    }
    /// The server's top is a key record of state `state`.
    pub(super) fn server_top_is(&self, state: KeyState) -> bool {
        matches!(self.key_top(), Top::Key { state: s, .. } if s == state)
    }
    /// A successor that needs no gate waits (KeyFileReady, §7.5).
    pub(super) fn successor_ready(&self) -> bool {
        matches!(
            self.key_top(),
            Top::Key {
                class: KeyClass::Successor { gate: None, .. },
                ..
            }
        )
    }
    /// A server candidate's gate is pending (GatePending, no override).
    pub(super) fn gate_waits(&self) -> bool {
        self.pending_gate().is_some()
    }
    /// Feature, GOYOKS01 (spec §7.5 Unverified): no line-0 view, a key
    /// record on top that is neither Equal nor Stale, or no helper with
    /// `features=keys` within 10 minutes.
    pub(super) fn keys_unverified(&self) -> bool {
        let Some(link) = self.sync.as_ref().filter(|_| self.ks01()) else {
            return false;
        };
        link.keys.line0().is_none()
            || !helper_fresh(link)
            || matches!(link.keys.top, Top::Key { class, .. } if !matches!(class, KeyClass::Equal | KeyClass::Stale))
    }
    /// W2's server terms for a GOYOKS01 result (spec §5.5): the top key
    /// record's epoch when it is Equal, Stale or a Successor within
    /// `gated + EPOCH_SILENT`; a cut's floor within `key_state.epoch +
    /// EPOCH_SILENT`. 0 otherwise; a larger value is ignored, never an
    /// error.
    pub(super) fn server_epoch(&self) -> u64 {
        let silent = |e: u64| {
            self.gated_epoch()
                .is_some_and(|g| e <= g.saturating_add(EPOCH_SILENT))
        };
        match self.key_top() {
            Top::Key {
                state,
                class: KeyClass::Equal | KeyClass::Stale,
                ..
            } => state.epoch,
            Top::Key {
                state,
                class: KeyClass::Successor { .. },
                ..
            } if silent(state.epoch) => state.epoch,
            Top::Cut { floor, .. }
                if floor <= self.key_state.epoch.saturating_add(EPOCH_SILENT) =>
            {
                floor
            }
            _ => 0,
        }
    }

    /// The key steps of a poll (spec §7.11): `kview` read and judged; the
    /// pin of `off.?`, the drop of a settled `ks` and the self-heal, each
    /// one locked rewrite of the confirmed line; a server candidate's gate
    /// stored as pending; the request table when anything changed or a
    /// write is due; the holds; the key notice when it changed.
    pub(super) fn poll_keys(&mut self, link: &mut SyncLink, notice: &mut Option<SyncNotice>) {
        self.read_keys(link);
        self.maintain_ks(link);
        self.store_gate(link);
        if link.keys.eval
            || link.keys.due
            || syncfile::stamp(&link.dir, KEY_REQUEST) != link.keys.req_stamp
        {
            self.key_table(link, None);
        }
        self.update_holds(link);
        match self.key_notice(link) {
            Some(n) if link.keys.told.as_ref() != Some(&n) => super::sync::offer(notice, n),
            Some(_) => {}
            None => link.keys.told = None,
        }
    }
    /// The holds of this poll; when they lift, the vault incoming they held
    /// is judged again.
    pub(super) fn update_holds(&self, link: &mut SyncLink) {
        let held = self.key_hold(link);
        if link.keys.held && !held {
            link.in_stamp = None;
        }
        link.keys.held = held;
    }
    /// The pin, the drop and the self-heal (spec §7.11): only in an
    /// unlocked session's poll, never under row 0's holds.
    fn maintain_ks(&mut self, link: &mut SyncLink) {
        if self.row0(link) {
            return;
        }
        let Some(v) = link.keys.line0().cloned() else {
            return;
        };
        let top = link.keys.top;
        let ks = self.ks();
        let want = match ks {
            // The pin: the first line-0 view decides what `off.?` ends.
            Ks::OffUnknown => match top {
                Top::Key { .. } | Top::Cut { damaged: true, .. } => Ks::Off(v.seq),
                _ => Ks::None,
            },
            // The drop of a value that no longer waits.
            Ks::On(_) | Ks::Off(_) if !ks_pending(ks, Some(&v), top) => Ks::None,
            // The self-heal (S6R2 #6): a record of this PC's own history
            // left on the server after it left key-file sync.
            Ks::None if !self.ks01() => match top {
                Top::Key { seq, state, .. }
                    if self.anchor.lines.vault.as_ref().is_some_and(|l| {
                        l.state.had(state) && l.state.magic != *Magic::Ks01.bytes()
                    }) =>
                {
                    Ks::Off(seq)
                }
                _ => return,
            },
            _ => return,
        };
        if want == ks {
            return;
        }
        let ok = self
            .anchor_strict(&mut |lines| match lines.vault.as_mut() {
                Some(l) if l.state.ks == ks => {
                    l.state.ks = want;
                    true
                }
                _ => false,
            })
            .is_ok();
        if ok && self.ks() == want {
            if let Ks::Off(_) = ks
                && want == Ks::None
            {
                link.keys.dropped = Some(v.seq);
            }
            link.keys.eval = true;
        }
    }
    /// A server candidate that needs a gate is stored as pending (spec
    /// §7.15a "Persistence"): a newer one replaces the stored one, which
    /// keeps `g2`, and so does the same file over a `none` line that a
    /// failed pick of it (a USB adopt, a login) left.
    fn store_gate(&mut self, link: &SyncLink) {
        let Top::Key {
            state,
            class: KeyClass::Successor { gate: Some(_), .. },
            ..
        } = link.keys.top
        else {
            return;
        };
        if self.row0(link) {
            return;
        }
        let named = |g: &anchor::GateLine| {
            (g.epoch, g.tag) == (state.epoch, state.tag) && g.state != GateState::None
        };
        if self.anchor.lines.gate.as_ref().is_some_and(named) {
            return;
        }
        let Ok(now) = crate::otp::now() else {
            return;
        };
        let _ = self.anchor_strict(&mut |lines| {
            let g2 = lines.gate.as_ref().is_none_or(|g| g.g2);
            if lines.gate.as_ref().is_some_and(named) {
                return false;
            }
            lines.gate = Some(anchor::GateLine {
                epoch: state.epoch,
                tag: state.tag,
                state: GateState::Pending,
                g2,
                since: now,
            });
            true
        });
        // Its pending line now holds merges: what this poll would merge
        // waits.
    }
    /// Row 0 of the request table (spec §7.11): nothing about `kreq` or
    /// `ks` is decided.
    fn row0(&self, link: &SyncLink) -> bool {
        self.local_rollback
            || self.restore_held
            || self.restored
            || self.unconfirmed()
            || self.gate_login.is_some()
            || !syncfile::usable_dir(&link.dir)
            || key_inside(&self.key_path, &link.dir) != Some(false)
    }
    /// The request table (spec §7.11) against the committed state: the
    /// confirmed line, or at S4 of a key change its pending entry
    /// (`committed`). Writes or deletes `kreq` as it says, through gate 1
    /// for a PUT; a failure sets `key_req_due`.
    pub(super) fn key_table(
        &mut self,
        link: &mut SyncLink,
        committed: Option<&anchor::PendingLine>,
    ) {
        link.keys.eval = false;
        let promoted;
        let line = match committed {
            Some(p) => {
                promoted = p.promoted(self.anchor.lines.vault.as_ref());
                Some(&promoted)
            }
            None => self.anchor.lines.vault.as_ref(),
        };
        // At S4 the top is judged again against the state just committed.
        let top = match committed {
            Some(_) => {
                let top = self.judge_top(link.keys.view.as_ref(), line);
                link.keys.top = top;
                top
            }
            None => link.keys.top,
        };
        let ks = line.map_or(Ks::None, |l| l.state.ks);
        let (want, drop_view) = self.wanted(link, ks, top);
        let path = link.dir.join(KEY_REQUEST);
        let mut ok = true;
        if drop_view {
            ok &= remove(&link.dir.join(KEY_VIEW));
            link.keys.again();
            link.keys.eval = false;
        }
        let current = match syncfile::read_bounded(&path, MAX_KEY_REQUEST) {
            Ok(bytes) => Some(bytes),
            Err(FileError::Missing) => None,
            // Held open (the helper's gate 2): tried again next poll.
            Err(FileError::Busy) => {
                link.keys.due = true;
                return;
            }
            Err(_) => Some(Vec::new()),
        };
        match want {
            Want::Keep => {}
            Want::KeepNoCut => {
                if current.as_deref().is_some_and(is_cut) {
                    ok &= remove(&path);
                }
            }
            Want::Delete => {
                if current.is_some() {
                    ok &= remove(&path);
                }
            }
            Want::Write(bytes) => {
                if current.as_deref() != Some(&bytes[..]) {
                    ok &= syncfile::replace_file(&path, &bytes).is_ok();
                }
            }
        }
        link.keys.due = !ok;
        link.keys.req_stamp = syncfile::stamp(&link.dir, KEY_REQUEST);
    }
    /// The row of the request table that matches first, and whether row 1
    /// deletes `kview` (it holds a key record of the generation being
    /// ended).
    fn wanted(&self, link: &SyncLink, ks: Ks, top: Top) -> (Want, bool) {
        if self.row0(link) {
            return (Want::Keep, false);
        }
        let view = link.keys.view.as_ref();
        // Row 1.
        match ks {
            Ks::OffUnknown => return (Want::Delete, false),
            Ks::Off(l) if ks_pending(ks, view, top) => {
                let cut = syncfile::render_key_request(&KeyRequest::cut(l));
                return (Want::Write(cut), matches!(top, Top::Key { .. }));
            }
            _ => {}
        }
        // Row 2.
        let Some(own) = self.key_file.header().filter(|_| self.ks01()) else {
            return (Want::Delete, false);
        };
        // Row 3.
        let held = self.anchor_failed
            || link.halted_by_copy()
            || self.pending_gate().is_some()
            || !own.pin()
            || !own.slots.iter().all(|s| s.pin())
            || matches!(
                top,
                Top::Key {
                    class: KeyClass::KeyFork | KeyClass::Refused(_) | KeyClass::Successor { .. },
                    ..
                }
            );
        if held {
            return (Want::KeepNoCut, false);
        }
        // Row 4.
        let Some(v) = view.filter(|v| v.line == 0) else {
            return (Want::KeepNoCut, false);
        };
        let put = |base: u64, floor: u64| match self.verified_ks() {
            Some(VerifiedKs(bytes)) => {
                let req = KeyRequest::put(base, floor, bytes);
                // A request the helper's gate 2 refuses is never written.
                if req.epoch() > floor {
                    Want::Write(syncfile::render_key_request(&req))
                } else {
                    Want::Keep
                }
            }
            None => Want::Keep,
        };
        match top {
            Top::Unknown => (Want::KeepNoCut, false),
            // Rows 5-7.
            Top::Key { class, state, .. } => match class {
                KeyClass::Equal => (Want::Delete, false),
                KeyClass::Stale => (put(v.seq, state.epoch), false),
                _ => (Want::Delete, false),
            },
            // Rows 8 and 9.
            Top::Cut { .. } | Top::Empty => {
                let floor = match top {
                    Top::Cut { floor, .. } => floor,
                    _ => 0,
                };
                match ks {
                    Ks::On(c) if c == v.seq && own.epoch > floor => (put(c, floor), false),
                    _ => (Want::Delete, false),
                }
            }
        }
    }
    /// The key channel's notice now (spec §7.4, §7.11), the strongest
    /// first; None when nothing is to be told.
    fn key_notice(&self, link: &SyncLink) -> Option<SyncNotice> {
        if !self.row0(link) {
            match link.keys.top {
                Top::Key {
                    class: KeyClass::KeyRollback,
                    ..
                } => return Some(SyncNotice::KeyRollback),
                Top::Key {
                    class: KeyClass::Refused(reason),
                    ..
                } => return Some(SyncNotice::KeyFileRefused(reason)),
                Top::Key {
                    class: KeyClass::Bad,
                    ..
                } => return Some(SyncNotice::BadKeyIncoming),
                Top::Key {
                    class: KeyClass::KeyFork,
                    ..
                } => {
                    return Some(match self.removal_merge_in(link) {
                        Some(m) => SyncNotice::KeyForkMerge {
                            auto: m == super::serverkey::RemovalMerge::Auto,
                        },
                        None => SyncNotice::KeyFork,
                    });
                }
                _ => {}
            }
        }
        if let Some(g) = self.pending_gate() {
            // With "열쇠 변경 자동 적용" on, the server's change waits for
            // [받기…] or the next unlock, which take it with no question
            // (spec §2.30): told as a change that needs no gate.
            if self.auto_apply()
                && matches!(link.keys.top, Top::Key {
                    state,
                    class: KeyClass::Successor { .. },
                    ..
                } if (state.epoch, state.tag) == (g.epoch, g.tag))
            {
                return Some(SyncNotice::KeyFileReady { epoch: g.epoch });
            }
            return Some(SyncNotice::GatePending);
        }
        if let Some(seq) = link.keys.dropped.filter(|_| !link.keys.deleted_told) {
            return Some(SyncNotice::KeySyncDeleted {
                seq,
                admin: !self.ks01(),
            });
        }
        if self.gone(link) {
            return Some(SyncNotice::KeySyncGone);
        }
        if let Top::Key {
            state,
            class: KeyClass::Successor { gate: None, .. },
            ..
        } = link.keys.top
        {
            return Some(SyncNotice::KeyFileReady { epoch: state.epoch });
        }
        if self.ks01() && link.keys.view.as_ref().is_some_and(|v| v.line == 1) {
            return Some(SyncNotice::NoKeySync);
        }
        if self.upload_refused(link) {
            return Some(SyncNotice::KeyUpRefused);
        }
        let uses = self.ks01() || matches!(self.ks(), Ks::Off(_) | Ks::OffUnknown | Ks::On(_));
        (uses && !helper_fresh(link)).then_some(SyncNotice::KeySyncHelper)
    }
    /// S-KEYUP-REFUSED (spec §7.11): `kreq` exists and `kview` answers it
    /// with `outcome` 3.
    fn upload_refused(&self, link: &SyncLink) -> bool {
        let Some(v) = link.keys.view.as_ref() else {
            return false;
        };
        if v.outcome != KeyOutcome::Refused {
            return false;
        }
        syncfile::read_bounded(&link.dir.join(KEY_REQUEST), MAX_KEY_REQUEST)
            .is_ok_and(|bytes| v.answered == Some(sha256(&bytes)))
    }

    /// What the Keys screen shows of key-file sync (spec §9.1); None when
    /// this session has no security keys.
    pub fn key_sync_view(&self) -> Option<KeySyncView> {
        self.key_file.header().filter(|h| !h.slots.is_empty())?;
        let mut v = KeySyncView {
            on: self.ks01(),
            synced: self.format == super::Format::V2,
            rollout: self.rollout().is_some(),
            auto_apply: self.auto_apply(),
            ..KeySyncView::default()
        };
        let Some(link) = self.sync.as_ref() else {
            v.deletion = match self.ks() {
                Ks::Off(_) => Some(Deletion::Pending),
                Ks::OffUnknown => Some(Deletion::PendingNoView),
                _ => None,
            };
            return Some(v);
        };
        v.helper = helper_fresh(link);
        v.gone = self.gone(link);
        v.no_key_ops = link.keys.view.as_ref().is_some_and(|k| k.line == 1);
        v.refused_upload = self.upload_refused(link);
        v.deletion = match self.ks() {
            _ if v.no_key_ops && matches!(self.ks(), Ks::Off(_) | Ks::OffUnknown) => {
                Some(Deletion::NoKeyOps)
            }
            Ks::Off(_) => Some(Deletion::Pending),
            Ks::OffUnknown => Some(Deletion::PendingNoView),
            _ => link.keys.dropped.map(Deletion::Answered),
        };
        if let Top::Key { state, class, .. } = link.keys.top
            && matches!(class, KeyClass::Successor { .. } | KeyClass::KeyFork)
        {
            let pending_gate = self
                .pending_gate()
                .is_some_and(|g| (g.epoch, g.tag) == (state.epoch, state.tag));
            v.waiting = Some(Waiting {
                epoch: state.epoch,
                class,
                pending_gate,
                supersede: self.supersede_offered(),
            });
        }
        if !v.waiting.is_some_and(|w| w.pending_gate) {
            v.stale_gate = self.pending_gate().map(|g| g.epoch);
        }
        Some(v)
    }
    /// The server's key file as a key file to take (spec §7.15): the bytes
    /// of the top key record of `kview` exactly as judged, with its record
    /// number. None when the top is no key record.
    pub fn server_key_file(&self) -> Option<(KeyFile, u64)> {
        self.server_key_file_in(self.sync.as_ref()?)
    }
    /// The same from `link` (a poll holds the link outside the session).
    pub(super) fn server_key_file_in(&self, link: &SyncLink) -> Option<(KeyFile, u64)> {
        let v = link.keys.view.as_ref()?;
        let record = v.top(&self.id).filter(|r| r.kind == RecordKind::Key)?;
        let file = KeyFile::from_bytes(&link.dir.join(KEY_VIEW), record.payload.to_vec()).ok()?;
        Some((file, record.number))
    }
    /// The epoch of the server's key file that this PC, whose own key file
    /// has no security keys, takes with '서버의 새 열쇠 파일 받기…' on its
    /// Keys screen: another PC turned keys on, then key-file sync (a PC
    /// without keys judges no server file, §7.14, so `adopt_check` judges
    /// it then). A file with security keys at a later epoch than this PC's
    /// key file; None on a PC with keys, or for an older file (this PC's
    /// own from before its keys off).
    pub fn pwonly_server_file(&self) -> Option<u64> {
        if self.key_file.needs_security_key() {
            return None;
        }
        let (file, _) = self.server_key_file()?;
        let epoch = file.header().filter(|_| file.needs_security_key())?.epoch;
        (epoch > self.key_state.epoch).then_some(epoch)
    }
    /// '코드 없이 이 서버를 믿고 받기…': a PC without security keys takes
    /// the server's key file without the other PC's code (G1). Only the
    /// server channel (never a USB file), the file of the record `seq`
    /// that this session's key view holds now in exactly the checked
    /// state, with security keys, a successor of this PC's (no fork), on a
    /// key file with no keys that this PC confirmed (never a bootstrap or
    /// a Restore). Every public check has run before this is asked, and
    /// runs again at the write, which judges this again.
    pub fn trusts_without_code(&self, check: &super::AdoptCheck) -> bool {
        // A USB file never.
        let super::Source::Server { seq } = &check.source else {
            return false;
        };
        let served = self.server_key_file().is_some_and(|(f, n)| {
            n == *seq
                && f.needs_security_key()
                && f.header().is_some_and(|h| h.state() == check.other)
        });
        let pwonly = !self.key_file.needs_security_key();
        served
            && pwonly
            && check.class == super::AdoptClass::Successor
            && !check.fork
            && !self.unconfirmed()
            && !self.restored
    }
    /// The class of the server's file now (spec §7.14).
    pub fn server_class(&self) -> Option<KeyClass> {
        match self.key_top() {
            Top::Key { class, .. } => Some(class),
            _ => None,
        }
    }

    /// What an off of key-file sync would ask of the server (spec §7.16
    /// step 2, for its dialogs and status): its `ks′` snapshot, taken now
    /// and kept for the rekey.
    pub fn off_request(&mut self) -> OffRequest {
        // A retry reuses the snapshot of the attempt that wrote nothing
        // while the view that attempt deleted is still missing (S6R2 #7);
        // any other off takes its own now.
        let retry = self
            .sync
            .as_ref()
            .filter(|l| l.keys.view.is_none())
            .and_then(|l| l.keys.off);
        let ks = retry.unwrap_or_else(|| self.leaving_ks(true));
        if let Some(link) = self.sync.as_mut() {
            link.keys.off = Some(ks);
        }
        match ks {
            Ks::Off(_) | Ks::On(_) => OffRequest::Deletes,
            Ks::OffUnknown => OffRequest::AfterView,
            Ks::None => OffRequest::Nothing,
        }
    }
    /// KeySyncOff's and KeysOff's `ks′` (spec §7.16 step 2), by the first
    /// rule that matches; kept in the session across a rekey that wrote
    /// nothing, and reused by an off retried in it (S6R2 #7).
    pub(super) fn off_snapshot(&mut self) -> Ks {
        if let Some(ks) = self.sync.as_ref().and_then(|l| l.keys.off) {
            return ks;
        }
        let ks = self.leaving_ks(true);
        if let Some(link) = self.sync.as_mut() {
            link.keys.off = Some(ks);
        }
        ks
    }
    /// The `ks` of a write that leaves key-file sync (spec §7.16 "Which
    /// writes set `ks`", rules 1-5). `off`: KeySyncOff or KeysOff; else a
    /// write that takes another file, which ends only a record of this
    /// PC's own state or history (`takes`: the top is the record it takes
    /// or merges, or the candidate whose gate it clears).
    pub(super) fn leaving_ks(&self, off: bool) -> Ks {
        self.leaving_ks_with(off, false)
    }
    pub(super) fn leaving_ks_with(&self, off: bool, takes: bool) -> Ks {
        let ks = self.ks();
        let (view, top) = match self.sync.as_ref() {
            Some(l) => (l.keys.view.as_ref(), l.keys.top),
            None => (None, Top::Unknown),
        };
        match ks {
            // 1. An off already pending is kept.
            Ks::Off(_) if ks_pending(ks, view, top) => return ks,
            Ks::OffUnknown => return ks,
            // 2. Own consented "on" waiting to land.
            Ks::On(c) if ks_pending(ks, view, top) => return Ks::Off(c),
            _ => {}
        }
        // A view: line 0, or line 1 with the record cached from its last
        // line-0 answer (S6R2 #5).
        let viewed = view.filter(|v| v.line == 0 || v.seq > 0);
        let Some(v) = viewed else {
            // 5. No view.
            return if off { Ks::OffUnknown } else { Ks::None };
        };
        match top {
            // 3. A damaged top, or a key record.
            Top::Cut { damaged: true, .. } => Ks::Off(v.seq),
            Top::Key { class, .. } => {
                let own = matches!(class, KeyClass::Equal | KeyClass::Stale);
                if off || own || takes {
                    Ks::Off(v.seq)
                } else {
                    Ks::None
                }
            }
            // 4. An undamaged cut, or none.
            _ => Ks::None,
        }
    }
    /// The `ks` an adopt or accept of `check` records (spec §7.16 "Which
    /// writes set `ks`"), when its result leaves key-file sync: Some when
    /// this PC's key file is GOYOKS01, or the write takes or merges the
    /// server's key record, or clears the gate of a candidate that is that
    /// record (S6R2 #3); None copies the confirmed line's.
    pub(super) fn take_ks(&self, check: &super::AdoptCheck) -> Option<Ks> {
        let top = match self.key_top() {
            Top::Key { state, .. } => Some(state),
            _ => None,
        };
        let (_, clear) = self.take_marks(check);
        let gate = self.pending_gate().map(|g| (g.epoch, g.tag));
        let takes = top == Some(check.other)
            || (clear && top.is_some_and(|t| gate == Some((t.epoch, t.tag))));
        (self.ks01() || takes).then(|| self.leaving_ks_with(false, takes))
    }
    /// What an adopt or accept of `check` records beside its state (spec
    /// §5.5 S0): `merged`, the server's file it joins (a union with it), or
    /// the candidate whose pending gate it clears (S6R2 #3); and whether it
    /// clears that gate: it takes the candidate, or lands above it.
    pub(super) fn take_marks(&self, check: &super::AdoptCheck) -> (Option<(u64, [u8; 16])>, bool) {
        let top = match self.key_top() {
            Top::Key { state, .. } => Some(state),
            _ => None,
        };
        let gate = self.pending_gate().map(|g| KeyState {
            epoch: g.epoch,
            tag: g.tag,
        });
        let clear = gate.is_some_and(|g| g == check.other || check.epoch > g.epoch);
        let union = check.class == super::AdoptClass::Union;
        let merged = if union && top == Some(check.other) {
            Some((check.other.epoch, check.other.tag))
        } else if clear && gate.is_some() && top == gate && gate != Some(check.other) {
            gate.map(|g| (g.epoch, g.tag))
        } else {
            None
        };
        (merged, clear)
    }
    /// The `ks` of a consented "on" (spec §7.16): refused while this PC's
    /// own off is pending; `on.<seq>` over a line-0 cut or none; `-` over a
    /// key record (the write takes, merges or supersedes it) or with no
    /// line-0 view.
    pub(super) fn on_ks(&self) -> Result<Ks> {
        if self.off_pending() {
            return Err(KEYSYNC_OFF_PENDING);
        }
        let Some(link) = self.sync.as_ref() else {
            return Ok(Ks::None);
        };
        Ok(match (link.keys.line0(), link.keys.top) {
            (Some(v), Top::Cut { .. } | Top::Empty) => Ks::On(v.seq),
            _ => Ks::None,
        })
    }
    /// This PC's own off waits for the server (`off.L` pending, or
    /// `off.?`).
    pub fn off_pending(&self) -> bool {
        let ks = self.ks();
        let (view, top) = match self.sync.as_ref() {
            Some(l) => (l.keys.view.as_ref(), l.keys.top),
            None => (None, Top::Unknown),
        };
        matches!(ks, Ks::Off(_) | Ks::OffUnknown) && ks_pending(ks, view, top)
    }
    /// §7.9's preconditions of KeySyncOn that the session decides (the
    /// transport is the Reauth's), in their order: Ok(the floor the new
    /// epoch must lie above).
    pub(super) fn keysync_on_check(&self) -> Result<u64> {
        let h = self.key_file.header().ok_or(KEYSYNC_NOT_ON)?;
        let reupload = self.ks01();
        if !reupload {
            let nopin: Vec<String> = h
                .slots
                .iter()
                .filter(|s| !s.pin() || !h.pin())
                .map(|s| s.number.to_string())
                .collect();
            if h.slots.is_empty() || !nopin.is_empty() {
                return Err(super::refuse(KEYSYNC_PIN, vec![nopin.join(", ")]));
            }
        }
        let link = self
            .sync
            .as_ref()
            .filter(|_| self.format == super::Format::V2)
            .ok_or(KEYSYNC_NOSYNC)?;
        if !helper_fresh(link) {
            return Err(KEYSYNC_NOHELPER);
        }
        if self.off_pending() {
            return Err(KEYSYNC_OFF_PENDING);
        }
        let v = link.keys.view.as_ref().ok_or(KEYSYNC_ASKING)?;
        if v.line == 1 {
            return Err(KEYSYNC_NOLINE);
        }
        let floor = match link.keys.top {
            Top::Empty => 0,
            Top::Cut { floor, .. } => floor,
            Top::Key { .. } if reupload => return Err(KEYSYNC_NOT_GONE),
            Top::Key { .. } => return Err(KEYSYNC_TAKEN),
            Top::Unknown => return Err(KEYSYNC_ASKING),
        };
        if floor > self.key_state.epoch.saturating_add(EPOCH_SILENT) {
            return Err(KEYSYNC_FLOOR);
        }
        if self.sync_halt().is_some() || self.key_halt().is_some() || self.pending_gate().is_some()
        {
            return Err(KEYSYNC_HALTED);
        }
        Ok(floor)
    }
    /// §7.16 step 4.1: `kreq` and `kview` deleted before the rotation
    /// (condition 15 (2)), each tried twice; a file that stays does not
    /// abort (the table replaces `kreq`, row 1 deletes such a `kview`).
    pub(super) fn off_delete(&mut self) {
        let Some(link) = self.sync.as_mut() else {
            return;
        };
        for name in [KEY_REQUEST, KEY_VIEW] {
            let path = link.dir.join(name);
            if !remove(&path) {
                let _ = remove(&path);
            }
        }
        link.keys.again();
        (link.keys.view, link.keys.top) = (None, Top::Unknown);
    }
    /// After a key change committed (spec §5.5 S4): the table against the
    /// pending entry `p`, first, before the vault outgoing.
    pub(super) fn keys_after_change(&mut self, p: &anchor::PendingLine) {
        let Some(mut link) = self.sync.take() else {
            return;
        };
        link.keys.off = None;
        self.key_table(&mut link, Some(p));
        // The holds follow the committed entry too, its `ks` and whether it
        // clears the pending gate, so that the vault outgoing of this very
        // change is written at S4: a consented "on" at `on.c` over a cut or
        // nothing is not KeySyncGone (row 8), whatever the confirmed line
        // still says until S5.
        let gate = self.pending_gate().is_some() && !(p.clears.g || p.clears.s);
        let held = self.key_hold_with(&link, p.state.ks, gate);
        if link.keys.held && !held {
            link.in_stamp = None;
        }
        link.keys.held = held;
        self.sync = Some(link);
    }
    /// S-PRUNE's yes (spec §7.19): `prune.request` with this state's epoch.
    pub fn request_prune(&self) -> Result<()> {
        let link = self.sync.as_ref().ok_or(KEYSYNC_NOSYNC)?;
        let bytes = syncfile::render_prune_request(&self.id, self.key_state.epoch);
        syncfile::replace_file(&link.dir.join(PRUNE_REQUEST), &bytes)
            .map_err(|_| "정리 요청을 쓰지 못했습니다. 동기화 폴더를 확인하세요.")
    }
    /// Whether S-PRUNE is asked after this key change (spec §7.19): a
    /// removal, or a union that removed keys of this PC (its write added a
    /// tombstone), on a GOYOKS01 vault that syncs. A union that removes
    /// nothing never asks, whatever earlier removals the file records.
    pub fn prune_offered(&self) -> bool {
        self.ks01()
            && self.sync.is_some()
            && self.tombs_added
            && self
                .key_file
                .header()
                .is_some_and(|h| matches!(h.kind as u8, 4 | 9))
    }
    /// [다른 PC가 없어 이 PC 상태로 올리기…] is offered (spec §7.15a, §9.1).
    pub(super) fn supersede_offered(&self) -> bool {
        self.supersede_candidate().is_some()
    }
    /// The candidate the supersede would answer (spec §7.15a): the server's
    /// top key record when it is a G1-gated successor (its gate pending, or
    /// dropped) or a KeyFork whose option 2 needs G1; that removes none of
    /// this PC's keys (R = ∅), carries no removal of a key this PC never
    /// knew (T_new = ∅) and is no silent jump; on a GOYOKH01 session only a
    /// GOYOKS01 successor, with §7.9's conditions that magic needs (every
    /// slot a PIN slot in PIN mode, vault sync, a capable helper on a line
    /// that serves key ops, no pending off). Public bytes only: the
    /// candidate is never opened.
    pub(super) fn supersede_candidate(&self) -> Option<(KeyState, KeyFile)> {
        if self.unconfirmed()
            || self.local_rollback
            || self.restored
            || self.restore_held
            || self.gate_login.is_some()
        {
            return None;
        }
        let own = self.key_file.header().filter(|h| !h.slots.is_empty())?;
        let link = self.sync.as_ref()?;
        let Top::Key { state, class, .. } = link.keys.top else {
            return None;
        };
        let (file, _) = self.server_key_file()?;
        let t = file.header().filter(|t| t.state() == state)?;
        let named = self
            .anchor
            .lines
            .gate
            .as_ref()
            .filter(|g| (g.epoch, g.tag) == (state.epoch, state.tag))
            .map(|g| g.state);
        let fork = match class {
            KeyClass::Successor {
                gate: Some(GateKind::G1),
                ..
            } => false,
            KeyClass::Refused(USER_DROPPED) if named == Some(GateState::Dropped) => false,
            KeyClass::KeyFork => true,
            _ => return None,
        };
        let chained = file.chain_ok(self.keys.current());
        if !fork && !chained {
            return None;
        }
        let line = self.anchor.lines.vault.as_ref();
        let checked = gate::public_checks(
            &self.key_file,
            line,
            &file,
            fork,
            chained,
            self.gated_epoch(),
        )
        .ok()?;
        let g = &checked.gates;
        if checked.removed_authorizer.is_some()
            || !g.removed.is_empty()
            || !g.unknown.is_empty()
            || g.jump
            || (g.added.is_empty() && !g.policy && !g.slot)
        {
            return None;
        }
        if own.magic != Magic::Ks01 {
            let ready = !fork
                && t.magic == Magic::Ks01
                && own.pin()
                && own.slots.iter().all(|s| s.pin())
                && self.format == super::Format::V2
                && helper_fresh(link)
                && link.keys.line0().is_some()
                && !self.off_pending();
            if !ready {
                return None;
            }
        }
        Some((state, file))
    }
    /// R0 of the supersede (spec §5.5, §7.15a): the candidate is still the
    /// one the flow named and is still offered; the vault channel is halted
    /// by nothing but a head under the candidate's own state (a header key
    /// ID in its list and not in this PC's bundle, at its epoch), else
    /// S-SUPERSEDE-HEAD. Ok: the candidate's tombstones and the `sup`
    /// entries of the key IDs of its list that this PC's bundle lacks.
    pub(super) fn supersede_check(
        &self,
        named: KeyState,
    ) -> Result<(Vec<super::keyfile::Tombstone>, Vec<anchor::Sup>)> {
        let (state, file) = self
            .supersede_candidate()
            .filter(|(s, _)| *s == named)
            .ok_or(NOT_SUPERSEDABLE)?;
        let t = file.header().ok_or(NOT_SUPERSEDABLE)?;
        let ours: Vec<[u8; 16]> = self
            .keys
            .keys()
            .iter()
            .map(|k| super::keyfile::key_id(&self.id, k))
            .collect();
        let theirs: Vec<[u8; 16]> = t
            .key_ids
            .iter()
            .filter(|i| !ours.contains(i))
            .copied()
            .collect();
        if let Some(head) = self.halted_head()
            && !(theirs.contains(&head.key_id) && head.epoch == state.epoch)
        {
            return Err(super::refuse(
                SUPERSEDE_HEAD,
                vec![head.epoch.to_string(), head.key_prefix()],
            ));
        }
        let sup = theirs
            .into_iter()
            .map(|keyid| anchor::Sup {
                keyid,
                epoch: state.epoch,
                tag: state.tag,
            })
            .collect();
        Ok((t.tombstones.clone(), sup))
    }
    /// The rollout reminder (spec §7.18): this PC changed this GOYOKS01 key
    /// file (the anchor's `p` on the confirmed state the session holds),
    /// and the user has not yet said every PC took it. None otherwise, and
    /// never before the key file is confirmed.
    pub fn rollout(&self) -> Option<Rollout> {
        let line = self.anchor.lines.vault.as_ref()?;
        if !line.state.flags.p
            || line.state.key_state() != self.key_state
            || !self.ks01()
            || self.unconfirmed()
            || self.restored
        {
            return None;
        }
        let h = self.key_file.header()?;
        Some(match h.kind {
            Kind::Remove => Rollout::Remove(self.key_code()?),
            Kind::Password | Kind::Pair => Rollout::Plain,
            Kind::SyncOn => Rollout::Maybe(self.key_code()?),
            _ => Rollout::Code(self.key_code()?),
        })
    }
    /// [모든 PC 확인 완료] (`KEY_ROLLOUT_DONE`, spec §7.18): the anchor's
    /// `p` cleared on the confirmed state this session holds; the change
    /// now counts as complete on this PC.
    pub fn rollout_done(&mut self) -> Result<()> {
        let state = self.key_state;
        self.anchor_strict(&mut |lines| match lines.vault.as_mut() {
            Some(l) if l.state.flags.p && l.state.key_state() == state => {
                l.state.flags.p = false;
                true
            }
            _ => false,
        })
    }
    /// "열쇠 변경 자동 적용 (이 서버를 믿음)" (spec §2.30): this PC's
    /// preference for this vault, the confirmed line's `auto`.
    pub fn auto_apply(&self) -> bool {
        self.anchor
            .lines
            .vault
            .as_ref()
            .is_some_and(|v| v.state.auto)
    }
    /// Turns it on or off in this PC's anchor, in the confirmed line and in
    /// a pending one, which becomes the confirmed line when it lands. On
    /// only for a GOYOKS01 key file this PC confirmed (AUTO_NOT_SYNCED);
    /// off always. The UI asks S-AUTO-APPLY before an on, and nothing
    /// before an off.
    pub fn set_auto_apply(&mut self, on: bool) -> Result<()> {
        if on && (!self.ks01() || self.unconfirmed() || self.restored) {
            return Err(AUTO_NOT_SYNCED);
        }
        self.anchor_strict(&mut |lines| {
            let Some(v) = lines.vault.as_mut() else {
                return false;
            };
            v.state.auto = on;
            if let Some(p) = lines.pending.as_mut() {
                p.state.auto = on;
            }
            true
        })?;
        if self.auto_apply() != on {
            return Err(AUTO_NOT_SYNCED);
        }
        Ok(())
    }
    /// A server key file that would wait for its gate is taken as if the
    /// gate had passed (spec §2.30): only with `auto` on, only from the
    /// server channel (never a USB file), only for a file that descends
    /// from this PC's (no fork), only on a GOYOKS01 key file this PC
    /// confirmed (never a bootstrap or a Restore). Every public check has
    /// run before this is asked, and runs again at the write.
    ///
    /// The server channel is this session's key view, not the source a
    /// caller names: the check must be of the server's file of record
    /// `seq` that the view holds now, in exactly the checked state. A file
    /// from anywhere else (or a view that moved on since) is not trusted,
    /// whatever `Source` it was checked under.
    pub fn trusts(&self, check: &super::AdoptCheck) -> bool {
        let served = match &check.source {
            super::Source::Server { seq } => self.server_key_file().is_some_and(|(f, n)| {
                n == *seq && f.header().is_some_and(|h| h.state() == check.other)
            }),
            super::Source::File(_) => false,
        };
        served
            && !check.fork
            && self.auto_apply()
            && self.ks01()
            && !self.unconfirmed()
            && !self.restored
    }
}
/// What S-ROLLOUT says (spec §7.18), by the gate the change this PC made
/// needs on the other PCs, with this PC's key code where one may be typed:
/// a removal (the removed keys picked, or the code on a PC that never knew
/// one of them), an addition or a re-seed (the code), key-file sync on, a
/// re-upload or a supersede (kind 6: the code only on a PC that still keeps
/// its key file to itself, none on one already on), or a password change
/// or a pairing (no gate).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Rollout {
    Remove(String),
    Code(String),
    Maybe(String),
    Plain,
}
/// A helper with `features=keys` wrote its status within 10 minutes.
fn helper_fresh(link: &SyncLink) -> bool {
    let now = crate::otp::now().unwrap_or(0);
    link.status.is_some_and(|s| {
        s.keys
            && s.heartbeat.saturating_add(HELPER_FRESH) >= now
            && s.heartbeat <= now.saturating_add(HELPER_FRESH)
    })
}
/// Deletes `path`; true when it is gone.
fn remove(path: &Path) -> bool {
    match fs::remove_file(path) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}
