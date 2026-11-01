//! The server's key file at login (spec v3 §5.1 step 10, §5.2 step 9(b) and
//! its second entry point, §5.3 `UnlockProof`, §7.15; security-key build).
//!
//! Precheck keeps the key record `kview` shows as a snapshot. A login whose
//! own key file opens returns an `UnlockProof` with the session, so the
//! flow can take that snapshot with the unlock's touch and no second OTP
//! code (`Session::reauth_from_unlock`), through the attended accept of
//! §7.15 (the adopt engine with `Source::Server`). A login whose own key
//! file does not open returns a `ServerEntry` when the snapshot could be a
//! successor: the failed-unlock entry (S-TRY-SERVER-KEY, and S-TRY-OTHERKEY
//! for a key only that file lists) opens the snapshot with the typed
//! password and the touch, takes this PC's data keys from it, requires rule
//! D and the local vault file under them, builds the session as this PC's
//! own and installs the snapshot as a plain successor behind its gate, in
//! one call: nothing of the session is returned unless that file landed.
//! Nothing here asks a question, and nothing is installed in a bootstrap.
use super::{
    AnchorClass, Given, KeyClass, Prepared, Session,
    gate::{self, GateAnswer, GateChoice, GateKind},
    keyfile::{
        Bundle, Code, EPOCH_SILENT, EPOCH_WINDOW, KeyFile, KeyHeader, KeyState, Kind, Magic, Touch,
        is_sync_key_file, key_id,
    },
    rotate::{Acks, AdoptClass, Adopted, Consent, ForkOption, GatePass, Source, UnionPassword},
};
use crate::{
    crypto::{AUTH_ERROR, Result},
    fido::{AssertRequest, salt},
    syncfile::{self, KEY_VIEW, MAX_KEY_VIEW, RecordKind},
};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

/// The server's key file does not hold this PC's current data key in its
/// chain (rule D): it is not on top of this PC's key file.
pub const SERVER_KEY_UNCHAINED: &str = "서버의 새 열쇠 파일은 이 PC의 열쇠 파일에서 이어진 것이 아니어서 열지 않았습니다. 이 PC의 비밀번호와 보안 키로 연 뒤 '열쇠 관리'를 확인하세요. 그런 변경을 한 적이 없다면 서버의 열쇠 파일이 위조되었을 수 있습니다.";
/// The server's key file lacks a data key of this PC's key file (more than
/// the key ring holds since): the failed-unlock entry cannot build the
/// session from it (spec §7.15 step 4, S-OLDPASS-OWN's case).
pub const SERVER_KEY_OLD_KEYS: &str = "서버의 새 열쇠 파일에는 이 PC의 열쇠 파일에 있는 예전 열쇠가 모두 들어 있지 않아 이 방법으로는 열 수 없습니다. 이 PC에서 쓰던 예전 비밀번호로 연 뒤 '열쇠 관리'의 [받기…]로 받으세요.";
/// The server's key file can be taken here only as a plain successor.
pub const SERVER_KEY_NOT_SUCCESSOR: &str = "서버의 열쇠 파일은 이 PC의 열쇠 파일을 바로 이어받은 것이 아니어서 이 방법으로는 받을 수 없습니다. 이 PC에서 쓰던 비밀번호로 연 뒤 '열쇠 관리'의 [받기…]로 받으세요.";
/// The OTP code was typed more than three minutes before the failed-unlock
/// entry started: not a failed attempt (nothing was derived).
pub const OTP_STALE: &str = "OTP 번호를 입력한 지 3분이 넘었습니다. 새 OTP 번호로 다시 여세요.";
/// The result turns key-file sync on here: S-KEYSYNC-ON is asked now that
/// the gate passed, and the call made again with the yes.
pub const KEYSYNC_CONSENT: &str =
    "열쇠 파일 동기화를 켜는 열쇠 파일입니다. 받기 전에 확인이 필요합니다.";

/// What precheck read of `kview` (spec §5.1 step 10): the top key record's
/// key file bytes and record number, and where they were read.
#[derive(Clone)]
pub(super) struct Snapshot {
    pub bytes: Vec<u8>,
    pub seq: u64,
    pub path: PathBuf,
}
impl Snapshot {
    fn file(&self) -> Result<KeyFile> {
        KeyFile::from_bytes(&self.path, self.bytes.clone())
    }
}

/// Step 10 of precheck: a hardware key file this PC confirmed (`t`; never
/// in a bootstrap, nor for a changed key file waiting for its gate or a
/// rollback) and a key record of this vault in `kview` within the window.
/// Nothing in it is trusted here.
pub(super) fn snapshot(
    vault: &Path,
    key: &KeyFile,
    seen: &super::anchor::Seen,
) -> Option<Snapshot> {
    let h = key.header().filter(|h| h.magic.hardware())?;
    if seen.forgotten
        || matches!(
            seen.class,
            AnchorClass::Bootstrap | AnchorClass::Gated(_) | AnchorClass::Rollback
        )
        || !seen.confirmed().is_some_and(|l| l.state.flags.t)
    {
        return None;
    }
    let dir = syncfile::sync_dir(vault)?;
    let path = dir.join(KEY_VIEW);
    let bytes = syncfile::read_bounded(&path, MAX_KEY_VIEW).ok()?;
    let view = syncfile::parse_key_view(&bytes, &h.vault_id)?;
    let record = view
        .top(&h.vault_id)
        .filter(|r| r.kind == RecordKind::Key && !r.damaged)?;
    is_sync_key_file(record.payload, &h.vault_id)?;
    let file = KeyFile::from_bytes(&path, record.payload.to_vec()).ok()?;
    if file.header()?.epoch > h.epoch.saturating_add(EPOCH_WINDOW) {
        return None;
    }
    Some(Snapshot {
        bytes: record.payload.to_vec(),
        seq: record.number,
        path,
    })
}

/// What a login returns to its own flow with the session (spec §5.3): the
/// password and the OTP step the unlock verified, and the snapshot. Single
/// use, bound to that session, zeroized on drop, never kept in the session.
pub struct UnlockProof {
    pub(super) session: u64,
    pub(super) password: Zeroizing<String>,
    pub(super) otp_step: Option<u64>,
    pub(super) snapshot: Option<Snapshot>,
}

impl UnlockProof {
    /// The login's password, for a fresh Reauth of the same flow (spec
    /// §9.2a "The Reauth's remaining life").
    pub fn password(&self) -> Zeroizing<String> {
        self.password.clone()
    }
}

/// A login that did not open (spec §5.2): the error, and the failed-unlock
/// entry when the server's key file could be a successor.
pub struct Failed {
    pub error: &'static str,
    pub entry: Option<Box<ServerEntry>>,
}
impl From<&'static str> for Failed {
    fn from(error: &'static str) -> Self {
        Self { error, entry: None }
    }
}

/// The failed-unlock entry (spec §5.2 second entry point): the precheck's
/// files and snapshot, and what was typed. Built only by a login whose own
/// key file did not open with that password and touch (S-TRY-SERVER-KEY),
/// or for S-TRY-OTHERKEY after Windows' cancel, when own was never tried.
/// Lives only in the login flow's frame; zeroized on drop.
pub struct ServerEntry {
    prepared: Prepared,
    password: Zeroizing<String>,
    otp: Zeroizing<String>,
    otp_time: u64,
    confirmed_older: Option<[u8; 32]>,
    /// The touch was of a key own lists (S-TRY-SERVER-KEY): the gate pick
    /// marks it.
    touched: Option<u8>,
    /// `start` checked the OTP code's time window.
    otp_in_time: bool,
    /// The OTP step this entry's own earlier call verified and saved.
    otp_spent: Option<u64>,
}

impl Prepared {
    /// The seed the snapshot gives credential `cred` when it differs from
    /// `seed` (a re-seed on another PC; spec §8.3).
    pub(super) fn server_seed(&self, cred: &[u8], seed: &[u8; 32]) -> Option<[u8; 32]> {
        let file = self.server.as_ref()?.file().ok()?;
        let s = file.header()?.slots.iter().find(|s| s.cred_id == cred)?;
        (s.seed != *seed).then_some(s.seed)
    }
    /// The same files and snapshot again, for one more attempt.
    fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            source: self.source.clone(),
            key_path: self.key_path.clone(),
            key: KeyFile::from_bytes(self.key.path(), self.key.bytes().to_vec())?,
            key_temp: self.key_temp.clone(),
            check: self.check,
            seen: self.seen.clone(),
            server: self.server.clone(),
            fetched: self.fetched,
        })
    }
    /// The snapshot can be taken here as a plain successor (spec §5.1 step
    /// 10, §5.2): a higher epoch, or the same with another current key; the
    /// public checks against this PC's key file passed unrelaxed, with no
    /// carry; and its gate, judged on public bytes. None otherwise. Its
    /// pair records are pinned once it is open (rule D chains it).
    fn successor_gate(&self) -> Option<(KeyFile, Option<GateKind>)> {
        let own = self.key.header()?;
        let file = self.server.as_ref()?.file().ok()?;
        let t = file.header()?;
        if !(t.epoch > own.epoch || (t.epoch == own.epoch && t.key_ids[0] != own.key_ids[0])) {
            return None;
        }
        let line = self.seen.confirmed();
        let gated = line.as_ref().map(|l| l.state.gated);
        let checked =
            gate::public_checks(&self.key, line.as_ref(), &file, false, false, gated).ok()?;
        if !checked.clean() || !checked.missing_pairs.is_empty() || !checked.gates.kept.is_empty() {
            return None;
        }
        let kind = match checked.gates.needed() {
            Some(GateKind::G2) if gate::g2_allowed(&self.seen.lines) => Some(GateKind::G2),
            Some(_) => Some(GateKind::G1),
            None => None,
        };
        Some((file, kind))
    }
    /// S-TRY-OTHERKEY is offered (spec §5.2): after Windows' cancel of the
    /// unlock's ceremony, for a snapshot that can be taken as a successor
    /// and lists live, non-suspended keys this PC's key file lacks.
    pub fn offers_other_key(&self) -> bool {
        self.successor_gate()
            .is_some_and(|(file, _)| !self.other_keys(&file).is_empty())
    }
    /// Those keys: the snapshot's own numbers and credentials.
    fn other_keys(&self, file: &KeyFile) -> Vec<(u8, Vec<u8>, [u8; 32])> {
        let (Some(own), Some(t)) = (self.key.header(), file.header()) else {
            return Vec::new();
        };
        t.slots
            .iter()
            .enumerate()
            .filter(|(j, s)| {
                (t.suspended >> j) & 1 == 0 && !own.slots.iter().any(|o| o.cred_id == s.cred_id)
            })
            .map(|(_, s)| (s.number, s.cred_id.clone(), s.seed))
            .collect()
    }
    /// The entry of S-TRY-OTHERKEY: own was never tried.
    pub fn other_key_entry(
        self,
        password: &str,
        otp: &str,
        otp_time: u64,
        confirmed_older: Option<[u8; 32]>,
    ) -> Option<ServerEntry> {
        self.offers_other_key().then(|| ServerEntry {
            prepared: self,
            password: Zeroizing::new(password.to_owned()),
            otp: Zeroizing::new(otp.to_owned()),
            otp_time,
            confirmed_older,
            touched: None,
            otp_in_time: false,
            otp_spent: None,
        })
    }
}

impl ServerEntry {
    /// The OTP code's time window, checked once when the entry starts (after
    /// S-TRY-SERVER-KEY's yes or S-TRY-OTHERKEY's touch, before the gate
    /// question), as a login checks it once its touch is in: the gate
    /// question, a wrong code typed again and S-KEYSYNC-ON that follow do
    /// not run it out. The code itself is checked at every call, as of when
    /// it was typed, against the vault file's last step (the step this
    /// entry's own earlier call saved passes again). OTP_STALE is no failed
    /// attempt.
    pub fn start(&mut self) -> Result<()> {
        if self.otp_in_time {
            return Ok(());
        }
        let server_otp = self
            .prepared
            .server
            .as_ref()
            .and_then(|s| s.file().ok())
            .is_some_and(|f| f.uses_otp());
        if self.prepared.key.uses_otp() || server_otp {
            let now = crate::otp::now()?;
            if now.saturating_sub(self.otp_time) > super::OTP_TYPED_MAX
                || self.otp_time > now.saturating_add(5)
            {
                return Err(OTP_STALE);
            }
        }
        self.otp_in_time = true;
        Ok(())
    }
    /// The snapshot's gate (spec §7.15a), asked after S-TRY-SERVER-KEY's
    /// yes or S-TRY-OTHERKEY's ceremony and before the open: the kind, the
    /// keys S-LOSTPICK offers (this PC's confirmed ones only) with the key
    /// the unlock touched, and the snapshot's epoch (public). None needs
    /// none, and so does a snapshot taken under "열쇠 변경 자동 적용" (spec
    /// §2.30), which `login_via_server` judges once it is open.
    pub fn gate(&self) -> Option<(GateKind, Vec<GateChoice>, Option<u8>, u64)> {
        if self.trusted() {
            return None;
        }
        let (file, kind) = self.prepared.successor_gate()?;
        let choices = self
            .prepared
            .seen
            .confirmed()
            .map(|l| gate::choices(&l.state.slots))
            .unwrap_or_default();
        Some((kind?, choices, self.touched, file.header()?.epoch))
    }
    /// This PC turned on "열쇠 변경 자동 적용" for the vault, on its
    /// GOYOKS01 key file (spec §2.30): the gate is not asked.
    pub fn trusted(&self) -> bool {
        self.prepared.key.magic() == Some(Magic::Ks01)
            && self.prepared.seen.confirmed().is_some_and(|l| l.state.auto)
    }
    /// S-TRY-OTHERKEY's ceremony: the keys only the snapshot lists, with
    /// its seeds.
    pub fn other_request(&self, owner: isize) -> Option<AssertRequest> {
        let (file, _) = self.prepared.successor_gate()?;
        let t = file.header()?;
        let allow = self
            .prepared
            .other_keys(&file)
            .into_iter()
            .map(|(_, cred, seed)| (cred, salt(&t.vault_id, &seed), None))
            .collect();
        AssertRequest::new(owner, allow, t.pin()).ok()
    }
    /// S-TRY-OTHERKEY names them by the snapshot's numbers (keys new to
    /// this PC).
    pub fn other_numbers(&self) -> Vec<u8> {
        self.prepared
            .successor_gate()
            .map(|(file, _)| self.prepared.other_keys(&file))
            .unwrap_or_default()
            .into_iter()
            .map(|(n, ..)| n)
            .collect()
    }
    /// Whether own was tried and did not open (S-TRY-SERVER-KEY's path):
    /// the failed attempt there is a wrong password or key; on
    /// S-TRY-OTHERKEY's path it is S-TRY-OTHERKEY-FAILED.
    pub fn own_tried(&self) -> bool {
        self.touched.is_some()
    }
    /// The vault and key paths of the login, for the screen.
    pub fn paths(&self) -> (&Path, &Path) {
        (&self.prepared.source, &self.prepared.key_path)
    }
}

/// The server's key file is older than this PC's vault file (spec §7.17:
/// the local vault is the floor).
pub const FETCHED_OLDER: &str = "서버의 열쇠 파일이 이 PC의 금고보다 오래되었습니다.";
/// A key file from the server that this PC's record of the vault would hold
/// (a fork, an older state, or one that needs a gate): not restored from.
pub const FETCHED_HELD: &str = "서버에서 받은 열쇠 파일이 이 PC가 기록해 둔 이 금고의 열쇠와 맞지 않아 열지 않았습니다. 이 PC의 열쇠 파일(열쇠 백업)로 연 뒤 '열쇠 관리'에서 받으세요.";
/// No key file from the server next to the vault file.
pub const FETCHED_NONE: &str = "이 금고 파일의 동기화 폴더에 서버에서 받은 열쇠 파일이 없습니다. goyo-sync의 '이 PC로 가져오기…'로 다시 가져오거나, 다른 PC의 열쇠 파일을 USB로 가져와 금고 옆에 두세요.";
/// What a session from the server's key file holds until it is saved.
pub const FETCHED_UNSAVED: &str = "서버에서 받은 열쇠 파일을 이 PC에 저장하기 전에는 항목을 고치거나 저장하지 않습니다. 위 칸의 '코드 확인'(또는 '저장하기')으로 먼저 저장하세요.";
/// The save step's path is in a sync folder.
pub const FETCHED_IN_SYNC: &str = "열쇠 파일은 동기화 폴더 밖에 저장하세요. 다른 곳을 고르세요.";
/// The save step never replaces a file.
pub const FETCHED_EXISTS: &str = "같은 이름의 파일이 이미 있습니다. 다른 이름을 고르세요.";

/// The key view next to `vault` when it holds a key record of `vault`'s
/// vault (spec §7.17): Restore offers it as the key source "서버에서 받은
/// 열쇠 파일 (확인 전)". Nothing in it is trusted here.
pub fn fetched_key(vault: &Path) -> Option<PathBuf> {
    fetched(vault).map(|(path, _)| path)
}
fn fetched(vault: &Path) -> Option<(PathBuf, Vec<u8>)> {
    let id = super::vault_id(vault)?;
    let path = syncfile::sync_dir(vault)?.join(KEY_VIEW);
    let bytes = syncfile::read_bounded(&path, MAX_KEY_VIEW).ok()?;
    let view = syncfile::parse_key_view(&bytes, &id)?;
    let record = view
        .top(&id)
        .filter(|r| r.kind == RecordKind::Key && !r.damaged)?;
    is_sync_key_file(record.payload, &id)?;
    Some((path, record.payload.to_vec()))
}
/// Phase 1 of a Restore of `backup` with the server's key file in its sync
/// folder (spec §7.17): read-only until G1, nothing written outside the
/// sync folder. The vault file is the floor (its key in the file, its
/// epoch not above the file's); this PC's record of the vault refuses a
/// file it would hold (FETCHED_HELD), and a pending line refuses it but
/// for this file's own `tofu` entry, whose save is resumed with no second
/// code.
pub fn prepare_restore_fetched(backup: &Path) -> Result<Prepared> {
    let source = super::normalized(backup)?;
    let (key_path, bytes) = fetched(&source).ok_or(FETCHED_NONE)?;
    let key = KeyFile::from_bytes(&key_path, bytes)?;
    let h = key.header().ok_or(FETCHED_NONE)?.clone();
    let (check, seen) = super::precheck(&source, &key, true, false)?;
    let data = super::read_bounded(&source, super::MAX_FILE)?;
    if let Ok((_, super::Header::Keyed { state, .. })) = super::read_header(&data)
        && state.epoch > h.epoch
    {
        return Err(FETCHED_OLDER);
    }
    if matches!(
        seen.class,
        AnchorClass::Fork | AnchorClass::Rollback | AnchorClass::Gated(_)
    ) {
        return Err(FETCHED_HELD);
    }
    if let Some(p) = &seen.lines.pending
        && !(p.src == super::anchor::Src::Tofu && p.state.key_state() == h.state())
    {
        return Err(super::RESTORE_PENDING);
    }
    Ok(Prepared {
        source,
        key_path,
        key,
        key_temp: None,
        check,
        seen,
        server: None,
        fetched: true,
    })
}
/// What the login screen reads of the server's key file next to `vault`
/// (its OTP flag), as of a key file at a path.
pub fn fetched_key_info(vault: &Path) -> Option<super::KeyInfo> {
    let (path, bytes) = fetched(vault)?;
    super::keyfile::key_info_of(&path, bytes)
}
/// Whether this PC's record of vaults (the anchor) holds a confirmed line
/// of `vault`'s vault: this PC opened it before, so it is no new PC. A
/// line that only waits (a save cut off after its code) is not one.
pub fn known_here(vault: &Path) -> bool {
    let Some(id) = super::vault_id(vault) else {
        return false;
    };
    let Some(dir) = super::anchor::locate() else {
        return false;
    };
    matches!(
        super::anchor::read(&dir),
        Ok(super::anchor::Parsed::Doc(doc)) if doc.lines(&id).vault.is_some()
    )
}
/// Whether `key` is the key view in `vault`'s sync folder.
pub fn is_fetched_key(vault: &Path, key: &Path) -> bool {
    syncfile::sync_dir(vault).is_some_and(|d| d.join(KEY_VIEW) == key)
}

impl Session {
    /// The session's key file came from the server's key view and is not
    /// saved on this PC yet (spec §7.17).
    pub fn fetched_unsaved(&self) -> bool {
        self.fetched
    }
    /// G1 of a session whose key file came from the server's key view, as
    /// the TOFU pass checks it, with nothing written (the save dialog comes
    /// next). None: S-TOFU-NOPC's yes, or a file this PC confirmed.
    pub fn tofu_check(&self, code: Option<&Code>) -> Result<()> {
        if !self.fetched && !self.tofu {
            return Err(gate::GATE_NOT_PENDING);
        }
        if let Some(code) = code.filter(|_| self.tofu)
            && !gate::code_matches(code, &self.id, self.keys.current(), self.key_state)
        {
            return Err(gate::GATE_CODE_WRONG);
        }
        Ok(())
    }
    /// The TOFU pass of a session whose key file came from the server's
    /// key view (spec §7.17), with the path the user picked for it, never
    /// in a sync folder and never over a file: the anchor's `tofu` pending
    /// entry (or this file's own entry a crash left), then the key file
    /// written and read back (a crash after that write: the file that
    /// entry names, taken as it is when it holds exactly these bytes), the
    /// restored vault file, and the entry promoted with `t` and `gated`. A
    /// state this PC confirmed writes only the two files. Ends TOFU, and
    /// starts vault sync as an unlock of the saved pair would.
    pub fn tofu_save(&mut self, code: Option<&Code>, path: &Path) -> Result<()> {
        if !self.fetched {
            return Err(gate::GATE_NOT_PENDING);
        }
        self.tofu_check(code)?;
        let dest = super::normalized(path)?;
        super::distinct(&dest, &self.path)?;
        let in_sync = |p: &Path| {
            p.ancestors().skip(1).any(|a| {
                a.file_name()
                    .is_some_and(|n| n.to_string_lossy().to_lowercase().ends_with(".sync"))
            })
        };
        if in_sync(&dest) {
            return Err(FETCHED_IN_SYNC);
        }
        let h = self.key_file.header().cloned().ok_or(AUTH_ERROR)?;
        let state = self.key_state;
        let bytes = self.key_file.bytes().to_vec();
        // A save cut off after it wrote its key file: the same name again
        // takes that file when the pending entry names it and it holds
        // exactly these bytes. Any other file there is never replaced.
        let written = dest.exists()
            && self.anchor.lines.pending.as_ref().is_some_and(|p| {
                p.src == super::anchor::Src::Tofu
                    && p.state.key_state() == state
                    && p.kpath.is_some()
                    && p.kpath == super::anchor::kpath_of(&dest)
            })
            && super::read_bounded(&dest, super::KEY_FILE_LIMIT)
                .ok()
                .as_deref()
                == Some(&bytes[..]);
        if dest.exists() && !written {
            return Err(FETCHED_EXISTS);
        }
        let resumed = self
            .anchor
            .lines
            .pending
            .as_ref()
            .is_some_and(|p| p.src == super::anchor::Src::Tofu && p.state.key_state() == state);
        let trust = self.tofu || resumed;
        // The pending entry first, naming the key file it writes.
        let mut entry = None;
        if trust {
            let mut p = super::anchor::pending_of(&h, None, None, super::anchor::kpath_of(&dest));
            (p.src, p.pw) = (super::anchor::Src::Tofu, None);
            p.state.flags.t = true;
            let forgotten = self.forgotten;
            self.anchor_strict(&mut |lines| {
                if lines.pending.as_ref().is_some_and(|q| {
                    q.src == super::anchor::Src::Tofu && q.state.key_state() == state
                }) {
                    entry = lines.pending.clone();
                    return false;
                }
                let mut p = p.clone();
                p.base = if forgotten {
                    (lines.vault, lines.gate, lines.forget) = (None, None, true);
                    None
                } else {
                    lines.vault.as_ref().map(|c| (c.state.epoch, c.state.tag))
                };
                entry = Some(p.clone());
                lines.pending = Some(p);
                true
            })?;
        }
        // The key file, read back.
        let _lock = super::FileLock::acquire(&dest)?;
        if !written {
            super::atomic_write(&dest, &bytes, false).map_err(<&'static str>::from)?;
        }
        if super::read_bounded(&dest, super::KEY_FILE_LIMIT)
            .ok()
            .as_deref()
            != Some(&bytes[..])
        {
            if !written {
                let _ = std::fs::remove_file(&dest);
            }
            return Err(super::KEY_NOT_SAVED);
        }
        self.key_file = KeyFile::from_bytes(&dest, bytes)?;
        self.key_path = dest;
        (self.fetched, self.tofu, self.forgotten) = (false, false, false);
        self.g2_spent.set(false);
        // The restored vault file, then the entry promoted.
        let deferred = self.deferred;
        self.finish_deferred();
        if let Some(p) = entry {
            let current = key_id(&self.id, self.keys.current());
            let mut v = p.promoted(None);
            if deferred.seal {
                v.vkey = Some(current);
                if h.resume != [0; 32] {
                    v.state.consumed = Some(h.resume);
                }
            }
            self.anchor_strict(&mut |lines| {
                if lines.pending.as_ref() == Some(&p) {
                    lines.pending = None;
                }
                lines.vault = Some(v.clone());
                true
            })?;
        }
        // Vault sync starts now, as at an unlock of the saved pair.
        self.link_saved();
        Ok(())
    }
}

impl Session {
    /// Phase 3 of a login with a key file that needs a security key (spec
    /// §5.2), returning with the session its `UnlockProof`; a failure that
    /// the server's key file may explain returns the failed-unlock entry
    /// (not in a bootstrap, and only when the snapshot could be a plain
    /// successor).
    pub fn login_proved(
        prepared: Prepared,
        password: &str,
        input: &str,
        otp_time: u64,
        confirmed_older: Option<[u8; 32]>,
        touch: &Touch,
    ) -> std::result::Result<(Self, UnlockProof), Failed> {
        if password.len() > 1024 {
            return Err(AUTH_ERROR.into());
        }
        if let Some(refusal) = prepared.key.refusal() {
            return Err(refusal.into());
        }
        if prepared.key.uses_otp() && !super::otp_format(input) {
            return Err(AUTH_ERROR.into());
        }
        let opened = match prepared.key.open(password, Some(touch)) {
            Ok(opened) => opened,
            Err(error) => {
                let touched = prepared
                    .key
                    .header()
                    .and_then(|h| h.slots.iter().find(|s| s.cred_id == touch.cred_id))
                    .map(|s| s.number);
                let entry = (error == AUTH_ERROR
                    && touched.is_some()
                    && prepared.successor_gate().is_some())
                .then(|| {
                    Box::new(ServerEntry {
                        prepared,
                        password: Zeroizing::new(password.to_owned()),
                        otp: Zeroizing::new(input.to_owned()),
                        otp_time,
                        confirmed_older,
                        touched,
                        otp_in_time: false,
                        otp_spent: None,
                    })
                });
                return Err(Failed { error, entry });
            }
        };
        let snapshot = prepared.server.clone();
        let given = Given {
            bundle: opened.bundle,
            state: opened.state,
            slot: opened.slot,
            otp_in_time: false,
            otp_spent: None,
        };
        let factors = (password, input, otp_time);
        let s = Self::load(
            prepared,
            factors,
            Some(touch),
            confirmed_older,
            None,
            Some(given),
        )?;
        let proof = UnlockProof {
            session: s.serial,
            password: Zeroizing::new(password.to_owned()),
            otp_step: s.uses_otp().then_some(s.last),
            snapshot,
        };
        Ok((s, proof))
    }
    /// The snapshot the login takes now (spec §5.2 step 9(b), §7.15 at
    /// login): exactly the key record `kview` shows to this session, judged
    /// a successor (with a carry or not) with rule D; never in TOFU, a held
    /// session or gate-pending mode. None otherwise: a fork or a refused
    /// file asks nothing at login.
    pub fn login_candidate(&self, proof: &UnlockProof) -> Option<(KeyFile, u64)> {
        let snap = proof.snapshot.as_ref()?;
        if proof.session != self.serial
            || self.unconfirmed()
            || self.gate_pending()
            || self.local_rollback
            || self.restored
        {
            return None;
        }
        let (file, seq) = self.server_key_file()?;
        let same = seq == snap.seq && file.bytes() == snap.bytes.as_slice();
        let successor = matches!(self.server_class(), Some(super::KeyClass::Successor { .. }));
        (same && successor).then_some((file, seq))
    }
    /// The failed-unlock entry (spec §5.2, §7.15 step 4): the snapshot
    /// opened with the typed password and `touch`; this PC's data keys
    /// taken from it (every key ID this PC's key file lists); rule D under
    /// this PC's current data key; the local vault file read under it as a
    /// login reads it, its OTP code checked; then the snapshot judged by
    /// its gate (`answer`, a wrong pick turns G2 off only now) and taken as
    /// a plain successor (the re-seal), S-KEYSYNC-ON's `keysync_on` where
    /// the result turns key-file sync on here. The session is returned only
    /// with the snapshot installed; any failure drops it (the OTP step the
    /// read spent stays spent, and this entry's next call takes the same
    /// code again; the time window is `start`'s).
    pub fn login_via_server(
        entry: &mut ServerEntry,
        touch: &Touch,
        answer: Option<GateAnswer>,
        keysync_on: bool,
    ) -> Result<(Self, Adopted)> {
        entry.start()?;
        let prepared = entry.prepared.duplicate()?;
        let snap = prepared.server.clone().ok_or(AUTH_ERROR)?;
        let own: KeyHeader = prepared.key.header().ok_or(AUTH_ERROR)?.clone();
        let file = snap.file()?;
        if entry.password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        let opened = file.open(&entry.password, Some(touch))?;
        // This PC's keys, from the file that holds them.
        let id = own.vault_id;
        // Sized up front: a growing Vec would free unwiped copies.
        let mut keys: Zeroizing<Vec<[u8; 32]>> =
            Zeroizing::new(Vec::with_capacity(own.key_ids.len()));
        for want in &own.key_ids {
            let key = opened
                .bundle
                .keys()
                .iter()
                .find(|k| key_id(&id, k) == *want)
                .ok_or(SERVER_KEY_OLD_KEYS)?;
            keys.push(*key);
        }
        let bundle = Bundle::new(&keys, opened.bundle.otp()).ok_or(AUTH_ERROR)?;
        drop(keys);
        // Rule D: the writer knew this PC's current data key.
        if !file.chain_ok(bundle.current()) {
            return Err(SERVER_KEY_UNCHAINED);
        }
        let given = Given {
            bundle: Box::new(bundle),
            state: own.state(),
            slot: own
                .slots
                .iter()
                .position(|s| s.cred_id == touch.cred_id)
                .and_then(|j| u8::try_from(j).ok()),
            otp_in_time: true,
            otp_spent: entry.otp_spent,
        };
        let factors = (entry.password.as_str(), entry.otp.as_str(), entry.otp_time);
        let mut s = Self::load(
            prepared,
            factors,
            Some(touch),
            entry.confirmed_older,
            None,
            Some(given),
        )?;
        if s.uses_otp() {
            entry.otp_spent = Some(s.last);
        }
        // The snapshot as this session's view shows it, a plain successor.
        let (shown, seq) = s.server_key_file().ok_or(super::NO_CANDIDATE)?;
        if seq != snap.seq || shown.bytes() != snap.bytes.as_slice() {
            return Err(gate::GATE_NOT_PENDING);
        }
        let check = s.adopt_check(&file, Source::Server { seq })?;
        if check.class != AdoptClass::Successor || check.fork {
            return Err(SERVER_KEY_NOT_SUCCESSOR);
        }
        let r = s.reauth_server(&entry.password, touch)?;
        let opened = s.other_opened(&file, opened, &entry.password, Some(touch))?;
        let (epoch, tag) = (check.other.epoch, check.other.tag);
        let pass = match (check.keys.gate, answer) {
            (None, _) => GatePass::none(&check),
            (Some(_), Some(GateAnswer::Pick(pick))) => GatePass::G2Passed { pick, epoch, tag },
            (Some(_), Some(GateAnswer::Code(code))) => GatePass::G1Passed { code, epoch, tag },
            // Auto-apply (spec §2.30), judged by the preview.
            (Some(_), None) if entry.trusted() => GatePass::Trusted { epoch, tag },
            (Some(_), None) => return Err(gate::GATE_NOT_PENDING),
        };
        let plan = s.adopt_preview_with(&r, &file, opened, &check, pass, ForkOption::Both)?;
        if plan.preview().keysync_on && !keysync_on {
            return Err(KEYSYNC_CONSENT);
        }
        let acks = Acks {
            password_only: false,
            union_password: UnionPassword::Other,
            both_passwords: false,
            fork_option: ForkOption::Both,
            keysync_on: plan.preview().keysync_on,
        };
        let adopted = s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)?;
        Ok((s, adopted))
    }
}

/// The kind-9 merges whose other file did not open, as `(vault ID, epoch,
/// tag)` (spec §5.8, S6-2 #5): for as long as the app runs, such a file is
/// Refused{"위조된 연결"} while it stays the incoming, and its open is not
/// tried again at every login.
static MERGE_UNOPENED: Mutex<Vec<Unopened>> = Mutex::new(Vec::new());
/// A vault ID and the epoch and tag of the file that did not open.
type Unopened = ([u8; 16], u64, [u8; 16]);
/// At most this many are remembered (the oldest go first).
const MERGE_UNOPENED_MAX: usize = 64;
/// Whether the merge of `state` of vault `id` did not open in this run.
pub(super) fn merge_unopened(id: &[u8; 16], state: KeyState) -> bool {
    MERGE_UNOPENED
        .lock()
        .is_ok_and(|v| v.contains(&(*id, state.epoch, state.tag)))
}

/// How the kind-9 merge of two removals made from one state joins the
/// server's KeyFork (spec §5.8): at the next unlock with that unlock's
/// touch and password and no question (`Auto`: the file carries this PC's
/// `pw_id`, and the key the session was unlocked with is live and not
/// suspended in it), or only with [받기] (`Attended`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RemovalMerge {
    Auto,
    Attended,
}

/// Both branches made only removals from one state (spec §5.8 "When"):
/// two single removals from the same data key, or, with three PCs or
/// more, the other file `t` a kind-9 file that holds this PC's
/// pre-removal key ID and every removal this PC has, while this PC's file
/// is a removal or a merge result that `t` has not merged yet. `hist` is
/// this PC's confirmed history, the newest first.
fn one_state_removals(own: &KeyHeader, t: &KeyHeader, hist: &[super::anchor::Hist]) -> bool {
    let lists = |id: &[u8; 16]| t.key_ids.contains(id);
    match (own.kind, t.kind) {
        (Kind::Remove, Kind::Remove) => {
            own.key_ids.len() > 1 && t.key_ids.get(1) == own.key_ids.get(1)
        }
        (Kind::Remove | Kind::Union, Kind::Union) => {
            let all = own
                .tombstones
                .iter()
                .all(|x| t.tombstones.iter().any(|y| y.credhash == x.credhash));
            let pre = match own.kind {
                Kind::Remove => own.key_ids.get(1).is_some_and(|k| t.key_ids.contains(k)),
                _ => {
                    // A merge result: its pre-removal state is in `t`, and
                    // its own removal is not (`t` never merged it).
                    let shared = hist.iter().skip(1).any(|h| lists(&h.keyid));
                    let removal = hist.iter().find(|h| h.kind == Kind::Remove as u8);
                    shared && removal.is_some_and(|h| !lists(&h.keyid))
                }
            };
            all && pre
        }
        _ => false,
    }
}

impl Session {
    /// Whether the server's KeyFork is the kind-9 merge of two removals made
    /// from one state, and how it joins (spec §5.8): the fork's public
    /// checks with P3 failing only on this PC's removals since the fork and
    /// P4 unrelaxed; both branches made only removals from one state; no
    /// gate (R = Δ = T_new = ∅, no policy or slot change); its epoch within
    /// `gated + EPOCH_SILENT`. Never in TOFU, a held session or gate-pending
    /// mode, and not for a file whose merge did not open (then Refused).
    pub fn removal_merge(&self) -> Option<RemovalMerge> {
        self.removal_merge_in(self.sync.as_ref()?)
    }
    /// The same with the sync link `link` (a poll holds it outside the
    /// session).
    pub(super) fn removal_merge_in(&self, link: &super::sync::SyncLink) -> Option<RemovalMerge> {
        let fork = matches!(
            link.keys.top,
            super::keysync::Top::Key {
                class: KeyClass::KeyFork,
                ..
            }
        );
        if !fork
            || self.unconfirmed()
            || self.gate_login.is_some()
            || self.local_rollback
            || self.restored
            || self.restore_held
        {
            return None;
        }
        let (file, seq) = self.server_key_file_in(link)?;
        let own = self.key_file.header()?;
        let t = file.header()?;
        let line = self.anchor.lines.vault.as_ref()?;
        if !one_state_removals(own, t, &line.state.hist)
            || t.epoch > self.gated_epoch()?.saturating_add(EPOCH_SILENT)
        {
            return None;
        }
        let check = self.adopt_check(&file, Source::Server { seq }).ok()?;
        if !check.fork
            || check.class != AdoptClass::Union
            || check.keys.gate.is_some()
            || !check.keys.both
        {
            return None;
        }
        // No question before the open: the same password and the unlock's
        // key live and not suspended in the other file (public bytes).
        let touched = self
            .unlocked_with
            .and_then(|n| own.slots.iter().find(|s| s.number == n));
        let opens = touched.is_some_and(|mine| {
            t.slots
                .iter()
                .enumerate()
                .any(|(j, s)| s.cred_id == mine.cred_id && (t.suspended >> j) & 1 == 0)
        });
        Some(if t.pw_id == own.pw_id && opens {
            RemovalMerge::Auto
        } else {
            RemovalMerge::Attended
        })
    }
    /// The kind-9 merge at login (spec §5.8 "What"): exactly the key record
    /// precheck read, which this session's view still shows, and which the
    /// merge joins with no question. None otherwise: the notice then says
    /// how it joins.
    pub fn login_merge(&self, proof: &UnlockProof) -> Option<(KeyFile, u64)> {
        let snap = proof.snapshot.as_ref()?;
        if proof.session != self.serial || self.removal_merge()? != RemovalMerge::Auto {
            return None;
        }
        let (file, seq) = self.server_key_file()?;
        (seq == snap.seq && file.bytes() == snap.bytes.as_slice()).then_some((file, seq))
    }
    /// The merge's other file did not open with a touched key live in it
    /// and the password (spec §5.8): nothing was written; it is remembered
    /// for this run and the key channel judged again (Refused{"위조된
    /// 연결"}).
    pub fn merge_failed(&mut self, other: &KeyFile) {
        let Some(t) = other.header() else {
            return;
        };
        if let Ok(mut v) = MERGE_UNOPENED.lock() {
            let entry = (self.id, t.epoch, t.state().tag);
            if !v.contains(&entry) {
                v.push(entry);
                let extra = v.len().saturating_sub(MERGE_UNOPENED_MAX);
                v.drain(..extra);
            }
        }
        if let Some(mut link) = self.sync.take() {
            link.keys.again();
            self.read_keys(&mut link);
            self.update_holds(&mut link);
            self.sync = Some(link);
        }
    }
}
