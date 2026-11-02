//! Key changes (spec v3 §5.5): re-authentication and the crash-safe rotation
//! of the data key. Every build changes the password and adopts another
//! PC's password-only key file (`adopt`, spec v3 §5.8); the security-key
//! build adds the changes with security keys (`hw`), through the same
//! steps.
//!
//! A rotation writes, in this order: the anchor's pending line (S0), the
//! vault file as it is under the old key (V_probe, S1), the new key file
//! (S2), the vault file under the new key (S3), the outgoing copy (S4), and
//! the anchor's confirmed line (S5). The new key file is verified before
//! anything is written and read back before the vault file moves to its key,
//! so at every instant the key file on disk holds the key of the vault file
//! on disk: a crash anywhere leaves a pair that opens, and the next unlock
//! finishes the change (`resume`) or drops it.
use super::{
    AtomicError, DataRef, FileLock, Format, GAP_KEPT, GAP_NOT_CHANGED, HaltedHead, Header,
    KEY_FILE_LIMIT, KeyFile, KeyNotice, LOCAL_ROLLBACK, PENDING_ELSEWHERE, RESTORE_KEYS,
    RESTORE_OLDKEY, RESTORE_PENDING, Session, anchor, atomic_write, decode_data, encode_data,
    keyfile::{
        self, Bundle, EPOCH_LIMIT, EPOCH_MAX, Kind, MAX_KEYS, Plan, Spec, Touch, WriterSecrets,
        key_id,
    },
    password_policy, read_bounded, recover, refuse, sha256,
};
use crate::crypto::{self, AUTH_ERROR, Key, Result, ct_eq};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

mod adopt;
#[cfg(feature = "security-key")]
mod hw;
#[cfg(feature = "security-key")]
pub use adopt::{ForkOption, KeyChange, KeyGates};
#[cfg(feature = "security-key")]
pub use hw::{
    ANCHOR_FAILED, Exposure, KeyRow, KeysOverview, LossReport, NOT_PLANNED, OLDSLOT, REACH_CHANGED,
    REMOVE_UNDONE, REPAIR_AUTH, ReSeedKey, ReSeedPlan, Redo, RedoFlow, UNION_FULL, UNREACHABLE,
};
#[cfg(feature = "security-key")]
pub(super) use hw::{create_with_keys, probe_anchor};
/// What S0 records beside the state a write becomes (spec §5.5 S0): the
/// security-key build's removals, loss and broken pair records; nothing in
/// the keyless build.
#[cfg(not(feature = "security-key"))]
type Landing = ();
pub use adopt::{
    ADOPT_CONTAINED, ADOPT_EQUAL, ADOPT_OLDER, ADOPT_REFUSED, ADOPT_ROLLBACK, Acks, AdoptCheck,
    AdoptClass, AdoptPlan, Adopted, GatePass, LostKeyAddOn, NOT_THIS_VAULT, OtherOpened,
    PassInForce, Preview, Source, UnionPassword,
};
#[cfg(feature = "security-key")]
use hw::Landing;

/// How long a Reauth stays usable within its flow (spec §5.3).
pub const REAUTH_MAX: Duration = Duration::from_secs(30 * 60);
/// S-SAMEPASS.
pub const SAMEPASS: &str = "새 비밀번호가 지금 비밀번호와 같습니다.";
/// S-VPENDING: the key changed, and the vault file is saved under the new
/// key at the next save or unlock.
pub const VPENDING: &str = "열쇠를 바꿨습니다. 금고 파일을 아직 새 열쇠로 다시 저장하지 못했습니다. 저장장치를 확인하세요. 다음 저장이나 잠금 해제 때 자동으로 마칩니다.";
/// S-KEYTEMP: the new key file's rename was cut off.
pub const KEYTEMP: &str =
    "열쇠 파일 이름 바꾸기가 끊겨 임시 파일로 두었습니다. 자동으로 다시 시도합니다.";
/// S-KEYTEMP-GONE.
pub const KEYTEMP_GONE: &str = "열쇠 파일과 그 임시 파일을 모두 찾지 못했습니다. 잠그기 전에 '열쇠 백업'으로 새 열쇠 파일을 저장하세요. 그 파일과 새 비밀번호로 이 금고를 열 수 있습니다.";
/// The key file was not written and reads back as it was: the only case
/// that says nothing changed (spec §5.5 S2).
pub const KEY_NOT_SAVED: &str =
    "열쇠 파일을 저장하지 못했습니다(저장장치·쓰기 권한 확인). 아무것도 바뀌지 않았습니다.";
/// S-KEYDAMAGED-SAVE: whether the new key file was saved is unknown. The
/// session keeps it in memory for a key backup and writes the vault file no
/// more; the app locks once it is saved (S-KEYDAMAGED-LOCKED).
pub const KEY_DAMAGED: &str = "열쇠 파일을 저장했는지 확인하지 못했습니다. 잠그기 전에 새 열쇠 파일을 다른 저장장치에 저장하세요. 그 파일과 새 비밀번호(와 보안 키)로 이 금고를 열 수 있습니다.";
/// S-KEYDAMAGED-LOCKED.
pub const KEY_DAMAGED_LOCKED: &str = "열쇠 파일을 저장했는지 확인하지 못해 금고를 잠갔습니다. 먼저 새 비밀번호(와 보안 키)로 열어 보세요. 열리지 않으면 예전 비밀번호로 여세요. 예전 열쇠 파일이 없어졌다면 열쇠 백업이 필요합니다.";
/// The key file changed on disk since the unlock.
const KEY_CHANGED: &str = "열쇠 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.";
/// A Reauth of another session or screen, or one older than REAUTH_MAX.
const REAUTH_STALE: &str = "확인한 지 오래되었거나 다른 화면에서 확인한 것이라 다시 확인해야 합니다. 처음부터 다시 하세요.";
/// The new key file or vault file did not verify: nothing was written.
const NOT_VERIFIED: &str =
    "새 열쇠 파일이나 금고 파일을 검증하지 못해 쓰지 않았습니다. 아무것도 바뀌지 않았습니다.";
/// S-GATE-STALE.
const GATE_STALE: &str = "다른 PC나 백업에 이 PC보다 새 열쇠 파일이 있습니다(보안 키 추가 등). 먼저 '새 열쇠 파일 받기'로 그 파일을 받으세요. 이대로 바꾸면 두 열쇠 파일이 갈라집니다(나중에 받으면 합쳐집니다). 그래도 계속할까요?";
/// S-GATE-UNVERIFIED.
const GATE_UNVERIFIED: &str = "이 PC가 서버와 맞춰졌는지 확인되지 않았습니다. 다른 PC에서도 따로 열쇠를 바꾸면 두 열쇠가 갈라져 '새 열쇠 파일 받기'로 합쳐야 합니다. 계속할까요?";
/// S-GATE-HALT: a server copy halts sync because another PC changed the
/// keys.
const GATE_HALT: &str = "다른 PC에서 이 금고의 열쇠가 바뀐 것으로 보입니다. 먼저 '새 열쇠 파일 받기'를 하세요. 서버 사본이 위조된 것이 확실할 때만 계속하세요. 계속하면 두 PC의 열쇠가 갈라져 나중에 '새 열쇠 파일 받기'로 합쳐야 합니다. 그래도 계속할까요?";
/// S-GATE-HALT in its fork wording: two PCs changed the keys apart.
const GATE_FORK: &str = "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라진 것으로 보입니다. 먼저 '새 열쇠 파일 받기'로 다른 PC의 열쇠 파일을 받아 합치세요. 서버 사본이 위조된 것이 확실할 때만 계속하세요. 계속하면 열쇠 파일이 더 갈라져 나중에 '새 열쇠 파일 받기'로 합쳐야 합니다. 그래도 계속할까요?";
/// S-OVERRIDE-HEAD (spec §7.5a), in two lines, filled with the head's
/// epoch, the first 8 hex digits of its key ID and its server version.
pub const OVERRIDE_HEAD: &str = concat!(
    "서버의 최신 사본(수정 {epoch}, 열쇠 {key}, 서버 버전 {v})을 이 PC의 상태로 덮어씁니다. 그 사본은 합치지 않고 서버 기록에만 남습니다. 다른 PC에서 열쇠를 바꾼 것이 맞다면 덮어쓰지 말고 그 PC의 열쇠 파일을 받으세요.",
    "\r\n",
    "그 PC를 더 쓸 수 없거나 위조된 사본이 확실할 때만 계속하세요. 다른 PC에 더 새 열쇠 파일이 있다면 그 PC는 이후 이 PC의 사본을 예전 열쇠 사본으로 보고 덮어씁니다."
);
/// The head override when no server copy halts sync.
const NOTHING_HALTED: &str = "멈춘 동기화가 없어 덮어쓸 서버 사본이 없습니다.";
/// The head override found another server copy than the one it named.
const HEAD_CHANGED: &str =
    "확인한 뒤에 서버의 최신 사본이 바뀌어 덮어쓰지 않았습니다. 처음부터 다시 하세요.";
/// [이 열쇠 파일이 맞습니다] or [끝나지 않은 열쇠 변경 버리기…] where there
/// is nothing to confirm or discard.
pub const NOTHING_HELD: &str = "확인하거나 버릴 열쇠 기록이 없습니다.";

/// A re-authentication (spec §5.3): the password (and a security key)
/// checked again for one flow, which holds the key file's lock until its key change.
/// Single-use (a key change consumes it), bound to its session, and usable
/// for REAUTH_MAX. Zeroized on drop.
pub struct Reauth {
    session: u64,
    /// The app's screen serial when the token was made; the app refuses a
    /// token from another screen (spec §5.3, §8.5).
    pub app_serial: u64,
    /// When it was made, on crypto::now_ms (spec §5.3 step 5, S45-2 #15),
    /// the clock a test moves.
    created: u64,
    password: Zeroizing<String>,
    /// The touched key of a key file with security keys: S, its output and
    /// what its pair records reach.
    #[cfg(feature = "security-key")]
    keys: Option<hw::Authorizer>,
    /// `password` is the one that opens this session's key file. Not on the
    /// second entry point of spec §5.2, whose password opened only the
    /// server's key file: that Reauth serves only the accept of that file,
    /// whose E5 then holds trivially (spec §7.15 step 4).
    own_password: bool,
    /// The transport of that entry's touch, which has no Authorizer.
    #[cfg(feature = "security-key")]
    bare_transport: Option<u32>,
    _lock: FileLock,
}
impl Reauth {
    /// What is left of its REAUTH_MAX (spec §9.2a): a flow checks it before
    /// a registration, another ceremony and the write.
    pub fn remaining(&self) -> Duration {
        REAUTH_MAX.saturating_sub(self.age())
    }
    /// How long ago it was made: every REAUTH_MAX check reads this.
    fn age(&self) -> Duration {
        Duration::from_millis(crate::crypto::now_ms().saturating_sub(self.created))
    }
}
/// What a key change does (spec §5.5).
pub enum Change {
    /// A new password: a rotation of the data key.
    Password(Zeroizing<String>),
    /// Security keys for a key file without them (GOYOKH01): every key
    /// registered in this flow, paired with every other, and optionally a
    /// new password (S45-2 #3).
    #[cfg(feature = "security-key")]
    KeysOn {
        pin: bool,
        keys: Vec<crate::fido::NewKey>,
        new_password: Option<Zeroizing<String>>,
    },
    /// One more key, paired with every key touched in the flow.
    #[cfg(feature = "security-key")]
    AddKey(crate::fido::NewKey),
    /// Removes the keys numbered `remove` with one touch of a staying key
    /// (a removal for a loss with its `loss` report). `over` names a waiting
    /// change of another PC it is written on top of (§9.2), which needs the
    /// key-file sync candidate of a later stage.
    #[cfg(feature = "security-key")]
    Remove {
        remove: Vec<u8>,
        new_password: Option<Zeroizing<String>>,
        loss: Option<hw::LossReport>,
        over: Option<(u64, [u8; 16])>,
    },
    /// Pairs the Reauth key with every key in `extra`.
    #[cfg(feature = "security-key")]
    Pair,
    /// New seeds for every live key (`ReSeedPlan`).
    #[cfg(feature = "security-key")]
    ReSeed(Vec<hw::ReSeedKey>),
    /// Back to a password-only key file (GOYOKE03), every key removed; for
    /// a GOYOKS01 key file through the off sequence of key-file sync (spec
    /// §7.16).
    #[cfg(feature = "security-key")]
    KeysOff,
    /// Key-file sync on (GOYOKS01, the data key kept), or the re-upload of
    /// a GOYOKS01 key file after the server's cut (spec §7.9).
    #[cfg(feature = "security-key")]
    KeySyncOn,
    /// Key-file sync off (GOYOKH01 under a new data key), through the off
    /// sequence of spec §7.16.
    #[cfg(feature = "security-key")]
    KeySyncOff,
    /// The supersede of a G1-gated change whose PC is gone (spec §7.15a):
    /// this PC's key file written again above the candidate `(epoch, tag)`
    /// (kind 6, the data key kept, own ∪ the candidate's tombstones), which
    /// is never opened. On a GOYOKH01 session it turns key-file sync on.
    #[cfg(feature = "security-key")]
    Supersede { epoch: u64, tag: [u8; 16] },
}
/// The keys the user agreed to suspend (S-SUSPEND; security-key build).
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Consent {
    pub suspend: Vec<u8>,
}
/// How a key change ended (spec §5.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rekeyed {
    Done,
    /// The new key file is in place, and the vault file could not be saved
    /// under its key yet: every save and poll tries again (S-VPENDING).
    VaultPending,
    /// The new key file is in place, and the vault file's replace was cut
    /// off: the app locks, and the next unlock takes it back
    /// (S-GAP-CHANGED).
    GapKept,
}
/// What the user is asked before a key change (spec §7.5), or what holds
/// it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gate {
    /// The key file is an older state of this PC: no key change until the
    /// user confirms it. Never overridden.
    LocalRollback,
    /// A server copy halts sync: another PC changed the keys (S-GATE-HALT).
    KeyHalt,
    /// A server copy halts sync because two PCs changed the keys apart
    /// (S-GATE-HALT, fork wording).
    KeyFork,
    /// The vault file is ahead of the key file: another PC changed the key
    /// file (S-GATE-STALE).
    StaleKeyFile,
    /// A synced vault not verified against the server (S-GATE-UNVERIFIED).
    Unverified,
    /// A key change of another PC that needs no gate waits on the server
    /// (spec §7.5 KeyFileReady).
    #[cfg(feature = "security-key")]
    KeyFileReady,
}
impl Gate {
    /// The question that lets the user go on anyway (danger, default No).
    pub fn question(self) -> &'static str {
        match self {
            Self::LocalRollback => LOCAL_ROLLBACK,
            Self::KeyHalt => GATE_HALT,
            Self::KeyFork => GATE_FORK,
            Self::StaleKeyFile => GATE_STALE,
            Self::Unverified => GATE_UNVERIFIED,
            #[cfg(feature = "security-key")]
            Self::KeyFileReady => super::keysync::KEYFILE_READY,
        }
    }
}
/// Names the step of a key change for the step-qualified crash points of
/// the tests (spec §14.5); a no-op in every other build.
struct Step;
impl Step {
    fn enter(name: &'static str) -> Self {
        #[cfg(test)]
        super::STEP.with(|s| s.set(Some(name)));
        #[cfg(not(test))]
        let _ = name;
        Step
    }
}
impl Drop for Step {
    fn drop(&mut self) {
        #[cfg(test)]
        super::STEP.with(|s| s.set(None));
    }
}
/// Err(SIMULATED_CRASH) once if a test set this point.
#[cfg(test)]
fn point(name: &'static str) -> Result<()> {
    super::point(name)
}
#[cfg(not(test))]
fn point(_: &'static str) -> Result<()> {
    Ok(())
}
/// Whether `e` is a test's simulated crash: the process died there, so
/// nothing may be cleaned up.
fn crashed(e: &str) -> bool {
    #[cfg(any(test, debug_assertions))]
    return e == super::SIMULATED_CRASH;
    #[cfg(not(any(test, debug_assertions)))]
    {
        let _ = e;
        false
    }
}
#[cfg(test)]
thread_local! {
    /// "K" or "V": the next key change flips a byte of its new key file or
    /// vault file before verifying it (spec §14.4-13).
    pub(super) static CORRUPT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    /// What another program, a pulled stick or a full disk does right
    /// before the first write of a step ("S2", "S3") of the next key change.
    #[allow(clippy::type_complexity)]
    pub(super) static BEFORE: std::cell::RefCell<Option<(&'static str, Box<dyn FnOnce()>)>> =
        const { std::cell::RefCell::new(None) };
}
/// Runs a test's action set for `step` (see BEFORE); nothing elsewhere.
fn before(step: &'static str) {
    #[cfg(test)]
    {
        let hook = BEFORE.with(|b| {
            let mut b = b.borrow_mut();
            match b.as_ref() {
                Some((s, _)) if *s == step => b.take(),
                _ => None,
            }
        });
        if let Some((_, act)) = hook {
            act();
        }
    }
    #[cfg(not(test))]
    let _ = step;
}
#[cfg(test)]
fn corrupt(which: &'static str, bytes: &mut [u8]) {
    if CORRUPT.with(|c| c.get()) == Some(which) {
        CORRUPT.with(|c| c.set(None));
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
    }
}
/// What a write of the key file left on disk (spec §5.5 S2).
enum Left {
    /// The new key file, read back.
    New,
    /// The old key file, byte for byte: nothing changed.
    Old,
    /// No key file, and the temp file the cut-off replace kept holds the
    /// new one.
    Temp(PathBuf),
    /// Anything else: whether it was saved is unknown.
    Unknown,
}
/// A key file built and verified in memory (spec §5.5 R1-R3), with the
/// vault file under its key: what S0-S5 write.
struct Built {
    /// The new key file as a reader parses it, and the keys it opens to.
    file: KeyFile,
    kh: keyfile::KeyHeader,
    bundle: Box<Bundle>,
    /// V_probe, when the data key changes: the vault file as it is, under
    /// the current key, which the new key file's `resume` names.
    probe: Option<Vec<u8>>,
    /// The vault file under the new key file's current key and state.
    vault: Vec<u8>,
    /// What S0 records beside the new state.
    landing: Landing,
}

impl Session {
    /// Re-authenticates for one key change (spec §5.3): takes the key file's
    /// lock, requires the key file on disk to be this session's, and opens
    /// it with `password` (and for a key file with security keys `touch`) to
    /// this session's keys. The keyless build has no security key, so
    /// `touch` is None.
    pub fn reauth(&mut self, password: &str, touch: Option<&Touch>) -> Result<Reauth> {
        self.reauth_with(password, touch)
    }
    /// The login's own Reauth (spec §5.3): the key file opened again with
    /// the unlock's password and touch. Only for the session the proof came
    /// from.
    #[cfg(feature = "security-key")]
    pub fn reauth_from_unlock(
        &mut self,
        proof: super::serverkey::UnlockProof,
        touch: &Touch,
    ) -> Result<Reauth> {
        if proof.session != self.serial {
            return Err(REAUTH_STALE);
        }
        self.reauth_with(&proof.password, Some(touch))
    }
    /// The Reauth of the second entry point (spec §5.2, §7.15 step 4): this
    /// session was built from the server's key file `password` opened, so
    /// this key file is not opened again; the lock and the key file on disk
    /// are checked as for any Reauth. It serves only that file's accept.
    #[cfg(feature = "security-key")]
    pub(super) fn reauth_server(&mut self, password: &str, touch: &Touch) -> Result<Reauth> {
        self.retry_key_temp();
        let lock = FileLock::acquire(&self.key_path)?;
        if !self.key_on_disk()? {
            return Err(KEY_CHANGED);
        }
        Ok(Reauth {
            session: self.serial,
            app_serial: 0,
            created: crate::crypto::now_ms(),
            password: Zeroizing::new(password.to_owned()),
            keys: None,
            own_password: false,
            bare_transport: touch.transport,
            _lock: lock,
        })
    }
    fn reauth_with(&mut self, password: &str, touch: Option<&Touch>) -> Result<Reauth> {
        if password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        // A rename a key change left to finish goes first.
        self.retry_key_temp();
        let lock = FileLock::acquire(&self.key_path)?;
        if !self.key_on_disk()? {
            return Err(KEY_CHANGED);
        }
        let opened = self.key_file.open(password, touch)?;
        if !opened.bundle.same(&self.keys) {
            return Err(AUTH_ERROR);
        }
        // The touched key's own pair records (spec §5.3 step 3).
        #[cfg(feature = "security-key")]
        let keys = self.authorizer(&opened, touch)?;
        drop(opened);
        Ok(Reauth {
            session: self.serial,
            app_serial: 0,
            created: crate::crypto::now_ms(),
            password: Zeroizing::new(password.to_owned()),
            #[cfg(feature = "security-key")]
            keys,
            own_password: true,
            #[cfg(feature = "security-key")]
            bare_transport: None,
            _lock: lock,
        })
    }
    /// What holds every key change of this session, or what the user must
    /// be asked first (spec §5.5 R0, §7.5). The UI calls it before any
    /// question.
    pub fn password_change(&self) -> Result<Option<Gate>> {
        self.change_gate(&Change::Password(Zeroizing::default()))
    }
    /// The same for `change`.
    pub fn change_gate(&self, change: &Change) -> Result<Option<Gate>> {
        self.held()?;
        // No key change before the key file is confirmed (spec §7.17), nor
        // in a held session whose confirmed line lacks `t` (§5.2 step 9(a)).
        #[cfg(feature = "security-key")]
        if self.unconfirmed() {
            return Err(super::gate::TOFU_HELD);
        }
        self.not_rolled_back()?;
        // A server candidate waiting for its gate holds every key change
        // but the lost-key flow and the off (spec §7.5 GatePending, no
        // override).
        #[cfg(feature = "security-key")]
        if self.gate_waits() && !self.passes_gate_pending(change) {
            return Err(super::keysync::GATE_PENDING);
        }
        Ok(self.rekey_gate(change))
    }
    /// What holds every key change and adopt of this session (spec §5.5 R0,
    /// §5.1): a replace gap of the vault file, a new key file whose save is
    /// unknown, a change of this PC that may have landed in a key file that
    /// could not be read, or a Restore (held, or any other: §2.18 #54).
    fn held(&self) -> Result<()> {
        if self.gap_kept {
            return Err(GAP_KEPT);
        }
        if self.unsaved_key.is_some() {
            return Err(KEY_DAMAGED);
        }
        if let Some(path) = &self.pending_elsewhere {
            return Err(refuse(
                PENDING_ELSEWHERE,
                vec![path.to_string_lossy().into_owned()],
            ));
        }
        if self.restore_held {
            let old = self.confirmed_epoch().unwrap_or(0);
            return Err(if self.anchor.lines.pending.is_some() {
                RESTORE_PENDING
            } else {
                refuse(
                    RESTORE_OLDKEY,
                    vec![old.to_string(), self.key_state.epoch.to_string()],
                )
            });
        }
        if self.restored {
            return Err(RESTORE_KEYS);
        }
        // Gate-pending mode writes nothing (spec §5.2, §5.5 R0), nor does
        // a security-key session whose anchor could not be written
        // (AnchorFailed, §5.10; no override).
        #[cfg(feature = "security-key")]
        if self.gate_login.is_some() {
            return Err(super::gate::GATE_HELD);
        }
        #[cfg(feature = "security-key")]
        if self.anchor_failed {
            return Err(ANCHOR_FAILED);
        }
        Ok(())
    }
    /// The gate a key change meets (spec §7.5): the local rollback first,
    /// which no answer overrides, then the questions, the strongest first: a
    /// halted vault is also unverified.
    pub fn rekey_gate(&self, change: &Change) -> Option<Gate> {
        // A removal for a loss protects this PC at once: no question holds
        // it, only a local rollback (spec §7.5; round 2, finding 21).
        #[cfg(feature = "security-key")]
        if !self.local_rollback && matches!(change, Change::Remove { loss: Some(_), .. }) {
            return None;
        }
        // The supersede ends the halt and the gate it would meet: none of
        // the rotation gates (spec §7.15a, round 2 finding 32); R0 refuses
        // any other halt (S-SUPERSEDE-HEAD).
        #[cfg(feature = "security-key")]
        if !self.local_rollback && matches!(change, Change::Supersede { .. }) {
            return None;
        }
        let _ = change;
        #[cfg(feature = "security-key")]
        let (key_halt, ready, unverified) = (
            self.key_halt(),
            self.successor_ready(),
            self.keys_unverified(),
        );
        #[cfg(not(feature = "security-key"))]
        let (key_halt, ready, unverified) = (None, false, false);
        if self.local_rollback {
            Some(Gate::LocalRollback)
        } else if let Some(fork) = self.sync_halt().or(key_halt) {
            Some(if fork { Gate::KeyFork } else { Gate::KeyHalt })
        } else if self.stale_key_file {
            Some(Gate::StaleKeyFile)
        } else if ready {
            // A waiting successor is the cause the user can act on; it
            // also leaves a GOYOKS01 session unverified.
            #[cfg(feature = "security-key")]
            const READY: Option<Gate> = Some(Gate::KeyFileReady);
            #[cfg(not(feature = "security-key"))]
            const READY: Option<Gate> = None;
            READY
        } else if self.sync_unverified() || unverified {
            Some(Gate::Unverified)
        } else {
            None
        }
    }
    /// Changes the keys (spec §5.5). `r` is this flow's re-authentication;
    /// `override_gate`: the user answered the gate's question. Nothing is
    /// written before every check passed and the new key file and vault
    /// file verified in memory. Err means the change did not happen, but
    /// for KEY_DAMAGED (whether the key file was saved is unknown) and a
    /// test's simulated crash.
    pub fn rekey(
        &mut self,
        r: Reauth,
        extra: Vec<Touch>,
        change: Change,
        consent: Consent,
        override_gate: bool,
    ) -> Result<Rekeyed> {
        // R0. The Reauth of the second entry point serves only its accept.
        if r.session != self.serial || r.age() > REAUTH_MAX || !r.own_password {
            return Err(REAUTH_STALE);
        }
        let gate = self.change_gate(&change)?;
        if let Some(gate) = gate.filter(|_| !override_gate) {
            return Err(gate.question());
        }
        // A key file with security keys, or a change of them.
        #[cfg(feature = "security-key")]
        if self.key_file.needs_security_key() || !matches!(change, Change::Password(_)) {
            return self.rekey_keys(r, extra, change, consent);
        }
        // A password change takes no other touch and suspends nothing.
        if !extra.is_empty() || !consent.suspend.is_empty() {
            return Err(AUTH_ERROR);
        }
        if !self.key_on_disk()? {
            return Err(KEY_CHANGED);
        }
        #[cfg(not(feature = "security-key"))]
        let Change::Password(password) = change;
        #[cfg(feature = "security-key")]
        let Change::Password(password) = change else {
            return Err(AUTH_ERROR);
        };
        password_policy(&password)?;
        if ct_eq(password.as_bytes(), r.password.as_bytes()) {
            return Err(SAMEPASS);
        }
        self.rotate(&password)
    }
    /// R1-R3 and S0-S5 of a rotation to `password` (spec §5.5).
    fn rotate(&mut self, password: &str) -> Result<Rekeyed> {
        // R1: the epoch above every state the opened files prove.
        let epoch = self
            .max_epoch
            .checked_add(1)
            .filter(|e| *e <= EPOCH_MAX)
            .ok_or(EPOCH_LIMIT)?;
        // V_probe: the vault file as it is, under the current key, so the
        // new key file can tell it apart (`resume`) from any other file
        // under that key.
        let probe = self.encode()?;
        let resume = sha256(&probe);
        let pw_id = fresh_pw_id()?;
        let mut dk: Box<Key> = Box::default();
        crypto::random_into(dk.as_mut_slice())?;
        let keys = rotated(&dk, self.keys.keys());
        let bundle = Bundle::new(&keys).ok_or(AUTH_ERROR)?;
        let h = self.key_file.header();
        let spec = Spec {
            vault_id: self.id,
            epoch,
            kind: Kind::Password,
            next: h.map_or(1, |h| h.next),
            pw_id,
            loss: 0,
            tombstones: h.map(|h| h.tombstones.clone()).unwrap_or_default(),
            resume,
        };
        let (bytes, writer) = keyfile::seal(&spec, &bundle, password, Plan::PasswordOnly)?;
        let built = self.built(bytes, &writer, &spec, &bundle, Some(probe), None)?;
        drop(writer);
        self.land(built, anchor::Src::Other, Some(anchor::Pw::New))
    }
    /// R2 and R3 (spec §5.5): the new key file `bytes`, which `writer`
    /// sealed from `spec` and `bundle`, as any reader parses and opens it,
    /// and the vault file under the key it holds, decoded back. Anything
    /// but what was meant is NOT_VERIFIED, with nothing written. `probe`:
    /// V_probe of a change of the data key, which `spec` names. `reseal`:
    /// the same-epoch re-seal of another file, which keeps its `[0, W)` and
    /// so an old OTP vault's flag; no other write has the flag.
    fn built(
        &self,
        bytes: Vec<u8>,
        writer: &WriterSecrets,
        spec: &Spec,
        bundle: &Bundle,
        probe: Option<Vec<u8>>,
        reseal: Option<&keyfile::KeyHeader>,
    ) -> Result<Built> {
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut bytes = bytes;
        #[cfg(test)]
        corrupt("K", &mut bytes);
        // R2: the new key file, as any reader parses and opens it.
        let file = KeyFile::from_bytes(&self.key_path, bytes).map_err(|_| NOT_VERIFIED)?;
        let kh = file.header().ok_or(NOT_VERIFIED)?.clone();
        let opened = file.open_written(writer).map_err(|_| NOT_VERIFIED)?;
        let mut tombstones = spec.tombstones.clone();
        tombstones.sort_unstable_by_key(|t| (t.epoch(), t.credhash));
        let ids: Vec<[u8; 16]> = bundle.keys().iter().map(|k| key_id(&self.id, k)).collect();
        if kh.magic != keyfile::Magic::Ke03
            || kh.spec()
                != (Spec {
                    tombstones,
                    ..spec.clone()
                })
            || kh.key_ids != ids
            // No new key file holds a TOTP secret (the OTP was removed).
            || (kh.otp_secret() && !reseal.is_some_and(|h| h.otp_secret()))
            || !opened.bundle.same(bundle)
            || kh.key_ids.last() != Some(&key_id(&self.id, self.keys.id_key()))
        {
            return Err(NOT_VERIFIED);
        }
        self.with_vault(file, kh, opened.bundle, probe)
    }
    /// R3 (spec §5.5): the vault file under the key the verified new key
    /// file `file` (in the state `kh`, opening to `bundle`) holds, decoded
    /// back. Anything but this session's contents is NOT_VERIFIED.
    fn with_vault(
        &self,
        file: KeyFile,
        kh: keyfile::KeyHeader,
        bundle: Box<Bundle>,
        probe: Option<Vec<u8>>,
    ) -> Result<Built> {
        let header = Header::Keyed {
            key_id: kh.current_key_id(),
            state: kh.state(),
            flags: Header::flags_of(kh.magic),
        };
        let data = self.data();
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut vault = encode_data(&self.id, bundle.current(), &header, self.format, data)?;
        #[cfg(test)]
        corrupt("V", &mut vault);
        match decode_data(&self.id, bundle.current(), bundle.id_key(), &vault) {
            Ok((format, read, c))
                if format == self.format && read == header && same(format, c.view(), data) => {}
            _ => return Err(NOT_VERIFIED),
        }
        Ok(Built {
            file,
            kh,
            bundle,
            probe,
            vault,
            landing: Landing::default(),
        })
    }
    /// S0-S5 (spec §5.5) of a key file built and verified in memory: what
    /// `src` wrote, sealed with the password `pw` names (None: this PC's).
    fn land(&mut self, b: Built, src: anchor::Src, pw: Option<anchor::Pw>) -> Result<Rekeyed> {
        let Built {
            file,
            kh,
            bundle,
            probe,
            vault: v_new,
            landing,
        } = b;
        let (state, epoch, resume) = (kh.state(), kh.epoch, kh.resume);
        // S0: the anchor's pending line, the complete line this state
        // becomes, before anything else is written.
        let pending = {
            let _step = Step::enter("S0");
            self.write_pending(&kh, src, pw, &landing)?
        };
        point("S0")?;
        // S0r: a removal for a loss (this PC's lost-key flow, or an adopt
        // that removes keys of this PC whose tombstones carry a loss mark)
        // makes the review due, in the merge log first, before anything is
        // installed (spec §5.5 S0r, §5.13; S45-2 #11). A failure stops like
        // S0.
        #[cfg(feature = "security-key")]
        let review = match pending.loss.as_deref() {
            Some(loss) => {
                let _step = Step::enter("S0r");
                match self.review_store(loss) {
                    Ok(date) => Some(date),
                    Err(e) => {
                        if !crashed(e) {
                            self.drop_pending(state);
                        }
                        return Err(e);
                    }
                }
            }
            None => None,
        };
        #[cfg(feature = "security-key")]
        if review.is_some() {
            point("review-stored")?;
        }
        // S1: V_probe, when the data key changes.
        if let Some(probe) = &probe {
            {
                let _step = Step::enter("S1");
                if let Err(e) = self.write(probe) {
                    if crashed(e) {
                        return Err(e);
                    }
                    point("S1.gapped")?;
                    // Nothing changed: the change is not reported again at
                    // the next unlock. After a replace gap the session
                    // writes the vault file no more, and the app locks
                    // (E-S1g).
                    self.drop_pending(state);
                    return Err(if self.gap_kept { GAP_NOT_CHANGED } else { e });
                }
            }
            point("S1.done")?;
        }
        // S2 and S2v: the new key file in place, read back.
        let bytes = file.bytes().to_vec();
        let old = self.key_file.bytes().to_vec();
        before("S2");
        let mut tries = 0;
        let left = loop {
            tries += 1;
            let _step = Step::enter("S2");
            match atomic_write(&self.key_path, &bytes, true) {
                Ok(()) => {
                    if read_bounded(&self.key_path, KEY_FILE_LIMIT).ok().as_deref()
                        == Some(&bytes[..])
                    {
                        break Left::New;
                    }
                    if tries < 2 {
                        continue;
                    }
                    break self.left(&old, &bytes, None);
                }
                Err(AtomicError::Failed(e)) if crashed(e) => return Err(e),
                Err(AtomicError::GapKept(temp)) => break self.left(&old, &bytes, Some(temp)),
                Err(AtomicError::Failed(_)) => break self.left(&old, &bytes, None),
            }
        };
        let key_temp = match left {
            Left::New => None,
            Left::Temp(temp) => Some(temp),
            Left::Old => {
                self.drop_pending(state);
                return Err(KEY_NOT_SAVED);
            }
            // The vault file is V_probe under the old key, which both key
            // files open: it stays as it is, and the pending line lets the
            // next unlock finish or drop the change.
            Left::Unknown => {
                self.unsaved_key = Some(bytes);
                self.key_file_damaged = true;
                return Err(KEY_DAMAGED);
            }
        };
        point("S2v")?;

        // Commit: the session takes the new keys. The key file is the state
        // the confirmed line becomes, so a local rollback is over (an adopt
        // takes only a file that descends from the confirmed state).
        #[cfg(feature = "security-key")]
        {
            let dead = |f: &KeyFile| -> Vec<[u8; 16]> {
                f.header()
                    .map(|h| h.tombstones.iter().map(|t| t.credhash).collect())
                    .unwrap_or_default()
            };
            let before = dead(&self.key_file);
            self.tombs_added = dead(&file).iter().any(|c| !before.contains(c));
        }
        self.keys = bundle;
        self.key_file = file;
        (self.key_state, self.max_epoch) = (state, epoch);
        (self.stale_key_file, self.resave_due) = (false, true);
        self.local_rollback = false;
        // The review is due in the session before anything is flushed
        // (spec §5.5 Commit).
        #[cfg(feature = "security-key")]
        if let Some(date) = &review {
            self.review_now(date);
        }
        if key_temp.is_some() {
            self.key_notices.push(KeyNotice::KeyTemp);
        }
        self.key_temp = key_temp;
        // Every verdict is derived again against the new state.
        self.relink();

        // S3: the vault file under the new key, read back; one more try.
        before("S3");
        let vault = {
            let _step = Step::enter("S3");
            let mut vault = Rekeyed::VaultPending;
            for _ in 0..2 {
                match self.write(&v_new) {
                    Ok(()) if self.vault_reads_back() => {
                        vault = Rekeyed::Done;
                        break;
                    }
                    Err(e) if crashed(e) => return Err(e),
                    // V′ is only in its temp file, which the next unlock
                    // takes back.
                    Err(_) if self.gap_kept => {
                        vault = Rekeyed::GapKept;
                        break;
                    }
                    _ => {}
                }
            }
            // Every later save and poll tries again.
            self.resave_due = vault == Rekeyed::VaultPending;
            vault
        };
        if vault == Rekeyed::Done {
            point("S3v")?;
        } else if vault == Rekeyed::GapKept {
            point("S3.gapped")?;
        }
        // S4: the outgoing copy, from the session (never a copy of the
        // file), after the vault file. Not after a replace gap: the server
        // never holds content no vault file on disk holds.
        if vault != Rekeyed::GapKept {
            // The key request first (spec §5.5 S4, §7.11), against the
            // committed state: its `hist`, `merged` and `ks`.
            #[cfg(feature = "security-key")]
            self.keys_after_change(&pending);
            if let Some(link) = self.sync.as_mut() {
                link.mark_due();
            }
            self.flush_outgoing();
            point("S4")?;
        }
        // S5.
        self.key_backup_due = true;
        self.delete_key_temps();
        {
            let _step = Step::enter("S5");
            let key_id = kh.current_key_id();
            let mut promoted = pending.promoted(None);
            // The vault file is in place under the new key, or in its temp
            // file: from now on no older one is taken for current (`vkey`).
            // Only one read back seals the change for good (`consumed`).
            if vault != Rekeyed::VaultPending {
                promoted.vkey = Some(key_id);
            }
            if vault == Rekeyed::Done && resume != [0; 32] {
                promoted.state.consumed = Some(resume);
            }
            self.anchor_update(anchor::LOCK_WAIT, &mut |lines| {
                let mut line = promoted.clone();
                // The confirmed line's `merged` list stays; a `vkey` is kept
                // only until the vault file is under the new key.
                if let Some(old) = &lines.vault {
                    line.merged = pending.promoted(Some(old)).merged;
                    line.vkey = line.vkey.or(old.vkey);
                }
                lines.vault = Some(line);
                if lines.pending.as_ref() == Some(&pending) {
                    lines.pending = None;
                }
                #[cfg(feature = "security-key")]
                {
                    anchor::apply_clears(lines, &pending);
                    anchor::apply_review(lines, &pending);
                    anchor::apply_clone(lines, &pending);
                }
                true
            })?;
            // A vault file saved later seals the change then.
            self.seal_due = vault == Rekeyed::VaultPending;
        }
        point("S5")?;
        Ok(vault)
    }
    /// S0 (spec §5.5): the pending line of the state `kh`, as the complete
    /// confirmed line it becomes once it lands: built under the anchor's
    /// lock from the confirmed line this session has, with that line's state
    /// as its `base`, naming the flow `src` that wrote it and the password
    /// `pw` it is sealed with. A password-only session whose anchor cannot
    /// be written keeps it in memory.
    fn write_pending(
        &mut self,
        kh: &keyfile::KeyHeader,
        src: anchor::Src,
        pw: Option<anchor::Pw>,
        landing: &Landing,
    ) -> Result<anchor::PendingLine> {
        let legacy = self.key_file.header().is_none().then(|| {
            let current = key_id(&self.id, self.keys.current());
            anchor::legacy_hist(self.key_state, &current)
        });
        // The key file this write replaces.
        let kpath = anchor::kpath_of(&self.key_path);
        #[cfg(feature = "security-key")]
        let own = self.key_file.header().cloned();
        let (mut made, mut behind) = (None, None);
        let mut change = |lines: &mut anchor::Lines| {
            // Never below the state this PC confirmed, nor beside it at its
            // epoch: a session that took an older key file for current (its
            // precheck could not read the anchor) would take the anchor
            // back. At that epoch, that state itself (an adopt of it ends a
            // local rollback) or a file that holds its current key (a
            // successor, §5.8) is no step back.
            let below = |v: &&anchor::VaultLine| {
                v.state.epoch > kh.epoch
                    || (v.state.epoch == kh.epoch
                        && v.state.key_state() != kh.state()
                        && !kh.key_ids.contains(&v.state.keyid))
            };
            if let Some(v) = lines.vault.as_ref().filter(below) {
                behind = Some(v.state.epoch);
                return false;
            }
            let mut pending = anchor::pending_of(kh, lines.vault.as_ref(), legacy, kpath.clone());
            (pending.src, pending.pw) = (src, pw);
            #[cfg(feature = "security-key")]
            landing.apply(&mut pending, own.as_ref(), kh);
            made = Some(pending.clone());
            lines.pending = Some(pending);
            true
        };
        // A security-key state needs its line: no in-memory fallback.
        #[cfg(feature = "security-key")]
        if landing.strict {
            self.anchor_strict(&mut change)?;
        } else {
            self.anchor_update(anchor::LOCK_WAIT, &mut change)?;
        }
        #[cfg(not(feature = "security-key"))]
        {
            let _ = landing;
            self.anchor_update(anchor::LOCK_WAIT, &mut change)?;
        }
        if let Some(old) = behind {
            return Err(refuse(
                LOCAL_ROLLBACK,
                vec![old.to_string(), self.key_state.epoch.to_string()],
            ));
        }
        made.ok_or(AUTH_ERROR)
    }
    /// Deletes this session's pending line of `state` after a change that
    /// wrote nothing to the key file: the user was told right then (spec
    /// §5.5 "In-session errors"). Best effort.
    fn drop_pending(&mut self, state: keyfile::KeyState) {
        let _ = self.anchor_update(anchor::LOCK_WAIT, &mut |lines| {
            if lines
                .pending
                .as_ref()
                .is_some_and(|p| p.state.key_state() == state)
            {
                lines.pending = None;
                true
            } else {
                false
            }
        });
    }
    /// Whether the key file on disk is this session's: the file itself, or
    /// after a key change whose rename was cut off, the temp file standing
    /// in for it (spec §5.5 S2).
    fn key_on_disk(&self) -> Result<bool> {
        let want = self.key_file.bytes();
        match (&self.key_temp, read_bounded(&self.key_path, KEY_FILE_LIMIT)) {
            (_, Ok(key)) if key == want => Ok(true),
            (Some(temp), _) => Ok(read_bounded(temp, KEY_FILE_LIMIT)? == want),
            (None, key) => Ok(key? == want),
        }
    }
    /// What a failed write or read-back of the key file left (spec §5.5 S2):
    /// the new bytes, the old ones byte for byte, or with no key file, a
    /// temp file `gap` kept that holds the new ones.
    fn left(&self, old: &[u8], new: &[u8], gap: Option<PathBuf>) -> Left {
        match read_bounded(&self.key_path, KEY_FILE_LIMIT) {
            Ok(k) if k == new => Left::New,
            Ok(k) if k == old => Left::Old,
            Ok(_) => Left::Unknown,
            Err(_) => match gap {
                Some(temp) if read_bounded(&temp, KEY_FILE_LIMIT).ok().as_deref() == Some(new) => {
                    Left::Temp(temp)
                }
                _ => Left::Unknown,
            },
        }
    }
    /// S3v: the vault file reads back under the current key with this
    /// session's state and contents.
    fn vault_reads_back(&self) -> bool {
        let Ok(disk) = read_bounded(&self.path, super::MAX_FILE) else {
            return false;
        };
        matches!(
            decode_data(&self.id, self.keys.current(), self.keys.id_key(), &disk),
            Ok((format, header, c)) if format == self.format
                && header == self.header()
                && same(format, c.view(), self.data())
        )
    }
    /// S5: this vault's key file temps that a change of it left (best
    /// effort), but for the one standing in for the key file. The flow's
    /// Reauth holds the key file's lock.
    fn delete_key_temps(&self) {
        for c in recover::candidates(&self.key_path, recover::KEY_LIMIT) {
            let ours = keyfile::head(&c.bytes).is_some_and(|(id, _)| id == self.id);
            if ours && Some(&c.path) != self.key_temp.as_ref() {
                let _ = fs::remove_file(&c.path);
            }
        }
    }
    /// The rename of a key file that a key change left only as a temp file
    /// (spec §5.5 S2, E-S2b), tried at every save and poll and before the
    /// app locks. Done once the key file reads back as the session's, by
    /// whoever renamed it; given up only when the key file's folder reads
    /// and neither name is there with the session's bytes, and then the
    /// session asks for a key backup from memory (S-KEYTEMP-GONE). Any other
    /// read failure, such as an unplugged stick, keeps trying.
    pub(super) fn retry_key_temp(&mut self) {
        let Some(temp) = self.key_temp.clone() else {
            return;
        };
        let want = self.key_file.bytes();
        let read = |path: &Path| holds(path, want);
        let key = read(&self.key_path);
        if key == Some(true) {
            self.key_temp = None;
            return;
        }
        let kept = read(&temp);
        if kept == Some(true) && super::publish(&temp, &self.key_path, false).is_ok() {
            super::flush(&self.key_path);
            self.key_temp = None;
            return;
        }
        let folder = self.key_path.parent().is_some_and(|d| d.is_dir());
        if folder && key == Some(false) && kept == Some(false) {
            self.key_temp = None;
            (self.key_file_damaged, self.key_backup_due) = (true, true);
            self.key_notices.push(KeyNotice::KeyTempGone);
        }
    }
    /// After a change whose vault file could only be saved later: the save
    /// that did it seals the change in the anchor (`vkey`, `consumed`).
    pub(super) fn seal_saved(&mut self) {
        if !std::mem::replace(&mut self.seal_due, false) {
            return;
        }
        let Some(h) = self.key_file.header().cloned() else {
            return;
        };
        let state = self.key_state;
        let _ = self.anchor_update(anchor::LOCK_WAIT, &mut |lines| match lines.vault.as_mut() {
            Some(v) if v.state.key_state() == state => {
                v.vkey = Some(h.current_key_id());
                if h.resume != [0; 32] {
                    v.state.consumed = Some(h.resume);
                }
                true
            }
            _ => false,
        });
    }
    /// [이 열쇠 파일이 맞습니다] (spec §5.10): the key file of a local
    /// rollback becomes this vault's confirmed state, after a Reauth. The
    /// hold lifts and every verdict is derived again; a later key change of
    /// this PC that the confirmed line held is forgotten. Not for a Restore.
    pub fn confirm_key_file(&mut self, r: Reauth) -> Result<()> {
        if r.session != self.serial || r.age() > REAUTH_MAX {
            return Err(REAUTH_STALE);
        }
        if !self.local_rollback || self.restore_held {
            return Err(NOTHING_HELD);
        }
        let state = self.key_state;
        let current = key_id(&self.id, self.keys.current());
        let (header, magic) = (self.key_file.header().cloned(), self.key_file.magic());
        let otp = self.key_file.otp_secret();
        // The vault file is under that key now, as its unlock left it.
        let vkey = (header.is_none() || self.current()).then_some(current);
        self.anchor_update(anchor::LOCK_WAIT, &mut |lines| {
            let mut line = match (&header, magic) {
                (Some(h), _) => anchor::line_of(h, lines.vault.as_ref()),
                (None, Some(magic)) => {
                    anchor::legacy_line(state, magic, otp, &current, lines.vault.as_ref())
                }
                (None, None) => return false,
            };
            line.state.gated = state.epoch;
            line.vkey = vkey.or(line.vkey);
            if let Some(h) = &header
                && h.resume != [0; 32]
            {
                line.state.consumed = Some(h.resume);
            }
            lines.vault = Some(line);
            true
        })?;
        self.local_rollback = false;
        // The hold lifted: a line without `t` is a bootstrap's from now on,
        // with the TOFU banner and pass (spec §5.2 step 9(a)).
        #[cfg(feature = "security-key")]
        {
            self.tofu = std::mem::take(&mut self.held_unconfirmed);
        }
        self.relink();
        if let Some(link) = self.sync.as_mut() {
            link.mark_due();
        }
        self.flush_outgoing();
        Ok(())
    }
    /// [끝나지 않은 열쇠 변경 버리기…] (spec §5.10, S23-2 #2): after a
    /// Reauth, the pending line whose key file could not be read is removed
    /// as one that never landed, if it is still the one this session found.
    pub fn forget_pending(&mut self, r: Reauth) -> Result<()> {
        if r.session != self.serial || r.age() > REAUTH_MAX {
            return Err(REAUTH_STALE);
        }
        if self.pending_elsewhere.is_none() {
            return Err(NOTHING_HELD);
        }
        let found = self.anchor.lines.pending.clone();
        self.anchor_update(anchor::LOCK_WAIT, &mut |lines| {
            if lines.pending.is_some() && lines.pending == found {
                lines.pending = None;
                true
            } else {
                false
            }
        })?;
        self.pending_elsewhere = None;
        Ok(())
    }
    /// P1 of [서버 사본을 이 PC 상태로 덮어쓰기…] (spec §7.5a): the server
    /// copy that halts sync, for S-OVERRIDE-HEAD (`OVERRIDE_HEAD`). Refused
    /// during a local rollback, whose halt is most likely this PC's own
    /// newer state (S23-3 #5).
    pub fn head_to_override(&self) -> Result<HaltedHead> {
        self.not_rolled_back()?;
        // Nor before the key file is confirmed or its gate passed: the push
        // would write the vault file under its data key (spec §5.2, §7.17).
        #[cfg(feature = "security-key")]
        self.edit_held()?;
        self.halted_head().ok_or(NOTHING_HALTED)
    }
    /// P3 of the head override (spec §7.5a): after the Reauth, and only if
    /// no local rollback holds now and incoming is still exactly `head`,
    /// this PC's state is pushed over that server version. Nothing is
    /// persisted: a later unlock, or any other head, is judged again.
    pub fn override_head(&mut self, r: Reauth, head: &HaltedHead) -> Result<()> {
        if r.session != self.serial || r.age() > REAUTH_MAX {
            return Err(REAUTH_STALE);
        }
        // Nothing reaches the server that no vault file on disk holds.
        if self.gap_kept {
            return Err(GAP_KEPT);
        }
        if self.unsaved_key.is_some() {
            return Err(KEY_DAMAGED);
        }
        self.not_rolled_back()?;
        #[cfg(feature = "security-key")]
        self.edit_held()?;
        if !self.push_over_head(head)? {
            return Err(HEAD_CHANGED);
        }
        Ok(())
    }
    /// S-LOCAL-ROLLBACK, filled, while a local rollback holds.
    fn not_rolled_back(&self) -> Result<()> {
        if self.local_rollback {
            let old = self.confirmed_epoch().unwrap_or(0);
            return Err(refuse(
                LOCAL_ROLLBACK,
                vec![old.to_string(), self.key_state.epoch.to_string()],
            ));
        }
        Ok(())
    }
}
/// What the retry of a key file's rename finds at `path` (spec §5.5 S2):
/// Some(true) for exactly `want`; Some(false) for other bytes, a file too
/// large to be a key file (read no further: whoever can write the key
/// stick could put gigabytes there, read at every poll), or no file
/// (ERROR_FILE_NOT_FOUND). Anything else (no folder, no device, no access)
/// says nothing: None.
fn holds(path: &Path, want: &[u8]) -> Option<bool> {
    let mut bytes = Vec::new();
    let read = fs::File::open(path)
        .and_then(|f| f.take(KEY_FILE_LIMIT as u64 + 1).read_to_end(&mut bytes));
    match read {
        Ok(_) => Some(bytes == want),
        Err(e) if e.raw_os_error() == Some(2) => Some(false),
        Err(_) => None,
    }
}
/// A fresh `pw_id`, never zero (spec §4.1).
fn fresh_pw_id() -> Result<[u8; 16]> {
    let mut pw_id = [0; 16];
    while pw_id == [0; 16] {
        crypto::random_into(&mut pw_id)?;
    }
    Ok(pw_id)
}
/// The bundle of a rotation (spec §4.2): the new key first, then the old
/// ones; past MAX_KEYS the oldest that is not the ID key goes.
fn rotated(fresh: &[u8; 32], keys: &[[u8; 32]]) -> Zeroizing<Vec<[u8; 32]>> {
    let mut out = Zeroizing::new(Vec::with_capacity(keys.len() + 1));
    out.push(*fresh);
    out.extend_from_slice(keys);
    while out.len() > MAX_KEYS {
        let at = out.len() - 2;
        out.remove(at);
    }
    out
}
/// The same contents in `format`: the old OTP watermark (kept as it is) and
/// the entries' text, and for V2 also their IDs and parents, the tombstones
/// and the counters.
/// A V1 file stores no IDs: they are derived when it is read.
fn same(format: Format, a: DataRef, b: DataRef) -> bool {
    let v2 = format == Format::V2;
    a.last == b.last
        && (!v2
            || (a.generation == b.generation && a.seen == b.seen && a.tombstones == b.tombstones))
        && a.entries.len() == b.entries.len()
        && a.entries.iter().zip(b.entries).all(|(x, y)| {
            x.same_content(y) && (!v2 || (x.id() == y.id() && x.parent() == y.parent()))
        })
}

/// Password changes, their crash matrix and their failures without a crash
/// (spec §14.4, §14.5), each PC with its own anchor folder and the Test KDF
/// profile.
#[cfg(test)]
mod tests {
    use super::super::{
        AnchorClass, CHANGE_DONE_NEWPASS, CRASH, Entry, KeyNotice, LEFTOVER_TEMP, OLDER_REFUSED,
        Provision, SIMULATED_CRASH, THEN, VaultClass, anchor::Parsed, prepare, read_header,
        set_anchor_dir,
    };
    use super::*;
    use crate::{crypto, syncfile};
    use std::{cell::RefCell, path::Path, rc::Rc};

    pub(super) const FIRST: &str = "synthetic first password";
    pub(super) const OLD: &str = "synthetic old password";
    pub(super) const NEW: &str = "synthetic new password";

    /// One PC: a folder with the vault file, the key file and the PC's own
    /// anchor folder, removed with all in it.
    pub(super) struct Pc(pub(super) PathBuf);
    impl Pc {
        /// `name` in this PC's folder as a session names it (normalized).
        pub(super) fn canonical(&self, name: &str) -> PathBuf {
            fs::canonicalize(&self.0).unwrap().join(name)
        }
        pub(super) fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "goyo-rotate-{:x}",
                u128::from_le_bytes(*crypto::random::<16>().unwrap())
            ));
            fs::create_dir(&p).unwrap();
            let pc = Self(p);
            pc.here();
            pc
        }
        pub(super) fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        pub(super) fn vault(&self) -> PathBuf {
            self.file("vault.goyo")
        }
        pub(super) fn key(&self) -> PathBuf {
            self.file("vault.goyokey")
        }
        pub(super) fn anchor_dir(&self) -> PathBuf {
            self.file("anchor")
        }
        /// Every call from now on is this PC's.
        pub(super) fn here(&self) {
            set_anchor_dir(Some(self.anchor_dir()));
        }
        pub(super) fn anchor(&self) -> Vec<u8> {
            fs::read(self.anchor_dir().join("goyo-vault.keys")).unwrap_or_default()
        }
        pub(super) fn lines(&self, id: &[u8; 16]) -> anchor::Lines {
            match anchor::read(&self.anchor_dir()) {
                Ok(Parsed::Doc(doc)) => doc.lines(id),
                _ => panic!("anchor unreadable"),
            }
        }
        /// The temp files next to `path`.
        pub(super) fn temps(&self, path: &Path) -> Vec<PathBuf> {
            recover::candidates(path, super::super::MAX_FILE)
                .into_iter()
                .map(|c| c.path)
                .collect()
        }
    }
    impl Drop for Pc {
        fn drop(&mut self) {
            set_anchor_dir(None);
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    pub(super) fn entry(secret: &str) -> Entry {
        Entry::new("item".into(), "kind".into(), secret.into(), String::new()).unwrap()
    }
    pub(super) fn secrets(s: &Session) -> Vec<String> {
        s.entries
            .iter()
            .map(|e| e.secret.as_str().to_owned())
            .collect()
    }
    pub(super) fn login(pc: &Pc, password: &str) -> Result<Session> {
        pc.here();
        let prepared = prepare(&pc.vault(), &pc.key())?;
        Session::login(prepared, password, None)
    }
    /// A failed login: what the app then says instead of AUTH_ERROR.
    pub(super) fn refused(pc: &Pc, password: &str) -> Option<&'static str> {
        pc.here();
        let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
        let said = prepared.auth_failure();
        assert_eq!(
            Session::login(prepared, password, None).err(),
            Some(AUTH_ERROR)
        );
        said
    }
    pub(super) fn change(s: &mut Session, from: &str, to: &str) -> Result<Rekeyed> {
        let r = s.reauth(from, None)?;
        let to = Change::Password(Zeroizing::new(to.to_owned()));
        s.rekey(r, Vec::new(), to, Consent::default(), true)
    }
    /// The security-key build gates a key file changed elsewhere in a way
    /// the gate guards (a removal of a key this PC never knew, a silent
    /// jump; spec §5.10, §7.15a): the user types the code the other PC
    /// shows, which is the file's own. The keyless build has no gate.
    pub(super) fn pass_gate(s: &mut Session) {
        #[cfg(feature = "security-key")]
        if s.gate_pending() {
            let code = keyfile::key_code(&s.id, s.keys.current(), s.key_state());
            s.pass_login_gate(super::super::GateAnswer::Code(code))
                .unwrap();
        }
        #[cfg(not(feature = "security-key"))]
        let _ = s;
    }
    /// What a login says, but for the key backup reminder of a new state.
    pub(super) fn notices(s: &mut Session) -> Vec<KeyNotice> {
        s.take_key_notices()
            .into_iter()
            .filter(|n| *n != KeyNotice::KeyBackupDue)
            .collect()
    }
    /// A vault of `pc` with two entries and the password OLD: a 0.8 one, or
    /// one whose password changed once already (`kf2`: GOYOKE03, with this
    /// PC's anchor line); with `sync`, linked to a sync folder the helper
    /// made. `with_otp`: made with the removed OTP, so its 0.8 key file is
    /// GOYOKE01 with a TOTP secret, which no key change keeps.
    pub(super) fn setup(pc: &Pc, kf2: bool, with_otp: bool, sync: bool) -> Session {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let p = Provision::new().unwrap();
        let first = if kf2 { FIRST } else { OLD };
        let mut s = p.finish(&pc.vault(), &pc.key(), first).unwrap();
        if with_otp {
            drop(s);
            let old = keyfile::encode_key_otp(&p.id, &p.key, &[0x77; 20], first).unwrap();
            fs::write(pc.key(), old).unwrap();
            s = login(pc, first).unwrap();
            assert!(s.key_file.otp_secret());
        }
        s.put(None, entry("one")).unwrap();
        s.put(None, entry("two")).unwrap();
        if sync {
            let dir = syncfile::sync_dir(&pc.vault()).unwrap();
            fs::create_dir(&dir).unwrap();
            let now = crate::clock::now().unwrap();
            let status = syncfile::render_status(now, now, syncfile::SyncState::Ok);
            syncfile::replace_file(&dir.join(syncfile::STATUS), &status).unwrap();
            s.enable_sync().unwrap();
        }
        if kf2 {
            assert_eq!(change(&mut s, FIRST, OLD), Ok(Rekeyed::Done));
            s.take_key_notices();
        }
        s
    }
    /// The vault file's header and the key file's current key and state
    /// agree, and the vault file decodes under it (I3).
    pub(super) fn consistent(pc: &Pc, s: &Session) {
        let v = fs::read(pc.vault()).unwrap();
        assert_eq!(read_header(&v).unwrap().1, s.header());
        let h = KeyFile::read(&pc.key()).unwrap();
        assert_eq!(h.bytes(), s.key_file.bytes());
        assert!(decode_data(&s.id, s.keys.current(), s.keys.id_key(), &v).is_ok());
    }

    /// Where a crash leaves the key change landed (spec §5.6: from
    /// S2.renamed on).
    pub(super) const LANDED: [&str; 8] = [
        "S2.renamed",
        "S2v",
        "S3.tmp_synced",
        "S3.renamed",
        "S3v",
        "S4",
        "S5",
        "S5.tmp_synced",
    ];
    pub(super) const POINTS: [&str; 17] = [
        "S0",
        "S0.tmp_synced",
        "S1.tmp_synced",
        "S1.renamed",
        "S1.gap",
        "S1.done",
        "S2.tmp_synced",
        "S2.gap",
        "S2.renamed",
        "S2v",
        "S3.tmp_synced",
        "S3.gap",
        "S3.renamed",
        "S3v",
        "S4",
        "S5",
        "S5.tmp_synced",
    ];
    /// The replace gap of a step (spec §14.5), and the crash right after
    /// it: before the pending line of a change that did not happen is
    /// deleted (S1: E-S1g's "deletion failed"), before the commit of a key
    /// file left as its temp file (S2), before S4 and S5 with V′ left as its
    /// temp file (S3).
    pub(super) const GAPS: [(&str, &str); 3] = [
        ("S1.gap", "S1.gapped"),
        ("S2.gap", "S2v"),
        ("S3.gap", "S3.gapped"),
    ];

    /// What a crash test changes: the password, or the key file by an adopt
    /// of another PC's (spec §14.5: Adopt-successor, Adopt-union) whose
    /// password is NEW.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum What {
        Password,
        Successor,
        Union,
    }
    /// Another PC's key file of `s`'s vault, sealed with NEW: a later state
    /// that holds this PC's current key (a successor), or one at this PC's
    /// epoch that split from the 0.8 state (a fork, joined in a union). It
    /// holds no TOTP secret, whatever this PC's key file holds.
    pub(super) fn other_of(s: &Session, what: What) -> Vec<u8> {
        let epoch = s.key_state().epoch;
        let keys = match what {
            What::Union => vec![[0x43; 32], *s.keys.id_key()],
            _ => [&[[0x42; 32]][..], s.keys.keys()].concat(),
        };
        let epoch = if what == What::Union {
            epoch
        } else {
            epoch + 1
        };
        sealed(s.id, &keys, epoch, &[], NEW).0
    }
    /// The plan of an adopt of `other`, opened with `password`, as the flow
    /// makes it: checked (its class must be `class`), opened and previewed.
    pub(super) fn plan_of(
        s: &Session,
        r: &Reauth,
        other: &[u8],
        password: &str,
        class: AdoptClass,
    ) -> AdoptPlan {
        let file = KeyFile::from_bytes(Path::new("other.goyokey"), other.to_vec()).unwrap();
        let check = s
            .adopt_check(&file, Source::File(file.path().to_owned()))
            .unwrap();
        assert_eq!(check.class, class);
        let opened = s.adopt_open(r, &file, Some(password)).unwrap();
        s.adopt_preview(r, &file, opened, &check, GatePass::none(&check), None)
            .unwrap()
    }
    /// What the user answers at a plan's preview: the defaults, and yes to
    /// S-ADOPT-BOTHPASS where it is asked.
    pub(super) fn acks_of(plan: &AdoptPlan) -> Acks {
        Acks {
            password_only: false,
            union_password: UnionPassword::Other,
            both_passwords: plan.preview().both_passwords,
            #[cfg(feature = "security-key")]
            fork_option: ForkOption::Both,
            #[cfg(feature = "security-key")]
            keysync_on: false,
        }
    }
    /// A key change killed at `point`, then unlocked again (spec §5.6,
    /// §14.5): I1 to I6, I9, I11, I12 and I16, and the hints of §5.12.
    fn crash(what: What, point: &'static str, kf2: bool, with_otp: bool, sync: bool) {
        let case = format!("{what:?} {point} kf2={kf2} otp={with_otp} sync={sync}");
        let pc = Pc::new();
        let mut s = setup(&pc, kf2, with_otp, sync);
        let id = s.id;
        let other = (what != What::Password).then(|| other_of(&s, what));
        let before = secrets(&s);
        let old_key = fs::read(pc.key()).unwrap();
        let had_anchor = !pc.anchor().is_empty();
        // V_probe, as S1 wrote it, for I11.
        let probe = Rc::new(RefCell::new(None));
        let held = probe.clone();
        let vault = pc.vault();
        BEFORE.with(|b| {
            *b.borrow_mut() = Some((
                "S2",
                Box::new(move || *held.borrow_mut() = fs::read(&vault).ok()),
            ))
        });
        let r = s.reauth(OLD, None).unwrap();
        let last = s.last;
        let gap = GAPS
            .iter()
            .find(|(g, _)| *g == point)
            .map(|(_, then)| *then);
        THEN.with(|t| t.set(gap));
        let result = match &other {
            None => {
                CRASH.with(|c| c.set(Some(point)));
                let to = Change::Password(Zeroizing::new(NEW.to_owned()));
                s.rekey(r, Vec::new(), to, Consent::default(), true)
                    .map(|_| ())
            }
            Some(other) => {
                let class = match what {
                    What::Union => AdoptClass::Union,
                    _ => AdoptClass::Successor,
                };
                let plan = plan_of(&s, &r, other, NEW, class);
                let acks = acks_of(&plan);
                CRASH.with(|c| c.set(Some(point)));
                s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
                    .map(|_| ())
            }
        };
        assert_eq!(result, Err(SIMULATED_CRASH), "{case}");
        assert_eq!(CRASH.with(|c| c.get()), None, "{case}: point not reached");
        assert_eq!(THEN.with(|t| t.take()), None, "{case}: gap not reached");
        BEFORE.with(|b| b.borrow_mut().take());
        drop(s);
        let landed = LANDED.contains(&point) || matches!(point, "S2.gap" | "S3.gap");
        let (right, wrong) = if landed { (NEW, OLD) } else { (OLD, NEW) };
        // The pending line is on disk, or only in its temp file when the
        // anchor's very first write was cut off: a read takes that back.
        let pending_seen = point != "S0.tmp_synced" || !had_anchor;
        // I1 and the hints: the other factors fail, and the app says which
        // password the key file now takes (§5.12).
        let hint = refused(&pc, wrong);
        // Once promoted (S5) the change is plainly complete: no pending
        // line names its password any more.
        let want = if point == "S5" {
            None
        } else if point == "S2.gap" {
            // The new key file is only its temp file (rule i).
            Some(CHANGE_DONE_NEWPASS)
        } else if landed && what == What::Password {
            Some(super::super::AUTH_LANDED_NEW)
        } else if landed {
            Some(super::super::AUTH_LANDED_OTHER)
        } else if pending_seen {
            Some(super::super::AUTH_HINT_INTERRUPTED)
        } else {
            None
        };
        assert_eq!(hint, want, "{case}");
        // The recovery unlock: a change that never landed is dropped and
        // said once; a landed one completes silently.
        let mut s = login(&pc, right).unwrap_or_else(|e| panic!("{case}: {e}"));
        let said = notices(&mut s);
        let unfinished = said
            .iter()
            .filter(|n| **n == KeyNotice::NotFinished)
            .count();
        let not_finished = !landed && (pending_seen || point == "S2.tmp_synced");
        assert_eq!(unfinished, usize::from(not_finished), "{case}: {said:?}");
        // I16: no rollback, refusal or fallback for this PC's own write.
        assert!(
            said.iter()
                .all(|n| matches!(n, KeyNotice::NotFinished | KeyNotice::Resumed)),
            "{case}: {said:?}"
        );
        if matches!(point, "S2.renamed" | "S2v" | "S3.tmp_synced" | "S2.gap") {
            assert_eq!(said, [KeyNotice::Resumed], "{case}");
        }
        // The vault file only in its temp file: rule (iii) took it back.
        assert_eq!(
            s.take_recovery().vault,
            matches!(point, "S1.gap" | "S3.gap"),
            "{case}"
        );
        // I2: the contents, and the old OTP watermark as it was.
        assert_eq!(secrets(&s), before, "{case}");
        assert_eq!(s.last, last, "{case}");
        // I3: the vault file under the key file's current key and state, no
        // key file temp left, nor a vault file temp with what it holds.
        consistent(&pc, &s);
        assert!(pc.temps(&pc.key()).is_empty(), "{case}");
        assert!(pc.temps(&pc.vault()).is_empty(), "{case}");
        // I9: a successor keeps the other file's state.
        if landed && what == What::Successor {
            let other = keyfile::parse(other.as_deref().unwrap()).unwrap();
            assert_eq!(s.key_state(), other.state(), "{case}");
        }
        // The anchor: no pending line left, the confirmed state the key
        // file's, the vault file's key sealed, and no line it cannot read.
        let lines = pc.lines(&id);
        assert!(lines.pending.is_none(), "{case}");
        if s.key_file.header().is_some() {
            let line = lines.vault.clone().expect("a confirmed line");
            assert_eq!(line.state.key_state(), s.key_state(), "{case}");
            assert_eq!(
                line.vkey,
                s.key_file.header().map(|h| h.current_key_id()),
                "{case}"
            );
        } else {
            assert!(lines.vault.is_none(), "{case}: a 0.8 session wrote a line");
        }
        assert!(anchor_doc(&pc).is_clean(), "{case}");
        // I4: from S2.renamed on, the old key file with the old password no
        // longer opens the vault file.
        if landed {
            let old = KeyFile::from_bytes(&pc.key(), old_key.clone()).unwrap();
            let old = old.open(OLD, None).unwrap();
            let v = fs::read(pc.vault()).unwrap();
            assert!(
                old.bundle
                    .keys()
                    .iter()
                    .all(|k| decode_data(&id, k, old.bundle.id_key(), &v).is_err()),
                "{case}"
            );
        }
        // I5: an outgoing copy is under the current key.
        if sync {
            let dir = syncfile::sync_dir(&pc.vault()).unwrap();
            if let Ok(bytes) = fs::read(dir.join(syncfile::OUTGOING)) {
                let (_, blob) = syncfile::parse_outgoing(&bytes).unwrap();
                let (_, header, _) =
                    decode_data(&id, s.keys.current(), s.keys.id_key(), blob).unwrap();
                assert_eq!(header, s.header(), "{case}");
            }
        }
        drop(s);
        // I6: a second unlock writes nothing, also for a vault made with
        // the removed OTP; its key file holds no TOTP secret once the
        // change landed.
        let files = (fs::read(pc.key()).unwrap(), pc.anchor());
        let v = fs::read(pc.vault()).unwrap();
        let mut s = login(&pc, right).unwrap();
        assert!(notices(&mut s).is_empty(), "{case}");
        assert_eq!((fs::read(pc.key()).unwrap(), pc.anchor()), files, "{case}");
        assert_eq!(fs::read(pc.vault()).unwrap(), v, "{case}");
        assert!(
            !s.key_file.otp_secret() || s.key_file.bytes() == old_key.as_slice(),
            "{case}"
        );
        assert_eq!(secrets(&s), before, "{case}");
        drop(s);
        // I11: the change completed, so its probe restored in place of the
        // vault file is refused before any key derivation.
        if landed {
            let probe = probe.borrow().clone().expect("the probe");
            let current = fs::read(pc.vault()).unwrap();
            fs::write(pc.vault(), &probe).unwrap();
            pc.here();
            let derived = crypto::derive_count();
            assert_eq!(
                prepare(&pc.vault(), &pc.key()).err(),
                Some(OLDER_REFUSED),
                "{case}"
            );
            assert_eq!(crypto::derive_count(), derived);
            fs::write(pc.vault(), current).unwrap();
        }
    }
    /// The anchor of `pc` as read.
    pub(super) fn anchor_doc(pc: &Pc) -> anchor::Anchor {
        match anchor::read(&pc.anchor_dir()) {
            Ok(Parsed::Doc(doc)) => doc,
            _ => panic!("anchor unreadable"),
        }
    }

    /// Every crash point of a password change from a 0.8 key file and from
    /// a GOYOKE03 one, the replace gaps each followed by a crash included,
    /// for a 0.8 vault made with the removed OTP too, with and without
    /// vault sync (spec §14.5).
    #[test]
    fn every_crash_point_leaves_a_pair_that_opens() {
        for kf2 in [false, true] {
            for with_otp in [false, true] {
                for sync in [false, true] {
                    for point in POINTS {
                        crash(What::Password, point, kf2, with_otp, sync);
                    }
                }
            }
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// The same for an adopt (spec §5.6 C11 and C13): the successor
    /// re-seal, from a 0.8 key file and from a GOYOKE03 one, and a union
    /// with a forked file.
    #[test]
    fn every_crash_point_of_an_adopt_leaves_a_pair_that_opens() {
        for (what, kf2) in [
            (What::Successor, false),
            (What::Successor, true),
            (What::Union, true),
        ] {
            for with_otp in [false, true] {
                for sync in [false, true] {
                    for point in POINTS {
                        crash(what, point, kf2, with_otp, sync);
                    }
                }
            }
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    pub(super) const THIRD: &str = "synthetic third password";
    /// The key file's current key ID.
    pub(super) fn current_id(s: &Session) -> Option<[u8; 16]> {
        s.key_file.header().map(|h| h.current_key_id())
    }
    /// What `pc`'s vault file, key file and anchor hold.
    pub(super) fn files(pc: &Pc) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            fs::read(pc.vault()).unwrap_or_default(),
            fs::read(pc.key()).unwrap_or_default(),
            pc.anchor(),
        )
    }
    pub(super) fn set_before(step: &'static str, act: impl FnOnce() + 'static) {
        BEFORE.with(|b| *b.borrow_mut() = Some((step, Box::new(act))));
    }

    /// E-S1g: the vault file's replace at S1 hit the gap. The key did not
    /// change, the change is not reported again, the session writes the
    /// vault file no more, and the old factors take V_probe back from its
    /// temp file with no question and no hint (spec §5.5 S1, §5.6).
    #[test]
    fn a_gap_at_s1_changes_nothing() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let key = fs::read(pc.key()).unwrap();
        CRASH.with(|c| c.set(Some("S1.gap")));
        assert_eq!(change(&mut s, OLD, NEW), Err(GAP_NOT_CHANGED));
        assert!(s.gap_kept() && !pc.vault().exists());
        assert_eq!(pc.temps(&pc.vault()).len(), 1);
        assert_eq!(fs::read(pc.key()).unwrap(), key);
        assert!(pc.lines(&id).pending.is_none());
        assert_eq!(s.put(None, entry("lost")), Err(GAP_KEPT));
        drop(s);
        assert_eq!(refused(&pc, NEW), None);
        let mut s = login(&pc, OLD).unwrap();
        assert!(s.take_recovery().vault);
        assert_eq!(notices(&mut s), []);
        assert_eq!(secrets(&s), ["one", "two"]);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-S2a: the key file cannot be replaced and reads back as it was:
    /// nothing changed, and only this one case says so. The vault file is
    /// V_probe under the old key, which the session and the next unlock
    /// keep using, with nothing to report.
    #[test]
    fn a_key_file_that_cannot_be_replaced_changes_nothing() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let key = pc.key();
        let locked = key.clone();
        set_before("S2", move || {
            let mut p = fs::metadata(&locked).unwrap().permissions();
            p.set_readonly(true);
            fs::set_permissions(&locked, p).unwrap();
        });
        assert_eq!(change(&mut s, OLD, NEW), Err(KEY_NOT_SAVED));
        let mut p = fs::metadata(&key).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        fs::set_permissions(&key, p).unwrap();
        assert!(pc.lines(&id).pending.is_none());
        s.put(None, entry("three")).unwrap();
        drop(s);
        assert_eq!(refused(&pc, NEW), None);
        let mut s = login(&pc, OLD).unwrap();
        assert_eq!(notices(&mut s), []);
        assert_eq!(secrets(&s), ["one", "two", "three"]);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-S2b: the key file's replace hit the gap: the key file is gone and
    /// its temp file holds the new one. The change commits; a key backup
    /// compares with the temp file; the next save renames it (spec §5.5
    /// S2). A crash before that leaves the new key file only as a temp
    /// file: the new factors take it back (rule i), the old ones are told
    /// the change almost finished (S-CHANGE-DONE-NEWPASS, S23-2 #7).
    #[test]
    fn a_gap_at_s2_commits_from_the_kept_temp_file() {
        for crash_after in [false, true] {
            let pc = Pc::new();
            let mut s = setup(&pc, true, false, false);
            CRASH.with(|c| c.set(Some("S2.gap")));
            assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
            assert!(s.key_temp() && !pc.key().exists());
            assert_eq!(s.take_key_notices(), [KeyNotice::KeyTemp]);
            let temp = pc.temps(&pc.key());
            assert_eq!(temp.len(), 1);
            assert_eq!(fs::read(&temp[0]).unwrap(), s.key_file.bytes());
            let backup = pc.file("backup.goyokey");
            s.backup_key(&backup).unwrap();
            assert!(KeyFile::read(&backup).unwrap().open(NEW, None).is_ok());
            if crash_after {
                drop(s);
                assert_eq!(refused(&pc, OLD), Some(CHANGE_DONE_NEWPASS));
                let mut s = login(&pc, NEW).unwrap();
                assert_eq!(notices(&mut s), []);
                assert!(pc.key().exists() && pc.temps(&pc.key()).is_empty());
                consistent(&pc, &s);
            } else {
                s.put(None, entry("three")).unwrap();
                assert!(!s.key_temp() && pc.key().exists());
                assert!(pc.temps(&pc.key()).is_empty());
                consistent(&pc, &s);
                drop(s);
                drop(login(&pc, NEW).unwrap());
            }
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// C4g: a crash once the new key file is in place, and the replace of
    /// the key file cut it back to a temp file: rule (i) opens it with the
    /// new factors and completes the change; the old ones are told the
    /// change almost finished, never the rename advice.
    #[test]
    fn a_landed_key_file_left_as_a_temp_file_completes() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        CRASH.with(|c| c.set(Some("S2v")));
        assert_eq!(change(&mut s, OLD, NEW), Err(SIMULATED_CRASH));
        drop(s);
        let mut name = pc.key().into_os_string();
        name.push(format!(".{:032x}.goyotmp", 0x5eu8));
        fs::rename(pc.key(), &name).unwrap();
        assert_eq!(refused(&pc, OLD), Some(CHANGE_DONE_NEWPASS));
        let mut s = login(&pc, NEW).unwrap();
        assert_eq!(notices(&mut s), [KeyNotice::Resumed]);
        assert!(pc.key().exists() && !Path::new(&name).exists());
        consistent(&pc, &s);
        drop(s);
        // An older key file's temp, below the state this PC confirmed, is
        // only the rename advice: here with the vault file of its time.
        let pc = Pc::new();
        let s = setup(&pc, true, false, false);
        let older = s.key_file.bytes().to_vec();
        let vault = fs::read(pc.vault()).unwrap();
        drop(s);
        let mut s = login(&pc, OLD).unwrap();
        change(&mut s, OLD, NEW).unwrap();
        drop(s);
        fs::write(pc.vault(), vault).unwrap();
        fs::remove_file(pc.key()).unwrap();
        let mut name = pc.key().into_os_string();
        name.push(format!(".{:032x}.goyotmp", 0x6fu8));
        fs::write(&name, older).unwrap();
        assert_eq!(refused(&pc, NEW), Some(LEFTOVER_TEMP));
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-S2b to its end: the key file and its temp file both gone, read as
    /// gone, give S-KEYTEMP-GONE and a key backup from memory; a key folder
    /// that cannot be read (an unplugged stick) only keeps the retry going,
    /// and the rename succeeds once it is back (S23-1 #7, S23-3 #11).
    #[test]
    fn a_kept_key_temp_file_is_retried_until_it_is_known_gone() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let pc = Pc::new();
        let keys = pc.file("stick");
        fs::create_dir(&keys).unwrap();
        let key = keys.join("vault.goyokey");
        let mut s = Provision::new()
            .unwrap()
            .finish(&pc.vault(), &key, OLD)
            .unwrap();
        s.put(None, entry("one")).unwrap();
        CRASH.with(|c| c.set(Some("S2.gap")));
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        assert!(s.key_temp());
        s.take_key_notices();
        // The stick is pulled: nothing is decided.
        let away = pc.file("stick-away");
        fs::rename(&keys, &away).unwrap();
        s.before_lock();
        assert!(s.key_temp() && !s.key_file_damaged);
        assert_eq!(s.take_key_notices(), []);
        // A second change before it is back: refused for the missing key
        // file, with nothing written.
        assert!(change(&mut s, NEW, THIRD).is_err());
        // Back: the rename happens.
        fs::rename(&away, &keys).unwrap();
        s.before_lock();
        assert!(!s.key_temp() && key.exists());
        assert_eq!(fs::read(&key).unwrap(), s.key_file.bytes());
        drop(s);
        // Both names read and gone: a key backup from memory, which opens.
        let mut s = Session::unlock(&pc.vault(), &key, NEW).unwrap();
        s.take_key_notices();
        CRASH.with(|c| c.set(Some("S2.gap")));
        assert_eq!(change(&mut s, NEW, THIRD), Ok(Rekeyed::Done));
        s.take_key_notices();
        for temp in pc.temps(&key) {
            fs::remove_file(temp).unwrap();
        }
        s.before_lock();
        assert!(!s.key_temp() && s.key_file_damaged && s.key_backup_due());
        assert_eq!(s.take_key_notices(), [KeyNotice::KeyTempGone]);
        let backup = pc.file("from-memory.goyokey");
        s.backup_key(&backup).unwrap();
        drop(s);
        fs::copy(&backup, &key).unwrap();
        drop(Session::unlock(&pc.vault(), &key, THIRD).unwrap());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// The retry reads either name no further than a key file can be: a
    /// file far over the limit (whoever can write the key stick can put
    /// gigabytes there, read at every poll) is other bytes, so
    /// S-KEYTEMP-GONE is still decided. Here the key file's bytes past 64
    /// KiB are locked by another handle, which a read of them fails on.
    #[cfg(windows)]
    #[test]
    fn a_key_file_far_over_the_limit_is_read_no_further() {
        use std::{ffi::c_void, os::windows::io::AsRawHandle};
        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            event: *mut c_void,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LockFileEx(
                file: *mut c_void,
                flags: u32,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut Overlapped,
            ) -> i32;
        }
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        CRASH.with(|c| c.set(Some("S2.gap")));
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        assert!(s.key_temp());
        s.take_key_notices();
        for temp in pc.temps(&pc.key()) {
            fs::remove_file(temp).unwrap();
        }
        fs::write(pc.key(), vec![0x55; 1 << 20]).unwrap();
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pc.key())
            .unwrap();
        let mut past = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 1 << 16,
            offset_high: 0,
            event: std::ptr::null_mut(),
        };
        // LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY.
        let locked = unsafe { LockFileEx(lock.as_raw_handle(), 3, 0, u32::MAX, 0, &mut past) };
        assert_ne!(locked, 0);
        s.before_lock();
        assert!(!s.key_temp() && s.key_file_damaged && s.key_backup_due());
        assert_eq!(s.take_key_notices(), [KeyNotice::KeyTempGone]);
        drop(lock);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-S3g: the vault file's replace at S3 hit the gap: the new key file
    /// stays, S4 is skipped and S5 runs (the vault file's key sealed, the
    /// change not yet consumed), and the app locks. The new factors take V′
    /// back by rule (iii) and seal it then (spec §5.5 S3).
    #[test]
    fn a_gap_at_s3_keeps_the_change() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, true);
        let id = s.id;
        let dir = syncfile::sync_dir(&pc.vault()).unwrap();
        let outgoing = fs::read(dir.join(syncfile::OUTGOING)).ok();
        CRASH.with(|c| c.set(Some("S3.gap")));
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::GapKept));
        assert!(s.gap_kept() && !pc.vault().exists());
        assert!(KeyFile::read(&pc.key()).unwrap().open(NEW, None).is_ok());
        let resume = s.key_file.header().unwrap().resume;
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), s.key_state());
        assert_eq!(line.vkey, current_id(&s));
        assert_ne!(line.state.consumed, Some(resume));
        assert!(pc.lines(&id).pending.is_none());
        assert_eq!(fs::read(dir.join(syncfile::OUTGOING)).ok(), outgoing);
        drop(s);
        assert_eq!(refused(&pc, OLD), None);
        let mut s = login(&pc, NEW).unwrap();
        assert!(s.take_recovery().vault);
        assert_eq!(secrets(&s), ["one", "two"]);
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.state.consumed, Some(resume));
        consistent(&pc, &s);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-S2c: whether the new key file was saved cannot be told (the key
    /// file's path is no file any more). The session keeps the old keys,
    /// writes the vault file no more, and holds the new key file for a key
    /// backup, which with the new password opens V_probe by its resume.
    #[test]
    fn a_key_file_of_unknown_state_is_kept_for_a_backup() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let key = pc.key();
        let gone = key.clone();
        set_before("S2", move || {
            fs::remove_file(&gone).unwrap();
            fs::create_dir(&gone).unwrap();
        });
        assert_eq!(change(&mut s, OLD, NEW), Err(KEY_DAMAGED));
        assert!(s.key_unsaved());
        assert_eq!(s.password_change(), Err(KEY_DAMAGED));
        assert_eq!(s.put(None, entry("x")), Err(KEY_DAMAGED));
        let backup = pc.file("saved.goyokey");
        s.backup_key(&backup).unwrap();
        drop(s);
        fs::remove_dir(&key).unwrap();
        fs::copy(&backup, &key).unwrap();
        let mut s = login(&pc, NEW).unwrap();
        assert_eq!(notices(&mut s), [KeyNotice::Resumed]);
        assert_eq!(secrets(&s), ["one", "two"]);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-VP: the vault file cannot be replaced at S3 (another program holds
    /// it): the change goes on with S4 and S5, the save that later works
    /// seals it, a second change in the same session starts from it, and the
    /// probe never completes again (spec §5.5 S3, I11).
    #[test]
    fn a_vault_file_saved_later_still_completes_the_change() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, true);
        let id = s.id;
        let held = Rc::new(RefCell::new(None));
        let hold = held.clone();
        let vault = pc.vault();
        set_before("S3", move || {
            *hold.borrow_mut() = Some(fs::File::open(&vault).unwrap())
        });
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::VaultPending));
        assert!(s.resave_due);
        let probe = fs::read(pc.vault()).unwrap();
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), s.key_state());
        assert!(pc.lines(&id).pending.is_none());
        assert_ne!(line.vkey, current_id(&s));
        let dir = syncfile::sync_dir(&pc.vault()).unwrap();
        let bytes = fs::read(dir.join(syncfile::OUTGOING)).unwrap();
        let (_, blob) = syncfile::parse_outgoing(&bytes).unwrap();
        assert_eq!(
            decode_data(&id, s.keys.current(), s.keys.id_key(), blob)
                .unwrap()
                .1,
            s.header()
        );
        drop(held.borrow_mut().take());
        let _ = s.poll_sync();
        assert!(!s.resave_due);
        consistent(&pc, &s);
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.vkey, current_id(&s));
        assert_eq!(
            line.state.consumed,
            Some(s.key_file.header().unwrap().resume)
        );
        assert_eq!(change(&mut s, NEW, THIRD), Ok(Rekeyed::Done));
        drop(s);
        let mut s = login(&pc, THIRD).unwrap();
        assert_eq!(notices(&mut s), []);
        drop(s);
        fs::write(pc.vault(), probe).unwrap();
        pc.here();
        assert_eq!(prepare(&pc.vault(), &pc.key()).err(), Some(OLDER_REFUSED));
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-SIDE: the anchor cannot be written. A password-only session says so
    /// once, keeps what it should hold in memory, completes the change and
    /// a second one, and writes it all at the next save that can (spec
    /// §5.10, S23-3 #10). The same when only the promotion (S5) cannot be
    /// written: another process holds the anchor's lock past the wait.
    #[test]
    fn an_anchor_that_cannot_be_written_is_kept_in_memory() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let anchor = pc.anchor();
        let blocker = pc.file("blocker");
        fs::write(&blocker, b"no folder").unwrap();
        let real = s.anchor.dir.replace(blocker.join("anchor"));
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        assert_eq!(s.take_key_notices(), [KeyNotice::SidecarFailed]);
        assert_eq!(pc.anchor(), anchor);
        assert_eq!(change(&mut s, NEW, THIRD), Ok(Rekeyed::Done));
        assert_eq!(s.take_key_notices(), []);
        s.anchor.dir = real;
        s.put(None, entry("three")).unwrap();
        assert!(s.take_key_notices().is_empty());
        let lines = pc.lines(&id);
        assert_eq!(lines.vault.unwrap().state.key_state(), s.key_state());
        assert!(lines.pending.is_none());
        drop(s);
        let mut s = login(&pc, THIRD).unwrap();
        assert_eq!(notices(&mut s), []);
        // Only S5 fails: the lock is held while S3 runs, and released after.
        let lock = Rc::new(RefCell::new(None));
        let hold = lock.clone();
        let dir = pc.anchor_dir();
        set_before("S3", move || {
            *hold.borrow_mut() = Some(anchor::hold_lock(&dir))
        });
        assert_eq!(change(&mut s, THIRD, NEW), Ok(Rekeyed::Done));
        assert_eq!(s.take_key_notices(), [KeyNotice::SidecarFailed]);
        let lines = pc.lines(&id);
        assert_eq!(lines.pending.unwrap().state.key_state(), s.key_state());
        drop(lock.borrow_mut().take());
        let _ = s.poll_sync();
        let lines = pc.lines(&id);
        assert!(lines.pending.is_none());
        assert_eq!(lines.vault.unwrap().state.key_state(), s.key_state());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A new key file or vault file that does not verify in memory is never
    /// written (spec §14.4-13): every file stays as it was.
    #[test]
    fn a_new_file_that_does_not_verify_is_never_written() {
        for which in ["K", "V"] {
            let pc = Pc::new();
            let mut s = setup(&pc, true, false, false);
            let before = files(&pc);
            CORRUPT.with(|c| c.set(Some(which)));
            assert_eq!(change(&mut s, OLD, NEW), Err(NOT_VERIFIED));
            assert_eq!(CORRUPT.with(|c| c.get()), None);
            assert_eq!(files(&pc), before, "{which}");
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// R0 (spec §5.5): what refuses a password change before anything is
    /// written: the same password, a weak one, a Reauth of another session
    /// or older than REAUTH_MAX, a key file changed on disk, an unanswered gate and the last epoch.
    #[test]
    fn a_password_change_is_refused_before_anything_is_written() {
        let rekey = |s: &mut Session, r: Reauth, to: &str, gate: bool| {
            let to = Change::Password(Zeroizing::new(to.to_owned()));
            s.rekey(r, Vec::new(), to, Consent::default(), gate)
        };
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let before = files(&pc);
        let reauth = |s: &mut Session| s.reauth(OLD, None).unwrap();
        let r = reauth(&mut s);
        assert_eq!(rekey(&mut s, r, OLD, true), Err(SAMEPASS));
        let r = reauth(&mut s);
        assert!(rekey(&mut s, r, "password1234", true).is_err());
        let mut r = reauth(&mut s);
        r.session ^= 1;
        assert_eq!(rekey(&mut s, r, NEW, true), Err(REAUTH_STALE));
        // Older than REAUTH_MAX on the clock a test moves.
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
        crate::crypto::set_test_clock(Some(clock.clone()));
        let r = reauth(&mut s);
        clock.fetch_add(
            REAUTH_MAX.as_millis() as u64 + 1000,
            std::sync::atomic::Ordering::SeqCst,
        );
        assert_eq!(r.remaining(), Duration::ZERO);
        assert_eq!(rekey(&mut s, r, NEW, true), Err(REAUTH_STALE));
        crate::crypto::set_test_clock(None);
        // A gate the user was not asked about.
        s.stale_key_file = true;
        assert_eq!(s.password_change(), Ok(Some(Gate::StaleKeyFile)));
        let r = reauth(&mut s);
        assert_eq!(rekey(&mut s, r, NEW, false), Err(GATE_STALE));
        s.stale_key_file = false;
        // The last epoch: nothing past EPOCH_MAX.
        s.max_epoch = EPOCH_MAX;
        let r = reauth(&mut s);
        assert_eq!(rekey(&mut s, r, NEW, true), Err(EPOCH_LIMIT));
        s.max_epoch = s.key_state.epoch;
        assert_eq!(files(&pc), before);
        // A key file changed on disk since the Reauth.
        let r = reauth(&mut s);
        let mut other = before.1.clone();
        other.push(0);
        fs::write(pc.key(), &other).unwrap();
        assert_eq!(rekey(&mut s, r, NEW, true), Err(KEY_CHANGED));
        drop(s);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// Seventy changes keep 64 data keys: the newest first, the previous
    /// one after it and the ID key last, so a 0.8 backup still restores with
    /// the newest key file; the entry IDs and the ID key never change
    /// (spec §4.2, §14.4-2/3/11).
    #[test]
    fn seventy_changes_keep_the_newest_keys_and_the_id_key() {
        let pc = Pc::new();
        let mut s = setup(&pc, false, false, true);
        let backup = pc.file("backup-08.goyo");
        s.backup(&backup).unwrap();
        let ids: Vec<EntryIdOf> = s.entries.iter().map(|e| e.id()).collect();
        let id_key = *s.keys.id_key();
        let mut password = OLD.to_owned();
        let mut previous = *s.keys.current();
        for n in 0..70 {
            let next = format!("synthetic password number {n}");
            assert_eq!(change(&mut s, &password, &next), Ok(Rekeyed::Done));
            assert_eq!(s.keys.keys()[1], previous);
            previous = *s.keys.current();
            password = next;
        }
        assert_eq!(s.keys.keys().len(), MAX_KEYS);
        assert_eq!(*s.keys.id_key(), id_key);
        assert_eq!(s.key_state().epoch, 70);
        assert_eq!(s.entries.iter().map(|e| e.id()).collect::<Vec<_>>(), ids);
        let restored = pc.file("restored.goyo");
        drop(s);
        let r = Session::restore(&backup, &pc.key(), &restored, &password).unwrap();
        assert_eq!(secrets(&r), ["one", "two"]);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    type EntryIdOf = super::super::EntryId;

    /// A GOYOKE03 key file of the vault `id` with `keys`, sealed at `epoch`
    /// with `password`, carrying `tombs` (credhash, epoch of removal); its
    /// bytes and state.
    pub(super) fn sealed(
        id: [u8; 16],
        keys: &[[u8; 32]],
        epoch: u64,
        tombs: &[([u8; 16], u64)],
        password: &str,
    ) -> (Vec<u8>, keyfile::KeyState) {
        sealed_with(id, keys, None, epoch, tombs, password)
    }
    /// The same with the TOTP secret `otp` of a vault made with the removed
    /// OTP: an old file, which no writer makes now.
    pub(super) fn sealed_with(
        id: [u8; 16],
        keys: &[[u8; 32]],
        otp: Option<&[u8; 20]>,
        epoch: u64,
        tombs: &[([u8; 16], u64)],
        password: &str,
    ) -> (Vec<u8>, keyfile::KeyState) {
        let mut pw_id = [0; 16];
        crypto::random_into(&mut pw_id).unwrap();
        let spec = Spec {
            vault_id: id,
            epoch,
            kind: Kind::Password,
            next: 1,
            pw_id,
            loss: 0,
            tombstones: tombs
                .iter()
                .map(|(credhash, removed)| keyfile::Tombstone {
                    credhash: *credhash,
                    removed: *removed,
                })
                .collect(),
            resume: [0; 32],
        };
        let bundle = Bundle::new(keys).unwrap();
        let bytes = match otp {
            Some(otp) => keyfile::seal_old_otp(&spec, &bundle, password, otp),
            None => {
                keyfile::seal(&spec, &bundle, password, Plan::PasswordOnly)
                    .unwrap()
                    .0
            }
        };
        let state = keyfile::parse(&bytes).unwrap().state();
        (bytes, state)
    }
    /// A vault file of `s`'s contents under `key`, written by a key file in
    /// `state`.
    pub(super) fn vault_of(s: &Session, key: &[u8; 32], state: keyfile::KeyState) -> Vec<u8> {
        let header = Header::Keyed {
            key_id: key_id(&s.id, key),
            state,
            flags: 0,
        };
        encode_data(&s.id, key, &header, s.format, s.data()).unwrap()
    }
    /// The data keys of the key file `bytes`, opened with `password`.
    pub(super) fn keys_of(bytes: &[u8], password: &str) -> Vec<[u8; 32]> {
        let file = KeyFile::from_bytes(Path::new("k.goyokey"), bytes.to_vec()).unwrap();
        file.open(password, None).unwrap().bundle.keys().to_vec()
    }
    /// Whether precheck refuses with `text`, before any key derivation.
    pub(super) fn precheck_refuses(pc: &Pc, key: &Path, text: &str) {
        pc.here();
        let derived = crypto::derive_count();
        assert_eq!(prepare(&pc.vault(), key).err(), Some(text));
        assert_eq!(crypto::derive_count(), derived);
        assert!(super::super::not_a_failure(text));
    }

    /// An older genuine pair of this PC put back is a local rollback (spec
    /// §5.10): it opens, and key changes, uploads and merges wait (a copy in
    /// incoming at that unlock is not even read, S23-2 #5) until the user
    /// confirms the key file after a Reauth, which records it as the state
    /// of this vault on this PC.
    #[test]
    fn an_older_pair_put_back_is_held_until_confirmed() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, true);
        let id = s.id;
        let (k1, v1) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        let dk1 = *s.keys.current();
        let state1 = s.key_state();
        // A copy under the old key, with an entry this PC lacks.
        let mut planted = s.entries.clone();
        planted.push(entry("planted"));
        planted[2].set_ids([0x99; 16], super::super::NO_ID);
        let copy = {
            let header = Header::Keyed {
                key_id: key_id(&id, &dk1),
                state: state1,
                flags: 0,
            };
            let d = DataRef {
                last: 0,
                generation: s.generation + 1,
                seen: 0,
                entries: &planted,
                tombstones: &s.tombstones,
            };
            encode_data(&id, &dk1, &header, Format::V2, d).unwrap()
        };
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        s.put(None, entry("three")).unwrap();
        drop(s);
        fs::write(pc.key(), &k1).unwrap();
        fs::write(pc.vault(), &v1).unwrap();
        let dir = syncfile::sync_dir(&pc.vault()).unwrap();
        let incoming = syncfile::render_incoming(7, &copy).unwrap();
        syncfile::replace_file(&dir.join(syncfile::INCOMING), &incoming).unwrap();
        let outgoing = fs::read(dir.join(syncfile::OUTGOING)).ok();
        let mut s = login(&pc, OLD).unwrap();
        assert_eq!(
            notices(&mut s),
            [KeyNotice::LocalRollback { old: 2, new: 1 }]
        );
        assert!(s.local_rollback() && !s.restore_held());
        assert_eq!(secrets(&s), ["one", "two"]);
        assert_eq!(s.password_change(), Err(super::super::LOCAL_ROLLBACK));
        assert_eq!(
            super::super::refusal_values(super::super::LOCAL_ROLLBACK),
            Some(vec!["2".into(), "1".into()])
        );
        // Edits are saved, but neither uploaded nor merged.
        s.put(None, entry("local")).unwrap();
        let _ = s.poll_sync();
        assert_eq!(secrets(&s), ["one", "two", "local"]);
        assert_eq!(fs::read(dir.join(syncfile::OUTGOING)).ok(), outgoing);
        assert_eq!(pc.lines(&id).vault.unwrap().state.epoch, 2);
        // [이 열쇠 파일이 맞습니다] after a Reauth.
        let r = s.reauth(OLD, None).unwrap();
        s.confirm_key_file(r).unwrap();
        assert!(!s.local_rollback());
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), state1);
        assert_eq!((line.state.gated, line.vkey), (1, Some(key_id(&id, &dk1))));
        // The hold is lifted: the copy merges, this PC's state uploads, and a
        // key change works again.
        let _ = s.poll_sync();
        assert!(secrets(&s).contains(&"planted".to_owned()));
        assert_ne!(fs::read(dir.join(syncfile::OUTGOING)).ok(), outgoing);
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        let mut s = login(&pc, NEW).unwrap();
        assert_eq!(notices(&mut s), []);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// The 0.8 pair from before this PC's first password change, put back:
    /// the conversion recorded its state, so it is a local rollback, decided
    /// once the key file opens (its state needs its key); confirmed, it is
    /// the vault's state on this PC. A 0.8 key file of another key is a
    /// fork, refused with nothing written and no failed attempt (round 4,
    /// finding 20).
    #[test]
    fn the_08_pair_from_before_the_first_change_is_a_rollback() {
        let pc = Pc::new();
        let mut s = setup(&pc, false, false, false);
        let id = s.id;
        let (k0, v0) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        assert!(pc.anchor().is_empty());
        // The turn-on-sync question asks for 0.8 or later only before the
        // first change, and for 0.9.0 everywhere after it.
        assert!(!s.needs_0_9());
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        assert!(s.needs_0_9());
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.state.hist.len(), 2);
        assert_eq!(line.state.hist[1].kind, 0);
        drop(s);
        fs::write(pc.key(), &k0).unwrap();
        fs::write(pc.vault(), &v0).unwrap();
        pc.here();
        assert_eq!(
            prepare(&pc.vault(), &pc.key()).unwrap().check().anchor,
            AnchorClass::Legacy
        );
        let mut s = login(&pc, OLD).unwrap();
        assert_eq!(
            notices(&mut s),
            [KeyNotice::LocalRollback { old: 1, new: 0 }]
        );
        let r = s.reauth(OLD, None).unwrap();
        s.confirm_key_file(r).unwrap();
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), s.key_state());
        assert_eq!(&line.state.magic, &k0[..8]);
        drop(s);
        let mut s = login(&pc, OLD).unwrap();
        assert_eq!(notices(&mut s), []);
        // A change from that 0.8 pair cut off before its key file was
        // written: the new password is told that the old one still opens it
        // (S-HINT-INTERRUPTED), and the old one drops the change, said once.
        CRASH.with(|c| c.set(Some("S1.done")));
        assert_eq!(change(&mut s, OLD, NEW), Err(SIMULATED_CRASH));
        drop(s);
        assert_eq!(refused(&pc, NEW), Some(super::super::AUTH_HINT_INTERRUPTED));
        let mut s = login(&pc, OLD).unwrap();
        assert_eq!(notices(&mut s), [KeyNotice::NotFinished]);
        assert!(pc.lines(&id).pending.is_none());
        drop(s);
        // Another 0.8 key of the same vault ID, with its vault file.
        let other = Provision::new().unwrap();
        let key = super::super::encode_key(&id, &other.key, OLD).unwrap();
        let vault = encode_data(
            &id,
            &other.key,
            &Header::Legacy,
            Format::V1,
            DataRef {
                last: 0,
                generation: 0,
                seen: 0,
                entries: &[],
                tombstones: &[],
            },
        )
        .unwrap();
        fs::write(pc.key(), &key).unwrap();
        fs::write(pc.vault(), &vault).unwrap();
        let anchor = pc.anchor();
        let refused = login(&pc, OLD).err();
        assert_eq!(refused, Some(super::super::ANCHOR_FORK));
        assert!(super::super::not_a_failure(super::super::ANCHOR_FORK));
        assert_eq!((fs::read(pc.key()).unwrap(), pc.anchor()), (key, anchor));
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// What the anchor refuses before any key derivation (spec §5.10, S23-3
    /// #1): an old key file re-sealed above the confirmed state under a key
    /// of its maker's choice (a fork; with its vault file under that key,
    /// the note that this PC's key file will not open it), a same- or
    /// lower-epoch key file outside the history, one far ahead, one that
    /// lacks a removal this PC recorded, and a password-only key file for a
    /// vault this PC pins as hardware. The anchor stays as it was, and this
    /// PC's own pair still opens normally.
    #[test]
    fn forks_relists_and_far_epochs_are_refused_before_any_key_derivation() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let k1 = fs::read(pc.key()).unwrap();
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        let (k2, v2) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        let keys1 = keys_of(&k1, OLD);
        let keys2 = keys_of(&k2, NEW);
        let anchor = pc.anchor();
        let forged = pc.file("forged.goyokey");
        let refuse = |bytes: &[u8], vault: Option<&[u8]>, text: &str| {
            fs::write(&forged, bytes).unwrap();
            fs::write(pc.vault(), vault.unwrap_or(&v2)).unwrap();
            precheck_refuses(&pc, &forged, text);
            assert_eq!(pc.anchor(), anchor);
        };
        // K1's bundle re-sealed one epoch above under a key of its own, with
        // a vault file under that key.
        let dkx = [0x5c; 32];
        let (bytes, state) = sealed(id, &[&[dkx][..], &keys1].concat(), 3, &[], OLD);
        let v = vault_of(&s, &dkx, state);
        refuse(&bytes, Some(&v), super::super::ANCHOR_FORK_VAULT);
        refuse(&bytes, None, super::super::ANCHOR_FORK);
        // A sibling at the same epoch, and one below, outside the history.
        let (bytes, _) = sealed(id, &[&[[0x5d; 32]][..], &keys1].concat(), 2, &[], OLD);
        refuse(&bytes, None, super::super::ANCHOR_FORK);
        let (bytes, _) = sealed(id, &[[0x5e; 32], *keys1.last().unwrap()], 1, &[], OLD);
        refuse(&bytes, None, super::super::ANCHOR_FORK);
        // Far ahead: refused with both epochs, and no last-resort advice.
        let far = 2 + keyfile::EPOCH_WINDOW + 1;
        let (bytes, _) = sealed(id, &[&[[0x5f; 32]][..], &keys2].concat(), far, &[], NEW);
        refuse(&bytes, None, super::super::ANCHOR_EPOCH);
        assert_eq!(
            super::super::refusal_values(super::super::ANCHOR_EPOCH),
            Some(vec![far.to_string(), "2".into()])
        );
        assert!(!super::super::ANCHOR_EPOCH.contains("goyo-vault.keys"));
        for text in [
            super::super::ANCHOR_FORK,
            super::super::ANCHOR_FORK_VAULT,
            super::super::ANCHOR_RELIST,
            super::super::ANCHOR_DOWNGRADE,
        ] {
            // The keyless build's only way out; the security-key build
            // offers the per-vault forget instead (spec §9.3).
            #[cfg(not(feature = "security-key"))]
            assert!(text.ends_with(anchor::LAST_RESORT));
            #[cfg(feature = "security-key")]
            assert!(!text.contains("goyo-vault.keys"), "{text}");
        }
        // This PC's own pair opens as it is.
        fs::write(pc.vault(), &v2).unwrap();
        drop(s);
        let mut s = login(&pc, NEW).unwrap();
        assert_eq!(notices(&mut s), []);
        // A later file with a removal (a GOYOKE03 after keys off on another
        // PC): taken silently in the keyless build (the security-key build
        // asks G1 for a removal of a key this PC never knew), and the
        // removal recorded.
        let dk3 = [0x63; 32];
        let (k3, state3) = sealed(
            id,
            &[&[dk3][..], &keys2].concat(),
            3,
            &[([0x77; 16], 3)],
            NEW,
        );
        fs::write(pc.key(), &k3).unwrap();
        fs::write(pc.vault(), vault_of(&s, &dk3, state3)).unwrap();
        drop(s);
        let mut s = login(&pc, NEW).unwrap();
        pass_gate(&mut s);
        assert_eq!(notices(&mut s), []);
        let line = pc.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), state3);
        assert_eq!(line.state.tombs[0].credhash, [0x77; 16]);
        // One that lacks that removal: refused.
        let anchor = pc.anchor();
        let (bytes, _) = sealed(
            id,
            &[&[[0x64; 32]][..], &[dk3], &keys2].concat(),
            4,
            &[],
            NEW,
        );
        fs::write(&forged, &bytes).unwrap();
        precheck_refuses(&pc, &forged, super::super::ANCHOR_RELIST);
        assert_eq!(pc.anchor(), anchor);
        // Pinned as hardware by a security-key build on this PC: every
        // password-only key file is refused, a 0.8 one too.
        drop(s);
        anchor::update(&pc.anchor_dir(), &id, anchor::LOCK_WAIT, &mut |lines| {
            lines.vault.as_mut().unwrap().state.magic = *b"GOYOKH01";
            true
        })
        .unwrap();
        precheck_refuses(&pc, &pc.key(), super::super::ANCHOR_DOWNGRADE);
        fs::write(
            &forged,
            super::super::encode_key(&id, &keys1[0], OLD).unwrap(),
        )
        .unwrap();
        precheck_refuses(&pc, &forged, super::super::ANCHOR_DOWNGRADE);
        // A Restore is refused the same.
        pc.here();
        assert_eq!(
            super::super::prepare_restore(&pc.vault(), &pc.key()).err(),
            Some(super::super::ANCHOR_DOWNGRADE)
        );
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// Two PCs open one vault file, each with a key-file copy of its own
    /// (S23-3 #8, S23-1 #3): after A's password change, B's own copy is told
    /// that another PC's new key file saved it; B opens with that key file
    /// silently (it holds the key B confirmed) and seals the change, so the
    /// probe restored later is refused before any key derivation, and on a
    /// line without `vkey` is only asked about, never completed silently.
    #[test]
    fn two_pcs_with_a_key_file_each_share_one_vault_file() {
        let a = Pc::new();
        let s = setup(&a, true, false, false);
        let id = s.id;
        // One PC at a time has the vault file open (its lock file).
        drop(s);
        let b = Pc::new();
        fs::copy(a.key(), b.key()).unwrap();
        let open_b = |key: &Path| {
            b.here();
            let prepared = prepare(&a.vault(), key)?;
            Session::login(prepared, OLD, None).or_else(|_| {
                b.here();
                let prepared = prepare(&a.vault(), key)?;
                Session::login(prepared, NEW, None)
            })
        };
        drop(open_b(&b.key()).unwrap());
        let probe = Rc::new(RefCell::new(None));
        let held = probe.clone();
        let vault = a.vault();
        set_before("S2", move || *held.borrow_mut() = fs::read(&vault).ok());
        let mut s = login(&a, OLD).unwrap();
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        // B's own copy cannot open the vault file A saved.
        b.here();
        let derived = crypto::derive_count();
        assert_eq!(
            prepare(&a.vault(), &b.key()).err(),
            Some(super::super::KEY_NOT_IN_KEY_FILE_NEWER)
        );
        assert_eq!(crypto::derive_count(), derived);
        assert_eq!(
            super::super::refusal_values(super::super::KEY_NOT_IN_KEY_FILE_NEWER),
            Some(vec!["2".into(), "1".into()])
        );
        // With A's new key file: a silent update, and the change sealed.
        fs::copy(a.key(), b.key()).unwrap();
        let mut sb = open_b(&b.key()).unwrap();
        assert_eq!(notices(&mut sb), []);
        let line = b.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), sb.key_state());
        assert_eq!(line.vkey, current_id(&sb));
        let resume = sb.key_file.header().unwrap().resume;
        assert_eq!(line.state.consumed, Some(resume));
        drop(sb);
        let current = fs::read(a.vault()).unwrap();
        fs::write(a.vault(), probe.borrow().as_ref().unwrap()).unwrap();
        b.here();
        let derived = crypto::derive_count();
        assert_eq!(prepare(&a.vault(), &b.key()).err(), Some(OLDER_REFUSED));
        assert_eq!(crypto::derive_count(), derived);
        // A line written without `vkey`: asked, never completed silently.
        anchor::update(&b.anchor_dir(), &id, anchor::LOCK_WAIT, &mut |lines| {
            lines.vault.as_mut().unwrap().vkey = None;
            true
        })
        .unwrap();
        assert!(matches!(
            prepare(&a.vault(), &b.key()).unwrap().check().vault,
            VaultClass::Older { .. }
        ));
        fs::write(a.vault(), current).unwrap();
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// The first open after another PC changed a shared key file: this PC's
    /// own vault file is still under the key it last used, so it is asked
    /// about (S-OLDER) and the yes completes and seals it (§7.7-2). An older
    /// vault file under that key whose counters no honest vault reaches is
    /// refused after its decode, writing nothing (S23-3 #2); within bounds,
    /// `seen` never above `generation`, and the old OTP watermark kept.
    #[test]
    fn an_older_vault_file_under_this_pcs_key_is_asked_and_its_counters_checked() {
        let a = Pc::new();
        let mut s = setup(&a, true, false, true);
        let id = s.id;
        let dk1 = *s.keys.current();
        let state1 = s.key_state();
        // PC B: its own vault file and the shared key file, opened once.
        let b = Pc::new();
        fs::copy(a.vault(), b.vault()).unwrap();
        fs::copy(a.key(), b.key()).unwrap();
        let mine = fs::read(b.vault()).unwrap();
        drop(login(&b, OLD).unwrap());
        // A changes the shared key file.
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        fs::copy(a.key(), b.key()).unwrap();
        let entries = s.entries.clone();
        let tombstones = s.tombstones.clone();
        drop(s);
        let with = |generation: u64, seen: u64, last: u64| {
            let header = Header::Keyed {
                key_id: key_id(&id, &dk1),
                state: state1,
                flags: 0,
            };
            let d = DataRef {
                last,
                generation,
                seen,
                entries: &entries,
                tombstones: &tombstones,
            };
            encode_data(&id, &dk1, &header, Format::V2, d).unwrap()
        };
        let yes = || {
            b.here();
            let prepared = prepare(&b.vault(), &b.key()).unwrap();
            let VaultClass::Older { sha } = prepared.check().vault else {
                panic!("not asked");
            };
            Session::login(prepared, NEW, Some(sha))
        };
        // Counters no honest vault reaches: refused, nothing written.
        let unsealed = b.anchor();
        for (generation, seen) in [(u64::MAX - 1, u64::MAX), (1 << 40, (1 << 40) + 1)] {
            let planted = with(generation, seen, u64::MAX);
            fs::write(b.vault(), &planted).unwrap();
            let anchor = b.anchor();
            assert_eq!(yes().err(), Some(super::super::VAULT_COUNTERS));
            assert!(super::super::not_a_failure(super::super::VAULT_COUNTERS));
            assert_eq!(
                (fs::read(b.vault()).unwrap(), b.anchor()),
                (planted, anchor)
            );
        }
        // Within bounds: `seen` is cut to `generation`; the old OTP
        // watermark `last` stays as it is, as nothing reads it.
        fs::write(b.vault(), with(100, 5000, u64::MAX)).unwrap();
        let s = yes().unwrap();
        assert_eq!((s.generation, s.seen, s.last), (100, 100, u64::MAX));
        drop(s);
        // That open completed the change on B: the key it sealed refuses
        // any older vault file now.
        fs::write(b.vault(), &mine).unwrap();
        b.here();
        assert_eq!(prepare(&b.vault(), &b.key()).err(), Some(OLDER_REFUSED));
        // B's own vault file, before any of that: the yes completes and
        // seals it.
        fs::write(b.anchor_dir().join("goyo-vault.keys"), &unsealed).unwrap();
        let mut s = yes().unwrap();
        assert_eq!(notices(&mut s), [KeyNotice::OlderAccepted]);
        let line = b.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), s.key_state());
        assert_eq!(line.vkey, current_id(&s));
        assert_eq!(
            line.state.consumed,
            Some(s.key_file.header().unwrap().resume)
        );
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// This PC's change landed in the key file at its path, and the user
    /// opens a key backup from another path (S23-1 #8): the file at the
    /// path tells that it landed, so the backup is a local rollback, and the
    /// next unlock with the new key file completes the change. With the
    /// stick unplugged, the entry waits and key changes are held; a path on
    /// a network share is never read; and when the stick is gone for good,
    /// the user discards the entry after a Reauth (S23-2 #2).
    #[test]
    fn a_change_that_landed_in_a_key_file_elsewhere() {
        for unplugged in [false, true] {
            let pc = Pc::new();
            let mut s = setup(&pc, true, false, false);
            let id = s.id;
            let backup = pc.file("backup.goyokey");
            s.backup_key(&backup).unwrap();
            CRASH.with(|c| c.set(Some("S2v")));
            assert_eq!(change(&mut s, OLD, NEW), Err(SIMULATED_CRASH));
            drop(s);
            let away = pc.file("away.goyokey");
            if unplugged {
                fs::rename(pc.key(), &away).unwrap();
            }
            pc.here();
            let prepared = prepare(&pc.vault(), &backup).unwrap();
            let mut s = Session::login(prepared, OLD, None).unwrap();
            if unplugged {
                let key = pc.canonical("vault.goyokey");
                assert_eq!(notices(&mut s), [KeyNotice::PendingElsewhere(key.clone())]);
                assert_eq!(s.pending_elsewhere(), Some(key.as_path()));
                assert_eq!(s.password_change(), Err(super::super::PENDING_ELSEWHERE));
                assert!(pc.lines(&id).pending.is_some());
                drop(s);
                fs::rename(&away, pc.key()).unwrap();
            } else {
                assert_eq!(
                    notices(&mut s),
                    [KeyNotice::LocalRollback { old: 2, new: 1 }]
                );
                assert!(pc.lines(&id).pending.is_none());
                drop(s);
            }
            let mut s = login(&pc, NEW).unwrap();
            assert_eq!(notices(&mut s), [KeyNotice::Resumed]);
            assert!(pc.lines(&id).pending.is_none());
            consistent(&pc, &s);
        }
        // Gone for good: discarded after a Reauth, then a change works.
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let backup = pc.file("backup.goyokey");
        s.backup_key(&backup).unwrap();
        CRASH.with(|c| c.set(Some("S2v")));
        assert_eq!(change(&mut s, OLD, NEW), Err(SIMULATED_CRASH));
        drop(s);
        fs::remove_file(pc.key()).unwrap();
        pc.here();
        let prepared = prepare(&pc.vault(), &backup).unwrap();
        let mut s = Session::login(prepared, OLD, None).unwrap();
        assert!(s.pending_elsewhere().is_some());
        let r = s.reauth(OLD, None).unwrap();
        s.forget_pending(r).unwrap();
        assert!(s.pending_elsewhere().is_none() && pc.lines(&id).pending.is_none());
        assert_eq!(s.password_change(), Ok(None));
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        // A path on a network share is never read at precheck: it counts as
        // a key file that cannot be read.
        anchor::update(&pc.anchor_dir(), &id, anchor::LOCK_WAIT, &mut |lines| {
            let line = lines.vault.clone().unwrap();
            let mut pending = anchor::PendingLine {
                state: line.state.clone(),
                kind: 2,
                src: anchor::Src::Other,
                opt: None,
                rm: Vec::new(),
                loss: None,
                exp: None,
                clone: Vec::new(),
                clears: anchor::Clears::default(),
                merged: None,
                kpath: anchor::kpath_of(Path::new(r"\\server\share\vault.goyokey")),
                pw: Some(anchor::Pw::New),
                base: Some((line.state.epoch, line.state.tag)),
            };
            pending.state.epoch += 1;
            lines.pending = Some(pending);
            true
        })
        .unwrap();
        anchor::KPATH_READS.with(|n| n.set(0));
        pc.here();
        let prepared = prepare(&pc.vault(), &backup).unwrap();
        assert_eq!(anchor::KPATH_READS.with(|n| n.get()), 0);
        let s = Session::login(prepared, NEW, None).unwrap();
        assert_eq!(
            s.pending_elsewhere(),
            Some(Path::new(r"\\server\share\vault.goyokey"))
        );
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A pending entry is promoted only over the state it was built on
    /// (S23-2 #3): after the confirmed line moved on to another PC's change
    /// while the stick was unplugged, the entry counts as one that never
    /// landed, and this PC's landed key file is then a fork.
    #[test]
    fn an_overtaken_pending_entry_is_dropped() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let keys1 = s.keys.keys().to_vec();
        let v1 = fs::read(pc.vault()).unwrap();
        CRASH.with(|c| c.set(Some("S2v")));
        assert_eq!(change(&mut s, OLD, NEW), Err(SIMULATED_CRASH));
        drop(s);
        let away = pc.file("stick.goyokey");
        fs::rename(pc.key(), &away).unwrap();
        // PC B's change from the same state: opened here while the stick is
        // out, with this PC's vault file, which is asked about and saved
        // under B's key; the confirmed line moves on to B's state.
        let dkb = [0xb2; 32];
        let (kb, state_b) = sealed(
            id,
            &[&[dkb][..], &keys1].concat(),
            2,
            &[],
            "synthetic b password",
        );
        let kb_path = pc.file("b.goyokey");
        fs::write(&kb_path, &kb).unwrap();
        fs::write(pc.vault(), &v1).unwrap();
        pc.here();
        let prepared = prepare(&pc.vault(), &kb_path).unwrap();
        let VaultClass::Older { sha } = prepared.check().vault else {
            panic!("not older");
        };
        let mut s = Session::login(prepared, "synthetic b password", Some(sha)).unwrap();
        let key = pc.canonical("vault.goyokey");
        assert!(
            s.take_key_notices()
                .contains(&KeyNotice::PendingElsewhere(key))
        );
        assert_eq!(pc.lines(&id).vault.unwrap().state.key_state(), state_b);
        assert!(pc.lines(&id).pending.is_some());
        drop(s);
        fs::rename(&away, pc.key()).unwrap();
        pc.here();
        let prepared = prepare(&pc.vault(), &kb_path).unwrap();
        let mut s = Session::login(prepared, "synthetic b password", None).unwrap();
        assert_eq!(notices(&mut s), [KeyNotice::NotFinished]);
        assert!(pc.lines(&id).pending.is_none());
        drop(s);
        precheck_refuses(&pc, &pc.key(), super::super::ANCHOR_FORK);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A Restore never writes the anchor, not even to move its lines first
    /// (S23-3 #18). With a key file other than the confirmed one, or while a
    /// change of this PC waits for a login, it restores into a held session:
    /// no key change, upload or merge (S23-1 #17, S23-3 #15).
    #[test]
    fn a_restore_never_writes_the_anchor() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let (k1, v1) = (pc.file("k1.goyokey"), pc.file("v1.goyo"));
        fs::copy(pc.key(), &k1).unwrap();
        fs::copy(pc.vault(), &v1).unwrap();
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        // Another vault's line first, so this vault's are not.
        anchor::update(
            &pc.anchor_dir(),
            &[0x01; 16],
            anchor::LOCK_WAIT,
            &mut |lines| {
                lines.vault = pc.lines(&id).vault;
                true
            },
        )
        .unwrap();
        let anchor = pc.anchor();
        let restored = pc.file("restored.goyo");
        pc.here();
        let mut r = Session::restore(&v1, &k1, &restored, OLD).unwrap();
        assert_eq!(
            r.take_key_notices(),
            [KeyNotice::RestoreOldKey { old: 2, new: 1 }]
        );
        assert!(r.local_rollback() && r.restore_held());
        assert!(r.password_change().is_err());
        drop(r);
        assert_eq!(pc.anchor(), anchor);
        // A Restore of a backup with this PC's current key file: not held,
        // and still nothing written to the anchor.
        let mut r = Session::restore(&v1, &pc.key(), &pc.file("r2.goyo"), NEW).unwrap();
        assert!(!r.local_rollback());
        assert_eq!(notices(&mut r), []);
        drop(r);
        assert_eq!(pc.anchor(), anchor);
        // A change of this PC that waits for a login: held, and the pending
        // line left for that login.
        let mut s = login(&pc, NEW).unwrap();
        CRASH.with(|c| c.set(Some("S2v")));
        assert_eq!(change(&mut s, NEW, THIRD), Err(SIMULATED_CRASH));
        drop(s);
        let anchor = pc.anchor();
        pc.here();
        let mut r = Session::restore(&v1, &k1, &pc.file("r3.goyo"), OLD).unwrap();
        assert_eq!(r.take_key_notices(), [KeyNotice::RestorePending]);
        assert_eq!(r.password_change(), Err(super::super::RESTORE_PENDING));
        drop(r);
        assert_eq!(pc.anchor(), anchor);
        let mut s = login(&pc, THIRD).unwrap();
        assert_eq!(notices(&mut s), [KeyNotice::Resumed]);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A key file's temp file alone never gives the hint to type the old
    /// password (S23-3 #3): a junk GOYOKE03 temp at a high epoch, beside a
    /// put-back older key file or beside the current one.
    #[test]
    fn a_planted_key_temp_gives_no_hint() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let (k1, v1) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        let (junk, _) = sealed(id, &[[0x6a; 32]], 9, &[], "synthetic junk password");
        let mut name = pc.key().into_os_string();
        name.push(format!(".{:032x}.goyotmp", 0x9u8));
        fs::write(&name, &junk).unwrap();
        assert_eq!(refused(&pc, OLD), None);
        fs::write(pc.key(), &k1).unwrap();
        fs::write(pc.vault(), &v1).unwrap();
        assert_eq!(refused(&pc, NEW), None);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// Rule (i) takes the highest-epoch temp of the vault whatever this PC
    /// confirmed (spec §5.12; SECURITY_REVIEW.md, the `.goyotmp` row): one
    /// below the confirmed state, beside a damaged key file, opens held as a
    /// local rollback and gets the key file's name back.
    #[test]
    fn a_key_temp_below_the_confirmed_state_opens_held() {
        let pc = Pc::new();
        let mut s = setup(&pc, false, false, false);
        let id = s.id;
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        let (k1, v1) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        assert_eq!(change(&mut s, NEW, THIRD), Ok(Rekeyed::Done));
        drop(s);
        assert_eq!(pc.lines(&id).vault.unwrap().state.epoch, 2);
        let k2 = fs::read(pc.key()).unwrap();
        fs::write(pc.key(), &k2[..40]).unwrap();
        fs::write(pc.vault(), &v1).unwrap();
        let mut name = pc.key().into_os_string();
        name.push(format!(".{:032x}.goyotmp", 0x1u8));
        fs::write(&name, &k1).unwrap();
        let mut s = login(&pc, NEW).unwrap();
        assert!(s.local_rollback());
        assert!(notices(&mut s).contains(&KeyNotice::LocalRollback { old: 2, new: 1 }));
        assert_eq!(fs::read(pc.key()).unwrap(), k1);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// The anchor step runs before every step that needs the vault file, also
    /// when the vault file is only a temp file (S23-3 #12): a put-back older
    /// pair whose vault file is a temp opens held; a forked key file with
    /// its vault file as a temp is refused before any key derivation, the
    /// temp file left alone; and a crash at C5g (V′ only in its temp file)
    /// completes silently.
    #[test]
    fn vault_files_left_as_temps_meet_the_anchor_first() {
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let id = s.id;
        let (k1, v1) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        let keys1 = s.keys.keys().to_vec();
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        let temp = |data: &[u8]| {
            let mut name = pc.vault().into_os_string();
            name.push(format!(".{:032x}.goyotmp", 0x3u8));
            fs::write(&name, data).unwrap();
            PathBuf::from(name)
        };
        let v2 = fs::read(pc.vault()).unwrap();
        let k2 = fs::read(pc.key()).unwrap();
        fs::remove_file(pc.vault()).unwrap();
        fs::write(pc.key(), &k1).unwrap();
        let t1 = temp(&v1);
        let mut s = login(&pc, OLD).unwrap();
        assert!(s.take_recovery().vault && s.local_rollback());
        assert_eq!(
            notices(&mut s),
            [KeyNotice::LocalRollback { old: 2, new: 1 }]
        );
        assert!(!t1.exists());
        drop(s);
        // A forked key file, its vault file only as a temp.
        fs::remove_file(pc.vault()).unwrap();
        let dkx = [0x7c; 32];
        let (forked, state) = sealed(id, &[&[dkx][..], &keys1].concat(), 3, &[], OLD);
        fs::write(pc.key(), &forked).unwrap();
        let header = Header::Keyed {
            key_id: key_id(&id, &dkx),
            state,
            flags: 0,
        };
        let data = encode_data(
            &id,
            &dkx,
            &header,
            Format::V1,
            DataRef {
                last: 0,
                generation: 0,
                seen: 0,
                entries: &[],
                tombstones: &[],
            },
        )
        .unwrap();
        let tx = temp(&data);
        precheck_refuses(&pc, &pc.key(), super::super::ANCHOR_FORK_VAULT);
        assert!(tx.exists());
        fs::remove_file(&tx).unwrap();
        // C5g: V′ in its temp file, the pending entry not yet promoted.
        fs::write(pc.key(), &k2).unwrap();
        fs::write(pc.vault(), &v2).unwrap();
        let mut s = login(&pc, NEW).unwrap();
        s.take_key_notices();
        CRASH.with(|c| c.set(Some("S3.tmp_synced")));
        assert_eq!(change(&mut s, NEW, THIRD), Err(SIMULATED_CRASH));
        drop(s);
        fs::remove_file(pc.vault()).unwrap();
        let mut s = login(&pc, THIRD).unwrap();
        assert!(s.take_recovery().vault);
        assert_eq!(notices(&mut s), []);
        let line = pc.lines(&id).vault.unwrap();
        assert!(pc.lines(&id).pending.is_none());
        assert_eq!(line.state.key_state(), s.key_state());
        assert_eq!(
            line.state.consumed,
            Some(s.key_file.header().unwrap().resume)
        );
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A 0.8 vault writes no anchor line and gets no key backup reminder, as
    /// in 0.8; after its first password change the reminder shows until a
    /// key backup records this state (S23-1 #19). An anchor that cannot be
    /// read or written at unlock leaves a password-only session working on
    /// what it holds in memory (S-SIDECAR-FAILED).
    #[test]
    fn the_key_backup_reminder_and_an_anchor_that_cannot_be_written() {
        let pc = Pc::new();
        let s = setup(&pc, false, false, false);
        drop(s);
        for _ in 0..2 {
            let mut s = login(&pc, OLD).unwrap();
            assert_eq!(s.take_key_notices(), []);
            assert!(!s.key_backup_due());
        }
        assert!(pc.anchor().is_empty());
        let mut s = login(&pc, OLD).unwrap();
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        let mut s = login(&pc, NEW).unwrap();
        assert_eq!(s.take_key_notices(), [KeyNotice::KeyBackupDue]);
        s.backup_key(&pc.file("key-backup.goyokey")).unwrap();
        drop(s);
        let mut s = login(&pc, NEW).unwrap();
        assert_eq!(s.take_key_notices(), []);
        drop(s);
        // The anchor's folder cannot be made.
        let blocker = pc.file("blocker");
        fs::write(&blocker, b"no folder").unwrap();
        set_anchor_dir(Some(blocker.join("anchor")));
        let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
        assert_eq!(prepared.check().anchor, AnchorClass::New);
        let mut s = Session::login(prepared, NEW, None).unwrap();
        let said = s.take_key_notices();
        assert!(said.contains(&KeyNotice::SidecarFailed));
        assert_eq!(change(&mut s, NEW, THIRD), Ok(Rekeyed::Done));
        assert_eq!(s.take_key_notices(), []);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// I11 on the normal path (spec §14.5): a change that completed in its
    /// session consumes its resume digest at S5, so its probe put back in
    /// place of the vault file is refused at the very next login, before
    /// any key derivation, with no unlock in between that would seal it;
    /// the same for an adopt that changed the data key.
    #[test]
    fn a_completed_change_refuses_its_probe_at_once() {
        for what in [What::Password, What::Successor] {
            let pc = Pc::new();
            let mut s = setup(&pc, true, false, false);
            let probe = Rc::new(RefCell::new(None));
            let held = probe.clone();
            let vault = pc.vault();
            set_before("S2", move || *held.borrow_mut() = fs::read(&vault).ok());
            let r = s.reauth(OLD, None).unwrap();
            if what == What::Password {
                let to = Change::Password(Zeroizing::new(NEW.to_owned()));
                let done = s.rekey(r, Vec::new(), to, Consent::default(), true);
                assert_eq!(done, Ok(Rekeyed::Done));
            } else {
                let other = other_of(&s, what);
                let plan = plan_of(&s, &r, &other, NEW, AdoptClass::Successor);
                let acks = acks_of(&plan);
                s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
                    .unwrap();
            }
            drop(s);
            let probe = probe.borrow_mut().take().expect("the probe");
            fs::write(pc.vault(), probe).unwrap();
            pc.here();
            let derived = crypto::derive_count();
            assert_eq!(
                prepare(&pc.vault(), &pc.key()).err(),
                Some(OLDER_REFUSED),
                "{what:?}"
            );
            assert_eq!(crypto::derive_count(), derived);
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// [이 열쇠 파일이 맞습니다] and [끝나지 않은 열쇠 변경 버리기…] take a
    /// Reauth with the password alone, as every key change does (spec
    /// §5.10), also for a 0.8 pair made with the removed OTP that was put
    /// back: no code is asked.
    #[test]
    fn the_hold_buttons_take_a_reauth_with_the_password_alone() {
        // A put-back pair, held: GOYOKE01 with its TOTP secret.
        let pc = Pc::new();
        let mut s = setup(&pc, false, true, false);
        let (k1, v1) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        fs::write(pc.key(), &k1).unwrap();
        fs::write(pc.vault(), &v1).unwrap();
        let mut s = login(&pc, OLD).unwrap();
        assert!(s.local_rollback() && s.key_file.otp_secret());
        let r = s.reauth(OLD, None).unwrap();
        s.confirm_key_file(r).unwrap();
        assert!(!s.local_rollback());
        drop(s);
        assert_eq!(fs::read(pc.key()).unwrap(), k1);
        let s = login(&pc, OLD).unwrap();
        assert!(!s.local_rollback());
        drop(s);
        // A change that may have landed in a key file that is away.
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let copy = pc.file("copy.goyokey");
        fs::copy(pc.key(), &copy).unwrap();
        CRASH.with(|c| c.set(Some("S2v")));
        assert_eq!(change(&mut s, OLD, NEW), Err(SIMULATED_CRASH));
        drop(s);
        fs::rename(pc.key(), pc.file("away.goyokey")).unwrap();
        pc.here();
        let prepared = prepare(&pc.vault(), &copy).unwrap();
        let mut s = Session::login(prepared, OLD, None).unwrap();
        assert!(s.pending_elsewhere().is_some());
        let r = s.reauth(OLD, None).unwrap();
        s.forget_pending(r).unwrap();
        assert!(s.pending_elsewhere().is_none());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A Restore takes no key change or adopt, also with the key file this
    /// PC confirmed (spec §2.18 #54): the restored file and the live one
    /// share that key file and one anchor line, so a change made from the
    /// restored file would leave the live one under an older key, which a
    /// login then refuses (S-OLDER-REFUSED). The live vault file still
    /// opens as it did.
    #[test]
    fn a_restored_vault_never_changes_the_shared_key_file() {
        let pc = Pc::new();
        let s = setup(&pc, true, false, false);
        drop(s);
        let backup = pc.file("backup.goyo");
        fs::copy(pc.vault(), &backup).unwrap();
        let before = files(&pc);
        pc.here();
        let mut r = Session::restore(&backup, &pc.key(), &pc.file("restored.goyo"), OLD).unwrap();
        assert!(r.restored() && !r.restore_held() && !r.local_rollback());
        assert_eq!(notices(&mut r), []);
        assert_eq!(r.password_change(), Err(RESTORE_KEYS));
        assert_eq!(change(&mut r, OLD, NEW), Err(RESTORE_KEYS));
        let other = other_of(&r, What::Successor);
        let file = KeyFile::from_bytes(Path::new("other.goyokey"), other).unwrap();
        let checked = r.adopt_check(&file, Source::File(file.path().to_owned()));
        assert_eq!(checked.err(), Some(RESTORE_KEYS));
        drop(r);
        assert_eq!(files(&pc), before);
        let mut s = login(&pc, OLD).unwrap();
        assert!(!s.restored());
        assert_eq!(notices(&mut s), []);
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// An anchor that cannot be read at precheck (another program holds it
    /// open) compares as one with no line, but nothing stands on that
    /// comparison (spec §2.18 #60): an unlock whose locked read finds other
    /// lines is refused, writing nothing, and the next try compares again;
    /// and a session that took an older key file for current (a 0.8 pair's
    /// unlock writes no line, so nothing is read again there) cannot take
    /// the anchor below its confirmed state with a key change.
    #[cfg(windows)]
    #[test]
    fn an_anchor_unread_at_precheck_is_not_trusted() {
        use std::os::windows::fs::OpenOptionsExt;
        let held = |pc: &Pc| {
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(pc.anchor_dir().join("goyo-vault.keys"))
                .unwrap()
        };
        // A KF2 pair put back: it looks new while the anchor is held, and
        // the unlock refuses once the lock shows the confirmed line.
        let pc = Pc::new();
        let mut s = setup(&pc, true, false, false);
        let (k1, v1) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
        assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
        drop(s);
        fs::write(pc.key(), &k1).unwrap();
        fs::write(pc.vault(), &v1).unwrap();
        let before = files(&pc);
        pc.here();
        let lock = held(&pc);
        let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
        assert_eq!(prepared.check().anchor, AnchorClass::New);
        drop(lock);
        let refused = Session::login(prepared, OLD, None).err();
        assert_eq!(refused, Some(super::super::ANCHOR_REREAD));
        assert!(super::super::not_a_failure(super::super::ANCHOR_REREAD));
        assert_eq!(files(&pc), before);
        let mut s = login(&pc, OLD).unwrap();
        assert!(s.local_rollback());
        assert_eq!(
            notices(&mut s),
            [KeyNotice::LocalRollback { old: 2, new: 1 }]
        );
        drop(s);
        // A 0.8 pair put back after two changes, and after one: its change
        // would take the anchor below the confirmed state, or beside it at
        // that epoch.
        for (changes, confirmed) in [(2, "2"), (1, "1")] {
            let pc = Pc::new();
            let mut s = setup(&pc, false, false, false);
            let (k0, v0) = (fs::read(pc.key()).unwrap(), fs::read(pc.vault()).unwrap());
            assert_eq!(change(&mut s, OLD, NEW), Ok(Rekeyed::Done));
            if changes == 2 {
                assert_eq!(change(&mut s, NEW, THIRD), Ok(Rekeyed::Done));
            }
            drop(s);
            fs::write(pc.key(), &k0).unwrap();
            fs::write(pc.vault(), &v0).unwrap();
            pc.here();
            let lock = held(&pc);
            let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
            assert_eq!(prepared.check().anchor, AnchorClass::New);
            drop(lock);
            let mut s = Session::login(prepared, OLD, None).unwrap();
            assert!(!s.local_rollback());
            let before = files(&pc);
            assert_eq!(change(&mut s, OLD, NEW), Err(LOCAL_ROLLBACK));
            assert_eq!(
                super::super::refusal_values(LOCAL_ROLLBACK),
                Some(vec![confirmed.into(), "0".into()])
            );
            assert_eq!(files(&pc), before);
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
}
