//! The per-PC anchor `goyo-vault.keys` (spec v3 §5.10): this PC's own record
//! of the key-file state it has seen for each vault, in
//! `%LOCALAPPDATA%\GoyoVault\`, out of reach of whoever can write only the
//! vault folder or the key USB. It holds no secret (no key code, seed,
//! credential ID or data key) and nothing authenticates it: it is a second
//! floor, compared with the key file on public bytes before any key
//! derivation (§5.1 step 9). A key file put back from an older state of this
//! PC is a local rollback; one that forked from this PC's, one far ahead,
//! one that lacks a removal this PC recorded, and a password-only key file
//! for a vault this PC opened with security keys are refused. The
//! security-key build also refuses a key file that lists, or was authorized
//! by, a key this PC removed, or lacks a key it added; a later one that
//! changes the keys or the policy waits for its gate (`gate`), and a key
//! file with security keys and no record is a bootstrap. A key change
//! writes its pending line first (S0) and promotes it last (S5), so the next
//! unlock recognizes this PC's own write that landed before a crash.
//!
//! Version 3, strict ASCII, one record per line. A line this version cannot
//! read is kept verbatim and counts as absent for its vault; a file of a
//! later version, or over 1 MiB, is never rewritten. Every read-modify-rename
//! holds a lock file, reads again under it, writes a temp file and renames
//! it over the anchor, so no crash leaves the file half-written. Line order
//! is recency: a write puts its vault's lines first, and the 1 MiB limit
//! drops the vaults at the end.
use super::{
    flush,
    keyfile::{EPOCH_MAX, EPOCH_WINDOW, KeyFile, KeyHeader, KeyState, Magic, TOMB_MAX, parse},
    publish,
};
use crate::crypto;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// The anchor's file name in its folder.
const NAME: &str = "goyo-vault.keys";
/// The first line of a version-4 file. Version 4 states key IDs, `pw_id`s,
/// tags (`merged` too), credhashes (`pbad` too) and seed hashes in full
/// where version 3 kept prefixes
/// (review finding: a 4-byte key ID prefix is cheap to grind). A version-3
/// file is read with this grammar: its lines with prefixes are unreadable
/// and count as absent, as any malformed line, until a write of that vault
/// replaces them.
const VERSION: &str = "goyo-vault-keys 4";
/// Largest anchor read or written.
pub(super) const LIMIT: usize = 1 << 20;
/// How long a write waits for another process's lock.
pub(super) const LOCK_WAIT: Duration = Duration::from_secs(5);
/// States a `hist` keeps, newest first.
const HIST_MAX: usize = 64;
/// Server files a `merged` list keeps, and candidates a `sup` list keeps.
const RECENT_MAX: usize = 16;
/// Slots of a key file (spec §4.1), and pair records among them.
const SLOTS_MAX: usize = 8;
/// The longest key path a pending line records, in UTF-16 units.
const KPATH_MAX: usize = 1024;

/// A security-key key file for a vault this PC pins as hardware is opened
/// only with such a file (spec §5.10, S-ANCHOR-DOWNGRADE).
macro_rules! downgrade {
    () => {
        "이 PC에서 이 금고는 보안 키 열쇠 파일로 열었습니다. 비밀번호만으로 여는 열쇠 파일로는 열지 않습니다. 다른 PC에서 보안 키를 끈 것이 맞다면, 보안 키를 지원하는 고요 금고에서 원래 열쇠 파일로 연 뒤 '새 열쇠 파일 받기'로 받으세요."
    };
}
/// S-ANCHOR-RELIST: the key file lacks a removal this PC recorded and is no
/// older state of this PC.
macro_rules! relist {
    () => {
        "이 열쇠 파일에는 이 PC가 기록해 둔 키 제거 기록이 빠져 있습니다. 예전 열쇠 파일로 되돌려졌거나 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요. 다른 PC의 열쇠 파일이라면 이 PC의 원래 열쇠 파일로 연 뒤 '새 열쇠 파일 받기'로 받으세요."
    };
}
/// S-ANCHOR-FORK, in two status lines: the key file is no later version
/// of the one this PC confirmed, nor an older state of this PC.
macro_rules! fork {
    () => {
        concat!(
            "이 열쇠 파일은 이 PC가 마지막으로 본 열쇠 파일에서 이어진 새 버전이 아니라, 그와 갈라진 다른 열쇠 파일입니다(다른 PC에서 따로 열쇠를 바꿨거나, 누군가 예전 열쇠 파일로 새로 만들었을 수 있습니다). 그대로 쓰면 이 PC의 열쇠 변경이 사라지므로 열지 않았습니다.",
            "\r\n",
            "다른 PC에서 바꾼 것이 맞다면 이 PC의 원래 열쇠 파일(열쇠 백업)로 연 뒤 '새 열쇠 파일 받기'로 이 파일을 받으면 두 파일이 합쳐집니다. 그런 변경을 한 PC가 없다면 받지 말고 백업을 확인하세요."
        )
    };
}
/// S-ANCHOR-FORK-VAULT, in two status lines: the vault file is under the
/// forked branch's key too.
macro_rules! fork_vault {
    () => {
        concat!(
            "금고 파일도 이 열쇠 파일의 열쇠로 저장되어 있어 이 PC의 원래 열쇠 파일로는 열리지 않습니다. 이 PC의 금고 백업이 있으면 원래 열쇠 파일과 그 백업으로 연 뒤 '새 열쇠 파일 받기'로 이 열쇠 파일을 받고, 이 금고 파일은 그 뒤 '백업 파일로 되살리기'로 새 파일에 되살려 항목을 확인하세요.",
            "\r\n",
            "이 금고 파일의 항목만 확인하려면 지금 이 열쇠 파일로 '복원'하세요(복원한 금고에서는 열쇠를 바꾸거나 올리지 않습니다)."
        )
    };
}
/// S-ANCHOR-LASTRESORT, on its own status line after the refusals below:
/// the default build's only way out of them (S23-1 #12). The security-key
/// build offers the per-vault forget instead ([이 금고의 기록 지우고 다시
/// 확인…], spec §5.10), which keeps every other vault's record.
#[cfg(not(feature = "security-key"))]
macro_rules! last_resort {
    () => {
        concat!(
            "\r\n",
            "이 열쇠 파일이 맞는 것이 확실하고 다른 방법이 없으면, 마지막 방법으로 고요 금고를 모두 닫고 %LOCALAPPDATA%\\GoyoVault 폴더의 goyo-vault.keys와 goyo-vault.keys.로 시작하는 .tmp 파일을 지운 뒤 다시 여세요. 이 PC에 있는 모든 금고의 열쇠 기록이 함께 지워집니다(README의 '이 PC의 열쇠 기록'을 보세요)."
        )
    };
}
#[cfg(feature = "security-key")]
macro_rules! last_resort {
    () => {
        ""
    };
}
/// The last-resort advice that ends the refusals below (empty in the
/// security-key build).
#[cfg(all(test, not(feature = "security-key")))]
pub(super) const LAST_RESORT: &str = last_resort!();
/// The anchor refusals of a login (spec §5.1 step 9). None counts as a
/// failed attempt, and each comes before any key derivation. In the default
/// build each ends with the last resort.
pub const ANCHOR_DOWNGRADE: &str = concat!(downgrade!(), last_resort!());
pub const ANCHOR_RELIST: &str = concat!(relist!(), last_resort!());
pub const ANCHOR_FORK: &str = concat!(fork!(), last_resort!());
/// The same when the vault file is under the forked branch's key as well.
pub const ANCHOR_FORK_VAULT: &str = concat!(fork!(), "\r\n", fork_vault!(), last_resort!());
/// S-ANCHOR-EPOCH, filled with the key file's epoch and this PC's.
pub const ANCHOR_EPOCH: &str = "이 열쇠 파일의 수정 번호(수정 {new})가 이 PC가 본 것(수정 {old})보다 비정상적으로 큽니다. 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요.";
/// S-ANCHOR-NEWER: a later version wrote the anchor, so this one keeps its
/// record in memory only.
pub const ANCHOR_NEWER: &str = "이 PC의 열쇠 기록(goyo-vault.keys)은 더 새로운 고요 금고가 쓴 것이라 이 버전은 고치지 않습니다. 이번 세션 동안만 기억합니다. 더 새로운 고요 금고를 쓰세요.";
/// S-SIDECAR-FAILED: the anchor could not be written.
pub const SIDECAR_FAILED: &str = "이 PC의 열쇠 상태 기록(goyo-vault.keys)을 저장하지 못했습니다. 이번 세션 동안만 기억합니다. 잠근 뒤에는 이 PC가 예전 열쇠 파일로 되돌려진 것을 알아채지 못하거나, 끊긴 열쇠 변경을 이 PC의 것으로 알아보지 못할 수 있습니다. %LOCALAPPDATA%\\GoyoVault 폴더의 쓰기 권한을 확인하세요.";

#[cfg(debug_assertions)]
thread_local! {
    /// The anchor's folder for this thread in place of %LOCALAPPDATA%: the
    /// tests simulate several PCs in one process, and none may touch the
    /// developer's own anchor (spec §5.10, S23-1 #14).
    static ANCHOR_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}
/// Marks the test folder hook: package_release.py refuses an exe holding it.
#[cfg(debug_assertions)]
const TEST_ANCHOR_MARKER: &str = "goyo-test-anchor";
/// Sets this thread's anchor folder (None: the default); returns the one it
/// replaces. Builds with debug assertions only.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn set_anchor_dir(dir: Option<PathBuf>) -> Option<PathBuf> {
    ANCHOR_DIR.with(|d| d.replace(dir))
}
/// The anchor's folder: `%LOCALAPPDATA%\GoyoVault`, per user and per PC,
/// never next to the exe (a USB disk reports itself as fixed too). A build
/// with debug assertions uses `GoyoVault-debug` instead, or the thread's
/// test folder. None without an absolute %LOCALAPPDATA%.
pub(super) fn locate() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = ANCHOR_DIR.with(|d| d.borrow().clone()) {
        std::hint::black_box(TEST_ANCHOR_MARKER);
        return Some(dir);
    }
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
    if !base.is_absolute() {
        return None;
    }
    #[cfg(debug_assertions)]
    return Some(base.join("GoyoVault-debug"));
    #[cfg(not(debug_assertions))]
    Some(base.join("GoyoVault"))
}

/// Where a tombstone's removal came from: `o` the user removed the key on
/// this PC, `t` it came in another file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Origin {
    Own,
    Taken,
}
/// A removed credential as this PC first saw it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct Tomb {
    pub credhash: [u8; 16],
    /// The current key ID of the first state on this PC that carried it;
    /// zero when unknown.
    pub keyid: [u8; 16],
    pub origin: Origin,
}
impl Tomb {
    /// Whether this removal was made since a fork from a branch whose data
    /// keys are `ids`: the first state on this PC that carried it holds a
    /// key that branch never listed. A removal of unknown origin never is.
    /// Whole key IDs: a prefix would let a forger grind one (review
    /// finding).
    pub fn unlisted(&self, ids: &[[u8; 16]]) -> bool {
        self.keyid != [0; 16] && !ids.contains(&self.keyid)
    }
}
/// A live slot: its number, credhash, registration date (yyyymmdd), the
/// hash of its record with the number and seed zeroed, and its seed's hash
/// (both hashes' first 16 bytes).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct Slot {
    pub number: u8,
    pub credhash: [u8; 16],
    pub date: [u8; 8],
    pub idhash: [u8; 16],
    pub seedhash: [u8; 16],
}
/// A state this PC installed or wrote: its epoch, tag, current key ID,
/// `pw_id` and authorizer's credhash (zero for none), all in full, and its
/// kind (0 for a 0.8 state recorded at its conversion).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Hist {
    pub epoch: u64,
    pub tag: [u8; 16],
    pub keyid: [u8; 16],
    pub pwid: [u8; 16],
    pub auth: [u8; 16],
    pub kind: u8,
}
/// `b`: a key backup was made of this exact state; `t` and `p` belong to
/// the security-key build, which this one keeps as they are.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) struct Flags {
    pub b: bool,
    pub t: bool,
    pub p: bool,
}
/// A `sup` entry (spec §5.10): the data-key ID of a candidate this PC
/// superseded or wrote a removal on top of, and that candidate's state. The
/// security-key build's key-file sync decides with it (stage 6); every
/// build reads and keeps it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Sup {
    pub keyid: [u8; 16],
    pub epoch: u64,
    pub tag: [u8; 16],
}
/// `ks`, this PC's key-file sync intent (spec §7.11): none (`-`, also an
/// absent field), a consented "on" made over the server's cut (`on.<c>`), a
/// write that left key-file sync over the record `L` (`off.<L>`), or one
/// made with no server view (`off.?`). Only the security-key build sets it
/// (stage 6); every build reads it and copies it to every line it writes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) enum Ks {
    #[default]
    None,
    On(u64),
    Off(u64),
    OffUnknown,
}
/// What a `vault` line and a `pending` line both state of a key-file state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct State {
    pub epoch: u64,
    pub tag: [u8; 16],
    pub magic: [u8; 8],
    pub policy: u8,
    pub flags: Flags,
    /// The last `resume` digest whose change completed.
    pub consumed: Option<[u8; 32]>,
    pub tombs: Vec<Tomb>,
    pub slots: Vec<Slot>,
    pub hist: Vec<Hist>,
    pub pbad: Vec<([u8; 16], [u8; 16])>,
    /// The newest state this PC wrote for a change its user started, or
    /// confirmed (spec §5.10).
    pub gated: u64,
    pub sup: Vec<Sup>,
    pub ks: Ks,
    /// `auto=on`: this PC's user turned on "열쇠 변경 자동 적용 (이 서버를
    /// 믿음)" for this vault (spec §2.30): a key file from the server that
    /// would wait for its gate is taken as if the gate had passed. A local
    /// preference: an absent field is off; only the security-key build sets
    /// it, every build reads it and copies it to every line it writes.
    pub auto: bool,
    /// The state's current key ID in full.
    pub keyid: [u8; 16],
}
impl State {
    pub fn key_state(&self) -> KeyState {
        KeyState {
            epoch: self.epoch,
            tag: self.tag,
        }
    }
    /// Whether this state's magic needs a security key.
    pub fn hardware(&self) -> bool {
        self.magic.starts_with(b"GOYOKH") || self.magic.starts_with(b"GOYOKS")
    }
    /// Whether `hist` holds the state (`epoch`, `tag`).
    pub fn had(&self, state: KeyState) -> bool {
        self.hist
            .iter()
            .any(|h| h.epoch == state.epoch && h.tag == state.tag)
    }
    /// Where in `hist` the state a fork shares with a branch whose data
    /// keys are `ids` is: the newest state of this PC whose current key
    /// that branch holds. Whole key IDs: a key ID of a forger's choice that
    /// shares only a prefix with a newer state's never makes that state the
    /// shared one (review finding).
    pub fn shared(&self, ids: &[[u8; 16]]) -> Option<usize> {
        self.hist.iter().position(|h| ids.contains(&h.keyid))
    }
}
/// The confirmed state of a vault: the latest this PC installed, wrote or
/// confirmed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct VaultLine {
    pub state: State,
    /// Server files this PC merged into a write of its own (epoch and the
    /// whole state tag), newest first.
    pub merged: Vec<(u64, [u8; 16])>,
    /// The key ID of the last vault file this PC read as current or wrote.
    pub vkey: Option<[u8; 16]>,
}
/// Which flow wrote a pending line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Src {
    Lost,
    Retire,
    Adopt,
    Accept,
    Merge,
    Supersede,
    Tofu,
    Other,
}
const SRC: [(Src, &str); 8] = [
    (Src::Lost, "lost"),
    (Src::Retire, "retire"),
    (Src::Adopt, "adopt"),
    (Src::Accept, "accept"),
    (Src::Merge, "merge"),
    (Src::Supersede, "supersede"),
    (Src::Tofu, "tofu"),
    (Src::Other, "other"),
];
/// Which password the pending state is sealed with, against this PC's
/// previous one: `n` typed in its flow, `o` the other file's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Pw {
    New,
    Other,
}
/// The gate effects a pending line brings when it lands (security-key
/// build): `g` the gate cleared, `2` a failed G2 reset, `s` superseded.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) struct Clears {
    pub g: bool,
    pub two: bool,
    pub s: bool,
}
/// A state this PC is about to write (spec §5.5 S0): the complete `vault`
/// line it becomes, and what the next unlock needs to recognize it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct PendingLine {
    pub state: State,
    pub kind: u8,
    pub src: Src,
    pub opt: Option<u8>,
    pub rm: Vec<(u8, Origin)>,
    /// yyyymmdd, `unknown` or none.
    pub loss: Option<String>,
    pub exp: Option<u8>,
    pub clone: Vec<u8>,
    pub clears: Clears,
    /// The server file this write merges in.
    pub merged: Option<(u64, [u8; 16])>,
    /// The key file this write replaces, normalized, in UTF-16.
    pub kpath: Option<Vec<u16>>,
    pub pw: Option<Pw>,
    /// The confirmed state this entry was built on; None when there was no
    /// line.
    pub base: Option<(u64, [u8; 16])>,
}
impl VaultLine {
    /// Whether this PC merged the server file at `state` into a write of
    /// its own: by its epoch and its whole state tag.
    #[cfg(any(test, feature = "security-key"))]
    pub fn merged_state(&self, state: KeyState) -> bool {
        self.merged
            .iter()
            .any(|(epoch, tag)| *epoch == state.epoch && *tag == state.tag)
    }
}
impl PendingLine {
    /// The confirmed line this entry becomes once it landed over `old`.
    pub fn promoted(&self, old: Option<&VaultLine>) -> VaultLine {
        let mut merged: Vec<(u64, [u8; 16])> = self.merged.iter().copied().collect();
        merged.extend(old.into_iter().flat_map(|o| o.merged.iter().copied()));
        merged.truncate(RECENT_MAX);
        VaultLine {
            state: self.state.clone(),
            merged,
            vkey: old.and_then(|o| o.vkey),
        }
    }
    /// The key file path this entry names, if any.
    pub fn kpath(&self) -> Option<PathBuf> {
        #[cfg(windows)]
        use std::os::windows::ffi::OsStringExt;
        self.kpath.as_ref().map(|units| {
            #[cfg(windows)]
            return PathBuf::from(std::ffi::OsString::from_wide(units));
            #[cfg(not(windows))]
            PathBuf::from(String::from_utf16_lossy(units))
        })
    }
}
/// The kinds of line. Gate, review and clone lines belong to the
/// security-key build: this one checks their grammar and keeps them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Vault,
    Pending,
    Gate,
    Review,
    Clone,
}
#[derive(Clone, PartialEq, Eq, Debug)]
enum Line {
    Vault([u8; 16], Box<VaultLine>),
    Pending([u8; 16], Box<PendingLine>),
    /// A gate, review or clone line, as it was read.
    Kept(Kind, [u8; 16], String),
}
impl Line {
    fn id(&self) -> &[u8; 16] {
        match self {
            Self::Vault(id, _) | Self::Pending(id, _) | Self::Kept(_, id, _) => id,
        }
    }
}
/// A line this version cannot read, kept verbatim. `owner` names the kind
/// and vault ID it starts with, when they are readable: that vault's next
/// line of that kind replaces it.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Unread {
    bytes: Vec<u8>,
    owner: Option<(Kind, [u8; 16])>,
}
/// The anchor as read: its well-formed lines in file order and the lines
/// kept verbatim.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub(super) struct Anchor {
    lines: Vec<Line>,
    unread: Vec<Unread>,
}
/// One vault's `vault` and `pending` lines: what a write changes.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub(super) struct Lines {
    pub vault: Option<VaultLine>,
    pub pending: Option<PendingLine>,
    /// These lines lead the file (spec §5.10: line order is recency).
    pub first: bool,
    /// The security-key build's `gate` line (spec §7.15a); this build keeps
    /// it as it was read.
    #[cfg(feature = "security-key")]
    pub gate: Option<GateLine>,
    /// The vault's `gate` and `clone` lines go with this write: the TOFU
    /// pass after a forget (spec §5.10, §7.17).
    #[cfg(feature = "security-key")]
    pub forget: bool,
    /// The security-key build's `review` line (spec §5.13); this build
    /// keeps it as it was read. A forget keeps it: a due review is never
    /// released by forgetting the record.
    #[cfg(feature = "security-key")]
    pub review: Option<ReviewLine>,
    /// The security-key build's `clone` lines (spec §5.10): keys flagged
    /// "possibly cloned" by the lost-key flow, each with the `seedhash` of
    /// the seed it had then. Every write of the confirmed line drops a flag
    /// whose key is no longer live there or whose seed changed.
    #[cfg(feature = "security-key")]
    pub clones: Vec<([u8; 16], [u8; 16])>,
}
/// A vault's `review` line (spec §5.13): the post-removal review a removal
/// for a loss made due on this PC, with its loss date (`yyyymmdd`, or
/// `unknown`, the earliest), the epoch of the state that made it due, and
/// whether it is still due or done.
#[cfg(feature = "security-key")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ReviewLine {
    pub loss: String,
    pub epoch: u64,
    pub due: bool,
}
#[cfg(feature = "security-key")]
impl ReviewLine {
    fn parse(text: &str) -> Option<Self> {
        let mut words = text.split(' ');
        (words.next()? == "review").then_some(())?;
        unhex::<16>(words.next()?)?;
        let mut f = Fields(words.peekable());
        let loss = f.get("loss")?;
        (loss == "unknown" || date(loss).is_some()).then_some(())?;
        let epoch = epoch_num(f.get("epoch")?)?;
        let due = match f.get("state")? {
            "due" => true,
            "done" => false,
            _ => return None,
        };
        f.end()?;
        Some(Self {
            loss: loss.to_owned(),
            epoch,
            due,
        })
    }
    fn render(&self, id: &[u8; 16]) -> String {
        format!(
            "review {} loss={} epoch={} state={}",
            hex(id),
            self.loss,
            self.epoch,
            if self.due { "due" } else { "done" }
        )
    }
}
/// The keys a landed pending entry flags "possibly cloned" (spec §5.5 S5):
/// its `clone` numbers, with their credhash and current `seedhash` in the
/// state it becomes.
#[cfg(feature = "security-key")]
pub(super) fn apply_clone(lines: &mut Lines, p: &PendingLine) {
    for n in &p.clone {
        if let Some(s) = p.state.slots.iter().find(|s| s.number == *n)
            && !lines.clones.iter().any(|(c, _)| *c == s.credhash)
        {
            lines.clones.push((s.credhash, s.seedhash));
        }
    }
}
/// The review a landed pending entry makes due (spec §5.13, §5.5 S0): its
/// `loss`, a removal for a loss, lands with the confirmed line as the
/// vault's `review` line; a review already due keeps the earlier date.
#[cfg(feature = "security-key")]
pub(super) fn apply_review(lines: &mut Lines, p: &PendingLine) {
    if let Some(loss) = &p.loss {
        review_due(lines, loss, p.state.epoch);
    }
}
/// The vault's `review` line due from `loss`, or the earlier date of the
/// one already due (the window only grows, spec §5.13).
#[cfg(feature = "security-key")]
pub(super) fn review_due(lines: &mut Lines, loss: &str, epoch: u64) {
    let loss = match lines.review.as_ref().filter(|r| r.due) {
        Some(r) => super::review::earlier(&r.loss, loss).to_owned(),
        None => loss.to_owned(),
    };
    lines.review = Some(ReviewLine {
        loss,
        epoch,
        due: true,
    });
}
/// What became of the change a `gate` line names (spec §7.15a).
#[cfg(feature = "security-key")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum GateState {
    /// A server candidate waits for its gate.
    Pending,
    Dropped,
    Superseded,
    /// Holds nothing: only keeps G2 off after a failed pick (S45-2 #8).
    None,
}
#[cfg(feature = "security-key")]
const GATE_STATES: [(GateState, &str); 4] = [
    (GateState::Pending, "pending"),
    (GateState::Dropped, "dropped"),
    (GateState::Superseded, "superseded"),
    (GateState::None, "none"),
];
/// A vault's `gate` line: the change it names, what became of it, whether
/// G2 is still allowed on this PC, and since when.
#[cfg(feature = "security-key")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct GateLine {
    pub epoch: u64,
    pub tag: [u8; 16],
    pub state: GateState,
    pub g2: bool,
    pub since: u64,
}
#[cfg(feature = "security-key")]
impl GateLine {
    fn parse(text: &str) -> Option<Self> {
        let mut words = text.split(' ');
        (words.next()? == "gate").then_some(())?;
        unhex::<16>(words.next()?)?;
        let mut f = Fields(words.peekable());
        let epoch = epoch_num(f.get("epoch")?)?;
        let tag = unhex(f.get("tag")?)?;
        let state = f.get("state")?;
        let state = GATE_STATES.iter().find(|(_, s)| *s == state)?.0;
        let g2 = match f.get("g2")? {
            "on" => true,
            "off" => false,
            _ => return None,
        };
        let since = num(f.get("since")?)?;
        f.end()?;
        Some(Self {
            epoch,
            tag,
            state,
            g2,
            since,
        })
    }
    fn render(&self, id: &[u8; 16]) -> String {
        let state = GATE_STATES
            .iter()
            .find(|(s, _)| *s == self.state)
            .map_or("none", |s| s.1);
        format!(
            "gate {} epoch={} tag={} state={state} g2={} since={}",
            hex(id),
            self.epoch,
            hex(&self.tag),
            if self.g2 { "on" } else { "off" },
            self.since
        )
    }
}
impl Anchor {
    /// Every line was read: none is kept only verbatim.
    #[cfg(test)]
    pub fn is_clean(&self) -> bool {
        self.unread.is_empty()
    }
    /// The lines of vault `id`, and whether they lead the file.
    pub fn lines(&self, id: &[u8; 16]) -> Lines {
        let mut out = Lines {
            first: self.lines.first().is_some_and(|l| l.id() == id),
            ..Lines::default()
        };
        for line in &self.lines {
            match line {
                Line::Vault(i, v) if i == id => out.vault = Some((**v).clone()),
                Line::Pending(i, p) if i == id => out.pending = Some((**p).clone()),
                #[cfg(feature = "security-key")]
                Line::Kept(Kind::Gate, i, text) if i == id => out.gate = GateLine::parse(text),
                #[cfg(feature = "security-key")]
                Line::Kept(Kind::Review, i, text) if i == id => {
                    out.review = ReviewLine::parse(text)
                }
                #[cfg(feature = "security-key")]
                Line::Kept(Kind::Clone, i, text) if i == id => {
                    let mut words = text.split(' ').skip(2);
                    let flag = (words.next().and_then(unhex), words.next().and_then(unhex));
                    if let (Some(credhash), Some(seedhash)) = flag
                        && !out.clones.iter().any(|(c, _)| *c == credhash)
                    {
                        out.clones.push((credhash, seedhash));
                    }
                }
                _ => {}
            }
        }
        out
    }
    /// The file with `lines` as vault `id`'s, put first. Lines this version
    /// cannot read stay at the end, but for the ones of this vault and kind
    /// that a new line replaces. Over LIMIT, unread lines go first, then
    /// whole vaults from the end, never `id`.
    fn render(&self, id: &[u8; 16], lines: &Lines) -> Vec<u8> {
        let mut own: Vec<String> = Vec::new();
        own.extend(lines.vault.as_ref().map(|v| render_vault(id, v)));
        own.extend(lines.pending.as_ref().map(|p| render_pending(id, p)));
        // The security-key build writes the gate line it holds in place of
        // the one read, and a forget's write drops the clone lines too.
        #[cfg(feature = "security-key")]
        own.extend(lines.gate.as_ref().map(|g| g.render(id)));
        #[cfg(feature = "security-key")]
        own.extend(lines.review.as_ref().map(|r| r.render(id)));
        #[cfg(feature = "security-key")]
        own.extend(
            lines
                .clones
                .iter()
                .filter(|_| !lines.forget)
                .map(|(c, s)| format!("clone {} {} {}", hex(id), hex(c), hex(s))),
        );
        #[cfg(feature = "security-key")]
        let kept = |kind: Kind| !matches!(kind, Kind::Gate | Kind::Review | Kind::Clone);
        #[cfg(not(feature = "security-key"))]
        let kept = |_: Kind| true;
        own.extend(self.lines.iter().filter_map(|l| match l {
            Line::Kept(kind, i, text) if i == id && kept(*kind) => Some(text.clone()),
            _ => None,
        }));
        // Other vaults in file order, grouped by vault so that one can go
        // as a whole.
        let mut others: Vec<([u8; 16], Vec<String>)> = Vec::new();
        for line in self.lines.iter().filter(|l| l.id() != id) {
            let text = match line {
                Line::Vault(i, v) => render_vault(i, v),
                Line::Pending(i, p) => render_pending(i, p),
                Line::Kept(_, _, text) => text.clone(),
            };
            match others.iter_mut().find(|(i, _)| i == line.id()) {
                Some((_, texts)) => texts.push(text),
                None => others.push((*line.id(), vec![text])),
            }
        }
        let replaced = |u: &Unread| match u.owner {
            Some((Kind::Vault, i)) => i == *id && lines.vault.is_some(),
            Some((Kind::Pending, i)) => i == *id && lines.pending.is_some(),
            _ => false,
        };
        let mut unread: Vec<&Vec<u8>> = self
            .unread
            .iter()
            .filter(|u| !replaced(u))
            .map(|u| &u.bytes)
            .collect();
        let size = |others: &[([u8; 16], Vec<String>)], unread: &[&Vec<u8>]| {
            VERSION.len()
                + 1
                + own.iter().map(|t| t.len() + 1).sum::<usize>()
                + others
                    .iter()
                    .flat_map(|(_, t)| t.iter())
                    .map(|t| t.len() + 1)
                    .sum::<usize>()
                + unread.iter().map(|u| u.len() + 1).sum::<usize>()
        };
        while size(&others, &unread) > LIMIT && unread.pop().is_some() {}
        while size(&others, &unread) > LIMIT && others.pop().is_some() {}
        let mut out = Vec::with_capacity(size(&others, &unread));
        out.extend_from_slice(VERSION.as_bytes());
        out.push(b'\n');
        for text in own.iter().chain(others.iter().flat_map(|(_, t)| t.iter())) {
            out.extend_from_slice(text.as_bytes());
            out.push(b'\n');
        }
        for bytes in unread {
            out.extend_from_slice(bytes);
            out.push(b'\n');
        }
        out
    }
}

/// What a read found.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) enum Parsed {
    Doc(Anchor),
    /// A later version's file, or one over LIMIT: never interpreted, never
    /// rewritten.
    Newer,
}
/// Parses anchor bytes. A garbled or missing version line, and every other
/// line this version cannot read, is kept verbatim.
pub(super) fn parse_file(bytes: &[u8]) -> Parsed {
    if bytes.len() > LIMIT {
        return Parsed::Newer;
    }
    let mut doc = Anchor::default();
    let mut parts: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    // A file that ends with a newline leaves one empty part.
    if parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    for (n, part) in parts.into_iter().enumerate() {
        if n == 0
            && let Some(version) = std::str::from_utf8(part)
                .ok()
                .and_then(|l| l.strip_prefix("goyo-vault-keys "))
                .and_then(num)
        {
            if version > 4 {
                return Parsed::Newer;
            }
            // A version-3 file reads with this version's grammar (see
            // VERSION).
            if version >= 3 {
                continue;
            }
        }
        if part.is_empty() {
            continue;
        }
        let line = std::str::from_utf8(part).ok().and_then(parse_line);
        // At most one vault and one pending line per vault; a second one is
        // malformed.
        match line {
            Some(line)
                if !doc.lines.iter().any(|l| {
                    l.id() == line.id()
                        && matches!(
                            (l, &line),
                            (Line::Vault(..), Line::Vault(..))
                                | (Line::Pending(..), Line::Pending(..))
                        )
                }) =>
            {
                doc.lines.push(line)
            }
            _ => doc.unread.push(Unread {
                bytes: part.to_vec(),
                owner: owner(part),
            }),
        }
    }
    Parsed::Doc(doc)
}
/// The kind and vault ID an unreadable line starts with, if readable.
fn owner(line: &[u8]) -> Option<(Kind, [u8; 16])> {
    let line = std::str::from_utf8(line).ok()?;
    let mut words = line.split(' ');
    let kind = match words.next()? {
        "vault" => Kind::Vault,
        "pending" => Kind::Pending,
        "gate" => Kind::Gate,
        "review" => Kind::Review,
        "clone" => Kind::Clone,
        _ => return None,
    };
    Some((kind, unhex(words.next()?)?))
}

/// The fields of a line after its kind and vault ID, in their order.
struct Fields<'a>(std::iter::Peekable<std::str::Split<'a, char>>);
impl<'a> Fields<'a> {
    fn get(&mut self, key: &str) -> Option<&'a str> {
        self.0.next()?.strip_prefix(key)?.strip_prefix('=')
    }
    /// A field a line may lack (spec §5.10: a line without `gated`).
    fn maybe(&mut self, key: &str) -> Option<Option<&'a str>> {
        match self.0.peek() {
            Some(f) if f.strip_prefix(key).is_some_and(|r| r.starts_with('=')) => {
                Some(self.get(key))
            }
            _ => Some(None),
        }
    }
    fn end(mut self) -> Option<()> {
        self.0.next().is_none().then_some(())
    }
}
fn parse_line(line: &str) -> Option<Line> {
    if !line.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return None;
    }
    let mut words = line.split(' ');
    let kind = words.next()?;
    let id: [u8; 16] = unhex(words.next()?)?;
    let mut f = Fields(words.peekable());
    let line = match kind {
        "vault" => {
            let state = state(&mut f)?;
            let merged = list(f.get("merged")?, RECENT_MAX, |m| {
                let (epoch, tag) = m.split_once(':')?;
                Some((epoch_num(epoch)?, unhex(tag)?))
            })?;
            let (pbad, gated, sup, ks, auto) = tail(&mut f, state.epoch)?;
            let keyid = unhex(f.get("keyid")?)?;
            let vkey = maybe(f.get("vkey")?, unhex)?;
            f.end()?;
            let state = State {
                pbad,
                gated,
                sup,
                ks,
                auto,
                keyid,
                ..state
            };
            Line::Vault(
                id,
                Box::new(VaultLine {
                    state,
                    merged,
                    vkey,
                }),
            )
        }
        "pending" => {
            let state = state(&mut f)?;
            let (pbad, gated, sup, ks, auto) = tail(&mut f, state.epoch)?;
            let keyid = unhex(f.get("keyid")?)?;
            let kind = num(f.get("kind")?).filter(|k| (1..=10).contains(k))? as u8;
            let src = f.get("src")?;
            let src = SRC.iter().find(|(_, s)| *s == src)?.0;
            let opt = maybe(f.get("opt")?, |o| match o {
                "1" => Some(1),
                "2" => Some(2),
                _ => None,
            })?;
            let rm = list(f.get("rm")?, SLOTS_MAX, |r| {
                let (number, origin) = r.split_once(':')?;
                Some((slot_number(number)?, origin_of(origin)?))
            })?;
            let loss = maybe(f.get("loss")?, |l| {
                (l == "unknown" || date(l).is_some()).then(|| l.to_owned())
            })?;
            let exp = maybe(f.get("exp")?, |e| match e {
                "y" | "n" | "u" => Some(e.as_bytes()[0]),
                _ => None,
            })?;
            let clone = list(f.get("clone")?, SLOTS_MAX, slot_number)?;
            let clears = flags_of(f.get("clears")?, "g2s")?;
            let clears = Clears {
                g: clears[0],
                two: clears[1],
                s: clears[2],
            };
            let merged = maybe(f.get("merged")?, state_pair)?;
            let kpath = maybe(f.get("kpath")?, kpath)?;
            let pw = maybe(f.get("pw")?, |p| match p {
                "n" => Some(Pw::New),
                "o" => Some(Pw::Other),
                _ => None,
            })?;
            let base = maybe(f.get("base")?, state_pair)?;
            f.end()?;
            let state = State {
                pbad,
                gated,
                sup,
                ks,
                auto,
                keyid,
                ..state
            };
            Line::Pending(
                id,
                Box::new(PendingLine {
                    state,
                    kind,
                    src,
                    opt,
                    rm,
                    loss,
                    exp,
                    clone,
                    clears,
                    merged,
                    kpath,
                    pw,
                    base,
                }),
            )
        }
        "gate" => {
            epoch_num(f.get("epoch")?)?;
            unhex::<16>(f.get("tag")?)?;
            matches!(
                f.get("state")?,
                "pending" | "dropped" | "superseded" | "none"
            )
            .then_some(())?;
            matches!(f.get("g2")?, "on" | "off").then_some(())?;
            num(f.get("since")?)?;
            f.end()?;
            Line::Kept(Kind::Gate, id, line.to_owned())
        }
        "review" => {
            let loss = f.get("loss")?;
            (loss == "unknown" || date(loss).is_some()).then_some(())?;
            epoch_num(f.get("epoch")?)?;
            matches!(f.get("state")?, "due" | "done").then_some(())?;
            f.end()?;
            Line::Kept(Kind::Review, id, line.to_owned())
        }
        "clone" => {
            unhex::<16>(f.0.next()?)?;
            if let Some(seed) = f.0.next() {
                unhex::<16>(seed)?;
            }
            f.end()?;
            Line::Kept(Kind::Clone, id, line.to_owned())
        }
        _ => return None,
    };
    Some(line)
}
/// The fields from `epoch` to `hist` that both line kinds state; the rest
/// of `State` follows in `tail`.
fn state(f: &mut Fields) -> Option<State> {
    let epoch = epoch_num(f.get("epoch")?)?;
    let tag = unhex(f.get("tag")?)?;
    let magic: [u8; 8] = f
        .get("magic")?
        .as_bytes()
        .try_into()
        .ok()
        .filter(|m: &[u8; 8]| {
            m.iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })?;
    let policy = unhex::<1>(f.get("policy")?)?[0];
    let flags = flags_of(f.get("flags")?, "btp")?;
    let consumed = maybe(f.get("consumed")?, unhex)?;
    let tombs = list(f.get("tombs")?, TOMB_MAX, |t| {
        let mut p = t.split(':');
        let tomb = Tomb {
            credhash: unhex(p.next()?)?,
            keyid: unhex(p.next()?)?,
            origin: origin_of(p.next()?)?,
        };
        p.next().is_none().then_some(tomb)
    })?;
    let slots = list(f.get("slots")?, SLOTS_MAX, |s| {
        let mut p = s.split(':');
        let slot = Slot {
            number: slot_number(p.next()?)?,
            credhash: unhex(p.next()?)?,
            date: date(p.next()?)?,
            idhash: unhex(p.next()?)?,
            seedhash: unhex(p.next()?)?,
        };
        p.next().is_none().then_some(slot)
    })?;
    let hist = list(f.get("hist")?, HIST_MAX, |h| {
        let mut p = h.split(':');
        let hist = Hist {
            epoch: epoch_num(p.next()?)?,
            tag: unhex(p.next()?)?,
            keyid: unhex(p.next()?)?,
            pwid: unhex(p.next()?)?,
            auth: unhex(p.next()?)?,
            kind: num(p.next()?).filter(|k| *k <= 10)? as u8,
        };
        p.next().is_none().then_some(hist)
    })?;
    Some(State {
        epoch,
        tag,
        magic,
        policy,
        flags: Flags {
            b: flags[0],
            t: flags[1],
            p: flags[2],
        },
        consumed,
        tombs,
        slots,
        hist,
        pbad: Vec::new(),
        gated: epoch,
        sup: Vec::new(),
        ks: Ks::None,
        auto: false,
        keyid: [0; 16],
    })
}
/// `pbad`, `gated` (a line without it reads as its epoch), `sup`, `ks` (a
/// line without it reads as `-`) and `auto` (a line without it is off).
type Tail = (Vec<([u8; 16], [u8; 16])>, u64, Vec<Sup>, Ks, bool);
fn tail(f: &mut Fields, epoch: u64) -> Option<Tail> {
    let pbad = list(f.get("pbad")?, SLOTS_MAX * (SLOTS_MAX - 1), |p| {
        let (owner, target) = p.split_once('>')?;
        Some((unhex(owner)?, unhex(target)?))
    })?;
    let gated = match f.maybe("gated")? {
        Some(g) => epoch_num(g)?,
        None => epoch,
    };
    // `<keyid>.<epoch>.<tag>`; the bare key ID that 308909f parsed was
    // never released, so it is not read (S6R2 #13).
    let sup = list(f.get("sup")?, RECENT_MAX, |s| {
        let mut p = s.split('.');
        let sup = Sup {
            keyid: unhex(p.next()?)?,
            epoch: epoch_num(p.next()?)?,
            tag: unhex(p.next()?)?,
        };
        p.next().is_none().then_some(sup)
    })?;
    let ks = match f.maybe("ks")? {
        None | Some("-") => Ks::None,
        Some("off.?") => Ks::OffUnknown,
        Some(k) => match k.split_once('.')? {
            ("on", c) => Ks::On(num(c)?),
            ("off", l) => Ks::Off(num(l)?),
            _ => return None,
        },
    };
    let auto = match f.maybe("auto")? {
        None => false,
        Some("on") => true,
        Some(_) => return None,
    };
    Some((pbad, gated, sup, ks, auto))
}
fn render_state(out: &mut String, s: &State) {
    let flags: String = [(s.flags.b, 'b'), (s.flags.t, 't'), (s.flags.p, 'p')]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, c)| *c)
        .collect();
    out.push_str(&format!(
        " epoch={} tag={} magic={} policy={:02x} flags={} consumed={}",
        s.epoch,
        hex(&s.tag),
        String::from_utf8_lossy(&s.magic),
        s.policy,
        dash(&flags),
        s.consumed.as_ref().map_or("-".into(), |c| hex(c)),
    ));
    out.push_str(" tombs=");
    out.push_str(&joined(s.tombs.iter().map(|t| {
        format!(
            "{}:{}:{}",
            hex(&t.credhash),
            hex(&t.keyid),
            origin_name(t.origin)
        )
    })));
    out.push_str(" slots=");
    out.push_str(&joined(s.slots.iter().map(|x| {
        format!(
            "{}:{}:{}:{}:{}",
            x.number,
            hex(&x.credhash),
            String::from_utf8_lossy(&x.date),
            hex(&x.idhash),
            hex(&x.seedhash)
        )
    })));
    out.push_str(" hist=");
    out.push_str(&joined(s.hist.iter().map(|h| {
        format!(
            "{}:{}:{}:{}:{}:{}",
            h.epoch,
            hex(&h.tag),
            hex(&h.keyid),
            hex(&h.pwid),
            hex(&h.auth),
            h.kind
        )
    })));
}
fn render_tail(out: &mut String, s: &State) {
    out.push_str(" pbad=");
    out.push_str(&joined(
        s.pbad.iter().map(|(o, t)| format!("{}>{}", hex(o), hex(t))),
    ));
    out.push_str(&format!(" gated={} sup=", s.gated));
    out.push_str(&joined(
        s.sup
            .iter()
            .map(|e| format!("{}.{}.{}", hex(&e.keyid), e.epoch, hex(&e.tag))),
    ));
    let ks = match s.ks {
        Ks::None => "-".into(),
        Ks::On(c) => format!("on.{c}"),
        Ks::Off(l) => format!("off.{l}"),
        Ks::OffUnknown => "off.?".into(),
    };
    out.push_str(&format!(" ks={ks}"));
    if s.auto {
        out.push_str(" auto=on");
    }
    out.push_str(&format!(" keyid={}", hex(&s.keyid)));
}
fn render_vault(id: &[u8; 16], v: &VaultLine) -> String {
    let mut out = format!("vault {}", hex(id));
    render_state(&mut out, &v.state);
    out.push_str(" merged=");
    out.push_str(&joined(
        v.merged
            .iter()
            .map(|(epoch, tag)| format!("{epoch}:{}", hex(tag))),
    ));
    render_tail(&mut out, &v.state);
    out.push_str(&format!(
        " vkey={}",
        v.vkey.as_ref().map_or("-".into(), |k| hex(k))
    ));
    out
}
fn render_pending(id: &[u8; 16], p: &PendingLine) -> String {
    let mut out = format!("pending {}", hex(id));
    render_state(&mut out, &p.state);
    render_tail(&mut out, &p.state);
    let src = SRC
        .iter()
        .find(|(s, _)| *s == p.src)
        .map_or("other", |s| s.1);
    out.push_str(&format!(
        " kind={} src={src} opt={}",
        p.kind,
        p.opt.map_or("-".into(), |o| o.to_string())
    ));
    out.push_str(" rm=");
    out.push_str(&joined(
        p.rm.iter()
            .map(|(n, origin)| format!("{n}:{}", origin_name(*origin))),
    ));
    out.push_str(&format!(
        " loss={} exp={} clone=",
        p.loss.as_deref().unwrap_or("-"),
        p.exp.map_or("-".into(), |e| char::from(e).to_string())
    ));
    out.push_str(&joined(p.clone.iter().map(u8::to_string)));
    let clears: String = [(p.clears.g, 'g'), (p.clears.two, '2'), (p.clears.s, 's')]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, c)| *c)
        .collect();
    out.push_str(&format!(
        " clears={} merged={} kpath={} pw={} base={}",
        dash(&clears),
        p.merged
            .map_or("-".into(), |(e, t)| format!("{e}:{}", hex(&t))),
        p.kpath.as_ref().map_or("-".into(), |units| {
            let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
            hex(&bytes)
        }),
        match p.pw {
            Some(Pw::New) => "n",
            Some(Pw::Other) => "o",
            None => "-",
        },
        p.base
            .map_or("-".into(), |(e, t)| format!("{e}:{}", hex(&t))),
    ));
    out
}
fn dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}
fn joined(items: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        "-".into()
    } else {
        items.join(",")
    }
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// Lowercase hex of exactly N bytes.
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
/// A decimal number without leading zeros that fits a u64.
fn num(s: &str) -> Option<u64> {
    let canonical = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    canonical.then(|| s.parse().ok()).flatten()
}
fn epoch_num(s: &str) -> Option<u64> {
    num(s).filter(|e| *e <= EPOCH_MAX)
}
fn slot_number(s: &str) -> Option<u8> {
    num(s).filter(|n| (1..=255).contains(n)).map(|n| n as u8)
}
fn date(s: &str) -> Option<[u8; 8]> {
    let d: [u8; 8] = s.as_bytes().try_into().ok()?;
    d.iter().all(u8::is_ascii_digit).then_some(d)
}
fn origin_of(s: &str) -> Option<Origin> {
    match s {
        "o" => Some(Origin::Own),
        "t" => Some(Origin::Taken),
        _ => None,
    }
}
fn origin_name(o: Origin) -> &'static str {
    match o {
        Origin::Own => "o",
        Origin::Taken => "t",
    }
}
/// `-`, or a non-empty subset of `letters` in their order.
fn flags_of(s: &str, letters: &str) -> Option<[bool; 3]> {
    let mut out = [false; 3];
    if s == "-" {
        return Some(out);
    }
    let mut next = 0;
    for c in s.chars() {
        let at = letters[next..].find(c)? + next;
        out[at] = true;
        next = at + 1;
    }
    (!s.is_empty()).then_some(out)
}
/// `-`, or `parse` of the field.
fn maybe<T>(s: &str, parse: impl Fn(&str) -> Option<T>) -> Option<Option<T>> {
    if s == "-" {
        Some(None)
    } else {
        parse(s).map(Some)
    }
}
/// `-`, or at most `max` comma-separated items.
fn list<T>(s: &str, max: usize, item: impl Fn(&str) -> Option<T>) -> Option<Vec<T>> {
    if s == "-" {
        return Some(Vec::new());
    }
    let items: Vec<&str> = s.split(',').collect();
    if items.len() > max {
        return None;
    }
    items.into_iter().map(item).collect()
}
fn state_pair(s: &str) -> Option<(u64, [u8; 16])> {
    let (epoch, tag) = s.split_once(':')?;
    Some((epoch_num(epoch)?, unhex(tag)?))
}
fn kpath(s: &str) -> Option<Vec<u16>> {
    if s.is_empty() || s.len() > 4 * KPATH_MAX || !s.len().is_multiple_of(4) {
        return None;
    }
    // Each UTF-16 unit as its two bytes, low byte first.
    s.as_bytes()
        .as_chunks::<4>()
        .0
        .iter()
        .map(|unit| Some(u16::from_le_bytes(unhex(std::str::from_utf8(unit).ok()?)?)))
        .collect()
}
/// A key path as a pending line records it: None when it is too long.
pub(super) fn kpath_of(path: &Path) -> Option<Vec<u16>> {
    #[cfg(windows)]
    let units: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str().encode_wide().collect()
    };
    #[cfg(not(windows))]
    let units: Vec<u16> = path.to_string_lossy().encode_utf16().collect();
    (!units.is_empty() && units.len() <= KPATH_MAX).then_some(units)
}
#[cfg(feature = "security-key")]
pub(super) fn prefix<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

/// Reads the anchor in `dir` without the lock. A missing file reads as its
/// newest well-formed temp file (the last write was cut off before its
/// rename), else as empty; a reparse point or a file with another name too
/// reads as empty. Err: the file is there but cannot be read.
pub(super) fn read(dir: &Path) -> Result<Parsed, ()> {
    match read_main(dir) {
        Ok(Some(read)) => Ok(read),
        Ok(None) => Ok(newest_temp(dir)
            .map(|(_, doc)| Parsed::Doc(doc))
            .unwrap_or(Parsed::Doc(Anchor::default()))),
        Err(()) => Err(()),
    }
}
/// The anchor file itself; None when it is missing.
fn read_main(dir: &Path) -> Result<Option<Parsed>, ()> {
    match open_plain(&dir.join(NAME)) {
        Ok(Some(bytes)) => Ok(Some(parse_file(&bytes))),
        Ok(None) => Ok(Some(Parsed::Doc(Anchor::default()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}
/// The bytes of the file at `path`, at most LIMIT + 1, read through one
/// handle that does not follow a link. Ok(None) for a reparse point, a
/// folder or a file with a second name: those are no anchor.
#[cfg(windows)]
pub(super) fn open_plain(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT: a link is opened as itself.
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)?;
    let info = super::file_info(&f).map_err(|_| std::io::Error::other("info"))?;
    // FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    if info.attributes & 0x410 != 0 || info.links != 1 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    f.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}
#[cfg(not(windows))]
pub(super) fn open_plain(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}
/// `goyo-vault.keys.<16 lowercase hex>.tmp`, the names `update` gives its
/// temp files.
fn temp_name(name: &str) -> bool {
    name.strip_prefix("goyo-vault.keys.")
        .and_then(|r| r.strip_suffix(".tmp"))
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}
fn temps(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_str().is_some_and(temp_name))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
}
/// The newest temp file that is a whole version-3 anchor: every line well
/// formed, so it is not a write cut off midway.
fn newest_temp(dir: &Path) -> Option<(PathBuf, Anchor)> {
    temps(dir)
        .into_iter()
        .filter_map(|path| {
            let time = fs::symlink_metadata(&path).ok()?.modified().ok()?;
            let bytes = open_plain(&path).ok()??;
            if !bytes.starts_with(VERSION.as_bytes()) || bytes.last() != Some(&b'\n') {
                return None;
            }
            match parse_file(&bytes) {
                Parsed::Doc(doc) if doc.unread.is_empty() => Some((time, path, doc)),
                _ => None,
            }
        })
        .max_by_key(|(time, ..)| *time)
        .map(|(_, path, doc)| (path, doc))
}

/// Why a write did not happen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Failure {
    /// Another process held the lock for LOCK_WAIT.
    Busy,
    /// A later version's file: never rewritten.
    Newer,
    Io,
    /// A test's simulated crash, between the temp file and the rename.
    #[cfg(test)]
    Crash,
}
/// Changes vault `id`'s lines: under the lock file, waiting at most `wait`
/// for it, reads the anchor again (taking back a file whose last write was
/// cut off before its rename), lets `change` edit this vault's lines, and
/// writes them first if it says so. Leftover temp files are deleted, only
/// ever under the lock. Returns the lines as they now are.
pub(super) fn update(
    dir: &Path,
    id: &[u8; 16],
    wait: Duration,
    change: &mut dyn FnMut(&mut Lines) -> bool,
) -> Result<Lines, Failure> {
    fs::create_dir_all(dir).map_err(|_| Failure::Io)?;
    let _lock = lock(dir, wait)?;
    let main = dir.join(NAME);
    let doc = match read_main(dir).map_err(|_| Failure::Io)? {
        Some(read) => read,
        // The last write was cut off before its rename: its temp file holds
        // the anchor.
        None => match newest_temp(dir) {
            Some((temp, doc)) => {
                publish(&temp, &main, false).map_err(|_| Failure::Io)?;
                flush(&main);
                Parsed::Doc(doc)
            }
            None => Parsed::Doc(Anchor::default()),
        },
    };
    let Parsed::Doc(doc) = doc else {
        return Err(Failure::Newer);
    };
    // The file exists, or is about to: no temp file of an unfinished write
    // can matter any more, and no other writer is between its temp file
    // and its rename while this lock is held.
    if main.exists() {
        for temp in temps(dir) {
            let _ = fs::remove_file(temp);
        }
    }
    let mut lines = doc.lines(id);
    if !change(&mut lines) {
        return Ok(lines);
    }
    // Every write of the confirmed line drops the "possibly cloned" flags
    // of keys no longer live there or re-seeded since (S45-2 #10).
    #[cfg(feature = "security-key")]
    {
        let slots = lines.vault.as_ref().map_or(&[][..], |v| &v.state.slots);
        let live = |(c, s): &([u8; 16], [u8; 16])| {
            slots.iter().any(|x| x.credhash == *c && x.seedhash == *s)
        };
        lines.clones.retain(live);
    }
    let bytes = doc.render(id, &lines);
    let suffix = crypto::random::<8>().map_err(|_| Failure::Io)?;
    let temp = dir.join(format!("{NAME}.{}.tmp", hex(suffix.as_slice())));
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
    if super::point("tmp_synced").is_err() {
        return Err(Failure::Crash);
    }
    if publish(&temp, &main, true).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(Failure::Io);
    }
    flush(&main);
    for temp in temps(dir) {
        let _ = fs::remove_file(temp);
    }
    lines.first = lines.vault.is_some() || lines.pending.is_some();
    Ok(lines)
}
/// The lock file around every read-modify-rename (spec §5.10): one anchor
/// serves every vault, and two goyo-vault.exe processes may each have one
/// open.
pub(super) fn lock(dir: &Path, wait: Duration) -> Result<File, Failure> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(format!("{NAME}.lock")))
        .map_err(|_| Failure::Io)?;
    let start = Instant::now();
    loop {
        if f.try_lock().is_ok() {
            return Ok(f);
        }
        if start.elapsed() >= wait {
            return Err(Failure::Busy);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
/// Lets a test hold the lock as another process would.
#[cfg(test)]
pub(super) fn hold_lock(dir: &Path) -> File {
    fs::create_dir_all(dir).unwrap();
    lock(dir, LOCK_WAIT).unwrap()
}

/// How a key file stands against this PC's confirmed state (spec §5.10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorClass {
    /// No line for this vault, or no anchor: a password-only key file is
    /// recorded as it is.
    New,
    Equal,
    /// A later state that descends from the confirmed one: recorded
    /// silently.
    Newer,
    /// An older state of this PC: opened, and key changes, uploads and
    /// merges are held until the user confirms it (S-LOCAL-ROLLBACK).
    Rollback,
    /// A key file that forked from this PC's: a Restore runs held.
    Fork,
    /// A 0.8 key file for a vault with a line: its state needs its data
    /// key, so it is compared once it opens.
    Legacy,
    /// A later state that descends from the confirmed one and changes what
    /// the gate guards (spec §7.15a): the login opens in gate-pending mode
    /// until the gate passes.
    #[cfg(feature = "security-key")]
    Gated(super::gate::GateKind),
    /// No line for a vault that uses security keys: trust on first use,
    /// with G1 before the first edit (spec §7.17).
    #[cfg(feature = "security-key")]
    Bootstrap,
}
/// What the comparison refuses (spec §5.10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Refusal {
    Downgrade,
    Relist,
    Fork,
    TooFar {
        old: u64,
        new: u64,
    },
    /// A key this PC removed is live again, or authorized the file
    /// (S-ANCHOR-RELIST-SK).
    #[cfg(feature = "security-key")]
    RelistKeys,
    /// A key both know has another record than this PC pinned.
    #[cfg(feature = "security-key")]
    Pinned,
    /// Another OTP flag than this PC recorded (E1).
    #[cfg(feature = "security-key")]
    Otp,
}
/// Compares a KF2 key file's public state with the confirmed line.
pub(super) fn compare(h: &KeyHeader, line: Option<&VaultLine>) -> Result<AnchorClass, Refusal> {
    let Some(line) = line else {
        // A key file with security keys and no record of this vault: a
        // bootstrap (spec §7.17).
        #[cfg(feature = "security-key")]
        if h.magic.hardware() {
            return Ok(AnchorClass::Bootstrap);
        }
        return Ok(AnchorClass::New);
    };
    let c = &line.state;
    if c.hardware() && !h.magic.hardware() {
        return Err(Refusal::Downgrade);
    }
    if h.state() == c.key_state() {
        return Ok(AnchorClass::Equal);
    }
    // P3 (a) and P4 against the anchor, at any epoch (round 2, finding 7).
    #[cfg(feature = "security-key")]
    if super::gate::relisted(h, c) {
        return Err(Refusal::RelistKeys);
    }
    // E1 (spec §7.14): the OTP flag is set at create and no writer changes
    // it; a policy change of the gate is only a PIN mode or a magic.
    #[cfg(feature = "security-key")]
    if (h.flags ^ c.policy) & 1 != 0 {
        return Err(Refusal::Otp);
    }
    let had = c.had(h.state());
    let lacks = c
        .tombs
        .iter()
        .any(|t| !h.tombstones.iter().any(|x| x.credhash == t.credhash));
    if lacks && !had {
        return Err(Refusal::Relist);
    }
    if h.epoch > c.epoch {
        if h.epoch - c.epoch > EPOCH_WINDOW {
            return Err(Refusal::TooFar {
                old: c.epoch,
                new: h.epoch,
            });
        }
        // A later key file must hold the confirmed state's current key: one
        // re-sealed from an older key file, or a branch that forked from an
        // older state, does not (S23-3 #1).
        if !h.key_ids.contains(&c.keyid) {
            return Err(Refusal::Fork);
        }
        // A key this PC lists live that the file lacks with no removal: a
        // branch that never saw this PC's change (M; round 3, finding 5).
        // A key both know with another record is no genuine file; one with
        // another number or seed, and every keyset or policy change, waits
        // for the gate (spec §7.15a).
        #[cfg(feature = "security-key")]
        {
            // A security-key state this PC never confirmed has no `gated`
            // epoch: nothing is taken without G1 (round 4, finding 1).
            let gated = (c.flags.t || !c.hardware()).then_some(c.gated);
            let base = super::gate::Base::of_line(line);
            let gates =
                super::gate::Gates::between(&base, h, gated).map_err(|_| Refusal::Pinned)?;
            if !gates.kept.is_empty() {
                return Err(Refusal::Fork);
            }
            if let Some(kind) = gates.needed() {
                return Ok(AnchorClass::Gated(kind));
            }
        }
        return Ok(AnchorClass::Newer);
    }
    if had {
        Ok(AnchorClass::Rollback)
    } else {
        Err(Refusal::Fork)
    }
}
/// The same for a 0.8 key file before it opens: only what needs no data key
/// is decided here.
pub(super) fn compare_legacy(line: Option<&VaultLine>) -> Result<AnchorClass, Refusal> {
    let Some(line) = line else {
        return Ok(AnchorClass::New);
    };
    let c = &line.state;
    if c.hardware() {
        return Err(Refusal::Downgrade);
    }
    // A 0.8 state is in `hist` only when this PC converted the vault, and
    // the confirmed state is one after [이 열쇠 파일이 맞습니다] on a 0.8
    // pair: then its tag decides, once the file opens.
    if c.epoch == 0 || c.hist.iter().any(|h| h.kind == 0) {
        return Ok(AnchorClass::Legacy);
    }
    Err(if c.tombs.is_empty() {
        Refusal::Fork
    } else {
        Refusal::Relist
    })
}
/// The rest of `compare_legacy`, once the 0.8 key file opened to `state`.
pub(super) fn compare_opened_legacy(
    state: KeyState,
    line: &VaultLine,
) -> Result<AnchorClass, Refusal> {
    let c = &line.state;
    if state == c.key_state() {
        Ok(AnchorClass::Equal)
    } else if c.had(state) {
        Ok(AnchorClass::Rollback)
    } else if c.tombs.is_empty() {
        Err(Refusal::Fork)
    } else {
        Err(Refusal::Relist)
    }
}
/// What a landed pending entry does to the vault's `gate` line (spec
/// §7.15a): `g` clears the gate, `2` allows G2 again (a key change the user
/// started; a line that only kept G2 off goes), `s` marks its candidate
/// superseded.
#[cfg(feature = "security-key")]
pub(super) fn apply_clears(lines: &mut Lines, p: &PendingLine) {
    if p.clears.g {
        // A take that trusted the server (spec §2.30: `g` without `2`)
        // clears the gate but keeps a G2 turned off, in a `none` line.
        lines.gate = lines
            .gate
            .take()
            .filter(|g| !g.g2 && !p.clears.two)
            .map(|g| GateLine {
                state: GateState::None,
                ..g
            });
    }
    if let Some(g) = lines.gate.as_mut() {
        if p.clears.s {
            g.state = GateState::Superseded;
        }
        if p.clears.two {
            g.g2 = true;
        }
    }
    if lines
        .gate
        .as_ref()
        .is_some_and(|g| g.state == GateState::None && g.g2)
    {
        lines.gate = None;
    }
}
/// Whether a key file in the state `h` is the pending entry's state.
pub(super) fn landed(h: &KeyHeader, p: &PendingLine) -> bool {
    h.state() == p.state.key_state()
}
/// Whether a key file in the state `h` was written on top of the pending
/// entry's state (spec §5.1 step 9): a later epoch that holds the entry's
/// current key, every slot it lists live or removed, every removal it lists,
/// and, for a write that kept the data key, its own change.
pub(super) fn descends(h: &KeyHeader, p: &PendingLine, confirmed: Option<&VaultLine>) -> bool {
    let s = &p.state;
    if h.epoch <= s.epoch || !h.key_ids.contains(&s.keyid) {
        return false;
    }
    let dead = |c: &[u8; 16]| h.tombstones.iter().any(|t| t.credhash == *c);
    let live = |c: &[u8; 16]| h.slots.iter().any(|x| x.credhash == *c);
    if !s.tombs.iter().all(|t| dead(&t.credhash))
        || !s
            .slots
            .iter()
            .all(|x| live(&x.credhash) || dead(&x.credhash))
    {
        return false;
    }
    match confirmed.map(|c| &c.state) {
        // A write that kept the data key (an added key, a pairing, sync on)
        // shows only through what it changed.
        Some(c) if c.keyid == s.keyid => {
            let added = s
                .slots
                .iter()
                .any(|x| !c.slots.iter().any(|y| y.credhash == x.credhash));
            let magic = s.magic != c.magic && h.magic.bytes() == &s.magic;
            added || magic
        }
        _ => true,
    }
}
/// The anchor's record of a live slot (spec §5.10): its number, credhash
/// and registration day, `idhash` over its slot record with the number and
/// seed zeroed, and `seedhash` over its seed. No seed and no credential ID.
#[cfg(feature = "security-key")]
pub(super) fn slot_of(s: &super::keyfile::SlotPublic) -> Slot {
    use sha2::{Digest, Sha256};
    let mut record = Sha256::new();
    record.update([1, s.flags, 0, 0]);
    record.update(s.registered.to_le_bytes());
    record.update(s.added_epoch.to_le_bytes());
    record.update(s.added_by);
    record.update([0; 32]);
    record.update((s.cred_id.len() as u16).to_le_bytes());
    record.update(&s.cred_id);
    let seed: [u8; 32] = Sha256::digest(s.seed).into();
    let mut date = [b'0'; 8];
    date.copy_from_slice(&crate::fido::stamp(s.registered).as_bytes()[..8]);
    Slot {
        number: s.number,
        credhash: s.credhash,
        date,
        idhash: prefix(&record.finalize()),
        seedhash: prefix(&seed),
    }
}
/// A `hist` entry of a KF2 state.
pub(super) fn hist_of(h: &KeyHeader) -> Hist {
    let auth = h
        .authorizer
        .and_then(|a| h.slots.get(usize::from(a)))
        .map_or([0; 16], |s| s.credhash);
    Hist {
        epoch: h.epoch,
        tag: h.tag,
        keyid: h.current_key_id(),
        pwid: h.pw_id,
        auth,
        kind: h.kind as u8,
    }
}
/// The `hist` entry of a 0.8 state: kind 0, no `pw_id`, no authorizer.
pub(super) fn legacy_hist(state: KeyState, key_id: &[u8; 16]) -> Hist {
    Hist {
        epoch: state.epoch,
        tag: state.tag,
        keyid: *key_id,
        pwid: [0; 16],
        auth: [0; 16],
        kind: 0,
    }
}
/// The confirmed line of a KF2 key file `h` that this PC takes over `old`:
/// its own state with `old`'s history before it, its removals with what
/// `old` knew of them (new ones taken from this file), `old`'s `merged`,
/// `sup`, `ks`, `auto`, `vkey` and `consumed`. `gated` and `t` stay. With
/// security keys also its slots, and `old`'s broken pair records between
/// keys still live.
pub(super) fn line_of(h: &KeyHeader, old: Option<&VaultLine>) -> VaultLine {
    let known = |c: &[u8; 16]| {
        old.and_then(|o| o.state.tombs.iter().find(|t| t.credhash == *c))
            .cloned()
    };
    let tombs = h
        .tombstones
        .iter()
        .map(|t| {
            known(&t.credhash).unwrap_or(Tomb {
                credhash: t.credhash,
                // First seen here; in a first line, its origin is unknown.
                keyid: if old.is_some() {
                    h.current_key_id()
                } else {
                    [0; 16]
                },
                origin: Origin::Taken,
            })
        })
        .collect();
    let mut hist = vec![hist_of(h)];
    hist.extend(
        old.into_iter()
            .flat_map(|o| o.state.hist.iter().copied())
            .filter(|e| (e.epoch, e.tag) != (h.epoch, h.tag)),
    );
    hist.truncate(HIST_MAX);
    // The default build has no security-key state: its lines list no slot
    // and no broken pair record.
    #[cfg(not(feature = "security-key"))]
    let (slots, pbad) = (Vec::new(), Vec::new());
    #[cfg(feature = "security-key")]
    let (slots, pbad) = {
        let slots: Vec<Slot> = h.slots.iter().map(slot_of).collect();
        // A re-seed taken inside any later file: a seed of a key live in
        // both differs from the state this PC held (S45-1 #3).
        let reseeded = old.is_some_and(|o| {
            o.state.slots.iter().any(|a| {
                slots
                    .iter()
                    .any(|b| b.credhash == a.credhash && b.seedhash != a.seedhash)
            })
        });
        if reseeded {
            hist[0].kind = 8;
        }
        // A broken record stays broken while both its keys stay live.
        let live = |c: &[u8; 16]| slots.iter().any(|s| s.credhash == *c);
        let pbad = old
            .map(|o| o.state.pbad.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|(o, t)| live(o) && live(t))
            .collect();
        (slots, pbad)
    };
    VaultLine {
        state: State {
            epoch: h.epoch,
            tag: h.tag,
            magic: *h.magic.bytes(),
            policy: h.flags,
            flags: Flags {
                t: old.is_some_and(|o| o.state.flags.t),
                ..Flags::default()
            },
            consumed: old.and_then(|o| o.state.consumed),
            tombs,
            slots,
            hist,
            pbad,
            gated: old.map_or(h.epoch, |o| o.state.gated),
            sup: old.map(|o| o.state.sup.clone()).unwrap_or_default(),
            ks: old.map_or(Ks::None, |o| o.state.ks),
            auto: old.is_some_and(|o| o.state.auto),
            keyid: h.current_key_id(),
        },
        merged: old.map(|o| o.merged.clone()).unwrap_or_default(),
        vkey: old.and_then(|o| o.vkey),
    }
}
/// The pending line of a key change of this PC to the password-only state
/// `h` (spec §5.5 S0): the complete line it becomes over `confirmed`, a
/// change the user started (`gated`), sealed with the password typed in
/// its flow, built on `confirmed`'s state. The conversion of a 0.8 key file
/// also records the 0.8 state (`legacy`) as the oldest one this PC had.
pub(super) fn pending_of(
    h: &KeyHeader,
    confirmed: Option<&VaultLine>,
    legacy: Option<Hist>,
    kpath: Option<Vec<u16>>,
) -> PendingLine {
    let mut line = line_of(h, confirmed);
    line.state.gated = h.epoch;
    if let Some(legacy) = legacy
        && !line.state.hist.contains(&legacy)
    {
        line.state.hist.push(legacy);
        line.state.hist.truncate(HIST_MAX);
    }
    PendingLine {
        state: line.state,
        kind: h.kind as u8,
        src: Src::Other,
        opt: None,
        rm: Vec::new(),
        loss: None,
        exp: None,
        clone: Vec::new(),
        clears: Clears {
            two: true,
            ..Clears::default()
        },
        merged: None,
        kpath,
        pw: Some(Pw::New),
        base: confirmed.map(|c| (c.state.epoch, c.state.tag)),
    }
}
/// The confirmed line of a 0.8 key file in `state` (epoch 0 and its legacy
/// tag, spec §4.5) whose one data key has the ID `key_id`, taken over
/// `old`: after [이 열쇠 파일이 맞습니다] on a 0.8 pair put back.
pub(super) fn legacy_line(
    state: KeyState,
    magic: Magic,
    otp: bool,
    key_id: &[u8; 16],
    old: Option<&VaultLine>,
) -> VaultLine {
    let mut hist = vec![legacy_hist(state, key_id)];
    hist.extend(
        old.into_iter()
            .flat_map(|o| o.state.hist.iter().copied())
            .filter(|e| (e.epoch, e.tag) != (state.epoch, state.tag)),
    );
    hist.truncate(HIST_MAX);
    VaultLine {
        state: State {
            epoch: state.epoch,
            tag: state.tag,
            magic: *magic.bytes(),
            policy: u8::from(otp),
            flags: Flags {
                t: old.is_some_and(|o| o.state.flags.t),
                ..Flags::default()
            },
            consumed: old.and_then(|o| o.state.consumed),
            tombs: Vec::new(),
            slots: Vec::new(),
            hist,
            pbad: Vec::new(),
            gated: state.epoch,
            sup: old.map(|o| o.state.sup.clone()).unwrap_or_default(),
            ks: old.map_or(Ks::None, |o| o.state.ks),
            auto: old.is_some_and(|o| o.state.auto),
            keyid: *key_id,
        },
        merged: old.map(|o| o.merged.clone()).unwrap_or_default(),
        vkey: old.and_then(|o| o.vkey),
    }
}
/// What precheck found in the anchor for a login or Restore (spec §5.1 step
/// 9), kept for the unlock to apply.
#[derive(Clone, Debug)]
pub(super) struct Seen {
    /// The anchor's folder; None when there is none.
    pub dir: Option<PathBuf>,
    /// The file is a later version's: compared as with no line, and never
    /// written.
    pub newer: bool,
    /// This vault's lines as read.
    pub lines: Lines,
    pub pending: Decision,
    pub class: AnchorClass,
    /// The per-vault forget: this vault's lines are ignored in memory, and
    /// nothing is written for it until the TOFU pass (spec §5.10).
    #[cfg(feature = "security-key")]
    pub forgotten: bool,
}
/// What becomes of the pending line of this vault (spec §5.1 step 9).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) enum Decision {
    None,
    /// It landed (exactly, or a later key file descends from it): promoted.
    /// `own`: the key file opened is that state or descends from it, not
    /// another copy read at `kpath`.
    Promote {
        own: bool,
    },
    /// It never landed, or was overtaken by a change of the confirmed line.
    Drop {
        overtaken: bool,
    },
    /// The file at its `kpath` could not be read: left as it is.
    Leave(PathBuf),
}
impl Seen {
    /// The confirmed line the key file is compared with: the pending one
    /// once it landed.
    pub fn confirmed(&self) -> Option<VaultLine> {
        match self.pending {
            Decision::Promote { .. } => self
                .lines
                .pending
                .as_ref()
                .map(|p| p.promoted(self.lines.vault.as_ref())),
            _ => self.lines.vault.clone(),
        }
    }
}
/// Reads the anchor and decides the pending line of vault `id` for a login
/// with `key` from `key_path` (spec §5.1 step 9). A Restore decides nothing
/// about it (`restore`).
pub(super) fn look(id: &[u8; 16], key: &KeyFile, key_path: &Path, restore: bool) -> Seen {
    let dir = locate();
    let read = dir.as_deref().map(read);
    // A file that cannot be read, or a later version's, compares as one
    // with no line.
    let (newer, lines) = match read {
        Some(Ok(Parsed::Doc(doc))) => (false, doc.lines(id)),
        Some(Ok(Parsed::Newer)) => (true, Lines::default()),
        Some(Err(())) | None => (false, Lines::default()),
    };
    let pending = match &lines.pending {
        None => Decision::None,
        Some(_) if restore => Decision::None,
        Some(p) => decide(p, lines.vault.as_ref(), key, key_path),
    };
    Seen {
        dir,
        newer,
        lines,
        pending,
        class: AnchorClass::New,
        #[cfg(feature = "security-key")]
        forgotten: false,
    }
}
fn decide(p: &PendingLine, line: Option<&VaultLine>, key: &KeyFile, key_path: &Path) -> Decision {
    // Built on a confirmed state this line no longer has: it waited while
    // the confirmed line moved on, and counts as one that never landed.
    if p.base != line.map(|l| (l.state.epoch, l.state.tag)) {
        return Decision::Drop { overtaken: true };
    }
    if let Some(h) = key.header()
        && (landed(h, p) || descends(h, p, line))
    {
        return Decision::Promote { own: true };
    }
    // Another copy of the key file was opened: only the file this write
    // replaced can tell whether it landed.
    match p.kpath() {
        Some(target) if !same_path(&target, key_path) => {
            if remote(&target) {
                return Decision::Leave(target);
            }
            match read_target(&target) {
                Some(bytes) => match parse(&bytes) {
                    Ok(h) if landed(&h, p) || descends(&h, p, line) => {
                        Decision::Promote { own: false }
                    }
                    _ => Decision::Drop { overtaken: false },
                },
                None => Decision::Leave(target),
            }
        }
        _ => Decision::Drop { overtaken: false },
    }
}
#[cfg(test)]
thread_local! {
    /// Reads of a pending line's key path on this thread.
    pub(super) static KPATH_READS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}
/// The key file at a pending line's path, 32 KiB at most; None when it is
/// missing or cannot be read (an unplugged stick).
fn read_target(path: &Path) -> Option<Vec<u8>> {
    #[cfg(test)]
    KPATH_READS.with(|n| n.set(n.get() + 1));
    super::keyfile::read_head(path, super::keyfile::KEY_FILE_LIMIT).ok()
}
fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
}
/// Whether `path` is on a network share: it is never read at precheck, so
/// an offline share does not stall a login (S23-2 #2).
#[cfg(not(windows))]
pub(super) fn remote(path: &Path) -> bool {
    path.to_string_lossy().starts_with("//")
}
#[cfg(windows)]
pub(super) fn remote(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let text = path.to_string_lossy();
    // Normalized: `\\?\UNC\server\share`; as typed: `\\server\share`.
    let verbatim = text.strip_prefix("\\\\?\\");
    if verbatim.is_some_and(|r| r.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("UNC\\")))
        || (verbatim.is_none() && text.starts_with("\\\\"))
    {
        return true;
    }
    let rest = verbatim.unwrap_or(&text);
    let Some(drive) = rest.get(..3).filter(|d| {
        let b = d.as_bytes();
        b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
    }) else {
        return false;
    };
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDriveTypeW(root: *const u16) -> u32;
    }
    let root: Vec<u16> = std::ffi::OsStr::new(drive)
        .encode_wide()
        .chain(Some(0))
        .collect();
    // DRIVE_REMOTE
    unsafe { GetDriveTypeW(root.as_ptr()) == 4 }
}
/// The key IDs a refusal's vault file note looks at: whether each one is
/// unknown to this PC, neither its last current vault key nor the current
/// key of a state it had (S23-2 #9).
pub(super) fn foreign_key(line: &VaultLine, key_id: &[u8; 16]) -> bool {
    line.vkey.as_ref() != Some(key_id) && !line.state.hist.iter().any(|h| h.keyid == *key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::keyfile::{self, Bundle, Kind, Plan, Spec, Tombstone};

    /// A fresh folder standing for `%LOCALAPPDATA%\GoyoVault`.
    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "goyo-anchor-{:x}",
                u128::from_le_bytes(*crypto::random::<16>().unwrap())
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn main(&self) -> PathBuf {
            self.0.join(NAME)
        }
        fn doc(&self) -> Anchor {
            match read(&self.0).unwrap() {
                Parsed::Doc(doc) => doc,
                Parsed::Newer => panic!("a later version's file"),
            }
        }
        fn temps(&self) -> Vec<PathBuf> {
            temps(&self.0)
        }
        /// Sets vault `id`'s confirmed line.
        fn put(&self, id: &[u8; 16], line: &VaultLine) {
            update(&self.0, id, LOCK_WAIT, &mut |lines| {
                lines.vault = Some(line.clone());
                true
            })
            .unwrap();
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    /// A state with every field of a line in use.
    fn full_state() -> State {
        State {
            epoch: 12,
            tag: [0xa1; 16],
            magic: *b"GOYOKH01",
            policy: 3,
            flags: Flags {
                b: true,
                t: true,
                p: true,
            },
            consumed: Some([0xc0; 32]),
            tombs: vec![
                Tomb {
                    credhash: [1; 16],
                    keyid: [2; 16],
                    origin: Origin::Own,
                },
                Tomb {
                    credhash: [3; 16],
                    keyid: [0; 16],
                    origin: Origin::Taken,
                },
            ],
            slots: vec![
                Slot {
                    number: 1,
                    credhash: [4; 16],
                    date: *b"20261027",
                    idhash: [5; 16],
                    seedhash: [6; 16],
                },
                Slot {
                    number: 255,
                    credhash: [0x44; 16],
                    date: *b"19700101",
                    idhash: [0x55; 16],
                    seedhash: [0x66; 16],
                },
            ],
            hist: vec![
                Hist {
                    epoch: 12,
                    tag: [7; 16],
                    keyid: [8; 16],
                    pwid: [9; 16],
                    auth: [10; 16],
                    kind: 4,
                },
                Hist {
                    epoch: 0,
                    tag: [0x70; 16],
                    keyid: [0x80; 16],
                    pwid: [0; 16],
                    auth: [0; 16],
                    kind: 0,
                },
            ],
            pbad: vec![([11; 16], [12; 16])],
            gated: 11,
            sup: vec![
                Sup {
                    keyid: [13; 16],
                    epoch: 9,
                    tag: [0xd3; 16],
                },
                Sup {
                    keyid: [0x13; 16],
                    epoch: EPOCH_MAX,
                    tag: [0; 16],
                },
            ],
            ks: Ks::Off(7),
            auto: false,
            keyid: [14; 16],
        }
    }
    /// The same with every list and option empty.
    fn bare_state() -> State {
        State {
            epoch: EPOCH_MAX,
            tag: [0; 16],
            magic: *b"GOYOKE03",
            policy: 0,
            flags: Flags::default(),
            consumed: None,
            tombs: Vec::new(),
            slots: Vec::new(),
            hist: Vec::new(),
            pbad: Vec::new(),
            gated: 0,
            sup: Vec::new(),
            ks: Ks::None,
            auto: false,
            keyid: [0xff; 16],
        }
    }
    fn full_pending() -> PendingLine {
        PendingLine {
            state: full_state(),
            kind: 4,
            src: Src::Lost,
            opt: Some(1),
            rm: vec![(2, Origin::Own), (5, Origin::Taken)],
            loss: Some("20261020".into()),
            exp: Some(b'u'),
            clone: vec![3, 9],
            clears: Clears {
                g: true,
                two: true,
                s: true,
            },
            merged: Some((11, [18; 16])),
            kpath: kpath_of(Path::new(r"\\?\D:\금고 폴더\열쇠.goyokey")),
            pw: Some(Pw::Other),
            base: Some((11, [0xa2; 16])),
        }
    }
    fn bare_pending() -> PendingLine {
        PendingLine {
            state: bare_state(),
            kind: 2,
            src: Src::Other,
            opt: None,
            rm: Vec::new(),
            loss: Some("unknown".into()),
            exp: None,
            clone: Vec::new(),
            clears: Clears::default(),
            merged: None,
            kpath: None,
            pw: None,
            base: None,
        }
    }
    fn parsed(text: &str) -> Option<Line> {
        parse_line(text)
    }

    /// Every line kind renders and parses back to itself, with every field
    /// in use and with every list empty, the feature fields included; a
    /// line without `keyid` is malformed, one without `gated` reads it as
    /// its epoch (spec §14.2-11).
    #[test]
    fn every_line_kind_renders_and_parses_back() {
        let id = [0x5e; 16];
        for line in [
            VaultLine {
                state: full_state(),
                merged: vec![(10, [15; 16]), (9, [16; 16])],
                vkey: Some([17; 16]),
            },
            VaultLine {
                state: bare_state(),
                merged: Vec::new(),
                vkey: None,
            },
        ] {
            let text = render_vault(&id, &line);
            assert!(text.is_ascii() && !text.contains('\n'));
            assert_eq!(parsed(&text), Some(Line::Vault(id, Box::new(line))));
        }
        for pending in [full_pending(), bare_pending()] {
            let text = render_pending(&id, &pending);
            assert!(text.is_ascii());
            assert_eq!(
                parsed(&text),
                Some(Line::Pending(id, Box::new(pending.clone())))
            );
        }
        // The key path is the user's, in UTF-16: a Korean path round-trips.
        assert_eq!(
            full_pending().kpath(),
            Some(PathBuf::from(r"\\?\D:\금고 폴더\열쇠.goyokey"))
        );
        // A path over 1024 UTF-16 units is recorded as none.
        let path = |n: usize| PathBuf::from(format!(r"\\?\C:\{}.goyokey", "가".repeat(n)));
        assert_eq!(
            kpath_of(&path(KPATH_MAX - 15)).map(|u| u.len()),
            Some(KPATH_MAX)
        );
        assert_eq!(kpath_of(&path(KPATH_MAX - 14)), None);
        // The security-key build's lines are read and kept as they are.
        let hex32 = "0123456789abcdef0123456789abcdef";
        for text in [
            format!("gate {hex32} epoch=3 tag={hex32} state=pending g2=off since=1700000000"),
            format!("gate {hex32} epoch=3 tag={hex32} state=superseded g2=on since=0"),
            format!("review {hex32} loss=unknown epoch=4 state=due"),
            format!("review {hex32} loss=20261020 epoch=4 state=done"),
            format!("clone {hex32} {hex32}"),
            format!("clone {hex32} {hex32} {hex32}"),
        ] {
            assert!(
                matches!(parsed(&text), Some(Line::Kept(_, _, t)) if t == text),
                "{text}"
            );
        }
        // Without `keyid`: malformed (no released version wrote one).
        let text = render_vault(
            &id,
            &VaultLine {
                state: full_state(),
                merged: Vec::new(),
                vkey: None,
            },
        );
        let at = text.find(" keyid=").unwrap();
        let without = format!("{}{}", &text[..at], &text[at + " keyid=".len() + 32..]);
        assert!(without.ends_with(" vkey=-"));
        assert_eq!(parsed(&without), None);
        // Without `gated`: read as the line's epoch.
        let at = text.find(" gated=").unwrap();
        let end = at + text[at + 1..].find(' ').unwrap() + 1;
        let read = parsed(&format!("{}{}", &text[..at], &text[end..]));
        assert!(matches!(read, Some(Line::Vault(_, v)) if v.state.gated == 12));
        // Strict: upper-case hex, a leading zero, an unknown flag, a field
        // out of order, an epoch above EPOCH_MAX, a trailing space.
        for bad in [
            text.replace("tag=a1a1", "tag=A1A1"),
            text.replace("epoch=12 ", "epoch=012 "),
            text.replace("flags=btp", "flags=bx"),
            text.replace("flags=btp", "flags=pt"),
            text.replace(" magic=GOYOKH01 policy=03", " policy=03 magic=GOYOKH01"),
            text.replace("epoch=12 ", &format!("epoch={} ", EPOCH_MAX + 1)),
            format!("{text} "),
            text.replace("vault ", "vault  "),
        ] {
            assert_ne!(bad, text);
            assert_eq!(parsed(&bad), None, "{bad}");
        }
    }

    /// Version 4 states every key ID, `pw_id`, tag, authorizer and hash in
    /// full (review finding: 4-byte key ID prefixes are cheap to grind):
    /// they round-trip whole, a version-3 line with prefixes is unreadable
    /// and counts as absent, and the next write of its vault replaces it
    /// under this version's first line.
    #[test]
    fn ids_round_trip_whole_and_a_version_3_line_is_unreadable() {
        let id = [0x5e; 16];
        let seq = |b: u8| -> [u8; 16] { std::array::from_fn(|i| b.wrapping_add(i as u8)) };
        let mut line = VaultLine {
            state: full_state(),
            merged: Vec::new(),
            vkey: None,
        };
        line.state.hist[0] = Hist {
            epoch: 12,
            tag: seq(0x10),
            keyid: seq(0x20),
            pwid: seq(0x30),
            auth: seq(0x40),
            kind: 4,
        };
        line.state.tombs[0].keyid = seq(0x50);
        line.state.slots[0].idhash = seq(0x60);
        line.state.slots[0].seedhash = seq(0x70);
        line.state.pbad = vec![(seq(0x80), seq(0x90))];
        line.merged = vec![(11, seq(0xa0))];
        let text = render_vault(&id, &line);
        assert!(
            text.contains(&format!(" merged=11:{} ", hex(&seq(0xa0)))),
            "{text}"
        );
        assert!(
            text.contains(&format!(" pbad={}>{} ", hex(&seq(0x80)), hex(&seq(0x90)))),
            "{text}"
        );
        let h = line.state.hist[0];
        let entry = format!(
            " hist=12:{}:{}:{}:{}:4,",
            hex(&h.tag),
            hex(&h.keyid),
            hex(&h.pwid),
            hex(&h.auth)
        );
        assert!(text.contains(&entry), "{text}");
        assert!(text.contains(&format!(":{}:o,", hex(&seq(0x50)))), "{text}");
        assert!(text.contains(&format!(":{}:{},", hex(&seq(0x60)), hex(&seq(0x70)))));
        assert_eq!(parsed(&text), Some(Line::Vault(id, Box::new(line.clone()))));
        // Version 3's prefixes: 8 bytes of a tag or a record hash, 4 of a
        // key ID, `pw_id`, credhash or seed hash.
        for (whole, kept) in [
            (seq(0x10), 8),
            (seq(0x20), 4),
            (seq(0x30), 4),
            (seq(0x40), 4),
            (seq(0x50), 4),
            (seq(0x60), 8),
            (seq(0x70), 4),
            (seq(0x80), 4),
            (seq(0x90), 4),
            (seq(0xa0), 8),
        ] {
            let short = text.replace(&hex(&whole), &hex(&whole[..kept]));
            assert_ne!(short, text);
            assert_eq!(parsed(&short), None, "{short}");
        }
        let hex32 = "0123456789abcdef0123456789abcdef";
        assert_eq!(parsed(&format!("clone {hex32} {hex32} 01234567")), None);
        // A version-3 file: no later version; its line with prefixes is
        // kept, counts as absent, and goes with the next write of its vault.
        let v3 = text.replace(&hex(&h.keyid), &hex(&h.keyid[..4]));
        let Parsed::Doc(doc) = parse_file(format!("goyo-vault-keys 3\n{v3}\n").as_bytes()) else {
            panic!("newer");
        };
        assert!(doc.lines(&id).vault.is_none() && !doc.is_clean());
        let lines = Lines {
            vault: Some(line),
            ..Lines::default()
        };
        assert_eq!(
            doc.render(&id, &lines),
            format!("{VERSION}\n{text}\n").into_bytes()
        );
    }

    /// The anchor's decisions take whole IDs (review finding): a key ID or
    /// tag that shares all but its last byte with one of `hist`, or with a
    /// removal's key ID, matches nothing.
    #[test]
    fn a_prefix_matches_no_state_no_removal_and_no_key() {
        let s = full_state();
        let near = |mut x: [u8; 16]| {
            x[15] ^= 1;
            x
        };
        let (newer, older) = (s.hist[0], s.hist[1]);
        // The shared state of a fork.
        assert_eq!(s.shared(&[older.keyid]), Some(1));
        assert_eq!(s.shared(&[near(newer.keyid), older.keyid]), Some(1));
        assert_eq!(s.shared(&[near(newer.keyid), near(older.keyid)]), None);
        assert_eq!(s.shared(&[newer.keyid]), Some(0));
        // A state this PC had.
        let state = |tag| KeyState { epoch: 12, tag };
        assert!(s.had(state(newer.tag)));
        assert!(!s.had(state(near(newer.tag))));
        // A removal made since a fork.
        let (known, unknown) = (&s.tombs[0], &s.tombs[1]);
        assert!(!known.unlisted(&[known.keyid]));
        assert!(known.unlisted(&[near(known.keyid)]));
        assert!(!unknown.unlisted(&[]));
        // A vault file's key this PC never had current.
        let line = VaultLine {
            state: s.clone(),
            merged: Vec::new(),
            vkey: None,
        };
        assert!(!foreign_key(&line, &older.keyid));
        assert!(foreign_key(&line, &near(older.keyid)));
        // A server file this PC merged.
        let line = VaultLine {
            merged: vec![(12, newer.tag)],
            ..line
        };
        assert!(line.merged_state(state(newer.tag)));
        assert!(!line.merged_state(state(near(newer.tag))));
        assert!(!line.merged_state(KeyState {
            epoch: 11,
            tag: newer.tag
        }));
    }

    /// A file this version cannot fully read is never thrown away: every
    /// well-formed line is used, every other line kept verbatim (a garbled
    /// version line too) and counts as absent for its vault, and a
    /// malformed line of the vault being written is replaced by its new
    /// line (S23-1 #11).
    #[test]
    fn unreadable_lines_are_kept_and_count_as_absent() {
        let d = Dir::new();
        let (a, b, c) = ([0xaa; 16], [0xbb; 16], [0xcc; 16]);
        let good = VaultLine {
            state: full_state(),
            merged: Vec::new(),
            vkey: None,
        };
        let text_a = render_vault(&a, &good);
        let broken_b = format!("vault {} epoch=zzz", hex(&b));
        let no_keyid_c = {
            let t = render_vault(&c, &good);
            let at = t.find(" keyid=").unwrap();
            format!("{}{}", &t[..at], &t[at + " keyid=".len() + 32..])
        };
        let gate_c = format!(
            "gate {} epoch=3 tag={} state=dropped g2=off since=5",
            hex(&c),
            hex(&[1; 16])
        );
        let file = format!(
            "goyo-vault-keyz 3\n{text_a}\n{broken_b}\nhello\u{ff}\n{no_keyid_c}\n{gate_c}\npending {} x\n",
            hex(&a)
        );
        fs::write(d.main(), &file).unwrap();
        let doc = d.doc();
        assert!(doc.lines(&a).vault.is_some() && doc.lines(&a).pending.is_none());
        assert_eq!(doc.lines(&b), Lines::default());
        assert!(doc.lines(&c).vault.is_none());
        // Writing B's line replaces B's malformed one and keeps every other
        // line, the unreadable ones verbatim after the well-formed ones.
        let mut line_b = good.clone();
        line_b.state.epoch = 3;
        d.put(&b, &line_b);
        let after = fs::read(d.main()).unwrap();
        let lines: Vec<&[u8]> = after.split(|x| *x == b'\n').collect();
        assert_eq!(lines[0], VERSION.as_bytes());
        assert_eq!(lines[1], render_vault(&b, &line_b).as_bytes());
        assert_eq!(lines[2], text_a.as_bytes());
        assert_eq!(lines[3], gate_c.as_bytes());
        let kept: Vec<&[u8]> = lines[4..]
            .iter()
            .copied()
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            kept,
            [
                &b"goyo-vault-keyz 3"[..],
                "hello\u{ff}".as_bytes(),
                no_keyid_c.as_bytes(),
                format!("pending {} x", hex(&a)).as_bytes(),
            ]
        );
        assert!(
            !after
                .windows(broken_b.len())
                .any(|w| w == broken_b.as_bytes())
        );
        // Writing C's vault line replaces its malformed one; its gate line,
        // a security-key build's, stays byte for byte.
        d.put(&c, &good);
        let after = String::from_utf8_lossy(&fs::read(d.main()).unwrap()).into_owned();
        assert!(!after.contains(&no_keyid_c) && after.contains(&gate_c));
        assert!(after.contains(&format!("pending {} x", hex(&a))));
    }

    /// A file of a later version, or one over 1 MiB, is neither interpreted
    /// nor rewritten (S23-1 #11).
    #[test]
    fn a_later_version_or_a_file_over_1_mib_is_never_rewritten() {
        let d = Dir::new();
        let later = format!(
            "goyo-vault-keys 5\n{}\n",
            render_vault(
                &[1; 16],
                &VaultLine {
                    state: full_state(),
                    merged: Vec::new(),
                    vkey: None,
                }
            )
        );
        let large = {
            let mut f = format!("{VERSION}\n").into_bytes();
            f.resize(LIMIT + 1, b'x');
            f
        };
        for bytes in [later.into_bytes(), large] {
            fs::write(d.main(), &bytes).unwrap();
            assert_eq!(read(&d.0), Ok(Parsed::Newer));
            let mut called = false;
            let result = update(&d.0, &[2; 16], LOCK_WAIT, &mut |_| {
                called = true;
                true
            });
            assert_eq!(result, Err(Failure::Newer));
            assert!(!called);
            assert_eq!(fs::read(d.main()).unwrap(), bytes);
        }
    }

    /// Line order is recency: every write puts its vault's lines first. Over
    /// 1 MiB the unreadable lines go first, then whole vaults from the end,
    /// never the vault being written (S23-2 #20).
    #[test]
    fn line_order_is_recency_and_the_limit_drops_the_oldest() {
        let d = Dir::new();
        let line = VaultLine {
            state: bare_state(),
            merged: Vec::new(),
            vkey: None,
        };
        let (a, b, c) = ([0xa; 16], [0xb; 16], [0xc; 16]);
        for id in [a, b, c, a] {
            d.put(&id, &line);
        }
        let order: Vec<[u8; 16]> = d.doc().lines.iter().map(|l| *l.id()).collect();
        assert_eq!(order, [a, c, b]);
        assert!(d.doc().lines(&a).first && !d.doc().lines(&b).first);
        // A big line per vault: 480 removals and 64 states.
        let mut big = line.clone();
        big.state.tombs = (0..TOMB_MAX)
            .map(|i| Tomb {
                credhash: [(i % 251) as u8; 16].map(|x| x ^ (i / 251) as u8),
                keyid: [1; 16],
                origin: Origin::Taken,
            })
            .collect();
        big.state.hist = vec![
            Hist {
                epoch: 1,
                tag: [1; 16],
                keyid: [1; 16],
                pwid: [1; 16],
                auth: [1; 16],
                kind: 2,
            };
            HIST_MAX
        ];
        let size = render_vault(&a, &big).len() + 1;
        let fit = (LIMIT - VERSION.len() - 1) / size;
        let mut doc = Anchor::default();
        for n in 0..fit {
            let id = [n as u8 + 1; 16];
            doc.lines.push(Line::Vault(id, Box::new(big.clone())));
        }
        doc.unread.push(Unread {
            bytes: b"garbage".to_vec(),
            owner: None,
        });
        // A new vault's line: the garbage goes, then the oldest vault, the
        // last in the file.
        let new = [0xee; 16];
        let lines = Lines {
            vault: Some(big.clone()),
            ..Lines::default()
        };
        let bytes = doc.render(&new, &lines);
        assert!(bytes.len() <= LIMIT);
        let Parsed::Doc(after) = parse_file(&bytes) else {
            panic!("newer");
        };
        assert!(after.unread.is_empty());
        assert_eq!(*after.lines[0].id(), new);
        assert_eq!(after.lines.len(), fit);
        assert!(after.lines(&[fit as u8; 16]).vault.is_none());
        assert!(after.lines(&[1; 16]).vault.is_some());
        // The vault being written stays even when it alone is that large.
        let lines = Lines {
            vault: Some(big),
            ..Lines::default()
        };
        let bytes = doc.render(&[fit as u8; 16], &lines);
        let Parsed::Doc(after) = parse_file(&bytes) else {
            panic!("newer");
        };
        assert_eq!(*after.lines[0].id(), [fit as u8; 16]);
    }

    /// The anchor is written to a temp file and renamed over: a crash in
    /// between leaves the old file (or, at the very first write, none), and
    /// the next read takes back the temp of a file that is missing (I12). A
    /// read without the lock never renames or deletes a temp file; the next
    /// locked write deletes every leftover one, so an old temp is never
    /// taken back after a later write (round 3, finding 21; round 4,
    /// finding 15).
    #[test]
    fn a_write_cut_off_before_its_rename_is_taken_back() {
        let d = Dir::new();
        let (a, b) = ([0xa; 16], [0xb; 16]);
        let line = VaultLine {
            state: bare_state(),
            merged: Vec::new(),
            vkey: None,
        };
        // The very first write is cut off: no anchor, only its temp file.
        crate::vault::CRASH.with(|c| c.set(Some("tmp_synced")));
        let crashed = update(&d.0, &a, LOCK_WAIT, &mut |lines| {
            lines.vault = Some(line.clone());
            true
        });
        assert_eq!(crashed, Err(Failure::Crash));
        assert!(!d.main().exists());
        let temp = d.temps();
        assert_eq!(temp.len(), 1);
        // A read without the lock sees it, and leaves it where it is.
        assert!(d.doc().lines(&a).vault.is_some());
        assert_eq!(d.temps(), temp);
        // The next locked write takes it back first.
        d.put(&b, &line);
        assert!(d.temps().is_empty());
        let doc = d.doc();
        assert!(doc.lines(&a).vault.is_some() && doc.lines(&b).vault.is_some());
        // A later write cut off: the anchor stays as it was, and its temp
        // file is a leftover the next locked write deletes.
        let before = fs::read(d.main()).unwrap();
        let mut changed = line.clone();
        changed.state.epoch = 7;
        crate::vault::CRASH.with(|c| c.set(Some("tmp_synced")));
        assert_eq!(
            update(&d.0, &a, LOCK_WAIT, &mut |lines| {
                lines.vault = Some(changed.clone());
                true
            }),
            Err(Failure::Crash)
        );
        assert_eq!(fs::read(d.main()).unwrap(), before);
        assert_eq!(d.temps().len(), 1);
        assert_eq!(d.doc().lines(&a).vault.unwrap().state.epoch, EPOCH_MAX);
        // A locked write that changes nothing still deletes it.
        update(&d.0, &a, LOCK_WAIT, &mut |_| false).unwrap();
        assert!(d.temps().is_empty());
        // So deleting the anchor by hand forgets it: no old temp brings it
        // back.
        fs::remove_file(d.main()).unwrap();
        assert_eq!(d.doc(), Anchor::default());
        // A temp file that is not a whole anchor is never taken back.
        fs::write(
            d.0.join(format!("{NAME}.0123456789abcdef.tmp")),
            format!("{VERSION}\nvault"),
        )
        .unwrap();
        assert_eq!(d.doc(), Anchor::default());
        update(&d.0, &a, LOCK_WAIT, &mut |_| false).unwrap();
        assert!(!d.main().exists());
    }

    /// One writer at a time: two processes that write lines of two vaults
    /// at once lose neither (round 3, finding 18). A lock held past the wait
    /// is a failed write, and nothing is written.
    #[test]
    fn two_writers_lose_no_line() {
        let d = Dir::new();
        let dir = d.0.clone();
        let writers: Vec<_> = [[0x1; 16], [0x2; 16]]
            .into_iter()
            .map(|id| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    for epoch in 1..=25 {
                        update(&dir, &id, LOCK_WAIT, &mut |lines| {
                            let mut line = VaultLine {
                                state: bare_state(),
                                merged: Vec::new(),
                                vkey: None,
                            };
                            line.state.epoch = epoch;
                            lines.vault = Some(line);
                            true
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let doc = d.doc();
        for id in [[0x1; 16], [0x2; 16]] {
            assert_eq!(doc.lines(&id).vault.unwrap().state.epoch, 25);
        }
        assert!(d.temps().is_empty());
        let before = fs::read(d.main()).unwrap();
        let _held = hold_lock(&d.0);
        let start = Instant::now();
        assert_eq!(
            update(&d.0, &[3; 16], Duration::from_millis(200), &mut |_| true),
            Err(Failure::Busy)
        );
        assert!(start.elapsed() >= Duration::from_millis(200));
        assert_eq!(fs::read(d.main()).unwrap(), before);
    }

    /// A link with the anchor's name is no anchor: it reads as empty, and a
    /// write replaces the link instead of writing through it.
    #[test]
    fn a_link_is_no_anchor() {
        let d = Dir::new();
        let elsewhere = d.0.join("elsewhere.txt");
        let line = VaultLine {
            state: bare_state(),
            merged: Vec::new(),
            vkey: None,
        };
        fs::write(
            &elsewhere,
            format!("{VERSION}\n{}\n", render_vault(&[1; 16], &line)),
        )
        .unwrap();
        fs::hard_link(&elsewhere, d.main()).unwrap();
        assert_eq!(d.doc(), Anchor::default());
        let held = fs::read(&elsewhere).unwrap();
        d.put(&[2; 16], &line);
        assert_eq!(fs::read(&elsewhere).unwrap(), held);
        let doc = d.doc();
        assert!(doc.lines(&[2; 16]).vault.is_some() && doc.lines(&[1; 16]).vault.is_none());
    }

    /// A password-only key file of the vault `vid` with data keys `keys`.
    fn ke03(
        vid: [u8; 16],
        keys: &[[u8; 32]],
        epoch: u64,
        tombs: &[([u8; 16], u64)],
        pw_id: u8,
    ) -> KeyHeader {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let spec = Spec {
            vault_id: vid,
            epoch,
            kind: Kind::Password,
            next: 1,
            pw_id: [pw_id; 16],
            loss: 0,
            tombstones: tombs
                .iter()
                .map(|(credhash, removed)| Tombstone {
                    credhash: *credhash,
                    removed: *removed,
                })
                .collect(),
            resume: [0; 32],
        };
        let bundle = Bundle::new(keys, None).unwrap();
        let (bytes, _) = keyfile::seal(&spec, &bundle, "p", Plan::PasswordOnly).unwrap();
        parse(&bytes).unwrap()
    }
    fn dk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// The login comparison of spec §5.10 for password-only key files: the
    /// same state, a later one that holds the confirmed key, one that does
    /// not (a fork, S23-3 #1), one far ahead, an older state of this PC
    /// (a rollback) and any other older or same-epoch one (a fork), one that
    /// lacks a removal this PC recorded, and any password-only key file of a
    /// vault this PC opened with security keys.
    #[test]
    fn key_files_compare_with_the_confirmed_line() {
        let vid = [0x77; 16];
        let k3 = ke03(vid, &[dk(3), dk(0)], 3, &[], 3);
        let k5 = ke03(vid, &[dk(5), dk(3), dk(0)], 5, &[], 5);
        let l3 = line_of(&k3, None);
        let l5 = line_of(&k5, Some(&l3));
        assert_eq!(l5.state.hist.len(), 2);
        assert_eq!(compare(&k5, None), Ok(AnchorClass::New));
        assert_eq!(compare(&k5, Some(&l5)), Ok(AnchorClass::Equal));
        // Another PC changed the password on top of this PC's state.
        let k6 = ke03(vid, &[dk(6), dk(5), dk(3), dk(0)], 6, &[], 6);
        assert_eq!(compare(&k6, Some(&l5)), Ok(AnchorClass::Newer));
        // An old key file re-sealed one epoch above under a key of its own
        // choice: it lacks the confirmed key.
        let k6x = ke03(vid, &[dk(0x66), dk(3), dk(0)], 6, &[], 6);
        assert_eq!(compare(&k6x, Some(&l5)), Err(Refusal::Fork));
        let far = ke03(vid, &[dk(9), dk(5), dk(0)], 5 + EPOCH_WINDOW + 1, &[], 9);
        assert_eq!(
            compare(&far, Some(&l5)),
            Err(Refusal::TooFar {
                old: 5,
                new: 5 + EPOCH_WINDOW + 1
            })
        );
        let near = ke03(vid, &[dk(9), dk(5), dk(0)], 5 + EPOCH_WINDOW, &[], 9);
        // More than EPOCH_SILENT above the last state this PC wrote: the
        // security-key build gates it with G1, the default build takes it.
        #[cfg(not(feature = "security-key"))]
        assert_eq!(compare(&near, Some(&l5)), Ok(AnchorClass::Newer));
        #[cfg(feature = "security-key")]
        assert_eq!(
            compare(&near, Some(&l5)),
            Ok(AnchorClass::Gated(super::super::gate::GateKind::G1))
        );
        // An older state of this PC put back, and another one.
        assert_eq!(compare(&k3, Some(&l5)), Ok(AnchorClass::Rollback));
        let k3x = ke03(vid, &[dk(0x33), dk(0)], 3, &[], 0x33);
        assert_eq!(compare(&k3x, Some(&l5)), Err(Refusal::Fork));
        let k5x = ke03(vid, &[dk(0x55), dk(3), dk(0)], 5, &[], 0x55);
        assert_eq!(compare(&k5x, Some(&l5)), Err(Refusal::Fork));
        // A removal recorded here, missing from the key file.
        let k7t = ke03(vid, &[dk(7), dk(5), dk(0)], 7, &[([0x99; 16], 6)], 7);
        let l7 = line_of(&k7t, Some(&l5));
        assert_eq!(l7.state.tombs[0].keyid, k7t.current_key_id());
        assert_eq!(l7.state.tombs[0].origin, Origin::Taken);
        let k8 = ke03(vid, &[dk(8), dk(7), dk(5), dk(0)], 8, &[], 8);
        assert_eq!(compare(&k8, Some(&l7)), Err(Refusal::Relist));
        // An older state of this PC that predates the removal is a rollback.
        assert_eq!(compare(&k5, Some(&l7)), Ok(AnchorClass::Rollback));
        // A later file with removals this PC never knew: a silent update in
        // the default build, G1 in the security-key build (T_new).
        let k8t = ke03(
            vid,
            &[dk(8), dk(7), dk(0)],
            8,
            &[([0x99; 16], 6), ([0x98; 16], 8)],
            8,
        );
        #[cfg(not(feature = "security-key"))]
        assert_eq!(compare(&k8t, Some(&l7)), Ok(AnchorClass::Newer));
        #[cfg(feature = "security-key")]
        assert_eq!(
            compare(&k8t, Some(&l7)),
            Ok(AnchorClass::Gated(super::super::gate::GateKind::G1))
        );
        // Pinned as hardware.
        let mut hw = l5.clone();
        hw.state.magic = *b"GOYOKS01";
        assert_eq!(compare(&k6, Some(&hw)), Err(Refusal::Downgrade));
        assert_eq!(compare_legacy(Some(&hw)), Err(Refusal::Downgrade));
        // A 0.8 key file: decided once it opens when this PC had a 0.8
        // state, else at once.
        assert_eq!(compare_legacy(None), Ok(AnchorClass::New));
        assert_eq!(compare_legacy(Some(&l5)), Err(Refusal::Fork));
        assert_eq!(compare_legacy(Some(&l7)), Err(Refusal::Relist));
        let legacy = KeyState {
            epoch: 0,
            tag: [0x0e; 16],
        };
        let mut converted = l5.clone();
        converted.state.hist.push(legacy_hist(legacy, &[0; 16]));
        assert_eq!(compare_legacy(Some(&converted)), Ok(AnchorClass::Legacy));
        assert_eq!(
            compare_opened_legacy(legacy, &converted),
            Ok(AnchorClass::Rollback)
        );
        let other = KeyState {
            epoch: 0,
            tag: [0x0f; 16],
        };
        assert_eq!(compare_opened_legacy(other, &converted), Err(Refusal::Fork));
        let back = legacy_line(
            legacy,
            keyfile::Magic::Ke02,
            false,
            &[0; 16],
            Some(&converted),
        );
        assert_eq!(compare_opened_legacy(legacy, &back), Ok(AnchorClass::Equal));
        assert_eq!(back.state.hist[0], legacy_hist(legacy, &[0; 16]));
        assert_eq!(back.state.hist.len(), converted.state.hist.len());
    }

    /// This PC's own pending write is recognized when the key file is its
    /// state, or a key file written on top of it (spec §5.1 step 9): a later
    /// epoch that holds its current key and keeps its removals. A write that
    /// kept the data key shows only through what it changed (round 4,
    /// finding 9).
    #[test]
    fn a_pending_write_is_recognized_when_it_landed_or_is_built_on() {
        let vid = [0x78; 16];
        let k5 = ke03(vid, &[dk(5), dk(0)], 5, &[([0x91; 16], 2)], 5);
        let l5 = line_of(&k5, None);
        let k6 = ke03(vid, &[dk(6), dk(5), dk(0)], 6, &[([0x91; 16], 2)], 6);
        let p = pending_of(&k6, Some(&l5), None, kpath_of(Path::new(r"C:\k.goyokey")));
        assert_eq!(p.base, Some((5, k5.tag)));
        assert_eq!(p.state.gated, 6);
        assert_eq!(p.pw, Some(Pw::New));
        assert!(landed(&k6, &p) && !descends(&k6, &p, Some(&l5)));
        let k7 = ke03(vid, &[dk(7), dk(6), dk(5), dk(0)], 7, &[([0x91; 16], 2)], 7);
        assert!(!landed(&k7, &p) && descends(&k7, &p, Some(&l5)));
        // Written on the old state instead: it lacks the pending key.
        let k7x = ke03(vid, &[dk(0x17), dk(5), dk(0)], 7, &[([0x91; 16], 2)], 7);
        assert!(!descends(&k7x, &p, Some(&l5)));
        // It dropped a removal the pending state carries.
        let k7r = ke03(vid, &[dk(7), dk(6), dk(5), dk(0)], 7, &[], 7);
        assert!(!descends(&k7r, &p, Some(&l5)));
        // A write that kept the data key and changed nothing a line records.
        let mut kept = p.clone();
        kept.state.keyid = l5.state.keyid;
        assert!(!descends(&k7, &kept, Some(&l5)));
        // The line it becomes: this state first, the confirmed one's after.
        let line = p.promoted(Some(&l5));
        assert_eq!(line.state.hist[0], hist_of(&k6));
        assert_eq!(line.state.hist[1], l5.state.hist[0]);
        assert_eq!(line.state.keyid, k6.current_key_id());
        // A 0.8 state converted: kept as the oldest one.
        let legacy = legacy_hist(
            KeyState {
                epoch: 0,
                tag: [1; 16],
            },
            &[2; 16],
        );
        let first = pending_of(&k6, None, Some(legacy), None);
        assert_eq!(first.state.hist, [hist_of(&k6), legacy]);
        assert_eq!(first.base, None);
    }

    /// The two grammars of stage 6 that every build reads, writes back and
    /// keeps (S6R2 #13): `sup` entries as `<keyid>.<epoch>.<tag>` and `ks`
    /// in each of its forms, at their places before `keyid`, in `vault` and
    /// `pending` lines alike; a line without `ks` reads `-`; the bare key ID
    /// and every other form is malformed; and every line this PC takes over
    /// or writes (`line_of`, `pending_of`, `legacy_line`, a promotion)
    /// carries the old line's values on.
    #[test]
    fn sup_and_ks_round_trip_and_are_kept() {
        let id = [0x5e; 16];
        let forms = [
            (Ks::None, "-"),
            (Ks::On(0), "on.0"),
            (Ks::On(41), "on.41"),
            (Ks::Off(u64::MAX), "off.18446744073709551615"),
            (Ks::OffUnknown, "off.?"),
        ];
        for (ks, form) in forms {
            let mut state = full_state();
            state.ks = ks;
            let vault = VaultLine {
                state: state.clone(),
                merged: Vec::new(),
                vkey: None,
            };
            let text = render_vault(&id, &vault);
            let sup = format!(
                " sup={}.9.{},{}.{EPOCH_MAX}.{} ks={form} keyid=",
                "0d".repeat(16),
                "d3".repeat(16),
                "13".repeat(16),
                "00".repeat(16)
            );
            assert!(text.contains(&sup), "{text}");
            assert_eq!(parsed(&text), Some(Line::Vault(id, Box::new(vault))));
            let pending = PendingLine {
                state,
                ..full_pending()
            };
            let text = render_pending(&id, &pending);
            assert!(text.contains(&format!(" ks={form} keyid=")), "{text}");
            assert_eq!(parsed(&text), Some(Line::Pending(id, Box::new(pending))));
        }
        // Without `ks`: `-`. Every other form, the bare key ID of 308909f,
        // a fourth part, an epoch above EPOCH_MAX and `ks` out of its place
        // are malformed.
        let text = render_vault(
            &id,
            &VaultLine {
                state: full_state(),
                merged: Vec::new(),
                vkey: None,
            },
        );
        let without = text.replace(" ks=off.7", "");
        assert!(matches!(parsed(&without), Some(Line::Vault(_, v)) if v.state.ks == Ks::None));
        let keyid = format!(" keyid={}", "0e".repeat(16));
        let first = format!("{}.9.{}", "0d".repeat(16), "d3".repeat(16));
        for bad in [
            text.replace("ks=off.7", "ks=off"),
            text.replace("ks=off.7", "ks=off."),
            text.replace("ks=off.7", "ks=off.07"),
            text.replace("ks=off.7", "ks=on.?"),
            text.replace("ks=off.7", "ks=off.?1"),
            text.replace("ks=off.7", "ks=up.7"),
            text.replace("ks=off.7", "ks=OFF.7"),
            text.replace("ks=off.7", "ks="),
            text.replace(" ks=off.7", "")
                .replace(&keyid, &format!("{keyid} ks=off.7")),
            text.replace(&first, &"0d".repeat(16)),
            text.replace(&first, &format!("{first}.1")),
            text.replace(&first, &format!("{}.9", "0d".repeat(16))),
            text.replace(
                &first,
                &first.replace(".9.", &format!(".{}.", EPOCH_MAX + 1)),
            ),
            text.replace(&first, &first.replace(".9.", ".09.")),
        ] {
            assert_ne!(bad, text);
            assert_eq!(parsed(&bad), None, "{bad}");
        }
        // Kept by every line this PC writes over the old one.
        let vid = [0x79; 16];
        let k5 = ke03(vid, &[dk(5), dk(0)], 5, &[], 5);
        let mut l5 = line_of(&k5, None);
        assert_eq!((l5.state.sup.as_slice(), l5.state.ks), (&[][..], Ks::None));
        l5.state.sup = full_state().sup;
        l5.state.ks = Ks::On(3);
        let k6 = ke03(vid, &[dk(6), dk(5), dk(0)], 6, &[], 6);
        let l6 = line_of(&k6, Some(&l5));
        assert_eq!((&l6.state.sup, l6.state.ks), (&l5.state.sup, Ks::On(3)));
        let p = pending_of(&k6, Some(&l5), None, None);
        assert_eq!((&p.state.sup, p.state.ks), (&l5.state.sup, Ks::On(3)));
        let promoted = p.promoted(Some(&l5));
        assert_eq!(
            (&promoted.state.sup, promoted.state.ks),
            (&l5.state.sup, Ks::On(3))
        );
        let legacy = KeyState {
            epoch: 0,
            tag: [0x0e; 16],
        };
        let back = legacy_line(legacy, keyfile::Magic::Ke02, false, &[0; 16], Some(&l5));
        assert_eq!((&back.state.sup, back.state.ks), (&l5.state.sup, Ks::On(3)));
    }

    /// `auto` (spec §2.30), a local preference every build reads, writes
    /// back and keeps: `auto=on` after `ks` in `vault` and `pending` lines,
    /// no field when off (a line without it is off), any other value or
    /// place malformed; and every line this PC takes over or writes
    /// (`line_of`, `pending_of`, `legacy_line`, a promotion) carries it on,
    /// through a whole anchor file and back.
    #[test]
    fn auto_round_trips_and_is_kept() {
        let id = [0x5f; 16];
        for auto in [false, true] {
            let mut state = full_state();
            state.auto = auto;
            let vault = VaultLine {
                state: state.clone(),
                merged: Vec::new(),
                vkey: None,
            };
            let text = render_vault(&id, &vault);
            assert_eq!(text.contains(" ks=off.7 auto=on keyid="), auto, "{text}");
            assert_eq!(text.contains(" ks=off.7 keyid="), !auto, "{text}");
            assert_eq!(parsed(&text), Some(Line::Vault(id, Box::new(vault))));
            let pending = PendingLine {
                state,
                ..full_pending()
            };
            let text = render_pending(&id, &pending);
            assert_eq!(text.contains(" auto=on keyid="), auto, "{text}");
            assert_eq!(parsed(&text), Some(Line::Pending(id, Box::new(pending))));
        }
        let mut state = full_state();
        state.auto = true;
        let line = VaultLine {
            state,
            merged: Vec::new(),
            vkey: None,
        };
        let text = render_vault(&id, &line);
        let keyid = format!(" keyid={}", "0e".repeat(16));
        for bad in [
            text.replace("auto=on", "auto=off"),
            text.replace("auto=on", "auto="),
            text.replace("auto=on", "auto=ON"),
            text.replace("auto=on", "auto=1"),
            text.replace(" auto=on", "")
                .replace(&keyid, &format!("{keyid} auto=on")),
            text.replace(" ks=off.7 auto=on", " auto=on ks=off.7"),
        ] {
            assert_ne!(bad, text);
            assert_eq!(parsed(&bad), None, "{bad}");
        }
        // Through the file: rendered, read back and kept by a write that
        // changes another vault's lines.
        let t = Dir::new();
        t.put(&id, &line);
        let other = [0x60; 16];
        update(&t.0, &other, LOCK_WAIT, &mut |lines| {
            lines.vault = Some(VaultLine {
                state: bare_state(),
                merged: Vec::new(),
                vkey: None,
            });
            true
        })
        .unwrap();
        assert_eq!(t.doc().lines(&id).vault, Some(line));
        // Kept by every line this PC writes over the old one.
        let vid = [0x7a; 16];
        let k5 = ke03(vid, &[dk(5), dk(0)], 5, &[], 5);
        let mut l5 = line_of(&k5, None);
        assert!(!l5.state.auto);
        l5.state.auto = true;
        let k6 = ke03(vid, &[dk(6), dk(5), dk(0)], 6, &[], 6);
        assert!(line_of(&k6, Some(&l5)).state.auto);
        let p = pending_of(&k6, Some(&l5), None, None);
        assert!(p.state.auto && p.promoted(Some(&l5)).state.auto);
        let legacy = KeyState {
            epoch: 0,
            tag: [0x0e; 16],
        };
        let back = legacy_line(legacy, keyfile::Magic::Ke02, false, &[0; 16], Some(&l5));
        assert!(back.state.auto);
    }
}
