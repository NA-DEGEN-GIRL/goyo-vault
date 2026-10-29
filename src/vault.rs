//! Versioned authenticated file formats; no plaintext files, no automatic key lookup.
use crate::{
    crypto::{self, AUTH_ERROR, Key, Result},
    otp,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

mod anchor;
#[cfg(feature = "security-key")]
mod gate;
pub mod keyfile;
mod recover;
#[cfg(feature = "security-key")]
mod review;
mod rotate;
mod sync;
#[cfg(debug_assertions)]
pub use anchor::set_anchor_dir;
pub use anchor::{
    ANCHOR_DOWNGRADE, ANCHOR_EPOCH, ANCHOR_FORK, ANCHOR_FORK_VAULT, ANCHOR_NEWER, ANCHOR_RELIST,
    AnchorClass, SIDECAR_FAILED,
};
use anchor::{Decision, Refusal, Seen};
#[cfg(feature = "security-key")]
pub use gate::{
    ANCHOR_OTP, ANCHOR_PINNED, ANCHOR_RELIST_KEYS, Checked, GATE_CODE_WRONG, GATE_G2FAIL,
    GATE_G2FAIL_DISK, GATE_HELD, GATE_NOT_PENDING, GateAnswer, GateChoice, GateKind, Gates,
    TOFU_ADOPT, TOFU_HELD, parse_code,
};
use keyfile::{
    Bundle, EPOCH_LIMIT, EPOCH_MAX, EPOCH_SILENT, KEY_FILE_LIMIT, KeyFile, KeyState, Magic,
    NEWER_KEY_FORMAT, NO_SECURITY_KEY_SUPPORT, NO_SECURITY_KEY_SUPPORT_DAMAGED, Touch, encode_key,
};
pub use keyfile::{KeyInfo, key_info};
pub use recover::Recovery;
#[cfg(feature = "security-key")]
pub use review::{ReviewChange, ReviewList, ReviewRow, day_of, shown_time};
pub use rotate::{
    ADOPT_CONTAINED, ADOPT_EQUAL, ADOPT_OLDER, ADOPT_REFUSED, ADOPT_ROLLBACK, Acks, AdoptCheck,
    AdoptClass, AdoptPlan, Adopted, Change, Consent, Gate, GatePass, KEY_DAMAGED,
    KEY_DAMAGED_LOCKED, KEY_NOT_SAVED, KEYTEMP, KEYTEMP_GONE, LostKeyAddOn, NOT_THIS_VAULT,
    NOTHING_HELD, OVERRIDE_HEAD, OtherOpened, PassInForce, Preview, REAUTH_MAX, Reauth, Rekeyed,
    SAMEPASS, Source, UnionPassword, VPENDING,
};
#[cfg(feature = "security-key")]
pub use rotate::{
    ANCHOR_FAILED, Exposure, ForkOption, KEYSOFF_SYNCED, KeyGates, KeyRow, KeysOverview,
    LossReport, NOT_PLANNED, OLDSLOT, REACH_CHANGED, REMOVE_UNDONE, REPAIR_AUTH, ReSeedKey,
    ReSeedPlan, Redo, RedoFlow, UNION_FULL, UNREACHABLE,
};
pub use sync::{HaltedHead, SyncBadge, SyncEvent, SyncNotice};

/// A vault without sync; 0.7.x and older read only this.
const DATA_MAGIC_V1: &[u8; 8] = b"GOYOVA01";
/// A vault with sync: entry IDs, tombstones and the sync counters as well.
const DATA_MAGIC_V2: &[u8; 8] = b"GOYOVA02";
/// GOYOVA01's contents under a KF2 key file (spec §4.3): the header also
/// names the data key that sealed the file and the writer's key-file state.
const DATA_MAGIC_V3: &[u8; 8] = b"GOYOVA03";
/// GOYOVA02's contents under a KF2 key file.
const DATA_MAGIC_V4: &[u8; 8] = b"GOYOVA04";
/// What a GOYOVA01/02 file adds to its plaintext: magic, vault ID, nonce
/// and the tag.
pub(crate) const LEGACY_OVERHEAD: usize = 64;
/// The same for GOYOVA03/04, whose header also holds the key ID, the epoch,
/// the state tag and the flags.
pub(crate) const KEYED_OVERHEAD: usize = 108;
pub const MAX_FILE: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1000;
pub const MAX_TEXT: usize = 8192;
/// Deleted and replaced IDs a vault remembers (1 MiB in v2). Forgetting one
/// would let an old copy bring its entry back, so there is no compaction.
pub const MAX_TOMBSTONES: usize = 65_536;
const NEWER_FORMAT: &str = "더 새로운 버전에서 만든 금고 형식입니다. 고요 금고를 업데이트하세요.";
const TOMBSTONE_LIMIT: &str = "삭제·수정 기록이 한도(65,536개)에 도달했습니다.";
const TOO_LARGE: &str = "파일 크기 제한 초과";
/// A file is missing and a temp file of it is there that no unlock took
/// back: only the user can tell what it holds.
pub const LEFTOVER_TEMP: &str = "파일이 없고, 저장이 끊기며 남은 임시 파일(.goyotmp)이 같은 폴더에 있습니다. 지우지 마세요. 그 파일 이름을 원래 이름으로 바꾸면 복구될 수 있습니다.";
/// The text of GAP_KEPT, for messages that add a line to it.
macro_rules! gap_kept {
    () => {
        "파일 교체가 끊겨 임시 파일(.goyotmp)을 남겼습니다. 다음에 열 때 자동으로 복구합니다."
    };
}
/// A vault or key file save whose replace was cut off (see atomic_write):
/// the file is gone and its temp file holds the new state. The app locks,
/// so that the next unlock takes it back.
pub const GAP_KEPT: &str = gap_kept!();
/// GAP_KEPT after a key change whose first vault file write hit the gap: the
/// key did not change (S-GAP-NOTCHANGED).
pub const GAP_NOT_CHANGED: &str = concat!(
    gap_kept!(),
    "\r\n",
    "열쇠는 바꾸지 않았습니다. 지금까지 쓰던 비밀번호로 다시 여세요."
);
/// GAP_KEPT after a key change whose last vault file write hit the gap: the
/// new key file is in place (S-GAP-CHANGED).
pub const GAP_CHANGED: &str = concat!(
    gap_kept!(),
    "\r\n",
    "열쇠 변경은 저장되었습니다. 다음에 열 때는 바뀐 열쇠 파일의 비밀번호로 여세요(비밀번호를 바꿨다면 새 비밀번호입니다). 연 뒤 '열쇠 백업'을 하세요."
);
/// The vault file's key is not in the key file (spec §5.1 step 4).
pub const KEY_NOT_IN_KEY_FILE: &str = "이 금고 파일은 이 열쇠 파일에 없는 열쇠로 저장되어 있습니다. 이 금고를 마지막으로 연 열쇠 파일을 선택하세요. 다른 PC에서 열쇠를 바꿨다면 이 PC의 원래 열쇠 파일로 연 뒤 '열쇠 관리 › 새 열쇠 파일 받기'로 새 열쇠 파일을 받으세요.";
/// The same for a Restore: the backup's key aged out of the key file.
pub const KEY_NOT_IN_BACKUP: &str = "이 백업은 이 열쇠 파일에 없는 열쇠로 잠겨 있습니다. 그 백업을 만들 때의 열쇠 파일 사본으로 복원하세요.";
/// A vault file whose key the key file lacks, and whose header says a
/// security-key file wrote it (spec §4.7): this build cannot have one.
pub const NO_SECURITY_KEY_SUPPORT_VAULT: &str = "이 금고 파일은 보안 키로 잠긴 열쇠 파일로 저장되었습니다. 이 고요 금고 빌드에는 보안 키 기능이 없어 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다.";
/// A GOYOVA03/04 header the grammar refuses (spec §4.3), before any key
/// derivation.
pub const VAULT_DAMAGED: &str = "금고 파일의 머리글이 손상되어 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다. 백업에서 복원하거나 서버 기록을 확인하세요.";
/// The key file and the vault file state different vault IDs.
pub const OTHER_VAULT: &str = "열쇠 파일과 금고 파일이 서로 다른 금고의 것입니다.";
/// The 8 MiB limit, which a vault file and a merge result must fit.
const VAULT_FULL: &str = "금고 용량 제한(8 MiB)을 초과했습니다.";
/// A key backup that did not read back as written.
const BACKUP_NOT_VERIFIED: &str =
    "열쇠 백업을 다시 읽어 확인하지 못했습니다. 다른 저장장치에 다시 백업하세요.";
/// An unlock or Restore that must save the vault file again under the key
/// file's format, whose header is 44 bytes longer than 0.8's (spec §4.3),
/// where the contents do not fit any more: nothing is written, and the
/// password was right.
pub const RESAVE_TOO_LARGE: &str = "이 금고 파일은 이 열쇠 파일의 형식으로 다시 저장하면 용량 제한(8 MiB)을 넘어 열지 않았습니다. 비밀번호가 틀린 것이 아닙니다. 이 금고의 예전 열쇠 파일(0.8 형식)이 있으면 그것으로 열어 항목을 줄인 뒤 다시 여세요.";
/// An older-key vault file that changed after the user agreed to open it,
/// or one opened with no agreement at all (spec §5.2 step 4).
pub const OLDER_NOT_CONFIRMED: &str = "확인한 뒤에 금고 파일이 바뀌어 열지 않았습니다. 다시 열어 보세요. 그런 일이 없었다면 누군가 금고 파일을 바꿔 넣었을 수 있으니 백업이나 서버 기록을 확인하세요.";
/// KEY_NOT_IN_KEY_FILE for a vault file whose header names a later key-file
/// state than this key file's: another PC changed the key of a vault file
/// both open (spec §5.1 step 4), filled with the two epochs.
pub const KEY_NOT_IN_KEY_FILE_NEWER: &str = concat!(
    "이 금고 파일은 다른 PC에서 바꾼 새 열쇠 파일(수정 {V.epoch})로 저장되어 있어 이 열쇠 파일(수정 {K.epoch})로는 열리지 않습니다.",
    "\r\n",
    "금고 파일을 여러 PC가 함께 쓰고 열쇠 파일은 PC마다 따로 두었다면, 열쇠를 바꾼 PC의 새 열쇠 파일을 USB로 가져와 그 파일로 여세요. 이 PC에서 따로 열쇠를 바꾼 적이 없다면 그 파일을 이 PC의 열쇠 파일 자리에 두어도 됩니다. 그 새 열쇠 파일이 어디에도 없다면 열쇠를 바꾼 PC의 열쇠 백업이 필요합니다."
);
/// An older-key vault file under another key than the one this PC last used
/// (spec §5.1 step 6): refused before any key derivation.
pub const OLDER_REFUSED: &str = "이 금고 파일은 이 PC가 마지막으로 쓴 열쇠가 아닌 예전 열쇠로 저장되어 있어 열지 않았습니다. 예전 열쇠 사본을 가진 누군가가 금고 파일을 바꿔 넣었을 수 있습니다. 예전 백업을 되살리려는 것이라면 '복원'으로 새 파일에 복원하세요. 그런 일이 없었다면 이 금고 파일을 최근 백업이나 서버 기록과 비교하세요.";
/// An older-key vault file whose counters an honest vault never reaches
/// (spec §5.2 step 5): nothing is written.
pub const VAULT_COUNTERS: &str = "이 금고 파일은 예전 열쇠로 저장되어 있고 저장 횟수 기록이 비정상적으로 커서 열지 않았습니다. 손상되었거나 예전 열쇠 사본을 가진 누군가가 만든 파일일 수 있습니다. 비밀번호가 틀린 것이 아닙니다. 다른 백업이나 서버 기록을 확인하세요.";
/// The highest `generation` and `seen` an older-key vault file may state:
/// an honest vault gains at most one per edit or merge (spec §5.2 step 5).
pub(crate) const GEN_CEILING: u64 = 1 << 40;
/// S-NOTFINISHED: a key change of this PC that never landed was dropped.
pub const NOT_FINISHED: &str =
    "지난 열쇠 변경이 끝나지 않아 예전 열쇠로 열었습니다. 다시 바꾸려면 '열쇠 관리'를 쓰세요.";
/// AUTH_ERROR when this PC's own key change never landed and the key file is
/// still the one it confirmed (spec §5.12, S-HINT-INTERRUPTED).
pub const AUTH_HINT_INTERRUPTED: &str = concat!(
    crypto::auth_error!(),
    "\r\n",
    "열쇠 변경이 중간에 끊긴 흔적이 있습니다. 예전 비밀번호(와 보안 키)로 열어 보세요."
);
/// AUTH_ERROR when the key file is this PC's own change that landed: with
/// the password it set (S-HINT-LANDED-NEW), the other file's it took
/// (S-HINT-LANDED-OTHER), or another PC's set on top of it
/// (S-HINT-LANDED-LATER).
pub const AUTH_LANDED_NEW: &str = concat!(
    crypto::auth_error!(),
    "\r\n",
    "이 PC에서 한 열쇠 변경은 저장되었습니다. 새로 정한 비밀번호로 여세요."
);
pub const AUTH_LANDED_OTHER: &str = concat!(
    crypto::auth_error!(),
    "\r\n",
    "이 PC에서 받은 열쇠 파일은 저장되었습니다. 그 열쇠 파일의 비밀번호(다른 PC에서 정한 비밀번호)로 여세요."
);
pub const AUTH_LANDED_LATER: &str = concat!(
    crypto::auth_error!(),
    "\r\n",
    "이 PC에서 한 열쇠 변경 뒤에 다른 PC가 이 열쇠 파일을 다시 바꿨습니다. 그 PC에서 정한 비밀번호로 여세요."
);
/// Rule (i)'s failure text for a key file that is only a temp file at or
/// above this PC's confirmed state: the change almost finished, and only
/// the new factors open it (spec §5.12).
pub const CHANGE_DONE_NEWPASS: &str = "열쇠 변경이 거의 끝난 상태로 열쇠 파일이 임시 파일로 남았습니다. 새 비밀번호(와 보안 키)로 여세요. 예전 비밀번호로 열려면 예전 열쇠 파일 백업이 필요합니다.";
/// S-LOCAL-ROLLBACK, filled with the confirmed epoch and the key file's.
pub const LOCAL_ROLLBACK: &str = "이 열쇠 파일은 이 고요 금고가 전에 본 것(수정 {old})보다 오래되었습니다(수정 {new}). 직접 예전 백업으로 되돌렸거나, 같은 고요 금고 폴더를 다른 PC와 함께 쓰는데 그 PC에서 바꾼 새 열쇠 파일을 아직 받지 않은 경우라면 정상입니다(뒤의 경우 '새 열쇠 파일 받기'를 하세요). 그런 일이 없었다면 누군가 예전 열쇠 파일과 금고 파일로 바꿔 놓았을 수 있으니 백업을 확인하세요.";
/// S-RESTORE-OLDKEY, filled with the confirmed epoch and the key file's.
pub const RESTORE_OLDKEY: &str = "이 PC가 마지막으로 본 열쇠 파일(수정 {old})과 다른 열쇠 파일(수정 {new})로 복원했습니다. 복원한 금고에서는 열쇠를 바꾸거나 새 열쇠 파일을 받거나 서버에 올리거나 서버 사본을 합치지 않습니다. 필요한 항목을 확인하는 데 쓰세요.";
/// Every Restore: a key change or adopt there would rotate the key file
/// that the live vault file shares, which would then open only through
/// Restore (spec §2.18 #54).
pub const RESTORE_KEYS: &str = "복원한 금고에서는 열쇠를 바꾸거나 새 열쇠 파일을 받지 않습니다. 바꾸면 같은 열쇠 파일을 쓰는 다른 금고 파일은 '복원'으로만 열립니다. 복원한 파일을 계속 쓰려면 잠근 뒤 로그인으로 여세요.";
/// The anchor under its lock is not what the precheck compared the key file
/// with (it could not be read then, or another process wrote it since): the
/// unlock does not stand on that comparison (spec §2.18 #60).
pub const ANCHOR_REREAD: &str = "이 PC의 열쇠 기록(goyo-vault.keys)을 처음에 읽지 못했거나 여는 동안 바뀌어 열지 않았습니다. 다시 여세요.";
/// S-RESTORE-PENDING: a key change of this PC waits for a login.
pub const RESTORE_PENDING: &str = "이 PC에서 하던 열쇠 변경이 아직 끝나지 않았습니다. 원래 금고 파일을 그 열쇠 파일로 다시 열면 마저 끝납니다. 그때까지 복원한 금고에서는 열쇠를 바꾸거나 새 열쇠 파일을 받거나 서버에 올리거나 서버 사본을 합치지 않습니다. 필요한 항목을 확인하는 데 쓰세요.";
/// S-PENDING-ELSEWHERE, filled with the key file's path.
pub const PENDING_ELSEWHERE: &str = "이 PC에서 하던 열쇠 변경이 다른 열쇠 파일({path})에 저장되었을 수 있는데, 그 파일을 읽지 못했습니다. 그 열쇠 파일로 열면 마저 끝납니다. 그때까지 이 PC에서는 열쇠를 바꾸거나 새 열쇠 파일을 받지 않습니다. 그 파일을 잃어버렸거나 더 쓸 수 없다면 '열쇠 관리'에서 [끝나지 않은 열쇠 변경 버리기…]를 누르세요.";
/// S-PENDING-DISCARD, filled with the key file's path (danger, default No).
pub const PENDING_DISCARD: &str = "이 PC에서 하던 열쇠 변경이 {path}에 저장되었는지 확인하지 않고 그 기록을 버립니다. 그 열쇠 파일을 잃어버렸거나 더 쓸 수 없을 때만 계속하세요. 나중에 그 파일을 다시 찾으면 이 PC의 것으로 알아보지 못하고 다른 열쇠 파일처럼 다룹니다(갈라졌다면 '새 열쇠 파일 받기'로 합치세요). 계속할까요?";
/// S-PENDING-DISCARDED.
pub const PENDING_DISCARDED: &str = "끝나지 않은 열쇠 변경 기록을 버렸습니다. 이제 이 PC에서 열쇠를 바꾸거나 새 열쇠 파일을 받을 수 있습니다.";
/// S-KEYBACKUP-DUE: no key backup of this KF2 key file yet.
pub const KEYBACKUP_DUE: &str = "이 열쇠 파일은 아직 '열쇠 백업'으로 백업하지 않았습니다. 열쇠 파일을 잃으면 비밀번호가 있어도 열 수 없습니다.";
/// S-LOCAL-OK-CONFIRM, filled with the confirmed epoch and the key file's
/// (danger, default No).
pub const LOCAL_OK_CONFIRM: &str = "이 PC가 마지막으로 본 열쇠 파일(수정 {old}) 대신 지금 열쇠 파일(수정 {new})을 이 금고의 열쇠 파일로 정합니다. 직접 예전 열쇠 파일로 되돌린 것이 맞을 때만 계속하세요. 그 뒤로 이 PC는 수정 {new}보다 나중의 열쇠 변경을 기억하지 않습니다. 계속할까요?";
/// The same for a vault that syncs: the server copy this PC wrote with the
/// newer key file then halts sync, and only the head override replaces it
/// (spec §2.18 #57).
pub const LOCAL_OK_CONFIRM_SYNCED: &str = "이 PC가 마지막으로 본 열쇠 파일(수정 {old}) 대신 지금 열쇠 파일(수정 {new})을 이 금고의 열쇠 파일로 정합니다. 직접 예전 열쇠 파일로 되돌린 것이 맞을 때만 계속하세요. 그 뒤로 이 PC는 수정 {new}보다 나중의 열쇠 변경을 기억하지 않습니다.\n서버 사본이 더 나중의 열쇠로 저장되어 있으면 그 뒤 동기화가 멈춥니다. 그 사본을 이 PC가 올렸다면 '열쇠 관리'에서 [서버 사본을 이 PC 상태로 덮어쓰기…]를 누르세요.\n계속할까요?";
thread_local! {
    /// The last refusal with `{…}` slots this thread got, and their values.
    static FILLED: std::cell::RefCell<Option<(&'static str, Vec<String>)>> =
        const { std::cell::RefCell::new(None) };
}
/// Returns `text` and keeps `values` for its `{…}` slots (see
/// refusal_values); the app's flows fill their own refusals this way.
pub fn refuse(text: &'static str, values: Vec<String>) -> &'static str {
    FILLED.with(|f| *f.borrow_mut() = Some((text, values)));
    text
}
/// The values for the `{…}` slots of `text`, a refusal this thread got last
/// from this module, in order; None for any other text.
pub fn refusal_values(text: &str) -> Option<Vec<String>> {
    FILLED.with(|f| {
        f.borrow()
            .as_ref()
            .filter(|(t, _)| *t == text)
            .map(|(_, values)| values.clone())
    })
}

/// Identifies one version of an entry across copies of a vault. Random for
/// new and edited entries, derived for v1 entries (`v1_ids`); never zero.
pub type EntryId = [u8; 16];
/// The parent of an entry that replaced nothing; never a stored ID.
const NO_ID: EntryId = [0; 16];

/// The layout of a vault file's contents. The header (`Header`) decides
/// between GOYOVA01/02 and GOYOVA03/04, which hold the same contents.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// GOYOVA01 or GOYOVA03: the OTP watermark and the entries.
    V1,
    /// GOYOVA02 or GOYOVA04: written only once the user turns sync on for
    /// the vault.
    V2,
}
/// The plaintext header of a vault file (spec §4.3, §6), authenticated as
/// the AAD once the file opens. Before that it only names the key to look
/// up (spec §4.5) and words a refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Header {
    /// GOYOVA01/02, under a 0.8 key file: sealed with the ID key, no state.
    Legacy,
    /// GOYOVA03/04, under a KF2 key file.
    Keyed {
        /// The data key that sealed the file.
        key_id: [u8; 16],
        /// The writer's own key-file state, never merged from other copies.
        state: KeyState,
        /// Bit0: the writer's key file needs a security key; bit1: it is
        /// GOYOKS01.
        flags: u8,
    },
}
impl Header {
    /// The bytes the AEAD authenticates: the header up to the nonce.
    fn len(&self) -> usize {
        match self {
            Self::Legacy => LEGACY_OVERHEAD - 16,
            Self::Keyed { .. } => KEYED_OVERHEAD - 16,
        }
    }
    /// What a file with this header adds to its plaintext.
    pub(crate) fn overhead(&self) -> usize {
        self.len() + 16
    }
    fn magic(&self, format: Format) -> &'static [u8; 8] {
        match (self, format) {
            (Self::Legacy, Format::V1) => DATA_MAGIC_V1,
            (Self::Legacy, Format::V2) => DATA_MAGIC_V2,
            (Self::Keyed { .. }, Format::V1) => DATA_MAGIC_V3,
            (Self::Keyed { .. }, Format::V2) => DATA_MAGIC_V4,
        }
    }
    /// The header flags a session with a key file of `magic` writes.
    fn flags_of(magic: Magic) -> u8 {
        match magic {
            Magic::Kh01 => 1,
            Magic::Ks01 => 3,
            _ => 0,
        }
    }
    /// Whether the writer's key file needs a security key (unauthenticated).
    fn hardware(&self) -> bool {
        matches!(self, Self::Keyed { flags, .. } if flags & 1 != 0)
    }
}

/// Cloning is fine: every copy of the text is zeroized when dropped.
#[derive(Clone)]
pub struct Entry {
    /// Zero until `Session::put` stores the entry.
    id: EntryId,
    /// The ID this entry replaced by an edit, zero for a new one. Two live
    /// entries with the same deleted parent were edited on two PCs.
    parent: EntryId,
    pub title: Zeroizing<String>,
    pub kind: Zeroizing<String>,
    pub secret: Zeroizing<String>,
    pub notes: Zeroizing<String>,
}
impl Entry {
    pub fn new(title: String, kind: String, secret: String, notes: String) -> Result<Self> {
        let e = Self {
            id: NO_ID,
            parent: NO_ID,
            title: Zeroizing::new(title),
            kind: Zeroizing::new(kind),
            secret: Zeroizing::new(secret),
            notes: Zeroizing::new(notes),
        };
        e.validate()?;
        Ok(e)
    }
    pub fn id(&self) -> EntryId {
        self.id
    }
    pub(crate) fn parent(&self) -> EntryId {
        self.parent
    }
    pub(crate) fn set_ids(&mut self, id: EntryId, parent: EntryId) {
        (self.id, self.parent) = (id, parent);
    }
    /// The four fields in file order, borrowed: comparing or counting them
    /// never copies a secret.
    pub(crate) fn fields(&self) -> [&str; 4] {
        [&self.title, &self.kind, &self.secret, &self.notes].map(|s| s.as_str())
    }
    /// Equal text in all four fields; IDs do not count.
    pub(crate) fn same_content(&self, other: &Entry) -> bool {
        self.fields() == other.fields()
    }
    fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() || self.secret.is_empty() {
            return Err("이름과 비밀정보를 입력하세요.");
        }
        if self.title.len() > 256
            || self.kind.len() > 64
            || self.secret.len() > MAX_TEXT
            || self.notes.len() > MAX_TEXT
        {
            return Err("항목이 너무 깁니다.");
        }
        if [&*self.title, &*self.kind, &*self.secret, &*self.notes]
            .iter()
            .any(|s| s.contains('\0'))
        {
            return Err("NUL 문자는 저장할 수 없습니다.");
        }
        Ok(())
    }
}
/// Heap copy of a secret, filled in place so no copy is left on the stack.
fn boxed<const N: usize>(src: &[u8; N]) -> Box<Zeroizing<[u8; N]>> {
    let mut out = Box::new(Zeroizing::new([0u8; N]));
    out.as_mut_slice().copy_from_slice(src);
    out
}
/// Short, non-secret name for a vault: the first 4 bytes of its random ID.
/// Each vault gets its own authenticator entry, so a second vault's QR can
/// never replace (Microsoft Authenticator) or be mistaken for the first.
fn tag(id: &[u8; 16]) -> String {
    format!("{:02X}{:02X}-{:02X}{:02X}", id[0], id[1], id[2], id[3])
}
/// The tag of the vault file at `path`, read from its plaintext header.
pub fn vault_tag(path: &Path) -> Option<String> {
    vault_id(path).map(|id| tag(&id))
}
/// The vault ID in the plaintext header of the vault file at `path`.
fn vault_id(path: &Path) -> Option<[u8; 16]> {
    let mut head = [0u8; 24];
    File::open(path).ok()?.read_exact(&mut head).ok()?;
    data_header(&head)
}
/// The vault ID of vault file bytes of a format this build reads (GOYOVA01
/// to 04: the ID is at offset 8 in each).
fn data_header(data: &[u8]) -> Option<[u8; 16]> {
    let magic = data.get(..8)?;
    let known = [DATA_MAGIC_V1, DATA_MAGIC_V2, DATA_MAGIC_V3, DATA_MAGIC_V4];
    if !known.iter().any(|m| m.as_slice() == magic) {
        return None;
    }
    data.get(8..24)?.try_into().ok()
}
/// Whether `data` starts with GOYOVA05 or later: a newer build wrote it. The
/// magic is public, so saying so before any decryption reveals nothing.
pub(crate) fn newer_format(data: &[u8]) -> bool {
    match data.get(..8) {
        Some([b'G', b'O', b'Y', b'O', b'V', b'A', a, b])
            if a.is_ascii_digit() && b.is_ascii_digit() =>
        {
            (a - b'0') * 10 + (b - b'0') >= 5
        }
        _ => false,
    }
}
/// The header of vault file bytes, before any key (spec §4.3). A GOYOVA03/04
/// header outside the grammar (shorter than its smallest file, an epoch of 0
/// or above EPOCH_MAX, an unknown flag, bit1 without bit0, a reserved byte
/// set) is VAULT_DAMAGED; any other file this build cannot read is
/// AUTH_ERROR, as its decryption would be.
pub(crate) fn read_header(data: &[u8]) -> Result<(Format, Header)> {
    if newer_format(data) {
        return Err(NEWER_FORMAT);
    }
    let (format, keyed) = match data.get(..8) {
        Some(m) if m == DATA_MAGIC_V1 => (Format::V1, false),
        Some(m) if m == DATA_MAGIC_V2 => (Format::V2, false),
        Some(m) if m == DATA_MAGIC_V3 => (Format::V1, true),
        Some(m) if m == DATA_MAGIC_V4 => (Format::V2, true),
        _ => return Err(AUTH_ERROR),
    };
    // The overhead, the counters of an empty plaintext and its entry count.
    let smallest = |overhead: usize| match format {
        Format::V1 => overhead + 12,
        Format::V2 => overhead + 32,
    };
    if !keyed {
        if data.len() < smallest(LEGACY_OVERHEAD) {
            return Err(AUTH_ERROR);
        }
        return Ok((format, Header::Legacy));
    }
    if data.len() < smallest(KEYED_OVERHEAD) {
        return Err(VAULT_DAMAGED);
    }
    let epoch = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let flags = data[64];
    if !(1..=EPOCH_MAX).contains(&epoch) || !matches!(flags, 0 | 1 | 3) || data[65..68] != [0; 3] {
        return Err(VAULT_DAMAGED);
    }
    let header = Header::Keyed {
        key_id: data[24..40].try_into().unwrap(),
        state: KeyState {
            epoch,
            tag: data[48..64].try_into().unwrap(),
        },
        flags,
    };
    Ok((format, header))
}
/// Where the key of a vault file with `header` sits in a bundle (spec
/// §4.5): GOYOVA01/02 under the ID key, the last; GOYOVA03/04 under the key
/// their header names. `kf2_ids` is a KF2 key file's public key-ID list,
/// None for a 0.8 key file, which lists none: only GOYOVA01/02 are under
/// its one key. Index 0 is the current key.
fn key_index(kf2_ids: Option<&[[u8; 16]]>, header: &Header) -> Option<usize> {
    match (kf2_ids, header) {
        (None, Header::Legacy) => Some(0),
        (None, Header::Keyed { .. }) => None,
        (Some(ids), Header::Legacy) => ids.len().checked_sub(1),
        (Some(ids), Header::Keyed { key_id, .. }) => ids.iter().position(|id| id == key_id),
    }
}
/// The temp file an unlock with the key file `key` reads in its place
/// (temp-candidate recovery, rule i): `key` is missing or unparseable, and
/// a save cut off mid-way left a copy of a key file of the vault `vault`
/// names. A successful unlock gives that copy the key file's name back.
pub fn key_candidate(vault: &Path, key: &Path) -> Option<PathBuf> {
    match recover::read_key(key) {
        Ok(recover::KeyRead::Lost { .. }) => {
            recover::key_candidate(&recover::vault_ids(vault), key).map(|c| c.path)
        }
        _ => None,
    }
}
/// Whether the vault file `vault` is missing while a save cut off mid-way
/// left copies of it, which an unlock tries to take back (rule iii).
pub fn vault_candidates(vault: &Path) -> bool {
    !vault.exists() && !recover::vault_ids(vault).is_empty()
}
/// The TOTP secret in the forms an authenticator app accepts.
pub struct OtpSetup {
    id: [u8; 16],
    otp: Box<Zeroizing<[u8; 20]>>,
}
impl OtpSetup {
    /// Base32 setup key for manual entry.
    pub fn code(&self) -> Zeroizing<String> {
        otp::base32(self.otp.as_slice())
    }
    /// Account name shown in the authenticator app, e.g. "3FA2-C1D0".
    pub fn tag(&self) -> String {
        tag(&self.id)
    }
    /// Key URI for the QR; SHA-1, 6 digits and 30 s are defaults.
    pub fn uri(&self) -> Zeroizing<String> {
        const HEAD: &str = "otpauth://totp/Goyo%20Vault:";
        const SECRET: &str = "?secret=";
        const TAIL: &str = "&issuer=Goyo%20Vault";
        let (tag, code) = (self.tag(), self.code());
        let size = HEAD.len() + tag.len() + SECRET.len() + code.len() + TAIL.len();
        // Sized up front so the secret is never left behind by a reallocation.
        let mut uri = Zeroizing::new(String::with_capacity(size));
        for part in [HEAD, &tag, SECRET, &code, TAIL] {
            uri.push_str(part);
        }
        uri
    }
}
pub struct Provision {
    id: [u8; 16],
    key: Box<Key>,
    otp: Box<Zeroizing<[u8; 20]>>,
}
impl Provision {
    pub fn new() -> Result<Self> {
        let mut p = Self {
            id: [0; 16],
            key: Box::default(),
            otp: Box::default(),
        };
        crypto::random_into(&mut p.id)?;
        crypto::random_into(p.key.as_mut_slice())?;
        crypto::random_into(p.otp.as_mut_slice())?;
        Ok(p)
    }
    pub fn setup(&self) -> OtpSetup {
        OtpSetup {
            id: self.id,
            otp: boxed(&self.otp),
        }
    }
    pub fn setup_code(&self) -> Zeroizing<String> {
        self.setup().code()
    }
    /// The authenticator account name, without copying the OTP secret.
    pub fn tag(&self) -> String {
        tag(&self.id)
    }
    /// Writes the new vault and key file. With `Some(code)` the vault uses
    /// the OTP and the code must come from the phone that scanned the QR;
    /// with None it opens with the password and key file alone.
    pub fn finish(
        &self,
        vault: &Path,
        key_path: &Path,
        password: &str,
        input: Option<&str>,
    ) -> Result<Session> {
        password_policy(password)?;
        let last = match input {
            Some(input) => otp::verify(self.otp.as_slice(), input, otp::now()?, None)?,
            None => 0,
        };
        let vault = normalized(vault)?;
        let key_path = normalized(key_path)?;
        distinct(&vault, &key_path)?;
        if vault.exists() || key_path.exists() {
            return Err("새 금고와 열쇠 파일은 기존 파일을 덮어쓸 수 없습니다.");
        }
        let locks = vec![FileLock::acquire(&vault)?];
        // A vault made without a security key stays in the 0.8 formats,
        // GOYOKE01/02 and GOYOVA01, byte for byte (spec §4.1).
        let otp = input.map(|_| &**self.otp);
        let key_bytes = encode_key(&self.id, &self.key, otp, password)?;
        let key_file = KeyFile::from_bytes(&key_path, key_bytes)?;
        let keys = Bundle::new(std::slice::from_ref(&**self.key), otp).ok_or(AUTH_ERROR)?;
        let key_state = key_file.legacy_state(&self.key).ok_or(AUTH_ERROR)?;
        let mut session = Session::new(
            vault,
            key_path,
            self.id,
            Box::new(keys),
            key_file,
            key_state,
        );
        session.last = last;
        session._locks = locks;
        session.serial = u64::from_le_bytes(*crypto::random::<8>()?);
        session.anchor.dir = anchor::locate();
        let data = session.encode()?;
        atomic_write(&session.key_path, session.key_file.bytes(), false)?;
        if let Err(e) = session.write_with(&data, false) {
            let _ = fs::remove_file(&session.key_path);
            return Err(e);
        }
        session.entries.shrink_to_fit();
        Ok(session)
    }
    /// The new vault's ID, which every registration's salt binds (spec
    /// §3.2, §8.3).
    #[cfg(feature = "security-key")]
    pub fn vault_id(&self) -> [u8; 16] {
        self.id
    }
    /// The code from the phone that scanned the QR, checked as of `otp_time`
    /// before any registration (spec §5.9): its time step.
    #[cfg(feature = "security-key")]
    pub fn check_otp(&self, input: &str, otp_time: u64) -> Result<u64> {
        let now = otp::now()?;
        if now.saturating_sub(otp_time) > OTP_TYPED_MAX || otp_time > now.saturating_add(5) {
            return Err(AUTH_ERROR);
        }
        otp::verify(self.otp.as_slice(), input, otp_time, None)
    }
    /// The anchor this vault's line goes to can be written: a locked read
    /// and a rewrite of the file as it is, before any registration (spec
    /// §5.9, S45-2 #7).
    #[cfg(feature = "security-key")]
    pub fn check_anchor(&self) -> Result<()> {
        rotate::probe_anchor(&self.id)
    }
    /// Writes the new vault with security keys (spec §5.9): the key file
    /// GOYOKH01 with every key registered here paired with every other, and
    /// the vault file under its key. `otp_step` is what `check_otp` gave; None
    /// makes a vault without an OTP.
    #[cfg(feature = "security-key")]
    pub fn finish_with_keys(
        &self,
        vault: &Path,
        key_path: &Path,
        password: &str,
        otp_step: Option<u64>,
        pin: bool,
        keys: Vec<crate::fido::NewKey>,
    ) -> Result<Session> {
        rotate::create_with_keys(self, (vault, key_path), password, otp_step, pin, keys)
    }
}
pub const MIN_PASSWORD: usize = 12;
/// Common words, keyboard walks, runs and repeats are what guessing tools try
/// first. A password made only of such pieces is refused at any length:
/// "password1234", "qwerty123456", "1q2w3e4r5t6y" and "123456123456" all are,
/// while unrelated words ("dragon-tiger-lemon") or a sentence still pass.
fn predictable(s: &str) -> bool {
    const WALKS: [&str; 10] = [
        "abcdefghijklmnopqrstuvwxyz",
        "01234567890",
        "qwertyuiop[]",
        "asdfghjkl;'",
        "zxcvbnm,./",
        "1q2w3e4r5t6y7u8i9o0p",
        "q1w2e3r4t5y6u7i8o9p0",
        "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
        "qazwsxedcrfvtgbyhnujmikolp",
        "!@#$%^&*()",
    ];
    const WORDS: [&str; 40] = [
        "password", "passwd", "pass", "iloveyou", "love", "letmein", "welcome", "admin", "login",
        "secret", "master", "hello", "dragon", "monkey", "shadow", "sunshine", "princess",
        "football", "baseball", "soccer", "superman", "batman", "freedom", "whatever", "trustno",
        "starwars", "qwerty", "test", "google", "naver", "kakao", "samsung", "bitcoin", "crypto",
        "wallet", "korea", "seoul", "sarang", "dkssud",
        "tkfkd", // 안녕, 사랑 typed with the Korean layout off
    ];
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(s.len()));
    chars.extend(
        s.chars()
            .flat_map(char::to_lowercase)
            .filter(|c| !c.is_whitespace()),
    );
    if chars.iter().all(char::is_ascii_digit) {
        return true; // dates, phone numbers
    }
    // A repeated block counts once: "qwerqwerqwer" is judged as "qwer".
    let n = chars.len();
    let unit = (1..=n / 2)
        .find(|p| n.is_multiple_of(*p) && (*p..n).all(|i| chars[i] == chars[i - p]))
        .unwrap_or(n);
    let text = &chars[..unit];
    let mut covered = vec![false; unit];
    let words: Vec<Vec<char>> = WORDS.iter().map(|w| w.chars().collect()).collect();
    let walks: Vec<Vec<char>> = WALKS
        .iter()
        .flat_map(|w| [w.chars().collect(), w.chars().rev().collect()])
        .collect();
    // No run is longer than the longest walk, which keeps this fast up to the
    // 1024-byte limit.
    let longest = walks.iter().map(Vec::len).max().unwrap_or(0);
    for i in 0..unit {
        for w in &words {
            if text[i..].starts_with(w) {
                covered[i..i + w.len()].fill(true);
            }
        }
        // Longest run from i that sits inside a keyboard or alphabet walk.
        let run = (3..=(unit - i).min(longest)).rev().find(|len| {
            let piece = &text[i..i + len];
            walks
                .iter()
                .any(|walk| walk.windows(*len).any(|w| w == piece))
        });
        if let Some(len) = run {
            covered[i..i + len].fill(true);
        }
    }
    covered.iter().filter(|c| !**c).count() < 4
}
pub fn password_policy(s: &str) -> Result<()> {
    // Argon2id slows each guess, but a stolen key file can still be guessed
    // offline without limit (an OTP never takes part in decryption), so
    // length is what keeps the password out of reach.
    if s.chars().count() < MIN_PASSWORD || s.len() > 1024 {
        return Err(
            "비밀번호는 12자 이상, UTF-8 1024바이트 이하로 입력하세요. 짧고 복잡한 암호보다 긴 문장이 안전합니다.",
        );
    }
    // Length alone admits "aaaaaaaaaaaaaaaa" or "abababababababab". Sized up
    // front: a growing Vec would free unwiped copies of the password.
    let mut distinct: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(s.len()));
    distinct.extend(s.chars());
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 6 {
        return Err(
            "같은 글자를 반복한 비밀번호는 쓸 수 없습니다. 서로 다른 글자가 6개 이상 필요합니다.",
        );
    }
    if predictable(s) {
        return Err(
            "흔한 단어(password, dragon 등)·키보드 배열·연속된 숫자는 추측 도구가 가장 먼저 시도해서 글자 수로 치지 않습니다. 흔하지 않은 단어나 나만 아는 문장을 섞으세요.",
        );
    }
    Ok(())
}

/// What the public precheck found about the vault file (spec §5.1 steps
/// 5-7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VaultClass {
    /// Under the key file's current key. `stale_key_file`: its header epoch,
    /// unauthenticated here and checked again once it opens, is above the
    /// key file's, so the key file was changed elsewhere.
    Current { stale_key_file: bool },
    /// Under an older key of the key file, and the very file the key file's
    /// last change expects to replace, a change not yet completed on this
    /// PC: the unlock completes it silently.
    Resume,
    /// Under an older key, and not that file: only the user's yes (S-OLDER)
    /// completes it, and only for these bytes (`sha`).
    Older { sha: [u8; 32] },
    /// The vault file is missing: the unlock looks for a temp copy of it
    /// under the current key (rule iii).
    Missing,
}
/// The public precheck of a login or Restore (spec §5.1): the vault file's
/// class and how the key file stands against this PC's anchor. A waiting
/// server key file (the security-key build) joins it here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Precheck {
    pub vault: VaultClass,
    pub anchor: AnchorClass,
}
/// The public precheck (spec §5.1): the key file's magic family, the vault
/// file's header, the vault IDs, this PC's anchor and the key lookup, all
/// before any password, touch or key derivation. Its refusals are final for
/// these files and say nothing about the password, so none counts as a
/// failed attempt. `restore`: the vault file is a backup the user picked,
/// which opens under any key of the key file and is never taken from a temp
/// file.
fn precheck(vault: &Path, key: &KeyFile, restore: bool, forget: bool) -> Result<(Precheck, Seen)> {
    // Step 1: a security-key file, decided on its magic alone. Step 2 for
    // the key file: a newer magic never became a KeyFile.
    if let Some(refusal) = key.refusal() {
        return Err(refusal);
    }
    let data = match read_bounded(vault, MAX_FILE) {
        Ok(data) => Some(data),
        Err(_) if !restore && !vault.exists() => None,
        Err(e) => return Err(e),
    };
    // Step 2 for the vault file: a newer format, or a damaged header. Step
    // 3: the vault IDs are public.
    let id = key.vault_id().ok_or(AUTH_ERROR)?;
    let header = match &data {
        Some(data) => {
            let (_, header) = read_header(data)?;
            if data.get(8..24) != Some(&id[..]) {
                return Err(OTHER_VAULT);
            }
            Some(header)
        }
        None => None,
    };
    // Step 9 runs here, before every step that depends on the vault file
    // (S23-3 #16): this PC's anchor against the key file alone.
    let mut seen = anchor::look(&id, key, key.path(), restore);
    // The per-vault forget (security-key build, spec §5.10): this vault's
    // lines are ignored in memory, and every key file is a bootstrap.
    #[cfg(feature = "security-key")]
    if forget {
        (seen.lines, seen.pending, seen.forgotten) =
            (anchor::Lines::default(), Decision::None, true);
    }
    #[cfg(not(feature = "security-key"))]
    let _ = forget;
    let confirmed = seen.confirmed();
    let kf2 = key.header();
    let class = match kf2 {
        Some(h) => anchor::compare(h, confirmed.as_ref()),
        None => anchor::compare_legacy(confirmed.as_ref()),
    };
    seen.class = match class {
        #[cfg(feature = "security-key")]
        _ if forget => AnchorClass::Bootstrap,
        // A password-only key file with no record of this vault, where
        // anything shows that security keys were once on: a bootstrap too
        // (spec §5.1 step 9, round 2, finding 10).
        #[cfg(feature = "security-key")]
        Ok(AnchorClass::New) if signs_of_keys(vault, data.as_deref(), key) => {
            AnchorClass::Bootstrap
        }
        Ok(class) => class,
        // A Restore reads a backup with the key file of its time: it runs
        // held instead (spec §5.1, S23-1 #17).
        Err(Refusal::Fork) if restore => AnchorClass::Fork,
        Err(Refusal::Fork) => {
            // The vault file under the forked branch's key too: this PC's own
            // key file alone will not open it (S23-2 #9).
            let line = confirmed.as_ref().ok_or(ANCHOR_FORK)?;
            let ids = match &header {
                Some(header) => vec![header_key_id(kf2, header)],
                None => recover::candidates(vault, MAX_FILE)
                    .iter()
                    .filter_map(|c| read_header(&c.bytes).ok())
                    .map(|(_, header)| header_key_id(kf2, &header))
                    .collect(),
            };
            let foreign = !ids.is_empty()
                && ids
                    .iter()
                    .all(|i| i.is_some_and(|i| anchor::foreign_key(line, &i)));
            return Err(if foreign {
                ANCHOR_FORK_VAULT
            } else {
                ANCHOR_FORK
            });
        }
        Err(refusal) => return Err(refused(refusal)),
    };
    let check = |vault| Precheck {
        vault,
        anchor: seen.class,
    };
    let (Some(data), Some(header)) = (data, header) else {
        // Step 7: rule (iii) looks for a temp copy of the vault file.
        return Ok((check(VaultClass::Missing), seen));
    };
    // Step 4: the key, by the key file's public key-ID list.
    let epoch = kf2.map_or(0, |h| h.epoch);
    let Some(index) = key_index(kf2.map(|h| h.key_ids.as_slice()), &header) else {
        return Err(match header {
            // Only a build without security-key support says why here.
            _ if !cfg!(feature = "security-key") && header.hardware() => {
                NO_SECURITY_KEY_SUPPORT_VAULT
            }
            _ if restore => KEY_NOT_IN_BACKUP,
            // Another PC changed the key of a vault file both PCs open, each
            // with its own key-file copy (S23-3 #8). The epoch is only words.
            Header::Keyed { state, .. } if state.epoch > epoch => refuse(
                KEY_NOT_IN_KEY_FILE_NEWER,
                vec![state.epoch.to_string(), epoch.to_string()],
            ),
            _ => KEY_NOT_IN_KEY_FILE,
        });
    };
    let vault = match header {
        // Step 5.
        Header::Keyed { state, .. } if index == 0 => VaultClass::Current {
            stale_key_file: state.epoch > epoch,
        },
        Header::Legacy if index == 0 => VaultClass::Current {
            stale_key_file: false,
        },
        // Step 6. `resume` is public here and checked again once the key
        // file opens. A change whose completion this PC already saw does
        // not complete again: its probe came back from a backup.
        _ => {
            let sha = sha256(&data);
            let line = confirmed.as_ref();
            let consumed = line.and_then(|l| l.state.consumed);
            let vkey = line.and_then(|l| l.vkey);
            if kf2.is_some_and(|h| h.resume == sha) && consumed != Some(sha) {
                VaultClass::Resume
            } else if !restore && vkey.is_some() && vkey != header_key_id(kf2, &header) {
                // Only an older vault file under the key this PC last used is
                // legitimate at login (S23-1 #2); a Restore takes any.
                return Err(OLDER_REFUSED);
            } else {
                VaultClass::Older { sha }
            }
        }
    };
    Ok((check(vault), seen))
}
/// The key ID a vault file header names: its own, or for GOYOVA01/02 the
/// ID key's, which a KF2 key file lists last. None under a 0.8 key file,
/// which lists none.
fn header_key_id(kf2: Option<&keyfile::KeyHeader>, header: &Header) -> Option<[u8; 16]> {
    match header {
        Header::Keyed { key_id, .. } => Some(*key_id),
        Header::Legacy => kf2.and_then(|h| h.key_ids.last().copied()),
    }
}
/// Whether a vault this PC has no record of shows that it used security
/// keys (spec §5.1 step 9, round 2, finding 10): a vault file, a temp copy
/// of it or a synced copy with the hardware flag, or a password-only key
/// file whose removals or key numbers show that keys were on.
#[cfg(feature = "security-key")]
fn signs_of_keys(vault: &Path, data: Option<&[u8]>, key: &KeyFile) -> bool {
    let hardware = |bytes: &[u8]| read_header(bytes).is_ok_and(|(_, h)| h.hardware());
    if key
        .header()
        .is_some_and(|h| !h.tombstones.is_empty() || h.next > 1)
        || data.is_some_and(hardware)
    {
        return true;
    }
    if recover::candidates(vault, MAX_FILE)
        .iter()
        .any(|c| hardware(&c.bytes))
    {
        return true;
    }
    use crate::syncfile::{INCOMING, MAX_WRAPPED, OUTGOING, parse_incoming, parse_outgoing};
    let Some(dir) = crate::syncfile::sync_dir(vault) else {
        return false;
    };
    let wrapped = |name: &str| crate::syncfile::read_bounded(&dir.join(name), MAX_WRAPPED).ok();
    wrapped(INCOMING).is_some_and(|b| parse_incoming(&b).is_some_and(|(_, v)| hardware(v)))
        || wrapped(OUTGOING).is_some_and(|b| parse_outgoing(&b).is_some_and(|(_, v)| hardware(v)))
}
/// The text of an anchor refusal (spec §5.10).
fn refused(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Downgrade => ANCHOR_DOWNGRADE,
        Refusal::Relist => ANCHOR_RELIST,
        Refusal::Fork => ANCHOR_FORK,
        Refusal::TooFar { old, new } => {
            refuse(ANCHOR_EPOCH, vec![new.to_string(), old.to_string()])
        }
        #[cfg(feature = "security-key")]
        Refusal::RelistKeys => gate::ANCHOR_RELIST_KEYS,
        #[cfg(feature = "security-key")]
        Refusal::Pinned => gate::ANCHOR_PINNED,
        #[cfg(feature = "security-key")]
        Refusal::Otp => gate::ANCHOR_OTP,
    }
}
/// Whether an unlock or Restore error came with no wrong password or OTP
/// code: a refusal of the files themselves (spec §4.7, §5.1), or an
/// older-key vault file not agreed to. The app starts no retry delay.
pub fn not_a_failure(e: &str) -> bool {
    #[cfg(feature = "security-key")]
    if keyfile::inbox::not_a_failure(e)
        || [
            gate::ANCHOR_RELIST_KEYS,
            gate::ANCHOR_PINNED,
            gate::ANCHOR_OTP,
        ]
        .contains(&e)
    {
        return true;
    }
    [
        NO_SECURITY_KEY_SUPPORT,
        NO_SECURITY_KEY_SUPPORT_DAMAGED,
        NO_SECURITY_KEY_SUPPORT_VAULT,
        NEWER_KEY_FORMAT,
        NEWER_FORMAT,
        VAULT_DAMAGED,
        OTHER_VAULT,
        KEY_NOT_IN_KEY_FILE,
        KEY_NOT_IN_KEY_FILE_NEWER,
        KEY_NOT_IN_BACKUP,
        OLDER_NOT_CONFIRMED,
        OLDER_REFUSED,
        VAULT_COUNTERS,
        RESAVE_TOO_LARGE,
        ANCHOR_DOWNGRADE,
        ANCHOR_RELIST,
        ANCHOR_FORK,
        ANCHOR_FORK_VAULT,
        ANCHOR_EPOCH,
        ANCHOR_REREAD,
    ]
    .contains(&e)
}
/// What phase 1 of a login or Restore read (spec §5.1, §9.2a): the key
/// file, or the temp file an interrupted save left in place of a missing or
/// unparseable one (rule i), the precheck and what it found in the anchor.
/// Phase 3 opens exactly these key file bytes.
pub struct Prepared {
    source: PathBuf,
    key_path: PathBuf,
    key: KeyFile,
    key_temp: Option<PathBuf>,
    check: Precheck,
    seen: Seen,
}
impl Prepared {
    pub fn check(&self) -> Precheck {
        self.check
    }
    /// The key file came from a temp file (rule i): a failed
    /// authentication may mean that copy needs other factors.
    pub fn key_temp(&self) -> bool {
        self.key_temp.is_some()
    }
    /// The allow list of the unlock's ceremony (spec §5.2 step 4): every
    /// live key of the key file, suspended ones included, each with its
    /// salt. None for a key file without security keys.
    #[cfg(feature = "security-key")]
    pub fn unlock_request(&self, owner: isize) -> Option<crate::fido::AssertRequest> {
        let h = self.key.header().filter(|h| !h.slots.is_empty())?;
        let allow = h
            .slots
            .iter()
            .map(|s| {
                (
                    s.cred_id.clone(),
                    crate::fido::salt(&h.vault_id, &s.seed),
                    None,
                )
            })
            .collect();
        crate::fido::AssertRequest::new(owner, allow, h.pin()).ok()
    }
    /// The gate a changed key file asks at login before the touch (spec
    /// §5.2 step 3, §7.15a): G2 while this PC still allows it, else G1,
    /// with the keys S-LOSTPICK offers, from the anchor's confirmed state
    /// only, and the key file's epoch (public; S-GATE-CODE shows it). None
    /// when the key file needs no gate.
    #[cfg(feature = "security-key")]
    pub fn login_gate(&self) -> Option<(GateKind, Vec<GateChoice>, u64)> {
        let AnchorClass::Gated(kind) = self.check.anchor else {
            return None;
        };
        let kind = match kind {
            GateKind::G2 if gate::g2_allowed(&self.seen.lines) => GateKind::G2,
            _ => GateKind::G1,
        };
        let choices = self
            .seen
            .lines
            .vault
            .as_ref()
            .map(|v| gate::choices(&v.state.slots))
            .unwrap_or_default();
        Some((kind, choices, self.key.header()?.epoch))
    }
    /// What a failed authentication of these files says instead of
    /// AUTH_ERROR (spec §5.12): rule (i)'s text for a key file that is only
    /// a temp file, or AUTH_ERROR with a hint when this PC's own key change
    /// left the key file as it is.
    pub fn auth_failure(&self) -> Option<&'static str> {
        if self.key_temp.is_some() {
            // The temp file is the only key file. At or above the state this
            // PC confirmed it is the change that almost finished: only the
            // new factors open it.
            let current = self.key.header().is_some_and(|h| {
                self.seen
                    .lines
                    .vault
                    .as_ref()
                    .is_none_or(|l| h.epoch >= l.state.epoch)
            });
            return Some(if current {
                CHANGE_DONE_NEWPASS
            } else {
                LEFTOVER_TEMP
            });
        }
        let pending = self.seen.lines.pending.as_ref()?;
        // A 0.8 key file's state needs its key, so precheck never finds it
        // Equal; with a confirmed 0.8 state (after [이 열쇠 파일이 맞습니다]
        // on a 0.8 pair) and a change built on it that never landed, it is
        // the key file that change left (spec §5.12 (b)).
        let confirmed_08 = self.check.anchor == AnchorClass::Legacy
            && self
                .seen
                .lines
                .vault
                .as_ref()
                .is_some_and(|l| l.state.epoch == 0);
        match self.seen.pending {
            // This PC's change never landed and the key file is the state it
            // confirmed: the old password still opens it (S23-3 #3, #9).
            Decision::Drop { overtaken: false }
                if self.check.anchor == AnchorClass::Equal
                    || confirmed_08
                    || self.seen.lines.vault.is_none() =>
            {
                Some(AUTH_HINT_INTERRUPTED)
            }
            // The key file is this PC's change, or one written on top of it:
            // its password is the one that change set, unless another PC set
            // another since (S23-1 #9, S23-2 #6).
            Decision::Promote { own: true } => {
                let h = self.key.header()?;
                let set = pending.state.hist.first()?.pwid;
                if h.pw_id[..4] != set {
                    Some(AUTH_LANDED_LATER)
                } else {
                    match pending.pw? {
                        anchor::Pw::New => Some(AUTH_LANDED_NEW),
                        anchor::Pw::Other => Some(AUTH_LANDED_OTHER),
                    }
                }
            }
            _ => None,
        }
    }
}
/// Phase 1 of a login: reads the key file and prechecks the vault file.
pub fn prepare(vault: &Path, key_path: &Path) -> Result<Prepared> {
    prepared(vault, key_path, false, false)
}
/// Phase 1 of a login after S-ANCHOR-FORGET's yes (spec §5.10, round 4,
/// finding 13): this PC's record of the vault is ignored, and the key
/// file, whatever it is, opens as a bootstrap; the record is removed only
/// by the TOFU pass, so a lock or crash before it leaves it as it was.
#[cfg(feature = "security-key")]
pub fn prepare_forgotten(vault: &Path, key_path: &Path) -> Result<Prepared> {
    prepared(vault, key_path, false, true)
}
/// The epoch of this PC's record of the vault of the key file at
/// `key_path` (S-ANCHOR-FORGET's `{old}`, spec §5.10): None without one.
/// Reads the anchor and writes nothing.
#[cfg(feature = "security-key")]
pub fn recorded_epoch(key_path: &Path) -> Option<u64> {
    let key = KeyFile::read(key_path).ok()?;
    let id = key.vault_id()?;
    anchor::look(&id, &key, key_path, false)
        .confirmed()
        .map(|l| l.state.epoch)
}
/// What the login screen's note says of a chosen key file (spec §9.1,
/// feature build): S-LOGIN-NOTE with the number of security keys and the
/// PIN line, or S-LOGIN-PWONLY.
#[cfg(feature = "security-key")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoginKeys {
    Keys { n: usize, pin: bool },
    PasswordOnly,
}
/// The login note of the key file at `key_path` (spec §9.1): its keys, but
/// this PC's confirmed state's whenever the file differs from it (a changed
/// file's key count is part of what its gate hides; round 2, finding 3),
/// and nothing then for a confirmed state without keys; S-LOGIN-PWONLY for
/// a password-only file this PC has no record of. Reads the anchor and
/// writes nothing.
#[cfg(feature = "security-key")]
pub fn login_keys(key_path: &Path) -> Option<LoginKeys> {
    let key = KeyFile::read(key_path).ok()?;
    let id = key.vault_id()?;
    let confirmed = anchor::look(&id, &key, key_path, false).confirmed();
    let own = key.header().map(|h| (h.state(), h.slots.len(), h.pin()));
    let keys = |n: usize, pin: bool| (n > 0).then_some(LoginKeys::Keys { n, pin });
    match (confirmed, own) {
        (Some(c), Some((state, n, pin))) if c.state.key_state() == state => keys(n, pin),
        (Some(c), _) => keys(c.state.slots.len(), c.state.policy & 2 != 0),
        (None, Some((_, n, pin))) if n > 0 => keys(n, pin),
        (None, _) => Some(LoginKeys::PasswordOnly),
    }
}
/// A login refusal that [이 금고의 기록 지우고 다시 확인…] answers (spec
/// §5.10, §9.1): S-ANCHOR-FORK (with or without its vault line),
/// S-ANCHOR-RELIST and S-ANCHOR-DOWNGRADE; not S-ANCHOR-EPOCH.
#[cfg(feature = "security-key")]
pub fn forgettable(e: &str) -> bool {
    [
        ANCHOR_FORK,
        ANCHOR_FORK_VAULT,
        ANCHOR_RELIST,
        ANCHOR_DOWNGRADE,
    ]
    .contains(&e)
}
/// Phase 1 of a Restore of `backup`.
pub fn prepare_restore(backup: &Path, key_path: &Path) -> Result<Prepared> {
    prepared(backup, key_path, true, false)
}
fn prepared(source: &Path, key_path: &Path, restore: bool, forget: bool) -> Result<Prepared> {
    let source = normalized(source)?;
    let key_path = normalized(key_path)?;
    distinct(&source, &key_path)?;
    // A key file missing or unparseable after a save was cut off: the temp
    // copy of a key file of this vault stands in (rule i).
    let (bytes, key_temp) = match recover::read_key(&key_path)? {
        recover::KeyRead::Found(bytes) => (bytes, None),
        recover::KeyRead::Lost { before, .. } => {
            match recover::key_candidate(&recover::vault_ids(&source), &key_path) {
                Some(c) => (c.bytes, Some(c.path)),
                None => (before?, None),
            }
        }
    };
    let key = KeyFile::from_bytes(&key_path, bytes)?;
    let (check, seen) = precheck(&source, &key, restore, forget)?;
    Ok(Prepared {
        source,
        key_path,
        key,
        key_temp,
        check,
        seen,
    })
}
fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
/// The re-save of an unlock or Restore that does not fit the 8 MiB limit is
/// no failed attempt: the files are fine and the password was right.
fn too_large_to_resave(e: &'static str) -> &'static str {
    if e == VAULT_FULL { RESAVE_TOO_LARGE } else { e }
}
/// How long after it was typed an OTP code is still checked (spec §5.2
/// step 6): a question in between may take a while, an unattended one not.
const OTP_TYPED_MAX: u64 = 180;

/// What an unlock, a key change or a later save found about the key and
/// vault files, for the status lines (spec §5.2 step 10, §5.11).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeyNotice {
    /// The vault file that a key change left under the old key is saved
    /// under the new one: the change is complete.
    Resumed,
    /// An older-key vault file the user agreed to open is saved under the
    /// current key.
    OlderAccepted,
    /// The vault file is under the current key at a higher epoch than the
    /// key file: another PC changed its copy of the key file.
    StaleKeyFile,
    /// The vault file could not be saved under the current key yet; the
    /// next save or poll tries again.
    ResavePending,
    /// The same because a 0.8 vault file within 44 bytes of the 8 MiB limit
    /// does not fit the key file's format: deleting or shortening entries
    /// lets the next save do it.
    ResaveTooLarge,
    /// A key change of this PC that never landed was dropped (S-NOTFINISHED).
    NotFinished,
    /// The key file is an older state of this PC (S-LOCAL-ROLLBACK): key
    /// changes, uploads and merges wait until the user confirms it. The
    /// confirmed epoch and the key file's.
    LocalRollback { old: u64, new: u64 },
    /// A key change of this PC may have landed in the key file at this
    /// path, which could not be read (S-PENDING-ELSEWHERE).
    PendingElsewhere(PathBuf),
    /// A Restore with a key file other than the one this PC confirmed
    /// (S-RESTORE-OLDKEY): the restored session is held.
    RestoreOldKey { old: u64, new: u64 },
    /// A Restore while a key change of this PC waits for a login
    /// (S-RESTORE-PENDING): held as well.
    RestorePending,
    /// No key backup of this KF2 key file yet (S-KEYBACKUP-DUE).
    KeyBackupDue,
    /// The anchor could not be written: this session remembers what it
    /// should hold (S-SIDECAR-FAILED).
    SidecarFailed,
    /// A later version wrote the anchor (S-ANCHOR-NEWER).
    AnchorNewer,
    /// The new key file is only a temp file whose rename is retried
    /// (S-KEYTEMP).
    KeyTemp,
    /// That temp file and the key file are both gone: back up the key file
    /// from memory now (S-KEYTEMP-GONE).
    KeyTempGone,
    /// A removal of the keys with these numbers never landed: this PC is
    /// not protected yet (S-REMOVE-UNDONE, in place of S-NOTFINISHED).
    #[cfg(feature = "security-key")]
    RemoveUndone(Vec<u8>),
    /// The anchor could not be written for a security-key session: key
    /// changes, adopts and uploads wait until it can (S-ANCHOR-FAILED).
    #[cfg(feature = "security-key")]
    AnchorFailed,
}

pub struct Session {
    pub path: PathBuf,
    pub key_path: PathBuf,
    id: [u8; 16],
    /// The data keys, the current one first and the ID key last, and the
    /// TOTP secret of an OTP vault (spec §4.2, §6).
    keys: Box<Bundle>,
    /// Last accepted OTP time step; always 0 without an OTP.
    last: u64,
    /// V1 until the user turns sync on for this vault; it never goes back.
    format: Format,
    /// Lamport counter of content changes, shared by the synced copies: a
    /// put, a delete or a merge to upload raises it, OTP and password changes
    /// do not. Written only in v2.
    generation: u64,
    /// This PC's highest `generation` of an authenticated server copy; a
    /// lower one later means the server went back. Written only in v2.
    seen: u64,
    pub entries: Vec<Entry>,
    /// IDs of deleted and replaced entries, oldest first, so that no other
    /// copy can bring them back. A v1 vault keeps them only in memory.
    tombstones: Vec<EntryId>,
    /// The link to `<vault>.sync`, for a v2 vault whose folder exists.
    sync: Option<sync::SyncLink>,
    /// What the unlock found in the sync folder, for the first status line.
    unlock_notice: Option<SyncNotice>,
    /// The key file is inside the sync folder: never link this session.
    sync_refused: bool,
    /// What the unlock took back from temp files, for the first status line.
    recovered: Recovery,
    /// A save of the vault file hit the replace gap (GAP_KEPT): see write.
    gap_kept: bool,
    /// The key file as the session opened it: its bytes, which a change of
    /// it compares with the file on disk, and what they state.
    key_file: KeyFile,
    /// The key file's state (spec §4.3): a 0.8 key file's is epoch 0 and
    /// its legacy tag.
    key_state: KeyState,
    /// The highest key-file epoch the opened files prove (spec §4.3).
    max_epoch: u64,
    /// The vault file is under the current key at a higher epoch than the
    /// key file (StaleKeyFile).
    stale_key_file: bool,
    /// The unlock could not save the vault file under the current key; any
    /// later save does, and every poll tries (spec §5.2 step 8). Never set
    /// by a replace gap, which ends every write (see write).
    resave_due: bool,
    /// What the unlock, a key change or a later save found, for the status
    /// lines; taken by the app.
    key_notices: Vec<KeyNotice>,
    /// Random per session: a Reauth token names it (spec §5.3).
    serial: u64,
    /// This KF2 key file state has no key backup yet (S-KEYBACKUP-DUE).
    key_backup_due: bool,
    /// A key change could not tell whether it saved the key file (spec §5.5
    /// S2), or its key file and the temp file standing in for it are both
    /// gone: `unsaved_key` or the session's key file is the one copy that
    /// opens the vault file, and `backup_key` writes it without comparing.
    key_file_damaged: bool,
    /// The new key file of a change that could not tell whether it saved
    /// it. The session keeps the old keys and writes the vault file no more.
    unsaved_key: Option<Vec<u8>>,
    /// The key file's temp file after a replace gap of a key change (spec
    /// §5.5 S2, E-S2b): its rename is retried at every save and poll.
    key_temp: Option<PathBuf>,
    /// The key file is an older state of this PC, or a Restore read a key
    /// file other than the one this PC confirmed (spec §5.10): no key
    /// change, outgoing write or merge until the user confirms it.
    local_rollback: bool,
    /// A Restore with such a key file, or while a key change of this PC
    /// waits for a login: no adopt either (spec §5.1).
    restore_held: bool,
    /// Opened by a Restore, whatever its key file: no key change or adopt
    /// (RESTORE_KEYS).
    restored: bool,
    /// A key change of this PC may have landed in the key file at this
    /// path, which could not be read: no key change until it is decided
    /// (spec §5.1 step 9).
    pending_elsewhere: Option<PathBuf>,
    /// This vault's lines of the anchor as this session knows them, and
    /// whether they still have to be written (spec §5.10).
    anchor: AnchorView,
    /// A key change whose vault file could only be saved later: the save
    /// that does it seals the change in the anchor (spec §5.5 S3).
    seal_due: bool,
    /// The number of the security key this session was unlocked with.
    #[cfg(feature = "security-key")]
    unlocked_with: Option<u8>,
    /// Trust on first use (spec §7.17): this PC has not confirmed the key
    /// file's state, so no edit, key change or upload before G1.
    #[cfg(feature = "security-key")]
    tofu: bool,
    /// A changed key file at login waits for its gate (gate-pending mode,
    /// spec §5.2): no edit, no write, no merge and no upload until it passes.
    #[cfg(feature = "security-key")]
    gate_login: Option<gate::GateLogin>,
    /// What the unlock left for the gate or TOFU pass (spec §5.2 steps 8-9).
    #[cfg(feature = "security-key")]
    deferred: gate::Deferred,
    /// This vault's anchor lines are ignored until the TOFU pass removes
    /// them (the per-vault forget, spec §5.10).
    #[cfg(feature = "security-key")]
    forgotten: bool,
    /// A held session (`local_rollback`) whose confirmed line lacks `t`, or
    /// that has none: TOFU's refusals apply on top of the hold (no edit, no
    /// key change, no outgoing write), with no TOFU pass, until the hold
    /// lifts (spec §5.2 step 9(a), S45-3 #2).
    #[cfg(feature = "security-key")]
    held_unconfirmed: bool,
    /// The post-removal review due on this PC (spec §5.13), with its loss
    /// date: the vault outgoing waits until it is done.
    #[cfg(feature = "security-key")]
    review_due: Option<String>,
    /// A removal that never landed, as [다시 하기] reopens it (spec §9.2;
    /// S-REMOVE-UNDONE).
    #[cfg(feature = "security-key")]
    redo: Option<rotate::Redo>,
    /// The anchor could not be written for a security-key session
    /// (AnchorFailed, spec §5.10): key changes, adopts and every outgoing
    /// write wait until a write succeeds, retried at every save and poll.
    #[cfg(feature = "security-key")]
    anchor_failed: bool,
    /// A pick failed in this session since a gate last passed: G2 is off
    /// for it whether or not `g2=off` reached the anchor (spec §7.15a), so
    /// an anchor that cannot be written never allows a second pick.
    #[cfg(feature = "security-key")]
    g2_spent: std::cell::Cell<bool>,
    _locks: Vec<FileLock>,
}
/// A session's view of the anchor (spec §5.10).
#[derive(Default)]
struct AnchorView {
    /// The anchor's folder; None when there is none.
    dir: Option<PathBuf>,
    /// This vault's lines as last read or written.
    lines: anchor::Lines,
    /// `lines` could not be written yet: the in-memory fallback of a
    /// password-only session, retried at every save and poll.
    unsaved: bool,
    /// The anchor is a later version's, or could not be read: never
    /// written.
    frozen: bool,
    /// S-SIDECAR-FAILED or S-ANCHOR-NEWER was shown.
    told: bool,
}
impl Session {
    /// A session with no entries yet, its files not yet read or written.
    fn new(
        path: PathBuf,
        key_path: PathBuf,
        id: [u8; 16],
        keys: Box<Bundle>,
        key_file: KeyFile,
        key_state: KeyState,
    ) -> Self {
        Self {
            path,
            key_path,
            id,
            keys,
            last: 0,
            format: Format::V1,
            generation: 0,
            seen: 0,
            entries: Vec::new(),
            tombstones: Vec::new(),
            sync: None,
            unlock_notice: None,
            sync_refused: false,
            recovered: Recovery::default(),
            gap_kept: false,
            key_file,
            max_epoch: key_state.epoch,
            key_state,
            stale_key_file: false,
            resave_due: false,
            key_notices: Vec::new(),
            serial: 0,
            key_backup_due: false,
            key_file_damaged: false,
            unsaved_key: None,
            key_temp: None,
            local_rollback: false,
            restore_held: false,
            restored: false,
            pending_elsewhere: None,
            anchor: AnchorView::default(),
            seal_due: false,
            #[cfg(feature = "security-key")]
            unlocked_with: None,
            #[cfg(feature = "security-key")]
            tofu: false,
            #[cfg(feature = "security-key")]
            gate_login: None,
            #[cfg(feature = "security-key")]
            deferred: gate::Deferred::default(),
            #[cfg(feature = "security-key")]
            forgotten: false,
            #[cfg(feature = "security-key")]
            held_unconfirmed: false,
            #[cfg(feature = "security-key")]
            review_due: None,
            #[cfg(feature = "security-key")]
            redo: None,
            #[cfg(feature = "security-key")]
            anchor_failed: false,
            #[cfg(feature = "security-key")]
            g2_spent: std::cell::Cell::new(false),
            _locks: Vec::new(),
        }
    }
    /// Phase 1 and phase 3 of a login at once, with no question between
    /// them: an older-key vault file that is not the one the key file's last
    /// change expects stays closed (OLDER_NOT_CONFIRMED).
    pub fn unlock(vault: &Path, key_path: &Path, password: &str, input: &str) -> Result<Self> {
        Self::login(
            prepare(vault, key_path)?,
            password,
            input,
            otp::now()?,
            None,
        )
    }
    /// Phase 1 and phase 3 of a Restore of `backup` into the new file
    /// `destination`.
    pub fn restore(
        backup: &Path,
        key_path: &Path,
        destination: &Path,
        password: &str,
        input: &str,
    ) -> Result<Self> {
        let prepared = prepare_restore(backup, key_path)?;
        Self::restore_from(prepared, destination, password, input, otp::now()?)
    }
    /// Phase 3 of a login (spec §5.2). `otp_time` is when the code was
    /// typed, so a question in between does not let it expire;
    /// `confirmed_older` is the SHA-256 of the older-key vault file the user
    /// agreed to open (S-OLDER).
    pub fn login(
        prepared: Prepared,
        password: &str,
        input: &str,
        otp_time: u64,
        confirmed_older: Option<[u8; 32]>,
    ) -> Result<Self> {
        let factors = (password, input, otp_time);
        Self::load(prepared, factors, None, confirmed_older, None)
    }
    /// Phase 3 of a Restore into the new file `destination`.
    pub fn restore_from(
        prepared: Prepared,
        destination: &Path,
        password: &str,
        input: &str,
        otp_time: u64,
    ) -> Result<Self> {
        let factors = (password, input, otp_time);
        Self::load(prepared, factors, None, None, Some(destination))
    }
    /// Phase 3 of a login with a key file that needs a security key: the
    /// same with the touch of the unlock's ceremony (spec §5.2 step 3).
    #[cfg(feature = "security-key")]
    pub fn login_with(
        prepared: Prepared,
        password: &str,
        input: &str,
        otp_time: u64,
        confirmed_older: Option<[u8; 32]>,
        touch: &Touch,
    ) -> Result<Self> {
        let factors = (password, input, otp_time);
        Self::load(prepared, factors, Some(touch), confirmed_older, None)
    }
    /// Phase 3 of a Restore with such a key file.
    #[cfg(feature = "security-key")]
    pub fn restore_with(
        prepared: Prepared,
        destination: &Path,
        password: &str,
        input: &str,
        otp_time: u64,
        touch: &Touch,
    ) -> Result<Self> {
        let factors = (password, input, otp_time);
        Self::load(prepared, factors, Some(touch), None, Some(destination))
    }
    /// `factors`: the password, the OTP code as typed and when it was typed.
    fn load(
        prepared: Prepared,
        factors: (&str, &str, u64),
        touch: Option<&Touch>,
        confirmed_older: Option<[u8; 32]>,
        destination: Option<&Path>,
    ) -> Result<Self> {
        let (password, input, otp_time) = factors;
        if password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        let Prepared {
            source,
            key_path,
            key,
            key_temp,
            seen,
            ..
        } = prepared;
        let login = destination.is_none();
        // Restore inputs and key files are immutable read snapshots. They may be
        // on read-only media; only the live output needs a writable sidecar lock.
        let mut locks = if login {
            vec![FileLock::acquire(&source)?]
        } else {
            Vec::new()
        };
        // A security-key file: no key derivation, no failure (spec §5.2).
        if let Some(refusal) = key.refusal() {
            return Err(refusal);
        }
        // A malformed code fails before the slow key derivation.
        if key.uses_otp() && !otp_format(input) {
            return Err(AUTH_ERROR);
        }
        let opened = key.open(password, touch)?;
        #[cfg(feature = "security-key")]
        let unlocked_with = opened
            .slot
            .and_then(|j| key.header()?.slots.get(usize::from(j)))
            .map(|slot| slot.number);
        let id = key.vault_id().ok_or(AUTH_ERROR)?;
        let kf2 = key.header();
        let kf2_ids = kf2.map(|h| h.key_ids.as_slice());
        let keys = opened.bundle;
        let key_state = opened.state;
        // A 0.8 key file of a vault this PC converted: its state needs its
        // data key, so the anchor compares it only now (spec §5.1 step 9).
        // Refused as before any derivation: not a failed attempt.
        let confirmed = seen.confirmed();
        let mut class = seen.class;
        if class == AnchorClass::Legacy {
            let line = confirmed.as_ref().ok_or(AUTH_ERROR)?;
            class = match anchor::compare_opened_legacy(key_state, line) {
                Ok(class) => class,
                Err(Refusal::Fork) if !login => AnchorClass::Fork,
                Err(refusal) => return Err(refused(refusal)),
            };
        }
        // A changed key file whose gate has not passed: gate-pending mode
        // for a login; a Restore runs held instead (spec §5.1, S45-3 #3).
        #[cfg(feature = "security-key")]
        let gated = match class {
            AnchorClass::Gated(kind) if login => Some(kind),
            _ => None,
        };
        #[cfg(not(feature = "security-key"))]
        let gated: Option<()> = None;
        let consumed = confirmed.as_ref().and_then(|l| l.state.consumed);
        let (format, header, mut contents, index, vault_temp, resumed) =
            match read_bounded(&source, MAX_FILE) {
                Ok(data) => {
                    let (_, header) = read_header(&data)?;
                    let hardware = !cfg!(feature = "security-key") && header.hardware();
                    let index = key_index(kf2_ids, &header).ok_or(if hardware {
                        NO_SECURITY_KEY_SUPPORT_VAULT
                    } else if login {
                        KEY_NOT_IN_KEY_FILE
                    } else {
                        KEY_NOT_IN_BACKUP
                    })?;
                    // A login takes an older-key vault file only as the one
                    // the key file's last change expects to replace (its
                    // `resume`, authenticated now) and that change did not
                    // complete here yet, or as the bytes the user agreed to
                    // open; a Restore under any key.
                    let mut resumed = false;
                    if index > 0 && login {
                        let sha = sha256(&data);
                        resumed = kf2.is_some_and(|h| h.resume == sha) && consumed != Some(sha);
                        if !resumed && confirmed_older != Some(sha) {
                            return Err(OLDER_NOT_CONFIRMED);
                        }
                    }
                    let key = keys.keys().get(index).ok_or(AUTH_ERROR)?;
                    let (format, header, contents) = decode_data(&id, key, keys.id_key(), &data)?;
                    (format, header, contents, index, None, resumed)
                }
                // A vault file missing after a save was cut off comes back from
                // its temp copy under the current key (rule iii). A restore
                // never takes a temp copy: its source is the file the user
                // picked.
                Err(e) if login && !source.exists() => {
                    let (temp, format, header, contents) = recover::vault_candidate(
                        &source, &id, &keys, kf2_ids,
                    )
                    .ok_or(if leftover_temp(&source) {
                        LEFTOVER_TEMP
                    } else {
                        e
                    })?;
                    (format, header, contents, 0, Some(temp), false)
                }
                Err(e) => return Err(e),
            };
        // A vault file under an older key authenticates only under a key
        // that old key-file copies hold: its counters are not trusted (spec
        // §5.2 step 5). Refused above GEN_CEILING, before anything is
        // written; `seen` never above `generation`, the OTP watermark never
        // ahead of the clock, as a merge takes them.
        if index > 0 {
            if contents.generation > GEN_CEILING || contents.seen > GEN_CEILING {
                return Err(VAULT_COUNTERS);
            }
            contents.seen = contents.seen.min(contents.generation);
            contents.last = contents.last.min(otp::now()? / 30 + 1);
        }
        // The key-file state, and how far the vault file proves it (spec
        // §4.3): its header counts only under the current key, and only up
        // to EPOCH_SILENT above the key file.
        let (stale_key_file, max_epoch) = match header {
            Header::Keyed { state, .. } if index == 0 => (
                state.epoch > key_state.epoch,
                key_state.epoch.max(
                    state
                        .epoch
                        .min(key_state.epoch.saturating_add(EPOCH_SILENT)),
                ),
            ),
            _ => (false, key_state.epoch),
        };
        // Not under the current key with the key file's header: an older
        // key, a 0.8 header under a KF2 key file, or a key change that kept
        // the data key and did not save the vault file again.
        let rekeyed = index > 0
            || (kf2.is_some() && header == Header::Legacy)
            || matches!(header, Header::Keyed { state, .. } if state.epoch < key_state.epoch);
        // A synced copy is merged (in memory) before the OTP check, so that a
        // code already used on another PC is refused once its content synced.
        // Not when this login is a local rollback: whoever put the older pair
        // back may know its key, so nothing is fetched (S23-2 #5).
        let own = sync::Own {
            id: &id,
            keys: &keys,
            ids: kf2_ids,
            state: key_state,
            hold: class == AnchorClass::Rollback || gated.is_some(),
        };
        let pending = sync::Pending::find(login, &source, &key_path, format, own, contents.view());
        let Contents {
            last,
            generation,
            seen: seen_generation,
            entries,
            tombstones,
        } = contents;
        let step = match keys.otp() {
            // Checked as of when it was typed, at most OTP_TYPED_MAX ago.
            Some(secret) => {
                let now = otp::now()?;
                if now.saturating_sub(otp_time) > OTP_TYPED_MAX || otp_time > now.saturating_add(5)
                {
                    return Err(AUTH_ERROR);
                }
                otp::verify(secret, input, otp_time, Some(pending.last(last)))
                    .map_err(|_| AUTH_ERROR)?
            }
            None => last,
        };
        let path = if let Some(dest) = destination {
            let dest = normalized(dest)?;
            distinct(&dest, &key_path)?;
            distinct(&dest, &source)?;
            if dest.exists() {
                return Err("복원 대상은 새 파일이어야 합니다.");
            }
            locks.push(FileLock::acquire(&dest)?);
            dest
        } else {
            source
        };
        // A backup or restore keeps the format, IDs, tombstones and counters.
        let mut s = Session::new(path, key_path, id, keys, key, key_state);
        s.serial = u64::from_le_bytes(*crypto::random::<8>()?);
        (s.last, s.format, s.generation, s.seen) = (step, format, generation, seen_generation);
        (s.entries, s.tombstones) = (entries, tombstones);
        (s.max_epoch, s.stale_key_file) = (max_epoch, stale_key_file);
        #[cfg(feature = "security-key")]
        {
            s.unlocked_with = unlocked_with;
        }
        s._locks = locks;
        s.anchor = AnchorView {
            dir: seen.dir.clone(),
            lines: seen.lines.clone(),
            frozen: seen.newer,
            ..AnchorView::default()
        };
        // An older state of this PC: held until the user confirms it. A
        // Restore with a key file other than the confirmed one, or while a
        // key change of this PC waits for a login, runs held too and takes
        // no key file (spec §5.1).
        #[cfg(feature = "security-key")]
        let would_gate = matches!(class, AnchorClass::Gated(_));
        #[cfg(not(feature = "security-key"))]
        let would_gate = false;
        let restore_held = !login
            && (matches!(class, AnchorClass::Fork | AnchorClass::Rollback)
                || would_gate
                || seen.lines.pending.is_some());
        s.local_rollback = class == AnchorClass::Rollback || restore_held;
        (s.restore_held, s.restored) = (restore_held, !login);
        // Trust on first use (spec §5.2 step 9(a), §7.17), judged by the
        // confirmed line: a key file with security keys, or a bootstrap,
        // with no line or a line without `t`. Never a held session, nor one
        // waiting for its login gate; a held session keeps TOFU's refusals
        // on top of the hold instead (S45-3 #2). A Restore of a key file
        // with security keys this PC has no record of writes nothing until
        // G1, nor does a held one (no `vault` line, only a pending one).
        #[cfg(feature = "security-key")]
        let bootstrap_restore = {
            s.forgotten = seen.forgotten;
            let hardware = s.key_file.needs_security_key();
            s.gate_login = gated.map(|kind| gate::GateLogin {
                state: key_state,
                kind,
            });
            let unconfirmed = (hardware || class == AnchorClass::Bootstrap)
                && gated.is_none()
                && confirmed.as_ref().is_none_or(|l| !l.state.flags.t);
            s.tofu = unconfirmed && !s.local_rollback;
            s.held_unconfirmed = unconfirmed && s.local_rollback;
            !login && unconfirmed && confirmed.is_none()
        };
        #[cfg(not(feature = "security-key"))]
        let bootstrap_restore = false;
        // The vault file's name back first, without replacing a file that
        // appeared meanwhile; if the rename fails, the contents are saved
        // under it instead.
        if let Some(temp) = vault_temp {
            if publish(&temp, &s.path, false).is_ok() {
                flush(&s.path);
            } else {
                let data = s.encode().map_err(too_large_to_resave)?;
                s.write_with(&data, false)?;
            }
            s.recovered.vault = true;
        }
        // Only now that the code passed: save a merge that changed anything,
        // with the consumed OTP, under the current key. If that fails it
        // opens unmerged instead.
        let merged = s.settle(pending);
        // That save hit the replace gap: the merge is only in a temp file,
        // which the next unlock takes back.
        if s.gap_kept {
            return Err(GAP_KEPT);
        }
        // Persist the consumed OTP before exposing any secret. Backup rollback
        // and modified clients cannot be prevented by this local watermark.
        // Without an OTP an unlock writes only a restore and a vault file
        // not yet under the current key with this key file's header.
        let otp = s.uses_otp();
        let mut too_large = false;
        // Gate-pending mode and a bootstrap Restore write no vault file
        // before the gate: the pass does it (spec §5.2 step 8, §7.17).
        let deferred = gated.is_some() || bootstrap_restore;
        #[cfg(feature = "security-key")]
        {
            s.deferred.resave = deferred && !merged && (!login || otp || rekeyed);
        }
        if !merged && !deferred && (!login || otp || rekeyed) {
            let written = match s.encode() {
                Ok(data) => s.write_with(&data, login),
                // A 0.8 file within 44 bytes of the limit: the longer
                // header of this key file's format does not fit.
                Err(e) if e == VAULT_FULL => {
                    too_large = true;
                    Err(RESAVE_TOO_LARGE)
                }
                Err(e) => return Err(e),
            };
            if let Err(e) = written {
                // Only the re-save of a vault file without an OTP may wait:
                // the file on disk still opens as it did. A replace gap is
                // not a failed write: the newest state is only in its temp
                // file, which the next unlock takes back (spec §5.7).
                if s.gap_kept || !login || otp {
                    return Err(e);
                }
                s.resave_due = true;
            }
        }
        // An OTP vault in gate-pending mode still persists the consumed step
        // before any secret is exposed (spec §5.2 step 8, stage 4): the vault
        // file is written again under exactly the key and header it was read
        // with, so nothing goes under the changed key file's data key before
        // its gate; the re-save under it waits for the pass.
        #[cfg(feature = "security-key")]
        if !merged && gated.is_some() && otp {
            let key = s.keys.keys().get(index).ok_or(AUTH_ERROR)?;
            let data = encode_data(&s.id, key, &header, s.format, s.data())?;
            s.write_with(&data, true)?;
        }
        if login {
            // The anchor (spec §5.2 step 7, step 9): this PC's pending change
            // promoted or dropped, the confirmed line of a new or later key
            // file, and the vault file now current sealed. A Restore never
            // writes it (S23-3 #18).
            let first = if too_large {
                Some(KeyNotice::ResaveTooLarge)
            } else if s.resave_due {
                Some(KeyNotice::ResavePending)
            } else if index > 0 && resumed {
                Some(KeyNotice::Resumed)
            } else if index > 0 {
                Some(KeyNotice::OlderAccepted)
            } else if stale_key_file {
                Some(KeyNotice::StaleKeyFile)
            } else {
                None
            };
            s.key_notices.extend(first.clone());
            let dropped = s.anchor_at_unlock(&seen, class, index == 0, rekeyed)?;
            // A removal that never landed names its keys (S-REMOVE-UNDONE,
            // spec §5.2 step 7): this PC is not protected yet.
            #[cfg(feature = "security-key")]
            let undone = dropped
                .as_ref()
                .filter(|p| {
                    matches!(
                        p.src,
                        anchor::Src::Lost
                            | anchor::Src::Retire
                            | anchor::Src::Adopt
                            | anchor::Src::Accept
                    ) && !p.rm.is_empty()
                })
                .map(|p| p.rm.iter().map(|(n, _)| *n).collect::<Vec<u8>>());
            #[cfg(feature = "security-key")]
            {
                s.redo = dropped.as_ref().and_then(rotate::Redo::of);
            }
            let not_finished = dropped.is_some();
            // The post-removal review due from the anchor or the merge log
            // (spec §5.13 "Due is durable").
            #[cfg(feature = "security-key")]
            s.review_load();
            // The unlock key's own pair records that do not open (spec §5.2
            // step 9(c)).
            #[cfg(feature = "security-key")]
            if let Some(touch) = touch
                && !s.forgotten
            {
                s.check_own_pairs(touch);
            }
            if class == AnchorClass::Rollback {
                let old = confirmed.as_ref().map_or(0, |l| l.state.epoch);
                s.key_notices.push(KeyNotice::LocalRollback {
                    old,
                    new: key_state.epoch,
                });
            }
            if let Some(path) = &s.pending_elsewhere {
                s.key_notices
                    .push(KeyNotice::PendingElsewhere(path.clone()));
            }
            // The unlock succeeded: the key file's name goes back to the temp
            // copy it came from, or the session keeps using the copy.
            let key_path = s.key_path.clone();
            if let Some(temp) = key_temp
                && !recover::restore_key(&temp, &key_path)
            {
                s.key_path = temp.clone();
                s.recovered.key_kept = Some(temp);
            }
            // Temp files that hold nothing the opened files lack (rule iv).
            // A key file's temp of a later epoch is a change that never
            // landed: told once, with a pending entry dropped above.
            if recover::clean(&s, &key_path) || not_finished {
                #[cfg(feature = "security-key")]
                let notice = match undone {
                    Some(numbers) => KeyNotice::RemoveUndone(numbers),
                    None => KeyNotice::NotFinished,
                };
                #[cfg(not(feature = "security-key"))]
                let notice = KeyNotice::NotFinished;
                s.key_notices.insert(usize::from(first.is_some()), notice);
            }
            s.key_backup_due = s.key_file.header().is_some()
                && !s
                    .anchor
                    .lines
                    .vault
                    .as_ref()
                    .is_some_and(|v| v.state.key_state() == key_state && v.state.flags.b);
            if s.key_backup_due {
                s.key_notices.push(KeyNotice::KeyBackupDue);
            }
        } else if restore_held {
            let old = confirmed.as_ref().map_or(0, |l| l.state.epoch);
            s.key_notices.push(if seen.lines.pending.is_some() {
                KeyNotice::RestorePending
            } else {
                KeyNotice::RestoreOldKey {
                    old,
                    new: key_state.epoch,
                }
            });
        }
        // A login that moved the vault file to the current key, or completed
        // a key change of this PC, offers its state at once, whatever
        // incoming showed: an outgoing copy under an older key must not stay
        // (spec §14.5 I5).
        if login
            && (rekeyed || matches!(seen.pending, Decision::Promote { .. }))
            && let Some(link) = s.sync.as_mut()
        {
            link.mark_due();
        }
        // Outgoing only after the vault file: the server never holds content
        // the file lacks. Held during a local rollback.
        s.flush_outgoing();
        Ok(s)
    }
    /// The anchor at a login (spec §5.2 step 7): a pending change of this PC
    /// promoted when it landed, dropped when it never did; a new or later
    /// password-only key file recorded silently; and, when the vault file
    /// the unlock read is current under the key file's current key, or a
    /// change completed and it is now, its key and the change's resume digest
    /// sealed (`vkey`, `consumed`), so the change never completes silently
    /// again. A 0.8 session writes nothing of its own. Every change of these
    /// lines is one locked write, made only while they are still what the
    /// precheck read; when it cannot be written, a password-only session
    /// keeps it in memory. Returns the pending entry of this PC's own that
    /// was dropped, if any.
    fn anchor_at_unlock(
        &mut self,
        seen: &Seen,
        class: AnchorClass,
        current_at_read: bool,
        rekeyed: bool,
    ) -> Result<Option<anchor::PendingLine>> {
        // A forgotten record is written by the TOFU pass alone.
        #[cfg(feature = "security-key")]
        if seen.forgotten {
            self.deferred.seal = current_at_read || (rekeyed && self.current());
            return Ok(None);
        }
        let snapshot = seen.lines.clone();
        let mut wanted = snapshot.clone();
        let mut dropped = None;
        match &seen.pending {
            Decision::Promote { .. } => {
                if let Some(p) = wanted.pending.take() {
                    wanted.vault = Some(p.promoted(wanted.vault.as_ref()));
                }
            }
            Decision::Drop { .. } => {
                // A dropped TOFU entry is no change of this PC's own.
                dropped = snapshot
                    .pending
                    .clone()
                    .filter(|p| p.src != anchor::Src::Tofu);
                wanted.pending = None;
            }
            Decision::Leave(path) => self.pending_elsewhere = Some(path.clone()),
            Decision::None => {}
        }
        let kf2 = self.key_file.header().cloned();
        if let Some(h) = &kf2 {
            match class {
                AnchorClass::New => wanted.vault = Some(anchor::line_of(h, None)),
                AnchorClass::Newer => {
                    wanted.vault = Some(anchor::line_of(h, wanted.vault.as_ref()));
                }
                _ => {}
            }
            #[cfg_attr(not(feature = "security-key"), allow(unused_mut))]
            let mut seal =
                class != AnchorClass::Rollback && (current_at_read || (rekeyed && self.current()));
            // The vault file could not be saved under the current key yet:
            // the save that does it seals the change.
            self.seal_due = !seal && class != AnchorClass::Rollback && rekeyed;
            // In gate-pending mode or TOFU, K's state is not confirmed yet:
            // its seal waits for the pass (spec §5.2 step 7).
            #[cfg(feature = "security-key")]
            if self.tofu || self.gate_login.is_some() {
                self.deferred.seal = seal;
                (seal, self.seal_due) = (false, false);
            }
            if let Some(v) = wanted.vault.as_mut().filter(|_| seal)
                && v.state.key_state() == self.key_state
            {
                v.vkey = Some(h.current_key_id());
                if h.resume != [0; 32] {
                    v.state.consumed = Some(h.resume);
                }
            }
        }
        let changed = (&wanted.vault, &wanted.pending) != (&snapshot.vault, &snapshot.pending);
        // Line order is recency: an unlock moves its vault's lines first.
        let moved = kf2.is_some() && wanted.vault.is_some() && !snapshot.first;
        let mut differed = false;
        if changed || moved {
            let promoted = matches!(seen.pending, Decision::Promote { .. });
            self.anchor_update(anchor::LOCK_WAIT, &mut |lines| {
                if (&lines.vault, &lines.pending) != (&snapshot.vault, &snapshot.pending) {
                    differed = true;
                    return false;
                }
                // The gate effects of this PC's own landed change (spec
                // §7.15a).
                #[cfg(feature = "security-key")]
                if let Some(p) = snapshot.pending.as_ref().filter(|_| promoted) {
                    anchor::apply_clears(lines, p);
                    anchor::apply_review(lines, p);
                    anchor::apply_clone(lines, p);
                }
                #[cfg(not(feature = "security-key"))]
                let _ = promoted;
                lines.vault = wanted.vault.clone();
                lines.pending = wanted.pending.clone();
                true
            })?;
        }
        // The lines under the lock are not the ones the key file was
        // compared with: a read that failed at precheck took a put-back key
        // file for a new one, say. Nothing is written, and the next try
        // compares again.
        if differed {
            return Err(ANCHOR_REREAD);
        }
        Ok(dropped)
    }
    /// Whether the vault file on disk is under the current key with this
    /// key file's state: the change it waited for is complete.
    fn current(&self) -> bool {
        let Some(h) = self.key_file.header() else {
            return false;
        };
        let head = keyfile::read_head(&self.path, KEYED_OVERHEAD + 32).unwrap_or_default();
        matches!(
            read_header(&head),
            Ok((_, Header::Keyed { key_id, state, .. }))
                if key_id == h.current_key_id() && state == self.key_state
        )
    }
    /// Writes this vault's anchor lines through `change` (spec §5.10),
    /// waiting at most `wait` for another process's lock. When the anchor
    /// cannot be written, a password-only session keeps the lines in memory
    /// and says so once (S-SIDECAR-FAILED, or S-ANCHOR-NEWER for a later
    /// version's file, which is never written); every save and poll tries
    /// again. A security-key session keeps them the same way, held by
    /// AnchorFailed meanwhile (S-ANCHOR-FAILED). Ok(false) then; Err only
    /// for a test's simulated crash.
    fn anchor_update(
        &mut self,
        wait: std::time::Duration,
        change: &mut dyn FnMut(&mut anchor::Lines) -> bool,
    ) -> Result<bool> {
        let failure = match (&self.anchor.dir, self.anchor.frozen) {
            (Some(dir), false) => {
                let held = self.anchor.unsaved.then(|| self.anchor.lines.clone());
                let result = anchor::update(dir, &self.id, wait, &mut |lines| {
                    if let Some(held) = &held {
                        lines.vault.clone_from(&held.vault);
                        lines.pending.clone_from(&held.pending);
                    }
                    change(lines) || held.is_some()
                });
                match result {
                    Ok(lines) => {
                        self.anchor.lines = lines;
                        self.anchor.unsaved = false;
                        #[cfg(feature = "security-key")]
                        {
                            self.anchor_failed = false;
                        }
                        return Ok(true);
                    }
                    #[cfg(test)]
                    Err(anchor::Failure::Crash) => return Err(SIMULATED_CRASH),
                    Err(failure) => failure,
                }
            }
            (Some(_), true) => anchor::Failure::Newer,
            (None, _) => anchor::Failure::Io,
        };
        let mut lines = self.anchor.lines.clone();
        if change(&mut lines) {
            self.anchor.lines = lines;
            self.anchor.unsaved = true;
        }
        if failure == anchor::Failure::Newer {
            self.anchor.frozen = true;
        }
        // A security-key session is held meanwhile (AnchorFailed).
        #[cfg(feature = "security-key")]
        let failed = {
            let hardware = self.hardware_anchor();
            self.anchor_failed |= hardware && self.anchor.unsaved;
            if hardware {
                KeyNotice::AnchorFailed
            } else {
                KeyNotice::SidecarFailed
            }
        };
        #[cfg(not(feature = "security-key"))]
        let failed = KeyNotice::SidecarFailed;
        if self.anchor.unsaved && !std::mem::replace(&mut self.anchor.told, true) {
            self.key_notices.push(if self.anchor.frozen {
                KeyNotice::AnchorNewer
            } else {
                failed
            });
        }
        Ok(false)
    }
    /// Writes the anchor lines this session holds only in memory, if any
    /// (spec §5.10): at every save and poll, without waiting for a busy
    /// lock.
    fn retry_anchor(&mut self) {
        if self.anchor.unsaved && !self.anchor.frozen {
            let _ = self.anchor_update(std::time::Duration::ZERO, &mut |_| false);
        }
    }
    /// What this unlock took back from temp files an interrupted save left;
    /// the next call returns nothing.
    pub fn take_recovery(&mut self) -> Recovery {
        std::mem::take(&mut self.recovered)
    }
    /// What the unlock, a key change or a later save found about the key
    /// and vault files, in the order they are shown; the next call returns
    /// only what came since.
    pub fn take_key_notices(&mut self) -> Vec<KeyNotice> {
        std::mem::take(&mut self.key_notices)
    }
    /// The key file's state (spec §4.3).
    pub fn key_state(&self) -> KeyState {
        self.key_state
    }
    /// The highest key-file epoch the opened key and vault files prove.
    pub fn max_epoch(&self) -> u64 {
        self.max_epoch
    }
    /// The vault file was ahead of the key file (StaleKeyFile).
    pub fn stale_key_file(&self) -> bool {
        self.stale_key_file
    }
    /// A save of the vault file hit the replace gap: this session writes it
    /// no more, and the app locks (spec §5.7).
    pub fn gap_kept(&self) -> bool {
        self.gap_kept
    }
    /// The key file is an older state of this PC, or a Restore read a key
    /// file other than the one this PC confirmed: no key change, outgoing
    /// write or merge until the user confirms it (spec §5.10).
    pub fn local_rollback(&self) -> bool {
        self.local_rollback
    }
    /// A Restore held as above, which takes no key file either (spec §5.1).
    pub fn restore_held(&self) -> bool {
        self.restore_held
    }
    /// Opened by a Restore: no key change or adopt (RESTORE_KEYS).
    pub fn restored(&self) -> bool {
        self.restored
    }
    /// A Restore held because a key change of this PC is still pending
    /// (S-RESTORE-PENDING rather than S-RESTORE-OLDKEY).
    pub fn restore_pending(&self) -> bool {
        self.restore_held && self.anchor.lines.pending.is_some()
    }
    /// The key code of the key file's state (spec §4.8), as the Keys screen
    /// shows it: `E{epoch} · XXXX-XXXX-XXXX-XXXX`. None for a 0.8 key file,
    /// which has none.
    pub fn key_code(&self) -> Option<String> {
        self.key_file.header()?;
        // Not before the key file is confirmed: gate-pending mode shows only
        // the anchor, and TOFU asks for the code instead (spec §5.10,
        // §7.17).
        #[cfg(feature = "security-key")]
        if self.tofu || self.gate_login.is_some() {
            return None;
        }
        let code = keyfile::key_code(&self.id, self.keys.current(), self.key_state);
        Some(code.show(self.key_state.epoch))
    }
    /// The number of the security key this session was unlocked with.
    #[cfg(feature = "security-key")]
    pub fn unlocked_with(&self) -> Option<u8> {
        self.unlocked_with
    }
    /// The key file a key change of this PC may have landed in, which could
    /// not be read: no key change until an unlock with it, or the user's
    /// discard (spec §5.1 step 9).
    pub fn pending_elsewhere(&self) -> Option<&Path> {
        self.pending_elsewhere.as_deref()
    }
    /// The key file of this state has no key backup yet.
    pub fn key_backup_due(&self) -> bool {
        self.key_backup_due
    }
    /// The new key file is only a temp file whose rename is retried (spec
    /// §5.5 S2).
    pub fn key_temp(&self) -> bool {
        self.key_temp.is_some()
    }
    /// A key change could not tell whether it saved the new key file: this
    /// session holds it for a key backup and writes nothing more (spec
    /// §5.5 S2).
    pub fn key_unsaved(&self) -> bool {
        self.unsaved_key.is_some()
    }
    /// The epoch of the state this PC confirmed for this vault, for the
    /// local-rollback texts; None without a line.
    pub fn confirmed_epoch(&self) -> Option<u64> {
        self.anchor.lines.vault.as_ref().map(|v| v.state.epoch)
    }
    fn data(&self) -> DataRef<'_> {
        DataRef {
            last: self.last,
            generation: self.generation,
            seen: self.seen,
            entries: &self.entries,
            tombstones: &self.tombstones,
        }
    }
    /// The header this session writes (spec §4.4): GOYOVA01/02 under a 0.8
    /// key file, else GOYOVA03/04 with the current key and the key file's
    /// state.
    fn header(&self) -> Header {
        match self.key_file.header() {
            Some(h) => Header::Keyed {
                key_id: h.current_key_id(),
                state: self.key_state,
                flags: Header::flags_of(h.magic),
            },
            None => Header::Legacy,
        }
    }
    /// `d` as a vault file of this session in `format`, under the current
    /// key.
    fn encode_as(&self, format: Format, d: DataRef) -> Result<Vec<u8>> {
        encode_data(&self.id, self.keys.current(), &self.header(), format, d)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.encode_as(self.format, self.data())
    }
    pub fn save(&mut self) -> Result<()> {
        let data = self.encode()?;
        self.write(&data)?;
        // What a key change left to finish: the key file's name, and the
        // anchor lines held in memory (spec §5.5 S2, §5.10).
        self.seal_saved();
        self.retry_key_temp();
        self.retry_anchor();
        Ok(())
    }
    /// Before the app locks: one more try at what a key change left to
    /// finish (spec §5.5 S2).
    pub fn before_lock(&mut self) {
        self.retry_key_temp();
        self.retry_anchor();
    }
    /// Writes `data`, a state of this session, as the vault file. A replace
    /// cut off by the FAT/exFAT gap leaves the vault file gone and the new
    /// state only in its temp file, which the next unlock takes back (rule
    /// iii) while the vault file is missing. So from then on this session
    /// writes the vault file no more: a later save would give the name to a
    /// state without that change, and the temp file would never be read
    /// again. The app locks on GAP_KEPT. Every write of the vault file goes
    /// through here (spec §5.7).
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.write_with(data, true)
    }
    /// `write`, or with `replace` false the vault file's first write.
    fn write_with(&mut self, data: &[u8], replace: bool) -> Result<()> {
        if self.gap_kept {
            return Err(GAP_KEPT);
        }
        // A key change could not tell whether it saved the new key file: the
        // vault file stays as it is, and both key files open it (spec §5.5
        // S2).
        if self.unsaved_key.is_some() {
            return Err(rotate::KEY_DAMAGED);
        }
        let result = atomic_write(&self.path, data, replace);
        self.gap_kept = matches!(result, Err(AtomicError::GapKept(_)));
        // Every state written is under the current key.
        self.resave_due &= result.is_err();
        result.map_err(Into::into)
    }
    /// Adds an entry (`None`) or replaces entry `index`. An edit gets a new
    /// ID whose parent is the old one, and the old ID becomes a tombstone: a
    /// copy synced from another PC can then neither bring the old text back
    /// nor hide this edit. Saving unchanged text changes nothing.
    pub fn put(&mut self, index: Option<usize>, mut entry: Entry) -> Result<()> {
        // No edit before the key file is confirmed (spec §5.2, §7.17).
        #[cfg(feature = "security-key")]
        self.edit_held()?;
        entry.validate()?;
        let previous = self.generation;
        if let Some(i) = index {
            let old = self.entries.get(i).ok_or("항목 선택 오류")?;
            if old.same_content(&entry) {
                return Ok(());
            }
            let parent = old.id;
            if self.tombstones.len() >= MAX_TOMBSTONES {
                return Err(TOMBSTONE_LIMIT);
            }
            let generation = previous.checked_add(1).ok_or(TOMBSTONE_LIMIT)?;
            entry.id = self.fresh_id()?;
            entry.parent = parent;
            self.tombstones.push(parent);
            self.generation = generation;
            let old = std::mem::replace(&mut self.entries[i], entry);
            if let Err(e) = self.save() {
                self.entries[i] = old;
                self.tombstones.pop();
                self.generation = previous;
                return Err(e);
            }
        } else {
            if self.entries.len() >= MAX_ENTRIES {
                return Err("최대 1000개까지 저장할 수 있습니다.");
            }
            let generation = previous.checked_add(1).ok_or(TOMBSTONE_LIMIT)?;
            entry.id = self.fresh_id()?;
            entry.parent = NO_ID;
            self.entries.push(entry);
            self.generation = generation;
            if let Err(e) = self.save() {
                self.entries.pop();
                self.generation = previous;
                return Err(e);
            }
        }
        self.after_edit();
        Ok(())
    }
    /// Removes entry `i` and keeps its ID as a tombstone, so the deletion
    /// reaches the other PCs instead of their copies bringing it back.
    pub fn delete(&mut self, i: usize) -> Result<()> {
        #[cfg(feature = "security-key")]
        self.edit_held()?;
        if i >= self.entries.len() {
            return Err("항목 선택 오류");
        }
        if self.tombstones.len() >= MAX_TOMBSTONES {
            return Err(TOMBSTONE_LIMIT);
        }
        let previous = self.generation;
        let generation = previous.checked_add(1).ok_or(TOMBSTONE_LIMIT)?;
        let old = self.entries.remove(i);
        self.tombstones.push(old.id);
        self.generation = generation;
        if let Err(e) = self.save() {
            self.tombstones.pop();
            self.entries.insert(i, old);
            self.generation = previous;
            return Err(e);
        }
        self.after_edit();
        Ok(())
    }
    /// A random ID that is not zero, live or a tombstone.
    fn fresh_id(&self) -> Result<EntryId> {
        loop {
            let id = *crypto::random::<16>()?;
            if id != NO_ID && self.entry_index(&id).is_none() && !self.tombstones.contains(&id) {
                return Ok(id);
            }
        }
    }
    /// The ID of entry `i`. Unlike the index it stays valid across merges.
    pub fn entry_id(&self, i: usize) -> Option<EntryId> {
        self.entries.get(i).map(Entry::id)
    }
    pub fn entry_index(&self, id: &EntryId) -> Option<usize> {
        self.entries.iter().position(|e| e.id == *id)
    }
    /// The entry that replaced `id` by an edit, if exactly one did, so that a
    /// selection can follow an edit merged in from another PC.
    pub fn successor(&self, id: &EntryId) -> Option<usize> {
        if *id == NO_ID {
            return None;
        }
        let mut found = (0..self.entries.len()).filter(|i| self.entries[*i].parent == *id);
        match (found.next(), found.next()) {
            (Some(i), None) => Some(i),
            _ => None,
        }
    }
    pub fn format(&self) -> Format {
        self.format
    }
    /// Turns a v1 vault into v2 once the user agreed to sync it. IDs are
    /// derived as for any v1 file, so a copy converted on another PC gets the
    /// same ones and merging the two makes no duplicates. A v2 vault is left
    /// as it is. If the save fails, everything is restored and it stays v1.
    /// Then the session links to the sync folder and offers its state for
    /// the first upload; read `badge()` again afterwards.
    pub fn enable_sync(&mut self) -> Result<()> {
        #[cfg(feature = "security-key")]
        self.edit_held()?;
        let converting = self.format == Format::V1;
        if converting {
            let ids: Vec<(EntryId, EntryId)> =
                self.entries.iter().map(|e| (e.id, e.parent)).collect();
            let tombstones = std::mem::take(&mut self.tombstones);
            let (generation, seen) = (self.generation, self.seen);
            v1_ids(&self.id, self.keys.id_key(), &mut self.entries);
            (self.generation, self.seen, self.format) = (1, 0, Format::V2);
            if let Err(e) = self.save() {
                for (entry, (id, parent)) in self.entries.iter_mut().zip(ids) {
                    entry.set_ids(id, parent);
                }
                self.tombstones = tombstones;
                (self.generation, self.seen, self.format) = (generation, seen, Format::V1);
                return Err(e);
            }
        }
        self.start_sync(converting);
        Ok(())
    }
    pub fn backup(&self, path: &Path) -> Result<()> {
        let path = normalized(path)?;
        distinct(&path, &self.path)?;
        distinct(&path, &self.key_path)?;
        let _lock = FileLock::acquire(&path)?;
        atomic_write(&path, &self.encode()?, false).map_err(Into::into)
    }
    /// Saves a copy of the key file at `path` and reads it back (spec
    /// §5.10). The key file on disk must still be this session's, or, after
    /// a key change whose rename was cut off, the temp file standing in for
    /// it. When a key change could not tell whether it saved the key file,
    /// or once the key file and that temp file are both gone, the copy comes
    /// from memory: it is the one key file that opens the vault file. A
    /// backup of this session's KF2 state is recorded in the anchor (`b`).
    pub fn backup_key(&mut self, path: &Path) -> Result<()> {
        let bytes = match &self.unsaved_key {
            Some(bytes) => bytes.clone(),
            None => self.key_file.bytes().to_vec(),
        };
        if !self.key_file_damaged {
            let disk = read_bounded(&self.key_path, KEY_FILE_LIMIT);
            let disk = match &self.key_temp {
                // The rename may have happened meanwhile, by this session or
                // by another PC that opened the stick.
                Some(temp) if disk.as_ref().ok() != Some(&bytes) => {
                    read_bounded(temp, KEY_FILE_LIMIT)
                }
                _ => disk,
            }?;
            if disk != bytes {
                return Err(
                    "열쇠 파일이 변경되었습니다. 잠근 뒤 새 비밀번호로 다시 열고 백업하세요.",
                );
            }
        }
        let path = normalized(path)?;
        distinct(&path, &self.path)?;
        distinct(&path, &self.key_path)?;
        let _lock = FileLock::acquire(&path)?;
        atomic_write(&path, &bytes, false)?;
        if read_bounded(&path, KEY_FILE_LIMIT)? != bytes {
            return Err(BACKUP_NOT_VERIFIED);
        }
        if self.unsaved_key.is_none() {
            self.key_backup_due = false;
            if self.key_file.header().is_some() {
                let state = self.key_state;
                self.anchor_update(anchor::LOCK_WAIT, &mut |lines| match lines.vault.as_mut() {
                    Some(v) if v.state.key_state() == state && !v.state.flags.b => {
                        v.state.flags.b = true;
                        true
                    }
                    _ => false,
                })?;
            }
        }
        Ok(())
    }
    /// Whether this vault asks for an OTP code when it opens.
    pub fn uses_otp(&self) -> bool {
        self.keys.otp().is_some()
    }
    /// The TOTP secret again, to enroll a spare phone or app before the
    /// current one is lost. Storing it as a vault entry would not help: the
    /// vault cannot be opened without the OTP. The vault is already open, but
    /// the password is asked again so a window left open does not hand out
    /// the OTP.
    pub fn otp_setup(&self, password: &str) -> Result<OtpSetup> {
        let otp = self.keys.otp().ok_or("이 금고는 OTP를 쓰지 않습니다.")?;
        if password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        self.verify(password)?;
        Ok(OtpSetup {
            id: self.id,
            otp: boxed(otp),
        })
    }
    /// The OTP backup of a key file with security keys (spec §5.10): no
    /// password verifier is kept, so the key file opens again with the
    /// password and the touch of one of its live, non-suspended keys, to
    /// this session's keys. Nothing is written, and no OTP code is asked.
    #[cfg(feature = "security-key")]
    pub fn otp_setup_with(&self, password: &str, touch: &Touch) -> Result<OtpSetup> {
        let otp = self.keys.otp().ok_or("이 금고는 OTP를 쓰지 않습니다.")?;
        if password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        if !self
            .key_file
            .open(password, Some(touch))?
            .bundle
            .same(&self.keys)
        {
            return Err(AUTH_ERROR);
        }
        Ok(OtpSetup {
            id: self.id,
            otp: boxed(otp),
        })
    }
    pub fn tag(&self) -> String {
        tag(&self.id)
    }
    /// The key file in memory opens with `password` to this session's keys.
    fn verify(&self, password: &str) -> Result<()> {
        if !self.key_file.open(password, None)?.bundle.same(&self.keys) {
            return Err(AUTH_ERROR);
        }
        Ok(())
    }
}

fn otp_format(input: &str) -> bool {
    input.len() == 6 && input.bytes().all(|b| b.is_ascii_digit())
}
/// The decrypted contents of a vault file, or a merge result.
#[derive(Clone)]
pub(crate) struct Contents {
    pub last: u64,
    pub generation: u64,
    pub seen: u64,
    pub entries: Vec<Entry>,
    pub tombstones: Vec<EntryId>,
}
impl Contents {
    pub(crate) fn view(&self) -> DataRef<'_> {
        DataRef {
            last: self.last,
            generation: self.generation,
            seen: self.seen,
            entries: &self.entries,
            tombstones: &self.tombstones,
        }
    }
}
/// What `encode_data` writes, borrowed from a session or from `Contents`.
#[derive(Clone, Copy)]
pub(crate) struct DataRef<'a> {
    pub last: u64,
    pub generation: u64,
    pub seen: u64,
    pub entries: &'a [Entry],
    pub tombstones: &'a [EntryId],
}
/// Plaintext length of a file with these entries and `tombstones`
/// tombstones; the file adds its header's overhead (LEGACY_OVERHEAD or
/// KEYED_OVERHEAD). Entries must be validated.
pub(crate) fn plain_size(format: Format, entries: &[Entry], tombstones: usize) -> usize {
    let text: usize = entries
        .iter()
        .map(|e| e.fields().iter().map(|s| s.len()).sum::<usize>())
        .sum();
    match format {
        Format::V1 => 12 + 16 * entries.len() + text,
        Format::V2 => 28 + 48 * entries.len() + text + 4 + 16 * tombstones,
    }
}
/// First 16 bytes of HMAC-SHA256 under the data key over `label`, `prefix`
/// and the four fields. Keyed, so an ID reveals nothing about the text.
pub(crate) fn derived_id(
    key: &[u8; 32],
    label: &[u8],
    prefix: &[u8],
    fields: [&str; 4],
) -> EntryId {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(label);
    mac.update(prefix);
    for field in fields {
        mac.update(&(field.len() as u32).to_le_bytes());
        mac.update(field.as_bytes());
    }
    let mut hash = mac.finalize().into_bytes();
    let mut id: EntryId = hash[..16].try_into().unwrap();
    hash.as_mut_slice().zeroize();
    if id == NO_ID {
        id[0] = 1;
    }
    id
}
/// IDs for the entries of a v1 file, which stores none. They depend only on
/// the vault and the text, so two PCs that turn on sync for copies of the
/// same v1 vault get the same IDs. `k` tells apart entries whose four fields
/// are all equal.
fn v1_ids(vault: &[u8; 16], key: &[u8; 32], entries: &mut [Entry]) {
    let ids: Vec<EntryId> = {
        // Keys borrow the text: counting copies no secret.
        let mut earlier: BTreeMap<[&str; 4], u32> = BTreeMap::new();
        entries
            .iter()
            .map(|e| {
                let k = earlier.entry(e.fields()).or_insert(0);
                let mut prefix = [0u8; 20];
                prefix[..16].copy_from_slice(vault);
                prefix[16..].copy_from_slice(&k.to_le_bytes());
                *k += 1;
                derived_id(key, b"goyo v1 entry\0", &prefix, e.fields())
            })
            .collect()
    };
    for (e, id) in entries.iter_mut().zip(ids) {
        e.set_ids(id, NO_ID);
    }
}
/// The rules `decode_data` enforces on v2 IDs. `encode_data` checks them
/// too: a vault it could not read back would be lost.
fn check_ids(entries: &[Entry], tombstones: &[EntryId]) -> Result<()> {
    if tombstones.len() > MAX_TOMBSTONES {
        return Err(TOMBSTONE_LIMIT);
    }
    let mut live = BTreeSet::new();
    if entries.iter().any(|e| e.id == NO_ID || !live.insert(e.id)) {
        return Err("항목 ID 오류");
    }
    let mut dead = BTreeSet::new();
    if tombstones
        .iter()
        .any(|t| *t == NO_ID || live.contains(t) || !dead.insert(*t))
    {
        return Err("항목 ID 오류");
    }
    Ok(())
}
/// GOYOVA01 holds the OTP watermark and the entries. GOYOVA02 adds each
/// entry's ID and parent, `generation`, `seen` and the tombstones; V1
/// leaves those out. GOYOVA03/04 hold the same under a longer header
/// (spec §4.3), sealed with `key`, the data key that `header` names.
fn encode_data(
    id: &[u8; 16],
    key: &[u8; 32],
    header: &Header,
    format: Format,
    d: DataRef,
) -> Result<Vec<u8>> {
    if d.entries.len() > MAX_ENTRIES {
        return Err("항목 수 제한 초과");
    }
    if format == Format::V2 {
        check_ids(d.entries, d.tombstones)?;
    }
    for e in d.entries {
        e.validate()?;
    }
    // A header read_header would refuse is never written.
    if let Header::Keyed { state, flags, .. } = header
        && (!(1..=EPOCH_MAX).contains(&state.epoch) || !matches!(flags, 0 | 1 | 3))
    {
        return Err(EPOCH_LIMIT);
    }
    let size = plain_size(format, d.entries, d.tombstones.len());
    if size + header.overhead() > MAX_FILE {
        return Err(VAULT_FULL);
    }
    let v2 = format == Format::V2;
    let mut plain = Zeroizing::new(Vec::with_capacity(size));
    plain.extend_from_slice(&d.last.to_le_bytes());
    if v2 {
        plain.extend_from_slice(&d.generation.to_le_bytes());
        plain.extend_from_slice(&d.seen.to_le_bytes());
    }
    plain.extend_from_slice(&(d.entries.len() as u32).to_le_bytes());
    for e in d.entries {
        if v2 {
            plain.extend_from_slice(&e.id);
            plain.extend_from_slice(&e.parent);
        }
        for s in e.fields() {
            plain.extend_from_slice(&(s.len() as u32).to_le_bytes());
            plain.extend_from_slice(s.as_bytes());
        }
    }
    if v2 {
        plain.extend_from_slice(&(d.tombstones.len() as u32).to_le_bytes());
        for t in d.tombstones {
            plain.extend_from_slice(t);
        }
    }
    let nonce = crypto::random::<24>()?;
    let mut out = Vec::with_capacity(size + header.overhead());
    out.extend_from_slice(header.magic(format));
    out.extend_from_slice(id);
    if let Header::Keyed {
        key_id,
        state,
        flags,
    } = header
    {
        out.extend_from_slice(key_id);
        out.extend_from_slice(&state.epoch.to_le_bytes());
        out.extend_from_slice(&state.tag);
        out.extend_from_slice(&[*flags, 0, 0, 0]);
    }
    out.extend_from_slice(nonce.as_slice());
    let cipher = crypto::seal(key, &nonce, &out, &plain)?;
    out.extend_from_slice(&cipher);
    Ok(out)
}
/// Any of the four formats, opened with `key`, which the caller looked up
/// by the header (spec §4.5). A v1 layout gets `v1_ids` under the ID key
/// `id_key`, no tombstones and zero counters.
fn decode_data(
    id: &[u8; 16],
    key: &[u8; 32],
    id_key: &[u8; 32],
    data: &[u8],
) -> Result<(Format, Header, Contents)> {
    let (format, header) = read_header(data)?;
    if data.len() > MAX_FILE || &data[8..24] != id {
        return Err(AUTH_ERROR);
    }
    let v2 = format == Format::V2;
    // The whole header up to the nonce is the AAD.
    let aad = header.len();
    let plain = crypto::open(
        key,
        data[aad - 24..aad].try_into().unwrap(),
        &data[..aad],
        &data[aad..],
    )?;
    let mut r = Reader(&plain);
    let last = r.u64()?;
    let (generation, seen) = if v2 { (r.u64()?, r.u64()?) } else { (0, 0) };
    let count = r.num()?;
    if count > MAX_ENTRIES {
        return Err(AUTH_ERROR);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let ids = if v2 {
            (r.id()?, r.id()?)
        } else {
            (NO_ID, NO_ID)
        };
        let e = Entry {
            id: ids.0,
            parent: ids.1,
            title: r.text(256)?,
            kind: r.text(64)?,
            secret: r.text(MAX_TEXT)?,
            notes: r.text(MAX_TEXT)?,
        };
        if v2 {
            e.validate().map_err(|_| AUTH_ERROR)?;
        } else {
            e.validate()?;
        }
        entries.push(e);
    }
    let mut tombstones = Vec::new();
    if v2 {
        let count = r.num()?;
        if count > MAX_TOMBSTONES {
            return Err(AUTH_ERROR);
        }
        tombstones.reserve_exact(count);
        for _ in 0..count {
            tombstones.push(r.id()?);
        }
        check_ids(&entries, &tombstones).map_err(|_| AUTH_ERROR)?;
    }
    if !r.0.is_empty() {
        return Err(AUTH_ERROR);
    }
    if !v2 {
        v1_ids(id, id_key, &mut entries);
    }
    let contents = Contents {
        last,
        generation,
        seen,
        entries,
        tombstones,
    };
    Ok((format, header, contents))
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(AUTH_ERROR);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn num(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn id(&mut self) -> Result<EntryId> {
        Ok(self.take(16)?.try_into().unwrap())
    }
    fn text(&mut self, limit: usize) -> Result<Zeroizing<String>> {
        let n = self.num()?;
        if n > limit {
            return Err(AUTH_ERROR);
        }
        Ok(Zeroizing::new(
            std::str::from_utf8(self.take(n)?)
                .map_err(|_| AUTH_ERROR)?
                .to_owned(),
        ))
    }
}
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let f = File::open(path).map_err(|_| "파일을 열 수 없습니다.")?;
    if f.metadata().map_err(|_| "파일 정보 오류")?.len() > max as u64 {
        return Err("파일 크기 제한 초과");
    }
    let mut b = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| "파일 읽기 실패")?;
    if b.len() > max {
        return Err("파일 크기 제한 초과");
    }
    Ok(b)
}
fn normalized(path: &Path) -> Result<PathBuf> {
    // Reject alternate data streams; accept ordinary file names only.
    for component in path.components() {
        if let std::path::Component::Normal(s) = component {
            let s = s.to_string_lossy();
            if s.contains(':') || s.contains('\0') || s.ends_with(['.', ' ']) {
                return Err(
                    "일반 파일 경로를 지정하세요. 스트림·끝 공백·끝 점은 허용하지 않습니다.",
                );
            }
            if is_device_name(&s) {
                return Err("CON·NUL·COM1 같은 장치 이름은 파일 이름으로 쓸 수 없습니다.");
            }
        }
    }
    if path.exists() {
        return path.canonicalize().map_err(|_| "경로 확인 실패");
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or("파일 경로를 지정하세요.")?;
    Ok(parent
        .canonicalize()
        .map_err(|_| "저장할 폴더가 없습니다.")?
        .join(name))
}
/// DOS device names open a device, not a file: a backup to "NUL" or
/// "nul.goyo" would report success and keep nothing. The stem decides.
fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end();
    let stem = stem.to_ascii_uppercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    };
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered("COM")
        || numbered("LPT")
}
fn distinct(a: &Path, b: &Path) -> Result<()> {
    if a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
        || (a.exists() && b.exists() && file_identity(a)? == file_identity(b)?)
    {
        Err("금고와 열쇠, 백업 대상은 서로 다른 파일이어야 합니다.")
    } else {
        Ok(())
    }
}
/// BY_HANDLE_FILE_INFORMATION.
#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct FileInfo {
    attributes: u32,
    /// Creation, last access and last write (FILETIME, low part first).
    times: [u32; 6],
    volume: u32,
    size_hi: u32,
    size_lo: u32,
    links: u32,
    index_hi: u32,
    index_lo: u32,
}
#[cfg(windows)]
fn file_info(f: &File) -> Result<FileInfo> {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(h: *mut std::ffi::c_void, info: *mut FileInfo) -> i32;
    }
    let mut i = FileInfo::default();
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut i) } == 0 {
        return Err("파일 식별 실패");
    }
    Ok(i)
}
#[cfg(windows)]
fn file_identity(path: &Path) -> Result<(u32, u64)> {
    let i = file_info(&File::open(path).map_err(|_| "파일 식별 실패")?)?;
    Ok((i.volume, ((i.index_hi as u64) << 32) | i.index_lo as u64))
}
#[cfg(not(windows))]
fn file_identity(_path: &Path) -> Result<(u32, u64)> {
    Err("Windows에서만 지원합니다.")
}
struct FileLock(File);
impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        let mut name = path.as_os_str().to_owned();
        name.push(".goyolock");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(name))
            .map_err(|_| "파일 잠금을 만들 수 없습니다.")?;
        f.try_lock()
            .map_err(|_| "다른 고요 금고에서 사용 중인 파일입니다.")?;
        Ok(Self(f))
    }
}
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
/// What a failed atomic_write left behind.
#[derive(Debug, PartialEq, Eq)]
enum AtomicError {
    /// The target is as it was, and the temp file is gone.
    Failed(&'static str),
    /// The replace deleted the target but could not rename the temp file in
    /// its place (FAT and exFAT replace in two steps), and a second try
    /// without replace failed too. The temp file at this path is now the
    /// only full copy; it stays for the next unlock to take back. A key
    /// change reads it back to commit (spec §5.5 S2); so far only the tests
    /// read the path.
    #[cfg_attr(not(test), allow(dead_code))]
    GapKept(PathBuf),
}
impl From<&'static str> for AtomicError {
    fn from(e: &'static str) -> Self {
        Self::Failed(e)
    }
}
impl From<AtomicError> for &'static str {
    fn from(e: AtomicError) -> Self {
        match e {
            AtomicError::Failed(e) => e,
            AtomicError::GapKept(_) => GAP_KEPT,
        }
    }
}
/// Writes `data` to a new temp file next to `path`, flushes it and renames
/// it over `path` (only if `path` is new unless `replace`).
fn atomic_write(path: &Path, data: &[u8], replace: bool) -> std::result::Result<(), AtomicError> {
    if !replace && path.exists() {
        return Err("기존 파일을 덮어쓰지 않습니다. 새 파일 이름을 선택하세요.".into());
    }
    let suffix = crypto::random::<16>()?;
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{:032x}.goyotmp", u128::from_le_bytes(*suffix)));
    let temp = PathBuf::from(name);
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|_| "임시 암호화 파일 생성 실패")?;
        f.write_all(data)
            .and_then(|_| f.sync_all())
            .map_err(|_| "저장 실패: 디스크 공간과 권한을 확인하세요.")
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&temp);
        return Err(e.into());
    }
    #[cfg(test)]
    point("tmp_synced")?;
    // Only a replace can delete the target before the temp file has its name.
    let existed = replace && path.exists();
    if let Err(e) = publish_temp(&temp, path, replace) {
        // FAT and exFAT replace by deleting the target first. Once it is
        // gone the temp file is the only full copy and is never deleted:
        // one more try without replace, else it stays for the next unlock.
        if !existed || !replaced_away(path, &temp) {
            let _ = fs::remove_file(&temp);
            return Err(e.into());
        }
        if publish_temp(&temp, path, false).is_err() {
            return Err(AtomicError::GapKept(temp));
        }
    }
    #[cfg(test)]
    point("renamed")?;
    flush(path);
    Ok(())
}
/// Whether a failed replace deleted `path` and left `temp`: the target is
/// not found while the temp file next to it is there. A pulled USB stick or
/// a dropped share makes both unreachable; the target may still be intact.
fn replaced_away(path: &Path, temp: &Path) -> bool {
    temp.is_file()
        && fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
/// The rename is only metadata. Flushing the file under its final name
/// keeps a power cut right after "saved" from undoing it (FAT/exFAT too).
fn flush(path: &Path) {
    if let Ok(f) = OpenOptions::new().write(true).open(path) {
        let _ = f.sync_all();
    }
}
/// The error a simulated crash returns. The process is taken to have died
/// there: nothing is cleaned up, and the test drops the session.
#[cfg(any(test, debug_assertions))]
const SIMULATED_CRASH: &str = "simulated crash";
#[cfg(any(test, debug_assertions))]
thread_local! {
    /// Where the next atomic_write of this thread stops: "tmp_synced" (the
    /// temp file is written and flushed), "renamed" (it has the target's
    /// name, not flushed again), "gap" (the replace deletes the target and
    /// fails, and so does the retry), "gap_once" (the retry succeeds) or
    /// "unplugged" (the replace fails as the target and the temp file
    /// become unreachable: both get a ".away" suffix). Debug builds only,
    /// so that the app's own tests can reach the gap too.
    static CRASH: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}
/// Makes the next replace of a file by this thread act out the FAT/exFAT
/// gap (see CRASH): the target is deleted and the new state stays only in
/// its temp file. For the app's window tests; release builds compile none
/// of it.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn simulate_replace_gap() {
    CRASH.with(|c| c.set(Some("gap")));
}
#[cfg(test)]
thread_local! {
    /// A handle on the target that the next replace of this thread closes
    /// once a try failed, before it waits: a scanner or reader that lets go
    /// soon. A thread meant to close it 10 ms later can be kept off the CPU
    /// for over 100 ms in a busy test run, longer than the retries last.
    static CLOSES_SOON: std::cell::RefCell<Option<File>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
thread_local! {
    /// The step of a key change whose writes run now (spec §14.5): "S0" to
    /// "S5". A CRASH name "<step>.<point>", such as "S2.tmp_synced" or
    /// "S3.gap", fires only within that step; a plain name fires at the
    /// first write that reaches it.
    pub(super) static STEP: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    /// Where CRASH points next once a "gap" has played out: a crash right
    /// after a replace gap (spec §14.5, S1.gap to S3.gap).
    pub(super) static THEN: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}
/// Whether CRASH names `point`, plainly or qualified by the step that runs.
#[cfg(any(test, debug_assertions))]
fn crash_is(point: &str) -> bool {
    let Some(set) = CRASH.with(|c| c.get()) else {
        return false;
    };
    if set == point {
        return true;
    }
    #[cfg(test)]
    if let Some(step) = STEP.with(|s| s.get())
        && set.strip_prefix(step).and_then(|r| r.strip_prefix('.')) == Some(point)
    {
        return true;
    }
    false
}
/// Err(SIMULATED_CRASH) once if a test set this point.
#[cfg(test)]
fn point(name: &'static str) -> Result<()> {
    if crash_is(name) {
        CRASH.with(|c| c.set(None));
        return Err(SIMULATED_CRASH);
    }
    Ok(())
}
/// `publish` for atomic_write; under test it can also act out the replace
/// gap of a FAT or exFAT volume (see CRASH).
fn publish_temp(temp: &Path, target: &Path, replace: bool) -> Result<()> {
    #[cfg(any(test, debug_assertions))]
    if replace && (crash_is("gap") || crash_is("gap_once")) {
        let retry_fails = crash_is("gap");
        let _ = fs::remove_file(target);
        CRASH.with(|c| c.set(retry_fails.then_some("gap_retry")));
        return Err(SIMULATED_CRASH);
    } else if !replace && CRASH.with(|c| c.get()) == Some("gap_retry") {
        #[cfg(test)]
        let then = THEN.with(|t| t.take());
        #[cfg(not(test))]
        let then = None;
        CRASH.with(|c| c.set(then));
        return Err(SIMULATED_CRASH);
    } else if replace && crash_is("unplugged") {
        CRASH.with(|c| c.set(None));
        for path in [temp, target] {
            let mut away = path.as_os_str().to_owned();
            away.push(".away");
            let _ = fs::rename(path, away);
        }
        return Err(SIMULATED_CRASH);
    }
    publish(temp, target, replace)
}

/// Whether an interrupted save left `<path>.<random>.goyotmp` next to `path`.
/// When the main file is missing, that temp file may be the only full copy.
pub fn leftover_temp(path: &Path) -> bool {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let prefix = format!("{}.", name.to_string_lossy().to_lowercase());
    fs::read_dir(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    })
    .map(|entries| {
        entries.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().to_lowercase();
            n.starts_with(&prefix) && n.ends_with(".goyotmp")
        })
    })
    .unwrap_or(false)
}
#[cfg(windows)]
fn publish(temp: &Path, target: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        fn GetLastError() -> u32;
    }
    let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    if from[..from.len() - 1].contains(&0) || to[..to.len() - 1].contains(&0) {
        return Err("올바르지 않은 파일 경로");
    }
    // Same-directory rename; atomic no-clobber when REPLACE_EXISTING is absent.
    // Unlike hard links this also supports common removable FAT/exFAT volumes.
    // Any open handle on the target, even a virus scanner's or a reader's
    // with full sharing, makes it fail with ACCESS_DENIED (5) or
    // SHARING_VIOLATION (32) until closed: retry for at most 100 ms.
    for retry in 0..=5 {
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 8 | u32::from(replace)) } != 0 {
            return Ok(());
        }
        if retry == 5 || !matches!(unsafe { GetLastError() }, 5 | 32) {
            break;
        }
        #[cfg(test)]
        drop(CLOSES_SOON.take());
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err("파일 저장/교체 실패: 기존 파일, 저장장치 연결과 쓰기 권한을 확인하세요.")
}

#[cfg(test)]
mod workflow_tests {
    use super::*;
    use keyfile::{KEY_MAGIC, KEY_MAGIC_NO_OTP, decode_key};
    /// Whether the key file at `path` shows the OTP field.
    fn key_otp(path: &Path) -> Option<bool> {
        key_info(path).map(|i| i.otp)
    }
    /// A test's folder, which is also its PC's anchor folder (`anchor` in
    /// it): no test touches another's anchor or the developer's own.
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "goyo-workflow-{:x}",
                u128::from_le_bytes(*crypto::random::<16>().unwrap())
            ));
            fs::create_dir(&p).unwrap();
            set_anchor_dir(Some(p.join("anchor")));
            Self(p)
        }
        fn file(&self, n: &str) -> PathBuf {
            self.0.join(n)
        }
        /// Another PC, or this PC with its anchor deleted: a fresh anchor
        /// folder from now on.
        fn other_anchor(&self, name: &str) -> PathBuf {
            let dir = self.0.join(format!("anchor-{name}"));
            set_anchor_dir(Some(dir.clone()));
            dir
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            set_anchor_dir(None);
            for e in fs::read_dir(&self.0).unwrap() {
                let e = e.unwrap();
                // Sync folders (<vault>.sync) and anchor folders are the only
                // folders tests make.
                let name = e.file_name().to_string_lossy().into_owned();
                if e.file_type().unwrap().is_dir()
                    && (name.ends_with(".sync") || name.starts_with("anchor"))
                {
                    let _ = fs::remove_dir_all(e.path());
                    continue;
                }
                assert!(e.file_type().unwrap().is_file());
                let _ = fs::remove_file(e.path());
            }
            let _ = fs::remove_dir(&self.0);
        }
    }
    /// A password change as the app makes it: a Reauth with the current
    /// password and a code typed now, then the key change, a gate answered
    /// yes.
    fn change_password(
        s: &mut Session,
        current: &str,
        password: &str,
        input: &str,
    ) -> Result<Rekeyed> {
        let r = s.reauth(current, Some((input, otp::now()?)), None)?;
        let change = Change::Password(Zeroizing::new(password.to_owned()));
        s.rekey(r, Vec::new(), change, Consent::default(), true)
    }
    /// Whether the key file at `path` opens with `password`.
    fn opens(path: &Path, password: &str) -> bool {
        KeyFile::read(path)
            .and_then(|k| k.open(password, None))
            .is_ok()
    }
    /// What an unlock says first about the key and vault files, but for the
    /// reminder of a key backup.
    fn key_notice(s: &mut Session) -> Option<KeyNotice> {
        s.take_key_notices()
            .into_iter()
            .find(|n| *n != KeyNotice::KeyBackupDue)
    }
    fn entry(value: &str) -> Entry {
        Entry::new(
            "테스트 항목".into(),
            "비밀".into(),
            value.into(),
            "메모".into(),
        )
        .unwrap()
    }
    fn v1(last: u64, entries: &[Entry]) -> DataRef<'_> {
        DataRef {
            last,
            generation: 0,
            seen: 0,
            entries,
            tombstones: &[],
        }
    }
    /// A session on `path` without a key file or lock, so tests of the
    /// entry rules skip the slow key derivation. Loads `path` if it exists.
    fn bare(path: PathBuf, id: [u8; 16], key: [u8; 32]) -> Session {
        // A 0.8 key file is classified by its magic and length alone.
        let key_file = [&KEY_MAGIC_NO_OTP[..], &id, &[0; 104]].concat();
        let key_file = KeyFile::from_bytes(Path::new("unused.goyokey"), key_file).unwrap();
        let state = key_file.legacy_state(&key).unwrap();
        let keys = Box::new(Bundle::new(&[key], None).unwrap());
        let mut s = Session::new(path, "unused.goyokey".into(), id, keys, key_file, state);
        if let Ok(data) = fs::read(&s.path) {
            let (format, _, c) = decode_data(&id, &key, &key, &data).unwrap();
            s.format = format;
            (s.last, s.generation, s.seen) = (c.last, c.generation, c.seen);
            (s.entries, s.tombstones) = (c.entries, c.tombstones);
        }
        s
    }
    /// Everything a failed save must restore.
    type Snapshot = (
        Vec<(EntryId, EntryId, String)>,
        Vec<EntryId>,
        u64,
        u64,
        Format,
    );
    fn snapshot(s: &Session) -> Snapshot {
        let entries = s
            .entries
            .iter()
            .map(|e| (e.id, e.parent, e.fields().concat()));
        (
            entries.collect(),
            s.tombstones.clone(),
            s.generation,
            s.seen,
            s.format,
        )
    }
    fn ids(entries: &[Entry]) -> Vec<EntryId> {
        entries.iter().map(Entry::id).collect()
    }
    #[test]
    fn lifecycle_backup_restore_password_and_failed_save() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let v = t.file("vault.goyo");
        let k = t.file("key.goyokey");
        let b = t.file("backup.goyo");
        let restored = t.file("restored.goyo");
        let pass = "a long synthetic password";
        let changed = "another synthetic password";
        let p = Provision::new().unwrap();
        let current = otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6);
        let input = format!("{current:06}");
        assert!(p.finish(&v, &k, "short", Some(&input)).is_err());
        assert!(!v.exists() && !k.exists());
        let mut s = p.finish(&v, &k, pass, Some(&input)).unwrap();
        assert!(s.uses_otp() && fs::read(&k).unwrap().len() == 148);
        assert_eq!(key_otp(&k), Some(true));
        let setup = s.otp_setup(pass).unwrap();
        assert_eq!(setup.code(), p.setup_code());
        assert!(setup.uri().contains(p.setup_code().as_str()));
        // Each vault is its own authenticator account; the URI still fits the QR.
        assert_eq!(vault_tag(&v), Some(s.tag()));
        assert_eq!(setup.tag(), s.tag());
        assert!(setup.uri().contains(&format!("Goyo%20Vault:{}?", s.tag())));
        assert!(setup.uri().len() <= crate::qr::CAPACITY);
        assert!(!leftover_temp(&v));
        fs::write(t.file("vault.goyo.0123.goyotmp"), b"synthetic").unwrap();
        assert!(leftover_temp(&v) && !leftover_temp(&k));
        fs::remove_file(t.file("vault.goyo.0123.goyotmp")).unwrap();
        assert_eq!(
            s.otp_setup("wrong synthetic password").err(),
            Some(AUTH_ERROR)
        );
        s.put(None, entry("original secret")).unwrap();
        s.put(Some(0), entry("updated secret")).unwrap();
        s.backup(&b).unwrap();
        let old_key = fs::read(&k).unwrap();
        assert!(s.backup(&b).is_err());
        assert!(Session::unlock(&v, &k, pass, &input).is_err()); // already open
        let actual = s.path.clone();
        s.path = t.file("missing-folder").join("failed.goyo");
        assert!(s.put(Some(0), entry("must not commit")).is_err());
        assert_eq!(&*s.entries[0].secret, "updated secret");
        assert!(s.delete(0).is_err());
        assert_eq!(s.entries.len(), 1);
        s.path = actual;
        s.delete(0).unwrap();
        assert!(s.entries.is_empty());
        s.put(None, entry("final secret")).unwrap();
        assert!(change_password(&mut s, "wrong", changed, &input).is_err());
        assert!(change_password(&mut s, pass, changed, &input).is_err());
        s.last = 0; // simulate a later interval without sleeping
        assert_eq!(
            change_password(&mut s, pass, changed, &input),
            Ok(Rekeyed::Done)
        );
        // The 0.8 key file became a KF2 one, and the vault file moved to a
        // new data key that the old key file lacks (spec §1 rule 15).
        assert_ne!(old_key, fs::read(&k).unwrap());
        assert!(!opens(&k, pass) && opens(&k, changed));
        let (_, old_master, _) = decode_key(&old_key, pass).unwrap();
        assert!(decode_data(&p.id, &old_master, &old_master, &fs::read(&v).unwrap()).is_err());
        // Simulate time elapsed since backup without sleeping or weakening production verification.
        let old_backup = encode_data(
            &p.id,
            &p.key,
            &Header::Legacy,
            Format::V1,
            v1(0, &[entry("restore snapshot")]),
        )
        .unwrap();
        fs::write(&b, &old_backup).unwrap();
        drop(s);
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        assert_eq!(
            Session::restore(&b, &k, &restored, "wrong password", &input)
                .err()
                .unwrap(),
            AUTH_ERROR
        );
        let step = otp::now().unwrap() / 30;
        let codes = [step - 1, step, step + 1].map(|t| otp::code(p.otp.as_slice(), t, 6));
        let wrong_code = (0..1_000_000).find(|c| !codes.contains(c)).unwrap();
        assert_eq!(
            Session::restore(&b, &k, &restored, changed, &format!("{wrong_code:06}"))
                .err()
                .unwrap(),
            AUTH_ERROR
        );
        assert!(!restored.exists());
        let rs = Session::restore(&b, &k, &restored, changed, &input).unwrap();
        assert_eq!(&*rs.entries[0].secret, "restore snapshot");
        assert_eq!(fs::read(&b).unwrap(), old_backup);
        drop(rs);
        assert!(Session::unlock(&restored, &k, changed, &input).is_err()); // consumed OTP
    }
    #[test]
    fn vault_without_otp() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let v = t.file("vault.goyo");
        let k = t.file("key.goyokey");
        let b = t.file("backup.goyo");
        let restored = t.file("restored.goyo");
        let pass = "a long synthetic password";
        let changed = "another synthetic password";
        let p = Provision::new().unwrap();
        let mut s = p.finish(&v, &k, pass, None).unwrap();
        assert!(!s.uses_otp());
        assert_eq!(key_otp(&k), Some(false));
        assert_eq!(fs::read(&k).unwrap().len(), 128);
        assert_eq!(
            s.otp_setup(pass).err(),
            Some("이 금고는 OTP를 쓰지 않습니다.")
        );
        s.put(None, entry("no otp secret")).unwrap();
        s.backup(&b).unwrap();
        // Any code, or none, is ignored when the vault has no OTP.
        change_password(&mut s, pass, changed, "").unwrap();
        let key = KeyFile::read(&k).unwrap();
        assert!(!key.uses_otp() && key.open(changed, None).is_ok());
        assert_eq!(key_otp(&k), Some(false));
        drop(s);
        let before = fs::read(&v).unwrap();
        assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(AUTH_ERROR));
        let s = Session::unlock(&v, &k, changed, "").unwrap();
        assert_eq!(&*s.entries[0].secret, "no otp secret");
        // Opening again is fine (no code to consume), and nothing was rewritten.
        drop(s);
        let s = Session::unlock(&v, &k, changed, "123456").unwrap();
        drop(s);
        assert_eq!(fs::read(&v).unwrap(), before);
        let rs = Session::restore(&b, &k, &restored, changed, "").unwrap();
        assert_eq!(&*rs.entries[0].secret, "no otp secret");
        drop(rs);
        // An OTP vault still needs its code, before any key derivation.
        let q = Provision::new().unwrap();
        let (v2, k2) = (t.file("otp.goyo"), t.file("otp.goyokey"));
        let code = format!(
            "{:06}",
            otp::code(q.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        drop(q.finish(&v2, &k2, pass, Some(&code)).unwrap());
        assert_eq!(Session::unlock(&v2, &k2, pass, "").err(), Some(AUTH_ERROR));
        assert_eq!(key_otp(&t.file("missing.goyokey")), None);
        assert_eq!(key_otp(&v), None);
    }
    #[test]
    fn restore_needs_no_sidecars_next_to_inputs() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let src = t.file("readonly-backup.goyo");
        let key = t.file("readonly-key.goyokey");
        let out = t.file("new.goyo");
        let p = Provision::new().unwrap();
        let pass = "readonly test password";
        fs::write(&key, encode_key(&p.id, &p.key, Some(&p.otp), pass).unwrap()).unwrap();
        fs::write(
            &src,
            encode_data(
                &p.id,
                &p.key,
                &Header::Legacy,
                Format::V1,
                v1(0, &[entry("saved")]),
            )
            .unwrap(),
        )
        .unwrap();
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        let mut s = Session::restore(&src, &key, &out, pass, &input).unwrap();
        assert!(!t.file("readonly-backup.goyo.goyolock").exists());
        assert!(!t.file("readonly-key.goyokey.goyolock").exists());
        // Another vault copy can share this key; password rewrap must invalidate
        // this session's cached key backup instead of silently exporting it.
        let mut other = Session::restore(&src, &key, &t.file("other.goyo"), pass, &input).unwrap();
        // As its login would be: a restored session changes no key (spec
        // §2.18 #54).
        (other.last, other.restored) = (0, false);
        change_password(&mut other, pass, "another shared key password", &input).unwrap();
        assert!(s.backup_key(&t.file("stale.goyokey")).is_err());
        assert!(change_password(&mut s, pass, "stale replacement password", &input).is_err());
        assert!(!t.file("stale.goyokey").exists());
        other.backup_key(&t.file("current.goyokey")).unwrap();
        drop(other);
        drop(s);
    }
    #[test]
    fn path_aliases_and_streams_rejected() {
        let t = Temp::new();
        let a = t.file("a.goyo");
        let b = t.file("b.goyo");
        fs::write(&a, b"synthetic").unwrap();
        fs::hard_link(&a, &b).unwrap();
        assert!(distinct(&a, &b).is_err());
        assert!(normalized(&t.file("a.goyo:hidden")).is_err());
        assert!(normalized(&t.file("trailing.")).is_err());
        for device in [
            "NUL",
            "nul.goyo",
            "Con.goyokey",
            "COM1",
            "lpt9.goyo",
            "COM¹",
        ] {
            assert!(normalized(&t.file(device)).is_err(), "{device}");
        }
        for name in ["console.goyo", "COM10.goyo", "nullable.goyo", "auxiliary"] {
            assert!(normalized(&t.file(name)).is_ok(), "{name}");
        }
    }
    #[test]
    fn password_policy_rejects_repetition() {
        assert!(password_policy("aaaaaaaaaaaaaaaa").is_err());
        assert!(password_policy("abababababababab").is_err());
        assert!(password_policy("abcdeabcdeabcdea").is_err()); // 5 distinct
        assert!(password_policy("short but varied").is_ok());
        assert!(password_policy("우리집 강아지는 복슬복슬 강아지").is_ok());
        assert!(password_policy("abc").is_err());
        assert!(password_policy("correct hors").is_ok()); // 12 characters
        assert!(password_policy("correct hor").is_err()); // 11
        assert!(password_policy("다람쥐 헌 쳇바퀴에 타고파").is_ok());
        // Guessable at any length: words, walks, runs, repeats, digits only.
        for weak in [
            "password1234",
            "Password1234!",
            "qwerty123456",
            "1q2w3e4r5t6y",
            "123456123456",
            "iloveyou1234",
            "qwertyuiop12",
            "abcdef123456",
            "qwerqwerqwer",
            "202610171234",
            "asdfghjkl;'12",
            "q1w2e3r4t5y6u7",
            "sunshine princess dragon football",
        ] {
            assert!(password_policy(weak).is_err(), "{weak}");
        }
        // No length at which the check stops (it used to give up past 64).
        let words = "password".repeat(9);
        assert!(password_policy(&words[..65]).is_err());
        assert!(password_policy(&"qwerty".repeat(170)).is_err()); // 1020 bytes
        for strong in [
            "dragon-tiger-lemon",
            "purple cactus 7 sing",
            "Goyo vault sits quietly",
            "a long synthetic password",
        ] {
            assert!(password_policy(strong).is_ok(), "{strong}");
        }
    }
    #[test]
    fn password_change_failure_stages_preserve_recoverability() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let v = t.file("vault.goyo");
        let k = t.file("key.goyokey");
        let p = Provision::new().unwrap();
        let pass = "synthetic original password";
        let next = "synthetic replacement password";
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        let mut s = p.finish(&v, &k, pass, Some(&input)).unwrap();
        s.last = 0;
        let before_key = fs::read(&k).unwrap();
        let before_vault = fs::read(&v).unwrap();
        assert_eq!(
            change_password(&mut s, "incorrect password", next, &input).unwrap_err(),
            AUTH_ERROR
        );
        assert_eq!(
            change_password(&mut s, pass, next, "abc").unwrap_err(),
            AUTH_ERROR
        );
        s.path = t.file("missing").join("failed.goyo");
        assert!(change_password(&mut s, pass, next, &input).is_err());
        assert_eq!(s.last, 0);
        assert_eq!(fs::read(&k).unwrap(), before_key);
        assert_eq!(fs::read(&v).unwrap(), before_vault);
        s.path = v.clone();
        let original_permissions = fs::metadata(&k).unwrap().permissions();
        let mut read_only = original_permissions.clone();
        read_only.set_readonly(true);
        fs::set_permissions(&k, read_only).unwrap();
        let result = change_password(&mut s, pass, next, &input);
        fs::set_permissions(&k, original_permissions).unwrap();
        assert!(result.is_err());
        assert!(s.last > 0);
        assert_eq!(fs::read(&k).unwrap(), before_key);
        assert!(decode_key(&before_key, pass).is_ok());
        let (_, _, c) = decode_data(&p.id, &p.key, &p.key, &fs::read(&v).unwrap()).unwrap();
        assert_eq!(c.last, s.last);
        assert_eq!(
            change_password(&mut s, pass, next, &input).unwrap_err(),
            AUTH_ERROR
        );
    }
    #[test]
    fn authenticated_malformed_payloads_are_rejected() {
        fn wrap(p: &[u8]) -> Vec<u8> {
            let mut h = Vec::from(*DATA_MAGIC_V1);
            h.extend_from_slice(&[1; 16]);
            h.extend_from_slice(&[2; 24]);
            let c = crypto::seal(&[3; 32], &[2; 24], &h, p).unwrap();
            h.extend(c);
            h
        }
        let mut cases = vec![vec![0; 11]];
        let mut count = vec![0; 8];
        count.extend_from_slice(&1001u32.to_le_bytes());
        cases.push(count);
        let mut length = vec![0; 8];
        length.extend_from_slice(&1u32.to_le_bytes());
        length.extend_from_slice(&u32::MAX.to_le_bytes());
        cases.push(length);
        let mut trailing = vec![0; 12];
        trailing.push(1);
        cases.push(trailing);
        for title in [vec![0xff], vec![0]] {
            let mut b = vec![0; 8];
            b.extend_from_slice(&1u32.to_le_bytes());
            for field in [
                title,
                b"kind".to_vec(),
                b"secret".to_vec(),
                b"notes".to_vec(),
            ] {
                b.extend_from_slice(&(field.len() as u32).to_le_bytes());
                b.extend(field);
            }
            cases.push(b);
        }
        for p in cases {
            assert!(decode_data(&[1; 16], &[3; 32], &[3; 32], &wrap(&p)).is_err());
        }
    }
    #[test]
    fn v2_structure_is_checked() {
        fn wrap(p: &[u8]) -> Vec<u8> {
            let mut h = Vec::from(*DATA_MAGIC_V2);
            h.extend_from_slice(&[1; 16]);
            h.extend_from_slice(&[2; 24]);
            let c = crypto::seal(&[3; 32], &[2; 24], &h, p).unwrap();
            h.extend(c);
            h
        }
        /// last, generation and seen, then the entry count.
        fn head(count: u32) -> Vec<u8> {
            let mut p = vec![0; 24];
            p.extend_from_slice(&count.to_le_bytes());
            p
        }
        fn add(p: &mut Vec<u8>, id: EntryId, title: &[u8]) {
            p.extend_from_slice(&id);
            p.extend_from_slice(&[9; 16]);
            let fixed = [b"kind".as_slice(), b"secret", b"notes"];
            for field in std::iter::once(title).chain(fixed) {
                p.extend_from_slice(&(field.len() as u32).to_le_bytes());
                p.extend_from_slice(field);
            }
        }
        fn bury(p: &mut Vec<u8>, ids: &[EntryId]) {
            p.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            for id in ids {
                p.extend_from_slice(id);
            }
        }
        fn file(entries: &[(EntryId, &str)], dead: &[EntryId]) -> Vec<u8> {
            let mut p = head(entries.len() as u32);
            for (id, title) in entries {
                add(&mut p, *id, title.as_bytes());
            }
            bury(&mut p, dead);
            p
        }
        let (a, b) = ([5; 16], [6; 16]);
        let good = file(&[(a, "a"), (b, "b")], &[[7; 16]]);
        let (format, _, c) = decode_data(&[1; 16], &[3; 32], &[3; 32], &wrap(&good)).unwrap();
        assert_eq!(format, Format::V2);
        assert_eq!((ids(&c.entries), c.tombstones), (vec![a, b], vec![[7; 16]]));
        assert_eq!(c.entries[0].parent, [9; 16]);
        let mut trailing = good.clone();
        trailing.push(0);
        let mut untold = head(1);
        add(&mut untold, a, b"a");
        let mut garbled = head(1);
        add(&mut garbled, a, &[0xff]);
        bury(&mut garbled, &[]);
        let mut crowded = head(1001);
        bury(&mut crowded, &[]);
        let mut graveyard = head(0);
        graveyard.extend_from_slice(&65_537u32.to_le_bytes());
        for p in [
            file(&[([0; 16], "a")], &[]),
            file(&[(a, "a"), (a, "b")], &[]),
            file(&[(a, "a")], &[a]),
            file(&[(a, "a")], &[b, b]),
            file(&[(a, "a")], &[[0; 16]]),
            file(&[(a, "\0")], &[]),
            file(&[(a, " ")], &[]),
            garbled,
            trailing,
            untold,
            crowded,
            graveyard,
        ] {
            assert_eq!(
                decode_data(&[1; 16], &[3; 32], &[3; 32], &wrap(&p)).err(),
                Some(AUTH_ERROR)
            );
        }
        // What decoding would refuse is never written.
        let mut x = entry("x");
        x.set_ids(a, NO_ID);
        let mut y = entry("y");
        let v2 = |entries: &[Entry], tombstones: &[EntryId]| {
            let d = DataRef {
                last: 0,
                generation: 1,
                seen: 0,
                entries,
                tombstones,
            };
            encode_data(&[1; 16], &[3; 32], &Header::Legacy, Format::V2, d).err()
        };
        assert_eq!(v2(&[x.clone(), y.clone()], &[]), Some("항목 ID 오류"));
        y.set_ids(a, NO_ID);
        assert_eq!(v2(&[x.clone(), y.clone()], &[]), Some("항목 ID 오류"));
        assert_eq!(v2(std::slice::from_ref(&x), &[a]), Some("항목 ID 오류"));
        assert_eq!(v2(std::slice::from_ref(&x), &[b, b]), Some("항목 ID 오류"));
        // Up to MAX_TOMBSTONES fit, and read back in order.
        let mut dead: Vec<EntryId> = (0..MAX_TOMBSTONES as u32)
            .map(|n| {
                let mut id = [0xAA; 16];
                id[..4].copy_from_slice(&n.to_le_bytes());
                id
            })
            .collect();
        let d = DataRef {
            last: 0,
            generation: 1,
            seen: 0,
            entries: std::slice::from_ref(&x),
            tombstones: &dead,
        };
        let data = encode_data(&[1; 16], &[3; 32], &Header::Legacy, Format::V2, d).unwrap();
        assert_eq!(
            decode_data(&[1; 16], &[3; 32], &[3; 32], &data)
                .unwrap()
                .2
                .tombstones,
            dead
        );
        dead.push([0xBB; 16]);
        assert_eq!(v2(std::slice::from_ref(&x), &dead), Some(TOMBSTONE_LIMIT));
        // v2 stores 32 more bytes per entry: a vault just under the size
        // limit in v1 can be over it in v2.
        let full: Vec<Entry> = (0..501)
            .map(|n| {
                let mut e = Entry::new(
                    "t".repeat(256),
                    "k".repeat(64),
                    "s".repeat(MAX_TEXT),
                    "n".repeat(MAX_TEXT),
                )
                .unwrap();
                let mut id = [1; 16];
                id[..4].copy_from_slice(&(n as u32).to_le_bytes());
                e.set_ids(id, NO_ID);
                e
            })
            .collect();
        assert!(
            encode_data(
                &[1; 16],
                &[3; 32],
                &Header::Legacy,
                Format::V1,
                v1(0, &full)
            )
            .is_ok()
        );
        assert_eq!(
            v2(&full, &[]),
            Some("금고 용량 제한(8 MiB)을 초과했습니다.")
        );
    }
    #[test]
    fn put_and_delete_keep_ids_and_tombstones() {
        let t = Temp::new();
        let mut s = bare(t.file("vault.goyo"), [1; 16], [2; 32]);
        s.save().unwrap();
        s.put(None, entry("one")).unwrap();
        s.put(None, entry("two")).unwrap();
        assert_eq!(s.generation, 2);
        assert!(s.entries.iter().all(|e| e.id != NO_ID && e.parent == NO_ID));
        assert_ne!(s.entry_id(0), s.entry_id(1));
        // A vault without sync stays v1 and keeps tombstones only in memory.
        s.put(Some(1), entry("two, edited")).unwrap();
        assert_eq!(s.tombstones.len(), 1);
        assert_eq!(&fs::read(&s.path).unwrap()[..8], DATA_MAGIC_V1);
        let reopened = bare(s.path.clone(), [1; 16], [2; 32]);
        assert_eq!(reopened.format(), Format::V1);
        assert!(reopened.tombstones.is_empty() && reopened.generation == 0);
        s.enable_sync().unwrap();
        assert_eq!(s.generation, 1);
        let (one, two) = (s.entry_id(0).unwrap(), s.entry_id(1).unwrap());

        // Saving unchanged text saves nothing, not even into a missing folder.
        let actual = s.path.clone();
        let saved = fs::read(&actual).unwrap();
        let before = snapshot(&s);
        s.path = t.file("missing-folder").join("failed.goyo");
        s.put(Some(0), entry("one")).unwrap();
        assert_eq!(snapshot(&s), before);
        // A failed save restores entries, tombstones and the counter exactly.
        assert!(s.put(Some(0), entry("changed")).is_err());
        assert_eq!(snapshot(&s), before);
        assert!(s.put(None, entry("three")).is_err());
        assert_eq!(snapshot(&s), before);
        assert!(s.delete(1).is_err());
        assert_eq!(snapshot(&s), before);
        s.path = actual;
        assert_eq!(fs::read(&s.path).unwrap(), saved);
        assert_eq!(s.put(Some(5), entry("x")).err(), Some("항목 선택 오류"));
        assert_eq!(s.delete(5).err(), Some("항목 선택 오류"));

        // An edit: a new ID, the old one as parent and tombstone, count + 1.
        s.put(Some(0), entry("changed")).unwrap();
        let edited = s.entry_id(0).unwrap();
        assert!(edited != one && edited != NO_ID);
        assert_eq!(s.entries[0].parent, one);
        assert_eq!((s.tombstones.clone(), s.generation), (vec![one], 2));
        assert_eq!(s.entry_index(&one), None);
        assert_eq!(s.entry_index(&edited), Some(0));
        assert_eq!(s.successor(&one), Some(0));
        assert_eq!(s.successor(&two), None);
        assert_eq!(s.successor(&NO_ID), None);
        // A delete: the ID becomes a tombstone, count + 1.
        s.delete(1).unwrap();
        assert_eq!((s.tombstones.clone(), s.generation), (vec![one, two], 3));
        // The file holds the same.
        let reopened = bare(s.path.clone(), [1; 16], [2; 32]);
        assert_eq!(snapshot(&reopened), snapshot(&s));
        assert_eq!(&fs::read(&s.path).unwrap()[..8], DATA_MAGIC_V2);
        // Two entries that replaced the same one: no single successor.
        let mut twin = s.entries[0].clone();
        twin.id = [3; 16];
        s.entries.push(twin);
        assert_eq!(s.successor(&one), None);
        s.entries.pop();

        // At the tombstone limit edits and deletes are refused unchanged;
        // adding still works because it leaves no tombstone.
        s.tombstones = (0..MAX_TOMBSTONES as u32)
            .map(|n| {
                let mut id = [0xAA; 16];
                id[..4].copy_from_slice(&n.to_le_bytes());
                id
            })
            .collect();
        let before = snapshot(&s);
        assert_eq!(s.put(Some(0), entry("again")).err(), Some(TOMBSTONE_LIMIT));
        assert_eq!(s.delete(0).err(), Some(TOMBSTONE_LIMIT));
        assert_eq!(snapshot(&s), before);
        s.put(None, entry("new")).unwrap();
        assert_eq!(s.tombstones.len(), MAX_TOMBSTONES);
    }
    #[test]
    fn enable_sync_converts_once() {
        let t = Temp::new();
        let mut s = bare(t.file("vault.goyo"), [1; 16], [2; 32]);
        s.save().unwrap();
        for value in ["twin", "twin", "other"] {
            s.put(None, entry(value)).unwrap();
        }
        s.put(Some(2), entry("edited")).unwrap();
        let v1_file = fs::read(&s.path).unwrap();
        let (_, _, from_file) =
            decode_data(&s.id, s.keys.current(), s.keys.id_key(), &v1_file).unwrap();
        assert!(from_file.tombstones.is_empty());
        // A failed save restores everything; the vault stays v1.
        let before = snapshot(&s);
        let actual = s.path.clone();
        s.path = t.file("missing-folder").join("failed.goyo");
        assert!(s.enable_sync().is_err());
        assert_eq!(snapshot(&s), before);
        assert_eq!(s.format(), Format::V1);
        s.path = actual;
        assert_eq!(fs::read(&s.path).unwrap(), v1_file);
        s.enable_sync().unwrap();
        // The IDs any PC derives from this v1 file, no history, count 1.
        assert_eq!(ids(&s.entries), ids(&from_file.entries));
        assert!(s.entries.iter().all(|e| e.parent == NO_ID));
        assert!(s.tombstones.is_empty());
        assert_eq!((s.format(), s.generation, s.seen), (Format::V2, 1, 0));
        let reopened = bare(s.path.clone(), [1; 16], [2; 32]);
        assert_eq!(snapshot(&reopened), snapshot(&s));
        assert_eq!(vault_tag(&s.path), Some(s.tag()));
        // Turning sync on again changes nothing.
        let v2_file = fs::read(&s.path).unwrap();
        s.enable_sync().unwrap();
        assert_eq!(fs::read(&s.path).unwrap(), v2_file);
        // A PC that turns sync on for a copy of the same v1 file merges with
        // this one without duplicates.
        fs::write(t.file("copy.goyo"), &v1_file).unwrap();
        let mut other = bare(t.file("copy.goyo"), [1; 16], [2; 32]);
        other.enable_sync().unwrap();
        let (_, _, remote) = decode_data(
            &s.id,
            s.keys.current(),
            s.keys.id_key(),
            &fs::read(&other.path).unwrap(),
        )
        .unwrap();
        let (merged, report) =
            crate::merge::merge(s.keys.id_key(), s.data(), remote, 0, LEGACY_OVERHEAD).unwrap();
        assert!(report.added == 0 && report.removed == 0 && report.conflicts == 0);
        assert!(!report.changed && !report.needs_push);
        assert_eq!(ids(&merged.entries), ids(&s.entries));
        // vault_tag reads the four formats (the ID is at offset 8 in each)
        // and nothing newer.
        let mut newer = v2_file.clone();
        newer[..8].copy_from_slice(b"GOYOVA05");
        fs::write(t.file("newer.goyo"), &newer).unwrap();
        assert_eq!(vault_tag(&t.file("copy.goyo")), Some(s.tag()));
        assert_eq!(vault_tag(&t.file("newer.goyo")), None);
        for magic in [DATA_MAGIC_V3, DATA_MAGIC_V4] {
            newer[..8].copy_from_slice(magic);
            fs::write(t.file("newer.goyo"), &newer).unwrap();
            assert_eq!(vault_tag(&t.file("newer.goyo")), Some(s.tag()));
        }
        fs::write(t.file("old.goyo"), &v1_file).unwrap();
        assert_eq!(vault_tag(&t.file("old.goyo")), Some(s.tag()));
    }
    #[test]
    fn restore_and_backup_keep_sync_state() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let p = Provision::new().unwrap();
        let pass = "synthetic sync password";
        let key = t.file("sync.goyokey");
        fs::write(&key, encode_key(&p.id, &p.key, Some(&p.otp), pass).unwrap()).unwrap();
        let mut es = vec![entry("kept"), entry("edited")];
        es[0].set_ids([5; 16], NO_ID);
        es[1].set_ids([6; 16], [4; 16]);
        let tombstones = [[4; 16], [3; 16]];
        let d = DataRef {
            last: 0,
            generation: 9,
            seen: 8,
            entries: &es,
            tombstones: &tombstones,
        };
        let src = t.file("synced.goyo");
        fs::write(
            &src,
            encode_data(&p.id, &p.key, &Header::Legacy, Format::V2, d).unwrap(),
        )
        .unwrap();
        let check = |c: &Contents| {
            assert_eq!(ids(&c.entries), [[5; 16], [6; 16]]);
            assert_eq!(c.entries[1].parent, [4; 16]);
            assert_eq!(c.tombstones, tombstones);
            assert_eq!((c.generation, c.seen), (9, 8));
        };
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        let out = t.file("restored.goyo");
        let mut s = Session::restore(&src, &key, &out, pass, &input).unwrap();
        assert_eq!(s.format(), Format::V2);
        // The used OTP code is the only change written.
        let (format, _, c) = decode_data(&p.id, &p.key, &p.key, &fs::read(&out).unwrap()).unwrap();
        assert!(format == Format::V2 && c.last > 0);
        check(&c);
        let b = t.file("backup.goyo");
        s.backup(&b).unwrap();
        let (format, _, c) = decode_data(&p.id, &p.key, &p.key, &fs::read(&b).unwrap()).unwrap();
        assert_eq!(format, Format::V2);
        check(&c);
        // A password change moves the file to a new data key and writes the
        // OTP watermark, and no content change: nothing new to upload. Made
        // as from a login of the restored file: a restored session changes
        // no key (spec §2.18 #54).
        s.last = 0; // simulate a later interval without sleeping
        s.restored = false;
        change_password(&mut s, pass, "another synthetic sync password", &input).unwrap();
        let saved = fs::read(&out).unwrap();
        assert!(decode_data(&p.id, &p.key, &p.key, &saved).is_err());
        let (format, header, c) =
            decode_data(&p.id, s.keys.current(), s.keys.id_key(), &saved).unwrap();
        assert!(format == Format::V2 && c.last > 0);
        assert_eq!(header, s.header());
        check(&c);
        drop(s);
    }
    /// The temp files next to `path`, sorted.
    fn temps(path: &Path) -> Vec<PathBuf> {
        let prefix = format!("{}.", path.file_name().unwrap().to_string_lossy());
        let mut found: Vec<PathBuf> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                name.starts_with(&prefix) && name.ends_with(".goyotmp")
            })
            .collect();
        found.sort();
        found
    }
    /// A temp file of `path` as atomic_write names them, with `data`.
    fn plant(path: &Path, n: u128, data: &[u8]) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".{n:032x}.goyotmp"));
        fs::write(&name, data).unwrap();
        PathBuf::from(name)
    }
    /// Sets a file's last write time `seconds` back.
    fn age(path: &Path, seconds: u64) {
        let f = OpenOptions::new().write(true).open(path).unwrap();
        let time = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
        f.set_modified(time).unwrap();
    }
    /// What a FAT or exFAT replace that deleted `path` and could not put the
    /// temp file in its place leaves: no `path`, and the temp file.
    fn gap(path: &Path, data: &[u8]) -> PathBuf {
        CRASH.with(|c| c.set(Some("gap")));
        match atomic_write(path, data, true) {
            Err(AtomicError::GapKept(temp)) => temp,
            other => panic!("expected a kept temp file, got {other:?}"),
        }
    }
    #[test]
    fn atomic_write_keeps_the_only_copy_through_a_replace_gap() {
        let t = Temp::new();
        let p = t.file("vault.goyo");
        atomic_write(&p, b"old", false).unwrap();
        // The replace deleted the target and the retry failed too: the temp
        // file stays with the new bytes, under a name recovery looks for.
        let temp = gap(&p, b"new");
        assert!(!p.exists());
        assert_eq!(fs::read(&temp).unwrap(), b"new");
        assert_eq!(temps(&p), std::slice::from_ref(&temp));
        let found = recover::candidates(&p, MAX_FILE);
        assert!(found.len() == 1 && found[0].path == temp && found[0].bytes == b"new");
        assert_eq!(<&str>::from(AtomicError::GapKept(temp.clone())), GAP_KEPT);
        fs::remove_file(&temp).unwrap();
        // The retry without replace worked: the new file is in place.
        atomic_write(&p, b"old", false).unwrap();
        CRASH.with(|c| c.set(Some("gap_once")));
        atomic_write(&p, b"new", true).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert!(temps(&p).is_empty());
        // A crash once the temp file is flushed leaves it and the old file.
        CRASH.with(|c| c.set(Some("tmp_synced")));
        assert_eq!(
            atomic_write(&p, b"newer", true),
            Err(AtomicError::Failed(SIMULATED_CRASH))
        );
        assert_eq!(fs::read(&p).unwrap(), b"new");
        let left = temps(&p);
        assert!(left.len() == 1 && fs::read(&left[0]).unwrap() == b"newer");
        fs::remove_file(&left[0]).unwrap();
        // One right after the rename leaves the new file and no temp file.
        CRASH.with(|c| c.set(Some("renamed")));
        assert_eq!(
            atomic_write(&p, b"newest", true),
            Err(AtomicError::Failed(SIMULATED_CRASH))
        );
        assert_eq!(fs::read(&p).unwrap(), b"newest");
        assert!(temps(&p).is_empty());
        // A replace that failed with the target still there deletes the
        // temp file, as before.
        let reader = File::open(&p).unwrap();
        assert!(matches!(
            atomic_write(&p, b"blocked", true),
            Err(AtomicError::Failed(_))
        ));
        drop(reader);
        assert_eq!(fs::read(&p).unwrap(), b"newest");
        assert!(temps(&p).is_empty());
        // A target that only cannot be reached (a pulled USB stick) is not
        // taken for one the replace deleted: no temp file is kept as the only
        // copy, and the error asks for the device.
        CRASH.with(|c| c.set(Some("unplugged")));
        assert_eq!(
            atomic_write(&p, b"unreached", true),
            Err(AtomicError::Failed(SIMULATED_CRASH))
        );
        assert!(!p.exists());
        // The stick is back: the file is intact, next to the temp file that
        // could not be deleted while it was away.
        for e in fs::read_dir(&t.0).unwrap().flatten() {
            let path = e.path();
            if let Some(back) = path.to_str().and_then(|n| n.strip_suffix(".away")) {
                fs::rename(&path, back).unwrap();
            }
        }
        assert_eq!(fs::read(&p).unwrap(), b"newest");
        let left = temps(&p);
        assert!(left.len() == 1 && fs::read(&left[0]).unwrap() == b"unreached");
    }
    /// A save whose replace hit the gap leaves the new state only in its
    /// temp file. The session writes the vault file no more, so no later
    /// save gives the name to a state without it, and the next unlock takes
    /// it back.
    #[test]
    fn after_a_replace_gap_the_next_unlock_takes_the_save_back() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic replace gap password";
        let mut s = Provision::new()
            .unwrap()
            .finish(&v, &k, pass, None)
            .unwrap();
        s.put(None, entry("first")).unwrap();
        let key = fs::read(&k).unwrap();
        CRASH.with(|c| c.set(Some("gap")));
        assert_eq!(s.put(None, entry("in the temp file")), Err(GAP_KEPT));
        assert!(!v.exists());
        let kept = temps(&v);
        assert_eq!(kept.len(), 1);
        // Each of these would write the vault file without that entry.
        assert_eq!(s.put(None, entry("another")), Err(GAP_KEPT));
        assert_eq!(s.put(Some(0), entry("edited")), Err(GAP_KEPT));
        assert_eq!(s.delete(0), Err(GAP_KEPT));
        assert_eq!(s.enable_sync(), Err(GAP_KEPT));
        assert_eq!(s.format(), Format::V1);
        assert_eq!(
            change_password(&mut s, pass, "synthetic other gap password", ""),
            Err(GAP_KEPT)
        );
        assert!(!v.exists() && temps(&v) == kept);
        assert_eq!(fs::read(&k).unwrap(), key);
        drop(s);
        let secrets = |s: &Session| -> Vec<String> {
            s.entries
                .iter()
                .map(|e| e.secret.as_str().to_owned())
                .collect()
        };
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert!(s.take_recovery().vault);
        assert_eq!(secrets(&s), ["first", "in the temp file"]);
        assert!(v.exists() && temps(&v).is_empty());
        s.put(None, entry("another")).unwrap();
        drop(s);
        let s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!(secrets(&s), ["first", "in the temp file", "another"]);
        drop(s);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    #[test]
    fn unlock_takes_the_key_file_back_from_its_temp_file() {
        use std::os::windows::fs::OpenOptionsExt;
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let (pass, next) = ("synthetic recovery password", "synthetic changed password");
        let p = Provision::new().unwrap();
        let mut s = p.finish(&v, &k, pass, None).unwrap();
        s.put(None, entry("kept")).unwrap();
        drop(s);
        // A password change whose key file replace hit the gap: the new key
        // file exists only as the temp file.
        let changed = encode_key(&p.id, &p.key, None, next).unwrap();
        let temp = gap(&k, &changed);
        assert_eq!(key_candidate(&v, &k), Some(temp.clone()));
        assert!(!vault_candidates(&v));
        // The old password does not open it, and nothing moves.
        assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(AUTH_ERROR));
        assert!(!k.exists() && temp.exists());
        // The new one does, and the key file gets its name back.
        let derived = crypto::derive_count();
        let mut s = Session::unlock(&v, &k, next, "").unwrap();
        assert_eq!(crypto::derive_count(), derived + 1);
        assert_eq!(s.take_recovery(), Recovery::default());
        assert_eq!(s.key_path, normalized(&k).unwrap());
        assert_eq!(fs::read(&k).unwrap(), changed);
        assert!(temps(&k).is_empty());
        assert_eq!(&*s.entries[0].secret, "kept");
        s.backup_key(&t.file("backup.goyokey")).unwrap();
        drop(s);
        // A second unlock writes nothing.
        let before = (fs::read(&v).unwrap(), fs::read(&k).unwrap());
        drop(Session::unlock(&v, &k, next, "").unwrap());
        assert_eq!((fs::read(&v).unwrap(), fs::read(&k).unwrap()), before);

        // A torn key file (a known magic at the wrong length) is replaced.
        fs::write(&k, &changed[..100]).unwrap();
        let temp = plant(&k, 7, &changed);
        assert_eq!(key_candidate(&v, &k), Some(temp.clone()));
        drop(Session::unlock(&v, &k, next, "").unwrap());
        assert_eq!(fs::read(&k).unwrap(), changed);
        assert!(!temp.exists());
        // A key file of a newer format is not damaged: nothing replaces it.
        let mut newer = changed.clone();
        newer[..8].copy_from_slice(b"GOYOKE04");
        fs::write(&k, &newer).unwrap();
        let temp = plant(&k, 8, &changed);
        assert_eq!(key_candidate(&v, &k), None);
        assert_eq!(
            Session::unlock(&v, &k, next, "").err(),
            Some(NEWER_KEY_FORMAT)
        );
        assert_eq!(fs::read(&k).unwrap(), newer);
        // Nor is one too large to read that starts like a newer build's: it
        // is that build's file, decided on its magic at any size.
        newer.resize(recover::KEY_LIMIT * 2, 0);
        fs::write(&k, &newer).unwrap();
        assert_eq!(key_candidate(&v, &k), None);
        assert_eq!(
            Session::unlock(&v, &k, next, "").err(),
            Some(NEWER_KEY_FORMAT)
        );
        assert_eq!(fs::read(&k).unwrap(), newer);
        assert!(temp.exists());
        // Once the key file opens again, the leftover copy of it goes.
        fs::write(&k, &changed).unwrap();
        drop(Session::unlock(&v, &k, next, "").unwrap());
        assert!(!temp.exists());
        // A file too large for a key file, that starts like none, is.
        fs::write(&k, vec![0x20; recover::KEY_LIMIT * 2]).unwrap();
        let temp = plant(&k, 10, &changed);
        assert_eq!(key_candidate(&v, &k), Some(temp.clone()));
        drop(Session::unlock(&v, &k, next, "").unwrap());
        assert_eq!(fs::read(&k).unwrap(), changed);
        assert!(!temp.exists());

        // A key file that cannot get its name back: the session goes on with
        // the temp file and says so; the next unlock renames it.
        fs::remove_file(&k).unwrap();
        let temp = plant(&k, 9, &changed);
        let held = FileLock::acquire(&k).unwrap();
        let mut s = Session::unlock(&v, &k, next, "").unwrap();
        let kept = s.take_recovery().key_kept.unwrap();
        assert_eq!(kept.file_name(), temp.file_name());
        assert_eq!(s.key_path, kept);
        assert!(!k.exists() && temp.exists());
        s.backup_key(&t.file("backup-2.goyokey")).unwrap();
        drop(s);
        drop(held);
        drop(Session::unlock(&v, &k, next, "").unwrap());
        assert!(k.exists() && !temp.exists());
        // The same with the key file's lock free: another program holds an
        // unparseable key file open without delete sharing, so the temp file
        // cannot replace it, and the cleanup after the unlock leaves the copy
        // in use alone.
        fs::write(&k, b"not a key file").unwrap();
        let temp = plant(&k, 11, &changed);
        let held = OpenOptions::new()
            .read(true)
            .share_mode(1) // FILE_SHARE_READ
            .open(&k)
            .unwrap();
        let mut s = Session::unlock(&v, &k, next, "").unwrap();
        let kept = s.take_recovery().key_kept.unwrap();
        assert_eq!(kept.file_name(), temp.file_name());
        assert_eq!(s.key_path, kept);
        assert!(temp.exists());
        assert_eq!(fs::read(&k).unwrap(), b"not a key file");
        s.backup_key(&t.file("backup-3.goyokey")).unwrap();
        drop(s);
        drop(held);
        drop(Session::unlock(&v, &k, next, "").unwrap());
        assert_eq!(fs::read(&k).unwrap(), changed);
        assert!(!temp.exists());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// Recovery reads at most the four newest temp files of a file: a
    /// folder full of planted ones costs little, and an older real copy
    /// behind them is not looked at.
    #[test]
    fn recovery_reads_at_most_four_temp_files() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic many temps password";
        drop(
            Provision::new()
                .unwrap()
                .finish(&v, &k, pass, None)
                .unwrap(),
        );
        let good = fs::read(&k).unwrap();
        fs::remove_file(&k).unwrap();
        let own = plant(&k, 1, &good);
        age(&own, 600);
        let other = Provision::new().unwrap();
        let foreign = encode_key(&other.id, &other.key, None, pass).unwrap();
        let planted: Vec<PathBuf> = (2..=recover::MAX_CANDIDATES as u64 + 1)
            .map(|n| {
                let path = plant(&k, n.into(), &foreign);
                age(&path, 60 * n);
                path
            })
            .collect();
        let found = recover::candidates(&k, recover::KEY_LIMIT);
        assert_eq!(found.len(), recover::MAX_CANDIDATES);
        assert!(found.iter().all(|c| c.path != own));
        assert_eq!(key_candidate(&v, &k), None);
        assert!(Session::unlock(&v, &k, pass, "").is_err());
        assert!(!k.exists() && own.exists());
        // One planted copy fewer, and the real one is among the four.
        fs::remove_file(&planted[0]).unwrap();
        assert_eq!(key_candidate(&v, &k), Some(own.clone()));
        drop(Session::unlock(&v, &k, pass, "").unwrap());
        assert_eq!(fs::read(&k).unwrap(), good);
        assert!(!own.exists());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// A restore reads a temp copy of a missing key file, but renames
    /// nothing and makes no lock file next to its inputs, which may be on
    /// read-only media. The next unlock gives the key file its name back.
    #[test]
    fn restore_reads_a_key_temp_file_and_writes_nothing_beside_it() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic restore temp password";
        drop(
            Provision::new()
                .unwrap()
                .finish(&v, &k, pass, None)
                .unwrap(),
        );
        let backup = t.file("backup.goyo");
        let input = t.file("input.goyokey");
        fs::copy(&v, &backup).unwrap();
        let temp = plant(&input, 1, &fs::read(&k).unwrap());
        assert_eq!(key_candidate(&backup, &input), Some(temp.clone()));
        let out = t.file("restored.goyo");
        let mut s = Session::restore(&backup, &input, &out, pass, "").unwrap();
        assert_eq!(s.take_recovery(), Recovery::default());
        assert_eq!(s.key_path, normalized(&input).unwrap());
        assert!(out.exists() && temp.exists() && !input.exists());
        assert!(!t.file("input.goyokey.goyolock").exists());
        drop(s);
        drop(Session::unlock(&out, &input, pass, "").unwrap());
        assert!(input.exists() && !temp.exists());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    #[test]
    fn only_plain_temp_files_of_this_vault_stand_in_for_a_key_file() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic candidate password";
        let p = Provision::new().unwrap();
        drop(p.finish(&v, &k, pass, None).unwrap());
        let good = fs::read(&k).unwrap();
        fs::remove_file(&k).unwrap();
        let other = Provision::new().unwrap();
        let foreign = plant(
            &k,
            1,
            &encode_key(&other.id, &other.key, None, pass).unwrap(),
        );
        let mut big = good.clone();
        big.resize(recover::KEY_LIMIT + 1, 0);
        let too_big = plant(&k, 2, &big);
        // A second name of a good copy (a hard link) is not a plain file.
        fs::write(t.file("elsewhere.bin"), &good).unwrap();
        let linked = t.file(&format!("vault.goyokey.{:032x}.goyotmp", 3));
        fs::hard_link(t.file("elsewhere.bin"), &linked).unwrap();
        // Names atomic_write never gives.
        let odd = [
            format!("vault.goyokey.{}.goyotmp", "AB".repeat(16)),
            format!("vault.goyokey.{}.goyotmp", "ab".repeat(15)),
            format!("vault.goyokey.{:032x}.tmp", 4),
            format!("vault.goyokey.{:032x}.goyotmp.txt", 5),
        ];
        for name in &odd {
            fs::write(t.file(name), &good).unwrap();
        }
        assert_eq!(key_candidate(&v, &k), None);
        assert!(Session::unlock(&v, &k, pass, "").is_err());
        // Of two plain copies of this vault's key file the newest stands in;
        // the other is deleted after the unlock, everything else stays.
        let older = plant(&k, 0xa0, &good);
        let newer = plant(&k, 0xb0, &good);
        age(&older, 60);
        assert_eq!(key_candidate(&v, &k), Some(newer.clone()));
        let s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!(s.key_path, normalized(&k).unwrap());
        assert_eq!(fs::read(&k).unwrap(), good);
        assert!(!older.exists() && !newer.exists());
        assert!(foreign.exists() && too_big.exists() && linked.exists());
        assert!(odd.iter().all(|name| t.file(name).exists()));
        drop(s);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    #[test]
    fn unlock_takes_the_vault_file_back_from_its_temp_file() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic vault recovery password";
        let p = Provision::new().unwrap();
        drop(p.finish(&v, &k, pass, None).unwrap());
        let mut es = [entry("saved"), entry("newest")];
        es[0].set_ids([5; 16], NO_ID);
        es[1].set_ids([6; 16], NO_ID);
        let at = |generation: u64, n: usize| DataRef {
            last: 0,
            generation,
            seen: 0,
            entries: &es[..n],
            tombstones: &[],
        };
        let v2 = |d: DataRef| encode_data(&p.id, &p.key, &Header::Legacy, Format::V2, d).unwrap();
        fs::write(&v, v2(at(4, 1))).unwrap();
        // The save of generation 5 hit the gap. An older temp file of
        // generation 3 is newer on disk, and one planted under another key
        // claims the highest generation: neither wins.
        let kept = gap(&v, &v2(at(5, 2)));
        let stale = plant(&v, 1, &v2(at(3, 1)));
        let planted = plant(
            &v,
            2,
            &encode_data(
                &p.id,
                &[9; 32],
                &Header::Legacy,
                Format::V2,
                at(u64::MAX, 2),
            )
            .unwrap(),
        );
        age(&kept, 60);
        assert!(vault_candidates(&v));
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!(
            s.take_recovery(),
            Recovery {
                vault: true,
                key_kept: None
            }
        );
        assert_eq!((s.generation, s.entries.len()), (5, 2));
        assert!(v.exists() && !kept.exists());
        assert_eq!(
            decode_data(&p.id, &p.key, &p.key, &fs::read(&v).unwrap())
                .unwrap()
                .2
                .generation,
            5
        );
        // Copies that differ from the opened vault stay.
        assert!(stale.exists() && planted.exists());
        drop(s);
        // A copy equal to the vault but for the OTP watermark goes after the
        // next unlock; one with other contents stays.
        let mut same = at(5, 2);
        same.last = 99;
        let equal = plant(&v, 3, &v2(same));
        drop(Session::unlock(&v, &k, pass, "").unwrap());
        assert!(!equal.exists() && stale.exists() && planted.exists());

        // Only a copy under another key: never taken.
        fs::remove_file(&v).unwrap();
        fs::remove_file(&stale).unwrap();
        assert!(vault_candidates(&v));
        assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(LEFTOVER_TEMP));
        assert!(!v.exists() && planted.exists());
        // v1 copies: the newest one.
        fs::remove_file(&planted).unwrap();
        let v1_file = |n: usize| {
            encode_data(&p.id, &p.key, &Header::Legacy, Format::V1, v1(0, &es[..n])).unwrap()
        };
        let old = plant(&v, 4, &v1_file(1));
        let new = plant(&v, 5, &v1_file(2));
        age(&old, 60);
        let s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!((s.format(), s.entries.len()), (Format::V1, 2));
        assert!(!new.exists() && old.exists());
        drop(s);
        // Restore never takes a temp copy of its source.
        let missing = t.file("backup.goyo");
        plant(&missing, 6, &v1_file(2));
        assert!(Session::restore(&missing, &k, &t.file("restored.goyo"), pass, "").is_err());
        assert!(!t.file("restored.goyo").exists());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A GOYOKE03 key file of `keys` (the current one first, the ID key
    /// last) at `epoch`, whose last change expects to replace the vault file
    /// with SHA-256 `resume`. Its state is in its header.
    fn kf2_key(
        id: [u8; 16],
        keys: &[[u8; 32]],
        epoch: u64,
        otp: Option<&[u8; 20]>,
        resume: [u8; 32],
        pass: &str,
    ) -> (Vec<u8>, KeyState) {
        let spec = keyfile::Spec {
            vault_id: id,
            epoch,
            kind: keyfile::Kind::Password,
            next: 1,
            pw_id: [7; 16],
            loss: 0,
            tombstones: Vec::new(),
            resume,
        };
        let bundle = Bundle::new(keys, otp).unwrap();
        let (bytes, _) = keyfile::seal(&spec, &bundle, pass, keyfile::Plan::PasswordOnly).unwrap();
        let state = keyfile::parse(&bytes).unwrap().state();
        (bytes, state)
    }
    /// A GOYOVA03 (V1) or GOYOVA04 vault file of `entries` under `key`, with
    /// the writer state `state` and header flags `flags`.
    fn kf2_vault(
        id: [u8; 16],
        key: &[u8; 32],
        state: KeyState,
        flags: u8,
        format: Format,
        entries: &[Entry],
    ) -> Vec<u8> {
        let header = Header::Keyed {
            key_id: keyfile::key_id(&id, key),
            state,
            flags,
        };
        let d = DataRef {
            last: 0,
            generation: u64::from(format == Format::V2),
            seen: 0,
            entries,
            tombstones: &[],
        };
        encode_data(&id, key, &header, format, d).unwrap()
    }
    fn current(id: &[u8; 16], key: &[u8; 32], state: KeyState) -> Header {
        Header::Keyed {
            key_id: keyfile::key_id(id, key),
            state,
            flags: 0,
        }
    }
    fn header_of(path: &Path) -> Header {
        read_header(&fs::read(path).unwrap()).unwrap().1
    }
    /// The header a session writes now.
    fn current_of(s: &Session) -> Header {
        s.header()
    }
    fn secrets(s: &Session) -> Vec<String> {
        s.entries
            .iter()
            .map(|e| e.secret.as_str().to_owned())
            .collect()
    }
    /// A vault whose key file is KF2 (one a later build wrote) opens, and
    /// every save writes GOYOVA03/04 under the current key with the key
    /// file's state; v1 IDs come from the ID key, the last of the bundle.
    #[test]
    fn kf2_vaults_open_and_save_with_the_v3_header() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic kf2 password";
        let (id, dk1, dk0) = ([0x42; 16], [0x11; 32], [0x10; 32]);
        let (key, state) = kf2_key(id, &[dk1, dk0], 4, None, [0; 32], pass);
        fs::write(&k, &key).unwrap();
        let es = [entry("first"), entry("first"), entry("second")];
        fs::write(&v, kf2_vault(id, &dk1, state, 0, Format::V1, &es)).unwrap();
        let before = fs::read(&v).unwrap();
        assert_eq!(
            prepare(&v, &k).unwrap().check().vault,
            VaultClass::Current {
                stale_key_file: false
            }
        );
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        // No OTP, and the file is under the current key with this state:
        // nothing to save.
        assert_eq!(fs::read(&v).unwrap(), before);
        assert_eq!(s.key_state(), state);
        assert_eq!((s.max_epoch(), s.stale_key_file()), (4, false));
        assert_eq!(key_notice(&mut s), None);
        let mut by_id_key = es.to_vec();
        v1_ids(&id, &dk0, &mut by_id_key);
        let mut by_current = es.to_vec();
        v1_ids(&id, &dk1, &mut by_current);
        assert_eq!(ids(&s.entries), ids(&by_id_key));
        assert!(
            ids(&by_current)
                .iter()
                .all(|i| !ids(&s.entries).contains(i))
        );
        let header = current(&id, &dk1, state);
        s.put(None, entry("third")).unwrap();
        assert_eq!(&fs::read(&v).unwrap()[..8], DATA_MAGIC_V3);
        assert_eq!(header_of(&v), header);
        // Sync on: GOYOVA04, with the IDs every PC derives from the v1 file.
        s.enable_sync().unwrap();
        let synced = fs::read(&v).unwrap();
        assert_eq!(read_header(&synced).unwrap(), (Format::V2, header));
        let (_, _, c) = decode_data(&id, &dk1, &dk0, &synced).unwrap();
        assert_eq!(ids(&c.entries[..3]), ids(&by_id_key));
        assert_eq!(c.generation, 1);
        // A backup and a restore keep the header; nothing writes the key
        // file.
        let b = t.file("backup.goyo");
        s.backup(&b).unwrap();
        assert_eq!(
            read_header(&fs::read(&b).unwrap()).unwrap(),
            (Format::V2, header)
        );
        drop(s);
        let r = t.file("restored.goyo");
        drop(Session::restore(&b, &k, &r, pass, "").unwrap());
        assert_eq!(
            read_header(&fs::read(&r).unwrap()).unwrap(),
            (Format::V2, header)
        );
        assert_eq!(fs::read(&k).unwrap(), key);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// An older-key vault file opens at login only as the file the key
    /// file's last change expects to replace (silently) or with the user's
    /// yes for exactly those bytes; either way it is saved under the current
    /// key at once (spec §5.1 steps 5-6, §5.2 step 4, §14.3).
    #[test]
    fn older_vault_files_open_by_resume_or_a_yes() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic older key password";
        let (id, dk1, dk0) = ([0x43; 16], [0x21; 32], [0x20; 32]);
        // What a password change of a 0.8 vault leaves before its last
        // step: the vault file still in 0.8's format under the ID key.
        let probe = encode_data(
            &id,
            &dk0,
            &Header::Legacy,
            Format::V1,
            v1(0, &[entry("kept")]),
        )
        .unwrap();
        fs::write(&v, &probe).unwrap();
        let (key, state) = kf2_key(id, &[dk1, dk0], 1, None, sha256(&probe), pass);
        fs::write(&k, &key).unwrap();
        assert_eq!(prepare(&v, &k).unwrap().check().vault, VaultClass::Resume);
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!(key_notice(&mut s), Some(KeyNotice::Resumed));
        assert_eq!(secrets(&s), ["kept"]);
        assert_eq!(header_of(&v), current(&id, &dk1, state));
        drop(s);
        let completed = fs::read(&v).unwrap();
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!(key_notice(&mut s), None);
        drop(s);
        assert_eq!(fs::read(&v).unwrap(), completed);

        // Any other older-key file: never without a yes. Its header, only
        // authenticated under an old key, counts toward nothing.
        let planted_state = KeyState {
            epoch: 900,
            tag: [5; 16],
        };
        let older = kf2_vault(id, &dk0, planted_state, 0, Format::V1, &[entry("older")]);
        fs::write(&v, &older).unwrap();
        // This PC read the vault file as current under the new key: an
        // older-key file is refused before any key derivation, and so is
        // the probe the change completed, restored (S23-1 #2).
        let derived = crypto::derive_count();
        assert_eq!(prepare(&v, &k).err(), Some(OLDER_REFUSED));
        fs::write(&v, &probe).unwrap();
        assert_eq!(prepare(&v, &k).err(), Some(OLDER_REFUSED));
        assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(OLDER_REFUSED));
        assert_eq!(crypto::derive_count(), derived);
        assert!(not_a_failure(OLDER_REFUSED));
        // With no record of this vault on this PC (no anchor yet, or one
        // deleted), only a yes for these very bytes opens such a file.
        t.other_anchor("fresh");
        fs::write(&v, &older).unwrap();
        let prepared = prepare(&v, &k).unwrap();
        assert_eq!(
            prepared.check().vault,
            VaultClass::Older {
                sha: sha256(&older)
            }
        );
        assert_eq!(
            Session::unlock(&v, &k, pass, "").err(),
            Some(OLDER_NOT_CONFIRMED)
        );
        assert!(not_a_failure(OLDER_NOT_CONFIRMED));
        assert_eq!(
            (fs::read(&v).unwrap(), fs::read(&k).unwrap()),
            (older.clone(), key.clone())
        );
        // The yes was for other bytes: the file was swapped after the question.
        let swapped = kf2_vault(id, &dk0, planted_state, 0, Format::V1, &[entry("swapped")]);
        fs::write(&v, &swapped).unwrap();
        let yes = Some(sha256(&older));
        let now = otp::now().unwrap();
        assert_eq!(
            Session::login(prepared, pass, "", now, yes).err(),
            Some(OLDER_NOT_CONFIRMED)
        );
        assert_eq!(fs::read(&v).unwrap(), swapped);
        // The yes for these bytes opens them and saves them under the
        // current key.
        let prepared = prepare(&v, &k).unwrap();
        let VaultClass::Older { sha } = prepared.check().vault else {
            panic!("not older");
        };
        let mut s = Session::login(prepared, pass, "", now, Some(sha)).unwrap();
        assert_eq!(key_notice(&mut s), Some(KeyNotice::OlderAccepted));
        assert_eq!(secrets(&s), ["swapped"]);
        assert_eq!((s.max_epoch(), s.stale_key_file()), (1, false));
        assert_eq!(header_of(&v), current(&id, &dk1, state));
        drop(s);
        // A Restore takes a backup under any key of the key file, asking
        // nothing, and writes it under the current key.
        let r = t.file("restored.goyo");
        fs::write(t.file("old-backup.goyo"), &older).unwrap();
        let mut s = Session::restore(&t.file("old-backup.goyo"), &k, &r, pass, "").unwrap();
        assert_eq!(
            (secrets(&s), key_notice(&mut s)),
            (vec!["older".into()], None)
        );
        assert_eq!(header_of(&r), current(&id, &dk1, state));
        drop(s);
        // One whose key aged out of the key file: the restore message.
        let gone = kf2_vault(id, &[0x2f; 32], state, 0, Format::V1, &[entry("gone")]);
        fs::write(t.file("aged-out.goyo"), &gone).unwrap();
        let derived = crypto::derive_count();
        assert_eq!(
            Session::restore(&t.file("aged-out.goyo"), &k, &t.file("r2.goyo"), pass, "").err(),
            Some(KEY_NOT_IN_BACKUP)
        );
        assert_eq!(crypto::derive_count(), derived);
        assert!(!t.file("r2.goyo").exists());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// What the precheck refuses, it refuses before any key derivation, for
    /// a login and a Restore alike, and none of it is a failed attempt
    /// (spec §4.3, §4.7, §5.1, §14.2-7/8, §14.3).
    #[test]
    fn the_precheck_refuses_before_any_key_derivation() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic precheck password";
        let (id, dk1, dk0) = ([0x44; 16], [0x31; 32], [0x30; 32]);
        let (key, state) = kf2_key(id, &[dk1, dk0], 3, None, [0; 32], pass);
        fs::write(&k, &key).unwrap();
        let good = kf2_vault(id, &dk1, state, 0, Format::V2, &[]);
        let refused = |vault: &[u8], login: &str, restore: &str| {
            fs::write(&v, vault).unwrap();
            let derived = crypto::derive_count();
            assert_eq!(prepare(&v, &k).err(), Some(login));
            assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(login));
            let r = t.file("restored.goyo");
            assert_eq!(Session::restore(&v, &k, &r, pass, "").err(), Some(restore));
            assert_eq!(crypto::derive_count(), derived);
            assert!(not_a_failure(login) && not_a_failure(restore));
            assert!(!r.exists());
            assert_eq!(fs::read(&v).unwrap(), vault);
        };
        // A key the key file does not list; one of a security-key file.
        let unknown = [0x3f; 32];
        refused(
            &kf2_vault(id, &unknown, state, 0, Format::V2, &[]),
            KEY_NOT_IN_KEY_FILE,
            KEY_NOT_IN_BACKUP,
        );
        // The security-key build has the keys, so the bit says nothing more.
        let hardware = if cfg!(feature = "security-key") {
            (KEY_NOT_IN_KEY_FILE, KEY_NOT_IN_BACKUP)
        } else {
            (NO_SECURITY_KEY_SUPPORT_VAULT, NO_SECURITY_KEY_SUPPORT_VAULT)
        };
        for flags in [1, 3] {
            let vault = kf2_vault(id, &unknown, state, flags, Format::V2, &[]);
            refused(&vault, hardware.0, hardware.1);
        }
        // A flipped key ID names a key the key file does not list.
        let mut flipped = good.clone();
        flipped[30] ^= 1;
        refused(&flipped, KEY_NOT_IN_KEY_FILE, KEY_NOT_IN_BACKUP);
        // Headers outside the grammar.
        let damaged = |at: usize, bytes: &[u8]| {
            let mut d = good.clone();
            d[at..at + bytes.len()].copy_from_slice(bytes);
            d
        };
        for bad in [
            damaged(40, &0u64.to_le_bytes()),
            damaged(40, &(EPOCH_MAX + 1).to_le_bytes()),
            damaged(40, &u64::MAX.to_le_bytes()),
            damaged(64, &[2]),
            damaged(64, &[4]),
            damaged(64, &[0x81]),
            damaged(65, &[1]),
            damaged(67, &[0x80]),
            good[..139].to_vec(),
            kf2_vault(id, &dk1, state, 0, Format::V1, &[])[..119].to_vec(),
        ] {
            refused(&bad, VAULT_DAMAGED, VAULT_DAMAGED);
        }
        refused(&damaged(0, b"GOYOVA05"), NEWER_FORMAT, NEWER_FORMAT);
        refused(
            &kf2_vault([0x45; 16], &dk1, state, 0, Format::V2, &[]),
            OTHER_VAULT,
            OTHER_VAULT,
        );
        // A 0.8 key file lists no key ID: a GOYOVA03/04 file is under none
        // of its keys. Its header epoch, above a 0.8 key file's 0, says that
        // another PC changed the key (S23-3 #8).
        let legacy = Provision::new().unwrap();
        fs::write(&k, encode_key(&legacy.id, &legacy.key, None, pass).unwrap()).unwrap();
        let header = Header::Keyed {
            key_id: keyfile::key_id(&legacy.id, &legacy.key),
            state,
            flags: 0,
        };
        let d = v1(0, &[]);
        refused(
            &encode_data(&legacy.id, &legacy.key, &header, Format::V1, d).unwrap(),
            KEY_NOT_IN_KEY_FILE_NEWER,
            KEY_NOT_IN_BACKUP,
        );
        // The login's refusal names both epochs.
        assert_eq!(
            refusal_values(KEY_NOT_IN_KEY_FILE_NEWER),
            Some(vec!["3".into(), "0".into()])
        );
        // Security-key files, damaged and newer ones included, on their
        // magic family alone (the default build; S45-1 #16).
        fs::write(&v, &good).unwrap();
        #[cfg(not(feature = "security-key"))]
        {
            let draft = keyfile::hardware_draft(false);
            for (bytes, refusal) in [
                (draft.clone(), NO_SECURITY_KEY_SUPPORT),
                (keyfile::hardware_draft(true), NO_SECURITY_KEY_SUPPORT),
                (draft[..100].to_vec(), NO_SECURITY_KEY_SUPPORT_DAMAGED),
                ([&draft[..], &[0]].concat(), NO_SECURITY_KEY_SUPPORT_DAMAGED),
                (
                    [&b"GOYOKS02"[..], &draft[8..]].concat(),
                    NO_SECURITY_KEY_SUPPORT_DAMAGED,
                ),
            ] {
                fs::write(&k, &bytes).unwrap();
                assert_eq!(key_info(&k).unwrap().refusal(), Some(refusal));
                refused(&good, refusal, refusal);
            }
        }
        // Flips the header grammar allows fail the AEAD after one key
        // derivation: the epoch, the tag, a flag.
        fs::write(&k, &key).unwrap();
        for (at, bit) in [(41, 1), (50, 0x10), (64, 1)] {
            let mut bad = good.clone();
            bad[at] ^= bit;
            fs::write(&v, &bad).unwrap();
            assert!(prepare(&v, &k).is_ok());
            let derived = crypto::derive_count();
            assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(AUTH_ERROR));
            assert_eq!(crypto::derive_count(), derived + 1);
            assert!(!not_a_failure(AUTH_ERROR));
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// The pinned security-key files of scripts/make_key_fixtures.py, next to
    /// the vault file their PC would have saved, are refused on the key
    /// file's magic before any key derivation: by `key_info` as soon as the
    /// file is chosen, and by the precheck, the unlock and a Restore, none
    /// of which counts as a failed attempt. Damaged copies and newer magics
    /// of the family get the damaged wording; nothing is ever the AUTH text
    /// and nothing is written (spec §4.7, §14.2-7). Default build only
    /// (S45-1 #16); the next test is the security-key build's.
    #[cfg(not(feature = "security-key"))]
    #[test]
    fn pinned_security_key_files_are_refused_before_any_key_derivation() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k, r) = (
            t.file("vault.goyo"),
            t.file("vault.goyokey"),
            t.file("restored.goyo"),
        );
        let seq = |start: u8| -> [u8; 32] { std::array::from_fn(|i| start.wrapping_add(i as u8)) };
        // GOYOVA03 under the GOYOKH01 fixture, GOYOVA04 under the GOYOKS01
        // one, each under its current data key with the hardware flags.
        let vaults: Vec<Vec<u8>> = [(0, 0xa1, 1, Format::V1), (1, 0x0b, 3, Format::V2)]
            .into_iter()
            .map(|(i, dk, flags, format)| {
                let h = keyfile::parse(keyfile::SECURITY_KEY_FIXTURES[i].1).unwrap();
                kf2_vault(h.vault_id, &seq(dk), h.state(), flags, format, &[])
            })
            .collect();
        let passwords = [
            "goyo security-key fixture, KH",
            "goyo security-key fixture, KS",
            "",
        ];
        for (name, key, well_formed) in keyfile::SECURITY_KEY_FIXTURES {
            let refusal = if well_formed {
                NO_SECURITY_KEY_SUPPORT
            } else {
                NO_SECURITY_KEY_SUPPORT_DAMAGED
            };
            let vault = &vaults[usize::from(name.starts_with("goyoks"))];
            fs::write(&k, key).unwrap();
            fs::write(&v, vault).unwrap();
            let derived = crypto::derive_count();
            let info = key_info(&k).unwrap();
            assert!(info.needs_security_key, "{name}");
            assert_eq!(
                (info.well_formed, info.refusal()),
                (well_formed, Some(refusal)),
                "{name}"
            );
            assert_eq!(prepare(&v, &k).err(), Some(refusal), "{name}");
            for pass in passwords {
                assert_eq!(
                    Session::unlock(&v, &k, pass, "").err(),
                    Some(refusal),
                    "{name}"
                );
                assert_eq!(
                    Session::restore(&v, &k, &r, pass, "").err(),
                    Some(refusal),
                    "{name}"
                );
            }
            assert_eq!(crypto::derive_count(), derived, "{name}");
            assert!(not_a_failure(refusal) && refusal != AUTH_ERROR);
            assert!(!r.exists(), "{name}");
            assert_eq!(fs::read(&k).unwrap(), key, "{name}");
            assert_eq!(&fs::read(&v).unwrap(), vault, "{name}");
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// The security-key build parses the pinned files in full: the screens
    /// show what they state, the precheck takes them, and an unlock or a
    /// Restore without a touch stops at SECURITY_KEY_NEEDED before any key
    /// derivation, which is no failed attempt. A damaged copy is AUTH_ERROR
    /// as any damaged key file, a newer magic of the family
    /// NEWER_KEY_FORMAT, which no temp file replaces (spec §4.6, §4.7,
    /// §5.12 rule i, §14.2-4).
    #[cfg(feature = "security-key")]
    #[test]
    fn pinned_security_key_files_need_a_touch() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k, r) = (
            t.file("vault.goyo"),
            t.file("vault.goyokey"),
            t.file("restored.goyo"),
        );
        let seq = |start: u8| -> [u8; 32] { std::array::from_fn(|i| start.wrapping_add(i as u8)) };
        for (i, dk, flags, format) in [(0, 0xa1, 1, Format::V1), (1, 0x0b, 3, Format::V2)] {
            let (name, key, _) = keyfile::SECURITY_KEY_FIXTURES[i];
            let h = keyfile::parse(key).unwrap();
            let vault = kf2_vault(h.vault_id, &seq(dk), h.state(), flags, format, &[]);
            fs::write(&k, key).unwrap();
            fs::write(&v, &vault).unwrap();
            let info = key_info(&k).unwrap();
            assert!(info.needs_security_key && info.well_formed, "{name}");
            assert_eq!(
                (info.refusal(), info.slots, info.key_sync),
                (None, h.slots.len() as u8, i == 1),
                "{name}"
            );
            assert!(prepare(&v, &k).is_ok(), "{name}");
            // A well-formed code, so the OTP vault gets as far as the key.
            let code = if h.otp() { "123456" } else { "" };
            let derived = crypto::derive_count();
            assert_eq!(
                Session::unlock(&v, &k, "any password", code).err(),
                Some(keyfile::SECURITY_KEY_NEEDED),
                "{name}"
            );
            assert_eq!(
                Session::restore(&v, &k, &r, "any password", code).err(),
                Some(keyfile::SECURITY_KEY_NEEDED),
                "{name}"
            );
            assert_eq!(crypto::derive_count(), derived, "{name}");
            assert!(not_a_failure(keyfile::SECURITY_KEY_NEEDED));
            assert!(!r.exists());
            assert_eq!(fs::read(&k).unwrap(), key, "{name}");
            assert_eq!(fs::read(&v).unwrap(), vault, "{name}");
        }
        for (name, key, well_formed) in keyfile::SECURITY_KEY_FIXTURES {
            if well_formed {
                continue;
            }
            fs::write(&k, key).unwrap();
            let newer = name.ends_with("02");
            let error = if newer { NEWER_KEY_FORMAT } else { AUTH_ERROR };
            assert_eq!(prepare(&v, &k).err(), Some(error), "{name}");
            assert!(!key_info(&k).unwrap().well_formed, "{name}");
            assert_eq!(keyfile::never_replaced(key), newer, "{name}");
        }
        // The cross-check of S23-1 #25 at the vault level: the fake holds
        // the recorded credentials, and each key with an S-wrap unlocks the
        // pinned file and its vault file, first as a bootstrap that the
        // recorded key code confirms; the suspended key stops before Argon2.
        let recorded = [
            keyfile::inbox::tests::recorded_kh(),
            keyfile::inbox::tests::recorded_ks(),
        ];
        for (i, (r, dk, flags, format)) in [(0xa1, 1, Format::V1), (0x0b, 3, Format::V2)]
            .into_iter()
            .enumerate()
            .map(|(i, (dk, flags, format))| (i, (&recorded[i], dk, flags, format)))
        {
            let _ = t.other_anchor(&format!("fixture-{i}"));
            let h = keyfile::parse(r.bytes).unwrap();
            fs::write(&k, r.bytes).unwrap();
            fs::write(
                &v,
                kf2_vault(h.vault_id, &seq(dk), h.state(), flags, format, &[]),
            )
            .unwrap();
            let fake = r.fake(false);
            let now = otp::now().unwrap();
            for j in 0..r.key_count() {
                let prepared = prepare(&v, &k).unwrap();
                let req = prepared.unlock_request(0).unwrap();
                fake.touch(Some(j));
                let raw = crate::fido::Authenticator::get_assertion(
                    &fake,
                    &req,
                    &crate::fido::Authenticator::new_cancel(&fake).unwrap(),
                );
                let touch = crate::fido::check_assertion(raw.unwrap(), &req, false).unwrap();
                let step = now / 30 - (r.key_count() - j) as u64;
                let code = r
                    .otp
                    .map(|secret| format!("{:06}", otp::code(&secret, step, 6)))
                    .unwrap_or_default();
                let derived = crypto::derive_count();
                let login =
                    Session::login_with(prepared, r.password, &code, step * 30, None, &touch);
                if r.suspended(j) {
                    assert_eq!(login.err(), Some(keyfile::SUSPENDED_KEY), "{i} {j}");
                    assert_eq!(crypto::derive_count(), derived);
                    continue;
                }
                let mut s = login.unwrap();
                assert_eq!(s.unlocked_with(), Some(h.slots[j].number), "{i} {j}");
                assert!(s.entries.is_empty());
                let code = parse_code(r.code).unwrap();
                if s.tofu() {
                    s.tofu_confirm(Some(&code)).unwrap();
                }
                assert_eq!(s.key_code(), Some(code.show(h.epoch)), "{i} {j}");
            }
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// This build can tell neither a damaged security-key file nor one over
    /// 32 KiB from a later build's, so it decides every one on its magic:
    /// SUBMIT refuses it as the file dialog did, and no temp file stands in
    /// for it or replaces it, not even a password-only key file of the same
    /// vault that the password opens (spec §4.6, §4.7, §5.12 rule i,
    /// §14.2-7). Default build only (S45-1 #16).
    #[cfg(not(feature = "security-key"))]
    #[test]
    fn security_key_files_are_never_replaced_by_a_temp_file() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k, r) = (
            t.file("vault.goyo"),
            t.file("vault.goyokey"),
            t.file("restored.goyo"),
        );
        let pass = "synthetic never replaced password";
        let (id, dk1, dk0) = ([0x4a; 16], [0x81; 32], [0x80; 32]);
        let (own, state) = kf2_key(id, &[dk1, dk0], 3, None, [0; 32], pass);
        let vault = kf2_vault(id, &dk1, state, 0, Format::V1, &[entry("kept")]);
        fs::write(&v, &vault).unwrap();
        let fixture = |name: &str| {
            keyfile::SECURITY_KEY_FIXTURES
                .iter()
                .find(|f| f.0 == name)
                .unwrap()
                .1
                .to_vec()
        };
        let over = |name: &str| {
            let mut big = fixture(name);
            big.resize(40_000, 0);
            big
        };
        for (what, key) in [
            ("truncated GOYOKH01", fixture("goyokh01-truncated")),
            (
                "GOYOKS01 with a reserved byte",
                fixture("goyoks01-reserved"),
            ),
            ("GOYOKH01 over 32 KiB", over("goyokh01")),
            ("GOYOKS01 over 32 KiB", over("goyoks01")),
            ("GOYOKH02 over 32 KiB", over("goyokh02")),
        ] {
            fs::write(&k, &key).unwrap();
            let refusal = NO_SECURITY_KEY_SUPPORT_DAMAGED;
            for temp in [false, true] {
                // The temp copy of a key file of this vault, which the
                // password opens.
                let planted = temp.then(|| plant(&k, 7, &own));
                let derived = crypto::derive_count();
                assert_eq!(key_info(&k).unwrap().refusal(), Some(refusal), "{what}");
                assert_eq!(key_candidate(&v, &k), None, "{what}");
                assert_eq!(prepare(&v, &k).err(), Some(refusal), "{what}");
                assert_eq!(
                    Session::unlock(&v, &k, pass, "").err(),
                    Some(refusal),
                    "{what}"
                );
                assert_eq!(
                    Session::restore(&v, &k, &r, pass, "").err(),
                    Some(refusal),
                    "{what}"
                );
                assert_eq!(crypto::derive_count(), derived, "{what}");
                assert_eq!(fs::read(&k).unwrap(), key, "{what}");
                assert_eq!(fs::read(&v).unwrap(), vault, "{what}");
                assert!(!r.exists(), "{what}");
                if let Some(planted) = planted {
                    assert_eq!(fs::read(&planted).unwrap(), own, "{what}");
                    fs::remove_file(planted).unwrap();
                }
            }
        }
        // A newer build's key file over 32 KiB is that build's, not damaged.
        let mut newer = own.clone();
        newer[..8].copy_from_slice(b"GOYOKE04");
        newer.resize(40_000, 0);
        fs::write(&k, &newer).unwrap();
        let planted = plant(&k, 7, &own);
        assert_eq!(key_candidate(&v, &k), None);
        assert_eq!(prepare(&v, &k).err(), Some(NEWER_KEY_FORMAT));
        assert_eq!(fs::read(&k).unwrap(), newer);
        fs::remove_file(planted).unwrap();
        // Unlike a key file of a known password-only format, damaged here:
        // there the temp copy stands in and takes the key file's name back.
        let mut torn = own.clone();
        torn.truncate(200);
        fs::write(&k, &torn).unwrap();
        let planted = plant(&k, 7, &own);
        assert_eq!(key_candidate(&v, &k), Some(planted.clone()));
        drop(Session::unlock(&v, &k, pass, "").unwrap());
        assert_eq!(fs::read(&k).unwrap(), own);
        assert!(!planted.exists());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// The vault file's header epoch counts toward `max_epoch` only under
    /// the current key and only EPOCH_SILENT above the key file; a vault
    /// file ahead of the key file is StaleKeyFile, one behind it, or in the
    /// 0.8 format, is saved again with the key file's state (spec §4.3,
    /// §5.2 steps 7-8).
    #[test]
    fn vault_header_epochs_and_the_resave_at_unlock() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic epoch password";
        let (id, dk1, dk0) = ([0x46; 16], [0x41; 32], [0x40; 32]);
        let (key, state) = kf2_key(id, &[dk1, dk0], 5, None, [0; 32], pass);
        fs::write(&k, &key).unwrap();
        let at = |epoch: u64| KeyState {
            epoch,
            tag: [9; 16],
        };
        for (epoch, max) in [(9, 9), (5 + (1 << 40), 5 + EPOCH_SILENT)] {
            let ahead = kf2_vault(id, &dk1, at(epoch), 0, Format::V1, &[entry("ahead")]);
            fs::write(&v, &ahead).unwrap();
            assert_eq!(
                prepare(&v, &k).unwrap().check().vault,
                VaultClass::Current {
                    stale_key_file: true
                }
            );
            let mut s = Session::unlock(&v, &k, pass, "").unwrap();
            assert_eq!((s.stale_key_file(), s.max_epoch()), (true, max));
            assert_eq!(key_notice(&mut s), Some(KeyNotice::StaleKeyFile));
            drop(s);
            assert_eq!(fs::read(&v).unwrap(), ahead);
        }
        // Behind the key file (a change that kept the data key and did not
        // save the vault file again): saved again with the key file's state.
        fs::write(
            &v,
            kf2_vault(id, &dk1, at(3), 0, Format::V1, &[entry("behind")]),
        )
        .unwrap();
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!((s.stale_key_file(), s.max_epoch()), (false, 5));
        assert_eq!(key_notice(&mut s), None);
        drop(s);
        assert_eq!(header_of(&v), current(&id, &dk1, state));
        // A KF2 key file whose current key is the ID key and a 0.8 vault
        // file under it: current, saved again in the GOYOVA03 format. Another
        // state of the vault from scratch, on a PC with no record of it.
        t.other_anchor("one");
        let (one, one_state) = kf2_key(id, &[dk0], 1, None, [0; 32], pass);
        fs::write(&k, &one).unwrap();
        let legacy = encode_data(
            &id,
            &dk0,
            &Header::Legacy,
            Format::V1,
            v1(0, &[entry("08")]),
        );
        fs::write(&v, legacy.unwrap()).unwrap();
        drop(Session::unlock(&v, &k, pass, "").unwrap());
        assert_eq!(header_of(&v), current(&id, &dk0, one_state));
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// A KF2 session's password change rotates the data key (spec §5.5):
    /// the new key file holds the new key first and the old ones after it,
    /// the vault file moves to the new key, and only the new password opens
    /// the key file. The OTP backup and the key backup verify against it.
    #[test]
    fn a_kf2_session_changes_its_password() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let (pass, next) = (
            "synthetic kf2 change password",
            "another synthetic password",
        );
        let (id, dk1, dk0) = ([0x47; 16], [0x51; 32], [0x50; 32]);
        let (key, state) = kf2_key(id, &[dk1, dk0], 2, None, [0; 32], pass);
        fs::write(&k, &key).unwrap();
        fs::write(
            &v,
            kf2_vault(id, &dk1, state, 0, Format::V1, &[entry("kept")]),
        )
        .unwrap();
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!(s.password_change(), Ok(None));
        assert_eq!(change_password(&mut s, pass, next, ""), Ok(Rekeyed::Done));
        let h = keyfile::parse(&fs::read(&k).unwrap()).unwrap();
        assert_eq!((h.epoch, h.kind), (3, keyfile::Kind::Password));
        assert_eq!(h.key_ids.len(), 3);
        assert_eq!(
            h.key_ids[1..],
            [keyfile::key_id(&id, &dk1), keyfile::key_id(&id, &dk0)]
        );
        assert_eq!(s.key_state(), h.state());
        assert_eq!(header_of(&v), current_of(&s));
        assert!(!opens(&k, pass) && opens(&k, next));
        assert!(decode_data(&id, &dk1, &dk0, &fs::read(&v).unwrap()).is_err());
        // The same password again: refused before anything is written.
        let files = (fs::read(&v).unwrap(), fs::read(&k).unwrap());
        assert_eq!(change_password(&mut s, next, next, ""), Err(SAMEPASS));
        assert_eq!((fs::read(&v).unwrap(), fs::read(&k).unwrap()), files);
        assert_eq!(
            s.otp_setup(next).err(),
            Some("이 금고는 OTP를 쓰지 않습니다.")
        );
        assert!(s.key_backup_due());
        s.backup_key(&t.file("key-backup.goyokey")).unwrap();
        assert_eq!(fs::read(t.file("key-backup.goyokey")).unwrap(), files.1);
        assert!(!s.key_backup_due());
        drop(s);
        // The key backup is recorded: no reminder at the next unlock.
        let mut s = Session::unlock(&v, &k, next, "").unwrap();
        assert_eq!(s.take_key_notices(), []);
        assert_eq!(secrets(&s), ["kept"]);
        drop(s);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// A vault made in this build without a security key is GOYOKE01/02 and
    /// GOYOVA01/02 throughout, as 0.8 writes them (spec §4.1, §14.2-9).
    #[test]
    fn new_vaults_stay_in_the_08_formats() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let pass = "synthetic 0.8 format password";
        for with_otp in [false, true] {
            let v = t.file(&format!("vault-{with_otp}.goyo"));
            let k = t.file(&format!("vault-{with_otp}.goyokey"));
            let p = Provision::new().unwrap();
            let code = format!(
                "{:06}",
                otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
            );
            let mut s = p.finish(&v, &k, pass, with_otp.then_some(&*code)).unwrap();
            let (magic, size) = if with_otp {
                (KEY_MAGIC, 148)
            } else {
                (KEY_MAGIC_NO_OTP, 128)
            };
            let key = fs::read(&k).unwrap();
            assert_eq!((&key[..8], key.len()), (&magic[..], size));
            assert_eq!(&fs::read(&v).unwrap()[..8], DATA_MAGIC_V1);
            assert_eq!(header_of(&v), Header::Legacy);
            let state = s.key_state();
            assert_eq!((state.epoch, s.max_epoch()), (0, 0));
            s.put(None, entry("kept")).unwrap();
            s.enable_sync().unwrap();
            assert_eq!(&fs::read(&v).unwrap()[..8], DATA_MAGIC_V2);
            // 0.8's decoder reads it: the ID key is the one key.
            let (_, _, c) = decode_data(&p.id, &p.key, &p.key, &fs::read(&v).unwrap()).unwrap();
            assert_eq!(ids(&c.entries), ids(&s.entries));
            // Until the first key change: then GOYOKE03 and GOYOVA04 (spec
            // §1 rule 15).
            s.last = 0; // a later interval, without sleeping
            change_password(&mut s, pass, "another 0.8 format password", &code).unwrap();
            assert_eq!(&fs::read(&k).unwrap()[..8], b"GOYOKE03");
            assert_eq!(&fs::read(&v).unwrap()[..8], DATA_MAGIC_V4);
            assert_eq!(s.key_state().epoch, state.epoch + 1);
            drop(s);
            let input = if with_otp { "" } else { "123456" };
            assert!(
                Session::unlock(&v, &k, "another 0.8 format password", input).is_err() == with_otp
            );
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// The OTP code is checked as of when it was typed, so a question in
    /// between does not let it expire, but never more than 3 minutes back
    /// nor ahead of the clock (spec §5.2 step 6, §14.3).
    #[test]
    fn the_otp_code_counts_as_of_when_it_was_typed() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic typed otp password";
        let p = Provision::new().unwrap();
        let now = otp::now().unwrap();
        let code_at = |time: u64| format!("{:06}", otp::code(p.otp.as_slice(), time / 30, 6));
        let mut s = p.finish(&v, &k, pass, Some(&code_at(now))).unwrap();
        s.last = 0; // as if made minutes ago
        s.save().unwrap();
        drop(s);
        let login = |code: &str, typed: u64| {
            Session::login(prepare(&v, &k).unwrap(), pass, code, typed, None).map(drop)
        };
        // Typed 100 s ago: accepted, and the same step is spent.
        login(&code_at(now - 100), now - 100).unwrap();
        assert_eq!(login(&code_at(now - 100), now - 100), Err(AUTH_ERROR));
        // Typed more than 3 minutes ago, or in the future: refused.
        assert_eq!(login(&code_at(now - 190), now - 190), Err(AUTH_ERROR));
        assert_eq!(login(&code_at(now + 60), now + 60), Err(AUTH_ERROR));
        login(&code_at(now), now).unwrap();
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// The unlock's save of an older-key vault file under the current key
    /// goes through Session::write: a replace gap fails the unlock and the
    /// next unlock takes the temp file back (spec §5.2 step 8, §5.7); any
    /// other failure leaves the session open and the next save or poll
    /// does it.
    #[test]
    fn the_resave_at_unlock_meets_the_gap_and_other_failures() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic resave password";
        let (id, dk1, dk0) = ([0x48; 16], [0x61; 32], [0x60; 32]);
        let (key, state) = kf2_key(id, &[dk1, dk0], 2, None, [0; 32], pass);
        fs::write(&k, &key).unwrap();
        let older = kf2_vault(id, &dk0, state, 0, Format::V1, &[entry("older")]);
        let yes = |v: &Path| {
            let prepared = prepare(v, &k).unwrap();
            let VaultClass::Older { sha } = prepared.check().vault else {
                panic!("not older");
            };
            Session::login(prepared, pass, "", otp::now().unwrap(), Some(sha))
        };
        fs::write(&v, &older).unwrap();
        CRASH.with(|c| c.set(Some("gap")));
        assert_eq!(yes(&v).err(), Some(GAP_KEPT));
        assert!(!v.exists() && temps(&v).len() == 1);
        // The temp file is under the current key: it comes back, no question.
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert!(s.take_recovery().vault);
        assert_eq!(secrets(&s), ["older"]);
        drop(s);
        assert_eq!(header_of(&v), current(&id, &dk1, state));
        // The replace fails while another program holds the file open: the
        // session opens and says the save is pending; the next poll saves.
        // On a PC with no record of the vault yet, so the older file is
        // asked about again.
        t.other_anchor("held");
        fs::write(&v, &older).unwrap();
        let held = File::open(&v).unwrap();
        let mut s = yes(&v).unwrap();
        assert_eq!(key_notice(&mut s), Some(KeyNotice::ResavePending));
        assert!(s.resave_due);
        assert_eq!(fs::read(&v).unwrap(), older);
        drop(held);
        assert_eq!(s.poll_sync(), None);
        assert!(!s.resave_due);
        assert_eq!(header_of(&v), current(&id, &dk1, state));
        drop(s);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// A 0.8 vault file whose contents lie in the 44 bytes that its header
    /// leaves of 8 MiB and the KF2 header does not: under a KF2 key file it
    /// opens without an OTP, is saved again only once entries make room,
    /// and says so; a Restore or an OTP vault, which must write it first,
    /// is refused, and neither counts as a failed attempt (spec §4.3, §5.2
    /// step 8).
    #[test]
    fn a_full_08_vault_file_and_the_longer_header() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k, r) = (
            t.file("vault.goyo"),
            t.file("vault.goyokey"),
            t.file("restored.goyo"),
        );
        let pass = "synthetic full vault password";
        let (id, dk1, dk0) = ([0x4b; 16], [0x91; 32], [0x90; 32]);
        let full = super::tests::filling(MAX_FILE - LEGACY_OVERHEAD - 20);
        let d = DataRef {
            last: 0,
            generation: 1,
            seen: 0,
            entries: &full,
            tombstones: &[],
        };
        let old = encode_data(&id, &dk0, &Header::Legacy, Format::V2, d).unwrap();
        assert_eq!(old.len(), MAX_FILE - 20);
        fs::write(&v, &old).unwrap();
        // The file a password change of this 0.8 vault expects to replace.
        let (key, state) = kf2_key(id, &[dk1, dk0], 1, None, sha256(&old), pass);
        fs::write(&k, &key).unwrap();
        assert_eq!(prepare(&v, &k).unwrap().check().vault, VaultClass::Resume);
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert_eq!(key_notice(&mut s), Some(KeyNotice::ResaveTooLarge));
        assert!(s.resave_due);
        assert_eq!(fs::read(&v).unwrap(), old);
        assert_eq!(s.poll_sync(), None);
        assert_eq!(fs::read(&v).unwrap(), old);
        // Deleting an entry makes room: the save writes the KF2 format.
        s.delete(0).unwrap();
        assert!(!s.resave_due);
        assert_eq!(header_of(&v), current(&id, &dk1, state));
        assert_eq!(s.entries.len(), full.len() - 1);
        drop(s);
        // A Restore of the full file writes it first: refused.
        let backup = t.file("backup.goyo");
        fs::write(&backup, &old).unwrap();
        let derived = crypto::derive_count();
        assert_eq!(
            Session::restore(&backup, &k, &r, pass, "").err(),
            Some(RESAVE_TOO_LARGE)
        );
        assert_eq!(crypto::derive_count(), derived + 1);
        assert!(not_a_failure(RESAVE_TOO_LARGE) && !r.exists());
        // So does a login of an OTP vault, which saves the code it took (on a
        // PC with no record of this other key file's state).
        t.other_anchor("otp");
        let secret = [0x5c; 20];
        let (key, _) = kf2_key(id, &[dk1, dk0], 1, Some(&secret), sha256(&old), pass);
        fs::write(&k, &key).unwrap();
        fs::write(&v, &old).unwrap();
        let code = format!("{:06}", otp::code(&secret, otp::now().unwrap() / 30, 6));
        assert_eq!(
            Session::unlock(&v, &k, pass, &code).err(),
            Some(RESAVE_TOO_LARGE)
        );
        assert_eq!(fs::read(&v).unwrap(), old);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
    /// Temp-candidate recovery with KF2 files: a key file's temp copy of the
    /// highest epoch stands in (rule i), a vault file's only under the
    /// current key (rule iii), and copies of the vault under any key of the
    /// bundle that hold nothing more go (rule iv).
    #[test]
    fn kf2_files_come_back_from_their_temp_files() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let t = Temp::new();
        let (v, k) = (t.file("vault.goyo"), t.file("vault.goyokey"));
        let pass = "synthetic kf2 temp password";
        let (id, dk1, dk0) = ([0x49; 16], [0x71; 32], [0x70; 32]);
        let (key, state) = kf2_key(id, &[dk1, dk0], 6, None, [0; 32], pass);
        let (lower, _) = kf2_key(id, &[dk1, dk0], 5, None, [0; 32], "an older key password");
        let es = [entry("kept")];
        fs::write(&v, kf2_vault(id, &dk1, state, 0, Format::V1, &es)).unwrap();
        let newest = plant(&k, 1, &key);
        let older = plant(&k, 2, &lower);
        age(&newest, 60);
        assert_eq!(key_candidate(&v, &k), Some(newest.clone()));
        let s = Session::unlock(&v, &k, pass, "").unwrap();
        drop(s);
        assert_eq!(fs::read(&k).unwrap(), key);
        assert!(!newest.exists() && !older.exists());
        // The vault file only as temp files: the one under the current key.
        let saved = fs::read(&v).unwrap();
        fs::remove_file(&v).unwrap();
        let planted = kf2_vault(id, &dk0, state, 0, Format::V1, &[entry("planted")]);
        let old_key = plant(&v, 3, &planted);
        assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(LEFTOVER_TEMP));
        let kept = plant(&v, 4, &saved);
        age(&kept, 60);
        let mut s = Session::unlock(&v, &k, pass, "").unwrap();
        assert!(s.take_recovery().vault);
        assert_eq!(secrets(&s), ["kept"]);
        drop(s);
        assert!(v.exists() && !kept.exists() && old_key.exists());
        // An older-key copy of the same contents says nothing more: it goes.
        let same = kf2_vault(id, &dk0, state, 0, Format::V1, &es);
        let same = plant(&v, 5, &same);
        drop(Session::unlock(&v, &k, pass, "").unwrap());
        assert!(!same.exists() && old_key.exists());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
}
#[cfg(not(windows))]
fn publish(temp: &Path, target: &Path, replace: bool) -> Result<()> {
    if !replace {
        return Err("Windows에서만 저장할 수 있습니다.");
    }
    fs::rename(temp, target).map_err(|_| "파일 교체 실패")
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyfile::decode_key;
    #[test]
    fn parser_and_binding() {
        let es = vec![
            Entry::new(
                "테스트".into(),
                "니모닉".into(),
                "private words".into(),
                "메모".into(),
            )
            .unwrap(),
        ];
        let data =
            encode_data(&[1; 16], &[2; 32], &Header::Legacy, Format::V1, v1(7, &es)).unwrap();
        assert!(!data.windows(13).any(|s| s == b"private words"));
        let (format, _, got) = decode_data(&[1; 16], &[2; 32], &[2; 32], &data).unwrap();
        assert_eq!((format, got.last), (Format::V1, 7));
        assert_eq!(&*got.entries[0].secret, "private words");
        assert!(decode_data(&[3; 16], &[2; 32], &[2; 32], &data).is_err());
        for n in 0..data.len() {
            assert!(decode_data(&[1; 16], &[2; 32], &[2; 32], &data[..n]).is_err());
        }
        for i in 0..data.len() {
            let mut bad = data.clone();
            bad[i] ^= 1;
            assert!(decode_data(&[1; 16], &[2; 32], &[2; 32], &bad).is_err());
        }
    }
    fn v1(last: u64, entries: &[Entry]) -> DataRef<'_> {
        DataRef {
            last,
            generation: 0,
            seen: 0,
            entries,
            tombstones: &[],
        }
    }
    fn entry(title: &str, secret: &str) -> Entry {
        Entry::new(title.into(), String::new(), secret.into(), String::new()).unwrap()
    }
    fn ids(entries: &[Entry]) -> Vec<EntryId> {
        entries.iter().map(Entry::id).collect()
    }
    #[test]
    fn v2_round_trip_and_binding() {
        let mut es = vec![entry("메일", "private words"), entry("bank", "pin")];
        es[0].set_ids([5; 16], NO_ID);
        es[1].set_ids([6; 16], [9; 16]);
        let d = DataRef {
            last: 7,
            generation: 11,
            seen: 10,
            entries: &es,
            tombstones: &[[9; 16], [8; 16]],
        };
        let data = encode_data(&[1; 16], &[2; 32], &Header::Legacy, Format::V2, d).unwrap();
        assert_eq!(&data[..24], [&DATA_MAGIC_V2[..], &[1u8; 16][..]].concat());
        assert!(!data.windows(13).any(|s| s == b"private words"));
        let (format, _, c) = decode_data(&[1; 16], &[2; 32], &[2; 32], &data).unwrap();
        assert_eq!(format, Format::V2);
        assert_eq!((c.last, c.generation, c.seen), (7, 11, 10));
        assert_eq!(ids(&c.entries), [[5; 16], [6; 16]]);
        assert_eq!(c.entries[1].parent, [9; 16]);
        assert_eq!(c.tombstones, [[9; 16], [8; 16]]);
        assert_eq!(&*c.entries[0].secret, "private words");
        assert!(c.entries[1].same_content(&es[1]));
        assert!(decode_data(&[3; 16], &[2; 32], &[2; 32], &data).is_err());
        assert!(decode_data(&[1; 16], &[3; 32], &[3; 32], &data).is_err());
        for n in 0..data.len() {
            assert!(decode_data(&[1; 16], &[2; 32], &[2; 32], &data[..n]).is_err());
        }
        for i in 0..data.len() {
            let mut bad = data.clone();
            bad[i] ^= 1;
            assert!(decode_data(&[1; 16], &[2; 32], &[2; 32], &bad).is_err());
        }
        // The magic is authenticated: a v2 file relabelled v1 is refused.
        let mut relabelled = data.clone();
        relabelled[..8].copy_from_slice(DATA_MAGIC_V1);
        assert_eq!(
            decode_data(&[1; 16], &[2; 32], &[2; 32], &relabelled).err(),
            Some(AUTH_ERROR)
        );
        // A newer format is named before any decryption, whatever the key.
        for magic in [b"GOYOVA05", b"GOYOVA10", b"GOYOVA99"] {
            let mut newer = data.clone();
            newer[..8].copy_from_slice(magic);
            assert_eq!(
                decode_data(&[3; 16], &[4; 32], &[4; 32], &newer).err(),
                Some(NEWER_FORMAT)
            );
            assert_eq!(
                decode_data(&[3; 16], &[4; 32], &[4; 32], &newer[..8]).err(),
                Some(NEWER_FORMAT)
            );
        }
        for magic in [b"GOYOVA00", b"GOYOVA0x", b"GOYOVB03", b"goyova03"] {
            let mut other = data.clone();
            other[..8].copy_from_slice(magic);
            assert_eq!(
                decode_data(&[1; 16], &[2; 32], &[2; 32], &other).err(),
                Some(AUTH_ERROR)
            );
        }
    }
    #[test]
    fn v1_ids_are_deterministic() {
        let es = vec![
            entry("same", "secret"),
            entry("other", "secret"),
            entry("same", "secret"),
        ];
        let decode = |vault: &[u8; 16], key: &[u8; 32]| {
            let data = encode_data(vault, key, &Header::Legacy, Format::V1, v1(3, &es)).unwrap();
            assert_eq!(&data[..8], DATA_MAGIC_V1);
            let (format, _, c) = decode_data(vault, key, key, &data).unwrap();
            assert_eq!(format, Format::V1);
            assert_eq!((c.last, c.generation, c.seen), (3, 0, 0));
            assert!(c.tombstones.is_empty());
            assert!(c.entries.iter().all(|e| e.parent == NO_ID));
            c
        };
        let a = decode(&[1; 16], &[2; 32]);
        // Every PC must derive the same IDs: vectors from Python's hmac.
        let hex = |id: EntryId| id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(a.entries[0].id), "734a865baafcdaf1039def39f95542fb");
        assert_eq!(hex(a.entries[2].id), "c1255ba186ea1086a39b1688aa77e307");
        // Stable across encodings (each with a new nonce) and decodes.
        assert_eq!(ids(&a.entries), ids(&decode(&[1; 16], &[2; 32]).entries));
        // Equal entries are told apart by occurrence; none is zero.
        let set: BTreeSet<EntryId> = ids(&a.entries).into_iter().collect();
        assert_eq!(set.len(), 3);
        assert!(!set.contains(&NO_ID));
        // Another data key or another vault derives other IDs.
        for other in [decode(&[1; 16], &[3; 32]), decode(&[4; 16], &[2; 32])] {
            assert!(ids(&other.entries).iter().all(|id| !set.contains(id)));
        }
        // v1 leaves IDs, counters and tombstones out.
        let mut changed = a.clone();
        changed.entries[0].set_ids([7; 16], [8; 16]);
        let d = DataRef {
            last: 3,
            generation: 9,
            seen: 4,
            entries: &changed.entries,
            tombstones: &[[8; 16]],
        };
        let data = encode_data(&[1; 16], &[2; 32], &Header::Legacy, Format::V1, d).unwrap();
        let (_, _, back) = decode_data(&[1; 16], &[2; 32], &[2; 32], &data).unwrap();
        assert_eq!(ids(&back.entries), ids(&a.entries));
        assert!(back.tombstones.is_empty() && back.generation == 0 && back.seen == 0);
    }
    #[test]
    fn key_password_and_tamper() {
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let secret = Zeroizing::new([3; 20]);
        let bytes = encode_key(&[1; 16], &[2; 32], Some(&secret), "long-test-password").unwrap();
        let (_, key, otp) = decode_key(&bytes, "long-test-password").unwrap();
        assert_eq!(**key, [2; 32]);
        assert_eq!(**otp.unwrap(), [3; 20]);
        assert!(decode_key(&bytes, "wrong-password").is_err());
        let mut bad = bytes.clone();
        bad[8] ^= 1;
        assert!(decode_key(&bad, "long-test-password").is_err());
        // Without an OTP: 128 bytes, data key only.
        let plain = encode_key(&[1; 16], &[2; 32], None, "long-test-password").unwrap();
        assert_eq!((plain.len(), &plain[..8]), (128, &b"GOYOKE02"[..]));
        let (_, key, otp) = decode_key(&plain, "long-test-password").unwrap();
        assert!(**key == [2; 32] && otp.is_none());
        // Neither kind passes as the other: the magic is authenticated, and
        // a relabelled or truncated file is refused.
        let mut relabelled = bytes.clone();
        relabelled[..8].copy_from_slice(b"GOYOKE02");
        assert!(decode_key(&relabelled, "long-test-password").is_err());
        assert!(decode_key(&relabelled[..128], "long-test-password").is_err());
        let mut relabelled = plain;
        relabelled[..8].copy_from_slice(b"GOYOKE01");
        assert!(decode_key(&relabelled, "long-test-password").is_err());
    }
    #[test]
    fn storage_lock_and_overwrite() {
        let dir = std::env::temp_dir().join(format!(
            "goyo-test-{:x}",
            u128::from_le_bytes(*crypto::random::<16>().unwrap())
        ));
        fs::create_dir(&dir).unwrap();
        let p = dir.join("test.goyo");
        atomic_write(&p, b"encrypted", false).unwrap();
        assert!(atomic_write(&p, b"overwrite", false).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"encrypted");
        let lock = FileLock::acquire(&p).unwrap();
        assert!(FileLock::acquire(&p).is_err());
        drop(lock);
        atomic_write(&p, b"updated", true).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"updated");
        // Any open handle on the target blocks the replace. One that stays
        // open fails it after about 100 ms of retries; one that closes soon
        // (a scanner, the sync helper reading a file) is waited for.
        let reader = File::open(&p).unwrap();
        let start = std::time::Instant::now();
        assert!(atomic_write(&p, b"blocked", true).is_err());
        assert!(start.elapsed() >= std::time::Duration::from_millis(80));
        // The first try fails on it and the handle closes during the wait.
        CLOSES_SOON.set(Some(reader));
        atomic_write(&p, b"after retry", true).unwrap();
        assert!(CLOSES_SOON.take().is_none());
        assert_eq!(fs::read(&p).unwrap(), b"after retry");
        fs::remove_file(&p).unwrap();
        fs::remove_file(dir.join("test.goyo.goyolock")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    /// GOYOVA03/04: GOYOVA01/02's contents under a 92-byte header that is the
    /// AAD. What the header grammar refuses is VAULT_DAMAGED before any key;
    /// any other change fails the AEAD (spec §4.3, §14.2-8, §14.2-10).
    #[test]
    fn goyova03_04_round_trip_and_header_grammar() {
        let (id, key, id_key) = ([1; 16], [2; 32], [3; 32]);
        let state = KeyState {
            epoch: 7,
            tag: [4; 16],
        };
        let header = Header::Keyed {
            key_id: [5; 16],
            state,
            flags: 3,
        };
        let mut es = vec![entry("메일", "private words"), entry("bank", "pin")];
        es[0].set_ids([5; 16], NO_ID);
        es[1].set_ids([6; 16], [9; 16]);
        let d = DataRef {
            last: 7,
            generation: 11,
            seen: 10,
            entries: &es,
            tombstones: &[[9; 16]],
        };
        for (format, magic) in [(Format::V1, DATA_MAGIC_V3), (Format::V2, DATA_MAGIC_V4)] {
            let data = encode_data(&id, &key, &header, format, d).unwrap();
            assert_eq!(&data[..8], magic);
            assert_eq!((&data[8..24], &data[24..40]), (&[1; 16][..], &[5; 16][..]));
            assert_eq!(data[40..48], 7u64.to_le_bytes());
            assert_eq!(
                (&data[48..64], &data[64..68]),
                (&[4; 16][..], &[3, 0, 0, 0][..])
            );
            let tombstones = if format == Format::V2 { 1 } else { 0 };
            assert_eq!(
                data.len(),
                plain_size(format, &es, tombstones) + KEYED_OVERHEAD
            );
            assert!(!data.windows(13).any(|s| s == b"private words"));
            assert_eq!(read_header(&data).unwrap(), (format, header));
            let (f, h, c) = decode_data(&id, &key, &id_key, &data).unwrap();
            assert_eq!((f, h), (format, header));
            assert_eq!(&*c.entries[0].secret, "private words");
            if format == Format::V2 {
                assert_eq!((c.last, c.generation, c.seen), (7, 11, 10));
                assert_eq!(ids(&c.entries), [[5; 16], [6; 16]]);
                assert_eq!(c.tombstones, [[9; 16]]);
            } else {
                // v1 IDs under the ID key, as 0.8 derives them under its key.
                let mut expected = es.clone();
                v1_ids(&id, &id_key, &mut expected);
                assert_eq!(ids(&c.entries), ids(&expected));
                assert_eq!((c.last, c.generation, c.seen), (7, 0, 0));
            }
            assert!(decode_data(&id, &id_key, &id_key, &data).is_err());
            assert!(decode_data(&[8; 16], &key, &id_key, &data).is_err());
            // Every truncation and every flipped bit is refused.
            for n in 0..data.len() {
                assert!(decode_data(&id, &key, &id_key, &data[..n]).is_err());
            }
            for i in 0..data.len() {
                for bit in [0x01, 0x80] {
                    let mut bad = data.clone();
                    bad[i] ^= bit;
                    assert!(decode_data(&id, &key, &id_key, &bad).is_err(), "{i}");
                }
            }
            // The smallest file of each layout; a byte less is damaged.
            let empty = DataRef {
                entries: &[],
                tombstones: &[],
                ..d
            };
            let small = encode_data(&id, &key, &header, format, empty).unwrap();
            let smallest = if format == Format::V1 { 120 } else { 140 };
            assert_eq!(small.len(), smallest);
            assert!(decode_data(&id, &key, &id_key, &small).is_ok());
            assert_eq!(
                read_header(&small[..smallest - 1]).err(),
                Some(VAULT_DAMAGED)
            );
            let with = |at: usize, bytes: &[u8]| {
                let mut b = data.clone();
                b[at..at + bytes.len()].copy_from_slice(bytes);
                b
            };
            for bad in [
                with(40, &0u64.to_le_bytes()),
                with(40, &(EPOCH_MAX + 1).to_le_bytes()),
                with(40, &u64::MAX.to_le_bytes()),
                with(64, &[2]),
                with(64, &[4]),
                with(64, &[0x83]),
                with(65, &[1]),
                with(66, &[1]),
                with(67, &[1]),
            ] {
                assert_eq!(read_header(&bad).err(), Some(VAULT_DAMAGED));
                let refused = decode_data(&id, &key, &id_key, &bad).err();
                assert_eq!(refused, Some(VAULT_DAMAGED));
            }
            // Inside the grammar: the AEAD decides.
            for other in [
                with(40, &EPOCH_MAX.to_le_bytes()),
                with(40, &1u64.to_le_bytes()),
                with(64, &[0]),
                with(64, &[1]),
                with(24, &[6]),
                with(48, &[0]),
            ] {
                assert!(read_header(&other).is_ok());
                let refused = decode_data(&id, &key, &id_key, &other).err();
                assert_eq!(refused, Some(AUTH_ERROR));
            }
            let newer = decode_data(&id, &key, &id_key, &with(0, b"GOYOVA05")).err();
            assert_eq!(newer, Some(NEWER_FORMAT));
            // Relabelled to 0.8's magic: the AEAD covers the magic.
            let legacy = if format == Format::V1 {
                DATA_MAGIC_V1
            } else {
                DATA_MAGIC_V2
            };
            let relabelled = decode_data(&id, &key, &id_key, &with(0, legacy)).err();
            assert_eq!(relabelled, Some(AUTH_ERROR));
        }
        // A 0.8 file relabelled GOYOVA04 is damaged or fails the AEAD.
        let old = encode_data(&id, &key, &Header::Legacy, Format::V2, d).unwrap();
        let mut relabelled = old.clone();
        relabelled[..8].copy_from_slice(DATA_MAGIC_V4);
        assert!(decode_data(&id, &key, &id_key, &relabelled).is_err());
        // What the grammar refuses is never written.
        for (epoch, flags) in [(0, 0), (EPOCH_MAX + 1, 0), (1, 2), (1, 4)] {
            let bad = Header::Keyed {
                key_id: [5; 16],
                state: KeyState {
                    epoch,
                    tag: [4; 16],
                },
                flags,
            };
            assert_eq!(
                encode_data(&id, &key, &bad, Format::V2, d).err(),
                Some(EPOCH_LIMIT)
            );
        }
    }
    /// V2 entries whose plaintext is exactly `size` bytes.
    pub(super) fn filling(size: usize) -> Vec<Entry> {
        let mut entries = Vec::new();
        let mut left = size - plain_size(Format::V2, &[], 0);
        // IDs and lengths take 48 bytes, a title and a secret at least 2.
        let (fixed, largest) = (48, 48 + 1 + 2 * MAX_TEXT);
        while left > 0 {
            let mut take = left.min(largest);
            if left - take > 0 && left - take < fixed + 2 {
                take = left - fixed - 2;
            }
            let text = take - fixed - 1;
            let secret = text.min(MAX_TEXT);
            let mut e = Entry::new(
                "t".into(),
                String::new(),
                "s".repeat(secret),
                "n".repeat(text - secret),
            )
            .unwrap();
            let mut id = [7; 16];
            id[..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
            e.set_ids(id, NO_ID);
            entries.push(e);
            left -= take;
        }
        assert_eq!(plain_size(Format::V2, &entries, 0), size);
        entries
    }
    /// GOYOVA03/04 add 108 bytes to the plaintext, 44 more than GOYOVA01/02:
    /// a plaintext in between fits only the 0.8 formats, and a merge refuses
    /// a result its session could not save (spec §4.3, §6).
    #[test]
    fn the_8_mib_limit_takes_the_header_overhead() {
        let (id, key) = ([1; 16], [2; 32]);
        let keyed = Header::Keyed {
            key_id: [5; 16],
            state: KeyState {
                epoch: 1,
                tag: [4; 16],
            },
            flags: 0,
        };
        fn view(entries: &[Entry]) -> DataRef<'_> {
            DataRef {
                last: 0,
                generation: 1,
                seen: 0,
                entries,
                tombstones: &[],
            }
        }
        let full = filling(MAX_FILE - LEGACY_OVERHEAD);
        let data = encode_data(&id, &key, &Header::Legacy, Format::V2, view(&full)).unwrap();
        assert_eq!(data.len(), MAX_FILE);
        assert!(decode_data(&id, &key, &key, &data).is_ok());
        assert_eq!(
            encode_data(&id, &key, &keyed, Format::V2, view(&full)).err(),
            Some("금고 용량 제한(8 MiB)을 초과했습니다.")
        );
        fn merge(entries: &[Entry], overhead: usize) -> bool {
            let remote = Contents {
                last: 0,
                generation: 0,
                seen: 0,
                entries: Vec::new(),
                tombstones: Vec::new(),
            };
            match crate::merge::merge(&[2; 32], view(entries), remote, 0, overhead) {
                Ok(_) => true,
                Err(crate::merge::MergeError::TooLarge) => false,
            }
        }
        assert!(merge(&full, LEGACY_OVERHEAD));
        assert!(!merge(&full, KEYED_OVERHEAD));
        let fits = filling(MAX_FILE - KEYED_OVERHEAD);
        let data = encode_data(&id, &key, &keyed, Format::V2, view(&fits)).unwrap();
        assert_eq!(data.len(), MAX_FILE);
        assert!(decode_data(&id, &key, &key, &data).is_ok());
        assert!(merge(&fits, KEYED_OVERHEAD));
    }
}
