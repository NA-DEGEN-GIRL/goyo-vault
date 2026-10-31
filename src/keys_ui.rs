//! The security-key build's screens, flows and texts (spec v3 §9.1-9.3):
//! the Keys screen's hardware section with the pairing status, keys on,
//! add key, pairing (`Screen::Pair`), re-seed and keys off; the removal of
//! lost keys (`Screen::LostKey`) and of retired keys (`Screen::KeyRemove`)
//! with their touch plan, and [다시 하기]; the post-removal review
//! (`Screen::Review`); the adopt with security keys and the fork options;
//! the gate dialogs (S-LOSTPICK, S-GATE-CODE) at login, for the Keys
//! screen's [받기…] and in the adopt; the TOFU banner; and Create with
//! security keys. Only that build compiles
//! this file, and the English of every Korean text in it is in
//! i18n::EN_SK, so the default exe holds none of them. Every flow runs
//! through `phased_command` (§9.2a): its secrets (the typed password, the
//! Reauth, every Touch and NewKey) live only in its frame.
use super::*;
use goyo_vault::fido::{self, MakeRequest, NewKey, Registration};
use goyo_vault::vault::{
    Exposure, GateAnswer, GateChoice, GateKind, KeyRow, KeysOverview, LossReport, RedoFlow,
    ReviewChange,
};

// Control IDs (spec §9.1 table).
pub const KEY_ON: i32 = 151;
pub const KEY_ADD: i32 = 153;
pub const KEY_REMOVE: i32 = 154;
pub const KEY_OFF: i32 = 155;
pub const SK_TOGGLE: i32 = 157;
pub const KEY_RESEED: i32 = 159;
pub const KEYSYNC_ON: i32 = 160;
pub const KEYSYNC_OFF: i32 = 161;
pub const KEY_ACCEPT: i32 = 162;
pub const KEY_REUPLOAD: i32 = 163;
pub const KEY_ROLLOUT_DONE: i32 = 164;
pub const TOFU_OK: i32 = 165;
pub const TOFU_LOCK: i32 = 166;
pub const KEY_LOST: i32 = 171;
pub const KEY_PAIR: i32 = 172;
pub const LOSS_PWCHANGE: i32 = 173;
pub const GATE_OK: i32 = 174;
pub const GATE_LATER: i32 = 175;
pub const GATE_DROP: i32 = 176;
pub const REVIEW_OK: i32 = 177;
pub const TOFU_NOPC: i32 = 178;
pub const LOSS_YES: i32 = 179;
pub const LOSS_NO: i32 = 180;
pub const LOSS_UNSURE: i32 = 181;
pub const FORK_OPT1: i32 = 182;
pub const FORK_OPT2: i32 = 183;
pub const REVIEW_LATER: i32 = 184;
pub const REMOVE_PWCHANGE: i32 = 185;
pub const GATE_TO_CODE: i32 = 186;
pub const GATE_SUPERSEDE: i32 = 187;
pub const LOST_REDO: i32 = 188;
pub const ANCHOR_FORGET: i32 = 189;
pub const SUSPEND_TOUCH: i32 = 191;
pub const KEYON_PWCHANGE: i32 = 192;
/// [뒤로] in the adopt preview of a fork (a Switch button of the guarded
/// dialog; spec §9.2 adopt step 8; free: no constant or literal 193 in
/// `main.rs`).
pub const PREVIEW_BACK: i32 = 193;
pub const KEY_LIST: i32 = 215;
pub const GATE_CODE: i32 = 216;
pub const LOSS_DATE: i32 = 217;
pub const REVIEW_LIST: i32 = 219;
/// The login screen's note (S-LOGIN-NOTE or S-LOGIN-PWONLY), rewritten
/// when the key path changes (free: no control ID 221 in `main.rs`); on
/// Restore the note in the same place (RESTORE_NOTE or RESTORE_IS_FETCHED).
pub const LOGIN_NOTE: i32 = 221;
/// Restore's [서버에서 가져온 금고로 열기] for a vault from the server
/// (spec §2.29; free: no control ID 194 in `main.rs`).
pub const RESTORE_FETCHED: i32 = 194;
/// `Screen::Pair`'s checklist (KEY_PICK, 218 in §9.1): one toggle per key,
/// from this ID on (spec §2.26).
pub const KEY_PICK_ITEM: i32 = 230;
pub const KEY_PICK_LAST: i32 = KEY_PICK_ITEM + 7;
/// `Screen::LostKey`'s second checklist, "같은 PIN을 쓰는 다른 보안 키"
/// (KEY_PICK's second section in §9.1): one toggle per key row, from this
/// ID on (free: no control ID 238-245 in `main.rs`).
pub const SHARED_ITEM: i32 = 238;
pub const SHARED_LAST: i32 = SHARED_ITEM + 7;

/// The Reauth's life a registration needs left (spec §9.2 keys on step 3):
/// three ceremonies at the 150 s cap, the write's minute and a margin.
const REG_RESERVE: Duration = Duration::from_secs(9 * 60);
/// What the write needs left of it (spec §9.2a).
const WRITE_RESERVE: Duration = Duration::from_secs(60);
/// What another ceremony needs left of it: the cap and the write's minute.
const TOUCH_RESERVE: Duration = Duration::from_secs(150 + 60);

/// S-TOUCH: the status line while Windows' dialog asks for the key. Windows
/// takes a key plugged in when its dialog opens, so a key for an NFC
/// reader must be unplugged first (real key, spec §2.28).
pub const TOUCH: &str =
    "Windows 보안 창에서 보안 키를 연결하고 터치하세요… NFC 리더에 댈 키는 먼저 USB에서 뽑으세요.";
/// S-CANCEL-KEYHINT (S45-1 #4): Windows ends a touch with a cancel when the
/// key holds no credential of the allow list, after its own "use another
/// key" prompt, so the app cannot tell that from the user's cancel.
pub const CANCEL_KEYHINT: &str = "Windows 창에 이 보안 키를 쓸 수 없다고 나왔다면, 그 키는 이 열쇠 파일에 등록되지 않았거나 이 금고에서 뺀 키이거나 FIDO 초기화된 키입니다. 등록된 다른 보안 키로 하세요.";

// The Keys screen's security-key section (spec §9.1).
pub const STATE_OFF: &str = "보안 키: 꺼짐";
pub const STATE_ON: &str = "보안 키: 켜짐 · {n}개 등록";
pub const STATE_ON_PIN: &str = "보안 키: 켜짐 · PIN 사용 · {n}개 등록";
pub const ROW: &str = "보안 키 {n} · {date} 등록";
pub const ROW_OPENED: &str = "이번에 연 키";
pub const ROW_STAMP: &str = "등록 표시 {stamp}";
pub const ROW_PAIRED: &str = "모든 키와 짝";
pub const ROW_UNPAIRED: &str = "보안 키 {list}과(와) 짝 맺기 필요";
pub const ROW_BROKEN: &str = "짝 기록 손상: 보안 키 {list}과(와) 다시 짝 맺기 필요";
pub const ROW_ORPHAN: &str = "짝 기록 없음: 빼고 다시 등록해야 함";
pub const ROW_SUSPENDED: &str = "일시 정지(짝 맺기 필요)";
pub const ROW_CLONED: &str = "복제됐을 수 있음: 모든 키 새로 잠그기나 다시 등록 권장";
pub const FULL: &str = "다른 키를 모두 대신할 수 있는 키: 보안 키 {list}";
pub const FULL_NONE: &str = "다른 키를 모두 대신할 수 있는 키: 없음 ('짝 맺기'를 하세요)";
/// S-KEYS-NOTE.
pub const KEYS_NOTE: &str = "보안 키(YubiKey 등 FIDO2)를 켜면 열쇠 파일을 비밀번호와 등록한 보안 키 둘 다로 잠급니다. OTP보다 권하는 방법이 아니라 또 하나의 선택지이며, 실험 기능입니다.\n등록한 키를 모두 잃으면 누구도(만든 사람도) 이 금고를 열 수 없고 복구 방법도 없으니 2개 이상 등록하세요. 키는 한 PC에서 함께 등록해야 서로 짝을 맺고, 하나를 잃어도 남은 키 하나로 바로 뺄 수 있습니다. 키마다 PIN을 다르게 정하고, 키 번호를 실물 키에 적어 두세요.";
/// S-KEYCODE-NOTE-SK.
pub const KEYCODE_NOTE: &str =
    "다른 PC에서 이 금고의 보안 키 추가나 설정 변경을 받을 때 이 코드를 입력합니다.";
pub const ON_BUTTON: &str = "보안 키 켜기";
pub const PWCHANGE_TOGGLE: &str = "비밀번호도 바꾸기 (권장)";
pub const ADD_BUTTON: &str = "키 추가";
pub const PAIR_BUTTON: &str = "짝 맺기…";
pub const RESEED_BUTTON: &str = "모든 키 새로 잠그기…";
pub const OFF_BUTTON: &str = "보안 키 끄기";
pub const ACCEPT_BUTTON: &str = "받기…";
pub const NEW_PASS: &str = "새 비밀번호 · 12자 이상";
pub const NEW_CONFIRM: &str = "새 비밀번호 확인";
/// S-KEYBACKUP-DUE-SK, in place of S-KEYBACKUP-DUE for a key file with
/// security keys.
pub const KEYBACKUP_DUE: &str = "이 열쇠 파일은 아직 '열쇠 백업'으로 백업하지 않았습니다. 열쇠 파일을 잃으면 보안 키와 비밀번호가 있어도 열 수 없습니다.";

// Create (spec §9.1, §9.2 "Create with keys").
pub const SK_LABEL: &str = "보안 키로도 잠그기 (실험)";
/// S-CREATE-NOTE, on the status line when the toggle turns on.
pub const CREATE_NOTE: &str = "열 때마다 등록한 보안 키를 연결하고 터치하고 키의 PIN을 입력합니다. 모두 잃으면 누구도 복구할 수 없으니 2개 이상, 지금 함께 등록하세요(함께 등록한 키끼리 짝을 맺습니다). 등록할 때 키마다 Windows 창이 세 번 열립니다. PIN이 없는 키는 그때 PIN을 정하며, 키마다 PIN을 다르게 정하세요.";
pub const SK_OFF_NOTE: &str = "보안 키 없이 비밀번호와 열쇠 파일로 여는 금고를 만듭니다.";
/// S-REGISTER: always with the key's PIN, which Windows makes the user set
/// on a key without one (real key, spec §2.28).
pub const REGISTER: &str = "보안 키 {n} 등록: Windows 창이 세 번 열립니다(등록 1번, 확인 2번). 매번 키를 터치하고 PIN을 입력하세요. PIN이 없는 키는 첫 창에서 PIN을 정합니다. NFC 리더에 댈 키는 먼저 USB에서 뽑으세요.";
/// S-PIN-DISTINCT, asked with the first S-SPARE.
pub const PIN_DISTINCT: &str = "키마다 다른 PIN을 쓰세요. 모든 키에 같은 PIN을 쓰면, 잃어버린 키와 그 PIN을 아는 사람이 다른 키를 잠깐 손에 넣는 것만으로 그 키를 복제할 수 있습니다.";
/// S-SPARE.
pub const SPARE: &str = "보안 키 {n}개를 등록했습니다. 등록한 키를 모두 잃으면 누구도(만든 사람도) 이 금고를 열 수 없고 복구 방법도 없습니다.\n예비 키를 지금 등록할까요? (강력 권장) 지금 함께 등록한 키끼리 짝을 맺어, 나중에 하나를 잃어도 남은 키 하나로 바로 뺄 수 있습니다.";
/// S-NOSPARE.
pub const NOSPARE: &str =
    "예비 키 없이 계속할까요? 나중에 '열쇠 관리 › 키 추가'로 등록할 수 있습니다.";
/// S-ONEKEY.
pub const ONEKEY: &str = "보안 키가 1개뿐입니다. 이 키를 잃거나 초기화하면 비밀번호와 열쇠 파일이 있어도 누구도 이 금고를 열 수 없습니다. '열쇠 관리'에서 예비 키를 추가하세요.";
/// S-ONEACTIVE, filled with the one key that is not suspended.
/// S-SUSPENDED-NEAR (spec §9.3, S45-1 #6), with a line break at a sentence
/// boundary (words unchanged), and its status line.
pub const SUSPENDED_NEAR: &str = "보안 키 {N}은(는) 이 열쇠 파일에서 일시 정지되어 있지만, 지금 연 보안 키 {M}과(와) 짝을 맺고 있어 이 PC에서 바로 다시 쓰게 할 수 있습니다.\n보안 키 {N}이(가) 이 PC 곁에 있다면 '열쇠 관리 › 짝 맺기'로 두 키를 터치하세요(2번 터치). 그러지 않으면 이 PC에서 쓸 수 있는 키가 보안 키 {M} 하나뿐일 수 있고, 그 키를 잃으면 다른 장소의 키를 가져올 때까지 이 PC에서 금고를 열 수 없습니다.";
pub const SUSPENDED_NEAR_SHORT: &str = "보안 키 {N}은(는) 일시 정지되어 있어, 이 PC에서 쓸 수 있는 키가 보안 키 {M} 하나뿐일 수 있습니다. 두 키가 여기 있으면 '열쇠 관리 › 짝 맺기'로 다시 쓰게 하세요.";
pub const ONEACTIVE: &str = "이 열쇠 파일을 열 수 있는 보안 키가 보안 키 {n} 하나뿐입니다(나머지는 일시 정지). 이 키를 잃으면 이 금고를 열 수 없습니다. 다른 키와 '짝 맺기'를 하세요.";
/// S-CREATED-KEYS.
pub const CREATED: &str = "새 금고를 만들었습니다. 보안 키 {n}개가 등록되었고 서로 짝을 맺었습니다. 아래 '열쇠 백업'으로 열쇠 파일 사본을 따로 두세요.";
/// The same with one key.
pub const CREATED_ONE: &str = "새 금고를 만들었습니다. 보안 키 1개가 등록되었습니다. 아래 '열쇠 백업'으로 열쇠 파일 사본을 따로 두세요.";
/// The Reauth is too old for one more registration (spec §9.2 keys on
/// step 3).
pub const NO_MORE_KEYS: &str =
    "확인한 지 오래되어 더 등록하지 않았습니다. 나머지 키는 '키 추가'로 등록하세요.";
/// S-REAUTH-AGAIN (spec §9.2a, §9.3; S45-2 #19, S45-3 #16): the Reauth is
/// too old for what is left, so a fresh one is taken in the same flow; the
/// text names what it needs. With neither, there is no dialog.
pub const REAUTH_AGAIN_OTP: &str = "확인한 지 오래되어 한 번 더 확인합니다. 새 OTP 코드를 입력하세요. 지금까지 등록하거나 터치한 키는 그대로 씁니다.";
pub const REAUTH_AGAIN_TOUCH: &str = "확인한 지 오래되어 한 번 더 확인합니다. 보안 키 {n}을(를) 다시 터치하세요. 지금까지 등록하거나 터치한 키는 그대로 씁니다.";
pub const REAUTH_AGAIN_BOTH: &str = "확인한 지 오래되어 한 번 더 확인합니다. 새 OTP 코드를 입력한 뒤 보안 키 {n}을(를) 다시 터치하세요. 지금까지 등록하거나 터치한 키는 그대로 씁니다.";

// Keys on, add key, pairing, re-seed and keys off (spec §9.2).
/// S-KEYSON-OLDFILES.
pub const KEYSON_OLDFILES: &str = "비밀번호를 그대로 두면, 보안 키를 켜기 전에 만든 열쇠 파일과 그 백업(비밀번호만으로 열림)을 가진 사람은 누구나 이 비밀번호를 오프라인으로 계속 추측할 수 있고, 맞히면 남은 것은 등록한 보안 키(와 PIN)뿐입니다. 그 사본들을 지우거나 비밀번호도 바꾸세요.";
pub const KEYS_ON_DONE: &str =
    "보안 키를 켰습니다. 보안 키 {n}개가 등록되었고 서로 짝을 맺었습니다.";
/// The same with one key, which has no other key to pair with.
pub const KEYS_ON_DONE_ONE: &str = "보안 키를 켰습니다. 보안 키 1개가 등록되었습니다.";
/// S-CODE-SK (spec §9.3), in the one-time dialog after a key change: the
/// code itself stays on the Keys screen.
pub const CODE_SK: &str = "열쇠 확인 코드: {code}. 다른 PC는 보안 키 추가나 설정 변경을 받을 때 이 코드를 입력하고, 제거를 받을 때는 잃어버린 키를 고릅니다. 모든 PC가 받아야 열쇠 변경이 끝난 것입니다.";
/// The code dialog after a change the other PCs take with this PC's code
/// (spec §2.29): the code on its own line, then why it matters.
pub const CODE_PHOTO: &str = "열쇠 확인 코드:\n{code}\n\n다른 PC가 이 변경을 받을 때 이 코드가 필요합니다. 휴대폰으로 찍어 두세요. 이 코드는 '열쇠 관리'에도 계속 보입니다.";
/// S-ADOPT-PASS-NEW.
pub const PASS_NEW: &str = "앞으로는 이번에 새로 정한 비밀번호로 엽니다.";
/// S-ADD-PAIR.
pub const ADD_PAIR: &str = "지금 꽂혀 있는 다른 보안 키가 있으면 함께 터치해 새 키와 짝을 맺으세요(키마다 한 번).\n다른 장소의 키와는 나중에 '짝 맺기'를 하면 됩니다. 지금 다른 키를 터치할까요?";
pub const PAIR_TOUCH: &str = "짝을 맺을 보안 키를 연결하고 터치하세요.";
pub const ADDED: &str = "보안 키 {n}을(를) 추가했습니다.";
/// S-BACKUP-SHORT.
pub const BACKUP_SHORT: &str = "새 열쇠 파일을 지금 백업할까요?";
/// S-CARRY (USB mode).
pub const CARRY: &str = "다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다. 다른 PC에서 '새 열쇠 파일 받기'로 이 열쇠 파일을 받고, 이 PC의 열쇠 확인 코드를 입력하세요.";
/// S-CARRY-PLAIN.
pub const CARRY_PLAIN: &str = "다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다. 다른 PC에서 '새 열쇠 파일 받기'로 이 열쇠 파일을 받으세요(코드는 필요 없습니다).";
pub const PAIR_TITLE: &str = "짝 맺기";
/// S-PAIR.
pub const PAIR_NOTE: &str = "함께 꽂아 차례로 터치하면 서로 짝을 맺습니다. 짝을 맺은 키끼리는 서로를 대신해 새 열쇠를 전할 수 있어, 하나를 잃어도 남은 키 하나로 바로 뺄 수 있습니다. 일시 정지된 키도 여기서 다시 쓰게 됩니다.";
pub const PAIR_SUBMIT: &str = "짝 맺기";
pub const PAIR_PICK: &str = "짝을 맺을 보안 키를 두 개 이상 고르세요.";
pub const PAIR_ITEM: &str = "보안 키 {n}";
pub const PAIR_NEEDED: &str = "짝 맺기 필요";
pub const PAIR_BROKEN: &str = "짝 기록 손상: 다시 짝 맺기 필요";
pub const PAIR_NEXT: &str = "짝을 맺을 보안 키 {n}을(를) 연결하고 터치하세요. ({i}/{m})";
pub const PAIRED: &str = "보안 키 {list}이(가) 서로 짝을 맺었습니다.";
/// S-RESEED.
pub const RESEED: &str = "모든 보안 키를 차례로 터치해 키별 값, 짝 기록, 키세트 비밀, 데이터 키를 모두 새로 만듭니다. 누군가 PIN을 알고 보안 키를 잠깐 가져가 터치했을 수 있을 때 쓰세요.\n등록한 키가 모두 여기 있어야 합니다. 다른 PC는 이 PC의 열쇠 확인 코드를 입력해야 받습니다. 비밀번호도 노출되었을 수 있으면 끝난 뒤 '비밀번호 변경'도 하세요. 계속할까요?";
pub const RESEED_NEXT: &str = "모든 보안 키를 하나씩 연결하고 터치하세요. ({i}/{n})";
/// S-RESEED-CONFIRM.
pub const RESEED_CONFIRM: &str = "마지막으로 보안 키 하나를 한 번 더 터치해 새 값을 확인합니다.";
/// S-TWOTOUCH.
pub const TWOTOUCH: &str = "이 Windows는 한 번의 터치로 두 값을 주지 않아 키마다 두 번 터치합니다.";
pub const RESEEDED: &str =
    "모든 보안 키를 새로 잠갔습니다. 다른 PC에서는 이 PC의 열쇠 확인 코드를 입력해야 받습니다.";
/// S-OFF.
pub const OFF: &str = "보안 키를 끄면 비밀번호와 열쇠 파일만으로 열리게 되어 더 약해집니다.\n데이터 키를 바꿉니다. 계속할까요?";
pub const KEYS_OFF_DONE: &str = "보안 키를 껐습니다. 이제 비밀번호와 열쇠 파일만으로 열립니다.";
pub const KEYS_OFF_OTHERS: &str =
    "다른 PC는 이 열쇠 파일을 USB로 받고 이 PC의 열쇠 확인 코드를 입력해야 합니다.";
/// S-RETIRE, filled with the registrations' display names.
pub const RETIRE: &str = "더 쓰지 않는 보안 키에서는 이 금고의 등록 '{display}'을(를) 지우세요.\n보안 키에서 등록 하나만 지우려면 키 제조사의 관리 도구를 쓰세요(YubiKey는 `ykman fido credentials delete`, Windows에서는 관리자 권한 명령 창에서). 이때 그 키의 PIN이 필요합니다. PIN이 없는 키는 먼저 PIN을 정해야 하는데, 그 키를 PIN 없이 쓰는 다른 고요 금고가 있으면 PIN을 정한 뒤 그 금고가 열리지 않을 수 있습니다.\n지우지 않으면 그 키와 예전 열쇠 파일 사본, 비밀번호로 예전 내용을 열 수 있습니다. 그 키를 다른 곳(다른 고요 금고, 웹사이트 패스키)에 쓰지 않을 때만 FIDO 초기화를 하세요. 초기화는 그 키의 모든 패스키와 다른 금고의 등록까지 지우며, 그 키가 다른 금고의 유일한 키라면 그 금고는 영영 열 수 없게 됩니다.";
/// A key change no staying key can authorize alone yet (spec §9.2a).
pub const PAIR_FIRST: &str =
    "모든 키와 짝을 맺은 키가 없습니다. 먼저 '짝 맺기'로 키를 모두 함께 터치하세요.";

// The removals (spec §9.1 `Screen::LostKey` and `Screen::KeyRemove`, §9.2).
pub const LOST_BUTTON: &str = "잃어버린 키 제거…";
pub const REMOVE_BUTTON: &str = "키 빼기…";
pub const LOST_TITLE: &str = "잃어버린 키 제거";
pub const REMOVE_TITLE: &str = "키 빼기";
/// S-LOST-PICK.
pub const LOST_PICK: &str = "잃어버린 키를 모두 고르세요.";
pub const REMOVE_PICK: &str = "뺄 보안 키를 고르세요.";
/// S-LOST-SHAREDPIN.
pub const SHAREDPIN: &str =
    "같은 PIN을 쓰는 다른 보안 키를 고르세요. 그 키는 복제됐을 수 있다고 표시합니다.";
/// S-LOST-DATE, and the cue of its empty field (round 1, finding 30).
pub const LOST_DATE: &str = "대략 언제 잃어버렸나요? (모르면 비워 두세요)";
pub const DATE_CUE: &str = "비워 두면 모름";
/// S-LOST-EXPOSE and its three answers, none by default.
pub const EXPOSE: &str = "PIN이나 비밀번호를 다른 사람이 알 수 있나요? (보았거나, 키와 함께 적어 두었거나, 다른 곳에도 같은 것을 썼다면 '예')";
pub const YES: &str = "예";
pub const NO: &str = "아니요";
pub const UNSURE: &str = "모름";
/// S-LOST-PWCHANGE: the box, and what it does (in the plan's lines).
pub const LOST_PWCHANGE: &str = "비밀번호도 함께 바꾸기 (권장)";
pub const LOST_PWCHANGE_NOTE: &str = "비밀번호도 바꾸면 잃어버린 키를 가진 사람이 만든 열쇠 파일은 새 비밀번호로 열리지 않습니다. 다른 PC에 이 변경 알림이 뜨지 않으면 서버가 숨기고 있을 수 있으니, 그 PC에서도 '잃어버린 키 제거'를 하세요.";
/// REMOVE_PWCHANGE's label (optional, off by default).
pub const REMOVE_PWCHANGE_LABEL: &str = "비밀번호도 바꾸기";
/// S-LOST-PWUNTICK (danger, default No).
pub const PWUNTICK: &str = "비밀번호를 바꾸지 않으면, 잃어버린 키와 그 PIN, 비밀번호를 함께 가진 사람이 만든 열쇠 파일이 다른 PC에서 열릴 수 있습니다. 그래도 비밀번호를 바꾸지 않을까요?";
pub const LOST_SUBMIT: &str = "제거";
pub const REMOVE_SUBMIT: &str = "빼기";
pub const DATE_FORMAT: &str = "날짜 형식이 맞지 않습니다. 예: 2026-10-29 (모르면 비워 두세요)";
pub const FUTURE_DATE: &str =
    "오늘 이후 날짜는 쓸 수 없습니다. 날짜를 확인하세요(모르면 비워 두세요).";
pub const EXPOSE_NEEDED: &str =
    "PIN이나 비밀번호를 다른 사람이 알 수 있는지 '예', '아니요', '모름' 중에서 고르세요.";
pub const LOST_PICK_NONE: &str = "잃어버린 키를 하나 이상 고르세요.";
pub const REMOVE_PICK_NONE: &str = "뺄 키를 하나 이상 고르세요.";
pub const NONE_STAYS: &str = "키를 모두 뺄 수는 없습니다. 하나 이상 남겨 두세요. 보안 키를 모두 없애려면 '보안 키 끄기'를 쓰세요.";
// The touch plan (spec §9.1 `Screen::LostKey` step 4).
pub const PLAN_EMPTY: &str = "키를 고르면 어느 키를 터치할지 여기에 보여 줍니다.";
pub const PLAN_TOUCH: &str = "터치할 키: 보안 키 {list} 중 하나";
pub const PLAN_TOUCH_ONE: &str = "터치할 키: 보안 키 {list}";
pub const PLAN_SUSPEND: &str = "일시 정지될 키: 보안 키 {list}";
pub const PLAN_ONLY_LOST: &str = "이 키와만 짝을 맺은 키: 보안 키 {list} (함께 뺍니다)";
/// S-ONLYPAIRED (default "함께 빼기").
pub const ONLYPAIRED: &str = "보안 키 {list}은(는) 빼는 키와만 짝을 맺었습니다. 남는 키로는 이 키에 새 열쇠를 줄 수 없고, 빼는 키가 몰래 넣은 키일 수도 있습니다. 남겨 두면 일시 정지되고 짝 기록이 남지 않아 다시 쓸 수 없습니다(빼고 다시 등록해야 합니다).\n다만 이 키가 다른 장소에서 쓰는 유일한 키일 수 있다면 남겨 두세요. 빼면 그 장소의 PC는 이 변경을 받을 때 다른 키를 가져가 짝을 맺은 뒤 '새 열쇠 파일 받기'로 합쳐야 합니다. 함께 뺄까요? (권장)";
/// S-ONLYPAIRED-RETIRE.
/// S-ONLYPAIRED's buttons: [함께 빼기] the default.
pub const ONLYPAIRED_DROP: &str = "함께 빼기";
pub const ONLYPAIRED_KEEP: &str = "남겨 두기";
pub const ONLYPAIRED_RETIRE: &str = "보안 키 {list}은(는) 빼는 키와만 짝을 맺었습니다(예: 그 키로 추가한 예비 키). 이번에 함께 터치하면 그대로 남고, 터치하지 않으면 일시 정지되며 짝 기록이 남지 않아 나중에 빼고 다시 등록해야 합니다.\n이 키가 다른 장소에서 쓰는 유일한 키일 수 있다면, 먼저 '짝 맺기'로 남는 키와 짝을 맺은 뒤에 빼세요. 함께 빼려면 목록에서 고르세요.";
/// S-SUSPEND, in parts: the keys, the full authorizers (before the touch,
/// or after it), the keys without a record left, and the question.
pub const SUSPEND: &str = "보안 키 {list}은(는) 터치할 키와 짝을 맺지 않아 새 열쇠 파일을 받을 수 없습니다. 이대로 하면 이 키는 일시 정지되고, 나중에 '짝 맺기'로 다시 쓸 수 있습니다.";
pub const SUSPEND_FULL: &str =
    "모든 키와 짝을 맺은 키(보안 키 {full})로 터치하면 일시 정지되지 않습니다.";
pub const SUSPEND_FULL_AFTER: &str =
    "다음에 모든 키와 짝을 맺은 키(보안 키 {full})로 터치하면 일시 정지되지 않습니다.";
pub const SUSPEND_ORPHANS: &str =
    "다만 보안 키 {orphans}은(는) 남는 짝 기록이 없어 다시 쓸 수 없고, 빼고 다시 등록해야 합니다.";
pub const SUSPEND_ASK: &str = "그 키가 지금 여기 있으면 '그 키도 함께 터치'를 누르세요. 함께 터치한 키는 일시 정지되지 않습니다. 계속할까요?";
/// S-SUSPEND's question when a named key is new to this PC, which cannot
/// touch it for the result (it has no seed of it).
pub const SUSPEND_ASK_NEW: &str =
    "이 PC에서 처음 보는 키는 여기서 함께 터치할 수 없습니다. 계속할까요?";
pub const CONTINUE: &str = "계속";
pub const TOUCH_TOO: &str = "그 키도 함께 터치";
pub const EXTRA_TOUCH: &str = "함께 터치할 보안 키 {list}을(를) 연결하고 터치하세요.";
/// S-MUSTTOUCH (spec §9.2 password change step 2, add key step 1, in
/// S-UNREACHABLE's wording): no key reaches every other.
pub const MUSTTOUCH: &str = "모든 키와 짝을 맺은 키가 없어, 보안 키 {list}도 연결해 함께 터치해야 합니다. 그 키가 지금 여기 없으면 '취소'를 누르고, 키가 모일 때 '짝 맺기'를 하세요.";
/// S-REPAIR-PROPOSE (spec §9.2a, S45-3 #6): a broken record between two
/// staying keys, both proposed as present; the touch first.
pub const REPAIR_PROPOSE: &str = "보안 키 {x}과(와) {y} 사이의 짝 기록이 손상되어 있습니다. 두 키가 모두 여기 있으면 보안 키 {a}을(를) 터치한 뒤 다른 키도 함께 터치해, 이번 변경에서 고치세요. 한 키가 다른 곳에 있으면 '건너뛰기'를 누르세요. 변경은 그대로 진행됩니다.";
pub const REPAIR_TOUCH: &str = "둘 다 터치";
pub const REPAIR_SKIP: &str = "건너뛰기";
/// S-REPAIR-SKIPPED: the write left that record as it was.
pub const REPAIR_SKIPPED: &str = "보안 키 {x}과(와) {y} 사이의 손상된 짝 기록은 고치지 않았습니다. 두 키를 한곳에서 '짝 맺기'하기 전까지 다른 PC가 이 변경을 받지 않을 수 있습니다.";
/// S-REMOVE.
pub const REMOVE_ASK: &str = "선택한 보안 키 {list}을(를) 뺍니다. 남는 키 하나를 터치하면 새 키세트 비밀과 데이터 키를 만들고, 이 PC에서는 바로 끝납니다.\n다른 키를 옮길 필요는 없습니다. 뺀 키와 예전 비밀번호로는 앞으로 저장하는 내용을 열 수 없습니다. 계속할까요?";
/// S-LOST-HALTED (info).
pub const LOST_HALTED: &str = "이 PC의 동기화가 멈춰 있지만, 잃어버린 키 제거는 이 PC를 바로 보호하므로 그대로 진행합니다. 다른 PC의 변경과는 나중에 합쳐집니다.";
/// S-LOST-DONE, and its first two sentences (S-DONE-ONLYHERE follows).
pub const LOST_DONE: &str = "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다.\n이 금고를 쓰는 다른 PC마다 '잃어버린 키 제거'를 하거나, 그 PC를 열 때 보안 키 {list}을(를) 모두 고르세요(서버가 이 변경을 숨겨도 그 PC에서 직접 하면 바로 보호됩니다).";
pub const LOST_DONE_SHORT: &str =
    "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다.";
/// S-LOST-DONE-USB, and its first three sentences.
pub const LOST_DONE_USB: &str = "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다. 다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다.\n다른 PC마다 둘 중 하나를 하세요. ① 이 열쇠 파일을 USB로 가져가 그 PC에서 '새 열쇠 파일 받기'로 받고, 보안 키 {list}을(를) 모두 고르세요(한 번 옮기면 끝납니다). ② 그 PC를 지금 바로 보호해야 하면 그 PC에서도 '잃어버린 키 제거'를 하세요. 그 뒤에는 두 PC가 서로의 열쇠 파일을 한 번씩 '새 열쇠 파일 받기'로 받아야 동기화가 다시 이어집니다.\n그 PC에서 쓰던 보안 키를 모두 뺐다면 그 PC는 열리지 않습니다. 여기서 새 키를 추가한 뒤, 그 키와 새 열쇠 파일을 함께 가져가 그 PC의 로그인에서 이 열쇠 파일을 고르고, 이 PC의 열쇠 확인 코드를 입력하세요.";
pub const LOST_DONE_USB_SHORT: &str = "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다. 다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다.";
/// S-DONE-ONLYHERE.
pub const DONE_ONLYHERE: &str = "새 열쇠 파일은 보안 키 {present}(으)로만 열 수 있습니다(보안 키 {suspended}은(는) 일시 정지됨).\n그 키가 없는 다른 PC는 이 열쇠 파일을 받을 수 없으니, 그 PC마다 직접 같은 키를 빼세요(잃어버린 키는 '잃어버린 키 제거', 아니면 '키 빼기'). 두 PC의 열쇠 파일은 나중에 보안 키 하나를 다른 PC로 가져가 '새 열쇠 파일 받기'로 합칩니다.";
/// S-CLONED.
pub const CLONED: &str = "같은 PIN을 쓰는 보안 키 {list}은(는) 복제됐을 수 있습니다. 모든 키가 한곳에 모일 때 '모든 키 새로 잠그기'를 하거나, 그 키를 빼고 다시 등록하세요.";
pub const REMOVED: &str = "보안 키 {list}을(를) 뺐습니다.";
/// S-CARRY-REMOVE.
pub const CARRY_REMOVE: &str = "다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다. 다른 PC에서 '새 열쇠 파일 받기'로 이 열쇠 파일을 받고, 뺀 보안 키 {list}을(를) 모두 고르세요.";
/// S-REMOVE-FAILED.
pub const REMOVE_FAILED: &str = "보안 키 {list} 제거를 저장하지 못했습니다. 아무것도 바뀌지 않았고 이 PC는 아직 보호되지 않습니다. 저장장치와 쓰기 권한을 확인한 뒤 다시 하세요.";
pub const REDO_BUTTON: &str = "다시 하기";
pub const REDO_ADOPT: &str =
    "'새 열쇠 파일 받기…'로 받으려던 열쇠 파일을 다시 고르세요. 이 PC의 키는 빼지 않습니다.";

// The post-removal review (spec §5.13, `Screen::Review`).
pub const REVIEW_TITLE: &str = "동기화로 들어온 변경 확인";
/// S-REVIEW, and its text for an unknown loss date.
pub const REVIEW: &str = "보안 키를 잃어버린 날({date}) 하루 전부터 다른 PC에서 동기화로 들어온 변경입니다. 잃어버린 키를 가진 사람이 서버를 통해 바꿔 넣었을 수 있습니다.\n계좌번호, 지갑 주소, 복구 이메일, 로그인 주소처럼 바뀌면 위험한 항목을 확인하고 필요하면 고치세요. 확인을 마치면 '확인함'을 누르세요. 그 전에는 이 PC의 금고 내용을 서버에 올리지 않습니다.";
pub const REVIEW_ALL: &str = "보안 키를 잃어버린 날을 몰라, 이 PC에 동기화로 들어온 변경 기록 전체입니다. 잃어버린 키를 가진 사람이 서버를 통해 바꿔 넣었을 수 있습니다.\n계좌번호, 지갑 주소, 복구 이메일, 로그인 주소처럼 바뀌면 위험한 항목을 확인하고 필요하면 고치세요. 확인을 마치면 '확인함'을 누르세요. 그 전에는 이 PC의 금고 내용을 서버에 올리지 않습니다.";
/// S-REVIEW-TRUNC.
pub const REVIEW_TRUNC: &str = "기록이 너무 많아 {time} 이전에 들어온 변경 일부는 이 목록에 없습니다. 백업이나 서버 기록과 비교하세요.";
/// S-REVIEW-REPLACED.
pub const REVIEW_REPLACED: &str = "같은 항목에 다른 PC의 내용이 들어왔습니다: {title}. 이 PC의 원래 내용은 '{title2}' 항목으로 옮겨졌습니다. 어느 쪽이 맞는지 확인하고, 틀린 쪽을 고치거나 지우세요.";
pub const REVIEW_DATE: &str = "잃어버린 날 (비워 두면 기록 전체)";
pub const REVIEW_HINT: &str = "항목을 두 번 누르면 열립니다. 날짜를 바꾸면 목록이 바뀝니다.";
pub const REVIEW_OK_LABEL: &str = "확인함";
pub const R_NEW: &str = "새 항목";
pub const R_EDITED: &str = "고친 항목";
pub const R_REPLACED: &str = "다른 PC의 내용으로 바뀐 항목";
pub const R_MOVED: &str = "이 PC의 원래 내용";
pub const R_DELETED: &str = "다른 PC에서 지운 항목 (내용은 백업이나 서버 기록에서 확인)";
pub const R_MISSING: &str = "이 PC에 없는 항목";
pub const REVIEW_NOT_HERE: &str =
    "이 PC에 없는 항목은 열 수 없습니다. 백업이나 서버 기록에서 확인하세요.";
pub const REVIEW_DONE: &str = "검토를 마쳤습니다.";
pub const REVIEW_LATER_TEXT: &str = "검토는 나중에 합니다. '확인함'을 누르기 전에는 이 PC의 금고 내용을 서버에 올리지 않고, 열 때마다 다시 보여 줍니다.";

// The adopt with security keys (spec §5.8, §9.2 "Adopt").
/// S-FORK: no default, no hint and no key number before the gate.
pub const FORK: &str = "열쇠 파일이 갈라졌습니다. [다른 PC 쪽 사용]은 이 PC의 열쇠 변경을 버리고 다른 PC의 열쇠 파일 내용으로 새 열쇠 파일을 씁니다(이 PC의 항목은 합칩니다).\n[둘 다 합치기]는 두 열쇠 파일을 합쳐 새로 만듭니다. 보안 키 구성이나 설정이 달라지는 쪽을 고르면, 먼저 잃어버린 키를 고르거나 다른 PC의 코드를 입력해야 합니다.";
/// S-FORK's parts, for a fork that offers one option only: the text then
/// names only the button shown.
pub const FORK_HEAD: &str = "열쇠 파일이 갈라졌습니다.";
pub const FORK_OPT1_TEXT: &str = "[다른 PC 쪽 사용]은 이 PC의 열쇠 변경을 버리고 다른 PC의 열쇠 파일 내용으로 새 열쇠 파일을 씁니다(이 PC의 항목은 합칩니다).";
pub const FORK_OPT2_TEXT: &str = "[둘 다 합치기]는 두 열쇠 파일을 합쳐 새로 만듭니다.";
pub const FORK_GATE_TEXT: &str = "보안 키 구성이나 설정이 바뀌는 경우, 먼저 잃어버린 키를 고르거나 다른 PC의 코드를 입력해야 합니다.";
pub const FORK_TAKE_OTHER: &str = "다른 PC 쪽 사용";
pub const FORK_BOTH: &str = "둘 다 합치기";
/// S-FORK-HINT (spec §5.8 "Order and display"): only in the preview,
/// after the gate, from this PC's own records.
pub const FORK_HINT: &str = "이 PC가 받은 변경은 다른 PC에서 제거한 보안 키 {n}이(가) 승인한 것입니다. '다른 PC 쪽 사용'을 권합니다.";
/// The preview's [뒤로].
pub const PREVIEW_BACK_LABEL: &str = "뒤로";
/// S-FORK-READMIT (danger, default No).
pub const FORK_READMIT: &str = "이 PC가 다른 PC에서 받은 보안 키 {list} 제거를 되돌려, 그 키를 다시 쓸 수 있게 합니다.\n그 키를 잃어버렸거나 뺀 것이 맞다면 [아니요]를 누르고 [둘 다 합치기]를 쓰세요. 잘못 고른 키 때문에 받은 위조 변경을 되돌리는 경우에만 계속하세요.";
/// S-ADOPT-PWONLY (danger, default No).
pub const ADOPT_PWONLY: &str = "받으면 보안 키가 모두 빠지고 이 금고는 비밀번호와 열쇠 파일만으로 열리게 됩니다(더 약해집니다). 다른 PC에서 보안 키를 끈 것이 맞을 때만 받으세요.";
/// S-OTHERKEY-ONLY, with [터치] and [취소].
pub const OTHERKEY_ONLY: &str = "받을 열쇠 파일은 보안 키 {list}(으)로만 열 수 있습니다. 그 키가 지금 이 PC에 있으면 연결하고 '터치'를 누르세요. 없으면 '취소'를 누르세요.";
pub const TOUCH_LABEL: &str = "터치";
/// S-TRY-SERVER-KEY (spec §5.2 second entry point).
pub const TRY_SERVER_KEY: &str = "열리지 않았습니다. 다른 PC에서 비밀번호를 바꿨다면 서버에 온 새 열쇠 파일로 열 수 있습니다. 서버의 새 열쇠 파일로 열어 볼까요?";
/// S-TRY-OTHERKEY, with [터치] and [취소] (S6-2 #4: own was not tried).
pub const TRY_OTHERKEY: &str = "보안 키 확인을 취소해서 이 PC의 열쇠 파일로는 열어 보지 않았습니다. 서버에서 받아 둔 열쇠 파일(아직 확인 전)에는 이 PC가 모르는 보안 키가 들어 있습니다. 다른 PC에서 새로 등록해 이 PC로 가져온 키가 있다면 그 키로 열어 볼까요? 그런 키를 가져온 적이 없다면 취소하고 이 PC의 보안 키로 다시 여세요.";
/// S-TRY-OTHERKEY-FAILED, in place of AUTH with S-AUTH-KEYS on that path.
pub const TRY_OTHERKEY_FAILED: &str = "서버에서 받아 둔 열쇠 파일이 이 보안 키와 입력한 비밀번호(와 OTP)로 열리지 않았습니다. 이 PC의 열쇠 파일에 등록된 보안 키로 다시 여세요. 다른 PC에서 키를 가져온 적이 없다면 서버의 열쇠 파일이 위조되었을 수 있습니다.";
/// The first status line after the server's key file was taken at login
/// (spec §7.15 step 9).
pub const ACCEPTED_AT_LOGIN: &str = "다른 PC의 열쇠 변경을 받았습니다. 열쇠 확인 코드 {code}";
/// S-NOACTIVEKEY.
pub const NOACTIVEKEY: &str = "받을 열쇠 파일에서 이 PC의 보안 키가 모두 빠졌거나 일시 정지되어 받을 수 없습니다. 키를 잃어버렸다면 이 PC에서 '잃어버린 키 제거'를 직접 하세요. 아니면 다른 키와 '짝 맺기'를 한 뒤 받으세요.";
pub const PREVIEW_SUSPEND: &str = "받으면 일시 정지될 키: 보안 키 {list}";
pub const PREVIEW_PWONLY: &str = "결과: 비밀번호만으로 열림";
pub const ADOPT_SUSPENDED: &str = "일시 정지된 키: 보안 키 {list} ('짝 맺기'로 다시 쓰게 하세요)";
/// S-ADOPT-RENUMBER and S-ADOPT-DROPPED-UV (spec §9.3).
pub const ADOPT_RENUMBER: &str =
    "번호가 겹쳐 보안 키 {a}를 보안 키 {b}(으)로 바꿨습니다. 실물 키의 표시도 고치세요.";
pub const ADOPT_DROPPED_UV: &str = "PIN 없이 등록한 보안 키 {N}은(는) PIN을 쓰는 열쇠 파일에 넣을 수 없어 빠졌습니다. 다시 등록하세요.";
/// The mark of a key new to this PC (spec §7.15a display rule).
pub const NEW_TO_PC: &str = "이 PC에서 처음 보는 키";

// The gate dialogs (spec §7.15a) and the TOFU banner (§7.17).
/// S-LOSTPICK.
pub const LOSTPICK: &str = "다른 PC에서 보안 키가 제거되었습니다. 이 PC에서 고르기 전에는 무엇이 바뀌었는지 보여 주지 않습니다.\n잃어버렸거나 뺀 키를 모두 고르세요.";
pub const LOSTPICK_NONE: &str = "잃어버렸거나 뺀 키를 하나 이상 고르세요.";
/// S-GATE-CODE, filled with the key file's epoch.
pub const GATE_CODE_TEXT: &str = "다른 PC의 '열쇠 관리'에 지금 보이는 열쇠 확인 코드를 입력하세요(E{epoch} · XXXX-XXXX-XXXX-XXXX).\n이 PC에서는 코드를 입력하기 전에 무엇이 바뀌었는지 보여 주지 않습니다.";
pub const CODE_FORMAT: &str =
    "코드 형식이 맞지 않습니다. 16자리(예: E7 · 1A2B-3C4D-5E6F-7A8B)를 입력하세요.";
pub const TO_CODE: &str = "코드로 확인…";
pub const LATER: &str = "나중에";
pub const GATE_PASSED: &str =
    "바뀐 열쇠 파일을 확인했습니다. 이제 항목을 고치고 저장할 수 있습니다.";
pub const GATE_LATER_TEXT: &str = "바뀐 열쇠 파일을 확인하기 전에는 항목을 고치거나 저장하지 않습니다. '열쇠 관리'의 [받기…]로 확인하세요.";
pub const TOFU_TITLE: &str = "이 열쇠 파일 확인";
/// S-TOFU, filled with the key file's own epoch.
pub const TOFU: &str = "이 PC는 이 열쇠 파일(수정 {e})을 아직 확인하지 않았습니다. 다른 PC의 '열쇠 관리'에 지금 보이는 열쇠 확인 코드를 입력하세요. 확인하기 전에는 항목을 고치거나 서버에 올리지 않습니다.";
/// S-TOFU-PWONLY.
pub const TOFU_PWONLY: &str = "이 열쇠 파일은 보안 키 없이 열리지만, 이 금고에는 보안 키를 쓴 흔적이 있습니다. 다른 PC에서 보안 키를 끈 것이 맞을 때만, 그 PC의 열쇠 확인 코드를 입력하세요.";
/// S-TOFU-OTHEREPOCH, after the mismatch.
pub const TOFU_OTHEREPOCH: &str = "다른 PC의 코드가 다른 수정 번호(E…)로 시작하면, 이 열쇠 파일을 복사한 뒤 그 PC에서 열쇠를 다시 바꾼 것입니다. 그 PC의 지금 열쇠 파일을 다시 복사해 와서 여세요.";
/// S-TOFU-NOPC (danger, default No).
pub const TOFU_NOPC_TEXT: &str = "확인할 다른 PC가 없으면 이 열쇠 파일이 진짜인지 확인할 방법이 없습니다.\n잃어버린 보안 키와 그 PIN, 비밀번호를 가진 사람이 서버를 장악했다면 위조된 열쇠 파일일 수 있습니다(보안 키를 뺄 때 비밀번호도 바꿨다면 위조 파일은 새 비밀번호로 열리지 않습니다). 그래도 이 열쇠 파일을 믿고 쓸까요?";
pub const TOFU_CODE_LABEL: &str = "다른 PC의 열쇠 확인 코드 (예: E7 · 1A2B-3C4D-5E6F-7A8B)";
pub const TOFU_OK_LABEL: &str = "코드 확인";
/// The trust without a code (S-TOFU-NOPC behind it, danger, default No):
/// for a key file from the server, and for any other first-seen one.
pub const TOFU_NOPC_LABEL: &str = "코드 없이 받기 (이 서버를 믿음)…";
pub const TOFU_NOPC_LOCAL: &str = "코드 없이 이 열쇠 파일 믿기…";
/// [코드 확인] with nothing typed.
pub const TOFU_CODE_EMPTY: &str =
    "다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 위 칸에 입력한 뒤 '코드 확인'을 누르세요.";
pub const TOFU_LOCK_LABEL: &str = "잠그기";
pub const TOFU_PASSED: &str = "이 열쇠 파일을 확인했습니다. 이제 항목을 고치고 저장할 수 있습니다.";
/// S-TOFU-FETCHED, after S-TOFU for a key file from the server's key view.
pub const TOFU_FETCHED: &str = "확인 전에는 이 열쇠 파일과 금고를 이 PC에 저장하지도 않습니다. 확인하면 열쇠 파일을 금고 옆에 저장합니다.";
/// The banner of such a key file this PC confirmed already (or whose save
/// a crash cut off after its code): only the save step is left.
pub const FETCHED_SAVE_TEXT: &str = "서버에서 받은 이 열쇠 파일은 이 PC가 이미 확인했습니다. 남은 일은 이 PC에 저장하는 것뿐입니다. '저장하기'를 누르세요.";
/// The banner's [확인] when only the save step is left.
pub const SAVE_STEP_LABEL: &str = "저장하기";
/// The banner's title for a key file from the server.
pub const FETCHED_TOFU_TITLE: &str = "서버에서 가져온 열쇠 파일 확인";
/// After the save step, with the key file's path.
pub const FETCHED_SAVED: &str = "열쇠 파일을 {path}에 저장했습니다. 이제 항목을 고치고 저장할 수 있고, 다음부터는 이 열쇠 파일로 엽니다. 이 PC의 서버 동기화도 지금 시작했습니다.";
/// The save step's question (spec §2.29): next to the vault by default,
/// after a lead that says how this key file came to be trusted.
pub const FETCHED_SAVE_ASK: &str = "열쇠 파일을 금고 옆에 저장합니다:\n{path}\n\n이 PC에서 금고를 열 때마다 이 열쇠 파일이 필요합니다. 다른 곳(USB 등)에 두려면 '다른 곳에 저장…'을 누르세요.";
/// The lead after the other PC's code matched.
pub const SAVE_LEAD_CODE: &str = "코드가 맞습니다. 이 열쇠 파일은 진짜입니다.";
/// The lead after S-TOFU-NOPC's yes: nothing was verified.
pub const SAVE_LEAD_NOCODE: &str =
    "코드 없이 이 서버를 믿기로 했습니다. 이 열쇠 파일이 진짜인지는 확인하지 않았습니다.";
/// The lead of a key file this PC confirmed before (a save that was cut
/// off or put off): nothing is typed this time.
pub const SAVE_LEAD_KNOWN: &str = "이 PC가 이미 확인한 열쇠 파일입니다.";
pub const SAVE_HERE: &str = "여기에 저장";
pub const SAVE_ELSEWHERE: &str = "다른 곳에 저장…";
/// The save step cancelled: nothing written, the banner stays.
pub const FETCHED_SAVE_LATER: &str =
    "아직 저장하지 않았습니다. 준비되면 '코드 확인'을 다시 누르세요(코드는 그대로 둡니다).";
/// The same after '코드 없이 받기…'.
pub const FETCHED_SAVE_LATER_NOCODE: &str = "아직 저장하지 않았습니다. 준비되면 '코드 없이 받기…'를 다시 누르거나, 다른 PC의 코드를 입력하고 '코드 확인'을 누르세요.";
/// The same when only the save step is left ('저장하기').
pub const FETCHED_SAVE_LATER_KNOWN: &str =
    "아직 저장하지 않았습니다. 준비되면 '저장하기'를 다시 누르세요.";
/// The save step's file dialog could not open (spec §2.29), by the
/// button that leads back to it.
pub const SAVE_DIALOG_FAILED: &str = "저장할 곳을 고르는 창을 열지 못했습니다. 아무것도 저장하지 않았습니다. '코드 확인'을 다시 누르고 '여기에 저장'을 고르세요.";
pub const SAVE_DIALOG_FAILED_NOCODE: &str = "저장할 곳을 고르는 창을 열지 못했습니다. 아무것도 저장하지 않았습니다. '코드 없이 받기…'를 다시 누르고 '여기에 저장'을 고르세요.";
pub const SAVE_DIALOG_FAILED_KNOWN: &str = "저장할 곳을 고르는 창을 열지 못했습니다. 아무것도 저장하지 않았습니다. '저장하기'를 다시 누르고 '여기에 저장'을 고르세요.";
/// Backups and key management while the TOFU banner stands (spec §2.29):
/// the step above comes first.
pub const TOFU_FIRST: &str = "먼저 위의 확인을 끝내세요(다른 PC의 열쇠 확인 코드 입력, 또는 '저장하기'). 그 전에는 백업하거나 열쇠를 관리하지 않습니다.";
/// Restore with the key view of a sync folder typed or picked as its key
/// file: that file is the Fetched screen's alone.
pub const RESTORE_KEY_VIEW: &str = "동기화 폴더 안의 그 파일은 서버에서 받은 열쇠 파일(확인 전)이라 여기서는 쓰지 않습니다. 그 금고 파일은 아래의 '서버에서 가져온 금고로 열기'(또는 시작 화면의 '금고 파일 열기')로 여세요.";
/// Restore with a vault goyo-sync brought from the server and no key file
/// of its own on this PC (the case "서버에서 가져온 금고" opens): the line
/// in place of RESTORE_NOTE, its button, and SUBMIT's refusal in place of
/// the key-file advice.
pub const RESTORE_IS_FETCHED: &str = "이 파일은 서버에서 가져온 금고입니다. 이 PC에 아직 열쇠 파일이 없으니 백업처럼 되살리지 말고 아래 버튼으로 여세요.";
pub const RESTORE_FETCHED_LABEL: &str = "서버에서 가져온 금고로 열기";
pub const RESTORE_FETCHED_KEY: &str =
    "이 파일은 서버에서 가져온 금고입니다. 아래의 '서버에서 가져온 금고로 열기'를 누르세요.";
/// "서버에서 가져온 금고" (`Screen::Fetched`, spec §2.29).
pub const FETCHED_TITLE: &str = "서버에서 가져온 금고";
pub const FETCHED_INTRO: &str = "goyo-sync가 서버에서 이 금고와 그 열쇠 파일을 가져왔습니다. 열쇠 파일은 아직 이 PC에 저장되지 않았고, 다른 PC의 코드로 확인하기 전에는 믿지 않습니다.\n{step}\n② 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력합니다.\n③ 열쇠 파일을 금고 옆에 {name}(으)로 저장합니다.";
/// Step ① of FETCHED_INTRO, by whether the server's key file has
/// security keys (no touch without them).
pub const FETCHED_STEP_TOUCH: &str = "① 비밀번호를 입력하고 '다음'을 누른 뒤 보안 키를 터치합니다.";
pub const FETCHED_STEP_PLAIN: &str = "① 비밀번호를 입력하고 '다음'을 누릅니다.";
pub const FETCHED_VAULT_LABEL: &str = "서버에서 가져온 금고 파일";
pub const FETCHED_SUBMIT: &str = "다음 · 보안 키 터치";
pub const FETCHED_SUBMIT_PLAIN: &str = "다음";
pub const FETCHED_OTHER_KEY: &str = "열쇠 파일이 있으면 그것으로 열기";
/// The login after the key file appeared next to the vault meanwhile.
pub const FETCHED_KEY_HERE: &str = "금고 옆에 열쇠 파일이 있습니다. 그 열쇠 파일로 여세요.";
/// The vault's sync folder has no key file from the server (any more).
pub const FETCHED_GONE: &str = "이 금고의 동기화 폴더에 서버에서 받은 열쇠 파일이 없습니다. goyo-sync에서 '이 PC로 가져오기'를 다시 하거나, 다른 PC의 열쇠 파일을 USB로 가져와 금고 옆에 두세요.";
/// The status line once the vault is open and the code is next.
pub const FETCHED_NEXT: &str =
    "② 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 오른쪽 칸에 입력하세요.";
/// The login's 찾기 picked a vault from the server with no key file here.
pub const FETCHED_PICKED: &str =
    "서버에서 가져온 금고이고, 이 PC에 열쇠 파일이 아직 없습니다. 위 순서대로 여세요.";
/// The save dialog's title.
pub const FETCHED_SAVE_TITLE: &str = "열쇠 파일을 저장할 곳을 고르세요 (동기화 폴더 밖)";
/// S-LOGIN-NOTE, its PIN line, and S-LOGIN-PWONLY (spec §9.1).
pub const LOGIN_KEYS: &str = "이 열쇠 파일은 보안 키가 필요합니다(등록 {n}개). '잠금 해제'를 누르면 Windows 보안 창이 열립니다.";
pub const LOGIN_PIN: &str = "보안 키 PIN은 Windows 창에 입력합니다.";
pub const LOGIN_PWONLY: &str = "이 열쇠 파일은 보안 키 없이 비밀번호만으로 열립니다.";
/// The forget done in gate-pending mode: the TOFU banner asks for the
/// other PC's code next (spec §5.10, §7.17).
pub const FORGOTTEN_HELD: &str = "이 금고의 기록을 무시하고, 이 열쇠 파일을 처음 보는 열쇠 파일로 확인합니다. 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 아래에 입력하세요.";
/// [이 금고의 기록 지우고 다시 확인…] (`ANCHOR_FORGET`) and S-ANCHOR-FORGET
/// (spec §5.10, danger, default 아니요).
pub const FORGET_BUTTON: &str = "이 금고의 기록 지우고 다시 확인…";
pub const FORGET: &str = "이 PC에 남은 이 금고의 열쇠 기록(수정 {old})을 지우고, 지금 고른 열쇠 파일을 처음 보는 열쇠 파일로 다시 확인합니다. 그 뒤에는 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력해야 항목을 고치거나 올릴 수 있습니다(다른 PC가 없으면 믿고 쓰기를 고를 수 있습니다).\n코드로 확인하기 전에 잠그면 이 기록은 지워지지 않고 그대로 남습니다. 이 PC에서 한 열쇠 변경 중 이 열쇠 파일에 없는 것은 사라질 수 있습니다. 다른 금고의 기록은 그대로 둡니다.\n예전 열쇠 파일이나 위조된 열쇠 파일일 수 있다면 누르지 마세요. 계속할까요?";

/// The status line of a ceremony or answer that failed (spec §8.7): its
/// Korean source, which the status line translates line by line, or for a
/// code the app does not know the code in the language shown. Windows' own
/// text never appears. A cancel of a touch with an allow list that the app
/// did not cause itself (`by_app`: the cap; a lock or close ends the flow
/// with no line of its own) adds S-CANCEL-KEYHINT.
pub fn failure(e: FidoError, allow_list: bool, by_app: bool) -> String {
    match e {
        FidoError::Other(hr) => fill(fido::OTHER, &[&format!("{:08X}", hr as u32)]),
        FidoError::Cancelled if allow_list && !by_app => {
            format!("{}\r\n{CANCEL_KEYHINT}", e.text())
        }
        e => e.text().to_owned(),
    }
}
/// The status line of a failed MakeCredential (spec §8.7): as `failure`,
/// and a code the app does not know yet gets S-KEYSTORE-FULL on its own
/// line, until §16-18 records the HRESULT of a full credential store.
pub fn make_failure(e: FidoError) -> String {
    match e {
        FidoError::Other(_) => format!("{}\r\n{}", failure(e, false, false), fido::KEYSTORE_FULL),
        e => failure(e, false, false),
    }
}

/// KEY_LIST's procedure: anything another thread sends is dropped (as for
/// the entry list), and so are paste, cut, clear and undo from this one:
/// EM_REPLACESEL would write into the read-only list.
unsafe extern "system" fn list_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() || matches!(m, 0x300..=0x304 | 0xc2 | 0xc7) {
        return 0;
    }
    unsafe { CallWindowProcW(EDIT_PROC.get().copied(), h, m, w, l) }
}
/// Keys as this PC names them (spec §7.15a): its own numbers, and a key
/// new to it by the other file's number with S-NEWKEY's mark: "3, 5 (이
/// PC에서 처음 보는 키)".
fn named_list(keys: &[(u8, bool)]) -> String {
    keys.iter()
        .map(|(n, new)| {
            if *new {
                format!("{n} ({})", tr(NEW_TO_PC))
            } else {
                n.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
/// S-ADOPT-RENUMBER for each key of this PC the union renumbered, and
/// S-ADOPT-DROPPED-UV for each key it dropped for want of a PIN (spec §9.2
/// adopt step 3, §5.8).
pub fn adopted_lines(renumbered: &[(u8, u8)], dropped_uv: &[u8]) -> Vec<String> {
    let mut lines: Vec<String> = renumbered
        .iter()
        .map(|(old, new)| fill(ADOPT_RENUMBER, &[old, new]))
        .collect();
    lines.extend(dropped_uv.iter().map(|n| fill(ADOPT_DROPPED_UV, &[n])));
    lines
}
/// Key numbers as the texts list them: "3, 4".
fn listed(numbers: &[u8]) -> String {
    numbers
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
/// A registration's day, YYYY-MM-DD, from its `<STAMP>`.
fn day(stamp: &str) -> String {
    match (stamp.get(..4), stamp.get(4..6), stamp.get(6..8)) {
        (Some(y), Some(m), Some(d)) => format!("{y}-{m}-{d}"),
        _ => String::new(),
    }
}
/// One key's row on the Keys screen (spec §9.1): number and day, the key
/// that unlocked, the registration's stamp, its pairing status and flags.
pub fn row_text(r: &KeyRow) -> String {
    let mut parts = vec![fill(ROW, &[&r.number, &day(&r.stamp)])];
    if r.opened {
        parts.push(tr(ROW_OPENED).to_owned());
    }
    parts.push(fill(ROW_STAMP, &[&r.stamp]));
    if r.orphan {
        parts.push(tr(ROW_ORPHAN).to_owned());
    } else if r.suspended {
        parts.push(tr(ROW_SUSPENDED).to_owned());
    }
    if !r.broken.is_empty() {
        parts.push(fill(ROW_BROKEN, &[&listed(&r.broken)]));
    } else if !r.suspended {
        parts.push(if r.unpaired.is_empty() {
            tr(ROW_PAIRED).to_owned()
        } else {
            fill(ROW_UNPAIRED, &[&listed(&r.unpaired)])
        });
    }
    if r.cloned {
        parts.push(tr(ROW_CLONED).to_owned());
    }
    parts.join(" · ")
}
/// The text of the list KEY_LIST: one row per key, then the full
/// authorizers and S-KEYS-NOTE.
pub fn list_text(o: &KeysOverview) -> String {
    let mut lines: Vec<String> = o.rows.iter().map(row_text).collect();
    lines.push(String::new());
    lines.push(if o.full.is_empty() {
        tr(FULL_NONE).to_owned()
    } else {
        fill(FULL, &[&listed(&o.full)])
    });
    lines.push(String::new());
    lines.push(tr(KEYS_NOTE).replace('\n', " "));
    lines.join("\r\n")
}
/// The state line of the section.
fn state_line(o: Option<&KeysOverview>) -> String {
    match o {
        None => tr(STATE_OFF).to_owned(),
        Some(o) if o.pin => fill(STATE_ON_PIN, &[&o.rows.len()]),
        Some(o) => fill(STATE_ON, &[&o.rows.len()]),
    }
}
/// The unlock's lines of a key file with security keys (spec §9.2 unlock
/// step 8, §9.3): S-KEYBACKUP-DUE-SK in place of S-KEYBACKUP-DUE, and
/// S-ONEKEY, or S-ONEACTIVE, when one key alone opens the key file.
pub fn unlock_lines(s: &Session, notices: &mut Vec<(Zeroizing<String>, isize)>) {
    // Gate-pending mode shows nothing of the changed key file before its
    // gate passed (spec §5.10, round 2 finding 3): these lines come with
    // the pass instead (see judge_login_gate).
    if s.gate_pending() {
        return;
    }
    let Some(o) = s.keys_overview() else {
        return;
    };
    for (text, _) in notices.iter_mut() {
        if text.as_str() == vault::KEYBACKUP_DUE {
            *text = line(KEYBACKUP_DUE);
        }
    }
    let active = o.active();
    if o.rows.len() == 1 {
        notices.push((line(ONEKEY), TONE_DANGER));
    } else if let [only] = active[..] {
        notices.push((Zeroizing::new(fill(ONEACTIVE, &[&only])), TONE_DANGER));
    }
    notices.extend(
        near_lines(s)
            .into_iter()
            .map(|t| (Zeroizing::new(t), TONE_DANGER)),
    );
    // S-ROLLOUT's gist at every unlock until [모든 PC 확인 완료] (spec
    // §7.18); the Keys screen's list leads with the whole text.
    match s.rollout() {
        Some(vault::Rollout::Remove(_)) => notices.push((line(ROLLOUT_REMOVE_SHORT), TONE_DANGER)),
        Some(_) => notices.push((line(ROLLOUT_SHORT), TONE_MUTED)),
        None => {}
    }
}
/// S-ROLLOUT's whole text (spec §7.18), as the Keys screen's list leads
/// with it, with this PC's key code where a PC may type it.
pub fn rollout_text(s: &Session) -> Option<String> {
    Some(match s.rollout()? {
        vault::Rollout::Remove(code) => fill(ROLLOUT_REMOVE, &[&code]),
        vault::Rollout::Code(code) => fill(ROLLOUT_CODE, &[&code]),
        vault::Rollout::Maybe(code) => fill(ROLLOUT_MAYBE, &[&code]),
        vault::Rollout::Plain => tr(ROLLOUT_PLAIN).to_owned(),
    })
}
/// The status after the server's key file was taken at login (spec §7.15
/// at login, the failed-unlock entry of §5.2), within the status box's
/// three lines: an unlock that warned (danger) keeps its lines first, then
/// what was taken; otherwise what was taken comes first and the unlock's
/// own lines follow, without its usual line.
pub(crate) fn at_login_status(unlock: &str, danger: bool, taken: &[&str]) -> Zeroizing<String> {
    let own: Vec<&str> = unlock
        .split("\r\n")
        .filter(|l| !l.is_empty() && !usual_unlock_line(l))
        .collect();
    let mut lines: Vec<&str> = Vec::with_capacity(own.len() + taken.len());
    if danger {
        lines.extend(&own);
        lines.extend(taken);
    } else {
        lines.extend(taken);
        lines.extend(&own);
    }
    joined(&lines)
}
/// The suspended keys that the key this session was unlocked with reaches
/// through a pair record this PC did not find broken (spec §5.2 step 10,
/// S45-1 #6), each with that key: one pairing here brings it back.
pub fn suspended_near(s: &Session) -> Vec<(u8, u8)> {
    let (Some(o), Some(m)) = (s.keys_overview(), s.unlocked_with()) else {
        return Vec::new();
    };
    let unreached = s.unreached(m);
    o.rows
        .iter()
        .filter(|r| r.suspended && r.number != m && !unreached.contains(&r.number))
        .map(|r| (r.number, m))
        .collect()
}
/// S-SUSPENDED-NEAR's status line for each of them (danger): at every
/// unlock and after every install or write while it holds. The status box
/// holds three lines, so it says the gist; the Keys screen's list leads
/// with the whole text (near_texts).
pub fn near_lines(s: &Session) -> Vec<String> {
    suspended_near(s)
        .into_iter()
        .map(|(n, m)| fill(SUSPENDED_NEAR_SHORT, &[&n, &m]))
        .collect()
}
/// S-SUSPENDED-NEAR's whole text for each of them, as the Keys screen's
/// list shows it.
pub fn near_texts(s: &Session) -> Vec<String> {
    suspended_near(s)
        .into_iter()
        .map(|(n, m)| fill(SUSPENDED_NEAR, &[&n, &m, &n, &m]).replace('\n', "\r\n"))
        .collect()
}

#[cfg(test)]
thread_local! {
    /// The vault screen shows the TOFU banner, set by a layout test.
    pub static TOFU_SHOWN: Cell<bool> = const { Cell::new(false) };
    /// With TOFU_SHOWN: the banner as a session in TOFU shows it, and as
    /// one whose key file came from the server's key view when this is set.
    pub static TOFU_FETCHED_SHOWN: Cell<bool> = const { Cell::new(false) };
    /// What the review screen lists, set by a layout test in place of the
    /// session's merge log.
    pub static REVIEW_SHOWN: RefCell<Option<vault::ReviewList>> = const { RefCell::new(None) };
}

/// The App's own state of these screens.
#[derive(Clone, Copy)]
pub struct Toggles {
    /// Create: lock the new vault with security keys too (default off),
    /// always with the keys' PIN (spec §2.28: no PIN toggle).
    pub create: bool,
    /// Keys, keys off: [비밀번호도 바꾸기 (권장)], on by default; the keys'
    /// PIN is always used.
    pub keyon_pw: bool,
    /// Screen::Pair, Screen::LostKey and Screen::KeyRemove: the ticked
    /// keys, by row.
    pub pick: u8,
    /// Screen::LostKey: the shared-PIN ticks by row, the exposure answer
    /// (none at first) and the password change, which 예 and 모름 tick;
    /// Screen::KeyRemove: its optional password change.
    pub shared: u8,
    pub exposure: Option<Exposure>,
    pub pwchange: bool,
    /// [다시 하기]: the loss date the reopened screen starts with.
    pub date: Option<u64>,
    /// Screen::Review: the loss date it lists from (None: unknown, the
    /// whole log), set when it opens; and an entry opened from its list,
    /// whose edit screen returns to it.
    pub review_day: Option<Option<u64>>,
    pub reviewing: bool,
}
impl Default for Toggles {
    fn default() -> Self {
        Self {
            create: false,
            keyon_pw: true,
            pick: 0,
            shared: 0,
            exposure: None,
            pwchange: false,
            date: None,
            review_day: None,
            reviewing: false,
        }
    }
}
/// What a removal screen keeps when it is rebuilt for a toggle.
const KEPT: [i32; 5] = [CURRENT_PASS, OTP, PASS, CONFIRM, LOSS_DATE];

/// The hardware section of the Keys screen and the screens of this build.
impl App {
    /// The Keys screen below the code (spec §9.1), when nothing holds key
    /// changes: the state line, the list with the pairing status, the full
    /// authorizers and S-KEYS-NOTE, the buttons, and the current password
    /// (and OTP) the flows' Reauth reads; with keys off, the toggles and
    /// the new password fields of [보안 키 켜기].
    pub(crate) fn build_hardware(
        &mut self,
        keys: Option<&KeysOverview>,
        halt: Option<(String, Option<(i32, &'static str)>)>,
    ) {
        let (small, body) = (self.font_of(|t| t.small()), self.font_of(|t| t.body()));
        self.text(0, &state_line(keys), (40, 376, 796, 22), body, TONE_TEXT, 0);
        let otp = self
            .session
            .as_ref()
            .filter(|s| s.uses_otp())
            .map(|s| s.tag());
        match keys {
            Some(o) => {
                // The key to keep at hand, always in view (spec §9.1).
                let full = if o.full.is_empty() {
                    tr(FULL_NONE).to_owned()
                } else {
                    fill(FULL, &[&listed(&o.full)])
                };
                self.text(0, &full, (40, 398, 796, 20), small, TONE_MUTED, 0);
                // A vault that syncs gets the key-file sync line under the
                // list (spec §9.1), which gives up 40 of its height.
                let sync = ks_view(self.session.as_ref()).filter(|v| v.synced);
                let short = if sync.is_some() { 40 } else { 0 };
                match &halt {
                    // A halted vault channel (spec §7.5a): its text in the
                    // list's place; the key changes stay, each with its gate
                    // question, and the removal of a lost key with none
                    // (S-LOST-HALTED).
                    Some((text, _)) => {
                        let box_ = (40, 424, 796, 104 - short);
                        self.text(0, text, box_, small, TONE_DANGER, 0);
                    }
                    None => {
                        // ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY |
                        // WS_VSCROLL: S-SUSPENDED-NEAR's whole text,
                        // S-ROLLOUT's, the rows and S-KEYS-NOTE, scrolled;
                        // nothing in it is secret.
                        let mut text = self.session.as_ref().map(near_texts).unwrap_or_default();
                        text.extend(self.session.as_ref().and_then(rollout_text));
                        text.push(list_text(o));
                        let list = self.ctrl(
                            KEY_LIST,
                            "EDIT",
                            &text.join("\r\n\r\n"),
                            52,
                            428,
                            780,
                            94 - short,
                            0x4 | 0x40 | 0x800 | 0x0020_0000,
                        );
                        self.frames.push((
                            Rect {
                                left: 40,
                                top: 422,
                                right: 836,
                                bottom: 528 - short,
                            },
                            list,
                        ));
                        unsafe {
                            SendMessageW(list, 0x30, small as usize, 0);
                            SetWindowLongPtrW(list, -21, TONE_TEXT);
                            // Only this thread reads or moves it, and nothing
                            // is pasted into it.
                            let orig = SetWindowLongPtrW(list, -4, list_proc as *const () as isize);
                            if orig == 0 {
                                std::process::abort();
                            }
                            EDIT_PROC.get_or_init(|| std::mem::transmute::<isize, Proc>(orig));
                        }
                    }
                }
                if let Some(v) = &sync {
                    let (text, buttons) = key_sync_text(v);
                    let tone = if v.waiting.is_some() || v.gone || v.no_key_ops {
                        TONE_DANGER
                    } else {
                        TONE_MUTED
                    };
                    let n = buttons.len();
                    let total: i32 = buttons
                        .iter()
                        .map(|(id, _)| sync_button_width(*id, n) + 8)
                        .sum();
                    let left = 836 - total + 8;
                    self.text(0, &text, (40, 492, left - 48, 40), small, tone, 0);
                    let mut x = left;
                    for (id, label) in buttons {
                        let variant = if id == KEY_ACCEPT {
                            theme::PRIMARY
                        } else if id == GATE_DROP || id == KEYSYNC_OFF {
                            theme::DANGER_GHOST
                        } else {
                            theme::SECONDARY
                        };
                        let bw = sync_button_width(id, n);
                        self.button(id, label, x, 494, bw, 32, variant);
                        x += bw + 8;
                    }
                }
                // Two rows of three: what adds or pairs keys, then what
                // removes them.
                let w = (796 - 2 * 8) / 3;
                for (i, (id, label, variant)) in [
                    (KEY_ADD, ADD_BUTTON, theme::SECONDARY),
                    (KEY_PAIR, PAIR_BUTTON, theme::SECONDARY),
                    (KEY_RESEED, RESEED_BUTTON, theme::SECONDARY),
                    (KEY_LOST, LOST_BUTTON, theme::SECONDARY),
                    (KEY_REMOVE, REMOVE_BUTTON, theme::SECONDARY),
                    (KEY_OFF, OFF_BUTTON, theme::DANGER_GHOST),
                ]
                .into_iter()
                .enumerate()
                {
                    let (row, col) = (i as i32 / 3, i as i32 % 3);
                    self.button(
                        id,
                        label,
                        40 + col * (w + 8),
                        536 + row * 36,
                        w,
                        30,
                        variant,
                    );
                }
                // The current password (and OTP) every flow's Reauth reads,
                // and a halt's override at the right, which reads them too;
                // else the supersede of a gated change whose PC is gone.
                let supersede = sync
                    .as_ref()
                    .and_then(|v| v.waiting)
                    .is_some_and(|w| w.supersede)
                    .then_some((GATE_SUPERSEDE, SUPERSEDE_BUTTON));
                let action = halt.and_then(|(_, action)| action).or(supersede);
                let w = match (otp.is_some(), action.is_some()) {
                    (true, true) => 184,
                    (true, false) | (false, true) => 380,
                    (false, false) => 796,
                };
                self.password_field(CURRENT_PASS, REAUTH_LABEL, 40, 608, w);
                if let Some(tag) = otp {
                    let caption = fill("새 OTP 6자리 · {tag}", &[&tag]);
                    self.field(OTP, &caption, "", 40 + w + 16, 608, 180, true);
                }
                if let Some((id, label)) = action {
                    self.button(id, label, 436, 630, 400, 40, theme::DANGER_GHOST);
                }
            }
            None => {
                self.note(KEYS_NOTE, 40, 400, 796, 84);
                let pw = self.toggles.keyon_pw;
                let toggle = if pw { theme::TOGGLE_ON } else { theme::TOGGLE };
                self.button(KEYON_PWCHANGE, PWCHANGE_TOGGLE, 40, 490, 388, 34, toggle);
                // The current password, the new one and its confirmation,
                // and the OTP code, in one row.
                let fields = 1 + 2 * usize::from(pw) + usize::from(otp.is_some());
                let w = (796 - 16 * (fields as i32 - 1)) / fields as i32;
                let mut x = 40;
                self.password_field(CURRENT_PASS, REAUTH_LABEL, x, 536, w);
                x += w + 16;
                if pw {
                    self.password_field(PASS, NEW_PASS, x, 536, w);
                    x += w + 16;
                    self.password_field(CONFIRM, NEW_CONFIRM, x, 536, w);
                    x += w + 16;
                }
                if let Some(tag) = otp {
                    let caption = fill("새 OTP 6자리 · {tag}", &[&tag]);
                    self.field(OTP, &caption, "", x, 536, w, true);
                }
                self.button(KEY_ON, ON_BUTTON, 40, 612, 300, 40, theme::PRIMARY);
            }
        }
    }
    /// `Screen::Pair` (spec §9.1 "짝 맺기"): S-PAIR, one toggle per live key
    /// with its pairing status (keys that need pairing ticked at first),
    /// the current password (and OTP) and [짝 맺기].
    pub(crate) fn build_pair(&mut self) {
        let title = self.font_of(|t| t.title());
        self.text(0, PAIR_TITLE, (AX, 80, AW - 100, 34), title, TONE_TEXT, 0);
        self.button(BACK, "‹ 뒤로", AX + AW - 84, 84, 84, 32, theme::GHOST);
        self.note(PAIR_NOTE, AX, 124, AW, 58);
        let rows = self.keys_view().keys.map(|o| o.rows).unwrap_or_default();
        let mut y = 192;
        for (i, r) in rows.iter().enumerate().take(8) {
            // The short status: the Keys screen lists the other keys.
            let status = tr(if r.suspended {
                ROW_SUSPENDED
            } else if !r.broken.is_empty() {
                PAIR_BROKEN
            } else if r.unpaired.is_empty() {
                ROW_PAIRED
            } else {
                PAIR_NEEDED
            });
            let label = format!("{} · {status}", fill(PAIR_ITEM, &[&r.number]));
            let on = self.toggles.pick >> i & 1 != 0;
            let variant = if on { theme::TOGGLE_ON } else { theme::TOGGLE };
            self.button(KEY_PICK_ITEM + i as i32, &label, AX, y, AW, 30, variant);
            y += 34;
        }
        let otp = self
            .session
            .as_ref()
            .filter(|s| s.uses_otp())
            .map(|s| s.tag());
        let w = if otp.is_some() { AW - 196 } else { AW };
        self.password_field(CURRENT_PASS, REAUTH_LABEL, AX, 474, w);
        if let Some(tag) = otp {
            let caption = fill("새 OTP 6자리 · {tag}", &[&tag]);
            self.field(OTP, &caption, "", AX + AW - 180, 474, 180, true);
        }
        self.button(SUBMIT, PAIR_SUBMIT, AX, 556, AW, 44, theme::PRIMARY);
        unsafe {
            SetFocus(self.handle(CURRENT_PASS));
        }
    }
    /// The ticks a pairing starts with: every key that is not yet paired
    /// with all the others both ways.
    pub(crate) fn pair_defaults(&mut self) {
        let rows = self.keys_view().keys.map(|o| o.rows).unwrap_or_default();
        // A suspended key the unlocking key reaches ticks that key too
        // (S-SUSPENDED-NEAR: one pairing of the two brings it back).
        let near: Vec<u8> = self
            .session
            .as_ref()
            .map(suspended_near)
            .unwrap_or_default()
            .into_iter()
            .map(|(_, m)| m)
            .collect();
        self.toggles.pick = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.suspended
                    || !r.unpaired.is_empty()
                    || !r.broken.is_empty()
                    || near.contains(&r.number)
            })
            .fold(0, |m, (i, _)| m | 1 << i);
    }
    /// Create's toggle, under the heading (spec §9.1 "Create"); the keys'
    /// PIN has no toggle of its own (spec §2.28).
    pub(crate) fn build_create_keys(&mut self) {
        let toggle = if self.toggles.create {
            theme::TOGGLE_ON
        } else {
            theme::TOGGLE
        };
        self.button(SK_TOGGLE, SK_LABEL, AX, 116, 288, 28, toggle);
    }
    /// The login screen's note in this build (spec §9.1), at `y` in the
    /// default note's place: S-LOGIN-NOTE (with the PIN line) or
    /// S-LOGIN-PWONLY for the chosen key file, else the default note; and
    /// [이 금고의 기록 지우고 다시 확인…] in its place after an anchor
    /// refusal of exactly these files. On Restore the default note, or for
    /// a vault from the server with no key file of its own here
    /// RESTORE_IS_FETCHED and [서버에서 가져온 금고로 열기] under it. False
    /// on any other screen.
    pub(crate) fn build_login_extra(&mut self, y: i32) -> bool {
        if self.screen == Screen::Restore {
            self.build_restore_extra(y);
            return true;
        }
        if self.screen != Screen::Login {
            return false;
        }
        let small = self.font_of(|t| t.small());
        // A key file not on this PC says where it comes from (spec §2.29).
        let missing = self.missing_key_note(&self.vault_path, &self.key_path);
        let tone = if missing.is_some() {
            TONE_DANGER
        } else {
            TONE_MUTED
        };
        let text = missing.unwrap_or_else(|| login_note(&self.key_path));
        self.text(LOGIN_NOTE, &text, (AX, y, AW, 54), small, tone, 0);
        self.button(
            ANCHOR_FORGET,
            FORGET_BUTTON,
            AX,
            y,
            AW,
            36,
            theme::DANGER_GHOST,
        );
        let paths = (self.vault_path.clone(), self.key_path.clone());
        let offered = self.forget_for.as_ref() == Some(&paths);
        self.show_forget(offered);
        true
    }
    /// Restore's note at `y` and the button that takes a vault from the
    /// server to its own screen (see restore_extra).
    fn build_restore_extra(&mut self, y: i32) {
        let small = self.font_of(|t| t.small());
        self.text(
            LOGIN_NOTE,
            RESTORE_NOTE,
            (AX, y, AW, 40),
            small,
            TONE_MUTED,
            0,
        );
        self.button(
            RESTORE_FETCHED,
            RESTORE_FETCHED_LABEL,
            AX,
            y + 44,
            AW,
            36,
            theme::SECONDARY,
        );
        let (backup, key) = (self.backup_path.clone(), self.key_path.clone());
        self.restore_extra(&backup, &key);
    }
    /// Restore's note and button for the paths in the fields: a vault from
    /// the server with no key file of its own here (restore_fetched) says
    /// so and offers its screen in place of the default note.
    fn restore_extra(&mut self, backup: &Path, key: &Path) {
        let fetched = restore_fetched(backup, key);
        let (text, tone) = if fetched {
            (RESTORE_IS_FETCHED, TONE_TEXT)
        } else {
            (RESTORE_NOTE, TONE_MUTED)
        };
        let h = self.handle(LOGIN_NOTE);
        unsafe {
            SetWindowLongPtrW(h, -21, tone);
            SetWindowTextW(h, wide(tr(text)).as_ptr());
            InvalidateRect(h, null(), 1);
            ShowWindow(self.handle(RESTORE_FETCHED), if fetched { 5 } else { 0 });
        }
    }
    /// [서버에서 가져온 금고로 열기] on Restore: the backup picked opens on
    /// "서버에서 가져온 금고" as the vault file, with nothing written.
    fn restore_to_fetched(&mut self) -> crypto::Result<()> {
        self.paths()?;
        let (backup, key) = (self.backup_path.clone(), self.key_path.clone());
        // No longer that case (the files changed since): the button goes.
        if !restore_fetched(&backup, &key) {
            self.restore_extra(&backup, &key);
            return Ok(());
        }
        self.vault_path = self.backup_path.clone();
        self.key_path = self.vault_path.with_extension("goyokey");
        self.from_welcome = false;
        self.show(Screen::Fetched);
        self.status = line(FETCHED_PICKED);
        self.build();
        Ok(())
    }
    /// The forget button or the note, never both.
    fn show_forget(&mut self, offered: bool) {
        unsafe {
            ShowWindow(self.handle(ANCHOR_FORGET), if offered { 5 } else { 0 });
            ShowWindow(self.handle(LOGIN_NOTE), if offered { 0 } else { 5 });
        }
    }
    /// The Keys screen's per-vault forget in gate-pending mode (spec §5.10,
    /// §9.1), under [받기…]: the password (and OTP) its Reauth checks, and
    /// [이 금고의 기록 지우고 다시 확인…] in the danger tone.
    pub(crate) fn build_forget_held(&mut self) {
        let otp = self
            .session
            .as_ref()
            .filter(|s| s.uses_otp())
            .map(|s| s.tag());
        let w = if otp.is_some() { AW - 196 } else { AW };
        self.password_field(CURRENT_PASS, REAUTH_LABEL, AX, 566, w);
        if let Some(tag) = otp {
            let caption = fill("새 OTP 6자리 · {tag}", &[&tag]);
            self.field(OTP, &caption, "", AX + AW - 180, 566, 180, true);
        }
        self.button(
            ANCHOR_FORGET,
            FORGET_BUTTON,
            AX,
            640,
            AW,
            36,
            theme::DANGER_GHOST,
        );
    }
    /// A path field changed on the login screen: the note follows the key
    /// file, and the forget is offered only for the files refused.
    /// On Restore, the note and the button for a vault from the server.
    pub(crate) fn refresh_login_extra(&mut self, vault: &Path, key: &Path) {
        if self.screen == Screen::Restore && self.handle(LOGIN_NOTE) != 0 {
            self.restore_extra(vault, key);
            return;
        }
        if self.screen != Screen::Login || self.handle(LOGIN_NOTE) == 0 {
            return;
        }
        if self
            .forget_for
            .as_ref()
            .is_some_and(|(v, k)| v != vault || k != key)
        {
            self.forget_for = None;
        }
        let offered = self.forget_for.is_some();
        let h = self.handle(LOGIN_NOTE);
        let missing = self.missing_key_note(vault, key);
        let tone = if missing.is_some() {
            TONE_DANGER
        } else {
            TONE_MUTED
        };
        let text = missing.unwrap_or_else(|| login_note(key));
        unsafe {
            SetWindowLongPtrW(h, -21, tone);
            SetWindowTextW(h, wide(&text).as_ptr());
            InvalidateRect(h, null(), 1);
        }
        self.show_forget(offered);
    }
    /// Whether the vault screen shows the TOFU banner in place of the entry
    /// detail (spec §7.17).
    /// The vault the login's (or Fetched's) 찾기 picked (spec §2.29): one
    /// goyo-sync brought from the server with no key file on this PC opens
    /// on "서버에서 가져온 금고", and one with a key file on the login. A
    /// key file in the field that is there (on a USB stick, say) of a vault
    /// this PC opened before keeps the login and is never replaced.
    pub(crate) fn route_picked_vault(&mut self) {
        if !matches!(self.screen, Screen::Login | Screen::Fetched) {
            return;
        }
        let vault = self.vault_path.clone();
        let own = vault.with_extension("goyokey");
        let usable = self.key_path.is_file() || key_candidate(&vault, &self.key_path).is_some();
        let fetched = picked_fetched(&vault, &self.key_path);
        if fetched != (self.screen == Screen::Fetched) {
            if !usable {
                self.key_path = own;
            }
            self.show(if fetched {
                Screen::Fetched
            } else {
                Screen::Login
            });
            self.status = line(if fetched { FETCHED_PICKED } else { "" });
            self.build();
        } else if fetched {
            self.rebuild_keeping(&[PASS, OTP]);
        }
    }
    /// The vault screen's backups and key management while the TOFU
    /// banner stands (spec §2.29): refused with TOFU_FIRST, and greyed.
    pub(crate) fn tofu_blocks(&self, id: i32) -> bool {
        matches!(id, BACKUP | KEYBACKUP | CHANGE) && self.tofu_banner()
    }
    pub(crate) fn tofu_banner(&self) -> bool {
        #[cfg(test)]
        if TOFU_SHOWN.with(Cell::get) {
            return self.screen == Screen::Vault;
        }
        self.screen == Screen::Vault
            && self
                .session
                .as_ref()
                .is_some_and(|s| s.tofu() || s.fetched_unsaved())
    }
    /// The TOFU banner (spec §7.17, §9.1, §2.29): S-TOFU with the key
    /// file's own epoch (and S-TOFU-PWONLY for a key file without keys),
    /// the code field with an example of the code, [확인] and [잠그기],
    /// and under them, in the danger tone, the trust without a code. It
    /// never shows a code. A key file from the server's key view names the
    /// steps left: the code, then the key file saved next to the vault.
    pub(crate) fn build_tofu(&mut self) {
        let Some(s) = self.session.as_ref() else {
            return;
        };
        let (tofu, fetched) = (s.tofu(), s.fetched_unsaved());
        // The bottom row's backups and key management wait for this step
        // (tofu_blocks): greyed, so nothing looks pressable meanwhile.
        for id in [BACKUP, KEYBACKUP, CHANGE] {
            unsafe {
                EnableWindow(self.handle(id), 0);
            }
        }
        #[cfg(test)]
        let (tofu, fetched) = if TOFU_SHOWN.with(Cell::get) {
            (true, TOFU_FETCHED_SHOWN.with(Cell::get))
        } else {
            (tofu, fetched)
        };
        let mut text = fill(TOFU, &[&s.key_state().epoch]);
        if s.keys_overview().is_none() {
            text = format!("{text}\r\n{}", tr(TOFU_PWONLY));
        }
        if fetched {
            text = if tofu {
                format!("{text}\r\n{}", tr(TOFU_FETCHED))
            } else {
                tr(FETCHED_SAVE_TEXT).to_owned()
            };
        }
        let (small, strong) = (self.font_of(|t| t.small()), self.font_of(|t| t.strong()));
        let title = if fetched {
            FETCHED_TOFU_TITLE
        } else {
            TOFU_TITLE
        };
        self.text(0, title, (CARD_X, 104, CARD_W, 26), strong, TONE_TEXT, 0);
        self.text(0, &text, (CARD_X, 136, CARD_W, 154), small, TONE_DANGER, 0);
        if tofu {
            self.field(GATE_CODE, TOFU_CODE_LABEL, "", CARD_X, 298, CARD_W, false);
        }
        let ok = if tofu { TOFU_OK_LABEL } else { SAVE_STEP_LABEL };
        self.button(TOFU_OK, ok, CARD_X, 376, 240, 40, theme::PRIMARY);
        self.button(
            TOFU_LOCK,
            TOFU_LOCK_LABEL,
            CARD_X + CARD_W - 100,
            376,
            100,
            40,
            theme::SECONDARY,
        );
        if tofu {
            let label = if fetched {
                TOFU_NOPC_LABEL
            } else {
                TOFU_NOPC_LOCAL
            };
            self.button(
                TOFU_NOPC,
                label,
                CARD_X,
                428,
                CARD_W,
                34,
                theme::DANGER_GHOST,
            );
        }
    }
    /// "서버에서 가져온 금고" (`Screen::Fetched`, spec §2.29): what happened
    /// and the three steps in plain words, the vault file (its own [찾기]),
    /// the password (and OTP), [다음 · 보안 키 터치], and the links to the
    /// login with another key file and to Restore. No key path: the key
    /// file is the server's, in the vault's sync folder.
    pub(crate) fn build_fetched(&mut self) {
        let (title, small) = (self.font_of(|t| t.title()), self.font_of(|t| t.small()));
        self.text(0, FETCHED_TITLE, (AX, 82, AW, 34), title, TONE_TEXT, 0);
        let name = self
            .vault_path
            .with_extension("goyokey")
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // No security keys in the server's key file: no touch is asked.
        let touch = vault::fetched_key_info(&self.vault_path).is_none_or(|i| i.needs_security_key);
        let (step, submit) = if touch {
            (FETCHED_STEP_TOUCH, FETCHED_SUBMIT)
        } else {
            (FETCHED_STEP_PLAIN, FETCHED_SUBMIT_PLAIN)
        };
        let intro = fill(FETCHED_INTRO, &[&tr(step), &name]);
        self.text(0, &intro, (AX, 124, AW, 112), small, TONE_TEXT, 0);
        let vault = self.vault_path.to_string_lossy().into_owned();
        self.path_field(VPATH, BROWSE_V, FETCHED_VAULT_LABEL, &vault, 244);
        let otp = self.key_otp();
        self.password_field(PASS, "비밀번호", AX, 318, if otp { AW - 196 } else { AW });
        if otp {
            let caption = match vault_tag(&self.vault_path) {
                Some(tag) => fill("OTP 6자리 · {tag}", &[&tag]),
                None => "Google OTP 6자리".into(),
            };
            self.field(OTP, &caption, "", AX + AW - 180, 318, 180, true);
        }
        self.button(SUBMIT, submit, AX, 400, AW, 46, theme::PRIMARY);
        let (_, ly, _, _) = LOGIN_LINKS;
        let mid = AX + AW / 2;
        self.button(
            OPEN,
            FETCHED_OTHER_KEY,
            mid - 236,
            ly + 14,
            228,
            30,
            theme::LINK,
        );
        self.button(
            RESTORE,
            "백업 파일로 되살리기",
            mid + 8,
            ly + 14,
            148,
            30,
            theme::LINK,
        );
        unsafe {
            SetFocus(self.handle(PASS));
        }
    }
    /// A toggle of this build's screens flipped (no flow: nothing is
    /// written). False for any other command.
    pub(crate) fn toggle(&mut self, id: i32) -> crypto::Result<bool> {
        match id {
            SK_TOGGLE => {
                self.toggles.create = !self.toggles.create;
                self.status = line(if self.toggles.create {
                    CREATE_NOTE
                } else {
                    SK_OFF_NOTE
                });
                self.rebuild_keeping(&[PASS, CONFIRM, OTP]);
            }
            KEYON_PWCHANGE => {
                self.toggles.keyon_pw = !self.toggles.keyon_pw;
                if !self.toggles.keyon_pw {
                    self.status = line(KEYSON_OLDFILES);
                }
                self.rebuild_keeping(&[CURRENT_PASS, OTP]);
            }
            KEY_PICK_ITEM..=KEY_PICK_LAST => {
                self.toggles.pick ^= 1 << (id - KEY_PICK_ITEM);
                // A key picked for removal is no other key sharing its PIN.
                self.toggles.shared &= !self.toggles.pick;
                self.rebuild_keeping(&KEPT);
            }
            SHARED_ITEM..=SHARED_LAST => {
                self.toggles.shared ^= 1 << (id - SHARED_ITEM);
                self.toggles.shared &= !self.toggles.pick;
                self.rebuild_keeping(&KEPT);
            }
            LOSS_YES | LOSS_NO | LOSS_UNSURE => {
                let answer = match id {
                    LOSS_YES => Exposure::Yes,
                    LOSS_NO => Exposure::No,
                    _ => Exposure::Unsure,
                };
                // 예 and 모름 tick the password change (it is unticked only
                // after S-LOST-PWUNTICK); 아니요 has none, and no shared PIN.
                if answer == Exposure::No {
                    (self.toggles.pwchange, self.toggles.shared) = (false, 0);
                } else if self.toggles.exposure.is_none_or(|e| e == Exposure::No) {
                    self.toggles.pwchange = true;
                }
                self.toggles.exposure = Some(answer);
                self.rebuild_keeping(&KEPT);
            }
            // Ticking needs no question; unticking runs pw_untick.
            LOSS_PWCHANGE | REMOVE_PWCHANGE => {
                self.toggles.pwchange = !self.toggles.pwchange;
                self.rebuild_keeping(&KEPT);
            }
            KEY_PAIR => {
                self.pair_defaults();
                self.show(Screen::Pair);
                self.build();
            }
            KEY_LOST | KEY_REMOVE => {
                self.toggles = Toggles::default();
                self.show(if id == KEY_LOST {
                    Screen::LostKey
                } else {
                    Screen::KeyRemove
                });
                self.build();
            }
            LOST_REDO => self.redo(),
            KEY_ROLLOUT_DONE => {
                let s = self.session.as_mut().ok_or("먼저 금고를 열어주세요.")?;
                s.rollout_done()?;
                self.status = line(ROLLOUT_DONE);
                self.status_tone = TONE_MUTED;
                self.build();
            }
            REVIEW_OK => self.review_ok()?,
            REVIEW_LATER => self.review_later(),
            BACK if self.screen == Screen::Review => self.review_later(),
            TOFU_LOCK => self.lock("수동으로 잠갔습니다.", true),
            RESTORE_FETCHED => self.restore_to_fetched()?,
            _ => return Ok(false),
        }
        Ok(true)
    }
}

impl App {
    /// What this build's screens and controls allow (see App::allows);
    /// None for the commands the default build decides.
    pub(crate) fn allows_sk(&self, id: i32) -> Option<bool> {
        match (self.screen, id) {
            (Screen::Pair, _) => Some(
                self.session.is_some()
                    && matches!(
                        id,
                        BACK | SUBMIT | CURRENT_PASS | PEEK_CURRENT | OTP | KEY_PICK_ITEM
                            ..=KEY_PICK_LAST
                    ),
            ),
            (Screen::LostKey | Screen::KeyRemove, _) => {
                let lost = self.screen == Screen::LostKey;
                Some(
                    self.session.is_some()
                        && (matches!(
                            id,
                            BACK | SUBMIT
                                | CURRENT_PASS
                                | PEEK_CURRENT
                                | OTP
                                | PASS
                                | CONFIRM
                                | PEEK_PASS
                                | PEEK_CONFIRM
                                | KEY_PICK_ITEM..=KEY_PICK_LAST
                        ) || (lost
                            && matches!(
                                id,
                                SHARED_ITEM
                                    ..=SHARED_LAST
                                        | LOSS_DATE
                                        | LOSS_YES
                                        | LOSS_NO
                                        | LOSS_UNSURE
                                        | LOSS_PWCHANGE
                            ))
                            || (!lost && id == REMOVE_PWCHANGE)),
                )
            }
            (Screen::Review, _) => Some(
                self.session.is_some()
                    && matches!(
                        id,
                        BACK | REVIEW_OK | REVIEW_LATER | REVIEW_LIST | LOSS_DATE
                    ),
            ),
            (Screen::Login, ANCHOR_FORGET) => Some(self.forget_for.is_some()),
            (Screen::Keys, ANCHOR_FORGET) => Some(
                self.session
                    .as_ref()
                    .is_some_and(|s| s.gate_pending() && !s.tofu()),
            ),
            (Screen::Create, SK_TOGGLE) => Some(true),
            (Screen::Restore, RESTORE_FETCHED) => Some(true),
            (Screen::Fetched, _) => Some(matches!(
                id,
                SUBMIT | BROWSE_V | VPATH | PASS | PEEK_PASS | OTP | OPEN | RESTORE
            )),
            (
                Screen::Keys,
                KEY_ON | KEYON_PWCHANGE | KEY_ADD | KEY_PAIR | KEY_RESEED | KEY_OFF | KEY_LOST
                | KEY_REMOVE | LOST_REDO | KEY_ACCEPT | KEY_LIST | PASS | CONFIRM | PEEK_PASS
                | PEEK_CONFIRM | KEYSYNC_ON | KEYSYNC_OFF | KEY_REUPLOAD | GATE_DROP
                | GATE_SUPERSEDE | KEY_ROLLOUT_DONE,
            ) => Some(true),
            (Screen::Vault, TOFU_OK | TOFU_NOPC | TOFU_LOCK | GATE_CODE) => {
                Some(self.tofu_banner())
            }
            (Screen::Vault, _) if self.tofu_blocks(id) => Some(false),
            _ => None,
        }
    }
}

/// Whether `phased_command` runs command `id` on `screen` here (spec
/// §9.2a): the Keys screen's key changes, SUBMIT on Pair, Create with keys,
/// and the TOFU buttons.
pub(crate) fn phased(a: &App, id: i32) -> bool {
    match a.screen {
        Screen::Keys => matches!(
            id,
            KEY_ON
                | KEY_ADD
                | KEY_RESEED
                | KEY_OFF
                | KEY_ACCEPT
                | ANCHOR_FORGET
                | KEYSYNC_ON
                | KEYSYNC_OFF
                | KEY_REUPLOAD
                | GATE_DROP
                | GATE_SUPERSEDE
        ),
        Screen::Pair | Screen::Adopt => matches!(id, 1 | SUBMIT),
        // A password change of a key file with security keys needs a touch.
        Screen::Password => {
            matches!(id, 1 | SUBMIT)
                && a.session
                    .as_ref()
                    .is_some_and(|s| s.keys_overview().is_some())
        }
        Screen::LostKey | Screen::KeyRemove => {
            matches!(id, 1 | SUBMIT)
                || (id == LOSS_PWCHANGE && a.screen == Screen::LostKey && a.toggles.pwchange)
        }
        // Enter in the banner's code field is [확인].
        Screen::Vault => {
            matches!(id, TOFU_OK | TOFU_NOPC) || (matches!(id, 1 | SUBMIT) && a.tofu_banner())
        }
        Screen::Login => id == ANCHOR_FORGET,
        Screen::Fetched => matches!(id, 1 | SUBMIT),
        _ => false,
    }
}
/// The flows of this build (see phased).
pub(crate) fn flow(h: Hwnd, id: i32) -> crypto::Result<()> {
    let screen = APP.with(|cell| cell.try_borrow().ok()?.as_ref().map(|a| a.screen));
    match (screen, id) {
        (Some(Screen::Create), _) => create_flow(h),
        (Some(Screen::Restore), _) => restore_flow(h),
        (Some(Screen::Fetched), _) => fetched_flow(h),
        (Some(Screen::OtpBackup), _) => otp_backup_flow(h),
        (Some(Screen::Pair), _) => pair_flow(h),
        (Some(Screen::Login), ANCHOR_FORGET) => forget_flow(h),
        (Some(Screen::Keys), ANCHOR_FORGET) => forget_held_flow(h),
        (Some(Screen::Password), _) => password_flow(h),
        (Some(Screen::LostKey), LOSS_PWCHANGE) => pw_untick(h),
        (Some(Screen::LostKey | Screen::KeyRemove), _) => remove_flow(h),
        (Some(Screen::Adopt), _) => adopt_from(h, Taking::File),
        (Some(Screen::Vault), 1 | SUBMIT) => tofu_flow(h, TOFU_OK),
        (Some(Screen::Vault), _) => tofu_flow(h, id),
        (_, KEY_ON) => keys_on_flow(h),
        (_, KEY_ADD) => add_key_flow(h),
        (_, KEY_RESEED) => reseed_flow(h),
        (_, KEY_OFF) => keys_off_flow(h),
        // [받기…]: the changed key file's own gate in gate-pending mode,
        // else the server's key file (spec §7.15).
        (_, KEY_ACCEPT) if gate_login() => accept_flow(h),
        (_, KEY_ACCEPT) => adopt_from(h, Taking::Server),
        (_, KEYSYNC_ON | KEY_REUPLOAD) => keysync_on_flow(h, id),
        (_, KEYSYNC_OFF) => keysync_off_flow(h),
        (_, GATE_DROP) => gate_drop_flow(h),
        (_, GATE_SUPERSEDE) => supersede_flow(h),
        _ => Err("현재 화면에서 허용되지 않는 작업입니다."),
    }
}

/// The login note of the key file at `key` (spec §9.1): S-LOGIN-NOTE with
/// its PIN line, S-LOGIN-PWONLY, or the default build's note.
fn login_note(key: &Path) -> String {
    match vault::login_keys(key) {
        Some(vault::LoginKeys::Keys { n, pin }) => {
            let mut text = fill(LOGIN_KEYS, &[&n]);
            if pin {
                text = format!("{text}\r\n{}", tr(LOGIN_PIN));
            }
            text
        }
        Some(vault::LoginKeys::PasswordOnly) => tr(LOGIN_PWONLY).to_owned(),
        None => tr(LOGIN_PLAIN_NOTE).to_owned(),
    }
}
/// A login refused by this PC's record of the vault (S-ANCHOR-FORK, -RELIST
/// or -DOWNGRADE, spec §5.10): the login screen offers the per-vault forget
/// for exactly these files.
pub(crate) fn offer_forget(e: &str) {
    if !vault::forgettable(e) {
        return;
    }
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
            && a.screen == Screen::Login
        {
            a.forget_for = Some((a.vault_path.clone(), a.key_path.clone()));
            a.show_forget(true);
        }
    });
}
/// [이 금고의 기록 지우고 다시 확인…] (spec §5.10): S-ANCHOR-FORGET (danger,
/// default 아니요) with the record's epoch, then the login of the same
/// files with this vault's lines ignored in memory, always as a bootstrap
/// (TOFU with G1, or S-TOFU-NOPC). Nothing of the record is removed before
/// the TOFU pass; a lock or a failed unlock leaves it as it was.
fn forget_flow(h: Hwnd) -> crypto::Result<()> {
    let old = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(ANCHOR_FORGET)?;
        a.paths()?;
        let paths = (a.vault_path.clone(), a.key_path.clone());
        if a.forget_for.as_ref() != Some(&paths) {
            a.forget_for = None;
            a.show_forget(false);
            return Err("현재 화면에서 허용되지 않는 작업입니다.");
        }
        Ok((a.serial, vault::recorded_epoch(&a.key_path).unwrap_or(0)))
    });
    drain_pending(h);
    let (serial, old) = old?;
    if !ask(h, &fill(FORGET, &[&old])) {
        return Ok(());
    }
    if !standing(Screen::Login, serial) {
        return Ok(());
    }
    let result = submit_flow(h, ANCHOR_FORGET);
    // Opened (as a bootstrap): the offer is spent.
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
            && a.session.is_some()
        {
            a.forget_for = None;
        }
    });
    result
}
/// [이 금고의 기록 지우고 다시 확인…] on the Keys screen in gate-pending
/// mode (spec §5.10, round 4, finding 13): S-ANCHOR-FORGET (danger,
/// default 아니요) with the record's epoch, the touch of one of the key
/// file's live, non-suspended keys and a Reauth with the password (and
/// OTP) typed there, which verifies the factors in place of the unlock;
/// then the session drops the changed key file's gate and runs as a
/// bootstrap (the TOFU banner: G1, or S-TOFU-NOPC). Nothing of the record
/// is removed before the TOFU pass.
fn forget_held_flow(h: Hwnd) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(ANCHOR_FORGET)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let keys = s.keys_overview();
        let request = match &keys {
            Some(keys) => {
                authenticator().map_err(FidoError::text)?;
                Some(s.key_request(&keys.active(), h)?)
            }
            None => None,
        };
        let old = vault::recorded_epoch(&s.key_path).unwrap_or(0);
        let typed = Typed {
            screen: a.screen,
            serial: a.serial,
            current: a.read(CURRENT_PASS)?,
            otp: a.read(OTP)?,
            otp_time: otp::now()?,
            gate: None,
            keys,
            uses_otp: s.uses_otp(),
        };
        a.flow = Some(ANCHOR_FORGET);
        Ok((typed, old, request))
    });
    drain_pending(h);
    let (t, old, request) = p1?;
    if !ask(h, &fill(FORGET, &[&old])) {
        return Ok(());
    }
    let touch = match request {
        Some(request) => match touch_step(h, t.screen, t.serial, request, TOUCH) {
            Some(touch) => Some(touch),
            None => return Ok(()),
        },
        None => None,
    };
    let Some(r) = reauth(h, &t, touch.as_ref())? else {
        return Ok(());
    };
    drop(touch);
    phase(h, t.screen, t.serial, |a| {
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        s.forget_record(r)?;
        a.show(Screen::Vault);
        a.status = line(FORGOTTEN_HELD);
        a.build();
        Ok(())
    })
    .map(|_| ())
}
/// What phase 1 of a key change took (spec §9.2a): the screen and serial
/// it ran on, the current password and OTP code typed there (wiped when
/// the flow ends), the gate the user must answer and the keys.
struct Typed {
    screen: Screen,
    serial: u64,
    current: Zeroizing<String>,
    otp: Zeroizing<String>,
    otp_time: u64,
    gate: Option<vault::Gate>,
    keys: Option<KeysOverview>,
    /// The vault asks for an OTP code: a fresh Reauth needs a new one.
    uses_otp: bool,
}
/// Phase 1 of a key change: the screen's checks, what holds key changes
/// (a local rollback is refused at once, every other gate is asked later),
/// the typed password and code, and `more`, under the same borrow.
fn take<T>(
    h: Hwnd,
    id: i32,
    more: impl FnOnce(&mut App, &Typed) -> crypto::Result<T>,
) -> crypto::Result<(Typed, T)> {
    take_with(h, id, &vault::Change::Password(Zeroizing::default()), more)
}
/// The same for `change`, whose own gate is asked (spec §7.5: the off of
/// key-file sync is not held by a pending gate, its on is).
fn take_with<T>(
    h: Hwnd,
    id: i32,
    change: &vault::Change,
    more: impl FnOnce(&mut App, &Typed) -> crypto::Result<T>,
) -> crypto::Result<(Typed, T)> {
    let taken = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(id)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let gate = s.change_gate(change)?;
        if gate == Some(vault::Gate::LocalRollback) {
            return Err(vault::Gate::LocalRollback.question());
        }
        let typed = Typed {
            screen: a.screen,
            serial: a.serial,
            current: a.read(CURRENT_PASS)?,
            otp: a.read(OTP)?,
            otp_time: otp::now()?,
            gate,
            keys: s.keys_overview(),
            uses_otp: s.uses_otp(),
        };
        let more = more(a, &typed)?;
        a.flow = Some(id);
        Ok((typed, more))
    });
    drain_pending(h);
    taken
}
/// The gate's question (spec §7.5), default No; true to go on.
fn gate_asked(h: Hwnd, t: &Typed) -> bool {
    t.gate.is_none_or(|g| ask(h, g.question()))
}
/// The flow's re-authentication (spec §5.3) with the typed password and
/// code and, for a key file with keys, the touch. A wrong password counts
/// as a failed attempt. None: the flow is void.
fn reauth(h: Hwnd, t: &Typed, touch: Option<&Touch>) -> crypto::Result<Option<vault::Reauth>> {
    reauth_as(h, t, (&t.otp, t.otp_time), touch)
}
/// The same with the OTP code `otp` (typed at that time).
fn reauth_as(
    h: Hwnd,
    t: &Typed,
    otp: (&str, u64),
    touch: Option<&Touch>,
) -> crypto::Result<Option<vault::Reauth>> {
    phase(h, t.screen, t.serial, |a| {
        let serial = a.serial;
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        match s.reauth(&t.current, Some(otp), touch) {
            Ok(mut r) => {
                r.app_serial = serial;
                a.failed = 0;
                Ok(r)
            }
            Err(e) => {
                if e == crypto::AUTH_ERROR {
                    a.failed_attempt();
                }
                Err(e)
            }
        }
    })
}
/// The flow's Reauth for its next step (spec §9.2a "The Reauth's
/// remaining life", S45-2 #19): `r` itself while it covers `need`, else a
/// fresh one in the same flow. S-REAUTH-AGAIN by what the fresh one needs
/// (a new OTP code in the guarded code dialog on an OTP vault, a touch of
/// the same key when `r` had one); with neither, it is taken from the
/// flow's snapshot with no dialog, so no Cancel can throw away what the
/// flow holds. The first Reauth (and its lock) is dropped first; every
/// NewKey and Touch the flow holds is kept. None: cancelled or void, and
/// nothing is written.
fn renewed(
    h: Hwnd,
    t: &Typed,
    r: vault::Reauth,
    need: Duration,
) -> crypto::Result<Option<vault::Reauth>> {
    if r.remaining() >= need {
        return Ok(Some(r));
    }
    let key = r.key();
    drop(r);
    let mut code: Option<(Zeroizing<String>, u64)> = None;
    let ok = DialogButton {
        id: 1,
        label: "확인",
        role: Role::Accept,
    };
    if t.uses_otp {
        let text = match key {
            Some(n) => fill(REAUTH_AGAIN_BOTH, &[&n]),
            None => tr(REAUTH_AGAIN_OTP).to_owned(),
        };
        match ask_input(h, InputKind::Code(""), &text, &[ok, CANCEL_BUTTON]) {
            InputAnswer::Code(typed) => code = Some((typed, otp::now()?)),
            _ => return Ok(None),
        }
    } else if let Some(n) = key {
        let text = fill(REAUTH_AGAIN_TOUCH, &[&n]);
        let kind = InputKind::Preview { check: None };
        if !matches!(
            ask_input(h, kind, &text, &[ok, CANCEL_BUTTON]),
            InputAnswer::Accept { .. }
        ) {
            return Ok(None);
        }
    }
    if !standing(t.screen, t.serial) {
        return Ok(None);
    }
    let touch = match key {
        Some(n) => match touch_of(h, t, &[n], TOUCH)? {
            Some(touch) => Some(touch),
            None => return Ok(None),
        },
        None => None,
    };
    let otp = match &code {
        Some((typed, at)) => (typed.as_str(), *at),
        None => (t.otp.as_str(), t.otp_time),
    };
    reauth_as(h, t, otp, touch.as_ref())
}
/// Shows `text` on the status line of a flow that still stands, before a
/// ceremony.
fn say(h: Hwnd, text: &str) {
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
        {
            a.status(text);
        }
    });
    unsafe {
        UpdateWindow(h);
    }
}
/// One touch of a key of `numbers` (spec §8.5): None ends the flow (the
/// status line says why, or a lock already did).
fn touch_of(h: Hwnd, t: &Typed, numbers: &[u8], text: &str) -> crypto::Result<Option<Touch>> {
    let request = phase(h, t.screen, t.serial, |a| {
        let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
        s.key_request(numbers, h)
    })?;
    let Some(request) = request else {
        return Ok(None);
    };
    Ok(touch_step(h, t.screen, t.serial, request, text))
}
/// The dialogs after a key change (spec §2.29): for a change the other
/// PCs of a vault that syncs take with this PC's code (`photo`), the code
/// first, in its own words, for the user to photograph; else the rest,
/// then the general sentence (one PC, or a key file carried by USB).
fn code_told(code: Option<String>, photo: bool, more: Vec<String>) -> Vec<String> {
    let mut told = Vec::new();
    match code {
        Some(code) if photo => {
            told.push(fill(CODE_PHOTO, &[&code]));
            told.extend(more);
        }
        code => {
            told.extend(more);
            told.extend(code.map(|code| fill(CODE_SK, &[&code])));
        }
    }
    told
}
/// What a key change says once written (spec §9.2): its status lines on
/// the Keys screen (one short line each, danger lines first: the status
/// box holds three lines), whether one is a danger line (S-ONEKEY), and
/// the longer lines the one-time dialog after S-BACKUP shows with S-CODE-SK
/// (the code itself stays on the Keys screen above).
#[derive(Default)]
struct Done {
    lines: Vec<String>,
    danger: bool,
    more: Vec<String>,
}
impl Done {
    fn of(lines: Vec<String>) -> Self {
        Self {
            lines,
            ..Self::default()
        }
    }
    fn more(mut self, line: String) -> Self {
        self.more.push(line);
        self
    }
}
/// The key change's write (spec §5.5) as phase 3, then the Keys screen
/// with its status lines: S-SUSPENDED-NEAR and `done`'s lines first, then
/// S-VPENDING and the notices. Some(text) when a new key file was written:
/// its backup is offered next, then `text` (S-CODE-SK and `done`'s longer
/// lines) once in a dialog (see tell_after). A replace gap locks (spec
/// §5.7).
fn write(
    h: Hwnd,
    t: &Typed,
    r: vault::Reauth,
    extra: Vec<Touch>,
    change: vault::Change,
    consent: vault::Consent,
    done: &dyn Fn(&Session) -> Done,
) -> crypto::Result<Option<String>> {
    let Some(r) = renewed(h, t, r, WRITE_RESERVE)? else {
        return Ok(None);
    };
    let override_gate = t.gate.is_some();
    // A change the other PCs take only with this PC's code (G1): an added
    // key, a re-seed, keys on or off, key-file sync on or off. A removal
    // is taken by picking the lost keys, a password change or a pairing
    // with nothing (spec §7.18, §2.29).
    let asks_code = !matches!(
        change,
        vault::Change::Password(_) | vault::Change::Pair | vault::Change::Remove { .. }
    );
    let written = phase(h, t.screen, t.serial, |a| {
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        let result = s.rekey(r, extra, change, consent, override_gate);
        let notices: Vec<(Zeroizing<String>, isize)> =
            s.take_key_notices().iter().map(key_line).collect();
        match result {
            Ok(vault::Rekeyed::GapKept) => Err(vault::GAP_CHANGED),
            Err(e) if e == vault::KEY_DAMAGED => {
                a.show(Screen::Vault);
                a.build();
                Err(e)
            }
            Err(e) => Err(e),
            Ok(rekeyed) => {
                let Done {
                    lines: mut done,
                    danger,
                    more,
                } = done(s);
                // The danger lines first: the status box holds three lines.
                let near = near_lines(s);
                let mut lines: Vec<String> = near.clone();
                lines.append(&mut done);
                if rekeyed == vault::Rekeyed::VaultPending {
                    lines.push(vault::VPENDING.to_owned());
                }
                let synced = s.key_sync_view().is_some_and(|v| v.synced);
                let told = code_told(s.key_code(), asks_code && synced, more);
                // The landed key change ends a dropped removal's [다시 하기].
                let _ = s.take_redo();
                a.sync_badge = s.badge();
                let mut parts: Vec<&str> = lines.iter().map(String::as_str).collect();
                parts.extend(notices.iter().map(|(text, _)| text.as_str()));
                a.toggles = Toggles::default();
                a.show(Screen::Keys);
                a.status = joined(&parts);
                if danger
                    || !near.is_empty()
                    || notices.iter().any(|(_, tone)| *tone == TONE_DANGER)
                {
                    a.status_tone = TONE_DANGER;
                }
                a.build();
                Ok(told.join("\r\n\r\n"))
            }
        }
    });
    match written {
        Ok(told) => Ok(told),
        Err(e) if e == vault::KEY_DAMAGED => {
            save_damaged_key(h);
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
/// After a key change's S-BACKUP: its longer lines once, in a read-only
/// dialog, while the flow still stands.
fn tell_after(h: Hwnd, text: &str) {
    if !text.is_empty() {
        tell(h, text);
    }
}
/// The flow is still on `screen` and `serial` (no lock, close or other
/// screen since phase 1).
fn standing(screen: Screen, serial: u64) -> bool {
    !quitting()
        && APP.with(|cell| {
            cell.try_borrow().is_ok_and(|b| {
                b.as_ref()
                    .is_some_and(|a| !a.closing && a.screen == screen && a.serial == serial)
            })
        })
}

/// One key's registration (spec §8.3): MakeCredential, then two
/// GetAssertions that must agree, each its own ceremony with no borrow
/// held, the main window as the dialogs' owner, always with the key's PIN
/// (spec §2.28). Err(None): the flow is
/// void (a lock, a close, another screen); Err(Some(e)): the key failed,
/// and the status line says why.
fn register(
    h: Hwnd,
    screen: Screen,
    serial: u64,
    vault_id: &[u8; 16],
    number: u8,
    exclude: Vec<Vec<u8>>,
) -> Result<NewKey, Option<FidoError>> {
    let failed_as = |e: FidoError, text: String| -> Option<FidoError> {
        APP.with(|cell| {
            let mut b = cell.try_borrow_mut().ok()?;
            let a = b.as_mut()?;
            if a.closing || a.serial != serial || a.screen != screen || quitting() {
                return None;
            }
            a.error(&text);
            Some(e)
        })
    };
    let failed = |e: FidoError| failed_as(e, failure(e, false, false));
    // A lock, close or quit since the last step: no Windows call (§8.5).
    if !standing(screen, serial) {
        return Err(None);
    }
    let registered = otp::now().map_err(|_| failed(FidoError::Other(0)))?;
    let (mut reg, make): (Registration, MakeRequest) =
        Registration::new(vault_id, number, registered, exclude, h)
            .map_err(|_| failed(FidoError::Other(0)))?;
    say(h, &fill(REGISTER, &[&number]));
    let auth = authenticator().map_err(failed)?;
    let made = ceremony(h, auth.clone(), move |auth, token| {
        auth.make_credential(&make, token)
    });
    drain_pending(h);
    if !standing(screen, serial) {
        return Err(None);
    }
    let raw = made.map_err(|e| failed_as(e, make_failure(e)))?;
    reg.made(&raw).map_err(failed)?;
    loop {
        let request = reg
            .check_request(h)
            .map_err(|_| failed(FidoError::Other(0)))?;
        let asked = request.clone();
        let raw = ceremony(h, auth.clone(), move |auth, token| {
            auth.get_assertion(&asked, token)
        });
        drain_pending(h);
        if !standing(screen, serial) {
            return Err(None);
        }
        if let Some(key) = raw
            .and_then(|raw| reg.checked(raw, &request))
            .map_err(failed)?
        {
            return Ok(key);
        }
    }
}
/// Registers keys one after the other (spec §9.2 Create steps 2-3 and 6,
/// keys on step 3): `numbers` gives each key's number, S-SPARE (with
/// S-PIN-DISTINCT the first time) asks for the next one, and
/// S-NOSPARE comes before going on with one key. A failure of the first
/// key ends the flow (None); one of a later key returns to S-SPARE with the
/// keys registered so far. `more` says whether one more registration fits
/// the Reauth's life (else the status line says so and the keys so far are
/// written). The exclude list grows with every key.
#[allow(clippy::too_many_arguments)] // The flow's identity and plan.
fn register_loop(
    h: Hwnd,
    screen: Screen,
    serial: u64,
    vault_id: &[u8; 16],
    numbers: &[u8],
    mut exclude: Vec<Vec<u8>>,
    more: &dyn Fn() -> bool,
) -> Option<Vec<NewKey>> {
    let mut keys: Vec<NewKey> = Vec::new();
    let mut asked_distinct = false;
    // A failed key keeps its number: the next try gets another stamp.
    while let Some(&number) = numbers.get(keys.len()) {
        if !keys.is_empty() {
            loop {
                if !more() {
                    say(h, NO_MORE_KEYS);
                    return standing(screen, serial).then_some(keys);
                }
                let mut text = fill(SPARE, &[&keys.len()]);
                if !asked_distinct {
                    text = format!("{}\n\n{text}", tr(PIN_DISTINCT));
                    asked_distinct = true;
                }
                let yes = ask(h, &text);
                if !standing(screen, serial) {
                    return None;
                }
                if yes {
                    if more() {
                        break;
                    }
                    continue;
                }
                let done = keys.len() > 1 || ask(h, NOSPARE);
                if !standing(screen, serial) {
                    return None;
                }
                if done {
                    return Some(keys);
                }
            }
        }
        match register(h, screen, serial, vault_id, number, exclude.clone()) {
            Ok(key) => {
                exclude.push(key.cred_id.clone());
                keys.push(key);
            }
            Err(Some(_)) if !keys.is_empty() => {}
            Err(_) => return None,
        }
    }
    standing(screen, serial).then_some(keys)
}

/// Create with security keys (spec §9.2, §5.9): phase 1 checks everything
/// that would refuse the vault before any registration (paths, password,
/// the OTP code, the anchor probe, the WebAuthn API), then the keys are
/// registered, then phase 3 writes the vault with every key paired with
/// every other. Nothing is written before that, and a lock voids it.
fn create_flow(h: Hwnd) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if !a.toggles.create {
            // Without keys, as before (spec §9.2a: no C step).
            a.flow = Some(SUBMIT);
            a.command(SUBMIT, 0)?;
            return Ok(None);
        }
        a.enter(SUBMIT)?;
        a.paths()?;
        a.check_files()?;
        let pass = a.read(PASS)?;
        if pass.as_str() != a.read(CONFIRM)?.as_str() {
            return Err("비밀번호 확인이 일치하지 않습니다.");
        }
        vault::password_policy(&pass)?;
        let otp_time = otp::now()?;
        let provision = a
            .provision
            .as_ref()
            .ok_or("새 금고 등록을 다시 시작하세요.")?;
        let otp_step = if a.create_otp {
            Some(provision.check_otp(&a.read(OTP)?, otp_time)?)
        } else {
            None
        };
        provision.check_anchor()?;
        authenticator().map_err(FidoError::text)?;
        let vault_id = provision.vault_id();
        a.flow = Some(SUBMIT);
        Ok(Some((
            a.serial,
            pass,
            otp_step,
            vault_id,
            (a.new_vault_path.clone(), a.new_key_path.clone()),
        )))
    });
    drain_pending(h);
    let Some((serial, pass, otp_step, vault_id, (vault, key))) = p1? else {
        return Ok(());
    };
    let numbers: Vec<u8> = (1..=8).collect();
    let Some(keys) = register_loop(
        h,
        Screen::Create,
        serial,
        &vault_id,
        &numbers,
        Vec::new(),
        &|| true,
    ) else {
        return Ok(());
    };
    let n = keys.len();
    unsafe {
        UpdateWindow(h);
    }
    // Phase 3 with no session yet: on Create, with the serial of phase 1.
    let result = APP.with(|cell| -> crypto::Result<()> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if !a.still(Screen::Create, serial, false)? {
            return Ok(());
        }
        let provision = a
            .provision
            .as_ref()
            .ok_or("새 금고 등록을 다시 시작하세요.")?;
        // PIN mode only (spec §2.28).
        let result = provision.finish_with_keys(&vault, &key, &pass, otp_step, true, keys);
        a.opened(Screen::Create, result, None)?;
        a.toggles = Toggles::default();
        let created = if n == 1 {
            tr(CREATED_ONE).to_owned()
        } else {
            fill(CREATED, &[&n])
        };
        let mut lines = vec![created.as_str()];
        if n == 1 {
            lines.push(ONEKEY);
            a.status_tone = TONE_DANGER;
        }
        a.status = joined(&lines);
        a.build();
        Ok(())
    });
    drain_pending(h);
    result
}

/// SUBMIT on Restore (spec §9.2 "Unlock / Restore", §9.2a; S45-2 #17): the
/// checks and the precheck of the backup and the key file as phase 1 (as
/// before, and never a failed attempt), then for a key file with security
/// keys the touch (the unlock's allow list: every live key, suspended ones
/// included), then phase 3 restores with it. A key file without keys
/// restores in phase 3 at once, as before.
fn restore_flow(h: Hwnd) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(SUBMIT)?;
        a.paths()?;
        let pass = a.read(PASS)?;
        let otp = a.read(OTP)?;
        // The server's key file in a sync folder's key view is opened only
        // by "서버에서 가져온 금고" (spec §2.29), never as a backup's key.
        if vault::is_fetched_key(&a.backup_path, &a.key_path) {
            return Err(RESTORE_KEY_VIEW);
        }
        a.check_files()?;
        let prepared = vault::prepare_restore(&a.backup_path, &a.key_path)?;
        let otp_time = otp::now()?;
        let auth_failure = prepared.auth_failure();
        let request = prepared.unlock_request(h);
        if request.is_some() {
            authenticator().map_err(FidoError::text)?;
        }
        a.working();
        a.flow = Some(SUBMIT);
        let dest = a.dest_path.clone();
        Ok((
            a.serial,
            prepared,
            pass,
            otp,
            otp_time,
            auth_failure,
            request,
            dest,
        ))
    });
    drain_pending(h);
    let (serial, prepared, pass, otp, otp_time, auth_failure, request, dest) = p1?;
    let touch = match request {
        Some(request) => match touch_step(h, Screen::Restore, serial, request, TOUCH) {
            Some(touch) => Some(touch),
            None => return Ok(()),
        },
        None => None,
    };
    unsafe {
        UpdateWindow(h);
    }
    let result = APP.with(|cell| -> crypto::Result<()> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if !a.still(Screen::Restore, serial, false)? {
            return Ok(());
        }
        let restored = match &touch {
            Some(touch) => Session::restore_with(prepared, &dest, &pass, &otp, otp_time, touch),
            None => Session::restore_from(prepared, &dest, &pass, &otp, otp_time),
        };
        a.opened(Screen::Restore, restored, auth_failure)
    });
    drain_pending(h);
    result
}
/// A vault file with the server's key file in its key view and no key
/// file of its own on this PC (spec §2.29): the key path is that key view,
/// or the vault's own `<name>.goyokey`, which is not there (nor the temp
/// file of a cut-off save).
pub(crate) fn fetched_pending(vault: &Path, key: &Path) -> bool {
    vault.is_file()
        && (vault::is_fetched_key(vault, key)
            || (key == vault.with_extension("goyokey")
                && !key.exists()
                && key_candidate(vault, key).is_none()))
        && vault::fetched_key(vault).is_some()
}
/// A vault picked on the login (or Fetched's 찾기) opens on "서버에서
/// 가져온 금고" (spec §2.29): fetched_pending for its own key file, unless
/// the key file in the field is usable and this PC opened the vault before.
pub(crate) fn picked_fetched(vault: &Path, key: &Path) -> bool {
    let usable = key.is_file() || key_candidate(vault, key).is_some();
    fetched_pending(vault, &vault.with_extension("goyokey"))
        && !(usable && vault::known_here(vault))
}
/// The backup picked on Restore is a vault goyo-sync brought from the
/// server with no key file of its own here: the case that opens "서버에서
/// 가져온 금고" (picked_fetched, or the key view in the key field), which
/// Restore points at in place of the key-file advice.
pub(crate) fn restore_fetched(backup: &Path, key: &Path) -> bool {
    (vault::is_fetched_key(backup, key) && fetched_pending(backup, key))
        || picked_fetched(backup, key)
}
/// SUBMIT on `Screen::Fetched` (spec §2.29, §7.17): the vault file is the
/// Restore's source and, in place, its destination; the key file is the
/// server's, read only from the key view. The password (and OTP), one
/// touch, then the vault screen's TOFU banner asks for the other PC's
/// code; nothing is written before it passes.
fn fetched_flow(h: Hwnd) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(SUBMIT)?;
        a.paths()?;
        let vault = a.vault_path.clone();
        let own = vault.with_extension("goyokey");
        // The key file came by USB meanwhile: the usual login opens it.
        if vault.is_file() && own.is_file() {
            a.key_path = own;
            a.show(Screen::Login);
            a.status = line(FETCHED_KEY_HERE);
            a.build();
            return Ok(None);
        }
        if vault::fetched_key(&vault).is_none() {
            return Err(FETCHED_GONE);
        }
        let pass = a.read(PASS)?;
        let otp = a.read(OTP)?;
        a.check_files()?;
        let prepared = vault::prepare_restore_fetched(&vault)?;
        let otp_time = otp::now()?;
        let auth_failure = prepared.auth_failure();
        let touch_request = prepared.unlock_request(h);
        if touch_request.is_some() {
            authenticator().map_err(FidoError::text)?;
        }
        a.working();
        a.flow = Some(SUBMIT);
        Ok(Some((
            a.serial,
            prepared,
            pass,
            otp,
            otp_time,
            auth_failure,
            touch_request,
            vault,
        )))
    });
    drain_pending(h);
    let Some((serial, prepared, pass, otp, otp_time, auth_failure, request, vault)) = p1? else {
        return Ok(());
    };
    let touch = match request {
        Some(request) => match touch_step(h, Screen::Fetched, serial, request, TOUCH) {
            Some(touch) => Some(touch),
            None => return Ok(()),
        },
        None => None,
    };
    unsafe {
        UpdateWindow(h);
    }
    let result = APP.with(|cell| -> crypto::Result<()> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if !a.still(Screen::Fetched, serial, false)? {
            return Ok(());
        }
        let restored = match &touch {
            Some(touch) => Session::restore_with(prepared, &vault, &pass, &otp, otp_time, touch),
            None => Session::restore_from(prepared, &vault, &pass, &otp, otp_time),
        };
        a.opened(Screen::Fetched, restored, auth_failure)?;
        // The next step on the status line too, above what the unlock said.
        if a.session.as_ref().is_some_and(Session::tofu) {
            let said = a.status.clone();
            let tone = unsafe { GetWindowLongPtrW(a.handle(STATUS), -21) };
            a.set_status(&joined(&[FETCHED_NEXT, said.as_str()]), tone);
        }
        Ok(())
    });
    drain_pending(h);
    result
}
/// SUBMIT on OtpBackup (spec §9.2 "OTP backup", §5.10; S45-1 #13): the
/// password typed, then for a key file with security keys a touch of one
/// of its live, non-suspended keys (no password verifier is kept), then
/// phase 3 shows the QR. A key file without keys runs the command as
/// before.
fn otp_backup_flow(h: Hwnd) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        let keys = a.session.as_ref().and_then(Session::keys_overview);
        let Some(keys) = keys.filter(|_| a.otp_setup.is_none()) else {
            // Without keys, as before (spec §9.2a: no C step).
            a.flow = Some(SUBMIT);
            a.command(SUBMIT, 0)?;
            return Ok(None);
        };
        a.enter(SUBMIT)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        if !s.uses_otp() {
            return Err("이 금고는 OTP를 쓰지 않습니다.");
        }
        let current = a.read(CURRENT_PASS)?;
        authenticator().map_err(FidoError::text)?;
        let request = s.key_request(&keys.active(), h)?;
        a.flow = Some(SUBMIT);
        Ok(Some((a.serial, current, request)))
    });
    drain_pending(h);
    let Some((serial, current, request)) = p1? else {
        return Ok(());
    };
    let Some(touch) = touch_step(h, Screen::OtpBackup, serial, request, TOUCH) else {
        return Ok(());
    };
    phase(h, Screen::OtpBackup, serial, |a| {
        let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
        match s.otp_setup_with(&current, &touch) {
            Ok(setup) => {
                a.failed = 0;
                a.otp_setup = Some(setup);
                a.status = line("예비 기기에 등록한 뒤 '닫기'를 누르세요.");
                a.build();
                Ok(())
            }
            Err(e) if e == crypto::AUTH_ERROR => {
                a.failed_attempt();
                Err("비밀번호가 맞지 않습니다.")
            }
            Err(e) => Err(e),
        }
    })
    .map(|_| ())
}

/// [보안 키 켜기] (spec §9.2 "Keys on"): the new password checked before any
/// question; S-ROTATE (with S-KEYSON-OLDFILES when it is kept) and the
/// gate; the Reauth (a wrong password fails before any registration); the
/// registrations with S-SPARE while the Reauth's life covers one more; the
/// write, every key paired with every other; S-BACKUP.
fn keys_on_flow(h: Hwnd) -> crypto::Result<()> {
    let (t, (new_password, vault_id, numbers, exclude, synced)) = take(h, KEY_ON, |a, t| {
        if t.keys.is_some() {
            return Err(vault::NOT_PLANNED);
        }
        let new_password = if a.toggles.keyon_pw {
            let pass = a.read(PASS)?;
            if pass.as_str() != a.read(CONFIRM)?.as_str() {
                return Err("비밀번호 확인이 일치하지 않습니다.");
            }
            vault::password_policy(&pass)?;
            if pass.as_str() == t.current.as_str() {
                return Err(vault::SAMEPASS);
            }
            Some(pass)
        } else {
            None
        };
        authenticator().map_err(FidoError::text)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let (numbers, exclude) = s.add_plan(8)?;
        Ok((
            new_password,
            s.vault_id(),
            numbers,
            exclude,
            s.badge().is_some(),
        ))
    })?;
    let mut question = tr(if synced {
        ROTATE_QUESTION_SYNCED
    } else {
        ROTATE_QUESTION
    })
    .to_owned();
    if new_password.is_none() {
        question = format!("{question}\n\n{}", tr(KEYSON_OLDFILES));
    }
    if !ask(h, &question) || !gate_asked(h, &t) {
        return Ok(());
    }
    let Some(r) = reauth(h, &t, None)? else {
        return Ok(());
    };
    let more = || r.remaining() >= REG_RESERVE;
    let Some(keys) = register_loop(h, t.screen, t.serial, &vault_id, &numbers, exclude, &more)
    else {
        return Ok(());
    };
    let n = keys.len();
    let changed = new_password.is_some();
    // PIN mode only (spec §2.28).
    let change = vault::Change::KeysOn {
        pin: true,
        keys,
        new_password,
    };
    let done = move |_: &Session| {
        // S-ONEKEY first and red, as after Create; the done line and the
        // password in force in one line.
        let mut done = keys_on_done(n, changed);
        if !changed {
            done = done.more(tr(KEYSON_OLDFILES).to_owned());
        }
        done
    };
    if let Some(told) = write(
        h,
        &t,
        r,
        Vec::new(),
        change,
        vault::Consent::default(),
        &done,
    )? {
        backup_after(h, BACKUP_QUESTION);
        tell_after(h, &told);
    }
    Ok(())
}
/// Keys on's status lines (spec §9.2 keys on step 5): S-ONEKEY first in
/// the danger tone with one key, then the done line with the password in
/// force.
fn keys_on_done(n: usize, changed: bool) -> Done {
    let mut done = if n == 1 {
        tr(KEYS_ON_DONE_ONE).to_owned()
    } else {
        fill(KEYS_ON_DONE, &[&n])
    };
    if changed {
        done = format!("{done} {}", tr(PASS_NEW));
    }
    let one = n == 1;
    let mut lines = Vec::new();
    if one {
        lines.push(tr(ONEKEY).to_owned());
    }
    lines.push(done);
    Done {
        lines,
        danger: one,
        more: Vec::new(),
    }
}

/// After the Reauth (spec §9.2a, S45-2 #6): its key's own records reach
/// every other live key, or the flow stops with S-UNREACHABLE before any
/// further ceremony or the write. `extra`: keys the flow touches as well.
fn reach_holds(t: &Typed, r: &vault::Reauth, extra: &[u8]) -> crypto::Result<()> {
    let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
    let missing: Vec<u8> = keys
        .rows
        .iter()
        .map(|k| k.number)
        .filter(|n| !r.reach().contains(n) && !extra.contains(n))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(vault::refuse(vault::UNREACHABLE, vec![listed(&missing)]))
    }
}

/// [키 추가] (spec §9.2 "Add key"): a touch of a key that reaches every
/// other, the Reauth and its reach, the registration, S-ADD-PAIR with one
/// touch per key the user offers, the write (the new key paired with
/// every key touched), S-BACKUP-SHORT.
fn add_key_flow(h: Hwnd) -> crypto::Result<()> {
    let (t, (vault_id, number, exclude, synced, reach)) = take(h, KEY_ADD, |a, _| {
        authenticator().map_err(FidoError::text)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let o = s.keys_overview().ok_or(vault::NOT_PLANNED)?;
        if o.rows.len() >= 8 {
            return Err("보안 키는 8개까지 등록할 수 있습니다.");
        }
        let (numbers, exclude) = s.add_plan(1)?;
        Ok((
            s.vault_id(),
            numbers[0],
            exclude,
            s.badge().is_some(),
            reach_of(s, &o),
        ))
    })?;
    if !gate_asked(h, &t) {
        return Ok(());
    }
    // The touch plan of a write that removes nothing: a key that reaches
    // every other, or one with the keys it does not reach touched as well
    // (S-MUSTTOUCH, before any ceremony); the Reauth, its reach and those
    // touches come before the registration, so no resident credential is
    // used up for a write that cannot land.
    let keys = t.keys.clone().ok_or(vault::NOT_PLANNED)?;
    let unreached = unreached_in(&reach);
    let Some(Touched {
        r,
        mut extra,
        present,
        unrepaired,
        ..
    }) = touch_by_plan(h, &t, &keys, &unreached, &[], false)?
    else {
        return Ok(());
    };
    let Some(mut r) = renewed(h, &t, r, REG_RESERVE)? else {
        return Ok(());
    };
    let key = match register(h, t.screen, t.serial, &vault_id, number, exclude) {
        Ok(key) => key,
        Err(_) => return Ok(()),
    };
    // S-ADD-PAIR: the other keys at hand, one touch each.
    let mut touched: Vec<u8> = present;
    loop {
        let left: Vec<u8> = t
            .keys
            .as_ref()
            .map(|o| o.rows.iter().map(|k| k.number))
            .into_iter()
            .flatten()
            .filter(|n| !touched.contains(n))
            .collect();
        if left.is_empty() || !ask(h, ADD_PAIR) {
            break;
        }
        r = match renewed(h, &t, r, TOUCH_RESERVE)? {
            Some(r) => r,
            None => return Ok(()),
        };
        // An optional touch that fails or is cancelled keeps the new key's
        // registration: the status line says why, and S-ADD-PAIR comes
        // again (No writes with the touches so far). Only a lock, close or
        // quit voids the flow.
        let Some(other) = touch_of(h, &t, &left, PAIR_TOUCH)? else {
            if !standing(t.screen, t.serial) {
                return Ok(());
            }
            continue;
        };
        let checked = phase(h, t.screen, t.serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            Ok(s.check_touch(&r, &other))
        })?;
        match checked {
            None => return Ok(()),
            Some(Ok(n)) => {
                touched.push(n);
                extra.push(other);
            }
            Some(Err(e)) => fail(&[e]),
        }
    }
    let done = move |s: &Session| {
        let mut done = Done::of(vec![fill(ADDED, &[&number])]);
        if synced && s.keys_overview().is_some() {
            done = done.more(tr(CARRY).to_owned());
        }
        done.more.extend(unrepaired_line(unrepaired));
        done
    };
    let change = vault::Change::AddKey(key);
    if let Some(told) = write(h, &t, r, extra, change, vault::Consent::default(), &done)? {
        backup_after(h, BACKUP_SHORT);
        tell_after(h, &told);
    }
    Ok(())
}

/// SUBMIT on `Screen::Pair` (spec §9.2 "Pair"): at least two keys; the
/// first touch is a picked key whose records reach every key not picked,
/// then the Reauth, then one touch per other picked key, each checked
/// against its own slot and S-wrap (or own pair record), then the write.
fn pair_flow(h: Hwnd) -> crypto::Result<()> {
    let (t, (picked, synced)) = take(h, SUBMIT, |a, t| {
        let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        let picked: Vec<u8> = keys
            .rows
            .iter()
            .enumerate()
            .filter(|(i, _)| a.toggles.pick >> i & 1 != 0)
            .map(|(_, r)| r.number)
            .collect();
        if picked.len() < 2 {
            return Err(PAIR_PICK);
        }
        authenticator().map_err(FidoError::text)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        Ok((picked, s.badge().is_some()))
    })?;
    // The first key: picked, live and not suspended, and every key it does
    // not reach is picked too.
    let first: Vec<u8> = APP.with(|cell| {
        cell.try_borrow()
            .ok()
            .and_then(|b| {
                let s = b.as_ref()?.session.as_ref()?;
                let keys = t.keys.as_ref()?;
                Some(
                    picked
                        .iter()
                        .copied()
                        .filter(|n| keys.active().contains(n))
                        .filter(|n| s.unreached(*n).iter().all(|u| picked.contains(u)))
                        .collect(),
                )
            })
            .unwrap_or_default()
    });
    if first.is_empty() {
        return Err(PAIR_FIRST);
    }
    if !gate_asked(h, &t) {
        return Ok(());
    }
    let m = picked.len();
    let text = fill(PAIR_NEXT, &[&listed(&first), &1, &m]);
    let Some(touch) = touch_of(h, &t, &first, &text)? else {
        return Ok(());
    };
    let Some(r) = reauth(h, &t, Some(&touch))? else {
        return Ok(());
    };
    drop(touch);
    reach_holds(&t, &r, &picked)?;
    let mut left: Vec<u8> = picked
        .iter()
        .copied()
        .filter(|n| Some(*n) != r.key())
        .collect();
    let mut extra: Vec<Touch> = Vec::new();
    let mut r = r;
    while !left.is_empty() {
        r = match renewed(h, &t, r, TOUCH_RESERVE)? {
            Some(r) => r,
            None => return Ok(()),
        };
        let i = m - left.len() + 1;
        let text = fill(PAIR_NEXT, &[&listed(&left), &i, &m]);
        let Some(other) = touch_of(h, &t, &left, &text)? else {
            return Ok(());
        };
        let checked = phase(h, t.screen, t.serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            s.check_touch(&r, &other)
        })?;
        let Some(n) = checked else {
            return Ok(());
        };
        left.retain(|k| *k != n);
        extra.push(other);
    }
    let done = move |_: &Session| {
        let done = Done::of(vec![fill(PAIRED, &[&listed(&picked)])]);
        if synced {
            done.more(tr(CARRY_PLAIN).to_owned())
        } else {
            done
        }
    };
    let consent = vault::Consent::default();
    if let Some(told) = write(h, &t, r, extra, vault::Change::Pair, consent, &done)? {
        backup_after(h, BACKUP_SHORT);
        tell_after(h, &told);
    }
    Ok(())
}

/// [모든 키 새로 잠그기…] (spec §9.2 "Re-seed all keys"): S-RESEED and the
/// gate; a fresh seed per key; a 2-salt touch of the first key, then the
/// Reauth, then one 2-salt touch per other key (the 2-touch fallback when
/// Windows gives only the first output); the confirmation touch; the write.
fn reseed_flow(h: Hwnd) -> crypto::Result<()> {
    let (t, mut plan) = take(h, KEY_RESEED, |a, t| {
        authenticator().map_err(FidoError::text)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        s.plan_reseed()
    })?;
    if !ask(h, RESEED) || !gate_asked(h, &t) {
        return Ok(());
    }
    let n = t.keys.as_ref().map_or(0, |o| o.rows.len());
    // The first touch is the Reauth: a suspended key cannot open the key
    // file, so it is asked of the live, non-suspended keys only.
    let active = t
        .keys
        .as_ref()
        .map(KeysOverview::active)
        .unwrap_or_default();
    let mut proved: Vec<u8> = Vec::new();
    let mut fallback = false;
    let mut r: Option<vault::Reauth> = None;
    while proved.len() < n {
        if let Some(token) = r.take() {
            match renewed(h, &t, token, TOUCH_RESERVE)? {
                Some(token) => r = Some(token),
                None => return Ok(()),
            }
        }
        let text = fill(RESEED_NEXT, &[&(proved.len() + 1), &n]);
        say(h, &text);
        let request = phase(h, t.screen, t.serial, |_| {
            if r.is_none() {
                plan.first_request(&active, h)
            } else {
                plan.request(h)
            }
        })?;
        let Some(request) = request else {
            return Ok(());
        };
        let Some(touch) = touch_step(h, t.screen, t.serial, request, &text) else {
            return Ok(());
        };
        if r.is_none() {
            r = reauth(h, &t, Some(&touch))?;
            if r.is_none() {
                return Ok(());
            }
        }
        let Some(token) = r.as_ref() else {
            return Ok(());
        };
        let taken = phase(h, t.screen, t.serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            plan.take(s, token, &touch)
        })?;
        let Some(number) = taken else {
            return Ok(());
        };
        if touch.second_missing() {
            // S-TWOTOUCH: this key's new value from a touch of its own.
            fallback = true;
            let text = format!("{}\r\n{}", tr(TWOTOUCH), text);
            let Some(request) = phase(h, t.screen, t.serial, |_| plan.second_request(number, h))?
            else {
                return Ok(());
            };
            let Some(second) = touch_step(h, t.screen, t.serial, request, &text) else {
                return Ok(());
            };
            let taken = phase(h, t.screen, t.serial, |a| {
                let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                plan.take_second(s, token, &second)
            })?;
            if taken.is_none() {
                return Ok(());
            }
        }
        proved.push(number);
    }
    let Some(r) = r else {
        return Ok(());
    };
    let Some(r) = renewed(h, &t, r, TOUCH_RESERVE)? else {
        return Ok(());
    };
    if !fallback {
        let first = proved.first().copied().ok_or(vault::NOT_PLANNED)?;
        let Some(request) = phase(h, t.screen, t.serial, |_| plan.second_request(first, h))? else {
            return Ok(());
        };
        let Some(touch) = touch_step(h, t.screen, t.serial, request, RESEED_CONFIRM) else {
            return Ok(());
        };
        plan.confirm(&touch)?;
    }
    let keys = plan.finish()?;
    let done = |_: &Session| Done::of(vec![tr(RESEEDED).to_owned()]);
    let change = vault::Change::ReSeed(keys);
    if let Some(told) = write(
        h,
        &t,
        r,
        Vec::new(),
        change,
        vault::Consent::default(),
        &done,
    )? {
        backup_after(h, BACKUP_QUESTION);
        tell_after(h, &told);
    }
    Ok(())
}

/// [보안 키 끄기] (spec §9.2 "Keys off"): S-OFF and the gate, a touch of any
/// live key, the Reauth and the write; S-BACKUP, then S-RETIRE with every
/// key's registration name.
fn keys_off_flow(h: Hwnd) -> crypto::Result<()> {
    let change = vault::Change::KeysOff;
    let (t, synced) = take_with(h, KEY_OFF, &change, |a, t| {
        t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        authenticator().map_err(FidoError::text)?;
        // A GOYOKS01 key file: the off sequence of key-file sync (spec
        // §7.16, §9.2 keys off step 1), with P1's `ks′` snapshot.
        let s = a.session.as_mut().ok_or("먼저 금고를 열어주세요.")?;
        Ok(s.key_sync_view()
            .filter(|v| v.on)
            .map(|view| (view, s.off_request())))
    })?;
    let asked = match &synced {
        Some((view, request)) => {
            let first = format!(
                "{}

{}",
                tr(OFF),
                tr(KEYSOFF_SYNCED)
            );
            off_asked(h, &first, view, *request)
        }
        None => ask(h, OFF),
    };
    if !asked || !gate_asked(h, &t) {
        return Ok(());
    }
    let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
    let active = keys.active();
    let names: Vec<String> = keys.rows.iter().map(|k| k.display.clone()).collect();
    let Some(touch) = touch_of(h, &t, &active, TOUCH)? else {
        return Ok(());
    };
    let Some(r) = reauth(h, &t, Some(&touch))? else {
        return Ok(());
    };
    drop(touch);
    let request = synced.map(|(_, request)| request);
    let done = move |_: &Session| match request {
        Some(request) => Done::of(vec![tr(KEYS_OFF_DONE).to_owned(), off_line(request)])
            .more(tr(OFF_OTHERS).to_owned()),
        None => Done::of(vec![tr(KEYS_OFF_DONE).to_owned()]).more(tr(KEYS_OFF_OTHERS).to_owned()),
    };
    if let Some(told) = write(
        h,
        &t,
        r,
        Vec::new(),
        change,
        vault::Consent::default(),
        &done,
    )? {
        backup_after(h, BACKUP_QUESTION);
        // One dialog: the other PCs' step, then S-RETIRE.
        let retire = fill(RETIRE, &[&names.join("', '")]);
        tell(h, &[told.as_str(), retire.as_str()].join("\r\n\r\n"));
    }
    Ok(())
}

/// The gate dialogs (spec §7.15a, §9.2a), before any detail of the change:
/// S-LOSTPICK for G2 with this PC's own keys (`choices`; `opened` marks
/// the key that unlocked the session), which can switch to S-GATE-CODE,
/// and S-GATE-CODE for G1 (`epoch`: the incoming file's, which is public).
/// `note` leads the text (a wrong code before). None: [나중에].
pub(crate) fn ask_gate(
    h: Hwnd,
    kind: GateKind,
    choices: &[GateChoice],
    opened: Option<u8>,
    epoch: u64,
    note: Option<&str>,
) -> Option<GateAnswer> {
    let answer = ask_gate_typed(h, kind, choices, opened, epoch, note);
    if !matches!(answer, Some(GateAnswer::Code(_))) {
        TYPED_CODE.with(|c| c.borrow_mut().clear());
    }
    answer
}
thread_local! {
    /// The key code last typed at a gate (a key code is public, as the Keys
    /// screen shows it): asked again with it after GATE_CODE_WRONG.
    static TYPED_CODE: RefCell<String> = const { RefCell::new(String::new()) };
}
fn ask_gate_typed(
    h: Hwnd,
    kind: GateKind,
    choices: &[GateChoice],
    opened: Option<u8>,
    epoch: u64,
    note: Option<&str>,
) -> Option<GateAnswer> {
    let lead = |text: String| match note {
        Some(note) => format!("{}\n\n{text}", tr(note)),
        None => text,
    };
    let ok = DialogButton {
        id: GATE_OK,
        label: "확인",
        role: Role::Accept,
    };
    let later = DialogButton {
        id: GATE_LATER,
        label: LATER,
        role: Role::Cancel,
    };
    let to_code = DialogButton {
        id: GATE_TO_CODE,
        label: TO_CODE,
        role: Role::Switch,
    };
    let mut kind = kind;
    let mut note_pick: Option<&str> = None;
    loop {
        match kind {
            GateKind::G2 => {
                let labels: Vec<String> = choices
                    .iter()
                    .map(|c| {
                        let date = std::str::from_utf8(&c.date).unwrap_or("");
                        let mut label = fill(ROW, &[&c.number, &day(date)]);
                        if opened == Some(c.number) {
                            label = format!("{label} · {}", tr(ROW_OPENED));
                        }
                        label
                    })
                    .collect();
                let items: Vec<(&str, bool)> = labels.iter().map(|l| (l.as_str(), false)).collect();
                let text = match note_pick {
                    Some(n) => format!("{}\n\n{}", tr(n), tr(LOSTPICK)),
                    None => lead(tr(LOSTPICK).to_owned()),
                };
                match ask_input(h, InputKind::Pick(&items), &text, &[ok, to_code, later]) {
                    InputAnswer::Pick(picked) if picked.is_empty() => {
                        note_pick = Some(LOSTPICK_NONE);
                    }
                    InputAnswer::Pick(picked) => {
                        return Some(GateAnswer::Pick(
                            picked
                                .iter()
                                .filter_map(|i| choices.get(usize::from(*i)))
                                .map(|c| c.credhash)
                                .collect(),
                        ));
                    }
                    InputAnswer::Switch(GATE_TO_CODE) => kind = GateKind::G1,
                    _ => return None,
                }
            }
            GateKind::G1 => {
                let mut format_note: Option<&str> = None;
                // A code that did not match is asked again with what was
                // typed, so one wrong character is corrected, not retyped.
                let mut typed_before = if note == Some(vault::GATE_CODE_WRONG) {
                    TYPED_CODE.with(|c| c.borrow().clone())
                } else {
                    String::new()
                };
                loop {
                    let text = fill(GATE_CODE_TEXT, &[&epoch]);
                    let text = match format_note {
                        Some(n) => format!("{}\n\n{text}", tr(n)),
                        None => lead(text),
                    };
                    match ask_input(h, InputKind::Code(&typed_before), &text, &[ok, later]) {
                        InputAnswer::Code(typed) => {
                            TYPED_CODE.with(|c| *c.borrow_mut() = typed.to_string());
                            match vault::parse_code(&typed) {
                                Some(code) => return Some(GateAnswer::Code(code)),
                                None => {
                                    format_note = Some(CODE_FORMAT);
                                    typed_before = typed.to_string();
                                }
                            }
                        }
                        _ => return None,
                    }
                }
            }
        }
    }
}
/// The gate of a changed key file, judged after the unlock (spec §5.2,
/// §7.15a): a pick or a code answered before the touch, then a code typed
/// again while it does not match, or [나중에], which leaves the session in
/// gate-pending mode. A wrong pick turns G2 off (S-GATE-G2FAIL-DISK).
pub(crate) fn judge_login_gate(h: Hwnd, answer: GateAnswer, epoch: u64) {
    let mut answer = Some(answer);
    while let Some(given) = answer.take() {
        let at = APP.with(|cell| {
            let b = cell.try_borrow().ok()?;
            let a = b.as_ref()?;
            a.session.as_ref()?;
            Some((a.screen, a.serial))
        });
        let Some((screen, serial)) = at else {
            return;
        };
        let judged = phase(h, screen, serial, |a| {
            let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
            Ok(s.pass_login_gate(given))
        });
        match judged {
            Ok(Some(Ok(()))) => {
                APP.with(|cell| {
                    if let Ok(mut b) = cell.try_borrow_mut()
                        && let Some(a) = b.as_mut()
                    {
                        a.sync_badge = a.session.as_ref().and_then(Session::badge);
                        let screen = a.screen;
                        a.show(screen);
                        // The unlock's key lines, held back until the gate
                        // passed (see unlock_lines).
                        let mut notices = Vec::new();
                        if let Some(s) = a.session.as_ref() {
                            unlock_lines(s, &mut notices);
                        }
                        let mut lines = vec![GATE_PASSED];
                        lines.extend(notices.iter().map(|(t, _)| t.as_str()));
                        a.status = joined(&lines);
                        if notices.iter().any(|(_, tone)| *tone == TONE_DANGER) {
                            a.status_tone = TONE_DANGER;
                        }
                        a.build();
                    }
                });
                return;
            }
            Ok(Some(Err(e))) if e == vault::GATE_CODE_WRONG => {
                answer = ask_gate(h, GateKind::G1, &[], None, epoch, Some(e));
                if answer.is_none() {
                    later();
                }
            }
            Ok(Some(Err(e))) => report(h, e),
            Ok(None) => {}
            Err(e) => report(h, e),
        }
    }
}
/// The status line after [나중에] at a gate: the session stays in
/// gate-pending mode.
pub(crate) fn later() {
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
            && a.session.as_ref().is_some_and(Session::gate_pending)
        {
            a.set_status(GATE_LATER_TEXT, TONE_DANGER);
        }
    });
}
/// [받기…] on the Keys screen in gate-pending mode (spec §9.1, S45-1 #5):
/// the changed key file's own gate, judged at once.
fn accept_flow(h: Hwnd) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(KEY_ACCEPT)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let kind = s.login_gate().ok_or(vault::GATE_NOT_PENDING)?;
        let choices = s.gate_choices();
        let epoch = s.key_state().epoch;
        let opened = s.unlocked_with();
        a.flow = Some(KEY_ACCEPT);
        Ok((kind, choices, epoch, opened))
    });
    drain_pending(h);
    let (kind, choices, epoch, opened) = p1?;
    match ask_gate(h, kind, &choices, opened, epoch, None) {
        Some(answer) => {
            judge_login_gate(h, answer, epoch);
            // A pass that made the post-removal review due shows it now
            // (spec §5.13 "right after").
            review_after(h);
        }
        None => later(),
    }
    Ok(())
}
/// The TOFU banner's [확인] and [코드 없이 받기…] (spec §7.17, §9.2):
/// the typed code against this key file's own (G1, constant time), or
/// S-TOFU-NOPC's yes; a mismatch adds S-TOFU-OTHEREPOCH and writes nothing.
/// The code step is where the user looks, so a step that fails says so in
/// a dialog as well as on the status line (spec §2.29), and the banner's
/// field keeps the code typed.
fn tofu_flow(h: Hwnd, id: i32) -> crypto::Result<()> {
    match tofu_steps(h, id) {
        Err(e) => {
            tofu_failed(h, e);
            Ok(())
        }
        ok => ok,
    }
}
/// A failed TOFU step (see tofu_flow): the status line as usual, then the
/// same text in a dialog while the banner still stands.
fn tofu_failed(h: Hwnd, text: &str) {
    report(h, text);
    let shown = APP.with(|cell| {
        let b = cell.try_borrow().ok()?;
        let a = b.as_ref()?;
        (a.screen == Screen::Vault && a.session.is_some()).then(|| tr_lines(&a.status))
    });
    if let Some(shown) = shown {
        tell(h, &shown);
    }
}
fn tofu_steps(h: Hwnd, id: i32) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(id)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let fetched = s.fetched_unsaved();
        if !s.tofu() && !fetched {
            return Err(vault::GATE_NOT_PENDING);
        }
        let code = if id == TOFU_OK && s.tofu() {
            let typed = a.read(GATE_CODE)?;
            if typed.trim().is_empty() {
                return Err(TOFU_CODE_EMPTY);
            }
            Some(vault::parse_code(&typed).ok_or(CODE_FORMAT)?)
        } else {
            None
        };
        // Next to the vault, named as the user knows the path.
        let default = PathBuf::from(shown(&s.path.with_extension("goyokey")));
        a.flow = Some(id);
        Ok((a.serial, code, fetched.then_some(default), s.tofu()))
    });
    drain_pending(h);
    let (serial, code, fetched, tofu) = p1?;
    if code.is_none() && tofu && !ask(h, TOFU_NOPC_TEXT) {
        return Ok(());
    }
    // A key file from the server's key view (spec §7.17): the code first,
    // then where to save it, then the files and the anchor in one step.
    if let Some(default) = fetched {
        let via = match (&code, tofu) {
            (Some(_), _) => Via::Code,
            (None, true) => Via::NoCode,
            (None, false) => Via::Known,
        };
        let checked = phase(h, Screen::Vault, serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            Ok(s.tofu_check(code.as_ref()))
        })?;
        match checked {
            None => return Ok(()),
            Some(Err(e)) if e == vault::GATE_CODE_WRONG => {
                tofu_failed(h, &format!("{e}\r\n{TOFU_OTHEREPOCH}"));
                return Ok(());
            }
            Some(Err(e)) => return Err(e),
            Some(Ok(())) => {}
        }
        let path = match save_key_path(h, &default, via) {
            Saved::At(path) => path,
            Saved::Cancelled => {
                say(
                    h,
                    match via {
                        Via::Code => FETCHED_SAVE_LATER,
                        Via::NoCode => FETCHED_SAVE_LATER_NOCODE,
                        Via::Known => FETCHED_SAVE_LATER_KNOWN,
                    },
                );
                return Ok(());
            }
            Saved::Failed => {
                return Err(match via {
                    Via::Code => SAVE_DIALOG_FAILED,
                    Via::NoCode => SAVE_DIALOG_FAILED_NOCODE,
                    Via::Known => SAVE_DIALOG_FAILED_KNOWN,
                });
            }
        };
        return phase(h, Screen::Vault, serial, |a| {
            let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
            s.tofu_save(code.as_ref(), &path)?;
            // The paths remembered for the next start are the saved ones,
            // never the key view in the sync folder.
            save_paths(&s.path, &path);
            a.key_path = path.clone();
            a.sync_badge = s.badge();
            // What linking the sync folder found, as an unlock says it.
            let saved = fill(FETCHED_SAVED, &[&shown(&path)]);
            let (status, tone) = match s.take_unlock_notice().as_ref().map(sync_line) {
                Some((text, tone)) => (joined(&[&saved, &text]), tone),
                None => (Zeroizing::new(saved), TONE_MUTED),
            };
            a.show(Screen::Vault);
            a.status = status;
            a.status_tone = tone;
            a.build();
            Ok(())
        })
        .map(|_| ());
    }
    let wrong = phase(h, Screen::Vault, serial, |a| {
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        match s.tofu_confirm(code.as_ref()) {
            Ok(()) => {
                a.sync_badge = s.badge();
                a.show(Screen::Vault);
                a.status = line(TOFU_PASSED);
                a.build();
                Ok(false)
            }
            Err(e) if e == vault::GATE_CODE_WRONG => Ok(true),
            Err(e) => Err(e),
        }
    })?;
    if wrong == Some(true) {
        tofu_failed(
            h,
            &format!("{}\r\n{TOFU_OTHEREPOCH}", vault::GATE_CODE_WRONG),
        );
    }
    Ok(())
}

/// How a key file from the server came to be trusted before its save
/// step: the other PC's code, S-TOFU-NOPC's yes, or a state this PC
/// confirmed before (only the save was left).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Via {
    Code,
    NoCode,
    Known,
}
/// How the save step ended.
enum Saved {
    At(PathBuf),
    Cancelled,
    /// The file dialog could not open (CommDlgExtendedError).
    Failed,
}
/// The save step (spec §7.17, §2.29): the key file goes next to the vault
/// file as `<vault>.goyokey` unless the user picks another place; the
/// file dialog opens only for that, or when that name is taken. Never a
/// silent end: a dialog that fails says so. A test answers in its place.
fn save_key_path(h: Hwnd, default: &Path, via: Via) -> Saved {
    if !default.exists() {
        let here = DialogButton {
            id: 1,
            label: SAVE_HERE,
            role: Role::Accept,
        };
        let elsewhere = DialogButton {
            id: 2,
            label: SAVE_ELSEWHERE,
            role: Role::Switch,
        };
        // Only a matched code says the file is genuine.
        let lead = match via {
            Via::Code => SAVE_LEAD_CODE,
            Via::NoCode => SAVE_LEAD_NOCODE,
            Via::Known => SAVE_LEAD_KNOWN,
        };
        let text = format!(
            "{}\n\n{}",
            tr(lead),
            fill(FETCHED_SAVE_ASK, &[&shown(default)])
        );
        match ask_input(
            h,
            InputKind::Preview { check: None },
            &text,
            &[here, elsewhere, CANCEL_BUTTON],
        ) {
            InputAnswer::Accept { .. } => return Saved::At(default.to_owned()),
            InputAnswer::Switch(_) => {}
            _ => return Saved::Cancelled,
        }
    }
    #[cfg(test)]
    let (picked, failed) = {
        let _ = FETCHED_SAVE_TITLE;
        let picked = SAVE_KEY.with(|p| p.borrow_mut().take());
        (picked, SAVE_FAILS.with(|f| f.replace(false)))
    };
    #[cfg(not(test))]
    let (picked, failed) = {
        let picked = pick_file(
            h,
            true,
            "고요 열쇠 파일 (*.goyokey)\0*.goyokey\0모든 파일\0*.*\0",
            "goyokey",
            FETCHED_SAVE_TITLE,
            Some(default),
        );
        let failed = picked.is_none() && dialog_failed();
        (picked, failed)
    };
    match picked {
        Some(path) => Saved::At(path),
        None if failed => Saved::Failed,
        None => Saved::Cancelled,
    }
}
#[cfg(test)]
thread_local! {
    /// The path the save step's dialog answers with in a test.
    pub static SAVE_KEY: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    /// The save step's file dialog fails to open, once.
    pub static SAVE_FAILS: Cell<bool> = const { Cell::new(false) };
}

/// The touch plan of a removal (spec §9.1 `Screen::LostKey` step 4, §9.2a
/// "Allow lists follow the plan"), from public bytes before any touch.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Plan {
    /// Every key the write removes: the pick, and the keys paired only
    /// with it when they go too.
    pub remove: Vec<u8>,
    /// Staying keys that no other staying key reaches: paired only with
    /// the picked keys ("이 키와만 짝을 맺은 키").
    pub only: Vec<u8>,
    /// The keys that stay.
    pub stay: Vec<u8>,
    /// The allow list of the one touch: staying, live, non-suspended keys
    /// whose write reaches every staying key, but for those agreed to be
    /// suspended and those touched as well; the full authorizers first.
    pub touch: Vec<u8>,
    /// When no key fits: what a touch of the best key would suspend, which
    /// S-SUSPEND names.
    pub suspend: Vec<u8>,
}
/// The plan of removing `pick` (and, with `drop_only`, the keys paired only
/// with it), with `extra` touched as well and `consent` agreed to be
/// suspended. `unreached(a)`: the live keys a write authorized by key a
/// cannot deliver to.
pub fn plan(
    o: &KeysOverview,
    unreached: &dyn Fn(u8) -> Vec<u8>,
    pick: &[u8],
    drop_only: bool,
    extra: &[u8],
    consent: &[u8],
) -> Plan {
    let live: Vec<u8> = o.rows.iter().map(|r| r.number).collect();
    let active = o.active();
    let reaches = |a: u8, k: u8| !unreached(a).contains(&k);
    let kept: Vec<u8> = live.iter().copied().filter(|n| !pick.contains(n)).collect();
    let mut only: Vec<u8> = kept
        .iter()
        .copied()
        .filter(|k| {
            let others: Vec<u8> = kept.iter().copied().filter(|a| a != k).collect();
            !extra.contains(k) && !others.is_empty() && others.iter().all(|a| !reaches(*a, *k))
        })
        .collect();
    // Never every key: one must stay.
    if kept.iter().all(|k| only.contains(k)) {
        only.clear();
    }
    let mut remove = pick.to_vec();
    if drop_only {
        remove.extend(&only);
    }
    remove.sort_unstable();
    remove.dedup();
    let stay: Vec<u8> = live
        .iter()
        .copied()
        .filter(|n| !remove.contains(n))
        .collect();
    let cut = |a: u8| -> Vec<u8> {
        stay.iter()
            .copied()
            .filter(|k| *k != a && !extra.contains(k) && !reaches(a, *k))
            .collect()
    };
    let candidates: Vec<u8> = stay
        .iter()
        .copied()
        .filter(|a| active.contains(a) && !extra.contains(a))
        .collect();
    let mut touch: Vec<(usize, u8)> = candidates
        .iter()
        .map(|a| (cut(*a), *a))
        .filter(|(u, _)| u.iter().all(|k| consent.contains(k)))
        .map(|(u, a)| (u.len(), a))
        .collect();
    touch.sort_unstable();
    let suspend = if touch.is_empty() {
        candidates
            .iter()
            .map(|a| cut(*a))
            .min_by_key(Vec::len)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Plan {
        remove,
        only,
        stay,
        touch: touch.into_iter().map(|(_, a)| a).collect(),
        suspend,
    }
}
/// The loss date typed on the lost-key or review screen (spec §9.1): empty
/// for unknown, else YYYY-MM-DD, never after today (`now`, Unix seconds;
/// a day starts in UTC, so a local today up to 14 hours ahead still
/// counts). A later day would make the post-removal review list nothing,
/// here and on every PC the loss mark reaches.
pub fn loss_day(text: &str, now: u64) -> crypto::Result<Option<u64>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let day = vault::day_of(text).ok_or(DATE_FORMAT)?;
    if day > now + 14 * 3600 {
        return Err(FUTURE_DATE);
    }
    Ok(Some(day))
}
/// The numbers of the rows whose bit is set in `bits`.
fn picked(rows: &[KeyRow], bits: u8) -> Vec<u8> {
    rows.iter()
        .enumerate()
        .filter(|(i, _)| bits >> i & 1 != 0)
        .map(|(_, r)| r.number)
        .collect()
}
/// The bits of the rows numbered `numbers`.
fn bits_of(rows: &[KeyRow], numbers: &[u8]) -> u8 {
    rows.iter()
        .enumerate()
        .filter(|(_, r)| numbers.contains(&r.number))
        .fold(0, |m, (i, _)| m | 1 << i)
}
/// Each live key's unreached keys, taken once at phase 1: the key file
/// does not change during a flow.
type Reach = Vec<(u8, Vec<u8>)>;
fn reach_of(s: &Session, o: &KeysOverview) -> Reach {
    o.rows
        .iter()
        .map(|r| (r.number, s.unreached(r.number)))
        .collect()
}
fn unreached_in(reach: &Reach) -> impl Fn(u8) -> Vec<u8> + '_ {
    move |n| {
        reach
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, u)| u.clone())
            .unwrap_or_default()
    }
}

/// What S-SUSPEND was answered (spec §9.2 lost-key step 2, §9.2a).
enum Suspend {
    /// [계속]: the named keys are suspended.
    Continue,
    /// [그 키도 함께 터치]: the named keys become planned extra touches.
    TouchToo,
    /// [취소]: back to the plan before the touch, or the flow ends after it.
    Back,
}
/// S-SUSPEND naming `named`, keys of this key file (spec §9.3): `full` the
/// staying full authorizers, `after` once the Reauth touch is behind.
fn ask_suspend(h: Hwnd, keys: &KeysOverview, named: &[u8], full: &[u8], after: bool) -> Suspend {
    let named: Vec<(u8, bool)> = named.iter().map(|n| (*n, false)).collect();
    ask_suspend_named(h, keys, &named, full, after, true)
}
/// The buttons of S-SUSPEND: [취소] first, so that Enter suspends nothing
/// (as S-FORK), then [그 키도 함께 터치] when `touch` (every named key can be
/// touched here), then [계속].
fn suspend_buttons(touch: bool) -> Vec<DialogButton<'static>> {
    let mut buttons = vec![CANCEL_BUTTON];
    if touch {
        buttons.push(DialogButton {
            id: SUSPEND_TOUCH,
            label: TOUCH_TOO,
            role: Role::Switch,
        });
    }
    buttons.push(DialogButton {
        id: 1,
        label: CONTINUE,
        role: Role::Accept,
    });
    buttons
}
/// S-SUSPEND naming `named` as this PC names them (spec §7.15a: a key new
/// to this PC with its mark), with [그 키도 함께 터치] only when `touch`.
fn ask_suspend_named(
    h: Hwnd,
    keys: &KeysOverview,
    named: &[(u8, bool)],
    full: &[u8],
    after: bool,
    touch: bool,
) -> Suspend {
    let mut parts = vec![fill(SUSPEND, &[&named_list(named)])];
    if !full.is_empty() {
        let text = if after {
            SUSPEND_FULL_AFTER
        } else {
            SUSPEND_FULL
        };
        parts.push(fill(text, &[&listed(full)]));
    }
    let orphans: Vec<u8> = keys
        .rows
        .iter()
        .filter(|r| r.orphan && named.contains(&(r.number, false)))
        .map(|r| r.number)
        .collect();
    if !orphans.is_empty() {
        parts.push(fill(SUSPEND_ORPHANS, &[&listed(&orphans)]));
    }
    parts.push(tr(if touch { SUSPEND_ASK } else { SUSPEND_ASK_NEW }).to_owned());
    let text = parts.join(" ");
    match ask_input(
        h,
        InputKind::Preview { check: None },
        &text,
        &suspend_buttons(touch),
    ) {
        InputAnswer::Accept { .. } => Suspend::Continue,
        InputAnswer::Switch(SUSPEND_TOUCH) => Suspend::TouchToo,
        _ => Suspend::Back,
    }
}
/// A read-only text after a flow (S-RETIRE, a removal's long done text),
/// with one [확인].
fn tell(h: Hwnd, text: &str) {
    let ok = DialogButton {
        id: 1,
        label: "확인",
        role: Role::Accept,
    };
    let _ = ask_input(h, InputKind::Preview { check: None }, text, &[ok]);
}
/// The status line of a flow that failed, in the danger tone: its Korean
/// source lines, which the status line translates one by one.
fn fail(lines: &[&str]) {
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
        {
            a.error(&lines.join("\r\n"));
        }
    });
}

/// What phase 1 of a removal took besides the password (spec §9.2).
struct Removal {
    lost: bool,
    pick: Vec<u8>,
    loss: Option<LossReport>,
    new_password: Option<Zeroizing<String>>,
    reach: Reach,
    synced: bool,
}
/// SUBMIT on `Screen::LostKey` and `Screen::KeyRemove` (spec §9.2
/// "Lost-key flow" and "Retire keys"; with no waiting change, §15 row 5):
/// phase 1 checks the pick, the loss date, the exposure answer and the new
/// password; S-REMOVE and the gate for a retirement (a removal for a loss
/// is held by none of them, S-LOST-HALTED); S-ONLYPAIRED for a loss; the
/// plan, with S-SUSPEND when no staying key reaches every other; one touch
/// of a staying key in the plan's allow list (never a removed key); the
/// Reauth and its reach (S-SUSPEND again for a record found broken); the
/// planned extra touches; the one write; S-BACKUP; then for a loss its
/// done text and S-REVIEW, for a retirement S-RETIRE.
fn remove_flow(h: Hwnd) -> crypto::Result<()> {
    let (t, typed) = take(h, SUBMIT, |a, t| {
        let lost = a.screen == Screen::LostKey;
        let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        let pick = picked(&keys.rows, a.toggles.pick);
        if pick.is_empty() {
            return Err(if lost {
                LOST_PICK_NONE
            } else {
                REMOVE_PICK_NONE
            });
        }
        let loss = if lost {
            let exposure = a.toggles.exposure.ok_or(EXPOSE_NEEDED)?;
            let date = loss_day(&a.read(LOSS_DATE)?, otp::now()?)?;
            let shared_pin = if exposure == Exposure::No {
                Vec::new()
            } else {
                picked(&keys.rows, a.toggles.shared & !a.toggles.pick)
            };
            Some(LossReport {
                date,
                exposure,
                shared_pin,
            })
        } else {
            None
        };
        let asks_password = match &loss {
            Some(l) => l.exposure != Exposure::No && a.toggles.pwchange,
            None => a.toggles.pwchange,
        };
        let new_password = if asks_password {
            let pass = a.read(PASS)?;
            if pass.as_str() != a.read(CONFIRM)?.as_str() {
                return Err("비밀번호 확인이 일치하지 않습니다.");
            }
            vault::password_policy(&pass)?;
            if pass.as_str() == t.current.as_str() {
                return Err(vault::SAMEPASS);
            }
            Some(pass)
        } else {
            None
        };
        authenticator().map_err(FidoError::text)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        Ok(Removal {
            lost,
            pick,
            loss,
            new_password,
            reach: reach_of(s, keys),
            synced: s.badge().is_some(),
        })
    })?;
    let Removal {
        lost,
        pick,
        loss,
        new_password,
        reach,
        synced,
    } = typed;
    let keys = t.keys.clone().ok_or(vault::NOT_PLANNED)?;
    let unreached = unreached_in(&reach);
    // The rotation gates hold no removal for a loss (spec §7.5); a halt of
    // this PC's sync is named in the done text (S-LOST-HALTED).
    let halted = lost && matches!(t.gate, Some(vault::Gate::KeyHalt | vault::Gate::KeyFork));
    if !lost && (!ask(h, &fill(REMOVE_ASK, &[&listed(&pick)])) || !gate_asked(h, &t)) {
        return Ok(());
    }
    // S-ONLYPAIRED: the keys paired only with the lost ones go too, unless
    // the user keeps them (a retirement keeps them unless they are picked).
    let mut drop_only = false;
    if lost {
        let first = plan(&keys, &unreached, &pick, true, &[], &[]);
        if !first.only.is_empty() {
            // [함께 빼기] first: Enter takes the default the plan line and
            // "(권장)" announce (spec §9.2 lost-key step 2).
            let buttons = [
                DialogButton {
                    id: 1,
                    label: ONLYPAIRED_DROP,
                    role: Role::Accept,
                },
                DialogButton {
                    id: 2,
                    label: ONLYPAIRED_KEEP,
                    role: Role::Cancel,
                },
            ];
            let text = fill(ONLYPAIRED, &[&listed(&first.only)]);
            let kind = InputKind::Preview { check: None };
            drop_only = matches!(
                ask_input(h, kind, &text, &buttons),
                InputAnswer::Accept { .. }
            );
            if !standing(t.screen, t.serial) {
                return Ok(());
            }
        }
    }
    let Some(Touched {
        plan: p,
        r,
        extra,
        present,
        consent,
        unrepaired,
    }) = touch_by_plan(h, &t, &keys, &unreached, &pick, drop_only)?
    else {
        return Ok(());
    };
    let remove = p.remove.clone();
    let names: Vec<String> = keys
        .rows
        .iter()
        .filter(|k| remove.contains(&k.number))
        .map(|k| k.display.clone())
        .collect();
    let change = vault::Change::Remove {
        remove: remove.clone(),
        new_password,
        loss: loss.clone(),
        over: None,
    };
    let done = |s: &Session| {
        let (status, mut long) = done_lines(s, lost, &remove, &present, synced, loss.as_ref());
        if halted {
            long.push(tr(LOST_HALTED).to_owned());
        }
        long.extend(unrepaired_line(unrepaired));
        Done {
            lines: status,
            danger: false,
            more: long,
        }
    };
    let consent = vault::Consent { suspend: consent };
    match write(h, &t, r, extra, change, consent, &done) {
        Ok(Some(told)) => {
            backup_after(h, BACKUP_QUESTION);
            prune_after(h);
            if lost {
                tell_after(h, &told);
                review_after(h);
            } else {
                // One dialog: the done text, then S-RETIRE.
                let retire = fill(RETIRE, &[&names.join("', '")]);
                tell(h, &[told.as_str(), retire.as_str()].join("\r\n\r\n"));
            }
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) if [GAP_KEPT, vault::GAP_CHANGED, vault::KEY_DAMAGED].contains(&e) => Err(e),
        Err(e) => {
            fail(&[e, &fill(REMOVE_FAILED, &[&listed(&remove)])]);
            Ok(())
        }
    }
}
/// What the touches of a planned write gave (see touch_by_plan).
struct Touched {
    plan: Plan,
    r: vault::Reauth,
    extra: Vec<Touch>,
    /// The keys touched: the Reauth's, then the extra touches'.
    present: Vec<u8>,
    /// The keys agreed to be suspended (a removal's only).
    consent: Vec<u8>,
    /// A broken record between two staying keys that this write does not
    /// repair (the proposal declined, or its touch not made): (key, key).
    unrepaired: Option<(u8, u8)>,
}
/// The first broken pair record between two staying keys of `stay`, as
/// this PC found it (`pbad`), by the two keys' numbers (spec §9.2a, S45-3
/// #6).
fn broken_between(keys: &KeysOverview, stay: &[u8]) -> Option<(u8, u8)> {
    keys.rows
        .iter()
        .filter(|r| stay.contains(&r.number))
        .find_map(|r| {
            r.broken
                .iter()
                .copied()
                .find(|b| stay.contains(b) && *b > r.number)
                .map(|b| (r.number, b))
        })
}
/// The touches of a write that removes `pick` (none for a password change
/// or a key addition) (spec §9.2a "Allow lists follow the plan"): the
/// plan; for a broken record between two staying keys, the proposal to
/// touch both (S-REPAIR-PROPOSE: the one that reaches the other absent
/// keys as the touch, the other as an extra touch, which may be declined);
/// for a removal S-SUSPEND before the touch until a staying key fits, for
/// any other write the keys to touch as well (S-MUSTTOUCH; a key already
/// suspended stays so); one touch of a staying key in the plan's allow
/// list (never a removed key); the Reauth and its reach (S-SUSPEND again
/// for a removal, S-UNREACHABLE for any other write, when a record of the
/// touched key is found broken); the planned extra touches. None: the flow
/// ended (the status line says why, or a lock did).
fn touch_by_plan(
    h: Hwnd,
    t: &Typed,
    keys: &KeysOverview,
    unreached: &dyn Fn(u8) -> Vec<u8>,
    pick: &[u8],
    drop_only: bool,
) -> crypto::Result<Option<Touched>> {
    let removal = !pick.is_empty();
    // A write that removes nothing suspends nothing: a key already
    // suspended stays so (W6), every other one must be reached.
    let kept: Vec<u8> = if removal {
        Vec::new()
    } else {
        keys.rows
            .iter()
            .filter(|r| r.suspended)
            .map(|r| r.number)
            .collect()
    };
    let (mut consent, mut planned) = (kept.clone(), Vec::new());
    let mut p = plan(keys, unreached, pick, drop_only, &planned, &consent);
    if p.stay.is_empty() {
        return Err(NONE_STAYS);
    }
    let full: Vec<u8> = keys
        .full
        .iter()
        .copied()
        .filter(|k| p.stay.contains(k))
        .collect();
    // A broken record between two staying keys (S45-3 #6): both proposed
    // as present, the one that reaches the other absent keys as the touch.
    let mut repair: Option<(u8, u8)> = None;
    let mut unrepaired = None;
    if let Some((x, y)) = broken_between(keys, &p.stay) {
        let active = keys.active();
        let first = [(x, y), (y, x)].into_iter().find(|(a, b)| {
            active.contains(a)
                && unreached(*a)
                    .iter()
                    .all(|k| k == b || !p.stay.contains(k) || consent.contains(k))
        });
        match first {
            Some((a, b)) => {
                let text = fill(REPAIR_PROPOSE, &[&x, &y, &a]);
                let buttons = [
                    DialogButton {
                        id: 1,
                        label: REPAIR_TOUCH,
                        role: Role::Accept,
                    },
                    DialogButton {
                        id: 2,
                        label: REPAIR_SKIP,
                        role: Role::Cancel,
                    },
                ];
                let kind = InputKind::Preview { check: None };
                if matches!(
                    ask_input(h, kind, &text, &buttons),
                    InputAnswer::Accept { .. }
                ) {
                    repair = Some((a, b));
                    planned.push(b);
                } else {
                    unrepaired = Some((x, y));
                }
                if !standing(t.screen, t.serial) {
                    return Ok(None);
                }
                p = plan(keys, unreached, pick, drop_only, &planned, &consent);
                if let Some((a, _)) = repair {
                    if p.touch.contains(&a) {
                        p.touch.retain(|k| *k == a);
                    } else {
                        // The plan cannot take it: as declined.
                        repair = None;
                        planned.clear();
                        unrepaired = Some((x, y));
                        p = plan(keys, unreached, pick, drop_only, &planned, &consent);
                    }
                }
            }
            // Neither reaches the others: S-SUSPEND or S-MUSTTOUCH names
            // what the touch cannot reach.
            None => unrepaired = Some((x, y)),
        }
    }
    // Before the touch, until a staying key fits: S-SUSPEND for a removal,
    // the keys to touch as well for any other write.
    while p.touch.is_empty() {
        if p.suspend.is_empty() {
            return Err(PAIR_FIRST);
        }
        // A write that removes nothing names only the keys to touch: a
        // key already suspended stays so.
        let named: Vec<u8> = p
            .suspend
            .iter()
            .copied()
            .filter(|k| removal || !consent.contains(k))
            .collect();
        let answer = if removal {
            ask_suspend(h, keys, &named, &full, false)
        } else {
            ask_touch_too(h, &named)
        };
        match answer {
            Suspend::Continue => consent.extend(&named),
            Suspend::TouchToo => planned.extend(&named),
            Suspend::Back => return Ok(None),
        }
        if !standing(t.screen, t.serial) {
            return Ok(None);
        }
        p = plan(keys, unreached, pick, drop_only, &planned, &consent);
    }
    let Some(touch) = touch_of(h, t, &p.touch, TOUCH)? else {
        return Ok(None);
    };
    let Some(r) = reauth(h, t, Some(&touch))? else {
        return Ok(None);
    };
    drop(touch);
    // After the Reauth (S45-2 #6): a record of the touched key found broken
    // leaves a staying key unreached that the plan counted.
    let by = r.key();
    let reach: Vec<u8> = r.reach().to_vec();
    let stay = p.stay.clone();
    let missing = |planned: &[u8], consent: &[u8]| -> Vec<u8> {
        stay.iter()
            .copied()
            .filter(|k| Some(*k) != by && !reach.contains(k))
            .filter(|k| !planned.contains(k) && !consent.contains(k))
            .collect()
    };
    let lacking = missing(&planned, &consent);
    if !lacking.is_empty() {
        if !removal {
            return Err(vault::refuse(vault::UNREACHABLE, vec![listed(&lacking)]));
        }
        match ask_suspend(h, keys, &lacking, &full, true) {
            Suspend::Continue => consent.extend(&lacking),
            Suspend::TouchToo => planned.extend(&lacking),
            Suspend::Back => return Ok(None),
        }
    }
    // The planned extra touches, one ceremony each. The repair's own touch
    // may fail or be cancelled: the write then goes ahead as planned.
    let mut extra: Vec<Touch> = Vec::new();
    let mut left: Vec<u8> = planned.iter().copied().filter(|k| Some(*k) != by).collect();
    let mut present: Vec<u8> = by.into_iter().collect();
    let mut r = r;
    while !left.is_empty() {
        r = match renewed(h, t, r, TOUCH_RESERVE)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let text = fill(EXTRA_TOUCH, &[&listed(&left)]);
        let optional = repair.is_some_and(|(_, b)| left == [b]);
        let Some(other) = touch_of(h, t, &left, &text)? else {
            if optional && standing(t.screen, t.serial) {
                left.clear();
                unrepaired = repair.map(|(a, b)| (a.min(b), a.max(b)));
                break;
            }
            return Ok(None);
        };
        let checked = phase(h, t.screen, t.serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            s.check_touch(&r, &other)
        })?;
        let Some(n) = checked else {
            return Ok(None);
        };
        left.retain(|k| *k != n);
        present.push(n);
        extra.push(other);
    }
    // A repair touch not made: the touched key must still reach its
    // partner, or the partner is named as after the Reauth.
    if let Some((_, b)) = repair.filter(|(_, b)| !present.contains(b)) {
        planned.retain(|k| *k != b);
        let lacking = missing(&planned, &consent);
        if !lacking.is_empty() {
            if !removal {
                return Err(vault::refuse(vault::UNREACHABLE, vec![listed(&lacking)]));
            }
            match ask_suspend(h, keys, &lacking, &full, true) {
                Suspend::Continue => consent.extend(&lacking),
                _ => return Ok(None),
            }
        }
    }
    // The keys already suspended stay so on their own: no consent.
    consent.retain(|k| !kept.contains(k));
    Ok(Some(Touched {
        plan: p,
        r,
        extra,
        present,
        consent,
        unrepaired,
    }))
}
/// S-MUSTTOUCH (spec §9.2 password change step 2, add key step 1, §9.2a):
/// no key at hand reaches every other, so `named` must be touched as well
/// before anything starts. [그 키도 함께 터치] (Enter) or [취소].
fn ask_touch_too(h: Hwnd, named: &[u8]) -> Suspend {
    let text = fill(MUSTTOUCH, &[&listed(named)]);
    let buttons = [
        DialogButton {
            id: 1,
            label: TOUCH_TOO,
            role: Role::Accept,
        },
        CANCEL_BUTTON,
    ];
    let kind = InputKind::Preview { check: None };
    match ask_input(h, kind, &text, &buttons) {
        InputAnswer::Accept { .. } => Suspend::TouchToo,
        _ => Suspend::Back,
    }
}
/// S-REPAIR-SKIPPED: the line a write adds when it leaves a broken record
/// between two staying keys as it was (spec §9.2a, S45-3 #6).
fn unrepaired_line(pair: Option<(u8, u8)>) -> Option<String> {
    pair.map(|(x, y)| fill(REPAIR_SKIPPED, &[&x, &y]))
}
/// SUBMIT on `Screen::Password` for a key file with security keys (spec
/// §9.2 "Password change (both)" step 3): the new password checked before
/// any question; S-ROTATE and the gate; the touch plan of a write that
/// removes nothing (S-SUSPEND when no live key reaches every other), its
/// touch, the Reauth with that touch and any planned extra touches; the
/// write; S-BACKUP. A key file without keys keeps the default build's flow.
fn password_flow(h: Hwnd) -> crypto::Result<()> {
    let (t, (new_password, reach, synced)) = take(h, SUBMIT, |a, t| {
        let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        let pass = a.read(PASS)?;
        if pass.as_str() != a.read(CONFIRM)?.as_str() {
            return Err("비밀번호 확인이 일치하지 않습니다.");
        }
        vault::password_policy(&pass)?;
        if pass.as_str() == t.current.as_str() {
            return Err(vault::SAMEPASS);
        }
        authenticator().map_err(FidoError::text)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        Ok((pass, reach_of(s, keys), s.badge().is_some()))
    })?;
    let question = if synced {
        ROTATE_QUESTION_SYNCED
    } else {
        ROTATE_QUESTION
    };
    if !ask(h, question) || !gate_asked(h, &t) {
        return Ok(());
    }
    let keys = t.keys.clone().ok_or(vault::NOT_PLANNED)?;
    let unreached = unreached_in(&reach);
    let Some(Touched {
        r,
        extra,
        consent,
        unrepaired,
        ..
    }) = touch_by_plan(h, &t, &keys, &unreached, &[], false)?
    else {
        return Ok(());
    };
    let done = |_: &Session| {
        let mut done = Done::of(vec![tr(PASSWORD_CHANGED).to_owned()]);
        done.more.extend(unrepaired_line(unrepaired));
        done
    };
    let change = vault::Change::Password(new_password);
    let consent = vault::Consent { suspend: consent };
    if let Some(told) = write(h, &t, r, extra, change, consent, &done)? {
        backup_after(h, BACKUP_QUESTION);
        tell_after(h, &told);
    }
    Ok(())
}
/// A removal's status lines and its long text (spec §9.2 lost-key step 8,
/// retire step 4): S-LOST-DONE (S-LOST-DONE-USB with vault sync on) or the
/// retirement's line with S-CARRY-REMOVE; when every live key outside the
/// touched ones is suspended in the written file, only the first sentences
/// and S-DONE-ONLYHERE (S45-3 #5); S-CLONED for a shared PIN. The status
/// line holds the first sentences; the whole text is shown once in a
/// dialog, as the status line has room for three lines.
fn done_lines(
    s: &Session,
    lost: bool,
    remove: &[u8],
    present: &[u8],
    synced: bool,
    loss: Option<&LossReport>,
) -> (Vec<String>, Vec<String>) {
    let list = listed(remove);
    let rows = s.keys_overview().map(|o| o.rows).unwrap_or_default();
    let absent: Vec<&KeyRow> = rows
        .iter()
        .filter(|r| !present.contains(&r.number))
        .collect();
    let only_here = !absent.is_empty() && absent.iter().all(|r| r.suspended);
    let mut status = Vec::new();
    let mut long = Vec::new();
    if lost {
        let short = if synced {
            LOST_DONE_USB_SHORT
        } else {
            LOST_DONE_SHORT
        };
        status.push(fill(short, &[&list]));
        long.push(match (synced, only_here) {
            (_, true) => fill(short, &[&list]),
            (false, false) => fill(LOST_DONE, &[&list, &list]),
            (true, false) => fill(LOST_DONE_USB, &[&list, &list]),
        });
    } else {
        status.push(fill(REMOVED, &[&list]));
        if synced && !only_here {
            long.push(fill(CARRY_REMOVE, &[&list]));
        }
    }
    if only_here {
        let here: Vec<u8> = rows
            .iter()
            .filter(|r| present.contains(&r.number))
            .map(|r| r.number)
            .collect();
        let away: Vec<u8> = absent.iter().map(|r| r.number).collect();
        long.push(fill(DONE_ONLYHERE, &[&listed(&here), &listed(&away)]));
    }
    if let Some(l) = loss
        && l.exposure != Exposure::No
        && !l.shared_pin.is_empty()
    {
        long.push(fill(CLONED, &[&listed(&l.shared_pin)]));
    }
    (status, long)
}
/// Unticking [비밀번호도 함께 바꾸기 (권장)] (spec §9.1 `Screen::LostKey`
/// step 3): only after the danger question S-LOST-PWUNTICK, asked with no
/// borrow; the screen keeps what was typed.
fn pw_untick(h: Hwnd) -> crypto::Result<()> {
    let at = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(LOSS_PWCHANGE)?;
        Ok((a.screen, a.serial))
    })?;
    if !ask(h, PWUNTICK) {
        return Ok(());
    }
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
            && (a.screen, a.serial) == at
        {
            a.toggles.pwchange = false;
            a.rebuild_keeping(&KEPT);
        }
    });
    Ok(())
}
/// S-REVIEW after a removal for a loss, an adopt or an unlock (spec §5.13):
/// the review screen when something came in since the day before the loss;
/// an empty list marks the review done.
pub(crate) fn review_after(h: Hwnd) {
    let _ = h;
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
        {
            a.open_review();
        }
    });
}

/// The removal screens, [다시 하기] and the review screen.
impl App {
    /// The touch plan's lines on a removal screen and their tone (spec
    /// §9.1 step 4): which keys may be touched, which would be suspended,
    /// the keys paired only with the picked ones, S-ONEKEY when one key
    /// would stay, and for a loss what the password change does.
    fn plan_text(&self, lost: bool) -> (String, isize) {
        let Some(o) = self.keys_view().keys else {
            return (String::new(), TONE_MUTED);
        };
        let pick = picked(&o.rows, self.toggles.pick);
        let mut lines: Vec<String> = Vec::new();
        let mut tone = TONE_MUTED;
        if pick.is_empty() {
            lines.push(tr(PLAN_EMPTY).to_owned());
        } else {
            // A screen shown without the session's keys (the layout tests)
            // counts the rows' pairing status instead.
            let reach: Reach = match self.session.as_ref() {
                Some(s) if s.keys_overview().as_ref() == Some(&o) => reach_of(s, &o),
                _ => o
                    .rows
                    .iter()
                    .map(|r| (r.number, r.unpaired.clone()))
                    .collect(),
            };
            let unreached = unreached_in(&reach);
            let first = plan(&o, &unreached, &pick, lost, &[], &[]);
            let p = if first.touch.is_empty() {
                plan(&o, &unreached, &pick, lost, &[], &first.suspend)
            } else {
                first.clone()
            };
            if p.stay.is_empty() {
                return (tr(NONE_STAYS).to_owned(), TONE_DANGER);
            }
            match p.touch[..] {
                [] => {}
                [one] => lines.push(fill(PLAN_TOUCH_ONE, &[&one])),
                _ => lines.push(fill(PLAN_TOUCH, &[&listed(&p.touch)])),
            }
            if !first.suspend.is_empty() {
                lines.push(fill(PLAN_SUSPEND, &[&listed(&first.suspend)]));
            }
            if !p.only.is_empty() {
                lines.push(if lost {
                    fill(PLAN_ONLY_LOST, &[&listed(&p.only)])
                } else {
                    fill(ONLYPAIRED_RETIRE, &[&listed(&p.only)])
                });
            }
            if p.stay.len() == 1 {
                lines.push(tr(ONEKEY).to_owned());
                tone = TONE_DANGER;
            }
        }
        if lost && self.toggles.pwchange {
            lines.push(tr(LOST_PWCHANGE_NOTE).to_owned());
        }
        (lines.join("\r\n"), tone)
    }
    /// The current password, the new one and its confirmation when
    /// `new`, and the OTP code, in one row at `y` (as keys off).
    fn removal_fields(&mut self, y: i32, new: bool) {
        let otp = self
            .session
            .as_ref()
            .filter(|s| s.uses_otp())
            .map(|s| s.tag());
        let fields = 1 + 2 * i32::from(new) + i32::from(otp.is_some());
        let w = (796 - 16 * (fields - 1)) / fields;
        let mut x = 40;
        self.password_field(CURRENT_PASS, REAUTH_LABEL, x, y, w);
        x += w + 16;
        if new {
            self.password_field(PASS, NEW_PASS, x, y, w);
            x += w + 16;
            self.password_field(CONFIRM, NEW_CONFIRM, x, y, w);
            x += w + 16;
        }
        if let Some(tag) = otp {
            let caption = fill("새 OTP 6자리 · {tag}", &[&tag]);
            self.field(OTP, &caption, "", x, y, w, true);
        }
    }
    /// `Screen::LostKey` and `Screen::KeyRemove` (spec §9.1): one toggle
    /// per live key; for a loss the shared-PIN toggles beside the keys not
    /// picked (for 예 and 모름), the loss date (empty: unknown), the
    /// exposure question with no answer at first and the password change
    /// it ticks; for a retirement the optional password change; the touch
    /// plan; the current password (and OTP), read by the flow's phase 1.
    pub(crate) fn build_remove(&mut self) {
        let lost = self.screen == Screen::LostKey;
        let (title, small) = (self.font_of(|t| t.title()), self.font_of(|t| t.small()));
        let heading = if lost { LOST_TITLE } else { REMOVE_TITLE };
        // The two columns below span 40..836; the title and [뒤로] too.
        self.text(0, heading, (40, 80, 696, 34), title, TONE_TEXT, 0);
        self.button(BACK, "‹ 뒤로", 836 - 84, 84, 84, 32, theme::GHOST);
        let rows = self.keys_view().keys.map(|o| o.rows).unwrap_or_default();
        // A loss's questions follow the last key row, a little apart: the
        // space of the rows not shown (up to eight) is not left empty.
        let up = (27 * (8 - rows.len().clamp(1, 8) as i32) - 10).max(0);
        let exposed = lost && self.toggles.exposure.is_some_and(|e| e != Exposure::No);
        self.note(if lost { LOST_PICK } else { REMOVE_PICK }, 40, 118, 388, 34);
        if exposed {
            self.note(SHAREDPIN, 448, 118, 388, 34);
        }
        let toggle = |on: bool| if on { theme::TOGGLE_ON } else { theme::TOGGLE };
        for (i, r) in rows.iter().enumerate().take(8) {
            let y = 156 + 27 * i as i32;
            let label = fill(ROW, &[&r.number, &day(&r.stamp)]);
            let on = self.toggles.pick >> i & 1 != 0;
            self.button(KEY_PICK_ITEM + i as i32, &label, 40, y, 388, 25, toggle(on));
            if exposed && !on {
                let shared = self.toggles.shared >> i & 1 != 0;
                let label = fill(PAIR_ITEM, &[&r.number]);
                let id = SHARED_ITEM + i as i32;
                self.button(id, &label, 448, y, 388, 25, toggle(shared));
            }
        }
        let (plan, tone) = self.plan_text(lost);
        if lost {
            self.note(LOST_DATE, 40, 376 - up, 388, 34);
            let date = self
                .toggles
                .date
                .take()
                .map(|d| vault::shown_time(d)[..10].to_owned())
                .unwrap_or_default();
            self.input(LOSS_DATE, &date, (40, 410 - up, 388, 34), false, false, 0);
            let cue = wide(tr(DATE_CUE));
            unsafe {
                // EM_SETCUEBANNER, shown also while the field has focus.
                SendMessageW(self.handle(LOSS_DATE), 0x1501, 1, cue.as_ptr() as isize);
            }
            self.note(EXPOSE, 40, 450 - up, 388, 52);
            let w = (388 - 2 * 8) / 3;
            for (i, (id, label, answer)) in [
                (LOSS_YES, YES, Exposure::Yes),
                (LOSS_NO, NO, Exposure::No),
                (LOSS_UNSURE, UNSURE, Exposure::Unsure),
            ]
            .into_iter()
            .enumerate()
            {
                let on = self.toggles.exposure == Some(answer);
                let variant = if on { theme::TAB_ON } else { theme::TAB };
                self.button(id, label, 40 + i as i32 * (w + 8), 504 - up, w, 28, variant);
            }
            if exposed {
                let on = self.toggles.pwchange;
                let y = 538 - up;
                self.button(LOSS_PWCHANGE, LOST_PWCHANGE, 40, y, 388, 26, toggle(on));
            }
            // The plan under the shared-PIN toggles.
            self.text(0, &plan, (448, 376 - up, 388, 188), small, tone, 0);
            self.removal_fields(568 - up, exposed && self.toggles.pwchange);
            self.button(SUBMIT, LOST_SUBMIT, 40, 638 - up, 300, 40, theme::PRIMARY);
        } else {
            self.text(0, &plan, (448, 118, 388, 262), small, tone, 0);
            let on = self.toggles.pwchange;
            let label = REMOVE_PWCHANGE_LABEL;
            self.button(REMOVE_PWCHANGE, label, 40, 392, 388, 26, toggle(on));
            self.removal_fields(430, on);
            self.button(SUBMIT, REMOVE_SUBMIT, 40, 510, 300, 40, theme::PRIMARY);
        }
        unsafe {
            SetFocus(self.handle(CURRENT_PASS));
        }
    }
    /// [다시 하기] (`LOST_REDO`, spec §9.2): the flow the dropped removal's
    /// `src` names, filled with its pick, loss date, exposure answer and
    /// shared-PIN keys; the password fields start empty. A dropped adopt
    /// asks for its file again and never becomes a removal of this PC's.
    fn redo(&mut self) {
        // Kept until a removal (or adopt) lands: [뒤로] or a cancelled touch
        // leaves S-REMOVE-UNDONE and [다시 하기] on the Keys screen.
        let Some(redo) = self.session.as_ref().and_then(Session::redo).cloned() else {
            self.build();
            return;
        };
        let rows = self.keys_view().keys.map(|o| o.rows).unwrap_or_default();
        let screen = match redo.flow {
            RedoFlow::Lost => Screen::LostKey,
            RedoFlow::Retire => Screen::KeyRemove,
            RedoFlow::Adopt => {
                self.status = line(REDO_ADOPT);
                self.build();
                return;
            }
        };
        let mut toggles = Toggles {
            pick: bits_of(&rows, &redo.remove),
            ..Toggles::default()
        };
        if let Some(l) = &redo.loss {
            toggles.exposure = Some(l.exposure);
            toggles.pwchange = l.exposure != Exposure::No;
            toggles.shared = bits_of(&rows, &l.shared_pin);
            toggles.date = l.date;
        }
        self.toggles = toggles;
        self.show(screen);
        self.build();
    }
    /// S-REVIEW (spec §5.13): `Screen::Review` when the review is due and
    /// the log lists something from the day before the loss on; an empty
    /// list marks the review done, which releases the vault outgoing.
    pub(crate) fn open_review(&mut self) {
        if self.screen == Screen::Review {
            return;
        }
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let Some(due) = s.review_due() else {
            return;
        };
        let day = vault::day_of(due);
        if s.review_list(day).rows.is_empty() {
            if s.review_done().is_ok() {
                self.sync_badge = s.badge();
            }
            return;
        }
        self.toggles.review_day = Some(day);
        self.reset_copy();
        self.reveal_until = None;
        self.show(Screen::Review);
        self.build();
    }
    /// `Screen::Review` (spec §9.1, §5.13): S-REVIEW with the loss date,
    /// S-REVIEW-REPLACED and S-REVIEW-TRUNC in the danger tone, the date
    /// field, the list (a row opens its entry), [확인함] and [나중에].
    pub(crate) fn build_review(&mut self) {
        let (title, small) = (self.font_of(|t| t.title()), self.font_of(|t| t.small()));
        self.text(0, REVIEW_TITLE, (40, 80, 796, 34), title, TONE_TEXT, 0);
        let day = self.toggles.review_day.flatten();
        let text = match day {
            Some(d) => fill(REVIEW, &[&&vault::shown_time(d)[..10]]),
            None => tr(REVIEW_ALL).to_owned(),
        };
        self.text(0, &text, (40, 120, 796, 88), small, TONE_TEXT, 0);
        let list = self.shown_review(day);
        let mut warn: Vec<String> = Vec::new();
        for pair in list.rows.windows(2) {
            if pair[0].change == ReviewChange::Replaced && pair[1].change == ReviewChange::Moved {
                // The first pair named, its titles cut: the rows show all.
                let short = |t: &Option<String>| {
                    let t = t.as_deref().unwrap_or_default();
                    match t.char_indices().nth(40) {
                        Some((i, _)) => format!("{}…", &t[..i]),
                        None => t.to_owned(),
                    }
                };
                warn.push(fill(
                    REVIEW_REPLACED,
                    &[&short(&pair[0].title), &short(&pair[1].title)],
                ));
                break;
            }
        }
        if let Some(before) = list.truncated {
            let time = local_time(before);
            warn.push(fill(REVIEW_TRUNC, &[&time]));
        }
        self.text(
            0,
            &warn.join("\r\n"),
            (40, 212, 796, 110),
            small,
            TONE_DANGER,
            0,
        );
        self.label(REVIEW_DATE, 40, 328, 300);
        let date = day.map_or_else(String::new, |d| vault::shown_time(d)[..10].to_owned());
        self.input(LOSS_DATE, &date, (40, 350, 240, 36), false, false, 0);
        self.note(REVIEW_HINT, 296, 358, 540, 22);
        // LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | WS_VSCROLL, in a painted
        // frame as the other lists.
        let rows = self.ctrl(
            REVIEW_LIST,
            "LISTBOX",
            "",
            52,
            402,
            780,
            206,
            0x1 | 0x100 | 0x0020_0000,
        );
        self.frames.push((
            Rect {
                left: 40,
                top: 394,
                right: 836,
                bottom: 616,
            },
            rows,
        ));
        unsafe {
            let orig = SetWindowLongPtrW(rows, -4, review_proc as *const () as isize);
            if orig == 0 {
                std::process::abort();
            }
            REVIEW_PROC.get_or_init(|| std::mem::transmute::<isize, Proc>(orig));
            for r in &list.rows {
                let row = wide(&row_text_of(r));
                SendMessageW(rows, 0x180, 0, row.as_ptr() as isize); // LB_ADDSTRING
            }
        }
        self.button(REVIEW_OK, REVIEW_OK_LABEL, 40, 624, 260, 40, theme::PRIMARY);
        self.button(REVIEW_LATER, LATER, 316, 624, 200, 40, theme::SECONDARY);
        unsafe {
            SetFocus(rows);
        }
    }
    /// What the review screen lists: the session's merge log from the day
    /// before `day` on; a layout test sets it instead.
    fn shown_review(&self, day: Option<u64>) -> vault::ReviewList {
        #[cfg(test)]
        if let Some(list) = REVIEW_SHOWN.with(|r| r.borrow().clone()) {
            return list;
        }
        self.session
            .as_ref()
            .map(|s| s.review_list(day))
            .unwrap_or_default()
    }
    /// The review list's notices (spec §5.13): a row double-clicked opens
    /// its entry (the edit screen returns here), and a valid or empty loss
    /// date shows the list from the day before it. True when handled.
    pub(crate) fn review_notice(&mut self, id: i32, notify: u16) -> crypto::Result<bool> {
        if self.screen != Screen::Review {
            return Ok(false);
        }
        match (id, notify) {
            // LBN_DBLCLK.
            (REVIEW_LIST, 2) => {
                let i = unsafe { SendMessageW(self.handle(REVIEW_LIST), 0x188, 0, 0) };
                let day = self.toggles.review_day.flatten();
                let s = self.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                let row = usize::try_from(i)
                    .ok()
                    .and_then(|i| s.review_list(day).rows.get(i).cloned());
                let Some(index) = row.and_then(|r| r.index) else {
                    self.status(REVIEW_NOT_HERE);
                    return Ok(true);
                };
                self.toggles.reviewing = true;
                self.selected = Some(index);
                self.editing = Some(index);
                self.reset_copy();
                self.reveal_until = None;
                self.show(Screen::Edit);
                self.build();
                Ok(true)
            }
            // EN_CHANGE of the date: only a date the list can use (a day
            // after today would list nothing and end the review unread).
            (LOSS_DATE, 0x300) => {
                let Ok(day) = loss_day(&self.read(LOSS_DATE)?, otp::now()?) else {
                    return Ok(true);
                };
                if self.toggles.review_day != Some(day) {
                    self.toggles.review_day = Some(day);
                    self.rebuild_keeping(&[LOSS_DATE]);
                    unsafe {
                        let edit = self.handle(LOSS_DATE);
                        SetFocus(edit);
                        SendMessageW(edit, 0xb1, usize::MAX, -1); // EM_SETSEL to the end
                    }
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    /// Where the edit screen goes back to: the review it was opened from,
    /// else the vault list.
    pub(crate) fn after_edit(&mut self) -> Screen {
        if std::mem::take(&mut self.toggles.reviewing) && self.session.is_some() {
            Screen::Review
        } else {
            Screen::Vault
        }
    }
    /// [확인함] (spec §5.13): the review done in the anchor and the merge
    /// log; the vault outgoing that waited for it is written.
    fn review_ok(&mut self) -> crypto::Result<()> {
        let s = self.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        s.review_done()?;
        self.sync_badge = s.badge();
        self.toggles.review_day = None;
        self.show(Screen::Vault);
        self.status = line(REVIEW_DONE);
        self.build();
        Ok(())
    }
    /// [나중에]: the review stays due; S-REVIEW comes back at every unlock.
    fn review_later(&mut self) {
        self.toggles.review_day = None;
        self.show(Screen::Vault);
        self.status = line(REVIEW_LATER_TEXT);
        self.build();
    }
}
/// A row of the review list: the entry's title (or what it is when it is
/// not live here), the change and the local merge time.
fn row_text_of(r: &vault::ReviewRow) -> String {
    let what = tr(match r.change {
        ReviewChange::New => R_NEW,
        ReviewChange::Edited => R_EDITED,
        ReviewChange::Replaced => R_REPLACED,
        ReviewChange::Moved => R_MOVED,
        ReviewChange::Deleted => R_DELETED,
    });
    let when = local_time(r.time);
    match (&r.title, r.change) {
        (_, ReviewChange::Deleted) => format!("{what} · {when}"),
        (Some(title), _) => format!("{title} · {what} · {when}"),
        (None, _) => format!("{} · {what} · {when}", tr(R_MISSING)),
    }
}
/// SYSTEMTIME.
#[repr(C)]
#[derive(Default)]
struct SystemTime {
    year: u16,
    month: u16,
    weekday: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    ms: u16,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn FileTimeToSystemTime(file: *const u64, out: *mut SystemTime) -> i32;
    fn SystemTimeToTzSpecificLocalTime(
        zone: *const u8,
        utc: *const SystemTime,
        local: *mut SystemTime,
    ) -> i32;
}
/// A merge time (Unix seconds) as the review shows it (spec §5.13 "local
/// merge time"): YYYY-MM-DD HH:MM in this PC's time zone, with its rules
/// for that date; the UTC time marked as such if Windows cannot convert it.
pub fn local_time(secs: u64) -> String {
    // 100 ns intervals since 1601-01-01.
    let file = (secs + 11_644_473_600).saturating_mul(10_000_000);
    let (mut utc, mut local) = (SystemTime::default(), SystemTime::default());
    let ok = unsafe {
        FileTimeToSystemTime(&file, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTime(null(), &utc, &mut local) != 0
    };
    if !ok {
        return format!("{} UTC", vault::shown_time(secs));
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        local.year, local.month, local.day, local.hour, local.minute
    )
}
static REVIEW_PROC: OnceLock<Proc> = OnceLock::new();
/// REVIEW_LIST's procedure: anything another thread sends is dropped, as
/// for the entry list.
unsafe extern "system" fn review_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() {
        return 0;
    }
    unsafe { CallWindowProcW(REVIEW_PROC.get().copied(), h, m, w, l) }
}

/// S-FORK with [취소] first, so that Enter chooses no option, then the
/// options offered (spec §9.2 adopt step 2.2): no default, no hint and no
/// key number. None: [취소].
fn ask_fork(h: Hwnd, check: &vault::AdoptCheck) -> Option<vault::ForkOption> {
    let mut buttons = vec![CANCEL_BUTTON];
    if check.keys.take_other_offered {
        buttons.push(DialogButton {
            id: FORK_OPT1,
            label: FORK_TAKE_OTHER,
            role: Role::Switch,
        });
    }
    if check.keys.both {
        buttons.push(DialogButton {
            id: FORK_OPT2,
            label: FORK_BOTH,
            role: Role::Switch,
        });
    }
    let text = fork_text(check.keys.take_other_offered, check.keys.both);
    match ask_input(h, InputKind::Preview { check: None }, &text, &buttons) {
        InputAnswer::Switch(FORK_OPT1) => Some(vault::ForkOption::TakeOther),
        InputAnswer::Switch(FORK_OPT2) => Some(vault::ForkOption::Both),
        _ => None,
    }
}
/// S-FORK naming only the options offered (spec §9.2 adopt step 2.2): the
/// whole text with both, else its head, the one option's sentence and the
/// gate's.
fn fork_text(take_other: bool, both: bool) -> String {
    if take_other && both {
        return tr(FORK).to_owned();
    }
    let option = if take_other {
        FORK_OPT1_TEXT
    } else {
        FORK_OPT2_TEXT
    };
    [FORK_HEAD, option, FORK_GATE_TEXT]
        .iter()
        .map(|t| tr(t))
        .collect::<Vec<_>>()
        .join(" ")
}
/// [열기] on `Screen::Adopt` in this build (spec §9.2 "Adopt", §5.8): the
/// default build's one flow with what security keys add: the fork option
/// (S-FORK with no default, no hint and no key number), the option's gate
/// (S-LOSTPICK or S-GATE-CODE) before any touch, the Reauth touch (with two
/// salts where the two files' seeds differ), a touch of a key of the other
/// file when the Reauth key does not open it (S-OTHERKEY-ONLY, whose
/// [취소] gives S-NOACTIVEKEY), the preview with the keys it would
/// suspend, S-FORK-READMIT, S-ADOPT-PWONLY, S-ADOPT-BOTHPASS and
/// S-SUSPEND, the write, S-BACKUP, and S-REVIEW after a removal for a loss.
/// The Reauth, every Touch, the other file's password and its opened keys
/// live only in this frame.
/// Where adopt_from's other file comes from: a file the user picked (the
/// Adopt screen), the server's key file ([받기…]), or that file at login,
/// taken with the unlock's touch and the login's `UnlockProof` (spec §5.2
/// step 9(b), §7.15 at login).
enum Taking {
    File,
    Server,
    Login(Box<(vault::UnlockProof, Touch)>),
}
/// The accept at login when the server's key file waits (spec §5.2 step
/// 9(b), §7.15 at login): a successor (with a carry or not) whose gate, if
/// any, is asked now, after the unlock and rule D and before anything about
/// the change is shown; no second touch and no second OTP code. A fork, a
/// refused file, or one whose result this Windows cannot take, asks
/// nothing.
pub(crate) fn accept_at_login(
    h: Hwnd,
    proof: vault::UnlockProof,
    touch: Touch,
) -> crypto::Result<()> {
    adopt_from(h, Taking::Login(Box::new((proof, touch))))
}
/// S-TRY-SERVER-KEY after a failed unlock with the server's key file
/// waiting (spec §5.2 second entry point): yes takes it on the failed-
/// unlock entry with the unlock's touch.
pub(crate) fn try_server_key(
    h: Hwnd,
    screen: Screen,
    serial: u64,
    mut entry: vault::ServerEntry,
    touch: &Touch,
) -> crypto::Result<()> {
    if !standing(screen, serial) || !ask(h, TRY_SERVER_KEY) {
        return Ok(());
    }
    server_entry(h, screen, serial, &mut entry, touch)
}
/// S-TRY-OTHERKEY after Windows' cancel of the unlock's ceremony (spec
/// §5.2, S6-1 #1, S6-2 #4): one ceremony with only the keys the server's
/// key file lists and this PC's lacks, then the failed-unlock entry with
/// that touch, without S-TRY-SERVER-KEY.
pub(crate) fn try_other_key(h: Hwnd, screen: Screen, serial: u64, mut entry: vault::ServerEntry) {
    let go = DialogButton {
        id: 1,
        label: TOUCH_LABEL,
        role: Role::Accept,
    };
    let kind = InputKind::Preview { check: None };
    let asked = ask_input(h, kind, TRY_OTHERKEY, &[go, CANCEL_BUTTON]);
    if !matches!(asked, InputAnswer::Accept { .. }) || !standing(screen, serial) {
        return;
    }
    let Some(request) = entry.other_request(h) else {
        return;
    };
    let Some(touch) = touch_step(h, screen, serial, request, TOUCH) else {
        return;
    };
    if let Err(e) = server_entry(h, screen, serial, &mut entry, &touch) {
        report(h, e);
    }
}
/// The failed-unlock entry (spec §5.2, §7.15 step 4): the OTP code's time
/// window checked as the entry starts (OTP_STALE is no failed attempt); the
/// gate asked once, before the open; then the server's key file opened with the typed
/// password and `touch`, judged and installed in one library call, which
/// returns the session only with the file taken. A wrong code may be typed
/// again; S-KEYSYNC-ON is asked once the gate passed, where the result
/// turns key-file sync on here. A file that does not open is a failed
/// attempt (S-TRY-OTHERKEY-FAILED on that path).
fn server_entry(
    h: Hwnd,
    screen: Screen,
    serial: u64,
    entry: &mut vault::ServerEntry,
    touch: &Touch,
) -> crypto::Result<()> {
    entry.start()?;
    let gate = entry.gate();
    let epoch = gate.as_ref().map_or(0, |g| g.3);
    let mut answer = match gate {
        Some((kind, choices, touched, epoch)) => {
            match ask_gate(h, kind, &choices, touched, epoch, None) {
                Some(answer) => Some(answer),
                None => return Ok(()),
            }
        }
        None => None,
    };
    let mut consent = false;
    loop {
        unsafe {
            UpdateWindow(h);
        }
        let taken = APP.with(|cell| -> crypto::Result<Option<_>> {
            let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
            let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
            // The unlock's own failure started the retry delay; this is
            // the same attempt (a failure here counts once more).
            if !a.still(screen, serial, false)? {
                return Ok(None);
            }
            let result = Session::login_via_server(entry, touch, answer.clone(), consent);
            Ok(Some(match result {
                Ok((s, adopted)) => {
                    a.opened(Screen::Login, Ok(s), None)?;
                    // The new password was typed at this login: the
                    // status says only what was taken (three lines).
                    let accepted = fill(
                        ACCEPTED_AT_LOGIN,
                        &[&adopted.code.show(adopted.state.epoch)],
                    );
                    let mut lines = vec![accepted.as_str()];
                    if adopted.vault_pending {
                        lines.push(vault::VPENDING);
                    }
                    let danger = a.status_tone == TONE_DANGER;
                    a.status = at_login_status(&a.status, danger, &lines);
                    a.build();
                    Ok(())
                }
                Err(e) if e == crypto::AUTH_ERROR => {
                    a.failed_attempt();
                    Err(if entry.own_tried() {
                        crypto::AUTH_ERROR
                    } else {
                        TRY_OTHERKEY_FAILED
                    })
                }
                Err(e) => Err(e),
            }))
        });
        drain_pending(h);
        match taken? {
            None => return Ok(()),
            Some(Ok(())) => {
                backup_after(h, BACKUP_QUESTION);
                return Ok(());
            }
            Some(Err(e)) if e == vault::GATE_CODE_WRONG => {
                answer = ask_gate(h, GateKind::G1, &[], None, epoch, Some(e));
                if answer.is_none() {
                    return Ok(());
                }
            }
            Some(Err(e)) if e == vault::KEYSYNC_CONSENT && !consent => {
                transport_reported()?;
                if !ask(h, KEYSYNC_ON_TEXT) {
                    return Ok(());
                }
                consent = true;
            }
            Some(Err(e)) => return Err(e),
        }
    }
}
fn adopt_from(h: Hwnd, taking: Taking) -> crypto::Result<()> {
    let server = !matches!(taking, Taking::File);
    let (login, mut held_touch) = match taking {
        Taking::Login(taken) => {
            let (proof, touch) = *taken;
            (Some(proof), Some(touch))
        }
        _ => (None, None),
    };
    let screen = match (&login, server) {
        (Some(_), _) => Screen::Vault,
        (None, true) => Screen::Keys,
        (None, false) => Screen::Adopt,
    };
    let p1 = APP.with(|cell| -> crypto::Result<Option<_>> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        match &login {
            // Still inside the login's flow, on the vault screen it opened.
            Some(_) if a.screen != Screen::Vault || a.closing => return Ok(None),
            Some(_) => {}
            None => a.enter(if server { KEY_ACCEPT } else { SUBMIT })?,
        }
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        // The server's key file exactly as judged (spec §7.15 step 1): a
        // successor (with a carry or not), or a fork, which this flow joins
        // with fork options 1 and 2 behind their gate; a refused file goes
        // only through "새 열쇠 파일 받기" with a file from elsewhere. At
        // login, only the snapshot precheck read, judged a successor.
        // The kind-9 merge of two removals made from one state (spec §5.8):
        // at login only with no question before the open; with [받기] it
        // skips the fork's options (it is option 2, with no gate).
        let mut removal = false;
        let (other, source) = match &login {
            Some(proof) => match s.login_candidate(proof) {
                Some((file, seq)) => (file, Source::Server { seq }),
                None => match s.login_merge(proof) {
                    Some((file, seq)) => {
                        removal = true;
                        (file, Source::Server { seq })
                    }
                    None => return Ok(None),
                },
            },
            None if server => {
                let (file, seq) = s.server_key_file().ok_or(vault::NO_CANDIDATE)?;
                if !server_takes(s.server_class()) {
                    return Err(vault::NOT_A_SUCCESSOR);
                }
                removal = s.removal_merge().is_some();
                (file, Source::Server { seq })
            }
            None => {
                let path = a.adopt_source.clone().ok_or("받을 열쇠 파일을 고르세요.")?;
                (KeyFile::read(&path)?, Source::File(path))
            }
        };
        let check = match s.adopt_check(&other, source) {
            Ok(check) => check,
            Err(_) if login.is_some() => return Ok(None),
            Err(e) => return Err(e),
        };
        if login.is_some() && !removal && (check.fork || check.class != AdoptClass::Successor) {
            return Ok(None);
        }
        let same = match check.class {
            AdoptClass::Equal => Some(vault::ADOPT_EQUAL),
            AdoptClass::Contained => Some(vault::ADOPT_CONTAINED),
            _ => None,
        };
        if let Some(same) = same {
            a.status(same);
            return Ok(None);
        }
        let keys = s.keys_overview();
        if keys.is_some() || other.needs_security_key() {
            authenticator().map_err(FidoError::text)?;
        }
        // A result that turns key-file sync on here: the transport first,
        // before any gate question or touch (spec §7.15 step 1, S6-3 #10).
        // At login it asks nothing and says why (S-KEYSYNC-NOTRANSPORT).
        let ks01 = |m: Option<vault::keyfile::Magic>| m == Some(vault::keyfile::Magic::Ks01);
        if ks01(other.magic()) && !ks01(s.key_magic()) && !check.fork {
            match transport_reported() {
                Err(e) if login.is_some() => {
                    let line = joined(&[tr(e), a.status.as_str()]);
                    a.set_status(&line, TONE_DANGER);
                    return Ok(None);
                }
                result => result?,
            }
        }
        let gate = (s.gate_choices(), s.unlocked_with());
        let (current, otp) = match &login {
            Some(proof) => (proof.password(), Zeroizing::new(String::new())),
            None => (a.read(CURRENT_PASS)?, a.read(OTP)?),
        };
        let typed = Typed {
            screen,
            serial: a.serial,
            current,
            otp,
            otp_time: otp::now()?,
            gate: None,
            keys: keys.clone(),
            uses_otp: s.uses_otp(),
        };
        if login.is_none() {
            a.flow = Some(if server { KEY_ACCEPT } else { SUBMIT });
        }
        Ok(Some((a.serial, other, check, typed, keys, gate, removal)))
    });
    drain_pending(h);
    let Some((serial, other, check, t, keys, (choices, opened_with), removal)) = p1? else {
        return Ok(());
    };
    let at_login = login.is_some();
    // The automatic merge at login asks nothing before the open, and shows
    // no preview: a question after the open (S-SUSPEND) is still asked.
    let quiet = at_login && removal;
    let (current, otp, otp_time) = (&t.current, &t.otp, t.otp_time);
    let (epoch, tag) = (check.other.epoch, check.other.tag);
    // A: the fork option, then its gate; nothing about the change before.
    // Two password-only files have no options: they are joined, as in the
    // default build.
    let hardware = keys.is_some() || other.needs_security_key();
    let fork_options = check.fork && hardware && !removal;
    let mut option = if fork_options {
        match ask_fork(h, &check) {
            Some(option) => option,
            None => return Ok(()),
        }
    } else {
        vault::ForkOption::Both
    };
    let gate_of = |option: vault::ForkOption| match option {
        vault::ForkOption::TakeOther => check.keys.take_other,
        vault::ForkOption::Both => check.keys.gate,
    };
    let mut pass = GatePass::none(&check);
    if let Some(kind) = gate_of(option) {
        pass = match ask_gate(h, kind, &choices, opened_with, epoch, None) {
            Some(GateAnswer::Pick(pick)) => GatePass::G2Passed { pick, epoch, tag },
            Some(GateAnswer::Code(code)) => GatePass::G1Passed { code, epoch, tag },
            None => return Ok(()),
        };
    }
    // C: the Reauth touch, with two salts where the files' seeds differ;
    // at login the unlock's own touch.
    let touch = if held_touch.is_some() {
        held_touch.take()
    } else if keys.is_some() {
        let request = phase(h, screen, serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            s.adopt_request(&other, h)
        })?;
        let Some(request) = request else {
            return Ok(());
        };
        let Some(touch) = touch_step(h, screen, serial, request, TOUCH) else {
            return Ok(());
        };
        Some(touch)
    } else {
        None
    };
    // P3: the re-authentication; at login the login's own (spec §5.3).
    let r = phase(h, screen, serial, |a| {
        let serial = a.serial;
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        let result = match (login, touch.as_ref()) {
            (Some(proof), Some(touch)) => s.reauth_from_unlock(proof, touch),
            _ => s.reauth(current, Some((otp, otp_time)), touch.as_ref()),
        };
        match result {
            Ok(mut r) => {
                r.app_serial = serial;
                a.failed = 0;
                Ok(r)
            }
            Err(e) => {
                if e == crypto::AUTH_ERROR {
                    a.failed_attempt();
                }
                Err(e)
            }
        }
    })?;
    let Some(mut r) = r else {
        return Ok(());
    };
    // C: a key of the other file, when the Reauth key does not open it.
    let mut opener = None;
    if other.needs_security_key() {
        let covered = phase(h, screen, serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            Ok(r.key().is_some_and(|n| s.opens_other(&other, n)))
        })?;
        match (covered, touch) {
            (None, _) => return Ok(()),
            // Windows gave only the first output (S45-3 #10): one more
            // single-salt touch of the same key with the other file's seed.
            (Some(true), Some(touch)) if touch.second_missing() => {
                let number = r.key().ok_or(vault::NOT_PLANNED)?;
                let request = phase(h, screen, serial, |a| {
                    let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                    s.other_seed_request(&other, number, h)
                })?;
                let Some(request) = request else {
                    return Ok(());
                };
                let text = format!("{}\r\n{}", tr(TWOTOUCH), tr(TOUCH));
                let Some(second) = touch_step(h, screen, serial, request, &text) else {
                    return Ok(());
                };
                opener = Some(second);
            }
            (Some(true), Some(touch)) => opener = Some(touch),
            _ => {
                let list = phase(h, screen, serial, |a| {
                    let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                    Ok(s.opening_keys(&other))
                })?;
                let Some(list) = list else {
                    return Ok(());
                };
                let text = fill(OTHERKEY_ONLY, &[&named_list(&list)]);
                let go = DialogButton {
                    id: 1,
                    label: TOUCH_LABEL,
                    role: Role::Accept,
                };
                let kind = InputKind::Preview { check: None };
                let asked = ask_input(h, kind, &text, &[go, CANCEL_BUTTON]);
                // A lock or close while it was open voids the flow, with
                // the lock's line and no Windows call (§8.5).
                if !standing(screen, serial) {
                    return Ok(());
                }
                if !matches!(asked, InputAnswer::Accept { .. }) {
                    return Err(NOACTIVEKEY);
                }
                let request = Session::other_request(&other, h)?;
                let Some(touch) = touch_step(h, screen, serial, request, TOUCH) else {
                    return Ok(());
                };
                opener = Some(touch);
            }
        }
    }
    // P3: the other file opened with this PC's password, else A: the
    // other file's (S-NEWPASS-OTHER); each wrong one counts.
    let open = |password: Option<&str>| {
        phase(h, screen, serial, |a| {
            if password.is_some() && Instant::now() < a.retry {
                return Ok(Err(RETRY_WAIT));
            }
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            match s.adopt_open_with(&r, &other, password, opener.as_ref()) {
                Ok(opened) => {
                    a.failed = 0;
                    Ok(Ok(opened))
                }
                Err(e) if e == crypto::AUTH_ERROR => {
                    if password.is_some() {
                        a.failed_attempt();
                    }
                    Ok(Err(e))
                }
                Err(e) => Err(e),
            }
        })
    };
    let mut typed: Option<Zeroizing<String>> = None;
    let mut opened = match open(None)? {
        None => return Ok(()),
        Some(Ok(opened)) => opened,
        // The merge's other file did not open with the unlock's touch and
        // password: nothing is written, it is Refused{"위조된 연결"} and
        // not tried again while the app runs (spec §5.8, S6-2 #5).
        Some(Err(_)) if quiet => {
            return phase(h, screen, serial, |a| {
                let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
                s.merge_failed(&other);
                a.sync_badge = s.badge();
                let text = fill(N_REFUSED, &[&tr(vault::FORGED_LINK)]);
                let line = joined(&[text.as_str(), a.status.as_str()]);
                a.set_status(&line, TONE_DANGER);
                Ok(())
            })
            .map(|_| ());
        }
        Some(Err(_)) => {
            let mut note: Option<&str> = None;
            loop {
                let text = match note {
                    None => tr(NEWPASS_OTHER).to_owned(),
                    Some(e) => format!("{}\n\n{}", tr(e), tr(NEWPASS_OTHER)),
                };
                let buttons = [OK_BUTTON, CANCEL_BUTTON];
                let InputAnswer::Password(given) =
                    ask_input(h, InputKind::Password, &text, &buttons)
                else {
                    return Ok(());
                };
                match open(Some(&given))? {
                    None => return Ok(()),
                    Some(Ok(opened)) => {
                        typed = Some(given);
                        break opened;
                    }
                    Some(Err(e)) => note = Some(e),
                }
            }
        }
    };
    let same_password = typed.is_none();
    // [뒤로] in the preview of a fork with both options (spec §9.2 adopt
    // step 8): back to the option choice, in the same flow.
    let back = fork_options && check.keys.take_other_offered && check.keys.both;
    let (plan, preview, names, own) = loop {
        // P3: the preview, which judges the gate against exactly this file;
        // a wrong code may be typed again (the file is opened again for it).
        let plan = loop {
            let planned = phase(h, screen, serial, |a| {
                let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                Ok(s.adopt_preview_with(&r, &other, opened, &check, pass.clone(), option))
            })?;
            match planned {
                None => return Ok(()),
                Some(Ok(plan)) => break plan,
                Some(Err(e)) if e == vault::GATE_CODE_WRONG => {
                    match ask_gate(h, GateKind::G1, &[], None, epoch, Some(e)) {
                        Some(GateAnswer::Code(code)) => {
                            pass = GatePass::G1Passed { code, epoch, tag }
                        }
                        _ => return Ok(()),
                    }
                    opened = match open(typed.as_deref().map(String::as_str))? {
                        Some(Ok(opened)) => opened,
                        Some(Err(e)) => return Err(e),
                        None => return Ok(()),
                    };
                }
                Some(Err(e)) => return Err(e),
            }
        };
        // A: the preview, then the confirmations the plan needs.
        let preview = plan.preview().clone();
        // The keys the result would suspend, as this PC names them (spec
        // §7.15a): its own numbers, the other file's for a key new to it;
        // and S-FORK-HINT, from this PC's own records, only now that the
        // gate passed and only when it recommends the option not chosen.
        let names = phase(h, screen, serial, |a| {
            let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
            let names = preview
                .suspend_keys
                .iter()
                .zip(&preview.suspend)
                .map(|(c, n)| s.named(&other, c).unwrap_or((*n, true)))
                .collect::<Vec<(u8, bool)>>();
            let hint = (fork_options
                && option == vault::ForkOption::Both
                && check.keys.take_other_offered)
                .then(|| s.fork_hint(&other))
                .flatten();
            Ok((names, hint))
        })?;
        let Some((names, hint)) = names else {
            return Ok(());
        };
        let mut text = preview_text(&preview, same_password);
        if !names.is_empty() {
            let line = fill(PREVIEW_SUSPEND, &[&named_list(&names)]);
            text = format!("{text}\r\n\r\n{line}");
        }
        if preview.password_only {
            text = format!("{text}\r\n\r\n{}", tr(PREVIEW_PWONLY));
        }
        if let Some(n) = hint {
            text = format!("{text}\r\n\r\n{}", fill(FORK_HINT, &[&n]));
        }
        if quiet {
            break (plan, preview, names, false);
        }
        let check_box = preview
            .own_pass
            .map(|on| (ADOPT_OWN_PASS, OWN_PASS_LABEL, on));
        let kind = InputKind::Preview { check: check_box };
        let mut buttons = vec![super::ACCEPT_BUTTON];
        if back {
            buttons.push(DialogButton {
                id: PREVIEW_BACK,
                label: PREVIEW_BACK_LABEL,
                role: Role::Switch,
            });
        }
        buttons.push(CANCEL_BUTTON);
        match ask_input(h, kind, &text, &buttons) {
            InputAnswer::Accept { checked } => break (plan, preview, names, checked),
            InputAnswer::Switch(PREVIEW_BACK) => {}
            _ => return Ok(()),
        }
        // [뒤로]: the option again; a passed G1 covers the other option too.
        drop(plan);
        let Some(chosen) = ask_fork(h, &check) else {
            return Ok(());
        };
        pass = match (gate_of(chosen), pass) {
            (None, _) => GatePass::none(&check),
            (Some(_), passed @ GatePass::G1Passed { .. }) if option != chosen => passed,
            (Some(_), passed) if option == chosen => passed,
            (Some(kind), _) => match ask_gate(h, kind, &choices, opened_with, epoch, None) {
                Some(GateAnswer::Pick(pick)) => GatePass::G2Passed { pick, epoch, tag },
                Some(GateAnswer::Code(code)) => GatePass::G1Passed { code, epoch, tag },
                None => return Ok(()),
            },
        };
        option = chosen;
        opened = match open(typed.as_deref().map(String::as_str))? {
            Some(Ok(opened)) => opened,
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        };
    };
    if option == vault::ForkOption::TakeOther && !check.keys.readmit.is_empty() {
        let back = Session::numbers_in(&other, &check.keys.readmit);
        if !ask(h, &fill(FORK_READMIT, &[&listed(&back)])) {
            return Ok(());
        }
    }
    if preview.password_only && !ask(h, ADOPT_PWONLY) {
        return Ok(());
    }
    // Key-file sync turned on here (S-KEYSYNC-ON, under the transport
    // precondition) or left (S-KEYSYNC-OFF-JOIN), spec §7.16.
    let keysync_on = preview.keysync_on;
    if keysync_on {
        transport_reported()?;
        if !ask(h, KEYSYNC_ON_TEXT) {
            return Ok(());
        }
    }
    if let Some(deletes) = preview.keysync_off {
        let middle = if deletes {
            OFF_JOIN_DELETES
        } else {
            OFF_JOIN_KEEPS
        };
        let text = [OFF_JOIN, middle, OFF_JOIN_USB].map(tr).join(" ");
        let go = DialogButton {
            id: 1,
            label: TOFU_OK_LABEL,
            role: Role::Accept,
        };
        let kind = InputKind::Preview { check: None };
        if !matches!(
            ask_input(h, kind, &text, &[go, CANCEL_BUTTON]),
            InputAnswer::Accept { .. }
        ) {
            return Ok(());
        }
    }
    if preview.both_passwords && !ask(h, ADOPT_BOTHPASS) {
        return Ok(());
    }
    // A: S-SUSPEND (its Cancel reads [취소]: the touch is behind), and
    // C: the keys the user touches as well.
    let mut consent = vault::Consent::default();
    let mut extra: Vec<Touch> = Vec::new();
    if !preview.suspend.is_empty() {
        let keys = keys.unwrap_or(KeysOverview {
            pin: false,
            rows: Vec::new(),
            full: Vec::new(),
        });
        // A key new to this PC has no seed here: only keys this PC knows
        // can be touched as well (with its own seeds, as the union takes
        // them), so the button is offered only when every named key is one.
        let known = names.iter().all(|(_, new)| !new);
        let own: Vec<u8> = names.iter().map(|(n, _)| *n).collect();
        match ask_suspend_named(h, &keys, &names, &[], true, known) {
            Suspend::Continue => consent.suspend = preview.suspend.clone(),
            Suspend::Back => return Ok(()),
            Suspend::TouchToo => {
                for n in &own {
                    r = match renewed(h, &t, r, TOUCH_RESERVE)? {
                        Some(r) => r,
                        None => return Ok(()),
                    };
                    let request = phase(h, screen, serial, |a| {
                        let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                        s.key_request(&[*n], h)
                    })?;
                    let Some(request) = request else {
                        return Ok(());
                    };
                    let text = fill(EXTRA_TOUCH, &[n]);
                    let Some(touch) = touch_step(h, screen, serial, request, &text) else {
                        return Ok(());
                    };
                    extra.push(touch);
                }
            }
        }
    }
    // P3: the write, with a Reauth that still covers it.
    let Some(r) = renewed(h, &t, r, WRITE_RESERVE)? else {
        return Ok(());
    };
    let acks = vault::Acks {
        password_only: preview.password_only,
        union_password: if own {
            vault::UnionPassword::Own
        } else {
            vault::UnionPassword::Other
        },
        both_passwords: preview.both_passwords,
        fork_option: option,
        keysync_on,
    };
    let written = phase(h, screen, serial, |a| {
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        let result = s.adopt(r, plan, extra, acks, consent, false);
        let notices: Vec<(Zeroizing<String>, isize)> =
            s.take_key_notices().iter().map(key_line).collect();
        let badge = s.badge();
        let adopted = match result {
            Ok(adopted) => adopted,
            Err(e) if e == vault::KEY_DAMAGED => {
                a.show(Screen::Vault);
                a.build();
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        let pass = match adopted.password {
            vault::PassInForce::Own => ADOPT_PASS_OWN,
            vault::PassInForce::Other => ADOPT_PASS_OTHER,
        };
        if adopted.gap_kept {
            a.error(vault::GAP_CHANGED);
            a.set_status(&joined(&[vault::GAP_CHANGED, pass]), TONE_DANGER);
            return Ok(false);
        }
        let code = fill(ADOPT_CODE, &[&adopted.code.show(adopted.state.epoch)]);
        let suspended = (!adopted.suspended.is_empty())
            .then(|| fill(ADOPT_SUSPENDED, &[&listed(&adopted.suspended)]));
        // S-ADOPT-RENUMBER and S-ADOPT-DROPPED-UV (spec §9.2 adopt step 3),
        // in the danger tone: the physical keys' labels must change.
        let mut changed = adopted_lines(&adopted.renumbered, &adopted.dropped_uv);
        // S-SUSPENDED-NEAR after an install that copies another site's
        // suspension (spec §5.2 step 10).
        changed.extend(near_lines(s));
        let mut lines: Vec<&str> = changed.iter().map(String::as_str).collect();
        // S-MERGED for the kind-9 merge, with the key code in it; at login
        // the accept's line with it, and no line about the password (the
        // status box holds three lines; the unlock's stay, below).
        let shown = adopted.code.show(adopted.state.epoch);
        let merged = fill(MERGED, &[&shown]);
        let accepted = fill(ACCEPTED_AT_LOGIN, &[&shown]);
        match (at_login, removal) {
            (true, true) => lines.push(merged.as_str()),
            (true, false) => lines.push(accepted.as_str()),
            (false, true) => lines.extend([merged.as_str(), pass]),
            (false, false) => lines.extend([code.as_str(), pass]),
        }
        if adopted.vault_pending {
            lines.push(vault::VPENDING);
        }
        lines.extend(suspended.as_deref());
        lines.extend(notices.iter().map(|(text, _)| text.as_str()));
        // The landed adopt also ends a dropped one's [다시 하기].
        let _ = s.take_redo();
        a.sync_badge = badge;
        a.adopt_source = None;
        a.show(Screen::Vault);
        a.status = if at_login {
            // Still the unlock's status: its warnings stay first.
            let danger = a.status_tone == TONE_DANGER;
            at_login_status(&a.status, danger, &lines)
        } else {
            joined(&lines)
        };
        if !changed.is_empty() || notices.iter().any(|(_, tone)| *tone == TONE_DANGER) {
            a.status_tone = TONE_DANGER;
        }
        a.build();
        Ok(true)
    });
    match written {
        Ok(Some(true)) => {
            backup_after(h, BACKUP_QUESTION);
            prune_after(h);
            review_after(h);
        }
        Err(e) if e == vault::KEY_DAMAGED => save_damaged_key(h),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    Ok(())
}

// Key-file sync (spec §7.8-§7.19, §9.1-§9.3; stage 6).

#[cfg(test)]
thread_local! {
    /// The key-file sync view a preview shows on the Keys screen.
    pub static KS_SHOWN: std::cell::RefCell<Option<vault::KeySyncView>> = const { std::cell::RefCell::new(None) };
}
/// The key-file sync view the Keys screen shows (spec §9.1, §2.29): the
/// session's, or a preview's in a test.
pub(crate) fn ks_view(s: Option<&Session>) -> Option<vault::KeySyncView> {
    #[cfg(test)]
    if let Some(v) = KS_SHOWN.with(|k| *k.borrow()) {
        return Some(v);
    }
    s.and_then(Session::key_sync_view)
}
/// The Keys screen's note when the key file syncs (spec §2.29): the other
/// PCs' changes come from the server, never by USB over this key file.
pub const KEYS_NOTE_SYNCED: &str = "이 열쇠 파일은 서버로 동기화됩니다. 다른 PC에서 비밀번호나 열쇠를 바꾸면 아래 열쇠 파일 줄에 [받기…]가 나타납니다. USB로 가져온 열쇠 파일을 이 PC의 열쇠 파일 위에 덮어쓰지 마세요.";
/// The Keys screen's key-file sync line (spec §9.1, §2.29): where this
/// vault's key file lives, in one line, beside the one switch.
pub const KS_OFF: &str = "열쇠 파일: 이 PC에만 보관 (다른 PC에는 USB로)";
pub const KS_SAME: &str = "열쇠 파일: 서버로 동기화 (실험)";
pub const KS_GONE: &str = "열쇠 파일: 서버로 동기화 (실험) · 서버에 없음";
pub const KS_READY: &str = "서버에 새 열쇠 파일 있음 (수정 {e})";
pub const KS_GATE: &str = "서버에 확인할 열쇠 변경 있음 (수정 {e})";
pub const KS_FORK: &str = "서버의 열쇠 파일과 갈라짐 (수정 {e}) · [받기…]로 합치세요";
/// A stored pending gate whose candidate is no longer the server's top
/// (spec §7.15a; [받지 않기…] still ends it).
pub const KS_GATE_GONE: &str = "확인을 기다리는 열쇠 변경(수정 {e})이 서버에 없습니다 · 받을 수 없으면 [받지 않기…]를 누르세요";
pub const KS_DEL_PENDING: &str = "서버의 열쇠 파일 삭제: 대기 중 (goyo-sync가 처리합니다)";
pub const KS_DEL_NOVIEW: &str = "서버의 열쇠 파일 삭제: 대기 중 (goyo-sync가 서버를 확인하면, 이 PC가 잠금 해제되어 있을 때 요청합니다)";
pub const KS_DEL_NOKEYS: &str = "서버의 열쇠 파일 삭제: 이 PC의 서버 연결이 이 금고의 열쇠 파일 요청을 받지 않습니다(--key-sync 목록에 없음). 다른 PC에서 이미 끄고 지웠다면 할 일이 없습니다.";
pub const KS_DEL_ANSWERED: &str = "서버의 열쇠 파일 삭제: 서버가 삭제했다고 응답함 (기록 {seq})";
pub const KEYSYNC_ON_BUTTON: &str = "열쇠 파일 동기화 켜기…";
pub const KEYSYNC_OFF_BUTTON: &str = "열쇠 파일 동기화 끄기…";
pub const REUPLOAD_BUTTON: &str = "열쇠 파일 다시 올리기";
pub const DROP_BUTTON: &str = "받지 않기…";
/// [다른 PC가 없어 이 PC 상태로 올리기…] (`GATE_SUPERSEDE`, spec §7.15a).
pub const SUPERSEDE_BUTTON: &str = "다른 PC가 없어 이 PC 상태로 올리기…";
/// S-GATE-SUPERSEDE (spec §7.15a), danger, default no.
pub const SUPERSEDE_ASK: &str = "서버의 새 열쇠 파일(다른 PC에서 바꾼 것)을 받지 않고, 이 PC의 열쇠 파일을 그보다 높은 수정 번호로 다시 올립니다. 그 PC를 더 쓸 수 없고 그 변경을 받은 PC가 하나도 없을 때만 하세요. 그 변경(예: 그 PC에서 추가한 보안 키)은 사라지니 필요하면 다시 하세요.";
/// S-GATE-SUPERSEDE-ON (spec §7.15a, round 4 finding 7): a GOYOKH01 PC.
pub const SUPERSEDE_ON: &str = "이 PC는 지금 열쇠 파일을 이 PC에만 두고 있습니다. 다시 올리면 이 PC에서도 열쇠 파일 동기화가 켜집니다. 원하지 않으면 끝난 뒤 '열쇠 파일 동기화 끄기'를 하세요(데이터 키를 바꿉니다).";
/// The supersede's status (spec §9.2).
pub const SUPERSEDED: &str = "다른 PC의 변경을 받지 않고 이 PC의 열쇠 파일을 다시 올렸습니다.";
/// S-ROLLOUT, per change (spec §7.18).
/// The Keys screen's list leads with the whole text, worded by the gate
/// the change needs on the other PCs: a removal (pick, or the code on a PC
/// that never knew a removed key; with the frozen PC's way out), added
/// keys or a re-seed (the code), key-file sync on, a re-upload or a
/// supersede (the code only on a PC that kept its key file to itself), a
/// password change or a pairing (nothing). The unlock's status says the
/// gist in one line (the box holds three; S-ONEKEY may take two).
pub const ROLLOUT_REMOVE: &str = "다른 PC들이 아직 이 제거를 받지 않았을 수 있습니다. 각 PC는 열 때 이 PC에서 뺀 보안 키를 모두 고르거나, 뺀 키를 모르는 PC라면 이 PC의 열쇠 확인 코드 {code}를 입력해 받습니다. 응답이 없는 PC는 서버가 이 변경을 숨기고 있을 수 있으니 그 PC에서 '잃어버린 키 제거'를 하세요. 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.";
pub const ROLLOUT_CODE: &str = "다른 PC들이 아직 이 열쇠 변경을 받지 않았을 수 있습니다. 각 PC는 열 때 이 PC의 열쇠 확인 코드 {code}를 입력해 받습니다. 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.";
pub const ROLLOUT_MAYBE: &str = "다른 PC들이 아직 이 열쇠 변경을 받지 않았을 수 있습니다. 각 PC는 다음 잠금 해제 때 받고, 열쇠 파일을 그 PC에만 두던 PC는 이 PC의 열쇠 확인 코드 {code}를 입력합니다. 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.";
pub const ROLLOUT_PLAIN: &str = "다른 PC들이 아직 이 열쇠 변경을 받지 않았을 수 있습니다. 각 PC는 다음 잠금 해제 때 받습니다(비밀번호를 바꿨다면 새 비밀번호로 여세요). 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.";
/// S-ROLLOUT's gist in the unlock's status: a removal (danger), any other
/// change (muted).
pub const ROLLOUT_REMOVE_SHORT: &str = "다른 PC들이 이 제거를 받았는지 확인 전입니다. 받지 못하는 PC에서는 '잃어버린 키 제거'를 하세요.";
pub const ROLLOUT_SHORT: &str =
    "다른 PC들이 이 열쇠 변경을 받았는지 확인 전입니다. 할 일은 '열쇠 관리'에 있습니다.";
/// [모든 PC 확인 완료] (`KEY_ROLLOUT_DONE`) and its line on the Keys screen.
pub const ROLLOUT_BUTTON: &str = "모든 PC 확인 완료";
pub const KS_ROLLOUT: &str = "다른 PC들이 이 변경을 받았는지 확인 전";
pub const ROLLOUT_DONE: &str = "모든 PC가 이 열쇠 변경을 받은 것으로 기록했습니다.";
/// S-MERGED (spec §5.8, §9.3): the kind-9 merge, with the key code.
pub const MERGED: &str = "두 PC에서 따로 한 보안 키 제거를 합쳤습니다. 열쇠 확인 코드 {code}";
/// S-KEYSYNC-ON (spec §7.9 items 1-10).
pub const KEYSYNC_ON_TEXT: &str = "열쇠 파일 동기화를 켜면:\n1. 서버, 또는 동기화 SSH 키를 가진 사람이 열쇠 파일을 갖게 됩니다. 남는 장벽은 비밀번호와 보안 키(+PIN)뿐입니다.\n2. 올린 열쇠 파일은 그때 서버에 접근한 사람이 영원히 보관할 수 있습니다. 키 제거나 비밀번호 변경은 그 뒤에 저장하는 것만 보호합니다. 키를 잃었고 비밀번호가 알려졌을 수 있다면 비밀 자체를 바꾸세요.\n3. 해킹된 서버는 열쇠 변경을 어느 PC에 숨길 수 있습니다. 모든 PC가 받아야(잃어버린 키를 고르거나 코드를 입력해야) 열쇠 변경이 끝납니다. 키를 잃으면 모든 PC에서 '잃어버린 키 제거'를 하세요.\n4. 서버 사본은 백업이 아닙니다. USB 열쇠 백업과 2개 이상의 키가 여전히 필요하고, 복구 코드는 없습니다.\n5. PIN이 필수입니다: 6자 이상, 비밀번호와 다르게. 8번 틀리면 키가 잠기고, 초기화한 키로는 이 금고를 열 수 없습니다.\n6. 잃어버린 PC의 authorized_keys 줄은 바로 지우고, 사람마다 서버 계정을 따로 쓰세요.\n7. 휴대폰과 Windows Hello는 쓸 수 없고, USB나 NFC 보안 키만 씁니다.\n8. 더 쓰지 않는 키에서는 이 금고의 등록을 지우세요(제조사 도구, 예: 관리자 권한으로 ykman fido credentials delete; 키의 PIN 필요). FIDO 전체 초기화는 다른 곳에 쓰지 않는 키만 하세요.\n9. 열쇠 파일 사본이 각 PC의 동기화 폴더에 생깁니다.\n10. 열쇠를 바꾸면 다른 PC는 다음 잠금 해제 때 받습니다. 제거는 잃어버린 키를 고르고, 키 추가나 설정 변경은 바꾼 PC에 보이는 코드를 입력합니다. 보안 키를 끄면 열쇠 파일 동기화도 꺼지고, 다른 PC는 다시 USB로 열쇠 파일을 받아야 합니다.\n열쇠 파일 동기화를 켤까요?";
/// [열쇠 파일 다시 올리기] (KeySyncGone, spec §7.11).
pub const REUPLOAD_ASK: &str = "서버에 이 금고의 열쇠 파일이 없습니다. 다른 PC에서 열쇠 파일 동기화를 끈 것이라면 다시 올리지 말고 그 PC의 열쇠 파일을 USB로 받으세요. 아무도 끄지 않았는데 지워진 것이 확실할 때만 다시 올리세요.\n이 PC의 열쇠 파일을 다시 올릴까요?";
pub const KEYSYNC_ON_DONE: &str = "열쇠 파일 동기화를 켰습니다. goyo-sync가 서버에 열쇠 파일을 올립니다. 다른 PC는 다음 잠금 해제 때 이 PC의 열쇠 확인 코드를 입력해야 받습니다.";
pub const REUPLOADED: &str = "열쇠 파일을 다시 올리도록 했습니다. goyo-sync가 서버에 올립니다.";
/// S-KEYSYNC-OFF and its additions (spec §7.16 step 1).
pub const KEYSYNC_OFF_ASK: &str = "열쇠 파일 동기화를 끕니다. 서버에 열쇠 파일 삭제를 요청하고 데이터 키를 바꿉니다. 다른 PC는 동기화를 멈추고 이 열쇠 파일을 USB로 받아야 합니다. 계속할까요?";
pub const KEYSOFF_SYNCED: &str = "이 열쇠 파일은 열쇠 파일 동기화를 씁니다. 보안 키를 끄면 열쇠 파일 동기화도 끄고, 서버에 열쇠 파일 삭제를 요청합니다. 다른 PC는 동기화를 멈추고 이 열쇠 파일을 USB로 받아야 합니다.";
pub const OFF_FORK: &str = "서버에 이 PC가 받지 않은 열쇠 파일(수정 {e})이 있습니다. 다른 PC의 변경일 수도, 위조된 파일일 수도 있습니다. 끄면 그 파일도 서버에서 지워지고, 다른 PC의 변경이라면 그 PC의 변경은 USB로 옮겨야 합니다. 끄기는 그래도 데이터 키를 바꾸므로, 앞으로 저장하는 항목은 서버에 남았던 열쇠 파일로 열리지 않습니다.";
pub const OFF_NOHELPER: &str = "열쇠 파일 동기화를 지원하는 goyo-sync(보안 키 빌드)가 응답하지 않습니다. 끄기는 지금 하지만, 서버의 열쇠 파일은 그 goyo-sync가 실행될 때까지 지워지지 않습니다. 계속할까요?";
pub const OFF_NOHELPER_NOVIEW: &str = "이 PC에 서버 확인 기록이 없어, goyo-sync가 서버를 확인한 뒤 이 PC를 한 번 더 잠금 해제해야 삭제 요청이 나갑니다.";
pub const OFF_NOKEYS: &str = "이 PC의 서버 연결이 이 금고의 열쇠 파일 요청을 받지 않아(서버 강제 명령에 --key-sync=<금고 ID> 없음) 서버의 열쇠 파일을 지울 수 없습니다.
열쇠 파일 동기화를 쓰던 금고에서 서버가 이렇게 답한다면 서버 설정이 바뀌었거나 서버가 해킹되었을 수 있습니다. 끄기는 그래도 데이터 키를 바꾸므로, 앞으로 저장하는 항목은 서버에 남은 열쇠 파일로 열리지 않습니다. 다만 서버 관리자가 이 PC의 줄에 그 설정을 넣거나 data/<id>/k/를 지울 때까지 이 PC의 금고는 서버에 올라가지 않습니다(서버의 열쇠 파일이 다른 상태를 요구합니다). 끌까요?";
/// The off's status (spec §7.16 step 6, S6R2 #22).
pub const OFF_DONE: &str = "열쇠 파일 동기화를 껐습니다.";
pub const OFF_DELETES: &str =
    "서버에 열쇠 파일 삭제를 요청했습니다(해킹된 서버라면 이미 복사했을 수 있습니다).";
pub const OFF_AFTER_VIEW: &str =
    "goyo-sync가 서버를 확인하면 열쇠 파일 삭제를 요청합니다(이 PC를 잠금 해제한 상태에서).";
pub const OFF_NOTHING: &str =
    "서버에는 지울 열쇠 파일이 없습니다(이미 다른 PC에서 껐거나 지워졌습니다).";
pub const OFF_OTHERS: &str = "다른 PC는 동기화를 멈추니 이 열쇠 파일을 USB로 옮겨 '새 열쇠 파일 받기'를 하세요. 더 쓰지 않는 보안 키는 그 키에서 이 금고의 등록을 지우세요(다른 곳에 쓰지 않는 키만 FIDO 초기화).";
pub const OFF_FAILED: &str = "열쇠 파일 동기화를 끄지 못했습니다. 아무것도 바뀌지 않았습니다.";
/// S-KEYSYNC-OFF-JOIN (spec §7.16; S6R2 #22).
pub const OFF_JOIN: &str = "받은 결과는 열쇠 파일 동기화가 꺼진 열쇠 파일입니다.";
pub const OFF_JOIN_DELETES: &str =
    "서버의 열쇠 파일을 지우도록 요청합니다(해킹된 서버라면 이미 복사했을 수 있습니다).";
pub const OFF_JOIN_KEEPS: &str = "서버의 열쇠 파일은 지우지 않습니다. 이미 다른 PC에서 끄고 지웠거나, 서버에 있는 것은 다른 PC가 나중에 정한 설정입니다(이 PC가 전에 쓰던 열쇠 파일이 서버에 남아 있으면 goyo-sync가 서버를 확인한 뒤 지우도록 요청합니다).";
pub const OFF_JOIN_USB: &str = "다른 PC는 이 열쇠 파일을 USB로 받아야 합니다.";
/// S-GATE-DROP (spec §7.15a).
pub const GATE_DROP_ASK: &str = "이 열쇠 변경을 받지 않습니다. 다른 PC에서 실제로 바꾼 것이라면 이 PC는 동기화를 계속 멈춘 채로 남습니다(나중에 USB로 받을 수 있습니다). 위조된 것이 확실할 때만 누르세요. 그 PC를 더 쓸 수 없어서라면 받지 않기 대신 '다른 PC가 없어 이 PC 상태로 올리기'(그 버튼이 있을 때)나 '열쇠 파일 동기화 끄기'를 하세요.";
pub const GATE_DROPPED: &str =
    "이 열쇠 변경을 받지 않았습니다. 서버에 다른 열쇠 파일이 올 때까지 동기화를 멈춥니다.";
/// S-PRUNE (spec §7.19).
pub const PRUNE_ASK: &str = "서버에 이 변경 전 금고 기록(최근 200개)이 남아 있습니다. 빠진 키와 예전 비밀번호를 가진 사람은 그 기록을 열 수 있습니다. 지울까요? 지우면 그 기록으로 되돌릴 수 없고, 해킹된 서버라면 이미 복사해 두었을 수 있습니다. 잃어버린 키와 비밀번호가 함께 노출되었을 수 있다면 금고 안의 비밀 자체를 바꾸세요.";
pub const PRUNE_DONE: &str =
    "서버에 이 변경 전 금고 기록을 지우도록 요청했습니다(goyo-sync가 보냅니다).";
/// The key notices of spec §7.4.
pub const N_KEY_ROLLBACK: &str =
    "서버가 이 금고에서 이미 본 것보다 오래된 열쇠 파일을 보냈습니다. 받지 않았습니다.";
pub const N_REFUSED: &str = "서버의 열쇠 파일을 받지 않고 동기화를 멈췄습니다({reason}). 다른 PC에서 바꾼 것이 맞다면 그 PC의 열쇠 파일을 USB로 가져와 '새 열쇠 파일 받기'로 받으세요. 그런 일이 없었다면 서버가 위조했을 수 있습니다.";
pub const N_BAD_KEY: &str = "받아 둔 서버 열쇠 파일을 읽을 수 없습니다. 무시했습니다.";
pub const N_GATE_PENDING: &str = "다른 PC에서 보안 키 구성이나 설정을 바꾼 열쇠 파일이 서버에 있습니다. 받기 전에 잃어버린 키를 고르거나 다른 PC의 열쇠 확인 코드를 입력해야 합니다('열쇠 관리'의 [받기…]). 그때까지 이 PC는 서버에 아무것도 올리지 않고 받은 사본도 합치지 않습니다. 키를 잃어버렸다면 '잃어버린 키 제거'를 이 PC에서도 하세요.";
pub const N_GONE: &str = "서버에 이 금고의 열쇠 파일이 없습니다(다른 PC에서 열쇠 파일 동기화를 껐거나 서버에서 지움). 다른 PC에서 끈 것이라면 다시 올리지 말고 그 PC의 열쇠 파일을 USB로 받으세요. 아무도 끄지 않았는데 지워진 것이 확실할 때만 '열쇠 관리'에서 '열쇠 파일 다시 올리기'를 누르세요. 그때까지 이 PC는 서버 사본을 합치지도 올리지도 않습니다(변경은 이 PC에 저장됩니다).";
pub const N_READY: &str =
    "다른 PC에서 바꾼 열쇠 파일(수정 {e})이 서버에 있습니다. '열쇠 관리'에서 [받기…]를 누르세요.";
/// What to fix, and that goyo-sync checks again (spec §2.29).
pub const N_NOKEYSYNC: &str = "서버가 이 금고의 열쇠 파일 동기화를 받지 않습니다: 서버 authorized_keys의 이 PC 줄(강제 명령)에 --key-sync=<금고 ID>가 없습니다. goyo-sync 설정의 '강제 명령 줄…'이 만든 줄로 바꾸면 goyo-sync가 2분 안에 다시 확인합니다.";
pub const N_KEYUP_REFUSED: &str = "goyo-sync나 서버가 이 PC의 열쇠 파일을 받지 않았습니다(형식 또는 크기). 그동안 이 PC의 금고는 서버에 올라가지 않습니다. goyo-sync와 서버 스크립트를 같은 버전으로 업데이트하세요. 업데이트한 뒤 goyo-sync가 다시 시작되거나 '지금 동기화'를 누르면 다시 올립니다.";
pub const N_HELPER: &str = "이 금고는 열쇠 파일 동기화를 쓰지만, 최근 10분 동안 열쇠 파일 동기화를 지원하는 goyo-sync(보안 키 빌드)의 응답이 없습니다. 그 goyo-sync를 실행하세요. 그 전에는 열쇠 파일이 오가지 않고, 끈 경우 서버의 열쇠 파일도 지워지지 않습니다.";
/// S-KEYSYNC-OFF-ADMIN (spec §7.16 step 7), once, after the deletion line.
pub const N_ADMIN: &str = "열쇠 파일 동기화를 다시 켜지 않을 거라면, 모든 PC가 이 끄기를 받은 뒤(이 열쇠 파일을 USB로 받거나 그 PC에서 직접 끔) 서버 관리자에게 모든 PC의 강제 명령에서 이 금고 ID를 --key-sync 목록에서 빼 달라고 하세요. 빼지 않으면 그 줄의 동기화 키를 훔친 사람이 이 금고의 업로드를 막을 수 있습니다.";
/// KeyFork-SK (spec §7.4), in place of the default build's KeyFork.
pub const N_KEYFORK_SK: &str = "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라졌습니다. 동기화를 멈췄습니다. 한 PC에서 '열쇠 관리 › 새 열쇠 파일 받기'로 다른 PC의 열쇠 파일을 받으세요. 보안 키 구성이 다르면 잃어버린 키를 고르거나 다른 PC의 열쇠 확인 코드를 입력해야 합니다. 키를 잃어버렸다면 이 PC에서도 '잃어버린 키 제거'를 하세요. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.";
/// KeyFork-SK-AUTO (spec §7.4, S6-2 #5): the kind-9 merge joins it at the
/// next unlock with no question; conditional, with the forgery sentence.
pub const N_KEYFORK_AUTO: &str = "두 PC에서 따로 한 보안 키 제거라면 다음 잠금 해제 때 이 PC의 보안 키와 비밀번호로 열어 합칩니다. 열리지 않으면 합치지 않고 알립니다. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.";
/// KeyFork-SK with KeyFork-SK-MERGE (spec §7.4, S6-1 #5), shortened to
/// the status box's three lines: the fork, the merge with [받기…], the
/// way for any other change and the forgery sentence.
pub const N_KEYFORK_MERGE: &str = "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라졌습니다. 동기화를 멈췄습니다. 두 PC에서 따로 보안 키를 제거한 것이라면 '열쇠 관리'의 [받기…]로 합칠 수 있습니다(다른 보안 키나 다른 비밀번호가 필요합니다). 다른 변경이라면 한 PC에서 '새 열쇠 파일 받기'로 받으세요. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.";

/// The status line of a key notice of key-file sync and whether it is a
/// danger line (spec §7.4); None for the notices main.rs words.
pub fn key_sync_line(notice: &vault::SyncNotice) -> Option<(Zeroizing<String>, bool)> {
    use vault::SyncNotice as N;
    Some(match notice {
        N::KeyFork => (line(N_KEYFORK_SK), true),
        N::KeyForkMerge { auto: true } => (line(N_KEYFORK_AUTO), true),
        N::KeyForkMerge { auto: false } => (line(N_KEYFORK_MERGE), true),
        N::KeyRollback => (line(N_KEY_ROLLBACK), true),
        N::KeyFileRefused(reason) => (Zeroizing::new(fill(N_REFUSED, &[&tr(reason)])), true),
        N::BadKeyIncoming => (line(N_BAD_KEY), true),
        N::GatePending => (line(N_GATE_PENDING), true),
        N::KeySyncGone => (line(N_GONE), true),
        N::KeyFileReady { epoch } => (Zeroizing::new(fill(N_READY, &[epoch])), true),
        N::NoKeySync => (line(N_NOKEYSYNC), true),
        N::KeyUpRefused => (line(N_KEYUP_REFUSED), true),
        N::KeySyncHelper => (line(N_HELPER), true),
        N::KeySyncDeleted { seq, admin } => {
            let mut text = fill(KS_DEL_ANSWERED, &[seq]);
            if *admin {
                text = format!("{text}\r\n{}", tr(N_ADMIN));
            }
            (Zeroizing::new(text), false)
        }
        _ => return None,
    })
}

/// The Keys screen's key-file sync line and its button (spec §9.1), for a
/// vault that syncs: the state, the waiting change or the deletion line,
/// and [받기…] with [받지 않기…], [열쇠 파일 다시 올리기], or [끄기…] /
/// [켜기…].
pub fn key_sync_text(v: &vault::KeySyncView) -> (String, Vec<(i32, &'static str)>) {
    let mut text: Vec<String> = Vec::new();
    let mut buttons: Vec<(i32, &'static str)> = Vec::new();
    match v.waiting {
        Some(w) if matches!(w.class, vault::KeyClass::Successor { .. }) => {
            text.push(fill(
                if w.pending_gate { KS_GATE } else { KS_READY },
                &[&w.epoch],
            ));
            buttons.push((KEY_ACCEPT, ACCEPT_BUTTON));
            if w.pending_gate {
                buttons.push((GATE_DROP, DROP_BUTTON));
            }
        }
        // A fork is joined by the same flow: fork options 1 and 2 behind
        // their gate, a union uploaded on the server's record (§7.15).
        Some(w) if w.class == vault::KeyClass::KeyFork => {
            text.push(fill(KS_FORK, &[&w.epoch]));
            buttons.push((KEY_ACCEPT, ACCEPT_BUTTON));
        }
        Some(w) => text.push(fill(KS_FORK, &[&w.epoch])),
        None => {}
    }
    // A pending gate whose candidate left the top (a server restored from a
    // backup, an admin's rm -r k/, a PC gone): [받지 않기…] still ends it.
    let stale_gate = v
        .stale_gate
        .filter(|_| !buttons.iter().any(|(id, _)| *id == GATE_DROP));
    if let Some(epoch) = stale_gate {
        text.push(fill(KS_GATE_GONE, &[&epoch]));
    }
    if text.is_empty() {
        text.push(
            tr(if !v.on {
                KS_OFF
            } else if v.gone {
                KS_GONE
            } else {
                KS_SAME
            })
            .to_owned(),
        );
    }
    match v.deletion {
        Some(vault::Deletion::Pending) => text.push(tr(KS_DEL_PENDING).to_owned()),
        Some(vault::Deletion::PendingNoView) => text.push(tr(KS_DEL_NOVIEW).to_owned()),
        Some(vault::Deletion::NoKeyOps) => text.push(tr(KS_DEL_NOKEYS).to_owned()),
        Some(vault::Deletion::Answered(seq)) => text.push(fill(KS_DEL_ANSWERED, &[&seq])),
        None => {}
    }
    if buttons.is_empty() {
        buttons.push(if v.on && v.gone {
            (KEY_REUPLOAD, REUPLOAD_BUTTON)
        } else if v.on {
            (KEYSYNC_OFF, KEYSYNC_OFF_BUTTON)
        } else {
            (KEYSYNC_ON, KEYSYNC_ON_BUTTON)
        });
    }
    if stale_gate.is_some() {
        buttons.push((GATE_DROP, DROP_BUTTON));
    }
    // The rollout reminder (spec §7.18): [모든 PC 확인 완료].
    if v.rollout {
        text.push(tr(KS_ROLLOUT).to_owned());
        buttons.push((KEY_ROLLOUT_DONE, ROLLOUT_BUTTON));
    }
    (text.join("\r\n"), buttons)
}
/// The width of a button of the key-file sync row (spec §9.1), when it
/// shares the row with `n - 1` others.
fn sync_button_width(id: i32, n: usize) -> i32 {
    match id {
        _ if n == 1 => 248,
        KEY_ROLLOUT_DONE => 176,
        KEYSYNC_ON | KEYSYNC_OFF | KEY_REUPLOAD => 216,
        _ => 120,
    }
}

/// Whether [받기…] takes the server's file of this class: a successor, or
/// a fork it joins (spec §7.15); a Refused, Stale or Equal file is not.
pub fn server_takes(class: Option<vault::KeyClass>) -> bool {
    matches!(
        class,
        Some(vault::KeyClass::Successor { .. } | vault::KeyClass::KeyFork)
    )
}

/// The transport precondition before any ceremony (spec §7.9, S6-1 #6):
/// this Windows' WebAuthn API reports the transport of an assertion
/// (version 4 assertions, API 6 and later).
fn transport_reported() -> crypto::Result<()> {
    let api = authenticator().map_err(FidoError::text)?.api_version();
    if api < 6 {
        return Err(vault::KEYSYNC_NOTRANSPORT);
    }
    Ok(())
}

/// [열쇠 파일 동기화 켜기…] and [열쇠 파일 다시 올리기] (spec §7.9,
/// §9.2): §7.9's preconditions and the transport before any question;
/// S-KEYSYNC-ON (or the re-upload's warning) and the gate; one touch of an
/// active key; `rekey(KeySyncOn)`.
fn keysync_on_flow(h: Hwnd, id: i32) -> crypto::Result<()> {
    let change = vault::Change::KeySyncOn;
    let (t, ()) = take_with(h, id, &change, |a, t| {
        t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        transport_reported()?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        s.keysync_ready()
    })?;
    let question = if id == KEY_REUPLOAD {
        REUPLOAD_ASK
    } else {
        KEYSYNC_ON_TEXT
    };
    if !ask(h, question) || !gate_asked(h, &t) {
        return Ok(());
    }
    let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
    let Some(touch) = touch_of(h, &t, &keys.active(), TOUCH)? else {
        return Ok(());
    };
    let Some(r) = reauth(h, &t, Some(&touch))? else {
        return Ok(());
    };
    drop(touch);
    let reupload = id == KEY_REUPLOAD;
    let done = move |_: &Session| {
        Done::of(vec![
            tr(if reupload {
                REUPLOADED
            } else {
                KEYSYNC_ON_DONE
            })
            .to_owned(),
        ])
    };
    if let Some(told) = write(
        h,
        &t,
        r,
        Vec::new(),
        change,
        vault::Consent::default(),
        &done,
    )? && !reupload
    {
        backup_after(h, BACKUP_QUESTION);
        tell_after(h, &told);
    }
    Ok(())
}
/// The questions an off of key-file sync asks first (spec §7.16 step 1),
/// after `first` (S-KEYSYNC-OFF, or S-OFF with its paragraph): the fork
/// warning, then S-KEYSYNC-OFF-NOKEYS (default yes) or
/// S-KEYSYNC-OFF-NOHELPER (default no). True to go on.
fn off_asked(h: Hwnd, first: &str, view: &vault::KeySyncView, request: vault::OffRequest) -> bool {
    let mut text = tr(first).to_owned();
    if let Some(w) = view.waiting {
        text = format!("{text}\n\n{}", fill(OFF_FORK, &[&w.epoch]));
    }
    if !ask(h, &text) {
        return false;
    }
    if view.no_key_ops {
        let yes = DialogButton {
            id: 1,
            label: YES,
            role: Role::Accept,
        };
        let no = DialogButton {
            id: 2,
            label: NO,
            role: Role::Cancel,
        };
        let kind = InputKind::Preview { check: None };
        return matches!(
            ask_input(h, kind, OFF_NOKEYS, &[yes, no]),
            InputAnswer::Accept { .. }
        );
    }
    if !view.helper {
        let mut text = tr(OFF_NOHELPER).to_owned();
        if request == vault::OffRequest::AfterView {
            text = format!("{text}\n{}", tr(OFF_NOHELPER_NOVIEW));
        }
        return ask(h, &text);
    }
    true
}
/// The off's status (spec §7.16 step 6): its request in the wording of its
/// `ks′` as one line; the other PCs' step follows in the dialog after the
/// backup.
fn off_line(request: vault::OffRequest) -> String {
    let said = match request {
        vault::OffRequest::Deletes => OFF_DELETES,
        vault::OffRequest::AfterView => OFF_AFTER_VIEW,
        vault::OffRequest::Nothing => OFF_NOTHING,
    };
    format!("{} {}", tr(OFF_DONE), tr(said))
}
/// [열쇠 파일 동기화 끄기…] (spec §7.16, §9.2): the questions of step 1,
/// the gate, P1's `ks′` snapshot (kept across a rekey that wrote
/// nothing), one touch, `rekey(KeySyncOff)`, which deletes `kreq` and
/// `kview` before it rotates.
fn keysync_off_flow(h: Hwnd) -> crypto::Result<()> {
    let change = vault::Change::KeySyncOff;
    let (t, (view, request)) = take_with(h, KEYSYNC_OFF, &change, |a, t| {
        t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        authenticator().map_err(FidoError::text)?;
        let s = a.session.as_mut().ok_or("먼저 금고를 열어주세요.")?;
        let view = s.key_sync_view().ok_or(vault::NOT_PLANNED)?;
        Ok((view, s.off_request()))
    })?;
    if !off_asked(h, KEYSYNC_OFF_ASK, &view, request) || !gate_asked(h, &t) {
        return Ok(());
    }
    let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
    let Some(touch) = touch_of(h, &t, &keys.active(), TOUCH)? else {
        return Ok(());
    };
    let Some(r) = reauth(h, &t, Some(&touch))? else {
        return Ok(());
    };
    drop(touch);
    let done = move |_: &Session| Done::of(vec![off_line(request)]).more(tr(OFF_OTHERS).to_owned());
    match write(
        h,
        &t,
        r,
        Vec::new(),
        change,
        vault::Consent::default(),
        &done,
    ) {
        Ok(Some(told)) => {
            backup_after(h, BACKUP_QUESTION);
            tell_after(h, &told);
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) if [GAP_KEPT, vault::GAP_CHANGED, vault::KEY_DAMAGED].contains(&e) => Err(e),
        Err(e) => {
            fail(&[e, OFF_FAILED]);
            Ok(())
        }
    }
}
/// [받지 않기…] (spec §7.15a): S-GATE-DROP (danger, default no), then the
/// candidate is remembered as dropped and never offered again.
fn gate_drop_flow(h: Hwnd) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(GATE_DROP)?;
        a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        a.flow = Some(GATE_DROP);
        Ok(a.serial)
    });
    drain_pending(h);
    let serial = p1?;
    if !ask(h, GATE_DROP_ASK) {
        return Ok(());
    }
    phase(h, Screen::Keys, serial, |a| {
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        s.drop_gate()?;
        a.sync_badge = s.badge();
        a.status = line(GATE_DROPPED);
        a.status_tone = TONE_DANGER;
        a.build();
        Ok(())
    })
    .map(|_| ())
}
/// [다른 PC가 없어 이 PC 상태로 올리기…] (spec §7.15a, §9.2): the
/// candidate named at P1; on a GOYOKH01 session the transport first, then
/// S-KEYSYNC-ON; S-GATE-SUPERSEDE (danger, default no; with
/// S-GATE-SUPERSEDE-ON there); one touch of an active key;
/// `rekey(Supersede)`, which no rotation gate holds.
fn supersede_flow(h: Hwnd) -> crypto::Result<()> {
    // P1 names the candidate; the change is checked against it at R0.
    let named = APP.with(|cell| -> crypto::Result<_> {
        let b = cell.try_borrow().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_ref().ok_or("화면이 닫혔습니다.")?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let (file, _) = s.server_key_file().ok_or(vault::NO_CANDIDATE)?;
        let state = file.header().ok_or(vault::NO_CANDIDATE)?.state();
        let on = s.key_magic() != Some(vault::keyfile::Magic::Ks01);
        Ok((state, on))
    })?;
    let (state, turns_on) = named;
    let change = vault::Change::Supersede {
        epoch: state.epoch,
        tag: state.tag,
    };
    let (t, ()) = take_with(h, GATE_SUPERSEDE, &change, |a, t| {
        t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
        if turns_on {
            transport_reported()?;
        } else {
            authenticator().map_err(FidoError::text)?;
        }
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let offered = s
            .key_sync_view()
            .and_then(|v| v.waiting)
            .is_some_and(|w| w.supersede && w.epoch == state.epoch);
        if offered {
            Ok(())
        } else {
            Err(vault::NOT_SUPERSEDABLE)
        }
    })?;
    if turns_on && !ask(h, KEYSYNC_ON_TEXT) {
        return Ok(());
    }
    let question = if turns_on {
        format!("{}\n\n{}", tr(SUPERSEDE_ASK), tr(SUPERSEDE_ON))
    } else {
        tr(SUPERSEDE_ASK).to_owned()
    };
    if !ask(h, &question) {
        return Ok(());
    }
    let keys = t.keys.as_ref().ok_or(vault::NOT_PLANNED)?;
    let Some(touch) = touch_of(h, &t, &keys.active(), TOUCH)? else {
        return Ok(());
    };
    let Some(r) = reauth(h, &t, Some(&touch))? else {
        return Ok(());
    };
    drop(touch);
    let done = move |s: &Session| {
        let mut lines = vec![tr(SUPERSEDED).to_owned()];
        lines.extend(s.key_code());
        Done::of(lines)
    };
    if write(
        h,
        &t,
        r,
        Vec::new(),
        change,
        vault::Consent::default(),
        &done,
    )?
    .is_some()
    {
        backup_after(h, BACKUP_QUESTION);
    }
    Ok(())
}
/// S-PRUNE after a removal on a GOYOKS01 vault (spec §7.19): a yes writes
/// `prune.request`, which goyo-sync sends once the head is at that epoch.
fn prune_after(h: Hwnd) {
    let offered = APP.with(|cell| {
        cell.try_borrow()
            .ok()
            .and_then(|b| {
                b.as_ref()
                    .and_then(|a| a.session.as_ref().map(Session::prune_offered))
            })
            .unwrap_or(false)
    });
    if !offered || !ask(h, PRUNE_ASK) {
        return;
    }
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
            && let Some(s) = a.session.as_ref()
        {
            match s.request_prune() {
                Ok(()) => a.status(PRUNE_DONE),
                Err(e) => a.error(e),
            }
        }
    });
}

/// Whether the session waits for a changed key file's own gate.
fn gate_login() -> bool {
    APP.with(|cell| {
        cell.try_borrow()
            .ok()
            .and_then(|b| {
                b.as_ref()
                    .and_then(|a| a.session.as_ref().map(Session::gate_pending))
            })
            .unwrap_or(false)
    })
}

/// Each flow's status after it is done, filled with its longest values, as
/// labels_fit_their_boxes measures them against the status box (three
/// lines): keys on, add key, pairing, re-seed, keys off, the removals, a
/// password change, the gate's pass with S-ONEKEY, an adopt that renumbered
/// a key, S-SUSPENDED-NEAR's line, the accept at login and the failed-
/// unlock entry, the merge, the supersede, and S-ROLLOUT's gist beside
/// S-ONEKEY.
#[cfg(test)]
pub fn composed_statuses() -> Vec<String> {
    let all = "1, 2, 3, 4, 5, 6, 7";
    let code = "E281474976710655 · DDDD-DDDD-DDDD-DDDD";
    let mut out: Vec<Vec<String>> = vec![
        keys_on_done(1, true).lines,
        keys_on_done(8, true).lines,
        keys_on_done(1, false).lines,
        vec![fill(ADDED, &[&8])],
        vec![fill(PAIRED, &[&"1, 2, 3, 4, 5, 6, 7, 8"])],
        vec![tr(RESEEDED).to_owned()],
        vec![tr(KEYS_OFF_DONE).to_owned()],
        vec![fill(LOST_DONE_SHORT, &[&all])],
        vec![fill(LOST_DONE_USB_SHORT, &[&all])],
        vec![fill(REMOVED, &[&all])],
        vec![tr(PASSWORD_CHANGED).to_owned()],
        vec![tr(GATE_PASSED).to_owned(), tr(ONEKEY).to_owned()],
        vec![
            fill(ADOPT_RENUMBER, &[&5, &8]),
            fill(ADOPT_CODE, &[&code]),
            tr(ADOPT_PASS_OTHER).to_owned(),
        ],
        vec![fill(SUSPENDED_NEAR_SHORT, &[&8, &7])],
        vec![tr(KEYSYNC_ON_DONE).to_owned()],
        vec![tr(REUPLOADED).to_owned()],
        // The accept at login and the failed-unlock entry (spec §7.15 at
        // login, §5.2): after an unlock that warned, with S-ADOPT-RENUMBER,
        // or with S-VPENDING.
        vec![fill(ACCEPTED_AT_LOGIN, &[&code])],
        vec![tr(ONEKEY).to_owned(), fill(ACCEPTED_AT_LOGIN, &[&code])],
        vec![
            fill(ADOPT_RENUMBER, &[&5, &8]),
            fill(ACCEPTED_AT_LOGIN, &[&code]),
        ],
        vec![
            fill(ACCEPTED_AT_LOGIN, &[&code]),
            tr(vault::VPENDING).to_owned(),
        ],
        // The kind-9 merge at login, the supersede.
        vec![tr(ONEKEY).to_owned(), fill(MERGED, &[&code])],
        vec![tr(SUPERSEDED).to_owned(), code.to_owned()],
        // S-ROLLOUT's gist beside S-ONEKEY at every unlock. (A refusal at
        // login comes first, before the unlock's lines: alone it fits.)
        vec![tr(ONEKEY).to_owned(), tr(ROLLOUT_REMOVE_SHORT).to_owned()],
        vec![tr(ONEKEY).to_owned(), tr(ROLLOUT_SHORT).to_owned()],
    ];
    // The offs, in each wording of their request (spec §7.16 step 6).
    for request in [
        vault::OffRequest::Deletes,
        vault::OffRequest::AfterView,
        vault::OffRequest::Nothing,
    ] {
        out.push(vec![off_line(request)]);
        out.push(vec![tr(KEYS_OFF_DONE).to_owned(), off_line(request)]);
    }
    out.iter_mut().map(|l| l.join("\r\n")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key row with `unpaired` keys and the flags given.
    fn row(number: u8, suspended: bool) -> KeyRow {
        KeyRow {
            number,
            registered: 1_790_000_000,
            stamp: "20260922-140000".into(),
            display: format!("Goyo Vault 7F2A90C4 key {number} 20260922-140000"),
            suspended,
            orphan: false,
            cloned: false,
            opened: false,
            unpaired: Vec::new(),
            broken: Vec::new(),
        }
    }
    fn overview(n: u8, suspended: &[u8]) -> KeysOverview {
        KeysOverview {
            pin: false,
            rows: (1..=n).map(|k| row(k, suspended.contains(&k))).collect(),
            full: Vec::new(),
        }
    }

    /// The code after a key change (spec §2.29): the photo dialog first only
    /// for a vault that syncs and a change taken with the code; else the
    /// general sentence after the rest, and nothing without a code.
    #[test]
    fn the_code_photo_is_for_the_other_pcs_of_a_synced_vault() {
        let code = "E7 · 1A2B-3C4D-5E6F-7A8B".to_owned();
        let more = vec!["more".to_owned()];
        assert_eq!(
            code_told(Some(code.clone()), true, more.clone()),
            [fill(CODE_PHOTO, &[&code]), "more".to_owned()]
        );
        assert_eq!(
            code_told(Some(code.clone()), false, more.clone()),
            ["more".to_owned(), fill(CODE_SK, &[&code])]
        );
        assert_eq!(code_told(None, true, more), ["more".to_owned()]);
    }
    /// The touch plan of a removal (spec §9.1 step 4, §9.2a; S45-1 #9,
    /// round 2 finding 26): keys 1-4, key 4 a replacement paired with key 1
    /// only. Losing key 1 leaves key 4 "paired only with it"; removed with
    /// it, keys 2 and 3 may touch; kept, no staying key reaches every other
    /// and S-SUSPEND names the smallest cut (key 4), until it is consented
    /// to or planned as an extra touch. A full authorizer comes first, and
    /// a suspended key never touches. Never every staying key is "only".
    #[test]
    fn plan_names_only_paired_keys_and_who_may_touch() {
        let o = overview(4, &[]);
        let unreached = |a: u8| -> Vec<u8> {
            match a {
                1 => vec![],
                2 | 3 => vec![4],
                _ => vec![2, 3],
            }
        };
        let p = plan(&o, &unreached, &[1], true, &[], &[]);
        assert_eq!(p.only, [4]);
        assert_eq!((p.remove.clone(), p.stay.clone()), (vec![1, 4], vec![2, 3]));
        assert_eq!((p.touch.clone(), p.suspend.clone()), (vec![2, 3], vec![]));
        // Kept: no key fits, S-SUSPEND names key 4 (the smallest cut).
        let p = plan(&o, &unreached, &[1], false, &[], &[]);
        assert_eq!((p.remove.clone(), p.stay.clone()), (vec![1], vec![2, 3, 4]));
        assert!(p.touch.is_empty());
        assert_eq!(p.suspend, [4]);
        // Consented: keys 2 and 3 fit, key 4 (whose cut is not) does not.
        let p = plan(&o, &unreached, &[1], false, &[], &[4]);
        assert_eq!((p.touch.clone(), p.suspend.clone()), (vec![2, 3], vec![]));
        // Planned as an extra touch: never the touch itself.
        let p = plan(&o, &unreached, &[1], false, &[4], &[]);
        assert_eq!(p.touch, [2, 3]);
        assert!(p.only.is_empty());
        // A retirement of key 2: key 1 reaches every staying key and comes
        // first; key 3's cut (key 4) needs consent.
        let p = plan(&o, &unreached, &[2], false, &[], &[]);
        assert_eq!(p.touch, [1]);
        let p = plan(&o, &unreached, &[2], false, &[], &[4]);
        assert_eq!(p.touch, [1, 3]);
        // Suspended keys never touch.
        let o = overview(4, &[1]);
        let p = plan(&o, &unreached, &[2], false, &[], &[4]);
        assert_eq!(p.touch, [3]);
        // Two keys that reach only each other's absent partner: each is
        // "only" for the other, so neither is (one must stay).
        let o = overview(3, &[]);
        let apart = |a: u8| -> Vec<u8> {
            match a {
                2 => vec![3],
                3 => vec![2],
                _ => vec![],
            }
        };
        let p = plan(&o, &apart, &[1], true, &[], &[]);
        assert!(p.only.is_empty() && p.stay == [2, 3]);
        assert!(p.touch.is_empty() && p.suspend.len() == 1);
    }

    /// A loss date is empty (unknown) or a day no later than today (spec
    /// §9.1): a typo into the future would end the review unread.
    #[test]
    fn a_loss_date_after_today_is_refused() {
        let now = vault::day_of("2026-10-29").unwrap() + 3 * 3600;
        assert_eq!(loss_day("  ", now), Ok(None));
        assert_eq!(
            loss_day("2026-10-01", now),
            vault::day_of("2026-10-01").map(Some).ok_or("")
        );
        // Today in a time zone up to 14 hours ahead of UTC.
        assert!(loss_day("2026-10-30", now + 11 * 3600).is_ok());
        assert_eq!(loss_day("2062-10-01", now), Err(FUTURE_DATE));
        assert_eq!(loss_day("2026-11-02", now), Err(FUTURE_DATE));
        assert_eq!(loss_day("2026-02-31", now), Err(DATE_FORMAT));
    }

    /// The texts that depend on what is offered or counted: S-FORK names
    /// only the options shown; S-ADOPT-RENUMBER and -DROPPED-UV; keys new
    /// to this PC carry their mark; a failed MakeCredential with an unknown
    /// code adds S-KEYSTORE-FULL; S-SUSPEND's Enter is [취소] and its
    /// [그 키도 함께 터치] only offered when every key can be touched; keys
    /// on with one key leads with S-ONEKEY in the danger tone.
    #[test]
    fn texts_follow_what_is_offered_and_counted() {
        assert_eq!(fork_text(true, true), FORK);
        let both_only = fork_text(false, true);
        assert!(both_only.contains(FORK_OPT2_TEXT) && !both_only.contains("다른 PC 쪽 사용"));
        let other_only = fork_text(true, false);
        assert!(other_only.contains(FORK_OPT1_TEXT) && !other_only.contains("둘 다 합치기"));
        assert_eq!(
            adopted_lines(&[(5, 6)], &[3]),
            [
                fill(ADOPT_RENUMBER, &[&5, &6]),
                fill(ADOPT_DROPPED_UV, &[&3])
            ]
        );
        assert!(adopted_lines(&[], &[]).is_empty());
        assert_eq!(
            named_list(&[(3, false), (5, true)]),
            format!("3, 5 ({NEW_TO_PC})")
        );
        let failed = make_failure(FidoError::Other(0x8000_4005_u32 as i32));
        assert!(
            failed.starts_with("보안 키 작업 실패 (코드 0x80004005)"),
            "{failed}"
        );
        assert!(failed.ends_with(&format!("\r\n{}", fido::KEYSTORE_FULL)));
        assert_eq!(make_failure(FidoError::Exists), fido::EXISTS);
        // hWnd 0's code is a refused request with its own text, never a
        // full store (real key, spec §2.28).
        let rejected = FidoError::from_hresult(fido::NTE_INVALID_PARAMETER);
        assert_eq!(make_failure(rejected), fido::REJECTED);
        assert_eq!(failure(rejected, true, false), fido::REJECTED);
        let ids = |touch| -> Vec<i32> { suspend_buttons(touch).iter().map(|b| b.id).collect() };
        assert_eq!(ids(true), [2, SUSPEND_TOUCH, 1]);
        assert_eq!(ids(false), [2, 1]);
        assert_eq!(suspend_buttons(true)[0].role, Role::Cancel);
        let one = keys_on_done(1, true);
        assert!(one.danger);
        assert_eq!(one.lines[0], ONEKEY);
        assert_eq!(one.lines[1], format!("{KEYS_ON_DONE_ONE} {PASS_NEW}"));
        let two = keys_on_done(2, false);
        assert!(!two.danger && two.lines == [fill(KEYS_ON_DONE, &[&2])]);
    }

    /// The Keys screen's key-file sync line (spec §9.1, §7.15, §7.15a):
    /// [받기…] for a successor and for a fork it joins, never for a
    /// refused file; [받지 않기…] for a pending gate, also once its
    /// candidate is no longer the server's top.
    #[test]
    fn key_sync_buttons_reach_every_way_out() {
        // The texts are compared in Korean.
        let _korean = crate::tests::KoreanAfter::hold();
        let ids = |v: &vault::KeySyncView| -> Vec<i32> {
            key_sync_text(v).1.iter().map(|(id, _)| *id).collect()
        };
        let waiting = |class, pending_gate| {
            Some(vault::Waiting {
                epoch: 7,
                class,
                pending_gate,
                supersede: false,
            })
        };
        let on = vault::KeySyncView {
            on: true,
            synced: true,
            ..vault::KeySyncView::default()
        };
        let gated = vault::KeyClass::Successor {
            carry: false,
            gate: Some(vault::GateKind::G1),
        };
        // Two KeySyncOn from one state: the loser's fork is joined here.
        let fork = vault::KeySyncView {
            waiting: waiting(vault::KeyClass::KeyFork, false),
            ..on
        };
        assert_eq!(ids(&fork), [KEY_ACCEPT]);
        assert!(key_sync_text(&fork).0.contains("[받기…]"));
        assert!(server_takes(Some(vault::KeyClass::KeyFork)));
        assert!(server_takes(Some(gated)));
        assert!(!server_takes(Some(vault::KeyClass::Refused("x"))));
        assert!(!server_takes(Some(vault::KeyClass::Equal)));
        let refused = vault::KeySyncView {
            waiting: waiting(vault::KeyClass::Refused("x"), false),
            ..on
        };
        assert_eq!(ids(&refused), [KEYSYNC_OFF]);
        let pending = vault::KeySyncView {
            waiting: waiting(gated, true),
            ..on
        };
        assert_eq!(ids(&pending), [KEY_ACCEPT, GATE_DROP]);
        // The candidate left the top (a GOYOKH01 PC: no off to end it).
        let gone = vault::KeySyncView {
            on: false,
            stale_gate: Some(7),
            ..on
        };
        assert_eq!(ids(&gone), [KEYSYNC_ON, GATE_DROP]);
        assert!(key_sync_text(&gone).0.contains(&fill(KS_GATE_GONE, &[&7])));
        // The rollout reminder (spec §7.18): [모든 PC 확인 완료] beside the
        // off, and the row fits: the buttons leave the text 300 px or more.
        let rollout = vault::KeySyncView {
            rollout: true,
            ..on
        };
        assert_eq!(ids(&rollout), [KEYSYNC_OFF, KEY_ROLLOUT_DONE]);
        assert!(key_sync_text(&rollout).0.ends_with(KS_ROLLOUT));
        for v in [&fork, &refused, &pending, &gone, &rollout] {
            let n = ids(v).len();
            let used: i32 = ids(v).iter().map(|id| sync_button_width(*id, n) + 8).sum();
            assert!(796 - used >= 300, "{:?}", ids(v));
        }
        // KeyFork-SK's merge variants (spec §7.4): AUTO keeps the forgery
        // sentence, MERGE comes after KeyFork-SK in full.
        let line = |auto| key_sync_line(&vault::SyncNotice::KeyForkMerge { auto }).unwrap();
        assert!(line(true).0.contains("서버 사본이 위조되었을 수 있습니다"));
        assert!(line(false).0.contains("[받기…]로 합칠 수 있습니다"));
        assert!(
            line(false)
                .0
                .ends_with("서버 사본이 위조되었을 수 있습니다.")
        );
    }

    /// The review's times are this PC's local time (spec §5.13), within the
    /// widest offset of any time zone from the UTC time.
    #[test]
    fn review_times_are_local() {
        let secs = 1_790_000_000;
        let shown = local_time(secs);
        assert_eq!(shown.len(), 16, "{shown}");
        let utc = vault::shown_time(secs);
        let minutes = |t: &str| -> i64 {
            let day = vault::day_of(&t[..10]).unwrap() as i64 / 60;
            day + t[11..13].parse::<i64>().unwrap() * 60 + t[14..16].parse::<i64>().unwrap()
        };
        assert!(
            (minutes(&shown) - minutes(&utc)).abs() <= 14 * 60,
            "{shown} {utc}"
        );
        assert!(!shown.contains("UTC"));
    }

    /// The accept at login and the failed-unlock entry (final review
    /// finding 5): an unlock that warned keeps its lines first; otherwise
    /// what was taken leads and the unlock's usual line gives way.
    #[test]
    fn the_accept_at_login_keeps_the_unlocks_warnings_first() {
        let taken = ["taken", "vpending"];
        let warned = format!("{ONEKEY}\r\n{}", crate::UNLOCKED);
        assert_eq!(
            *at_login_status(&warned, true, &taken),
            format!("{ONEKEY}\r\ntaken\r\nvpending")
        );
        assert_eq!(
            *at_login_status(crate::UNLOCKED_NO_AUTO_LOCK, false, &taken),
            "taken\r\nvpending"
        );
        let recovered = format!("recovered\r\n{}", crate::UNLOCKED);
        assert_eq!(
            *at_login_status(&recovered, false, &taken[..1]),
            "taken\r\nrecovered"
        );
    }
}
