#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("Goyo Vault requires Windows x64.");
mod i18n;
#[cfg(feature = "security-key")]
mod keys_ui;
mod theme;
#[cfg(feature = "security-key")]
mod webauthn;
mod win;
#[cfg(feature = "security-key")]
use goyo_vault::fido::{
    AssertRequest, Authenticator, CancelToken, FidoError, Touch, check_assertion,
};
use goyo_vault::{
    clock, crypto,
    otp::{self, Otp},
    qr, syncfile,
    vault::{
        self, AdoptClass, Entry, Format, GAP_KEPT, GatePass, KeyInfo, KeyNotice, LEFTOVER_TEMP,
        Prepared, Provision, Recovery, Session, Source, SyncBadge, SyncNotice, VaultClass,
        key_candidate, key_info, keyfile::KeyFile, leftover_temp, vault_candidates,
    },
};
use i18n::{fill, tr};
#[cfg(feature = "security-key")]
use std::sync::Arc;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::OnceLock,
    time::{Duration, Instant},
};
use theme::{
    DT_CENTER, DT_EDITCONTROL, DT_END_ELLIPSIS, DT_NOPREFIX, DT_RIGHT, DT_WORDBREAK, LINE,
    TONE_DANGER, TONE_MUTED, TONE_TEXT,
};
use win::*;
use zeroize::{Zeroize, Zeroizing};

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    static INTERNAL_READ: Cell<bool> = const { Cell::new(false) };
    static PENDING_EVENTS: Cell<u8> = const { Cell::new(0) };
    /// The window was hidden until pending events are handled.
    static HIDDEN_FOR_EVENTS: Cell<bool> = const { Cell::new(false) };
    static WINDOW_GONE: Cell<bool> = const { Cell::new(false) };
    /// Set by edit_proc before it posts PASTE_CLEARED (bit 1), INPUT_ERROR
    /// (bit 2) or OTP_PASTED (bit 4), so the same messages posted by another
    /// program do nothing.
    static PASTE_NOTICE: Cell<u8> = const { Cell::new(0) };
    /// Set by App::submit when an unlock found a v1 vault next to a sync
    /// folder; window_proc then asks whether to turn sync on (offer_sync).
    /// Internal state, never a message, so no other program can raise it.
    static SYNC_OFFER: Cell<bool> = const { Cell::new(false) };
}
/// Answers one question in place of the user; gets the question's text.
#[cfg(test)]
type Answer = Box<dyn FnMut(&str) -> bool>;
/// Answers an input dialog in place of the user; gets its text and kind.
#[cfg(test)]
type InputHook = Box<dyn FnMut(&str, &InputKind) -> InputAnswer>;
#[cfg(test)]
thread_local! {
    /// The answer to the next ask(), given by a test: no test can click a
    /// real message box. It runs as the box would, inside modal().
    static ANSWER: RefCell<Option<Answer>> = const { RefCell::new(None) };
    /// The same for every ask_input() until a test takes it away.
    static INPUT_ANSWER: RefCell<Option<InputHook>> = const { RefCell::new(None) };
}
static EDIT_PROC: OnceLock<Proc> = OnceLock::new();
static LIST_PROC: OnceLock<Proc> = OnceLock::new();
const DRAIN_EVENTS: u32 = 0x8001;
const INPUT_ERROR: u32 = 0x8002;
const PASTE_CLEARED: u32 = 0x8003;
/// An otpauth URI was pasted into OTP_FIELD: its names fill the two fields
/// next to it.
const OTP_PASTED: u32 = 0x8004;
const CREATE: i32 = 101;
const OPEN: i32 = 102;
const RESTORE: i32 = 103;
const SUBMIT: i32 = 104;
const BROWSE_V: i32 = 105;
const BROWSE_K: i32 = 106;
const BROWSE_D: i32 = 107;
const VPATH: i32 = 201;
const KPATH: i32 = 202;
const PASS: i32 = 203;
const CONFIRM: i32 = 204;
const DEST: i32 = 206;
const CURRENT_PASS: i32 = 207;
const LIST: i32 = 210;
const TITLE: i32 = 211;
const KIND: i32 = 212;
const SECRET: i32 = 213;
const NOTES: i32 = 214;
/// The entry editor's OTP secret (masked, with an eye) and its names.
const OTP_FIELD: i32 = 222;
const OTP_ISSUER: i32 = 223;
const OTP_ACCOUNT: i32 = 224;
/// The entry view's OTP row: copy the code, copy the secret, the QR panel.
const OTP_COPY: i32 = 225;
const OTP_SECRET_COPY: i32 = 226;
const OTP_QR: i32 = 227;
/// The QR panel hides by itself after this long.
const QR_SHOWN: Duration = Duration::from_secs(60);
/// The OTP row's top: under the memo, or for an OTP entry (0.12.1), which
/// shows no 비밀정보, in its place under the chip.
const OTP_TOP: i32 = 522;
const OTP_ENTRY_TOP: i32 = 190;
/// The OTP row's buttons, 34 under its top: [복사] at this x, then
/// [시크릿 복사] and [QR 보기].
const OTP_ROW: (i32, i32) = (536, OTP_TOP + 34);
/// What the timer repaints of the OTP row, from its top: its names line
/// with the countdown, and the code (the buttons are child windows).
const OTP_TICKING: (i32, i32) = (4, 68);
/// The QR panel's square, under its caption, above the OTP row; for an OTP
/// entry under the row, in the memo's place.
const QR_AREA: (i32, i32, i32, i32) = (CARD_X, 224, CARD_W, 288);
const QR_AREA_OTP_ENTRY: (i32, i32, i32, i32) = (CARD_X, 324, CARD_W, 288);
const NO_OTP: &str = "이 항목에는 OTP 시크릿이 없습니다.";
/// An OTP entry keeps no 비밀정보 to copy or page through.
const NO_SECRET: &str = "OTP 항목에는 비밀정보가 없습니다.";
/// The editor's captions that change with the kind, and the OTP kind's
/// note in the 비밀정보's place (0.12.1).
const SECRET_LABEL: i32 = 250;
const OTP_LABEL: i32 = 251;
const OTP_ISSUER_LABEL: i32 = 252;
const OTP_ACCOUNT_LABEL: i32 = 253;
const OTP_KIND_NOTE: i32 = 254;
/// The editor's OTP row (caption, field, eye and the two names): its top,
/// and for the OTP kind its top in the 비밀정보's place.
const OTP_EDIT_TOP: i32 = 500;
const OTP_EDIT_TOP_KIND: i32 = 272;
const OTP_FIELD_OPTIONAL: &str = "OTP 시크릿 (선택) · 키 또는 otpauth 주소";
const OTP_FIELD_REQUIRED: &str = "OTP 시크릿 · 키 또는 otpauth 주소";
const OTP_KIND_TEXT: &str = "OTP 항목은 비밀정보 없이 OTP 시크릿만 저장합니다. 이 항목에 비밀정보가 있었다면 저장할 때 지워집니다.";
const NEW: i32 = 110;
const EDIT: i32 = 111;
const DELETE: i32 = 112;
const SAVE: i32 = 113;
const CANCEL: i32 = 114;
const LOCK: i32 = 115;
const BACKUP: i32 = 116;
const KEYBACKUP: i32 = 117;
const CHANGE: i32 = 118;
const TOGGLE: i32 = 119;
const COPY: i32 = 120;
const REVEAL: i32 = 121;
const PREVIOUS: i32 = 122;
const NEXT: i32 = 123;
const THEME_DARK: i32 = 124;
const THEME_LIGHT: i32 = 125;
const BACK: i32 = 126;
/// Eye buttons inside the password fields, in the order of PEEK_FIELDS.
const PEEK_PASS: i32 = 127;
const PEEK_CONFIRM: i32 = 128;
const PEEK_CURRENT: i32 = 129;
const PEEK_OTP: i32 = 228;
/// With the shortest auto-lock, an open vault locks once another app has had
/// focus this long. Shorter trips (pasting a copied value, a screenshot
/// tool's overlay) only hide what was shown; capture exclusion already keeps
/// the window out of shots. Longer settings count time away as unused time.
const AWAY_LOCK: Duration = Duration::from_secs(30);
/// Auto-lock choices for an open vault, in the order of the switch on the
/// vault screen: caption, how long the vault may go unused (None: no timer;
/// locking Windows, sleep and shutdown still lock), the status line when it
/// is picked and the warning on the edit screen.
const AUTO_LOCKS: [(&str, Option<Duration>, &str, &str); 4] = [
    (
        "1분",
        Some(Duration::from_secs(60)),
        "자동 잠금 1분: 1분 동안 쓰지 않거나 다른 앱에 30초 넘게 머무르면 잠급니다.",
        "편집 중 내용이 화면에 보입니다. 다른 앱에 30초 넘게 머무르면 잠기고 저장하지 않은 내용은 지워집니다.",
    ),
    (
        "5분",
        Some(Duration::from_secs(300)),
        "자동 잠금 5분: 5분 동안 쓰지 않으면 잠급니다. 다른 앱에 있는 시간도 포함됩니다.",
        "편집 중 내용이 화면에 보입니다. 5분 동안 쓰지 않으면 잠기고 저장하지 않은 내용은 지워집니다.",
    ),
    (
        "30분",
        Some(Duration::from_secs(1800)),
        "자동 잠금 30분: 30분 동안 쓰지 않으면 잠급니다. 다른 앱에 있는 시간도 포함됩니다.",
        "편집 중 내용이 화면에 보입니다. 30분 동안 쓰지 않으면 잠기고 저장하지 않은 내용은 지워집니다.",
    ),
    (
        "끔",
        None,
        "자동 잠금 끔: 잠금 버튼, Windows 화면 잠금(Win+L), 절전, 종료 때만 잠깁니다. 자리를 비울 때는 Win+L을 누르세요.",
        "편집 중 내용이 화면에 보입니다. 잠금·화면 잠금·절전 때 저장하지 않은 내용은 지워집니다.",
    ),
];
/// Segments of the auto-lock switch, in the order of AUTO_LOCKS.
const AUTO_LOCK: i32 = 139;
const AUTO_LOCK_LAST: i32 = AUTO_LOCK + AUTO_LOCKS.len() as i32 - 1;
/// Bottom right of the vault screen, next to its "자동 잠금" label.
const AUTO_LOCK_SWITCH: (i32, i32, i32, i32) = (634, 640, 202, 36);
/// Language switch next to the theme switch.
const LANG_KO: i32 = 137;
const LANG_EN: i32 = 138;
const KEY_NOTE: i32 = 220;
/// The Keys screen (spec §9.1): "비밀번호 변경…" and "새 열쇠 파일 받기…".
const KEY_PASSWORD: i32 = 150;
const KEY_ADOPT: i32 = 156;
/// "이 PC의 비밀번호 쓰기", the check box of the adopt preview.
const ADOPT_OWN_PASS: i32 = 168;
/// [서버 사본을 이 PC 상태로 덮어쓰기…] (spec §7.5a).
const KEY_OVERRIDE_HEAD: i32 = 169;
const OVERRIDE_HEAD_LABEL: &str = "서버 사본을 이 PC 상태로 덮어쓰기…";
/// [이 열쇠 파일이 맞습니다] (spec §5.10).
const KEY_LOCAL_OK: i32 = 170;
/// [끝나지 않은 열쇠 변경 버리기…] (spec §5.10).
const PENDING_FORGET: i32 = 190;
/// While a flow runs (see App::flow), an open vault locks after this long
/// unused at the earliest: a flow's questions take longer to answer than
/// the shortest auto-lock (spec §9.2a).
const FLOW_IDLE: Duration = Duration::from_secs(600);
const PEEK_FIELDS: [(i32, i32); 4] = [
    (PEEK_PASS, PASS),
    (PEEK_CONFIRM, CONFIRM),
    (PEEK_CURRENT, CURRENT_PASS),
    (PEEK_OTP, OTP_FIELD),
];
const PRESET: i32 = 130;
const PRESET_LAST: i32 = PRESET + KIND_PRESETS.len() as i32 - 1;
const STATUS: i32 = 299;
/// The kind chips of the editor; the last is the OTP kind (vault::OTP_KIND).
const KIND_PRESETS: [&str; 5] = [
    "비밀번호",
    "니모닉",
    "프라이빗키",
    "API 키",
    vault::OTP_KIND,
];
// Layout grid in 96-DPI units. Auth/password screens use one centered column.
const AX: i32 = 158;
const AW: i32 = 560;
const CARD_X: i32 = 348;
const CARD_W: i32 = 464;
const HINT: (i32, i32, i32, i32) = (CARD_X, 372, CARD_W, 40);
/// Dark/light segmented switch in the top-right corner of every screen.
const THEME_SWITCH: (i32, i32, i32, i32) = (704, 21, 132, 36);
/// 한국어 | English, left of the theme switch.
const LANG_SWITCH: (i32, i32, i32, i32) = (554, 21, 146, 36);
/// The "open" pill after the brand ends here at the latest, clear of the
/// lock button; a long file name is cut with an ellipsis.
const PILL_RIGHT: i32 = LANG_SWITCH.0 - 108;
/// The sync folder is polled on every 4th timer tick (2 s).
const SYNC_TICKS: u32 = 4;
/// Top of the painted note card on Password.
const PASSWORD_CARD_Y: i32 = 384;
/// Divider above the "새 금고 만들기 · 백업 파일로 되살리기" links on Login.
const LOGIN_LINKS: (i32, i32, i32, i32) = (AX, 500, AW, 1);
#[derive(Clone, Copy, PartialEq)]
enum Screen {
    /// No vault at the default location: choose create, restore or open.
    Welcome,
    Login,
    Create,
    Restore,
    Vault,
    Edit,
    Password,
    /// "열쇠 관리": the password change, another PC's key file, the key
    /// backup and code, and what holds key changes (spec §9.1).
    Keys,
    /// "새 열쇠 파일 받기": another PC's key file, chosen, and opened with
    /// [열기] (spec §9.1).
    Adopt,
    /// "짝 맺기": the keys to touch together (spec §9.1).
    #[cfg(feature = "security-key")]
    Pair,
    /// "잃어버린 키 제거": the lost keys, the loss and the touch plan.
    #[cfg(feature = "security-key")]
    LostKey,
    /// "키 빼기": a planned retirement of keys.
    #[cfg(feature = "security-key")]
    KeyRemove,
    /// S-REVIEW: what came in by sync since the day before a loss.
    #[cfg(feature = "security-key")]
    Review,
    /// "서버에서 가져온 금고" (spec §2.29): a vault file goyo-sync fetched
    /// with the server's key file in its sync folder and no key file on
    /// this PC; the password, the touch, then the TOFU banner's code and
    /// the key file saved next to the vault.
    #[cfg(feature = "security-key")]
    Fetched,
}
/// The command whose phased flow runs (see App::flow).
type FlowId = i32;
struct App {
    hwnd: Hwnd,
    font: isize,
    scale: f32,
    controls: BTreeMap<i32, Hwnd>,
    children: Vec<Hwnd>,
    edits: Vec<Hwnd>,
    /// Painted outlines around borderless inputs: (96-DPI rect, control).
    frames: Vec<(Rect, Hwnd)>,
    screen: Screen,
    session: Option<Session>,
    provision: Option<Provision>,
    selected: Option<usize>,
    editing: Option<usize>,
    /// Folder of the executable; default home of new and restored vaults.
    home_dir: PathBuf,
    /// The vault to open and its key (Login; also the key used by Restore).
    vault_path: PathBuf,
    key_path: PathBuf,
    /// Create and Restore keep their own fields so switching screens never
    /// turns a typed "new file" into the vault to open, or the reverse.
    new_vault_path: PathBuf,
    new_key_path: PathBuf,
    backup_path: PathBuf,
    dest_path: PathBuf,
    activity: Instant,
    copy_until: Option<Instant>,
    reveal_until: Option<Instant>,
    clipboard: Option<(u32, Instant)>,
    failed: u32,
    retry: Instant,
    /// Korean source of the status line, shown translated line by line.
    /// Wiped when replaced: a sync conflict line names an entry.
    status: Zeroizing<String>,
    /// The process protection that stopped holding (THREADS_OPEN,
    /// DLL_BESIDE): sticky until the app ends, shown in the header pill and
    /// on any screen whose status line is empty (VC-4).
    weakened: Option<&'static str>,
    /// A notice that stays first on the status line, in the danger tone,
    /// over every line that comes by itself (a poll, a lock), until the
    /// next click: a key change taken from the server under auto-apply
    /// (G-01), which no question showed before it was applied.
    pinned: Option<Zeroizing<String>>,
    page: usize,
    closing: bool,
    auth_dirty: bool,
    input_failed: bool,
    /// Login was opened from Welcome ("금고 파일 열기"), so it
    /// offers a way back instead of being the home screen.
    from_welcome: bool,
    /// When another app took focus while a vault was open.
    away_since: Option<Instant>,
    /// Another app is in front (see deactivated/activated).
    inactive: bool,
    /// Which PEEK_FIELDS are shown with the eye button. Kept here, not in the
    /// button's window data, which other programs can overwrite.
    shown: [bool; PEEK_FIELDS.len()],
    /// The entry whose OTP QR code the detail card shows, and until when
    /// (see qr_shown). Gone on lock, on leaving the entry or the screen,
    /// when another app comes in front, and after QR_SHOWN.
    qr: Option<(vault::EntryId, Instant)>,
    /// Tone of the status line on the next build (one-shot).
    status_tone: isize,
    /// Index into AUTO_LOCKS, kept in goyo-vault.autolock.
    auto_lock: usize,
    /// Timer ticks, for polling the sync folder on every SYNC_TICKS-th.
    sync_ticks: u32,
    /// The word on the "open" pill for a vault that syncs, as of the last
    /// unlock, edit or poll that changed it.
    sync_badge: Option<SyncBadge>,
    /// Raised by lock(), scrub() and every screen change (show), so that a
    /// phased command finds out when what it started on is gone.
    serial: u64,
    /// The phased flow under way, from its first phase to its end (spec
    /// §9.2a): the idle limits are at least FLOW_IDLE meanwhile.
    flow: Option<FlowId>,
    /// Raised by every status line set and every build, so that a flow
    /// finds out whether it told anything (see told_how_it_ended).
    told: u64,
    /// The progress line a flow showed last ("touch your key", a
    /// registration under way): a flow that ends with it still on the
    /// status line told nothing of how it ended. Public text only.
    prompt: String,
    /// What the Keys screen showed of the session at its last build: a
    /// poll there rebuilds it only when this changed (see refresh_keys).
    keys_shown: Option<KeysShown>,
    /// Adopt: the other PC's key file the user chose.
    adopt_source: Option<PathBuf>,
    /// The toggles of Create, Keys and Pair in the security-key build.
    #[cfg(feature = "security-key")]
    toggles: keys_ui::Toggles,
    /// The vault and key paths a login refused with S-ANCHOR-FORK, -RELIST
    /// or -DOWNGRADE: the login screen offers [이 금고의 기록 지우고 다시
    /// 확인…] for exactly these (spec §5.10, §9.1).
    #[cfg(feature = "security-key")]
    forget_for: Option<(PathBuf, PathBuf)>,
}
/// What phase 1 of a phased command took (see phased_command): the typed
/// secrets, wiped when the flow ends however it ends, and what phase 3 must
/// find unchanged.
struct Flow {
    screen: Screen,
    serial: u64,
    /// A session was open. Only an unlock opens one, and that changes the
    /// screen, so with the serial this names the session.
    session: bool,
    pass: Zeroizing<String>,
    /// Password: the current password.
    current: Zeroizing<String>,
    /// Login: what a failed authentication says instead of the AUTH text
    /// (spec §5.12): rule (i)'s text when the key file is a temp file an
    /// interrupted save left, or a hint about this PC's own key change.
    auth_failure: Option<&'static str>,
    /// Password: S-ROTATE, what the change does (spec §9.2), asked first.
    question: Option<&'static str>,
    /// Password: the question asked before the key change (spec §7.5), and
    /// the one the user went on past: only that one is passed.
    gate: Option<vault::Gate>,
    answered: Option<vault::Gate>,
    /// Login: the key file and the vault file's precheck (spec §5.1). Phase
    /// 3 opens exactly the key file read here.
    prepared: Option<Prepared>,
    /// Login: the user agreed to open this older-key vault file (S-OLDER).
    confirmed_older: Option<[u8; 32]>,
    /// Login with a key file that has security keys: the touch of the
    /// unlock's ceremony (spec §5.2 step 3), taken between the phases.
    #[cfg(feature = "security-key")]
    touch: Option<Touch>,
}
/// What a login with security keys hands back to its flow (spec §5.2,
/// §5.3): the unlock's touch, and either the session's `UnlockProof` (the
/// server's key file taken at login) or the failed-unlock entry.
#[cfg(feature = "security-key")]
#[derive(Default)]
struct LoginOut {
    touch: Option<Touch>,
    proof: Option<vault::UnlockProof>,
    entry: Option<Box<vault::ServerEntry>>,
}
impl Flow {
    /// The older-key vault file a login must ask about first (S-OLDER).
    fn older(&self) -> Option<[u8; 32]> {
        match self.prepared.as_ref()?.check().vault {
            VaultClass::Older { sha } => Some(sha),
            _ => None,
        }
    }
}
/// What the Keys screen shows of a session (spec §9.1).
#[derive(Clone, Default, PartialEq)]
struct KeysView {
    /// A KF2 key file's key code, "E{epoch} · XXXX-XXXX-XXXX-XXXX".
    code: Option<String>,
    hold: Hold,
    /// The key file's security keys (None: keys off).
    #[cfg(feature = "security-key")]
    keys: Option<vault::KeysOverview>,
}
/// What holds key changes, as the Keys screen tells it; the first that
/// applies, in the order the library refuses a change for them.
#[derive(Clone, Default, PartialEq)]
enum Hold {
    #[default]
    None,
    /// S-PENDING-ELSEWHERE, with [끝나지 않은 열쇠 변경 버리기…].
    PendingElsewhere(PathBuf),
    /// S-RESTORE-PENDING, with no button.
    RestorePending,
    /// S-RESTORE-OLDKEY (confirmed and key file epochs), with no button.
    RestoreOldKey(u64, u64),
    /// Any other Restore (RESTORE_KEYS), with no button.
    Restored,
    /// A changed key file waits for its gate (S-GATE-HELD), with [받기…].
    #[cfg(feature = "security-key")]
    GatePending,
    /// S-LOCAL-ROLLBACK (the same epochs), with [이 열쇠 파일이 맞습니다].
    LocalRollback(u64, u64),
    /// A server copy halts sync, with the head override (spec §7.5a).
    Halted,
    /// A PC without security keys whose vault's server holds another PC's
    /// key file with keys, at this epoch (keys on, then key-file sync):
    /// S-PWONLY-SERVER with [서버의 새 열쇠 파일 받기…], and the head
    /// override below it while a server copy halts sync.
    #[cfg(feature = "security-key")]
    ServerKeysOn { epoch: u64, halted: bool },
    /// Not a hold: a removal that never landed (S-REMOVE-UNDONE, its key
    /// numbers), with [다시 하기] before any other key change.
    #[cfg(feature = "security-key")]
    Undone(String),
}
impl KeysView {
    fn of(s: &Session) -> Self {
        let (old, new) = (s.confirmed_epoch().unwrap_or(0), s.key_state().epoch);
        let hold = if let Some(path) = s.pending_elsewhere() {
            Hold::PendingElsewhere(path.to_owned())
        } else if s.restore_held() && s.restore_pending() {
            Hold::RestorePending
        } else if s.restore_held() {
            Hold::RestoreOldKey(old, new)
        } else if s.restored() {
            Hold::Restored
        } else if let Some(pending) = gate_hold(s) {
            pending
        } else if s.local_rollback() {
            Hold::LocalRollback(old, new)
        } else if let Some(server) = server_hold(s) {
            server
        } else if s.halted_head().is_some() {
            Hold::Halted
        } else {
            redo_hold(s)
        };
        Self {
            code: s.key_code(),
            hold,
            #[cfg(feature = "security-key")]
            keys: s.keys_overview(),
        }
    }
}
/// Everything of the session the Keys screen shows (see App::keys_shown):
/// its view, the key-file sync line and buttons, and the list's leading
/// texts (S-SUSPENDED-NEAR, S-ROLLOUT).
#[derive(PartialEq)]
struct KeysShown {
    view: KeysView,
    #[cfg(feature = "security-key")]
    sync: Option<vault::KeySyncView>,
    #[cfg(feature = "security-key")]
    texts: Vec<String>,
}
/// What holds key changes while a changed key file waits for its gate
/// (spec §5.2); never in the keyless build.
fn gate_hold(s: &Session) -> Option<Hold> {
    #[cfg(feature = "security-key")]
    return s.gate_pending().then_some(Hold::GatePending);
    #[cfg(not(feature = "security-key"))]
    {
        let _ = s;
        None
    }
}
/// The server's key file with keys that a PC without keys takes (see
/// Hold::ServerKeysOn); never in the keyless build.
fn server_hold(s: &Session) -> Option<Hold> {
    #[cfg(feature = "security-key")]
    return s.pwonly_server_file().map(|epoch| Hold::ServerKeysOn {
        epoch,
        halted: s.halted_head().is_some(),
    });
    #[cfg(not(feature = "security-key"))]
    {
        let _ = s;
        None
    }
}
/// A removal that never landed, which [다시 하기] reopens (spec §9.2);
/// never in the keyless build.
fn redo_hold(s: &Session) -> Hold {
    #[cfg(feature = "security-key")]
    if let Some(redo) = s.redo() {
        let list: Vec<String> = redo.remove.iter().map(u8::to_string).collect();
        return Hold::Undone(list.join(", "));
    }
    let _ = s;
    Hold::None
}
/// A button: its control ID and label.
type Action = (i32, &'static str);
impl Hold {
    /// The text in its language and tone, and the button that acts on it.
    fn shown(&self) -> Option<(String, isize, Option<Action>)> {
        Some(match self {
            Hold::None => return None,
            Hold::PendingElsewhere(path) => (
                fill(vault::PENDING_ELSEWHERE, &[&shown(path)]),
                TONE_DANGER,
                Some((PENDING_FORGET, "끝나지 않은 열쇠 변경 버리기…")),
            ),
            Hold::RestorePending => (tr(vault::RESTORE_PENDING).to_owned(), TONE_MUTED, None),
            Hold::RestoreOldKey(old, new) => {
                (fill(vault::RESTORE_OLDKEY, &[old, new]), TONE_MUTED, None)
            }
            Hold::Restored => (tr(vault::RESTORE_KEYS).to_owned(), TONE_MUTED, None),
            #[cfg(feature = "security-key")]
            Hold::GatePending => (
                tr(vault::GATE_HELD).to_owned(),
                TONE_DANGER,
                Some((keys_ui::KEY_ACCEPT, keys_ui::ACCEPT_BUTTON)),
            ),
            Hold::LocalRollback(old, new) => (
                fill(vault::LOCAL_ROLLBACK, &[old, new]),
                TONE_DANGER,
                Some((KEY_LOCAL_OK, "이 열쇠 파일이 맞습니다")),
            ),
            Hold::Halted => (
                tr("서버 사본 때문에 동기화가 멈춰 있습니다. 그 사본을 올린 PC의 열쇠 파일을 받을 수 없을 때만 서버 사본을 덮어쓰세요.").to_owned(),
                TONE_DANGER,
                Some((KEY_OVERRIDE_HEAD, OVERRIDE_HEAD_LABEL)),
            ),
            #[cfg(feature = "security-key")]
            Hold::ServerKeysOn { epoch, .. } => (
                fill(keys_ui::SERVER_TAKE_HOLD, &[epoch]),
                TONE_DANGER,
                Some((keys_ui::KEY_SERVER_TAKE, keys_ui::SERVER_TAKE_BUTTON)),
            ),
            #[cfg(feature = "security-key")]
            Hold::Undone(list) => (
                fill(vault::REMOVE_UNDONE, &[list]),
                TONE_DANGER,
                Some((keys_ui::LOST_REDO, keys_ui::REDO_BUTTON)),
            ),
        })
    }
}
#[cfg(test)]
thread_local! {
    /// What the Keys screen shows, set by a test in place of the session's.
    static KEYS_VIEW: RefCell<Option<KeysView>> = const { RefCell::new(None) };
}
/// The login screen's note under the button (the security-key build's
/// S-LOGIN-NOTE and S-LOGIN-PWONLY take its place for such key files).
/// Every re-authentication's password field (spec §2.29): an open vault
/// asks again to make sure it is its owner at the keyboard.
const REAUTH_LABEL: &str = "본인 확인: 현재 비밀번호";
const REAUTH_LABEL_ADOPT: &str = "본인 확인: 이 PC의 현재 비밀번호";
/// Restore's labels and note (spec §2.29): a backup made with "금고 백업",
/// the key file it was made with, and where the vault comes back to.
const RESTORE_BACKUP_LABEL: &str = "금고 백업 파일 (.goyo) · '찾기'로 선택";
const RESTORE_KEY_LABEL: &str = "그 백업을 만들 때 쓰던 열쇠 파일";
const RESTORE_DEST_LABEL: &str = "되살린 금고를 저장할 새 위치";
const RESTORE_NOTE: &str = "'금고 백업'으로 만든 파일을 새 금고 파일로 되살립니다. 백업을 만들 때 쓰던 열쇠 파일(또는 '열쇠 백업')과 그때의 비밀번호가 필요합니다.";
/// The login's note when the key file is not on this PC (spec §2.29).
const KEY_MISSING_NOTE: &str = "열쇠 파일이 이 PC에 없습니다. 다른 PC에서 가져온 금고라면 그 PC의 열쇠 파일을 USB로 가져와 이 금고 옆에 {name} 이름으로 두세요.";
/// The same for a key file kept elsewhere (a USB stick not plugged in).
const KEY_ELSEWHERE_NOTE: &str = "열쇠 파일 {name}이(가) 보이지 않습니다. USB 등에 두었다면 꽂은 뒤 여세요. 다른 곳에 있으면 '찾기'로 고르세요.";
const LOGIN_PLAIN_NOTE: &str = "열쇠 파일은 비밀번호로 암호화되어 있습니다. 금고와 분리 보관하면 보호가 강화됩니다.\r\n분실한 비밀번호·열쇠를 우회하는 복구 기능은 없습니다.";
/// S-OLDER (spec §5.1): asked before a login opens a vault file saved
/// under an older key of the key file, default No.
const OLDER_QUESTION: &str = "이 금고 파일은 이 열쇠 파일의 예전 열쇠로 저장되어 있습니다.\n다른 PC에서 열쇠를 바꾼 뒤 이 PC에서 처음 여는 것이라면 정상입니다(같은 열쇠 파일을 함께 쓰거나 새 열쇠 파일을 옮겨 온 경우).\n그런 일이 없었다면 예전 열쇠를 가진 누군가가 금고 파일을 바꿔 넣었을 수 있습니다. 그 경우 '아니요'를 누르고 백업이나 서버 기록을 확인하세요.\n이 파일을 열고 새 열쇠로 다시 저장할까요?";
/// S-OLDER answered no: not opened, and not a failed attempt.
const OLDER_DECLINED: &str = "열지 않았습니다. 백업에서 복원이나 서버 기록을 확인하세요.";
/// A key or password flow that ended at the user's No or Cancel, with no
/// line of its own (see told_how_it_ended).
const FLOW_CANCELLED: &str = "취소했습니다. 바뀐 것은 없습니다.";
/// The same for a flow whose screen changed under it.
const FLOW_STOPPED: &str = "화면이 바뀌어 작업을 멈췄습니다. 바뀐 것은 없습니다.";
/// S-ROTATE (spec §9.3), asked before a password change; the synced
/// paragraph for a vault that syncs.
const ROTATE_QUESTION: &str = "열쇠를 바꿉니다. 새 데이터 키로 금고를 다시 암호화하고 새 열쇠 파일을 씁니다.\n• 바꾼 뒤에는 예전 열쇠 파일과 예전 비밀번호(또는 뺀 보안 키)로 앞으로 저장하는 내용을 열 수 없습니다. 바꾸기 전에 만든 백업과 서버의 예전 버전은 예전 열쇠 사본으로 계속 열립니다.\n• 0.8 이하 버전에서는 이 금고를 열 수 없게 됩니다.\n• 끝나면 새 열쇠 파일을 백업하세요.\n계속할까요?";
const ROTATE_QUESTION_SYNCED: &str = "열쇠를 바꿉니다. 새 데이터 키로 금고를 다시 암호화하고 새 열쇠 파일을 씁니다.\n• 바꾼 뒤에는 예전 열쇠 파일과 예전 비밀번호(또는 뺀 보안 키)로 앞으로 저장하는 내용을 열 수 없습니다. 바꾸기 전에 만든 백업과 서버의 예전 버전은 예전 열쇠 사본으로 계속 열립니다.\n• 0.8 이하 버전에서는 이 금고를 열 수 없게 됩니다.\n• 끝나면 새 열쇠 파일을 백업하세요.\n• 동기화 중인 금고입니다. 다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다(USB로 '새 열쇠 파일 받기'). 열쇠는 한 번에 한 PC에서만 바꾸고, 서버 스크립트와 모든 PC(고요 금고·goyo-sync)를 먼저 0.9.0으로 업데이트하세요.\n계속할까요?";
/// S-BACKUP: asked after a key change wrote a new key file.
const BACKUP_QUESTION: &str = "열쇠 파일이 바뀌었습니다. 새 열쇠 파일을 지금 백업할까요?\n이제 금고를 여는 데 필요한 것은 이 새 열쇠 파일입니다. 예전 '열쇠 백업'으로는 앞으로 저장하는 항목을 열 수 없으니, 이 PC나 열쇠 파일을 잃을 때를 대비해 새 사본을 USB 등 금고와 다른 곳에 두세요.";
/// The save dialogs of "금고 백업" and "열쇠 백업": what each file is and
/// where to keep it (spec §2.29).
const VAULT_BACKUP_TITLE: &str =
    "금고 백업 저장 · 항목이 담긴 금고 파일의 사본 (열려면 열쇠 파일과 비밀번호도 필요)";
const KEY_BACKUP_TITLE: &str = "열쇠 백업 저장 · 열쇠 파일의 사본, 금고와 다른 곳(USB 등)에 보관";
/// A file dialog that could not open (spec §2.29: never a silent end).
const DIALOG_FAILED: &str = "파일을 고르는 창을 열지 못했습니다. 경로에 쓸 수 없는 문자가 있거나 폴더에 접근할 수 없을 수 있습니다. 다시 하거나 다른 폴더를 고르세요.";
/// S-KEYDAMAGED-SAVE as a question (spec §5.5 S2): whether the new key
/// file was saved is unknown, so it is saved from memory before the lock.
const KEY_DAMAGED_SAVE: &str = "열쇠 파일을 저장했는지 확인하지 못했습니다. 잠그기 전에 새 열쇠 파일을 다른 저장장치에 저장하세요. 그 파일과 새 비밀번호(와 보안 키)로 이 금고를 열 수 있습니다.\n지금 저장할까요?";
/// The status line of a password change, then S-CODE with the key code.
const PASSWORD_CHANGED: &str = "비밀번호를 바꾸고 금고를 새 열쇠로 다시 암호화했습니다.";
const CODE_LINE: &str =
    "열쇠 확인 코드: {code}. 다른 PC에서 새 열쇠 파일을 받은 뒤 그 PC의 코드와 같은지 비교하세요.";
/// The key backup's own status line (see modal_command).
const KEY_BACKED_UP: &str = "암호화된 열쇠를 백업했습니다. 금고와 분리하여 보관하세요.";
/// S-NEWPASS-OTHER: the other file does not open with this PC's password.
const NEWPASS_OTHER: &str =
    "받을 열쇠 파일은 다른 비밀번호로 잠겨 있습니다. 그 PC에서 바꾼 새 비밀번호를 입력하세요.";
/// The adopt preview (spec §9.1, §5.8): what is done with the other file,
/// the result's revision, a successor's key code and the password in force.
const ADOPT_SUCCESSOR: &str =
    "이 열쇠 파일은 이 PC의 열쇠 파일에서 이어진 새 버전입니다. 그대로 받습니다.";
const ADOPT_UNION: &str = "이 열쇠 파일은 이 PC의 열쇠 파일과 갈라졌거나, 이 PC에서 추가한 것이 빠져 있습니다. 두 파일을 합치고 새 데이터 키(보안 키가 있으면 새 키세트 비밀도)로 금고를 다시 암호화합니다. 다른 PC는 그 뒤 이 PC의 열쇠 파일을 받아야 합니다.";
const ADOPT_RESULT: &str = "받은 뒤의 열쇠 파일: 수정 {epoch}";
/// S-ADOPT-CODE: a successor's code in the preview, every result's after
/// the write.
const ADOPT_CODE: &str = "받은 뒤의 열쇠 확인 코드: {code}";
/// The unlock's usual line, when nothing else is said.
const UNLOCKED: &str =
    "잠금 해제됨 · 저장하면 즉시 암호화됩니다. 화면 캡처는 막지만 악성코드까지 막지는 못합니다.";
const UNLOCKED_NO_AUTO_LOCK: &str =
    "잠금 해제됨 · 자동 잠금이 꺼져 있습니다. 자리를 비울 때는 잠금 버튼이나 Win+L을 누르세요.";
/// Whether a status line is the unlock's usual line (a later status may
/// drop it to make room).
#[cfg(feature = "security-key")]
fn usual_unlock_line(line: &str) -> bool {
    [UNLOCKED, UNLOCKED_NO_AUTO_LOCK]
        .iter()
        .any(|t| line == *t || line == tr(t))
}
const ADOPT_PASS_OWN: &str = "앞으로도 이 PC의 비밀번호로 엽니다.";
const ADOPT_PASS_OTHER: &str = "앞으로는 가져온 열쇠 파일의 비밀번호로 엽니다.";
const OWN_PASS_LABEL: &str = "이 PC의 비밀번호 쓰기";
/// S-ADOPT-BOTHPASS, asked at [받기] where the preview needs it.
const ADOPT_BOTHPASS: &str = "두 PC에서 모두 비밀번호를 바꿨습니다. 앞으로 쓸 비밀번호를 정하세요. '이 PC의 비밀번호 쓰기'를 켜면 이 PC의 비밀번호를, 끄면 가져온 열쇠 파일의 비밀번호를 씁니다. 다른 PC는 받을 때 그 비밀번호를 입력합니다. 이대로 받을까요?";
/// The Keys screen's flows that end with no key change.
const HEAD_OVERRIDDEN: &str =
    "서버 사본 대신 이 PC의 상태를 올립니다. goyo-sync가 올리면 동기화가 다시 이어집니다.";
const KEY_FILE_CONFIRMED: &str =
    "지금 열쇠 파일을 이 금고의 열쇠 파일로 정했습니다. 동기화와 열쇠 변경을 다시 할 수 있습니다.";
/// Its second line for a vault that syncs: a server copy under the newer
/// key file that was put aside halts sync again (spec §2.18 #57).
const KEY_FILE_CONFIRMED_SYNCED: &str = "서버 사본이 더 나중의 열쇠로 저장되어 있으면 동기화가 다시 멈춥니다. 그 사본을 이 PC가 올렸다면 [서버 사본을 이 PC 상태로 덮어쓰기…]를 누르세요.";
/// The wait after a failed authentication.
const RETRY_WAIT: &str = "인증 실패 후 대기 중입니다. 잠시 후 다시 시도하세요.";
impl App {
    fn new(hwnd: Hwnd) -> Self {
        let (scale, font) = theme::with(|t| (t.scale, t.body())).unwrap_or((1.0, 0));
        let base = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_owned()))
            .unwrap_or_default();
        let mut app = Self {
            hwnd,
            font,
            scale,
            controls: BTreeMap::new(),
            children: vec![],
            edits: vec![],
            frames: vec![],
            screen: Screen::Login,
            session: None,
            provision: None,
            selected: None,
            editing: None,
            vault_path: base.join("vault.goyo"),
            key_path: base.join("vault.goyokey"),
            new_vault_path: PathBuf::new(),
            new_key_path: PathBuf::new(),
            backup_path: PathBuf::new(),
            dest_path: PathBuf::new(),
            home_dir: base,
            activity: Instant::now(),
            copy_until: None,
            reveal_until: None,
            clipboard: None,
            failed: 0,
            retry: Instant::now(),
            status: line("금고·열쇠 파일을 확인하고 비밀번호를 입력하세요."),
            weakened: None,
            pinned: None,
            page: 0,
            closing: false,
            auth_dirty: false,
            input_failed: false,
            from_welcome: false,
            away_since: None,
            inactive: false,
            shown: [false; PEEK_FIELDS.len()],
            qr: None,
            status_tone: TONE_MUTED,
            auto_lock: load_auto_lock(),
            sync_ticks: 0,
            sync_badge: None,
            serial: 0,
            flow: None,
            told: 0,
            prompt: String::new(),
            keys_shown: None,
            adopt_source: None,
            #[cfg(feature = "security-key")]
            toggles: keys_ui::Toggles::default(),
            #[cfg(feature = "security-key")]
            forget_for: None,
        };
        // The last vault and key that opened, so a key kept on a USB drive does
        // not have to be picked with "찾기" on every start.
        if let Some((vault, key)) = load_paths()
            && (vault.is_file() || vault_candidates(&vault))
        {
            app.vault_path = vault;
            app.key_path = key;
        }
        app
    }
    fn px(&self, n: i32) -> i32 {
        (n as f32 * self.scale) as i32
    }
    fn r(&self, x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect {
            left: self.px(x),
            top: self.px(y),
            right: self.px(x + w),
            bottom: self.px(y + h),
        }
    }
    fn scaled(&self, r: &Rect) -> Rect {
        self.r(r.left, r.top, r.right - r.left, r.bottom - r.top)
    }
    fn font_of(&self, pick: fn(&theme::Theme) -> isize) -> isize {
        theme::with(pick).unwrap_or(self.font)
    }
    #[allow(clippy::too_many_arguments)] // Native control geometry follows Win32.
    fn ctrl(
        &mut self,
        id: i32,
        class: &str,
        text: &str,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        style: u32,
    ) -> Hwnd {
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                wide(class).as_ptr(),
                secret_wide(if class == "EDIT" { text } else { tr(text) }).as_ptr(),
                0x50000000 | style,
                self.px(x),
                self.px(y),
                self.px(w),
                self.px(h),
                self.hwnd,
                id as isize,
                GetModuleHandleW(null()),
                null_mut(),
            )
        };
        if hwnd == 0 {
            std::process::abort();
        }
        unsafe {
            // No redraw yet: owner-drawn and toned controls get their style next.
            SendMessageW(hwnd, 0x30, self.font_of(|t| t.body()) as usize, 0);
        }
        self.children.push(hwnd);
        if id != 0 {
            self.controls.insert(id, hwnd);
        }
        hwnd
    }
    /// Static text. `tone` (GWLP_USERDATA) selects the colour in WM_CTLCOLORSTATIC.
    #[allow(clippy::too_many_arguments)] // Native control geometry follows Win32.
    fn text(
        &mut self,
        id: i32,
        text: &str,
        (x, y, w, h): (i32, i32, i32, i32),
        font: isize,
        tone: isize,
        style: u32,
    ) -> Hwnd {
        let h = self.ctrl(id, "STATIC", text, x, y, w, h, 0x80 | style);
        unsafe {
            SetWindowLongPtrW(h, -21, tone);
            SendMessageW(h, 0x30, font as usize, 0);
        }
        h
    }
    fn label(&mut self, text: &str, x: i32, y: i32, w: i32) {
        self.label_as(0, text, x, y, w);
    }
    /// A caption with control ID `id`, for one whose text or place changes.
    fn label_as(&mut self, id: i32, text: &str, x: i32, y: i32, w: i32) {
        let small = self.font_of(|t| t.small());
        self.text(id, text, (x, y, w, 20), small, TONE_MUTED, 0);
    }
    fn note(&mut self, text: &str, x: i32, y: i32, w: i32, h: i32) {
        let small = self.font_of(|t| t.small());
        self.text(0, text, (x, y, w, h), small, TONE_MUTED, 0);
    }
    #[allow(clippy::too_many_arguments)] // Native control geometry follows Win32.
    fn button(&mut self, id: i32, text: &str, x: i32, y: i32, w: i32, h: i32, variant: isize) {
        // BS_OWNERDRAW; theme::draw_item paints it from the variant.
        let b = self.ctrl(id, "BUTTON", text, x, y, w, h, 0x10000 | 0xb);
        unsafe {
            SetWindowLongPtrW(b, -21, variant);
        }
    }
    /// Borderless edit inside a painted frame at (x, y, w, h). `reserve` keeps
    /// room on the right of the frame for an inline button.
    #[allow(clippy::too_many_arguments)] // Native control geometry follows Win32.
    fn input(
        &mut self,
        id: i32,
        text: &str,
        (x, y, w, h): (i32, i32, i32, i32),
        password: bool,
        multiline: bool,
        reserve: i32,
    ) {
        let style = 0x10000
            | if multiline { 0x1044 | 0x200000 } else { 0x80 }
            | if password { 0x20 } else { 0 };
        let (ix, iy, iw, ih) = if multiline {
            (x + 12, y + 8, w - 16 - reserve, h - 16)
        } else {
            (x + 12, y + (h - 24) / 2, w - 24 - reserve, 24)
        };
        let edit = self.ctrl(id, "EDIT", "", ix, iy, iw, ih, style);
        self.frames.push((
            Rect {
                left: x,
                top: y,
                right: x + w,
                bottom: y + h,
            },
            edit,
        ));
        unsafe {
            if password {
                // Cosmetic mask; set before the subclass blocks EM_SETPASSWORDCHAR.
                SendMessageW(edit, 0xcc, '•' as usize, 0);
            }
            let orig = SetWindowLongPtrW(edit, -4, edit_proc as *const () as isize);
            if orig == 0 {
                std::process::abort();
            }
            let original = std::mem::transmute::<isize, Proc>(orig);
            EDIT_PROC.get_or_init(|| original);
            // Apply private input handling before providing any initial value.
            // Password scope is a hint to OS text services, not an isolation boundary.
            let scope_ok = SetInputScope(edit, 31) == 0;
            let ime_ok = if matches!(id, SECRET | NOTES | OTP_FIELD) {
                ImmAssociateContextEx(edit, 0, 0);
                let context = ImmGetContext(edit);
                if context != 0 {
                    ImmReleaseContext(edit, context);
                }
                context == 0
            } else {
                true
            };
            if !scope_ok || !ime_ok {
                self.input_failed = true;
                EnableWindow(edit, 0);
                self.status = line(
                    "입력 보호 설정 실패. 프로그램을 다시 시작하고 Windows 입력기를 확인하세요.",
                );
            }
            SendMessageW(
                edit,
                0xc5,
                if matches!(id, PASS | CONFIRM | CURRENT_PASS) {
                    1024
                } else if id == TITLE {
                    256
                } else if matches!(id, KIND | OTP_ISSUER | OTP_ACCOUNT) {
                    64
                } else if id == OTP_FIELD {
                    otp::MAX_INPUT
                } else {
                    8192
                },
                0,
            );
            SendMessageW(edit, 0xcd, 0, 0);
            if scope_ok && ime_ok {
                SetWindowTextW(edit, secret_wide(text).as_ptr());
            }
        }
        self.edits.push(edit);
    }
    /// Small caption above a 40px single-line input.
    #[allow(clippy::too_many_arguments)] // Native control geometry follows Win32.
    fn field(&mut self, id: i32, label: &str, value: &str, x: i32, y: i32, w: i32, password: bool) {
        self.field_as(0, id, label, value, (x, y, w), password);
    }
    /// field() with its caption's control ID.
    fn field_as(
        &mut self,
        label_id: i32,
        id: i32,
        label: &str,
        value: &str,
        (x, y, w): (i32, i32, i32),
        password: bool,
    ) {
        self.label_as(label_id, label, x, y, w);
        self.input(id, value, (x, y + 22, w, 40), password, false, 0);
    }
    /// Masked field with an eye button that shows what was typed.
    fn password_field(&mut self, id: i32, label: &str, x: i32, y: i32, w: i32) {
        self.password_field_as(0, id, label, x, y, w);
    }
    /// password_field() with its caption's control ID.
    fn password_field_as(&mut self, label_id: i32, id: i32, label: &str, x: i32, y: i32, w: i32) {
        self.label_as(label_id, label, x, y, w);
        self.input(id, "", (x, y + 22, w, 40), true, false, 36);
        let peek = PEEK_FIELDS.iter().find(|(_, f)| *f == id).map(|(p, _)| *p);
        if let Some(peek) = peek {
            // Not a tab stop, so Tab still goes from password to the next field.
            let b = self.ctrl(
                peek,
                "BUTTON",
                "비밀번호 보기",
                x + w - 38,
                y + 26,
                32,
                32,
                0xb,
            );
            unsafe {
                SetWindowLongPtrW(b, -21, theme::EYE);
            }
        }
    }
    /// Shows or hides the typed password. This is the only way to change the
    /// mask: edit_proc drops EM_SETPASSWORDCHAR and every other message sent
    /// by another program, and window_proc ignores their WM_COMMANDs.
    /// Shown text stays behind the same protections as masked text (no
    /// copy, no external read, capture exclusion), and every rebuild (lock,
    /// idle timeout, screen change) and app switch masks it again.
    fn peek(&mut self, button: i32) -> crypto::Result<()> {
        let Some(i) = PEEK_FIELDS.iter().position(|(p, _)| *p == button) else {
            return Ok(());
        };
        let edit = self.handle(PEEK_FIELDS[i].1);
        if edit == 0 {
            return Ok(());
        }
        self.set_shown(i, !self.shown[i])?;
        unsafe {
            // Keep typing where the user left off.
            SetFocus(edit);
        }
        Ok(())
    }
    /// Rebuilds the screen and puts back what was typed into `ids`.
    fn rebuild_keeping(&mut self, ids: &[i32]) {
        let kept: Vec<_> = ids.iter().map(|&id| (id, self.read(id))).collect();
        let _ = self.paths();
        self.build();
        if self.input_failed {
            return;
        }
        for (id, text) in kept {
            if let Ok(text) = text {
                unsafe {
                    SetWindowTextW(self.handle(id), secret_wide(&text).as_ptr());
                }
            }
        }
    }
    /// What the key file an unlock reads states before any password: the
    /// chosen one, or the temp file an interrupted save left in its place.
    fn unlock_key_info(&self) -> Option<KeyInfo> {
        let vault = if self.screen == Screen::Restore {
            &self.backup_path
        } else {
            &self.vault_path
        };
        // The server's key file in the fetched vault's key view (spec
        // §7.17, §2.29).
        #[cfg(feature = "security-key")]
        if self.screen == Screen::Fetched {
            return vault::fetched_key_info(vault);
        }
        let key = key_candidate(vault, &self.key_path).unwrap_or_else(|| self.key_path.clone());
        key_info(&key)
    }
    /// Masks every password field, whatever its recorded state, and never
    /// moves focus, so it is safe while another app is being activated.
    fn mask_passwords(&mut self) {
        for i in 0..PEEK_FIELDS.len() {
            let _ = self.set_shown(i, false); // masking cannot fail
        }
    }
    fn set_shown(&mut self, i: usize, show: bool) -> crypto::Result<()> {
        let (button, field) = PEEK_FIELDS[i];
        let (edit, b) = (self.handle(field), self.handle(button));
        if edit == 0 || b == 0 {
            return Ok(());
        }
        let original = EDIT_PROC.get().copied();
        unsafe {
            let mask = if show { 0 } else { '•' as usize };
            CallWindowProcW(original, edit, 0xcc, mask, 0);
            if show {
                // Clearing ES_PASSWORD hands the edit its IME context back, which
                // would turn on Hangul input and let text services learn the
                // password. Take it away again; if that fails, mask again.
                ImmAssociateContextEx(edit, 0, 0);
                let context = ImmGetContext(edit);
                if context != 0 {
                    ImmReleaseContext(edit, context);
                }
                if context != 0 || SetInputScope(edit, 31) != 0 {
                    CallWindowProcW(original, edit, 0xcc, '•' as usize, 0);
                    self.shown[i] = false;
                    return Err("입력 보호를 확인할 수 없어 비밀번호를 표시하지 않았습니다.");
                }
            }
            self.shown[i] = show;
            SetWindowLongPtrW(b, -21, if show { theme::EYE_ON } else { theme::EYE });
            let name = if show {
                "비밀번호 숨기기"
            } else {
                "비밀번호 보기"
            };
            SetWindowTextW(b, wide(tr(name)).as_ptr());
            InvalidateRect(b, null(), 0);
            InvalidateRect(edit, null(), 1);
        }
        Ok(())
    }
    /// The login's note for a key file that is not on this PC (spec §2.29):
    /// the vault file is there, and neither its key file nor the temp file
    /// of a cut-off save.
    fn missing_key_note(&self, vault: &Path, key: &Path) -> Option<String> {
        if self.screen != Screen::Login
            || !vault.is_file()
            || key.as_os_str().is_empty()
            || key.is_file()
            || key_candidate(vault, key).is_some()
            || leftover_temp(key)
        {
            return None;
        }
        let own = vault.with_extension("goyokey");
        let synced = syncfile::sync_dir(vault).is_some_and(|d| d.is_dir());
        if key != own && !synced {
            let name = key.file_name()?.to_string_lossy().into_owned();
            return Some(fill(KEY_ELSEWHERE_NOTE, &[&name]));
        }
        let name = own.file_name()?.to_string_lossy().into_owned();
        Some(fill(KEY_MISSING_NOTE, &[&name]))
    }
    /// Key path caption; warns when the placement undoes the key file's
    /// protection. Refreshed whenever a path field changes.
    fn refresh_key_note(&mut self) {
        let h = self.handle(KEY_NOTE);
        if h == 0 {
            return;
        }
        let (Ok(vault), Ok(key)) = (self.read(VPATH), self.read(KPATH)) else {
            return;
        };
        let create = self.screen == Screen::Create;
        let warning = placement_warning(Path::new(vault.as_str()), Path::new(key.as_str()));
        let text = match (warning, create) {
            (Some(Placement::SameFolder), true) => {
                "새 열쇠 파일 · 금고와 같은 폴더라 함께 도난당하면 비밀번호만 남습니다"
            }
            (Some(Placement::SameFolder), false) => "열쇠 파일 · 금고와 같은 폴더에 있습니다",
            (Some(Placement::Cloud), true) => {
                "새 열쇠 파일 · 금고와 함께 클라우드 동기화 폴더에 있습니다"
            }
            (Some(Placement::Cloud), false) => {
                "열쇠 파일 · 금고와 함께 클라우드 동기화 폴더에 있습니다"
            }
            (None, true) => "새 열쇠 파일 · 금고와 다른 곳(USB 등)에 두세요",
            (None, false) if self.screen == Screen::Restore => RESTORE_KEY_LABEL,
            (None, false)
                if self
                    .missing_key_note(Path::new(vault.as_str()), Path::new(key.as_str()))
                    .is_some() =>
            {
                "열쇠 파일 · 이 경로에 없습니다"
            }
            (None, false) => "열쇠 파일",
        };
        unsafe {
            SetWindowLongPtrW(
                h,
                -21,
                if warning.is_some()
                    || self
                        .missing_key_note(Path::new(vault.as_str()), Path::new(key.as_str()))
                        .is_some()
                {
                    TONE_DANGER
                } else {
                    TONE_MUTED
                },
            );
            SetWindowTextW(h, wide(tr(text)).as_ptr());
            InvalidateRect(h, null(), 1);
        }
        #[cfg(feature = "security-key")]
        if !create {
            self.refresh_login_extra(Path::new(vault.as_str()), Path::new(key.as_str()));
        }
    }
    fn path_field(&mut self, id: i32, browse: i32, label: &str, value: &str, y: i32) {
        // The key caption is addressable: refresh_key_note rewrites it.
        let small = self.font_of(|t| t.small());
        let caption = if id == KPATH { KEY_NOTE } else { 0 };
        self.text(caption, label, (AX, y, AW, 20), small, TONE_MUTED, 0);
        self.input(id, value, (AX, y + 22, AW, 40), false, false, 64);
        self.button(browse, "찾기", AX + AW - 70, y + 26, 64, 32, theme::GHOST);
    }
    fn handle(&self, id: i32) -> Hwnd {
        *self.controls.get(&id).unwrap_or(&0)
    }
    fn entry(&self) -> Option<&Entry> {
        self.selected
            .and_then(|i| self.session.as_ref()?.entries.get(i))
    }
    fn read(&self, id: i32) -> crypto::Result<Zeroizing<String>> {
        let h = self.handle(id);
        if h == 0 {
            return Ok(Zeroizing::new(String::new()));
        }
        INTERNAL_READ.with(|flag| {
            let prior = flag.replace(true);
            let n = unsafe { GetWindowTextLengthW(h) }.clamp(0, 32767) as usize;
            let mut buf = Zeroizing::new(vec![0u16; n + 1]);
            let got =
                unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) }.max(0) as usize;
            flag.set(prior);
            secret_utf8(&buf[..got])
        })
    }
    fn clear_controls(&mut self) {
        for h in self.edits.drain(..) {
            unsafe {
                let n = INTERNAL_READ.with(|f| {
                    let old = f.replace(true);
                    let n = GetWindowTextLengthW(h).clamp(0, 32767) as usize;
                    f.set(old);
                    n
                });
                let replacement = secret_wide(&" ".repeat(n));
                SendMessageW(h, 0xb1, 0, -1);
                SendMessageW(h, 0xc2, 0, replacement.as_ptr() as isize);
                SetWindowTextW(h, wide("").as_ptr());
                SendMessageW(h, 0xcd, 0, 0);
                SetInputScope(h, 0);
            }
        }
        for h in self.children.drain(..) {
            unsafe {
                DestroyWindow(h);
            }
        }
        self.controls.clear();
        self.frames.clear();
        self.shown = [false; PEEK_FIELDS.len()];
    }
    fn status(&mut self, text: &str) {
        self.set_status(text, TONE_MUTED);
    }
    /// A process protection stopped holding: said at once in the danger
    /// tone, and kept for the header pill and later screens (`weakened`).
    fn weaken(&mut self, why: &'static str) {
        if self.weakened.is_none() {
            self.weakened = Some(why);
            self.status_tone = TONE_DANGER;
            self.set_status(why, TONE_DANGER);
            if self.hwnd != 0 {
                unsafe {
                    InvalidateRect(self.hwnd, null(), 0);
                }
            }
        }
    }
    /// The header pill's words: the lock state, and first a weakened
    /// process protection.
    fn pill_text(&self, state: String) -> String {
        match self.weakened {
            Some(_) => fill("보호 약화 · {}", &[&state]),
            None => state,
        }
    }
    /// Errors stay on the screen in the status line instead of a modal box.
    /// A save cut off by the replace gap also locks: the newest state is
    /// only in a temp file, which the next unlock takes back, and the
    /// session writes nothing more meanwhile.
    fn error(&mut self, text: &str) {
        if [GAP_KEPT, vault::GAP_CHANGED, vault::GAP_NOT_CHANGED].contains(&text)
            && self.session.is_some()
        {
            self.lock(text, true);
        }
        // A refusal that names an epoch, a path or a reason is filled in;
        // a reason is text of its own, translated as well.
        let filled = vault::refusal_values(text).map(|values| {
            let values: Vec<&str> = values.iter().map(|v| tr(v)).collect();
            let values: Vec<&dyn std::fmt::Display> =
                values.iter().map(|v| v as &dyn std::fmt::Display).collect();
            fill(text, &values)
        });
        self.set_status(filled.as_deref().unwrap_or(text), TONE_DANGER);
        unsafe {
            MessageBeep(0x30);
        }
    }
    /// A flow's progress line (see `prompt`), in the muted tone; only the
    /// security-key build's ceremonies show one.
    #[cfg(feature = "security-key")]
    fn prompt(&mut self, text: &str) {
        self.set_status(text, TONE_MUTED);
        self.prompt.clear();
        self.prompt.push_str(text);
    }
    /// `text` with the pinned notice first, unless it holds it already.
    fn with_pinned(&self, text: &str) -> Zeroizing<String> {
        match self.pinned.as_deref() {
            Some(p) if text.is_empty() => Zeroizing::new(p.to_owned()),
            Some(p) if !text.contains(p.as_str()) => joined(&[p.as_str(), text]),
            _ => Zeroizing::new(text.to_owned()),
        }
    }
    fn set_status(&mut self, text: &str, tone: isize) {
        self.told = self.told.wrapping_add(1);
        let (text, tone) = match self.pinned {
            Some(_) => (self.with_pinned(text), TONE_DANGER),
            None => (Zeroizing::new(text.to_owned()), tone),
        };
        let text = text.as_str();
        // Wipe the line it replaces, before the buffer may grow.
        self.status.zeroize();
        self.status.push_str(text);
        let h = self.handle(STATUS);
        unsafe {
            // Tone first: setting the text repaints the label.
            SetWindowLongPtrW(h, -21, tone);
            SetWindowTextW(h, secret_wide(&tr_lines(text)).as_ptr());
            InvalidateRect(h, null(), 1);
        }
    }
    /// Where a path field's value lives on the current screen.
    fn path_slot(&mut self, field: i32) -> &mut PathBuf {
        match (field, self.screen) {
            (VPATH, Screen::Create) => &mut self.new_vault_path,
            (VPATH, Screen::Restore) => &mut self.backup_path,
            (VPATH, _) => &mut self.vault_path,
            (KPATH, Screen::Create) => &mut self.new_key_path,
            (KPATH, _) => &mut self.key_path,
            _ => &mut self.dest_path,
        }
    }
    fn paths(&mut self) -> crypto::Result<()> {
        for field in [VPATH, KPATH, DEST] {
            if self.handle(field) != 0 {
                let p = PathBuf::from(self.read(field)?.as_str());
                *self.path_slot(field) = p;
            }
        }
        Ok(())
    }
    /// Every screen change goes through here (see serial).
    /// Every screen change, a lock's included, takes the QR panel away.
    fn show(&mut self, screen: Screen) {
        self.screen = screen;
        self.serial += 1;
        self.qr = None;
    }
    /// Login when a vault exists at the current path (or only its temp file,
    /// which the unlock takes back), otherwise Welcome.
    fn home(&self) -> Screen {
        // A vault goyo-sync brought from the server with its key file, which
        // this PC has not saved yet (spec §2.29).
        #[cfg(feature = "security-key")]
        if keys_ui::fetched_pending(&self.vault_path, &self.key_path) {
            return Screen::Fetched;
        }
        if self.vault_path.is_file() || vault_candidates(&self.vault_path) {
            Screen::Login
        } else {
            Screen::Welcome
        }
    }
    /// Suggests file names that do not exist yet for Create and Restore.
    fn default_paths(&mut self) {
        let dir = self.home_dir.clone();
        let free = |names: &mut dyn Iterator<Item = String>| {
            names.take(100).find(|stem| {
                !dir.join(format!("{stem}.goyo")).exists()
                    && !dir.join(format!("{stem}.goyokey")).exists()
            })
        };
        let numbered = |base: &'static str| {
            (1..).map(move |n| {
                if n == 1 {
                    base.to_owned()
                } else {
                    format!("{base}-{n}")
                }
            })
        };
        match self.screen {
            Screen::Create
                if self.new_vault_path.as_os_str().is_empty()
                    || self.new_vault_path.exists()
                    || self.new_key_path.exists() =>
            {
                if let Some(stem) = free(&mut numbered("vault")) {
                    self.new_vault_path = dir.join(format!("{stem}.goyo"));
                    self.new_key_path = dir.join(format!("{stem}.goyokey"));
                }
            }
            Screen::Restore if self.dest_path.as_os_str().is_empty() || self.dest_path.exists() => {
                // A first restore on a new PC becomes the vault opened next time.
                let mut names = std::iter::once("vault".to_owned()).chain(numbered("restored"));
                if let Some(stem) = free(&mut names) {
                    self.dest_path = dir.join(format!("{stem}.goyo"));
                }
            }
            _ => {}
        }
    }
    fn build(&mut self) {
        // The TOFU banner's code survives a rebuild (a sync event, a failed
        // step): it is public, and retyping it is where users give up.
        #[cfg(feature = "security-key")]
        let code = (self.screen == Screen::Vault)
            .then(|| self.read(keys_ui::GATE_CODE).ok())
            .flatten()
            .filter(|c| !c.is_empty());
        self.told = self.told.wrapping_add(1);
        self.clear_controls();
        self.input_failed = false;
        match self.screen {
            Screen::Welcome => self.build_welcome(),
            Screen::Login | Screen::Create | Screen::Restore => self.build_auth(),
            Screen::Vault => self.build_vault(),
            Screen::Edit => self.build_edit(),
            Screen::Password => self.build_password(),
            Screen::Keys => self.build_keys(),
            Screen::Adopt => self.build_adopt(),
            #[cfg(feature = "security-key")]
            Screen::Pair => self.build_pair(),
            #[cfg(feature = "security-key")]
            Screen::LostKey | Screen::KeyRemove => self.build_remove(),
            #[cfg(feature = "security-key")]
            Screen::Review => self.build_review(),
            #[cfg(feature = "security-key")]
            Screen::Fetched => self.build_fetched(),
        }
        let small = self.font_of(|t| t.small());
        let mut tone = std::mem::replace(&mut self.status_tone, TONE_MUTED);
        if let Some(why) = self.weakened.filter(|_| self.status.is_empty()) {
            self.status.push_str(why);
            tone = TONE_DANGER;
        }
        if self.pinned.is_some() {
            self.status = self.with_pinned(&self.status);
            tone = TONE_DANGER;
        }
        let status = tr_lines(&self.status);
        self.text(STATUS, &status, (40, 690, 796, 60), small, tone, 0);
        let dark = theme::is_dark();
        let (x, y, _, _) = THEME_SWITCH;
        for (i, (id, name, on)) in [(THEME_DARK, "다크", dark), (THEME_LIGHT, "라이트", !dark)]
            .into_iter()
            .enumerate()
        {
            let variant = if on { theme::TAB_ON } else { theme::TAB };
            self.button(id, name, x + 2 + i as i32 * 65, y + 2, 63, 32, variant);
        }
        let english = i18n::english();
        let (x, y, _, _) = LANG_SWITCH;
        for (i, (id, name, on)) in [(LANG_KO, "한국어", !english), (LANG_EN, "English", english)]
            .into_iter()
            .enumerate()
        {
            let variant = if on { theme::TAB_ON } else { theme::TAB };
            self.button(id, name, x + 2 + i as i32 * 73, y + 2, 71, 32, variant);
        }
        self.theme_scrollbars();
        #[cfg(feature = "security-key")]
        if let Some(code) = code
            && self.handle(keys_ui::GATE_CODE) != 0
        {
            unsafe {
                SetWindowTextW(self.handle(keys_ui::GATE_CODE), wide(&code).as_ptr());
            }
        }
        unsafe {
            InvalidateRect(self.hwnd, null(), 0);
        }
    }
    /// Native scrollbars follow the palette; colours come from WM_CTLCOLOR*.
    fn theme_scrollbars(&self) {
        let name = wide(if theme::is_dark() {
            "DarkMode_Explorer"
        } else {
            "Explorer"
        });
        #[cfg(not(feature = "security-key"))]
        let ids = [LIST, SECRET, NOTES];
        // The Keys screen's list and the review list scroll too.
        #[cfg(feature = "security-key")]
        let ids = [LIST, SECRET, NOTES, keys_ui::KEY_LIST, keys_ui::REVIEW_LIST];
        for id in ids {
            let h = self.handle(id);
            if h != 0 {
                unsafe {
                    SetWindowTheme(h, name.as_ptr(), null());
                }
            }
        }
    }
    fn set_theme(&mut self, dark: bool) {
        theme::set_dark(dark);
        apply_window_theme(self.hwnd);
        self.theme_scrollbars();
        for (id, on) in [(THEME_DARK, dark), (THEME_LIGHT, !dark)] {
            let variant = if on { theme::TAB_ON } else { theme::TAB };
            unsafe {
                SetWindowLongPtrW(self.handle(id), -21, variant);
            }
        }
        unsafe {
            // RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME
            RedrawWindow(self.hwnd, null(), 0, 0x1 | 0x4 | 0x80 | 0x400);
        }
        save_theme(dark);
    }
    /// Switches the interface language. The screen is rebuilt with the new
    /// captions; typed passwords, codes and entry fields are put back.
    fn set_language(&mut self, english: bool) {
        if english == i18n::english() {
            return;
        }
        i18n::set_english(english);
        save_language(english);
        self.status_tone = unsafe { GetWindowLongPtrW(self.handle(STATUS), -21) };
        let typed: Vec<i32> = [
            PASS,
            CONFIRM,
            CURRENT_PASS,
            TITLE,
            KIND,
            SECRET,
            NOTES,
            OTP_FIELD,
            OTP_ISSUER,
            OTP_ACCOUNT,
        ]
        .into_iter()
        .filter(|&id| self.handle(id) != 0)
        .collect();
        self.rebuild_keeping(&typed);
        let button = if english { LANG_EN } else { LANG_KO };
        unsafe {
            SetFocus(self.handle(button));
        }
    }
    /// Empty state: nothing to unlock yet, so no unlock form. The badge,
    /// heading and the "what you need" card are painted.
    fn build_welcome(&mut self) {
        self.button(
            CREATE,
            "새 금고 만들기",
            AX + 100,
            300,
            AW - 200,
            48,
            theme::PRIMARY,
        );
        self.button(
            RESTORE,
            "백업 파일로 되살리기",
            AX + 100,
            358,
            AW - 200,
            44,
            theme::SECONDARY,
        );
        self.button(
            OPEN,
            "금고 파일 열기 (다른 폴더 · 서버에서 가져온 금고)",
            AX,
            410,
            AW,
            32,
            theme::LINK,
        );
        unsafe {
            SetFocus(self.handle(CREATE));
        }
    }
    fn build_auth(&mut self) {
        self.default_paths();
        let mode = self.screen;
        let (vault_path, key_path) = match mode {
            Screen::Create => (&self.new_vault_path, &self.new_key_path),
            Screen::Restore => (&self.backup_path, &self.key_path),
            _ => (&self.vault_path, &self.key_path),
        };
        let vault_path = vault_path.to_string_lossy().into_owned();
        let key_path = key_path.to_string_lossy().into_owned();
        let dest_path = self.dest_path.to_string_lossy().into_owned();
        let title = self.font_of(|t| t.title());
        let heading = match mode {
            Screen::Create => "새 금고 만들기",
            Screen::Restore => "백업 파일로 되살리기",
            _ => "금고 열기",
        };
        self.text(0, heading, (AX, 82, AW - 100, 34), title, TONE_TEXT, 0);
        // Login is the home screen once a vault exists; otherwise every auth
        // screen was reached from Welcome and leads back there.
        if mode != Screen::Login || self.from_welcome {
            self.button(BACK, "‹ 뒤로", AX + AW - 84, 84, 84, 32, theme::GHOST);
        }
        let create = mode == Screen::Create;
        let restore = mode == Screen::Restore;
        let (vault_label, key_label) = if create {
            (
                "새 금고 파일",
                "새 열쇠 파일 · 금고와 따로 보관하면 더 안전합니다",
            )
        } else if restore {
            (RESTORE_BACKUP_LABEL, RESTORE_KEY_LABEL)
        } else {
            ("금고 파일", "열쇠 파일")
        };
        self.path_field(VPATH, BROWSE_V, vault_label, &vault_path, 148);
        self.path_field(KPATH, BROWSE_K, key_label, &key_path, 220);
        let mut y = 292;
        if restore {
            self.path_field(DEST, BROWSE_D, RESTORE_DEST_LABEL, &dest_path, y);
            y += 72;
        }
        if create {
            self.refresh_key_note();
            #[cfg(feature = "security-key")]
            self.build_create_keys();
            let half = (AW - 16) / 2;
            self.password_field(PASS, "비밀번호 · 12자 이상", AX, y, half);
            self.password_field(CONFIRM, "비밀번호 확인", AX + half + 16, y, half);
            self.button(SUBMIT, "금고 만들기", AX, y + 88, AW, 46, theme::PRIMARY);
        } else {
            self.refresh_key_note();
            self.password_field(PASS, "비밀번호", AX, y, AW);
            y += 88;
            let submit = if restore {
                "확인 · 새 파일로 복원"
            } else {
                "잠금 해제"
            };
            self.button(SUBMIT, submit, AX, y, AW, 46, theme::PRIMARY);
            // The security-key build's login note (S-LOGIN-NOTE, S-LOGIN-
            // PWONLY) and the per-vault forget after an anchor refusal take
            // this note's place (spec §9.1).
            #[cfg(feature = "security-key")]
            let keyed = self.build_login_extra(y + 62);
            #[cfg(not(feature = "security-key"))]
            let keyed = false;
            if !keyed {
                // Restore says what it does; a login whose key file is not
                // on this PC says where it comes from (spec §2.29).
                let missing = self.missing_key_note(&self.vault_path, &self.key_path);
                let note = if restore {
                    tr(RESTORE_NOTE).to_owned()
                } else {
                    missing
                        .clone()
                        .unwrap_or_else(|| tr(LOGIN_PLAIN_NOTE).to_owned())
                };
                let small = self.font_of(|t| t.small());
                let tone = if missing.is_some() && !restore {
                    TONE_DANGER
                } else {
                    TONE_MUTED
                };
                self.text(0, &note, (AX, y + 62, AW, 40), small, tone, 0);
            }
            if !restore {
                // Secondary tasks under a painted divider (see LOGIN_LINKS).
                let (_, ly, _, _) = LOGIN_LINKS;
                let mid = AX + AW / 2;
                self.button(
                    CREATE,
                    "새 금고 만들기",
                    mid - 156,
                    ly + 14,
                    148,
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
            }
        }
        let first = if restore && self.backup_path.as_os_str().is_empty() {
            BROWSE_V
        } else {
            PASS
        };
        unsafe {
            SetFocus(self.handle(first));
        }
    }
    fn build_vault(&mut self) {
        let small = self.font_of(|t| t.small());
        self.button(LOCK, "잠금", 462, 22, 84, 34, theme::SECONDARY);
        let count = self.session.as_ref().map_or(0, |s| s.entries.len());
        self.text(
            0,
            &fill("항목 {count}개", &[&count]),
            (40, 90, 150, 22),
            small,
            TONE_MUTED,
            0,
        );
        self.button(NEW, "+ 새 항목", 196, 82, 104, 34, theme::SECONDARY);
        // Owner-drawn fixed rows (0x10 | 0x40) inside a painted frame.
        let list = self.ctrl(
            LIST,
            "LISTBOX",
            "",
            46,
            130,
            248,
            488,
            0x10000 | 0x200000 | 1 | 0x100 | 0x10 | 0x40,
        );
        self.frames.push((
            Rect {
                left: 40,
                top: 124,
                right: 300,
                bottom: 624,
            },
            list,
        ));
        unsafe {
            let orig = SetWindowLongPtrW(list, -4, list_proc as *const () as isize);
            if orig == 0 {
                std::process::abort();
            }
            LIST_PROC.get_or_init(|| std::mem::transmute::<isize, Proc>(orig));
        }
        unsafe {
            SendMessageW(list, 0x1a0, 0, self.px(40) as isize);
        }
        if let Some(session) = self.session.as_ref() {
            for entry in &session.entries {
                let label = secret_wide(&entry.title);
                unsafe {
                    let i = SendMessageW(list, 0x180, 0, label.as_ptr() as isize);
                    // LB_SETITEMDATA: the row's OTP mark (theme::draw_row).
                    if i >= 0 && entry.has_otp() {
                        SendMessageW(list, 0x19a, i as usize, theme::ROW_OTP);
                    }
                }
            }
            if let Some(i) = self.selected.filter(|i| *i < session.entries.len()) {
                unsafe {
                    SendMessageW(list, 0x186, i, 0);
                }
            }
        }
        // Detail card actions; shown only while an entry is selected.
        self.button(EDIT, "수정", 676, 104, 64, 32, theme::GHOST);
        self.button(DELETE, "삭제", 748, 104, 64, 32, theme::DANGER_GHOST);
        self.button(REVEAL, "15초 보기", CARD_X, 322, 104, 36, theme::SECONDARY);
        self.button(TOGGLE, "복사 허용", 464, 322, 136, 36, theme::TOGGLE);
        self.button(COPY, "복사", 608, 322, 88, 36, theme::PRIMARY);
        unsafe {
            EnableWindow(self.handle(COPY), 0);
        }
        self.button(PREVIOUS, "‹", 728, 322, 40, 36, theme::GHOST);
        self.button(NEXT, "›", 772, 322, 40, 36, theme::GHOST);
        // The OTP row, for an entry with an OTP secret (see draw_otp).
        let (x, y) = (OTP_ROW.0, OTP_ROW.1);
        self.button(OTP_COPY, "복사", x, y, 64, 34, theme::SECONDARY);
        self.button(
            OTP_SECRET_COPY,
            "시크릿 복사",
            x + 72,
            y,
            104,
            34,
            theme::SECONDARY,
        );
        self.button(OTP_QR, "QR 보기", x + 184, y, 92, 34, theme::SECONDARY);
        unsafe {
            EnableWindow(self.handle(OTP_SECRET_COPY), 0);
        }
        self.button(BACKUP, "금고 백업", 40, 642, 112, 34, theme::SECONDARY);
        self.button(KEYBACKUP, "열쇠 백업", 160, 642, 104, 34, theme::SECONDARY);
        self.button(CHANGE, "열쇠 관리", 272, 642, 148, 34, theme::SECONDARY);
        self.text(0, "자동 잠금", (536, 650, 90, 20), small, TONE_MUTED, 2);
        let (x, y, _, _) = AUTO_LOCK_SWITCH;
        for (i, (name, ..)) in AUTO_LOCKS.iter().enumerate() {
            let variant = if i == self.auto_lock {
                theme::TAB_ON
            } else {
                theme::TAB
            };
            let id = AUTO_LOCK + i as i32;
            self.button(id, name, x + 2 + i as i32 * 50, y + 2, 48, 32, variant);
        }
        #[cfg(feature = "security-key")]
        if self.tofu_banner() {
            self.build_tofu();
        }
        self.sync_detail();
        // The banner's code field is the next step (spec §2.29).
        #[cfg(feature = "security-key")]
        let list = match self.handle(keys_ui::GATE_CODE) {
            0 => list,
            code => code,
        };
        unsafe {
            SetFocus(list);
        }
    }
    fn build_edit(&mut self) {
        let title = self.font_of(|t| t.title());
        let heading = if self.editing.is_some() {
            "항목 수정"
        } else {
            "새 항목"
        };
        self.text(0, heading, (40, 74, 400, 34), title, TONE_TEXT, 0);
        // Temporary UI buffers zeroize after transfer to the native control.
        let values = if let Some(e) = self
            .editing
            .and_then(|i| self.session.as_ref()?.entries.get(i))
        {
            [
                Zeroizing::new(e.title.to_string()),
                // Built-in types such as "니모닉" follow the interface language.
                Zeroizing::new(tr(&e.kind).to_string()),
                // Never an OTP entry's secret field (the marker or older
                // text): it has no 비밀정보 to show.
                Zeroizing::new(e.shown_secret().to_owned()),
                Zeroizing::new(e.notes.to_string()),
            ]
        } else {
            [
                Zeroizing::new(String::new()),
                Zeroizing::new(tr(KIND_PRESETS[0]).into()),
                Zeroizing::new(String::new()),
                Zeroizing::new(String::new()),
            ]
        };
        self.field(
            TITLE,
            "이름 · 목록에 표시됩니다",
            &values[0],
            40,
            120,
            796,
            false,
        );
        self.field(KIND, "종류", &values[1], 40, 196, 240, false);
        for (i, name) in KIND_PRESETS.iter().enumerate() {
            let x = 296 + i as i32 * 100;
            self.button(PRESET + i as i32, name, x, 222, 92, 32, theme::CHIP);
        }
        self.label_as(SECRET_LABEL, "비밀정보 · 여러 줄 가능", 40, 272, 400);
        self.input(SECRET, &values[2], (40, 294, 796, 100), false, true, 0);
        // In the OTP kind's shape, under its OTP row (see edit_shape).
        self.note(OTP_KIND_TEXT, 40, 346, 796, 48);
        if let Some(note) = self.children.last().copied() {
            self.controls.insert(OTP_KIND_NOTE, note);
        }
        self.label("메모", 40, 404, 400);
        self.input(NOTES, &values[3], (40, 426, 796, 64), false, true, 0);
        // The OTP secret, masked like a password, and its names. Pasting a
        // whole otpauth URI fills the names (see otp_pasted).
        let otp = self
            .editing
            .and_then(|i| self.session.as_ref()?.entries.get(i))
            .and_then(Entry::otp);
        let (text, issuer, account) = match &otp {
            Some(o) => (o.editor_text(), o.issuer.clone(), o.account.clone()),
            None => Default::default(),
        };
        let y = OTP_EDIT_TOP;
        self.password_field_as(OTP_LABEL, OTP_FIELD, OTP_FIELD_OPTIONAL, 40, y, 420);
        if !self.input_failed {
            unsafe {
                SetWindowTextW(self.handle(OTP_FIELD), secret_wide(&text).as_ptr());
            }
        }
        let issuer_at = (476, y, 172);
        self.field_as(
            OTP_ISSUER_LABEL,
            OTP_ISSUER,
            "발급자 (선택)",
            &issuer,
            issuer_at,
            false,
        );
        let account_at = (664, y, 172);
        self.field_as(
            OTP_ACCOUNT_LABEL,
            OTP_ACCOUNT,
            "계정 (선택)",
            &account,
            account_at,
            false,
        );
        self.edit_shape();
        let note = format!(
            "{}\r\n{}",
            tr(
                "비밀정보·메모 칸은 한글 IME를 차단합니다. 입력기 학습 위험이 있어 붙여넣기를 권장합니다.\r\n이 화면에서 복사·잘라내기는 막혀 있고 붙여넣기만 됩니다."
            ),
            tr(AUTO_LOCKS[self.auto_lock].3)
        );
        self.note(&note, 40, 572, 796, 60);
        self.button(CANCEL, "취소", 588, 640, 100, 40, theme::SECONDARY);
        self.button(SAVE, "암호화하여 저장", 696, 640, 140, 40, theme::PRIMARY);
        unsafe {
            SetFocus(self.handle(TITLE));
        }
    }
    /// The editor's shape for the kind typed (0.12.1). The OTP kind has no
    /// 비밀정보: its field goes, the OTP row takes its place with the OTP
    /// secret required, and a note says none is kept. Other kinds as
    /// before. Called on build, on each change of the kind and on a chip.
    fn edit_shape(&mut self) {
        let (secret, field) = (self.handle(SECRET), self.handle(OTP_FIELD));
        if self.screen != Screen::Edit || secret == 0 || field == 0 {
            return;
        }
        let otp = self.read(KIND).is_ok_and(|k| vault::is_otp_kind(&k));
        let top = if otp { OTP_EDIT_TOP_KIND } else { OTP_EDIT_TOP };
        let Some(now) = self
            .frames
            .iter()
            .find(|(_, h)| *h == field)
            .map(|(r, _)| r.top - 22)
        else {
            return;
        };
        unsafe {
            if otp && GetFocus() == secret {
                SetFocus(field);
            }
            for (id, show) in [(SECRET_LABEL, !otp), (SECRET, !otp), (OTP_KIND_NOTE, otp)] {
                ShowWindow(self.handle(id), if show { 8 } else { 0 });
            }
            let label = if otp {
                OTP_FIELD_REQUIRED
            } else {
                OTP_FIELD_OPTIONAL
            };
            SetWindowTextW(self.handle(OTP_LABEL), wide(tr(label)).as_ptr());
        }
        if now != top {
            // The row in its new place, and next in the tab order after
            // the field above it: the 비밀정보 (hidden) or the memo.
            let dy = self.px(top) - self.px(now);
            let mut after = self.handle(if otp { SECRET } else { NOTES });
            for id in [
                OTP_LABEL,
                OTP_FIELD,
                PEEK_OTP,
                OTP_ISSUER_LABEL,
                OTP_ISSUER,
                OTP_ACCOUNT_LABEL,
                OTP_ACCOUNT,
            ] {
                let h = self.handle(id);
                unsafe {
                    let mut r = Rect::default();
                    GetWindowRect(h, &mut r);
                    let mut corner = Point {
                        x: r.left,
                        y: r.top,
                    };
                    MapWindowPoints(0, self.hwnd, &mut corner, 1);
                    // SWP_NOSIZE | SWP_NOACTIVATE
                    SetWindowPos(h, after, corner.x, corner.y + dy, 0, 0, 0x1 | 0x10);
                }
                after = h;
            }
            let moved = [field, self.handle(OTP_ISSUER), self.handle(OTP_ACCOUNT)];
            for (frame, h) in &mut self.frames {
                if moved.contains(h) {
                    frame.top += top - now;
                    frame.bottom += top - now;
                }
            }
        }
        unsafe {
            InvalidateRect(self.hwnd, null(), 0);
        }
    }
    fn build_password(&mut self) {
        let title = self.font_of(|t| t.title());
        self.text(0, "비밀번호 변경", (AX, 80, AW, 34), title, TONE_TEXT, 0);
        self.note(
            "현재 비밀번호를 확인한 뒤 새 열쇠로 금고를 다시 암호화합니다.",
            AX,
            118,
            AW,
            22,
        );
        self.password_field(CURRENT_PASS, REAUTH_LABEL, AX, 160, AW);
        self.password_field(PASS, "새 비밀번호 · 12자 이상", AX, 232, AW);
        self.password_field(CONFIRM, "새 비밀번호 확인", AX, 304, AW);
        let y = PASSWORD_CARD_Y;
        self.note(
            "새 데이터 키로 금고를 다시 암호화하고 새 열쇠 파일을 씁니다. 예전 열쇠 파일과 예전 비밀번호로는 앞으로 저장하는 내용을 열 수 없습니다. 바꾼 뒤 새 열쇠 파일을 백업하세요.",
            AX + 18,
            y + 14,
            AW - 36,
            54,
        );
        self.button(
            CANCEL,
            "취소",
            AX + AW - 268,
            y + 100,
            100,
            42,
            theme::SECONDARY,
        );
        self.button(
            SUBMIT,
            "비밀번호 변경",
            AX + AW - 160,
            y + 100,
            160,
            42,
            theme::PRIMARY,
        );
        unsafe {
            SetFocus(self.handle(CURRENT_PASS));
        }
    }
    /// "열쇠 관리" (spec §9.1, keyless build): the password change, another
    /// PC's key file and the key backup; for a KF2 key file its key code;
    /// and what holds key changes, with the button that acts on it and the
    /// fields its re-authentication reads.
    fn build_keys(&mut self) {
        self.keys_shown = Some(self.keys_now());
        let (title, small, body) = (
            self.font_of(|t| t.title()),
            self.font_of(|t| t.small()),
            self.font_of(|t| t.body()),
        );
        let view = self.keys_view();
        // The security-key section, when nothing holds key changes, and
        // under a halted vault channel, which holds none: each key change
        // asks its gate question, and the removal of a lost key none (spec
        // §7.5, S-LOST-HALTED). The halt's text and override then sit in it.
        #[cfg(feature = "security-key")]
        let halted_keys = matches!(view.hold, Hold::Halted) && view.keys.is_some();
        #[cfg(not(feature = "security-key"))]
        let halted_keys = false;
        #[cfg(feature = "security-key")]
        let hardware = matches!(view.hold, Hold::None) || halted_keys;
        #[cfg(not(feature = "security-key"))]
        let hardware = false;
        // The part above the security-key section spans its width, so both
        // start at the same left edge; otherwise the centered column.
        let (x, w) = if hardware { (40, 796) } else { (AX, AW) };
        self.text(0, "열쇠 관리", (x, 80, w - 100, 34), title, TONE_TEXT, 0);
        self.button(BACK, "‹ 뒤로", x + w - 84, 84, 84, 32, theme::GHOST);
        // A key file that syncs takes the other PCs' changes from the
        // server ([받기…] below), not by USB.
        let usb = "다른 PC에서 비밀번호를 바꿨다면 그 PC의 새 열쇠 파일을 USB로 가져와 '새 열쇠 파일 받기'로 받으세요. 이 PC의 열쇠 파일 위에 덮어쓰지 마세요.";
        #[cfg(feature = "security-key")]
        let usb = if keys_ui::ks_view(self.session.as_ref()).is_some_and(|v| v.on) {
            keys_ui::KEYS_NOTE_SYNCED
        } else {
            usb
        };
        self.note(usb, x, 124, w, 40);
        let half = (w - 16) / 2;
        let right = x + half + 16;
        self.label("비밀번호", x, 178, half);
        self.button(
            KEY_PASSWORD,
            "비밀번호 변경…",
            x,
            200,
            half,
            38,
            theme::SECONDARY,
        );
        self.label("다른 PC의 열쇠 파일", right, 178, half);
        self.button(
            KEY_ADOPT,
            "새 열쇠 파일 받기…",
            right,
            200,
            half,
            38,
            theme::SECONDARY,
        );
        self.label("열쇠 백업 · 열쇠 파일 사본, 금고와 다른 곳에", x, 254, half);
        self.button(KEYBACKUP, "열쇠 백업", x, 276, half, 38, theme::SECONDARY);
        if let Some(code) = &view.code {
            self.label("열쇠 확인 코드", right, 254, half);
            self.text(0, code, (right, 282, half, 26), body, TONE_TEXT, 0);
            #[cfg(not(feature = "security-key"))]
            let note = "두 PC의 열쇠 확인 코드가 같으면 같은 열쇠 파일입니다. 열쇠를 바꾼 뒤 다른 PC에서 새 열쇠 파일을 받았다면 두 코드를 비교하세요.";
            #[cfg(feature = "security-key")]
            let note = keys_ui::KEYCODE_NOTE;
            self.note(note, x, 326, w, 40);
        }
        let mut focus = self.handle(KEY_PASSWORD);
        #[cfg(feature = "security-key")]
        if hardware {
            let halt = view
                .hold
                .shown()
                .filter(|_| halted_keys)
                .map(|(text, _, action)| (text, action));
            self.build_hardware(view.keys.as_ref(), halt);
            focus = self.handle(CURRENT_PASS);
        }
        if !halted_keys && let Some((text, tone, action)) = view.hold.shown() {
            self.text(0, &text, (AX, 382, AW, 126), small, tone, 0);
            // The gate of a changed key file, and [다시 하기], which opens
            // a screen, need no password.
            #[cfg(feature = "security-key")]
            let action = match action {
                Some((id, label)) if id == keys_ui::KEY_ACCEPT || id == keys_ui::LOST_REDO => {
                    self.button(id, label, AX + AW - 400, 516, 400, 40, theme::PRIMARY);
                    focus = self.handle(id);
                    // Gate-pending mode also offers the per-vault forget,
                    // whose Reauth needs the password.
                    if id == keys_ui::KEY_ACCEPT {
                        self.build_forget_held();
                    }
                    None
                }
                // [서버의 새 열쇠 파일 받기…], whose Reauth reads the
                // password, and under it the head override while
                // a server copy halts sync.
                Some((id, label)) if id == keys_ui::KEY_SERVER_TAKE => {
                    self.reauth_row(516);
                    self.button(id, label, AX + AW - 400, 592, 400, 40, theme::PRIMARY);
                    if matches!(view.hold, Hold::ServerKeysOn { halted: true, .. }) {
                        self.button(
                            KEY_OVERRIDE_HEAD,
                            OVERRIDE_HEAD_LABEL,
                            AX + AW - 400,
                            640,
                            400,
                            36,
                            theme::DANGER_GHOST,
                        );
                    }
                    focus = self.handle(CURRENT_PASS);
                    None
                }
                other => other,
            };
            if let Some((id, label)) = action {
                // The button's flow checks the password again.
                self.reauth_row(516);
                self.button(id, label, AX + AW - 400, 592, 400, 40, theme::DANGER_GHOST);
                focus = self.handle(CURRENT_PASS);
            }
        }
        unsafe {
            SetFocus(focus);
        }
    }
    /// The Keys screen's current password at `y`, which a hold's button
    /// reads for its re-authentication.
    fn reauth_row(&mut self, y: i32) {
        self.password_field(CURRENT_PASS, REAUTH_LABEL, AX, y, AW);
    }
    /// Where the edit screen goes back to (the security-key build's goes
    /// back to the review it was opened from).
    #[cfg(not(feature = "security-key"))]
    fn after_edit(&mut self) -> Screen {
        Screen::Vault
    }
    /// What the Keys screen shows of the session; a test sets it instead.
    fn keys_view(&self) -> KeysView {
        #[cfg(test)]
        if let Some(view) = KEYS_VIEW.with(|v| v.borrow().clone()) {
            return view;
        }
        self.session.as_ref().map(KeysView::of).unwrap_or_default()
    }
    /// What the Keys screen would show of the session now.
    fn keys_now(&self) -> KeysShown {
        #[cfg(feature = "security-key")]
        let texts = {
            let s = self.session.as_ref();
            let mut texts = s.map(keys_ui::near_texts).unwrap_or_default();
            texts.extend(s.and_then(keys_ui::rollout_text));
            texts
        };
        KeysShown {
            view: self.keys_view(),
            #[cfg(feature = "security-key")]
            sync: keys_ui::ks_view(self.session.as_ref()),
            #[cfg(feature = "security-key")]
            texts,
        }
    }
    /// The Keys screen after a poll there (see timer): rebuilt only when
    /// what it shows of the session changed (a key view the helper wrote,
    /// a server key file it fetched, a merge), keeping what was typed, the
    /// focus with its caret and the list's scroll position. The status
    /// line stays as it is, in its tone.
    fn refresh_keys(&mut self) {
        if self.screen != Screen::Keys {
            return;
        }
        let now = self.keys_now();
        if self.keys_shown.as_ref() == Some(&now) {
            return;
        }
        let focused = unsafe { GetFocus() };
        let focus = self
            .controls
            .iter()
            .find(|(_, h)| **h == focused && focused != 0)
            .map(|(id, _)| *id);
        let (mut start, mut end) = (0u32, 0u32);
        // The list's first visible line (EM_GETFIRSTVISIBLELINE).
        #[cfg(feature = "security-key")]
        let top = match self.handle(keys_ui::KEY_LIST) {
            0 => 0,
            list => unsafe { SendMessageW(list, 0xce, 0, 0) },
        };
        unsafe {
            if focus.is_some() && self.edits.contains(&focused) {
                SendMessageW(
                    focused,
                    0xb0, // EM_GETSEL
                    &mut start as *mut u32 as usize,
                    &mut end as *mut u32 as isize,
                );
            }
            self.status_tone = GetWindowLongPtrW(self.handle(STATUS), -21);
        }
        self.rebuild_keeping(&[CURRENT_PASS, PASS, CONFIRM]);
        unsafe {
            #[cfg(feature = "security-key")]
            if top > 0 {
                SendMessageW(self.handle(keys_ui::KEY_LIST), 0xb6, 0, top); // EM_LINESCROLL
            }
            let h = focus.map_or(0, |id| self.handle(id));
            if h != 0 {
                SetFocus(h);
                if self.edits.contains(&h) {
                    SendMessageW(h, 0xb1, start as usize, end as isize); // EM_SETSEL
                }
            }
        }
    }
    /// "새 열쇠 파일 받기" (spec §9.1): the chosen file, read-only, its
    /// revision, and this PC's password for [열기], which runs the
    /// whole adopt as one flow (see adopt_flow).
    fn build_adopt(&mut self) {
        let (title, body) = (self.font_of(|t| t.title()), self.font_of(|t| t.body()));
        self.text(
            0,
            "새 열쇠 파일 받기",
            (AX, 80, AW - 100, 34),
            title,
            TONE_TEXT,
            0,
        );
        self.button(BACK, "‹ 뒤로", AX + AW - 84, 84, 84, 32, theme::GHOST);
        self.note(
            "다른 PC에서 바꾼 열쇠 파일을 이 PC의 열쇠 파일과 비교합니다. 이어진 새 버전이면 그대로 받고, 갈라졌으면 두 파일을 합칩니다. 받기 전에 무엇이 바뀌는지 보여 줍니다.",
            AX,
            124,
            AW,
            40,
        );
        self.label("받을 열쇠 파일", AX, 180, AW);
        let source = self.adopt_source.clone().unwrap_or_default();
        // SS_PATHELLIPSIS: a long path keeps its file name.
        let shown_path = shown(&source);
        self.text(0, &shown_path, (AX, 204, AW, 24), body, TONE_TEXT, 0x8000);
        let info = match key_info(&source) {
            Some(i) if matches!(&i.magic, b"GOYOKE01" | b"GOYOKE02") => {
                tr("0.8 형식 열쇠 파일").to_owned()
            }
            Some(i) => fill("열쇠 파일 수정 {epoch}", &[&i.epoch]),
            None => String::new(),
        };
        let small = self.font_of(|t| t.small());
        self.text(0, &info, (AX, 230, AW, 20), small, TONE_MUTED, 0);
        self.password_field(CURRENT_PASS, REAUTH_LABEL_ADOPT, AX, 268, AW);
        self.button(SUBMIT, "열기", AX, 356, AW, 46, theme::PRIMARY);
        self.note(
            "받을 열쇠 파일의 비밀번호가 이 PC와 다르면 열 때 그 비밀번호를 묻습니다.",
            AX,
            414,
            AW,
            40,
        );
        unsafe {
            SetFocus(self.handle(CURRENT_PASS));
        }
    }
    /// Shows the detail-card controls that apply to the current selection.
    fn sync_detail(&self) {
        if self.screen != Screen::Vault {
            return;
        }
        // The TOFU banner takes the detail's place (spec §7.17).
        #[cfg(feature = "security-key")]
        let entry = self.entry().filter(|_| !self.tofu_banner());
        #[cfg(not(feature = "security-key"))]
        let entry = self.entry();
        let revealed = entry.is_some() && self.reveal_until.is_some();
        // An OTP entry has no 비밀정보 to page through or copy; 15초 보기
        // and 복사 허용 stay for its OTP secret and memo.
        let otp_entry = entry.is_some_and(Entry::is_otp_entry);
        let paging = revealed
            && !otp_entry
            && entry
                .and_then(|e| self.shown(e).ok())
                .is_some_and(|p| p.len() > 1);
        // The QR panel takes the secret's place, buttons and all.
        let qr = self.qr_shown();
        let secret = entry.is_some() && !qr;
        let otp = entry.is_some_and(Entry::has_otp);
        self.place_otp_row(self.otp_top());
        unsafe {
            let reveal = if revealed {
                "가리기"
            } else {
                "15초 보기"
            };
            SetWindowTextW(self.handle(REVEAL), wide(tr(reveal)).as_ptr());
            let shown = if qr { "QR 숨기기" } else { "QR 보기" };
            SetWindowTextW(self.handle(OTP_QR), wide(tr(shown)).as_ptr());
            let focus = GetFocus();
            for (id, show) in [
                (EDIT, entry.is_some()),
                (DELETE, entry.is_some()),
                (REVEAL, secret),
                (TOGGLE, secret),
                (COPY, secret && !otp_entry),
                (PREVIOUS, paging && !qr),
                (NEXT, paging && !qr),
                (OTP_COPY, otp),
                (OTP_SECRET_COPY, otp),
                (OTP_QR, otp),
            ] {
                let h = self.handle(id);
                if !show && h == focus {
                    SetFocus(self.handle(LIST));
                }
                ShowWindow(h, if show { 8 } else { 0 });
            }
        }
    }
    /// The top of the selected entry's OTP row: an OTP entry's in the
    /// 비밀정보's place, any other's under the memo.
    fn otp_top(&self) -> i32 {
        if self.entry().is_some_and(Entry::is_otp_entry) {
            OTP_ENTRY_TOP
        } else {
            OTP_TOP
        }
    }
    /// The QR panel's caption line and square for the selected entry.
    fn qr_area(&self) -> (i32, (i32, i32, i32, i32)) {
        if self.otp_top() == OTP_ENTRY_TOP {
            (OTP_ENTRY_TOP + 108, QR_AREA_OTP_ENTRY)
        } else {
            (198, QR_AREA)
        }
    }
    /// The OTP row's buttons under its top `top`.
    fn place_otp_row(&self, top: i32) {
        let y = self.px(top + OTP_ROW.1 - OTP_TOP);
        for (id, dx) in [(OTP_COPY, 0), (OTP_SECRET_COPY, 72), (OTP_QR, 184)] {
            let h = self.handle(id);
            if h != 0 {
                // SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE
                let x = self.px(OTP_ROW.0 + dx);
                unsafe {
                    SetWindowPos(h, 0, x, y, 0, 0, 0x1 | 0x4 | 0x10);
                }
            }
        }
    }
    /// First run (no vault at the default location) starts on Welcome.
    fn start_screen(&mut self) {
        self.show(self.home());
        if self.screen == Screen::Welcome {
            self.status.clear();
        }
        let folder = &self.home_dir;
        let temp = std::env::temp_dir().to_string_lossy().to_lowercase();
        if folder
            .to_string_lossy()
            .to_lowercase()
            .starts_with(temp.trim_end_matches('\\'))
        {
            self.status = line(
                "압축 파일 안이나 임시 폴더에서 실행 중입니다. 이 폴더는 지워질 수 있으니, 계속 보관할 폴더에 압축을 푼 뒤 실행하세요.",
            );
            self.status_tone = TONE_DANGER;
        } else if in_cloud_folder(folder) {
            self.status = line(
                "프로그램 폴더가 클라우드 동기화 폴더에 있습니다. 여기에 금고와 열쇠를 함께 두면 둘 다 같은 계정에 올라갑니다.",
            );
            self.status_tone = TONE_DANGER;
        }
    }
    /// Another app is in front. Nothing revealed stays on screen while the
    /// user is elsewhere: passwords shown with the eye are masked; with a
    /// vault open the 15-second view and copy permission also end.
    /// Pre-unlock forms are kept. An open vault locks per the auto-lock setting (see timer). Runs on
    /// WM_ACTIVATEAPP and from the timer, which also catches missed messages.
    fn deactivated(&mut self) {
        self.mask_passwords();
        self.inactive = true;
        if self.session.is_none() {
            return;
        }
        self.away_since.get_or_insert_with(Instant::now);
        self.reset_copy();
        let qr = self.qr.take().is_some();
        if self.reveal_until.take().is_some() || qr {
            self.sync_detail();
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
        }
    }
    /// Back in front. Trusts only the real foreground window, so a
    /// WM_ACTIVATEAPP faked by another program cannot cancel the away lock.
    fn activated(&mut self) {
        if !is_foreground(self.hwnd) {
            return;
        }
        self.away_since = None;
        if std::mem::take(&mut self.inactive) {
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
        }
    }
    /// Picks an auto-lock choice; it applies from the next timer tick and is
    /// saved next to the exe.
    fn set_auto_lock(&mut self, choice: usize) {
        self.auto_lock = choice;
        save_auto_lock(choice);
        for i in 0..AUTO_LOCKS.len() {
            let variant = if i == choice {
                theme::TAB_ON
            } else {
                theme::TAB
            };
            let b = self.handle(AUTO_LOCK + i as i32);
            unsafe {
                SetWindowLongPtrW(b, -21, variant);
                InvalidateRect(b, null(), 0);
            }
        }
        self.status(AUTO_LOCKS[choice].2);
    }
    fn lock(&mut self, why: &str, clear_clipboard: bool) {
        // A ceremony under way ends: the worker holds no vault secret, so
        // the session goes at once (spec §8.6).
        #[cfg(feature = "security-key")]
        cancel_ceremony();
        self.auth_dirty = false;
        self.activity = Instant::now();
        let _ = self.paths();
        self.clear_controls();
        // What a key change left to finish gets one more try. A new key file
        // whose save is unknown is gone with the session: say how to open.
        let why = match self.session.as_mut() {
            Some(s) => {
                s.before_lock();
                if s.key_unsaved() {
                    vault::KEY_DAMAGED_LOCKED
                } else {
                    why
                }
            }
            None => why,
        };
        self.session = None;
        self.provision = None;
        self.adopt_source = None;
        // A flow's input dialog goes too, with what was typed into it.
        cancel_input();
        self.away_since = None;
        self.selected = None;
        self.status_tone = TONE_MUTED;
        self.editing = None;
        self.copy_until = None;
        self.reveal_until = None;
        self.page = 0;
        if clear_clipboard {
            self.expire_clipboard();
        }
        self.sync_badge = None;
        // The removal screens' picks and the review's place go too.
        #[cfg(feature = "security-key")]
        {
            self.toggles = keys_ui::Toggles::default();
        }
        self.show(self.home());
        self.from_welcome = false;
        // The line may name an entry (a sync conflict).
        self.status.zeroize();
        self.status = line(why);
        self.build();
    }
    /// Drops the keys and any reveal or copy permission
    /// without touching the controls; a pending lock rebuilds the screen
    /// moments later (see window_proc).
    fn scrub(&mut self) {
        #[cfg(feature = "security-key")]
        cancel_ceremony();
        self.serial += 1;
        self.session = None;
        self.provision = None;
        self.adopt_source = None;
        cancel_input();
        self.reveal_until = None;
        self.qr = None;
        self.copy_until = None;
        self.expire_clipboard();
    }
    fn expire_clipboard(&mut self) {
        if let Some((seq, _)) = self.clipboard {
            if clear_clip(self.hwnd, seq) {
                self.clipboard = None;
            } else {
                self.clipboard = Some((seq, Instant::now()));
            }
        }
    }
    /// SUBMIT. Login and Password run in phases (see phased_command); a
    /// call from here runs them at once, asking S-OLDER in between with the
    /// app still borrowed.
    fn submit(&mut self) -> crypto::Result<()> {
        if matches!(self.screen, Screen::Login | Screen::Password) {
            let mut flow = self.begin(SUBMIT)?;
            if let Some(sha) = flow.older() {
                if !ask(self.hwnd, OLDER_QUESTION) {
                    return Err(OLDER_DECLINED);
                }
                flow.confirmed_older = Some(sha);
            }
            // The question and the gate's in one box (default No).
            if let Some(q) = flow.question {
                let text = match flow.gate {
                    Some(g) => format!(
                        "{}

{}",
                        tr(q),
                        tr(g.question())
                    ),
                    None => tr(q).to_owned(),
                };
                if !ask(self.hwnd, &text) {
                    return Ok(());
                }
                flow.answered = flow.gate;
            }
            let mut gate = flow.gate.filter(|g| flow.answered != Some(*g));
            loop {
                if let Some(g) = gate {
                    if !ask(self.hwnd, g.question()) {
                        return Ok(());
                    }
                    flow.answered = Some(g);
                }
                gate = self.gate_now(&flow)?;
                if gate.is_none() {
                    break;
                }
            }
            return self.finish(flow).map(|_| ());
        }
        // An adopt asks inside its flow, which runs only through
        // phased_command (spec §9.2a).
        if self.screen == Screen::Adopt {
            return Err("화면 작업 중입니다.");
        }
        if self.input_failed {
            return Err("입력 보호 설정 실패로 저장/인증을 중단합니다.");
        }
        check_environment(self.hwnd)?;
        if Instant::now() < self.retry {
            return Err("인증 실패 후 대기 중입니다. 잠시 후 다시 시도하세요.");
        }
        self.paths()?;
        let pass = self.read(PASS)?;
        self.check_files()?;
        if self.screen == Screen::Create && pass.as_str() != self.read(CONFIRM)?.as_str() {
            return Err("비밀번호 확인이 일치하지 않습니다.");
        }
        // A Restore's key file and the backup's precheck: refusals of the
        // files themselves, before any key derivation and never counted as
        // a failed attempt (spec §5.1).
        let prepared = match self.screen {
            Screen::Create => None,
            _ => Some(vault::prepare_restore(&self.backup_path, &self.key_path)?),
        };
        let auth_failure = prepared.as_ref().and_then(Prepared::auth_failure);
        self.working();
        unsafe {
            UpdateWindow(self.hwnd);
        }
        let screen = self.screen;
        let result = match prepared {
            None => {
                goyo_vault::vault::password_policy(&pass)?;
                let provision = self
                    .provision
                    .as_ref()
                    .ok_or("새 금고 등록을 다시 시작하세요.")?;
                provision.finish(&self.new_vault_path, &self.new_key_path, &pass)
            }
            Some(prepared) => Session::restore_from(prepared, &self.dest_path, &pass),
        };
        self.opened(screen, result, auth_failure)
    }
    /// The checks the first phase of every flow makes before it takes
    /// anything (see phased_command).
    fn enter(&mut self, id: i32) -> crypto::Result<()> {
        if !self.allows(id) {
            return Err("현재 화면에서 허용되지 않는 작업입니다.");
        }
        if self.closing {
            return Err("클립보드 정리 후 종료를 기다리고 있습니다.");
        }
        self.activity = Instant::now();
        if self.input_failed {
            return Err("입력 보호 설정 실패로 저장/인증을 중단합니다.");
        }
        check_environment(self.hwnd)?;
        if Instant::now() < self.retry {
            return Err(RETRY_WAIT);
        }
        Ok(())
    }
    /// Phase 1 of SUBMIT on Login and Password (see phased_command): every
    /// check command() and submit() make before the slow part, under a
    /// short borrow, and a snapshot of what was typed.
    fn begin(&mut self, id: i32) -> crypto::Result<Flow> {
        self.enter(id)?;
        self.paths()?;
        let pass = self.read(PASS)?;
        let mut current = Zeroizing::new(String::new());
        let mut auth_failure = None;
        let (mut question, mut gate) = (None, None);
        let mut prepared = None;
        if self.screen == Screen::Password {
            // What holds a key change, or what is asked first (spec §7.5).
            let s = self.session.as_mut().ok_or("먼저 금고를 열어주세요.")?;
            gate = s.password_change()?;
            question = Some(if s.badge().is_some() {
                ROTATE_QUESTION_SYNCED
            } else {
                ROTATE_QUESTION
            });
            if pass.as_str() != self.read(CONFIRM)?.as_str() {
                return Err("비밀번호 확인이 일치하지 않습니다.");
            }
            current = self.read(CURRENT_PASS)?;
            // Before the slow re-authentication.
            goyo_vault::vault::password_policy(&pass)?;
            if pass.as_str() == current.as_str() {
                return Err(vault::SAMEPASS);
            }
        } else {
            self.check_files()?;
            // The precheck's refusals come before any key derivation and
            // are not failed attempts (spec §5.1). After S-ANCHOR-FORGET's
            // yes, this PC's record of the vault is ignored (spec §5.10).
            #[cfg(feature = "security-key")]
            let checked = if id == keys_ui::ANCHOR_FORGET {
                vault::prepare_forgotten(&self.vault_path, &self.key_path)?
            } else {
                vault::prepare(&self.vault_path, &self.key_path)?
            };
            #[cfg(not(feature = "security-key"))]
            let checked = vault::prepare(&self.vault_path, &self.key_path)?;
            auth_failure = checked.auth_failure();
            prepared = Some(checked);
            self.working();
        }
        Ok(Flow {
            screen: self.screen,
            serial: self.serial,
            session: self.session.is_some(),
            pass,
            current,
            auth_failure,
            question,
            gate,
            answered: None,
            prepared,
            confirmed_older: None,
            #[cfg(feature = "security-key")]
            touch: None,
        })
    }
    /// Phase 3 (see phased_command): only on the screen, serial and session
    /// phase 1 saw, not while closing and with the environment checked
    /// again. Then the library call, and the screen for its result. True
    /// when a key change wrote a new key file, whose backup is offered next.
    fn finish(&mut self, flow: Flow) -> crypto::Result<bool> {
        #[cfg(feature = "security-key")]
        return self.finish_out(flow, &mut LoginOut::default());
        #[cfg(not(feature = "security-key"))]
        self.finish_out(flow)
    }
    /// The same, handing a login's touch, proof or failed-unlock entry back
    /// to its flow (security-key build).
    fn finish_out(
        &mut self,
        flow: Flow,
        #[cfg(feature = "security-key")] out: &mut LoginOut,
    ) -> crypto::Result<bool> {
        if !self.still(flow.screen, flow.serial, flow.session)? {
            return Ok(false);
        }
        if flow.screen == Screen::Login {
            let Flow {
                prepared,
                pass,
                confirmed_older,
                auth_failure,
                #[cfg(feature = "security-key")]
                touch,
                ..
            } = flow;
            let prepared = prepared.ok_or("화면 작업 중입니다.")?;
            #[cfg(feature = "security-key")]
            if let Some(touch) = touch {
                let result = Session::login_proved(prepared, &pass, confirmed_older, &touch);
                out.touch = Some(touch);
                let result = match result {
                    Ok((s, proof)) => {
                        out.proof = Some(proof);
                        Ok(s)
                    }
                    Err(failed) => {
                        out.entry = failed.entry;
                        Err(failed.error)
                    }
                };
                return self
                    .opened(Screen::Login, result, auth_failure)
                    .map(|_| false);
            }
            let result = Session::login(prepared, &pass, confirmed_older);
            return self
                .opened(Screen::Login, result, auth_failure)
                .map(|_| false);
        }
        // The password change (spec §5.5): a re-authentication with the
        // current password, then the key change itself, past the gate the
        // user answered and no other. A gate that came up since was asked in
        // between (gate_now): one that still differs is refused before the
        // re-authentication.
        let serial = self.serial;
        let s = self.session.as_mut().ok_or("먼저 금고를 열어주세요.")?;
        let gate = s.password_change()?;
        if let Some(gate) = gate.filter(|g| flow.answered != Some(*g)) {
            return Err(gate.question());
        }
        let override_gate = gate.is_some();
        let result = s.reauth(&flow.current, None).and_then(|mut r| {
            r.app_serial = serial;
            let change = vault::Change::Password(flow.pass.clone());
            s.rekey(
                r,
                Vec::new(),
                change,
                vault::Consent::default(),
                override_gate,
            )
        });
        let notices: Vec<(Zeroizing<String>, isize)> =
            s.take_key_notices().iter().map(key_line).collect();
        let code = s.key_code();
        let done = match result {
            Ok(vault::Rekeyed::Done) => PASSWORD_CHANGED,
            Ok(vault::Rekeyed::VaultPending) => vault::VPENDING,
            // The new vault file is only in its temp file: the app locks,
            // and the next unlock takes it back (spec §5.5 S3).
            Ok(vault::Rekeyed::GapKept) => return Err(vault::GAP_CHANGED),
            // Whether the key file was saved is unknown: the vault list
            // stays, so that the new key file can be backed up from memory
            // before the vault locks (S-KEYDAMAGED-SAVE).
            Err(e) if e == vault::KEY_DAMAGED => {
                self.show(Screen::Vault);
                self.build();
                return Err(e);
            }
            Err(e) => {
                if e == crypto::AUTH_ERROR {
                    self.failed_attempt();
                }
                return Err(e);
            }
        };
        self.failed = 0;
        self.show(Screen::Vault);
        let code = code.map(|c| fill(CODE_LINE, &[&c]));
        let mut lines: Vec<&str> = vec![done];
        lines.extend(code.as_deref());
        lines.extend(notices.iter().map(|(text, _)| text.as_str()));
        self.status = joined(&lines);
        if notices.iter().any(|(_, tone)| *tone == TONE_DANGER) {
            self.status_tone = TONE_DANGER;
        }
        self.build();
        Ok(true)
    }
    /// The gate a password change meets now, when it is not the one the
    /// user answered (spec §7.5): a poll that halted sync, or a helper that
    /// stopped, while a question was open. Asked before the re-
    /// authentication. None for a flow that no longer
    /// stands (finish then does nothing) or with no other gate; a hold
    /// that came up is its refusal.
    fn gate_now(&mut self, flow: &Flow) -> crypto::Result<Option<vault::Gate>> {
        if flow.screen != Screen::Password || !self.still(flow.screen, flow.serial, flow.session)? {
            return Ok(None);
        }
        let s = self.session.as_mut().ok_or("먼저 금고를 열어주세요.")?;
        Ok(s.password_change()?.filter(|g| flow.answered != Some(*g)))
    }
    /// Whether a flow's later phase may go on: the screen, serial and
    /// session its first phase saw are still there, the app is not closing,
    /// and the environment checks out (else it locks). Only a lock or a
    /// close in between changes the first three, and it wrote its own line.
    fn still(&mut self, screen: Screen, serial: u64, session: bool) -> crypto::Result<bool> {
        if self.closing
            || self.serial != serial
            || self.screen != screen
            || self.session.is_some() != session
            || quitting()
        {
            return Ok(false);
        }
        if let Err(e) = check_environment(self.hwnd) {
            self.lock(e, true);
            return Err(e);
        }
        Ok(true)
    }
    /// A failed authentication: the retry delay grows.
    fn failed_attempt(&mut self) {
        self.failed = self.failed.saturating_add(1);
        self.retry = Instant::now() + Duration::from_secs((1u64 << self.failed.min(6)).min(60));
    }
    /// Login, Restore and Create: the files must be there before any key
    /// derivation. Missing files are a navigation problem, not a failed
    /// authentication: say what to do and do not start the retry delay. A
    /// file an interrupted save left only as its temp file is not missing:
    /// the unlock takes it back.
    fn check_files(&mut self) -> crypto::Result<()> {
        let source = if self.screen == Screen::Restore {
            &self.backup_path
        } else {
            &self.vault_path
        };
        match self.screen {
            Screen::Login if !self.vault_path.is_file() && !vault_candidates(&self.vault_path) => {
                return Err(if leftover_temp(&self.vault_path) {
                    LEFTOVER_TEMP
                } else {
                    "금고 파일을 찾을 수 없습니다. 경로를 확인하거나 '찾기'로 선택하세요."
                });
            }
            Screen::Restore if !self.backup_path.is_file() => {
                return Err("복원할 백업 파일을 '찾기'로 선택하세요.");
            }
            Screen::Login | Screen::Restore
                if !self.key_path.is_file() && key_candidate(source, &self.key_path).is_none() =>
            {
                // A vault from the server with no key file here opens on
                // its own screen, which Restore points at (spec §2.29).
                #[cfg(feature = "security-key")]
                if self.screen == Screen::Restore
                    && keys_ui::restore_fetched(&self.backup_path, &self.key_path)
                {
                    return Err(keys_ui::RESTORE_FETCHED_KEY);
                }
                return Err(if leftover_temp(&self.key_path) {
                    LEFTOVER_TEMP
                } else {
                    "열쇠 파일을 찾을 수 없습니다. USB 등 다른 곳에 두었다면 '찾기'로 선택하세요. 다른 PC에서 가져온 금고라면 그 PC의 열쇠 파일을 USB로 가져오세요."
                });
            }
            Screen::Restore if self.dest_path.exists() => {
                return Err(
                    "'되살린 금고를 저장할 새 위치'에 같은 이름의 파일이 이미 있습니다. 다른 이름을 지정하세요.",
                );
            }
            Screen::Create if self.new_vault_path.exists() || self.new_key_path.exists() => {
                return Err("같은 이름의 파일이 이미 있습니다. 새 금고·열쇠 파일 이름을 바꾸세요.");
            }
            _ => {}
        }
        // A key file this build cannot open is refused first, also one typed
        // in by path (spec §4.7, §5.1).
        if matches!(self.screen, Screen::Login | Screen::Restore)
            && let Some(refusal) = self.unlock_key_info().and_then(|i| i.refusal())
        {
            return Err(refusal);
        }
        Ok(())
    }
    /// The status line while the key derivation runs. True if the unlock
    /// reads the temp file an interrupted save left in place of a missing or
    /// unparseable key file (temp-candidate recovery).
    fn working(&mut self) -> bool {
        let source = if self.screen == Screen::Restore {
            &self.backup_path
        } else {
            &self.vault_path
        };
        let key_temp = matches!(self.screen, Screen::Login | Screen::Restore)
            && key_candidate(source, &self.key_path).is_some();
        self.status(if key_temp {
            "열쇠 파일이 없어, 저장이 끊기며 남은 임시 파일로 엽니다."
        } else {
            "인증 및 암호화 처리 중입니다…"
        });
        key_temp
    }
    /// The screen after Create, Restore or an unlock. `auth_failure`: what a
    /// failed authentication of these files says instead of the AUTH text
    /// (spec §5.12), when the key file came from a temp file or this PC's
    /// own key change left it as it is.
    fn opened(
        &mut self,
        screen: Screen,
        result: crypto::Result<Session>,
        auth_failure: Option<&'static str>,
    ) -> crypto::Result<()> {
        match result {
            Ok(mut s) => {
                let recovery = s.take_recovery();
                self.vault_path = s.path.clone();
                // A key file still under its temp name: the field keeps the
                // name the user is asked to give it back.
                if recovery.key_kept.is_none() {
                    self.key_path = s.key_path.clone();
                }
                self.new_vault_path = PathBuf::new();
                self.new_key_path = PathBuf::new();
                self.backup_path = PathBuf::new();
                self.dest_path = PathBuf::new();
                // A key file from the server's key view is remembered only
                // once it is saved on this PC (spec §7.17).
                #[cfg(feature = "security-key")]
                let remember = !s.fetched_unsaved();
                #[cfg(not(feature = "security-key"))]
                let remember = true;
                if remember {
                    save_paths(&s.path, &self.key_path);
                }
                let warning = placement_warning(&s.path, &s.key_path);
                // Once per PC and vault: the OTP is gone, and so is its
                // secret at the next key change (Session::otp_note).
                let otp_note = s.otp_note();
                // Only opening a vault looks at its sync folder.
                let login = screen == Screen::Login;
                let notice = if login { s.take_unlock_notice() } else { None };
                #[allow(unused_mut)] // The security-key build rewords one.
                let mut key_notices: Vec<(Zeroizing<String>, isize)> =
                    s.take_key_notices().iter().map(key_line).collect();
                #[cfg(feature = "security-key")]
                keys_ui::unlock_lines(&s, &mut key_notices);
                if login && s.sync_offer() {
                    SYNC_OFFER.with(|f| f.set(true));
                }
                self.sync_badge = s.badge();
                self.session = Some(s);
                self.provision = None;
                self.failed = 0;
                self.show(Screen::Vault);
                let first = if screen == Screen::Create {
                    "새 금고를 만들었습니다. 아래 '열쇠 백업'으로 열쇠 파일 사본을 금고와 다른 곳에 두세요."
                } else if AUTO_LOCKS[self.auto_lock].1.is_none() {
                    UNLOCKED_NO_AUTO_LOCK
                } else {
                    UNLOCKED
                };
                // What the unlock took back from temp files, what it did with
                // the vault file's key and what it found in the sync folder
                // replace the usual line; the placement warning still follows
                // them.
                let (first, mut tone) = match &notice {
                    Some(n) => sync_line(n),
                    None => (Zeroizing::new(first.to_owned()), TONE_MUTED),
                };
                let (recovered, rename) = recovery_lines(&recovery, &self.key_path);
                if warning.is_some() || rename || key_notices.iter().any(|(_, t)| *t == TONE_DANGER)
                {
                    tone = TONE_DANGER;
                }
                let mut lines: Vec<&str> = recovered.iter().map(|l| l.as_str()).collect();
                lines.extend(key_notices.iter().map(|(text, _)| text.as_str()));
                self.status = if lines.is_empty() && warning.is_none() && !otp_note {
                    first
                } else {
                    let mut parts = lines;
                    if parts.is_empty() || notice.is_some() {
                        parts.push(&first);
                    }
                    parts.extend(warning.map(Placement::message));
                    parts.extend(otp_note.then_some(vault::OTP_REMOVED));
                    joined(&parts)
                };
                self.status_tone = tone;
                self.build();
                Ok(())
            }
            // A vault file missing with no temp file its key opens is a
            // navigation problem, as check_files says before any key
            // derivation: the password was right, so no retry delay. Nor is
            // there one for a refusal of the files themselves (spec §5.1).
            Err(e) if e == LEFTOVER_TEMP || vault::not_a_failure(e) => Err(e),
            Err(e) => {
                self.failed = self.failed.saturating_add(1);
                self.retry =
                    Instant::now() + Duration::from_secs((1u64 << self.failed.min(6)).min(60));
                self.status("인증 실패. 잠시 후 다시 시도하세요.");
                Err(match auth_failure {
                    Some(text) if e == crypto::AUTH_ERROR => text,
                    _ => e,
                })
            }
        }
    }
    fn command(&mut self, id: i32, notify: u16) -> crypto::Result<()> {
        let id = match (id, self.screen) {
            (
                1,
                Screen::Login | Screen::Create | Screen::Restore | Screen::Password | Screen::Adopt,
            ) => SUBMIT,
            (1, Screen::Edit) => SAVE,
            (2, Screen::Edit | Screen::Password) => CANCEL,
            (2, Screen::Keys | Screen::Adopt) => BACK,
            #[cfg(feature = "security-key")]
            (1, Screen::Pair | Screen::LostKey | Screen::KeyRemove | Screen::Fetched) => SUBMIT,
            #[cfg(feature = "security-key")]
            (2, Screen::Pair | Screen::LostKey | Screen::KeyRemove | Screen::Review) => BACK,
            (2, Screen::Vault) => LOCK,
            (2, Screen::Login | Screen::Create | Screen::Restore) if self.handle(BACK) != 0 => BACK,
            (1 | 2, _) => return Ok(()),
            _ => id,
        };
        #[cfg(feature = "security-key")]
        if self.tofu_blocks(id) {
            return Err(keys_ui::TOFU_FIRST);
        }
        if !self.allows(id) {
            return Err("현재 화면에서 허용되지 않는 작업입니다.");
        }
        if self.closing {
            return Err("클립보드 정리 후 종료를 기다리고 있습니다.");
        }
        self.activity = Instant::now();
        if notify == 0x300 && matches!(id, PASS | CONFIRM | CURRENT_PASS) {
            self.auth_dirty = true;
        }
        if notify == 0x300 && matches!(id, VPATH | KPATH) {
            self.refresh_key_note();
            return Ok(());
        }
        // The kind typed: the editor's shape follows it.
        if notify == 0x300 && id == KIND {
            self.edit_shape();
            return Ok(());
        }
        // The review list's double click and its loss date (spec §5.13).
        #[cfg(feature = "security-key")]
        if self.review_notice(id, notify)? {
            return Ok(());
        }
        // Focus moved between inputs: repaint the field outlines.
        if matches!(notify, 0x100 | 0x200) || (id == LIST && matches!(notify, 4 | 5)) {
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
            return Ok(());
        }
        if id == LIST && notify == 1 {
            let i = unsafe { SendMessageW(self.handle(LIST), 0x188, 0, 0) };
            self.selected = if i >= 0 { Some(i as usize) } else { None };
            self.reveal_until = None;
            self.qr = None;
            self.page = 0;
            self.reset_copy();
            self.sync_detail();
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
            return Ok(());
        }
        if notify != 0 {
            return Ok(());
        }
        if self.session.is_some() {
            check_environment(self.hwnd)?;
        }
        // The toggles and screen changes of the security-key build.
        #[cfg(feature = "security-key")]
        if self.toggle(id)? {
            return Ok(());
        }
        #[cfg(feature = "security-key")]
        if id == BACK
            && matches!(
                self.screen,
                Screen::Pair | Screen::LostKey | Screen::KeyRemove
            )
        {
            self.show(Screen::Keys);
            self.build();
            return Ok(());
        }
        match id {
            // Keys leads back to the vault list, Adopt to Keys.
            BACK if matches!(self.screen, Screen::Keys | Screen::Adopt) => {
                self.adopt_source = None;
                self.show(if self.screen == Screen::Adopt {
                    Screen::Keys
                } else {
                    Screen::Vault
                });
                self.build();
            }
            CREATE | OPEN | RESTORE | BACK => {
                check_environment(self.hwnd)?;
                self.paths()?;
                // Generate before switching so a failure leaves the screen as is.
                // Back or Esc keeps it; lock and the idle timeout drop it.
                if id == CREATE && self.provision.is_none() {
                    self.provision = Some(Provision::new()?);
                }
                self.copy_until = None;
                self.reveal_until = None;
                self.from_welcome = id == OPEN;
                self.show(match id {
                    CREATE => Screen::Create,
                    RESTORE => Screen::Restore,
                    OPEN => Screen::Login,
                    // Back from the login opened from "서버에서 가져온 금고".
                    #[cfg(feature = "security-key")]
                    _ if self.screen == Screen::Login && self.home() == Screen::Fetched => {
                        Screen::Fetched
                    }
                    _ if self.screen == Screen::Login => Screen::Welcome,
                    _ => self.home(),
                });
                self.status = line("");
                self.build();
            }
            SUBMIT => self.submit()?,
            LOCK => self.lock("수동으로 잠갔습니다.", true),
            NEW | EDIT => {
                self.editing = if id == EDIT {
                    Some(self.selected.ok_or("수정할 항목을 선택하세요.")?)
                } else {
                    None
                };
                self.reset_copy();
                self.reveal_until = None;
                self.show(Screen::Edit);
                self.build();
            }
            // The password change returns to Keys, where it was started,
            // and an entry opened from the review to the review.
            CANCEL => {
                let back = if self.screen == Screen::Password {
                    Screen::Keys
                } else {
                    self.after_edit()
                };
                self.show(back);
                self.build();
            }
            THEME_DARK | THEME_LIGHT => self.set_theme(id == THEME_DARK),
            LANG_KO | LANG_EN => self.set_language(id == LANG_EN),
            AUTO_LOCK..=AUTO_LOCK_LAST => self.set_auto_lock((id - AUTO_LOCK) as usize),
            PEEK_PASS | PEEK_CONFIRM | PEEK_CURRENT | PEEK_OTP => self.peek(id)?,
            PRESET..=PRESET_LAST => unsafe {
                let kind = self.handle(KIND);
                let name = KIND_PRESETS[(id - PRESET) as usize];
                SetWindowTextW(kind, wide(tr(name)).as_ptr());
                SendMessageW(kind, 0xcd, 0, 0);
                self.edit_shape();
                // The OTP kind's main field is its OTP secret.
                let next = if styled_visible(self.handle(SECRET)) {
                    SECRET
                } else {
                    OTP_FIELD
                };
                SetFocus(self.handle(next));
                InvalidateRect(self.hwnd, null(), 0);
            },
            SAVE => {
                if self.input_failed {
                    return Err("입력 보호 설정 실패로 저장을 중단합니다.");
                }
                let mut title = self.read(TITLE)?;
                let mut kind = self.read(KIND)?;
                let mut secret = self.read(SECRET)?;
                let mut notes = self.read(NOTES)?;
                let otp = Otp::from_editor(
                    &self.read(OTP_FIELD)?,
                    &self.read(OTP_ISSUER)?,
                    &self.read(OTP_ACCOUNT)?,
                )?;
                let e = Entry::new_with_otp(
                    std::mem::take(&mut *title),
                    std::mem::take(&mut *kind),
                    std::mem::take(&mut *secret),
                    std::mem::take(&mut *notes),
                    otp.as_ref(),
                )?;
                let s = self.session.as_mut().ok_or("금고가 잠겼습니다.")?;
                // `editing` is still the entry's index: merges wait while
                // the edit screen is shown (see timer).
                s.put(self.editing, e)?;
                self.sync_badge = s.badge();
                self.selected = self.editing.or(Some(s.entries.len() - 1));
                self.page = 0;
                let back = self.after_edit();
                self.show(back);
                self.status = line("암호화하여 저장했습니다.");
                self.build();
            }
            CHANGE | KEY_PASSWORD => {
                self.reset_copy();
                self.reveal_until = None;
                self.show(if id == CHANGE {
                    Screen::Keys
                } else {
                    Screen::Password
                });
                self.build();
            }
            TOGGLE => {
                if self.copy_until.is_some() {
                    self.reset_copy();
                } else {
                    self.copy_until = Some(Instant::now() + Duration::from_secs(30));
                    self.set_toggle(true);
                    self.status(
                        "복사 허용: 클립보드 감시 프로그램이 복사한 값을 읽을 수 있습니다.",
                    );
                }
            }
            COPY => {
                if self.copy_until.is_none_or(|t| Instant::now() >= t) {
                    self.reset_copy();
                    return Err("먼저 복사 허용을 켜주세요.");
                }
                let e = self.entry().ok_or("복사할 항목을 선택하세요.")?;
                if e.is_otp_entry() {
                    return Err(NO_SECRET);
                }
                let seq = copy_value(self.hwnd, &e.secret)?;
                self.clipboard = Some((seq, Instant::now() + Duration::from_secs(15)));
                self.reset_copy();
                self.status("복사 완료 · 15초 안에 붙여넣으세요. 복사 허용은 다시 꺼졌습니다.");
            }
            OTP_COPY => {
                let e = self.entry().ok_or("복사할 항목을 선택하세요.")?;
                let otp = e.otp().ok_or(NO_OTP)?;
                let code = otp.code(clock::now()?);
                let seq = copy_value(self.hwnd, &code)?;
                self.clipboard = Some((seq, Instant::now() + Duration::from_secs(15)));
                self.status("OTP 코드를 복사했습니다 · 15초 안에 붙여넣으세요.");
            }
            OTP_SECRET_COPY => {
                if self.copy_until.is_none_or(|t| Instant::now() >= t) {
                    self.reset_copy();
                    return Err("먼저 복사 허용을 켜주세요.");
                }
                let e = self.entry().ok_or("복사할 항목을 선택하세요.")?;
                let otp = e.otp().ok_or(NO_OTP)?;
                let seq = copy_value(self.hwnd, &otp.secret_base32())?;
                self.clipboard = Some((seq, Instant::now() + Duration::from_secs(15)));
                self.reset_copy();
                self.status(
                    "OTP 시크릿을 복사했습니다 · 15초 안에 붙여넣으세요. 복사 허용은 다시 꺼졌습니다.",
                );
            }
            OTP_QR => {
                if self.qr_shown() {
                    self.hide_qr();
                } else {
                    let e = self.entry().ok_or("항목을 선택하세요.")?;
                    if !e.has_otp() {
                        return Err(NO_OTP);
                    }
                    self.qr = Some((e.id(), Instant::now() + QR_SHOWN));
                    self.reveal_until = None;
                    self.page = 0;
                    self.sync_detail();
                    unsafe {
                        InvalidateRect(self.hwnd, null(), 0);
                    }
                }
            }
            REVEAL => {
                if self.selected.is_none() {
                    return Err("항목을 선택하세요.");
                }
                self.page = 0;
                self.reveal_until = match self.reveal_until {
                    Some(_) => None,
                    None => Some(Instant::now() + Duration::from_secs(15)),
                };
                self.sync_detail();
                unsafe {
                    InvalidateRect(self.hwnd, null(), 0);
                }
            }
            PREVIOUS | NEXT => {
                if self.reveal_until.is_none_or(|t| Instant::now() >= t) {
                    return Err("먼저 15초간 보기를 눌러주세요.");
                }
                let e = self.entry().ok_or("항목을 선택하세요.")?;
                if e.is_otp_entry() {
                    return Err(NO_SECRET);
                }
                let pages = self.shown(e)?.len();
                self.page = if id == NEXT {
                    (self.page + 1).min(pages.saturating_sub(1))
                } else {
                    self.page.saturating_sub(1)
                };
                self.reveal_until = Some(Instant::now() + Duration::from_secs(15));
                unsafe {
                    InvalidateRect(self.hwnd, null(), 0);
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn allows(&self, id: i32) -> bool {
        if matches!(
            self.screen,
            Screen::Vault | Screen::Edit | Screen::Password | Screen::Keys | Screen::Adopt
        ) && self.session.is_none()
        {
            return false;
        }
        #[cfg(feature = "security-key")]
        if matches!(
            self.screen,
            Screen::Pair | Screen::LostKey | Screen::KeyRemove | Screen::Review
        ) && self.session.is_none()
        {
            return false;
        }
        if matches!(id, THEME_DARK | THEME_LIGHT | LANG_KO | LANG_EN) {
            return true;
        }
        #[cfg(feature = "security-key")]
        if let Some(allowed) = self.allows_sk(id) {
            return allowed;
        }
        match self.screen {
            Screen::Welcome => matches!(id, CREATE | RESTORE | OPEN),
            Screen::Login => matches!(
                id,
                CREATE
                    | RESTORE
                    | BACK
                    | SUBMIT
                    | BROWSE_V
                    | BROWSE_K
                    | VPATH
                    | KPATH
                    | PASS
                    | PEEK_PASS
            ),
            Screen::Create => matches!(
                id,
                BACK | SUBMIT
                    | BROWSE_V
                    | BROWSE_K
                    | VPATH
                    | KPATH
                    | PASS
                    | CONFIRM
                    | PEEK_PASS
                    | PEEK_CONFIRM
            ),
            Screen::Restore => matches!(
                id,
                BACK | SUBMIT
                    | BROWSE_V
                    | BROWSE_K
                    | BROWSE_D
                    | VPATH
                    | KPATH
                    | DEST
                    | PASS
                    | PEEK_PASS
            ),
            Screen::Vault => matches!(
                id,
                LOCK | BACKUP
                    | KEYBACKUP
                    | CHANGE
                    | LIST
                    | NEW
                    | EDIT
                    | DELETE
                    | REVEAL
                    | TOGGLE
                    | COPY
                    | PREVIOUS
                    | NEXT
                    | OTP_COPY
                    | OTP_SECRET_COPY
                    | OTP_QR
                    | AUTO_LOCK..=AUTO_LOCK_LAST
            ),
            Screen::Edit => matches!(
                id,
                TITLE
                    | KIND
                    | SECRET
                    | NOTES
                    | OTP_FIELD
                    | OTP_ISSUER
                    | OTP_ACCOUNT
                    | PEEK_OTP
                    | SAVE
                    | CANCEL
                    | PRESET..=PRESET_LAST
            ),
            Screen::Password => matches!(
                id,
                PASS | CONFIRM
                    | CURRENT_PASS
                    | PEEK_PASS
                    | PEEK_CONFIRM
                    | PEEK_CURRENT
                    | SUBMIT
                    | CANCEL
            ),
            Screen::Keys => matches!(
                id,
                BACK | KEY_PASSWORD
                    | KEY_ADOPT
                    | KEYBACKUP
                    | KEY_OVERRIDE_HEAD
                    | KEY_LOCAL_OK
                    | PENDING_FORGET
                    | CURRENT_PASS
                    | PEEK_CURRENT
            ),
            Screen::Adopt => matches!(id, BACK | SUBMIT | CURRENT_PASS | PEEK_CURRENT),
            // Decided by allows_sk.
            #[cfg(feature = "security-key")]
            Screen::Pair
            | Screen::LostKey
            | Screen::KeyRemove
            | Screen::Review
            | Screen::Fetched => false,
        }
    }
    fn reset_copy(&mut self) {
        self.copy_until = None;
        self.set_toggle(false);
    }
    /// Whether the detail card shows the QR panel: on the vault list, for
    /// the entry it was opened for, which still has an OTP secret, and
    /// before its time is up.
    fn qr_shown(&self) -> bool {
        self.screen == Screen::Vault
            && self.qr.is_some_and(|(id, until)| {
                Instant::now() < until && self.entry().is_some_and(|e| e.id() == id && e.has_otp())
            })
    }
    /// The QR panel's QR_SHOWN are up at `now`: it goes (see timer).
    fn expire_qr(&mut self, now: Instant) {
        if self.qr.is_some_and(|(_, t)| now >= t) {
            self.hide_qr();
        }
    }
    /// Takes the QR panel away, with the secret's buttons back.
    fn hide_qr(&mut self) {
        if self.qr.take().is_some() {
            self.sync_detail();
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
        }
    }
    /// A pasted otpauth URI: its issuer and account fill the two fields
    /// next to the secret, over what they held (the paste is the user's).
    fn otp_pasted(&mut self) {
        if self.screen != Screen::Edit {
            return;
        }
        let Ok(text) = self.read(OTP_FIELD) else {
            return;
        };
        match Otp::parse(&text) {
            Ok(Some(o)) => {
                unsafe {
                    SetWindowTextW(self.handle(OTP_ISSUER), secret_wide(&o.issuer).as_ptr());
                    SetWindowTextW(self.handle(OTP_ACCOUNT), secret_wide(&o.account).as_ptr());
                }
                self.status("otpauth 주소에서 발급자와 계정 이름을 채웠습니다.");
            }
            Ok(None) => {}
            Err(e) => self.error(e),
        }
    }
    fn set_toggle(&self, on: bool) {
        unsafe {
            let toggle = self.handle(TOGGLE);
            if toggle != 0 {
                let variant = if on { theme::TOGGLE_ON } else { theme::TOGGLE };
                SetWindowLongPtrW(toggle, -21, variant);
                InvalidateRect(toggle, null(), 0);
            }
            EnableWindow(self.handle(COPY), on as i32);
            EnableWindow(self.handle(OTP_SECRET_COPY), on as i32);
            if self.screen == Screen::Vault {
                let (x, y, w, h) = HINT;
                InvalidateRect(self.hwnd, &self.r(x, y, w, h), 0);
            }
        }
    }
    fn timer(&mut self) {
        // Threads Windows started since the last tick (e.g. for a file
        // dialog). One that stays open to other programs is said, and the
        // flag stays (VC-4).
        if !threads_restricted() {
            self.weaken(THREADS_OPEN);
        }
        let now = Instant::now();
        let ticking =
            self.reveal_until.is_some() || self.copy_until.is_some() || self.clipboard.is_some();
        if self.clipboard.is_some_and(|(_, t)| now >= t) {
            self.expire_clipboard();
        }
        // A close during a ceremony waits for its end (spec §8.6): the
        // first tick after it destroys the window.
        if self.closing && self.clipboard.is_none() && !in_ceremony() {
            unsafe {
                DestroyWindow(self.hwnd);
            }
            return;
        }
        // During a ceremony only the environment and the cap: Windows'
        // dialog belongs to another process, so this window is not in
        // front, and that is neither being away nor idleness. No sync poll.
        #[cfg(feature = "security-key")]
        if in_ceremony() {
            if let Err(e) = check_environment(self.hwnd) {
                self.lock(e, true);
            }
            ceremony_overdue();
            return;
        }
        if self.copy_until.is_some_and(|t| now >= t) {
            self.reset_copy();
        }
        if self.reveal_until.is_some_and(|t| now >= t) {
            self.reveal_until = None;
            self.sync_detail();
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
        }
        self.expire_qr(now);
        // The OTP code and its countdown, and the QR panel's.
        if self.screen == Screen::Vault && self.entry().is_some_and(Entry::has_otp) {
            let (dy, h) = OTP_TICKING;
            let caption = self.qr_area().0;
            unsafe {
                let ticking = self.r(CARD_X, self.otp_top() + dy, CARD_W, h);
                InvalidateRect(self.hwnd, &ticking, 0);
                if self.qr.is_some() {
                    InvalidateRect(self.hwnd, &self.r(CARD_X, caption - 2, CARD_W, 24), 0);
                }
            }
        }
        if self.session.is_some() || self.provision.is_some() || self.auth_dirty {
            if let Err(e) = check_environment(self.hwnd) {
                self.lock(e, true);
                return;
            }
            // The foreground window decides, not WM_ACTIVATEAPP alone: a missed
            // message must not lock a vault in use, and a missed or faked one
            // must not stop the away lock (e.g. focus left during an unlock).
            if is_foreground(self.hwnd) {
                self.activated();
            } else if !self.inactive || (self.session.is_some() && self.away_since.is_none()) {
                self.deactivated();
            }
            let away = self.away_since.map_or(Duration::ZERO, |t| now - t);
            // During a flow the idle limit below stands in for the away lock.
            if self.session.is_some()
                && self.auto_lock == 0
                && away >= AWAY_LOCK
                && self.flow.is_none()
            {
                self.lock("다른 앱에 30초 넘게 머물러 잠갔습니다.", false);
                return;
            }
            let idle = now.duration_since(self.activity);
            // Typed forms before a vault is open are cleared on fixed times;
            // making a vault takes longer, and so does answering a flow's
            // questions, which may mean reading a code on another PC (spec
            // §9.2a). "Off" stays off.
            let limit = if self.provision.is_some() {
                Some(Duration::from_secs(300))
            } else if self.session.is_none() {
                Some(Duration::from_secs(60))
            } else {
                AUTO_LOCKS[self.auto_lock].1
            };
            let limit = match self.flow {
                Some(_) => limit.map(|l| l.max(FLOW_IDLE)),
                None => limit,
            };
            // Time in another app counts as unused even if an input slipped by.
            if limit.is_some_and(|l| idle.max(away) >= l) {
                self.lock("미사용 시간이 지나 자동으로 잠갔습니다.", true);
                return;
            }
        }
        // Merges wait while an entry is edited, another screen is shown or a
        // dialog runs, so `editing` and `selected` keep pointing at the
        // entry they meant; the first tick back on the list applies them.
        // The Keys screen polls too, so its key-file sync line and buttons
        // follow the server (a key view the helper wrote, another PC's key
        // file it fetched), but never while a flow runs there: a key
        // change works on the state its first phase read.
        self.sync_ticks = self.sync_ticks.wrapping_add(1);
        let polled = match self.screen {
            Screen::Vault => true,
            Screen::Keys => self.flow.is_none(),
            _ => false,
        };
        if self.sync_ticks.is_multiple_of(SYNC_TICKS)
            && self.session.is_some()
            && polled
            && !self.closing
            && !in_modal()
        {
            self.poll_sync();
            self.refresh_keys();
        }
        if ticking && self.screen == Screen::Vault {
            let (x, y, w, h) = HINT;
            unsafe {
                InvalidateRect(self.hwnd, &self.r(x, y, w, h), 0);
            }
        }
    }
    /// One look at the sync folder from the vault list or the Keys screen
    /// (see timer). A merge can move or replace entries: the selection
    /// follows its entry by ID, or the entry that replaced it by an edit on
    /// another PC. The 15-second view and copy permission end with any
    /// change to the list, since a merge can also put other text under the
    /// same ID. Only the vault list is rebuilt for it: the Keys screen keeps
    /// what was typed (see refresh_keys). Polling is not use (`activity`
    /// stays) and its notices never beep.
    fn poll_sync(&mut self) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let kept = self.selected.and_then(|i| s.entry_id(i));
        let event = s.poll_sync();
        // A save of the poll hit the replace gap: the newest state is only
        // in a temp file, which the next unlock takes back (spec §5.7).
        if s.gap_kept() {
            self.error(GAP_KEPT);
            return;
        }
        // What a key change left to finish, found at this poll
        // (S-KEYTEMP-GONE asks for a key backup now).
        let notices: Vec<(Zeroizing<String>, isize)> =
            s.take_key_notices().iter().map(key_line).collect();
        if !notices.is_empty() {
            let lines: Vec<&str> = notices.iter().map(|(text, _)| text.as_str()).collect();
            let danger = notices.iter().any(|(_, tone)| *tone == TONE_DANGER);
            self.set_status(
                &joined(&lines),
                if danger { TONE_DANGER } else { TONE_MUTED },
            );
            return;
        }
        let Some(event) = event else {
            return;
        };
        if event.badge_changed {
            self.sync_badge = s.badge();
        }
        let line = event.notice.as_ref().map(sync_line);
        if event.list_changed {
            self.selected = kept.and_then(|id| s.entry_index(&id).or_else(|| s.successor(&id)));
            self.reveal_until = None;
            self.qr = None;
            self.page = 0;
            self.reset_copy();
        }
        if event.list_changed && self.screen == Screen::Vault {
            if let Some((text, tone)) = line {
                self.status.zeroize();
                self.status.push_str(&text);
                self.status_tone = tone;
            } else {
                // The line stays as it is, in its tone.
                self.status_tone = unsafe { GetWindowLongPtrW(self.handle(STATUS), -21) };
            }
            self.build();
        } else {
            if let Some((text, tone)) = line {
                self.set_status(&text, tone);
            }
            if event.badge_changed {
                unsafe {
                    InvalidateRect(self.hwnd, &self.r(40, 22, PILL_RIGHT - 40, 34), 0);
                }
            }
        }
    }
    /// Clicking a field's padding focuses the borderless control inside it.
    fn click(&self, l: isize) {
        let (x, y) = (
            (l & 0xffff) as i16 as i32,
            ((l >> 16) & 0xffff) as i16 as i32,
        );
        for (frame, h) in &self.frames {
            let r = self.scaled(frame);
            if styled_visible(*h) && x >= r.left && x < r.right && y >= r.top && y < r.bottom {
                unsafe {
                    SetFocus(*h);
                    InvalidateRect(self.hwnd, null(), 0);
                }
                return;
            }
        }
    }
    fn hint(&self) -> String {
        let now = Instant::now();
        let left = |t: Instant| t.saturating_duration_since(now).as_millis().div_ceil(1000);
        let mut lines = vec![];
        if let Some(t) = self.reveal_until {
            lines.push(fill("{}초 뒤 다시 가려집니다.", &[&left(t)]));
        }
        if let Some(t) = self.copy_until {
            lines.push(fill("복사 허용 중 · {}초 안에 복사하세요.", &[&left(t)]));
        } else if let Some((_, t)) = self.clipboard {
            lines.push(if t > now {
                fill("복사한 값을 {}초 뒤 클립보드에서 지웁니다.", &[&left(t)])
            } else {
                tr("클립보드를 지우는 중입니다.").into()
            });
        }
        if lines.is_empty() {
            tr("복사하려면 먼저 '복사 허용'을 켜세요.\n복사한 값은 앱을 전환해도 15초간 유지된 뒤 지워집니다.")
                .into()
        } else {
            lines.join("\n")
        }
    }
    fn paint(&self) {
        let bg = theme::palette().bg;
        unsafe {
            let mut ps: Paint = std::mem::zeroed();
            let dc = BeginPaint(self.hwnd, &mut ps);
            let mut client = Rect::default();
            GetClientRect(self.hwnd, &mut client);
            // Double-buffered to avoid flicker on countdown repaints.
            let mem = CreateCompatibleDC(dc);
            let bmp = if mem != 0 {
                CreateCompatibleBitmap(dc, client.right.max(1), client.bottom.max(1))
            } else {
                0
            };
            if bmp == 0 {
                if mem != 0 {
                    DeleteDC(mem);
                }
                theme::fill(dc, &client, bg);
                self.draw_screen(dc);
            } else {
                let old = SelectObject(mem, bmp);
                theme::fill(mem, &client, bg);
                self.draw_screen(mem);
                let r = ps.rect;
                BitBlt(
                    dc,
                    r.left,
                    r.top,
                    r.right - r.left,
                    r.bottom - r.top,
                    mem,
                    r.left,
                    r.top,
                    0x00cc0020,
                );
                // Scrub revealed values from the off-screen copy before release.
                theme::fill(mem, &client, bg);
                SelectObject(mem, old);
                DeleteObject(bmp);
                DeleteDC(mem);
            }
            EndPaint(self.hwnd, &ps);
        }
    }
    unsafe fn draw_screen(&self, dc: isize) {
        let Some((title, small)) = theme::with(|t| (t.title(), t.small())) else {
            return;
        };
        let p = theme::palette();
        unsafe {
            // Brand and lock state.
            let brand = tr("고요 금고");
            theme::text(dc, brand, &self.r(40, 22, 200, 34), title, p.text, LINE);
            let open = self.session.as_ref();
            // A vault that syncs shows its sync state before the file name,
            // so the ellipsis of a long name never hides it.
            let badge = open.and(self.sync_badge);
            let state = match open {
                Some(s) => {
                    let name = s
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    match badge {
                        Some(b) => fill("열림 · {} · {}", &[&tr(badge_word(b)), &name]),
                        None => fill("열림 · {}", &[&name]),
                    }
                }
                None => tr("잠김").into(),
            };
            let state = self.pill_text(state);
            let x = self.px(40) + theme::text_width(dc, brand, title) + self.px(14);
            let width = theme::text_width(dc, &state, small) + self.px(32);
            let pill = Rect {
                left: x,
                top: self.px(28),
                right: (x + width).min(self.px(PILL_RIGHT)),
                bottom: self.px(50),
            };
            theme::round(dc, &pill, self.px(11), Some(p.surface), None);
            let dot = Rect {
                left: x + self.px(10),
                top: self.px(36),
                right: x + self.px(16),
                bottom: self.px(42),
            };
            let dot_color = match (open, badge) {
                _ if self.weakened.is_some() => p.danger,
                (None, _) => p.faint,
                (Some(_), Some(SyncBadge::Warning)) => p.danger,
                (Some(_), _) => p.unlocked,
            };
            theme::round(dc, &dot, self.px(3), Some(dot_color), None);
            let mut label = pill;
            label.left += self.px(22);
            label.right -= self.px(8);
            theme::text(dc, &state, &label, small, p.muted, LINE);
            let vault = (self.screen == Screen::Vault).then_some(AUTO_LOCK_SWITCH);
            for (sx, sy, sw, sh) in [THEME_SWITCH, LANG_SWITCH].into_iter().chain(vault) {
                theme::round(
                    dc,
                    &self.r(sx, sy, sw, sh),
                    self.px(9),
                    Some(p.surface),
                    None,
                );
            }
            match self.screen {
                Screen::Welcome => self.draw_welcome(dc, &p),
                Screen::Login if self.handle(CREATE) != 0 => {
                    let (x, y, w, h) = LOGIN_LINKS;
                    theme::fill(dc, &self.r(x, y, w, h), p.border);
                }
                Screen::Password => {
                    let card = self.r(AX, PASSWORD_CARD_Y, AW, 80);
                    theme::round(dc, &card, self.px(10), Some(p.bg), Some(p.border));
                }
                #[cfg(feature = "security-key")]
                Screen::Fetched => {
                    let (x, y, w, h) = LOGIN_LINKS;
                    theme::fill(dc, &self.r(x, y, w, h), p.border);
                }
                _ => {}
            }
            if self.screen == Screen::Vault {
                self.draw_detail(dc, small, title);
            }
            // Every field's frame last, over any card painted under it (the
            // TOFU banner's code field sits on the detail card): a field is
            // never drawn without its outline (spec §2.29).
            let focus = GetFocus();
            // A hidden field (the OTP kind's 비밀정보) has no outline.
            for (frame, h) in self.frames.iter().filter(|(_, h)| styled_visible(*h)) {
                let border = if *h == focus && *h != self.handle(LIST) {
                    p.focus
                } else {
                    p.border
                };
                let r = self.scaled(frame);
                theme::round(dc, &r, self.px(8), Some(p.bg), Some(border));
            }
        }
    }
    unsafe fn draw_welcome(&self, dc: isize, p: &theme::Palette) {
        let Some((title, small, strong, icon)) =
            theme::with(|t| (t.title(), t.small(), t.strong(), t.icon))
        else {
            return;
        };
        let center = DT_CENTER | DT_WORDBREAK | DT_NOPREFIX;
        unsafe {
            let badge = self.r(AX + AW / 2 - 32, 112, 64, 64);
            theme::round(dc, &badge, self.px(16), Some(p.surface), None);
            // Segoe Fluent Icons "Lock".
            theme::text(dc, "\u{E72E}", &badge, icon, p.text, DT_CENTER | LINE);
            let heading = tr("아직 저장된 금고가 없습니다");
            theme::text(dc, heading, &self.r(AX, 194, AW, 36), title, p.text, center);
            theme::text(
                dc,
                tr(
                    "비밀번호·니모닉·프라이빗키를 암호화해 이 PC에 보관합니다.\n처음 사용한다면 새 금고를 만드세요.",
                ),
                &self.r(AX, 236, AW, 44),
                small,
                p.muted,
                center,
            );
            let card = self.r(AX, 470, AW, 146);
            theme::round(dc, &card, self.px(12), None, Some(p.border));
            theme::text(
                dc,
                tr("금고를 열 때 필요한 것"),
                &self.r(AX + 20, 486, AW - 40, 20),
                small,
                p.muted,
                LINE,
            );
            let column = (AW - 40) / 4;
            for (i, (name, about)) in [
                ("금고 파일", "암호화된 항목\n(.goyo)"),
                ("열쇠 파일", "금고와 따로 보관\n(.goyokey)"),
                ("비밀번호", "12자 이상의\n긴 문장"),
            ]
            .into_iter()
            .enumerate()
            {
                let x = AX + 20 + i as i32 * column;
                let number = format!("{}  {}", i + 1, tr(name));
                theme::text(
                    dc,
                    &number,
                    &self.r(x, 518, column - 8, 22),
                    strong,
                    p.text,
                    LINE,
                );
                let wrap = DT_WORDBREAK | DT_NOPREFIX;
                theme::text(
                    dc,
                    tr(about),
                    &self.r(x, 546, column - 8, 54),
                    small,
                    p.muted,
                    wrap,
                );
            }
        }
    }
    unsafe fn draw_detail(&self, dc: isize, small: isize, title: isize) {
        let body = self.font_of(|t| t.body());
        let p = theme::palette();
        unsafe {
            let card = self.r(324, 82, 512, 542);
            theme::round(dc, &card, self.px(12), Some(p.bg), Some(p.border));
            #[cfg(feature = "security-key")]
            if self.tofu_banner() {
                return;
            }
            let Some(e) = self.entry() else {
                let empty = self.session.as_ref().is_none_or(|s| s.entries.is_empty());
                let message = tr(if empty {
                    "아직 저장된 항목이 없습니다.\n'+ 새 항목'으로 첫 비밀정보를 추가하세요."
                } else {
                    "왼쪽 목록에서 항목을 선택하세요."
                });
                let r = self.r(CARD_X, 320, CARD_W, 60);
                theme::text(
                    dc,
                    message,
                    &r,
                    body,
                    p.muted,
                    DT_CENTER | DT_WORDBREAK | DT_NOPREFIX,
                );
                return;
            };
            theme::text(
                dc,
                &e.title,
                &self.r(CARD_X, 104, 316, 34),
                title,
                p.text,
                LINE,
            );
            // Built-in types such as "니모닉" show in the interface language.
            let kind = tr(if e.kind.is_empty() {
                "종류 없음"
            } else {
                &e.kind
            });
            let chip_w = (theme::text_width(dc, kind, small) + self.px(24)).min(self.px(CARD_W));
            let chip = Rect {
                left: self.px(CARD_X),
                top: self.px(144),
                right: self.px(CARD_X) + chip_w,
                bottom: self.px(168),
            };
            theme::round(dc, &chip, self.px(12), Some(p.surface), None);
            theme::text(dc, kind, &chip, small, p.muted, DT_CENTER | LINE);
            theme::fill(dc, &self.r(CARD_X, 184, CARD_W, 1), p.border);
            let otp = e.otp();
            if e.is_otp_entry() {
                self.draw_otp_entry(dc, e, otp.as_ref(), small, title);
                return;
            }
            if let Some(o) = &otp {
                self.draw_otp(dc, o, OTP_TOP, small, title);
                if self.qr_shown() {
                    self.draw_qr(dc, e, o, small, body);
                    return;
                }
            }
            theme::text(
                dc,
                tr("비밀정보"),
                &self.r(CARD_X, 198, 200, 20),
                small,
                p.muted,
                LINE,
            );
            let box_rect = self.r(CARD_X, 224, CARD_W, 84);
            theme::round(dc, &box_rect, self.px(8), Some(p.surface), None);
            let revealed = self.reveal_until.is_some();
            let secret_rect = self.r(CARD_X + 16, 242, 430, 48);
            let wrap = DT_WORDBREAK | DT_NOPREFIX;
            if revealed {
                match self.shown(e) {
                    Ok(shown) => {
                        let index = self.page.min(shown.len() - 1);
                        match &shown {
                            Shown::Text(pages) => {
                                theme::text(dc, &pages[index], &secret_rect, body, p.text, wrap);
                            }
                            Shown::Grid(pages) => self.draw_grid(dc, &e.secret, &pages[index]),
                        }
                        if shown.len() > 1 {
                            let r = self.r(612, 198, 200, 20);
                            let n = fill("{} / {} 페이지", &[&(index + 1), &shown.len()]);
                            theme::text(dc, &n, &r, small, p.muted, DT_RIGHT | LINE);
                        }
                    }
                    Err(err) => theme::text(dc, tr(err), &secret_rect, body, p.danger, wrap),
                }
            } else {
                let r = self.r(CARD_X + 16, 224, 430, 84);
                theme::text(dc, "••••••••••••", &r, title, p.faint, LINE);
            }
            let (x, y, w, h) = HINT;
            theme::text(dc, &self.hint(), &self.r(x, y, w, h), small, p.muted, wrap);
            theme::fill(dc, &self.r(CARD_X, 428, CARD_W, 1), p.border);
            theme::text(
                dc,
                tr("메모"),
                &self.r(CARD_X, 442, 200, 20),
                small,
                p.muted,
                LINE,
            );
            // Two lines above the OTP row, for an entry with one.
            let notes = self.r(CARD_X, 468, CARD_W, if otp.is_some() { 44 } else { 132 });
            if e.notes.is_empty() {
                theme::text(dc, tr("메모 없음"), &notes, body, p.faint, wrap);
            } else if revealed {
                let flags = wrap | DT_EDITCONTROL | DT_END_ELLIPSIS;
                theme::text(dc, &e.notes, &notes, body, p.text, flags);
            } else {
                let hidden = tr("가려짐 · 보기를 누르면 비밀정보와 함께 표시됩니다.");
                theme::text(dc, hidden, &notes, small, p.muted, wrap);
            }
        }
    }
    /// An OTP entry (0.12.1): no 비밀정보, its OTP row in that place (or
    /// a line saying it has no OTP secret), then the QR panel or the hint
    /// and the memo, which the 15-second view shows with the OTP secret.
    unsafe fn draw_otp_entry(
        &self,
        dc: isize,
        e: &Entry,
        otp: Option<&Otp>,
        small: isize,
        title: isize,
    ) {
        let body = self.font_of(|t| t.body());
        let p = theme::palette();
        let wrap = DT_WORDBREAK | DT_NOPREFIX;
        unsafe {
            match otp {
                Some(o) => {
                    self.draw_otp(dc, o, OTP_ENTRY_TOP, small, title);
                    if self.qr_shown() {
                        self.draw_qr(dc, e, o, small, body);
                        return;
                    }
                }
                None => {
                    let r = self.r(CARD_X, OTP_ENTRY_TOP + 8, CARD_W, 44);
                    theme::text(dc, tr(NO_OTP), &r, body, p.muted, wrap);
                }
            }
            let (x, y, w, h) = HINT;
            theme::text(dc, &self.hint(), &self.r(x, y, w, h), small, p.muted, wrap);
            theme::fill(dc, &self.r(CARD_X, 428, CARD_W, 1), p.border);
            theme::text(
                dc,
                tr("메모"),
                &self.r(CARD_X, 442, 200, 20),
                small,
                p.muted,
                LINE,
            );
            let notes = self.r(CARD_X, 468, CARD_W, 132);
            if e.notes.is_empty() {
                theme::text(dc, tr("메모 없음"), &notes, body, p.faint, wrap);
            } else if self.reveal_until.is_some() {
                let flags = wrap | DT_EDITCONTROL | DT_END_ELLIPSIS;
                theme::text(dc, &e.notes, &notes, body, p.text, flags);
            } else {
                let hidden = tr("가려짐 · 보기를 누르면 OTP 시크릿과 함께 표시됩니다.");
                theme::text(dc, hidden, &notes, small, p.muted, wrap);
            }
        }
    }
    /// The OTP row with its top at `top` (OTP_TOP under the memo, or an
    /// OTP entry's OTP_ENTRY_TOP): the names, the code of the moment with
    /// its countdown (shown: it lives only for its period), and the secret,
    /// masked but during the 15-second view.
    unsafe fn draw_otp(&self, dc: isize, o: &Otp, top: i32, small: isize, title: isize) {
        let p = theme::palette();
        let dy = top - OTP_TOP;
        unsafe {
            if top == OTP_TOP {
                theme::fill(dc, &self.r(CARD_X, 522, CARD_W, 1), p.border);
            }
            let names = match (o.issuer.is_empty(), o.account.is_empty()) {
                (false, false) => format!("OTP · {} ({})", *o.issuer, *o.account),
                (false, true) => format!("OTP · {}", *o.issuer),
                (true, false) => format!("OTP · {}", *o.account),
                (true, true) => "OTP".to_owned(),
            };
            let names = Zeroizing::new(names);
            theme::text(
                dc,
                &names,
                &self.r(CARD_X, 530 + dy, CARD_W - 140, 20),
                small,
                p.muted,
                LINE,
            );
            match clock::now() {
                Ok(now) => {
                    let code = otp_grouped(&o.code(now));
                    let r = self.r(CARD_X, 554 + dy, OTP_ROW.0 - CARD_X - 8, 38);
                    theme::text(dc, &code, &r, title, p.text, LINE);
                    let left = fill("{}초 뒤 바뀜", &[&o.remaining(now)]);
                    let r = self.r(CARD_X + CARD_W - 136, 530 + dy, 136, 20);
                    theme::text(dc, &left, &r, small, p.muted, DT_RIGHT | LINE);
                }
                Err(e) => {
                    let r = self.r(CARD_X, 554 + dy, OTP_ROW.0 - CARD_X - 8, 38);
                    theme::text(dc, tr(e), &r, small, p.danger, LINE);
                }
            }
            let r = self.r(CARD_X, 598 + dy, CARD_W, 20);
            if self.reveal_until.is_some() {
                let shown = Zeroizing::new(fill("시크릿 {}", &[&*o.secret_grouped()]));
                theme::text(dc, &shown, &r, small, p.text, LINE);
            } else {
                theme::text(dc, tr("시크릿 ••••••••"), &r, small, p.faint, LINE);
            }
        }
    }
    /// The QR panel in the secret's place: the entry's otpauth URI as black
    /// modules on white with a four-module quiet zone, each module a whole
    /// number of pixels, as large as the area allows.
    unsafe fn draw_qr(&self, dc: isize, e: &Entry, o: &Otp, small: isize, body: isize) {
        let p = theme::palette();
        unsafe {
            let (caption, (x, y, w, h)) = self.qr_area();
            theme::text(
                dc,
                tr("QR 코드 · 휴대폰 인증 앱으로 스캔하세요"),
                &self.r(CARD_X, caption, CARD_W - 120, 20),
                small,
                p.muted,
                LINE,
            );
            if let Some((_, until)) = self.qr {
                let left = until
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .div_ceil(1000);
                let r = self.r(CARD_X + CARD_W - 120, caption, 120, 20);
                theme::text(
                    dc,
                    &fill("{}초 뒤 숨김", &[&left]),
                    &r,
                    small,
                    p.muted,
                    DT_RIGHT | LINE,
                );
            }
            let wrap = DT_WORDBREAK | DT_NOPREFIX;
            let uri = o.uri(&e.title);
            let code = match qr::encode(uri.as_bytes()) {
                Ok(code) => code,
                Err(err) => {
                    theme::text(dc, tr(err), &self.r(x, y, w, 60), body, p.danger, wrap);
                    return;
                }
            };
            let Some(layout) = qr_layout(code.size, self.px(w), self.px(h)) else {
                let r = self.r(x, y, w, 60);
                theme::text(dc, tr(QR_TOO_LARGE), &r, body, p.danger, wrap);
                return;
            };
            let left = self.px(x) + layout.offset.0;
            let top = self.px(y) + layout.offset.1;
            let m = layout.module;
            let side = m * (code.size as i32 + 8);
            let all = Rect {
                left,
                top,
                right: left + side,
                bottom: top + side,
            };
            theme::fill(dc, &all, 0x00FF_FFFF);
            // Each row's runs of dark modules as one rectangle.
            for row in 0..code.size {
                let mut col = 0;
                while col < code.size {
                    if !code.dark(col, row) {
                        col += 1;
                        continue;
                    }
                    let start = col;
                    while col < code.size && code.dark(col, row) {
                        col += 1;
                    }
                    let r = Rect {
                        left: left + (start as i32 + 4) * m,
                        top: top + (row as i32 + 4) * m,
                        right: left + (col as i32 + 4) * m,
                        bottom: top + (row as i32 + 5) * m,
                    };
                    theme::fill(dc, &r, 0);
                }
            }
        }
    }
    fn pages(&self, text: &str) -> crypto::Result<Vec<Zeroizing<String>>> {
        unsafe {
            let dc = GetDC(self.hwnd);
            if dc == 0 {
                return Err("화면 글자 크기를 측정할 수 없습니다.");
            }
            let previous = SelectObject(dc, self.font_of(|t| t.body()));
            let result = secret_pages(text, self.px(430), |line| {
                let w = secret_wide(line);
                let mut size = Size::default();
                if GetTextExtentPoint32W(dc, w.as_ptr(), w.len() as i32 - 1, &mut size) == 0 {
                    Err("화면 글자 크기를 측정할 수 없습니다.")
                } else {
                    Ok(size.cx)
                }
            });
            SelectObject(dc, previous);
            ReleaseDC(self.hwnd, dc);
            result
        }
    }
    /// What the 15-second view shows of `e`: a mnemonic (the built-in kind
    /// "니모닉") as its numbered grid, else, or when its grid fits at no
    /// face, the running text in pages.
    fn shown(&self, e: &Entry) -> crypto::Result<Shown> {
        if e.kind.as_str() == KIND_PRESETS[1]
            && let Some(pages) = self.grid(&e.secret)?
        {
            return Ok(Shown::Grid(pages));
        }
        self.pages(&e.secret).map(Shown::Text)
    }
    /// `secret`'s grid pages (see mnemonic_grid), measured with the grid's
    /// faces at this DPI.
    fn grid(&self, secret: &str) -> crypto::Result<Option<Vec<GridPage>>> {
        unsafe {
            let dc = GetDC(self.hwnd);
            if dc == 0 {
                return Err("화면 글자 크기를 측정할 수 없습니다.");
            }
            let gaps = (self.px(GRID_GAP), self.px(GRID_NUM_GAP));
            let result = mnemonic_grid(
                secret,
                self.px(GRID.2),
                theme::GRID_FONTS,
                gaps,
                |font, text| {
                    let face = theme::with(|t| t.grid_font(font)).unwrap_or(self.font);
                    Ok(theme::text_width(dc, text, face))
                },
            );
            ReleaseDC(self.hwnd, dc);
            result
        }
    }
    /// One page of a mnemonic's grid in the secret box: each word after its
    /// number, the numbers muted and right-aligned in their column, the
    /// rows centred in the box.
    unsafe fn draw_grid(&self, dc: isize, secret: &str, page: &GridPage) {
        let p = theme::palette();
        let face = theme::with(|t| t.grid_font(page.font)).unwrap_or(self.font);
        let (x, y, _, h) = GRID;
        let top = y + (h - page.rows as i32 * GRID_ROW) / 2;
        let (left, gap) = (self.px(x), self.px(GRID_NUM_GAP));
        for c in &page.cells {
            let row_top = self.px(top + c.row as i32 * GRID_ROW);
            let bottom = row_top + self.px(GRID_ROW);
            let number = Rect {
                left: left + c.x,
                top: row_top,
                right: left + c.x + c.num_w,
                bottom,
            };
            let word = Rect {
                left: number.right + gap,
                right: left + c.x + c.w,
                ..number
            };
            let n = c.number.to_string();
            unsafe {
                theme::text(dc, &n, &number, face, p.muted, DT_RIGHT | LINE);
                theme::text(dc, &secret[c.word.clone()], &word, face, p.text, LINE);
            }
        }
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.clear_controls();
        self.expire_clipboard();
    }
}

fn secret_pages(
    text: &str,
    max_width: i32,
    mut measure: impl FnMut(&str) -> crypto::Result<i32>,
) -> crypto::Result<Vec<Zeroizing<String>>> {
    let mut pages = Vec::new();
    let mut page = Zeroizing::new(String::with_capacity(512));
    let mut line = Zeroizing::new(String::with_capacity(256));
    let mut row = 0;
    for c in text.chars() {
        let c = match c {
            '\r' => '␍',
            '\t' => '⇥',
            other => other,
        };
        line.push(c);
        if c == '\n' || line.len() > 128 || measure(&line)? > max_width {
            row += 1;
            line.zeroize();
            if row == 2 {
                pages.push(page);
                page = Zeroizing::new(String::with_capacity(512));
                row = 0;
            } else {
                page.push('\n');
            }
            if c == '\n' {
                continue;
            }
            line.push(c);
            if measure(&line)? > max_width {
                return Err("표시할 글자가 화면 너비를 초과합니다.");
            }
        }
        page.push(c);
    }
    if !page.is_empty() || pages.is_empty() {
        pages.push(page);
    }
    Ok(pages)
}

/// What the 15-second view shows: running text in pages, or a mnemonic's
/// numbered grid in pages.
enum Shown {
    Text(Vec<Zeroizing<String>>),
    Grid(Vec<GridPage>),
}
impl Shown {
    fn len(&self) -> usize {
        match self {
            Shown::Text(pages) => pages.len(),
            Shown::Grid(pages) => pages.len(),
        }
    }
}
/// A mnemonic's numbered grid: 8 words a row, 3 rows a page.
const GRID_COLS: usize = 8;
const GRID_ROWS: usize = 3;
/// The grid's place in the secret box (96-DPI units), the height of one
/// row, the space between two columns and between a number and its word.
const GRID: (i32, i32, i32, i32) = (CARD_X + 8, 224, CARD_W - 16, 84);
const GRID_ROW: i32 = 26;
const GRID_GAP: i32 = 6;
const GRID_NUM_GAP: i32 = 3;
/// The page, row and column of word `i` (from 0) of a mnemonic's grid; its
/// number is `i + 1`.
/// Whether a control has the WS_VISIBLE style, whether or not its window
/// is on screen.
fn styled_visible(h: Hwnd) -> bool {
    unsafe { GetWindowLongPtrW(h, -16) & 0x1000_0000 != 0 }
}
fn grid_place(i: usize) -> (usize, usize, usize) {
    let per_page = GRID_COLS * GRID_ROWS;
    (i / per_page, i % per_page / GRID_COLS, i % GRID_COLS)
}
/// A word on a page of the grid: its number, row and column; its column's
/// left edge and width and the width of its number column (device px from
/// the grid's left); where the word is in the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GridCell {
    number: usize,
    row: usize,
    col: usize,
    x: i32,
    w: i32,
    num_w: i32,
    word: std::ops::Range<usize>,
}
/// A page of the grid: the face its words fit at (see Theme::grid_font)
/// and how many rows it has.
#[derive(Debug)]
struct GridPage {
    font: usize,
    rows: usize,
    cells: Vec<GridCell>,
}
/// Lays `secret`'s words (its whitespace-separated tokens; the secret is
/// not changed or copied) out on grid pages `width` device px wide. Each
/// page takes the first of `fonts` faces at which every column holds its
/// widest number and widest word side by side (`gaps`: between columns,
/// and between a number and its word): columns of one width when the
/// widest fits so, else a long word widens its own column and narrows none
/// below its own content; the spare width is shared out, and no two
/// columns overlap. None when there is no word, or when a page
/// fits at no face: the caller then shows the running text, in pages.
/// `measure(font, text)` is the width of `text` in face `font`.
fn mnemonic_grid(
    secret: &str,
    width: i32,
    fonts: usize,
    gaps: (i32, i32),
    mut measure: impl FnMut(usize, &str) -> crypto::Result<i32>,
) -> crypto::Result<Option<Vec<GridPage>>> {
    let (gap, num_gap) = gaps;
    let base = secret.as_ptr() as usize;
    let words: Vec<std::ops::Range<usize>> = secret
        .split_whitespace()
        .map(|w| {
            let start = w.as_ptr() as usize - base;
            start..start + w.len()
        })
        .collect();
    let mut pages: Vec<GridPage> = Vec::new();
    for (i, word) in words.into_iter().enumerate() {
        let (page, row, col) = grid_place(i);
        if pages.len() == page {
            pages.push(GridPage {
                font: 0,
                rows: 0,
                cells: Vec::new(),
            });
        }
        let p = &mut pages[page];
        p.rows = p.rows.max(row + 1);
        p.cells.push(GridCell {
            number: i + 1,
            row,
            col,
            x: 0,
            w: 0,
            num_w: 0,
            word,
        });
    }
    if pages.is_empty() {
        return Ok(None);
    }
    for page in &mut pages {
        let cols = page.cells.len().min(GRID_COLS);
        let mut fitted = None;
        for font in 0..fonts {
            let (mut num_w, mut word_w) = (vec![0; cols], vec![0; cols]);
            for c in &page.cells {
                num_w[c.col] = num_w[c.col].max(measure(font, &c.number.to_string())?);
                word_w[c.col] = word_w[c.col].max(measure(font, &secret[c.word.clone()])?);
            }
            let mut need: Vec<i32> = (0..cols).map(|c| num_w[c] + num_gap + word_w[c]).collect();
            let gaps = gap * (cols as i32 - 1);
            // Columns of one width when the widest fits so; else each as
            // wide as its own content.
            let widest = need.iter().copied().max().unwrap_or(0);
            if widest * cols as i32 + gaps <= width {
                need.fill(widest);
            }
            let total = need.iter().sum::<i32>() + gaps;
            if total <= width {
                fitted = Some((font, num_w, need, (width - total) / cols as i32));
                break;
            }
        }
        let Some((font, num_w, need, extra)) = fitted else {
            return Ok(None);
        };
        let mut lefts = Vec::with_capacity(cols);
        let mut x = 0;
        for w in &need {
            lefts.push(x);
            x += w + extra + gap;
        }
        page.font = font;
        for c in &mut page.cells {
            (c.x, c.w, c.num_w) = (lefts[c.col], need[c.col] + extra, num_w[c.col]);
        }
    }
    Ok(Some(pages))
}

// Native dialogs pump messages. No RefCell borrow may span these calls: timers,
// session lock notifications and focus loss must remain able to wipe secrets.
fn modal_command(h: Hwnd, id: i32) -> crypto::Result<()> {
    let prepared = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if a.closing {
            return Err("종료 중입니다.");
        }
        // The backups wait for the TOFU banner's step (spec §2.29).
        #[cfg(feature = "security-key")]
        if a.tofu_blocks(id) {
            return Err(keys_ui::TOFU_FIRST);
        }
        if !a.allows(id) {
            return Err("현재 화면에서 허용되지 않는 작업입니다.");
        }
        if matches!(id, BACKUP | KEYBACKUP | DELETE | KEY_ADOPT) && a.session.is_none() {
            return Err("금고가 잠겼습니다.");
        }
        // DELETE removes the entry the user confirmed, found again by its ID
        // afterwards, not whatever then sits at its index.
        let doomed = match (id, a.session.as_ref()) {
            (DELETE, Some(s)) => {
                let i = a.selected.ok_or("삭제할 항목을 선택하세요.")?;
                Some(s.entry_id(i).ok_or("항목 선택 오류")?)
            }
            _ => None,
        };
        a.activity = Instant::now();
        a.paths()?;
        a.reset_copy();
        a.reveal_until = None;
        a.qr = None;
        unsafe {
            InvalidateRect(h, null(), 1);
        }
        Ok((a.screen, a.selected, doomed))
    });
    drain_pending(h);
    let (screen, selected, doomed) = prepared?;
    if !APP.with(|cell| {
        cell.try_borrow().is_ok_and(|b| {
            b.as_ref()
                .is_some_and(|a| a.screen == screen && a.allows(id))
        })
    }) {
        return Err("금고가 잠겼습니다.");
    }
    unsafe {
        UpdateWindow(h);
    }
    let path = if id == DELETE {
        if !ask(
            h,
            "선택한 항목을 삭제할까요? 기존 백업 사본은 삭제되지 않습니다.",
        ) {
            return Ok(());
        }
        None
    } else {
        let save = matches!(id, BACKUP | KEYBACKUP | BROWSE_D) || screen == Screen::Create;
        let key = matches!(id, KEYBACKUP | BROWSE_K | KEY_ADOPT);
        // The two backups say in their dialog what each file is and where
        // it belongs (spec §2.29).
        let picked = match id {
            BACKUP => pick_file(
                h,
                true,
                "고요 금고/백업 (*.goyo)\0*.goyo\0모든 파일\0*.*\0",
                "goyo",
                VAULT_BACKUP_TITLE,
                None,
            ),
            KEYBACKUP => pick_file(
                h,
                true,
                "고요 열쇠 파일 (*.goyokey)\0*.goyokey\0모든 파일\0*.*\0",
                "goyokey",
                KEY_BACKUP_TITLE,
                None,
            ),
            _ => dialog(h, save, key),
        };
        let Some(p) = picked else {
            // A dialog that could not open is not a cancel.
            if dialog_failed() {
                return Err(DIALOG_FAILED);
            }
            return Ok(());
        };
        Some(p)
    };
    let result = APP.with(|cell| -> crypto::Result<()> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if a.closing || a.screen != screen || a.selected != selected {
            return Err("대화상자가 열린 동안 잠겼습니다. 다시 인증하세요.");
        }
        if let Err(e) = check_environment(h) {
            a.lock(e, true);
            return Err(e);
        }
        a.activity = Instant::now();
        match id {
            DELETE => {
                let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
                let i = doomed
                    .and_then(|id| s.entry_index(&id))
                    .ok_or("항목 선택 오류")?;
                s.delete(i)?;
                a.sync_badge = s.badge();
                a.selected = None;
                a.page = 0;
                a.status = line("항목을 삭제했습니다.");
                a.build();
            }
            BACKUP | KEYBACKUP => {
                let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
                let p = path.ok_or("경로 오류")?;
                if id == BACKUP {
                    s.backup(&p)?;
                } else {
                    s.backup_key(&p)?;
                }
                // The new key file of a change whose save is unknown is saved
                // now: the vault locks (S-KEYDAMAGED-LOCKED).
                if s.key_unsaved() {
                    a.lock(vault::KEY_DAMAGED_LOCKED, true);
                    return Ok(());
                }
                a.status(if id == BACKUP {
                    "금고 백업을 저장했습니다. 열 때 열쇠 파일과 비밀번호도 필요합니다."
                } else {
                    KEY_BACKED_UP
                });
            }
            // Another PC's key file, for Screen::Adopt. A file this build
            // cannot open says so at once (spec §4.7).
            KEY_ADOPT => {
                let p = path.ok_or("경로 오류")?;
                if let Some(refusal) = key_info(&p).and_then(|i| i.refusal()) {
                    return Err(refusal);
                }
                a.adopt_source = Some(p);
                a.show(Screen::Adopt);
                a.status = line("");
                a.build();
            }
            _ => {
                let p = path.ok_or("경로 오류")?;
                let field = match id {
                    BROWSE_V => VPATH,
                    BROWSE_K => KPATH,
                    _ => DEST,
                };
                let text = wide(&p.to_string_lossy());
                // A key file this build cannot open says so as soon as it is
                // chosen, never later as a wrong password (spec §4.7).
                let refusal = (field == KPATH)
                    .then(|| key_info(&p).and_then(|i| i.refusal()))
                    .flatten();
                *a.path_slot(field) = p;
                unsafe {
                    SetWindowTextW(a.handle(field), text.as_ptr());
                }
                // The change notice arrived while the state was busy.
                a.refresh_key_note();
                #[cfg(feature = "security-key")]
                if field == VPATH {
                    a.route_picked_vault();
                }
                if let Some(refusal) = refusal {
                    a.set_status(refusal, TONE_DANGER);
                }
            }
        }
        Ok(())
    });
    drain_pending(h);
    result
}
/// Runs a command in phases (spec §9.2a), so that no borrow of the app spans
/// anything that pumps messages: phase 1 checks the screen and takes what
/// was typed under a short borrow; questions in between run with no
/// borrow, like modal_command's dialogs, so timers and session notices can
/// still lock; phase 3 makes the library call under a borrow, and only if
/// nothing changed meanwhile, else the flow and its secrets are dropped.
/// The commands routed here (see phased) are SUBMIT on Login, Password,
/// Adopt, Create and Restore and the Keys screen's buttons that
/// change what holds key changes.
/// App::flow is set from phase 1 to the end. It returns before
/// window_proc's tail, so it drains the deferred events and makes the sync
/// offer itself.
fn phased_command(h: Hwnd, id: i32) -> crypto::Result<()> {
    let screen = APP.with(|cell| cell.try_borrow().ok()?.as_ref().map(|a| a.screen));
    let start = tells_end(screen)
        .then(|| {
            APP.with(|cell| {
                let mut b = cell.try_borrow_mut().ok()?;
                let a = b.as_mut()?;
                a.prompt.clear();
                Some((a.serial, a.told))
            })
        })
        .flatten();
    #[cfg(feature = "security-key")]
    let theirs = APP.with(|cell| {
        cell.try_borrow()
            .is_ok_and(|b| b.as_ref().is_some_and(|a| keys_ui::phased(a, id)))
    }) || matches!(screen, Some(Screen::Create | Screen::Restore));
    #[cfg(not(feature = "security-key"))]
    let theirs = false;
    let result = match screen {
        #[cfg(feature = "security-key")]
        _ if theirs => keys_ui::flow(h, id),
        #[cfg(not(feature = "security-key"))]
        Some(Screen::Create | Screen::Restore) => plain_flow(h),
        Some(Screen::Adopt) => adopt_flow(h),
        Some(Screen::Keys) => keys_flow(h, id),
        _ => submit_flow(h, id),
    };
    let _ = theirs;
    // The flow is over, however it ended.
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
        {
            a.flow = None;
        }
    });
    drain_pending(h);
    if let (Ok(()), Some(start)) = (&result, start) {
        told_how_it_ended(start);
    }
    // Raised only by the unlock just made.
    if APP.with(|cell| cell.try_borrow_mut().is_ok()) && SYNC_OFFER.with(|f| f.replace(false)) {
        offer_sync(h);
    }
    result
}
/// The screens whose flows say how they ended (see told_how_it_ended):
/// the key changes, an adopt and a password change, and the security-key
/// build's pairing and removals. A login, Create and Restore have lines
/// of their own.
fn tells_end(screen: Option<Screen>) -> bool {
    match screen {
        Some(Screen::Keys | Screen::Adopt | Screen::Password) => true,
        #[cfg(feature = "security-key")]
        Some(Screen::Pair | Screen::LostKey | Screen::KeyRemove) => true,
        _ => false,
    }
}
/// The status line of a flow that ended with no line of its own: nothing
/// told since it started (`start`: the serial and `told` then), or only its
/// last progress line still shown. Every failure, every refusal and every
/// write tells its own line, and a lock tells its own, so a flow that still
/// stands ended at the user's No or Cancel (FLOW_CANCELLED); one whose
/// screen changed under it stopped (FLOW_STOPPED). Neither wrote anything.
/// A closing window gets no line.
fn told_how_it_ended(start: (u64, u64)) {
    let (serial, told) = start;
    APP.with(|cell| {
        let Ok(mut b) = cell.try_borrow_mut() else {
            return;
        };
        let Some(a) = b.as_mut() else {
            return;
        };
        let prompted = !a.prompt.is_empty() && a.status.as_str() == a.prompt;
        a.prompt.clear();
        if a.closing || quitting() || a.session.is_none() || (a.told != told && !prompted) {
            return;
        }
        let text = if a.serial == serial {
            FLOW_CANCELLED
        } else {
            FLOW_STOPPED
        };
        a.set_status(text, TONE_MUTED);
    });
}
/// SUBMIT on Create and Restore (spec §9.2a, S45-1 #13, S45-2
/// #17): the same command as before, under one borrow, as a flow; the
/// security-key build's registrations and touches run in keys_ui's flows
/// instead. These flows have no question and no ceremony here.
#[cfg(not(feature = "security-key"))]
fn plain_flow(h: Hwnd) -> crypto::Result<()> {
    let _ = h;
    APP.with(|cell| -> crypto::Result<()> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.flow = Some(SUBMIT);
        a.command(SUBMIT, 0)
    })
}
/// SUBMIT on Login and Password: S-OLDER for a login whose vault file is
/// under an older key; S-ROTATE and the gate (spec §7.5) for a password
/// change, then its key backup (S-BACKUP).
fn submit_flow(h: Hwnd, id: i32) -> crypto::Result<()> {
    let flow = APP.with(|cell| -> crypto::Result<Flow> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        let flow = a.begin(id)?;
        a.flow = Some(id);
        Ok(flow)
    });
    drain_pending(h);
    // An anchor refusal at login offers the per-vault forget for these
    // files (security-key build, spec §5.10).
    #[cfg(feature = "security-key")]
    if let Err(e) = flow {
        keys_ui::offer_forget(e);
    }
    let mut flow = flow?;
    if let Some(sha) = flow.older() {
        // Not opened, and not a failed attempt: nothing was derived.
        if !ask(h, OLDER_QUESTION) {
            return Err(OLDER_DECLINED);
        }
        flow.confirmed_older = Some(sha);
    }
    // A key file with security keys: the touch, between the phases and
    // with no borrow (spec §5.2 step 3, §8.5). A key file without keys
    // never loads webauthn.dll.
    // A changed key file asks its gate first, before the touch and before
    // anything about the change is shown (spec §5.2 step 3, §7.15a); the
    // answer is judged once the unlock verified the password and the touch.
    // [나중에] opens the session in gate-pending mode.
    #[cfg(feature = "security-key")]
    let login_gate = match flow.prepared.as_ref().and_then(|p| p.login_gate()) {
        Some((kind, choices, epoch)) => {
            keys_ui::ask_gate(h, kind, &choices, None, epoch, None).map(|answer| (answer, epoch))
        }
        None => None,
    };
    // Windows' cancel of the unlock's ceremony may mean a key that only the
    // server's waiting key file lists (S-TRY-OTHERKEY, spec §5.2).
    #[cfg(feature = "security-key")]
    if let Some(request) = flow.prepared.as_ref().and_then(|p| p.unlock_request(h)) {
        match touch_step_or(h, flow.screen, flow.serial, request, keys_ui::TOUCH) {
            Ok(touch) => flow.touch = Some(touch),
            Err(Some(FidoError::Cancelled))
                if flow.screen == Screen::Login
                    && login_gate.is_none()
                    && flow.prepared.as_ref().is_some_and(|p| p.offers_other_key()) =>
            {
                let entry = flow
                    .prepared
                    .take()
                    .and_then(|p| p.other_key_entry(&flow.pass, flow.confirmed_older));
                if let Some(entry) = entry {
                    keys_ui::try_other_key(h, flow.screen, flow.serial, entry);
                }
                return Ok(());
            }
            Err(_) => return Ok(()),
        }
    }
    // What a key change does, then its gate (spec §7.5): asked with no
    // borrow, default No; No changes nothing. Checked again before the
    // code is spent: a gate that came up while a question was open is
    // asked as well.
    if let Some(q) = flow.question {
        let text = match flow.gate {
            Some(g) => format!(
                "{}

{}",
                tr(q),
                tr(g.question())
            ),
            None => tr(q).to_owned(),
        };
        if !ask(h, &text) {
            return Ok(());
        }
        flow.answered = flow.gate;
    }
    let mut gate = flow.gate.filter(|g| flow.answered != Some(*g));
    loop {
        if let Some(g) = gate {
            if !ask(h, g.question()) {
                return Ok(());
            }
            flow.answered = Some(g);
        }
        let now = APP.with(|cell| -> crypto::Result<Option<vault::Gate>> {
            let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
            b.as_mut().ok_or("화면이 닫혔습니다.")?.gate_now(&flow)
        });
        drain_pending(h);
        gate = now?;
        if gate.is_none() {
            break;
        }
    }
    #[cfg(feature = "security-key")]
    let login = flow.screen == Screen::Login;
    unsafe {
        UpdateWindow(h);
    }
    #[cfg(feature = "security-key")]
    let mut out = LoginOut::default();
    let (screen, serial) = (flow.screen, flow.serial);
    let result = APP.with(|cell| -> crypto::Result<bool> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        #[cfg(feature = "security-key")]
        return a.finish_out(flow, &mut out);
        #[cfg(not(feature = "security-key"))]
        a.finish(flow)
    });
    drain_pending(h);
    // AUTH with a server key file that could explain it: S-TRY-SERVER-KEY,
    // with the same touch (spec §5.2 second entry point).
    #[cfg(feature = "security-key")]
    if let (Err(e), Some(entry), Some(touch)) = (&result, out.entry.take(), out.touch.as_ref())
        && *e == crypto::AUTH_ERROR
    {
        if let Err(e) = keys_ui::try_server_key(h, screen, serial, *entry, touch) {
            report(h, e);
        }
        if opened_session() {
            keys_ui::review_after(h);
        }
        return Ok(());
    }
    let _ = (screen, serial);
    match result {
        Ok(true) => backup_after(h, BACKUP_QUESTION),
        Err(e) if e == vault::KEY_DAMAGED => save_damaged_key(h),
        Err(e) => return Err(e),
        Ok(false) => {}
    }
    // The login's gate, judged now against the opened key file; the pick of
    // a login that failed is dropped unjudged.
    #[cfg(feature = "security-key")]
    match login_gate {
        Some((answer, epoch)) if opened_session() => keys_ui::judge_login_gate(h, answer, epoch),
        None if opened_session() => keys_ui::later(),
        _ => {}
    }
    // The server's waiting key file, taken now with the unlock's touch and
    // the login's own Reauth (spec §5.2 step 9(b), §7.15 at login).
    #[cfg(feature = "security-key")]
    if let (Some(proof), Some(touch)) = (out.proof.take(), out.touch.take())
        && opened_session()
        && let Err(e) = keys_ui::accept_at_login(h, proof, touch)
    {
        report(h, e);
    }
    // S-REVIEW at every unlock while a review is due (spec §9.2 unlock
    // step 7, §5.13).
    #[cfg(feature = "security-key")]
    if login && opened_session() {
        keys_ui::review_after(h);
    }
    Ok(())
}
/// A login opened its session: the vault list shows it.
#[cfg(feature = "security-key")]
fn opened_session() -> bool {
    APP.with(|cell| {
        cell.try_borrow()
            .is_ok_and(|b| b.as_ref().is_some_and(|a| a.session.is_some()))
    })
}
/// [열기] on Screen::Adopt (spec §9.2 "Adopt", §5.8): the whole adopt as
/// one flow, from the public checks to the write, with one
/// re-authentication. The Reauth, the other file's
/// password and its opened keys live only in this frame and are wiped when
/// it returns. [취소], a No or a lock anywhere writes nothing.
fn adopt_flow(h: Hwnd) -> crypto::Result<()> {
    // P1: what was typed, and the public checks of the file as read now;
    // every later step works on exactly these bytes.
    let p1 = APP.with(|cell| -> crypto::Result<Option<_>> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(SUBMIT)?;
        let path = a.adopt_source.clone().ok_or("받을 열쇠 파일을 고르세요.")?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let other = KeyFile::read(&path)?;
        let check = s.adopt_check(&other, Source::File(path))?;
        // Nothing to write for these.
        let same = match check.class {
            AdoptClass::Equal => Some(vault::ADOPT_EQUAL),
            AdoptClass::Contained => Some(vault::ADOPT_CONTAINED),
            _ => None,
        };
        if let Some(same) = same {
            a.status(same);
            return Ok(None);
        }
        let current = a.read(CURRENT_PASS)?;
        a.flow = Some(SUBMIT);
        Ok(Some((a.serial, other, check, current)))
    });
    drain_pending(h);
    let Some((serial, other, check, current)) = p1? else {
        return Ok(());
    };
    // P3: the re-authentication, and the other file opened with this PC's
    // password.
    let first = phase(h, Screen::Adopt, serial, |a| {
        let serial = a.serial;
        let result = a
            .session
            .as_mut()
            .ok_or("금고가 잠겼습니다.")
            .and_then(|s| {
                let mut r = s.reauth(&current, None)?;
                r.app_serial = serial;
                let opened = s.adopt_open(&r, &other, None);
                Ok((r, opened))
            });
        let (r, opened) = result.inspect_err(|e| {
            if *e == crypto::AUTH_ERROR {
                a.failed_attempt();
            }
        })?;
        a.failed = 0;
        match opened {
            Ok(opened) => Ok((r, Some(opened))),
            // The other file has another password.
            Err(e) if e == crypto::AUTH_ERROR => Ok((r, None)),
            Err(e) => Err(e),
        }
    })?;
    let Some((r, opened)) = first else {
        return Ok(());
    };
    let same_password = opened.is_some();
    // A: S-NEWPASS-OTHER until the other file opens; each wrong password
    // counts as a failed attempt, and the retry delay applies.
    let opened = match opened {
        Some(opened) => opened,
        None => {
            let mut note = None;
            loop {
                let text = match note {
                    None => tr(NEWPASS_OTHER).to_owned(),
                    Some(e) => format!("{}\n\n{}", tr(e), tr(NEWPASS_OTHER)),
                };
                let buttons = [OK_BUTTON, CANCEL_BUTTON];
                let InputAnswer::Password(typed) =
                    ask_input(h, InputKind::Password, &text, &buttons)
                else {
                    return Ok(());
                };
                let tried = phase(h, Screen::Adopt, serial, |a| {
                    if Instant::now() < a.retry {
                        return Ok(Err(RETRY_WAIT));
                    }
                    let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                    match s.adopt_open(&r, &other, Some(&typed)) {
                        Ok(opened) => {
                            a.failed = 0;
                            Ok(Ok(opened))
                        }
                        Err(e) if e == crypto::AUTH_ERROR => {
                            a.failed_attempt();
                            Ok(Err(e))
                        }
                        Err(e) => Err(e),
                    }
                })?;
                match tried {
                    None => return Ok(()),
                    Some(Ok(opened)) => break opened,
                    Some(Err(e)) => note = Some(e),
                }
            }
        }
    };
    // P3: the preview, from the checks again for exactly this file.
    let plan = phase(h, Screen::Adopt, serial, |a| {
        let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
        s.adopt_preview(&r, &other, opened, &check, GatePass::none(&check), None)
    })?;
    let Some(plan) = plan else {
        return Ok(());
    };
    // A: the preview, then S-ADOPT-BOTHPASS where it applies.
    let preview = plan.preview().clone();
    let text = preview_text(&preview, same_password);
    let check_box = preview
        .own_pass
        .map(|on| (ADOPT_OWN_PASS, OWN_PASS_LABEL, on));
    let kind = InputKind::Preview { check: check_box };
    let own = match ask_input(h, kind, &text, &[ACCEPT_BUTTON, CANCEL_BUTTON]) {
        InputAnswer::Accept { checked } => checked,
        _ => return Ok(()),
    };
    if preview.both_passwords && !ask(h, ADOPT_BOTHPASS) {
        return Ok(());
    }
    // P3: the write.
    let acks = vault::Acks {
        password_only: false,
        union_password: if own {
            vault::UnionPassword::Own
        } else {
            vault::UnionPassword::Other
        },
        both_passwords: preview.both_passwords,
        // The fork options' dialog arrives with the key screens (stage 5).
        #[cfg(feature = "security-key")]
        fork_option: vault::ForkOption::Both,
        #[cfg(feature = "security-key")]
        keysync_on: false,
    };
    let written = phase(h, Screen::Adopt, serial, |a| {
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        let result = s.adopt(r, plan, Vec::new(), acks, vault::Consent::default(), false);
        let notices: Vec<(Zeroizing<String>, isize)> =
            s.take_key_notices().iter().map(key_line).collect();
        let badge = s.badge();
        let adopted = match result {
            Ok(adopted) => adopted,
            // As after a password change (S-KEYDAMAGED-SAVE).
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
        // The new vault file is only in its temp file: the app locks
        // (spec §5.5 S3), and the line says which password opens it.
        if adopted.gap_kept {
            a.error(vault::GAP_CHANGED);
            a.set_status(&joined(&[vault::GAP_CHANGED, pass]), TONE_DANGER);
            return Ok(false);
        }
        let code = fill(ADOPT_CODE, &[&adopted.code.show(adopted.state.epoch)]);
        let mut lines: Vec<&str> = vec![code.as_str(), pass];
        if adopted.vault_pending {
            lines.push(vault::VPENDING);
        }
        lines.extend(notices.iter().map(|(text, _)| text.as_str()));
        a.sync_badge = badge;
        a.adopt_source = None;
        a.show(Screen::Vault);
        a.status = joined(&lines);
        if notices.iter().any(|(_, tone)| *tone == TONE_DANGER) {
            a.status_tone = TONE_DANGER;
        }
        a.build();
        Ok(true)
    });
    match written {
        Ok(Some(true)) => backup_after(h, BACKUP_QUESTION),
        Err(e) if e == vault::KEY_DAMAGED => save_damaged_key(h),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    Ok(())
}
/// The adopt preview's text (spec §9.1): what is done with the other file,
/// the result's revision, a successor's key code (a union's exists only
/// once written), and the password in force where no check box decides it.
fn preview_text(p: &vault::Preview, same_password: bool) -> String {
    let what = match p.class {
        AdoptClass::Successor => ADOPT_SUCCESSOR,
        _ => ADOPT_UNION,
    };
    let mut lines = vec![tr(what).to_owned(), fill(ADOPT_RESULT, &[&p.epoch])];
    if let Some(code) = p.code {
        lines.push(fill(ADOPT_CODE, &[&code.show(p.epoch)]));
    }
    if p.own_pass.is_none() {
        let pass = if same_password {
            ADOPT_PASS_OWN
        } else {
            ADOPT_PASS_OTHER
        };
        lines.push(tr(pass).to_owned());
    }
    lines.join("\r\n\r\n")
}
/// A Keys-screen button that acts on what holds key changes (spec §9.2):
/// [서버 사본을 이 PC 상태로 덮어쓰기…] (§7.5a), [이 열쇠 파일이 맞습니다]
/// or [끝나지 않은 열쇠 변경 버리기…] (§5.10). Its question (danger,
/// default No), then (security-key build, a key file with keys) the touch
/// of one of its live, non-suspended keys, then a re-authentication with
/// the password typed on the screen, and the library call, which
/// checks the hold again.
fn keys_flow(h: Hwnd, id: i32) -> crypto::Result<()> {
    let p1 = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        a.enter(id)?;
        let s = a.session.as_ref().ok_or("먼저 금고를 열어주세요.")?;
        let (old, new) = (s.confirmed_epoch().unwrap_or(0), s.key_state().epoch);
        let (question, head) = match id {
            KEY_OVERRIDE_HEAD => {
                let head = s.head_to_override()?;
                let values: [&dyn std::fmt::Display; 3] =
                    [&head.epoch, &head.key_prefix(), &head.version];
                (fill(vault::OVERRIDE_HEAD, &values), Some(head))
            }
            KEY_LOCAL_OK if s.local_rollback() && !s.restore_held() => {
                let question = if s.badge().is_some() {
                    vault::LOCAL_OK_CONFIRM_SYNCED
                } else {
                    vault::LOCAL_OK_CONFIRM
                };
                (fill(question, &[&old, &new, &new]), None)
            }
            PENDING_FORGET => {
                let path = s.pending_elsewhere().ok_or(vault::NOTHING_HELD)?;
                (fill(vault::PENDING_DISCARD, &[&shown(path)]), None)
            }
            KEY_LOCAL_OK => return Err(vault::NOTHING_HELD),
            _ => return Err("현재 화면에서 허용되지 않는 작업입니다."),
        };
        // The allow list of the touch a key file with keys needs.
        #[cfg(feature = "security-key")]
        let request = match s.keys_overview() {
            Some(keys) => {
                authenticator().map_err(FidoError::text)?;
                Some(s.key_request(&keys.active(), h)?)
            }
            None => None,
        };
        #[cfg(not(feature = "security-key"))]
        let request: Option<()> = None;
        let current = a.read(CURRENT_PASS)?;
        a.flow = Some(id);
        Ok((a.serial, question, head, current, request))
    });
    drain_pending(h);
    let (serial, question, head, current, request) = p1?;
    if !ask(h, &question) {
        return Ok(());
    }
    // C: the touch (n ≥ 1), with no borrow.
    #[cfg(feature = "security-key")]
    let touch = match request {
        Some(request) => match touch_step(h, Screen::Keys, serial, request, keys_ui::TOUCH) {
            Some(touch) => Some(touch),
            None => return Ok(()),
        },
        None => None,
    };
    #[cfg(not(feature = "security-key"))]
    let _ = request;
    phase(h, Screen::Keys, serial, |a| {
        let serial = a.serial;
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        #[cfg(feature = "security-key")]
        let touched = touch.as_ref();
        #[cfg(not(feature = "security-key"))]
        let touched = None;
        let result = s.reauth(&current, touched).and_then(|mut r| {
            r.app_serial = serial;
            match (id, &head) {
                (KEY_OVERRIDE_HEAD, Some(head)) => s.override_head(r, head),
                (KEY_LOCAL_OK, _) => s.confirm_key_file(r),
                _ => s.forget_pending(r),
            }
        });
        let notices: Vec<(Zeroizing<String>, isize)> =
            s.take_key_notices().iter().map(key_line).collect();
        let badge = s.badge();
        if let Err(e) = result {
            if e == crypto::AUTH_ERROR {
                a.failed_attempt();
            }
            return Err(e);
        }
        a.failed = 0;
        a.sync_badge = badge;
        let done = match id {
            KEY_OVERRIDE_HEAD => HEAD_OVERRIDDEN,
            KEY_LOCAL_OK => KEY_FILE_CONFIRMED,
            _ => vault::PENDING_DISCARDED,
        };
        let mut lines = vec![done];
        if id == KEY_LOCAL_OK && badge.is_some() {
            lines.push(KEY_FILE_CONFIRMED_SYNCED);
        }
        lines.extend(notices.iter().map(|(text, _)| text.as_str()));
        // Sync goes on from the vault list; the other two stay on Keys,
        // where key changes are now possible.
        a.show(if id == KEY_OVERRIDE_HEAD {
            Screen::Vault
        } else {
            Screen::Keys
        });
        a.status = joined(&lines);
        if notices.iter().any(|(_, tone)| *tone == TONE_DANGER) {
            a.status_tone = TONE_DANGER;
        }
        a.build();
        Ok(())
    })
    .map(|_| ())
}
/// A later phase of a flow (spec §9.2a): `f` runs under the app's borrow,
/// and only while the vault, `screen` and `serial` of phase 1 still stand
/// (see App::still); None when they do not, and the flow is void.
fn phase<T>(
    h: Hwnd,
    screen: Screen,
    serial: u64,
    f: impl FnOnce(&mut App) -> crypto::Result<T>,
) -> crypto::Result<Option<T>> {
    unsafe {
        UpdateWindow(h);
    }
    let result = APP.with(|cell| -> crypto::Result<Option<T>> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if !a.still(screen, serial, true)? {
            return Ok(None);
        }
        f(a).map(Some)
    });
    drain_pending(h);
    result
}
/// S-BACKUP (or S-BACKUP-SHORT, `question`) after a key change (spec §9.2):
/// the new key file's backup now. The change's status line stays above the
/// backup's.
fn backup_after(h: Hwnd, question: &str) {
    let done = APP.with(|cell| {
        let b = cell.try_borrow().ok()?;
        let a = b.as_ref()?;
        a.session.as_ref()?;
        let tone = unsafe { GetWindowLongPtrW(a.handle(STATUS), -21) };
        Some((a.status.clone(), tone))
    });
    let Some((done, tone)) = done else {
        return;
    };
    if !ask(h, question) {
        return;
    }
    match modal_command(h, KEYBACKUP) {
        Ok(()) => APP.with(|cell| {
            if let Ok(mut b) = cell.try_borrow_mut()
                && let Some(a) = b.as_mut()
                && a.session.is_some()
                && a.status.as_str() == KEY_BACKED_UP
            {
                a.set_status(&joined(&[done.as_str(), KEY_BACKED_UP]), tone);
            }
        }),
        // A failed backup must not pass as one more status line.
        Err(e) => message(h, e),
    }
}
/// S-KEYDAMAGED-SAVE (spec §5.5 S2): whether the new key file was saved is
/// unknown, so it is saved from memory now, which locks the vault
/// (S-KEYDAMAGED-LOCKED); "No" leaves the vault list open with the danger
/// line, and "열쇠 백업" still saves it.
fn save_damaged_key(h: Hwnd) {
    report(h, vault::KEY_DAMAGED);
    if ask(h, KEY_DAMAGED_SAVE)
        && let Err(e) = modal_command(h, KEYBACKUP)
    {
        message(h, e);
    }
}
/// Whether window_proc hands command `id` to phased_command: SUBMIT (or
/// Enter) on Login, Password, Adopt, Create and Restore (spec
/// §9.2a; S45-1 #13, S45-2 #17), the Keys screen's buttons that act on
/// what holds key changes, and the flows of the security-key build.
/// Anything else, or a busy app, goes the usual way.
fn phased(id: i32) -> bool {
    APP.with(|cell| {
        cell.try_borrow().is_ok_and(|b| {
            b.as_ref().is_some_and(|a| match a.screen {
                #[cfg(feature = "security-key")]
                _ if keys_ui::phased(a, id) => true,
                Screen::Login
                | Screen::Password
                | Screen::Adopt
                | Screen::Create
                | Screen::Restore => matches!(id, 1 | SUBMIT),
                Screen::Keys => matches!(id, KEY_OVERRIDE_HEAD | KEY_LOCAL_OK | PENDING_FORGET),
                _ => false,
            })
        })
    })
}
/// The buttons of the input dialogs (spec §9.2a): Enter and Esc arrive as
/// IDOK (1) and IDCANCEL (2).
const OK_BUTTON: DialogButton = DialogButton {
    id: 1,
    label: "확인",
    role: Role::Accept,
};
const ACCEPT_BUTTON: DialogButton = DialogButton {
    id: 1,
    label: "받기",
    role: Role::Accept,
};
const CANCEL_BUTTON: DialogButton = DialogButton {
    id: 2,
    label: "취소",
    role: Role::Cancel,
};
/// confirm(); a test answers in its place (see ANSWER), and a question no
/// test answered is a No. Answering counts as use of the app (spec §9.2a).
fn ask(h: Hwnd, text: &str) -> bool {
    #[cfg(test)]
    let yes = {
        let _ = h;
        match ANSWER.with(|a| a.borrow_mut().take()) {
            Some(mut answer) => modal(|| answer(text)),
            None => false,
        }
    };
    #[cfg(not(test))]
    let yes = confirm(h, text);
    used();
    yes
}
/// input_dialog() with this app's edit subclass; a test answers in its
/// place (see INPUT_ANSWER), and an input no test answered is cancelled.
/// Answering counts as use of the app.
fn ask_input(h: Hwnd, kind: InputKind, text: &str, buttons: &[DialogButton]) -> InputAnswer {
    #[cfg(test)]
    let answer = {
        let _ = (h, edit_proc as Proc);
        let cancel = buttons
            .iter()
            .find(|b| b.role == Role::Cancel)
            .map_or(2, |b| b.id);
        match INPUT_ANSWER.with(|i| i.borrow_mut().take()) {
            Some(mut answer) => {
                let given = modal(|| answer(text, &kind));
                // Kept for the next input of the flow, unless it set another.
                INPUT_ANSWER.with(|i| {
                    let mut i = i.borrow_mut();
                    if i.is_none() {
                        *i = Some(answer);
                    }
                });
                given
            }
            None => InputAnswer::Cancel(cancel),
        }
    };
    #[cfg(not(test))]
    let answer = input_dialog(h, kind, text, buttons, edit_proc);
    used();
    answer
}
/// The user answered a dialog: that is use of the app, for the idle lock.
fn used() {
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
        {
            a.activity = Instant::now();
        }
    });
}
/// A WM_QUIT reached a ceremony's pump and was posted again (spec §8.6): the
/// app is ending, so every flow that is still running is void; never in the
/// keyless build, which has no pump of its own.
fn quitting() -> bool {
    #[cfg(feature = "security-key")]
    return QUIT_SEEN.with(Cell::get);
    #[cfg(not(feature = "security-key"))]
    false
}
/// A security-key ceremony is under way (spec §8.6); never in the default
/// build, which has none.
fn in_ceremony() -> bool {
    #[cfg(feature = "security-key")]
    return CEREMONY.with(|c| c.borrow().is_some());
    #[cfg(not(feature = "security-key"))]
    false
}
/// The cap on one ceremony (spec §8.5), in ms: the app cancels it then.
#[cfg(feature = "security-key")]
const CEREMONY_CAP: u64 = 150_000;
/// How long a cancelled ceremony may take to end before the app goes on
/// without its worker, in ms.
#[cfg(feature = "security-key")]
const CEREMONY_DETACH: u64 = 10_000;
/// The pump's wait for the worker or a message, in ms.
#[cfg(feature = "security-key")]
const PUMP_WAIT: u32 = 250;
/// The ceremony under way (spec §8.5): its cancel token, when it started
/// (`crypto::now_ms`), and whether the app asked it to end.
#[cfg(feature = "security-key")]
struct Active {
    token: Arc<CancelToken>,
    started: u64,
    cancel_requested: bool,
}
#[cfg(feature = "security-key")]
thread_local! {
    static CEREMONY: RefCell<Option<Active>> = const { RefCell::new(None) };
    /// See quitting().
    static QUIT_SEEN: Cell<bool> = const { Cell::new(false) };
}
#[cfg(all(test, feature = "security-key"))]
thread_local! {
    /// The authenticator of a test, in place of Windows' (spec §8.9).
    static AUTHENTICATOR: RefCell<Option<Arc<dyn Authenticator>>> = const { RefCell::new(None) };
}
#[cfg(feature = "security-key")]
#[link(name = "user32")]
unsafe extern "system" {
    fn PeekMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32, remove: u32) -> i32;
    fn MsgWaitForMultipleObjectsEx(
        count: u32,
        handles: *const isize,
        ms: u32,
        wake: u32,
        flags: u32,
    ) -> u32;
}
/// The authenticator a ceremony runs with: Windows' WebAuthn API, loaded
/// the first time a flow needs a key (spec §8.1); in a test only the fake
/// the test put in place, never a real key.
#[cfg(feature = "security-key")]
fn authenticator() -> Result<Arc<dyn Authenticator>, FidoError> {
    #[cfg(test)]
    return AUTHENTICATOR.with(|a| a.borrow().clone().ok_or(FidoError::NoApi));
    #[cfg(not(test))]
    webauthn::WebAuthn::load()
}
/// Asks the ceremony under way, if any, to end (spec §8.6): its token's
/// flag at once, so that a worker not yet in its Windows call makes none,
/// and Windows' cancel from the pump's next round on. A lock, a scrub, a
/// close and WM_QUIT do.
#[cfg(feature = "security-key")]
fn cancel_ceremony() {
    CEREMONY.with(|c| {
        if let Some(active) = c.borrow_mut().as_mut() {
            active.cancel_requested = true;
            active.token.cancel();
        }
    });
}
/// The timer's look at the ceremony under way: past the cap, it ends.
#[cfg(feature = "security-key")]
fn ceremony_overdue() {
    let now = crypto::now_ms();
    CEREMONY.with(|c| {
        if let Some(active) = c.borrow_mut().as_mut()
            && now.saturating_sub(active.started) > CEREMONY_CAP
        {
            active.cancel_requested = true;
        }
    });
}
/// How the pump ended.
#[cfg(feature = "security-key")]
enum Pumped {
    /// The worker returned.
    Finished,
    /// It did not return within CEREMONY_DETACH of the cancel: it is left
    /// to end on its own, with every buffer it owns.
    Detached,
}
/// One ceremony (spec §8.5): `job` makes exactly one Windows call on a
/// worker thread that owns every buffer of it, while this thread pumps
/// messages inside `modal`, with no APP borrow held, so that timers, paint,
/// session and power notices and a close run as usual and commands and
/// input are dropped. A lock, scrub, close, WM_QUIT or the 150-second cap
/// cancels it; the cancel is issued again at every round until the worker
/// returns, and 10 seconds after the first one the worker is left behind.
/// The worker never sends or posts a message: its result comes back only
/// through `join`. A result that arrives after the app's cancel is dropped
/// (and zeroized), so a lock always ends the step with Cancelled.
#[cfg(feature = "security-key")]
fn ceremony<T: Send + 'static>(
    h: Hwnd,
    auth: Arc<dyn Authenticator>,
    job: impl FnOnce(&dyn Authenticator, &CancelToken) -> Result<T, FidoError> + Send + 'static,
) -> Result<T, FidoError> {
    // One at a time: commands are dropped while one runs.
    if in_ceremony() {
        return Err(FidoError::Cancelled);
    }
    let token = Arc::new(auth.new_cancel()?);
    let started = crypto::now_ms();
    CEREMONY.with(|c| {
        *c.borrow_mut() = Some(Active {
            token: token.clone(),
            started,
            cancel_requested: false,
        })
    });
    let worker = {
        let (auth, token) = (auth.clone(), token.clone());
        std::thread::Builder::new()
            .name("goyo-webauthn".into())
            .spawn(move || job(&*auth, &token))
    };
    // Its handle is open to other programs until restricted.
    restrict_threads();
    let (result, quit) = match worker {
        Ok(worker) => {
            let (pumped, quit) = modal(|| pump(h, &worker, &*auth, &token, started));
            let result = match pumped {
                Pumped::Finished => worker.join().unwrap_or(Err(FidoError::Other(0))),
                Pumped::Detached => Err(FidoError::Cancelled),
            };
            (result, quit)
        }
        Err(_) => (Err(FidoError::Other(0)), None),
    };
    let by_app = CEREMONY.with(|c| c.borrow_mut().take().is_some_and(|a| a.cancel_requested));
    restrict_threads();
    // The wait in Windows' dialog was use of the app when someone answered
    // it or cancelled it in time, and its window was in front only if it is
    // now (spec §8.6). A ceremony that Windows' own timeout or the app's cap
    // ended had nobody at it: the idle time runs on from before it.
    let spent = crypto::now_ms().saturating_sub(started);
    let unattended = spent > CEREMONY_CAP
        || (matches!(result, Err(FidoError::Cancelled))
            && spent >= u64::from(goyo_vault::fido::TIMEOUT_MS));
    APP.with(|cell| {
        if let Ok(mut b) = cell.try_borrow_mut()
            && let Some(a) = b.as_mut()
        {
            let now = Instant::now();
            if !unattended {
                a.activity = now;
            }
            a.away_since = if is_foreground(h) {
                None
            } else if unattended {
                a.away_since.or(Some(now))
            } else {
                Some(now)
            };
        }
    });
    if let Some(code) = quit {
        // Every flow still running ends with the app (see quitting()).
        QUIT_SEEN.with(|q| q.set(true));
        unsafe {
            PostQuitMessage(code as i32);
        }
    }
    if by_app || token.is_cancelled() {
        // Dropped unread (and zeroized): whatever came back answers a step
        // the app ended.
        drop(result);
        return Err(FidoError::Cancelled);
    }
    result
}
/// The message loop of a ceremony (spec §8.5): waits for the worker's
/// handle or a message, takes every queued message through the same
/// filter as the main loop and drops all keyboard and mouse input (the user
/// is in Windows' dialog; anything else was posted by someone else),
/// restricts the threads Windows starts, and cancels at every round once
/// the app asked or the cap passed. A WM_QUIT is kept for later and ends
/// the ceremony. While a test clock is set, each round waits 1 ms of real
/// time and moves that clock on by one wait.
#[cfg(feature = "security-key")]
fn pump<T>(
    h: Hwnd,
    worker: &std::thread::JoinHandle<T>,
    auth: &dyn Authenticator,
    token: &CancelToken,
    started: u64,
) -> (Pumped, Option<usize>) {
    use std::os::windows::io::AsRawHandle;
    let handle = worker.as_raw_handle() as isize;
    let mut quit = None;
    let mut cancelled_at: Option<u64> = None;
    let mut msg = Msg::default();
    loop {
        #[cfg(debug_assertions)]
        let wait = if crypto::advance_test_clock(u64::from(PUMP_WAIT)) {
            1
        } else {
            PUMP_WAIT
        };
        #[cfg(not(debug_assertions))]
        let wait = PUMP_WAIT;
        unsafe {
            // QS_ALLINPUT, MWMO_INPUTAVAILABLE.
            MsgWaitForMultipleObjectsEx(1, &handle, wait, 0x04ff, 0x0004);
        }
        while unsafe { PeekMessageW(&mut msg, 0, 0, 0, 1) } != 0 {
            if msg.message == 0x12 {
                quit = Some(msg.wparam);
                cancel_ceremony();
                continue;
            }
            if (0x100..=0x109).contains(&msg.message) || (0x201..=0x20e).contains(&msg.message) {
                continue;
            }
            if !accept_queued(h, &msg) {
                continue;
            }
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        // webauthn.dll starts about two threads per ceremony.
        restrict_threads();
        let now = crypto::now_ms();
        let requested = CEREMONY.with(|c| c.borrow().as_ref().is_some_and(|a| a.cancel_requested));
        if requested || now.saturating_sub(started) > CEREMONY_CAP {
            cancelled_at.get_or_insert(now);
            // The flag first: a worker not yet in its Windows call then
            // makes none. Again at every round, since Windows forgets a
            // cancel that came with no operation running (S45-1 #12).
            token.cancel();
            auth.cancel(token);
        }
        if worker.is_finished() {
            return (Pumped::Finished, quit);
        }
        if cancelled_at.is_some_and(|at| now.saturating_sub(at) > CEREMONY_DETACH) {
            return (Pumped::Detached, quit);
        }
    }
}
/// The C step of a phased flow (spec §8.5, §9.2a): one assertion ceremony
/// for `request`, with no borrow held, and its answer checked (§8.4). The
/// status line asks for the key meanwhile (`status`). None ends the flow: a lock,
/// scrub or close during the ceremony voided it (their own line stays),
/// or the ceremony or its answer failed, and the status line says why
/// (§8.7), with the retry delay where that failure has one.
#[cfg(feature = "security-key")]
fn touch_step(
    h: Hwnd,
    screen: Screen,
    serial: u64,
    request: AssertRequest,
    status: &str,
) -> Option<Touch> {
    touch_step_or(h, screen, serial, request, status).ok()
}
/// The same, with why it ended: Err(Some(e)) when the ceremony or its
/// answer failed while the flow still stands (its text is on the status
/// line), Err(None) when the flow is void or the 150-second cap ended it.
/// So Err(Some(Cancelled)) is Windows' cancel: the app's own cancel voids
/// the flow or is the cap's.
#[cfg(feature = "security-key")]
fn touch_step_or(
    h: Hwnd,
    screen: Screen,
    serial: u64,
    request: AssertRequest,
    status: &str,
) -> Result<Touch, Option<FidoError>> {
    // A lock, close or quit since the flow's last step voids it before any
    // Windows call (spec §8.3, §8.5; S45-1 #12): no dialog opens over a
    // locked app, and the lock's line stays.
    let standing = APP.with(|cell| {
        let mut b = cell.try_borrow_mut().ok()?;
        let a = b.as_mut()?;
        if a.closing || a.serial != serial || a.screen != screen || quitting() {
            return None;
        }
        a.prompt(status);
        Some(())
    });
    standing.ok_or(None)?;
    let auth = authenticator();
    unsafe {
        UpdateWindow(h);
    }
    let start = crypto::now_ms();
    let result = auth.and_then(|auth| {
        let asked = request.clone();
        ceremony(h, auth, move |auth, token| {
            auth.get_assertion(&asked, token)
        })
    });
    let result = result.and_then(|raw| check_assertion(raw, &request, false));
    let capped = crypto::now_ms().saturating_sub(start) > CEREMONY_CAP;
    drain_pending(h);
    APP.with(|cell| {
        let mut b = cell.try_borrow_mut().map_err(|_| None)?;
        let a = b.as_mut().ok_or(None)?;
        if a.closing || a.serial != serial || a.screen != screen {
            return Err(None);
        }
        match result {
            Ok(touch) => Ok(touch),
            Err(e) => {
                if e.delays() {
                    a.failed_attempt();
                }
                a.error(&keys_ui::failure(e, !request.allow.is_empty(), capped));
                // The cap's cancel is the app's own.
                Err((!capped).then_some(e))
            }
        }
    })
}

/// Asks once per unlock whether to turn sync on for a v1 vault next to a
/// sync folder (see SYNC_OFFER). Saying yes changes the vault's format for
/// good, so it is the user's choice, made in a dialog. Like modal_command
/// no borrow spans the dialog, and the answer counts only for the vault it
/// was asked about, still open and still v1.
fn offer_sync(h: Hwnd) {
    let asked = APP.with(|cell| {
        let b = cell.try_borrow().ok()?;
        let a = b.as_ref()?;
        let s = a.session.as_ref().filter(|s| s.sync_offer())?;
        if a.closing || a.screen != Screen::Vault {
            return None;
        }
        let folder = syncfile::sync_dir(&s.path)?;
        let folder = folder.file_name()?.to_string_lossy().into_owned();
        Some((s.path.clone(), folder, s.needs_0_9()))
    });
    let Some((path, folder, needs_0_9)) = asked else {
        return;
    };
    unsafe {
        UpdateWindow(h);
    }
    // A vault whose keys were changed (a 0.9.0 key file) is already beyond
    // 0.8, and its first upload is GOYOVA04, which a 0.8 server script
    // refuses (SYNC.md, the order of the 0.9.0 update).
    let text = if needs_0_9 {
        "이 금고 옆에 동기화 폴더({})가 있습니다. goyo-sync가 이 폴더를 통해 암호화된 금고 사본만 서버와 주고받습니다. 열쇠 파일과 비밀번호는 보내지 않습니다.\n\n이 금고는 열쇠를 바꾼 적이 있어 0.8 이하 버전에서는 열 수 없고, 0.8 서버 스크립트는 이 금고의 사본을 받지 않습니다. 동기화를 켜기 전에 서버 스크립트를 먼저, 그다음 다른 PC의 고요 금고와 goyo-sync를 0.9.0 이상으로 업데이트하세요. 동기화를 켤까요?"
    } else {
        "이 금고 옆에 동기화 폴더({})가 있습니다. goyo-sync가 이 폴더를 통해 암호화된 금고 사본만 서버와 주고받습니다. 열쇠 파일과 비밀번호는 보내지 않습니다.\n\n동기화를 켜면 금고 형식이 바뀌어 0.7 이하 버전에서는 이 금고와 이후 백업을 열 수 없습니다. 다른 PC도 먼저 0.8 이상으로 업데이트하세요. 동기화를 켤까요?"
    };
    let consent = fill(text, &[&folder]);
    // No keeps v1, and the question comes again at the next unlock.
    if !ask(h, &consent) {
        return;
    }
    let result = APP.with(|cell| -> crypto::Result<()> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        let same = a.session.as_ref().is_some_and(|s| s.path == path);
        if a.closing || a.screen != Screen::Vault || !same {
            return Err("대화상자가 열린 동안 잠겼습니다. 다시 인증하세요.");
        }
        if let Err(e) = check_environment(h) {
            a.lock(e, true);
            return Err(e);
        }
        a.activity = Instant::now();
        let s = a.session.as_mut().ok_or("금고가 잠겼습니다.")?;
        // The change is for good: only while what was asked still holds
        // (still v1, the folder still there, the key file still outside it).
        if s.format() != Format::V1 || !s.sync_offer() {
            return Ok(());
        }
        s.enable_sync()?;
        a.sync_badge = s.badge();
        let (line, tone) = sync_line(&SyncNotice::SyncOn);
        a.set_status(&line, tone);
        unsafe {
            InvalidateRect(h, null(), 0);
        }
        Ok(())
    });
    drain_pending(h);
    if let Err(e) = result {
        report(h, e);
    }
}

/// Shows an error in the status line. Falls back to a message box only while
/// the app state is busy or already gone.
fn report(h: Hwnd, e: &str) {
    let shown = APP.with(|cell| {
        cell.try_borrow_mut()
            .ok()
            .and_then(|mut b| b.as_mut().map(|a| a.error(e)))
            .is_some()
    });
    if !shown {
        message(h, e);
    }
}
fn drain_pending(h: Hwnd) {
    if WINDOW_GONE.with(Cell::get) || unsafe { IsWindow(h) } == 0 {
        PENDING_EVENTS.with(|p| p.set(0));
        return;
    }
    APP.with(|cell| {
        let Ok(mut b) = cell.try_borrow_mut() else {
            return;
        };
        let Some(a) = b.as_mut() else {
            return;
        };
        let pending = PENDING_EVENTS.with(|p| p.replace(0));
        if pending == 0 {
            return;
        }
        if a.closing {
            if pending & 6 != 0 {
                a.expire_clipboard();
            }
            return;
        }
        if pending & 6 == 0 {
            a.deactivated(); // only an app switch arrived while busy
        } else {
            a.lock("화면 또는 시스템 세션 변경으로 잠갔습니다.", true);
        }
        if pending & 4 != 0 {
            a.closing = true;
        }
        unsafe {
            // A close during a ceremony waits for its end (spec §8.6).
            if a.closing && a.clipboard.is_none() && !in_ceremony() {
                DestroyWindow(h);
            } else if HIDDEN_FOR_EVENTS.with(|v| v.replace(false)) {
                ShowWindow(h, 8); // Show locked UI in its state, without focus.
            }
        }
    });
}

fn valid_paste(data: &[u16], multiline: bool, remaining: usize) -> bool {
    data.len() <= remaining
        && (multiline || !data.iter().any(|c| matches!(c, 10 | 13)))
        && char::decode_utf16(data.iter().copied()).all(|c| c.is_ok_and(|c| c != '\0'))
}
fn paste_into_edit(h: Hwnd) -> crypto::Result<()> {
    let (mut data, sequence) = clipboard_text(h)?;
    unsafe {
        let multiline = GetWindowLongPtrW(h, -16) & 4 != 0;
        let (mut start, mut end) = (0u32, 0u32);
        SendMessageW(
            h,
            0xb0,
            &mut start as *mut u32 as usize,
            &mut end as *mut u32 as isize,
        );
        let n = INTERNAL_READ.with(|f| {
            let old = f.replace(true);
            let n = GetWindowTextLengthW(h).max(0) as usize;
            f.set(old);
            n
        });
        let limit = SendMessageW(h, 0xd5, 0, 0).max(0) as usize;
        let remaining = limit.saturating_sub(n.saturating_sub(end.saturating_sub(start) as usize));
        if !valid_paste(&data, multiline, remaining) {
            return Err("붙여넣기 형식 또는 길이 오류");
        }
        data.push(0);
        SendMessageW(h, 0xc2, 0, data.as_ptr() as isize);
        SendMessageW(h, 0xcd, 0, 0);
        // A pasted password or secret should not outlive the paste on the
        // clipboard. Anything copied since then belongs to the user.
        let id = GetWindowLongPtrW(h, -12) as i32;
        if id == OTP_FIELD && is_otp_uri(&data) {
            PASTE_NOTICE.with(|n| n.set(n.get() | 4));
            PostMessageW(GetParent(h), OTP_PASTED, 0, 0);
        }
        if matches!(
            id,
            SECRET | OTP_FIELD | PASS | CONFIRM | CURRENT_PASS | INPUT_EDIT
        ) && clear_pasted(h, sequence)
        {
            PASTE_NOTICE.with(|n| n.set(n.get() | 1));
            PostMessageW(GetParent(h), PASTE_CLEARED, 0, 0);
        }
    }
    Ok(())
}

/// A code in two groups for reading it out: "123 456", "1234 5678",
/// "123 4567".
fn otp_grouped(code: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(code.len() + 1));
    let half = code.len() / 2;
    for (i, c) in code.chars().enumerate() {
        if i == half && half > 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}
const QR_TOO_LARGE: &str =
    "QR 코드가 이 창에 담기에 너무 큽니다. [시크릿 복사]로 인증 앱에 직접 넣으세요.";
/// Where a QR symbol of `size` modules goes in an area of `w` × `h` pixels.
#[derive(Debug, PartialEq)]
struct QrLayout {
    /// Pixels a module, the same across and down.
    module: i32,
    /// The top left of the quiet zone in the area.
    offset: (i32, i32),
}
/// The largest whole number of pixels a module that fits the symbol and its
/// four-module quiet zone on each side, centred; None below 2 pixels a
/// module, which a phone camera cannot read from a screen.
fn qr_layout(size: usize, w: i32, h: i32) -> Option<QrLayout> {
    let total = size as i32 + 8;
    let module = w.min(h) / total;
    if module < 2 {
        return None;
    }
    let side = module * total;
    Some(QrLayout {
        module,
        offset: ((w - side) / 2, (h - side) / 2),
    })
}
/// Puts a secret on the clipboard, kept out of its history (see
/// win::copy_secret), and returns the clipboard's sequence number.
#[cfg(not(test))]
fn copy_value(h: Hwnd, text: &str) -> crypto::Result<u32> {
    copy_secret(h, text)
}
/// The tests' clipboard: what the app copied last, so no test reads or
/// changes the user's own clipboard.
#[cfg(test)]
fn copy_value(_: Hwnd, text: &str) -> crypto::Result<u32> {
    COPIED.with(|c| *c.borrow_mut() = Some(Zeroizing::new(text.to_owned())));
    Ok(1)
}
#[cfg(test)]
thread_local! {
    static COPIED: RefCell<Option<Zeroizing<String>>> = const { RefCell::new(None) };
}
/// Whether pasted UTF-16 text starts like an otpauth URI.
fn is_otp_uri(data: &[u16]) -> bool {
    let head: String = char::decode_utf16(data.iter().copied().take(16))
        .map(|c| c.unwrap_or('\u{fffd}'))
        .collect();
    otp::is_uri(&head)
}
/// Clears and returns a notice bit set by edit_proc (see PASTE_NOTICE).
fn take_notice(bit: u8) -> bool {
    PASTE_NOTICE.with(|n| {
        let set = n.get() & bit != 0;
        n.set(n.get() & !bit);
        set
    })
}
/// The entry list ignores everything other programs send it, so they cannot
/// move the selection behind the user's back.
unsafe extern "system" fn list_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() {
        return 0;
    }
    unsafe { CallWindowProcW(LIST_PROC.get().copied(), h, m, w, l) }
}
unsafe extern "system" fn edit_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    // Only this UI thread drives the inputs. Anything sent from another
    // program is dropped: besides text reads, even geometry such as
    // EM_POSFROMCHAR leaks a secret through character widths.
    if from_other_thread() {
        return 0;
    }
    if matches!(
        m,
        0x300 | 0x301 | 0x7b | 0xc4 | 0x317 | 0x318 | 0x3d | 0xd0 | 0xcc | 0xbc
    ) {
        return 0;
    }
    if matches!(m, 0xd | 0xe) && !INTERNAL_READ.with(Cell::get) {
        return 0;
    }
    if m == 0x302 {
        if paste_into_edit(h).is_err() {
            PASTE_NOTICE.with(|n| n.set(n.get() | 2));
            unsafe {
                PostMessageW(GetParent(h), INPUT_ERROR, 0, 0);
            }
        }
        return 0;
    }
    let original = EDIT_PROC.get().copied();
    unsafe { CallWindowProcW(original, h, m, w, l) }
}
unsafe extern "system" fn window_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if m == 0x317 || m == 0x318 {
        return 0;
    }
    // Commands, owner-draw, input and the app's own notices only ever come
    // from this UI thread. Sent from another program, they are fakes (e.g. a
    // scripted click on "copy").
    let foreign = from_other_thread();
    if foreign
        && matches!(
            m,
            0x100..=0x109 | 0x111 | 0x113 | 0x2b | 0x133..=0x138 | 0x201..=0x20e
                | DRAIN_EVENTS
                | INPUT_ERROR
                | PASTE_CLEARED
                | OTP_PASTED
        )
    {
        return 0;
    }
    // While a message box, file dialog, move loop or menu runs, the main
    // window gets no real click, so a command or click then is a fake (e.g. a
    // posted click on a button, which the button itself turns into a command).
    if matches!(m, 0x111 | 0x201) && in_modal() {
        return 0;
    }
    // Theme messages never borrow APP, so controls keep their look while busy.
    if m == 0x14 {
        return 1; // WM_PAINT fills the whole client area itself.
    }
    if matches!(m, 0x133..=0x135 | 0x138)
        && let Some(brush) = unsafe { theme::control_color(m, w as isize, l) }
    {
        return brush;
    }
    if m == 0x2b
        && l != 0
        && unsafe {
            let item = &*(l as *const DrawItem);
            IsChild(h, item.item) != 0 && theme::draw_item(item)
        }
    {
        return 1;
    }
    if m == 2 {
        WINDOW_GONE.with(|p| p.set(true));
        PENDING_EVENTS.with(|p| p.set(0));
        unsafe {
            PostQuitMessage(0);
        }
        return 0;
    }
    if m == DRAIN_EVENTS {
        drain_pending(h);
        return 0;
    }
    // A click, or Enter or Esc, on the main window, whichever route it
    // takes below: the pinned notice has been seen (G-01).
    if m == 0x111 && (w >> 16) == 0 {
        APP.with(|cell| {
            if let Ok(mut b) = cell.try_borrow_mut()
                && let Some(a) = b.as_mut()
            {
                a.pinned = None;
            }
        });
    }
    if m == 0x111
        && (w >> 16) == 0
        && matches!(
            (w & 0xffff) as i32,
            BROWSE_V | BROWSE_K | BROWSE_D | DELETE | BACKUP | KEYBACKUP | KEY_ADOPT
        )
    {
        if !APP.with(|cell| cell.try_borrow_mut().is_ok()) {
            return 0;
        }
        let id = (w & 0xffff) as i32;
        if let Err(e) = modal_command(h, id) {
            // A failed backup must not pass as one more status line.
            if matches!(id, BACKUP | KEYBACKUP) {
                message(h, e);
            } else {
                report(h, e);
            }
        }
        return 0;
    }
    if m == 0x111 && (w >> 16) == 0 && phased((w & 0xffff) as i32) {
        let id = match (w & 0xffff) as i32 {
            1 => SUBMIT,
            id => id,
        };
        if let Err(e) = phased_command(h, id) {
            report(h, e);
        }
        return 0;
    }
    let strong_event = (m == 0x2b1 && matches!(w, 2 | 3 | 4 | 6 | 7 | 9))
        || (m == 0x218 && w == 4)
        || (m == 0x16 && w != 0);
    let security_event = (m == 0x1c && w == 0) || strong_event;
    let deferrable = security_event || m == 0x10;
    let bit = if m == 0x10 {
        4
    } else if strong_event {
        2
    } else {
        1
    };
    let defer = |hide: bool| unsafe {
        PENDING_EVENTS.with(|p| p.set(p.get() | bit));
        if hide && IsWindowVisible(h) != 0 {
            ShowWindow(h, 0);
            HIDDEN_FOR_EVENTS.with(|v| v.set(true));
        }
        PostMessageW(h, DRAIN_EVENTS, 0, 0);
    };
    let mut error = None;
    let handled = APP.with(|cell| {
        let Ok(mut borrow) = cell.try_borrow_mut() else {
            if deferrable {
                defer(true);
                return true;
            }
            return false;
        };
        let Some(app) = borrow.as_mut() else {
            return false;
        };
        // Windows sends session end, sleep and some close requests from other
        // threads, and calls the app makes while handling them inherit that
        // origin: the controls would drop their own wipe and teardown. Drop
        // the secrets now and rebuild the screen from the queue. A faked
        // activation is ignored; the timer checks the real foreground window.
        if foreign && (deferrable || m == 0x1c) {
            if deferrable {
                if bit != 1 {
                    app.scrub();
                }
                defer(bit != 1);
            }
            return true;
        }
        match m {
            0x111 => {
                if let Err(e) = app.command((w & 0xffff) as i32, (w >> 16) as u16) {
                    error = Some(e);
                }
                true
            }
            0x113 => {
                app.timer();
                true
            }
            0xf => {
                app.paint();
                true
            }
            0x201 => {
                app.click(l);
                true
            }
            0x1c if w == 0 => {
                if !app.closing {
                    app.deactivated();
                }
                true
            }
            0x1c => {
                app.activated();
                true
            }
            0x2b1 if matches!(w, 2 | 3 | 4 | 6 | 7 | 9) => {
                app.lock("Windows 세션이 잠기거나 연결이 변경되어 잠갔습니다.", true);
                true
            }
            0x218 if w == 4 => {
                app.lock("절전 전환으로 잠갔습니다.", true);
                true
            }
            // Windows is ending the session or Restart Manager closes the app.
            0x16 if w != 0 => {
                app.lock("Windows 종료로 잠갔습니다.", true);
                true
            }
            0x10 => {
                app.lock("종료 중 · 클립보드 지우기를 확인하고 있습니다.", true);
                app.closing = true;
                // During a ceremony the timer closes once it ended.
                if app.clipboard.is_none() && !in_ceremony() {
                    unsafe {
                        DestroyWindow(h);
                    }
                }
                true
            }
            PASTE_CLEARED => {
                if take_notice(1) {
                    app.status("붙여넣은 값을 클립보드에서 지웠습니다. 다른 앱이 남긴 기록(Win+V 등)은 지우지 못합니다.");
                }
                true
            }
            OTP_PASTED => {
                if take_notice(4) {
                    app.otp_pasted();
                }
                true
            }
            INPUT_ERROR => {
                if take_notice(2) {
                    app.status("붙여넣기 실패: 길이 제한, 줄바꿈, 유니코드 형식 또는 클립보드 사용 상태를 확인하세요.");
                }
                true
            }
            _ => false,
        }
    });
    if !foreign {
        drain_pending(h);
        // Raised only by an unlock this window just handled. A nested call
        // (a control notifying the window while the unlock rebuilds the
        // screen) leaves it for the outer one, which holds no borrow.
        if APP.with(|cell| cell.try_borrow_mut().is_ok()) && SYNC_OFFER.with(|f| f.replace(false)) {
            offer_sync(h);
        }
    }
    if let Some(e) = error {
        report(h, e);
    }
    if handled {
        0
    } else {
        unsafe { DefWindowProcW(h, m, w, l) }
    }
}
/// The only setting kept outside the vault: "light" or "dark", next to the exe.
fn theme_file() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .join("goyo-vault.theme"),
    )
}
fn load_theme() -> bool {
    use std::io::Read;
    let mut buf = Vec::new();
    let read = theme_file()
        .and_then(|p| std::fs::File::open(p).ok())
        .and_then(|f| f.take(16).read_to_end(&mut buf).ok());
    !(read.is_some() && buf.trim_ascii() == b"light")
}
/// "en" or "ko" next to the exe. Without it: the Windows display language.
fn language_file() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .join("goyo-vault.lang"),
    )
}
fn load_language() -> bool {
    use std::io::Read;
    if cfg!(test) {
        return false;
    }
    let mut buf = Vec::new();
    let read = language_file()
        .and_then(|p| std::fs::File::open(p).ok())
        .and_then(|f| f.take(16).read_to_end(&mut buf).ok());
    match (read, buf.trim_ascii()) {
        (Some(_), b"en") => true,
        (Some(_), b"ko") => false,
        // LANG_KOREAN is 0x12.
        _ => (unsafe { GetUserDefaultUILanguage() } & 0x3ff) != 0x12,
    }
}
fn save_language(english: bool) {
    if let Some(p) = language_file() {
        write_setting(&p, if english { b"en" } else { b"ko" });
    }
}
/// The auto-lock choice in minutes ("1", "5", "30") or "off", next to the
/// exe. Anything else is the shortest choice.
fn auto_lock_file() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .join("goyo-vault.autolock"),
    )
}
const AUTO_LOCK_NAMES: [&[u8]; AUTO_LOCKS.len()] = [b"1", b"5", b"30", b"off"];
fn load_auto_lock() -> usize {
    use std::io::Read;
    if cfg!(test) {
        return 0;
    }
    let mut buf = Vec::new();
    let read = auto_lock_file()
        .and_then(|p| std::fs::File::open(p).ok())
        .and_then(|f| f.take(16).read_to_end(&mut buf).ok());
    read.map_or(0, |_| auto_lock_choice(&buf))
}
/// Index into AUTO_LOCKS for the saved text.
fn auto_lock_choice(saved: &[u8]) -> usize {
    AUTO_LOCK_NAMES
        .iter()
        .position(|n| *n == saved.trim_ascii())
        .unwrap_or(0)
}
fn save_auto_lock(choice: usize) {
    if let Some(p) = auto_lock_file() {
        write_setting(&p, AUTO_LOCK_NAMES[choice]);
    }
}
fn save_theme(dark: bool) {
    if let Some(p) = theme_file() {
        write_setting(&p, if dark { b"dark" } else { b"light" });
    }
}
/// Best effort: a read-only folder only loses the setting. Removing first
/// means a planted link with this name is replaced, not written through.
fn write_setting(path: &Path, data: &[u8]) {
    use std::io::Write;
    if cfg!(test) {
        return;
    }
    let _ = std::fs::remove_file(path);
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| f.write_all(data));
}
fn paths_file() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .join("goyo-vault.paths"),
    )
}
/// Vault and key locations only (no secrets), one per line.
fn save_paths(vault: &Path, key: &Path) {
    if let Some(p) = paths_file() {
        let text = format!("{}\n{}\n", vault.display(), key.display());
        write_setting(&p, text.as_bytes());
    }
}
fn load_paths() -> Option<(PathBuf, PathBuf)> {
    use std::io::Read;
    if cfg!(test) {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(paths_file()?)
        .ok()?
        .take(8192)
        .read_to_string(&mut text)
        .ok()?;
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let (vault, key) = (lines.next()?, lines.next()?);
    Some((PathBuf::from(vault), PathBuf::from(key)))
}
#[derive(Clone, Copy, PartialEq)]
enum Placement {
    SameFolder,
    Cloud,
}
impl Placement {
    fn message(self) -> &'static str {
        match self {
            Placement::SameFolder => {
                "주의: 열쇠 파일이 금고와 같은 폴더에 있어, 폴더째 가져간 사람은 비밀번호만 알아내면 됩니다. '열쇠 백업'으로 USB 등에 옮기고 원래 열쇠는 지우세요."
            }
            Placement::Cloud => {
                "주의: 금고와 열쇠가 모두 클라우드 동기화 폴더에 있어, 그 계정이 털리면 비밀번호만 남습니다. 열쇠는 동기화되지 않는 곳에 두세요."
            }
        }
    }
}
/// The word on the "open" pill for a vault that syncs.
fn badge_word(badge: SyncBadge) -> &'static str {
    match badge {
        SyncBadge::Synced => "동기화됨",
        SyncBadge::Uploading => "올리는 중",
        SyncBadge::HelperOff => "도우미 꺼짐",
        SyncBadge::Offline => "연결 안 됨",
        SyncBadge::Warning => "동기화 경고",
    }
}
/// A status line in a buffer wiped when it is replaced.
fn line(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}
/// Status lines joined with CRLF in one buffer of the exact final size. A
/// buffer that grew would have freed its earlier copy of the text unwiped.
fn joined(lines: &[&str]) -> Zeroizing<String> {
    let breaks = 2 * lines.len().saturating_sub(1);
    let size = lines.iter().map(|l| l.len()).sum::<usize>() + breaks;
    let mut out = Zeroizing::new(String::with_capacity(size));
    for (i, l) in lines.iter().enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(l);
    }
    out
}
/// The status line when a thread of this process stays open to other
/// programs (restrict_threads failed on a timer tick).
const THREADS_OPEN: &str = "프로세스 보호가 약해졌습니다. 다른 프로그램이 열 수 있는 스레드가 남아, 같은 PC의 악성 프로그램이 금고를 엿볼 수 있습니다. 금고를 잠그고 앱을 다시 시작하세요.";
/// The status line when a DLL was loaded from the program's folder.
const DLL_BESIDE: &str = "프로세스 보호가 약해졌습니다. 프로그램 폴더에 있던 DLL이 앱에 로드되었습니다. 그 폴더에는 고요 금고 파일만 두고 앱을 다시 시작하세요.";
#[cfg(test)]
thread_local! {
    /// A test's stand-in for a thread restrict_threads could not restrict.
    static THREADS_STUCK: Cell<bool> = const { Cell::new(false) };
}
/// restrict_threads, or under test what the test says it found.
fn threads_restricted() -> bool {
    #[cfg(test)]
    if THREADS_STUCK.with(Cell::get) {
        return false;
    }
    restrict_threads()
}
/// tr() for each line of a status: an unlock line and the placement warning
/// after it are separate entries, and the stored Korean source lets a
/// language switch translate them again.
fn tr_lines(text: &str) -> Zeroizing<String> {
    let parts: Vec<&str> = text.split("\r\n").map(tr).collect();
    joined(&parts)
}
/// The status line for what an unlock, a key change or a later save found
/// about the key and vault files (spec §5.2 step 10, §5.11) and its tone. A
/// line without values keeps its Korean source, so a language switch
/// translates it.
fn key_line(notice: &KeyNotice) -> (Zeroizing<String>, isize) {
    let filled = |text: &str, values: &[&dyn std::fmt::Display]| Zeroizing::new(fill(text, values));
    match notice {
        KeyNotice::Resumed => (
            line("지난 열쇠 변경을 마저 끝내 금고 파일을 새 열쇠로 다시 저장했습니다."),
            TONE_MUTED,
        ),
        KeyNotice::OlderAccepted => (
            line(
                "예전 열쇠로 저장된 금고 파일을 새 열쇠로 다시 저장했습니다. 항목이 예상과 다르면 백업이나 서버 기록을 확인하세요.",
            ),
            TONE_DANGER,
        ),
        // Its own text (spec §5.2 step 10): an unlock stops no sync.
        KeyNotice::StaleKeyFile => (
            line(
                "이 금고 파일은 이 PC의 열쇠 파일보다 새로운 열쇠 파일로 저장되었습니다. 다른 PC에서 이 금고의 열쇠 파일을 바꾼 것으로 보입니다. 그 열쇠 파일을 USB로 가져와 '열쇠 관리 › 새 열쇠 파일 받기'로 받으세요. 그 전에는 이 PC에서 열쇠를 바꾸지 마세요.",
            ),
            TONE_DANGER,
        ),
        KeyNotice::ResavePending => (
            line(
                "금고 파일을 아직 새 열쇠로 다시 저장하지 못했습니다. 저장장치를 확인하세요. 다음 저장이나 잠금 해제 때 자동으로 마칩니다.",
            ),
            TONE_DANGER,
        ),
        KeyNotice::ResaveTooLarge => (
            line(
                "금고 파일을 새 열쇠로 다시 저장하지 못했습니다. 새 형식은 머리글이 44바이트 더 길어 용량 제한(8 MiB)을 넘습니다. 항목을 지우거나 줄이면 그 저장 때 마칩니다.",
            ),
            TONE_DANGER,
        ),
        KeyNotice::NotFinished => (line(vault::NOT_FINISHED), TONE_MUTED),
        KeyNotice::LocalRollback { old, new } => {
            (filled(vault::LOCAL_ROLLBACK, &[old, new]), TONE_DANGER)
        }
        KeyNotice::PendingElsewhere(path) => (
            filled(vault::PENDING_ELSEWHERE, &[&shown(path)]),
            TONE_DANGER,
        ),
        KeyNotice::RestoreOldKey { old, new } => {
            (filled(vault::RESTORE_OLDKEY, &[old, new]), TONE_MUTED)
        }
        KeyNotice::RestorePending => (line(vault::RESTORE_PENDING), TONE_MUTED),
        KeyNotice::KeyBackupDue => (line(vault::KEYBACKUP_DUE), TONE_MUTED),
        KeyNotice::SidecarFailed => (line(vault::SIDECAR_FAILED), TONE_DANGER),
        KeyNotice::AnchorNewer => (line(vault::ANCHOR_NEWER), TONE_DANGER),
        KeyNotice::KeyTemp => (line(vault::KEYTEMP), TONE_MUTED),
        KeyNotice::KeyTempGone => (line(vault::KEYTEMP_GONE), TONE_DANGER),
        #[cfg(feature = "security-key")]
        KeyNotice::AnchorFailed => (line(vault::ANCHOR_FAILED), TONE_DANGER),
        #[cfg(feature = "security-key")]
        KeyNotice::RemoveUndone(numbers) => {
            let list: Vec<String> = numbers.iter().map(u8::to_string).collect();
            (
                filled(vault::REMOVE_UNDONE, &[&list.join(", ")]),
                TONE_DANGER,
            )
        }
    }
}
/// A path as the user knows it: without the `\\?\` prefix of a
/// normalized one.
fn shown(path: &Path) -> String {
    let text = path.to_string_lossy();
    match text.strip_prefix("\\\\?\\") {
        Some(rest) => match rest.strip_prefix("UNC\\") {
            Some(share) => format!("\\\\{share}"),
            None => rest.to_owned(),
        },
        None => text.into_owned(),
    }
}
/// The status line for a sync notice and its tone. Sync news never beeps:
/// it is not the result of what the user just did. A line without values
/// keeps its Korean source, so a language switch translates it. No line
/// names an entry: the status line is window text other programs can read.
fn sync_line(notice: &SyncNotice) -> (Zeroizing<String>, isize) {
    // The key notices of key-file sync, and KeyFork-SK (spec v3 §7.4).
    #[cfg(feature = "security-key")]
    if let Some((text, danger)) = keys_ui::key_sync_line(notice) {
        return (text, if danger { TONE_DANGER } else { TONE_MUTED });
    }
    let (text, danger) = match notice {
        SyncNotice::SyncOn => (
            line("동기화를 켰습니다. 서버에 올라가면 위에 '동기화됨'이 표시됩니다."),
            false,
        ),
        SyncNotice::Merged { added, removed } => (
            Zeroizing::new(fill(
                "다른 PC의 변경을 합쳤습니다: 추가 {}개, 삭제 {}개.",
                &[added, removed],
            )),
            false,
        ),
        SyncNotice::Conflicts(n) => (
            Zeroizing::new(fill(
                "두 PC에서 함께 고친 항목 {}개는 두 버전을 모두 남겼습니다. 이름이 같은 항목을 확인하세요.",
                &[n],
            )),
            false,
        ),
        // The count includes entries edited there: an edit replaces the
        // old entry, which is gone here as well. In the danger tone: it may
        // be a key holder deleting through the server.
        SyncNotice::MassDelete { removed, file } => (
            Zeroizing::new(fill(
                "다른 PC에서 항목 {}개가 삭제되거나 수정되었습니다. 합치기 전 상태를 {}에 보관했습니다.",
                &[removed, file],
            )),
            true,
        ),
        SyncNotice::Rollback => (
            line(
                "경고: 서버가 이전 상태의 금고를 보냈습니다. 이 PC의 항목은 그대로이며 서버에 다시 올립니다.",
            ),
            true,
        ),
        SyncNotice::BadIncoming => (
            line(
                "서버에서 받은 금고를 인증하지 못해 무시했습니다(손상 또는 변조). 이 PC의 상태를 다시 올립니다.",
            ),
            true,
        ),
        SyncNotice::ForeignIncoming => (
            line(
                "서버 사본이 다른 금고의 것이라 무시했습니다. goyo-sync를 멈추고 동기화 폴더를 지운 뒤 다시 실행하세요.",
            ),
            true,
        ),
        SyncNotice::TooLarge => (
            line("합치면 항목 1000개 또는 8 MiB를 넘어 합치지 않았습니다. 항목을 정리하세요."),
            true,
        ),
        SyncNotice::NewerFormat => (
            line("서버 사본이 새 버전 형식이라 동기화를 멈췄습니다. 고요 금고를 업데이트하세요."),
            true,
        ),
        SyncNotice::KeyInFolder => (
            line(
                "열쇠 파일이 동기화 폴더 안에 있어 동기화하지 않습니다. 열쇠를 다른 폴더로 옮기세요.",
            ),
            true,
        ),
        SyncNotice::Synced { code } => (
            Zeroizing::new(fill(
                "동기화됨 · 확인 코드 {} (다른 PC에서도 같으면 같은 내용입니다)",
                &[code],
            )),
            false,
        ),
        SyncNotice::HelperOff => (
            line(
                "동기화 도우미(goyo-sync.exe)가 실행 중이 아닙니다. 변경은 이 PC에 저장되어 있습니다.",
            ),
            false,
        ),
        SyncNotice::Offline => (
            line("동기화 오프라인: 변경은 이 PC에 저장되어 있고 연결되면 올립니다."),
            false,
        ),
        SyncNotice::HostKey => (
            line("동기화 중단: 서버 호스트 키가 바뀌었습니다. 확인하기 전에는 연결하지 않습니다."),
            true,
        ),
        SyncNotice::Auth => (
            line("동기화 오류: SSH 인증에 실패했습니다. goyo-sync.log를 확인하세요."),
            true,
        ),
        SyncNotice::HelperError => (
            line("동기화 오류: goyo-sync.log를 확인하세요. 변경은 이 PC에 저장되어 있습니다."),
            true,
        ),
        SyncNotice::OldServer => (
            line(
                "서버의 goyo-sync 스크립트가 이 금고 형식을 받지 않습니다. goyo-sync 설정 창에서 '서버에 설치·업데이트'를 누르세요. 변경은 이 PC에 저장되어 있습니다.",
            ),
            true,
        ),
        SyncNotice::KeyBehind => (
            line(
                "서버의 열쇠 파일 기록과 이 PC의 금고 사본이 맞지 않아 서버가 업로드를 받지 않습니다(다른 PC가 열쇠를 바꿨거나 열쇠 파일 동기화를 껐음). 새 열쇠 파일을 받으면 다시 올라갑니다. 변경은 이 PC에 저장되어 있습니다.",
            ),
            true,
        ),
        // The key notices of spec v3 §7.4, the longer ones in two status
        // lines (as S-ANCHOR-FORK, §2.18 #2).
        SyncNotice::KeyChanged { hardware: false } => (
            line(concat!(
                "다른 PC에서 이 금고의 열쇠를 바꿔 동기화를 멈췄습니다. 그 PC의 새 열쇠 파일을 USB로 가져와 '열쇠 관리 › 새 열쇠 파일 받기'로 받으세요. 이 PC의 열쇠 파일에 덮어쓰지는 마세요. 그때까지 이 PC의 변경은 이 PC에만 저장됩니다.",
                "\r\n",
                "어느 PC에서도 열쇠를 바꾸지 않았다면 서버 사본이 위조되었을 수 있습니다. 열쇠를 바꾼 PC를 더 쓸 수 없다면 '열쇠 관리'에서 서버 사본을 이 PC 상태로 덮어쓸 수 있습니다.",
            )),
            true,
        ),
        SyncNotice::KeyChanged { hardware: true } => (
            line(concat!(
                "다른 PC에서 이 금고에 보안 키를 켜서 동기화를 멈췄습니다. 이 고요 금고 빌드는 보안 키를 지원하지 않아 그 열쇠 파일을 받을 수 없습니다(docs/SECURITY_KEY.md).",
                "\r\n",
                "이 PC의 변경은 이 PC에만 저장됩니다. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.",
            )),
            true,
        ),
        SyncNotice::KeyFork => (
            line(
                "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라졌습니다. 동기화를 멈췄습니다. 한 PC에서 '열쇠 관리 › 새 열쇠 파일 받기'로 다른 PC의 열쇠 파일을 받으면 두 열쇠 파일을 합칩니다. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.",
            ),
            true,
        ),
        SyncNotice::OldKeyDamaged => (
            line(concat!(
                "서버 사본이 이 PC의 예전 열쇠 이름을 달고 있지만 열리지 않아 동기화를 멈췄습니다. 손상되었거나 위조된 사본일 수 있습니다. 다른 PC가 새 사본을 올리면 다시 이어집니다.",
                "\r\n",
                "그럴 PC가 없다면 '열쇠 관리'에서 서버 사본을 이 PC 상태로 덮어쓸 수 있습니다. 이 PC의 변경은 이 PC에 저장되어 있습니다.",
            )),
            true,
        ),
        SyncNotice::RollbackHeld => (
            line(concat!(
                "이 PC는 이 PC가 전에 쓴 것보다 오래된 열쇠 파일로 열려 있어 동기화를 멈췄습니다. 서버 사본은 합치지도 덮어쓰지도 않습니다. 이 PC가 전에 쓴 최신 열쇠 파일(열쇠 백업)로 다시 열거나 '열쇠 관리 › 새 열쇠 파일 받기'로 그 파일을 받으세요.",
                "\r\n",
                "지금 열쇠 파일이 맞다면 '열쇠 관리'에서 [이 열쇠 파일이 맞습니다]를 누르세요. 이 PC의 변경은 이 PC에 저장되어 있습니다.",
            )),
            true,
        ),
        SyncNotice::NewerKeyFile => (
            line(
                "다른 PC의 열쇠 파일이 이 PC의 것보다 새롭습니다. 동기화를 멈췄습니다. 그 열쇠 파일을 USB로 가져와 '열쇠 관리 › 새 열쇠 파일 받기'로 받으세요. 그 전에는 이 PC에서 열쇠를 바꾸지 마세요.",
            ),
            true,
        ),
        SyncNotice::OldKeyReplaced => (
            line(concat!(
                "예전 열쇠로 만든 서버 사본은 합치지 않고 이 PC의 상태로 덮었습니다. 새 열쇠 파일을 아직 받지 않은 PC가 있으면 그 PC에서 '새 열쇠 파일 받기'를 하세요. 그 PC의 변경은 그 뒤에 합쳐집니다.",
                "\r\n",
                "그런 PC가 없다면 예전 열쇠 사본을 가진 누군가가 올린 것일 수 있습니다.",
            )),
            true,
        ),
        #[cfg(feature = "security-key")]
        _ => (Zeroizing::default(), false),
    };
    (text, if danger { TONE_DANGER } else { TONE_MUTED })
}
/// Status lines for what an unlock took back from temp files an
/// interrupted save left, and whether one asks the user to act.
fn recovery_lines(recovery: &Recovery, key: &Path) -> (Vec<Zeroizing<String>>, bool) {
    let mut lines = Vec::new();
    if recovery.vault {
        lines.push(line(
            "금고 파일이 없어, 저장이 끊기며 남은 임시 파일에서 복구했습니다.",
        ));
    }
    let name = |p: &Path| {
        p.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    };
    if let Some(temp) = &recovery.key_kept {
        lines.push(Zeroizing::new(fill(
            "열쇠 파일 이름을 되돌리지 못했습니다. 잠근 뒤 {temp}를 {name}(으)로 바꾸세요.",
            &[&name(temp), &name(key)],
        )));
    }
    (lines, recovery.key_kept.is_some())
}
/// Placements that leave only the password between a thief and the data.
fn placement_warning(vault: &Path, key: &Path) -> Option<Placement> {
    let folder = |p: &Path| p.parent().map(|d| d.to_string_lossy().to_lowercase());
    if folder(vault).is_some_and(|f| !f.is_empty()) && folder(vault) == folder(key) {
        Some(Placement::SameFolder)
    } else if in_cloud_folder(vault) && in_cloud_folder(key) {
        Some(Placement::Cloud)
    } else {
        None
    }
}
/// OneDrive (incl. known-folder backup of Documents/Desktop), Dropbox,
/// Google Drive and iCloud folders.
fn in_cloud_folder(p: &Path) -> bool {
    let path = p.to_string_lossy().to_lowercase();
    let roots = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
        .iter()
        .filter_map(std::env::var_os)
        .map(|r| r.to_string_lossy().to_lowercase());
    roots
        .filter(|r| !r.is_empty())
        .any(|r| path.starts_with(&r))
        || [
            "\\dropbox\\",
            "\\google drive\\",
            "\\my drive\\",
            "\\icloud drive\\",
            "\\iclouddrive\\",
        ]
        .iter()
        .any(|n| path.contains(n))
}
/// Title bar colours follow the palette (Windows 11 immersive dark mode).
fn apply_window_theme(h: Hwnd) {
    let dark: i32 = theme::is_dark().into();
    unsafe {
        DwmSetWindowAttribute(h, 20, (&dark as *const i32).cast(), 4);
    }
}
fn create_window(instance: isize, class: &[u16]) -> Hwnd {
    unsafe {
        let scale = GetDpiForSystem() as f32 / 96.0;
        CreateWindowExW(
            0,
            class.as_ptr(),
            wide("고요 금고 · Goyo Vault").as_ptr(),
            0x00ca0000 | 0x02000000, // fixed caption window, WS_CLIPCHILDREN
            0x80000000u32 as i32,
            0x80000000u32 as i32,
            (890.0 * scale) as i32,
            (795.0 * scale) as i32,
            0,
            0,
            instance,
            null_mut(),
        )
    }
}
/// Filters posted messages. The app never posts commands, clicks, list or
/// edit operations, text or activation to itself, so those come from another
/// program. Of posted system commands only the taskbar's close, minimize and
/// restore are taken (a posted "move" would start a move loop). Keyboard and
/// mouse-button input is real only while one of the app's windows is in
/// front; otherwise it was posted by someone else.
fn accept_queued(h: Hwnd, msg: &Msg) -> bool {
    // A confirm box and an input dialog are owned popups, not children:
    // their controls count too.
    let popup = |b: Hwnd| b != 0 && (msg.hwnd == b || unsafe { IsChild(b, msg.hwnd) } != 0);
    let ours = msg.hwnd != 0
        && (msg.hwnd == h
            || unsafe { IsChild(h, msg.hwnd) } != 0
            || popup(confirm_box())
            || popup(input_box()));
    if !ours {
        return true;
    }
    let m = msg.message;
    if matches!(m, 0x0c | 0x1c | 0x2b | 0x111 | 0xb0..=0xda | 0xf0..=0xf8 | 0x180..=0x1b2) {
        return false;
    }
    if m == 0x112 {
        return matches!(msg.wparam & 0xfff0, 0xf060 | 0xf020 | 0xf120); // SC_CLOSE, SC_MINIMIZE, SC_RESTORE
    }
    if (0x100..=0x109).contains(&m) || (0x201..=0x20e).contains(&m) {
        return is_foreground(h);
    }
    true
}
thread_local! {
    static FILTERED_WINDOW: Cell<Hwnd> = const { Cell::new(0) };
}
/// Applies accept_queued to every message this thread takes from its queue,
/// including inside message boxes, file dialogs, move loops and menus, which
/// run their own message loops. A refused message becomes WM_NULL.
unsafe extern "system" fn queue_filter(code: i32, w: usize, l: isize) -> isize {
    if code >= 0 && l != 0 {
        let h = FILTERED_WINDOW.with(Cell::get);
        let msg = unsafe { &mut *(l as *mut Msg) };
        if h != 0 && !accept_queued(h, msg) {
            msg.message = 0;
        }
    }
    unsafe { CallNextHookEx(0, code, w, l) }
}
/// Installs queue_filter for this thread (WH_GETMESSAGE, no DLL involved).
fn filter_queue(h: Hwnd) -> isize {
    FILTERED_WINDOW.with(|f| f.set(h));
    unsafe { SetWindowsHookExW(3, queue_filter, 0, GetCurrentThreadId()) }
}
/// Owner-drawn buttons report DLGC_BUTTON only, so IsDialogMessage would turn
/// Enter into IDOK. Click the focused button instead, like a native push button.
fn enter_on_button(h: Hwnd, msg: &Msg) -> bool {
    if msg.message != 0x100 || msg.wparam != 0x0d {
        return false;
    }
    unsafe {
        let focus = GetFocus();
        if focus == 0 || GetParent(focus) != h || GetWindowLongPtrW(focus, -16) & 0xf != 0xb {
            return false;
        }
        SendMessageW(focus, 0xf5, 0, 0);
    }
    true
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let self_check = std::env::args_os().any(|v| v == "--self-check");
    let startup_error = |h, e| {
        if self_check {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
        message(h, e);
    };
    if let Err(e) = initialize_defenses().and_then(|_| restrict_process_access()) {
        startup_error(0, e);
        return;
    }
    unsafe {
        SetProcessDPIAware();
        let instance = GetModuleHandleW(null());
        let name = wide("GoyoVaultWindow");
        // Group icon 1 is embedded by build.rs; 0 (default icon) if missing.
        let icon = |metric: i32| {
            let size = GetSystemMetrics(metric);
            LoadImageW(instance, std::ptr::without_provenance(1), 1, size, size, 0)
        };
        let (big, small) = (icon(11), icon(49)); // SM_CXICON, SM_CXSMICON
        let wc = WndClass {
            style: 3,
            proc: Some(window_proc),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon: big,
            cursor: LoadCursorW(0, 32512usize as *const u16),
            background: 6,
            menu: null(),
            class: name.as_ptr(),
        };
        if RegisterClassW(&wc) == 0 {
            startup_error(0, "화면 초기화 실패");
            return;
        }
        if !self_check {
            theme::set_dark(load_theme());
            i18n::set_english(load_language());
        }
        let h = create_window(instance, &name);
        if h == 0 {
            startup_error(0, "화면 생성 실패");
            return;
        }
        apply_window_theme(h);
        SendMessageW(h, 0x80, 0, small); // WM_SETICON, ICON_SMALL
        SendMessageW(h, 0x80, 1, big);
        // Without this, Modern Standby laptops never send WM_POWERBROADCAST,
        // so closing the lid would not lock.
        let suspend = RegisterSuspendResumeNotification(h, 0);
        if SetWindowDisplayAffinity(h, 0x11) == 0
            || WTSRegisterSessionNotification(h, 0) == 0
            || suspend == 0
            || filter_queue(h) == 0
        {
            startup_error(
                h,
                "캡처 차단, 세션 잠금 감시 또는 메시지 필터를 설정할 수 없어 종료합니다.",
            );
            DestroyWindow(h);
            return;
        }
        if let Err(e) = check_environment(h) {
            startup_error(h, e);
            DestroyWindow(h);
            return;
        }
        if self_check {
            let mut ok = crypto::random::<32>().is_ok() && SetTimer(h, 1, 500, 0) != 0;
            let mut app = App::new(h);
            app.build();
            ok &= !app.input_failed;
            app.screen = Screen::Edit;
            app.build();
            ok &= !app.input_failed;
            drop(app);
            UnregisterSuspendResumeNotification(suspend);
            WTSUnRegisterSessionNotification(h);
            DestroyWindow(h);
            // The key derivations of the vault formats, with the KDF settings
            // every release build has.
            #[cfg(debug_assertions)]
            crypto::set_kdf_profile(crypto::KdfProfile::Real);
            if crypto::self_test().is_err() {
                eprintln!("FAIL: HKDF self-test");
                std::process::exit(1);
            }
            let (memory, passes) = crypto::kdf_params();
            println!("HKDF self-test: PASS");
            println!("KDF: Argon2id, {memory} KiB, {passes} passes, 1 lane");
            #[cfg(not(feature = "security-key"))]
            println!("security-key: not built");
            #[cfg(feature = "security-key")]
            {
                println!("security-key: built");
                if goyo_vault::fido::self_test().is_err() {
                    eprintln!("FAIL: salt self-test");
                    std::process::exit(1);
                }
                println!("salt self-test: PASS");
                // webauthn.dll and what it loads, with no ceremony; the
                // planting and thread checks below then cover them too.
                match webauthn::api_version() {
                    Some(api) => println!("WebAuthn API {api}"),
                    None => println!("WebAuthn API: not available"),
                }
            }
            // Planting check: a DLL loaded from the program folder fails here
            // even if it loaded silently.
            for planted in modules_beside_exe() {
                eprintln!(
                    "FAIL: DLL loaded from the program folder: {}",
                    planted.display()
                );
                ok = false;
            }
            if !restrict_threads() || open_threads() != 0 {
                eprintln!("FAIL: a thread is still open to other programs");
                ok = false;
            }
            if ok {
                println!(
                    "PASS: process mitigations, process and thread access, no DLL beside the exe, Windows version, capture exclusion, session and sleep notifications, message filter, local session, debugger check, timer, RDSEED, input scope, IME exclusion"
                );
            } else {
                std::process::exit(1);
            }
            return;
        }
        APP.with(|a| {
            let mut app = App::new(h);
            app.start_screen();
            // --self-check fails on it; a normal start says so and stays
            // flagged (VC-4).
            if !modules_beside_exe().is_empty() {
                app.weaken(DLL_BESIDE);
            }
            app.build();
            *a.borrow_mut() = Some(app);
        });
        if SetTimer(h, 1, 500, 0) == 0 {
            message(h, "자동 잠금 타이머를 시작할 수 없어 종료합니다.");
            DestroyWindow(h);
            APP.with(|a| {
                a.borrow_mut().take();
            });
            return;
        }
        ShowWindow(h, 5);
        UpdateWindow(h);
        let mut msg = Msg::default();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            if !accept_queued(h, &msg) {
                continue;
            }
            if (0x100..=0x109).contains(&msg.message) || (0x201..=0x20e).contains(&msg.message) {
                APP.with(|a| {
                    if let Ok(mut b) = a.try_borrow_mut()
                        && let Some(s) = b.as_mut()
                    {
                        s.activity = Instant::now();
                    }
                });
            }
            if enter_on_button(h, &msg) {
                continue;
            }
            if IsDialogMessageW(h, &mut msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        UnregisterSuspendResumeNotification(suspend);
        WTSUnRegisterSessionNotification(h);
        APP.with(|a| {
            a.borrow_mut().take();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paste_validation_and_strict_unicode() {
        let pem: Vec<u16> = "-----BEGIN KEY-----\r\nabcdef\r\n-----END KEY-----"
            .encode_utf16()
            .collect();
        assert!(valid_paste(&pem, true, 8192));
        assert!(!valid_paste(&pem, false, 8192));
        assert!(!valid_paste(&pem, true, 6));
        assert!(!valid_paste(&[0xd800], true, 8192));
        assert!(secret_utf8(&[0xd800]).is_err());
        assert_eq!(
            &*secret_utf8(&"한글😀".encode_utf16().collect::<Vec<_>>()).unwrap(),
            "한글😀"
        );
    }
    #[test]
    fn protected_pages_cover_long_secrets() {
        for value in [
            "a".repeat(8192),
            "한글니모닉😀".repeat(100),
            "short key".into(),
        ] {
            let pages = secret_pages(&value, 40, |line| {
                Ok(line.chars().map(|c| if c.is_ascii() { 1 } else { 2 }).sum())
            })
            .unwrap();
            let reconstructed: String = pages
                .iter()
                .flat_map(|p| p.chars().filter(|c| *c != '\n'))
                .collect();
            assert_eq!(reconstructed, value);
            for p in &pages {
                assert!(p.lines().count() <= 2);
                for line in p.lines() {
                    assert!(
                        line.chars()
                            .map(|c| if c.is_ascii() { 1 } else { 2 })
                            .sum::<usize>()
                            <= 40
                    );
                }
            }
        }
    }
    /// A mnemonic's numbered grid: words 1-8 on the first row, 9-16 on the
    /// second, 17-24 on the third, then a new page; any count of words, the
    /// whitespace-separated tokens of the secret, which stays as stored. A
    /// column is as wide as its widest number and word, no two overlap, a
    /// page steps down a face until it fits, and one that fits at no face
    /// is shown as running text (None).
    #[test]
    fn a_mnemonic_is_a_numbered_grid_of_eight_words_a_row() {
        // A face's width per character: 8 px at the largest, 4 at the last.
        let per_char = [8, 7, 6, 5, 4];
        let measure = |font: usize, text: &str| Ok(per_char[font] * text.chars().count() as i32);
        let width = 440;
        let words = |n: usize| -> String {
            (1..=n)
                .map(|i| ["abandon", "zoo", "category", "act"][i % 4])
                .collect::<Vec<_>>()
                .join(" ")
        };
        for (n, rows) in [
            (1, vec![vec![1]]),
            (5, vec![vec![1, 2, 3, 4, 5]]),
            (12, vec![(1..=8).collect(), (9..=12).collect()]),
            (
                18,
                vec![(1..=8).collect(), (9..=16).collect(), vec![17, 18]],
            ),
            (
                24,
                vec![(1..=8).collect(), (9..=16).collect(), (17..=24).collect()],
            ),
        ] {
            let secret = words(n);
            let pages = mnemonic_grid(&secret, width, 5, (8, 4), measure)
                .unwrap()
                .unwrap_or_else(|| panic!("{n} words: no grid"));
            assert_eq!(pages.len(), 1, "{n}");
            let page = &pages[0];
            assert_eq!(page.rows, rows.len(), "{n}");
            for (r, numbers) in rows.iter().enumerate() {
                let row: Vec<&GridCell> = page.cells.iter().filter(|c| c.row == r).collect();
                assert_eq!(
                    row.iter().map(|c| c.number).collect::<Vec<_>>(),
                    *numbers,
                    "{n} words, row {r}"
                );
                for (col, c) in row.iter().enumerate() {
                    assert_eq!(c.col, col, "{n} words, number {}", c.number);
                    assert_eq!(grid_place(c.number - 1), (0, r, col));
                }
            }
            // Word i is the i-th token, the stored text unchanged.
            let tokens: Vec<&str> = secret.split_whitespace().collect();
            for c in &page.cells {
                assert_eq!(&secret[c.word.clone()], tokens[c.number - 1]);
            }
            assert_eq!(secret, words(n));
            grid_fits(page, &secret, width, per_char[page.font]);
        }
        // 24 words step down a face (8 columns of "8 category" do not fit
        // 440 px at 8 px a character); 5 words fit at the largest.
        let pages = mnemonic_grid(&words(24), width, 5, (8, 4), measure)
            .unwrap()
            .unwrap();
        assert!(pages[0].font > 0);
        let pages = mnemonic_grid(&words(5), width, 5, (8, 4), measure)
            .unwrap()
            .unwrap();
        assert_eq!(pages[0].font, 0);
        // Tabs, line breaks and runs of spaces separate words too; 25 words
        // and more go on to a second page, numbered on from 25.
        let secret = format!("  {}\t\r\nlast  ", words(24));
        let pages = mnemonic_grid(&secret, width, 5, (8, 4), measure)
            .unwrap()
            .unwrap();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].cells.len(), 24);
        let c = &pages[1].cells[0];
        assert_eq!((c.number, c.row, c.col, pages[1].rows), (25, 0, 0, 1));
        assert_eq!(&secret[c.word.clone()], "last");
        assert_eq!(grid_place(24), (1, 0, 0));
        assert_eq!(grid_place(47), (1, 2, 7));
        assert_eq!(grid_place(48), (2, 0, 0));
        // A long word widens its own column, never into the next one.
        let long = format!("{} supercalifragilistic", words(11));
        let pages = mnemonic_grid(&long, width, 5, (8, 4), measure)
            .unwrap()
            .unwrap();
        grid_fits(&pages[0], &long, width, per_char[pages[0].font]);
        let wide = pages[0].cells.iter().find(|c| c.number == 12).unwrap();
        let narrow = pages[0].cells.iter().find(|c| c.number == 5).unwrap();
        assert!(wide.w > narrow.w);
        // Short words: columns of one width, the whole width shared out.
        let pages = mnemonic_grid(&["zoo"; 12].join(" "), width, 5, (8, 4), measure)
            .unwrap()
            .unwrap();
        let w = pages[0].cells[0].w;
        assert!(
            pages[0]
                .cells
                .iter()
                .all(|c| c.w == w && c.x == c.col as i32 * (w + 8))
        );
        assert!(8 * w + 7 * 8 <= width && 8 * (w + 1) + 7 * 8 > width - 8);
        // A word too long for any face: the running text, in pages.
        let too_long = format!("{} {}", words(3), "x".repeat(120));
        assert!(
            mnemonic_grid(&too_long, width, 5, (8, 4), measure)
                .unwrap()
                .is_none()
        );
        assert!(
            mnemonic_grid(" \t\r\n", width, 5, (8, 4), measure)
                .unwrap()
                .is_none()
        );
        assert!(
            mnemonic_grid("", width, 5, (8, 4), measure)
                .unwrap()
                .is_none()
        );
        // A measure that fails fails the layout.
        assert!(mnemonic_grid("a b", width, 5, (8, 4), |_, _| Err("x")).is_err());
    }
    /// Every column of `page` holds its numbers and words at a face of
    /// `per_char` px a character, inside `width`, apart from the next.
    fn grid_fits(page: &GridPage, secret: &str, width: i32, per_char: i32) {
        for c in &page.cells {
            let word = per_char * secret[c.word.clone()].chars().count() as i32;
            let number = per_char * c.number.to_string().len() as i32;
            assert!(number <= c.num_w, "{c:?}");
            assert!(c.num_w + 4 + word <= c.w, "{c:?}");
            assert!(c.x >= 0 && c.x + c.w <= width, "{c:?}");
            if let Some(next) = page
                .cells
                .iter()
                .find(|n| n.row == c.row && n.col == c.col + 1)
            {
                assert!(c.x + c.w + 8 <= next.x, "{c:?} {next:?}");
            }
        }
    }
    /// The login's note for a key file that is not there (spec §2.29):
    /// "next to the vault" only for the vault's own key name or a synced
    /// vault; a key kept elsewhere (an unplugged stick) is to be plugged in
    /// or picked, never moved next to the vault.
    #[test]
    fn a_missing_key_note_fits_where_the_key_is_kept() {
        let _korean = KoreanAfter::hold();
        let dir = test_dir("missing-key-note");
        let vault = dir.join("vault.goyo");
        std::fs::write(&vault, b"any vault bytes").unwrap();
        let mut app = App::new(0);
        app.screen = Screen::Login;
        let own = dir.join("vault.goyokey");
        assert_eq!(
            app.missing_key_note(&vault, &own),
            Some(fill(KEY_MISSING_NOTE, &[&"vault.goyokey"]))
        );
        let stick = Path::new(r"Q:\keys\home.goyokey");
        assert_eq!(
            app.missing_key_note(&vault, stick),
            Some(fill(KEY_ELSEWHERE_NOTE, &[&"home.goyokey"]))
        );
        // A synced vault: its key file belongs on each PC.
        std::fs::create_dir(dir.join("vault.goyo.sync")).unwrap();
        assert_eq!(
            app.missing_key_note(&vault, stick),
            Some(fill(KEY_MISSING_NOTE, &[&"vault.goyokey"]))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A thread restrict_threads cannot restrict is said at the next tick,
    /// in the danger tone, and the flag stays after ticks that find every
    /// thread restricted again; the header pill names it (VC-4).
    #[test]
    fn a_weakened_protection_is_said_and_stays() {
        let _korean = KoreanAfter::hold();
        let mut app = App::new(0);
        app.timer();
        assert_eq!(app.weakened, None);
        assert_eq!(app.pill_text("잠김".into()), "잠김");
        THREADS_STUCK.with(|s| s.set(true));
        app.timer();
        THREADS_STUCK.with(|s| s.set(false));
        assert_eq!(app.weakened, Some(THREADS_OPEN));
        assert_eq!(app.status.as_str(), THREADS_OPEN);
        assert_eq!(app.status_tone, TONE_DANGER);
        app.status("다른 안내");
        app.timer();
        assert_eq!(app.weakened, Some(THREADS_OPEN));
        assert_eq!(app.pill_text("잠김".into()), "보호 약화 · 잠김");
        // A later cause does not replace the first one.
        app.weaken(DLL_BESIDE);
        assert_eq!(app.weakened, Some(THREADS_OPEN));
        assert_eq!(app.status.as_str(), "다른 안내");
    }
    #[test]
    fn first_run_starts_on_welcome() {
        let dir = std::env::temp_dir().join(format!(
            "goyo-first-run-{:x}",
            u64::from_le_bytes(*crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut app = App::new(0);
        app.vault_path = dir.join("vault.goyo");
        app.start_screen();
        assert!(app.screen == Screen::Welcome && app.provision.is_none());
        assert!(app.allows(CREATE) && app.allows(RESTORE) && app.allows(OPEN));
        assert!(!app.allows(SUBMIT) && !app.allows(PASS)); // nothing to unlock
        // Create suggests names that do not exist; Restore lands on vault.goyo.
        app.home_dir = dir.clone();
        app.screen = Screen::Create;
        app.default_paths();
        assert_eq!(app.new_vault_path, dir.join("vault.goyo"));
        app.screen = Screen::Restore;
        app.default_paths();
        assert_eq!(app.dest_path, dir.join("vault.goyo"));
        std::fs::write(&app.vault_path, b"synthetic").unwrap();
        let mut app = App::new(0);
        app.vault_path = dir.join("vault.goyo");
        app.start_screen();
        assert!(app.screen == Screen::Login && app.provision.is_none());
        app.home_dir = dir.clone();
        app.screen = Screen::Create;
        app.default_paths();
        assert_eq!(app.new_vault_path, dir.join("vault-2.goyo"));
        assert_eq!(app.new_key_path, dir.join("vault-2.goyokey"));
        app.screen = Screen::Restore;
        app.default_paths();
        assert_eq!(app.dest_path, dir.join("restored.goyo"));
        std::fs::remove_file(dir.join("vault.goyo")).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
    /// The interface language is one setting for the whole process. Tests
    /// that switch it, or that check text translated while they run, hold
    /// this for their whole run, so they take turns. It puts the interface
    /// back in Korean when the test ends, even by a failed assertion.
    pub(crate) struct KoreanAfter {
        _turn: std::sync::MutexGuard<'static, ()>,
    }
    impl KoreanAfter {
        pub(crate) fn hold() -> Self {
            static LANGUAGE: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let turn = LANGUAGE.lock();
            Self {
                _turn: turn.unwrap_or_else(std::sync::PoisonError::into_inner),
            }
        }
    }
    impl Drop for KoreanAfter {
        fn drop(&mut self) {
            i18n::set_english(false);
        }
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetClassNameW(h: Hwnd, name: *mut u16, n: i32) -> i32;
    }
    fn class_of(h: Hwnd) -> String {
        let mut class = [0u16; 16];
        let n = unsafe { GetClassNameW(h, class.as_mut_ptr(), 16) }.max(0) as usize;
        String::from_utf16_lossy(&class[..n])
    }
    fn caption(h: Hwnd) -> String {
        let mut buf = vec![0u16; 2048];
        let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), 2048) }.max(0) as usize;
        String::from_utf16_lossy(&buf[..n])
    }
    fn has_korean(s: &str) -> bool {
        s.chars().any(|c| {
            ('\u{ac00}'..='\u{d7a3}').contains(&c) || ('\u{3131}'..='\u{318e}').contains(&c)
        })
    }
    /// Text painted by draw_screen (not child controls), from an off-screen DC.
    unsafe fn painted(app: &App) -> Vec<String> {
        unsafe {
            theme::PAINTED.with(|p| p.borrow_mut().clear());
            let screen = GetDC(app.hwnd);
            let dc = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, 1600, 1400);
            ReleaseDC(app.hwnd, screen);
            let old = SelectObject(dc, bmp);
            app.draw_screen(dc);
            SelectObject(dc, old);
            DeleteObject(bmp);
            DeleteDC(dc);
            theme::PAINTED.with(|p| p.take())
        }
    }
    /// Builds every screen with synthetic data and calls `visit` on each:
    /// first run, open, restore, create, the vault empty, with a shown
    /// entry and syncing (each pill word), edit, password change, key
    /// management
    /// with each thing that holds key changes, and adopt.
    unsafe fn each_screen(dir: &std::path::Path, visit: &mut dyn FnMut(&mut App, &str)) {
        let mut session = synthetic_session(dir, "synthetic layout password");
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(h, 0);
            let mut app = App::new(h);
            app.home_dir = dir.to_owned();
            app.vault_path = session.path.clone();
            app.key_path = session.key_path.clone();
            for (screen, name) in [
                (Screen::Welcome, "welcome"),
                (Screen::Login, "login"),
                (Screen::Restore, "restore"),
                // A vault from the server with no key file here (spec §2.29).
                #[cfg(feature = "security-key")]
                (Screen::Fetched, "fetched"),
            ] {
                app.screen = screen;
                app.build();
                visit(&mut app, name);
            }
            // The login of a vault whose key file is not on this PC.
            let key = std::mem::replace(&mut app.key_path, dir.join("missing.goyokey"));
            app.screen = Screen::Login;
            app.build();
            visit(&mut app, "login-no-key");
            app.key_path = key;
            app.provision = Some(Provision::new().unwrap());
            app.screen = Screen::Create;
            app.build();
            visit(&mut app, "create");
            // With security keys and their PIN toggle.
            #[cfg(feature = "security-key")]
            {
                app.toggles.create = true;
                app.build();
                visit(&mut app, "create-keys");
                app.toggles.create = false;
            }
            app.provision = None;
            app.screen = Screen::Vault;
            app.session = Some(session);
            app.build();
            visit(&mut app, "vault-empty");
            // The TOFU banner in place of the detail.
            #[cfg(feature = "security-key")]
            {
                keys_ui::TOFU_SHOWN.with(|t| t.set(true));
                app.build();
                // This 0.8 key file: S-TOFU-LEGACY, no code field.
                visit(&mut app, "vault-tofu");
                // A GOYOKE03 one: S-TOFU and S-TOFU-PWONLY, the code field.
                keys_ui::TOFU_KF2_SHOWN.with(|t| t.set(true));
                app.build();
                visit(&mut app, "vault-tofu-pwonly");
                keys_ui::TOFU_KF2_SHOWN.with(|t| t.set(false));
                // A key file from the server: its title and the steps left.
                keys_ui::TOFU_FETCHED_SHOWN.with(|t| t.set(true));
                app.build();
                visit(&mut app, "vault-tofu-fetched");
                keys_ui::TOFU_FETCHED_SHOWN.with(|t| t.set(false));
                keys_ui::TOFU_SHOWN.with(|t| t.set(false));
            }
            session = app.session.take().unwrap();
            // "니모닉" is a built-in type, so its chip follows the language.
            let entry = Entry::new(
                "GitHub".into(),
                "니모닉".into(),
                "synthetic secret".into(),
                String::new(),
            )
            .unwrap();
            session.put(None, entry).unwrap();
            app.session = Some(session);
            app.selected = Some(0);
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.build();
            visit(&mut app, "vault-shown");
            app.reveal_until = None;
            app.copy_until = Some(Instant::now() + Duration::from_secs(15));
            app.build();
            visit(&mut app, "vault-copy");
            app.copy_until = None;
            // An entry with an OTP secret: its row, its secret shown, its QR.
            let otp = Otp::parse(SYNTHETIC_OTP).unwrap();
            let entry = Entry::new_with_otp(
                "Synthetic bank with a long name".into(),
                "비밀번호".into(),
                "synthetic secret".into(),
                "synthetic memo".into(),
                otp.as_ref(),
            )
            .unwrap();
            let s = app.session.as_mut().unwrap();
            s.put(None, entry).unwrap();
            let otp_id = s.entries[1].id();
            app.selected = Some(1);
            app.build();
            visit(&mut app, "vault-otp");
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.build();
            visit(&mut app, "vault-otp-shown");
            app.reveal_until = None;
            app.qr = Some((otp_id, Instant::now() + QR_SHOWN));
            app.build();
            visit(&mut app, "vault-otp-qr");
            app.qr = None;
            app.editing = Some(1);
            app.screen = Screen::Edit;
            app.build();
            visit(&mut app, "edit-otp");
            // An OTP entry (0.12.1): its view, its QR and its editor.
            let entry = Entry::new_with_otp(
                "Synthetic code only".into(),
                vault::OTP_KIND.into(),
                String::new(),
                "synthetic memo".into(),
                otp.as_ref(),
            )
            .unwrap();
            let s = app.session.as_mut().unwrap();
            s.put(None, entry).unwrap();
            let otp_entry_id = s.entries[2].id();
            app.editing = None;
            app.screen = Screen::Vault;
            app.selected = Some(2);
            app.build();
            visit(&mut app, "vault-otp-entry");
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.build();
            visit(&mut app, "vault-otp-entry-shown");
            app.reveal_until = None;
            app.qr = Some((otp_entry_id, Instant::now() + QR_SHOWN));
            app.build();
            visit(&mut app, "vault-otp-entry-qr");
            app.qr = None;
            app.editing = Some(2);
            app.screen = Screen::Edit;
            app.build();
            visit(&mut app, "edit-otp-kind");
            app.session.as_mut().unwrap().delete(2).unwrap();
            app.editing = None;
            app.screen = Screen::Vault;
            app.selected = Some(0);
            // A vault that syncs: the helper's folder and status, sync turned
            // on and its first upload handed back, so the pill shows a real
            // "동기화됨" before the file name; then every other word.
            let s = app.session.as_mut().unwrap();
            let mut server = Server::default();
            server.helper(&s.path);
            s.enable_sync().unwrap();
            upload(&mut server, s);
            app.sync_badge = s.badge();
            assert_eq!(app.sync_badge, Some(SyncBadge::Synced));
            app.build();
            visit(&mut app, "vault-sync");
            for badge in [
                SyncBadge::Uploading,
                SyncBadge::HelperOff,
                SyncBadge::Offline,
                SyncBadge::Warning,
            ] {
                app.sync_badge = Some(badge);
                app.build();
                visit(&mut app, &format!("vault-sync-{badge:?}"));
            }
            app.sync_badge = Some(SyncBadge::Synced);
            // The edit screen's warning follows the auto-lock choice.
            for choice in 1..AUTO_LOCKS.len() {
                app.auto_lock = choice;
                app.screen = Screen::Edit;
                app.build();
                visit(&mut app, &format!("edit-auto-lock-{choice}"));
            }
            app.auto_lock = 0;
            for (screen, name) in [(Screen::Edit, "edit"), (Screen::Password, "password")] {
                app.screen = screen;
                app.build();
                visit(&mut app, name);
            }
            // Keys as this 0.8 key file shows it, then a KF2 key file's code
            // with each hold, filled with long values.
            app.screen = Screen::Keys;
            app.build();
            visit(&mut app, "keys");
            let path = PathBuf::from(
                r"D:\Users\synthetic-user\Documents\Goyo Vault backups\2026\vault-backup.goyokey",
            );
            for (name, hold) in [
                ("keys-code", Hold::None),
                ("keys-pending", Hold::PendingElsewhere(path)),
                ("keys-restore-pending", Hold::RestorePending),
                ("keys-restore-oldkey", Hold::RestoreOldKey(65_535, 65_536)),
                ("keys-restored", Hold::Restored),
                ("keys-rollback", Hold::LocalRollback(65_536, 65_535)),
                ("keys-halted", Hold::Halted),
            ] {
                let code = Some("E65536 · DDDD-DDDD-DDDD-DDDD".to_owned());
                KEYS_VIEW.with(|v| {
                    *v.borrow_mut() = Some(KeysView {
                        code,
                        hold,
                        #[cfg(feature = "security-key")]
                        keys: None,
                    })
                });
                app.build();
                visit(&mut app, name);
            }
            // The security-key section: on, with eight keys and long rows,
            // and the pairing screen; off, with the password change ticked
            // and not; and a changed key file waiting for its gate.
            #[cfg(feature = "security-key")]
            {
                let keys = Some(long_overview());
                for (name, hold) in [
                    ("keys-hardware", Hold::None),
                    ("keys-hardware-halted", Hold::Halted),
                    ("keys-gate-pending", Hold::GatePending),
                ] {
                    KEYS_VIEW.with(|v| {
                        *v.borrow_mut() = Some(KeysView {
                            code: Some("E65536 · DDDD-DDDD-DDDD-DDDD".to_owned()),
                            hold,
                            keys: keys.clone(),
                        })
                    });
                    app.screen = Screen::Keys;
                    app.build();
                    visit(&mut app, name);
                }
                // A PC without keys and the server's keys-on file, halted:
                // [서버의 새 열쇠 파일 받기…] and the head override below it.
                KEYS_VIEW.with(|v| {
                    *v.borrow_mut() = Some(KeysView {
                        code: Some("E65536 · DDDD-DDDD-DDDD-DDDD".to_owned()),
                        hold: Hold::ServerKeysOn {
                            epoch: (1 << 48) - 1,
                            halted: true,
                        },
                        keys: None,
                    })
                });
                app.screen = Screen::Keys;
                app.build();
                visit(&mut app, "keys-server-take");
                // Key-file sync on, a gated change waiting and "열쇠 변경
                // 자동 적용" on (spec §2.30): its toggle beside the state line.
                keys_ui::KS_SHOWN.with(|k| {
                    *k.borrow_mut() = Some(vault::KeySyncView {
                        on: true,
                        synced: true,
                        helper: true,
                        auto_apply: true,
                        waiting: Some(vault::Waiting {
                            epoch: (1 << 48) - 1,
                            class: vault::KeyClass::Successor {
                                carry: false,
                                gate: Some(vault::GateKind::G1),
                            },
                            pending_gate: true,
                            supersede: false,
                        }),
                        ..vault::KeySyncView::default()
                    })
                });
                KEYS_VIEW.with(|v| {
                    *v.borrow_mut() = Some(KeysView {
                        code: Some("E65536 · DDDD-DDDD-DDDD-DDDD".to_owned()),
                        hold: Hold::None,
                        keys: keys.clone(),
                    })
                });
                app.screen = Screen::Keys;
                app.build();
                visit(&mut app, "keys-hardware-auto");
                keys_ui::KS_SHOWN.with(|k| *k.borrow_mut() = None);
                app.toggles.pick = 0xff;
                app.screen = Screen::Pair;
                app.build();
                visit(&mut app, "pair");
                // The removal screens: nothing picked; keys picked with the
                // exposure answered 모름 (the password change and the
                // shared-PIN toggles); one key left (S-ONEKEY); and a
                // retirement with its password change.
                for (screen, name, pick, exposure) in [
                    (Screen::LostKey, "lost-key", 0, None),
                    (
                        Screen::LostKey,
                        "lost-key-unsure",
                        0b0000_0011,
                        Some(vault::Exposure::Unsure),
                    ),
                    (
                        Screen::LostKey,
                        "lost-key-one-left",
                        0b0111_1111,
                        Some(vault::Exposure::No),
                    ),
                    (Screen::KeyRemove, "key-remove", 0b0000_0110, None),
                    (Screen::KeyRemove, "key-remove-one-left", 0b0111_1111, None),
                ] {
                    app.toggles = keys_ui::Toggles {
                        pick,
                        shared: 0b0011_0000,
                        exposure,
                        pwchange: exposure.is_some_and(|e| e != vault::Exposure::No)
                            || screen == Screen::KeyRemove,
                        ..keys_ui::Toggles::default()
                    };
                    app.screen = screen;
                    app.build();
                    visit(&mut app, name);
                }
                // The review with the longest rows and both warnings.
                keys_ui::REVIEW_SHOWN.with(|r| *r.borrow_mut() = Some(long_review()));
                app.toggles = keys_ui::Toggles {
                    review_day: Some(Some(4_102_358_400)),
                    ..keys_ui::Toggles::default()
                };
                app.screen = Screen::Review;
                app.build();
                visit(&mut app, "review");
                app.toggles.review_day = Some(None);
                app.build();
                visit(&mut app, "review-all");
                keys_ui::REVIEW_SHOWN.with(|r| r.borrow_mut().take());
                app.toggles = keys_ui::Toggles::default();
                KEYS_VIEW.with(|v| v.borrow_mut().take());
                for pw in [true, false] {
                    app.toggles.keyon_pw = pw;
                    app.screen = Screen::Keys;
                    app.build();
                    visit(&mut app, if pw { "keys-off" } else { "keys-off-nopw" });
                }
                app.toggles = keys_ui::Toggles::default();
            }
            KEYS_VIEW.with(|v| v.borrow_mut().take());
            app.screen = Screen::Adopt;
            app.adopt_source = Some(app.key_path.clone());
            app.build();
            visit(&mut app, "adopt");
            app.adopt_source = None;
            drop(app);
            DestroyWindow(h);
        }
    }
    /// What ui_preview shows on the security-key build's screens: four keys
    /// registered together, key 4 a replacement paired with key 3 only;
    /// key 1 picked as lost with 모름 and key 2 sharing its PIN; key 4 picked
    /// for retirement; a review with every kind of row.
    #[cfg(feature = "security-key")]
    fn preview_keys(a: &mut App, file: &str) {
        use vault::{ReviewChange as C, ReviewRow};
        let row = |n: u8, unpaired: Vec<u8>| vault::KeyRow {
            number: n,
            registered: 1_790_000_000,
            stamp: "20260922-140000".into(),
            display: format!("Goyo Vault 7F2A90C4 key {n} 20260922-140000"),
            suspended: false,
            orphan: false,
            cloned: false,
            opened: n == 1,
            unpaired,
            broken: Vec::new(),
        };
        let keys = vault::KeysOverview {
            pin: true,
            rows: vec![
                row(1, vec![4]),
                row(2, vec![4]),
                row(3, Vec::new()),
                row(4, vec![1, 2]),
            ],
            full: vec![3],
        };
        let hold = if file.ends_with("19-keys-undone") {
            Hold::Undone("1".into())
        } else {
            Hold::None
        };
        let shown = [
            "14-keys-sk",
            "15-lost-key",
            "16-key-remove",
            "17-pair",
            "19-keys-undone",
            "23-keys-ks-off",
            "24-keys-ks-on",
        ]
        .iter()
        .any(|f| file.ends_with(f));
        // A vault that syncs, its key file kept on this PC or synced: the
        // one line and the one switch (spec §2.29), and the note above.
        let ks = ["23-keys-ks-off", "24-keys-ks-on"]
            .iter()
            .position(|f| file.ends_with(f))
            .map(|on| vault::KeySyncView {
                on: on == 1,
                synced: true,
                helper: true,
                ..vault::KeySyncView::default()
            });
        keys_ui::KS_SHOWN.with(|k| *k.borrow_mut() = ks);
        if shown {
            KEYS_VIEW.with(|v| {
                *v.borrow_mut() = Some(KeysView {
                    code: Some("E5 · 7F2A-90C4-1B5E-D836".into()),
                    hold,
                    keys: Some(keys),
                })
            });
        }
        // A PC without keys, halted, the server holding another PC's
        // keys-on file: [서버의 새 열쇠 파일 받기…].
        if file.ends_with("25-keys-server-take") {
            KEYS_VIEW.with(|v| {
                *v.borrow_mut() = Some(KeysView {
                    code: Some("E4 · 7F2A-90C4-1B5E-D836".into()),
                    hold: Hold::ServerKeysOn {
                        epoch: 5,
                        halted: true,
                    },
                    keys: None,
                })
            });
        }
        a.toggles = keys_ui::Toggles::default();
        if file.ends_with("15-lost-key") {
            a.toggles.pick = 0b0001;
            a.toggles.shared = 0b0010;
            a.toggles.exposure = Some(vault::Exposure::Unsure);
            a.toggles.pwchange = true;
        } else if file.ends_with("16-key-remove") {
            a.toggles.pick = 0b1000;
        } else if file.ends_with("17-pair") {
            a.toggles.pick = 0b1100;
        }
        let review = file.ends_with("18-review").then(|| {
            let row = |change, title: Option<&str>| ReviewRow {
                change,
                title: title.map(str::to_owned),
                index: None,
                time: 1_793_250_000,
            };
            a.toggles.review_day = Some(Some(1_791_590_400));
            vault::ReviewList {
                rows: vec![
                    row(C::Replaced, Some("Bank account")),
                    row(C::Moved, Some("Bank account")),
                    row(C::New, Some("Recovery e-mail")),
                    row(C::Edited, Some("Server SSH key")),
                    row(C::Deleted, None),
                ],
                truncated: None,
            }
        });
        keys_ui::REVIEW_SHOWN.with(|r| *r.borrow_mut() = review);
    }
    /// Eight keys with the longest rows the Keys and Pair screens show: every
    /// flag, every other key unpaired or broken.
    #[cfg(feature = "security-key")]
    fn long_overview() -> vault::KeysOverview {
        let rows = (1..=8u8)
            .map(|n| vault::KeyRow {
                number: 240 + n,
                registered: 4_102_444_799,
                stamp: "20991231-235959".into(),
                display: format!("Goyo Vault DDDDDDDD key {} 20991231-235959", 240 + n),
                suspended: n == 2,
                orphan: n == 3,
                cloned: true,
                opened: n == 1,
                unpaired: (241..=248).filter(|k| *k != 240 + n).collect(),
                broken: if n == 4 {
                    vec![241, 242, 243]
                } else {
                    Vec::new()
                },
            })
            .collect();
        vault::KeysOverview {
            pin: true,
            rows,
            full: vec![241, 245, 246, 247, 248],
        }
    }
    /// A review list with every kind of row, the longest titles and both
    /// warnings (S-REVIEW-REPLACED, S-REVIEW-TRUNC).
    #[cfg(feature = "security-key")]
    fn long_review() -> vault::ReviewList {
        use vault::{ReviewChange as C, ReviewRow};
        let title = Some("W".repeat(64));
        let row = |change, title: Option<String>, index| ReviewRow {
            change,
            title,
            index,
            time: 4_102_444_799,
        };
        vault::ReviewList {
            rows: vec![
                row(C::Replaced, title.clone(), Some(0)),
                row(C::Moved, title.clone(), Some(1)),
                row(C::New, title.clone(), Some(2)),
                row(C::Edited, None, None),
                row(C::Deleted, None, None),
            ],
            truncated: Some(4_102_444_799),
        }
    }
    /// A test's folder, which is also the anchor folder of the PC the test
    /// plays (`anchor` in it): no test touches the developer's own.
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "goyo-{name}-{:x}",
            u64::from_le_bytes(*crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        vault::set_anchor_dir(Some(dir.join("anchor")));
        dir
    }
    /// A 0.8 key file that waits for trust (a vault with signs of security
    /// keys, most likely turned on at another PC) has no key check code: the
    /// banner says what to do instead (S-TOFU-LEGACY) and shows no code
    /// field and no [코드 확인], whose code could never match; the trust
    /// without a code stays, behind its own question. A GOYOKE03 key file
    /// keeps S-TOFU-PWONLY and the code field.
    #[cfg(feature = "security-key")]
    #[test]
    fn a_0_8_key_file_waiting_for_trust_asks_no_code() {
        let _korean = KoreanAfter::hold();
        i18n::set_english(false);
        let dir = test_dir("tofu-legacy");
        let session = synthetic_session(&dir, "synthetic layout password");
        assert!(matches!(
            session.key_magic(),
            Some(vault::keyfile::Magic::Ke01 | vault::keyfile::Magic::Ke02)
        ));
        unsafe {
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(h, 0);
            let mut app = App::new(h);
            app.session = Some(session);
            app.screen = Screen::Vault;
            keys_ui::TOFU_SHOWN.with(|t| t.set(true));
            app.build();
            let texts =
                |app: &App| -> Vec<String> { app.children.iter().map(|c| caption(*c)).collect() };
            assert!(texts(&app).contains(&keys_ui::TOFU_LEGACY.to_owned()));
            assert!(!texts(&app).iter().any(|t| t.contains(keys_ui::TOFU_PWONLY)));
            assert_eq!(app.handle(keys_ui::GATE_CODE), 0);
            assert_eq!(app.handle(keys_ui::TOFU_OK), 0);
            assert_ne!(app.handle(keys_ui::TOFU_NOPC), 0);
            assert_ne!(app.handle(keys_ui::TOFU_LOCK), 0);
            keys_ui::TOFU_KF2_SHOWN.with(|t| t.set(true));
            app.build();
            assert!(
                texts(&app)
                    .iter()
                    .any(|t| t.ends_with(keys_ui::TOFU_PWONLY))
            );
            assert_ne!(app.handle(keys_ui::GATE_CODE), 0);
            assert_ne!(app.handle(keys_ui::TOFU_OK), 0);
            keys_ui::TOFU_KF2_SHOWN.with(|t| t.set(false));
            keys_ui::TOFU_SHOWN.with(|t| t.set(false));
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// Every label's text fits its box at this machine's DPI, in both
    /// languages: a STATIC clips whatever does not fit and an owner-drawn
    /// button cuts its caption, so a cut-off line would go unnoticed, and
    /// every message fits the status line.
    #[test]
    fn labels_fit_their_boxes() {
        let _korean = KoreanAfter::hold();
        unsafe fn measure(h: Hwnd, font: isize, text: &str, width: i32, flags: u32) -> Rect {
            unsafe {
                let dc = GetDC(h);
                let old = SelectObject(dc, font);
                let mut calc = Rect {
                    left: 0,
                    top: 0,
                    right: width,
                    bottom: 0,
                };
                let s = wide(text);
                DrawTextW(dc, s.as_ptr(), -1, &mut calc, 0x400 | 0x800 | flags); // DT_CALCRECT | DT_NOPREFIX
                SelectObject(dc, old);
                ReleaseDC(h, dc);
                calc
            }
        }
        let mut failures = vec![];
        for english in [false, true] {
            i18n::set_english(english);
            let dir = test_dir("fit");
            let language = if english { "en" } else { "ko" };
            let mut check = |app: &mut App, name: &str| unsafe {
                for &child in &app.children {
                    let class = class_of(child);
                    let text = caption(child);
                    let mut r = Rect::default();
                    GetClientRect(child, &mut r);
                    if class == "Static" {
                        // DT_WORDBREAK | DT_EXPANDTABS
                        let font = SendMessageW(child, 0x31, 0, 0); // WM_GETFONT
                        let need = measure(child, font, &text, r.right, 0x10 | 0x40).bottom;
                        if need > r.bottom {
                            failures.push(format!(
                                "{language} {name}: needs {need}px, has {}px: {text:?}",
                                r.bottom
                            ));
                        }
                    } else if class == "Button" {
                        let variant = GetWindowLongPtrW(child, -21);
                        if matches!(variant, theme::EYE | theme::EYE_ON) {
                            continue;
                        }
                        let font = theme::with(|t| match variant {
                            theme::PRIMARY | theme::TAB_ON => t.strong(),
                            theme::LINK | theme::CHIP => t.small(),
                            _ => t.body(),
                        })
                        .unwrap();
                        let pad = match variant {
                            theme::TOGGLE | theme::TOGGLE_ON => app.px(52),
                            theme::LINK => 0,
                            _ => app.px(12),
                        };
                        let need = measure(child, font, &text, 0, 0x20).right + pad; // DT_SINGLELINE
                        if need > r.right {
                            failures.push(format!(
                                "{language} {name}: button needs {need}px, has {}px: {text:?}",
                                r.right
                            ));
                        }
                        continue;
                    } else {
                        continue;
                    }
                }
                // Every one-line message in the status line.
                if name == "vault-empty" {
                    let status = app.handle(STATUS);
                    let font = SendMessageW(status, 0x31, 0, 0);
                    let mut r = Rect::default();
                    GetClientRect(status, &mut r);
                    for (ko, _) in english_table() {
                        let text = tr(ko);
                        if text.contains('\n') {
                            continue;
                        }
                        let need = measure(status, font, text, r.right, 0x10 | 0x40).bottom;
                        if need > r.bottom {
                            failures.push(format!(
                                "{language} status: needs {need}px, has {}px: {text:?}",
                                r.bottom
                            ));
                        }
                    }
                    // Sync notices filled with their longest values, and the
                    // recovery lines with the longest temp file name. A notice
                    // in two status lines fits line by line, as the other
                    // multi-line texts do.
                    // Each security-key flow's whole status once it is
                    // done, as one text: it must fit the box.
                    #[cfg(feature = "security-key")]
                    for text in keys_ui::composed_statuses() {
                        let need = measure(status, font, &text, r.right, 0x10 | 0x40).bottom;
                        if need > r.bottom {
                            failures.push(format!(
                                "{language} composed status: needs {need}px, has {}px: {text:?}",
                                r.bottom
                            ));
                        }
                    }
                    let notices = sync_notices().into_iter().map(|n| sync_line(&n).0);
                    let recovered =
                        recovery_lines(&kept_key_recovery(), Path::new("vault.goyokey"));
                    for line in notices.chain(recovered.0) {
                        for part in line.split("\r\n") {
                            let text = tr(part);
                            let need = measure(status, font, text, r.right, 0x10 | 0x40).bottom;
                            if need > r.bottom {
                                failures.push(format!(
                                    "{language} status: needs {need}px, has {}px: {text:?}",
                                    r.bottom
                                ));
                            }
                        }
                    }
                }
            };
            unsafe { each_screen(&dir, &mut check) };
            let _ = std::fs::remove_dir_all(&dir);
        }
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    }
    /// Every field on every screen shows its outline (spec §2.29): the
    /// frames are painted after the cards under them, so the TOFU banner's
    /// code field on the vault screen's detail card has one too.
    #[test]
    fn every_field_shows_its_frame() {
        #[link(name = "gdi32")]
        unsafe extern "system" {
            fn GetPixel(dc: isize, x: i32, y: i32) -> u32;
        }
        let _korean = KoreanAfter::hold();
        let dir = test_dir("frames");
        let mut seen = vec![];
        let mut check = |app: &mut App, name: &str| unsafe {
            let screen = GetDC(app.hwnd);
            let dc = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, 1600, 1400);
            ReleaseDC(app.hwnd, screen);
            let old = SelectObject(dc, bmp);
            let p = theme::palette();
            let all = Rect {
                left: 0,
                top: 0,
                right: 1600,
                bottom: 1400,
            };
            theme::fill(dc, &all, p.bg);
            app.draw_screen(dc);
            for (frame, _) in &app.frames {
                let r = app.scaled(frame);
                let x = (r.left + r.right) / 2;
                let outlined = (0..2).any(|dy| {
                    let c = GetPixel(dc, x, r.top + dy);
                    c == p.border || c == p.focus
                });
                assert!(
                    outlined,
                    "{name}: a field at {:?} has no outline",
                    frame.top
                );
            }
            seen.push(name.to_owned());
            SelectObject(dc, old);
            DeleteObject(bmp);
            DeleteDC(dc);
        };
        unsafe { each_screen(&dir, &mut check) };
        #[cfg(feature = "security-key")]
        assert!(seen.iter().any(|n| n == "vault-tofu"));
        assert!(seen.iter().any(|n| n == "login"));
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The source files whose Korean literals english_is_complete checks,
    /// by their path under src/ (spec §9.3).
    const SCANNED: [(&str, &str); 17] = [
        ("main.rs", include_str!("main.rs")),
        ("otp.rs", include_str!("otp.rs")),
        ("qr.rs", include_str!("qr.rs")),
        ("win.rs", include_str!("win.rs")),
        ("theme.rs", include_str!("theme.rs")),
        ("vault.rs", include_str!("vault.rs")),
        ("vault/keyfile.rs", include_str!("vault/keyfile.rs")),
        ("vault/recover.rs", include_str!("vault/recover.rs")),
        ("vault/anchor.rs", include_str!("vault/anchor.rs")),
        ("vault/rotate.rs", include_str!("vault/rotate.rs")),
        (
            "vault/rotate/adopt.rs",
            include_str!("vault/rotate/adopt.rs"),
        ),
        ("vault/sync.rs", include_str!("vault/sync.rs")),
        ("merge.rs", include_str!("merge.rs")),
        ("crypto.rs", include_str!("crypto.rs")),
        ("clock.rs", include_str!("clock.rs")),
        // goyo-sync's settings window draws with this app's i18n.rs.
        ("bin/goyo-sync/gui.rs", include_str!("bin/goyo-sync/gui.rs")),
        // And its background helper's tray icon.
        (
            "bin/goyo-sync/tray.rs",
            include_str!("bin/goyo-sync/tray.rs"),
        ),
    ];
    /// The security-key build's own source files with Korean literals: their
    /// English is in EN_SK, which only that build compiles, so only that
    /// build checks it; every build checks that each is listed (spec §9.3).
    const SCANNED_SK: [&str; 8] = [
        "fido.rs",
        "keys_ui.rs",
        "vault/gate.rs",
        "vault/keyfile/inbox.rs",
        "vault/keysync.rs",
        "vault/rotate/hw.rs",
        "vault/serverkey.rs",
        // goyo-sync's window draws with this app's i18n.rs.
        "bin/goyo-sync/keys_gui.rs",
    ];
    #[cfg(feature = "security-key")]
    const SOURCES_SK: [&str; 8] = [
        include_str!("fido.rs"),
        include_str!("keys_ui.rs"),
        include_str!("vault/gate.rs"),
        include_str!("vault/keyfile/inbox.rs"),
        include_str!("vault/keysync.rs"),
        include_str!("vault/rotate/hw.rs"),
        include_str!("vault/serverkey.rs"),
        include_str!("bin/goyo-sync/keys_gui.rs"),
    ];
    /// The texts english_is_complete checks with their English: EN, and in
    /// the security-key build EN_SK too.
    fn english_table() -> Vec<(&'static str, &'static str)> {
        let table = i18n::EN.iter().copied();
        #[cfg(feature = "security-key")]
        let table = table.chain(i18n::EN_SK.iter().copied());
        table.collect()
    }
    /// The sources english_is_complete scans in this build.
    fn scanned_sources() -> Vec<&'static str> {
        let sources = SCANNED.iter().map(|(_, source)| *source);
        #[cfg(feature = "security-key")]
        let sources = sources.chain(SOURCES_SK);
        sources.collect()
    }
    /// Files with Korean literals that english_is_complete does not check.
    const NOT_SCANNED: [&str; 4] = [
        // The table itself.
        "i18n.rs",
        // goyo-sync's command-line messages carry their English beside them.
        "bin/goyo-sync/msg.rs",
        // goyo-sync's tests: test modules as a whole.
        "bin/goyo-sync/tests.rs",
        "bin/goyo-sync/e2e.rs",
    ];
    /// Every source file with a Korean literal outside its tests is checked
    /// for its English or exempt for a reason, so a new module cannot slip
    /// past (spec §9.3).
    #[test]
    fn every_source_file_with_korean_text_is_scanned() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![root.clone()];
        let mut found = vec![];
        while let Some(path) = files.pop() {
            if path.is_dir() {
                files.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let name = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(&path).unwrap();
            if !korean_literals(outside_tests(&source)).is_empty() {
                found.push(name);
            }
        }
        for name in &found {
            assert!(
                SCANNED.iter().any(|(n, _)| n == name)
                    || SCANNED_SK.contains(&name.as_str())
                    || NOT_SCANNED.contains(&name.as_str()),
                "{name} has Korean text that english_is_complete does not check"
            );
        }
        // Each listed name is the file whose text is scanned: a name listed
        // with another file's text (or none) would pass both checks.
        let text = |name: &str| std::fs::read_to_string(root.join(name)).unwrap();
        for (name, source) in SCANNED {
            assert_eq!(text(name), source, "{name}: SCANNED holds another file");
        }
        #[cfg(feature = "security-key")]
        for (name, source) in SCANNED_SK.iter().zip(SOURCES_SK) {
            assert_eq!(text(name), source, "{name}: SOURCES_SK is not SCANNED_SK");
        }
        assert!(found.iter().any(|n| n == "vault/anchor.rs"));
        assert!(found.iter().any(|n| n == "vault/keyfile/inbox.rs"));
    }
    /// A source file up to its test module (`mod tests` or
    /// `pub(crate) mod tests` under `#[cfg(test)]`): a test-only item among
    /// the program's own (ANSWER here, PAINTED in theme.rs) must not end it.
    fn outside_tests(source: &str) -> &str {
        source
            .match_indices("#[cfg(test)]\n")
            .find(|(i, m)| {
                source[i + m.len()..]
                    .lines()
                    .next()
                    .is_some_and(|l| l.trim_start_matches("pub(crate) ").starts_with("mod "))
            })
            .map_or(source, |(i, _)| &source[..i])
    }
    /// Korean string literals in a source file, outside tests and comments.
    fn korean_literals(source: &str) -> Vec<String> {
        let mut out = vec![];
        let mut it = source.chars().peekable();
        while let Some(c) = it.next() {
            match c {
                '/' if it.peek() == Some(&'/') => {
                    for c in it.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                // A char literal ('"', '\'') or a lifetime.
                '\'' => {
                    let mut look = it.clone();
                    match look.next() {
                        Some('\\') => {
                            it.next();
                            for c in it.by_ref() {
                                if c == '\'' {
                                    break;
                                }
                            }
                        }
                        Some(_) if look.next() == Some('\'') => {
                            it.next();
                            it.next();
                        }
                        _ => {}
                    }
                }
                '"' => {
                    let mut s = String::new();
                    while let Some(c) = it.next() {
                        match c {
                            '"' => break,
                            '\\' => match it.next() {
                                Some('n') => s.push('\n'),
                                Some('r') => s.push('\r'),
                                Some('t') => s.push('\t'),
                                Some('0') => s.push('\0'),
                                Some('u') => {
                                    it.next(); // {
                                    let hex: String =
                                        it.by_ref().take_while(|c| *c != '}').collect();
                                    s.push(
                                        char::from_u32(u32::from_str_radix(&hex, 16).unwrap())
                                            .unwrap(),
                                    );
                                }
                                Some('\n') => {
                                    while it.peek().is_some_and(|c| c.is_whitespace()) {
                                        it.next();
                                    }
                                }
                                Some(c) => s.push(c),
                                None => {}
                            },
                            c => s.push(c),
                        }
                    }
                    if has_korean(&s) {
                        out.push(s);
                    }
                }
                _ => {}
            }
        }
        out
    }
    /// Every Korean text in the program has an English entry, and in English
    /// no screen shows Korean, whether in a control or painted.
    #[test]
    fn english_is_complete() {
        let _korean = KoreanAfter::hold();
        let (mut missing, mut scanned) = (vec![], vec![]);
        let table = english_table();
        for source in scanned_sources() {
            for text in korean_literals(outside_tests(source)) {
                if !table.iter().any(|(ko, _)| *ko == text) && !i18n::KEEP.contains(&text.as_str())
                {
                    missing.push(text.clone());
                }
                scanned.push(text);
            }
        }
        assert!(
            missing.is_empty(),
            "no English for:\n{}",
            missing.join("\n")
        );
        // The scan of this file reached main(), the end of its program code.
        assert!(
            scanned
                .iter()
                .any(|text| text == "자동 잠금 타이머를 시작할 수 없어 종료합니다.")
        );
        // And the scan of gui.rs reached run(), near the end of its code.
        assert!(
            scanned
                .iter()
                .any(|text| text == "화면을 만들 수 없어 종료합니다.")
        );
        for (ko, en) in &table {
            assert!(!has_korean(en), "untranslated: {ko:?}");
        }
        i18n::set_english(true);
        let dir = test_dir("english");
        let mut shown = vec![];
        let mut visit = |app: &mut App, name: &str| unsafe {
            for &child in &app.children {
                if matches!(class_of(child).as_str(), "Static" | "Button") {
                    shown.push((name.to_owned(), caption(child)));
                }
            }
            for text in painted(app) {
                shown.push((name.to_owned(), text));
            }
        };
        unsafe { each_screen(&dir, &mut visit) };
        let _ = std::fs::remove_dir_all(&dir);
        let korean: Vec<_> = shown
            .iter()
            .filter(|(_, text)| has_korean(text) && !i18n::KEEP.contains(&text.as_str()))
            .map(|(screen, text)| format!("{screen}: {text:?}"))
            .collect();
        assert!(
            korean.is_empty(),
            "Korean in English mode:\n{}",
            korean.join("\n")
        );
        // The painted chip of a built-in type follows the language too.
        assert!(
            shown
                .iter()
                .any(|(s, t)| s == "vault-shown" && t == "Seed phrase")
        );
        // So does the sync word on the pill, before the file name.
        assert!(
            shown
                .iter()
                .any(|(s, t)| s == "vault-sync" && t == "Open · Synced · vault.goyo")
        );
        // Sync notices are filled from their English templates, line by
        // line.
        for notice in sync_notices() {
            let (line, _) = sync_line(&notice);
            let text = tr_lines(&line);
            assert!(!has_korean(&text), "Korean in English mode: {text:?}");
        }
        // So are the lines on what an unlock took back from temp files.
        let (lines, _) = recovery_lines(&kept_key_recovery(), Path::new("vault.goyokey"));
        assert_eq!(lines.len(), 2);
        for line in lines {
            let text = tr(&line);
            assert!(!has_korean(text), "Korean in English mode: {text:?}");
        }
    }
    /// Both recoveries, with the longest temp file name atomic_write gives.
    fn kept_key_recovery() -> Recovery {
        Recovery {
            vault: true,
            key_kept: Some(PathBuf::from(format!(
                "vault.goyokey.{:032x}.goyotmp",
                u128::MAX
            ))),
        }
    }
    /// Switching the language keeps what was typed and the screen's state.
    #[test]
    fn language_switch_keeps_input() {
        let _korean = KoreanAfter::hold();
        let dir = test_dir("switch");
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.home_dir = dir.clone();
            app.vault_path = dir.join("vault.goyo");
            app.key_path = dir.join("vault.goyokey");
            app.screen = app.home();
            app.build();
            app.command(CREATE, 0).unwrap();
            let tag = app.provision.as_ref().unwrap().tag();
            SetWindowTextW(app.handle(PASS), wide("synthetic switch password").as_ptr());
            app.command(LANG_EN, 0).unwrap();
            assert!(i18n::english() && app.screen == Screen::Create);
            assert_eq!(caption(app.handle(SUBMIT)), "Create vault");
            assert_eq!(&*app.read(PASS).unwrap(), "synthetic switch password");
            assert_eq!(app.provision.as_ref().unwrap().tag(), tag);
            assert_eq!(GetWindowLongPtrW(app.handle(LANG_EN), -21), theme::TAB_ON);
            // The status line follows the language; its Korean source is kept.
            app.status("수동으로 잠갔습니다.");
            assert_eq!(caption(app.handle(STATUS)), "Locked.");
            app.command(LANG_KO, 0).unwrap();
            assert!(!i18n::english());
            assert_eq!(caption(app.handle(STATUS)), "수동으로 잠갔습니다.");
            assert_eq!(&*app.read(PASS).unwrap(), "synthetic switch password");
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// Synthetic vault on disk, open.
    fn synthetic_session(dir: &std::path::Path, password: &str) -> Session {
        Provision::new()
            .unwrap()
            .finish(
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                password,
            )
            .unwrap()
    }
    /// The 15-second view of a mnemonic (the built-in kind "니모닉") paints
    /// its words one by one after their numbers, 24 a page with [‹] [›] for
    /// more; the same words under another kind stay running text; nothing
    /// of either is put into a control, and the view ends after 15 s.
    #[test]
    fn a_revealed_mnemonic_paints_its_numbered_words() {
        let _korean = KoreanAfter::hold();
        i18n::set_english(false);
        let dir = test_dir("mnemonic-grid");
        let mut session = synthetic_session(&dir, "synthetic grid password");
        let words: Vec<String> = (1..=30).map(|i| format!("w{i:02}x")).collect();
        let mnemonic = |n: usize| words[..n].join(" ");
        for (kind, secret) in [
            ("니모닉", mnemonic(24)),
            ("비밀번호", mnemonic(24)),
            ("니모닉", mnemonic(30)),
        ] {
            let entry = Entry::new("t".into(), kind.into(), secret, String::new()).unwrap();
            session.put(None, entry).unwrap();
        }
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.session = Some(session);
            app.screen = Screen::Vault;
            app.build();
            let shown = |app: &mut App, i: usize| -> Vec<String> {
                app.selected = Some(i);
                app.page = 0;
                app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
                app.sync_detail();
                painted(app)
            };
            // 24 words: each word alone, after its number; one page.
            let texts = shown(&mut app, 0);
            for (i, w) in words[..24].iter().enumerate() {
                assert!(texts.contains(w), "{w}");
                assert!(texts.contains(&(i + 1).to_string()), "{i}");
            }
            assert!(!texts.iter().any(|t| t.contains("w01x w02x")));
            assert_eq!(GetWindowLongPtrW(app.handle(NEXT), -16) & 0x1000_0000, 0);
            // No control holds a word.
            for c in &app.children {
                assert!(!caption(*c).contains("w01x"), "{}", caption(*c));
            }
            // Another kind: the running text.
            let texts = shown(&mut app, 1);
            assert!(texts.iter().any(|t| t.starts_with("w01x w02x")));
            assert!(!texts.contains(&"w01x".to_owned()));
            // 30 words: 24 on the first page, 25-30 on the next, numbered on.
            let texts = shown(&mut app, 2);
            assert!(texts.contains(&"w24x".to_owned()) && !texts.contains(&"w25x".to_owned()));
            assert!(texts.contains(&"1 / 2 페이지".to_owned()));
            assert_ne!(GetWindowLongPtrW(app.handle(NEXT), -16) & 0x1000_0000, 0);
            app.command(NEXT, 0).unwrap();
            let texts = painted(&app);
            assert!(texts.contains(&"w25x".to_owned()) && texts.contains(&"25".to_owned()));
            assert!(texts.contains(&"w30x".to_owned()) && !texts.contains(&"w24x".to_owned()));
            assert!(texts.contains(&"2 / 2 페이지".to_owned()));
            app.command(NEXT, 0).unwrap();
            assert_eq!(app.page, 1);
            // The view ends after 15 s: no word painted.
            app.reveal_until = Some(Instant::now() - Duration::from_secs(1));
            app.timer();
            assert!(app.reveal_until.is_none());
            assert!(!painted(&app).iter().any(|t| t.starts_with('w')));
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    const SYNC_PASSWORD: &str = "synthetic sync password";
    fn sync_entry(title: &str, secret: &str) -> Entry {
        Entry::new(title.into(), "kind".into(), secret.into(), String::new()).unwrap()
    }
    /// What goyo-sync and the server do, for the sync tests, without ssh:
    /// numbered copies of the uploads, the newest handed back as incoming.
    #[derive(Default)]
    struct Server {
        versions: Vec<Vec<u8>>,
    }
    impl Server {
        /// The helper's first run next to `vault`: its folder and a fresh
        /// status saying all is well.
        fn helper(&self, vault: &Path) {
            let dir = syncfile::sync_dir(vault).unwrap();
            std::fs::create_dir(&dir).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let status = syncfile::render_status(now, now, syncfile::SyncState::Ok);
            syncfile::replace_file(&dir.join(syncfile::STATUS), &status).unwrap();
        }
        /// One helper pass for `vault`: an upload made from the newest
        /// version becomes the next one (any other lost the race), and the
        /// newest goes to the incoming file if it is not there yet.
        fn pass(&mut self, vault: &Path) {
            let dir = syncfile::sync_dir(vault).unwrap();
            if let Ok(bytes) = std::fs::read(dir.join(syncfile::OUTGOING)) {
                let (base, blob) = syncfile::parse_outgoing(&bytes).unwrap();
                if base == self.versions.len() as u64 {
                    self.versions.push(blob.to_vec());
                }
            }
            let Some(head) = self.versions.last() else {
                return;
            };
            let incoming = syncfile::render_incoming(self.versions.len() as u64, head).unwrap();
            let path = dir.join(syncfile::INCOMING);
            if std::fs::read(&path).ok().as_ref() != Some(&incoming) {
                syncfile::replace_file(&path, &incoming).unwrap();
            }
        }
    }
    /// A helper pass for `s`, whose app then looks at what it brought.
    fn upload(server: &mut Server, s: &mut Session) {
        server.pass(&s.path);
        s.poll_sync();
    }
    /// PC A turns sync on for a vault holding `titles` and uploads it as
    /// version 1. PC B gets the key and that version (by USB and `goyo-sync
    /// --fetch`, then Restore) next to its own helper's folder, which already
    /// holds version 1 as incoming. Returns A's session and B's vault and key.
    fn two_pcs(dir: &Path, server: &mut Server, titles: &[&str]) -> (Session, PathBuf, PathBuf) {
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let mut sa = Provision::new()
            .unwrap()
            .finish(
                &a.join("vault.goyo"),
                &a.join("vault.goyokey"),
                SYNC_PASSWORD,
            )
            .unwrap();
        for title in titles {
            sa.put(None, sync_entry(title, "secret")).unwrap();
        }
        server.helper(&sa.path);
        sa.enable_sync().unwrap();
        upload(server, &mut sa);
        assert_eq!(sa.badge(), Some(SyncBadge::Synced));
        let (vault, key) = (b.join("vault.goyo"), b.join("vault.goyokey"));
        std::fs::copy(&sa.key_path, &key).unwrap();
        let fetched = b.join("from-server.goyo");
        std::fs::write(&fetched, &server.versions[0]).unwrap();
        drop(Session::restore(&fetched, &key, &vault, SYNC_PASSWORD).unwrap());
        server.helper(&vault);
        server.pass(&vault);
        (sa, vault, key)
    }
    /// A mass delete may be a key holder deleting through the server, so it
    /// is told in the danger tone. Status lines, joined or translated, are
    /// built in buffers of their final size in both languages, so no grown
    /// buffer frees an unwiped copy.
    #[test]
    fn sync_lines_and_status_buffers() {
        let _korean = KoreanAfter::hold();
        let mass = SyncNotice::MassDelete {
            removed: 5,
            file: r"vault.goyo.sync\pre-merge-1792000000.goyo".into(),
        };
        assert_eq!(sync_line(&mass).1, TONE_DANGER);
        let merged = SyncNotice::Merged {
            added: 1,
            removed: 1,
        };
        assert_eq!(sync_line(&merged).1, TONE_MUTED);
        // The key notices of spec v3 §7.4 are all in the danger tone, and a
        // copy under a key this PC does not hold may be forged (§14.6-9).
        let all = sync_notices();
        let at = all
            .iter()
            .position(|n| *n == SyncNotice::KeyChanged { hardware: false })
            .unwrap();
        for notice in &all[at..at + 7] {
            assert_eq!(sync_line(notice).1, TONE_DANGER, "{notice:?}");
        }
        let changed = sync_line(&SyncNotice::KeyChanged { hardware: false }).0;
        assert!(changed.contains("서버 사본이 위조되었을 수 있습니다"));
        for english in [false, true] {
            i18n::set_english(english);
            // S-OVERRIDE-HEAD, a two-line template, fills in both languages.
            let head = fill(vault::OVERRIDE_HEAD, &[&2, &"0A1B2C3D", &7]);
            assert_eq!(head.split("\r\n").count(), 2);
            assert_eq!(has_korean(&head), !english);
            assert!(head.contains("0A1B2C3D") && !head.contains('{'));
            for notice in sync_notices() {
                let (line, _) = sync_line(&notice);
                for warning in [Placement::SameFolder, Placement::Cloud] {
                    let both = joined(&[&line, warning.message()]);
                    assert_eq!(both.capacity(), both.len());
                    let shown = tr_lines(&both);
                    assert_eq!(shown.capacity(), shown.len());
                    assert_eq!(shown.split("\r\n").last(), Some(tr(warning.message())));
                }
            }
        }
    }
    /// The security-key build's notice of a vault copy under another PC's
    /// new key written under key-file sync (spec §2.30, the wrong-notice
    /// fix): it points to [받기…] and the next unlock, never to this build
    /// lacking security-key support or to a USB copy.
    #[cfg(feature = "security-key")]
    #[test]
    fn a_key_change_through_the_server_is_not_told_as_unsupported() {
        let _korean = KoreanAfter::hold();
        let (text, tone) = sync_line(&SyncNotice::KeyChangedServer);
        let text: &str = &text;
        assert_eq!(tone, TONE_DANGER);
        assert!(
            text.contains("[받기…]") && text.contains("다음 잠금 해제"),
            "{text}"
        );
        let unsupported = sync_line(&SyncNotice::KeyChanged { hardware: true }).0;
        assert_ne!(text, unsupported.as_str());
        assert!(
            !text.contains("지원하지 않아") && !text.contains("USB"),
            "{text}"
        );
        // On a PC without keys: the Keys screen's button, never [받기…],
        // the next unlock or USB.
        let (text, tone) = sync_line(&SyncNotice::KeyChangedServerPwOnly);
        let text: &str = &text;
        assert_eq!(tone, TONE_DANGER);
        assert!(text.contains(keys_ui::SERVER_TAKE_BUTTON), "{text}");
        assert!(
            !text.contains("[받기…]")
                && !text.contains("다음 잠금 해제")
                && !text.contains("USB")
                && !text.contains("지원하지 않아"),
            "{text}"
        );
    }
    /// Every sync notice, with values as long as they get.
    fn sync_notices() -> Vec<SyncNotice> {
        vec![
            SyncNotice::SyncOn,
            SyncNotice::Merged {
                added: 1000,
                removed: 1000,
            },
            SyncNotice::Conflicts(1000),
            // Losses since the last copy: at most 4 before the merge that
            // made it, plus that merge's.
            SyncNotice::MassDelete {
                removed: 1004,
                file: r"vault-2.goyo.sync\pre-merge-1792000000.goyo".into(),
            },
            SyncNotice::Rollback,
            SyncNotice::BadIncoming,
            SyncNotice::TooLarge,
            SyncNotice::NewerFormat,
            SyncNotice::KeyInFolder,
            SyncNotice::Synced {
                code: "DDDD-DDDD-DDDD-DDDD".into(),
            },
            SyncNotice::HelperOff,
            SyncNotice::Offline,
            SyncNotice::HostKey,
            SyncNotice::Auth,
            SyncNotice::HelperError,
            SyncNotice::OldServer,
            SyncNotice::KeyBehind,
            SyncNotice::KeyChanged { hardware: false },
            SyncNotice::KeyChanged { hardware: true },
            SyncNotice::KeyFork,
            SyncNotice::OldKeyDamaged,
            SyncNotice::RollbackHeld,
            SyncNotice::NewerKeyFile,
            SyncNotice::OldKeyReplaced,
            #[cfg(feature = "security-key")]
            SyncNotice::KeyRollback,
            #[cfg(feature = "security-key")]
            SyncNotice::KeyFileRefused("수정 번호가 너무 큼"),
            #[cfg(feature = "security-key")]
            SyncNotice::BadKeyIncoming,
            #[cfg(feature = "security-key")]
            SyncNotice::GatePending,
            #[cfg(feature = "security-key")]
            SyncNotice::KeySyncGone,
            #[cfg(feature = "security-key")]
            SyncNotice::KeyFileReady {
                epoch: (1 << 48) - 1,
            },
            #[cfg(feature = "security-key")]
            SyncNotice::NoKeySync,
            #[cfg(feature = "security-key")]
            SyncNotice::KeyUpRefused,
            #[cfg(feature = "security-key")]
            SyncNotice::KeySyncHelper,
            #[cfg(feature = "security-key")]
            SyncNotice::KeySyncDeleted {
                seq: (1 << 48) - 1,
                admin: true,
            },
            #[cfg(feature = "security-key")]
            SyncNotice::KeyForkMerge { auto: true },
            #[cfg(feature = "security-key")]
            SyncNotice::KeyForkMerge { auto: false },
            #[cfg(feature = "security-key")]
            SyncNotice::KeyChangedServer,
            #[cfg(feature = "security-key")]
            SyncNotice::KeyChangedServerPwOnly,
        ]
    }
    /// Turns the GOYOKE02 key file at `key` into the GOYOKE01 that a vault
    /// made with the removed OTP has: the same data key, sealed under the
    /// same password with a TOTP secret after it.
    fn old_otp_key_file(key: &std::path::Path, password: &str) {
        let bytes = std::fs::read(key).unwrap();
        assert_eq!((&bytes[..8], bytes.len()), (&b"GOYOKE02"[..], 128));
        let salt: [u8; 32] = bytes[24..56].try_into().unwrap();
        let nonce: [u8; 24] = bytes[56..80].try_into().unwrap();
        let wrapping = crypto::derive(password.as_bytes(), &salt).unwrap();
        let data_key = crypto::open(&wrapping, &nonce, &bytes[..80], &bytes[80..]).unwrap();
        let nonce = crypto::random::<24>().unwrap();
        let mut header = b"GOYOKE01".to_vec();
        header.extend_from_slice(&bytes[8..56]);
        header.extend_from_slice(nonce.as_slice());
        let plain = [&data_key[..], &[0x5c; 20]].concat();
        let body = crypto::seal(&wrapping, &nonce, &header, &plain).unwrap();
        std::fs::write(key, [header, body].concat()).unwrap();
    }
    /// Create asks for the password twice and nothing else; the vault opens
    /// with the password and key file alone, also on the Keys and password
    /// screens. A vault made with the removed OTP (GOYOKE01), typed in by
    /// path, opens with the password alone too, and says once on this PC
    /// that the OTP is gone; its files stay byte for byte.
    #[test]
    fn create_and_open_ask_for_no_code_and_an_old_otp_vault_says_so_once() {
        let _korean = KoreanAfter::hold();
        i18n::set_english(false);
        let dir = test_dir("no-otp");
        let pass = "synthetic no otp passphrase";
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.home_dir = dir.clone();
            app.vault_path = dir.join("vault.goyo");
            app.key_path = dir.join("vault.goyokey");
            app.screen = app.home();
            app.build();
            app.command(CREATE, 0).unwrap();
            assert!(app.screen == Screen::Create);
            assert_eq!(caption(app.handle(SUBMIT)), "금고 만들기");
            for id in [PASS, CONFIRM] {
                SetWindowTextW(app.handle(id), wide(pass).as_ptr());
            }
            app.command(SUBMIT, 0).unwrap();
            assert!(app.screen == Screen::Vault);
            let made = app.session.as_ref().unwrap();
            assert_eq!(std::fs::read(&made.key_path).unwrap().len(), 128);
            assert!(!caption(app.handle(STATUS)).contains("OTP"));
            app.command(CHANGE, 0).unwrap();
            assert!(app.screen == Screen::Keys);
            app.command(KEY_PASSWORD, 0).unwrap();
            assert!(app.screen == Screen::Password);
            app.command(CANCEL, 0).unwrap();
            app.command(2, 0).unwrap();
            assert!(app.screen == Screen::Vault);
            // Opens again with the password alone.
            app.lock("synthetic lock", true);
            assert!(app.screen == Screen::Login);
            SetWindowTextW(app.handle(PASS), wide(pass).as_ptr());
            app.command(SUBMIT, 0).unwrap();
            assert!(app.session.is_some());
            app.lock("synthetic lock", true);
            // A vault made with the removed OTP, chosen by typing its paths.
            let other = dir.join("otp");
            std::fs::create_dir(&other).unwrap();
            drop(synthetic_session(&other, pass));
            let (old_vault, old_key) = (other.join("vault.goyo"), other.join("vault.goyokey"));
            old_otp_key_file(&old_key, pass);
            let files = (
                std::fs::read(&old_vault).unwrap(),
                std::fs::read(&old_key).unwrap(),
            );
            let open = |app: &mut App| {
                SetWindowTextW(
                    app.handle(VPATH),
                    wide(&old_vault.to_string_lossy()).as_ptr(),
                );
                SetWindowTextW(app.handle(KPATH), wide(&old_key.to_string_lossy()).as_ptr());
                SetWindowTextW(app.handle(PASS), wide(pass).as_ptr());
                app.command(SUBMIT, 0).unwrap();
                assert!(app.session.is_some() && app.failed == 0);
                caption(app.handle(STATUS))
            };
            let first = open(&mut app);
            assert!(first.contains(tr(vault::OTP_REMOVED)), "{first}");
            app.lock("synthetic lock", true);
            let second = open(&mut app);
            assert!(!second.contains("OTP"), "{second}");
            app.lock("synthetic lock", true);
            assert_eq!(
                (
                    std::fs::read(&old_vault).unwrap(),
                    std::fs::read(&old_key).unwrap()
                ),
                files
            );
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// Another app in front: the 15-second view and copy permission end at
    /// once and the vault stays open; it locks after AWAY_LOCK away, and an
    /// activation message alone does not cancel that.
    #[test]
    fn away_from_the_app_ends_the_view_and_locks_later() {
        let dir = test_dir("away");
        let session = synthetic_session(&dir, "synthetic away password");
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            // Stands in for another app. build() focuses a control, which can
            // bring the test window to the front, so leave it before a check
            // (as in auto_lock_choices).
            #[link(name = "user32")]
            unsafe extern "system" {
                fn SetForegroundWindow(h: Hwnd) -> i32;
            }
            let other = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            let mut app = App::new(h);
            app.vault_path = session.path.clone();
            app.session = Some(session);
            app.screen = Screen::Vault;
            app.build();
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.copy_until = Some(Instant::now() + Duration::from_secs(30));
            app.deactivated();
            assert!(app.session.is_some() && app.screen == Screen::Vault);
            assert!(app.reveal_until.is_none() && app.copy_until.is_none());
            // Back within AWAY_LOCK: still open.
            SetForegroundWindow(other);
            assert!(!is_foreground(h));
            app.away_since = Some(Instant::now() - Duration::from_secs(20));
            app.activated();
            // Not actually in front: an activation message alone (which another
            // program could fake) does not cancel the away lock.
            assert!(app.away_since.is_some());
            app.timer();
            assert!(app.session.is_some());
            // Away longer than AWAY_LOCK: locked.
            app.deactivated();
            app.away_since = Some(Instant::now() - AWAY_LOCK - Duration::from_secs(1));
            SetForegroundWindow(other);
            app.timer();
            assert!(app.session.is_none() && app.away_since.is_none());
            assert!(app.screen == Screen::Login);
            drop(app);
            DestroyWindow(h);
            DestroyWindow(other);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The auto-lock switch on the vault screen. Longer choices count time in
    /// another app as unused time; "끔" keeps the vault open on the timer.
    #[test]
    fn auto_lock_choices() {
        assert_eq!(auto_lock_choice(b"5\r\n"), 1);
        assert_eq!(auto_lock_choice(b"off"), 3);
        assert_eq!(auto_lock_choice(b"never"), 0);
        let dir = test_dir("auto-lock");
        std::fs::create_dir(dir.join("b")).unwrap();
        let pass = "synthetic auto-lock password";
        let sessions = [
            synthetic_session(&dir, pass),
            synthetic_session(&dir.join("b"), pass),
        ];
        #[link(name = "user32")]
        unsafe extern "system" {
            fn SetForegroundWindow(h: Hwnd) -> i32;
        }
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            // Stands in for another app. build() focuses a control, which can
            // bring the test window to the front, so leave it before a check.
            let other = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            let leave = |app: &mut App, away: Duration| {
                SetForegroundWindow(other);
                assert!(!is_foreground(h));
                app.deactivated();
                app.away_since = Some(Instant::now() - away);
            };
            let mut app = App::new(h);
            app.vault_path = dir.join("missing.goyo");
            app.screen = app.home();
            app.build();
            assert!(app.command(AUTO_LOCK + 3, 0).is_err()); // only with a vault open
            assert_eq!(app.auto_lock, 0);
            let [first, second] = sessions;
            app.session = Some(first);
            app.screen = Screen::Vault;
            app.build();
            let variant = |app: &App, i: i32| GetWindowLongPtrW(app.handle(AUTO_LOCK + i), -21);
            assert_eq!(variant(&app, 0), theme::TAB_ON);
            app.command(AUTO_LOCK + 1, 0).unwrap();
            assert_eq!(app.auto_lock, 1);
            assert_eq!(variant(&app, 0), theme::TAB);
            assert_eq!(variant(&app, 1), theme::TAB_ON);
            assert_eq!(*app.status, AUTO_LOCKS[1].2);
            // Five minutes: 31 s in another app no longer locks; five minutes do.
            leave(&mut app, AWAY_LOCK + Duration::from_secs(1));
            app.timer();
            assert!(app.session.is_some());
            app.away_since = Some(Instant::now() - Duration::from_secs(301));
            app.timer();
            assert!(app.session.is_none());
            assert_eq!(*app.status, "미사용 시간이 지나 자동으로 잠갔습니다.");
            // Off: an hour unused and away keeps the vault open.
            app.session = Some(second);
            app.screen = Screen::Vault;
            app.build();
            app.command(AUTO_LOCK + 3, 0).unwrap();
            leave(&mut app, Duration::from_secs(3600));
            app.activity = Instant::now() - Duration::from_secs(3600);
            app.timer();
            assert!(app.session.is_some() && app.screen == Screen::Vault);
            drop(app);
            DestroyWindow(other);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn native_control_protection_layout_and_expiry() {
        // Own hidden test window, synthetic strings only; no real vault or
        // system clipboard contents are read or changed by this test.
        unsafe {
            SetProcessDPIAware();
            let scale = GetDpiForSystem() as f32 / 96.0;
            let h = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                wide("Goyo unit-test window").as_ptr(),
                0x00ca0000,
                0,
                0,
                (890.0 * scale) as i32,
                (795.0 * scale) as i32,
                0,
                0,
                GetModuleHandleW(null()),
                null_mut(),
            );
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            assert!(check_environment(h).is_ok());
            let mut app = App::new(h);
            // Any existing file stands in for a vault, so Login is the home screen.
            app.vault_path = std::env::current_exe().unwrap();
            app.build();
            SetWindowTextW(app.handle(PASS), wide("synthetic password only").as_ptr());
            assert_eq!(&*app.read(PASS).unwrap(), "synthetic password only");
            assert_eq!(GetWindowTextLengthW(app.handle(PASS)), 0); // external getter blocked
            assert_eq!(SendMessageW(app.handle(PASS), 0x301, 0, 0), 0); // copy blocked
            let mask = SendMessageW(app.handle(PASS), 0xd2, 0, 0);
            assert_ne!(mask, 0);
            SendMessageW(app.handle(PASS), 0xcc, 0, 0);
            assert_eq!(SendMessageW(app.handle(PASS), 0xd2, 0, 0), mask);
            assert_eq!(SendMessageW(app.handle(PASS), 0xd0, 0, 0), 0);
            assert_eq!(SendMessageW(app.handle(PASS), 0xbc, 0, 0), 0);
            // Eye button: unmasks for the user only; the other protections stay.
            app.command(PEEK_PASS, 0).unwrap();
            assert_eq!(SendMessageW(app.handle(PASS), 0xd2, 0, 0), 0);
            assert_eq!(&*app.read(PASS).unwrap(), "synthetic password only");
            assert_eq!(GetWindowTextLengthW(app.handle(PASS)), 0);
            assert_eq!(SendMessageW(app.handle(PASS), 0x301, 0, 0), 0);
            assert_eq!(SendMessageW(app.handle(PASS), 0x3d, 0, -4), 0); // no accessibility object
            assert_eq!(ImmGetContext(app.handle(PASS)), 0);
            SendMessageW(app.handle(PASS), 0xcc, '*' as usize, 0); // still ignored
            assert_eq!(SendMessageW(app.handle(PASS), 0xd2, 0, 0), 0);
            app.command(PEEK_PASS, 0).unwrap();
            assert_eq!(SendMessageW(app.handle(PASS), 0xd2, 0, 0), mask);
            // A shown/masked state faked in the button's window data (which
            // other programs can write) does not stop re-masking.
            app.command(PEEK_PASS, 0).unwrap();
            SetWindowLongPtrW(app.handle(PEEK_PASS), -21, theme::EYE);
            app.mask_passwords();
            assert_eq!(SendMessageW(app.handle(PASS), 0xd2, 0, 0), mask);
            // Create keeps one new vault across Back and a second visit.
            app.command(CREATE, 0).unwrap();
            let tag = app.provision.as_ref().unwrap().tag();
            app.command(BACK, 0).unwrap();
            app.command(CREATE, 0).unwrap();
            assert_eq!(app.provision.as_ref().unwrap().tag(), tag);
            app.provision = None;
            app.screen = Screen::Login;
            app.build();
            SetWindowTextW(app.handle(PASS), wide("synthetic password only").as_ptr());
            app.command(PEEK_PASS, 0).unwrap(); // left shown: the lock below must mask it
            app.command(PASS, 0x300).unwrap();
            app.activity = Instant::now() - Duration::from_secs(61);
            app.timer();
            assert!(app.read(PASS).unwrap().is_empty() && !app.auth_dirty);
            assert_eq!(SendMessageW(app.handle(PASS), 0xd2, 0, 0), mask);
            // Switching apps mid-create keeps the new vault form; only the
            // shown password is masked again.
            app.screen = Screen::Create;
            app.provision = Some(Provision::new().unwrap());
            app.build();
            let tag = app.provision.as_ref().unwrap().tag();
            SetWindowTextW(app.handle(PASS), wide("synthetic enrollment").as_ptr());
            app.command(PEEK_PASS, 0).unwrap();
            app.deactivated();
            assert!(app.screen == Screen::Create);
            assert_eq!(app.provision.as_ref().unwrap().tag(), tag);
            assert_eq!(&*app.read(PASS).unwrap(), "synthetic enrollment");
            assert_eq!(SendMessageW(app.handle(PASS), 0xd2, 0, 0), mask);
            app.provision = None;
            app.screen = Screen::Login;
            app.build();
            assert!(app.command(CANCEL, 0).is_err());
            assert!(app.screen == Screen::Login);
            for value in ["W".repeat(8192), "M".repeat(400), "한글😀".repeat(100)] {
                let pages = app.pages(&value).unwrap();
                assert_eq!(
                    pages
                        .iter()
                        .flat_map(|p| p.chars().filter(|c| *c != '\n'))
                        .collect::<String>(),
                    value
                );
                let dc = GetDC(h);
                let previous = SelectObject(dc, app.font_of(|t| t.body()));
                for page in &pages {
                    assert!(page.lines().count() <= 2);
                    for line in page.lines() {
                        let wide = secret_wide(line);
                        let mut size = Size::default();
                        assert_ne!(
                            GetTextExtentPoint32W(
                                dc,
                                wide.as_ptr(),
                                wide.len() as i32 - 1,
                                &mut size
                            ),
                            0
                        );
                        assert!(size.cx <= app.px(430));
                    }
                }
                SelectObject(dc, previous);
                ReleaseDC(h, dc);
            }
            for screen in [
                Screen::Welcome,
                Screen::Login,
                Screen::Create,
                Screen::Restore,
                Screen::Vault,
                Screen::Edit,
                Screen::Password,
            ] {
                app.screen = screen;
                app.build();
                assert!(!app.input_failed);
                if screen == Screen::Edit {
                    assert_eq!(ImmGetContext(app.handle(SECRET)), 0);
                    assert_eq!(ImmGetContext(app.handle(NOTES)), 0);
                    SendMessageW(app.handle(NOTES), 0x102, '한' as usize, 0);
                    SendMessageW(app.handle(NOTES), 0x102, 'a' as usize, 0);
                    assert_eq!(&*app.read(NOTES).unwrap(), "한a");
                    let pem = "-----BEGIN KEY-----\r\nabcdef\r\n-----END KEY-----";
                    SetWindowTextW(app.handle(SECRET), secret_wide(pem).as_ptr());
                    assert_eq!(&*app.read(SECRET).unwrap(), pem);
                }
                let mut client = Rect::default();
                assert_ne!(GetClientRect(h, &mut client), 0);
                for &child in &app.children {
                    let mut rect = Rect::default();
                    assert_ne!(GetWindowRect(child, &mut rect), 0);
                    let mut pts = [
                        Point {
                            x: rect.left,
                            y: rect.top,
                        },
                        Point {
                            x: rect.right,
                            y: rect.bottom,
                        },
                    ];
                    MapWindowPoints(0, h, pts.as_mut_ptr(), 2);
                    assert!(
                        pts[0].x >= 0
                            && pts[0].y >= 0
                            && pts[1].x <= client.right
                            && pts[1].y <= client.bottom,
                        "control exceeds client rectangle"
                    );
                }
            }
            app.screen = Screen::Vault;
            app.build();
            assert!(app.command(REVEAL, 0).is_err()); // No session: fail closed.
            // Reentrant modal command while app state is borrowed is ignored.
            APP.with(|cell| {
                let _borrow = cell.borrow_mut();
                assert_eq!(window_proc(h, 0x111, BACKUP as usize, 0), 0);
            });
            assert!(app.command(COPY, 0).is_err());
            app.copy_until = Some(Instant::now() - Duration::from_secs(1));
            app.reveal_until = app.copy_until;
            app.timer();
            assert!(app.copy_until.is_none() && app.reveal_until.is_none());
            app.lock("test lock", true);
            assert!(app.read(PASS).unwrap().is_empty());
            assert!(app.session.is_none() && app.provision.is_none());
            SetWindowTextW(
                app.handle(PASS),
                wide("synthetic pending-event password").as_ptr(),
            );
            app.auth_dirty = true;
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            APP.with(|cell| {
                let _borrow = cell.borrow_mut();
                assert_eq!(window_proc(h, 0x2b1, 9, 0), 0);
                assert_eq!(PENDING_EVENTS.with(Cell::get), 2);
            });
            drain_pending(h);
            APP.with(|cell| {
                let b = cell.borrow();
                let a = b.as_ref().unwrap();
                assert!(a.read(PASS).unwrap().is_empty() && !a.auth_dirty);
                assert!(a.screen == Screen::Login);
                SetWindowTextW(a.handle(PASS), wide("synthetic kept").as_ptr());
            });
            // A deferred app switch with nothing unlocked keeps typed input.
            APP.with(|cell| {
                let _borrow = cell.borrow_mut();
                assert_eq!(window_proc(h, 0x1c, 0, 0), 0);
                assert_eq!(PENDING_EVENTS.with(Cell::get), 1);
            });
            drain_pending(h);
            APP.with(|cell| {
                let b = cell.borrow();
                let a = b.as_ref().unwrap();
                assert_eq!(&*a.read(PASS).unwrap(), "synthetic kept");
                assert!(a.screen == Screen::Login);
            });
            APP.with(|cell| {
                let _borrow = cell.borrow_mut();
                assert_eq!(window_proc(h, 0x10, 0, 0), 0);
                assert_eq!(PENDING_EVENTS.with(Cell::get), 4);
            });
            drain_pending(h);
            APP.with(|cell| {
                cell.borrow_mut().take();
            });
        }
    }
    /// A synthetic otpauth URI with long names, for the screens.
    const SYNTHETIC_OTP: &str = "otpauth://totp/Synthetic%20Bank:someone%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Synthetic%20Bank";
    fn style_visible(h: Hwnd) -> bool {
        unsafe { GetWindowLongPtrW(h, -16) & 0x1000_0000 != 0 }
    }
    /// An entry with an OTP secret: the code and its countdown are painted
    /// (never put into a control); [복사] copies the code with the usual
    /// expiry; [시크릿 복사] needs 복사 허용 like the password; the secret
    /// shows only in the 15-second view; [QR 보기] paints the URI as a QR
    /// code (black on white, a quiet zone, whole pixels a module) in the
    /// secret's place, which goes after 60 s, on another entry, another
    /// screen, another app in front and on lock. The editor's OTP field is
    /// masked, unreadable from outside and without IME; a pasted URI fills
    /// the names; saving adds, changes and removes the secret.
    #[test]
    fn an_otp_entry_shows_its_code_and_qr() {
        #[link(name = "gdi32")]
        unsafe extern "system" {
            fn GetPixel(dc: isize, x: i32, y: i32) -> u32;
        }
        let _korean = KoreanAfter::hold();
        i18n::set_english(false);
        let dir = test_dir("otp-view");
        let mut session = synthetic_session(&dir, "synthetic otp password");
        let o = Otp::parse(SYNTHETIC_OTP).unwrap().unwrap();
        let entry = Entry::new_with_otp(
            "Bank".into(),
            "비밀번호".into(),
            "synthetic password".into(),
            String::new(),
            Some(&o),
        )
        .unwrap();
        session.put(None, entry).unwrap();
        let plain = Entry::new("Plain".into(), String::new(), "x".into(), String::new()).unwrap();
        session.put(None, plain).unwrap();
        COPIED.with(|c| c.borrow_mut().take());
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.session = Some(session);
            app.screen = Screen::Vault;
            app.build();
            // The list marks the entry (LB_GETITEMDATA).
            let list = app.handle(LIST);
            assert_eq!(SendMessageW(list, 0x199, 0, 0), theme::ROW_OTP);
            assert_eq!(SendMessageW(list, 0x199, 1, 0), 0);
            let pick = |app: &mut App, i: usize| {
                SendMessageW(app.handle(LIST), 0x186, i, 0);
                app.command(LIST, 1).unwrap();
            };
            pick(&mut app, 1);
            assert!(!style_visible(app.handle(OTP_COPY)) && !style_visible(app.handle(OTP_QR)));
            assert!(!painted(&app).iter().any(|t| t.starts_with("OTP")));
            pick(&mut app, 0);
            for id in [OTP_COPY, OTP_SECRET_COPY, OTP_QR, REVEAL, TOGGLE, COPY] {
                assert!(style_visible(app.handle(id)), "{id}");
            }
            // The code of now (or of the next period, should one begin
            // meanwhile), the names and the countdown; the secret masked.
            let now = clock::now().unwrap();
            let codes: Vec<String> = [now, now + 30]
                .iter()
                .map(|t| otp_grouped(&o.code(*t)).to_string())
                .collect();
            let texts = painted(&app);
            assert!(texts.iter().any(|t| codes.contains(t)), "{texts:?}");
            assert!(texts.contains(&"OTP · Synthetic Bank (someone@example.com)".to_owned()));
            assert!(texts.iter().any(|t| t.ends_with("초 뒤 바뀜")));
            assert!(texts.contains(&"시크릿 ••••••••".to_owned()));
            assert!(!texts.iter().any(|t| t.contains("JBSW")));
            for c in &app.children {
                let text = caption(*c);
                assert!(!text.contains("JBSW") && !codes.iter().any(|code| text.contains(code)));
            }
            // The 15-second view shows the secret too.
            app.command(REVEAL, 0).unwrap();
            let secret = format!("시크릿 {}", *o.secret_grouped());
            assert!(painted(&app).contains(&secret));
            app.command(REVEAL, 0).unwrap();
            assert!(!painted(&app).contains(&secret));
            // [복사]: the code, cleared after 15 s like a copied password.
            app.command(OTP_COPY, 0).unwrap();
            let copied = COPIED.with(|c| c.borrow_mut().take()).unwrap();
            assert!(codes.iter().any(|c| c.replace(' ', "") == *copied));
            let (_, until) = app.clipboard.unwrap();
            let soon = Instant::now() + Duration::from_secs(15);
            assert!(until <= soon && until + Duration::from_secs(5) > soon);
            app.clipboard = Some((1, Instant::now() - Duration::from_secs(1)));
            app.timer();
            assert!(app.clipboard.is_none());
            // [시크릿 복사] only while 복사 허용 is on, and it turns it off.
            assert!(app.command(OTP_SECRET_COPY, 0).is_err());
            assert!(COPIED.with(|c| c.borrow().is_none()));
            app.command(TOGGLE, 0).unwrap();
            app.command(OTP_SECRET_COPY, 0).unwrap();
            let copied = COPIED.with(|c| c.borrow_mut().take()).unwrap();
            assert_eq!(copied.as_str(), "JBSWY3DPEHPK3PXP");
            assert!(app.copy_until.is_none() && app.clipboard.is_some());
            app.clipboard = None;
            // [QR 보기]: the panel in the secret's place.
            app.command(OTP_QR, 0).unwrap();
            assert!(app.qr_shown());
            for id in [REVEAL, TOGGLE, COPY] {
                assert!(!style_visible(app.handle(id)), "{id}");
            }
            assert_eq!(caption(app.handle(OTP_QR)), "QR 숨기기");
            let texts = painted(&app);
            assert!(texts.contains(&"QR 코드 · 휴대폰 인증 앱으로 스캔하세요".to_owned()));
            assert!(texts.iter().any(|t| t.ends_with("초 뒤 숨김")));
            assert!(!texts.contains(&"비밀정보".to_owned()));
            // Its pixels: every module where the encoder put it, the quiet
            // zone white, sharp edges.
            let code = qr::encode(o.uri("Bank").as_bytes()).unwrap();
            let (x, y, w, hh) = QR_AREA;
            let layout = qr_layout(code.size, app.px(w), app.px(hh)).unwrap();
            assert!(layout.module >= 4, "{layout:?}");
            let screen = GetDC(app.hwnd);
            let dc = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, 1600, 1400);
            ReleaseDC(app.hwnd, screen);
            let old = SelectObject(dc, bmp);
            app.draw_screen(dc);
            let (left, top, m) = (
                app.px(x) + layout.offset.0,
                app.px(y) + layout.offset.1,
                layout.module,
            );
            let n = code.size as i32;
            for my in -4..n + 4 {
                for mx in -4..n + 4 {
                    let dark = (0..n).contains(&mx)
                        && (0..n).contains(&my)
                        && code.dark(mx as usize, my as usize);
                    let want = if dark { 0 } else { 0x00FF_FFFF };
                    let (px, py) = (left + (mx + 4) * m, top + (my + 4) * m);
                    for (dx, dy) in [(0, 0), (m - 1, m - 1), (m / 2, m / 2)] {
                        assert_eq!(GetPixel(dc, px + dx, py + dy), want, "module {mx},{my}");
                    }
                }
            }
            SelectObject(dc, old);
            DeleteObject(bmp);
            DeleteDC(dc);
            // It goes on another entry, after 60 s, on another app in front,
            // on another screen and on lock.
            pick(&mut app, 1);
            assert!(app.qr.is_none() && style_visible(app.handle(REVEAL)));
            pick(&mut app, 0);
            app.command(OTP_QR, 0).unwrap();
            app.expire_qr(Instant::now() + QR_SHOWN - Duration::from_secs(1));
            assert!(app.qr.is_some());
            app.expire_qr(Instant::now() + QR_SHOWN);
            assert!(app.qr.is_none() && style_visible(app.handle(REVEAL)));
            assert_eq!(caption(app.handle(OTP_QR)), "QR 보기");
            app.command(OTP_QR, 0).unwrap();
            app.command(OTP_QR, 0).unwrap();
            assert!(app.qr.is_none());
            app.command(OTP_QR, 0).unwrap();
            app.deactivated();
            assert!(app.qr.is_none());
            app.activated();
            app.inactive = false;
            app.command(OTP_QR, 0).unwrap();
            // A QR of another entry is never shown for this one.
            let other = app.session.as_ref().unwrap().entries[1].id();
            app.qr = Some((other, Instant::now() + QR_SHOWN));
            assert!(!app.qr_shown());
            app.command(OTP_QR, 0).unwrap();
            assert!(app.qr_shown());
            app.command(EDIT, 0).unwrap();
            assert!(app.qr.is_none() && app.screen == Screen::Edit);
            // The editor: masked, unreadable from outside, no IME, the
            // names in their fields.
            let field = app.handle(OTP_FIELD);
            assert_eq!(&*app.read(OTP_FIELD).unwrap(), "JBSWY3DPEHPK3PXP");
            assert_eq!(&*app.read(OTP_ISSUER).unwrap(), "Synthetic Bank");
            assert_eq!(&*app.read(OTP_ACCOUNT).unwrap(), "someone@example.com");
            assert_ne!(SendMessageW(field, 0xd2, 0, 0), 0);
            assert_eq!(GetWindowTextLengthW(field), 0);
            assert_eq!(GetWindowTextLengthW(app.handle(OTP_ISSUER)), 0);
            assert_eq!(SendMessageW(field, 0x301, 0, 0), 0);
            assert_eq!(ImmGetContext(field), 0);
            app.command(PEEK_OTP, 0).unwrap();
            assert_eq!(SendMessageW(field, 0xd2, 0, 0), 0);
            assert_eq!(GetWindowTextLengthW(field), 0);
            assert_eq!(ImmGetContext(field), 0);
            app.command(PEEK_OTP, 0).unwrap();
            assert_ne!(SendMessageW(field, 0xd2, 0, 0), 0);
            // A pasted URI fills the names; posted by another program, the
            // notice does nothing (no bit set).
            assert!(!take_notice(4));
            let uri = "otpauth://totp/New%20Issuer:new%40example.com?secret=JBSWY3DPEHPK3PXQ&issuer=New%20Issuer&digits=8";
            SetWindowTextW(field, secret_wide(uri).as_ptr());
            app.otp_pasted();
            assert_eq!(&*app.read(OTP_ISSUER).unwrap(), "New Issuer");
            assert_eq!(&*app.read(OTP_ACCOUNT).unwrap(), "new@example.com");
            SetWindowTextW(app.handle(OTP_ACCOUNT), secret_wide("typed").as_ptr());
            app.command(SAVE, 0).unwrap();
            assert!(app.screen == Screen::Vault);
            let saved = app.session.as_ref().unwrap().entries[0].otp().unwrap();
            assert_eq!(
                (saved.issuer.as_str(), saved.account.as_str(), saved.digits),
                ("New Issuer", "typed", 8)
            );
            assert_eq!(&*saved.secret_base32(), "JBSWY3DPEHPK3PXQ");
            assert_eq!(&fs_magic(&app), b"GOYOVA05");
            // A bad secret is refused and nothing changes; an empty field
            // removes the secret.
            app.command(EDIT, 0).unwrap();
            SetWindowTextW(app.handle(OTP_FIELD), secret_wide("not base32!").as_ptr());
            assert!(app.command(SAVE, 0).is_err());
            assert!(app.screen == Screen::Edit);
            for id in [OTP_FIELD, OTP_ISSUER, OTP_ACCOUNT] {
                SetWindowTextW(app.handle(id), wide("").as_ptr());
            }
            app.command(SAVE, 0).unwrap();
            assert!(
                app.session
                    .as_ref()
                    .unwrap()
                    .entries
                    .iter()
                    .all(|e| !e.has_otp())
            );
            assert_eq!(SendMessageW(app.handle(LIST), 0x199, 0, 0), 0);
            assert_eq!(&fs_magic(&app), b"GOYOVA01");
            // Lock: no QR survives it.
            app.session
                .as_mut()
                .unwrap()
                .put(Some(0), {
                    Entry::new_with_otp(
                        "Bank".into(),
                        String::new(),
                        "x".into(),
                        String::new(),
                        Some(&o),
                    )
                    .unwrap()
                })
                .unwrap();
            app.build();
            pick(&mut app, 0);
            app.command(OTP_QR, 0).unwrap();
            assert!(app.qr_shown());
            app.lock("test lock", true);
            assert!(app.qr.is_none());
            // A scrub (Windows locking or ending the session, sent from
            // another thread) drops it at once, before the lock rebuilds.
            app.qr = Some((other, Instant::now() + QR_SHOWN));
            app.scrub();
            assert!(app.qr.is_none());
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A control's top left in the main window's client pixels.
    fn placed(app: &App, id: i32) -> (i32, i32) {
        unsafe {
            let mut r = Rect::default();
            GetWindowRect(app.handle(id), &mut r);
            let mut p = Point {
                x: r.left,
                y: r.top,
            };
            MapWindowPoints(0, app.hwnd, &mut p, 1);
            (p.x, p.y)
        }
    }
    /// The logical top of a field's painted frame.
    fn frame_top(app: &App, id: i32) -> i32 {
        let h = app.handle(id);
        app.frames.iter().find(|(_, f)| *f == h).unwrap().0.top
    }
    /// An OTP entry (0.12.1): the view shows its title and kind, the OTP
    /// row in the 비밀정보's place and the memo, never its secret field
    /// (the marker, or a 0.12.0 entry's dummy), with no [복사] or paging
    /// for it; 15초 보기 shows the OTP secret and memo, and [시크릿 복사]
    /// still needs 복사 허용. The editor follows the kind: the OTP chip or
    /// the typed "OTP" hides the 비밀정보 field, puts the required OTP row
    /// in its place with a note; saving needs the OTP secret and stores the
    /// marker; another kind brings the field back and needs 비밀정보.
    #[test]
    fn an_otp_kind_entry_shows_and_edits_without_a_secret() {
        let _korean = KoreanAfter::hold();
        i18n::set_english(false);
        let dir = test_dir("otp-kind");
        let mut session = synthetic_session(&dir, "synthetic otp-kind password");
        let o = Otp::parse(SYNTHETIC_OTP).unwrap().unwrap();
        let otp_entry = Entry::new_with_otp(
            "Bank".into(),
            "OTP".into(),
            "typed but dropped".into(),
            "synthetic memo".into(),
            Some(&o),
        )
        .unwrap();
        assert_eq!(&*otp_entry.secret, vault::OTP_MARKER);
        session.put(None, otp_entry).unwrap();
        // As 0.12.0 left it: kind "OTP", a dummy 비밀정보, the OTP secret.
        let mut legacy = Entry::new_with_otp(
            "Mail".into(),
            "비밀번호".into(),
            "legacy dummy".into(),
            String::new(),
            Some(&o),
        )
        .unwrap();
        legacy.kind = Zeroizing::new("OTP".into());
        session.put(None, legacy).unwrap();
        let plain = Entry::new(
            "Plain".into(),
            "비밀번호".into(),
            "pw".into(),
            String::new(),
        );
        session.put(None, plain.unwrap()).unwrap();
        COPIED.with(|c| c.borrow_mut().take());
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.session = Some(session);
            app.screen = Screen::Vault;
            app.build();
            let list = app.handle(LIST);
            for (i, mark) in [(0, theme::ROW_OTP), (1, theme::ROW_OTP), (2, 0)] {
                assert_eq!(SendMessageW(list, 0x199, i, 0), mark);
            }
            let pick = |app: &mut App, i: usize| {
                SendMessageW(app.handle(LIST), 0x186, i, 0);
                app.command(LIST, 1).unwrap();
            };
            let now = clock::now().unwrap();
            let codes: Vec<String> = [now, now + 30]
                .iter()
                .map(|t| otp_grouped(&o.code(*t)).to_string())
                .collect();
            for i in [0, 1] {
                pick(&mut app, i);
                for id in [OTP_COPY, OTP_SECRET_COPY, OTP_QR, REVEAL, TOGGLE] {
                    assert!(style_visible(app.handle(id)), "{i} {id}");
                }
                assert!(!style_visible(app.handle(COPY)));
                assert!(!style_visible(app.handle(NEXT)));
                // The OTP row sits under the chip.
                let y = app.px(OTP_ENTRY_TOP + 34);
                assert_eq!(placed(&app, OTP_COPY), (app.px(OTP_ROW.0), y));
                let texts = painted(&app);
                assert!(texts.iter().any(|t| codes.contains(t)), "{texts:?}");
                assert!(texts.contains(&"OTP".to_owned()), "the chip: {texts:?}");
                assert!(texts.contains(&"시크릿 ••••••••".to_owned()));
                assert!(texts.contains(&"메모".to_owned()));
                for gone in [
                    "비밀정보",
                    "••••••••••••",
                    vault::OTP_MARKER,
                    "legacy dummy",
                ] {
                    assert!(!texts.iter().any(|t| t.contains(gone)), "{gone}: {texts:?}");
                }
                // 15초 보기: the OTP secret (and memo), never the field.
                app.command(REVEAL, 0).unwrap();
                let texts = painted(&app);
                assert!(texts.contains(&format!("시크릿 {}", *o.secret_grouped())));
                assert!(!texts.iter().any(|t| t.contains("legacy dummy")));
                assert!(!texts.iter().any(|t| t.contains(vault::OTP_MARKER)));
                assert!(!style_visible(app.handle(NEXT)));
                assert_eq!(app.command(NEXT, 0).err(), Some(NO_SECRET));
                app.command(REVEAL, 0).unwrap();
                // [복사] of 비밀정보 does not exist for it, even if sent.
                app.command(TOGGLE, 0).unwrap();
                assert_eq!(app.command(COPY, 0).err(), Some(NO_SECRET));
                assert!(COPIED.with(|c| c.borrow().is_none()));
                // 복사 허용 still on: [시크릿 복사] takes it.
                app.command(OTP_SECRET_COPY, 0).unwrap();
                let copied = COPIED.with(|c| c.borrow_mut().take()).unwrap();
                assert_eq!(copied.as_str(), "JBSWY3DPEHPK3PXP");
                app.clipboard = None;
            }
            assert!(painted(&app).contains(&"메모 없음".to_owned()));
            pick(&mut app, 0);
            assert!(
                painted(&app)
                    .contains(&"가려짐 · 보기를 누르면 OTP 시크릿과 함께 표시됩니다.".to_owned())
            );
            // The QR panel in the memo's place, under the row.
            app.command(OTP_QR, 0).unwrap();
            assert!(app.qr_shown() && !style_visible(app.handle(REVEAL)));
            assert_eq!(app.qr_area().1, QR_AREA_OTP_ENTRY);
            let texts = painted(&app);
            assert!(texts.contains(&"QR 코드 · 휴대폰 인증 앱으로 스캔하세요".to_owned()));
            assert!(!texts.contains(&"메모".to_owned()));
            app.command(OTP_QR, 0).unwrap();
            // An ordinary entry: its row under the memo, as before.
            pick(&mut app, 2);
            assert!(style_visible(app.handle(COPY)) && !style_visible(app.handle(OTP_COPY)));
            assert!(painted(&app).contains(&"비밀정보".to_owned()));

            // The editor of the OTP entry: no 비밀정보 field, the OTP row
            // in its place and required, the note.
            pick(&mut app, 1);
            app.command(EDIT, 0).unwrap();
            let otp_shape = |app: &App| {
                !style_visible(app.handle(SECRET))
                    && !style_visible(app.handle(SECRET_LABEL))
                    && style_visible(app.handle(OTP_KIND_NOTE))
                    && caption(app.handle(OTP_LABEL)) == "OTP 시크릿 · 키 또는 otpauth 주소"
                    && frame_top(app, OTP_FIELD) == OTP_EDIT_TOP_KIND + 22
                    && frame_top(app, OTP_ACCOUNT) == OTP_EDIT_TOP_KIND + 22
            };
            let plain_shape = |app: &App| {
                style_visible(app.handle(SECRET))
                    && style_visible(app.handle(SECRET_LABEL))
                    && !style_visible(app.handle(OTP_KIND_NOTE))
                    && caption(app.handle(OTP_LABEL)) == OTP_FIELD_OPTIONAL
                    && frame_top(app, OTP_FIELD) == OTP_EDIT_TOP + 22
            };
            assert!(otp_shape(&app));
            assert_eq!(caption(app.handle(OTP_KIND_NOTE)), OTP_KIND_TEXT);
            // The dummy never reaches the editor.
            assert_eq!(&*app.read(SECRET).unwrap(), "");
            assert_eq!(&*app.read(OTP_FIELD).unwrap(), "JBSWY3DPEHPK3PXP");
            // The field and its eye moved with their frame.
            let (_, field_y) = placed(&app, OTP_FIELD);
            assert!(
                (field_y - app.px(OTP_EDIT_TOP_KIND + 30)).abs() <= 1,
                "{field_y}"
            );
            let (_, eye_y) = placed(&app, PEEK_OTP);
            assert!(
                (eye_y - app.px(OTP_EDIT_TOP_KIND + 26)).abs() <= 1,
                "{eye_y}"
            );
            // Without the OTP secret it is refused; saved, the marker
            // replaces the dummy.
            SetWindowTextW(app.handle(OTP_FIELD), wide("").as_ptr());
            for id in [OTP_ISSUER, OTP_ACCOUNT] {
                SetWindowTextW(app.handle(id), wide("").as_ptr());
            }
            assert_eq!(app.command(SAVE, 0).err(), Some(vault::OTP_REQUIRED));
            assert!(app.screen == Screen::Edit);
            SetWindowTextW(app.handle(OTP_FIELD), wide("JBSWY3DPEHPK3PXP").as_ptr());
            app.command(SAVE, 0).unwrap();
            let s = app.session.as_ref().unwrap();
            assert_eq!(&*s.entries[1].secret, vault::OTP_MARKER);
            assert!(s.entries[1].is_otp_entry());

            // Typing another kind brings 비밀정보 back, required.
            pick(&mut app, 0);
            app.command(EDIT, 0).unwrap();
            assert!(otp_shape(&app));
            SetWindowTextW(app.handle(KIND), wide("OT").as_ptr());
            app.command(KIND, 0x300).unwrap();
            assert!(plain_shape(&app));
            assert_eq!(&*app.read(SECRET).unwrap(), "");
            assert_eq!(
                app.command(SAVE, 0).err(),
                Some("이름과 비밀정보를 입력하세요.")
            );
            // Back and forth: the same places.
            SetWindowTextW(app.handle(KIND), wide(" otp").as_ptr());
            app.command(KIND, 0x300).unwrap();
            assert!(otp_shape(&app));
            SetWindowTextW(app.handle(KIND), wide("비밀번호").as_ptr());
            app.command(KIND, 0x300).unwrap();
            assert!(plain_shape(&app));
            SetWindowTextW(app.handle(SECRET), secret_wide("a new password").as_ptr());
            app.command(SAVE, 0).unwrap();
            let s = app.session.as_ref().unwrap();
            assert_eq!(&*s.entries[0].secret, "a new password");
            assert!(!s.entries[0].is_otp_entry() && s.entries[0].has_otp());

            // A new entry: the OTP chip turns the editor into the OTP
            // shape, the OTP field next; the 비밀정보 typed before is not
            // kept.
            app.command(NEW, 0).unwrap();
            assert!(plain_shape(&app));
            SetWindowTextW(app.handle(TITLE), wide("Code only").as_ptr());
            SetWindowTextW(app.handle(SECRET), secret_wide("typed first").as_ptr());
            let chip = PRESET + KIND_PRESETS.len() as i32 - 1;
            assert_eq!(caption(app.handle(chip)), "OTP");
            app.command(chip, 0).unwrap();
            assert!(otp_shape(&app));
            assert_eq!(GetFocus(), app.handle(OTP_FIELD));
            assert_eq!(app.command(SAVE, 0).err(), Some(vault::OTP_REQUIRED));
            SetWindowTextW(app.handle(OTP_FIELD), wide(SYNTHETIC_OTP).as_ptr());
            app.command(SAVE, 0).unwrap();
            let s = app.session.as_ref().unwrap();
            let e = s.entries.last().unwrap();
            let fields = [&e.title, &e.kind, &e.secret, &e.notes].map(|f| f.as_str());
            assert_eq!(fields, ["Code only", "OTP", vault::OTP_MARKER, ""]);
            assert_eq!(e.otp(), Some(o.clone()));
            // A chip of another kind puts the field back, focused.
            app.command(NEW, 0).unwrap();
            app.command(chip, 0).unwrap();
            app.command(PRESET, 0).unwrap();
            assert!(plain_shape(&app));
            assert_eq!(GetFocus(), app.handle(SECRET));
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The first eight bytes of the open vault's file.
    fn fs_magic(app: &App) -> [u8; 8] {
        let path = &app.session.as_ref().unwrap().path;
        std::fs::read(path).unwrap()[..8].try_into().unwrap()
    }
    /// The code in two groups, and the QR layout's whole pixels, centred,
    /// none below two a module.
    #[test]
    fn otp_codes_group_and_the_qr_fits_whole_pixels() {
        assert_eq!(&*otp_grouped("123456"), "123 456");
        assert_eq!(&*otp_grouped("1234567"), "123 4567");
        assert_eq!(&*otp_grouped("12345678"), "1234 5678");
        assert_eq!(
            qr_layout(41, 464, 288),
            Some(QrLayout {
                module: 5,
                offset: ((464 - 245) / 2, (288 - 245) / 2)
            })
        );
        assert_eq!(qr_layout(41, 98, 98).unwrap().module, 2);
        assert_eq!(qr_layout(41, 97, 400), None);
        assert_eq!(qr_layout(177, 1000, 1000).unwrap().module, 5);
    }
    /// Renders every screen with synthetic data to `test-output/ui-preview/*.bmp`
    /// for design review. It shows a real window briefly without capture
    /// exclusion, so it only runs on request: `cargo test ui_preview -- --ignored`.
    #[test]
    #[ignore]
    fn ui_preview() {
        /// Focus moving between this test and the desktop would trigger the
        /// app-switch lock mid-capture and close the sample vault.
        unsafe extern "system" fn preview_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
            if m == 0x1c {
                return 0;
            }
            unsafe { window_proc(h, m, w, l) }
        }
        #[link(name = "user32")]
        unsafe extern "system" {
            fn PrintWindow(h: Hwnd, dc: isize, flags: u32) -> i32;
            fn PeekMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32, remove: u32) -> i32;
        }
        #[link(name = "dwmapi")]
        unsafe extern "system" {
            fn DwmFlush() -> i32;
        }
        #[link(name = "gdi32")]
        unsafe extern "system" {
            fn GdiFlush() -> i32;
            fn GetDIBits(
                dc: isize,
                bmp: isize,
                start: u32,
                lines: u32,
                bits: *mut u8,
                info: *mut u8,
                usage: u32,
            ) -> i32;
        }
        fn pump() {
            for _ in 0..6 {
                let mut msg = Msg::default();
                unsafe {
                    while PeekMessageW(&mut msg, 0, 0, 0, 1) != 0 {
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        /// Client area as top-down 32-bit pixels plus the BITMAPINFOHEADER.
        fn grab(h: Hwnd) -> ([u8; 44], Vec<u8>) {
            unsafe {
                let mut c = Rect::default();
                GetClientRect(h, &mut c);
                let (w, hh) = (c.right, c.bottom);
                let screen = GetDC(0);
                let mem = CreateCompatibleDC(screen);
                let bmp = CreateCompatibleBitmap(screen, w, hh);
                let old = SelectObject(mem, bmp);
                GdiFlush();
                DwmFlush();
                assert_ne!(PrintWindow(h, mem, 3), 0);
                SelectObject(mem, old);
                let mut info = [0u8; 44];
                info[0..4].copy_from_slice(&40u32.to_le_bytes());
                info[4..8].copy_from_slice(&w.to_le_bytes());
                info[8..12].copy_from_slice(&(-hh).to_le_bytes());
                info[12..14].copy_from_slice(&1u16.to_le_bytes());
                info[14..16].copy_from_slice(&32u16.to_le_bytes());
                let mut pixels = vec![0u8; (w * hh * 4) as usize];
                let rows = GetDIBits(
                    mem,
                    bmp,
                    0,
                    hh as u32,
                    pixels.as_mut_ptr(),
                    info.as_mut_ptr(),
                    0,
                );
                assert_eq!(rows, hh);
                DeleteObject(bmp);
                DeleteDC(mem);
                ReleaseDC(0, screen);
                (info, pixels)
            }
        }
        /// DWM can hand back a frame with some labels not yet composed, so
        /// keep grabbing until two frames agree (a blinking caret is allowed).
        fn capture(h: Hwnd, path: &std::path::Path) {
            let (info, mut pixels) = grab(h);
            for _ in 0..20 {
                pump();
                let (_, next) = grab(h);
                let changed = pixels
                    .chunks(4)
                    .zip(next.chunks(4))
                    .filter(|(a, b)| a[..3] != b[..3])
                    .count();
                pixels = next;
                if changed < 200 {
                    break;
                }
            }
            let mut file = b"BM".to_vec();
            file.extend((54 + pixels.len() as u32).to_le_bytes());
            file.extend([0u8; 4]);
            file.extend(54u32.to_le_bytes());
            file.extend(&info[..40]);
            file.extend(&pixels);
            std::fs::write(path, file).unwrap();
        }
        // GOYO_PREVIEW_DIR puts the pictures elsewhere.
        let out = std::env::var_os("GOYO_PREVIEW_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-output/ui-preview")
            });
        std::fs::create_dir_all(&out).unwrap();
        // GOYO_PREVIEW_LANG=en renders the English interface to en-*.bmp.
        let english = std::env::var("GOYO_PREVIEW_LANG").is_ok_and(|v| v == "en");
        let _korean = KoreanAfter::hold();
        i18n::set_english(english);
        let pick = |ko: &'static str, en: &'static str| if english { en } else { ko };
        let temp = std::env::temp_dir().join(format!(
            "goyo-preview-{:x}",
            u64::from_le_bytes(*crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir(&temp).unwrap();
        let provision = Provision::new().unwrap();
        let mut session = provision
            .finish(
                &temp.join("vault.goyo"),
                &temp.join("vault.goyokey"),
                "synthetic preview password",
            )
            .unwrap();
        const MNEMONIC_24: &str = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual";
        for (title, kind, value, notes) in [
            (
                "GitHub",
                "비밀번호",
                "correct-horse-battery-staple-2026",
                pick(
                    "복구 코드는 종이에 따로 보관",
                    "Recovery codes kept on paper",
                ),
            ),
            (
                pick("비트코인 지갑", "Bitcoin wallet"),
                "니모닉",
                MNEMONIC_24,
                pick(
                    "하드웨어 지갑 · 2024년 생성",
                    "Hardware wallet · created 2024",
                ),
            ),
            (
                pick("서버 SSH 키", "Server SSH key"),
                "프라이빗키",
                "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\r\n-----END OPENSSH PRIVATE KEY-----",
                "",
            ),
            (
                pick("은행 공동인증서", "Bank certificate"),
                "비밀번호",
                "synthetic-only-value",
                pick("만료 2027-03", "Expires 2027-03"),
            ),
        ] {
            let entry = Entry::new(title.into(), kind.into(), value.into(), notes.into()).unwrap();
            session.put(None, entry).unwrap();
        }
        // Enough rows to show the list scrollbar.
        for i in 1..=10 {
            let entry = Entry::new(
                format!("{} {i}", pick("예시 계정", "Sample account")),
                "비밀번호".into(),
                "synthetic".into(),
                String::new(),
            )
            .unwrap();
            session.put(None, entry).unwrap();
        }
        // The vault syncs, so the pill shows "동기화됨" before the file name:
        // the helper's folder and status, and the first upload handed back.
        let mut server = Server::default();
        server.helper(&session.path);
        session.enable_sync().unwrap();
        upload(&mut server, &mut session);
        assert_eq!(session.badge(), Some(SyncBadge::Synced));
        unsafe {
            SetProcessDPIAware();
            let instance = GetModuleHandleW(null());
            let name = wide("GoyoPreviewWindow");
            let wc = WndClass {
                style: 3,
                proc: Some(preview_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: 6,
                menu: null(),
                class: name.as_ptr(),
            };
            assert_ne!(RegisterClassW(&wc), 0);
            let h = create_window(instance, &name);
            assert_ne!(h, 0);
            APP.with(|cell| {
                // Example paths for the README screenshots, not this machine's.
                let mut app = App::new(h);
                app.home_dir = PathBuf::from(r"C:\GoyoVault");
                app.vault_path = app.home_dir.join("vault.goyo");
                app.key_path = app.home_dir.join("vault.goyokey");
                *cell.borrow_mut() = Some(app);
            });
            ShowWindow(h, 4);
            let mut session = Some(session);
            #[allow(unused_mut)]
            let mut shots = vec![
                ("0-welcome", Screen::Welcome),
                ("1-login", Screen::Login),
                ("2-create", Screen::Create),
                ("3-restore", Screen::Restore),
                ("4-vault", Screen::Vault),
                ("5-vault-selected", Screen::Vault),
                ("6-vault-revealed", Screen::Vault),
                // The same mnemonic cut to 12 and 18 words (its grid).
                ("6-vault-revealed-12", Screen::Vault),
                ("6-vault-revealed-18", Screen::Vault),
                ("7-edit", Screen::Edit),
                ("8-new", Screen::Edit),
                ("9-password", Screen::Password),
                ("11-keys", Screen::Keys),
                ("12-adopt", Screen::Adopt),
                ("13-keys-rollback", Screen::Keys),
            ];
            // The security-key build's screens (spec §14.8-10).
            #[cfg(feature = "security-key")]
            shots.extend([
                ("14-keys-sk", Screen::Keys),
                ("15-lost-key", Screen::LostKey),
                ("16-key-remove", Screen::KeyRemove),
                ("17-pair", Screen::Pair),
                ("18-review", Screen::Review),
                ("19-keys-undone", Screen::Keys),
                ("20-fetched", Screen::Fetched),
                ("21-vault-tofu-fetched", Screen::Vault),
                ("22-vault-tofu", Screen::Vault),
                ("23-keys-ks-off", Screen::Keys),
                ("24-keys-ks-on", Screen::Keys),
                ("25-keys-server-take", Screen::Keys),
            ]);
            for (dark, (file, screen)) in [true, false]
                .into_iter()
                .flat_map(|dark| shots.iter().map(move |s| (dark, *s)))
            {
                if theme::is_dark() != dark || file == "0-welcome" {
                    theme::set_dark(dark);
                    apply_window_theme(h);
                    // Each theme pass starts locked.
                    APP.with(|cell| {
                        if let Some(s) = cell.borrow_mut().as_mut().unwrap().session.take() {
                            session = Some(s);
                        }
                    });
                }
                let file = format!(
                    "{}{}-{file}",
                    if english { "en-" } else { "" },
                    if dark { "dark" } else { "light" }
                );
                let file = file.as_str();
                APP.with(|cell| {
                    let mut b = cell.borrow_mut();
                    let a = b.as_mut().unwrap();
                    a.screen = screen;
                    // Status lines as the real app shows them on each screen.
                    a.status = line(match screen {
                        Screen::Login => "금고·열쇠 파일을 확인하고 비밀번호를 입력하세요.",
                        Screen::Vault => "잠금 해제됨 · 저장하면 즉시 암호화됩니다. 화면 캡처는 막지만 악성코드까지 막지는 못합니다.",
                        _ => "",
                    });
                    a.reveal_until = None;
                    a.copy_until = None;
                    a.provision = None;
                    if screen == Screen::Create {
                        a.provision = Some(Provision::new().unwrap());
                    }
                    if screen == Screen::Vault && a.session.is_none() {
                        a.session = session.take();
                    }
                    // "동기화됨" (checked above) however long the shots take:
                    // the helper's heartbeat would grow stale meanwhile.
                    a.sync_badge = a.session.as_ref().map(|_| SyncBadge::Synced);
                    a.selected = if file.ends_with("5-vault-selected") {
                        Some(0)
                    } else if file.contains("6-vault-revealed") {
                        Some(1)
                    } else {
                        None
                    };
                    a.editing = file.ends_with("7-edit").then_some(2);
                    a.adopt_source = file
                        .ends_with("12-adopt")
                        .then(|| a.home_dir.join("from-other-pc.goyokey"));
                    // A KF2 key file put back over this PC's newer one.
                    let rollback = file.ends_with("13-keys-rollback").then(|| KeysView {
                        code: Some("E3 · 7F2A-90C4-1B5E-D836".into()),
                        hold: Hold::LocalRollback(4, 3),
                        #[cfg(feature = "security-key")]
                        keys: None,
                    });
                    KEYS_VIEW.with(|v| *v.borrow_mut() = rollback);
                    #[cfg(feature = "security-key")]
                    preview_keys(a, file);
                    // The TOFU banner of a vault from the server, and of a
                    // key file copied by USB, with a code half typed.
                    #[cfg(feature = "security-key")]
                    {
                        let fetched = file.ends_with("21-vault-tofu-fetched");
                        let banner = fetched || file.ends_with("22-vault-tofu");
                        keys_ui::TOFU_SHOWN.with(|t| t.set(banner));
                        keys_ui::TOFU_FETCHED_SHOWN.with(|t| t.set(fetched));
                        if file.ends_with("20-fetched") {
                            // Locked, as the screen is before the unlock.
                            if let Some(s) = a.session.take() {
                                session = Some(s);
                            }
                            a.status = line(keys_ui::FETCHED_PICKED);
                        } else if banner {
                            a.status = line(keys_ui::FETCHED_NEXT);
                        }
                    }
                    // The mnemonic has 24 words but in its 12 and 18 shots.
                    if let Some(s) = a.session.as_mut() {
                        let n = match file.rsplit_once("revealed-") {
                            Some((_, n)) => n.parse().unwrap(),
                            None => 24,
                        };
                        let e = &s.entries[1];
                        let words: Vec<&str> = MNEMONIC_24.split(' ').take(n).collect();
                        let entry = Entry::new(
                            e.title.to_string(),
                            e.kind.to_string(),
                            words.join(" "),
                            e.notes.to_string(),
                        )
                        .unwrap();
                        s.put(Some(1), entry).unwrap();
                    }
                    if file.contains("6-vault-revealed") {
                        a.reveal_until = Some(Instant::now() + Duration::from_secs(15));
                    }
                    a.build();
                    if file.contains("6-vault-revealed") {
                        a.copy_until = Some(Instant::now() + Duration::from_secs(30));
                        a.set_toggle(true);
                    }
                    #[cfg(feature = "security-key")]
                    if file.ends_with("vault-tofu-fetched") {
                        let sample = wide("E5 · 7F2A-90C4");
                        SetWindowTextW(a.handle(keys_ui::GATE_CODE), sample.as_ptr());
                    }
                    if file.ends_with("9-password") {
                        // One field shown with the eye button, one still masked.
                        for id in [CURRENT_PASS, PASS] {
                            let sample = secret_wide("example passphrase");
                            SetWindowTextW(a.handle(id), sample.as_ptr());
                        }
                        a.peek(PEEK_CURRENT).unwrap();
                    }
                });
                pump();
                // Repaint everything synchronously so the capture never
                // catches a half-drawn label.
                RedrawWindow(h, null(), 0, 0x1 | 0x80 | 0x100);
                pump();
                capture(h, &out.join(format!("{file}.bmp")));
            }
            APP.with(|cell| {
                cell.borrow_mut().take();
            });
            DestroyWindow(h);
            pump();
        }
        // Also the sync folder.
        let _ = std::fs::remove_dir_all(&temp);
    }
    /// A yes/no box (the sync consent, delete) answers only to this thread:
    /// another thread, standing in for another program, posts and sends
    /// "Yes" in every form, and the box still waits. This thread, standing in
    /// for the user, then answers it. It shows a real box for about a second.
    #[test]
    fn confirm_box_ignores_other_programs() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetDlgItem(h: Hwnd, id: i32) -> Hwnd;
            fn KillTimer(h: Hwnd, id: usize) -> i32;
        }
        static TRIED: AtomicBool = AtomicBool::new(false);
        static ANSWER: AtomicUsize = AtomicUsize::new(7);
        unsafe extern "system" fn answer(_: Hwnd, _: u32, _: usize, _: u32) {
            let b = confirm_box();
            if b != 0 && TRIED.load(Relaxed) {
                unsafe { SendMessageW(b, 0x111, ANSWER.load(Relaxed), 0) };
            }
        }
        use std::sync::atomic::Ordering::Relaxed;
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            let hook = filter_queue(h);
            assert_ne!(hook, 0);
            let timer = SetTimer(0, 0, 50, answer as *const () as isize);
            assert_ne!(timer, 0);
            // Each way another program could answer "Yes"; then this thread
            // answers. The last round checks that a real answer still works.
            // Posted mouse or key input is taken while the box is in front:
            // like SendInput, it cannot be told from the user's own input
            // (docs/SECURITY_REVIEW.md, same-user programs are out of scope).
            type Attack = fn(Hwnd, Hwnd);
            let attacks: [(&str, Attack); 6] = [
                ("posted WM_COMMAND", |b, _| {
                    PostMessageW(b, 0x111, 6, 0);
                }),
                ("posted BM_CLICK", |_, y| {
                    PostMessageW(y, 0xf5, 0, 0);
                }),
                ("sent WM_COMMAND", |b, _| {
                    SendMessageW(b, 0x111, 6, 0);
                }),
                ("sent BM_CLICK", |_, y| {
                    SendMessageW(y, 0xf5, 0, 0);
                }),
                ("sent mouse click", |_, y| {
                    SendMessageW(y, 0x201, 1, 0);
                    SendMessageW(y, 0x202, 0, 0);
                }),
                ("nothing", |_, _| {}),
            ];
            for (i, (name, attack)) in attacks.into_iter().enumerate() {
                let last = i == 5;
                TRIED.store(false, Relaxed);
                ANSWER.store(if last { 6 } else { 7 }, Relaxed);
                let other = std::thread::spawn(move || {
                    let start = Instant::now();
                    let mut b = 0;
                    while b == 0 && start.elapsed() < Duration::from_secs(10) {
                        std::thread::sleep(Duration::from_millis(20));
                        b = confirm_box();
                    }
                    assert_ne!(b, 0, "the box never opened");
                    let yes = GetDlgItem(b, 6); // IDYES
                    assert_ne!(yes, 0);
                    attack(b, yes);
                    std::thread::sleep(Duration::from_millis(200));
                    let open = confirm_box() == b;
                    TRIED.store(true, Relaxed);
                    open
                });
                let yes = win::confirm(
                    h,
                    "선택한 항목을 삭제할까요? 기존 백업 사본은 삭제되지 않습니다.",
                );
                let open = other.join().unwrap();
                assert!(open, "{name} answered the box");
                assert_eq!(yes, last, "{name}");
                assert_eq!(confirm_box(), 0);
            }
            KillTimer(0, timer);
            UnhookWindowsHookEx(hook);
            FILTERED_WINDOW.with(|f| f.set(0));
            DestroyWindow(h);
        }
    }
    /// Another thread stands in for another program: Windows reports both as
    /// "sent from another thread" (ISMEX_SEND, or ISMEX_NOTIFY for
    /// SendNotifyMessage). Posted fakes are covered by accept_queued.
    #[test]
    fn foreign_messages_are_ignored() {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn PeekMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32, remove: u32) -> i32;
            fn SendNotifyMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> i32;
        }
        fn pump_until<T>(worker: &std::thread::JoinHandle<T>) {
            unsafe {
                while !worker.is_finished() {
                    let mut msg = Msg::default();
                    while PeekMessageW(&mut msg, 0, 0, 0, 1) != 0 {
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                // Notifications and posted follow-ups still in the queue.
                let mut msg = Msg::default();
                while PeekMessageW(&mut msg, 0, 0, 0, 1) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }
        unsafe {
            let name = wide("GoyoForeignMessageTest");
            let instance = GetModuleHandleW(null());
            let wc = WndClass {
                style: 0,
                proc: Some(window_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: 6,
                menu: null(),
                class: name.as_ptr(),
            };
            assert_ne!(RegisterClassW(&wc), 0);
            let h = CreateWindowExW(
                0,
                name.as_ptr(),
                wide("Synthetic foreign message test").as_ptr(),
                0x00ca0000,
                0,
                0,
                900,
                800,
                0,
                0,
                instance,
                null_mut(),
            );
            assert_ne!(h, 0);
            WINDOW_GONE.with(|p| p.set(false));
            theme::set_dark(true);
            let mut app = App::new(h);
            app.vault_path = std::env::current_exe().unwrap(); // Login screen
            app.build();
            let pass = app.handle(PASS);
            let peek = app.handle(PEEK_PASS);
            SetWindowTextW(pass, wide("synthetic secret").as_ptr());
            let local = SendMessageW(pass, 0xd6, 3, 0); // EM_POSFROMCHAR, same thread
            assert_ne!(local, 0);
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            let results = std::thread::spawn(move || {
                let send = |to: Hwnd, m: u32, w: usize| SendMessageW(to, m, w, 0);
                // Not waited for, so these arrive as ISMEX_NOTIFY.
                SendNotifyMessageW(h, 0x111, THEME_LIGHT as usize, 0);
                SendNotifyMessageW(peek, 0xf5, 0, 0);
                [
                    send(pass, 0xd6, 3),                  // EM_POSFROMCHAR
                    send(pass, 0xc1, 0),                  // EM_LINELENGTH
                    send(pass, 0x0e, 0),                  // WM_GETTEXTLENGTH
                    send(h, 0x111, THEME_LIGHT as usize), // WM_COMMAND
                    send(peek, 0xf5, 0),                  // BM_CLICK
                    send(h, 0x111, SUBMIT as usize),      // an unlock, then the sync offer
                ]
            });
            pump_until(&results);
            assert_eq!(results.join().unwrap(), [0; 6]);
            assert!(!SYNC_OFFER.with(Cell::get));
            // Message boxes, file dialogs and move loops run message loops
            // that never call accept_queued; the queue filter covers them.
            let hook = filter_queue(h);
            assert_ne!(hook, 0);
            let drain = || {
                let mut msg = Msg::default();
                while PeekMessageW(&mut msg, 0, 0, 0, 1) != 0 {
                    DispatchMessageW(&msg);
                }
            };
            PostMessageW(h, 0x111, THEME_LIGHT as usize, 0);
            PostMessageW(peek, 0xf5, 0, 0); // BM_CLICK
            drain();
            // The modal state comes from the app's own dialog calls and from
            // Windows, so posted "loop ended" notices cannot switch it off.
            modal(|| {
                PostMessageW(h, 0x212, 0, 0); // WM_EXITMENULOOP
                PostMessageW(h, 0x232, 0, 0); // WM_EXITSIZEMOVE
                drain();
                assert!(in_modal());
                assert_eq!(window_proc(h, 0x111, THEME_LIGHT as usize, 0), 0);
            });
            assert!(!in_modal());
            UnhookWindowsHookEx(hook);
            FILTERED_WINDOW.with(|f| f.set(0));
            APP.with(|cell| {
                let b = cell.borrow();
                let a = b.as_ref().unwrap();
                assert!(theme::is_dark(), "foreign WM_COMMAND changed the theme");
                assert!(!a.shown[0], "foreign click unmasked the password");
                assert_ne!(SendMessageW(pass, 0xd2, 0, 0), 0);
                // Posted fakes never reach the window procedure.
                let posted = |hwnd: Hwnd, message: u32| Msg {
                    hwnd,
                    message,
                    ..Msg::default()
                };
                for m in [0x111, 0xf5, 0x0c, 0x1c, 0x2b, 0x186, 0xd6] {
                    assert!(!accept_queued(
                        h,
                        &posted(if m == 0x111 { h } else { pass }, m)
                    ));
                }
                // A posted SC_MOVE would start a move loop; the taskbar's
                // close, minimize and restore still work.
                let syscommand = |command: usize| Msg {
                    hwnd: h,
                    message: 0x112,
                    wparam: command,
                    ..Msg::default()
                };
                assert!(!accept_queued(h, &syscommand(0xf010)));
                assert!(!accept_queued(h, &syscommand(0xf012)));
                for allowed in [0xf060, 0xf020, 0xf120] {
                    assert!(accept_queued(h, &syscommand(allowed)));
                }
                // Input counts only while the app is in front. Whether the
                // hidden test window is depends on how the test was started.
                let front = is_foreground(h);
                assert_eq!(accept_queued(h, &posted(pass, 0x100)), front);
                assert_eq!(accept_queued(h, &posted(peek, 0x201)), front);
                assert!(accept_queued(h, &posted(h, 0x113))); // WM_TIMER
                assert!(accept_queued(h, &posted(0, 0x111))); // not ours
            });
            // Windows sends WM_ENDSESSION from another thread. The lock must
            // still wipe the inputs and keep the paths: its own calls to the
            // controls would otherwise look foreign and be dropped.
            let ended = std::thread::spawn(move || SendMessageW(h, 0x16, 1, 0));
            pump_until(&ended);
            ended.join().unwrap();
            APP.with(|cell| {
                let b = cell.borrow();
                let a = b.as_ref().unwrap();
                assert!(a.read(PASS).unwrap().is_empty(), "lock left the password");
                assert!(a.screen == Screen::Login, "lock lost the vault path");
                assert!(a.status.contains("잠갔습니다"));
            });
            assert_eq!(PENDING_EVENTS.with(Cell::get), 0);
            APP.with(|cell| {
                cell.borrow_mut().take();
            });
            DestroyWindow(h);
            WINDOW_GONE.with(|p| p.set(false));
            PENDING_EVENTS.with(|p| p.set(0));
        }
    }
    /// The App behind the window of a test, borrowed for `f`.
    fn with_app<T>(f: impl FnOnce(&mut App) -> T) -> T {
        APP.with(|cell| f(cell.borrow_mut().as_mut().unwrap()))
    }
    /// Gives the next ask() its answer, and records the question.
    fn answer(asked: &std::rc::Rc<RefCell<Vec<String>>>, yes: bool) {
        let asked = asked.clone();
        ANSWER.with(|a| {
            *a.borrow_mut() = Some(Box::new(move |text: &str| {
                // Asked like a message box: timers see a dialog.
                assert!(in_modal());
                asked.borrow_mut().push(text.to_owned());
                yes
            }))
        });
    }
    /// Timer ticks as they come while another app is in front, its switch
    /// handled a moment ago: nothing locks or ends what is shown on that
    /// account (see auto_lock_choices).
    fn tick(app: &mut App, n: u32) {
        for _ in 0..n {
            app.inactive = true;
            app.away_since = Some(Instant::now());
            app.timer();
        }
    }
    /// B's vault list merges what A uploaded within one poll (every 4th
    /// tick), and only there: not while an entry is edited, not while a
    /// dialog runs. The selection follows its entry by ID or the edit that
    /// replaced it; the 15-second view and copy permission end with any
    /// change to the list, since a merge can put other text under the same
    /// ID. Polling never counts as use.
    #[test]
    fn timer_merges_on_the_vault_list() {
        let _korean = KoreanAfter::hold();
        let dir = test_dir("sync-timer");
        let mut server = Server::default();
        let titles = ["entry 0", "entry 1", "entry 2", "entry 3"];
        let (mut a, vault, key) = two_pcs(&dir, &mut server, &titles);
        let ids: Vec<_> = (0..titles.len()).map(|i| a.entry_id(i).unwrap()).collect();
        let entries = |app: &App| app.session.as_ref().unwrap().entries.len();
        let merged = |added: usize, removed: usize| {
            let (line, _) = sync_line(&SyncNotice::Merged { added, removed });
            line.to_string()
        };
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.vault_path = vault.clone();
            app.key_path = key;
            app.screen = Screen::Login;
            app.build();
            // B opens, in English. The unlock merged version 1 and found it
            // equal, so the check code takes the usual line's place; the key
            // next to the vault still gets its warning, translated as well.
            i18n::set_english(true);
            SetWindowTextW(app.handle(PASS), wide(SYNC_PASSWORD).as_ptr());
            app.command(SUBMIT, 0).unwrap();
            assert!(app.screen == Screen::Vault);
            assert_eq!(app.session.as_ref().unwrap().check_code(), a.check_code());
            assert_eq!(app.sync_badge, Some(SyncBadge::Synced));
            assert!(!SYNC_OFFER.with(Cell::get)); // already syncing
            let code = SyncNotice::Synced {
                code: a.check_code(),
            };
            let line = format!(
                "{}\r\n{}",
                *sync_line(&code).0,
                tr(Placement::SameFolder.message())
            );
            assert_eq!(caption(app.handle(STATUS)), line);
            assert!(!has_korean(&line));
            assert_eq!(GetWindowLongPtrW(app.handle(STATUS), -21), TONE_DANGER);
            // Joined in a buffer of the final size: none grew and freed an
            // unwiped copy of the line.
            assert_eq!(app.status.capacity(), app.status.len());
            // The status keeps its Korean source, so a switch back to Korean
            // translates the warning again (lines built with values keep the
            // language they were shown in).
            app.command(LANG_KO, 0).unwrap();
            let shown = caption(app.handle(STATUS));
            assert_eq!(
                shown.split("\r\n").nth(1),
                Some(Placement::SameFolder.message())
            );
            let pill = "열림 · 동기화됨 · vault.goyo".to_owned();
            assert!(painted(&app).contains(&pill));

            // A deletes entry 0. Entry 2, selected, shown and allowed to be
            // copied, moves up one row and stays selected; the view and the
            // copy permission end.
            app.selected = Some(2);
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.copy_until = Some(Instant::now() + Duration::from_secs(30));
            app.build();
            app.set_toggle(true);
            a.delete(a.entry_index(&ids[0]).unwrap()).unwrap();
            upload(&mut server, &mut a);
            server.pass(&vault);
            let used = app.activity;
            app.sync_ticks = 0;
            tick(&mut app, SYNC_TICKS - 1);
            assert_eq!(entries(&app), 4);
            tick(&mut app, 1);
            assert_eq!(entries(&app), 3);
            let s = app.session.as_ref().unwrap();
            assert_eq!(app.selected, Some(1));
            assert_eq!(app.selected, s.entry_index(&ids[2]));
            assert_eq!(SendMessageW(app.handle(LIST), 0x188, 0, 0), 1); // LB_GETCURSEL
            assert!(app.reveal_until.is_none() && app.copy_until.is_none());
            assert_eq!(GetWindowLongPtrW(app.handle(TOGGLE), -21), theme::TOGGLE);
            assert_eq!(*app.status, merged(0, 1));
            assert_eq!(GetWindowLongPtrW(app.handle(STATUS), -21), TONE_MUTED);
            assert_eq!(app.activity, used);

            // A edits entry 2: the selection follows the edit, and the view
            // of the old text and the copy permission end.
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.copy_until = Some(Instant::now() + Duration::from_secs(30));
            app.build();
            app.set_toggle(true);
            app.page = 1;
            let i = a.entry_index(&ids[2]).unwrap();
            a.put(Some(i), sync_entry("entry 2", "edited on A"))
                .unwrap();
            upload(&mut server, &mut a);
            server.pass(&vault);
            tick(&mut app, SYNC_TICKS);
            let s = app.session.as_ref().unwrap();
            let edited = s.successor(&ids[2]);
            assert!(edited.is_some() && app.selected == edited);
            assert_eq!(&*s.entries[edited.unwrap()].secret, "edited on A");
            assert!(app.reveal_until.is_none() && app.copy_until.is_none());
            assert_eq!(app.page, 0);
            assert_eq!(GetWindowLongPtrW(app.handle(TOGGLE), -21), theme::TOGGLE);
            // Two of B's four entries went in this session: added up, that
            // makes a safety copy, told in the danger tone.
            let copies = syncfile::pre_merge_copies(&syncfile::sync_dir(&vault).unwrap());
            assert_eq!(copies.len(), 1);
            let name = copies[0].file_name().unwrap().to_string_lossy();
            let file = format!("vault.goyo.sync\\{name}");
            let (line, tone) = sync_line(&SyncNotice::MassDelete { removed: 2, file });
            assert_eq!(*app.status, *line);
            assert_eq!(tone, TONE_DANGER);
            assert_eq!(GetWindowLongPtrW(app.handle(STATUS), -21), TONE_DANGER);

            // A adds an entry while B edits the selected one: nothing merges
            // until B is back on the list, so the edit replaces the entry it
            // opened. A dialog holds merges back as well.
            let selected = app.selected;
            let opened = edited.and_then(|i| s.entry_id(i)).unwrap();
            app.command(EDIT, 0).unwrap();
            assert!(app.screen == Screen::Edit && app.editing == selected);
            a.put(None, sync_entry("entry 4", "secret")).unwrap();
            upload(&mut server, &mut a);
            server.pass(&vault);
            tick(&mut app, 2 * SYNC_TICKS);
            assert_eq!(entries(&app), 3);
            SetWindowTextW(app.handle(SECRET), secret_wide("edited on B").as_ptr());
            app.command(SAVE, 0).unwrap();
            let s = app.session.as_ref().unwrap();
            assert_eq!(&*s.entries[selected.unwrap()].secret, "edited on B");
            assert_eq!(s.successor(&opened), selected);
            assert_eq!(app.sync_badge, Some(SyncBadge::Uploading));
            modal(|| tick(&mut app, 2 * SYNC_TICKS));
            assert_eq!(entries(&app), 3);
            tick(&mut app, SYNC_TICKS);
            assert_eq!(entries(&app), 4);
            assert_eq!(app.selected, selected);
            assert_eq!(*app.status, merged(1, 0));

            // B's upload lands: only the pill changes.
            server.pass(&vault);
            tick(&mut app, SYNC_TICKS);
            assert_eq!(app.sync_badge, Some(SyncBadge::Synced));
            assert_eq!(*app.status, merged(1, 0));
            assert!(painted(&app).contains(&pill));

            // A deletes the entry B shows: the selection and the view end.
            upload(&mut server, &mut a);
            app.selected = app.session.as_ref().unwrap().entry_index(&ids[1]);
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.build();
            a.delete(a.entry_index(&ids[1]).unwrap()).unwrap();
            upload(&mut server, &mut a);
            server.pass(&vault);
            tick(&mut app, SYNC_TICKS);
            assert!(app.selected.is_none() && app.reveal_until.is_none());
            assert_eq!(*app.status, merged(0, 1));
            let s = app.session.as_ref().unwrap();
            assert_eq!(s.entries.len(), 3);
            assert_eq!(s.check_code(), a.check_code());
            drop(app);
            DestroyWindow(h);
        }
        drop(a);
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A poll whose save of the merge hits the replace gap of a FAT or exFAT
    /// volume locks the app: the vault file is gone and the merged state is
    /// only in its temp file, which the session writes no more and the next
    /// unlock takes back (spec §5.7).
    #[test]
    fn a_poll_that_hits_the_replace_gap_locks() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("sync-gap");
        let mut server = Server::default();
        let (mut a, vault, key) = two_pcs(&dir, &mut server, &["entry 0"]);
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.vault_path = vault.clone();
            app.key_path = key;
            app.screen = Screen::Login;
            app.build();
            SetWindowTextW(app.handle(PASS), wide(SYNC_PASSWORD).as_ptr());
            app.command(SUBMIT, 0).unwrap();
            assert!(app.screen == Screen::Vault);
            a.put(None, sync_entry("from a", "secret")).unwrap();
            upload(&mut server, &mut a);
            server.pass(&vault);
            app.sync_ticks = 0;
            vault::simulate_replace_gap();
            tick(&mut app, SYNC_TICKS);
            assert!(app.session.is_none() && app.screen == Screen::Login);
            assert_eq!(*app.status, *GAP_KEPT);
            assert_eq!(GetWindowLongPtrW(app.handle(STATUS), -21), TONE_DANGER);
            assert!(!vault.exists() && leftover_temp(&vault));
            // The next unlock takes the merged state back.
            SetWindowTextW(app.handle(PASS), wide(SYNC_PASSWORD).as_ptr());
            app.command(SUBMIT, 0).unwrap();
            let s = app.session.as_ref().unwrap();
            assert_eq!(s.entries.len(), 2);
            assert_eq!(s.check_code(), a.check_code());
            assert!(vault.is_file() && !leftover_temp(&vault));
            drop(app);
            DestroyWindow(h);
        }
        drop(a);
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// Sync is offered right after the user's own unlock of a v1 vault next
    /// to a sync folder, and from nothing else: another program can neither
    /// unlock nor raise the question, not even with the flag already up.
    /// "No" keeps v1 and asks again next time; "yes" while the vault locked
    /// changes nothing; "yes" makes it v2 and starts the upload.
    #[test]
    fn sync_is_offered_after_an_unlock_only() {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn PeekMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32, remove: u32) -> i32;
            fn SendNotifyMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> i32;
        }
        /// Handles what another thread sends, and nothing posted: the filter
        /// matches no queued message.
        fn serve_sent<T>(worker: std::thread::JoinHandle<T>) -> T {
            let peek = || unsafe {
                let mut msg = Msg::default();
                PeekMessageW(&mut msg, 0, 0x7fff, 0x7fff, 0);
            };
            while !worker.is_finished() {
                peek();
                std::thread::sleep(Duration::from_millis(5));
            }
            peek();
            worker.join().unwrap()
        }
        // The question is checked in Korean.
        let _korean = KoreanAfter::hold();
        let dir = test_dir("sync-offer");
        let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
        let mut s = Provision::new()
            .unwrap()
            .finish(&vault, &key, SYNC_PASSWORD)
            .unwrap();
        s.put(None, sync_entry("entry 0", "secret")).unwrap();
        drop(s);
        Server::default().helper(&vault);
        let outgoing = syncfile::sync_dir(&vault).unwrap().join(syncfile::OUTGOING);
        let format = || std::fs::read(&vault).unwrap()[..8].to_vec();
        assert_eq!(format(), b"GOYOVA01");
        let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
        unsafe {
            let name = wide("GoyoSyncOfferTest");
            let instance = GetModuleHandleW(null());
            let wc = WndClass {
                style: 0,
                proc: Some(window_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: 6,
                menu: null(),
                class: name.as_ptr(),
            };
            assert_ne!(RegisterClassW(&wc), 0);
            let h = CreateWindowExW(
                0,
                name.as_ptr(),
                wide("Synthetic sync offer test").as_ptr(),
                0x00ca0000,
                0,
                0,
                900,
                800,
                0,
                0,
                instance,
                null_mut(),
            );
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            WINDOW_GONE.with(|p| p.set(false));
            let mut app = App::new(h);
            app.vault_path = vault.clone();
            app.key_path = key.clone();
            app.screen = Screen::Login;
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            let type_password = || {
                with_app(|a| SetWindowTextW(a.handle(PASS), wide(SYNC_PASSWORD).as_ptr()));
            };
            let unlock = || SendMessageW(h, 0x111, SUBMIT as usize, 0);

            // Another program: no unlock, no question.
            type_password();
            answer(&asked, true);
            let worker = std::thread::spawn(move || {
                SendNotifyMessageW(h, 0x111, SUBMIT as usize, 0);
                SendMessageW(h, 0x111, SUBMIT as usize, 0)
            });
            assert_eq!(serve_sent(worker), 0);
            assert!(with_app(|a| a.session.is_none()));
            assert!(!SYNC_OFFER.with(Cell::get) && asked.borrow().is_empty());

            // The user's unlock asks once, right after it, about this folder.
            // "No" keeps v1 and the usual line.
            answer(&asked, false);
            unlock();
            assert_eq!(asked.borrow().len(), 1);
            assert!(asked.borrow()[0].starts_with("이 금고 옆에 동기화 폴더(vault.goyo.sync)가"));
            assert!(ANSWER.with(|a| a.borrow().is_none()) && !SYNC_OFFER.with(Cell::get));
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(s.format() == Format::V1 && a.sync_badge.is_none());
                assert!(a.status.starts_with("잠금 해제됨 · "));
            });
            assert_eq!(format(), b"GOYOVA01");
            assert!(!outgoing.exists());
            SendMessageW(h, 0, 0, 0); // only an unlock asks
            assert_eq!(asked.borrow().len(), 1);

            // A flag left up is not taken by another program's message.
            answer(&asked, true);
            SYNC_OFFER.with(|f| f.set(true));
            let worker = std::thread::spawn(move || {
                SendNotifyMessageW(h, 0, 0, 0);
                SendMessageW(h, 0, 0, 0)
            });
            serve_sent(worker);
            assert!(SYNC_OFFER.with(Cell::get) && asked.borrow().len() == 1);
            SYNC_OFFER.with(|f| f.set(false));
            ANSWER.with(|a| a.borrow_mut().take());

            // "Yes" counts only for the vault it asked about, still open.
            with_app(|a| a.lock("synthetic lock", true));
            type_password();
            ANSWER.with(|a| {
                *a.borrow_mut() = Some(Box::new(|_: &str| {
                    with_app(|a| a.lock("synthetic lock", true));
                    true
                }))
            });
            unlock();
            assert!(with_app(|a| a.session.is_none()));
            assert_eq!(format(), b"GOYOVA01");
            assert!(!outgoing.exists());
            assert_eq!(
                with_app(|a| a.status.to_string()),
                "대화상자가 열린 동안 잠겼습니다. 다시 인증하세요."
            );

            // Nor once its folder is gone: the vault stays v1.
            type_password();
            let dir = syncfile::sync_dir(&vault).unwrap();
            ANSWER.with(|a| {
                *a.borrow_mut() = Some(Box::new(move |_: &str| {
                    std::fs::remove_dir_all(&dir).unwrap();
                    true
                }))
            });
            unlock();
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().format() == Format::V1);
                assert!(a.sync_badge.is_none() && a.status.starts_with("잠금 해제됨 · "));
            });
            assert_eq!(format(), b"GOYOVA01");
            with_app(|a| a.lock("synthetic lock", true));
            Server::default().helper(&vault);

            // "Yes": v2 from now on, the first upload made from no server
            // version, and the pill shows it under way.
            type_password();
            answer(&asked, true);
            unlock();
            assert_eq!(asked.borrow().len(), 2);
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().format() == Format::V2);
                assert_eq!(a.sync_badge, Some(SyncBadge::Uploading));
                assert_eq!(*sync_line(&SyncNotice::SyncOn).0, *a.status);
                assert!(painted(a).contains(&"열림 · 올리는 중 · vault.goyo".to_owned()));
            });
            assert_eq!(format(), b"GOYOVA02");
            let bytes = std::fs::read(&outgoing).unwrap();
            let (base, blob) = syncfile::parse_outgoing(&bytes).unwrap();
            assert!(base == 0 && blob.starts_with(b"GOYOVA02"));

            // Once v2, an unlock asks nothing.
            with_app(|a| a.lock("synthetic lock", true));
            type_password();
            answer(&asked, false);
            unlock();
            assert!(with_app(|a| a.session.is_some()));
            assert!(ANSWER.with(|a| a.borrow_mut().take()).is_some());
            assert_eq!(asked.borrow().len(), 2);

            APP.with(|cell| {
                cell.borrow_mut().take();
            });
            DestroyWindow(h);
            WINDOW_GONE.with(|p| p.set(false));
            PENDING_EVENTS.with(|p| p.set(0));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// SUBMIT on Login and Password runs in phases through window_proc. A
    /// lock that arrives between the phases drops the flow before any key
    /// derivation. An unlock that finds the vault and key files only as the
    /// temp files of a cut-off save takes them back and says so; a wrong
    /// password then gets the leftover-temp advice, not just a failure.
    #[test]
    fn phased_submit_and_temp_recovery() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("phased");
        let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
        let (pass, next) = ("synthetic phased password", "synthetic phased change");
        drop(
            Provision::new()
                .unwrap()
                .finish(&vault, &key, pass)
                .unwrap(),
        );
        let vault_temp = dir.join(format!("vault.goyo.{:032x}.goyotmp", 0xabc));
        let key_temp = dir.join(format!("vault.goyokey.{:032x}.goyotmp", 0xdef));
        std::fs::rename(&vault, &vault_temp).unwrap();
        std::fs::rename(&key, &key_temp).unwrap();
        unsafe {
            let name = wide("GoyoPhasedTest");
            let instance = GetModuleHandleW(null());
            let wc = WndClass {
                style: 0,
                proc: Some(window_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: 6,
                menu: null(),
                class: name.as_ptr(),
            };
            assert_ne!(RegisterClassW(&wc), 0);
            let h = CreateWindowExW(
                0,
                name.as_ptr(),
                wide("Synthetic phased test").as_ptr(),
                0x00ca0000,
                0,
                0,
                900,
                800,
                0,
                0,
                instance,
                null_mut(),
            );
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            WINDOW_GONE.with(|p| p.set(false));
            let mut app = App::new(h);
            app.vault_path = vault.clone();
            app.key_path = key.clone();
            // Only temp files are left, and still the vault opens from Login.
            app.show(app.home());
            assert!(app.screen == Screen::Login);
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            let type_in = |id: i32, text: &str| {
                with_app(|a| SetWindowTextW(a.handle(id), wide(text).as_ptr()));
            };
            let submit = |id: i32| SendMessageW(h, 0x111, id as usize, 0);

            // A wrong password: the key file's temp copy may need the
            // factors of the change that left it.
            type_in(PASS, "wrong synthetic password");
            submit(SUBMIT);
            with_app(|a| {
                assert!(a.session.is_none() && a.failed == 1);
                assert_eq!(*a.status, *LEFTOVER_TEMP);
                a.retry = Instant::now();
            });
            assert!(vault_temp.exists() && key_temp.exists());

            // A lock between the phases: no unlock, the password is wiped.
            type_in(PASS, pass);
            let derived = crypto::derive_count();
            PENDING_EVENTS.with(|p| p.set(2));
            submit(SUBMIT);
            assert_eq!(crypto::derive_count(), derived);
            with_app(|a| {
                assert!(a.session.is_none() && a.screen == Screen::Login);
                assert!(a.read(PASS).unwrap().is_empty());
                assert_eq!(*a.status, *"화면 또는 시스템 세션 변경으로 잠갔습니다.");
            });
            assert!(vault_temp.exists() && key_temp.exists());

            // Enter: both files come back under their names.
            type_in(PASS, pass);
            submit(1);
            with_app(|a| {
                assert!(a.session.is_some() && a.screen == Screen::Vault);
                let lines: Vec<&str> = a.status.split("\r\n").collect();
                assert_eq!(
                    lines,
                    [
                        "금고 파일이 없어, 저장이 끊기며 남은 임시 파일에서 복구했습니다.",
                        Placement::SameFolder.message()
                    ]
                );
                assert_eq!(a.key_path, a.session.as_ref().unwrap().key_path);
            });
            assert!(vault.is_file() && key.is_file());
            assert!(!vault_temp.exists() && !key_temp.exists());

            // A password change runs through the phases as well: S-ROTATE
            // is answered yes, and S-BACKUP, unanswered, no.
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| a.command(KEY_PASSWORD, 0)).unwrap();
            type_in(CURRENT_PASS, pass);
            type_in(PASS, next);
            type_in(CONFIRM, next);
            ANSWER.with(|a| *a.borrow_mut() = Some(Box::new(|_: &str| true)));
            submit(SUBMIT);
            with_app(|a| {
                assert!(a.screen == Screen::Vault && a.failed == 0);
                assert!(a.status.starts_with(PASSWORD_CHANGED));
                assert!(a.flow.is_none());
            });
            with_app(|a| a.lock("synthetic lock", true));
            type_in(PASS, next);
            submit(SUBMIT);
            assert!(with_app(|a| a.session.is_some()));

            // A save cut off by the replace gap locks, so that the next
            // unlock takes the temp file back.
            with_app(|a| a.error(GAP_KEPT));
            with_app(|a| {
                assert!(a.session.is_none() && a.screen == Screen::Login);
                assert_eq!(*a.status, *GAP_KEPT);
            });

            // The vault file is gone and its only temp file does not open
            // with this key: the right password gets the leftover-temp
            // advice without a retry delay.
            let mut torn = std::fs::read(&vault).unwrap();
            *torn.last_mut().unwrap() ^= 1;
            std::fs::rename(&vault, dir.join("moved.goyo")).unwrap();
            std::fs::write(&vault_temp, &torn).unwrap();
            type_in(PASS, next);
            submit(SUBMIT);
            with_app(|a| {
                assert!(a.session.is_none() && a.failed == 0);
                assert!(a.retry <= Instant::now());
                assert_eq!(*a.status, *LEFTOVER_TEMP);
            });
            assert!(vault_temp.exists() && !vault.exists());

            APP.with(|cell| {
                cell.borrow_mut().take();
            });
            DestroyWindow(h);
            WINDOW_GONE.with(|p| p.set(false));
            PENDING_EVENTS.with(|p| p.set(0));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A login whose vault file is under an older key of a KF2 key file asks
    /// S-OLDER between the phases, with no borrow of the app held: no is no
    /// failed attempt, a lock during the question drops the flow, and yes
    /// opens the file and saves it under the current key. A refusal of the
    /// files themselves (a security-key file here) and a password change
    /// this build cannot make start no retry delay either (spec §5.1,
    /// §9.2a, §14.8-11).
    #[test]
    fn older_vault_files_ask_between_the_phases() {
        use goyo_vault::vault::keyfile::{Bundle, Kind, Plan, Spec, seal};
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("older");
        let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
        let pass = "synthetic older login password";
        let (id, dk1, dk0) = ([0x5a; 16], [0x91; 32], [0x90; 32]);
        // A key file a later build wrote (keys DK1, then the ID key DK0),
        // and a vault file still in 0.8's format under the ID key.
        let spec = Spec {
            vault_id: id,
            epoch: 2,
            kind: Kind::Password,
            next: 1,
            pw_id: [3; 16],
            loss: 0,
            tombstones: Vec::new(),
            resume: [0; 32],
        };
        let bundle = Bundle::new(&[dk1, dk0]).unwrap();
        let (key_bytes, _) = seal(&spec, &bundle, pass, Plan::PasswordOnly).unwrap();
        std::fs::write(&key, &key_bytes).unwrap();
        let mut older = [&b"GOYOVA01"[..], &id, &[0x24; 24]].concat();
        let plain = [0u8; 12]; // the old OTP watermark and no entries
        older.extend(crypto::seal(&dk0, &[0x24; 24], &older.clone(), &plain).unwrap());
        std::fs::write(&vault, &older).unwrap();
        unsafe {
            let name = wide("GoyoOlderTest");
            let instance = GetModuleHandleW(null());
            let wc = WndClass {
                style: 0,
                proc: Some(window_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: 6,
                menu: null(),
                class: name.as_ptr(),
            };
            assert_ne!(RegisterClassW(&wc), 0);
            let h = CreateWindowExW(
                0,
                name.as_ptr(),
                wide("Synthetic older test").as_ptr(),
                0x00ca0000,
                0,
                0,
                900,
                800,
                0,
                0,
                instance,
                null_mut(),
            );
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            WINDOW_GONE.with(|p| p.set(false));
            let mut app = App::new(h);
            app.vault_path = vault.clone();
            app.key_path = key.clone();
            app.show(app.home());
            assert!(app.screen == Screen::Login);
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            let type_in = |id: i32, text: &str| {
                with_app(|a| SetWindowTextW(a.handle(id), wide(text).as_ptr()));
            };
            let submit = |id: i32| SendMessageW(h, 0x111, id as usize, 0);
            let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
            let ask_then = |then: fn() -> bool| {
                let asked = asked.clone();
                ANSWER.with(|a| {
                    *a.borrow_mut() = Some(Box::new(move |text: &str| {
                        // Asked between the phases: the app is free.
                        assert!(APP.with(|cell| cell.try_borrow_mut().is_ok()));
                        asked.borrow_mut().push(text.to_owned());
                        then()
                    }))
                });
            };

            // No: not opened, no key derived, no failed attempt.
            type_in(PASS, pass);
            ask_then(|| false);
            let derived = crypto::derive_count();
            submit(SUBMIT);
            assert_eq!(crypto::derive_count(), derived);
            with_app(|a| {
                assert!(a.session.is_none() && a.failed == 0);
                assert!(a.retry <= Instant::now());
                assert_eq!(*a.status, *OLDER_DECLINED);
            });
            assert_eq!(asked.borrow().as_slice(), [OLDER_QUESTION]);
            assert_eq!(std::fs::read(&vault).unwrap(), older);

            // A lock while the question is open: phase 3 does nothing.
            type_in(PASS, pass);
            ask_then(|| {
                with_app(|a| a.lock("synthetic lock", true));
                true
            });
            submit(SUBMIT);
            assert_eq!(crypto::derive_count(), derived);
            with_app(|a| assert!(a.session.is_none() && a.read(PASS).unwrap().is_empty()));
            assert_eq!(std::fs::read(&vault).unwrap(), older);

            // Yes: opened and saved under the current key, in danger tone.
            type_in(PASS, pass);
            ask_then(|| true);
            submit(SUBMIT);
            with_app(|a| {
                assert!(a.session.is_some() && a.screen == Screen::Vault);
                let first = a.status.split("\r\n").next().unwrap().to_owned();
                assert_eq!(first, *key_line(&KeyNotice::OlderAccepted).0);
                assert_eq!(GetWindowLongPtrW(a.handle(STATUS), -21), TONE_DANGER);
            });
            assert_eq!(&std::fs::read(&vault).unwrap()[..8], b"GOYOVA03");
            assert_eq!(asked.borrow().len(), 3);

            // A KF2 key file's password changes as well (spec §5.5): a new
            // key file, and the vault file under its new key.
            // S-ROTATE first; the status gives the new key code.
            let changed = "another synthetic older password";
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| a.command(KEY_PASSWORD, 0)).unwrap();
            type_in(CURRENT_PASS, pass);
            type_in(PASS, changed);
            type_in(CONFIRM, changed);
            ask_then(|| true);
            submit(SUBMIT);
            with_app(|a| {
                assert!(a.session.is_some() && a.failed == 0 && a.screen == Screen::Vault);
                let lines: Vec<&str> = a.status.split("\r\n").collect();
                assert_eq!(lines[0], PASSWORD_CHANGED);
                let code = a.session.as_ref().unwrap().key_code().unwrap();
                assert!(code.starts_with("E3 · "), "{code}");
                assert_eq!(lines[1], fill(CODE_LINE, &[&code]));
            });
            assert_ne!(std::fs::read(&key).unwrap(), key_bytes);
            assert_eq!(asked.borrow()[3], ROTATE_QUESTION);

            // The next login asks nothing: the vault file is current.
            with_app(|a| a.lock("synthetic lock", true));
            type_in(PASS, changed);
            submit(SUBMIT);
            assert!(with_app(|a| a.session.is_some()));
            assert_eq!(asked.borrow().len(), 4);

            // A security-key file: refused on its magic, before any key
            // derivation and with no retry delay. The files pinned by
            // scripts/make_key_fixtures.py, well-formed, damaged and newer,
            // and one that is only the magic. A path typed in (here: a file
            // swapped under it) gets the refusal at once, also when its file
            // holds a TOTP secret of the removed OTP (the GOYOKH01 fixture).
            with_app(|a| a.lock("synthetic lock", true));
            #[cfg(not(feature = "security-key"))]
            let junk = [&b"GOYOKH01"[..], &[0; 300]].concat();
            #[cfg(not(feature = "security-key"))]
            let files: [(&[u8], &str); 5] = {
                use vault::keyfile::{NO_SECURITY_KEY_SUPPORT, NO_SECURITY_KEY_SUPPORT_DAMAGED};
                [
                    (
                        include_bytes!("../tests/fixtures/goyokh01.goyokey"),
                        NO_SECURITY_KEY_SUPPORT,
                    ),
                    (
                        include_bytes!("../tests/fixtures/goyoks01.goyokey"),
                        NO_SECURITY_KEY_SUPPORT,
                    ),
                    (
                        include_bytes!("../tests/fixtures/goyoks01-truncated.goyokey"),
                        NO_SECURITY_KEY_SUPPORT_DAMAGED,
                    ),
                    (
                        include_bytes!("../tests/fixtures/goyokh02.goyokey"),
                        NO_SECURITY_KEY_SUPPORT_DAMAGED,
                    ),
                    (&junk, NO_SECURITY_KEY_SUPPORT_DAMAGED),
                ]
            };
            // The security-key build reads them in full instead: a
            // well-formed one of another vault than this vault file is
            // refused by the precheck on its vault ID (the touch its own
            // vault needs is vault.rs's test), a later magic is a newer key
            // file; neither before any key derivation, nor a failure.
            #[cfg(feature = "security-key")]
            let files: [(&[u8], &str); 2] = [
                (
                    include_bytes!("../tests/fixtures/goyoks01.goyokey"),
                    vault::OTHER_VAULT,
                ),
                (
                    include_bytes!("../tests/fixtures/goyokh02.goyokey"),
                    vault::keyfile::NEWER_KEY_FORMAT,
                ),
            ];
            for (bytes, refusal) in files {
                std::fs::write(&key, bytes).unwrap();
                type_in(PASS, pass);
                let derived = crypto::derive_count();
                submit(SUBMIT);
                assert_eq!(crypto::derive_count(), derived);
                with_app(|a| {
                    assert!(a.session.is_none() && a.failed == 0);
                    assert!(a.retry <= Instant::now());
                    assert_eq!(*a.status, *refusal);
                });
            }

            APP.with(|cell| {
                cell.borrow_mut().take();
            });
            DestroyWindow(h);
            WINDOW_GONE.with(|p| p.set(false));
            PENDING_EVENTS.with(|p| p.set(0));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// DELETE removes the entry the user confirmed, found by its ID after
    /// the question, even if the list moved meanwhile; one deleted on the
    /// other PC meanwhile is not replaced by its neighbour. Sync adds no
    /// command: what each screen accepts is as before.
    #[test]
    fn delete_finds_the_entry_by_id() {
        let always = [THEME_DARK, THEME_LIGHT, LANG_KO, LANG_EN];
        // The security-key build's own commands on these screens.
        #[cfg(feature = "security-key")]
        let sk = |screen: Screen| -> Vec<i32> {
            use keys_ui::*;
            match screen {
                Screen::Create => vec![SK_TOGGLE],
                Screen::Restore => vec![RESTORE_FETCHED],
                Screen::Keys => vec![
                    KEY_ON,
                    KEY_ADD,
                    KEY_OFF,
                    KEY_RESEED,
                    KEY_ACCEPT,
                    KEY_PAIR,
                    KEY_LOST,
                    KEY_REMOVE,
                    LOST_REDO,
                    KEYON_PWCHANGE,
                    KEY_LIST,
                    PASS,
                    CONFIRM,
                    PEEK_PASS,
                    PEEK_CONFIRM,
                    KEYSYNC_ON,
                    KEYSYNC_OFF,
                    KEY_REUPLOAD,
                    GATE_DROP,
                    GATE_SUPERSEDE,
                    KEY_ROLLOUT_DONE,
                    KEY_AUTO,
                    KEY_SERVER_TAKE,
                ],
                _ => Vec::new(),
            }
        };
        let commands = |app: &App, ids: &[i32]| {
            let mut want: Vec<i32> = ids.iter().chain(&always).copied().collect();
            #[cfg(feature = "security-key")]
            want.extend(sk(app.screen));
            want.sort();
            let allowed: Vec<i32> = (0..=400).filter(|&id| app.allows(id)).collect();
            assert_eq!(allowed, want, "{}", app.screen as u8);
        };
        let dir = test_dir("sync-delete");
        let mut app = App::new(0);
        for (screen, ids) in [
            (Screen::Welcome, &[CREATE, OPEN, RESTORE][..]),
            (
                Screen::Login,
                &[
                    CREATE, RESTORE, BACK, SUBMIT, BROWSE_V, BROWSE_K, VPATH, KPATH, PASS,
                    PEEK_PASS,
                ],
            ),
            (
                Screen::Create,
                &[
                    BACK,
                    SUBMIT,
                    BROWSE_V,
                    BROWSE_K,
                    VPATH,
                    KPATH,
                    PASS,
                    CONFIRM,
                    PEEK_PASS,
                    PEEK_CONFIRM,
                ],
            ),
            (
                Screen::Restore,
                &[
                    BACK, SUBMIT, BROWSE_V, BROWSE_K, BROWSE_D, VPATH, KPATH, DEST, PASS, PEEK_PASS,
                ],
            ),
            // The vault fetched from the server (spec §2.29): no key path,
            // and the links to the login and to Restore.
            #[cfg(feature = "security-key")]
            (
                Screen::Fetched,
                &[SUBMIT, BROWSE_V, VPATH, PASS, PEEK_PASS, OPEN, RESTORE][..],
            ),
        ] {
            app.screen = screen;
            commands(&app, ids);
        }
        for screen in [
            Screen::Vault,
            Screen::Edit,
            Screen::Password,
            Screen::Keys,
            Screen::Adopt,
            #[cfg(feature = "security-key")]
            Screen::Pair,
            #[cfg(feature = "security-key")]
            Screen::LostKey,
            #[cfg(feature = "security-key")]
            Screen::KeyRemove,
            #[cfg(feature = "security-key")]
            Screen::Review,
        ] {
            app.screen = screen;
            assert!((0..=400).all(|id| !app.allows(id)), "no vault open");
        }
        // Create has no PIN toggle: the keys' PIN is always used (spec
        // §2.28), whatever the key toggle says.
        #[cfg(feature = "security-key")]
        {
            app.screen = Screen::Create;
            for on in [true, false] {
                app.toggles.create = on;
                assert!(app.allows(keys_ui::SK_TOGGLE));
                assert!(!app.allows(158) && !app.allows(152));
            }
        }
        app.session = Some(synthetic_session(&dir, "synthetic allows password"));
        let auto_lock: Vec<i32> = (AUTO_LOCK..=AUTO_LOCK_LAST).collect();
        let presets: Vec<i32> = (PRESET..=PRESET_LAST).collect();
        let vault = [
            LOCK,
            BACKUP,
            KEYBACKUP,
            CHANGE,
            LIST,
            NEW,
            EDIT,
            DELETE,
            REVEAL,
            TOGGLE,
            COPY,
            PREVIOUS,
            NEXT,
            OTP_COPY,
            OTP_SECRET_COPY,
            OTP_QR,
        ];
        let edit = [
            TITLE,
            KIND,
            SECRET,
            NOTES,
            OTP_FIELD,
            OTP_ISSUER,
            OTP_ACCOUNT,
            PEEK_OTP,
            SAVE,
            CANCEL,
        ];
        for (screen, ids) in [
            (Screen::Vault, [&vault[..], &auto_lock].concat()),
            (Screen::Edit, [&edit[..], &presets].concat()),
            (
                Screen::Password,
                vec![
                    PASS,
                    CONFIRM,
                    CURRENT_PASS,
                    PEEK_PASS,
                    PEEK_CONFIRM,
                    PEEK_CURRENT,
                    SUBMIT,
                    CANCEL,
                ],
            ),
            (
                Screen::Keys,
                vec![
                    BACK,
                    KEY_PASSWORD,
                    KEY_ADOPT,
                    KEYBACKUP,
                    KEY_OVERRIDE_HEAD,
                    KEY_LOCAL_OK,
                    PENDING_FORGET,
                    CURRENT_PASS,
                    PEEK_CURRENT,
                ],
            ),
            (
                Screen::Adopt,
                vec![BACK, SUBMIT, CURRENT_PASS, PEEK_CURRENT],
            ),
            #[cfg(feature = "security-key")]
            (
                Screen::Pair,
                [
                    &[BACK, SUBMIT, CURRENT_PASS, PEEK_CURRENT][..],
                    &(keys_ui::KEY_PICK_ITEM..=keys_ui::KEY_PICK_LAST).collect::<Vec<_>>(),
                ]
                .concat(),
            ),
            #[cfg(feature = "security-key")]
            (
                Screen::LostKey,
                [
                    &[
                        BACK,
                        SUBMIT,
                        CURRENT_PASS,
                        PEEK_CURRENT,
                        PASS,
                        CONFIRM,
                        PEEK_PASS,
                        PEEK_CONFIRM,
                        keys_ui::LOSS_DATE,
                        keys_ui::LOSS_YES,
                        keys_ui::LOSS_NO,
                        keys_ui::LOSS_UNSURE,
                        keys_ui::LOSS_PWCHANGE,
                    ][..],
                    &(keys_ui::KEY_PICK_ITEM..=keys_ui::KEY_PICK_LAST).collect::<Vec<_>>(),
                    &(keys_ui::SHARED_ITEM..=keys_ui::SHARED_LAST).collect::<Vec<_>>(),
                ]
                .concat(),
            ),
            #[cfg(feature = "security-key")]
            (
                Screen::KeyRemove,
                [
                    &[
                        BACK,
                        SUBMIT,
                        CURRENT_PASS,
                        PEEK_CURRENT,
                        PASS,
                        CONFIRM,
                        PEEK_PASS,
                        PEEK_CONFIRM,
                        keys_ui::REMOVE_PWCHANGE,
                    ][..],
                    &(keys_ui::KEY_PICK_ITEM..=keys_ui::KEY_PICK_LAST).collect::<Vec<_>>(),
                ]
                .concat(),
            ),
            #[cfg(feature = "security-key")]
            (
                Screen::Review,
                vec![
                    BACK,
                    keys_ui::REVIEW_OK,
                    keys_ui::REVIEW_LATER,
                    keys_ui::REVIEW_LIST,
                    keys_ui::LOSS_DATE,
                ],
            ),
        ] {
            app.screen = screen;
            commands(&app, &ids);
        }
        drop(app);

        let mut server = Server::default();
        let titles = ["entry 0", "entry 1", "entry 2", "entry 3"];
        let (mut a, vault, key) = two_pcs(&dir, &mut server, &titles);
        let ids: Vec<_> = (0..titles.len()).map(|i| a.entry_id(i).unwrap()).collect();
        let b = Session::unlock(&vault, &key, SYNC_PASSWORD).unwrap();
        let titles_of = |app: &App| -> Vec<String> {
            let s = app.session.as_ref().unwrap();
            s.entries.iter().map(|e| e.title.to_string()).collect()
        };
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            WINDOW_GONE.with(|p| p.set(false));
            let mut app = App::new(h);
            app.session = Some(b);
            app.screen = Screen::Vault;
            app.selected = Some(2);
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));

            // B asks to delete entry 2 while A's deletion of entry 0 waits.
            a.delete(a.entry_index(&ids[0]).unwrap()).unwrap();
            upload(&mut server, &mut a);
            server.pass(&vault);
            ANSWER.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(|text: &str| {
                    assert_eq!(
                        text,
                        "선택한 항목을 삭제할까요? 기존 백업 사본은 삭제되지 않습니다."
                    );
                    with_app(|a| {
                        // No merge while the question is open...
                        a.sync_ticks = 0;
                        tick(a, 2 * SYNC_TICKS);
                        assert_eq!(a.session.as_ref().unwrap().entries.len(), 4);
                        // ...and had the list moved under the selection, the
                        // index would now point at entry 3.
                        a.session.as_mut().unwrap().poll_sync().unwrap();
                        assert_eq!(a.session.as_ref().unwrap().entries.len(), 3);
                        assert_eq!(a.selected, Some(2));
                    });
                    true
                }))
            });
            modal_command(h, DELETE).unwrap();
            with_app(|a| {
                assert_eq!(titles_of(a), ["entry 1", "entry 3"]);
                assert!(a.selected.is_none());
                assert_eq!(*a.status, "항목을 삭제했습니다.");
                assert_eq!(a.sync_badge, Some(SyncBadge::Uploading));
                a.selected = Some(1); // entry 3
                a.build();
            });

            // Entry 3 is deleted on A while B asks: B deletes nothing else.
            a.delete(a.entry_index(&ids[3]).unwrap()).unwrap();
            upload(&mut server, &mut a);
            server.pass(&vault);
            ANSWER.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(|_: &str| {
                    with_app(|a| a.session.as_mut().unwrap().poll_sync());
                    true
                }))
            });
            assert_eq!(modal_command(h, DELETE), Err("항목 선택 오류"));
            with_app(|a| assert_eq!(titles_of(a), ["entry 1"]));

            APP.with(|cell| {
                cell.borrow_mut().take();
            });
            DestroyWindow(h);
            WINDOW_GONE.with(|p| p.set(false));
            PENDING_EVENTS.with(|p| p.set(0));
        }
        drop(a);
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The self-check's planting test reports a DLL loaded from the exe's
    /// folder. A renamed copy of a System32 DLL stands in for a planted one.
    #[test]
    fn dll_beside_exe_is_reported() {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LoadLibraryW(name: *const u16) -> isize;
            fn FreeLibrary(module: isize) -> i32;
        }
        assert!(modules_beside_exe().is_empty());
        let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let planted = dir.join(format!("goyo-plant-test-{}.dll", std::process::id()));
        std::fs::copy(system.join("wtsapi32.dll"), &planted).unwrap();
        unsafe {
            let module = LoadLibraryW(wide(&planted.to_string_lossy()).as_ptr());
            assert_ne!(module, 0);
            let found = modules_beside_exe();
            FreeLibrary(module);
            let _ = std::fs::remove_file(&planted);
            assert_eq!(found.len(), 1, "{found:?}");
            assert!(found[0].file_name() == planted.file_name());
        }
        assert!(modules_beside_exe().is_empty());
    }
    /// Threads started after launch (the test harness has several) get the
    /// same restricted DACL as the UI thread.
    #[test]
    fn later_threads_are_restricted() {
        let (stop, wait) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || wait.recv().ok());
        assert!(restrict_threads());
        let start = Instant::now();
        assert!(restrict_threads()); // the timer's per-tick cost
        let cost = start.elapsed();
        assert_eq!(open_threads(), 0);
        assert!(cost < Duration::from_millis(10), "{cost:?}"); // runs every 500 ms
        stop.send(()).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn close_and_timer_do_not_rebuild_destroyed_windows() {
        // Exercise the actual window procedure with a synthetic reentrant
        // deactivation during destruction. No visible window or vault data.
        unsafe extern "system" fn test_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
            unsafe {
                if m == 2 {
                    window_proc(h, 0x1c, 0, 0);
                }
                window_proc(h, m, w, l)
            }
        }
        unsafe {
            let name = wide("GoyoCloseRegressionTest");
            let instance = GetModuleHandleW(null());
            let wc = WndClass {
                style: 0,
                proc: Some(test_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: 6,
                menu: null(),
                class: name.as_ptr(),
            };
            assert_ne!(RegisterClassW(&wc), 0);
            for timer in [false, true] {
                WINDOW_GONE.with(|p| p.set(false));
                PENDING_EVENTS.with(|p| p.set(0));
                let h = CreateWindowExW(
                    0,
                    name.as_ptr(),
                    wide("Synthetic close test").as_ptr(),
                    0x00ca0000,
                    0,
                    0,
                    900,
                    800,
                    0,
                    0,
                    instance,
                    null_mut(),
                );
                assert_ne!(h, 0);
                let mut app = App::new(h);
                app.build();
                app.closing = timer;
                APP.with(|cell| *cell.borrow_mut() = Some(app));
                SendMessageW(h, if timer { 0x113 } else { 0x10 }, 0, 0);
                assert_eq!(IsWindow(h), 0);
                assert!(WINDOW_GONE.with(Cell::get));
                assert_eq!(PENDING_EVENTS.with(Cell::get), 0);
                APP.with(|cell| {
                    cell.borrow_mut().take();
                });
            }
            WINDOW_GONE.with(|p| p.set(false));
            PENDING_EVENTS.with(|p| p.set(0));
        }
    }
    /// A window that runs window_proc, as the real one does, for the flow
    /// tests; the app goes behind it with APP.
    unsafe fn flow_window(name: &str) -> Hwnd {
        unsafe {
            let class = wide(name);
            let instance = GetModuleHandleW(null());
            let wc = WndClass {
                style: 0,
                proc: Some(window_proc),
                cls_extra: 0,
                wnd_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: 6,
                menu: null(),
                class: class.as_ptr(),
            };
            assert_ne!(RegisterClassW(&wc), 0);
            let h = CreateWindowExW(
                0,
                class.as_ptr(),
                wide("Synthetic flow test").as_ptr(),
                0x00ca0000,
                0,
                0,
                900,
                800,
                0,
                0,
                instance,
                null_mut(),
            );
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            WINDOW_GONE.with(|p| p.set(false));
            h
        }
    }
    /// Takes the app away and closes a flow window.
    unsafe fn close_flow_window(h: Hwnd) {
        APP.with(|cell| {
            cell.borrow_mut().take();
        });
        INPUT_ANSWER.with(|i| i.borrow_mut().take());
        ANSWER.with(|a| a.borrow_mut().take());
        unsafe {
            DestroyWindow(h);
        }
        WINDOW_GONE.with(|p| p.set(false));
        PENDING_EVENTS.with(|p| p.set(0));
    }
    /// Answers every input dialog until taken away; records each text.
    fn inputs(
        asked: &std::rc::Rc<RefCell<Vec<String>>>,
        mut answer: impl FnMut(usize, &str, &InputKind) -> InputAnswer + 'static,
    ) {
        let asked = asked.clone();
        INPUT_ANSWER.with(|i| {
            *i.borrow_mut() = Some(Box::new(move |text: &str, kind: &InputKind| {
                // Asked inside the flow, as a dialog, with the app free.
                assert!(in_modal());
                assert!(APP.with(|cell| cell.try_borrow_mut().is_ok()));
                asked.borrow_mut().push(text.to_owned());
                let n = asked.borrow().len();
                answer(n, text, kind)
            }))
        });
    }
    /// A typed password, as the dialog returns it.
    fn typed(text: &str) -> InputAnswer {
        InputAnswer::Password(Zeroizing::new(text.to_owned()))
    }
    /// Two PCs' key files of one vault, each changed from the same first key
    /// to its own password (a fork, spec §5.8), sealed with the Test KDF
    /// profile; and PC B's vault file still under that first key. B's
    /// session opens and writes its anchor line. Returns the session and
    /// A's key file.
    fn fork(dir: &Path) -> (Session, PathBuf) {
        use goyo_vault::vault::keyfile::{Bundle, Kind, Plan, Spec, seal};
        let (id, dk0) = ([0x6b; 16], [0x70; 32]);
        let key_file = |name: &str, dk: [u8; 32], password: &str| {
            let spec = Spec {
                vault_id: id,
                epoch: 1,
                kind: Kind::Password,
                next: 1,
                pw_id: *crypto::random::<16>().unwrap(),
                loss: 0,
                tombstones: Vec::new(),
                resume: [0; 32],
            };
            let bundle = Bundle::new(&[dk, dk0]).unwrap();
            let (bytes, _) = seal(&spec, &bundle, password, Plan::PasswordOnly).unwrap();
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let a_key = key_file("a.goyokey", [0x71; 32], FORK_A);
        let b_key = key_file("vault.goyokey", [0x72; 32], FORK_B);
        // GOYOVA01 under the first key: the old OTP watermark 0 and no
        // entries.
        let b_vault = dir.join("vault.goyo");
        let nonce = [0x24; 24];
        let mut v = [&b"GOYOVA01"[..], &id, &nonce].concat();
        v.extend(crypto::seal(&dk0, &nonce, &v.clone(), &[0u8; 12]).unwrap());
        std::fs::write(&b_vault, &v).unwrap();
        // The vault file is under an older key of B's: S-OLDER, answered yes.
        let prepared = vault::prepare(&b_vault, &b_key).unwrap();
        let VaultClass::Older { sha } = prepared.check().vault else {
            panic!("not an older-key vault file");
        };
        let s = Session::login(prepared, FORK_B, Some(sha)).unwrap();
        (s, a_key)
    }
    const FORK_A: &str = "synthetic fork password on A";
    const FORK_B: &str = "synthetic fork password on B";
    /// The app with B's session on Screen::Adopt for `other`.
    unsafe fn adopt_screen(h: Hwnd, s: Session, other: &Path) {
        let mut app = App::new(h);
        app.vault_path = s.path.clone();
        app.key_path = s.key_path.clone();
        app.session = Some(s);
        app.adopt_source = Some(other.to_owned());
        app.screen = Screen::Adopt;
        app.build();
        APP.with(|cell| *cell.borrow_mut() = Some(app));
    }
    /// The whole adopt is one flow (spec §14.4-10 "one flow"): [열기] takes
    /// one re-authentication to the write. The other file's password is asked inside the flow, again
    /// after a wrong one; the preview and S-ADOPT-BOTHPASS follow, and
    /// App.serial stays as it was across every dialog. Both PCs changed the
    /// password since the key they share, so the files are a fork: a union,
    /// with the check box, here ticked for this PC's password.
    #[test]
    fn adopt_runs_as_one_flow() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("adopt-flow");
        let (s, a_key) = fork(&dir);
        let b_key = s.key_path.clone();
        let before = std::fs::read(&b_key).unwrap();
        let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        let questions = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        unsafe {
            let h = flow_window("GoyoAdoptFlowTest");
            adopt_screen(h, s, &a_key);
            let serial = with_app(|a| a.serial);
            inputs(&asked, move |n, text, kind| {
                assert_eq!(with_app(|a| (a.serial, a.flow)), (serial, Some(SUBMIT)));
                match (n, kind) {
                    // A wrong password first: asked again, saying so.
                    (1, InputKind::Password) => {
                        assert_eq!(text, NEWPASS_OTHER);
                        typed("wrong synthetic password for A")
                    }
                    (2, InputKind::Password) => {
                        assert!(text.starts_with(crypto::AUTH_ERROR), "{text}");
                        assert!(text.ends_with(NEWPASS_OTHER));
                        // The retry delay has passed.
                        with_app(|a| a.retry = Instant::now());
                        typed(FORK_A)
                    }
                    (3, InputKind::Preview { check }) => {
                        // A union shows no code before it is written.
                        assert!(text.starts_with(ADOPT_UNION), "{text}");
                        assert!(text.contains(&fill(ADOPT_RESULT, &[&2])));
                        assert!(!text.contains("E2 · "));
                        assert_eq!(*check, Some((ADOPT_OWN_PASS, OWN_PASS_LABEL, false)));
                        InputAnswer::Accept { checked: true }
                    }
                    _ => panic!("unexpected input {n}: {text}"),
                }
            });
            let q = questions.clone();
            ANSWER.with(|a| {
                *a.borrow_mut() = Some(Box::new(move |text: &str| {
                    assert_eq!(with_app(|a| a.serial), serial);
                    q.borrow_mut().push(text.to_owned());
                    true
                }))
            });
            with_app(|a| {
                SetWindowTextW(a.handle(CURRENT_PASS), wide(FORK_B).as_ptr());
            });
            SendMessageW(h, 0x111, SUBMIT as usize, 0);
            assert_eq!(asked.borrow().len(), 3);
            // S-ADOPT-BOTHPASS, then S-BACKUP, which no test answers.
            assert_eq!(questions.borrow().as_slice(), [ADOPT_BOTHPASS]);
            with_app(|a| {
                assert!(a.screen == Screen::Vault && a.flow.is_none());
                assert!(a.adopt_source.is_none());
                let s = a.session.as_ref().unwrap();
                let code = s.key_code().unwrap();
                assert!(code.starts_with("E2 · "), "{code}");
                let lines: Vec<&str> = a.status.split("\r\n").collect();
                assert_eq!(lines[0], fill(ADOPT_CODE, &[&code]));
                assert_eq!(lines[1], ADOPT_PASS_OWN);
                // The wrong password counted, and is forgotten once the
                // right one opened the file.
                assert_eq!(a.failed, 0);
            });
            // The union opens with this PC's password only.
            let after = KeyFile::read(&b_key).unwrap();
            assert_ne!(after.bytes(), before);
            assert_eq!(after.header().unwrap().epoch, 2);
            assert!(after.open(FORK_B, None).is_ok());
            assert!(after.open(FORK_A, None).is_err());
            close_flow_window(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// An adopt writes nothing when the user stops it anywhere: [취소] at
    /// S-NEWPASS-OTHER or at the preview, No at S-ADOPT-BOTHPASS, or a lock
    /// while the preview is up. No Reauth is left behind: the next one
    /// takes the key file's lock at once. Then [받기] with the box unticked
    /// takes the other file's password (S-ADOPT-PASS-OTHER).
    #[test]
    fn adopts_stopped_anywhere_write_nothing() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("adopt-stop");
        let (s, a_key) = fork(&dir);
        let (b_vault, b_key) = (s.path.clone(), s.key_path.clone());
        let files = || {
            (
                std::fs::read(&b_key).unwrap(),
                std::fs::read(&b_vault).unwrap(),
            )
        };
        let before = files();
        let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        unsafe {
            let h = flow_window("GoyoAdoptStopTest");
            adopt_screen(h, s, &a_key);
            let submit = || {
                with_app(|a| {
                    SetWindowTextW(a.handle(CURRENT_PASS), wide(FORK_B).as_ptr());
                    a.retry = Instant::now();
                });
                SendMessageW(h, 0x111, SUBMIT as usize, 0);
            };
            let untouched = |files: (Vec<u8>, Vec<u8>)| {
                assert!(files == before, "an adopt that was stopped wrote");
                with_app(|a| assert!(a.flow.is_none()));
            };
            // [취소] at S-NEWPASS-OTHER.
            inputs(&asked, |_, _, _| InputAnswer::Cancel(2));
            submit();
            untouched(files());
            with_app(|a| assert!(a.screen == Screen::Adopt && a.session.is_some()));
            // [취소] at the preview.
            inputs(&asked, |_, _, kind| match kind {
                InputKind::Password => typed(FORK_A),
                InputKind::Preview { .. } => InputAnswer::Cancel(2),
                _ => unreachable!("no code or pick in an adopt"),
            });
            submit();
            untouched(files());
            // No Reauth left: this one gets the key file's lock.
            with_app(|a| {
                let s = a.session.as_mut().unwrap();
                drop(s.reauth(FORK_B, None).unwrap());
            });
            // No at S-ADOPT-BOTHPASS.
            inputs(&asked, |_, _, kind| match kind {
                InputKind::Password => typed(FORK_A),
                InputKind::Preview { .. } => InputAnswer::Accept { checked: false },
                _ => unreachable!("no code or pick in an adopt"),
            });
            answer(&std::rc::Rc::new(RefCell::new(Vec::new())), false);
            submit();
            untouched(files());
            assert!(ANSWER.with(|a| a.borrow().is_none()));
            // A lock while the preview is up.
            inputs(&asked, |_, _, kind| match kind {
                InputKind::Password => typed(FORK_A),
                InputKind::Preview { .. } => {
                    with_app(|a| a.lock("synthetic lock", true));
                    InputAnswer::Accept { checked: false }
                }
                _ => unreachable!("no code or pick in an adopt"),
            });
            submit();
            untouched(files());
            with_app(|a| assert!(a.session.is_none() && a.screen == Screen::Login));

            // Open again (B's vault is under its own key now), and receive
            // with the box unticked: A's password from now on.
            let prepared = vault::prepare(&b_vault, &b_key).unwrap();
            let s = Session::login(prepared, FORK_B, None).unwrap();
            with_app(|a| {
                a.session = Some(s);
                a.adopt_source = Some(a_key.clone());
                a.show(Screen::Adopt);
                a.build();
            });
            inputs(&asked, |_, _, kind| match kind {
                InputKind::Password => typed(FORK_A),
                InputKind::Preview { .. } => InputAnswer::Accept { checked: false },
                _ => unreachable!("no code or pick in an adopt"),
            });
            ANSWER.with(|a| *a.borrow_mut() = Some(Box::new(|_: &str| true)));
            submit();
            with_app(|a| {
                assert!(a.screen == Screen::Vault);
                let lines: Vec<&str> = a.status.split("\r\n").collect();
                assert_eq!(lines[1], ADOPT_PASS_OTHER);
            });
            let after = KeyFile::read(&b_key).unwrap();
            assert!(after.open(FORK_A, None).is_ok());
            close_flow_window(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A successor's preview shows the key code the result then has, and
    /// the password in force: the other file's, asked for because this PC's
    /// does not open it. No check box and no S-ADOPT-BOTHPASS.
    #[test]
    fn a_successor_preview_shows_its_code() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("adopt-successor");
        let (pa, pb) = (dir.join("a"), dir.join("b"));
        std::fs::create_dir(&pa).unwrap();
        std::fs::create_dir(&pb).unwrap();
        let pass = "synthetic successor password";
        // One vault, its 0.8 key file copied to B before A changes it with
        // the same password typed again: a successor, with no new password.
        vault::set_anchor_dir(Some(dir.join("anchor-a")));
        let mut sa = Provision::new()
            .unwrap()
            .finish(&pa.join("vault.goyo"), &pa.join("vault.goyokey"), pass)
            .unwrap();
        for name in ["vault.goyo", "vault.goyokey"] {
            std::fs::copy(pa.join(name), pb.join(name)).unwrap();
        }
        let r = sa.reauth(pass, None).unwrap();
        let next = "synthetic successor password 2";
        let change = vault::Change::Password(Zeroizing::new(next.to_owned()));
        sa.rekey(r, Vec::new(), change, vault::Consent::default(), true)
            .unwrap();
        let a_code = sa.key_code().unwrap();
        drop(sa);
        vault::set_anchor_dir(Some(dir.join("anchor")));
        let s = Session::unlock(&pb.join("vault.goyo"), &pb.join("vault.goyokey"), pass).unwrap();
        let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        unsafe {
            let h = flow_window("GoyoAdoptSuccessorTest");
            adopt_screen(h, s, &pa.join("vault.goyokey"));
            let want = a_code.clone();
            inputs(&asked, move |n, text, kind| match kind {
                InputKind::Password => typed(next),
                InputKind::Preview { check } => {
                    assert_eq!(n, 2);
                    assert!(check.is_none());
                    let parts: Vec<&str> = text.split("\r\n\r\n").collect();
                    assert_eq!(
                        parts,
                        [
                            ADOPT_SUCCESSOR,
                            fill(ADOPT_RESULT, &[&1]).as_str(),
                            fill(ADOPT_CODE, &[&want]).as_str(),
                            ADOPT_PASS_OTHER,
                        ]
                    );
                    InputAnswer::Accept { checked: false }
                }
                _ => unreachable!("no code or pick in an adopt"),
            });
            with_app(|a| SetWindowTextW(a.handle(CURRENT_PASS), wide(pass).as_ptr()));
            SendMessageW(h, 0x111, SUBMIT as usize, 0);
            with_app(|a| {
                assert!(a.screen == Screen::Vault);
                // The code the preview showed is the one now in force.
                assert_eq!(a.session.as_ref().unwrap().key_code().unwrap(), a_code);
                let lines: Vec<&str> = a.status.split("\r\n").collect();
                assert_eq!(lines[0], fill(ADOPT_CODE, &[&a_code]));
                assert_eq!(lines[1], ADOPT_PASS_OTHER);
            });
            close_flow_window(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The Keys screen offers [이 열쇠 파일이 맞습니다] for a key file put
    /// back over this PC's newer one, and only then; its question (danger,
    /// default No) comes first, and the password is checked again. The
    /// buttons of what does not hold refuse before any question.
    #[test]
    fn the_keys_screen_confirms_a_put_back_key_file() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("keys-rollback");
        let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
        let (old, new) = ("synthetic put back password", "synthetic newer password");
        let mut s = Provision::new().unwrap().finish(&vault, &key, old).unwrap();
        let (k0, v0) = (std::fs::read(&key).unwrap(), std::fs::read(&vault).unwrap());
        let r = s.reauth(old, None).unwrap();
        let change = vault::Change::Password(Zeroizing::new(new.to_owned()));
        s.rekey(r, Vec::new(), change, vault::Consent::default(), true)
            .unwrap();
        drop(s);
        // The old pair put back.
        std::fs::write(&key, &k0).unwrap();
        std::fs::write(&vault, &v0).unwrap();
        let s = Session::unlock(&vault, &key, old).unwrap();
        assert!(s.local_rollback());
        let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        unsafe {
            let h = flow_window("GoyoKeysRollbackTest");
            let mut app = App::new(h);
            app.session = Some(s);
            app.screen = Screen::Vault;
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| {
                assert!(a.screen == Screen::Keys);
                assert_ne!(a.handle(KEY_LOCAL_OK), 0);
                assert_eq!(a.handle(KEY_OVERRIDE_HEAD), 0);
                assert_eq!(a.handle(PENDING_FORGET), 0);
                // A 0.8 key file has no key code.
                assert!(a.keys_view().code.is_none());
            });
            let press = |id: i32, password: &str| {
                with_app(|a| {
                    SetWindowTextW(a.handle(CURRENT_PASS), wide(password).as_ptr());
                    a.retry = Instant::now();
                });
                SendMessageW(h, 0x111, id as usize, 0);
            };
            let rolled_back = || with_app(|a| a.session.as_ref().unwrap().local_rollback());
            // Nothing is pending: refused at once. Nor is a halted copy
            // overridden during the hold (S23-3 #5).
            press(PENDING_FORGET, old);
            with_app(|a| assert_eq!(*a.status, *vault::NOTHING_HELD));
            press(KEY_OVERRIDE_HEAD, old);
            with_app(|a| assert_eq!(*a.status, fill(vault::LOCAL_ROLLBACK, &[&1, &0])));
            assert!(asked.borrow().is_empty());
            // No: nothing changes.
            answer(&asked, false);
            press(KEY_LOCAL_OK, old);
            assert_eq!(
                asked.borrow()[0],
                fill(vault::LOCAL_OK_CONFIRM, &[&1, &0, &0])
            );
            assert!(rolled_back());
            // A wrong password: a failed attempt, nothing changes.
            answer(&asked, true);
            press(KEY_LOCAL_OK, "wrong synthetic password");
            with_app(|a| assert_eq!(a.failed, 1));
            assert!(rolled_back());
            // Yes, with the password: confirmed, and the button is gone.
            answer(&asked, true);
            press(KEY_LOCAL_OK, old);
            assert_eq!(asked.borrow().len(), 3);
            assert!(!rolled_back());
            with_app(|a| {
                assert!(a.screen == Screen::Keys && a.failed == 0 && a.flow.is_none());
                assert_eq!(*a.status, *KEY_FILE_CONFIRMED);
                assert_eq!(a.handle(KEY_LOCAL_OK), 0);
            });
            close_flow_window(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// Another PC changed the key and its copy halts sync here (spec
    /// §7.5a): the Keys screen offers the head override, which asks
    /// S-OVERRIDE-HEAD with that copy's revision, key and version, checks
    /// the password again and pushes this PC's state over that version.
    #[test]
    fn the_keys_screen_overrides_a_halted_head() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("keys-override");
        let mut server = Server::default();
        vault::set_anchor_dir(Some(dir.join("anchor-a")));
        let (mut a, vault_b, key_b) = two_pcs(&dir, &mut server, &["entry 0"]);
        // A changes the key and uploads under it.
        let r = a.reauth(SYNC_PASSWORD, None).unwrap();
        let change = vault::Change::Password(Zeroizing::new("synthetic key of A".into()));
        a.rekey(r, Vec::new(), change, vault::Consent::default(), true)
            .unwrap();
        upload(&mut server, &mut a);
        assert_eq!(server.versions.len(), 2);
        vault::set_anchor_dir(Some(dir.join("anchor")));
        server.pass(&vault_b);
        let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        unsafe {
            let h = flow_window("GoyoKeysOverrideTest");
            let mut app = App::new(h);
            app.vault_path = vault_b.clone();
            app.key_path = key_b;
            app.screen = Screen::Login;
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            with_app(|a| SetWindowTextW(a.handle(PASS), wide(SYNC_PASSWORD).as_ptr()));
            SendMessageW(h, 0x111, SUBMIT as usize, 0);
            let head = with_app(|a| {
                assert!(a.screen == Screen::Vault);
                a.session.as_ref().unwrap().halted_head().unwrap()
            });
            assert_eq!((head.epoch, head.version), (1, 2));
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| {
                assert_ne!(a.handle(KEY_OVERRIDE_HEAD), 0);
                SetWindowTextW(a.handle(CURRENT_PASS), wide(SYNC_PASSWORD).as_ptr());
            });
            answer(&asked, true);
            SendMessageW(h, 0x111, KEY_OVERRIDE_HEAD as usize, 0);
            let values: [&dyn std::fmt::Display; 3] = [&1, &head.key_prefix(), &2];
            assert_eq!(
                asked.borrow().as_slice(),
                [fill(vault::OVERRIDE_HEAD, &values)]
            );
            with_app(|a| {
                assert!(a.screen == Screen::Vault && a.flow.is_none());
                assert_eq!(*a.status, *HEAD_OVERRIDDEN);
                assert!(a.session.as_ref().unwrap().halted_head().is_none());
            });
            // This PC's state goes up over that version.
            let dir_b = syncfile::sync_dir(&vault_b).unwrap();
            let bytes = std::fs::read(dir_b.join(syncfile::OUTGOING)).unwrap();
            let (base, blob) = syncfile::parse_outgoing(&bytes).unwrap();
            assert!(base == 2 && blob.starts_with(b"GOYOVA02"));
            close_flow_window(h);
        }
        drop(a);
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// [이 열쇠 파일이 맞습니다] on a vault that syncs says what follows,
    /// in its question and its status: a server copy this PC wrote with the
    /// newer key file it puts aside halts sync again, and the head override
    /// replaces it (spec §2.18 #57).
    #[test]
    fn confirming_a_synced_put_back_key_file_says_what_follows() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("keys-rollback-synced");
        let mut server = Server::default();
        let (mut a, _, _) = two_pcs(&dir, &mut server, &["entry 0"]);
        let (vault, key) = (a.path.clone(), dir.join("a").join("vault.goyokey"));
        let (k0, v0) = (std::fs::read(&key).unwrap(), std::fs::read(&vault).unwrap());
        let r = a.reauth(SYNC_PASSWORD, None).unwrap();
        let change = vault::Change::Password(Zeroizing::new("synthetic newer password".into()));
        a.rekey(r, Vec::new(), change, vault::Consent::default(), true)
            .unwrap();
        upload(&mut server, &mut a);
        drop(a);
        std::fs::write(&key, &k0).unwrap();
        std::fs::write(&vault, &v0).unwrap();
        let mut s = Session::unlock(&vault, &key, SYNC_PASSWORD).unwrap();
        assert!(s.local_rollback() && s.badge().is_some());
        // Shown at the unlock.
        s.take_key_notices();
        let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        unsafe {
            let h = flow_window("GoyoKeysRollbackSyncedTest");
            let mut app = App::new(h);
            app.session = Some(s);
            app.screen = Screen::Vault;
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| SetWindowTextW(a.handle(CURRENT_PASS), wide(SYNC_PASSWORD).as_ptr()));
            answer(&asked, true);
            SendMessageW(h, 0x111, KEY_LOCAL_OK as usize, 0);
            assert_eq!(
                asked.borrow().as_slice(),
                [fill(vault::LOCAL_OK_CONFIRM_SYNCED, &[&1, &0, &0])]
            );
            with_app(|a| {
                assert!(!a.session.as_ref().unwrap().local_rollback());
                let lines: Vec<&str> = a.status.split("\r\n").collect();
                assert_eq!(lines, [KEY_FILE_CONFIRMED, KEY_FILE_CONFIRMED_SYNCED]);
            });
            close_flow_window(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// A gate that comes up while S-ROTATE is open (a poll halts sync on
    /// another PC's key change) is asked before the re-authentication: No
    /// changes nothing, and no question ends up as
    /// a status line (spec §7.5, §2.18 #64).
    #[test]
    fn a_gate_that_comes_up_during_a_question_is_asked_first() {
        let _korean = KoreanAfter::hold();
        crypto::set_kdf_profile(crypto::KdfProfile::Test);
        let dir = test_dir("late-gate");
        let mut server = Server::default();
        vault::set_anchor_dir(Some(dir.join("anchor-a")));
        let (mut a, vault_b, key_b) = two_pcs(&dir, &mut server, &["entry 0"]);
        vault::set_anchor_dir(Some(dir.join("anchor")));
        let mut b = Session::unlock(&vault_b, &key_b, SYNC_PASSWORD).unwrap();
        assert_eq!(b.password_change(), Ok(None));
        let key = std::fs::read(&key_b).unwrap();
        let asked = std::rc::Rc::new(RefCell::new(Vec::<String>::new()));
        unsafe {
            let h = flow_window("GoyoLateGateTest");
            let mut app = App::new(h);
            app.session = Some(b);
            app.screen = Screen::Vault;
            app.build();
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| a.command(KEY_PASSWORD, 0)).unwrap();
            let next = "synthetic late gate password";
            with_app(|a| {
                for (id, text) in [(CURRENT_PASS, SYNC_PASSWORD), (PASS, next), (CONFIRM, next)] {
                    SetWindowTextW(a.handle(id), wide(text).as_ptr());
                }
            });
            // While S-ROTATE is open, A changes the key and B's poll halts.
            let record = asked.clone();
            ANSWER.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |text: &str| {
                    record.borrow_mut().push(text.to_owned());
                    let r = a.reauth(SYNC_PASSWORD, None).unwrap();
                    let to = Zeroizing::new("synthetic key of A".to_owned());
                    let change = vault::Change::Password(to);
                    a.rekey(r, Vec::new(), change, vault::Consent::default(), true)
                        .unwrap();
                    upload(&mut server, &mut a);
                    server.pass(&vault_b);
                    with_app(|app| app.session.as_mut().unwrap().poll_sync());
                    answer(&record, false);
                    true
                }))
            });
            SendMessageW(h, 0x111, SUBMIT as usize, 0);
            assert_eq!(
                asked.borrow().as_slice(),
                [
                    ROTATE_QUESTION_SYNCED.to_owned(),
                    vault::Gate::KeyHalt.question().to_owned()
                ]
            );
            with_app(|a| {
                assert!(a.flow.is_none() && a.failed == 0);
                assert_ne!(*a.status, *vault::Gate::KeyHalt.question());
                assert!(a.session.as_ref().unwrap().halted_head().is_some());
            });
            assert_eq!(std::fs::read(&key_b).unwrap(), key);
            close_flow_window(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// While a flow runs, an open vault locks after FLOW_IDLE unused at the
    /// earliest, and the 30-second away lock waits for the same limit
    /// (spec §9.2a); "off" stays off. Without a flow both apply as set.
    #[test]
    fn flows_raise_the_idle_limit() {
        let dir = test_dir("flow-idle");
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            for (flow, idle, away, locks) in [
                (Some(SUBMIT), 120, 0, false),
                (Some(SUBMIT), 120, 60, false),
                (Some(SUBMIT), 601, 0, true),
                (None, 120, 0, true),
                (None, 0, 60, true),
            ] {
                app.session = Some(synthetic_session(&dir, "synthetic idle password"));
                app.screen = Screen::Keys;
                app.build();
                app.flow = flow;
                app.auto_lock = 0;
                let now = Instant::now();
                app.activity = now - Duration::from_secs(idle);
                app.away_since = (away > 0).then(|| now - Duration::from_secs(away));
                app.inactive = true;
                // The timer trusts the real foreground window: in front, it
                // was never away.
                let front = away > 0 && is_foreground(h);
                app.timer();
                if !front {
                    assert_eq!(app.session.is_none(), locks, "{flow:?} {idle} {away}");
                }
                app.lock("synthetic lock", true);
                for name in ["vault.goyo", "vault.goyokey"] {
                    let _ = std::fs::remove_file(dir.join(name));
                }
            }
            // "Off" stays off during a flow.
            app.session = Some(synthetic_session(&dir, "synthetic idle password"));
            app.auto_lock = AUTO_LOCKS.len() - 1;
            app.flow = Some(SUBMIT);
            app.activity = Instant::now() - Duration::from_secs(3600);
            app.away_since = None;
            app.timer();
            assert!(app.session.is_some());
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// An input dialog answers only to this thread (spec §9.2a): another
    /// thread, standing in for another program, posts and sends "OK" in
    /// every form, types into its password field and reads it, and the
    /// dialog still waits, with nothing typed or read. This thread, standing
    /// in for the user, then types and answers it; a lock cancels it. It
    /// shows a real dialog for about a second each time.
    /// The input dialog tests one at a time: input_box() is one per
    /// process, and each test's other thread looks for its own dialog.
    fn dialog_turn() -> std::sync::MutexGuard<'static, ()> {
        static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        TURN.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    #[test]
    fn input_dialog_ignores_other_programs() {
        let _turn = dialog_turn();
        use std::sync::atomic::{AtomicBool, AtomicU8, Ordering::Relaxed};
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetDlgItem(h: Hwnd, id: i32) -> Hwnd;
            fn KillTimer(h: Hwnd, id: usize) -> i32;
        }
        static TRIED: AtomicBool = AtomicBool::new(false);
        /// What this thread does once the other one is done: 0 cancels,
        /// 1 types and answers, 2 locks, 3 types and waits for a read.
        static USER: AtomicU8 = AtomicU8::new(0);
        static TYPED: AtomicBool = AtomicBool::new(false);
        /// The field as this thread read it after the other thread was done.
        static SEEN: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
        /// The field's text as this thread reads it.
        fn field(d: Hwnd) -> String {
            let edit = unsafe { GetDlgItem(d, INPUT_EDIT) };
            INTERNAL_READ.with(|f| f.set(true));
            let text = caption(edit);
            INTERNAL_READ.with(|f| f.set(false));
            text
        }
        unsafe extern "system" fn user(_: Hwnd, _: u32, _: usize, _: u32) {
            let d = input_box();
            if d == 0 {
                return;
            }
            let edit = unsafe { GetDlgItem(d, INPUT_EDIT) };
            if USER.load(Relaxed) == 3 && !TYPED.swap(true, Relaxed) {
                unsafe { SetWindowTextW(edit, wide("synthetic typed secret").as_ptr()) };
            }
            if !TRIED.swap(false, Relaxed) {
                return;
            }
            // Whatever the other thread sent did not reach the field.
            *SEEN.lock().unwrap() = field(d);
            unsafe {
                match USER.load(Relaxed) {
                    1 => {
                        SetWindowTextW(edit, wide("synthetic typed password").as_ptr());
                        SendMessageW(d, 0x111, 1, 0);
                    }
                    2 => cancel_input(),
                    _ => {
                        SendMessageW(d, 0x111, 2, 0);
                    }
                }
            }
        }
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            // Shown without activation, so that activation goes back to this
            // thread's window when a dialog closes, never to a window of
            // another test's thread, which pumps no messages.
            ShowWindow(h, 8);
            // The app's edit subclass needs the edit class's own procedure.
            let mut app = App::new(h);
            app.build();
            let hook = filter_queue(h);
            assert_ne!(hook, 0);
            let timer = SetTimer(0, 0, 50, user as *const () as isize);
            assert_ne!(timer, 0);
            type Attack = fn(Hwnd, Hwnd, Hwnd);
            let attacks: [(&str, Attack, u8); 8] = [
                (
                    "posted WM_COMMAND",
                    |d, _, _| {
                        PostMessageW(d, 0x111, 1, 0);
                    },
                    0,
                ),
                (
                    "posted BM_CLICK",
                    |_, ok, _| {
                        PostMessageW(ok, 0xf5, 0, 0);
                    },
                    0,
                ),
                (
                    "sent WM_COMMAND",
                    |d, _, _| {
                        SendMessageW(d, 0x111, 1, 0);
                    },
                    0,
                ),
                (
                    "sent BM_CLICK",
                    |_, ok, _| {
                        SendMessageW(ok, 0xf5, 0, 0);
                    },
                    0,
                ),
                (
                    "sent mouse click",
                    |_, ok, _| {
                        SendMessageW(ok, 0x201, 1, 0);
                        SendMessageW(ok, 0x202, 0, 0);
                    },
                    0,
                ),
                (
                    "sent WM_SETTEXT",
                    |_, _, e| {
                        SendMessageW(e, 0xc, 0, wide("forged").as_ptr() as isize);
                    },
                    0,
                ),
                (
                    "sent WM_GETTEXT",
                    |_, _, e| {
                        let mut buf = [0u16; 64];
                        let n = SendMessageW(e, 0xd, 64, buf.as_mut_ptr() as isize);
                        assert_eq!(n, 0, "the field was read");
                    },
                    3,
                ),
                ("a lock", |_, _, _| {}, 2),
            ];
            let others = attacks.into_iter().map(|(n, a, u)| (n, a, u, false));
            for (name, attack, mode, last) in
                others.chain([("the user", (|_, _, _| {}) as Attack, 1, true)])
            {
                TRIED.store(false, Relaxed);
                TYPED.store(false, Relaxed);
                USER.store(mode, Relaxed);
                let other = std::thread::spawn(move || {
                    // Whatever happens here, this thread is told to answer,
                    // so a failure ends the dialog instead of leaving it open.
                    let tried = std::panic::catch_unwind(|| {
                        // Wait until the dialog is up with its controls, and
                        // where this thread types first, until it did: a busy
                        // machine may take a while.
                        let start = Instant::now();
                        let ready = |d: Hwnd| {
                            d != 0 && IsWindowVisible(d) != 0 && (mode != 3 || TYPED.load(Relaxed))
                        };
                        let mut d = input_box();
                        while !ready(d) && start.elapsed() < Duration::from_secs(20) {
                            std::thread::sleep(Duration::from_millis(20));
                            d = input_box();
                        }
                        assert!(ready(d), "the dialog never opened");
                        let (ok, edit) = (GetDlgItem(d, 1), GetDlgItem(d, INPUT_EDIT));
                        assert!(ok != 0 && edit != 0);
                        attack(d, ok, edit);
                        std::thread::sleep(Duration::from_millis(200));
                        input_box() == d
                    });
                    TRIED.store(true, Relaxed);
                    tried.unwrap_or_else(|e| std::panic::resume_unwind(e))
                });
                let answer = input_dialog(
                    h,
                    InputKind::Password,
                    NEWPASS_OTHER,
                    &[OK_BUTTON, CANCEL_BUTTON],
                    edit_proc,
                );
                let open = other.join().unwrap();
                assert!(open, "{name} answered the dialog");
                let expect = if mode == 3 {
                    "synthetic typed secret"
                } else {
                    ""
                };
                assert_eq!(*SEEN.lock().unwrap(), expect, "{name} reached the field");
                match answer {
                    InputAnswer::Password(p) => {
                        assert!(last, "{name}");
                        assert_eq!(&*p, "synthetic typed password");
                    }
                    InputAnswer::Cancel(2) => assert!(!last, "{name}"),
                    _ => panic!("{name}: another answer"),
                }
                assert_eq!(input_box(), 0);
            }
            KillTimer(0, timer);
            UnhookWindowsHookEx(hook);
            FILTERED_WINDOW.with(|f| f.set(0));
            drop(app);
            DestroyWindow(h);
        }
    }

    /// The pick and code kinds of the input dialog (spec §9.2a, §14.8-14):
    /// another thread, standing in for another program, clicks an item
    /// (sent and posted), sends "OK" and sets the code field's text, and
    /// none of it reaches the dialog. This thread, standing in for the
    /// user, then ticks two items, or types a code, and answers; the
    /// dialog is capture-excluded, read back. It shows a real dialog for
    /// about a second each time.
    #[test]
    fn input_dialog_pick_and_code_ignore_other_programs() {
        let _turn = dialog_turn();
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetDlgItem(h: Hwnd, id: i32) -> Hwnd;
            fn KillTimer(h: Hwnd, id: usize) -> i32;
        }
        static TRIED: AtomicBool = AtomicBool::new(false);
        static CODE: AtomicBool = AtomicBool::new(false);
        /// What this thread found once the other was done: the second
        /// item's tick, the code field's text and the capture exclusion.
        static TICKED: AtomicBool = AtomicBool::new(false);
        static AFFINITY: AtomicU32 = AtomicU32::new(0);
        static SEEN: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
        unsafe extern "system" fn user(_: Hwnd, _: u32, _: usize, _: u32) {
            let d = input_box();
            if d == 0 || !TRIED.swap(false, Relaxed) {
                return;
            }
            unsafe {
                let mut affinity = 0u32;
                GetWindowDisplayAffinity(d, &mut affinity);
                AFFINITY.store(affinity, Relaxed);
                if CODE.load(Relaxed) {
                    let edit = GetDlgItem(d, INPUT_CODE);
                    INTERNAL_READ.with(|f| f.set(true));
                    *SEEN.lock().unwrap() = caption(edit);
                    INTERNAL_READ.with(|f| f.set(false));
                    SetWindowTextW(edit, wide("E3 · 0123-4567-89AB-CDEF").as_ptr());
                } else {
                    let second = GetDlgItem(d, INPUT_PICK + 1);
                    TICKED.store(SendMessageW(second, 0xf0, 0, 0) == 1, Relaxed);
                    SendMessageW(GetDlgItem(d, INPUT_PICK), 0xf5, 0, 0);
                    SendMessageW(GetDlgItem(d, INPUT_PICK + 2), 0xf5, 0, 0);
                }
                SendMessageW(d, 0x111, 1, 0);
            }
        }
        unsafe {
            SetProcessDPIAware();
            let h = create_window(GetModuleHandleW(null()), &wide("STATIC"));
            ShowWindow(h, 8);
            let mut app = App::new(h);
            app.build();
            let hook = filter_queue(h);
            assert_ne!(hook, 0);
            let timer = SetTimer(0, 0, 50, user as *const () as isize);
            assert_ne!(timer, 0);
            let ok = DialogButton {
                id: 1,
                label: "확인",
                role: Role::Accept,
            };
            let items = [
                ("synthetic item one", false),
                ("synthetic item two", false),
                ("synthetic item three", false),
            ];
            for code in [false, true] {
                CODE.store(code, Relaxed);
                TRIED.store(false, Relaxed);
                let other = std::thread::spawn(move || {
                    let tried = std::panic::catch_unwind(|| {
                        let start = Instant::now();
                        let mut d = input_box();
                        while (d == 0 || IsWindowVisible(d) == 0)
                            && start.elapsed() < Duration::from_secs(20)
                        {
                            std::thread::sleep(Duration::from_millis(20));
                            d = input_box();
                        }
                        assert!(d != 0, "the dialog never opened");
                        if code {
                            let edit = GetDlgItem(d, INPUT_CODE);
                            assert_ne!(edit, 0);
                            SendMessageW(edit, 0xc, 0, wide("forged").as_ptr() as isize);
                        } else {
                            let second = GetDlgItem(d, INPUT_PICK + 1);
                            assert_ne!(second, 0);
                            SendMessageW(second, 0xf5, 0, 0);
                            PostMessageW(second, 0xf5, 0, 0);
                        }
                        SendMessageW(d, 0x111, 1, 0);
                        PostMessageW(d, 0x111, 1, 0);
                        std::thread::sleep(Duration::from_millis(200));
                        input_box() == d
                    });
                    TRIED.store(true, Relaxed);
                    tried.unwrap_or_else(|e| std::panic::resume_unwind(e))
                });
                let kind = if code {
                    InputKind::Code("")
                } else {
                    InputKind::Pick(&items)
                };
                let answer = input_dialog(h, kind, NEWPASS_OTHER, &[ok, CANCEL_BUTTON], edit_proc);
                assert!(other.join().unwrap(), "the other thread answered");
                assert_eq!(AFFINITY.load(Relaxed), 0x11);
                match answer {
                    InputAnswer::Pick(picked) => {
                        assert!(!code && !TICKED.load(Relaxed));
                        assert_eq!(picked, [0, 2]);
                    }
                    InputAnswer::Code(typed) => {
                        assert!(code);
                        assert_eq!(*SEEN.lock().unwrap(), "");
                        assert_eq!(&*typed, "E3 · 0123-4567-89AB-CDEF");
                    }
                    _ => panic!("another answer"),
                }
                assert_eq!(input_box(), 0);
            }
            // Too many items, or none: the dialog cannot be shown, and the
            // answer is the cancel button.
            let many = [("synthetic", false); PICK_MAX + 1];
            for list in [&many[..], &[]] {
                let answer = input_dialog(
                    h,
                    InputKind::Pick(list),
                    NEWPASS_OTHER,
                    &[ok, CANCEL_BUTTON],
                    edit_proc,
                );
                assert!(matches!(answer, InputAnswer::Cancel(2)));
            }
            KillTimer(0, timer);
            UnhookWindowsHookEx(hook);
            FILTERED_WINDOW.with(|f| f.set(0));
            drop(app);
            DestroyWindow(h);
        }
    }

    /// SUBMIT (or Enter) on Restore runs as a flow through phased_command
    /// in both builds (spec §9.2a; S45-1 #13, S45-2 #17), as on Create: the
    /// keyless build's has no question and no ceremony, the security-key
    /// build's a touch.
    #[test]
    fn restore_submit_runs_as_a_flow() {
        let mut app = App::new(0);
        app.screen = Screen::Restore;
        APP.with(|cell| *cell.borrow_mut() = Some(app));
        assert!(phased(SUBMIT) && phased(1) && !phased(BACK));
        with_app(|a| a.screen = Screen::Create);
        assert!(phased(SUBMIT));
        with_app(|a| a.screen = Screen::Vault);
        assert!(!phased(SUBMIT));
        APP.with(|cell| cell.borrow_mut().take());
    }

    /// The ceremony runner and the unlock's touch (spec §8.5, §8.6, §14.8)
    /// with the fake authenticator on a real worker thread, driven through
    /// channels from another thread while the UI thread pumps. No real key.
    #[cfg(feature = "security-key")]
    mod ceremonies {
        use super::*;
        use goyo_vault::fido::{
            self, MakeRequest, RawAssertion, RawCredential,
            fake::{Device, Fake, Fault},
            register, salt,
        };
        use std::sync::{
            Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
            mpsc::{Receiver, Sender, channel},
        };

        /// The fake behind the runner, with what the runner did counted:
        /// its cancels, the fake's own answers, and an optional hold of the
        /// worker before it reaches the fake's pre-call check.
        struct Counted {
            fake: Arc<Fake>,
            cancels: AtomicUsize,
            answers: Mutex<Vec<Result<(), FidoError>>>,
            before: Mutex<Option<(Sender<()>, Receiver<()>)>>,
            /// Moves the test clock on by this much when a call starts.
            jump: AtomicU64,
            clock: Arc<AtomicU64>,
        }
        impl Counted {
            fn new(fake: Arc<Fake>, clock: Arc<AtomicU64>) -> Arc<Self> {
                Arc::new(Self {
                    fake,
                    cancels: AtomicUsize::new(0),
                    answers: Mutex::new(Vec::new()),
                    before: Mutex::new(None),
                    jump: AtomicU64::new(0),
                    clock,
                })
            }
            /// Holds the next call before the fake's check: the first
            /// channel says the worker got there, the second lets it go on.
            fn hold_before_call(&self) -> (Receiver<()>, Sender<()>) {
                let (reached, at) = channel();
                let (release, wait) = channel();
                *self.before.lock().unwrap() = Some((reached, wait));
                (at, release)
            }
            fn start(&self) {
                let before = self.before.lock().unwrap().take();
                if let Some((reached, wait)) = before {
                    let _ = reached.send(());
                    let _ = wait.recv();
                }
                self.clock
                    .fetch_add(self.jump.load(Ordering::SeqCst), Ordering::SeqCst);
            }
        }
        impl Authenticator for Counted {
            fn api_version(&self) -> u32 {
                self.fake.api_version()
            }
            fn new_cancel(&self) -> Result<CancelToken, FidoError> {
                self.fake.new_cancel()
            }
            fn make_credential(
                &self,
                r: &MakeRequest,
                c: &CancelToken,
            ) -> Result<RawCredential, FidoError> {
                self.start();
                self.fake.make_credential(r, c)
            }
            fn get_assertion(
                &self,
                r: &AssertRequest,
                c: &CancelToken,
            ) -> Result<RawAssertion, FidoError> {
                self.start();
                let answer = self.fake.get_assertion(r, c);
                let kept = answer.as_ref().map(|_| ()).map_err(|e| *e);
                self.answers.lock().unwrap().push(kept);
                answer
            }
            fn cancel(&self, c: &CancelToken) {
                self.cancels.fetch_add(1, Ordering::SeqCst);
                self.fake.cancel(c)
            }
        }
        /// An authenticator whose one call never ends by a cancel: it waits
        /// for the test, after moving the test clock past the cap.
        struct Stuck {
            release: Mutex<Receiver<()>>,
            clock: Arc<AtomicU64>,
            cancels: AtomicUsize,
            /// The test clock right after the jump.
            jumped: AtomicU64,
        }
        impl Authenticator for Stuck {
            fn api_version(&self) -> u32 {
                9
            }
            fn new_cancel(&self) -> Result<CancelToken, FidoError> {
                Ok(CancelToken::new([7; 16]))
            }
            fn make_credential(
                &self,
                _: &MakeRequest,
                _: &CancelToken,
            ) -> Result<RawCredential, FidoError> {
                Err(FidoError::Other(1))
            }
            fn get_assertion(
                &self,
                _: &AssertRequest,
                _: &CancelToken,
            ) -> Result<RawAssertion, FidoError> {
                let at = self.clock.fetch_add(CEREMONY_CAP + 1_000, Ordering::SeqCst);
                self.jumped
                    .store(at + CEREMONY_CAP + 1_000, Ordering::SeqCst);
                let _ = self.release.lock().unwrap().recv();
                Err(FidoError::Other(1))
            }
            fn cancel(&self, _: &CancelToken) {
                self.cancels.fetch_add(1, Ordering::SeqCst);
            }
        }

        thread_local! {
            /// What the probe window saw while the pump dispatched to it:
            /// in_modal(), and whether APP could be borrowed.
            static PROBED: Cell<Option<(bool, bool)>> = const { Cell::new(None) };
        }
        unsafe extern "system" fn probe_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
            if m == 0x8005 {
                let free = APP.with(|cell| cell.try_borrow_mut().is_ok());
                PROBED.with(|p| p.set(Some((in_modal(), free))));
                return 0;
            }
            unsafe { DefWindowProcW(h, m, w, l) }
        }
        #[link(name = "user32")]
        unsafe extern "system" {
            fn PostThreadMessageW(thread: u32, m: u32, w: usize, l: isize) -> i32;
        }

        /// `auth` as Windows takes a request (spec §2.28): one whose owner
        /// is not the app's top-level window fails at once, as hWnd 0 fails
        /// with a real key, and is counted, so that every test through
        /// `window` checks that each ceremony names the main window.
        struct Owned {
            auth: Arc<dyn Authenticator>,
            window: Hwnd,
        }
        /// Requests that named another owner, over every test.
        static WRONG_OWNER: AtomicUsize = AtomicUsize::new(0);
        impl Owned {
            fn check(&self, owner: Hwnd) -> Result<(), FidoError> {
                if owner == self.window && owner != 0 {
                    return Ok(());
                }
                WRONG_OWNER.fetch_add(1, Ordering::SeqCst);
                Err(FidoError::from_hresult(fido::NTE_INVALID_PARAMETER))
            }
        }
        impl Authenticator for Owned {
            fn api_version(&self) -> u32 {
                self.auth.api_version()
            }
            fn new_cancel(&self) -> Result<CancelToken, FidoError> {
                self.auth.new_cancel()
            }
            fn make_credential(
                &self,
                r: &MakeRequest,
                c: &CancelToken,
            ) -> Result<RawCredential, FidoError> {
                self.check(r.owner)?;
                self.auth.make_credential(r, c)
            }
            fn get_assertion(
                &self,
                r: &AssertRequest,
                c: &CancelToken,
            ) -> Result<RawAssertion, FidoError> {
                self.check(r.owner)?;
                self.auth.get_assertion(r, c)
            }
            fn cancel(&self, c: &CancelToken) {
                self.auth.cancel(c)
            }
        }

        /// The app's window with the app behind it, on the Login screen of
        /// `vault`, a test clock on this thread and `auth` in place of
        /// Windows' WebAuthn, taking only requests the window owns.
        fn window(
            class: &str,
            vault: &Path,
            key: &Path,
            auth: Arc<dyn Authenticator>,
            clock: &Arc<AtomicU64>,
        ) -> Hwnd {
            crypto::set_test_clock(Some(clock.clone()));
            unsafe {
                let name = wide(class);
                let instance = GetModuleHandleW(null());
                let wc = WndClass {
                    style: 0,
                    proc: Some(window_proc),
                    cls_extra: 0,
                    wnd_extra: 0,
                    instance,
                    icon: 0,
                    cursor: 0,
                    background: 6,
                    menu: null(),
                    class: name.as_ptr(),
                };
                assert_ne!(RegisterClassW(&wc), 0);
                let h = CreateWindowExW(
                    0,
                    name.as_ptr(),
                    wide("Synthetic ceremony test").as_ptr(),
                    0x00ca0000,
                    0,
                    0,
                    900,
                    800,
                    0,
                    0,
                    instance,
                    null_mut(),
                );
                assert_ne!(h, 0);
                AUTHENTICATOR.with(|a| *a.borrow_mut() = Some(Arc::new(Owned { auth, window: h })));
                assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
                WINDOW_GONE.with(|p| p.set(false));
                PENDING_EVENTS.with(|p| p.set(0));
                let mut app = App::new(h);
                app.vault_path = vault.to_path_buf();
                app.key_path = key.to_path_buf();
                app.show(Screen::Login);
                app.build();
                APP.with(|cell| *cell.borrow_mut() = Some(app));
                h
            }
        }
        /// Closes the test's window and its app when dropped, also after a
        /// failed assertion.
        struct Window(Hwnd);
        impl Drop for Window {
            fn drop(&mut self) {
                close(self.0);
            }
        }
        fn close(h: Hwnd) {
            APP.with(|cell| {
                cell.borrow_mut().take();
            });
            unsafe {
                if IsWindow(h) != 0 {
                    DestroyWindow(h);
                }
                // The WM_QUIT of WM_DESTROY, and any other left.
                let mut msg = Msg::default();
                while PeekMessageW(&mut msg, 0, 0, 0, 1) != 0 {}
            }
            WINDOW_GONE.with(|p| p.set(false));
            PENDING_EVENTS.with(|p| p.set(0));
            AUTHENTICATOR.with(|a| a.borrow_mut().take());
            QUIT_SEEN.with(|q| q.set(false));
            crypto::set_test_clock(None);
            // No ceremony of any test named another window than the app's.
            if !std::thread::panicking() {
                assert_eq!(
                    WRONG_OWNER.load(Ordering::SeqCst),
                    0,
                    "a request without the app's window"
                );
            }
        }
        /// A fake key with a credential of vault `id`, and the unlock's
        /// request for it, owned by `owner`.
        fn keyed(fake: &Fake, owner: isize) -> (usize, AssertRequest) {
            let id = [0x4c; 16];
            let i = fake.plug(Device::default());
            fake.touch(Some(i));
            let key = register(fake, &id, 1, 0, false, Vec::new()).unwrap();
            let req = AssertRequest::new(
                owner,
                vec![(key.cred_id.clone(), salt(&id, &key.seed), None)],
                false,
            )
            .unwrap();
            (i, req)
        }
        /// Runs `act` on another thread once the fake's worker passed its
        /// pre-call check and waits right before the operation, then lets
        /// the worker go on.
        fn in_the_gap(fake: &Fake, act: impl FnOnce() + Send + 'static) -> JoinHandle<bool> {
            let (reached, release) = fake.pause_after_check();
            std::thread::spawn(move || {
                let got = reached.recv_timeout(Duration::from_secs(20)).is_ok();
                if got {
                    act();
                }
                let _ = release.send(());
                got
            })
        }
        type JoinHandle<T> = std::thread::JoinHandle<T>;

        /// A ceremony's one Windows call runs on its own named worker while
        /// the UI thread pumps inside modal() with no APP borrow: a window's
        /// message is dispatched meanwhile, posted commands, clicks and
        /// keystrokes to the password field are dropped, the request names
        /// the main window, the worker's thread is restricted, and after it
        /// the idle and away times start again (spec §8.5, §8.6, §14.8-2,
        /// -5, -7, -8).
        #[test]
        fn a_ceremony_runs_on_its_worker_while_the_app_stays_free() {
            let _korean = KoreanAfter::hold();
            let dir = test_dir("ceremony-run");
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let counted = Counted::new(fake.clone(), clock.clone());
            let h = window(
                "GoyoCeremonyRun",
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                counted.clone(),
                &clock,
            );
            let guard = Window(h);
            let (i, request) = keyed(&fake, h);
            // A slow key: it answers 5 s of test time later.
            fake.device(i, |d| d.answer_at = Some(1_005_000));
            unsafe {
                let class = wide("GoyoCeremonyProbe");
                let wc = WndClass {
                    style: 0,
                    proc: Some(probe_proc),
                    cls_extra: 0,
                    wnd_extra: 0,
                    instance: GetModuleHandleW(null()),
                    icon: 0,
                    cursor: 0,
                    background: 0,
                    menu: null(),
                    class: class.as_ptr(),
                };
                assert_ne!(RegisterClassW(&wc), 0);
                let probe = CreateWindowExW(
                    0,
                    class.as_ptr(),
                    null(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    GetModuleHandleW(null()),
                    null_mut(),
                );
                assert_ne!(probe, 0);
                with_app(|a| {
                    SetWindowTextW(a.handle(PASS), wide("typed").as_ptr());
                    a.activity = Instant::now() - Duration::from_secs(3600);
                    a.away_since = Some(Instant::now() - Duration::from_secs(3600));
                });
                let pass = with_app(|a| a.handle(PASS));
                let driver = in_the_gap(&fake, move || {
                    PostMessageW(probe, 0x8005, 0, 0);
                    PostMessageW(h, 0x111, LOCK as usize, 0);
                    PostMessageW(h, 0x201, 1, 0);
                    PostMessageW(pass, 0x102, 'x' as usize, 0);
                    PostMessageW(pass, 0x100, 0x41, 0);
                    // Lets the pump take them before the worker goes on.
                    std::thread::sleep(Duration::from_millis(100));
                });
                let (tx, rx) = channel();
                let asked = request.clone();
                let ui = std::thread::current().id();
                let started = Instant::now();
                let raw = ceremony(h, counted.clone(), move |auth, token| {
                    let me = std::thread::current();
                    // The pump restricts this thread too.
                    let until = Instant::now() + Duration::from_secs(5);
                    while open_threads() != 0 && Instant::now() < until {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let _ = tx.send((me.name().map(str::to_owned), me.id(), open_threads()));
                    auth.get_assertion(&asked, token)
                });
                assert!(driver.join().unwrap());
                let touch = check_assertion(raw.unwrap(), &request, false).unwrap();
                assert!(!touch.cred_id.is_empty());
                let (name, worker, open) = rx.recv().unwrap();
                assert_eq!(name.as_deref(), Some("goyo-webauthn"));
                assert_ne!(worker, ui);
                assert_eq!(open, 0);
                assert!(restrict_threads());
                assert_eq!(open_threads(), 0);
                assert_eq!(PROBED.with(Cell::get), Some((true, true)));
                assert!(!in_modal() && !in_ceremony());
                // The answer came at 5 s of test time, before the cap, with
                // no cancel.
                let now = clock.load(Ordering::SeqCst);
                assert!(
                    (1_005_000..1_000_000 + CEREMONY_CAP).contains(&now),
                    "{now}"
                );
                assert_eq!(counted.cancels.load(Ordering::SeqCst), 0);
                assert_eq!(*counted.answers.lock().unwrap(), [Ok(())]);
                assert!(fake.seen().iter().all(|s| s.owner == h || s.owner == 0));
                assert_eq!(fake.seen().last().unwrap().owner, h);
                with_app(|a| {
                    // Nothing typed, no command, no lock.
                    assert_eq!(*a.read(PASS).unwrap(), "typed");
                    assert!(a.screen == Screen::Login);
                    assert!(a.activity >= started);
                    let front = is_foreground(h);
                    assert_eq!(a.away_since.is_none(), front);
                    assert!(a.away_since.is_none_or(|t| t >= started));
                });
                DestroyWindow(probe);
            }
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A lock, a suspend or a session end that arrives while the worker
        /// is between its pre-call check and the fake's operation (S45-3
        /// #13): the cancel then reaches no operation, and Windows (and the
        /// fake) forget it; only the pump's cancel, issued again every
        /// round, ends the operation, at once and not at the cap or the
        /// detach. The answer is dropped, and the app's state is the
        /// lock's (spec §8.6, §14.8-6, -7).
        #[test]
        fn a_lock_before_the_call_is_cancelled_again_until_the_worker_ends() {
            let _korean = KoreanAfter::hold();
            let dir = test_dir("ceremony-lock");
            for (m, w) in [(0x2b1, 7), (0x218, 4), (0x16, 1)] {
                let clock = Arc::new(AtomicU64::new(1_000_000));
                let fake = Arc::new(Fake::new(Some(clock.clone())));
                let counted = Counted::new(fake.clone(), clock.clone());
                let h = window(
                    &format!("GoyoCeremonyLock{m:x}"),
                    &dir.join("vault.goyo"),
                    &dir.join("vault.goyokey"),
                    counted.clone(),
                    &clock,
                );
                let guard = Window(h);
                let (i, request) = keyed(&fake, h);
                // It would answer only after the cap.
                fake.device(i, |d| d.answer_at = Some(1_000_000 + 1_000_000));
                let serial = with_app(|a| a.serial);
                // Sent from another thread, as Windows sends them.
                let driver = in_the_gap(&fake, move || unsafe {
                    SendMessageW(h, m, w, 0);
                });
                let asked = request.clone();
                let result = ceremony(h, counted.clone(), move |auth, token| {
                    auth.get_assertion(&asked, token)
                });
                assert!(driver.join().unwrap());
                assert_eq!(result.err(), Some(FidoError::Cancelled), "{m:#x}");
                // The fake's operation ran and was ended by a cancel.
                assert_eq!(
                    *counted.answers.lock().unwrap(),
                    [Err(FidoError::Cancelled)],
                    "{m:#x}"
                );
                assert!(counted.cancels.load(Ordering::SeqCst) >= 2, "{m:#x}");
                let spent = clock.load(Ordering::SeqCst) - 1_000_000;
                assert!(spent < CEREMONY_DETACH, "{m:#x}: {spent} ms");
                drain_pending(h);
                with_app(|a| {
                    assert!(a.serial > serial, "{m:#x}");
                    assert!(a.session.is_none());
                });
                drop(guard);
            }
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A cancel that reached the token before the worker's call: the
        /// worker makes no call at all (spec §8.5, §14.8-4).
        #[test]
        fn a_cancel_before_the_call_makes_none() {
            let _korean = KoreanAfter::hold();
            let dir = test_dir("ceremony-before");
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let counted = Counted::new(fake.clone(), clock.clone());
            let h = window(
                "GoyoCeremonyBefore",
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                counted.clone(),
                &clock,
            );
            let guard = Window(h);
            let (_, request) = keyed(&fake, h);
            let seen = fake.seen().len();
            let (reached, release) = counted.hold_before_call();
            let driver = std::thread::spawn(move || {
                let got = reached.recv_timeout(Duration::from_secs(20)).is_ok();
                if got {
                    unsafe {
                        SendMessageW(h, 0x2b1, 7, 0);
                    }
                }
                let _ = release.send(());
                got
            });
            let asked = request.clone();
            let result = ceremony(h, counted.clone(), move |auth, token| {
                auth.get_assertion(&asked, token)
            });
            assert!(driver.join().unwrap());
            assert_eq!(result.err(), Some(FidoError::Cancelled));
            assert_eq!(
                *counted.answers.lock().unwrap(),
                [Err(FidoError::Cancelled)]
            );
            assert_eq!(fake.seen().len(), seen);
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// The 150-second cap on the test clock: timer ticks meanwhile
        /// lock nothing, though the idle and away times are long past; the
        /// cap cancels; nobody was at it, so the idle time does not start
        /// again and the next tick locks (§2.26: an answered ceremony starts
        /// it again, see the first test). A worker that does not end within
        /// 10 s of the cancel is left behind (spec §8.5, §8.6, §14.8-7).
        #[test]
        fn the_cap_ends_a_ceremony_and_a_stuck_worker_is_left_after_10_s() {
            let _korean = KoreanAfter::hold();
            let dir = test_dir("ceremony-cap");
            let pass = "synthetic ceremony cap password";
            let session = synthetic_session(&dir, pass);
            let vault = std::fs::read(dir.join("vault.goyo")).unwrap();
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let counted = Counted::new(fake.clone(), clock.clone());
            let h = window(
                "GoyoCeremonyCap",
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                counted.clone(),
                &clock,
            );
            let guard = Window(h);
            let (i, request) = keyed(&fake, h);
            fake.device(i, |d| d.answer_at = Some(1_000_000 + 1_000_000));
            // The call starts at 149 s of test time.
            counted.jump.store(CEREMONY_CAP - 1_000, Ordering::SeqCst);
            let long_ago = Instant::now() - Duration::from_secs(3600);
            with_app(|a| {
                a.session = Some(session);
                a.show(Screen::Vault);
                a.build();
                a.auto_lock = 0;
                a.activity = long_ago;
                a.away_since = Some(long_ago);
                a.inactive = true;
            });
            // Timer ticks as Windows posts them, during the ceremony.
            let driver = in_the_gap(&fake, move || unsafe {
                for _ in 0..3 {
                    PostMessageW(h, 0x113, 1, 0);
                }
                std::thread::sleep(Duration::from_millis(100));
            });
            let asked = request.clone();
            let result = ceremony(h, counted.clone(), move |auth, token| {
                auth.get_assertion(&asked, token)
            });
            assert!(driver.join().unwrap());
            assert_eq!(result.err(), Some(FidoError::Cancelled));
            assert_eq!(
                *counted.answers.lock().unwrap(),
                [Err(FidoError::Cancelled)]
            );
            // Ended by the cap's cancel: not before it, and not by the
            // detach 10 s after it.
            let spent = clock.load(Ordering::SeqCst) - 1_000_000;
            assert!(
                (CEREMONY_CAP..CEREMONY_CAP + CEREMONY_DETACH).contains(&spent),
                "{spent} ms"
            );
            with_app(|a| {
                assert!(a.session.is_some(), "a tick locked during the ceremony");
                // Nobody was at a ceremony the cap ended: the idle time runs
                // on from before it, and the next tick locks (spec §8.6).
                assert!(a.activity == long_ago);
                a.timer();
                assert!(a.session.is_none(), "the idle time started again");
            });
            assert_eq!(std::fs::read(dir.join("vault.goyo")).unwrap(), vault);
            drop(guard);

            // A worker that ignores the cancel: left 10 s after it.
            let (go, release) = channel();
            let stuck = Arc::new(Stuck {
                release: Mutex::new(release),
                clock: clock.clone(),
                cancels: AtomicUsize::new(0),
                jumped: AtomicU64::new(0),
            });
            let h = window(
                "GoyoCeremonyStuck",
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                stuck.clone(),
                &clock,
            );
            let guard = Window(h);
            let asked = request.clone();
            let result = ceremony(h, stuck.clone(), move |auth, token| {
                auth.get_assertion(&asked, token)
            });
            assert_eq!(result.err(), Some(FidoError::Cancelled));
            // Past the cap at the first round after the jump, and left 10 s
            // of test time later.
            let after_cap = clock.load(Ordering::SeqCst) - stuck.jumped.load(Ordering::SeqCst);
            assert!(
                (CEREMONY_DETACH..CEREMONY_DETACH + 1_000).contains(&after_cap),
                "{after_cap} ms after the cap"
            );
            // Cancelled at every round until it was left.
            assert!(stuck.cancels.load(Ordering::SeqCst) >= 40);
            assert!(!in_ceremony() && !in_modal());
            go.send(()).unwrap();
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// WM_CLOSE during a ceremony locks and cancels it but destroys the
        /// window only at the first timer tick after its end; a WM_QUIT is
        /// kept, cancels, and is posted again afterwards (spec §8.6,
        /// §14.8-6).
        #[test]
        fn a_close_or_quit_during_a_ceremony_waits_for_its_end() {
            let _korean = KoreanAfter::hold();
            let dir = test_dir("ceremony-close");
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let counted = Counted::new(fake.clone(), clock.clone());
            let h = window(
                "GoyoCeremonyClose",
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                counted.clone(),
                &clock,
            );
            let guard = Window(h);
            let (i, request) = keyed(&fake, h);
            fake.device(i, |d| d.answer_at = Some(1_000_000 + 1_000_000));
            let ui = unsafe { GetCurrentThreadId() };
            // Posted, as the close button or the taskbar does: handled in
            // window_proc. Timer ticks follow while the ceremony still runs.
            let driver = in_the_gap(&fake, move || unsafe {
                PostMessageW(h, 0x10, 0, 0);
                PostThreadMessageW(ui, 0x12, 7, 0);
                std::thread::sleep(Duration::from_millis(50));
                PostMessageW(h, 0x113, 1, 0);
                std::thread::sleep(Duration::from_millis(50));
            });
            let asked = request.clone();
            let result = ceremony(h, counted.clone(), move |auth, token| {
                auth.get_assertion(&asked, token)
            });
            assert!(driver.join().unwrap());
            assert_eq!(result.err(), Some(FidoError::Cancelled));
            assert_eq!(
                *counted.answers.lock().unwrap(),
                [Err(FidoError::Cancelled)]
            );
            unsafe {
                // Still there, closing; the quit was posted again.
                assert_ne!(IsWindow(h), 0);
                with_app(|a| assert!(a.closing));
                let mut msg = Msg::default();
                assert_ne!(PeekMessageW(&mut msg, 0, 0x12, 0x12, 1), 0);
                assert_eq!(msg.wparam, 7);
                // The next tick closes it.
                with_app(|a| a.timer());
                assert_eq!(IsWindow(h), 0);
            }
            drop(guard);

            // WM_CLOSE sent from another thread: deferred to drain_pending.
            let counted = Counted::new(fake.clone(), clock.clone());
            let h = window(
                "GoyoCeremonyCloseSent",
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                counted.clone(),
                &clock,
            );
            let guard = Window(h);
            let request = AssertRequest {
                owner: h,
                ..request
            };
            let driver = in_the_gap(&fake, move || unsafe {
                SendMessageW(h, 0x10, 0, 0);
                std::thread::sleep(Duration::from_millis(50));
                PostMessageW(h, 0x113, 1, 0);
                std::thread::sleep(Duration::from_millis(50));
            });
            let asked = request.clone();
            let result = ceremony(h, counted.clone(), move |auth, token| {
                auth.get_assertion(&asked, token)
            });
            assert!(driver.join().unwrap());
            assert_eq!(result.err(), Some(FidoError::Cancelled));
            unsafe {
                assert_ne!(IsWindow(h), 0);
                with_app(|a| assert!(a.closing && a.session.is_none()));
                with_app(|a| a.timer());
                assert_eq!(IsWindow(h), 0);
            }
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// An answer that comes back after the app's own cancel (a lock
        /// while the key was answering) is dropped: the step ends with
        /// Cancelled (spec §8.5, §14.8-6).
        #[test]
        fn an_answer_after_a_lock_is_dropped() {
            /// Answers whatever happens, once the test lets it.
            struct Late {
                reached: Mutex<Sender<()>>,
                release: Mutex<Receiver<()>>,
            }
            impl Authenticator for Late {
                fn api_version(&self) -> u32 {
                    9
                }
                fn new_cancel(&self) -> Result<CancelToken, FidoError> {
                    Ok(CancelToken::new([8; 16]))
                }
                fn make_credential(
                    &self,
                    _: &MakeRequest,
                    _: &CancelToken,
                ) -> Result<RawCredential, FidoError> {
                    Err(FidoError::Other(1))
                }
                fn get_assertion(
                    &self,
                    r: &AssertRequest,
                    _: &CancelToken,
                ) -> Result<RawAssertion, FidoError> {
                    let _ = self.reached.lock().unwrap().send(());
                    let _ = self.release.lock().unwrap().recv();
                    Ok(RawAssertion {
                        version: 6,
                        auth_data: [&fido::rp_id_hash()[..], &[fido::UP], &[0, 0, 0, 1]].concat(),
                        cred_id: r.allow[0].0.clone(),
                        first: Some(Zeroizing::new(vec![0x11; 32])),
                        second: None,
                        transport: Some(fido::USB),
                    })
                }
                fn cancel(&self, _: &CancelToken) {}
            }
            let _korean = KoreanAfter::hold();
            let dir = test_dir("ceremony-late");
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let (reached, at) = channel();
            let (release, wait) = channel();
            let late = Arc::new(Late {
                reached: Mutex::new(reached),
                release: Mutex::new(wait),
            });
            let h = window(
                "GoyoCeremonyLate",
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                late.clone(),
                &clock,
            );
            let guard = Window(h);
            let driver = std::thread::spawn(move || {
                let got = at.recv_timeout(Duration::from_secs(20)).is_ok();
                if got {
                    unsafe {
                        SendMessageW(h, 0x2b1, 7, 0);
                    }
                }
                let _ = release.send(());
                got
            });
            let request = AssertRequest::new(h, vec![(vec![3; 16], [4; 32], None)], false).unwrap();
            let asked = request.clone();
            let result = ceremony(h, late.clone(), move |auth, token| {
                auth.get_assertion(&asked, token)
            });
            assert!(driver.join().unwrap());
            assert_eq!(result.err(), Some(FidoError::Cancelled));
            // Without the lock the same answer is taken.
            let (reached, at) = channel();
            let (release, wait) = channel();
            *late.reached.lock().unwrap() = reached;
            *late.release.lock().unwrap() = wait;
            let driver = std::thread::spawn(move || {
                let got = at.recv_timeout(Duration::from_secs(20)).is_ok();
                let _ = release.send(());
                got
            });
            let asked = request.clone();
            let raw = ceremony(h, late.clone(), move |auth, token| {
                auth.get_assertion(&asked, token)
            });
            assert!(driver.join().unwrap());
            assert!(check_assertion(raw.unwrap(), &request, false).is_ok());
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// Login with a key file that has a security key (spec §5.2, §8.7,
        /// §14.8-9): the touch between the phases opens the vault with the
        /// main window as the dialog's owner; a cancelled touch shows the
        /// cancel text with S-CANCEL-KEYHINT and no retry delay; a wrong
        /// password after a touch and an unrequested credential do get one;
        /// a lock during the touch voids the flow with the lock's line, and
        /// nothing is derived or written.
        #[test]
        fn unlock_with_a_touch() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-login");
            let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
            let pass = "synthetic touch login password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let device = fake.plug(Device::default());
            fake.touch(Some(device));
            let provision = Provision::new().unwrap();
            let new = register(&*fake, &provision.vault_id(), 1, 0, false, Vec::new()).unwrap();
            drop(
                provision
                    .finish_with_keys(&vault, &key, pass, false, vec![new])
                    .unwrap(),
            );
            let (vault_bytes, key_bytes) =
                (std::fs::read(&vault).unwrap(), std::fs::read(&key).unwrap());
            let counted = Counted::new(fake.clone(), clock.clone());
            let h = window("GoyoCeremonyLogin", &vault, &key, counted.clone(), &clock);
            let guard = Window(h);
            let type_in = |text: &str| {
                with_app(|a| unsafe {
                    SetWindowTextW(a.handle(PASS), wide(text).as_ptr());
                })
            };
            let submit = || unsafe { SendMessageW(h, 0x111, SUBMIT as usize, 0) };
            let reset = || {
                with_app(|a| {
                    a.failed = 0;
                    a.retry = Instant::now();
                })
            };

            // The user touches no key: Windows ends with a cancel.
            fake.touch(None);
            type_in(pass);
            let derived = crypto::derive_count();
            submit();
            assert_eq!(crypto::derive_count(), derived);
            with_app(|a| {
                assert!(a.session.is_none() && a.failed == 0);
                assert!(a.retry <= Instant::now());
                let expected = format!("{}\r\n{}", fido::CANCELLED, keys_ui::CANCEL_KEYHINT);
                assert_eq!(*a.status, expected);
                assert!(a.flow.is_none());
            });
            assert_eq!(fake.seen().last().unwrap().owner, h);

            // A wrong password after a touch: a failed attempt.
            fake.touch(Some(device));
            type_in("synthetic wrong password here");
            submit();
            with_app(|a| assert!(a.session.is_none() && a.failed == 1));
            reset();

            // Windows answers with a credential it was not asked for.
            fake.device(device, |d| d.fault = Fault::Unrequested);
            type_in(pass);
            let derived = crypto::derive_count();
            submit();
            assert_eq!(crypto::derive_count(), derived);
            with_app(|a| {
                assert!(a.session.is_none() && a.failed == 1);
                assert_eq!(*a.status, fido::NOT_REGISTERED);
            });
            fake.device(device, |d| d.fault = Fault::None);
            reset();

            // A lock during the touch: no answer is taken, nothing derived.
            type_in(pass);
            let derived = crypto::derive_count();
            let driver = in_the_gap(&fake, move || unsafe {
                SendMessageW(h, 0x2b1, 7, 0);
            });
            submit();
            assert!(driver.join().unwrap());
            assert_eq!(crypto::derive_count(), derived);
            with_app(|a| {
                assert!(a.session.is_none() && a.failed == 0);
                assert_eq!(*a.status, "화면 또는 시스템 세션 변경으로 잠갔습니다.");
                assert!(a.read(PASS).unwrap().is_empty());
            });

            // The touch opens it.
            reset();
            type_in(pass);
            submit();
            with_app(|a| {
                let s = a.session.as_ref().expect("opened with the touch");
                assert_eq!(s.unlocked_with(), Some(1));
                assert!(a.screen == Screen::Vault && a.failed == 0);
            });
            assert_eq!(fake.seen().last().unwrap().owner, h);
            assert_eq!(std::fs::read(&key).unwrap(), key_bytes);
            let _ = vault_bytes;
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// The fake with the user's hand: before each Windows call, the
        /// next key of the script is the one touched (None: no key), so a
        /// flow's ceremonies can meet different keys with no question in
        /// between. An empty script keeps the last key.
        struct Scripted {
            fake: Arc<Fake>,
            script: Mutex<std::collections::VecDeque<Option<usize>>>,
        }
        impl Scripted {
            fn new(fake: Arc<Fake>) -> Arc<Self> {
                Arc::new(Self {
                    fake,
                    script: Mutex::new(Default::default()),
                })
            }
            /// The keys the next calls meet, in order.
            fn plan(&self, keys: &[Option<usize>]) {
                self.script.lock().unwrap().extend(keys.iter().copied());
            }
            fn next(&self) {
                if let Some(key) = self.script.lock().unwrap().pop_front() {
                    self.fake.touch(key);
                }
            }
            fn left(&self) -> usize {
                self.script.lock().unwrap().len()
            }
        }
        impl Authenticator for Scripted {
            fn api_version(&self) -> u32 {
                self.fake.api_version()
            }
            fn new_cancel(&self) -> Result<CancelToken, FidoError> {
                self.fake.new_cancel()
            }
            fn make_credential(
                &self,
                r: &MakeRequest,
                c: &CancelToken,
            ) -> Result<RawCredential, FidoError> {
                self.next();
                self.fake.make_credential(r, c)
            }
            fn get_assertion(
                &self,
                r: &AssertRequest,
                c: &CancelToken,
            ) -> Result<RawAssertion, FidoError> {
                self.next();
                self.fake.get_assertion(r, c)
            }
            fn cancel(&self, c: &CancelToken) {
                self.fake.cancel(c)
            }
        }
        /// Answers every ask() with `f` until the test stops it, recording
        /// each question; each answer runs as the box would, in modal().
        fn every_answer(
            asked: &std::rc::Rc<RefCell<Vec<String>>>,
            f: impl FnMut(&str) -> bool + 'static,
        ) {
            type Shared = std::rc::Rc<RefCell<dyn FnMut(&str) -> bool>>;
            fn install(asked: std::rc::Rc<RefCell<Vec<String>>>, f: Shared) {
                ANSWER.with(|a| {
                    *a.borrow_mut() = Some(Box::new(move |text: &str| {
                        assert!(in_modal());
                        asked.borrow_mut().push(text.to_owned());
                        let yes = (f.borrow_mut())(text);
                        install(asked.clone(), f.clone());
                        yes
                    }))
                });
            }
            install(asked.clone(), std::rc::Rc::new(RefCell::new(f)));
        }
        fn stop_answers() {
            ANSWER.with(|a| a.borrow_mut().take());
            INPUT_ANSWER.with(|a| a.borrow_mut().take());
        }
        /// Answers every input dialog with `f` (its text, kind and the
        /// count of earlier ones) until the test stops it.
        fn every_input(f: impl FnMut(usize, &str, &InputKind) -> InputAnswer + 'static) {
            let mut f = f;
            let mut n = 0;
            INPUT_ANSWER.with(|i| {
                *i.borrow_mut() = Some(Box::new(move |text: &str, kind: &InputKind| {
                    assert!(in_modal());
                    n += 1;
                    f(n - 1, text, kind)
                }))
            });
        }
        fn set(h: Hwnd, id: i32, text: &str) {
            let _ = h;
            with_app(|a| unsafe {
                SetWindowTextW(a.handle(id), wide(text).as_ptr());
            });
        }
        fn press(h: Hwnd, id: i32) {
            unsafe {
                SendMessageW(h, 0x111, id as usize, 0);
            }
        }
        fn status() -> String {
            with_app(|a| a.status.to_string())
        }
        fn numbers(o: &Option<vault::KeysOverview>) -> Vec<u8> {
            o.as_ref()
                .map(|o| o.rows.iter().map(|r| r.number).collect())
                .unwrap_or_default()
        }

        /// Create with security keys (spec §9.2, §14.8-9): a cancel during
        /// key 1 writes nothing; two keys with S-SPARE and S-PIN-DISTINCT,
        /// paired with each other; an exclude hit at key 2 goes back to
        /// S-SPARE with key 1 kept, and No with S-NOSPARE's yes makes the
        /// vault with one key and the red S-ONEKEY. Every request names the
        /// main window.
        #[test]
        fn create_with_keys() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-create");
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (k1, k2) = (fake.plug(Device::with_pin()), fake.plug(Device::with_pin()));
            let auth = Scripted::new(fake.clone());
            let h = window(
                "GoyoCeremonyCreate",
                &dir.join("none.goyo"),
                &dir.join("none.goyokey"),
                auth.clone(),
                &clock,
            );
            let guard = Window(h);
            let pass = "synthetic create keys password";
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            let create = |name: &str| {
                let (vault, key) = (
                    dir.join(format!("{name}.goyo")),
                    dir.join(format!("{name}.goyokey")),
                );
                with_app(|a| {
                    a.provision = Some(Provision::new().unwrap());
                    a.new_vault_path = vault.clone();
                    a.new_key_path = key.clone();
                    a.session = None;
                    a.toggles = keys_ui::Toggles::default();
                    a.show(Screen::Create);
                    a.build();
                });
                press(h, keys_ui::SK_TOGGLE);
                with_app(|a| {
                    assert!(a.toggles.create);
                    assert_eq!(*a.status, keys_ui::CREATE_NOTE);
                });
                set(h, PASS, pass);
                set(h, CONFIRM, pass);
                (vault, key)
            };

            // Key 1 cancelled: nothing written, no question.
            let (vault, key) = create("cancelled");
            auth.plan(&[None]);
            press(h, SUBMIT);
            assert!(!vault.exists() && !key.exists());
            with_app(|a| {
                assert!(a.screen == Screen::Create && a.flow.is_none());
                assert_eq!(*a.status, fido::CANCELLED);
            });
            assert!(asked.borrow().is_empty());

            // Two keys: S-SPARE (with S-PIN-DISTINCT once), yes, then No.
            let (vault, key) = create("two");
            auth.plan(&[Some(k1); 2]);
            let script = auth.clone();
            every_answer(&asked, move |text| {
                if text.contains(tr(keys_ui::PIN_DISTINCT)) {
                    script.plan(&[Some(k2); 2]);
                    return true;
                }
                false
            });
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(auth.left(), 0);
            {
                let asked = asked.borrow();
                assert_eq!(asked.len(), 2);
                assert!(asked[0].starts_with(tr(keys_ui::PIN_DISTINCT)));
                assert!(asked[0].ends_with(&fill(keys_ui::SPARE, &[&1])));
                assert_eq!(asked[1], fill(keys_ui::SPARE, &[&2]));
            }
            asked.borrow_mut().clear();
            assert!(vault.exists() && key.exists(), "{}", status());
            with_app(|a| {
                assert!(a.screen == Screen::Vault && a.flow.is_none());
                assert_eq!(*a.status, fill(keys_ui::CREATED, &[&2]));
                let o = a.session.as_ref().unwrap().keys_overview().unwrap();
                assert!(o.pin && o.rows.len() == 2 && o.full == [1, 2]);
                assert!(o.rows.iter().all(|r| r.unpaired.is_empty()));
            });
            assert!(fake.seen().iter().all(|s| s.owner == h));

            // An exclude hit at key 2 (the same key again), then No and
            // S-NOSPARE's yes: one key, and S-ONEKEY in red.
            let (vault, key) = create("one");
            auth.plan(&[Some(k1); 3]);
            let at_second = std::rc::Rc::new(RefCell::new(String::new()));
            let record = at_second.clone();
            every_answer(&asked, move |text| {
                if text.contains(tr(keys_ui::PIN_DISTINCT)) {
                    return true;
                }
                if text == fill(keys_ui::SPARE, &[&1]) {
                    *record.borrow_mut() = status();
                    return false;
                }
                text == keys_ui::NOSPARE
            });
            press(h, SUBMIT);
            stop_answers();
            {
                let asked = asked.borrow();
                assert_eq!(asked.len(), 3, "{asked:?}");
                assert_eq!(asked[1], fill(keys_ui::SPARE, &[&1]));
                assert_eq!(asked[2], keys_ui::NOSPARE);
            }
            assert_eq!(*at_second.borrow(), fido::EXISTS);
            asked.borrow_mut().clear();
            assert!(vault.exists() && key.exists());
            with_app(|a| {
                let created = keys_ui::CREATED_ONE;
                assert_eq!(*a.status, format!("{created}\r\n{}", keys_ui::ONEKEY));
                let tone = unsafe { GetWindowLongPtrW(a.handle(STATUS), -21) };
                assert_eq!(tone, TONE_DANGER);
                let o = a.session.as_ref().unwrap().keys_overview().unwrap();
                assert_eq!(o.rows.len(), 1);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// Every Keys action of a vault (spec §9.2, §14.8-9), with the fake:
        /// keys on with the password change and a spare; add a key paired
        /// with one of them only, which the pairing status names; the pair
        /// screen; re-seed with the confirmation touch; keys off with
        /// S-RETIRE. Each writes a new key file, offers its backup, and
        /// leaves the screen on Keys with its status line.
        #[test]
        fn keys_on_add_pair_reseed_and_off() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-keys");
            let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
            let (pass, newpass) = (
                "synthetic keys flow password",
                "synthetic keys flow new password",
            );
            drop(
                Provision::new()
                    .unwrap()
                    .finish(&vault, &key, pass)
                    .unwrap(),
            );
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (k1, k2, k3) = (
                fake.plug(Device::with_pin()),
                fake.plug(Device::with_pin()),
                fake.plug(Device::with_pin()),
            );
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyKeys", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| assert!(a.screen == Screen::Keys && a.handle(keys_ui::KEY_ON) != 0));
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            let overview = || with_app(|a| a.session.as_ref().unwrap().keys_overview());

            // Keys on, the password changed, with two keys.
            set(h, CURRENT_PASS, pass);
            set(h, PASS, newpass);
            set(h, CONFIRM, newpass);
            auth.plan(&[Some(k1); 2]);
            let script = auth.clone();
            every_answer(&asked, move |text| {
                if text.contains(tr(keys_ui::PIN_DISTINCT)) {
                    script.plan(&[Some(k2); 2]);
                    return true;
                }
                text.starts_with(keys_ui::KEYSON_PLAN)
            });
            let told = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = told.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            press(h, keys_ui::KEY_ON);
            stop_answers();
            INPUT_ANSWER.with(|i| i.borrow_mut().take());
            // What keys on means first (S-KEYSON-PLAN: the key at every
            // unlock, the keys at hand, the other PCs), then S-ROTATE.
            assert_eq!(
                asked.borrow()[0],
                format!(
                    "{}

{ROTATE_QUESTION}",
                    keys_ui::KEYSON_PLAN
                )
            );
            assert_eq!(asked.borrow().last().unwrap(), BACKUP_QUESTION);
            asked.borrow_mut().clear();
            // After S-BACKUP, once: what every other PC of the vault does,
            // then the code (a vault that does not sync).
            assert_eq!(told.borrow().len(), 1);
            assert!(told.borrow()[0].starts_with(keys_ui::KEYSON_OTHERS));
            assert!(!told.borrow()[0].contains(keys_ui::KEYSON_OTHERS_SYNCED));
            let o = overview().expect("keys on");
            assert!(o.pin && numbers(&Some(o.clone())) == [1, 2] && o.full == [1, 2]);
            assert!(status().starts_with(&fill(keys_ui::KEYS_ON_DONE, &[&2])));
            assert!(status().contains(keys_ui::PASS_NEW));
            with_app(|a| {
                assert!(a.screen == Screen::Keys && a.flow.is_none());
                assert!(a.handle(keys_ui::KEY_ADD) != 0 && a.handle(keys_ui::KEY_ON) == 0);
            });

            // Add key 3, paired with the touched key 1 only.
            set(h, CURRENT_PASS, newpass);
            auth.plan(&[Some(k1), Some(k3), Some(k3)]);
            every_answer(&asked, |_| false);
            let told = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = told.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            INPUT_ANSWER.with(|i| i.borrow_mut().take());
            assert_eq!(*asked.borrow(), [keys_ui::ADD_PAIR, keys_ui::BACKUP_SHORT]);
            asked.borrow_mut().clear();
            // A vault that does not sync: the code in the general sentence,
            // no "other PCs need it" photo dialog (spec §2.29).
            let code = with_app(|a| a.session.as_ref().unwrap().key_code()).unwrap();
            assert_eq!(told.borrow().len(), 1);
            assert!(told.borrow()[0].ends_with(&fill(keys_ui::CODE_SK, &[&code])));
            assert!(!told.borrow()[0].contains(&fill(keys_ui::CODE_PHOTO, &[&code])));
            let o = overview().unwrap();
            assert_eq!(numbers(&Some(o.clone())), [1, 2, 3]);
            assert_eq!(o.full, [1]);
            assert_eq!(o.rows[2].unpaired, [2]);
            assert!(status().starts_with(&fill(keys_ui::ADDED, &[&3])));
            let list = keys_ui::list_text(&o);
            assert!(list.contains(&fill(keys_ui::ROW_UNPAIRED, &[&"2"])));
            assert!(list.contains(&fill(keys_ui::FULL, &[&"1"])));

            // Only key 1 reaches every key now: another addition asks for it
            // alone (here no key answers, and nothing is written).
            let before = std::fs::read(&key).unwrap();
            auth.plan(&[None]);
            press(h, keys_ui::KEY_ADD);
            assert_eq!(fake.seen().last().unwrap().credentials.len(), 1);
            assert!(status().starts_with(fido::CANCELLED));
            assert_eq!(std::fs::read(&key).unwrap(), before);

            // The pair screen ticks keys 2 and 3; touching both pairs them.
            press(h, keys_ui::KEY_PAIR);
            with_app(|a| {
                assert!(a.screen == Screen::Pair);
                assert_eq!(a.toggles.pick, 0b110);
            });
            set(h, CURRENT_PASS, newpass);
            auth.plan(&[Some(k2), Some(k3)]);
            every_answer(&asked, |_| false);
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(*asked.borrow(), [keys_ui::BACKUP_SHORT]);
            asked.borrow_mut().clear();
            let o = overview().unwrap();
            assert_eq!(o.full, [1, 2, 3]);
            with_app(|a| assert!(a.screen == Screen::Keys));
            assert!(status().starts_with(&fill(keys_ui::PAIRED, &[&"2, 3"])));

            // Re-seed: every key touched with two salts, then one more.
            let code = with_app(|a| a.session.as_ref().unwrap().key_code());
            set(h, CURRENT_PASS, newpass);
            // Key 2 first (the Reauth), then 1 and 3, then key 2's new value.
            auth.plan(&[Some(k2), Some(k1), Some(k3), Some(k2)]);
            every_answer(&asked, |text| text == keys_ui::RESEED);
            press(h, keys_ui::KEY_RESEED);
            stop_answers();
            assert_eq!(*asked.borrow(), [keys_ui::RESEED, BACKUP_QUESTION]);
            asked.borrow_mut().clear();
            assert!(status().starts_with(keys_ui::RESEEDED), "{}", status());
            let after = with_app(|a| a.session.as_ref().unwrap().key_code());
            assert!(after.is_some() && after != code);

            // Keys off: S-OFF, a touch, S-BACKUP, then S-RETIRE.
            set(h, CURRENT_PASS, newpass);
            auth.plan(&[Some(k3)]);
            every_answer(&asked, |text| text == keys_ui::OFF);
            let retired = std::rc::Rc::new(RefCell::new(String::new()));
            let seen = retired.clone();
            every_input(move |_, text, kind| {
                assert!(matches!(kind, InputKind::Preview { check: None }));
                *seen.borrow_mut() = text.to_owned();
                InputAnswer::Accept { checked: false }
            });
            press(h, keys_ui::KEY_OFF);
            stop_answers();
            assert_eq!(*asked.borrow(), [keys_ui::OFF, BACKUP_QUESTION]);
            assert!(retired.borrow().contains("Goyo Vault "));
            assert!(overview().is_none());
            assert!(status().starts_with(keys_ui::KEYS_OFF_DONE));
            with_app(|a| assert!(a.handle(keys_ui::KEY_ON) != 0));
            assert!(fake.seen().iter().all(|s| s.owner == h));
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// One touch of key `number` of `s`'s key file, made with the fake
        /// outside any flow (another PC's own write).
        fn touched(fake: &Fake, device: usize, s: &Session, number: u8) -> Touch {
            let req = s.key_request(&[number], 0).unwrap();
            fake.touch(Some(device));
            let raw = fake
                .get_assertion(&req, &fake.new_cancel().unwrap())
                .unwrap();
            check_assertion(raw, &req, false).unwrap()
        }

        /// The gate dialogs and the TOFU banner (spec §7.15a, §7.17,
        /// §14.8-9): PC B confirms PC A's key file with A's code in the
        /// banner, after a wrong one that adds S-TOFU-OTHEREPOCH. A removes
        /// key 3; B's login asks S-LOSTPICK before the touch, with B's own
        /// keys only, and the right pick passes after the unlock. A removes
        /// key 2; a wrong pick shows S-GATE-G2FAIL-DISK and turns G2 off, so
        /// [받기…] asks S-GATE-CODE, which takes the code with or without
        /// its prefix, after a malformed and a wrong one.
        #[test]
        fn gate_dialogs_and_tofu() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir_a = test_dir("gate-a");
            let pass = "synthetic gate password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let devices: Vec<usize> = (0..3).map(|_| fake.plug(Device::default())).collect();
            let provision = Provision::new().unwrap();
            let id = provision.vault_id();
            let keys: Vec<_> = devices
                .iter()
                .zip(1u8..)
                .map(|(d, n)| {
                    fake.touch(Some(*d));
                    register(&*fake, &id, n, 0, false, Vec::new()).unwrap()
                })
                .collect();
            let (va, ka) = (dir_a.join("vault.goyo"), dir_a.join("vault.goyokey"));
            let mut a = provision
                .finish_with_keys(&va, &ka, pass, false, keys)
                .unwrap();
            let code_e1 = a.key_code().unwrap();
            // PC B: a copy of A's files, its own anchor.
            let dir_b = test_dir("gate-b");
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            let copy = |from: (&Path, &Path)| {
                std::fs::copy(from.0, &vb).unwrap();
                std::fs::copy(from.1, &kb).unwrap();
            };
            copy((&va, &ka));
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyGate", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let login = |device: usize| {
                auth.plan(&[Some(device)]);
                set(h, PASS, pass);
                press(h, SUBMIT);
            };
            login(devices[0]);
            with_app(|a| {
                assert!(a.screen == Screen::Vault && a.tofu_banner());
                assert!(a.handle(keys_ui::TOFU_OK) != 0 && a.handle(EDIT) != 0);
            });
            // A wrong code: S-TOFU-OTHEREPOCH, nothing written.
            set(h, keys_ui::GATE_CODE, "E1 · 0000-0000-0000-0000");
            press(h, keys_ui::TOFU_OK);
            assert_eq!(
                status(),
                format!("{}\r\n{}", vault::GATE_CODE_WRONG, keys_ui::TOFU_OTHEREPOCH)
            );
            // The code stays in its field, also across a rebuild (spec
            // §2.29).
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().tofu());
                a.build();
                let kept = a.read(keys_ui::GATE_CODE).unwrap();
                assert_eq!(kept.as_str(), "E1 · 0000-0000-0000-0000");
            });
            // Enter in the code field is [확인].
            set(h, keys_ui::GATE_CODE, &code_e1.to_lowercase());
            press(h, 1);
            with_app(|a| {
                assert!(!a.session.as_ref().unwrap().tofu() && !a.tofu_banner());
                assert_eq!(*a.status, keys_ui::TOFU_PASSED);
                assert!(a.handle(keys_ui::TOFU_OK) == 0);
                a.lock("synthetic lock", true);
            });

            // A removes key 3 with key 1's touch.
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let remove = |a: &mut Session, number: u8| {
                let t = touched(&fake, devices[0], a, 1);
                let r = a.reauth(pass, Some(&t)).unwrap();
                let change = vault::Change::Remove {
                    remove: vec![number],
                    new_password: None,
                    loss: None,
                    over: None,
                };
                a.rekey(r, vec![], change, vault::Consent::default(), false)
                    .unwrap();
            };
            remove(&mut a, 3);
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            copy((&va, &ka));
            // A lock while S-LOSTPICK is open voids the login: no Windows
            // call follows, and the lock's line stays (spec §8.5, S45-1 #12).
            every_input(move |_, _, kind| {
                assert!(matches!(kind, InputKind::Pick(_)));
                unsafe {
                    SendMessageW(h, 0x2b1, 7, 0);
                }
                InputAnswer::Pick(vec![2])
            });
            let seen_before = fake.seen().len();
            login(devices[0]);
            stop_answers();
            assert_eq!(fake.seen().len(), seen_before, "a ceremony after the lock");
            with_app(|a| {
                assert!(a.session.is_none());
                assert_eq!(
                    *a.status,
                    "Windows 세션이 잠기거나 연결이 변경되어 잠갔습니다."
                );
            });
            // B: S-LOSTPICK before the touch, B's own three keys, no count
            // and no code; the pick of key 3 passes after the unlock.
            let shown = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = shown.clone();
            every_input(move |n, text, kind| {
                let InputKind::Pick(items) = kind else {
                    panic!("not a pick");
                };
                let labels: Vec<&str> = items
                    .iter()
                    .map(|(l, on)| {
                        assert!(!on);
                        *l
                    })
                    .collect();
                record
                    .borrow_mut()
                    .push((n, text.to_owned(), labels.join("|")));
                InputAnswer::Pick(vec![2])
            });
            let seen_before = fake.seen().len();
            login(devices[0]);
            stop_answers();
            {
                let shown = shown.borrow();
                assert_eq!(shown.len(), 1);
                assert_eq!(shown[0].1, keys_ui::LOSTPICK);
                let rows: Vec<&str> = shown[0].2.split('|').collect();
                assert_eq!(rows.len(), 3);
                assert!(
                    rows.iter()
                        .zip(1..)
                        .all(|(r, n)| r.starts_with(&format!("보안 키 {n} · ")))
                );
                assert!(!shown[0].2.contains("이번에 연 키"));
            }
            assert_eq!(fake.seen().len(), seen_before + 1);
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(!s.gate_pending() && !s.tofu());
                assert_eq!(*a.status, keys_ui::GATE_PASSED);
                a.lock("synthetic lock", true);
            });

            // A removes key 2; B picks key 1 instead: S-GATE-G2FAIL-DISK.
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            remove(&mut a, 2);
            let code_e3 = a.key_code().unwrap();
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            copy((&va, &ka));
            every_input(|_, _, kind| {
                assert!(matches!(kind, InputKind::Pick(_)));
                InputAnswer::Pick(vec![0])
            });
            login(devices[0]);
            stop_answers();
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(s.gate_pending());
                assert_eq!(s.login_gate(), Some(vault::GateKind::G1));
                assert_eq!(*a.status, vault::GATE_G2FAIL_DISK);
                a.lock("synthetic lock", true);
            });
            // The next login asks the code first; a wrong one asks again,
            // and the status line behind it shows nothing of the changed
            // file (its one key: no S-ONEKEY before the gate passed; spec
            // §5.10, round 2 finding 3). [나중에] leaves it gate-pending.
            let behind = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = behind.clone();
            every_input(move |n, _, kind| {
                assert!(matches!(kind, InputKind::Code(_)));
                record.borrow_mut().push(status());
                match n {
                    0 => InputAnswer::Code(Zeroizing::new("E3 · 0123-4567-89AB-CDEF".into())),
                    _ => InputAnswer::Cancel(keys_ui::GATE_LATER),
                }
            });
            login(devices[0]);
            stop_answers();
            assert_eq!(behind.borrow().len(), 2);
            assert!(
                !behind.borrow()[1].contains(keys_ui::ONEKEY),
                "{:?}",
                behind.borrow()
            );
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(s.gate_pending());
                assert!(!a.status.contains(keys_ui::ONEKEY));
                a.command(CHANGE, 0).unwrap();
                // [받기…] needs no password; the per-vault forget beside it
                // does (spec §5.10).
                assert!(a.handle(keys_ui::KEY_ACCEPT) != 0 && a.handle(CURRENT_PASS) != 0);
                assert!(a.handle(keys_ui::ANCHOR_FORGET) != 0);
            });
            // [받기…]: S-GATE-CODE; a malformed code, a wrong one, then the
            // code without its prefix.
            let texts = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = texts.clone();
            let digits = code_e3.split(" · ").nth(1).unwrap().to_owned();
            every_input(move |n, text, kind| {
                let InputKind::Code(typed) = kind else {
                    panic!("not a code");
                };
                record
                    .borrow_mut()
                    .push((text.to_owned(), typed.to_string()));
                InputAnswer::Code(Zeroizing::new(match n {
                    0 => "not a code".to_owned(),
                    1 => "E3 · 0123-4567-89AB-CDEF".to_owned(),
                    _ => digits.clone(),
                }))
            });
            press(h, keys_ui::KEY_ACCEPT);
            stop_answers();
            {
                // Each code asked again starts with the one typed before
                // (spec §2.29).
                let typed: Vec<String> = texts.borrow().iter().map(|t| t.1.clone()).collect();
                assert_eq!(typed, ["", "not a code", "E3 · 0123-4567-89AB-CDEF"]);
                let texts: Vec<String> = texts.borrow().iter().map(|t| t.0.clone()).collect();
                assert_eq!(texts.len(), 3);
                let code_text = fill(keys_ui::GATE_CODE_TEXT, &[&3]);
                assert_eq!(texts[0], code_text);
                assert_eq!(texts[1], format!("{}\n\n{code_text}", keys_ui::CODE_FORMAT));
                assert_eq!(
                    texts[2],
                    format!("{}\n\n{code_text}", vault::GATE_CODE_WRONG)
                );
            }
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(!s.gate_pending());
                // The unlock's key lines come with the pass: one key left.
                assert_eq!(
                    *a.status,
                    format!("{}\r\n{}", keys_ui::GATE_PASSED, keys_ui::ONEKEY)
                );
                assert!(a.screen == Screen::Keys && a.handle(keys_ui::KEY_ACCEPT) == 0);
            });
            drop(a);
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// Four keys registered together on one PC, as a 4-key vault of
        /// `dir` with password `pass`, the anchor of `dir`: the session and
        /// the fake devices of keys 1-4.
        fn four_keys(fake: &Arc<Fake>, dir: &Path, pass: &str) -> (Session, Vec<usize>) {
            let devices: Vec<usize> = (0..4).map(|_| fake.plug(Device::default())).collect();
            let provision = Provision::new().unwrap();
            let id = provision.vault_id();
            let keys: Vec<_> = devices
                .iter()
                .zip(1u8..)
                .map(|(d, n)| {
                    fake.touch(Some(*d));
                    register(&**fake, &id, n, 0, false, Vec::new()).unwrap()
                })
                .collect();
            vault::set_anchor_dir(Some(dir.join("anchor")));
            let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
            let s = provision
                .finish_with_keys(&vault, &key, pass, false, keys)
                .unwrap();
            (s, devices)
        }
        fn controls_of(ids: &[i32]) -> Vec<bool> {
            with_app(|a| ids.iter().map(|id| a.handle(*id) != 0).collect())
        }

        /// The lost-key flow and the retirement on one PC (spec §9.1,
        /// §9.2, §14.8-9): the date field starts empty, no exposure answer
        /// is set, and 모름 ticks the password change and shows the
        /// shared-PIN toggles; unticking asks S-LOST-PWUNTICK. Key 1 is
        /// removed with one touch from an allow list without it, the new
        /// password and the shared PIN recorded, S-LOST-DONE in the dialog
        /// and S-CLONED for key 3; the empty merge log marks the review done.
        /// Then "키 빼기" retires key 4 after S-REMOVE, with S-RETIRE and no
        /// review.
        #[test]
        fn lost_key_and_retire_flows() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-lost");
            let (pass, newpass) = (
                "synthetic lost key password",
                "synthetic lost key new password",
            );
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (s, devices) = four_keys(&fake, &dir, pass);
            let (vault, key) = (s.path.clone(), s.key_path.clone());
            drop(s);
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyLost", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            auth.plan(&[Some(devices[1])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            press(h, keys_ui::KEY_LOST);
            use keys_ui::*;
            with_app(|a| {
                assert!(a.screen == Screen::LostKey);
                assert!(a.read(LOSS_DATE).unwrap().is_empty());
                assert!(a.toggles.exposure.is_none() && !a.toggles.pwchange);
            });
            assert_eq!(
                controls_of(&[
                    LOSS_YES,
                    LOSS_NO,
                    LOSS_UNSURE,
                    LOSS_PWCHANGE,
                    SHARED_ITEM,
                    PASS
                ]),
                [true, true, true, false, false, false]
            );
            // Nothing picked, then no exposure answer: refused before any
            // touch.
            let before = fake.seen().len();
            press(h, SUBMIT);
            assert_eq!(status(), LOST_PICK_NONE);
            press(h, KEY_PICK_ITEM);
            set(h, CURRENT_PASS, pass);
            press(h, SUBMIT);
            assert_eq!(status(), EXPOSE_NEEDED);
            assert_eq!(fake.seen().len(), before, "no ceremony yet");
            // 모름: the password change ticked, its fields and the shared
            // PIN toggles of the other keys.
            press(h, LOSS_UNSURE);
            with_app(|a| assert!(a.toggles.pwchange));
            assert_eq!(
                controls_of(&[LOSS_PWCHANGE, PASS, CONFIRM, SHARED_ITEM, SHARED_ITEM + 2]),
                [true, true, true, false, true]
            );
            // Unticking asks S-LOST-PWUNTICK; No keeps it.
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            press(h, LOSS_PWCHANGE);
            stop_answers();
            assert_eq!(*asked.borrow(), [PWUNTICK]);
            asked.borrow_mut().clear();
            with_app(|a| assert!(a.toggles.pwchange));
            press(h, SHARED_ITEM + 2);
            set(h, LOSS_DATE, "2026-02-31");
            set(h, CURRENT_PASS, pass);
            set(h, PASS, newpass);
            set(h, CONFIRM, newpass);
            press(h, SUBMIT);
            assert_eq!(status(), DATE_FORMAT);
            set(h, LOSS_DATE, "2026-10-01");
            set(h, CURRENT_PASS, pass);
            set(h, PASS, newpass);
            set(h, CONFIRM, newpass);
            auth.plan(&[Some(devices[1])]);
            every_answer(&asked, |_| false);
            let told = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = told.clone();
            every_input(move |_, text, kind| {
                assert!(matches!(kind, InputKind::Preview { check: None }));
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(*asked.borrow(), [BACKUP_QUESTION], "{}", status());
            asked.borrow_mut().clear();
            // One touch, from an allow list of the staying keys only.
            let calls = fake.seen();
            assert_eq!(calls.len(), seen + 1);
            assert_eq!(calls.last().unwrap().credentials.len(), 3);
            assert!(status().starts_with(&fill(LOST_DONE_SHORT, &[&"1"])));
            {
                let told = told.borrow();
                assert_eq!(told.len(), 1);
                assert!(told[0].starts_with(&fill(LOST_DONE, &[&"1", &"1"])));
                assert!(told[0].contains(&fill(CLONED, &[&"3"])));
            }
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                let o = s.keys_overview().unwrap();
                assert_eq!(numbers(&Some(o.clone())), [2, 3, 4]);
                assert!(o.rows.iter().find(|r| r.number == 3).unwrap().cloned);
                // Nothing came in by sync: the review is done at once.
                assert!(s.review_due().is_none());
                assert!(a.screen == Screen::Keys);
            });

            // "키 빼기": key 4, retired after S-REMOVE; S-RETIRE names it.
            press(h, KEY_REMOVE);
            with_app(|a| assert!(a.screen == Screen::KeyRemove && !a.toggles.pwchange));
            assert_eq!(controls_of(&[REMOVE_PWCHANGE, PASS]), [true, false]);
            press(h, KEY_PICK_ITEM + 2);
            set(h, CURRENT_PASS, newpass);
            auth.plan(&[Some(devices[2])]);
            every_answer(&asked, |text| text.starts_with("선택한 보안 키 4"));
            told.borrow_mut().clear();
            let record = told.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(asked.borrow().len(), 2, "{:?}", asked.borrow());
            assert_eq!(asked.borrow()[1], BACKUP_QUESTION);
            assert_eq!(told.borrow().len(), 1);
            assert!(told.borrow()[0].contains("Goyo Vault "));
            assert!(
                status().starts_with(&fill(REMOVED, &[&"4"])),
                "{}",
                status()
            );
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert_eq!(numbers(&s.keys_overview()), [2, 3]);
                assert!(s.review_due().is_none());
                a.lock("synthetic lock", true);
            });
            // The new password opens with key 3; key 1 is gone.
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, newpass);
            press(h, SUBMIT);
            with_app(|a| assert!(a.session.is_some(), "{}", *a.status));
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// The 4-key, 2-site walkthrough at UI level, in USB mode (spec
        /// §7.21-17, §7.7-14(a), §14.8-9): keys 1-4 registered together,
        /// keys 1 and 2 at PC A, keys 3 and 4 at PC B, both syncing the
        /// vault. An entry A adds comes in to B by sync (a provenance line).
        /// At A key 1 is lost: one touch of key 2 removes it (never key 1 in
        /// the allow list) and A is protected at once (S-LOST-DONE-USB).
        /// A's key file goes to B on a stick: "새 열쇠 파일 받기" asks
        /// S-LOSTPICK first, B picks key 1, the Reauth touch of key 3 opens
        /// both files, and B takes it as a successor; S-REVIEW lists the
        /// entry, a row opens it, and [확인함] releases B's upload, which
        /// waited for it.
        #[test]
        fn four_keys_two_sites_lost_key_walkthrough() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("site-a"), test_dir("site-b"));
            let pass = "synthetic two sites password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (mut a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let mut server = Server::default();
            server.helper(&va);
            a.enable_sync().unwrap();
            upload(&mut server, &mut a);
            let code = a.key_code().unwrap();
            let id = a.vault_id();
            // PC B: the same vault and key file, its own helper and anchor.
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            server.helper(&vb);
            server.pass(&vb);
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonySites", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let login = |device: usize, anchor: &Path, vault: &Path, key: &Path| {
                vault::set_anchor_dir(Some(anchor.to_path_buf()));
                with_app(|a| {
                    a.vault_path = vault.to_path_buf();
                    a.key_path = key.to_path_buf();
                    if a.screen != Screen::Login {
                        a.show(Screen::Login);
                    }
                    a.build();
                });
                auth.plan(&[Some(device)]);
                set(h, PASS, pass);
                press(h, SUBMIT);
                with_app(|a| assert!(a.session.is_some(), "{}", *a.status));
            };
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            // B confirms the key file with A's code (TOFU).
            login(devices[2], &anchor_b, &vb, &kb);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                assert_eq!(*a.status, keys_ui::TOFU_PASSED);
                a.lock("synthetic lock", true);
            });
            // A adds an entry; B merges it at its next unlock and logs it.
            vault::set_anchor_dir(Some(anchor_a.clone()));
            a.put(None, sync_entry("Injected IBAN", "DE00 0000 0000"))
                .unwrap();
            upload(&mut server, &mut a);
            drop(a);
            server.pass(&vb);
            login(devices[2], &anchor_b, &vb, &kb);
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(s.entries.iter().any(|e| *e.title == "Injected IBAN"));
                a.lock("synthetic lock", true);
            });
            let log = anchor_b
                .join("goyo-vault.merges")
                .join(format!("{}.log", hex(&id)));
            let text = std::fs::read_to_string(&log).unwrap();
            assert!(text.lines().any(|l| l.contains(" + ")), "{text}");

            // PC A: key 1 is lost; one touch of key 2 removes it.
            login(devices[1], &anchor_a, &va, &ka);
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            press(h, keys_ui::KEY_LOST);
            press(h, keys_ui::KEY_PICK_ITEM);
            press(h, keys_ui::LOSS_NO);
            set(h, keys_ui::LOSS_DATE, "2020-01-01");
            set(h, CURRENT_PASS, pass);
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            every_input(|_, _, _| InputAnswer::Accept { checked: false });
            auth.plan(&[Some(devices[1])]);
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(*asked.borrow(), [BACKUP_QUESTION], "{}", status());
            asked.borrow_mut().clear();
            assert_eq!(fake.seen().len(), seen + 1);
            assert_eq!(fake.seen().last().unwrap().credentials.len(), 3);
            assert!(
                status().starts_with(&fill(keys_ui::LOST_DONE_USB_SHORT, &[&"1"])),
                "{}",
                status()
            );
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert_eq!(numbers(&s.keys_overview()), [2, 3, 4]);
                // A's log is empty: its review was done at once.
                assert!(s.review_due().is_none());
                a.lock("synthetic lock", true);
            });
            let carried = dir_b.join("from-a.goyokey");
            std::fs::copy(&ka, &carried).unwrap();

            // PC B: "새 열쇠 파일 받기" with A's file: S-LOSTPICK first with
            // B's own four keys, then the Reauth touch of key 3.
            login(devices[2], &anchor_b, &vb, &kb);
            with_app(|a| {
                a.command(CHANGE, 0).unwrap();
                a.adopt_source = Some(carried.clone());
                a.show(Screen::Adopt);
                a.build();
            });
            set(h, CURRENT_PASS, pass);
            let shown = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = shown.clone();
            let devices_seen = fake.seen().len();
            every_input(move |n, text, kind| {
                record.borrow_mut().push(text.to_owned());
                match (n, kind) {
                    (0, InputKind::Pick(items)) => {
                        assert_eq!(items.len(), 4);
                        assert_eq!(text, keys_ui::LOSTPICK);
                        InputAnswer::Pick(vec![0])
                    }
                    (1, InputKind::Preview { .. }) => InputAnswer::Accept { checked: false },
                    _ => panic!("unexpected input {n}: {text}"),
                }
            });
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[2])]);
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(shown.borrow().len(), 2, "{}", status());
            assert_eq!(*asked.borrow(), [BACKUP_QUESTION]);
            // One ceremony: the Reauth touch, which opened A's file too.
            assert_eq!(fake.seen().len(), devices_seen + 1);
            let outgoing = syncfile::sync_dir(&vb).unwrap().join(syncfile::OUTGOING);
            let before = std::fs::read(&outgoing).ok();
            with_app(|a| {
                assert!(a.screen == Screen::Review, "{}", *a.status);
                let s = a.session.as_ref().unwrap();
                assert_eq!(numbers(&s.keys_overview()), [2, 3, 4]);
                assert_eq!(s.review_due(), Some("20200101"));
                let list = a.handle(keys_ui::REVIEW_LIST);
                let n = unsafe { SendMessageW(list, 0x18b, 0, 0) }; // LB_GETCOUNT
                assert_eq!(n, 1);
            });
            // A row opens its entry; leaving the edit screen comes back.
            with_app(|a| unsafe {
                SendMessageW(a.handle(keys_ui::REVIEW_LIST), 0x186, 0, 0); // LB_SETCURSEL
            });
            with_app(|a| a.command(keys_ui::REVIEW_LIST, 2)).unwrap();
            with_app(|a| {
                assert!(a.screen == Screen::Edit);
                let s = a.session.as_ref().unwrap();
                assert_eq!(*s.entries[a.editing.unwrap()].title, "Injected IBAN");
            });
            press(h, CANCEL);
            with_app(|a| assert!(a.screen == Screen::Review));
            // [확인함]: the review done, and the upload that waited for it.
            press(h, keys_ui::REVIEW_OK);
            with_app(|a| {
                assert!(a.screen == Screen::Vault);
                assert_eq!(*a.status, keys_ui::REVIEW_DONE);
                assert!(a.session.as_ref().unwrap().review_due().is_none());
            });
            let after = std::fs::read(&outgoing).ok();
            assert!(after.is_some() && after != before);
            let text = std::fs::read_to_string(&log).unwrap();
            assert!(text.lines().last().unwrap().ends_with(" D"), "{text}");
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        fn hex(id: &[u8; 16]) -> String {
            id.iter().map(|b| format!("{b:02x}")).collect()
        }

        /// The fork options (spec §5.8 "Forks", §9.2 adopt step 2.2,
        /// §14.8-9; walkthrough §7.7-14(b)): both sites removed lost key 1,
        /// A with key 2 and B with key 3. At B, A's key file is a fork:
        /// S-FORK comes first, before any touch, with no option as the
        /// default and no key number; [둘 다 합치기] needs no gate (nothing
        /// of B's is removed), and one touch of key 3 joins the two files.
        /// [취소] there writes nothing.
        #[test]
        fn fork_options_come_first_and_join_both_removals() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("fork-a"), test_dir("fork-b"));
            let pass = "synthetic fork options password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let code = a.key_code().unwrap();
            drop(a);
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyFork", &va, &ka, auth.clone(), &clock);
            let guard = Window(h);
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            let open = |device: usize, anchor: &Path, vault: &Path, key: &Path| {
                vault::set_anchor_dir(Some(anchor.to_path_buf()));
                with_app(|a| {
                    a.vault_path = vault.to_path_buf();
                    a.key_path = key.to_path_buf();
                    if a.screen != Screen::Login {
                        a.show(Screen::Login);
                    }
                    a.build();
                });
                auth.plan(&[Some(device)]);
                set(h, PASS, pass);
                press(h, SUBMIT);
                with_app(|a| assert!(a.session.is_some(), "{}", *a.status));
            };
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            let remove_lost = |device: usize| {
                with_app(|a| a.command(CHANGE, 0)).unwrap();
                press(h, keys_ui::KEY_LOST);
                press(h, keys_ui::KEY_PICK_ITEM);
                press(h, keys_ui::LOSS_NO);
                set(h, CURRENT_PASS, pass);
                every_answer(&asked, |_| false);
                every_input(|_, _, _| InputAnswer::Accept { checked: false });
                auth.plan(&[Some(device)]);
                press(h, SUBMIT);
                stop_answers();
                assert!(status().starts_with(&fill(keys_ui::LOST_DONE_SHORT, &[&"1"])));
                with_app(|a| a.lock("synthetic lock", true));
            };
            open(devices[1], &anchor_a, &va, &ka);
            remove_lost(devices[1]);
            // B: a copy of the first state, confirmed in its TOFU banner
            // with the code A showed for it.
            open(devices[2], &anchor_b, &vb, &kb);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            remove_lost(devices[2]);
            let carried = dir_b.join("from-a.goyokey");
            std::fs::copy(&ka, &carried).unwrap();
            open(devices[2], &anchor_b, &vb, &kb);
            let adopt = || {
                with_app(|a| {
                    a.command(CHANGE, 0).unwrap();
                    a.adopt_source = Some(carried.clone());
                    a.show(Screen::Adopt);
                    a.build();
                });
                set(h, CURRENT_PASS, pass);
            };
            // [취소] at S-FORK: no touch, nothing written.
            adopt();
            let before = std::fs::read(&kb).unwrap();
            let seen = fake.seen().len();
            let texts = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = texts.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Cancel(2)
            });
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(*texts.borrow(), [keys_ui::FORK]);
            assert_eq!(fake.seen().len(), seen);
            assert_eq!(std::fs::read(&kb).unwrap(), before);
            // [둘 다 합치기]: no gate, one touch of key 3, a union.
            texts.borrow_mut().clear();
            let record = texts.clone();
            every_input(move |n, text, kind| {
                record.borrow_mut().push(text.to_owned());
                match (n, kind) {
                    (0, InputKind::Preview { check: None }) => {
                        InputAnswer::Switch(keys_ui::FORK_OPT2)
                    }
                    (1, InputKind::Preview { .. }) => InputAnswer::Accept { checked: false },
                    _ => panic!("unexpected input {n}: {text}"),
                }
            });
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[2])]);
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(texts.borrow().len(), 2, "{}", status());
            assert_eq!(texts.borrow()[0], keys_ui::FORK);
            assert!(texts.borrow()[1].starts_with(ADOPT_UNION));
            assert_eq!(fake.seen().len(), seen + 1);
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert_eq!(numbers(&s.keys_overview()), [2, 3, 4]);
                assert!(a.screen == Screen::Vault, "{}", *a.status);
            });
            assert_ne!(std::fs::read(&kb).unwrap(), before);
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// A MakeCredential that fails with a code the app does not know
        /// says that the key's store may be full (S-KEYSTORE-FULL, spec
        /// §8.7, §14.8-9), and a WM_QUIT during a later key's registration
        /// ends the flow with nothing written, never a loop of questions
        /// (spec §8.6).
        #[test]
        fn a_failed_registration_names_a_full_store_and_a_quit_ends_it() {
            /// The fake with every MakeCredential failing with `code`.
            struct Full {
                fake: Arc<Fake>,
            }
            impl Authenticator for Full {
                fn api_version(&self) -> u32 {
                    self.fake.api_version()
                }
                fn new_cancel(&self) -> Result<CancelToken, FidoError> {
                    self.fake.new_cancel()
                }
                fn make_credential(
                    &self,
                    _: &MakeRequest,
                    _: &CancelToken,
                ) -> Result<RawCredential, FidoError> {
                    Err(FidoError::Other(0x8000_4005_u32 as i32))
                }
                fn get_assertion(
                    &self,
                    r: &AssertRequest,
                    c: &CancelToken,
                ) -> Result<RawAssertion, FidoError> {
                    self.fake.get_assertion(r, c)
                }
                fn cancel(&self, c: &CancelToken) {
                    self.fake.cancel(c)
                }
            }
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-full");
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (k1, k2) = (fake.plug(Device::default()), fake.plug(Device::default()));
            let h = window(
                "GoyoCeremonyFull",
                &dir.join("none.goyo"),
                &dir.join("none.goyokey"),
                Arc::new(Full { fake: fake.clone() }),
                &clock,
            );
            let guard = Window(h);
            let pass = "synthetic full store password";
            let create = |name: &str| {
                let (vault, key) = (
                    dir.join(format!("{name}.goyo")),
                    dir.join(format!("{name}.goyokey")),
                );
                with_app(|a| {
                    a.provision = Some(Provision::new().unwrap());
                    a.new_vault_path = vault.clone();
                    a.new_key_path = key.clone();
                    a.toggles = keys_ui::Toggles::default();
                    a.show(Screen::Create);
                    a.build();
                });
                press(h, keys_ui::SK_TOGGLE);
                set(h, PASS, pass);
                set(h, CONFIRM, pass);
                (vault, key)
            };
            let (vault, key) = create("full");
            fake.touch(Some(k1));
            press(h, SUBMIT);
            assert!(!vault.exists() && !key.exists());
            let expected = format!(
                "{}\r\n{}",
                fill(fido::OTHER, &[&"80004005"]),
                fido::KEYSTORE_FULL
            );
            assert_eq!(status(), expected);

            // Key 1 registered, S-SPARE's yes, then a WM_QUIT while key 2's
            // MakeCredential runs: nothing is written and nothing more is
            // asked (a No to every question would otherwise write key 1).
            let auth = Scripted::new(fake.clone());
            let owned = Owned {
                auth: auth.clone(),
                window: h,
            };
            AUTHENTICATOR.with(|a| *a.borrow_mut() = Some(Arc::new(owned)));
            let (vault, key) = create("quit");
            auth.plan(&[Some(k1); 2]);
            let ui = unsafe { GetCurrentThreadId() };
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            let (gap, script) = (fake.clone(), auth.clone());
            let driver: std::rc::Rc<RefCell<Option<JoinHandle<bool>>>> = Default::default();
            let started = driver.clone();
            let mut once = true;
            every_answer(&asked, move |text| {
                if text.ends_with(&fill(keys_ui::SPARE, &[&1])) && std::mem::take(&mut once) {
                    script.plan(&[Some(k2)]);
                    *started.borrow_mut() = Some(in_the_gap(&gap, move || unsafe {
                        PostThreadMessageW(ui, 0x12, 9, 0);
                        std::thread::sleep(Duration::from_millis(100));
                    }));
                    return true;
                }
                // S-NOSPARE's yes would write the vault with key 1.
                text == keys_ui::NOSPARE
            });
            press(h, SUBMIT);
            stop_answers();
            assert!(driver.borrow_mut().take().unwrap().join().unwrap());
            assert_eq!(asked.borrow().len(), 1, "{:?}", asked.borrow());
            assert!(!vault.exists() && !key.exists(), "{}", status());
            unsafe {
                let mut msg = Msg::default();
                assert_ne!(PeekMessageW(&mut msg, 0, 0x12, 0x12, 1), 0);
                assert_eq!(msg.wparam, 9);
            }
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A key file with security keys changes its password with a touch
        /// (spec §9.2 "Password change (both)" step 3, §14.8-9): S-ROTATE,
        /// one ceremony of a key that reaches every other, the write, its
        /// backup; the new password opens with a key afterwards.
        #[test]
        fn a_password_change_with_keys_takes_a_touch() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-password");
            let (pass, newpass) = (
                "synthetic keyed password one",
                "synthetic keyed password two",
            );
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (s, devices) = four_keys(&fake, &dir, pass);
            let (vault, key) = (s.path.clone(), s.key_path.clone());
            drop(s);
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyPassword", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            auth.plan(&[Some(devices[0])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            with_app(|a| a.command(KEY_PASSWORD, 0)).unwrap();
            with_app(|a| assert!(a.screen == Screen::Password));
            set(h, CURRENT_PASS, pass);
            set(h, PASS, newpass);
            set(h, CONFIRM, newpass);
            auth.plan(&[Some(devices[1])]);
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |text| text == ROTATE_QUESTION);
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(
                *asked.borrow(),
                [ROTATE_QUESTION, BACKUP_QUESTION],
                "{}",
                status()
            );
            assert_eq!(fake.seen().len(), seen + 1);
            assert_eq!(fake.seen().last().unwrap().credentials.len(), 4);
            assert!(status().starts_with(PASSWORD_CHANGED), "{}", status());
            with_app(|a| {
                assert!(a.screen == Screen::Keys);
                a.lock("synthetic lock", true);
            });
            auth.plan(&[Some(devices[3])]);
            set(h, PASS, newpass);
            press(h, SUBMIT);
            with_app(|a| assert!(a.session.is_some(), "{}", *a.status));
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A key added with key 1 alone is paired with it only (spec §9.2a,
        /// §14.4-14): losing key 1 asks S-ONLYPAIRED (kept here), then
        /// S-SUSPEND names key 5 before any touch; [그 키도 함께 터치] plans
        /// it as an extra touch, so key 3 is touched, then key 5, and the
        /// removal leaves no key suspended. A cancelled optional pairing at
        /// the addition keeps the registration and asks S-ADD-PAIR again.
        #[test]
        fn a_key_paired_with_one_key_is_kept_with_an_extra_touch() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-extra");
            let pass = "synthetic extra touch password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (s, devices) = four_keys(&fake, &dir, pass);
            let (vault, key) = (s.path.clone(), s.key_path.clone());
            drop(s);
            let k5 = fake.plug(Device::default());
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyExtra", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            auth.plan(&[Some(devices[0])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            // [키 추가] with key 1: S-ADD-PAIR's yes, a cancelled touch,
            // S-ADD-PAIR again, No: key 5 is written, paired with key 1.
            set(h, CURRENT_PASS, pass);
            auth.plan(&[Some(devices[0]), Some(k5), Some(k5), None]);
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            let mut first = true;
            every_answer(&asked, move |text| {
                if text == keys_ui::ADD_PAIR {
                    return std::mem::take(&mut first);
                }
                false
            });
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            assert_eq!(
                *asked.borrow(),
                [keys_ui::ADD_PAIR, keys_ui::ADD_PAIR, keys_ui::BACKUP_SHORT]
            );
            asked.borrow_mut().clear();
            let o = with_app(|a| a.session.as_ref().unwrap().keys_overview()).unwrap();
            assert_eq!(numbers(&Some(o.clone())), [1, 2, 3, 4, 5]);
            assert_eq!(o.rows[4].unpaired, [2, 3, 4]);

            // Key 1 is lost.
            press(h, keys_ui::KEY_LOST);
            press(h, keys_ui::KEY_PICK_ITEM);
            press(h, keys_ui::LOSS_NO);
            set(h, CURRENT_PASS, pass);
            let texts = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = texts.clone();
            every_input(move |n, text, kind| {
                assert!(matches!(kind, InputKind::Preview { check: None }));
                record.borrow_mut().push(text.to_owned());
                match n {
                    // S-ONLYPAIRED: [남겨 두기].
                    0 => InputAnswer::Cancel(2),
                    // S-SUSPEND: [그 키도 함께 터치].
                    1 => InputAnswer::Switch(keys_ui::SUSPEND_TOUCH),
                    _ => InputAnswer::Accept { checked: false },
                }
            });
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[2]), Some(k5)]);
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            {
                let texts = texts.borrow();
                assert_eq!(texts.len(), 3, "{}", status());
                assert_eq!(texts[0], fill(keys_ui::ONLYPAIRED, &[&"5"]));
                assert!(texts[1].starts_with(&fill(keys_ui::SUSPEND, &[&"5"])));
            }
            let calls = fake.seen();
            assert_eq!(calls.len(), seen + 2);
            // The touch never lists key 5 (planned) nor key 1 (removed); the
            // extra touch lists key 5 alone.
            assert_eq!(calls[seen].credentials.len(), 3);
            assert_eq!(calls[seen + 1].credentials.len(), 1);
            let o = with_app(|a| a.session.as_ref().unwrap().keys_overview()).unwrap();
            assert_eq!(numbers(&Some(o.clone())), [2, 3, 4, 5]);
            assert!(o.rows.iter().all(|r| !r.suspended));
            assert!(status().starts_with(&fill(keys_ui::LOST_DONE_SHORT, &[&"1"])));
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A halted vault channel holds no removal for a loss (spec §7.5,
        /// S-LOST-HALTED): PC B, halted by A's upload under a new key, still
        /// shows the security-key section beside the halt and its override,
        /// opens the lost-key screen and removes the key, and the done text
        /// says why it went ahead.
        #[test]
        fn a_halted_pc_can_still_remove_a_lost_key() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("halt-a"), test_dir("halt-b"));
            let pass = "synthetic halted removal password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (mut a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let mut server = Server::default();
            server.helper(&va);
            a.enable_sync().unwrap();
            upload(&mut server, &mut a);
            let code = a.key_code().unwrap();
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            server.helper(&vb);
            server.pass(&vb);
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyHalted", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            vault::set_anchor_dir(Some(anchor_b.clone()));
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                assert_eq!(*a.status, keys_ui::TOFU_PASSED);
                a.lock("synthetic lock", true);
            });
            // A retires key 4 with key 2's touch and uploads under its new
            // key (a removal for a loss would hold A's upload for its
            // review).
            vault::set_anchor_dir(Some(anchor_a));
            let t = touched(&fake, devices[1], &a, 2);
            let r = a.reauth(pass, Some(&t)).unwrap();
            let change = vault::Change::Remove {
                remove: vec![4],
                new_password: None,
                loss: None,
                over: None,
            };
            a.rekey(r, vec![], change, vault::Consent::default(), false)
                .unwrap();
            upload(&mut server, &mut a);
            drop(a);
            // B: halted at its next unlock.
            vault::set_anchor_dir(Some(anchor_b));
            server.pass(&vb);
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().halted_head().is_some());
                a.command(CHANGE, 0).unwrap();
            });
            assert_eq!(
                controls_of(&[keys_ui::KEY_LOST, KEY_OVERRIDE_HEAD, CURRENT_PASS]),
                [true, true, true]
            );
            press(h, keys_ui::KEY_LOST);
            with_app(|a| assert!(a.screen == Screen::LostKey));
            press(h, keys_ui::KEY_PICK_ITEM);
            press(h, keys_ui::LOSS_NO);
            set(h, CURRENT_PASS, pass);
            let told = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = told.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[2])]);
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(*asked.borrow(), [BACKUP_QUESTION], "{}", status());
            assert!(
                told.borrow()[0].contains(keys_ui::LOST_HALTED),
                "{:?}",
                told.borrow()
            );
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert_eq!(numbers(&s.keys_overview()), [2, 3, 4]);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// After S-ANCHOR-DOWNGRADE (a password-only key file for a vault
        /// this PC pins as hardware) the login screen offers the per-vault
        /// forget for exactly these files (spec §5.10): S-ANCHOR-FORGET with
        /// the record's revision, then the same login as a bootstrap (the
        /// TOFU banner); the refusal has no last resort in this build. A
        /// changed key path withdraws the offer.
        #[test]
        fn an_anchor_refusal_offers_the_per_vault_forget() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("forget-a"), test_dir("forget-b"));
            let pass = "synthetic forget password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (mut a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let code = a.key_code().unwrap();
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyForget", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            vault::set_anchor_dir(Some(anchor_b.clone()));
            // The login note counts this PC's keys.
            with_app(|a| {
                let note = caption(a.handle(keys_ui::LOGIN_NOTE));
                assert!(
                    note.starts_with(&fill(keys_ui::LOGIN_KEYS, &[&4])),
                    "{note}"
                );
            });
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| a.lock("synthetic lock", true));
            // A turns the keys off; B gets that key file.
            vault::set_anchor_dir(Some(anchor_a));
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(pass, Some(&t)).unwrap();
            a.rekey(
                r,
                vec![],
                vault::Change::KeysOff,
                vault::Consent::default(),
                false,
            )
            .unwrap();
            drop(a);
            std::fs::copy(&ka, &kb).unwrap();
            vault::set_anchor_dir(Some(anchor_b));
            // WS_VISIBLE of the control (the test's window is never shown).
            let visible = |id: i32| {
                with_app(|a| unsafe { GetWindowLongPtrW(a.handle(id), -16) & 0x1000_0000 != 0 })
            };
            // The login note keeps this PC's count of keys while the key
            // file differs from its record (round 2, finding 3).
            set(h, KPATH, &kb.to_string_lossy());
            with_app(|a| a.command(KPATH, 0x300)).unwrap();
            with_app(|a| {
                let note = caption(a.handle(keys_ui::LOGIN_NOTE));
                assert!(
                    note.starts_with(&fill(keys_ui::LOGIN_KEYS, &[&4])),
                    "{note}"
                );
            });
            set(h, PASS, pass);
            press(h, SUBMIT);
            assert_eq!(status(), vault::ANCHOR_DOWNGRADE);
            assert!(!status().contains("goyo-vault.keys"));
            assert!(visible(keys_ui::ANCHOR_FORGET) && !visible(keys_ui::LOGIN_NOTE));
            // Another key path withdraws it; the same one is refused again.
            set(h, KPATH, &dir_b.join("other.goyokey").to_string_lossy());
            with_app(|a| a.command(KPATH, 0x300)).unwrap();
            assert!(!visible(keys_ui::ANCHOR_FORGET) && visible(keys_ui::LOGIN_NOTE));
            set(h, KPATH, &kb.to_string_lossy());
            with_app(|a| a.command(KPATH, 0x300)).unwrap();
            set(h, PASS, pass);
            press(h, SUBMIT);
            assert!(visible(keys_ui::ANCHOR_FORGET));
            // S-ANCHOR-FORGET's yes and S-OLDER's: a bootstrap.
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| true);
            let seen = fake.seen().len();
            set(h, PASS, pass);
            press(h, keys_ui::ANCHOR_FORGET);
            stop_answers();
            assert_eq!(asked.borrow()[0], fill(keys_ui::FORGET, &[&1]));
            assert_eq!(fake.seen().len(), seen, "a password-only key file");
            with_app(|a| {
                let s = a.session.as_ref().expect("opened");
                assert!(s.tofu() && a.tofu_banner(), "{}", *a.status);
                assert!(a.forget_for.is_none());
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// Two sites add a key from the same state, both numbered 5 (spec
        /// §5.8, §7.15a, §9.2 adopt step 3; §14.8-9). At B, A's file is a
        /// fork: [둘 다 합치기] asks A's code (A's key is new here), one touch
        /// of key 3 opens both files, and the preview and S-SUSPEND name A's
        /// key by A's number with "이 PC에서 처음 보는 키", with no [그 키도
        /// 함께 터치] (B has no seed of it). The union keeps A's numbers, so
        /// B's own key 5 becomes key 6: S-ADOPT-RENUMBER in the danger tone.
        #[test]
        fn colliding_additions_renumber_and_name_new_keys() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("collide-a"), test_dir("collide-b"));
            let pass = "synthetic colliding keys password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (mut a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let code = a.key_code().unwrap();
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            // A adds X as key 5 with key 1's touch.
            let x = fake.plug(Device::default());
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(pass, Some(&t)).unwrap();
            let (planned, exclude) = a.add_plan(1).unwrap();
            assert_eq!(planned, [5]);
            fake.touch(Some(x));
            let new = register(&*fake, &a.vault_id(), 5, 0, false, exclude).unwrap();
            a.rekey(
                r,
                vec![],
                vault::Change::AddKey(new),
                vault::Consent::default(),
                false,
            )
            .unwrap();
            let code_a = a.key_code().unwrap();
            drop(a);
            let carried = dir_b.join("from-a.goyokey");
            std::fs::copy(&ka, &carried).unwrap();
            // B: confirmed, then adds Y as its own key 5 with key 3.
            let y = fake.plug(Device::default());
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyCollide", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            set(h, CURRENT_PASS, pass);
            auth.plan(&[Some(devices[2]), Some(y), Some(y)]);
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            assert!(
                status().starts_with(&fill(keys_ui::ADDED, &[&5])),
                "{}",
                status()
            );
            // The adopt of A's file.
            with_app(|a| {
                a.adopt_source = Some(carried.clone());
                a.show(Screen::Adopt);
                a.build();
            });
            set(h, CURRENT_PASS, pass);
            let texts = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = texts.clone();
            every_input(move |n, text, kind| {
                record.borrow_mut().push(text.to_owned());
                match (n, kind) {
                    (0, InputKind::Preview { check: None }) => {
                        InputAnswer::Switch(keys_ui::FORK_OPT2)
                    }
                    (1, InputKind::Code(_)) => InputAnswer::Code(Zeroizing::new(code_a.clone())),
                    (2, InputKind::Preview { .. }) => InputAnswer::Accept { checked: false },
                    // S-SUSPEND: [계속].
                    (3, InputKind::Preview { check: None }) => {
                        InputAnswer::Accept { checked: false }
                    }
                    _ => panic!("unexpected input {n}: {text}"),
                }
            });
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[2])]);
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            let new_key = format!("5 ({})", keys_ui::NEW_TO_PC);
            {
                let texts = texts.borrow();
                assert_eq!(texts.len(), 4, "{}", status());
                assert!(texts[2].contains(&fill(keys_ui::PREVIEW_SUSPEND, &[&new_key])));
                assert!(texts[3].starts_with(&fill(keys_ui::SUSPEND, &[&new_key])));
                assert!(texts[3].ends_with(keys_ui::SUSPEND_ASK_NEW));
            }
            assert_eq!(fake.seen().len(), seen + 1);
            let renumbered = fill(keys_ui::ADOPT_RENUMBER, &[&5, &6]);
            assert!(status().starts_with(&renumbered), "{}", status());
            with_app(|a| {
                let tone = unsafe { GetWindowLongPtrW(a.handle(STATUS), -21) };
                assert_eq!(tone, TONE_DANGER);
                let o = a.session.as_ref().unwrap().keys_overview().unwrap();
                assert_eq!(numbers(&Some(o.clone())), [1, 2, 3, 4, 5, 6]);
                // A's key, which no touched key reaches, is suspended.
                assert!(o.rows[4].suspended && !o.rows[5].suspended);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// A key file re-seeded at A, taken at B on a Windows that never
        /// returns `pbSecond` (spec §8.3, §9.2 adopt step 2.6, S45-3 #10):
        /// the Reauth touch opens B's own file with its first output, and one
        /// more single-salt touch of the same key with A's seed opens A's
        /// (S-TWOTOUCH); the successor is taken.
        #[test]
        fn an_adopt_touches_twice_when_windows_gives_one_output() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("twotouch-a"), test_dir("twotouch-b"));
            let pass = "synthetic two touch password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let code = a.key_code().unwrap();
            drop(a);
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyTwoTouch", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            let open = |device: usize, anchor: &Path, vault: &Path, key: &Path| {
                vault::set_anchor_dir(Some(anchor.to_path_buf()));
                with_app(|a| {
                    a.vault_path = vault.to_path_buf();
                    a.key_path = key.to_path_buf();
                    if a.screen != Screen::Login {
                        a.show(Screen::Login);
                    }
                    a.build();
                });
                auth.plan(&[Some(device)]);
                set(h, PASS, pass);
                press(h, SUBMIT);
                with_app(|a| assert!(a.session.is_some(), "{}", *a.status));
            };
            // B confirms the first state.
            open(devices[2], &anchor_b, &vb, &kb);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| a.lock("synthetic lock", true));
            // A re-seeds every key.
            open(devices[0], &anchor_a, &va, &ka);
            with_app(|a| a.command(CHANGE, 0)).unwrap();
            set(h, CURRENT_PASS, pass);
            auth.plan(&[
                Some(devices[0]),
                Some(devices[1]),
                Some(devices[2]),
                Some(devices[3]),
                Some(devices[0]),
            ]);
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |text| text == keys_ui::RESEED);
            press(h, keys_ui::KEY_RESEED);
            stop_answers();
            assert!(status().starts_with(keys_ui::RESEEDED), "{}", status());
            let code_a = with_app(|a| a.session.as_ref().unwrap().key_code().unwrap());
            with_app(|a| a.lock("synthetic lock", true));
            let carried = dir_b.join("from-a.goyokey");
            std::fs::copy(&ka, &carried).unwrap();
            // B, on a Windows that never returns the second output.
            open(devices[2], &anchor_b, &vb, &kb);
            fake.device(devices[2], |d| d.fault = Fault::NoSecond);
            with_app(|a| {
                a.command(CHANGE, 0).unwrap();
                a.adopt_source = Some(carried.clone());
                a.show(Screen::Adopt);
                a.build();
            });
            set(h, CURRENT_PASS, pass);
            let typed = code_a.clone();
            every_input(move |n, text, kind| match (n, kind) {
                (0, InputKind::Code(_)) => InputAnswer::Code(Zeroizing::new(typed.clone())),
                (1, InputKind::Preview { .. }) => InputAnswer::Accept { checked: false },
                _ => panic!("unexpected input {n}: {text}"),
            });
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[2]), Some(devices[2])]);
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            let calls = fake.seen();
            assert_eq!(calls.len(), seen + 2, "{}", status());
            // The second: key 3 alone, A's seed only.
            assert_eq!(calls[seen + 1].credentials.len(), 1);
            with_app(|a| {
                assert!(a.screen == Screen::Vault, "{}", *a.status);
                let s = a.session.as_ref().unwrap();
                assert_eq!(s.key_code(), Some(code_a.clone()));
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// Restore of a key file with security keys (spec §9.2 "Unlock /
        /// Restore", §9.2a; S45-1 #13, S45-2 #17): it runs through
        /// phased_command and takes one touch with no borrow held, with the
        /// unlock's allow list.
        #[test]
        fn restore_takes_a_touch() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-restore");
            let pass = "synthetic keyed restore password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let devices: Vec<usize> = (0..2).map(|_| fake.plug(Device::default())).collect();
            let provision = Provision::new().unwrap();
            let id = provision.vault_id();
            let keys: Vec<_> = devices
                .iter()
                .zip(1u8..)
                .map(|(d, n)| {
                    fake.touch(Some(*d));
                    register(&*fake, &id, n, 0, false, Vec::new()).unwrap()
                })
                .collect();
            vault::set_anchor_dir(Some(dir.join("anchor")));
            let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
            let s = provision
                .finish_with_keys(&vault, &key, pass, false, keys)
                .unwrap();
            let backup = dir.join("backup.goyo");
            std::fs::copy(&vault, &backup).unwrap();
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyRestore", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            with_app(|a| {
                a.session = Some(s);
                a.show(Screen::Vault);
                a.build();
                a.lock("synthetic lock", true);
                a.command(RESTORE, 0).unwrap();
                assert!(a.screen == Screen::Restore);
            });
            assert!(phased(SUBMIT) && phased(1));
            let seen = fake.seen().len();
            let restored = dir.join("restored.goyo");
            set(h, VPATH, &backup.to_string_lossy());
            set(h, KPATH, &key.to_string_lossy());
            set(h, DEST, &restored.to_string_lossy());
            set(h, PASS, pass);
            auth.plan(&[Some(devices[1])]);
            press(h, SUBMIT);
            assert_eq!(fake.seen().len(), seen + 1, "{}", status());
            assert_eq!(fake.seen().last().unwrap().credentials.len(), 2);
            assert_eq!(fake.seen().last().unwrap().owner, h);
            with_app(|a| {
                let s = a.session.as_ref().expect("restored with the touch");
                assert!(s.path.ends_with("restored.goyo"), "{}", s.path.display());
                assert!(a.screen == Screen::Vault && a.flow.is_none());
            });
            assert!(restored.is_file());
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// [서버 사본을 이 PC 상태로 덮어쓰기…] of a key file with security
        /// keys (spec §9.2 "Override a halted head", §7.5a): S-OVERRIDE-HEAD,
        /// then one touch of a live, non-suspended key before the Reauth,
        /// and the halt is gone.
        #[test]
        fn a_hold_button_takes_a_touch() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("hold-a"), test_dir("hold-b"));
            let pass = "synthetic keyed override password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (mut a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let mut server = Server::default();
            server.helper(&va);
            a.enable_sync().unwrap();
            upload(&mut server, &mut a);
            let code = a.key_code().unwrap();
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            server.helper(&vb);
            server.pass(&vb);
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyHold", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            vault::set_anchor_dir(Some(anchor_b.clone()));
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| a.lock("synthetic lock", true));
            // A retires key 4 and uploads under its new key.
            vault::set_anchor_dir(Some(anchor_a));
            let t = touched(&fake, devices[1], &a, 2);
            let r = a.reauth(pass, Some(&t)).unwrap();
            let change = vault::Change::Remove {
                remove: vec![4],
                new_password: None,
                loss: None,
                over: None,
            };
            a.rekey(r, vec![], change, vault::Consent::default(), false)
                .unwrap();
            upload(&mut server, &mut a);
            drop(a);
            vault::set_anchor_dir(Some(anchor_b));
            server.pass(&vb);
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().halted_head().is_some());
                a.command(CHANGE, 0).unwrap();
            });
            set(h, CURRENT_PASS, pass);
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| true);
            auth.plan(&[Some(devices[3])]);
            let seen = fake.seen().len();
            press(h, KEY_OVERRIDE_HEAD);
            stop_answers();
            assert_eq!(asked.borrow().len(), 1, "{}", status());
            assert_eq!(fake.seen().len(), seen + 1);
            assert_eq!(fake.seen().last().unwrap().credentials.len(), 4);
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().halted_head().is_none());
                assert!(a.status.starts_with(HEAD_OVERRIDDEN), "{}", *a.status);
                assert!(a.screen == Screen::Vault && a.flow.is_none());
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// A Reauth too old for the next step is taken again in the same
        /// flow (S-REAUTH-AGAIN, spec §9.2a; S45-2 #19, S45-3 #16), keeping
        /// what the flow holds: keys on (its own file has no key) takes it
        /// from the flow's snapshot with no dialog before the write, and an
        /// added key's write asks the same key's touch again. Either way the
        /// write lands; the old Reauth would have been refused at R0.
        #[test]
        fn a_reauth_too_old_is_taken_again_in_the_flow() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-reauth");
            let pass = "synthetic reauth again password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let provision = Provision::new().unwrap();
            let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
            vault::set_anchor_dir(Some(dir.join("anchor")));
            let s = provision.finish(&vault, &key, pass).unwrap();
            let k1 = fake.plug(Device::default());
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyReauth", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            with_app(|a| {
                a.session = Some(s);
                a.show(Screen::Vault);
                a.build();
                a.command(CHANGE, 0).unwrap();
                a.toggles.keyon_pw = false;
            });
            set(h, CURRENT_PASS, pass);
            // S-SPARE stays open past the Reauth's life.
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            let late = clock.clone();
            every_answer(&asked, move |text| {
                if text.starts_with(&fill(keys_ui::SPARE, &[&1])) {
                    late.fetch_add(
                        vault::REAUTH_MAX.as_millis() as u64 + 1000,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    return false;
                }
                text != BACKUP_QUESTION
            });
            let inputs = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = inputs.clone();
            every_input(move |_, text, kind| {
                assert!(
                    !matches!(kind, InputKind::Code(_)),
                    "no code is asked: {text}"
                );
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            auth.plan(&[Some(k1), Some(k1)]);
            press(h, keys_ui::KEY_ON);
            stop_answers();
            // No S-REAUTH-AGAIN dialog: only the change's longer lines after
            // S-BACKUP.
            assert_eq!(inputs.borrow().len(), 1, "{}", status());
            with_app(|a| {
                let o = a.session.as_ref().unwrap().keys_overview();
                assert_eq!(numbers(&o), [1], "{}", *a.status);
                assert!(a.screen == Screen::Keys && a.flow.is_none());
            });

            // A vault with four keys: [키 추가] with key 1, and
            // S-ADD-PAIR stays open too long; the write asks key 1's touch
            // again (S-REAUTH-AGAIN's touch text), its allow list key 1 alone.
            let dir2 = test_dir("ceremony-reauth-keys");
            let (s, devices) = four_keys(&fake, &dir2, pass);
            let (vault2, key2) = (s.path.clone(), s.key_path.clone());
            drop(s);
            with_app(|a| {
                a.lock("synthetic lock", true);
                a.vault_path = vault2.clone();
                a.key_path = key2.clone();
                a.show(Screen::Login);
                a.build();
            });
            auth.plan(&[Some(devices[0])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| {
                assert!(a.session.is_some(), "{}", *a.status);
                a.command(CHANGE, 0).unwrap();
            });
            let k5 = fake.plug(Device::default());
            set(h, CURRENT_PASS, pass);
            let late = clock.clone();
            every_answer(&asked, move |text| {
                if text == keys_ui::ADD_PAIR {
                    late.fetch_add(
                        vault::REAUTH_MAX.as_millis() as u64 + 1000,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }
                false
            });
            inputs.borrow_mut().clear();
            let record = inputs.clone();
            every_input(move |_, text, kind| {
                assert!(matches!(kind, InputKind::Preview { check: None }));
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            auth.plan(&[Some(devices[0]), Some(k5), Some(k5), Some(devices[0])]);
            let seen = fake.seen().len();
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            assert_eq!(
                inputs.borrow()[0],
                fill(keys_ui::REAUTH_AGAIN_TOUCH, &[&1]),
                "{}",
                status()
            );
            let calls = fake.seen();
            assert_eq!(calls.len(), seen + 4, "{}", status());
            assert_eq!(calls[seen + 3].credentials.len(), 1);
            with_app(|a| {
                let o = a.session.as_ref().unwrap().keys_overview();
                assert_eq!(numbers(&o), [1, 2, 3, 4, 5], "{}", *a.status);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::remove_dir_all(&dir2);
        }

        /// [키 추가] never ends without a word (spec §9.2a): Windows' cancel
        /// of the first touch and of the registration each leave their line;
        /// the user's Cancel of S-REAUTH-AGAIN after an optional pairing
        /// touch failed says the flow was cancelled, not the touch's failure;
        /// a lock during S-ADD-PAIR leaves the lock's line. The other key
        /// changes' No (re-seed, keys off) say so too. Nothing is written.
        #[test]
        fn a_key_flow_that_ends_early_says_how() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-add-ends");
            let pass = "synthetic add key ends password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (s, devices) = four_keys(&fake, &dir, pass);
            let (vault, key) = (s.path.clone(), s.key_path.clone());
            drop(s);
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyAddEnds", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            auth.plan(&[Some(devices[0])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| {
                assert!(a.session.is_some(), "{}", *a.status);
                a.command(CHANGE, 0).unwrap();
                assert!(a.screen == Screen::Keys);
            });
            let before = std::fs::read(&key).unwrap();
            let unchanged = || {
                assert_eq!(std::fs::read(&key).unwrap(), before);
                with_app(|a| {
                    let o = a.session.as_ref().unwrap().keys_overview();
                    assert_eq!(numbers(&o), [1, 2, 3, 4]);
                    assert!(a.screen == Screen::Keys && a.flow.is_none());
                });
            };
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));

            // Windows cancels the first touch.
            set(h, CURRENT_PASS, pass);
            auth.plan(&[None]);
            press(h, keys_ui::KEY_ADD);
            assert!(status().starts_with(fido::CANCELLED), "{}", status());
            unchanged();

            // Windows cancels the registration, after the touch.
            set(h, CURRENT_PASS, pass);
            auth.plan(&[Some(devices[0]), None]);
            press(h, keys_ui::KEY_ADD);
            assert!(status().starts_with(fido::CANCELLED), "{}", status());
            assert_eq!(auth.left(), 0);
            unchanged();

            // The new key registers; the first pairing touch meets no key,
            // its line shows; the second S-ADD-PAIR comes after the Reauth's
            // life, and S-REAUTH-AGAIN is cancelled.
            let k5 = fake.plug(Device::default());
            set(h, CURRENT_PASS, pass);
            auth.plan(&[Some(devices[0]), Some(k5), Some(k5), None]);
            let pairs = std::rc::Rc::new(Cell::new(0));
            let late = clock.clone();
            let counted = pairs.clone();
            every_answer(&asked, move |text| {
                if text == keys_ui::ADD_PAIR {
                    counted.set(counted.get() + 1);
                    if counted.get() == 2 {
                        late.fetch_add(
                            vault::REAUTH_MAX.as_millis() as u64 + 1000,
                            std::sync::atomic::Ordering::SeqCst,
                        );
                    }
                    return true;
                }
                false
            });
            let inputs = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = inputs.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Cancel(2)
            });
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            assert_eq!(pairs.get(), 2, "{}", status());
            assert_eq!(
                *inputs.borrow(),
                [fill(keys_ui::REAUTH_AGAIN_TOUCH, &[&1])],
                "{}",
                status()
            );
            assert_eq!(status(), FLOW_CANCELLED);
            unchanged();

            // A lock while S-ADD-PAIR is open: the lock's line stays.
            let k6 = fake.plug(Device::default());
            set(h, CURRENT_PASS, pass);
            auth.plan(&[Some(devices[0]), Some(k6), Some(k6)]);
            every_answer(&asked, |text| {
                if text == keys_ui::ADD_PAIR {
                    with_app(|a| a.lock("synthetic lock", true));
                }
                false
            });
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            assert_eq!(status(), "synthetic lock");
            assert_eq!(std::fs::read(&key).unwrap(), before);
            auth.plan(&[Some(devices[0])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| a.command(CHANGE, 0).unwrap());

            // A No to S-RESEED, and to S-OFF: nothing is touched.
            for (id, question) in [
                (keys_ui::KEY_RESEED, keys_ui::RESEED),
                (keys_ui::KEY_OFF, keys_ui::OFF),
            ] {
                asked.borrow_mut().clear();
                set(h, CURRENT_PASS, pass);
                every_answer(&asked, |_| false);
                let seen = fake.seen().len();
                press(h, id);
                stop_answers();
                assert_eq!(*asked.borrow(), [question]);
                assert_eq!(fake.seen().len(), seen);
                assert_eq!(status(), FLOW_CANCELLED);
                unchanged();
            }
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// Marks, in this PC's anchor (`pbad`), the pair records of `pairs`
        /// (owner, target) broken, as a Reauth that could not open them
        /// would have.
        fn mark_broken(anchor: &Path, pairs: &[(u8, u8)]) {
            let file = anchor.join("goyo-vault.keys");
            let text = std::fs::read_to_string(&file).unwrap();
            let mut out = String::new();
            for l in text.lines() {
                let mut line = l.to_owned();
                if l.starts_with("vault ") {
                    let slots = l
                        .split(' ')
                        .find_map(|f| f.strip_prefix("slots="))
                        .unwrap()
                        .to_owned();
                    let prefix = |n: u8| -> String {
                        slots
                            .split(',')
                            .find_map(|s| {
                                let mut p = s.split(':');
                                (p.next()? == n.to_string())
                                    .then(|| p.next().unwrap()[..32].to_owned())
                            })
                            .unwrap()
                    };
                    let pbad: Vec<String> = pairs
                        .iter()
                        .map(|(o, t)| format!("{}>{}", prefix(*o), prefix(*t)))
                        .collect();
                    line = l
                        .split(' ')
                        .map(|f| {
                            if f.starts_with("pbad=") {
                                format!("pbad={}", pbad.join(","))
                            } else {
                                f.to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                }
                out.push_str(&line);
                out.push('\n');
            }
            std::fs::write(&file, out).unwrap();
        }

        /// The touch plan of a write that removes nothing (spec §9.2a,
        /// §9.2 add key step 1 and password change step 2): with no key
        /// that reaches every other, S-MUSTTOUCH names the keys to touch as
        /// well before any ceremony, and they are touched after the Reauth.
        /// A broken record between two staying keys (S45-3 #6) is proposed
        /// for repair first: declined, the write says so; accepted, the
        /// key that reaches the others is the touch (alone in the allow
        /// list) and its partner the extra touch.
        #[test]
        fn the_plan_asks_for_more_touches_and_proposes_a_repair() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let dir = test_dir("ceremony-plan");
            let pass = "synthetic plan password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (s, devices) = four_keys(&fake, &dir, pass);
            let (vault, key) = (s.path.clone(), s.key_path.clone());
            drop(s);
            let anchor = dir.join("anchor");
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyPlan", &vault, &key, auth.clone(), &clock);
            let guard = Window(h);
            let lock = || {
                with_app(|a| {
                    if a.session.is_some() {
                        a.lock("synthetic lock", true);
                    }
                });
            };
            let login = |device: usize, password: &str| {
                lock();
                auth.plan(&[Some(device)]);
                set(h, PASS, password);
                press(h, SUBMIT);
                with_app(|a| {
                    assert!(a.session.is_some(), "{}", *a.status);
                    a.command(CHANGE, 0).unwrap();
                });
            };
            // Key 1 and key 2 each reach the other only through a record
            // this PC found broken (a Reauth of either key writes its own
            // entries again; the unlock here is key 3's).
            mark_broken(&anchor, &[(1, 2), (2, 1)]);
            login(devices[2], pass);
            // A password change: the repair first; [둘 다 터치] makes key 1
            // the touch (its other records hold), alone in the allow list,
            // and key 2 the extra one.
            with_app(|a| a.command(KEY_PASSWORD, 0)).unwrap();
            let next = "synthetic plan password two";
            set(h, CURRENT_PASS, pass);
            set(h, PASS, next);
            set(h, CONFIRM, next);
            let texts = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = texts.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Accept { checked: false }
            });
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |text| text == ROTATE_QUESTION);
            auth.plan(&[Some(devices[0]), Some(devices[1])]);
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(
                texts.borrow()[0],
                fill(keys_ui::REPAIR_PROPOSE, &[&1, &2, &1])
            );
            let calls = fake.seen();
            assert_eq!(calls.len(), seen + 2, "{}", status());
            assert_eq!(calls[seen].credentials.len(), 1);
            assert_eq!(calls[seen + 1].credentials.len(), 1);
            assert!(status().starts_with(PASSWORD_CHANGED), "{}", status());
            // [건너뛰기]: the plan as before (neither key 1 nor key 2 can be
            // the touch); the write's text says the record stays as it was.
            lock();
            mark_broken(&anchor, &[(1, 2), (2, 1)]);
            login(devices[2], next);
            with_app(|a| a.command(KEY_PASSWORD, 0)).unwrap();
            set(h, CURRENT_PASS, next);
            set(h, PASS, pass);
            set(h, CONFIRM, pass);
            texts.borrow_mut().clear();
            let record = texts.clone();
            every_input(move |n, text, _| {
                record.borrow_mut().push(text.to_owned());
                match n {
                    0 => InputAnswer::Cancel(2),
                    _ => InputAnswer::Accept { checked: false },
                }
            });
            every_answer(&asked, |text| text == ROTATE_QUESTION);
            auth.plan(&[Some(devices[3])]);
            let seen = fake.seen().len();
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "{}", status());
            assert_eq!(fake.seen()[seen].credentials.len(), 2);
            {
                let texts = texts.borrow();
                assert_eq!(texts.len(), 2, "{texts:?}");
                assert!(texts[1].contains(&fill(keys_ui::REPAIR_SKIPPED, &[&1, &2])));
            }
            // Key 5 added with key 1 alone is paired with key 1 only.
            let k5 = fake.plug(Device::default());
            login(devices[2], pass);
            set(h, CURRENT_PASS, pass);
            every_answer(&asked, |_| false);
            every_input(|_, _, _| InputAnswer::Accept { checked: false });
            auth.plan(&[Some(devices[0]), Some(k5), Some(k5)]);
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            with_app(|a| {
                let o = a.session.as_ref().unwrap().keys_overview();
                assert_eq!(numbers(&o), [1, 2, 3, 4, 5], "{}", *a.status);
            });
            // Key 1's record for key 5 found broken: no key reaches every
            // other. [키 추가] with key 2: the repair of 1 and 5 declined,
            // S-MUSTTOUCH names key 5, which is touched after the Reauth.
            lock();
            mark_broken(&anchor, &[(1, 5)]);
            login(devices[1], pass);
            let k6 = fake.plug(Device::default());
            set(h, CURRENT_PASS, pass);
            texts.borrow_mut().clear();
            let record = texts.clone();
            every_input(move |n, text, _| {
                record.borrow_mut().push(text.to_owned());
                match n {
                    0 => InputAnswer::Cancel(2),
                    _ => InputAnswer::Accept { checked: false },
                }
            });
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[1]), Some(k5), Some(k6), Some(k6)]);
            let seen = fake.seen().len();
            press(h, keys_ui::KEY_ADD);
            stop_answers();
            {
                let texts = texts.borrow();
                assert!(texts.len() >= 2, "{texts:?} {}", status());
                assert_eq!(texts[0], fill(keys_ui::REPAIR_PROPOSE, &[&1, &5, &1]));
                assert_eq!(texts[1], fill(keys_ui::MUSTTOUCH, &[&"5"]));
            }
            let calls = fake.seen();
            assert_eq!(calls.len(), seen + 4, "{}", status());
            assert_eq!(calls[seen].credentials.len(), 4);
            assert_eq!(calls[seen + 1].credentials.len(), 1);
            with_app(|a| {
                let o = a.session.as_ref().unwrap().keys_overview().unwrap();
                assert_eq!(
                    numbers(&Some(o.clone())),
                    [1, 2, 3, 4, 5, 6],
                    "{}",
                    *a.status
                );
                // The new key is paired with both keys touched.
                assert_eq!(o.rows[5].unpaired, [1, 3, 4]);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// The fork's hint and the preview's [뒤로] (spec §5.8 "Order and
        /// display", §9.2 adopt step 8; round 1, finding 19): A retires key
        /// 3, B changes the password with key 3's touch. At B, S-FORK has no
        /// hint; the gate is answered with A's code; the preview of [둘 다
        /// 합치기] names key 3 (S-FORK-HINT, from B's own history); [뒤로]
        /// goes back to S-FORK, and [다른 PC 쪽 사용] reuses the code (G1
        /// covers both) and shows no hint.
        #[test]
        fn the_fork_hint_shows_in_the_preview_and_back_returns_to_the_options() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("hint-a"), test_dir("hint-b"));
            let pass = "synthetic fork hint password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (mut a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let code_e1 = a.key_code().unwrap();
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            // A retires key 3 with key 2's touch.
            let t = touched(&fake, devices[1], &a, 2);
            let r = a.reauth(pass, Some(&t)).unwrap();
            let change = vault::Change::Remove {
                remove: vec![3],
                new_password: None,
                loss: None,
                over: None,
            };
            a.rekey(r, vec![], change, vault::Consent::default(), false)
                .unwrap();
            let code_a = a.key_code().unwrap();
            drop(a);
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyHint", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            auth.plan(&[Some(devices[2])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            set(h, keys_ui::GATE_CODE, &code_e1);
            press(h, keys_ui::TOFU_OK);
            // B changes the password with key 3's touch: a new data key.
            let next = "synthetic fork hint password two";
            with_app(|a| {
                let s = a.session.as_mut().unwrap();
                let t = touched(&fake, devices[2], s, 3);
                let r = s.reauth(pass, Some(&t)).unwrap();
                let change = vault::Change::Password(Zeroizing::new(next.to_owned()));
                s.rekey(r, vec![], change, vault::Consent::default(), false)
                    .unwrap();
                a.command(CHANGE, 0).unwrap();
                a.adopt_source = Some(ka.clone());
                a.show(Screen::Adopt);
                a.build();
            });
            set(h, CURRENT_PASS, next);
            let texts = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = texts.clone();
            let typed = code_a.clone();
            every_input(move |n, text, kind| {
                record.borrow_mut().push(text.to_owned());
                match (n, kind) {
                    (0, InputKind::Preview { check: None }) => {
                        InputAnswer::Switch(keys_ui::FORK_OPT2)
                    }
                    (1, InputKind::Pick(_)) => InputAnswer::Switch(keys_ui::GATE_TO_CODE),
                    (2, InputKind::Code(_)) => InputAnswer::Code(Zeroizing::new(typed.clone())),
                    (3, InputKind::Password) => InputAnswer::Password(Zeroizing::new(pass.into())),
                    (4, InputKind::Preview { .. }) => InputAnswer::Switch(keys_ui::PREVIEW_BACK),
                    (5, InputKind::Preview { check: None }) => {
                        InputAnswer::Switch(keys_ui::FORK_OPT1)
                    }
                    (6, InputKind::Preview { .. }) => InputAnswer::Accept { checked: false },
                    _ => InputAnswer::Cancel(2),
                }
            });
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            auth.plan(&[Some(devices[1])]);
            press(h, SUBMIT);
            stop_answers();
            let hint = fill(keys_ui::FORK_HINT, &[&3]);
            {
                let texts = texts.borrow();
                assert_eq!(texts.len(), 7, "{texts:?} {}", status());
                assert_eq!(texts[0], keys_ui::FORK);
                assert!(!texts[0].contains(&hint) && !texts[1].contains(&hint));
                assert!(texts[4].contains(&hint), "{}", texts[4]);
                assert_eq!(texts[5], keys_ui::FORK);
                assert!(!texts[6].contains(&hint));
            }
            with_app(|a| {
                assert!(a.screen == Screen::Vault, "{}", *a.status);
                let s = a.session.as_ref().unwrap();
                assert_eq!(numbers(&s.keys_overview()), [1, 2, 4]);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }

        /// The per-vault forget in gate-pending mode (spec §5.10, round 4
        /// finding 13): after [나중에] at the login gate, the Keys screen
        /// offers it with the password; S-ANCHOR-FORGET, a touch and the
        /// Reauth make the session a bootstrap (the TOFU banner), with no
        /// line of the anchor written; the TOFU pass with the other PC's
        /// code then confirms the key file.
        #[test]
        fn the_forget_in_gate_pending_mode_starts_a_bootstrap() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("held-forget-a"), test_dir("held-forget-b"));
            let pass = "synthetic held forget password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let (mut a, devices) = four_keys(&fake, &dir_a, pass);
            let (va, ka) = (a.path.clone(), a.key_path.clone());
            let code_e1 = a.key_code().unwrap();
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyHeldForget", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let anchor_b = dir_b.join("anchor");
            vault::set_anchor_dir(Some(anchor_b.clone()));
            auth.plan(&[Some(devices[0])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            set(h, keys_ui::GATE_CODE, &code_e1);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| a.lock("synthetic lock", true));
            // A retires key 4; B takes the copy at login and answers
            // [나중에]: gate-pending mode.
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(pass, Some(&t)).unwrap();
            let change = vault::Change::Remove {
                remove: vec![4],
                new_password: None,
                loss: None,
                over: None,
            };
            a.rekey(r, vec![], change, vault::Consent::default(), false)
                .unwrap();
            let code_a = a.key_code().unwrap();
            drop(a);
            vault::set_anchor_dir(Some(anchor_b.clone()));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            every_input(|_, _, _| InputAnswer::Cancel(keys_ui::GATE_LATER));
            auth.plan(&[Some(devices[0])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            stop_answers();
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().gate_pending(), "{}", *a.status);
                a.command(CHANGE, 0).unwrap();
            });
            assert_eq!(
                controls_of(&[keys_ui::KEY_ACCEPT, keys_ui::ANCHOR_FORGET, CURRENT_PASS]),
                [true, true, true]
            );
            let before = std::fs::read(anchor_b.join("goyo-vault.keys")).unwrap();
            // A No changes nothing and asks for no touch.
            set(h, CURRENT_PASS, pass);
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            let seen = fake.seen().len();
            press(h, keys_ui::ANCHOR_FORGET);
            stop_answers();
            assert_eq!(fake.seen().len(), seen);
            assert!(asked.borrow()[0].starts_with(&fill(keys_ui::FORGET, &[&1])));
            with_app(|a| assert!(a.session.as_ref().unwrap().gate_pending()));
            // Yes: the touch and the Reauth; then the TOFU banner.
            set(h, CURRENT_PASS, pass);
            every_answer(&asked, |_| true);
            auth.plan(&[Some(devices[1])]);
            press(h, keys_ui::ANCHOR_FORGET);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1);
            assert_eq!(fake.seen().last().unwrap().credentials.len(), 3);
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(!s.gate_pending() && s.tofu(), "{}", *a.status);
                assert!(a.screen == Screen::Vault && a.tofu_banner());
                assert_eq!(*a.status, keys_ui::FORGOTTEN_HELD);
            });
            assert_eq!(
                std::fs::read(anchor_b.join("goyo-vault.keys")).unwrap(),
                before
            );
            set(h, keys_ui::GATE_CODE, &code_a);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(!s.tofu() && !s.gate_pending(), "{}", *a.status);
                assert_eq!(*a.status, keys_ui::TOFU_PASSED);
            });
            assert_ne!(
                std::fs::read(anchor_b.join("goyo-vault.keys")).unwrap(),
                before
            );
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        /// `vault`'s key view as goyo-sync's KG writes it (spec §7.10):
        /// line 0 and the server's top record `seq`, a key record of
        /// `key` (none when empty).
        fn key_view(vault: &Path, seq: u64, key: &[u8]) {
            let dir = syncfile::sync_dir(vault).unwrap();
            let mut view = syncfile::KeyView {
                seq,
                ..Default::default()
            };
            if !key.is_empty() {
                let h = vault::keyfile::parse(key).unwrap();
                view.record =
                    syncfile::render_record_header(syncfile::RecordKind::Key, false, 0, h.epoch)
                        .to_vec();
                view.record.extend_from_slice(key);
            }
            syncfile::replace_file(
                &dir.join(syncfile::KEY_VIEW),
                &syncfile::render_key_view(&view),
            )
            .unwrap();
        }
        /// A password change of A's session `s`, touched with `device`.
        fn change_password(fake: &Fake, device: usize, s: &mut Session, old: &str, new: &str) {
            let t = touched(fake, device, s, 1);
            let r = s.reauth(old, Some(&t)).unwrap();
            let change = vault::Change::Password(Zeroizing::new(new.to_owned()));
            assert_eq!(
                s.rekey(r, Vec::new(), change, vault::Consent::default(), true),
                Ok(vault::Rekeyed::Done)
            );
        }

        /// The server's key file at login (spec §5.2 step 9(b) and its
        /// second entry point, §7.15 at login; §14.10 walkthrough 2): A and
        /// B use key-file sync. A changes the password; B's login with the
        /// old one takes A's file in the same flow (S-NEWPASS-OTHER, the
        /// preview, S-BACKUP) with the unlock's one touch. A changes it
        /// again; B's login with the newest password fails on B's own key
        /// file, S-TRY-SERVER-KEY's yes takes A's file with the same touch,
        /// and the session opens.
        #[test]
        fn the_server_key_file_is_taken_at_login() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("login-take-a"), test_dir("login-take-b"));
            let (pass, newer, newest) = (
                "synthetic login take password",
                "synthetic login take newer",
                "synthetic login take newest",
            );
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let devices: Vec<usize> = (0..2).map(|_| fake.plug(Device::with_pin())).collect();
            let provision = Provision::new().unwrap();
            let id = provision.vault_id();
            let keys: Vec<_> = devices
                .iter()
                .zip(1u8..)
                .map(|(d, n)| {
                    fake.touch(Some(*d));
                    register(&*fake, &id, n, 0, true, Vec::new()).unwrap()
                })
                .collect();
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            vault::set_anchor_dir(Some(anchor_a.clone()));
            let (va, ka) = (dir_a.join("vault.goyo"), dir_a.join("vault.goyokey"));
            let mut a = provision
                .finish_with_keys(&va, &ka, pass, true, keys)
                .unwrap();
            let server = Server::default();
            server.helper(&va);
            a.enable_sync().unwrap();
            key_view(&va, 0, &[]);
            a.poll_sync();
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(pass, Some(&t)).unwrap();
            assert_eq!(
                a.rekey(
                    r,
                    Vec::new(),
                    vault::Change::KeySyncOn,
                    vault::Consent::default(),
                    true
                ),
                Ok(vault::Rekeyed::Done)
            );
            let code = a.key_code().unwrap();
            // PC B: A's files, its own helper's view of A's "on".
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            server.helper(&vb);
            key_view(&vb, 1, &std::fs::read(&ka).unwrap());
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyLoginTake", &vb, &kb, auth.clone(), &clock);
            let guard = Window(h);
            let login = |device: usize, password: &str| {
                vault::set_anchor_dir(Some(anchor_b.clone()));
                with_app(|a| {
                    if a.screen != Screen::Login {
                        a.show(Screen::Login);
                    }
                    a.build();
                });
                auth.plan(&[Some(device)]);
                set(h, PASS, password);
                press(h, SUBMIT);
            };
            login(devices[1], pass);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                assert_eq!(*a.status, keys_ui::TOFU_PASSED);
                a.lock("synthetic lock", true);
            });

            // A's password change reaches B's view; B logs in with the old
            // password and takes it in the same flow.
            vault::set_anchor_dir(Some(anchor_a.clone()));
            change_password(&fake, devices[0], &mut a, pass, newer);
            key_view(&vb, 2, &std::fs::read(&ka).unwrap());
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            let shown = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = shown.clone();
            let typed = newer.to_owned();
            every_input(move |n, text, kind| {
                record.borrow_mut().push(text.to_owned());
                match (n, kind) {
                    (0, InputKind::Password) => {
                        InputAnswer::Password(Zeroizing::new(typed.clone()))
                    }
                    (1, InputKind::Preview { .. }) => InputAnswer::Accept { checked: false },
                    _ => panic!("unexpected input {n}: {text}"),
                }
            });
            let seen = fake.seen().len();
            login(devices[1], pass);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "one touch: {}", status());
            assert_eq!(*asked.borrow(), [BACKUP_QUESTION], "{}", status());
            asked.borrow_mut().clear();
            assert_eq!(shown.borrow()[0], NEWPASS_OTHER);
            assert!(
                status().contains(keys_ui::ACCEPTED_AT_LOGIN.split('{').next().unwrap()),
                "{}",
                status()
            );
            assert_eq!(std::fs::read(&kb).unwrap(), {
                let bytes = std::fs::read(&ka).unwrap();
                // The successor re-seal keeps [0, W): the same state.
                assert_eq!(
                    vault::keyfile::parse(&bytes).unwrap().state(),
                    vault::keyfile::parse(&std::fs::read(&kb).unwrap())
                        .unwrap()
                        .state()
                );
                std::fs::read(&kb).unwrap()
            });
            with_app(|a| a.lock("synthetic lock", true));

            // The newest password at B: S-TRY-SERVER-KEY with the same touch.
            vault::set_anchor_dir(Some(anchor_a.clone()));
            change_password(&fake, devices[0], &mut a, newer, newest);
            key_view(&vb, 3, &std::fs::read(&ka).unwrap());
            every_answer(&asked, |text| text == keys_ui::TRY_SERVER_KEY);
            let seen = fake.seen().len();
            login(devices[1], newest);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "one touch: {}", status());
            assert_eq!(
                *asked.borrow(),
                [keys_ui::TRY_SERVER_KEY, BACKUP_QUESTION],
                "{}",
                status()
            );
            with_app(|a| {
                let s = a.session.as_ref().expect("opened from the server's file");
                assert_eq!(
                    s.key_state(),
                    vault::keyfile::parse(&std::fs::read(&ka).unwrap())
                        .unwrap()
                        .state()
                );
                assert!(a.screen == Screen::Vault && a.failed == 0);
                assert!(
                    a.status
                        .contains(keys_ui::ACCEPTED_AT_LOGIN.split('{').next().unwrap()),
                    "{}",
                    *a.status
                );
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        /// A and B on key-file sync, A's vault made with `n` keys and its
        /// "on" landed; B confirmed A's file in the TOFU banner of the window
        /// `h` and locked. Returns what the tests below drive.
        #[allow(clippy::type_complexity)]
        fn two_on_window(
            name: &str,
            n: u8,
            keysync: bool,
        ) -> (
            PathBuf,
            PathBuf,
            Arc<Fake>,
            Vec<usize>,
            Session,
            (PathBuf, PathBuf),
            (PathBuf, PathBuf),
            Arc<Scripted>,
            Window,
            Arc<AtomicU64>,
        ) {
            let (dir_a, dir_b) = (
                test_dir(&format!("{name}-a")),
                test_dir(&format!("{name}-b")),
            );
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let devices: Vec<usize> = (0..n).map(|_| fake.plug(Device::with_pin())).collect();
            let provision = Provision::new().unwrap();
            let id = provision.vault_id();
            let keys: Vec<_> = devices
                .iter()
                .zip(1u8..)
                .map(|(d, n)| {
                    fake.touch(Some(*d));
                    register(&*fake, &id, n, 0, true, Vec::new()).unwrap()
                })
                .collect();
            let anchor_a = dir_a.join("anchor");
            vault::set_anchor_dir(Some(anchor_a.clone()));
            let (va, ka) = (dir_a.join("vault.goyo"), dir_a.join("vault.goyokey"));
            let mut a = provision
                .finish_with_keys(&va, &ka, PASS2, true, keys)
                .unwrap();
            let server = Server::default();
            server.helper(&va);
            a.enable_sync().unwrap();
            key_view(&va, 0, &[]);
            a.poll_sync();
            if keysync {
                let t = touched(&fake, devices[0], &a, 1);
                let r = a.reauth(PASS2, Some(&t)).unwrap();
                assert_eq!(
                    a.rekey(
                        r,
                        Vec::new(),
                        vault::Change::KeySyncOn,
                        vault::Consent::default(),
                        true
                    ),
                    Ok(vault::Rekeyed::Done)
                );
            }
            let code = a.key_code().unwrap();
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            server.helper(&vb);
            let top = if keysync {
                std::fs::read(&ka).unwrap()
            } else {
                Vec::new()
            };
            key_view(&vb, u64::from(keysync), &top);
            let auth = Scripted::new(fake.clone());
            let h = window(
                &format!("GoyoCeremony-{name}"),
                &vb,
                &kb,
                auth.clone(),
                &clock,
            );
            let guard = Window(h);
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            auth.plan(&[Some(devices[1])]);
            set(h, PASS, PASS2);
            press(h, SUBMIT);
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                assert_eq!(*a.status, keys_ui::TOFU_PASSED);
                a.lock("synthetic lock", true);
            });
            (
                dir_a,
                dir_b,
                fake,
                devices,
                a,
                (va, ka),
                (vb, kb),
                auth,
                guard,
                clock,
            )
        }
        const PASS2: &str = "synthetic part two password";
        /// A login of the window `h` on B's files with `device`.
        fn login_b(h: Hwnd, dir_b: &Path, auth: &Scripted, device: usize) {
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            with_app(|a| {
                if a.screen != Screen::Login {
                    a.show(Screen::Login);
                }
                a.build();
            });
            auth.plan(&[Some(device)]);
            set(h, PASS, PASS2);
            press(h, SUBMIT);
        }
        /// The kind-9 merge at login (spec §5.8, §14.10 walkthrough 18): A
        /// and B remove the same lost key apart, A's lands first; B's next
        /// login merges with the unlock's one touch and password, asking
        /// nothing before the open and showing no preview; the status is
        /// S-MERGED with the new code.
        #[test]
        fn two_removals_merge_at_the_next_login() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b, fake, devices, mut a, (_va, ka), (vb, kb), auth, guard, _clock) =
                two_on_window("merge-login", 3, true);
            let h = guard.0;
            let lost = || vault::Change::Remove {
                remove: vec![3],
                new_password: None,
                loss: Some(vault::LossReport {
                    date: None,
                    exposure: vault::Exposure::No,
                    shared_pin: Vec::new(),
                }),
                over: None,
            };
            // A removes key 3 and lands first.
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(PASS2, Some(&t)).unwrap();
            assert_eq!(
                a.rekey(r, Vec::new(), lost(), vault::Consent::default(), false),
                Ok(vault::Rekeyed::Done)
            );
            // B removes it too, from the same state (its own unlock).
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            let prepared = vault::prepare(&vb, &kb).unwrap();
            let req = prepared.unlock_request(0).unwrap();
            fake.touch(Some(devices[1]));
            let raw = fake
                .get_assertion(&req, &fake.new_cancel().unwrap())
                .unwrap();
            let t = check_assertion(raw, &req, false).unwrap();
            let (mut b, _) = Session::login_proved(prepared, PASS2, None, &t)
                .ok()
                .unwrap();
            let t = touched(&fake, devices[1], &b, 2);
            let r = b.reauth(PASS2, Some(&t)).unwrap();
            assert_eq!(
                b.rekey(r, Vec::new(), lost(), vault::Consent::default(), false),
                Ok(vault::Rekeyed::Done)
            );
            drop(b);
            // B's helper: its PUT met A's record.
            key_view(&vb, 2, &std::fs::read(&ka).unwrap());
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            every_input(|n, text, _| panic!("asked {n}: {text}"));
            let seen = fake.seen().len();
            login_b(h, &dir_b, &auth, devices[1]);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "one touch: {}", status());
            assert_eq!(*asked.borrow(), [BACKUP_QUESTION], "{}", status());
            let merged = vault::keyfile::parse(&std::fs::read(&kb).unwrap()).unwrap();
            assert_eq!(merged.kind, vault::keyfile::Kind::Union);
            let code = fill(keys_ui::MERGED, &[&""]);
            assert!(status().starts_with(code.trim_end()), "{}", status());
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        /// The supersede on the Keys screen (spec §7.15a, §9.2; §14.10
        /// walkthrough 1, "PC gone"): A turns key-file sync on and is gone
        /// before B typed its code. At B's login the gate is put off; on
        /// the Keys screen [다른 PC가 없어 이 PC 상태로 올리기…] asks
        /// S-KEYSYNC-ON, then S-GATE-SUPERSEDE with S-GATE-SUPERSEDE-ON,
        /// takes one touch and writes B's own key file again, GOYOKS01,
        /// above A's.
        #[test]
        fn a_gated_change_whose_pc_is_gone_is_superseded_from_the_keys_screen() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b, fake, devices, mut a, (va, ka), (vb, kb), auth, guard, _clock) =
                two_on_window("supersede", 2, false);
            let h = guard.0;
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            key_view(&va, 0, &[]);
            a.poll_sync();
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(PASS2, Some(&t)).unwrap();
            assert_eq!(
                a.rekey(
                    r,
                    Vec::new(),
                    vault::Change::KeySyncOn,
                    vault::Consent::default(),
                    true
                ),
                Ok(vault::Rekeyed::Done)
            );
            let on = vault::keyfile::parse(&std::fs::read(&ka).unwrap()).unwrap();
            drop(a);
            key_view(&vb, 1, &std::fs::read(&ka).unwrap());
            // The login's gate is put off.
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |text| text != BACKUP_QUESTION);
            every_input(|_, _, _| InputAnswer::Cancel(0));
            login_b(h, &dir_b, &auth, devices[1]);
            with_app(|a| {
                a.show(Screen::Keys);
                a.build();
                assert_ne!(a.handle(keys_ui::GATE_SUPERSEDE), 0, "offered");
            });
            set(h, CURRENT_PASS, PASS2);
            auth.plan(&[Some(devices[1])]);
            let seen = fake.seen().len();
            press(h, keys_ui::GATE_SUPERSEDE);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "one touch: {}", status());
            let shown = asked.borrow().clone();
            assert_eq!(shown.len(), 3, "{shown:?}");
            assert_eq!(shown[0], keys_ui::KEYSYNC_ON_TEXT);
            assert!(
                shown[1].starts_with(keys_ui::SUPERSEDE_ASK)
                    && shown[1].ends_with(keys_ui::SUPERSEDE_ON)
            );
            assert_eq!(shown[2], BACKUP_QUESTION);
            assert!(status().starts_with(keys_ui::SUPERSEDED), "{}", status());
            let up = vault::keyfile::parse(&std::fs::read(&kb).unwrap()).unwrap();
            assert_eq!(up.magic, vault::keyfile::Magic::Ks01);
            assert_eq!(up.epoch, on.epoch + 1);
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        /// A PC without security keys and the server's keys-on file: A and
        /// B sync a vault made without keys; A turns keys on, then key-file
        /// sync, and uploads. B's unlock halts with KeyChangedServerPwOnly,
        /// which names [서버의 새 열쇠 파일 받기…]; B's Keys screen offers it
        /// (S-PWONLY-SERVER) with the password field, the USB adopt and the
        /// head override still there, and no [받기…]. In S-GATE-CODE,
        /// [코드 없이 이 서버를 믿고 받기…] asks S-NOCODE-SERVER, whose No
        /// asks the code again; [나중에] writes nothing. Then the take: A's
        /// code, or the trust without it; S-OTHERKEY-ONLY and one touch of
        /// A's key; the preview; S-KEYSYNC-ON; S-BACKUP. B holds A's file
        /// (GOYOKS01), its status says how it was taken, the offer is gone
        /// and the halt lifts.
        #[test]
        fn a_pc_without_keys_takes_keys_on_from_the_server() {
            for nocode in [false, true] {
                pwonly_take(nocode);
            }
        }
        fn pwonly_take(nocode: bool) {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b) = (test_dir("pwonly-take-a"), test_dir("pwonly-take-b"));
            let pass = "synthetic pwonly take password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let devices: Vec<usize> = (0..2).map(|_| fake.plug(Device::with_pin())).collect();
            let provision = Provision::new().unwrap();
            let id = provision.vault_id();
            let (anchor_a, anchor_b) = (dir_a.join("anchor"), dir_b.join("anchor"));
            vault::set_anchor_dir(Some(anchor_a.clone()));
            let (va, ka) = (dir_a.join("vault.goyo"), dir_a.join("vault.goyokey"));
            let mut a = provision.finish(&va, &ka, pass).unwrap();
            a.put(None, sync_entry("one", "secret")).unwrap();
            let mut server = Server::default();
            server.helper(&va);
            a.enable_sync().unwrap();
            upload(&mut server, &mut a);
            // B: copies of A's pair, its own helper with version 1.
            let (vb, kb) = (dir_b.join("vault.goyo"), dir_b.join("vault.goyokey"));
            std::fs::copy(&va, &vb).unwrap();
            std::fs::copy(&ka, &kb).unwrap();
            server.helper(&vb);
            server.pass(&vb);
            // B opens it once, syncing, before A's change: its record.
            vault::set_anchor_dir(Some(anchor_b.clone()));
            let prepared = vault::prepare(&vb, &kb).unwrap();
            let mut b = Session::login(prepared, pass, None).unwrap();
            b.poll_sync();
            drop(b);
            vault::set_anchor_dir(Some(anchor_a.clone()));
            // A: keys on with two keys, then key-file sync on.
            let keys: Vec<_> = devices
                .iter()
                .zip(1u8..)
                .map(|(d, n)| {
                    fake.touch(Some(*d));
                    register(&*fake, &id, n, 0, true, Vec::new()).unwrap()
                })
                .collect();
            let r = a.reauth(pass, None).unwrap();
            let on = vault::Change::KeysOn {
                pin: true,
                keys,
                new_password: None,
            };
            assert_eq!(
                a.rekey(r, Vec::new(), on, vault::Consent::default(), true),
                Ok(vault::Rekeyed::Done)
            );
            key_view(&va, 0, &[]);
            a.poll_sync();
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(pass, Some(&t)).unwrap();
            assert_eq!(
                a.rekey(
                    r,
                    Vec::new(),
                    vault::Change::KeySyncOn,
                    vault::Consent::default(),
                    true
                ),
                Ok(vault::Rekeyed::Done)
            );
            let a_key = std::fs::read(&ka).unwrap();
            let state_a = vault::keyfile::parse(&a_key).unwrap().state();
            let code_a = a.key_code().unwrap();
            // The server took A's key file; A's next copy goes up.
            key_view(&va, 1, &a_key);
            a.poll_sync();
            a.put(None, sync_entry("from a", "secret")).unwrap();
            upload(&mut server, &mut a);
            assert_eq!(server.versions.len(), 2, "A's copy under its new key");
            drop(a);
            // B's helper brought that copy and the key view.
            server.pass(&vb);
            key_view(&vb, 1, &a_key);
            let before = std::fs::read(&kb).unwrap();
            let auth = Scripted::new(fake.clone());
            let h = window(
                &format!("GoyoCeremonyPwOnlyTake{nocode}"),
                &vb,
                &kb,
                auth.clone(),
                &clock,
            );
            let guard = Window(h);
            vault::set_anchor_dir(Some(anchor_b.clone()));
            set(h, PASS, pass);
            press(h, SUBMIT);
            // The unlock's notice names the Keys screen's button. B's key
            // file is a 0.8 one, which no code confirms: S-TOFU-LEGACY,
            // pointing to the same button, and its trust without a code.
            let notice = keys_ui::N_KEY_CHANGED_SERVER_PWONLY;
            assert!(status().contains(notice), "{}", status());
            with_app(|a| {
                assert!(a.tofu_banner());
                let shown: Vec<String> = a.children.iter().map(|c| caption(*c)).collect();
                assert!(shown.contains(&keys_ui::TOFU_LEGACY.to_owned()));
                assert!(keys_ui::TOFU_LEGACY.contains(keys_ui::SERVER_TAKE_BUTTON));
            });
            let trusted = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&trusted, |text| text == keys_ui::TOFU_NOPC_TEXT);
            press(h, keys_ui::TOFU_NOPC);
            stop_answers();
            assert_eq!(*trusted.borrow(), [keys_ui::TOFU_NOPC_TEXT]);
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(s.halted_head().is_some() && !s.tofu(), "{}", *a.status);
                assert_eq!(s.pwonly_server_file(), Some(state_a.epoch));
                a.command(CHANGE, 0).unwrap();
                assert!(a.screen == Screen::Keys);
                let shown: Vec<String> = a.children.iter().map(|c| caption(*c)).collect();
                let hold = fill(keys_ui::SERVER_TAKE_HOLD, &[&state_a.epoch]);
                assert!(shown.contains(&hold), "{shown:?}");
            });
            assert_eq!(
                controls_of(&[
                    keys_ui::KEY_SERVER_TAKE,
                    CURRENT_PASS,
                    KEY_ADOPT,
                    KEY_OVERRIDE_HEAD,
                    keys_ui::KEY_ACCEPT,
                    keys_ui::KEY_ON,
                ]),
                [true, true, true, true, false, false]
            );
            set(h, CURRENT_PASS, pass);
            // S-NOCODE-SERVER's No asks the code again; [나중에] ends it.
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            let buttons = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = buttons.clone();
            every_input(move |n, text, kind| {
                assert!(matches!(kind, InputKind::Code(_)), "{text}");
                record.borrow_mut().push(text.to_owned());
                match n {
                    0 => InputAnswer::Switch(keys_ui::GATE_NOCODE),
                    _ => InputAnswer::Cancel(keys_ui::GATE_LATER),
                }
            });
            let seen = fake.seen().len();
            press(h, keys_ui::KEY_SERVER_TAKE);
            stop_answers();
            assert_eq!(*asked.borrow(), [keys_ui::NOCODE_SERVER_ASK]);
            assert_eq!(buttons.borrow().len(), 2);
            let gate = fill(keys_ui::GATE_CODE_TEXT, &[&state_a.epoch]);
            assert!(buttons.borrow().iter().all(|t| *t == gate));
            assert_eq!(fake.seen().len(), seen, "no touch");
            assert_eq!(std::fs::read(&kb).unwrap(), before);
            asked.borrow_mut().clear();
            // The take: the code or the trust without it, then one touch of
            // A's key, the preview, S-KEYSYNC-ON and S-BACKUP.
            every_answer(&asked, |text| {
                text == keys_ui::NOCODE_SERVER_ASK || text == keys_ui::KEYSYNC_ON_TEXT
            });
            let shown = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = shown.clone();
            let code = code_a.clone();
            every_input(move |_, text, kind| {
                record.borrow_mut().push(text.to_owned());
                match kind {
                    InputKind::Code(_) if nocode => InputAnswer::Switch(keys_ui::GATE_NOCODE),
                    InputKind::Code(_) => InputAnswer::Code(Zeroizing::new(code.clone())),
                    InputKind::Preview { .. } => InputAnswer::Accept { checked: false },
                    _ => panic!("unexpected input: {text}"),
                }
            });
            auth.plan(&[Some(devices[1])]);
            set(h, CURRENT_PASS, pass);
            press(h, keys_ui::KEY_SERVER_TAKE);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "one touch: {}", status());
            let mut questions = vec![keys_ui::KEYSYNC_ON_TEXT, BACKUP_QUESTION];
            if nocode {
                questions.insert(0, keys_ui::NOCODE_SERVER_ASK);
            }
            assert_eq!(*asked.borrow(), questions, "{}", status());
            {
                let shown = shown.borrow();
                assert_eq!(shown.len(), 3, "{shown:?}");
                assert_eq!(shown[0], fill(keys_ui::GATE_CODE_TEXT, &[&state_a.epoch]));
                assert!(shown[1].starts_with(keys_ui::OTHERKEY_ONLY.split('{').next().unwrap()));
            }
            let taken = vault::keyfile::parse(&std::fs::read(&kb).unwrap()).unwrap();
            assert_eq!(taken.state(), state_a);
            assert_eq!(taken.magic, vault::keyfile::Magic::Ks01);
            assert_eq!(
                status().starts_with(keys_ui::ADOPT_NOCODE),
                nocode,
                "{}",
                status()
            );
            with_app(|a| {
                let s = a.session.as_mut().unwrap();
                assert_eq!(s.pwonly_server_file(), None);
                assert!(s.keys_overview().is_some());
                s.poll_sync();
                assert!(s.halted_head().is_none());
                a.show(Screen::Keys);
                a.build();
                assert_eq!(a.handle(keys_ui::KEY_SERVER_TAKE), 0);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        /// "열쇠 변경 자동 적용 (이 서버를 믿음)" in the window (spec §2.30):
        /// off, B's login asks the gate of A's removal as before (put off
        /// here). The Keys screen's toggle asks S-AUTO-APPLY once (a No
        /// changes nothing) and is kept in B's anchor; [받기…] then takes
        /// the removal with one touch and neither a gate nor a preview, its
        /// status naming the removed key; A's added key is taken at B's next
        /// login with the unlock's touch alone, its status naming the new
        /// key. Turning it off asks nothing.
        #[test]
        fn server_key_changes_apply_by_themselves_once_the_server_is_trusted() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b, fake, devices, mut a, (_va, ka), (vb, kb), auth, guard, _clock) =
                two_on_window("auto-apply", 3, true);
            let h = guard.0;
            let parsed = |p: &Path| vault::keyfile::parse(&std::fs::read(p).unwrap()).unwrap();
            let id = parsed(&ka).vault_id;
            // A removes key 3 (no loss).
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(PASS2, Some(&t)).unwrap();
            let change = vault::Change::Remove {
                remove: vec![3],
                new_password: None,
                loss: None,
                over: None,
            };
            assert_eq!(
                a.rekey(r, Vec::new(), change, vault::Consent::default(), true),
                Ok(vault::Rekeyed::Done)
            );
            key_view(&vb, 2, &std::fs::read(&ka).unwrap());
            // Off: B's login asks the gate, which is put off.
            let gates = std::rc::Rc::new(RefCell::new(0));
            let counted = gates.clone();
            every_input(move |_, _, kind| {
                if matches!(kind, InputKind::Pick(_) | InputKind::Code(_)) {
                    *counted.borrow_mut() += 1;
                }
                InputAnswer::Cancel(keys_ui::GATE_LATER)
            });
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| false);
            login_b(h, &dir_b, &auth, devices[1]);
            stop_answers();
            assert_eq!(*gates.borrow(), 1, "{}", status());
            let before = std::fs::read(&kb).unwrap();
            // The toggle: a No changes nothing, a Yes is kept.
            with_app(|a| {
                a.show(Screen::Keys);
                a.build();
                assert_ne!(a.handle(keys_ui::KEY_AUTO), 0, "offered");
            });
            every_answer(&asked, |_| false);
            press(h, keys_ui::KEY_AUTO);
            with_app(|a| assert!(!a.session.as_ref().unwrap().auto_apply()));
            every_answer(&asked, |_| true);
            press(h, keys_ui::KEY_AUTO);
            stop_answers();
            assert_eq!(*asked.borrow(), [keys_ui::AUTO_ASK, keys_ui::AUTO_ASK]);
            asked.borrow_mut().clear();
            with_app(|a| {
                assert!(a.session.as_ref().unwrap().auto_apply());
                assert_eq!(*a.status, keys_ui::AUTO_ON_DONE);
            });
            // [받기…]: one touch, no gate, no preview.
            every_input(|n, text, _| panic!("asked {n}: {text}"));
            every_answer(&asked, |_| false);
            set(h, CURRENT_PASS, PASS2);
            auth.plan(&[Some(devices[1])]);
            let seen = fake.seen().len();
            press(h, keys_ui::KEY_ACCEPT);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "one touch: {}", status());
            // The backup, then S-PRUNE after a removal; no gate, no preview.
            assert_eq!(
                *asked.borrow(),
                [BACKUP_QUESTION, keys_ui::PRUNE_ASK],
                "{}",
                status()
            );
            asked.borrow_mut().clear();
            let removed = vault::KeyChange {
                removed: vec![3],
                ..vault::KeyChange::default()
            };
            let notice = keys_ui::auto_applied(&removed, "");
            assert!(status().starts_with(notice.trim_end()), "{}", status());
            assert_ne!(std::fs::read(&kb).unwrap(), before);
            assert_eq!(parsed(&kb).state(), parsed(&ka).state());
            // G-01: in the danger tone, and first over every line that
            // comes by itself (a poll's, a lock's) until the next click.
            with_app(|a| {
                assert_eq!(
                    unsafe { GetWindowLongPtrW(a.handle(STATUS), -21) },
                    TONE_DANGER
                );
                a.status("synthetic poll line");
                assert_eq!(
                    unsafe { GetWindowLongPtrW(a.handle(STATUS), -21) },
                    TONE_DANGER
                );
            });
            assert!(
                status().starts_with(notice.trim_end())
                    && status().ends_with("synthetic poll line"),
                "{}",
                status()
            );
            with_app(|a| a.lock("synthetic lock", true));
            assert!(
                status().starts_with(notice.trim_end()) && status().ends_with("synthetic lock"),
                "{}",
                status()
            );
            // A adds key 4; B's next login takes it with the unlock's touch.
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let d4 = fake.plug(Device::with_pin());
            fake.touch(Some(d4));
            let key4 = register(&*fake, &id, 4, 0, true, Vec::new()).unwrap();
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(PASS2, Some(&t)).unwrap();
            assert_eq!(
                a.rekey(
                    r,
                    Vec::new(),
                    vault::Change::AddKey(key4),
                    vault::Consent::default(),
                    true
                ),
                Ok(vault::Rekeyed::Done)
            );
            key_view(&vb, 3, &std::fs::read(&ka).unwrap());
            every_input(|n, text, _| panic!("asked {n}: {text}"));
            every_answer(&asked, |_| false);
            let seen = fake.seen().len();
            login_b(h, &dir_b, &auth, devices[1]);
            stop_answers();
            assert_eq!(fake.seen().len(), seen + 1, "one touch: {}", status());
            assert_eq!(*asked.borrow(), [BACKUP_QUESTION], "{}", status());
            asked.borrow_mut().clear();
            let added = vault::KeyChange {
                added: vec![4],
                ..vault::KeyChange::default()
            };
            let notice = keys_ui::auto_applied(&added, "");
            assert!(status().contains(notice.trim_end()), "{}", status());
            assert_eq!(parsed(&kb).state(), parsed(&ka).state());
            // Taken at the login too, it stays first over a line that
            // comes by itself (G-01).
            with_app(|a| a.status("synthetic poll line"));
            assert!(
                status().starts_with(notice.trim_end())
                    && status().ends_with("synthetic poll line"),
                "{}",
                status()
            );
            // Off asks nothing.
            with_app(|a| {
                a.show(Screen::Keys);
                a.build();
            });
            every_answer(&asked, |text| panic!("asked: {text}"));
            press(h, keys_ui::KEY_AUTO);
            stop_answers();
            with_app(|a| {
                assert!(!a.session.as_ref().unwrap().auto_apply());
                assert_eq!(*a.status, keys_ui::AUTO_OFF_DONE);
            });
            // On again for the last case.
            every_answer(&asked, |_| true);
            press(h, keys_ui::KEY_AUTO);
            stop_answers();
            asked.borrow_mut().clear();
            with_app(|a| assert!(a.session.as_ref().unwrap().auto_apply()));
            // A changes the password; B's login with the new one fails on
            // B's own key file, and S-TRY-SERVER-KEY's yes takes A's file
            // with no gate: that notice is pinned too (G-01).
            with_app(|a| a.lock("synthetic lock", true));
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let newest = "synthetic auto-apply newest password";
            change_password(&fake, devices[0], &mut a, PASS2, newest);
            key_view(&vb, 4, &std::fs::read(&ka).unwrap());
            every_input(|n, text, _| panic!("asked {n}: {text}"));
            every_answer(&asked, |text| text == keys_ui::TRY_SERVER_KEY);
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            with_app(|a| {
                if a.screen != Screen::Login {
                    a.show(Screen::Login);
                }
                a.build();
            });
            auth.plan(&[Some(devices[1])]);
            set(h, PASS, newest);
            press(h, SUBMIT);
            stop_answers();
            assert_eq!(
                *asked.borrow(),
                [keys_ui::TRY_SERVER_KEY, BACKUP_QUESTION],
                "{}",
                status()
            );
            asked.borrow_mut().clear();
            assert_eq!(parsed(&kb).state(), parsed(&ka).state());
            with_app(|a| a.status("synthetic poll line"));
            let lead = keys_ui::AUTO_APPLIED.split('{').next().unwrap();
            assert!(
                status().starts_with(lead)
                    && status().contains(keys_ui::AUTO_PASSWORD)
                    && status().ends_with("synthetic poll line"),
                "{}",
                status()
            );
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        /// The Keys screen follows the server while it is shown (spec §9.1):
        /// A adds a key, and B's next poll there offers [받기…] in place of
        /// [열쇠 파일 동기화 끄기…], keeping the password typed, the focus and
        /// its caret. A poll that changes nothing rebuilds nothing; a flow
        /// under way or an open dialog holds the poll back, and the next
        /// tick after it shows the change (here the server refusing this
        /// PC's line).
        #[test]
        fn the_keys_screen_follows_the_server_and_keeps_what_was_typed() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let (dir_a, dir_b, fake, devices, mut a, (_va, ka), (vb, _kb), auth, guard, _clock) =
                two_on_window("keys-poll", 2, true);
            let h = guard.0;
            login_b(h, &dir_b, &auth, devices[1]);
            with_app(|b| {
                assert!(b.session.is_some(), "{}", *b.status);
                b.show(Screen::Keys);
                b.build();
                assert_ne!(b.handle(keys_ui::KEYSYNC_OFF), 0);
                assert_eq!(b.handle(keys_ui::KEY_ACCEPT), 0);
            });
            let typed = "typed while the server changes";
            set(h, CURRENT_PASS, typed);
            with_app(|b| unsafe {
                SetFocus(b.handle(CURRENT_PASS));
                SendMessageW(b.handle(CURRENT_PASS), 0xb1, 2, 5); // EM_SETSEL
            });
            // A adds key 3, and B's helper fetched A's key file.
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let id = vault::keyfile::parse(&std::fs::read(&ka).unwrap())
                .unwrap()
                .vault_id;
            let d3 = fake.plug(Device::with_pin());
            fake.touch(Some(d3));
            let key3 = register(&*fake, &id, 3, 0, true, Vec::new()).unwrap();
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(PASS2, Some(&t)).unwrap();
            assert_eq!(
                a.rekey(
                    r,
                    Vec::new(),
                    vault::Change::AddKey(key3),
                    vault::Consent::default(),
                    true
                ),
                Ok(vault::Rekeyed::Done)
            );
            let a_key = std::fs::read(&ka).unwrap();
            key_view(&vb, 2, &a_key);
            vault::set_anchor_dir(Some(dir_b.join("anchor")));
            let sel = |b: &App| unsafe {
                let (mut start, mut end) = (0u32, 0u32);
                SendMessageW(
                    b.handle(CURRENT_PASS),
                    0xb0, // EM_GETSEL
                    &mut start as *mut u32 as usize,
                    &mut end as *mut u32 as isize,
                );
                (start, end)
            };
            let field = with_app(|b| {
                b.sync_ticks = 0;
                tick(b, SYNC_TICKS);
                assert!(b.screen == Screen::Keys, "{}", *b.status);
                assert_ne!(b.handle(keys_ui::KEY_ACCEPT), 0, "{}", *b.status);
                assert_eq!(b.handle(keys_ui::KEYSYNC_OFF), 0);
                assert_eq!(*b.read(CURRENT_PASS).unwrap(), typed);
                assert_eq!(unsafe { GetFocus() }, b.handle(CURRENT_PASS));
                assert_eq!(sel(b), (2, 5));
                b.handle(CURRENT_PASS)
            });
            // Nothing changed: nothing is rebuilt.
            with_app(|b| {
                tick(b, SYNC_TICKS);
                assert_eq!(b.handle(CURRENT_PASS), field);
            });
            // The server stops serving this PC's key line: held back during
            // a flow and while a dialog is open, shown at the next tick.
            let dir = syncfile::sync_dir(&vb).unwrap();
            let h3 = vault::keyfile::parse(&a_key).unwrap();
            let mut view = syncfile::KeyView {
                line: 1,
                seq: 2,
                ..Default::default()
            };
            view.record =
                syncfile::render_record_header(syncfile::RecordKind::Key, false, 0, h3.epoch)
                    .to_vec();
            view.record.extend_from_slice(&a_key);
            syncfile::replace_file(
                &dir.join(syncfile::KEY_VIEW),
                &syncfile::render_key_view(&view),
            )
            .unwrap();
            let shown = |b: &App| keys_ui::ks_view(b.session.as_ref()).unwrap();
            with_app(|b| {
                assert!(!shown(b).no_key_ops);
                b.flow = Some(keys_ui::KEY_ADD);
                tick(b, 2 * SYNC_TICKS);
                assert!(!shown(b).no_key_ops);
                assert_eq!(b.handle(CURRENT_PASS), field);
                b.flow = None;
                modal(|| tick(b, 2 * SYNC_TICKS));
                assert!(!shown(b).no_key_ops);
                assert_eq!(b.handle(CURRENT_PASS), field);
                tick(b, SYNC_TICKS);
                assert!(shown(b).no_key_ops);
                assert_ne!(b.handle(CURRENT_PASS), field);
                assert_eq!(*b.read(CURRENT_PASS).unwrap(), typed);
                assert!(b.screen == Screen::Keys && b.session.is_some());
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_b);
        }
        /// PC A and PC C of the tests of a new PC from the server: A's vault
        /// syncs with key-file sync on; C's folder is as goyo-sync's "이 PC로
        /// 가져오기" leaves it, vault.goyo next to its sync folder with the
        /// server's key file in its view, no key file, and C's own anchor,
        /// empty and in use.
        struct FetchedPcs {
            dir_a: PathBuf,
            dir_c: PathBuf,
            pass: &'static str,
            clock: Arc<AtomicU64>,
            fake: Arc<Fake>,
            devices: Vec<usize>,
            ka: PathBuf,
            anchor_c: PathBuf,
            vc: PathBuf,
            key: PathBuf,
            code: String,
        }
        fn fetched_pcs(tag: &str) -> FetchedPcs {
            let (dir_a, dir_c) = (test_dir(&format!("{tag}-a")), test_dir(&format!("{tag}-c")));
            let pass = "synthetic fetched key password";
            let clock = Arc::new(AtomicU64::new(1_000_000));
            let fake = Arc::new(Fake::new(Some(clock.clone())));
            let devices: Vec<usize> = (0..2).map(|_| fake.plug(Device::with_pin())).collect();
            let provision = Provision::new().unwrap();
            let id = provision.vault_id();
            let keys: Vec<_> = devices
                .iter()
                .zip(1u8..)
                .map(|(d, n)| {
                    fake.touch(Some(*d));
                    register(&*fake, &id, n, 0, true, Vec::new()).unwrap()
                })
                .collect();
            vault::set_anchor_dir(Some(dir_a.join("anchor")));
            let (va, ka) = (dir_a.join("vault.goyo"), dir_a.join("vault.goyokey"));
            let mut a = provision
                .finish_with_keys(&va, &ka, pass, true, keys)
                .unwrap();
            let server = Server::default();
            server.helper(&va);
            a.enable_sync().unwrap();
            key_view(&va, 0, &[]);
            a.poll_sync();
            let t = touched(&fake, devices[0], &a, 1);
            let r = a.reauth(pass, Some(&t)).unwrap();
            assert_eq!(
                a.rekey(
                    r,
                    Vec::new(),
                    vault::Change::KeySyncOn,
                    vault::Consent::default(),
                    true
                ),
                Ok(vault::Rekeyed::Done)
            );
            let code = a.key_code().unwrap();
            drop(a);
            // PC C: goyo-sync's "이 PC로 가져오기" put the vault file into the
            // folder picked, as vault.goyo next to its sync folder with the
            // server's key file in its view; no key file, its own anchor,
            // empty.
            let anchor_c = dir_c.join("anchor");
            vault::set_anchor_dir(Some(anchor_c.clone()));
            let (vc, key) = (dir_c.join("vault.goyo"), dir_c.join("vault.goyokey"));
            std::fs::copy(&va, &vc).unwrap();
            server.helper(&vc);
            key_view(&vc, 1, &std::fs::read(&ka).unwrap());
            FetchedPcs {
                dir_a,
                dir_c,
                pass,
                clock,
                fake,
                devices,
                ka,
                anchor_c,
                vc,
                key,
                code,
            }
        }
        /// A new PC from the server (spec §7.17, §2.29; §14.10 walkthrough
        /// 4): the vault file goyo-sync brought into a folder with the
        /// server's key file opens on "서버에서 가져온 금고"; the password
        /// and the touch write nothing and show the TOFU banner with the
        /// code field framed and focused; a wrong code is said in a dialog
        /// and kept in the field; A's code, then the save step next to the
        /// vault (a cancel and a failed file dialog write nothing), writes
        /// the key file and the vault file in place.
        #[test]
        fn a_new_pc_restores_from_the_server_key_file() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let FetchedPcs {
                dir_a,
                dir_c,
                pass,
                clock,
                fake,
                devices,
                ka,
                anchor_c,
                vc,
                key,
                code,
            } = fetched_pcs("fetched");
            let fetched = std::fs::read(&vc).unwrap();
            let auth = Scripted::new(fake.clone());
            let h = window("GoyoCeremonyFetched", &vc, &key, auth.clone(), &clock);
            let guard = Window(h);
            // Restore never takes the server's key file from a sync folder:
            // it points at "서버에서 가져온 금고", and writes nothing.
            let view = syncfile::sync_dir(&vc).unwrap().join(syncfile::KEY_VIEW);
            with_app(|a| {
                a.show(Screen::Restore);
                a.backup_path = vc.clone();
                a.key_path = view.clone();
                a.dest_path = dir_c.join("restored.goyo");
                a.build();
            });
            set(h, PASS, pass);
            press(h, SUBMIT);
            assert_eq!(status(), keys_ui::RESTORE_KEY_VIEW);
            assert!(!dir_c.join("restored.goyo").exists());
            // Restore says what the file is and offers its screen, with the
            // key view as its key file and with no key file at all; SUBMIT
            // names that button there, never the key-file advice by USB.
            let visible = |id: i32| {
                with_app(|a| unsafe { GetWindowLongPtrW(a.handle(id), -16) & 0x1000_0000 != 0 })
            };
            let note = || with_app(|a| caption(a.handle(keys_ui::LOGIN_NOTE)));
            assert!(visible(keys_ui::RESTORE_FETCHED));
            assert_eq!(note(), keys_ui::RESTORE_IS_FETCHED);
            let gone = dir_c.join("gone.goyokey");
            set(h, KPATH, &gone.to_string_lossy());
            with_app(|a| a.command(KPATH, 0x300)).unwrap();
            assert!(visible(keys_ui::RESTORE_FETCHED));
            set(h, PASS, pass);
            press(h, SUBMIT);
            assert_eq!(status(), keys_ui::RESTORE_FETCHED_KEY);
            assert!(!dir_c.join("restored.goyo").exists());
            // A backup that is no vault from the server keeps the usual
            // note, and no such button.
            set(h, VPATH, &dir_a.join("vault.goyo").to_string_lossy());
            with_app(|a| a.command(VPATH, 0x300)).unwrap();
            assert!(!visible(keys_ui::RESTORE_FETCHED));
            assert_eq!(note(), RESTORE_NOTE);
            set(h, VPATH, &vc.to_string_lossy());
            with_app(|a| a.command(VPATH, 0x300)).unwrap();
            assert!(visible(keys_ui::RESTORE_FETCHED));
            // The button opens "서버에서 가져온 금고" with that file, and
            // writes nothing.
            press(h, keys_ui::RESTORE_FETCHED);
            with_app(|a| {
                assert!(a.screen == Screen::Fetched);
                assert_eq!(a.vault_path, vc);
                assert_eq!(a.key_path, key);
                assert_eq!(*a.status, keys_ui::FETCHED_PICKED);
            });
            assert!(!key.exists() && !dir_c.join("restored.goyo").exists());
            with_app(|a| a.key_path = key.clone());
            // The app opens on "서버에서 가져온 금고", which has no key path.
            with_app(|a| {
                a.show(a.home());
                a.build();
                assert!(a.screen == Screen::Fetched);
                assert!(a.handle(KPATH) == 0 && a.handle(DEST) == 0);
            });
            auth.plan(&[Some(devices[1])]);
            set(h, PASS, pass);
            press(h, SUBMIT);
            with_app(|a| {
                let s = a.session.as_ref().expect("restored");
                assert!(s.tofu() && s.fetched_unsaved(), "{}", *a.status);
                assert!(a.screen == Screen::Vault && a.tofu_banner());
                assert!(a.status.starts_with(keys_ui::FETCHED_NEXT), "{}", *a.status);
                // The code field is framed, and it has the focus.
                let field = a.handle(keys_ui::GATE_CODE);
                assert!(a.frames.iter().any(|(_, f)| *f == field));
                assert_eq!(unsafe { GetFocus() }, field);
            });
            assert!(!key.exists() && !anchor_c.join("goyo-vault.keys").exists());
            assert_eq!(std::fs::read(&vc).unwrap(), fetched);
            // The vault file restored in place is locked as a login's is,
            // so no other instance saves it before the TOFU pass.
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir_c.join("vault.goyo.goyolock"))
                .unwrap();
            assert!(lock.try_lock().is_err());
            drop(lock);
            // A wrong code says so in a dialog too, writes nothing, and the
            // field keeps what was typed.
            let mut wrong = code.clone();
            let last = if wrong.pop() == Some('0') { '1' } else { '0' };
            wrong.push(last);
            let told = std::rc::Rc::new(RefCell::new(Vec::new()));
            let record = told.clone();
            every_input(move |_, text, _| {
                record.borrow_mut().push(text.to_owned());
                InputAnswer::Cancel(2)
            });
            set(h, keys_ui::GATE_CODE, &wrong);
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                assert_eq!(a.read(keys_ui::GATE_CODE).unwrap().as_str(), wrong);
                assert!(a.session.as_ref().unwrap().tofu());
            });
            assert!(told.borrow()[0].starts_with(vault::GATE_CODE_WRONG));
            assert!(!key.exists());
            // The backups and key management wait for this step: greyed,
            // and refused with the reason if sent anyway.
            with_app(|a| {
                for id in [BACKUP, KEYBACKUP, CHANGE] {
                    assert!(!a.allows(id), "{id}");
                }
                assert_eq!(a.command(CHANGE, 0), Err(keys_ui::TOFU_FIRST));
            });
            // (A refused backup says so in a message box: called directly.)
            assert_eq!(modal_command(h, BACKUP), Err(keys_ui::TOFU_FIRST));
            assert_eq!(modal_command(h, KEYBACKUP), Err(keys_ui::TOFU_FIRST));
            assert!(!dir_c.join("backup.goyo").exists());
            // The right code: the save step asks to save next to the vault;
            // a cancel writes nothing, and a file dialog that fails says so.
            set(h, keys_ui::GATE_CODE, &code);
            press(h, keys_ui::TOFU_OK);
            assert_eq!(status(), keys_ui::FETCHED_SAVE_LATER);
            assert!(told.borrow()[1].contains(&*key.to_string_lossy()));
            assert!(told.borrow()[1].starts_with(keys_ui::SAVE_LEAD_CODE));
            assert!(!key.exists());
            // No code (S-TOFU-NOPC's yes): the save step says nothing was
            // verified, never that the file is genuine; its cancel points
            // back at the same button.
            let asked = std::rc::Rc::new(RefCell::new(Vec::new()));
            every_answer(&asked, |_| true);
            press(h, keys_ui::TOFU_NOPC);
            assert_eq!(asked.borrow().as_slice(), [keys_ui::TOFU_NOPC_TEXT]);
            assert_eq!(status(), keys_ui::FETCHED_SAVE_LATER_NOCODE);
            let nocode = told.borrow()[2].clone();
            assert!(nocode.starts_with(keys_ui::SAVE_LEAD_NOCODE), "{nocode}");
            assert!(!nocode.contains(keys_ui::SAVE_LEAD_CODE), "{nocode}");
            assert!(!key.exists());
            with_app(|a| assert!(a.session.as_ref().unwrap().tofu()));
            every_input(|_, _, _| InputAnswer::Switch(2));
            keys_ui::SAVE_FAILS.with(|f| f.set(true));
            press(h, keys_ui::TOFU_OK);
            assert_eq!(status(), keys_ui::SAVE_DIALOG_FAILED);
            assert!(!key.exists());
            every_input(|_, _, _| InputAnswer::Accept { checked: false });
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                let s = a.session.as_ref().unwrap();
                assert!(!s.tofu() && !s.fetched_unsaved(), "{}", *a.status);
                assert_eq!(*a.status, fill(keys_ui::FETCHED_SAVED, &[&shown(&key)]));
                assert!(!a.tofu_banner());
                assert_eq!(a.key_path, key);
            });
            assert_eq!(std::fs::read(&key).unwrap(), std::fs::read(&ka).unwrap());
            assert_ne!(std::fs::read(&vc).unwrap(), fetched);
            // The next start is a plain login of the saved pair.
            assert!(!keys_ui::fetched_pending(&vc, &key));
            // That key file moved to a stick: picking the vault on the
            // login keeps it, though the vault's sync folder still has the
            // server's key file; with no key file at all, the server's
            // way in comes back.
            let stick = dir_c.join("stick");
            std::fs::create_dir(&stick).unwrap();
            let moved = stick.join("vault.goyokey");
            std::fs::rename(&key, &moved).unwrap();
            with_app(|a| {
                a.lock("synthetic lock", true);
                a.vault_path = vc.clone();
                a.key_path = moved.clone();
                a.show(Screen::Login);
                a.build();
                a.route_picked_vault();
                assert!(a.screen == Screen::Login);
                assert_eq!(a.key_path, moved);
                a.key_path = stick.join("gone.goyokey");
                a.route_picked_vault();
                assert!(a.screen == Screen::Fetched);
                assert_eq!(a.key_path, key);
            });
            drop(guard);
            let _ = std::fs::remove_dir_all(&dir_a);
            let _ = std::fs::remove_dir_all(&dir_c);
        }
        /// A vault from the server syncs as soon as its key file is saved
        /// (spec §7.17): the polls while the banner stands link nothing and
        /// say nothing of the key view in the sync folder, and the save
        /// links the session as an unlock of the saved pair would, so an
        /// entry added right after it goes up with no lock and no second
        /// unlock.
        #[test]
        fn a_vault_from_the_server_syncs_once_its_key_file_is_saved() {
            let _korean = KoreanAfter::hold();
            crypto::set_kdf_profile(crypto::KdfProfile::Test);
            let pcs = fetched_pcs("fetched-sync");
            let auth = Scripted::new(pcs.fake.clone());
            let h = window(
                "GoyoCeremonyFetchedSync",
                &pcs.vc,
                &pcs.key,
                auth.clone(),
                &pcs.clock,
            );
            let guard = Window(h);
            with_app(|a| {
                a.show(a.home());
                a.build();
                assert!(a.screen == Screen::Fetched);
            });
            auth.plan(&[Some(pcs.devices[1])]);
            set(h, PASS, pcs.pass);
            press(h, SUBMIT);
            let outgoing = syncfile::sync_dir(&pcs.vc)
                .unwrap()
                .join(syncfile::OUTGOING);
            with_app(|a| {
                let said = a.status.clone();
                assert!(a.session.as_ref().unwrap().fetched_unsaved(), "{}", *said);
                a.poll_sync();
                a.poll_sync();
                assert_eq!(*a.status, *said);
                assert_eq!(a.session.as_ref().unwrap().badge(), None);
            });
            assert!(!outgoing.exists());
            set(h, keys_ui::GATE_CODE, &pcs.code);
            every_input(|_, _, _| InputAnswer::Accept { checked: false });
            press(h, keys_ui::TOFU_OK);
            with_app(|a| {
                let s = a.session.as_mut().unwrap();
                assert!(!s.fetched_unsaved(), "{}", *a.status);
                assert!(s.badge().is_some(), "{}", *a.status);
                assert_eq!(a.sync_badge, s.badge());
                // Linked as an unlock links: the first copy is offered at
                // the next poll that finds no server copy either, or by
                // the first edit.
                assert!(!outgoing.exists());
                assert_eq!(*a.status, fill(keys_ui::FETCHED_SAVED, &[&shown(&pcs.key)]));
                s.put(None, sync_entry("added right after the save", "secret"))
                    .unwrap();
            });
            assert!(pcs.key.exists());
            let up = std::fs::read(&outgoing).expect("uploaded without a second unlock");
            let (_, blob) = syncfile::parse_outgoing(&up).unwrap();
            assert!(syncfile::is_sync_vault(blob));
            drop(guard);
            let _ = std::fs::remove_dir_all(&pcs.dir_a);
            let _ = std::fs::remove_dir_all(&pcs.dir_c);
        }
    }
}
