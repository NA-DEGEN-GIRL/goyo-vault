#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("Goyo Vault requires Windows x64.");
mod i18n;
mod theme;
mod win;
use goyo_vault::{
    crypto, syncfile,
    vault::{
        Entry, Format, OtpSetup, Provision, Session, SyncBadge, SyncNotice, key_uses_otp,
        leftover_temp, vault_tag,
    },
};
use i18n::{fill, tr};
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
    /// Set by edit_proc before it posts PASTE_CLEARED (bit 1) or INPUT_ERROR
    /// (bit 2), so the same messages posted by another program do nothing.
    static PASTE_NOTICE: Cell<u8> = const { Cell::new(0) };
    /// Set by App::submit when an unlock found a v1 vault next to a sync
    /// folder; window_proc then asks whether to turn sync on (offer_sync).
    /// Internal state, never a message, so no other program can raise it.
    static SYNC_OFFER: Cell<bool> = const { Cell::new(false) };
}
/// Answers one question in place of the user; gets the question's text.
#[cfg(test)]
type Answer = Box<dyn FnMut(&str) -> bool>;
#[cfg(test)]
thread_local! {
    /// The answer to the next ask(), given by a test: no test can click a
    /// real message box. It runs as the box would, inside modal().
    static ANSWER: RefCell<Option<Answer>> = const { RefCell::new(None) };
}
static EDIT_PROC: OnceLock<Proc> = OnceLock::new();
static LIST_PROC: OnceLock<Proc> = OnceLock::new();
const DRAIN_EVENTS: u32 = 0x8001;
const INPUT_ERROR: u32 = 0x8002;
const PASTE_CLEARED: u32 = 0x8003;
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
const OTP: i32 = 205;
const DEST: i32 = 206;
const CURRENT_PASS: i32 = 207;
const LIST: i32 = 210;
const TITLE: i32 = 211;
const KIND: i32 = 212;
const SECRET: i32 = 213;
const NOTES: i32 = 214;
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
/// The OTP backup QR closes after this long without use, whatever the
/// auto-lock setting; scanning it takes longer than the shortest setting.
const OTP_QR_IDLE: Duration = Duration::from_secs(120);
const OTP_SETUP: i32 = 135;
/// Create: turns the optional OTP on or off.
const OTP_TOGGLE: i32 = 136;
/// Language switch next to the theme switch.
const LANG_KO: i32 = 137;
const LANG_EN: i32 = 138;
const KEY_NOTE: i32 = 220;
const PEEK_FIELDS: [(i32, i32); 3] = [
    (PEEK_PASS, PASS),
    (PEEK_CONFIRM, CONFIRM),
    (PEEK_CURRENT, CURRENT_PASS),
];
const PRESET: i32 = 130;
const PRESET_LAST: i32 = PRESET + KIND_PRESETS.len() as i32 - 1;
const STATUS: i32 = 299;
const KIND_PRESETS: [&str; 4] = ["비밀번호", "니모닉", "프라이빗키", "API 키"];
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
/// Create with the OTP off: the painted card that recommends it.
const CREATE_OTP_CARD: (i32, i32, i32, i32) = (AX, 374, AW, 124);
/// Divider above the "새 금고 만들기 · 백업에서 복원" links on Login.
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
    /// The OTP QR again, for a spare phone or app (vault open, password asked).
    OtpBackup,
}
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
    /// Create: the new vault will also ask for the phone's OTP. Off by
    /// default; the provision keeps one OTP secret either way.
    create_otp: bool,
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
    page: usize,
    closing: bool,
    auth_dirty: bool,
    input_failed: bool,
    /// Login was opened from Welcome ("다른 위치에 있는 금고 열기"), so it
    /// offers a way back instead of being the home screen.
    from_welcome: bool,
    /// OTP secret shown on OtpBackup after the password check.
    otp_setup: Option<OtpSetup>,
    /// When another app took focus while a vault was open.
    away_since: Option<Instant>,
    /// Another app is in front (see deactivated/activated).
    inactive: bool,
    /// Which PEEK_FIELDS are shown with the eye button. Kept here, not in the
    /// button's window data, which other programs can overwrite.
    shown: [bool; 3],
    /// Tone of the status line on the next build (one-shot).
    status_tone: isize,
    /// Index into AUTO_LOCKS, kept in goyo-vault.autolock.
    auto_lock: usize,
    /// Timer ticks, for polling the sync folder on every SYNC_TICKS-th.
    sync_ticks: u32,
    /// The word on the "open" pill for a vault that syncs, as of the last
    /// unlock, edit or poll that changed it.
    sync_badge: Option<SyncBadge>,
}
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
            create_otp: false,
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
            page: 0,
            closing: false,
            auth_dirty: false,
            input_failed: false,
            from_welcome: false,
            otp_setup: None,
            away_since: None,
            inactive: false,
            shown: [false; 3],
            status_tone: TONE_MUTED,
            auto_lock: load_auto_lock(),
            sync_ticks: 0,
            sync_badge: None,
        };
        // The last vault and key that opened, so a key kept on a USB drive does
        // not have to be picked with "찾기" on every start.
        if let Some((vault, key)) = load_paths()
            && vault.is_file()
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
        let small = self.font_of(|t| t.small());
        self.text(0, text, (x, y, w, 20), small, TONE_MUTED, 0);
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
            let ime_ok = if matches!(id, SECRET | NOTES) {
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
                } else if id == OTP {
                    6
                } else if id == TITLE {
                    256
                } else if id == KIND {
                    64
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
        self.label(label, x, y, w);
        self.input(id, value, (x, y + 22, w, 40), password, false, 0);
    }
    /// Masked field with an eye button that shows what was typed.
    fn password_field(&mut self, id: i32, label: &str, x: i32, y: i32, w: i32) {
        self.label(label, x, y, w);
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
    /// Login and Restore show the OTP field only for a key file that uses
    /// one. When the chosen key file needs the other layout, rebuilds the
    /// form keeping the typed password. True if the OTP field was added.
    fn fit_otp_field(&mut self) -> bool {
        if !matches!(self.screen, Screen::Login | Screen::Restore) {
            return false;
        }
        let wanted = key_uses_otp(&self.key_path) == Some(true);
        if wanted == (self.handle(OTP) != 0) {
            return false;
        }
        self.rebuild_keeping(&[PASS]);
        wanted
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
            (None, false) => "열쇠 파일",
        };
        unsafe {
            SetWindowLongPtrW(
                h,
                -21,
                if warning.is_some() {
                    TONE_DANGER
                } else {
                    TONE_MUTED
                },
            );
            SetWindowTextW(h, wide(tr(text)).as_ptr());
            InvalidateRect(h, null(), 1);
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
        self.shown = [false; 3];
    }
    fn status(&mut self, text: &str) {
        self.set_status(text, TONE_MUTED);
    }
    /// Errors stay on the screen in the status line instead of a modal box.
    fn error(&mut self, text: &str) {
        self.set_status(text, TONE_DANGER);
        unsafe {
            MessageBeep(0x30);
        }
    }
    fn set_status(&mut self, text: &str, tone: isize) {
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
    /// Login when a vault exists at the current path, otherwise Welcome.
    fn home(&self) -> Screen {
        if self.vault_path.is_file() {
            Screen::Login
        } else {
            Screen::Welcome
        }
    }
    /// OTP card: QR on the left, instructions and key on the right.
    fn enroll(&self) -> (i32, i32, i32, i32) {
        let y = if self.screen == Screen::OtpBackup {
            150
        } else {
            374
        };
        (AX, y, AW, 226)
    }
    /// Labels of the OTP card; the frame, QR and key are painted.
    fn enrollment_labels(&mut self, tag: &str, footer: &str) {
        let strong = self.font_of(|t| t.strong());
        let (cx, cy, cw, _) = self.enroll();
        let (rx, rw) = (cx + 180, cw - 196);
        // Create keeps room for the "OTP 끄기" button at the top right.
        let head = if self.screen == Screen::Create {
            rw - 112
        } else {
            rw
        };
        self.text(
            0,
            &fill("휴대폰 OTP 등록 · {tag}", &[&tag]),
            (rx, cy + 14, head, 22),
            strong,
            TONE_TEXT,
            0,
        );
        self.note(
            "Google Authenticator → + → QR 코드 스캔\r\nOTP 앱 안의 스캐너로만 찍고, 사진으로 남기지 마세요.",
            rx,
            cy + 40,
            rw,
            40,
        );
        self.note("스캔이 안 되면 '설정 키 입력'에:", rx, cy + 84, rw, 18);
        self.note(footer, cx + 16, cy + 172, cw - 32, 40);
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
        self.clear_controls();
        self.input_failed = false;
        match self.screen {
            Screen::Welcome => self.build_welcome(),
            Screen::Login | Screen::Create | Screen::Restore => self.build_auth(),
            Screen::Vault => self.build_vault(),
            Screen::Edit => self.build_edit(),
            Screen::Password => self.build_password(),
            Screen::OtpBackup => self.build_otp_backup(),
        }
        let small = self.font_of(|t| t.small());
        let status = tr_lines(&self.status);
        let tone = std::mem::replace(&mut self.status_tone, TONE_MUTED);
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
        for id in [LIST, SECRET, NOTES] {
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
        let typed: Vec<i32> = [PASS, CONFIRM, OTP, CURRENT_PASS, TITLE, KIND, SECRET, NOTES]
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
            "백업에서 복원",
            AX + 100,
            358,
            AW - 200,
            44,
            theme::SECONDARY,
        );
        self.button(
            OPEN,
            "다른 위치에 있는 금고 열기",
            AX + 100,
            410,
            AW - 200,
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
            Screen::Restore => "백업에서 복원",
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
            ("백업 파일 · '찾기'로 선택", "열쇠 파일")
        } else {
            ("금고 파일", "열쇠 파일")
        };
        self.path_field(VPATH, BROWSE_V, vault_label, &vault_path, 148);
        self.path_field(KPATH, BROWSE_K, key_label, &key_path, 220);
        let mut y = 292;
        if restore {
            self.path_field(DEST, BROWSE_D, "복원할 새 파일", &dest_path, y);
            y += 72;
        }
        if create {
            self.refresh_key_note();
            let half = (AW - 16) / 2;
            self.password_field(PASS, "비밀번호 · 12자 이상", AX, y, half);
            self.password_field(CONFIRM, "비밀번호 확인", AX + half + 16, y, half);
            if self.create_otp {
                // Enrollment card: QR, setup key and frame are painted.
                let tag = self.provision.as_ref().map(|p| p.tag()).unwrap_or_default();
                self.enrollment_labels(
                    &tag,
                    "휴대폰을 잃으면 금고를 열 수 없으니 예비 기기에도 등록해 두세요.\r\n금고를 연 뒤 아래쪽 'OTP 백업'에서 이 QR을 다시 볼 수 있습니다.",
                );
                let (cx, cy, cw, _) = self.enroll();
                self.button(
                    OTP_TOGGLE,
                    "OTP 끄기",
                    cx + cw - 104,
                    cy + 10,
                    88,
                    30,
                    theme::GHOST,
                );
                self.field(OTP, "앱에 표시된 6자리", "", AX, 616, 180, true);
                self.button(
                    SUBMIT,
                    "등록 확인 · 금고 만들기",
                    AX + 196,
                    638,
                    AW - 196,
                    40,
                    theme::PRIMARY,
                );
            } else {
                // Off by default but recommended: the card's frame, heading
                // and "권장" badge are painted (see draw_otp_offer).
                let (cx, cy, cw, ch) = CREATE_OTP_CARD;
                self.button(
                    OTP_TOGGLE,
                    "OTP 켜기",
                    cx + cw - 136,
                    cy + 14,
                    120,
                    36,
                    theme::ACCENT,
                );
                self.note(
                    "켜 두면 비밀번호가 새어도 휴대폰 없이는 이 앱으로 금고를 열 수 없습니다.\r\n금고를 열 때마다 휴대폰 OTP 앱의 6자리를 함께 입력합니다.\r\n금고·열쇠 파일을 통째로 복사해 가는 것은 막지 못하니, 열쇠 파일은 따로 두세요.",
                    cx + 20,
                    cy + 54,
                    cw - 40,
                    60,
                );
                self.button(
                    SUBMIT,
                    "OTP 없이 금고 만들기",
                    AX,
                    cy + ch + 20,
                    AW,
                    46,
                    theme::PRIMARY,
                );
            }
        } else {
            self.refresh_key_note();
            // Only a key file that uses an OTP gets the OTP field; a key
            // chosen later is handled by fit_otp_field.
            let otp = key_uses_otp(&self.key_path) == Some(true);
            self.password_field(PASS, "비밀번호", AX, y, if otp { AW - 196 } else { AW });
            if otp {
                let source = if restore {
                    &self.backup_path
                } else {
                    &self.vault_path
                };
                let caption = match vault_tag(source) {
                    Some(tag) => fill("OTP 6자리 · {tag}", &[&tag]),
                    None => "Google OTP 6자리".into(),
                };
                self.field(OTP, &caption, "", AX + AW - 180, y, 180, true);
            }
            y += 88;
            let submit = if restore {
                "확인 · 새 파일로 복원"
            } else {
                "잠금 해제"
            };
            self.button(SUBMIT, submit, AX, y, AW, 46, theme::PRIMARY);
            self.note(
                "열쇠 파일은 비밀번호로 암호화되어 있습니다. 금고와 분리 보관하면 보호가 강화됩니다.\r\n분실한 비밀번호·열쇠·OTP를 우회하는 복구 기능은 없습니다.",
                AX,
                y + 62,
                AW,
                40,
            );
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
                    "백업에서 복원",
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
                    SendMessageW(list, 0x180, 0, label.as_ptr() as isize);
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
        self.button(BACKUP, "금고 백업", 40, 642, 112, 34, theme::SECONDARY);
        self.button(KEYBACKUP, "열쇠 백업", 160, 642, 104, 34, theme::SECONDARY);
        self.button(CHANGE, "비밀번호 변경", 272, 642, 140, 34, theme::SECONDARY);
        if self.session.as_ref().is_some_and(Session::uses_otp) {
            self.button(OTP_SETUP, "OTP 백업", 420, 642, 104, 34, theme::SECONDARY);
        }
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
        self.sync_detail();
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
                Zeroizing::new(e.secret.to_string()),
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
        self.label("비밀정보 · 여러 줄 가능", 40, 272, 400);
        self.input(SECRET, &values[2], (40, 294, 796, 130), false, true, 0);
        self.label("메모", 40, 440, 400);
        self.input(NOTES, &values[3], (40, 462, 796, 100), false, true, 0);
        let note = format!(
            "{}\r\n{}",
            tr(
                "비밀정보·메모 칸은 한글 IME를 차단합니다. 입력기 학습 위험이 있어 붙여넣기를 권장합니다.\r\n이 화면에서 복사·잘라내기는 막혀 있고 붙여넣기만 됩니다."
            ),
            tr(AUTO_LOCKS[self.auto_lock].3)
        );
        self.note(&note, 40, 574, 796, 58);
        self.button(CANCEL, "취소", 588, 640, 100, 40, theme::SECONDARY);
        self.button(SAVE, "암호화하여 저장", 696, 640, 140, 40, theme::PRIMARY);
        unsafe {
            SetFocus(self.handle(TITLE));
        }
    }
    /// Top of the painted note card on Password, below the OTP field if any.
    fn password_card_y(&self) -> i32 {
        if self.session.as_ref().is_some_and(Session::uses_otp) {
            456
        } else {
            384
        }
    }
    fn build_password(&mut self) {
        let title = self.font_of(|t| t.title());
        self.text(0, "비밀번호 변경", (AX, 80, AW, 34), title, TONE_TEXT, 0);
        let otp = self
            .session
            .as_ref()
            .filter(|s| s.uses_otp())
            .map(|s| s.tag());
        self.note(
            if otp.is_some() {
                "현재 비밀번호와 새 OTP 번호를 확인한 뒤 열쇠 파일을 다시 암호화합니다."
            } else {
                "현재 비밀번호를 확인한 뒤 열쇠 파일을 다시 암호화합니다."
            },
            AX,
            118,
            AW,
            22,
        );
        self.password_field(CURRENT_PASS, "현재 비밀번호", AX, 160, AW);
        self.password_field(PASS, "새 비밀번호 · 12자 이상", AX, 232, AW);
        self.password_field(CONFIRM, "새 비밀번호 확인", AX, 304, AW);
        if let Some(tag) = otp {
            self.field(
                OTP,
                &fill("새 OTP 6자리 · {tag}", &[&tag]),
                "",
                AX,
                376,
                180,
                true,
            );
        }
        let y = self.password_card_y();
        self.note(
            "현재 열쇠 파일만 갱신됩니다. 이전 열쇠와 이전 비밀번호로 이후 금고도 열 수 있습니다. 유출 대응용 키 교체가 아닙니다. 변경 후 새 열쇠 파일을 별도로 백업하세요.",
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
    /// Shows the OTP QR again so a spare phone or app can be enrolled while
    /// the current one still works. Asks for the password first.
    fn build_otp_backup(&mut self) {
        let title = self.font_of(|t| t.title());
        self.text(0, "OTP 백업", (AX, 80, AW, 34), title, TONE_TEXT, 0);
        if self.otp_setup.is_some() {
            self.note(
                "예비 휴대폰이나 다른 OTP 앱에 등록하면 지금 휴대폰과 같은 번호가 나옵니다.",
                AX,
                118,
                AW,
                22,
            );
            let tag = self.otp_setup.as_ref().map(|s| s.tag()).unwrap_or_default();
            self.enrollment_labels(
                &tag,
                "등록 키를 종이에 적어 두어도 됩니다. 사진으로는 남기지 마세요.\r\n다른 앱으로 전환하면 이 QR은 바로 닫힙니다.",
            );
            self.button(CANCEL, "닫기", AX + AW - 160, 400, 160, 42, theme::PRIMARY);
            unsafe {
                SetFocus(self.handle(CANCEL));
            }
        } else {
            self.note(
                "휴대폰을 잃어도 금고를 열 수 있도록, 지금 쓰는 OTP를 예비 휴대폰이나\r\n다른 OTP 앱에도 등록해 둡니다. 휴대폰을 잃은 뒤에는 이 화면을 열 수 없습니다.",
                AX,
                118,
                AW,
                40,
            );
            self.password_field(CURRENT_PASS, "현재 비밀번호", AX, 172, AW);
            self.note(
                "OTP 등록 정보는 두 번째 잠금 수단이라 금고가 열려 있어도 비밀번호를 다시 확인합니다.",
                AX,
                244,
                AW,
                22,
            );
            self.button(
                CANCEL,
                "취소",
                AX + AW - 268,
                290,
                100,
                42,
                theme::SECONDARY,
            );
            self.button(
                SUBMIT,
                "QR 보기",
                AX + AW - 160,
                290,
                160,
                42,
                theme::PRIMARY,
            );
            unsafe {
                SetFocus(self.handle(CURRENT_PASS));
            }
        }
    }
    /// Shows the detail-card controls that apply to the current selection.
    fn sync_detail(&self) {
        if self.screen != Screen::Vault {
            return;
        }
        let entry = self.entry();
        let revealed = entry.is_some() && self.reveal_until.is_some();
        let paging = revealed
            && entry
                .and_then(|e| self.pages(&e.secret).ok())
                .is_some_and(|p| p.len() > 1);
        unsafe {
            let reveal = if revealed {
                "가리기"
            } else {
                "15초 보기"
            };
            SetWindowTextW(self.handle(REVEAL), wide(tr(reveal)).as_ptr());
            let focus = GetFocus();
            for (id, show) in [
                (EDIT, entry.is_some()),
                (DELETE, entry.is_some()),
                (REVEAL, entry.is_some()),
                (TOGGLE, entry.is_some()),
                (COPY, entry.is_some()),
                (PREVIOUS, paging),
                (NEXT, paging),
            ] {
                let h = self.handle(id);
                if !show && h == focus {
                    SetFocus(self.handle(LIST));
                }
                ShowWindow(h, if show { 8 } else { 0 });
            }
        }
    }
    /// First run (no vault at the default location) starts on Welcome.
    fn start_screen(&mut self) {
        self.screen = self.home();
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
    /// user is elsewhere: passwords shown with the eye are masked and the new
    /// vault's OTP QR is hidden; with a vault open the 15-second view and copy
    /// permission also end and the OTP backup QR closes. Pre-unlock forms are
    /// kept. An open vault locks per the auto-lock setting (see timer). Runs on
    /// WM_ACTIVATEAPP and from the timer, which also catches missed messages.
    fn deactivated(&mut self) {
        self.mask_passwords();
        if !std::mem::replace(&mut self.inactive, true) && self.provision.is_some() {
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
        }
        if self.session.is_none() {
            return;
        }
        self.away_since.get_or_insert_with(Instant::now);
        self.reset_copy();
        if self.reveal_until.take().is_some() {
            self.sync_detail();
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
        }
        if self.otp_setup.take().is_some() {
            self.screen = Screen::Vault;
            self.status = line("다른 앱으로 전환되어 OTP 화면을 닫았습니다.");
            self.build();
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
        self.auth_dirty = false;
        self.activity = Instant::now();
        let _ = self.paths();
        self.clear_controls();
        self.session = None;
        self.provision = None;
        self.otp_setup = None;
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
        self.screen = self.home();
        self.from_welcome = false;
        // The line may name an entry (a sync conflict).
        self.status.zeroize();
        self.status = line(why);
        self.build();
    }
    /// Drops the keys, the OTP secret and any reveal or copy permission
    /// without touching the controls; a pending lock rebuilds the screen
    /// moments later (see window_proc).
    fn scrub(&mut self) {
        self.session = None;
        self.provision = None;
        self.otp_setup = None;
        self.reveal_until = None;
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
    fn submit(&mut self) -> crypto::Result<()> {
        if self.input_failed {
            return Err("입력 보호 설정 실패로 저장/인증을 중단합니다.");
        }
        check_environment(self.hwnd)?;
        if Instant::now() < self.retry {
            return Err("인증 실패 후 대기 중입니다. 잠시 후 다시 시도하세요.");
        }
        self.paths()?;
        let pass = self.read(PASS)?;
        let otp = self.read(OTP)?;
        if self.screen == Screen::OtpBackup {
            if self.otp_setup.is_some() {
                return Ok(());
            }
            let current = self.read(CURRENT_PASS)?;
            self.status("비밀번호 확인 중입니다…");
            unsafe {
                UpdateWindow(self.hwnd);
            }
            let result = self
                .session
                .as_ref()
                .ok_or("먼저 금고를 열어주세요.")?
                .otp_setup(&current);
            return match result {
                Ok(setup) => {
                    self.failed = 0;
                    self.otp_setup = Some(setup);
                    self.status = line("예비 기기에 등록한 뒤 '닫기'를 누르세요.");
                    self.build();
                    Ok(())
                }
                Err(_) => {
                    self.failed = self.failed.saturating_add(1);
                    self.retry =
                        Instant::now() + Duration::from_secs((1u64 << self.failed.min(6)).min(60));
                    Err("비밀번호가 맞지 않습니다.")
                }
            };
        }
        if self.screen == Screen::Password {
            if pass.as_str() != self.read(CONFIRM)?.as_str() {
                return Err("비밀번호 확인이 일치하지 않습니다.");
            }
            let current = self.read(CURRENT_PASS)?;
            let result = self
                .session
                .as_mut()
                .ok_or("먼저 금고를 열어주세요.")?
                .change_password(&current, &pass, &otp);
            if let Err(e) = result {
                self.failed = self.failed.saturating_add(1);
                self.retry =
                    Instant::now() + Duration::from_secs((1u64 << self.failed.min(6)).min(60));
                return Err(e);
            }
            self.failed = 0;
            self.screen = Screen::Vault;
            self.status = line(
                "비밀번호 변경 완료. 새 열쇠 파일을 백업하세요. 이전 사본은 자동 폐기되지 않습니다.",
            );
            self.build();
            return Ok(());
        }
        // Missing files are a navigation problem, not a failed authentication:
        // say what to do and do not start the retry delay.
        match self.screen {
            Screen::Login if !self.vault_path.is_file() => {
                return Err(if leftover_temp(&self.vault_path) {
                    LEFTOVER_TEMP
                } else {
                    "금고 파일을 찾을 수 없습니다. 경로를 확인하거나 '찾기'로 선택하세요."
                });
            }
            Screen::Restore if !self.backup_path.is_file() => {
                return Err("복원할 백업 파일을 '찾기'로 선택하세요.");
            }
            Screen::Login | Screen::Restore if !self.key_path.is_file() => {
                return Err(if leftover_temp(&self.key_path) {
                    LEFTOVER_TEMP
                } else {
                    "열쇠 파일을 찾을 수 없습니다. USB 등 다른 곳에 두었다면 '찾기'로 선택하세요."
                });
            }
            Screen::Restore if self.dest_path.exists() => {
                return Err(
                    "'복원할 새 파일'과 같은 이름의 파일이 이미 있습니다. 다른 이름을 지정하세요.",
                );
            }
            Screen::Create if self.new_vault_path.exists() || self.new_key_path.exists() => {
                return Err("같은 이름의 파일이 이미 있습니다. 새 금고·열쇠 파일 이름을 바꾸세요.");
            }
            _ => {}
        }
        // A key file typed in by path may be one that uses an OTP: ask for
        // the code instead of failing the authentication.
        if self.fit_otp_field() {
            return Err("이 열쇠 파일은 OTP를 씁니다. 휴대폰 OTP 앱의 6자리도 입력하세요.");
        }
        if self.screen == Screen::Create && pass.as_str() != self.read(CONFIRM)?.as_str() {
            return Err("비밀번호 확인이 일치하지 않습니다.");
        }
        self.status("인증 및 암호화 처리 중입니다…");
        unsafe {
            UpdateWindow(self.hwnd);
        }
        let screen = self.screen;
        let result = match self.screen {
            Screen::Create => {
                goyo_vault::vault::password_policy(&pass)?;
                // Verify before consuming the provisioning object; a typo must
                // not replace the enrollment secret already entered on the phone.
                let provision = self
                    .provision
                    .as_ref()
                    .ok_or("새 금고 등록을 다시 시작하세요.")?;
                let code = self.create_otp.then_some(otp.as_str());
                provision.finish(&self.new_vault_path, &self.new_key_path, &pass, code)
            }
            Screen::Restore => Session::restore(
                &self.backup_path,
                &self.key_path,
                &self.dest_path,
                &pass,
                &otp,
            ),
            _ => Session::unlock(&self.vault_path, &self.key_path, &pass, &otp),
        };
        match result {
            Ok(mut s) => {
                self.vault_path = s.path.clone();
                self.key_path = s.key_path.clone();
                self.new_vault_path = PathBuf::new();
                self.new_key_path = PathBuf::new();
                self.backup_path = PathBuf::new();
                self.dest_path = PathBuf::new();
                save_paths(&s.path, &s.key_path);
                let warning = placement_warning(&s.path, &s.key_path);
                let uses_otp = s.uses_otp();
                // Only opening a vault looks at its sync folder.
                let login = screen == Screen::Login;
                let notice = if login { s.take_unlock_notice() } else { None };
                if login && s.sync_offer() {
                    SYNC_OFFER.with(|f| f.set(true));
                }
                self.sync_badge = s.badge();
                self.session = Some(s);
                self.provision = None;
                self.create_otp = false;
                self.failed = 0;
                self.screen = Screen::Vault;
                let first = match (screen == Screen::Create, uses_otp) {
                    (true, true) => {
                        "새 금고를 만들었습니다. 휴대폰 분실에 대비해 아래 'OTP 백업'으로 예비 기기에도 등록해 두세요."
                    }
                    (true, false) => {
                        "새 금고를 만들었습니다. 아래 '열쇠 백업'으로 열쇠 파일 사본을 금고와 다른 곳에 두세요."
                    }
                    _ if AUTO_LOCKS[self.auto_lock].1.is_none() => {
                        "잠금 해제됨 · 자동 잠금이 꺼져 있습니다. 자리를 비울 때는 잠금 버튼이나 Win+L을 누르세요."
                    }
                    _ => {
                        "잠금 해제됨 · 저장하면 즉시 암호화됩니다. 화면 캡처는 막지만 악성코드까지 막지는 못합니다."
                    }
                };
                // What the unlock found in the sync folder replaces the usual
                // line; the placement warning still follows it.
                let (first, mut tone) = match &notice {
                    Some(n) => sync_line(n),
                    None => (Zeroizing::new(first.to_owned()), TONE_MUTED),
                };
                self.status = match warning {
                    Some(w) => {
                        tone = TONE_DANGER;
                        joined(&[&first, w.message()])
                    }
                    None => first,
                };
                self.status_tone = tone;
                self.build();
                Ok(())
            }
            Err(e) => {
                self.failed = self.failed.saturating_add(1);
                self.retry =
                    Instant::now() + Duration::from_secs((1u64 << self.failed.min(6)).min(60));
                self.status("인증 실패. 잠시 후 다시 시도하세요.");
                Err(e)
            }
        }
    }
    fn command(&mut self, id: i32, notify: u16) -> crypto::Result<()> {
        let id = match (id, self.screen) {
            (1, Screen::OtpBackup) if self.otp_setup.is_some() => CANCEL,
            (
                1,
                Screen::Login
                | Screen::Create
                | Screen::Restore
                | Screen::Password
                | Screen::OtpBackup,
            ) => SUBMIT,
            (1, Screen::Edit) => SAVE,
            (2, Screen::Edit | Screen::Password | Screen::OtpBackup) => CANCEL,
            (2, Screen::Vault) => LOCK,
            (2, Screen::Login | Screen::Create | Screen::Restore) if self.handle(BACK) != 0 => BACK,
            (1 | 2, _) => return Ok(()),
            _ => id,
        };
        if !self.allows(id) {
            return Err("현재 화면에서 허용되지 않는 작업입니다.");
        }
        if self.closing {
            return Err("클립보드 정리 후 종료를 기다리고 있습니다.");
        }
        self.activity = Instant::now();
        if notify == 0x300 && matches!(id, PASS | CONFIRM | OTP | CURRENT_PASS) {
            self.auth_dirty = true;
        }
        if notify == 0x300 && matches!(id, VPATH | KPATH) {
            self.refresh_key_note();
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
        match id {
            CREATE | OPEN | RESTORE | BACK => {
                check_environment(self.hwnd)?;
                self.paths()?;
                // Generate before switching so a failure leaves the screen as is.
                // Back or Esc keeps it: the QR may already be on the phone, and a
                // new one would silently make that entry useless. Lock and the
                // idle timeout still drop it.
                if id == CREATE && self.provision.is_none() {
                    self.provision = Some(Provision::new()?);
                    self.create_otp = false;
                }
                self.copy_until = None;
                self.reveal_until = None;
                self.from_welcome = id == OPEN;
                self.screen = match id {
                    CREATE => Screen::Create,
                    RESTORE => Screen::Restore,
                    OPEN => Screen::Login,
                    _ if self.screen == Screen::Login => Screen::Welcome,
                    _ => self.home(),
                };
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
                self.screen = Screen::Edit;
                self.build();
            }
            CANCEL => {
                self.otp_setup = None;
                self.screen = Screen::Vault;
                self.build();
            }
            OTP_SETUP => {
                self.reset_copy();
                self.reveal_until = None;
                self.otp_setup = None;
                self.screen = Screen::OtpBackup;
                self.build();
            }
            OTP_TOGGLE => {
                self.create_otp = !self.create_otp;
                self.status = line(if self.create_otp {
                    "휴대폰 OTP 앱으로 QR을 등록하고, 앱에 표시된 6자리를 입력하세요."
                } else {
                    "OTP 없이 비밀번호와 열쇠 파일로만 여는 금고를 만듭니다. 이 PC를 다른 사람도 쓸 수 있다면 OTP를 켜 두세요."
                });
                // Same OTP secret either way, so a QR already scanned stays valid.
                self.rebuild_keeping(&[PASS, CONFIRM]);
                let next = if self.read(PASS)?.is_empty() {
                    PASS
                } else if self.create_otp {
                    OTP
                } else {
                    SUBMIT
                };
                unsafe {
                    SetFocus(self.handle(next));
                }
            }
            THEME_DARK | THEME_LIGHT => self.set_theme(id == THEME_DARK),
            LANG_KO | LANG_EN => self.set_language(id == LANG_EN),
            AUTO_LOCK..=AUTO_LOCK_LAST => self.set_auto_lock((id - AUTO_LOCK) as usize),
            PEEK_PASS | PEEK_CONFIRM | PEEK_CURRENT => self.peek(id)?,
            PRESET..=PRESET_LAST => unsafe {
                let kind = self.handle(KIND);
                let name = KIND_PRESETS[(id - PRESET) as usize];
                SetWindowTextW(kind, wide(tr(name)).as_ptr());
                SendMessageW(kind, 0xcd, 0, 0);
                SetFocus(self.handle(SECRET));
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
                let e = Entry::new(
                    std::mem::take(&mut *title),
                    std::mem::take(&mut *kind),
                    std::mem::take(&mut *secret),
                    std::mem::take(&mut *notes),
                )?;
                let s = self.session.as_mut().ok_or("금고가 잠겼습니다.")?;
                // `editing` is still the entry's index: merges wait while
                // the edit screen is shown (see timer).
                s.put(self.editing, e)?;
                self.sync_badge = s.badge();
                self.selected = self.editing.or(Some(s.entries.len() - 1));
                self.page = 0;
                self.screen = Screen::Vault;
                self.status = line("암호화하여 저장했습니다.");
                self.build();
            }
            CHANGE => {
                self.reset_copy();
                self.reveal_until = None;
                self.screen = Screen::Password;
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
                let seq = copy_secret(self.hwnd, &e.secret)?;
                self.clipboard = Some((seq, Instant::now() + Duration::from_secs(15)));
                self.reset_copy();
                self.status("복사 완료 · 15초 안에 붙여넣으세요. 복사 허용은 다시 꺼졌습니다.");
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
                let pages = self.pages(&e.secret)?;
                self.page = if id == NEXT {
                    (self.page + 1).min(pages.len().saturating_sub(1))
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
            Screen::Vault | Screen::Edit | Screen::Password | Screen::OtpBackup
        ) && self.session.is_none()
        {
            return false;
        }
        if matches!(id, THEME_DARK | THEME_LIGHT | LANG_KO | LANG_EN) {
            return true;
        }
        if id == OTP_SETUP && !self.session.as_ref().is_some_and(Session::uses_otp) {
            return false;
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
                    | OTP
            ),
            Screen::Create => matches!(
                id,
                BACK | SUBMIT
                    | OTP_TOGGLE
                    | BROWSE_V
                    | BROWSE_K
                    | VPATH
                    | KPATH
                    | PASS
                    | CONFIRM
                    | PEEK_PASS
                    | PEEK_CONFIRM
                    | OTP
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
                    | OTP
            ),
            Screen::Vault => matches!(
                id,
                LOCK | BACKUP
                    | KEYBACKUP
                    | CHANGE
                    | OTP_SETUP
                    | LIST
                    | NEW
                    | EDIT
                    | DELETE
                    | REVEAL
                    | TOGGLE
                    | COPY
                    | PREVIOUS
                    | NEXT
                    | AUTO_LOCK..=AUTO_LOCK_LAST
            ),
            Screen::Edit => matches!(
                id,
                TITLE | KIND | SECRET | NOTES | SAVE | CANCEL | PRESET..=PRESET_LAST
            ),
            Screen::Password => matches!(
                id,
                PASS | CONFIRM
                    | CURRENT_PASS
                    | PEEK_PASS
                    | PEEK_CONFIRM
                    | PEEK_CURRENT
                    | OTP
                    | SUBMIT
                    | CANCEL
            ),
            Screen::OtpBackup => matches!(id, CURRENT_PASS | PEEK_CURRENT | SUBMIT | CANCEL),
        }
    }
    fn reset_copy(&mut self) {
        self.copy_until = None;
        self.set_toggle(false);
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
            if self.screen == Screen::Vault {
                let (x, y, w, h) = HINT;
                InvalidateRect(self.hwnd, &self.r(x, y, w, h), 0);
            }
        }
    }
    fn timer(&mut self) {
        // Threads Windows started since the last tick (e.g. for a file dialog).
        restrict_threads();
        let now = Instant::now();
        let ticking =
            self.reveal_until.is_some() || self.copy_until.is_some() || self.clipboard.is_some();
        if self.clipboard.is_some_and(|(_, t)| now >= t) {
            self.expire_clipboard();
        }
        if self.closing && self.clipboard.is_none() {
            unsafe {
                DestroyWindow(self.hwnd);
            }
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
            if self.session.is_some() && self.auto_lock == 0 && away >= AWAY_LOCK {
                self.lock("다른 앱에 30초 넘게 머물러 잠갔습니다.", false);
                return;
            }
            let idle = now.duration_since(self.activity);
            // Typed forms before a vault is open are cleared on fixed times;
            // copying the new key onto paper or scanning a QR takes longer.
            let limit = if self.provision.is_some() {
                Some(Duration::from_secs(300))
            } else if self.session.is_none() {
                Some(Duration::from_secs(60))
            } else if self.otp_setup.is_some() {
                AUTO_LOCKS[self.auto_lock].1.map(|l| l.max(OTP_QR_IDLE))
            } else {
                AUTO_LOCKS[self.auto_lock].1
            };
            // Time in another app counts as unused even if an input slipped by.
            if limit.is_some_and(|l| idle.max(away) >= l) {
                self.lock("미사용 시간이 지나 자동으로 잠갔습니다.", true);
                return;
            }
            if self.otp_setup.is_some() && idle >= OTP_QR_IDLE {
                self.otp_setup = None;
                self.screen = Screen::Vault;
                self.status = line("2분 동안 쓰지 않아 OTP 화면을 닫았습니다.");
                self.build();
            }
        }
        // Merges wait while an entry is edited, another screen is shown or a
        // dialog runs, so `editing` and `selected` keep pointing at the
        // entry they meant; the first tick back on the list applies them.
        self.sync_ticks = self.sync_ticks.wrapping_add(1);
        if self.sync_ticks.is_multiple_of(SYNC_TICKS)
            && self.session.is_some()
            && self.screen == Screen::Vault
            && !self.closing
            && !in_modal()
        {
            self.poll_sync();
        }
        if ticking && self.screen == Screen::Vault {
            let (x, y, w, h) = HINT;
            unsafe {
                InvalidateRect(self.hwnd, &self.r(x, y, w, h), 0);
            }
        }
    }
    /// One look at the sync folder from the vault list (see timer). A merge
    /// can move or replace entries: the selection follows its entry by ID,
    /// or the entry that replaced it by an edit on another PC. The 15-second
    /// view and copy permission end with any change to the list, since a
    /// merge can also put other text under the same ID. Polling is not use
    /// (`activity` stays) and its notices never beep.
    fn poll_sync(&mut self) {
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let kept = self.selected.and_then(|i| s.entry_id(i));
        let Some(event) = s.poll_sync() else {
            return;
        };
        if event.badge_changed {
            self.sync_badge = s.badge();
        }
        let line = event.notice.as_ref().map(sync_line);
        if event.list_changed {
            self.selected = kept.and_then(|id| s.entry_index(&id).or_else(|| s.successor(&id)));
            self.reveal_until = None;
            self.page = 0;
            self.reset_copy();
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
            if x >= r.left && x < r.right && y >= r.top && y < r.bottom {
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
        let Some((title, small, code)) = theme::with(|t| (t.title(), t.small(), t.code)) else {
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
                    let card = self.r(AX, self.password_card_y(), AW, 80);
                    theme::round(dc, &card, self.px(10), Some(p.bg), Some(p.border));
                }
                Screen::Create if !self.create_otp => self.draw_otp_offer(dc, &p, small),
                _ => {}
            }
            let focus = GetFocus();
            for (frame, h) in &self.frames {
                let border = if *h == focus && *h != self.handle(LIST) {
                    p.focus
                } else {
                    p.border
                };
                let r = self.scaled(frame);
                theme::round(dc, &r, self.px(8), Some(p.bg), Some(border));
            }
            if self.screen == Screen::Create
                && self.create_otp
                && let Some(provision) = &self.provision
            {
                if self.inactive {
                    self.draw_enrollment_hidden(dc, &p, small);
                } else {
                    self.draw_enrollment(dc, &provision.setup(), &p, code);
                }
            }
            if self.screen == Screen::OtpBackup
                && let Some(setup) = &self.otp_setup
            {
                self.draw_enrollment(dc, setup, &p, code);
            }
            if self.screen == Screen::Vault {
                self.draw_detail(dc, small, title);
            }
        }
    }
    /// Create with the OTP off: an accent frame, the heading and a "권장"
    /// badge, painted so the badge can sit right after the heading.
    unsafe fn draw_otp_offer(&self, dc: isize, p: &theme::Palette, small: isize) {
        let Some(strong) = theme::with(|t| t.strong()) else {
            return;
        };
        let (x, y, w, h) = CREATE_OTP_CARD;
        unsafe {
            theme::round(
                dc,
                &self.r(x, y, w, h),
                self.px(12),
                Some(p.bg),
                Some(p.accent),
            );
            let heading = tr("휴대폰 OTP로 한 번 더 잠그기");
            theme::text(
                dc,
                heading,
                &self.r(x + 20, y + 20, w - 180, 24),
                strong,
                p.text,
                LINE,
            );
            let left = self.px(x + 20) + theme::text_width(dc, heading, strong) + self.px(10);
            let badge = Rect {
                left,
                top: self.px(y + 22),
                right: left + theme::text_width(dc, tr("권장"), small) + self.px(18),
                bottom: self.px(y + 42),
            };
            theme::round(dc, &badge, self.px(10), None, Some(p.accent));
            theme::text(dc, tr("권장"), &badge, small, p.accent, DT_CENTER | LINE);
        }
    }
    /// While another app is in front the card shows no QR and no key.
    unsafe fn draw_enrollment_hidden(&self, dc: isize, p: &theme::Palette, small: isize) {
        let (cx, cy, _, _) = self.enroll();
        unsafe {
            let tile = self.r(cx + 16, cy + 16, 148, 148);
            theme::round(dc, &tile, self.px(8), Some(p.surface), None);
            theme::text(
                dc,
                tr("창을 선택하면\nQR이 다시 보입니다"),
                &tile,
                small,
                p.muted,
                DT_CENTER | DT_WORDBREAK | DT_NOPREFIX,
            );
            let key = self.r(cx + 180, cy + 106, self.enroll().2 - 196, 58);
            theme::round(dc, &key, self.px(8), Some(p.surface), None);
        }
    }
    /// QR for authenticator apps plus the same key as text for manual entry.
    unsafe fn draw_enrollment(&self, dc: isize, setup: &OtpSetup, p: &theme::Palette, code: isize) {
        let (cx, cy, cw, ch) = self.enroll();
        unsafe {
            theme::round(
                dc,
                &self.r(cx, cy, cw, ch),
                self.px(12),
                Some(p.bg),
                Some(p.border),
            );
            // Black on white in both themes: scanners expect dark modules on light.
            let tile = self.r(cx + 16, cy + 16, 148, 148);
            theme::round(dc, &tile, self.px(8), Some(theme::rgb(255, 255, 255)), None);
            let uri = setup.uri();
            if let Ok(qr) = goyo_vault::qr::encode(uri.as_bytes()) {
                // Whole pixels per module keep edges sharp; 4-module quiet zone.
                let span = goyo_vault::qr::SIZE as i32 + 8;
                let side = tile.right - tile.left;
                let m = (side / span).max(1);
                let left = tile.left + (side - m * span) / 2 + 4 * m;
                let top = tile.top + (side - m * span) / 2 + 4 * m;
                let ink = CreateSolidBrush(theme::rgb(0, 0, 0));
                for y in 0..goyo_vault::qr::SIZE {
                    for x in 0..goyo_vault::qr::SIZE {
                        if qr.dark(x, y) {
                            let (x, y) = (x as i32, y as i32);
                            let r = Rect {
                                left: left + x * m,
                                top: top + y * m,
                                right: left + (x + 1) * m,
                                bottom: top + (y + 1) * m,
                            };
                            FillRect(dc, &r, ink);
                        }
                    }
                }
                DeleteObject(ink);
            }
            // Two lines of four groups; authenticator apps ignore the spaces.
            let (rx, rw) = (cx + 180, cw - 196);
            let key = self.r(rx, cy + 106, rw, 58);
            theme::round(dc, &key, self.px(8), Some(p.surface), None);
            let raw = setup.code();
            let mut grouped = Zeroizing::new(String::with_capacity(raw.len() * 2));
            for (i, c) in raw.chars().enumerate() {
                if i > 0 && i % 16 == 0 {
                    grouped.push('\n');
                } else if i > 0 && i % 4 == 0 {
                    grouped.push(' ');
                }
                grouped.push(c);
            }
            let inner = theme::inset(&key, 0, self.px(5));
            theme::text(dc, &grouped, &inner, code, p.text, DT_CENTER | DT_NOPREFIX);
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
                ("휴대폰 OTP", "켜기 권장\n켠 금고만 필요"),
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
                match self.pages(&e.secret) {
                    Ok(pages) => {
                        let index = self.page.min(pages.len() - 1);
                        theme::text(dc, &pages[index], &secret_rect, body, p.text, wrap);
                        if pages.len() > 1 {
                            let r = self.r(612, 198, 200, 20);
                            let n = fill("{} / {} 페이지", &[&(index + 1), &pages.len()]);
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
            let notes = self.r(CARD_X, 468, CARD_W, 132);
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

// Native dialogs pump messages. No RefCell borrow may span these calls: timers,
// session lock notifications and focus loss must remain able to wipe secrets.
fn modal_command(h: Hwnd, id: i32) -> crypto::Result<()> {
    let prepared = APP.with(|cell| -> crypto::Result<_> {
        let mut b = cell.try_borrow_mut().map_err(|_| "화면 작업 중입니다.")?;
        let a = b.as_mut().ok_or("화면이 닫혔습니다.")?;
        if a.closing || !a.allows(id) {
            return Err("종료 중입니다.");
        }
        if matches!(id, BACKUP | KEYBACKUP | DELETE) && a.session.is_none() {
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
        let Some(p) = dialog(h, save, matches!(id, KEYBACKUP | BROWSE_K)) else {
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
                let s = a.session.as_ref().ok_or("금고가 잠겼습니다.")?;
                let p = path.ok_or("경로 오류")?;
                if id == BACKUP {
                    s.backup(&p)?;
                } else {
                    s.backup_key(&p)?;
                }
                a.status(match (id == BACKUP, s.uses_otp()) {
                    (true, true) => {
                        "금고 백업을 저장했습니다. 열 때 열쇠 파일, 비밀번호, OTP도 필요합니다."
                    }
                    (true, false) => {
                        "금고 백업을 저장했습니다. 열 때 열쇠 파일과 비밀번호도 필요합니다."
                    }
                    _ => "암호화된 열쇠를 백업했습니다. 금고와 분리하여 보관하세요.",
                });
            }
            _ => {
                let p = path.ok_or("경로 오류")?;
                let field = match id {
                    BROWSE_V => VPATH,
                    BROWSE_K => KPATH,
                    _ => DEST,
                };
                let text = wide(&p.to_string_lossy());
                *a.path_slot(field) = p;
                unsafe {
                    SetWindowTextW(a.handle(field), text.as_ptr());
                }
                // The change notice arrived while the state was busy.
                if !(field == KPATH && a.fit_otp_field()) {
                    a.refresh_key_note();
                }
            }
        }
        Ok(())
    });
    drain_pending(h);
    result
}
/// confirm(); a test answers in its place (see ANSWER).
fn ask(h: Hwnd, text: &str) -> bool {
    #[cfg(test)]
    if let Some(mut answer) = ANSWER.with(|a| a.borrow_mut().take()) {
        return modal(|| answer(text));
    }
    confirm(h, text)
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
        Some((s.path.clone(), folder))
    });
    let Some((path, folder)) = asked else {
        return;
    };
    unsafe {
        UpdateWindow(h);
    }
    let consent = fill(
        "이 금고 옆에 동기화 폴더({})가 있습니다. goyo-sync가 이 폴더를 통해 암호화된 금고 사본만 서버와 주고받습니다. 열쇠 파일과 비밀번호는 보내지 않습니다.\n\n동기화를 켜면 금고 형식이 바뀌어 0.7 이하 버전에서는 이 금고와 이후 백업을 열 수 없습니다. 다른 PC도 먼저 0.8 이상으로 업데이트하세요. 동기화를 켤까요?",
        &[&folder],
    );
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
            if a.closing && a.clipboard.is_none() {
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
        if matches!(id, SECRET | PASS | CONFIRM | CURRENT_PASS) && clear_pasted(h, sequence) {
            PASTE_NOTICE.with(|n| n.set(n.get() | 1));
            PostMessageW(GetParent(h), PASTE_CLEARED, 0, 0);
        }
    }
    Ok(())
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
    if m == 0x111
        && (w >> 16) == 0
        && matches!(
            (w & 0xffff) as i32,
            BROWSE_V | BROWSE_K | BROWSE_D | DELETE | BACKUP | KEYBACKUP
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
                if app.clipboard.is_none() {
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
/// tr() for each line of a status: an unlock line and the placement warning
/// after it are separate entries, and the stored Korean source lets a
/// language switch translate them again.
fn tr_lines(text: &str) -> Zeroizing<String> {
    let parts: Vec<&str> = text.split("\r\n").map(tr).collect();
    joined(&parts)
}
/// The status line for a sync notice and its tone. Sync news never beeps:
/// it is not the result of what the user just did. A line without values
/// keeps its Korean source, so a language switch translates it. No line
/// names an entry: the status line is window text other programs can read.
fn sync_line(notice: &SyncNotice) -> (Zeroizing<String>, isize) {
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
    };
    (text, if danger { TONE_DANGER } else { TONE_MUTED })
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
const LEFTOVER_TEMP: &str = "파일이 없고, 저장이 끊기며 남은 임시 파일(.goyotmp)이 같은 폴더에 있습니다. 지우지 마세요. 그 파일 이름을 원래 이름으로 바꾸면 복구될 수 있습니다.";
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
    // A confirm box is an owned popup, not a child: its buttons count too.
    let b = confirm_box();
    let ours = msg.hwnd != 0
        && (msg.hwnd == h
            || unsafe { IsChild(h, msg.hwnd) } != 0
            || (b != 0 && (msg.hwnd == b || unsafe { IsChild(b, msg.hwnd) } != 0)));
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
    /// Puts the interface back in Korean when a test that switched to
    /// English ends, even by a failed assertion.
    struct KoreanAfter;
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
    /// first run, open, restore, create with and without the OTP, the vault
    /// empty, with a shown entry and syncing (each pill word), edit,
    /// password change, OTP backup with and without the QR.
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
            ] {
                app.screen = screen;
                app.build();
                visit(&mut app, name);
            }
            app.provision = Some(Provision::new().unwrap());
            for otp in [false, true] {
                app.screen = Screen::Create;
                app.create_otp = otp;
                app.build();
                visit(&mut app, if otp { "create-otp" } else { "create" });
            }
            app.provision = None;
            app.screen = Screen::Vault;
            app.session = Some(session);
            app.build();
            visit(&mut app, "vault-empty");
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
            for (screen, name) in [
                (Screen::Edit, "edit"),
                (Screen::Password, "password"),
                (Screen::OtpBackup, "otp-backup"),
            ] {
                app.screen = screen;
                app.build();
                visit(&mut app, name);
            }
            app.otp_setup = Some(
                app.session
                    .as_ref()
                    .unwrap()
                    .otp_setup("synthetic layout password")
                    .unwrap(),
            );
            app.build();
            visit(&mut app, "otp-backup-qr");
            app.otp_setup = None;
            drop(app);
            DestroyWindow(h);
        }
    }
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "goyo-{name}-{:x}",
            u64::from_le_bytes(*crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }
    /// Every label's text fits its box at this machine's DPI, in both
    /// languages: a STATIC clips whatever does not fit and an owner-drawn
    /// button cuts its caption, so a cut-off line would go unnoticed. Labels
    /// on the OTP card end clear of its painted border, and every message
    /// fits the status line.
    #[test]
    fn labels_fit_their_boxes() {
        let _korean = KoreanAfter;
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
                            theme::PRIMARY | theme::ACCENT | theme::TAB_ON => t.strong(),
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
                    let card =
                        (app.provision.is_some() && app.create_otp) || app.otp_setup.is_some();
                    if card {
                        let (x, y, w, h) = app.enroll();
                        let frame = app.r(x, y, w, h);
                        let mut r = Rect::default();
                        GetWindowRect(child, &mut r);
                        let mut pts = [
                            Point {
                                x: r.left,
                                y: r.top,
                            },
                            Point {
                                x: r.right,
                                y: r.bottom,
                            },
                        ];
                        MapWindowPoints(0, app.hwnd, pts.as_mut_ptr(), 2);
                        let inside = pts[0].y >= frame.top && pts[0].y < frame.bottom;
                        if inside && pts[1].y > frame.bottom - app.px(8) {
                            failures.push(format!(
                                "{language} {name}: touches the card border: {text:?}"
                            ));
                        }
                    }
                }
                // Every one-line message in the status line.
                if name == "vault-empty" {
                    let status = app.handle(STATUS);
                    let font = SendMessageW(status, 0x31, 0, 0);
                    let mut r = Rect::default();
                    GetClientRect(status, &mut r);
                    for &(ko, _) in i18n::EN {
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
                    // Sync notices filled with their longest values.
                    for notice in sync_notices() {
                        let (line, _) = sync_line(&notice);
                        let text = tr(&line);
                        let need = measure(status, font, text, r.right, 0x10 | 0x40).bottom;
                        if need > r.bottom {
                            failures.push(format!(
                                "{language} status: needs {need}px, has {}px: {text:?}",
                                r.bottom
                            ));
                        }
                    }
                }
            };
            unsafe { each_screen(&dir, &mut check) };
            let _ = std::fs::remove_dir_all(&dir);
        }
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
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
        let _korean = KoreanAfter;
        let main = include_str!("main.rs");
        let main = &main[..main.find("#[cfg(test)]\nmod tests").unwrap()];
        let (mut missing, mut scanned) = (vec![], vec![]);
        for source in [
            main,
            include_str!("win.rs"),
            include_str!("theme.rs"),
            include_str!("vault.rs"),
            include_str!("crypto.rs"),
            include_str!("otp.rs"),
            // goyo-sync's settings window draws with this app's i18n.rs.
            include_str!("bin/goyo-sync/gui.rs"),
        ] {
            // Up to the test modules: a test-only item among the program's
            // own (ANSWER here, PAINTED in theme.rs) must not end the scan.
            let code = source.split("#[cfg(test)]\nmod ").next().unwrap();
            for text in korean_literals(code) {
                if !i18n::EN.iter().any(|(ko, _)| *ko == text)
                    && !i18n::KEEP.contains(&text.as_str())
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
        for (ko, en) in i18n::EN {
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
        // Sync notices are filled from their English templates.
        for notice in sync_notices() {
            let (line, _) = sync_line(&notice);
            let text = tr(&line);
            assert!(!has_korean(text), "Korean in English mode: {text:?}");
        }
    }
    /// Switching the language keeps what was typed and the screen's state.
    #[test]
    fn language_switch_keeps_input() {
        let _korean = KoreanAfter;
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
            let code = app.provision.as_ref().unwrap().setup_code();
            SetWindowTextW(app.handle(PASS), wide("synthetic switch password").as_ptr());
            app.command(LANG_EN, 0).unwrap();
            assert!(i18n::english() && app.screen == Screen::Create);
            assert_eq!(caption(app.handle(SUBMIT)), "Create vault without OTP");
            assert_eq!(&*app.read(PASS).unwrap(), "synthetic switch password");
            assert_eq!(app.provision.as_ref().unwrap().setup_code(), code);
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
    /// Synthetic vault on disk with a fresh OTP code that opens it.
    fn synthetic_session(dir: &std::path::Path, password: &str) -> Session {
        let provision = Provision::new().unwrap();
        let secret = base32_decode(&provision.setup_code());
        let now = goyo_vault::otp::now().unwrap();
        let code = format!("{:06}", goyo_vault::otp::code(&secret, now / 30, 6));
        provision
            .finish(
                &dir.join("vault.goyo"),
                &dir.join("vault.goyokey"),
                password,
                Some(&code),
            )
            .unwrap()
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
                None,
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
        drop(Session::restore(&fetched, &key, &vault, SYNC_PASSWORD, "").unwrap());
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
        let _korean = KoreanAfter;
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
        for english in [false, true] {
            i18n::set_english(english);
            for notice in sync_notices() {
                let (line, _) = sync_line(&notice);
                for warning in [Placement::SameFolder, Placement::Cloud] {
                    let both = joined(&[&line, warning.message()]);
                    assert_eq!(both.capacity(), both.len());
                    let shown = tr_lines(&both);
                    assert_eq!(shown.capacity(), shown.len());
                    assert_eq!(shown.split("\r\n").nth(1), Some(tr(warning.message())));
                }
            }
        }
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
        ]
    }
    fn base32_decode(s: &str) -> Vec<u8> {
        let (mut acc, mut bits, mut out) = (0u32, 0u32, vec![]);
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => continue,
            } as u32;
            acc = (acc << 5) | v;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }
    /// The OTP is optional and off by default. Switching it keeps the typed
    /// passwords and the enrollment secret; a vault made without it opens
    /// with the password alone and offers no OTP backup. A key file that uses
    /// an OTP, typed in by path, gets the OTP field instead of a failed login.
    #[test]
    fn optional_otp_create_and_open() {
        let dir = std::env::temp_dir().join(format!(
            "goyo-optional-otp-{:x}",
            u64::from_le_bytes(*crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        let pass = "synthetic optional otp passphrase";
        unsafe {
            SetProcessDPIAware();
            let h = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                wide("Goyo optional OTP test").as_ptr(),
                0x00ca0000,
                0,
                0,
                900,
                800,
                0,
                0,
                GetModuleHandleW(null()),
                null_mut(),
            );
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.home_dir = dir.clone();
            app.vault_path = dir.join("vault.goyo");
            app.key_path = dir.join("vault.goyokey");
            app.screen = app.home();
            app.build();
            app.command(CREATE, 0).unwrap();
            assert!(app.screen == Screen::Create && !app.create_otp);
            assert_eq!(app.handle(OTP), 0);
            // Off, but offered as the recommended choice.
            assert_eq!(
                GetWindowLongPtrW(app.handle(OTP_TOGGLE), -21),
                theme::ACCENT
            );
            let code = app.provision.as_ref().unwrap().setup_code();
            for id in [PASS, CONFIRM] {
                SetWindowTextW(app.handle(id), wide(pass).as_ptr());
            }
            app.command(OTP_TOGGLE, 0).unwrap();
            assert!(app.create_otp && app.handle(OTP) != 0);
            assert_eq!(GetFocus(), app.handle(OTP));
            assert_eq!(app.provision.as_ref().unwrap().setup_code(), code);
            app.command(OTP_TOGGLE, 0).unwrap();
            assert!(!app.create_otp && app.handle(OTP) == 0);
            for id in [PASS, CONFIRM] {
                assert_eq!(&*app.read(id).unwrap(), pass);
            }
            assert_eq!(app.provision.as_ref().unwrap().setup_code(), code);
            app.command(SUBMIT, 0).unwrap();
            assert!(app.screen == Screen::Vault);
            assert!(!app.session.as_ref().unwrap().uses_otp());
            assert_eq!(app.handle(OTP_SETUP), 0);
            assert!(!app.allows(OTP_SETUP));
            app.command(CHANGE, 0).unwrap();
            assert!(app.screen == Screen::Password && app.handle(OTP) == 0);
            app.command(CANCEL, 0).unwrap();
            // Opens again with the password alone.
            app.lock("synthetic lock", true);
            assert!(app.screen == Screen::Login && app.handle(OTP) == 0);
            SetWindowTextW(app.handle(PASS), wide(pass).as_ptr());
            app.command(SUBMIT, 0).unwrap();
            assert!(app.session.is_some());
            app.lock("synthetic lock", true);
            // An OTP vault chosen by typing its paths: the first try asks for
            // the code, keeps the password and is not a failed attempt.
            let other = dir.join("otp");
            std::fs::create_dir(&other).unwrap();
            drop(synthetic_session(&other, pass));
            let other_vault = wide(&other.join("vault.goyo").to_string_lossy());
            let other_key = wide(&other.join("vault.goyokey").to_string_lossy());
            SetWindowTextW(app.handle(VPATH), other_vault.as_ptr());
            SetWindowTextW(app.handle(KPATH), other_key.as_ptr());
            SetWindowTextW(app.handle(PASS), wide(pass).as_ptr());
            assert!(app.command(SUBMIT, 0).unwrap_err().contains("OTP"));
            assert!(app.handle(OTP) != 0 && app.failed == 0);
            assert_eq!(&*app.read(PASS).unwrap(), pass);
            assert!(app.session.is_none());
            drop(app);
            DestroyWindow(h);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn otp_backup_needs_password_and_closes_with_lock() {
        let dir = std::env::temp_dir().join(format!(
            "goyo-otp-backup-{:x}",
            u64::from_le_bytes(*crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        let session = synthetic_session(&dir, "synthetic backup password");
        unsafe {
            SetProcessDPIAware();
            let h = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                wide("Goyo OTP backup test").as_ptr(),
                0x00ca0000,
                0,
                0,
                900,
                800,
                0,
                0,
                GetModuleHandleW(null()),
                null_mut(),
            );
            assert_ne!(h, 0);
            assert_ne!(SetWindowDisplayAffinity(h, 0x11), 0);
            let mut app = App::new(h);
            app.vault_path = session.path.clone();
            app.session = Some(session);
            app.screen = Screen::Vault;
            app.build();
            app.command(OTP_SETUP, 0).unwrap();
            assert!(app.screen == Screen::OtpBackup && app.otp_setup.is_none());
            // Wrong password: nothing shown, and the retry delay applies.
            SetWindowTextW(
                app.handle(CURRENT_PASS),
                wide("wrong synthetic pass").as_ptr(),
            );
            assert!(app.command(SUBMIT, 0).is_err());
            assert!(app.otp_setup.is_none() && app.failed == 1);
            assert!(app.command(SUBMIT, 0).is_err()); // still waiting
            app.retry = Instant::now();
            SetWindowTextW(
                app.handle(CURRENT_PASS),
                wide("synthetic backup password").as_ptr(),
            );
            app.command(SUBMIT, 0).unwrap();
            assert!(app.otp_setup.is_some() && app.failed == 0);
            app.command(CANCEL, 0).unwrap();
            assert!(app.screen == Screen::Vault && app.otp_setup.is_none());
            // Shown again, then another app takes focus: the vault locks.
            app.command(OTP_SETUP, 0).unwrap();
            SetWindowTextW(
                app.handle(CURRENT_PASS),
                wide("synthetic backup password").as_ptr(),
            );
            app.command(SUBMIT, 0).unwrap();
            assert!(app.otp_setup.is_some());
            app.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            app.copy_until = Some(Instant::now() + Duration::from_secs(30));
            app.deactivated();
            assert!(app.session.is_some() && app.screen == Screen::Vault);
            assert!(app.otp_setup.is_none() && app.reveal_until.is_none());
            assert!(app.copy_until.is_none());
            // Back within AWAY_LOCK: still open.
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
            app.timer();
            assert!(app.session.is_none() && app.away_since.is_none());
            assert!(app.screen == Screen::Login);
            drop(app);
            DestroyWindow(h);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The auto-lock switch on the vault screen. Longer choices count time in
    /// another app as unused time; "끔" keeps the vault open on the timer, but
    /// the OTP backup QR still closes after OTP_QR_IDLE.
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
            // The OTP backup QR closes on its own time; the vault stays open.
            // Leaving the app would close it at once, so the timer must see an
            // app switch that has already been handled and just begun.
            let just_left = |app: &mut App| {
                app.inactive = true;
                app.away_since = Some(Instant::now());
            };
            app.otp_setup = Some(app.session.as_ref().unwrap().otp_setup(pass).unwrap());
            app.screen = Screen::OtpBackup;
            app.build();
            just_left(&mut app);
            app.activity = Instant::now() - OTP_QR_IDLE - Duration::from_secs(1);
            app.timer();
            assert!(app.otp_setup.is_none() && app.screen == Screen::Vault);
            assert!(app.session.is_some());
            // Shortest choice: the QR screen locks the vault after OTP_QR_IDLE.
            app.command(AUTO_LOCK, 0).unwrap();
            app.otp_setup = Some(app.session.as_ref().unwrap().otp_setup(pass).unwrap());
            app.screen = Screen::OtpBackup;
            app.build();
            just_left(&mut app);
            app.activity = Instant::now() - Duration::from_secs(61);
            app.timer();
            assert!(app.session.is_some() && app.otp_setup.is_some());
            app.activity = Instant::now() - OTP_QR_IDLE - Duration::from_secs(1);
            app.timer();
            assert!(app.session.is_none() && app.otp_setup.is_none());
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
            // Create keeps one OTP secret across Back and a second visit.
            app.command(CREATE, 0).unwrap();
            let code = app.provision.as_ref().unwrap().setup_code();
            app.command(BACK, 0).unwrap();
            app.command(CREATE, 0).unwrap();
            assert_eq!(app.provision.as_ref().unwrap().setup_code(), code);
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
            // Switching apps mid-enrollment keeps the new vault form and its
            // OTP secret; only the shown password is masked again.
            app.screen = Screen::Create;
            app.provision = Some(Provision::new().unwrap());
            app.build();
            let code = app.provision.as_ref().unwrap().setup_code();
            SetWindowTextW(app.handle(PASS), wide("synthetic enrollment").as_ptr());
            app.command(PEEK_PASS, 0).unwrap();
            app.deactivated();
            assert!(app.screen == Screen::Create);
            assert_eq!(app.provision.as_ref().unwrap().setup_code(), code);
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
                Screen::OtpBackup,
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
        let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-output/ui-preview");
        std::fs::create_dir_all(&out).unwrap();
        // GOYO_PREVIEW_LANG=en renders the English interface to en-*.bmp.
        let english = std::env::var("GOYO_PREVIEW_LANG").is_ok_and(|v| v == "en");
        let _korean = KoreanAfter;
        i18n::set_english(english);
        let pick = |ko: &'static str, en: &'static str| if english { en } else { ko };
        let temp = std::env::temp_dir().join(format!(
            "goyo-preview-{:x}",
            u64::from_le_bytes(*crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir(&temp).unwrap();
        let provision = Provision::new().unwrap();
        let secret = base32_decode(&provision.setup_code());
        let now = goyo_vault::otp::now().unwrap();
        let code = format!("{:06}", goyo_vault::otp::code(&secret, now / 30, 6));
        let mut session = provision
            .finish(
                &temp.join("vault.goyo"),
                &temp.join("vault.goyokey"),
                "synthetic preview password",
                Some(&code),
            )
            .unwrap();
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
                "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual",
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
            let shots = [
                ("0-welcome", Screen::Welcome),
                ("1-login", Screen::Login),
                ("2-create", Screen::Create),
                ("2-create-otp", Screen::Create),
                ("3-restore", Screen::Restore),
                ("4-vault", Screen::Vault),
                ("5-vault-selected", Screen::Vault),
                ("6-vault-revealed", Screen::Vault),
                ("7-edit", Screen::Edit),
                ("8-new", Screen::Edit),
                ("9-password", Screen::Password),
                ("10-otp-backup", Screen::OtpBackup),
            ];
            for (dark, (file, screen)) in [true, false]
                .into_iter()
                .flat_map(|dark| shots.map(|s| (dark, s)))
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
                    a.create_otp = file.ends_with("2-create-otp");
                    if screen == Screen::Vault && a.session.is_none() {
                        a.session = session.take();
                    }
                    // "동기화됨" (checked above) however long the shots take:
                    // the helper's heartbeat would grow stale meanwhile.
                    a.sync_badge = a.session.as_ref().map(|_| SyncBadge::Synced);
                    a.selected = if file.ends_with("5-vault-selected") {
                        Some(0)
                    } else if file.ends_with("6-vault-revealed") {
                        Some(1)
                    } else {
                        None
                    };
                    a.editing = file.ends_with("7-edit").then_some(2);
                    a.otp_setup = file.ends_with("10-otp-backup").then(|| {
                        let s = a.session.as_ref().unwrap();
                        s.otp_setup("synthetic preview password").unwrap()
                    });
                    if file.ends_with("6-vault-revealed") {
                        a.reveal_until = Some(Instant::now() + Duration::from_secs(15));
                    }
                    a.build();
                    if file.ends_with("6-vault-revealed") {
                        a.copy_until = Some(Instant::now() + Duration::from_secs(30));
                        a.set_toggle(true);
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
        let _korean = KoreanAfter;
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
        let dir = test_dir("sync-offer");
        let (vault, key) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
        let mut s = Provision::new()
            .unwrap()
            .finish(&vault, &key, SYNC_PASSWORD, None)
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
    /// DELETE removes the entry the user confirmed, found by its ID after
    /// the question, even if the list moved meanwhile; one deleted on the
    /// other PC meanwhile is not replaced by its neighbour. Sync adds no
    /// command: what each screen accepts is as before.
    #[test]
    fn delete_finds_the_entry_by_id() {
        let always = [THEME_DARK, THEME_LIGHT, LANG_KO, LANG_EN];
        let commands = |app: &App, ids: &[i32]| {
            let mut want: Vec<i32> = ids.iter().chain(&always).copied().collect();
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
                    PEEK_PASS, OTP,
                ],
            ),
            (
                Screen::Create,
                &[
                    BACK,
                    SUBMIT,
                    OTP_TOGGLE,
                    BROWSE_V,
                    BROWSE_K,
                    VPATH,
                    KPATH,
                    PASS,
                    CONFIRM,
                    PEEK_PASS,
                    PEEK_CONFIRM,
                    OTP,
                ],
            ),
            (
                Screen::Restore,
                &[
                    BACK, SUBMIT, BROWSE_V, BROWSE_K, BROWSE_D, VPATH, KPATH, DEST, PASS,
                    PEEK_PASS, OTP,
                ],
            ),
        ] {
            app.screen = screen;
            commands(&app, ids);
        }
        for screen in [
            Screen::Vault,
            Screen::Edit,
            Screen::Password,
            Screen::OtpBackup,
        ] {
            app.screen = screen;
            assert!((0..=400).all(|id| !app.allows(id)), "no vault open");
        }
        app.session = Some(synthetic_session(&dir, "synthetic allows password"));
        let auto_lock: Vec<i32> = (AUTO_LOCK..=AUTO_LOCK_LAST).collect();
        let presets: Vec<i32> = (PRESET..=PRESET_LAST).collect();
        let vault = [
            LOCK, BACKUP, KEYBACKUP, CHANGE, OTP_SETUP, LIST, NEW, EDIT, DELETE, REVEAL, TOGGLE,
            COPY, PREVIOUS, NEXT,
        ];
        let edit = [TITLE, KIND, SECRET, NOTES, SAVE, CANCEL];
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
                    OTP,
                    SUBMIT,
                    CANCEL,
                ],
            ),
            (
                Screen::OtpBackup,
                vec![CURRENT_PASS, PEEK_CURRENT, SUBMIT, CANCEL],
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
        let b = Session::unlock(&vault, &key, SYNC_PASSWORD, "").unwrap();
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
}
