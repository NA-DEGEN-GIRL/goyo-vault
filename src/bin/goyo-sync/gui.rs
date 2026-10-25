//! The settings window of goyo-sync.exe (started without arguments): the
//! server, the vaults to sync and the background helper on one fixed-size
//! window in Goyo Vault's look. It draws with the vault app's palette, fonts
//! and owner-drawn controls (theme.rs), uses its Win32 bindings, file
//! dialogs and guarded yes/no boxes (win.rs) and its translations (i18n.rs:
//! Korean source text, English entries). Dark or light follows
//! goyo-vault.theme and Korean or English goyo-vault.lang next to the exe,
//! also while the window is open.
//!
//! The window never waits for ssh: a worker thread runs each job (setup.rs)
//! and leaves its result in a slot of this process, then posts a bare
//! private message, so no other program can hand the window a result. Like
//! the vault's window it ignores commands, clicks and input sent from other
//! threads; its inputs and lists ignore everything sent from them; and its
//! message loop, and a queue filter inside dialogs, drops posted commands,
//! button clicks and edit or list operations aimed at its windows. It reads
//! goyo-sync.conf, the helper's status files and goyo-sync.log; it never
//! opens a vault or key file: paths come from file dialogs only, and whether
//! a vault exists is read from its folder's listing.
use crate::{
    CONFIG, ERROR, OK,
    config::{self, Config, Problem},
    engine::{Folder, Log, Outcome, tag, utc},
    i18n::{self, fill, tr},
    setup::{
        self, Bad, Cause, Checked, Field, Fields, Got, Installed, KeyStep, Known, Live, MakeRunner,
        Restarted, Runner, SshRunner, System, Trouble, Trusted, Why, Windows,
    },
    sys,
    theme::{self, LINE, TONE_DANGER, TONE_MUTED, TONE_TEXT},
    win::*,
};
use goyo_vault::{
    syncfile::{self, SyncState},
    syncwire::ListEntry,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        Arc, Mutex, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[link(name = "user32")]
unsafe extern "system" {
    fn SetWindowPos(h: Hwnd, after: Hwnd, x: i32, y: i32, w: i32, h2: i32, flags: u32) -> i32;
    fn AdjustWindowRectEx(r: *mut Rect, style: u32, menu: i32, ex: u32) -> i32;
    fn FindWindowW(class: *const u16, title: *const u16) -> Hwnd;
    fn SetForegroundWindow(h: Hwnd) -> i32;
    fn IsIconic(h: Hwnd) -> i32;
    fn MonitorFromWindow(h: Hwnd, flags: u32) -> isize;
    fn GetMonitorInfoW(monitor: isize, info: *mut MonitorInfo) -> i32;
}
#[repr(C)]
#[derive(Default)]
struct MonitorInfo {
    size: u32,
    _monitor: Rect,
    work: Rect,
    _flags: u32,
}

const TITLE: &str = "고요 금고 동기화";
// Inputs, lists and lines.
const HOST: i32 = 201;
const REMOTE: i32 = 202;
const PYTHON: i32 = 203;
const IDENTITY: i32 = 204;
const INTERVAL: i32 = 205;
const TIMEOUT: i32 = 206;
const VAULT_LIST: i32 = 210;
const SERVER_LIST: i32 = 211;
const LOG_VIEW: i32 = 212;
const SERVER_LINE: i32 = 301;
const RUN_LINE: i32 = 302;
// Buttons.
const CHECK: i32 = 101;
const INSTALL: i32 = 102;
const ADVANCED: i32 = 103;
const BROWSE_KEY: i32 = 104;
const ADD: i32 = 105;
const REMOVE: i32 = 106;
const FETCH: i32 = 107;
const AUTOSTART: i32 = 108;
const SAVE: i32 = 109;
const SYNC: i32 = 110;
const STOP: i32 = 111;
const LOG: i32 = 112;
const CLOSE: i32 = 113;
const REFRESH: i32 = 114;
const TAKE: i32 = 115;
/// IDCANCEL: Esc in the log and server-list views.
const ESCAPE: i32 = 2;
/// A worker finished; the result waits in [`DONE`].
const WM_DONE: u32 = 0x8001;
const TIMER: usize = 1;
/// The running pill and the vault rows are refreshed this often.
const TICK: u32 = 2000;
/// Lines of goyo-sync.log in the log view.
const LOG_LINES: usize = 400;
/// A "sync now" result stays on its row this long.
const RESULT_SHOWN: Duration = Duration::from_secs(60);

// Layout in 96-DPI units: one column of cards, as wide as the vault app.
const W: i32 = 876;
const X: i32 = 40;
const CW: i32 = W - 2 * X;
const IX: i32 = X + 20;
const IW: i32 = CW - 40;
/// Top of the first card, below the title.
const S: i32 = 64;
const CHECK_W: i32 = 148;
const INSTALL_W: i32 = 220;
const HOST_W: i32 = IW - CHECK_W - INSTALL_W - 16;
const ROW: i32 = 44;
const STYLE: u32 = 0x00ca_0000 | 0x0200_0000; // fixed caption window, WS_CLIPCHILDREN

fn server_bottom(advanced: bool) -> i32 {
    S + if advanced { 310 } else { 170 }
}
fn vault_top(advanced: bool) -> i32 {
    server_bottom(advanced) + 10
}
fn run_top(advanced: bool) -> i32 {
    vault_top(advanced) + 210
}
fn client_height(advanced: bool) -> i32 {
    run_top(advanced) + 164
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    /// What each list row shows: [vaults, server list]. Owner-draw reads it
    /// without borrowing APP.
    static ROWS: RefCell<[Vec<RowView>; 2]> = const { RefCell::new([Vec::new(), Vec::new()]) };
    static FILTERED: Cell<Hwnd> = const { Cell::new(0) };
}
static EDIT_PROC: OnceLock<Proc> = OnceLock::new();
static LIST_PROC: OnceLock<Proc> = OnceLock::new();
/// Finished jobs' results: the window they belong to, the job's number and
/// the result. Only this process's worker threads add to it; WM_DONE
/// carries nothing.
static DONE: Mutex<Vec<(Hwnd, u32, Done)>> = Mutex::new(Vec::new());

#[cfg(test)]
thread_local! {
    /// Answers for the next yes/no boxes and file dialogs, given by a test;
    /// no test shows a real dialog. What would have been shown is kept.
    static ANSWERS: RefCell<std::collections::VecDeque<bool>> = RefCell::default();
    static PICKS: RefCell<std::collections::VecDeque<Option<PathBuf>>> = RefCell::default();
    static ASKED: RefCell<Vec<String>> = RefCell::default();
    static TOLD: RefCell<Vec<String>> = RefCell::default();
}
/// A guarded yes/no box (win::confirm_in): only the user can answer it.
#[cfg(not(test))]
fn ask(h: Hwnd, text: &str) -> bool {
    confirm_in(h, text, TITLE)
}
#[cfg(test)]
fn ask(_: Hwnd, text: &str) -> bool {
    ASKED.with(|a| a.borrow_mut().push(text.to_owned()));
    modal(|| ANSWERS.with(|a| a.borrow_mut().pop_front().unwrap_or(false)))
}
#[cfg(not(test))]
fn tell(h: Hwnd, text: &str) {
    message_in(h, text, TITLE);
}
#[cfg(test)]
fn tell(_: Hwnd, text: &str) {
    TOLD.with(|t| t.borrow_mut().push(text.to_owned()));
}
/// The file dialog an [`Ask`] needs; the only source of paths.
#[cfg(not(test))]
fn pick(h: Hwnd, what: &Ask) -> Option<PathBuf> {
    match what {
        Ask::Key => pick_file(
            h,
            false,
            "SSH 개인 키 (모든 파일)\0*.*\0",
            "",
            "전용 SSH 키 파일 선택",
            None,
        ),
        Ask::Fetch(_, default) => pick_file(
            h,
            true,
            "고요 금고/백업 (*.goyo)\0*.goyo\0모든 파일\0*.*\0",
            "goyo",
            "새 파일 이름을 선택하세요 (기존 파일 덮어쓰기 금지)",
            Some(default.as_path()),
        ),
        _ => dialog(h, false, false),
    }
}
#[cfg(test)]
fn pick(_: Hwnd, _: &Ask) -> Option<PathBuf> {
    PICKS.with(|p| p.borrow_mut().pop_front().flatten())
}

/// What the worker thread runs.
enum Job {
    Check(Config),
    Trust(Config),
    Install(Config),
    List(Config),
    Fetch(Config, [u8; 16], PathBuf),
    Sync(Config),
    Restart,
}
impl Job {
    fn kind(&self) -> Kind {
        match self {
            Job::Check(_) => Kind::Check,
            Job::Trust(_) => Kind::Trust,
            Job::Install(_) => Kind::Install,
            Job::List(_) => Kind::List,
            Job::Fetch(..) => Kind::Fetch,
            Job::Sync(_) => Kind::Sync,
            Job::Restart => Kind::Restart,
        }
    }
    fn run(self, runner: &mut dyn Runner, system: &dyn System, log: &Log) -> Done {
        match self {
            Job::Check(c) => Done::Checked(setup::check(runner, log, &c), c),
            Job::Trust(c) => Done::Trusted(setup::trust(runner, log, &c), c),
            Job::Install(c) => Done::Installed(setup::install(runner, log, &c)),
            Job::List(c) => Done::Listed(setup::list(runner, log, &c), c),
            Job::Fetch(c, id, path) => {
                let got = setup::fetch(runner, log, &c, id, &path);
                Done::Got(got, path)
            }
            Job::Sync(c) => Done::Synced(setup::sync_now(runner, log, &c), c.vaults),
            Job::Restart => Done::Restarted(setup::restart(system, Duration::from_millis(100))),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Check,
    Trust,
    Install,
    List,
    Fetch,
    Sync,
    Restart,
}
impl Kind {
    /// The run card shows these; the server card the rest.
    fn on_run_line(self) -> bool {
        matches!(self, Kind::Sync | Kind::Restart)
    }
}
/// A job's result, handed back to the window.
enum Done {
    Checked(Checked, Config),
    Trusted(Trusted, Config),
    Installed(Installed),
    Listed(Result<Vec<ListEntry>, Checked>, Config),
    Got(Got, PathBuf),
    Synced(Vec<Outcome>, Vec<PathBuf>),
    Restarted(Restarted),
}
struct Busy {
    seq: u32,
    kind: Kind,
    since: Instant,
}

/// A dialog the window needs; it runs while APP is not borrowed, since
/// dialogs pump messages (the timer, paint and worker results go on).
#[derive(Clone, Debug, PartialEq)]
enum Ask {
    /// Open a vault file to add.
    Vault,
    /// Open the dedicated SSH key.
    Key,
    Install(Config),
    Trust(Config, String),
    /// Save a server version as a new file (suggested name).
    Fetch([u8; 16], PathBuf),
    /// Close with unsaved changes?
    Close,
    Tell(String),
    Quit,
}
enum Answer {
    Path(Option<PathBuf>),
    Yes(bool),
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Screen {
    Main,
    Log,
    /// The server's vaults, to get one.
    Server,
}
/// A line under a card: what the last action did, or the default.
#[derive(Clone, Debug, PartialEq)]
enum Note {
    // The server card.
    Intro,
    Busy(Kind, u64),
    Bad(Bad),
    CheckOk(usize),
    Trouble(Trouble),
    Key(KeyStep),
    TrustDeclined,
    Installed,
    NotPass {
        line: String,
        cause: Cause,
        noisy: bool,
    },
    Unsafe,
    ServerEmpty,
    Got {
        version: u64,
        bytes: usize,
    },
    GotExists,
    GotMissing,
    GotWrite,
    // The run card.
    Idle,
    Damaged(usize),
    Restart(Restarted),
    SaveFailed,
    AutostartFailed(i32),
    Synced {
        ok: usize,
        failed: usize,
    },
    Stopped(bool),
    Added,
    Removed,
    VaultRefused(Why),
    KeyRefused,
    PickFirst,
    AutostartOff,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tone {
    Good,
    Muted,
    Faint,
    Danger,
}
/// One painted list row.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RowView {
    title: String,
    detail: String,
    state: String,
    tone: Tone,
}
struct Row {
    path: PathBuf,
    live: Live,
    /// The last "sync now" result, shown for a minute.
    result: Option<(Instant, Outcome)>,
}

struct App {
    hwnd: Hwnd,
    scale: f32,
    /// Consolas for the log view (owned).
    mono: isize,
    controls: BTreeMap<i32, Hwnd>,
    children: Vec<Hwnd>,
    /// Painted outlines around borderless inputs and lists: (96-DPI rect, id).
    frames: Vec<(Rect, i32)>,
    /// A control could not be made (the self-check fails then).
    broken: bool,
    screen: Screen,
    /// The exe's folder: goyo-sync.conf, goyo-sync.log, goyo-vault.theme/lang.
    dir: PathBuf,
    log: Log,
    fields: Fields,
    /// What goyo-sync.conf holds; None without a valid file.
    saved: Option<Fields>,
    advanced: bool,
    autostart: bool,
    autostart_saved: bool,
    running: bool,
    rows: Vec<Row>,
    selected: Option<usize>,
    server_note: Note,
    run_note: Note,
    /// The input shown in red.
    bad: Option<Field>,
    busy: Option<Busy>,
    seq: u32,
    /// The server list, and the settings it came from (for the fetch).
    listing: Vec<ListEntry>,
    listed: Option<Config>,
    picked: Option<usize>,
    autostart_error: Option<i32>,
    system: Arc<dyn System>,
    runner: MakeRunner,
    /// Kills a running ssh when the window closes.
    cancel: Arc<AtomicBool>,
    /// The worker threads, so the process waits for a job (above all a
    /// restart of the background helper) before it ends.
    workers: Vec<std::thread::JoinHandle<()>>,
}
impl App {
    fn new(
        hwnd: Hwnd,
        dir: PathBuf,
        log: Log,
        system: Arc<dyn System>,
        runner: MakeRunner,
        cancel: Arc<AtomicBool>,
    ) -> Self {
        let scale = theme::with(|t| t.scale).unwrap_or(1.0);
        let mono = unsafe {
            CreateFontW(
                -(13.0 * scale) as i32,
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                1,
                0,
                0,
                5,
                0,
                wide("Consolas").as_ptr(),
            )
        };
        let read = config::read(&dir.join(CONFIG));
        let first = read.as_ref().is_err_and(|e| e.problem == Problem::Missing);
        let (fields, saved, run_note) = match read {
            Ok(text) => match config::parse(&text) {
                Ok(c) => {
                    let f = Fields::from_config(&c);
                    (f.clone(), Some(f), Note::Idle)
                }
                Err(e) => (Fields::from_text(&text), None, Note::Damaged(e.line)),
            },
            Err(_) if first => (Fields::default(), None, Note::Idle),
            Err(_) => (Fields::default(), None, Note::Damaged(0)),
        };
        let autostart_saved = system.autostart();
        let mut app = Self {
            hwnd,
            scale,
            mono,
            controls: BTreeMap::new(),
            children: Vec::new(),
            frames: Vec::new(),
            broken: false,
            screen: Screen::Main,
            log,
            fields,
            // Sync is meant to keep going after a restart: on for a first
            // setup, otherwise as the Run value says.
            autostart: autostart_saved || first,
            autostart_saved,
            saved,
            advanced: false,
            running: system.running(),
            rows: Vec::new(),
            selected: None,
            server_note: Note::Intro,
            run_note,
            bad: None,
            busy: None,
            seq: 0,
            listing: Vec::new(),
            listed: None,
            picked: None,
            autostart_error: None,
            system,
            runner,
            cancel,
            workers: Vec::new(),
            dir,
        };
        let beside = app.dir.join("vault.goyo");
        if app.fields.vaults.is_empty() && crate::engine::listed(&beside) {
            app.fields.vaults.push(beside);
        }
        app.rows = app.fields.vaults.iter().map(|p| Row::new(p)).collect();
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
    fn font(pick: fn(&theme::Theme) -> isize) -> isize {
        theme::with(pick).unwrap_or(0)
    }
    fn handle(&self, id: i32) -> Hwnd {
        *self.controls.get(&id).unwrap_or(&0)
    }

    // ---- controls ----

    fn ctrl(
        &mut self,
        id: i32,
        class: &str,
        text: &str,
        r: (i32, i32, i32, i32),
        style: u32,
    ) -> Hwnd {
        let (x, y, w, h) = r;
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                wide(class).as_ptr(),
                wide(if class == "EDIT" { text } else { tr(text) }).as_ptr(),
                0x5000_0000 | style,
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
            self.broken = true;
            return 0;
        }
        unsafe {
            SendMessageW(hwnd, 0x30, Self::font(|t| t.body()) as usize, 0);
        }
        self.children.push(hwnd);
        if id != 0 {
            self.controls.insert(id, hwnd);
        }
        hwnd
    }
    /// Static text; `tone` (GWLP_USERDATA) picks its colour.
    fn text(
        &mut self,
        id: i32,
        text: &str,
        r: (i32, i32, i32, i32),
        font: isize,
        tone: isize,
    ) -> Hwnd {
        let h = self.ctrl(id, "STATIC", text, r, 0x80); // SS_NOPREFIX
        unsafe {
            SetWindowLongPtrW(h, -21, tone);
            SendMessageW(h, 0x30, font as usize, 0);
        }
        h
    }
    fn label(&mut self, text: &str, x: i32, y: i32, w: i32) {
        self.text(
            0,
            text,
            (x, y, w, 20),
            Self::font(|t| t.small()),
            TONE_MUTED,
        );
    }
    fn button(&mut self, id: i32, text: &str, r: (i32, i32, i32, i32), variant: isize) {
        // WS_TABSTOP | BS_OWNERDRAW; theme::draw_item paints the variant.
        let b = self.ctrl(id, "BUTTON", text, r, 0x10000 | 0xb);
        unsafe {
            SetWindowLongPtrW(b, -21, variant);
        }
    }
    /// A borderless edit in a painted frame; `reserve` keeps room on the
    /// right for a button inside the frame.
    fn input(&mut self, id: i32, text: &str, (x, y, w, h): (i32, i32, i32, i32), reserve: i32) {
        // WS_TABSTOP | ES_AUTOHSCROLL
        let edit = self.ctrl(
            id,
            "EDIT",
            "",
            (x + 12, y + (h - 24) / 2, w - 24 - reserve, 24),
            0x10000 | 0x80,
        );
        self.frames.push((
            Rect {
                left: x,
                top: y,
                right: x + w,
                bottom: y + h,
            },
            id,
        ));
        if edit == 0 {
            return;
        }
        let limit = match id {
            HOST => 320,
            REMOTE => 256,
            PYTHON => 64,
            INTERVAL | TIMEOUT => 5,
            _ => 1024,
        };
        unsafe {
            subclass(edit, &EDIT_PROC, edit_proc);
            SendMessageW(edit, 0xc5, limit, 0); // EM_SETLIMITTEXT
            SetWindowTextW(edit, wide(text).as_ptr());
        }
    }
    /// Caption above a 40px input.
    fn field(&mut self, id: i32, label: &str, value: &str, (x, y, w): (i32, i32, i32)) {
        self.label(label, x, y, w);
        self.input(id, value, (x, y + 22, w, 40), 0);
    }
    /// An owner-drawn list in a painted frame.
    fn list(&mut self, id: i32, (x, y, w, h): (i32, i32, i32, i32)) -> Hwnd {
        // WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT |
        // LBS_OWNERDRAWFIXED | LBS_HASSTRINGS
        let list = self.ctrl(
            id,
            "LISTBOX",
            "",
            (x + 4, y + 4, w - 8, h - 8),
            0x10000 | 0x20_0000 | 1 | 0x100 | 0x10 | 0x40,
        );
        self.frames.push((
            Rect {
                left: x,
                top: y,
                right: x + w,
                bottom: y + h,
            },
            id,
        ));
        if list != 0 {
            unsafe {
                subclass(list, &LIST_PROC, list_proc);
                SendMessageW(list, 0x1a0, 0, self.px(ROW) as isize); // LB_SETITEMHEIGHT
            }
        }
        list
    }
    /// The width a TOGGLE button needs for `text`, in 96-DPI units.
    fn toggle_width(&self, text: &str) -> i32 {
        let px = unsafe {
            let dc = GetDC(self.hwnd);
            let w = theme::text_width(dc, tr(text), Self::font(|t| t.body()));
            ReleaseDC(self.hwnd, dc);
            w
        };
        (px as f32 / self.scale).ceil() as i32 + 64
    }
    fn clear(&mut self) {
        for h in self.children.drain(..) {
            unsafe {
                DestroyWindow(h);
            }
        }
        self.controls.clear();
        self.frames.clear();
    }

    // ---- screens ----

    fn build(&mut self) {
        self.clear();
        match self.screen {
            Screen::Main => self.build_main(),
            Screen::Log => self.build_log(),
            Screen::Server => self.build_server(),
        }
        self.theme_scrollbars();
        self.enable();
        unsafe {
            InvalidateRect(self.hwnd, null(), 0);
        }
    }
    /// Native scrollbars follow the palette, as in the vault app.
    fn theme_scrollbars(&self) {
        let name = wide(if theme::is_dark() {
            "DarkMode_Explorer"
        } else {
            "Explorer"
        });
        for id in [VAULT_LIST, SERVER_LIST, LOG_VIEW] {
            let h = self.handle(id);
            if h != 0 {
                unsafe {
                    SetWindowTheme(h, name.as_ptr(), null());
                }
            }
        }
    }
    fn build_main(&mut self) {
        let (small, strong) = (Self::font(|t| t.small()), Self::font(|t| t.strong()));
        let adv = self.advanced;
        let f = self.fields.clone();
        // Server.
        self.text(
            0,
            "서버 (ssh 호스트)",
            (IX, S + 14, 400, 22),
            strong,
            TONE_TEXT,
        );
        let w = self.toggle_width("고급 설정");
        let variant = if adv { theme::TOGGLE_ON } else { theme::TOGGLE };
        self.button(ADVANCED, "고급 설정", (IX + IW - w, S + 8, w, 32), variant);
        self.input(HOST, &f.host, (IX, S + 40, HOST_W, 40), 0);
        self.button(
            CHECK,
            "연결 확인",
            (IX + HOST_W + 8, S + 40, CHECK_W, 40),
            theme::SECONDARY,
        );
        self.button(
            INSTALL,
            "서버에 설치·업데이트",
            (IX + HOST_W + CHECK_W + 16, S + 40, INSTALL_W, 40),
            theme::SECONDARY,
        );
        self.text(
            0,
            "~/.ssh/config의 별칭(예: my-server)이나 user@host를 적습니다. 집 밖에서는 ssh 포트를 인터넷에 열지 말고 Tailscale 같은 VPN으로 서버에 닿게 하세요.",
            (IX, S + 86, IW, 34),
            small,
            TONE_MUTED,
        );
        self.text(SERVER_LINE, "", (IX, S + 122, IW, 36), small, TONE_MUTED);
        if adv {
            let a = S + 166;
            self.field(REMOTE, "서버의 스크립트 경로", &f.remote, (IX, a, 420));
            self.field(PYTHON, "파이썬 명령", &f.python, (IX + 432, a, 156));
            self.field(INTERVAL, "간격(초)", &f.interval, (IX + 600, a, 72));
            self.field(TIMEOUT, "제한(초)", &f.timeout, (IX + 684, a, 72));
            self.label(
                "전용 SSH 키 파일 (선택) · 비우면 평소 ssh 설정을 씁니다",
                IX,
                a + 70,
                IW,
            );
            self.input(IDENTITY, &f.identity, (IX, a + 92, IW, 40), 64);
            self.button(
                BROWSE_KEY,
                "찾기",
                (IX + IW - 70, a + 96, 64, 32),
                theme::GHOST,
            );
        }
        // Vaults.
        let v = vault_top(adv);
        self.text(0, "금고", (IX, v + 16, 64, 22), strong, TONE_TEXT);
        self.text(
            0,
            "동기화할 금고 파일 · 최대 8개",
            (IX + 68, v + 19, 300, 18),
            small,
            TONE_MUTED,
        );
        let fetch_x = IX + IW - 168;
        self.button(
            FETCH,
            "서버에서 받기…",
            (fetch_x, v + 10, 168, 34),
            theme::SECONDARY,
        );
        self.button(
            REMOVE,
            "빼기",
            (fetch_x - 104, v + 10, 96, 34),
            theme::SECONDARY,
        );
        self.button(
            ADD,
            "추가…",
            (fetch_x - 208, v + 10, 96, 34),
            theme::SECONDARY,
        );
        if self.rows.is_empty() {
            self.frames.push((
                Rect {
                    left: IX,
                    top: v + 52,
                    right: IX + IW,
                    bottom: v + 196,
                },
                VAULT_LIST,
            ));
        } else {
            let list = self.list(VAULT_LIST, (IX, v + 52, IW, 144));
            for row in &self.rows {
                unsafe {
                    SendMessageW(
                        list,
                        0x180,
                        0,
                        wide(&row.path.to_string_lossy()).as_ptr() as isize,
                    );
                }
            }
            if let Some(i) = self.selected {
                unsafe {
                    SendMessageW(list, 0x186, i, 0);
                }
            }
        }
        self.show_rows();
        // Run.
        let r = run_top(adv);
        let label = "Windows에 로그인하면 자동으로 시작";
        let w = self.toggle_width(label);
        let variant = if self.autostart {
            theme::TOGGLE_ON
        } else {
            theme::TOGGLE
        };
        self.button(AUTOSTART, label, (IX, r + 12, w, 32), variant);
        self.button(SAVE, "저장하고 시작", (IX, r + 52, 168, 40), theme::PRIMARY);
        self.button(
            SYNC,
            "지금 동기화",
            (IX + 176, r + 52, 140, 40),
            theme::SECONDARY,
        );
        self.button(STOP, "중지", (IX + 324, r + 52, 92, 40), theme::SECONDARY);
        self.button(
            LOG,
            "로그 보기",
            (IX + IW - 124, r + 52, 124, 40),
            theme::GHOST,
        );
        self.text(RUN_LINE, "", (IX, r + 100, IW, 36), small, TONE_MUTED);
        self.show_notes();
    }
    fn build_log(&mut self) {
        let (small, strong) = (Self::font(|t| t.small()), Self::font(|t| t.strong()));
        let bottom = client_height(self.advanced) - 16;
        let lines = setup::log_tail(&self.dir, LOG_LINES);
        self.text(0, "로그", (IX, S + 16, 80, 22), strong, TONE_TEXT);
        self.text(
            0,
            &fill("goyo-sync.log의 최근 {}줄", &[&lines.len()]),
            (IX + 84, S + 19, 380, 18),
            small,
            TONE_MUTED,
        );
        self.button(
            REFRESH,
            "새로 고침",
            (IX + IW - 236, S + 10, 124, 34),
            theme::SECONDARY,
        );
        self.button(
            CLOSE,
            "닫기",
            (IX + IW - 104, S + 10, 104, 34),
            theme::PRIMARY,
        );
        let (y, h) = (S + 56, bottom - 14 - (S + 56));
        self.frames.push((
            Rect {
                left: IX,
                top: y,
                right: IX + IW,
                bottom: y + h,
            },
            LOG_VIEW,
        ));
        // WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY
        let view = self.ctrl(
            LOG_VIEW,
            "EDIT",
            "",
            (IX + 10, y + 8, IW - 14, h - 16),
            0x10000 | 0x20_0000 | 0x4 | 0x40 | 0x800,
        );
        if view != 0 {
            let text = if lines.is_empty() {
                tr("아직 로그가 없습니다.").to_owned()
            } else {
                lines.join("\r\n")
            };
            let w = wide(&text);
            unsafe {
                subclass(view, &EDIT_PROC, edit_proc);
                SendMessageW(view, 0x30, self.mono as usize, 0);
                SendMessageW(view, 0xc5, 0x10_0000, 0);
                SetWindowTextW(view, w.as_ptr());
                SendMessageW(view, 0xb1, w.len(), w.len() as isize); // EM_SETSEL at the end
                SendMessageW(view, 0xb7, 0, 0); // EM_SCROLLCARET
            }
        }
        unsafe {
            SetFocus(self.handle(CLOSE));
        }
    }
    fn build_server(&mut self) {
        let (small, strong) = (Self::font(|t| t.small()), Self::font(|t| t.strong()));
        let bottom = client_height(self.advanced) - 16;
        self.text(0, "서버에서 받기", (IX, S + 16, 300, 22), strong, TONE_TEXT);
        self.text(
            0,
            "받을 금고를 고르세요. 태그는 OTP 앱에 보이는 'Goyo Vault (태그)'의 태그와 같습니다.",
            (IX, S + 44, IW, 18),
            small,
            TONE_MUTED,
        );
        let top = S + 72;
        let list = self.list(SERVER_LIST, (IX, top, IW, bottom - 70 - top));
        for e in &self.listing {
            unsafe {
                SendMessageW(
                    list,
                    0x180,
                    0,
                    wide(&syncfile::hex(&e.id)).as_ptr() as isize,
                );
            }
        }
        if let Some(i) = self.picked {
            unsafe {
                SendMessageW(list, 0x186, i, 0);
            }
        }
        self.show_rows();
        self.text(
            0,
            "받은 파일은 고요 금고의 '백업에서 복원'으로 엽니다. 이 PC에서 동기화할 경로로 복원하세요.",
            (IX, bottom - 58, IW - 272, 40),
            small,
            TONE_MUTED,
        );
        self.button(
            CLOSE,
            "취소",
            (IX + IW - 256, bottom - 58, 104, 40),
            theme::SECONDARY,
        );
        self.button(
            TAKE,
            "받기…",
            (IX + IW - 144, bottom - 58, 144, 40),
            theme::PRIMARY,
        );
        unsafe {
            SetFocus(list);
        }
    }
    /// Commands that start a job wait while one runs.
    fn enable(&self) {
        let idle = self.busy.is_none();
        for id in [CHECK, INSTALL, FETCH, SAVE, SYNC, TAKE] {
            let h = self.handle(id);
            if h != 0 {
                unsafe {
                    EnableWindow(h, idle as i32);
                }
            }
        }
    }
    /// Resizes the window to the client height for the current layout. A
    /// window that grows past the bottom of its screen's work area moves up,
    /// so the run card never ends up below the taskbar.
    fn fit_window(&self) {
        let mut r = Rect {
            left: 0,
            top: 0,
            right: self.px(W),
            bottom: self.px(client_height(self.advanced)),
        };
        unsafe {
            AdjustWindowRectEx(&mut r, STYLE, 0, 0);
            let (width, height) = (r.right - r.left, r.bottom - r.top);
            let mut now = Rect::default();
            GetWindowRect(self.hwnd, &mut now);
            let mut info = MonitorInfo {
                size: size_of::<MonitorInfo>() as u32,
                ..MonitorInfo::default()
            };
            // MONITOR_DEFAULTTONEAREST
            let top = if GetMonitorInfoW(MonitorFromWindow(self.hwnd, 2), &mut info) != 0 {
                now.top.min(info.work.bottom - height).max(info.work.top)
            } else {
                now.top
            };
            // SWP_NOZORDER | SWP_NOACTIVATE
            SetWindowPos(self.hwnd, 0, now.left, top, width, height, 0x4 | 0x10);
        }
    }

    // ---- state shown ----

    /// Reads what is typed into `fields` (the inputs of a hidden section
    /// keep their last values there).
    fn read_fields(&mut self) {
        for (id, slot) in [
            (HOST, &mut self.fields.host),
            (REMOTE, &mut self.fields.remote),
            (PYTHON, &mut self.fields.python),
            (IDENTITY, &mut self.fields.identity),
            (INTERVAL, &mut self.fields.interval),
            (TIMEOUT, &mut self.fields.timeout),
        ] {
            let h = *self.controls.get(&id).unwrap_or(&0);
            if h != 0 {
                *slot = read_text(h).trim().to_owned();
            }
        }
    }
    fn dirty(&self) -> bool {
        self.saved.as_ref() != Some(&self.fields) || self.autostart != self.autostart_saved
    }
    fn show_notes(&self) {
        for (id, note) in [(SERVER_LINE, &self.server_note), (RUN_LINE, &self.run_note)] {
            let h = self.handle(id);
            if h == 0 {
                continue;
            }
            let (text, tone) = self.note_text(note);
            if read_text(h) != text || unsafe { GetWindowLongPtrW(h, -21) } != tone {
                unsafe {
                    SetWindowLongPtrW(h, -21, tone);
                    SetWindowTextW(h, wide(&text).as_ptr());
                    InvalidateRect(h, null(), 1);
                }
            }
        }
    }
    /// The row texts for owner-draw, and a repaint of the lists.
    fn show_rows(&self) {
        let vaults: Vec<RowView> = self.rows.iter().map(row_view).collect();
        let mine: Vec<(String, [u8; 16])> = self
            .rows
            .iter()
            .filter_map(|r| {
                let dir = syncfile::sync_dir(&r.path)?;
                let id = syncfile::read_helper_state(&dir)?.id?;
                Some((file_name(&r.path), id))
            })
            .collect();
        let server: Vec<RowView> = self.listing.iter().map(|e| server_view(e, &mine)).collect();
        ROWS.with(|rows| {
            if let Ok(mut rows) = rows.try_borrow_mut() {
                *rows = [vaults, server];
            }
        });
        for id in [VAULT_LIST, SERVER_LIST] {
            let h = self.handle(id);
            if h != 0 {
                unsafe {
                    InvalidateRect(h, null(), 0);
                }
            }
        }
    }
    fn set_server_note(&mut self, note: Note) {
        self.server_note = note;
        self.show_notes();
    }
    fn set_run_note(&mut self, note: Note) {
        self.run_note = note;
        self.show_notes();
    }
    /// A problem with an input: its frame turns red, the advanced section
    /// opens if it holds it, and it gets the focus.
    fn show_bad(&mut self, bad: Bad, run_line: bool) {
        let id = control_of(bad.field);
        if matches!(id, REMOTE | PYTHON | IDENTITY | INTERVAL | TIMEOUT) && !self.advanced {
            self.advanced = true;
            self.fit_window();
            self.build();
        }
        if let Field::Vault(i) = bad.field {
            self.selected = Some(i);
            unsafe {
                SendMessageW(self.handle(VAULT_LIST), 0x186, i, 0);
            }
        }
        self.bad = Some(bad.field);
        if run_line {
            self.run_note = Note::Bad(bad);
        } else {
            self.server_note = Note::Bad(bad);
        }
        self.show_notes();
        unsafe {
            let h = self.handle(id);
            if h != 0 {
                SetFocus(h);
            }
            MessageBeep(0x30);
            InvalidateRect(self.hwnd, null(), 0);
        }
    }
    fn clear_bad(&mut self) {
        if self.bad.take().is_some() {
            unsafe {
                InvalidateRect(self.hwnd, null(), 0);
            }
        }
    }

    // ---- commands ----

    fn allows(&self, id: i32) -> bool {
        let idle = self.busy.is_none();
        match self.screen {
            Screen::Main => match id {
                CHECK | INSTALL | FETCH | SAVE | SYNC => idle,
                HOST | REMOTE | PYTHON | IDENTITY | INTERVAL | TIMEOUT | VAULT_LIST | ADVANCED
                | BROWSE_KEY | ADD | REMOVE | AUTOSTART | STOP | LOG => true,
                _ => false,
            },
            Screen::Log => matches!(id, CLOSE | REFRESH | LOG_VIEW | ESCAPE),
            Screen::Server => match id {
                TAKE => idle,
                SERVER_LIST | CLOSE | ESCAPE => true,
                _ => false,
            },
        }
    }
    /// A click or notification. A dialog it needs comes back to be run
    /// without the borrow (see [`run_asks`]).
    fn command(&mut self, id: i32, notify: u16) -> Option<Ask> {
        if !self.allows(id) {
            return None;
        }
        match notify {
            // Focus moved: repaint the field outlines.
            0x100 | 0x200 if id != VAULT_LIST && id != SERVER_LIST => {
                unsafe {
                    InvalidateRect(self.hwnd, null(), 0);
                }
                return None;
            }
            // EN_CHANGE: typing clears the red outline.
            0x300 => {
                if self.bad.map(control_of) == Some(id) {
                    self.clear_bad();
                }
                return None;
            }
            1 if id == VAULT_LIST => {
                let i = unsafe { SendMessageW(self.handle(VAULT_LIST), 0x188, 0, 0) };
                self.selected = (i >= 0).then_some(i as usize);
                return None;
            }
            1 if id == SERVER_LIST => {
                let i = unsafe { SendMessageW(self.handle(SERVER_LIST), 0x188, 0, 0) };
                self.picked = (i >= 0).then_some(i as usize);
                return None;
            }
            // A double click takes the row.
            2 if id == SERVER_LIST => return self.command(TAKE, 0),
            0 => {}
            _ => return None,
        }
        self.read_fields();
        match id {
            ADVANCED => {
                self.advanced = !self.advanced;
                self.fit_window();
                self.build();
                unsafe {
                    SetFocus(self.handle(ADVANCED));
                }
                None
            }
            CHECK => {
                match setup::server_config(&self.fields) {
                    Ok(c) => self.start(Job::Check(c)),
                    Err(bad) => self.show_bad(bad, false),
                }
                None
            }
            INSTALL => match setup::server_config(&self.fields) {
                Ok(c) => Some(Ask::Install(c)),
                Err(bad) => {
                    self.show_bad(bad, false);
                    None
                }
            },
            FETCH => {
                match setup::server_config(&self.fields) {
                    Ok(c) => self.start(Job::List(c)),
                    Err(bad) => self.show_bad(bad, false),
                }
                None
            }
            BROWSE_KEY => Some(Ask::Key),
            ADD => Some(Ask::Vault),
            REMOVE => {
                match self.selected.filter(|i| *i < self.rows.len()) {
                    Some(i) => {
                        self.rows.remove(i);
                        self.fields.vaults.remove(i);
                        self.selected = None;
                        self.bad = None;
                        self.run_note = Note::Removed;
                        self.build();
                    }
                    None => self.set_run_note(Note::PickFirst),
                }
                None
            }
            // Off applies at once: removing the Run value is always safe, and
            // "save and start" would start the helper again. On waits for
            // the save, which writes the settings it needs.
            AUTOSTART => {
                let on = !self.autostart;
                let note = if on {
                    Note::Idle
                } else {
                    match self.system.set_autostart(false) {
                        Ok(()) => {
                            self.autostart_saved = false;
                            Note::AutostartOff
                        }
                        Err(code) => {
                            self.set_run_note(Note::AutostartFailed(code));
                            return None;
                        }
                    }
                };
                self.autostart = on;
                let variant = if on { theme::TOGGLE_ON } else { theme::TOGGLE };
                unsafe {
                    SetWindowLongPtrW(self.handle(AUTOSTART), -21, variant);
                    InvalidateRect(self.handle(AUTOSTART), null(), 0);
                }
                self.set_run_note(note);
                None
            }
            SAVE => {
                self.save();
                None
            }
            SYNC => {
                match setup::render(&self.fields) {
                    Ok((_, c)) => self.start(Job::Sync(c)),
                    Err(bad) => self.show_bad(bad, true),
                }
                None
            }
            STOP => {
                let sent = self.system.stop();
                self.set_run_note(Note::Stopped(sent));
                None
            }
            LOG => {
                self.screen = Screen::Log;
                self.build();
                None
            }
            REFRESH => {
                self.build();
                None
            }
            CLOSE | ESCAPE => {
                self.screen = Screen::Main;
                self.build();
                None
            }
            TAKE => {
                let e = self.picked.and_then(|i| self.listing.get(i))?;
                Some(Ask::Fetch(e.id, self.suggested(&e.id)))
            }
            _ => None,
        }
    }
    /// A new file name for a fetched copy next to the exe.
    fn suggested(&self, id: &[u8; 16]) -> PathBuf {
        let tag = tag(id);
        (1..100)
            .map(|n| {
                let name = if n == 1 {
                    format!("from-server-{tag}.goyo")
                } else {
                    format!("from-server-{tag}-{n}.goyo")
                };
                self.dir.join(name)
            })
            .find(|p| !setup::present(p))
            .unwrap_or_else(|| self.dir.join("from-server.goyo"))
    }
    /// What a dialog answered.
    fn answered(&mut self, ask: Ask, answer: Answer) -> Option<Ask> {
        match (ask, answer) {
            (Ask::Vault, Answer::Path(Some(path))) => {
                match setup::vault_problem(&path, &self.fields.vaults) {
                    Some(why) => {
                        self.set_run_note(Note::VaultRefused(why));
                        unsafe {
                            MessageBeep(0x30);
                        }
                    }
                    None => {
                        self.rows.push(Row::new(&path));
                        self.fields.vaults.push(path);
                        self.selected = Some(self.rows.len() - 1);
                        self.run_note = Note::Added;
                        self.bad = None;
                        self.build();
                    }
                }
                None
            }
            (Ask::Key, Answer::Path(Some(path))) => {
                let name = path.to_string_lossy().to_lowercase();
                if setup::key_file(&path) || name.trim_end_matches(['.', ' ']).ends_with(".goyo") {
                    self.set_run_note(Note::KeyRefused);
                } else {
                    self.fields.identity = path.to_string_lossy().into_owned();
                    unsafe {
                        SetWindowTextW(self.handle(IDENTITY), wide(&self.fields.identity).as_ptr());
                    }
                    self.clear_bad();
                }
                None
            }
            (Ask::Install(c), Answer::Yes(true)) => {
                self.start(Job::Install(c));
                None
            }
            (Ask::Trust(c, _), Answer::Yes(true)) => {
                self.start(Job::Trust(c));
                None
            }
            (Ask::Trust(..), Answer::Yes(false)) => {
                self.set_server_note(Note::TrustDeclined);
                None
            }
            (Ask::Fetch(id, _), Answer::Path(Some(path))) => {
                self.screen = Screen::Main;
                self.build();
                if setup::key_file(&path) {
                    self.set_server_note(Note::GotWrite);
                } else if let Some(c) = self.listed.clone() {
                    self.start(Job::Fetch(c, id, path));
                }
                None
            }
            (Ask::Close, Answer::Yes(true)) => Some(Ask::Quit),
            _ => None,
        }
    }
    /// Validates, writes goyo-sync.conf, applies the autostart switch and
    /// restarts the background helper on the worker thread.
    fn save(&mut self) {
        let (text, _) = match setup::render(&self.fields) {
            Ok(rendered) => rendered,
            Err(bad) => return self.show_bad(bad, true),
        };
        if syncfile::replace_file(&self.dir.join(CONFIG), text.as_bytes()).is_err() {
            return self.set_run_note(Note::SaveFailed);
        }
        self.saved = Some(self.fields.clone());
        // Always written, so a value from before --background is replaced.
        self.autostart_error = self.system.set_autostart(self.autostart).err();
        if self.autostart_error.is_none() {
            self.autostart_saved = self.autostart;
        }
        self.start(Job::Restart);
    }
    /// Runs `job` on a worker thread.
    fn start(&mut self, job: Job) {
        self.seq = self.seq.wrapping_add(1);
        let (seq, kind) = (self.seq, job.kind());
        let mut runner = (self.runner)();
        let system = self.system.clone();
        let log = self.log.clone();
        let hwnd = self.hwnd;
        let spawned = std::thread::Builder::new()
            .name("goyo-sync-window".into())
            .spawn(move || {
                let done = job.run(&mut *runner, &*system, &log);
                DONE.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((hwnd, seq, done));
                unsafe {
                    PostMessageW(hwnd, WM_DONE, 0, 0);
                }
            });
        let Ok(worker) = spawned else {
            let trouble = Note::Trouble(Trouble::of(SyncState::Server));
            return if kind.on_run_line() {
                self.set_run_note(trouble)
            } else {
                self.set_server_note(trouble)
            };
        };
        self.workers.retain(|w| !w.is_finished());
        self.workers.push(worker);
        self.busy = Some(Busy {
            seq,
            kind,
            since: Instant::now(),
        });
        self.clear_bad();
        self.show_busy();
        self.enable();
    }
    fn show_busy(&mut self) {
        let Some(b) = &self.busy else {
            return;
        };
        let note = Note::Busy(b.kind, b.since.elapsed().as_secs());
        if b.kind.on_run_line() {
            self.run_note = note;
        } else {
            self.server_note = note;
        }
        self.show_notes();
    }
    /// A worker's result.
    fn finish(&mut self, seq: u32, done: Done) -> Option<Ask> {
        if self.busy.as_ref().is_none_or(|b| b.seq != seq) {
            return None;
        }
        self.busy = None;
        self.enable();
        let ask = match done {
            Done::Checked(checked, c) => self.checked(checked, &c),
            Done::Trusted(trusted, c) => match trusted.checked.clone() {
                // Refused again (the key changed meanwhile): nothing new was
                // stored, so no fingerprint; and never a second question.
                Checked::HostKey(step) => {
                    let step = match step {
                        KeyStep::Ask { .. } => KeyStep::Unclear,
                        step => step,
                    };
                    self.checked(Checked::HostKey(step), &c)
                }
                checked => {
                    self.checked(checked, &c);
                    Some(Ask::Tell(fingerprint_text(&trusted, &c.host)))
                }
            },
            Done::Installed(installed) => {
                self.set_server_note(match installed {
                    Installed::Pass => Note::Installed,
                    Installed::Refused(_) => Note::Unsafe,
                    Installed::NotPass { line, cause, noisy } => {
                        Note::NotPass { line, cause, noisy }
                    }
                    Installed::Failed(t) => Note::Trouble(t),
                    Installed::Cancelled => Note::Intro,
                });
                None
            }
            Done::Listed(Ok(entries), c) => {
                if entries.is_empty() {
                    self.set_server_note(Note::ServerEmpty);
                } else {
                    self.listing = entries;
                    self.listed = Some(c);
                    self.picked = Some(0);
                    self.server_note = Note::Intro;
                    self.screen = Screen::Server;
                    self.build();
                }
                None
            }
            Done::Listed(Err(checked), c) => self.checked(checked, &c),
            Done::Got(got, path) => match got {
                Got::Saved { version, bytes } => {
                    self.set_server_note(Note::Got { version, bytes });
                    Some(Ask::Tell(fill(
                        "서버 버전 {}({}바이트)을 다음 파일로 받았습니다:\n{}\n\n이렇게 여세요.\n1. 열쇠 파일(.goyokey)을 USB 등으로 이 PC에 옮깁니다.\n2. 고요 금고에서 '백업에서 복원'을 누르고 이 파일을 고릅니다.\n3. '복원할 새 파일'은 이 PC에서 동기화할 경로(예: GoyoVault 폴더의 vault.goyo)로 정합니다.\n4. 복원한 금고 파일을 여기서 '추가…'로 넣고 '저장하고 시작'을 누릅니다.\n\n처음 받는 사본은 서버를 믿는 것이니, 연 뒤 확인 코드를 첫 PC와 비교하세요.",
                        &[&version, &bytes, &path.display()],
                    )))
                }
                Got::Exists => {
                    self.set_server_note(Note::GotExists);
                    None
                }
                Got::NotFound => {
                    self.set_server_note(Note::GotMissing);
                    None
                }
                Got::Write => {
                    self.set_server_note(Note::GotWrite);
                    None
                }
                Got::Failed(t) => {
                    self.set_server_note(Note::Trouble(t));
                    None
                }
                Got::Cancelled => None,
            },
            Done::Synced(outcomes, paths) => {
                let now = Instant::now();
                let failed = outcomes.iter().filter(|o| !outcome_ok(o)).count();
                for (path, outcome) in paths.iter().zip(outcomes.iter()) {
                    if let Some(row) = self.rows.iter_mut().find(|r| &r.path == path) {
                        row.result = Some((now, *outcome));
                    }
                }
                self.refresh_rows();
                self.set_run_note(Note::Synced {
                    ok: outcomes.len() - failed,
                    failed,
                });
                None
            }
            Done::Restarted(restarted) => {
                self.running = self.system.running();
                let note = match self.autostart_error.take() {
                    Some(code) => Note::AutostartFailed(code),
                    None => Note::Restart(restarted),
                };
                self.set_run_note(note);
                self.refresh_rows();
                unsafe {
                    InvalidateRect(self.hwnd, null(), 0);
                }
                None
            }
        };
        self.show_notes();
        ask
    }
    /// The connection check's result; a first-seen host key asks the user.
    fn checked(&mut self, checked: Checked, c: &Config) -> Option<Ask> {
        match checked {
            Checked::Ok { vaults } => self.set_server_note(Note::CheckOk(vaults)),
            Checked::HostKey(KeyStep::Ask { name }) => {
                self.set_server_note(Note::Intro);
                return Some(Ask::Trust(c.clone(), name));
            }
            Checked::HostKey(step) => {
                let changed = matches!(step, KeyStep::Changed | KeyStep::OtherKey { .. });
                let name = match &step {
                    KeyStep::OtherKey { name } => name.clone(),
                    _ => c.host.clone(),
                };
                self.set_server_note(Note::Key(step));
                if changed {
                    return Some(Ask::Tell(fill(
                        "서버 호스트 키가 이 PC의 known_hosts에 저장된 키와 다릅니다.\n\n누군가 연결을 가로채고 있을 수 있어 goyo-sync는 연결하지 않으며, 이 창에서는 새 키를 받아들이지 않습니다.\n\n서버를 다시 설치했거나 키를 바꾼 것이 확실할 때만: 서버에서 직접 지문을 확인하고(예: ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub), PowerShell에서 ssh-keygen -R {} 으로 예전 키를 지운 뒤 ssh {} 로 한 번 접속해 지문을 비교하세요.",
                        &[&name, &c.host],
                    )));
                }
            }
            Checked::Failed(t) => self.set_server_note(Note::Trouble(t)),
            Checked::Cancelled => {}
        }
        None
    }
    /// Closing with unsaved changes asks first.
    fn closing(&mut self) -> Option<Ask> {
        self.read_fields();
        self.dirty().then_some(Ask::Close)
    }
    /// Every 2 s: the running pill, the vault rows, a job's seconds, and the
    /// theme and language files.
    fn tick(&mut self) {
        self.follow_settings();
        let running = self.system.running();
        if running != self.running {
            self.running = running;
            unsafe {
                InvalidateRect(self.hwnd, &self.r(X, 16, W - X, 40), 0);
            }
        }
        if self.screen == Screen::Main && !in_modal() {
            self.read_fields();
        }
        self.refresh_rows();
        self.show_busy();
        self.show_notes();
    }
    fn refresh_rows(&mut self) {
        let now = crate::now();
        let mut changed = false;
        for row in &mut self.rows {
            let live = setup::live(&row.path, now);
            let expired = row.result.is_some_and(|(t, _)| t.elapsed() >= RESULT_SHOWN);
            if live != row.live || expired {
                row.live = live;
                if expired {
                    row.result = None;
                }
                changed = true;
            }
        }
        if changed {
            self.show_rows();
        }
    }
    /// goyo-vault.theme and goyo-vault.lang, as the vault app writes them.
    fn follow_settings(&mut self) {
        if in_modal() {
            return;
        }
        if let Some(dark) = read_setting(&self.dir, "goyo-vault.theme", b"dark", b"light")
            && dark != theme::is_dark()
        {
            // Controls take their colours when they paint; only the
            // scrollbars and the title bar are told.
            theme::set_dark(dark);
            apply_window_theme(self.hwnd);
            self.theme_scrollbars();
            unsafe {
                // RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME
                RedrawWindow(self.hwnd, null(), 0, 0x1 | 0x4 | 0x80 | 0x400);
            }
        }
        if let Some(english) = read_setting(&self.dir, "goyo-vault.lang", b"en", b"ko")
            && english != i18n::english()
        {
            i18n::set_english(english);
            self.read_fields();
            self.build();
            unsafe {
                SetWindowTextW(self.hwnd, wide(tr(TITLE)).as_ptr());
            }
        }
    }
    /// Clicking a frame's padding focuses the control inside.
    fn click(&self, l: isize) {
        let (x, y) = (
            (l & 0xffff) as i16 as i32,
            ((l >> 16) & 0xffff) as i16 as i32,
        );
        for (frame, id) in &self.frames {
            let r = self.scaled(frame);
            let h = self.handle(*id);
            if h != 0 && x >= r.left && x < r.right && y >= r.top && y < r.bottom {
                unsafe {
                    SetFocus(h);
                    InvalidateRect(self.hwnd, null(), 0);
                }
                return;
            }
        }
    }

    // ---- painting ----

    fn paint(&self) {
        let bg = theme::palette().bg;
        unsafe {
            let mut ps: Paint = std::mem::zeroed();
            let dc = BeginPaint(self.hwnd, &mut ps);
            let mut client = Rect::default();
            GetClientRect(self.hwnd, &mut client);
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
                self.draw(dc);
            } else {
                let old = SelectObject(mem, bmp);
                theme::fill(mem, &client, bg);
                self.draw(mem);
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
                    0x00cc_0020,
                );
                SelectObject(mem, old);
                DeleteObject(bmp);
                DeleteDC(mem);
            }
            EndPaint(self.hwnd, &ps);
        }
    }
    unsafe fn draw(&self, dc: isize) {
        let Some((title, small)) = theme::with(|t| (t.title(), t.small())) else {
            return;
        };
        let p = theme::palette();
        unsafe {
            let name = tr(TITLE);
            theme::text(dc, name, &self.r(X, 18, 420, 34), title, p.text, LINE);
            let state = tr(if self.running {
                "백그라운드 동기화 실행 중"
            } else {
                "백그라운드 동기화 꺼짐"
            });
            let x = self.px(X) + theme::text_width(dc, name, title) + self.px(14);
            let pill = Rect {
                left: x,
                top: self.px(24),
                right: (x + theme::text_width(dc, state, small) + self.px(32)).min(self.px(W - X)),
                bottom: self.px(46),
            };
            theme::round(dc, &pill, self.px(11), Some(p.surface), None);
            let dot = Rect {
                left: x + self.px(10),
                top: self.px(32),
                right: x + self.px(16),
                bottom: self.px(38),
            };
            let dot_color = if self.running { p.unlocked } else { p.faint };
            theme::round(dc, &dot, self.px(3), Some(dot_color), None);
            let mut label = pill;
            label.left += self.px(22);
            label.right -= self.px(8);
            theme::text(dc, state, &label, small, p.muted, LINE);
            for (x, y, w, h) in self.cards() {
                theme::round(
                    dc,
                    &self.r(x, y, w, h),
                    self.px(12),
                    Some(p.bg),
                    Some(p.border),
                );
            }
            let focus = GetFocus();
            let bad = self.bad.map(control_of);
            for (frame, id) in &self.frames {
                let h = self.handle(*id);
                let border = if Some(*id) == bad {
                    p.danger
                } else if h != 0
                    && h == focus
                    && !matches!(*id, VAULT_LIST | SERVER_LIST | LOG_VIEW)
                {
                    p.focus
                } else {
                    p.border
                };
                theme::round(
                    dc,
                    &self.scaled(frame),
                    self.px(8),
                    Some(p.bg),
                    Some(border),
                );
            }
            if self.screen == Screen::Main && self.rows.is_empty() {
                let v = vault_top(self.advanced);
                theme::text(
                    dc,
                    tr("아직 동기화할 금고가 없습니다. '추가…'로 금고 파일(.goyo)을 고르세요."),
                    &self.r(IX + 16, v + 52, IW - 32, 144),
                    small,
                    p.muted,
                    theme::DT_CENTER | LINE,
                );
            }
        }
    }
    fn cards(&self) -> Vec<(i32, i32, i32, i32)> {
        let adv = self.advanced;
        match self.screen {
            Screen::Main => vec![
                (X, S, CW, server_bottom(adv) - S),
                (X, vault_top(adv), CW, 200),
                (X, run_top(adv), CW, 148),
            ],
            _ => vec![(X, S, CW, client_height(adv) - 16 - S)],
        }
    }

    // ---- words ----

    /// The text and tone of a line.
    fn note_text(&self, note: &Note) -> (String, isize) {
        let f = &self.fields;
        let muted = |s: &str| (tr(s).to_owned(), TONE_MUTED);
        let danger = |s: String| (s, TONE_DANGER);
        match note {
            Note::Intro => muted(
                "서버를 적고 '연결 확인'을 누르세요. 서버에 스크립트가 아직 없다면 먼저 '서버에 설치·업데이트'를 누르세요.",
            ),
            Note::Busy(kind, secs) => {
                let template = match kind {
                    Kind::Check => "연결 확인 중… {}초",
                    Kind::Trust => "호스트 키를 저장하고 연결 확인 중… {}초",
                    Kind::Install => "서버에 설치하는 중… {}초",
                    Kind::List => "서버의 금고 목록을 받는 중… {}초",
                    Kind::Fetch => "서버에서 금고를 받는 중… {}초",
                    Kind::Sync => "모든 금고를 지금 동기화하는 중… {}초",
                    Kind::Restart => "백그라운드 동기화를 다시 시작하는 중… {}초",
                };
                (fill(template, &[secs]), TONE_TEXT)
            }
            Note::Bad(bad) => danger(bad_text(bad, f)),
            Note::CheckOk(n) => (
                fill("연결 정상 · 512바이트 이진 왕복 확인 · 서버에 금고 {}개", &[n]),
                TONE_TEXT,
            ),
            Note::Trouble(t) => danger(trouble_text(t, f)),
            Note::Key(step) => danger(match step {
                KeyStep::Changed => tr("서버 호스트 키가 known_hosts와 다릅니다. 중간자 공격일 수 있어 연결하지 않습니다.").to_owned(),
                KeyStep::OtherKey { .. } => tr("서버가 known_hosts에 있는 키와 다른 종류의 키를 보냈습니다. 연결하지 않습니다.").to_owned(),
                KeyStep::Unclear | KeyStep::Ask { .. } => fill(
                    "호스트 키를 확인할 수 없습니다. PowerShell에서 ssh {}로 한 번 접속해 지문을 확인하세요.",
                    &[&f.host],
                ),
            }),
            Note::TrustDeclined => muted(
                "호스트 키를 저장하지 않았습니다. 지문을 확인할 수 있을 때 다시 '연결 확인'을 누르세요.",
            ),
            Note::Installed => (
                tr("서버에 스크립트를 설치했습니다(selftest: PASS). 이제 '연결 확인'을 누르세요.").to_owned(),
                TONE_TEXT,
            ),
            Note::NotPass { line, cause, noisy } => danger(if *noisy {
                tr("설치는 됐지만 서버 셸이 PASS 외의 글을 출력합니다. 셸 시작 파일이 대화형 셸에서만 출력하게 고치세요.").to_owned()
            } else if *cause == Cause::PythonMissing {
                fill(
                    "서버에서 파이썬 명령({})을 찾지 못했습니다. 고급 설정의 파이썬 명령을 확인하세요.",
                    &[&f.python],
                )
            } else {
                fill("설치하지 못했습니다. 서버 출력: {}", &[&short(line)])
            }),
            Note::Unsafe => danger(tr("스크립트 경로나 파이썬 명령을 설치 명령에 쓸 수 없습니다. 스크립트 경로는 파일 이름으로 끝나야 합니다.").to_owned()),
            Note::ServerEmpty => muted("서버에 금고가 없습니다. 첫 PC의 고요 금고에서 동기화를 켜면 올라갑니다."),
            Note::Got { version, bytes } => (
                fill(
                    "서버 버전 {}({}바이트)을 받았습니다. 안내대로 고요 금고의 '백업에서 복원'으로 여세요.",
                    &[version, bytes],
                ),
                TONE_TEXT,
            ),
            Note::GotExists => danger(tr("이미 있는 파일입니다. 덮어쓰지 않으니 새 이름을 고르세요.").to_owned()),
            Note::GotMissing => danger(tr("서버에 그 금고가 없습니다.").to_owned()),
            Note::GotWrite => danger(tr("파일을 저장할 수 없습니다. 다른 폴더나 이름을 고르세요.").to_owned()),
            Note::Idle => muted(if self.saved.is_none() && self.fields.host.is_empty() {
                "아직 설정이 저장되지 않았습니다. 서버와 금고를 정한 뒤 '저장하고 시작'을 누르세요."
            } else if self.dirty() {
                "저장하지 않은 변경이 있습니다. '저장하고 시작'을 누르면 적용됩니다."
            } else if self.running {
                "백그라운드에서 동기화하고 있습니다. 이 창을 닫아도 계속됩니다."
            } else {
                "백그라운드 동기화가 꺼져 있습니다. '저장하고 시작'으로 켜세요."
            }),
            Note::Damaged(0) => danger(tr("goyo-sync.conf를 읽을 수 없습니다. 설정을 다시 저장하세요.").to_owned()),
            Note::Damaged(line) => danger(fill(
                "goyo-sync.conf {}번째 줄에 문제가 있습니다. 보이는 설정을 고친 뒤 '저장하고 시작'을 누르세요.",
                &[line],
            )),
            Note::Restart(r) => match r {
                Restarted::Started => (tr("설정을 저장하고 백그라운드 동기화를 시작했습니다.").to_owned(), TONE_TEXT),
                Restarted::StillRunning => danger(tr("실행 중인 도우미가 멈추지 않아 다시 시작하지 못했습니다. 잠시 뒤 다시 누르세요.").to_owned()),
                Restarted::StartFailed(code) => danger(fill("도우미를 시작하지 못했습니다(오류 {}).", &[code])),
                Restarted::NotStarted => danger(tr("도우미가 시작하자마자 끝났습니다. '로그 보기'로 이유를 확인하세요.").to_owned()),
            },
            Note::SaveFailed => danger(tr("goyo-sync.conf를 저장하지 못했습니다. 이 폴더에 쓸 수 있는지 확인하세요.").to_owned()),
            Note::AutostartFailed(code) => danger(fill("자동 시작 설정을 바꾸지 못했습니다(오류 {}).", &[code])),
            Note::Synced { ok, failed } => {
                let text = fill(
                    "지금 동기화를 마쳤습니다: 정상 {}개, 문제 {}개. 금고마다 결과가 목록에 보입니다.",
                    &[ok, failed],
                );
                (text, if *failed > 0 { TONE_DANGER } else { TONE_TEXT })
            }
            Note::Stopped(true) => muted("실행 중인 도우미에 중지 신호를 보냈습니다."),
            Note::Stopped(false) => muted("실행 중인 도우미가 없습니다."),
            Note::Added => muted("금고를 추가했습니다. '저장하고 시작'을 누르면 적용됩니다."),
            Note::Removed => muted(
                "목록에서 뺐습니다. '저장하고 시작'을 누르면 적용됩니다. 금고 옆 동기화 폴더는 그대로 남습니다.",
            ),
            Note::VaultRefused(why) => danger(vault_why(*why, None)),
            Note::KeyRefused => danger(tr("고요 금고 파일(.goyo·.goyokey)은 전용 키로 쓸 수 없습니다. SSH 개인 키를 고르세요.").to_owned()),
            Note::PickFirst => muted("뺄 금고를 목록에서 고르세요."),
            Note::AutostartOff if self.running => muted(
                "로그인할 때 자동으로 시작하지 않습니다. 지금 실행 중인 도우미는 '중지'로 멈추세요.",
            ),
            Note::AutostartOff => muted("로그인할 때 자동으로 시작하지 않습니다."),
        }
    }
}
impl Drop for App {
    fn drop(&mut self) {
        unsafe {
            DeleteObject(self.mono);
        }
    }
}
impl Row {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            live: setup::live(path, crate::now()),
            result: None,
        }
    }
}

fn control_of(field: Field) -> i32 {
    match field {
        Field::Host => HOST,
        Field::Remote => REMOTE,
        Field::Python => PYTHON,
        Field::Identity => IDENTITY,
        Field::Interval => INTERVAL,
        Field::Timeout => TIMEOUT,
        Field::Vault(_) | Field::Vaults => VAULT_LIST,
    }
}
fn read_text(h: Hwnd) -> String {
    unsafe {
        let n = GetWindowTextLengthW(h).clamp(0, 32767) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
        String::from_utf16_lossy(&buf[..got])
    }
}
fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}
/// At most 80 characters of a server's output in a line.
fn short(text: &str) -> String {
    let mut s: String = text.chars().take(80).collect();
    if text.chars().count() > 80 {
        s.push('…');
    }
    s
}
fn bad_text(bad: &Bad, f: &Fields) -> String {
    let field = match bad.field {
        Field::Host => "서버",
        Field::Remote => "스크립트 경로",
        Field::Python => "파이썬 명령",
        Field::Identity => "전용 키 파일",
        Field::Interval => "간격",
        Field::Timeout => "제한 시간",
        Field::Vault(_) | Field::Vaults => "금고 경로",
    };
    match (bad.why, bad.field) {
        (Why::Hash, _) => fill(
            "{}에 #를 쓸 수 없습니다. goyo-sync.conf에서 주석을 시작하는 기호입니다.",
            &[&tr(field)],
        ),
        (Why::TooLarge, _) => tr("설정이 8 KiB를 넘습니다. 금고 경로가 너무 깁니다.").to_owned(),
        (Why::Config(Problem::NoHost), _) => tr("서버(ssh 호스트)를 적으세요.").to_owned(),
        (Why::Config(_), Field::Host) => tr("서버는 ssh 별칭이나 호스트 이름이어야 합니다(영문·숫자·. _ -, user@ 허용, -로 시작 불가).").to_owned(),
        (Why::Config(_), Field::Remote) => tr("서버의 스크립트 경로는 영문·숫자·. _ / ~ + -만 쓸 수 있고 -로 시작할 수 없습니다.").to_owned(),
        (Why::Config(_), Field::Python) => tr("파이썬 명령은 영문·숫자·. _ / + -만 쓸 수 있고 -로 시작할 수 없습니다.").to_owned(),
        (Why::Config(_), Field::Identity) => tr("전용 키 파일은 있는 SSH 개인 키 파일의 절대 경로여야 합니다(.goyo·.goyokey 불가).").to_owned(),
        (Why::Config(_), Field::Interval) => tr("간격은 30~3600초 사이의 숫자여야 합니다.").to_owned(),
        (Why::Config(_), Field::Timeout) => tr("제한 시간은 30~600초 사이의 숫자여야 합니다.").to_owned(),
        (Why::Config(problem), Field::Vault(i)) => vault_why(Why::Config(problem), f.vaults.get(i).map(|p| p.as_path())),
        (Why::Config(problem), Field::Vaults) => vault_why(Why::Config(problem), None),
    }
}
/// Why a vault cannot be synced, as goyo-sync.conf would refuse it.
fn vault_why(why: Why, path: Option<&Path>) -> String {
    match why {
        Why::Hash => fill(
            "{}에 #를 쓸 수 없습니다. goyo-sync.conf에서 주석을 시작하는 기호입니다.",
            &[&tr("금고 경로")],
        ),
        Why::TooLarge => tr("설정이 8 KiB를 넘습니다. 금고 경로가 너무 깁니다.").to_owned(),
        Why::Config(Problem::KeyFile) => {
            tr("열쇠 파일(.goyokey)은 동기화하지 않습니다. 금고 파일(.goyo)을 고르세요.").to_owned()
        }
        Why::Config(Problem::DuplicateVault) => tr("이미 목록에 있는 금고입니다.").to_owned(),
        Why::Config(Problem::TooManyVaults) => tr("금고는 8개까지 넣을 수 있습니다.").to_owned(),
        Why::Config(Problem::NoVault) => tr("동기화할 금고를 하나 이상 추가하세요.").to_owned(),
        Why::Config(_) => fill(
            "이 금고 경로는 쓸 수 없습니다(절대 경로만, 따옴표·와일드카드·장치 경로 불가): {}",
            &[&path.map_or_else(String::new, |p| short(&p.display().to_string()))],
        ),
    }
}
fn trouble_text(t: &Trouble, f: &Fields) -> String {
    match (t.state, t.cause) {
        (_, Cause::ScriptMissing) => fill(
            "서버에 동기화 스크립트가 없습니다({}). '서버에 설치·업데이트'로 설치하세요.",
            &[&f.remote],
        ),
        (_, Cause::PythonMissing) => fill(
            "서버에서 파이썬 명령({})을 찾지 못했습니다. 고급 설정의 파이썬 명령을 확인하세요.",
            &[&f.python],
        ),
        (SyncState::Offline, _) => tr("서버에 연결할 수 없습니다. 네트워크·VPN과 서버 이름을 확인하세요.").to_owned(),
        (SyncState::Auth, _) => tr("SSH 인증에 실패했습니다. 키나 ssh-agent, 서버의 authorized_keys를 확인하세요. 암호를 묻는 키는 쓸 수 없습니다.").to_owned(),
        (SyncState::HostKey, _) => tr("서버 호스트 키를 확인해야 합니다. '연결 확인'을 누르세요.").to_owned(),
        (SyncState::NoSsh, _) => tr("Windows OpenSSH 클라이언트(ssh.exe)가 없습니다. 설정 > 시스템 > 선택적 기능에서 'OpenSSH 클라이언트'를 추가하세요.").to_owned(),
        (SyncState::Refused, _) => tr("서버가 요청을 거부했습니다. goyo-sync.log를 확인하세요.").to_owned(),
        (SyncState::Update, _) => tr("서버 사본이 더 새로운 형식입니다. 고요 금고와 goyo-sync를 업데이트하세요.").to_owned(),
        (SyncState::Config, _) => tr("설정을 확인하세요.").to_owned(),
        _ if t.detail.is_empty() => tr("서버 또는 통신 오류입니다. 서버 스크립트와 파이썬을 확인하고 goyo-sync.log를 보세요.").to_owned(),
        _ => fill(
            "서버 또는 통신 오류입니다(ssh: {}). 서버 스크립트와 파이썬을 확인하세요.",
            &[&short(&t.detail)],
        ),
    }
}
fn fingerprint_text(t: &Trusted, host: &str) -> String {
    let name = t.name.as_deref().unwrap_or(host);
    match &t.known {
        Known::Keys(lines) => fill(
            "known_hosts에 저장된 {} 서버의 호스트 키:\n\n{}\n\n서버에서 직접 확인한 지문과 같은지 비교하세요. 서버에서는 예를 들어 ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub 로 볼 수 있습니다. 다르면 ssh-keygen -R {} 으로 지우고 이 서버에 연결하지 마세요.",
            &[&name, &lines.join("\n"), &name],
        ),
        _ => fill(
            "호스트 키를 저장했는지 확인하지 못했습니다. PowerShell에서 ssh-keygen -l -F {} 로 지문을 보고 서버의 지문과 비교하세요.",
            &[&name],
        ),
    }
}
fn install_question(c: &Config) -> String {
    fill(
        "{} 서버에 동기화 스크립트를 설치하거나 업데이트합니다.\n\n서버 경로: {} (/로 시작하지 않으면 홈 폴더 기준)\n확인: 보낸 스크립트를 먼저 {} -I로 selftest하고, PASS일 때만 기존 스크립트와 바꿉니다.\n\n설치에는 평소의 ssh 로그인(기본 키나 ssh-agent)을 쓰고, '전용 키 파일'은 쓰지 않습니다. 전용 키는 서버에서 동기화 명령만 실행하도록 묶여 있을 수 있기 때문입니다. 계속할까요?",
        &[&c.host, &c.remote, &c.python],
    )
}
fn trust_question(name: &str) -> String {
    fill(
        "이 PC는 아직 {} 서버의 호스트 키를 모릅니다(처음 연결).\n\n'예'를 누르면 이번 한 번만 서버가 보내는 키를 확인 없이 믿고 known_hosts에 저장합니다(처음 사용할 때 신뢰). 지금 누군가 연결을 가로채고 있다면 그 사람의 키가 저장됩니다. 그 뒤로는 키가 바뀌면 연결하지 않습니다.\n\n저장한 뒤 지문을 보여 드리니, 서버에서 직접 본 지문과 꼭 비교하세요. 이 키를 믿고 저장할까요?",
        &[&name],
    )
}
fn outcome_ok(o: &Outcome) -> bool {
    matches!(o, Outcome::Done(r) if matches!(r.state, SyncState::Ok | SyncState::Idle))
}
/// A vault row: its file name and folder, then the last "sync now" result
/// (for a minute) or what the helper's files say.
fn row_view(row: &Row) -> RowView {
    let (state, tone) = match row.result.filter(|(t, _)| t.elapsed() < RESULT_SHOWN) {
        Some((_, outcome)) => outcome_text(&outcome, row.live),
        None => live_text(row.live),
    };
    RowView {
        title: file_name(&row.path),
        detail: row
            .path
            .parent()
            .map_or_else(String::new, |p| p.display().to_string()),
        state,
        tone,
    }
}
fn live_text(live: Live) -> (String, Tone) {
    let t = |s: &str, tone| (tr(s).to_owned(), tone);
    match live {
        Live::NoVault => t(
            "금고 파일을 찾을 수 없습니다. 경로를 확인하세요.",
            Tone::Danger,
        ),
        Live::NotSetUp => t(
            "아직 설정 전 · '저장하고 시작'하면 금고 옆에 동기화 폴더를 만듭니다",
            Tone::Muted,
        ),
        Live::Unusable => t(
            "동기화 폴더가 링크이거나 폴더가 아니어서 쓰지 않습니다",
            Tone::Danger,
        ),
        Live::HelperOff { server: 0 } => t("도우미 꺼짐", Tone::Faint),
        Live::HelperOff { server } => (
            fill("도우미 꺼짐 · 마지막 서버 버전 {}", &[&server]),
            Tone::Faint,
        ),
        Live::State { state, server } => state_text(state, server),
    }
}
fn state_text(state: SyncState, server: u64) -> (String, Tone) {
    let t = |s: &str, tone| (tr(s).to_owned(), tone);
    match state {
        SyncState::Ok if server > 0 => (fill("정상 · 서버 버전 {}", &[&server]), Tone::Good),
        SyncState::Ok => t("정상 · 서버에 아직 사본 없음", Tone::Good),
        SyncState::Idle => t(
            "고요 금고에서 동기화 동의를 기다리는 중 · 금고를 열면 묻습니다",
            Tone::Muted,
        ),
        SyncState::Offline => t(
            "오프라인 · 변경은 이 PC에 남아 있다가 연결되면 올라갑니다",
            Tone::Muted,
        ),
        SyncState::Auth => t("SSH 인증 실패 · '연결 확인'으로 확인하세요", Tone::Danger),
        SyncState::HostKey => t("호스트 키 확인 필요 · '연결 확인'을 누르세요", Tone::Danger),
        SyncState::NoSsh => t("ssh.exe가 없습니다", Tone::Danger),
        SyncState::Server => t("서버 오류 · '로그 보기'로 확인하세요", Tone::Danger),
        SyncState::Refused => t("업로드 거부됨 · '로그 보기'로 확인하세요", Tone::Danger),
        SyncState::Config => t("설정 오류 · 설정을 고친 뒤 저장하세요", Tone::Danger),
        SyncState::Update => t("새 형식 · 고요 금고를 업데이트하세요", Tone::Danger),
    }
}
fn outcome_text(outcome: &Outcome, live: Live) -> (String, Tone) {
    match outcome {
        Outcome::Locked => (
            tr("실행 중인 도우미가 처리하고 있어 건너뛰었습니다").to_owned(),
            Tone::Muted,
        ),
        Outcome::Folder(Folder::NoVault) => live_text(Live::NoVault),
        Outcome::Folder(Folder::Unusable) => live_text(Live::Unusable),
        Outcome::Done(r) => match r.state {
            SyncState::Ok => match (r.uploaded, r.downloaded) {
                (Some(v), _) => (
                    fill("지금 동기화: 올렸습니다 · 서버 버전 {}", &[&v]),
                    Tone::Good,
                ),
                (None, Some(v)) => (
                    fill("지금 동기화: 새 서버 버전 {}을 받았습니다", &[&v]),
                    Tone::Good,
                ),
                _ if r.server > 0 => (
                    fill("지금 동기화: 최신입니다 · 서버 버전 {}", &[&r.server]),
                    Tone::Good,
                ),
                _ => (
                    tr("지금 동기화: 서버에 아직 사본이 없습니다").to_owned(),
                    Tone::Good,
                ),
            },
            state => match live {
                Live::State { .. } | Live::HelperOff { .. } => state_text(state, r.server),
                other => live_text(other),
            },
        },
    }
}
/// A server row: tag and version, size and time, and which vault of this
/// PC it is (by the vault ID the helper pinned for it).
fn server_view(e: &ListEntry, mine: &[(String, [u8; 16])]) -> RowView {
    let time = utc(e.mtime).replace('T', " ");
    let time = time.trim_end_matches('Z');
    let time = time.get(..16).unwrap_or(time);
    let (state, tone) = match mine.iter().find(|(_, id)| *id == e.id) {
        Some((name, _)) => (fill("이 PC의 {}와 같은 금고", &[name]), Tone::Good),
        None => (fill("금고 ID {}", &[&syncfile::hex(&e.id)]), Tone::Muted),
    };
    RowView {
        title: fill("{} · 버전 {}", &[&tag(&e.id), &e.head]),
        detail: fill("{} KB · {} UTC 저장", &[&e.size.div_ceil(1024), &time]),
        state,
        tone,
    }
}
/// "light"/"dark" or "en"/"ko" in a file next to the exe; None if missing
/// or anything else, which leaves the window as it is.
fn read_setting(dir: &Path, name: &str, yes: &[u8], no: &[u8]) -> Option<bool> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(dir.join(name))
        .ok()?
        .take(16)
        .read_to_end(&mut buf)
        .ok()?;
    match buf.trim_ascii() {
        b if b == yes => Some(true),
        b if b == no => Some(false),
        _ => None,
    }
}
fn apply_window_theme(h: Hwnd) {
    let dark: i32 = theme::is_dark().into();
    unsafe {
        DwmSetWindowAttribute(h, 20, (&dark as *const i32).cast(), 4);
    }
}

// ---- window procedures ----

/// Inputs and lists take nothing from other threads: no text, no
/// selection, no geometry (like the vault's own inputs and list).
unsafe fn subclass(h: Hwnd, original: &OnceLock<Proc>, proc: Proc) {
    unsafe {
        let old = SetWindowLongPtrW(h, -4, proc as *const () as isize);
        if old != 0 {
            original.get_or_init(|| std::mem::transmute::<isize, Proc>(old));
        }
    }
}
unsafe extern "system" fn edit_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() {
        return 0;
    }
    unsafe { CallWindowProcW(EDIT_PROC.get().copied(), h, m, w, l) }
}
unsafe extern "system" fn list_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() {
        return 0;
    }
    unsafe { CallWindowProcW(LIST_PROC.get().copied(), h, m, w, l) }
}
fn with_app<T>(f: impl FnOnce(&mut App) -> T) -> Option<T> {
    APP.with(|cell| {
        cell.try_borrow_mut()
            .ok()
            .and_then(|mut b| b.as_mut().map(f))
    })
}
/// Runs the dialogs a command asked for, one after the other, with APP free.
fn run_asks(h: Hwnd, mut next: Option<Ask>) {
    while let Some(ask) = next.take() {
        let answer = match &ask {
            Ask::Vault | Ask::Key | Ask::Fetch(..) => Answer::Path(pick(h, &ask)),
            Ask::Install(c) => Answer::Yes(ask_yes(h, &install_question(c))),
            Ask::Trust(_, name) => Answer::Yes(ask_yes(h, &trust_question(name))),
            Ask::Close => Answer::Yes(ask_yes(
                h,
                tr("저장하지 않은 변경이 있습니다. 저장하지 않고 닫을까요?"),
            )),
            Ask::Tell(text) => {
                tell(h, text);
                Answer::Done
            }
            Ask::Quit => {
                unsafe {
                    DestroyWindow(h);
                }
                return;
            }
        };
        next = with_app(|a| a.answered(ask, answer)).flatten();
    }
}
fn ask_yes(h: Hwnd, text: &str) -> bool {
    unsafe {
        UpdateWindow(h);
    }
    ask(h, text)
}
unsafe extern "system" fn window_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    // Commands, owner-draw, timers, input and the worker notice only ever
    // come from this thread. Sent from another program they are fakes.
    if from_other_thread()
        && matches!(m, 0x100..=0x109 | 0x111 | 0x113 | 0x2b | 0x133..=0x138 | 0x201..=0x20e | WM_DONE)
    {
        return 0;
    }
    // While a dialog runs, the window gets no real click.
    if matches!(m, 0x111 | 0x201) && in_modal() {
        return 0;
    }
    match m {
        0x14 => return 1, // WM_PAINT fills everything
        0x133..=0x135 | 0x138 => {
            if let Some(brush) = unsafe { theme::control_color(m, w as isize, l) } {
                return brush;
            }
        }
        0x2b if l != 0 => {
            let item = unsafe { &*(l as *const DrawItem) };
            if unsafe { IsChild(h, item.item) } != 0 {
                if item.ctl_type == 2 {
                    unsafe { draw_row(item) };
                    return 1;
                }
                if unsafe { theme::draw_item(item) } {
                    return 1;
                }
            }
        }
        0x0f => {
            if with_app(|a| a.paint()).is_some() {
                return 0;
            }
        }
        0x111 => {
            let ask = with_app(|a| a.command((w & 0xffff) as i32, (w >> 16) as u16)).flatten();
            run_asks(h, ask);
            return 0;
        }
        0x113 if w == TIMER => {
            with_app(App::tick);
            return 0;
        }
        WM_DONE => {
            if APP.with(|cell| cell.try_borrow_mut().is_ok()) {
                let done = {
                    let mut slot = DONE.lock().unwrap_or_else(PoisonError::into_inner);
                    let mine = slot.iter().position(|(owner, ..)| *owner == h);
                    mine.map(|i| slot.remove(i))
                };
                if let Some((_, seq, done)) = done {
                    let ask = with_app(|a| a.finish(seq, done)).flatten();
                    run_asks(h, ask);
                }
            }
            return 0;
        }
        0x201 => {
            with_app(|a| a.click(l));
        }
        // A close request while a dialog runs waits for it (the user cannot
        // reach the window meanwhile).
        0x10 if in_modal() => return 0,
        0x10 => {
            match with_app(App::closing) {
                Some(Some(ask)) => run_asks(h, Some(ask)),
                _ => unsafe {
                    DestroyWindow(h);
                },
            }
            return 0;
        }
        0x02 => {
            with_app(|a| a.cancel.store(true, Ordering::Relaxed));
            unsafe {
                PostQuitMessage(0);
            }
            return 0;
        }
        _ => {}
    }
    unsafe { DefWindowProcW(h, m, w, l) }
}
/// One list row from [`ROWS`]: name and folder, then a dot and the state.
unsafe fn draw_row(d: &DrawItem) {
    theme::with(|t| unsafe {
        let p = t.palette();
        theme::fill(d.dc, &d.rect, p.bg);
        if d.item_id == u32::MAX {
            return;
        }
        let which = usize::from(d.ctl_id == SERVER_LIST as u32);
        let Some(row) = ROWS.with(|rows| {
            rows.try_borrow()
                .ok()
                .and_then(|rows| rows[which].get(d.item_id as usize).cloned())
        }) else {
            return;
        };
        let selected = d.state & 1 != 0;
        let r = theme::inset(&d.rect, t.px(2), t.px(2));
        if selected {
            theme::round(d.dc, &r, t.px(6), Some(p.surface), None);
        }
        let (left, right, top) = (r.left + t.px(12), r.right - t.px(10), r.top);
        let font = if selected { t.strong() } else { t.body() };
        let width = theme::text_width(d.dc, &row.title, font).min(right - left);
        let line = |l: i32, r: i32, a: i32, b: i32| Rect {
            left: l,
            top: top + t.px(a),
            right: r,
            bottom: top + t.px(b),
        };
        theme::text(
            d.dc,
            &row.title,
            &line(left, left + width + 1, 2, 22),
            font,
            p.text,
            LINE,
        );
        theme::text(
            d.dc,
            &row.detail,
            &line(left + width + t.px(10), right, 4, 22),
            t.small(),
            p.faint,
            LINE,
        );
        let color = match row.tone {
            Tone::Good => p.unlocked,
            Tone::Muted => p.muted,
            Tone::Faint => p.faint,
            Tone::Danger => p.danger,
        };
        let dot = Rect {
            left,
            top: top + t.px(28),
            right: left + t.px(6),
            bottom: top + t.px(34),
        };
        theme::round(d.dc, &dot, t.px(3), Some(color), None);
        let text_color = if row.tone == Tone::Danger {
            p.danger
        } else {
            p.muted
        };
        theme::text(
            d.dc,
            &row.state,
            &line(left + t.px(12), right, 22, 40),
            t.small(),
            text_color,
            LINE,
        );
    });
}

/// Filters posted messages, as the vault's window does: the window never
/// posts commands, clicks, list or edit operations, text or activation to
/// itself, so those come from another program. Of posted system commands
/// only close, minimize and restore pass. Keys and mouse buttons count only
/// while one of this program's windows is in front.
fn accept_queued(h: Hwnd, msg: &Msg) -> bool {
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
        return matches!(msg.wparam & 0xfff0, 0xf060 | 0xf020 | 0xf120);
    }
    if (0x100..=0x109).contains(&m) || (0x201..=0x20e).contains(&m) {
        return is_foreground(h);
    }
    true
}
/// accept_queued inside message boxes and file dialogs too, which run
/// their own message loops. A refused message becomes WM_NULL.
unsafe extern "system" fn queue_filter(code: i32, w: usize, l: isize) -> isize {
    if code >= 0 && l != 0 {
        let h = FILTERED.with(Cell::get);
        let msg = unsafe { &mut *(l as *mut Msg) };
        if h != 0 && !accept_queued(h, msg) {
            msg.message = 0;
        }
    }
    unsafe { CallNextHookEx(0, code, w, l) }
}
fn filter_queue(h: Hwnd) -> isize {
    FILTERED.with(|f| f.set(h));
    unsafe { SetWindowsHookExW(3, queue_filter, 0, GetCurrentThreadId()) } // WH_GETMESSAGE
}
/// Owner-drawn buttons report DLGC_BUTTON only, so IsDialogMessage would
/// turn Enter into IDOK: click the focused button instead.
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

/// Registers `class` (once) and creates the window at its basic size,
/// hidden.
fn create(class: &str) -> Option<Hwnd> {
    unsafe {
        let instance = GetModuleHandleW(null());
        let name = wide(class);
        let icon = LoadImageW(
            instance,
            std::ptr::without_provenance(1),
            1,
            GetSystemMetrics(11),
            GetSystemMetrics(11),
            0,
        );
        let wc = WndClass {
            style: 3,
            proc: Some(window_proc),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon,
            cursor: LoadCursorW(0, 32512usize as *const u16),
            background: 6,
            menu: null(),
            class: name.as_ptr(),
        };
        RegisterClassW(&wc); // fails harmlessly when already registered
        let scale = GetDpiForSystem() as f32 / 96.0;
        let mut r = Rect {
            left: 0,
            top: 0,
            right: (W as f32 * scale) as i32,
            bottom: (client_height(false) as f32 * scale) as i32,
        };
        AdjustWindowRectEx(&mut r, STYLE, 0, 0);
        let h = CreateWindowExW(
            0,
            name.as_ptr(),
            wide(tr(TITLE)).as_ptr(),
            STYLE,
            0x8000_0000u32 as i32,
            0x8000_0000u32 as i32,
            r.right - r.left,
            r.bottom - r.top,
            0,
            0,
            instance,
            null_mut(),
        );
        if h == 0 {
            return None;
        }
        apply_window_theme(h);
        let small = LoadImageW(
            instance,
            std::ptr::without_provenance(1),
            1,
            GetSystemMetrics(49),
            GetSystemMetrics(49),
            0,
        );
        SendMessageW(h, 0x80, 0, small); // WM_SETICON, ICON_SMALL
        SendMessageW(h, 0x80, 1, icon);
        Some(h)
    }
}
/// A start before Windows let the window open (no window to show it in).
pub fn startup_failed(text: &str) {
    let title = if crate::msg::english() {
        "Goyo Vault Sync"
    } else {
        TITLE
    };
    unsafe {
        MessageBoxW(0, wide(text).as_ptr(), wide(title).as_ptr(), 0x10);
    }
}
/// The window, until it is closed. A second start of the same exe brings
/// the first window to the front and ends.
pub fn run(dir: &Path, log: &Log) -> i32 {
    let (mutex, class) = crate::window_names();
    unsafe {
        SetProcessDPIAware();
    }
    let Some((instance, existed)) = sys::named_mutex(&mutex) else {
        return ERROR;
    };
    if existed {
        unsafe {
            let h = FindWindowW(wide(&class).as_ptr(), null());
            if h != 0 {
                if IsIconic(h) != 0 {
                    ShowWindow(h, 9); // SW_RESTORE
                }
                SetForegroundWindow(h);
            }
        }
        return OK;
    }
    theme::set_dark(read_setting(dir, "goyo-vault.theme", b"dark", b"light").unwrap_or(true));
    i18n::set_english(crate::msg::english());
    let Some(h) = create(&class) else {
        startup_failed(tr("화면을 만들 수 없어 종료합니다."));
        return ERROR;
    };
    let exe = std::env::current_exe().unwrap_or_else(|_| dir.join("goyo-sync.exe"));
    let cancel = Arc::new(AtomicBool::new(false));
    let runner: MakeRunner = {
        let cancel = cancel.clone();
        Arc::new(move || Box::new(SshRunner::new(cancel.clone())))
    };
    let app = App::new(
        h,
        dir.to_owned(),
        log.clone(),
        Arc::new(Windows { exe }),
        runner,
        cancel,
    );
    APP.with(|cell| *cell.borrow_mut() = Some(app));
    with_app(|a| {
        a.build();
        let first = if a.fields.host.is_empty() { HOST } else { SAVE };
        unsafe {
            SetFocus(a.handle(first));
        }
    });
    let hook = filter_queue(h);
    if hook == 0 || unsafe { SetTimer(h, TIMER, TICK, 0) } == 0 {
        unsafe {
            DestroyWindow(h);
        }
        APP.with(|cell| cell.borrow_mut().take());
        startup_failed(tr("화면을 만들 수 없어 종료합니다."));
        return ERROR;
    }
    unsafe {
        ShowWindow(h, 5);
        UpdateWindow(h);
        let mut msg = Msg::default();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            if !accept_queued(h, &msg) || enter_on_button(h, &msg) {
                continue;
            }
            if IsDialogMessageW(h, &mut msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        UnhookWindowsHookEx(hook);
    }
    let workers = APP
        .with(|cell| cell.borrow_mut().take())
        .map(|mut app| std::mem::take(&mut app.workers))
        .unwrap_or_default();
    // The window is gone: a new start may open its own meanwhile.
    drop(instance);
    finish_workers(workers, Duration::from_secs(25));
    OK
}
/// After the window closed, waits up to `limit` for the jobs still running.
/// Their ssh calls end at once (the window set `cancel`), but a restart of
/// the background helper runs to its end, so pressing "save and start" and
/// closing the window right away never leaves sync stopped.
fn finish_workers(workers: Vec<std::thread::JoinHandle<()>>, limit: Duration) {
    let deadline = Instant::now() + limit;
    for worker in workers {
        while !worker.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if worker.is_finished() {
            let _ = worker.join();
        }
    }
}
/// For `--self-check`: the window built hidden on every view (so the DLLs
/// it loads are loaded and checked too), then destroyed. Nothing is shown,
/// written or started.
pub fn self_check() -> bool {
    unsafe {
        SetProcessDPIAware();
    }
    let class = format!("GoyoSyncSelfCheck-{}", std::process::id());
    let Some(h) = create(&class) else {
        return false;
    };
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_default();
    let cancel = Arc::new(AtomicBool::new(true));
    let runner: MakeRunner = {
        let cancel = cancel.clone();
        Arc::new(move || Box::new(SshRunner::new(cancel.clone())))
    };
    let exe = dir.join("goyo-sync.exe");
    let mut app = App::new(
        h,
        dir,
        Log::new(None),
        Arc::new(Windows { exe }),
        runner,
        cancel,
    );
    let mut ok = app.mono != 0;
    for (screen, advanced, key) in [
        (Screen::Main, false, SAVE),
        (Screen::Main, true, IDENTITY),
        (Screen::Log, false, LOG_VIEW),
        (Screen::Server, false, TAKE),
    ] {
        app.screen = screen;
        app.advanced = advanced;
        app.build();
        ok &= !app.broken && app.handle(key) != 0;
    }
    drop(app);
    unsafe {
        DestroyWindow(h);
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        setup::tests::{Script, hello_ok, list_ok, out, reply, ssh_said},
        tests::Temp,
    };
    use goyo_vault::syncwire::Status;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetClassNameW(h: Hwnd, name: *mut u16, n: i32) -> i32;
        fn PeekMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32, remove: u32) -> i32;
    }

    /// What the window did outside itself, instead of doing it.
    #[derive(Default)]
    struct Fake {
        state: Mutex<FakeState>,
    }
    #[derive(Default)]
    struct FakeState {
        running: bool,
        autostart: bool,
        calls: Vec<String>,
        /// How long a stopped helper takes to end its pass and exit.
        stop_delay: Duration,
        stopping: Option<Instant>,
    }
    impl System for Fake {
        fn running(&self) -> bool {
            let mut s = self.state.lock().unwrap();
            if s.stopping.is_some_and(|t| t.elapsed() >= s.stop_delay) {
                s.stopping = None;
                s.running = false;
            }
            s.running
        }
        fn stop(&self) -> bool {
            let mut s = self.state.lock().unwrap();
            s.calls.push("stop".into());
            if s.stop_delay.is_zero() {
                std::mem::replace(&mut s.running, false)
            } else {
                s.stopping = Some(Instant::now());
                s.running
            }
        }
        fn start(&self) -> Result<(), u32> {
            let mut s = self.state.lock().unwrap();
            s.calls.push("start".into());
            s.running = true;
            Ok(())
        }
        fn autostart(&self) -> bool {
            self.state.lock().unwrap().autostart
        }
        fn set_autostart(&self, on: bool) -> Result<(), i32> {
            let mut s = self.state.lock().unwrap();
            s.calls.push(format!("autostart {on}"));
            s.autostart = on;
            Ok(())
        }
    }
    fn calls(fake: &Fake) -> Vec<String> {
        std::mem::take(&mut fake.state.lock().unwrap().calls)
    }

    /// A hidden window with the App in APP, a scripted runner and a fake
    /// system; removed with everything when dropped.
    struct Window {
        h: Hwnd,
        script: Script,
        fake: Arc<Fake>,
        t: Temp,
    }
    impl Window {
        fn new(name: &str) -> Self {
            Self::with(name, |_| {})
        }
        /// `prepare` puts files into the exe folder before the window reads it.
        fn with(name: &str, prepare: impl FnOnce(&Path)) -> Self {
            let t = Temp::new(name);
            prepare(&t.0);
            unsafe {
                SetProcessDPIAware();
            }
            let h = create(&format!("GoyoSyncTest-{name}")).unwrap();
            let script = Script::default();
            let fake = Arc::new(Fake::default());
            let runner: MakeRunner = {
                let script = script.clone();
                Arc::new(move || Box::new(script.clone()))
            };
            let app = App::new(
                h,
                t.0.clone(),
                Log::new(Some(t.0.join(crate::LOG))),
                fake.clone(),
                runner,
                Arc::new(AtomicBool::new(false)),
            );
            APP.with(|cell| *cell.borrow_mut() = Some(app));
            with_app(App::build);
            Self { h, script, fake, t }
        }
        fn app<T>(&self, f: impl FnOnce(&mut App) -> T) -> T {
            with_app(f).unwrap()
        }
        /// A click on a button, as the button would send it.
        fn click(&self, id: i32) {
            unsafe {
                window_proc(self.h, 0x111, id as usize, self.app(|a| a.handle(id)));
            }
        }
        fn type_in(&self, id: i32, text: &str) {
            let edit = self.app(|a| a.handle(id));
            assert_ne!(edit, 0, "no input {id}");
            unsafe {
                SetWindowTextW(edit, wide(text).as_ptr());
            }
        }
        /// Pumps messages until the job ends.
        fn wait(&self) {
            let start = Instant::now();
            while self.app(|a| a.busy.is_some()) {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "the job never ended"
                );
                pump();
                std::thread::sleep(Duration::from_millis(5));
            }
            pump();
        }
    }
    impl Drop for Window {
        fn drop(&mut self) {
            APP.with(|cell| cell.borrow_mut().take());
            unsafe {
                DestroyWindow(self.h);
            }
            pump();
        }
    }
    fn pump() {
        let mut msg = Msg::default();
        unsafe {
            while PeekMessageW(&mut msg, 0, 0, 0, 1) != 0 {
                if msg.message == 0x12 {
                    continue; // WM_QUIT of a test window
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    fn answer(yes: bool) {
        ANSWERS.with(|a| a.borrow_mut().push_back(yes));
    }
    fn choose(path: Option<PathBuf>) {
        PICKS.with(|p| p.borrow_mut().push_back(path));
    }
    fn told() -> Vec<String> {
        TOLD.with(|t| std::mem::take(&mut *t.borrow_mut()))
    }
    fn asked() -> Vec<String> {
        ASKED.with(|a| std::mem::take(&mut *a.borrow_mut()))
    }
    fn class_of(h: Hwnd) -> String {
        let mut class = [0u16; 16];
        let n = unsafe { GetClassNameW(h, class.as_mut_ptr(), 16) }.max(0) as usize;
        String::from_utf16_lossy(&class[..n])
    }
    fn has_korean(s: &str) -> bool {
        s.chars().any(|c| {
            ('\u{ac00}'..='\u{d7a3}').contains(&c) || ('\u{3131}'..='\u{318e}').contains(&c)
        })
    }
    struct KoreanAfter;
    impl Drop for KoreanAfter {
        fn drop(&mut self) {
            i18n::set_english(false);
        }
    }

    /// Fill the fields, add and remove vaults, check the server, save into
    /// the test folder: goyo-sync.conf is what the helper reads, autostart
    /// and the restart go through the fake, and bad input is refused with
    /// its field marked.
    #[test]
    fn smoke_fill_check_and_save() {
        let _korean = KoreanAfter;
        i18n::set_english(false);
        // vault.goyo next to the exe is offered at once; the switch is on
        // before the first save.
        let w = Window::with("smoke", |dir| {
            std::fs::write(dir.join("vault.goyo"), b"never read").unwrap()
        });
        let vault = w.t.0.join("vault.goyo");
        let other = Temp::new("smoke-other");
        let second = other.0.join("second.goyo");
        assert_eq!(
            w.app(|a| a.fields.vaults.clone()),
            std::slice::from_ref(&vault)
        );
        assert!(w.app(|a| a.autostart));
        assert_eq!(
            ROWS.with(|r| r.borrow()[0][0].state.clone()),
            tr("아직 설정 전 · '저장하고 시작'하면 금고 옆에 동기화 폴더를 만듭니다")
        );
        // Empty host: the check is refused with the field marked.
        w.click(CHECK);
        assert_eq!(w.app(|a| a.bad), Some(Field::Host));
        assert!(w.script.ran().is_empty());
        // The check.
        w.type_in(HOST, "my-server");
        w.script.push(hello_ok());
        w.script.push(list_ok(&[]));
        w.click(CHECK);
        assert!(w.app(|a| a.busy.is_some()));
        w.wait();
        assert_eq!(w.app(|a| a.server_note.clone()), Note::CheckOk(0));
        assert_eq!(w.app(|a| a.bad), None);
        // Vaults: a key file is refused, a vault added, then removed.
        choose(Some(other.0.join("vault.goyokey")));
        w.click(ADD);
        assert_eq!(
            w.app(|a| a.run_note.clone()),
            Note::VaultRefused(Why::Config(Problem::KeyFile))
        );
        choose(Some(second.clone()));
        w.click(ADD);
        choose(Some(vault.clone()));
        w.click(ADD);
        assert_eq!(
            w.app(|a| a.run_note.clone()),
            Note::VaultRefused(Why::Config(Problem::DuplicateVault))
        );
        assert_eq!(
            w.app(|a| a.fields.vaults.clone()),
            [vault.clone(), second.clone()]
        );
        assert_eq!(w.app(|a| a.selected), Some(1));
        w.click(REMOVE);
        assert_eq!(
            w.app(|a| a.fields.vaults.clone()),
            std::slice::from_ref(&vault)
        );
        assert_eq!(ROWS.with(|r| r.borrow()[0].len()), 1);
        // Bad advanced input: the section opens and nothing is written.
        w.click(ADVANCED);
        assert!(w.app(|a| a.advanced && a.handle(INTERVAL) != 0));
        w.type_in(INTERVAL, "5");
        w.click(SAVE);
        assert_eq!(w.app(|a| a.bad), Some(Field::Interval));
        assert!(!w.t.0.join(CONFIG).exists());
        w.type_in(INTERVAL, "90");
        // Save: the file, the Run value, then stop (nothing ran) and start.
        w.fake.state.lock().unwrap().running = true;
        w.click(SAVE);
        w.wait();
        let saved = config::load(&w.t.0.join(CONFIG)).unwrap();
        assert_eq!(saved.host, "my-server");
        assert_eq!(saved.interval, 90);
        assert_eq!(saved.vaults, std::slice::from_ref(&vault));
        assert_eq!(calls(&w.fake), ["autostart true", "stop", "start"]);
        assert_eq!(
            w.app(|a| a.run_note.clone()),
            Note::Restart(Restarted::Started)
        );
        assert!(!w.app(|a| a.dirty()));
        let text = std::fs::read_to_string(w.t.0.join(CONFIG)).unwrap();
        assert!(text.starts_with("# goyo-sync.conf, written by the goyo-sync settings window"));
        // The switch off applies at once, starting nothing; on waits for
        // the save.
        w.click(AUTOSTART);
        assert_eq!(calls(&w.fake), ["autostart false"]);
        assert!(!w.app(|a| a.dirty()));
        assert_eq!(w.app(|a| a.run_note.clone()), Note::AutostartOff);
        w.click(AUTOSTART);
        assert!(calls(&w.fake).is_empty());
        assert!(w.app(|a| a.dirty()));
        w.click(SAVE);
        w.wait();
        assert_eq!(calls(&w.fake), ["autostart true", "stop", "start"]);
        // Stop.
        w.click(STOP);
        assert_eq!(calls(&w.fake), ["stop"]);
        assert_eq!(w.app(|a| a.run_note.clone()), Note::Stopped(true));
        // Unsaved changes ask before closing; "no" keeps the window.
        w.type_in(HOST, "other-server");
        answer(false);
        unsafe {
            window_proc(w.h, 0x10, 0, 0);
        }
        assert_eq!(asked().len(), 1);
        assert_ne!(unsafe { IsWindow(w.h) }, 0);
    }

    /// "Save and start", then closing the window at once: the process waits
    /// for the restart, so the old helper is never left stopped without the
    /// new one started.
    #[test]
    fn closing_waits_for_the_restart() {
        let w = Window::with("closing", |dir| {
            std::fs::write(dir.join("vault.goyo"), b"never read").unwrap()
        });
        w.type_in(HOST, "my-server");
        {
            let mut s = w.fake.state.lock().unwrap();
            s.running = true;
            s.stop_delay = Duration::from_secs(2);
        }
        w.click(SAVE);
        let workers = w.app(|a| std::mem::take(&mut a.workers));
        assert_eq!(workers.len(), 1);
        // The old helper is still ending its pass: nothing started yet.
        assert!(!w.fake.state.lock().unwrap().calls.contains(&"start".into()));
        finish_workers(workers, Duration::from_secs(20));
        assert_eq!(calls(&w.fake), ["autostart true", "stop", "start"]);
        w.wait();
        assert_eq!(
            w.app(|a| a.run_note.clone()),
            Note::Restart(Restarted::Started)
        );
    }

    /// Install (asked first, sent without the dedicated key), the first
    /// connection (asked, one accept-new call, fingerprint shown), a
    /// changed key (explained, never asked), and getting a vault from the
    /// server into a new file.
    #[test]
    fn server_flows() {
        let _korean = KoreanAfter;
        let w = Window::new("server");
        w.type_in(HOST, "my-server");
        // A dedicated key, which the install must not use.
        let key = w.t.0.join("goyo_sync");
        std::fs::write(&key, b"not read").unwrap();
        w.app(|a| a.fields.identity = key.to_string_lossy().into_owned());
        // Install: "no" sends nothing; "yes" sends the script.
        answer(false);
        w.click(INSTALL);
        assert!(asked()[0].contains("my-server"));
        assert!(w.script.ran().is_empty());
        answer(true);
        w.script.push(out(0, b"PASS\n", ""));
        w.click(INSTALL);
        w.wait();
        assert_eq!(w.app(|a| a.server_note.clone()), Note::Installed);
        let ran = w.script.ran();
        assert_eq!(ran.last().unwrap().input, setup::SERVER_SCRIPT.len());
        assert_eq!(
            ran.last().unwrap().args.last().unwrap(),
            &setup::install_command(config::DEFAULT_REMOTE, config::DEFAULT_PYTHON).unwrap()
        );
        assert!(
            !ran.last()
                .unwrap()
                .args
                .iter()
                .any(|a| a == "-i" || a.contains("IdentitiesOnly"))
        );
        asked();
        // First connection: asked; "no" stores nothing.
        let unknown = "No ED25519 host key is known for my-server and you have requested strict checking.\r\nHost key verification failed.\r\n";
        let resolved = || out(0, b"hostname my-server\nport 22\n", "");
        for reply in [ssh_said(unknown), resolved(), out(1, b"", "")] {
            w.script.push(reply);
        }
        answer(false);
        w.click(CHECK);
        w.wait();
        assert!(asked()[0].contains("known_hosts"));
        assert_eq!(w.app(|a| a.server_note.clone()), Note::TrustDeclined);
        // "yes": one accept-new HELLO, the fingerprint, then LIST.
        for reply in [ssh_said(unknown), resolved(), out(1, b"", "")] {
            w.script.push(reply);
        }
        for reply in [
            hello_ok(),
            resolved(),
            out(0, b"my-server ED25519 SHA256:abc\n", ""),
            list_ok(&[]),
        ] {
            w.script.push(reply);
        }
        answer(true);
        let before = w.script.ran().len();
        w.click(CHECK);
        w.wait();
        w.wait();
        let ran = w.script.ran();
        let accept = ran[before..]
            .iter()
            .filter(|r| {
                r.args
                    .iter()
                    .any(|a| a == "StrictHostKeyChecking=accept-new")
            })
            .count();
        assert_eq!(accept, 1);
        assert!(told().iter().any(|t| t.contains("SHA256:abc")));
        assert_eq!(w.app(|a| a.server_note.clone()), Note::CheckOk(0));
        asked();
        // A changed key: explained, never asked.
        let changed =
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\r\nHost key verification failed.\r\n";
        w.script.push(ssh_said(changed));
        w.click(CHECK);
        w.wait();
        assert!(asked().is_empty());
        assert_eq!(
            w.app(|a| a.server_note.clone()),
            Note::Key(KeyStep::Changed)
        );
        assert!(told().iter().any(|t| t.contains("ssh-keygen -R my-server")));
        // Get from the server: the list, then a new file.
        let id = [0xA7; 16];
        let entry = ListEntry {
            id,
            head: 4,
            size: 160,
            mtime: 1_800_000_000,
        };
        w.script.push(list_ok(&[entry]));
        w.click(FETCH);
        w.wait();
        assert_eq!(w.app(|a| a.screen), Screen::Server);
        assert_eq!(
            ROWS.with(|r| r.borrow()[1][0].title.clone()),
            "A7A7-A7A7 · 버전 4"
        );
        let mut blob = Vec::from(*b"GOYOVA02");
        blob.extend_from_slice(&id);
        blob.resize(160, 1);
        w.script.push(reply(Status::Ok, 4, &blob));
        let target = w.t.0.join("from-server.goyo");
        choose(Some(target.clone()));
        w.click(TAKE);
        w.wait();
        assert_eq!(std::fs::read(&target).unwrap(), blob);
        assert_eq!(w.app(|a| a.screen), Screen::Main);
        assert_eq!(
            w.app(|a| a.server_note.clone()),
            Note::Got {
                version: 4,
                bytes: 160
            }
        );
        assert!(told().iter().any(|t| t.contains("from-server.goyo")));
        // The log view shows the log's last lines.
        std::fs::write(w.t.0.join(crate::LOG), "first\nlast line\n").unwrap();
        w.click(LOG);
        let view = w.app(|a| a.handle(LOG_VIEW));
        assert!(read_text(view).ends_with("last line"));
        w.click(CLOSE);
        assert_eq!(w.app(|a| a.screen), Screen::Main);
    }

    /// Commands, clicks and text sent from another thread change nothing,
    /// and posted ones never reach the window.
    #[test]
    fn foreign_messages_are_ignored() {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn SendNotifyMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> i32;
        }
        // Settings that "save and start" would accept, so a foreign command
        // that got through would write goyo-sync.conf.
        let w = Window::with("foreign", |dir| {
            std::fs::write(dir.join("vault.goyo"), b"never read").unwrap()
        });
        w.type_in(HOST, "my-server");
        assert!(
            setup::render(&w.app(|a| {
                a.read_fields();
                a.fields.clone()
            }))
            .is_ok()
        );
        let (h, host, save, list) =
            w.app(|a| (a.hwnd, a.handle(HOST), a.handle(SAVE), a.handle(VAULT_LIST)));
        let other = std::thread::spawn(move || unsafe {
            SendNotifyMessageW(h, 0x111, SAVE as usize, 0);
            [
                SendMessageW(h, 0x111, SAVE as usize, save),
                SendMessageW(save, 0xf5, 0, 0),
                // A click made of sent mouse messages.
                SendMessageW(save, 0x201, 1, 0x000a_000a),
                SendMessageW(save, 0x202, 0, 0x000a_000a),
                SendMessageW(host, 0x0c, 0, wide("attacker").as_ptr() as isize),
                SendMessageW(host, 0x0e, 0, 0),
                SendMessageW(h, WM_DONE, 0, 0),
            ]
        });
        while !other.is_finished() {
            pump();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(other.join().unwrap(), [0; 7]);
        pump();
        assert!(!w.t.0.join(CONFIG).exists(), "a foreign command saved");
        assert_eq!(read_text(host), "my-server");
        assert!(w.app(|a| a.busy.is_none()));
        let posted = |hwnd: Hwnd, message: u32| Msg {
            hwnd,
            message,
            ..Msg::default()
        };
        for (target, m) in [
            (h, 0x111),
            (save, 0xf5),
            (host, 0x0c),
            (host, 0xb1),
            (list.max(host), 0x186),
            (h, 0x2b),
        ] {
            assert!(!accept_queued(h, &posted(target, m)), "{m:#x}");
        }
        assert!(accept_queued(h, &posted(h, WM_DONE)));
        assert!(accept_queued(h, &posted(h, 0x113)));
        assert!(!accept_queued(
            h,
            &Msg {
                hwnd: h,
                message: 0x112,
                wparam: 0xf010,
                ..Msg::default()
            }
        ));
        // A posted WM_DONE without a result does nothing.
        unsafe {
            PostMessageW(h, WM_DONE, 0, 0);
        }
        pump();
        assert!(w.app(|a| a.busy.is_none()));
    }

    /// Builds each view with synthetic data and calls `visit` on it.
    fn each_view(visit: &mut dyn FnMut(&Window, &str)) {
        let w = Window::new("views");
        let vault = w.t.0.join("vault.goyo");
        std::fs::write(&vault, b"never read").unwrap();
        let dir = w.t.0.join("vault.goyo.sync");
        std::fs::create_dir(&dir).unwrap();
        let state = syncfile::HelperState {
            id: Some([0xA7; 16]),
            server: 12,
            ..Default::default()
        };
        syncfile::replace_file(
            &dir.join(syncfile::HELPER_STATE),
            &syncfile::render_helper_state(&state),
        )
        .unwrap();
        syncfile::replace_file(
            &dir.join(syncfile::STATUS),
            &syncfile::render_status(crate::now(), crate::now(), SyncState::Ok),
        )
        .unwrap();
        w.app(|a| {
            a.fields.host = "my-server".into();
            a.fields.vaults = vec![
                vault.clone(),
                PathBuf::from(r"C:\Users\<you>\Documents\GoyoVault\missing.goyo"),
            ];
            a.rows = a.fields.vaults.iter().map(|p| Row::new(p)).collect();
            a.build();
        });
        visit(&w, "main");
        w.app(|a| {
            a.advanced = true;
            a.fit_window();
            a.build();
        });
        visit(&w, "advanced");
        w.app(|a| {
            a.busy = Some(Busy {
                seq: 99,
                kind: Kind::Restart,
                since: Instant::now(),
            });
            a.server_note = Note::Busy(Kind::Install, 12);
            a.run_note = Note::Busy(Kind::Restart, 3);
            a.enable();
            a.show_notes();
        });
        visit(&w, "busy");
        w.app(|a| {
            a.busy = None;
            a.advanced = false;
            a.fit_window();
            a.rows.clear();
            a.fields.vaults.clear();
            a.server_note = Note::Intro;
            a.run_note = Note::Idle;
            a.build();
        });
        visit(&w, "empty");
        std::fs::write(
            w.t.0.join(crate::LOG),
            "2026-10-25T01:02:03Z A7A7-A7A7 check HELLO OK v=1\n",
        )
        .unwrap();
        w.app(|a| {
            a.screen = Screen::Log;
            a.build();
        });
        visit(&w, "log");
        w.app(|a| {
            a.rows = vec![Row::new(&vault)];
            a.listing = vec![
                ListEntry {
                    id: [0xA7; 16],
                    head: 12,
                    size: 40_000,
                    mtime: 1_800_000_000,
                },
                ListEntry {
                    id: [0x3F; 16],
                    head: 3,
                    size: 900,
                    mtime: 1_790_000_000,
                },
            ];
            a.picked = Some(0);
            a.screen = Screen::Server;
            a.build();
        });
        visit(&w, "server");
    }
    /// Every note, row state and question with sample values, for the
    /// language and fit checks.
    fn every_note() -> Vec<Note> {
        let bad = |field, why| Note::Bad(Bad { field, why });
        let mut notes = vec![
            Note::Intro,
            Note::CheckOk(64),
            Note::TrustDeclined,
            Note::Installed,
            Note::NotPass {
                line: "FAIL: concurrent PUT with the same expected version".into(),
                cause: Cause::Plain,
                noisy: false,
            },
            Note::NotPass {
                line: String::new(),
                cause: Cause::PythonMissing,
                noisy: false,
            },
            Note::NotPass {
                line: "PASS".into(),
                cause: Cause::Plain,
                noisy: true,
            },
            Note::Unsafe,
            Note::ServerEmpty,
            Note::Got {
                version: 123_456,
                bytes: 8_388_608,
            },
            Note::GotExists,
            Note::GotMissing,
            Note::GotWrite,
            Note::Idle,
            Note::Damaged(0),
            Note::Damaged(12),
            Note::SaveFailed,
            Note::AutostartFailed(1234),
            Note::Synced { ok: 8, failed: 0 },
            Note::Synced { ok: 4, failed: 4 },
            Note::Stopped(true),
            Note::Stopped(false),
            Note::Added,
            Note::Removed,
            Note::KeyRefused,
            Note::PickFirst,
            Note::AutostartOff,
        ];
        for kind in [
            Kind::Check,
            Kind::Trust,
            Kind::Install,
            Kind::List,
            Kind::Fetch,
            Kind::Sync,
            Kind::Restart,
        ] {
            notes.push(Note::Busy(kind, 600));
        }
        for step in [
            KeyStep::Changed,
            KeyStep::OtherKey {
                name: "my-server".into(),
            },
            KeyStep::Unclear,
        ] {
            notes.push(Note::Key(step));
        }
        for r in [
            Restarted::Started,
            Restarted::StillRunning,
            Restarted::StartFailed(1234),
            Restarted::NotStarted,
        ] {
            notes.push(Note::Restart(r));
        }
        for state in SyncState::ALL {
            notes.push(Note::Trouble(Trouble {
                state,
                cause: Cause::Plain,
                detail: String::new(),
            }));
        }
        notes.push(Note::Trouble(Trouble {
            state: SyncState::Server,
            cause: Cause::Plain,
            detail: "x".repeat(200),
        }));
        notes.push(Note::Trouble(Trouble {
            state: SyncState::Server,
            cause: Cause::ScriptMissing,
            detail: String::new(),
        }));
        notes.push(Note::Trouble(Trouble {
            state: SyncState::Server,
            cause: Cause::PythonMissing,
            detail: String::new(),
        }));
        for field in [
            Field::Host,
            Field::Remote,
            Field::Python,
            Field::Identity,
            Field::Interval,
            Field::Timeout,
            Field::Vault(0),
            Field::Vaults,
        ] {
            notes.push(bad(field, Why::Hash));
            notes.push(bad(field, Why::Config(field_problem(field))));
        }
        notes.push(bad(Field::Host, Why::Config(Problem::NoHost)));
        notes.push(bad(Field::Vaults, Why::TooLarge));
        for problem in [
            Problem::KeyFile,
            Problem::DuplicateVault,
            Problem::TooManyVaults,
            Problem::NoVault,
            Problem::Vault,
        ] {
            notes.push(Note::VaultRefused(Why::Config(problem)));
            notes.push(bad(Field::Vault(0), Why::Config(problem)));
        }
        notes
    }
    /// Every note's text in each state its wording depends on (running or
    /// not, saved or not, changed or not).
    fn note_texts(w: &Window) -> Vec<String> {
        w.app(|a| {
            let kept = (a.running, a.saved.clone(), a.fields.host.clone());
            let mut texts = vec![];
            for (running, saved, host) in [
                (false, false, ""),
                (false, true, "my-server"),
                (true, true, "my-server"),
                (true, false, "my-server"),
            ] {
                a.running = running;
                a.fields.host = host.into();
                a.saved = saved.then(|| a.fields.clone());
                texts.extend(every_note().iter().map(|n| a.note_text(n).0));
            }
            a.saved = Some(Fields::default());
            texts.push(a.note_text(&Note::Idle).0);
            (a.running, a.saved, a.fields.host) = kept;
            texts
        })
    }
    fn field_problem(field: Field) -> Problem {
        match field {
            Field::Host => Problem::Host,
            Field::Remote => Problem::Remote,
            Field::Python => Problem::Python,
            Field::Identity => Problem::Identity,
            Field::Interval => Problem::Interval,
            Field::Timeout => Problem::Timeout,
            Field::Vault(_) => Problem::Vault,
            Field::Vaults => Problem::NoVault,
        }
    }
    fn every_state() -> Vec<(String, Tone)> {
        let mut states = vec![];
        for live in [
            Live::NoVault,
            Live::NotSetUp,
            Live::Unusable,
            Live::HelperOff { server: 0 },
            Live::HelperOff { server: 123_456 },
        ] {
            states.push(live_text(live));
        }
        for state in SyncState::ALL {
            states.push(state_text(state, 123_456));
            states.push(state_text(state, 0));
        }
        let report = |state, server, up, down| {
            Outcome::Done(crate::engine::Report {
                state,
                server,
                uploaded: up,
                downloaded: down,
            })
        };
        for o in [
            Outcome::Locked,
            Outcome::Folder(Folder::NoVault),
            Outcome::Folder(Folder::Unusable),
            report(SyncState::Ok, 9, Some(123_456), None),
            report(SyncState::Ok, 9, None, Some(123_456)),
            report(SyncState::Ok, 123_456, None, None),
            report(SyncState::Ok, 0, None, None),
            report(SyncState::Offline, 3, None, None),
        ] {
            states.push(outcome_text(&o, Live::HelperOff { server: 0 }));
        }
        let entry = ListEntry {
            id: [0xA7; 16],
            head: 123_456,
            size: 8_388_608,
            mtime: 1_800_000_000,
        };
        let v = server_view(
            &entry,
            &[("a-long-vault-file-name.goyo".into(), [0xA7; 16])],
        );
        states.push((v.title, v.tone));
        states.push((v.detail, v.tone));
        states.push((v.state, v.tone));
        states.push((server_view(&entry, &[]).state, Tone::Muted));
        states
    }
    fn questions() -> Vec<String> {
        let c = setup::server_config(&Fields {
            host: "my-server".into(),
            ..Fields::default()
        })
        .unwrap();
        let keys = Trusted {
            name: Some("my-server".into()),
            known: Known::Keys(vec!["my-server ED25519 SHA256:abc".into()]),
            checked: Checked::Cancelled,
        };
        let none = Trusted {
            known: Known::Unclear,
            ..keys.clone()
        };
        vec![
            install_question(&c),
            trust_question("my-server"),
            fingerprint_text(&keys, "my-server"),
            fingerprint_text(&none, "my-server"),
            tr("저장하지 않은 변경이 있습니다. 저장하지 않고 닫을까요?").to_owned(),
        ]
    }

    /// Every label and button fits its box at this DPI in both languages,
    /// and every line message fits its two-line line, every row state its
    /// row (as labels_fit_their_boxes does for the vault app).
    #[test]
    fn labels_fit_in_both_languages() {
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
                DrawTextW(dc, s.as_ptr(), -1, &mut calc, 0x400 | 0x800 | flags);
                SelectObject(dc, old);
                ReleaseDC(h, dc);
                calc
            }
        }
        let mut failures = vec![];
        for english in [false, true] {
            i18n::set_english(english);
            let language = if english { "en" } else { "ko" };
            each_view(&mut |w, name| unsafe {
                let children = w.app(|a| a.children.clone());
                for child in children {
                    let class = class_of(child);
                    let text = read_text(child);
                    let mut r = Rect::default();
                    GetClientRect(child, &mut r);
                    if class == "Static" {
                        let font = SendMessageW(child, 0x31, 0, 0);
                        let need = measure(child, font, &text, r.right, 0x10 | 0x40).bottom;
                        if need > r.bottom {
                            failures.push(format!(
                                "{language} {name}: needs {need}px, has {}px: {text:?}",
                                r.bottom
                            ));
                        }
                    } else if class == "Button" {
                        let variant = GetWindowLongPtrW(child, -21);
                        let font = theme::with(|t| match variant {
                            theme::PRIMARY | theme::ACCENT | theme::TAB_ON => t.strong(),
                            theme::LINK | theme::CHIP => t.small(),
                            _ => t.body(),
                        })
                        .unwrap();
                        let pad = match variant {
                            theme::TOGGLE | theme::TOGGLE_ON => w.app(|a| a.px(52)),
                            _ => w.app(|a| a.px(12)),
                        };
                        let need = measure(child, font, &text, 0, 0x20).right + pad;
                        if need > r.right {
                            failures.push(format!(
                                "{language} {name}: button needs {need}px, has {}px: {text:?}",
                                r.right
                            ));
                        }
                    }
                }
                if name == "main" {
                    let line = w.app(|a| a.handle(SERVER_LINE));
                    let font = SendMessageW(line, 0x31, 0, 0);
                    let mut r = Rect::default();
                    GetClientRect(line, &mut r);
                    for text in note_texts(w) {
                        let need = measure(line, font, &text, r.right, 0x10 | 0x40).bottom;
                        if need > r.bottom {
                            failures.push(format!(
                                "{language} line: needs {need}px, has {}px: {text:?}",
                                r.bottom
                            ));
                        }
                    }
                    // Row states are one line next to a dot.
                    let list = w.app(|a| a.handle(VAULT_LIST));
                    let mut r = Rect::default();
                    GetClientRect(list, &mut r);
                    let room = r.right - w.app(|a| a.px(4 + 12 + 12 + 10));
                    let small = theme::with(|t| t.small()).unwrap();
                    for (text, _) in every_state() {
                        let need = measure(list, small, &text, 0, 0x20).right;
                        if need > room {
                            failures.push(format!(
                                "{language} row: needs {need}px, has {room}px: {text:?}"
                            ));
                        }
                    }
                }
            });
        }
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    }

    /// In English nothing in the window is Korean: controls, painted text,
    /// list rows, line messages and dialog texts.
    #[test]
    fn english_shows_no_korean() {
        let _korean = KoreanAfter;
        i18n::set_english(true);
        let mut shown = vec![];
        each_view(&mut |w, name| unsafe {
            for child in w.app(|a| a.children.clone()) {
                if matches!(class_of(child).as_str(), "Static" | "Button") {
                    shown.push((name.to_owned(), read_text(child)));
                }
            }
            theme::PAINTED.with(|p| p.borrow_mut().clear());
            let screen = GetDC(w.h);
            let dc = CreateCompatibleDC(screen);
            let bmp = CreateCompatibleBitmap(screen, 1600, 1400);
            ReleaseDC(w.h, screen);
            let old = SelectObject(dc, bmp);
            w.app(|a| a.draw(dc));
            SelectObject(dc, old);
            DeleteObject(bmp);
            DeleteDC(dc);
            for text in theme::PAINTED.with(|p| p.take()) {
                shown.push((name.to_owned(), text));
            }
            for rows in ROWS.with(|r| r.borrow().clone()) {
                for row in rows {
                    shown.push((name.to_owned(), row.state));
                    shown.push((name.to_owned(), row.title));
                }
            }
            if name == "main" {
                for text in note_texts(w) {
                    shown.push(("note".into(), text));
                }
            }
        });
        for (text, _) in every_state() {
            shown.push(("row".into(), text));
        }
        for text in questions() {
            shown.push(("dialog".into(), text));
        }
        shown.push(("title".into(), tr(TITLE).to_owned()));
        let korean: Vec<_> = shown
            .iter()
            .filter(|(_, text)| has_korean(text))
            .map(|(view, text)| format!("{view}: {text:?}"))
            .collect();
        assert!(
            korean.is_empty(),
            "Korean in English mode:\n{}",
            korean.join("\n")
        );
        assert!(
            shown
                .iter()
                .any(|(v, t)| v == "main" && t == "Save and start")
        );
        assert!(
            shown
                .iter()
                .any(|(v, t)| v == "main" && t.starts_with("OK · server version 12"))
        );
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn PrintWindow(h: Hwnd, dc: isize, flags: u32) -> i32;
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
    /// The client area as top-down 32-bit pixels and its BITMAPINFOHEADER.
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
            assert_ne!(PrintWindow(h, mem, 3), 0);
            SelectObject(mem, old);
            let mut info = [0u8; 44];
            info[0..4].copy_from_slice(&40u32.to_le_bytes());
            info[4..8].copy_from_slice(&w.to_le_bytes());
            info[8..12].copy_from_slice(&(-hh).to_le_bytes());
            info[12..14].copy_from_slice(&1u16.to_le_bytes());
            info[14..16].copy_from_slice(&32u16.to_le_bytes());
            let mut pixels = vec![0u8; (w * hh * 4) as usize];
            GetDIBits(
                mem,
                bmp,
                0,
                hh as u32,
                pixels.as_mut_ptr(),
                info.as_mut_ptr(),
                0,
            );
            DeleteObject(bmp);
            DeleteDC(mem);
            ReleaseDC(0, screen);
            (info, pixels)
        }
    }
    /// Grabs until two frames agree (DWM can hand back one with some
    /// controls not yet drawn), then writes a BMP.
    fn capture(h: Hwnd, path: &Path) {
        let (info, mut pixels) = grab(h);
        for _ in 0..20 {
            for _ in 0..4 {
                pump();
                std::thread::sleep(Duration::from_millis(40));
            }
            let (_, next) = grab(h);
            let same = pixels == next;
            pixels = next;
            if same {
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

    /// Renders the window in both themes and languages, the log view and a
    /// server list to `test-output/sync-ui-preview/*.bmp` for design review.
    /// It shows a real window briefly, so it runs only on request:
    /// `cargo test --bin goyo-sync sync_ui_preview -- --ignored`.
    #[test]
    #[ignore]
    fn sync_ui_preview() {
        let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-output/sync-ui-preview");
        std::fs::create_dir_all(&out).unwrap();
        // Before the theme makes its fonts: they follow the DPI then.
        unsafe {
            SetProcessDPIAware();
        }
        let _korean = KoreanAfter;
        for (english, dark) in [(false, true), (false, false), (true, true), (true, false)] {
            i18n::set_english(english);
            theme::set_dark(dark);
            let prefix = format!(
                "{}{}",
                if english { "en-" } else { "" },
                if dark { "dark" } else { "light" }
            );
            each_view(&mut |w, name| {
                apply_window_theme(w.h);
                w.app(|a| {
                    a.running = name != "empty";
                    a.build();
                });
                unsafe {
                    ShowWindow(w.h, 4);
                    RedrawWindow(w.h, null(), 0, 0x1 | 0x80 | 0x100);
                }
                capture(w.h, &out.join(format!("{prefix}-{name}.bmp")));
            });
        }
        theme::set_dark(true);
    }
}
