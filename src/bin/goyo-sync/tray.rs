//! The background helper's icon in the notification area (system tray).
//! Only `--background` shows it, and only one helper runs per exe path (its
//! instance mutex), so there is one icon; the settings window never makes
//! one. The icon lives on a hidden top-level window of the helper's main
//! thread (top-level, so it gets the shell's "TaskbarCreated" broadcast and
//! comes back after explorer restarts), while a worker thread syncs.
//!
//! The tooltip says how sync goes (checking, OK, vaults with a problem,
//! syncing now, stopping). Right-click, or the keyboard's context-menu key,
//! opens the menu: 설정 열기 starts `"<this exe>"` with no arguments (the
//! settings window, which brings an open one forward), 지금 동기화 asks the
//! worker for one forced pass over every vault, and 완전 종료 (동기화 중지)
//! removes the icon and ends the helper as `--stop` does. A double click or
//! Enter on the icon opens the settings too.
//!
//! The menu returns its choice to the code that opened it (TPM_RETURNCMD,
//! TPM_NONOTIFY), so no command ever arrives as a message, and the window
//! takes no WM_COMMAND, WM_SYSCOMMAND or WM_CLOSE at all. The icon's
//! notifications come from explorer, another program, so they are taken
//! from anyone; one sent from another thread is handled from the queue,
//! outside that send (as the settings window does with a close). What a
//! forged one can do, open the settings window, sync now or open the menu
//! for the user to choose from, any program of this user can already do by
//! running goyo-sync.exe. The worker's notice carries nothing: the window
//! reads the state the worker left in [`Signals`], so a forged notice
//! changes nothing. Commands, close and timers posted to it, and any
//! timer message that names a callback, are dropped (it sets no timer).
use crate::{
    engine::{Log, Outcome},
    i18n::{fill, tr},
    sys,
    win::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        GetModuleHandleW, GetSystemMetrics, Hwnd, IsWindow, LoadImageW, Msg, PostMessageW,
        PostQuitMessage, RegisterClassW, SetProcessDPIAware, TranslateMessage, WndClass,
        from_other_thread, in_modal, wide,
    },
};
use goyo_vault::syncfile::SyncState;
use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    path::PathBuf,
    ptr::{null, null_mut},
    rc::Rc,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

#[link(name = "shell32")]
unsafe extern "system" {
    fn Shell_NotifyIconW(message: u32, data: *const NotifyIconData) -> i32;
}
#[link(name = "user32")]
unsafe extern "system" {
    fn RegisterWindowMessageW(name: *const u16) -> u32;
    fn CreatePopupMenu() -> isize;
    fn AppendMenuW(menu: isize, flags: u32, id: usize, text: *const u16) -> i32;
    fn SetMenuDefaultItem(menu: isize, item: u32, by_position: u32) -> i32;
    fn TrackPopupMenuEx(
        menu: isize,
        flags: u32,
        x: i32,
        y: i32,
        h: Hwnd,
        params: *const c_void,
    ) -> i32;
    fn DestroyMenu(menu: isize) -> i32;
    fn SetForegroundWindow(h: Hwnd) -> i32;
}

/// NOTIFYICONDATAW (x64: 976 bytes).
#[repr(C)]
struct NotifyIconData {
    size: u32,
    hwnd: Hwnd,
    id: u32,
    flags: u32,
    callback: u32,
    icon: isize,
    tip: [u16; 128],
    state: u32,
    state_mask: u32,
    info: [u16; 256],
    version: u32,
    info_title: [u16; 64],
    info_flags: u32,
    guid: [u8; 16],
    balloon_icon: isize,
}
const NIM_ADD: u32 = 0;
const NIM_MODIFY: u32 = 1;
const NIM_DELETE: u32 = 2;
const NIM_SETVERSION: u32 = 4;
/// NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP.
const NIF_ALL: u32 = 0x1 | 0x2 | 0x4 | 0x80;
/// The icon's notifications: WM_APP + 1.
pub const WM_TRAY: u32 = 0x8001;
/// The worker's notice: its state changed or it ended (see [`Signals`]).
pub const WM_LOOP: u32 = 0x8002;
/// The one icon of this window.
const ICON_ID: u32 = 1;
// NOTIFYICON_VERSION_4 notifications (in the low word of lParam).
const WM_CONTEXTMENU: u32 = 0x7b;
const WM_LBUTTONDBLCLK: u32 = 0x203;
const NIN_KEYSELECT: u32 = 0x401;

/// What the worker thread and the icon's window share.
pub struct Signals {
    /// The named stop event: `--stop`, the settings window and this menu.
    stop: sys::Event,
    /// Wakes the worker from its 2 s wait for a "sync now".
    wake: sys::Event,
    now: AtomicBool,
    health: Mutex<Health>,
    ended: AtomicBool,
}
impl Signals {
    pub fn new(stop: sys::Event) -> Option<Self> {
        Some(Self {
            stop,
            wake: sys::Event::wake()?,
            now: AtomicBool::new(false),
            health: Mutex::new(Health::Starting),
            ended: AtomicBool::new(false),
        })
    }
    /// The stop event's handle, for the transport's waits.
    pub fn stop_handle(&self) -> isize {
        self.stop.raw()
    }
    pub fn stop(&self) {
        self.stop.set();
    }
    pub fn stopping(&self) -> bool {
        sys::wait(self.stop.raw(), 0)
    }
    /// Asks the worker for one forced pass over every vault.
    pub fn sync_now(&self) {
        self.now.store(true, Ordering::SeqCst);
        self.wake.set();
    }
    /// Whether a "sync now" was asked since the last call.
    pub fn take_now(&self) -> bool {
        self.now.swap(false, Ordering::SeqCst)
    }
    /// Waits up to `ms` for the stop event or a "sync now"; true on stop.
    pub fn wait(&self, ms: u32) -> bool {
        sys::wait_any(&[self.stop.raw(), self.wake.raw()], ms) == Some(0)
    }
    pub fn health(&self) -> Health {
        *self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// The worker's state; the window `notify` (0: none) hears of a change.
    pub fn report(&self, notify: Hwnd, health: Health) {
        let changed = {
            let mut now = self.health.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *now, health) != health
        };
        if changed && notify != 0 {
            unsafe {
                PostMessageW(notify, WM_LOOP, 0, 0);
            }
        }
    }
    /// The worker is done; the window removes its icon and ends.
    pub fn end(&self, notify: Hwnd) {
        self.ended.store(true, Ordering::SeqCst);
        if notify != 0 {
            unsafe {
                PostMessageW(notify, WM_LOOP, 0, 0);
            }
        }
    }
    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

/// How sync goes, for the tooltip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// No pass has finished yet.
    Starting,
    Ok,
    /// This many vaults had a problem at their last pass.
    Problem(usize),
    /// A "sync now" runs.
    Syncing,
    /// The helper was asked to stop and is ending its pass.
    Stopping,
}
/// The overall state from each vault's last outcome (None: none yet). A
/// vault another goyo-sync held (`Locked`) keeps its earlier outcome.
pub fn health(last: &[Option<Outcome>]) -> Health {
    let problems = last
        .iter()
        .flatten()
        .filter(|o| match o {
            Outcome::Locked => false,
            Outcome::Folder(_) => true,
            Outcome::Done(r) => !matches!(r.state, SyncState::Ok | SyncState::Idle),
        })
        .count();
    if problems > 0 {
        Health::Problem(problems)
    } else if last.iter().flatten().any(|o| *o != Outcome::Locked) {
        Health::Ok
    } else {
        Health::Starting
    }
}
/// The tooltip (at most 127 UTF-16 units: it is cut to fit anyway).
pub fn tip(health: Health) -> String {
    let state = match health {
        Health::Starting => tr("확인 중").to_owned(),
        Health::Ok => tr("정상").to_owned(),
        Health::Problem(n) => fill("문제 있는 금고 {}개", &[&n]),
        Health::Syncing => tr("지금 동기화하는 중").to_owned(),
        Health::Stopping => tr("멈추는 중").to_owned(),
    };
    fill("고요 금고 동기화 · {}", &[&state])
}

/// The menu's commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    OpenSettings,
    SyncNow,
    Quit,
}
/// The menu: item id, command, Korean label (shown through tr()).
const MENU: [(u32, Command, &str); 3] = [
    (1, Command::OpenSettings, "설정 열기"),
    (2, Command::SyncNow, "지금 동기화"),
    (3, Command::Quit, "완전 종료 (동기화 중지)"),
];
/// The items as shown: id and label. A separator goes before 완전 종료;
/// 설정 열기, what a double click does, is the default (bold).
pub fn menu_items() -> Vec<(u32, String)> {
    MENU.iter()
        .map(|(id, _, label)| (*id, tr(label).to_owned()))
        .collect()
}
pub fn command_of(id: u32) -> Option<Command> {
    MENU.iter().find(|(i, ..)| *i == id).map(|(_, c, _)| *c)
}

/// What the icon's window does outside itself. Tests use a fake: no test
/// adds a real icon or starts a process.
pub trait Shell {
    /// Adds, changes or removes the icon (with this tooltip).
    fn icon(&self, h: Hwnd, op: Op, tip: &str) -> bool;
    /// Shows the menu at (x, y) and returns the chosen item's id.
    fn menu(&self, h: Hwnd, x: i32, y: i32, items: &[(u32, String)]) -> Option<u32>;
    /// Starts the settings window: this exe, with no arguments.
    fn open_settings(&self) -> Result<(), u32>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Add,
    Modify,
    Delete,
}
/// The real one.
pub struct Windows {
    pub exe: PathBuf,
    pub icon: isize,
}
impl Shell for Windows {
    fn icon(&self, h: Hwnd, op: Op, tip: &str) -> bool {
        // SAFETY: plain data; all-zero is a valid NOTIFYICONDATAW.
        let mut data: NotifyIconData = unsafe { std::mem::zeroed() };
        data.size = size_of::<NotifyIconData>() as u32;
        data.hwnd = h;
        data.id = ICON_ID;
        data.flags = NIF_ALL;
        data.callback = WM_TRAY;
        data.icon = self.icon;
        for (slot, c) in data.tip.iter_mut().zip(tip.encode_utf16().take(127)) {
            *slot = c;
        }
        let message = match op {
            Op::Add => NIM_ADD,
            Op::Modify => NIM_MODIFY,
            Op::Delete => NIM_DELETE,
        };
        let ok = unsafe { Shell_NotifyIconW(message, &data) } != 0;
        if ok && op == Op::Add {
            // NOTIFYICON_VERSION_4: WM_CONTEXTMENU for the right button and
            // the menu key, with the anchor point in wParam.
            data.version = 4;
            unsafe {
                Shell_NotifyIconW(NIM_SETVERSION, &data);
            }
        }
        ok
    }
    fn menu(&self, h: Hwnd, x: i32, y: i32, items: &[(u32, String)]) -> Option<u32> {
        unsafe {
            let menu = CreatePopupMenu();
            if menu == 0 {
                return None;
            }
            fill_menu(menu, items);
            // The menu closes when the user clicks elsewhere only if its
            // window is in front; the posted WM_NULL lets the next click
            // after it work (KB135788).
            SetForegroundWindow(h);
            // TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD
            let chosen = TrackPopupMenuEx(menu, 0x2 | 0x80 | 0x100, x, y, h, null());
            PostMessageW(h, 0, 0, 0);
            DestroyMenu(menu);
            u32::try_from(chosen).ok().filter(|id| *id != 0)
        }
    }
    fn open_settings(&self) -> Result<(), u32> {
        sys::start_detached(&self.exe, "")
    }
}
/// The items, a separator before the last one, and the first as default.
unsafe fn fill_menu(menu: isize, items: &[(u32, String)]) -> bool {
    let mut ok = true;
    for (i, (id, label)) in items.iter().enumerate() {
        unsafe {
            if i + 1 == items.len() && i > 0 {
                ok &= AppendMenuW(menu, 0x800, 0, null()) != 0; // MF_SEPARATOR
            }
            ok &= AppendMenuW(menu, 0, *id as usize, wide(label).as_ptr()) != 0;
        }
    }
    if let Some((id, _)) = items.first() {
        unsafe {
            SetMenuDefaultItem(menu, *id, 0);
        }
    }
    ok
}

/// The icon's window state, on the main thread.
struct Tray {
    shell: Rc<dyn Shell>,
    signals: std::sync::Arc<Signals>,
    log: Log,
    /// The icon is in the notification area (as far as we know).
    shown: bool,
    tip: String,
    /// 완전 종료 was chosen: the icon is gone and stays gone.
    quitting: bool,
}
impl Tray {
    /// Adds the icon unless it is there (or the helper is ending).
    fn show(&mut self, h: Hwnd) {
        if self.quitting {
            return;
        }
        self.tip = tip(self.signals.health());
        self.shown = self.shell.icon(h, Op::Add, &self.tip);
    }
    fn hide(&mut self, h: Hwnd) {
        if std::mem::take(&mut self.shown) {
            self.shell.icon(h, Op::Delete, "");
        }
    }
    /// The worker's notice: the tooltip follows its state (an icon that
    /// could not be added is tried again). True when the worker ended and
    /// the window should go.
    fn notice(&mut self, h: Hwnd) -> bool {
        if !self.quitting {
            let tip = tip(self.signals.health());
            if !self.shown {
                self.show(h);
            } else if tip != self.tip {
                self.shell.icon(h, Op::Modify, &tip);
                self.tip = tip;
            }
        }
        self.signals.ended()
    }
    /// Explorer started again (or for the first time): its new taskbar has
    /// no icon of ours.
    fn taskbar_created(&mut self, h: Hwnd) {
        self.shown = false;
        self.show(h);
    }
    /// A menu command. True when the window should go.
    fn command(&mut self, h: Hwnd, command: Command) -> bool {
        if self.quitting {
            return self.signals.ended();
        }
        match command {
            Command::OpenSettings => {
                if let Err(code) = self.shell.open_settings() {
                    self.log
                        .line(&format!("tray: the settings window did not start ({code})"));
                }
            }
            Command::SyncNow => {
                self.signals.sync_now();
                self.signals.report(0, Health::Syncing);
                self.notice(h);
            }
            Command::Quit => {
                self.log.line("tray: stop requested");
                self.quitting = true;
                self.signals.stop();
                self.hide(h);
            }
        }
        self.signals.ended()
    }
}

thread_local! {
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
    /// The shell's "TaskbarCreated" message (registered at create).
    static TASKBAR_CREATED: Cell<u32> = const { Cell::new(0) };
}
fn with_tray<T>(f: impl FnOnce(&mut Tray) -> T) -> Option<T> {
    TRAY.with(|cell| {
        cell.try_borrow_mut()
            .ok()
            .and_then(|mut t| t.as_mut().map(f))
    })
}
/// Ends the window (outside any borrow of TRAY): WM_DESTROY removes the
/// icon and ends the message loop.
fn finish(h: Hwnd, done: Option<bool>) {
    if done == Some(true) {
        unsafe {
            DestroyWindow(h);
        }
    }
}

/// The app icon at the small-icon size of this DPI.
pub fn app_icon() -> isize {
    unsafe {
        LoadImageW(
            GetModuleHandleW(null()),
            std::ptr::without_provenance(1),
            1,
            GetSystemMetrics(49),
            GetSystemMetrics(50),
            0,
        )
    }
}
/// Registers `class` (once), creates the hidden window and adds the icon
/// (or tries to: see [`Tray::notice`]). None if Windows made no window.
pub fn create(
    class: &str,
    shell: Rc<dyn Shell>,
    signals: std::sync::Arc<Signals>,
    log: Log,
) -> Option<Hwnd> {
    let h = window(class)?;
    TASKBAR_CREATED
        .with(|t| t.set(unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) }));
    let mut tray = Tray {
        shell,
        signals,
        log,
        shown: false,
        tip: String::new(),
        quitting: false,
    };
    tray.show(h);
    TRAY.with(|cell| *cell.borrow_mut() = Some(tray));
    Some(h)
}
fn window(class: &str) -> Option<Hwnd> {
    unsafe {
        let instance = GetModuleHandleW(null());
        let name = wide(class);
        let wc = WndClass {
            style: 0,
            proc: Some(tray_proc),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon: 0,
            cursor: 0,
            background: 0,
            menu: null(),
            class: name.as_ptr(),
        };
        RegisterClassW(&wc); // fails harmlessly when already registered
        // WS_EX_TOOLWINDOW, WS_POPUP, never shown.
        let h = CreateWindowExW(
            0x80,
            name.as_ptr(),
            wide(tr("고요 금고 동기화")).as_ptr(),
            0x8000_0000u32,
            0,
            0,
            0,
            0,
            0,
            0,
            instance,
            null_mut(),
        );
        (h != 0).then_some(h)
    }
}
/// The window's message loop, until the window is gone (or a WM_QUIT came
/// from elsewhere: then the window goes now, removing the icon).
pub fn run(h: Hwnd) {
    unsafe {
        let mut msg = Msg::default();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            if !accept_queued(h, &msg) {
                continue;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if IsWindow(h) != 0 {
            DestroyWindow(h);
        }
    }
}
/// Posted messages the window never posts to itself: commands, close and
/// timers (it has none). A timer message naming a callback is dropped for
/// any window of this thread: this program sets no timer callback.
fn accept_queued(h: Hwnd, msg: &Msg) -> bool {
    match msg.message {
        0x113 | 0x118 => msg.hwnd != h && msg.lparam == 0,
        0x10 | 0x111 | 0x112 => msg.hwnd != h,
        _ => true,
    }
}
unsafe extern "system" fn tray_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    let other = from_other_thread();
    match m {
        WM_TRAY if other => {
            // Handled from the queue, outside the sender's send: a menu
            // run inside it would count as sent from another thread.
            unsafe {
                PostMessageW(h, WM_TRAY, w, l);
            }
            return 0;
        }
        WM_TRAY => {
            notification(h, w, l);
            return 0;
        }
        WM_LOOP => {
            if !other {
                let done = with_tray(|t| t.notice(h));
                finish(h, done);
            }
            return 0;
        }
        // No command, system command or close: the menu and the stop
        // event are the only ways to end the helper.
        0x10 | 0x111 | 0x112 => return 0,
        0x02 => {
            if let Some(mut tray) =
                TRAY.with(|cell| cell.try_borrow_mut().ok().and_then(|mut t| t.take()))
            {
                tray.hide(h);
            }
            unsafe {
                PostQuitMessage(0);
            }
            return 0;
        }
        _ => {}
    }
    if m != 0 && m == TASKBAR_CREATED.with(Cell::get) {
        with_tray(|t| t.taskbar_created(h));
        return 0;
    }
    unsafe { DefWindowProcW(h, m, w, l) }
}
/// The icon's notification (NOTIFYICON_VERSION_4): the event in the low
/// word of lParam, the anchor point in wParam.
fn notification(h: Hwnd, w: usize, l: isize) {
    let event = (l & 0xffff) as u32;
    if (l >> 16) & 0xffff != ICON_ID as isize {
        return;
    }
    let command = match event {
        WM_CONTEXTMENU => {
            if in_modal() {
                return;
            }
            let Some(shell) = with_tray(|t| (!t.quitting).then(|| t.shell.clone())).flatten()
            else {
                return;
            };
            let x = (w & 0xffff) as u16 as i16 as i32;
            let y = ((w >> 16) & 0xffff) as u16 as i16 as i32;
            // The menu runs with TRAY free: it pumps messages.
            match shell.menu(h, x, y, &menu_items()).and_then(command_of) {
                Some(command) => command,
                None => return,
            }
        }
        WM_LBUTTONDBLCLK | NIN_KEYSELECT => Command::OpenSettings,
        _ => return,
    };
    let done = with_tray(|t| t.command(h, command));
    finish(h, done);
}

/// For `--self-check`: the hidden window and the menu built (never shown,
/// no icon added), then destroyed.
pub fn self_check() -> bool {
    let class = format!("GoyoSyncTraySelfCheck-{}", std::process::id());
    let Some(h) = window(&class) else {
        return false;
    };
    let ok = unsafe {
        let menu = CreatePopupMenu();
        let filled = menu != 0 && fill_menu(menu, &menu_items());
        if menu != 0 {
            DestroyMenu(menu);
        }
        filled
    };
    unsafe {
        DestroyWindow(h);
    }
    // The test harness has no icon resource; the exe must.
    ok && (cfg!(test) || app_icon() != 0)
}
/// The background helper's window and icon (then [`run`] its message
/// loop). Called on the main thread; the DPI awareness makes the icon sharp.
pub fn start(
    class: &str,
    exe: PathBuf,
    signals: std::sync::Arc<Signals>,
    log: Log,
) -> Option<Hwnd> {
    unsafe {
        SetProcessDPIAware();
    }
    let shell = Rc::new(Windows {
        exe,
        icon: app_icon(),
    });
    create(class, shell, signals, log)
}

#[cfg(test)]
pub fn layout_size() -> usize {
    size_of::<NotifyIconData>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::{Folder, Report},
        tests::Temp,
    };
    use std::sync::Arc;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn SendMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> isize;
        fn PeekMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32, remove: u32) -> i32;
    }

    /// What the window did outside itself, instead of doing it.
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        /// The menu's answer.
        choose: Cell<Option<u32>>,
        /// Whether an add works (explorer is there).
        add_fails: Cell<bool>,
        menus: RefCell<Vec<Vec<(u32, String)>>>,
    }
    impl Shell for Fake {
        fn icon(&self, _: Hwnd, op: Op, tip: &str) -> bool {
            self.calls
                .borrow_mut()
                .push(format!("{op:?} {tip}").trim_end().to_owned());
            !(op == Op::Add && self.add_fails.get())
        }
        fn menu(&self, _: Hwnd, x: i32, y: i32, items: &[(u32, String)]) -> Option<u32> {
            self.calls.borrow_mut().push(format!("menu {x},{y}"));
            self.menus.borrow_mut().push(items.to_vec());
            self.choose.get()
        }
        fn open_settings(&self) -> Result<(), u32> {
            self.calls.borrow_mut().push("open settings".into());
            Ok(())
        }
    }
    fn calls(fake: &Fake) -> Vec<String> {
        std::mem::take(&mut *fake.calls.borrow_mut())
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
    /// Signals with a stop event of their own (named, like the real one,
    /// but never another test's).
    fn signals() -> Arc<Signals> {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let name = format!(
            r"Local\GoyoSyncTrayTest-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        Arc::new(Signals::new(sys::Event::create(&name).unwrap()).unwrap())
    }
    struct Window {
        h: Hwnd,
        fake: Rc<Fake>,
        signals: Arc<Signals>,
        _t: Temp,
    }
    impl Window {
        fn new(name: &str, add_fails: bool) -> Self {
            let t = Temp::new(name);
            let fake = Rc::new(Fake::default());
            fake.add_fails.set(add_fails);
            let signals = signals();
            let h = create(
                &format!("GoyoSyncTrayTest-{name}"),
                fake.clone(),
                signals.clone(),
                Log::new(Some(t.0.join(crate::LOG))),
            )
            .unwrap();
            Self {
                h,
                fake,
                signals,
                _t: t,
            }
        }
        fn send(&self, m: u32, w: usize, l: isize) {
            unsafe {
                SendMessageW(self.h, m, w, l);
            }
        }
        /// The icon's notification as explorer sends it.
        fn notify(&self, event: u32, x: i16, y: i16) {
            let w = (x as u16 as usize) | ((y as u16 as usize) << 16);
            self.send(WM_TRAY, w, (event | (ICON_ID << 16)) as isize);
        }
        fn alive(&self) -> bool {
            unsafe { IsWindow(self.h) != 0 }
        }
    }
    impl Drop for Window {
        fn drop(&mut self) {
            if self.alive() {
                unsafe {
                    DestroyWindow(self.h);
                }
            }
            pump();
        }
    }
    fn has_korean(s: &str) -> bool {
        s.chars().any(|c| ('\u{ac00}'..='\u{d7a3}').contains(&c))
    }

    #[test]
    fn the_icon_data_has_the_windows_layout() {
        assert_eq!(layout_size(), 976);
    }

    /// Right-click (or the menu key) opens the menu at the anchor point;
    /// each item does its own thing: 설정 열기 starts the settings window,
    /// 지금 동기화 signals the worker, 완전 종료 removes the icon at once,
    /// stops the worker, and the window ends when the worker has ended.
    /// A double click and Enter open the settings.
    #[test]
    fn the_menu_commands_do_what_they_say() {
        let _korean = crate::tests::KoreanAfter::hold();
        crate::i18n::set_english(false);
        let w = Window::new("tray-menu", false);
        assert_eq!(calls(&w.fake), ["Add 고요 금고 동기화 · 확인 중"]);
        // The menu: three items, ids mapping to the commands.
        let items = menu_items();
        assert_eq!(
            items,
            [
                (1, "설정 열기".to_owned()),
                (2, "지금 동기화".to_owned()),
                (3, "완전 종료 (동기화 중지)".to_owned()),
            ]
        );
        assert_eq!(command_of(1), Some(Command::OpenSettings));
        assert_eq!(command_of(2), Some(Command::SyncNow));
        assert_eq!(command_of(3), Some(Command::Quit));
        assert_eq!(command_of(0), None);
        assert_eq!(command_of(4), None);
        // Dismissed: nothing.
        w.fake.choose.set(None);
        w.notify(WM_CONTEXTMENU, 1200, -5);
        assert_eq!(calls(&w.fake), ["menu 1200,-5"]);
        assert_eq!(w.fake.menus.borrow()[0], items);
        // 설정 열기.
        w.fake.choose.set(Some(1));
        w.notify(WM_CONTEXTMENU, 10, 20);
        assert_eq!(calls(&w.fake), ["menu 10,20", "open settings"]);
        // A double click and Enter (NIN_KEYSELECT) open the settings; a
        // single click, or an event for another icon id, does nothing.
        w.notify(WM_LBUTTONDBLCLK, 0, 0);
        w.notify(NIN_KEYSELECT, 0, 0);
        w.notify(0x202, 0, 0);
        w.send(WM_TRAY, 0, (WM_LBUTTONDBLCLK | (7 << 16)) as isize);
        assert_eq!(calls(&w.fake), ["open settings", "open settings"]);
        // 지금 동기화: the worker is woken with a forced pass asked, and
        // the tooltip says so.
        assert!(!w.signals.take_now());
        w.fake.choose.set(Some(2));
        w.notify(WM_CONTEXTMENU, 10, 20);
        assert_eq!(
            calls(&w.fake),
            ["menu 10,20", "Modify 고요 금고 동기화 · 지금 동기화하는 중"]
        );
        assert!(!w.signals.wait(0), "the wake is not a stop");
        assert!(w.signals.take_now());
        assert!(!w.signals.take_now());
        assert!(!w.signals.stopping());
        // The worker's notices change the tooltip.
        w.signals.report(w.h, Health::Problem(2));
        pump();
        assert_eq!(
            calls(&w.fake),
            ["Modify 고요 금고 동기화 · 문제 있는 금고 2개"]
        );
        // 완전 종료: the icon goes at once and the stop event is set; the
        // window waits for the worker.
        w.fake.choose.set(Some(3));
        w.notify(WM_CONTEXTMENU, 10, 20);
        assert_eq!(calls(&w.fake), ["menu 10,20", "Delete"]);
        assert!(w.signals.stopping());
        assert!(w.alive());
        // Nothing brings it back meanwhile.
        let taskbar = TASKBAR_CREATED.with(Cell::get);
        w.send(taskbar, 0, 0);
        w.notify(WM_CONTEXTMENU, 10, 20);
        w.notify(WM_LBUTTONDBLCLK, 0, 0);
        w.signals.report(w.h, Health::Stopping);
        pump();
        assert!(calls(&w.fake).is_empty());
        // The worker ended: the window goes, without a second delete.
        w.signals.end(w.h);
        pump();
        assert!(!w.alive());
        assert!(calls(&w.fake).is_empty());
        assert!(TRAY.with(|t| t.borrow().is_none()));
    }

    /// The helper stopped from elsewhere (`--stop`, the settings window):
    /// the worker ends and the window removes its icon on its way out.
    #[test]
    fn a_stop_from_elsewhere_removes_the_icon() {
        let w = Window::new("tray-stop", false);
        calls(&w.fake);
        w.signals.stop();
        w.signals.report(w.h, Health::Stopping);
        pump();
        assert_eq!(calls(&w.fake).len(), 1, "the tooltip says it stops");
        assert!(w.alive());
        w.signals.end(w.h);
        pump();
        assert!(!w.alive());
        assert_eq!(calls(&w.fake), ["Delete"]);
        // A WM_QUIT from elsewhere ends the loop and the window with it.
        let w = Window::new("tray-quit", false);
        calls(&w.fake);
        unsafe {
            PostMessageW(0, 0x12, 0, 0);
        }
        run(w.h);
        assert!(!w.alive());
        assert_eq!(calls(&w.fake), ["Delete"]);
    }

    /// Explorer restarted: its "TaskbarCreated" broadcast adds the icon
    /// again. An icon that could not be added at the start (no taskbar
    /// yet) comes with that broadcast, or with the worker's next notice.
    #[test]
    fn taskbar_created_adds_the_icon_again() {
        let w = Window::new("tray-taskbar", false);
        let taskbar = TASKBAR_CREATED.with(Cell::get);
        assert_ne!(taskbar, 0);
        assert_eq!(calls(&w.fake).len(), 1);
        w.send(taskbar, 0, 0);
        assert_eq!(calls(&w.fake), [format!("Add {}", tip(Health::Starting))]);
        drop(w);
        let w = Window::new("tray-late", true);
        assert_eq!(calls(&w.fake).len(), 1);
        w.signals.report(w.h, Health::Ok);
        pump();
        assert_eq!(calls(&w.fake), [format!("Add {}", tip(Health::Ok))]);
        w.fake.add_fails.set(false);
        w.send(taskbar, 0, 0);
        assert_eq!(calls(&w.fake), [format!("Add {}", tip(Health::Ok))]);
        w.signals.report(w.h, Health::Problem(1));
        pump();
        assert_eq!(
            calls(&w.fake),
            [format!("Modify {}", tip(Health::Problem(1)))]
        );
    }

    /// The icon's notification sent from another thread (explorer is
    /// another program) is handled once, from the queue. Commands, close
    /// and the worker's notice sent from another thread do nothing, and
    /// posted commands, close and timers are dropped.
    #[test]
    fn foreign_messages_reach_only_the_icon() {
        let w = Window::new("tray-foreign", false);
        calls(&w.fake);
        let h = w.h;
        let other = std::thread::spawn(move || unsafe {
            let dbl = (WM_LBUTTONDBLCLK | (ICON_ID << 16)) as isize;
            SendMessageW(h, WM_TRAY, 0, dbl);
            SendMessageW(h, 0x10, 0, 0);
            SendMessageW(h, 0x111, 3, 0);
            SendMessageW(h, 0x112, 0xf060, 0);
        });
        while !other.is_finished() {
            pump();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        other.join().unwrap();
        pump();
        assert_eq!(calls(&w.fake), ["open settings"]);
        assert!(w.alive());
        assert!(!w.signals.stopping());
        // A notice sent from another thread is not read, even after the end.
        w.signals.ended.store(true, Ordering::SeqCst);
        let other = std::thread::spawn(move || unsafe { SendMessageW(h, WM_LOOP, 0, 0) });
        while !other.is_finished() {
            pump();
        }
        other.join().unwrap();
        assert!(w.alive());
        for m in [0x10, 0x111, 0x112, 0x113, 0x118] {
            let msg = Msg {
                hwnd: h,
                message: m,
                ..Msg::default()
            };
            assert!(!accept_queued(h, &msg), "{m:#x}");
        }
        for m in [WM_TRAY, WM_LOOP, 0] {
            let msg = Msg {
                hwnd: h,
                message: m,
                ..Msg::default()
            };
            assert!(accept_queued(h, &msg), "{m:#x}");
        }
        // Another window of this thread (the IME's) keeps its own timers,
        // never one that names a callback.
        let timer = |lparam| Msg {
            hwnd: h + 4,
            message: 0x113,
            lparam,
            ..Msg::default()
        };
        assert!(accept_queued(h, &timer(0)));
        assert!(!accept_queued(h, &timer(0x1234)));
        assert!(!accept_queued(
            h,
            &Msg {
                hwnd: 0,
                message: 0x113,
                lparam: 0x1234,
                ..Msg::default()
            }
        ));
    }

    /// The tooltip's state from each vault's last pass.
    #[test]
    fn the_tooltip_follows_the_passes() {
        let done = |state| {
            Some(Outcome::Done(Report {
                state,
                server: 1,
                uploaded: None,
                downloaded: None,
            }))
        };
        assert_eq!(health(&[]), Health::Starting);
        assert_eq!(health(&[None, None]), Health::Starting);
        assert_eq!(health(&[Some(Outcome::Locked), None]), Health::Starting);
        assert_eq!(health(&[done(SyncState::Ok), None]), Health::Ok);
        assert_eq!(
            health(&[done(SyncState::Idle), Some(Outcome::Locked)]),
            Health::Ok
        );
        assert_eq!(
            health(&[done(SyncState::Ok), done(SyncState::Offline)]),
            Health::Problem(1)
        );
        assert_eq!(
            health(&[
                Some(Outcome::Folder(Folder::NoVault)),
                done(SyncState::Auth),
                done(SyncState::Ok)
            ]),
            Health::Problem(2)
        );
    }

    /// The tooltip and the menu in both languages: English has no Korean,
    /// and every tooltip fits the 127 units the shell keeps.
    #[test]
    fn tooltip_and_menu_in_both_languages() {
        let _korean = crate::tests::KoreanAfter::hold();
        let all = [
            Health::Starting,
            Health::Ok,
            Health::Problem(8),
            Health::Syncing,
            Health::Stopping,
        ];
        for english in [false, true] {
            crate::i18n::set_english(english);
            let mut shown: Vec<String> = all.iter().map(|h| tip(*h)).collect();
            for t in &shown {
                assert!(t.encode_utf16().count() <= 127, "{t}");
            }
            shown.extend(menu_items().into_iter().map(|(_, label)| label));
            shown.push(tr("고요 금고 동기화").to_owned());
            for t in &shown {
                assert_eq!(has_korean(t), !english, "{t}");
            }
        }
        crate::i18n::set_english(true);
        assert_eq!(tip(Health::Ok), "Goyo Vault Sync · OK");
        assert_eq!(menu_items()[2].1, "Quit (stop syncing)");
    }

    /// 설정 열기 starts this exe by its full path in quotes and nothing
    /// else (no argument: the settings window); the helper itself is
    /// started with the one fixed argument `--background`.
    #[test]
    fn the_settings_command_line_is_the_exe_alone() {
        let exe = std::path::Path::new(r"C:\Users\me\Goyo Vault\goyo-sync.exe");
        assert_eq!(
            sys::command_line(exe, "").unwrap(),
            r#""C:\Users\me\Goyo Vault\goyo-sync.exe""#
        );
        assert_eq!(
            sys::command_line(exe, "--background").unwrap(),
            crate::autostart_command(exe)
        );
        assert_eq!(
            sys::command_line(std::path::Path::new(r#"C:\a"b\goyo-sync.exe"#), ""),
            None
        );
    }

    /// The worker: no pass while none is due; a "sync now" runs one forced
    /// pass over every vault and the tooltip state follows the outcomes;
    /// the stop event ends it at once, also while it waits.
    #[test]
    fn sync_now_runs_one_forced_pass_and_stop_ends_the_loop() {
        use std::sync::Mutex;
        struct Fake(Arc<Mutex<Vec<(usize, bool)>>>);
        impl crate::Passes for Fake {
            fn vaults(&self) -> usize {
                2
            }
            fn due(&self, _: usize) -> bool {
                false
            }
            fn pass(&mut self, i: usize, force: bool) -> Outcome {
                self.0.lock().unwrap().push((i, force));
                if i == 0 {
                    Outcome::Folder(Folder::NoVault)
                } else {
                    Outcome::Locked
                }
            }
        }
        let signals = signals();
        let passes = Arc::new(Mutex::new(vec![]));
        let worker = {
            let (signals, passes) = (signals.clone(), passes.clone());
            std::thread::spawn(move || crate::run_passes(&mut Fake(passes), &signals, 0))
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(passes.lock().unwrap().is_empty());
        assert_eq!(signals.health(), Health::Starting);
        signals.sync_now();
        let start = std::time::Instant::now();
        while signals.health() != Health::Problem(1) {
            assert!(start.elapsed().as_secs() < 10, "no pass");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(*passes.lock().unwrap(), [(0, true), (1, true)]);
        // Stop while it waits its 2 s tick: it ends well before.
        let start = std::time::Instant::now();
        signals.stop();
        worker.join().unwrap();
        assert!(start.elapsed().as_millis() < 1500);
        assert_eq!(signals.health(), Health::Stopping);
        assert_eq!(passes.lock().unwrap().len(), 2);
    }

    /// The window and menu of `--self-check` are built without an icon.
    #[test]
    fn self_check_builds_the_window_and_menu() {
        assert!(self_check());
    }
}
