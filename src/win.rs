//! Minimal Win32 UI/clipboard/defense bindings. Cryptography never calls Win32.
#![allow(non_snake_case, dead_code)]
use crate::i18n::tr;
use std::{
    ffi::c_void,
    mem::size_of,
    path::PathBuf,
    sync::atomic::{AtomicIsize, Ordering},
};
use zeroize::Zeroizing;
pub type Hwnd = isize;
pub type Proc = unsafe extern "system" fn(Hwnd, u32, usize, isize) -> isize;
#[repr(C)]
pub struct WndClass {
    pub style: u32,
    pub proc: Option<Proc>,
    pub cls_extra: i32,
    pub wnd_extra: i32,
    pub instance: isize,
    pub icon: isize,
    pub cursor: isize,
    pub background: isize,
    pub menu: *const u16,
    pub class: *const u16,
}
#[repr(C)]
#[derive(Default)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}
#[repr(C)]
#[derive(Default)]
pub struct Size {
    pub cx: i32,
    pub cy: i32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}
#[repr(C)]
#[derive(Default)]
pub struct Msg {
    pub hwnd: Hwnd,
    pub message: u32,
    pub wparam: usize,
    pub lparam: isize,
    pub time: u32,
    pub pt: Point,
    pub private: u32,
}
#[repr(C)]
pub struct DrawItem {
    pub ctl_type: u32,
    pub ctl_id: u32,
    pub item_id: u32,
    pub action: u32,
    pub state: u32,
    pub item: Hwnd,
    pub dc: isize,
    pub rect: Rect,
    pub data: usize,
}
#[repr(C)]
pub struct Paint {
    pub dc: isize,
    pub erase: i32,
    pub rect: Rect,
    pub restore: i32,
    pub inc_update: i32,
    pub reserved: [u8; 32],
}
#[repr(C)]
struct OpenFile {
    size: u32,
    owner: Hwnd,
    instance: isize,
    filter: *const u16,
    custom: *mut u16,
    max_custom: u32,
    index: u32,
    file: *mut u16,
    max_file: u32,
    title_file: *mut u16,
    max_title: u32,
    initial: *const u16,
    title: *const u16,
    flags: u32,
    offset: u16,
    extension: u16,
    def_ext: *const u16,
    data: isize,
    hook: isize,
    template: *const u16,
    reserved: *mut c_void,
    reserved_dw: u32,
    flags_ex: u32,
}
#[repr(C)]
pub struct Version {
    pub size: u32,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform: u32,
    pub csd: [u16; 128],
}

#[link(name = "user32")]
unsafe extern "system" {
    pub fn RegisterClassW(c: *const WndClass) -> u16;
    pub fn CreateWindowExW(
        ex: u32,
        class: *const u16,
        title: *const u16,
        style: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        parent: Hwnd,
        menu: isize,
        inst: isize,
        param: *mut c_void,
    ) -> Hwnd;
    pub fn DefWindowProcW(h: Hwnd, m: u32, w: usize, l: isize) -> isize;
    pub fn CallWindowProcW(p: Option<Proc>, h: Hwnd, m: u32, w: usize, l: isize) -> isize;
    pub fn SetWindowLongPtrW(h: Hwnd, i: i32, v: isize) -> isize;
    pub fn GetWindowLongPtrW(h: Hwnd, i: i32) -> isize;
    pub fn GetMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32) -> i32;
    pub fn TranslateMessage(m: *const Msg) -> i32;
    pub fn DispatchMessageW(m: *const Msg) -> isize;
    pub fn IsDialogMessageW(h: Hwnd, m: *mut Msg) -> i32;
    pub fn ShowWindow(h: Hwnd, n: i32) -> i32;
    pub fn IsWindowVisible(h: Hwnd) -> i32;
    pub fn SetWindowsHookExW(
        id: i32,
        proc: unsafe extern "system" fn(i32, usize, isize) -> isize,
        module: isize,
        thread: u32,
    ) -> isize;
    pub fn UnhookWindowsHookEx(hook: isize) -> i32;
    pub fn CallNextHookEx(hook: isize, code: i32, w: usize, l: isize) -> isize;
    fn GetGUIThreadInfo(thread: u32, info: *mut GuiThreadInfo) -> i32;
    pub fn UpdateWindow(h: Hwnd) -> i32;
    pub fn DestroyWindow(h: Hwnd) -> i32;
    pub fn PostQuitMessage(code: i32);
    pub fn SendMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> isize;
    pub fn PostMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> i32;
    pub fn SetWindowTextW(h: Hwnd, s: *const u16) -> i32;
    pub fn GetWindowTextLengthW(h: Hwnd) -> i32;
    pub fn GetWindowTextW(h: Hwnd, s: *mut u16, n: i32) -> i32;
    pub fn EnableWindow(h: Hwnd, enable: i32) -> i32;
    pub fn SetFocus(h: Hwnd) -> Hwnd;
    pub fn GetFocus() -> Hwnd;
    pub fn GetParent(h: Hwnd) -> Hwnd;
    pub fn IsWindow(h: Hwnd) -> i32;
    pub fn GetClientRect(h: Hwnd, r: *mut Rect) -> i32;
    pub fn GetWindowRect(h: Hwnd, r: *mut Rect) -> i32;
    pub fn MapWindowPoints(from: Hwnd, to: Hwnd, points: *mut Point, count: u32) -> i32;
    pub fn SetWindowPos(h: Hwnd, after: Hwnd, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> i32;
    pub fn SetTimer(h: Hwnd, id: usize, ms: u32, callback: isize) -> usize;
    pub fn MessageBoxW(h: Hwnd, text: *const u16, title: *const u16, flags: u32) -> i32;
    fn AdjustWindowRectEx(r: *mut Rect, style: u32, menu: i32, ex: u32) -> i32;
    pub fn LoadCursorW(instance: isize, id: *const u16) -> isize;
    pub fn BeginPaint(h: Hwnd, p: *mut Paint) -> isize;
    pub fn GetDC(h: Hwnd) -> isize;
    pub fn ReleaseDC(h: Hwnd, dc: isize) -> i32;
    pub fn EndPaint(h: Hwnd, p: *const Paint) -> i32;
    pub fn InvalidateRect(h: Hwnd, r: *const Rect, erase: i32) -> i32;
    pub fn RedrawWindow(h: Hwnd, r: *const Rect, region: isize, flags: u32) -> i32;
    pub fn MessageBeep(kind: u32) -> i32;
    pub fn GetForegroundWindow() -> Hwnd;
    pub fn GetAncestor(h: Hwnd, flags: u32) -> Hwnd;
    fn GetWindowThreadProcessId(h: Hwnd, pid: *mut u32) -> u32;
    pub fn IsChild(parent: Hwnd, h: Hwnd) -> i32;
    fn InSendMessageEx(reserved: *const c_void) -> u32;
    pub fn RegisterSuspendResumeNotification(recipient: isize, flags: u32) -> isize;
    pub fn UnregisterSuspendResumeNotification(handle: isize) -> i32;
    pub fn LoadImageW(
        inst: isize,
        name: *const u16,
        kind: u32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> isize;
    pub fn DrawTextW(dc: isize, s: *const u16, n: i32, r: *mut Rect, format: u32) -> i32;
    pub fn FillRect(dc: isize, r: *const Rect, brush: isize) -> i32;
    pub fn SetWindowDisplayAffinity(h: Hwnd, affinity: u32) -> i32;
    pub fn GetWindowDisplayAffinity(h: Hwnd, affinity: *mut u32) -> i32;
    pub fn GetSystemMetrics(index: i32) -> i32;
    pub fn SetProcessDPIAware() -> i32;
    pub fn GetDpiForSystem() -> u32;
    pub fn OpenClipboard(h: Hwnd) -> i32;
    pub fn CloseClipboard() -> i32;
    pub fn EmptyClipboard() -> i32;
    pub fn SetClipboardData(format: u32, data: isize) -> isize;
    pub fn GetClipboardSequenceNumber() -> u32;
    pub fn GetClipboardOwner() -> Hwnd;
    pub fn GetClipboardData(format: u32) -> isize;
    pub fn DisableProcessWindowsGhosting();
    pub fn RegisterClipboardFormatW(name: *const u16) -> u32;
}
#[link(name = "gdi32")]
unsafe extern "system" {
    pub fn CreateFontW(
        height: i32,
        width: i32,
        esc: i32,
        orient: i32,
        weight: i32,
        italic: u32,
        underline: u32,
        strike: u32,
        charset: u32,
        out: u32,
        clip: u32,
        quality: u32,
        pitch: u32,
        face: *const u16,
    ) -> isize;
    pub fn SelectObject(dc: isize, obj: isize) -> isize;
    pub fn GetTextExtentPoint32W(dc: isize, text: *const u16, count: i32, size: *mut Size) -> i32;
    pub fn SetTextColor(dc: isize, color: u32) -> u32;
    pub fn SetBkMode(dc: isize, mode: i32) -> i32;
    pub fn DeleteObject(obj: isize) -> i32;
    pub fn CreateSolidBrush(color: u32) -> isize;
    pub fn CreatePen(style: i32, width: i32, color: u32) -> isize;
    pub fn RoundRect(dc: isize, l: i32, t: i32, r: i32, b: i32, w: i32, h: i32) -> i32;
    pub fn SetBkColor(dc: isize, color: u32) -> u32;
    pub fn GetStockObject(index: i32) -> isize;
    pub fn CreateCompatibleDC(dc: isize) -> isize;
    pub fn CreateCompatibleBitmap(dc: isize, w: i32, h: i32) -> isize;
    pub fn BitBlt(
        dst: isize,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        src: isize,
        sx: i32,
        sy: i32,
        rop: u32,
    ) -> i32;
    pub fn DeleteDC(dc: isize) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetUserDefaultUILanguage() -> u16;
    pub fn GetModuleHandleW(name: *const u16) -> isize;
    pub fn IsDebuggerPresent() -> i32;
    pub fn CheckRemoteDebuggerPresent(proc: isize, present: *mut i32) -> i32;
    pub fn GetCurrentProcess() -> isize;
    pub fn GetCurrentThread() -> isize;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetCurrentThreadId() -> u32;
    pub fn OpenProcess(access: u32, inherit: i32, id: u32) -> isize;
    pub fn OpenThread(access: u32, inherit: i32, id: u32) -> isize;
    pub fn CloseHandle(h: isize) -> i32;
    fn K32EnumProcessModules(proc: isize, modules: *mut isize, size: u32, needed: *mut u32) -> i32;
    fn GetModuleFileNameW(module: isize, name: *mut u16, size: u32) -> u32;
    fn GetThreadId(thread: isize) -> u32;
    pub fn SetDefaultDllDirectories(flags: u32) -> i32;
    pub fn SetProcessMitigationPolicy(policy: i32, buf: *const u32, len: usize) -> i32;
    pub fn SetProcessWorkingSetSize(proc: isize, min: usize, max: usize) -> i32;
    pub fn GlobalAlloc(flags: u32, size: usize) -> isize;
    pub fn GlobalLock(mem: isize) -> *mut c_void;
    pub fn GlobalUnlock(mem: isize) -> i32;
    pub fn GlobalFree(mem: isize) -> isize;
    pub fn GlobalSize(mem: isize) -> usize;
    fn LoadLibraryExW(name: *const u16, file: isize, flags: u32) -> isize;
    fn GetProcAddress(module: isize, name: *const u8) -> *const c_void;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(v: *mut Version) -> i32;
    fn NtGetNextThread(
        process: isize,
        thread: isize,
        access: u32,
        attributes: u32,
        flags: u32,
        next: *mut isize,
    ) -> i32;
    fn RtlCreateAcl(acl: *mut u8, length: u32, revision: u32) -> i32;
    fn RtlAddAccessAllowedAce(acl: *mut u8, revision: u32, mask: u32, sid: *const u8) -> i32;
    fn RtlCreateSecurityDescriptor(sd: *mut u8, revision: u32) -> i32;
    fn RtlSetDaclSecurityDescriptor(sd: *mut u8, present: u8, acl: *mut u8, defaulted: u8) -> i32;
    fn RtlSetControlSecurityDescriptor(sd: *mut u8, mask: u16, bits: u16) -> i32;
    fn NtSetSecurityObject(handle: isize, info: u32, sd: *const u8) -> i32;
}
#[link(name = "imm32")]
unsafe extern "system" {
    pub fn ImmAssociateContextEx(h: Hwnd, context: isize, flags: u32) -> i32;
    pub fn ImmGetContext(h: Hwnd) -> isize;
    pub fn ImmReleaseContext(h: Hwnd, context: isize) -> i32;
}
pub fn SetInputScope(h: Hwnd, scope: i32) -> i32 {
    type SetScope = unsafe extern "system" fn(Hwnd, i32) -> i32;
    static API: std::sync::OnceLock<Option<SetScope>> = std::sync::OnceLock::new();
    let api = API.get_or_init(|| unsafe {
        // Keep this system module loaded for the lifetime of the cached pointer.
        let module = LoadLibraryExW(wide("msctf.dll").as_ptr(), 0, 0x800);
        if module == 0 {
            return None;
        }
        let p = GetProcAddress(module, c"SetInputScope".as_ptr().cast());
        if p.is_null() {
            None
        } else {
            Some(std::mem::transmute::<*const c_void, SetScope>(p))
        }
    });
    api.map_or(-1, |f| unsafe { f(h, scope) })
}
#[link(name = "dwmapi")]
unsafe extern "system" {
    fn DwmIsCompositionEnabled(enabled: *mut i32) -> i32;
    pub fn DwmSetWindowAttribute(h: Hwnd, attribute: u32, value: *const c_void, size: u32) -> i32;
}
#[link(name = "uxtheme")]
unsafe extern "system" {
    pub fn SetWindowTheme(h: Hwnd, app: *const u16, id_list: *const u16) -> i32;
}
#[link(name = "comdlg32")]
unsafe extern "system" {
    fn GetOpenFileNameW(ofn: *mut OpenFile) -> i32;
    fn GetSaveFileNameW(ofn: *mut OpenFile) -> i32;
    fn CommDlgExtendedError() -> u32;
}
type SessionNotify = unsafe extern "system" fn(Hwnd, u32) -> i32;
type SessionUnnotify = unsafe extern "system" fn(Hwnd) -> i32;
/// wtsapi32 is loaded at run time from System32 only. As a static import it
/// pulled SspiCli.dll through the default search order, from the exe's own
/// folder, before main and any defense ran (DLL planting).
fn wtsapi() -> Option<(SessionNotify, SessionUnnotify)> {
    static API: std::sync::OnceLock<Option<(SessionNotify, SessionUnnotify)>> =
        std::sync::OnceLock::new();
    *API.get_or_init(|| unsafe {
        // LOAD_LIBRARY_SEARCH_SYSTEM32 also applies to the DLL's dependencies.
        let module = LoadLibraryExW(wide("wtsapi32.dll").as_ptr(), 0, 0x800);
        if module == 0 {
            return None;
        }
        let register = GetProcAddress(module, c"WTSRegisterSessionNotification".as_ptr().cast());
        let unregister =
            GetProcAddress(module, c"WTSUnRegisterSessionNotification".as_ptr().cast());
        if register.is_null() || unregister.is_null() {
            return None;
        }
        Some((
            std::mem::transmute::<*const c_void, SessionNotify>(register),
            std::mem::transmute::<*const c_void, SessionUnnotify>(unregister),
        ))
    })
}
pub fn WTSRegisterSessionNotification(h: Hwnd, flags: u32) -> i32 {
    wtsapi().map_or(0, |(register, _)| unsafe { register(h, flags) })
}
pub fn WTSUnRegisterSessionNotification(h: Hwnd) -> i32 {
    wtsapi().map_or(0, |(_, unregister)| unsafe { unregister(h) })
}
/// True while handling a message another thread sent (SendMessage,
/// SendNotifyMessage or SendMessageCallback). The app's own controls and
/// timers run on its single UI thread, so such a message can only come from
/// another program or from Windows itself.
pub fn from_other_thread() -> bool {
    // ISMEX_SEND | ISMEX_NOTIFY | ISMEX_CALLBACK
    unsafe { InSendMessageEx(std::ptr::null()) & 7 != 0 }
}
/// True when the foreground window is this app's window or one it owns
/// (its file dialogs and message boxes). Another program can create a window
/// owned by ours, so the window must also belong to this process.
pub fn is_foreground(h: Hwnd) -> bool {
    unsafe {
        let fg = GetForegroundWindow();
        let mut pid = 0u32;
        fg != 0
            && GetAncestor(fg, 3) == h // GA_ROOTOWNER
            && GetWindowThreadProcessId(fg, &mut pid) != 0
            && pid == GetCurrentProcessId()
    }
}
#[repr(C)]
struct GuiThreadInfo {
    size: u32,
    flags: u32,
    active: Hwnd,
    focus: Hwnd,
    capture: Hwnd,
    menu_owner: Hwnd,
    move_size: Hwnd,
    caret: Hwnd,
    caret_rect: Rect,
}
thread_local! {
    static MODAL: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}
/// True while a message box, file dialog, move/size loop or menu runs. The
/// main window gets no real click meanwhile, so commands must be ignored.
/// Decided from the app's own dialog calls and from Windows' thread state,
/// never from messages, which another program could post.
pub fn in_modal() -> bool {
    MODAL.with(|m| m.get() != 0)
        || unsafe {
            let mut info: GuiThreadInfo = std::mem::zeroed();
            info.size = size_of::<GuiThreadInfo>() as u32;
            // GUI_INMOVESIZE | GUI_INMENUMODE | GUI_SYSTEMMENUMODE | GUI_POPUPMENUMODE
            GetGUIThreadInfo(GetCurrentThreadId(), &mut info) != 0 && info.flags & 0x1e != 0
        }
}
/// Runs a message box or file dialog; see in_modal.
pub fn modal<T>(f: impl FnOnce() -> T) -> T {
    MODAL.with(|m| m.set(m.get() + 1));
    let result = f();
    MODAL.with(|m| m.set(m.get() - 1));
    result
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
pub fn secret_wide(s: &str) -> Zeroizing<Vec<u16>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() + 1));
    out.extend(s.encode_utf16());
    out.push(0);
    out
}
pub fn secret_utf8(s: &[u16]) -> std::result::Result<Zeroizing<String>, &'static str> {
    let mut out = Zeroizing::new(String::with_capacity(s.len() * 3));
    for c in char::decode_utf16(s.iter().copied()) {
        out.push(c.map_err(|_| "올바르지 않은 유니코드 입력입니다.")?);
    }
    Ok(out)
}
/// Clipboard text and the sequence number of that exact content.
type Pasted = (Zeroizing<Vec<u16>>, u32);
pub fn clipboard_text(h: Hwnd) -> std::result::Result<Pasted, &'static str> {
    unsafe {
        if OpenClipboard(h) == 0 {
            return Err("클립보드 사용 중");
        }
        let result = (|| {
            let mem = GetClipboardData(13);
            if mem == 0 {
                return Err("텍스트가 없습니다.");
            }
            let bytes = GlobalSize(mem);
            if bytes == 0 || bytes > 131072 || !bytes.is_multiple_of(2) {
                return Err("붙여넣기 크기 초과");
            }
            let p = GlobalLock(mem);
            if p.is_null() {
                return Err("클립보드 읽기 실패");
            }
            let units = std::slice::from_raw_parts(p.cast::<u16>(), bytes / 2);
            let value = if let Some(end) = units.iter().position(|v| *v == 0) {
                let mut value = Zeroizing::new(Vec::with_capacity(end + 1));
                value.extend_from_slice(&units[..end]);
                Ok(value)
            } else {
                Err("텍스트 형식 오류")
            };
            GlobalUnlock(mem);
            // Read before closing: another app cannot replace the content
            // while it is open, and format synthesis has already happened.
            value.map(|v| (v, GetClipboardSequenceNumber()))
        })();
        CloseClipboard();
        result
    }
}
pub fn message(h: Hwnd, s: &str) {
    message_in(h, s, "고요 금고");
}
/// [`message`] with its own title (goyo-sync's settings window).
pub fn message_in(h: Hwnd, s: &str, title: &str) {
    modal(|| unsafe {
        MessageBoxW(h, wide(tr(s)).as_ptr(), wide(tr(title)).as_ptr(), 0x40);
    });
}
/// The open confirm box (0 when none), for the queue filter: a message box
/// is an owned popup, not a child of the main window.
static CONFIRM_BOX: AtomicIsize = AtomicIsize::new(0);
static CONFIRM_PROC: AtomicIsize = AtomicIsize::new(0);
pub fn confirm_box() -> Hwnd {
    CONFIRM_BOX.load(Ordering::Relaxed)
}
/// Asks a yes/no question that only the user can answer. Another program
/// could otherwise answer the box for them: posted clicks are refused by the
/// queue filter (see confirm_box), and commands or input sent from another
/// thread by confirm_proc. If the box cannot be guarded, the answer is no.
pub fn confirm(h: Hwnd, s: &str) -> bool {
    confirm_in(h, s, "고요 금고")
}
/// [`confirm`] with its own title (goyo-sync's settings window).
pub fn confirm_in(h: Hwnd, s: &str, title: &str) -> bool {
    modal(|| unsafe {
        let hook = SetWindowsHookExW(5, confirm_cbt, 0, GetCurrentThreadId()); // WH_CBT
        if hook == 0 {
            return false;
        }
        let yes = MessageBoxW(h, wide(tr(s)).as_ptr(), wide(tr(title)).as_ptr(), 0x124) == 6;
        UnhookWindowsHookEx(hook);
        let guarded = CONFIRM_PROC.swap(0, Ordering::Relaxed) != 0;
        CONFIRM_BOX.store(0, Ordering::Relaxed);
        yes && guarded
    })
}
/// Subclasses the box when it is first activated (HCBT_ACTIVATE), before
/// it takes any input.
unsafe extern "system" fn confirm_cbt(code: i32, w: usize, l: isize) -> isize {
    if code == 5 && CONFIRM_BOX.load(Ordering::Relaxed) == 0 {
        let b = w as Hwnd;
        let old = unsafe { SetWindowLongPtrW(b, -4, confirm_proc as *const () as isize) };
        if old != 0 {
            CONFIRM_PROC.store(old, Ordering::Relaxed);
            CONFIRM_BOX.store(b, Ordering::Relaxed);
        }
    }
    unsafe { CallNextHookEx(0, code, w, l) }
}
/// Drops commands and input sent from another thread, including the command
/// a button sends while it handles a BM_CLICK from another thread.
unsafe extern "system" fn confirm_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() && matches!(m, 0x111 | 0x100..=0x109 | 0x201..=0x20e) {
        return 0;
    }
    let old = CONFIRM_PROC.load(Ordering::Relaxed);
    unsafe { CallWindowProcW(std::mem::transmute::<isize, Option<Proc>>(old), h, m, w, l) }
}
/// What a button of a guarded input dialog does (spec §9.2a): it answers,
/// it switches to another kind of entry, or it cancels.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Accept,
    Switch,
    Cancel,
}
/// A button of a guarded input dialog. The caller passes every label, so
/// this file gains no text of its own.
#[derive(Clone, Copy)]
pub struct DialogButton<'a> {
    pub id: i32,
    pub label: &'a str,
    pub role: Role,
}
/// What a guarded input dialog asks for (spec §9.2a): a password, a code,
/// a pick from a checklist, or a preview to accept.
#[derive(Clone, Copy)]
pub enum InputKind<'a> {
    /// A masked password field under the text.
    Password,
    /// A code field under the text (a key code): not masked,
    /// with the same subclass and input scope as a password field, holding
    /// what was typed before when it is asked again (a code that did not
    /// match or parse is kept for correcting, never retyped).
    Code(&'a str),
    /// A checklist under the text: each item's label (composed by the
    /// caller) and first state. At most PICK_MAX items.
    Pick(&'a [(&'a str, bool)]),
    /// The text read-only and scrollable (a preview the caller composed),
    /// with an optional check box: its control ID, label and first state.
    Preview { check: Option<(i32, &'a str, bool)> },
}
/// How a guarded input dialog was answered. A dialog that could not be
/// guarded, or that closed because the app locked, answers its cancel
/// button.
pub enum InputAnswer {
    Password(Zeroizing<String>),
    Code(Zeroizing<String>),
    /// The indexes of the ticked items, ascending.
    Pick(Vec<u8>),
    Accept {
        checked: bool,
    },
    Switch(i32),
    Cancel(i32),
}
/// The control ID of the password field of an input dialog: the edit
/// subclass clears a password pasted into it from the clipboard.
pub const INPUT_EDIT: i32 = 0x7f01;
/// The control ID of the code field of an input dialog.
pub const INPUT_CODE: i32 = 0x7f02;
/// The control ID of a checklist's first item; the others follow.
pub const INPUT_PICK: i32 = 0x7f10;
/// The most items a checklist holds (a key file holds at most 8 keys).
pub const PICK_MAX: usize = 8;
/// The open input dialog (0 when none), for the queue filter: like a
/// confirm box it is an owned popup, not a child of the main window.
static INPUT_BOX: AtomicIsize = AtomicIsize::new(0);
pub fn input_box() -> Hwnd {
    INPUT_BOX.load(Ordering::Relaxed)
}
/// The open input dialog's controls and answer.
#[derive(Default)]
struct Input {
    /// The password field, and its own procedure under the caller's
    /// subclass, through which this file reads and wipes it.
    edit: Hwnd,
    edit_own: isize,
    check: Hwnd,
    /// The checklist's items, in order.
    picks: Vec<Hwnd>,
    /// The other controls under input_child_proc, with their procedures.
    children: Vec<(Hwnd, isize)>,
    buttons: Vec<(i32, Role)>,
    /// The button that answered.
    answer: Option<(i32, Role)>,
}
thread_local! {
    static INPUT: std::cell::RefCell<Input> = std::cell::RefCell::new(Input::default());
}
/// Asks for input that only the user can give, inside a flow (spec §9.2a):
/// an owned modal window that changes neither the main window's screen nor
/// anything else about it. Like a confirm box, it drops commands and input
/// sent from another thread (its own procedure and input_child_proc), and
/// posted fakes are refused by the queue filter (see input_box). It is
/// excluded from screen capture, and its password field carries the
/// caller's edit subclass (`edit_proc`) and the password input scope. If
/// any of that cannot be set up, it answers "cancel", as it does when the
/// app locks while it is open (cancel_input).
pub fn input_dialog(
    h: Hwnd,
    kind: InputKind,
    text: &str,
    buttons: &[DialogButton],
    edit_proc: Proc,
) -> InputAnswer {
    let cancel = buttons
        .iter()
        .find(|b| b.role == Role::Cancel)
        .map_or(2, |b| b.id);
    modal(|| unsafe { run_input(h, kind, text, buttons, edit_proc) })
        .unwrap_or(InputAnswer::Cancel(cancel))
}
/// Closes the open input dialog, if any, with its cancel button: the app
/// locked, which voids the flow that asked.
pub fn cancel_input() {
    let open = INPUT.with(|s| {
        let mut s = s.borrow_mut();
        let cancel = s.buttons.iter().find(|(_, r)| *r == Role::Cancel).copied();
        if input_box() != 0 && s.answer.is_none() {
            s.answer = Some(cancel.unwrap_or((2, Role::Cancel)));
        }
        input_box()
    });
    if open != 0 {
        unsafe {
            PostMessageW(open, 0, 0, 0); // wakes its message loop
        }
    }
}
unsafe fn run_input(
    owner: Hwnd,
    kind: InputKind,
    text: &str,
    buttons: &[DialogButton],
    edit_proc: Proc,
) -> Option<InputAnswer> {
    // One at a time: a flow asks one question after the other.
    if input_box() != 0
        || buttons.is_empty()
        || matches!(kind, InputKind::Pick(items) if items.is_empty() || items.len() > PICK_MAX)
    {
        return None;
    }
    let class = wide("GoyoInputDialog");
    static REGISTERED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let registered = *REGISTERED.get_or_init(|| unsafe {
        let wc = WndClass {
            style: 0,
            proc: Some(input_proc),
            cls_extra: 0,
            wnd_extra: 0,
            instance: GetModuleHandleW(std::ptr::null()),
            icon: 0,
            cursor: LoadCursorW(0, 32512usize as *const u16),
            background: 16, // COLOR_BTNFACE + 1, as a message box
            menu: std::ptr::null(),
            class: class.as_ptr(),
        };
        RegisterClassW(&wc) != 0
    });
    if !registered {
        return None;
    }
    let scale = unsafe { GetDpiForSystem() } as f32 / 96.0;
    let px = |n: i32| (n as f32 * scale) as i32;
    let font = unsafe {
        CreateFontW(
            -px(12),
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
            // The app's faces: Malgun Gothic draws a backslash as a won sign.
            wide(if crate::i18n::english() {
                "Segoe UI"
            } else {
                "맑은 고딕"
            })
            .as_ptr(),
        )
    };
    if font == 0 {
        return None;
    }
    INPUT.with(|s| {
        *s.borrow_mut() = Input {
            buttons: buttons.iter().map(|b| (b.id, b.role)).collect(),
            ..Input::default()
        }
    });
    let answer = unsafe { build_input(owner, kind, text, buttons, edit_proc, font, &px) };
    unsafe {
        DeleteObject(font);
    }
    INPUT.with(|s| *s.borrow_mut() = Input::default());
    INPUT_BOX.store(0, Ordering::Relaxed);
    answer
}
/// Lays out the dialog, runs it and takes its answer; the dialog is gone
/// when this returns.
unsafe fn build_input(
    owner: Hwnd,
    kind: InputKind,
    text: &str,
    buttons: &[DialogButton],
    edit_proc: Proc,
    font: isize,
    px: &dyn Fn(i32) -> i32,
) -> Option<InputAnswer> {
    let class = wide("GoyoInputDialog");
    let text = tr(text);
    // Client width 480 (96 DPI); the text's height as it wraps.
    let (width, margin) = (px(480), px(16));
    let inner = width - 2 * margin;
    let text_h = match kind {
        InputKind::Preview { .. } => px(240),
        InputKind::Password | InputKind::Code(_) | InputKind::Pick(_) => unsafe {
            let dc = GetDC(owner);
            let old = SelectObject(dc, font);
            let mut r = Rect {
                right: inner,
                ..Rect::default()
            };
            let s = wide(text);
            DrawTextW(dc, s.as_ptr(), -1, &mut r, 0x400 | 0x800 | 0x10); // CALCRECT | NOPREFIX | WORDBREAK
            SelectObject(dc, old);
            ReleaseDC(owner, dc);
            r.bottom.clamp(px(20), px(320))
        },
    };
    let mut y = margin + text_h + px(12);
    let field_y = y;
    match kind {
        InputKind::Password | InputKind::Code(_) => y += px(26) + px(16),
        InputKind::Pick(items) => y += items.len() as i32 * px(26) + px(8),
        InputKind::Preview { check: Some(_) } => y += px(22) + px(12),
        InputKind::Preview { check: None } => {}
    }
    let buttons_y = y;
    let height = y + px(30) + margin;
    // The window around that client area, centred on the owner.
    let style = 0x8000_0000 | 0x00c0_0000 | 0x0008_0000; // WS_POPUP | WS_CAPTION | WS_SYSMENU
    let ex = 0x1; // WS_EX_DLGMODALFRAME
    let mut frame = Rect {
        left: 0,
        top: 0,
        right: width,
        bottom: height,
    };
    let mut parent = Rect::default();
    unsafe {
        AdjustWindowRectEx(&mut frame, style, 0, ex);
        GetWindowRect(owner, &mut parent);
    }
    let (w, h) = (frame.right - frame.left, frame.bottom - frame.top);
    let x = parent.left + (parent.right - parent.left - w) / 2;
    let top = parent.top + (parent.bottom - parent.top - h) / 2;
    let dialog = unsafe {
        CreateWindowExW(
            ex,
            class.as_ptr(),
            wide(tr("고요 금고")).as_ptr(),
            style,
            x,
            top,
            w,
            h,
            owner,
            0,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null_mut(),
        )
    };
    if dialog == 0 {
        return None;
    }
    INPUT_BOX.store(dialog, Ordering::Relaxed);
    let answer = unsafe {
        fill_input(
            owner,
            dialog,
            kind,
            text,
            buttons,
            edit_proc,
            font,
            px,
            [text_h, field_y, buttons_y],
        )
    };
    unsafe {
        // The owner first, so that it is activated again, not another app.
        EnableWindow(owner, 1);
        DestroyWindow(dialog);
    }
    answer
}
/// Creates the dialog's controls and guards them, runs its message loop
/// and reads the answer, wiping the password field.
#[allow(clippy::too_many_arguments)] // Native control geometry follows Win32.
unsafe fn fill_input(
    owner: Hwnd,
    dialog: Hwnd,
    kind: InputKind,
    text: &str,
    buttons: &[DialogButton],
    edit_proc: Proc,
    font: isize,
    px: &dyn Fn(i32) -> i32,
    [text_h, field_y, buttons_y]: [i32; 3],
) -> Option<InputAnswer> {
    let (width, margin) = (px(480), px(16));
    let inner = width - 2 * margin;
    let child = |class: &str,
                 text: &str,
                 style: u32,
                 ex: u32,
                 (x, y, w, h): (i32, i32, i32, i32),
                 id: i32| unsafe {
        let c = CreateWindowExW(
            ex,
            wide(class).as_ptr(),
            secret_wide(text).as_ptr(),
            0x5000_0000 | style, // WS_CHILD | WS_VISIBLE
            x,
            y,
            w,
            h,
            dialog,
            id as isize,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null_mut(),
        );
        if c != 0 {
            SendMessageW(c, 0x30, font as usize, 0); // WM_SETFONT
        }
        c
    };
    // Every control but the password field takes input only from this
    // thread; the password field gets the caller's subclass instead.
    let guard = |c: Hwnd| unsafe {
        if c == 0 {
            return false;
        }
        let own = SetWindowLongPtrW(c, -4, input_child_proc as *const () as isize);
        if own == 0 {
            return false;
        }
        INPUT.with(|s| s.borrow_mut().children.push((c, own)));
        true
    };
    let mut ok = true;
    let text_box = if let InputKind::Preview { .. } = kind {
        // ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL
        let lines = text.replace("\r\n", "\n").replace('\n', "\r\n");
        child(
            "EDIT",
            &lines,
            0x4 | 0x40 | 0x800 | 0x0020_0000,
            0x200,
            (margin, margin, inner, text_h),
            0,
        )
    } else {
        child("STATIC", text, 0x80, 0, (margin, margin, inner, text_h), 0) // SS_NOPREFIX
    };
    ok &= guard(text_box);
    match kind {
        InputKind::Password | InputKind::Code(_) => {
            // ES_AUTOHSCROLL, WS_TABSTOP, with a sunken edge; ES_PASSWORD
            // for a password. A code asked again starts with the one typed.
            let password = matches!(kind, InputKind::Password);
            let typed = match kind {
                InputKind::Code(typed) if typed.len() <= 64 => typed,
                _ => "",
            };
            let edit = child(
                "EDIT",
                typed,
                if password { 0x20 } else { 0 } | 0x80 | 0x0001_0000,
                0x200,
                (margin, field_y, inner, px(26)),
                if password { INPUT_EDIT } else { INPUT_CODE },
            );
            ok &= edit != 0;
            if edit != 0 {
                unsafe {
                    // The mask goes first: the subclass blocks EM_SETPASSWORDCHAR.
                    if password {
                        SendMessageW(edit, 0xcc, '•' as usize, 0);
                    }
                    SendMessageW(edit, 0xc5, if password { 1024 } else { 64 }, 0); // EM_LIMITTEXT
                    let own = SetWindowLongPtrW(edit, -4, edit_proc as *const () as isize);
                    ok &= own != 0 && SetInputScope(edit, 31) == 0;
                    INPUT.with(|s| {
                        let mut s = s.borrow_mut();
                        s.edit = edit;
                        s.edit_own = own;
                    });
                }
            }
        }
        InputKind::Preview {
            check: Some((id, label, on)),
        } => {
            // BS_AUTOCHECKBOX, WS_TABSTOP
            let check = child(
                "BUTTON",
                tr(label),
                0x3 | 0x0001_0000,
                0,
                (margin, field_y, inner, px(22)),
                id,
            );
            ok &= guard(check);
            if check != 0 {
                unsafe {
                    SendMessageW(check, 0xf1, on as usize, 0); // BM_SETCHECK
                }
                INPUT.with(|s| s.borrow_mut().check = check);
            }
        }
        InputKind::Pick(items) => {
            // BS_AUTOCHECKBOX, WS_TABSTOP; one per row.
            for (i, (label, on)) in items.iter().enumerate() {
                let item = child(
                    "BUTTON",
                    tr(label),
                    0x3 | 0x0001_0000,
                    0,
                    (margin, field_y + i as i32 * px(26), inner, px(22)),
                    INPUT_PICK + i as i32,
                );
                ok &= guard(item);
                if item != 0 {
                    unsafe {
                        SendMessageW(item, 0xf1, *on as usize, 0); // BM_SETCHECK
                    }
                    INPUT.with(|s| s.borrow_mut().picks.push(item));
                }
            }
        }
        InputKind::Preview { check: None } => {}
    }
    // The buttons right-aligned, the first one the default.
    let mut right = width - margin;
    let mut first = 0;
    for (i, b) in buttons.iter().enumerate().rev() {
        let label = tr(b.label);
        let w = (unsafe { text_width(dialog, font, label) } + px(24)).max(px(96));
        right -= w;
        let style = 0x0001_0000 | if i == 0 { 0x1 } else { 0 }; // WS_TABSTOP, BS_DEFPUSHBUTTON
        let c = child(
            "BUTTON",
            label,
            style,
            0,
            (right, buttons_y, w, px(30)),
            b.id,
        );
        ok &= guard(c);
        right -= px(8);
        if i == 0 {
            first = c;
        }
    }
    // Capture exclusion, read back.
    let mut affinity = 0;
    ok &= unsafe {
        SetWindowDisplayAffinity(dialog, 0x11) != 0
            && GetWindowDisplayAffinity(dialog, &mut affinity) != 0
            && affinity == 0x11
    };
    if !ok {
        unsafe { wipe_input() };
        return None;
    }
    unsafe {
        // Active first, then the owner disabled: activation stays with this
        // thread's windows.
        ShowWindow(dialog, 5);
        let (edit, pick) = INPUT.with(|s| {
            let s = s.borrow();
            (s.edit, s.picks.first().copied().unwrap_or(0))
        });
        SetFocus(if edit != 0 {
            edit
        } else if pick != 0 {
            pick
        } else {
            first
        });
        EnableWindow(owner, 0);
    }
    let mut msg = Msg::default();
    loop {
        if INPUT.with(|s| s.borrow().answer.is_some()) || unsafe { IsWindow(dialog) } == 0 {
            break;
        }
        let got = unsafe { GetMessageW(&mut msg, 0, 0, 0) };
        if got <= 0 {
            // WM_QUIT is for the app's own loop.
            if got == 0 {
                unsafe { PostQuitMessage(msg.wparam as i32) };
            }
            break;
        }
        unsafe {
            if IsDialogMessageW(dialog, &mut msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    let (answer, check, picks) = INPUT.with(|s| {
        let s = s.borrow();
        (s.answer, s.check, s.picks.clone())
    });
    let result = match answer {
        Some((_, Role::Accept)) => match kind {
            InputKind::Password => unsafe { read_input() }.map(InputAnswer::Password),
            InputKind::Code(_) => unsafe { read_input() }.map(InputAnswer::Code),
            // BM_GETCHECK of each item.
            InputKind::Pick(_) => Some(InputAnswer::Pick(
                (0..picks.len() as u8)
                    .filter(|i| unsafe { SendMessageW(picks[*i as usize], 0xf0, 0, 0) } == 1)
                    .collect(),
            )),
            InputKind::Preview { .. } => Some(InputAnswer::Accept {
                checked: check != 0 && unsafe { SendMessageW(check, 0xf0, 0, 0) } == 1, // BM_GETCHECK
            }),
        },
        Some((id, Role::Switch)) => Some(InputAnswer::Switch(id)),
        Some((id, Role::Cancel)) => Some(InputAnswer::Cancel(id)),
        None => None,
    };
    unsafe { wipe_input() };
    result
}
/// The width of `text` in `font`.
unsafe fn text_width(h: Hwnd, font: isize, text: &str) -> i32 {
    unsafe {
        let dc = GetDC(h);
        let old = SelectObject(dc, font);
        let s = wide(text);
        let mut size = Size::default();
        GetTextExtentPoint32W(dc, s.as_ptr(), s.len() as i32 - 1, &mut size);
        SelectObject(dc, old);
        ReleaseDC(h, dc);
        size.cx
    }
}
/// The password field's text, read past the caller's subclass, which drops
/// every outside read.
unsafe fn read_input() -> Option<Zeroizing<String>> {
    let (edit, own) = INPUT.with(|s| {
        let s = s.borrow();
        (s.edit, s.edit_own)
    });
    if edit == 0 || own == 0 {
        return None;
    }
    let own = unsafe { std::mem::transmute::<isize, Option<Proc>>(own) };
    unsafe {
        let n = CallWindowProcW(own, edit, 0xe, 0, 0).clamp(0, 32767) as usize; // WM_GETTEXTLENGTH
        let mut buf = Zeroizing::new(vec![0u16; n + 1]);
        let got = CallWindowProcW(own, edit, 0xd, buf.len(), buf.as_mut_ptr() as isize).max(0);
        secret_utf8(&buf[..(got as usize).min(n)]).ok()
    }
}
/// Overwrites the password field's text in place before the dialog goes.
unsafe fn wipe_input() {
    let (edit, own) = INPUT.with(|s| {
        let s = s.borrow();
        (s.edit, s.edit_own)
    });
    if edit == 0 || own == 0 {
        return;
    }
    let own = unsafe { std::mem::transmute::<isize, Option<Proc>>(own) };
    unsafe {
        let n = CallWindowProcW(own, edit, 0xe, 0, 0).clamp(0, 32767) as usize;
        let spaces = secret_wide(&" ".repeat(n));
        CallWindowProcW(own, edit, 0xb1, 0, -1); // EM_SETSEL
        CallWindowProcW(own, edit, 0xc2, 0, spaces.as_ptr() as isize); // EM_REPLACESEL
        CallWindowProcW(own, edit, 0xc, 0, wide("").as_ptr() as isize); // WM_SETTEXT
        CallWindowProcW(own, edit, 0xcd, 0, 0); // EM_EMPTYUNDOBUFFER
    }
}
/// The input dialog's own procedure: a button answers, closing cancels.
/// Commands and input sent from another thread are dropped (the
/// confirm_proc rule); app messages its controls post (a cleared paste)
/// go to the main window.
unsafe extern "system" fn input_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() && matches!(m, 0x10 | 0x111 | 0x112 | 0x100..=0x109 | 0x201..=0x20e) {
        return 0;
    }
    match m {
        0x111 => {
            let id = (w & 0xffff) as i32;
            INPUT.with(|s| {
                let mut s = s.borrow_mut();
                // Enter and Esc arrive as IDOK and IDCANCEL.
                let pick = |role: Role| s.buttons.iter().find(|(_, r)| *r == role).copied();
                let pressed = match s.buttons.iter().find(|(b, _)| *b == id) {
                    Some(b) => Some(*b),
                    None if id == 1 => pick(Role::Accept),
                    None if id == 2 => pick(Role::Cancel),
                    None => None,
                };
                if s.answer.is_none() && pressed.is_some() {
                    s.answer = pressed;
                }
            });
            0
        }
        0x10 => {
            INPUT.with(|s| {
                let mut s = s.borrow_mut();
                let cancel = s.buttons.iter().find(|(_, r)| *r == Role::Cancel).copied();
                if s.answer.is_none() {
                    s.answer = Some(cancel.unwrap_or((2, Role::Cancel)));
                }
            });
            0
        }
        0x8000..=0xbfff => {
            unsafe { PostMessageW(GetParent(h), m, w, l) };
            0
        }
        _ => unsafe { DefWindowProcW(h, m, w, l) },
    }
}
/// The input dialog's controls other than the password field: anything
/// sent from another thread is dropped, as for the main window's list.
unsafe extern "system" fn input_child_proc(h: Hwnd, m: u32, w: usize, l: isize) -> isize {
    if from_other_thread() {
        return 0;
    }
    let own = INPUT.with(|s| {
        s.borrow()
            .children
            .iter()
            .find(|(c, _)| *c == h)
            .map_or(0, |(_, p)| *p)
    });
    if own == 0 {
        return unsafe { DefWindowProcW(h, m, w, l) };
    }
    unsafe { CallWindowProcW(std::mem::transmute::<isize, Option<Proc>>(own), h, m, w, l) }
}
pub fn dialog(h: Hwnd, save: bool, key: bool) -> Option<PathBuf> {
    pick_file(
        h,
        save,
        if key {
            "고요 열쇠 파일 (*.goyokey)\0*.goyokey\0모든 파일\0*.*\0"
        } else {
            "고요 금고/백업 (*.goyo)\0*.goyo\0모든 파일\0*.*\0"
        },
        if key { "goyokey" } else { "goyo" },
        if save {
            "새 파일 이름을 선택하세요 (기존 파일 덮어쓰기 금지)"
        } else {
            "파일 선택"
        },
        None,
    )
}
/// Whether the last pick_file returned None because the dialog failed
/// (CommDlgExtendedError), not because the user cancelled it.
static DIALOG_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn dialog_failed() -> bool {
    DIALOG_FAILED.load(Ordering::Relaxed)
}
/// An open or save file dialog. `filter` and `title` are Korean sources
/// (passed through tr()); `ext` is added to a typed name without one ("":
/// none); `initial` prefills the name and folder.
pub fn pick_file(
    h: Hwnd,
    save: bool,
    filter: &str,
    ext: &str,
    title: &str,
    initial: Option<&std::path::Path>,
) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStrExt;
    let mut file = vec![0u16; 32768];
    if let Some(initial) = initial {
        // The common dialogs refuse a `\\?\` path and fail without showing,
        // so a normalized path goes in as the user knows it.
        let text = initial.to_string_lossy();
        let plain = match text.strip_prefix("\\\\?\\") {
            Some(rest) => match rest.strip_prefix("UNC\\") {
                Some(share) => format!("\\\\{share}"),
                None => rest.to_owned(),
            },
            None => text.into_owned(),
        };
        let name: Vec<u16> = std::ffi::OsStr::new(&plain).encode_wide().collect();
        if name.len() < file.len() && !name.contains(&0) {
            file[..name.len()].copy_from_slice(&name);
        }
    }
    let filter = wide(tr(filter));
    let ext = wide(ext);
    let title = wide(tr(title));
    let mut o: OpenFile = unsafe { std::mem::zeroed() };
    o.size = size_of::<OpenFile>() as u32;
    o.owner = h;
    o.filter = filter.as_ptr();
    o.index = 1;
    o.file = file.as_mut_ptr();
    o.max_file = file.len() as u32;
    o.title = title.as_ptr();
    if ext.len() > 1 {
        o.def_ext = ext.as_ptr();
    }
    o.flags = 0x80000 | 0x800 | 0x8 | 0x02000000 | if save { 0x2 } else { 0x1000 };
    let ok = modal(|| unsafe {
        if save {
            GetSaveFileNameW(&mut o)
        } else {
            GetOpenFileNameW(&mut o)
        }
    });
    // A cancel leaves no error; a dialog that could not open (a path it
    // refuses, a buffer it cannot use) does, and its caller says so.
    DIALOG_FAILED.store(
        ok == 0 && unsafe { CommDlgExtendedError() } != 0,
        Ordering::Relaxed,
    );
    if ok == 0 {
        return None;
    }
    let end = file.iter().position(|c| *c == 0).unwrap_or(0);
    use std::os::windows::ffi::OsStringExt;
    Some(PathBuf::from(std::ffi::OsString::from_wide(&file[..end])))
}
pub fn initialize_defenses() -> std::result::Result<(), &'static str> {
    unsafe {
        DisableProcessWindowsGhosting();
        let mut v: Version = std::mem::zeroed();
        v.size = size_of::<Version>() as u32;
        if RtlGetVersion(&mut v) != 0 || v.major < 10 || v.build < 22000 {
            return Err("Windows 11 이상에서 실행하세요.");
        }
        if SetDefaultDllDirectories(0x800) == 0 {
            return Err("DLL 검색 경로 보호 설정에 실패했습니다.");
        }
        // Disable dynamically generated executable code, legacy extension points,
        // non-system fonts, remote/low-integrity image loading, prefer system32
        // images, allow only Microsoft-signed DLLs (third-party injected modules,
        // shell extensions and IMEs), and forbid child processes.
        for (policy, flags) in [(2, 1u32), (6, 1), (9, 1), (10, 7), (8, 1), (13, 1)] {
            if SetProcessMitigationPolicy(policy, &flags, 4) == 0 {
                return Err("프로세스 보호 설정에 실패했습니다.");
            }
        }
    }
    Ok(())
}
// SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION
const THREAD_OWNER: u32 = 0x0010_0000 | 0x800;
/// Gives `handle` a protected DACL: SYSTEM keeps full access, the owner gets
/// only `owner`. The OWNER RIGHTS entry also removes the owner's implicit
/// right to rewrite this DACL.
fn restrict_object(handle: isize, owner: u32) -> bool {
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]; // S-1-5-18
    const OWNER_RIGHTS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0]; // S-1-3-4
    // u64 storage: the ACL needs 4-byte and the descriptor 8-byte alignment.
    let mut acl = [0u64; 16];
    let mut sd = [0u64; 8]; // SECURITY_DESCRIPTOR is 40 bytes on x64
    let (acl, sd) = (acl.as_mut_ptr().cast::<u8>(), sd.as_mut_ptr().cast::<u8>());
    unsafe {
        RtlCreateAcl(acl, 128, 2) >= 0
            && RtlAddAccessAllowedAce(acl, 2, 0x1000_0000, SYSTEM.as_ptr()) >= 0 // GENERIC_ALL
            && RtlAddAccessAllowedAce(acl, 2, owner, OWNER_RIGHTS.as_ptr()) >= 0
            && RtlCreateSecurityDescriptor(sd, 1) >= 0
            && RtlSetDaclSecurityDescriptor(sd, 1, acl, 0) >= 0
            && RtlSetControlSecurityDescriptor(sd, 0x1000, 0x1000) >= 0 // SE_DACL_PROTECTED
            && NtSetSecurityObject(handle, 4, sd) >= 0 // DACL_SECURITY_INFORMATION
    }
}
/// Opens each thread of this process with `access`; threads that refuse are
/// skipped. Walks only this process (a system-wide snapshot takes ~100 ms).
/// False if the threads could not be listed.
fn each_thread(access: u32, mut f: impl FnMut(isize)) -> bool {
    const NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
    unsafe {
        let mut current = 0;
        loop {
            let mut next = 0;
            // THREAD_QUERY_LIMITED_INFORMATION stays granted after the DACL change.
            let status = NtGetNextThread(GetCurrentProcess(), current, 0x800, 0, 0, &mut next);
            if current != 0 {
                CloseHandle(current);
            }
            if status < 0 {
                return status == NO_MORE_ENTRIES;
            }
            current = next;
            let t = OpenThread(access, 0, GetThreadId(next));
            if t != 0 {
                f(t);
                CloseHandle(t);
            }
        }
    }
}
/// Applies the thread DACL to every thread of this process that still has
/// the default one. Windows starts loader and thread-pool threads on its own
/// (at launch, for file dialogs), so the timer calls this again. False if a
/// thread could be opened but not restricted.
pub fn restrict_threads() -> bool {
    let mut restricted = true;
    // WRITE_DAC | SET_CONTEXT: opens only while the default DACL is in place.
    let listed = each_thread(0x0004_0000 | 0x10, |t| {
        restricted &= restrict_object(t, THREAD_OWNER);
    });
    listed && restricted
}
/// Threads of this process another program could still take over.
pub fn open_threads() -> usize {
    let mut n = 0;
    each_thread(0x10, |_| n += 1); // THREAD_SET_CONTEXT
    n
}
/// DLLs loaded from the exe's own folder. Every DLL the app uses lives in
/// System32, so one found next to the exe was planted there.
pub fn modules_beside_exe() -> Vec<PathBuf> {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
    else {
        return vec![];
    };
    let exe = unsafe { GetModuleHandleW(std::ptr::null()) };
    let mut modules = vec![0isize; 1024];
    let mut needed = 0u32;
    let size = (modules.len() * size_of::<isize>()) as u32;
    if unsafe {
        K32EnumProcessModules(GetCurrentProcess(), modules.as_mut_ptr(), size, &mut needed)
    } == 0
    {
        return vec![dir]; // cannot tell: report as a failure
    }
    modules.truncate((needed as usize / size_of::<isize>()).min(modules.len()));
    let mut found = vec![];
    for &m in modules.iter().filter(|&&m| m != exe) {
        let mut name = vec![0u16; 32768];
        let n = unsafe { GetModuleFileNameW(m, name.as_mut_ptr(), name.len() as u32) } as usize;
        use std::os::windows::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_wide(&name[..n]));
        let parent = path.parent().map(|p| p.to_string_lossy().to_lowercase());
        if parent == Some(dir.to_string_lossy().to_lowercase()) {
            found.push(path);
        }
    }
    found
}
/// Narrows who may open this process and its threads. By default any
/// program running as the same user can read the vault's memory, write into
/// it or start a thread in it. Afterwards SYSTEM keeps full access and the
/// owner only gets what Task Manager needs (query, wait, terminate).
/// Administrators with SeDebugPrivilege are not stopped.
pub fn restrict_process_access() -> std::result::Result<(), &'static str> {
    // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE
    const PROCESS_OWNER: u32 = 0x0010_0000 | 0x1000 | 0x1;
    unsafe {
        if !restrict_object(GetCurrentProcess(), PROCESS_OWNER)
            || !restrict_object(GetCurrentThread(), THREAD_OWNER)
            || !restrict_threads()
        {
            return Err("다른 프로그램의 메모리 접근 차단 설정에 실패했습니다.");
        }
        // Opening ourselves by ID goes through the new DACL; both must fail.
        let process = OpenProcess(0x10, 0, GetCurrentProcessId()); // PROCESS_VM_READ
        let thread = OpenThread(0x10, 0, GetCurrentThreadId()); // THREAD_SET_CONTEXT
        for handle in [process, thread] {
            if handle != 0 {
                CloseHandle(handle);
            }
        }
        if process != 0 || thread != 0 {
            return Err("다른 프로그램의 메모리 접근 차단을 확인하지 못했습니다.");
        }
    }
    Ok(())
}
pub fn check_environment(h: Hwnd) -> std::result::Result<(), &'static str> {
    unsafe {
        let mut debug = 0;
        let mut composition = 0;
        let mut affinity = 0;
        if IsDebuggerPresent() != 0
            || CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut debug) == 0
            || debug != 0
        {
            return Err("디버거 연결이 감지되었거나 확인할 수 없어 잠갔습니다.");
        }
        if GetSystemMetrics(0x1000) != 0 || GetSystemMetrics(0x2001) != 0 {
            return Err("원격/공유 세션에서는 금고를 열 수 없습니다.");
        }
        if DwmIsCompositionEnabled(&mut composition) != 0 || composition == 0 {
            return Err("화면 보호 상태를 확인할 수 없습니다.");
        }
        if GetWindowDisplayAffinity(h, &mut affinity) == 0 || affinity != 0x11 {
            return Err("캡처 차단이 적용되지 않아 금고를 잠갔습니다.");
        }
    }
    Ok(())
}

pub fn copy_secret(h: Hwnd, text: &str) -> std::result::Result<u32, &'static str> {
    let data = secret_wide(text);
    unsafe {
        if OpenClipboard(h) == 0 {
            return Err("다른 프로그램이 클립보드를 사용 중입니다.");
        }
        struct Close;
        impl Drop for Close {
            fn drop(&mut self) {
                unsafe {
                    CloseClipboard();
                }
            }
        }
        let _close = Close;
        if EmptyClipboard() == 0 {
            return Err("클립보드를 비울 수 없습니다.");
        }
        // Keep the value out of Win+V history and cloud sync, and ask clipboard
        // managers that honour the convention not to record it.
        for name in [
            "CanIncludeInClipboardHistory",
            "CanUploadToCloudClipboard",
            "ExcludeClipboardContentFromMonitorProcessing",
        ] {
            let format = RegisterClipboardFormatW(wide(name).as_ptr());
            if format == 0 || put_clip(format, &[0u8; 4]).is_err() {
                EmptyClipboard();
                return Err("클립보드 기록 제외 설정 실패");
            }
        }
        let bytes = std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2);
        if put_clip(13, bytes).is_err() {
            EmptyClipboard();
            return Err("복사 실패");
        }
        drop(_close);
        Ok(GetClipboardSequenceNumber())
    }
}
unsafe fn put_clip(format: u32, data: &[u8]) -> std::result::Result<(), ()> {
    unsafe {
        let mem = GlobalAlloc(0x42, data.len());
        if mem == 0 {
            return Err(());
        }
        let ptr = GlobalLock(mem);
        if ptr.is_null() {
            GlobalFree(mem);
            return Err(());
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.cast::<u8>(), data.len());
        GlobalUnlock(mem);
        if SetClipboardData(format, mem) == 0 {
            let p = GlobalLock(mem);
            if !p.is_null() {
                std::ptr::write_bytes(p, 0, data.len());
                GlobalUnlock(mem);
            }
            GlobalFree(mem);
            return Err(());
        }
        Ok(())
    }
}
/// Empties the clipboard only if nothing replaced the content read at `sequence`.
pub fn clear_pasted(h: Hwnd, sequence: u32) -> bool {
    unsafe {
        if GetClipboardSequenceNumber() != sequence || OpenClipboard(h) == 0 {
            return false;
        }
        let clear = GetClipboardSequenceNumber() == sequence && EmptyClipboard() != 0;
        CloseClipboard();
        clear
    }
}
pub fn clear_clip(h: Hwnd, _sequence: u32) -> bool {
    unsafe {
        // Synthesized formats can change the sequence without replacing the
        // content. EmptyClipboard transfers ownership on a genuine replacement.
        if GetClipboardOwner() != h {
            return true;
        }
        if OpenClipboard(h) == 0 {
            return false;
        }
        let clear = if GetClipboardOwner() == h {
            EmptyClipboard() != 0
        } else {
            true
        };
        CloseClipboard();
        clear
    }
}
