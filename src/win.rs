//! Minimal Win32 UI/clipboard/defense bindings. Cryptography never calls Win32.
#![allow(non_snake_case, dead_code)]
use std::{ffi::c_void, mem::size_of, path::PathBuf};
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
    pub fn SetTimer(h: Hwnd, id: usize, ms: u32, callback: isize) -> usize;
    pub fn MessageBoxW(h: Hwnd, text: *const u16, title: *const u16, flags: u32) -> i32;
    pub fn LoadCursorW(instance: isize, id: *const u16) -> isize;
    pub fn BeginPaint(h: Hwnd, p: *mut Paint) -> isize;
    pub fn GetDC(h: Hwnd) -> isize;
    pub fn ReleaseDC(h: Hwnd, dc: isize) -> i32;
    pub fn EndPaint(h: Hwnd, p: *const Paint) -> i32;
    pub fn InvalidateRect(h: Hwnd, r: *const Rect, erase: i32) -> i32;
    pub fn RedrawWindow(h: Hwnd, r: *const Rect, region: isize, flags: u32) -> i32;
    pub fn MessageBeep(kind: u32) -> i32;
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
    pub fn GetModuleHandleW(name: *const u16) -> isize;
    pub fn IsDebuggerPresent() -> i32;
    pub fn CheckRemoteDebuggerPresent(proc: isize, present: *mut i32) -> i32;
    pub fn GetCurrentProcess() -> isize;
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
}
#[link(name = "wtsapi32")]
unsafe extern "system" {
    pub fn WTSRegisterSessionNotification(hwnd: Hwnd, flags: u32) -> i32;
    pub fn WTSUnRegisterSessionNotification(hwnd: Hwnd) -> i32;
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
pub fn clipboard_text(h: Hwnd) -> std::result::Result<Zeroizing<Vec<u16>>, &'static str> {
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
            value
        })();
        CloseClipboard();
        result
    }
}
pub fn message(h: Hwnd, s: &str) {
    unsafe {
        MessageBoxW(h, wide(s).as_ptr(), wide("고요 금고").as_ptr(), 0x40);
    }
}
pub fn confirm(h: Hwnd, s: &str) -> bool {
    unsafe { MessageBoxW(h, wide(s).as_ptr(), wide("고요 금고").as_ptr(), 0x124) == 6 }
}
pub fn dialog(h: Hwnd, save: bool, key: bool) -> Option<PathBuf> {
    let mut file = vec![0u16; 32768];
    let filter = wide(if key {
        "고요 열쇠 파일 (*.goyokey)\0*.goyokey\0모든 파일\0*.*\0"
    } else {
        "고요 금고/백업 (*.goyo)\0*.goyo\0모든 파일\0*.*\0"
    });
    let ext = wide(if key { "goyokey" } else { "goyo" });
    let title = wide(if save {
        "새 파일 이름을 선택하세요 (기존 파일 덮어쓰기 금지)"
    } else {
        "파일 선택"
    });
    let mut o: OpenFile = unsafe { std::mem::zeroed() };
    o.size = size_of::<OpenFile>() as u32;
    o.owner = h;
    o.filter = filter.as_ptr();
    o.index = 1;
    o.file = file.as_mut_ptr();
    o.max_file = file.len() as u32;
    o.title = title.as_ptr();
    o.def_ext = ext.as_ptr();
    o.flags = 0x80000 | 0x800 | 0x8 | 0x02000000 | if save { 0x2 } else { 0x1000 };
    let ok = unsafe {
        if save {
            GetSaveFileNameW(&mut o)
        } else {
            GetOpenFileNameW(&mut o)
        }
    };
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
