//! Process-level Win32 calls of goyo-sync.exe: kernel32, plus advapi32 for
//! the Run value only. No sockets, no OS cryptography. The settings window
//! (gui.rs) draws with the vault app's win.rs and theme.rs; the defenses and
//! the process, job, event and registry calls stay here, because win.rs's
//! start-up defenses forbid the child processes this program exists to run.
use std::{
    ffi::{OsStr, OsString, c_void},
    fs::{File, OpenOptions},
    io::{self, Write},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    process::Child,
    ptr::{null, null_mut},
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetDefaultDllDirectories(flags: u32) -> i32;
    fn SetProcessMitigationPolicy(policy: i32, buf: *const u32, len: usize) -> i32;
    fn AttachConsole(process: u32) -> i32;
    fn GetStdHandle(which: u32) -> isize;
    fn SetStdHandle(which: u32, handle: isize) -> i32;
    fn GetConsoleMode(handle: isize, mode: *mut u32) -> i32;
    fn GetConsoleOutputCP() -> u32;
    fn WideCharToMultiByte(
        page: u32,
        flags: u32,
        wide: *const u16,
        wide_len: i32,
        out: *mut u8,
        out_len: i32,
        default: *const u8,
        used_default: *mut i32,
    ) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: isize,
    ) -> isize;
    fn GetFileInformationByHandle(file: isize, info: *mut ByHandleInfo) -> i32;
    fn GetSystemDirectoryW(buf: *mut u16, len: u32) -> u32;
    fn CreateJobObjectW(security: *const c_void, name: *const u16) -> isize;
    fn SetInformationJobObject(job: isize, class: i32, info: *const c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: isize, process: isize) -> i32;
    fn CreateMutexW(security: *const c_void, owner: i32, name: *const u16) -> isize;
    fn OpenMutexW(access: u32, inherit: i32, name: *const u16) -> isize;
    fn CreateProcessW(
        application: *const u16,
        command_line: *mut u16,
        process_security: *const c_void,
        thread_security: *const c_void,
        inherit_handles: i32,
        flags: u32,
        environment: *const c_void,
        directory: *const u16,
        startup: *const StartupInfo,
        info: *mut ProcessInfo,
    ) -> i32;
    fn CreateEventW(security: *const c_void, manual: i32, initial: i32, name: *const u16) -> isize;
    fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> isize;
    fn SetEvent(event: isize) -> i32;
    fn WaitForSingleObject(handle: isize, ms: u32) -> u32;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: isize) -> i32;
    fn GetCurrentProcess() -> isize;
    fn GetModuleHandleW(name: *const u16) -> isize;
    fn K32EnumProcessModules(proc: isize, modules: *mut isize, size: u32, needed: *mut u32) -> i32;
    fn GetModuleFileNameW(module: isize, name: *mut u16, size: u32) -> u32;
    fn GetUserDefaultUILanguage() -> u16;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegSetKeyValueW(
        key: isize,
        subkey: *const u16,
        value: *const u16,
        kind: u32,
        data: *const c_void,
        len: u32,
    ) -> i32;
    fn RegDeleteKeyValueW(key: isize, subkey: *const u16, value: *const u16) -> i32;
    fn RegGetValueW(
        key: isize,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut c_void,
        len: *mut u32,
    ) -> i32;
}

const STD_OUTPUT: u32 = -11i32 as u32;
const STD_ERROR: u32 = -12i32 as u32;
/// HKEY_CURRENT_USER: (HKEY)(LONG)0x80000001, sign-extended on x64.
const HKCU: isize = 0x8000_0001u32 as i32 as isize;
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// DLLs load from System32 only, and the process refuses dynamic code,
/// legacy extension points, non-system fonts, remote or low-integrity images
/// and DLLs not signed by Microsoft. Unlike the vault, child processes stay
/// allowed (policy 13 is not set): this program exists to start ssh.exe.
pub fn harden() -> Result<(), &'static str> {
    unsafe {
        if SetDefaultDllDirectories(0x800) == 0 {
            return Err("SetDefaultDllDirectories failed");
        }
        for (policy, flags) in [(2, 1u32), (6, 1), (9, 1), (10, 7), (8, 1)] {
            if SetProcessMitigationPolicy(policy, &flags, 4) == 0 {
                return Err("SetProcessMitigationPolicy failed");
            }
        }
    }
    Ok(())
}

fn invalid(handle: isize) -> bool {
    handle == 0 || handle == -1
}
/// A windows-subsystem program has no console. For CLI use it attaches to
/// the one it was started from: that gives the code page for piped output
/// (see [`print`]) and a place for whichever of stdout and stderr is not
/// redirected (`| Out-Host` pipes stdout only).
pub fn attach_console() {
    unsafe {
        if AttachConsole(u32::MAX) == 0 {
            return;
        }
        for which in [STD_OUTPUT, STD_ERROR] {
            if invalid(GetStdHandle(which)) {
                // GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | WRITE, OPEN_EXISTING
                let console = wide(OsStr::new("CONOUT$"));
                let h = CreateFileW(console.as_ptr(), 0xC000_0000, 3, null(), 3, 0, 0);
                if !invalid(h) {
                    SetStdHandle(which, h);
                }
            }
        }
    }
}
/// Writes CLI text. A console gets it as UTF-16 (std does that). A pipe to
/// PowerShell is decoded with the console's code page, so Korean text is
/// converted to it instead of being sent as UTF-8 that would be garbled.
pub fn print(text: &str, error: bool) {
    // The test harness captures only the print macros.
    if cfg!(test) {
        if error {
            eprint!("{text}");
        } else {
            print!("{text}");
        }
        return;
    }
    let handle = unsafe { GetStdHandle(if error { STD_ERROR } else { STD_OUTPUT }) };
    if invalid(handle) {
        return;
    }
    let mut mode = 0;
    let console = unsafe { GetConsoleMode(handle, &mut mode) } != 0;
    let page = unsafe { GetConsoleOutputCP() };
    let bytes = if console || page == 0 || page == 65001 || text.is_ascii() {
        text.as_bytes().to_vec()
    } else {
        code_page(text, page)
    };
    let _ = if error {
        io::stderr()
            .write_all(&bytes)
            .and_then(|_| io::stderr().flush())
    } else {
        io::stdout()
            .write_all(&bytes)
            .and_then(|_| io::stdout().flush())
    };
}
fn code_page(text: &str, page: u32) -> Vec<u8> {
    let w: Vec<u16> = text.encode_utf16().collect();
    let Ok(len) = i32::try_from(w.len()) else {
        return text.as_bytes().to_vec();
    };
    unsafe {
        let need = WideCharToMultiByte(page, 0, w.as_ptr(), len, null_mut(), 0, null(), null_mut());
        if need <= 0 {
            return text.as_bytes().to_vec();
        }
        let mut out = vec![0u8; need as usize];
        let n = WideCharToMultiByte(
            page,
            0,
            w.as_ptr(),
            len,
            out.as_mut_ptr(),
            need,
            null(),
            null_mut(),
        );
        out.truncate(n.max(0) as usize);
        out
    }
}

/// `<System32>` from the OS, never from the environment.
pub fn system_dir() -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(OsString::from_wide(&buf[..n])))
}
/// LANG_KOREAN is 0x12.
pub fn korean_ui() -> bool {
    unsafe { GetUserDefaultUILanguage() & 0x3ff == 0x12 }
}

/// A kernel handle closed on drop.
pub struct Handle(isize);
impl Handle {
    fn new(raw: isize) -> Option<Self> {
        (!invalid(raw)).then_some(Self(raw))
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct BasicLimits {
    per_process_time: i64,
    per_job_time: i64,
    flags: u32,
    min_working_set: usize,
    max_working_set: usize,
    active_processes: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
}
/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
#[repr(C)]
#[derive(Default)]
struct ExtendedLimits {
    basic: BasicLimits,
    io: [u64; 6],
    process_memory: usize,
    job_memory: usize,
    peak_process_memory: usize,
    peak_job_memory: usize,
}
/// A job whose processes are killed when it closes: when the helper drops
/// it, exits or is killed, no ssh.exe (or anything ssh started) outlives it.
pub struct Job(Handle);
impl Job {
    pub fn new() -> Option<Self> {
        let job = Handle::new(unsafe { CreateJobObjectW(null(), null()) })?;
        let mut limits = ExtendedLimits::default();
        limits.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                9, // JobObjectExtendedLimitInformation
                (&raw const limits).cast(),
                size_of::<ExtendedLimits>() as u32,
            )
        };
        (ok != 0).then_some(Self(job))
    }
    pub fn assign(&self, child: &Child) -> bool {
        unsafe { AssignProcessToJobObject(self.0.0, child.as_raw_handle() as isize) != 0 }
    }
}

/// A named mutex; `None` if it could not be created. The flag says whether
/// it already existed, i.e. another instance holds it.
pub fn named_mutex(name: &str) -> Option<(Handle, bool)> {
    let name = wide(OsStr::new(name));
    unsafe {
        let raw = CreateMutexW(null(), 0, name.as_ptr());
        let existed = GetLastError() == 183; // ERROR_ALREADY_EXISTS
        Handle::new(raw).map(|h| (h, existed))
    }
}
/// Whether a named mutex exists, i.e. another process holds it. Only opens
/// it, and closes it at once: a handle kept open would keep the name alive
/// after its owner exits, and the next owner would think one still runs.
pub fn mutex_exists(name: &str) -> bool {
    let name = wide(OsStr::new(name));
    unsafe {
        // SYNCHRONIZE
        let raw = OpenMutexW(0x0010_0000, 0, name.as_ptr());
        if raw != 0 {
            CloseHandle(raw);
            return true;
        }
        GetLastError() == 5 // ERROR_ACCESS_DENIED: it exists
    }
}
/// A manual-reset event that stays set once signalled.
pub struct Event(Handle);
impl Event {
    pub fn create(name: &str) -> Option<Self> {
        let name = wide(OsStr::new(name));
        Handle::new(unsafe { CreateEventW(null(), 1, 0, name.as_ptr()) }).map(Self)
    }
    /// Sets an event another process created; false if there is none.
    pub fn signal(name: &str) -> bool {
        let name = wide(OsStr::new(name));
        // EVENT_MODIFY_STATE
        let Some(h) = Handle::new(unsafe { OpenEventW(2, 0, name.as_ptr()) }) else {
            return false;
        };
        unsafe { SetEvent(h.0) != 0 }
    }
    /// The raw handle, valid while this `Event` lives.
    pub fn raw(&self) -> isize {
        self.0.0
    }
}
/// Waits up to `ms` for `handle`; true if it is signalled.
pub fn wait(handle: isize, ms: u32) -> bool {
    unsafe { WaitForSingleObject(handle, ms) == 0 }
}

/// The HKCU Run value, so the helper starts at sign-in. Only on request.
pub fn set_run_value(name: &str, command: &OsStr) -> Result<(), i32> {
    let (key, value, data) = (
        wide(OsStr::new(RUN_KEY)),
        wide(OsStr::new(name)),
        wide(command),
    );
    let len = (data.len() * 2) as u32;
    let code = unsafe {
        // REG_SZ
        RegSetKeyValueW(
            HKCU,
            key.as_ptr(),
            value.as_ptr(),
            1,
            data.as_ptr().cast(),
            len,
        )
    };
    if code == 0 { Ok(()) } else { Err(code) }
}
/// The Run value as text, if there is one (REG_SZ only).
pub fn run_value(name: &str) -> Option<OsString> {
    let (key, value) = (wide(OsStr::new(RUN_KEY)), wide(OsStr::new(name)));
    let mut buf = vec![0u16; 2048];
    let mut len = (buf.len() * 2) as u32;
    let code = unsafe {
        // RRF_RT_REG_SZ
        RegGetValueW(
            HKCU,
            key.as_ptr(),
            value.as_ptr(),
            2,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if code != 0 {
        return None;
    }
    buf.truncate((len as usize / 2).min(buf.len()));
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Some(OsString::from_wide(&buf))
}
pub fn delete_run_value(name: &str) -> Result<(), i32> {
    let (key, value) = (wide(OsStr::new(RUN_KEY)), wide(OsStr::new(name)));
    match unsafe { RegDeleteKeyValueW(HKCU, key.as_ptr(), value.as_ptr()) } {
        0 | 2 => Ok(()), // ERROR_FILE_NOT_FOUND: already off
        code => Err(code),
    }
}

/// DLLs loaded from the exe's own folder. Every DLL the helper uses lives in
/// System32, so one found next to the exe was planted there. (A copy of
/// win.rs `modules_beside_exe`, which is private to the vault binary.)
pub fn modules_beside_exe() -> Vec<PathBuf> {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
    else {
        return vec![];
    };
    let exe = unsafe { GetModuleHandleW(null()) };
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
        let path = PathBuf::from(OsString::from_wide(&name[..n]));
        let parent = path.parent().map(|p| p.to_string_lossy().to_lowercase());
        if parent == Some(dir.to_string_lossy().to_lowercase()) {
            found.push(path);
        }
    }
    found
}

#[repr(C)]
pub struct StartupInfo {
    size: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    columns: u32,
    rows: u32,
    fill: u32,
    flags: u32,
    show: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    stdin: isize,
    stdout: isize,
    stderr: isize,
}
#[repr(C)]
#[derive(Default)]
pub struct ProcessInfo {
    process: isize,
    thread: isize,
    pid: u32,
    tid: u32,
}
/// Starts `"<exe>" <args>` on its own: no window, no console, no handle
/// inherited from this process (so not the pipes of an ssh.exe running
/// meanwhile), outside any job of this process where Windows allows it, and
/// in System32, so it holds no user folder open. Returns the Windows error.
pub fn start_detached(exe: &Path, args: &str) -> Result<(), u32> {
    let application: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut line: Vec<u16> = OsStr::new("\"")
        .encode_wide()
        .chain(exe.as_os_str().encode_wide())
        .chain(OsStr::new("\" ").encode_wide())
        .chain(OsStr::new(args).encode_wide())
        .chain(Some(0))
        .collect();
    if application[..application.len() - 1].contains(&0)
        || exe.as_os_str().encode_wide().any(|c| c == u16::from(b'"'))
    {
        return Err(87); // ERROR_INVALID_PARAMETER
    }
    let directory = system_dir().map(|d| wide(d.as_os_str()));
    let startup = StartupInfo {
        size: size_of::<StartupInfo>() as u32,
        reserved: null_mut(),
        desktop: null_mut(),
        title: null_mut(),
        x: 0,
        y: 0,
        width: 0,
        height: 0,
        columns: 0,
        rows: 0,
        fill: 0,
        flags: 0,
        show: 0,
        reserved2_len: 0,
        reserved2: null_mut(),
        stdin: 0,
        stdout: 0,
        stderr: 0,
    };
    // CREATE_NO_WINDOW, then CREATE_BREAKAWAY_FROM_JOB while a job of the
    // caller (a terminal, an IDE) allows it.
    for flags in [0x0800_0000 | 0x0100_0000, 0x0800_0000] {
        let mut info = ProcessInfo::default();
        let ok = unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                0,
                flags,
                null(),
                directory.as_ref().map_or(null(), |d| d.as_ptr()),
                &startup,
                &mut info,
            )
        };
        if ok != 0 {
            unsafe {
                CloseHandle(info.thread);
                CloseHandle(info.process);
            }
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        if code != 5 {
            return Err(code);
        }
    }
    Err(5)
}

#[repr(C)]
#[derive(Default)]
struct ByHandleInfo {
    attributes: u32,
    created: [u32; 2],
    accessed: [u32; 2],
    written: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
/// What the upload gate needs to know about an open file.
pub struct FileInfo {
    pub attributes: u32,
    pub links: u32,
    pub size: u64,
}
/// Opens `path` itself even if it is a symlink or junction
/// (FILE_FLAG_OPEN_REPARSE_POINT), so a link is seen as a link and its
/// target, perhaps a key file, is never opened. FILE_FLAG_BACKUP_SEMANTICS
/// lets a directory open too, so it is refused instead of failing quietly.
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000 | 0x0200_0000)
        .open(path)
}
pub fn file_info(file: &File) -> io::Result<FileInfo> {
    let mut info = ByHandleInfo::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileInfo {
        attributes: info.attributes,
        links: info.links,
        size: (u64::from(info.size_high) << 32) | u64::from(info.size_low),
    })
}

#[cfg(test)]
pub fn layout_sizes() -> (usize, usize, usize, usize, usize) {
    (
        size_of::<BasicLimits>(),
        size_of::<ExtendedLimits>(),
        size_of::<ByHandleInfo>(),
        size_of::<StartupInfo>(),
        size_of::<ProcessInfo>(),
    )
}
