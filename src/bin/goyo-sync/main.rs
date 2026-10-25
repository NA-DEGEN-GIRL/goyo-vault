#![windows_subsystem = "windows"]
//! goyo-sync.exe: the optional sync helper. It moves only the encrypted
//! vault file between `<vault>.sync\` and the user's own SSH server by
//! running Windows' `ssh.exe`; it has no socket, HTTP or crypto code of its
//! own (SHA-256 comes from the `sha2` crate), never decrypts anything and
//! never opens the vault file or a key file. goyo-vault.exe does every
//! decryption and merge, and decides what is "synced".
//!
//! Without arguments it opens the settings window (gui.rs, one per exe
//! path), which writes goyo-sync.conf, installs the server script and starts
//! the background helper. `--background` is the helper itself (one instance
//! per exe path) until `--stop`. Exit codes: 0 ok, 1 error, 2 settings.
#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("goyo-sync requires Windows x64.");
mod config;
#[cfg(test)]
mod e2e;
mod engine;
mod gui;
// The vault app's look: its palette, fonts and owner-drawn controls, and its
// Win32 bindings and translations. Only drawing, dialogs and message checks
// are used; never win.rs's start-up defenses, which forbid child processes
// (sys.rs keeps this program's own).
#[allow(dead_code)]
#[path = "../../i18n.rs"]
mod i18n;
mod msg;
mod setup;
mod sys;
#[cfg(test)]
mod tests;
#[allow(dead_code)]
#[path = "../../theme.rs"]
mod theme;
mod transport;
#[path = "../../win.rs"]
mod win;

use config::{Config, Problem};
use engine::{Engine, Folder, Log, Outcome, Report, call, tag, utc};
use goyo_vault::{
    syncfile::{self, STATUS, SyncState},
    syncwire::{self, Request, Status},
};
use msg::{Msg, say, warn};
use std::{
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use transport::{SshTransport, Transport};

const CONFIG: &str = "goyo-sync.conf";
const LOG: &str = "goyo-sync.log";
const RUN_VALUE: &str = "GoyoSync";
const OK: i32 = 0;
const ERROR: i32 = 1;
const CONFIG_ERROR: i32 = 2;
/// The background loop's tick: stamps are listed, nothing is opened.
const TICK: u32 = 2000;

fn main() {
    // Before anything else can load a DLL.
    let hardened = sys::harden();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let log = Log::new(dir.as_ref().map(|d| d.join(LOG)));
    let panic_log = log.clone();
    std::panic::set_hook(Box::new(move |info| {
        panic_log.line(&format!("panic: {info}"));
    }));
    // The CLI commands print to the console they were started from. Neither
    // the window nor the background helper attaches: closing that console
    // would end the helper.
    let background = args.first().is_some_and(|a| a == "--background");
    if !args.is_empty() && !background {
        sys::attach_console();
    }
    msg::init(dir.as_deref());
    let code = match (hardened, dir) {
        (Err(e), _) => {
            log.line(&format!("startup failed: {e}"));
            if args.first().is_some_and(|a| a == "--self-check") {
                sys::print(&format!("FAIL: {e}\n"), true);
            } else if args.is_empty() {
                gui::startup_failed(&msg::fill(Msg::Defenses, &[&e]));
            } else if !background {
                warn(Msg::Defenses, &[&e]);
            }
            ERROR
        }
        (Ok(()), Some(dir)) => run(&args, &dir, &log),
        (Ok(()), None) => ERROR,
    };
    std::process::exit(code);
}

fn run(args: &[OsString], dir: &Path, log: &Log) -> i32 {
    let command = args.first().map(|a| a.to_str().unwrap_or(""));
    match (command, args.len()) {
        (None, _) => gui::run(dir, log),
        (Some("--background"), 1) => background(dir, log),
        (Some("--once"), 1) => once(dir, log),
        (Some("--check"), 1) => check(dir, log),
        (Some("--list"), 1) => list(dir, log),
        (Some("--fetch"), 4) => fetch(dir, log, &args[1], &args[2], &args[3]),
        (Some("--autostart"), 2) => autostart(args[1].to_str()),
        (Some("--stop"), 1) => stop(),
        (Some("--self-check"), 1) => self_check(),
        (Some("--help" | "-h" | "/?"), 1) => {
            say(Msg::Usage, &[]);
            OK
        }
        _ => {
            warn(Msg::Usage, &[]);
            ERROR
        }
    }
}

/// The instance mutex and stop event, named from the exe path so two
/// GoyoVault folders on one PC each run their own helper.
fn object_names() -> (String, String) {
    let id = exe_id();
    (
        format!(r"Local\GoyoSync-{id}"),
        format!(r"Local\GoyoSyncStop-{id}"),
    )
}
/// The settings window's own instance mutex and window class, so a second
/// start of the same exe brings its window forward instead.
fn window_names() -> (String, String) {
    let id = exe_id();
    (
        format!(r"Local\GoyoSyncWindow-{id}"),
        format!("GoyoSyncWindow-{id}"),
    )
}
fn exe_id() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    syncfile::hex(&syncwire::sha256(exe.as_bytes())[..8])
}
/// The Run value's command: the background helper of this exe.
fn autostart_command(exe: &Path) -> OsString {
    let mut command = OsString::from("\"");
    command.push(exe);
    command.push("\" --background");
    command
}
fn now() -> u64 {
    engine::system_clock()().as_secs()
}

/// Reads goyo-sync.conf next to the exe. A bad file is fatal (exit 2) and
/// logged; with `mark`, the folders of the vault lines that were valid get
/// `state=config`, so the app shows a warning instead of "helper off".
fn load_config(dir: &Path, log: &Log, cli: bool, mark: bool) -> Result<Config, i32> {
    let path = dir.join(CONFIG);
    config::load(&path).map_err(|e| {
        log.line(&format!(
            "state=config: {CONFIG} line {} {:?}",
            e.line, e.problem
        ));
        if cli {
            report_config(e.line, e.problem, &path);
        }
        if mark {
            for vault in &e.vaults {
                if let Some(sync) = syncfile::sync_dir(vault)
                    && syncfile::usable_dir(&sync)
                {
                    let contact = syncfile::read_status(&sync).map_or(0, |s| s.contact);
                    let status = syncfile::render_status(now(), contact, SyncState::Config);
                    let _ = syncfile::replace_file(&sync.join(STATUS), &status);
                }
            }
        }
        CONFIG_ERROR
    })
}
fn report_config(line: usize, problem: Problem, path: &Path) {
    let what = match problem {
        Problem::Missing => return warn(Msg::ConfigMissing, &[&path.display()]),
        Problem::Unreadable => return warn(Msg::ConfigUnreadable, &[&path.display()]),
        Problem::TooLarge => return warn(Msg::ConfigTooLarge, &[]),
        Problem::NotUtf8 => return warn(Msg::ConfigNotUtf8, &[]),
        Problem::NoHost => return warn(Msg::ConfigNoHost, &[]),
        Problem::NoVault => return warn(Msg::ConfigNoVault, &[]),
        Problem::NoEquals => Msg::NoEquals,
        Problem::UnknownKey => Msg::UnknownKey,
        Problem::Duplicate => Msg::Duplicate,
        Problem::Host => Msg::BadHost,
        Problem::Remote => Msg::BadRemote,
        Problem::Python => Msg::BadPython,
        Problem::Identity => Msg::BadIdentity,
        Problem::Interval => Msg::BadInterval,
        Problem::Timeout => Msg::BadTimeout,
        Problem::Vault => Msg::BadVault,
        Problem::KeyFile => Msg::KeyFileVault,
        Problem::TooManyVaults => Msg::TooManyVaults,
        Problem::DuplicateVault => Msg::DuplicateVault,
    };
    warn(Msg::ConfigLine, &[&line, &msg::text(what)]);
}
fn state_message(state: SyncState) -> Msg {
    match state {
        SyncState::Offline => Msg::StateOffline,
        SyncState::Auth => Msg::StateAuth,
        SyncState::HostKey => Msg::StateHostKey,
        SyncState::NoSsh => Msg::StateNoSsh,
        SyncState::Refused => Msg::StateRefused,
        SyncState::Update => Msg::StateUpdate,
        SyncState::Config => Msg::PassUnusable,
        SyncState::Ok | SyncState::Idle | SyncState::Server => Msg::StateServer,
    }
}
/// For the CLI commands: no stop event, plain sleeps.
fn cli_transport(config: &Config) -> SshTransport {
    SshTransport::new(
        config,
        Box::new(|d| {
            std::thread::sleep(d);
            false
        }),
    )
}
/// Prints why an exchange without a valid response failed.
fn report_failure(host: &str, error: engine::CallError) {
    if let engine::CallError::Failed(state, detail) = error {
        warn(state_message(state), &[&host]);
        if !detail.is_empty() {
            warn(Msg::StderrLine, &[&detail]);
        }
    }
}

/// `--background`: sync every vault until the stop event is set. Each 2 s
/// tick lists the sync folders and runs a pass where one is due.
fn background(dir: &Path, log: &Log) -> i32 {
    let (mutex, stop_name) = object_names();
    let Some((_instance, existed)) = sys::named_mutex(&mutex) else {
        log.line("startup failed: no instance mutex");
        return ERROR;
    };
    if existed {
        return OK; // already running for this exe
    }
    let config = match load_config(dir, log, false, true) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let Some(stop) = sys::Event::create(&stop_name) else {
        log.line("startup failed: no stop event");
        return ERROR;
    };
    let raw = stop.raw();
    let wait = move |d: Duration| sys::wait(raw, d.as_millis().min(u128::from(TICK)) as u32);
    let transport = SshTransport::new(&config, Box::new(wait));
    let mut engine = Engine::new(
        transport,
        &config.vaults,
        config.interval,
        engine::system_clock(),
        log.clone(),
    );
    log.line(&format!(
        "started: {} vaults, every {} s, timeout {} s",
        config.vaults.len(),
        config.interval,
        config.timeout
    ));
    'run: loop {
        for i in 0..engine.vaults() {
            if sys::wait(raw, 0) {
                break 'run;
            }
            if engine.due(i) {
                engine.pass(i, false);
            }
        }
        if sys::wait(raw, TICK) {
            break;
        }
    }
    drop(engine);
    log.line("stopped");
    OK
}

/// `--once`: one pass over every vault, polling the server, with results.
fn once(dir: &Path, log: &Log) -> i32 {
    let config = match load_config(dir, log, true, true) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let mut engine = Engine::new(
        cli_transport(&config),
        &config.vaults,
        config.interval,
        engine::system_clock(),
        log.clone(),
    );
    let mut code = OK;
    for i in 0..engine.vaults() {
        let name = engine.path(i).display().to_string();
        match engine.pass(i, true) {
            Outcome::Locked => say(Msg::PassLocked, &[&name]),
            Outcome::Folder(Folder::NoVault) => {
                warn(Msg::PassNoVault, &[&name]);
                code = ERROR;
            }
            Outcome::Folder(Folder::Unusable) => {
                warn(Msg::PassUnusable, &[&name]);
                code = ERROR;
            }
            Outcome::Done(report) => {
                if !print_report(&name, &report) {
                    code = ERROR;
                }
            }
        }
    }
    code
}
fn print_report(name: &str, r: &Report) -> bool {
    match r.state {
        SyncState::Ok => {
            match (r.uploaded, r.downloaded) {
                (Some(v), _) => say(Msg::PassUploaded, &[&name, &v]),
                (None, Some(v)) => say(Msg::PassDownloaded, &[&name, &v]),
                _ if r.server > 0 => say(Msg::PassCurrent, &[&name, &r.server]),
                _ => say(Msg::PassNothing, &[&name]),
            }
            true
        }
        SyncState::Idle => {
            say(Msg::PassIdle, &[&name]);
            true
        }
        state => {
            warn(state_message(state), &[&name]);
            false
        }
    }
}

/// `--check`: read-only. Settings, ssh.exe, a HELLO whose 512-byte echo
/// proves the ssh pipe is binary-transparent, then LIST; per vault the
/// folder, the pinned ID and the server's head. Writes no sync file.
fn check(dir: &Path, log: &Log) -> i32 {
    let config = match load_config(dir, log, true, false) {
        Ok(config) => config,
        Err(code) => return code,
    };
    say(Msg::SettingsOk, &[&config.host, &config.vaults.len()]);
    let mut transport = cli_transport(&config);
    match transport.program() {
        Some(p) if p.is_file() => say(Msg::SshFound, &[&p.display()]),
        p => {
            let shown = p.map_or_else(
                || r"System32\OpenSSH\ssh.exe".into(),
                |p| p.display().to_string(),
            );
            warn(Msg::SshMissing, &[&shown]);
            return ERROR;
        }
    }
    match call(&mut transport, &Request::hello(), "check", log) {
        Ok(reply) if reply.status == Status::Ok => say(Msg::HelloOk, &[]),
        Ok(_) => {
            warn(Msg::StateServer, &[&config.host]);
            return ERROR;
        }
        Err(e) => {
            report_failure(&config.host, e);
            return ERROR;
        }
    }
    let listing = match call(&mut transport, &Request::list(), "check", log) {
        Ok(reply) if reply.status == Status::Ok => syncwire::parse_list(reply.blob()),
        Ok(_) => None,
        Err(e) => {
            report_failure(&config.host, e);
            return ERROR;
        }
    };
    let Some(listing) = listing else {
        warn(Msg::StateServer, &[&config.host]);
        return ERROR;
    };
    say(Msg::ServerVaults, &[&listing.len()]);
    for vault in &config.vaults {
        say(Msg::VaultHeading, &[&vault.display()]);
        let sync = syncfile::sync_dir(vault).filter(|d| {
            let usable = syncfile::usable_dir(d);
            if usable {
                say(Msg::FolderPresent, &[]);
            } else if std::fs::symlink_metadata(d).is_ok() {
                say(Msg::FolderUnusable, &[]);
            } else {
                say(Msg::FolderMissing, &[]);
            }
            usable
        });
        // As pinned in helper.state, else as named by incoming's header.
        let id = sync.and_then(|d| {
            syncfile::read_helper_state(&d)
                .and_then(|s| s.id)
                .or_else(|| engine::from_incoming(&d).2)
        });
        let Some(id) = id else {
            say(Msg::NotPinned, &[]);
            continue;
        };
        say(
            Msg::Pinned,
            &[&format!("{} ({})", tag(&id), syncfile::hex(&id))],
        );
        match listing.iter().find(|e| e.id == id && e.head > 0) {
            Some(e) => say(Msg::ServerHead, &[&e.head, &e.size]),
            None => say(Msg::ServerNone, &[]),
        }
    }
    OK
}

/// `--list`: every vault on the server.
fn list(dir: &Path, log: &Log) -> i32 {
    let config = match load_config(dir, log, true, false) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let mut transport = cli_transport(&config);
    let listing = match call(&mut transport, &Request::list(), "list", log) {
        Ok(reply) if reply.status == Status::Ok => syncwire::parse_list(reply.blob()),
        Ok(_) => None,
        Err(e) => {
            report_failure(&config.host, e);
            return ERROR;
        }
    };
    let Some(listing) = listing else {
        warn(Msg::StateServer, &[&config.host]);
        return ERROR;
    };
    if listing.is_empty() {
        say(Msg::ListEmpty, &[]);
    }
    for e in &listing {
        let id = syncfile::hex(&e.id);
        say(
            Msg::ListRow,
            &[&tag(&e.id), &id, &e.head, &e.size, &utc(e.mtime)],
        );
    }
    OK
}

/// `--fetch <id> <head|N> <new file>`: one server version, checked (frame
/// SHA, GOYOVA02, this vault's ID) and written to a new file, never over an
/// existing one. The app's Restore screen opens it.
fn fetch(dir: &Path, log: &Log, id: &OsStr, version: &OsStr, out: &OsStr) -> i32 {
    let id = id
        .to_str()
        .and_then(|s| syncfile::parse_hex::<16>(&s.to_ascii_lowercase()))
        .filter(|id| *id != [0; 16]);
    let Some(id) = id else {
        warn(Msg::FetchBadId, &[]);
        return ERROR;
    };
    let number = match version.to_str() {
        Some("head") => Some(0),
        Some(s) if !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse::<u64>().ok().filter(|n| *n >= 1)
        }
        _ => None,
    };
    let Some(number) = number else {
        warn(Msg::FetchBadVersion, &[]);
        return ERROR;
    };
    let path = PathBuf::from(out);
    if std::fs::symlink_metadata(&path).is_ok() {
        warn(Msg::FetchExists, &[&path.display()]);
        return ERROR;
    }
    let config = match load_config(dir, log, true, false) {
        Ok(config) => config,
        Err(code) => return code,
    };
    fetch_into(
        &mut cli_transport(&config),
        log,
        &config.host,
        id,
        number,
        &path,
    )
}
/// The exchange and the write of `--fetch`, with its messages.
fn fetch_into<T: Transport>(
    transport: &mut T,
    log: &Log,
    host: &str,
    id: [u8; 16],
    number: u64,
    path: &Path,
) -> i32 {
    match fetch_file(transport, log, id, number, path) {
        Fetched::Saved { version, bytes } => {
            say(Msg::FetchSaved, &[&version, &bytes, &path.display()]);
            OK
        }
        Fetched::Failed(e) => {
            report_failure(host, e);
            ERROR
        }
        Fetched::NotFound => {
            warn(Msg::FetchNotFound, &[]);
            ERROR
        }
        Fetched::Server => {
            warn(Msg::StateServer, &[&host]);
            ERROR
        }
        Fetched::Write => {
            warn(Msg::FetchWriteFailed, &[&path.display()]);
            ERROR
        }
    }
}
/// What [`fetch_file`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Fetched {
    Saved {
        version: u64,
        bytes: usize,
    },
    /// No valid response.
    Failed(engine::CallError),
    NotFound,
    /// A valid response with another status.
    Server,
    /// The new file could not be created or written (it may exist now).
    Write,
}
/// One server version, checked (frame SHA, GOYOVA02, this vault's ID) and
/// written to a new file, never over an existing one (`--fetch` and the
/// settings window). A file it could not finish is removed again, so
/// Restore never offers a cut-off copy.
fn fetch_file<T: Transport>(
    transport: &mut T,
    log: &Log,
    id: [u8; 16],
    number: u64,
    path: &Path,
) -> Fetched {
    let reply = match call(transport, &Request::fetch(id, number), "fetch", log) {
        Ok(reply) => reply,
        Err(e) => return Fetched::Failed(e),
    };
    match reply.status {
        Status::Ok => {}
        Status::NotFound => return Fetched::NotFound,
        _ => return Fetched::Server,
    }
    let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(path) else {
        return Fetched::Write;
    };
    if file
        .write_all(reply.blob())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = std::fs::remove_file(path); // created above, so ours
        return Fetched::Write;
    }
    Fetched::Saved {
        version: reply.version,
        bytes: reply.blob().len(),
    }
}

/// `--autostart on|off`: the HKCU Run value, written only on request.
fn autostart(choice: Option<&str>) -> i32 {
    let result = match choice {
        Some("on") => {
            let Ok(exe) = std::env::current_exe() else {
                return ERROR;
            };
            sys::set_run_value(RUN_VALUE, &autostart_command(&exe)).map(|()| Msg::AutostartOn)
        }
        Some("off") => sys::delete_run_value(RUN_VALUE).map(|()| {
            sys::Event::signal(&object_names().1);
            Msg::AutostartOff
        }),
        _ => {
            warn(Msg::Usage, &[]);
            return ERROR;
        }
    };
    match result {
        Ok(m) => {
            say(m, &[]);
            OK
        }
        Err(code) => {
            warn(Msg::AutostartFailed, &[&code]);
            ERROR
        }
    }
}
fn stop() -> i32 {
    if sys::Event::signal(&object_names().1) {
        say(Msg::Stopped, &[]);
    } else {
        say(Msg::NotRunning, &[]);
    }
    OK
}
/// `--self-check` (used by check_dll_planting.py): the defenses applied in
/// `main`, the settings window built hidden (so the DLLs it loads load
/// here too), no DLL loaded from the exe's folder, a kill-on-close job, and
/// ssh.exe where it must be. Fixed English, read by scripts.
fn self_check() -> i32 {
    let mut ok = true;
    if !gui::self_check() {
        sys::print("FAIL: the settings window could not be built\n", true);
        ok = false;
    }
    for planted in sys::modules_beside_exe() {
        sys::print(
            &format!(
                "FAIL: DLL loaded from the program folder: {}\n",
                planted.display()
            ),
            true,
        );
        ok = false;
    }
    if sys::Job::new().is_none() {
        sys::print("FAIL: cannot create a kill-on-close job\n", true);
        ok = false;
    }
    let ssh = sys::system_dir().map(|d| transport::ssh_program(&d));
    if !ssh.as_ref().is_some_and(|p| p.is_file()) {
        sys::print("FAIL: System32\\OpenSSH\\ssh.exe not found\n", true);
        ok = false;
    }
    if !ok {
        return ERROR;
    }
    sys::print(
        "PASS: process mitigations, System32-only DLL search, settings window, no DLL beside the exe, kill-on-close job, ssh.exe present\n",
        false,
    );
    OK
}
