//! Moving one request frame through a child process (spec §9.7, §9.8). The
//! helper itself has no socket code: it runs `<System32>\OpenSSH\ssh.exe`
//! with a fixed argv, writes the frame to its stdin, closes it, and reads a
//! bounded stdout. All variable data travels inside the frame; the remote
//! command line holds only validated config tokens and the word `serve`.
//! ssh's own messages come back in a file of each call (`-E`), apart from
//! the remote side's stderr.
use crate::{config::Config, sys};
// The engine's side of an exchange, in the lib with the engine.
#[cfg(test)]
pub use goyo_vault::syncengine::transport::key_ignored;
pub use goyo_vault::syncengine::transport::{
    Failure, KEY_IGNORED, Killed, MAX_STDERR, MAX_STDOUT, Output, Transport, classify, first_line,
};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const POLL: Duration = Duration::from_millis(50);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Each call's ssh log in this account's %TEMP% (else beside the exe):
/// `goyo-sync.ssh-<pid>-<nanos>-<n>.log` (hex), removed when the call ends.
pub const SSH_LOG: [&str; 2] = ["goyo-sync.ssh-", ".log"];
/// One left by a helper killed mid-call is removed at a later start once it
/// is this old (no call outlives the 600 s timeout), or once it is
/// [`STALE_EMPTY_LOG`] old while it is empty: ssh never wrote to it.
pub const STALE_LOG: Duration = Duration::from_secs(3600);
/// An empty log this old is debris: ssh holds its log exclusively while it
/// runs, so only the moments before it opens it and after it exits are
/// left, far shorter than this.
pub const STALE_EMPTY_LOG: Duration = Duration::from_secs(60);
/// The fixed ssh options, in order: no TTY, no forwarding, no escape
/// character, never a password or host-key prompt, no local commands.
const SSH_OPTIONS: [&str; 10] = [
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "UpdateHostKeys=no",
    "ConnectTimeout=20",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=3",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RequestTTY=no",
    "LogLevel=ERROR",
];

/// Sleeps up to the given time; true if the helper was asked to stop.
pub type Wait = Box<dyn Fn(Duration) -> bool>;

/// Runs `command` with `input` on stdin and bounded output. A writer thread
/// feeds stdin and then closes it, so an 8 MiB request cannot deadlock
/// against a child that writes before it has read everything. The child is
/// killed on `timeout`, on stdout overflow and on a stop request (`wait`
/// returns true), and runs in a kill-on-close job, so nothing it started
/// outlives this call.
pub fn run_bounded(
    mut command: Command,
    input: &[u8],
    timeout: Duration,
    wait: &mut dyn FnMut(Duration) -> bool,
) -> Result<Output, Failure> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let job = sys::Job::new().ok_or(Failure::Start)?;
    let mut child = command.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Failure::Missing,
        _ => Failure::Start,
    })?;
    if !job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Failure::Start);
    }
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Failure::Start);
    };
    let overflow = AtomicBool::new(false);
    let started = Instant::now();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            // A child that exits early breaks the pipe; its output decides.
            let _ = stdin.write_all(input);
        });
        let out = scope.spawn(|| read_capped(stdout, MAX_STDOUT, Some(&overflow)));
        let err = scope.spawn(|| read_capped(stderr, MAX_STDERR, None));
        let mut killed = None;
        let status = loop {
            // Overflow first: a child that exits on the broken pipe still
            // sent more than any valid response.
            let reason = if overflow.load(Ordering::Relaxed) {
                Some(Killed::Overflow)
            } else if let Ok(Some(status)) = child.try_wait() {
                break Some(status);
            } else if started.elapsed() >= timeout {
                Some(Killed::Timeout)
            } else if wait(POLL) {
                Some(Killed::Cancelled)
            } else {
                None
            };
            if reason.is_some() {
                killed = reason;
                let _ = child.kill();
                break child.wait().ok();
            }
        };
        // Closing the job kills anything ssh started that still holds the
        // pipes, so the readers below reach end of file.
        drop(job);
        let stdout = out.join().unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        if overflow.load(Ordering::Relaxed) {
            killed = Some(Killed::Overflow);
        }
        Ok(Output {
            stdout,
            stderr,
            log: Vec::new(),
            code: status.and_then(|s| s.code()),
            killed,
        })
    })
}
/// Reads to end of file, keeping at most `cap` bytes. Past the cap, stdout
/// raises `overflow` and stops reading (the caller kills the child); stderr
/// is drained so the child never blocks on it.
fn read_capped(mut pipe: impl Read, cap: usize, overflow: Option<&AtomicBool>) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if kept.len() + n > cap {
            if let Some(flag) = overflow {
                flag.store(true, Ordering::Relaxed);
                break;
            }
            let room = cap - kept.len();
            kept.extend_from_slice(&chunk[..room]);
        } else {
            kept.extend_from_slice(&chunk[..n]);
        }
    }
    kept
}

/// `<System32>\OpenSSH\ssh.exe`: admin-owned, never found through PATH.
pub fn ssh_program(system: &Path) -> PathBuf {
    system.join("OpenSSH").join("ssh.exe")
}
/// The whole ssh argv after the program. ssh writes its own messages to
/// `log` (`-E`), apart from the remote side's stderr. `--` ends ssh's
/// options, so even a host that slipped past validation could not become
/// one.
pub fn ssh_args(config: &Config, log: &Path) -> Vec<OsString> {
    let mut args = ssh_options(config);
    args.splice(5..5, [OsString::from("-E"), log.into()]);
    args
}
/// [`ssh_args`] without the `-E` log, for callers that add their own per
/// run (the settings window's runner).
pub fn ssh_options(config: &Config) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["-T", "-x", "-a", "-e", "none"]
        .into_iter()
        .map(OsString::from)
        .collect();
    for option in SSH_OPTIONS {
        args.extend(["-o", option].map(OsString::from));
    }
    if let Some(identity) = &config.identity {
        args.push("-i".into());
        args.push(identity.into());
        args.extend(["-o", "IdentitiesOnly=yes"].map(OsString::from));
    }
    args.push("--".into());
    for token in [&*config.host, &config.python, "-I", &config.remote, "serve"] {
        args.push(token.into());
    }
    args
}

/// Where ssh logs are made, in order: this account's temp folder (per
/// user, not shared, and made absolute: ssh runs in the OpenSSH folder, so
/// a relative TMP would name another place), then the exe's folder.
pub fn log_dirs() -> Vec<PathBuf> {
    let temp = std::path::absolute(std::env::temp_dir())
        .ok()
        .filter(|p| p.is_absolute());
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    temp.into_iter().chain(exe).collect()
}

static LOGS: AtomicU64 = AtomicU64::new(0);
/// The file one ssh run writes its own messages to (`-E`). ssh passes the
/// remote side's stderr through to its own, so only this file tells a real
/// host key, login or network failure from a server that prints the same
/// words. It is made here (`create_new`, so nothing was at that name
/// before) and its identity (volume and file index) kept; ssh opens it
/// exclusively and appends; it is read back only if the name still holds
/// that very file, and removed on drop. Windows OpenSSH shares its log with
/// nobody, so the helper cannot keep a handle open across the run.
pub struct SshLog {
    path: PathBuf,
    id: (u32, u64),
}
impl SshLog {
    /// A new empty file in the first of `dirs` that takes one (a read-only
    /// exe folder does not), named uniquely without an RNG (process ID,
    /// time, counter); None if none does.
    pub fn create(dirs: &[PathBuf]) -> Option<Self> {
        dirs.iter().find_map(|dir| {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let n = LOGS.fetch_add(1, Ordering::Relaxed);
            let [prefix, suffix] = SSH_LOG;
            let path = dir.join(format!(
                "{prefix}{:x}-{nanos:x}-{n:x}{suffix}",
                std::process::id()
            ));
            // Refused if anything has the name already, a link included.
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .ok()?;
            let id = sys::file_info(&file).ok()?.id;
            Some(Self { path, id })
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// What ssh wrote, at most [`MAX_STDERR`] bytes; None when the name no
    /// longer holds the file [`SshLog::create`] made, alone (removed,
    /// replaced, a link, a directory, or a file with another name too), so
    /// the caller can say the log was lost instead of reading nothing.
    pub fn read(&self) -> Option<Vec<u8>> {
        let file = sys::open_no_follow(&self.path).ok()?;
        // FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
        let info = sys::file_info(&file).ok()?;
        if info.attributes & 0x410 != 0 || info.links != 1 || info.id != self.id {
            return None;
        }
        let mut kept = Vec::new();
        (&file)
            .take(MAX_STDERR as u64)
            .read_to_end(&mut kept)
            .ok()?;
        Some(kept)
    }
}
impl Drop for SshLog {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
/// What stands for ssh's log when [`SshLog::read`] found it lost: it is
/// the `ssh=` detail goyo-sync.log and the CLI show, so a failure that can
/// no longer be told from a server error (a host-key or login failure
/// among them) says why. It holds none of the words [`classify`] and
/// [`key_ignored`] look for.
pub const LOG_LOST: &str = "ssh's own log was removed or replaced during the call";
/// Removes the ssh logs that helpers killed mid-call left in `dir`, judged
/// from the listing alone: plain files with the log name, at least
/// [`STALE_LOG`] old, or [`STALE_EMPTY_LOG`] old and empty, so a call
/// still running elsewhere keeps its own. Returns how many.
pub fn sweep_logs(dir: &Path, now: SystemTime) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let [prefix, suffix] = SSH_LOG;
    let mut removed = 0;
    for e in entries.flatten() {
        let name = e.file_name();
        let own = name
            .to_str()
            .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix));
        let stale = e.metadata().is_ok_and(|m| {
            let wait = if m.len() == 0 {
                STALE_EMPTY_LOG
            } else {
                STALE_LOG
            };
            m.is_file()
                && m.modified()
                    .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age >= wait))
        });
        if own && stale && fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The real transport: one ssh.exe per request.
pub struct SshTransport {
    program: Option<PathBuf>,
    config: Config,
    /// Where each call's ssh log is made ([`log_dirs`]): this account's
    /// temp folder, else the exe's folder.
    logs: Vec<PathBuf>,
    timeout: Duration,
    wait: Wait,
}
impl SshTransport {
    pub fn new(config: &Config, wait: Wait) -> Self {
        let logs = log_dirs();
        for dir in &logs {
            sweep_logs(dir, SystemTime::now());
        }
        Self {
            program: sys::system_dir().map(|d| ssh_program(&d)),
            config: config.clone(),
            logs,
            timeout: Duration::from_secs(config.timeout),
            wait,
        }
    }
    /// The ssh.exe path, if Windows reported its system folder.
    pub fn program(&self) -> Option<&Path> {
        self.program.as_deref()
    }
}
impl Transport for SshTransport {
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        let Some(program) = self.program.as_ref().filter(|p| p.is_file()) else {
            return Err(Failure::Missing);
        };
        let Some(log) = SshLog::create(&self.logs) else {
            return Err(Failure::Start);
        };
        let mut command = Command::new(program);
        // The current folder is the admin-owned OpenSSH folder, not the
        // helper's, so nothing is looked up beside a user-writable file.
        command
            .args(ssh_args(&self.config, log.path()))
            .current_dir(program.parent().unwrap_or(program));
        let wait = &self.wait;
        let mut out = run_bounded(command, request, self.timeout, &mut |d| {
            beat();
            wait(d)
        })?;
        // ssh has exited and its job is closed: nothing writes the file now.
        out.log = log.read().unwrap_or_else(|| LOG_LOST.into());
        Ok(out)
    }
    fn dedicated_key(&self) -> Option<PathBuf> {
        self.config.identity.clone()
    }
}
