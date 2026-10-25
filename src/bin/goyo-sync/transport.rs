//! Moving one request frame through a child process (spec §9.7, §9.8). The
//! helper itself has no socket code: it runs `<System32>\OpenSSH\ssh.exe`
//! with a fixed argv, writes the frame to its stdin, closes it, and reads a
//! bounded stdout. All variable data travels inside the frame; the remote
//! command line holds only validated config tokens and the word `serve`.
//! ssh's own messages come back in a file of each call (`-E`), apart from
//! the remote side's stderr.
use crate::{config::Config, sys};
use goyo_vault::{syncfile::SyncState, syncwire::MAX_RESPONSE};
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

/// Banner, response header and the largest vault file.
pub const MAX_STDOUT: usize = MAX_RESPONSE;
pub const MAX_STDERR: usize = 4 * 1024;
const POLL: Duration = Duration::from_millis(50);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Each call's ssh log beside the exe (else in %TEMP%):
/// `goyo-sync.ssh-<pid>-<nanos>-<n>.log` (hex), removed when the call ends.
pub const SSH_LOG: [&str; 2] = ["goyo-sync.ssh-", ".log"];
/// One left by a helper killed mid-call is removed at a later start once it
/// is this old: no call outlives the 600 s timeout.
pub const STALE_LOG: Duration = Duration::from_secs(3600);
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

/// Why the child was killed before it exited on its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Killed {
    Timeout,
    /// More stdout than any valid response.
    Overflow,
    /// The helper is stopping.
    Cancelled,
}
pub struct Output {
    pub stdout: Vec<u8>,
    /// At most [`MAX_STDERR`] bytes; the rest is read and dropped. ssh
    /// passes the remote side's stderr through here, so it never decides a
    /// state.
    pub stderr: Vec<u8>,
    /// ssh.exe's own messages from its `-E` file, at most [`MAX_STDERR`]
    /// bytes; empty for any other child.
    pub log: Vec<u8>,
    pub code: Option<i32>,
    pub killed: Option<Killed>,
}
/// The child could not be run at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Failure {
    /// The program does not exist (for ssh: state `nossh`).
    Missing,
    /// Spawning or confining it failed.
    Start,
}
/// One request on stdin, one raw response back. Tests swap in a script
/// (MockTransport) or the real server script run locally.
pub trait Transport {
    /// `beat` is called every 50 ms or so while the exchange runs, which can
    /// take minutes for a slow upload, so the caller can show it is alive.
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure>;
}
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

static LOGS: AtomicU64 = AtomicU64::new(0);
/// The file one ssh run writes its own messages to (`-E`). ssh passes the
/// remote side's stderr through to its own, so only this file tells a real
/// host key, login or network failure from a server that prints the same
/// words. It is made here, so nothing was at that name before; ssh appends
/// to it; it is read without following links and removed on drop.
pub struct SshLog(PathBuf);
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
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .ok()?;
            Some(Self(path))
        })
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    /// What ssh wrote, at most [`MAX_STDERR`] bytes. A link, a directory or
    /// a file with other names put there meanwhile is not read.
    pub fn read(&self) -> Vec<u8> {
        let Ok(file) = sys::open_no_follow(&self.0) else {
            return Vec::new();
        };
        // FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
        if !sys::file_info(&file).is_ok_and(|i| i.attributes & 0x410 == 0 && i.links == 1) {
            return Vec::new();
        }
        let mut kept = Vec::new();
        let _ = (&file).take(MAX_STDERR as u64).read_to_end(&mut kept);
        kept
    }
}
impl Drop for SshLog {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
/// Removes the ssh logs that helpers killed mid-call left in `dir`, judged
/// from the listing alone: plain files with the log name, at least
/// [`STALE_LOG`] old, so a call still running elsewhere keeps its own.
/// Returns how many.
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
            m.is_file()
                && m.modified()
                    .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age >= STALE_LOG))
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
    /// Where each call's ssh log is made: the exe's folder, beside
    /// goyo-sync.log, if Windows said where the exe is, else or if that
    /// folder takes no file, this account's temp folder.
    logs: Vec<PathBuf>,
    timeout: Duration,
    wait: Wait,
}
impl SshTransport {
    pub fn new(config: &Config, wait: Wait) -> Self {
        let logs: Vec<PathBuf> = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .into_iter()
            .chain([std::env::temp_dir()])
            .collect();
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
        out.log = log.read();
        Ok(out)
    }
}

/// The state for an exchange without a valid response frame (spec §9.8).
/// A valid frame always wins, so this is only asked when there is none.
/// The words are looked for in ssh's own log only: its stderr also carries
/// whatever the remote side prints, and a server must not be able to raise
/// the host key or login alarm by printing them.
pub fn classify(out: &Output) -> SyncState {
    if out.killed == Some(Killed::Overflow) {
        return SyncState::Server;
    }
    let text = String::from_utf8_lossy(&out.log);
    let own = own_lines(&text);
    let has = |words: &[&str]| own.iter().any(|l| words.iter().any(|w| l.contains(w)));
    if has(&[
        "Host key verification failed",
        "REMOTE HOST IDENTIFICATION HAS CHANGED",
    ]) {
        SyncState::HostKey
    } else if has(&["Permission denied"]) {
        SyncState::Auth
    } else if has(&[
        "Could not resolve",
        "timed out",
        "refused",
        "unreachable",
        "No route",
    ]) {
        SyncState::Offline
    } else if out.killed == Some(Killed::Timeout) {
        // ssh's own timeouts (ConnectTimeout, ServerAlive) did not fire, so
        // the link is alive but too slow for the configured timeout.
        SyncState::Offline
    } else {
        SyncState::Server
    }
}
/// The lines of ssh's log that are its own words. Three of its messages
/// quote what the other end sent, line breaks included: the version line
/// and a disconnect's reason, which anyone answering the connection can
/// send before any host key check, and the methods a refused login lists.
/// So the log is read up to the first two, and up to and with the third.
fn own_lines(log: &str) -> Vec<&str> {
    let mut own = Vec::new();
    for line in log.split(['\r', '\n']) {
        if line.contains("Bad remote protocol version identification")
            || line.contains("Received disconnect from")
        {
            break;
        }
        own.push(line);
        if line.contains("Permission denied (") {
            break;
        }
    }
    own
}
/// The first line of ssh's log or of stderr, for goyo-sync.log: printable
/// ASCII, at most 200 chars.
pub fn first_line(text: &[u8]) -> String {
    let line = text
        .split(|b| *b == b'\n' || *b == b'\r')
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    line.iter()
        .filter(|b| (0x20..0x7f).contains(*b))
        .take(200)
        .map(|b| *b as char)
        .collect()
}
