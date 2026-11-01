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
    /// The dedicated key the exchanges name (`-i`, IdentitiesOnly), if
    /// any: then an exchange in which ssh ignored that key is refused (see
    /// [`key_ignored`]).
    fn dedicated_key(&self) -> Option<PathBuf> {
        None
    }
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

/// The detail of an exchange refused because ssh ignored the dedicated key
/// (spec §2.29 (sync)): goyo-sync.log and the settings window name it.
pub const KEY_IGNORED: &str = "the dedicated SSH key was ignored: bad permissions";
/// Whether ssh's own log says it ignored a private key file because others
/// may read it (Windows OpenSSH: "UNPROTECTED PRIVATE KEY FILE", "Load
/// key ...: bad permissions"). ssh then logs in with any other key it
/// finds, which the server's forced command for the dedicated key does
/// not bind, so goyo-sync does not use such an exchange. ssh says this
/// before it connects, so no server can write it. Only a line that names
/// `identity` counts: ssh also loads the IdentityFile lines of
/// ~/.ssh/config for the host, and another key's loose permissions leave
/// the dedicated key in use. A line whose file name cannot be read counts
/// (the safe side).
pub fn key_ignored(log: &[u8], identity: &Path) -> bool {
    let text = String::from_utf8_lossy(log);
    // Case and either slash, and a doubled backslash as ssh may print it.
    let plain = |s: &str| {
        let mut out = s.to_lowercase().replace('/', "\\");
        while out.contains("\\\\") {
            out = out.replace("\\\\", "\\");
        }
        out
    };
    let ours = plain(&identity.to_string_lossy());
    let named = |line: &str, open: &str, close: char| {
        let start = line.find(open)? + open.len();
        let len = line[start..].find(close)?;
        Some(plain(&line[start..start + len]))
    };
    own_lines(&text).iter().any(|l| {
        let file = if l.contains("bad permissions") {
            named(l, "Load key \"", '"')
        } else if l.contains("are too open") {
            named(l, "Permissions for '", '\'')
        } else {
            return false;
        };
        file.is_none_or(|f| f == ours)
    })
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
