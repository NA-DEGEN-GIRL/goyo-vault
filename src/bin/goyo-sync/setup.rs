//! The settings window's work, apart from the window itself (gui.rs): the
//! fields and the goyo-sync.conf they become, the fixed ssh command lines of
//! the connection check, the first-connection trust step and the server
//! install, the state of each vault for the list, and the jobs the window's
//! worker thread runs. Nothing here words a message: gui.rs picks the text
//! for every result. Tests run each job with a scripted [`Runner`]; none of
//! them runs ssh, touches the registry or starts a process.
use crate::{
    Fetched,
    config::{
        self, Config, ConfigError, DEFAULT_INTERVAL, DEFAULT_PYTHON, DEFAULT_REMOTE,
        DEFAULT_TIMEOUT, MAX_CONFIG, MAX_VAULTS, Problem,
    },
    engine::{self, CallError, Engine, Log, Outcome, call},
    fetch_file,
    transport::{
        Failure, Killed, Output, SshLog, Transport, classify, first_line, run_bounded, ssh_options,
    },
};
use goyo_vault::{
    syncfile::{self, SyncState},
    syncwire::{ListEntry, Request, Status},
};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The server script this exe installs, byte for byte the shipped
/// `server/goyo-sync-server.py`.
pub const SERVER_SCRIPT: &[u8] = include_bytes!("../../../server/goyo-sync-server.py");
/// `ssh -G` and `ssh-keygen -F` only read local files.
const LOCAL_TIMEOUT: Duration = Duration::from_secs(15);
/// The vault app calls the helper off after this long without a heartbeat.
const HEARTBEAT_STALE: u64 = 180;
/// A vault line used only to check the server settings on their own (the
/// connection check, the install, the server list); never written.
const PLACEHOLDER: &str = r"C:\goyo-sync\placeholder.goyo";

/// What the window's inputs hold, as typed (trimmed). Every value is
/// checked by [`render`] exactly as goyo-sync.conf is checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    pub host: String,
    pub remote: String,
    pub python: String,
    /// Empty: no dedicated key.
    pub identity: String,
    pub interval: String,
    pub timeout: String,
    pub vaults: Vec<PathBuf>,
}
impl Default for Fields {
    fn default() -> Self {
        Self {
            host: String::new(),
            remote: DEFAULT_REMOTE.into(),
            python: DEFAULT_PYTHON.into(),
            identity: String::new(),
            interval: DEFAULT_INTERVAL.to_string(),
            timeout: DEFAULT_TIMEOUT.to_string(),
            vaults: Vec::new(),
        }
    }
}
impl Fields {
    pub fn from_config(c: &Config) -> Self {
        Self {
            host: c.host.clone(),
            remote: c.remote.clone(),
            python: c.python.clone(),
            identity: c
                .identity
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            interval: c.interval.to_string(),
            timeout: c.timeout.to_string(),
            vaults: c.vaults.clone(),
        }
    }
    /// What a file that does not parse says, so the window can show it to
    /// be fixed: `name = value` pairs as written, nothing checked or used.
    pub fn from_text(text: &str) -> Self {
        let mut f = Self::default();
        for raw in text.strip_prefix('\u{feff}').unwrap_or(text).split('\n') {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_owned();
            match name.trim() {
                "host" => f.host = value,
                "remote" => f.remote = value,
                "python" => f.python = value,
                "identity" => f.identity = value,
                "interval" => f.interval = value,
                "timeout" => f.timeout = value,
                "vault" if !value.is_empty() && f.vaults.len() < MAX_VAULTS => {
                    f.vaults.push(PathBuf::from(value));
                }
                _ => {}
            }
        }
        f
    }
}

/// The input a problem belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Host,
    Remote,
    Python,
    Identity,
    Interval,
    Timeout,
    /// One vault line, by its place in the list.
    Vault(usize),
    /// The list as a whole (none, too many, too long).
    Vaults,
}
impl Field {
    fn problem(self) -> Problem {
        match self {
            Self::Host => Problem::Host,
            Self::Remote => Problem::Remote,
            Self::Python => Problem::Python,
            Self::Identity => Problem::Identity,
            Self::Interval => Problem::Interval,
            Self::Timeout => Problem::Timeout,
            Self::Vault(_) => Problem::Vault,
            Self::Vaults => Problem::NoVault,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// As goyo-sync.conf would report it.
    Config(Problem),
    /// A `#`, which starts a comment in goyo-sync.conf.
    Hash,
    /// The file would be larger than 8 KiB.
    TooLarge,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bad {
    pub field: Field,
    pub why: Why,
}

/// The goyo-sync.conf text for `f` and the settings it parses to. The text
/// goes through `config::parse`, the helper's own check, and must give back
/// exactly what was typed.
pub fn render(f: &Fields) -> Result<(String, Config), Bad> {
    build(f, true)
}
/// The server settings alone (host, script, Python, key, times), checked the
/// same way, for the connection check, the install and the server list.
pub fn server_config(f: &Fields) -> Result<Config, Bad> {
    let (_, mut config) = build(f, false)?;
    config.vaults.clear();
    Ok(config)
}
fn build(f: &Fields, vaults: bool) -> Result<(String, Config), Bad> {
    let bad = |field: Field, why| Bad { field, why };
    if f.host.is_empty() {
        return Err(bad(Field::Host, Why::Config(Problem::NoHost)));
    }
    for (field, value) in [
        (Field::Host, &f.host),
        (Field::Remote, &f.remote),
        (Field::Python, &f.python),
        (Field::Identity, &f.identity),
        (Field::Interval, &f.interval),
        (Field::Timeout, &f.timeout),
    ] {
        plain(field, value)?;
    }
    let paths: Vec<String> = if vaults {
        if f.vaults.is_empty() {
            return Err(bad(Field::Vaults, Why::Config(Problem::NoVault)));
        }
        if f.vaults.len() > MAX_VAULTS {
            return Err(bad(Field::Vaults, Why::Config(Problem::TooManyVaults)));
        }
        let mut paths = Vec::new();
        for (i, path) in f.vaults.iter().enumerate() {
            let text = path
                .to_str()
                .ok_or(bad(Field::Vault(i), Why::Config(Problem::Vault)))?;
            plain(Field::Vault(i), text)?;
            paths.push(text.to_owned());
        }
        paths
    } else {
        vec![PLACEHOLDER.into()]
    };
    let (text, lines) = config_text(f, &paths);
    if text.len() > MAX_CONFIG {
        return Err(bad(Field::Vaults, Why::TooLarge));
    }
    let config = config::parse(&text).map_err(|e| from_error(&e, &lines))?;
    same(f, &config, vaults)?;
    Ok((text, config))
}
/// A value goyo-sync.conf can hold as it is: no `#`, no control character
/// (a line break would start another setting), no space at either end.
fn plain(field: Field, value: &str) -> Result<(), Bad> {
    if value.contains('#') {
        Err(Bad {
            field,
            why: Why::Hash,
        })
    } else if value.chars().any(char::is_control) || value != value.trim() {
        Err(Bad {
            field,
            why: Why::Config(field.problem()),
        })
    } else {
        Ok(())
    }
}
/// The file, with short comments, and the input behind each line.
fn config_text(f: &Fields, vaults: &[String]) -> (String, Vec<Option<Field>>) {
    let mut text = String::new();
    let mut lines = Vec::new();
    let mut put = |line: &str, field: Option<Field>| {
        text.push_str(line);
        text.push('\n');
        lines.push(field);
    };
    for comment in [
        "# goyo-sync.conf, written by the goyo-sync settings window. It names",
        "# your server: keep it on this PC and never share it. Guide: docs/SYNC.md",
        "# One \"name = value\" per line; \"#\" starts a comment.",
        "",
        "# ssh destination: an alias from %USERPROFILE%\\.ssh\\config or [user@]host",
    ] {
        put(comment, None);
    }
    put(&format!("host = {}", f.host), Some(Field::Host));
    put(
        "# The server script (from your home folder there) and its Python",
        None,
    );
    put(&format!("remote = {}", f.remote), Some(Field::Remote));
    put(&format!("python = {}", f.python), Some(Field::Python));
    put("# A dedicated ssh key; empty: your usual ssh setup", None);
    put(&format!("identity = {}", f.identity), Some(Field::Identity));
    put(
        "# Seconds between server checks (30-3600) and per ssh call (30-600)",
        None,
    );
    put(&format!("interval = {}", f.interval), Some(Field::Interval));
    put(&format!("timeout = {}", f.timeout), Some(Field::Timeout));
    put(
        "# Vault files to sync, 1 to 8; never a key file (*.goyokey)",
        None,
    );
    for (i, vault) in vaults.iter().enumerate() {
        put(&format!("vault = {vault}"), Some(Field::Vault(i)));
    }
    (text, lines)
}
fn from_error(e: &ConfigError, lines: &[Option<Field>]) -> Bad {
    let field = match e.problem {
        Problem::NoHost => Field::Host,
        Problem::NoVault | Problem::TooManyVaults => Field::Vaults,
        _ => lines
            .get(e.line.wrapping_sub(1))
            .copied()
            .flatten()
            .unwrap_or(Field::Vaults),
    };
    Bad {
        field,
        why: Why::Config(e.problem),
    }
}
/// What was parsed is what was typed.
fn same(f: &Fields, c: &Config, vaults: bool) -> Result<(), Bad> {
    let identity = (!f.identity.is_empty()).then(|| PathBuf::from(&f.identity));
    let checks = [
        (Field::Host, c.host == f.host),
        (Field::Remote, c.remote == f.remote),
        (Field::Python, c.python == f.python),
        (Field::Identity, c.identity == identity),
        (Field::Interval, f.interval.parse() == Ok(c.interval)),
        (Field::Timeout, f.timeout.parse() == Ok(c.timeout)),
    ];
    for (field, ok) in checks {
        if !ok {
            return Err(Bad {
                field,
                why: Why::Config(field.problem()),
            });
        }
    }
    if vaults {
        for (i, (parsed, typed)) in c.vaults.iter().zip(&f.vaults).enumerate() {
            if parsed != typed {
                return Err(Bad {
                    field: Field::Vault(i),
                    why: Why::Config(Problem::Vault),
                });
            }
        }
        if c.vaults.len() != f.vaults.len() {
            return Err(Bad {
                field: Field::Vaults,
                why: Why::Config(Problem::Vault),
            });
        }
    }
    Ok(())
}
/// Whether `path` names a key file as Windows resolves the name (trailing
/// dots and spaces dropped, any case).
pub fn key_file(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    name.trim_end_matches(['.', ' '])
        .to_lowercase()
        .ends_with(".goyokey")
}
/// Why a vault picked in the window cannot go in the list, checked as a
/// goyo-sync.conf vault line is.
pub fn vault_problem(path: &Path, list: &[PathBuf]) -> Option<Why> {
    if key_file(path) {
        return Some(Why::Config(Problem::KeyFile));
    }
    // goyo-sync.conf is UTF-8: a name it cannot hold cannot be synced.
    let Some(text) = path.to_str() else {
        return Some(Why::Config(Problem::Vault));
    };
    if text.contains('#') {
        return Some(Why::Hash);
    }
    let lower = text.to_lowercase();
    if list
        .iter()
        .any(|v| v.to_string_lossy().to_lowercase() == lower)
    {
        return Some(Why::Config(Problem::DuplicateVault));
    }
    if list.len() >= MAX_VAULTS {
        return Some(Why::Config(Problem::TooManyVaults));
    }
    match config::parse(&format!("host = my-server\nvault = {text}\n")) {
        Ok(c) if c.vaults == [path] => None,
        Ok(_) => Some(Why::Config(Problem::Vault)),
        Err(e) => Some(Why::Config(e.problem)),
    }
}

/// A server setting the install refuses to put into a remote command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsafe {
    Remote,
    Python,
}
/// The one remote command of the install. It is built only from the two
/// settings, each limited to goyo-sync.conf's character sets: in a POSIX
/// shell every one of those characters stands for itself, except a leading
/// `~`, which expands to the home folder exactly as in the `serve` command
/// the helper runs, so the script lands where the helper looks for it. The
/// script itself comes on stdin, and only `PASS` from its selftest counts.
/// The selftest runs on the new copy before it replaces the old one: a
/// connection that drops mid-transfer ends `cat` as if the script were
/// complete, and a cut-off copy must never become the installed script.
pub fn install_command(remote: &str, python: &str) -> Result<String, Unsafe> {
    let name = remote.rsplit('/').next().unwrap_or(remote);
    if !config::word(remote, 256, b"._/~+-")
        || name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('~')
    {
        return Err(Unsafe::Remote);
    }
    if !config::word(python, 64, b"._/+-") {
        return Err(Unsafe::Python);
    }
    let dir = match remote.rfind('/') {
        Some(0) => "/",
        Some(i) => &remote[..i],
        None => ".",
    };
    Ok(format!(
        "umask 077 && mkdir -p {dir} && cat > {remote}.new && chmod 700 {remote}.new \
         && {python} -I {remote}.new selftest && mv -f {remote}.new {remote}"
    ))
}
/// The install's ssh argv: the helper's fixed options and host, then the
/// install command instead of `serve`. It logs in as the user normally does
/// (ssh config, default key, ssh-agent) and never with the dedicated key,
/// which may be bound to a forced command that only runs `serve`.
pub fn install_args(config: &Config) -> Result<Vec<OsString>, Unsafe> {
    let command = install_command(&config.remote, &config.python)?;
    let mut plain = config.clone();
    plain.identity = None;
    let mut args = ssh_options(&plain);
    let end = args
        .iter()
        .position(|a| a == "--")
        .map_or(args.len(), |i| i + 2);
    args.truncate(end);
    args.push(command.into());
    Ok(args)
}
/// The helper's argv with one change, for the single call after the user
/// agreed to trust a first-seen host key: ssh then stores a key it has never
/// seen, while a changed key is still refused.
pub fn trust_args(config: &Config) -> Vec<OsString> {
    ssh_options(config)
        .into_iter()
        .map(|a| {
            if a == "StrictHostKeyChecking=yes" {
                "StrictHostKeyChecking=accept-new".into()
            } else {
                a
            }
        })
        .collect()
}
/// `ssh -G`: the settings ssh would use for `host`, without connecting.
pub fn resolve_args(host: &str) -> Vec<OsString> {
    ["-G", "--", host].map(OsString::from).to_vec()
}
/// `ssh-keygen -l -F`: the fingerprints known_hosts holds for `name`.
pub fn fingerprint_args(name: &str) -> Vec<OsString> {
    ["-l", "-F", name].map(OsString::from).to_vec()
}

/// Makes a runner for each job (the window's worker owns it).
pub type MakeRunner = Arc<dyn Fn() -> Box<dyn Runner> + Send + Sync>;
/// What runs the programs of System32\OpenSSH; tests script one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Ssh,
    Keygen,
}
pub trait Runner: Send {
    /// One run with `input` on stdin, bounded like every ssh call.
    fn run(
        &mut self,
        tool: Tool,
        args: &[OsString],
        input: &[u8],
        timeout: Duration,
        beat: &mut dyn FnMut(),
    ) -> Result<Output, Failure>;
}
/// The real runner: `<System32>\OpenSSH\ssh.exe` or `ssh-keygen.exe`, never
/// found through PATH, started in that folder through [`run_bounded`]
/// (kill-on-close job, capped output, timeout). `cancel` kills it when the
/// window closes.
pub struct SshRunner {
    openssh: Option<PathBuf>,
    cancel: Arc<AtomicBool>,
}
impl SshRunner {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            openssh: crate::sys::system_dir().map(|d| d.join("OpenSSH")),
            cancel,
        }
    }
}
impl Runner for SshRunner {
    fn run(
        &mut self,
        tool: Tool,
        args: &[OsString],
        input: &[u8],
        timeout: Duration,
        beat: &mut dyn FnMut(),
    ) -> Result<Output, Failure> {
        let Some(dir) = &self.openssh else {
            return Err(Failure::Missing);
        };
        let program = dir.join(match tool {
            Tool::Ssh => "ssh.exe",
            Tool::Keygen => "ssh-keygen.exe",
        });
        if !program.is_file() {
            return Err(Failure::Missing);
        }
        // ssh writes its own messages to a fresh -E file, apart from the
        // remote side's stderr, so a server cannot fake a host key or login
        // failure (see transport::SshLog).
        let log = match tool {
            Tool::Ssh => {
                let dirs: Vec<PathBuf> = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(Path::to_path_buf))
                    .into_iter()
                    .chain([std::env::temp_dir()])
                    .collect();
                Some(SshLog::create(&dirs).ok_or(Failure::Start)?)
            }
            Tool::Keygen => None,
        };
        let mut command = Command::new(&program);
        if let Some(log) = &log {
            command.arg("-E").arg(log.path());
        }
        command.args(args).current_dir(dir);
        let cancel = &self.cancel;
        let mut out = run_bounded(command, input, timeout, &mut |d| {
            beat();
            std::thread::sleep(d);
            cancel.load(Ordering::Relaxed)
        })?;
        // The child has exited and its job is closed: nothing writes it now.
        if let Some(log) = &log {
            out.log = log.read();
        }
        Ok(out)
    }
}
/// The helper's [`Transport`] over a [`Runner`], keeping the last stderr so
/// a failure can be told apart in more detail than the status file needs.
pub struct Wire<'a> {
    runner: &'a mut dyn Runner,
    args: Vec<OsString>,
    timeout: Duration,
    /// The remote side's stderr: a missing script or Python shows here.
    pub stderr: Vec<u8>,
    /// ssh's own messages (`-E`): only these tell host key trouble.
    pub log: Vec<u8>,
}
impl<'a> Wire<'a> {
    pub fn new(runner: &'a mut dyn Runner, args: Vec<OsString>, timeout: Duration) -> Self {
        Self {
            runner,
            args,
            timeout,
            stderr: Vec::new(),
            log: Vec::new(),
        }
    }
}
impl Transport for Wire<'_> {
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        let result = self
            .runner
            .run(Tool::Ssh, &self.args, request, self.timeout, beat);
        (self.stderr, self.log) = result.as_ref().map_or_else(
            |_| (Vec::new(), Vec::new()),
            |o| (o.stderr.clone(), o.log.clone()),
        );
        result
    }
}

/// A failed exchange in the words the window needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trouble {
    pub state: SyncState,
    pub cause: Cause,
    /// The first stderr line, printable ASCII (may name the server).
    pub detail: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    Plain,
    /// Python ran but could not open the server script.
    ScriptMissing,
    /// The server's shell did not find the Python command.
    PythonMissing,
}
impl Trouble {
    pub fn of(state: SyncState) -> Self {
        Self {
            state,
            cause: Cause::Plain,
            detail: String::new(),
        }
    }
}
/// The state as the helper reports it, plus what stderr says about a
/// missing script or Python (both are `server` to the helper).
pub fn trouble(state: SyncState, stderr: &[u8], detail: String) -> Trouble {
    let text = String::from_utf8_lossy(stderr);
    let (state, cause) = if text.contains("can't open file") {
        (SyncState::Server, Cause::ScriptMissing)
    } else if state == SyncState::Server
        && (text.contains("command not found")
            || text.contains(": not found")
            || text.contains("No such file or directory"))
    {
        (SyncState::Server, Cause::PythonMissing)
    } else {
        (state, Cause::Plain)
    };
    Trouble {
        state,
        cause,
        detail,
    }
}

/// How ssh refused the server's host key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProblem {
    /// "No ... host key is known for ...": never seen before.
    Unknown,
    /// Changed, revoked, or a message this program does not know: never
    /// accepted from the window.
    Changed,
}
pub fn key_problem(stderr: &str) -> KeyProblem {
    let changed = [
        "IDENTIFICATION HAS CHANGED",
        "has changed",
        "DNS SPOOFING",
        "Offending",
        "REVOKED",
    ];
    if changed.iter().any(|w| stderr.contains(w)) {
        KeyProblem::Changed
    } else if stderr.contains("host key is known for") && stderr.contains("strict checking") {
        KeyProblem::Unknown
    } else {
        KeyProblem::Changed
    }
}
/// What known_hosts holds for the server's name, from `ssh-keygen -l -F`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Known {
    Nothing,
    /// The fingerprint lines.
    Keys(Vec<String>),
    /// It could not be asked (no ssh-keygen, a name it could not resolve).
    Unclear,
}
/// The next step after a host key refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyStep {
    /// A first connection: ask the user whether to trust the key once.
    Ask { name: String },
    /// The key changed: explain and stop.
    Changed,
    /// ssh saw a key type it does not know, yet known_hosts has a key for
    /// this name: the server no longer offers the known key. Stop.
    OtherKey { name: String },
    /// known_hosts could not be read for the name, so nothing is trusted.
    Unclear,
}
pub fn key_step(stderr: &str, name: Option<&str>, known: &Known) -> KeyStep {
    match (key_problem(stderr), name, known) {
        (KeyProblem::Changed, ..) => KeyStep::Changed,
        (KeyProblem::Unknown, Some(name), Known::Nothing) => KeyStep::Ask { name: name.into() },
        (KeyProblem::Unknown, Some(name), Known::Keys(_)) => {
            KeyStep::OtherKey { name: name.into() }
        }
        _ => KeyStep::Unclear,
    }
}
/// The name known_hosts files the server under, from `ssh -G` output: the
/// HostKeyAlias, else the host name with a non-default port as
/// `[host]:port`, as ssh writes it.
pub fn parse_resolved(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let value = |key: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.trim().split_once(' ')?;
            (k == key).then(|| v.trim().to_owned())
        })
    };
    let name_ok = |s: &str| {
        (1..=253).contains(&s.len())
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
    };
    if let Some(alias) = value("hostkeyalias").filter(|a| a != "none") {
        return name_ok(&alias).then_some(alias);
    }
    let host = value("hostname").filter(|h| name_ok(h))?;
    let port = match value("port") {
        None => 22,
        Some(p) if p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u32>().ok().filter(|p| (1..=65535).contains(p))?
        }
        Some(_) => return None,
    };
    Some(if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    })
}
/// The fingerprint lines of `ssh-keygen -l -F` output; exit 1 is "none".
pub fn parse_known(out: &Output) -> Known {
    match out.code {
        Some(0) => {
            let lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .take(8)
                .map(|l| {
                    l.chars()
                        .filter(|c| (' '..='~').contains(c))
                        .take(200)
                        .collect()
                })
                .collect();
            if lines.is_empty() {
                Known::Unclear
            } else {
                Known::Keys(lines)
            }
        }
        Some(1) => Known::Nothing,
        // No known_hosts file yet: nothing is known.
        _ if String::from_utf8_lossy(&out.stderr).contains("No such file or directory") => {
            Known::Nothing
        }
        _ => Known::Unclear,
    }
}
fn resolve(runner: &mut dyn Runner, host: &str) -> Option<String> {
    let out = runner
        .run(
            Tool::Ssh,
            &resolve_args(host),
            b"",
            LOCAL_TIMEOUT,
            &mut || {},
        )
        .ok()?;
    (out.code == Some(0) && out.killed.is_none())
        .then(|| parse_resolved(&out.stdout))
        .flatten()
}
fn lookup(runner: &mut dyn Runner, name: &str) -> Known {
    match runner.run(
        Tool::Keygen,
        &fingerprint_args(name),
        b"",
        LOCAL_TIMEOUT,
        &mut || {},
    ) {
        Ok(out) if out.killed.is_none() => parse_known(&out),
        _ => Known::Unclear,
    }
}

/// The connection check's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Checked {
    /// HELLO echoed 512 bytes unchanged and LIST answered.
    Ok {
        vaults: usize,
    },
    HostKey(KeyStep),
    Failed(Trouble),
    Cancelled,
}
/// HELLO, whose 512-byte echo proves the ssh pipe is binary-transparent,
/// then LIST: the same exchanges and options as the helper, nothing written.
pub fn check(runner: &mut dyn Runner, log: &Log, config: &Config) -> Checked {
    if let Err(checked) = hello(runner, log, config, ssh_options(config), "window check") {
        return checked;
    }
    check_list(runner, log, config)
}
fn hello(
    runner: &mut dyn Runner,
    log: &Log,
    config: &Config,
    args: Vec<OsString>,
    label: &str,
) -> Result<(), Checked> {
    let mut wire = Wire::new(runner, args, Duration::from_secs(config.timeout));
    let result = call(&mut wire, &Request::hello(), label, log);
    let stderr = std::mem::take(&mut wire.stderr);
    let said = std::mem::take(&mut wire.log);
    match result {
        Ok(reply) if reply.status == Status::Ok => Ok(()),
        Ok(_) => Err(Checked::Failed(Trouble::of(SyncState::Server))),
        Err(CallError::Cancelled) => Err(Checked::Cancelled),
        Err(CallError::Failed(SyncState::HostKey, _)) => {
            // ssh's own words, never the server's.
            let text = String::from_utf8_lossy(&said).into_owned();
            let step = if key_problem(&text) == KeyProblem::Changed {
                KeyStep::Changed
            } else {
                let name = resolve(runner, &config.host);
                let known = name
                    .as_deref()
                    .map_or(Known::Unclear, |n| lookup(runner, n));
                key_step(&text, name.as_deref(), &known)
            };
            log.line(&format!("{label} host key: {step:?}"));
            Err(Checked::HostKey(step))
        }
        Err(CallError::Failed(state, detail)) => {
            Err(Checked::Failed(trouble(state, &stderr, detail)))
        }
    }
}
/// Every vault on the server (`--list`).
pub fn list(
    runner: &mut dyn Runner,
    log: &Log,
    config: &Config,
) -> Result<Vec<ListEntry>, Checked> {
    let mut wire = Wire::new(
        runner,
        ssh_options(config),
        Duration::from_secs(config.timeout),
    );
    let result = call(&mut wire, &Request::list(), "window list", log);
    match result {
        Ok(reply) if reply.status == Status::Ok => goyo_vault::syncwire::parse_list(reply.blob())
            .ok_or(Checked::Failed(Trouble::of(SyncState::Server))),
        Ok(_) => Err(Checked::Failed(Trouble::of(SyncState::Server))),
        Err(CallError::Cancelled) => Err(Checked::Cancelled),
        Err(CallError::Failed(state, detail)) => {
            Err(Checked::Failed(trouble(state, &wire.stderr, detail)))
        }
    }
}
/// After the user agreed: one HELLO that lets ssh store the first-seen key,
/// the fingerprint now in known_hosts, then the rest of the check with the
/// usual options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trusted {
    pub name: Option<String>,
    pub known: Known,
    pub checked: Checked,
}
pub fn trust(runner: &mut dyn Runner, log: &Log, config: &Config) -> Trusted {
    let first = hello(runner, log, config, trust_args(config), "window trust");
    // ssh stores the key as soon as it accepts it, whatever comes after.
    let name = resolve(runner, &config.host);
    let known = name
        .as_deref()
        .map_or(Known::Unclear, |n| lookup(runner, n));
    let checked = match first {
        Ok(()) => check_list(runner, log, config),
        Err(checked) => checked,
    };
    Trusted {
        name,
        known,
        checked,
    }
}
fn check_list(runner: &mut dyn Runner, log: &Log, config: &Config) -> Checked {
    match list(runner, log, config) {
        Ok(entries) => Checked::Ok {
            vaults: entries.len(),
        },
        Err(checked) => checked,
    }
}

/// The install's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Installed {
    /// The selftest printed exactly `PASS`.
    Pass,
    Refused(Unsafe),
    /// The remote command ran but did not end in a lone `PASS`: `line` is
    /// its last output (or stderr) line; `noisy` if it did pass but the
    /// server's shell printed other text too.
    NotPass {
        line: String,
        cause: Cause,
        noisy: bool,
    },
    /// ssh itself failed (exit 255 or killed).
    Failed(Trouble),
    Cancelled,
}
/// Sends the embedded server script over ssh stdin to the fixed install
/// command; bounded like every ssh call.
pub fn install(runner: &mut dyn Runner, log: &Log, config: &Config) -> Installed {
    let args = match install_args(config) {
        Ok(args) => args,
        Err(which) => return Installed::Refused(which),
    };
    let started = Instant::now();
    let out = runner.run(
        Tool::Ssh,
        &args,
        SERVER_SCRIPT,
        Duration::from_secs(config.timeout),
        &mut || {},
    );
    let result = install_result(out);
    log.line(&format!(
        "window install {result:?} ms={}",
        started.elapsed().as_millis()
    ));
    result
}
pub fn install_result(out: Result<Output, Failure>) -> Installed {
    let out = match out {
        Ok(out) => out,
        Err(Failure::Missing) => return Installed::Failed(Trouble::of(SyncState::NoSsh)),
        Err(Failure::Start) => return Installed::Failed(Trouble::of(SyncState::Server)),
    };
    if out.killed == Some(Killed::Cancelled) {
        return Installed::Cancelled;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines == ["PASS"] && out.code == Some(0) && out.killed.is_none() {
        return Installed::Pass;
    }
    // ssh reports its own failures with exit code 255; any other code is
    // the remote command's.
    if out.killed.is_some() || out.code.is_none_or(|c| c == 255) {
        let state = classify(&out);
        let said = if out.log.is_empty() {
            &out.stderr
        } else {
            &out.log
        };
        return Installed::Failed(trouble(state, &out.stderr, first_line(said)));
    }
    // The selftest passed but the step after it (moving the new copy in
    // place) failed: stderr says why, and the old script is still there.
    if lines.last() == Some(&"PASS") && out.code != Some(0) {
        return Installed::NotPass {
            line: first_line(&out.stderr),
            cause: Cause::Plain,
            noisy: false,
        };
    }
    let cause = trouble(SyncState::Server, &out.stderr, String::new()).cause;
    let line = lines
        .last()
        .map(|l| first_line(l.as_bytes()))
        .unwrap_or_else(|| first_line(&out.stderr));
    Installed::NotPass {
        line,
        cause,
        noisy: lines.last() == Some(&"PASS"),
    }
}

/// `--fetch <id> head <new file>` for the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Got {
    Saved {
        version: u64,
        bytes: usize,
    },
    /// The file appeared; it is never overwritten.
    Exists,
    NotFound,
    Failed(Trouble),
    Write,
    Cancelled,
}
/// Fetches the head into `path`, a new file chosen in a save dialog. The
/// user may have picked an existing file, perhaps a vault in use, so its
/// presence is read from the folder listing, never with a handle on it; the
/// new file is created with CREATE_NEW, which fails on one that exists.
pub fn fetch(
    runner: &mut dyn Runner,
    log: &Log,
    config: &Config,
    id: [u8; 16],
    path: &Path,
) -> Got {
    if present(path) {
        return Got::Exists;
    }
    let mut wire = Wire::new(
        runner,
        ssh_options(config),
        Duration::from_secs(config.timeout),
    );
    match fetch_file(&mut wire, log, id, 0, path) {
        Fetched::Saved { version, bytes } => Got::Saved { version, bytes },
        Fetched::NotFound => Got::NotFound,
        Fetched::Server => Got::Failed(Trouble::of(SyncState::Server)),
        Fetched::Write => Got::Write,
        Fetched::Failed(CallError::Cancelled) => Got::Cancelled,
        Fetched::Failed(CallError::Failed(state, detail)) => {
            Got::Failed(trouble(state, &wire.stderr, detail))
        }
    }
}
/// Whether the folder of `path` lists something by its name (file, folder
/// or link); read from the listing alone, like [`engine::listed`].
pub fn present(path: &Path) -> bool {
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => fs::read_dir(dir).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().eq_ignore_ascii_case(name))
        }),
        _ => false,
    }
}
/// One forced pass over every vault, as `--once`. A folder the background
/// helper is working on is skipped by its helper.lock (`Locked`).
pub fn sync_now(runner: &mut dyn Runner, log: &Log, config: &Config) -> Vec<Outcome> {
    let wire = Wire::new(
        runner,
        ssh_options(config),
        Duration::from_secs(config.timeout),
    );
    let mut engine = Engine::new(
        wire,
        &config.vaults,
        config.interval,
        engine::system_clock(),
        log.clone(),
    );
    (0..engine.vaults()).map(|i| engine.pass(i, true)).collect()
}

/// What the window does outside itself: the background helper and the Run
/// value. Tests use a fake; nothing in a test starts a process or writes
/// the registry.
pub trait System: Send + Sync {
    /// The background helper's instance mutex exists (opened, never made).
    fn running(&self) -> bool;
    /// Sets the stop event; false if no helper made one.
    fn stop(&self) -> bool;
    /// Starts `"<exe>" --background`, detached.
    fn start(&self) -> Result<(), u32>;
    /// The Run value names this exe.
    fn autostart(&self) -> bool;
    fn set_autostart(&self, on: bool) -> Result<(), i32>;
}
/// The real one.
pub struct Windows {
    pub exe: PathBuf,
}
impl System for Windows {
    fn running(&self) -> bool {
        crate::sys::mutex_exists(&crate::object_names().0)
    }
    fn stop(&self) -> bool {
        crate::sys::Event::signal(&crate::object_names().1)
    }
    fn start(&self) -> Result<(), u32> {
        crate::sys::start_detached(&self.exe, "--background")
    }
    fn autostart(&self) -> bool {
        crate::sys::run_value(crate::RUN_VALUE).is_some_and(|v| names_exe(&v, &self.exe))
    }
    fn set_autostart(&self, on: bool) -> Result<(), i32> {
        if on {
            crate::sys::set_run_value(crate::RUN_VALUE, &crate::autostart_command(&self.exe))
        } else {
            crate::sys::delete_run_value(crate::RUN_VALUE)
        }
    }
}
/// Whether a Run command starts `exe` (with or without `--background`).
pub fn names_exe(command: &std::ffi::OsStr, exe: &Path) -> bool {
    let command = command.to_string_lossy().to_lowercase();
    let quoted = format!("\"{}\"", exe.to_string_lossy().to_lowercase());
    command == quoted || command.starts_with(&(quoted + " "))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restarted {
    Started,
    /// The old helper did not stop in time; nothing was started.
    StillRunning,
    StartFailed(u32),
    /// Started, but its instance mutex never showed (see the log).
    NotStarted,
}
/// Stops a running helper (it ends its pass, killing an ssh call in flight),
/// waits until its mutex is gone, so the new one does not take itself for a
/// second instance and exit, then starts the new one.
/// With a 100 ms `poll` it waits up to 15 s for the stop and 5 s for the
/// start.
pub fn restart(system: &dyn System, poll: Duration) -> Restarted {
    let wait = |running: bool, polls: u32| {
        for _ in 0..polls {
            if system.running() == running {
                return true;
            }
            std::thread::sleep(poll);
        }
        system.running() == running
    };
    if system.running() {
        system.stop();
        if !wait(false, 150) {
            return Restarted::StillRunning;
        }
    }
    if let Err(code) = system.start() {
        return Restarted::StartFailed(code);
    }
    if wait(true, 50) {
        Restarted::Started
    } else {
        Restarted::NotStarted
    }
}

/// One vault's state for the list, from its folder listing and the
/// helper's `status` and `helper.state` files; the vault file itself is
/// never opened or stat-ed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Live {
    /// Its folder does not list the vault file.
    NoVault,
    /// No sync folder yet: the helper makes it on its first pass.
    NotSetUp,
    /// The sync folder is a link or not a folder.
    Unusable,
    /// No helper has written the status file for 3 minutes.
    HelperOff {
        server: u64,
    },
    State {
        state: SyncState,
        server: u64,
    },
}
pub fn live(vault: &Path, now: u64) -> Live {
    // A relative line from a damaged goyo-sync.conf names nothing yet.
    let Some(dir) = syncfile::sync_dir(vault).filter(|_| vault.is_absolute()) else {
        return Live::NoVault;
    };
    if !syncfile::usable_dir(&dir) {
        return if fs::symlink_metadata(&dir).is_ok() {
            Live::Unusable
        } else if engine::listed(vault) {
            Live::NotSetUp
        } else {
            Live::NoVault
        };
    }
    if !engine::listed(vault) {
        return Live::NoVault;
    }
    let server = syncfile::read_helper_state(&dir).map_or(0, |s| s.server);
    match syncfile::read_status(&dir) {
        Ok(s) if fresh(s.heartbeat, now) => match s.state {
            Some(state) => Live::State { state, server },
            None => Live::HelperOff { server },
        },
        _ => Live::HelperOff { server },
    }
}
/// As the vault app decides "helper off": a heartbeat older than 3 minutes,
/// or one as far in the future (written before the clock was set back).
fn fresh(heartbeat: u64, now: u64) -> bool {
    heartbeat.saturating_add(HEARTBEAT_STALE) >= now
        && heartbeat <= now.saturating_add(HEARTBEAT_STALE)
}

/// The last `lines` lines of goyo-sync.log, continued from goyo-sync.log.1
/// when the current file is shorter. Both are at most 256 KiB.
pub fn log_tail(dir: &Path, lines: usize) -> Vec<String> {
    let read = |name: &str| {
        let mut bytes = Vec::new();
        File::open(dir.join(name))
            .and_then(|f| f.take(2 * engine::MAX_LOG).read_to_end(&mut bytes))
            .map(|_| {
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let mut all = read(crate::LOG);
    if all.len() < lines {
        let mut older = read(&format!("{}.1", crate::LOG));
        older.append(&mut all);
        all = older;
    }
    let skip = all.len().saturating_sub(lines);
    all.split_off(skip)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tests::Temp;
    use goyo_vault::syncwire::Response;
    use std::{collections::VecDeque, sync::Mutex};

    /// One scripted run: what the job ran and what it got back.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Ran {
        pub(crate) tool: Tool,
        pub(crate) args: Vec<String>,
        pub(crate) input: usize,
    }
    /// A runner that answers from a script and records every call; shared,
    /// so a test keeps a handle while a worker thread owns a clone.
    type Shared = Arc<Mutex<(VecDeque<Result<Output, Failure>>, Vec<Ran>)>>;
    #[derive(Clone, Default)]
    pub(crate) struct Script(Shared);
    impl Script {
        pub(crate) fn with(replies: impl IntoIterator<Item = Result<Output, Failure>>) -> Self {
            Self(Arc::new(Mutex::new((
                replies.into_iter().collect(),
                Vec::new(),
            ))))
        }
        pub(crate) fn ran(&self) -> Vec<Ran> {
            self.0.lock().unwrap().1.clone()
        }
        pub(crate) fn push(&self, reply: Result<Output, Failure>) {
            self.0.lock().unwrap().0.push_back(reply);
        }
    }
    impl Runner for Script {
        fn run(
            &mut self,
            tool: Tool,
            args: &[OsString],
            input: &[u8],
            _timeout: Duration,
            _beat: &mut dyn FnMut(),
        ) -> Result<Output, Failure> {
            let mut s = self.0.lock().unwrap();
            s.1.push(Ran {
                tool,
                args: args
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect(),
                input: input.len(),
            });
            s.0.pop_front().expect("a run no reply was scripted for")
        }
    }
    pub(crate) fn out(code: i32, stdout: &[u8], stderr: &str) -> Result<Output, Failure> {
        Ok(Output {
            stdout: stdout.to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            log: Vec::new(),
            code: Some(code),
            killed: None,
        })
    }
    /// ssh failing by itself: its message is in its `-E` log, not on stderr.
    pub(crate) fn ssh_said(said: &str) -> Result<Output, Failure> {
        Ok(Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            log: said.as_bytes().to_vec(),
            code: Some(255),
            killed: None,
        })
    }
    pub(crate) fn reply(status: Status, version: u64, blob: &[u8]) -> Result<Output, Failure> {
        out(0, &Response::new(status, version, blob).encode(), "")
    }
    pub(crate) fn hello_ok() -> Result<Output, Failure> {
        reply(Status::Ok, 1, &goyo_vault::syncwire::HELLO_ECHO)
    }
    pub(crate) fn list_ok(entries: &[ListEntry]) -> Result<Output, Failure> {
        reply(
            Status::Ok,
            entries.len() as u64,
            &goyo_vault::syncwire::render_list(entries),
        )
    }
    const UNKNOWN: &str = "No ED25519 host key is known for my-server and you have requested strict checking.\r\nHost key verification failed.\r\n";
    const CHANGED: &str = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\nHost key for my-server has changed and you have requested strict checking.\r\nHost key verification failed.\r\n";

    fn fields() -> Fields {
        Fields {
            host: "my-server".into(),
            vaults: vec![PathBuf::from(r"D:\GoyoVault\vault.goyo")],
            ..Fields::default()
        }
    }
    fn config() -> Config {
        server_config(&fields()).unwrap()
    }
    fn log(t: &Temp) -> Log {
        Log::new(Some(t.0.join(crate::LOG)))
    }

    /// The window's fields become a goyo-sync.conf that the helper parses
    /// back to the same settings, with every value checked as the helper
    /// checks it, and the input to blame for each problem.
    #[test]
    fn fields_round_trip_through_goyo_sync_conf() {
        let t = Temp::new("fields");
        let key = t.0.join("goyo_sync");
        fs::write(&key, b"not read").unwrap();
        let f = Fields {
            host: "user@my-server".into(),
            remote: "~/sync/goyo-sync-server.py".into(),
            python: "/usr/bin/python3".into(),
            identity: key.to_string_lossy().into_owned(),
            interval: "300".into(),
            timeout: "600".into(),
            vaults: vec![
                PathBuf::from("D:\\\u{ae08}\u{ace0}\\vault.goyo"),
                PathBuf::from(r"\\server\share\other.goyo"),
            ],
        };
        let (text, config) = render(&f).unwrap();
        assert_eq!(config::parse(&text).unwrap(), config);
        assert_eq!(Fields::from_config(&config), f);
        assert_eq!(Fields::from_text(&text), f);
        assert!(text.is_ascii() || text.contains('\u{ae08}'));
        assert!(
            text.lines().all(|l| l.is_empty()
                || l.starts_with('#')
                || l.contains(" = ")
                || l.ends_with(" ="))
        );
        // Written and read back as the helper does.
        let file = t.0.join(crate::CONFIG);
        syncfile::replace_file(&file, text.as_bytes()).unwrap();
        assert_eq!(config::load(&file).unwrap(), config);
        // Defaults and no key.
        let (text, config) = render(&fields()).unwrap();
        assert!(text.contains("identity = \n") || text.contains("identity =\n"));
        assert_eq!(config.identity, None);
        assert_eq!((config.interval, config.timeout), (60, 120));
        assert_eq!(
            server_config(&fields()).unwrap().vaults,
            Vec::<PathBuf>::new()
        );
        // Each problem, blamed on its input.
        type Change = fn(&mut Fields);
        fn case(change: Change, field: Field, why: Why) -> (Change, Field, Why) {
            (change, field, why)
        }
        let cases = [
            case(
                |f| f.host.clear(),
                Field::Host,
                Why::Config(Problem::NoHost),
            ),
            case(
                |f| f.host = "-oProxyCommand=x".into(),
                Field::Host,
                Why::Config(Problem::Host),
            ),
            case(|f| f.host = "my-server#x".into(), Field::Host, Why::Hash),
            case(
                |f| f.host = "a b".into(),
                Field::Host,
                Why::Config(Problem::Host),
            ),
            case(
                |f| f.host = "my-server\nvault = C:\\x.goyo".into(),
                Field::Host,
                Why::Config(Problem::Host),
            ),
            case(
                |f| f.remote = "a;b".into(),
                Field::Remote,
                Why::Config(Problem::Remote),
            ),
            case(
                |f| f.remote.clear(),
                Field::Remote,
                Why::Config(Problem::Remote),
            ),
            case(
                |f| f.python = "python3 -c x".into(),
                Field::Python,
                Why::Config(Problem::Python),
            ),
            case(
                |f| f.identity = r"D:\missing\goyo_sync".into(),
                Field::Identity,
                Why::Config(Problem::Identity),
            ),
            case(
                |f| f.identity = "relative".into(),
                Field::Identity,
                Why::Config(Problem::Identity),
            ),
            case(
                |f| f.interval = "5".into(),
                Field::Interval,
                Why::Config(Problem::Interval),
            ),
            case(
                |f| f.interval = "60s".into(),
                Field::Interval,
                Why::Config(Problem::Interval),
            ),
            case(
                |f| f.timeout = "601".into(),
                Field::Timeout,
                Why::Config(Problem::Timeout),
            ),
            case(
                |f| f.vaults.clear(),
                Field::Vaults,
                Why::Config(Problem::NoVault),
            ),
            case(
                |f| f.vaults.push(r"D:\GoyoVault\vault.goyokey".into()),
                Field::Vault(1),
                Why::Config(Problem::KeyFile),
            ),
            case(
                |f| f.vaults.push(r"D:\#1\vault.goyo".into()),
                Field::Vault(1),
                Why::Hash,
            ),
            case(
                |f| f.vaults.push("vault.goyo".into()),
                Field::Vault(1),
                Why::Config(Problem::Vault),
            ),
            case(
                |f| f.vaults.push(r"d:\goyovault\VAULT.goyo".into()),
                Field::Vault(1),
                Why::Config(Problem::DuplicateVault),
            ),
            case(
                |f| {
                    f.vaults = (0..9)
                        .map(|i| PathBuf::from(format!(r"D:\v{i}\vault.goyo")))
                        .collect()
                },
                Field::Vaults,
                Why::Config(Problem::TooManyVaults),
            ),
            case(
                |f| {
                    f.vaults = (0..8)
                        .map(|i| PathBuf::from(format!("D:\\{}\\v{i}.goyo", "x".repeat(1100))))
                        .collect()
                },
                Field::Vaults,
                Why::TooLarge,
            ),
        ];
        for (i, (change, field, why)) in cases.into_iter().enumerate() {
            let mut f = fields();
            change(&mut f);
            assert_eq!(render(&f).unwrap_err(), Bad { field, why }, "case {i}");
        }
        // Server settings are checked without any vault.
        let mut f = fields();
        f.vaults.clear();
        assert!(server_config(&f).is_ok());
        f.timeout = "29".into();
        assert_eq!(server_config(&f).unwrap_err().field, Field::Timeout);
        // A damaged file is still shown as written.
        let shown =
            Fields::from_text("host = my server\nremote=x\nvault = D:\\a.goyo # c\nbogus\n");
        assert_eq!(shown.host, "my server");
        assert_eq!(shown.remote, "x");
        assert_eq!(shown.vaults, [PathBuf::from(r"D:\a.goyo")]);
        // Picking a vault: key files, '#', duplicates and the limit.
        let list = vec![PathBuf::from(r"D:\GoyoVault\vault.goyo")];
        assert_eq!(
            vault_problem(Path::new(r"D:\k\vault.goyokey. "), &list),
            Some(Why::Config(Problem::KeyFile))
        );
        assert_eq!(
            vault_problem(Path::new(r"D:\#\v.goyo"), &list),
            Some(Why::Hash)
        );
        assert_eq!(
            vault_problem(Path::new(r"D:\GOYOVAULT\vault.goyo"), &list),
            Some(Why::Config(Problem::DuplicateVault))
        );
        assert_eq!(
            vault_problem(Path::new(r"D:\a\b.goyo:s"), &list),
            Some(Why::Config(Problem::Vault))
        );
        assert_eq!(
            vault_problem(Path::new(r"D:\other\vault.goyo"), &list),
            None
        );
        // A name that is not valid Unicode cannot go into goyo-sync.conf.
        let mut odd: Vec<u16> = r"D:\v".encode_utf16().collect();
        odd.push(0xd800);
        odd.extend(".goyo".encode_utf16());
        let odd = PathBuf::from(<OsString as std::os::windows::ffi::OsStringExt>::from_wide(
            &odd,
        ));
        assert_eq!(
            vault_problem(&odd, &list),
            Some(Why::Config(Problem::Vault))
        );
        let full: Vec<PathBuf> = (0..8)
            .map(|i| PathBuf::from(format!(r"D:\v{i}.goyo")))
            .collect();
        assert_eq!(
            vault_problem(Path::new(r"D:\x.goyo"), &full),
            Some(Why::Config(Problem::TooManyVaults))
        );
    }

    /// The install sends one fixed command made only of validated words.
    #[test]
    fn install_command_is_fixed_and_refuses_bad_words() {
        assert_eq!(
            install_command(DEFAULT_REMOTE, DEFAULT_PYTHON).unwrap(),
            "umask 077 && mkdir -p .local/share/goyo-sync && \
             cat > .local/share/goyo-sync/goyo-sync-server.py.new && \
             chmod 700 .local/share/goyo-sync/goyo-sync-server.py.new && \
             python3 -I .local/share/goyo-sync/goyo-sync-server.py.new selftest && \
             mv -f .local/share/goyo-sync/goyo-sync-server.py.new .local/share/goyo-sync/goyo-sync-server.py"
        );
        assert_eq!(
            install_command("~/sync/s.py", "/usr/bin/python3.12").unwrap(),
            "umask 077 && mkdir -p ~/sync && cat > ~/sync/s.py.new && chmod 700 ~/sync/s.py.new \
             && /usr/bin/python3.12 -I ~/sync/s.py.new selftest && mv -f ~/sync/s.py.new ~/sync/s.py"
        );
        assert!(
            install_command("s.py", "python3")
                .unwrap()
                .contains("mkdir -p . &&")
        );
        assert!(
            install_command("/s.py", "python3")
                .unwrap()
                .contains("mkdir -p / &&")
        );
        for remote in [
            "",
            "a;b",
            "a b",
            "$HOME/x.py",
            "x`id`",
            "-x",
            "dir/",
            "~",
            "a/..",
            "a/.",
            "\"x\"",
            "x|y",
            "x>y",
            "x&y",
            "x\ny",
            "a/~b",
            "x'y",
            "x\\y",
            "x(y)",
            "x$y",
            "*.py",
            "x?.py",
            "[x].py",
            "x{a,b}.py",
            "x\u{a0}y.py",
            "x.py\0",
        ] {
            assert_eq!(
                install_command(remote, "python3"),
                Err(Unsafe::Remote),
                "{remote:?}"
            );
        }
        for python in [
            "",
            "python3;id",
            "-c",
            "py thon",
            "~/python",
            "python3 -c x",
            "$(id)",
            "python3&&id",
            "py*",
            "`id`",
            "python3\n",
        ] {
            assert_eq!(
                install_command(DEFAULT_REMOTE, python),
                Err(Unsafe::Python),
                "{python:?}"
            );
        }
        // The argv: the helper's fixed options, no dedicated key, "--", the
        // host and the command as one argument.
        let mut c = config();
        c.identity = Some(PathBuf::from(r"C:\Users\<you>\.ssh\goyo_sync"));
        let args: Vec<String> = install_args(&c)
            .unwrap()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let mut want: Vec<String> = ssh_options(&config())
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = want.iter().position(|a| a == "--").unwrap();
        want.truncate(at + 2);
        want.push(install_command(DEFAULT_REMOTE, DEFAULT_PYTHON).unwrap());
        assert_eq!(args, want);
        assert!(
            !args
                .iter()
                .any(|a| a == "-i" || a.contains("IdentitiesOnly"))
        );
        assert_eq!(args[at..at + 2], ["--", "my-server"]);
        c.remote = "a;b".into();
        assert_eq!(install_args(&c), Err(Unsafe::Remote));
        // The trust call changes exactly one option.
        let normal = ssh_options(&config());
        let trust = trust_args(&config());
        let changed: Vec<_> = normal.iter().zip(&trust).filter(|(a, b)| a != b).collect();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].0, "StrictHostKeyChecking=yes");
        assert_eq!(changed[0].1, "StrictHostKeyChecking=accept-new");
        assert_eq!(normal.len(), trust.len());
        assert_eq!(
            resolve_args("user@my-server"),
            ["-G", "--", "user@my-server"]
        );
        assert_eq!(
            fingerprint_args("[my-server]:2222"),
            ["-l", "-F", "[my-server]:2222"]
        );
        // The embedded script is the shipped one, LF only.
        let shipped =
            fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(r"server\goyo-sync-server.py"))
                .unwrap();
        assert_eq!(SERVER_SCRIPT, shipped.as_slice());
        assert!(!SERVER_SCRIPT.contains(&b'\r'));
    }

    /// Host key refusals lead to the right next step, and only a first
    /// connection with nothing known for the name is ever offered.
    #[test]
    fn host_key_steps() {
        let nothing = Known::Nothing;
        let keys = Known::Keys(vec!["my-server ED25519 SHA256:x".into()]);
        assert_eq!(key_problem(UNKNOWN), KeyProblem::Unknown);
        assert_eq!(key_problem(CHANGED), KeyProblem::Changed);
        assert_eq!(
            key_problem("Host key verification failed."),
            KeyProblem::Changed
        );
        assert_eq!(
            key_step(UNKNOWN, Some("my-server"), &nothing),
            KeyStep::Ask {
                name: "my-server".into()
            }
        );
        assert_eq!(
            key_step(UNKNOWN, Some("my-server"), &keys),
            KeyStep::OtherKey {
                name: "my-server".into()
            }
        );
        assert_eq!(
            key_step(UNKNOWN, Some("my-server"), &Known::Unclear),
            KeyStep::Unclear
        );
        assert_eq!(key_step(UNKNOWN, None, &nothing), KeyStep::Unclear);
        for known in [&nothing, &keys, &Known::Unclear] {
            assert_eq!(
                key_step(CHANGED, Some("my-server"), known),
                KeyStep::Changed
            );
        }
        assert_eq!(
            key_step(
                "WARNING: REVOKED HOST KEY DETECTED! ... strict checking. host key is known for",
                Some("m"),
                &nothing
            ),
            KeyStep::Changed
        );
        // ssh -G output: alias, port, invalid names.
        let g = |s: &str| parse_resolved(s.as_bytes());
        assert_eq!(
            g("user u\nhostname my-server.example\nport 22\n"),
            Some("my-server.example".into())
        );
        assert_eq!(
            g("hostname my-server\r\nport 2222\r\n"),
            Some("[my-server]:2222".into())
        );
        assert_eq!(
            g("hostname 192.0.2.10\nport 22\nhostkeyalias my-alias\n"),
            Some("my-alias".into())
        );
        assert_eq!(g("hostname -oProxyCommand=x\nport 22\n"), None);
        assert_eq!(g("hostname my-server\nport 99999\n"), None);
        assert_eq!(g("port 22\n"), None);
        // ssh-keygen -l -F output.
        let k = |code, stdout: &str, stderr: &str| {
            parse_known(&out(code, stdout.as_bytes(), stderr).unwrap())
        };
        assert_eq!(
            k(
                0,
                "# Host my-server found: line 3 \nmy-server ED25519 SHA256:L3tj\n",
                ""
            ),
            Known::Keys(vec!["my-server ED25519 SHA256:L3tj".into()])
        );
        assert_eq!(k(1, "", ""), Known::Nothing);
        assert_eq!(
            k(
                255,
                "",
                "Cannot stat C:\\Users\\u/.ssh/known_hosts: No such file or directory"
            ),
            Known::Nothing
        );
        assert_eq!(k(255, "", "something else"), Known::Unclear);

        // The whole check with scripted runs.
        let t = Temp::new("hostkey");
        let log = log(&t);
        let c = config();
        let resolved = || out(0, b"hostname my-server\nport 22\n", "");
        // First connection: HELLO refused, ssh -G, ssh-keygen finds nothing.
        let s = Script::with([ssh_said(UNKNOWN), resolved(), out(1, b"", "")]);
        let got = check(&mut s.clone(), &log, &c);
        assert_eq!(
            got,
            Checked::HostKey(KeyStep::Ask {
                name: "my-server".into()
            })
        );
        let ran = s.ran();
        assert_eq!(
            ran.iter().map(|r| r.tool).collect::<Vec<_>>(),
            [Tool::Ssh, Tool::Ssh, Tool::Keygen]
        );
        assert!(ran[0].args.contains(&"StrictHostKeyChecking=yes".into()));
        assert_eq!(ran[1].args, ["-G", "--", "my-server"]);
        assert_eq!(ran[2].args, ["-l", "-F", "my-server"]);
        // Changed: no lookup, never a question.
        let s = Script::with([ssh_said(CHANGED)]);
        assert_eq!(
            check(&mut s.clone(), &log, &c),
            Checked::HostKey(KeyStep::Changed)
        );
        assert_eq!(s.ran().len(), 1);
        // A key of another type is known for the name.
        let s = Script::with([
            ssh_said(UNKNOWN),
            resolved(),
            out(0, b"my-server RSA SHA256:x\n", ""),
        ]);
        assert_eq!(
            check(&mut s.clone(), &log, &c),
            Checked::HostKey(KeyStep::OtherKey {
                name: "my-server".into()
            })
        );
        // No ssh-keygen: nothing trusted.
        let s = Script::with([ssh_said(UNKNOWN), resolved(), Err(Failure::Missing)]);
        assert_eq!(
            check(&mut s.clone(), &log, &c),
            Checked::HostKey(KeyStep::Unclear)
        );
        // After "yes": one HELLO with accept-new, the fingerprint, then LIST
        // with the usual options.
        let s = Script::with([
            hello_ok(),
            resolved(),
            out(0, b"my-server ED25519 SHA256:abc\n", ""),
            list_ok(&[]),
        ]);
        let got = trust(&mut s.clone(), &log, &c);
        assert_eq!(got.name.as_deref(), Some("my-server"));
        assert_eq!(
            got.known,
            Known::Keys(vec!["my-server ED25519 SHA256:abc".into()])
        );
        assert_eq!(got.checked, Checked::Ok { vaults: 0 });
        let ran = s.ran();
        let accept: Vec<_> = ran
            .iter()
            .filter(|r| r.args.contains(&"StrictHostKeyChecking=accept-new".into()))
            .collect();
        assert_eq!(accept.len(), 1);
        assert_eq!(
            ran[0].args,
            trust_args(&c)
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
        assert!(ran[3].args.contains(&"StrictHostKeyChecking=yes".into()));
        // The key changed between the question and the answer: refused.
        let s = Script::with([
            ssh_said(CHANGED),
            resolved(),
            out(0, b"my-server ED25519 SHA256:old\n", ""),
        ]);
        assert_eq!(
            trust(&mut s.clone(), &log, &c).checked,
            Checked::HostKey(KeyStep::Changed)
        );
    }

    /// Every failure of the check has its own state, and a missing script or
    /// Python is told apart from other server errors.
    #[test]
    fn check_results() {
        let t = Temp::new("check");
        let log = log(&t);
        let c = config();
        let entry = ListEntry {
            id: [7; 16],
            head: 3,
            size: 160,
            mtime: 1_800_000_000,
        };
        let s = Script::with([
            hello_ok(),
            list_ok(&[
                entry,
                ListEntry {
                    id: [8; 16],
                    ..entry
                },
            ]),
        ]);
        assert_eq!(check(&mut s.clone(), &log, &c), Checked::Ok { vaults: 2 });
        assert_eq!(s.ran()[0].input, goyo_vault::syncwire::REQUEST_HEADER + 512);
        let failed =
            |reply: Result<Output, Failure>| match check(&mut Script::with([reply]), &log, &c) {
                Checked::Failed(t) => t,
                other => panic!("{other:?}"),
            };
        assert_eq!(failed(Err(Failure::Missing)).state, SyncState::NoSsh);
        assert_eq!(
            failed(ssh_said("u@my-server: Permission denied (publickey).")).state,
            SyncState::Auth
        );
        assert_eq!(
            failed(ssh_said(
                "ssh: Could not resolve hostname my-server: No such host is known."
            ))
            .state,
            SyncState::Offline
        );
        assert_eq!(
            failed(ssh_said(
                "ssh: connect to host my-server port 22: Connection timed out"
            ))
            .state,
            SyncState::Offline
        );
        // The same words printed by the server are the server's, not ssh's.
        assert_eq!(
            failed(out(
                255,
                b"",
                "ssh: connect to host my-server port 22: Connection timed out"
            ))
            .state,
            SyncState::Server
        );
        let missing = failed(out(
            2,
            b"",
            "python3: can't open file '/home/u/.local/share/goyo-sync/goyo-sync-server.py': [Errno 2] No such file or directory",
        ));
        assert_eq!(
            (missing.state, missing.cause),
            (SyncState::Server, Cause::ScriptMissing)
        );
        let python = failed(out(127, b"", "bash: line 1: python3: command not found"));
        assert_eq!(
            (python.state, python.cause),
            (SyncState::Server, Cause::PythonMissing)
        );
        let other = failed(out(1, b"garbage", "Traceback (most recent call last):"));
        assert_eq!(
            (other.state, other.cause),
            (SyncState::Server, Cause::Plain)
        );
        // The remote side's line, marked as such: ssh itself said nothing.
        assert_eq!(other.detail, "stderr: Traceback (most recent call last):");
        // A server that answers HELLO but not LIST.
        let s = Script::with([hello_ok(), out(1, b"", "boom")]);
        assert!(
            matches!(check(&mut s.clone(), &log, &c), Checked::Failed(t) if t.state == SyncState::Server)
        );
        // The server list.
        let s = Script::with([list_ok(&[entry])]);
        assert_eq!(list(&mut s.clone(), &log, &c).unwrap(), [entry]);
        assert_eq!(
            s.ran()[0].args,
            ssh_options(&c)
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
    }

    /// Only a lone PASS from the selftest is an install; the shell's own
    /// failures, a failing selftest and extra output are each reported.
    #[test]
    fn install_results() {
        let t = Temp::new("install");
        let log = log(&t);
        let s = Script::with([out(0, b"PASS\n", "")]);
        assert_eq!(install(&mut s.clone(), &log, &config()), Installed::Pass);
        let ran = s.ran();
        assert_eq!(ran.len(), 1);
        assert_eq!(ran[0].input, SERVER_SCRIPT.len());
        assert_eq!(
            ran[0].args.last().unwrap(),
            &install_command(DEFAULT_REMOTE, DEFAULT_PYTHON).unwrap()
        );
        let r = |o| install_result(o);
        assert_eq!(r(out(0, b"\r\nPASS\r\n", "")), Installed::Pass);
        assert_eq!(
            r(out(1, b"FAIL: history\n", "")),
            Installed::NotPass {
                line: "FAIL: history".into(),
                cause: Cause::Plain,
                noisy: false
            }
        );
        assert_eq!(
            r(out(0, b"Welcome to my-server\nPASS\n", "")),
            Installed::NotPass {
                line: "PASS".into(),
                cause: Cause::Plain,
                noisy: true
            }
        );
        assert_eq!(
            r(out(127, b"", "bash: line 1: python3: command not found")),
            Installed::NotPass {
                line: "bash: line 1: python3: command not found".into(),
                cause: Cause::PythonMissing,
                noisy: false
            }
        );
        // The new copy passed but could not be moved in place: the old script
        // stays, and mv's own words are shown (never "Python missing").
        assert_eq!(
            r(out(
                1,
                b"PASS\n",
                "mv: cannot move 'x.new' to 'x': No such file or directory"
            )),
            Installed::NotPass {
                line: "mv: cannot move 'x.new' to 'x': No such file or directory".into(),
                cause: Cause::Plain,
                noisy: false
            }
        );
        // A cut-off copy fails its own selftest, so nothing is replaced.
        assert_eq!(
            r(out(
                1,
                b"",
                "  File \"x.new\", line 9\nSyntaxError: invalid syntax"
            )),
            Installed::NotPass {
                line: "  File \"x.new\", line 9".into(),
                cause: Cause::Plain,
                noisy: false
            }
        );
        // mkdir's "Permission denied" is the remote command's, not a login failure.
        assert!(matches!(
            r(out(
                1,
                b"",
                "mkdir: cannot create directory '/x': Permission denied"
            )),
            Installed::NotPass { .. }
        ));
        assert!(
            matches!(r(ssh_said("u@my-server: Permission denied (publickey).")), Installed::Failed(t) if t.state == SyncState::Auth)
        );
        assert!(
            matches!(r(ssh_said(UNKNOWN)), Installed::Failed(t) if t.state == SyncState::HostKey)
        );
        assert!(
            matches!(r(Err(Failure::Missing)), Installed::Failed(t) if t.state == SyncState::NoSsh)
        );
        let killed = Ok(Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            log: Vec::new(),
            code: None,
            killed: Some(Killed::Timeout),
        });
        assert!(matches!(r(killed), Installed::Failed(t) if t.state == SyncState::Offline));
        let cancelled = Ok(Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            log: Vec::new(),
            code: None,
            killed: Some(Killed::Cancelled),
        });
        assert_eq!(r(cancelled), Installed::Cancelled);
        let mut c = config();
        c.python = "python3;id".into();
        assert_eq!(
            install(&mut Script::default(), &log, &c),
            Installed::Refused(Unsafe::Python)
        );
    }

    /// Restart stops the old helper first and confirms the new one; the
    /// list shows each vault's state from its folder alone.
    #[test]
    fn restart_and_live_states() {
        #[derive(Default)]
        struct Fake(Mutex<(bool, Vec<&'static str>, bool)>);
        impl System for Fake {
            fn running(&self) -> bool {
                self.0.lock().unwrap().0
            }
            fn stop(&self) -> bool {
                let mut s = self.0.lock().unwrap();
                s.1.push("stop");
                s.0 = false;
                true
            }
            fn start(&self) -> Result<(), u32> {
                let mut s = self.0.lock().unwrap();
                s.1.push("start");
                s.0 = !s.2;
                Ok(())
            }
            fn autostart(&self) -> bool {
                false
            }
            fn set_autostart(&self, _: bool) -> Result<(), i32> {
                Ok(())
            }
        }
        let poll = Duration::from_millis(1);
        let fake = Fake::default();
        assert_eq!(restart(&fake, poll), Restarted::Started);
        assert_eq!(restart(&fake, poll), Restarted::Started);
        assert_eq!(fake.0.lock().unwrap().1, ["start", "stop", "start"]);
        fake.0.lock().unwrap().0 = false;
        fake.0.lock().unwrap().2 = true; // exits at once
        assert_eq!(restart(&fake, poll), Restarted::NotStarted);
        // Run values.
        let exe = Path::new(r"C:\Goyo Vault\goyo-sync.exe");
        assert!(names_exe(
            "\"C:\\Goyo Vault\\goyo-sync.exe\" --background".as_ref(),
            exe
        ));
        assert!(names_exe("\"c:\\goyo vault\\GOYO-SYNC.EXE\"".as_ref(), exe));
        assert!(!names_exe(
            "\"C:\\Other\\goyo-sync.exe\" --background".as_ref(),
            exe
        ));
        assert!(!names_exe(
            "\"C:\\Goyo Vault\\goyo-sync.exe.bak\"".as_ref(),
            exe
        ));
        assert_eq!(
            crate::autostart_command(exe),
            "\"C:\\Goyo Vault\\goyo-sync.exe\" --background"
        );
        // Live states.
        let t = Temp::new("live");
        let vault = t.0.join("vault.goyo");
        let dir = t.0.join("vault.goyo.sync");
        let now = 1_800_000_000;
        assert_eq!(live(&vault, now), Live::NoVault);
        fs::write(&vault, b"never read").unwrap();
        assert_eq!(live(&vault, now), Live::NotSetUp);
        fs::create_dir(&dir).unwrap();
        assert_eq!(live(&vault, now), Live::HelperOff { server: 0 });
        let write = |heartbeat, state| {
            syncfile::replace_file(
                &dir.join(syncfile::STATUS),
                &syncfile::render_status(heartbeat, 0, state),
            )
            .unwrap();
        };
        write(now - 10, SyncState::Idle);
        assert_eq!(
            live(&vault, now),
            Live::State {
                state: SyncState::Idle,
                server: 0
            }
        );
        let state = syncfile::HelperState {
            id: Some([3; 16]),
            server: 7,
            ..Default::default()
        };
        syncfile::replace_file(
            &dir.join(syncfile::HELPER_STATE),
            &syncfile::render_helper_state(&state),
        )
        .unwrap();
        write(now - 10, SyncState::Ok);
        assert_eq!(
            live(&vault, now),
            Live::State {
                state: SyncState::Ok,
                server: 7
            }
        );
        write(now - 200, SyncState::Ok);
        assert_eq!(live(&vault, now), Live::HelperOff { server: 7 });
        write(now + 200, SyncState::Ok);
        assert_eq!(live(&vault, now), Live::HelperOff { server: 7 });
        fs::remove_file(&vault).unwrap();
        assert_eq!(live(&vault, now), Live::NoVault);
        fs::write(&vault, b"x").unwrap();
        fs::remove_dir_all(&dir).unwrap();
        crate::tests::junction(&dir, &t.0);
        assert_eq!(live(&vault, now), Live::Unusable);
        fs::remove_dir(&dir).unwrap();
        // The log tail continues from the rotated file.
        let logdir = Temp::new("tail");
        fs::write(logdir.0.join("goyo-sync.log.1"), "a\nb\nc\n").unwrap();
        fs::write(logdir.0.join(crate::LOG), "d\ne\n").unwrap();
        assert_eq!(log_tail(&logdir.0, 4), ["b", "c", "d", "e"]);
        assert_eq!(log_tail(&logdir.0, 1), ["e"]);
        assert!(log_tail(&t.0.join("none"), 5).is_empty());
    }

    /// The server list and a fetch through the window's jobs; a target that
    /// exists is never written, before any network call.
    #[test]
    fn fetch_and_sync_jobs() {
        let t = Temp::new("fetchjob");
        let log = log(&t);
        let c = config();
        let id = [0xA7; 16];
        let mut blob = Vec::from(*b"GOYOVA02");
        blob.extend_from_slice(&id);
        blob.resize(160, 1);
        let target = t.0.join("from-server.goyo");
        let s = Script::with([reply(Status::Ok, 4, &blob)]);
        assert_eq!(
            fetch(&mut s.clone(), &log, &c, id, &target),
            Got::Saved {
                version: 4,
                bytes: 160
            }
        );
        assert_eq!(fs::read(&target).unwrap(), blob);
        let s = Script::default();
        assert_eq!(fetch(&mut s.clone(), &log, &c, id, &target), Got::Exists);
        assert!(s.ran().is_empty());
        let other = t.0.join("other.goyo");
        assert_eq!(
            fetch(
                &mut Script::with([reply(Status::NotFound, 0, b"")]),
                &log,
                &c,
                id,
                &other
            ),
            Got::NotFound
        );
        assert!(
            matches!(fetch(&mut Script::with([ssh_said("Connection refused")]), &log, &c, id, &other), Got::Failed(t) if t.state == SyncState::Offline)
        );
        assert!(!other.exists());
        // A forced pass over a vault without a sync folder makes the folder
        // and asks nothing yet (no vault ID pinned).
        let vault = t.0.join("vault.goyo");
        fs::write(&vault, b"never read by the helper").unwrap();
        let mut c = config();
        c.vaults = vec![vault.clone()];
        let s = Script::default();
        let results = sync_now(&mut s.clone(), &log, &c);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Outcome::Done(r) if r.state == SyncState::Idle));
        assert!(t.0.join("vault.goyo.sync").is_dir());
        assert!(s.ran().is_empty());
    }
}
