//! goyo-sync tests (spec §17 items 17-21 and 23, plus end-to-end runs
//! against the real server script). Nothing here runs ssh or touches the
//! registry. The python-based tests fail loudly when python is missing,
//! unless GOYO_SYNC_SKIP_PYTHON=1.
use super::*;
use crate::{
    config::{DEFAULT_PYTHON, DEFAULT_REMOTE, MAX_CONFIG},
    engine::{
        CallError, Clock, Gate, HEARTBEAT, MAX_BACKOFF, RETRY_HELD, Refusal, backoff, gate,
        jittered,
    },
    transport::{
        Failure, Killed, MAX_STDERR, MAX_STDOUT, Output, SSH_LOG, STALE_LOG, SshLog, Transport,
        classify, first_line, run_bounded, ssh_args, ssh_program, sweep_logs,
    },
};
use goyo_vault::{
    syncfile::{
        HELPER_LOCK, HELPER_STATE, HelperState, INCOMING, OUTGOING, SyncStatus, render_incoming,
        render_outgoing, replace_file,
    },
    syncwire::{Op, Response, sha256},
    vault::{Entry, Provision, Session, SyncBadge, SyncNotice},
};
use std::{
    cell::Cell,
    collections::VecDeque,
    fs,
    path::Path,
    process::Command,
    rc::Rc,
    sync::atomic::{AtomicU32, Ordering},
    time::{Instant, SystemTime},
};

const PASSWORD: &str = "a long synthetic password";
const START: u64 = 1_800_000_000;

/// A fresh folder under %TEMP%, removed with everything in it.
pub(crate) struct Temp(pub(crate) PathBuf);
impl Temp {
    pub(crate) fn new(what: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = engine::system_clock()().subsec_nanos();
        let name = format!(
            "goyo-sync-{what}-{:x}-{nanos:x}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        let p = std::env::temp_dir().join(name);
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One simulated PC: a vault path, its key path and its sync folder.
struct Pc {
    t: Temp,
    vault: PathBuf,
    key: PathBuf,
    dir: PathBuf,
}
impl Pc {
    fn new() -> Self {
        let t = Temp::new("pc");
        let (vault, key, dir) = (
            t.0.join("vault.goyo"),
            t.0.join("vault.goyokey"),
            t.0.join("vault.goyo.sync"),
        );
        Self { t, vault, key, dir }
    }
    /// A vault file the helper must never read, and its sync folder.
    fn with_folder() -> Self {
        let pc = Self::new();
        fs::write(&pc.vault, b"never read by the helper").unwrap();
        fs::create_dir(&pc.dir).unwrap();
        pc
    }
    /// What the app writes; returns the SHA-256 of the whole file.
    fn outgoing(&self, base: u64, vault: &[u8]) -> [u8; 32] {
        let bytes = render_outgoing(base, vault).unwrap();
        replace_file(&self.dir.join(OUTGOING), &bytes).unwrap();
        sha256(&bytes)
    }
    fn incoming(&self) -> Option<(u64, Vec<u8>)> {
        let bytes = fs::read(self.dir.join(INCOMING)).ok()?;
        syncfile::parse_incoming(&bytes).map(|(v, b)| (v, b.to_vec()))
    }
    fn state(&self) -> HelperState {
        syncfile::read_helper_state(&self.dir).unwrap()
    }
    fn status(&self) -> SyncStatus {
        syncfile::read_status(&self.dir).unwrap()
    }
    fn log(&self) -> String {
        fs::read_to_string(self.t.0.join(LOG)).unwrap_or_default()
    }
    fn engine<T: Transport>(&self, transport: T, clock: &TestClock) -> Engine<T> {
        Engine::new(
            transport,
            std::slice::from_ref(&self.vault),
            60,
            clock.boxed(),
            Log::new(Some(self.t.0.join(LOG))),
        )
    }
}

/// A clock the test moves by hand; nanoseconds 0 make the poll wait 0.9 x
/// the interval (54 s for 60).
#[derive(Clone)]
struct TestClock(Rc<Cell<u64>>);
impl TestClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(START)))
    }
    fn boxed(&self) -> Clock {
        let now = self.0.clone();
        Box::new(move || Duration::from_secs(now.get()))
    }
    fn advance(&self, secs: u64) {
        self.0.set(self.0.get() + secs);
    }
    fn back(&self, secs: u64) {
        self.0.set(self.0.get() - secs);
    }
}

/// A GOYOVA02-shaped file; the helper never decrypts, so filler will do.
fn blob(id: &[u8; 16], fill: u8) -> Vec<u8> {
    let mut v = Vec::from(*b"GOYOVA02");
    v.extend_from_slice(id);
    v.resize(160, fill);
    v
}
/// The same as GOYOVA04, the format under a KF2 key file (140 B at least).
fn keyed(id: &[u8; 16], fill: u8) -> Vec<u8> {
    let mut v = blob(id, fill);
    v[..8].copy_from_slice(b"GOYOVA04");
    v
}

/// Scripted server replies and a log of the requests, each of which must
/// pass the server's own frame rules.
#[derive(Default)]
struct Mock {
    replies: VecDeque<Result<Output, Failure>>,
    calls: Vec<Call>,
    /// In the security-key build, unless this is set, a GETKEY is answered
    /// EMPTY (a server that holds no key file for the vault) without a
    /// scripted reply and counted in `fetched`, not logged in `calls`: the
    /// vault channel's tests see the calls they script.
    #[cfg(feature = "security-key")]
    keys: bool,
    #[cfg(feature = "security-key")]
    fetched: usize,
}
#[derive(Clone, PartialEq, Eq, Debug)]
struct Call {
    op: Op,
    version: u64,
    sha: [u8; 32],
    blob: Vec<u8>,
}
impl Mock {
    fn with(replies: impl IntoIterator<Item = Result<Output, Failure>>) -> Self {
        Self {
            replies: replies.into_iter().collect(),
            ..Self::default()
        }
    }
    fn ops(&self) -> Vec<(Op, u64)> {
        self.calls.iter().map(|c| (c.op, c.version)).collect()
    }
}
impl Transport for Mock {
    fn exchange(&mut self, request: &[u8], _beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        let r = Request::decode(request).expect("the server would refuse this frame");
        #[cfg(feature = "security-key")]
        if !self.keys && r.op == Op::GetKey {
            self.fetched += 1;
            return reply(Status::Empty, 0, b"");
        }
        self.calls.push(Call {
            op: r.op,
            version: r.version,
            sha: r.blob_sha,
            blob: r.blob.to_vec(),
        });
        self.replies
            .pop_front()
            .expect("the engine made a call no reply was scripted for")
    }
}
fn reply(status: Status, version: u64, blob: &[u8]) -> Result<Output, Failure> {
    Ok(Output {
        stdout: Response::new(status, version, blob).encode(),
        stderr: Vec::new(),
        log: Vec::new(),
        code: Some(0),
        killed: None,
    })
}
/// ssh failed and said why in its own log (`-E`).
fn ssh_error(log: &str) -> Result<Output, Failure> {
    Ok(Output {
        stdout: Vec::new(),
        stderr: Vec::new(),
        log: log.as_bytes().to_vec(),
        code: Some(255),
        killed: None,
    })
}
/// No frame, and only the remote side's words on stderr, as when the
/// server prints ssh's messages itself and exits 255.
fn remote_error(stderr: &str) -> Result<Output, Failure> {
    Ok(Output {
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        log: Vec::new(),
        code: Some(255),
        killed: None,
    })
}
fn done(state: SyncState, server: u64, up: Option<u64>, down: Option<u64>) -> Outcome {
    Outcome::Done(Report {
        state,
        server,
        uploaded: up,
        downloaded: down,
    })
}

// ---- 17: config ----

/// A valid file with `line` as its line 2 (and no second host line).
fn parse_with(line: &str) -> Result<Config, config::ConfigError> {
    let host = if line.starts_with("host") {
        ""
    } else {
        "host = my-server"
    };
    config::parse(&format!(
        "vault = D:\\GoyoVault\\vault.goyo\n{line}\n{host}\n"
    ))
}
#[test]
fn config_accepts_the_example_and_rejects_the_rest() {
    let example = config::parse(include_str!("../../../goyo-sync.conf.example")).unwrap();
    assert_eq!(
        example,
        Config {
            host: "my-server".into(),
            remote: DEFAULT_REMOTE.into(),
            python: DEFAULT_PYTHON.into(),
            identity: None,
            interval: 60,
            timeout: 120,
            vaults: vec![PathBuf::from(r"D:\GoyoVault\vault.goyo")],
        }
    );
    // Accepted forms.
    let t = Temp::new("config");
    let identity = t.0.join("goyo_sync");
    fs::write(&identity, b"not read by these tests").unwrap();
    let full = format!(
        "\u{feff}# comment\r\n  host=<user>@my-server.example_1  # trailing comment\r\n\
         remote = ~/sync/goyo-sync-server.py\npython = /usr/bin/python3.12\n\
         identity = {}\ninterval = 30\ntimeout = 600\n\
         vault = D:\\\u{ae08}\u{ace0}\\vault.goyo\nvault = \\\\server\\share\\other.goyo\n",
        identity.display()
    )
    .replace("<user>", "user");
    let c = config::parse(&full).unwrap();
    assert_eq!(c.host, "user@my-server.example_1");
    assert_eq!(c.remote, "~/sync/goyo-sync-server.py");
    assert_eq!(c.python, "/usr/bin/python3.12");
    assert_eq!(c.identity.as_deref(), Some(identity.as_path()));
    assert_eq!((c.interval, c.timeout), (30, 600));
    assert_eq!(c.vaults.len(), 2);
    assert!(parse_with("interval = 3600\ntimeout = 30").is_ok());
    let eight: String = (0..8)
        .map(|i| format!("vault = D:\\v{i}\\vault.goyo\n"))
        .collect();
    assert_eq!(
        config::parse(&format!("host = my-server\n{eight}"))
            .unwrap()
            .vaults
            .len(),
        8
    );

    let rejected: &[(&str, Problem)] = &[
        ("host = -oProxyCommand=x", Problem::Host),
        ("host = a b", Problem::Host),
        ("host = h;rm", Problem::Host),
        ("host = \"my-server\"", Problem::Host),
        ("host = 'my-server'", Problem::Host),
        ("host = \u{c11c}\u{bc84}", Problem::Host),
        ("host = -my-server", Problem::Host),
        ("host = -x@my-server", Problem::Host),
        ("host = user@-x", Problem::Host),
        ("host = a@b@c", Problem::Host),
        ("host = my-server:22", Problem::Host),
        ("host = $(id)", Problem::Host),
        ("host =", Problem::Host),
        ("remote = a;b", Problem::Remote),
        ("remote = -x", Problem::Remote),
        ("remote = a b", Problem::Remote),
        ("remote = $HOME/x.py", Problem::Remote),
        ("remote = x`id`", Problem::Remote),
        ("remote = \"x\"", Problem::Remote),
        ("python = python3;id", Problem::Python),
        ("python = -c", Problem::Python),
        ("python = py thon", Problem::Python),
        ("python = ~/python", Problem::Python),
        ("identity = goyo_sync", Problem::Identity),
        ("identity = D:\\missing\\goyo_sync", Problem::Identity),
        ("proxy = x", Problem::UnknownKey),
        ("Host = x", Problem::UnknownKey),
        ("sshexe = C:\\ssh.exe", Problem::UnknownKey),
        ("key = D:\\GoyoVault\\vault.goyokey", Problem::UnknownKey),
        ("just text", Problem::NoEquals),
        (
            "python = python3
python = python3",
            Problem::Duplicate,
        ),
        ("interval = 5", Problem::Interval),
        ("interval = 3601", Problem::Interval),
        ("interval = 60s", Problem::Interval),
        ("interval = -60", Problem::Interval),
        ("timeout = 29", Problem::Timeout),
        ("timeout = 601", Problem::Timeout),
        ("vault = vault.goyo", Problem::Vault),
        ("vault = D:vault.goyo", Problem::Vault),
        ("vault = \\GoyoVault\\vault.goyo", Problem::Vault),
        ("vault = \\\\?\\D:\\GoyoVault\\vault.goyo", Problem::Vault),
        ("vault = D:\\GoyoVault\\..\\vault.goyo", Problem::Vault),
        ("vault = D:\\GoyoVault\\vault.goyo:stream", Problem::Vault),
        ("vault = \"D:\\GoyoVault\\vault.goyo\"", Problem::Vault),
        ("vault = D:\\GoyoVault\\*.goyo", Problem::Vault),
        ("vault = D:\\GoyoVault\\vault.goyokey", Problem::KeyFile),
        ("vault = D:\\GoyoVault\\VAULT.GOYOKEY", Problem::KeyFile),
        ("vault = D:\\GoyoVault\\vault.goyokey.", Problem::KeyFile),
        ("vault = D:\\GoyoVault\\vault.goyokey. .", Problem::KeyFile),
        ("vault = d:\\goyovault\\VAULT.goyo", Problem::DuplicateVault),
    ];
    for (line, problem) in rejected {
        let e = parse_with(line).unwrap_err();
        let at = if *problem == Problem::Duplicate { 3 } else { 2 };
        assert_eq!((e.problem, e.line), (*problem, at), "{line}");
    }
    // A goyokey identity is refused even when the file exists.
    let key = t.0.join("vault.goyokey");
    fs::write(&key, b"x").unwrap();
    let e = parse_with(&format!("identity = {}", key.display())).unwrap_err();
    assert_eq!(e.problem, Problem::Identity);
    // A ninth vault line.
    let nine = format!("host = my-server\n{eight}vault = D:\\v9\\vault.goyo\n");
    let e = config::parse(&nine).unwrap_err();
    assert_eq!((e.problem, e.line), (Problem::TooManyVaults, 10));
    assert_eq!(e.vaults.len(), 8);
    // Whole-file problems, and the valid vault lines kept for state=config.
    assert_eq!(
        config::parse("vault = D:\\v\\vault.goyo")
            .unwrap_err()
            .problem,
        Problem::NoHost
    );
    assert_eq!(
        config::parse("host = my-server").unwrap_err().problem,
        Problem::NoVault
    );
    let e =
        config::parse("vault = D:\\v\\vault.goyo\nhost = a b\nvault = D:\\w\\x.goyo").unwrap_err();
    assert_eq!((e.problem, e.line), (Problem::Host, 2));
    assert_eq!(
        e.vaults,
        [
            PathBuf::from(r"D:\v\vault.goyo"),
            PathBuf::from(r"D:\w\x.goyo")
        ]
    );
    // Files: missing, too large, not UTF-8.
    let file = t.0.join(CONFIG);
    assert_eq!(config::load(&file).unwrap_err().problem, Problem::Missing);
    fs::write(&file, vec![b'#'; MAX_CONFIG + 1]).unwrap();
    assert_eq!(config::load(&file).unwrap_err().problem, Problem::TooLarge);
    fs::write(&file, b"host = my-server\nvault = D:\\\xff.goyo\n").unwrap();
    assert_eq!(config::load(&file).unwrap_err().problem, Problem::NotUtf8);
    fs::write(&file, include_bytes!("../../../goyo-sync.conf.example")).unwrap();
    assert_eq!(config::load(&file).unwrap(), example);
}

/// A key-file vault line is a settings error (exit 2); the valid vault
/// lines' folders show state=config, and nothing is created anywhere.
#[test]
fn bad_settings_exit_2_and_mark_valid_folders() {
    let pc = Pc::with_folder();
    let log = Log::new(Some(pc.t.0.join(LOG)));
    let text = format!(
        "host = my-server\nvault = {}\nvault = {}\n",
        pc.vault.display(),
        pc.key.display()
    );
    fs::write(pc.t.0.join(CONFIG), text).unwrap();
    assert_eq!(load_config(&pc.t.0, &log, false, false), Err(CONFIG_ERROR));
    assert!(fs::read_dir(&pc.dir).unwrap().next().is_none(), "read-only");
    assert_eq!(load_config(&pc.t.0, &log, false, true), Err(CONFIG_ERROR));
    assert_eq!(pc.status().state, Some(SyncState::Config));
    assert!(!pc.t.0.join("vault.goyokey.sync").exists());
    assert!(
        pc.log()
            .contains("state=config: goyo-sync.conf line 3 KeyFile")
    );
    // Missing settings are exit 2 as well.
    fs::remove_file(pc.t.0.join(CONFIG)).unwrap();
    assert_eq!(load_config(&pc.t.0, &log, false, false), Err(CONFIG_ERROR));
    // The example is accepted.
    fs::write(
        pc.t.0.join(CONFIG),
        include_bytes!("../../../goyo-sync.conf.example"),
    )
    .unwrap();
    assert!(load_config(&pc.t.0, &log, false, false).is_ok());
}

// ---- 18: the ssh command line ----

#[test]
fn ssh_argv_is_exact() {
    let mut c = config::parse(include_str!("../../../goyo-sync.conf.example")).unwrap();
    // Each call's own log file (see ssh_log_is_fresh_bounded_and_removed).
    let log = Path::new(r"D:\GoyoVault\goyo-sync.ssh-1a2b-17f00d-0.log");
    let want: Vec<&str> = vec![
        "-T",
        "-x",
        "-a",
        "-e",
        "none",
        "-E",
        r"D:\GoyoVault\goyo-sync.ssh-1a2b-17f00d-0.log",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ConnectTimeout=20",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "RequestTTY=no",
        "-o",
        "LogLevel=ERROR",
        "--",
        "my-server",
        "python3",
        "-I",
        ".local/share/goyo-sync/goyo-sync-server.py",
        "serve",
    ];
    assert_eq!(
        ssh_args(&c, log),
        want.iter().map(OsString::from).collect::<Vec<_>>()
    );
    // An identity goes before "--", with IdentitiesOnly.
    c.identity = Some(PathBuf::from(r"C:\Users\<you>\.ssh\goyo sync"));
    let mut with_key = want.clone();
    let at = with_key.iter().position(|a| *a == "--").unwrap();
    with_key.splice(
        at..at,
        [
            "-i",
            r"C:\Users\<you>\.ssh\goyo sync",
            "-o",
            "IdentitiesOnly=yes",
        ],
    );
    assert_eq!(
        ssh_args(&c, log),
        with_key.iter().map(OsString::from).collect::<Vec<_>>()
    );
    // The program is System32's, from the OS, never from PATH.
    assert_eq!(
        ssh_program(Path::new(r"C:\Windows\System32")),
        PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe")
    );
    let system = sys::system_dir().unwrap();
    assert!(system.is_absolute());
    assert!(system.ends_with("System32") || system.ends_with("system32"));
    let t = cli_transport(&c);
    assert_eq!(t.program(), Some(ssh_program(&system).as_path()));
}

/// Each ssh call gets a log file of its own (`-E`), made new beside the exe
/// (else in %TEMP%) and named without an RNG. What ssh appends is read back
/// bounded, never through a link or another name of a file, and the file is
/// removed after the call. Logs a killed helper left are swept once they are
/// an hour old.
#[test]
fn ssh_log_is_fresh_bounded_and_removed() {
    let t = Temp::new("sshlog");
    let dir = [t.0.clone()];
    let (a, b) = (SshLog::create(&dir).unwrap(), SshLog::create(&dir).unwrap());
    assert_ne!(a.path(), b.path());
    for log in [&a, &b] {
        assert_eq!(log.path().parent(), Some(t.0.as_path()));
        let name = log.path().file_name().unwrap().to_str().unwrap();
        let [prefix, suffix] = SSH_LOG;
        let middle = name.strip_prefix(prefix).unwrap().strip_suffix(suffix);
        let parts: Vec<&str> = middle.unwrap().split('-').collect();
        assert_eq!(parts.len(), 3, "{name}");
        assert_eq!(parts[0], format!("{:x}", std::process::id()));
        let hex = |p: &&str| !p.is_empty() && p.bytes().all(|c| c.is_ascii_hexdigit());
        assert!(parts.iter().all(hex), "{name}");
        assert_eq!(fs::metadata(log.path()).unwrap().len(), 0);
        assert!(log.read().is_empty());
    }
    // In the argv right after "-E", among ssh's options.
    let c = config::parse(include_str!("../../../goyo-sync.conf.example")).unwrap();
    let args = ssh_args(&c, a.path());
    let at = args.iter().position(|x| x == "-E").unwrap();
    assert_eq!(Path::new(&args[at + 1]), a.path());
    assert!(at < args.iter().position(|x| x == "--").unwrap());
    // ssh appends its messages; the first MAX_STDERR bytes are kept.
    let text = format!(
        "Host key verification failed.\r\n{}",
        "x".repeat(MAX_STDERR)
    );
    fs::OpenOptions::new()
        .append(true)
        .open(a.path())
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    assert_eq!(a.read(), text.as_bytes()[..MAX_STDERR]);
    let path = a.path().to_path_buf();
    drop(a);
    assert!(!path.exists());
    // Another name of some file, or a junction, put at the name is not read.
    let other = t.0.join("other.txt");
    fs::write(&other, b"Permission denied").unwrap();
    fs::remove_file(b.path()).unwrap();
    fs::hard_link(&other, b.path()).unwrap();
    assert!(b.read().is_empty());
    drop(b);
    assert_eq!(fs::read(&other).unwrap(), b"Permission denied");
    // A folder that takes no file (here one that is not there) passes the
    // log to the next: a read-only exe folder does not stop syncing.
    let missing = t.0.join("missing");
    assert!(SshLog::create(std::slice::from_ref(&missing)).is_none());
    let next = SshLog::create(&[missing.clone(), t.0.clone()]).unwrap();
    assert_eq!(next.path().parent(), Some(t.0.as_path()));
    assert!(!missing.exists());
    drop(next);
    let c = SshLog::create(&dir).unwrap();
    fs::remove_file(c.path()).unwrap();
    junction(c.path(), &t.0);
    assert!(c.read().is_empty());
    let path = c.path().to_path_buf();
    drop(c);
    fs::remove_dir(&path).unwrap();
    // Swept: own names only, plain files only, an hour old only.
    let now = SystemTime::now();
    let old = now - STALE_LOG;
    let make = |name: &str, at: SystemTime| {
        let p = t.0.join(name);
        fs::File::create(&p).unwrap().set_modified(at).unwrap();
        p
    };
    let stale = make("goyo-sync.ssh-1-2-3.log", old);
    let fresh = make("goyo-sync.ssh-1-2-4.log", now);
    let kept = [
        make("goyo-sync.log", old),
        make("goyo-sync.ssh-1-2-5.txt", old),
        make("vault.goyo", old),
    ];
    fs::create_dir(t.0.join("goyo-sync.ssh-1-2-6.log")).unwrap();
    assert_eq!(sweep_logs(&t.0, now), 1);
    assert!(!stale.exists() && fresh.exists());
    assert!(kept.iter().all(|p| p.exists()) && other.exists());
    assert_eq!(sweep_logs(&t.0, now + STALE_LOG), 1);
    assert!(!fresh.exists() && t.0.join("goyo-sync.ssh-1-2-6.log").is_dir());
}

// ---- 19: bounded child processes ----

/// `python` as the tests start it outside the bounded runner: with
/// CREATE_NO_WINDOW, as run_bounded starts every child. This binary is a
/// windows-subsystem program, so it has no console of its own, and a
/// console program it starts without that flag gets a new console window
/// each time; while the GUI tests make their windows, Windows sometimes
/// fails to set one up and the child dies in its start-up with
/// STATUS_DLL_INIT_FAILED (0xC0000142), printing nothing.
fn python_command() -> Command {
    use std::os::windows::process::CommandExt;
    let mut c = Command::new("python");
    c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    c
}
/// Whether python can run the server script; panics if not, unless
/// GOYO_SYNC_SKIP_PYTHON=1. Only a python that is not found counts as
/// missing; one that does not run says what Windows or python reported.
pub(crate) fn python() -> bool {
    match python_command().arg("--version").output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => panic!(
            "`python --version` exited with {:?} (code {:#x}): {}",
            o.status,
            o.status.code().unwrap_or(0) as u32,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if std::env::var("GOYO_SYNC_SKIP_PYTHON").as_deref() == Ok("1") {
                return false;
            }
            panic!("python is needed for these tests; set GOYO_SYNC_SKIP_PYTHON=1 to skip them");
        }
        Err(e) => panic!("`python --version` did not start: {e} ({e:?})"),
    }
}
fn py(code: &str) -> Command {
    let mut c = Command::new("python");
    c.args(["-c", code]);
    c
}
fn no_stop(d: Duration) -> bool {
    std::thread::sleep(d);
    false
}
#[test]
fn run_bounded_feeds_caps_and_kills() {
    if !python() {
        return;
    }
    let long = Duration::from_secs(60);
    // 8 MiB in and out at once: stdin is fed by its own thread.
    let input: Vec<u8> = (0..8u32 << 20).map(|i| (i % 251) as u8).collect();
    let echo = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())";
    let out = run_bounded(py(echo), &input, long, &mut no_stop).unwrap();
    assert!(out.stdout == input && out.killed.is_none() && out.code == Some(0));

    // More stdout than any response: killed and reported as `server`.
    let flood = "import sys; sys.stdout.buffer.write(b'x' * (9 << 20))";
    let out = run_bounded(py(flood), b"", long, &mut no_stop).unwrap();
    assert_eq!(out.killed, Some(Killed::Overflow));
    assert!(out.stdout.len() <= MAX_STDOUT);
    assert_eq!(classify(&out), SyncState::Server);

    // A child that never answers is killed at the timeout.
    let started = Instant::now();
    let sleep = "import time; time.sleep(60)";
    let out = run_bounded(py(sleep), b"", Duration::from_secs(1), &mut no_stop).unwrap();
    assert_eq!(out.killed, Some(Killed::Timeout));
    assert!(started.elapsed() < Duration::from_secs(15));
    assert_eq!(classify(&out), SyncState::Offline);

    // A stop request kills it at once.
    let started = Instant::now();
    let out = run_bounded(py(sleep), b"", long, &mut |_| true).unwrap();
    assert_eq!(out.killed, Some(Killed::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(15));

    // stderr is capped; stdout still arrives whole.
    let noisy = "import sys; sys.stderr.write('e' * 100000); sys.stdout.write('ok')";
    let out = run_bounded(py(noisy), b"", long, &mut no_stop).unwrap();
    assert_eq!(
        (out.stdout.as_slice(), out.stderr.len()),
        (&b"ok"[..], MAX_STDERR)
    );

    // Whatever the child started dies with the job, so the readers are not
    // held open by a grandchild that inherited the pipes.
    let started = Instant::now();
    let spawner = "import subprocess, sys; \
         subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); \
         print('started')";
    let out = run_bounded(py(spawner), b"", long, &mut no_stop).unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("started"));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );

    // A program that does not exist.
    let missing = Command::new(r"C:\goyo-sync-missing\no-such-program.exe");
    assert_eq!(
        run_bounded(missing, b"", long, &mut no_stop).err(),
        Some(Failure::Missing)
    );
}

#[test]
fn failures_are_classified() {
    // What ssh wrote to its own log (`-E`); stderr stays empty then.
    let out = |log: &str, killed| Output {
        stdout: Vec::new(),
        stderr: Vec::new(),
        log: log.as_bytes().to_vec(),
        code: Some(255),
        killed,
    };
    // The same words on stderr only: the remote side printed them.
    let remote = |stderr: &str| Output {
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        log: Vec::new(),
        code: Some(255),
        killed: None,
    };
    let cases = [
        ("Host key verification failed.", SyncState::HostKey),
        (
            "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@",
            SyncState::HostKey,
        ),
        (
            "<user>@my-server: Permission denied (publickey).",
            SyncState::Auth,
        ),
        (
            "ssh: Could not resolve hostname my-server: No such host is known.",
            SyncState::Offline,
        ),
        (
            "ssh: connect to host my-server port 22: Connection timed out",
            SyncState::Offline,
        ),
        (
            "ssh: connect to host my-server port 22: Connection refused",
            SyncState::Offline,
        ),
        ("connect: Network is unreachable", SyncState::Offline),
        ("connect: No route to host", SyncState::Offline),
        ("bash: python3: command not found", SyncState::Server),
        ("", SyncState::Server),
    ];
    for (text, state) in cases {
        assert_eq!(classify(&out(text, None)), state, "{text}");
        // A server that prints ssh's words and exits 255 is only a server
        // problem: no host key alarm, no 15-minute wait.
        assert_eq!(classify(&remote(text)), SyncState::Server, "{text}");
    }
    // ssh's log as OpenSSH 9.5p2 wrote it against a throwaway listener on
    // this PC (paths, names and the fingerprint replaced). A changed host key
    // takes many lines; the alarm stands.
    let changed = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
        @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n\
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n\
        IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n\
        Someone could be eavesdropping on you right now (man-in-the-middle attack)!\r\n\
        It is also possible that a host key has just been changed.\r\n\
        The fingerprint for the ECDSA key sent by the remote host is\nSHA256:<fingerprint>.\r\n\
        Please contact your system administrator.\r\n\
        Add correct host key in C:\\\\Users\\\\<user>\\\\.ssh\\\\known_hosts to get rid of this message.\r\n\
        Offending ECDSA key in C:\\\\Users\\\\<user>\\\\.ssh\\\\known_hosts:1\r\n\
        Host key for my-server has changed and you have requested strict checking.\r\n\
        Host key verification failed.\r\n";
    assert_eq!(classify(&out(changed, None)), SyncState::HostKey);
    // Three of its messages quote what the other end sent, line breaks
    // included: the version line and a disconnect's reason, which anyone
    // answering the connection can send before any host key check, and the
    // login methods the server lists. None of that raises an alarm; a
    // refused login stays only that.
    let quoted = [
        (
            "Bad remote protocol version identification: \
             'SSH-Host key verification failed. Permission denied (publickey).'\r\n",
            SyncState::Server,
        ),
        (
            "Received disconnect from 192.0.2.1 port 22:2: bye\r\n\
             Host key verification failed.\r\n\
             <user>@my-server: Permission denied (publickey).\r\n",
            SyncState::Server,
        ),
        (
            "Received disconnect from 192.0.2.1 port 22:2: \
             ssh: Could not resolve hostname my-server\r\n",
            SyncState::Server,
        ),
        (
            "<user>@my-server: Permission denied (publickey\r\n\
             Host key verification failed.\r\n\
             x).\r\n",
            SyncState::Auth,
        ),
    ];
    for (text, state) in quoted {
        assert_eq!(classify(&out(text, None)), state, "{text}");
    }
    assert_eq!(
        classify(&out("", Some(Killed::Timeout))),
        SyncState::Offline
    );
    assert_eq!(
        classify(&out("Permission denied", Some(Killed::Overflow))),
        SyncState::Server
    );
    // A valid frame wins over ssh's log, stderr and the exit code.
    let mut mock = Mock::with([Ok(Output {
        stdout: [
            b"banner from a login shell\n".as_slice(),
            &Response::new(Status::Ok, 1, &syncwire::HELLO_ECHO).encode(),
        ]
        .concat(),
        stderr: b"Permission denied".to_vec(),
        log: b"Permission denied".to_vec(),
        code: Some(255),
        killed: Some(Killed::Timeout),
    })]);
    let hello = call(&mut mock, &Request::hello(), "test", &Log::new(None)).unwrap();
    assert_eq!(
        (hello.status, hello.blob()),
        (Status::Ok, &syncwire::HELLO_ECHO[..])
    );
    // A damaged echo is a protocol error.
    let mut echo = syncwire::HELLO_ECHO;
    echo[13] = b'\n';
    let mut mock = Mock::with([reply(Status::Ok, 1, &echo)]);
    assert!(matches!(
        call(&mut mock, &Request::hello(), "test", &Log::new(None)),
        Err(CallError::Failed(SyncState::Server, _))
    ));
    let mut mock = Mock::with([Err(Failure::Missing)]);
    assert!(matches!(
        call(&mut mock, &Request::hello(), "test", &Log::new(None)),
        Err(CallError::Failed(SyncState::NoSsh, _))
    ));
    // The CLI detail: ssh's own line, else the stderr line marked as such.
    let hostkey = "Host key verification failed.";
    let mut mock = Mock::with([ssh_error(hostkey), remote_error(hostkey)]);
    let mut details = Vec::new();
    for _ in 0..2 {
        if let Err(CallError::Failed(state, detail)) =
            call(&mut mock, &Request::hello(), "test", &Log::new(None))
        {
            details.push((state, detail));
        }
    }
    assert_eq!(
        details,
        [
            (SyncState::HostKey, hostkey.to_string()),
            (SyncState::Server, format!("stderr: {hostkey}"))
        ]
    );
    // The log gets one printable line.
    assert_eq!(
        first_line(b"\r\n\x1b[31mssh: bad\x07 thing\r\nsecond line"),
        "[31mssh: bad thing"
    );
    assert_eq!(first_line(&[b'a'; 500]).len(), 200);
    assert_eq!(first_line(b""), "");
}

// ---- 20: the pass state machine ----

#[test]
fn put_ok_writes_incoming_and_done() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x11; 16];
    let v1 = blob(&id, 1);
    let fsha = pc.outgoing(0, &v1);
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 1, b"")]), &clock);
    assert!(e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    let call = &e.transport.calls[0];
    assert_eq!((call.op, call.version, &call.blob), (Op::Put, 0, &v1));
    assert_eq!(call.sha, sha256(&v1));
    assert_eq!(pc.incoming(), Some((1, v1.clone())));
    let state = pc.state();
    assert_eq!(state.id, Some(id));
    assert_eq!((state.server, state.head), (1, Some(sha256(&v1))));
    assert_eq!((state.done, state.rejected), (Some(fsha), None));
    let status = pc.status();
    assert_eq!(status.state, Some(SyncState::Ok));
    assert_eq!((status.heartbeat, status.contact), (START, START));
    assert!(pc.log().contains("pinned this vault ID"));
    assert!(pc.log().contains("1111-1111 PUT OK v=1 out=160"));
    // Nothing is due until the heartbeat; then a pass makes no call.
    assert!(!e.due(0));
    clock.advance(HEARTBEAT);
    assert!(e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, None, None));
    assert_eq!(e.transport.calls.len(), 1);
    assert_eq!(pc.status().heartbeat, START + HEARTBEAT);
    // The poll asks with the version and SHA already held.
    clock.advance(10);
    assert!(e.due(0));
    e.transport
        .replies
        .push_back(reply(Status::NotModified, 1, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, None, None));
    let get = &e.transport.calls[1];
    assert_eq!((get.op, get.version, get.sha), (Op::Get, 1, sha256(&v1)));
    assert_eq!(pc.status().contact, START + HEARTBEAT + 10);
    // Old temp files of this helper are cleaned up; the app's are not.
    for name in [
        "incoming.goyosync.1-2-3.goyotmp",
        "outgoing.goyosync.1-2-3.goyotmp",
    ] {
        fs::write(pc.dir.join(name), b"x").unwrap();
    }
    clock.advance(HEARTBEAT);
    e.pass(0, false);
    assert!(!pc.dir.join("incoming.goyosync.1-2-3.goyotmp").exists());
    assert!(pc.dir.join("outgoing.goyosync.1-2-3.goyotmp").exists());
}

/// Deleting the sync folder resets the helper for that vault, also while it
/// runs: a new vault created at the same path is pinned and uploaded instead
/// of being refused as "a file of another vault" forever.
#[test]
fn a_recreated_folder_pins_again() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let (old, new) = ([0x11; 16], [0x22; 16]);
    pc.outgoing(0, &blob(&old, 1));
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 1, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(pc.state().id, Some(old));
    // Same path, another vault: refused while the old pin stands.
    pc.outgoing(0, &blob(&new, 2));
    clock.advance(HEARTBEAT);
    e.transport
        .replies
        .push_back(reply(Status::NotModified, 1, b""));
    e.pass(0, true);
    assert_eq!(e.transport.ops(), [(Op::Put, 0), (Op::Get, 1)]);
    assert!(pc.log().contains("a file of another vault"));
    // The user deletes the folder; the helper makes it again, unpinned,
    // and the app's next outgoing pins the new vault.
    fs::remove_dir_all(&pc.dir).unwrap();
    clock.advance(HEARTBEAT);
    e.pass(0, true);
    assert!(pc.dir.is_dir() && pc.incoming().is_none());
    let v1 = blob(&new, 3);
    pc.outgoing(0, &v1);
    clock.advance(HEARTBEAT);
    e.transport.replies.push_back(reply(Status::Ok, 1, b""));
    assert_eq!(e.pass(0, true), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(pc.state().id, Some(new));
    assert_eq!(pc.incoming(), Some((1, v1)));
}

#[test]
fn conflict_with_our_own_blob_counts_as_landed() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x22; 16];
    let v3 = blob(&id, 3);
    let fsha = pc.outgoing(2, &v3);
    // An earlier PUT committed version 3, but its OK never arrived.
    let mut e = pc.engine(Mock::with([reply(Status::Conflict, 3, &v3)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 3, Some(3), None));
    assert_eq!(e.transport.ops(), [(Op::Put, 2)]);
    assert_eq!(pc.incoming(), Some((3, v3)));
    assert_eq!(pc.state().done, Some(fsha));
    assert!(pc.log().contains("already on the server"));
}

#[test]
fn conflict_with_another_head_ends_the_outgoing() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x33; 16];
    let (ours, theirs) = (blob(&id, 1), blob(&id, 2));
    let fsha = pc.outgoing(3, &ours);
    let mut e = pc.engine(Mock::with([reply(Status::Conflict, 4, &theirs)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 4, None, Some(4)));
    assert_eq!(pc.incoming(), Some((4, theirs.clone())));
    assert_eq!(pc.state().done, Some(fsha));
    assert!(pc.log().contains("upload lost to server version 4"));
    // The dead file is not sent again; the next poll asks for news only.
    clock.advance(HEARTBEAT);
    e.pass(0, false);
    assert_eq!(e.transport.calls.len(), 1);
    clock.advance(10);
    e.transport
        .replies
        .push_back(reply(Status::NotModified, 4, b""));
    e.pass(0, false);
    assert_eq!(e.transport.ops(), [(Op::Put, 3), (Op::Get, 4)]);
    // A CONFLICT showing the head already in incoming rewrites nothing.
    let before = syncfile::stamp(&pc.dir, INCOMING);
    pc.outgoing(3, &blob(&id, 9));
    e.transport
        .replies
        .push_back(reply(Status::Conflict, 4, &theirs));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 4, None, None));
    assert_eq!(syncfile::stamp(&pc.dir, INCOMING), before);
}

/// A server that keeps this PC's uploads out while it shows a head the app
/// has merged: a CONFLICT naming the very version the upload expected, or
/// the copy already held under a new number, is no honest answer. It is a
/// server fault with a backoff. The head is not queued (the open app would
/// merge and upload again at once) and the file is not done, and the new
/// outgoing the app writes at each unlock waits for the backoff instead of
/// telling the server when the vault was opened.
#[test]
fn a_server_holding_back_uploads_is_a_server_fault() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x3C; 16];
    let held = blob(&id, 4);
    seed_incoming(&pc, id, 4, &held);
    let before = syncfile::stamp(&pc.dir, INCOMING);
    pc.outgoing(4, &blob(&id, 5));
    let mut e = pc.engine(Mock::with([reply(Status::Conflict, 4, &held)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
    assert_eq!(e.transport.ops(), [(Op::Put, 4)]);
    assert_eq!(pc.state().done, None);
    assert_eq!(pc.status().state, Some(SyncState::Server));
    assert_eq!(syncfile::stamp(&pc.dir, INCOMING), before);
    assert!(pc.log().contains(
        "3C3C-3C3C server answered CONFLICT although its head is version 4, \
         the one this upload expected: it is holding back uploads"
    ));
    assert!(pc.log().contains("retry in 30 s"));
    // Three unlocks, three new files: none is sent in the backoff.
    for fill in 6..9 {
        clock.advance(9);
        pc.outgoing(4, &blob(&id, fill));
        assert!(!e.due(0));
    }
    clock.advance(2);
    assert!(!e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
    assert_eq!(e.transport.calls.len(), 1);
    // After it, the newest file is tried once. The held copy again, under
    // a new number: the same fault, and incoming stays as it is.
    clock.advance(1);
    assert!(e.due(0));
    e.transport
        .replies
        .push_back(reply(Status::Conflict, 9, &held));
    assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
    assert_eq!(e.transport.ops(), [(Op::Put, 4), (Op::Put, 4)]);
    assert_eq!(e.transport.calls[1].blob, blob(&id, 8));
    assert_eq!(pc.incoming(), Some((4, held.clone())));
    assert_eq!(pc.state().done, None);
    assert!(pc.log().contains(
        "server answered CONFLICT although its head is the copy already held as version 4, \
         numbered 9"
    ));
    assert!(pc.log().contains("retry in 60 s"));
    pc.outgoing(4, &blob(&id, 9));
    clock.advance(19);
    assert!(!e.due(0));
    assert_eq!(e.transport.calls.len(), 2);
    // Any other head under the expected version is the same fault.
    clock.advance(41);
    assert!(e.due(0));
    e.transport
        .replies
        .push_back(reply(Status::Conflict, 4, &blob(&id, 0xEE)));
    assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
    assert_eq!(pc.incoming(), Some((4, held)));
    // Once the server takes an upload, a new file after an ordinary failure
    // gets its one attempt in the backoff again.
    clock.advance(120);
    e.transport.replies.push_back(reply(Status::Ok, 5, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, Some(5), None));
    pc.outgoing(5, &blob(&id, 10));
    let timed_out = "ssh: connect to host my-server port 22: Connection timed out";
    e.transport.replies.push_back(ssh_error(timed_out));
    assert_eq!(e.pass(0, false), done(SyncState::Offline, 5, None, None));
    pc.outgoing(5, &blob(&id, 11));
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 6, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 6, Some(6), None));
}

/// The honest CONFLICTs that show a head this PC already holds still end
/// the upload: a file made before the app merged the held head, and the
/// held copy re-seeded as version 1 by another PC after a wipe.
#[test]
fn honest_conflicts_with_the_held_copy_end_the_outgoing() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x3D; 16];
    let held = blob(&id, 5);
    seed_incoming(&pc, id, 5, &held);
    // Made from version 4, before the app merged version 5.
    let old = pc.outgoing(4, &blob(&id, 1));
    let mut e = pc.engine(Mock::with([reply(Status::Conflict, 5, &held)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, None, None));
    assert_eq!(pc.state().done, Some(old));
    // The server was wiped and another PC put the same copy back.
    let fsha = pc.outgoing(5, &blob(&id, 2));
    e.transport
        .replies
        .push_back(reply(Status::Conflict, 1, &held));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, None, Some(1)));
    assert_eq!(pc.incoming(), Some((1, held)));
    assert_eq!(pc.state().done, Some(fsha));
    assert!(pc.log().contains("server version went back 5->1"));
    assert!(!pc.log().contains("holding back"));
    // The app's file made from version 1 lands.
    pc.outgoing(1, &blob(&id, 3));
    e.transport.replies.push_back(reply(Status::Ok, 2, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 2, Some(2), None));
}

/// A server, or the remote account's shell files, that prints ssh's own
/// alarms on stderr and exits 255 gets state=server and the ordinary
/// backoff: never the host key or login alarm, or their 15-minute wait.
#[test]
fn a_server_cannot_raise_the_ssh_alarms() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x3E; 16];
    pc.outgoing(0, &blob(&id, 1));
    let fake = "Host key verification failed.\r\n\
                @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@";
    let mut e = pc.engine(Mock::with([remote_error(fake)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Server, 0, None, None));
    assert_eq!(pc.status().state, Some(SyncState::Server));
    assert!(pc.log().contains("PUT failed state=server"));
    assert!(pc.log().contains("ssh= err=Host key verification failed."));
    assert!(pc.log().contains("retry in 30 s"));
    clock.advance(30);
    let denied = "<user>@my-server: Permission denied (publickey).";
    e.transport.replies.push_back(remote_error(denied));
    assert_eq!(e.pass(0, false), done(SyncState::Server, 0, None, None));
    assert!(pc.log().contains("retry in 60 s"));
    // ssh's own log saying it is the real alarm.
    clock.advance(60);
    e.transport
        .replies
        .push_back(ssh_error("Host key verification failed."));
    assert_eq!(e.pass(0, false), done(SyncState::HostKey, 0, None, None));
    assert!(pc.log().contains("ssh=Host key verification failed. err="));
    assert!(pc.log().contains(&format!("retry in {MAX_BACKOFF} s")));
}

#[test]
fn empty_put_seeds_again_from_zero() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x44; 16];
    let v = blob(&id, 4);
    pc.outgoing(5, &v);
    let replies = [reply(Status::Empty, 0, b""), reply(Status::Ok, 1, b"")];
    let mut e = pc.engine(Mock::with(replies), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(e.transport.ops(), [(Op::Put, 5), (Op::Put, 0)]);
    assert_eq!(pc.incoming(), Some((1, v)));
}

/// Writes incoming and a matching helper.state, as after a pull of
/// `version`.
fn seed_incoming(pc: &Pc, id: [u8; 16], version: u64, vault: &[u8]) {
    let bytes = render_incoming(version, vault).unwrap();
    replace_file(&pc.dir.join(INCOMING), &bytes).unwrap();
    let state = HelperState {
        id: Some(id),
        server: version,
        head: Some(sha256(vault)),
        ..HelperState::default()
    };
    replace_file(
        &pc.dir.join(HELPER_STATE),
        &syncfile::render_helper_state(&state),
    )
    .unwrap();
}
#[test]
fn get_empty_reseeds_from_incoming() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x55; 16];
    let v = blob(&id, 5);
    seed_incoming(&pc, id, 3, &v);
    let replies = [reply(Status::Empty, 0, b""), reply(Status::Ok, 1, b"")];
    let mut e = pc.engine(Mock::with(replies), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    let calls = &e.transport.calls;
    assert_eq!(
        (calls[0].op, calls[0].version, calls[0].sha),
        (Op::Get, 3, sha256(&v))
    );
    assert_eq!(
        (calls[1].op, calls[1].version, &calls[1].blob),
        (Op::Put, 0, &v)
    );
    assert_eq!(pc.incoming(), Some((1, v)));
    assert!(
        pc.log()
            .contains("server was empty; re-uploaded the last known copy")
    );
    // Without an incoming there is nothing to re-seed from.
    let pc = Pc::with_folder();
    pc.outgoing(0, &blob(&id, 6));
    let replies = [reply(Status::BadBlob, 0, b""), reply(Status::Empty, 0, b"")];
    let mut e = pc.engine(Mock::with(replies), &clock);
    e.pass(0, false);
    clock.advance(60);
    e.pass(0, false);
    assert_eq!(e.transport.ops(), [(Op::Put, 0), (Op::Get, 0)]);
}

#[test]
fn rejected_outgoing_waits_for_a_new_one() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x66; 16];
    let fsha = pc.outgoing(0, &blob(&id, 1));
    let mut e = pc.engine(Mock::with([reply(Status::Limit, 0, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Refused, 0, None, None));
    assert_eq!(pc.state().rejected, Some(fsha));
    assert_eq!(pc.status().state, Some(SyncState::Refused));
    // Polls go on, the refused file is not sent again, the state stays.
    for _ in 0..3 {
        clock.advance(60);
        assert!(e.due(0));
        e.transport.replies.push_back(reply(Status::Empty, 0, b""));
        assert_eq!(e.pass(0, false), done(SyncState::Refused, 0, None, None));
    }
    assert_eq!(
        e.transport.ops(),
        [(Op::Put, 0), (Op::Get, 0), (Op::Get, 0), (Op::Get, 0)]
    );
    // A new file from the app is sent at once.
    clock.advance(1);
    pc.outgoing(0, &blob(&id, 2));
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 1, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(pc.status().state, Some(SyncState::Ok));
}

/// GOYOVA04, the format under a KF2 key file, passes the gate and incoming
/// like GOYOVA02, each from its smallest file up; every other format and
/// every key file is refused, wrapped or not (spec §7.6, §14.7-1/2).
#[test]
fn goyova04_passes_the_gate_and_incoming_like_goyova02() {
    let pc = Pc::with_folder();
    let id = [0x6D; 16];
    let path = pc.dir.join(OUTGOING);
    for v in [blob(&id, 1), keyed(&id, 1)] {
        fs::write(&path, render_outgoing(0, &v).unwrap()).unwrap();
        let ok = matches!(gate(&path, Some(&id)), Gate::Ok(g) if g.bytes[16..] == v[..]);
        assert!(ok, "{:?}", &v[..8]);
    }
    let wrapped = |magic: &[u8; 8], len: usize| {
        let mut v = blob(&id, 2);
        v.resize(len, 2);
        v[..8].copy_from_slice(magic);
        [&b"GOYOSOU1"[..], &0u64.to_le_bytes(), &v].concat()
    };
    for (magic, len) in [
        (b"GOYOVA01", 160),
        (b"GOYOVA03", 160),
        (b"GOYOVA05", 160),
        (b"GOYOVA04", 139),
        (b"GOYOKE01", 148),
        (b"GOYOKE02", 128),
        (b"GOYOKE03", 312),
        (b"GOYOKH01", 489),
        (b"GOYOKS01", 489),
    ] {
        fs::write(&path, wrapped(magic, len)).unwrap();
        let refused = matches!(
            gate(&path, Some(&id)),
            Gate::Refused(Refusal::Format, Some(_))
        );
        assert!(refused, "{magic:?} {len}");
    }
    fs::remove_file(&path).unwrap();
    // Incoming is read back with its version, SHA and ID, and a GOYOVA04
    // copy re-seeds a wiped server.
    let v = keyed(&id, 3);
    seed_incoming(&pc, id, 7, &v);
    assert_eq!(
        engine::from_incoming(&pc.dir),
        (7, Some(sha256(&v)), Some(id))
    );
    let clock = TestClock::new();
    let replies = [reply(Status::Empty, 0, b""), reply(Status::Ok, 1, b"")];
    let mut e = pc.engine(Mock::with(replies), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(
        (e.transport.calls[1].op, &e.transport.calls[1].blob),
        (Op::Put, &v)
    );
    assert_eq!(pc.incoming(), Some((1, v.clone())));
    // A re-seed that a script older than 0.9.0 refuses shows `oldserver`.
    seed_incoming(&pc, id, 7, &v);
    let replies = [reply(Status::Empty, 0, b""), reply(Status::BadBlob, 0, b"")];
    let mut e = pc.engine(Mock::with(replies), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::OldServer, 7, None, None));
}

/// A server script older than 0.9.0 answers a GOYOVA04 upload with
/// BAD_BLOB. That is no refusal of the file: the helper shows `oldserver`,
/// keeps polling, and sends the same file again after ten minutes and
/// whenever it starts, and a new file from the app at once. A GOYOVA02
/// BAD_BLOB stays a refusal (spec §7.6, §7.7-8, §14.7-3).
#[test]
fn an_old_server_script_holds_goyova04_uploads() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x6A; 16];
    let v = keyed(&id, 1);
    let fsha = pc.outgoing(0, &v);
    let mut e = pc.engine(Mock::with([reply(Status::BadBlob, 0, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::OldServer, 0, None, None));
    let state = pc.state();
    assert_eq!(
        (state.id, state.done, state.rejected),
        (Some(id), None, None)
    );
    assert_eq!(pc.status().state, Some(SyncState::OldServer));
    assert!(
        pc.log().contains(
            "6A6A-6A6A server refused GOYOVA04: its goyo-sync script is older than 0.9.0"
        )
    );
    // Polls go on; the file waits, and the state stays.
    for _ in 0..3 {
        clock.advance(60);
        assert!(e.due(0));
        e.transport.replies.push_back(reply(Status::Empty, 0, b""));
        assert_eq!(e.pass(0, false), done(SyncState::OldServer, 0, None, None));
    }
    assert_eq!(
        e.transport.ops(),
        [(Op::Put, 0), (Op::Get, 0), (Op::Get, 0), (Op::Get, 0)]
    );
    // Ten minutes after the refusal it goes again, and lands once the
    // server script was updated.
    clock.advance(RETRY_HELD - 180);
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 1, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(e.transport.calls[4].sha, sha256(&v));
    assert_eq!(pc.state().done, Some(fsha));
    // A helper that starts again sends a held file at once, and a new
    // file from the app goes at once too.
    let v2 = keyed(&id, 2);
    pc.outgoing(1, &v2);
    clock.advance(1);
    e.transport
        .replies
        .push_back(reply(Status::BadBlob, 0, b""));
    assert_eq!(e.pass(0, false), done(SyncState::OldServer, 1, None, None));
    let mut e = pc.engine(Mock::with([reply(Status::BadBlob, 0, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::OldServer, 1, None, None));
    assert_eq!(e.transport.ops(), [(Op::Put, 1)]);
    clock.advance(1);
    let v3 = keyed(&id, 3);
    pc.outgoing(1, &v3);
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 2, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 2, Some(2), None));
    assert_eq!(pc.incoming(), Some((2, v3)));
    // BAD_BLOB for a GOYOVA02 file is a refusal, kept as before.
    let fsha = pc.outgoing(2, &blob(&id, 4));
    clock.advance(1);
    e.transport
        .replies
        .push_back(reply(Status::BadBlob, 0, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Refused, 2, None, None));
    assert_eq!(pc.state().rejected, Some(fsha));
}

/// KEY_BEHIND (status 14) answers an upload whose header does not match the
/// server's key file: `keyfile`, nothing persisted, the file sent again
/// after ten minutes, and a new file from the app at once (spec §7.6,
/// §14.6-15). The security-key build waits for the key view instead
/// (`key_behind_waits_for_the_key_view`).
#[cfg(not(feature = "security-key"))]
#[test]
fn key_behind_holds_the_upload_for_a_new_key_file() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x6B; 16];
    let v = keyed(&id, 1);
    pc.outgoing(4, &v);
    let mut e = pc.engine(Mock::with([reply(Status::KeyBehind, 0, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 0, None, None));
    let state = pc.state();
    assert_eq!((state.done, state.rejected), (None, None));
    assert_eq!(pc.status().state, Some(SyncState::KeyFile));
    assert!(pc.log().contains("PUT KEY_BEHIND"));
    clock.advance(60);
    e.transport.replies.push_back(reply(Status::Empty, 0, b""));
    assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 0, None, None));
    clock.advance(RETRY_HELD);
    e.transport
        .replies
        .push_back(reply(Status::KeyBehind, 0, b""));
    assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 0, None, None));
    assert_eq!(
        e.transport.ops(),
        [(Op::Put, 4), (Op::Get, 0), (Op::Put, 4)]
    );
    // The app took the new key file and wrote a new outgoing: sent at once.
    clock.advance(1);
    let v2 = keyed(&id, 2);
    pc.outgoing(4, &v2);
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 5, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, Some(5), None));
    assert_eq!(pc.incoming(), Some((5, v2)));
}

/// A helper older than 0.9.0 refused every GOYOVA04 outgoing at its gate
/// and kept the file's SHA as rejected. This one sends such a file once
/// when it starts; a second refusal is kept as before, and a rejected
/// GOYOVA02 file is never sent again (spec §7.6, §14.7-4).
#[test]
fn a_goyova04_an_older_helper_refused_is_retried_once_at_start() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x6C; 16];
    let fsha = pc.outgoing(2, &keyed(&id, 1));
    let old = HelperState {
        id: Some(id),
        rejected: Some(fsha),
        ..HelperState::default()
    };
    replace_file(
        &pc.dir.join(HELPER_STATE),
        &syncfile::render_helper_state(&old),
    )
    .unwrap();
    let mut e = pc.engine(Mock::with([reply(Status::Limit, 0, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Refused, 0, None, None));
    assert_eq!(e.transport.ops(), [(Op::Put, 2)]);
    assert!(
        pc.log()
            .contains("retrying a GOYOVA04 upload an older helper refused")
    );
    assert_eq!(pc.state().rejected, Some(fsha));
    // Not again in this run.
    clock.advance(60);
    e.transport.replies.push_back(reply(Status::Empty, 0, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Refused, 0, None, None));
    assert_eq!(e.transport.ops(), [(Op::Put, 2), (Op::Get, 0)]);
    // The next start sends it once more, and it lands.
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 3, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 3, Some(3), None));
    let state = pc.state();
    assert_eq!((state.done, state.rejected), (Some(fsha), None));
    // A rejected GOYOVA02 file is not sent at a start.
    let fsha = pc.outgoing(3, &blob(&id, 2));
    let state = HelperState {
        rejected: Some(fsha),
        ..pc.state()
    };
    replace_file(
        &pc.dir.join(HELPER_STATE),
        &syncfile::render_helper_state(&state),
    )
    .unwrap();
    let mut e = pc.engine(Mock::with([reply(Status::NotModified, 3, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Refused, 3, None, None));
    assert_eq!(e.transport.ops(), [(Op::Get, 3)]);
}

#[test]
fn a_server_going_back_is_logged() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x77; 16];
    seed_incoming(&pc, id, 9, &blob(&id, 9));
    let old = blob(&id, 5);
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 5, &old)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, None, Some(5)));
    assert_eq!(pc.incoming(), Some((5, old)));
    assert!(pc.log().contains("7777-7777 server version went back 9->5"));
}

#[test]
fn backoff_schedule() {
    let waits: Vec<u64> = (1..=8).map(|n| backoff(n, SyncState::Offline)).collect();
    assert_eq!(waits, [30, 60, 120, 240, 480, 900, 900, 900]);
    assert_eq!(backoff(u32::MAX, SyncState::Server), MAX_BACKOFF);
    for n in [1, 2, 9] {
        assert_eq!(backoff(n, SyncState::Auth), MAX_BACKOFF);
        assert_eq!(backoff(n, SyncState::HostKey), MAX_BACKOFF);
    }
    for nanos in [0, 1, 100, 200, 201, 999_999_999] {
        let j = jittered(60, nanos);
        assert!((54..=66).contains(&j), "{j}");
    }
    assert_eq!((jittered(60, 0), jittered(60, 200)), (54, 66));

    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x88; 16];
    pc.outgoing(0, &blob(&id, 1));
    let timed_out = "ssh: connect to host my-server port 22: Connection timed out";
    let mut e = pc.engine(Mock::with([ssh_error(timed_out)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Offline, 0, None, None));
    assert_eq!(pc.status().state, Some(SyncState::Offline));
    assert!(pc.log().contains("PUT failed state=offline"));
    assert!(pc.log().contains("retry in 30 s"));
    clock.advance(29);
    assert!(!e.due(0));
    clock.advance(1);
    assert!(e.due(0));
    e.transport
        .replies
        .push_back(ssh_error("Permission denied (publickey)."));
    assert_eq!(e.pass(0, false), done(SyncState::Auth, 0, None, None));
    // A heartbeat pass in the backoff calls nobody and keeps the state.
    clock.advance(HEARTBEAT);
    assert!(e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Auth, 0, None, None));
    assert_eq!(e.transport.calls.len(), 2);
    clock.advance(10);
    assert!(!e.due(0));
    // A new outgoing gets one attempt even in the backoff, and only one.
    pc.outgoing(0, &blob(&id, 2));
    assert!(e.due(0));
    e.transport
        .replies
        .push_back(ssh_error("Host key verification failed."));
    assert_eq!(e.pass(0, false), done(SyncState::HostKey, 0, None, None));
    assert_eq!(e.transport.calls.len(), 3);
    assert!(!e.due(0));
    clock.advance(HEARTBEAT);
    e.pass(0, false);
    assert_eq!(e.transport.calls.len(), 3);
    // After the 15 minutes the upload is retried; success clears it.
    clock.advance(MAX_BACKOFF);
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 1, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    clock.advance(1);
    assert!(!e.due(0));
}

/// Deadlines set before the wall clock went back do not stall syncing.
#[test]
fn a_clock_going_back_does_not_stop_syncing() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x8A; 16];
    pc.outgoing(0, &blob(&id, 1));
    let timed_out = "ssh: connect to host my-server port 22: Connection timed out";
    let mut e = pc.engine(Mock::with([ssh_error(timed_out)]), &clock);
    e.pass(0, false);
    clock.advance(1);
    assert!(!e.due(0), "in the backoff");
    // A day back: the backoff, the poll and the heartbeat are all due.
    clock.back(86_400);
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 1, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(pc.status().heartbeat, START + 1 - 86_400);
    clock.advance(1);
    assert!(!e.due(0));
    clock.back(86_400);
    assert!(e.due(0));
    e.transport
        .replies
        .push_back(reply(Status::NotModified, 1, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, None, None));
    assert_eq!(
        e.transport.ops(),
        [(Op::Put, 0), (Op::Put, 0), (Op::Get, 1)]
    );
}

/// An ssh exchange that takes its time: each call runs for its number of
/// test-clock seconds, calling `beat` once a second (`run_bounded` calls it
/// every 50 ms), and notes the watched folders' status files after each.
struct Slow {
    clock: TestClock,
    calls: VecDeque<(u64, Result<Output, Failure>)>,
    watch: Vec<PathBuf>,
    /// The test clock and each watched status, after every beat.
    seen: Vec<(u64, Vec<SyncStatus>)>,
    /// From the first time to the second, the first watched status is held
    /// open (as by the app reading it), so it cannot be replaced.
    hold: (u64, u64),
}
impl Transport for Slow {
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        let _r = Request::decode(request).expect("the server would refuse this frame");
        // The security-key build fetches the key view first: at once, empty.
        #[cfg(feature = "security-key")]
        if _r.op == Op::GetKey {
            return reply(Status::Empty, 0, b"");
        }
        let (secs, reply) = self.calls.pop_front().expect("no reply was scripted");
        let mut held = None;
        for _ in 0..secs {
            self.clock.advance(1);
            let now = self.clock.0.get();
            if now == self.hold.0 {
                held = Some(fs::File::open(self.watch[0].join(syncfile::STATUS)).unwrap());
            } else if now == self.hold.1 {
                held = None;
            }
            beat();
            let status = self.watch.iter().map(|d| syncfile::read_status(d).unwrap());
            self.seen.push((now, status.collect()));
        }
        drop(held);
        reply
    }
}
/// The times at which one watched status got a new heartbeat.
fn beats(seen: &[(u64, Vec<SyncStatus>)], folder: usize) -> Vec<u64> {
    let mut times: Vec<u64> = seen.iter().map(|(_, s)| s[folder].heartbeat).collect();
    times.dedup();
    times
}

/// A slow upload must not make the app call the helper off (no heartbeat
/// for 180 s): while it runs, this vault's status and every other vault's
/// get a heartbeat when one is due, and a status that cannot be replaced is
/// tried again only after STATUS_GAP, not on every 50 ms wait.
#[test]
fn slow_exchanges_keep_every_heartbeat() {
    let (a, b) = (Pc::with_folder(), Pc::with_folder());
    let clock = TestClock::new();
    let (ida, idb) = ([0xB1; 16], [0xB2; 16]);
    seed_incoming(&b, idb, 1, &blob(&idb, 1));
    a.outgoing(0, &blob(&ida, 1));
    let slow = Slow {
        clock: clock.clone(),
        calls: VecDeque::from([
            (0, reply(Status::NotModified, 1, b"")),
            (400, reply(Status::Ok, 1, b"")),
        ]),
        watch: vec![a.dir.clone(), b.dir.clone()],
        seen: Vec::new(),
        hold: (START + 100, START + 200),
    };
    let vaults = [a.vault.clone(), b.vault.clone()];
    let log = Log::new(Some(a.t.0.join(LOG)));
    let mut e = Engine::new(slow, &vaults, 60, clock.boxed(), log);
    // B's pass: a quick poll.
    assert_eq!(e.pass(1, false), done(SyncState::Ok, 1, None, None));
    assert_eq!(b.status().heartbeat, START);
    // A's first upload takes 400 s, 100 of them with its status held open.
    let started = Instant::now();
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    let took = started.elapsed();
    let seen = &e.transport.seen;
    assert_eq!(seen.len(), 400);
    // B's status, untouched by this pass otherwise, beats every 50 s.
    let want: Vec<u64> = (1..=8).map(|k| START + k * HEARTBEAT).collect();
    assert_eq!(beats(seen, 1), [&[START][..], &want].concat());
    // A's beats at once (it had no status yet), then when due. While held,
    // a try every STATUS_GAP fails; the first try after the release works.
    let want = [1, 51, 201, 251, 301, 351].map(|t| START + t);
    assert_eq!(beats(seen, 0), want);
    for (now, status) in seen {
        assert!(status.iter().all(|s| s.state == Some(SyncState::Ok)));
        let lag = now - status[1].heartbeat;
        assert!(lag < HEARTBEAT, "B's heartbeat {lag} s old at {now}");
        if !(START + 100..START + 201).contains(now) {
            let lag = now - status[0].heartbeat;
            assert!(lag < HEARTBEAT, "A's heartbeat {lag} s old at {now}");
        }
    }
    // Ten tries failed after 150 ms of retries each; a try on every beat
    // of the 100 s would have taken 15 s.
    assert!(took < Duration::from_secs(8), "{took:?}");
    // The pass ends with the time it ends, not the time it started.
    assert_eq!(a.status().heartbeat, START + 400);
    assert_eq!(a.status().contact, START + 400);

    // A slow failure: its backoff counts from when the exchange gave up.
    a.outgoing(1, &blob(&ida, 2));
    let timed_out = "ssh: connect to host my-server port 22: Connection timed out";
    e.transport.calls.push_back((120, ssh_error(timed_out)));
    assert!(e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Offline, 1, None, None));
    assert_eq!(a.status().heartbeat, START + 520);
    assert!(!e.due(0), "retried at once after a 120 s timeout");
    clock.advance(29);
    assert!(!e.due(0));
    clock.advance(1);
    assert!(e.due(0));
}

#[test]
fn a_queued_incoming_survives_a_busy_file() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0x99; 16];
    let (v1, v2) = (blob(&id, 1), blob(&id, 2));
    pc.outgoing(0, &v1);
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 1, b"")]), &clock);
    e.pass(0, false);
    // The app is reading incoming while the next upload lands.
    let reader = fs::File::open(pc.dir.join(INCOMING)).unwrap();
    pc.outgoing(1, &v2);
    e.transport.replies.push_back(reply(Status::Ok, 2, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(2), None));
    assert_eq!(pc.incoming(), Some((1, v1)));
    assert_eq!(pc.state().server, 1);
    assert!(
        pc.log()
            .contains("incoming not written (Busy); version 2 stays queued")
    );
    // It is written on the next loop, with no server call.
    assert!(e.due(0));
    e.pass(0, false);
    assert_eq!(pc.incoming().map(|(v, _)| v), Some(1), "still held open");
    drop(reader);
    assert!(e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 2, None, None));
    assert_eq!(pc.incoming(), Some((2, v2.clone())));
    assert_eq!((pc.state().server, pc.state().head), (2, Some(sha256(&v2))));
    assert_eq!(e.transport.calls.len(), 2);
    assert!(!e.due(0));
}

#[test]
fn state_is_rebuilt_from_incoming() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0xAA; 16];
    let v1 = blob(&id, 1);
    pc.outgoing(0, &v1);
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 1, b"")]), &clock);
    e.pass(0, false);
    // The app verified and removed outgoing; helper.state is lost.
    fs::remove_file(pc.dir.join(OUTGOING)).unwrap();
    fs::remove_file(pc.dir.join(HELPER_STATE)).unwrap();
    let mut e = pc.engine(Mock::with([reply(Status::NotModified, 1, b"")]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, None, None));
    let get = &e.transport.calls[0];
    assert_eq!((get.op, get.version, get.sha), (Op::Get, 1, sha256(&v1)));
    let state = pc.state();
    assert_eq!((state.id, state.server), (Some(id), 1));
    assert!(pc.log().contains("rebuilt from incoming (server=1)"));
    // Damaged rather than missing: the same. With outgoing still there, the
    // forgotten `done` costs one PUT, answered as already landed.
    let fsha = pc.outgoing(0, &v1);
    fs::write(pc.dir.join(HELPER_STATE), b"goyo-sync-state 1\njunk\n").unwrap();
    let mut e = pc.engine(Mock::with([reply(Status::Conflict, 1, &v1)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(e.transport.ops(), [(Op::Put, 0)]);
    assert_eq!(pc.state().done, Some(fsha));
}

/// incoming deleted or damaged while helper.state survives: the helper must
/// not keep telling the server it has that copy, or GET answers NOT_MODIFIED
/// forever and a dead upload queues nothing, so the app never sees the head.
#[test]
fn a_lost_incoming_is_fetched_again() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0xA5; 16];
    let (v1, v2) = (blob(&id, 1), blob(&id, 2));
    seed_incoming(&pc, id, 1, &v1);
    // A restarted helper finds helper.state but no incoming: the app's
    // upload from base 0 is dead, and the head is written again.
    fs::remove_file(pc.dir.join(INCOMING)).unwrap();
    pc.outgoing(0, &v2);
    let mut e = pc.engine(Mock::with([reply(Status::Conflict, 1, &v1)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, None, Some(1)));
    assert_eq!(pc.incoming(), Some((1, v1.clone())));
    assert!(
        pc.log()
            .contains("incoming changed outside the helper; server 1->0")
    );
    // A running helper: incoming damaged behind its back. The next poll
    // asks as if it held nothing.
    fs::write(pc.dir.join(INCOMING), b"GOYOSIN1 damaged").unwrap();
    clock.advance(60);
    e.transport.replies.push_back(reply(Status::Ok, 1, &v1));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, None, Some(1)));
    assert_eq!(e.transport.ops()[1], (Op::Get, 0));
    assert_eq!(pc.incoming(), Some((1, v1.clone())));
    // Its own writes are not mistaken for outside changes: the next poll
    // sends what it holds and reads nothing again.
    clock.advance(60);
    e.transport
        .replies
        .push_back(reply(Status::NotModified, 1, b""));
    e.pass(0, false);
    let get = &e.transport.calls[2];
    assert_eq!((get.op, get.version, get.sha), (Op::Get, 1, sha256(&v1)));
    assert_eq!(pc.log().matches("incoming changed outside").count(), 2);
}

/// helper.lock is held, byte-range locked, for a whole pass: a link planted
/// there (here a hard link to the key file) is never locked or used.
#[test]
fn a_linked_lock_file_is_refused() {
    let pc = Pc::with_folder();
    fs::write(&pc.key, b"key file bytes").unwrap();
    fs::hard_link(&pc.key, pc.dir.join(HELPER_LOCK)).unwrap();
    let clock = TestClock::new();
    pc.outgoing(0, &blob(&[0xA6; 16], 1));
    let mut e = pc.engine(Mock::default(), &clock);
    assert_eq!(e.pass(0, true), Outcome::Folder(Folder::Unusable));
    assert!(e.transport.calls.is_empty());
    assert!(!pc.dir.join(syncfile::STATUS).exists());
    assert!(
        pc.log()
            .contains("helper.lock is a link or not a plain file")
    );
    // Logged once; the key file is not held: it can be replaced at once.
    clock.advance(HEARTBEAT);
    assert!(e.due(0));
    assert_eq!(e.pass(0, true), Outcome::Folder(Folder::Unusable));
    assert_eq!(pc.log().matches("helper.lock is a link").count(), 1);
    fs::remove_file(pc.dir.join(HELPER_LOCK)).unwrap();
    replace_file(&pc.key, b"replaced").unwrap();
    // A plain lock file again: the pass runs.
    e.transport.replies.push_back(reply(Status::Ok, 1, b""));
    assert_eq!(e.pass(0, true), done(SyncState::Ok, 1, Some(1), None));
}

#[test]
fn idle_without_a_vault_id_and_folder_rules() {
    // The folder is created only next to a vault that exists.
    let pc = Pc::new();
    let clock = TestClock::new();
    let mut e = pc.engine(Mock::default(), &clock);
    assert_eq!(e.pass(0, false), Outcome::Folder(Folder::NoVault));
    assert!(!pc.dir.exists());
    assert!(pc.log().contains("the vault file is not in its folder"));
    // A missing vault is looked for again at the heartbeat pace.
    fs::write(&pc.vault, b"x").unwrap();
    assert!(!e.due(0));
    clock.advance(HEARTBEAT);
    assert!(e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Idle, 0, None, None));
    assert!(syncfile::usable_dir(&pc.dir));
    assert_eq!(pc.status().state, Some(SyncState::Idle));
    assert!(pc.log().contains("created the sync folder"));
    assert!(e.transport.calls.is_empty());
    // Idle stays quiet until the app writes outgoing.
    clock.advance(10);
    assert!(!e.due(0));
    let id = [0xBB; 16];
    pc.outgoing(0, &blob(&id, 1));
    assert!(e.due(0));
    e.transport.replies.push_back(reply(Status::Ok, 1, b""));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    // Another helper pass holding the lock: skipped.
    let lock = fs::File::options()
        .read(true)
        .write(true)
        .open(pc.dir.join(HELPER_LOCK))
        .unwrap();
    lock.try_lock().unwrap();
    assert_eq!(e.pass(0, true), Outcome::Locked);
    drop(lock);
    // A junction where the folder should be is never used.
    let other = Pc::new();
    fs::write(&other.vault, b"x").unwrap();
    junction(&other.dir, &other.t.0);
    let mut e = other.engine(Mock::default(), &clock);
    assert_eq!(e.pass(0, true), Outcome::Folder(Folder::Unusable));
    assert!(!other.t.0.join(syncfile::STATUS).exists());
    fs::remove_dir(&other.dir).unwrap();
}

#[test]
fn a_newer_format_head_is_never_written() {
    let pc = Pc::with_folder();
    let clock = TestClock::new();
    let id = [0xCC; 16];
    seed_incoming(&pc, id, 2, &blob(&id, 2));
    // GOYOVA03 is never synced: a server sending one is broken.
    let mut unsynced = blob(&id, 3);
    unsynced[..8].copy_from_slice(b"GOYOVA03");
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 3, &unsynced)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Server, 2, None, None));
    assert!(
        pc.log()
            .contains("frame=not a GOYOVA02/04 file of this vault")
    );
    let mut newer = blob(&id, 3);
    newer[..8].copy_from_slice(b"GOYOVA05");
    let mut e = pc.engine(Mock::with([reply(Status::Ok, 3, &newer)]), &clock);
    assert_eq!(e.pass(0, false), done(SyncState::Update, 2, None, None));
    assert_eq!(pc.incoming().map(|(v, _)| v), Some(2));
    assert_eq!(pc.status().state, Some(SyncState::Update));
    assert!(pc.log().contains("frame=vault from a newer version"));
}

// ---- 21: a key file is never uploaded ----

fn key_file(pc: &Pc) -> Vec<u8> {
    let p = Provision::new().unwrap();
    drop(p.finish(&pc.vault, &pc.key, PASSWORD, None).unwrap());
    fs::read(&pc.key).unwrap()
}
/// Makes `link` a junction to `target` the way `mklink /J` does.
pub(crate) fn junction(link: &Path, target: &Path) {
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            device: *mut std::ffi::c_void,
            code: u32,
            input: *const u8,
            input_len: u32,
            output: *mut u8,
            output_len: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }
    fs::create_dir(link).unwrap();
    // FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
    let dir = fs::OpenOptions::new()
        .write(true)
        .custom_flags(0x0020_0000 | 0x0200_0000)
        .open(link)
        .unwrap();
    let substitute: Vec<u16> = OsStr::new(r"\??\")
        .encode_wide()
        .chain(target.as_os_str().encode_wide())
        .collect();
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let names = 2 * (substitute.len() + print.len() + 2);
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xA000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
    buf.extend_from_slice(&((8 + names) as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    let offsets = [
        0,
        2 * substitute.len(),
        2 * (substitute.len() + 1),
        2 * print.len(),
    ];
    for n in offsets {
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    }
    for c in substitute.iter().chain(&[0]).chain(&print).chain(&[0]) {
        buf.extend_from_slice(&c.to_le_bytes());
    }
    let mut returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            dir.as_raw_handle(),
            0x0009_00A4, // FSCTL_SET_REPARSE_POINT
            buf.as_ptr(),
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
}
/// Plants `make(outgoing)` and runs a pass of a fresh engine with no
/// scripted replies: any transport call fails the test.
fn refused(pc: &Pc, make: impl FnOnce(&Path), why: &str) {
    let outgoing = pc.dir.join(OUTGOING);
    let _ = fs::remove_file(&outgoing);
    let _ = fs::remove_dir(&outgoing);
    make(&outgoing);
    let _ = fs::remove_file(pc.dir.join(HELPER_STATE));
    let clock = TestClock::new();
    let mut e = pc.engine(Mock::default(), &clock);
    let logged = pc.log().matches(why).count();
    assert_eq!(
        e.pass(0, true),
        done(SyncState::Refused, 0, None, None),
        "{why}"
    );
    assert!(e.transport.calls.is_empty(), "{why}");
    assert_eq!(pc.log().matches(why).count(), logged + 1, "{why}");
    assert_eq!(pc.status().state, Some(SyncState::Refused));
    // Also when the ID is pinned: the poll may run, the upload may not.
    let id = [0xDD; 16];
    seed_incoming(pc, id, 1, &blob(&id, 1));
    let mut e = pc.engine(Mock::with([reply(Status::NotModified, 1, b"")]), &clock);
    e.pass(0, true);
    assert_eq!(e.transport.ops(), [(Op::Get, 1)], "{why}");
    fs::remove_file(pc.dir.join(INCOMING)).unwrap();
}
#[test]
fn a_key_file_is_never_uploaded() {
    let pc = Pc::new();
    let key = key_file(&pc);
    assert!(key.starts_with(b"GOYOKE02") && key.len() == 128);
    fs::create_dir(&pc.dir).unwrap();
    // The key's bytes, raw or wrapped as an upload.
    refused(
        &pc,
        |p| fs::write(p, &key).unwrap(),
        "not a GOYOSOU1-wrapped",
    );
    let mut wrapped = b"GOYOSOU1".to_vec();
    wrapped.extend_from_slice(&0u64.to_le_bytes());
    wrapped.extend_from_slice(&key);
    refused(
        &pc,
        |p| fs::write(p, &wrapped).unwrap(),
        "not a GOYOSOU1-wrapped",
    );
    // A key file is refused by its magic: GOYOKE02 (128 B) and GOYOKE01
    // (148 B) are sizes a small GOYOVA02 vault can have too. Below the
    // smallest upload (16 + 96 B) the size alone refuses it.
    refused(
        &pc,
        |p| fs::write(p, &wrapped[..111]).unwrap(),
        "the wrong size",
    );
    // A hard link to the key file: refused before it is read.
    refused(
        &pc,
        |p| fs::hard_link(&pc.key, p).unwrap(),
        "more than one hard link",
    );
    // A junction at the outgoing name.
    refused(&pc, |p| junction(p, &pc.t.0), "a symlink or junction");
    // A file symlink to the key, where Windows lets this account make one
    // (developer mode or an elevated prompt).
    let probe = pc.t.0.join("symlink-probe");
    if std::os::windows::fs::symlink_file(&pc.key, &probe).is_ok() {
        fs::remove_file(&probe).unwrap();
        refused(
            &pc,
            |p| std::os::windows::fs::symlink_file(&pc.key, p).unwrap(),
            "a symlink or junction",
        );
    }
    // The key itself was never touched by any of it.
    assert_eq!(fs::read(&pc.key).unwrap(), key);
    // The gate on its own.
    let id = [0xDD; 16];
    let path = pc.dir.join(OUTGOING);
    // What the last refusal left there: the junction, or the file symlink
    // where Windows lets this account make one (else the write below goes
    // through it into the key file).
    let _ = fs::remove_dir(&path);
    let _ = fs::remove_file(&path);
    fs::write(&path, render_outgoing(0, &blob(&id, 1)).unwrap()).unwrap();
    assert!(matches!(gate(&path, Some(&id)), Gate::Ok(g) if g.id == id && g.base == 0));
    assert!(matches!(
        gate(&path, Some(&[0xEE; 16])),
        Gate::Refused(Refusal::Id, Some(_))
    ));
    fs::write(&path, render_outgoing(0, &blob(&[0; 16], 1)).unwrap()).unwrap();
    assert!(matches!(
        gate(&path, None),
        Gate::Refused(Refusal::Id, Some(_))
    ));
    fs::remove_file(&path).unwrap();
    assert!(matches!(gate(&path, None), Gate::Missing));
}

/// The helper never holds the vault or key file open: an app's rename over
/// either never fails while passes run, folder creation included (the only
/// step that lists the vault's folder).
#[test]
fn passes_never_hold_the_vault_or_key_file() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    use std::os::windows::ffi::OsStrExt;
    let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(Some(0)).collect() };
    let pc = Pc::new();
    fs::write(&pc.vault, b"v").unwrap();
    fs::write(&pc.key, b"k").unwrap();
    let clock = TestClock::new();
    let id = [0x12; 16];
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (failed, renames) = std::thread::scope(|s| {
        let renamer = s.spawn(|| {
            let (mut failed, mut renames) = (0u32, 0u32);
            while !stop.load(Ordering::Relaxed) {
                for target in [&pc.vault, &pc.key] {
                    let temp = pc.t.0.join(format!("rename-{renames}.goyotmp"));
                    fs::write(&temp, renames.to_le_bytes()).unwrap();
                    // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH, once.
                    if unsafe { MoveFileExW(wide(&temp).as_ptr(), wide(target).as_ptr(), 9) } == 0 {
                        failed += 1;
                        let _ = fs::remove_file(&temp);
                    }
                    renames += 1;
                }
            }
            (failed, renames)
        });
        for round in 0..40u8 {
            // Every other round starts without the folder, so P1 lists the
            // vault's folder and creates it again.
            if round % 2 == 0 {
                let _ = fs::remove_dir_all(&pc.dir);
            }
            let mut e = pc.engine(Mock::with([reply(Status::Ok, 1, b"")]), &clock);
            e.pass(0, true);
            if round % 2 == 1 {
                pc.outgoing(0, &blob(&id, round));
                let _ = fs::remove_file(pc.dir.join(HELPER_STATE));
                let mut e = pc.engine(Mock::with([reply(Status::Ok, 1, b"")]), &clock);
                assert_eq!(e.pass(0, true), done(SyncState::Ok, 1, Some(1), None));
            }
        }
        stop.store(true, Ordering::Relaxed);
        renamer.join().unwrap()
    });
    assert!(renames >= 40, "only {renames} renames ran alongside");
    assert_eq!(failed, 0, "a rename over the vault or key failed");
}

// ---- 23 and end to end: the real server script ----

fn server_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(r"server\goyo-sync-server.py")
}
#[test]
fn server_selftest_passes() {
    if !python() {
        return;
    }
    let out = python_command()
        .arg("-I")
        .arg(server_script())
        .arg("selftest")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.trim() == "PASS",
        "{:?} (code {:#x})\n{stdout}\n{}",
        out.status,
        out.status.code().unwrap_or(0) as u32,
        String::from_utf8_lossy(&out.stderr)
    );
    // The server allows each connection as long as the longest ssh timeout.
    let script = fs::read_to_string(server_script()).unwrap();
    assert!(script.contains("TIMEOUT = 600 "));
}

/// The server script run locally, one process per request, through the same
/// bounded runner as ssh.exe.
pub(crate) struct Local {
    pub(crate) root: PathBuf,
}
impl Transport for Local {
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        let mut command = Command::new("python");
        command
            .arg("-I")
            .arg(server_script())
            .args(["serve", "--root"])
            .arg(&self.root);
        run_bounded(command, request, Duration::from_secs(60), &mut |d| {
            beat();
            no_stop(d)
        })
    }
}
impl Local {
    /// The stored versions of vault `id`, oldest first.
    pub(crate) fn versions(&self, id: &[u8; 16]) -> Vec<(u64, Vec<u8>)> {
        let dir = self.root.join(syncfile::hex(id)).join("v");
        let mut found: Vec<(u64, Vec<u8>)> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| {
                        let name = e.file_name().to_string_lossy().into_owned();
                        (name[..12].parse().unwrap(), fs::read(e.path()).unwrap())
                    })
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found
    }
}
/// A real vault with sync turned on, as the app leaves it: GOYOVA02.
fn real_vault(pc: &Pc) -> (Session, [u8; 16]) {
    let p = Provision::new().unwrap();
    let mut s = p.finish(&pc.vault, &pc.key, PASSWORD, None).unwrap();
    let entry = Entry::new(
        "mail".into(),
        "login".into(),
        "synthetic secret".into(),
        String::new(),
    );
    s.put(None, entry.unwrap()).unwrap();
    s.enable_sync().unwrap();
    let bytes = fs::read(&pc.vault).unwrap();
    assert_eq!(&bytes[..8], b"GOYOVA02");
    (s, bytes[8..24].try_into().unwrap())
}
/// A fresh encryption of the session's current content, as the app writes
/// for each upload.
fn encode(s: &mut Session) -> Vec<u8> {
    s.save().unwrap();
    fs::read(&s.path).unwrap()
}

#[test]
fn end_to_end_seed_join_and_landed() {
    if !python() {
        return;
    }
    let server = Temp::new("server");
    let local = || Local {
        root: server.0.join("data"),
    };
    let clock = TestClock::new();
    let (a, b) = (Pc::new(), Pc::new());
    let (mut s, id) = real_vault(&a);
    // S1: the helper made the folder, the app consented and wrote outgoing
    // with base 0; the helper seeds the empty server.
    fs::create_dir(&a.dir).unwrap();
    let v1 = fs::read(&a.vault).unwrap();
    let fa = a.outgoing(0, &v1);
    let mut ea = a.engine(local(), &clock);
    assert_eq!(ea.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(local().versions(&id), [(1, v1.clone())]);
    assert_eq!(a.incoming(), Some((1, v1.clone())));
    assert_eq!(a.state().done, Some(fa));
    // The next poll: NOT_MODIFIED, nothing written.
    let before = syncfile::stamp(&a.dir, INCOMING);
    assert_eq!(ea.pass(0, true), done(SyncState::Ok, 1, None, None));
    assert_eq!(syncfile::stamp(&a.dir, INCOMING), before);
    // S2: B restored a copy and unlocked it: its own fresh encryption with
    // base 0 loses to the head, which B's app then merges.
    fs::write(&b.vault, b"B's copy of the vault").unwrap();
    fs::create_dir(&b.dir).unwrap();
    let fb = b.outgoing(0, &encode(&mut s));
    let mut eb = b.engine(local(), &clock);
    assert_eq!(eb.pass(0, false), done(SyncState::Ok, 1, None, Some(1)));
    assert_eq!(b.incoming(), Some((1, v1.clone())));
    assert_eq!(b.state().done, Some(fb));
    // A dead outgoing makes no new version, pass after pass.
    for _ in 0..3 {
        clock.advance(60);
        eb.pass(0, false);
        ea.pass(0, false);
    }
    assert_eq!(local().versions(&id).len(), 1);
    // S3 and S5: A edits; the PUT commits but the helper dies before it
    // records OK. The restarted helper finds its own upload as the head.
    s.put(
        None,
        Entry::new(
            "bank".into(),
            String::new(),
            "another secret".into(),
            String::new(),
        )
        .unwrap(),
    )
    .unwrap();
    let v2 = fs::read(&a.vault).unwrap();
    a.outgoing(1, &v2);
    let r = local()
        .exchange(&Request::put(id, 1, &v2).unwrap().encode(), &mut || {})
        .unwrap();
    let (direct, _) = Response::decode(&r.stdout, Op::Put, &id, 1).unwrap();
    assert_eq!((direct.status, direct.version), (Status::Ok, 2));
    let mut ea = a.engine(local(), &clock);
    assert_eq!(ea.pass(0, false), done(SyncState::Ok, 2, Some(2), None));
    assert_eq!(local().versions(&id).len(), 2, "no duplicate version");
    assert_eq!(a.incoming(), Some((2, v2.clone())));
    // B pulls the edit.
    assert_eq!(eb.pass(0, true), done(SyncState::Ok, 2, None, Some(2)));
    assert_eq!(b.incoming(), Some((2, v2)));
    assert!(a.status().contact >= START && b.status().state == Some(SyncState::Ok));
}

#[test]
fn end_to_end_wipe_and_rollback() {
    if !python() {
        return;
    }
    let server = Temp::new("server");
    let local = || Local {
        root: server.0.join("data"),
    };
    let clock = TestClock::new();
    let a = Pc::new();
    let (mut s, id) = real_vault(&a);
    fs::create_dir(&a.dir).unwrap();
    let mut e = a.engine(local(), &clock);
    let v1 = fs::read(&a.vault).unwrap();
    a.outgoing(0, &v1);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    // S9: the server's folder is wiped. GET says EMPTY and the helper puts
    // back the copy in incoming, with no help from the app.
    let vault_dir = server.0.join("data").join(syncfile::hex(&id));
    fs::remove_dir_all(&vault_dir).unwrap();
    assert_eq!(e.pass(0, true), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(local().versions(&id), [(1, v1.clone())]);
    assert!(
        a.log()
            .contains("server was empty; re-uploaded the last known copy")
    );
    // Wiped again while an upload based on version 1 waits: EMPTY, then
    // the same file as the first version.
    fs::remove_dir_all(&vault_dir).unwrap();
    let mut add = |title: &str| {
        let entry = Entry::new(title.into(), String::new(), "x".into(), String::new());
        s.put(None, entry.unwrap()).unwrap();
        fs::read(&a.vault).unwrap()
    };
    let v2 = add("two");
    a.outgoing(1, &v2);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    assert_eq!(local().versions(&id), [(1, v2.clone())]);
    assert!(
        a.log()
            .contains("server has no copy; uploading as the first version")
    );
    // S8: versions 2 and 3, then the server drops version 3.
    let v3 = add("three");
    a.outgoing(1, &v3);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 2, Some(2), None));
    let v4 = add("four");
    a.outgoing(2, &v4);
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 3, Some(3), None));
    fs::remove_file(vault_dir.join("v").join("000000000003.goyo")).unwrap();
    assert_eq!(e.pass(0, true), done(SyncState::Ok, 2, None, Some(2)));
    assert_eq!(a.incoming(), Some((2, v3)));
    assert!(a.log().contains("server version went back 3->2"));
    // Gate 3 and the end check: every stored file is GOYOVA02 of this
    // vault, none holds key-file bytes, and posting the key file itself is
    // refused with nothing written.
    let key = fs::read(&a.key).unwrap();
    let stored = local().versions(&id);
    assert_eq!(stored.len(), 2);
    for (_, data) in &stored {
        assert!(data.starts_with(b"GOYOVA02") && data[8..24] == id);
        assert!(!data.windows(32).any(|w| key.windows(32).any(|k| k == w)));
    }
    let forged = Request {
        op: Op::Put,
        vault_id: id,
        version: 2,
        blob_sha: sha256(&key),
        blob: &key,
    };
    let r = local().exchange(&forged.encode(), &mut || {}).unwrap();
    let (refusal, _) = Response::decode(&r.stdout, Op::Put, &id, 2).unwrap();
    assert_eq!(refusal.status, Status::BadBlob);
    assert_eq!(local().versions(&id), stored);
}

/// The real server behind a front that, while `frozen`, takes no upload:
/// each PUT gets CONFLICT with the head the server holds, the way a hostile
/// server would freeze sync. Counts the PUTs that reach it.
struct Frozen {
    local: Local,
    frozen: bool,
    puts: usize,
}
impl Transport for Frozen {
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        let r = Request::decode(request).unwrap();
        if r.op != Op::Put {
            return self.local.exchange(request, beat);
        }
        self.puts += 1;
        if !self.frozen {
            return self.local.exchange(request, beat);
        }
        let get = Request::get(r.vault_id, 0, None).encode();
        let out = self.local.exchange(&get, beat)?;
        let (head, _) = Response::decode(&out.stdout, Op::Get, &r.vault_id, 0).unwrap();
        reply(Status::Conflict, head.version, head.blob)
    }
}

/// The frozen-server finding end to end, with the app's own sessions: once
/// the server stops taking uploads and answers each with the head this PC
/// already holds, the app warns, and the upload it writes again at each
/// unlock (its edit is not on the server) is not sent at each unlock, so the
/// server does not learn when the vault is opened.
#[test]
fn end_to_end_a_frozen_server_is_shown_and_learns_no_unlock() {
    if !python() {
        return;
    }
    let server = Temp::new("server");
    let local = Local {
        root: server.0.join("data"),
    };
    // The app reads the helper's heartbeat against the real time.
    let clock = TestClock(Rc::new(Cell::new(engine::system_clock()().as_secs())));
    let a = Pc::new();
    let frozen = Frozen {
        local,
        frozen: false,
        puts: 0,
    };
    let mut e = a.engine(frozen, &clock);
    let entry = |title: &str| Entry::new(title.into(), String::new(), "x".into(), String::new());
    let p = Provision::new().unwrap();
    let mut s = p.finish(&a.vault, &a.key, PASSWORD, None).unwrap();
    s.put(None, entry("mail").unwrap()).unwrap();
    assert_eq!(e.pass(0, false), done(SyncState::Idle, 0, None, None));
    s.enable_sync().unwrap();
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
    // The status file is read on every 5th poll.
    let polls = |s: &mut Session| -> Vec<SyncNotice> {
        (0..5).filter_map(|_| s.poll_sync()?.notice).collect()
    };
    assert!(matches!(
        polls(&mut s).as_slice(),
        [SyncNotice::Synced { .. }]
    ));
    // Frozen at version 1. An edit is uploaded once, and the answer is a
    // server fault the app shows.
    e.transport.frozen = true;
    s.put(None, entry("bank").unwrap()).unwrap();
    assert_eq!(e.pass(0, false), done(SyncState::Server, 1, None, None));
    assert_eq!(e.transport.puts, 2);
    assert!(a.log().contains("it is holding back uploads"));
    assert_eq!(polls(&mut s), [SyncNotice::HelperError]);
    assert_eq!(s.badge(), Some(SyncBadge::Offline));
    drop(s);
    // Three unlocks in the backoff: each merges version 1, finds the same
    // state already offered in outgoing and leaves that file alone, so the
    // helper has nothing new to try; none reaches the server.
    for _ in 0..3 {
        clock.advance(5);
        let before = syncfile::stamp(&a.dir, OUTGOING);
        assert!(before.is_some());
        drop(Session::unlock(&a.vault, &a.key, PASSWORD, "").unwrap());
        assert_eq!(syncfile::stamp(&a.dir, OUTGOING), before);
        assert!(!e.due(0));
        assert_eq!(e.pass(0, false), done(SyncState::Server, 1, None, None));
        assert_eq!(e.transport.puts, 2);
    }
    // After the backoff the newest file is sent once, and a server that
    // takes uploads again ends it.
    clock.advance(30);
    e.transport.frozen = false;
    assert!(e.due(0));
    assert_eq!(e.pass(0, false), done(SyncState::Ok, 2, Some(2), None));
    assert_eq!(e.transport.puts, 3);
    let mut s = Session::unlock(&a.vault, &a.key, PASSWORD, "").unwrap();
    assert!(matches!(
        s.take_unlock_notice(),
        Some(SyncNotice::Synced { .. })
    ));
    assert_eq!(syncfile::stamp(&a.dir, OUTGOING), None);
    assert_eq!(s.entries.len(), 2);
    assert_eq!(s.badge(), Some(SyncBadge::Synced));
}

/// `--fetch`: an existing target is refused before the settings are read,
/// so before any network call; a fetched version is written whole, only to a
/// new file, and nothing is left behind when there is nothing to write.
#[test]
fn fetch_writes_only_a_new_file() {
    let t = Temp::new("fetch");
    let log = Log::new(Some(t.0.join(LOG)));
    let hex = "a7".repeat(16);
    let os = |s: &str| OsString::from(s);
    let existing = t.0.join("existing.goyo");
    fs::write(&existing, b"kept").unwrap();
    let new = t.0.join("new.goyo");
    // There is no goyo-sync.conf here, so reading it would give exit 2.
    let run = |id: &str, version: &str, out: &Path| {
        fetch(&t.0, &log, &os(id), &os(version), out.as_os_str())
    };
    assert_eq!(run(&hex, "head", &existing), ERROR);
    assert_eq!(fs::read(&existing).unwrap(), b"kept");
    for (id, version) in [
        ("a7", "head"),
        (&*"00".repeat(16), "head"),
        (&*"g7".repeat(16), "head"),
        (&*hex, "0"),
        (&*hex, "-1"),
        (&*hex, "1234567890123"),
        (&*hex, "HEAD"),
    ] {
        assert_eq!(run(id, version, &new), ERROR, "{id} {version}");
    }
    assert_eq!(run(&hex.to_uppercase(), "head", &new), CONFIG_ERROR);
    assert!(!new.exists());
    if !python() {
        return;
    }
    let server = Temp::new("server");
    let mut local = Local {
        root: server.0.join("data"),
    };
    let id = [0xA7; 16];
    // The head is a GOYOVA04 copy, as after a key change (spec §14.7-2).
    let (v1, v2) = (blob(&id, 1), keyed(&id, 2));
    for (expected, v) in [(0, &v1), (1, &v2)] {
        let r = local
            .exchange(&Request::put(id, expected, v).unwrap().encode(), &mut || {})
            .unwrap();
        let (put, _) = Response::decode(&r.stdout, Op::Put, &id, expected).unwrap();
        assert_eq!(put.status, Status::Ok);
    }
    let head = t.0.join("head.goyo");
    assert_eq!(fetch_into(&mut local, &log, "my-server", id, 0, &head), OK);
    assert_eq!(fs::read(&head).unwrap(), v2);
    let first = t.0.join("first.goyo");
    assert_eq!(fetch_into(&mut local, &log, "my-server", id, 1, &first), OK);
    assert_eq!(fs::read(&first).unwrap(), v1);
    // A version the server does not have, and another vault: no file.
    assert_eq!(
        fetch_into(&mut local, &log, "my-server", id, 9, &new),
        ERROR
    );
    let other = [0xA8; 16];
    assert_eq!(
        fetch_into(&mut local, &log, "my-server", other, 0, &new),
        ERROR
    );
    assert!(!new.exists());
    // A file that appeared in the meantime is never overwritten.
    assert_eq!(
        fetch_into(&mut local, &log, "my-server", id, 0, &first),
        ERROR
    );
    assert_eq!(fs::read(&first).unwrap(), v1);
}

// ---- smaller pieces ----

#[test]
fn messages_have_both_languages() {
    let hangul = |s: &str| {
        s.chars().any(|c| {
            ('\u{ac00}'..='\u{d7a3}').contains(&c) || ('\u{3130}'..='\u{318f}').contains(&c)
        })
    };
    for m in Msg::ALL {
        let (ko, en) = m.pair();
        assert!(!ko.is_empty() && !en.is_empty(), "{m:?}");
        assert_eq!(ko.matches("{}").count(), en.matches("{}").count(), "{m:?}");
        assert!(!hangul(en), "{m:?} English has Korean");
    }
    msg::set_english(true);
    assert_eq!(
        msg::fill(Msg::PassUploaded, &[&"vault.goyo", &3]),
        "vault.goyo: uploaded (server version 3)."
    );
    msg::set_english(false);
    assert!(hangul(&msg::fill(Msg::PassUploaded, &[&"vault.goyo", &3])));
    msg::set_english(true);
}

#[test]
fn small_helpers() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc(1_792_000_000), "2026-10-14T17:46:40Z");
    assert_eq!(utc(4_102_444_799), "2099-12-31T23:59:59Z");
    let id: [u8; 16] = std::array::from_fn(|i| 0x3F + i as u8);
    assert_eq!(tag(&id), "3F40-4142");
    let (mutex, stop) = object_names();
    let suffix = mutex.strip_prefix(r"Local\GoyoSync-").unwrap();
    assert_eq!(stop, format!(r"Local\GoyoSyncStop-{suffix}"));
    assert!(suffix.len() == 16 && suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(sys::layout_sizes(), (64, 144, 52, 104, 24));
    // The log rotates at 256 KiB and keeps one older file.
    let t = Temp::new("log");
    let path = t.0.join(LOG);
    fs::write(&path, vec![b'x'; engine::MAX_LOG as usize]).unwrap();
    let log = Log::new(Some(path.clone()));
    log.line("first\nsecond");
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.ends_with(" first second\n") && text.lines().count() == 1);
    assert_eq!(
        fs::metadata(t.0.join("goyo-sync.log.1")).unwrap().len(),
        engine::MAX_LOG
    );
    // A kill-on-close job can be made.
    assert!(sys::Job::new().is_some());
}

// ---- key-file sync in the helper (security-key build; spec v3 §7.12, §14.7-7) ----

#[cfg(feature = "security-key")]
pub(crate) mod keys {
    use super::*;
    use crate::engine::{
        BEHIND_HOURLY, KEY_OPENS, KEY_RETRY, KeyGate, LINE_RETRY, VIEW_STUCK, key_gate,
    };
    use goyo_vault::{
        syncfile::{
            KEY_REQUEST, KEY_VIEW, KeyOp, KeyOutcome, KeyRequest, KeyView, PRUNE_REQUEST,
            RecordKind, parse_key_view, render_key_request, render_key_view, render_prune_request,
            render_record_header,
        },
        vault::keyfile::{EPOCH_MAX, EPOCH_WINDOW, is_sync_key_file, ks_id_zero},
    };

    /// The GOYOKS01 fixture: vault 3a3b…49, epoch 9 (tests/fixtures).
    const KS: &[u8] = include_bytes!("../../../tests/fixtures/goyoks01.goyokey");
    fn id() -> [u8; 16] {
        KS[8..24].try_into().unwrap()
    }
    /// The fixture at another epoch, still well formed (no slot was added
    /// at an epoch above 9).
    fn ks(epoch: u64) -> Vec<u8> {
        let mut f = KS.to_vec();
        f[24..32].copy_from_slice(&epoch.to_le_bytes());
        f
    }
    /// Another file at `epoch`: one body byte differs, which no public
    /// check can see.
    fn other(epoch: u64, n: u8) -> Vec<u8> {
        let mut f = ks(epoch);
        *f.last_mut().unwrap() ^= n;
        f
    }
    fn epoch_of(file: &[u8]) -> u64 {
        u64::from_le_bytes(file[24..32].try_into().unwrap())
    }
    fn header(generation: u64, file: &[u8]) -> Vec<u8> {
        render_record_header(RecordKind::Key, false, generation, epoch_of(file)).to_vec()
    }
    fn key_record(generation: u64, file: &[u8]) -> Vec<u8> {
        [header(generation, file), file.to_vec()].concat()
    }
    fn cut(number: u64, floor: u64) -> Vec<u8> {
        render_record_header(RecordKind::Cut, false, number, floor).to_vec()
    }
    /// A mock on which every call, the key ops included, is scripted.
    fn mock(replies: impl IntoIterator<Item = Result<Output, Failure>>) -> Mock {
        Mock {
            keys: true,
            ..Mock::with(replies)
        }
    }
    fn timeout() -> Result<Output, Failure> {
        Ok(Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            log: Vec::new(),
            code: None,
            killed: Some(Killed::Timeout),
        })
    }
    /// A GOYOVA04 header the server's floor takes under `file`: its epoch,
    /// current key ID and state tag (spec v3 §7.13), flags 3 (key-file
    /// sync).
    fn floor_vault(file: &[u8], fill: u8) -> Vec<u8> {
        let syntax = is_sync_key_file(file, &id()).unwrap();
        let mut v = keyed(&id(), fill);
        v[24..40].copy_from_slice(&syntax.current_key_id);
        v[40..48].copy_from_slice(&syntax.epoch.to_le_bytes());
        v[48..64].copy_from_slice(&syntax.tag);
        v[64..68].copy_from_slice(&[3, 0, 0, 0]);
        v
    }
    impl Pc {
        /// What the app writes as `kreq`; returns its SHA-256.
        fn request(&self, r: &KeyRequest) -> [u8; 32] {
            let bytes = render_key_request(r);
            replace_file(&self.dir.join(KEY_REQUEST), &bytes).unwrap();
            sha256(&bytes)
        }
        /// `kview`, if present and well formed.
        fn view(&self) -> Option<KeyView> {
            parse_key_view(&fs::read(self.dir.join(KEY_VIEW)).ok()?, &id())
        }
        fn set_view(&self, v: &KeyView) {
            replace_file(&self.dir.join(KEY_VIEW), &render_key_view(v)).unwrap();
        }
    }
    /// An engine that polls hourly: within one test the 10-minute rules
    /// run without polls in between.
    fn quiet<T: Transport>(pc: &Pc, transport: T, clock: &TestClock) -> Engine<T> {
        let log = Log::new(Some(pc.t.0.join(LOG)));
        Engine::new(
            transport,
            std::slice::from_ref(&pc.vault),
            3600,
            clock.boxed(),
            log,
        )
    }
    fn put_keys(e: &Engine<Mock>) -> Vec<&Call> {
        e.transport
            .calls
            .iter()
            .filter(|c| c.op == Op::PutKey)
            .collect()
    }
    /// A pinned vault whose server head is version 4.
    fn pinned() -> Pc {
        let pc = Pc::with_folder();
        seed_incoming(&pc, id(), 4, &keyed(&id(), 3));
        pc
    }

    /// Gate 2 (spec v3 §7.12, §14.7-7): only a `GOYOSKO2` request of this
    /// vault's GOYOKS01 file at an epoch above `floor`, or a bare CUT, in a
    /// plain single-link file. The vault gate refuses a key request.
    #[test]
    fn gate_2_takes_only_this_vaults_key_requests() {
        let pc = Pc::with_folder();
        let path = pc.dir.join(KEY_REQUEST);
        let id = id();
        let check = |bytes: &[u8]| {
            fs::write(&path, bytes).unwrap();
            key_gate(&path, &id)
        };
        let file = ks(12);
        let put = render_key_request(&KeyRequest::put(3, 9, &file));
        let got = check(&put);
        assert!(matches!(&got, KeyGate::Ok(g)
            if (g.op, g.base, g.epoch, g.sha) == (KeyOp::Put, 3, 12, sha256(&put))));
        let cut_request = render_key_request(&KeyRequest::cut(4));
        assert!(matches!(check(&cut_request), KeyGate::Ok(g) if (g.op, g.base) == (KeyOp::Cut, 4)));
        // No bound above floor (S6-2 #1): an honest drifted upload passes.
        let far = render_key_request(&KeyRequest::put(1, 9, &ks(EPOCH_MAX)));
        assert!(matches!(check(&far), KeyGate::Ok(_)));
        let as_payload = |magic: &[u8; 8]| {
            let mut f = file.clone();
            f[..8].copy_from_slice(magic);
            render_key_request(&KeyRequest::put(0, 0, &f))
        };
        let with = |bytes: &[u8], at: usize, value: u8| {
            let mut b = bytes.to_vec();
            b[at] = value;
            b
        };
        let mut zero_ks = file.clone();
        zero_ks[48..64].copy_from_slice(&ks_id_zero(&id));
        let mut another = file.clone();
        another[8] ^= 1;
        let cases: Vec<(Vec<u8>, Refusal)> = vec![
            (as_payload(b"GOYOKE01"), Refusal::KeyFormat),
            (as_payload(b"GOYOKE02"), Refusal::KeyFormat),
            (as_payload(b"GOYOKE03"), Refusal::KeyFormat),
            (as_payload(b"GOYOKH01"), Refusal::KeyFormat),
            (as_payload(b"GOYOVA02"), Refusal::KeyFormat),
            (as_payload(b"GOYOVA04"), Refusal::KeyFormat),
            (
                render_key_request(&KeyRequest::put(0, 0, &another)),
                Refusal::Id,
            ),
            (with(&put, 7, b'1'), Refusal::KeyFormat), // GOYOSKO1
            (with(&put, 3, b'S'), Refusal::KeyFormat), // GOYSSKO2
            (with(&put, 8, 3), Refusal::KeyFormat),    // unknown op
            (with(&put, 12, 1), Refusal::KeyFormat),   // reserved
            (with(&cut_request, 8, 1), Refusal::KeyFormat), // a PUT of 32 bytes
            (with(&put, 8, 2), Refusal::KeyFormat),    // a CUT with a payload
            ([&cut_request[..], &[0]].concat(), Refusal::Size),
            (put[..32 + 488].to_vec(), Refusal::Size),
            (Vec::new(), Refusal::Size),
            (
                render_key_request(&KeyRequest::cut(EPOCH_MAX + 1)),
                Refusal::KeyFormat,
            ),
            (
                render_key_request(&KeyRequest::put(EPOCH_MAX + 1, 0, &file)),
                Refusal::KeyFormat,
            ),
            (
                render_key_request(&KeyRequest::put(0, EPOCH_MAX + 1, &file)),
                Refusal::KeyFormat,
            ),
            (
                render_key_request(&KeyRequest::put(0, 12, &file)),
                Refusal::KeyFormat,
            ),
            (
                render_key_request(&KeyRequest::put(0, 0, &ks(EPOCH_MAX + 1))),
                Refusal::KeyFormat,
            ),
            (
                render_key_request(&KeyRequest::put(0, 0, &zero_ks)),
                Refusal::KeyFormat,
            ),
        ];
        for (i, (bytes, want)) in cases.iter().enumerate() {
            let got = check(bytes);
            assert!(matches!(got, KeyGate::Refused(r) if r == *want), "case {i}");
        }
        // Every structural rule of the key file is the strict parse's own
        // (the mask, pair-record and via rules of §4.6): the gate refuses a
        // header byte changed exactly when `is_sync_key_file` does.
        let mut refused = 0;
        for at in 24..300 {
            let mut f = file.clone();
            f[at] ^= 0x41;
            let valid = is_sync_key_file(&f, &id).is_some();
            let got = check(&render_key_request(&KeyRequest::put(0, 0, &f)));
            assert_eq!(matches!(got, KeyGate::Ok(_)), valid, "byte {at}");
            refused += usize::from(!valid);
        }
        assert!(refused > 30, "only {refused} changes refused");
        // The file checks: a hard link, a junction, a folder, nothing.
        fs::write(&path, &put).unwrap();
        fs::hard_link(&path, pc.t.0.join("elsewhere")).unwrap();
        assert!(matches!(
            key_gate(&path, &id),
            KeyGate::Refused(Refusal::HardLink)
        ));
        fs::remove_file(&path).unwrap();
        assert!(matches!(key_gate(&path, &id), KeyGate::Missing));
        junction(&path, &pc.t.0);
        assert!(matches!(
            key_gate(&path, &id),
            KeyGate::Refused(Refusal::Link)
        ));
        fs::remove_dir(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(matches!(
            key_gate(&path, &id),
            KeyGate::Refused(Refusal::NotFile)
        ));
        fs::remove_dir(&path).unwrap();
        // The vault gate never takes a key request, wrapped or not.
        let outgoing = pc.dir.join(OUTGOING);
        let wrapped_vault = render_key_request(&KeyRequest::put(0, 0, &keyed(&id, 3)));
        for bytes in [&put, &cut_request, &wrapped_vault] {
            fs::write(&outgoing, bytes).unwrap();
            assert!(matches!(gate(&outgoing, Some(&id)), Gate::Refused(..)));
        }
    }

    /// KR comes before P4, and KG between them (spec v3 §7.12, §14.7-7
    /// "pass order without holds"): a request with no answer holds back
    /// only its own pass's P4 and P5; a vault at the new state that lands
    /// first gets KEY_BEHIND, and the request's answer releases it into
    /// the same pass.
    #[test]
    fn kr_and_kg_run_before_the_vault_steps() {
        let pc = pinned();
        let clock = TestClock::new();
        let file = ks(10);
        let sha = pc.request(&KeyRequest::put(0, 0, &file));
        pc.outgoing(4, &keyed(&id(), 3));
        // KR fails: KG waits for KR's answer, and P4 and P5 for KG.
        let mut e = pc.engine(mock([reply(Status::ServerError, 0, b"")]), &clock);
        assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
        assert_eq!(e.transport.ops(), [(Op::PutKey, 0)]);
        assert_eq!(e.transport.calls[0].blob, file);
        assert!(pc.view().is_none());
        // In the backoff the app writes another vault upload: sent once,
        // after KG, while the request waits; the server's floor refuses it.
        clock.advance(5);
        let v = keyed(&id(), 7);
        pc.outgoing(4, &v);
        assert!(e.due(0));
        e.transport.replies.extend([
            reply(Status::Empty, 0, b""),
            reply(Status::KeyBehind, 0, b""),
        ]);
        assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 4, None, None));
        // The request's answer releases the held upload into this pass.
        clock.advance(1);
        assert!(e.due(0));
        e.transport.replies.extend([
            reply(Status::Ok, 1, &header(0, &file)),
            reply(Status::NotModified, 1, b""),
            reply(Status::Ok, 5, b""),
        ]);
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, Some(5), None));
        assert_eq!(
            e.transport.ops(),
            [
                (Op::PutKey, 0),
                (Op::GetKey, 0),
                (Op::Put, 4),
                (Op::PutKey, 0),
                (Op::GetKey, 1),
                (Op::Put, 4),
            ]
        );
        assert_eq!(e.transport.calls[4].sha, sha256(&key_record(0, &file)));
        assert_eq!(e.transport.calls[5].blob, v);
        let view = pc.view().unwrap();
        assert_eq!((view.seq, view.line), (1, 0));
        assert_eq!(
            (view.answered, view.outcome),
            (Some(sha), KeyOutcome::Applied)
        );
        assert_eq!(view.record, key_record(0, &file));
        assert!(
            pc.log()
                .contains("the upload refused as KEY_BEHIND goes again")
        );
        // The status says this helper does key-file sync.
        assert!(pc.status().keys);
        // Answered: nothing more is due until the heartbeat.
        assert!(!e.due(0));
    }

    /// KR sends like `push` (S6-1 #13 and #21; §14.7-7): after no reply, a
    /// timeout or SERVER_ERROR the same request goes again once the backoff
    /// has passed; LIMIT holds it for RETRY_HELD in memory; an answer with
    /// outcome 3 goes again every 10 minutes and at the next helper start,
    /// never more often, and lands once the server takes it.
    #[test]
    fn kr_retries_like_push() {
        let pc = pinned();
        let clock = TestClock::new();
        let file = ks(10);
        let sha = pc.request(&KeyRequest::put(0, 0, &file));
        let mut e = quiet(&pc, mock([Err(Failure::Start)]), &clock);
        assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
        for (wait, failure, state) in [
            (30, timeout(), SyncState::Offline),
            (60, reply(Status::ServerError, 0, b""), SyncState::Server),
        ] {
            clock.advance(wait - 1);
            e.pass(0, false); // in the backoff: no call (none is scripted)
            clock.advance(1);
            assert!(e.due(0));
            e.transport.replies.push_back(failure);
            assert_eq!(e.pass(0, false), done(state, 4, None, None));
        }
        // LIMIT: held for RETRY_HELD, in memory only.
        clock.advance(120);
        e.transport.replies.push_back(reply(Status::Limit, 0, b""));
        e.pass(0, false);
        assert!(
            pc.log()
                .contains(&format!("key request held; retry in {RETRY_HELD} s"))
        );
        // The next pass fetches the view and polls; the request waits.
        e.transport.replies.extend([
            reply(Status::Empty, 0, b""),
            reply(Status::NotModified, 4, b""),
        ]);
        e.pass(0, false);
        clock.advance(RETRY_HELD - 1);
        e.pass(0, false);
        clock.advance(1);
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::Ok, 1, &header(0, &file)));
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 4, None, None));
        let sends = put_keys(&e);
        assert_eq!(sends.len(), 5);
        assert!(sends.iter().all(|c| c.version == 0 && c.blob == file));
        let view = pc.view().unwrap();
        assert_eq!(
            (view.seq, view.answered, view.outcome),
            (1, Some(sha), KeyOutcome::Applied)
        );
        // A refused key file (outcome 3, S-KEYUP-REFUSED): `refused`, sent
        // again every 10 minutes only, and at the next start.
        let next = ks(11);
        let sha = pc.request(&KeyRequest::put(1, 10, &next));
        clock.advance(1);
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::BadBlob, 0, b""));
        assert_eq!(e.pass(0, false), done(SyncState::Refused, 4, None, None));
        let view = pc.view().unwrap();
        assert_eq!(
            (view.seq, view.answered, view.outcome),
            (1, Some(sha), KeyOutcome::Refused)
        );
        assert!(!e.due(0));
        clock.advance(KEY_RETRY - 1);
        assert_eq!(e.pass(0, false), done(SyncState::Refused, 4, None, None));
        clock.advance(1);
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::TooLarge, 0, b""));
        assert_eq!(e.pass(0, false), done(SyncState::Refused, 4, None, None));
        assert_eq!(put_keys(&e).len(), 7);
        // The server script was updated and the helper starts again: sent
        // at once, and taken.
        let replies = [
            reply(Status::Ok, 2, &header(0, &next)),
            reply(Status::NotModified, 2, b""),
            reply(Status::NotModified, 4, b""),
        ];
        let mut e = quiet(&pc, mock(replies), &clock);
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 4, None, None));
        assert_eq!(
            e.transport.ops(),
            [(Op::PutKey, 1), (Op::GetKey, 2), (Op::Get, 4)]
        );
        let view = pc.view().unwrap();
        assert_eq!((view.seq, view.outcome), (2, KeyOutcome::Applied));
    }

    /// `Engine::due` (S6-1 #22, S6R1 #25): an answered request left in place
    /// while the app is closed makes no pass and opens nothing, tick after
    /// tick; an unanswered one is due only after its backoff; a changed
    /// stamp of `kreq` or `kview` is decided by the next pass.
    #[test]
    fn due_lists_the_key_files_and_opens_neither() {
        let pc = pinned();
        let clock = TestClock::new();
        let file = ks(10);
        pc.request(&KeyRequest::put(0, 0, &file));
        let replies = [
            reply(Status::Ok, 1, &header(0, &file)),
            reply(Status::NotModified, 1, b""),
            reply(Status::NotModified, 4, b""),
        ];
        let mut e = quiet(&pc, mock(replies), &clock);
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 4, None, None));
        let opens = KEY_OPENS.with(|n| n.get());
        for _ in 0..100 {
            assert!(!e.due(0));
        }
        // Two-second ticks until the heartbeat is due: nothing.
        for _ in 0..(HEARTBEAT / 2 - 1) {
            clock.advance(2);
            assert!(!e.due(0));
        }
        assert_eq!(
            KEY_OPENS.with(|n| n.get()),
            opens,
            "due() opened kreq or kview"
        );
        // A new request is due at once; after a failed send, not before the
        // backoff has passed.
        pc.request(&KeyRequest::put(1, 10, &ks(11)));
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::ServerError, 0, b""));
        assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
        let opens = KEY_OPENS.with(|n| n.get());
        for _ in 0..14 {
            clock.advance(2);
            assert!(!e.due(0));
        }
        assert_eq!(KEY_OPENS.with(|n| n.get()), opens);
        clock.advance(2);
        assert!(e.due(0));
        // A view changed behind the helper is looked at by the next pass,
        // also in the backoff.
        clock.back(2);
        let mut v = pc.view().unwrap();
        v.line = 1;
        pc.set_view(&v);
        assert!(e.due(0));
    }

    /// No key bytes after an off (S6-1 #30, S6-3 #19; rules (a)-(c) of
    /// §7.12): KG waits while this PC's CUT is unanswered; a fetched key
    /// record queued before the CUT is never written while the CUT waits
    /// (b); a later write drops a queued view (a); and a view queued for
    /// content that another engine has since replaced is dropped (c).
    #[test]
    fn no_key_record_comes_back_while_an_off_waits() {
        let pc = pinned();
        let clock = TestClock::new();
        let record = key_record(0, &ks(10));
        // (b) A fetch of the server's key record queued: the app holds
        // kview open.
        pc.set_view(&KeyView::default());
        let reader = fs::File::open(pc.dir.join(KEY_VIEW)).unwrap();
        let mut e = quiet(&pc, mock([reply(Status::Ok, 1, &record)]), &clock);
        e.pass(0, false);
        assert_eq!(
            e.transport.ops(),
            [(Op::GetKey, 0)],
            "P5 waits for the view"
        );
        assert!(
            pc.log()
                .contains("kview not written (Busy); the answer stays queued")
        );
        // The app turns key-file sync off: its CUT, then it lets go of
        // kview. The CUT fails once: still no key record, and no KG.
        let sha = pc.request(&KeyRequest::cut(1));
        drop(reader);
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::ServerError, 0, b""));
        e.pass(0, false);
        assert!(pc.log().contains("kept a fetched key record out of kview"));
        assert_eq!(pc.view(), Some(KeyView::default()));
        clock.advance(30);
        e.transport.replies.extend([
            reply(Status::Ok, 2, &cut(2, 10)),
            reply(Status::NotModified, 2, b""),
            reply(Status::NotModified, 4, b""),
        ]);
        assert!(e.due(0));
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 4, None, None));
        assert_eq!(
            e.transport.ops(),
            [
                (Op::GetKey, 0),
                (Op::CutKey, 1),
                (Op::CutKey, 1),
                (Op::GetKey, 2),
                (Op::Get, 4)
            ]
        );
        let view = pc.view().unwrap();
        assert_eq!((view.seq, view.record.clone()), (2, cut(2, 10)));
        assert_eq!(
            (view.answered, view.outcome),
            (Some(sha), KeyOutcome::Applied)
        );

        // (a) A queued fetch, then this engine's answer to a PUT: the
        // fetch is never written.
        let pc = pinned();
        pc.set_view(&KeyView::default());
        let reader = fs::File::open(pc.dir.join(KEY_VIEW)).unwrap();
        let mut e = quiet(&pc, mock([reply(Status::Ok, 1, &record)]), &clock);
        e.pass(0, false);
        let mine = ks(11);
        let sha = pc.request(&KeyRequest::put(1, 10, &mine));
        let theirs = key_record(0, &other(11, 1));
        e.transport.replies.extend([
            reply(Status::Conflict, 2, &theirs),
            reply(Status::NotModified, 2, b""),
        ]);
        e.pass(0, false);
        assert_eq!(
            e.transport.ops(),
            [(Op::GetKey, 0), (Op::PutKey, 1), (Op::GetKey, 2)]
        );
        drop(reader);
        assert!(e.due(0));
        e.transport.replies.extend([
            reply(Status::NotModified, 2, b""),
            reply(Status::NotModified, 4, b""),
        ]);
        e.pass(0, false);
        let view = pc.view().unwrap();
        assert_eq!((view.seq, view.record.clone()), (2, theirs.clone()));
        assert_eq!(
            (view.answered, view.outcome),
            (Some(sha), KeyOutcome::Conflict)
        );

        // (c) Two engines on one folder: one queues an older view, the
        // other writes a newer one; the first drops its own.
        let pc = pinned();
        pc.set_view(&KeyView::default());
        let reader = fs::File::open(pc.dir.join(KEY_VIEW)).unwrap();
        let mut daemon = quiet(&pc, mock([reply(Status::Ok, 1, &record)]), &clock);
        daemon.pass(0, false);
        drop(reader);
        let newer = key_record(0, &ks(12));
        let mut now = quiet(
            &pc,
            mock([
                reply(Status::Ok, 3, &newer),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        now.pass(0, true);
        assert_eq!(pc.view().unwrap().seq, 3);
        clock.advance(1);
        assert!(daemon.due(0));
        daemon.transport.replies.extend([
            reply(Status::NotModified, 3, b""),
            reply(Status::NotModified, 4, b""),
        ]);
        daemon.pass(0, false);
        assert_eq!(daemon.transport.calls[1].sha, sha256(&newer));
        assert_eq!(pc.view().unwrap().record, newer);
        assert!(
            pc.log()
                .contains("dropped a queued key view: kview changed since it was made")
        );
        // A second engine finds the first one's answer and sends nothing:
        // the request is answered.
        let file = ks(13);
        let sha = pc.request(&KeyRequest::put(3, 12, &file));
        let mut first = quiet(
            &pc,
            mock([
                reply(Status::Ok, 4, &header(0, &file)),
                reply(Status::NotModified, 4, b""),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        first.pass(0, false);
        assert_eq!(pc.view().unwrap().answered, Some(sha));
        let mut second = quiet(
            &pc,
            mock([
                reply(Status::NotModified, 4, b""),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        second.pass(0, false);
        assert_eq!(second.transport.ops(), [(Op::GetKey, 4), (Op::Get, 4)]);
        // While one engine holds the folder's lock the other skips.
        let lock = fs::File::options()
            .read(true)
            .write(true)
            .open(pc.dir.join(HELPER_LOCK))
            .unwrap();
        lock.try_lock().unwrap();
        assert_eq!(second.pass(0, true), Outcome::Locked);
    }

    /// `kview` is what GETKEY sends as "have" (round 3, finding 19): read
    /// at every pass, so a deleted or damaged one is fetched again whole;
    /// and a server that went back (round 4, finding 4) is written like any
    /// other answer and logged.
    #[test]
    fn kview_is_what_getkey_sends_as_have() {
        let pc = pinned();
        let clock = TestClock::new();
        let (r5, r2) = (key_record(0, &ks(12)), key_record(0, &ks(10)));
        let mut e = quiet(
            &pc,
            mock([
                reply(Status::Ok, 5, &r5),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        e.pass(0, false);
        let poll = |e: &mut Engine<Mock>, get: Result<Output, Failure>| {
            clock.advance(3600);
            e.transport
                .replies
                .extend([get, reply(Status::NotModified, 4, b"")]);
            e.pass(0, false);
            let call = &e.transport.calls[e.transport.calls.len() - 2];
            (call.version, call.sha)
        };
        assert_eq!(
            poll(&mut e, reply(Status::NotModified, 5, b"")),
            (5, sha256(&r5))
        );
        // Deleted behind the helper, then damaged: asked with nothing held.
        fs::remove_file(pc.dir.join(KEY_VIEW)).unwrap();
        assert_eq!(poll(&mut e, reply(Status::Ok, 5, &r5)), (0, [0; 32]));
        assert_eq!(pc.view().unwrap().record, r5);
        let mut damaged = render_key_view(&pc.view().unwrap());
        damaged[60] ^= 1;
        fs::write(pc.dir.join(KEY_VIEW), &damaged).unwrap();
        assert_eq!(poll(&mut e, reply(Status::Ok, 5, &r5)), (0, [0; 32]));
        assert_eq!(pc.view().unwrap().record, r5);
        // A restored server: a lower number replaces the view, logged.
        assert_eq!(poll(&mut e, reply(Status::Ok, 2, &r2)), (5, sha256(&r5)));
        assert_eq!(pc.view().unwrap().seq, 2);
        assert!(pc.log().contains("server key record went back 5->2"));
        // EMPTY: no record.
        poll(&mut e, reply(Status::Empty, 0, b""));
        assert_eq!(pc.view(), Some(KeyView::default()));
        // A malformed answer is a protocol error: the view stays.
        let bad = key_record(1, &ks(12)); // generation 1 is not below 1
        clock.advance(3600);
        e.transport.replies.push_back(reply(Status::Ok, 1, &bad));
        assert_eq!(e.pass(0, false), done(SyncState::Server, 4, None, None));
        assert_eq!(pc.view(), Some(KeyView::default()));
        assert!(pc.log().contains("frame=not a key record of this vault"));
    }

    /// The answers KR writes (spec v3 §7.12): a PUTKEY CONFLICT on a cut,
    /// and EMPTY, are recorded with outcome 2 and hold nothing; a planted
    /// `kview` whose `answered` names the request keeps it unsent; a
    /// planted CUT is sent (R33); a request gate 2 refuses shows `refused`
    /// with no pass storm, and the app's rewrite releases it (S6-2 #22).
    #[test]
    fn answers_and_planted_files() {
        let pc = pinned();
        let clock = TestClock::new();
        let file = ks(11);
        let sha = pc.request(&KeyRequest::put(3, 9, &file));
        pc.outgoing(4, &keyed(&id(), 3));
        let mut e = quiet(
            &pc,
            mock([
                reply(Status::Conflict, 4, &cut(4, 9)),
                reply(Status::NotModified, 4, b""),
                reply(Status::Ok, 5, b""),
            ]),
            &clock,
        );
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, Some(5), None));
        let view = pc.view().unwrap();
        assert_eq!((view.seq, view.record.clone()), (4, cut(4, 9)));
        assert_eq!(
            (view.answered, view.outcome),
            (Some(sha), KeyOutcome::Conflict)
        );
        let sha = pc.request(&KeyRequest::put(9, 9, &file));
        clock.advance(1);
        e.transport.replies.push_back(reply(Status::Empty, 0, b""));
        e.pass(0, false);
        let view = pc.view().unwrap();
        assert_eq!(
            (view.seq, view.answered, view.outcome),
            (0, Some(sha), KeyOutcome::Conflict)
        );
        // A planted view that says the next request was answered.
        let sha = pc.request(&KeyRequest::put(0, 0, &file));
        pc.set_view(&KeyView {
            answered: Some(sha),
            outcome: KeyOutcome::Applied,
            ..KeyView::default()
        });
        clock.advance(1);
        assert!(e.due(0));
        e.pass(0, false);
        assert!(!e.due(0));
        assert_eq!(put_keys(&e).len(), 2, "a planted answer keeps it unsent");
        // A planted CUT is sent as it is.
        pc.request(&KeyRequest::cut(EPOCH_MAX));
        clock.advance(1);
        e.transport
            .replies
            .push_back(reply(Status::Ok, 1, &cut(1, 0)));
        e.pass(0, false);
        assert_eq!(e.transport.ops().last(), Some(&(Op::CutKey, EPOCH_MAX)));
        // A zero-length request and a junction: refused, logged once, and
        // no pass storm.
        let makes: [&dyn Fn(&Path); 2] = [&|p: &Path| fs::write(p, b"").unwrap(), &|p: &Path| {
            junction(p, &pc.t.0)
        }];
        for make in makes {
            let path = pc.dir.join(KEY_REQUEST);
            let _ = fs::remove_file(&path);
            make(&path);
            clock.advance(1);
            assert!(e.due(0));
            assert_eq!(e.pass(0, false), done(SyncState::Refused, 5, None, None));
            for _ in 0..20 {
                clock.advance(2);
                assert!(!e.due(0), "a refused request makes passes");
            }
            let _ = fs::remove_dir(&path);
        }
        assert_eq!(
            pc.log()
                .matches("refused key request before sending")
                .count(),
            2
        );
        // The app's rewrite releases it.
        let file = ks(12);
        pc.request(&KeyRequest::put(1, 0, &file));
        clock.advance(1);
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::Ok, 2, &header(1, &file)));
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, None, None));
        // A PUTKEY OK whose record header names another epoch than the file
        // sent breaks the answer rules: a protocol error, and the view
        // keeps its last answer.
        let before = pc.view();
        pc.request(&KeyRequest::put(2, 12, &ks(13)));
        clock.advance(1);
        e.transport
            .replies
            .push_back(reply(Status::Ok, 3, &header(0, &ks(14))));
        assert_eq!(e.pass(0, false), done(SyncState::Server, 5, None, None));
        assert!(
            pc.log()
                .contains("PUTKEY OK names another epoch than the key file sent")
        );
        assert_eq!(pc.view(), before);
    }

    /// KEY_BEHIND in the security-key build (spec v3 §7.12, S6R2 #9): with
    /// the key view present and `line` 0 the upload goes again only when
    /// the view changes, or at helper start, never on a timer; with no
    /// view or `line` 1, hourly; a hardware vault on a line without key
    /// ops shows `nokeys`.
    #[test]
    fn key_behind_waits_for_the_key_view() {
        let pc = pinned();
        let clock = TestClock::new();
        let v = keyed(&id(), 3);
        pc.outgoing(4, &v);
        let mut e = pc.engine(
            mock([
                reply(Status::Empty, 0, b""),
                reply(Status::KeyBehind, 0, b""),
            ]),
            &clock,
        );
        assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 4, None, None));
        assert!(
            pc.log()
                .contains("upload held until the server's key record changes")
        );
        // Polls go on; the view does not change; no PUT, not even after
        // RETRY_HELD.
        for _ in 0..12 {
            clock.advance(60);
            e.transport.replies.extend([
                reply(Status::Empty, 0, b""),
                reply(Status::NotModified, 4, b""),
            ]);
            assert!(e.due(0));
            assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 4, None, None));
        }
        assert_eq!(
            e.transport.calls.iter().filter(|c| c.op == Op::Put).count(),
            1
        );
        // The server's key record changes: KG writes it and the held upload
        // goes in the same pass.
        clock.advance(60);
        let file = ks(10);
        e.transport.replies.extend([
            reply(Status::Ok, 1, &key_record(0, &file)),
            reply(Status::Ok, 5, b""),
        ]);
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 5, Some(5), None));
        assert_eq!(
            e.transport.ops()[e.transport.calls.len() - 2..],
            [(Op::GetKey, 0), (Op::Put, 4)]
        );
        // At helper start a held upload goes at once.
        let v2 = keyed(&id(), 5);
        pc.outgoing(5, &v2);
        clock.advance(1);
        e.transport.replies.extend([
            reply(Status::NotModified, 1, b""),
            reply(Status::KeyBehind, 0, b""),
        ]);
        assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 5, None, None));
        let mut e = pc.engine(
            mock([
                reply(Status::NotModified, 1, b""),
                reply(Status::Ok, 6, b""),
            ]),
            &clock,
        );
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 6, Some(6), None));
        // A line without key ops: a hardware vault's KEY_BEHIND is
        // `nokeys`, and goes again hourly.
        pc.set_view(&KeyView {
            line: 1,
            ..pc.view().unwrap()
        });
        let v3 = keyed(&id(), 1);
        pc.outgoing(6, &v3);
        let mut e = quiet(
            &pc,
            mock([
                reply(Status::BadRequest, 0, b""),
                reply(Status::KeyBehind, 0, b""),
            ]),
            &clock,
        );
        assert_eq!(e.pass(0, false), done(SyncState::NoKeys, 6, None, None));
        assert!(
            pc.log()
                .contains(&format!("upload held; retry in {BEHIND_HOURLY} s"))
        );
        clock.advance(BEHIND_HOURLY - 1);
        e.transport.replies.extend([
            reply(Status::BadRequest, 0, b""),
            reply(Status::NotModified, 6, b""),
        ]);
        assert_eq!(e.pass(0, false), done(SyncState::NoKeys, 6, None, None));
        assert_eq!(
            e.transport.ops(),
            [(Op::GetKey, 1), (Op::Put, 6), (Op::GetKey, 1), (Op::Get, 6)]
        );
        clock.advance(1);
        e.transport
            .replies
            .push_back(reply(Status::KeyBehind, 0, b""));
        assert!(e.due(0));
        e.pass(0, false);
        assert_eq!(
            e.transport.calls.iter().filter(|c| c.op == Op::Put).count(),
            2
        );
    }

    /// A line without key ops (S6-1 #18 and #20; §14.7-7; spec §2.29
    /// (sync)): KR's answer has outcome 4 and `line` 1; `nokeys` for a vault
    /// that uses key-file sync; KR goes again at start, every two minutes
    /// and at once when the app writes the request again, KG for a vault
    /// that does not use key-file sync at start and every 10 minutes; P3-P5
    /// keep running without a backoff.
    #[test]
    fn a_line_without_key_ops_shows_nokeys() {
        let pc = pinned();
        let clock = TestClock::new();
        let file = ks(10);
        let sha = pc.request(&KeyRequest::put(0, 0, &file));
        let mut e = pc.engine(
            mock([
                reply(Status::BadRequest, 0, b""),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        assert_eq!(e.pass(0, false), done(SyncState::NoKeys, 4, None, None));
        assert_eq!(e.transport.ops(), [(Op::PutKey, 0), (Op::Get, 4)]);
        let view = pc.view().unwrap();
        assert_eq!(
            (view.line, view.answered, view.outcome),
            (1, Some(sha), KeyOutcome::NoKeyOps)
        );
        assert_eq!(pc.status().state, Some(SyncState::NoKeys));
        // Polls go on; key ops wait for their two minutes.
        assert_eq!(LINE_RETRY, 120);
        for _ in 0..2 {
            clock.advance(59);
            e.transport
                .replies
                .push_back(reply(Status::NotModified, 4, b""));
            assert_eq!(e.pass(0, false), done(SyncState::NoKeys, 4, None, None));
        }
        assert_eq!(put_keys(&e).len(), 1);
        clock.advance(2); // 120 s after the answer: KR's retry alone
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::BadRequest, 0, b""));
        e.pass(0, false);
        assert_eq!(put_keys(&e).len(), 2);
        assert!(e.transport.replies.is_empty());
        // The app writes the same request again (a retry): due and sent at
        // once, before its two minutes.
        clock.advance(5);
        assert!(!e.due(0));
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(pc.request(&KeyRequest::put(0, 0, &file)), sha);
        assert!(e.due(0));
        e.transport
            .replies
            .push_back(reply(Status::BadRequest, 0, b""));
        assert_eq!(e.pass(0, false), done(SyncState::NoKeys, 4, None, None));
        assert_eq!(put_keys(&e).len(), 3);
        // The admin adds the vault to the line: the next start sends it.
        let mut e = pc.engine(
            mock([
                reply(Status::Ok, 1, &header(0, &file)),
                reply(Status::NotModified, 1, b""),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 4, None, None));
        assert_eq!(pc.view().unwrap().line, 0);
        // KG on a line without key ops: at start and every 10 minutes only.
        fs::remove_file(pc.dir.join(KEY_REQUEST)).unwrap();
        let mut e = pc.engine(
            mock([
                reply(Status::BadRequest, 0, b""),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        e.pass(0, false);
        assert_eq!(pc.view().unwrap().line, 1);
        for _ in 0..9 {
            clock.advance(60);
            e.transport
                .replies
                .push_back(reply(Status::NotModified, 4, b""));
            e.pass(0, false);
        }
        clock.advance(60);
        e.transport.replies.extend([
            reply(Status::NotModified, 1, b""),
            reply(Status::NotModified, 4, b""),
        ]);
        e.pass(0, false);
        let gets: Vec<_> = e
            .transport
            .ops()
            .into_iter()
            .filter(|o| o.0 == Op::GetKey)
            .collect();
        assert_eq!(gets, [(Op::GetKey, 1), (Op::GetKey, 1)]);
        assert_eq!(
            pc.view().unwrap().line,
            0,
            "NOT_MODIFIED on a line that serves key ops again"
        );
    }

    /// KG's cadence (review finding 34; S6R1 #22; S6R2 #1): in every pass
    /// where P5 runs, also with no request at all; before every vault
    /// upload; never while this PC's CUT is unanswered.
    #[test]
    fn kg_runs_where_p5_runs_and_before_every_upload() {
        let pc = pinned();
        let clock = TestClock::new();
        let mut e = pc.engine(
            mock([
                reply(Status::Empty, 0, b""),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        e.pass(0, false);
        assert_eq!(e.transport.ops(), [(Op::GetKey, 0), (Op::Get, 4)]);
        // Each edit's upload is preceded by a fetch (S6R2 #1: no vault copy
        // reaches the app before the cut it came with).
        for n in 0..5u64 {
            clock.advance(1);
            pc.outgoing(4 + n, &keyed(&id(), 10 + n as u8));
            e.transport
                .replies
                .extend([reply(Status::Empty, 0, b""), reply(Status::Ok, 5 + n, b"")]);
            assert!(e.due(0));
            e.pass(0, false);
        }
        let ops = e.transport.ops();
        assert_eq!(ops.len(), 12);
        for pair in ops[2..].chunks(2) {
            assert_eq!((pair[0].0, pair[1].0), (Op::GetKey, Op::Put));
        }
        // An unanswered CUT: no GETKEY, and the vault steps still run.
        pc.request(&KeyRequest::cut(0));
        clock.advance(60);
        e.transport
            .replies
            .push_back(reply(Status::ServerError, 0, b""));
        e.pass(0, false);
        clock.advance(5);
        pc.outgoing(9, &keyed(&id(), 30));
        e.transport.replies.push_back(reply(Status::Ok, 10, b""));
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 10, Some(10), None));
        clock.advance(60);
        e.transport.replies.extend([
            reply(Status::Ok, 1, &cut(1, 0)),
            reply(Status::NotModified, 1, b""),
            reply(Status::NotModified, 10, b""),
        ]);
        e.pass(0, false);
        let tail = e.transport.ops()[12..].to_vec();
        assert_eq!(
            tail,
            [
                (Op::CutKey, 0),
                (Op::Put, 9),
                (Op::CutKey, 0),
                (Op::GetKey, 1),
                (Op::Get, 10)
            ]
        );
    }

    /// The order rule for a fetched copy (S6R2 #1): a copy that P5 brings
    /// is written to incoming only after a GETKEY made after the GET, so a
    /// cut that landed between KG and P5 is in `kview` before the copy is
    /// in incoming. When that GETKEY fails, the copy is not written and the
    /// next poll fetches it again.
    #[test]
    fn a_fetched_copy_waits_for_a_getkey_after_it() {
        let pc = pinned();
        let clock = TestClock::new();
        let copy = keyed(&id(), 7);
        let mut e = pc.engine(
            mock([
                reply(Status::Ok, 1, &key_record(0, &ks(9))),
                reply(Status::Ok, 5, &copy),
                reply(Status::Ok, 2, &cut(2, 9)),
            ]),
            &clock,
        );
        e.pass(0, true);
        assert_eq!(
            e.transport.ops(),
            [(Op::GetKey, 0), (Op::Get, 4), (Op::GetKey, 1)]
        );
        assert_eq!(pc.view().unwrap().record, cut(2, 9));
        assert_eq!(pc.incoming(), Some((5, copy.clone())));
        // The GETKEY after the copy fails: the copy waits for a later poll.
        let next = keyed(&id(), 8);
        clock.advance(120);
        e.transport.replies.extend([
            reply(Status::NotModified, 2, b""),
            reply(Status::Ok, 6, &next),
            reply(Status::ServerError, 0, b""),
        ]);
        e.pass(0, true);
        assert_eq!(pc.incoming(), Some((5, copy)));
        clock.advance(600);
        e.transport.replies.extend([
            reply(Status::NotModified, 2, b""),
            reply(Status::Ok, 6, &next),
            reply(Status::NotModified, 2, b""),
        ]);
        e.pass(0, true);
        assert_eq!(pc.incoming(), Some((6, next)));
        assert_eq!(
            e.transport.ops()[3..],
            [
                (Op::GetKey, 2),
                (Op::Get, 5),
                (Op::GetKey, 2),
                (Op::GetKey, 2),
                (Op::Get, 5),
                (Op::GetKey, 2)
            ]
        );
    }

    /// A refusal of this PC's key file (BAD_BLOB) over a missing `kview`
    /// carries no top of its own: it is written with the top a GETKEY gets
    /// at once, never as `seq` 0 (an empty namespace, which a GOYOKS01 PC
    /// would read as KeySyncGone).
    #[test]
    fn a_refusal_over_no_view_is_written_with_the_top() {
        let pc = pinned();
        let clock = TestClock::new();
        let mut e = quiet(
            &pc,
            mock([
                reply(Status::Ok, 1, &key_record(0, &ks(9))),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        e.pass(0, true);
        // The view is lost (an antivirus); the request goes in a pass with
        // no poll, so no KG of its own follows.
        fs::remove_file(pc.dir.join(KEY_VIEW)).unwrap();
        let sha = pc.request(&KeyRequest::put(1, 9, &ks(10)));
        clock.advance(1);
        e.transport.replies.extend([
            reply(Status::BadBlob, 0, b""),
            reply(Status::Ok, 1, &key_record(0, &ks(9))),
        ]);
        assert!(e.due(0));
        e.pass(0, false);
        assert_eq!(e.transport.ops()[2..], [(Op::PutKey, 1), (Op::GetKey, 0)]);
        let view = pc.view().unwrap();
        assert_eq!(
            (view.seq, view.line, view.answered, view.outcome),
            (1, 0, Some(sha), KeyOutcome::Refused)
        );
        assert_eq!(view.record, key_record(0, &ks(9)));
    }

    /// A `kview` that can never be written (a folder planted under its
    /// name): after `VIEW_STUCK` failed writes the vault shows `config`;
    /// since the app then reads no view at all, the vault steps go on.
    #[test]
    fn an_unwritable_key_view_shows_and_does_not_stop_the_vault() {
        let pc = pinned();
        let clock = TestClock::new();
        fs::create_dir(pc.dir.join(KEY_VIEW)).unwrap();
        let mut e = pc.engine(Mock::default(), &clock);
        e.transport.keys = true;
        for _ in 0..VIEW_STUCK {
            e.transport.replies.extend([
                reply(Status::Ok, 1, &key_record(0, &ks(9))),
                reply(Status::NotModified, 4, b""),
            ]);
            clock.advance(120);
            e.pass(0, true);
        }
        let ops = e.transport.ops();
        assert_eq!(
            ops.iter().filter(|o| o.0 == Op::Get).count() as u32,
            VIEW_STUCK
        );
        assert_eq!(pc.status().state, Some(SyncState::Config));
    }

    /// KP (spec v3 §7.12, §7.19): sent once the vault head has reached the
    /// request's epoch; OK or NOT_FOUND deletes the request; BAD_REQUEST
    /// holds it for 10 minutes without the backoff; another vault's
    /// request is left alone.
    #[test]
    fn prune_requests_wait_for_the_head() {
        let pc = Pc::with_folder();
        let clock = TestClock::new();
        let head = |epoch: u64| {
            let mut v = keyed(&id(), 3);
            v[40..48].copy_from_slice(&epoch.to_le_bytes());
            seed_incoming(&pc, id(), 4, &v);
        };
        head(7);
        replace_file(&pc.dir.join(PRUNE_REQUEST), &render_prune_request(&id(), 9)).unwrap();
        let mut e = quiet(
            &pc,
            mock([
                reply(Status::Empty, 0, b""),
                reply(Status::NotModified, 4, b""),
            ]),
            &clock,
        );
        e.pass(0, false);
        assert_eq!(e.transport.ops(), [(Op::GetKey, 0), (Op::Get, 4)]);
        head(9);
        clock.advance(1);
        e.transport
            .replies
            .push_back(reply(Status::BadRequest, 0, b""));
        e.pass(0, false);
        assert_eq!(e.transport.ops().last(), Some(&(Op::Prune, 9)));
        clock.advance(KEY_RETRY - 1);
        e.pass(0, false);
        clock.advance(1);
        e.transport.replies.push_back(reply(Status::Ok, 3, b""));
        e.pass(0, false);
        assert_eq!(
            e.transport
                .ops()
                .iter()
                .filter(|o| o.0 == Op::Prune)
                .count(),
            2
        );
        assert!(!pc.dir.join(PRUNE_REQUEST).exists());
        assert!(
            pc.log()
                .contains("server pruned 3 vault versions below epoch 9")
        );
        // Another vault's request: left alone, logged once.
        replace_file(
            &pc.dir.join(PRUNE_REQUEST),
            &render_prune_request(&[0x77; 16], 2),
        )
        .unwrap();
        for _ in 0..3 {
            clock.advance(1);
            e.pass(0, false);
        }
        assert!(pc.dir.join(PRUNE_REQUEST).exists());
        assert_eq!(pc.log().matches("prune.request ignored").count(), 1);
    }

    /// The server script run locally with `--key-sync` naming `ids` (none:
    /// the flag is left out), one process per request.
    pub(crate) struct KeyLocal {
        pub(crate) root: PathBuf,
        pub(crate) ids: Vec<[u8; 16]>,
    }
    impl Transport for KeyLocal {
        fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
            let mut command = python_command();
            command
                .arg("-I")
                .arg(server_script())
                .args(["serve", "--root"])
                .arg(&self.root);
            if !self.ids.is_empty() {
                let ids: Vec<String> = self.ids.iter().map(|id| syncfile::hex(id)).collect();
                command.arg(format!("--key-sync={}", ids.join(",")));
            }
            run_bounded(command, request, Duration::from_secs(60), &mut |d| {
                beat();
                no_stop(d)
            })
        }
    }
    /// Every file the server stores under `root`, by path.
    fn stored(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for e in fs::read_dir(&dir).into_iter().flatten().flatten() {
                if e.file_type().unwrap().is_dir() {
                    dirs.push(e.path());
                } else {
                    out.push((e.path(), fs::read(e.path()).unwrap()));
                }
            }
        }
        out
    }
    fn records(root: &Path) -> Vec<String> {
        let k = root.join(syncfile::hex(&id())).join("k");
        let mut names: Vec<String> = fs::read_dir(k)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".rec"))
            .collect();
        names.sort();
        names
    }

    /// The key steps against the real server script (spec v3 §7.12-§7.13,
    /// §14.7-7 idempotence and "a line without key ops"): a first upload
    /// and the vault at its state; a lost `kview` and a lost reply each
    /// cost one resend, answered CONFLICT with this PC's own file and no
    /// extra record; the floor holds a vault at an older state until it is
    /// rewritten; a CUT, and its replay, end the generation, after which
    /// any GOYOVA04 passes; a line without `--key-sync` answers outcome 4
    /// and shows `nokeys` while the vault channel goes on. No stored file
    /// is a password-only or local key file, and at most two key files are
    /// kept.
    #[test]
    fn end_to_end_key_requests_with_the_real_server() {
        if !python() {
            return;
        }
        let server = Temp::new("keyserver");
        let root = server.0.join("data");
        let clock = TestClock::new();
        let a = Pc::with_folder();
        let local = |ids: Vec<[u8; 16]>| KeyLocal {
            root: root.clone(),
            ids,
        };
        let mut e = quiet(&a, local(vec![id()]), &clock);
        // KeySyncOn's S4: the key file and the vault at its state.
        let (f10, f11) = (ks(10), ks(11));
        let sha = a.request(&KeyRequest::put(0, 0, &f10));
        a.outgoing(0, &floor_vault(&f10, 1));
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 1, Some(1), None));
        let view = a.view().unwrap();
        assert_eq!(
            (view.seq, view.answered, view.outcome),
            (1, Some(sha), KeyOutcome::Applied)
        );
        assert_eq!(view.record, key_record(0, &f10));
        assert_eq!(records(&root).len(), 1);
        // kview lost after an applied PUT: one resend, CONFLICT carrying
        // this PC's own file, no new record.
        fs::remove_file(a.dir.join(KEY_VIEW)).unwrap();
        clock.advance(1);
        assert!(e.due(0));
        e.pass(0, false);
        let view = a.view().unwrap();
        assert_eq!((view.seq, view.outcome), (1, KeyOutcome::Conflict));
        assert_eq!(view.record, key_record(0, &f10));
        assert_eq!(records(&root).len(), 1);
        // A reply lost: the next request committed by an earlier attempt.
        let sha = a.request(&KeyRequest::put(1, 10, &f11));
        let direct = Request::put_key(id(), 1, &f11).unwrap().encode();
        let out = local(vec![id()]).exchange(&direct, &mut || {}).unwrap();
        let (r, _) = Response::decode(&out.stdout, Op::PutKey, &id(), 1).unwrap();
        assert_eq!((r.status, r.version), (Status::Ok, 2));
        clock.advance(1);
        // The vault at the old state waits behind the floor meanwhile.
        a.outgoing(1, &floor_vault(&f10, 2));
        assert_eq!(e.pass(0, false), done(SyncState::KeyFile, 1, None, None));
        let view = a.view().unwrap();
        assert_eq!(
            (view.seq, view.answered, view.outcome),
            (2, Some(sha), KeyOutcome::Conflict)
        );
        assert_eq!(view.record, key_record(0, &f11));
        assert_eq!(records(&root).len(), 2, "the previous key file and the top");
        // The app rewrites the vault under the new state: it lands.
        clock.advance(1);
        a.outgoing(1, &floor_vault(&f11, 3));
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 2, Some(2), None));
        // The off: a CUT on record 2; then the same CUT again after a lost
        // view, which changes nothing.
        let sha = a.request(&KeyRequest::cut(2));
        clock.advance(1);
        e.pass(0, false);
        let view = a.view().unwrap();
        assert_eq!(
            (view.seq, view.answered, view.outcome),
            (3, Some(sha), KeyOutcome::Applied)
        );
        assert_eq!(view.record, cut(3, 11));
        fs::remove_file(a.dir.join(KEY_VIEW)).unwrap();
        clock.advance(1);
        e.pass(0, false);
        assert_eq!(a.view().unwrap().record, cut(3, 11));
        assert_eq!(records(&root).len(), 1, "only the cut");
        // No floor after a cut: a vault under any state lands.
        clock.advance(1);
        a.outgoing(2, &floor_vault(&f10, 4));
        assert_eq!(e.pass(0, false), done(SyncState::Ok, 3, Some(3), None));

        // B's forced command has no --key-sync: its request is answered
        // with outcome 4, `nokeys` shows, and the vault channel goes on.
        let b = Pc::with_folder();
        seed_incoming(&b, id(), 3, &floor_vault(&f10, 4));
        let sha = b.request(&KeyRequest::put(3, 11, &ks(12)));
        let mut eb = quiet(&b, local(Vec::new()), &clock);
        assert_eq!(eb.pass(0, false), done(SyncState::NoKeys, 3, None, None));
        let view = b.view().unwrap();
        assert_eq!(
            (view.line, view.answered, view.outcome),
            (1, Some(sha), KeyOutcome::NoKeyOps)
        );
        assert_eq!(eb.pass(0, true), done(SyncState::NoKeys, 3, None, None));
        assert!(b.log().contains("GET NOT_MODIFIED"));
        // Gate 3 and the end check: no password-only or local key file was
        // ever stored, GOYOKS01 only in k/, at most two key files.
        let files = stored(&root);
        assert!(!files.is_empty());
        for (path, data) in &files {
            assert!(
                !data.starts_with(b"GOYOKE") && !data.starts_with(b"GOYOKH"),
                "{path:?}"
            );
            let in_k = path.parent().is_some_and(|p| p.ends_with("k"));
            let holds_ks = data.windows(8).any(|w| w == b"GOYOKS01");
            assert!(!holds_ks || in_k, "{path:?}");
        }
        let payloads = files
            .iter()
            .filter(|(p, d)| p.parent().is_some_and(|p| p.ends_with("k")) && d.len() > 32)
            .count();
        assert!(payloads <= 2);
    }

    /// Gate 3 against the strict parse (S6-1 #25, S6-2 #19; §14.7-7): each
    /// GOYOKS01 file, the fixture and its changed copies, is sent by
    /// PUTKEY(0) to the real script on a fresh root of its own, with
    /// `--key-sync` naming the fixture's vault. The script refuses it as
    /// "not a GOYOKS01 key file of this vault" exactly when
    /// `is_sync_key_file` refuses it; a file both accept is stored when its
    /// epoch is within EPOCH_WINDOW and refused with the window reason
    /// otherwise.
    #[test]
    fn gate_3_judges_key_files_as_the_strict_parse_does() {
        if !python() {
            return;
        }
        let id = id();
        let mut cases: Vec<Vec<u8>> = [
            9,
            EPOCH_WINDOW,
            EPOCH_WINDOW + 1,
            EPOCH_MAX,
            EPOCH_MAX + 1,
            0,
        ]
        .into_iter()
        .map(ks)
        .collect();
        for at in (0..128)
            .chain((128..1300).step_by(5))
            .chain((1300..KS.len()).step_by(41))
        {
            for flip in [0x01u8, 0x80] {
                if at >= 128 && flip == 0x80 {
                    continue;
                }
                let mut f = KS.to_vec();
                f[at] ^= flip;
                cases.push(f);
            }
        }
        cases.push(KS[..KS.len() - 1].to_vec());
        cases.push([KS, &[0]].concat());
        let server = Temp::new("gate3");
        let next = AtomicU32::new(0);
        let results: Vec<(usize, Status, String)> = std::thread::scope(|s| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        let mut mine = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                            let Some(f) = cases.get(i) else {
                                return mine;
                            };
                            let mut local = KeyLocal {
                                root: server.0.join(format!("r{i}")),
                                ids: vec![id],
                            };
                            let request = Request {
                                op: Op::PutKey,
                                vault_id: id,
                                version: 0,
                                blob_sha: sha256(f),
                                blob: f,
                            };
                            let out = local.exchange(&request.encode(), &mut || {}).unwrap();
                            let (r, _) = Response::decode(&out.stdout, Op::PutKey, &id, 0).unwrap();
                            let err = String::from_utf8_lossy(&out.stderr).into_owned();
                            mine.push((i, r.status, err));
                        }
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|w| w.join().unwrap())
                .collect()
        });
        assert_eq!(results.len(), cases.len());
        let (mut refused, mut stored) = (0, 0);
        for (i, status, err) in results {
            let f = &cases[i];
            let grammar = err.contains("not a GOYOKS01 key file of this vault");
            match is_sync_key_file(f, &id) {
                None => {
                    assert!(
                        status == Status::BadBlob && grammar,
                        "case {i}: {status:?} {err}"
                    );
                    refused += 1;
                }
                Some(s) if s.epoch <= EPOCH_WINDOW => {
                    assert_eq!(status, Status::Ok, "case {i}: {err}");
                    stored += 1;
                }
                Some(_) => {
                    let window = err.contains("epoch window");
                    assert!(
                        status == Status::BadBlob && window,
                        "case {i}: {status:?} {err}"
                    );
                }
            }
        }
        assert!(
            refused > 100 && stored > 50,
            "{refused} refused, {stored} stored"
        );
    }
}
