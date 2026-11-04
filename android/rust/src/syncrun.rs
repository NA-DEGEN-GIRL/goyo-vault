//! Sync on the phone: the settings, the pinned host key, and the runs of
//! the shared engine (`goyo_vault::syncengine`, the Windows helper's own
//! passes) over the Android transport. A run only moves encrypted files
//! between the server and the vault's sync folder (`vault.goyo.sync`); it
//! never opens the vault or the key file, so the background worker can run
//! it while the vault is locked. The open vault merges and uploads through
//! the session's own `poll_sync`, as goyo-vault.exe does on a PC.
//!
//! Files, all in the app's private storage (`<files>`):
//! `sync/settings` (host, port, user, script path, Python command),
//! `sync/host_key` (the pin), `sync/goyo-sync.log` (one line per event, as
//! goyo-sync.log; no file contents, no secrets), `sync/result` (the last
//! run's state for the badge). The client key's wrapped form and public
//! line are the app's (Keystore, Kotlin).
use crate::{
    hostkey::{self, Pin},
    line,
    ssh::{AndroidTransport, Problem, Target},
};
use goyo_vault::{
    syncengine::{self, Engine, Folder, Log, Outcome},
    syncfile::{self, SyncState},
    syncwire::{HELLO_ECHO, Request, Status, parse_list},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};
use zeroize::Zeroizing;

const SETTINGS_HEADER: &str = "goyo-android-sync 1";
const MAX_SETTINGS: u64 = 4096;

/// The phone's sync settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub remote: String,
    pub python: String,
}
impl Settings {
    /// The checked settings; Err names the first bad field in Korean.
    pub fn new(
        host: &str,
        port: &str,
        user: &str,
        remote: &str,
        python: &str,
    ) -> Result<Self, &'static str> {
        let (host, user, remote, python) = (host.trim(), user.trim(), remote.trim(), python.trim());
        if !line::host(host) {
            return Err(
                "서버 주소는 Tailscale 이름(예: my-server.tail1234.ts.net)이나 100.x 주소만 적으세요(영문·숫자·. - _).",
            );
        }
        let port = match port.trim() {
            "" => line::DEFAULT_PORT,
            p => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or("포트는 1~65535의 숫자입니다.")?,
        };
        if !line::user(user) {
            return Err("사용자 이름은 영문·숫자·. _ - 만 됩니다.");
        }
        let remote = if remote.is_empty() {
            line::DEFAULT_REMOTE
        } else {
            remote
        };
        if !line::remote(remote) {
            return Err(
                "서버의 스크립트 경로는 영문·숫자·. _ / ~ + - 만 되고 . 이나 .. 칸은 안 됩니다.",
            );
        }
        let python = if python.is_empty() {
            line::DEFAULT_PYTHON
        } else {
            python
        };
        if !line::python(python) {
            return Err("파이썬 명령은 영문·숫자·. _ / + - 만 됩니다.");
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            user: user.to_owned(),
            remote: remote.to_owned(),
            python: python.to_owned(),
        })
    }
    pub fn render(&self) -> String {
        format!(
            "{SETTINGS_HEADER}\nhost={}\nport={}\nuser={}\nremote={}\npython={}\n",
            self.host, self.port, self.user, self.remote, self.python
        )
    }
    pub fn parse(text: &str) -> Option<Self> {
        let mut lines = text.strip_suffix('\n')?.split('\n');
        if lines.next()? != SETTINGS_HEADER {
            return None;
        }
        let mut field = |name: &str| lines.next()?.strip_prefix(name).map(str::to_owned);
        let (host, port, user, remote, python) = (
            field("host=")?,
            field("port=")?,
            field("user=")?,
            field("remote=")?,
            field("python=")?,
        );
        if lines.next().is_some() {
            return None;
        }
        Self::new(&host, &port, &user, &remote, &python).ok()
    }
    pub fn target(&self) -> Target {
        Target {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            command: line::serve_command(&self.python, &self.remote).unwrap_or_default(),
            timeout: Duration::from_secs(line::DEFAULT_TIMEOUT),
        }
    }
}

/// The app's files.
pub struct Paths {
    pub sync: PathBuf,
    pub vault: PathBuf,
}
impl Paths {
    pub fn new(root: &Path) -> Self {
        Self {
            sync: root.join("sync"),
            vault: root.join("vault").join("vault.goyo"),
        }
    }
    fn settings(&self) -> PathBuf {
        self.sync.join("settings")
    }
    fn pin(&self) -> PathBuf {
        self.sync.join("host_key")
    }
    fn log(&self) -> Log {
        Log::new(Some(self.sync.join("goyo-sync.log")))
    }
    fn result(&self) -> PathBuf {
        self.sync.join("result")
    }
    fn make(&self) -> Result<(), String> {
        fs::create_dir_all(&self.sync).map_err(|_| "동기화 폴더를 만들 수 없습니다.".to_owned())
    }
}

pub fn load_settings(paths: &Paths) -> Option<Settings> {
    let path = paths.settings();
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SETTINGS {
        return None;
    }
    Settings::parse(&fs::read_to_string(path).ok()?)
}
pub fn save_settings(paths: &Paths, settings: &Settings) -> Result<(), String> {
    paths.make()?;
    syncfile::replace_file(&paths.settings(), settings.render().as_bytes())
        .map_err(|_| "설정을 저장하지 못했습니다.".to_owned())
}
pub fn load_pin(paths: &Paths) -> Option<Pin> {
    hostkey::load(&paths.pin())
}
pub fn forget_pin(paths: &Paths) -> Result<(), String> {
    match fs::remove_file(paths.pin()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("고정된 호스트 키를 지우지 못했습니다.".to_owned()),
    }
}
/// The vault's ID from its plaintext header (GOYOVA01 to 08), for the
/// line's `--key-sync=`; None without an imported vault.
pub fn vault_id(paths: &Paths) -> Option<[u8; 16]> {
    use std::io::Read;
    let mut head = [0u8; 24];
    fs::File::open(&paths.vault)
        .ok()?
        .read_exact(&mut head)
        .ok()?;
    // GOYOVA05 to 08 (0.12.0, entries with OTP secrets) keep the header
    // of 01 to 04.
    if !(head.starts_with(b"GOYOVA0") && (b'1'..=b'8').contains(&head[7])) {
        return None;
    }
    let id: [u8; 16] = head[8..24].try_into().ok()?;
    (id != [0; 16]).then_some(id)
}

/// A host key the user may confirm: the last one an unpinned host showed.
#[derive(Clone)]
struct Offered {
    host: String,
    port: u16,
    blob: Vec<u8>,
}
static OFFERED: Mutex<Option<Offered>> = Mutex::new(None);
/// Pins the key the last unknown host showed, if `fingerprint` is its
/// fingerprint and the settings still name that host: what the user saw on
/// the confirmation screen is exactly what is pinned.
pub fn pin_offered(paths: &Paths, fingerprint: &str) -> Result<(), String> {
    let settings = load_settings(paths).ok_or("동기화 설정이 없습니다.")?;
    let offered = OFFERED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("확인할 호스트 키가 없습니다. 연결 확인을 다시 하세요.")?;
    if offered.host != settings.host
        || offered.port != settings.port
        || hostkey::fingerprint(&offered.blob) != fingerprint
    {
        return Err(
            "서버 설정이나 호스트 키가 그사이 바뀌었습니다. 연결 확인을 다시 하세요.".into(),
        );
    }
    if load_pin(paths).is_some_and(|p| p.host == offered.host && p.port == offered.port) {
        return Err(
            "이 서버에는 이미 고정된 호스트 키가 있습니다. 바꾸려면 설정에서 먼저 지우세요.".into(),
        );
    }
    let pin = hostkey::pin_for(&offered.host, offered.port, &offered.blob)
        .ok_or("이 종류의 호스트 키는 쓸 수 없습니다.")?;
    paths.make()?;
    syncfile::replace_file(&paths.pin(), hostkey::render(&pin).as_bytes())
        .map_err(|_| "호스트 키를 저장하지 못했습니다.".to_owned())?;
    *OFFERED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    paths.log().line(&format!(
        "pinned the host key of {}:{} ({fingerprint})",
        offered.host, offered.port
    ));
    Ok(())
}

/// What the app shows for a run or a check: a state word, a Korean text,
/// and the host key's fingerprint when the state is about one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    pub state: &'static str,
    pub text: String,
    pub fingerprint: String,
}
impl Shown {
    fn new(state: &'static str, text: impl Into<String>) -> Self {
        Self {
            state,
            text: text.into(),
            fingerprint: String::new(),
        }
    }
}
/// The transport's own reason first (Tailscale, host key), else the
/// engine's state.
fn shown(problem: Option<&Problem>, state: SyncState, host: &str, detail: &str) -> Shown {
    match problem {
        Some(Problem::NoKey) => {
            return Shown::new(
                "nokey",
                "이 휴대폰의 동기화 키가 없습니다. 설정에서 키를 만드세요.",
            );
        }
        Some(Problem::Tailnet(r)) => return Shown::new("tailnet", r.text(host)),
        Some(Problem::NotTunnel(local)) => {
            return Shown::new(
                "tailnet",
                format!(
                    "휴대폰 쪽 주소({})가 Tailscale 주소가 아니라 연결을 끊었습니다. Tailscale이 켜져 있는지 확인하세요.",
                    local.ip()
                ),
            );
        }
        Some(Problem::HostUnknown { blob }) => {
            return Shown {
                state: "hostkey-unknown",
                text: "처음 연결하는 서버입니다. 설정의 '연결 확인'에서 호스트 키 지문을 확인하고 받으세요.".into(),
                fingerprint: hostkey::fingerprint(blob),
            };
        }
        Some(Problem::HostChanged { blob }) => {
            return Shown {
                state: "hostkey-changed",
                text: "경고: 서버의 호스트 키가 고정된 키와 다릅니다. 누군가 연결을 가로채고 있을 수 있어 연결하지 않았습니다. 서버를 다시 설치한 것이 확실할 때만, 서버에서 직접 지문을 확인한 뒤 설정에서 고정된 키를 지우세요.".into(),
                fingerprint: hostkey::fingerprint(blob),
            };
        }
        _ => {}
    }
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(" ({detail})")
    };
    match state {
        SyncState::Ok => Shown::new("ok", "동기화 정상"),
        SyncState::Idle => Shown::new("idle", "금고를 열면 동기화를 켤지 묻습니다."),
        SyncState::Offline => Shown::new(
            "offline",
            format!(
                "서버에 닿지 않습니다(오프라인){detail}. Tailscale과 서버가 켜져 있는지 확인하세요."
            ),
        ),
        SyncState::Auth => Shown::new(
            "auth",
            "서버가 이 휴대폰의 키를 받지 않습니다. PC의 goyo-sync 설정 창 'Android 기기 추가'로 이 휴대폰의 줄을 넣으세요.",
        ),
        SyncState::HostKey => Shown::new("hostkey-unknown", "호스트 키 확인이 필요합니다."),
        SyncState::NoSsh | SyncState::Server => Shown::new(
            "server",
            format!(
                "서버 오류{detail}. 서버 스크립트가 설치되어 있는지 PC에서 '서버에 설치·업데이트'로 확인하세요."
            ),
        ),
        SyncState::Refused => Shown::new(
            "refused",
            "업로드가 거부되었습니다. 이 금고나 열쇠 파일을 서버가 받지 않습니다.",
        ),
        SyncState::Config => Shown::new("config", "동기화 폴더에 문제가 있습니다."),
        SyncState::Update => Shown::new(
            "update",
            "서버에 더 새 형식이 있습니다. 앱을 업데이트하세요.",
        ),
        SyncState::OldServer => Shown::new(
            "oldserver",
            "서버의 goyo-sync 스크립트가 0.9.0보다 오래되었습니다. PC에서 '서버에 설치·업데이트'를 누르세요.",
        ),
        SyncState::KeyFile => Shown::new(
            "keyfile",
            "열쇠: 서버의 열쇠 파일과 상태가 달라 올리지 못했습니다. PC에서 먼저 처리하세요.",
        ),
        SyncState::NoKeys => Shown::new(
            "nokeys",
            "열쇠: 서버가 이 휴대폰 줄에 열쇠 파일 동기화를 허용하지 않습니다(--key-sync). 'Android 기기 추가'를 다시 하세요.",
        ),
    }
}

/// The engine, kept for the process so its memory (backoff, held uploads,
/// key steps) lasts across the foreground loop's runs, as in the Windows
/// background helper. Rebuilt when the settings change. The engine is not
/// `Send` (its clock and log are the Windows helper's), so it lives on one
/// thread of its own and every run is a job sent there.
struct Runner {
    settings: Settings,
    vault: PathBuf,
    engine: Engine<AndroidTransport>,
}
type Job = Box<dyn FnOnce(&mut Option<Runner>) + Send>;
static JOBS: Mutex<Option<std::sync::mpsc::Sender<Job>>> = Mutex::new(None);
/// Runs `f` on the engine's thread and waits for it.
fn on_engine<T: Send + 'static>(f: impl FnOnce(&mut Option<Runner>) -> T + Send + 'static) -> T {
    let (reply, answer) = std::sync::mpsc::channel();
    let job: Job = Box::new(move |runner| {
        let _ = reply.send(f(runner));
    });
    let mut jobs = JOBS.lock().unwrap_or_else(|e| e.into_inner());
    let sender = jobs.get_or_insert_with(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        std::thread::spawn(move || {
            let mut runner = None;
            for job in rx {
                // A panic in one run must not take the engine thread down
                // with the next runs' replies.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(&mut runner)));
            }
        });
        tx
    });
    if let Err(std::sync::mpsc::SendError(job)) = sender.send(job) {
        // The thread is gone: start a new one next time, run this here.
        *jobs = None;
        drop(jobs);
        let mut runner = None;
        job(&mut runner);
    } else {
        drop(jobs);
    }
    answer.recv().expect("the engine thread answers every job")
}
static CANCEL: std::sync::LazyLock<Arc<AtomicBool>> =
    std::sync::LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// Asks a running exchange to stop (the worker was stopped).
pub fn cancel() {
    CANCEL.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Whether a run would do anything now (a pass is due), without a key:
/// the foreground loop asks this every few seconds and unwraps the key
/// only when it is.
pub fn due(paths: &Paths) -> bool {
    let Some(settings) = load_settings(paths) else {
        return false;
    };
    let vault = paths.vault.clone();
    on_engine(move |runner| match runner.as_ref() {
        Some(r) if r.settings == settings && r.vault == vault => {
            (0..r.engine.vaults()).any(|i| r.engine.due(i))
        }
        _ => true,
    })
}

/// One run: every vault's pass, polling the server when `force` (unlock,
/// save, "지금 동기화", the periodic worker) and otherwise only what is due.
pub fn run(paths: &Paths, seed: Option<Zeroizing<[u8; 32]>>, force: bool) -> Shown {
    let shown = run_inner(paths, seed, force);
    let _ = paths.make().and_then(|()| {
        let text = format!(
            "{}\n{}\n{}\n",
            shown.state,
            shown.fingerprint,
            shown.text.replace('\n', " ")
        );
        syncfile::replace_file(&paths.result(), text.as_bytes()).map_err(|_| String::new())
    });
    shown
}
fn run_inner(paths: &Paths, seed: Option<Zeroizing<[u8; 32]>>, force: bool) -> Shown {
    let Some(settings) = load_settings(paths) else {
        return Shown::new("nosettings", "동기화 설정이 없습니다.");
    };
    if !paths.vault.is_file() {
        return Shown::new("novault", "가져온 금고가 없습니다.");
    }
    if paths.make().is_err() {
        return Shown::new("config", "동기화 폴더를 만들 수 없습니다.");
    }
    CANCEL.store(false, std::sync::atomic::Ordering::Relaxed);
    let pin = load_pin(paths);
    let (vault, log, host) = (paths.vault.clone(), paths.log(), settings.host.clone());
    let s = settings.clone();
    let (last, problem) = on_engine(move |runner| {
        if runner
            .as_ref()
            .is_none_or(|r| r.settings != s || r.vault != vault)
        {
            let transport = AndroidTransport::new(s.target(), CANCEL.clone());
            let engine = Engine::new(
                transport,
                std::slice::from_ref(&vault),
                line::DEFAULT_INTERVAL,
                syncengine::system_clock(),
                log,
            );
            *runner = Some(Runner {
                settings: s,
                vault,
                engine,
            });
        }
        let engine = &mut runner.as_mut().expect("just made").engine;
        engine.transport.seed = seed;
        engine.transport.pin = pin;
        engine.transport.problem = None;
        let mut last = None;
        for i in 0..engine.vaults() {
            if force || engine.due(i) {
                last = Some(engine.pass(i, force));
            }
        }
        // The key leaves memory with the run (Zeroizing wipes it).
        engine.transport.seed = None;
        (last, engine.transport.problem.clone())
    });
    remember_offer(&settings, problem.as_ref());
    match last {
        None => read_result(paths).unwrap_or_else(|| Shown::new("idle", "")),
        Some(Outcome::Locked) => Shown::new("busy", "다른 동기화가 진행 중입니다."),
        Some(Outcome::Folder(Folder::NoVault)) => Shown::new("novault", "가져온 금고가 없습니다."),
        Some(Outcome::Folder(Folder::Unusable)) => Shown::new(
            "config",
            "동기화 폴더(vault.goyo.sync)가 폴더가 아니거나 링크입니다.",
        ),
        Some(Outcome::Done(report)) => shown(problem.as_ref(), report.state, &host, ""),
    }
}
fn remember_offer(settings: &Settings, problem: Option<&Problem>) {
    if let Some(Problem::HostUnknown { blob }) = problem {
        *OFFERED.lock().unwrap_or_else(|e| e.into_inner()) = Some(Offered {
            host: settings.host.clone(),
            port: settings.port,
            blob: blob.clone(),
        });
    }
}
/// The last run's result as `run` wrote it.
pub fn read_result(paths: &Paths) -> Option<Shown> {
    let bytes = syncfile::read_bounded(&paths.result(), 4096).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let mut lines = text.split('\n');
    let state = lines.next()?;
    let fingerprint = lines.next()?.to_owned();
    let text = lines.next()?.to_owned();
    const STATES: [&str; 20] = [
        "ok",
        "idle",
        "offline",
        "auth",
        "hostkey-unknown",
        "hostkey-changed",
        "server",
        "refused",
        "config",
        "update",
        "oldserver",
        "keyfile",
        "nokeys",
        "tailnet",
        "nokey",
        "nosettings",
        "novault",
        "busy",
        "check",
        "cancelled",
    ];
    let state = STATES.into_iter().find(|s| *s == state)?;
    Some(Shown {
        state,
        text,
        fingerprint,
    })
}

/// '연결 확인': HELLO's 512-byte round trip, then LIST, with the phone's
/// key and the pin, as the Windows window's check. Writes nothing on the
/// server. An unknown host key is offered for pinning.
pub fn check(paths: &Paths, seed: Option<Zeroizing<[u8; 32]>>) -> Shown {
    let Some(settings) = load_settings(paths) else {
        return Shown::new("nosettings", "동기화 설정이 없습니다.");
    };
    let mut transport = AndroidTransport::new(settings.target(), CANCEL.clone());
    transport.seed = seed;
    transport.pin = load_pin(paths);
    let log = paths.log();
    let hello = syncengine::call(&mut transport, &Request::hello(), "android check", &log);
    let failed = |transport: &AndroidTransport, state: SyncState, detail: &str| {
        let problem = transport.problem.clone();
        remember_offer(&settings, problem.as_ref());
        shown(problem.as_ref(), state, &settings.host, detail)
    };
    match hello {
        Ok(reply) if reply.status == Status::Ok && reply.blob() == HELLO_ECHO => {}
        Ok(_) => {
            return failed(
                &transport,
                SyncState::Server,
                "HELLO가 그대로 돌아오지 않음",
            );
        }
        Err(syncengine::CallError::Failed(state, detail)) => {
            return failed(&transport, state, &detail);
        }
        Err(syncengine::CallError::Cancelled) => return Shown::new("cancelled", "취소했습니다."),
    }
    match syncengine::call(&mut transport, &Request::list(), "android check", &log) {
        Ok(reply) if reply.status == Status::Ok => {
            let n = parse_list(reply.blob()).map_or(0, |l| l.len());
            Shown::new("ok", format!("연결 정상 · 서버에 금고 {n}개"))
        }
        Ok(_) => failed(&transport, SyncState::Server, "LIST"),
        Err(syncengine::CallError::Failed(state, detail)) => failed(&transport, state, &detail),
        Err(syncengine::CallError::Cancelled) => Shown::new("cancelled", "취소했습니다."),
    }
}

/// The line for the server's authorized_keys (see line.rs).
pub fn server_line(paths: &Paths, blob: &str, model: &str) -> Result<String, String> {
    let settings = load_settings(paths);
    let (python, remote) = settings
        .as_ref()
        .map_or((line::DEFAULT_PYTHON, line::DEFAULT_REMOTE), |s| {
            (s.python.as_str(), s.remote.as_str())
        });
    let ids: Vec<[u8; 16]> = vault_id(paths).into_iter().collect();
    line::forced_line(python, remote, &ids, blob, model)
        .ok_or_else(|| "줄을 만들 수 없습니다(설정 확인).".to_owned())
}

/// Removes the vault's sync folder (a new import, or the vault removed):
/// as deleting `vault.goyo.sync` on a PC, it resets sync for that path.
pub fn reset_folder(paths: &Paths) {
    if let Some(dir) = syncfile::sync_dir(&paths.vault)
        && fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir())
    {
        let _ = fs::remove_dir_all(dir);
    }
    on_engine(|runner| *runner = None);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OTP formats (GOYOVA05 to 08, 0.12.0) keep the ID where 01 to 04
    /// have it; a newer format or no vault gives none.
    #[test]
    fn the_vault_id_is_read_from_every_known_format() {
        let dir = std::env::temp_dir().join(format!("goyo-vault-id-{}", std::process::id()));
        let paths = Paths::new(&dir);
        fs::create_dir_all(paths.vault.parent().unwrap()).unwrap();
        assert_eq!(vault_id(&paths), None);
        for n in 1..=9u8 {
            let mut head = format!("GOYOVA0{n}").into_bytes();
            head.extend_from_slice(&[0x5a; 16]);
            fs::write(&paths.vault, &head).unwrap();
            let want = (n <= 8).then_some([0x5a; 16]);
            assert_eq!(vault_id(&paths), want, "GOYOVA0{n}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn settings_round_trip_and_refuse_bad_words() {
        let s = Settings::new("box.tail1234.ts.net", "", "me", "", "").unwrap();
        assert_eq!(s.port, 22);
        assert_eq!(s.remote, line::DEFAULT_REMOTE);
        assert_eq!(s.python, line::DEFAULT_PYTHON);
        assert_eq!(Settings::parse(&s.render()), Some(s.clone()));
        assert_eq!(
            s.target().command,
            "python3 -I .local/share/goyo-sync/goyo-sync-server.py serve"
        );
        assert!(Settings::new("-oProxyCommand=x", "", "me", "", "").is_err());
        assert!(Settings::new("box", "0", "me", "", "").is_err());
        assert!(Settings::new("box", "70000", "me", "", "").is_err());
        assert!(Settings::new("box", "", "me;id", "", "").is_err());
        assert!(Settings::new("box", "", "me", "../x.py", "").is_err());
        assert!(Settings::new("box", "", "me", "", "python3 -c").is_err());
        assert_eq!(
            Settings::parse(&s.render().replace("port=22", "port=x")),
            None
        );
        assert_eq!(Settings::parse(&format!("{}x=1\n", s.render())), None);
    }
}
