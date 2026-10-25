//! The helper's CLI text: each message with its Korean and English form side
//! by side. The language follows `goyo-vault.lang` next to the exe ("ko" or
//! "en", as the vault app writes it), else the Windows display language.
//! Only the CLI prints these; the log and the status file use fixed ASCII.
//! The settings window (gui.rs) words its text through the vault's i18n.rs.
use crate::sys;
use std::{
    fmt::Display,
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

static ENGLISH: AtomicBool = AtomicBool::new(true);

pub fn init(exe_dir: Option<&Path>) {
    let mut buf = Vec::new();
    let read = exe_dir
        .and_then(|d| File::open(d.join("goyo-vault.lang")).ok())
        .and_then(|f| f.take(16).read_to_end(&mut buf).ok());
    let english = match (read, buf.trim_ascii()) {
        (Some(_), b"en") => true,
        (Some(_), b"ko") => false,
        _ => !sys::korean_ui(),
    };
    ENGLISH.store(english, Ordering::Relaxed);
}

macro_rules! messages {
    ($($name:ident = $ko:literal, $en:literal;)*) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Msg { $($name,)* }
        impl Msg {
            #[cfg(test)]
            pub const ALL: &[Msg] = &[$(Msg::$name,)*];
            /// (Korean, English).
            pub fn pair(self) -> (&'static str, &'static str) {
                match self { $(Msg::$name => ($ko, $en),)* }
            }
        }
    };
}
messages! {
    Usage = "사용법: goyo-sync.exe [--background | --once | --check | --list | --fetch <금고 ID> <head|버전> <새 파일.goyo> | --autostart on|off | --stop | --self-check]\n인자 없이 실행하면 설정 창을 엽니다. --background는 창 없이 백그라운드에서 동기화합니다. 설정 파일: 실행 파일 옆의 goyo-sync.conf",
        "Usage: goyo-sync.exe [--background | --once | --check | --list | --fetch <vault ID> <head|version> <new-file.goyo> | --autostart on|off | --stop | --self-check]\nWithout arguments it opens the settings window. --background syncs in the background without a window. Settings: goyo-sync.conf next to the program";
    Defenses = "프로세스 보호 설정에 실패해 종료합니다: {}",
        "Process protection could not be set up, so goyo-sync stops: {}";
    ConfigMissing = "설정 파일이 없습니다: {}. goyo-sync.exe를 인자 없이 실행해 설정 창에서 저장하거나, goyo-sync.conf.example을 복사해 만드세요.",
        "Settings file not found: {}. Run goyo-sync.exe without arguments and save in the settings window, or copy goyo-sync.conf.example.";
    ConfigUnreadable = "설정 파일을 읽을 수 없습니다: {}",
        "Cannot read the settings file: {}";
    ConfigTooLarge = "설정 파일이 8 KiB보다 큽니다.",
        "The settings file is larger than 8 KiB.";
    ConfigNotUtf8 = "설정 파일이 UTF-8 텍스트가 아닙니다.",
        "The settings file is not UTF-8 text.";
    ConfigNoHost = "설정에 host가 없습니다.",
        "The settings have no host.";
    ConfigNoVault = "설정에 vault가 하나도 없습니다.",
        "The settings name no vault.";
    ConfigLine = "goyo-sync.conf {}번째 줄: {}",
        "goyo-sync.conf line {}: {}";
    NoEquals = "'이름 = 값' 형식이 아닙니다.",
        "not in the form 'name = value'.";
    UnknownKey = "알 수 없는 설정입니다.",
        "unknown setting.";
    Duplicate = "같은 설정이 두 번 있습니다.",
        "this setting appears twice.";
    BadHost = "host는 ssh 별칭이나 호스트 이름이어야 합니다(영문·숫자·. _ -, user@ 허용, -로 시작 불가).",
        "host must be an ssh alias or host name (letters, digits, . _ -, optional user@, not starting with -).";
    BadRemote = "remote는 서버의 스크립트 경로여야 합니다(영문·숫자·. _ / ~ + -, -로 시작 불가).",
        "remote must be the script path on the server (letters, digits, . _ / ~ + -, not starting with -).";
    BadPython = "python은 서버의 파이썬 명령이어야 합니다(영문·숫자·. _ / + -, -로 시작 불가).",
        "python must be the Python command on the server (letters, digits, . _ / + -, not starting with -).";
    BadIdentity = "identity는 따옴표 없는, 있는 SSH 개인 키 파일의 절대 경로여야 합니다.",
        "identity must be the absolute path of an existing SSH private key file, without quotes.";
    BadInterval = "interval은 30~3600(초) 사이의 숫자여야 합니다.",
        "interval must be a number from 30 to 3600 (seconds).";
    BadTimeout = "timeout은 30~600(초) 사이의 숫자여야 합니다.",
        "timeout must be a number from 30 to 600 (seconds).";
    BadVault = "vault는 따옴표 없는 금고 파일의 절대 경로여야 합니다.",
        "vault must be the absolute path of a vault file, without quotes.";
    KeyFileVault = "vault에 열쇠 파일(*.goyokey)을 적을 수 없습니다. 열쇠 파일은 동기화하지 않습니다.",
        "vault cannot name a key file (*.goyokey). Key files are never synced.";
    TooManyVaults = "vault는 8개까지 적을 수 있습니다.",
        "at most 8 vault lines are allowed.";
    DuplicateVault = "같은 vault가 두 번 있습니다.",
        "the same vault appears twice.";
    SettingsOk = "설정: 정상 (서버 {}, 금고 {}개)",
        "Settings: OK (server {}, vaults: {})";
    SshFound = "ssh.exe: {}",
        "ssh.exe: {}";
    SshMissing = "Windows OpenSSH 클라이언트(ssh.exe)가 없습니다: {}. Windows 설정 > 시스템 > 선택적 기능에서 'OpenSSH 클라이언트'를 추가하세요.",
        "The Windows OpenSSH client (ssh.exe) is missing: {}. Add 'OpenSSH Client' under Settings > System > Optional features.";
    HelloOk = "연결: 정상 (512바이트 이진 데이터가 그대로 왕복함)",
        "Connection: OK (512 bytes of binary data made the round trip unchanged)";
    ServerVaults = "서버에 있는 금고: {}개",
        "Vaults on the server: {}";
    VaultHeading = "금고 {}",
        "Vault {}";
    FolderPresent = "  동기화 폴더: 있음",
        "  sync folder: present";
    FolderMissing = "  동기화 폴더: 없음 (도우미가 실행되면 만듭니다)",
        "  sync folder: missing (the helper creates it when it runs)";
    FolderUnusable = "  동기화 폴더: 쓸 수 없음 (링크이거나 폴더가 아닙니다)",
        "  sync folder: unusable (a link or not a folder)";
    Pinned = "  금고 ID: {}",
        "  vault ID: {}";
    NotPinned = "  금고 ID: 아직 없음 (고요 금고에서 동기화를 켜고 금고를 여세요)",
        "  vault ID: none yet (turn sync on in Goyo Vault and unlock the vault)";
    ServerHead = "  서버: 버전 {}, {}바이트",
        "  server: version {}, {} bytes";
    ServerNone = "  서버: 아직 사본 없음",
        "  server: no copy yet";
    ListEmpty = "서버에 금고가 없습니다.",
        "The server has no vaults.";
    ListRow = "{}  {}  버전 {}  {}바이트  {}",
        "{}  {}  version {}  {} bytes  {}";
    FetchBadId = "금고 ID는 32자리 16진수여야 합니다 (--list로 확인하세요).",
        "The vault ID must be 32 hex digits (see --list).";
    FetchBadVersion = "버전은 head 또는 1 이상의 숫자여야 합니다.",
        "The version must be head or a number from 1.";
    FetchExists = "이미 있는 파일입니다. 덮어쓰지 않습니다: {}",
        "The file already exists and is never overwritten: {}";
    FetchNotFound = "서버에 그 버전이 없습니다.",
        "The server does not have that version.";
    FetchWriteFailed = "파일을 저장할 수 없습니다: {}",
        "Cannot save the file: {}";
    FetchSaved = "버전 {}({}바이트)을 {}에 저장했습니다. 고요 금고의 '백업에서 복원'으로 여세요.",
        "Saved version {} ({} bytes) to {}. Open it with Restore in Goyo Vault.";
    AutostartOn = "로그인하면 goyo-sync가 시작되도록 등록했습니다.",
        "goyo-sync now starts when you sign in.";
    AutostartOff = "자동 시작을 껐고, 실행 중인 도우미에 중지 신호를 보냈습니다.",
        "Autostart is off, and a running helper was asked to stop.";
    AutostartFailed = "자동 시작 설정을 바꾸지 못했습니다 (오류 {}).",
        "Could not change the autostart setting (error {}).";
    Stopped = "실행 중인 도우미에 중지 신호를 보냈습니다.",
        "The running helper was asked to stop.";
    NotRunning = "실행 중인 도우미가 없습니다.",
        "No helper is running.";
    PassLocked = "{}: 다른 goyo-sync가 지금 이 금고를 처리하고 있습니다.",
        "{}: another goyo-sync is working on this vault right now.";
    PassNoVault = "{}: 금고 파일이 없습니다. 경로를 확인하세요.",
        "{}: the vault file was not found. Check the path.";
    PassUnusable = "{}: 동기화 폴더가 링크이거나 폴더가 아니어서 쓰지 않습니다.",
        "{}: the sync folder is a link or not a folder, so it is not used.";
    PassIdle = "{}: 대기 중. 고요 금고에서 동기화를 켜고 금고를 열면 시작합니다.",
        "{}: waiting. Sync starts once it is turned on in Goyo Vault and the vault is unlocked.";
    PassUploaded = "{}: 올렸습니다 (서버 버전 {}).",
        "{}: uploaded (server version {}).";
    PassDownloaded = "{}: 새 서버 버전 {}을 받았습니다.",
        "{}: received server version {}.";
    PassCurrent = "{}: 최신입니다 (서버 버전 {}).",
        "{}: up to date (server version {}).";
    PassNothing = "{}: 서버에 아직 사본이 없습니다.",
        "{}: the server has no copy yet.";
    StateOffline = "{}: 서버에 연결할 수 없습니다. 변경은 이 PC에 저장되어 있습니다.",
        "{}: cannot reach the server. Changes are kept on this PC.";
    StateAuth = "{}: SSH 인증에 실패했습니다. goyo-sync.log를 확인하세요.",
        "{}: SSH authentication failed. See goyo-sync.log.";
    StateHostKey = "{}: 서버 호스트 키가 바뀌었거나 known_hosts에 없습니다. 확인하기 전에는 연결하지 않습니다.",
        "{}: the server's host key changed or is not in known_hosts. goyo-sync will not connect until you check it.";
    StateNoSsh = "{}: Windows OpenSSH 클라이언트(ssh.exe)가 없습니다.",
        "{}: the Windows OpenSSH client (ssh.exe) is missing.";
    StateServer = "{}: 서버 또는 통신 오류입니다. goyo-sync.log를 확인하세요.",
        "{}: server or protocol error. See goyo-sync.log.";
    StateRefused = "{}: 올릴 파일이 검사나 서버에서 거부되었습니다. goyo-sync.log를 확인하세요.",
        "{}: the upload was refused by a check or by the server. See goyo-sync.log.";
    StateUpdate = "{}: 서버 사본이 더 새로운 형식입니다. 고요 금고를 업데이트하세요.",
        "{}: the server copy uses a newer format. Update Goyo Vault.";
    StderrLine = "  ssh: {}",
        "  ssh: {}";
}

/// The language [`init`] picked.
pub fn english() -> bool {
    ENGLISH.load(Ordering::Relaxed)
}
pub fn text(m: Msg) -> &'static str {
    let (ko, en) = m.pair();
    if ENGLISH.load(Ordering::Relaxed) {
        en
    } else {
        ko
    }
}
/// The message with each `{}` replaced by the next argument.
pub fn fill(m: Msg, args: &[&dyn Display]) -> String {
    let mut out = String::new();
    let mut args = args.iter();
    let mut parts = text(m).split("{}");
    out.push_str(parts.next().unwrap_or(""));
    for part in parts {
        if let Some(a) = args.next() {
            out.push_str(&a.to_string());
        }
        out.push_str(part);
    }
    out
}
/// A result line on stdout.
pub fn say(m: Msg, args: &[&dyn Display]) {
    sys::print(&(fill(m, args) + "\n"), false);
}
/// A problem line on stderr.
pub fn warn(m: Msg, args: &[&dyn Display]) {
    sys::print(&(fill(m, args) + "\n"), true);
}
#[cfg(test)]
pub fn set_english(english: bool) {
    ENGLISH.store(english, Ordering::Relaxed);
}
