//! `goyo-sync.conf` next to the exe (spec §9.2). Every value that reaches
//! the ssh command line is checked against a fixed character set, so no
//! setting can become an ssh option, a second remote command or a shell
//! construct. Unknown names and invalid values are fatal. On purpose there
//! is no setting for a key file and none for another ssh.exe.
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    path::{Component, Path, PathBuf, Prefix},
};

pub const MAX_CONFIG: usize = 8 * 1024;
pub const MAX_VAULTS: usize = 8;
pub const DEFAULT_REMOTE: &str = ".local/share/goyo-sync/goyo-sync-server.py";
pub const DEFAULT_PYTHON: &str = "python3";
pub const DEFAULT_INTERVAL: u64 = 60;
pub const DEFAULT_TIMEOUT: u64 = 120;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// ssh destination: an alias from ~/.ssh/config or `[user@]host`.
    pub host: String,
    /// Server script, relative to the remote home.
    pub remote: String,
    pub python: String,
    /// Adds `-i <path> -o IdentitiesOnly=yes`.
    pub identity: Option<PathBuf>,
    /// Seconds between server checks.
    pub interval: u64,
    /// Seconds per ssh call.
    pub timeout: u64,
    /// Absolute vault paths; the helper uses only `<vault>.sync\` and a
    /// listing of the vault's folder, never the vault file itself.
    pub vaults: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    Missing,
    Unreadable,
    TooLarge,
    NotUtf8,
    NoEquals,
    UnknownKey,
    Duplicate,
    Host,
    Remote,
    Python,
    Identity,
    Interval,
    Timeout,
    Vault,
    /// A vault line naming a `*.goyokey` file.
    KeyFile,
    TooManyVaults,
    DuplicateVault,
    NoHost,
    NoVault,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// 1-based line, or 0 for the file as a whole.
    pub line: usize,
    pub problem: Problem,
    /// The vault lines that were valid, so their folders can show
    /// `state=config` in the app.
    pub vaults: Vec<PathBuf>,
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    parse(&read(path)?)
}
/// The file's text, at most [`MAX_CONFIG`] bytes of UTF-8; the settings
/// window shows a file that does not parse so it can be fixed.
pub fn read(path: &Path) -> Result<String, ConfigError> {
    let whole = |problem| ConfigError {
        line: 0,
        problem,
        vaults: Vec::new(),
    };
    let file = File::open(path).map_err(|e| {
        whole(if e.kind() == io::ErrorKind::NotFound {
            Problem::Missing
        } else {
            Problem::Unreadable
        })
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| whole(Problem::Unreadable))?;
    if bytes.len() > MAX_CONFIG {
        return Err(whole(Problem::TooLarge));
    }
    String::from_utf8(bytes).map_err(|_| whole(Problem::NotUtf8))
}

/// `name = value` lines; `#` starts a comment anywhere on a line, so no
/// value can contain `#`. A UTF-8 byte order mark (Notepad) is ignored.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut first: Option<(usize, Problem)> = None;
    let mut seen = BTreeSet::new();
    let mut config = Config {
        host: String::new(),
        remote: DEFAULT_REMOTE.into(),
        python: DEFAULT_PYTHON.into(),
        identity: None,
        interval: DEFAULT_INTERVAL,
        timeout: DEFAULT_TIMEOUT,
        vaults: Vec::new(),
    };
    for (n, raw) in text.split('\n').enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let result = match line.split_once('=') {
            None => Err(Problem::NoEquals),
            Some((name, value)) => {
                let (name, value) = (name.trim(), value.trim());
                if name != "vault" && !seen.insert(name.to_owned()) {
                    Err(Problem::Duplicate)
                } else {
                    apply(&mut config, name, value)
                }
            }
        };
        if let Err(problem) = result
            && first.is_none()
        {
            first = Some((n + 1, problem));
        }
    }
    if first.is_none() && config.host.is_empty() {
        first = Some((0, Problem::NoHost));
    }
    if first.is_none() && config.vaults.is_empty() {
        first = Some((0, Problem::NoVault));
    }
    match first {
        None => Ok(config),
        Some((line, problem)) => Err(ConfigError {
            line,
            problem,
            vaults: config.vaults,
        }),
    }
}
fn apply(config: &mut Config, name: &str, value: &str) -> Result<(), Problem> {
    match name {
        "host" if host(value) => config.host = value.into(),
        "host" => return Err(Problem::Host),
        "remote" if word(value, 256, b"._/~+-") => config.remote = value.into(),
        "remote" => return Err(Problem::Remote),
        "python" if word(value, 64, b"._/+-") => config.python = value.into(),
        "python" => return Err(Problem::Python),
        "identity" if value.is_empty() => config.identity = None,
        "identity" => config.identity = Some(identity(value).ok_or(Problem::Identity)?),
        "interval" => config.interval = number(value, 30, 3600).ok_or(Problem::Interval)?,
        "timeout" => config.timeout = number(value, 30, 600).ok_or(Problem::Timeout)?,
        "vault" => {
            let path = vault(value)?;
            let key = path.to_string_lossy().to_lowercase();
            if config
                .vaults
                .iter()
                .any(|v| v.to_string_lossy().to_lowercase() == key)
            {
                return Err(Problem::DuplicateVault);
            }
            if config.vaults.len() == MAX_VAULTS {
                return Err(Problem::TooManyVaults);
            }
            config.vaults.push(path);
        }
        _ => return Err(Problem::UnknownKey),
    }
    Ok(())
}

/// `^(?:[A-Za-z0-9._-]{1,64}@)?[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`, and no
/// leading `-` at all: the regex alone would allow `-x@host`.
pub fn host(s: &str) -> bool {
    let plain = |part: &str| {
        part.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    let (user, name) = match s.split_once('@') {
        Some((user, name)) => (Some(user), name),
        None => (None, s),
    };
    !s.starts_with('-')
        && user.is_none_or(|u| (1..=64).contains(&u.len()) && plain(u))
        && (1..=253).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && plain(name)
}
/// ASCII letters, digits and `extra`; 1 to `max` bytes; no leading `-`.
/// The server install builds its remote command from such words only.
pub fn word(s: &str, max: usize, extra: &[u8]) -> bool {
    (1..=max).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}
/// Plain decimal digits within `min..=max`.
fn number(s: &str, min: u64, max: u64) -> Option<u64> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| (min..=max).contains(n))
}
/// An absolute `C:\...` or `\\server\share\...` path with only plain
/// names in it: no `.` or `..`, no `\\?\` or device forms, no `:` after the
/// drive (an alternate data stream), and no quote or wildcard.
fn absolute(s: &str) -> Option<PathBuf> {
    if s.chars()
        .any(|c| c.is_control() || matches!(c, '"' | '*' | '?' | '<' | '>' | '|'))
    {
        return None;
    }
    let path = PathBuf::from(s);
    if !path.is_absolute() || path.file_name().is_none() {
        return None;
    }
    for c in path.components() {
        match c {
            Component::Prefix(p) if matches!(p.kind(), Prefix::Disk(_) | Prefix::UNC(..)) => {}
            Component::RootDir => {}
            Component::Normal(name) if !name.to_string_lossy().contains(':') => {}
            _ => return None,
        }
    }
    Some(path)
}
/// The file name as Windows resolves it: trailing dots and spaces dropped.
fn resolved_name(path: &Path) -> String {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    name.trim_end_matches(['.', ' ']).to_lowercase()
}
fn vault(s: &str) -> Result<PathBuf, Problem> {
    let path = absolute(s).ok_or(Problem::Vault)?;
    if resolved_name(&path).ends_with(".goyokey") {
        return Err(Problem::KeyFile);
    }
    Ok(path)
}
/// An SSH private key: an existing file, and never a Goyo key or vault.
fn identity(s: &str) -> Option<PathBuf> {
    let path = absolute(s)?;
    let name = resolved_name(&path);
    let goyo = name.ends_with(".goyokey") || name.ends_with(".goyo");
    (!goyo && path.is_file()).then_some(path)
}
