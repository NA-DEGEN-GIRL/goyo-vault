//! The one-button setup of the dedicated key (security-key build, docs/SYNC.md
//! '전용 키와 강제 명령'): [서버에 설치·업데이트] installs the server script,
//! makes this PC's dedicated ssh key when none is set (Windows OpenSSH
//! `ssh-keygen`, ed25519, no passphrase: the background helper runs
//! unattended; only this Windows account may read it), puts its
//! forced-command line into the server's `~/.ssh/authorized_keys` through
//! the script's `authorize` (the line on stdin, checked again there; only
//! the lines of this key change), and checks that the key reaches the
//! server. The install and `authorize` use the usual ssh login, never the
//! dedicated key, whose line runs only `serve`. Nothing here words a
//! message (keys_gui.rs does); tests script the [`Runner`].
use crate::{
    config::Config,
    engine::Log,
    keys_gui::serve_command,
    setup::{self, Checked, Installed, Runner, Tool, Trouble, Unsafe, present, trouble},
    transport::{Failure, Killed, Output, classify, first_line},
};
use goyo_vault::syncfile::SyncState;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// The new key's file name in `%USERPROFILE%\.ssh` (then `-2`, `-3`, …).
pub const KEY_NAME: &str = "goyo-sync_ed25519";
/// ssh-keygen and icacls only touch local files.
const LOCAL_TIMEOUT: Duration = Duration::from_secs(30);
/// The start of every ed25519 public key blob in base64: the type name
/// `ssh-ed25519` and the 32-byte length, as the server script checks it.
const ED25519_BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAI";

/// The dedicated key the setup uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// `identity` names an existing file.
    Existing(PathBuf),
    /// No usable `identity`: this free name gets a new key.
    New(PathBuf),
}
impl Key {
    pub fn path(&self) -> &Path {
        match self {
            Key::Existing(p) | Key::New(p) => p,
        }
    }
}
/// What the window decided before asking: the key, the IDs of every listed
/// vault whose ID it knows, how many listed vaults it does not know yet,
/// and the line's comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub key: Key,
    pub ids: Vec<[u8; 16]>,
    pub unknown: usize,
    pub comment: String,
}
/// What `authorize` did to authorized_keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorized {
    Added,
    Replaced,
    Same,
}
/// How the key part ended (after a passing install).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The line is on the server and the key logged in through it.
    Ready(Authorized),
    /// No `%USERPROFILE%` (or no free name in its `.ssh`).
    NoHome,
    /// The new key's name appeared meanwhile: nothing was overwritten.
    Taken,
    /// ssh-keygen did not make the key (its first stderr line).
    Keygen(String),
    /// The new key's file could not be limited to this account.
    Acl,
    /// ssh-keygen would not read the key: others may read it
    /// (`permissions`), or it has a passphrase or is no key.
    Unreadable {
        permissions: bool,
    },
    NotEd25519,
    Refused(Unsafe),
    /// The server has this key without a forced command (perhaps a usual
    /// login key): authorized_keys was left alone.
    Unrestricted,
    /// `authorize` did not end in ADDED, REPLACED or SAME: its last line.
    Script(String),
    /// ssh itself failed on the way to `authorize`.
    Failed(Trouble),
    /// The line is on the server, but the key's own check failed.
    Verify(Checked),
    Cancelled,
}
/// The whole job's result: the install, then the key (created: true when
/// this run made it) and how that part ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    pub installed: Installed,
    pub key: Option<(PathBuf, bool)>,
    pub outcome: Option<Outcome>,
}

/// `%USERPROFILE%\.ssh\goyo-sync_ed25519`, or the first of `-2` … `-99`
/// whose key and `.pub` are both free. Never an existing file.
pub fn free_key(dir: &Path) -> Option<PathBuf> {
    (1..100)
        .map(|n| match n {
            1 => dir.join(KEY_NAME),
            n => dir.join(format!("{KEY_NAME}-{n}")),
        })
        .find(|p| !present(p) && !present(&pub_file(p)))
}
/// The `.pub` beside a key file.
pub fn pub_file(key: &Path) -> PathBuf {
    let mut name = key.file_name().unwrap_or_default().to_owned();
    name.push(".pub");
    key.with_file_name(name)
}
/// The key's and the line's comment: `goyo-sync <computer>`, the computer
/// name reduced to `A-Z a-z 0-9 . _ -` (63 at most), as the server script
/// accepts it.
pub fn comment(computer: Option<&str>) -> String {
    let name: String = computer
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(63)
        .collect();
    if name.is_empty() {
        "goyo-sync".into()
    } else {
        format!("goyo-sync {name}")
    }
}
/// `ssh-keygen -q -t ed25519 -N "" -C <comment> -f <path>`: no passphrase,
/// since the background helper uses the key unattended.
pub fn keygen_args(path: &Path, comment: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"]
        .map(OsString::from)
        .to_vec();
    args.push(path.into());
    args
}
/// `ssh-keygen -y -P "" -f <path>`: the public key from the private key
/// itself (never a `.pub` that may not match). It refuses a key others may
/// read, as ssh does, and never asks for a passphrase.
pub fn public_args(path: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["-y", "-P", "", "-f"].map(OsString::from).to_vec();
    args.push(path.into());
    args
}
/// `icacls <path> /inheritance:r /grant:r <user>:F`: only this account
/// may use the new key (docs/SYNC.md gives the same two steps by hand).
pub fn acl_args(path: &Path, user: &str) -> Vec<OsString> {
    let mut args = vec![OsString::from(path)];
    args.extend(
        ["/inheritance:r", "/grant:r", &format!("{user}:F")]
            .into_iter()
            .map(OsString::from),
    );
    args
}
/// This Windows account as icacls names it (`DOMAIN\user`), from the
/// environment; None if a part is missing or not a plain name.
pub fn account(domain: Option<&str>, user: Option<&str>) -> Option<String> {
    let plain = |s: &str| {
        !s.is_empty()
            && s.len() <= 256
            && !s
                .chars()
                .any(|c| c.is_control() || matches!(c, '\\' | '/' | ':' | '"' | '*' | '?'))
    };
    let user = user.filter(|u| plain(u))?;
    Some(match domain.filter(|d| plain(d)) {
        Some(domain) => format!("{domain}\\{user}"),
        None => user.to_owned(),
    })
}
/// What `ssh-keygen -y` printed: the blob of an ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Public {
    Ed25519(String),
    Other,
}
pub fn parse_public(stdout: &[u8]) -> Public {
    let text = String::from_utf8_lossy(stdout);
    let mut words = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .split_whitespace();
    match (words.next(), words.next()) {
        (Some("ssh-ed25519"), Some(blob))
            if blob.len() == 68
                && blob.starts_with(ED25519_BLOB)
                && blob
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') =>
        {
            Public::Ed25519(blob.to_owned())
        }
        _ => Public::Other,
    }
}
/// This PC's authorized_keys line: the forced command, the key, the
/// comment. None when the script path or the Python command could not be
/// in it (the install's checks).
pub fn server_line(
    python: &str,
    remote: &str,
    ids: &[[u8; 16]],
    blob: &str,
    comment: &str,
) -> Option<String> {
    let serve = serve_command(python, remote, ids)?;
    Some(format!(
        "restrict,command=\"{serve}\" ssh-ed25519 {blob} {comment}"
    ))
}
/// `<python> -I <remote> authorize`, built from the two settings as the
/// install command is (setup::install_command checks them).
pub fn authorize_command(remote: &str, python: &str) -> Result<String, Unsafe> {
    setup::install_command(remote, python)?;
    Ok(format!("{python} -I {remote} authorize"))
}
/// `authorize`'s answer: one of its words alone on the last line, exit 0.
pub fn authorize_result(out: Result<Output, Failure>) -> Result<Authorized, Outcome> {
    let out = match out {
        Ok(out) => out,
        Err(Failure::Missing) => return Err(Outcome::Failed(Trouble::of(SyncState::NoSsh))),
        Err(Failure::Start) => return Err(Outcome::Failed(Trouble::of(SyncState::Server))),
    };
    if out.killed == Some(Killed::Cancelled) {
        return Err(Outcome::Cancelled);
    }
    if out.killed.is_some() || out.code.is_none_or(|c| c == 255) {
        let said = if out.log.is_empty() {
            &out.stderr
        } else {
            &out.log
        };
        return Err(Outcome::Failed(trouble(
            classify(&out),
            &out.stderr,
            first_line(said),
        )));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let last = stdout.lines().map(str::trim).rfind(|l| !l.is_empty());
    match (last, out.code) {
        (Some("ADDED"), Some(0)) => Ok(Authorized::Added),
        (Some("REPLACED"), Some(0)) => Ok(Authorized::Replaced),
        (Some("SAME"), Some(0)) => Ok(Authorized::Same),
        (Some("UNRESTRICTED"), _) => Err(Outcome::Unrestricted),
        (Some(line), _) => Err(Outcome::Script(first_line(line.as_bytes()))),
        // An older script prints its usage on stderr.
        (None, _) => Err(Outcome::Script(first_line(&out.stderr))),
    }
}

/// The job: install, then the key, the line and the key's own check.
/// `account` is who may read a new key (see [`account`]).
pub fn run(
    runner: &mut dyn Runner,
    log: &Log,
    config: &Config,
    plan: &Plan,
    account: Option<&str>,
) -> Setup {
    let installed = setup::install(runner, log, config);
    if installed != Installed::Pass {
        return Setup {
            installed,
            key: None,
            outcome: None,
        };
    }
    let started = Instant::now();
    let path = plan.key.path().to_owned();
    let created = matches!(plan.key, Key::New(_));
    let outcome = key_steps(runner, log, config, plan, account);
    log.line(&format!(
        "window key setup created={created} ids={} {outcome:?} ms={}",
        plan.ids.len(),
        started.elapsed().as_millis()
    ));
    // A new key that was never made is no key to name.
    let made = !created
        || !matches!(
            outcome,
            Outcome::Taken | Outcome::Keygen(_) | Outcome::NoHome
        );
    Setup {
        installed,
        key: made.then_some((path, created)),
        outcome: Some(outcome),
    }
}
fn key_steps(
    runner: &mut dyn Runner,
    log: &Log,
    config: &Config,
    plan: &Plan,
    account: Option<&str>,
) -> Outcome {
    let path = plan.key.path();
    if matches!(plan.key, Key::New(_))
        && let Err(outcome) = make_key(runner, path, &plan.comment, account)
    {
        return outcome;
    }
    let blob = match runner.run(
        Tool::Keygen,
        &public_args(path),
        b"",
        LOCAL_TIMEOUT,
        &mut || {},
    ) {
        Ok(out) if out.code == Some(0) && out.killed.is_none() => match parse_public(&out.stdout) {
            Public::Ed25519(blob) => blob,
            Public::Other => return Outcome::NotEd25519,
        },
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stderr);
            return Outcome::Unreadable {
                permissions: text.contains("bad permissions")
                    || text.contains("UNPROTECTED PRIVATE KEY FILE"),
            };
        }
        Err(Failure::Missing) => return Outcome::Failed(Trouble::of(SyncState::NoSsh)),
        Err(Failure::Start) => return Outcome::Unreadable { permissions: false },
    };
    let command = match authorize_command(&config.remote, &config.python) {
        Ok(command) => command,
        Err(which) => return Outcome::Refused(which),
    };
    let Some(line) = server_line(
        &config.python,
        &config.remote,
        &plan.ids,
        &blob,
        &plan.comment,
    ) else {
        return Outcome::Refused(Unsafe::Remote);
    };
    let out = runner.run(
        Tool::Ssh,
        &setup::login_args(config, command),
        format!("{line}\n").as_bytes(),
        Duration::from_secs(config.timeout),
        &mut || {},
    );
    let authorized = match authorize_result(out) {
        Ok(authorized) => authorized,
        Err(outcome) => return outcome,
    };
    // The key itself, through its forced command: HELLO and LIST.
    let mut keyed = config.clone();
    keyed.identity = Some(path.to_owned());
    match setup::check(runner, log, &keyed) {
        Checked::Ok { .. } => Outcome::Ready(authorized),
        checked => Outcome::Verify(checked),
    }
}
/// Makes the key at `path` (never over an existing file) and lets only
/// this account read it.
fn make_key(
    runner: &mut dyn Runner,
    path: &Path,
    comment: &str,
    account: Option<&str>,
) -> Result<(), Outcome> {
    if present(path) || present(&pub_file(path)) {
        return Err(Outcome::Taken);
    }
    let dir = path.parent().ok_or(Outcome::NoHome)?;
    if !dir.is_dir() && fs::create_dir(dir).is_err() {
        return Err(Outcome::Keygen(String::new()));
    }
    // "n": should ssh-keygen still find a file there, it overwrites nothing.
    let out = runner.run(
        Tool::Keygen,
        &keygen_args(path, comment),
        b"n\n",
        LOCAL_TIMEOUT,
        &mut || {},
    );
    match out {
        Ok(out) if out.code == Some(0) && out.killed.is_none() && present(path) => {}
        Ok(out) => return Err(Outcome::Keygen(first_line(&out.stderr))),
        Err(Failure::Missing) => return Err(Outcome::Failed(Trouble::of(SyncState::NoSsh))),
        Err(Failure::Start) => return Err(Outcome::Keygen(String::new())),
    }
    let user = account.ok_or(Outcome::Acl)?;
    match runner.run(
        Tool::Icacls,
        &acl_args(path, user),
        b"",
        LOCAL_TIMEOUT,
        &mut || {},
    ) {
        Ok(out) if out.code == Some(0) && out.killed.is_none() => Ok(()),
        _ => Err(Outcome::Acl),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        setup::{
            Fields, server_config,
            tests::{Script, hello_ok, list_ok, out, ssh_said},
        },
        tests::Temp,
    };

    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    fn config() -> Config {
        server_config(&Fields {
            host: "my-server".into(),
            ..Fields::default()
        })
        .unwrap()
    }
    fn public(blob: &str) -> Result<Output, Failure> {
        out(
            0,
            format!("ssh-ed25519 {blob} goyo-sync PC\r\n").as_bytes(),
            "",
        )
    }

    /// The pure parts: the free name, the comment, the argv of each local
    /// tool, the public key, the line and the remote command.
    #[test]
    fn names_lines_and_arguments() {
        let t = Temp::new("keysetup-names");
        assert_eq!(free_key(&t.0), Some(t.0.join(KEY_NAME)));
        fs::write(t.0.join(KEY_NAME), b"x").unwrap();
        assert_eq!(free_key(&t.0), Some(t.0.join("goyo-sync_ed25519-2")));
        // A lone .pub takes the name too.
        fs::write(t.0.join("goyo-sync_ed25519-2.pub"), b"x").unwrap();
        assert_eq!(free_key(&t.0), Some(t.0.join("goyo-sync_ed25519-3")));
        assert_eq!(
            pub_file(&t.0.join("k")),
            t.0.join("k.pub"),
            "the .pub beside the key"
        );
        assert_eq!(comment(Some("DESKTOP-AB12")), "goyo-sync DESKTOP-AB12");
        assert_eq!(comment(Some("PC \"x\";$(id)")), "goyo-sync PCxid");
        assert_eq!(comment(Some("한글")), "goyo-sync");
        assert_eq!(comment(None), "goyo-sync");
        assert_eq!(
            comment(Some(&"A".repeat(99))).len(),
            "goyo-sync ".len() + 63
        );
        let key = Path::new(r"C:\Users\me\.ssh\goyo-sync_ed25519");
        assert_eq!(
            keygen_args(key, "goyo-sync PC"),
            [
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "goyo-sync PC",
                "-f",
                r"C:\Users\me\.ssh\goyo-sync_ed25519"
            ]
            .map(OsString::from)
        );
        assert_eq!(
            public_args(key),
            ["-y", "-P", "", "-f", r"C:\Users\me\.ssh\goyo-sync_ed25519"].map(OsString::from)
        );
        assert_eq!(
            acl_args(key, r"PC\me"),
            [
                r"C:\Users\me\.ssh\goyo-sync_ed25519",
                "/inheritance:r",
                "/grant:r",
                r"PC\me:F"
            ]
            .map(OsString::from)
        );
        assert_eq!(account(Some("PC"), Some("me")).as_deref(), Some(r"PC\me"));
        assert_eq!(account(None, Some("me")).as_deref(), Some("me"));
        assert_eq!(account(Some("P:C"), Some("me")).as_deref(), Some("me"));
        for user in [None, Some(""), Some("a:b"), Some("a\\b"), Some("a\"b")] {
            assert_eq!(account(Some("PC"), user), None, "{user:?}");
        }
        // The public key: an ed25519 blob only.
        assert_eq!(
            parse_public(format!("ssh-ed25519 {BLOB} c\n").as_bytes()),
            Public::Ed25519(BLOB.into())
        );
        assert_eq!(
            parse_public(format!("\r\nssh-ed25519 {BLOB}").as_bytes()),
            Public::Ed25519(BLOB.into())
        );
        for bad in [
            format!("ssh-rsa {BLOB}"),
            format!("ssh-ed25519 {}", &BLOB[..67]),
            format!("ssh-ed25519 {}=", &BLOB[..67]),
            format!("ssh-ed25519 {}A", &BLOB[1..]),
            "ssh-ed25519".into(),
            String::new(),
        ] {
            assert_eq!(parse_public(bad.as_bytes()), Public::Other, "{bad}");
        }
        // The line: the forced command of crate::keys_gui, the key, the
        // comment.
        let ids = [[0xA7; 16], [0x01; 16]];
        assert_eq!(
            server_line(
                "python3",
                ".local/share/goyo-sync/goyo-sync-server.py",
                &ids,
                BLOB,
                "goyo-sync PC"
            )
            .unwrap(),
            format!(
                "restrict,command=\"python3 -I .local/share/goyo-sync/goyo-sync-server.py serve --key-sync={},{}\" ssh-ed25519 {BLOB} goyo-sync PC",
                "a7".repeat(16),
                "01".repeat(16)
            )
        );
        assert_eq!(
            server_line("python3", "s.py", &[], BLOB, "goyo-sync").unwrap(),
            format!("restrict,command=\"python3 -I s.py serve\" ssh-ed25519 {BLOB} goyo-sync")
        );
        assert_eq!(
            server_line("python3", "s\".py", &[], BLOB, "goyo-sync"),
            None
        );
        assert_eq!(
            authorize_command("s.py", "/usr/bin/python3").unwrap(),
            "/usr/bin/python3 -I s.py authorize"
        );
        assert_eq!(authorize_command("s;x.py", "python3"), Err(Unsafe::Remote));
        assert_eq!(authorize_command("s.py", "-c"), Err(Unsafe::Python));
    }

    /// The line this program builds is one the shipped script's
    /// `authorize` takes: added to a temporary home's authorized_keys (never
    /// this account's), then the same again, then new IDs in its place,
    /// beside a line it leaves alone; a line with a quote in the comment is
    /// refused there too.
    #[test]
    fn the_server_script_takes_the_line() {
        use std::io::Write;
        if !crate::tests::python() {
            return;
        }
        let t = Temp::new("keysetup-authorize");
        let script = t.0.join("goyo-sync-server.py");
        fs::write(&script, setup::SERVER_SCRIPT).unwrap();
        let home = t.0.join("home");
        fs::create_dir(&home).unwrap();
        let run = |line: &str| {
            let mut child = crate::tests::python_command()
                .arg("-I")
                .arg(&script)
                .args(["authorize", "--home"])
                .arg(&home)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{line}\n").as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            authorize_result(Ok(Output {
                stdout: out.stdout,
                stderr: out.stderr,
                log: Vec::new(),
                code: out.status.code(),
                killed: None,
            }))
        };
        let c = config();
        let keys = home.join(".ssh").join("authorized_keys");
        let one = server_line(&c.python, &c.remote, &[[0xA7; 16]], BLOB, "goyo-sync PC").unwrap();
        assert_eq!(run(&one), Ok(Authorized::Added));
        assert_eq!(fs::read_to_string(&keys).unwrap(), format!("{one}\n"));
        assert_eq!(run(&one), Ok(Authorized::Same));
        let other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8 laptop";
        fs::write(&keys, format!("{other}\r\n{one}\n")).unwrap();
        let ids = [[0xA7; 16], [0x01; 16], [0xFF; 16]];
        let three = server_line(&c.python, &c.remote, &ids, BLOB, "goyo-sync PC").unwrap();
        assert_eq!(run(&three), Ok(Authorized::Replaced));
        assert_eq!(
            fs::read_to_string(&keys).unwrap(),
            format!("{other}\r\n{three}\n")
        );
        assert_eq!(
            fs::read_to_string(home.join(".ssh").join("authorized_keys.goyo-backup")).unwrap(),
            format!("{other}\r\n{one}\n")
        );
        let none = server_line(&c.python, &c.remote, &[], BLOB, "goyo-sync").unwrap();
        assert_eq!(run(&none), Ok(Authorized::Replaced));
        assert_eq!(
            run(&format!("{none}\"")),
            Err(Outcome::Script("FAIL bad line".into()))
        );
        assert_eq!(
            fs::read_to_string(&keys).unwrap(),
            format!("{other}\r\n{none}\n")
        );
    }

    /// authorize's words, a failing ssh, an older script.
    #[test]
    fn authorize_answers() {
        assert_eq!(
            authorize_result(out(0, b"ADDED\n", "")),
            Ok(Authorized::Added)
        );
        assert_eq!(
            authorize_result(out(0, b"motd\nREPLACED\n", "")),
            Ok(Authorized::Replaced)
        );
        assert_eq!(
            authorize_result(out(0, b"SAME\r\n", "")),
            Ok(Authorized::Same)
        );
        assert_eq!(
            authorize_result(out(1, b"UNRESTRICTED\n", "")),
            Err(Outcome::Unrestricted)
        );
        assert_eq!(
            authorize_result(out(1, b"FAIL authorized_keys is not a plain file\n", "")),
            Err(Outcome::Script(
                "FAIL authorized_keys is not a plain file".into()
            ))
        );
        // ADDED with a failing exit is no success.
        assert_eq!(
            authorize_result(out(1, b"ADDED\n", "")),
            Err(Outcome::Script("ADDED".into()))
        );
        assert_eq!(
            authorize_result(out(2, b"", "usage: goyo-sync-server.py serve\n")),
            Err(Outcome::Script("usage: goyo-sync-server.py serve".into()))
        );
        assert!(matches!(
            authorize_result(ssh_said("user@my-server: Permission denied (publickey).\r\n")),
            Err(Outcome::Failed(t)) if t.state == SyncState::Auth
        ));
        assert_eq!(
            authorize_result(Err(Failure::Missing)),
            Err(Outcome::Failed(Trouble::of(SyncState::NoSsh)))
        );
        let mut cancelled = out(0, b"", "").unwrap();
        cancelled.killed = Some(Killed::Cancelled);
        assert_eq!(authorize_result(Ok(cancelled)), Err(Outcome::Cancelled));
    }

    /// A new key: install, ssh-keygen (never over a file), icacls, the
    /// public key, `authorize` over the usual login with the line on stdin,
    /// then HELLO and LIST with the key. Each step that fails stops there.
    #[test]
    fn a_new_key_is_made_registered_and_checked() {
        let t = Temp::new("keysetup-new");
        let log = Log::new(Some(t.0.join(crate::LOG)));
        let dir = t.0.join(".ssh");
        let key = free_key(&dir).unwrap();
        let plan = Plan {
            key: Key::New(key.clone()),
            ids: vec![[0xA7; 16]],
            unknown: 0,
            comment: "goyo-sync PC".into(),
        };
        let script = Script::with([
            out(0, b"PASS\n", ""),
            out(0, b"", ""),
            out(0, b"processed 1 file\r\n", ""),
            public(BLOB),
            out(0, b"ADDED\n", ""),
            hello_ok(),
            list_ok(&[]),
        ]);
        let made = key.clone();
        script.on_run(move |tool, args| {
            if tool == Tool::Keygen && args.iter().any(|a| a == "-t") {
                fs::write(&made, b"private").unwrap();
                fs::write(pub_file(&made), b"public").unwrap();
            }
        });
        let c = config();
        let setup = run(&mut script.clone(), &log, &c, &plan, Some(r"PC\me"));
        assert_eq!(setup.installed, Installed::Pass);
        assert_eq!(setup.key, Some((key.clone(), true)));
        assert_eq!(setup.outcome, Some(Outcome::Ready(Authorized::Added)));
        let ran = script.ran();
        let tools: Vec<Tool> = ran.iter().map(|r| r.tool).collect();
        assert_eq!(
            tools,
            [
                Tool::Ssh,
                Tool::Keygen,
                Tool::Icacls,
                Tool::Keygen,
                Tool::Ssh,
                Tool::Ssh,
                Tool::Ssh
            ]
        );
        let text = |a: &[OsString]| {
            a.iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert!(dir.is_dir(), "the .ssh folder is made");
        assert_eq!(ran[1].args, text(&keygen_args(&key, "goyo-sync PC")));
        assert_eq!(ran[1].stdin, b"n\n");
        assert_eq!(ran[2].args, text(&acl_args(&key, r"PC\me")));
        assert_eq!(ran[3].args, text(&public_args(&key)));
        // authorize: the usual login (no -i), the fixed command, the line.
        let login = &ran[4];
        assert!(
            !login
                .args
                .iter()
                .any(|a| a == "-i" || a.contains("IdentitiesOnly"))
        );
        assert_eq!(
            login.args.last().unwrap(),
            &authorize_command(&c.remote, &c.python).unwrap()
        );
        let line = server_line(&c.python, &c.remote, &plan.ids, BLOB, "goyo-sync PC").unwrap();
        assert_eq!(login.stdin, format!("{line}\n").into_bytes());
        // The check: the key alone, through the forced command.
        for check in &ran[5..] {
            let at = check.args.iter().position(|a| a == "-i").unwrap();
            assert_eq!(check.args[at + 1], key.to_string_lossy());
            assert!(check.args.iter().any(|a| a == "IdentitiesOnly=yes"));
        }

        // The name was taken meanwhile: nothing is run after the install,
        // nothing overwritten, no key named.
        let script = Script::with([out(0, b"PASS\n", "")]);
        let setup = run(&mut script.clone(), &log, &c, &plan, Some(r"PC\me"));
        assert_eq!(setup.outcome, Some(Outcome::Taken));
        assert_eq!(setup.key, None);
        assert_eq!(script.ran().len(), 1);
        assert_eq!(fs::read(&key).unwrap(), b"private");

        // ssh-keygen fails; icacls fails; no account to grant.
        let fresh = Plan {
            key: Key::New(free_key(&dir).unwrap()),
            ..plan.clone()
        };
        let script = Script::with([out(0, b"PASS\n", ""), out(1, b"", "Saving key failed\r\n")]);
        let setup = run(&mut script.clone(), &log, &c, &fresh, Some(r"PC\me"));
        assert_eq!(
            setup.outcome,
            Some(Outcome::Keygen("Saving key failed".into()))
        );
        assert_eq!(setup.key, None);
        for (account, replies) in [
            (
                Some(r"PC\me"),
                vec![
                    out(0, b"PASS\n", ""),
                    out(0, b"", ""),
                    out(5, b"", "denied"),
                ],
            ),
            (None, vec![out(0, b"PASS\n", ""), out(0, b"", "")]),
        ] {
            let path = free_key(&dir).unwrap();
            let plan = Plan {
                key: Key::New(path.clone()),
                ..plan.clone()
            };
            let script = Script::with(replies);
            let made = path.clone();
            script.on_run(move |tool, args| {
                if tool == Tool::Keygen && args.iter().any(|a| a == "-t") {
                    fs::write(&made, b"private").unwrap();
                }
            });
            let setup = run(&mut script.clone(), &log, &c, &plan, account);
            assert_eq!(setup.outcome, Some(Outcome::Acl));
            assert_eq!(setup.key, Some((path, true)));
            assert!(
                !script
                    .ran()
                    .iter()
                    .any(|r| r.tool == Tool::Keygen && r.args[0] == "-y")
            );
        }
    }

    /// An existing key: no ssh-keygen -t, no icacls. A key others may read,
    /// one with a passphrase, an RSA key, a usual login line on the server
    /// and a failing check each stop with their own outcome; a failing
    /// install stops before any of it.
    #[test]
    fn an_existing_key_and_every_stop() {
        let t = Temp::new("keysetup-old");
        let log = Log::new(Some(t.0.join(crate::LOG)));
        let key = t.0.join("id_goyo");
        fs::write(&key, b"private").unwrap();
        let plan = Plan {
            key: Key::Existing(key.clone()),
            ids: vec![],
            unknown: 1,
            comment: "goyo-sync".into(),
        };
        let c = config();
        let go = |replies: Vec<Result<Output, Failure>>| {
            let script = Script::with(replies);
            let setup = run(&mut script.clone(), &log, &c, &plan, Some("me"));
            (setup, script.ran())
        };
        let pass = || out(0, b"PASS\n", "");
        let (setup, ran) = go(vec![
            pass(),
            public(BLOB),
            out(0, b"SAME\n", ""),
            hello_ok(),
            list_ok(&[]),
        ]);
        assert_eq!(setup.outcome, Some(Outcome::Ready(Authorized::Same)));
        assert_eq!(setup.key, Some((key.clone(), false)));
        assert_eq!(
            ran.iter().map(|r| r.tool).collect::<Vec<_>>(),
            [Tool::Ssh, Tool::Keygen, Tool::Ssh, Tool::Ssh, Tool::Ssh]
        );
        let line = server_line(&c.python, &c.remote, &[], BLOB, "goyo-sync").unwrap();
        assert!(!line.contains("--key-sync"));
        assert_eq!(ran[2].stdin, format!("{line}\n").into_bytes());
        let stops = [
            (
                vec![pass(), out(1, b"", "Load key \"x\": bad permissions\r\n")],
                Outcome::Unreadable { permissions: true },
            ),
            (
                vec![
                    pass(),
                    out(
                        1,
                        b"",
                        "Load key \"x\": incorrect passphrase supplied to decrypt private key\r\n",
                    ),
                ],
                Outcome::Unreadable { permissions: false },
            ),
            (
                vec![pass(), out(0, b"ssh-rsa AAAAB3Nza me\n", "")],
                Outcome::NotEd25519,
            ),
            (
                vec![pass(), public(BLOB), out(1, b"UNRESTRICTED\n", "")],
                Outcome::Unrestricted,
            ),
            (
                vec![
                    pass(),
                    public(BLOB),
                    out(0, b"ADDED\n", ""),
                    ssh_said("me@my-server: Permission denied (publickey).\r\n"),
                ],
                Outcome::Verify(Checked::Failed(Trouble {
                    state: SyncState::Auth,
                    cause: setup::Cause::Plain,
                    detail: "me@my-server: Permission denied (publickey).".into(),
                })),
            ),
        ];
        for (replies, outcome) in stops {
            let n = replies.len();
            let (setup, ran) = go(replies);
            assert_eq!(setup.outcome, Some(outcome));
            assert_eq!(ran.len(), n, "nothing after the stop");
        }
        // The install fails: no key step at all.
        let (setup, ran) = go(vec![out(1, b"FAIL: x\n", "")]);
        assert!(matches!(setup.installed, Installed::NotPass { .. }));
        assert_eq!((setup.key, setup.outcome, ran.len()), (None, None, 1));
    }
}
