//! What one exchange with the server gives the engine, whatever carries it:
//! goyo-sync.exe runs Windows' `ssh.exe` (its bin's transport.rs), the
//! Android app runs its own SSH client (android/rust). Either way the
//! engine sends one request frame and gets back a bounded stdout, the
//! remote side's stderr, and the transport's own messages in `log`, which
//! alone decide a failed exchange's state ([`classify`]): they are worded
//! as OpenSSH words them, and no server can write into them.
use crate::{syncfile::SyncState, syncwire::MAX_RESPONSE};
use std::path::{Path, PathBuf};

/// Banner, response header and the largest vault file.
pub const MAX_STDOUT: usize = MAX_RESPONSE;
pub const MAX_STDERR: usize = 4 * 1024;

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
    /// The transport's own messages (ssh.exe's `-E` file, or the Android
    /// client's), at most [`MAX_STDERR`] bytes; empty for any other child.
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
