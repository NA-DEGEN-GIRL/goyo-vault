//! The pass state machine for each vault (spec §9.5, P0 to P7). The helper
//! is an untrusted data mover: it never decrypts, never merges and never
//! opens, stats or reads the vault file or any key file. It sees only
//! `<vault>.sync\` and a listing of the vault's folder, because any open
//! handle on `vault.goyo` would make the app's save fail.
//!
//! What it uploads must pass the gate: `outgoing.goyosync`, opened without
//! following links, a single-link regular file, wrapped `GOYOSOU1` around a
//! `GOYOVA02` or `GOYOVA04` file of the pinned vault ID. A key file can fail
//! every one of those checks; failing any one means no exchange is started.
//! The security-key build adds the key steps (`keys.rs`).
//!
//! It lives in the lib so that goyo-sync.exe (Windows, which spawns
//! `ssh.exe`) and the Android app (its own SSH client, android/rust) run
//! the same passes; each brings its [`Transport`]. Nothing here opens a
//! socket or starts a process.
mod fsys;
#[cfg(feature = "security-key")]
mod keys;
pub mod transport;
use crate::{
    syncfile::{
        self, HELPER_LOCK, HELPER_STATE, HELPER_TEMPS, HelperState, INCOMING, MAX_WRAPPED,
        MIN_VAULT, OUTGOING, STATUS, Stamp, SyncState, WRAP_HEADER,
    },
    syncwire::{
        Op, RESPONSE_HEADER, Request, Response, Status, WireError, check_vault_blob, sha256,
    },
};
#[cfg(feature = "security-key")]
pub use keys::{BEHIND_HOURLY, KEY_OPENS, KEY_RETRY, KeyGate, LINE_RETRY, VIEW_STUCK, key_gate};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use transport::{Failure, KEY_IGNORED, Killed, Transport, classify, first_line, key_ignored};

/// First wait after a failed exchange; it doubles up to [`MAX_BACKOFF`].
pub const FIRST_BACKOFF: u64 = 30;
pub const MAX_BACKOFF: u64 = 15 * 60;
/// The status file is rewritten at least this often (the spec promises
/// 60 s; the app calls the helper off after 180 s without one), also while
/// a slow exchange runs.
pub const HEARTBEAT: u64 = 50;
/// A heartbeat during an exchange is never tried sooner than this after the
/// last status write or try, so a status file that cannot be replaced (the
/// app reading it, a scanner) is not retried every 50 ms.
pub const STATUS_GAP: u64 = 10;
pub const MAX_LOG: u64 = 256 * 1024;
/// An upload the server refused only for now (see [`Held`]) is tried again
/// after this long, and at once when the app writes another one.
pub const RETRY_HELD: u64 = 10 * 60;
/// The one synced format every server script takes. A script older than
/// 0.9.0 refuses GOYOVA04 (the format under a KF2 key file) as a bad blob,
/// and one older than 0.12.0 GOYOVA06 and 08 (the OTP formats) too.
const PLAIN_VAULT: &[u8; 8] = b"GOYOVA02";
/// The oldest server script that takes `blob`'s format.
fn script_for(blob: &[u8]) -> &'static str {
    if blob.starts_with(b"GOYOVA04") {
        "0.9.0"
    } else {
        "0.12.0"
    }
}

/// Seconds and nanoseconds since the Unix epoch; tests inject their own.
pub type Clock = Box<dyn Fn() -> Duration>;
pub fn system_clock() -> Clock {
    Box::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    })
}
/// `interval` scaled by 0.9 to 1.1, from the clock's nanoseconds, so PCs
/// that start together drift apart without an RNG.
pub fn jittered(interval: u64, nanos: u32) -> u64 {
    interval * (900 + u64::from(nanos % 201)) / 1000
}
/// Seconds to wait after `failures` failed exchanges in a row. A refused
/// login or a changed host key will not fix itself, so those wait longest.
pub fn backoff(failures: u32, state: SyncState) -> u64 {
    match state {
        SyncState::Auth | SyncState::HostKey => MAX_BACKOFF,
        _ => (FIRST_BACKOFF << failures.saturating_sub(1).min(5)).min(MAX_BACKOFF),
    }
}
/// Whether `deadline`, set at most `longest` seconds ahead, has passed. One
/// further ahead means the wall clock went back; waiting for it would stop
/// syncing until the clock caught up.
fn passed(deadline: u64, now: u64, longest: u64) -> bool {
    now >= deadline || deadline > now.saturating_add(longest)
}

/// `goyo-sync.log` next to the exe: one line per event, rotated to
/// `.log.1` at 256 KiB. It never holds blob bytes or file contents, but
/// may hold the host alias, so it stays on this PC.
#[derive(Clone)]
pub struct Log(Option<PathBuf>);
impl Log {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self(path)
    }
    pub fn line(&self, text: &str) {
        let Some(path) = &self.0 else {
            return;
        };
        if fs::metadata(path).is_ok_and(|m| m.len() >= MAX_LOG) {
            let mut old = path.as_os_str().to_owned();
            old.push(".1");
            let _ = fs::rename(path, old);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let text: String = text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let line = format!("{} {text}\n", utc(now));
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}
/// `2026-10-25T01:02:03Z`.
pub fn utc(secs: u64) -> String {
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}
/// The short vault name the authenticator app and the vault app show.
pub fn tag(id: &[u8; 16]) -> String {
    format!("{:02X}{:02X}-{:02X}{:02X}", id[0], id[1], id[2], id[3])
}
fn op_name(op: Op) -> &'static str {
    match op {
        Op::Hello => "HELLO",
        Op::Get => "GET",
        Op::Put => "PUT",
        Op::List => "LIST",
        Op::Fetch => "FETCH",
        #[cfg(feature = "security-key")]
        Op::PutKey => "PUTKEY",
        #[cfg(feature = "security-key")]
        Op::GetKey => "GETKEY",
        #[cfg(feature = "security-key")]
        Op::CutKey => "CUTKEY",
        #[cfg(feature = "security-key")]
        Op::Prune => "PRUNE",
    }
}
fn status_name(status: Status) -> &'static str {
    match status {
        Status::Ok => "OK",
        Status::NotModified => "NOT_MODIFIED",
        Status::Conflict => "CONFLICT",
        Status::Empty => "EMPTY",
        Status::NotFound => "NOT_FOUND",
        Status::BadRequest => "BAD_REQUEST",
        Status::BadBlob => "BAD_BLOB",
        Status::TooLarge => "TOO_LARGE",
        Status::Limit => "LIMIT",
        Status::KeyBehind => "KEY_BEHIND",
        Status::ServerError => "SERVER_ERROR",
    }
}

/// A valid response, owning the child's stdout.
pub struct Reply {
    pub status: Status,
    pub version: u64,
    /// SHA-256 of the blob (checked by `Response::decode`).
    pub sha: [u8; 32],
    data: Vec<u8>,
    at: usize,
}
impl Reply {
    pub fn blob(&self) -> &[u8] {
        &self.data[self.at..]
    }
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CallError {
    /// No valid response; the state to report and a detail for the CLI
    /// (ssh's first message, else the first stderr line marked `stderr:`,
    /// else the frame error).
    Failed(SyncState, String),
    /// The helper is stopping.
    Cancelled,
}
/// One exchange, decoded and logged. A valid response frame always wins,
/// whatever the exit code; without one the failure is classified.
pub fn call<T: Transport>(
    transport: &mut T,
    request: &Request,
    label: &str,
    log: &Log,
) -> Result<Reply, CallError> {
    call_with(transport, request, label, log, &mut || {})
}
/// [`call`], with `beat` called while the exchange runs.
fn call_with<T: Transport>(
    transport: &mut T,
    request: &Request,
    label: &str,
    log: &Log,
    beat: &mut dyn FnMut(),
) -> Result<Reply, CallError> {
    let started = Instant::now();
    let result = transport.exchange(&request.encode(), beat);
    let ms = started.elapsed().as_millis();
    let op = op_name(request.op);
    let sent = request.blob.len();
    let out = match result {
        Ok(out) => out,
        Err(failure) => {
            let state = match failure {
                Failure::Missing => SyncState::NoSsh,
                Failure::Start => SyncState::Server,
            };
            log.line(&format!(
                "{label} {op} failed state={} start={failure:?} ms={ms}",
                state.token()
            ));
            return Err(CallError::Failed(state, String::new()));
        }
    };
    // ssh ignored the dedicated key (its file's permissions) and may have
    // logged in with another one, outside the forced command: refused, as
    // a failed login, whatever came back.
    if let Some(identity) = transport.dedicated_key()
        && key_ignored(&out.log, &identity)
    {
        log.line(&format!(
            "{label} {op} failed state=auth ms={ms}: {KEY_IGNORED}; let only this Windows account read the key file (see goyo-sync's settings window)"
        ));
        return Err(CallError::Failed(SyncState::Auth, KEY_IGNORED.into()));
    }
    // ssh's own first message, and the first stderr line, which for ssh is
    // the remote side's: shown in the log, never used to pick a state.
    let (ssh, err) = (first_line(&out.log), first_line(&out.stderr));
    let exit = out.code.map_or("-".into(), |c| c.to_string());
    match Response::decode(&out.stdout, request.op, &request.vault_id, request.version) {
        Ok((response, banner)) => {
            let (status, version, sha) = (response.status, response.version, response.blob_sha);
            let received = response.blob.len();
            let note = if banner > 0 {
                format!(" banner={banner}")
            } else {
                String::new()
            };
            log.line(&format!(
                "{label} {op} {} v={version} out={sent} in={received} ms={ms} exit={exit}{note} err={err}",
                status_name(status)
            ));
            if let Some(number) = damaged_version(request.op, status, version) {
                log.line(&format!(
                    "{label} {}",
                    damaged_note(&request.vault_id, number)
                ));
            }
            Ok(Reply {
                status,
                version,
                sha,
                data: out.stdout,
                at: banner + RESPONSE_HEADER,
            })
        }
        Err(_) if out.killed == Some(Killed::Cancelled) => {
            log.line(&format!("{label} {op} cancelled ms={ms}"));
            Err(CallError::Cancelled)
        }
        Err(wire) => {
            let state = if wire == WireError::NewerFormat {
                SyncState::Update
            } else {
                classify(&out)
            };
            let killed = out.killed.map_or("-", |k| match k {
                Killed::Timeout => "timeout",
                Killed::Overflow => "overflow",
                Killed::Cancelled => "cancelled",
            });
            log.line(&format!(
                "{label} {op} failed state={} frame={} out={sent} in={} ms={ms} exit={exit} killed={killed} ssh={ssh} err={err}",
                state.token(),
                wire.as_str(),
                out.stdout.len()
            ));
            let detail = if !ssh.is_empty() {
                ssh
            } else if !err.is_empty() {
                format!("stderr: {err}")
            } else {
                wire.as_str().into()
            };
            Err(CallError::Failed(state, detail))
        }
    }
}

/// The stored version a vault op's SERVER_ERROR names as damaged: the
/// server answers so, with the version's number, when something at a
/// version name is no stored version (a link, a folder, a FIFO, a file under
/// 96 bytes or over 8 MiB). Without the number the vault would stay stuck
/// with no hint which file to repair.
pub fn damaged_version(op: Op, status: Status, version: u64) -> Option<u64> {
    (status == Status::ServerError && version >= 1 && matches!(op, Op::Get | Op::Put | Op::Fetch))
        .then_some(version)
}
/// The log line for [`damaged_version`]: the number and the server path.
pub fn damaged_note(id: &[u8; 16], number: u64) -> String {
    format!(
        "server version {number} of this vault is damaged: remove or repair data/{}/v/{number:012}.goyo on the server",
        syncfile::hex(id)
    )
}

/// An outgoing file that passed the upload gate.
pub struct Gated {
    /// The whole file: wrapper, then the vault file.
    pub bytes: Vec<u8>,
    /// SHA-256 of the whole file; `done` and `rejected` remember it.
    pub sha: [u8; 32],
    /// The server version the app merged before writing it.
    pub base: u64,
    pub id: [u8; 16],
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    Link,
    HardLink,
    NotFile,
    Size,
    Format,
    Id,
    Unreadable,
    /// Gate 2: not a key request the app writes (spec v3 §7.12).
    #[cfg(feature = "security-key")]
    KeyFormat,
}
impl Refusal {
    fn as_str(self) -> &'static str {
        match self {
            Self::Link => "a symlink or junction",
            Self::HardLink => "a file with more than one hard link",
            Self::NotFile => "not a file",
            Self::Size => "the wrong size",
            Self::Format => "not a GOYOSOU1-wrapped GOYOVA02/04 file",
            Self::Id => "a file of another vault",
            Self::Unreadable => "unreadable",
            #[cfg(feature = "security-key")]
            Self::KeyFormat => "not a GOYOSKO2 key request for a GOYOKS01 key file of this vault",
        }
    }
}
pub enum Gate {
    Missing,
    /// Being replaced or held open; try again on the next loop.
    Busy,
    /// Never uploaded; the SHA when the bytes were read.
    Refused(Refusal, Option<[u8; 32]>),
    Ok(Gated),
}
/// What both gates check before reading a file: opened without following
/// links, so a link to a key file is refused as a link and its target is
/// never opened; not a directory; and a link count of 1, which a hard link
/// to a key file exceeds.
fn opened(path: &Path) -> Result<(File, fsys::Info), Gate> {
    let file = match fsys::open_no_follow(path) {
        Ok(file) => file,
        Err(e) => {
            return Err(match e {
                fsys::OpenError::Missing => Gate::Missing,
                // Replaced right now (delete pending), or open elsewhere.
                fsys::OpenError::Busy => Gate::Busy,
                fsys::OpenError::Link => Gate::Refused(Refusal::Link, None),
                fsys::OpenError::Other => Gate::Refused(Refusal::Unreadable, None),
            });
        }
    };
    let Ok(info) = fsys::info(&file) else {
        return Err(Gate::Refused(Refusal::Unreadable, None));
    };
    if info.link {
        return Err(Gate::Refused(Refusal::Link, None));
    }
    if info.not_file {
        return Err(Gate::Refused(Refusal::NotFile, None));
    }
    match info.links {
        0 => Err(Gate::Busy), // deleted, still open elsewhere
        1 => Ok((file, info)),
        _ => Err(Gate::Refused(Refusal::HardLink, None)),
    }
}
/// Gate 2 of 3 against uploading a key file (spec §12 S11): the file
/// checks of [`opened`], then the size, the wrapper, the inner magic
/// (GOYOVA02 or GOYOVA04, each from its smallest file up) and the vault ID
/// must match, which a key file (GOYOK…) never does.
pub fn gate(path: &Path, pinned: Option<&[u8; 16]>) -> Gate {
    let (file, info) = match opened(path) {
        Ok(opened) => opened,
        Err(gate) => return gate,
    };
    let size = (WRAP_HEADER + MIN_VAULT) as u64..=MAX_WRAPPED as u64;
    if !size.contains(&info.size) {
        return Gate::Refused(Refusal::Size, None);
    }
    let mut bytes = Vec::with_capacity(info.size as usize);
    if (&file)
        .take(MAX_WRAPPED as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Gate::Busy;
    }
    drop(file);
    let sha = sha256(&bytes);
    let Some((base, vault)) = syncfile::parse_outgoing(&bytes) else {
        return Gate::Refused(Refusal::Format, Some(sha));
    };
    let id: Option<[u8; 16]> = vault.get(8..24).and_then(|s| s.try_into().ok());
    let Some(id) = id.filter(|id| *id != [0; 16] && pinned.is_none_or(|p| p == id)) else {
        return Gate::Refused(Refusal::Id, Some(sha));
    };
    Gate::Ok(Gated {
        bytes,
        sha,
        base,
        id,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Folder {
    /// No sync folder, and the vault's folder does not list the vault.
    NoVault,
    /// The sync folder is a link or not a directory.
    Unusable,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    pub state: SyncState,
    /// Server version of the copy in incoming (0 = none).
    pub server: u64,
    pub uploaded: Option<u64>,
    pub downloaded: Option<u64>,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Another goyo-sync holds `helper.lock` for this folder.
    Locked,
    /// Logged; nothing in the folder was touched (`state=config`).
    Folder(Folder),
    Done(Report),
}

struct Queued {
    version: u64,
    blob: Vec<u8>,
    logged: bool,
}
/// An upload the server refused for a reason that goes away without a new
/// file from the app (spec §7.6): a server script older than 0.9.0 (BAD_BLOB
/// for a GOYOVA04 file) or a server key file this upload does not match
/// (KEY_BEHIND). It is not remembered as rejected, so the next helper start
/// tries it at once, and this run tries it again after [`RETRY_HELD`].
#[derive(Clone, Copy)]
struct Held {
    sha: [u8; 32],
    /// `oldserver` or `keyfile` (or `nokeys`), shown while it waits.
    state: SyncState,
    until: u64,
    /// A KEY_BEHIND upload in the security-key build (spec v3 §7.12, S6R2
    /// #9): while the key view is present with `line` 0 it waits for that
    /// view's content (its SHA-256) to change, never for `until`; else
    /// `until` is an hour ahead.
    #[cfg(feature = "security-key")]
    view: Option<[u8; 32]>,
    /// How far ahead `until` was set.
    #[cfg(feature = "security-key")]
    wait: u64,
}
impl Held {
    /// Whether its wait is over.
    fn over(&self, now: u64) -> bool {
        #[cfg(feature = "security-key")]
        if self.view.is_some() {
            return false; // released when the key view changes
        }
        #[cfg(feature = "security-key")]
        let wait = self.wait;
        #[cfg(not(feature = "security-key"))]
        let wait = RETRY_HELD;
        passed(self.until, now, wait)
    }
}
/// What the helper remembers about one vault between passes.
struct Vault {
    path: PathBuf,
    dir: PathBuf,
    state: HelperState,
    loaded: bool,
    /// `helper.state` as last read or written; None if unknown.
    persisted: Option<HelperState>,
    /// A server copy not yet written to incoming (the app held it open).
    queued: Option<Queued>,
    /// The outgoing stamp last read and its SHA (None if it was refused
    /// unread, e.g. a link).
    out_seen: Option<(Stamp, Option<[u8; 32]>)>,
    /// The incoming listing that `server` and `head` were last checked
    /// against (inner None: no file); None until the first check.
    in_seen: Option<Option<Stamp>>,
    next_poll: u64,
    backoff_until: u64,
    failures: u32,
    /// The state of the last failed exchange, shown until one succeeds.
    problem: Option<SyncState>,
    /// The server answered an upload with a CONFLICT no honest server
    /// sends ([`Pass::held_back`]). Until an exchange succeeds, a new
    /// outgoing waits out the backoff too: the app writes one at each
    /// unlock while its changes are not on the server, and sending each at
    /// once would tell the server when the vault is opened.
    withheld: bool,
    /// Unix seconds of the last valid reply; None until read from status.
    contact: Option<u64>,
    /// When the status file was last written, and the state it shows.
    status_at: Option<u64>,
    shown: Option<SyncState>,
    /// When a status write was last tried, written or not.
    status_tried: Option<u64>,
    folder: Option<Folder>,
    /// The outgoing file the server refused for now.
    held: Option<Held>,
    /// Whether an outgoing that `helper.state` names as rejected may be
    /// tried once more: true until this run (the background helper's start,
    /// `--once` or "sync now") first reads an outgoing. Nothing persisted
    /// tells a 0.8 helper's refusal from this one's, so each run tries once.
    upgrade_retry: bool,
    /// The key steps' memory for this run (nothing of it is persisted).
    #[cfg(feature = "security-key")]
    keys: keys::Keys,
    /// The header flags (byte 64) of the last GOYOVA04 outgoing that passed
    /// the gate: bit0 a hardware key file, bit1 key-file sync.
    #[cfg(feature = "security-key")]
    out_flags: u8,
}
impl Vault {
    /// What a held upload `sha` shows while it waits, until its wait is
    /// over.
    fn holding(&self, sha: Option<[u8; 32]>, now: u64) -> Option<SyncState> {
        self.held
            .filter(|h| Some(h.sha) == sha && !h.over(now))
            .map(|h| h.state)
    }
}

pub struct Engine<T> {
    pub transport: T,
    vaults: Vec<Vault>,
    interval: u64,
    clock: Clock,
    log: Log,
}
impl<T: Transport> Engine<T> {
    pub fn new(transport: T, vaults: &[PathBuf], interval: u64, clock: Clock, log: Log) -> Self {
        let vaults = vaults
            .iter()
            .map(|path| Vault {
                path: path.clone(),
                dir: syncfile::sync_dir(path).unwrap_or_default(),
                state: HelperState::default(),
                loaded: false,
                persisted: None,
                queued: None,
                out_seen: None,
                in_seen: None,
                next_poll: 0, // poll at startup
                backoff_until: 0,
                failures: 0,
                problem: None,
                withheld: false,
                contact: None,
                status_at: None,
                shown: None,
                status_tried: None,
                folder: None,
                held: None,
                upgrade_retry: true,
                #[cfg(feature = "security-key")]
                keys: keys::Keys::default(),
                #[cfg(feature = "security-key")]
                out_flags: 0,
            })
            .collect();
        Self {
            transport,
            vaults,
            interval,
            clock,
            log,
        }
    }
    pub fn vaults(&self) -> usize {
        self.vaults.len()
    }
    pub fn path(&self, i: usize) -> &Path {
        &self.vaults[i].path
    }
    /// Whether vault `i` needs a pass now: a new or changed outgoing (once
    /// even during a backoff, unless the server holds back uploads), a
    /// queued incoming, a poll or a retry that is due, or the status
    /// heartbeat; in the security-key build also what the key steps cached
    /// (spec v3 §7.12). Lists the sync folder; opens nothing.
    pub fn due(&self, i: usize) -> bool {
        let now = (self.clock)().as_secs();
        let v = &self.vaults[i];
        if v.queued.is_some()
            || v.status_at
                .is_none_or(|t| passed(t + HEARTBEAT, now, HEARTBEAT))
        {
            return true;
        }
        let waiting = !passed(v.backoff_until, now, MAX_BACKOFF);
        if !waiting && passed(v.next_poll, now, 2 * self.interval) {
            return true;
        }
        #[cfg(feature = "security-key")]
        if keys::due(v, now, waiting) {
            return true;
        }
        match (syncfile::stamp(&v.dir, OUTGOING), v.out_seen) {
            (None, _) => false,
            (Some(stamp), Some((seen, sha))) if seen == stamp => {
                let handled = sha.is_none()
                    || sha == v.state.done
                    || sha == v.state.rejected
                    || v.holding(sha, now).is_some();
                !handled && !waiting
            }
            (Some(_), _) => !(waiting && v.withheld),
        }
    }
    /// One pass over vault `i`. `force` polls the server even if no poll
    /// is due (`--once`).
    pub fn pass(&mut self, i: usize, force: bool) -> Outcome {
        let now = (self.clock)();
        let poll_wait = jittered(self.interval, now.subsec_nanos());
        let Engine {
            transport,
            vaults,
            log,
            clock,
            ..
        } = self;
        // The other vaults wait behind this pass; their heartbeats go on.
        let (before, rest) = vaults.split_at_mut(i);
        let (v, after) = rest.split_at_mut(1);
        Pass {
            v: &mut v[0],
            others: [before, after],
            transport,
            log,
            clock,
            now: now.as_secs(),
            poll_wait,
            state: None,
            uploaded: None,
            downloaded: None,
            put: false,
            queued_now: false,
            cancelled: false,
        }
        .run(force)
    }
}

/// P1: the sync folder must be a plain directory. If it is missing it is
/// created, but only when the vault's folder lists the vault, so a typo in
/// the config creates nothing. Only the listing is read: the vault file is
/// never opened or stat-ed. Returns whether the folder was created.
fn folder(vault: &Path, dir: &Path) -> Result<bool, Folder> {
    if syncfile::usable_dir(dir) {
        return Ok(false);
    }
    if fs::symlink_metadata(dir).is_ok() {
        return Err(Folder::Unusable);
    }
    if !listed(vault) {
        return Err(Folder::NoVault);
    }
    let _ = fs::create_dir(dir); // not recursive
    if syncfile::usable_dir(dir) {
        Ok(true)
    } else {
        Err(Folder::Unusable)
    }
}
/// Whether the vault's folder lists the vault (not as a folder). Only the
/// listing is read, so the vault file is never opened or stat-ed: any
/// handle on it, even a brief one, can make the app's save fail.
pub fn listed(vault: &Path) -> bool {
    match (vault.parent(), vault.file_name()) {
        (Some(parent), Some(name)) => fs::read_dir(parent).is_ok_and(|entries| {
            entries.flatten().any(|e| {
                e.file_name().eq_ignore_ascii_case(name) && e.file_type().is_ok_and(|t| !t.is_dir())
            })
        }),
        _ => false,
    }
}
enum Lock {
    /// Another pass holds it (or it cannot be opened now).
    Busy,
    /// A link, a directory or a file with other names: never locked.
    NotPlain,
}
/// P0: one pass per folder at a time, across the daemon and `--once`. The
/// lock is held for the whole pass, ssh calls included, as a whole-file
/// byte-range lock, so it is opened without following links and must be a
/// plain single-link file: a planted link must not make the helper open, and
/// lock against the app, the vault or key file it points to.
fn lock(dir: &Path) -> Result<File, Lock> {
    let file = fsys::open_lock(&dir.join(HELPER_LOCK)).map_err(|_| Lock::Busy)?;
    let plain = fsys::info(&file).is_ok_and(|i| !i.link && !i.not_file && i.links == 1);
    if !plain {
        return Err(Lock::NotPlain);
    }
    file.try_lock().map_err(|_| Lock::Busy)?;
    Ok(file)
}
type InIncoming = (u64, Option<[u8; 32]>, Option<[u8; 16]>);
/// The server version, blob SHA and vault ID of the copy in incoming;
/// (0, None, None) if there is none or it is damaged. None if it could not
/// be read just now (try again later).
fn read_incoming(dir: &Path) -> Option<InIncoming> {
    let bytes = match syncfile::read_bounded(&dir.join(INCOMING), MAX_WRAPPED) {
        Ok(bytes) => bytes,
        Err(syncfile::FileError::Missing | syncfile::FileError::TooLarge) => {
            return Some((0, None, None));
        }
        Err(syncfile::FileError::Busy | syncfile::FileError::Io) => return None,
    };
    Some(match syncfile::parse_incoming(&bytes) {
        Some((version, blob)) if syncfile::is_sync_vault(blob) => {
            let id: Option<[u8; 16]> = blob.get(8..24).and_then(|s| s.try_into().ok());
            (version, Some(sha256(blob)), id.filter(|id| *id != [0; 16]))
        }
        _ => (0, None, None),
    })
}
/// As [`read_incoming`], with a failed read as no copy (for `--check`).
pub fn from_incoming(dir: &Path) -> InIncoming {
    read_incoming(dir).unwrap_or((0, None, None))
}

/// Rewrites a vault's status file while an exchange runs, if a heartbeat is
/// due, so the app does not take a slow upload for a stopped helper. `state`
/// is the current pass's; another vault shows again what it last showed, so
/// one that never showed a status is left alone. Nothing is written for a
/// folder problem, and no try comes within [`STATUS_GAP`] of the last one.
fn refresh(v: &mut Vault, state: Option<SyncState>, now: u64) {
    let Some(state) = state.or(v.shown) else {
        return;
    };
    let due = v
        .status_at
        .is_none_or(|t| passed(t + HEARTBEAT, now, HEARTBEAT));
    let tried = v.status_tried.is_some_and(|t| t.abs_diff(now) < STATUS_GAP);
    // A folder replaced by a link since the pass looked could point anywhere.
    if v.folder.is_some() || !due || tried || !syncfile::usable_dir(&v.dir) {
        return;
    }
    v.status_tried = Some(now);
    let status = syncfile::render_status(now, v.contact.unwrap_or(0), state);
    if syncfile::replace_file(&v.dir.join(STATUS), &status).is_ok() {
        (v.status_at, v.shown) = (Some(now), Some(state));
    }
}

/// One pass over one vault.
struct Pass<'a, T> {
    v: &'a mut Vault,
    /// The vaults before and after this one, for their heartbeats.
    others: [&'a mut [Vault]; 2],
    transport: &'a mut T,
    log: &'a Log,
    clock: &'a Clock,
    /// The time the pass started; [`Pass::time`] is the time now.
    now: u64,
    poll_wait: u64,
    /// The first problem met in this pass; it decides `state=`.
    state: Option<SyncState>,
    uploaded: Option<u64>,
    downloaded: Option<u64>,
    /// A PUT was sent: its reply told the head, so no GET is needed.
    put: bool,
    /// A server copy was queued in this pass (P6 has work).
    queued_now: bool,
    cancelled: bool,
}
impl<T: Transport> Pass<'_, T> {
    fn run(mut self, force: bool) -> Outcome {
        // P1
        match folder(&self.v.path, &self.v.dir) {
            // A new folder starts unpinned: deleting the folder is how a user
            // resets sync, e.g. for a new vault created at the same path.
            Ok(true) => {
                let v = &mut *self.v;
                (v.state, v.persisted, v.queued) = (HelperState::default(), None, None);
                (v.out_seen, v.in_seen, v.held) = (None, None, None);
                #[cfg(feature = "security-key")]
                {
                    (v.keys, v.out_flags) = (keys::Keys::default(), 0);
                }
                self.note("created the sync folder");
            }
            Ok(false) => {}
            Err(Folder::NoVault) => {
                return self.skip(
                    Folder::NoVault,
                    "state=config: the vault file is not in its folder",
                );
            }
            Err(Folder::Unusable) => {
                return self.skip(
                    Folder::Unusable,
                    "state=config: the sync folder is a link or not a folder",
                );
            }
        }
        // P0
        let _lock = match lock(&self.v.dir) {
            Ok(file) => file,
            Err(Lock::Busy) => return Outcome::Locked,
            Err(Lock::NotPlain) => {
                return self.skip(
                    Folder::Unusable,
                    "state=config: helper.lock is a link or not a plain file",
                );
            }
        };
        self.v.folder = None;
        syncfile::remove_own_temps(&self.v.dir, &HELPER_TEMPS);
        self.load();
        // P2
        if self.v.state.id.is_none() {
            self.pin();
        }
        if let Some(id) = self.v.state.id {
            let poll = force || passed(self.v.next_poll, self.now, 2 * self.poll_wait);
            #[cfg(not(feature = "security-key"))]
            let (go, upload) = {
                self.flush(); // P3
                (true, self.upload(&id))
            };
            // KR, P4's choice and KG come first; P4 and P5 wait while KG has
            // not written or confirmed the key view (spec v3 §7.12).
            #[cfg(feature = "security-key")]
            let (go, upload) = {
                let first = self.keys_first(&id, poll);
                self.flush(); // P3
                first
            };
            if go {
                let ok = self.push(upload); // P4
                if ok && !self.put && !self.cancelled && poll && !self.waiting() {
                    self.pull(&id); // P5
                }
            }
            // A server copy that P4's CONFLICT or P5 brought is written only
            // after a GETKEY made after it (S6R2 #1): a cut that came before
            // the copy is then in kview before the copy is in incoming.
            #[cfg(feature = "security-key")]
            self.keys_after_fetch(&id);
            #[cfg(feature = "security-key")]
            self.keys_last(&id); // KP
            if self.queued_now {
                self.flush(); // P6
            }
        } else {
            // Nothing to ask the server yet: wait for the app's outgoing.
            self.v.next_poll = self.now + self.poll_wait;
        }
        self.finish() // P7
    }
    fn label(&self) -> String {
        match self.v.state.id {
            Some(id) => tag(&id),
            None => self
                .v
                .path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        }
    }
    fn note(&self, text: &str) {
        self.log.line(&format!("{} {text}", self.label()));
    }
    /// A folder problem: nothing in the folder is touched, the log says why
    /// once, and the folder is looked at again at the heartbeat pace.
    fn skip(&mut self, problem: Folder, why: &str) -> Outcome {
        if self.v.folder != Some(problem) {
            self.note(why);
        }
        self.v.folder = Some(problem);
        self.v.status_at = Some(self.now);
        self.v.next_poll = self.now + self.poll_wait;
        Outcome::Folder(problem)
    }
    fn set(&mut self, state: SyncState) {
        self.state.get_or_insert(state);
    }
    /// The time now: an exchange can take minutes.
    fn time(&self) -> u64 {
        (self.clock)().as_secs()
    }
    /// What the status file shows for this pass so far: its first problem,
    /// else a failed exchange's that still stands, else ok (idle while no
    /// vault ID is pinned).
    fn shown(&self) -> SyncState {
        match self.v.state.id {
            None => self.state.unwrap_or(SyncState::Idle),
            Some(_) => self.state.or(self.v.problem).unwrap_or(SyncState::Ok),
        }
    }
    fn fail(&mut self, state: SyncState) {
        self.v.failures = self.v.failures.saturating_add(1);
        let wait = backoff(self.v.failures, state);
        // From the end of the failed exchange, which may have taken the
        // whole ssh timeout: counted from the pass's start, a short wait
        // would already be over.
        self.v.backoff_until = self.time() + wait;
        self.v.problem = Some(state);
        self.set(state);
        self.note(&format!("retry in {wait} s"));
    }
    /// Still in the wait after a failed exchange.
    fn waiting(&self) -> bool {
        !passed(self.v.backoff_until, self.now, MAX_BACKOFF)
    }
    fn succeeded(&mut self) {
        (self.v.failures, self.v.backoff_until, self.v.problem) = (0, 0, None);
        self.v.withheld = false;
    }
    /// The server's head is known now; the next poll can wait.
    fn heard(&mut self) {
        self.succeeded();
        self.v.next_poll = self.time() + self.poll_wait;
    }
    /// One exchange. While it runs, the status files of this and every
    /// other vault keep their heartbeat.
    fn call(&mut self, request: &Request) -> Option<Reply> {
        let (label, state) = (self.label(), self.shown());
        let Pass {
            v,
            others,
            transport,
            log,
            clock,
            ..
        } = self;
        let mut beat = || {
            let now = clock().as_secs();
            refresh(v, Some(state), now);
            for other in others.iter_mut().flat_map(|o| o.iter_mut()) {
                refresh(other, None, now);
            }
        };
        match call_with(*transport, request, &label, log, &mut beat) {
            Ok(reply) => {
                self.v.contact = Some(self.time());
                Some(reply)
            }
            Err(CallError::Cancelled) => {
                self.cancelled = true;
                None
            }
            Err(CallError::Failed(state, _)) => {
                self.fail(state);
                None
            }
        }
    }

    /// Reads helper.state; one written by another pass (`--once`) wins over
    /// memory. Then `server` and `head` are checked against incoming itself
    /// whenever its listing changed since the last check, and once at
    /// startup. They are what GET sends as "have": if they named a copy that
    /// incoming no longer holds (state lost, or incoming deleted or damaged
    /// behind the helper's back), the server would answer NOT_MODIFIED
    /// forever, a dead upload would queue nothing, and the app would never
    /// see the head again. A wrong state costs at most one redundant request.
    fn load(&mut self) {
        if self.v.contact.is_none() {
            let old = syncfile::read_status(&self.v.dir).map_or(0, |s| s.contact);
            self.v.contact = Some(old);
        }
        // A zero ID is never pinned, so such a file is damaged.
        let disk = syncfile::read_helper_state(&self.v.dir).filter(|s| s.id != Some([0; 16]));
        let missing = disk.is_none();
        match disk {
            Some(disk) if Some(disk) != self.v.persisted => {
                if self.v.loaded && self.v.queued.take().is_some() {
                    self.note("helper.state changed by another pass; dropped a queued copy");
                }
                (self.v.state, self.v.persisted) = (disk, Some(disk));
                self.v.in_seen = None; // checked against incoming below
            }
            // As last written or read; memory may be ahead of a failed write.
            Some(_) => {}
            None => {
                if self.v.persisted.is_some() {
                    self.note("helper.state missing or damaged; written again");
                }
                self.v.persisted = None;
            }
        }
        let listed = syncfile::stamp(&self.v.dir, INCOMING);
        if self.v.in_seen != Some(listed)
            && let Some((server, head, id)) = read_incoming(&self.v.dir)
        {
            let old = self.v.state.server;
            if (server, head) != (old, self.v.state.head) {
                self.note(&if missing && !self.v.loaded {
                    format!(
                        "helper.state missing or damaged; rebuilt from incoming (server={server})"
                    )
                } else {
                    format!("incoming changed outside the helper; server {old}->{server}")
                });
                (self.v.state.server, self.v.state.head) = (server, head);
            }
            if self.v.state.id.is_none() {
                self.v.state.id = id;
            }
            self.v.in_seen = Some(listed);
        }
        self.v.loaded = true;
    }
    /// P2: the first valid outgoing pins the vault ID (incoming already did
    /// in `load` if there is one).
    fn pin(&mut self) {
        let Some(stamp) = syncfile::stamp(&self.v.dir, OUTGOING) else {
            self.v.out_seen = None;
            return;
        };
        if let Some(gated) = self.outgoing(stamp, None) {
            self.v.state.id = Some(gated.id);
            self.note("pinned this vault ID from the app's first upload");
        }
    }
    /// The outgoing file at `stamp` if it still needs uploading. A refusal
    /// is remembered by stamp and SHA, so it is logged once and not retried
    /// until the app writes a new file; while it stands, state=refused. A
    /// held file waits out its retry time, showing its own state.
    fn outgoing(&mut self, stamp: Stamp, pinned: Option<&[u8; 16]>) -> Option<Gated> {
        if let Some((seen, sha)) = self.v.out_seen
            && seen == stamp
        {
            if sha.is_none() || sha == self.v.state.rejected {
                self.set(SyncState::Refused);
                return None;
            }
            if sha == self.v.state.done {
                return None;
            }
            if let Some(state) = self.v.holding(sha, self.now) {
                self.set(state);
                return None;
            }
        }
        match gate(&self.v.dir.join(OUTGOING), pinned) {
            Gate::Missing | Gate::Busy => None,
            Gate::Refused(why, sha) => {
                self.v.upgrade_retry = false;
                self.v.out_seen = Some((stamp, sha));
                if sha.is_some() {
                    self.v.state.rejected = sha;
                }
                self.note(&format!("refused outgoing before upload: {}", why.as_str()));
                self.set(SyncState::Refused);
                None
            }
            Gate::Ok(gated) => {
                self.v.out_seen = Some((stamp, Some(gated.sha)));
                #[cfg(feature = "security-key")]
                {
                    let vault = &gated.bytes[WRAP_HEADER..];
                    let keyed = syncfile::keyed_vault(vault);
                    self.v.out_flags = vault.get(64).filter(|_| keyed).copied().unwrap_or(0);
                }
                let retry = std::mem::take(&mut self.v.upgrade_retry);
                if Some(gated.sha) == self.v.state.done {
                    None
                } else if Some(gated.sha) == self.v.state.rejected {
                    // The gate of a helper older than 0.9.0 refused every
                    // GOYOVA04 file, and one older than 0.12.0 every
                    // GOYOVA06/08 file: one that passes this gate is tried
                    // once in each run of this helper (spec §7.6). Another
                    // refusal is kept for the rest of the run.
                    let vault = &gated.bytes[WRAP_HEADER..];
                    if retry && !vault.starts_with(PLAIN_VAULT) {
                        self.note(&format!(
                            "retrying a {} upload an older helper refused",
                            String::from_utf8_lossy(vault.get(..8).unwrap_or_default())
                        ));
                        self.v.state.rejected = None;
                        return Some(gated);
                    }
                    self.set(SyncState::Refused);
                    None
                } else if let Some(state) = self.v.holding(Some(gated.sha), self.now) {
                    self.set(state);
                    None
                } else {
                    Some(gated)
                }
            }
        }
    }
    /// Queues a server copy for incoming unless incoming already holds it.
    /// True if queued.
    fn queue(&mut self, version: u64, blob: &[u8]) -> bool {
        let sha = sha256(blob);
        if (version, Some(sha)) == (self.v.state.server, self.v.state.head) {
            self.v.queued = None;
            return false;
        }
        if version < self.v.state.server {
            self.note(&format!(
                "server version went back {}->{version}",
                self.v.state.server
            ));
        }
        self.v.queued = Some(Queued {
            version,
            blob: blob.to_vec(),
            logged: false,
        });
        self.queued_now = true;
        true
    }
    /// P3 and P6: incoming is written only by replacing it; while the app
    /// holds it open the copy stays queued for the next 2 s loop. Only a
    /// written copy moves `server` and `head`.
    fn flush(&mut self) {
        let Some(mut q) = self.v.queued.take() else {
            return;
        };
        let Some(bytes) = syncfile::render_incoming(q.version, &q.blob) else {
            return;
        };
        match syncfile::replace_file(&self.v.dir.join(INCOMING), &bytes) {
            Ok(()) => {
                self.v.state.server = q.version;
                self.v.state.head = Some(sha256(&q.blob));
                // Only this helper writes incoming, and it holds helper.lock.
                self.v.in_seen = Some(syncfile::stamp(&self.v.dir, INCOMING));
            }
            Err(e) => {
                if !q.logged {
                    self.note(&format!(
                        "incoming not written ({e:?}); version {} stays queued",
                        q.version
                    ));
                    q.logged = true;
                }
                self.v.queued = Some(q);
            }
        }
    }
    /// P4's choice: the outgoing file to send now, if any.
    fn upload(&mut self, id: &[u8; 16]) -> Option<Gated> {
        let Some(stamp) = syncfile::stamp(&self.v.dir, OUTGOING) else {
            self.v.out_seen = None;
            return None;
        };
        let fresh = self.v.out_seen.is_none_or(|(seen, _)| seen != stamp);
        if (!fresh || self.v.withheld) && self.waiting() {
            // Waiting out a failure; a new outgoing gets one attempt anyway,
            // unless the server is holding back uploads.
            if let Some((_, sha)) = self.v.out_seen {
                if sha.is_none() || sha == self.v.state.rejected {
                    self.set(SyncState::Refused);
                } else if let Some(state) = self.v.holding(sha, self.now) {
                    self.set(state);
                }
            }
            return None;
        }
        self.outgoing(stamp, Some(id))
    }
    /// P4. False if an exchange failed, which ends the pass's network use.
    fn push(&mut self, upload: Option<Gated>) -> bool {
        match upload {
            Some(gated) => self.put(&gated, gated.base, true),
            None => true,
        }
    }
    fn put(&mut self, gated: &Gated, expected: u64, empty_retry: bool) -> bool {
        let blob = &gated.bytes[WRAP_HEADER..];
        let Ok(request) = Request::put(gated.id, expected, blob) else {
            return true; // the gate already checked this
        };
        self.put = true;
        let Some(reply) = self.call(&request) else {
            return false;
        };
        match reply.status {
            Status::Ok => {
                self.queue(reply.version, blob);
                self.v.state.done = Some(gated.sha);
                self.uploaded = Some(reply.version);
                self.heard();
            }
            // Not queued, since the open app would merge it and upload again
            // at once, and not done: the newest file is tried again after
            // the backoff, and new ones wait for it (`withheld`).
            Status::Conflict
                if reply.sha != request.blob_sha && self.held_back(&reply, expected) =>
            {
                let why = if reply.version == expected {
                    format!("its head is version {expected}, the one this upload expected")
                } else {
                    format!(
                        "its head is the copy already held as version {}, numbered {}",
                        self.v.state.server, reply.version
                    )
                };
                self.note(&format!(
                    "server answered CONFLICT although {why}: it is holding back uploads"
                ));
                self.v.withheld = true;
                self.fail(SyncState::Server);
                return false;
            }
            Status::Conflict => {
                if reply.sha == request.blob_sha {
                    // Committed by an earlier attempt whose OK was lost.
                    self.queue(reply.version, blob);
                    self.uploaded = Some(reply.version);
                    self.note("upload was already on the server");
                } else {
                    // Another PC was first: this file is dead, and the app
                    // merges the head and writes a new one.
                    if self.queue(reply.version, reply.blob()) {
                        self.downloaded = Some(reply.version);
                    }
                    self.note(&format!(
                        "upload lost to server version {}; the app merges it",
                        reply.version
                    ));
                }
                self.v.state.done = Some(gated.sha);
                self.heard();
            }
            // The server was wiped or restored: seed it again, once.
            Status::Empty if empty_retry => {
                self.note("server has no copy; uploading as the first version");
                return self.put(gated, 0, false);
            }
            // Refusals that a server update or a new key file clears.
            Status::BadBlob if !blob.starts_with(PLAIN_VAULT) => {
                self.note(&format!(
                    "server refused {}: its goyo-sync script is older than {}; \
                     use 'Install or update on server'",
                    String::from_utf8_lossy(blob.get(..8).unwrap_or_default()),
                    script_for(blob)
                ));
                self.hold(gated.sha, SyncState::OldServer);
            }
            Status::KeyBehind => {
                self.note(
                    "server refused the upload: its key file for this vault has another state",
                );
                #[cfg(not(feature = "security-key"))]
                self.hold(gated.sha, SyncState::KeyFile);
                #[cfg(feature = "security-key")]
                self.hold_behind(gated.sha, blob);
            }
            Status::BadBlob | Status::TooLarge | Status::Limit | Status::BadRequest => {
                self.v.state.rejected = Some(gated.sha);
                self.set(SyncState::Refused);
                self.succeeded();
            }
            _ => {
                self.fail(SyncState::Server);
                return false;
            }
        }
        true
    }
    /// The server refused upload `sha` for now: it shows `state` and is
    /// sent again after RETRY_HELD, or never if the app writes another file
    /// first, which is sent at once. Nothing is persisted (spec §7.6).
    fn hold(&mut self, sha: [u8; 32], state: SyncState) {
        let until = self.time() + RETRY_HELD;
        self.v.held = Some(Held {
            sha,
            state,
            until,
            #[cfg(feature = "security-key")]
            view: None,
            #[cfg(feature = "security-key")]
            wait: RETRY_HELD,
        });
        self.set(state);
        self.succeeded();
        self.note(&format!("upload held; retry in {RETRY_HELD} s"));
    }
    /// A CONFLICT, with a head other than the upload, that no honest server
    /// sends: its compare-and-swap answers CONFLICT only when the head is
    /// not the version the upload expected, and every head is a new upload
    /// with fresh bytes, except a re-seed, which stores a copy a PC held as
    /// version 1. A server that answers so keeps this PC's uploads out, and
    /// taking its head would only make the app merge and upload again.
    fn held_back(&self, reply: &Reply, expected: u64) -> bool {
        let replayed = Some(reply.sha) == self.v.state.head
            && reply.version != self.v.state.server
            && reply.version != 1;
        reply.version == expected || replayed
    }
    /// P5: ask for the head, sending the version and SHA already held.
    fn pull(&mut self, id: &[u8; 16]) {
        let request = Request::get(*id, self.v.state.server, self.v.state.head);
        let Some(reply) = self.call(&request) else {
            return;
        };
        match reply.status {
            Status::Ok => {
                if self.queue(reply.version, reply.blob()) {
                    self.downloaded = Some(reply.version);
                }
                self.heard();
            }
            Status::NotModified => self.heard(),
            Status::Empty => {
                self.succeeded();
                self.reseed(id);
            }
            _ => self.fail(SyncState::Server),
        }
    }
    /// GET said the server has no copy (wiped or restored): put back the
    /// last copy this PC fetched, so no app has to react.
    fn reseed(&mut self, id: &[u8; 16]) {
        let blob = match syncfile::read_bounded(&self.v.dir.join(INCOMING), MAX_WRAPPED) {
            // The app is reading it: try again on the next loop.
            Err(syncfile::FileError::Busy) => return,
            Err(_) => None,
            Ok(bytes) => syncfile::parse_incoming(&bytes)
                .filter(|(_, blob)| check_vault_blob(blob, id).is_ok())
                .map(|(_, blob)| blob.to_vec()),
        };
        let Some(blob) = blob else {
            // Nothing fetched yet; the app's outgoing seeds the server. The
            // wait counts from now, after the GET, as in `heard`.
            self.v.next_poll = self.time() + self.poll_wait;
            return;
        };
        let Ok(request) = Request::put(*id, 0, &blob) else {
            return;
        };
        self.put = true;
        let Some(reply) = self.call(&request) else {
            return;
        };
        match reply.status {
            Status::Ok => {
                self.queue(reply.version, &blob);
                self.uploaded = Some(reply.version);
                self.note("server was empty; re-uploaded the last known copy");
                self.heard();
            }
            Status::Conflict => {
                // Another PC re-seeded first.
                if self.queue(reply.version, reply.blob()) {
                    self.downloaded = Some(reply.version);
                }
                self.heard();
            }
            Status::BadBlob if !blob.starts_with(PLAIN_VAULT) => {
                self.set(SyncState::OldServer);
                self.heard();
            }
            Status::KeyBehind => {
                self.set(SyncState::KeyFile);
                self.heard();
            }
            Status::BadBlob | Status::TooLarge | Status::Limit | Status::BadRequest => {
                self.set(SyncState::Refused);
                self.heard();
            }
            _ => self.fail(SyncState::Server),
        }
    }
    /// P7: helper.state when it changed, then the status file, which also
    /// serves as the heartbeat. A failed write is retried next loop.
    fn finish(self) -> Outcome {
        // The time now, not the pass's start: after a long upload that
        // heartbeat would already look stale, and older than one written
        // during the upload.
        let (state, now) = (self.shown(), self.time());
        let v = self.v;
        if v.persisted != Some(v.state) {
            let bytes = syncfile::render_helper_state(&v.state);
            match syncfile::replace_file(&v.dir.join(HELPER_STATE), &bytes) {
                Ok(()) => v.persisted = Some(v.state),
                Err(e) => self.log.line(&format!("helper.state not written ({e:?})")),
            }
        }
        let status = syncfile::render_status(now, v.contact.unwrap_or(0), state);
        v.status_tried = Some(now);
        if syncfile::replace_file(&v.dir.join(STATUS), &status).is_ok() {
            (v.status_at, v.shown) = (Some(now), Some(state));
        }
        Outcome::Done(Report {
            state,
            server: v.state.server,
            uploaded: self.uploaded,
            downloaded: self.downloaded,
        })
    }
}
