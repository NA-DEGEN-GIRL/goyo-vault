//! Key-file sync in the helper (security-key build only; spec v3 §7.12,
//! §2.23 S6S-6 and S6S-7). Gate 2 checks the app's key request `kreq`; the
//! key steps send it (KR), fetch the server's top record into the key view
//! `kview` (KG) and prune old vault versions (KP). The helper keeps nothing
//! about key epochs beyond one run and never derives a request of its own:
//! it sends exactly `kreq`'s bytes to the op `kreq` names and writes what
//! the server answered into `kview`, where the app decides. It never opens
//! a key file, and it does not know where the live one is.
use super::transport::Transport;
use super::{Gate, Gated, Held, Pass, RETRY_HELD, Refusal, Vault, opened, passed};
use crate::{
    syncfile::{
        self, FileError, INCOMING, INCOMING_MAGIC, KEY_REQUEST, KEY_REQUEST_HEADER, KEY_VIEW,
        KeyOp, KeyOutcome, KeyView, MAX_KEY_REQUEST, MAX_KEY_VIEW, MAX_PRUNE_REQUEST,
        MIN_SYNC_KEY_FILE, PRUNE_REQUEST, RecordKind, RequestError, Stamp, SyncState,
        parse_key_request, parse_key_view, parse_prune_request, parse_record_header,
        render_key_view,
    },
    syncwire::{Request, Status, sha256},
};
use std::{io::Read, path::Path, time::Duration};

/// When an answered request with outcome 3 or 4 is sent again, KG asks
/// again on a line without key ops, and a PRUNE that line refused goes
/// again: at helper start, then every ten minutes.
pub const KEY_RETRY: u64 = RETRY_HELD;
/// While this PC's line serves no key ops for a vault that uses key-file
/// sync (a request, or flags bit1 on its last upload), KR and KG ask again
/// this often instead, so a line fixed on the server is seen within two
/// minutes (spec §2.29 (sync)). A request the app writes again goes at
/// once.
pub const LINE_RETRY: u64 = 120;
/// A KEY_BEHIND upload waits this long while the key view cannot show the
/// server's floor (absent, or `line` 1); otherwise it waits for the view to
/// change (S6R2 #9).
pub const BEHIND_HOURLY: u64 = 3600;
/// After this many writes of `kview` in a row failed, the vault shows
/// `config` (a read-only file, a folder planted under its name) and the
/// log says so once.
pub const VIEW_STUCK: u32 = 5;

thread_local! {
    /// How often the helper opened `kreq` or `kview` on this thread, for
    /// the tests: the listing in `Engine::due` must open neither (S6R1
    /// #25). Counted in every build, since the tests that read it are the
    /// goyo-sync bin's, which build this lib without cfg(test).
    #[doc(hidden)]
    pub static KEY_OPENS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}
fn count_open() {
    KEY_OPENS.with(|n| n.set(n.get() + 1));
}

/// A key request that passed gate 2.
#[derive(Clone)]
pub struct KeyGated {
    /// The whole file: the `GOYOSKO2` header, then the key file (a PUT).
    pub bytes: Vec<u8>,
    /// SHA-256 of the whole file: what `kview.answered` names.
    pub sha: [u8; 32],
    pub op: KeyOp,
    pub base: u64,
    /// A PUT's key-file epoch, which PUTKEY OK's record header must carry.
    pub epoch: u64,
}
impl KeyGated {
    fn payload(&self) -> &[u8] {
        &self.bytes[KEY_REQUEST_HEADER..]
    }
}
pub enum KeyGate {
    Missing,
    /// Being replaced or held open; try again on the next loop.
    Busy,
    /// Never sent (nothing is persisted: the app's next write is judged
    /// again).
    Refused(Refusal),
    Ok(KeyGated),
}
/// Gate 2 (spec v3 §7.12) on `kreq`: the file checks of the vault gate
/// (opened without following links, not a reparse point or a directory,
/// one link), the size (a CUT is exactly 32 bytes, a PUT 32 + 489 to
/// 32 + 32,768), then [`parse_key_request`] for the pinned vault ID: syntax
/// only, the exact magics, and an epoch above `floor` with no bound above
/// it (S6-2 #1). It opens nothing but `kreq`.
pub fn key_gate(path: &Path, pinned: &[u8; 16]) -> KeyGate {
    count_open();
    let (file, info) = match opened(path) {
        Ok(opened) => opened,
        Err(Gate::Missing) => return KeyGate::Missing,
        Err(Gate::Refused(why, _)) => return KeyGate::Refused(why),
        Err(_) => return KeyGate::Busy,
    };
    let put = (KEY_REQUEST_HEADER + MIN_SYNC_KEY_FILE) as u64..=MAX_KEY_REQUEST as u64;
    if info.size != KEY_REQUEST_HEADER as u64 && !put.contains(&info.size) {
        return KeyGate::Refused(Refusal::Size);
    }
    let mut bytes = Vec::with_capacity(info.size as usize);
    if (&file)
        .take(MAX_KEY_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return KeyGate::Busy;
    }
    drop(file);
    let sha = sha256(&bytes);
    match parse_key_request(&bytes, pinned) {
        Ok(r) => {
            let (op, base, epoch) = (r.op, r.base, r.epoch());
            KeyGate::Ok(KeyGated {
                bytes,
                sha,
                op,
                base,
                epoch,
            })
        }
        Err(RequestError::Format) => KeyGate::Refused(Refusal::KeyFormat),
        Err(RequestError::Id) => KeyGate::Refused(Refusal::Id),
    }
}

/// What `kview` held when it was last read or written.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum Disk {
    #[default]
    Missing,
    /// Not a plain file, or too large.
    Junk,
    Bytes([u8; 32]),
}
/// `kview` now: what is on disk and its parse (None: missing or malformed).
/// Err while another program holds it open (three tries, 50 ms apart).
fn read_view(dir: &Path, id: &[u8; 16]) -> Result<(Disk, Option<KeyView>), ()> {
    count_open();
    let path = dir.join(KEY_VIEW);
    for attempt in 0..3 {
        match syncfile::read_bounded(&path, MAX_KEY_VIEW) {
            Ok(bytes) => return Ok((Disk::Bytes(sha256(&bytes)), parse_key_view(&bytes, id))),
            Err(FileError::Missing) => return Ok((Disk::Missing, None)),
            Err(FileError::TooLarge | FileError::Io) => return Ok((Disk::Junk, None)),
            Err(FileError::Busy) if attempt < 2 => std::thread::sleep(Duration::from_millis(50)),
            Err(FileError::Busy) => {}
        }
    }
    Err(())
}
/// The content a KEY_BEHIND upload waits on.
fn content(view: &KeyView) -> [u8; 32] {
    sha256(&render_key_view(view))
}
/// Whether `kreq`, read again now, is a gate-2-valid CUT that `view` has
/// not answered (rule (b): the key bytes of a generation being ended never
/// come back after an off, S6-1 #30).
fn cut_unanswered(dir: &Path, id: &[u8; 16], view: &KeyView) -> bool {
    match key_gate(&dir.join(KEY_REQUEST), id) {
        KeyGate::Ok(g) => g.op == KeyOp::Cut && view.answered != Some(g.sha),
        _ => false,
    }
}
/// The vault head's header epoch: bytes 40..48 of the GOYOVA04 file in
/// incoming (KP); None for GOYOVA02 or no copy. Only the first 64 bytes are
/// read.
fn head_epoch(dir: &Path) -> Option<u64> {
    let (file, _) = opened(&dir.join(INCOMING)).ok()?;
    let mut head = [0u8; 64];
    (&file).read_exact(&mut head).ok()?;
    let keyed = &head[..8] == INCOMING_MAGIC && &head[16..24] == b"GOYOVA04";
    keyed.then(|| u64::from_le_bytes(head[56..64].try_into().unwrap()))
}

enum Req {
    Refused,
    Ok(KeyGated),
}
/// A `kview` the app's open handle kept out (`Busy`), flushed at the next
/// pass: only over the disk content it was made for (rule (c)), dropped by
/// any later write of this engine (rule (a)), and, as a fetched key record,
/// never while this PC's off is unanswered (rule (b)).
struct Queued {
    view: KeyView,
    against: Disk,
    fetched_key: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// No request, a refused one, or one answered for good.
    Quiet,
    /// Not answered: due unless the backoff or a LIMIT hold says wait.
    Unanswered([u8; 32]),
    /// Answered with outcome 3 or 4: due at its ten-minute retry.
    Retry,
}
/// What `Engine::due` compares the listing with: the stamps the pass
/// judged, and its verdict (S6R1 #25).
#[derive(Clone, Copy)]
struct Seen {
    req: Option<Stamp>,
    view: Option<Stamp>,
    verdict: Verdict,
}
/// One vault's key-step memory for one run (an `Engine`). A restart loses
/// all of it; every request is idempotent at the server, so the worst case
/// is one resend (spec v3 §7.12).
#[derive(Default)]
pub(super) struct Keys {
    /// `kreq` as gate 2 last judged it, by its listing stamp.
    req: Option<(Stamp, Req)>,
    /// `kview`'s stamp when last read or written, what was on disk, the
    /// view in effect (a queued one wins) and whether it is present and
    /// well formed.
    view_stamp: Option<Stamp>,
    disk: Disk,
    view: KeyView,
    present: bool,
    queued: Option<Queued>,
    /// `kview` was held open at the last pass: the next tick tries again.
    unread: bool,
    /// Writes of `kview` that failed in a row.
    stuck: u32,
    /// LIMIT: the request's SHA-256 and when it goes again.
    limit: Option<([u8; 32], u64)>,
    /// When an answer with outcome 3 or 4 goes again (0: at start).
    kr_retry: u64,
    /// When KG asks again while `line` is 1 (0: at start).
    kg_retry: u64,
    /// PRUNE: a BAD_REQUEST hold, and a request left alone until it changes.
    kp_hold: Option<(Stamp, u64)>,
    kp_ignored: Option<Stamp>,
    seen: Option<Seen>,
}
impl Keys {
    fn line_off(&self) -> bool {
        self.present && self.view.line == 1
    }
    /// The gated request if it is a CUT that the view has not answered.
    fn cut_waiting(&self) -> bool {
        matches!(&self.req, Some((_, Req::Ok(g))) if g.op == KeyOp::Cut && self.view.answered != Some(g.sha))
    }
    fn limited(&self, sha: &[u8; 32], now: u64) -> bool {
        self.limit
            .is_some_and(|(s, until)| s == *sha && !passed(until, now, RETRY_HELD))
    }
}
/// The key part of `Engine::due`: a queued or unread view; a changed
/// listing of `kreq` or `kview` (a new request is sent once even in a
/// backoff); an unanswered request unless the backoff or a LIMIT hold
/// says wait; an answer with outcome 3 or 4 at its retry. It compares
/// listed stamps with what the last pass judged and opens nothing.
pub(super) fn due(v: &Vault, now: u64, waiting: bool) -> bool {
    let k = &v.keys;
    if v.state.id.is_none() {
        return false; // no key steps before a vault ID is pinned
    }
    if k.queued.is_some() || k.unread {
        return true;
    }
    let Some(seen) = k.seen else {
        return false; // the first pass, due anyway, decides
    };
    let listed = (
        syncfile::stamp(&v.dir, KEY_REQUEST),
        syncfile::stamp(&v.dir, KEY_VIEW),
    );
    if listed != (seen.req, seen.view) {
        return true;
    }
    match seen.verdict {
        Verdict::Quiet => false,
        Verdict::Unanswered(sha) => !waiting && !k.limited(&sha, now),
        Verdict::Retry => !waiting && passed(k.kr_retry, now, KEY_RETRY),
    }
}

/// What KR did in this pass.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kr {
    NotRun,
    /// The server answered for good, and `kview` holds the answer.
    Answered,
    /// Sent with no definitive answer: a failed exchange, or LIMIT.
    Pending,
}
/// What a write of `kview` did.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrote {
    /// Written, or already on disk.
    Written,
    Queued,
    /// Rule (b): a fetched key record while this PC's off is unanswered.
    Dropped,
}
/// One answer's change to `kview`. What it leaves None keeps the value the
/// view on disk has (or the one this engine queued).
struct Update {
    /// The server's top record: its number and its bytes as served.
    top: Option<(u64, Vec<u8>)>,
    /// The request this answers and its outcome.
    answer: Option<([u8; 32], KeyOutcome)>,
    line: u8,
    /// A GETKEY answer that carries a key record (rule (b)).
    fetched_key: bool,
}
impl Update {
    fn line(line: u8) -> Self {
        Self {
            top: None,
            answer: None,
            line,
            fetched_key: false,
        }
    }
}

impl<T: Transport> Pass<'_, T> {
    /// The key steps before the vault's P3 (spec v3 §7.12): `kview` is read
    /// (and a queued one flushed), then KR, P4's choice and KG. Returns
    /// whether P4 and P5 may run in this pass, and what P4 sends.
    pub(super) fn keys_first(&mut self, id: &[u8; 16], poll: bool) -> (bool, Option<Gated>) {
        if !self.load_view(id) {
            return (false, None); // held open: the next tick tries again
        }
        let kr = self.key_request(id);
        // After KR, whose answer may have released a KEY_BEHIND upload.
        let shown = self.state;
        let upload = self.upload(id);
        let wanted = (poll && !self.waiting()) || upload.is_some();
        let go = self.key_get(id, kr, wanted);
        // A KEY_BEHIND upload that KG's new view released goes in this
        // pass, after the fetch, and no longer shows as held.
        let upload = match upload {
            None if go => {
                let released = self.upload(id);
                if released.is_some() {
                    self.state = shown;
                }
                released
            }
            upload => upload,
        };
        // `refused` while the server refuses this PC's key file, and
        // `nokeys` while this PC's line serves no key ops for a vault that
        // uses key-file sync (a request, or flags bit1 on its last upload).
        let k = &self.v.keys;
        let refused = match &k.req {
            Some((_, Req::Refused)) => true,
            Some((_, Req::Ok(g))) => {
                k.view.answered == Some(g.sha) && k.view.outcome == KeyOutcome::Refused
            }
            None => false,
        };
        let nokeys = k.line_off() && self.uses_key_sync();
        if refused {
            self.set(SyncState::Refused);
        }
        if self.v.keys.stuck >= VIEW_STUCK {
            self.set(SyncState::Config);
        }
        if nokeys {
            self.set(SyncState::NoKeys);
        }
        (go, upload)
    }
    /// After P4 and P5 (S6R2 #1): a server copy fetched in this pass waits
    /// in memory for a GETKEY made after it, so `kview` shows any cut that
    /// came before the copy before incoming holds it. When that GETKEY
    /// neither writes nor confirms `kview`, the copy is dropped unwritten
    /// and fetched again at the next poll.
    pub(super) fn keys_after_fetch(&mut self, id: &[u8; 16]) {
        if self.downloaded.is_none() || self.v.queued.is_none() || self.cancelled {
            return;
        }
        if !self.key_get(id, Kr::NotRun, true) {
            (self.v.queued, self.queued_now, self.downloaded) = (None, false, None);
            self.note("server copy not written: the key view after it is not current; fetched again later");
        }
    }
    /// The vault uses key-file sync: the app wrote a request, or the last
    /// upload's flags say GOYOKS01.
    fn uses_key_sync(&self) -> bool {
        self.v.keys.req.is_some() || self.v.out_flags & 2 != 0
    }
    /// KP, then what `Engine::due` compares the listing with.
    pub(super) fn keys_last(&mut self, id: &[u8; 16]) {
        if !self.v.keys.unread {
            self.key_prune(id);
        }
        let k = &mut self.v.keys;
        let verdict = match &k.req {
            Some((_, Req::Ok(g))) if k.view.answered == Some(g.sha) => match k.view.outcome {
                KeyOutcome::Refused | KeyOutcome::NoKeyOps => Verdict::Retry,
                _ => Verdict::Quiet,
            },
            Some((_, Req::Ok(g))) => Verdict::Unanswered(g.sha),
            _ => Verdict::Quiet,
        };
        k.seen = Some(Seen {
            req: k.req.as_ref().map(|(stamp, _)| *stamp),
            view: k.view_stamp,
            verdict,
        });
    }

    /// Reads `kview` at the start of the key steps, flushes a view this
    /// engine queued, and releases a KEY_BEHIND upload that waited for the
    /// view to change (S6R2 #9). False while `kview` is held open.
    fn load_view(&mut self, id: &[u8; 16]) -> bool {
        let dir = self.v.dir.clone();
        let stamp = syncfile::stamp(&dir, KEY_VIEW);
        let Ok((disk, parsed)) = read_view(&dir, id) else {
            self.v.keys.unread = true;
            return false;
        };
        let k = &mut self.v.keys;
        k.unread = false;
        (k.view_stamp, k.disk) = (stamp, disk);
        (k.present, k.view) = (parsed.is_some(), parsed.unwrap_or_default());
        if let Some(q) = k.queued.take() {
            if q.against == disk {
                self.store_view(id, q.view, q.fetched_key);
            } else {
                self.note("dropped a queued key view: kview changed since it was made");
            }
        }
        self.release_behind();
        true
    }
    /// A KEY_BEHIND upload that waited for the key view goes again once
    /// the view's content changed (S6R2 #9).
    fn release_behind(&mut self) {
        let k = &self.v.keys;
        let now = k.present.then(|| content(&k.view));
        if let Some(held) = self.v.held
            && held.view.is_some()
            && held.view != now
        {
            self.v.held = None;
            self.note("the key view changed; the upload refused as KEY_BEHIND goes again");
        }
    }
    /// Writes `view` as `kview`, replacing it whole; a Busy replace is
    /// queued for the next pass. Rule (b) drops a fetched key record while
    /// `kreq`, read again now, is a CUT that the view has not answered.
    fn store_view(&mut self, id: &[u8; 16], view: KeyView, fetched_key: bool) -> Wrote {
        let dir = self.v.dir.clone();
        self.v.keys.queued = None; // (a): any later write replaces a queued one
        if fetched_key && cut_unanswered(&dir, id, &view) {
            self.note("kept a fetched key record out of kview: this PC's off waits for its answer");
            return Wrote::Dropped;
        }
        let bytes = render_key_view(&view);
        let disk = Disk::Bytes(sha256(&bytes));
        let k = &mut self.v.keys;
        let wrote = if k.disk == disk {
            Wrote::Written // already on disk
        } else {
            match syncfile::replace_file(&dir.join(KEY_VIEW), &bytes) {
                Ok(()) => {
                    (k.disk, k.view_stamp) = (disk, syncfile::stamp(&dir, KEY_VIEW));
                    k.stuck = 0;
                    Wrote::Written
                }
                Err(e) => {
                    k.queued = Some(Queued {
                        view: view.clone(),
                        against: k.disk,
                        fetched_key,
                    });
                    k.stuck = k.stuck.saturating_add(1);
                    // Logged once when it starts and once when it shows.
                    if k.stuck == 1 {
                        self.note(&format!(
                            "kview not written ({e:?}); the answer stays queued"
                        ));
                    } else if k.stuck == VIEW_STUCK {
                        self.note(&format!(
                            "kview cannot be written ({e:?}): state=config until it can"
                        ));
                    }
                    Wrote::Queued
                }
            }
        };
        let k = &mut self.v.keys;
        (k.view, k.present) = (view, true);
        self.release_behind();
        wrote
    }
    /// Applies one answer to `kview`, read again first: the request it last
    /// answered and that answer's outcome stay unless this answer sets them
    /// (spec v3 §7.12).
    fn write_view(&mut self, id: &[u8; 16], update: Update) -> Wrote {
        let dir = self.v.dir.clone();
        let stamp = syncfile::stamp(&dir, KEY_VIEW);
        if let Ok((disk, parsed)) = read_view(&dir, id)
            && disk != self.v.keys.disk
        {
            // Changed behind this engine (the app deleted it, or another
            // engine wrote it): a view queued for the old content goes (c).
            let k = &mut self.v.keys;
            let dropped = k.queued.take().is_some();
            (k.view_stamp, k.disk) = (stamp, disk);
            (k.present, k.view) = (parsed.is_some(), parsed.unwrap_or_default());
            if dropped {
                self.note("dropped a queued key view: kview changed since it was made");
            }
        }
        let mut view = self.v.keys.view.clone();
        if let Some((seq, record)) = update.top {
            if seq < view.seq {
                self.note(&format!("server key record went back {}->{seq}", view.seq));
            }
            (view.seq, view.record) = (seq, record);
        }
        if let Some((sha, outcome)) = update.answer {
            (view.answered, view.outcome) = (Some(sha), outcome);
        }
        view.line = update.line;
        self.store_view(id, view, update.fetched_key)
    }

    /// KR: sends `kreq` when gate 2 accepts it and it is unanswered, or its
    /// answer had outcome 3 or 4 and the retry is due. As `push` sends a
    /// vault upload: a new request once even in the backoff, the same one
    /// again once the backoff has passed; LIMIT holds it for RETRY_HELD. A
    /// definitive answer goes into `kview` and releases a KEY_BEHIND upload.
    fn key_request(&mut self, id: &[u8; 16]) -> Kr {
        let dir = self.v.dir.clone();
        let Some(stamp) = syncfile::stamp(&dir, KEY_REQUEST) else {
            self.v.keys.req = None;
            return Kr::NotRun;
        };
        let fresh = self
            .v
            .keys
            .req
            .as_ref()
            .is_none_or(|(seen, _)| *seen != stamp);
        if fresh {
            match key_gate(&dir.join(KEY_REQUEST), id) {
                KeyGate::Missing | KeyGate::Busy => {
                    self.v.keys.req = None;
                    return Kr::NotRun;
                }
                KeyGate::Refused(why) => {
                    self.v.keys.req = Some((stamp, Req::Refused));
                    self.note(&format!(
                        "refused key request before sending: {}",
                        why.as_str()
                    ));
                }
                KeyGate::Ok(g) => self.v.keys.req = Some((stamp, Req::Ok(g))),
            }
        }
        let k = &self.v.keys;
        let Some((_, Req::Ok(g))) = &k.req else {
            return Kr::NotRun;
        };
        let skip = if k.view.answered == Some(g.sha) {
            // Answered: only outcomes 3 and 4 go again, at start, at their
            // retry (S6-2 #7, S6-1 #18) and when the app wrote the request
            // again (spec §2.29 (sync)).
            let again = matches!(k.view.outcome, KeyOutcome::Refused | KeyOutcome::NoKeyOps)
                && (fresh || passed(k.kr_retry, self.now, KEY_RETRY));
            !again || self.waiting()
        } else {
            !fresh && self.waiting() || k.limited(&g.sha, self.now)
        };
        if skip {
            return Kr::NotRun;
        }
        let g = g.clone();
        let request = match g.op {
            KeyOp::Put => Request::put_key(*id, g.base, g.payload()),
            KeyOp::Cut => Request::cut_key(*id, g.base),
        };
        let Ok(request) = request else {
            return Kr::NotRun; // gate 2 already checked this
        };
        let Some(reply) = self.call(&request) else {
            return Kr::Pending;
        };
        let now = self.time();
        let answer = |outcome| Some((g.sha, outcome));
        let top = |seq: u64, record: &[u8]| Some((seq, record.to_vec()));
        let put = g.op == KeyOp::Put;
        let update = match reply.status {
            Status::Ok if put => {
                // The header of the record the server made for this file
                // must name its epoch (spec §7.13).
                match parse_record_header(reply.blob()) {
                    Some((RecordKind::Key, _, _, floor)) if floor == g.epoch => {}
                    _ => {
                        self.note("PUTKEY OK names another epoch than the key file sent");
                        self.fail(SyncState::Server);
                        return Kr::Pending;
                    }
                }
                let record = [reply.blob(), g.payload()].concat();
                Update {
                    top: Some((reply.version, record)),
                    answer: answer(KeyOutcome::Applied),
                    line: 0,
                    fetched_key: false,
                }
            }
            Status::Ok => Update {
                top: top(reply.version, reply.blob()),
                answer: answer(KeyOutcome::Applied),
                line: 0,
                fetched_key: false,
            },
            Status::Conflict => Update {
                top: top(reply.version, reply.blob()),
                answer: answer(KeyOutcome::Conflict),
                line: 0,
                fetched_key: false,
            },
            Status::Empty => Update {
                top: top(0, &[]),
                answer: answer(KeyOutcome::Conflict),
                line: 0,
                fetched_key: false,
            },
            Status::BadBlob | Status::TooLarge => {
                self.v.keys.kr_retry = now + KEY_RETRY;
                self.note("server refused this PC's key file; sent again every 10 minutes");
                // Over no well-formed view the answer carries no top, so
                // alone it would read as `seq` 0, an empty namespace
                // (KeySyncGone): it goes in with the top a GETKEY gets now.
                let (top, fetched_key) = if self.v.keys.present {
                    (None, false)
                } else {
                    match self.call(&Request::get_key(*id, 0, None)) {
                        Some(r) if r.status == Status::Ok => {
                            let key = parse_record_header(r.blob())
                                .is_some_and(|h| h.0 == RecordKind::Key);
                            (Some((r.version, r.blob().to_vec())), key)
                        }
                        Some(r) if r.status == Status::Empty => (Some((0, Vec::new())), false),
                        Some(_) => {
                            self.fail(SyncState::Server);
                            return Kr::Pending;
                        }
                        None => return Kr::Pending,
                    }
                };
                Update {
                    top,
                    answer: answer(KeyOutcome::Refused),
                    line: 0,
                    fetched_key,
                }
            }
            // This line serves no key ops for the vault: no backoff; KR and
            // KG ask again at start and every two minutes (LINE_RETRY), KP
            // every 10.
            Status::BadRequest => {
                (self.v.keys.kr_retry, self.v.keys.kg_retry) = (now + LINE_RETRY, now + LINE_RETRY);
                Update {
                    answer: answer(KeyOutcome::NoKeyOps),
                    ..Update::line(1)
                }
            }
            Status::Limit => {
                self.v.keys.limit = Some((g.sha, now + RETRY_HELD));
                self.note(&format!("key request held; retry in {RETRY_HELD} s"));
                return Kr::Pending;
            }
            _ => {
                self.fail(SyncState::Server);
                return Kr::Pending;
            }
        };
        self.write_view(id, update);
        self.v.keys.limit = None;
        if self
            .v
            .held
            .is_some_and(|h| matches!(h.state, SyncState::KeyFile | SyncState::NoKeys))
        {
            self.v.held = None;
            self.note("key request answered; the upload refused as KEY_BEHIND goes again");
        }
        Kr::Answered
    }
    /// KG: GETKEY with what `kview` holds, right after KR and before P3-P5,
    /// in every pass where P5 runs or P4 has an upload (`wanted`); after a
    /// KR in this pass only once it was answered; never while this PC's
    /// CUT is unanswered; and while `line` is 1 only at start and every 10
    /// minutes (two for a vault that uses key-file sync). Returns the order
    /// rule (S6R2 #1): P4 and P5 run only after
    /// KG wrote `kview` or found it current, except while a CUT is
    /// unanswered or `line` is 1, where this PC has no KeySyncGone hold.
    fn key_get(&mut self, id: &[u8; 16], kr: Kr, wanted: bool) -> bool {
        let k = &self.v.keys;
        if self.cancelled {
            return false;
        }
        if !wanted || k.cut_waiting() {
            return true;
        }
        if kr == Kr::Pending {
            return false;
        }
        let line_off = k.line_off();
        if line_off && !passed(k.kg_retry, self.now, KEY_RETRY) {
            return true;
        }
        let held = k.present && k.view.seq > 0;
        let have = if held { k.view.seq } else { 0 };
        let have_sha = held.then(|| sha256(&k.view.record));
        let Some(reply) = self.call(&Request::get_key(*id, have, have_sha)) else {
            return false;
        };
        let update = match reply.status {
            Status::Ok => {
                let key = parse_record_header(reply.blob()).is_some_and(|h| h.0 == RecordKind::Key);
                Update {
                    top: Some((reply.version, reply.blob().to_vec())),
                    fetched_key: key,
                    ..Update::line(0)
                }
            }
            // Current: P4 and P5 may run, unless the view is still queued.
            Status::NotModified if !line_off => {
                let k = &self.v.keys;
                return k.queued.is_none() || matches!(k.disk, Disk::Missing | Disk::Junk);
            }
            Status::NotModified => Update::line(0),
            Status::Empty => Update {
                top: Some((0, Vec::new())),
                ..Update::line(0)
            },
            Status::BadRequest => {
                let wait = if self.uses_key_sync() {
                    LINE_RETRY
                } else {
                    KEY_RETRY
                };
                self.v.keys.kg_retry = self.time() + wait;
                Update::line(1)
            }
            _ => {
                self.fail(SyncState::Server);
                return false;
            }
        };
        match self.write_view(id, update) {
            Wrote::Written => true,
            // Not on disk yet: P4 and P5 wait, unless the app reads no view
            // at all there (missing, or not a plain file), which holds
            // nothing that waiting could add.
            Wrote::Queued => matches!(self.v.keys.disk, Disk::Missing | Disk::Junk),
            // A CUT of this PC's is unanswered: no KeySyncGone hold.
            Wrote::Dropped => true,
        }
    }
    /// KP: `prune.request` names this vault and the vault head's header
    /// epoch has reached its epoch → PRUNE. OK or NOT_FOUND deletes the
    /// request; BAD_REQUEST holds it for 10 minutes without the backoff.
    /// The request is not authenticated (R33).
    fn key_prune(&mut self, id: &[u8; 16]) {
        if self.cancelled || self.waiting() {
            return;
        }
        let dir = self.v.dir.clone();
        let Some(stamp) = syncfile::stamp(&dir, PRUNE_REQUEST) else {
            return;
        };
        let k = &self.v.keys;
        let held = k
            .kp_hold
            .is_some_and(|(s, until)| s == stamp && !passed(until, self.now, KEY_RETRY));
        if held || k.kp_ignored == Some(stamp) {
            return;
        }
        let bytes = match syncfile::read_bounded(&dir.join(PRUNE_REQUEST), MAX_PRUNE_REQUEST) {
            Ok(bytes) => bytes,
            Err(FileError::Busy) => return,
            Err(_) => Vec::new(),
        };
        let epoch = match parse_prune_request(&bytes) {
            Some((named, epoch)) if named == *id => epoch,
            _ => {
                self.v.keys.kp_ignored = Some(stamp);
                self.note("prune.request ignored: malformed, or for another vault");
                return;
            }
        };
        if head_epoch(&dir).is_none_or(|head| head < epoch) {
            return; // the vault at that epoch has not landed yet
        }
        let Ok(request) = Request::prune(*id, epoch) else {
            return;
        };
        let Some(reply) = self.call(&request) else {
            return;
        };
        match reply.status {
            Status::Ok | Status::NotFound => {
                self.note(&format!(
                    "server pruned {} vault versions below epoch {epoch}",
                    reply.version
                ));
                if syncfile::stamp(&dir, PRUNE_REQUEST) == Some(stamp) {
                    let _ = std::fs::remove_file(dir.join(PRUNE_REQUEST));
                }
            }
            Status::BadRequest => {
                self.v.keys.kp_hold = Some((stamp, self.time() + KEY_RETRY));
            }
            _ => self.fail(SyncState::Server),
        }
    }
    /// KEY_BEHIND (spec v3 §7.12, S6R2 #9, §7.20): `nokeys` for a hardware
    /// vault while this PC's line serves no key ops, else `keyfile`. While
    /// the key view is present with `line` 0 the upload waits for that view
    /// to change (KG runs before every P4, and every change of the server's
    /// top changes it) or a helper start; else it goes again hourly.
    pub(super) fn hold_behind(&mut self, sha: [u8; 32], blob: &[u8]) {
        let k = &self.v.keys;
        let hardware = blob.starts_with(b"GOYOVA04") && blob.get(64).is_some_and(|f| f & 1 != 0);
        let state = if k.line_off() && hardware {
            SyncState::NoKeys
        } else {
            SyncState::KeyFile
        };
        let view = (k.present && k.view.line == 0).then(|| content(&k.view));
        let wait = if view.is_some() {
            RETRY_HELD
        } else {
            BEHIND_HOURLY
        };
        let until = self.time() + wait;
        self.v.held = Some(Held {
            sha,
            state,
            until,
            view,
            wait,
        });
        self.set(state);
        self.succeeded();
        self.note(&match view {
            Some(_) => "upload held until the server's key record changes".into(),
            None => format!("upload held; retry in {wait} s"),
        });
    }
}
