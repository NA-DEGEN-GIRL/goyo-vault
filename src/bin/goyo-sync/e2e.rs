//! Two PCs end to end (spec §17 item 22). Each simulated PC is a GoyoVault
//! folder with real vault sessions, its own sync folder and its own helper
//! engine; the two share one synthetic key, copied as by USB. The server is
//! the real script run locally (`python server/goyo-sync-server.py serve
//! --root <tmp>`) through the same bounded runner as ssh.exe. Helper passes
//! alternate with the app's `poll_sync` and, for an app that was closed,
//! with a fresh unlock. Nothing runs ssh or touches the registry. Without
//! python the tests that need it fail loudly, unless GOYO_SYNC_SKIP_PYTHON=1.
use super::*;
use crate::{
    engine::system_clock,
    tests::{Local, Temp, junction, python},
    transport::Output,
};
use goyo_vault::{
    crypto::AUTH_ERROR,
    otp,
    syncfile::{HELPER_STATE, INCOMING, OUTGOING},
    syncwire::{Op, Response, sha256},
    vault::{Entry, Format, MAX_FILE, Provision, Session, SyncBadge, SyncEvent, SyncNotice},
};
use std::{fs, time::Instant};

const PASSWORD: &str = "a long synthetic password";

/// One simulated PC: its GoyoVault folder and its running helper.
struct Pc {
    t: Temp,
    vault: PathBuf,
    key: PathBuf,
    dir: PathBuf,
    root: PathBuf,
    helper: Engine<Local>,
}
impl Pc {
    fn new(name: &str, store: &Store) -> Self {
        let t = Temp::new(name);
        let vault = t.0.join("vault.goyo");
        let helper = engine(&t.0, &vault, &store.root);
        Self {
            key: t.0.join("vault.goyokey"),
            dir: t.0.join("vault.goyo.sync"),
            root: store.root.clone(),
            vault,
            t,
            helper,
        }
    }
    /// The helper started again: what it held in memory is gone.
    fn restart(&mut self) {
        self.helper = engine(&self.t.0, &self.vault, &self.root);
    }
    /// One helper pass that also asks the server for news, as a pass does
    /// once a poll is due.
    fn pass(&mut self) -> Report {
        match self.helper.pass(0, true) {
            Outcome::Done(report) => report,
            other => panic!("{other:?}"),
        }
    }
    fn unlock(&self, code: &str) -> Session {
        Session::unlock(&self.vault, &self.key, PASSWORD, code).unwrap()
    }
    /// The base of the app's waiting upload, if any.
    fn outgoing(&self) -> Option<u64> {
        let bytes = fs::read(self.dir.join(OUTGOING)).ok()?;
        syncfile::parse_outgoing(&bytes).map(|(base, _)| base)
    }
    fn upload(&self) -> Vec<u8> {
        let bytes = fs::read(self.dir.join(OUTGOING)).unwrap();
        syncfile::parse_outgoing(&bytes).unwrap().1.to_vec()
    }
    fn incoming(&self) -> Option<(u64, Vec<u8>)> {
        let bytes = fs::read(self.dir.join(INCOMING)).ok()?;
        syncfile::parse_incoming(&bytes).map(|(v, b)| (v, b.to_vec()))
    }
    fn log(&self) -> String {
        fs::read_to_string(self.t.0.join(LOG)).unwrap_or_default()
    }
    /// What the vault file holds, opened as a copy elsewhere, where there
    /// is no sync folder to merge.
    fn on_disk(&self) -> Vec<String> {
        let t = Temp::new("copy");
        let (vault, key) = (t.0.join("vault.goyo"), t.0.join("vault.goyokey"));
        fs::copy(&self.vault, &vault).unwrap();
        fs::copy(&self.key, &key).unwrap();
        titles(&Session::unlock(&vault, &key, PASSWORD, "").unwrap())
    }
}
fn engine(folder: &Path, vault: &Path, root: &Path) -> Engine<Local> {
    let local = Local {
        root: root.to_path_buf(),
    };
    let log = Log::new(Some(folder.join(LOG)));
    Engine::new(local, &[vault.to_path_buf()], 60, system_clock(), log)
}
fn report(state: SyncState, server: u64, up: Option<u64>, down: Option<u64>) -> Report {
    Report {
        state,
        server,
        uploaded: up,
        downloaded: down,
    }
}

/// The server's storage folder.
struct Store {
    _t: Temp,
    root: PathBuf,
}
impl Store {
    fn new() -> Self {
        let t = Temp::new("server");
        let root = t.0.join("data");
        Self { _t: t, root }
    }
    fn local(&self) -> Local {
        Local {
            root: self.root.clone(),
        }
    }
    fn versions(&self, id: &[u8; 16]) -> Vec<(u64, Vec<u8>)> {
        self.local().versions(id)
    }
    fn version(&self, id: &[u8; 16], n: u64) -> PathBuf {
        let name = format!("{n:012}.goyo");
        self.root.join(syncfile::hex(id)).join("v").join(name)
    }
    /// A frame sent as is, the way the helper never would.
    fn post(&self, frame: &[u8]) -> Output {
        self.local().exchange(frame, &mut || {}).unwrap()
    }
    /// Every file under the storage folder, with its contents.
    fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            for e in fs::read_dir(dir).unwrap().flatten() {
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), out);
                } else {
                    out.push((e.path(), fs::read(e.path()).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out.sort();
        out
    }
    /// Gate 3 and the end check of spec §12 S11: every file the server
    /// keeps is a version of vault `id` (GOYOVA02 and that ID up front) and
    /// holds no stretch of the key file.
    fn holds_only_vault_files(&self, id: &[u8; 16], key: &[u8]) {
        let files = self.files();
        assert!(!files.is_empty());
        for (path, data) in &files {
            let rel = path.strip_prefix(&self.root).unwrap();
            let parts: Vec<String> = rel
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            assert_eq!(parts.len(), 3, "{rel:?}");
            assert_eq!((&*parts[0], &*parts[1]), (&*syncfile::hex(id), "v"));
            assert!(
                parts[2].len() == 17 && parts[2].ends_with(".goyo"),
                "{rel:?}"
            );
            assert!(
                data.starts_with(b"GOYOVA02") && data[8..24] == id[..],
                "{rel:?}"
            );
            assert!(
                !data.windows(32).any(|w| key.windows(32).any(|k| k == w)),
                "{rel:?} holds key-file bytes"
            );
        }
    }
}
fn put_frame(id: [u8; 16], expected: u64, blob: &[u8]) -> Vec<u8> {
    let request = Request {
        op: Op::Put,
        vault_id: id,
        version: expected,
        blob_sha: sha256(blob),
        blob,
    };
    request.encode()
}

fn entry(title: &str, secret: &str) -> Entry {
    Entry::new(title.into(), "login".into(), secret.into(), String::new()).unwrap()
}
/// `title=secret` of every entry, sorted: merges may reorder entries.
fn titles(s: &Session) -> Vec<String> {
    let mut t: Vec<String> = s
        .entries
        .iter()
        .map(|e| format!("{}={}", e.title.as_str(), e.secret.as_str()))
        .collect();
    t.sort();
    t
}
fn find(s: &Session, title: &str) -> usize {
    s.entries.iter().position(|e| *e.title == title).unwrap()
}
fn notice(event: Option<SyncEvent>) -> Option<SyncNotice> {
    event.and_then(|e| e.notice)
}
fn synced(s: &Session) -> Option<SyncNotice> {
    Some(SyncNotice::Synced {
        code: s.check_code(),
    })
}
fn merged(added: usize, removed: usize) -> Option<SyncNotice> {
    Some(SyncNotice::Merged { added, removed })
}
/// One entry edited on two PCs, counted: notices never name an entry.
fn conflict(event: &SyncEvent) -> bool {
    event.notice == Some(SyncNotice::Conflicts(1))
}
fn vault_id(path: &Path) -> [u8; 16] {
    fs::read(path).unwrap()[8..24].try_into().unwrap()
}
/// The server's head as a new PC gets it: fetched, then restored.
fn head_titles(store: &Store, key: &Path, id: [u8; 16]) -> Vec<String> {
    let t = Temp::new("third");
    let fetched = t.0.join("head.goyo");
    let log = Log::new(None);
    let mut local = store.local();
    assert_eq!(
        fetch_into(&mut local, &log, "my-server", id, 0, &fetched),
        OK
    );
    let restored = t.0.join("vault.goyo");
    titles(&Session::restore(&fetched, key, &restored, PASSWORD, "").unwrap())
}

/// Codes from the authenticator app. Each is for a later time step than
/// the last one used, since a PC accepts a step only once and the PCs share
/// the watermark through sync.
struct Otp {
    secret: Vec<u8>,
    used: u64,
}
impl Otp {
    fn new(setup: &str) -> Self {
        let (mut secret, mut acc, mut bits) = (Vec::new(), 0u32, 0);
        for c in setup.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => panic!("not base32"),
            };
            acc = ((acc << 5) | u32::from(v)) & 0xFFFF;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                secret.push((acc >> bits) as u8);
            }
        }
        assert_eq!(secret.len(), 20);
        Self { secret, used: 0 }
    }
    /// A vault accepts steps now-1 to now+1. The oldest is used only while
    /// it stays good for the slow key derivation that comes before the
    /// check; past now+1 this waits for the next step.
    fn next(&mut self) -> String {
        loop {
            let now = otp::now().unwrap();
            let step = now / 30;
            let lowest = if 30 - now % 30 > 10 { step - 1 } else { step };
            let pick = lowest.max(self.used + 1);
            if pick <= step + 1 {
                self.used = pick;
                return format!("{:06}", otp::code(&self.secret, pick, 6));
            }
            std::thread::sleep(Duration::from_secs(30 - now % 30));
        }
    }
    /// The code of the next time step, which every vault accepts for at
    /// least another minute: a refusal within that time is not the clock's.
    fn lasting(&mut self) -> String {
        loop {
            let now = otp::now().unwrap();
            let pick = now / 30 + 1;
            if pick > self.used {
                self.used = pick;
                return format!("{:06}", otp::code(&self.secret, pick, 6));
            }
            std::thread::sleep(Duration::from_secs(30 - now % 30));
        }
    }
}

/// Spec §17 item 22, scenarios 1 to 12, in one history: two PCs with an
/// OTP-free vault, one server, and the failures the design must survive.
#[test]
fn two_pcs_end_to_end() {
    if !python() {
        return;
    }
    let store = Store::new();
    let (mut a, mut b) = (Pc::new("a", &store), Pc::new("b", &store));

    // ---- 1 (S1): first setup into an empty server ----
    let p = Provision::new().unwrap();
    let mut sa = p.finish(&a.vault, &a.key, PASSWORD, None).unwrap();
    for title in ["mail", "bank", "shop"] {
        sa.put(None, entry(title, "first")).unwrap();
    }
    // The helper runs first: it makes the folder and waits for the app.
    assert_eq!(a.pass(), report(SyncState::Idle, 0, None, None));
    assert!(syncfile::usable_dir(&a.dir));
    assert!(sa.sync_offer());
    sa.enable_sync().unwrap();
    let id = vault_id(&a.vault);
    assert_eq!(a.outgoing(), Some(0));
    let first = a.upload();
    assert_eq!(a.pass(), report(SyncState::Ok, 1, Some(1), None));
    assert_eq!(store.versions(&id), [(1, first.clone())]);
    assert_eq!(notice(sa.poll_sync()), synced(&sa));
    assert_eq!(a.outgoing(), None);
    assert_eq!(sa.badge(), Some(SyncBadge::Synced));

    // ---- 2 (S2): B joins through --fetch and Restore ----
    fs::copy(&a.key, &b.key).unwrap(); // by USB, never through the server
    let fetched = b.t.0.join("from-server.goyo");
    let log = Log::new(Some(b.t.0.join(LOG)));
    assert_eq!(
        fetch_into(&mut store.local(), &log, "my-server", id, 0, &fetched),
        OK
    );
    let restored = Session::restore(&fetched, &b.key, &b.vault, PASSWORD, "").unwrap();
    assert_eq!(restored.format(), Format::V2);
    drop(restored);
    assert_eq!(b.pass(), report(SyncState::Idle, 0, None, None));
    let mut sb = b.unlock("");
    assert_eq!(sb.take_unlock_notice(), None);
    // Nothing fetched yet: B offers its copy from no version; it loses to
    // version 1, which B's app merges with nothing to add.
    assert_eq!(b.outgoing(), Some(0));
    assert_eq!(b.pass(), report(SyncState::Ok, 1, None, Some(1)));
    assert_eq!(b.incoming(), Some((1, first.clone())));
    assert_eq!(notice(sb.poll_sync()), synced(&sb));
    assert_eq!(sb.check_code(), sa.check_code());
    assert_eq!(titles(&sb), titles(&sa));
    assert_eq!(sb.entries.len(), 3, "no duplicates");
    assert_eq!(b.outgoing(), None);
    assert_eq!(store.versions(&id).len(), 1);

    // ---- 3 (S3): A edits, B pulls ----
    let old = sa.entry_id(find(&sa, "mail")).unwrap();
    sa.put(Some(find(&sa, "mail")), entry("mail", "second"))
        .unwrap();
    assert_eq!(a.outgoing(), Some(1));
    assert_eq!(a.pass(), report(SyncState::Ok, 2, Some(2), None));
    assert_eq!(notice(sa.poll_sync()), None);
    assert_eq!(a.outgoing(), None);
    assert_eq!(b.pass(), report(SyncState::Ok, 2, None, Some(2)));
    let ev = sb.poll_sync().unwrap();
    assert_eq!(ev.notice, merged(1, 1));
    assert!(ev.list_changed);
    // A selection on the old entry follows the edit to its successor.
    let new = sa.entry_id(find(&sa, "mail")).unwrap();
    let edited = sb.entry_index(&new);
    assert!(edited.is_some() && sb.entry_index(&old).is_none());
    assert_eq!(sb.successor(&old), edited);
    assert_eq!(titles(&sb), titles(&sa));

    // ---- 4 (S4): both edit one entry, and B adds one ----
    sa.put(Some(find(&sa, "bank")), entry("bank", "by A"))
        .unwrap();
    sb.put(Some(find(&sb, "bank")), entry("bank", "by B"))
        .unwrap();
    sb.put(None, entry("notes", "by B")).unwrap();
    assert_eq!(a.pass(), report(SyncState::Ok, 3, Some(3), None));
    // B's upload loses; its app merges A's version and uploads the union.
    assert_eq!(b.pass(), report(SyncState::Ok, 3, None, Some(3)));
    let ev = sb.poll_sync().unwrap();
    assert!(conflict(&ev) && ev.list_changed, "{ev:?}");
    assert_eq!(b.outgoing(), Some(3));
    assert_eq!(b.pass(), report(SyncState::Ok, 4, Some(4), None));
    assert_eq!(notice(sb.poll_sync()), None, "the conflict is told once");
    assert_eq!(a.pass(), report(SyncState::Ok, 4, None, Some(4)));
    let ev = sa.poll_sync().unwrap();
    assert!(conflict(&ev) && ev.list_changed, "{ev:?}");
    let both = titles(&sa);
    assert_eq!(titles(&sb), both);
    for t in ["bank=by A", "bank=by B", "notes=by B", "mail=second"] {
        assert!(both.iter().any(|x| x == t), "{t} missing from {both:?}");
    }
    assert_eq!(sa.check_code(), sb.check_code());

    // ---- 5: converged, three more rounds make no server version ----
    for _ in 0..3 {
        assert_eq!(a.pass(), report(SyncState::Ok, 4, None, None));
        assert_eq!(b.pass(), report(SyncState::Ok, 4, None, None));
        for s in [&mut sa, &mut sb] {
            if let Some(ev) = s.poll_sync() {
                assert_eq!((ev.notice, ev.list_changed), (None, false));
            }
        }
    }
    assert_eq!(store.versions(&id).len(), 4);
    assert_eq!((a.outgoing(), b.outgoing()), (None, None));
    assert_eq!(sa.badge(), Some(SyncBadge::Synced));
    assert_eq!(sb.badge(), Some(SyncBadge::Synced));

    // ---- 6 (S5): the helper dies after its PUT committed ----
    sa.put(None, entry("gift card", "by A")).unwrap();
    assert_eq!(a.outgoing(), Some(4));
    let blob = a.upload();
    let state = fs::read(a.dir.join(HELPER_STATE)).unwrap();
    let out = store.post(&Request::put(id, 4, &blob).unwrap().encode());
    let (direct, _) = Response::decode(&out.stdout, Op::Put, &id, 4).unwrap();
    assert_eq!((direct.status, direct.version), (Status::Ok, 5));
    // Restarted with the old helper.state, it finds its upload as the head.
    a.restart();
    assert_eq!(fs::read(a.dir.join(HELPER_STATE)).unwrap(), state);
    assert_eq!(a.pass(), report(SyncState::Ok, 5, Some(5), None));
    assert!(a.log().contains("upload was already on the server"));
    assert_eq!(store.versions(&id).len(), 5, "no second copy");
    assert_eq!(store.versions(&id)[4], (5, blob));
    assert_eq!(notice(sa.poll_sync()), None);
    assert_eq!(a.outgoing(), None);
    assert_eq!(b.pass(), report(SyncState::Ok, 5, None, Some(5)));
    assert_eq!(notice(sb.poll_sync()), merged(1, 0));

    // ---- 7 (S6): B's app dies after a merge saved its vault ----
    sa.put(None, entry("ticket", "by A")).unwrap();
    sb.put(None, entry("receipt", "by B")).unwrap();
    assert_eq!(a.pass(), report(SyncState::Ok, 6, Some(6), None));
    assert_eq!(b.pass(), report(SyncState::Ok, 6, None, Some(6)));
    // The merge is saved, the new outgoing cannot replace the dead one (held
    // open), and the app is gone before it tries again.
    let held = fs::File::open(b.dir.join(OUTGOING)).unwrap();
    let before = fs::read(&b.vault).unwrap();
    assert_eq!(notice(sb.poll_sync()), merged(1, 0));
    assert_ne!(fs::read(&b.vault).unwrap(), before);
    drop(sb);
    drop(held);
    assert_eq!(b.outgoing(), Some(5), "only the dead upload");
    assert_eq!(b.pass(), report(SyncState::Ok, 6, None, None));
    assert_eq!(store.versions(&id).len(), 6);
    let saved = b.on_disk();
    assert!(saved.iter().any(|t| t == "ticket=by A"), "{saved:?}");
    assert!(saved.iter().any(|t| t == "receipt=by B"), "{saved:?}");
    // Reopened, the vault is ahead of incoming: outgoing is written again,
    // from version 6, and uploaded.
    let mut sb = b.unlock("");
    assert_eq!(sb.take_unlock_notice(), None);
    assert_eq!(b.outgoing(), Some(6));
    assert_eq!(b.pass(), report(SyncState::Ok, 7, Some(7), None));
    assert_eq!(notice(sb.poll_sync()), synced(&sb));
    assert_eq!(a.pass(), report(SyncState::Ok, 7, None, Some(7)));
    assert_eq!(notice(sa.poll_sync()), merged(1, 0));
    assert_eq!(sa.check_code(), sb.check_code());

    // ---- 8 (S7): B's app is closed while A's changes arrive ----
    drop(sb);
    sa.put(Some(find(&sa, "shop")), entry("shop", "by A"))
        .unwrap();
    sa.put(None, entry("train", "by A")).unwrap();
    assert_eq!(a.pass(), report(SyncState::Ok, 8, Some(8), None));
    assert_eq!(notice(sa.poll_sync()), None);
    assert_eq!(b.pass(), report(SyncState::Ok, 8, None, Some(8)));
    let mut sb = b.unlock("");
    assert_eq!(sb.take_unlock_notice(), merged(2, 1));
    assert_eq!(titles(&sb), titles(&sa));
    assert_eq!(sb.check_code(), sa.check_code());
    assert_eq!(b.outgoing(), None);
    assert_eq!(b.on_disk(), titles(&sa), "saved at unlock");

    // ---- 9 (S8): the server goes back two versions ----
    let kept = titles(&sa);
    for n in [7, 8] {
        fs::remove_file(store.version(&id, n)).unwrap();
    }
    assert_eq!(a.pass(), report(SyncState::Ok, 6, None, Some(6)));
    assert!(a.log().contains("server version went back 8->6"));
    assert_eq!(b.pass(), report(SyncState::Ok, 6, None, Some(6)));
    assert!(b.log().contains("server version went back 8->6"));
    for (s, pc) in [(&mut sa, &a), (&mut sb, &b)] {
        let ev = s.poll_sync().unwrap();
        assert_eq!(ev.notice, Some(SyncNotice::Rollback));
        assert!(!ev.list_changed);
        assert_eq!(titles(s), kept, "nothing lost");
        assert_eq!(s.badge(), Some(SyncBadge::Warning));
        assert_eq!(pc.outgoing(), Some(6));
    }
    // A's upload heals the server; B's, from the same version, then loses.
    assert_eq!(a.pass(), report(SyncState::Ok, 7, Some(7), None));
    assert_eq!(b.pass(), report(SyncState::Ok, 7, None, Some(7)));
    assert_eq!(notice(sa.poll_sync()), None);
    assert_eq!(notice(sb.poll_sync()), synced(&sb));
    assert_eq!((titles(&sa), titles(&sb)), (kept.clone(), kept.clone()));
    assert_eq!((a.outgoing(), b.outgoing()), (None, None));
    assert_eq!(sa.check_code(), sb.check_code());
    assert_eq!(head_titles(&store, &a.key, id), kept);
    // Healed, but the warning stays for the rest of the session.
    assert_eq!(sa.badge(), Some(SyncBadge::Warning));
    assert_eq!(sb.badge(), Some(SyncBadge::Warning));

    // ---- 10 (S9): the server's copy of the vault is wiped ----
    let vault_dir = store.root.join(syncfile::hex(&id));
    fs::remove_dir_all(&vault_dir).unwrap();
    assert_eq!(a.pass(), report(SyncState::Ok, 1, Some(1), None));
    assert!(
        a.log()
            .contains("server was empty; re-uploaded the last known copy")
    );
    let seeded = store.versions(&id);
    assert_eq!(seeded.len(), 1);
    assert_eq!(a.incoming(), Some(seeded[0].clone()));
    assert_eq!(b.pass(), report(SyncState::Ok, 1, None, Some(1)));
    assert!(b.log().contains("server version went back 7->1"));
    assert_eq!(notice(sa.poll_sync()), None);
    assert_eq!(notice(sb.poll_sync()), None);
    assert_eq!((titles(&sa), titles(&sb)), (kept.clone(), kept.clone()));
    // Wiped again while B's next upload waits: it seeds the server.
    sb.put(None, entry("wifi", "by B")).unwrap();
    assert_eq!(b.outgoing(), Some(1));
    fs::remove_dir_all(&vault_dir).unwrap();
    assert_eq!(b.pass(), report(SyncState::Ok, 1, Some(1), None));
    assert!(
        b.log()
            .contains("server has no copy; uploading as the first version")
    );
    assert_eq!(notice(sb.poll_sync()), None);
    assert_eq!(a.pass(), report(SyncState::Ok, 1, None, Some(1)));
    assert_eq!(notice(sa.poll_sync()), merged(1, 0));
    assert_eq!(sa.check_code(), sb.check_code());
    assert_eq!(store.versions(&id).len(), 1);

    // ---- 11 (S10): a version is damaged on the server ----
    // A's app opens again first: the warning of step 9 lasts a session, and
    // the one below must be this session's own.
    drop(sa);
    let mut sa = a.unlock("");
    assert_eq!(sa.take_unlock_notice(), synced(&sa));
    assert_eq!(sa.badge(), Some(SyncBadge::Synced));
    // B uploads one more entry; the server damages it before A reads it.
    sb.put(None, entry("printer", "by B")).unwrap();
    assert_eq!(b.pass(), report(SyncState::Ok, 2, Some(2), None));
    assert_eq!(notice(sb.poll_sync()), None);
    let mut damaged = fs::read(store.version(&id, 2)).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    fs::write(store.version(&id, 2), &damaged).unwrap();
    // It passes all the helper can check (magic, ID, frame SHA)...
    assert_eq!(a.pass(), report(SyncState::Ok, 2, None, Some(2)));
    assert_eq!(a.incoming(), Some((2, damaged)));
    // ...but not the app's authentication: ignored, and written over from
    // that version.
    let ev = sa.poll_sync().unwrap();
    assert_eq!(ev.notice, Some(SyncNotice::BadIncoming));
    assert!(!ev.list_changed);
    assert_eq!(sa.badge(), Some(SyncBadge::Warning));
    assert_eq!(a.outgoing(), Some(2));
    assert_eq!(a.pass(), report(SyncState::Ok, 3, Some(3), None));
    assert_eq!(notice(sa.poll_sync()), None);
    assert_eq!(a.outgoing(), None);
    // The new head lacks B's entry, and its content counter is below that of
    // the copy B uploaded: to B the server went back. B is warned and
    // uploads the entry again; nothing is lost.
    assert_eq!(b.pass(), report(SyncState::Ok, 3, None, Some(3)));
    let ev = sb.poll_sync().unwrap();
    assert_eq!(ev.notice, Some(SyncNotice::Rollback));
    assert!(!ev.list_changed);
    assert_eq!(b.outgoing(), Some(3));
    assert_eq!(b.pass(), report(SyncState::Ok, 4, Some(4), None));
    assert_eq!(notice(sb.poll_sync()), None);
    assert_eq!(a.pass(), report(SyncState::Ok, 4, None, Some(4)));
    assert_eq!(notice(sa.poll_sync()), merged(1, 0));
    assert!(titles(&sa).iter().any(|t| t == "printer=by B"));
    assert_eq!(titles(&sa), titles(&sb));
    assert_eq!(sa.check_code(), sb.check_code());
    assert_eq!(head_titles(&store, &a.key, id), titles(&sa));

    // ---- 12 (S11): the key file never reached the server ----
    let key = fs::read(&a.key).unwrap();
    assert!(key.starts_with(b"GOYOKE02"));
    store.holds_only_vault_files(&id, &key);
    // Gate 3: posts the helper never makes are refused, and none of them
    // writes anything. Complete, the last frame would be version 5.
    let tree = store.files();
    let vault = fs::read(&a.vault).unwrap();
    let mut huge = vault.clone();
    huge.resize(MAX_FILE + 1, 0);
    let valid = put_frame(id, 4, &vault);
    let other = [0x5A; 16];
    let posts = [
        ("a key file", put_frame(id, 4, &key), id, Status::BadBlob, 0),
        (
            "another vault's ID",
            put_frame(other, 0, &vault),
            other,
            Status::BadBlob,
            0,
        ),
        (
            "8 MiB + 1",
            put_frame(id, 4, &huge),
            id,
            Status::TooLarge,
            1,
        ),
        (
            "cut short",
            valid[..valid.len() - 1].to_vec(),
            id,
            Status::BadRequest,
            1,
        ),
        (
            "a byte too many",
            [&valid[..], b"x"].concat(),
            id,
            Status::BadRequest,
            1,
        ),
    ];
    for (what, frame, vid, status, code) in posts {
        let out = store.post(&frame);
        let (r, _) = Response::decode(&out.stdout, Op::Put, &vid, 4).unwrap();
        assert_eq!((r.status, out.code), (status, Some(code)), "{what}");
        assert!(store.files() == tree, "{what} wrote something");
    }
    let out = store.post(&valid);
    let (r, _) = Response::decode(&out.stdout, Op::Put, &id, 4).unwrap();
    assert_eq!((r.status, r.version), (Status::Ok, 5));
    store.holds_only_vault_files(&id, &key);
}

/// An OTP vault: B joins with a fetched copy and an open Restore session,
/// is closed, and merges A's change when it opens, before its code is
/// checked. OTP-only changes (each unlock uses a code) are never uploaded.
#[test]
fn an_otp_vault_syncs_the_same_way() {
    if !python() {
        return;
    }
    let store = Store::new();
    let (mut a, mut b) = (Pc::new("otp-a", &store), Pc::new("otp-b", &store));
    let p = Provision::new().unwrap();
    let mut otp = Otp::new(&p.setup_code());
    let mut sa = p
        .finish(&a.vault, &a.key, PASSWORD, Some(&otp.next()))
        .unwrap();
    assert!(sa.uses_otp());
    sa.put(None, entry("mail", "first")).unwrap();
    assert_eq!(a.pass(), report(SyncState::Idle, 0, None, None));
    sa.enable_sync().unwrap();
    let id = vault_id(&a.vault);
    assert_eq!(a.pass(), report(SyncState::Ok, 1, Some(1), None));
    assert_eq!(notice(sa.poll_sync()), synced(&sa));

    fs::copy(&a.key, &b.key).unwrap();
    let fetched = b.t.0.join("from-server.goyo");
    let log = Log::new(None);
    assert_eq!(
        fetch_into(&mut store.local(), &log, "my-server", id, 0, &fetched),
        OK
    );
    let mut sb = Session::restore(&fetched, &b.key, &b.vault, PASSWORD, &otp.next()).unwrap();
    // B's helper makes the folder; the restored session links on its next
    // poll and offers its copy from no version.
    assert_eq!(b.pass(), report(SyncState::Idle, 0, None, None));
    assert_eq!(sb.badge(), None);
    assert!(sb.poll_sync().unwrap().badge_changed);
    assert_eq!(b.outgoing(), Some(0));
    assert_eq!(b.pass(), report(SyncState::Ok, 1, None, Some(1)));
    assert_eq!(notice(sb.poll_sync()), synced(&sb));
    assert_eq!(sb.check_code(), sa.check_code());

    // B is closed while A opens again, with a code, and changes something;
    // the code's step rides along with the change, while an unlock alone
    // is not uploaded.
    drop(sb);
    drop(sa);
    let used = otp.lasting();
    let mut sa = a.unlock(&used);
    assert_eq!(a.outgoing(), None);
    sa.put(Some(0), entry("mail", "second")).unwrap();
    sa.put(None, entry("bank", "first")).unwrap();
    assert_eq!(a.pass(), report(SyncState::Ok, 2, Some(2), None));
    assert_eq!(b.pass(), report(SyncState::Ok, 2, None, Some(2)));
    // B merges A's change before it checks its code, so the code A used is
    // refused on B too (still in its time window, and above B's own
    // watermark), and the refused unlock writes nothing.
    let before = fs::read(&b.vault).unwrap();
    let refused = Session::unlock(&b.vault, &b.key, PASSWORD, &used).err();
    assert_eq!(refused, Some(AUTH_ERROR));
    assert_eq!(fs::read(&b.vault).unwrap(), before);
    assert_eq!(b.outgoing(), None);
    let mut sb = b.unlock(&otp.next());
    assert_eq!(sb.take_unlock_notice(), merged(2, 1));
    assert_eq!(titles(&sb), titles(&sa));
    assert_eq!(sb.check_code(), sa.check_code());
    assert_eq!(b.outgoing(), None, "an unlock alone is never uploaded");
    assert_eq!(b.pass(), report(SyncState::Ok, 2, None, None));
    assert_eq!(store.versions(&id).len(), 2);
    let key = fs::read(&a.key).unwrap();
    assert!(key.starts_with(b"GOYOKE01"));
    store.holds_only_vault_files(&id, &key);
}

/// Readers never follow a link at a sync file (`read_bounded` refuses it as
/// Io, not Busy). The app treats that as "not readable now": no merge of
/// whatever the link points to, no error event, no busy loop, just another
/// look on its normal 2 s poll, and the next real file is merged as usual.
#[test]
fn the_app_never_follows_a_link_at_incoming() {
    let t = Temp::new("links");
    let (vault, key, dir) = (
        t.0.join("vault.goyo"),
        t.0.join("vault.goyokey"),
        t.0.join("vault.goyo.sync"),
    );
    let p = Provision::new().unwrap();
    let mut s = p.finish(&vault, &key, PASSWORD, None).unwrap();
    s.put(None, entry("mail", "first")).unwrap();
    fs::create_dir(&dir).unwrap(); // what the helper does first
    let status = syncfile::render_status(otp::now().unwrap(), 0, SyncState::Ok);
    syncfile::replace_file(&dir.join(syncfile::STATUS), &status).unwrap();
    s.enable_sync().unwrap();
    // The helper's part, by hand: version 1 is the app's first upload.
    let deliver = |version: u64, blob: &[u8]| {
        let wrapped = syncfile::render_incoming(version, blob).unwrap();
        syncfile::replace_file(&dir.join(INCOMING), &wrapped).unwrap();
    };
    let outgoing = fs::read(dir.join(OUTGOING)).unwrap();
    deliver(1, syncfile::parse_outgoing(&outgoing).unwrap().1);
    assert_eq!(notice(s.poll_sync()), synced(&s));
    // A newer copy from another PC, with one more entry, kept elsewhere.
    let other = Temp::new("links-other");
    let (other_vault, other_key) = (other.0.join("vault.goyo"), other.0.join("vault.goyokey"));
    fs::copy(&vault, &other_vault).unwrap();
    fs::copy(&key, &other_key).unwrap();
    let mut s2 = Session::unlock(&other_vault, &other_key, PASSWORD, "").unwrap();
    s2.put(None, entry("bank", "first")).unwrap();
    drop(s2);
    let newer = fs::read(&other_vault).unwrap();
    let elsewhere = t.0.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let wrapped = syncfile::render_incoming(2, &newer).unwrap();
    fs::write(elsewhere.join(INCOMING), wrapped).unwrap();
    let before = titles(&s);

    let polls = |s: &mut Session| {
        let started = Instant::now();
        for _ in 0..20 {
            if let Some(ev) = s.poll_sync() {
                assert_eq!((&ev.notice, ev.list_changed), (&None, false), "{ev:?}");
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "20 polls took long"
        );
        assert_eq!(titles(s), before);
    };
    // A junction where incoming should be.
    fs::remove_file(dir.join(INCOMING)).unwrap();
    junction(&dir.join(INCOMING), &elsewhere);
    polls(&mut s);
    fs::remove_dir(dir.join(INCOMING)).unwrap();
    // A file symlink to the newer copy, where this account may make one.
    let link = dir.join(INCOMING);
    if std::os::windows::fs::symlink_file(elsewhere.join(INCOMING), &link).is_ok() {
        polls(&mut s);
        fs::remove_file(&link).unwrap();
    }
    // The helper writes a real file again: it is merged.
    deliver(2, &newer);
    let ev = s.poll_sync().unwrap();
    assert_eq!(ev.notice, merged(1, 0));
    assert!(ev.list_changed);
    assert!(titles(&s).iter().any(|t| t == "bank=first"));
}
