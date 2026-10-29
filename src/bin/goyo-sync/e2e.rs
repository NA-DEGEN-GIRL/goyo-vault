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
    /// keeps is a version of vault `id` (GOYOVA02 or GOYOVA04 and that ID up
    /// front, so never a key file's GOYOK…) and holds no stretch of the key
    /// file.
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
                syncfile::is_sync_vault(data) && data[8..24] == id[..],
                "{rel:?}"
            );
            assert!(!data.starts_with(b"GOYOK"), "{rel:?}");
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
    // Nothing fetched yet: B offers its copy from no version at its first
    // poll that finds no incoming either (one listing could be the moment
    // the helper replaces it); it loses to version 1, which B's app merges
    // with nothing to add.
    assert_eq!(b.outgoing(), None);
    let _ = sb.poll_sync();
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
    // poll and offers its copy from no version at the poll after.
    assert_eq!(b.pass(), report(SyncState::Idle, 0, None, None));
    assert_eq!(sb.badge(), None);
    assert!(sb.poll_sync().unwrap().badge_changed);
    assert_eq!(b.outgoing(), None);
    let _ = sb.poll_sync();
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

/// Two PCs on a KF2 key file (the GOYOKE03 a later build writes for a vault
/// without security keys) sync through the real server script: the vault
/// file and every upload are GOYOVA04, the helper gates and uploads them,
/// the server stores and serves them, and each PC merges the other's. No
/// key file byte reaches the server (spec §4.4, §7.6, §14.7-6).
#[test]
fn kf2_vaults_sync_goyova04_end_to_end() {
    use goyo_vault::{
        crypto::{KdfProfile, set_kdf_profile},
        vault::keyfile::{KeyFile, Kind, Plan, Spec, seal},
    };
    if !python() {
        return;
    }
    set_kdf_profile(KdfProfile::Test);
    let store = Store::new();
    let (mut a, mut b) = (Pc::new("a", &store), Pc::new("b", &store));
    let p = Provision::new().unwrap();
    let mut sa = p.finish(&a.vault, &a.key, PASSWORD, None).unwrap();
    sa.put(None, entry("mail", "first")).unwrap();
    drop(sa);
    // The key file sealed again as GOYOKE03: its one data key is both the
    // current key and the ID key.
    let id = vault_id(&a.vault);
    let opened = KeyFile::read(&a.key).unwrap().open(PASSWORD, None).unwrap();
    let spec = Spec {
        vault_id: id,
        epoch: 1,
        kind: Kind::Password,
        next: 1,
        pw_id: [5; 16],
        loss: 0,
        tombstones: Vec::new(),
        resume: [0; 32],
    };
    let (key, _) = seal(&spec, &opened.bundle, PASSWORD, Plan::PasswordOnly).unwrap();
    fs::write(&a.key, &key).unwrap();
    assert_eq!(a.pass(), report(SyncState::Idle, 0, None, None));
    let mut sa = a.unlock("");
    sa.enable_sync().unwrap();
    assert_eq!(&fs::read(&a.vault).unwrap()[..8], b"GOYOVA04");
    let first = a.upload();
    assert_eq!(&first[..8], b"GOYOVA04");
    assert_eq!(a.pass(), report(SyncState::Ok, 1, Some(1), None));
    assert_eq!(store.versions(&id), [(1, first.clone())]);
    assert_eq!(notice(sa.poll_sync()), synced(&sa));

    // B has both files by USB, and adds an entry: its upload from no
    // version loses to version 1, which its app merges and offers again.
    fs::copy(&a.key, &b.key).unwrap();
    fs::copy(&a.vault, &b.vault).unwrap();
    assert_eq!(b.pass(), report(SyncState::Idle, 0, None, None));
    let mut sb = b.unlock("");
    sb.put(None, entry("bank", "second")).unwrap();
    assert_eq!(b.pass(), report(SyncState::Ok, 1, None, Some(1)));
    sb.poll_sync();
    assert_eq!(b.pass(), report(SyncState::Ok, 2, Some(2), None));
    assert_eq!(a.pass(), report(SyncState::Ok, 2, None, Some(2)));
    assert_eq!(notice(sa.poll_sync()), merged(1, 0));
    assert_eq!(titles(&sa), ["bank=second", "mail=first"]);
    assert_eq!(titles(&sa), titles(&sb));
    assert_eq!(sa.check_code(), sb.check_code());
    for (_, blob) in store.versions(&id) {
        assert_eq!(&blob[..8], b"GOYOVA04");
    }
    store.holds_only_vault_files(&id, &key);
    set_kdf_profile(KdfProfile::Real);
}

// ---- key-file sync end to end (security-key build; spec v3 §7.21, §14.10) ----

/// Key-file sync between PCs with security keys (spec v3 §7.8-§7.21 as
/// §2.23 simplified it). Each PC is a folder with its vault, its key file,
/// its sync folder and its own anchor, and runs the real helper on its own
/// server line: the real script with `--key-sync` naming the vault. The
/// keys are fake authenticators that travel between the sites by hand. A
/// hostile server is the same script on a copy of the storage that the
/// test then edits as an attacker would.
#[cfg(feature = "security-key")]
mod keys {
    use super::*;
    use crate::{tests::keys::KeyLocal, transport::Failure};
    use goyo_vault::{
        crypto::{KdfProfile, derive_count, set_kdf_profile},
        fido::{
            AssertRequest, Authenticator, FidoError, NewKey, Touch, check_assertion,
            fake::{Device, Fake},
            register,
        },
        syncfile::{
            KEY_REQUEST, KEY_VIEW, KeyOp, KeyOutcome, KeyView, RecordKind, parse_key_request,
            parse_key_view, render_record_header,
        },
        vault::{
            Acks, AdoptCheck, Adopted, Change, Consent, Exposure, ForkOption, GATE_CODE_WRONG,
            GATE_G2FAIL, GATE_PENDING, GateKind, GatePass, KEYSYNC_ASKING, KEYSYNC_OFF_PENDING,
            KeyClass, LossReport, Preview, Reauth, Rekeyed, Source, UnionPassword,
            keyfile::{KeyFile, KeyHeader, KeyState, Magic, is_sync_key_file, parse},
            parse_code, prepare, set_anchor_dir,
        },
    };
    use zeroize::Zeroizing;

    type Res<T> = std::result::Result<T, &'static str>;
    const NEW: &str = "a new long synthetic password";

    /// The user's security keys, by number, each a fake key of its own
    /// plugged into one fake authenticator.
    struct Keys {
        fake: Fake,
        plugged: Vec<(u8, usize)>,
    }
    impl Keys {
        fn new() -> Self {
            Self {
                fake: Fake::new(None),
                plugged: Vec::new(),
            }
        }
        /// Key `number` of vault `id`, registered with its PIN.
        fn register(&mut self, id: &[u8; 16], number: u8) -> NewKey {
            let i = self.fake.plug(Device::with_pin());
            self.fake.touch(Some(i));
            self.plugged.retain(|(n, _)| *n != number);
            self.plugged.push((number, i));
            register(
                &self.fake,
                id,
                number,
                otp::now().unwrap(),
                true,
                Vec::new(),
            )
            .unwrap()
        }
        /// Key `number` touched for `req`, checked as the app checks it.
        fn touch(&self, number: u8, req: &AssertRequest) -> Res<Touch> {
            let i = self.plugged.iter().find(|(n, _)| *n == number).unwrap().1;
            self.fake.touch(Some(i));
            let ceremony = || -> std::result::Result<Touch, FidoError> {
                let raw = self.fake.get_assertion(req, &self.fake.new_cancel()?)?;
                check_assertion(raw, req, false)
            };
            ceremony().map_err(FidoError::text)
        }
        /// How many ceremonies the fake has seen.
        fn asked(&self) -> usize {
            self.fake.seen().len()
        }
    }

    /// One PC's server line: the real script with `--key-sync` naming the
    /// vault once `serve` is called, and the ops sent on it, in order.
    struct Line {
        local: KeyLocal,
        ops: Vec<Op>,
    }
    impl Transport for Line {
        fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
            if let Ok(r) = Request::decode(request) {
                self.ops.push(r.op);
            }
            self.local.exchange(request, beat)
        }
    }

    /// One PC with security keys: its folder (vault, key file, sync folder
    /// and anchor) and its helper.
    struct Hw {
        t: Temp,
        vault: PathBuf,
        key: PathBuf,
        dir: PathBuf,
        helper: Engine<Line>,
    }
    impl Hw {
        fn new(name: &str, root: &Path) -> Self {
            let t = Temp::new(name);
            let vault = t.0.join("vault.goyo");
            let line = Line {
                local: KeyLocal {
                    root: root.to_path_buf(),
                    ids: Vec::new(),
                },
                ops: Vec::new(),
            };
            let log = Log::new(Some(t.0.join(LOG)));
            let helper = Engine::new(line, std::slice::from_ref(&vault), 60, system_clock(), log);
            Self {
                key: t.0.join("vault.goyokey"),
                dir: t.0.join("vault.goyo.sync"),
                vault,
                t,
                helper,
            }
        }
        /// Every creation and login from now on is this PC's (its anchor).
        fn here(&self) {
            set_anchor_dir(Some(self.t.0.join("anchor")));
        }
        /// The server line names vault `id` for key-file sync.
        fn serve(&mut self, id: [u8; 16]) {
            self.helper.transport.local.ids = vec![id];
        }
        /// The helper talks to the server whose storage is `root` from now
        /// on (a hostile copy, or the honest one again).
        fn to(&mut self, root: &Path) {
            self.helper.transport.local.root = root.to_path_buf();
        }
        /// One helper pass that also asks the server for news.
        fn pass(&mut self) -> Report {
            match self.helper.pass(0, true) {
                Outcome::Done(report) => report,
                other => panic!("{other:?}"),
            }
        }
        /// The ops sent since the last call.
        fn sent(&mut self) -> Vec<Op> {
            std::mem::take(&mut self.helper.transport.ops)
        }
        fn header(&self) -> KeyHeader {
            parse(&fs::read(&self.key).unwrap()).unwrap()
        }
        fn state(&self) -> KeyState {
            self.header().state()
        }
        fn kreq(&self) -> Option<Vec<u8>> {
            fs::read(self.dir.join(KEY_REQUEST)).ok()
        }
        /// `kreq` as its op, base, floor and key-file epoch.
        fn request(&self, id: &[u8; 16]) -> Option<(KeyOp, u64, u64, u64)> {
            let bytes = self.kreq()?;
            let r = parse_key_request(&bytes, id).ok()?;
            Some((r.op, r.base, r.floor, r.epoch()))
        }
        fn kview(&self, id: &[u8; 16]) -> Option<KeyView> {
            parse_key_view(&fs::read(self.dir.join(KEY_VIEW)).ok()?, id)
        }
        fn outgoing(&self) -> Option<Vec<u8>> {
            fs::read(self.dir.join(OUTGOING)).ok()
        }
    }

    /// A vault of `pc` with keys 1 to `n` registered together in PIN mode
    /// and one entry, made in the Test KDF profile.
    fn create(pc: &Hw, keys: &mut Keys, n: u8) -> Session {
        set_kdf_profile(KdfProfile::Test);
        let p = Provision::new().unwrap();
        let id = p.vault_id();
        let new: Vec<NewKey> = (1..=n).map(|i| keys.register(&id, i)).collect();
        pc.here();
        let mut s = p
            .finish_with_keys(&pc.vault, &pc.key, PASSWORD, None, true, new)
            .unwrap();
        s.put(None, entry("mail", "first")).unwrap();
        s
    }
    /// A login with `password` and a touch of key `number`.
    fn open(pc: &Hw, password: &str, keys: &Keys, number: u8) -> Res<Session> {
        pc.here();
        let prepared = prepare(&pc.vault, &pc.key)?;
        let req = prepared.unlock_request(0).expect("a key file with keys");
        let t = keys.touch(number, &req)?;
        Session::login_with(prepared, password, "", otp::now().unwrap(), None, &t)
    }
    /// A Reauth with `password` and a touch of key `number`.
    fn reauth(s: &mut Session, password: &str, keys: &Keys, number: u8) -> Res<Reauth> {
        let req = s.key_request(&[number], 0)?;
        let t = keys.touch(number, &req)?;
        s.reauth(password, Some(("", otp::now().unwrap())), Some(&t))
    }
    /// `change`, after a Reauth touched with key `number`, any rotation
    /// gate answered.
    fn rekey(
        s: &mut Session,
        password: &str,
        keys: &Keys,
        number: u8,
        change: Change,
    ) -> Res<Rekeyed> {
        let r = reauth(s, password, keys, number)?;
        s.rekey(r, Vec::new(), change, Consent::default(), true)
    }
    fn password(p: &str) -> Change {
        Change::Password(Zeroizing::new(p.to_owned()))
    }
    fn lost(numbers: &[u8]) -> Change {
        Change::Remove {
            remove: numbers.to_vec(),
            new_password: None,
            loss: Some(LossReport {
                date: None,
                exposure: Exposure::No,
                shared_pin: Vec::new(),
            }),
            over: None,
        }
    }
    fn acks(p: &Preview, option: ForkOption) -> Acks {
        Acks {
            password_only: p.password_only,
            union_password: match p.own_pass {
                Some(true) => UnionPassword::Own,
                _ => UnionPassword::Other,
            },
            both_passwords: p.both_passwords,
            fork_option: option,
            keysync_on: p.keysync_on,
        }
    }
    /// The accept of the server's key file as the flow runs it (spec
    /// §7.15, and "새 열쇠 파일 받기" with the server's file for a fork):
    /// its checks, a Reauth with `mine` touched with key `number`, a touch
    /// of that key for the file's seeds, the open (with `theirs` when the
    /// file has another password), the gate answered by `gate`, the
    /// preview of `option` (S-KEYSYNC-ON answered yes) and the write.
    fn accept(
        s: &mut Session,
        (mine, theirs): (&str, Option<&str>),
        keys: &Keys,
        number: u8,
        option: ForkOption,
        gate: impl FnOnce(&AdoptCheck, &Session) -> GatePass,
    ) -> Res<Adopted> {
        let (f, seq) = s.server_key_file().ok_or("no key file on the server")?;
        let check = s.adopt_check(&f, Source::Server { seq })?;
        let r = reauth(s, mine, keys, number)?;
        let t = keys.touch(number, &Session::other_request(&f, 0)?)?;
        let opened = s.adopt_open_with(&r, &f, theirs, Some(&t))?;
        let pass = gate(&check, s);
        let plan = s.adopt_preview_with(&r, &f, opened, &check, pass, option)?;
        let acks = acks(plan.preview(), option);
        s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
    }
    /// The same for a key file carried by USB.
    fn adopt_usb(
        s: &mut Session,
        (mine, bytes): (&str, &[u8]),
        keys: &Keys,
        number: u8,
        gate: impl FnOnce(&AdoptCheck, &Session) -> GatePass,
    ) -> Res<Adopted> {
        let f = KeyFile::from_bytes(Path::new("usb.goyokey"), bytes.to_vec())?;
        let check = s.adopt_check(&f, Source::File(f.path().to_owned()))?;
        let r = reauth(s, mine, keys, number)?;
        let opener = if f.needs_security_key() {
            Some(keys.touch(number, &Session::other_request(&f, 0)?)?)
        } else {
            None
        };
        let opened = s.adopt_open_with(&r, &f, None, opener.as_ref())?;
        let pass = gate(&check, s);
        let option = ForkOption::Both;
        let plan = s.adopt_preview_with(&r, &f, opened, &check, pass, option)?;
        let acks = acks(plan.preview(), option);
        s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
    }
    fn none(c: &AdoptCheck, _: &Session) -> GatePass {
        GatePass::none(c)
    }
    /// G1: the code as another PC shows it, typed.
    fn code(shown: &str) -> impl FnOnce(&AdoptCheck, &Session) -> GatePass {
        let code = parse_code(shown).unwrap();
        move |c, _| GatePass::G1Passed {
            code,
            epoch: c.other.epoch,
            tag: c.other.tag,
        }
    }
    /// G2: this PC's keys numbered `numbers`, picked from its own list.
    fn pick(numbers: &[u8]) -> impl FnOnce(&AdoptCheck, &Session) -> GatePass + '_ {
        move |c, s| GatePass::G2Passed {
            pick: s
                .gate_choices()
                .iter()
                .filter(|g| numbers.contains(&g.number))
                .map(|g| g.credhash)
                .collect(),
            epoch: c.other.epoch,
            tag: c.other.tag,
        }
    }
    /// A code no PC shows.
    const WRONG: &str = "E1 · 0000-0000-0000-0000";
    /// Polls until nothing changes; every notice on the way.
    fn polls(s: &mut Session) -> Vec<SyncNotice> {
        let mut told = Vec::new();
        for _ in 0..5 {
            if let Some(n) = s.poll_sync().and_then(|e| e.notice) {
                told.push(n);
            }
        }
        told
    }
    /// Whether an edit writes a new vault outgoing (none while a key hold
    /// applies).
    fn uploads(pc: &Hw, s: &mut Session, title: &str) -> bool {
        let before = pc.outgoing();
        s.put(None, entry(title, "x")).unwrap();
        pc.outgoing().is_some() && pc.outgoing() != before
    }
    /// The vault outgoing waits for nothing: a review due after a removal
    /// is done (spec §5.13).
    fn reviewed(s: &mut Session) {
        if s.review_due().is_some() {
            s.review_done().unwrap();
        }
    }
    fn has(s: &Session, title: &str) -> bool {
        titles(s)
            .iter()
            .any(|t| t.starts_with(&format!("{title}=")))
    }
    fn view_of(s: &Session) -> goyo_vault::vault::KeySyncView {
        s.key_sync_view().unwrap()
    }

    /// The server's records of vault `id`, by name.
    fn records(root: &Path, id: &[u8; 16]) -> Vec<String> {
        let k = root.join(syncfile::hex(id)).join("k");
        let mut names: Vec<String> = fs::read_dir(k)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
    /// Every file under `root`, with its contents.
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
    /// Spec §14.10-12's scan: no GOYOKE/GOYOKH bytes anywhere, a GOYOKS01
    /// key file only in a record of `k/`, at most two records with a key
    /// payload, and no temp left in `k/`. Returns how many key payloads.
    fn audit(root: &Path, id: &[u8; 16]) -> usize {
        let mut payloads = 0;
        for (path, data) in stored(root) {
            for magic in [&b"GOYOKE"[..], b"GOYOKH"] {
                assert!(!data.windows(6).any(|w| w == magic), "{path:?}");
            }
            let in_k = path.parent().is_some_and(|p| p.ends_with("k"));
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if in_k {
                // `tombs`: the ended key file's removed-key IDs (16 bytes
                // each), never a key file.
                assert!(
                    name.ends_with(".rec")
                        || name == "lock"
                        || name == "tombs" && data.len() % 16 == 0,
                    "{path:?}"
                );
                if name.ends_with(".rec") && data.len() > 32 {
                    assert!(is_sync_key_file(&data[32..], id).is_some(), "{path:?}");
                    payloads += 1;
                }
            } else {
                assert!(!data.windows(8).any(|w| w == b"GOYOKS01"), "{path:?}");
            }
        }
        assert!(payloads <= 2, "{payloads} key payloads");
        payloads
    }
    /// The top record of vault `id` on the server: its number, its kind and
    /// its generation.
    fn top(root: &Path, id: &[u8; 16]) -> Option<(u64, RecordKind, u64)> {
        let name = records(root, id)
            .into_iter()
            .rfind(|n| n.ends_with(".rec"))?;
        let number: u64 = name[..20].parse().unwrap();
        let bytes = fs::read(root.join(syncfile::hex(id)).join("k").join(&name)).unwrap();
        let (kind, _, generation, _) =
            goyo_vault::syncfile::parse_record_header(&bytes[..32]).unwrap();
        Some((number, kind, generation))
    }
    /// Plants `record` as record `n` with `floor` in its name, as a hostile
    /// server's admin can: the top from now on.
    fn plant(root: &Path, id: &[u8; 16], n: u64, floor: u64, record: &[u8]) {
        let k = root.join(syncfile::hex(id)).join("k");
        fs::create_dir_all(&k).unwrap();
        fs::write(k.join(format!("{n:020}-{floor:020}.rec")), record).unwrap();
    }
    /// A key record of generation `generation` for key file `file`.
    fn key_record(generation: u64, file: &[u8]) -> Vec<u8> {
        let epoch = parse(file).unwrap().epoch;
        let mut r = render_record_header(RecordKind::Key, false, generation, epoch).to_vec();
        r.extend_from_slice(file);
        r
    }
    /// A copy of the server's storage: the server this PC's helper is
    /// given from now on, which the attacker edits.
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for e in fs::read_dir(from).unwrap().flatten() {
            let target = to.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_tree(&e.path(), &target);
            } else {
                fs::copy(e.path(), target).unwrap();
            }
        }
    }
    fn done() {
        set_anchor_dir(None);
        set_kdf_profile(KdfProfile::Real);
    }

    /// PCs of one vault made on the first with keys 1 to `n`, each PC
    /// unlocking with its own key (`touch[i]`): vault sync on, key-file sync
    /// turned on and landed on the first when `on`, every other PC joined
    /// by USB and confirmed with the first's code, each synced and, with
    /// `on`, Equal with the server's key file.
    struct World {
        store: Store,
        keys: Keys,
        pcs: Vec<Hw>,
        s: Vec<Session>,
        id: [u8; 16],
    }
    fn world(names: &[&str], n: u8, touch: &[u8], on: bool) -> World {
        let store = Store::new();
        let mut keys = Keys::new();
        let mut pcs: Vec<Hw> = names
            .iter()
            .map(|name| Hw::new(name, &store.root))
            .collect();
        let mut sa = create(&pcs[0], &mut keys, n);
        let id = vault_id(&pcs[0].vault);
        for pc in &mut pcs {
            pc.serve(id);
        }
        pcs[0].pass();
        sa.enable_sync().unwrap();
        pcs[0].pass();
        polls(&mut sa);
        if on {
            assert_eq!(
                rekey(&mut sa, PASSWORD, &keys, touch[0], Change::KeySyncOn),
                Ok(Rekeyed::Done)
            );
            pcs[0].pass();
            polls(&mut sa);
            assert_eq!(sa.server_class(), Some(KeyClass::Equal));
        }
        let shown = sa.key_code().unwrap();
        let mut s = vec![sa];
        for i in 1..pcs.len() {
            fs::copy(&pcs[0].vault, &pcs[i].vault).unwrap();
            fs::copy(&pcs[0].key, &pcs[i].key).unwrap();
            pcs[i].pass();
            let mut si = open(&pcs[i], PASSWORD, &keys, touch[i]).unwrap();
            si.tofu_confirm(Some(&parse_code(&shown).unwrap())).unwrap();
            for _ in 0..2 {
                polls(&mut si);
                pcs[i].pass();
            }
            polls(&mut si);
            if on {
                assert_eq!(si.server_class(), Some(KeyClass::Equal), "{}", names[i]);
            }
            s.push(si);
        }
        World {
            store,
            keys,
            pcs,
            s,
            id,
        }
    }
    impl World {
        /// One helper pass and the app's polls on PC `i`; its notices.
        fn round(&mut self, i: usize) -> Vec<SyncNotice> {
            self.pcs[i].pass();
            polls(&mut self.s[i])
        }
        /// Rounds on every PC until every PC holds the same entries (at
        /// most eight).
        fn settle(&mut self) {
            for _ in 0..8 {
                for i in 0..self.pcs.len() {
                    self.round(i);
                }
                let same = |s: &Session| {
                    titles(s) == titles(&self.s[0]) && s.check_code() == self.s[0].check_code()
                };
                if self.s.iter().all(same) {
                    return;
                }
            }
        }
        /// Every PC holds the same entries, and every vault file's code is
        /// the same.
        fn converged(&self) {
            for (i, s) in self.s.iter().enumerate().skip(1) {
                assert_eq!(titles(s), titles(&self.s[0]), "PC {i}");
                assert_eq!(s.check_code(), self.s[0].check_code(), "PC {i}");
            }
        }
    }

    /// Walkthroughs §7.21 1, 2, 4 (in walkthrough 17's two sites) and 9,
    /// and §14.10-12, through the real server script and each PC's helper:
    /// keys 1 and 2 stay with A, keys 3 and 4 with B. B joins by USB and
    /// confirms with A's code (G1, spec §7.17). A turns key-file sync on;
    /// B (GOYOKH01) holds that policy change behind G1 (GatePending: no
    /// merge, no upload, no key change) and takes it with A's code. A's
    /// password change reaches B with no gate (KeyFileReady) and the new
    /// password; A's removal of lost key 1 with a touch of key 2 reaches B
    /// behind G2 with B's pick and B's own touch; no key is ever carried.
    /// A turns key-file sync off: `kreq` and `kview` go before the
    /// rotation, the CUT is answered and told once, B holds (KeySyncGone)
    /// and takes A's GOYOKH01 by USB with A's code. The server never
    /// stores a GOYOKE/GOYOKH byte or more than two key payloads, and none
    /// after the cut.
    #[test]
    fn key_file_sync_between_two_sites() {
        if !python() {
            return;
        }
        let store = Store::new();
        let mut keys = Keys::new();
        let (mut a, mut b) = (Hw::new("ks-a", &store.root), Hw::new("ks-b", &store.root));
        let mut sa = create(&a, &mut keys, 4);
        let id = vault_id(&a.vault);
        a.serve(id);
        b.serve(id);
        assert_eq!(a.pass(), report(SyncState::Idle, 0, None, None));
        sa.enable_sync().unwrap();
        // goyo-sync has not looked at the server's key files yet.
        polls(&mut sa);
        let asked = rekey(&mut sa, PASSWORD, &keys, 1, Change::KeySyncOn);
        assert_eq!(asked.err(), Some(KEYSYNC_ASKING));
        assert_eq!(a.pass(), report(SyncState::Ok, 1, Some(1), None));
        assert_eq!(notice(sa.poll_sync()), synced(&sa));
        // KG ran before the upload: the server holds no key file.
        let view = a.kview(&id).unwrap();
        assert_eq!((view.line, view.seq), (0, 0));

        // ---- B joins: both files by USB, confirmed with A's code ----
        fs::copy(&a.vault, &b.vault).unwrap();
        fs::copy(&a.key, &b.key).unwrap();
        assert_eq!(b.pass(), report(SyncState::Idle, 0, None, None));
        let mut sb = open(&b, PASSWORD, &keys, 3).unwrap();
        assert!(sb.tofu());
        assert_eq!(sb.key_code(), None, "no code before its gate");
        let wrong = parse_code(WRONG).unwrap();
        assert_eq!(sb.tofu_confirm(Some(&wrong)).err(), Some(GATE_CODE_WRONG));
        assert!(sb.tofu());
        let shown = sa.key_code().unwrap();
        sb.tofu_confirm(Some(&parse_code(&shown).unwrap())).unwrap();
        assert!(!sb.tofu());
        sb.put(None, entry("bank", "by B")).unwrap();
        assert_eq!(b.pass(), report(SyncState::Ok, 1, None, Some(1)));
        polls(&mut sb);
        assert_eq!(b.pass(), report(SyncState::Ok, 2, Some(2), None));
        assert_eq!(a.pass(), report(SyncState::Ok, 2, None, Some(2)));
        assert_eq!(notice(sa.poll_sync()), merged(1, 0));
        assert_eq!(titles(&sa), titles(&sb));

        // ---- walkthrough 1: A turns key-file sync on ----
        sa.put(None, entry("shop", "by A")).unwrap();
        let n = sa.key_state().epoch;
        let ids = a.header().key_ids;
        assert_eq!(
            rekey(&mut sa, PASSWORD, &keys, 1, Change::KeySyncOn),
            Ok(Rekeyed::Done)
        );
        let on = a.header();
        assert_eq!((on.magic, on.epoch), (Magic::Ks01, n + 1));
        assert_eq!(on.key_ids, ids, "the same data key");
        assert_eq!(a.request(&id), Some((KeyOp::Put, 0, 0, n + 1)));
        a.sent();
        assert_eq!(a.pass(), report(SyncState::Ok, 3, Some(3), None));
        assert_eq!(a.sent(), [Op::PutKey, Op::GetKey, Op::Put]);
        assert_eq!(records(&store.root, &id).len(), 1);
        polls(&mut sa);
        assert!(a.kreq().is_none());
        assert_eq!(sa.server_class(), Some(KeyClass::Equal));

        // B: another PC's "on" is a policy change, behind G1; held
        // meanwhile (I-S9).
        assert_eq!(b.pass(), report(SyncState::Ok, 3, None, Some(3)));
        let told = polls(&mut sb);
        assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
        let gated = KeyClass::Successor {
            carry: false,
            gate: Some(GateKind::G1),
        };
        assert_eq!(sb.server_class(), Some(gated));
        assert!(!has(&sb, "shop"), "no merge behind the gate");
        assert!(!uploads(&b, &mut sb, "held on b"));
        assert_eq!(sb.change_gate(&password(NEW)).err(), Some(GATE_PENDING));
        assert!(b.kreq().is_none());
        // A wrong code takes nothing; A's code takes the file.
        let before = fs::read(&b.key).unwrap();
        let got = accept(
            &mut sb,
            (PASSWORD, None),
            &keys,
            3,
            ForkOption::Both,
            code(WRONG),
        );
        assert_eq!(got.err(), Some(GATE_CODE_WRONG));
        assert_eq!(fs::read(&b.key).unwrap(), before);
        let shown = sa.key_code().unwrap();
        accept(
            &mut sb,
            (PASSWORD, None),
            &keys,
            3,
            ForkOption::Both,
            code(&shown),
        )
        .unwrap();
        assert_eq!(b.state(), a.state());
        assert_eq!(sb.key_code(), sa.key_code());
        polls(&mut sb);
        assert_eq!(sb.server_class(), Some(KeyClass::Equal));
        assert!(has(&sb, "shop") && has(&sb, "held on b"));
        assert!(b.kreq().is_none(), "Equal: nothing to upload");
        assert_eq!(b.pass(), report(SyncState::Ok, 4, Some(4), None));
        assert_eq!(a.pass(), report(SyncState::Ok, 4, None, Some(4)));
        polls(&mut sa);
        assert_eq!(titles(&sa), titles(&sb));
        assert_eq!(sa.check_code(), sb.check_code());

        // ---- walkthrough 2: A's password change, one touch ----
        assert_eq!(
            rekey(&mut sa, PASSWORD, &keys, 1, password(NEW)),
            Ok(Rekeyed::Done)
        );
        let changed = a.header();
        assert_ne!(changed.key_ids[0], on.key_ids[0], "a new data key");
        assert_eq!(sa.server_class(), Some(KeyClass::Stale));
        assert_eq!(
            a.request(&id),
            Some((KeyOp::Put, 1, on.epoch, changed.epoch))
        );
        assert_eq!(a.pass(), report(SyncState::Ok, 5, Some(5), None));
        polls(&mut sa);
        assert!(a.kreq().is_none());
        // B: no gate for a password change; told, and it gates key changes.
        assert_eq!(b.pass(), report(SyncState::Ok, 5, None, Some(5)));
        let told = polls(&mut sb);
        let ready = SyncNotice::KeyFileReady {
            epoch: changed.epoch,
        };
        assert!(told.contains(&ready), "{told:?}");
        assert!(sb.change_gate(&password(NEW)).unwrap().is_some());
        // B's own file does not open with the new password; the server's
        // file does (S-NEWPASS-OTHER), with B's touch of key 3.
        accept(
            &mut sb,
            (PASSWORD, Some(NEW)),
            &keys,
            3,
            ForkOption::Both,
            none,
        )
        .unwrap();
        assert_eq!(b.state(), changed.state());
        assert_eq!(sb.key_code(), sa.key_code());
        polls(&mut sb);
        assert_eq!(sb.server_class(), Some(KeyClass::Equal));
        assert_eq!(titles(&sa), titles(&sb));

        // ---- walkthroughs 4 and 17: key 1 lost at A, removed with key 2 ----
        let asked = keys.asked();
        assert_eq!(rekey(&mut sa, NEW, &keys, 2, lost(&[1])), Ok(Rekeyed::Done));
        assert_eq!(keys.asked(), asked + 1, "one touch at A");
        reviewed(&mut sa);
        let removed = a.header();
        let numbers: Vec<u8> = removed.slots.iter().map(|s| s.number).collect();
        assert_eq!(numbers, [2, 3, 4]);
        assert_eq!(a.pass().uploaded, Some(6));
        polls(&mut sa);
        assert!(a.kreq().is_none());
        // B behind G2: its own keys in the pick, then its own touch.
        assert_eq!(b.pass(), report(SyncState::Ok, 6, None, Some(6)));
        let told = polls(&mut sb);
        assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
        let g2 = KeyClass::Successor {
            carry: false,
            gate: Some(GateKind::G2),
        };
        assert_eq!(sb.server_class(), Some(g2));
        let choices: Vec<u8> = sb.gate_choices().iter().map(|c| c.number).collect();
        assert_eq!(choices, [1, 2, 3, 4], "this PC's own keys");
        let asked = keys.asked();
        accept(&mut sb, (NEW, None), &keys, 3, ForkOption::Both, pick(&[1])).unwrap();
        assert_eq!(keys.asked(), asked + 2, "the Reauth and the open");
        assert_eq!(b.state(), removed.state());
        assert_eq!(sb.key_code(), sa.key_code());
        reviewed(&mut sb);
        polls(&mut sb);
        assert_eq!(sb.server_class(), Some(KeyClass::Equal));
        assert!(uploads(&b, &mut sb, "after the removal"));
        assert_eq!(b.pass(), report(SyncState::Ok, 7, Some(7), None));
        assert_eq!(a.pass(), report(SyncState::Ok, 7, None, Some(7)));
        polls(&mut sa);
        assert_eq!(titles(&sa), titles(&sb));
        // Key 1 opens neither PC's key file any more.
        drop(sb);
        assert!(open(&b, NEW, &keys, 1).is_err());
        let mut sb = open(&b, NEW, &keys, 4).unwrap();
        polls(&mut sb);
        assert_eq!(audit(&store.root, &id), 2);

        // ---- walkthrough 9: A turns key-file sync off ----
        assert_eq!(
            rekey(&mut sa, NEW, &keys, 2, Change::KeySyncOff),
            Ok(Rekeyed::Done)
        );
        let off = a.header();
        assert_eq!(off.magic, Magic::Kh01);
        assert_ne!(off.key_ids[0], removed.key_ids[0], "the off rotates");
        assert!(a.kview(&id).is_none(), "kview deleted before the rotation");
        assert_eq!(a.request(&id).map(|r| (r.0, r.1)), Some((KeyOp::Cut, 3)));
        let view = view_of(&sa);
        assert_eq!(view.deletion, Some(goyo_vault::vault::Deletion::Pending));
        a.sent();
        a.pass();
        assert_eq!(a.sent()[..2], [Op::CutKey, Op::GetKey]);
        let told = polls(&mut sa);
        let deleted = SyncNotice::KeySyncDeleted {
            seq: 4,
            admin: true,
        };
        assert_eq!(
            told.iter().filter(|n| **n == deleted).count(),
            1,
            "{told:?}"
        );
        assert!(a.kreq().is_none());
        assert_eq!(top(&store.root, &id), Some((4, RecordKind::Cut, 4)));
        assert_eq!(audit(&store.root, &id), 0, "no key payload after the cut");
        // B: the cut on a GOYOKS01 PC holds its vault channel.
        b.pass();
        let told = polls(&mut sb);
        assert!(told.contains(&SyncNotice::KeySyncGone), "{told:?}");
        assert!(view_of(&sb).gone);
        assert!(!uploads(&b, &mut sb, "held by the cut"));
        assert!(b.kreq().is_none(), "no PC re-uploads by itself");
        // B takes A's GOYOKH01 by USB behind G1; it leaves key-file sync
        // with nothing to end (its view shows the cut).
        let usb = fs::read(&a.key).unwrap();
        let shown = sa.key_code().unwrap();
        adopt_usb(&mut sb, (NEW, &usb), &keys, 3, code(&shown)).unwrap();
        assert_eq!(b.state(), a.state());
        assert_eq!(b.header().magic, Magic::Kh01);
        polls(&mut sb);
        assert!(b.kreq().is_none());
        for _ in 0..2 {
            a.pass();
            polls(&mut sa);
            b.pass();
            polls(&mut sb);
        }
        assert_eq!(titles(&sa), titles(&sb));
        assert!(has(&sa, "held by the cut"));
        assert_eq!(audit(&store.root, &id), 0);
        done();
    }

    /// Walkthroughs §7.21-7 and -33 (d) and §14.10-23 (f), three PCs at two
    /// sites (keys 1 and 2 with A; 3 with B and 4 with C) on the real
    /// script's vault lock. A and B turn key-file sync on from one state:
    /// A's PUTKEY lands, B's gets CONFLICT and B's vault at its own state
    /// gets KEY_BEHIND, so it never becomes the head, and A never halts. B
    /// is forked and joins A's file ([둘 다 합치기], no gate), uploaded on
    /// A's record; A takes that union with no gate, C (GOYOKH01) behind G1
    /// with B's code. Then A and C change the password at once: A wins, C
    /// is forked (its uploads held, no key change but the join) and joins
    /// A's side ([다른 PC 쪽 사용]) behind G1 with A's code, opened with A's
    /// password; B takes A's change and then C's union, A takes C's union,
    /// and the three converge with one code.
    #[test]
    fn three_pcs_change_keys_at_once() {
        if !python() {
            return;
        }
        const THIRD: &str = "a third long synthetic password";
        let mut w = world(&["c3-a", "c3-b", "c3-c"], 4, &[1, 3, 4], false);
        let id = w.id;
        let n = w.s[0].key_state().epoch;
        w.s[0].put(None, entry("from a", "1")).unwrap();
        w.s[1].put(None, entry("from b", "1")).unwrap();
        // ---- two KeySyncOn from one state (walkthrough 33 (d)) ----
        for (i, k) in [(0, 1), (1, 3)] {
            assert_eq!(
                rekey(&mut w.s[i], PASSWORD, &w.keys, k, Change::KeySyncOn),
                Ok(Rekeyed::Done)
            );
            assert_eq!(w.pcs[i].request(&id), Some((KeyOp::Put, 0, 0, n + 1)));
        }
        w.pcs[0].sent();
        assert_eq!(w.pcs[0].pass().state, SyncState::Ok);
        assert_eq!(w.pcs[0].sent(), [Op::PutKey, Op::GetKey, Op::Put]);
        let head = w.store.versions(&id).last().unwrap().clone();
        // B: CONFLICT on A's record; its vault, at B's own state, refused
        // by the floor (exact under the lock).
        w.pcs[1].sent();
        assert_eq!(w.pcs[1].pass().state, SyncState::KeyFile);
        assert_eq!(w.pcs[1].sent(), [Op::PutKey, Op::GetKey, Op::Put]);
        assert_eq!(
            w.store.versions(&id).last(),
            Some(&head),
            "B's vault never the head"
        );
        let view = w.pcs[1].kview(&id).unwrap();
        assert_eq!((view.seq, view.outcome), (1, KeyOutcome::Conflict));
        let told = polls(&mut w.s[1]);
        assert!(told.contains(&SyncNotice::KeyFork), "{told:?}");
        assert_eq!(w.s[1].server_class(), Some(KeyClass::KeyFork));
        assert!(!uploads(&w.pcs[1], &mut w.s[1], "held by the fork"));
        // Its answered request stays (row 3) and is not sent again.
        let answered = w.pcs[1].kview(&id).unwrap().answered;
        assert_eq!(answered, w.pcs[1].kreq().map(|r| sha256(&r)));
        w.pcs[1].pass();
        assert!(!w.pcs[1].sent().contains(&Op::PutKey));
        // A, the winner, never halts.
        let told = w.round(0);
        assert!(!told.contains(&SyncNotice::KeyFork), "{told:?}");
        assert_eq!(w.s[0].server_class(), Some(KeyClass::Equal));
        // B joins A's file: both sides, no gate, above both, on A's record.
        accept(
            &mut w.s[1],
            (PASSWORD, None),
            &w.keys,
            3,
            ForkOption::Both,
            none,
        )
        .unwrap();
        let union = w.pcs[1].header();
        assert_eq!((union.magic, union.epoch), (Magic::Ks01, n + 2));
        assert_eq!(w.pcs[1].request(&id), Some((KeyOp::Put, 1, n + 1, n + 2)));
        w.round(1);
        assert!(w.pcs[1].kreq().is_none());
        assert_eq!(w.s[1].server_class(), Some(KeyClass::Equal));
        assert_eq!(top(&w.store.root, &id), Some((2, RecordKind::Key, 0)));
        // A: a successor with no gate (the join adds nothing to A's file).
        let told = w.round(0);
        let ready = SyncNotice::KeyFileReady { epoch: n + 2 };
        assert!(told.contains(&ready), "{told:?}");
        accept(
            &mut w.s[0],
            (PASSWORD, None),
            &w.keys,
            1,
            ForkOption::Both,
            none,
        )
        .unwrap();
        assert_eq!(w.pcs[0].state(), union.state());
        // C (GOYOKH01): sync turned on elsewhere, behind G1 with B's code.
        let told = w.round(2);
        assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
        let shown = w.s[1].key_code().unwrap();
        accept(
            &mut w.s[2],
            (PASSWORD, None),
            &w.keys,
            4,
            ForkOption::Both,
            code(&shown),
        )
        .unwrap();
        assert_eq!(w.pcs[2].state(), union.state());
        w.settle();
        w.converged();
        assert!(has(&w.s[2], "from a") && has(&w.s[2], "from b"));

        // ---- A and C change the password from one state ----
        assert_eq!(
            rekey(&mut w.s[0], PASSWORD, &w.keys, 1, password(NEW)),
            Ok(Rekeyed::Done)
        );
        assert_eq!(
            rekey(&mut w.s[2], PASSWORD, &w.keys, 4, password(THIRD)),
            Ok(Rekeyed::Done)
        );
        let a_new = w.pcs[0].header();
        w.round(0);
        assert_eq!(top(&w.store.root, &id), Some((3, RecordKind::Key, 0)));
        let head = w.store.versions(&id).last().unwrap().clone();
        assert_eq!(w.pcs[2].pass().state, SyncState::KeyFile);
        assert_eq!(
            w.store.versions(&id).last(),
            Some(&head),
            "C's vault never the head"
        );
        let told = polls(&mut w.s[2]);
        assert!(told.contains(&SyncNotice::KeyFork), "{told:?}");
        assert!(!uploads(&w.pcs[2], &mut w.s[2], "held on c"));
        assert!(w.s[2].rekey_gate(&password(NEW)).is_some());
        // C joins A's side behind G1 (A's code), with A's password.
        let shown = w.s[0].key_code().unwrap();
        let wrong = accept(
            &mut w.s[2],
            (THIRD, Some(NEW)),
            &w.keys,
            4,
            ForkOption::TakeOther,
            none,
        );
        assert!(wrong.is_err(), "option 1 needs its gate");
        accept(
            &mut w.s[2],
            (THIRD, Some(NEW)),
            &w.keys,
            4,
            ForkOption::TakeOther,
            code(&shown),
        )
        .unwrap();
        let joined = w.pcs[2].header();
        assert!(joined.epoch > a_new.epoch);
        assert_eq!(
            w.pcs[2].request(&id).map(|r| (r.0, r.1)),
            Some((KeyOp::Put, 3))
        );
        w.round(2);
        assert_eq!(w.s[2].server_class(), Some(KeyClass::Equal));
        // C now opens with A's password; B and A take C's join.
        drop(w.s.remove(2));
        let sc = open(&w.pcs[2], NEW, &w.keys, 4).unwrap();
        w.s.push(sc);
        w.round(1);
        accept(
            &mut w.s[1],
            (PASSWORD, Some(NEW)),
            &w.keys,
            3,
            ForkOption::Both,
            none,
        )
        .unwrap();
        assert_eq!(w.pcs[1].state(), joined.state());
        w.round(0);
        accept(&mut w.s[0], (NEW, None), &w.keys, 1, ForkOption::Both, none).unwrap();
        assert_eq!(w.pcs[0].state(), joined.state());
        w.settle();
        w.converged();
        assert!(has(&w.s[0], "held on c") && has(&w.s[1], "held by the fork"));
        for (i, s) in w.s.iter().enumerate() {
            assert_eq!(s.server_class(), Some(KeyClass::Equal), "PC {i}");
            assert_eq!(s.key_code(), w.s[0].key_code(), "PC {i}");
        }
        assert!(audit(&w.store.root, &id) <= 2);
        done();
    }

    /// A change the lib itself writes on the attacker's own PC (spec
    /// §14.10-5): `old`'s files, confirmed there with no code, and each
    /// change authorized by key `x` with the password given. The key file
    /// it wrote last.
    fn written_by(
        old: &(Vec<u8>, Vec<u8>),
        root: &Path,
        keys: &Keys,
        x: u8,
        changes: Vec<(&str, Change)>,
    ) -> Vec<u8> {
        let e = Hw::new("forger", root);
        fs::write(&e.vault, &old.0).unwrap();
        fs::write(&e.key, &old.1).unwrap();
        let mut s = open(&e, changes[0].0, keys, x).unwrap();
        s.tofu_confirm(None).unwrap();
        for (password, change) in changes {
            assert_eq!(rekey(&mut s, password, keys, x, change), Ok(Rekeyed::Done));
        }
        fs::read(&e.key).unwrap()
    }

    /// The removed-key simulator over the server channel (spec §14.10-5,
    /// -11 and walkthroughs §7.21-5, -6 and -33 (i)). Keys X = 1 and Y = 2
    /// with A, Z = 3 with B and C; all on key-file sync and synced with A's
    /// password change. X's holder knows the password and every old file,
    /// controls a copy of the server (B's line) and holds B's sync SSH key.
    /// A removes X. To B, frozen before that removal, the hostile server
    /// serves X's files: the mirror image "X removes Y" fails G2 with B's
    /// pick of X and then G1 with A's code; a forged addition fails G1; a
    /// same-password "password change" fails E5; this PC's own public file
    /// with its epoch raised is a fork that opens for no key. B's older
    /// file comes back as Stale and is uploaded over; a server restored
    /// from a backup halts nothing; a damaged top and a cut whose floor is
    /// too high hold B (KeySyncGone), and the re-upload lands above the
    /// first and is refused for the second. Every classification runs
    /// before any touch, no forged file is taken, and A, up to date,
    /// refuses an X-authored file before any touch or Argon2. Then A turns
    /// key-file sync off while C is offline, and X uploads a vault under the
    /// data key C still has, with an injected entry: C holds on the cut and
    /// merges nothing, and takes A's file by USB with A's code, its review
    /// listing nothing injected.
    #[test]
    fn a_hostile_server_gets_nothing_taken_without_its_gate() {
        if !python() {
            return;
        }
        const THIRD: &str = "a third long synthetic password";
        let mut w = world(&["h-a", "h-b", "h-c"], 3, &[2, 3, 3], true);
        let id = w.id;
        let t = Temp::new("hostile");
        let hostile = t.0.join("data");
        // A's password change, taken by B: B's history holds the first
        // GOYOKS01 state.
        let first = fs::read(&w.pcs[1].key).unwrap();
        assert_eq!(
            rekey(&mut w.s[0], PASSWORD, &w.keys, 2, password(NEW)),
            Ok(Rekeyed::Done)
        );
        w.round(0);
        for i in [1, 2] {
            w.round(i);
            accept(
                &mut w.s[i],
                (PASSWORD, Some(NEW)),
                &w.keys,
                3,
                ForkOption::Both,
                none,
            )
            .unwrap();
        }
        w.settle();
        w.converged();
        // C goes offline: no helper pass from here until the cut.
        let frozen = w.pcs[1].state();
        // B's line is the hostile copy from now on: B is frozen here.
        let snap = t.0.join("snap");
        copy_tree(&w.store.root, &snap);
        copy_tree(&snap, &hostile);
        w.pcs[1].to(&hostile);
        let old = (
            fs::read(&w.pcs[1].vault).unwrap(),
            fs::read(&w.pcs[1].key).unwrap(),
        );
        // X's files, written from the frozen state with key 1.
        let five = w.keys.register(&id, 5);
        let forged = [
            (
                "mirror",
                written_by(&old, &t.0, &w.keys, 1, vec![(NEW, lost(&[2]))]),
            ),
            (
                "added",
                written_by(&old, &t.0, &w.keys, 1, vec![(NEW, Change::AddKey(five))]),
            ),
            (
                "samepass",
                written_by(
                    &old,
                    &t.0,
                    &w.keys,
                    1,
                    vec![(NEW, password(THIRD)), (THIRD, password(NEW))],
                ),
            ),
        ];
        // A removes X with a touch of Y.
        assert_eq!(
            rekey(&mut w.s[0], NEW, &w.keys, 2, lost(&[1])),
            Ok(Rekeyed::Done)
        );
        reviewed(&mut w.s[0]);
        w.round(0);
        let genuine = w.s[0].key_code().unwrap();
        let removal = w.pcs[0].state();

        let b_key = fs::read(&w.pcs[1].key).unwrap();
        let mut n = top(&hostile, &id).unwrap().0;
        let mut serve = |w: &mut World, file: &[u8]| -> Vec<SyncNotice> {
            n += 1;
            plant(
                &hostile,
                &id,
                n,
                parse(file).unwrap().epoch,
                &key_record(0, file),
            );
            let (asked, derived) = (w.keys.asked(), derive_count());
            let told = w.round(1);
            assert_eq!(
                (w.keys.asked(), derive_count()),
                (asked, derived),
                "a touch before the gate"
            );
            told
        };
        let file = |name: &str| forged.iter().find(|(n, _)| *n == name).unwrap().1.clone();
        // The mirror image: G2, B picks X (the key it lost), which fails and
        // reveals nothing; then only G1, which A's code does not pass.
        let told = serve(&mut w, &file("mirror"));
        assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
        let g2 = KeyClass::Successor {
            carry: false,
            gate: Some(GateKind::G2),
        };
        assert_eq!(w.s[1].server_class(), Some(g2));
        assert!(!uploads(&w.pcs[1], &mut w.s[1], "held behind the gate"));
        assert!(w.pcs[1].kreq().is_none());
        let got = accept(
            &mut w.s[1],
            (NEW, None),
            &w.keys,
            3,
            ForkOption::Both,
            pick(&[1]),
        );
        assert_eq!(got.err(), Some(GATE_G2FAIL));
        assert_eq!(goyo_vault::vault::refusal_values(GATE_G2FAIL), None);
        let g1 = KeyClass::Successor {
            carry: false,
            gate: Some(GateKind::G1),
        };
        polls(&mut w.s[1]);
        assert_eq!(w.s[1].server_class(), Some(g1), "G2 is off");
        let got = accept(
            &mut w.s[1],
            (NEW, None),
            &w.keys,
            3,
            ForkOption::Both,
            code(&genuine),
        );
        assert_eq!(got.err(), Some(GATE_CODE_WRONG));
        // A forged addition of X's new credential: G1 only, which fails.
        serve(&mut w, &file("added"));
        assert_eq!(w.s[1].server_class(), Some(g1));
        let got = accept(
            &mut w.s[1],
            (NEW, None),
            &w.keys,
            3,
            ForkOption::Both,
            code(&genuine),
        );
        assert_eq!(got.err(), Some(GATE_CODE_WRONG));
        // A password change that kept the password: E5.
        serve(&mut w, &file("samepass"));
        let got = accept(&mut w.s[1], (NEW, None), &w.keys, 3, ForkOption::Both, none);
        assert_eq!(got.err(), Some(goyo_vault::vault::ADOPT_REFUSED));
        // This PC's own public file with its epoch raised: a fork, no gate
        // question, and it opens for no key.
        let mut raised = b_key.clone();
        raised[24..32].copy_from_slice(&(frozen.epoch + 1).to_le_bytes());
        let told = serve(&mut w, &raised);
        assert!(told.contains(&SyncNotice::KeyFork), "{told:?}");
        assert_eq!(w.s[1].server_class(), Some(KeyClass::KeyFork));
        assert!(accept(&mut w.s[1], (NEW, None), &w.keys, 3, ForkOption::Both, none).is_err());
        assert_eq!(fs::read(&w.pcs[1].key).unwrap(), b_key, "nothing taken");
        // The forged addition's gate stays pending (GatePending) until the
        // user drops it ([받지 않기…]); dropped, it is refused when served
        // again, with no gate.
        assert!(w.s[1].key_sync_view().unwrap().waiting.is_some());
        w.s[1].drop_gate().unwrap();
        serve(&mut w, &file("added"));
        assert_eq!(
            w.s[1].server_class(),
            Some(KeyClass::Refused("사용자가 받지 않음"))
        );

        // A rolled-back record: B's own older file is Stale, uploaded over.
        serve(&mut w, &first);
        assert_eq!(w.s[1].server_class(), Some(KeyClass::Stale));
        let base = n;
        assert_eq!(
            w.pcs[1].request(&id),
            Some((KeyOp::Put, base, parse(&first).unwrap().epoch, frozen.epoch))
        );
        w.round(1);
        assert_eq!(w.s[1].server_class(), Some(KeyClass::Equal));
        assert_eq!(top(&hostile, &id).map(|t| t.0), Some(base + 1));
        // A server restored from a backup: record numbers go back; B's own
        // state on top is Equal, and nothing halts.
        fs::remove_dir_all(&hostile).unwrap();
        copy_tree(&snap, &hostile);
        n = top(&hostile, &id).unwrap().0;
        assert_eq!(n, 2);
        let told = w.round(1);
        assert_eq!(w.s[1].server_class(), Some(KeyClass::Equal), "{told:?}");
        // A damaged top: a cut to every PC; B holds and re-uploads above it.
        n += 1;
        plant(&hostile, &id, n, frozen.epoch, b"GOYOSKR1 not a record");
        let told = w.round(1);
        assert!(told.contains(&SyncNotice::KeySyncGone), "{told:?}");
        assert!(!uploads(&w.pcs[1], &mut w.s[1], "held by the damaged top"));
        assert_eq!(
            rekey(&mut w.s[1], NEW, &w.keys, 3, Change::KeySyncOn),
            Ok(Rekeyed::Done)
        );
        let again = w.pcs[1].state();
        assert!(again.epoch > frozen.epoch);
        assert_eq!(
            w.pcs[1].request(&id).map(|r| (r.0, r.1)),
            Some((KeyOp::Put, n))
        );
        w.round(1);
        assert_eq!(w.s[1].server_class(), Some(KeyClass::Equal));
        n += 1;
        assert_eq!(top(&hostile, &id), Some((n, RecordKind::Key, n - 1)));
        // A cut whose floor is beyond EPOCH_SILENT: held, and the re-upload
        // is refused with the admin text.
        n += 1;
        let far = again.epoch + 1_000_000;
        let cut = render_record_header(RecordKind::Cut, false, n, far);
        plant(&hostile, &id, n, far, &cut);
        let told = w.round(1);
        assert!(told.contains(&SyncNotice::KeySyncGone), "{told:?}");
        let refused = rekey(&mut w.s[1], NEW, &w.keys, 3, Change::KeySyncOn).err();
        assert!(
            refused.is_some_and(|e| e.starts_with("서버의 열쇠 파일 기록이 비정상적으로 큽니다")),
            "{refused:?}"
        );
        assert_eq!(w.pcs[1].state(), again);

        // A, up to date: an X-authored file is refused before any touch or
        // Argon2, from its public bytes.
        let t2 = Temp::new("hostile-a");
        let to_a = t2.0.join("data");
        copy_tree(&w.store.root, &to_a);
        let mirror = file("mirror");
        let next = top(&to_a, &id).unwrap().0 + 1;
        plant(
            &to_a,
            &id,
            next,
            parse(&mirror).unwrap().epoch,
            &key_record(0, &mirror),
        );
        w.pcs[0].to(&to_a);
        let (asked, derived) = (w.keys.asked(), derive_count());
        let told = w.round(0);
        assert_eq!((w.keys.asked(), derive_count()), (asked, derived));
        let class = w.s[0].server_class();
        assert!(matches!(class, Some(KeyClass::Refused(_))), "{class:?}");
        assert!(
            told.iter()
                .any(|n| matches!(n, SyncNotice::KeyFileRefused(_))),
            "{told:?}"
        );
        let root = w.store.root.clone();
        w.pcs[0].to(&root);
        w.round(0);
        assert_eq!(w.pcs[0].state(), removal);

        // Walkthrough 33 (i): A turns key-file sync off. C, offline since
        // the password change, lags at the data key X knows; X's vault at
        // C's state with an injected entry is held at the cut, never merged.
        assert_eq!(
            rekey(&mut w.s[0], NEW, &w.keys, 2, Change::KeySyncOff),
            Ok(Rekeyed::Done)
        );
        w.round(0);
        w.round(0);
        assert_eq!(top(&w.store.root, &id).map(|t| t.1), Some(RecordKind::Cut));
        let off = fs::read(&w.pcs[0].key).unwrap();
        let x = Hw::new("x-vault", &t.0);
        fs::write(&x.vault, &old.0).unwrap();
        fs::write(&x.key, &old.1).unwrap();
        let mut sx = open(&x, NEW, &w.keys, 1).unwrap();
        sx.tofu_confirm(None).unwrap();
        sx.put(None, entry("injected", "by X")).unwrap();
        drop(sx);
        let injected = fs::read(&x.vault).unwrap();
        let head = w.store.versions(&id).last().unwrap().0;
        let out = w.store.post(&put_frame(id, head, &injected));
        let (r, _) = Response::decode(&out.stdout, Op::Put, &id, head).unwrap();
        assert_eq!(r.status, Status::Ok, "no floor after the cut");
        w.pcs[2].pass();
        let told = polls(&mut w.s[2]);
        assert!(told.contains(&SyncNotice::KeySyncGone), "{told:?}");
        assert!(!has(&w.s[2], "injected"), "merged nothing");
        assert!(!uploads(&w.pcs[2], &mut w.s[2], "held by the cut"));
        w.pcs[2].pass();
        polls(&mut w.s[2]);
        assert!(!has(&w.s[2], "injected"), "merged nothing");
        // C takes A's off by USB with A's code, and its review lists
        // nothing injected.
        let shown = w.s[0].key_code().unwrap();
        adopt_usb(&mut w.s[2], (NEW, &off), &w.keys, 3, code(&shown)).unwrap();
        assert_eq!(w.pcs[2].state(), w.pcs[0].state());
        let review = w.s[2].review_list(None);
        assert!(
            review
                .rows
                .iter()
                .all(|r| r.title.as_deref() != Some("injected")),
            "{review:?}"
        );
        assert!(!has(&w.s[2], "injected"));
        done();
    }

    /// The gate tests over the server channel (spec §14.10-6, §7.15a): A
    /// removes lost keys 1 and 2 with a touch of key 3; the other PCs (key
    /// 4 at the other site) each meet that file behind G2. The pick must
    /// match R exactly: a subset (B), a superset (C) and a disjoint pick (D)
    /// each fail and turn G2 off, revealing nothing, and the exact pick (F)
    /// takes the file. B's pending gate survives a restart and still holds
    /// its uploads while its edits are saved; C leaves it for later and
    /// stays held; D drops it ([받지 않기…]) and is never offered it again.
    /// E, offline through the removal and A's next change (an added key 5),
    /// meets both at once: R and Δ count together, so G1, not G2. Every PC
    /// that took a file ends with A's state and the same entries. Then a
    /// branch removed key 1 authored from before its removal reaches F,
    /// which took that removal from A's file: P4 is never relaxed on the
    /// key channel, so it is refused before any touch, not a fork.
    #[test]
    fn the_gate_over_the_server_channel() {
        if !python() {
            return;
        }
        let names = ["g-a", "g-b", "g-c", "g-d", "g-e", "g-f"];
        let mut w = world(&names, 4, &[3, 4, 4, 4, 4, 4], true);
        let id = w.id;
        let (b, c, d, e, f) = (1, 2, 3, 4, 5);
        let old = (
            fs::read(&w.pcs[f].vault).unwrap(),
            fs::read(&w.pcs[f].key).unwrap(),
        );
        assert_eq!(
            rekey(&mut w.s[0], PASSWORD, &w.keys, 3, lost(&[1, 2])),
            Ok(Rekeyed::Done)
        );
        reviewed(&mut w.s[0]);
        w.round(0);
        let removal = w.pcs[0].state();
        let shown = w.s[0].key_code().unwrap();
        for i in [b, c, d, f] {
            let told = w.round(i);
            assert!(told.contains(&SyncNotice::GatePending), "PC {i}: {told:?}");
            let g2 = KeyClass::Successor {
                carry: false,
                gate: Some(GateKind::G2),
            };
            assert_eq!(w.s[i].server_class(), Some(g2), "PC {i}");
            // The pick offers this PC's own keys, never the file's R.
            let offered: Vec<u8> = w.s[i].gate_choices().iter().map(|c| c.number).collect();
            assert_eq!(offered, [1, 2, 3, 4], "PC {i}");
            assert_eq!(w.s[i].key_code().map(|k| k == shown), Some(false));
        }
        for (i, wrong) in [(b, &[1][..]), (c, &[1, 2, 4][..]), (d, &[4][..])] {
            let before = fs::read(&w.pcs[i].key).unwrap();
            let got = accept(
                &mut w.s[i],
                (PASSWORD, None),
                &w.keys,
                4,
                ForkOption::Both,
                pick(wrong),
            );
            assert_eq!(got.err(), Some(GATE_G2FAIL), "PC {i}");
            assert_eq!(fs::read(&w.pcs[i].key).unwrap(), before, "PC {i}");
            polls(&mut w.s[i]);
            let g1 = KeyClass::Successor {
                carry: false,
                gate: Some(GateKind::G1),
            };
            assert_eq!(w.s[i].server_class(), Some(g1), "PC {i}: G2 is off");
        }
        // The exact pick takes the file.
        accept(
            &mut w.s[f],
            (PASSWORD, None),
            &w.keys,
            4,
            ForkOption::Both,
            pick(&[1, 2]),
        )
        .unwrap();
        assert_eq!(w.pcs[f].state(), removal);
        reviewed(&mut w.s[f]);
        // B: the gate survives a restart and holds uploads; edits are kept.
        drop(w.s.remove(b));
        let mut sb = open(&w.pcs[b], PASSWORD, &w.keys, 4).unwrap();
        let told = polls(&mut sb);
        assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
        assert!(!uploads(&w.pcs[b], &mut sb, "kept on b"));
        assert!(has(&sb, "kept on b"));
        let got = accept(
            &mut sb,
            (PASSWORD, None),
            &w.keys,
            4,
            ForkOption::Both,
            pick(&[1, 2]),
        );
        assert!(got.is_err(), "no second G2 for this file");
        accept(
            &mut sb,
            (PASSWORD, None),
            &w.keys,
            4,
            ForkOption::Both,
            code(&shown),
        )
        .unwrap();
        assert_eq!(w.pcs[b].state(), removal);
        reviewed(&mut sb);
        w.s.insert(b, sb);
        // C: "나중에" leaves it pending; the uploads stay held.
        for _ in 0..2 {
            let told = w.round(c);
            assert!(!told.contains(&SyncNotice::KeyFileReady {
                epoch: removal.epoch
            }));
            assert!(
                w.s[c]
                    .key_sync_view()
                    .unwrap()
                    .waiting
                    .is_some_and(|w| w.pending_gate)
            );
        }
        assert!(!uploads(&w.pcs[c], &mut w.s[c], "kept on c"));
        // D: dropped after the danger confirmation; never offered again.
        w.s[d].drop_gate().unwrap();
        let told = w.round(d);
        let dropped = KeyClass::Refused("사용자가 받지 않음");
        assert_eq!(w.s[d].server_class(), Some(dropped), "{told:?}");
        assert!(w.s[d].key_sync_view().unwrap().waiting.is_none());
        // The key channel halts on the dropped file until another arrives.
        assert!(!uploads(&w.pcs[d], &mut w.s[d], "kept on d"));

        // A adds key 5: E meets the removal and the addition at once.
        let five = w.keys.register(&id, 5);
        let r = reauth(&mut w.s[0], PASSWORD, &w.keys, 3).unwrap();
        assert_eq!(
            w.s[0].rekey(
                r,
                Vec::new(),
                Change::AddKey(five),
                Consent::default(),
                true
            ),
            Ok(Rekeyed::Done)
        );
        w.round(0);
        let added = w.pcs[0].state();
        let shown = w.s[0].key_code().unwrap();
        let told = w.round(e);
        assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
        let g1 = KeyClass::Successor {
            carry: false,
            gate: Some(GateKind::G1),
        };
        assert_eq!(w.s[e].server_class(), Some(g1), "R and Δ together need G1");
        accept(
            &mut w.s[e],
            (PASSWORD, None),
            &w.keys,
            4,
            ForkOption::Both,
            code(&shown),
        )
        .unwrap();
        assert_eq!(w.pcs[e].state(), added);
        reviewed(&mut w.s[e]);
        // C and D take A's newest file with its code too (behind G1: G2 is
        // off on both, and the addition needs it anyway); B and F, which
        // took the removal, need it for the addition.
        for i in [b, c, d, f] {
            w.round(i);
            accept(
                &mut w.s[i],
                (PASSWORD, None),
                &w.keys,
                4,
                ForkOption::Both,
                code(&shown),
            )
            .unwrap_or_else(|e| panic!("PC {i}: {e}"));
            assert_eq!(w.pcs[i].state(), added, "PC {i}");
            reviewed(&mut w.s[i]);
        }
        w.settle();
        w.converged();
        for i in 0..names.len() {
            assert_eq!(w.s[i].server_class(), Some(KeyClass::Equal), "PC {i}");
        }
        for title in ["kept on b", "kept on c", "kept on d"] {
            assert!(has(&w.s[0], title), "{title}");
        }
        // Key 1's holder writes a password change from before the removal
        // and a hostile copy of the server serves it to F.
        let t = Temp::new("gate-hostile");
        let forged = written_by(&old, &t.0, &w.keys, 1, vec![(PASSWORD, password(NEW))]);
        let hostile = t.0.join("data");
        copy_tree(&w.store.root, &hostile);
        let next = top(&hostile, &id).unwrap().0 + 1;
        let epoch = parse(&forged).unwrap().epoch;
        plant(&hostile, &id, next, epoch, &key_record(0, &forged));
        w.pcs[f].to(&hostile);
        let (asked, derived) = (w.keys.asked(), derive_count());
        let told = w.round(f);
        assert_eq!((w.keys.asked(), derive_count()), (asked, derived));
        let refused = KeyClass::Refused("제거된 보안 키가 승인함");
        assert_eq!(w.s[f].server_class(), Some(refused), "{told:?}");
        assert!(told.contains(&SyncNotice::KeyFileRefused("제거된 보안 키가 승인함")));
        done();
    }

    /// A request sent as a stolen sync key would send it, on a line that
    /// names the vault.
    fn stolen(root: &Path, id: [u8; 16], frame: &[u8]) -> Status {
        let mut line = KeyLocal {
            root: root.to_path_buf(),
            ids: vec![id],
        };
        let out = line.exchange(frame, &mut || {}).unwrap();
        let op = Request::decode(frame).unwrap().op;
        Response::decode(&out.stdout, op, &id, 0)
            .map(|(r, _)| r.status)
            .unwrap_or(Status::BadRequest)
    }

    /// Walkthrough §7.21-33 (a), (b), (e) and (f) with the real script
    /// (§14.10-24 (a), -25 and -26). (b) An off whose rotation fails writes
    /// nothing and sends no CUT; the retry in the same session reuses its
    /// snapshot and lands. (a) An on right after an off is refused until
    /// the CUT's answer settles the off, then lands on the cut with no CUT
    /// after it, and the other PC, held by the cut meanwhile, takes the
    /// re-enable with no gate. (e) The off's CUT replayed by a stolen key
    /// is a no-op on the later generation; a planted CUT on the current
    /// record ends it, both PCs hold, and one re-upload restores sync. (f)
    /// An admin's `rm -r k/`: no PC re-uploads by itself; one re-upload
    /// starts the namespace again. Record numbers only grow within a
    /// namespace, and every vault passes the floor at the end.
    #[test]
    fn off_and_on_cycles_with_the_real_server() {
        if !python() {
            return;
        }
        let mut w = world(&["p-a", "p-b"], 2, &[1, 2], true);
        let id = w.id;
        let root = w.store.root.clone();
        let on = w.pcs[0].state();

        // ---- (b) an off whose rotation fails ----
        let mut perms = fs::metadata(&w.pcs[0].key).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&w.pcs[0].key, perms.clone()).unwrap();
        let failed = rekey(&mut w.s[0], PASSWORD, &w.keys, 1, Change::KeySyncOff);
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&w.pcs[0].key, perms).unwrap();
        assert_eq!(failed.err(), Some(goyo_vault::vault::KEY_NOT_SAVED));
        assert_eq!(w.pcs[0].state(), on, "nothing changed");
        assert_eq!(w.pcs[0].header().magic, Magic::Ks01);
        assert!(w.pcs[0].kreq().is_none(), "no CUT without its write");
        w.pcs[0].sent();
        w.round(0);
        assert!(!w.pcs[0].sent().contains(&Op::CutKey));
        assert_eq!(top(&root, &id).map(|t| t.1), Some(RecordKind::Key));
        // The retry in the same session lands, with the snapshot it took.
        assert_eq!(
            rekey(&mut w.s[0], PASSWORD, &w.keys, 1, Change::KeySyncOff),
            Ok(Rekeyed::Done)
        );
        let l = 1;
        assert_eq!(
            w.pcs[0].request(&id).map(|r| (r.0, r.1)),
            Some((KeyOp::Cut, l))
        );

        // ---- (a) on right after the off ----
        let refused = rekey(&mut w.s[0], PASSWORD, &w.keys, 1, Change::KeySyncOn);
        assert_eq!(refused.err(), Some(KEYSYNC_OFF_PENDING));
        w.pcs[0].sent();
        let told = w.round(0);
        assert!(
            told.contains(&SyncNotice::KeySyncDeleted {
                seq: l + 1,
                admin: true
            }),
            "{told:?}"
        );
        assert_eq!(top(&root, &id), Some((l + 1, RecordKind::Cut, l + 1)));
        assert_eq!(
            rekey(&mut w.s[0], PASSWORD, &w.keys, 1, Change::KeySyncOn),
            Ok(Rekeyed::Done)
        );
        let again = w.pcs[0].header();
        assert_eq!(again.magic, Magic::Ks01);
        assert!(again.epoch > on.epoch);
        assert_eq!(
            w.pcs[0].request(&id).map(|r| (r.0, r.1)),
            Some((KeyOp::Put, l + 1))
        );
        w.pcs[0].sent();
        w.round(0);
        w.round(0);
        assert!(
            !w.pcs[0].sent().contains(&Op::CutKey),
            "no CUT after the on"
        );
        assert_eq!(top(&root, &id), Some((l + 2, RecordKind::Key, l + 1)));
        assert_eq!(w.s[0].server_class(), Some(KeyClass::Equal));
        assert!(!w.s[0].key_sync_view().unwrap().gone);
        // B was held by the cut and takes the re-enable with no gate.
        let told = w.round(1);
        let ready = SyncNotice::KeyFileReady { epoch: again.epoch };
        assert!(told.contains(&ready), "{told:?}");
        accept(
            &mut w.s[1],
            (PASSWORD, None),
            &w.keys,
            2,
            ForkOption::Both,
            none,
        )
        .unwrap();
        assert_eq!(w.pcs[1].state(), again.state());
        w.settle();
        w.converged();

        // ---- (e) the generation rule ----
        let cut = Request::cut_key(id, l).unwrap().encode();
        assert_eq!(stolen(&root, id, &cut), Status::Ok);
        assert_eq!(
            top(&root, &id),
            Some((l + 2, RecordKind::Key, l + 1)),
            "a no-op"
        );
        let planted = Request::cut_key(id, l + 2).unwrap().encode();
        assert_eq!(stolen(&root, id, &planted), Status::Ok);
        assert_eq!(top(&root, &id), Some((l + 3, RecordKind::Cut, l + 3)));
        for i in [0, 1] {
            let told = w.round(i);
            assert!(told.contains(&SyncNotice::KeySyncGone), "PC {i}: {told:?}");
            assert!(!uploads(&w.pcs[i], &mut w.s[i], &format!("held {i}")));
            assert!(w.pcs[i].kreq().is_none(), "no PC re-uploads by itself");
        }
        assert_eq!(
            rekey(&mut w.s[1], PASSWORD, &w.keys, 2, Change::KeySyncOn),
            Ok(Rekeyed::Done)
        );
        let restored = w.pcs[1].state();
        assert_eq!(
            w.pcs[1].request(&id).map(|r| (r.0, r.1)),
            Some((KeyOp::Put, l + 3))
        );
        w.round(1);
        assert_eq!(top(&root, &id), Some((l + 4, RecordKind::Key, l + 3)));
        let told = w.round(0);
        let ready = SyncNotice::KeyFileReady {
            epoch: restored.epoch,
        };
        assert!(told.contains(&ready), "{told:?}");
        accept(
            &mut w.s[0],
            (PASSWORD, None),
            &w.keys,
            1,
            ForkOption::Both,
            none,
        )
        .unwrap();
        w.settle();
        w.converged();
        assert!(has(&w.s[0], "held 0") && has(&w.s[0], "held 1"));

        // ---- (f) an admin's rm -r k/ ----
        let vault_dir = root.join(syncfile::hex(&id));
        fs::remove_dir_all(vault_dir.join("k")).unwrap();
        let _ = fs::remove_file(vault_dir.join("lock"));
        for i in [0, 1] {
            let told = w.round(i);
            assert!(told.contains(&SyncNotice::KeySyncGone), "PC {i}: {told:?}");
            w.round(i);
            assert!(w.pcs[i].kreq().is_none(), "PC {i} re-uploads by itself");
        }
        assert!(records(&root, &id).is_empty());
        assert_eq!(
            rekey(&mut w.s[0], PASSWORD, &w.keys, 1, Change::KeySyncOn),
            Ok(Rekeyed::Done)
        );
        assert_eq!(
            w.pcs[0].request(&id).map(|r| (r.0, r.1)),
            Some((KeyOp::Put, 0))
        );
        w.round(0);
        assert_eq!(top(&root, &id), Some((1, RecordKind::Key, 0)));
        w.round(1);
        accept(
            &mut w.s[1],
            (PASSWORD, None),
            &w.keys,
            2,
            ForkOption::Both,
            none,
        )
        .unwrap();
        w.settle();
        w.converged();
        for i in [0, 1] {
            assert_eq!(w.s[i].server_class(), Some(KeyClass::Equal), "PC {i}");
            assert!(uploads(&w.pcs[i], &mut w.s[i], &format!("after {i}")));
        }
        w.settle();
        w.converged();
        assert!(audit(&root, &id) <= 2);
        done();
    }
}
