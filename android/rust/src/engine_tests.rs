//! The phone's side of sync end to end, on the PC that builds the app: the
//! shared engine (`goyo_vault::syncengine`) running the phone's passes over
//! the phone's file layout (`<files>/vault/vault.goyo` and its
//! `vault.goyo.sync`) against the real server script, run locally over
//! pipes (`python server/goyo-sync-server.py serve --root <tmp>`) as the
//! goyo-sync bin's tests do; and the Android transport's refusals, which
//! need no server. Nothing here opens a network connection or touches the
//! PC's own key record (each test's anchor is a temp folder). Without
//! python the server tests fail loudly, unless GOYO_SYNC_SKIP_PYTHON=1.
use crate::{
    ssh::{AndroidTransport, Problem, Target},
    syncrun, tailnet,
};
use goyo_vault::{
    syncengine::{
        Engine, Log, Outcome, Report, system_clock,
        transport::{Failure, Killed, MAX_STDERR, MAX_STDOUT, Output, Transport},
    },
    syncfile::{
        self, INCOMING, KEY_REQUEST, KEY_VIEW, KeyOutcome, KeyRequest, OUTGOING, SyncState,
        parse_key_view, render_key_request,
    },
    syncwire::{Request, sha256},
    vault::{self, Entry, Provision, Session, SyncBadge, keyfile::is_sync_key_file},
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

const PASSWORD: &str = "a long synthetic password";
/// The GOYOKS01 fixture of the lib's tests: vault 3a3b…49, epoch 9.
const KS: &[u8] = include_bytes!("../../../tests/fixtures/goyoks01.goyokey");

struct Temp(PathBuf);
impl Temp {
    fn new(what: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "goyo-android-{what}-{:x}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn server_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/goyo-sync-server.py")
}
fn python() -> bool {
    let ok = Command::new("python")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok && std::env::var_os("GOYO_SYNC_SKIP_PYTHON").is_none() {
        panic!("python is needed for the server tests (GOYO_SYNC_SKIP_PYTHON=1 skips them)");
    }
    ok
}

/// The server script over pipes: one process per exchange, as one ssh
/// connection runs one `serve`. `key_sync` is the forced command's
/// `--key-sync=` list.
struct Pipe {
    root: PathBuf,
    key_sync: Vec<[u8; 16]>,
}
impl Transport for Pipe {
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        let mut command = Command::new("python");
        command
            .arg("-I")
            .arg(server_script())
            .args(["serve", "--root"])
            .arg(&self.root);
        if !self.key_sync.is_empty() {
            let ids: Vec<String> = self.key_sync.iter().map(|i| syncfile::hex(i)).collect();
            command.arg(format!("--key-sync={}", ids.join(",")));
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| Failure::Missing)?;
        let mut stdin = child.stdin.take().ok_or(Failure::Start)?;
        let mut stdout = child.stdout.take().ok_or(Failure::Start)?;
        let mut stderr = child.stderr.take().ok_or(Failure::Start)?;
        let input = request.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = (&mut stdout)
                .take(MAX_STDOUT as u64 + 1)
                .read_to_end(&mut out);
            out
        });
        let mut err = Vec::new();
        let _ = (&mut stderr).take(MAX_STDERR as u64).read_to_end(&mut err);
        beat();
        let status = child.wait().map_err(|_| Failure::Start)?;
        let _ = writer.join();
        let out = reader.join().unwrap_or_default();
        let overflow = out.len() > MAX_STDOUT;
        Ok(Output {
            stdout: out,
            stderr: err,
            log: Vec::new(),
            code: status.code(),
            killed: overflow.then_some(Killed::Overflow),
        })
    }
}

/// A device: a folder laid out as the phone's `<files>` (or a PC's
/// GoyoVault folder), and its engine, which runs the phone's passes.
struct Device {
    t: Temp,
    vault: PathBuf,
    key: PathBuf,
    dir: PathBuf,
    engine: Engine<Pipe>,
}
impl Device {
    fn new(name: &str, root: &Path, key_sync: &[[u8; 16]]) -> Self {
        let t = Temp::new(name);
        let paths = syncrun::Paths::new(&t.0);
        fs::create_dir_all(paths.vault.parent().unwrap()).unwrap();
        let vault = paths.vault.clone();
        let engine = Engine::new(
            Pipe {
                root: root.to_owned(),
                key_sync: key_sync.to_vec(),
            },
            std::slice::from_ref(&vault),
            60,
            system_clock(),
            Log::new(Some(t.0.join("goyo-sync.log"))),
        );
        Self {
            key: vault.with_file_name("vault.goyokey"),
            dir: syncfile::sync_dir(&vault).unwrap(),
            vault,
            t,
            engine,
        }
    }
    fn pass(&mut self) -> Report {
        match self.engine.pass(0, true) {
            Outcome::Done(report) => report,
            other => panic!("{other:?}"),
        }
    }
    fn outgoing(&self) -> Option<u64> {
        let bytes = fs::read(self.dir.join(OUTGOING)).ok()?;
        syncfile::parse_outgoing(&bytes).map(|(base, _)| base)
    }
    fn log(&self) -> String {
        fs::read_to_string(self.t.0.join("goyo-sync.log")).unwrap_or_default()
    }
}
fn entry(title: &str, secret: &str) -> Entry {
    Entry::new(title.into(), "login".into(), secret.into(), String::new()).unwrap()
}
fn titles(s: &Session) -> Vec<String> {
    let mut t: Vec<String> = s
        .entries
        .iter()
        .map(|e| e.title.as_str().to_owned())
        .collect();
    t.sort();
    t
}
fn done(state: SyncState, server: u64, up: Option<u64>, down: Option<u64>) -> Report {
    Report {
        state,
        server,
        uploaded: up,
        downloaded: down,
    }
}

/// A vault made on a PC, synced there, imported by the phone as stage 1
/// imports it (both files copied in), then edited on both sides: the
/// phone's passes fetch, upload and keep the server's history exactly as a
/// PC's helper does, and the two sessions merge each other's changes.
#[test]
fn the_phone_syncs_a_pc_vault_through_the_real_server() {
    if !python() {
        return;
    }
    let anchor = Temp::new("anchor");
    vault::set_anchor_dir(Some(anchor.0.clone()));
    let store = Temp::new("server");
    let root = store.0.join("data");
    let mut pc = Device::new("pc", &root, &[]);
    let mut phone = Device::new("phone", &root, &[]);

    // The PC: a vault with two entries, sync turned on, uploaded.
    let mut spc = Provision::new()
        .unwrap()
        .finish(&pc.vault, &pc.key, PASSWORD)
        .unwrap();
    spc.put(None, entry("mail", "first")).unwrap();
    spc.put(None, entry("bank", "first")).unwrap();
    assert_eq!(pc.pass(), done(SyncState::Idle, 0, None, None));
    assert!(spc.sync_offer());
    spc.enable_sync().unwrap();
    assert_eq!(pc.pass(), done(SyncState::Ok, 1, Some(1), None));
    let _ = spc.poll_sync();
    assert_eq!(spc.badge(), Some(SyncBadge::Synced));

    // The phone imports both files (by USB in real life).
    fs::copy(&pc.vault, &phone.vault).unwrap();
    fs::copy(&pc.key, &phone.key).unwrap();
    // Its first pass makes the sync folder; nothing is pinned yet.
    assert_eq!(phone.pass(), done(SyncState::Idle, 0, None, None));
    assert!(syncfile::usable_dir(&phone.dir));
    let mut sphone = Session::unlock(&phone.vault, &phone.key, PASSWORD).unwrap();
    // Unlock, then the app's polls offer this state; it loses to version 1.
    for _ in 0..2 {
        let _ = sphone.poll_sync();
    }
    assert_eq!(phone.outgoing(), Some(0));
    assert_eq!(phone.pass(), done(SyncState::Ok, 1, None, Some(1)));
    let _ = sphone.poll_sync();
    assert_eq!(sphone.check_code(), spc.check_code());
    assert_eq!(sphone.badge(), Some(SyncBadge::Synced));

    // The phone saves an entry ("after each save" runs a pass).
    sphone
        .put(None, entry("phone", "added on the phone"))
        .unwrap();
    assert_eq!(phone.outgoing(), Some(1));
    assert_eq!(phone.pass(), done(SyncState::Ok, 2, Some(2), None));
    // The PC's helper fetches it and its app merges it.
    assert_eq!(pc.pass(), done(SyncState::Ok, 2, None, Some(2)));
    let ev = spc.poll_sync().unwrap();
    assert!(ev.list_changed);
    assert_eq!(titles(&spc), ["bank", "mail", "phone"]);

    // The PC deletes one; the phone's periodic pass brings it over.
    let i = spc
        .entries
        .iter()
        .position(|e| e.title.as_str() == "bank")
        .unwrap();
    spc.delete(i).unwrap();
    assert_eq!(pc.pass(), done(SyncState::Ok, 3, Some(3), None));
    assert_eq!(phone.pass(), done(SyncState::Ok, 3, None, Some(3)));
    let _ = sphone.poll_sync();
    assert_eq!(titles(&sphone), ["mail", "phone"]);
    let _ = spc.poll_sync();
    assert_eq!(sphone.check_code(), spc.check_code());

    // A background pass with the vault closed moves only files: the PC's
    // next change lands in incoming, and the next unlock merges it.
    drop(sphone);
    spc.put(None, entry("later", "while the phone was locked"))
        .unwrap();
    assert_eq!(pc.pass(), done(SyncState::Ok, 4, Some(4), None));
    assert_eq!(phone.pass(), done(SyncState::Ok, 4, None, Some(4)));
    let incoming = fs::read(phone.dir.join(INCOMING)).unwrap();
    assert_eq!(syncfile::parse_incoming(&incoming).unwrap().0, 4);
    let sphone = Session::unlock(&phone.vault, &phone.key, PASSWORD).unwrap();
    assert_eq!(titles(&sphone), ["later", "mail", "phone"]);
    assert!(!phone.log().is_empty());
    vault::set_anchor_dir(None);
}

/// Key-file sync over the real server with this phone's line naming the
/// vault (`--key-sync=`): the app's PUT request goes as PUTKEY before the
/// vault upload (KR before P4), the server's answer lands in `kview`, a
/// GOYOVA04 upload at that key file's state passes the server's floor, an
/// upload at another state is held as `keyfile`, another device's GETKEY
/// gets the record, and a CUT ends it. A line without the vault gets
/// `nokeys` and changes nothing on the server.
#[test]
fn key_file_ops_through_the_real_server() {
    if !python() {
        return;
    }
    let store = Temp::new("server-keys");
    let root = store.0.join("data");
    let id: [u8; 16] = KS[8..24].try_into().unwrap();
    let syntax = is_sync_key_file(KS, &id).unwrap();
    // A GOYOVA04 vault at the key file's state (what the server's floor
    // checks: epoch, current key ID, state tag), flags 3.
    let vault_at = |epoch: u64, fill: u8| {
        let mut v = Vec::from(*b"GOYOVA04");
        v.extend_from_slice(&id);
        v.resize(200, fill);
        v[24..40].copy_from_slice(&syntax.current_key_id);
        v[40..48].copy_from_slice(&epoch.to_le_bytes());
        v[48..64].copy_from_slice(&syntax.tag);
        v[64..68].copy_from_slice(&[3, 0, 0, 0]);
        v
    };
    let mut phone = Device::new("phone-keys", &root, &[id]);
    fs::write(&phone.vault, b"never read by the engine").unwrap();
    fs::create_dir(&phone.dir).unwrap();

    // The app's request and its upload at that state, written together.
    let put = render_key_request(&KeyRequest::put(0, 0, KS));
    syncfile::replace_file(&phone.dir.join(KEY_REQUEST), &put).unwrap();
    let up = syncfile::render_outgoing(0, &vault_at(syntax.epoch, 1)).unwrap();
    syncfile::replace_file(&phone.dir.join(OUTGOING), &up).unwrap();
    assert_eq!(phone.pass(), done(SyncState::Ok, 1, Some(1), None));
    let view = parse_key_view(&fs::read(phone.dir.join(KEY_VIEW)).unwrap(), &id).unwrap();
    assert_eq!(view.answered, Some(sha256(&put)));
    assert_eq!(view.outcome, KeyOutcome::Applied);
    assert_eq!(view.line, 0);
    let seq = view.seq;
    assert!(seq >= 1);
    assert!(view.record.ends_with(KS), "the record carries the key file");

    // An upload at another key-file state is refused by the floor and held.
    let wrong = syncfile::render_outgoing(1, &vault_at(syntax.epoch + 1, 2)).unwrap();
    syncfile::replace_file(&phone.dir.join(OUTGOING), &wrong).unwrap();
    assert_eq!(phone.pass().state, SyncState::KeyFile);

    // Another device on a line with the vault fetches the record.
    let mut wire = Pipe {
        root: root.clone(),
        key_sync: vec![id],
    };
    let got = goyo_vault::syncengine::call(
        &mut wire,
        &Request::get_key(id, 0, None),
        "test",
        &Log::new(None),
    )
    .unwrap();
    assert_eq!(got.version, seq);
    assert!(got.blob().ends_with(KS));

    // The phone ends the generation (CUT at the record it holds).
    let cut = render_key_request(&KeyRequest::cut(seq));
    syncfile::replace_file(&phone.dir.join(KEY_REQUEST), &cut).unwrap();
    let _ = phone.pass();
    let view = parse_key_view(&fs::read(phone.dir.join(KEY_VIEW)).unwrap(), &id).unwrap();
    assert_eq!(view.answered, Some(sha256(&cut)));
    assert_eq!(view.outcome, KeyOutcome::Applied);
    assert!(view.seq > seq);

    // A line that does not name the vault: the server refuses every key op
    // (BAD_REQUEST), the view says line 1, and the vault shows `nokeys`.
    let mut other = Device::new("pc-nokeys", &root, &[]);
    fs::write(&other.vault, b"never read by the engine").unwrap();
    fs::create_dir(&other.dir).unwrap();
    let req = render_key_request(&KeyRequest::put(0, 0, KS));
    syncfile::replace_file(&other.dir.join(KEY_REQUEST), &req).unwrap();
    let up = syncfile::render_outgoing(0, &vault_at(syntax.epoch, 3)).unwrap();
    syncfile::replace_file(&other.dir.join(OUTGOING), &up).unwrap();
    let report = other.pass();
    assert_eq!(report.state, SyncState::NoKeys, "{}", other.log());
    let view = parse_key_view(&fs::read(other.dir.join(KEY_VIEW)).unwrap(), &id).unwrap();
    assert_eq!(view.line, 1);
    assert_eq!(view.outcome, KeyOutcome::NoKeyOps);
}

/// The Android transport refuses before any connection: a host that is not
/// on Tailscale (every address must be), a name that resolves to nothing,
/// and a phone without its key. The engine reads its words as OpenSSH's.
#[test]
fn the_transport_refuses_before_connecting() {
    let cancel = Arc::new(AtomicBool::new(false));
    let target = |host: &str| Target {
        host: host.into(),
        port: 22,
        user: "me".into(),
        command: "python3 -I s.py serve".into(),
        timeout: Duration::from_secs(5),
    };
    let request = Request::hello().encode();
    let log = Log::new(None);
    for host in ["127.0.0.1", "192.168.1.20", "100.128.0.1", "::1"] {
        let mut t = AndroidTransport::new(target(host), cancel.clone());
        t.seed = Some(zeroize::Zeroizing::new([7u8; 32]));
        let got = goyo_vault::syncengine::call(&mut t, &Request::hello(), "test", &log);
        assert!(
            matches!(
                got,
                Err(goyo_vault::syncengine::CallError::Failed(
                    SyncState::Offline,
                    _
                ))
            ),
            "{host}"
        );
        assert!(
            matches!(
                &t.problem,
                Some(Problem::Tailnet(tailnet::Refusal::NotTailscale(_)))
            ),
            "{host}: {:?}",
            t.problem
        );
    }
    // An unresolvable name (the reserved .invalid TLD).
    let mut t = AndroidTransport::new(target("no-such-host.invalid"), cancel.clone());
    t.seed = Some(zeroize::Zeroizing::new([7u8; 32]));
    let out = t.exchange(&request, &mut || {}).unwrap();
    assert!(String::from_utf8_lossy(&out.log).contains("Could not resolve"));
    assert_eq!(
        t.problem,
        Some(Problem::Tailnet(tailnet::Refusal::Unresolved))
    );
    // No key on the phone: refused as a failed login, nothing resolved.
    let mut t = AndroidTransport::new(target("100.64.0.1"), cancel);
    let got = goyo_vault::syncengine::call(&mut t, &Request::hello(), "test", &log);
    assert!(matches!(
        got,
        Err(goyo_vault::syncengine::CallError::Failed(
            SyncState::Auth,
            _
        ))
    ));
    assert_eq!(t.problem, Some(Problem::NoKey));
}
