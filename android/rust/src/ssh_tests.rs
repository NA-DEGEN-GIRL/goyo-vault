//! The Android transport against a real SSH server: a russh server on
//! 127.0.0.1 inside the test that runs the real server script
//! (`python server/goyo-sync-server.py serve --root <tmp>`) for each exec,
//! as sshd runs the forced command. It checks what only a real SSH
//! connection shows: the host key's trust on first use, the pin, a
//! changed key refused before authentication, a key the server does not
//! know refused as a failed login, the request frame through the channel
//! (HELLO's 512-byte echo, LIST, a vault upload) and an engine pass over
//! SSH. Loopback is admitted only by the test-only `loopback` switch; the
//! Tailscale rule itself is tested in tailnet.rs and engine_tests.rs.
use crate::{
    hostkey,
    ssh::{AndroidTransport, Problem, Target},
};
use goyo_vault::{
    syncengine::{CallError, Engine, Log, Outcome, call, system_clock},
    syncfile::{self, OUTGOING, SyncState},
    syncwire::{HELLO_ECHO, Request, Status, parse_list},
};
use russh::{
    Channel, ChannelId, CryptoVec,
    keys::{PrivateKey, ssh_key::private::Ed25519Keypair},
    server::{self, Auth, Msg, Session},
};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use zeroize::Zeroizing;

fn server_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/goyo-sync-server.py")
}
fn python() -> bool {
    let ok = Command::new("python")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok && std::env::var_os("GOYO_SYNC_SKIP_PYTHON").is_none() {
        panic!("python is needed for the SSH tests (GOYO_SYNC_SKIP_PYTHON=1 skips them)");
    }
    ok
}

/// What the test's sshd does on one connection: takes only `client`'s
/// key, and runs the server script on each exec with what came on the
/// channel's stdin, once that ends.
#[derive(Clone)]
struct Sshd {
    client: Vec<u8>,
    root: PathBuf,
    input: HashMap<ChannelId, Vec<u8>>,
    exec: HashMap<ChannelId, String>,
}
impl server::Handler for Sshd {
    type Error = russh::Error;
    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(
            if key.to_bytes().ok().as_deref() == Some(&self.client[..]) {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.exec
            .insert(channel, String::from_utf8_lossy(data).into_owned());
        session.channel_success(channel)?;
        Ok(())
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.input
            .entry(channel)
            .or_default()
            .extend_from_slice(data);
        Ok(())
    }
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let input = self.input.remove(&channel).unwrap_or_default();
        // The command the client asked for, as a forced command would
        // replace it: only `serve` is run here.
        assert!(
            self.exec
                .get(&channel)
                .is_some_and(|c| c.ends_with(" serve")),
            "{:?}",
            self.exec.get(&channel)
        );
        let mut child = Command::new("python")
            .arg("-I")
            .arg(server_script())
            .args(["serve", "--root"])
            .arg(&self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
        let mut out = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        let mut err = Vec::new();
        child.stderr.take().unwrap().read_to_end(&mut err).unwrap();
        let status = child.wait().unwrap();
        let _ = writer.join();
        for chunk in out.chunks(16 * 1024) {
            session.data(channel, CryptoVec::from_slice(chunk))?;
        }
        if !err.is_empty() {
            session.extended_data(channel, 1, CryptoVec::from_slice(&err))?;
        }
        session.exit_status_request(channel, status.code().unwrap_or(1) as u32)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

/// The test's sshd on 127.0.0.1 with host key `host_seed`, serving
/// connections one after the other on its own thread for the test's life.
fn sshd(host_seed: [u8; 32], client: Vec<u8>, root: PathBuf) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async move {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let config = Arc::new(server::Config {
                keys: vec![PrivateKey::from(Ed25519Keypair::from_seed(&host_seed))],
                auth_rejection_time: Duration::from_millis(10),
                auth_rejection_time_initial: Some(Duration::from_millis(0)),
                ..server::Config::default()
            });
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let handler = Sshd {
                    client: client.clone(),
                    root: root.clone(),
                    input: HashMap::new(),
                    exec: HashMap::new(),
                };
                if let Ok(running) = server::run_stream(config.clone(), stream, handler).await {
                    let _ = running.await;
                }
            }
        });
    });
    port
}

fn public_wire(seed: &[u8; 32]) -> Vec<u8> {
    PrivateKey::from(Ed25519Keypair::from_seed(seed))
        .public_key()
        .to_bytes()
        .unwrap()
}
fn transport(port: u16, seed: [u8; 32], pin: Option<hostkey::Pin>) -> AndroidTransport {
    let target = Target {
        host: "127.0.0.1".into(),
        port,
        user: "goyo".into(),
        command: "python3 -I .local/share/goyo-sync/goyo-sync-server.py serve".into(),
        timeout: Duration::from_secs(60),
    };
    let mut t = AndroidTransport::new(target, Arc::new(AtomicBool::new(false)));
    t.loopback = true;
    t.seed = Some(Zeroizing::new(seed));
    t.pin = pin;
    t
}

#[test]
fn the_transport_over_real_ssh() {
    if !python() {
        return;
    }
    let tmp = std::env::temp_dir().join(format!("goyo-android-ssh-{:x}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let root = tmp.join("data");
    let (host, phone, stranger) = ([9u8; 32], [3u8; 32], [4u8; 32]);
    let port = sshd(host, public_wire(&phone), root.clone());
    let log = Log::new(Some(tmp.join("goyo-sync.log")));

    // Trust on first use: no pin, so the key is shown and nothing is sent.
    let mut t = transport(port, phone, None);
    let got = call(&mut t, &Request::hello(), "test", &log);
    assert!(
        matches!(got, Err(CallError::Failed(SyncState::HostKey, _))),
        "{got:?}",
        got = got.as_ref().err()
    );
    let Some(Problem::HostUnknown { blob }) = t.problem.clone() else {
        panic!("{:?}", t.problem);
    };
    assert_eq!(blob, public_wire(&host));
    assert_eq!(
        hostkey::fingerprint(&blob),
        russh::keys::PublicKey::from_bytes(&blob)
            .unwrap()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string()
    );

    // Pinned: HELLO's 512 bytes come back unchanged, LIST answers.
    let pin = hostkey::pin_for("127.0.0.1", port, &blob).unwrap();
    let mut t = transport(port, phone, Some(pin.clone()));
    let hello = call(&mut t, &Request::hello(), "test", &log).unwrap();
    assert_eq!(hello.status, Status::Ok);
    assert_eq!(hello.blob(), HELLO_ECHO);
    let list = call(&mut t, &Request::list(), "test", &log).unwrap();
    assert_eq!(parse_list(list.blob()).map(|l| l.len()), Some(0));
    assert_eq!(t.problem, None);

    // A pin of another key: refused before authentication, never asked.
    let other = hostkey::pin_for("127.0.0.1", port, &public_wire(&[5; 32])).unwrap();
    let mut t = transport(port, phone, Some(other));
    let got = call(&mut t, &Request::hello(), "test", &log);
    assert!(matches!(got, Err(CallError::Failed(SyncState::HostKey, _))));
    assert!(matches!(&t.problem, Some(Problem::HostChanged { blob: b }) if *b == blob));

    // A client key the server does not know: a failed login.
    let mut t = transport(port, stranger, Some(pin.clone()));
    let got = call(&mut t, &Request::hello(), "test", &log);
    assert!(matches!(got, Err(CallError::Failed(SyncState::Auth, _))));
    assert_eq!(t.problem, Some(Problem::Auth));

    // An engine pass over SSH: the app's upload lands on the server.
    let files = tmp.join("files");
    let vault = files.join("vault").join("vault.goyo");
    std::fs::create_dir_all(vault.parent().unwrap()).unwrap();
    std::fs::write(&vault, b"never read by the engine").unwrap();
    let dir = syncfile::sync_dir(&vault).unwrap();
    std::fs::create_dir(&dir).unwrap();
    let id = [0x5au8; 16];
    let mut blob = Vec::from(*b"GOYOVA02");
    blob.extend_from_slice(&id);
    blob.resize(4000, 7);
    let out = syncfile::render_outgoing(0, &blob).unwrap();
    syncfile::replace_file(&dir.join(OUTGOING), &out).unwrap();
    let mut engine = Engine::new(
        transport(port, phone, Some(pin)),
        std::slice::from_ref(&vault),
        60,
        system_clock(),
        log,
    );
    match engine.pass(0, true) {
        Outcome::Done(report) => {
            assert_eq!(report.state, SyncState::Ok);
            assert_eq!(report.uploaded, Some(1));
        }
        other => panic!("{other:?}"),
    }
    let stored = root
        .join(syncfile::hex(&id))
        .join("v")
        .join(format!("{:012}.goyo", 1));
    assert_eq!(std::fs::read(stored).unwrap(), blob);
    let _ = std::fs::remove_dir_all(&tmp);
}
