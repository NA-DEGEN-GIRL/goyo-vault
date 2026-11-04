//! The Android transport: one SSH connection per exchange, as the Windows
//! helper runs one `ssh.exe` per exchange, with russh (ring crypto) in
//! place of OpenSSH. It sends exactly the engine's request frame on the
//! channel's stdin, closes it, and hands back a bounded stdout, the remote
//! stderr and its own messages (`log`), worded as OpenSSH words them so the
//! engine's `classify` reads them alike. No server can write into `log`.
//!
//! In the order the Windows helper's options give (transport.rs there):
//! the host is resolved once and refused unless every address is a
//! Tailscale address (tailnet.rs: the user's rule for the phone); connect
//! within 20 s (ConnectTimeout=20); the host key must be the pinned one
//! (StrictHostKeyChecking=yes; hostkey.rs), an unknown or changed key ends
//! the connection before authentication; only the phone's own ed25519 key
//! is offered (IdentitiesOnly=yes), never a password or keyboard prompt
//! (BatchMode=yes); keepalives every 15 s, 3 missed end it
//! (ServerAliveInterval=15, ServerAliveCountMax=3); no PTY, no forwarding,
//! no agent, no X11 (`-T -x -a`): the client asks for nothing but one exec
//! channel. The whole exchange is cut at the configured timeout.
use crate::{
    hostkey::{self, Pin, Verdict},
    tailnet,
};
use goyo_vault::syncengine::transport::{
    Failure, Killed, MAX_STDERR, MAX_STDOUT, Output, Transport,
};
use russh::{
    ChannelMsg, Disconnect, Preferred,
    client::{self, AuthResult},
    keys::{
        Algorithm, EcdsaCurve, PrivateKey, PrivateKeyWithHashAlg, ssh_key::private::Ed25519Keypair,
    },
};
use std::{
    borrow::Cow,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const KEEPALIVE: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 3;
const BEAT: Duration = Duration::from_millis(50);

/// The base64 of the public wire encoding of the key with `seed`: what
/// follows `ssh-ed25519` in the server's line.
pub fn public_blob(seed: &[u8; 32]) -> String {
    let pair = Ed25519Keypair::from_seed(seed);
    crate::line::public_blob_of(&pair.public.0)
}

/// Where and as whom; every value was checked by line.rs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// `<python> -I <remote> serve` (line::serve_command).
    pub command: String,
    pub timeout: Duration,
}

/// Why the last exchange ended before the server answered, for the app's
/// badge and its host-key screen. The engine sees only the `log` words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// No key on this phone yet (or it could not be unwrapped).
    NoKey,
    Tailnet(tailnet::Refusal),
    /// The socket's local end is not a Tailscale address.
    NotTunnel(SocketAddr),
    Connect(String),
    /// No pin for this host: the key it showed, for the TOFU screen.
    HostUnknown {
        blob: Vec<u8>,
    },
    /// The host is pinned to another key.
    HostChanged {
        blob: Vec<u8>,
    },
    Auth,
    Ssh(String),
}

/// What the host-key check saw, shared with the russh handler.
#[derive(Default)]
struct Seen {
    blob: Option<Vec<u8>>,
    verdict: Option<Verdict>,
}
struct Handler {
    pin: Option<Pin>,
    host: String,
    port: u16,
    seen: Arc<Mutex<Seen>>,
}
impl client::Handler for Handler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let blob = key.to_bytes().unwrap_or_default();
        let verdict = hostkey::judge(self.pin.as_ref(), &self.host, self.port, &blob);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.blob = Some(blob);
        seen.verdict = Some(verdict);
        Ok(verdict == Verdict::Match)
    }
}

/// The algorithms offered: the russh defaults without RSA (this build has
/// no RSA), so a host key is ed25519 or ECDSA.
fn preferred() -> Preferred {
    Preferred {
        key: Cow::Borrowed(&[
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
        ]),
        ..Preferred::default()
    }
}

pub struct AndroidTransport {
    pub target: Target,
    /// The ed25519 seed, set by the caller for one run and taken out after.
    pub seed: Option<Zeroizing<[u8; 32]>>,
    pub pin: Option<Pin>,
    pub cancel: Arc<AtomicBool>,
    /// Why the last exchange failed before an answer; None after one that
    /// reached the server's script.
    pub problem: Option<Problem>,
    /// Whether the local end must be a Tailscale address too (off only in
    /// the tests, which run the server script over pipes, not this).
    pub check_local: bool,
}
impl AndroidTransport {
    pub fn new(target: Target, cancel: Arc<AtomicBool>) -> Self {
        Self {
            target,
            seed: None,
            pin: None,
            cancel,
            problem: None,
            check_local: true,
        }
    }
    fn refused(&mut self, problem: Problem, log: String) -> Result<Output, Failure> {
        self.problem = Some(problem);
        Ok(Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            log: log.into_bytes(),
            code: Some(255),
            killed: None,
        })
    }
}

impl Transport for AndroidTransport {
    fn exchange(&mut self, request: &[u8], beat: &mut dyn FnMut()) -> Result<Output, Failure> {
        self.problem = None;
        let Some(seed) = self.seed.as_ref() else {
            return self.refused(
                Problem::NoKey,
                "Permission denied (publickey): no key on this phone".into(),
            );
        };
        let key = PrivateKey::from(Ed25519Keypair::from_seed(seed));
        let target = self.target.clone();
        // Resolved once, here; only these addresses are ever connected to.
        let resolved: Vec<SocketAddr> = match (target.host.as_str(), target.port).to_socket_addrs()
        {
            Ok(it) => it.collect(),
            Err(_) => Vec::new(),
        };
        let addrs = match tailnet::admit(&resolved) {
            Ok(addrs) => addrs,
            Err(tailnet::Refusal::Unresolved) => {
                return self.refused(
                    Problem::Tailnet(tailnet::Refusal::Unresolved),
                    format!(
                        "ssh: Could not resolve hostname {}: no Tailscale address",
                        target.host
                    ),
                );
            }
            Err(refusal) => {
                return self.refused(
                    Problem::Tailnet(refusal),
                    format!(
                        "ssh: {}: not a Tailscale address: unreachable over Tailscale, not connected",
                        target.host
                    ),
                );
            }
        };
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
        else {
            return Err(Failure::Start);
        };
        let seen = Arc::new(Mutex::new(Seen::default()));
        let handler = Handler {
            pin: self.pin.clone(),
            host: target.host.clone(),
            port: target.port,
            seen: seen.clone(),
        };
        let cancel = self.cancel.clone();
        let check_local = self.check_local;
        let started = Instant::now();
        let outcome = rt.block_on(run(
            addrs,
            handler,
            key,
            &target,
            request,
            check_local,
            &cancel,
            started,
            beat,
        ));
        rt.shutdown_timeout(Duration::from_millis(100));
        match outcome {
            Ran::Out(out) => Ok(out),
            Ran::NotTunnel(local) => self.refused(
                Problem::NotTunnel(local),
                format!(
                    "ssh: connect to host {}: local address {local} is not on Tailscale: unreachable over Tailscale",
                    target.host
                ),
            ),
            Ran::Connect(e) => {
                let log = format!(
                    "ssh: connect to host {} port {}: {e}",
                    target.host, target.port
                );
                self.refused(Problem::Connect(e), log)
            }
            Ran::Ssh(e) => {
                let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
                match (&seen.verdict, &seen.blob) {
                    (Some(Verdict::Unknown), Some(blob)) => {
                        let blob = blob.clone();
                        drop(seen);
                        self.refused(
                            Problem::HostUnknown { blob },
                            format!(
                                "No pinned host key for {}.\nHost key verification failed.",
                                target.host
                            ),
                        )
                    }
                    (Some(Verdict::Changed), Some(blob)) => {
                        let blob = blob.clone();
                        drop(seen);
                        self.refused(
                            Problem::HostChanged { blob },
                            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed."
                                .into(),
                        )
                    }
                    _ => {
                        drop(seen);
                        let log = format!("ssh: {e}");
                        self.refused(Problem::Ssh(e), log)
                    }
                }
            }
            Ran::Auth => self.refused(
                Problem::Auth,
                format!(
                    "{}@{}: Permission denied (publickey).",
                    target.user, target.host
                ),
            ),
        }
    }
}

enum Ran {
    Out(Output),
    NotTunnel(SocketAddr),
    Connect(String),
    Ssh(String),
    Auth,
}

/// Connects to the first address that answers within 20 s.
async fn connect(addrs: &[SocketAddr]) -> Result<tokio::net::TcpStream, String> {
    let mut last = String::from("no address");
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "Connection timed out".into(),
        }
    }
    Err(last)
}

#[allow(clippy::too_many_arguments)]
async fn run(
    addrs: Vec<SocketAddr>,
    handler: Handler,
    key: PrivateKey,
    target: &Target,
    request: &[u8],
    check_local: bool,
    cancel: &AtomicBool,
    started: Instant,
    beat: &mut dyn FnMut(),
) -> Ran {
    let stream = match connect(&addrs).await {
        Ok(s) => s,
        Err(e) => return Ran::Connect(e),
    };
    if check_local
        && let Ok(local) = stream.local_addr()
        && !tailnet::is_tailscale(local.ip())
    {
        return Ran::NotTunnel(local);
    }
    let _ = stream.set_nodelay(true);
    let config = Arc::new(client::Config {
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: KEEPALIVE_MAX,
        inactivity_timeout: None,
        preferred: preferred(),
        ..client::Config::default()
    });
    let left = target.timeout.saturating_sub(started.elapsed());
    let mut session =
        match tokio::time::timeout(left, client::connect_stream(config, stream, handler)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Ran::Ssh(e.to_string()),
            Err(_) => return Ran::Connect("Connection timed out during key exchange".into()),
        };
    let auth = session
        .authenticate_publickey(
            target.user.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(key), None),
        )
        .await;
    match auth {
        Ok(AuthResult::Success) => {}
        Ok(AuthResult::Failure { .. }) => return Ran::Auth,
        Err(e) => return Ran::Ssh(e.to_string()),
    }
    let channel = match session.channel_open_session().await {
        Ok(c) => c,
        Err(e) => return Ran::Ssh(e.to_string()),
    };
    if let Err(e) = channel.exec(true, target.command.as_bytes()).await {
        return Ran::Ssh(e.to_string());
    }
    let (mut read, write) = channel.split();
    let mut out = Output {
        stdout: Vec::new(),
        stderr: Vec::new(),
        log: Vec::new(),
        code: None,
        killed: None,
    };
    // The request goes in while the answer comes back: a server that
    // answers before it read everything (TOO_LARGE) is still heard, and an
    // answer that ends the exchange drops a send that would wait forever.
    let send = async {
        let _ = write.data(request).await;
        let _ = write.eof().await;
    };
    tokio::pin!(send);
    let mut sent = false;
    let mut tick = tokio::time::interval(BEAT);
    loop {
        tokio::select! {
            () = &mut send, if !sent => sent = true,
            msg = read.wait() => match msg {
                Some(ChannelMsg::Data { data }) => {
                    if out.stdout.len() + data.len() > MAX_STDOUT {
                        out.killed = Some(Killed::Overflow);
                        break;
                    }
                    out.stdout.extend_from_slice(&data);
                }
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    let room = MAX_STDERR.saturating_sub(out.stderr.len());
                    out.stderr.extend_from_slice(&data[..data.len().min(room)]);
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    out.code = i32::try_from(exit_status).ok();
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            _ = tick.tick() => {
                beat();
                if cancel.load(Ordering::Relaxed) {
                    out.killed = Some(Killed::Cancelled);
                    break;
                }
                if started.elapsed() >= target.timeout {
                    out.killed = Some(Killed::Timeout);
                    break;
                }
            }
        }
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        session.disconnect(Disconnect::ByApplication, "", "en"),
    )
    .await;
    Ran::Out(out)
}
