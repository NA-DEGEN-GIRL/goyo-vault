//! The fake authenticator of the tests (spec v3 §8.9): CTAP 2.1's
//! hmac-secret and credProtect behind Windows' behaviour as probed (the
//! raw-salt flag, the allow list, a cancel with nothing pending). Up to 8
//! keys can be plugged in; the test picks which one answers each ceremony.
//! Builds with debug assertions only, so a release exe never holds it, and
//! package_release.py refuses its marker. It draws no randomness of the
//! vault's: its credential IDs and CredRandoms come from its own counter,
//! so a test's recorded draws stay in order.
use super::{
    AT, AssertRequest, Authenticator, BE, BS, CancelToken, FidoError, MakeRequest, RawAssertion,
    RawCredential, STORE_FULL, UP, USB, UV, Uv, rp_id_hash,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicU64, Ordering},
    mpsc::{Receiver, Sender, channel},
};
use zeroize::Zeroizing;

/// Marks the fake: package_release.py refuses an exe holding it.
const MARKER: &str = "goyo-fake-authenticator";
/// Wrong PINs before a key blocks.
const PIN_TRIES: u8 = 8;

/// A credential on a fake key.
#[derive(Clone)]
pub struct Credential {
    pub cred_id: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub user_id: Vec<u8>,
    pub resident: bool,
    pub random_uv: [u8; 32],
    pub random_nouv: [u8; 32],
    /// credProtect level 1-3.
    pub cred_protect: u8,
    /// The fake's clock when it was made, in ms.
    pub created: u64,
}
/// What a fake key does wrong when asked to (spec §8.9 "Faults").
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Fault {
    #[default]
    None,
    /// No hmac-secret output.
    NoOutput,
    /// A 31-byte output.
    ShortOutput,
    /// All-zero outputs.
    ZeroOutput,
    /// Another output for every call.
    Nondeterministic,
    WrongRpId,
    /// Windows answers with a credential that was not asked for.
    Unrequested,
    /// `pbFirst` and `pbSecond` swapped.
    Swapped,
    /// `pbSecond` never returned.
    NoSecond,
    /// MakeCredential fails: the store of discoverable credentials is full.
    StoreFull,
}
/// A fake security key.
#[derive(Clone)]
pub struct Device {
    pub credentials: Vec<Credential>,
    /// A PIN is set.
    pub pin: bool,
    /// The user types the right PIN when Windows asks.
    pub pin_right: bool,
    pub pin_tries: u8,
    /// alwaysUv: every assertion verifies the user.
    pub always_uv: bool,
    /// With UV discouraged and a PIN set, Windows asks for the PIN anyway
    /// (one of the two probed behaviours).
    pub uv_when_discouraged: bool,
    /// The highest credProtect level it supports; 0: none.
    pub cred_protect: u8,
    pub hmac_secret: bool,
    pub transport: u32,
    pub be: bool,
    pub bs: bool,
    /// The length of the credential IDs it makes, 16..=1023.
    pub cred_id_len: usize,
    pub fault: Fault,
    /// It answers only once the fake's clock reaches this (ms).
    pub answer_at: Option<u64>,
}
impl Default for Device {
    fn default() -> Self {
        Self {
            credentials: Vec::new(),
            pin: false,
            pin_right: true,
            pin_tries: PIN_TRIES,
            always_uv: false,
            uv_when_discouraged: false,
            cred_protect: 3,
            hmac_secret: true,
            transport: USB,
            be: false,
            bs: false,
            cred_id_len: 64,
            fault: Fault::None,
            answer_at: None,
        }
    }
}
impl Device {
    /// A key with a PIN, as PIN mode needs.
    pub fn with_pin() -> Self {
        Self {
            pin: true,
            ..Self::default()
        }
    }
}
/// What the fake saw of one request, for the tests' assertions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub owner: isize,
    /// The allowed or excluded credential IDs.
    pub credentials: Vec<Vec<u8>>,
    pub uv: Uv,
}

struct State {
    devices: Vec<Device>,
    plugged: Vec<bool>,
    /// The key the user touches at the next ceremony.
    touching: Option<usize>,
    api: u32,
    /// An operation is running, and whether a cancel reached it.
    busy: bool,
    cancel_hit: bool,
    seen: Vec<Seen>,
    /// Holds the next operation between the worker's check of its cancel
    /// flag and the start of the operation: (reached, release).
    pause: Option<(Sender<()>, Receiver<()>)>,
    counter: u64,
}
/// A set of fake keys behind the `Authenticator` trait (spec §8.9).
pub struct Fake {
    state: Mutex<State>,
    clock: Option<Arc<AtomicU64>>,
}
impl Fake {
    /// No key plugged in, API version 9. `clock` is the test clock the
    /// fake reads for slow answers (spec §8.5); None reads `now_ms`.
    pub fn new(clock: Option<Arc<AtomicU64>>) -> Self {
        std::hint::black_box(MARKER);
        Self {
            state: Mutex::new(State {
                devices: Vec::new(),
                plugged: Vec::new(),
                touching: None,
                api: 9,
                busy: false,
                cancel_hit: false,
                seen: Vec::new(),
                pause: None,
                counter: 0,
            }),
            clock,
        }
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn now(&self) -> u64 {
        match &self.clock {
            Some(clock) => clock.load(Ordering::SeqCst),
            None => crate::crypto::now_ms(),
        }
    }
    /// Plugs in a key; returns its index.
    pub fn plug(&self, device: Device) -> usize {
        let mut s = self.lock();
        assert!(s.devices.len() < 8, "at most 8 keys at once");
        s.devices.push(device);
        s.plugged.push(true);
        s.devices.len() - 1
    }
    pub fn unplug(&self, i: usize) {
        self.lock().plugged[i] = false;
    }
    pub fn replug(&self, i: usize) {
        self.lock().plugged[i] = true;
    }
    /// The key the user touches from the next ceremony on; None: none.
    pub fn touch(&self, i: Option<usize>) {
        self.lock().touching = i;
    }
    pub fn set_api(&self, api: u32) {
        self.lock().api = api;
    }
    /// Changes a key's settings, faults or credentials.
    pub fn device<T>(&self, i: usize, f: impl FnOnce(&mut Device) -> T) -> T {
        f(&mut self.lock().devices[i])
    }
    /// A FIDO reset: every credential on the key is gone, and its PIN.
    pub fn reset(&self, i: usize) {
        self.device(i, |d| {
            d.credentials.clear();
            d.pin = false;
            d.pin_tries = PIN_TRIES;
        });
    }
    /// Puts a resident credential with exactly these values on key `i`
    /// (S23-1 #25), so the pinned fixtures open with the outputs their
    /// script derived. `uv_registered`: its slot saw UV, so the key has a
    /// PIN that Windows asks for even with UV discouraged.
    pub fn import_credential(
        &self,
        i: usize,
        cred_id: &[u8],
        random_uv: &[u8; 32],
        random_nouv: &[u8; 32],
        cred_protect: u8,
        uv_registered: bool,
    ) {
        let created = self.now();
        self.device(i, |d| {
            if uv_registered {
                d.pin = true;
                d.uv_when_discouraged = true;
            }
            d.credentials.push(Credential {
                cred_id: cred_id.to_vec(),
                rp_id_hash: rp_id_hash(),
                user_id: cred_id.to_vec(),
                resident: true,
                random_uv: *random_uv,
                random_nouv: *random_nouv,
                cred_protect,
                created,
            });
        });
    }
    /// What the fake saw of each request so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.lock().seen.clone()
    }
    /// Holds the next operation right before it starts, once the worker
    /// has checked its cancel flag (S45-3 #13): the first channel says it
    /// got there, sending on the second lets it go on.
    pub fn pause_after_check(&self) -> (Receiver<()>, Sender<()>) {
        let (reached, at) = channel();
        let (release, wait) = channel();
        self.lock().pause = Some((reached, wait));
        (at, release)
    }
    /// 32 bytes of the fake's own sequence.
    fn draw(s: &mut State) -> [u8; 32] {
        s.counter += 1;
        Sha256::new()
            .chain_update(MARKER)
            .chain_update(s.counter.to_le_bytes())
            .finalize()
            .into()
    }
    /// Starts an operation as the app's `Authenticator` does: the app's
    /// cancel flag checked right before the call (spec §8.5), the pause
    /// hook, then the touched key, if the user touches one that is plugged
    /// in.
    fn begin(&self, c: &CancelToken, seen: Seen) -> Result<usize, FidoError> {
        c.check()?;
        let pause = self.lock().pause.take();
        if let Some((reached, wait)) = pause {
            let _ = reached.send(());
            let _ = wait.recv();
        }
        let mut s = self.lock();
        s.seen.push(seen);
        s.busy = true;
        s.cancel_hit = false;
        match s.touching {
            Some(i) if s.plugged.get(i) == Some(&true) => Ok(i),
            // Nobody touches a key: the user gives up in Windows' dialog.
            _ => {
                s.busy = false;
                Err(FidoError::Cancelled)
            }
        }
    }
    /// Waits for a slow key's answer in the fake's time; a cancel ends it.
    fn wait(&self, i: usize) -> Result<(), FidoError> {
        loop {
            let at = {
                let s = self.lock();
                if s.cancel_hit {
                    return Err(FidoError::Cancelled);
                }
                s.devices[i].answer_at
            };
            match at {
                Some(at) if self.now() < at => {
                    std::thread::sleep(std::time::Duration::from_millis(1))
                }
                _ => return Ok(()),
            }
        }
    }
    fn end<T>(&self, result: Result<T, FidoError>) -> Result<T, FidoError> {
        let mut s = self.lock();
        s.busy = false;
        if s.cancel_hit {
            s.cancel_hit = false;
            return Err(FidoError::Cancelled);
        }
        result
    }
    /// Whether the user verifies with the PIN in this ceremony; Err when
    /// Windows' PIN dialog ends in a cancel (no PIN, a wrong one, blocked).
    fn verify(d: &mut Device, uv: Uv) -> Result<bool, FidoError> {
        let asks = match uv {
            Uv::Required => true,
            Uv::Discouraged => d.always_uv || (d.pin && d.uv_when_discouraged),
        };
        if !asks {
            return Ok(false);
        }
        if !d.pin || d.pin_tries == 0 {
            return Err(FidoError::Cancelled);
        }
        if !d.pin_right {
            d.pin_tries -= 1;
            return Err(FidoError::Cancelled);
        }
        d.pin_tries = PIN_TRIES;
        Ok(true)
    }
    fn make(&self, i: usize, r: &MakeRequest) -> Result<RawCredential, FidoError> {
        let now = self.now();
        let mut s = self.lock();
        let api = s.api;
        let d = &s.devices[i];
        if d.fault == Fault::StoreFull {
            return Err(FidoError::from_hresult(STORE_FULL));
        }
        if d.credentials.iter().any(|c| r.exclude.contains(&c.cred_id)) {
            return Err(FidoError::Exists);
        }
        let (level, required) = r.cred_protect;
        if required && u32::from(d.cred_protect) < level {
            return Err(FidoError::NoCredProtect);
        }
        let level = level.min(u32::from(d.cred_protect)).max(1) as u8;
        let uv = Self::verify(&mut s.devices[i], r.uv)?;
        let len = s.devices[i].cred_id_len.clamp(16, 1023);
        let mut cred_id = Vec::with_capacity(len);
        while cred_id.len() < len {
            cred_id.extend_from_slice(&Self::draw(&mut s));
        }
        cred_id.truncate(len);
        let (random_uv, random_nouv) = (Self::draw(&mut s), Self::draw(&mut s));
        let d = &mut s.devices[i];
        // The same RP and user ID overwrite a resident credential.
        d.credentials
            .retain(|c| !(c.rp_id_hash == rp_id_hash() && c.user_id == r.user_id));
        d.credentials.push(Credential {
            cred_id: cred_id.clone(),
            rp_id_hash: rp_id_hash(),
            user_id: r.user_id.to_vec(),
            resident: true,
            random_uv,
            random_nouv,
            cred_protect: level,
            created: now,
        });
        let flags = UP | AT | if uv { UV } else { 0 } | flag(d.be, BE) | flag(d.bs, BS);
        Ok(RawCredential {
            version: if api >= 6 { 4 } else { 3 },
            auth_data: [&rp_id_hash()[..], &[flags], &[0, 0, 0, 1], &[0; 16]].concat(),
            cred_id,
            transport: Some(d.transport),
        })
    }
    fn assert(&self, i: usize, r: &AssertRequest) -> Result<RawAssertion, FidoError> {
        let mut s = self.lock();
        let api = s.api;
        let uv = Self::verify(&mut s.devices[i], r.uv)?;
        let fresh = Self::draw(&mut s);
        let d = &s.devices[i];
        // The first allowed credential the key holds and shows: level 3
        // only with UV; levels 1 and 2 with an allow list, which every
        // request has.
        let found = r.allow.iter().find_map(|(id, s1, s2)| {
            d.credentials
                .iter()
                .find(|c| {
                    c.cred_id == *id && c.rp_id_hash == rp_id_hash() && (c.cred_protect < 3 || uv)
                })
                .map(|c| (c, s1, s2))
        });
        // Windows asks for another key, and the user cancels (S45-1 #4).
        let Some((c, salt1, salt2)) = found else {
            return Err(FidoError::Cancelled);
        };
        let random = match d.fault {
            Fault::Nondeterministic => fresh,
            _ if uv => c.random_uv,
            _ => c.random_nouv,
        };
        let output = |salt: &[u8; 32]| {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&random).expect("any key size");
            m.update(salt);
            Zeroizing::new(m.finalize().into_bytes().to_vec())
        };
        let (mut first, mut second) = if d.hmac_secret {
            (Some(output(salt1)), salt2.as_ref().map(output))
        } else {
            (None, None)
        };
        match d.fault {
            Fault::NoOutput => (first, second) = (None, None),
            Fault::ShortOutput => first = first.map(|o| Zeroizing::new(o[..31].to_vec())),
            Fault::ZeroOutput => first = first.map(|_| Zeroizing::new(vec![0; 32])),
            Fault::Swapped if second.is_some() => std::mem::swap(&mut first, &mut second),
            Fault::NoSecond => second = None,
            _ => {}
        }
        let cred_id = match d.fault {
            Fault::Unrequested => [&c.cred_id[..], b"?"].concat(),
            _ => c.cred_id.clone(),
        };
        let mut rp = rp_id_hash();
        if d.fault == Fault::WrongRpId {
            rp[0] ^= 1;
        }
        let flags = UP | flag(uv, UV) | flag(d.be, BE) | flag(d.bs, BS);
        // API 4-5 give a version-3 assertion, with no transport.
        let version = match api {
            ..=5 => 3,
            6 => 4,
            7 => 5,
            _ => 6,
        };
        Ok(RawAssertion {
            version,
            auth_data: [&rp[..], &[flags], &[0, 0, 0, 2]].concat(),
            cred_id,
            first,
            second,
            transport: (version >= 4).then_some(d.transport),
        })
    }
}
fn flag(on: bool, bit: u8) -> u8 {
    if on { bit } else { 0 }
}
impl Authenticator for Fake {
    fn api_version(&self) -> u32 {
        self.lock().api
    }
    fn new_cancel(&self) -> Result<CancelToken, FidoError> {
        let mut s = self.lock();
        let mut id = [0; 16];
        id.copy_from_slice(&Self::draw(&mut s)[..16]);
        Ok(CancelToken::new(id))
    }
    fn make_credential(
        &self,
        r: &MakeRequest,
        c: &CancelToken,
    ) -> Result<RawCredential, FidoError> {
        let i = self.begin(
            c,
            Seen {
                owner: r.owner,
                credentials: r.exclude.clone(),
                uv: r.uv,
            },
        )?;
        let result = self.wait(i).and_then(|()| self.make(i, r));
        self.end(result)
    }
    fn get_assertion(&self, r: &AssertRequest, c: &CancelToken) -> Result<RawAssertion, FidoError> {
        let i = self.begin(
            c,
            Seen {
                owner: r.owner,
                credentials: r.allow.iter().map(|(id, ..)| id.clone()).collect(),
                uv: r.uv,
            },
        )?;
        let result = self.wait(i).and_then(|()| self.assert(i, r));
        self.end(result)
    }
    /// As Windows does: a cancel ends the running operation with
    /// 0x800704C7; with none running it succeeds and is forgotten.
    fn cancel(&self, _c: &CancelToken) {
        let mut s = self.lock();
        if s.busy {
            s.cancel_hit = true;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::super::{Registration, Touch, check_assertion, check_credential, register, salt};
    use super::*;

    fn touch_with(fake: &Fake, req: &AssertRequest) -> Result<Touch, FidoError> {
        let raw = fake.get_assertion(req, &fake.new_cancel()?)?;
        check_assertion(raw, req, false)
    }

    #[test]
    fn a_registered_key_answers_its_seed_and_nothing_else() {
        let fake = Fake::new(None);
        let a = fake.plug(Device::with_pin());
        let b = fake.plug(Device::default());
        let id = [0x31; 16];
        fake.touch(Some(a));
        let key = register(&fake, &id, 1, 1_767_225_600, true, vec![]).unwrap();
        assert!(key.uv && key.cp3 && key.cred_id.len() == 64);
        // The same output for the same salt, also through another request.
        let req = AssertRequest::new(
            5,
            vec![(key.cred_id.clone(), salt(&id, &key.seed), None)],
            true,
        )
        .unwrap();
        let t = touch_with(&fake, &req).unwrap();
        assert_eq!(**t.first, **key.output);
        assert_eq!(t.output_for(&key.seed, &id), Some(&**key.output));
        // Another key holds no credential of the list: Windows asks for
        // another key and the user cancels.
        fake.touch(Some(b));
        assert_eq!(touch_with(&fake, &req).err(), Some(FidoError::Cancelled));
        // Excluded: the key already holds it.
        fake.touch(Some(a));
        assert_eq!(
            register(&fake, &id, 2, 0, true, vec![key.cred_id.clone()]).err(),
            Some(FidoError::Exists)
        );
        // A FIDO reset deletes it.
        fake.reset(a);
        fake.device(a, |d| d.pin = true);
        assert_eq!(touch_with(&fake, &req).err(), Some(FidoError::Cancelled));
        assert!(fake.seen().iter().all(|s| s.owner == 0 || s.owner == 5));
    }

    #[test]
    fn imported_credentials_give_the_recorded_outputs() {
        // The first key of hw_fixtures.json's GOYOKH01 (UV at registration).
        let fake = Fake::new(None);
        let i = fake.plug(Device::default());
        let cred: Vec<u8> = (2..18).collect();
        let random_uv: [u8; 32] = std::array::from_fn(|j| 0x41 ^ j as u8);
        let random_nouv: [u8; 32] = std::array::from_fn(|j| 0x42 ^ j as u8);
        fake.import_credential(i, &cred, &random_uv, &random_nouv, 1, true);
        fake.touch(Some(i));
        let id: [u8; 16] = std::array::from_fn(|j| 0x31 + j as u8);
        let seed: [u8; 32] = std::array::from_fn(|j| 0x13 ^ j as u8);
        let req = AssertRequest::new(0, vec![(cred, salt(&id, &seed), None)], false).unwrap();
        let t = touch_with(&fake, &req).unwrap();
        assert!(t.uv);
        let hex: String = t.first.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "dea4c552db128f0f7146ffae2b8fa371a03e5d7b7792a3c117836d6784e808df"
        );
    }

    #[test]
    fn credprotect_pin_and_flags_behave_as_ctap_and_windows() {
        let fake = Fake::new(None);
        let i = fake.plug(Device::with_pin());
        fake.touch(Some(i));
        let id = [7; 16];
        let key = register(&fake, &id, 1, 0, true, vec![]).unwrap();
        let entry = vec![(key.cred_id.clone(), salt(&id, &key.seed), None)];
        // Level 3 is invisible without UV.
        let no_uv = AssertRequest::new(0, entry.clone(), false).unwrap();
        assert_eq!(touch_with(&fake, &no_uv).err(), Some(FidoError::Cancelled));
        // Wrong PINs block the key after 8.
        fake.device(i, |d| d.pin_right = false);
        let with_uv = AssertRequest::new(0, entry, true).unwrap();
        for _ in 0..8 {
            assert_eq!(
                touch_with(&fake, &with_uv).err(),
                Some(FidoError::Cancelled)
            );
        }
        fake.device(i, |d| d.pin_right = true);
        assert_eq!(
            touch_with(&fake, &with_uv).err(),
            Some(FidoError::Cancelled)
        );
        // A key without credProtect 3 cannot register in PIN mode.
        let old = fake.plug(Device {
            cred_protect: 1,
            pin: true,
            ..Device::default()
        });
        fake.touch(Some(old));
        assert_eq!(
            register(&fake, &id, 2, 0, true, vec![]).err(),
            Some(FidoError::NoCredProtect)
        );
        // Without hmac-secret, the registration's check says so.
        let plain = fake.plug(Device {
            hmac_secret: false,
            ..Device::default()
        });
        fake.touch(Some(plain));
        assert_eq!(
            register(&fake, &id, 2, 0, false, vec![]).err(),
            Some(FidoError::NoHmacSecret)
        );
        // Synced passkeys, other transports, a full store.
        for (device, error) in [
            (
                Device {
                    be: true,
                    ..Device::default()
                },
                FidoError::SyncedPasskey,
            ),
            (
                Device {
                    transport: super::super::HYBRID,
                    ..Device::default()
                },
                FidoError::Transport,
            ),
            (
                Device {
                    fault: Fault::StoreFull,
                    ..Device::default()
                },
                FidoError::StoreFull,
            ),
            (
                Device {
                    fault: Fault::Nondeterministic,
                    ..Device::default()
                },
                FidoError::Nondeterministic,
            ),
        ] {
            let fake = Fake::new(None);
            let i = fake.plug(device);
            fake.touch(Some(i));
            assert_eq!(register(&fake, &id, 1, 0, false, vec![]).err(), Some(error));
        }
        // A plain registration step by step.
        let fake = Fake::new(None);
        fake.touch(Some(fake.plug(Device::default())));
        let (mut reg, make) = Registration::new(&id, 1, 0, false, vec![], 9).unwrap();
        let raw = fake
            .make_credential(&make, &fake.new_cancel().unwrap())
            .unwrap();
        assert!(check_credential(&raw).is_ok());
        reg.made(&raw).unwrap();
        let check = reg.check_request(9).unwrap();
        let raw = fake
            .get_assertion(&check, &fake.new_cancel().unwrap())
            .unwrap();
        assert!(reg.checked(raw, &check).unwrap().is_none());
        let raw = fake
            .get_assertion(&check, &fake.new_cancel().unwrap())
            .unwrap();
        let key = reg.checked(raw, &check).unwrap().unwrap();
        assert!(!key.uv && !key.cp3);
        assert!(fake.seen().iter().all(|s| s.owner == 9));
    }

    #[test]
    fn faults_and_api_versions() {
        let id = [3; 16];
        let fake = Fake::new(None);
        let i = fake.plug(Device::default());
        fake.touch(Some(i));
        let key = register(&fake, &id, 1, 0, false, vec![]).unwrap();
        let (s1, s2) = (salt(&id, &key.seed), salt(&id, &[9; 32]));
        let req = AssertRequest::new(0, vec![(key.cred_id.clone(), s1, Some(s2))], false).unwrap();
        let good = touch_with(&fake, &req).unwrap();
        assert!(good.second.is_some() && good.transport == Some(USB));
        for (fault, error) in [
            (Fault::NoOutput, Some(FidoError::BadAnswer)),
            (Fault::ShortOutput, Some(FidoError::BadAnswer)),
            (Fault::ZeroOutput, Some(FidoError::BadAnswer)),
            (Fault::WrongRpId, Some(FidoError::Unverifiable)),
            (Fault::Unrequested, Some(FidoError::NotRegistered)),
            (Fault::NoSecond, None),
            (Fault::Swapped, None),
        ] {
            fake.device(i, |d| d.fault = fault);
            let t = touch_with(&fake, &req);
            assert_eq!(t.as_ref().err(), error.as_ref(), "{fault:?}");
            if let Ok(t) = t {
                match fault {
                    Fault::NoSecond => assert!(t.second_missing()),
                    // Swapped outputs: only a confirmation touch can tell.
                    _ => assert_eq!(**t.second.unwrap(), **good.first),
                }
            }
        }
        fake.device(i, |d| d.fault = Fault::None);
        // API 4-5: a version-3 assertion with no transport.
        fake.set_api(5);
        assert_eq!(fake.api_version(), 5);
        let t = touch_with(&fake, &req).unwrap();
        assert_eq!(t.transport, None);
        // An unplugged key, or none touched: the user cancels.
        fake.unplug(i);
        assert_eq!(touch_with(&fake, &req).err(), Some(FidoError::Cancelled));
        fake.replug(i);
        fake.touch(None);
        assert_eq!(touch_with(&fake, &req).err(), Some(FidoError::Cancelled));
    }

    #[test]
    fn a_cancel_with_nothing_pending_is_dropped() {
        let clock = Arc::new(AtomicU64::new(0));
        let fake = Arc::new(Fake::new(Some(clock.clone())));
        let i = fake.plug(Device::default());
        fake.touch(Some(i));
        let id = [4; 16];
        let key = register(&*fake, &id, 1, 0, false, vec![]).unwrap();
        let req = AssertRequest::new(
            0,
            vec![(key.cred_id.clone(), salt(&id, &key.seed), None)],
            false,
        )
        .unwrap();
        // Cancelled between the worker's check and the call: Windows forgets
        // it, and the call runs.
        let (at, release) = fake.pause_after_check();
        let worker = {
            let (fake, req) = (fake.clone(), req.clone());
            std::thread::spawn(move || {
                let token = fake.new_cancel().unwrap();
                fake.get_assertion(&req, &token).map(|_| ())
            })
        };
        at.recv().unwrap();
        fake.cancel(&fake.new_cancel().unwrap());
        release.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), Ok(()));
        // A cancel that reached the token before the call: no call at all,
        // as the app's WebAuthn does it (spec §8.5).
        let seen = fake.seen().len();
        let token = fake.new_cancel().unwrap();
        token.cancel();
        assert_eq!(token.check(), Err(FidoError::Cancelled));
        assert_eq!(
            fake.get_assertion(&req, &token).err(),
            Some(FidoError::Cancelled)
        );
        assert_eq!(fake.seen().len(), seen);
        // A slow key answers when the test clock gets there, unless a
        // cancel ends the operation first.
        fake.device(i, |d| d.answer_at = Some(150_000));
        let worker = {
            let (fake, req) = (fake.clone(), req.clone());
            std::thread::spawn(move || {
                let token = fake.new_cancel().unwrap();
                fake.get_assertion(&req, &token).map(|_| ())
            })
        };
        clock.store(150_000, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), Ok(()));
        fake.device(i, |d| d.answer_at = Some(300_000));
        let worker = {
            let (fake, req) = (fake.clone(), req.clone());
            std::thread::spawn(move || {
                let token = fake.new_cancel().unwrap();
                fake.get_assertion(&req, &token).map(|_| ())
            })
        };
        while !fake.lock().busy {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        fake.cancel(&fake.new_cancel().unwrap());
        assert_eq!(worker.join().unwrap(), Err(FidoError::Cancelled));
    }
}
