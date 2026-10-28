//! FIDO2 security keys (spec v3 §8): what the vault asks of a key, the
//! checks of what comes back, and the `Authenticator` trait behind which
//! Windows' WebAuthn API (the app's webauthn.rs) and the fake of the tests
//! answer. Only the security-key build compiles this file. Every check is a
//! pure function over copied fields, and every hmac-secret output lives in
//! a zeroized box for the flow that asked for it.
use crate::crypto::{self, Result, ct_eq};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

#[cfg(debug_assertions)]
pub mod fake;

/// The relying party of every credential, the same forever (spec §8.3).
pub const RP_ID: &str = "goyo-vault.invalid";
pub const RP_NAME: &str = "Goyo Vault";
/// The origin the client data names; nobody verifies it.
const ORIGIN: &str = "https://goyo-vault.invalid";
/// Windows' own limit for one ceremony.
pub const TIMEOUT_MS: u32 = 120_000;
/// The salts go to the key as they are: Windows hashes nothing more, so any
/// CTAP client reproduces the outputs (spec §3.2).
pub const HMAC_SECRET_VALUES_FLAG: u32 = 0x0010_0000;
/// A user cancel, a timeout or the app's cancel.
pub const E_CANCELLED: i32 = 0x8007_04C7_u32 as i32;
/// The key already holds a credential of the exclude list.
pub const NTE_EXISTS: i32 = 0x8009_000F_u32 as i32;
/// A full store of discoverable credentials. A placeholder with the
/// customer bit set (never a Windows code) until a real key records the
/// HRESULT (spec §16-18); the fake fails with it.
pub const STORE_FULL: i32 = 0x2000_0028;
/// `dwUsedTransport` values.
pub const USB: u32 = 0x01;
pub const NFC: u32 = 0x02;
pub const BLE: u32 = 0x04;
pub const INTERNAL: u32 = 0x10;
pub const HYBRID: u32 = 0x20;
/// Authenticator data flags.
pub const UP: u8 = 0x01;
pub const UV: u8 = 0x04;
pub const BE: u8 = 0x08;
pub const BS: u8 = 0x10;
/// Attested credential data follows (a MakeCredential's authenticator data).
pub const AT: u8 = 0x40;

/// The texts of spec §8.7; Windows' own text is never shown.
pub const CANCELLED: &str = "보안 키 확인을 취소했거나 시간이 지났습니다.";
pub const EXISTS: &str = "이 보안 키는 이미 이 금고에 등록되어 있습니다. 다른 키를 연결하세요.";
/// S-KEYSTORE-FULL.
pub const KEYSTORE_FULL: &str = "이 보안 키에 등록할 자리가 다 찼을 수 있습니다. 쓰지 않는 등록(뺀 키, 실패한 등록, 쓰지 않는 웹사이트 패스키)을 키 제조사의 관리 도구로 지우거나 다른 키를 쓰세요.";
pub const NO_HMAC_SECRET: &str = "이 보안 키는 hmac-secret(FIDO2 확장)을 지원하지 않습니다.";
pub const NO_CRED_PROTECT: &str = "이 보안 키는 PIN 필수 보호(credProtect)를 지원하지 않습니다. 'PIN도 사용'을 끄거나 다른 키를 쓰세요.";
pub const TRANSPORT: &str = "USB·NFC 보안 키만 쓸 수 있습니다(Windows Hello·휴대폰 제외).";
/// S-SYNCEDPASSKEY.
pub const SYNCED_PASSKEY: &str =
    "클라우드로 동기화되는 패스키는 쓸 수 없습니다. USB·NFC 보안 키만 됩니다.";
/// S-BADANSWER.
pub const BAD_ANSWER: &str = "보안 키 응답이 올바르지 않습니다. 다른 키를 쓰거나 키를 확인하세요.";
pub const UNVERIFIABLE: &str = "보안 키 응답을 확인할 수 없습니다.";
pub const NOT_REGISTERED: &str = "이 보안 키는 이 열쇠 파일에 등록되어 있지 않습니다.";
pub const UV_CHANGED: &str = "이 보안 키의 PIN 확인 여부가 등록 때와 다릅니다(키의 PIN 설정 변경 등). 키 설정을 되돌리거나, 다른 등록 키로 연 뒤 이 키를 빼고 다시 추가하세요.";
/// S-NONDETERMINISTIC.
pub const NONDETERMINISTIC: &str = "이 보안 키가 같은 값을 다시 돌려주지 않아 저장하지 않았습니다.";
/// S-NOAPI.
pub const NO_API: &str =
    "이 Windows에서는 보안 키(WebAuthn API 4 이상)를 쓸 수 없습니다. Windows를 업데이트하세요.";
/// Any other failure, filled with the HRESULT in hex.
pub const OTHER: &str = "보안 키 작업 실패 (코드 0x{hr:08X}).";
const SELF_TEST_FAILED: &str = "보안 키 자체 시험에 실패했습니다.";

/// Why a ceremony or its answer failed (spec §8.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FidoError {
    /// 0x800704C7: the user cancelled, the time ran out, or the app
    /// cancelled.
    Cancelled,
    /// The key already holds a credential of the exclude list.
    Exists,
    StoreFull,
    /// No or a short hmac-secret output at a registration's check.
    NoHmacSecret,
    /// PIN mode, and the key cannot require credProtect 3.
    NoCredProtect,
    /// Not USB or NFC: Windows Hello, a phone, BLE.
    Transport,
    /// A passkey that syncs (BE or BS set).
    SyncedPasskey,
    BadAnswer,
    /// A wrong rpIdHash, no UP or a malformed answer.
    Unverifiable,
    /// Windows answered for a credential that was not asked for.
    NotRegistered,
    UvChanged,
    Nondeterministic,
    /// WebAuthn API below 4.
    NoApi,
    /// Any other HRESULT.
    Other(i32),
}
impl FidoError {
    /// The error an HRESULT stands for.
    pub fn from_hresult(hr: i32) -> Self {
        match hr {
            E_CANCELLED => Self::Cancelled,
            NTE_EXISTS => Self::Exists,
            STORE_FULL => Self::StoreFull,
            _ => Self::Other(hr),
        }
    }
    /// The text to show; for `Other` a template for the code.
    pub fn text(self) -> &'static str {
        match self {
            Self::Cancelled => CANCELLED,
            Self::Exists => EXISTS,
            Self::StoreFull => KEYSTORE_FULL,
            Self::NoHmacSecret => NO_HMAC_SECRET,
            Self::NoCredProtect => NO_CRED_PROTECT,
            Self::Transport => TRANSPORT,
            Self::SyncedPasskey => SYNCED_PASSKEY,
            Self::BadAnswer => BAD_ANSWER,
            Self::Unverifiable => UNVERIFIABLE,
            Self::NotRegistered => NOT_REGISTERED,
            Self::UvChanged => UV_CHANGED,
            Self::Nondeterministic => NONDETERMINISTIC,
            Self::NoApi => NO_API,
            Self::Other(_) => OTHER,
        }
    }
    /// Whether the app starts its growing retry delay (spec §8.7).
    pub fn delays(self) -> bool {
        matches!(self, Self::NotRegistered | Self::UvChanged)
    }
}

/// The user verification a request asks for: required in PIN mode, else
/// discouraged; never "preferred" (spec §8.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Uv {
    Required = 1,
    Discouraged = 3,
}
impl Uv {
    pub fn of(pin: bool) -> Self {
        if pin {
            Self::Required
        } else {
            Self::Discouraged
        }
    }
}

/// The salt sent for a key's seed (spec §3.2): Windows' own PRF hashing of
/// the input, so the flag that passes it raw changes nothing a CTAP client
/// could not reproduce.
pub fn salt(vault_id: &[u8; 16], seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [
        &b"WebAuthn PRF\0"[..],
        b"goyo-vault/v2/hmac-salt\0",
        vault_id,
        seed,
    ] {
        h.update(part);
    }
    h.finalize().into()
}
/// SHA-256 of the RP ID, which every answer's authenticator data starts
/// with.
pub fn rp_id_hash() -> [u8; 32] {
    Sha256::digest(RP_ID.as_bytes()).into()
}

/// One ceremony's cancel. The app's runner sets the flag before it asks the
/// authenticator to cancel; the worker checks it right before its one
/// Windows call (spec §8.5).
pub struct CancelToken {
    /// Windows' cancellation GUID, as its 16 bytes.
    pub id: [u8; 16],
    cancelled: AtomicBool,
}
impl CancelToken {
    pub fn new(id: [u8; 16]) -> Self {
        Self {
            id,
            cancelled: AtomicBool::new(false),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// A registration (spec §8.3 MakeCredential). The builders of webauthn.rs
/// turn it into Windows' option structs.
#[derive(Clone, Debug)]
pub struct MakeRequest {
    /// The main window: Windows' dialog belongs to it.
    pub owner: isize,
    /// Fresh for every registration, never reused.
    pub user_id: [u8; 32],
    /// `goyo-<TAG>-<N>-<STAMP>`.
    pub name: String,
    /// `Goyo Vault <TAG> key <N> <STAMP>`.
    pub display_name: String,
    /// The client data JSON; Windows hashes it and nobody verifies it.
    pub client_data: Vec<u8>,
    pub uv: Uv,
    /// credProtect 3 with `bRequireCredProtect` in PIN mode, else 2
    /// without.
    pub cred_protect: (u32, bool),
    /// Every credential the key must not register again.
    pub exclude: Vec<Vec<u8>>,
}
/// An allowed credential: its ID, the salt of its seed, and an optional
/// second salt.
pub type Allowed = (Vec<u8>, [u8; 32], Option<[u8; 32]>);
/// An assertion (spec §8.3 GetAssertion): the allowed credentials, each
/// with the salt of its seed and an optional second salt.
#[derive(Clone, Debug)]
pub struct AssertRequest {
    pub owner: isize,
    pub allow: Vec<Allowed>,
    pub uv: Uv,
    pub client_data: Vec<u8>,
}
impl AssertRequest {
    /// A request with a fresh challenge.
    pub fn new(owner: isize, allow: Vec<Allowed>, pin: bool) -> Result<Self> {
        Ok(Self {
            owner,
            allow,
            uv: Uv::of(pin),
            client_data: client_data("webauthn.get")?,
        })
    }
}
/// The client data of a ceremony with a fresh challenge.
fn client_data(kind: &str) -> Result<Vec<u8>> {
    let challenge = crypto::random::<32>()?;
    Ok(format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}",
        base64url(challenge.as_slice())
    )
    .into_bytes())
}
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// What MakeCredential gave, copied out of Windows' struct.
#[derive(Clone, Debug)]
pub struct RawCredential {
    /// The struct's `dwVersion`.
    pub version: u32,
    pub cred_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    /// `dwUsedTransport` (version 3 and later).
    pub transport: Option<u32>,
}
/// What GetAssertion gave, copied out of Windows' struct; the outputs are
/// zeroized on drop.
pub struct RawAssertion {
    pub version: u32,
    pub auth_data: Vec<u8>,
    pub cred_id: Vec<u8>,
    /// `pbFirst`, as long as `cbFirst` said; None without `pHmacSecret` or
    /// with a null `pbFirst`.
    pub first: Option<Zeroizing<Vec<u8>>>,
    /// `pbSecond`; None when it is null or `cbSecond` is 0.
    pub second: Option<Zeroizing<Vec<u8>>>,
    /// `dwUsedTransport` (version 4 and later).
    pub transport: Option<u32>,
}

/// One answered assertion, checked (spec §8.3, §8.4): which credential
/// answered, its flags and the hmac-secret outputs for the salts asked.
/// Lives only in the frame of the flow that asked for it.
pub struct Touch {
    pub cred_id: Vec<u8>,
    pub uv: bool,
    /// The authenticator data flags.
    pub flags: u8,
    /// None for a version-3 assertion (API 4-5), which states none.
    pub transport: Option<u32>,
    pub first: Box<Zeroizing<[u8; 32]>>,
    pub second: Option<Box<Zeroizing<[u8; 32]>>>,
    /// The salts each output answers.
    salts: ([u8; 32], Option<[u8; 32]>),
}
impl Touch {
    /// The output for a key file whose slot holds `seed`: None when this
    /// touch answered no salt of that seed (another seed, or a second
    /// output Windows did not return).
    pub fn output_for(&self, seed: &[u8; 32], vault_id: &[u8; 16]) -> Option<&[u8; 32]> {
        let wanted = salt(vault_id, seed);
        if self.salts.0 == wanted {
            return Some(&**self.first);
        }
        match (&self.salts.1, &self.second) {
            (Some(second), Some(output)) if *second == wanted => Some(&***output),
            _ => None,
        }
    }
    /// A second salt was sent and no second output came back: the flow
    /// adds one single-salt ceremony for that seed (spec §8.3).
    pub fn second_missing(&self) -> bool {
        self.salts.1.is_some() && self.second.is_none()
    }
}

/// The checks of a new credential (spec §8.4).
pub fn check_credential(raw: &RawCredential) -> std::result::Result<(), FidoError> {
    let data = &raw.auth_data;
    if !(1..=1023).contains(&raw.cred_id.len())
        || data.len() < 37
        || data[..32] != rp_id_hash()
        || data[32] & UP == 0
    {
        return Err(FidoError::Unverifiable);
    }
    if data[32] & (BE | BS) != 0 {
        return Err(FidoError::SyncedPasskey);
    }
    // Version 3 and later state the transport: only USB and NFC.
    if raw.version >= 3 && !matches!(raw.transport, Some(USB | NFC)) {
        return Err(FidoError::Transport);
    }
    Ok(())
}

/// The checks of an assertion against what was asked (spec §8.4), into a
/// `Touch`. `registration`: a registration's check of the new credential,
/// where a missing output means the key lacks hmac-secret.
pub fn check_assertion(
    raw: RawAssertion,
    req: &AssertRequest,
    registration: bool,
) -> std::result::Result<Touch, FidoError> {
    let RawAssertion {
        version,
        auth_data,
        cred_id,
        first,
        second,
        transport,
    } = raw;
    let mut asked = req.allow.iter().filter(|(id, ..)| *id == cred_id);
    let (Some((_, salt1, salt2)), None) = (asked.next(), asked.next()) else {
        return Err(FidoError::NotRegistered);
    };
    let missing = if registration {
        FidoError::NoHmacSecret
    } else {
        FidoError::BadAnswer
    };
    let first = match first {
        Some(out) if version >= 3 && out.len() == 32 => boxed32(&out),
        _ => return Err(missing),
    };
    if ct_eq(first.as_slice(), &[0; 32]) {
        return Err(FidoError::BadAnswer);
    }
    // A missing second output is the fallback of spec §8.3, never an
    // error; one that was not asked for is dropped (and zeroized).
    let second = match (salt2, second) {
        (Some(_), Some(out)) if !out.is_empty() => {
            if out.len() != 32 || ct_eq(&out, &[0; 32]) {
                return Err(FidoError::BadAnswer);
            }
            Some(boxed32(&out))
        }
        _ => None,
    };
    if auth_data.len() < 37 || auth_data[..32] != rp_id_hash() || auth_data[32] & UP == 0 {
        return Err(FidoError::Unverifiable);
    }
    let flags = auth_data[32];
    if flags & (BE | BS) != 0 {
        return Err(FidoError::SyncedPasskey);
    }
    // Version 4 and later state the transport; version 3 has none, and its
    // credential's transport was checked at its registration.
    let transport = if version >= 4 {
        match transport {
            Some(t @ (USB | NFC)) => Some(t),
            _ => return Err(FidoError::Transport),
        }
    } else {
        None
    };
    let uv = flags & UV != 0;
    if req.uv == Uv::Required && !uv {
        return Err(FidoError::UvChanged);
    }
    Ok(Touch {
        cred_id,
        uv,
        flags,
        transport,
        first,
        second,
        salts: (*salt1, *salt2),
    })
}
fn boxed32(src: &[u8]) -> Box<Zeroizing<[u8; 32]>> {
    let mut out = Box::new(Zeroizing::new([0u8; 32]));
    out.copy_from_slice(&src[..32]);
    out
}

/// What the app asks of a security key (spec §8.5). Each method is one
/// Windows call; nothing here waits on the UI thread.
pub trait Authenticator: Send + Sync {
    fn api_version(&self) -> u32;
    fn new_cancel(&self) -> std::result::Result<CancelToken, FidoError>;
    fn make_credential(
        &self,
        r: &MakeRequest,
        c: &CancelToken,
    ) -> std::result::Result<RawCredential, FidoError>;
    fn get_assertion(
        &self,
        r: &AssertRequest,
        c: &CancelToken,
    ) -> std::result::Result<RawAssertion, FidoError>;
    fn cancel(&self, c: &CancelToken);
}

/// A registered key (spec §8.3): what its slot record states and GA #2's
/// output for its seed. Zeroized on drop.
pub struct NewKey {
    pub cred_id: Vec<u8>,
    pub seed: [u8; 32],
    /// UV observed at registration.
    pub uv: bool,
    /// Registered with credProtect 3, required.
    pub cp3: bool,
    pub output: Box<Zeroizing<[u8; 32]>>,
    /// Unix seconds, as its `<STAMP>` shows them.
    pub registered: u64,
}
/// A registration between its three ceremonies (spec §8.3): MakeCredential,
/// then two GetAssertions that must give the same output. The flow keeps it
/// in its frame; the outputs are zeroized on drop.
pub struct Registration {
    vault_id: [u8; 16],
    pub seed: [u8; 32],
    pub registered: u64,
    pub pin: bool,
    cred_id: Option<Vec<u8>>,
    /// GA #1's output and UV.
    first: Option<(Box<Zeroizing<[u8; 32]>>, bool)>,
}
impl Registration {
    /// Step 1: the seed, drawn before MakeCredential, and its request.
    /// `registered` is the time its name shows, taken once.
    pub fn new(
        vault_id: &[u8; 16],
        number: u8,
        registered: u64,
        pin: bool,
        exclude: Vec<Vec<u8>>,
        owner: isize,
    ) -> Result<(Self, MakeRequest)> {
        let seed = *crypto::random::<32>()?;
        let user_id = *crypto::random::<32>()?;
        let tag: String = vault_id[..4].iter().map(|b| format!("{b:02X}")).collect();
        let stamp = stamp(registered);
        let request = MakeRequest {
            owner,
            user_id,
            name: format!("goyo-{tag}-{number}-{stamp}"),
            display_name: format!("Goyo Vault {tag} key {number} {stamp}"),
            client_data: client_data("webauthn.create")?,
            uv: Uv::of(pin),
            cred_protect: if pin { (3, true) } else { (2, false) },
            exclude,
        };
        let registration = Self {
            vault_id: *vault_id,
            seed,
            registered,
            pin,
            cred_id: None,
            first: None,
        };
        Ok((registration, request))
    }
    /// Step 2: MakeCredential's answer.
    pub fn made(&mut self, raw: &RawCredential) -> std::result::Result<(), FidoError> {
        check_credential(raw)?;
        self.cred_id = Some(raw.cred_id.clone());
        Ok(())
    }
    /// The request of step 3 or 4: the new credential alone, with its salt.
    pub fn check_request(&self, owner: isize) -> Result<AssertRequest> {
        let cred_id = self.cred_id.clone().ok_or(UNVERIFIABLE)?;
        AssertRequest::new(
            owner,
            vec![(cred_id, salt(&self.vault_id, &self.seed), None)],
            self.pin,
        )
    }
    /// The answer of step 3 (None back) or of step 4, which must repeat
    /// step 3's output and UV: the new key.
    pub fn checked(
        &mut self,
        raw: RawAssertion,
        req: &AssertRequest,
    ) -> std::result::Result<Option<NewKey>, FidoError> {
        let touch = check_assertion(raw, req, true)?;
        let Some((first, uv)) = self.first.take() else {
            self.first = Some((touch.first, touch.uv));
            return Ok(None);
        };
        if !ct_eq(first.as_slice(), touch.first.as_slice()) || uv != touch.uv {
            return Err(FidoError::Nondeterministic);
        }
        Ok(Some(NewKey {
            cred_id: touch.cred_id,
            seed: self.seed,
            uv,
            cp3: self.pin,
            output: touch.first,
            registered: self.registered,
        }))
    }
}
/// The three calls of a registration one after the other, each with its
/// own cancel token: for the library's tests and flows that run no
/// ceremony of their own. The app runs each as its own ceremony.
pub fn register(
    auth: &dyn Authenticator,
    vault_id: &[u8; 16],
    number: u8,
    registered: u64,
    pin: bool,
    exclude: Vec<Vec<u8>>,
) -> std::result::Result<NewKey, FidoError> {
    let other = |_| FidoError::Other(0);
    let (mut reg, request) =
        Registration::new(vault_id, number, registered, pin, exclude, 0).map_err(other)?;
    let raw = auth.make_credential(&request, &auth.new_cancel()?)?;
    reg.made(&raw)?;
    loop {
        let request = reg.check_request(0).map_err(other)?;
        let raw = auth.get_assertion(&request, &auth.new_cancel()?)?;
        if let Some(key) = reg.checked(raw, &request)? {
            return Ok(key);
        }
    }
}
/// `YYYYMMDD-HHMMSS` in UTC.
pub(crate) fn stamp(secs: u64) -> String {
    let days = secs / 86_400;
    let rest = secs % 86_400;
    // Days to the civil date (Howard Hinnant's algorithm), from 1970-01-01.
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
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// The hmac-salt vector and the security-key constructions of spec
/// §14.1-2, pinned from an independent Python implementation. No Argon2.
/// The lib's tests run it; `--self-check` runs it in this build only from
/// stage 5, with its own self-check line (§8.8).
pub fn self_test() -> Result<()> {
    let id: [u8; 16] = std::array::from_fn(|i| i as u8);
    let seed: [u8; 32] = std::array::from_fn(|i| 0x20 + i as u8);
    let hex: String = salt(&id, &seed)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let ok = ct_eq(
        hex.as_bytes(),
        b"488aab95a176250dcd73d41f3b4d9a7bbd8442abe031a32ec177fba27826b4b1",
    ) & crate::vault::keyfile::inbox::self_test();
    if ok { Ok(()) } else { Err(SELF_TEST_FAILED) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(cred: &[u8], s1: u8, s2: Option<u8>) -> AssertRequest {
        AssertRequest::new(
            7,
            vec![
                (vec![9; 20], [1; 32], None),
                (cred.to_vec(), [s1; 32], s2.map(|s| [s; 32])),
            ],
            false,
        )
        .unwrap()
    }
    fn auth_data(flags: u8) -> Vec<u8> {
        [&rp_id_hash()[..], &[flags], &[0, 0, 0, 1]].concat()
    }
    fn answer(cred: &[u8], flags: u8, version: u32) -> RawAssertion {
        RawAssertion {
            version,
            auth_data: auth_data(flags),
            cred_id: cred.to_vec(),
            first: Some(Zeroizing::new(vec![0x11; 32])),
            second: Some(Zeroizing::new(vec![0x22; 32])),
            transport: (version >= 4).then_some(USB),
        }
    }

    #[test]
    fn the_salt_and_the_constructions_match_the_pinned_vectors() {
        self_test().unwrap();
        assert_ne!(salt(&[0; 16], &[0; 32]), salt(&[1; 16], &[0; 32]));
        assert_ne!(salt(&[0; 16], &[0; 32]), salt(&[0; 16], &[1; 32]));
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url(b"any carnal pleas"), "YW55IGNhcm5hbCBwbGVhcw");
        let data = String::from_utf8(client_data("webauthn.get").unwrap()).unwrap();
        assert!(data.starts_with("{\"type\":\"webauthn.get\",\"challenge\":\""));
        assert!(
            data.ends_with("\",\"origin\":\"https://goyo-vault.invalid\",\"crossOrigin\":false}")
        );
        // 32 bytes: 43 characters of the URL alphabet, no padding.
        let challenge = &data[36..data.find("\",\"origin").unwrap()];
        assert_eq!(challenge.len(), 43);
        assert!(
            challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn stamps_are_utc_civil_times() {
        assert_eq!(stamp(0), "19700101-000000");
        assert_eq!(stamp(1_767_225_600), "20260101-000000");
        assert_eq!(stamp(951_782_399), "20000228-235959");
        assert_eq!(stamp(951_782_400), "20000229-000000");
        assert_eq!(stamp(4_102_444_799), "20991231-235959");
        let (_, r) = Registration::new(&[0xab; 16], 3, 1_767_225_601, true, vec![], 42).unwrap();
        assert_eq!(r.name, "goyo-ABABABAB-3-20260101-000001");
        assert_eq!(r.display_name, "Goyo Vault ABABABAB key 3 20260101-000001");
        assert_eq!(
            (r.owner, r.uv, r.cred_protect),
            (42, Uv::Required, (3, true))
        );
        let (_, r) = Registration::new(&[0xab; 16], 3, 0, false, vec![], 42).unwrap();
        assert_eq!((r.uv, r.cred_protect), (Uv::Discouraged, (2, false)));
    }

    #[test]
    fn assertions_are_checked_field_by_field() {
        let cred = [5u8; 16];
        let req = allow(&cred, 3, Some(4));
        let touch = check_assertion(answer(&cred, UP, 4), &req, false).unwrap();
        assert_eq!(
            (touch.uv, touch.transport, touch.flags),
            (false, Some(USB), UP)
        );
        assert_eq!(**touch.first, [0x11; 32]);
        assert_eq!(touch.second.as_deref().map(|s| **s), Some([0x22; 32]));
        assert!(!touch.second_missing());
        // A version-3 assertion states no transport: none is checked.
        let touch = check_assertion(answer(&cred, UP | UV, 3), &req, false).unwrap();
        assert_eq!((touch.uv, touch.transport), (true, None));
        type Change = fn(&mut RawAssertion);
        let cases: [(Change, FidoError); 14] = [
            (|a| a.cred_id = vec![6; 16], FidoError::NotRegistered),
            (|a| a.first = None, FidoError::BadAnswer),
            (
                |a| a.first = Some(Zeroizing::new(vec![1; 31])),
                FidoError::BadAnswer,
            ),
            (
                |a| a.first = Some(Zeroizing::new(vec![0; 32])),
                FidoError::BadAnswer,
            ),
            (|a| a.version = 2, FidoError::BadAnswer),
            (
                |a| a.second = Some(Zeroizing::new(vec![1; 31])),
                FidoError::BadAnswer,
            ),
            (
                |a| a.second = Some(Zeroizing::new(vec![0; 32])),
                FidoError::BadAnswer,
            ),
            (|a| a.auth_data[0] ^= 1, FidoError::Unverifiable),
            (|a| a.auth_data.truncate(36), FidoError::Unverifiable),
            (|a| a.auth_data[32] = UV, FidoError::Unverifiable),
            (|a| a.auth_data[32] |= BE, FidoError::SyncedPasskey),
            (|a| a.auth_data[32] |= BS, FidoError::SyncedPasskey),
            (|a| a.transport = Some(INTERNAL), FidoError::Transport),
            (|a| a.transport = None, FidoError::Transport),
        ];
        for (i, (change, error)) in cases.into_iter().enumerate() {
            let mut a = answer(&cred, UP, 4);
            change(&mut a);
            assert_eq!(
                check_assertion(a, &req, false).err(),
                Some(error),
                "case {i}"
            );
        }
        for t in [BLE, HYBRID, USB | NFC, 0] {
            let mut a = answer(&cred, UP, 5);
            a.transport = Some(t);
            assert_eq!(
                check_assertion(a, &req, false).err(),
                Some(FidoError::Transport)
            );
        }
        let mut a = answer(&cred, UP, 4);
        a.transport = Some(NFC);
        assert!(check_assertion(a, &req, false).is_ok());
        // At a registration's check a missing output means no hmac-secret.
        let mut a = answer(&cred, UP, 4);
        a.first = None;
        assert_eq!(
            check_assertion(a, &req, true).err(),
            Some(FidoError::NoHmacSecret)
        );
        // PIN mode needs UV.
        let mut pin = req.clone();
        pin.uv = Uv::Required;
        assert_eq!(
            check_assertion(answer(&cred, UP, 4), &pin, false).err(),
            Some(FidoError::UvChanged)
        );
        assert!(check_assertion(answer(&cred, UP | UV, 4), &pin, false).is_ok());
        // A missing second output is no error: the touch says so.
        for second in [None, Some(Zeroizing::new(vec![]))] {
            let mut a = answer(&cred, UP, 4);
            a.second = second;
            let touch = check_assertion(a, &req, false).unwrap();
            assert!(touch.second.is_none() && touch.second_missing());
        }
        // One that was not asked for is dropped.
        let touch = check_assertion(answer(&cred, UP, 4), &allow(&cred, 3, None), false).unwrap();
        assert!(touch.second.is_none() && !touch.second_missing());
        // Each output answers its own seed's salt only.
        let id = [8; 16];
        let (seed1, seed2) = ([1; 32], [2; 32]);
        let req = AssertRequest::new(
            0,
            vec![(cred.to_vec(), salt(&id, &seed1), Some(salt(&id, &seed2)))],
            false,
        )
        .unwrap();
        let touch = check_assertion(answer(&cred, UP, 4), &req, false).unwrap();
        assert_eq!(touch.output_for(&seed1, &id), Some(&[0x11; 32]));
        assert_eq!(touch.output_for(&seed2, &id), Some(&[0x22; 32]));
        assert_eq!(touch.output_for(&[3; 32], &id), None);
        assert_eq!(touch.output_for(&seed1, &[9; 16]), None);
        // Two allowed entries for one credential cannot be told apart.
        let mut twice = req.clone();
        twice.allow.push(twice.allow[0].clone());
        assert_eq!(
            check_assertion(answer(&cred, UP, 4), &twice, false).err(),
            Some(FidoError::NotRegistered)
        );
    }

    #[test]
    fn credentials_are_checked_field_by_field() {
        let good = RawCredential {
            version: 3,
            cred_id: vec![1; 64],
            auth_data: auth_data(UP | AT),
            transport: Some(NFC),
        };
        assert!(check_credential(&good).is_ok());
        type Change = fn(&mut RawCredential);
        let cases: [(Change, FidoError); 9] = [
            (|c| c.cred_id.clear(), FidoError::Unverifiable),
            (|c| c.cred_id = vec![1; 1024], FidoError::Unverifiable),
            (|c| c.auth_data[31] ^= 1, FidoError::Unverifiable),
            (|c| c.auth_data[32] = AT, FidoError::Unverifiable),
            (|c| c.auth_data[32] |= BE, FidoError::SyncedPasskey),
            (|c| c.auth_data[32] |= BS, FidoError::SyncedPasskey),
            (|c| c.transport = Some(INTERNAL), FidoError::Transport),
            (|c| c.transport = Some(HYBRID), FidoError::Transport),
            (|c| c.transport = None, FidoError::Transport),
        ];
        for (i, (change, error)) in cases.into_iter().enumerate() {
            let mut c = good.clone();
            change(&mut c);
            assert_eq!(check_credential(&c).err(), Some(error), "case {i}");
        }
        assert_eq!(FidoError::from_hresult(E_CANCELLED).text(), CANCELLED);
        assert_eq!(FidoError::from_hresult(NTE_EXISTS), FidoError::Exists);
        assert_eq!(FidoError::from_hresult(STORE_FULL), FidoError::StoreFull);
        assert_eq!(FidoError::from_hresult(5), FidoError::Other(5));
        assert!(FidoError::UvChanged.delays() && !FidoError::BadAnswer.delays());
    }
}
