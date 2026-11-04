//! The multi-step flows of stage 4, in Rust between their JNI calls: a new
//! vault (its provision, the password and the keys registered so far) and
//! a key added to an open vault (its Reauth and the new key). Kotlin only
//! runs the YubiKey ceremonies each step states and hands back what the
//! key returned; every check and every decision is the lib's. A flow is
//! dropped (and with it every secret it holds, zeroized) when it ends,
//! fails for good, or the app locks.
use crate::{reg, text};
use goyo_vault::{
    clock, fido,
    vault::{self, Change, Consent, Provision, Reauth, Rekeyed, Session},
};
use std::path::Path;
use zeroize::Zeroizing;

/// One registration between its ceremonies.
pub struct Reg {
    reg: fido::Registration,
    check: Option<fido::AssertRequest>,
    /// The request as the lib stated it (the tests' fake runs it).
    #[cfg(test)]
    make: fido::MakeRequest,
}
impl Reg {
    fn start(
        vault_id: &[u8; 16],
        number: u8,
        exclude: Vec<Vec<u8>>,
    ) -> Result<(Self, Vec<u8>), String> {
        let now = clock::now().map_err(str::to_owned)?;
        let (reg, make) =
            fido::Registration::new(vault_id, number, now, exclude, 0).map_err(text)?;
        let wire = reg::encode_make(&make).map_err(str::to_owned)?;
        Ok((
            Self {
                reg,
                check: None,
                #[cfg(test)]
                make,
            },
            wire,
        ))
    }
    /// MakeCredential's answer: the check request (one GetAssertion of the
    /// new credential with its salt).
    fn made(&mut self, auth_data: &[u8], transport: u32) -> Result<fido::AssertRequest, String> {
        let raw = reg::made(auth_data, transport).map_err(str::to_owned)?;
        self.reg.made(&raw).map_err(crate::fido_text)?;
        let check = self.reg.check_request(0).map_err(text)?;
        self.check = Some(check.clone());
        Ok(check)
    }
    fn checked(&mut self, raw: fido::RawAssertion) -> Result<fido::NewKey, String> {
        let check = self.check.take().ok_or(fido::UNVERIFIABLE)?;
        match self.reg.checked(raw, &check).map_err(crate::fido_text)? {
            Some(key) => Ok(key),
            None => Err(fido::NONDETERMINISTIC.to_owned()),
        }
    }
}

/// A new vault (spec §9.2 "Create", "Create with keys").
pub struct Creating {
    provision: Provision,
    password: Zeroizing<String>,
    keys: Vec<fido::NewKey>,
    reg: Option<Reg>,
}
/// A key added to the open vault `session` (spec §9.2 "Add key").
pub struct Adding {
    pub session: jni::sys::jlong,
    password: Zeroizing<String>,
    override_gate: bool,
    touch_request: fido::AssertRequest,
    reauth: Option<Reauth>,
    vault_id: [u8; 16],
    number: u8,
    exclude: Vec<Vec<u8>>,
    reg: Option<Reg>,
    key: Option<fido::NewKey>,
}
pub enum Flow {
    Create(Box<Creating>),
    AddKey(Box<Adding>),
}

/// At most this many keys in a new vault, as the PC (8 slots).
pub const MAX_KEYS: usize = 8;

impl Creating {
    /// The password is checked against the PC's policy first, and the
    /// anchor this vault's line goes to must be writable before any
    /// registration (spec §5.9).
    pub fn new(password: Zeroizing<String>) -> Result<Self, String> {
        vault::password_policy(&password).map_err(text)?;
        let provision = Provision::new().map_err(text)?;
        provision.check_anchor().map_err(text)?;
        Ok(Self {
            provision,
            password,
            keys: Vec::new(),
            reg: None,
        })
    }
    pub fn tag(&self) -> String {
        self.provision.tag()
    }
    /// Writes the new vault: with the keys registered (PIN mode, every key
    /// paired with every other) or, with none and `with_keys` false,
    /// password-only. Neither file may exist.
    pub fn finish(self, vault: &Path, key: &Path, with_keys: bool) -> Result<Session, String> {
        let Self {
            provision,
            password,
            keys,
            ..
        } = self;
        if with_keys {
            if keys.is_empty() {
                return Err("보안 키를 하나 이상 등록하세요.".into());
            }
            provision
                .finish_with_keys(vault, key, &password, true, keys)
                .map_err(text)
        } else {
            provision.finish(vault, key, &password).map_err(text)
        }
    }
}

impl Adding {
    /// [키 추가] on the open vault: at most 8 keys; the touch that
    /// re-authenticates is asked of the keys that reach every other (the
    /// PC's touch plan without extra touches); the gate of a key change
    /// (spec §7.5) unless the user answered its question (`override_gate`).
    pub fn new(
        s: &mut Session,
        session: jni::sys::jlong,
        password: Zeroizing<String>,
        override_gate: bool,
    ) -> Result<Self, String> {
        let o = s
            .keys_overview()
            .ok_or("이 금고에는 보안 키가 없습니다. 보안 키 켜기는 PC의 고요 금고에서 하세요.")?;
        if o.rows.len() >= MAX_KEYS {
            return Err("보안 키는 8개까지 등록할 수 있습니다.".into());
        }
        if let Some(gate) = gate(s)?
            && !override_gate
        {
            return Err(gate.into());
        }
        if o.full.is_empty() {
            return Err("다른 키를 모두 대신할 수 있는 키가 없어 휴대폰에서는 키를 추가할 수 없습니다. PC의 '열쇠 관리 › 짝 맺기'를 먼저 하세요.".into());
        }
        let touch_request = s.key_request(&o.full, 0).map_err(text)?;
        let (numbers, exclude) = s.add_plan(1).map_err(text)?;
        Ok(Self {
            session,
            password,
            override_gate,
            touch_request,
            reauth: None,
            vault_id: s.vault_id(),
            number: numbers[0],
            exclude,
            reg: None,
            key: None,
        })
    }
    pub fn touch_request(&self) -> &fido::AssertRequest {
        &self.touch_request
    }
    /// The Reauth with the typed password and the touch (spec §5.3).
    pub fn reauth(&mut self, s: &mut Session, raw: fido::RawAssertion) -> Result<(), String> {
        let touch =
            fido::check_assertion(raw, &self.touch_request, false).map_err(crate::fido_text)?;
        let r = s.reauth(&self.password, Some(&touch)).map_err(text)?;
        self.reauth = Some(r);
        Ok(())
    }
    /// The write (the new key paired with the Reauth key), then the key
    /// code and whether the app must lock (S-GAP-CHANGED).
    pub fn finish(mut self, s: &mut Session) -> Result<(String, bool), String> {
        let r = self
            .reauth
            .take()
            .ok_or("먼저 등록된 보안 키로 확인하세요.")?;
        let key = self.key.take().ok_or("새 보안 키를 먼저 등록하세요.")?;
        let number = self.number;
        let done = s
            .rekey(
                r,
                Vec::new(),
                Change::AddKey(key),
                Consent::default(),
                self.override_gate,
            )
            .map_err(text)?;
        let mut line = format!("보안 키 {number}을(를) 추가했습니다.");
        if let Some(code) = s.key_code() {
            line.push_str(&format!(
                "\n열쇠 확인 코드: {code}\n다른 기기가 이 변경을 받을 때 이 코드를 입력합니다. '열쇠 관리'에도 계속 보입니다."
            ));
        }
        match done {
            Rekeyed::Done => Ok((line, false)),
            Rekeyed::VaultPending => Ok((
                format!(
                    "{line}\n금고 파일은 아직 새 열쇠로 저장하지 못했습니다. 다음 저장 때 다시 합니다."
                ),
                false,
            )),
            Rekeyed::GapKept => Ok((
                format!("{line}\n금고 파일 저장이 끊겨 잠급니다. 다시 열면 이어서 처리합니다."),
                true,
            )),
        }
    }
}

/// What holds every key change of this session now, as the question the
/// user may answer with yes (spec §7.5); a local rollback is refused.
pub fn gate(s: &mut Session) -> Result<Option<&'static str>, String> {
    match s.password_change().map_err(text)? {
        Some(vault::Gate::LocalRollback) => Err(text(vault::Gate::LocalRollback.question())),
        Some(g) => Ok(Some(g.question())),
        None => Ok(None),
    }
}

impl Flow {
    /// The next registration's MakeCredential request.
    pub fn register(&mut self) -> Result<Vec<u8>, String> {
        let (reg, wire) = match self {
            Self::Create(c) => {
                if c.keys.len() >= MAX_KEYS {
                    return Err("보안 키는 8개까지 등록할 수 있습니다.".into());
                }
                let number = u8::try_from(c.keys.len() + 1).map_err(|_| "번호")?;
                let exclude = c.keys.iter().map(|k| k.cred_id.clone()).collect();
                Reg::start(&c.provision.vault_id(), number, exclude)?
            }
            Self::AddKey(a) => {
                if a.reauth.is_none() {
                    return Err("먼저 등록된 보안 키로 확인하세요.".into());
                }
                if a.key.is_some() {
                    return Err("이미 새 키를 등록했습니다.".into());
                }
                Reg::start(&a.vault_id, a.number, a.exclude.clone())?
            }
        };
        *self.reg_slot() = Some(reg);
        Ok(wire)
    }
    fn reg_slot(&mut self) -> &mut Option<Reg> {
        match self {
            Self::Create(c) => &mut c.reg,
            Self::AddKey(a) => &mut a.reg,
        }
    }
    pub fn made(
        &mut self,
        auth_data: &[u8],
        transport: u32,
    ) -> Result<fido::AssertRequest, String> {
        let slot = self.reg_slot();
        let reg = slot.as_mut().ok_or("등록을 처음부터 다시 하세요.")?;
        match reg.made(auth_data, transport) {
            Ok(check) => Ok(check),
            Err(e) => {
                *slot = None;
                Err(e)
            }
        }
    }
    /// The check's answer: the new key kept; the number of keys so far.
    pub fn checked(&mut self, raw: fido::RawAssertion) -> Result<usize, String> {
        let mut reg = self
            .reg_slot()
            .take()
            .ok_or("등록을 처음부터 다시 하세요.")?;
        let key = reg.checked(raw)?;
        match self {
            Self::Create(c) => {
                c.keys.push(key);
                Ok(c.keys.len())
            }
            Self::AddKey(a) => {
                a.key = Some(key);
                Ok(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goyo_vault::fido::{
        AT, Authenticator, RawCredential, UP, UV,
        fake::{Device, Fake},
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    const PASSWORD: &str = "a long synthetic password for the flows";

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new(what: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "goyo-android-flows-{what}-{:x}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// What yubikit hands back for a registration on a real key: the
    /// fake's MakeCredential with its credential ID, a COSE key and the
    /// extension outputs written into the authenticator data, as CTAP2
    /// lays them out.
    fn as_from_yubikit(raw: &RawCredential) -> Vec<u8> {
        let mut a = raw.auth_data[..37].to_vec();
        a[32] |= 0x80; // ED
        a.extend_from_slice(&raw.auth_data[37..53]);
        a.extend_from_slice(&(raw.cred_id.len() as u16).to_be_bytes());
        a.extend_from_slice(&raw.cred_id);
        a.extend_from_slice(&[0xa1, 0x01, 0x02]); // a tiny COSE map
        a.extend_from_slice(&[0xa2, 0x6b]);
        a.extend_from_slice(b"credProtect");
        a.push(0x03);
        a.push(0x6b);
        a.extend_from_slice(b"hmac-secret");
        a.push(0xf5);
        a
    }

    /// One registration of `flow` on the fake key `i`, as the app runs it:
    /// the request the flow states, MakeCredential, the check.
    fn register(flow: &mut Flow, fake: &Fake, i: usize) -> usize {
        fake.touch(Some(i));
        flow.register().unwrap();
        let make = match flow {
            Flow::Create(c) => c.reg.as_ref().unwrap().make.clone(),
            Flow::AddKey(a) => a.reg.as_ref().unwrap().make.clone(),
        };
        let raw = fake
            .make_credential(&make, &fake.new_cancel().unwrap())
            .unwrap();
        assert_eq!(raw.auth_data[32] & (UP | AT | UV), UP | AT | UV);
        let check = flow.made(&as_from_yubikit(&raw), fido::USB).unwrap();
        let answer = fake
            .get_assertion(&check, &fake.new_cancel().unwrap())
            .unwrap();
        flow.checked(answer).unwrap()
    }
    fn open(vault: &Path, key: &Path, fake: &Fake, i: usize) -> Session {
        let prepared = vault::prepare(vault, key).unwrap();
        let request = prepared.unlock_request(0).unwrap();
        fake.touch(Some(i));
        let raw = fake
            .get_assertion(&request, &fake.new_cancel().unwrap())
            .unwrap();
        let touch = fido::check_assertion(raw, &request, false).unwrap();
        Session::login_with(prepared, PASSWORD, None, &touch).unwrap()
    }

    /// 새 금고 만들기 with two YubiKeys, then [키 추가] of a third on the
    /// open vault: the flows run the lib's registrations and key change
    /// with what the keys returned, and each key opens the vault.
    #[test]
    fn create_with_keys_then_add_one() {
        let anchor = Temp::new("anchor");
        vault::set_anchor_dir(Some(anchor.0.clone()));
        let t = Temp::new("files");
        let (v, k) = (t.0.join("vault.goyo"), t.0.join("vault.goyokey"));
        assert!(Creating::new(Zeroizing::new("short".into())).is_err());
        let fake = Fake::new(None);
        let (a, b, c) = (
            fake.plug(Device::with_pin()),
            fake.plug(Device::with_pin()),
            fake.plug(Device::with_pin()),
        );
        let mut flow = Flow::Create(Box::new(
            Creating::new(Zeroizing::new(PASSWORD.into())).unwrap(),
        ));
        assert_eq!(register(&mut flow, &fake, a), 1);
        // The same key again: the exclude list holds its credential.
        fake.touch(Some(a));
        flow.register().unwrap();
        let make = match &flow {
            Flow::Create(c) => c.reg.as_ref().unwrap().make.clone(),
            Flow::AddKey(_) => unreachable!(),
        };
        assert_eq!(make.exclude.len(), 1);
        assert!(
            fake.make_credential(&make, &fake.new_cancel().unwrap())
                .is_err()
        );
        assert_eq!(register(&mut flow, &fake, b), 2);
        let Flow::Create(creating) = flow else {
            unreachable!()
        };
        let s = creating.finish(&v, &k, true).unwrap();
        assert_eq!(s.keys_overview().unwrap().rows.len(), 2);
        drop(s);

        // Key b opens it; [키 추가] with a touch of a key that reaches all.
        let mut s = open(&v, &k, &fake, b);
        assert_eq!(gate(&mut s).unwrap(), None);
        let lines = crate::jni_keys::keys_lines(&s);
        assert_eq!(lines[0], "보안 키: 켜짐 · PIN 사용 · 2개 등록");
        assert!(lines[1].starts_with('E'), "{lines:?}");
        assert_eq!(lines.len(), 6);
        // A wrong password fails the Reauth.
        let mut wrong = Adding::new(
            &mut s,
            1,
            Zeroizing::new("not the password at all".into()),
            false,
        )
        .unwrap();
        fake.touch(Some(a));
        let raw = fake
            .get_assertion(wrong.touch_request(), &fake.new_cancel().unwrap())
            .unwrap();
        assert!(wrong.reauth(&mut s, raw).is_err());
        drop(wrong);
        let mut adding = Adding::new(&mut s, 1, Zeroizing::new(PASSWORD.into()), false).unwrap();
        let raw = fake
            .get_assertion(adding.touch_request(), &fake.new_cancel().unwrap())
            .unwrap();
        adding.reauth(&mut s, raw).unwrap();
        let mut flow = Flow::AddKey(Box::new(adding));
        assert_eq!(register(&mut flow, &fake, c), 1);
        let Flow::AddKey(adding) = flow else {
            unreachable!()
        };
        let (line, lock) = adding.finish(&mut s).unwrap();
        assert!(!lock);
        assert!(line.starts_with("보안 키 3을(를) 추가했습니다."), "{line}");
        assert_eq!(s.keys_overview().unwrap().rows.len(), 3);
        drop(s);
        for key in [a, b, c] {
            let s = open(&v, &k, &fake, key);
            assert_eq!(s.keys_overview().unwrap().rows.len(), 3);
        }
        vault::set_anchor_dir(None);
    }

    /// A vault without security keys (the toggle off); a create flow that
    /// registered none refuses to write one with keys.
    #[test]
    fn create_password_only() {
        let anchor = Temp::new("anchor-pw");
        vault::set_anchor_dir(Some(anchor.0.clone()));
        let t = Temp::new("files-pw");
        let (v, k) = (t.0.join("vault.goyo"), t.0.join("vault.goyokey"));
        let c = Creating::new(Zeroizing::new(PASSWORD.into())).unwrap();
        assert!(c.finish(&v, &k, true).is_err());
        let c = Creating::new(Zeroizing::new(PASSWORD.into())).unwrap();
        let tag = c.tag();
        let s = c.finish(&v, &k, false).unwrap();
        assert!(s.keys_overview().is_none());
        assert_eq!(vault::vault_tag(&v), Some(tag));
        drop(s);
        assert!(Session::unlock(&v, &k, PASSWORD).is_ok());
        // Never over existing files.
        let c = Creating::new(Zeroizing::new(PASSWORD.into())).unwrap();
        assert!(c.finish(&v, &k, false).is_err());
        vault::set_anchor_dir(None);
    }
}
