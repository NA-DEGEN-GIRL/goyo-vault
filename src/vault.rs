//! Versioned authenticated file formats; no plaintext files, no automatic key lookup.
use crate::{
    crypto::{self, AUTH_ERROR, Key, Result},
    otp,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const KEY_MAGIC: &[u8; 8] = b"GOYOKE01";
const DATA_MAGIC: &[u8; 8] = b"GOYOVA01";
pub const MAX_FILE: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1000;
pub const MAX_TEXT: usize = 8192;

pub struct Entry {
    pub title: Zeroizing<String>,
    pub kind: Zeroizing<String>,
    pub secret: Zeroizing<String>,
    pub notes: Zeroizing<String>,
}
impl Entry {
    pub fn new(title: String, kind: String, secret: String, notes: String) -> Result<Self> {
        let e = Self {
            title: Zeroizing::new(title),
            kind: Zeroizing::new(kind),
            secret: Zeroizing::new(secret),
            notes: Zeroizing::new(notes),
        };
        e.validate()?;
        Ok(e)
    }
    fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() || self.secret.is_empty() {
            return Err("이름과 비밀정보를 입력하세요.");
        }
        if self.title.len() > 256
            || self.kind.len() > 64
            || self.secret.len() > MAX_TEXT
            || self.notes.len() > MAX_TEXT
        {
            return Err("항목이 너무 깁니다.");
        }
        if [&*self.title, &*self.kind, &*self.secret, &*self.notes]
            .iter()
            .any(|s| s.contains('\0'))
        {
            return Err("NUL 문자는 저장할 수 없습니다.");
        }
        Ok(())
    }
}
pub struct Provision {
    id: [u8; 16],
    key: Key,
    otp: Zeroizing<[u8; 20]>,
}
impl Provision {
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: *crypto::random()?,
            key: crypto::random()?,
            otp: crypto::random()?,
        })
    }
    pub fn setup_code(&self) -> Zeroizing<String> {
        otp::base32(self.otp.as_slice())
    }
    /// Key URI for authenticator apps; SHA-1, 6 digits and 30 s are defaults.
    pub fn setup_uri(&self) -> Zeroizing<String> {
        const HEAD: &str = "otpauth://totp/Goyo%20Vault?secret=";
        const TAIL: &str = "&issuer=Goyo%20Vault";
        let code = self.setup_code();
        // Sized up front so the secret is never left behind by a reallocation.
        let mut uri = Zeroizing::new(String::with_capacity(HEAD.len() + code.len() + TAIL.len()));
        uri.push_str(HEAD);
        uri.push_str(&code);
        uri.push_str(TAIL);
        uri
    }
    pub fn finish(
        &self,
        vault: &Path,
        key_path: &Path,
        password: &str,
        input: &str,
    ) -> Result<Session> {
        password_policy(password)?;
        let last = otp::verify(self.otp.as_slice(), input, otp::now()?, None)?;
        let vault = normalized(vault)?;
        let key_path = normalized(key_path)?;
        distinct(&vault, &key_path)?;
        if vault.exists() || key_path.exists() {
            return Err("새 금고와 열쇠 파일은 기존 파일을 덮어쓸 수 없습니다.");
        }
        let locks = vec![FileLock::acquire(&vault)?];
        let key_bytes = encode_key(&self.id, &self.key, &self.otp, password)?;
        let mut session = Session {
            path: vault,
            key_path,
            id: self.id,
            key: Zeroizing::new(*self.key),
            otp: Zeroizing::new(*self.otp),
            last,
            entries: Vec::new(),
            key_bytes,
            _locks: locks,
        };
        let data = session.encode()?;
        atomic_write(&session.key_path, &session.key_bytes, false)?;
        if let Err(e) = atomic_write(&session.path, &data, false) {
            let _ = fs::remove_file(&session.key_path);
            return Err(e);
        }
        session.entries.shrink_to_fit();
        Ok(session)
    }
}
pub const MIN_PASSWORD: usize = 12;
pub fn password_policy(s: &str) -> Result<()> {
    // Argon2id slows each guess, but a stolen key file can still be guessed
    // offline without limit (the OTP does not take part in decryption), so
    // length is what keeps the password out of reach.
    if s.chars().count() < MIN_PASSWORD || s.len() > 1024 {
        return Err(
            "비밀번호는 12자 이상, UTF-8 1024바이트 이하로 입력하세요. 짧고 복잡한 암호보다 긴 문장이 안전합니다.",
        );
    }
    // Length alone admits "aaaaaaaaaaaaaaaa" or "abababababababab".
    let mut distinct: Zeroizing<Vec<char>> = Zeroizing::new(s.chars().collect());
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 6 {
        return Err(
            "같은 글자를 반복한 비밀번호는 쓸 수 없습니다. 서로 다른 글자가 6개 이상 필요합니다.",
        );
    }
    Ok(())
}

pub struct Session {
    pub path: PathBuf,
    pub key_path: PathBuf,
    id: [u8; 16],
    key: Key,
    otp: Zeroizing<[u8; 20]>,
    last: u64,
    pub entries: Vec<Entry>,
    key_bytes: Vec<u8>,
    _locks: Vec<FileLock>,
}
impl Session {
    pub fn unlock(vault: &Path, key_path: &Path, password: &str, input: &str) -> Result<Self> {
        Self::load(vault, key_path, password, input, None)
    }
    pub fn restore(
        backup: &Path,
        key_path: &Path,
        destination: &Path,
        password: &str,
        input: &str,
    ) -> Result<Self> {
        Self::load(backup, key_path, password, input, Some(destination))
    }
    fn load(
        vault: &Path,
        key_path: &Path,
        password: &str,
        input: &str,
        destination: Option<&Path>,
    ) -> Result<Self> {
        if password.len() > 1024 || input.len() != 6 || !input.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AUTH_ERROR);
        }
        let source = normalized(vault)?;
        let key_path = normalized(key_path)?;
        distinct(&source, &key_path)?;
        // Restore inputs and key files are immutable read snapshots. They may be
        // on read-only media; only the live output needs a writable sidecar lock.
        let mut locks = if destination.is_none() {
            vec![FileLock::acquire(&source)?]
        } else {
            Vec::new()
        };
        let key_bytes = read_bounded(&key_path, 1024)?;
        let (id, key, otp) = decode_key(&key_bytes, password)?;
        let data = read_bounded(&source, MAX_FILE)?;
        let (last, entries) = decode_data(&id, &key, &data)?;
        let step =
            otp::verify(otp.as_slice(), input, otp::now()?, Some(last)).map_err(|_| AUTH_ERROR)?;
        let path = if let Some(dest) = destination {
            let dest = normalized(dest)?;
            distinct(&dest, &key_path)?;
            distinct(&dest, &source)?;
            if dest.exists() {
                return Err("복원 대상은 새 파일이어야 합니다.");
            }
            locks.push(FileLock::acquire(&dest)?);
            dest
        } else {
            source
        };
        let s = Self {
            path,
            key_path,
            id,
            key,
            otp,
            last: step,
            entries,
            key_bytes,
            _locks: locks,
        };
        // Persist the consumed OTP before exposing any secret. Backup rollback
        // and modified clients cannot be prevented by this local watermark.
        atomic_write(&s.path, &s.encode()?, destination.is_none())?;
        Ok(s)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        encode_data(&self.id, &self.key, self.last, &self.entries)
    }
    pub fn save(&self) -> Result<()> {
        atomic_write(&self.path, &self.encode()?, true)
    }
    pub fn put(&mut self, index: Option<usize>, entry: Entry) -> Result<()> {
        entry.validate()?;
        if let Some(i) = index {
            if i >= self.entries.len() {
                return Err("항목 선택 오류");
            }
            let old = std::mem::replace(&mut self.entries[i], entry);
            if let Err(e) = self.save() {
                self.entries[i] = old;
                return Err(e);
            }
        } else {
            if self.entries.len() >= MAX_ENTRIES {
                return Err("최대 1000개까지 저장할 수 있습니다.");
            }
            self.entries.push(entry);
            if let Err(e) = self.save() {
                self.entries.pop();
                return Err(e);
            }
        }
        Ok(())
    }
    pub fn delete(&mut self, i: usize) -> Result<()> {
        if i >= self.entries.len() {
            return Err("항목 선택 오류");
        }
        let old = self.entries.remove(i);
        if let Err(e) = self.save() {
            self.entries.insert(i, old);
            return Err(e);
        }
        Ok(())
    }
    pub fn backup(&self, path: &Path) -> Result<()> {
        let path = normalized(path)?;
        distinct(&path, &self.path)?;
        distinct(&path, &self.key_path)?;
        let _lock = FileLock::acquire(&path)?;
        atomic_write(&path, &self.encode()?, false)
    }
    pub fn backup_key(&self, path: &Path) -> Result<()> {
        if read_bounded(&self.key_path, 1024)? != self.key_bytes {
            return Err("열쇠 파일이 변경되었습니다. 잠근 뒤 새 비밀번호로 다시 열고 백업하세요.");
        }
        let path = normalized(path)?;
        distinct(&path, &self.path)?;
        distinct(&path, &self.key_path)?;
        let _lock = FileLock::acquire(&path)?;
        atomic_write(&path, &self.key_bytes, false)
    }
    pub fn change_password(&mut self, current: &str, password: &str, input: &str) -> Result<()> {
        password_policy(password)?;
        if current.len() > 1024 || input.len() != 6 || !input.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AUTH_ERROR);
        }
        let _lock = FileLock::acquire(&self.key_path)?;
        if read_bounded(&self.key_path, 1024)? != self.key_bytes {
            return Err("열쇠 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.");
        }
        let _verified = decode_key(&self.key_bytes, current)?;
        let step = otp::verify(self.otp.as_slice(), input, otp::now()?, Some(self.last))
            .map_err(|_| AUTH_ERROR)?;
        let bytes = encode_key(&self.id, &self.key, &self.otp, password)?;
        let previous = self.last;
        self.last = step;
        if let Err(e) = self.save() {
            self.last = previous;
            return Err(e);
        }
        atomic_write(&self.key_path, &bytes, true)?;
        self.key_bytes = bytes;
        Ok(())
    }
}

fn encode_key(id: &[u8; 16], key: &[u8; 32], otp: &[u8; 20], password: &str) -> Result<Vec<u8>> {
    let salt = crypto::random::<32>()?;
    let nonce = crypto::random::<24>()?;
    let wrapping = crypto::derive(password.as_bytes(), &salt)?;
    let mut header = Vec::with_capacity(148);
    header.extend_from_slice(KEY_MAGIC);
    header.extend_from_slice(id);
    header.extend_from_slice(salt.as_slice());
    header.extend_from_slice(nonce.as_slice());
    let mut plain = Zeroizing::new([0u8; 52]);
    plain[..32].copy_from_slice(key);
    plain[32..].copy_from_slice(otp);
    let ciphertext = crypto::seal(&wrapping, &nonce, &header, plain.as_slice())?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}
type KeyMaterial = ([u8; 16], Key, Zeroizing<[u8; 20]>);
fn decode_key(data: &[u8], password: &str) -> Result<KeyMaterial> {
    if data.len() != 148 || &data[..8] != KEY_MAGIC {
        return Err(AUTH_ERROR);
    }
    let id = data[8..24].try_into().unwrap();
    let salt = data[24..56].try_into().unwrap();
    let nonce = data[56..80].try_into().unwrap();
    let wrapping = crypto::derive(password.as_bytes(), salt)?;
    let plain = crypto::open(&wrapping, nonce, &data[..80], &data[80..])?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&plain[..32]);
    let mut otp = Zeroizing::new([0; 20]);
    otp.copy_from_slice(&plain[32..]);
    Ok((id, key, otp))
}
fn encode_data(id: &[u8; 16], key: &[u8; 32], last: u64, entries: &[Entry]) -> Result<Vec<u8>> {
    if entries.len() > MAX_ENTRIES {
        return Err("항목 수 제한 초과");
    }
    let mut size = 12usize;
    for e in entries {
        e.validate()?;
        size += 16 + e.title.len() + e.kind.len() + e.secret.len() + e.notes.len();
    }
    if size + 64 > MAX_FILE {
        return Err("금고 용량 제한(8 MiB)을 초과했습니다.");
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(size));
    plain.extend_from_slice(&last.to_le_bytes());
    plain.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        for s in [&e.title, &e.kind, &e.secret, &e.notes] {
            plain.extend_from_slice(&(s.len() as u32).to_le_bytes());
            plain.extend_from_slice(s.as_bytes());
        }
    }
    let nonce = crypto::random::<24>()?;
    let mut header = Vec::with_capacity(size + 64);
    header.extend_from_slice(DATA_MAGIC);
    header.extend_from_slice(id);
    header.extend_from_slice(nonce.as_slice());
    let cipher = crypto::seal(key, &nonce, &header, &plain)?;
    header.extend_from_slice(&cipher);
    Ok(header)
}
fn decode_data(id: &[u8; 16], key: &[u8; 32], data: &[u8]) -> Result<(u64, Vec<Entry>)> {
    if data.len() < 76 || data.len() > MAX_FILE || &data[..8] != DATA_MAGIC || &data[8..24] != id {
        return Err(AUTH_ERROR);
    }
    let plain = crypto::open(
        key,
        data[24..48].try_into().unwrap(),
        &data[..48],
        &data[48..],
    )?;
    let mut r = Reader(&plain);
    let last = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
    let count = r.num()?;
    if count > MAX_ENTRIES {
        return Err(AUTH_ERROR);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let e = Entry {
            title: r.text(256)?,
            kind: r.text(64)?,
            secret: r.text(MAX_TEXT)?,
            notes: r.text(MAX_TEXT)?,
        };
        e.validate()?;
        entries.push(e);
    }
    if !r.0.is_empty() {
        return Err(AUTH_ERROR);
    }
    Ok((last, entries))
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(AUTH_ERROR);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn num(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn text(&mut self, limit: usize) -> Result<Zeroizing<String>> {
        let n = self.num()?;
        if n > limit {
            return Err(AUTH_ERROR);
        }
        Ok(Zeroizing::new(
            std::str::from_utf8(self.take(n)?)
                .map_err(|_| AUTH_ERROR)?
                .to_owned(),
        ))
    }
}
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let f = File::open(path).map_err(|_| "파일을 열 수 없습니다.")?;
    if f.metadata().map_err(|_| "파일 정보 오류")?.len() > max as u64 {
        return Err("파일 크기 제한 초과");
    }
    let mut b = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| "파일 읽기 실패")?;
    if b.len() > max {
        return Err("파일 크기 제한 초과");
    }
    Ok(b)
}
fn normalized(path: &Path) -> Result<PathBuf> {
    // Reject alternate data streams; accept ordinary file names only.
    for component in path.components() {
        if let std::path::Component::Normal(s) = component {
            let s = s.to_string_lossy();
            if s.contains(':') || s.contains('\0') || s.ends_with(['.', ' ']) {
                return Err(
                    "일반 파일 경로를 지정하세요. 스트림·끝 공백·끝 점은 허용하지 않습니다.",
                );
            }
            if is_device_name(&s) {
                return Err("CON·NUL·COM1 같은 장치 이름은 파일 이름으로 쓸 수 없습니다.");
            }
        }
    }
    if path.exists() {
        return path.canonicalize().map_err(|_| "경로 확인 실패");
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or("파일 경로를 지정하세요.")?;
    Ok(parent
        .canonicalize()
        .map_err(|_| "저장할 폴더가 없습니다.")?
        .join(name))
}
/// DOS device names open a device, not a file: a backup to "NUL" or
/// "nul.goyo" would report success and keep nothing. The stem decides.
fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end();
    let stem = stem.to_ascii_uppercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    };
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered("COM")
        || numbered("LPT")
}
fn distinct(a: &Path, b: &Path) -> Result<()> {
    if a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
        || (a.exists() && b.exists() && file_identity(a)? == file_identity(b)?)
    {
        Err("금고와 열쇠, 백업 대상은 서로 다른 파일이어야 합니다.")
    } else {
        Ok(())
    }
}
#[cfg(windows)]
fn file_identity(path: &Path) -> Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        attributes: u32,
        times: [u32; 6],
        volume: u32,
        size_hi: u32,
        size_lo: u32,
        links: u32,
        index_hi: u32,
        index_lo: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(h: *mut std::ffi::c_void, info: *mut Info) -> i32;
    }
    let f = File::open(path).map_err(|_| "파일 식별 실패")?;
    let mut i = Info::default();
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut i) } == 0 {
        return Err("파일 식별 실패");
    }
    Ok((i.volume, ((i.index_hi as u64) << 32) | i.index_lo as u64))
}
#[cfg(not(windows))]
fn file_identity(_path: &Path) -> Result<(u32, u64)> {
    Err("Windows에서만 지원합니다.")
}
struct FileLock(File);
impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        let mut name = path.as_os_str().to_owned();
        name.push(".goyolock");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(name))
            .map_err(|_| "파일 잠금을 만들 수 없습니다.")?;
        f.try_lock()
            .map_err(|_| "다른 고요 금고에서 사용 중인 파일입니다.")?;
        Ok(Self(f))
    }
}
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
fn atomic_write(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    if !replace && path.exists() {
        return Err("기존 파일을 덮어쓰지 않습니다. 새 파일 이름을 선택하세요.");
    }
    let suffix = crypto::random::<16>()?;
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{:032x}.goyotmp", u128::from_le_bytes(*suffix)));
    let temp = PathBuf::from(name);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|_| "임시 암호화 파일 생성 실패")?;
        f.write_all(data)
            .and_then(|_| f.sync_all())
            .map_err(|_| "저장 실패: 디스크 공간과 권한을 확인하세요.")?;
        drop(f);
        publish(&temp, path, replace)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(windows)]
fn publish(temp: &Path, target: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    if from[..from.len() - 1].contains(&0) || to[..to.len() - 1].contains(&0) {
        return Err("올바르지 않은 파일 경로");
    }
    // Same-directory rename; atomic no-clobber when REPLACE_EXISTING is absent.
    // Unlike hard links this also supports common removable FAT/exFAT volumes.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 8 | u32::from(replace)) } == 0 {
        return Err("파일 저장/교체 실패: 기존 파일, 저장장치 연결과 쓰기 권한을 확인하세요.");
    }
    Ok(())
}

#[cfg(test)]
mod workflow_tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "goyo-workflow-{:x}",
                u128::from_le_bytes(*crypto::random::<16>().unwrap())
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn file(&self, n: &str) -> PathBuf {
            self.0.join(n)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            for e in fs::read_dir(&self.0).unwrap() {
                let e = e.unwrap();
                assert!(e.file_type().unwrap().is_file());
                let _ = fs::remove_file(e.path());
            }
            let _ = fs::remove_dir(&self.0);
        }
    }
    fn entry(value: &str) -> Entry {
        Entry::new(
            "테스트 항목".into(),
            "비밀".into(),
            value.into(),
            "메모".into(),
        )
        .unwrap()
    }
    #[test]
    fn lifecycle_backup_restore_password_and_failed_save() {
        let t = Temp::new();
        let v = t.file("vault.goyo");
        let k = t.file("key.goyokey");
        let b = t.file("backup.goyo");
        let restored = t.file("restored.goyo");
        let pass = "a long synthetic password";
        let changed = "another synthetic password";
        let p = Provision::new().unwrap();
        let current = otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6);
        let input = format!("{current:06}");
        assert!(p.finish(&v, &k, "short", &input).is_err());
        assert!(!v.exists() && !k.exists());
        let mut s = p.finish(&v, &k, pass, &input).unwrap();
        s.put(None, entry("original secret")).unwrap();
        s.put(Some(0), entry("updated secret")).unwrap();
        s.backup(&b).unwrap();
        let old_key = fs::read(&k).unwrap();
        assert!(s.backup(&b).is_err());
        assert!(Session::unlock(&v, &k, pass, &input).is_err()); // already open
        let actual = s.path.clone();
        s.path = t.file("missing-folder").join("failed.goyo");
        assert!(s.put(Some(0), entry("must not commit")).is_err());
        assert_eq!(&*s.entries[0].secret, "updated secret");
        assert!(s.delete(0).is_err());
        assert_eq!(s.entries.len(), 1);
        s.path = actual;
        s.delete(0).unwrap();
        assert!(s.entries.is_empty());
        s.put(None, entry("final secret")).unwrap();
        assert!(s.change_password("wrong", changed, &input).is_err());
        assert!(s.change_password(pass, changed, &input).is_err());
        s.last = 0; // simulate a later interval without sleeping
        s.change_password(pass, changed, &input).unwrap();
        assert_ne!(old_key, fs::read(&k).unwrap());
        assert!(decode_key(&fs::read(&k).unwrap(), pass).is_err());
        assert!(decode_key(&fs::read(&k).unwrap(), changed).is_ok());
        let (_, old_master, _) = decode_key(&old_key, pass).unwrap();
        assert!(decode_data(&p.id, &old_master, &fs::read(&v).unwrap()).is_ok()); // documented non-revocation
        // Simulate time elapsed since backup without sleeping or weakening production verification.
        let old_backup = encode_data(&p.id, &p.key, 0, &[entry("restore snapshot")]).unwrap();
        fs::write(&b, &old_backup).unwrap();
        drop(s);
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        assert_eq!(
            Session::restore(&b, &k, &restored, "wrong password", &input)
                .err()
                .unwrap(),
            AUTH_ERROR
        );
        let step = otp::now().unwrap() / 30;
        let codes = [step - 1, step, step + 1].map(|t| otp::code(p.otp.as_slice(), t, 6));
        let wrong_code = (0..1_000_000).find(|c| !codes.contains(c)).unwrap();
        assert_eq!(
            Session::restore(&b, &k, &restored, changed, &format!("{wrong_code:06}"))
                .err()
                .unwrap(),
            AUTH_ERROR
        );
        assert!(!restored.exists());
        let rs = Session::restore(&b, &k, &restored, changed, &input).unwrap();
        assert_eq!(&*rs.entries[0].secret, "restore snapshot");
        assert_eq!(fs::read(&b).unwrap(), old_backup);
        drop(rs);
        assert!(Session::unlock(&restored, &k, changed, &input).is_err()); // consumed OTP
    }
    #[test]
    fn restore_needs_no_sidecars_next_to_inputs() {
        let t = Temp::new();
        let src = t.file("readonly-backup.goyo");
        let key = t.file("readonly-key.goyokey");
        let out = t.file("new.goyo");
        let p = Provision::new().unwrap();
        let pass = "readonly test password";
        fs::write(&key, encode_key(&p.id, &p.key, &p.otp, pass).unwrap()).unwrap();
        fs::write(
            &src,
            encode_data(&p.id, &p.key, 0, &[entry("saved")]).unwrap(),
        )
        .unwrap();
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        let mut s = Session::restore(&src, &key, &out, pass, &input).unwrap();
        assert!(!t.file("readonly-backup.goyo.goyolock").exists());
        assert!(!t.file("readonly-key.goyokey.goyolock").exists());
        // Another vault copy can share this key; password rewrap must invalidate
        // this session's cached key backup instead of silently exporting it.
        let mut other = Session::restore(&src, &key, &t.file("other.goyo"), pass, &input).unwrap();
        other.last = 0;
        other
            .change_password(pass, "another shared key password", &input)
            .unwrap();
        assert!(s.backup_key(&t.file("stale.goyokey")).is_err());
        assert!(
            s.change_password(pass, "stale replacement password", &input)
                .is_err()
        );
        assert!(!t.file("stale.goyokey").exists());
        other.backup_key(&t.file("current.goyokey")).unwrap();
        drop(other);
        drop(s);
    }
    #[test]
    fn path_aliases_and_streams_rejected() {
        let t = Temp::new();
        let a = t.file("a.goyo");
        let b = t.file("b.goyo");
        fs::write(&a, b"synthetic").unwrap();
        fs::hard_link(&a, &b).unwrap();
        assert!(distinct(&a, &b).is_err());
        assert!(normalized(&t.file("a.goyo:hidden")).is_err());
        assert!(normalized(&t.file("trailing.")).is_err());
        for device in [
            "NUL",
            "nul.goyo",
            "Con.goyokey",
            "COM1",
            "lpt9.goyo",
            "COM¹",
        ] {
            assert!(normalized(&t.file(device)).is_err(), "{device}");
        }
        for name in ["console.goyo", "COM10.goyo", "nullable.goyo", "auxiliary"] {
            assert!(normalized(&t.file(name)).is_ok(), "{name}");
        }
    }
    #[test]
    fn password_policy_rejects_repetition() {
        assert!(password_policy("aaaaaaaaaaaaaaaa").is_err());
        assert!(password_policy("abababababababab").is_err());
        assert!(password_policy("abcdeabcdeabcdea").is_err()); // 5 distinct
        assert!(password_policy("short but varied").is_ok());
        assert!(password_policy("우리집 강아지는 복슬복슬 강아지").is_ok());
        assert!(password_policy("abc").is_err());
        assert!(password_policy("correct hors").is_ok()); // 12 characters
        assert!(password_policy("correct hor").is_err()); // 11
        assert!(password_policy("다람쥐 헌 쳇바퀴에 타고파").is_ok());
    }
    #[test]
    fn password_change_failure_stages_preserve_recoverability() {
        let t = Temp::new();
        let v = t.file("vault.goyo");
        let k = t.file("key.goyokey");
        let p = Provision::new().unwrap();
        let pass = "synthetic original password";
        let next = "synthetic replacement password";
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        let mut s = p.finish(&v, &k, pass, &input).unwrap();
        s.last = 0;
        let before_key = fs::read(&k).unwrap();
        let before_vault = fs::read(&v).unwrap();
        assert_eq!(
            s.change_password("incorrect password", next, &input)
                .unwrap_err(),
            AUTH_ERROR
        );
        assert_eq!(
            s.change_password(pass, next, "abc").unwrap_err(),
            AUTH_ERROR
        );
        s.path = t.file("missing").join("failed.goyo");
        assert!(s.change_password(pass, next, &input).is_err());
        assert_eq!(s.last, 0);
        assert_eq!(fs::read(&k).unwrap(), before_key);
        assert_eq!(fs::read(&v).unwrap(), before_vault);
        s.path = v.clone();
        let original_permissions = fs::metadata(&k).unwrap().permissions();
        let mut read_only = original_permissions.clone();
        read_only.set_readonly(true);
        fs::set_permissions(&k, read_only).unwrap();
        let result = s.change_password(pass, next, &input);
        fs::set_permissions(&k, original_permissions).unwrap();
        assert!(result.is_err());
        assert!(s.last > 0);
        assert_eq!(fs::read(&k).unwrap(), before_key);
        assert!(decode_key(&before_key, pass).is_ok());
        let (last, _) = decode_data(&p.id, &p.key, &fs::read(&v).unwrap()).unwrap();
        assert_eq!(last, s.last);
        assert_eq!(
            s.change_password(pass, next, &input).unwrap_err(),
            AUTH_ERROR
        );
    }
    #[test]
    fn authenticated_malformed_payloads_are_rejected() {
        fn wrap(p: &[u8]) -> Vec<u8> {
            let mut h = Vec::from(*DATA_MAGIC);
            h.extend_from_slice(&[1; 16]);
            h.extend_from_slice(&[2; 24]);
            let c = crypto::seal(&[3; 32], &[2; 24], &h, p).unwrap();
            h.extend(c);
            h
        }
        let mut cases = vec![vec![0; 11]];
        let mut count = vec![0; 8];
        count.extend_from_slice(&1001u32.to_le_bytes());
        cases.push(count);
        let mut length = vec![0; 8];
        length.extend_from_slice(&1u32.to_le_bytes());
        length.extend_from_slice(&u32::MAX.to_le_bytes());
        cases.push(length);
        let mut trailing = vec![0; 12];
        trailing.push(1);
        cases.push(trailing);
        for title in [vec![0xff], vec![0]] {
            let mut b = vec![0; 8];
            b.extend_from_slice(&1u32.to_le_bytes());
            for field in [
                title,
                b"kind".to_vec(),
                b"secret".to_vec(),
                b"notes".to_vec(),
            ] {
                b.extend_from_slice(&(field.len() as u32).to_le_bytes());
                b.extend(field);
            }
            cases.push(b);
        }
        for p in cases {
            assert!(decode_data(&[1; 16], &[3; 32], &wrap(&p)).is_err());
        }
    }
}
#[cfg(not(windows))]
fn publish(temp: &Path, target: &Path, replace: bool) -> Result<()> {
    if !replace {
        return Err("Windows에서만 저장할 수 있습니다.");
    }
    fs::rename(temp, target).map_err(|_| "파일 교체 실패")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parser_and_binding() {
        let es = vec![
            Entry::new(
                "테스트".into(),
                "니모닉".into(),
                "private words".into(),
                "메모".into(),
            )
            .unwrap(),
        ];
        let data = encode_data(&[1; 16], &[2; 32], 7, &es).unwrap();
        assert!(!data.windows(13).any(|s| s == b"private words"));
        let (last, got) = decode_data(&[1; 16], &[2; 32], &data).unwrap();
        assert_eq!(last, 7);
        assert_eq!(&*got[0].secret, "private words");
        assert!(decode_data(&[3; 16], &[2; 32], &data).is_err());
        for n in 0..data.len() {
            assert!(decode_data(&[1; 16], &[2; 32], &data[..n]).is_err());
        }
        for i in 0..data.len() {
            let mut bad = data.clone();
            bad[i] ^= 1;
            assert!(decode_data(&[1; 16], &[2; 32], &bad).is_err());
        }
    }
    #[test]
    fn key_password_and_tamper() {
        let bytes = encode_key(&[1; 16], &[2; 32], &[3; 20], "long-test-password").unwrap();
        let (_, key, otp) = decode_key(&bytes, "long-test-password").unwrap();
        assert_eq!(*key, [2; 32]);
        assert_eq!(*otp, [3; 20]);
        assert!(decode_key(&bytes, "wrong-password").is_err());
        let mut bad = bytes;
        bad[8] ^= 1;
        assert!(decode_key(&bad, "long-test-password").is_err());
    }
    #[test]
    fn storage_lock_and_overwrite() {
        let dir = std::env::temp_dir().join(format!(
            "goyo-test-{:x}",
            u128::from_le_bytes(*crypto::random::<16>().unwrap())
        ));
        fs::create_dir(&dir).unwrap();
        let p = dir.join("test.goyo");
        atomic_write(&p, b"encrypted", false).unwrap();
        assert!(atomic_write(&p, b"overwrite", false).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"encrypted");
        let lock = FileLock::acquire(&p).unwrap();
        assert!(FileLock::acquire(&p).is_err());
        drop(lock);
        atomic_write(&p, b"updated", true).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"updated");
        fs::remove_file(&p).unwrap();
        fs::remove_file(dir.join("test.goyo.goyolock")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
