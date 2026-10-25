//! Versioned authenticated file formats; no plaintext files, no automatic key lookup.
use crate::{
    crypto::{self, AUTH_ERROR, Key, Result},
    otp,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

mod sync;
pub use sync::{SyncBadge, SyncEvent, SyncNotice};

/// Key file with the TOTP secret: the app also asks for the phone's code.
const KEY_MAGIC: &[u8; 8] = b"GOYOKE01";
/// Key file without one: password and key file only.
const KEY_MAGIC_NO_OTP: &[u8; 8] = b"GOYOKE02";
/// A vault without sync; 0.7.x and older read only this.
const DATA_MAGIC_V1: &[u8; 8] = b"GOYOVA01";
/// A vault with sync: entry IDs, tombstones and the sync counters as well.
const DATA_MAGIC_V2: &[u8; 8] = b"GOYOVA02";
pub const MAX_FILE: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1000;
pub const MAX_TEXT: usize = 8192;
/// Deleted and replaced IDs a vault remembers (1 MiB in v2). Forgetting one
/// would let an old copy bring its entry back, so there is no compaction.
pub const MAX_TOMBSTONES: usize = 65_536;
const NEWER_FORMAT: &str = "더 새로운 버전에서 만든 금고 형식입니다. 고요 금고를 업데이트하세요.";
const TOMBSTONE_LIMIT: &str = "삭제·수정 기록이 한도(65,536개)에 도달했습니다.";

/// Identifies one version of an entry across copies of a vault. Random for
/// new and edited entries, derived for v1 entries (`v1_ids`); never zero.
pub type EntryId = [u8; 16];
/// The parent of an entry that replaced nothing; never a stored ID.
const NO_ID: EntryId = [0; 16];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// GOYOVA01: the OTP watermark and the entries.
    V1,
    /// GOYOVA02: written only once the user turns sync on for the vault.
    V2,
}

/// Cloning is fine: every copy of the text is zeroized when dropped.
#[derive(Clone)]
pub struct Entry {
    /// Zero until `Session::put` stores the entry.
    id: EntryId,
    /// The ID this entry replaced by an edit, zero for a new one. Two live
    /// entries with the same deleted parent were edited on two PCs.
    parent: EntryId,
    pub title: Zeroizing<String>,
    pub kind: Zeroizing<String>,
    pub secret: Zeroizing<String>,
    pub notes: Zeroizing<String>,
}
impl Entry {
    pub fn new(title: String, kind: String, secret: String, notes: String) -> Result<Self> {
        let e = Self {
            id: NO_ID,
            parent: NO_ID,
            title: Zeroizing::new(title),
            kind: Zeroizing::new(kind),
            secret: Zeroizing::new(secret),
            notes: Zeroizing::new(notes),
        };
        e.validate()?;
        Ok(e)
    }
    pub fn id(&self) -> EntryId {
        self.id
    }
    pub(crate) fn parent(&self) -> EntryId {
        self.parent
    }
    pub(crate) fn set_ids(&mut self, id: EntryId, parent: EntryId) {
        (self.id, self.parent) = (id, parent);
    }
    /// The four fields in file order, borrowed: comparing or counting them
    /// never copies a secret.
    pub(crate) fn fields(&self) -> [&str; 4] {
        [&self.title, &self.kind, &self.secret, &self.notes].map(|s| s.as_str())
    }
    /// Equal text in all four fields; IDs do not count.
    pub(crate) fn same_content(&self, other: &Entry) -> bool {
        self.fields() == other.fields()
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
/// Heap copy of a secret, filled in place so no copy is left on the stack.
fn boxed<const N: usize>(src: &[u8; N]) -> Box<Zeroizing<[u8; N]>> {
    let mut out = Box::new(Zeroizing::new([0u8; N]));
    out.as_mut_slice().copy_from_slice(src);
    out
}
/// Short, non-secret name for a vault: the first 4 bytes of its random ID.
/// Each vault gets its own authenticator entry, so a second vault's QR can
/// never replace (Microsoft Authenticator) or be mistaken for the first.
fn tag(id: &[u8; 16]) -> String {
    format!("{:02X}{:02X}-{:02X}{:02X}", id[0], id[1], id[2], id[3])
}
/// The tag of the vault file at `path`, read from its plaintext header.
pub fn vault_tag(path: &Path) -> Option<String> {
    let mut head = [0u8; 24];
    File::open(path).ok()?.read_exact(&mut head).ok()?;
    let magic = &head[..8];
    (magic == DATA_MAGIC_V1 || magic == DATA_MAGIC_V2).then(|| tag(head[8..24].try_into().unwrap()))
}
/// Whether `data` starts with GOYOVA03 or later: a newer build wrote it. The
/// magic is public, so saying so before any decryption reveals nothing.
pub(crate) fn newer_format(data: &[u8]) -> bool {
    match data.get(..8) {
        Some([b'G', b'O', b'Y', b'O', b'V', b'A', a, b])
            if a.is_ascii_digit() && b.is_ascii_digit() =>
        {
            (a - b'0') * 10 + (b - b'0') >= 3
        }
        _ => false,
    }
}
/// Whether the key file at `path` asks for an OTP code, from its plaintext
/// magic. None if it is missing or not a key file. Only decides which fields
/// the screen shows: the magic is authenticated, so the real decision is made
/// after decryption.
pub fn key_uses_otp(path: &Path) -> Option<bool> {
    let mut head = [0u8; 8];
    File::open(path).ok()?.read_exact(&mut head).ok()?;
    match &head {
        KEY_MAGIC => Some(true),
        KEY_MAGIC_NO_OTP => Some(false),
        _ => None,
    }
}
/// The TOTP secret in the forms an authenticator app accepts.
pub struct OtpSetup {
    id: [u8; 16],
    otp: Box<Zeroizing<[u8; 20]>>,
}
impl OtpSetup {
    /// Base32 setup key for manual entry.
    pub fn code(&self) -> Zeroizing<String> {
        otp::base32(self.otp.as_slice())
    }
    /// Account name shown in the authenticator app, e.g. "3FA2-C1D0".
    pub fn tag(&self) -> String {
        tag(&self.id)
    }
    /// Key URI for the QR; SHA-1, 6 digits and 30 s are defaults.
    pub fn uri(&self) -> Zeroizing<String> {
        const HEAD: &str = "otpauth://totp/Goyo%20Vault:";
        const SECRET: &str = "?secret=";
        const TAIL: &str = "&issuer=Goyo%20Vault";
        let (tag, code) = (self.tag(), self.code());
        let size = HEAD.len() + tag.len() + SECRET.len() + code.len() + TAIL.len();
        // Sized up front so the secret is never left behind by a reallocation.
        let mut uri = Zeroizing::new(String::with_capacity(size));
        for part in [HEAD, &tag, SECRET, &code, TAIL] {
            uri.push_str(part);
        }
        uri
    }
}
pub struct Provision {
    id: [u8; 16],
    key: Box<Key>,
    otp: Box<Zeroizing<[u8; 20]>>,
}
impl Provision {
    pub fn new() -> Result<Self> {
        let mut p = Self {
            id: [0; 16],
            key: Box::default(),
            otp: Box::default(),
        };
        crypto::random_into(&mut p.id)?;
        crypto::random_into(p.key.as_mut_slice())?;
        crypto::random_into(p.otp.as_mut_slice())?;
        Ok(p)
    }
    pub fn setup(&self) -> OtpSetup {
        OtpSetup {
            id: self.id,
            otp: boxed(&self.otp),
        }
    }
    pub fn setup_code(&self) -> Zeroizing<String> {
        self.setup().code()
    }
    /// The authenticator account name, without copying the OTP secret.
    pub fn tag(&self) -> String {
        tag(&self.id)
    }
    /// Writes the new vault and key file. With `Some(code)` the vault uses
    /// the OTP and the code must come from the phone that scanned the QR;
    /// with None it opens with the password and key file alone.
    pub fn finish(
        &self,
        vault: &Path,
        key_path: &Path,
        password: &str,
        input: Option<&str>,
    ) -> Result<Session> {
        password_policy(password)?;
        let last = match input {
            Some(input) => otp::verify(self.otp.as_slice(), input, otp::now()?, None)?,
            None => 0,
        };
        let otp = input.map(|_| boxed(&self.otp));
        let vault = normalized(vault)?;
        let key_path = normalized(key_path)?;
        distinct(&vault, &key_path)?;
        if vault.exists() || key_path.exists() {
            return Err("새 금고와 열쇠 파일은 기존 파일을 덮어쓸 수 없습니다.");
        }
        let locks = vec![FileLock::acquire(&vault)?];
        let key_bytes = encode_key(&self.id, &self.key, otp.as_deref(), password)?;
        let mut session = Session {
            path: vault,
            key_path,
            id: self.id,
            key: boxed(&self.key),
            otp,
            last,
            format: Format::V1,
            generation: 0,
            seen: 0,
            entries: Vec::new(),
            tombstones: Vec::new(),
            sync: None,
            unlock_notice: None,
            sync_refused: false,
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
/// Common words, keyboard walks, runs and repeats are what guessing tools try
/// first. A password made only of such pieces is refused at any length:
/// "password1234", "qwerty123456", "1q2w3e4r5t6y" and "123456123456" all are,
/// while unrelated words ("dragon-tiger-lemon") or a sentence still pass.
fn predictable(s: &str) -> bool {
    const WALKS: [&str; 10] = [
        "abcdefghijklmnopqrstuvwxyz",
        "01234567890",
        "qwertyuiop[]",
        "asdfghjkl;'",
        "zxcvbnm,./",
        "1q2w3e4r5t6y7u8i9o0p",
        "q1w2e3r4t5y6u7i8o9p0",
        "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
        "qazwsxedcrfvtgbyhnujmikolp",
        "!@#$%^&*()",
    ];
    const WORDS: [&str; 40] = [
        "password", "passwd", "pass", "iloveyou", "love", "letmein", "welcome", "admin", "login",
        "secret", "master", "hello", "dragon", "monkey", "shadow", "sunshine", "princess",
        "football", "baseball", "soccer", "superman", "batman", "freedom", "whatever", "trustno",
        "starwars", "qwerty", "test", "google", "naver", "kakao", "samsung", "bitcoin", "crypto",
        "wallet", "korea", "seoul", "sarang", "dkssud",
        "tkfkd", // 안녕, 사랑 typed with the Korean layout off
    ];
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(s.len()));
    chars.extend(
        s.chars()
            .flat_map(char::to_lowercase)
            .filter(|c| !c.is_whitespace()),
    );
    if chars.iter().all(char::is_ascii_digit) {
        return true; // dates, phone numbers
    }
    // A repeated block counts once: "qwerqwerqwer" is judged as "qwer".
    let n = chars.len();
    let unit = (1..=n / 2)
        .find(|p| n.is_multiple_of(*p) && (*p..n).all(|i| chars[i] == chars[i - p]))
        .unwrap_or(n);
    let text = &chars[..unit];
    let mut covered = vec![false; unit];
    let words: Vec<Vec<char>> = WORDS.iter().map(|w| w.chars().collect()).collect();
    let walks: Vec<Vec<char>> = WALKS
        .iter()
        .flat_map(|w| [w.chars().collect(), w.chars().rev().collect()])
        .collect();
    // No run is longer than the longest walk, which keeps this fast up to the
    // 1024-byte limit.
    let longest = walks.iter().map(Vec::len).max().unwrap_or(0);
    for i in 0..unit {
        for w in &words {
            if text[i..].starts_with(w) {
                covered[i..i + w.len()].fill(true);
            }
        }
        // Longest run from i that sits inside a keyboard or alphabet walk.
        let run = (3..=(unit - i).min(longest)).rev().find(|len| {
            let piece = &text[i..i + len];
            walks
                .iter()
                .any(|walk| walk.windows(*len).any(|w| w == piece))
        });
        if let Some(len) = run {
            covered[i..i + len].fill(true);
        }
    }
    covered.iter().filter(|c| !**c).count() < 4
}
pub fn password_policy(s: &str) -> Result<()> {
    // Argon2id slows each guess, but a stolen key file can still be guessed
    // offline without limit (an OTP never takes part in decryption), so
    // length is what keeps the password out of reach.
    if s.chars().count() < MIN_PASSWORD || s.len() > 1024 {
        return Err(
            "비밀번호는 12자 이상, UTF-8 1024바이트 이하로 입력하세요. 짧고 복잡한 암호보다 긴 문장이 안전합니다.",
        );
    }
    // Length alone admits "aaaaaaaaaaaaaaaa" or "abababababababab". Sized up
    // front: a growing Vec would free unwiped copies of the password.
    let mut distinct: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(s.len()));
    distinct.extend(s.chars());
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 6 {
        return Err(
            "같은 글자를 반복한 비밀번호는 쓸 수 없습니다. 서로 다른 글자가 6개 이상 필요합니다.",
        );
    }
    if predictable(s) {
        return Err(
            "흔한 단어(password, dragon 등)·키보드 배열·연속된 숫자는 추측 도구가 가장 먼저 시도해서 글자 수로 치지 않습니다. 흔하지 않은 단어나 나만 아는 문장을 섞으세요.",
        );
    }
    Ok(())
}

pub struct Session {
    pub path: PathBuf,
    pub key_path: PathBuf,
    id: [u8; 16],
    key: Box<Key>,
    /// None when the vault opens without an OTP code.
    otp: Option<Box<Zeroizing<[u8; 20]>>>,
    /// Last accepted OTP time step; always 0 without an OTP.
    last: u64,
    /// V1 until the user turns sync on for this vault; it never goes back.
    format: Format,
    /// Lamport counter of content changes, shared by the synced copies: a
    /// put, a delete or a merge to upload raises it, OTP and password changes
    /// do not. Written only in v2.
    generation: u64,
    /// This PC's highest `generation` of an authenticated server copy; a
    /// lower one later means the server went back. Written only in v2.
    seen: u64,
    pub entries: Vec<Entry>,
    /// IDs of deleted and replaced entries, oldest first, so that no other
    /// copy can bring them back. A v1 vault keeps them only in memory.
    tombstones: Vec<EntryId>,
    /// The link to `<vault>.sync`, for a v2 vault whose folder exists.
    sync: Option<sync::SyncLink>,
    /// What the unlock found in the sync folder, for the first status line.
    unlock_notice: Option<SyncNotice>,
    /// The key file is inside the sync folder: never link this session.
    sync_refused: bool,
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
        if password.len() > 1024 {
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
        // A malformed code fails before the slow key derivation.
        if key_bytes.starts_with(KEY_MAGIC) && !otp_format(input) {
            return Err(AUTH_ERROR);
        }
        let (id, key, otp) = decode_key(&key_bytes, password)?;
        let data = read_bounded(&source, MAX_FILE)?;
        let (format, contents) = decode_data(&id, &key, &data)?;
        // A synced copy is merged (in memory) before the OTP check, so that a
        // code already used on another PC is refused once its content synced.
        let pending = sync::Pending::find(
            destination.is_none(),
            &source,
            &key_path,
            format,
            &id,
            &key,
            contents.view(),
        );
        let Contents {
            last,
            generation,
            seen,
            entries,
            tombstones,
        } = contents;
        let step = match &otp {
            Some(secret) => otp::verify(
                secret.as_slice(),
                input,
                otp::now()?,
                Some(pending.last(last)),
            )
            .map_err(|_| AUTH_ERROR)?,
            None => last,
        };
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
        // A backup or restore keeps the format, IDs, tombstones and counters.
        let mut s = Self {
            path,
            key_path,
            id,
            key,
            otp,
            last: step,
            format,
            generation,
            seen,
            entries,
            tombstones,
            sync: None,
            unlock_notice: None,
            sync_refused: false,
            key_bytes,
            _locks: locks,
        };
        // Only now that the code passed: save a merge that changed anything,
        // with the consumed OTP. If that fails it opens unmerged instead.
        let merged = s.settle(pending);
        // Persist the consumed OTP before exposing any secret. Backup rollback
        // and modified clients cannot be prevented by this local watermark.
        // Without an OTP an unlock changes nothing, so only a restore writes.
        if !merged && (destination.is_some() || s.otp.is_some()) {
            atomic_write(&s.path, &s.encode()?, destination.is_none())?;
        }
        // Outgoing only after the vault file: the server never holds content
        // the file lacks.
        s.flush_outgoing();
        Ok(s)
    }
    fn data(&self) -> DataRef<'_> {
        DataRef {
            last: self.last,
            generation: self.generation,
            seen: self.seen,
            entries: &self.entries,
            tombstones: &self.tombstones,
        }
    }
    fn encode(&self) -> Result<Vec<u8>> {
        encode_data(&self.id, &self.key, self.format, self.data())
    }
    pub fn save(&self) -> Result<()> {
        atomic_write(&self.path, &self.encode()?, true)
    }
    /// Adds an entry (`None`) or replaces entry `index`. An edit gets a new
    /// ID whose parent is the old one, and the old ID becomes a tombstone: a
    /// copy synced from another PC can then neither bring the old text back
    /// nor hide this edit. Saving unchanged text changes nothing.
    pub fn put(&mut self, index: Option<usize>, mut entry: Entry) -> Result<()> {
        entry.validate()?;
        let previous = self.generation;
        if let Some(i) = index {
            let old = self.entries.get(i).ok_or("항목 선택 오류")?;
            if old.same_content(&entry) {
                return Ok(());
            }
            let parent = old.id;
            if self.tombstones.len() >= MAX_TOMBSTONES {
                return Err(TOMBSTONE_LIMIT);
            }
            let generation = previous.checked_add(1).ok_or(TOMBSTONE_LIMIT)?;
            entry.id = self.fresh_id()?;
            entry.parent = parent;
            self.tombstones.push(parent);
            self.generation = generation;
            let old = std::mem::replace(&mut self.entries[i], entry);
            if let Err(e) = self.save() {
                self.entries[i] = old;
                self.tombstones.pop();
                self.generation = previous;
                return Err(e);
            }
        } else {
            if self.entries.len() >= MAX_ENTRIES {
                return Err("최대 1000개까지 저장할 수 있습니다.");
            }
            let generation = previous.checked_add(1).ok_or(TOMBSTONE_LIMIT)?;
            entry.id = self.fresh_id()?;
            entry.parent = NO_ID;
            self.entries.push(entry);
            self.generation = generation;
            if let Err(e) = self.save() {
                self.entries.pop();
                self.generation = previous;
                return Err(e);
            }
        }
        self.after_edit();
        Ok(())
    }
    /// Removes entry `i` and keeps its ID as a tombstone, so the deletion
    /// reaches the other PCs instead of their copies bringing it back.
    pub fn delete(&mut self, i: usize) -> Result<()> {
        if i >= self.entries.len() {
            return Err("항목 선택 오류");
        }
        if self.tombstones.len() >= MAX_TOMBSTONES {
            return Err(TOMBSTONE_LIMIT);
        }
        let previous = self.generation;
        let generation = previous.checked_add(1).ok_or(TOMBSTONE_LIMIT)?;
        let old = self.entries.remove(i);
        self.tombstones.push(old.id);
        self.generation = generation;
        if let Err(e) = self.save() {
            self.tombstones.pop();
            self.entries.insert(i, old);
            self.generation = previous;
            return Err(e);
        }
        self.after_edit();
        Ok(())
    }
    /// A random ID that is not zero, live or a tombstone.
    fn fresh_id(&self) -> Result<EntryId> {
        loop {
            let id = *crypto::random::<16>()?;
            if id != NO_ID && self.entry_index(&id).is_none() && !self.tombstones.contains(&id) {
                return Ok(id);
            }
        }
    }
    /// The ID of entry `i`. Unlike the index it stays valid across merges.
    pub fn entry_id(&self, i: usize) -> Option<EntryId> {
        self.entries.get(i).map(Entry::id)
    }
    pub fn entry_index(&self, id: &EntryId) -> Option<usize> {
        self.entries.iter().position(|e| e.id == *id)
    }
    /// The entry that replaced `id` by an edit, if exactly one did, so that a
    /// selection can follow an edit merged in from another PC.
    pub fn successor(&self, id: &EntryId) -> Option<usize> {
        if *id == NO_ID {
            return None;
        }
        let mut found = (0..self.entries.len()).filter(|i| self.entries[*i].parent == *id);
        match (found.next(), found.next()) {
            (Some(i), None) => Some(i),
            _ => None,
        }
    }
    pub fn format(&self) -> Format {
        self.format
    }
    /// Turns a v1 vault into v2 once the user agreed to sync it. IDs are
    /// derived as for any v1 file, so a copy converted on another PC gets the
    /// same ones and merging the two makes no duplicates. A v2 vault is left
    /// as it is. If the save fails, everything is restored and it stays v1.
    /// Then the session links to the sync folder and offers its state for
    /// the first upload; read `badge()` again afterwards.
    pub fn enable_sync(&mut self) -> Result<()> {
        let converting = self.format == Format::V1;
        if converting {
            let ids: Vec<(EntryId, EntryId)> =
                self.entries.iter().map(|e| (e.id, e.parent)).collect();
            let tombstones = std::mem::take(&mut self.tombstones);
            let (generation, seen) = (self.generation, self.seen);
            v1_ids(&self.id, &self.key, &mut self.entries);
            (self.generation, self.seen, self.format) = (1, 0, Format::V2);
            if let Err(e) = self.save() {
                for (entry, (id, parent)) in self.entries.iter_mut().zip(ids) {
                    entry.set_ids(id, parent);
                }
                self.tombstones = tombstones;
                (self.generation, self.seen, self.format) = (generation, seen, Format::V1);
                return Err(e);
            }
        }
        self.start_sync(converting);
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
    /// Whether this vault asks for an OTP code when it opens.
    pub fn uses_otp(&self) -> bool {
        self.otp.is_some()
    }
    /// The TOTP secret again, to enroll a spare phone or app before the
    /// current one is lost. Storing it as a vault entry would not help: the
    /// vault cannot be opened without the OTP. The vault is already open, but
    /// the password is asked again so a window left open does not hand out
    /// the OTP.
    pub fn otp_setup(&self, password: &str) -> Result<OtpSetup> {
        let otp = self.otp.as_ref().ok_or("이 금고는 OTP를 쓰지 않습니다.")?;
        if password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        let _verified = decode_key(&self.key_bytes, password)?;
        Ok(OtpSetup {
            id: self.id,
            otp: boxed(otp),
        })
    }
    pub fn tag(&self) -> String {
        tag(&self.id)
    }
    /// `input` is the phone's current code; ignored without an OTP.
    pub fn change_password(&mut self, current: &str, password: &str, input: &str) -> Result<()> {
        password_policy(password)?;
        if current.len() > 1024 || (self.otp.is_some() && !otp_format(input)) {
            return Err(AUTH_ERROR);
        }
        let _lock = FileLock::acquire(&self.key_path)?;
        if read_bounded(&self.key_path, 1024)? != self.key_bytes {
            return Err("열쇠 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.");
        }
        let _verified = decode_key(&self.key_bytes, current)?;
        let step = match &self.otp {
            Some(secret) => otp::verify(secret.as_slice(), input, otp::now()?, Some(self.last))
                .map_err(|_| AUTH_ERROR)?,
            None => self.last,
        };
        let bytes = encode_key(&self.id, &self.key, self.otp.as_deref(), password)?;
        // Only the OTP watermark changes. That is never synced, so the
        // content counter stays.
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

fn otp_format(input: &str) -> bool {
    input.len() == 6 && input.bytes().all(|b| b.is_ascii_digit())
}
/// GOYOKE01 (148 bytes) holds the data key and the TOTP secret, GOYOKE02
/// (128 bytes) the data key only. The magic is part of the authenticated
/// header, so one kind cannot be passed off as the other.
fn encode_key(
    id: &[u8; 16],
    key: &[u8; 32],
    otp: Option<&Zeroizing<[u8; 20]>>,
    password: &str,
) -> Result<Vec<u8>> {
    let salt = crypto::random::<32>()?;
    let nonce = crypto::random::<24>()?;
    let wrapping = crypto::derive(password.as_bytes(), &salt)?;
    let mut header = Vec::with_capacity(148);
    header.extend_from_slice(if otp.is_some() {
        KEY_MAGIC
    } else {
        KEY_MAGIC_NO_OTP
    });
    header.extend_from_slice(id);
    header.extend_from_slice(salt.as_slice());
    header.extend_from_slice(nonce.as_slice());
    let mut plain = Zeroizing::new([0u8; 52]);
    plain[..32].copy_from_slice(key);
    let used = match otp {
        Some(secret) => {
            plain[32..].copy_from_slice(secret.as_slice());
            52
        }
        None => 32,
    };
    let ciphertext = crypto::seal(&wrapping, &nonce, &header, &plain[..used])?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}
type KeyMaterial = ([u8; 16], Box<Key>, Option<Box<Zeroizing<[u8; 20]>>>);
fn decode_key(data: &[u8], password: &str) -> Result<KeyMaterial> {
    let with_otp = match (data.len(), data.get(..8)) {
        (148, Some(m)) if m == KEY_MAGIC => true,
        (128, Some(m)) if m == KEY_MAGIC_NO_OTP => false,
        _ => return Err(AUTH_ERROR),
    };
    let id = data[8..24].try_into().unwrap();
    let salt = data[24..56].try_into().unwrap();
    let nonce = data[56..80].try_into().unwrap();
    let wrapping = crypto::derive(password.as_bytes(), salt)?;
    let plain = crypto::open(&wrapping, nonce, &data[..80], &data[80..])?;
    if plain.len() != if with_otp { 52 } else { 32 } {
        return Err(AUTH_ERROR);
    }
    let mut key: Box<Key> = Box::default();
    key.copy_from_slice(&plain[..32]);
    let otp = with_otp.then(|| {
        let mut otp: Box<Zeroizing<[u8; 20]>> = Box::default();
        otp.copy_from_slice(&plain[32..]);
        otp
    });
    Ok((id, key, otp))
}
/// The decrypted contents of a vault file, or a merge result.
#[derive(Clone)]
pub(crate) struct Contents {
    pub last: u64,
    pub generation: u64,
    pub seen: u64,
    pub entries: Vec<Entry>,
    pub tombstones: Vec<EntryId>,
}
impl Contents {
    pub(crate) fn view(&self) -> DataRef<'_> {
        DataRef {
            last: self.last,
            generation: self.generation,
            seen: self.seen,
            entries: &self.entries,
            tombstones: &self.tombstones,
        }
    }
}
/// What `encode_data` writes, borrowed from a session or from `Contents`.
#[derive(Clone, Copy)]
pub(crate) struct DataRef<'a> {
    pub last: u64,
    pub generation: u64,
    pub seen: u64,
    pub entries: &'a [Entry],
    pub tombstones: &'a [EntryId],
}
/// Plaintext length of a file with these entries and `tombstones`
/// tombstones; the file adds 64 bytes. Entries must be validated.
pub(crate) fn plain_size(format: Format, entries: &[Entry], tombstones: usize) -> usize {
    let text: usize = entries
        .iter()
        .map(|e| e.fields().iter().map(|s| s.len()).sum::<usize>())
        .sum();
    match format {
        Format::V1 => 12 + 16 * entries.len() + text,
        Format::V2 => 28 + 48 * entries.len() + text + 4 + 16 * tombstones,
    }
}
/// First 16 bytes of HMAC-SHA256 under the data key over `label`, `prefix`
/// and the four fields. Keyed, so an ID reveals nothing about the text.
pub(crate) fn derived_id(
    key: &[u8; 32],
    label: &[u8],
    prefix: &[u8],
    fields: [&str; 4],
) -> EntryId {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(label);
    mac.update(prefix);
    for field in fields {
        mac.update(&(field.len() as u32).to_le_bytes());
        mac.update(field.as_bytes());
    }
    let mut hash = mac.finalize().into_bytes();
    let mut id: EntryId = hash[..16].try_into().unwrap();
    hash.as_mut_slice().zeroize();
    if id == NO_ID {
        id[0] = 1;
    }
    id
}
/// IDs for the entries of a v1 file, which stores none. They depend only on
/// the vault and the text, so two PCs that turn on sync for copies of the
/// same v1 vault get the same IDs. `k` tells apart entries whose four fields
/// are all equal.
fn v1_ids(vault: &[u8; 16], key: &[u8; 32], entries: &mut [Entry]) {
    let ids: Vec<EntryId> = {
        // Keys borrow the text: counting copies no secret.
        let mut earlier: BTreeMap<[&str; 4], u32> = BTreeMap::new();
        entries
            .iter()
            .map(|e| {
                let k = earlier.entry(e.fields()).or_insert(0);
                let mut prefix = [0u8; 20];
                prefix[..16].copy_from_slice(vault);
                prefix[16..].copy_from_slice(&k.to_le_bytes());
                *k += 1;
                derived_id(key, b"goyo v1 entry\0", &prefix, e.fields())
            })
            .collect()
    };
    for (e, id) in entries.iter_mut().zip(ids) {
        e.set_ids(id, NO_ID);
    }
}
/// The rules `decode_data` enforces on v2 IDs. `encode_data` checks them
/// too: a vault it could not read back would be lost.
fn check_ids(entries: &[Entry], tombstones: &[EntryId]) -> Result<()> {
    if tombstones.len() > MAX_TOMBSTONES {
        return Err(TOMBSTONE_LIMIT);
    }
    let mut live = BTreeSet::new();
    if entries.iter().any(|e| e.id == NO_ID || !live.insert(e.id)) {
        return Err("항목 ID 오류");
    }
    let mut dead = BTreeSet::new();
    if tombstones
        .iter()
        .any(|t| *t == NO_ID || live.contains(t) || !dead.insert(*t))
    {
        return Err("항목 ID 오류");
    }
    Ok(())
}
/// GOYOVA01 holds the OTP watermark and the entries. GOYOVA02 adds each
/// entry's ID and parent, `generation`, `seen` and the tombstones; V1
/// leaves those out.
fn encode_data(id: &[u8; 16], key: &[u8; 32], format: Format, d: DataRef) -> Result<Vec<u8>> {
    if d.entries.len() > MAX_ENTRIES {
        return Err("항목 수 제한 초과");
    }
    if format == Format::V2 {
        check_ids(d.entries, d.tombstones)?;
    }
    for e in d.entries {
        e.validate()?;
    }
    let size = plain_size(format, d.entries, d.tombstones.len());
    if size + 64 > MAX_FILE {
        return Err("금고 용량 제한(8 MiB)을 초과했습니다.");
    }
    let v2 = format == Format::V2;
    let mut plain = Zeroizing::new(Vec::with_capacity(size));
    plain.extend_from_slice(&d.last.to_le_bytes());
    if v2 {
        plain.extend_from_slice(&d.generation.to_le_bytes());
        plain.extend_from_slice(&d.seen.to_le_bytes());
    }
    plain.extend_from_slice(&(d.entries.len() as u32).to_le_bytes());
    for e in d.entries {
        if v2 {
            plain.extend_from_slice(&e.id);
            plain.extend_from_slice(&e.parent);
        }
        for s in e.fields() {
            plain.extend_from_slice(&(s.len() as u32).to_le_bytes());
            plain.extend_from_slice(s.as_bytes());
        }
    }
    if v2 {
        plain.extend_from_slice(&(d.tombstones.len() as u32).to_le_bytes());
        for t in d.tombstones {
            plain.extend_from_slice(t);
        }
    }
    let nonce = crypto::random::<24>()?;
    let mut header = Vec::with_capacity(size + 64);
    header.extend_from_slice(if v2 { DATA_MAGIC_V2 } else { DATA_MAGIC_V1 });
    header.extend_from_slice(id);
    header.extend_from_slice(nonce.as_slice());
    let cipher = crypto::seal(key, &nonce, &header, &plain)?;
    header.extend_from_slice(&cipher);
    Ok(header)
}
/// Either format. A v1 file gets `v1_ids`, no tombstones and zero counters.
fn decode_data(id: &[u8; 16], key: &[u8; 32], data: &[u8]) -> Result<(Format, Contents)> {
    if newer_format(data) {
        return Err(NEWER_FORMAT);
    }
    // 48-byte header, 16-byte tag and the smallest plaintext.
    let (format, min) = match data.get(..8) {
        Some(m) if m == DATA_MAGIC_V1 => (Format::V1, 76),
        Some(m) if m == DATA_MAGIC_V2 => (Format::V2, 96),
        _ => return Err(AUTH_ERROR),
    };
    if data.len() < min || data.len() > MAX_FILE || &data[8..24] != id {
        return Err(AUTH_ERROR);
    }
    let v2 = format == Format::V2;
    let plain = crypto::open(
        key,
        data[24..48].try_into().unwrap(),
        &data[..48],
        &data[48..],
    )?;
    let mut r = Reader(&plain);
    let last = r.u64()?;
    let (generation, seen) = if v2 { (r.u64()?, r.u64()?) } else { (0, 0) };
    let count = r.num()?;
    if count > MAX_ENTRIES {
        return Err(AUTH_ERROR);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let ids = if v2 {
            (r.id()?, r.id()?)
        } else {
            (NO_ID, NO_ID)
        };
        let e = Entry {
            id: ids.0,
            parent: ids.1,
            title: r.text(256)?,
            kind: r.text(64)?,
            secret: r.text(MAX_TEXT)?,
            notes: r.text(MAX_TEXT)?,
        };
        if v2 {
            e.validate().map_err(|_| AUTH_ERROR)?;
        } else {
            e.validate()?;
        }
        entries.push(e);
    }
    let mut tombstones = Vec::new();
    if v2 {
        let count = r.num()?;
        if count > MAX_TOMBSTONES {
            return Err(AUTH_ERROR);
        }
        tombstones.reserve_exact(count);
        for _ in 0..count {
            tombstones.push(r.id()?);
        }
        check_ids(&entries, &tombstones).map_err(|_| AUTH_ERROR)?;
    }
    if !r.0.is_empty() {
        return Err(AUTH_ERROR);
    }
    if !v2 {
        v1_ids(id, key, &mut entries);
    }
    let contents = Contents {
        last,
        generation,
        seen,
        entries,
        tombstones,
    };
    Ok((format, contents))
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
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn id(&mut self) -> Result<EntryId> {
        Ok(self.take(16)?.try_into().unwrap())
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
        // The rename is only metadata. Flush the file under its final name so a
        // power cut right after "saved" cannot undo it (FAT/exFAT included).
        if let Ok(f) = OpenOptions::new().write(true).open(path) {
            let _ = f.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Whether an interrupted save left `<path>.<random>.goyotmp` next to `path`.
/// When the main file is missing, that temp file may be the only full copy.
pub fn leftover_temp(path: &Path) -> bool {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let prefix = format!("{}.", name.to_string_lossy().to_lowercase());
    fs::read_dir(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    })
    .map(|entries| {
        entries.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().to_lowercase();
            n.starts_with(&prefix) && n.ends_with(".goyotmp")
        })
    })
    .unwrap_or(false)
}
#[cfg(windows)]
fn publish(temp: &Path, target: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        fn GetLastError() -> u32;
    }
    let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    if from[..from.len() - 1].contains(&0) || to[..to.len() - 1].contains(&0) {
        return Err("올바르지 않은 파일 경로");
    }
    // Same-directory rename; atomic no-clobber when REPLACE_EXISTING is absent.
    // Unlike hard links this also supports common removable FAT/exFAT volumes.
    // Any open handle on the target, even a virus scanner's or a reader's
    // with full sharing, makes it fail with ACCESS_DENIED (5) or
    // SHARING_VIOLATION (32) until closed: retry for at most 100 ms.
    for retry in 0..=5 {
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 8 | u32::from(replace)) } != 0 {
            return Ok(());
        }
        if retry == 5 || !matches!(unsafe { GetLastError() }, 5 | 32) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err("파일 저장/교체 실패: 기존 파일, 저장장치 연결과 쓰기 권한을 확인하세요.")
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
                // Sync folders (<vault>.sync) are the only folders tests make.
                if e.file_type().unwrap().is_dir()
                    && e.file_name().to_string_lossy().ends_with(".sync")
                {
                    let _ = fs::remove_dir_all(e.path());
                    continue;
                }
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
    fn v1(last: u64, entries: &[Entry]) -> DataRef<'_> {
        DataRef {
            last,
            generation: 0,
            seen: 0,
            entries,
            tombstones: &[],
        }
    }
    /// A session on `path` without a key file or lock, so tests of the
    /// entry rules skip the slow key derivation. Loads `path` if it exists.
    fn bare(path: PathBuf, id: [u8; 16], key: [u8; 32]) -> Session {
        let mut s = Session {
            path,
            key_path: PathBuf::from("unused.goyokey"),
            id,
            key: Box::new(Zeroizing::new(key)),
            otp: None,
            last: 0,
            format: Format::V1,
            generation: 0,
            seen: 0,
            entries: Vec::new(),
            tombstones: Vec::new(),
            sync: None,
            unlock_notice: None,
            sync_refused: false,
            key_bytes: Vec::new(),
            _locks: Vec::new(),
        };
        if let Ok(data) = fs::read(&s.path) {
            let (format, c) = decode_data(&id, &key, &data).unwrap();
            s.format = format;
            (s.last, s.generation, s.seen) = (c.last, c.generation, c.seen);
            (s.entries, s.tombstones) = (c.entries, c.tombstones);
        }
        s
    }
    /// Everything a failed save must restore.
    type Snapshot = (
        Vec<(EntryId, EntryId, String)>,
        Vec<EntryId>,
        u64,
        u64,
        Format,
    );
    fn snapshot(s: &Session) -> Snapshot {
        let entries = s
            .entries
            .iter()
            .map(|e| (e.id, e.parent, e.fields().concat()));
        (
            entries.collect(),
            s.tombstones.clone(),
            s.generation,
            s.seen,
            s.format,
        )
    }
    fn ids(entries: &[Entry]) -> Vec<EntryId> {
        entries.iter().map(Entry::id).collect()
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
        assert!(p.finish(&v, &k, "short", Some(&input)).is_err());
        assert!(!v.exists() && !k.exists());
        let mut s = p.finish(&v, &k, pass, Some(&input)).unwrap();
        assert!(s.uses_otp() && fs::read(&k).unwrap().len() == 148);
        assert_eq!(key_uses_otp(&k), Some(true));
        let setup = s.otp_setup(pass).unwrap();
        assert_eq!(setup.code(), p.setup_code());
        assert!(setup.uri().contains(p.setup_code().as_str()));
        // Each vault is its own authenticator account; the URI still fits the QR.
        assert_eq!(vault_tag(&v), Some(s.tag()));
        assert_eq!(setup.tag(), s.tag());
        assert!(setup.uri().contains(&format!("Goyo%20Vault:{}?", s.tag())));
        assert!(setup.uri().len() <= crate::qr::CAPACITY);
        assert!(!leftover_temp(&v));
        fs::write(t.file("vault.goyo.0123.goyotmp"), b"synthetic").unwrap();
        assert!(leftover_temp(&v) && !leftover_temp(&k));
        fs::remove_file(t.file("vault.goyo.0123.goyotmp")).unwrap();
        assert_eq!(
            s.otp_setup("wrong synthetic password").err(),
            Some(AUTH_ERROR)
        );
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
        let old_backup = encode_data(
            &p.id,
            &p.key,
            Format::V1,
            v1(0, &[entry("restore snapshot")]),
        )
        .unwrap();
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
    fn vault_without_otp() {
        let t = Temp::new();
        let v = t.file("vault.goyo");
        let k = t.file("key.goyokey");
        let b = t.file("backup.goyo");
        let restored = t.file("restored.goyo");
        let pass = "a long synthetic password";
        let changed = "another synthetic password";
        let p = Provision::new().unwrap();
        let mut s = p.finish(&v, &k, pass, None).unwrap();
        assert!(!s.uses_otp());
        assert_eq!(key_uses_otp(&k), Some(false));
        assert_eq!(fs::read(&k).unwrap().len(), 128);
        assert_eq!(
            s.otp_setup(pass).err(),
            Some("이 금고는 OTP를 쓰지 않습니다.")
        );
        s.put(None, entry("no otp secret")).unwrap();
        s.backup(&b).unwrap();
        // Any code, or none, is ignored when the vault has no OTP.
        s.change_password(pass, changed, "").unwrap();
        assert!(
            decode_key(&fs::read(&k).unwrap(), changed)
                .unwrap()
                .2
                .is_none()
        );
        assert_eq!(key_uses_otp(&k), Some(false));
        drop(s);
        let before = fs::read(&v).unwrap();
        assert_eq!(Session::unlock(&v, &k, pass, "").err(), Some(AUTH_ERROR));
        let s = Session::unlock(&v, &k, changed, "").unwrap();
        assert_eq!(&*s.entries[0].secret, "no otp secret");
        // Opening again is fine (no code to consume), and nothing was rewritten.
        drop(s);
        let s = Session::unlock(&v, &k, changed, "123456").unwrap();
        drop(s);
        assert_eq!(fs::read(&v).unwrap(), before);
        let rs = Session::restore(&b, &k, &restored, changed, "").unwrap();
        assert_eq!(&*rs.entries[0].secret, "no otp secret");
        drop(rs);
        // An OTP vault still needs its code, before any key derivation.
        let q = Provision::new().unwrap();
        let (v2, k2) = (t.file("otp.goyo"), t.file("otp.goyokey"));
        let code = format!(
            "{:06}",
            otp::code(q.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        drop(q.finish(&v2, &k2, pass, Some(&code)).unwrap());
        assert_eq!(Session::unlock(&v2, &k2, pass, "").err(), Some(AUTH_ERROR));
        assert_eq!(key_uses_otp(&t.file("missing.goyokey")), None);
        assert_eq!(key_uses_otp(&v), None);
    }
    #[test]
    fn restore_needs_no_sidecars_next_to_inputs() {
        let t = Temp::new();
        let src = t.file("readonly-backup.goyo");
        let key = t.file("readonly-key.goyokey");
        let out = t.file("new.goyo");
        let p = Provision::new().unwrap();
        let pass = "readonly test password";
        fs::write(&key, encode_key(&p.id, &p.key, Some(&p.otp), pass).unwrap()).unwrap();
        fs::write(
            &src,
            encode_data(&p.id, &p.key, Format::V1, v1(0, &[entry("saved")])).unwrap(),
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
        // Guessable at any length: words, walks, runs, repeats, digits only.
        for weak in [
            "password1234",
            "Password1234!",
            "qwerty123456",
            "1q2w3e4r5t6y",
            "123456123456",
            "iloveyou1234",
            "qwertyuiop12",
            "abcdef123456",
            "qwerqwerqwer",
            "202610171234",
            "asdfghjkl;'12",
            "q1w2e3r4t5y6u7",
            "sunshine princess dragon football",
        ] {
            assert!(password_policy(weak).is_err(), "{weak}");
        }
        // No length at which the check stops (it used to give up past 64).
        let words = "password".repeat(9);
        assert!(password_policy(&words[..65]).is_err());
        assert!(password_policy(&"qwerty".repeat(170)).is_err()); // 1020 bytes
        for strong in [
            "dragon-tiger-lemon",
            "purple cactus 7 sing",
            "Goyo vault sits quietly",
            "a long synthetic password",
        ] {
            assert!(password_policy(strong).is_ok(), "{strong}");
        }
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
        let mut s = p.finish(&v, &k, pass, Some(&input)).unwrap();
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
        let (_, c) = decode_data(&p.id, &p.key, &fs::read(&v).unwrap()).unwrap();
        assert_eq!(c.last, s.last);
        assert_eq!(
            s.change_password(pass, next, &input).unwrap_err(),
            AUTH_ERROR
        );
    }
    #[test]
    fn authenticated_malformed_payloads_are_rejected() {
        fn wrap(p: &[u8]) -> Vec<u8> {
            let mut h = Vec::from(*DATA_MAGIC_V1);
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
    #[test]
    fn v2_structure_is_checked() {
        fn wrap(p: &[u8]) -> Vec<u8> {
            let mut h = Vec::from(*DATA_MAGIC_V2);
            h.extend_from_slice(&[1; 16]);
            h.extend_from_slice(&[2; 24]);
            let c = crypto::seal(&[3; 32], &[2; 24], &h, p).unwrap();
            h.extend(c);
            h
        }
        /// last, generation and seen, then the entry count.
        fn head(count: u32) -> Vec<u8> {
            let mut p = vec![0; 24];
            p.extend_from_slice(&count.to_le_bytes());
            p
        }
        fn add(p: &mut Vec<u8>, id: EntryId, title: &[u8]) {
            p.extend_from_slice(&id);
            p.extend_from_slice(&[9; 16]);
            let fixed = [b"kind".as_slice(), b"secret", b"notes"];
            for field in std::iter::once(title).chain(fixed) {
                p.extend_from_slice(&(field.len() as u32).to_le_bytes());
                p.extend_from_slice(field);
            }
        }
        fn bury(p: &mut Vec<u8>, ids: &[EntryId]) {
            p.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            for id in ids {
                p.extend_from_slice(id);
            }
        }
        fn file(entries: &[(EntryId, &str)], dead: &[EntryId]) -> Vec<u8> {
            let mut p = head(entries.len() as u32);
            for (id, title) in entries {
                add(&mut p, *id, title.as_bytes());
            }
            bury(&mut p, dead);
            p
        }
        let (a, b) = ([5; 16], [6; 16]);
        let good = file(&[(a, "a"), (b, "b")], &[[7; 16]]);
        let (format, c) = decode_data(&[1; 16], &[3; 32], &wrap(&good)).unwrap();
        assert_eq!(format, Format::V2);
        assert_eq!((ids(&c.entries), c.tombstones), (vec![a, b], vec![[7; 16]]));
        assert_eq!(c.entries[0].parent, [9; 16]);
        let mut trailing = good.clone();
        trailing.push(0);
        let mut untold = head(1);
        add(&mut untold, a, b"a");
        let mut garbled = head(1);
        add(&mut garbled, a, &[0xff]);
        bury(&mut garbled, &[]);
        let mut crowded = head(1001);
        bury(&mut crowded, &[]);
        let mut graveyard = head(0);
        graveyard.extend_from_slice(&65_537u32.to_le_bytes());
        for p in [
            file(&[([0; 16], "a")], &[]),
            file(&[(a, "a"), (a, "b")], &[]),
            file(&[(a, "a")], &[a]),
            file(&[(a, "a")], &[b, b]),
            file(&[(a, "a")], &[[0; 16]]),
            file(&[(a, "\0")], &[]),
            file(&[(a, " ")], &[]),
            garbled,
            trailing,
            untold,
            crowded,
            graveyard,
        ] {
            assert_eq!(
                decode_data(&[1; 16], &[3; 32], &wrap(&p)).err(),
                Some(AUTH_ERROR)
            );
        }
        // What decoding would refuse is never written.
        let mut x = entry("x");
        x.set_ids(a, NO_ID);
        let mut y = entry("y");
        let v2 = |entries: &[Entry], tombstones: &[EntryId]| {
            let d = DataRef {
                last: 0,
                generation: 1,
                seen: 0,
                entries,
                tombstones,
            };
            encode_data(&[1; 16], &[3; 32], Format::V2, d).err()
        };
        assert_eq!(v2(&[x.clone(), y.clone()], &[]), Some("항목 ID 오류"));
        y.set_ids(a, NO_ID);
        assert_eq!(v2(&[x.clone(), y.clone()], &[]), Some("항목 ID 오류"));
        assert_eq!(v2(std::slice::from_ref(&x), &[a]), Some("항목 ID 오류"));
        assert_eq!(v2(std::slice::from_ref(&x), &[b, b]), Some("항목 ID 오류"));
        // Up to MAX_TOMBSTONES fit, and read back in order.
        let mut dead: Vec<EntryId> = (0..MAX_TOMBSTONES as u32)
            .map(|n| {
                let mut id = [0xAA; 16];
                id[..4].copy_from_slice(&n.to_le_bytes());
                id
            })
            .collect();
        let d = DataRef {
            last: 0,
            generation: 1,
            seen: 0,
            entries: std::slice::from_ref(&x),
            tombstones: &dead,
        };
        let data = encode_data(&[1; 16], &[3; 32], Format::V2, d).unwrap();
        assert_eq!(
            decode_data(&[1; 16], &[3; 32], &data).unwrap().1.tombstones,
            dead
        );
        dead.push([0xBB; 16]);
        assert_eq!(v2(std::slice::from_ref(&x), &dead), Some(TOMBSTONE_LIMIT));
        // v2 stores 32 more bytes per entry: a vault just under the size
        // limit in v1 can be over it in v2.
        let full: Vec<Entry> = (0..501)
            .map(|n| {
                let mut e = Entry::new(
                    "t".repeat(256),
                    "k".repeat(64),
                    "s".repeat(MAX_TEXT),
                    "n".repeat(MAX_TEXT),
                )
                .unwrap();
                let mut id = [1; 16];
                id[..4].copy_from_slice(&(n as u32).to_le_bytes());
                e.set_ids(id, NO_ID);
                e
            })
            .collect();
        assert!(encode_data(&[1; 16], &[3; 32], Format::V1, v1(0, &full)).is_ok());
        assert_eq!(
            v2(&full, &[]),
            Some("금고 용량 제한(8 MiB)을 초과했습니다.")
        );
    }
    #[test]
    fn put_and_delete_keep_ids_and_tombstones() {
        let t = Temp::new();
        let mut s = bare(t.file("vault.goyo"), [1; 16], [2; 32]);
        s.save().unwrap();
        s.put(None, entry("one")).unwrap();
        s.put(None, entry("two")).unwrap();
        assert_eq!(s.generation, 2);
        assert!(s.entries.iter().all(|e| e.id != NO_ID && e.parent == NO_ID));
        assert_ne!(s.entry_id(0), s.entry_id(1));
        // A vault without sync stays v1 and keeps tombstones only in memory.
        s.put(Some(1), entry("two, edited")).unwrap();
        assert_eq!(s.tombstones.len(), 1);
        assert_eq!(&fs::read(&s.path).unwrap()[..8], DATA_MAGIC_V1);
        let reopened = bare(s.path.clone(), [1; 16], [2; 32]);
        assert_eq!(reopened.format(), Format::V1);
        assert!(reopened.tombstones.is_empty() && reopened.generation == 0);
        s.enable_sync().unwrap();
        assert_eq!(s.generation, 1);
        let (one, two) = (s.entry_id(0).unwrap(), s.entry_id(1).unwrap());

        // Saving unchanged text saves nothing, not even into a missing folder.
        let actual = s.path.clone();
        let saved = fs::read(&actual).unwrap();
        let before = snapshot(&s);
        s.path = t.file("missing-folder").join("failed.goyo");
        s.put(Some(0), entry("one")).unwrap();
        assert_eq!(snapshot(&s), before);
        // A failed save restores entries, tombstones and the counter exactly.
        assert!(s.put(Some(0), entry("changed")).is_err());
        assert_eq!(snapshot(&s), before);
        assert!(s.put(None, entry("three")).is_err());
        assert_eq!(snapshot(&s), before);
        assert!(s.delete(1).is_err());
        assert_eq!(snapshot(&s), before);
        s.path = actual;
        assert_eq!(fs::read(&s.path).unwrap(), saved);
        assert_eq!(s.put(Some(5), entry("x")).err(), Some("항목 선택 오류"));
        assert_eq!(s.delete(5).err(), Some("항목 선택 오류"));

        // An edit: a new ID, the old one as parent and tombstone, count + 1.
        s.put(Some(0), entry("changed")).unwrap();
        let edited = s.entry_id(0).unwrap();
        assert!(edited != one && edited != NO_ID);
        assert_eq!(s.entries[0].parent, one);
        assert_eq!((s.tombstones.clone(), s.generation), (vec![one], 2));
        assert_eq!(s.entry_index(&one), None);
        assert_eq!(s.entry_index(&edited), Some(0));
        assert_eq!(s.successor(&one), Some(0));
        assert_eq!(s.successor(&two), None);
        assert_eq!(s.successor(&NO_ID), None);
        // A delete: the ID becomes a tombstone, count + 1.
        s.delete(1).unwrap();
        assert_eq!((s.tombstones.clone(), s.generation), (vec![one, two], 3));
        // The file holds the same.
        let reopened = bare(s.path.clone(), [1; 16], [2; 32]);
        assert_eq!(snapshot(&reopened), snapshot(&s));
        assert_eq!(&fs::read(&s.path).unwrap()[..8], DATA_MAGIC_V2);
        // Two entries that replaced the same one: no single successor.
        let mut twin = s.entries[0].clone();
        twin.id = [3; 16];
        s.entries.push(twin);
        assert_eq!(s.successor(&one), None);
        s.entries.pop();

        // At the tombstone limit edits and deletes are refused unchanged;
        // adding still works because it leaves no tombstone.
        s.tombstones = (0..MAX_TOMBSTONES as u32)
            .map(|n| {
                let mut id = [0xAA; 16];
                id[..4].copy_from_slice(&n.to_le_bytes());
                id
            })
            .collect();
        let before = snapshot(&s);
        assert_eq!(s.put(Some(0), entry("again")).err(), Some(TOMBSTONE_LIMIT));
        assert_eq!(s.delete(0).err(), Some(TOMBSTONE_LIMIT));
        assert_eq!(snapshot(&s), before);
        s.put(None, entry("new")).unwrap();
        assert_eq!(s.tombstones.len(), MAX_TOMBSTONES);
    }
    #[test]
    fn enable_sync_converts_once() {
        let t = Temp::new();
        let mut s = bare(t.file("vault.goyo"), [1; 16], [2; 32]);
        s.save().unwrap();
        for value in ["twin", "twin", "other"] {
            s.put(None, entry(value)).unwrap();
        }
        s.put(Some(2), entry("edited")).unwrap();
        let v1_file = fs::read(&s.path).unwrap();
        let (_, from_file) = decode_data(&s.id, &s.key, &v1_file).unwrap();
        assert!(from_file.tombstones.is_empty());
        // A failed save restores everything; the vault stays v1.
        let before = snapshot(&s);
        let actual = s.path.clone();
        s.path = t.file("missing-folder").join("failed.goyo");
        assert!(s.enable_sync().is_err());
        assert_eq!(snapshot(&s), before);
        assert_eq!(s.format(), Format::V1);
        s.path = actual;
        assert_eq!(fs::read(&s.path).unwrap(), v1_file);
        s.enable_sync().unwrap();
        // The IDs any PC derives from this v1 file, no history, count 1.
        assert_eq!(ids(&s.entries), ids(&from_file.entries));
        assert!(s.entries.iter().all(|e| e.parent == NO_ID));
        assert!(s.tombstones.is_empty());
        assert_eq!((s.format(), s.generation, s.seen), (Format::V2, 1, 0));
        let reopened = bare(s.path.clone(), [1; 16], [2; 32]);
        assert_eq!(snapshot(&reopened), snapshot(&s));
        assert_eq!(vault_tag(&s.path), Some(s.tag()));
        // Turning sync on again changes nothing.
        let v2_file = fs::read(&s.path).unwrap();
        s.enable_sync().unwrap();
        assert_eq!(fs::read(&s.path).unwrap(), v2_file);
        // A PC that turns sync on for a copy of the same v1 file merges with
        // this one without duplicates.
        fs::write(t.file("copy.goyo"), &v1_file).unwrap();
        let mut other = bare(t.file("copy.goyo"), [1; 16], [2; 32]);
        other.enable_sync().unwrap();
        let (_, remote) = decode_data(&s.id, &s.key, &fs::read(&other.path).unwrap()).unwrap();
        let (merged, report) = crate::merge::merge(&s.key, s.data(), remote, 0).unwrap();
        assert!(report.added == 0 && report.removed == 0 && report.conflicts == 0);
        assert!(!report.changed && !report.needs_push);
        assert_eq!(ids(&merged.entries), ids(&s.entries));
        // vault_tag reads both formats and nothing newer.
        let mut newer = v2_file.clone();
        newer[..8].copy_from_slice(b"GOYOVA03");
        fs::write(t.file("newer.goyo"), &newer).unwrap();
        assert_eq!(vault_tag(&t.file("copy.goyo")), Some(s.tag()));
        assert_eq!(vault_tag(&t.file("newer.goyo")), None);
        fs::write(t.file("old.goyo"), &v1_file).unwrap();
        assert_eq!(vault_tag(&t.file("old.goyo")), Some(s.tag()));
    }
    #[test]
    fn restore_and_backup_keep_sync_state() {
        let t = Temp::new();
        let p = Provision::new().unwrap();
        let pass = "synthetic sync password";
        let key = t.file("sync.goyokey");
        fs::write(&key, encode_key(&p.id, &p.key, Some(&p.otp), pass).unwrap()).unwrap();
        let mut es = vec![entry("kept"), entry("edited")];
        es[0].set_ids([5; 16], NO_ID);
        es[1].set_ids([6; 16], [4; 16]);
        let tombstones = [[4; 16], [3; 16]];
        let d = DataRef {
            last: 0,
            generation: 9,
            seen: 8,
            entries: &es,
            tombstones: &tombstones,
        };
        let src = t.file("synced.goyo");
        fs::write(&src, encode_data(&p.id, &p.key, Format::V2, d).unwrap()).unwrap();
        let check = |c: &Contents| {
            assert_eq!(ids(&c.entries), [[5; 16], [6; 16]]);
            assert_eq!(c.entries[1].parent, [4; 16]);
            assert_eq!(c.tombstones, tombstones);
            assert_eq!((c.generation, c.seen), (9, 8));
        };
        let input = format!(
            "{:06}",
            otp::code(p.otp.as_slice(), otp::now().unwrap() / 30, 6)
        );
        let out = t.file("restored.goyo");
        let mut s = Session::restore(&src, &key, &out, pass, &input).unwrap();
        assert_eq!(s.format(), Format::V2);
        // The used OTP code is the only change written.
        let (format, c) = decode_data(&p.id, &p.key, &fs::read(&out).unwrap()).unwrap();
        assert!(format == Format::V2 && c.last > 0);
        check(&c);
        let b = t.file("backup.goyo");
        s.backup(&b).unwrap();
        let (format, c) = decode_data(&p.id, &p.key, &fs::read(&b).unwrap()).unwrap();
        assert_eq!(format, Format::V2);
        check(&c);
        // A password change, too, writes only the OTP watermark: no content
        // change, so nothing to upload.
        s.last = 0; // simulate a later interval without sleeping
        s.change_password(pass, "another synthetic sync password", &input)
            .unwrap();
        let (format, c) = decode_data(&p.id, &p.key, &fs::read(&out).unwrap()).unwrap();
        assert!(format == Format::V2 && c.last > 0);
        check(&c);
        drop(s);
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
        let data = encode_data(&[1; 16], &[2; 32], Format::V1, v1(7, &es)).unwrap();
        assert!(!data.windows(13).any(|s| s == b"private words"));
        let (format, got) = decode_data(&[1; 16], &[2; 32], &data).unwrap();
        assert_eq!((format, got.last), (Format::V1, 7));
        assert_eq!(&*got.entries[0].secret, "private words");
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
    fn v1(last: u64, entries: &[Entry]) -> DataRef<'_> {
        DataRef {
            last,
            generation: 0,
            seen: 0,
            entries,
            tombstones: &[],
        }
    }
    fn entry(title: &str, secret: &str) -> Entry {
        Entry::new(title.into(), String::new(), secret.into(), String::new()).unwrap()
    }
    fn ids(entries: &[Entry]) -> Vec<EntryId> {
        entries.iter().map(Entry::id).collect()
    }
    #[test]
    fn v2_round_trip_and_binding() {
        let mut es = vec![entry("메일", "private words"), entry("bank", "pin")];
        es[0].set_ids([5; 16], NO_ID);
        es[1].set_ids([6; 16], [9; 16]);
        let d = DataRef {
            last: 7,
            generation: 11,
            seen: 10,
            entries: &es,
            tombstones: &[[9; 16], [8; 16]],
        };
        let data = encode_data(&[1; 16], &[2; 32], Format::V2, d).unwrap();
        assert_eq!(&data[..24], [&DATA_MAGIC_V2[..], &[1u8; 16][..]].concat());
        assert!(!data.windows(13).any(|s| s == b"private words"));
        let (format, c) = decode_data(&[1; 16], &[2; 32], &data).unwrap();
        assert_eq!(format, Format::V2);
        assert_eq!((c.last, c.generation, c.seen), (7, 11, 10));
        assert_eq!(ids(&c.entries), [[5; 16], [6; 16]]);
        assert_eq!(c.entries[1].parent, [9; 16]);
        assert_eq!(c.tombstones, [[9; 16], [8; 16]]);
        assert_eq!(&*c.entries[0].secret, "private words");
        assert!(c.entries[1].same_content(&es[1]));
        assert!(decode_data(&[3; 16], &[2; 32], &data).is_err());
        assert!(decode_data(&[1; 16], &[3; 32], &data).is_err());
        for n in 0..data.len() {
            assert!(decode_data(&[1; 16], &[2; 32], &data[..n]).is_err());
        }
        for i in 0..data.len() {
            let mut bad = data.clone();
            bad[i] ^= 1;
            assert!(decode_data(&[1; 16], &[2; 32], &bad).is_err());
        }
        // The magic is authenticated: a v2 file relabelled v1 is refused.
        let mut relabelled = data.clone();
        relabelled[..8].copy_from_slice(DATA_MAGIC_V1);
        assert_eq!(
            decode_data(&[1; 16], &[2; 32], &relabelled).err(),
            Some(AUTH_ERROR)
        );
        // A newer format is named before any decryption, whatever the key.
        for magic in [b"GOYOVA03", b"GOYOVA10", b"GOYOVA99"] {
            let mut newer = data.clone();
            newer[..8].copy_from_slice(magic);
            assert_eq!(
                decode_data(&[3; 16], &[4; 32], &newer).err(),
                Some(NEWER_FORMAT)
            );
            assert_eq!(
                decode_data(&[3; 16], &[4; 32], &newer[..8]).err(),
                Some(NEWER_FORMAT)
            );
        }
        for magic in [b"GOYOVA00", b"GOYOVA0x", b"GOYOVB03", b"goyova03"] {
            let mut other = data.clone();
            other[..8].copy_from_slice(magic);
            assert_eq!(
                decode_data(&[1; 16], &[2; 32], &other).err(),
                Some(AUTH_ERROR)
            );
        }
    }
    #[test]
    fn v1_ids_are_deterministic() {
        let es = vec![
            entry("same", "secret"),
            entry("other", "secret"),
            entry("same", "secret"),
        ];
        let decode = |vault: &[u8; 16], key: &[u8; 32]| {
            let data = encode_data(vault, key, Format::V1, v1(3, &es)).unwrap();
            assert_eq!(&data[..8], DATA_MAGIC_V1);
            let (format, c) = decode_data(vault, key, &data).unwrap();
            assert_eq!(format, Format::V1);
            assert_eq!((c.last, c.generation, c.seen), (3, 0, 0));
            assert!(c.tombstones.is_empty());
            assert!(c.entries.iter().all(|e| e.parent == NO_ID));
            c
        };
        let a = decode(&[1; 16], &[2; 32]);
        // Every PC must derive the same IDs: vectors from Python's hmac.
        let hex = |id: EntryId| id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(a.entries[0].id), "734a865baafcdaf1039def39f95542fb");
        assert_eq!(hex(a.entries[2].id), "c1255ba186ea1086a39b1688aa77e307");
        // Stable across encodings (each with a new nonce) and decodes.
        assert_eq!(ids(&a.entries), ids(&decode(&[1; 16], &[2; 32]).entries));
        // Equal entries are told apart by occurrence; none is zero.
        let set: BTreeSet<EntryId> = ids(&a.entries).into_iter().collect();
        assert_eq!(set.len(), 3);
        assert!(!set.contains(&NO_ID));
        // Another data key or another vault derives other IDs.
        for other in [decode(&[1; 16], &[3; 32]), decode(&[4; 16], &[2; 32])] {
            assert!(ids(&other.entries).iter().all(|id| !set.contains(id)));
        }
        // v1 leaves IDs, counters and tombstones out.
        let mut changed = a.clone();
        changed.entries[0].set_ids([7; 16], [8; 16]);
        let d = DataRef {
            last: 3,
            generation: 9,
            seen: 4,
            entries: &changed.entries,
            tombstones: &[[8; 16]],
        };
        let data = encode_data(&[1; 16], &[2; 32], Format::V1, d).unwrap();
        let (_, back) = decode_data(&[1; 16], &[2; 32], &data).unwrap();
        assert_eq!(ids(&back.entries), ids(&a.entries));
        assert!(back.tombstones.is_empty() && back.generation == 0 && back.seen == 0);
    }
    #[test]
    fn key_password_and_tamper() {
        let secret = Zeroizing::new([3; 20]);
        let bytes = encode_key(&[1; 16], &[2; 32], Some(&secret), "long-test-password").unwrap();
        let (_, key, otp) = decode_key(&bytes, "long-test-password").unwrap();
        assert_eq!(**key, [2; 32]);
        assert_eq!(**otp.unwrap(), [3; 20]);
        assert!(decode_key(&bytes, "wrong-password").is_err());
        let mut bad = bytes.clone();
        bad[8] ^= 1;
        assert!(decode_key(&bad, "long-test-password").is_err());
        // Without an OTP: 128 bytes, data key only.
        let plain = encode_key(&[1; 16], &[2; 32], None, "long-test-password").unwrap();
        assert_eq!((plain.len(), &plain[..8]), (128, &b"GOYOKE02"[..]));
        let (_, key, otp) = decode_key(&plain, "long-test-password").unwrap();
        assert!(**key == [2; 32] && otp.is_none());
        // Neither kind passes as the other: the magic is authenticated, and
        // a relabelled or truncated file is refused.
        let mut relabelled = bytes.clone();
        relabelled[..8].copy_from_slice(b"GOYOKE02");
        assert!(decode_key(&relabelled, "long-test-password").is_err());
        assert!(decode_key(&relabelled[..128], "long-test-password").is_err());
        let mut relabelled = plain;
        relabelled[..8].copy_from_slice(b"GOYOKE01");
        assert!(decode_key(&relabelled, "long-test-password").is_err());
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
        // Any open handle on the target blocks the replace. One that stays
        // open fails it after about 100 ms of retries; one that closes soon
        // (a scanner, the sync helper reading a file) is waited for.
        let reader = File::open(&p).unwrap();
        let start = std::time::Instant::now();
        assert!(atomic_write(&p, b"blocked", true).is_err());
        assert!(start.elapsed() >= std::time::Duration::from_millis(80));
        let closer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            drop(reader);
        });
        atomic_write(&p, b"after retry", true).unwrap();
        closer.join().unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"after retry");
        fs::remove_file(&p).unwrap();
        fs::remove_file(dir.join("test.goyo.goyolock")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
