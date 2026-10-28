//! Key files (spec v3 §4.1-§4.8). The 0.8 formats GOYOKE01/02 hold one data
//! key. The KF2 layout holds a bundle of data keys behind the password alone
//! (GOYOKE03) or behind security keys as well (GOYOKH01, and GOYOKS01 with
//! key-file sync). One strict parser reads every KF2 magic and is the same in
//! every build. This build has no security-key code: it refuses those files
//! on their magic alone, before any key derivation, and never as a wrong
//! password.
use super::{TOO_LARGE, boxed};
use crate::{
    crypto::{self, AUTH_ERROR, Key, Result, ct_eq, hkdf_expand, hkdf_extract},
    otp,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Key file with the TOTP secret: the app also asks for the phone's code.
pub(super) const KEY_MAGIC: &[u8; 8] = b"GOYOKE01";
/// Key file without one: password and key file only.
pub(super) const KEY_MAGIC_NO_OTP: &[u8; 8] = b"GOYOKE02";
/// Largest key file any read takes. The largest KF2 file is 32,532 bytes:
/// 64 data keys, 480 tombstones, 8 security keys with 1023-byte credential
/// IDs, every pair record and an OTP.
pub const KEY_FILE_LIMIT: usize = 32_768;
/// Highest epoch. A tombstone keeps the epoch of its removal in 48 bits, so
/// a larger one would read back as another epoch with a loss mark.
pub const EPOCH_MAX: u64 = (1 << 48) - 1;
/// How far above the key file's epoch a vault file's header epoch still
/// counts (spec §4.3): whoever knows the current data key can plant a vault
/// file with any epoch, and honest ones are ahead only by a few changes.
pub const EPOCH_SILENT: u64 = 1 << 8;
/// How far above this PC's confirmed state a key file found at login may
/// lie (spec §4.1, §5.10): one planted far ahead would otherwise make every
/// later key change fail at EPOCH_MAX.
pub const EPOCH_WINDOW: u64 = 1 << 16;
/// Most tombstones a key file carries. None is ever dropped, so an old
/// credential can never come back (spec §4.1).
pub const TOMB_MAX: usize = 480;
/// Most data keys a bundle keeps; a rotation drops the oldest one that is
/// not the ID key (spec §4.2).
pub const MAX_KEYS: usize = 64;
const MAX_SLOTS: u8 = 8;
const MAX_CRED_ID: usize = 1023;
/// A committing wrap of a 32-byte secret: nonce, commitment, ciphertext and
/// tag.
const WRAP: usize = 104;
/// The seal block: `resume`, the Argon2 salt and the body nonce.
const SEAL_BLOCK: usize = 88;

pub const NEWER_KEY_FORMAT: &str =
    "더 새로운 버전에서 만든 열쇠 파일입니다. 고요 금고를 업데이트하세요.";
/// A GOYOKH01 or GOYOKS01 key file in a build without security-key support.
pub const NO_SECURITY_KEY_SUPPORT: &str = "이 열쇠 파일은 보안 키(YubiKey 등)가 있어야 열립니다. 지금 쓰는 고요 금고는 보안 키 기능이 빠진 기본 빌드라 이 파일을 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다. 보안 키 기능은 아직 실험 단계라 직접 빌드해야 합니다(docs/SECURITY_KEY.md).";
/// The same for any other GOYOKH or GOYOKS magic, or such a file that does
/// not parse: a truncated copy, or a later version's grammar.
pub const NO_SECURITY_KEY_SUPPORT_DAMAGED: &str = "이 열쇠 파일은 보안 키(YubiKey 등)가 있어야 열립니다. 지금 쓰는 고요 금고는 보안 키 기능이 빠진 기본 빌드라 이 파일을 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다. 보안 키 기능은 아직 실험 단계라 직접 빌드해야 합니다(docs/SECURITY_KEY.md). 파일이 손상되었거나 더 새로운 버전에서 만든 파일일 수도 있습니다.";
/// A key change whose epoch would pass EPOCH_MAX: nothing is written.
pub const EPOCH_LIMIT: &str =
    "열쇠 수정 번호가 한도에 닿았습니다. 새 금고를 만들어 항목을 옮기세요.";
/// A key change whose result would carry more than TOMB_MAX tombstones.
pub const TOMBSTONES_FULL: &str = "열쇠 파일의 제거 기록이 가득 찼습니다(480개). 더 이상 보안 키를 뺄 수 없습니다. 새 금고를 만들어 항목을 옮기세요.";
/// `seal` was asked for a file the strict parse would refuse.
const NOT_SEALED: &str = "새 열쇠 파일이 형식 검사를 통과하지 못해 쓰지 않았습니다.";

/// The key-file magics this build knows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Magic {
    /// 0.8, with the TOTP secret.
    Ke01,
    /// 0.8, without one.
    Ke02,
    /// KF2, password only.
    Ke03,
    /// KF2 with security keys, a local key file.
    Kh01,
    /// KF2 with security keys and key-file sync.
    Ks01,
}
impl Magic {
    const ALL: [Magic; 5] = [Self::Ke01, Self::Ke02, Self::Ke03, Self::Kh01, Self::Ks01];
    pub fn bytes(self) -> &'static [u8; 8] {
        match self {
            Self::Ke01 => KEY_MAGIC,
            Self::Ke02 => KEY_MAGIC_NO_OTP,
            Self::Ke03 => b"GOYOKE03",
            Self::Kh01 => b"GOYOKH01",
            Self::Ks01 => b"GOYOKS01",
        }
    }
    pub(crate) fn of(magic: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.bytes() == magic)
    }
    /// GOYOKH01 or GOYOKS01: opens only with a security key.
    pub fn hardware(self) -> bool {
        matches!(self, Self::Kh01 | Self::Ks01)
    }
}
/// How a read classifies a file by its first 8 bytes, before any length or
/// grammar check (spec §4.6).
enum Family {
    Legacy(Magic),
    PasswordOnly,
    /// `GOYOKH` or `GOYOKS` and any two more bytes: this build decides on
    /// the family alone, a newer magic of it included.
    SecurityKey,
    /// Any other `GOYOK` + `A`-`Z` + two digits numbered above the magics
    /// of that letter this build knows (above 03 for `E`, above 00 for a
    /// letter it does not know): a later build's. `GOYOKE00` is no such
    /// file, only a damaged one.
    Newer,
    Unknown,
}
fn family(bytes: &[u8]) -> Family {
    let Some(magic) = bytes.get(..8) else {
        return Family::Unknown;
    };
    if magic.starts_with(b"GOYOKH") || magic.starts_with(b"GOYOKS") {
        return Family::SecurityKey;
    }
    match Magic::of(magic) {
        Some(Magic::Ke03) => Family::PasswordOnly,
        Some(m) => Family::Legacy(m),
        None if magic.starts_with(b"GOYOK")
            && magic[5].is_ascii_uppercase()
            && magic[6..].iter().all(u8::is_ascii_digit)
            && (magic[6] - b'0') * 10 + (magic[7] - b'0')
                > if magic[5] == b'E' { 3 } else { 0 } =>
        {
            Family::Newer
        }
        None => Family::Unknown,
    }
}
/// How an unlock treats a key file it finds, by its first 8 bytes (spec
/// §4.6, §5.12 rule i): a security-key file (`GOYOKH*`/`GOYOKS*`, which this
/// build can neither open nor tell a damaged copy of from a later build's)
/// or a newer build's file is never damaged here, so no temp file ever
/// takes its place, at any size.
pub(super) fn never_replaced(bytes: &[u8]) -> bool {
    matches!(family(bytes), Family::SecurityKey | Family::Newer)
}
/// The vault ID and epoch of a key file that parses as a known format: a
/// 0.8 file of its exact length (epoch 0), or a KF2 file of any magic by
/// the strict parse. Public bytes only; temp-candidate recovery picks by it.
pub(super) fn head(bytes: &[u8]) -> Option<([u8; 16], u64)> {
    let legacy =
        |length: usize| (bytes.len() == length).then(|| (bytes[8..24].try_into().unwrap(), 0));
    match bytes.get(..8).and_then(Magic::of)? {
        Magic::Ke01 => legacy(148),
        Magic::Ke02 => legacy(128),
        _ => parse(bytes).ok().map(|h| (h.vault_id, h.epoch)),
    }
}

/// What an authored write did (byte 38). A re-seal copies it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Create with keys, or keys on: every slot present and new.
    KeysOn = 1,
    /// A password change, also the conversion of a 0.8 key file.
    Password = 2,
    AddKey = 3,
    Remove = 4,
    Pair = 5,
    /// Key-file sync on, or the re-upload after a server deletion.
    SyncOn = 6,
    SyncOff = 7,
    ReSeed = 8,
    /// A union of two key files.
    Union = 9,
    KeysOff = 10,
}
impl Kind {
    const ALL: [Kind; 10] = [
        Self::KeysOn,
        Self::Password,
        Self::AddKey,
        Self::Remove,
        Self::Pair,
        Self::SyncOn,
        Self::SyncOff,
        Self::ReSeed,
        Self::Union,
        Self::KeysOff,
    ];
    fn of(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| *k as u8 == byte)
    }
    /// The kinds each KF2 magic may carry.
    fn allowed(self, magic: Magic) -> bool {
        match magic {
            Magic::Ke03 => matches!(self, Self::Password | Self::Union | Self::KeysOff),
            Magic::Kh01 => !matches!(self, Self::SyncOn | Self::KeysOff),
            Magic::Ks01 => !matches!(self, Self::KeysOn | Self::SyncOff | Self::KeysOff),
            Magic::Ke01 | Magic::Ke02 => false,
        }
    }
}

/// A removed credential. Every later file carries it, so the credential can
/// never come back (spec §4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tombstone {
    pub credhash: [u8; 16],
    /// Bits 0-47: the epoch of the removal. Bits 48-63: the loss mark.
    pub removed: u64,
}
impl Tombstone {
    /// The epoch of the write that removed the credential.
    pub fn epoch(&self) -> u64 {
        self.removed & EPOCH_MAX
    }
    /// 0: not a loss; 1: a loss on an unknown date; d ≥ 2: a loss on day
    /// d − 2 counted from 1970-01-01.
    pub fn loss_mark(&self) -> u16 {
        (self.removed >> 48) as u16
    }
    /// The order of the tombstone list. The loss mark takes no part.
    fn order(&self) -> (u64, [u8; 16]) {
        (self.epoch(), self.credhash)
    }
}
/// A key file's state: its epoch and state tag (spec §4.3, §4.8). The same
/// epoch with another tag is a fork, never "newer".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyState {
    pub epoch: u64,
    pub tag: [u8; 16],
}
/// A registered security key, as its slot record states it (public).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlotPublic {
    /// Bit0: UV at registration; bit1: credProtect 3. Both: a PIN slot.
    pub flags: u8,
    /// Shown as "보안 키 N"; unique and ascending.
    pub number: u8,
    pub registered: u64,
    pub added_epoch: u64,
    /// The credhash of the key that authorized the addition (zero for the
    /// keys of a create or keys on).
    pub added_by: [u8; 16],
    pub seed: [u8; 32],
    pub cred_id: Vec<u8>,
    pub credhash: [u8; 16],
}
impl SlotPublic {
    pub fn pin(&self) -> bool {
        self.flags == 3
    }
}
/// The public part of a KF2 key file, as the strict parse read it. Every
/// field is unauthenticated until the file opens.
#[derive(Clone, Debug)]
pub struct KeyHeader {
    pub magic: Magic,
    pub vault_id: [u8; 16],
    pub epoch: u64,
    /// The policy byte: bit0 OTP vault, bit1 PIN mode.
    pub flags: u8,
    /// The next key number to give out.
    pub next: u8,
    pub kind: Kind,
    /// The slot index of the key that authorized the write; None without
    /// security keys.
    pub authorizer: Option<u8>,
    /// Bit i: slot i was touched in this write.
    pub present: u8,
    /// Bit i: slot i is live but has no S-wrap in this file.
    pub suspended: u8,
    pub ks_id: [u8; 16],
    pub pw_id: [u8; 16],
    /// Unix seconds of the authored write; display only.
    pub written: u64,
    /// 0 not a loss, 1 a loss on an unknown date, else its Unix seconds;
    /// display only.
    pub loss: u64,
    /// Bundle order: the current key first, the ID key last.
    pub key_ids: Vec<[u8; 16]>,
    pub tombstones: Vec<Tombstone>,
    pub slots: Vec<SlotPublic>,
    /// Pair records as (owner, target) slot indexes, strictly ascending.
    pub pairs: Vec<(u8, u8)>,
    /// S-wraps in slot order as (recipient, via) slot indexes.
    pub wraps: Vec<(u8, u8)>,
    /// SHA-256 of the vault file this write expects to replace next.
    pub resume: [u8; 32],
    /// The state tag over `[0, W)`.
    pub tag: [u8; 16],
    /// Where the seal block (W), `C_body` (B) and the chain (E) start.
    w: usize,
    b: usize,
    e: usize,
}
impl KeyHeader {
    pub fn otp(&self) -> bool {
        self.flags & 1 != 0
    }
    /// PIN mode: every slot is a PIN slot.
    pub fn pin(&self) -> bool {
        self.flags & 2 != 0
    }
    pub fn state(&self) -> KeyState {
        KeyState {
            epoch: self.epoch,
            tag: self.tag,
        }
    }
    /// The key ID of the current data key.
    pub fn current_key_id(&self) -> [u8; 16] {
        self.key_ids[0]
    }
    /// The credhashes of the live keys, in slot order.
    pub fn live(&self) -> Vec<[u8; 16]> {
        self.slots.iter().map(|s| s.credhash).collect()
    }
    /// The keys a write authorized by key `number` alone can deliver S to
    /// (spec §5.5 W6): that key and every target of its pair records, as
    /// ascending numbers; empty when no live slot has that number. Public
    /// bytes only: the UI proposes a key that reaches everything before any
    /// touch.
    pub fn reach(&self, number: u8) -> Vec<u8> {
        let Some(a) = self.slots.iter().position(|s| s.number == number) else {
            return Vec::new();
        };
        let mut out: Vec<u8> = self
            .pairs
            .iter()
            .filter(|(owner, _)| usize::from(*owner) == a)
            .filter_map(|(_, target)| self.slots.get(usize::from(*target)))
            .map(|s| s.number)
            .collect();
        out.push(number);
        out.sort_unstable();
        out
    }
    /// What `seal` needs to write this state again (a re-seal), with this
    /// file's `resume`.
    pub fn spec(&self) -> Spec {
        Spec {
            vault_id: self.vault_id,
            epoch: self.epoch,
            kind: self.kind,
            next: self.next,
            pw_id: self.pw_id,
            loss: self.loss,
            tombstones: self.tombstones.clone(),
            resume: self.resume,
        }
    }
}

/// Reads a file's fields in order; reading past its end is AUTH_ERROR.
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.data.len())
            .ok_or(AUTH_ERROR)?;
        let part = &self.data[self.at..end];
        self.at = end;
        Ok(part)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}
/// Err(AUTH_ERROR) unless `ok`: every grammar failure looks the same.
fn need(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(AUTH_ERROR) }
}
/// The strict parse of a KF2 key file (GOYOKE03, GOYOKH01, GOYOKS01; spec
/// §4.6). Public bytes only, no secret and no `cfg`: the same code in every
/// build. Every failure is AUTH_ERROR. Lengths come from counts checked
/// against their limits first, and the file must end exactly where the
/// layout does, so no input can make it read past the end or allocate more
/// than the 32 KiB it was given.
pub fn parse(bytes: &[u8]) -> Result<KeyHeader> {
    let magic = bytes
        .get(..8)
        .and_then(Magic::of)
        .filter(|m| !matches!(m, Magic::Ke01 | Magic::Ke02))
        .ok_or(AUTH_ERROR)?;
    need(bytes.len() <= KEY_FILE_LIMIT)?;
    let mut r = Cursor { data: bytes, at: 8 };
    let vault_id = r.array::<16>()?;
    let epoch = r.u64()?;
    let flags = r.u8()?;
    let k = usize::from(r.u8()?);
    let n = r.u8()?;
    let next = r.u8()?;
    let count = usize::from(r.u16()?);
    let kind = Kind::of(r.u8()?)
        .filter(|kind| kind.allowed(magic))
        .ok_or(AUTH_ERROR)?;
    let authorizer = r.u8()?;
    let present = r.u8()?;
    let suspended = r.u8()?;
    let p = usize::from(r.u8()?);
    let reserved = r.take(5)?;
    let ks_id = r.array::<16>()?;
    let pw_id = r.array::<16>()?;
    let written = r.u64()?;
    let loss = r.u64()?;
    let pin = flags & 2 != 0;
    need(
        (1..=EPOCH_MAX).contains(&epoch)
            && flags & !3 == 0
            && (1..=MAX_KEYS).contains(&k)
            && next >= 1
            && count <= TOMB_MAX
            && reserved.iter().all(|b| *b == 0)
            && pw_id != [0; 16],
    )?;
    if magic == Magic::Ke03 {
        need(
            n == 0
                && p == 0
                && !pin
                && authorizer == 0xFF
                && present == 0
                && suspended == 0
                && ks_id == [0; 16],
        )?;
    } else {
        // n is at most 8 from here on, so every shift below stays in range.
        need((1..=MAX_SLOTS).contains(&n))?;
        need(
            (magic == Magic::Kh01 || pin)
                && p <= usize::from(n) * usize::from(n - 1)
                && u16::from(present | suspended) >> n == 0
                && present & suspended == 0
                && authorizer < n
                && present & (1 << authorizer) != 0
                && ks_id != [0; 16]
                && ks_id != ks_id_zero(&vault_id),
        )?;
    }
    let mut key_ids = Vec::with_capacity(k);
    for _ in 0..k {
        key_ids.push(r.array::<16>()?);
    }
    need(key_ids.iter().collect::<BTreeSet<_>>().len() == k)?;
    let mut tombstones = Vec::with_capacity(count);
    for _ in 0..count {
        tombstones.push(Tombstone {
            credhash: r.array()?,
            removed: r.u64()?,
        });
    }
    let dead: BTreeSet<[u8; 16]> = tombstones.iter().map(|t| t.credhash).collect();
    need(
        dead.len() == count
            && tombstones.windows(2).all(|t| t[0].order() < t[1].order())
            && tombstones.iter().all(|t| (1..=epoch).contains(&t.epoch())),
    )?;
    let mut slots: Vec<SlotPublic> = Vec::with_capacity(n.into());
    for _ in 0..n {
        let (slot_kind, slot_flags, number, slot_reserved) = (r.u8()?, r.u8()?, r.u8()?, r.u8()?);
        let registered = r.u64()?;
        let added_epoch = r.u64()?;
        let added_by = r.array()?;
        let seed = r.array()?;
        let c = usize::from(r.u16()?);
        need(
            slot_kind == 1
                && slot_flags <= 3
                && (!pin || slot_flags == 3)
                && slot_reserved == 0
                && slots
                    .last()
                    .map_or(number >= 1, |last| number > last.number)
                && (1..=MAX_CRED_ID).contains(&c)
                && (1..=epoch).contains(&added_epoch),
        )?;
        let cred_id = r.take(c)?.to_vec();
        slots.push(SlotPublic {
            flags: slot_flags,
            number,
            registered,
            added_epoch,
            added_by,
            seed,
            credhash: credhash(&cred_id),
            cred_id,
        });
    }
    let ids: BTreeSet<&[u8]> = slots.iter().map(|s| s.cred_id.as_slice()).collect();
    let hashes: BTreeSet<[u8; 16]> = slots.iter().map(|s| s.credhash).collect();
    need(ids.len() == slots.len() && hashes.len() == slots.len() && hashes.is_disjoint(&dead))?;
    // Which slots this write added, by the kind of the write.
    let new: Vec<usize> = (0..slots.len())
        .filter(|i| slots[*i].added_epoch == epoch)
        .collect();
    let all = ((1u16 << n) - 1) as u8;
    need(match kind {
        Kind::KeysOn => {
            present == all
                && suspended == 0
                && new.len() == slots.len()
                && slots.iter().all(|s| s.added_by == [0; 16])
        }
        Kind::ReSeed => present == all && suspended == 0 && new.is_empty(),
        Kind::AddKey => {
            new.len() == 1
                && present & (1 << new[0]) != 0
                && slots
                    .get(usize::from(authorizer))
                    .is_some_and(|a| a.credhash == slots[new[0]].added_by)
        }
        Kind::Pair => present.count_ones() >= 2 && new.is_empty(),
        _ => new.is_empty(),
    })?;
    let mut pairs = Vec::with_capacity(p);
    for _ in 0..p {
        let (owner, target) = (r.u8()?, r.u8()?);
        need(r.take(2)? == [0, 0] && owner != target && owner < n && target < n)?;
        r.take(WRAP)?;
        pairs.push((owner, target));
    }
    need(pairs.windows(2).all(|w| w[0] < w[1]))?;
    // One S-wrap per live slot that is not suspended, in slot order: through
    // the key itself when it was touched, else through the authorizer and
    // its pair record.
    let mut wraps = Vec::with_capacity(n.into());
    for j in (0..n).filter(|j| suspended & (1 << *j) == 0) {
        let (recipient, via) = (r.u8()?, r.u8()?);
        need(
            recipient == j
                && if present & (1 << j) != 0 {
                    via == j
                } else {
                    via == authorizer && pairs.binary_search(&(authorizer, j)).is_ok()
                },
        )?;
        r.take(WRAP)?;
        wraps.push((recipient, via));
    }
    let w = r.at;
    let resume = r.array::<32>()?;
    r.take(SEAL_BLOCK - 32)?;
    let b = r.at;
    r.take(32 + body_size(k, flags & 1 != 0))?;
    let e = r.at;
    r.take(32 * k)?;
    need(r.at == bytes.len())?;
    Ok(KeyHeader {
        magic,
        vault_id,
        epoch,
        flags,
        next,
        kind,
        authorizer: (n > 0).then_some(authorizer),
        present,
        suspended,
        ks_id,
        pw_id,
        written,
        loss,
        key_ids,
        tombstones,
        slots,
        pairs,
        wraps,
        resume,
        tag: state_tag(&bytes[..w]),
        w,
        b,
        e,
    })
}

/// The secrets of a key file (spec §4.2): the data keys, the current one
/// first and the ID key last (one entry for both when there is one key),
/// and the TOTP secret of an OTP vault. Zeroized on drop.
pub struct Bundle {
    keys: Zeroizing<Vec<[u8; 32]>>,
    otp: Option<Box<Zeroizing<[u8; 20]>>>,
}
impl Bundle {
    /// None unless there are 1 to MAX_KEYS keys.
    pub fn new(keys: &[[u8; 32]], otp: Option<&[u8; 20]>) -> Option<Self> {
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return None;
        }
        // Sized up front: a growing Vec would free unwiped copies.
        let mut stored = Zeroizing::new(Vec::with_capacity(keys.len()));
        stored.extend_from_slice(keys);
        Some(Self {
            keys: stored,
            otp: otp.map(boxed),
        })
    }
    /// The body plaintext of a key file: `keys ‖ [otp]`.
    fn from_plain(plain: &[u8], k: usize, otp: bool) -> Option<Self> {
        if plain.len() + 16 != body_size(k, otp) {
            return None;
        }
        let mut keys = Zeroizing::new(vec![[0u8; 32]; k]);
        for (key, part) in keys.iter_mut().zip(plain.as_chunks::<32>().0) {
            key.copy_from_slice(part);
        }
        let otp = otp.then(|| {
            let mut secret: Box<Zeroizing<[u8; 20]>> = Box::default();
            secret.copy_from_slice(&plain[32 * k..]);
            secret
        });
        Some(Self { keys, otp })
    }
    fn plain(&self) -> Zeroizing<Vec<u8>> {
        let mut plain = Zeroizing::new(Vec::with_capacity(32 * self.keys.len() + 20));
        for key in self.keys.iter() {
            plain.extend_from_slice(key);
        }
        if let Some(otp) = &self.otp {
            plain.extend_from_slice(otp.as_slice());
        }
        plain
    }
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }
    /// The data key that seals the vault file.
    pub fn current(&self) -> &[u8; 32] {
        &self.keys[0]
    }
    /// The key of the vault's identity: `v1_ids`, merges and the check code.
    /// It never changes and is never dropped.
    pub fn id_key(&self) -> &[u8; 32] {
        &self.keys[self.keys.len() - 1]
    }
    pub fn otp(&self) -> Option<&[u8; 20]> {
        self.otp.as_deref().map(|otp| &**otp)
    }
    /// The same keys in the same order and the same TOTP secret, compared in
    /// constant time (counts are public).
    pub fn same(&self, other: &Bundle) -> bool {
        let mut same = self.keys.len() == other.keys.len();
        for (a, b) in self.keys.iter().zip(other.keys.iter()) {
            same &= ct_eq(a, b);
        }
        same & match (self.otp(), other.otp()) {
            (Some(a), Some(b)) => ct_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        }
    }
}

/// A security-key touch (spec §8.3). This build has no security-key code,
/// so none exists and every `open` gets None.
pub enum Touch {}

/// What `open` returns. The bundle is zeroized on drop.
pub struct Opened {
    pub bundle: Box<Bundle>,
    /// S of a security-key file, kept for a re-authentication or an adopt
    /// planner. A password-only file has none.
    pub s: Option<Box<Zeroizing<[u8; 32]>>>,
    /// The slot whose key opened the file; None without security keys.
    pub slot: Option<u8>,
    /// Zero for a 0.8 key file, which has none.
    pub pw_id: [u8; 16],
    /// For a 0.8 key file: epoch 0 and its legacy tag (spec §4.5).
    pub state: KeyState,
    /// SHA-256 of the key file bytes that opened. Private, so an Opened
    /// only ever comes from opening a file: a re-seal checks it is that of
    /// its source.
    file: [u8; 32],
}

/// Where `open` stopped (spec §3.4): every failure after the public checks
/// is AUTH_ERROR at the body step, whatever its cause.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Step {
    Body,
}
#[cfg(test)]
thread_local! {
    /// Body AEADs that `open` ran on this thread, and where its last
    /// failure stopped.
    static BODY_AEADS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static FAILED_AT: std::cell::Cell<Option<Step>> = const { std::cell::Cell::new(None) };
}

enum Form {
    /// GOYOKE01 or GOYOKE02, of the exact length.
    Legacy(Magic),
    /// A KF2 file this build opens: GOYOKE03.
    Kf2(Box<KeyHeader>),
    /// A GOYOKH*/GOYOKS* file, which this build does not open. The header
    /// when it is a well-formed GOYOKH01/GOYOKS01, only ever shown.
    SecurityKey(Option<Box<KeyHeader>>),
}
/// A key file as read (spec §4.6, §4.7): its bytes and what they state
/// before any password.
pub struct KeyFile {
    path: PathBuf,
    bytes: Vec<u8>,
    form: Form,
}
impl KeyFile {
    /// Reads at most KEY_FILE_LIMIT bytes of `path` and classifies them.
    pub fn read(path: &Path) -> Result<Self> {
        Self::from_bytes(path, read_head(path, KEY_FILE_LIMIT)?)
    }
    /// Classifies key file bytes by their magic family first (spec §4.6):
    /// any GOYOKH*/GOYOKS* is a security-key file, decided on the magic
    /// alone, with no length or grammar check, so a damaged or later copy
    /// is never taken for a wrong password; any other newer magic is
    /// NEWER_KEY_FORMAT; then the 0.8 formats by their exact length and
    /// GOYOKE03 by the strict parse. Anything else is AUTH_ERROR. The
    /// security-key build (stage 4) decides those files by the full grammar.
    pub fn from_bytes(path: &Path, bytes: Vec<u8>) -> Result<Self> {
        let form = match family(&bytes) {
            Family::SecurityKey => {
                let header = bytes
                    .get(..8)
                    .and_then(Magic::of)
                    .filter(|m| m.hardware())
                    .and_then(|_| parse(&bytes).ok());
                Form::SecurityKey(header.map(Box::new))
            }
            Family::Newer => return Err(NEWER_KEY_FORMAT),
            _ if bytes.len() > KEY_FILE_LIMIT => return Err(TOO_LARGE),
            Family::Legacy(magic) => {
                let length = if magic == Magic::Ke01 { 148 } else { 128 };
                need(bytes.len() == length)?;
                Form::Legacy(magic)
            }
            Family::PasswordOnly => Form::Kf2(Box::new(parse(&bytes)?)),
            Family::Unknown => return Err(AUTH_ERROR),
        };
        Ok(Self {
            path: path.to_owned(),
            bytes,
            form,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The parsed header of a KF2 file this build opens; None for a 0.8
    /// file and for a security-key file.
    pub fn header(&self) -> Option<&KeyHeader> {
        match &self.form {
            Form::Kf2(h) => Some(h),
            _ => None,
        }
    }
    /// Whether the file needs a security key, from its magic family alone.
    pub fn needs_security_key(&self) -> bool {
        matches!(self.form, Form::SecurityKey(_))
    }
    /// What this build says instead of opening the file: no derive, no
    /// failure count, no retry delay, never the AUTH text (spec §4.7).
    pub fn refusal(&self) -> Option<&'static str> {
        match &self.form {
            Form::SecurityKey(Some(_)) => Some(NO_SECURITY_KEY_SUPPORT),
            Form::SecurityKey(None) => Some(NO_SECURITY_KEY_SUPPORT_DAMAGED),
            _ => None,
        }
    }
    pub fn magic(&self) -> Option<Magic> {
        match &self.form {
            Form::Legacy(magic) => Some(*magic),
            Form::Kf2(h) => Some(h.magic),
            Form::SecurityKey(h) => h.as_ref().map(|h| h.magic),
        }
    }
    /// The vault ID of a file this build opens (public, at offset 8 in
    /// every format).
    pub fn vault_id(&self) -> Option<[u8; 16]> {
        match &self.form {
            Form::Legacy(_) => self.bytes[8..24].try_into().ok(),
            Form::Kf2(h) => Some(h.vault_id),
            Form::SecurityKey(_) => None,
        }
    }
    /// Whether the vault asks for an OTP code. Unauthenticated: it only
    /// decides which fields the screen shows.
    pub fn uses_otp(&self) -> bool {
        match &self.form {
            Form::Legacy(magic) => *magic == Magic::Ke01,
            Form::Kf2(h) => h.otp(),
            Form::SecurityKey(h) => h.as_ref().is_some_and(|h| h.otp()),
        }
    }
    /// The state of a 0.8 key file whose data key is `key` (spec §4.5):
    /// epoch 0 and the legacy tag, as `open` gives it. None for any other
    /// file, whose state its header states.
    pub fn legacy_state(&self, key: &[u8; 32]) -> Option<KeyState> {
        let Form::Legacy(magic) = self.form else {
            return None;
        };
        let id: [u8; 16] = self.bytes[8..24].try_into().ok()?;
        let tag = legacy_tag(magic, &id, magic == Magic::Ke01, &key_id(&id, key));
        Some(KeyState { epoch: 0, tag })
    }
    /// Opens the file (spec §3.4). The order is fixed: the public checks,
    /// one Argon2 always, then the body, whose every failure is the same
    /// AUTH_ERROR. A security-key file never gets that far here.
    pub fn open(&self, password: &str, touch: Option<&Touch>) -> Result<Opened> {
        if let Some(touch) = touch {
            match *touch {}
        }
        match &self.form {
            Form::SecurityKey(_) => Err(self.refusal().unwrap_or(NO_SECURITY_KEY_SUPPORT)),
            Form::Legacy(magic) => {
                let (id, key, otp) = decode_key(&self.bytes, password)?;
                let bundle =
                    Bundle::new(std::slice::from_ref(&**key), otp.as_deref().map(|o| &**o))
                        .ok_or(AUTH_ERROR)?;
                let tag = legacy_tag(*magic, &id, otp.is_some(), &key_id(&id, &key));
                Ok(Opened {
                    bundle: Box::new(bundle),
                    s: None,
                    slot: None,
                    pw_id: [0; 16],
                    state: KeyState { epoch: 0, tag },
                    file: sha256(&[&self.bytes[..]]),
                })
            }
            Form::Kf2(h) => {
                let salt: &[u8; 32] = self.bytes[h.w + 32..h.w + 64]
                    .try_into()
                    .map_err(|_| AUTH_ERROR)?;
                let pw_key = crypto::derive(password.as_bytes(), salt)?;
                self.open_body(h, &pw_key)
            }
        }
    }
    /// Opens a file `seal` just wrote with the writer's own factors, with no
    /// second Argon2: the read-back check of a key change (spec §5.5 W10).
    pub fn open_written(&self, w: &WriterSecrets) -> Result<Opened> {
        match &self.form {
            Form::Kf2(h) => self.open_body(h, &w.pw_key),
            _ => Err(AUTH_ERROR),
        }
    }
    /// Steps 4-6 of spec §3.4 for a password-only file: S' is all zero.
    /// Every failure is AUTH_ERROR at the body step: a wrong password ends
    /// at the commitment, with no body AEAD.
    fn open_body(&self, h: &KeyHeader, pw_key: &[u8; 32]) -> Result<Opened> {
        let result = self.body(h, pw_key);
        #[cfg(test)]
        if result.is_err() {
            FAILED_AT.with(|s| s.set(Some(Step::Body)));
        }
        result
    }
    fn body(&self, h: &KeyHeader, pw_key: &[u8; 32]) -> Result<Opened> {
        let bytes = &self.bytes;
        let (k_body, c_body) = body_keys(pw_key, &[0; 32], &sha256(&[&bytes[..h.b]]));
        need(ct_eq(&c_body, &bytes[h.b..h.b + 32]))?;
        let nonce: &[u8; 24] = bytes[h.w + 64..h.b].try_into().map_err(|_| AUTH_ERROR)?;
        #[cfg(test)]
        BODY_AEADS.with(|n| n.set(n.get() + 1));
        let plain = crypto::open(&k_body, nonce, &bytes[..h.b + 32], &bytes[h.b + 32..h.e])?;
        let bundle = Bundle::from_plain(&plain, h.key_ids.len(), h.otp()).ok_or(AUTH_ERROR)?;
        // Every listed key ID belongs to a key of the body, and every
        // chain entry verifies, so every byte of the file is checked.
        let end = sha256(&[&bytes[..h.e]]);
        let mut ok = true;
        for (i, key) in bundle.keys().iter().enumerate() {
            ok &= ct_eq(&key_id(&h.vault_id, key), &h.key_ids[i]);
            let at = h.e + 32 * i;
            ok &= ct_eq(&chain_mac(&h.vault_id, key, &end), &bytes[at..at + 32]);
        }
        need(ok)?;
        Ok(Opened {
            bundle: Box::new(bundle),
            s: None,
            slot: None,
            pw_id: h.pw_id,
            state: h.state(),
            file: sha256(&[&bytes[..]]),
        })
    }
    /// Whether this file's chain entry for `dk` verifies (spec §3.4): it
    /// proves that whoever wrote the file knew that data key. No password
    /// and no touch. False for a 0.8 file, which has no chain.
    pub fn chain_ok(&self, dk: &[u8; 32]) -> bool {
        let Form::Kf2(h) = &self.form else {
            return false;
        };
        let id = key_id(&h.vault_id, dk);
        let Some(i) = h.key_ids.iter().position(|k| *k == id) else {
            return false;
        };
        let at = h.e + 32 * i;
        ct_eq(
            &chain_mac(&h.vault_id, dk, &sha256(&[&self.bytes[..h.e]])),
            &self.bytes[at..at + 32],
        )
    }
}

/// The authored fields of a KF2 key file that `seal` writes (spec §4.1).
/// `written` is the time of the seal; the bundle gives the key IDs and the
/// OTP bit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Spec {
    pub vault_id: [u8; 16],
    pub epoch: u64,
    pub kind: Kind,
    pub next: u8,
    pub pw_id: [u8; 16],
    pub loss: u64,
    /// In any order; the file lists them by (epoch, credhash).
    pub tombstones: Vec<Tombstone>,
    /// Per copy: the SHA-256 of the vault file this write expects to
    /// replace next, else zero.
    pub resume: [u8; 32],
}
/// How `seal` arranges a file (spec §3.3).
#[derive(Clone, Copy)]
pub enum Plan<'a> {
    /// GOYOKE03: no security keys, so no pair records and no S-wraps.
    PasswordOnly,
    /// The same-epoch re-seal of a verified file: `[0, W)` byte for byte
    /// (so the state tag stays), with a new seal block, body and chain. The
    /// spec must be that file's, but for `resume`; `opened` is what opening
    /// `source` gave, and the bundle must be the one it holds, TOTP secret
    /// included. The password is the one that opened it: comparing it with
    /// the source's would cost a second Argon2. A security-key file also
    /// needs its S from `opened` (stage 4).
    Reseal {
        source: &'a KeyFile,
        opened: &'a Opened,
    },
}
/// The writer's factors of a sealed file, for its read-back check. Zeroized
/// on drop. A security-key result adds S and the S-wrap bases (stage 4).
pub struct WriterSecrets {
    pw_key: Box<Key>,
}
/// Seals `bundle` under `password` as a KF2 key file (spec §3.3). The
/// random draws come in a fixed order, the salt, then the body nonce, so a
/// test can reproduce a file byte for byte. The result is strict-parsed
/// before it is returned.
pub fn seal(
    spec: &Spec,
    bundle: &Bundle,
    password: &str,
    plan: Plan,
) -> Result<(Vec<u8>, WriterSecrets)> {
    if spec.epoch > EPOCH_MAX {
        return Err(EPOCH_LIMIT);
    }
    if spec.tombstones.len() > TOMB_MAX {
        return Err(TOMBSTONES_FULL);
    }
    let k = bundle.keys().len();
    let otp = bundle.otp().is_some();
    // A re-seal copies [0, W) of a verified file: the spec must be that
    // file's but for `resume`, and the bundle the one its opening gave.
    // Refused before any draw or Argon2.
    if let Plan::Reseal { source, opened } = plan {
        let h = source.header().ok_or(NOT_SEALED)?;
        let mut same = h.spec();
        same.resume = spec.resume;
        let mut sorted = spec.clone();
        sorted.tombstones.sort_unstable_by_key(Tombstone::order);
        let keys_match = h.key_ids.len() == k
            && h.otp() == otp
            && bundle
                .keys()
                .iter()
                .zip(&h.key_ids)
                .all(|(key, id)| key_id(&h.vault_id, key) == *id);
        // Two states never differ in a secret: same keys, same TOTP secret
        // (constant time), as `opened` read them from exactly these bytes.
        let opened_here = opened.file == sha256(&[source.bytes()]) && bundle.same(&opened.bundle);
        // Only a password-only state so far: one with security keys also
        // needs its S (stage 4).
        if sorted != same || !keys_match || !opened_here || !h.slots.is_empty() {
            return Err(NOT_SEALED);
        }
    }
    let size = 96 + 16 * k + 24 * spec.tombstones.len() + SEAL_BLOCK + 32 + body_size(k, otp);
    let size = size + 32 * k;
    // Step 1.
    let salt = crypto::random::<32>()?;
    let pw_key = crypto::derive(password.as_bytes(), &salt)?;
    let nonce = crypto::random::<24>()?;
    // Step 2: [0, H), which for a password-only file is also [0, W).
    let mut out = match plan {
        Plan::PasswordOnly => {
            let mut tombstones = spec.tombstones.clone();
            tombstones.sort_unstable_by_key(Tombstone::order);
            let mut out = Vec::with_capacity(size);
            out.extend_from_slice(Magic::Ke03.bytes());
            out.extend_from_slice(&spec.vault_id);
            out.extend_from_slice(&spec.epoch.to_le_bytes());
            out.extend_from_slice(&[u8::from(otp), k as u8, 0, spec.next]);
            out.extend_from_slice(&(tombstones.len() as u16).to_le_bytes());
            out.extend_from_slice(&[spec.kind as u8, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&[0; 16]);
            out.extend_from_slice(&spec.pw_id);
            out.extend_from_slice(&now()?.to_le_bytes());
            out.extend_from_slice(&spec.loss.to_le_bytes());
            for key in bundle.keys() {
                out.extend_from_slice(&key_id(&spec.vault_id, key));
            }
            for t in &tombstones {
                out.extend_from_slice(&t.credhash);
                out.extend_from_slice(&t.removed.to_le_bytes());
            }
            out
        }
        Plan::Reseal { source, .. } => {
            let h = source.header().ok_or(NOT_SEALED)?;
            let mut out = Vec::with_capacity(size);
            out.extend_from_slice(&source.bytes[..h.w]);
            out
        }
    };
    // Step 4: the seal block. Step 5: the commitment and the body.
    out.extend_from_slice(&spec.resume);
    out.extend_from_slice(salt.as_slice());
    out.extend_from_slice(nonce.as_slice());
    let (k_body, c_body) = body_keys(&pw_key, &[0; 32], &sha256(&[&out]));
    out.extend_from_slice(&c_body);
    let body = crypto::seal(&k_body, &nonce, &out, &bundle.plain())?;
    out.extend_from_slice(&body);
    // Step 6: a chain entry for every data key.
    let end = sha256(&[&out]);
    for key in bundle.keys() {
        out.extend_from_slice(&chain_mac(&spec.vault_id, key, &end));
    }
    if parse(&out).is_err() {
        return Err(NOT_SEALED);
    }
    Ok((
        out,
        WriterSecrets {
            pw_key: boxed(&pw_key),
        },
    ))
}
/// The body ciphertext of a bundle of `k` keys: `keys ‖ [otp]` and the tag.
fn body_size(k: usize, otp: bool) -> usize {
    let otp = if otp { 20 } else { 0 };
    32 * k + otp + 16
}
/// Unix seconds for `written`; a test can fix it (spec §3.1).
fn now() -> Result<u64> {
    #[cfg(test)]
    if let Some(now) = crypto::test_now() {
        return Ok(now);
    }
    otp::now()
}

/// The public syntax of a GOYOKS01 file, which sync gates check (spec §4.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeySyntax {
    pub epoch: u64,
    pub tag: [u8; 16],
    pub current_key_id: [u8; 16],
    pub kind: Kind,
    /// The credhash of the key that authorized the write.
    pub authorizer: [u8; 16],
    pub tombstones: Vec<Tombstone>,
    /// The credhashes of the live keys.
    pub live: Vec<[u8; 16]>,
}
/// The full strict parse restricted to GOYOKS01 of the vault `id`: the only
/// key file that may ever reach a sync server. Public bytes only.
pub fn is_sync_key_file(bytes: &[u8], id: &[u8; 16]) -> Option<KeySyntax> {
    if bytes.get(..8)? != Magic::Ks01.bytes() {
        return None;
    }
    let h = parse(bytes).ok().filter(|h| h.vault_id == *id)?;
    let authorizer = h.slots.get(usize::from(h.authorizer?))?.credhash;
    Some(KeySyntax {
        epoch: h.epoch,
        tag: h.tag,
        current_key_id: h.current_key_id(),
        kind: h.kind,
        authorizer,
        live: h.live(),
        tombstones: h.tombstones,
    })
}

/// What the login, Restore and Adopt screens show for a chosen key file
/// before any password (spec §4.7). Only `needs_security_key` comes from
/// the magic alone; the rest from the strict parse when it succeeds, shown
/// and never used for a decision.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyInfo {
    pub magic: [u8; 8],
    /// The OTP field is shown.
    pub otp: bool,
    pub needs_security_key: bool,
    pub well_formed: bool,
    pub slots: u8,
    pub pin: bool,
    pub key_sync: bool,
    pub epoch: u64,
}
impl KeyInfo {
    /// What this build says about the file instead of opening it, as soon
    /// as it is chosen (spec §4.7).
    pub fn refusal(&self) -> Option<&'static str> {
        self.needs_security_key.then_some(if self.well_formed {
            NO_SECURITY_KEY_SUPPORT
        } else {
            NO_SECURITY_KEY_SUPPORT_DAMAGED
        })
    }
}
/// None if `path` is missing or does not start like a key file (GOYOK…).
pub fn key_info(path: &Path) -> Option<KeyInfo> {
    let bytes = read_head(path, KEY_FILE_LIMIT).ok()?;
    let magic: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    if !magic.starts_with(b"GOYOK") {
        return None;
    }
    let mut info = KeyInfo {
        magic,
        otp: &magic == KEY_MAGIC,
        needs_security_key: matches!(family(&bytes), Family::SecurityKey),
        well_formed: false,
        slots: 0,
        pin: false,
        key_sync: false,
        epoch: 0,
    };
    match KeyFile::from_bytes(path, bytes).map(|f| f.form) {
        Ok(Form::Legacy(_)) => info.well_formed = true,
        Ok(Form::Kf2(h) | Form::SecurityKey(Some(h))) => {
            info.well_formed = true;
            info.otp = h.otp();
            info.slots = h.slots.len() as u8;
            info.pin = h.pin();
            info.key_sync = h.magic == Magic::Ks01;
            info.epoch = h.epoch;
        }
        _ => {}
    }
    Some(info)
}
/// The first `limit + 1` bytes of the file at `path` at most, so that the
/// magic of a file of any size can be classified.
pub(super) fn read_head(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let f = File::open(path).map_err(|_| "파일을 열 수 없습니다.")?;
    let mut bytes = Vec::new();
    f.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "파일 읽기 실패")?;
    Ok(bytes)
}

/// The keyed key code of a key-file state (spec §4.8), "열쇠 확인 코드".
/// Only a holder of the state's current data key can compute it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Code(pub [u8; 8]);
impl Code {
    /// `E{epoch} · XXXX-XXXX-XXXX-XXXX`, the style of the check code.
    pub fn show(&self, epoch: u64) -> String {
        let d = self.0;
        format!(
            "E{epoch} · {:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}
/// The key code of `state` under its current data key `dk`.
pub fn key_code(vault_id: &[u8; 16], dk: &[u8; 32], state: KeyState) -> Code {
    let prk = hkdf_extract(b"goyo-vault/v2/key-code", &[dk]);
    let mut key = Box::new(Zeroizing::new([0u8; 32]));
    hkdf_expand(&prk, &[vault_id], key.as_mut_slice());
    let mut code = [0; 8];
    code.copy_from_slice(
        &mac(
            &key,
            &[b"goyo key state\0", &state.epoch.to_le_bytes(), &state.tag],
        )[..8],
    );
    Code(code)
}
/// The public ID of a data key (spec §3.2).
pub fn key_id(vault_id: &[u8; 16], dk: &[u8; 32]) -> [u8; 16] {
    let prk = hkdf_extract(b"goyo-vault/v2/key-id", &[dk]);
    let mut id = [0; 16];
    hkdf_expand(&prk, &[vault_id], &mut id);
    id
}
/// The `ks_id` a security-key file would carry if its S were all zero.
/// Computable from public bytes, so every parser refuses it.
pub fn ks_id_zero(vault_id: &[u8; 16]) -> [u8; 16] {
    let prk = hkdf_extract(b"goyo-vault/v2/ks-id", &[&[0; 32]]);
    let mut id = [0; 16];
    hkdf_expand(&prk, &[vault_id], &mut id);
    id
}
/// The public hash of a credential ID.
pub fn credhash(cred_id: &[u8]) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(&sha256(&[b"goyo-vault/v2/cred\0", cred_id])[..16]);
    out
}
/// The state tag of a KF2 file from its bytes `[0, W)` (spec §4.8).
fn state_tag(region: &[u8]) -> [u8; 16] {
    let mut tag = [0; 16];
    tag.copy_from_slice(&sha256(&[b"goyo-vault/v2/state\0", &sha256(&[region])])[..16]);
    tag
}
/// The state tag of a 0.8 key file, from its opened data key.
fn legacy_tag(magic: Magic, vault_id: &[u8; 16], otp: bool, key_id: &[u8; 16]) -> [u8; 16] {
    let mut tag = [0; 16];
    tag.copy_from_slice(
        &sha256(&[
            b"goyo-vault/v2/state-legacy\0",
            magic.bytes(),
            vault_id,
            &[u8::from(otp)],
            key_id,
        ])[..16],
    );
    tag
}
/// Chain entry of data key `dk` over `end`, the hash of `file[0 .. E)`.
fn chain_mac(vault_id: &[u8; 16], dk: &[u8; 32], end: &[u8; 32]) -> [u8; 32] {
    let prk = hkdf_extract(b"goyo-vault/v2/chain", &[dk]);
    let mut key = Box::new(Zeroizing::new([0u8; 32]));
    hkdf_expand(&prk, &[vault_id], key.as_mut_slice());
    mac(&key, &[b"goyo-vault/v2/chain-msg\0", end])
}
/// `K_body` and `C_body` from `pw_key`, the keyset secret (all zero without
/// security keys) and `hh`, the hash of `file[0 .. B)`.
fn body_keys(pw_key: &[u8; 32], s: &[u8; 32], hh: &[u8; 32]) -> (Box<Key>, [u8; 32]) {
    let prk = hkdf_extract(b"goyo-vault/v2/body", &[pw_key, s]);
    let mut key = Box::new(Zeroizing::new([0u8; 32]));
    hkdf_expand(&prk, &[b"key\0", hh], key.as_mut_slice());
    let mut commitment = [0; 32];
    hkdf_expand(&prk, &[b"commit\0", hh], &mut commitment);
    (key, commitment)
}
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    for part in parts {
        m.update(part);
    }
    m.finalize().into_bytes().into()
}

/// GOYOKE01 (148 bytes) holds the data key and the TOTP secret, GOYOKE02
/// (128 bytes) the data key only. The magic is part of the authenticated
/// header, so one kind cannot be passed off as the other. 0.9 still writes
/// them for a new vault without security keys.
pub(super) fn encode_key(
    id: &[u8; 16],
    key: &[u8; 32],
    otp: Option<&[u8; 20]>,
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
            plain[32..].copy_from_slice(secret);
            52
        }
        None => 32,
    };
    let ciphertext = crypto::seal(&wrapping, &nonce, &header, &plain[..used])?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}
pub(super) type KeyMaterial = ([u8; 16], Box<Key>, Option<Box<Zeroizing<[u8; 20]>>>);
pub(super) fn decode_key(data: &[u8], password: &str) -> Result<KeyMaterial> {
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

/// A GOYOKE03 of `spec` and `bundle` sealed with `password` whose key-ID
/// list states `ids` instead of the bundle's own: what a key file claiming
/// a data key it lacks looks like (spec §3.4 step 6). Its commitment, body
/// and every chain entry verify; the key-ID check of `open` refuses it.
#[cfg(test)]
pub(crate) fn seal_claiming(
    spec: &Spec,
    bundle: &Bundle,
    password: &str,
    ids: &[[u8; 16]],
) -> Vec<u8> {
    let (bytes, _) = seal(spec, bundle, password, Plan::PasswordOnly).unwrap();
    let w = parse(&bytes).unwrap().w;
    let mut out = bytes[..w].to_vec();
    for (i, id) in ids.iter().enumerate() {
        out[96 + 16 * i..96 + 16 * (i + 1)].copy_from_slice(id);
    }
    let pw_key = crypto::derive(password.as_bytes(), &[1; 32]).unwrap();
    out.extend_from_slice(&spec.resume);
    out.extend_from_slice(&[1; 32]);
    out.extend_from_slice(&[2; 24]);
    let (k_body, c_body) = body_keys(&pw_key, &[0; 32], &sha256(&[&out]));
    out.extend_from_slice(&c_body);
    let body = crypto::seal(&k_body, &[2; 24], &out, &bundle.plain()).unwrap();
    out.extend_from_slice(&body);
    let end = sha256(&[&out]);
    for key in bundle.keys() {
        out.extend_from_slice(&chain_mac(&spec.vault_id, key, &end));
    }
    out
}
/// A well-formed GOYOKS01 (`sync`) or GOYOKH01 of three keys from the
/// grammar tests, for the tests of what a build without security-key
/// support does with one. Its wraps and body are filler.
#[cfg(test)]
pub(crate) fn hardware_draft(sync: bool) -> Vec<u8> {
    if sync { tests::ks() } else { tests::kh() }.bytes()
}
/// The security-key files scripts/make_key_fixtures.py pinned in the v3
/// layout, with whether each is a well-formed GOYOKH01/GOYOKS01; the others
/// are damaged copies of them and newer magics of the family (spec §11.4).
#[cfg(test)]
pub(crate) const SECURITY_KEY_FIXTURES: [(&str, &[u8], bool); 10] = [
    (
        "goyokh01",
        include_bytes!("../../tests/fixtures/goyokh01.goyokey"),
        true,
    ),
    (
        "goyoks01",
        include_bytes!("../../tests/fixtures/goyoks01.goyokey"),
        true,
    ),
    (
        "goyokh01-truncated",
        include_bytes!("../../tests/fixtures/goyokh01-truncated.goyokey"),
        false,
    ),
    (
        "goyokh01-appended",
        include_bytes!("../../tests/fixtures/goyokh01-appended.goyokey"),
        false,
    ),
    (
        "goyokh01-reserved",
        include_bytes!("../../tests/fixtures/goyokh01-reserved.goyokey"),
        false,
    ),
    (
        "goyoks01-truncated",
        include_bytes!("../../tests/fixtures/goyoks01-truncated.goyokey"),
        false,
    ),
    (
        "goyoks01-appended",
        include_bytes!("../../tests/fixtures/goyoks01-appended.goyokey"),
        false,
    ),
    (
        "goyoks01-reserved",
        include_bytes!("../../tests/fixtures/goyoks01-reserved.goyokey"),
        false,
    ),
    (
        "goyokh02",
        include_bytes!("../../tests/fixtures/goyokh02.goyokey"),
        false,
    ),
    (
        "goyoks02",
        include_bytes!("../../tests/fixtures/goyoks02.goyokey"),
        false,
    ),
];
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        KdfProfile, derive_count, queue_random, queued_random, set_kdf_profile, set_test_now,
    };

    fn seq<const N: usize>(start: u8) -> [u8; N] {
        std::array::from_fn(|i| start.wrapping_add(i as u8))
    }
    fn mixed<const N: usize>(byte: u8) -> [u8; N] {
        std::array::from_fn(|i| byte ^ i as u8)
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn body_aeads() -> u32 {
        BODY_AEADS.with(std::cell::Cell::get)
    }
    fn take_failed_at() -> Option<Step> {
        FAILED_AT.with(|s| s.take())
    }
    fn file(bytes: &[u8]) -> Result<KeyFile> {
        KeyFile::from_bytes(Path::new("test.goyokey"), bytes.to_vec())
    }

    /// A GOYOKE03 that scripts/make_key_fixtures.py wrote from recorded
    /// inputs, and those inputs (the same seq/mixed patterns as there).
    struct Fixture {
        bytes: &'static [u8],
        password: &'static str,
        spec: Spec,
        keys: Vec<[u8; 32]>,
        otp: Option<[u8; 20]>,
        written: u64,
        /// The recorded draws in seal's order: the salt, the body nonce.
        draws: ([u8; 32], [u8; 24]),
        tag: &'static str,
        code: &'static str,
    }
    const WRITTEN: u64 = 1_767_225_600;
    fn fixture_password() -> Fixture {
        Fixture {
            bytes: include_bytes!("../../tests/fixtures/goyoke03-test.goyokey"),
            password: "goyo fixture passphrase, KE03",
            spec: Spec {
                vault_id: seq(0x10),
                epoch: 7,
                kind: Kind::Password,
                next: 3,
                pw_id: seq(0x30),
                loss: 0,
                // Out of order on purpose: seal sorts them.
                tombstones: vec![
                    Tombstone {
                        credhash: [0xa2; 16],
                        removed: 5 | 20_455 << 48,
                    },
                    Tombstone {
                        credhash: [0xa1; 16],
                        removed: 2,
                    },
                ],
                resume: seq(0xc0),
            },
            keys: vec![seq(0x40), seq(0x60)],
            otp: Some(seq(0x80)),
            written: WRITTEN,
            draws: (mixed(0x5a), mixed(0xa5)),
            tag: "d0ae538c5e5bdeaef009ae29055c806a",
            code: "6af6e45f0540f1c6",
        }
    }
    fn fixture_keys_off() -> Fixture {
        Fixture {
            bytes: include_bytes!("../../tests/fixtures/goyoke03-keysoff.goyokey"),
            password: "another fixture passphrase",
            spec: Spec {
                vault_id: seq(0x90),
                epoch: EPOCH_MAX,
                kind: Kind::KeysOff,
                next: 5,
                pw_id: seq(0x01),
                loss: 0,
                tombstones: vec![
                    Tombstone {
                        credhash: [0xb3; 16],
                        removed: EPOCH_MAX | 1 << 48,
                    },
                    Tombstone {
                        credhash: [0xb1; 16],
                        removed: EPOCH_MAX,
                    },
                    Tombstone {
                        credhash: [0xb2; 16],
                        removed: 4,
                    },
                ],
                resume: [0; 32],
            },
            keys: vec![seq(0x21), seq(0x42), seq(0x63)],
            otp: None,
            written: WRITTEN + 1,
            draws: (mixed(0x3c), mixed(0xc3)),
            tag: "12f5816cd94593c5af55336c002af204",
            code: "26c0e60076514644",
        }
    }
    fn fixture_real() -> Fixture {
        Fixture {
            bytes: include_bytes!("../../tests/fixtures/goyoke03-real.goyokey"),
            password: "goyo real-profile fixture passphrase",
            spec: Spec {
                vault_id: seq(0xf0),
                epoch: 1,
                kind: Kind::Password,
                next: 1,
                pw_id: seq(0x71),
                loss: 0,
                tombstones: vec![],
                resume: [0; 32],
            },
            keys: vec![seq(0x20)],
            otp: None,
            written: WRITTEN,
            draws: (mixed(0x11), mixed(0x22)),
            tag: "51af9edf2d7225ba074565cc4c954af6",
            code: "5ab3e523313a4c70",
        }
    }
    impl Fixture {
        fn bundle(&self) -> Bundle {
            Bundle::new(&self.keys, self.otp.as_ref()).unwrap()
        }
        /// Seals the recorded inputs with the recorded draws and time.
        fn seal(&self, plan: Plan) -> Result<(Vec<u8>, WriterSecrets)> {
            queue_random(&[&self.draws.0, &self.draws.1]);
            set_test_now(Some(self.written));
            let sealed = seal(&self.spec, &self.bundle(), self.password, plan);
            set_test_now(None);
            assert_eq!(queued_random(), 0, "seal draws the salt and the nonce");
            sealed
        }
        /// Seals, compares with the Python bytes and opens them.
        fn reproduce(&self) {
            let (bytes, written) = self.seal(Plan::PasswordOnly).unwrap();
            assert_eq!(hex(&bytes), hex(self.bytes));
            let file = file(self.bytes).unwrap();
            let h = file.header().unwrap();
            let mut spec = self.spec.clone();
            spec.tombstones.sort_unstable_by_key(Tombstone::order);
            assert_eq!(h.spec(), spec);
            assert_eq!(
                (h.magic, h.written, h.otp()),
                (Magic::Ke03, self.written, self.otp.is_some())
            );
            assert_eq!(hex(&h.tag), self.tag);
            let opened = file.open(self.password, None).unwrap();
            assert!(opened.bundle.same(&self.bundle()));
            assert_eq!(opened.state, h.state());
            assert_eq!(
                (opened.pw_id, opened.slot, opened.s.is_none()),
                (self.spec.pw_id, None, true)
            );
            assert!(
                file.open_written(&written)
                    .unwrap()
                    .bundle
                    .same(&self.bundle())
            );
            let code = key_code(&self.spec.vault_id, &self.keys[0], h.state());
            assert_eq!(hex(&code.0), self.code);
            for key in &self.keys {
                assert!(file.chain_ok(key));
            }
        }
    }

    #[test]
    fn goyoke03_bytes_match_the_independent_encoder() {
        set_kdf_profile(KdfProfile::Test);
        let fixture = fixture_password();
        fixture.reproduce();
        fixture_keys_off().reproduce();
        // The tombstone at EPOCH_MAX keeps its epoch and its loss mark.
        let h = parse(fixture_keys_off().bytes).unwrap();
        assert_eq!(h.epoch, EPOCH_MAX);
        let marks: Vec<_> = h
            .tombstones
            .iter()
            .map(|t| (t.epoch(), t.loss_mark()))
            .collect();
        assert_eq!(marks, [(4, 0), (EPOCH_MAX, 0), (EPOCH_MAX, 1)]);
        assert_eq!(
            parse(fixture.bytes).unwrap().tombstones[1].loss_mark(),
            20_455
        );
        // The same-epoch re-seal: [0, W) byte for byte, so the state tag
        // stays; a new seal block, body and chain.
        let source = file(fixture.bytes).unwrap();
        let w = source.header().unwrap().w;
        let opened = source.open(fixture.password, None).unwrap();
        let mut again = fixture.spec.clone();
        again.resume = seq(0xe0);
        queue_random(&[&mixed::<32>(0x66), &mixed::<24>(0x99)]);
        let (resealed, _) = seal(
            &again,
            &fixture.bundle(),
            fixture.password,
            Plan::Reseal {
                source: &source,
                opened: &opened,
            },
        )
        .unwrap();
        let python = include_bytes!("../../tests/fixtures/goyoke03-test-reseal.goyokey");
        assert_eq!(hex(&resealed), hex(python));
        assert_eq!(resealed[..w], fixture.bytes[..w]);
        let resealed = file(&resealed).unwrap();
        let h = resealed.header().unwrap();
        assert_eq!(
            (h.tag, h.resume, h.written),
            (source.header().unwrap().tag, seq(0xe0), WRITTEN)
        );
        assert!(
            resealed
                .open(fixture.password, None)
                .unwrap()
                .bundle
                .same(&fixture.bundle())
        );
    }

    #[test]
    fn goyoke03_real_profile_matches_the_independent_encoder() {
        // Pins the Argon2 constants of a release build across both sides.
        set_kdf_profile(KdfProfile::Real);
        let start = derive_count();
        fixture_real().reproduce();
        assert_eq!(derive_count(), start + 2);
    }

    /// A GOYOKH01 or GOYOKS01 that scripts/make_key_fixtures.py wrote, and
    /// what this build can check it against (hw_fixtures.json): the data
    /// keys, the OTP secret, S and the password.
    struct HwFixture {
        bytes: &'static [u8],
        password: &'static str,
        vault_id: [u8; 16],
        keys: Vec<[u8; 32]>,
        otp: Option<[u8; 20]>,
        s: [u8; 32],
        tag: &'static str,
        code: &'static str,
    }
    /// The day of the recorded loss (2025-12-31) as a tombstone's loss mark.
    const LOSS: u64 = 1_767_139_200;
    const LOSS_MARK: u16 = (LOSS / 86_400 + 2) as u16;
    fn fixture_kh() -> HwFixture {
        HwFixture {
            bytes: SECURITY_KEY_FIXTURES[0].1,
            password: "goyo security-key fixture, KH",
            vault_id: seq(0x31),
            keys: vec![seq(0xa1), seq(0xc1)],
            otp: Some(seq(0x91)),
            s: mixed(0x3d),
            tag: "506757c8238d41012b6f1972c4ee7987",
            code: "7f9163db126f5fe9",
        }
    }
    fn fixture_ks() -> HwFixture {
        HwFixture {
            bytes: SECURITY_KEY_FIXTURES[1].1,
            password: "goyo security-key fixture, KS",
            vault_id: seq(0x3a),
            keys: vec![seq(0x0b), seq(0x2b), seq(0x4b)],
            otp: None,
            s: mixed(0x6d),
            tag: "4cc404ad040270f44a7cc6f227bafcde",
            code: "cd3f27d44e6cf236",
        }
    }
    fn slot_view(h: &KeyHeader) -> Vec<(u8, u8, usize, u64)> {
        h.slots
            .iter()
            .map(|s| (s.number, s.flags, s.cred_id.len(), s.added_epoch))
            .collect()
    }
    fn marks(h: &KeyHeader) -> Vec<(u64, u16)> {
        h.tombstones
            .iter()
            .map(|t| (t.epoch(), t.loss_mark()))
            .collect()
    }

    /// The pinned security-key files parse to what they were made from (the
    /// parser is the same in every build), and their body opens with the
    /// recorded S and password through this build's own primitives: no
    /// security-key code is needed to agree with the independent encoder on
    /// the layout, `ks_id`, the body keys, the chain, the state tag and the
    /// key code. Opening them as key files is refused on the magic, with no
    /// key derivation (spec §4.6, §4.7, §14.1-3, §14.2-7).
    #[test]
    fn security_key_fixtures_match_the_independent_encoder() {
        set_kdf_profile(KdfProfile::Test);
        let (kh, ks) = (fixture_kh(), fixture_ks());
        // Two keys without PIN mode, both touched to remove a lost third.
        let a = parse(kh.bytes).unwrap();
        assert_eq!(
            (a.magic, a.epoch, a.kind, a.flags, a.next, a.loss),
            (Magic::Kh01, 6, Kind::Remove, 1, 4, LOSS)
        );
        assert_eq!((a.authorizer, a.present, a.suspended), (Some(1), 0b11, 0));
        assert_eq!(slot_view(&a), [(1, 1, 16, 1), (3, 0, 64, 4)]);
        assert_eq!(
            (a.slots[0].added_by, a.slots[1].added_by),
            ([0; 16], a.slots[0].credhash)
        );
        assert_eq!(
            (a.pairs.as_slice(), a.wraps.as_slice()),
            (&[(0, 1), (1, 0)][..], &[(0, 0), (1, 1)][..])
        );
        assert_eq!(marks(&a), [(3, 0), (6, LOSS_MARK)]);
        assert_eq!((a.reach(1), a.reach(3)), (vec![1, 3], vec![1, 3]));
        // Four keys in PIN mode: keys 2 and 4 touched, key 5 reached through
        // the authorizer's pair record, key 6 suspended.
        let b = parse(ks.bytes).unwrap();
        assert_eq!(
            (b.magic, b.epoch, b.kind, b.flags, b.next, b.loss),
            (Magic::Ks01, 9, Kind::Pair, 2, 7, 0)
        );
        assert_eq!(
            (b.authorizer, b.present, b.suspended),
            (Some(0), 0b0011, 0b1000)
        );
        assert_eq!(
            slot_view(&b),
            [(2, 3, 32, 1), (4, 3, 48, 3), (5, 3, 64, 5), (6, 3, 80, 7)]
        );
        assert_eq!(b.pairs, [(0, 1), (0, 2), (1, 0), (2, 0), (3, 0)]);
        assert_eq!(b.wraps, [(0, 0), (1, 1), (2, 0)]);
        assert_eq!(marks(&b), [(2, 0), (8, 1), (8, LOSS_MARK)]);
        assert_eq!((b.reach(2), b.reach(6)), (vec![2, 4, 5], vec![2, 6]));
        let derives = derive_count();
        for f in [&kh, &ks] {
            let h = parse(f.bytes).unwrap();
            assert_eq!(hex(&h.tag), f.tag);
            let ids: Vec<_> = f.keys.iter().map(|k| key_id(&f.vault_id, k)).collect();
            assert_eq!((h.vault_id, h.key_ids.clone()), (f.vault_id, ids));
            let prk = hkdf_extract(b"goyo-vault/v2/ks-id", &[&f.s]);
            let mut ks_id = [0; 16];
            hkdf_expand(&prk, &[&f.vault_id], &mut ks_id);
            assert_eq!(h.ks_id, ks_id);
            assert_ne!(h.ks_id, ks_id_zero(&f.vault_id));
            // The body: one key derivation, then C_body and the AEAD under
            // the recorded S. Without S (as a GOYOKE03 relabel would read
            // it) the commitment differs.
            let salt: [u8; 32] = f.bytes[h.w + 32..h.w + 64].try_into().unwrap();
            let nonce: [u8; 24] = f.bytes[h.w + 64..h.b].try_into().unwrap();
            let pw_key = crypto::derive(f.password.as_bytes(), &salt).unwrap();
            let hh = sha256(&[&f.bytes[..h.b]]);
            let (k_body, c_body) = body_keys(&pw_key, &f.s, &hh);
            assert_eq!(c_body, f.bytes[h.b..h.b + 32]);
            assert_ne!(body_keys(&pw_key, &[0; 32], &hh).1, c_body);
            let plain = crypto::open(
                &k_body,
                &nonce,
                &f.bytes[..h.b + 32],
                &f.bytes[h.b + 32..h.e],
            )
            .unwrap();
            let bundle = Bundle::from_plain(&plain, f.keys.len(), f.otp.is_some()).unwrap();
            assert!(bundle.same(&Bundle::new(&f.keys, f.otp.as_ref()).unwrap()));
            let end = sha256(&[&f.bytes[..h.e]]);
            for (i, key) in f.keys.iter().enumerate() {
                let at = h.e + 32 * i;
                assert_eq!(chain_mac(&f.vault_id, key, &end), f.bytes[at..at + 32]);
            }
            assert_eq!(hex(&key_code(&f.vault_id, &f.keys[0], h.state()).0), f.code);
        }
        assert_eq!(derive_count(), derives + 2);
        // GOYOKS01 of its own vault is the one file sync may carry.
        let syntax = is_sync_key_file(ks.bytes, &ks.vault_id).unwrap();
        assert_eq!(
            (syntax.epoch, syntax.kind, syntax.tag, syntax.current_key_id),
            (9, Kind::Pair, b.tag, b.key_ids[0])
        );
        assert_eq!(
            (syntax.authorizer, syntax.live),
            (b.slots[0].credhash, b.live())
        );
        assert_eq!(syntax.tombstones, b.tombstones);
        assert!(is_sync_key_file(ks.bytes, &kh.vault_id).is_none());
        assert!(is_sync_key_file(kh.bytes, &kh.vault_id).is_none());
        // This build refuses each of them on the magic family alone, the
        // damaged and newer copies with the damaged wording, never as a
        // wrong password and with no key derivation.
        let derives = derive_count();
        for (name, bytes, well_formed) in SECURITY_KEY_FIXTURES {
            assert_eq!(parse(bytes).is_ok(), well_formed, "{name}");
            let f = file(bytes).unwrap();
            let refusal = if well_formed {
                NO_SECURITY_KEY_SUPPORT
            } else {
                NO_SECURITY_KEY_SUPPORT_DAMAGED
            };
            assert!(f.needs_security_key(), "{name}");
            assert_eq!(f.refusal(), Some(refusal), "{name}");
            assert!(f.header().is_none() && f.vault_id().is_none(), "{name}");
            assert_eq!(f.open(kh.password, None).err(), Some(refusal), "{name}");
            assert_eq!(f.open(ks.password, None).err(), Some(refusal), "{name}");
        }
        assert!(file(kh.bytes).unwrap().uses_otp());
        assert_eq!(derive_count(), derives);
    }

    #[test]
    fn goyoke03_round_trips() {
        set_kdf_profile(KdfProfile::Test);
        let password = "round trip passphrase";
        for (k, r, otp, kind) in [1usize, 2, 64]
            .into_iter()
            .flat_map(|k| [0usize, 1, 480].map(|r| (k, r)))
            .flat_map(|(k, r)| [false, true].map(|otp| (k, r, otp)))
            .flat_map(|(k, r, otp)| {
                [Kind::Password, Kind::Union, Kind::KeysOff].map(|kind| (k, r, otp, kind))
            })
        {
            let keys: Vec<[u8; 32]> = (0..k).map(|i| [i as u8 + 1; 32]).collect();
            let otp_secret = otp.then_some([9; 20]);
            let bundle = Bundle::new(&keys, otp_secret.as_ref()).unwrap();
            let spec = Spec {
                vault_id: [5; 16],
                epoch: 1000,
                kind,
                next: 1,
                pw_id: [6; 16],
                loss: 0,
                tombstones: (0..r)
                    .map(|i| {
                        let mut credhash = [0x40; 16];
                        credhash[..2].copy_from_slice(&(i as u16).to_be_bytes());
                        let mark = (i as u64) << 50;
                        Tombstone {
                            credhash,
                            removed: (1 + (i as u64 % 1000)) | mark,
                        }
                    })
                    .collect(),
                resume: [7; 32],
            };
            let (bytes, written) = seal(&spec, &bundle, password, Plan::PasswordOnly).unwrap();
            let size = 96 + 16 * k + 24 * r + 88 + 32 + body_size(k, otp) + 32 * k;
            assert_eq!(bytes.len(), size);
            let f = file(&bytes).unwrap();
            let h = f.header().unwrap();
            let mut sorted = spec.clone();
            sorted.tombstones.sort_unstable_by_key(Tombstone::order);
            assert_eq!(h.spec(), sorted);
            assert_eq!((h.otp(), f.uses_otp(), h.slots.len()), (otp, otp, 0));
            assert!(f.open_written(&written).unwrap().bundle.same(&bundle));
            assert!(f.open(password, None).unwrap().bundle.same(&bundle));
            assert!(f.chain_ok(&keys[k - 1]) && !f.chain_ok(&[0xEE; 32]));
        }
        // The sizes of spec §4.1.
        let one = Bundle::new(&[[1; 32]], None).unwrap();
        let two = Bundle::new(&[[1; 32], [2; 32]], None).unwrap();
        let with_otp = Bundle::new(&[[1; 32]], Some(&[3; 20])).unwrap();
        let spec = fixture_real().spec;
        for (bundle, size) in [(&one, 312), (&with_otp, 332), (&two, 392)] {
            let (bytes, _) = seal(&spec, bundle, "p", Plan::PasswordOnly).unwrap();
            assert_eq!(bytes.len(), size);
        }
    }

    #[test]
    fn seal_refuses_what_the_parse_would_refuse() {
        set_kdf_profile(KdfProfile::Test);
        let fixture = fixture_password();
        let bundle = fixture.bundle();
        let refused = |spec: &Spec| seal(spec, &bundle, "p", Plan::PasswordOnly).err();
        let mut spec = fixture.spec.clone();
        spec.epoch = EPOCH_MAX + 1;
        assert_eq!(refused(&spec), Some(EPOCH_LIMIT));
        let mut spec = fixture.spec.clone();
        spec.tombstones = (0..=TOMB_MAX)
            .map(|i| {
                let mut credhash = [0; 16];
                credhash[..2].copy_from_slice(&(i as u16).to_le_bytes());
                Tombstone {
                    credhash,
                    removed: 1,
                }
            })
            .collect();
        assert_eq!(refused(&spec), Some(TOMBSTONES_FULL));
        spec.tombstones.pop();
        assert_eq!(refused(&spec), None);
        for change in [
            (|s: &mut Spec| s.epoch = 0) as fn(&mut Spec),
            |s| s.next = 0,
            |s| s.pw_id = [0; 16],
            |s| s.kind = Kind::AddKey,
            |s| s.tombstones[0].removed = 8,
            |s| s.tombstones[0].removed = 0,
            |s| s.tombstones[0].removed = 1 << 48,
            |s| s.tombstones[0].credhash = s.tombstones[1].credhash,
        ] {
            let mut spec = fixture.spec.clone();
            change(&mut spec);
            assert_eq!(refused(&spec), Some(NOT_SEALED));
        }
        // A re-seal takes nothing but `resume` from its spec, and needs the
        // bundle that opening the source gave: the same keys and the same
        // TOTP secret, so two files of one state never differ in a secret.
        let source = file(fixture.bytes).unwrap();
        let opened = source.open(fixture.password, None).unwrap();
        let derives = derive_count();
        let reseal = |spec: &Spec, bundle: &Bundle, opened: &Opened| {
            let plan = Plan::Reseal {
                source: &source,
                opened,
            };
            seal(spec, bundle, fixture.password, plan).err()
        };
        let mut spec = fixture.spec.clone();
        spec.epoch += 1;
        assert_eq!(reseal(&spec, &bundle, &opened), Some(NOT_SEALED));
        let other = Bundle::new(&[seq(0x40), seq(0x61)], fixture.otp.as_ref()).unwrap();
        assert_eq!(reseal(&fixture.spec, &other, &opened), Some(NOT_SEALED));
        let no_otp = Bundle::new(&fixture.keys, None).unwrap();
        assert_eq!(reseal(&fixture.spec, &no_otp, &opened), Some(NOT_SEALED));
        let other_otp = Bundle::new(&fixture.keys, Some(&[0x5a; 20])).unwrap();
        assert_eq!(reseal(&fixture.spec, &other_otp, &opened), Some(NOT_SEALED));
        assert_eq!(derive_count(), derives);
        assert_eq!(reseal(&fixture.spec, &bundle, &opened), None);
        // What opening another file gave, even one of the same state and
        // bundle (a re-seal of the source), is not the source's.
        let mut again = fixture.spec.clone();
        again.resume = [0xab; 32];
        let (copy, _) = seal(
            &again,
            &bundle,
            fixture.password,
            Plan::Reseal {
                source: &source,
                opened: &opened,
            },
        )
        .unwrap();
        let copy = file(&copy).unwrap();
        assert_eq!(copy.header().unwrap().tag, source.header().unwrap().tag);
        let opened_copy = copy.open(fixture.password, None).unwrap();
        assert!(opened_copy.bundle.same(&bundle));
        let derives = derive_count();
        assert_eq!(
            reseal(&fixture.spec, &bundle, &opened_copy),
            Some(NOT_SEALED)
        );
        assert_eq!(derive_count(), derives);
        // Only a KF2 file can be re-sealed.
        let legacy = file(&encode_key(&[1; 16], &[2; 32], None, "p").unwrap()).unwrap();
        let one = Bundle::new(&[[2; 32]], None).unwrap();
        let opened_legacy = legacy.open("p", None).unwrap();
        let plan = Plan::Reseal {
            source: &legacy,
            opened: &opened_legacy,
        };
        assert_eq!(seal(&fixture.spec, &one, "p", plan).err(), Some(NOT_SEALED));
    }

    #[test]
    fn a_wrong_password_fails_at_the_body_step() {
        set_kdf_profile(KdfProfile::Test);
        let fixture = fixture_password();
        let good = file(fixture.bytes).unwrap();
        let h = good.header().unwrap().clone();
        // (bytes, password, body AEADs it may run)
        let mut c_body = fixture.bytes.to_vec();
        c_body[h.b] ^= 1;
        let mut body = fixture.bytes.to_vec();
        body[h.b + 40] ^= 1;
        let mut chain = fixture.bytes.to_vec();
        chain[h.e + 33] ^= 1;
        let mut nonce = fixture.bytes.to_vec();
        nonce[h.w + 70] ^= 1;
        let cases: [(&[u8], &str, u32); 5] = [
            // A wrong password ends at the commitment: no body AEAD. So does
            // the right one under another commitment or seal block.
            (fixture.bytes, "wrong passphrase", 0),
            (&c_body, fixture.password, 0),
            (&nonce, fixture.password, 0),
            // A changed body or chain fails after the AEAD, at the same step.
            (&body, fixture.password, 1),
            (&chain, fixture.password, 1),
        ];
        for (bytes, password, aeads) in cases {
            let f = file(bytes).unwrap();
            let (derives, before) = (derive_count(), body_aeads());
            take_failed_at();
            assert_eq!(f.open(password, None).err(), Some(AUTH_ERROR));
            assert_eq!(derive_count(), derives + 1, "one Argon2, always");
            assert_eq!(body_aeads(), before + aeads);
            assert_eq!(take_failed_at(), Some(Step::Body));
        }
        assert!(good.open(fixture.password, None).is_ok());
        assert_eq!(take_failed_at(), None);
        // A security-key file stops before all of it, and never with the
        // AUTH text: no Argon2, no body step.
        let derives = derive_count();
        for bytes in [kh().bytes(), ks().bytes(), kh().bytes()[..300].to_vec()] {
            let refusal = file(&bytes).unwrap().open("any password", None).err();
            assert!(matches!(
                refusal,
                Some(NO_SECURITY_KEY_SUPPORT | NO_SECURITY_KEY_SUPPORT_DAMAGED)
            ));
        }
        assert_eq!(derive_count(), derives);
        assert_eq!(take_failed_at(), None);
    }

    #[test]
    fn a_listed_key_id_needs_its_data_key() {
        // Whoever knows the password can seal a file that lists a key ID
        // without its data key, as a key file claiming to descend from a
        // state would (spec §5.1). The commitment, the body and every chain
        // entry verify; the key-ID cross-check refuses it.
        set_kdf_profile(KdfProfile::Test);
        let fixture = fixture_password();
        let bundle = fixture.bundle();
        let vault_id = fixture.spec.vault_id;
        let w = parse(fixture.bytes).unwrap().w;
        let seal_after = |head: &[u8]| {
            let pw_key = crypto::derive(fixture.password.as_bytes(), &[1; 32]).unwrap();
            let mut bytes = head.to_vec();
            bytes.extend_from_slice(&fixture.spec.resume);
            bytes.extend_from_slice(&[1; 32]);
            bytes.extend_from_slice(&[2; 24]);
            let (k_body, c_body) = body_keys(&pw_key, &[0; 32], &sha256(&[&bytes]));
            bytes.extend_from_slice(&c_body);
            let body = crypto::seal(&k_body, &[2; 24], &bytes, &bundle.plain()).unwrap();
            bytes.extend_from_slice(&body);
            let end = sha256(&[&bytes]);
            for key in bundle.keys() {
                bytes.extend_from_slice(&chain_mac(&vault_id, key, &end));
            }
            file(&bytes).unwrap()
        };
        let honest = seal_after(&fixture.bytes[..w]);
        assert!(honest.open(fixture.password, None).is_ok());
        let mut head = fixture.bytes[..w].to_vec();
        head[96 + 16..96 + 32].copy_from_slice(&key_id(&vault_id, &[0xEE; 32]));
        let claimed = seal_after(&head);
        let before = body_aeads();
        take_failed_at();
        assert_eq!(claimed.open(fixture.password, None).err(), Some(AUTH_ERROR));
        assert_eq!(body_aeads(), before + 1);
        assert_eq!(take_failed_at(), Some(Step::Body));
    }

    #[test]
    fn a_flip_before_the_chain_fails_every_chain_entry() {
        let fixture = fixture_password();
        let e = parse(fixture.bytes).unwrap().e;
        let good = file(fixture.bytes).unwrap();
        assert!(fixture.keys.iter().all(|key| good.chain_ok(key)));
        // A data key the file does not list.
        assert!(!good.chain_ok(&[0x40; 32]));
        for i in 0..e {
            let mut bytes = fixture.bytes.to_vec();
            bytes[i] ^= 1;
            if let Ok(f) = file(&bytes) {
                assert!(fixture.keys.iter().all(|key| !f.chain_ok(key)), "byte {i}");
            }
        }
        // A changed chain entry fails its own key only.
        let mut bytes = fixture.bytes.to_vec();
        bytes[e + 32] ^= 1;
        let f = file(&bytes).unwrap();
        assert!(f.chain_ok(&fixture.keys[0]) && !f.chain_ok(&fixture.keys[1]));
    }

    #[test]
    fn every_byte_flip_of_a_goyoke03_is_refused() {
        set_kdf_profile(KdfProfile::Test);
        let fixture = fixture_password();
        for i in 0..fixture.bytes.len() {
            for mask in [0x01, 0x80, 0xFF] {
                let mut bytes = fixture.bytes.to_vec();
                bytes[i] ^= mask;
                match file(&bytes) {
                    Ok(f) => assert_eq!(
                        f.open(fixture.password, None).err(),
                        Some(AUTH_ERROR),
                        "byte {i} ^ {mask:#x}"
                    ),
                    Err(e) => assert!(matches!(e, AUTH_ERROR | NEWER_KEY_FORMAT), "byte {i}: {e}"),
                }
            }
        }
    }

    #[test]
    fn every_truncation_and_extension_is_refused() {
        set_kdf_profile(KdfProfile::Test);
        let fixture = fixture_password();
        for full in [
            fixture.bytes.to_vec(),
            kh().bytes(),
            ks().bytes(),
            ke03().bytes(),
        ] {
            assert!(parse(&full).is_ok());
            let mut longer = full.clone();
            longer.push(0);
            assert!(parse(&longer).is_err());
            for n in 0..full.len() {
                assert!(parse(&full[..n]).is_err(), "{n} of {} bytes", full.len());
            }
        }
        // A password-only file cut short or grown is refused before any
        // Argon2; a security-key one still gets this build's refusal and never
        // the AUTH text.
        let derives = derive_count();
        let bytes = fixture.bytes;
        for n in 0..bytes.len() {
            assert_eq!(file(&bytes[..n]).err(), Some(AUTH_ERROR));
        }
        assert_eq!(file(&[bytes, &[0][..]].concat()).err(), Some(AUTH_ERROR));
        let bytes = kh().bytes();
        for n in 8..bytes.len() {
            let f = file(&bytes[..n]).unwrap();
            assert_eq!(f.refusal(), Some(NO_SECURITY_KEY_SUPPORT_DAMAGED));
        }
        let f = file(&[&bytes[..], &[0][..]].concat()).unwrap();
        assert_eq!(f.refusal(), Some(NO_SECURITY_KEY_SUPPORT_DAMAGED));
        assert_eq!(derive_count(), derives);
    }

    /// A KF2 file field by field, for the grammar tests. Wraps, the seal
    /// block, the body and the chain are filler: the parse only places them.
    /// The counts follow the lists unless set.
    #[derive(Clone)]
    pub(super) struct Draft {
        magic: [u8; 8],
        vault_id: [u8; 16],
        epoch: u64,
        flags: u8,
        k: Option<u8>,
        n: Option<u8>,
        next: u8,
        r: Option<u16>,
        kind: u8,
        authorizer: u8,
        present: u8,
        suspended: u8,
        p: Option<u8>,
        reserved: [u8; 5],
        ks_id: [u8; 16],
        pw_id: [u8; 16],
        key_ids: Vec<[u8; 16]>,
        tombstones: Vec<([u8; 16], u64)>,
        slots: Vec<DraftSlot>,
        /// owner, target, reserved
        pairs: Vec<[u8; 4]>,
        /// recipient, via
        wraps: Vec<[u8; 2]>,
    }
    #[derive(Clone)]
    struct DraftSlot {
        /// kind, flags, number, reserved
        head: [u8; 4],
        added_epoch: u64,
        added_by: [u8; 16],
        cred_id: Vec<u8>,
    }
    impl Draft {
        pub(super) fn bytes(&self) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend(self.magic);
            b.extend(self.vault_id);
            b.extend(self.epoch.to_le_bytes());
            b.push(self.flags);
            b.push(self.k.unwrap_or(self.key_ids.len() as u8));
            b.push(self.n.unwrap_or(self.slots.len() as u8));
            b.push(self.next);
            b.extend(self.r.unwrap_or(self.tombstones.len() as u16).to_le_bytes());
            let p = self.p.unwrap_or(self.pairs.len() as u8);
            b.extend([self.kind, self.authorizer, self.present, self.suspended, p]);
            b.extend(self.reserved);
            b.extend(self.ks_id);
            b.extend(self.pw_id);
            b.extend(WRITTEN.to_le_bytes());
            b.extend(1u64.to_le_bytes());
            for id in &self.key_ids {
                b.extend(id);
            }
            for (credhash, removed) in &self.tombstones {
                b.extend(credhash);
                b.extend(removed.to_le_bytes());
            }
            for s in &self.slots {
                b.extend(s.head);
                b.extend(WRITTEN.to_le_bytes());
                b.extend(s.added_epoch.to_le_bytes());
                b.extend(s.added_by);
                b.extend([s.head[2]; 32]);
                b.extend((s.cred_id.len() as u16).to_le_bytes());
                b.extend(&s.cred_id);
            }
            for pair in &self.pairs {
                b.extend(pair);
                b.extend([0x5a; WRAP]);
            }
            for wrap in &self.wraps {
                b.extend(wrap);
                b.extend([0xa5; WRAP]);
            }
            b.extend([0x3c; SEAL_BLOCK + 32]);
            b.extend(vec![
                0xc3;
                body_size(self.key_ids.len(), self.flags & 1 != 0)
            ]);
            b.extend(vec![0x66; 32 * self.key_ids.len()]);
            b
        }
        fn parses(&self) -> bool {
            parse(&self.bytes()).is_ok()
        }
    }
    fn slot(number: u8, flags: u8, added_epoch: u64, cred: u8, c: usize) -> DraftSlot {
        DraftSlot {
            head: [1, flags, number, 0],
            added_epoch,
            added_by: [0; 16],
            cred_id: vec![cred; c],
        }
    }
    /// `count` tombstones at epoch 1, credhashes ascending.
    fn tombstones(count: usize) -> Vec<([u8; 16], u64)> {
        (0..count)
            .map(|i| {
                let mut credhash = [0xEE; 16];
                credhash[..2].copy_from_slice(&(i as u16).to_be_bytes());
                (credhash, 1)
            })
            .collect()
    }
    /// GOYOKH01 with three keys at epoch 9, written by key 1 (slot 0) alone:
    /// key 2 gets S through key 1's pair record, key 3 is suspended.
    pub(super) fn kh() -> Draft {
        let mut slots = vec![
            slot(1, 0, 1, 0x11, 40),
            slot(2, 1, 1, 0x22, 64),
            slot(3, 3, 5, 0x33, 1),
        ];
        slots[2].added_by = credhash(&[0x11; 40]);
        Draft {
            magic: *b"GOYOKH01",
            vault_id: seq(0x10),
            epoch: 9,
            flags: 0,
            k: None,
            n: None,
            next: 4,
            r: None,
            kind: Kind::Password as u8,
            authorizer: 0,
            present: 0b001,
            suspended: 0b100,
            p: None,
            reserved: [0; 5],
            ks_id: [0x77; 16],
            pw_id: seq(0x30),
            key_ids: vec![seq(0x40), seq(0x50)],
            tombstones: vec![([0xa1; 16], 2), ([0xa2; 16], 3 | 7 << 48)],
            slots,
            pairs: vec![[0, 1, 0, 0], [1, 0, 0, 0], [2, 0, 0, 0]],
            wraps: vec![[0, 0], [1, 0]],
        }
    }
    /// GOYOKS01: PIN mode, every slot a PIN slot, with an OTP.
    pub(super) fn ks() -> Draft {
        let mut d = kh();
        d.magic = *b"GOYOKS01";
        d.flags = 3;
        for s in &mut d.slots {
            s.head[1] = 3;
        }
        d
    }
    fn ke03() -> Draft {
        Draft {
            magic: *b"GOYOKE03",
            n: None,
            authorizer: 0xFF,
            present: 0,
            suspended: 0,
            ks_id: [0; 16],
            slots: vec![],
            pairs: vec![],
            wraps: vec![],
            ..kh()
        }
    }
    /// The largest file: 64 keys, 480 tombstones, 8 keys with 1023-byte
    /// credential IDs, all 56 pair records, 8 S-wraps and an OTP.
    fn largest() -> Draft {
        let mut d = kh();
        d.flags = 1;
        d.key_ids = (0..64).map(|i| [i; 16]).collect();
        d.tombstones = tombstones(TOMB_MAX);
        d.slots = (0..8).map(|i| slot(i + 1, 0, 1, i, MAX_CRED_ID)).collect();
        d.suspended = 0;
        d.pairs = (0..8u8)
            .flat_map(|o| (0..8).filter(move |t| *t != o).map(move |t| [o, t, 0, 0]))
            .collect();
        d.wraps = (0..8).map(|j| [j, 0]).collect();
        d
    }

    #[test]
    fn the_drafts_parse_and_the_largest_fits_the_read_limit() {
        for d in [kh(), ks(), ke03()] {
            assert!(d.parses());
        }
        let largest = largest().bytes();
        assert_eq!(largest.len(), 32_532);
        let h = parse(&largest).unwrap();
        assert_eq!(
            (
                h.key_ids.len(),
                h.tombstones.len(),
                h.slots.len(),
                h.pairs.len()
            ),
            (64, 480, 8, 56)
        );
        // The smallest security-key file.
        let mut d = kh();
        d.key_ids.truncate(1);
        d.tombstones.clear();
        d.slots = vec![slot(1, 0, 1, 7, 1)];
        d.suspended = 0;
        d.pairs.clear();
        d.wraps = vec![[0, 0]];
        assert_eq!(d.bytes().len(), 489);
        assert!(d.parses());
        // A file over the read limit is refused whatever it holds.
        let mut over = fixture_password().bytes.to_vec();
        over.resize(KEY_FILE_LIMIT + 1, 0);
        assert!(parse(&over).is_err());
        assert_eq!(file(&over).err(), Some(TOO_LARGE));
        let mut over = largest;
        over.resize(KEY_FILE_LIMIT + 1, 0);
        assert_eq!(
            file(&over).unwrap().refusal(),
            Some(NO_SECURITY_KEY_SUPPORT_DAMAGED)
        );
        over[..8].copy_from_slice(b"GOYOKE04");
        assert_eq!(file(&over).err(), Some(NEWER_KEY_FORMAT));
    }

    #[test]
    fn each_count_stops_at_its_limit() {
        let at = |change: fn(&mut Draft)| {
            let mut d = largest();
            change(&mut d);
            d.parses()
        };
        // k: 64, r: 480, c: 1023, p: n(n-1)
        assert!(at(|_| {}));
        assert!(!at(|d| d.key_ids.push([0xFF; 16])));
        assert!(!at(|d| d.tombstones = tombstones(TOMB_MAX + 1)));
        assert!(!at(|d| d.slots[7].cred_id.push(7)));
        assert!(!at(|d| d.p = Some(57)));
        let mut d = kh();
        d.key_ids.clear();
        assert!(!d.parses());
        d.key_ids = vec![[1; 16]];
        d.slots[1].cred_id.clear();
        assert!(!d.parses());
        // n: 8, with the ninth slot past what the masks can address.
        let mut d = kh();
        d.slots = (0..9).map(|i| slot(i + 1, 0, 1, i, 1)).collect();
        d.suspended = 0b1111_1110;
        d.pairs = vec![[0, 8, 0, 0]];
        d.wraps = vec![[0, 0], [8, 0]];
        assert!(!d.parses());
        d.slots.pop();
        d.pairs.clear();
        d.wraps.pop();
        assert!(d.parses());
    }

    #[test]
    fn each_parse_rule_fails_on_its_own() {
        type Change = fn(&mut Draft);
        // Every base parses, so each change below is what makes it fail.
        let refused = |base: fn() -> Draft, name: &str, change: Change| {
            let mut d = base();
            assert!(d.parses(), "{name}: base");
            change(&mut d);
            assert!(!d.parses(), "{name}");
        };
        let header: [(&str, Change); 30] = [
            ("epoch above EPOCH_MAX", |d| d.epoch = EPOCH_MAX + 1),
            ("epoch 2^64 - 1", |d| d.epoch = u64::MAX),
            ("flag bit 2", |d| d.flags |= 4),
            ("flag bit 7", |d| d.flags |= 0x80),
            ("next 0", |d| d.next = 0),
            ("reserved 43", |d| d.reserved[0] = 1),
            ("reserved 44", |d| d.reserved[1] = 1),
            ("reserved 45", |d| d.reserved[2] = 1),
            ("reserved 46", |d| d.reserved[3] = 1),
            ("reserved 47", |d| d.reserved[4] = 0x80),
            ("pw_id zero", |d| d.pw_id = [0; 16]),
            ("ks_id zero", |d| d.ks_id = [0; 16]),
            ("ks_id of a zero S", |d| d.ks_id = ks_id_zero(&d.vault_id)),
            ("PIN mode with a non-PIN slot", |d| d.flags |= 2),
            ("duplicate key IDs", |d| d.key_ids[1] = d.key_ids[0]),
            ("present bit at n", |d| d.present |= 0b1000),
            ("suspended bit at n", |d| d.suspended |= 0b1000),
            ("present and suspended", |d| d.present |= 0b100),
            ("authorizer outside the present mask", |d| {
                d.present = 0b010;
                d.suspended = 0b101;
                d.wraps = vec![[1, 1]];
            }),
            ("authorizer at n", |d| d.authorizer = 3),
            ("kind 0", |d| d.kind = 0),
            ("kind 11", |d| d.kind = 11),
            ("kind 6 in GOYOKH01", |d| d.kind = Kind::SyncOn as u8),
            ("kind 10 in GOYOKH01", |d| d.kind = Kind::KeysOff as u8),
            ("p above n(n-1)", |d| d.pairs.extend([[2, 1, 0, 0]; 4])),
            ("tombstone above the epoch", |d| {
                d.tombstones[1].1 = 10 | 1 << 48
            }),
            ("tombstones out of order by bits 0-47", |d| {
                d.tombstones[0].1 = 4
            }),
            ("tombstone at epoch 0", |d| d.tombstones[0].1 = 0),
            ("tombstone at epoch 0 with a loss mark", |d| {
                d.tombstones[0].1 = 1 << 48
            }),
            ("duplicate tombstone", |d| {
                d.tombstones[1].0 = d.tombstones[0].0
            }),
        ];
        for (name, change) in header {
            refused(kh, name, change);
        }
        let slots: [(&str, Change); 15] = [
            ("slot kind 0", |d| d.slots[1].head[0] = 0),
            ("slot kind 2", |d| d.slots[1].head[0] = 2),
            ("slot flags 4", |d| d.slots[1].head[1] = 4),
            ("slot reserved", |d| d.slots[1].head[3] = 1),
            ("number 0", |d| d.slots[0].head[2] = 0),
            ("numbers out of order", |d| d.slots[1].head[2] = 9),
            ("duplicate number", |d| d.slots[1].head[2] = 1),
            ("credential ID 1024 bytes", |d| {
                d.slots[1].cred_id = vec![0x22; 1024]
            }),
            ("empty credential ID", |d| d.slots[1].cred_id.clear()),
            ("duplicate credential ID", |d| {
                d.slots[1].cred_id = vec![0x11; 40]
            }),
            ("a tombstoned credential", |d| {
                d.tombstones[0].0 = credhash(&[0x22; 64])
            }),
            ("added above the epoch", |d| d.slots[1].added_epoch = 10),
            ("added at epoch 0", |d| d.slots[1].added_epoch = 0),
            ("a slot added in a write of another kind", |d| {
                d.slots[1].added_epoch = 9
            }),
            ("n 0", |d| {
                d.slots.clear();
                d.present = 0;
                d.suspended = 0;
                d.pairs.clear();
                d.wraps.clear();
            }),
        ];
        for (name, change) in slots {
            refused(kh, name, change);
        }
        let tables: [(&str, Change); 13] = [
            ("pair records out of order", |d| d.pairs.swap(0, 1)),
            ("duplicate pair record", |d| d.pairs.insert(0, [0, 1, 0, 0])),
            ("pair record to itself", |d| d.pairs[2] = [2, 2, 0, 0]),
            ("pair record owner at n", |d| d.pairs[2] = [3, 0, 0, 0]),
            ("pair record target at n", |d| d.pairs[2] = [2, 3, 0, 0]),
            ("pair record reserved", |d| d.pairs[1][2] = 1),
            ("pair record reserved 2", |d| d.pairs[1][3] = 1),
            ("missing S-wrap", |d| {
                d.wraps.pop();
            }),
            ("S-wrap for a suspended slot", |d| d.wraps.push([2, 0])),
            ("via neither recipient nor authorizer", |d| {
                d.wraps[1] = [1, 2]
            }),
            ("via without its pair record", |d| {
                d.pairs.remove(0);
            }),
            ("via the authorizer for a present key", |d| {
                d.present = 0b011
            }),
            ("S-wraps out of slot order", |d| d.wraps.swap(0, 1)),
        ];
        for (name, change) in tables {
            refused(kh, name, change);
        }
        // The kinds with their own slot and mask rules, each from a base of
        // that kind that parses.
        let keys_on = || {
            let mut d = kh();
            d.kind = Kind::KeysOn as u8;
            d.present = 0b111;
            d.suspended = 0;
            for s in &mut d.slots {
                s.added_epoch = 9;
                s.added_by = [0; 16];
            }
            d.wraps = vec![[0, 0], [1, 1], [2, 2]];
            d
        };
        refused(keys_on, "kind 1 with an absent key", |d| {
            d.present = 0b011;
            d.pairs = vec![[0, 2, 0, 0]];
            d.wraps[2] = [2, 0];
        });
        refused(keys_on, "kind 1 with an older key", |d| {
            d.slots[0].added_epoch = 8
        });
        refused(keys_on, "kind 1 added by a key", |d| {
            d.slots[1].added_by = [1; 16]
        });
        refused(keys_on, "kind 1 in GOYOKS01", |d| {
            d.magic = *b"GOYOKS01";
            d.flags = 2;
            for s in &mut d.slots {
                s.head[1] = 3;
            }
        });
        let add_key = || {
            let mut d = kh();
            d.kind = Kind::AddKey as u8;
            d.slots[2].added_epoch = 9;
            d.present = 0b101;
            d.suspended = 0;
            d.wraps = vec![[0, 0], [1, 0], [2, 2]];
            d
        };
        refused(add_key, "kind 3 with no new key", |d| {
            d.slots[2].added_epoch = 5
        });
        refused(add_key, "kind 3 with two new keys", |d| {
            d.slots[1].added_epoch = 9;
            d.slots[1].added_by = d.slots[2].added_by;
        });
        refused(add_key, "kind 3 with an absent new key", |d| {
            d.present = 0b001;
            d.pairs.insert(1, [0, 2, 0, 0]);
            d.wraps[2] = [2, 0];
        });
        refused(add_key, "kind 3 added by another key", |d| {
            d.slots[2].added_by = credhash(&[0x22; 64]);
        });
        refused(add_key, "kind 3 in GOYOKE03", |d| d.magic = *b"GOYOKE03");
        let pair = || {
            let mut d = kh();
            d.kind = Kind::Pair as u8;
            d.present = 0b011;
            d.wraps = vec![[0, 0], [1, 1]];
            d
        };
        refused(pair, "kind 5 with one key present", |d| {
            d.present = 0b001;
            d.wraps[1] = [1, 0];
        });
        let reseed = || {
            let mut d = kh();
            d.kind = Kind::ReSeed as u8;
            d.present = 0b111;
            d.suspended = 0;
            d.wraps = vec![[0, 0], [1, 1], [2, 2]];
            d
        };
        refused(reseed, "kind 8 with an absent key", |d| {
            d.present = 0b011;
            d.wraps[2] = [2, 0];
            d.pairs.insert(1, [0, 2, 0, 0]);
        });
        refused(reseed, "kind 8 with a suspended key", |d| {
            d.present = 0b011;
            d.suspended = 0b100;
            d.wraps.pop();
        });
        refused(reseed, "kind 8 with a new key", |d| {
            d.slots[2].added_epoch = 9;
        });
        // GOYOKS01: PIN mode and PIN slots, and its own kinds.
        let ks_rules: [(&str, Change); 4] = [
            ("GOYOKS01 without PIN mode", |d| d.flags = 1),
            ("GOYOKS01 with a non-PIN slot", |d| d.slots[0].head[1] = 1),
            ("kind 7 in GOYOKS01", |d| d.kind = Kind::SyncOff as u8),
            ("kind 10 in GOYOKS01", |d| d.kind = Kind::KeysOff as u8),
        ];
        for (name, change) in ks_rules {
            refused(ks, name, change);
        }
        // GOYOKE03: no keys, no masks, no keyset ID, its own kinds.
        let ke03_rules: [(&str, Change); 11] = [
            ("epoch 0", |d| {
                d.epoch = 0;
                d.tombstones.clear();
            }),
            ("PIN mode", |d| d.flags = 2),
            ("an authorizer", |d| d.authorizer = 0),
            ("a present mask", |d| d.present = 1),
            ("a suspended mask", |d| d.suspended = 1),
            ("a keyset ID", |d| d.ks_id = [0x77; 16]),
            ("kind 4", |d| d.kind = Kind::Remove as u8),
            ("kind 6", |d| d.kind = Kind::SyncOn as u8),
            ("kind 7", |d| d.kind = Kind::SyncOff as u8),
            ("a slot", |d| {
                d.slots = vec![slot(1, 0, 1, 7, 1)];
            }),
            ("a pair record count", |d| d.p = Some(1)),
        ];
        for (name, change) in ke03_rules {
            refused(ke03, name, change);
        }
        // What the rules leave free: any loss mark, order by bits 0-47 only,
        // `written` and `loss`, an epoch of EPOCH_MAX.
        let accepted: [Change; 5] = [
            |d| d.tombstones[1].1 = 3 | 0xFFFF << 48,
            |d| {
                d.tombstones[0].1 = 2 | 9 << 48;
                d.tombstones[1].1 = 3;
            },
            |d| d.tombstones[1].0 = [0x01; 16],
            |d| d.epoch = EPOCH_MAX,
            |d| d.next = 255,
        ];
        for change in accepted {
            for base in [kh as fn() -> Draft, ks, ke03] {
                let mut d = base();
                change(&mut d);
                assert!(d.parses());
            }
        }
    }

    #[test]
    fn the_magic_family_decides_first() {
        set_kdf_profile(KdfProfile::Test);
        let derives = derive_count();
        // Well-formed GOYOKH01/GOYOKS01: refused, on the magic alone.
        for d in [kh(), ks()] {
            let f = file(&d.bytes()).unwrap();
            assert!(f.needs_security_key());
            assert_eq!(f.refusal(), Some(NO_SECURITY_KEY_SUPPORT));
            assert_eq!(f.magic(), Some(Magic::of(&d.magic).unwrap()));
            assert!(f.header().is_none() && f.vault_id().is_none());
        }
        assert!(file(&ks().bytes()).unwrap().uses_otp());
        // Damaged, newer, or another grammar under the same family: the same
        // refusal with S-NOSK-DAMAGED, never a wrong password.
        let mut flipped = kh().bytes();
        flipped[38] = 10;
        let damaged = [
            [b"GOYOKH02".as_slice(), &kh().bytes()[8..]].concat(),
            [b"GOYOKS02".as_slice(), &ks().bytes()[8..]].concat(),
            [b"GOYOKHzz".as_slice(), &kh().bytes()[8..]].concat(),
            kh().bytes()[..100].to_vec(),
            flipped,
            [b"GOYOKH01".as_slice(), &fixture_password().bytes[8..]].concat(),
            b"GOYOKS01".to_vec(),
        ];
        for bytes in damaged {
            let f = file(&bytes).unwrap();
            assert!(f.needs_security_key() && f.magic().is_none());
            assert_eq!(f.refusal(), Some(NO_SECURITY_KEY_SUPPORT_DAMAGED));
        }
        assert_eq!(derive_count(), derives);
        // Other newer magics: numbered above what this build knows of their
        // letter. Then anything else is a wrong file, GOYOKE00 included.
        for magic in [b"GOYOKE04", b"GOYOKX01", b"GOYOKZ99", b"GOYOKE10"] {
            let bytes = [magic.as_slice(), &fixture_password().bytes[8..]].concat();
            assert_eq!(file(&bytes).err(), Some(NEWER_KEY_FORMAT));
            assert!(never_replaced(&bytes));
        }
        for bytes in [
            &b"GOYOKE0A"[..],
            b"GOYOKE00",
            b"GOYOKX00",
            b"GOYOKe01",
            b"GOYOVA01",
            b"GOYOKH",
            b"",
            &fixture_password().bytes[1..],
        ] {
            assert_eq!(file(bytes).err(), Some(AUTH_ERROR));
            assert!(!never_replaced(bytes));
        }
        // An unlock never puts a temp file in place of a security-key file
        // (spec §5.12 rule i), whatever its state; known magics it can
        // judge.
        for bytes in [kh().bytes(), b"GOYOKS02".to_vec(), b"GOYOKHzz".to_vec()] {
            assert!(never_replaced(&bytes));
        }
        for bytes in [fixture_password().bytes, b"GOYOKE01", b"GOYOKE02"] {
            assert!(!never_replaced(bytes));
        }
        // The relabel matrix over the five magics: no file passes as
        // another; a hardware magic gets this build's refusal.
        let legacy_otp =
            encode_key(&[1; 16], &[2; 32], Some(&Zeroizing::new([3; 20])), "p").unwrap();
        let legacy = encode_key(&[1; 16], &[2; 32], None, "p").unwrap();
        let originals = [
            legacy_otp,
            legacy,
            fixture_password().bytes.to_vec(),
            kh().bytes(),
            ks().bytes(),
        ];
        let derives = derive_count();
        for (i, original) in originals.iter().enumerate() {
            for (j, magic) in Magic::ALL.into_iter().enumerate() {
                if i == j {
                    continue;
                }
                let bytes = [magic.bytes().as_slice(), &original[8..]].concat();
                match file(&bytes) {
                    Ok(f) => {
                        assert!(
                            magic.hardware() && f.refusal().is_some(),
                            "{i} as {magic:?}"
                        );
                        // A GOYOKS01 relabelled GOYOKH01 is well-formed, and
                        // its AAD names the other magic.
                        assert_eq!(
                            f.refusal() == Some(NO_SECURITY_KEY_SUPPORT),
                            (i, magic) == (4, Magic::Kh01)
                        );
                    }
                    Err(e) => assert!(!magic.hardware() && e == AUTH_ERROR),
                }
            }
        }
        assert_eq!(derive_count(), derives);
    }

    #[test]
    fn legacy_key_files_open_with_their_state() {
        set_kdf_profile(KdfProfile::Test);
        let otp = Zeroizing::new([3; 20]);
        for (secret, magic, size) in [(Some(&otp), Magic::Ke01, 148), (None, Magic::Ke02, 128)] {
            let bytes = encode_key(
                &[1; 16],
                &[2; 32],
                secret.map(|o| &**o),
                "legacy passphrase",
            )
            .unwrap();
            let f = file(&bytes).unwrap();
            assert_eq!(
                (f.bytes().len(), f.magic(), f.uses_otp()),
                (size, Some(magic), secret.is_some())
            );
            assert_eq!(f.vault_id(), Some([1; 16]));
            assert!(f.header().is_none() && !f.needs_security_key() && f.refusal().is_none());
            let opened = f.open("legacy passphrase", None).unwrap();
            assert_eq!(opened.bundle.keys(), [[2; 32]]);
            assert!(opened.bundle.current() == opened.bundle.id_key());
            assert_eq!(opened.bundle.otp(), secret.map(|o| &**o));
            let tag = legacy_tag(
                magic,
                &[1; 16],
                secret.is_some(),
                &key_id(&[1; 16], &[2; 32]),
            );
            assert_eq!(opened.state, KeyState { epoch: 0, tag });
            assert_eq!(opened.pw_id, [0; 16]);
            assert!(!f.chain_ok(&[2; 32]));
            assert_eq!(f.open("wrong passphrase", None).err(), Some(AUTH_ERROR));
            assert_eq!(file(&bytes[..size - 1]).err(), Some(AUTH_ERROR));
            assert_eq!(
                file(&[&bytes[..], &[0][..]].concat()).err(),
                Some(AUTH_ERROR)
            );
        }
    }

    #[test]
    fn constructions_match_the_pinned_vectors() {
        // The inputs and values of crypto::self_test, which an independent
        // Python implementation pinned.
        let id: [u8; 16] = seq(0x00);
        let dk: [u8; 32] = seq(0x40);
        let pw_key: [u8; 32] = seq(0x60);
        let s: [u8; 32] = seq(0x20);
        assert_eq!(hex(&ks_id_zero(&id)), "00e05758b26ba1020e4917c0f09cde46");
        assert_eq!(
            hex(&ks_id_zero(&seq(0xf0))),
            "05dbbff54e112a43163cfd3043607e99"
        );
        assert_eq!(hex(&key_id(&id, &dk)), "e8a35551018cd7f203358a34f4d4ce11");
        assert_eq!(
            hex(&credhash(&seq::<48>(0x80))),
            "eae7075189d482632efecaea800c1751"
        );
        let header = sha256(&[b"goyo self-test: file[0..B)"]);
        let (k_body, c_body) = body_keys(&pw_key, &s, &header);
        assert_eq!(
            hex(k_body.as_slice()),
            "3eb7c4357aa110ac681e1efef18258f9cd2031b79711286ec7275f0abc1186f1"
        );
        assert_eq!(
            hex(&c_body),
            "342931f2dcdfa681c7436d171865dea78fc1add85afb8d9f0377bfd0a83ec978"
        );
        let (k_body, _) = body_keys(&pw_key, &[0; 32], &header);
        assert_eq!(
            hex(k_body.as_slice()),
            "ff41d4f12b5014376f124f6d622e89365fc91dab5dd86b876bc5e1acf3178668"
        );
        let end = sha256(&[b"goyo self-test: file[0..E)"]);
        assert_eq!(
            hex(&chain_mac(&id, &dk, &end)),
            "de51f3d425d54f72473348c64778f35d8467aad6c443209865d7dd2e62b78ae1"
        );
        let tag = state_tag(b"goyo self-test: file[0..W)");
        assert_eq!(hex(&tag), "3d2aa8812e6c57811402bce76d161dcd");
        let legacy = legacy_tag(Magic::Ke01, &id, true, &key_id(&id, &dk));
        assert_eq!(hex(&legacy), "6587b8d02709169936da046237e83509");
        let code = key_code(&id, &dk, KeyState { epoch: 7, tag });
        assert_eq!(hex(&code.0), "cd8acfb3a5e496f0");
        assert_eq!(code.show(7), "E7 · CD8A-CFB3-A5E4-96F0");
        // Keyed by the data key and bound to the state.
        assert_ne!(key_code(&id, &s, KeyState { epoch: 7, tag }), code);
        assert_ne!(key_code(&id, &dk, KeyState { epoch: 8, tag }), code);
        assert_ne!(key_code(&seq(0xf0), &dk, KeyState { epoch: 7, tag }), code);
    }

    #[test]
    fn sync_key_files_and_reach_from_public_bytes() {
        let d = ks();
        let syntax = is_sync_key_file(&d.bytes(), &d.vault_id).unwrap();
        assert_eq!(
            (syntax.epoch, syntax.kind, syntax.current_key_id),
            (9, Kind::Password, seq(0x40))
        );
        assert_eq!(syntax.tag, parse(&d.bytes()).unwrap().tag);
        assert_eq!(syntax.authorizer, credhash(&[0x11; 40]));
        assert_eq!(syntax.live.len(), 3);
        assert_eq!(syntax.tombstones[1].loss_mark(), 7);
        // GOYOKS01 of this vault only, and only a well-formed one.
        assert!(is_sync_key_file(&d.bytes(), &[0; 16]).is_none());
        assert!(is_sync_key_file(&kh().bytes(), &d.vault_id).is_none());
        assert!(is_sync_key_file(&ke03().bytes(), &d.vault_id).is_none());
        assert!(is_sync_key_file(fixture_password().bytes, &seq(0x10)).is_none());
        assert!(is_sync_key_file(&d.bytes()[..400], &d.vault_id).is_none());
        let mut zero = ks();
        zero.ks_id = ks_id_zero(&zero.vault_id);
        assert!(is_sync_key_file(&zero.bytes(), &zero.vault_id).is_none());
        let mut far = ks();
        far.epoch = EPOCH_MAX + 1;
        assert!(is_sync_key_file(&far.bytes(), &far.vault_id).is_none());
        // Reach: key 1 reaches key 2 by its pair record, not key 3; key 3
        // reaches key 1.
        let h = parse(&kh().bytes()).unwrap();
        assert_eq!(h.reach(1), [1, 2]);
        assert_eq!(h.reach(2), [1, 2]);
        assert_eq!(h.reach(3), [1, 3]);
        assert!(h.reach(4).is_empty());
        assert_eq!(
            parse(&largest().bytes()).unwrap().reach(5),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn key_info_reads_magic_and_grammar_only() {
        set_kdf_profile(KdfProfile::Test);
        let dir = std::env::temp_dir().join(format!(
            "goyo-keyfile-{:x}",
            u128::from_le_bytes(*crypto::random::<16>().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let info = |bytes: &[u8]| key_info(&write("k.goyokey", bytes));
        let legacy = encode_key(&[1; 16], &[2; 32], Some(&Zeroizing::new([3; 20])), "p").unwrap();
        let i = info(&legacy).unwrap();
        assert!(i.otp && i.well_formed && !i.needs_security_key && i.epoch == 0);
        let i = info(&legacy[..100]).unwrap();
        assert!(i.otp && !i.well_formed);
        let i = info(fixture_password().bytes).unwrap();
        assert_eq!((i.otp, i.well_formed, i.epoch, i.slots), (true, true, 7, 0));
        let i = info(&ks().bytes()).unwrap();
        assert_eq!(
            (
                i.needs_security_key,
                i.well_formed,
                i.otp,
                i.slots,
                i.pin,
                i.key_sync,
                i.epoch
            ),
            (true, true, true, 3, true, true, 9)
        );
        let i = info(&kh().bytes()).unwrap();
        assert!(i.needs_security_key && i.well_formed && !i.pin && !i.key_sync);
        let mut big = kh().bytes();
        big.resize(40_000, 0);
        let head = kh().bytes();
        for bytes in [&head[..50], &b"GOYOKH02"[..], &big[..]] {
            let i = info(bytes).unwrap();
            assert!(i.needs_security_key && !i.well_formed && !i.otp);
        }
        let i = info(b"GOYOKE04").unwrap();
        assert!(!i.needs_security_key && !i.well_formed);
        assert_eq!(info(b"GOYOVA01 not a key file"), None);
        assert_eq!(info(b"GOYO"), None);
        assert_eq!(key_info(&dir.join("missing.goyokey")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_takes_at_most_the_limit() {
        let dir = std::env::temp_dir().join(format!(
            "goyo-keyread-{:x}",
            u128::from_le_bytes(*crypto::random::<16>().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("k.goyokey");
        std::fs::write(&path, fixture_password().bytes).unwrap();
        let f = KeyFile::read(&path).unwrap();
        assert_eq!(
            (f.path(), f.bytes()),
            (path.as_path(), fixture_password().bytes)
        );
        let mut big = kh().bytes();
        big.resize(1 << 20, 0);
        std::fs::write(&path, &big).unwrap();
        let f = KeyFile::read(&path).unwrap();
        assert_eq!(f.bytes().len(), KEY_FILE_LIMIT + 1);
        assert_eq!(f.refusal(), Some(NO_SECURITY_KEY_SUPPORT_DAMAGED));
        assert_eq!(
            KeyFile::read(&dir.join("missing")).err(),
            Some("파일을 열 수 없습니다.")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bundles_keep_the_id_key_last() {
        assert!(Bundle::new(&[], None).is_none());
        assert!(Bundle::new(&[[1; 32]; MAX_KEYS + 1], None).is_none());
        let b = Bundle::new(&[[1; 32], [2; 32], [3; 32]], Some(&[4; 20])).unwrap();
        assert_eq!(
            (b.current(), b.id_key(), b.otp()),
            (&[1; 32], &[3; 32], Some(&[4; 20]))
        );
        assert!(b.same(&Bundle::new(&[[1; 32], [2; 32], [3; 32]], Some(&[4; 20])).unwrap()));
        assert!(!b.same(&Bundle::new(&[[1; 32], [2; 32], [3; 32]], None).unwrap()));
        assert!(!b.same(&Bundle::new(&[[1; 32], [2; 32]], Some(&[4; 20])).unwrap()));
        assert!(!b.same(&Bundle::new(&[[1; 32], [2; 32], [5; 32]], Some(&[4; 20])).unwrap()));
        let plain = b.plain();
        assert_eq!(plain.len(), 3 * 32 + 20);
        assert!(Bundle::from_plain(&plain, 3, true).unwrap().same(&b));
        assert!(Bundle::from_plain(&plain, 3, false).is_none());
    }
}
