//! Frames between goyo-sync.exe and goyo-sync-server.py: one request on the
//! ssh child's stdin, one response on its stdout, then EOF. Little endian.
//! Both directions carry the exact blob length and its SHA-256, so a cut
//! stream, a line-ending translation or shell output cannot pass as data.
//! Only the helper and tests use this; goyo-vault.exe never calls it. The
//! key ops (PUTKEY, GETKEY, CUTKEY and PRUNE, spec v3 §7.13) exist only in
//! the security-key build: the default helper cannot encode one.
#[cfg(feature = "security-key")]
use crate::{
    syncfile::{MAX_RECORD, RECORD_HEADER, RecordKind, parse_record, parse_record_header},
    vault::keyfile::{EPOCH_MAX, KEY_FILE_LIMIT, is_sync_key_file},
};
use crate::{
    syncfile::{decimal, is_sync_vault, newer_vault_format, parse_hex},
    vault::MAX_FILE,
};
use sha2::{Digest, Sha256};

pub const REQUEST_MAGIC: &[u8; 8] = b"GOYOSRQ1";
pub const RESPONSE_MAGIC: &[u8; 8] = b"GOYOSRS1";
/// `<8sB16sQI32s`: magic, op, vault ID, version, blob length, blob SHA-256.
pub const REQUEST_HEADER: usize = 69;
/// `<8sBQI32s`: magic, status, version, blob length, blob SHA-256.
pub const RESPONSE_HEADER: usize = 53;
pub const PROTOCOL: u64 = 1;
/// Login-shell output tolerated before the response magic.
pub const MAX_BANNER: usize = 64 * 1024;
pub const MAX_LIST: usize = 64 * 1024;
/// The most stdout a transport has to keep for one response.
pub const MAX_RESPONSE: usize = MAX_BANNER + RESPONSE_HEADER + MAX_FILE;
/// HELLO payload, echoed by the server: every byte value twice. A CR/LF
/// translation, a dropped NUL or a code-page conversion on the ssh pipe
/// shows up here, before any vault crosses it.
pub const HELLO_ECHO: [u8; 512] = {
    let mut a = [0u8; 512];
    let mut i = 0;
    while i < a.len() {
        a[i] = i as u8;
        i += 1;
    }
    a
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Hello = 1,
    Get = 2,
    Put = 3,
    List = 4,
    Fetch = 5,
    /// Store a GOYOKS01 key file as the record after `base` (the record CAS).
    #[cfg(feature = "security-key")]
    PutKey = 6,
    /// The server's top key record, never an older one.
    #[cfg(feature = "security-key")]
    GetKey = 7,
    /// End the generation that holds record `base`.
    #[cfg(feature = "security-key")]
    CutKey = 8,
    /// Drop the stored vault versions below an epoch.
    #[cfg(feature = "security-key")]
    Prune = 9,
}
impl Op {
    #[cfg(not(feature = "security-key"))]
    pub const ALL: [Op; 5] = [Op::Hello, Op::Get, Op::Put, Op::List, Op::Fetch];
    #[cfg(feature = "security-key")]
    pub const ALL: [Op; 9] = [
        Op::Hello,
        Op::Get,
        Op::Put,
        Op::List,
        Op::Fetch,
        Op::PutKey,
        Op::GetKey,
        Op::CutKey,
        Op::Prune,
    ];
    pub fn code(self) -> u8 {
        self as u8
    }
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.code() == code)
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Ok = 0,
    NotModified = 1,
    Conflict = 2,
    Empty = 3,
    NotFound = 4,
    BadRequest = 10,
    BadBlob = 11,
    TooLarge = 12,
    Limit = 13,
    /// The upload's header does not match the server's key file for the
    /// vault (key-file sync, spec §7.13); only a PUT gets it. Never stored
    /// as a refusal: a new key file makes the upload land.
    KeyBehind = 14,
    ServerError = 20,
}
impl Status {
    pub const ALL: [Status; 11] = [
        Status::Ok,
        Status::NotModified,
        Status::Conflict,
        Status::Empty,
        Status::NotFound,
        Status::BadRequest,
        Status::BadBlob,
        Status::TooLarge,
        Status::Limit,
        Status::KeyBehind,
        Status::ServerError,
    ];
    pub fn code(self) -> u8 {
        self as u8
    }
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.code() == code)
    }
}

/// Why a frame was refused. Every one is a protocol error (`state=server`)
/// except `NewerFormat` (`state=update`); incoming is left untouched.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// No magic at the start (request) or within 64 KiB (response).
    Magic,
    Truncated,
    /// Unknown op or status, or a status the op does not allow.
    Code,
    /// A vault ID for HELLO or LIST, or a zero one for an op on a vault.
    Id,
    /// `blob_len` over the limit, or not the number of bytes that follow.
    Length,
    Sha,
    /// A blob where none is allowed, or a malformed LIST.
    Blob,
    /// Not a GOYOVA02 (96 B to 8 MiB) or GOYOVA04 (140 B to 8 MiB) file of
    /// this vault.
    Vault,
    /// GOYOVA05 or later: a newer Goyo Vault wrote it.
    NewerFormat,
    /// The HELLO echo differs: the ssh pipe is not binary-transparent.
    Echo,
    /// The version breaks the rule for this reply.
    Version,
    /// A key record or record header outside the server's grammar for this
    /// vault (spec v3 §7.13), or a CUTKEY answer that does not end the
    /// generation asked for.
    #[cfg(feature = "security-key")]
    Record,
}
impl WireError {
    /// Fixed English text for the helper's log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Magic => "no frame magic",
            Self::Truncated => "truncated header",
            Self::Code => "unexpected op or status",
            Self::Id => "vault id not allowed",
            Self::Length => "wrong blob length",
            Self::Sha => "blob sha256 mismatch",
            Self::Blob => "unexpected or malformed blob",
            Self::Vault => "not a GOYOVA02/04 file of this vault",
            Self::NewerFormat => "vault from a newer version",
            Self::Echo => "binary echo differs",
            Self::Version => "unexpected version",
            #[cfg(feature = "security-key")]
            Self::Record => "not a key record of this vault",
        }
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
/// A blob-less frame may carry zeros (the request convention) or the hash
/// of nothing; there is nothing to authenticate either way.
fn sha_matches(blob: &[u8], sha: &[u8; 32]) -> bool {
    sha256(blob) == *sha || (blob.is_empty() && *sha == [0; 32])
}
/// A vault file the server may store or serve: GOYOVA02 (96 B to 8 MiB) or
/// GOYOVA04 (140 B to 8 MiB) with this vault's ID. GOYOVA01/03 are never
/// synced, and a key file (GOYOK…) never passes.
pub fn check_vault_blob(blob: &[u8], id: &[u8; 16]) -> Result<(), WireError> {
    if newer_vault_format(blob) {
        return Err(WireError::NewerFormat);
    }
    if !is_sync_vault(blob) || &blob[8..24] != id {
        return Err(WireError::Vault);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request<'a> {
    pub op: Op,
    /// Zero for HELLO and LIST.
    pub vault_id: [u8; 16],
    /// HELLO: protocol version; GET: `have`; PUT: `expected`; FETCH: N (0 = head).
    pub version: u64,
    /// PUT and HELLO: SHA-256 of the blob; GET: `have_sha`; zero otherwise.
    pub blob_sha: [u8; 32],
    pub blob: &'a [u8],
}
impl<'a> Request<'a> {
    pub fn hello() -> Request<'static> {
        Request {
            op: Op::Hello,
            vault_id: [0; 16],
            version: PROTOCOL,
            blob_sha: sha256(&HELLO_ECHO),
            blob: &HELLO_ECHO,
        }
    }
    /// `have` and `have_sha`: the version and SHA-256 already in incoming.
    pub fn get(id: [u8; 16], have: u64, have_sha: Option<[u8; 32]>) -> Self {
        Self {
            op: Op::Get,
            vault_id: id,
            version: have,
            blob_sha: have_sha.unwrap_or([0; 32]),
            blob: &[],
        }
    }
    /// Compare-and-swap onto server version `expected`. Refuses anything but
    /// a GOYOVA02 or GOYOVA04 file of `id`: the last gate before the ssh
    /// pipe.
    pub fn put(id: [u8; 16], expected: u64, blob: &'a [u8]) -> Result<Self, WireError> {
        check_vault_blob(blob, &id)?;
        Ok(Self {
            op: Op::Put,
            vault_id: id,
            version: expected,
            blob_sha: sha256(blob),
            blob,
        })
    }
    pub fn list() -> Self {
        Self {
            op: Op::List,
            vault_id: [0; 16],
            version: 0,
            blob_sha: [0; 32],
            blob: &[],
        }
    }
    /// Version `n`, or the head for 0.
    pub fn fetch(id: [u8; 16], n: u64) -> Self {
        Self {
            op: Op::Fetch,
            vault_id: id,
            version: n,
            blob_sha: [0; 32],
            blob: &[],
        }
    }
    /// PUTKEY: the record CAS onto record `base`. Refuses anything but a
    /// GOYOKS01 key file of `id`, and a `base` above `EPOCH_MAX`.
    #[cfg(feature = "security-key")]
    pub fn put_key(id: [u8; 16], base: u64, key_file: &'a [u8]) -> Result<Self, WireError> {
        if base > EPOCH_MAX || is_sync_key_file(key_file, &id).is_none() {
            return Err(WireError::Record);
        }
        Ok(Self {
            op: Op::PutKey,
            vault_id: id,
            version: base,
            blob_sha: sha256(key_file),
            blob: key_file,
        })
    }
    /// GETKEY: `have` and `have_sha` are the record number and the SHA-256
    /// of the record already held (0 and None for none).
    #[cfg(feature = "security-key")]
    pub fn get_key(id: [u8; 16], have: u64, have_sha: Option<[u8; 32]>) -> Self {
        Self {
            op: Op::GetKey,
            vault_id: id,
            version: have,
            blob_sha: have_sha.unwrap_or([0; 32]),
            blob: &[],
        }
    }
    /// CUTKEY: end the generation that holds record `base`.
    #[cfg(feature = "security-key")]
    pub fn cut_key(id: [u8; 16], base: u64) -> Result<Self, WireError> {
        if base > EPOCH_MAX {
            return Err(WireError::Version);
        }
        Ok(Self {
            op: Op::CutKey,
            vault_id: id,
            version: base,
            blob_sha: [0; 32],
            blob: &[],
        })
    }
    /// PRUNE: drop the stored versions whose header epoch is below `epoch`.
    #[cfg(feature = "security-key")]
    pub fn prune(id: [u8; 16], epoch: u64) -> Result<Self, WireError> {
        if !(1..=EPOCH_MAX).contains(&epoch) {
            return Err(WireError::Version);
        }
        Ok(Self {
            op: Op::Prune,
            vault_id: id,
            version: epoch,
            blob_sha: [0; 32],
            blob: &[],
        })
    }
    /// Header and blob, exactly as given (tests build invalid frames too).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REQUEST_HEADER + self.blob.len());
        out.extend_from_slice(REQUEST_MAGIC);
        out.push(self.op.code());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.blob_sha);
        out.extend_from_slice(self.blob);
        out
    }
    /// The server's frame rules: magic at offset 0, a known op, a zero ID
    /// for HELLO and LIST and a nonzero one otherwise, HELLO version 1 and
    /// LIST version 0, `blob_len` exactly what follows (HELLO 512, PUT up to
    /// 8 MiB, PUTKEY up to 32 KiB, none otherwise) and a matching SHA (GET
    /// and GETKEY carry `have_sha` there); CUTKEY's version at most
    /// `EPOCH_MAX` and PRUNE's at least 1. Whether a PUT or PUTKEY blob is a
    /// vault or a key file is the server's BAD_BLOB check.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, WireError> {
        if bytes.len() < REQUEST_HEADER {
            return Err(WireError::Truncated);
        }
        if &bytes[..8] != REQUEST_MAGIC {
            return Err(WireError::Magic);
        }
        let op = Op::from_code(bytes[8]).ok_or(WireError::Code)?;
        let vault_id: [u8; 16] = bytes[9..25].try_into().unwrap();
        let version = u64::from_le_bytes(bytes[25..33].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[33..37].try_into().unwrap()) as usize;
        let blob_sha: [u8; 32] = bytes[37..REQUEST_HEADER].try_into().unwrap();
        let blob = &bytes[REQUEST_HEADER..];
        // A vault ID comes from a key file and is never all zero.
        let names_vault = !matches!(op, Op::Hello | Op::List);
        if names_vault == (vault_id == [0; 16]) {
            return Err(WireError::Id);
        }
        let fits = match op {
            Op::Hello => len == HELLO_ECHO.len(),
            Op::Put => len <= MAX_FILE,
            Op::Get | Op::List | Op::Fetch => len == 0,
            #[cfg(feature = "security-key")]
            Op::PutKey => len <= KEY_FILE_LIMIT,
            #[cfg(feature = "security-key")]
            Op::GetKey | Op::CutKey | Op::Prune => len == 0,
        };
        if !fits || blob.len() != len {
            return Err(WireError::Length);
        }
        let sha_ok = match op {
            Op::Hello | Op::Put => sha256(blob) == blob_sha,
            Op::Get => true,
            Op::List | Op::Fetch => blob_sha == [0; 32],
            #[cfg(feature = "security-key")]
            Op::PutKey => sha256(blob) == blob_sha,
            #[cfg(feature = "security-key")]
            Op::GetKey => true,
            #[cfg(feature = "security-key")]
            Op::CutKey | Op::Prune => blob_sha == [0; 32],
        };
        if !sha_ok {
            return Err(WireError::Sha);
        }
        let version_fits = match op {
            Op::Hello => version == PROTOCOL,
            Op::List => version == 0,
            Op::Get | Op::Put | Op::Fetch => true,
            #[cfg(feature = "security-key")]
            Op::PutKey | Op::GetKey => true,
            #[cfg(feature = "security-key")]
            Op::CutKey => version <= EPOCH_MAX,
            #[cfg(feature = "security-key")]
            Op::Prune => version >= 1,
        };
        if !version_fits {
            return Err(WireError::Version);
        }
        Ok(Self {
            op,
            vault_id,
            version,
            blob_sha,
            blob,
        })
    }
}

/// What a reply carries after its header.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    Nothing,
    Vault,
    Echo,
    List,
    /// A key record as served, numbered by the reply's version.
    #[cfg(feature = "security-key")]
    Record,
    /// Exactly the 32-byte header of the key record a PUTKEY made.
    #[cfg(feature = "security-key")]
    RecordHeader,
}
/// The replies each op accepts. Any op may get BAD_REQUEST (the server could
/// not read the frame, so it may not know the op) or SERVER_ERROR.
fn body(op: Op, status: Status) -> Option<Body> {
    use Status as S;
    Some(match (op, status) {
        (_, S::BadRequest | S::ServerError) => Body::Nothing,
        (Op::Hello, S::Ok) => Body::Echo,
        (Op::Get | Op::Fetch, S::Ok) | (Op::Put, S::Conflict) => Body::Vault,
        (Op::Get, S::NotModified | S::Empty)
        | (Op::Put, S::Ok | S::Empty | S::BadBlob | S::TooLarge | S::Limit | S::KeyBehind)
        | (Op::Fetch, S::NotFound) => Body::Nothing,
        (Op::List, S::Ok) => Body::List,
        #[cfg(feature = "security-key")]
        (Op::PutKey, S::Ok) => Body::RecordHeader,
        #[cfg(feature = "security-key")]
        (Op::PutKey, S::Conflict) | (Op::GetKey | Op::CutKey, S::Ok) => Body::Record,
        #[cfg(feature = "security-key")]
        (Op::PutKey, S::Empty | S::BadBlob | S::TooLarge | S::Limit)
        | (Op::GetKey, S::NotModified | S::Empty)
        | (Op::CutKey, S::Limit)
        | (Op::Prune, S::Ok | S::NotFound) => Body::Nothing,
        _ => return None,
    })
}
/// `have` is the request's version field: GET have, PUT expected, FETCH N;
/// PUTKEY and CUTKEY `base`, GETKEY have, PRUNE the epoch.
fn version_ok(op: Op, status: Status, version: u64, have: u64) -> bool {
    match (op, status) {
        (Op::Hello, Status::Ok) => version == PROTOCOL,
        (Op::Get, Status::Ok) | (Op::Put, Status::Conflict) => version >= 1,
        // "Your copy is the head": it must echo a version we really have.
        (Op::Get, Status::NotModified) => have >= 1 && version == have,
        (Op::Get, Status::Empty) => version == 0,
        // EMPTY answers a PUT onto a version the server no longer has.
        (Op::Put, Status::Empty) => have >= 1 && version == 0,
        (Op::Put, Status::Ok) => have.checked_add(1) == Some(version),
        (Op::Fetch, Status::Ok) => version >= 1 && (have == 0 || version == have),
        // Record numbers run from 1 to EPOCH_MAX (spec v3 §7.13): PUTKEY's
        // CAS makes base + 1, and EMPTY carries 0 for any base.
        #[cfg(feature = "security-key")]
        (Op::PutKey, Status::Ok) => have.checked_add(1) == Some(version) && version <= EPOCH_MAX,
        #[cfg(feature = "security-key")]
        (Op::PutKey, Status::Conflict) | (Op::GetKey | Op::CutKey, Status::Ok) => {
            (1..=EPOCH_MAX).contains(&version)
        }
        #[cfg(feature = "security-key")]
        (Op::GetKey, Status::NotModified) => (1..=EPOCH_MAX).contains(&have) && version == have,
        #[cfg(feature = "security-key")]
        (Op::PutKey | Op::GetKey, Status::Empty) | (Op::Prune, Status::NotFound) => version == 0,
        // LIST's count is checked against its lines; errors carry no version.
        _ => true,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Response<'a> {
    pub status: Status,
    /// HELLO: protocol version; GET, CONFLICT, FETCH: the blob's version;
    /// PUT OK: the new head; NOT_MODIFIED: `have`; LIST: the line count.
    pub version: u64,
    pub blob_sha: [u8; 32],
    pub blob: &'a [u8],
}
impl<'a> Response<'a> {
    pub fn new(status: Status, version: u64, blob: &'a [u8]) -> Self {
        Self {
            status,
            version,
            blob_sha: sha256(blob),
            blob,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESPONSE_HEADER + self.blob.len());
        out.extend_from_slice(RESPONSE_MAGIC);
        out.push(self.status.code());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.blob_sha);
        out.extend_from_slice(self.blob);
        out
    }
    /// The reply to a request of `op` for vault `id`, with `have` the
    /// request's version field. Returns the response and the number of
    /// banner bytes skipped before it, for the log. The reply must be one
    /// the op allows, with exactly `blob_len` bytes after the header, a
    /// matching SHA-256 and a blob only where one belongs; a vault blob must
    /// pass [`check_vault_blob`]. A key record must be one of `id` numbered
    /// by the reply's version, and CUTKEY's a cut or a key record of a later
    /// generation than `have`; PUTKEY OK carries exactly a key-record header
    /// (its `floor` is the uploaded file's epoch, which the caller checks).
    /// Anything else is a protocol error.
    pub fn decode(
        bytes: &'a [u8],
        op: Op,
        id: &[u8; 16],
        have: u64,
    ) -> Result<(Self, usize), WireError> {
        let window = &bytes[..bytes.len().min(MAX_BANNER + RESPONSE_MAGIC.len())];
        let banner = window
            .windows(RESPONSE_MAGIC.len())
            .position(|w| w == RESPONSE_MAGIC)
            .ok_or(WireError::Magic)?;
        let frame = &bytes[banner..];
        if frame.len() < RESPONSE_HEADER {
            return Err(WireError::Truncated);
        }
        let status = Status::from_code(frame[8]).ok_or(WireError::Code)?;
        let body = body(op, status).ok_or(WireError::Code)?;
        let version = u64::from_le_bytes(frame[9..17].try_into().unwrap());
        let len = u32::from_le_bytes(frame[17..21].try_into().unwrap()) as usize;
        let blob_sha: [u8; 32] = frame[21..RESPONSE_HEADER].try_into().unwrap();
        let blob = &frame[RESPONSE_HEADER..];
        let limit = match body {
            Body::Nothing if len > 0 => return Err(WireError::Blob),
            Body::Nothing => 0,
            Body::Vault => MAX_FILE,
            Body::Echo => HELLO_ECHO.len(),
            Body::List => MAX_LIST,
            #[cfg(feature = "security-key")]
            Body::Record => MAX_RECORD,
            #[cfg(feature = "security-key")]
            Body::RecordHeader => RECORD_HEADER,
        };
        if len > limit || blob.len() != len {
            return Err(WireError::Length);
        }
        if !sha_matches(blob, &blob_sha) {
            return Err(WireError::Sha);
        }
        match body {
            Body::Vault => check_vault_blob(blob, id)?,
            Body::Echo if blob != HELLO_ECHO => return Err(WireError::Echo),
            Body::List => {
                let count = parse_list(blob).ok_or(WireError::Blob)?.len();
                if count as u64 != version {
                    return Err(WireError::Version);
                }
            }
            #[cfg(feature = "security-key")]
            Body::Record => {
                let record = parse_record(blob, version, id).ok_or(WireError::Record)?;
                // A CUTKEY that left the generation it was asked to end on
                // top would leave the off pending for good.
                let ended = record.kind == RecordKind::Cut || record.generation > have;
                if op == Op::CutKey && !ended {
                    return Err(WireError::Record);
                }
            }
            #[cfg(feature = "security-key")]
            Body::RecordHeader => match parse_record_header(blob) {
                Some((RecordKind::Key, false, generation, _))
                    if blob.len() == RECORD_HEADER && generation < version => {}
                _ => return Err(WireError::Record),
            },
            _ => {}
        }
        if !version_ok(op, status, version, have) {
            return Err(WireError::Version);
        }
        let response = Self {
            status,
            version,
            blob_sha,
            blob,
        };
        Ok((response, banner))
    }
}

/// One LIST line: `<id32> <head> <size> <mtime>\n`, all decimal but the ID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ListEntry {
    pub id: [u8; 16],
    pub head: u64,
    /// Bytes of the head version.
    pub size: u64,
    /// Unix seconds when the head version was stored.
    pub mtime: u64,
}
pub fn render_list(entries: &[ListEntry]) -> Vec<u8> {
    let mut out = String::new();
    for e in entries {
        let id = crate::syncfile::hex(&e.id);
        out.push_str(&format!("{id} {} {} {}\n", e.head, e.size, e.mtime));
    }
    out.into_bytes()
}
/// None unless every line is well formed and LF-terminated.
pub fn parse_list(blob: &[u8]) -> Option<Vec<ListEntry>> {
    if blob.len() > MAX_LIST || !blob.is_ascii() {
        return None;
    }
    let text = std::str::from_utf8(blob).ok()?;
    let mut out = Vec::new();
    if text.is_empty() {
        return Some(out);
    }
    for line in text.strip_suffix('\n')?.split('\n') {
        let mut f = line.split(' ');
        out.push(ListEntry {
            id: parse_hex(f.next()?)?,
            head: decimal(f.next()?)?,
            size: decimal(f.next()?)?,
            mtime: decimal(f.next()?)?,
        });
        if f.next().is_some() {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: [u8; 16] = [0x3F; 16];
    /// The request's version field in reply tests.
    const HAVE: u64 = 4;
    /// The vault ops, which both builds have.
    const VAULT_OPS: [Op; 5] = [Op::Hello, Op::Get, Op::Put, Op::List, Op::Fetch];
    /// Blob kinds, indexes into `blobs()`.
    const NOTHING: usize = 0;
    const VAULT: usize = 1;
    const ECHO: usize = 2;
    const LIST: usize = 3;
    fn vault(id: &[u8; 16], len: usize) -> Vec<u8> {
        let mut v = Vec::from(*b"GOYOVA02");
        v.extend_from_slice(id);
        v.resize(len, 0x5A);
        v
    }
    fn one_line_list() -> Vec<u8> {
        render_list(&[ListEntry {
            id: ID,
            head: 7,
            size: 4096,
            mtime: 1_792_000_000,
        }])
    }
    fn blobs() -> [Vec<u8>; 4] {
        [
            Vec::new(),
            vault(&ID, 300),
            HELLO_ECHO.to_vec(),
            one_line_list(),
        ]
    }
    /// The reply table of the spec written out pair by pair, plus
    /// BAD_REQUEST and SERVER_ERROR for every op.
    fn allowed(op: Op, status: Status) -> Option<usize> {
        let table = [
            (Op::Hello, Status::Ok, ECHO),
            (Op::Get, Status::Ok, VAULT),
            (Op::Get, Status::NotModified, NOTHING),
            (Op::Get, Status::Empty, NOTHING),
            (Op::Put, Status::Ok, NOTHING),
            (Op::Put, Status::Conflict, VAULT),
            (Op::Put, Status::Empty, NOTHING),
            (Op::Put, Status::BadBlob, NOTHING),
            (Op::Put, Status::TooLarge, NOTHING),
            (Op::Put, Status::Limit, NOTHING),
            (Op::Put, Status::KeyBehind, NOTHING),
            (Op::List, Status::Ok, LIST),
            (Op::Fetch, Status::Ok, VAULT),
            (Op::Fetch, Status::NotFound, NOTHING),
        ];
        if matches!(status, Status::BadRequest | Status::ServerError) {
            return Some(NOTHING);
        }
        table
            .iter()
            .find(|(o, s, _)| (*o, *s) == (op, status))
            .map(|t| t.2)
    }
    /// A version the reply rules accept when the request said `HAVE`.
    fn good_version(op: Op, status: Status) -> u64 {
        match (op, status) {
            (Op::Hello, Status::Ok) | (Op::List, Status::Ok) => 1,
            (Op::Get, Status::Ok) | (Op::Put, Status::Conflict) => 9,
            (Op::Get, Status::NotModified) | (Op::Fetch, Status::Ok) => HAVE,
            (Op::Put, Status::Ok) => HAVE + 1,
            _ => 0,
        }
    }
    fn decode(bytes: &[u8], op: Op) -> Result<(Response<'_>, usize), WireError> {
        Response::decode(bytes, op, &ID, HAVE)
    }
    fn reply(status: Status, version: u64, blob: &[u8]) -> Vec<u8> {
        Response::new(status, version, blob).encode()
    }

    #[test]
    fn headers_match_the_server_struct_layout() {
        let req = Request::get(ID, 0x0102_0304_0506_0708, Some([0xEE; 32])).encode();
        assert_eq!(req.len(), REQUEST_HEADER);
        assert_eq!(&req[..8], REQUEST_MAGIC);
        assert_eq!(req[8], 2);
        assert_eq!(&req[9..25], &ID);
        assert_eq!(&req[25..33], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&req[33..37], &[0; 4]);
        assert_eq!(&req[37..69], &[0xEE; 32]);
        let v = vault(&ID, 300);
        let res = reply(Status::Conflict, 0x0A0B, &v);
        assert_eq!(res.len(), RESPONSE_HEADER + 300);
        assert_eq!(&res[..8], RESPONSE_MAGIC);
        assert_eq!(res[8], 2);
        assert_eq!(&res[9..17], &[0x0B, 0x0A, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&res[17..21], &300u32.to_le_bytes());
        assert_eq!(&res[21..53], &sha256(&v));
        assert_eq!(&res[53..], &v[..]);
        let codes: Vec<u8> = Status::ALL.iter().map(|s| s.code()).collect();
        assert_eq!(codes, [0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 20]);
        let ops: Vec<u8> = Op::ALL.iter().map(|o| o.code()).collect();
        #[cfg(not(feature = "security-key"))]
        assert_eq!(ops, [1, 2, 3, 4, 5]);
        #[cfg(feature = "security-key")]
        assert_eq!(ops, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
    #[test]
    fn every_frame_round_trips() {
        let v = vault(&ID, 300);
        let requests = [
            Request::hello(),
            Request::get(ID, 0, None),
            Request::get(ID, 7, Some([9; 32])),
            Request::put(ID, 3, &v).unwrap(),
            Request::list(),
            Request::fetch(ID, 0),
            Request::fetch(ID, 12),
        ];
        for r in requests {
            let bytes = r.encode();
            assert_eq!(bytes.len(), REQUEST_HEADER + r.blob.len());
            assert_eq!(Request::decode(&bytes), Ok(r), "{:?}", r.op);
        }
        let blobs = blobs();
        let mut checked = 0;
        for op in Op::ALL {
            for status in Status::ALL {
                let Some(kind) = allowed(op, status) else {
                    continue;
                };
                let r = Response::new(status, good_version(op, status), &blobs[kind]);
                let bytes = r.encode();
                assert_eq!(decode(&bytes, op), Ok((r, 0)), "{op:?} {status:?}");
                checked += 1;
            }
        }
        assert_eq!(checked, 14 + 2 * Op::ALL.len());
        // An empty LIST says 0 vaults.
        let bytes = reply(Status::Ok, 0, &[]);
        assert!(decode(&bytes, Op::List).is_ok());
    }
    #[test]
    fn only_listed_replies_are_accepted() {
        let blobs = blobs();
        for op in VAULT_OPS {
            for status in Status::ALL {
                for (kind, blob) in blobs.iter().enumerate() {
                    let bytes = reply(status, good_version(op, status), blob);
                    let valid = allowed(op, status) == Some(kind);
                    let got = decode(&bytes, op);
                    assert_eq!(got.is_ok(), valid, "{op:?} {status:?} kind {kind}: {got:?}");
                }
            }
            for code in [5, 9, 15, 19, 21, 255] {
                let mut bytes = reply(Status::Ok, good_version(op, Status::Ok), &[]);
                bytes[8] = code;
                assert_eq!(decode(&bytes, op), Err(WireError::Code));
            }
        }
        // A blob where none belongs.
        let bytes = reply(Status::NotFound, 0, b"x");
        assert_eq!(decode(&bytes, Op::Fetch), Err(WireError::Blob));
        let bytes = reply(Status::ServerError, 0, b"traceback");
        assert_eq!(decode(&bytes, Op::Get), Err(WireError::Blob));
    }
    #[test]
    fn lengths_hashes_and_vault_checks() {
        let v = vault(&ID, 300);
        let good = reply(Status::Ok, 9, &v);
        assert!(decode(&good, Op::Get).is_ok());
        // Cut or extended streams.
        assert_eq!(
            decode(&good[..good.len() - 1], Op::Get),
            Err(WireError::Length)
        );
        assert_eq!(
            decode(&good[..RESPONSE_HEADER], Op::Get),
            Err(WireError::Length)
        );
        assert_eq!(
            decode(&good[..RESPONSE_HEADER - 1], Op::Get),
            Err(WireError::Truncated)
        );
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(decode(&extra, Op::Get), Err(WireError::Length));
        // blob_len over each limit, with a matching hash.
        let big = vault(&ID, MAX_FILE + 1);
        let bytes = reply(Status::Ok, 9, &big);
        assert_eq!(decode(&bytes, Op::Get), Err(WireError::Length));
        let mut lines = Vec::new();
        while lines.len() <= MAX_LIST {
            lines.extend_from_slice(&one_line_list());
        }
        let bytes = reply(Status::Ok, 1, &lines);
        assert_eq!(decode(&bytes, Op::List), Err(WireError::Length));
        let bytes = reply(Status::Ok, 1, &[0; 513]);
        assert_eq!(decode(&bytes, Op::Hello), Err(WireError::Length));
        // A length field that disagrees with the bytes.
        let mut lying = good.clone();
        lying[17..21].copy_from_slice(&299u32.to_le_bytes());
        assert_eq!(decode(&lying, Op::Get), Err(WireError::Length));
        lying[17..21].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&lying, Op::Get), Err(WireError::Length));
        // SHA-256 must match the blob.
        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(decode(&flipped, Op::Get), Err(WireError::Sha));
        let mut flipped = good.clone();
        flipped[30] ^= 1;
        assert_eq!(decode(&flipped, Op::Get), Err(WireError::Sha));
        // Without a blob, zeros or the hash of nothing.
        let mut none = reply(Status::Empty, 0, &[]);
        assert_eq!(&none[21..53], &sha256(&[]));
        assert!(decode(&none, Op::Get).is_ok());
        none[21..53].fill(0);
        assert!(decode(&none, Op::Get).is_ok());
        none[21] = 1;
        assert_eq!(decode(&none, Op::Get), Err(WireError::Sha));
        // Wrong frame magic.
        let mut magic = good.clone();
        magic[7] = b'2';
        assert_eq!(decode(&magic, Op::Get), Err(WireError::Magic));
        assert_eq!(decode(&[], Op::Get), Err(WireError::Magic));
        // Vault blobs: GOYOVA02 of this vault, 96 B to 8 MiB, or GOYOVA04,
        // 140 B to 8 MiB.
        let as_magic = |magic: &[u8; 8], len: usize| {
            let mut v = vault(&ID, len);
            v[..8].copy_from_slice(magic);
            v
        };
        let cases = [
            (vault(&[0x40; 16], 300), WireError::Vault),
            (vault(&ID, 95), WireError::Vault),
            (as_magic(b"GOYOVA04", 139), WireError::Vault),
            (as_magic(b"GOYOKE01", 148), WireError::Vault),
            (as_magic(b"GOYOKE03", 312), WireError::Vault),
            (as_magic(b"GOYOKH01", 489), WireError::Vault),
            (as_magic(b"GOYOKS01", 489), WireError::Vault),
            (as_magic(b"GOYOVA01", 300), WireError::Vault),
            (as_magic(b"GOYOVA03", 300), WireError::Vault),
            (as_magic(b"GOYOVA05", 300), WireError::NewerFormat),
        ];
        for (blob, want) in cases {
            for (op, status) in [
                (Op::Get, Status::Ok),
                (Op::Put, Status::Conflict),
                (Op::Fetch, Status::Ok),
            ] {
                let bytes = reply(status, good_version(op, status), &blob);
                assert_eq!(decode(&bytes, op), Err(want), "{op:?} {:?}", &blob[..8]);
            }
        }
        for v in [
            vault(&ID, MAX_FILE),
            vault(&ID, 96),
            as_magic(b"GOYOVA04", MAX_FILE),
            as_magic(b"GOYOVA04", 140),
        ] {
            let bytes = reply(Status::Ok, 9, &v);
            assert!(decode(&bytes, Op::Get).is_ok(), "{:?} {}", &v[..8], v.len());
        }
    }
    #[test]
    fn version_rules() {
        let v = vault(&ID, 300);
        let check = |op: Op, status: Status, version: u64, have: u64, blob: &[u8]| {
            let bytes = reply(status, version, blob);
            Response::decode(&bytes, op, &ID, have).map(|(r, _)| r.version)
        };
        let bad = Err(WireError::Version);
        // NOT_MODIFIED must echo `have`, which must name a version.
        assert_eq!(check(Op::Get, Status::NotModified, 4, 4, &[]), Ok(4));
        assert_eq!(check(Op::Get, Status::NotModified, 5, 4, &[]), bad);
        assert_eq!(check(Op::Get, Status::NotModified, 3, 4, &[]), bad);
        assert_eq!(check(Op::Get, Status::NotModified, 0, 0, &[]), bad);
        assert_eq!(check(Op::Get, Status::Ok, 0, 0, &v), bad);
        assert_eq!(check(Op::Get, Status::Ok, 2, 7, &v), Ok(2)); // logged as a rollback
        assert_eq!(check(Op::Get, Status::Empty, 3, 4, &[]), bad);
        // PUT OK is exactly expected + 1.
        assert_eq!(check(Op::Put, Status::Ok, 1, 0, &[]), Ok(1));
        assert_eq!(check(Op::Put, Status::Ok, 6, 4, &[]), bad);
        assert_eq!(check(Op::Put, Status::Ok, 4, 4, &[]), bad);
        assert_eq!(check(Op::Put, Status::Ok, 0, u64::MAX, &[]), bad);
        assert_eq!(check(Op::Put, Status::Conflict, 0, 4, &v), bad);
        // EMPTY answers only a PUT onto an existing version.
        assert_eq!(check(Op::Put, Status::Empty, 0, 4, &[]), Ok(0));
        assert_eq!(check(Op::Put, Status::Empty, 0, 0, &[]), bad);
        assert_eq!(check(Op::Put, Status::Empty, 1, 4, &[]), bad);
        // FETCH returns the version asked for, or any head for 0.
        assert_eq!(check(Op::Fetch, Status::Ok, 12, 12, &v), Ok(12));
        assert_eq!(check(Op::Fetch, Status::Ok, 11, 12, &v), bad);
        assert_eq!(check(Op::Fetch, Status::Ok, 11, 0, &v), Ok(11));
        assert_eq!(check(Op::Fetch, Status::Ok, 0, 0, &v), bad);
        assert_eq!(check(Op::Hello, Status::Ok, 2, 1, &HELLO_ECHO), bad);
        assert_eq!(check(Op::List, Status::Ok, 2, 0, &one_line_list()), bad);
        assert_eq!(check(Op::List, Status::Ok, 1, 0, &[]), bad);
        // Errors carry no version worth checking.
        assert_eq!(check(Op::Put, Status::Limit, 77, 4, &[]), Ok(77));
    }
    #[test]
    fn banner_is_skipped_up_to_64_kib() {
        let v = vault(&ID, 300);
        let frame = reply(Status::Ok, 9, &v);
        let motd = b"Welcome to my-server\r\nLast login: never\r\n";
        for size in [0, 1, motd.len(), 1000, MAX_BANNER] {
            let mut bytes: Vec<u8> = motd.iter().copied().cycle().take(size).collect();
            bytes.extend_from_slice(&frame);
            let (r, banner) = decode(&bytes, Op::Get).unwrap();
            assert_eq!((banner, r.blob), (size, &v[..]));
        }
        let mut bytes = vec![b'#'; MAX_BANNER + 1];
        bytes.extend_from_slice(&frame);
        assert_eq!(decode(&bytes, Op::Get), Err(WireError::Magic));
        // A banner may end with part of the magic.
        let mut bytes = RESPONSE_MAGIC[..7].to_vec();
        bytes.extend_from_slice(&frame);
        assert_eq!(decode(&bytes, Op::Get).unwrap().1, 7);
        // Output after the frame is not a banner.
        let mut bytes = frame.clone();
        bytes.extend_from_slice(b"logout\n");
        assert_eq!(decode(&bytes, Op::Get), Err(WireError::Length));
    }
    #[test]
    fn hello_echo_proves_a_binary_pipe() {
        assert!((0..256).all(|i| HELLO_ECHO[i] == i as u8));
        assert_eq!(HELLO_ECHO[..256], HELLO_ECHO[256..]);
        let hello = Request::hello();
        assert_eq!(hello.blob_sha, sha256(&HELLO_ECHO));
        assert!(decode(&reply(Status::Ok, 1, &HELLO_ECHO), Op::Hello).is_ok());
        // Text-mode translation on the way back, hashed after the damage.
        let crlf: Vec<u8> = HELLO_ECHO
            .iter()
            .flat_map(|&b| {
                if b == b'\n' {
                    vec![b'\r', b'\n']
                } else {
                    vec![b]
                }
            })
            .collect();
        let bytes = reply(Status::Ok, 1, &crlf);
        assert_eq!(decode(&bytes, Op::Hello), Err(WireError::Length));
        let mut changed = HELLO_ECHO;
        changed[0x80] = b'?';
        let bytes = reply(Status::Ok, 1, &changed);
        assert_eq!(decode(&bytes, Op::Hello), Err(WireError::Echo));
        let bytes = reply(Status::Ok, 1, &HELLO_ECHO[..511]);
        assert_eq!(decode(&bytes, Op::Hello), Err(WireError::Echo));
    }
    #[test]
    fn requests_follow_the_server_rules() {
        let v = vault(&ID, 300);
        let put = Request::put(ID, 3, &v).unwrap().encode();
        assert_eq!(
            Request::decode(&put[..REQUEST_HEADER - 1]),
            Err(WireError::Truncated)
        );
        let mut bad = put.clone();
        bad[0] = b'X';
        assert_eq!(Request::decode(&bad), Err(WireError::Magic));
        // The key ops (6 to 9) exist only in the security-key build.
        let unknown = if cfg!(feature = "security-key") {
            10
        } else {
            6
        };
        for op in [0, unknown, 255] {
            let mut bad = Request::list().encode();
            bad[8] = op;
            assert_eq!(Request::decode(&bad), Err(WireError::Code));
        }
        for r in [Request::hello(), Request::list()] {
            let mut bad = r.encode();
            bad[9] = 1;
            assert_eq!(Request::decode(&bad), Err(WireError::Id));
        }
        // An op on a vault must name one, as the server requires.
        let zero = vault(&[0; 16], 300);
        for r in [
            Request::get([0; 16], 1, None),
            Request::put([0; 16], 0, &zero).unwrap(),
            Request::fetch([0; 16], 0),
        ] {
            assert_eq!(
                Request::decode(&r.encode()),
                Err(WireError::Id),
                "{:?}",
                r.op
            );
        }
        let mut bad = Request::hello().encode();
        bad[25] = 2;
        assert_eq!(Request::decode(&bad), Err(WireError::Version));
        let mut bad = Request::list().encode();
        bad[25] = 1;
        assert_eq!(Request::decode(&bad), Err(WireError::Version));
        let short = Request {
            blob: &HELLO_ECHO[..511],
            blob_sha: sha256(&HELLO_ECHO[..511]),
            ..Request::hello()
        };
        assert_eq!(Request::decode(&short.encode()), Err(WireError::Length));
        let big = vault(&ID, MAX_FILE + 1);
        let huge = Request {
            blob: &big,
            blob_sha: sha256(&big),
            ..Request::put(ID, 0, &v).unwrap()
        };
        assert_eq!(Request::decode(&huge.encode()), Err(WireError::Length));
        for r in [
            Request::get(ID, 1, None),
            Request::list(),
            Request::fetch(ID, 0),
        ] {
            let with_blob = Request { blob: b"x", ..r };
            assert_eq!(Request::decode(&with_blob.encode()), Err(WireError::Length));
        }
        let mut extra = put.clone();
        extra.push(0);
        assert_eq!(Request::decode(&extra), Err(WireError::Length));
        assert_eq!(
            Request::decode(&put[..put.len() - 1]),
            Err(WireError::Length)
        );
        let mut bad = put.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(Request::decode(&bad), Err(WireError::Sha));
        for r in [Request::list(), Request::fetch(ID, 2)] {
            let tagged = Request {
                blob_sha: [1; 32],
                ..r
            };
            assert_eq!(Request::decode(&tagged.encode()), Err(WireError::Sha));
        }
        // GET's hash field is `have_sha`, not a blob hash.
        assert!(Request::decode(&Request::get(ID, 1, Some([7; 32])).encode()).is_ok());
    }
    /// The last gate before ssh: only this vault's GOYOVA02 file is put.
    #[test]
    fn put_refuses_anything_but_this_vault() {
        let mut key_otp = vault(&ID, 148);
        key_otp[..8].copy_from_slice(b"GOYOKE01");
        let mut key = vault(&ID, 128);
        key[..8].copy_from_slice(b"GOYOKE02");
        let as_magic = |magic: &[u8; 8], len: usize| {
            let mut v = vault(&ID, len);
            v[..8].copy_from_slice(magic);
            v
        };
        let cases = [
            (key_otp, WireError::Vault),
            (key, WireError::Vault),
            (as_magic(b"GOYOKE03", 312), WireError::Vault),
            (as_magic(b"GOYOKH01", 489), WireError::Vault),
            (as_magic(b"GOYOKS01", 489), WireError::Vault),
            (as_magic(b"GOYOVA01", 300), WireError::Vault),
            (as_magic(b"GOYOVA03", 300), WireError::Vault),
            (as_magic(b"GOYOVA04", 139), WireError::Vault),
            (as_magic(b"GOYOVA04", MAX_FILE + 1), WireError::Vault),
            (vault(&[0x40; 16], 300), WireError::Vault),
            (vault(&ID, 95), WireError::Vault),
            (vault(&ID, MAX_FILE + 1), WireError::Vault),
            (as_magic(b"GOYOVA05", 300), WireError::NewerFormat),
            (Vec::new(), WireError::Vault),
        ];
        for (blob, want) in cases {
            assert_eq!(Request::put(ID, 0, &blob).err(), Some(want));
            assert_eq!(check_vault_blob(&blob, &ID), Err(want));
        }
        for blob in [
            vault(&ID, 96),
            vault(&ID, MAX_FILE),
            as_magic(b"GOYOVA04", 140),
            as_magic(b"GOYOVA04", MAX_FILE),
        ] {
            assert!(Request::put(ID, 0, &blob).is_ok());
        }
    }
    /// The key ops (spec v3 §7.13), in the security-key build only.
    #[cfg(feature = "security-key")]
    mod keys {
        use super::*;
        use crate::syncfile::render_record_header;
        /// The GOYOKS01 fixture: vault 3a3b…49, epoch 9.
        const KS: &[u8] = include_bytes!("../tests/fixtures/goyoks01.goyokey");
        fn id() -> [u8; 16] {
            KS[8..24].try_into().unwrap()
        }
        fn ks(epoch: u64) -> Vec<u8> {
            let mut f = KS.to_vec();
            f[24..32].copy_from_slice(&epoch.to_le_bytes());
            f
        }
        fn key_record(generation: u64, epoch: u64) -> Vec<u8> {
            let mut r = render_record_header(RecordKind::Key, false, generation, epoch).to_vec();
            r.extend_from_slice(&ks(epoch));
            r
        }
        fn cut(number: u64, floor: u64) -> Vec<u8> {
            render_record_header(RecordKind::Cut, false, number, floor).to_vec()
        }
        fn decode(bytes: &[u8], op: Op, have: u64) -> Result<Response<'_>, WireError> {
            Response::decode(bytes, op, &id(), have).map(|(r, _)| r)
        }
        fn reply(status: Status, version: u64, blob: &[u8]) -> Vec<u8> {
            Response::new(status, version, blob).encode()
        }

        #[test]
        fn key_requests_follow_the_server_rules() {
            let id = id();
            let file = ks(12);
            let requests = [
                Request::put_key(id, 0, &file).unwrap(),
                Request::put_key(id, EPOCH_MAX, &file).unwrap(),
                Request::get_key(id, 0, None),
                Request::get_key(id, 5, Some([7; 32])),
                Request::cut_key(id, 0).unwrap(),
                Request::cut_key(id, EPOCH_MAX).unwrap(),
                Request::prune(id, 1).unwrap(),
                Request::prune(id, EPOCH_MAX).unwrap(),
            ];
            for r in requests {
                let bytes = r.encode();
                assert_eq!(bytes[8], r.op.code());
                assert_eq!(Request::decode(&bytes), Ok(r), "{:?}", r.op);
            }
            assert_eq!(requests[0].blob_sha, sha256(&file));
            // Only a GOYOKS01 file of this vault is put, and every number
            // stays within EPOCH_MAX (prune's epoch from 1).
            let mut kh = file.clone();
            kh[..8].copy_from_slice(b"GOYOKH01");
            let mut vault = file.clone();
            vault[..8].copy_from_slice(b"GOYOVA04");
            for bad in [&kh, &vault, &ks(EPOCH_MAX + 1), &file[..488].to_vec()] {
                assert_eq!(Request::put_key(id, 0, bad), Err(WireError::Record));
            }
            assert_eq!(
                Request::put_key([0x40; 16], 0, &file),
                Err(WireError::Record)
            );
            assert_eq!(
                Request::put_key(id, EPOCH_MAX + 1, &file),
                Err(WireError::Record)
            );
            assert_eq!(Request::cut_key(id, EPOCH_MAX + 1), Err(WireError::Version));
            assert_eq!(Request::prune(id, 0), Err(WireError::Version));
            assert_eq!(Request::prune(id, EPOCH_MAX + 1), Err(WireError::Version));
            // The server's frame rules for ops 6 to 9.
            let with = |r: Request, f: &dyn Fn(&mut Vec<u8>)| {
                let mut b = r.encode();
                f(&mut b);
                Request::decode(&b).map(|_| ())
            };
            let cut = Request::cut_key(id, 3).unwrap();
            let prune = Request::prune(id, 3).unwrap();
            assert_eq!(with(cut, &|b| b[37] = 1), Err(WireError::Sha));
            assert_eq!(with(prune, &|b| b[37] = 1), Err(WireError::Sha));
            assert_eq!(
                with(cut, &|b| b[25..33]
                    .copy_from_slice(&(EPOCH_MAX + 1).to_le_bytes())),
                Err(WireError::Version)
            );
            assert_eq!(with(prune, &|b| b[25..33].fill(0)), Err(WireError::Version));
            assert_eq!(with(cut, &|b| b[9..25].fill(0)), Err(WireError::Id));
            for r in [cut, prune, Request::get_key(id, 1, None)] {
                let with_blob = Request {
                    blob: b"x",
                    blob_sha: sha256(b"x"),
                    ..r
                };
                assert_eq!(Request::decode(&with_blob.encode()), Err(WireError::Length));
            }
            let put = Request::put_key(id, 1, &file).unwrap();
            assert_eq!(
                with(put, &|b| *b.last_mut().unwrap() ^= 1),
                Err(WireError::Sha)
            );
            let big = vec![0u8; KEY_FILE_LIMIT + 1];
            let huge = Request {
                blob: &big,
                blob_sha: sha256(&big),
                ..put
            };
            assert_eq!(Request::decode(&huge.encode()), Err(WireError::Length));
        }

        /// The answer rules of ops 6-9 (spec v3 §7.13, S6-2 #20): each op
        /// gets only its own statuses, with the version and the record each
        /// one carries.
        #[test]
        fn key_replies_follow_the_answer_rules() {
            let base = 4;
            let header = render_record_header(RecordKind::Key, false, 2, 12);
            // (op, status, version, blob, the request's version)
            let good: Vec<(Op, Status, u64, Vec<u8>, u64)> = vec![
                (Op::PutKey, Status::Ok, base + 1, header.to_vec(), base),
                (Op::PutKey, Status::Conflict, 7, key_record(3, 12), base),
                (Op::PutKey, Status::Conflict, 7, cut(7, 12), base),
                (Op::PutKey, Status::Empty, 0, vec![], base),
                (Op::PutKey, Status::Empty, 0, vec![], 0),
                (Op::PutKey, Status::BadBlob, 0, vec![], base),
                (Op::PutKey, Status::TooLarge, 0, vec![], base),
                (Op::PutKey, Status::Limit, 0, vec![], base),
                (Op::GetKey, Status::Ok, 7, key_record(3, 12), 0),
                (Op::GetKey, Status::Ok, 2, key_record(1, 12), 7), // went back
                (
                    Op::GetKey,
                    Status::Ok,
                    7,
                    render_record_header(RecordKind::Cut, true, 7, 4).to_vec(),
                    7,
                ),
                (Op::GetKey, Status::NotModified, 7, vec![], 7),
                (Op::GetKey, Status::Empty, 0, vec![], 7),
                (Op::CutKey, Status::Ok, 5, cut(5, 12), base),
                (Op::CutKey, Status::Ok, 3, cut(3, 12), base), // numbers went back
                (Op::CutKey, Status::Ok, 9, key_record(base + 1, 12), base),
                (Op::CutKey, Status::Limit, 0, vec![], base),
                (Op::Prune, Status::Ok, 3, vec![], 5),
                (Op::Prune, Status::NotFound, 0, vec![], 5),
            ];
            for (op, status, version, blob, have) in &good {
                let bytes = reply(*status, *version, blob);
                let r = decode(&bytes, *op, *have);
                assert_eq!(
                    r.map(|r| (r.status, r.version)),
                    Ok((*status, *version)),
                    "{op:?} {status:?}"
                );
            }
            for op in [Op::PutKey, Op::GetKey, Op::CutKey, Op::Prune] {
                for status in [Status::BadRequest, Status::ServerError] {
                    assert!(decode(&reply(status, 0, &[]), op, 1).is_ok());
                }
                // Every other status of the op, and a vault blob anywhere.
                for status in Status::ALL {
                    let listed = good.iter().any(|g| (g.0, g.1) == (op, status))
                        || matches!(status, Status::BadRequest | Status::ServerError);
                    if !listed {
                        assert_eq!(
                            decode(&reply(status, 1, &[]), op, 1).err(),
                            Some(WireError::Code),
                            "{op:?} {status:?}"
                        );
                    }
                }
            }
            let vault = {
                let mut v = Vec::from(*b"GOYOVA04");
                v.extend_from_slice(&id());
                v.resize(300, 1);
                v
            };
            let bad = Err(WireError::Record);
            // (op, status, version, blob, the request's version, the verdict)
            type Case = (Op, Status, u64, Vec<u8>, u64, Result<(), WireError>);
            let cases: Vec<Case> = vec![
                // CUTKEY's EMPTY is gone (S6R2 #4).
                (
                    Op::CutKey,
                    Status::Empty,
                    0,
                    vec![],
                    base,
                    Err(WireError::Code),
                ),
                // A CUTKEY answer that leaves the generation it ends on top.
                (Op::CutKey, Status::Ok, 9, key_record(base, 12), base, bad),
                (Op::CutKey, Status::Ok, 9, key_record(1, 12), base, bad),
                // Records outside the grammar, numbered by the version.
                (Op::GetKey, Status::Ok, 3, key_record(3, 12), 0, bad),
                (Op::GetKey, Status::Ok, 4, cut(3, 12), 0, bad),
                (Op::GetKey, Status::Ok, 0, cut(0, 12), 0, bad),
                (
                    Op::GetKey,
                    Status::Ok,
                    EPOCH_MAX + 1,
                    cut(EPOCH_MAX + 1, 12),
                    0,
                    bad,
                ),
                (
                    Op::GetKey,
                    Status::Ok,
                    3,
                    render_record_header(RecordKind::Key, false, 1, 13)
                        .iter()
                        .chain(&ks(12))
                        .copied()
                        .collect(),
                    0,
                    bad,
                ),
                (
                    Op::GetKey,
                    Status::Ok,
                    3,
                    render_record_header(RecordKind::Key, false, 1, 12)
                        .iter()
                        .chain(&vault)
                        .copied()
                        .collect(),
                    0,
                    bad,
                ),
                (
                    Op::GetKey,
                    Status::Ok,
                    3,
                    render_record_header(RecordKind::Cut, false, 3, EPOCH_MAX + 1).to_vec(),
                    0,
                    bad,
                ),
                (Op::GetKey, Status::Ok, 3, vault.clone(), 0, bad),
                (Op::PutKey, Status::Conflict, 3, vault.clone(), base, bad),
                // PUTKEY OK: exactly a key-record header, numbered base + 1.
                (
                    Op::PutKey,
                    Status::Ok,
                    base + 1,
                    key_record(2, 12),
                    base,
                    Err(WireError::Length),
                ),
                (
                    Op::PutKey,
                    Status::Ok,
                    base + 1,
                    cut(base + 1, 12),
                    base,
                    bad,
                ),
                (
                    Op::PutKey,
                    Status::Ok,
                    base + 1,
                    render_record_header(RecordKind::Key, false, base + 1, 12).to_vec(),
                    base,
                    bad,
                ),
                (
                    Op::PutKey,
                    Status::Ok,
                    base + 1,
                    render_record_header(RecordKind::Cut, true, 2, 12).to_vec(),
                    base,
                    bad,
                ),
                (Op::PutKey, Status::Ok, base + 1, vec![], base, bad),
                (
                    Op::PutKey,
                    Status::Ok,
                    base + 2,
                    header.to_vec(),
                    base,
                    Err(WireError::Version),
                ),
                (
                    Op::PutKey,
                    Status::Ok,
                    EPOCH_MAX + 1,
                    header.to_vec(),
                    EPOCH_MAX,
                    Err(WireError::Version),
                ),
                // Versions of the blob-less answers.
                (
                    Op::PutKey,
                    Status::Empty,
                    1,
                    vec![],
                    base,
                    Err(WireError::Version),
                ),
                (
                    Op::GetKey,
                    Status::Empty,
                    1,
                    vec![],
                    base,
                    Err(WireError::Version),
                ),
                (
                    Op::GetKey,
                    Status::NotModified,
                    6,
                    vec![],
                    7,
                    Err(WireError::Version),
                ),
                (
                    Op::GetKey,
                    Status::NotModified,
                    0,
                    vec![],
                    0,
                    Err(WireError::Version),
                ),
                (
                    Op::GetKey,
                    Status::NotModified,
                    EPOCH_MAX + 1,
                    vec![],
                    EPOCH_MAX + 1,
                    Err(WireError::Version),
                ),
                (
                    Op::Prune,
                    Status::NotFound,
                    2,
                    vec![],
                    5,
                    Err(WireError::Version),
                ),
                // A blob where none belongs.
                (
                    Op::GetKey,
                    Status::NotModified,
                    7,
                    cut(7, 1),
                    7,
                    Err(WireError::Blob),
                ),
                (
                    Op::Prune,
                    Status::Ok,
                    1,
                    b"1".to_vec(),
                    5,
                    Err(WireError::Blob),
                ),
            ];
            for (i, (op, status, version, blob, have, want)) in cases.into_iter().enumerate() {
                let got = decode(&reply(status, version, &blob), op, have).map(|_| ());
                assert_eq!(got, want, "case {i}: {op:?} {status:?}");
            }
            // A record past the size limit.
            let mut long = key_record(1, 12);
            long.resize(MAX_RECORD + 1, 0);
            assert_eq!(
                decode(&reply(Status::Ok, 3, &long), Op::GetKey, 0).err(),
                Some(WireError::Length)
            );
            // The vault ops never take a record.
            assert_eq!(
                decode(&reply(Status::Ok, 3, &cut(3, 1)), Op::Get, 0).err(),
                Some(WireError::Vault)
            );
        }
    }

    #[test]
    fn list_lines() {
        let entries = [
            ListEntry {
                id: ID,
                head: 42,
                size: 8192,
                mtime: 1_792_000_000,
            },
            ListEntry {
                id: [0; 16],
                head: u64::MAX,
                size: 0,
                mtime: 0,
            },
        ];
        let blob = render_list(&entries);
        let text = format!("{} 42 8192 1792000000\n", crate::syncfile::hex(&ID));
        assert!(blob.starts_with(text.as_bytes()));
        assert_eq!(parse_list(&blob).unwrap(), entries);
        assert_eq!(parse_list(b""), Some(Vec::new()));
        let line = text.trim_end();
        for bad in [
            line.to_string(),                          // no final LF
            format!("{}\n", line.to_uppercase()),      // uppercase ID
            format!("{line} 7\n"),                     // extra field
            format!("{line} \n"),                      // trailing space
            format!("{}\n", &line[..line.len() - 11]), // missing field
            format!("{line}\r\n"),
            format!("{line}\n\n"),
            text.replace(" 42 ", " +42 "),
            text.replace("1792000000", "1792000000.5"),
            text.replace("8192", "-1"),
            text.replace("42", "18446744073709551616"),
            text.replace("8192", "\u{c624}"),
        ] {
            assert_eq!(parse_list(bad.as_bytes()), None, "{bad:?}");
        }
        let bytes = reply(Status::Ok, 2, &blob);
        let (r, _) = decode(&bytes, Op::List).unwrap();
        assert_eq!(parse_list(r.blob).unwrap().len(), 2);
        let mut broken = blob.clone();
        broken[0] = b'G';
        let bytes = reply(Status::Ok, 2, &broken);
        assert_eq!(decode(&bytes, Op::List), Err(WireError::Blob));
    }
}
