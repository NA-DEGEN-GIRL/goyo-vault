//! Frames between goyo-sync.exe and goyo-sync-server.py: one request on the
//! ssh child's stdin, one response on its stdout, then EOF. Little endian.
//! Both directions carry the exact blob length and its SHA-256, so a cut
//! stream, a line-ending translation or shell output cannot pass as data.
//! Only the helper and tests use this; goyo-vault.exe never calls it.
use crate::{
    syncfile::{MIN_VAULT, VAULT_MAGIC, decimal, newer_vault_format, parse_hex},
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
}
impl Op {
    pub const ALL: [Op; 5] = [Op::Hello, Op::Get, Op::Put, Op::List, Op::Fetch];
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
    ServerError = 20,
}
impl Status {
    pub const ALL: [Status; 10] = [
        Status::Ok,
        Status::NotModified,
        Status::Conflict,
        Status::Empty,
        Status::NotFound,
        Status::BadRequest,
        Status::BadBlob,
        Status::TooLarge,
        Status::Limit,
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
    /// Not a GOYOVA02 file of this vault, 96 B to 8 MiB.
    Vault,
    /// GOYOVA03 or later: a newer Goyo Vault wrote it.
    NewerFormat,
    /// The HELLO echo differs: the ssh pipe is not binary-transparent.
    Echo,
    /// The version breaks the rule for this reply.
    Version,
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
            Self::Vault => "not a GOYOVA02 file of this vault",
            Self::NewerFormat => "vault from a newer version",
            Self::Echo => "binary echo differs",
            Self::Version => "unexpected version",
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
/// A vault file the server may store or serve: GOYOVA02 with this vault's ID
/// and 96 B to 8 MiB. A key file (GOYOKE) never passes.
pub fn check_vault_blob(blob: &[u8], id: &[u8; 16]) -> Result<(), WireError> {
    if newer_vault_format(blob) {
        return Err(WireError::NewerFormat);
    }
    if !(MIN_VAULT..=MAX_FILE).contains(&blob.len())
        || &blob[..8] != VAULT_MAGIC
        || &blob[8..24] != id
    {
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
    /// a GOYOVA02 file of `id`: the last gate before the ssh pipe.
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
    /// 8 MiB, none otherwise) and a matching SHA. Whether a PUT blob is a
    /// vault is the server's BAD_BLOB check.
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
        };
        if !fits || blob.len() != len {
            return Err(WireError::Length);
        }
        let sha_ok = match op {
            Op::Hello | Op::Put => sha256(blob) == blob_sha,
            Op::Get => true,
            Op::List | Op::Fetch => blob_sha == [0; 32],
        };
        if !sha_ok {
            return Err(WireError::Sha);
        }
        let version_fits = match op {
            Op::Hello => version == PROTOCOL,
            Op::List => version == 0,
            Op::Get | Op::Put | Op::Fetch => true,
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
        | (Op::Put, S::Ok | S::Empty | S::BadBlob | S::TooLarge | S::Limit)
        | (Op::Fetch, S::NotFound) => Body::Nothing,
        (Op::List, S::Ok) => Body::List,
        _ => return None,
    })
}
/// `have` is the request's version field: GET have, PUT expected, FETCH N.
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
    /// pass [`check_vault_blob`]. Anything else is a protocol error.
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
    /// Blob kinds, indexes into `blobs()`.
    const NOTHING: usize = 0;
    const VAULT: usize = 1;
    const ECHO: usize = 2;
    const LIST: usize = 3;
    fn vault(id: &[u8; 16], len: usize) -> Vec<u8> {
        let mut v = Vec::from(*VAULT_MAGIC);
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
        assert_eq!(codes, [0, 1, 2, 3, 4, 10, 11, 12, 13, 20]);
        let ops: Vec<u8> = Op::ALL.iter().map(|o| o.code()).collect();
        assert_eq!(ops, [1, 2, 3, 4, 5]);
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
        assert_eq!(checked, 13 + 2 * Op::ALL.len());
        // An empty LIST says 0 vaults.
        let bytes = reply(Status::Ok, 0, &[]);
        assert!(decode(&bytes, Op::List).is_ok());
    }
    #[test]
    fn only_listed_replies_are_accepted() {
        let blobs = blobs();
        for op in Op::ALL {
            for status in Status::ALL {
                for (kind, blob) in blobs.iter().enumerate() {
                    let bytes = reply(status, good_version(op, status), blob);
                    let valid = allowed(op, status) == Some(kind);
                    let got = decode(&bytes, op);
                    assert_eq!(got.is_ok(), valid, "{op:?} {status:?} kind {kind}: {got:?}");
                }
            }
            for code in [5, 9, 14, 19, 21, 255] {
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
        // Vault blobs: GOYOVA02 of this vault, 96 B to 8 MiB.
        let mut key = vault(&ID, 148);
        key[..8].copy_from_slice(b"GOYOKE01");
        let mut v1 = vault(&ID, 300);
        v1[..8].copy_from_slice(b"GOYOVA01");
        let cases = [
            (vault(&[0x40; 16], 300), WireError::Vault),
            (vault(&ID, MIN_VAULT - 1), WireError::Vault),
            (key, WireError::Vault),
            (v1, WireError::Vault),
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
        let mut newer = vault(&ID, 300);
        newer[..8].copy_from_slice(b"GOYOVA03");
        let bytes = reply(Status::Ok, 9, &newer);
        assert_eq!(decode(&bytes, Op::Get), Err(WireError::NewerFormat));
        let bytes = reply(Status::Ok, 9, &vault(&ID, MAX_FILE));
        assert!(decode(&bytes, Op::Get).is_ok());
        let bytes = reply(Status::Ok, 9, &vault(&ID, MIN_VAULT));
        assert!(decode(&bytes, Op::Get).is_ok());
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
        for op in [0, 6, 255] {
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
        let mut v1 = vault(&ID, 300);
        v1[..8].copy_from_slice(b"GOYOVA01");
        let mut newer = vault(&ID, 300);
        newer[..8].copy_from_slice(b"GOYOVA03");
        let cases = [
            (key_otp, WireError::Vault),
            (key, WireError::Vault),
            (v1, WireError::Vault),
            (vault(&[0x40; 16], 300), WireError::Vault),
            (vault(&ID, MIN_VAULT - 1), WireError::Vault),
            (vault(&ID, MAX_FILE + 1), WireError::Vault),
            (newer, WireError::NewerFormat),
            (Vec::new(), WireError::Vault),
        ];
        for (blob, want) in cases {
            assert_eq!(Request::put(ID, 0, &blob).err(), Some(want));
            assert_eq!(check_vault_blob(&blob, &ID), Err(want));
        }
        assert!(Request::put(ID, 0, &vault(&ID, MIN_VAULT)).is_ok());
        assert!(Request::put(ID, 0, &vault(&ID, MAX_FILE)).is_ok());
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
