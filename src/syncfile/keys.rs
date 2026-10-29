//! The key-file sync files of `<vault>.sync\` (security-key build only;
//! spec v3 §7.10): the app's key request `outgoing.goyokeysync` (`kreq`),
//! the helper's key view `incoming.goyokeysync` (`kview`) with the server's
//! record grammar, and the app's `prune.request`. None of them is
//! authenticated (R33): every request is idempotent and CAS-guarded at the
//! server, so a planted file costs availability and server history, never a
//! key file that any PC opens. Every epoch and record number in them is at
//! most `EPOCH_MAX`; a larger one makes the file malformed.
use super::{ascii, decimal, field, hex, parse_hex};
use crate::vault::keyfile::{EPOCH_MAX, KEY_FILE_LIMIT, is_sync_key_file};

/// The key request: written by the app, read by the helper.
pub const KEY_REQUEST: &str = "outgoing.goyokeysync";
/// The key view: written by the helper (and its fetch), read by the app.
pub const KEY_VIEW: &str = "incoming.goyokeysync";
/// A request to drop server history below an epoch (spec §7.19).
pub const PRUNE_REQUEST: &str = "prune.request";
pub const KEY_REQUEST_MAGIC: &[u8; 8] = b"GOYOSKO2";
pub const KEY_VIEW_MAGIC: &[u8; 8] = b"GOYOSKI2";
/// The header of a record in the server's `k/`, as served.
pub const RECORD_MAGIC: &[u8; 8] = b"GOYOSKR1";
/// Magic, op, 7 zero bytes, `base`, `floor`.
pub const KEY_REQUEST_HEADER: usize = 32;
/// Magic, line, outcome, 6 zero bytes, `seq`, `answered`.
pub const KEY_VIEW_HEADER: usize = 56;
/// Magic, type, damaged flag and 6 zero bytes, `generation`, `floor`.
pub const RECORD_HEADER: usize = 32;
/// The smallest GOYOKS01 file (one slot, no tombstones), as gate 3 says.
pub const MIN_SYNC_KEY_FILE: usize = 489;
pub const MAX_SYNC_KEY_FILE: usize = KEY_FILE_LIMIT;
pub const MAX_KEY_REQUEST: usize = KEY_REQUEST_HEADER + MAX_SYNC_KEY_FILE;
pub const MAX_RECORD: usize = RECORD_HEADER + MAX_SYNC_KEY_FILE;
pub const MAX_KEY_VIEW: usize = KEY_VIEW_HEADER + MAX_RECORD;
pub const MAX_PRUNE_REQUEST: usize = 128;
const PRUNE_HEADER: &str = "goyo-prune 1";

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// What a key request asks the server to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyOp {
    /// PUTKEY: store this GOYOKS01 file as the record after `base`.
    Put = 1,
    /// CUTKEY: end the generation that holds record `base`.
    Cut = 2,
}
/// The key request `kreq` (`GOYOSKO2`): one PUT or one CUT.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyRequest<'a> {
    pub op: KeyOp,
    /// A record number (spec §7.13). PUT: the record this upload builds on,
    /// 0 for none; CUT: the record whose generation it ends, 0 for the empty
    /// namespace.
    pub base: u64,
    /// PUT: the epoch of the record `base` names, as the app read it (0 for
    /// none); the payload's epoch lies above it. CUT: 0.
    pub floor: u64,
    /// PUT: the GOYOKS01 file; CUT: nothing.
    pub payload: &'a [u8],
}
impl<'a> KeyRequest<'a> {
    pub fn put(base: u64, floor: u64, payload: &'a [u8]) -> Self {
        Self {
            op: KeyOp::Put,
            base,
            floor,
            payload,
        }
    }
    pub fn cut(base: u64) -> Self {
        Self {
            op: KeyOp::Cut,
            base,
            floor: 0,
            payload: &[],
        }
    }
    /// The payload's epoch (bytes 24..32 of a GOYOKS01 file); 0 for a CUT.
    pub fn epoch(&self) -> u64 {
        match self.op {
            KeyOp::Put if self.payload.len() >= 32 => u64_at(self.payload, 24),
            _ => 0,
        }
    }
}
/// Why a key request is refused (the helper's gate 2 adds the file checks).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestError {
    /// Not a `GOYOSKO2` request for a GOYOKS01 key file: the wrapper, the
    /// size, the key file's grammar or its epoch.
    Format,
    /// A GOYOKS01 key file of another vault.
    Id,
}
pub fn render_key_request(r: &KeyRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_REQUEST_HEADER + r.payload.len());
    out.extend_from_slice(KEY_REQUEST_MAGIC);
    out.push(r.op as u8);
    out.extend_from_slice(&[0; 7]);
    out.extend_from_slice(&r.base.to_le_bytes());
    out.extend_from_slice(&r.floor.to_le_bytes());
    out.extend_from_slice(r.payload);
    out
}
/// The strict parse of `kreq` for the vault `id` (the syntax of gate 2,
/// spec §7.12): the magic, op 1 or 2, the reserved bytes zero, `base` and
/// `floor` at most `EPOCH_MAX`; a CUT is exactly the 32-byte header with
/// `floor` 0; a PUT carries 489 to 32,768 bytes that pass
/// `is_sync_key_file` for `id` (GOYOKS01, PIN mode, every slot a PIN slot,
/// epoch at most `EPOCH_MAX`, `ks_id` not `KS_ID_ZERO`) at an epoch above
/// `floor`. There is no bound above `floor` (S6-2 #1).
pub fn parse_key_request<'a>(
    bytes: &'a [u8],
    id: &[u8; 16],
) -> Result<KeyRequest<'a>, RequestError> {
    let format = Err(RequestError::Format);
    if bytes.len() < KEY_REQUEST_HEADER
        || bytes.len() > MAX_KEY_REQUEST
        || &bytes[..8] != KEY_REQUEST_MAGIC
        || bytes[9..16] != [0; 7]
    {
        return format;
    }
    let (base, floor) = (u64_at(bytes, 16), u64_at(bytes, 24));
    if base > EPOCH_MAX || floor > EPOCH_MAX {
        return format;
    }
    let payload = &bytes[KEY_REQUEST_HEADER..];
    match bytes[8] {
        2 if payload.is_empty() && floor == 0 => Ok(KeyRequest::cut(base)),
        1 if (MIN_SYNC_KEY_FILE..=MAX_SYNC_KEY_FILE).contains(&payload.len()) => {
            // A GOYOKS01 file of another vault is told apart from one that
            // is not a sync key file at all.
            if &payload[..8] == b"GOYOKS01" && &payload[8..24] != id {
                return Err(RequestError::Id);
            }
            match is_sync_key_file(payload, id) {
                Some(syntax) if syntax.epoch > floor => Ok(KeyRequest::put(base, floor, payload)),
                _ => format,
            }
        }
        _ => format,
    }
}

/// A record of the server's key namespace (spec §7.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// A GOYOKS01 file of one generation.
    Key = 1,
    /// The end of a generation.
    Cut = 2,
}
/// A record as served: its 32-byte header, then the key file (a key
/// record) or nothing (a cut).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Record<'a> {
    pub number: u64,
    pub kind: RecordKind,
    /// The cut the server reads a damaged top as (header byte 9 = 1); its
    /// floor is the one in the damaged record's name.
    pub damaged: bool,
    /// A key record: the number of the cut that began its generation (0
    /// before any). A cut: its own number.
    pub generation: u64,
    /// A key record: its key file's epoch. A cut: the floor of the top it
    /// ended.
    pub floor: u64,
    pub payload: &'a [u8],
}
/// A record header: the magic, the type, byte 9 (1 only in the cut the
/// server synthesizes for a damaged top), 6 zero bytes, `generation` and `floor`.
pub fn render_record_header(
    kind: RecordKind,
    damaged: bool,
    generation: u64,
    floor: u64,
) -> [u8; 32] {
    let mut out = [0u8; RECORD_HEADER];
    out[..8].copy_from_slice(RECORD_MAGIC);
    out[8] = kind as u8;
    out[9] = u8::from(damaged);
    out[16..24].copy_from_slice(&generation.to_le_bytes());
    out[24..32].copy_from_slice(&floor.to_le_bytes());
    out
}
/// The header grammar alone: (type, damaged, `generation`, `floor`). Byte 9 may be
/// 1 only for a cut, and `generation` and `floor` are at most `EPOCH_MAX`.
pub fn parse_record_header(bytes: &[u8]) -> Option<(RecordKind, bool, u64, u64)> {
    let head = bytes.get(..RECORD_HEADER)?;
    if &head[..8] != RECORD_MAGIC || head[10..16] != [0; 6] {
        return None;
    }
    let kind = match head[8] {
        1 => RecordKind::Key,
        2 => RecordKind::Cut,
        _ => return None,
    };
    let damaged = match (kind, head[9]) {
        (_, 0) => false,
        (RecordKind::Cut, 1) => true,
        _ => return None,
    };
    let (generation, floor) = (u64_at(head, 16), u64_at(head, 24));
    (generation <= EPOCH_MAX && floor <= EPOCH_MAX).then_some((kind, damaged, generation, floor))
}
/// The record numbered `number` (1 to `EPOCH_MAX`) of the vault `id`, as
/// every answer that carries one must hold it (spec §7.13): a key record
/// with `generation` below its number and a payload that passes
/// `is_sync_key_file` for `id` at the epoch `floor`, or a cut of exactly 32
/// bytes whose `generation` is its own number.
pub fn parse_record<'a>(bytes: &'a [u8], number: u64, id: &[u8; 16]) -> Option<Record<'a>> {
    let (kind, damaged, generation, floor) = parse_record_header(bytes)?;
    if !(1..=EPOCH_MAX).contains(&number) || bytes.len() > MAX_RECORD {
        return None;
    }
    let payload = &bytes[RECORD_HEADER..];
    let valid = match kind {
        RecordKind::Key => {
            generation < number && is_sync_key_file(payload, id).is_some_and(|s| s.epoch == floor)
        }
        RecordKind::Cut => payload.is_empty() && generation == number,
    };
    valid.then_some(Record {
        number,
        kind,
        damaged,
        generation,
        floor,
        payload,
    })
}

/// What the server answered to the request `answered` names (spec §7.10).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum KeyOutcome {
    #[default]
    None = 0,
    /// PUTKEY or CUTKEY OK.
    Applied = 1,
    /// PUTKEY CONFLICT, or EMPTY.
    Conflict = 2,
    /// PUTKEY BAD_BLOB or TOO_LARGE: the server refused the key file.
    Refused = 3,
    /// BAD_REQUEST: this line serves no key ops for this vault.
    NoKeyOps = 4,
}
impl KeyOutcome {
    const ALL: [KeyOutcome; 5] = [
        Self::None,
        Self::Applied,
        Self::Conflict,
        Self::Refused,
        Self::NoKeyOps,
    ];
    fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|o| *o as u8 == code)
    }
}
/// The key view `kview` (`GOYOSKI2`): the server's top record as last
/// served to this PC, and which request the last answer was for. Only a
/// cache: losing it costs one fetch, or one resend that the server answers
/// like a late request.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct KeyView {
    /// 0: this PC's line serves key ops; 1: it answered BAD_REQUEST, and
    /// `seq` and `record` are the last line-0 answer's.
    pub line: u8,
    pub outcome: KeyOutcome,
    /// The server's top record number; 0 for none.
    pub seq: u64,
    /// SHA-256 of the whole `kreq` file `outcome` answers; None with
    /// `outcome` None.
    pub answered: Option<[u8; 32]>,
    /// The top record exactly as served; empty when `seq` is 0.
    pub record: Vec<u8>,
}
impl KeyView {
    /// The top record; None when the server holds none (`seq` 0). A view
    /// from [`parse_key_view`] always holds a valid one otherwise.
    pub fn top(&self, id: &[u8; 16]) -> Option<Record<'_>> {
        (self.seq > 0)
            .then(|| parse_record(&self.record, self.seq, id))
            .flatten()
    }
}
pub fn render_key_view(v: &KeyView) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_VIEW_HEADER + v.record.len());
    out.extend_from_slice(KEY_VIEW_MAGIC);
    out.push(v.line);
    out.push(v.outcome as u8);
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&v.seq.to_le_bytes());
    out.extend_from_slice(&v.answered.unwrap_or([0; 32]));
    out.extend_from_slice(&v.record);
    out
}
/// The strict parse of `kview` for the vault `id`: the magic, `line` 0 or
/// 1, a known `outcome` that is 0 exactly when `answered` is zero, the
/// reserved bytes zero, `seq` at most `EPOCH_MAX`, and the record numbered
/// `seq` (nothing at all for `seq` 0). Anything else is malformed, which the
/// app treats as absent and the helper fetches again with `have` 0.
pub fn parse_key_view(bytes: &[u8], id: &[u8; 16]) -> Option<KeyView> {
    if bytes.len() < KEY_VIEW_HEADER
        || bytes.len() > MAX_KEY_VIEW
        || &bytes[..8] != KEY_VIEW_MAGIC
        || bytes[8] > 1
        || bytes[10..16] != [0; 6]
    {
        return None;
    }
    let outcome = KeyOutcome::from_code(bytes[9])?;
    let seq = u64_at(bytes, 16);
    let answered: [u8; 32] = bytes[24..56].try_into().unwrap();
    let answered = (answered != [0; 32]).then_some(answered);
    let record = &bytes[KEY_VIEW_HEADER..];
    let consistent = (outcome == KeyOutcome::None) == answered.is_none();
    let record_ok = match seq {
        0 => record.is_empty(),
        _ => parse_record(record, seq, id).is_some(),
    };
    (consistent && seq <= EPOCH_MAX && record_ok).then(|| KeyView {
        line: bytes[8],
        outcome,
        seq,
        answered,
        record: record.to_vec(),
    })
}

/// `goyo-prune 1\nid=<32 hex>\nepoch=<u64>\n`: drop the server's vault
/// versions of `id` below `epoch` (spec §7.19).
pub fn render_prune_request(id: &[u8; 16], epoch: u64) -> Vec<u8> {
    format!("{PRUNE_HEADER}\nid={}\nepoch={epoch}\n", hex(id)).into_bytes()
}
/// `(id, epoch)`, with an epoch from 1 to `EPOCH_MAX`, when the bytes are
/// exactly what [`render_prune_request`] writes.
pub fn parse_prune_request(bytes: &[u8]) -> Option<([u8; 16], u64)> {
    let text = ascii(bytes, MAX_PRUNE_REQUEST)?.strip_suffix('\n')?;
    let mut lines = text.split('\n');
    if lines.next()? != PRUNE_HEADER {
        return None;
    }
    let id = parse_hex(field(&mut lines, "id=")?)?;
    let epoch = decimal(field(&mut lines, "epoch=")?)?;
    let valid = id != [0; 16] && (1..=EPOCH_MAX).contains(&epoch) && lines.next().is_none();
    valid.then_some((id, epoch))
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The GOYOKS01 fixture: vault 3a3b…49, epoch 9 (tests/fixtures).
    const KS: &[u8] = include_bytes!("../../tests/fixtures/goyoks01.goyokey");
    const ID: [u8; 16] = [
        0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49,
    ];
    /// The fixture at another epoch; still well formed (no slot was added
    /// at any epoch above 9).
    fn ks(epoch: u64) -> Vec<u8> {
        let mut f = KS.to_vec();
        f[24..32].copy_from_slice(&epoch.to_le_bytes());
        f
    }
    fn key_record(generation: u64, payload: &[u8]) -> Vec<u8> {
        let mut r =
            render_record_header(RecordKind::Key, false, generation, u64_at(payload, 24)).to_vec();
        r.extend_from_slice(payload);
        r
    }

    #[test]
    fn key_requests_round_trip_and_refuse_the_rest() {
        assert!(is_sync_key_file(KS, &ID).is_some());
        let file = ks(12);
        let put = KeyRequest::put(4, 9, &file);
        let bytes = render_key_request(&put);
        assert_eq!(bytes.len(), 32 + file.len());
        assert_eq!(&bytes[..9], b"GOYOSKO2\x01");
        assert_eq!(parse_key_request(&bytes, &ID), Ok(put));
        assert_eq!(put.epoch(), 12);
        let cut = KeyRequest::cut(7);
        let bytes = render_key_request(&cut);
        assert_eq!(bytes.len(), 32);
        assert_eq!(parse_key_request(&bytes, &ID), Ok(cut));
        assert_eq!(cut.epoch(), 0);
        let max = KeyRequest::cut(EPOCH_MAX);
        assert_eq!(parse_key_request(&render_key_request(&max), &ID), Ok(max));
        // No epoch bound above floor (S6-2 #1).
        let far = ks(EPOCH_MAX);
        let up = KeyRequest::put(0, 0, &far);
        assert_eq!(parse_key_request(&render_key_request(&up), &ID), Ok(up));
        let format = Err(RequestError::Format);
        let with = |r: &KeyRequest, at: usize, value: u8| {
            let mut b = render_key_request(r);
            b[at] = value;
            b
        };
        let other_vault = {
            let mut f = file.clone();
            f[8] ^= 1;
            f
        };
        let wrong_magic = |magic: &[u8; 8]| {
            let mut f = file.clone();
            f[..8].copy_from_slice(magic);
            render_key_request(&KeyRequest::put(0, 0, &f))
        };
        let cases = [
            (with(&put, 7, b'1'), format), // GOYOSKO1
            (with(&put, 8, 3), format),    // unknown op
            (with(&put, 8, 0), format),
            (with(&put, 9, 1), format), // reserved bytes
            (with(&put, 15, 1), format),
            (with(&cut, 8, 1), format),  // a PUT with no payload
            (with(&put, 8, 2), format),  // a CUT with a payload
            (with(&cut, 24, 1), format), // a CUT's floor is 0
            (render_key_request(&KeyRequest::cut(EPOCH_MAX + 1)), format),
            (
                render_key_request(&KeyRequest::put(EPOCH_MAX + 1, 0, &file)),
                format,
            ),
            (
                render_key_request(&KeyRequest::put(0, EPOCH_MAX + 1, &file)),
                format,
            ),
            // The payload's epoch at or below floor, or above EPOCH_MAX.
            (render_key_request(&KeyRequest::put(3, 12, &file)), format),
            (render_key_request(&KeyRequest::put(3, 13, &file)), format),
            (
                render_key_request(&KeyRequest::put(0, 0, &ks(EPOCH_MAX + 1))),
                format,
            ),
            (
                render_key_request(&KeyRequest::put(0, 0, &other_vault)),
                Err(RequestError::Id),
            ),
            (
                render_key_request(&KeyRequest::put(0, 0, &file[..488])),
                format,
            ),
            (
                render_key_request(&KeyRequest::put(0, 0, &file[..file.len() - 1])),
                format,
            ),
            (wrong_magic(b"GOYOKH01"), format),
            (wrong_magic(b"GOYOKE03"), format),
            (wrong_magic(b"GOYOKS02"), format),
            (wrong_magic(b"GOYOVA04"), format),
            (Vec::new(), format),
            (bytes[..31].to_vec(), format),
        ];
        for (i, (bytes, want)) in cases.into_iter().enumerate() {
            assert_eq!(parse_key_request(&bytes, &ID), want, "case {i}");
        }
        // The vault wrapper is never a key request, and a key request never
        // a vault upload.
        let mut wrapped = b"GOYOSOU1".to_vec();
        wrapped.extend_from_slice(&[0; 24]);
        wrapped.extend_from_slice(&file);
        assert_eq!(parse_key_request(&wrapped, &ID), format);
        assert_eq!(
            super::super::parse_outgoing(&render_key_request(&put)),
            None
        );
    }
    #[test]
    fn records_follow_the_server_grammar() {
        let file = ks(12);
        let key = key_record(3, &file);
        let r = parse_record(&key, 5, &ID).unwrap();
        assert_eq!(
            (r.kind, r.damaged, r.generation, r.floor),
            (RecordKind::Key, false, 3, 12)
        );
        assert_eq!(r.payload, &file[..]);
        let cut = render_record_header(RecordKind::Cut, false, 6, 12);
        assert!(parse_record(&cut, 6, &ID).is_some());
        let damaged = render_record_header(RecordKind::Cut, true, 6, 12);
        assert!(parse_record(&damaged, 6, &ID).unwrap().damaged);
        let refused = [
            (key.clone(), 3, "generation not below its number"),
            (key.clone(), 0, "number 0"),
            (key.clone(), EPOCH_MAX + 1, "number above EPOCH_MAX"),
            (key_record(3, &ks(13))[..].to_vec(), 5, "fine"),
            (cut.to_vec(), 7, "a cut's generation is its number"),
            (
                render_record_header(RecordKind::Key, true, 3, 12).to_vec(),
                5,
                "damaged key",
            ),
        ];
        for (bytes, number, what) in refused {
            let ok = parse_record(&bytes, number, &ID).is_some();
            assert_eq!(ok, what == "fine", "{what}");
        }
        let mutate = |at: usize, value: u8| {
            let mut b = key.clone();
            b[at] = value;
            parse_record(&b, 5, &ID).is_none()
        };
        assert!(mutate(7, b'2')); // GOYOSKR2
        assert!(mutate(8, 3)); // unknown type
        assert!(mutate(10, 1)); // reserved
        assert!(mutate(24, 13)); // floor not the payload's epoch
        assert!(mutate(32 + 8, 0)); // another vault's file
        let mut big = render_record_header(RecordKind::Cut, false, 6, EPOCH_MAX + 1).to_vec();
        assert!(parse_record(&big, 6, &ID).is_none());
        big[24..32].copy_from_slice(&EPOCH_MAX.to_le_bytes());
        assert!(parse_record(&big, 6, &ID).is_some());
        let mut long_cut = cut.to_vec();
        long_cut.push(0);
        assert!(parse_record(&long_cut, 6, &ID).is_none());
        assert!(parse_record(&key[..40], 5, &ID).is_none());
        let mut ke = file.clone();
        ke[..8].copy_from_slice(b"GOYOKH01");
        assert!(parse_record(&key_record(3, &ke), 5, &ID).is_none());
    }
    #[test]
    fn key_views_are_strict() {
        let file = ks(12);
        let views = [
            KeyView::default(),
            KeyView {
                line: 1,
                outcome: KeyOutcome::NoKeyOps,
                seq: 5,
                answered: Some([7; 32]),
                record: key_record(3, &file),
            },
            KeyView {
                line: 0,
                outcome: KeyOutcome::Applied,
                seq: 6,
                answered: Some([8; 32]),
                record: render_record_header(RecordKind::Cut, false, 6, 12).to_vec(),
            },
            KeyView {
                line: 0,
                outcome: KeyOutcome::None,
                seq: EPOCH_MAX,
                answered: None,
                record: render_record_header(RecordKind::Cut, true, EPOCH_MAX, 4).to_vec(),
            },
        ];
        for v in &views {
            let bytes = render_key_view(v);
            assert!(bytes.len() <= MAX_KEY_VIEW);
            assert_eq!(parse_key_view(&bytes, &ID).as_ref(), Some(v));
        }
        assert_eq!(views[1].top(&ID).unwrap().kind, RecordKind::Key);
        assert_eq!(views[0].top(&ID), None);
        let base = render_key_view(&views[1]);
        let with = |at: usize, value: u8| {
            let mut b = base.clone();
            b[at] = value;
            b
        };
        let mut broken = vec![
            with(7, b'1'), // GOYOSKI1
            with(8, 2),    // line
            with(9, 5),    // outcome
            with(9, 0),    // outcome 0 with an answer
            with(10, 1),   // reserved
            with(16, 3),   // seq not above the key record's generation
            base[..base.len() - 1].to_vec(),
            base[..55].to_vec(),
            Vec::new(),
        ];
        let mut appended = base.clone();
        appended.push(0);
        broken.push(appended);
        let mut no_answer = base.clone();
        no_answer[24..56].fill(0);
        broken.push(no_answer);
        let mut empty_with_record = render_key_view(&KeyView::default());
        empty_with_record.extend_from_slice(&render_record_header(RecordKind::Cut, false, 1, 0));
        broken.push(empty_with_record);
        let mut huge = render_key_view(&views[2]);
        huge[16..24].copy_from_slice(&(EPOCH_MAX + 1).to_le_bytes());
        broken.push(huge);
        for (i, b) in broken.iter().enumerate() {
            assert!(parse_key_view(b, &ID).is_none(), "case {i}");
        }
        // Another vault's view.
        assert!(parse_key_view(&base, &[0x3b; 16]).is_none());
    }
    #[test]
    fn prune_requests_are_strict() {
        let bytes = render_prune_request(&ID, 42);
        assert_eq!(
            bytes,
            b"goyo-prune 1\nid=3a3b3c3d3e3f40414243444546474849\nepoch=42\n"
        );
        assert!(bytes.len() <= MAX_PRUNE_REQUEST);
        assert_eq!(parse_prune_request(&bytes), Some((ID, 42)));
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            text.replace("epoch=42", "epoch=0"),
            text.replace("epoch=42", &format!("epoch={}", EPOCH_MAX + 1)),
            text.replace("prune 1", "prune 2"),
            text.replace("3a3b", "3A3B"),
            text.replace(&hex(&ID), &hex(&[0; 16])),
            text.trim_end().to_string(),
            text.replace('\n', "\r\n"),
            format!("{text}x=1\n"),
            text.replace("epoch=42\n", ""),
        ] {
            assert_eq!(parse_prune_request(bad.as_bytes()), None, "{bad:?}");
        }
    }
}
