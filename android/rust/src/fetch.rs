//! "서버에서 가져오기" (stage 4): the phone's side of goyo-sync's "이 PC로
//! 가져오기" (src/bin/goyo-sync/setup.rs `fetch`, `fetch_key`,
//! `server_keys`), over any transport so the tests run it against the real
//! server script. LIST shows the server's vaults (and, for the first few,
//! whether the server holds their key file); FETCH writes the head version
//! of one vault as a new file, checked by the wire layer exactly as
//! `--fetch` checks it (frame SHA, a GOYOVA vault blob of the ID asked for,
//! the size limit); GETKEY then puts the server's key record into the
//! vault's sync folder as the key view (`incoming.goyokeysync`, line 0,
//! nothing answered), never as a `.goyokey`. The vault app's "서버에서
//! 가져온 금고" steps (the lib's `prepare_restore_fetched`, G1 or the trust
//! without a code, `tofu_save`) take it from there. Nothing here trusts
//! the key record: it is only offered to the lib's own checks.
use goyo_vault::{
    syncengine::{self, CallError, Log, transport::Transport},
    syncfile::{self, KEY_VIEW, KeyView, RecordKind, SyncState, parse_record, render_key_view},
    syncwire::{ListEntry, Request, Status, parse_list},
    vault::keyfile::is_sync_key_file,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

/// The server list asks this many vaults' key files at most (one
/// exchange each), as goyo-sync's window does.
pub const MAX_KEY_ASKS: usize = 4;

/// What the server holds as a vault's key file, as this phone's line lets
/// it see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerKey {
    /// A key record of this vault on top.
    Held,
    /// None (EMPTY, or a cut on top).
    Missing,
    /// BAD_REQUEST: the phone's line has no `--key-sync` for the vault.
    NotAllowed,
    /// Not asked, or the exchange or its answer failed.
    Unknown,
}
impl ServerKey {
    pub fn word(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Missing => "missing",
            Self::NotAllowed => "notallowed",
            Self::Unknown => "unknown",
        }
    }
}

/// A failed exchange: the engine's state and detail, or a cancel.
pub type Failed = CallError;

/// LIST, then GETKEY (nothing held) for the first MAX_KEY_ASKS vaults;
/// after a failed GETKEY exchange the rest are not asked.
pub fn list<T: Transport>(
    transport: &mut T,
    log: &Log,
) -> Result<Vec<(ListEntry, ServerKey)>, Failed> {
    let reply = syncengine::call(transport, &Request::list(), "android list", log)?;
    if reply.status != Status::Ok {
        return Err(CallError::Failed(SyncState::Server, "LIST".into()));
    }
    let rows = parse_list(reply.blob())
        .ok_or_else(|| CallError::Failed(SyncState::Server, "LIST".into()))?;
    let mut out = Vec::with_capacity(rows.len());
    let mut failed = false;
    for (n, row) in rows.into_iter().enumerate() {
        if n >= MAX_KEY_ASKS || failed {
            out.push((row, ServerKey::Unknown));
            continue;
        }
        let held = match syncengine::call(
            transport,
            &Request::get_key(row.id, 0, None),
            "android getkey",
            log,
        ) {
            Ok(reply) => match reply.status {
                Status::Ok => match parse_record(reply.blob(), reply.version, &row.id) {
                    Some(r) if r.kind == RecordKind::Key && !r.damaged => {
                        if is_sync_key_file(r.payload, &row.id).is_some() {
                            ServerKey::Held
                        } else {
                            ServerKey::Unknown
                        }
                    }
                    Some(_) => ServerKey::Missing,
                    None => ServerKey::Unknown,
                },
                Status::Empty => ServerKey::Missing,
                Status::BadRequest => ServerKey::NotAllowed,
                _ => ServerKey::Unknown,
            },
            Err(_) => {
                failed = true;
                ServerKey::Unknown
            }
        };
        out.push((row, held));
    }
    Ok(out)
}

/// What [`fetch_vault`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Fetched {
    Saved {
        version: u64,
        bytes: usize,
    },
    /// The vault file (or its sync folder) is there already: never
    /// overwritten.
    Exists,
    NotFound,
    /// A valid answer with another status.
    Server,
    /// The file could not be created or written (it is removed again).
    Write,
    Failed(Failed),
}

/// FETCH of the head version of vault `id` into the new file `path`
/// (`--fetch <id> head <file>`): the reply's vault blob was checked by
/// `Response::decode` (GOYOVA magic, this ID, the size limit, the frame's
/// SHA-256). A file that could not be finished is removed again.
pub fn fetch_vault<T: Transport>(
    transport: &mut T,
    log: &Log,
    id: [u8; 16],
    path: &Path,
) -> Fetched {
    if fs::symlink_metadata(path).is_ok()
        || syncfile::sync_dir(path).is_some_and(|d| fs::symlink_metadata(d).is_ok())
    {
        return Fetched::Exists;
    }
    let reply = match syncengine::call(transport, &Request::fetch(id, 0), "android fetch", log) {
        Ok(reply) => reply,
        Err(e) => return Fetched::Failed(e),
    };
    match reply.status {
        Status::Ok => {}
        Status::NotFound => return Fetched::NotFound,
        _ => return Fetched::Server,
    }
    // The wire layer checked the blob; the header's ID is checked once
    // more here, where it becomes a file.
    let blob = reply.blob();
    if blob.len() < 24 || !blob.starts_with(b"GOYOVA0") || blob[8..24] != id {
        return Fetched::Server;
    }
    if let Some(dir) = path.parent()
        && fs::create_dir_all(dir).is_err()
    {
        return Fetched::Write;
    }
    let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(path) else {
        return Fetched::Write;
    };
    if file.write_all(blob).and_then(|()| file.sync_all()).is_err() {
        drop(file);
        let _ = fs::remove_file(path); // created above, so ours
        return Fetched::Write;
    }
    Fetched::Saved {
        version: reply.version,
        bytes: blob.len(),
    }
}

/// What [`fetch_key`] did with the server's key file once the vault file
/// was saved (setup.rs `KeyGot`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyGot {
    Written,
    /// BAD_REQUEST: the phone's line has no `--key-sync` for the vault.
    NoKeys,
    /// No key record on top.
    Empty,
    /// An answer that is no key file of this vault.
    BadAnswer,
    WriteFailed,
    Failed,
}
impl KeyGot {
    pub fn word(&self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::NoKeys => "nokeys",
            Self::Empty => "empty",
            Self::BadAnswer => "bad",
            Self::WriteFailed => "write",
            Self::Failed => "failed",
        }
    }
}

/// GETKEY with nothing held, after the fetch of `vault` (so the key file is
/// at least as new as the vault file, the floor of spec §7.17). A key
/// record of this vault, by the syntax gate the engine's KG uses, goes
/// into `<vault>.sync/incoming.goyokeysync` (line 0, nothing answered),
/// the sync folder made as a plain directory if needed.
pub fn fetch_key<T: Transport>(transport: &mut T, log: &Log, id: [u8; 16], vault: &Path) -> KeyGot {
    let reply = match syncengine::call(
        transport,
        &Request::get_key(id, 0, None),
        "android getkey",
        log,
    ) {
        Ok(reply) => reply,
        Err(_) => return KeyGot::Failed,
    };
    match reply.status {
        Status::Ok => {}
        Status::Empty => return KeyGot::Empty,
        Status::BadRequest => return KeyGot::NoKeys,
        _ => return KeyGot::BadAnswer,
    }
    let blob = reply.blob();
    let Some(record) = parse_record(blob, reply.version, &id) else {
        return KeyGot::BadAnswer;
    };
    if record.kind != RecordKind::Key || record.damaged {
        return KeyGot::Empty;
    }
    if is_sync_key_file(record.payload, &id).is_none() {
        return KeyGot::BadAnswer;
    }
    let Some(dir) = syncfile::sync_dir(vault) else {
        return KeyGot::WriteFailed;
    };
    if (fs::symlink_metadata(&dir).is_err() && fs::create_dir(&dir).is_err())
        || !syncfile::usable_dir(&dir)
    {
        return KeyGot::WriteFailed;
    }
    let view = KeyView {
        line: 0,
        seq: reply.version,
        record: blob.to_vec(),
        ..KeyView::default()
    };
    if syncfile::replace_file(&dir.join(KEY_VIEW), &render_key_view(&view)).is_err() {
        return KeyGot::WriteFailed;
    }
    KeyGot::Written
}

/// A 32-hex vault ID that is not all zero.
pub fn parse_id(s: &str) -> Option<[u8; 16]> {
    syncfile::parse_hex::<16>(&s.trim().to_ascii_lowercase()).filter(|id| *id != [0; 16])
}
/// A vault's short public tag, as the lib names it (`3FA2-C1D0`).
pub fn tag(id: &[u8; 16]) -> String {
    format!("{:02X}{:02X}-{:02X}{:02X}", id[0], id[1], id[2], id[3])
}
