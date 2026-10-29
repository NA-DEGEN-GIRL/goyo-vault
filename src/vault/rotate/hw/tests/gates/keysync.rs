//! Key-file sync between two PCs (spec v3 §7.8-§7.20 as §2.23 simplified
//! it; §14.10): the app's side against an in-memory key namespace that
//! answers `kreq` and writes `kview` as goyo-sync's KR and KG do, each PC
//! with its own anchor and sync folder.
use super::*;
use crate::{
    syncfile::{
        self, KEY_REQUEST, KEY_VIEW, KeyOp, KeyOutcome, KeyRequest, KeyView, OUTGOING, RecordKind,
        parse_key_request, parse_key_view, render_key_request, render_key_view,
        render_record_header,
    },
    vault::{
        SyncNotice,
        anchor::{GateState, Ks},
        keyfile::EPOCH_SILENT,
        keysync::{
            GATE_PENDING, KEYFILE_READY, KEYSYNC_ASKING, KEYSYNC_FLOOR, KEYSYNC_OFF_PENDING,
            KeyClass,
        },
        rotate::tests::THIRD,
        sha256,
    },
};
use std::path::PathBuf;

/// The server's key namespace (spec §7.13) in memory: records numbered
/// from 1 (type, generation, floor, key file), PUTKEY's CAS on the record
/// number, CUTKEY's generation rule with its fence.
#[derive(Default)]
struct KeyServer {
    records: Vec<(RecordKind, u64, u64, Vec<u8>)>,
}
impl KeyServer {
    fn top(&self) -> u64 {
        self.records.len() as u64
    }
    fn record(&self, n: u64) -> Vec<u8> {
        let (kind, generation, floor, payload) = &self.records[n as usize - 1];
        let mut out = render_record_header(*kind, false, *generation, *floor).to_vec();
        out.extend_from_slice(payload);
        out
    }
    /// The answer to `req`: applied, or not (CONFLICT).
    fn apply(&mut self, req: &KeyRequest) -> bool {
        let top = self.top();
        let last = self.records.last().map(|(k, g, f, _)| (*k, *g, *f));
        match req.op {
            KeyOp::Put if req.base == top => {
                let generation = match last {
                    Some((RecordKind::Key, g, _)) => g,
                    Some((RecordKind::Cut, ..)) => top,
                    None => 0,
                };
                self.records.push((
                    RecordKind::Key,
                    generation,
                    req.epoch(),
                    req.payload.to_vec(),
                ));
                true
            }
            KeyOp::Put => false,
            KeyOp::Cut => {
                let ended = match last {
                    Some((RecordKind::Cut, ..)) => top > req.base,
                    Some((RecordKind::Key, g, _)) => g > req.base,
                    None => false,
                };
                if !ended {
                    let floor = last.map_or(0, |(_, _, f)| f);
                    self.records
                        .push((RecordKind::Cut, top + 1, floor, Vec::new()));
                }
                true
            }
        }
    }
    /// One helper pass for `pc` (spec §7.12): KR sends `kreq` when `kview`
    /// has not answered it, then KG writes the top record into `kview`.
    fn pass(&mut self, pc: &Pc, id: &[u8; 16]) {
        let dir = dir(pc);
        let mut view = kview(pc, id).unwrap_or_default();
        if let Ok(bytes) = fs::read(dir.join(KEY_REQUEST))
            && view.answered != Some(sha256(&bytes))
            && let Ok(req) = parse_key_request(&bytes, id)
        {
            view.outcome = if self.apply(&req) {
                KeyOutcome::Applied
            } else {
                KeyOutcome::Conflict
            };
            view.answered = Some(sha256(&bytes));
        }
        view.line = 0;
        view.seq = self.top();
        view.record = if view.seq > 0 {
            self.record(view.seq)
        } else {
            Vec::new()
        };
        fs::write(dir.join(KEY_VIEW), render_key_view(&view)).unwrap();
    }
}
fn dir(pc: &Pc) -> PathBuf {
    syncfile::sync_dir(&pc.vault()).unwrap()
}
fn kreq(pc: &Pc) -> Option<Vec<u8>> {
    fs::read(dir(pc).join(KEY_REQUEST)).ok()
}
fn kview(pc: &Pc, id: &[u8; 16]) -> Option<KeyView> {
    parse_key_view(&fs::read(dir(pc).join(KEY_VIEW)).ok()?, id)
}
fn ks_of(pc: &Pc, id: &[u8; 16]) -> Ks {
    pc.lines(id).vault.unwrap().state.ks
}
/// A second PC of `a`'s vault (its first unlock confirmed with the code)
/// that syncs: its folder, with a helper status that does key-file sync.
fn synced_pc(a: &Pc, codes: &mut Codes, keys: &Keys, number: u8) -> Pc {
    let b = second_pc(a, codes, keys, number);
    fs::create_dir(dir(&b)).unwrap();
    status(&b);
    b
}
/// A fresh helper status with `features=keys` in `pc`'s sync folder.
fn status(pc: &Pc) {
    let now = otp::now().unwrap();
    let bytes = syncfile::render_status(now, now, syncfile::SyncState::Ok);
    syncfile::replace_file(&dir(pc).join(syncfile::STATUS), &bytes).unwrap();
}
/// `change` with a Reauth touched with key `number`, any gate answered.
fn rekey(
    s: &mut Session,
    codes: &mut Codes,
    keys: &Keys,
    number: u8,
    change: Change,
) -> Result<Rekeyed> {
    let r = reauth(s, OLD, codes, keys, number)?;
    s.rekey(r, Vec::new(), change, Consent::default(), true)
}
/// Polls until nothing changes, and every notice on the way.
fn polls(s: &mut Session) -> Vec<SyncNotice> {
    let mut told = Vec::new();
    for _ in 0..5 {
        if let Some(n) = s.poll_sync().and_then(|e| e.notice) {
            told.push(n);
        }
    }
    told
}
/// The accept of the server's key file as the flow runs it (spec §7.15):
/// its checks, a Reauth touched with key `number`, the open, the gate
/// answered by `gate`, the preview (S-KEYSYNC-ON answered yes) and the
/// write.
fn take_server(
    s: &mut Session,
    codes: &mut Codes,
    keys: &Keys,
    number: u8,
    gate: impl FnOnce(&AdoptCheck, &Session) -> GatePass,
) -> Result<Adopted> {
    let (f, seq) = s.server_key_file().unwrap();
    let check = s.adopt_check(&f, Source::Server { seq })?;
    let r = reauth(s, OLD, codes, keys, number)?;
    let t = touch_other(&f, keys, number);
    let opened = s.adopt_open_with(&r, &f, None, Some(&t))?;
    let pass = gate(&check, s);
    let plan = s.adopt_preview_with(&r, &f, opened, &check, pass, ForkOption::Both)?;
    let acks = acks(plan.preview(), ForkOption::Both);
    s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
}
/// The vault outgoing after an edit: none while the key channel holds it.
fn uploads(pc: &Pc, s: &mut Session, title: &str) -> bool {
    let _ = fs::remove_file(dir(pc).join(OUTGOING));
    s.put(None, entry(title)).unwrap();
    dir(pc).join(OUTGOING).exists()
}

/// Spec §7.9-§7.16 and §14.10-1, -3, -12: key-file sync turned on on A
/// (no view: S-KEYSYNC-ASKING; `on.0` and a PUT on nothing), landed and
/// settled; B takes A's "on" only through G1, held meanwhile (GatePending:
/// no upload, no key change); A's password change is uploaded over its own
/// older file (Stale, row 6) and B takes it with no gate (KeyFileReady);
/// A's off deletes `kreq` and `kview` first, sends CUT(L), and its answer
/// is told once; B then holds (KeySyncGone) until it re-uploads.
#[test]
fn key_file_sync_goes_on_and_off_between_two_pcs() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &mut codes, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    // goyo-sync has not looked at the server yet.
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn).err(),
        Some(KEYSYNC_ASKING)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let before = header(&a);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    let on = header(&a);
    assert_eq!(on.magic, Magic::Ks01);
    assert_eq!(on.epoch, before.epoch + 1);
    // The same data key: kind 6 rotates nothing.
    assert_eq!(on.key_ids, before.key_ids);
    assert_eq!(ks_of(&a, &id), Ks::On(0));
    let bytes = kreq(&a).unwrap();
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!((req.op, req.base, req.floor), (KeyOp::Put, 0, 0));
    assert_eq!(req.payload, fs::read(a.key()).unwrap());
    // Landed: the view shows A's own file, `on.0` is dropped, `kreq` goes.
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(ks_of(&a, &id), Ks::None);
    assert!(kreq(&a).is_none());
    assert_eq!(sa.server_class(), Some(KeyClass::Equal));

    // B: another PC's "on" is a policy change, behind G1.
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
    assert_eq!(
        sb.server_class(),
        Some(KeyClass::Successor {
            carry: false,
            gate: Some(GateKind::G1)
        })
    );
    let gate = b.lines(&id).gate.unwrap();
    assert_eq!((gate.epoch, gate.state), (on.epoch, GateState::Pending));
    // I-S9: nothing goes up and no key change but the off runs.
    assert!(!uploads(&b, &mut sb, "edited on b"));
    assert_eq!(sb.change_gate(&password(NEW)).err(), Some(GATE_PENDING));
    assert!(kreq(&b).is_none());
    // A wrong code takes nothing; A's code takes the file.
    assert_eq!(
        take_server(&mut sb, &mut codes, &keys, 2, code(Code([7; 8]))).err(),
        Some(GATE_CODE_WRONG)
    );
    let shown = code_of(&sa);
    take_server(&mut sb, &mut codes, &keys, 2, code(shown)).unwrap();
    assert_eq!(header(&b).state(), on.state());
    assert!(b.lines(&id).gate.is_none());
    assert_eq!(ks_of(&b, &id), Ks::None);
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    assert!(kreq(&b).is_none());
    assert!(uploads(&b, &mut sb, "uploaded from b"));

    // A's password change: a GOYOKS01 result, uploaded over the server's
    // file of A's own history (Stale), with that record as its base.
    a.here();
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, password(NEW)),
        Ok(Rekeyed::Done)
    );
    let changed = header(&a);
    assert_eq!(sa.server_class(), Some(KeyClass::Stale));
    let bytes = kreq(&a).unwrap();
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!(
        (req.op, req.base, req.floor, req.epoch()),
        (KeyOp::Put, 1, on.epoch, changed.epoch)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    assert!(kreq(&a).is_none());
    // B: no gate for a password change; it is told and gates key changes.
    server.pass(&b, &id);
    let told = polls(&mut sb);
    assert!(
        told.contains(&SyncNotice::KeyFileReady {
            epoch: changed.epoch
        }),
        "{told:?}"
    );
    assert_eq!(
        sb.change_gate(&password(NEW)),
        Ok(Some(super::super::super::super::Gate::KeyFileReady))
    );
    assert_eq!(
        super::super::super::super::Gate::KeyFileReady.question(),
        KEYFILE_READY
    );
    // The accept: E5 would refuse a password change that kept the
    // password, so the new password opens it (S-NEWPASS-OTHER).
    let (f, seq) = sb.server_key_file().unwrap();
    let check = sb.adopt_check(&f, Source::Server { seq }).unwrap();
    assert_eq!(check.class, AdoptClass::Successor);
    let r = reauth(&mut sb, OLD, &mut codes, &keys, 2).unwrap();
    let t = touch_other(&f, &keys, 2);
    let opened = sb.adopt_open_with(&r, &f, Some(NEW), Some(&t)).unwrap();
    let plan = sb
        .adopt_preview_with(
            &r,
            &f,
            opened,
            &check,
            GatePass::none(&check),
            ForkOption::Both,
        )
        .unwrap();
    assert!(!plan.preview().keysync_on && plan.preview().keysync_off.is_none());
    let acks = acks(plan.preview(), ForkOption::Both);
    sb.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
        .unwrap();
    assert_eq!(header(&b).state(), changed.state());
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));

    // A's off: `kreq` and `kview` go before the rotation, `off.1` is
    // recorded, the CUT names the record A saw.
    a.here();
    assert_eq!(
        rekey_new(&mut sa, &mut codes, &keys, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    let off = header(&a);
    assert_eq!(off.magic, Magic::Kh01);
    assert_ne!(off.key_ids[0], changed.key_ids[0], "the off rotates");
    assert_eq!(ks_of(&a, &id), Ks::Off(2));
    assert!(kview(&a, &id).is_none());
    assert_eq!(kreq(&a).unwrap(), render_key_request(&KeyRequest::cut(2)));
    // Its answer settles the off: the deletion is told once, with the
    // admin advice (A's key file is no longer GOYOKS01).
    server.pass(&a, &id);
    let told = polls(&mut sa);
    let deleted = SyncNotice::KeySyncDeleted {
        seq: 3,
        admin: true,
    };
    assert_eq!(
        told.iter().filter(|n| **n == deleted).count(),
        1,
        "{told:?}"
    );
    assert_eq!(ks_of(&a, &id), Ks::None);
    assert!(kreq(&a).is_none());
    // No key payload left on the server's top.
    assert_eq!(server.records.last().unwrap().0, RecordKind::Cut);
    // B: the cut on a GOYOKS01 PC holds its vault channel (KeySyncGone).
    server.pass(&b, &id);
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::KeySyncGone), "{told:?}");
    assert!(sb.key_sync_view().unwrap().gone);
    assert!(!uploads(&b, &mut sb, "held on b"));
    assert!(kreq(&b).is_none(), "no PC re-uploads by itself");
    set_kdf_profile(KdfProfile::Real);
}
/// `change` with A's new password (after its password change).
fn rekey_new(s: &mut Session, codes: &mut Codes, keys: &Keys, change: Change) -> Result<Rekeyed> {
    let r = reauth(s, NEW, codes, keys, 1)?;
    s.rekey(r, Vec::new(), change, Consent::default(), true)
}

/// Spec §7.11 (§14.10-3, the request table and gate 1): a GOYOKH01
/// session deletes any `kreq`, planted PUT or CUT (row 2); on a GOYOKS01
/// session a line-1 view leaves a PUT as it is and deletes a CUT (row 4);
/// an Equal top deletes it (row 5); a cut on top with no consented "on"
/// writes nothing (row 9).
#[test]
fn the_request_table_writes_only_what_it_derives() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    let planted_cut = render_key_request(&KeyRequest::cut(9));
    fs::write(dir(&a).join(KEY_REQUEST), &planted_cut).unwrap();
    polls(&mut sa);
    assert!(kreq(&a).is_none(), "row 2");
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    let put = kreq(&a).unwrap();
    server.pass(&a, &id);
    polls(&mut sa);
    assert!(kreq(&a).is_none(), "row 5");
    // A view from a line that serves no key ops (BAD_REQUEST).
    let mut view = kview(&a, &id).unwrap();
    view.line = 1;
    fs::write(dir(&a).join(KEY_VIEW), render_key_view(&view)).unwrap();
    fs::write(dir(&a).join(KEY_REQUEST), &put).unwrap();
    let told = polls(&mut sa);
    assert!(told.contains(&SyncNotice::NoKeySync), "{told:?}");
    assert_eq!(kreq(&a).unwrap(), put, "row 4 leaves a PUT");
    fs::write(dir(&a).join(KEY_REQUEST), &planted_cut).unwrap();
    polls(&mut sa);
    assert!(kreq(&a).is_none(), "row 4 deletes a CUT");
    // A cut on top (another PC's off): nothing is written, and the hold.
    server.records.push((RecordKind::Cut, 2, 0, Vec::new()));
    server.pass(&a, &id);
    polls(&mut sa);
    assert!(kreq(&a).is_none(), "row 9");
    assert!(sa.key_sync_view().unwrap().gone);
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.16 step 2 and §7.11 (S6R1 #8, S6R2 #7): an off with no view
/// records `off.?` and requests nothing; the first line-0 view pins it to
/// the record it shows, and the CUT goes; a consented "on" is refused
/// while the off is pending, and lands once its CUT is answered, above the
/// cut's floor.
#[test]
fn an_off_with_no_view_waits_for_its_pin() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a);
    // The view is gone (an antivirus, a reset folder): no view at P1.
    fs::remove_file(dir(&a).join(KEY_VIEW)).unwrap();
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    assert_eq!(ks_of(&a, &id), Ks::OffUnknown);
    assert!(kreq(&a).is_none());
    // Turning it on again waits for the off.
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn).err(),
        Some(KEYSYNC_OFF_PENDING)
    );
    // The first view pins it to the record on top: here a top the server
    // could not read, served as a damaged cut (spec §7.13), whose record
    // the CUT then ends.
    let damaged = KeyView {
        seq: 2,
        record: render_record_header(RecordKind::Cut, true, 2, on.epoch).to_vec(),
        ..KeyView::default()
    };
    fs::write(dir(&a).join(KEY_VIEW), render_key_view(&damaged)).unwrap();
    polls(&mut sa);
    assert_eq!(ks_of(&a, &id), Ks::Off(2));
    assert_eq!(kreq(&a).unwrap(), render_key_request(&KeyRequest::cut(2)));
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(ks_of(&a, &id), Ks::None);
    assert!(kreq(&a).is_none());
    // On again: above the cut's floor (the ended record's epoch).
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    let again = header(&a);
    assert!(again.epoch > on.epoch);
    let bytes = kreq(&a).unwrap();
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!((req.op, req.base, req.floor), (KeyOp::Put, 2, on.epoch));
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(sa.server_class(), Some(KeyClass::Equal));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.5 W2 and §7.9 (§14.10-16): a cut's floor counts for a
/// GOYOKS01 result only within `EPOCH_SILENT` of the key state; a larger
/// one (a planted view) fails KeySyncOn's precondition with the admin text.
#[test]
fn a_cut_floor_counts_only_within_its_bound() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let epoch = sa.key_state().epoch;
    let plant = |floor: u64| {
        let view = KeyView {
            seq: 1,
            record: render_record_header(RecordKind::Cut, false, 1, floor).to_vec(),
            ..KeyView::default()
        };
        fs::write(dir(&a).join(KEY_VIEW), render_key_view(&view)).unwrap();
    };
    plant(epoch + EPOCH_SILENT + 1);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn).err(),
        Some(KEYSYNC_FLOOR)
    );
    plant(epoch + EPOCH_SILENT);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    assert_eq!(header(&a).epoch, epoch + EPOCH_SILENT + 1);
    let bytes = kreq(&a).unwrap();
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!((req.base, req.floor), (1, epoch + EPOCH_SILENT));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.14 KeyFork and §7.13's CAS (§14.10-7, -19): two PCs change the
/// password apart; the second PUT meets the first's record (CONFLICT), which
/// is a fork for it: its vault and key uploads stop, key changes ask the
/// fork's question, and turning key-file sync off is still allowed.
#[test]
fn two_changes_apart_fork_on_the_server() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &mut codes, &keys, 2);
    let mut server = KeyServer::default();
    a.here();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
    polls(&mut sb);
    let shown = code_of(&sa);
    take_server(&mut sb, &mut codes, &keys, 2, code(shown)).unwrap();
    polls(&mut sb);
    // Both change the password from the same state.
    a.here();
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, password(NEW)),
        Ok(Rekeyed::Done)
    );
    b.here();
    assert_eq!(
        rekey(&mut sb, &mut codes, &keys, 2, password(THIRD)),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    server.pass(&b, &id);
    assert_eq!(kview(&b, &id).unwrap().outcome, KeyOutcome::Conflict);
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::KeyFork), "{told:?}");
    assert_eq!(sb.server_class(), Some(KeyClass::KeyFork));
    assert!(!uploads(&b, &mut sb, "held by the fork"));
    assert_eq!(
        sb.rekey_gate(&password(NEW)),
        Some(super::super::super::super::Gate::KeyFork)
    );
    // The fork's way out on this PC: turn key-file sync off.
    let r = reauth(&mut sb, THIRD, &mut codes, &keys, 2).unwrap();
    assert_eq!(
        sb.rekey(r, Vec::new(), Change::KeySyncOff, Consent::default(), true),
        Ok(Rekeyed::Done)
    );
    assert_eq!(ks_of(&b, &id), Ks::Off(2));
    set_kdf_profile(KdfProfile::Real);
}

/// A and B both GOYOKS01 at A's "on" (B took it with A's code).
#[allow(clippy::type_complexity)]
fn both_on(n: u8) -> (Pc, Session, Pc, Session, Codes, Keys, KeyServer, [u8; 16]) {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, n, false, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &mut codes, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
    polls(&mut sb);
    let shown = code_of(&sa);
    take_server(&mut sb, &mut codes, &keys, 2, code(shown)).unwrap();
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    (a, sa, b, sb, codes, keys, server, id)
}
fn has(s: &Session, secret: &str) -> bool {
    secrets(s).iter().any(|t| t == secret)
}

/// Spec I-S9, §7.20 and §2.27 row 37: a gated candidate that goyo-sync
/// fetched while this PC was locked holds the vault copy that came with it
/// already at the unlock, before any poll stored its gate line.
#[test]
fn a_gated_candidate_holds_the_copy_from_the_unlock_on() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &mut codes, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    // A copy under the state B holds (the head before A's own vault lands).
    assert!(uploads(&a, &mut sa, "from a"));
    let out = fs::read(dir(&a).join(OUTGOING)).unwrap();
    let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    // goyo-sync on B while B is locked: A's "on" (G1) and the copy.
    server.pass(&b, &id);
    let incoming = syncfile::render_incoming(1, copy).unwrap();
    syncfile::replace_file(&dir(&b).join(syncfile::INCOMING), &incoming).unwrap();
    let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
    assert!(b.lines(&id).gate.is_none(), "no line stored yet");
    assert!(!has(&sb, "from a"), "merged at the unlock");
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
    assert_eq!(b.lines(&id).gate.unwrap().state, GateState::Pending);
    assert!(!has(&sb, "from a"), "merged while the gate waits");
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.15a (S-GATE-G2FAIL, then the server channel): a wrong pick of
/// a USB copy of a removal leaves a `none` line naming it; when the same
/// file then arrives from the server it is stored as pending (G2 kept off),
/// so it holds merges and uploads and is told.
#[test]
fn a_failed_pick_then_the_same_file_from_the_server_is_pending() {
    let (a, mut sa, b, mut sb, mut codes, keys, mut server, id) = both_on(3);
    a.here();
    remove_lost(&mut sa, &mut codes, &keys, 3, 1);
    let removal = fs::read(a.key()).unwrap();
    b.here();
    let taken = take(
        &mut sb,
        &mut codes,
        &keys,
        (OLD, 2),
        &removal,
        ForkOption::Both,
        pick(&[2]),
        Consent::default(),
    );
    assert_eq!(taken.err(), Some(GATE_G2FAIL));
    let line = b.lines(&id).gate.unwrap();
    assert_eq!((line.state, line.g2), (GateState::None, false));
    a.here();
    server.pass(&a, &id);
    polls(&mut sa);
    b.here();
    server.pass(&b, &id);
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
    let line = b.lines(&id).gate.unwrap();
    assert_eq!(
        (line.epoch, line.state, line.g2),
        (header(&a).epoch, GateState::Pending, false)
    );
    assert!(!uploads(&b, &mut sb, "held on b"));
    set_kdf_profile(KdfProfile::Real);
}

/// Two PCs (three keys, key 3 retired on both) turn key-file sync on
/// from one state: A lands, B's PUT meets A's record (CONFLICT) and B is
/// KeyFork-held.
#[allow(clippy::type_complexity)]
fn two_ons() -> (Pc, Session, Pc, Session, Codes, Keys, KeyServer, [u8; 16]) {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 3, false, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &mut codes, &keys, 2);
    a.here();
    let r = reauth(&mut sa, OLD, &mut codes, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            remove(&[3], None, None),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    let retired = fs::read(a.key()).unwrap();
    let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
    take(
        &mut sb,
        &mut codes,
        &keys,
        (OLD, 2),
        &retired,
        ForkOption::Both,
        pick(&[3]),
        Consent::default(),
    )
    .unwrap();
    let mut server = KeyServer::default();
    server.pass(&b, &id);
    polls(&mut sb);
    a.here();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    b.here();
    assert_eq!(
        rekey(&mut sb, &mut codes, &keys, 2, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    a.here();
    server.pass(&a, &id);
    b.here();
    server.pass(&b, &id);
    assert_eq!(kview(&b, &id).unwrap().outcome, KeyOutcome::Conflict);
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::KeyFork));
    assert!(!uploads(&b, &mut sb, "held by the fork"));
    (a, sa, b, sb, codes, keys, server, id)
}
/// After the join: B's union lands on the server's record and nothing
/// holds B.
fn joined(b: &Pc, sb: &mut Session, server: &mut KeyServer, id: &[u8; 16]) {
    assert_eq!(header(b).kind as u8, 9);
    assert!(!sb.prune_offered(), "a union that removed nothing");
    polls(sb);
    server.pass(b, id);
    polls(sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    assert!(uploads(b, sb, "joined"));
}

/// Spec §7.14 KeyFork, §7.15 and §7.19 (walkthrough 33 (d)): the loser of
/// two KeySyncOn at once joins by the accept of the server's file (a
/// union above both, uploaded on its record), and S-PRUNE is not asked
/// for a union that removed nothing, although the vault removed a key
/// before.
#[test]
fn two_ons_at_once_are_joined_and_ask_no_prune() {
    let (_a, _sa, b, mut sb, mut codes, keys, mut server, id) = two_ons();
    take_server(&mut sb, &mut codes, &keys, 2, none).unwrap();
    joined(&b, &mut sb, &mut server, &id);
    set_kdf_profile(KdfProfile::Real);
}

/// The same join from a USB copy of the server's file (KeyFork-SK's route,
/// "새 열쇠 파일 받기"): not Contained, a union above both.
#[test]
fn two_ons_at_once_are_joined_by_usb_too() {
    let (a, _sa, b, mut sb, mut codes, keys, mut server, id) = two_ons();
    let winner = fs::read(a.key()).unwrap();
    take(
        &mut sb,
        &mut codes,
        &keys,
        (OLD, 2),
        &winner,
        ForkOption::Both,
        none,
        Consent::default(),
    )
    .unwrap();
    joined(&b, &mut sb, &mut server, &id);
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.11's self-heal (S6R2 #6, walkthrough 33 (i), a stale cut at
/// the off): an off made while `kview` showed a stale cut records `-`; when
/// the next fetch shows this PC's own record still on top, it is ended.
#[test]
fn the_self_heal_ends_this_pcs_own_record() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a);
    // A sync folder restored from a backup: a cut on top.
    let stale = KeyView {
        seq: 2,
        record: render_record_header(RecordKind::Cut, false, 2, on.epoch).to_vec(),
        ..KeyView::default()
    };
    fs::write(dir(&a).join(KEY_VIEW), render_key_view(&stale)).unwrap();
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    assert_eq!(ks_of(&a, &id), Ks::None);
    assert!(kreq(&a).is_none());
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(ks_of(&a, &id), Ks::Off(1));
    assert_eq!(kreq(&a).unwrap(), render_key_request(&KeyRequest::cut(1)));
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(ks_of(&a, &id), Ks::None);
    assert_eq!(server.records.last().unwrap().0, RecordKind::Cut);
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.16 (S6R1 #2, walkthrough 33 (h)): an off taken while a server
/// candidate waits for its gate clears that gate (`clears=g`), so once its
/// CUT lands nothing holds this PC.
#[test]
fn an_off_from_gate_pending_clears_the_gate() {
    let (a, mut sa, b, mut sb, mut codes, keys, mut server, id) = both_on(3);
    a.here();
    remove_lost(&mut sa, &mut codes, &keys, 3, 1);
    server.pass(&a, &id);
    polls(&mut sa);
    b.here();
    server.pass(&b, &id);
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
    assert_eq!(
        rekey(&mut sb, &mut codes, &keys, 2, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    assert!(
        b.lines(&id)
            .gate
            .is_none_or(|g| g.state != GateState::Pending)
    );
    assert!(!sb.gate_waits());
    server.pass(&b, &id);
    polls(&mut sb);
    assert_eq!(server.records.last().unwrap().0, RecordKind::Cut);
    assert!(uploads(&b, &mut sb, "after the off"));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.11 `key_req_due` (S6R1 #17): a `kreq` write that failed is
/// retried at every poll until it succeeds, although nothing else changed
/// (here a folder planted under its name, then removed).
#[test]
fn a_failed_kreq_write_is_retried_at_the_next_poll() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    let blocker = dir(&a).join(KEY_REQUEST);
    fs::remove_file(&blocker).unwrap();
    fs::create_dir(&blocker).unwrap();
    polls(&mut sa);
    assert!(kreq(&a).is_none());
    fs::remove_dir(&blocker).unwrap();
    polls(&mut sa);
    let bytes = kreq(&a).expect("written at the next poll");
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!((req.op, req.base), (KeyOp::Put, 0));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.16 "Which writes set `ks`" rule 3 (S6R1 #7, walkthrough 12): a
/// lagging PC that takes another PC's off by USB while that PC's later
/// re-enable is on the server records `-`, so it never ends that
/// deliberate re-enable.
#[test]
fn a_lagging_join_leaves_another_pcs_re_enable() {
    let (a, mut sa, b, mut sb, mut codes, keys, mut server, id) = both_on(2);
    a.here();
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    let off = fs::read(a.key()).unwrap();
    let off_code = code_of(&sa);
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let top = server.top();
    b.here();
    server.pass(&b, &id);
    polls(&mut sb);
    take(
        &mut sb,
        &mut codes,
        &keys,
        (OLD, 2),
        &off,
        ForkOption::Both,
        code(off_code),
        Consent::default(),
    )
    .unwrap();
    assert_eq!(header(&b).magic, Magic::Kh01);
    assert_eq!(ks_of(&b, &id), Ks::None);
    polls(&mut sb);
    assert!(kreq(&b).is_none());
    server.pass(&b, &id);
    assert_eq!(server.top(), top);
    assert_eq!(server.records.last().unwrap().0, RecordKind::Key);
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.5 S0 `merged` (S6R2 #3, walkthrough 14 (b)): a GOYOKH01 PC
/// whose gate on another PC's "on" waits takes that PC's off by USB; the
/// write clears the gate and names the candidate as merged, so the
/// candidate is Stale there, not a fork, until the CUT this PC sends lands.
#[test]
fn a_join_that_clears_a_gate_names_its_candidate() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &mut codes, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a).state();
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
    polls(&mut sb);
    assert_eq!(b.lines(&id).gate.unwrap().state, GateState::Pending);
    // A turns it off; its CUT has not gone out.
    a.here();
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    let off = fs::read(a.key()).unwrap();
    b.here();
    take(
        &mut sb,
        &mut codes,
        &keys,
        (OLD, 2),
        &off,
        ForkOption::Both,
        none,
        Consent::default(),
    )
    .unwrap();
    let merged = b.lines(&id).vault.unwrap().merged;
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&on.tag[..8]);
    assert!(merged.contains(&(on.epoch, prefix)), "{merged:?}");
    assert!(!sb.gate_waits());
    // Judged at S4 against the state just written: no fork, no hold.
    assert_eq!(sb.server_class(), Some(KeyClass::Stale));
    assert!(uploads(&b, &mut sb, "after the join"));
    polls(&mut sb);
    assert_eq!(ks_of(&b, &id), Ks::Off(1));
    assert_eq!(kreq(&b).unwrap(), render_key_request(&KeyRequest::cut(1)));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.15a: a pending gate whose candidate is no longer on the server
/// (an admin's `rm -r k/`, a server restored from a backup) still holds,
/// is shown, and [받지 않기…] ends it on a GOYOKH01 PC, which has no off.
#[test]
fn a_pending_gate_without_its_candidate_can_be_dropped() {
    let a = Pc::new();
    let (mut sa, mut codes, keys) = create_with(&a, 2, false, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &mut codes, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &mut codes, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
    polls(&mut sb);
    server.records.clear();
    server.pass(&b, &id);
    polls(&mut sb);
    let view = sb.key_sync_view().unwrap();
    assert!(view.waiting.is_none());
    assert_eq!(view.stale_gate, Some(on.epoch));
    assert!(!uploads(&b, &mut sb, "held by the line"));
    sb.drop_gate().unwrap();
    assert_eq!(sb.key_sync_view().unwrap().stale_gate, None);
    assert!(uploads(&b, &mut sb, "dropped"));
    set_kdf_profile(KdfProfile::Real);
}
