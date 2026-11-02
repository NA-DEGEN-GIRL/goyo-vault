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
        AUTO_NOT_SYNCED, KeyChange, NOT_TRUSTED, SyncNotice,
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
fn synced_pc(a: &Pc, keys: &Keys, number: u8) -> Pc {
    let b = second_pc(a, keys, number);
    fs::create_dir(dir(&b)).unwrap();
    status(&b);
    b
}
/// A fresh helper status with `features=keys` in `pc`'s sync folder.
fn status(pc: &Pc) {
    let now = crate::clock::now().unwrap();
    let bytes = syncfile::render_status(now, now, syncfile::SyncState::Ok);
    syncfile::replace_file(&dir(pc).join(syncfile::STATUS), &bytes).unwrap();
}
/// `change` with a Reauth touched with key `number`, any gate answered.
fn rekey(s: &mut Session, keys: &Keys, number: u8, change: Change) -> Result<Rekeyed> {
    let r = reauth(s, OLD, keys, number)?;
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
    keys: &Keys,
    number: u8,
    gate: impl FnOnce(&AdoptCheck, &Session) -> GatePass,
) -> Result<Adopted> {
    let (f, seq) = s.server_key_file().unwrap();
    let check = s.adopt_check(&f, Source::Server { seq })?;
    let r = reauth(s, OLD, keys, number)?;
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    // goyo-sync has not looked at the server yet.
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn).err(),
        Some(KEYSYNC_ASKING)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let before = header(&a);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
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
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
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
        take_server(&mut sb, &keys, 2, code(Code([7; 8]))).err(),
        Some(GATE_CODE_WRONG)
    );
    let shown = code_of(&sa);
    take_server(&mut sb, &keys, 2, code(shown)).unwrap();
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
    assert_eq!(rekey(&mut sa, &keys, 1, password(NEW)), Ok(Rekeyed::Done));
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
    let r = reauth(&mut sb, OLD, &keys, 2).unwrap();
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
        rekey_new(&mut sa, &keys, Change::KeySyncOff),
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
fn rekey_new(s: &mut Session, keys: &Keys, change: Change) -> Result<Rekeyed> {
    let r = reauth(s, NEW, keys, 1)?;
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    let planted_cut = render_key_request(&KeyRequest::cut(9));
    fs::write(dir(&a).join(KEY_REQUEST), &planted_cut).unwrap();
    polls(&mut sa);
    assert!(kreq(&a).is_none(), "row 2");
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a);
    // The view is gone (an antivirus, a reset folder): no view at P1.
    fs::remove_file(dir(&a).join(KEY_VIEW)).unwrap();
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    assert_eq!(ks_of(&a, &id), Ks::OffUnknown);
    assert!(kreq(&a).is_none());
    // Turning it on again waits for the off.
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn).err(),
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
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
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
        rekey(&mut sa, &keys, 1, Change::KeySyncOn).err(),
        Some(KEYSYNC_FLOOR)
    );
    plant(epoch + EPOCH_SILENT);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    let mut server = KeyServer::default();
    a.here();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    polls(&mut sb);
    let shown = code_of(&sa);
    take_server(&mut sb, &keys, 2, code(shown)).unwrap();
    polls(&mut sb);
    // Both change the password from the same state.
    a.here();
    assert_eq!(rekey(&mut sa, &keys, 1, password(NEW)), Ok(Rekeyed::Done));
    b.here();
    assert_eq!(rekey(&mut sb, &keys, 2, password(THIRD)), Ok(Rekeyed::Done));
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
    let r = reauth(&mut sb, THIRD, &keys, 2).unwrap();
    assert_eq!(
        sb.rekey(r, Vec::new(), Change::KeySyncOff, Consent::default(), true),
        Ok(Rekeyed::Done)
    );
    assert_eq!(ks_of(&b, &id), Ks::Off(2));
    set_kdf_profile(KdfProfile::Real);
}

/// A and B both GOYOKS01 at A's "on" (B took it with A's code).
#[allow(clippy::type_complexity)]
fn both_on(n: u8) -> (Pc, Session, Pc, Session, Keys, KeyServer, [u8; 16]) {
    let a = Pc::new();
    let (mut sa, keys) = create_with(&a, n, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    polls(&mut sb);
    let shown = code_of(&sa);
    take_server(&mut sb, &keys, 2, code(shown)).unwrap();
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    (a, sa, b, sb, keys, server, id)
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    // A copy under the state B holds (the head before A's own vault lands).
    assert!(uploads(&a, &mut sa, "from a"));
    let out = fs::read(dir(&a).join(OUTGOING)).unwrap();
    let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    // goyo-sync on B while B is locked: A's "on" (G1) and the copy.
    server.pass(&b, &id);
    let incoming = syncfile::render_incoming(1, copy).unwrap();
    syncfile::replace_file(&dir(&b).join(syncfile::INCOMING), &incoming).unwrap();
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
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
    let (a, mut sa, b, mut sb, keys, mut server, id) = both_on(3);
    a.here();
    remove_lost(&mut sa, &keys, 3, 1);
    let removal = fs::read(a.key()).unwrap();
    b.here();
    let taken = take(
        &mut sb,
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
fn two_ons() -> (Pc, Session, Pc, Session, Keys, KeyServer, [u8; 16]) {
    let a = Pc::new();
    let (mut sa, keys) = create_with(&a, 3, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
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
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    take(
        &mut sb,
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
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    b.here();
    assert_eq!(
        rekey(&mut sb, &keys, 2, Change::KeySyncOn),
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
    (a, sa, b, sb, keys, server, id)
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
    let (_a, _sa, b, mut sb, keys, mut server, id) = two_ons();
    take_server(&mut sb, &keys, 2, none).unwrap();
    joined(&b, &mut sb, &mut server, &id);
    set_kdf_profile(KdfProfile::Real);
}

/// The same join from a USB copy of the server's file (KeyFork-SK's route,
/// "새 열쇠 파일 받기"): not Contained, a union above both.
#[test]
fn two_ons_at_once_are_joined_by_usb_too() {
    let (a, _sa, b, mut sb, keys, mut server, id) = two_ons();
    let winner = fs::read(a.key()).unwrap();
    take(
        &mut sb,
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
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
        rekey(&mut sa, &keys, 1, Change::KeySyncOff),
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
    let (a, mut sa, b, mut sb, keys, mut server, id) = both_on(3);
    a.here();
    remove_lost(&mut sa, &keys, 3, 1);
    server.pass(&a, &id);
    polls(&mut sa);
    b.here();
    server.pass(&b, &id);
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
    assert_eq!(
        rekey(&mut sb, &keys, 2, Change::KeySyncOff),
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
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
    let (a, mut sa, b, mut sb, keys, mut server, id) = both_on(2);
    a.here();
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    let off = fs::read(a.key()).unwrap();
    let off_code = code_of(&sa);
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a).state();
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    polls(&mut sb);
    assert_eq!(b.lines(&id).gate.unwrap().state, GateState::Pending);
    // A turns it off; its CUT has not gone out.
    a.here();
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOff),
        Ok(Rekeyed::Done)
    );
    let off = fs::read(a.key()).unwrap();
    b.here();
    take(
        &mut sb,
        &keys,
        (OLD, 2),
        &off,
        ForkOption::Both,
        none,
        Consent::default(),
    )
    .unwrap();
    let merged = b.lines(&id).vault.unwrap().merged;
    assert!(merged.contains(&(on.epoch, on.tag)), "{merged:?}");
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
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
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

/// A login of `pc` with `password` and a touch of key `number` that hands
/// back what the login flow gets (spec §5.3): the session and its
/// `UnlockProof`, or the failed-unlock entry; and the touch.
#[allow(clippy::type_complexity)]
fn login_proved(
    pc: &Pc,
    password: &str,
    keys: &Keys,
    number: u8,
) -> (
    std::result::Result<(Session, crate::vault::UnlockProof), crate::vault::Failed>,
    Touch,
) {
    pc.here();
    let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
    let t = keys
        .touch(number, &prepared.unlock_request(0).unwrap())
        .unwrap();
    let result = Session::login_proved(prepared, password, None, &t);
    (result, t)
}
/// A and B both GOYOKS01 (B took A's "on" with its code), and A's password
/// changed to NEW on top, landed and fetched by B's helper.
#[allow(clippy::type_complexity)]
fn new_password_waiting() -> (Pc, Session, Pc, Keys, KeyServer, [u8; 16]) {
    let a = Pc::new();
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    polls(&mut sb);
    take_server(&mut sb, &keys, 2, code(code_of(&sa))).unwrap();
    polls(&mut sb);
    drop(sb);
    a.here();
    assert_eq!(rekey(&mut sa, &keys, 1, password(NEW)), Ok(Rekeyed::Done));
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    (a, sa, b, keys, server, id)
}

/// Spec §5.2 step 9(b), §5.3, §7.15 at login (§14.10 walkthrough 2): the
/// server's successor is taken inside the login, with the unlock's touch
/// and the login's own Reauth, with no second password; the proof serves its own session only and only the snapshot the login read.
#[test]
fn the_server_key_file_is_taken_at_login_with_the_unlocks_touch() {
    let (a, _sa, b, keys, _server, _id) = new_password_waiting();
    let changed = header(&a);
    let (result, t) = login_proved(&b, OLD, &keys, 2);
    let (mut sb, proof) = result.ok().unwrap();
    let (f, seq) = sb.login_candidate(&proof).unwrap();
    let check = sb.adopt_check(&f, Source::Server { seq }).unwrap();
    assert_eq!(
        (check.class, check.keys.gate),
        (AdoptClass::Successor, None)
    );
    let r = sb.reauth_from_unlock(proof, &t).unwrap();
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
    let acks = acks(plan.preview(), ForkOption::Both);
    sb.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
        .unwrap();
    assert_eq!(header(&b).state(), changed.state());
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.2 second entry point, §7.15 step 4 (§14.10 walkthrough 2, the
/// new password at B): the unlock with the new password fails on B's own
/// key file and returns the entry; the server's file opens with it and the
/// same touch, chains under B's data key, and is installed before the
/// session is returned. A password that opens neither file installs
/// nothing.
#[test]
fn the_new_password_at_login_takes_the_server_key_file() {
    let (a, _sa, b, keys, _server, _id) = new_password_waiting();
    let changed = header(&a);
    let before = fs::read(b.key()).unwrap();
    // A proof serves its own session only (spec §5.3).
    let (result, _) = login_proved(&b, OLD, &keys, 2);
    let (s1, stale) = result.ok().unwrap();
    drop(s1);
    let (result, t) = login_proved(&b, OLD, &keys, 2);
    let (mut s2, _) = result.ok().unwrap();
    assert_eq!(
        s2.reauth_from_unlock(stale, &t).err(),
        Some(crate::vault::rotate::REAUTH_STALE)
    );
    drop(s2);
    // Neither file opens.
    let (result, t) = login_proved(&b, "wrong-password-1", &keys, 2);
    let failed = result.err().unwrap();
    assert_eq!(failed.error, AUTH_ERROR);
    let mut entry = failed.entry.unwrap();
    assert!(entry.gate().is_none() && entry.own_tried());
    assert_eq!(
        Session::login_via_server(&mut entry, &t, None, false).err(),
        Some(AUTH_ERROR)
    );
    assert_eq!(fs::read(b.key()).unwrap(), before);
    // The new password.
    let (result, t) = login_proved(&b, NEW, &keys, 2);
    let mut entry = result.err().unwrap().entry.unwrap();
    let (mut s, adopted) = Session::login_via_server(&mut entry, &t, None, false).unwrap();
    assert_eq!(adopted.state, changed.state());
    // That entry's Reauth serves its accept only: no key change takes it.
    let r = s.reauth_server(NEW, &t).unwrap();
    assert_eq!(
        s.rekey(
            r,
            Vec::new(),
            password("another synthetic password"),
            Consent::default(),
            true
        )
        .err(),
        Some(crate::vault::rotate::REAUTH_STALE)
    );
    assert_eq!(adopted.password, crate::vault::PassInForce::Other);
    assert_eq!(s.key_state(), changed.state());
    assert_eq!(header(&b).state(), changed.state());
    assert!(b.lines(&s.id).vault.unwrap().state.flags.t);
    assert!(has(&s, "one"));
    drop(s);
    let s = open(&b, NEW, &keys, 2).unwrap();
    assert!(!s.tofu() && !s.gate_pending());
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.2, §7.15a (S6-1 #4, round 3 findings 7 and 27): on the failed-
/// unlock entry the gate is asked before the open and judged only once the
/// server's file opened, chained and the local vault file read: a pick made
/// with a password that opens nothing is discarded unseen (G2 stays on); a
/// wrong pick after the open turns G2 off and installs nothing; the next
/// login asks G1, and the other PC's code takes the removal.
#[test]
fn the_failed_unlock_entry_judges_its_gate_after_the_open() {
    let (a, mut sa, b, sb, keys, mut server, id) = both_on(3);
    drop(sb);
    a.here();
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    let change = remove(&[3], Some(lost()), Some(NEW));
    assert_eq!(
        sa.rekey(r, Vec::new(), change, Consent::default(), false),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let before = fs::read(b.key()).unwrap();
    let three = credhash(&parse(&before).unwrap(), 3);
    let one = credhash(&parse(&before).unwrap(), 1);
    // A pick with a password that opens nothing: discarded unseen.
    let (result, t) = login_proved(&b, "wrong-password-1", &keys, 2);
    let mut entry = result.err().unwrap().entry.unwrap();
    let (kind, choices, touched, _) = entry.gate().unwrap();
    assert_eq!((kind, touched), (GateKind::G2, Some(2)));
    assert_eq!(choices.len(), 3);
    let wrong = Some(GateAnswer::Pick(vec![one]));
    assert_eq!(
        Session::login_via_server(&mut entry, &t, wrong.clone(), false).err(),
        Some(AUTH_ERROR)
    );
    assert!(b.lines(&id).gate.is_none_or(|g| g.g2));
    // The right password, a wrong pick: G2 off, nothing installed.
    let (result, t) = login_proved(&b, NEW, &keys, 2);
    let mut entry = result.err().unwrap().entry.unwrap();
    assert_eq!(
        Session::login_via_server(&mut entry, &t, wrong, false).err(),
        Some(GATE_G2FAIL)
    );
    assert!(!b.lines(&id).gate.unwrap().g2);
    assert_eq!(fs::read(b.key()).unwrap(), before);
    // The next login asks G1; a wrong code may be typed again.
    let (result, t) = login_proved(&b, NEW, &keys, 2);
    let mut entry = result.err().unwrap().entry.unwrap();
    assert_eq!(entry.gate().unwrap().0, GateKind::G1);
    let bad = Some(GateAnswer::Code(Code([7; 8])));
    assert_eq!(
        Session::login_via_server(&mut entry, &t, bad, false).err(),
        Some(GATE_CODE_WRONG)
    );
    let good = Some(GateAnswer::Code(code_of(&sa)));
    let (s, _) = Session::login_via_server(&mut entry, &t, good, false).unwrap();
    assert_eq!(header(&b).state(), header(&a).state());
    assert!(
        !parse(&fs::read(b.key()).unwrap())
            .unwrap()
            .slots
            .iter()
            .any(|x| x.credhash == three)
    );
    assert!(s.review_due.is_some(), "a loss makes the review due");
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.2 (S6-1 #1, S6-2 #4; §14.10 walkthrough 20): a key that only
/// the server's file lists is never in the unlock's allow list; after
/// Windows' cancel, S-TRY-OTHERKEY's ceremony holds that key alone, and its
/// touch takes the file behind G1 (the key is new to this PC).
#[test]
fn a_key_only_the_server_file_lists_opens_after_a_cancel() {
    let (a, mut sa, b, sb, mut keys, mut server, id) = both_on(2);
    drop(sb);
    a.here();
    let key3 = keys.register(&id, 3, true);
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key3),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    b.here();
    let prepared = prepare(&b.vault(), &b.key()).unwrap();
    let cred3 = header(&a)
        .slots
        .iter()
        .find(|s| s.number == 3)
        .unwrap()
        .cred_id
        .clone();
    // Never in the unlock's allow list.
    let unlock = prepared.unlock_request(0).unwrap();
    assert!(!unlock.allow.iter().any(|(c, ..)| *c == cred3));
    assert!(prepared.offers_other_key());
    let mut entry = prepared.other_key_entry(OLD, None).unwrap();
    assert!(!entry.own_tried());
    assert_eq!(entry.other_numbers(), [3]);
    let request = entry.other_request(0).unwrap();
    assert_eq!(request.allow.len(), 1);
    let t = keys.touch(3, &request).unwrap();
    let (kind, _, touched, _) = entry.gate().unwrap();
    assert_eq!((kind, touched), (GateKind::G1, None));
    assert_eq!(
        Session::login_via_server(&mut entry, &t, None, false).err(),
        Some(GATE_NOT_PENDING)
    );
    let good = Some(GateAnswer::Code(code_of(&sa)));
    let (s, _) = Session::login_via_server(&mut entry, &t, good, false).unwrap();
    assert_eq!(s.key_state(), header(&a).state());
    drop(s);
    // Key 3 now opens B's own key file.
    open(&b, OLD, &keys, 3).unwrap();
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.2, §7.15 step 4 (final review finding 3): the failed-unlock
/// entry takes a wrong G1 code, writes nothing, and takes the right one
/// typed again in the same entry.
#[test]
fn a_failed_unlock_entry_takes_the_code_again_after_a_wrong_one() {
    let a = Pc::new();
    let (mut sa, mut keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    polls(&mut sb);
    take_server(&mut sb, &keys, 2, code(code_of(&sa))).unwrap();
    drop(sb);
    a.here();
    assert_eq!(rekey(&mut sa, &keys, 1, password(NEW)), Ok(Rekeyed::Done));
    let key3 = keys.register(&id, 3, true);
    let r = reauth(&mut sa, NEW, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key3),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let before = fs::read(b.key()).unwrap();
    let (result, t) = login_proved(&b, NEW, &keys, 2);
    let mut entry = result.err().unwrap().entry.unwrap();
    assert_eq!(entry.gate().unwrap().0, GateKind::G1);
    let bad = Some(GateAnswer::Code(Code([7; 8])));
    assert_eq!(
        Session::login_via_server(&mut entry, &t, bad, false).err(),
        Some(GATE_CODE_WRONG)
    );
    assert_eq!(fs::read(b.key()).unwrap(), before);
    let good = Some(GateAnswer::Code(code_of(&sa)));
    let (s, _) = Session::login_via_server(&mut entry, &t, good, false).unwrap();
    assert_eq!(s.key_state(), header(&a).state());
    drop(s);
    open(&b, NEW, &keys, 3).unwrap();
    set_kdf_profile(KdfProfile::Real);
}

/// The same for S-KEYSYNC-ON's second call (final review finding 1): a
/// GOYOKH01 PC opens with the new password on top of another PC's "on";
/// the gate passes, S-KEYSYNC-ON is asked, and the yes takes it in the
/// same entry.
#[test]
fn a_keysync_consent_takes_the_same_entry_again() {
    let a = Pc::new();
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(rekey(&mut sa, &keys, 1, password(NEW)), Ok(Rekeyed::Done));
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    let (result, t) = login_proved(&b, NEW, &keys, 2);
    let mut entry = result.err().unwrap().entry.unwrap();
    assert_eq!(entry.gate().unwrap().0, GateKind::G1);
    let good = Some(GateAnswer::Code(code_of(&sa)));
    assert_eq!(
        Session::login_via_server(&mut entry, &t, good.clone(), false).err(),
        Some(crate::vault::KEYSYNC_CONSENT)
    );
    let (s, adopted) = Session::login_via_server(&mut entry, &t, good, true).unwrap();
    assert_eq!(adopted.state, header(&a).state());
    assert_eq!(s.key_state(), header(&a).state());
    assert!(header(&b).magic.hardware() && header(&b).magic == header(&a).magic);
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.1 step 10, §7.17 (round 4, finding 1): in a bootstrap the
/// server's key file is no snapshot: nothing is offered or taken at login.
#[test]
fn a_bootstrap_takes_nothing_from_the_server_at_login() {
    let (a, _sa, b, keys, _server, _id) = new_password_waiting();
    let c = Pc::new();
    carry(&b, &c);
    fs::create_dir(dir(&c)).unwrap();
    fs::copy(dir(&b).join(KEY_VIEW), dir(&c).join(KEY_VIEW)).unwrap();
    let (result, _) = login_proved(&c, NEW, &keys, 2);
    assert!(result.err().unwrap().entry.is_none());
    let (result, _) = login_proved(&c, OLD, &keys, 2);
    let (s, proof) = result.ok().unwrap();
    assert!(s.tofu());
    assert!(s.login_candidate(&proof).is_none());
    assert_ne!(header(&c).state(), header(&a).state());
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.1 step 10 (round 2, finding 8): the login takes only the
/// snapshot precheck read; a key view that changed during the login is
/// not taken there (it waits for [받기…]).
#[test]
fn a_key_view_swapped_during_the_login_is_not_taken() {
    let (a, mut sa, b, keys, mut server, id) = new_password_waiting();
    b.here();
    let prepared = prepare(&b.vault(), &b.key()).unwrap();
    // A changes the password again; B's helper writes that file meanwhile.
    a.here();
    assert_eq!(
        rekey_new(&mut sa, &keys, password("third synthetic password")),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    server.pass(&b, &id);
    b.here();
    let t = keys.touch(2, &prepared.unlock_request(0).unwrap()).unwrap();
    let (sb, proof) = Session::login_proved(prepared, OLD, None, &t).ok().unwrap();
    assert!(matches!(
        sb.server_class(),
        Some(KeyClass::Successor { .. })
    ));
    assert!(sb.login_candidate(&proof).is_none());
    set_kdf_profile(KdfProfile::Real);
}
/// A Restore of `pc`'s vault file into `dest` with the server's key file
/// from its key view, touched with key `number`.
fn restore_fetched(
    pc: &Pc,
    dest: &Path,
    password: &str,
    keys: &Keys,
    number: u8,
) -> Result<Session> {
    pc.here();
    let prepared = crate::vault::prepare_restore_fetched(&pc.vault())?;
    let t = keys
        .touch(number, &prepared.unlock_request(0).unwrap())
        .unwrap();
    Session::restore_with(prepared, dest, password, &t)
}

/// Spec §7.17 (§14.10 walkthrough 4, a new PC from the server): the vault
/// brought with goyo-sync's "이 PC로 가져오기" restores with the server's
/// key file read only: nothing is written outside the sync folder before G1 (no key
/// file, no restored vault file, no anchor line), no edit; a wrong code
/// writes nothing; the save step never writes into a sync folder or over a
/// file; then the key file, the vault file and the confirmed line with `t`,
/// and the pair opens as a login with no gate.
#[test]
fn a_new_pc_starts_from_the_server_key_file_behind_its_code() {
    let (a, sa, _b, keys, mut server, id) = new_password_waiting();
    let shown = code_of(&sa);
    // PC C: the vault file fetched next to its own sync folder and the
    // server's key file in its view.
    let c = Pc::new();
    fs::copy(a.vault(), c.vault()).unwrap();
    fs::create_dir(dir(&c)).unwrap();
    server.pass(&c, &id);
    assert_eq!(
        crate::vault::fetched_key(&c.vault()),
        Some(dir(&c).join(KEY_VIEW))
    );
    let dest = c.file("restored.goyo");
    let mut s = restore_fetched(&c, &dest, NEW, &keys, 1).unwrap();
    assert!(s.tofu() && s.fetched_unsaved());
    assert!(!dest.exists() && !c.key().exists() && c.anchor().is_empty());
    assert_eq!(
        s.put(None, entry("three")).err(),
        Some(crate::vault::TOFU_HELD)
    );
    assert_eq!(s.tofu_confirm(Some(&shown)).err(), Some(GATE_NOT_PENDING));
    assert_eq!(
        s.tofu_check(Some(&Code([7; 8]))).err(),
        Some(GATE_CODE_WRONG)
    );
    assert_eq!(
        s.tofu_save(Some(&Code([7; 8])), &c.key()).err(),
        Some(GATE_CODE_WRONG)
    );
    assert!(!c.key().exists() && c.anchor().is_empty());
    s.tofu_check(Some(&shown)).unwrap();
    let inside = dir(&c).join("vault.goyokey");
    assert_eq!(
        s.tofu_save(Some(&shown), &inside).err(),
        Some(crate::vault::FETCHED_IN_SYNC)
    );
    fs::write(c.key(), b"taken").unwrap();
    assert_eq!(
        s.tofu_save(Some(&shown), &c.key()).err(),
        Some(crate::vault::FETCHED_EXISTS)
    );
    fs::remove_file(c.key()).unwrap();
    s.tofu_save(Some(&shown), &c.key()).unwrap();
    assert!(!s.tofu() && !s.fetched_unsaved());
    assert_eq!(fs::read(c.key()).unwrap(), fs::read(a.key()).unwrap());
    assert!(dest.exists());
    let line = c.lines(&id).vault.unwrap();
    assert!(line.state.flags.t && c.lines(&id).pending.is_none());
    assert_eq!(line.state.key_state(), header(&a).state());
    s.put(None, entry("three")).unwrap();
    drop(s);
    c.here();
    let prepared = prepare(&dest, &c.key()).unwrap();
    let t = keys.touch(2, &prepared.unlock_request(0).unwrap()).unwrap();
    let s = Session::login_with(prepared, NEW, None, &t).unwrap();
    assert!(!s.tofu() && !s.gate_pending());
    assert!(has(&s, "three"));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §2.29 (UX overhaul, "서버에서 가져온 금고"): goyo-sync fetched the
/// vault file into the folder the user picked, next to its sync folder;
/// the app restores it in place with the server's key file. Nothing is
/// written before G1 (the fetched file keeps its bytes, no key file, no
/// anchor line); the pass writes the key file next to it and saves the
/// vault file where it was, and the pair then opens as a login. A Restore
/// of any other file onto itself is still refused.
#[test]
fn a_fetched_vault_is_restored_in_place_behind_its_code() {
    let (a, sa, _b, keys, mut server, id) = new_password_waiting();
    let shown = code_of(&sa);
    let c = c_with_view(&a, &id, &mut server);
    let fetched = fs::read(c.vault()).unwrap();
    let mut s = restore_fetched(&c, &c.vault(), NEW, &keys, 1).unwrap();
    assert!(s.tofu() && s.fetched_unsaved());
    assert_eq!(fs::read(c.vault()).unwrap(), fetched);
    assert!(!c.key().exists() && c.anchor().is_empty());
    assert_eq!(
        s.tofu_save(Some(&Code([7; 8])), &c.key()).err(),
        Some(GATE_CODE_WRONG)
    );
    assert_eq!(fs::read(c.vault()).unwrap(), fetched);
    s.tofu_save(Some(&shown), &c.key()).unwrap();
    assert!(!s.tofu() && !s.fetched_unsaved());
    assert_eq!(fs::read(c.key()).unwrap(), fs::read(a.key()).unwrap());
    assert!(c.lines(&id).vault.unwrap().state.flags.t);
    s.put(None, entry("in place")).unwrap();
    drop(s);
    c.here();
    let prepared = prepare(&c.vault(), &c.key()).unwrap();
    let t = keys.touch(2, &prepared.unlock_request(0).unwrap()).unwrap();
    let s = Session::login_with(prepared, NEW, None, &t).unwrap();
    assert!(!s.tofu() && !s.gate_pending());
    assert!(has(&s, "in place"));
    drop(s);
    // An ordinary Restore never writes over its own backup.
    let prepared = crate::vault::prepare_restore(&c.vault(), &c.key()).unwrap();
    let t = keys.touch(2, &prepared.unlock_request(0).unwrap()).unwrap();
    assert_eq!(
        Session::restore_with(prepared, &c.vault(), NEW, &t).err(),
        Some(crate::vault::NOT_DISTINCT)
    );
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.17 (a lost key file on a PC that still has its vault): a save
/// step cut off after its pending entry is resumed by the next Restore
/// with no second code; and the local vault file is the floor, so a
/// server key file older than it is refused.
#[test]
fn a_lost_key_file_comes_back_from_the_server_once_and_not_older() {
    let (a, mut sa, b, mut keys, mut server, id) = new_password_waiting();
    let shown = code_of(&sa);
    // The save is cut off after its pending entry, in the key file's write.
    let c = c_with_view(&b, &id, &mut server);
    let dest = c.file("restored.goyo");
    let mut s = restore_fetched(&c, &dest, NEW, &keys, 1).unwrap();
    CRASH.with(|x| x.set(Some("tmp_synced")));
    assert!(s.tofu_save(Some(&shown), &c.key()).is_err());
    assert!(!c.key().exists());
    assert_eq!(
        c.lines(&id).pending.unwrap().src,
        crate::vault::anchor::Src::Tofu
    );
    assert!(!dest.exists());
    drop(s);
    // The next Restore resumes at the save step: no code. A file under the
    // pending entry's own name is taken only when it holds exactly the key
    // file (a cut after its write, final review finding 10).
    fs::write(c.key(), b"taken").unwrap();
    let mut s = restore_fetched(&c, &dest, NEW, &keys, 1).unwrap();
    assert!(!s.tofu() && s.fetched_unsaved());
    assert_eq!(
        s.put(None, entry("x")).err(),
        Some(crate::vault::FETCHED_UNSAVED)
    );
    assert_eq!(
        s.tofu_save(None, &c.key()).err(),
        Some(crate::vault::FETCHED_EXISTS)
    );
    assert_eq!(fs::read(c.key()).unwrap(), b"taken");
    fs::write(c.key(), fs::read(a.key()).unwrap()).unwrap();
    s.tofu_save(None, &c.key()).unwrap();
    assert!(c.lines(&id).vault.unwrap().state.flags.t);
    assert!(c.lines(&id).pending.is_none() && dest.exists());
    drop(s);
    // A adds a key, which keeps the data key: A's vault file is now above
    // the server's key file, which is refused as a rollback.
    a.here();
    let key3 = keys.register(&id, 3, true);
    let r = reauth(&mut sa, NEW, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key3),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    let older = c_with_view(&a, &id, &mut server);
    assert_eq!(
        restore_fetched(&older, &older.file("x.goyo"), NEW, &keys, 1).err(),
        Some(crate::vault::FETCHED_OLDER)
    );
    set_kdf_profile(KdfProfile::Real);
}
/// A PC with `from`'s vault file and a key view of the server's top.
fn c_with_view(from: &Pc, id: &[u8; 16], server: &mut KeyServer) -> Pc {
    let c = Pc::new();
    fs::copy(from.vault(), c.vault()).unwrap();
    fs::create_dir(dir(&c)).unwrap();
    server.pass(&c, id);
    c
}

/// Spec §7.15a (§14.10 walkthrough 26, round 2 findings 13 and 23, S6-1
/// #2): A adds key 3 and changes its password, and its disk dies before
/// anyone typed its code. B is held (GatePending, G1); [다른 PC가 없어 이
/// PC 상태로 올리기…] is offered; the supersede writes B's own keyset
/// again above A's file (kind 6, B's data key kept, key 3 not in it),
/// marks the gate superseded, keeps A's data key in `sup` with A's state,
/// and uploads on A's record; A's vault head, under that state, is pushed
/// over at the next poll and at every later unlock.
#[test]
fn a_change_whose_pc_is_gone_is_superseded() {
    let (a, mut sa, b, mut sb, mut keys, mut server, id) = both_on(2);
    a.here();
    let key3 = keys.register(&id, 3, true);
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key3),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(rekey(&mut sa, &keys, 1, password(NEW)), Ok(Rekeyed::Done));
    server.pass(&a, &id);
    polls(&mut sa);
    let gone = header(&a);
    // A's last vault upload, under its new data key and state.
    assert!(uploads(&a, &mut sa, "written on a"));
    let out = fs::read(dir(&a).join(OUTGOING)).unwrap();
    let copy = syncfile::parse_outgoing(&out).unwrap().1.to_vec();
    drop(sa);
    // B: A's change waits for A's code, which nobody can read any more.
    b.here();
    let before = header(&b);
    server.pass(&b, &id);
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
    let incoming = syncfile::render_incoming(7, &copy).unwrap();
    syncfile::replace_file(&dir(&b).join(syncfile::INCOMING), &incoming).unwrap();
    polls(&mut sb);
    let waiting = sb.key_sync_view().unwrap().waiting.unwrap();
    assert!(waiting.supersede && waiting.pending_gate);
    assert_eq!(sb.change_gate(&password(THIRD)).err(), Some(GATE_PENDING));
    let wrong = Change::Supersede {
        epoch: gone.epoch,
        tag: [9; 16],
    };
    assert_eq!(
        rekey(&mut sb, &keys, 2, wrong).err(),
        Some(crate::vault::NOT_SUPERSEDABLE)
    );
    let change = Change::Supersede {
        epoch: gone.epoch,
        tag: gone.state().tag,
    };
    assert_eq!(sb.change_gate(&change), Ok(None));
    assert_eq!(rekey(&mut sb, &keys, 2, change), Ok(Rekeyed::Done));
    let up = header(&b);
    assert_eq!((up.magic, up.kind), (Magic::Ks01, keyfile::Kind::SyncOn));
    assert_eq!(up.epoch, gone.epoch + 1);
    assert_eq!(up.key_ids, before.key_ids, "the data key is kept");
    assert_eq!(numbers(&up), [1, 2], "key 3 is not taken");
    let lines = b.lines(&id);
    assert_eq!(lines.gate.unwrap().state, GateState::Superseded);
    let line = lines.vault.unwrap();
    assert!(line.state.flags.p, "the rollout reminder");
    assert!(
        line.state
            .sup
            .iter()
            .any(|e| e.keyid == gone.key_ids[0]
                && (e.epoch, e.tag) == (gone.epoch, gone.state().tag))
    );
    assert!(
        !line
            .state
            .sup
            .iter()
            .any(|e| before.key_ids.contains(&e.keyid))
    );
    // The key request: a PUT on A's record, above its epoch; A's vault
    // head is pushed over, B's state going up from version 7.
    let _ = fs::remove_file(dir(&b).join(OUTGOING));
    polls(&mut sb);
    let bytes = kreq(&b).unwrap();
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!(
        (req.op, req.base, req.floor),
        (KeyOp::Put, server.top(), gone.epoch)
    );
    let out = fs::read(dir(&b).join(OUTGOING)).unwrap();
    assert_eq!(syncfile::parse_outgoing(&out).unwrap().0, 7);
    server.pass(&b, &id);
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    assert!(sb.key_sync_view().unwrap().waiting.is_none());
    drop(sb);
    // At the next unlock `sup` still pushes that head over.
    let _ = fs::remove_file(dir(&b).join(OUTGOING));
    syncfile::replace_file(&dir(&b).join(syncfile::INCOMING), &incoming).unwrap();
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    let told = polls(&mut sb);
    assert!(
        !told.iter().any(|n| matches!(
            n,
            SyncNotice::KeyChanged { .. } | SyncNotice::KeyChangedServer | SyncNotice::KeyFork
        )),
        "{told:?}"
    );
    assert!(dir(&b).join(OUTGOING).exists());
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.15a (round 3, finding 1; round 4, finding 7): a removal of one
/// of this PC's keys (R ≠ ∅) is never superseded; a GOYOKH01 PC supersedes
/// another PC's "on" (a GOYOKS01 successor) and so turns key-file sync on
/// itself.
#[test]
fn a_removal_is_never_superseded_and_an_on_is() {
    let (a, mut sa, b, mut sb, mut keys, mut server, id) = both_on(3);
    a.here();
    remove_lost(&mut sa, &keys, 3, 1);
    server.pass(&a, &id);
    polls(&mut sa);
    b.here();
    server.pass(&b, &id);
    polls(&mut sb);
    assert!(!sb.key_sync_view().unwrap().waiting.unwrap().supersede);
    // A removal with an addition on top needs the code (G1), and is still
    // never superseded.
    a.here();
    let key4 = keys.register(&id, 4, true);
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key4),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let removal = header(&a);
    b.here();
    server.pass(&b, &id);
    polls(&mut sb);
    assert_eq!(
        sb.server_class(),
        Some(KeyClass::Successor {
            carry: false,
            gate: Some(GateKind::G1)
        })
    );
    assert!(!sb.key_sync_view().unwrap().waiting.unwrap().supersede);
    let change = Change::Supersede {
        epoch: removal.epoch,
        tag: removal.state().tag,
    };
    assert_eq!(
        rekey(&mut sb, &keys, 2, change).err(),
        Some(crate::vault::NOT_SUPERSEDABLE)
    );
    drop((sa, sb));

    // A GOYOKH01 PC and another PC's "on".
    let a = Pc::new();
    let (mut sa, keys) = create_with(&a, 2, true, true);
    let id = sa.id;
    let b = synced_pc(&a, &keys, 2);
    a.here();
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    let on = header(&a);
    drop(sa);
    server.pass(&b, &id);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    polls(&mut sb);
    assert_eq!(header(&b).magic, Magic::Kh01);
    assert!(sb.key_sync_view().unwrap().waiting.unwrap().supersede);
    let change = Change::Supersede {
        epoch: on.epoch,
        tag: on.state().tag,
    };
    assert_eq!(rekey(&mut sb, &keys, 2, change), Ok(Rekeyed::Done));
    let up = header(&b);
    assert_eq!((up.magic, up.epoch), (Magic::Ks01, on.epoch + 1));
    polls(&mut sb);
    let bytes = kreq(&b).unwrap();
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!((req.op, req.base, req.floor), (KeyOp::Put, 1, on.epoch));
    server.pass(&b, &id);
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    assert!(uploads(&b, &mut sb, "up again"));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §7.18: the PC that changed a GOYOKS01 key file is reminded at each
/// unlock, worded per change, until [모든 PC 확인 완료].
#[test]
fn the_rollout_reminder_stays_until_every_pc_is_confirmed() {
    let (a, sa, b, sb, mut keys, mut server, id) = both_on(3);
    a.here();
    // The "on" asks a code only of a PC that keeps its key file to itself.
    let code = sa.key_code().unwrap();
    assert_eq!(sa.rollout(), Some(crate::vault::Rollout::Maybe(code)));
    // B took the "on": no reminder there.
    b.here();
    assert_eq!(sb.rollout(), None);
    drop((sa, sb));
    let mut sa = open(&a, OLD, &keys, 1).unwrap();
    assert!(sa.rollout().is_some(), "at every unlock");
    sa.rollout_done().unwrap();
    assert_eq!(sa.rollout(), None);
    assert!(!a.lines(&id).vault.unwrap().state.flags.p);
    assert_eq!(rekey(&mut sa, &keys, 1, password(NEW)), Ok(Rekeyed::Done));
    assert_eq!(sa.rollout(), Some(crate::vault::Rollout::Plain));
    server.pass(&a, &id);
    polls(&mut sa);
    let r = reauth(&mut sa, NEW, &keys, 1).unwrap();
    let change = remove(&[3], Some(lost()), None);
    assert_eq!(
        sa.rekey(r, Vec::new(), change, Consent::default(), false),
        Ok(Rekeyed::Done)
    );
    let code = sa.key_code().unwrap();
    assert_eq!(sa.rollout(), Some(crate::vault::Rollout::Remove(code)));
    // An added key: always the code.
    let key4 = keys.register(&id, 4, true);
    let r = reauth(&mut sa, NEW, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key4),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    let code = sa.key_code().unwrap();
    assert_eq!(sa.rollout(), Some(crate::vault::Rollout::Code(code)));
    set_kdf_profile(KdfProfile::Real);
}

/// The kind-9 merge's other file `f` taken with the unlock's touch `t`
/// and the login's own Reauth, no gate and no question (spec §5.8).
fn merge_at_login(
    s: &mut Session,
    proof: crate::vault::UnlockProof,
    t: &Touch,
    f: &KeyFile,
    seq: u64,
) -> Adopted {
    let check = s.adopt_check(f, Source::Server { seq }).unwrap();
    let r = s.reauth_from_unlock(proof, t).unwrap();
    let opened = s.adopt_open_with(&r, f, None, Some(t)).unwrap();
    let pass = GatePass::none(&check);
    let plan = s
        .adopt_preview_with(&r, f, opened, &check, pass, ForkOption::Both)
        .unwrap();
    let acks = acks(plan.preview(), ForkOption::Both);
    s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
        .unwrap()
}

/// Spec §5.8 the kind-9 merge (§14.10 walkthrough 18, S6-1 #5): A and B
/// remove the same lost key from one state; A's PUT wins and B's meets it
/// (KeyFork). B is told the merge comes at its next unlock (KeyFork-SK-
/// AUTO); that unlock merges with its own touch and password, no question
/// and no second code, and uploads on A's record; at A the merge is a
/// successor with no gate, taken at A's next unlock.
#[test]
fn two_removals_from_one_state_merge_at_the_next_unlock() {
    let (a, mut sa, b, mut sb, keys, mut server, id) = both_on(3);
    let three = credhash(&header(&a), 3);
    a.here();
    remove_lost(&mut sa, &keys, 3, 1);
    server.pass(&a, &id);
    polls(&mut sa);
    let ka = header(&a);
    b.here();
    remove_lost(&mut sb, &keys, 3, 2);
    let kb = header(&b);
    server.pass(&b, &id);
    assert_eq!(kview(&b, &id).unwrap().outcome, KeyOutcome::Conflict);
    let told = polls(&mut sb);
    assert!(
        told.contains(&SyncNotice::KeyForkMerge { auto: true }),
        "{told:?}"
    );
    assert_eq!(sb.removal_merge(), Some(crate::vault::RemovalMerge::Auto));
    drop(sb);
    // The next unlock.
    let (result, t) = login_proved(&b, OLD, &keys, 2);
    let (mut sb, proof) = result.ok().unwrap();
    assert!(sb.login_candidate(&proof).is_none());
    let (f, seq) = sb.login_merge(&proof).unwrap();
    merge_at_login(&mut sb, proof, &t, &f, seq);
    let merged = header(&b);
    assert_eq!(merged.kind, keyfile::Kind::Union);
    assert_eq!(merged.epoch, ka.epoch.max(kb.epoch) + 1);
    assert_eq!(numbers(&merged), [1, 2]);
    assert!(merged.tombstones.iter().any(|x| x.credhash == three));
    polls(&mut sb);
    let bytes = kreq(&b).unwrap();
    let req = parse_key_request(&bytes, &id).unwrap();
    assert_eq!((req.op, req.base), (KeyOp::Put, server.top()));
    server.pass(&b, &id);
    polls(&mut sb);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    // A: B's merge needs no gate, and is taken at A's next unlock.
    a.here();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        sa.server_class(),
        Some(KeyClass::Successor {
            carry: false,
            gate: None
        })
    );
    drop(sa);
    let (result, t) = login_proved(&a, OLD, &keys, 1);
    let (mut sa, proof) = result.ok().unwrap();
    assert!(sa.login_merge(&proof).is_none(), "the head never merges");
    let (f, seq) = sa.login_candidate(&proof).unwrap();
    merge_at_login(&mut sa, proof, &t, &f, seq);
    assert_eq!(header(&a).state(), merged.state());
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §5.8 (S6-1 #5, S6-2 #5): a removal made with a new password on
/// the other PC is merged only with [받기] (KeyFork-SK-MERGE), never at
/// login; a merge whose other file did not open is remembered, and that
/// file is then Refused{"위조된 연결"} with no merge offered.
#[test]
fn a_merge_that_needs_a_question_waits_and_one_that_failed_is_refused() {
    let (a, mut sa, b, mut sb, keys, mut server, id) = both_on(3);
    a.here();
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    let change = remove(&[3], Some(lost()), Some(NEW));
    assert_eq!(
        sa.rekey(r, Vec::new(), change, Consent::default(), false),
        Ok(Rekeyed::Done)
    );
    server.pass(&a, &id);
    polls(&mut sa);
    b.here();
    remove_lost(&mut sb, &keys, 3, 2);
    server.pass(&b, &id);
    let told = polls(&mut sb);
    assert!(
        told.contains(&SyncNotice::KeyForkMerge { auto: false }),
        "{told:?}"
    );
    drop(sb);
    let (result, _) = login_proved(&b, OLD, &keys, 2);
    let (mut sb, proof) = result.ok().unwrap();
    assert!(sb.login_merge(&proof).is_none());
    let (f, _) = sb.server_key_file().unwrap();
    sb.merge_failed(&f);
    assert_eq!(
        sb.server_class(),
        Some(KeyClass::Refused(crate::vault::FORGED_LINK))
    );
    assert_eq!(sb.removal_merge(), None);
    let told = polls(&mut sb);
    assert!(
        !told
            .iter()
            .any(|n| matches!(n, SyncNotice::KeyForkMerge { .. })),
        "{told:?}"
    );
    set_kdf_profile(KdfProfile::Real);
}

/// '코드 없이 이 서버를 믿고 받기…' is for a PC without keys only: a PC
/// with keys taking another PC's added key from the server (G1) is offered
/// no such take (pwonly_server_file) and refused one (NOT_TRUSTED), with
/// nothing written; its code still takes it.
#[test]
fn a_take_without_a_code_is_only_for_a_pc_without_keys() {
    let (a, mut sa, b, mut sb, mut keys, mut server, id) = both_on(3);
    a.here();
    let key4 = keys.register(&id, 4, true);
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key4),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    fetch(&a, &mut sa, &mut server, &id);
    fetch(&b, &mut sb, &mut server, &id);
    assert_eq!(sb.pwonly_server_file(), None);
    let (served, seq) = sb.server_key_file().unwrap();
    let check = sb.adopt_check(&served, Source::Server { seq }).unwrap();
    assert_eq!(check.class, AdoptClass::Successor);
    assert_eq!(check.keys.gate, Some(GateKind::G1));
    assert!(!sb.trusts_without_code(&check));
    let before = fs::read(b.key()).unwrap();
    let take = |sb: &mut Session, pass: GatePass| {
        let r = reauth(sb, OLD, &keys, 2).unwrap();
        let t = touch_other(&served, &keys, 2);
        let opened = sb.adopt_open_with(&r, &served, None, Some(&t)).unwrap();
        let planned = sb.adopt_preview_with(&r, &served, opened, &check, pass, ForkOption::Both);
        (r, planned)
    };
    let nocode = GatePass::NoCode {
        epoch: check.other.epoch,
        tag: check.other.tag,
    };
    let (_, planned) = take(&mut sb, nocode);
    assert_eq!(planned.err(), Some(NOT_TRUSTED));
    assert_eq!(fs::read(b.key()).unwrap(), before);
    let code = GatePass::G1Passed {
        code: code_of(&sa),
        epoch: check.other.epoch,
        tag: check.other.tag,
    };
    let (r, planned) = take(&mut sb, code);
    let planned = planned.unwrap();
    let acked = acks(planned.preview(), ForkOption::Both);
    sb.adopt(r, planned, Vec::new(), acked, Consent::default(), false)
        .unwrap();
    assert_eq!(header(&b).state(), header(&a).state());
    set_kdf_profile(KdfProfile::Real);
}

/// The take of auto-apply (spec §2.30): no gate question, the gate passed
/// as trusted.
fn trusted(c: &AdoptCheck, _: &Session) -> GatePass {
    GatePass::Trusted {
        epoch: c.other.epoch,
        tag: c.other.tag,
    }
}
/// One helper pass for `pc`, then polls of `s` until nothing changes.
fn fetch(pc: &Pc, s: &mut Session, server: &mut KeyServer, id: &[u8; 16]) -> Vec<SyncNotice> {
    pc.here();
    server.pass(pc, id);
    polls(s)
}

/// Spec §2.30 ("열쇠 변경 자동 적용 (이 서버를 믿음)"): off, A's removal
/// waits for its gate on B as before and a take that trusts the server is
/// refused with nothing written. On (stored in B's anchor and read again
/// by the next session), never for a USB file, the removal and then A's
/// added key come from the server with no gate answer, each told by what
/// it changed (this PC's number of the removed key, the file's of the new
/// one), the review of the removal for a loss still due, G2 not turned
/// back on, and the public checks still holding: an older file from the
/// server is not taken. Off asks nothing; a bootstrap cannot turn it on.
#[test]
fn auto_apply_takes_server_changes_with_no_gate_and_only_those() {
    let (a, mut sa, b, mut sb, mut keys, mut server, id) = both_on(3);
    let shared = fs::read(a.key()).unwrap();
    a.here();
    remove_lost(&mut sa, &keys, 3, 1);
    fetch(&a, &mut sa, &mut server, &id);
    let told = fetch(&b, &mut sb, &mut server, &id);
    assert!(told.contains(&SyncNotice::GatePending), "{told:?}");
    // Off: the gate as today.
    assert!(!sb.auto_apply() && !b.lines(&id).vault.unwrap().state.auto);
    let (f, seq) = sb.server_key_file().unwrap();
    let check = sb.adopt_check(&f, Source::Server { seq }).unwrap();
    assert!(!sb.trusts(&check));
    assert_eq!(check.keys.gate, Some(GateKind::G2));
    let before = fs::read(b.key()).unwrap();
    let taken = take_server(&mut sb, &keys, 2, trusted);
    assert_eq!(taken.err(), Some(NOT_TRUSTED));
    assert_eq!(fs::read(b.key()).unwrap(), before);
    // A wrong pick turns G2 off for B (as before); the trusted take below
    // never turns it back on.
    let picked = take_server(&mut sb, &keys, 2, pick(&[1]));
    assert_eq!(picked.err(), Some(GATE_G2FAIL));
    assert!(!b.lines(&id).gate.unwrap().g2);
    // On: in the anchor, and a server change is taken with no answer.
    sb.set_auto_apply(true).unwrap();
    assert!(sb.auto_apply() && b.lines(&id).vault.unwrap().state.auto);
    assert!(sb.key_sync_view().unwrap().auto_apply);
    let removal = fs::read(a.key()).unwrap();
    // Never a USB file.
    let usb = take(
        &mut sb,
        &keys,
        (OLD, 2),
        &removal,
        ForkOption::Both,
        trusted,
        Consent::default(),
    );
    assert_eq!(usb.err(), Some(NOT_TRUSTED));
    assert_eq!(fs::read(b.key()).unwrap(), before);
    let (f, seq) = sb.server_key_file().unwrap();
    assert!(sb.trusts(&sb.adopt_check(&f, Source::Server { seq }).unwrap()));
    let adopted = take_server(&mut sb, &keys, 2, trusted).unwrap();
    assert!(adopted.trusted);
    assert_eq!(
        adopted.change,
        KeyChange {
            removed: vec![3],
            ..KeyChange::default()
        }
    );
    assert_eq!(header(&b).state(), header(&a).state());
    assert!(sb.review_due().is_some(), "the review of a loss stays due");
    assert!(b.lines(&id).review.is_some_and(|r| r.due));
    // G2 stays off: the gate is cleared into a line that holds nothing.
    let line = b.lines(&id).gate.unwrap();
    assert_eq!((line.state, line.g2), (GateState::None, false));
    fetch(&b, &mut sb, &mut server, &id);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    // A adds key 4 with key 1: G1 before, none asked now.
    a.here();
    let key4 = keys.register(&id, 4, true);
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key4),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    fetch(&a, &mut sa, &mut server, &id);
    let told = fetch(&b, &mut sb, &mut server, &id);
    assert!(
        told.iter()
            .any(|n| matches!(n, SyncNotice::KeyFileReady { .. })),
        "{told:?}"
    );
    let (f, seq) = sb.server_key_file().unwrap();
    let check = sb.adopt_check(&f, Source::Server { seq }).unwrap();
    assert_eq!(check.keys.gate, Some(GateKind::G1));
    let adopted = take_server(&mut sb, &keys, 2, trusted).unwrap();
    assert_eq!(
        adopted.change,
        KeyChange {
            added: vec![4],
            ..KeyChange::default()
        }
    );
    assert_eq!(header(&b).state(), header(&a).state());
    // An older file from the server (the shared state before the removal)
    // is still refused.
    let generation = server.records.last().unwrap().1;
    let floor = parse(&shared).unwrap().epoch;
    server
        .records
        .push((RecordKind::Key, generation, floor, shared.clone()));
    fetch(&b, &mut sb, &mut server, &id);
    let after = fs::read(b.key()).unwrap();
    assert!(!matches!(
        sb.server_class(),
        Some(KeyClass::Successor { .. } | KeyClass::KeyFork)
    ));
    let (f, seq) = sb.server_key_file().unwrap();
    assert!(sb.adopt_check(&f, Source::Server { seq }).is_err());
    assert!(take_server(&mut sb, &keys, 2, trusted).is_err());
    assert_eq!(fs::read(b.key()).unwrap(), after);
    // Read again by the next session; off asks nothing and writes it.
    drop(sb);
    let mut sb = open(&b, OLD, &keys, 2).unwrap();
    assert!(sb.auto_apply());
    sb.set_auto_apply(false).unwrap();
    assert!(!sb.auto_apply() && !b.lines(&id).vault.unwrap().state.auto);
    drop(sb);
    // A bootstrap (a new PC with B's files) cannot turn it on.
    let c = Pc::new();
    carry(&b, &c);
    let mut sc = open(&c, OLD, &keys, 2).unwrap();
    assert!(sc.tofu());
    assert_eq!(sc.set_auto_apply(true).err(), Some(AUTO_NOT_SYNCED));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §2.30: with auto-apply on, a server file that fails a public check
/// is still refused before any touch: one authored by a key this PC's user
/// removed (P4; a fork of the state before that removal, which the trust
/// never serves either).
#[test]
fn auto_apply_still_refuses_a_file_of_a_removed_key() {
    let (_a, _sa, b, mut sb, keys, mut server, id) = both_on(3);
    let shared = fs::read(b.key()).unwrap();
    b.here();
    sb.set_auto_apply(true).unwrap();
    remove_lost(&mut sb, &keys, 3, 2);
    fetch(&b, &mut sb, &mut server, &id);
    assert_eq!(sb.server_class(), Some(KeyClass::Equal));
    let mine = fs::read(b.key()).unwrap();
    // Key 3's holder, with the password, writes on the state before.
    let forged = Forger {
        keys: &keys,
        base: shared,
        x: 3,
    }
    .forge(|_| {});
    let generation = server.records.last().unwrap().1;
    let floor = parse(&forged).unwrap().epoch;
    server
        .records
        .push((RecordKind::Key, generation, floor, forged));
    let told = fetch(&b, &mut sb, &mut server, &id);
    assert!(
        told.contains(&SyncNotice::KeyFileRefused(REMOVED_AUTHORIZER)),
        "{told:?}"
    );
    let (derived, seen) = (derive_count(), keys.fake.seen().len());
    let taken = take_server(&mut sb, &keys, 1, trusted);
    assert_eq!(taken.err(), Some(ADOPT_REFUSED));
    assert_eq!(
        refusal_values(ADOPT_REFUSED),
        Some(vec![REMOVED_AUTHORIZER.to_owned()])
    );
    assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
    assert_eq!(fs::read(b.key()).unwrap(), mine);
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §2.30 (the wrong notice, task 2 of that round): on a security-key
/// build, a vault copy under another PC's new key, written under key-file
/// sync (A removed a key), halts B with KeyChangedServer, the change that
/// [받기…] or the next unlock takes; never the default build's "this build
/// cannot take that key file" (KeyChanged{hardware: true}) or the USB
/// advice of KeyChanged. Told once per halt.
#[test]
fn a_copy_under_another_pcs_new_key_points_to_the_server_key_file() {
    let (a, mut sa, b, mut sb, keys, mut server, id) = both_on(3);
    a.here();
    assert_eq!(
        rekey(&mut sa, &keys, 1, remove(&[3], None, None)),
        Ok(Rekeyed::Done)
    );
    fetch(&a, &mut sa, &mut server, &id);
    a.here();
    assert!(uploads(&a, &mut sa, "after the removal"));
    let out = fs::read(dir(&a).join(OUTGOING)).unwrap();
    let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
    // goyo-sync on B brought the vault copy before the key file.
    b.here();
    let incoming = syncfile::render_incoming(50, copy).unwrap();
    syncfile::replace_file(&dir(&b).join(syncfile::INCOMING), &incoming).unwrap();
    let told = polls(&mut sb);
    assert!(told.contains(&SyncNotice::KeyChangedServer), "{told:?}");
    let wrong = |told: &[SyncNotice]| {
        told.iter()
            .any(|n| matches!(n, SyncNotice::KeyChanged { .. }))
    };
    assert!(!wrong(&told), "{told:?}");
    assert!(!polls(&mut sb).contains(&SyncNotice::KeyChangedServer));
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §2.30: auto-apply never joins a fork. A adds key 4 while B
/// removes key 3 from the same state; B's removal meets A's record
/// (KeyFork), and the union of the two needs A's code (G1): with auto-apply
/// on, a take that trusts the server is refused and nothing is written.
#[test]
fn auto_apply_never_joins_a_fork() {
    let (a, mut sa, b, mut sb, mut keys, mut server, id) = both_on(3);
    b.here();
    sb.set_auto_apply(true).unwrap();
    a.here();
    let key4 = keys.register(&id, 4, true);
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key4),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    fetch(&a, &mut sa, &mut server, &id);
    b.here();
    assert_eq!(
        rekey(&mut sb, &keys, 2, remove(&[3], None, None)),
        Ok(Rekeyed::Done)
    );
    fetch(&b, &mut sb, &mut server, &id);
    assert_eq!(sb.server_class(), Some(KeyClass::KeyFork));
    let (f, seq) = sb.server_key_file().unwrap();
    let check = sb.adopt_check(&f, Source::Server { seq }).unwrap();
    assert!(check.fork && check.keys.gate.is_some(), "{check:?}");
    assert!(!sb.trusts(&check));
    let mine = fs::read(b.key()).unwrap();
    let taken = take_server(&mut sb, &keys, 2, trusted);
    assert_eq!(taken.err(), Some(NOT_TRUSTED));
    assert_eq!(fs::read(b.key()).unwrap(), mine);
    set_kdf_profile(KdfProfile::Real);
}

/// Spec §2.30, review: the trust is bound to the server channel itself,
/// not to the source a caller names, and is judged again at the write.
/// With auto-apply on and A's removal waiting on the server, a later file
/// of A's that never reached the server (its key addition, a successor
/// that needs the code) checked under the server's record number is not
/// trusted, and a take that trusts the server with it writes nothing; a
/// take of the server's own file previewed under the setting writes
/// nothing once the setting was turned off before the write; with the
/// setting on again the same take lands.
#[test]
fn auto_apply_trusts_only_the_servers_own_file_and_judges_again_at_the_write() {
    let (a, mut sa, b, mut sb, mut keys, mut server, id) = both_on(3);
    b.here();
    sb.set_auto_apply(true).unwrap();
    a.here();
    remove_lost(&mut sa, &keys, 3, 1);
    fetch(&a, &mut sa, &mut server, &id);
    // A adds key 4 on top; goyo-sync on A does not run, so the server
    // keeps the removal.
    a.here();
    let key4 = keys.register(&id, 4, true);
    let r = reauth(&mut sa, OLD, &keys, 1).unwrap();
    assert_eq!(
        sa.rekey(
            r,
            Vec::new(),
            Change::AddKey(key4),
            Consent::default(),
            true
        ),
        Ok(Rekeyed::Done)
    );
    let unsent = fs::read(a.key()).unwrap();
    fetch(&b, &mut sb, &mut server, &id);
    let before = fs::read(b.key()).unwrap();
    let (served, seq) = sb.server_key_file().unwrap();
    assert_ne!(served.bytes(), unsent.as_slice());
    // The unsent file, named as the server's: a gated successor, never
    // trusted.
    let f = file(&unsent);
    let check = sb.adopt_check(&f, Source::Server { seq }).unwrap();
    assert_eq!(check.class, AdoptClass::Successor);
    assert!(!check.fork && check.keys.gate.is_some(), "{check:?}");
    assert!(!sb.trusts(&check));
    let r = reauth(&mut sb, OLD, &keys, 2).unwrap();
    let t = touch_other(&f, &keys, 2);
    let opened = sb.adopt_open_with(&r, &f, None, Some(&t)).unwrap();
    let pass = trusted(&check, &sb);
    let planned = sb.adopt_preview_with(&r, &f, opened, &check, pass, ForkOption::Both);
    assert_eq!(planned.err(), Some(NOT_TRUSTED));
    assert_eq!(fs::read(b.key()).unwrap(), before);
    drop(r);
    // The server's own file, previewed under the setting; turned off
    // before the write: nothing is written.
    let check = sb.adopt_check(&served, Source::Server { seq }).unwrap();
    assert!(sb.trusts(&check));
    let plan = |sb: &mut Session| {
        let r = reauth(sb, OLD, &keys, 2).unwrap();
        let t = touch_other(&served, &keys, 2);
        let opened = sb.adopt_open_with(&r, &served, None, Some(&t)).unwrap();
        let pass = trusted(&check, sb);
        let plan = sb
            .adopt_preview_with(&r, &served, opened, &check, pass, ForkOption::Both)
            .unwrap();
        (r, plan)
    };
    let (r, planned) = plan(&mut sb);
    let acked = acks(planned.preview(), ForkOption::Both);
    sb.set_auto_apply(false).unwrap();
    let written = sb.adopt(r, planned, Vec::new(), acked, Consent::default(), false);
    assert_eq!(written.err(), Some(NOT_TRUSTED));
    assert_eq!(fs::read(b.key()).unwrap(), before);
    // On again: the same take lands.
    sb.set_auto_apply(true).unwrap();
    let (r, planned) = plan(&mut sb);
    let acked = acks(planned.preview(), ForkOption::Both);
    let adopted = sb
        .adopt(r, planned, Vec::new(), acked, Consent::default(), false)
        .unwrap();
    assert!(adopted.trusted);
    assert_eq!(header(&b).state(), served.header().unwrap().state());
    set_kdf_profile(KdfProfile::Real);
}

/// How a PC without keys takes another PC's keys-on file: by USB behind
/// that PC's code, from the server behind it, or from the server without it
/// ('코드 없이 이 서버를 믿고 받기…').
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Took {
    Usb,
    ServerCode,
    ServerNoCode,
}
/// A vault made without security keys and synced on two PCs (from a 0.8
/// pair and from a GOYOKE03): A turns keys on, then key-file sync on. B,
/// still on its password-only key file, has neither [받기…] nor an unlock
/// touch: it is told KeyChangedServerPwOnly (never KeyChangedServer or the
/// USB advice), and its Keys screen offers the server's file
/// (pwonly_server_file). B takes A's GOYOKS01 file by USB or from the
/// server's key view behind A's code (G1), or from the server without it,
/// which a USB file never is and which the write judges again; the touch
/// of one of A's keys states the transport its password-only Reauth
/// cannot. Then it syncs again: both PCs hold the same key-file state,
/// entries and check code, and B's own edit goes up.
#[test]
fn keys_on_then_key_file_sync_reaches_a_password_only_pc() {
    for kf2 in [false, true] {
        for took in [Took::Usb, Took::ServerCode, Took::ServerNoCode] {
            keys_on_then_key_file_sync(kf2, took);
        }
    }
    set_kdf_profile(KdfProfile::Real);
}
fn keys_on_then_key_file_sync(kf2: bool, took: Took) {
    let usb = took == Took::Usb;
    let case = format!("kf2={kf2} took={took:?}");
    let a = Pc::new();
    let mut sa = setup(&a, kf2, false, true);
    let id = sa.id;
    // B: copies of A's pair, syncing with a helper that does key-file sync.
    let b = Pc::new();
    carry(&a, &b);
    fs::create_dir(dir(&b)).unwrap();
    status(&b);
    let mut sb = login(&b, OLD).unwrap();
    sb.enable_sync().unwrap();
    polls(&mut sb);
    drop(sb);

    // A: keys on (PIN mode, as the app registers them), its gate question
    // answered yes; then key-file sync on, once goyo-sync has looked.
    a.here();
    let mut keys = Keys::new();
    let new_keys = vec![keys.register(&id, 1, true), keys.register(&id, 2, true)];
    let r = sa.reauth(OLD, None).unwrap();
    let on = Change::KeysOn {
        pin: true,
        keys: new_keys,
        new_password: None,
    };
    assert_eq!(
        sa.rekey(r, Vec::new(), on, Consent::default(), true),
        Ok(Rekeyed::Done),
        "{case}"
    );
    let mut server = KeyServer::default();
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeySyncOn),
        Ok(Rekeyed::Done),
        "{case}"
    );
    server.pass(&a, &id);
    polls(&mut sa);
    assert_eq!(sa.server_class(), Some(KeyClass::Equal), "{case}");
    assert_eq!(header(&a).magic, Magic::Ks01, "{case}");
    assert!(uploads(&a, &mut sa, "from a"), "{case}");
    let out = fs::read(dir(&a).join(OUTGOING)).unwrap();
    let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
    let incoming = syncfile::render_incoming(5, copy).unwrap();

    // B: goyo-sync brought the vault copy and the key view.
    b.here();
    server.pass(&b, &id);
    syncfile::replace_file(&dir(&b).join(syncfile::INCOMING), &incoming).unwrap();
    let mut sb = login(&b, OLD).unwrap();
    let mut told: Vec<SyncNotice> = sb.take_unlock_notice().into_iter().collect();
    told.extend(polls(&mut sb));
    assert!(
        told.contains(&SyncNotice::KeyChangedServerPwOnly),
        "{case}: {told:?}"
    );
    assert!(
        !told.iter().any(|n| matches!(
            n,
            SyncNotice::KeyChangedServer | SyncNotice::KeyChanged { .. }
        )),
        "{case}: {told:?}"
    );
    // The Keys screen offers the server's file; A, with keys, has none.
    assert_eq!(sb.pwonly_server_file(), Some(header(&a).epoch), "{case}");
    assert_eq!(sa.pwonly_server_file(), None, "{case}");
    // The server's key file, or A's on a stick, behind A's code or (from
    // the server only) without it, with a touch of one of A's keys.
    let (f, seq) = sb.server_key_file().expect("the server's key file");
    let (f, source) = if usb {
        let path = b.file("from-a.goyokey");
        fs::copy(a.key(), &path).unwrap();
        (KeyFile::read(&path).unwrap(), Source::File(path))
    } else {
        (f, Source::Server { seq })
    };
    let mut check = sb.adopt_check(&f, source.clone()).unwrap();
    assert_eq!(
        (check.class, check.keys.gate),
        (AdoptClass::Successor, Some(GateKind::G1)),
        "{case}"
    );
    // A 0.8 PC's unlock was a bootstrap: no take without a code before it
    // trusts its own key file (S-TOFU-LEGACY, '코드 없이 이 열쇠 파일
    // 믿기…'); A's code takes A's file even so.
    assert_eq!(sb.tofu(), !kf2, "{case}");
    if sb.tofu() {
        assert!(!sb.trusts_without_code(&check), "{case}");
        if took == Took::ServerNoCode {
            sb.tofu_confirm(None).unwrap();
            assert!(!sb.tofu(), "{case}");
            check = sb.adopt_check(&f, source).unwrap();
        }
    }
    assert_eq!(
        sb.trusts_without_code(&check),
        took == Took::ServerNoCode || (!usb && kf2),
        "{case}"
    );
    let nocode = GatePass::NoCode {
        epoch: check.other.epoch,
        tag: check.other.tag,
    };
    let pass = match took {
        Took::ServerNoCode => nocode.clone(),
        _ => GatePass::G1Passed {
            code: code_of(&sa),
            epoch: check.other.epoch,
            tag: check.other.tag,
        },
    };
    let before = fs::read(b.key()).unwrap();
    let plan = |sb: &mut Session, pass: GatePass| {
        let r = sb.reauth(OLD, None).unwrap();
        let t = touch_other(&f, &keys, 2);
        let opened = sb.adopt_open_with(&r, &f, None, Some(&t)).unwrap();
        let plan = sb.adopt_preview_with(&r, &f, opened, &check, pass, ForkOption::Both);
        (r, plan)
    };
    // A USB file is never taken without the code.
    if usb {
        let (_, planned) = plan(&mut sb, nocode.clone());
        assert_eq!(planned.err(), Some(NOT_TRUSTED), "{case}");
        assert_eq!(fs::read(b.key()).unwrap(), before, "{case}");
    }
    // Without the code, judged again at the write: the server's view gone
    // since the preview writes nothing; back again, the same take lands.
    if took == Took::ServerNoCode {
        let (r, planned) = plan(&mut sb, pass.clone());
        let planned = planned.unwrap();
        let acked = acks(planned.preview(), ForkOption::Both);
        let view = fs::read(dir(&b).join(KEY_VIEW)).unwrap();
        fs::remove_file(dir(&b).join(KEY_VIEW)).unwrap();
        sb.poll_sync();
        assert!(!sb.trusts_without_code(&check), "{case}");
        let written = sb.adopt(r, planned, Vec::new(), acked, Consent::default(), false);
        assert_eq!(written.err(), Some(NOT_TRUSTED), "{case}");
        assert_eq!(fs::read(b.key()).unwrap(), before, "{case}");
        syncfile::replace_file(&dir(&b).join(KEY_VIEW), &view).unwrap();
        sb.poll_sync();
        assert!(sb.trusts_without_code(&check), "{case}");
    }
    let (r, planned) = plan(&mut sb, pass);
    let planned = planned.unwrap();
    let acks = acks(planned.preview(), ForkOption::Both);
    let adopted = sb
        .adopt(r, planned, Vec::new(), acks, Consent::default(), false)
        .unwrap();
    assert!(!adopted.trusted, "{case}");
    assert_eq!(sb.pwonly_server_file(), None, "{case}");
    assert!(!sb.tofu(), "{case}");
    assert_eq!(header(&b).state(), header(&a).state(), "{case}");
    assert_eq!(header(&b).magic, Magic::Ks01, "{case}");
    // Synced again: the copy merges, B's edit goes up.
    let told = polls(&mut sb);
    assert!(
        !told.iter().any(|n| matches!(
            n,
            SyncNotice::KeyChangedServer | SyncNotice::KeyChanged { .. } | SyncNotice::KeyFork
        )),
        "{case}: {told:?}"
    );
    assert_eq!(sb.server_class(), Some(KeyClass::Equal), "{case}");
    assert!(has(&sb, "from a"), "{case}");
    assert!(uploads(&b, &mut sb, "from b"), "{case}");
    let out = fs::read(dir(&b).join(OUTGOING)).unwrap();
    let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
    let incoming = syncfile::render_incoming(6, copy).unwrap();
    a.here();
    syncfile::replace_file(&dir(&a).join(syncfile::INCOMING), &incoming).unwrap();
    polls(&mut sa);
    assert!(has(&sa, "from b"), "{case}");
    assert_eq!(sa.check_code(), sb.check_code(), "{case}");
    drop(sb);
    // B's pair now opens with a key.
    let s = open(&b, OLD, &keys, 1).unwrap();
    assert!(has(&s, "from b"), "{case}");
    drop(s);
    // A turns keys off: its key file has no keys again. A view whose top
    // is still A's own older file (the helper answered the off with a
    // conflict) offers it nothing to take.
    a.here();
    let on = fs::read(a.key()).unwrap();
    assert_eq!(
        rekey(&mut sa, &keys, 1, Change::KeysOff),
        Ok(Rekeyed::Done),
        "{case}"
    );
    assert!(sa.keys_overview().is_none(), "{case}");
    let mut view = KeyView {
        seq: 99,
        ..Default::default()
    };
    view.record = render_record_header(RecordKind::Key, false, 0, header(&b).epoch).to_vec();
    view.record.extend_from_slice(&on);
    if let Some(req) = kreq(&a) {
        view.outcome = KeyOutcome::Conflict;
        view.answered = Some(sha256(&req));
    }
    syncfile::replace_file(&dir(&a).join(KEY_VIEW), &render_key_view(&view)).unwrap();
    sa.poll_sync();
    let (old, _) = sa.server_key_file().expect("A's record from before");
    assert!(old.needs_security_key(), "{case}");
    assert_eq!(sa.pwonly_server_file(), None, "{case}");
}
