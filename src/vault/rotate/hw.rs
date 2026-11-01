//! The key changes of a key file with security keys (spec v3 §5.5, feature
//! `security-key`): keys on, one more key, a removal with one touch, a
//! pairing, new seeds for every key, keys off, and a password change of such
//! a file. Each is built and verified in memory by the write procedure
//! W1-W10 and written through the rotation engine's steps (`land`, S0-S5),
//! so a crash anywhere leaves a pair that opens. Also the vault made with
//! keys (§5.9), the Reauth's touched key (§5.3) and the unlock's own pair
//! records (§5.2 step 9(c)).
//!
//! Who can open what after a write authorized by key a: every touched key
//! through its own S-wrap, every absent key that one of a's pair records
//! reaches through the inbox key that record carries, and no other key
//! (P-INV). A key that nothing reaches gets no S-wrap: a removal suspends it
//! with the user's consent, every other write refuses.
use super::{
    super::{
        FileLock, KeyFile, Provision, Session, anchor, atomic_write, distinct,
        keyfile::{
            self, Bundle, EPOCH_LIMIT, EPOCH_MAX, KeyHeader, Kind, Magic, PairPlan, Plan,
            SECURITY_KEY_NEEDED, SUSPENDED_ORPHAN, Secret, SlotPublic, Spec, TOMB_MAX,
            TOMBSTONES_FULL, Tombstone, Touch,
            inbox::{inbox_key, touch_output},
            key_id,
        },
        normalized, password_policy, refuse,
    },
    Built, Change, Consent, KEY_CHANGED, NOT_VERIFIED, REAUTH_STALE, Reauth, Rekeyed, SAMEPASS,
    Step, fresh_pw_id, point, rotated,
};
use crate::{
    crypto::{self, AUTH_ERROR, Key, Result, ct_eq},
    fido::{self, AssertRequest, NewKey, salt},
};
use zeroize::Zeroizing;

/// The anchor keeps the last this many `sup` entries (spec §5.10).
const SUP_MAX: usize = 16;
/// S-UNREACHABLE, filled with the keys no touched key reaches.
pub const UNREACHABLE: &str = "보안 키 {list}은(는) 지금 터치한 키와 짝을 맺지 않아 새 열쇠 파일을 받을 수 없습니다. 그 키도 연결해 함께 터치하거나, 모든 키와 짝을 맺은 키로 하세요.";
/// S-OLDSLOT: a pairing or re-seed touch that does not prove its key.
pub const OLDSLOT: &str =
    "이 보안 키의 응답이 이 열쇠 파일과 맞지 않습니다. 이 키를 빼고 나중에 다시 등록하세요.";
/// S-REACH-CHANGED: a removal would suspend keys the user did not agree to.
pub const REACH_CHANGED: &str = "보안 키 {list}에 새 열쇠를 전할 짝 기록이 열리지 않아 저장하지 않았습니다. 아무것도 바뀌지 않았습니다. '열쇠 관리'에서 짝 기록 상태를 확인한 뒤 다시 하세요.";
/// S-REPAIR-AUTH, filled with the broken record's owner and target, three
/// times.
pub const REPAIR_AUTH: &str = "이 변경은 망가진 짝 기록(보안 키 {o} → 보안 키 {t})을 고칩니다. 다른 PC가 이 수리를 받으려면 보안 키 {o}나 {t}가 승인해야 하는데, 두 키 모두 이번에 터치하지 않은 키에 닿지 않습니다. 먼저 보안 키 {o}, {t} 둘만 '짝 맺기'를 하거나, 빠진 키도 함께 터치하세요. 아무것도 바뀌지 않았습니다.";
/// S-ANCHOR-FAILED: a security-key vault changes no key without its line.
pub const ANCHOR_FAILED: &str = "이 PC의 열쇠 기록(goyo-vault.keys)을 읽거나 쓸 수 없습니다. 보안 키 금고는 이 기록 없이 열쇠를 바꾸거나 받거나 서버에 올리지 않습니다. %LOCALAPPDATA%\\GoyoVault 폴더의 쓰기 권한을 확인하세요.";
/// A key change the flow should never have offered for this key file: a
/// key that is not live, one touched twice, the wrong number of keys.
pub const NOT_PLANNED: &str =
    "이 열쇠 변경은 지금 열쇠 파일과 맞지 않아 쓰지 않았습니다. 아무것도 바뀌지 않았습니다.";
/// S-REMOVE-UNDONE, filled with the removed keys' numbers: a removal that
/// never landed (spec §5.2 step 7, §5.6 C0b-C3).
pub const REMOVE_UNDONE: &str = "지난번 보안 키 {list} 제거가 저장 중에 끊겨 끝나지 않았습니다. 이 PC는 아직 보호되지 않습니다. [다시 하기]로 같은 내용으로 다시 하세요.";

/// The touched key of a Reauth of a key file with security keys (spec
/// §5.3): S, the key's output for its seed (`H_a`, which opens its pair
/// records at a write), which key it is and the keys its records reach.
/// Zeroized on drop.
pub(super) struct Authorizer {
    s: Secret,
    h: Box<Key>,
    credhash: [u8; 16],
    number: u8,
    reach: Vec<u8>,
    /// The touch's transport, which assertions from version 4 on state
    /// (spec §7.9: key-file sync needs it).
    transport: Option<u32>,
}
impl Reauth {
    /// The transport the Reauth's touch stated (USB or NFC), or None.
    pub fn transport(&self) -> Option<u32> {
        self.keys
            .as_ref()
            .map_or(self.bare_transport, |k| k.transport)
    }
    /// The keys a write authorized by this Reauth's key reaches through
    /// its own pair records, itself included, as numbers (spec §5.3,
    /// S45-2 #6): the flow compares them with its plan.
    pub fn reach(&self) -> &[u8] {
        self.keys.as_ref().map_or(&[], |k| &k.reach)
    }
    /// The number of the key this Reauth was touched with.
    pub fn key(&self) -> Option<u8> {
        self.keys.as_ref().map(|k| k.number)
    }
}

/// Whether the PIN or password may be known to someone else (S-LOST-EXPOSE).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exposure {
    Yes,
    No,
    Unsure,
}
/// What the lost-key flow knows of a loss (spec §5.5): its day (None:
/// unknown), the exposure answer, and the keys that share the exposed PIN.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LossReport {
    /// Unix seconds of the day the key was lost.
    pub date: Option<u64>,
    pub exposure: Exposure,
    pub shared_pin: Vec<u8>,
}
impl LossReport {
    /// The loss mark of a tombstone (spec §4.1): 1 for an unknown day, else
    /// the day counted from 1970-01-01 plus 2; a day past the mark's range
    /// is stored as unknown.
    fn mark(&self) -> u64 {
        self.date
            .map(|d| d / 86_400 + 2)
            .filter(|m| *m <= u64::from(u16::MAX))
            .unwrap_or(1)
    }
    /// The header's `loss`: the day's Unix seconds, or 1 when unknown.
    fn header(&self) -> u64 {
        self.date.map_or(1, |d| d.max(2))
    }
}

/// Which flow [다시 하기] (`LOST_REDO`, spec §9.2) reopens for a removal
/// that never landed: the one its pending entry's `src` names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedoFlow {
    /// "잃어버린 키 제거", with the pick and the loss report.
    Lost,
    /// "키 빼기", with the same keys.
    Retire,
    /// "새 열쇠 파일 받기" (an adopt or an accept): the file is picked
    /// again; never a removal of this PC's own.
    Adopt,
}
/// A removal that never landed (S-REMOVE-UNDONE, spec §5.2 step 7): what
/// [다시 하기] fills the reopened screen with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Redo {
    pub flow: RedoFlow,
    /// The removed keys' numbers.
    pub remove: Vec<u8>,
    /// The lost-key flow's loss date, exposure answer and shared-PIN keys.
    pub loss: Option<LossReport>,
}
impl Redo {
    /// What a dropped pending entry asks [다시 하기] to reopen; None for
    /// any other source (S-NOTFINISHED).
    pub(in crate::vault) fn of(p: &anchor::PendingLine) -> Option<Self> {
        let flow = match p.src {
            anchor::Src::Lost => RedoFlow::Lost,
            anchor::Src::Retire => RedoFlow::Retire,
            anchor::Src::Adopt | anchor::Src::Accept => RedoFlow::Adopt,
            _ => return None,
        };
        let remove: Vec<u8> = p.rm.iter().map(|(n, _)| *n).collect();
        if remove.is_empty() {
            return None;
        }
        let loss = (flow == RedoFlow::Lost).then(|| LossReport {
            date: p.loss.as_deref().and_then(super::super::review::day_of),
            exposure: match p.exp {
                Some(b'y') => Exposure::Yes,
                Some(b'u') => Exposure::Unsure,
                _ => Exposure::No,
            },
            shared_pin: p.clone.clone(),
        });
        Some(Self { flow, remove, loss })
    }
}

/// One key's entry of a re-seed (spec §5.5): its number, its new seed and
/// its output for that seed. Built only by `ReSeedPlan`; zeroized on drop.
pub struct ReSeedKey {
    number: u8,
    seed_new: [u8; 32],
    h_new: Box<Key>,
}
/// A key of a re-seed between its ceremonies.
struct Planned {
    number: u8,
    cred_id: Vec<u8>,
    seed: [u8; 32],
    seed_new: [u8; 32],
    /// Its old output opened its S-wrap (or one of its pair records).
    proved: bool,
    h_new: Option<Box<Key>>,
    /// The new-seed output came from a touch of its own (the 2-touch
    /// fallback of spec §8.3), which needs no confirmation.
    second: bool,
}
/// A re-seed of every live key (spec §5.5, §9.2): a fresh seed per key,
/// then per key a 2-salt touch whose `first` proves the key and whose
/// `second` is its new output, then one confirmation touch. Zeroized on
/// drop.
pub struct ReSeedPlan {
    session: u64,
    vault_id: [u8; 16],
    pin: bool,
    keys: Vec<Planned>,
    confirmed: bool,
}
impl ReSeedPlan {
    /// The allow list of the next 2-salt ceremony: every key not yet
    /// proved, each with its old and its new seed's salt.
    pub fn request(&self, owner: isize) -> Result<AssertRequest> {
        let allow = self
            .keys
            .iter()
            .filter(|k| !k.proved)
            .map(|k| {
                let (old, new) = (
                    salt(&self.vault_id, &k.seed),
                    salt(&self.vault_id, &k.seed_new),
                );
                (k.cred_id.clone(), old, Some(new))
            })
            .collect();
        AssertRequest::new(owner, allow, self.pin)
    }
    /// The allow list of the first 2-salt ceremony, whose touch is also the
    /// flow's Reauth (spec §9.2 re-seed step 3, §9.2a "for an authorizer,
    /// not suspended"): the keys of `active` (the live, non-suspended ones)
    /// only, since a suspended key cannot open the key file.
    pub fn first_request(&self, active: &[u8], owner: isize) -> Result<AssertRequest> {
        let allow = self
            .keys
            .iter()
            .filter(|k| !k.proved && active.contains(&k.number))
            .map(|k| {
                let (old, new) = (
                    salt(&self.vault_id, &k.seed),
                    salt(&self.vault_id, &k.seed_new),
                );
                (k.cred_id.clone(), old, Some(new))
            })
            .collect();
        AssertRequest::new(owner, allow, self.pin)
    }
    /// The allow list of a new-seed-only ceremony of key `number`: the
    /// confirmation, or the fallback's second touch.
    pub fn second_request(&self, number: u8, owner: isize) -> Result<AssertRequest> {
        let k = self.planned(number).ok_or(NOT_PLANNED)?;
        let allow = vec![(k.cred_id.clone(), salt(&self.vault_id, &k.seed_new), None)];
        AssertRequest::new(owner, allow, self.pin)
    }
    fn planned(&self, number: u8) -> Option<&Planned> {
        self.keys.iter().find(|k| k.number == number)
    }
    /// A 2-salt touch (spec §9.2 re-seed steps 3-4): `first` must prove its
    /// key in the session's key file (else S-OLDSLOT), and `second` is
    /// recorded as its new output. Without `second` the key is proved and
    /// waits for `take_second`. Returns the key's number.
    pub fn take(&mut self, s: &Session, r: &Reauth, t: &Touch) -> Result<u8> {
        if self.session != s.serial || r.session != s.serial {
            return Err(REAUTH_STALE);
        }
        let number = s.check_touch(r, t)?;
        let vault_id = self.vault_id;
        let k = self
            .keys
            .iter_mut()
            .find(|k| k.number == number)
            .ok_or(NOT_PLANNED)?;
        k.proved = true;
        match t.output_for(&k.seed_new, &vault_id) {
            Some(new) => (k.h_new, k.second) = (Some(super::super::boxed(new)), false),
            None if t.second_missing() => {}
            None => return Err(fido::BAD_ANSWER),
        }
        Ok(number)
    }
    /// The fallback's new-seed touch of a key `take` already proved.
    pub fn take_second(&mut self, s: &Session, r: &Reauth, t: &Touch) -> Result<u8> {
        if self.session != s.serial || r.session != s.serial {
            return Err(REAUTH_STALE);
        }
        let h = s.key_file.header().ok_or(NOT_PLANNED)?;
        let k = self
            .keys
            .iter_mut()
            .find(|k| k.proved && k.cred_id == t.cred_id)
            .ok_or(NOT_PLANNED)?;
        let mut slot = h
            .slots
            .iter()
            .find(|x| x.number == k.number)
            .ok_or(NOT_PLANNED)?
            .clone();
        slot.seed = k.seed_new;
        let new = touch_output(t, &slot, h)?;
        (k.h_new, k.second) = (Some(super::super::boxed(new)), true);
        Ok(k.number)
    }
    /// The confirmation touch (S-RESEED-CONFIRM): a key's new-seed output
    /// again, equal to the one recorded (else S-NONDETERMINISTIC).
    pub fn confirm(&mut self, t: &Touch) -> Result<()> {
        let k = self
            .keys
            .iter()
            .find(|k| k.cred_id == t.cred_id)
            .ok_or(NOT_PLANNED)?;
        let new = t
            .output_for(&k.seed_new, &self.vault_id)
            .ok_or(fido::BAD_ANSWER)?;
        let recorded = k.h_new.as_deref().ok_or(NOT_PLANNED)?;
        if !ct_eq(new, recorded.as_slice()) {
            return Err(fido::NONDETERMINISTIC);
        }
        self.confirmed = true;
        Ok(())
    }
    /// Every live key exactly once, proved, with its new output, and the
    /// confirmation made (or every new output from a touch of its own).
    pub fn finish(self) -> Result<Vec<ReSeedKey>> {
        let complete = self.keys.iter().all(|k| k.proved && k.h_new.is_some());
        if !complete || !(self.confirmed || self.keys.iter().all(|k| k.second)) {
            return Err(NOT_PLANNED);
        }
        let mut out = Vec::with_capacity(self.keys.len());
        for k in self.keys {
            let Some(h_new) = k.h_new else {
                return Err(NOT_PLANNED);
            };
            out.push(ReSeedKey {
                number: k.number,
                seed_new: k.seed_new,
                h_new,
            });
        }
        Ok(out)
    }
}

/// What S0 records beside the state a write of this build becomes (spec
/// §5.5 S0): that this PC wrote it (`t`), the keys its user removed here
/// (origin `o`), the lost-key flow's answers, and the pair records W5 found
/// broken or rewrote.
#[derive(Default)]
pub(in crate::vault) struct Landing {
    /// The write starts from or ends in a security-key state: the anchor
    /// line is mandatory, with no in-memory fallback (S45-1 #2).
    pub(super) strict: bool,
    removed: Vec<(u8, [u8; 16])>,
    loss: Option<String>,
    exp: Option<u8>,
    clone: Vec<u8>,
    broken: Vec<([u8; 4], [u8; 4])>,
    fixed: Vec<([u8; 4], [u8; 4])>,
    /// A fork union's option (spec §5.8).
    opt: Option<u8>,
    /// `ks` of this write (spec §7.16 "Which writes set `ks`"); None copies
    /// the confirmed line's.
    pub(super) ks: Option<anchor::Ks>,
    /// `clears=g`: an off clears a pending gate unconditionally (S6R1 #2),
    /// an accept the gate of the file it takes.
    pub(super) clear_gate: bool,
    /// The server file this write merges in, takes or clears the gate of
    /// (`merged`, spec §5.5 S0).
    pub(super) merged: Option<(u64, [u8; 16])>,
    /// `clears=s`: a supersede marks its candidate's gate line superseded
    /// (spec §7.15a).
    pub(super) supersede: bool,
    /// The take trusted the server instead of asking its gate (spec
    /// §2.30): no `clears=2`, so a G2 turned off stays off (a write the
    /// server made this PC do never turns it back on, §7.15a).
    pub(super) trusted: bool,
    /// `sup`: the candidate's data-key IDs this PC lacks, each with the
    /// candidate's state, so a vault head under that state is pushed over
    /// at every unlock (spec §5.10, §7.1).
    pub(super) sup: Vec<anchor::Sup>,
}
impl Landing {
    /// The entry `p` of the state `kh` written over this PC's key file
    /// `own`. An adopt also records this PC's keys the result removes (R):
    /// taken from the other file (`rm` origin `t`), and when a tombstone of
    /// R carries a loss mark, the earliest date as its `loss`, which makes
    /// the review due (spec §5.13; the marks decide, not the file's own
    /// `loss`). A dropped adopt of a removal is then told as one.
    pub(super) fn apply(
        &self,
        p: &mut anchor::PendingLine,
        own: Option<&KeyHeader>,
        kh: &KeyHeader,
    ) {
        p.state.flags.t = true;
        p.opt = self.opt;
        // The rollout reminder is for a change this PC made, not for one it
        // took or merged (spec §7.18).
        p.state.flags.p = p.state.magic == *Magic::Ks01.bytes()
            && matches!(p.kind, 2 | 3 | 4 | 5 | 6 | 8)
            && p.src != anchor::Src::Adopt;
        if let Some(ks) = self.ks {
            p.state.ks = ks;
        }
        p.clears.g |= self.clear_gate;
        p.clears.s |= self.supersede;
        if self.trusted {
            p.clears.two = false;
        }
        if self.merged.is_some() {
            p.merged = self.merged;
        }
        // The last 16 `sup` entries, the newest last, one per key ID.
        for e in &self.sup {
            p.state.sup.retain(|x| x.keyid != e.keyid);
            p.state.sup.push(*e);
        }
        let extra = p.state.sup.len().saturating_sub(SUP_MAX);
        p.state.sup.drain(..extra);
        for t in &mut p.state.tombs {
            if self.removed.iter().any(|(_, c)| *c == t.credhash) {
                t.origin = anchor::Origin::Own;
            }
        }
        p.rm = self
            .removed
            .iter()
            .map(|(n, _)| (*n, anchor::Origin::Own))
            .collect();
        (p.loss, p.exp, p.clone) = (self.loss.clone(), self.exp, self.clone.clone());
        if p.src == anchor::Src::Adopt {
            let dead = |c: &[u8; 16]| kh.tombstones.iter().any(|t| t.credhash == *c);
            let taken: Vec<&SlotPublic> = own
                .map_or(&[][..], |h| &h.slots)
                .iter()
                .filter(|s| dead(&s.credhash))
                .collect();
            p.rm.extend(taken.iter().map(|s| (s.number, anchor::Origin::Taken)));
            let removed: Vec<[u8; 16]> = taken.iter().map(|s| s.credhash).collect();
            p.loss = p
                .loss
                .take()
                .or_else(|| super::super::review::loss_of(&removed, &kh.tombstones));
        }
        let mut pbad: Vec<([u8; 4], [u8; 4])> = p
            .state
            .pbad
            .iter()
            .filter(|e| !self.fixed.contains(e))
            .copied()
            .collect();
        pbad.extend(self.broken.iter().copied());
        pbad.sort_unstable();
        pbad.dedup();
        p.state.pbad = pbad;
    }
}

/// The pair records a key owns, as `open_pairs` read them with its output:
/// each target's credhash and the inbox key the record carries.
type Records = Vec<([u8; 16], Option<Box<Key>>)>;
/// What a write with keys becomes, before W4-W10 (spec §5.5 R1).
struct Target {
    kind: Kind,
    /// A new data key: V_probe and `resume`.
    rotate: bool,
    password: Zeroizing<String>,
    /// The password was typed in this flow: a fresh `pw_id`, `pw = n`.
    new_password: bool,
    /// A fresh `pw_id` for another reason: a conversion from 0.8.
    fresh_pw_id: bool,
    sync: bool,
    pin: bool,
    /// The result's live keys, ascending by number.
    slots: Vec<SlotPublic>,
    /// The output of every present key for its seed in the result.
    present: Vec<([u8; 16], Box<Key>)>,
    /// The key that authorizes the write, unless a repair names another.
    authorizer: [u8; 16],
    tombstones: Vec<Tombstone>,
    next: u8,
    loss: u64,
    /// A removal: keys nothing reaches are suspended, with consent.
    suspends: bool,
    /// A removal for a loss: a repair never stops it (S45-3 #6).
    lost: bool,
    landing: Landing,
    src: anchor::Src,
}

/// The anchor can be written for a new vault `id` (spec §5.9): a locked
/// read and a rewrite of the file as it is.
pub(in crate::vault) fn probe_anchor(id: &[u8; 16]) -> Result<()> {
    let dir = anchor::locate().ok_or(ANCHOR_FAILED)?;
    match anchor::update(&dir, id, anchor::LOCK_WAIT, &mut |_| true) {
        Ok(_) => Ok(()),
        Err(anchor::Failure::Newer) => Err(anchor::ANCHOR_NEWER),
        Err(_) => Err(ANCHOR_FAILED),
    }
}

/// The slot record of a key registered in this flow.
fn slot_of(key: &NewKey, number: u8, epoch: u64, added_by: [u8; 16]) -> SlotPublic {
    let flags = u8::from(key.uv) | u8::from(key.cp3) << 1;
    SlotPublic::new(
        flags,
        number,
        key.registered,
        epoch,
        added_by,
        key.seed,
        key.cred_id.clone(),
    )
}
/// The number of a key added now (spec §5.5 R1): `next`, or once numbers
/// would pass 255 the lowest free one; and `next` after it.
fn new_number(next: u8, used: &[u8]) -> Option<(u8, u8)> {
    if next >= 1 && !used.contains(&next) {
        return Some((next, next.saturating_add(1)));
    }
    let free = (1..=255).find(|n| !used.contains(n))?;
    Some((free, next))
}
fn listed(numbers: &[u8]) -> String {
    numbers
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
fn short(credhash: &[u8; 16]) -> [u8; 4] {
    anchor::prefix(credhash)
}
/// New keys for a key file whose numbers `used` are taken: distinct
/// credentials no slot or tombstone of it names, in PIN mode only PIN
/// slots, numbered from `next`. The slots and `next` after them.
fn new_slots(
    keys: &[NewKey],
    h: Option<&KeyHeader>,
    pin: bool,
    epoch: u64,
) -> Result<(Vec<SlotPublic>, u8)> {
    let mut used: Vec<u8> = h
        .map(|h| h.slots.iter().map(|s| s.number).collect())
        .unwrap_or_default();
    let mut next = h.map_or(1, |h| h.next);
    let mut out: Vec<SlotPublic> = Vec::with_capacity(keys.len());
    for key in keys {
        let (number, after) = new_number(next, &used).ok_or(NOT_PLANNED)?;
        let slot = slot_of(key, number, epoch, [0; 16]);
        let known = h.is_some_and(|h| {
            h.slots.iter().any(|s| s.credhash == slot.credhash)
                || h.tombstones.iter().any(|t| t.credhash == slot.credhash)
        });
        if known || out.iter().any(|s| s.credhash == slot.credhash) {
            return Err(fido::EXISTS);
        }
        if pin && slot.flags != 3 {
            return Err(NOT_PLANNED);
        }
        used.push(number);
        next = after;
        out.push(slot);
    }
    Ok((out, next))
}

/// Writes the new vault with security keys (spec §5.9): GOYOKH01 at epoch
/// 1 with every key present and every ordered pair of them paired, verified
/// through each key's output; the anchor's pending line with `t` first,
/// then the key file, then the vault file (GOYOVA03, flags 1), then the
/// line promoted. A crash after the vault file leaves the line for the next
/// unlock (crash row C16).
pub(in crate::vault) fn create_with_keys(
    p: &Provision,
    (vault, key_path): (&std::path::Path, &std::path::Path),
    password: &str,
    otp_step: Option<u64>,
    pin: bool,
    keys: Vec<NewKey>,
) -> Result<Session> {
    password_policy(password)?;
    if !(1..=8).contains(&keys.len()) {
        return Err(NOT_PLANNED);
    }
    let vault = normalized(vault)?;
    let key_path = normalized(key_path)?;
    distinct(&vault, &key_path)?;
    if vault.exists() || key_path.exists() {
        return Err("새 금고와 열쇠 파일은 기존 파일을 덮어쓸 수 없습니다.");
    }
    let (slots, next) = new_slots(&keys, None, pin, 1)?;
    let locks = vec![FileLock::acquire(&vault)?];
    let otp = otp_step.map(|_| &**p.otp);
    let bundle = Bundle::new(std::slice::from_ref(&**p.key), otp).ok_or(AUTH_ERROR)?;
    let s = Secret::random()?;
    let spec = Spec {
        vault_id: p.id,
        epoch: 1,
        kind: Kind::KeysOn,
        next,
        pw_id: fresh_pw_id()?,
        loss: 0,
        tombstones: Vec::new(),
        resume: [0; 32],
    };
    let pairs = every_pair(&slots);
    let plan = keyfile::KeysPlan {
        sync: false,
        pin,
        s: &s,
        slots,
        authorizer: 0,
        present: all(keys.len()),
        suspended: 0,
        pairs,
        outputs: keys
            .iter()
            .enumerate()
            .map(|(j, k)| (j as u8, &**k.output))
            .collect(),
        inbox: Vec::new(),
    };
    let (bytes, writer) = keyfile::seal(&spec, &bundle, password, Plan::Keys(&plan))?;
    let file = KeyFile::from_bytes(&key_path, bytes).map_err(|_| NOT_VERIFIED)?;
    let kh = file.header().ok_or(NOT_VERIFIED)?.clone();
    let opened = file.verify_keys(&writer, &plan).map_err(|_| NOT_VERIFIED)?;
    drop(writer);
    if kh.magic != Magic::Kh01 || kh.spec() != spec || !opened.bundle.same(&bundle) {
        return Err(NOT_VERIFIED);
    }
    let mut session = Session::new(vault, key_path, p.id, opened.bundle, file, kh.state());
    session.last = otp_step.unwrap_or(0);
    session._locks = locks;
    session.serial = u64::from_le_bytes(*crypto::random::<8>()?);
    session.anchor.dir = anchor::locate();
    // S0: the line this state becomes, with `t`, before any file.
    let mut pending = anchor::pending_of(&kh, None, None, anchor::kpath_of(&session.key_path));
    let landing = Landing {
        strict: true,
        ..Landing::default()
    };
    landing.apply(&mut pending, None, &kh);
    {
        let _step = Step::enter("S0");
        session.anchor_strict(&mut |lines| {
            lines.pending = Some(pending.clone());
            true
        })?;
    }
    point("S0")?;
    let data = session.encode()?;
    {
        let _step = Step::enter("S2");
        if let Err(e) = atomic_write(&session.key_path, session.key_file.bytes(), false) {
            let e: &'static str = e.into();
            if !super::crashed(e) {
                session.drop_pending(kh.state());
            }
            return Err(e);
        }
    }
    point("S2v")?;
    {
        let _step = Step::enter("S3");
        if let Err(e) = session.write_with(&data, false) {
            if !super::crashed(e) {
                let _ = std::fs::remove_file(&session.key_path);
                session.drop_pending(kh.state());
            }
            return Err(e);
        }
    }
    point("S3v")?;
    // S5: promoted, with the vault file sealed under the current key. A
    // failure keeps the promoted line in memory (stage 3's fallback, as at
    // a key change's S5), so the next write of the anchor, a later key
    // change's R0 probe and S0 included, lands it first; a crash leaves the
    // pending line for the next unlock.
    let mut line = pending.promoted(None);
    line.vkey = Some(kh.current_key_id());
    super::before("S5");
    {
        let _step = Step::enter("S5");
        session.anchor_update(anchor::LOCK_WAIT, &mut |lines| {
            if lines.pending.as_ref() == Some(&pending) {
                lines.pending = None;
            }
            lines.vault = Some(line.clone());
            true
        })?;
    }
    point("S5")?;
    session.key_backup_due = true;
    session.entries.shrink_to_fit();
    Ok(session)
}
/// Bit i for each of `n` slots.
fn all(n: usize) -> u8 {
    ((1u16 << n) - 1) as u8
}
/// A new pair record for every ordered pair of `slots`.
fn every_pair(slots: &[SlotPublic]) -> Vec<PairPlan> {
    let mut out = Vec::new();
    for o in slots {
        for t in slots.iter().filter(|t| t.credhash != o.credhash) {
            out.push(PairPlan::New {
                owner: o.credhash,
                target: t.credhash,
            });
        }
    }
    out
}

/// One key as the Keys screen lists it (spec §9.1): from this PC's own key
/// file and anchor, public bytes only.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyRow {
    pub number: u8,
    /// Unix seconds, as its registration's `<STAMP>` shows them.
    pub registered: u64,
    /// The registration's `<STAMP>` (`YYYYMMDD-HHMMSS`, UTC) and its whole
    /// display name `Goyo Vault <TAG> key <N> <STAMP>` (spec §8.3).
    pub stamp: String,
    pub display: String,
    /// Live but without an S-wrap: it opens the key file again only after
    /// a pairing.
    pub suspended: bool,
    /// Suspended and owning no pair record: only a removal and a new
    /// registration help.
    pub orphan: bool,
    /// The anchor flags it "possibly cloned" (spec §5.10 `clone`).
    pub cloned: bool,
    /// The key this session was unlocked with.
    pub opened: bool,
    /// The other live keys it is not paired with both ways, through records
    /// this PC did not find broken.
    pub unpaired: Vec<u8>,
    /// The other keys whose record with it this PC found broken (`pbad`).
    pub broken: Vec<u8>,
}
/// The Keys screen's security-key section (spec §9.1): PIN mode, one row
/// per live key, and the full authorizers (keys that reach every other
/// live, non-suspended key through records not marked broken).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeysOverview {
    pub pin: bool,
    pub rows: Vec<KeyRow>,
    pub full: Vec<u8>,
}
impl KeysOverview {
    /// The live, non-suspended keys.
    pub fn active(&self) -> Vec<u8> {
        self.rows
            .iter()
            .filter(|r| !r.suspended)
            .map(|r| r.number)
            .collect()
    }
}

impl Session {
    /// What the Keys screen shows of this key file's security keys (spec
    /// §9.1): None for a key file without them. The pairing status counts
    /// the public pair records minus those this PC found broken.
    pub fn keys_overview(&self) -> Option<KeysOverview> {
        let h = self.key_file.header().filter(|h| !h.slots.is_empty())?;
        let pbad = self
            .anchor
            .lines
            .vault
            .as_ref()
            .filter(|v| v.state.key_state() == self.key_state)
            .map(|v| v.state.pbad.clone())
            .unwrap_or_default();
        let shorts: Vec<[u8; 4]> = h.slots.iter().map(|s| short(&s.credhash)).collect();
        let broken = |o: usize, t: usize| pbad.contains(&(shorts[o], shorts[t]));
        // Records that deliver: owner → target, not marked broken.
        let delivers = |o: usize, t: usize| {
            h.pairs
                .iter()
                .any(|(a, b)| usize::from(*a) == o && usize::from(*b) == t)
                && !broken(o, t)
        };
        let suspended = |j: usize| (h.suspended >> j) & 1 != 0;
        let tag: String = h.vault_id[..4].iter().map(|b| format!("{b:02X}")).collect();
        let clones = &self.anchor.lines.clones;
        let rows = h
            .slots
            .iter()
            .enumerate()
            .map(|(j, s)| {
                let others = (0..h.slots.len()).filter(|k| *k != j);
                let stamp = fido::stamp(s.registered);
                KeyRow {
                    number: s.number,
                    registered: s.registered,
                    display: format!("Goyo Vault {tag} key {} {stamp}", s.number),
                    stamp,
                    suspended: suspended(j),
                    orphan: suspended(j) && !h.pairs.iter().any(|(o, _)| usize::from(*o) == j),
                    cloned: clones.iter().any(|(c, _)| *c == s.credhash),
                    opened: self.unlocked_with == Some(s.number),
                    unpaired: others
                        .clone()
                        .filter(|k| !(delivers(j, *k) && delivers(*k, j)))
                        .map(|k| h.slots[k].number)
                        .collect(),
                    broken: others
                        .filter(|k| broken(j, *k) || broken(*k, j))
                        .map(|k| h.slots[k].number)
                        .collect(),
                }
            })
            .collect();
        let full = (0..h.slots.len())
            .filter(|a| !suspended(*a))
            .filter(|a| {
                (0..h.slots.len())
                    .filter(|t| t != a && !suspended(*t))
                    .all(|t| delivers(*a, t))
            })
            .map(|a| h.slots[a].number)
            .collect();
        Some(KeysOverview {
            pin: h.pin(),
            rows,
            full,
        })
    }
    /// The vault ID every registration's salt binds (spec §3.2, §8.3).
    pub fn vault_id(&self) -> [u8; 16] {
        self.id
    }
    /// What the registration of `n` keys added to this key file needs
    /// (spec §8.3, §5.5 R1): the numbers they get, in order, and every live
    /// credential, which none of them may register again.
    pub fn add_plan(&self, n: usize) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        let h = self.key_file.header();
        let mut used: Vec<u8> = h
            .map(|h| h.slots.iter().map(|s| s.number).collect())
            .unwrap_or_default();
        let mut next = h.map_or(1, |h| h.next);
        let mut numbers = Vec::with_capacity(n);
        for _ in 0..n {
            let (number, after) = new_number(next, &used).ok_or(NOT_PLANNED)?;
            used.push(number);
            numbers.push(number);
            next = after;
        }
        let exclude = h
            .map(|h| h.slots.iter().map(|s| s.cred_id.clone()).collect())
            .unwrap_or_default();
        Ok((numbers, exclude))
    }
    /// The keys a write authorized by key `number` cannot deliver to (spec
    /// §5.4): the live keys outside its reach, the records this PC found
    /// broken counted as missing, as numbers.
    pub fn unreached(&self, number: u8) -> Vec<u8> {
        let Some(o) = self.keys_overview() else {
            return Vec::new();
        };
        let Some(row) = o.rows.iter().find(|r| r.number == number) else {
            return Vec::new();
        };
        let h = self.key_file.header();
        let reach = h.map(|h| h.reach(number)).unwrap_or_default();
        o.rows
            .iter()
            .map(|r| r.number)
            .filter(|n| *n != number && (!reach.contains(n) || row.broken.contains(n)))
            .collect()
    }
    /// Whether the anchor is mandatory for this session (spec §5.10): its
    /// key file has security keys, or this PC pins the vault as hardware.
    pub(in crate::vault) fn hardware_anchor(&self) -> bool {
        self.key_file.needs_security_key()
            || self
                .anchor
                .lines
                .vault
                .as_ref()
                .is_some_and(|l| l.state.hardware())
    }
    /// Writes this vault's anchor lines through `change` with no in-memory
    /// fallback (spec §5.10: mandatory for security-key sessions):
    /// S-ANCHOR-FAILED, or S-ANCHOR-NEWER for a later version's file, when
    /// it cannot be written. Lines a password-only session held in memory
    /// go first.
    pub(in crate::vault) fn anchor_strict(
        &mut self,
        change: &mut dyn FnMut(&mut anchor::Lines) -> bool,
    ) -> Result<()> {
        if self.anchor.frozen {
            return Err(anchor::ANCHOR_NEWER);
        }
        let dir = self.anchor.dir.clone().ok_or(ANCHOR_FAILED)?;
        let held = self.anchor.unsaved.then(|| self.anchor.lines.clone());
        let result = anchor::update(&dir, &self.id, anchor::LOCK_WAIT, &mut |lines| {
            if let Some(held) = &held {
                lines.vault.clone_from(&held.vault);
                lines.pending.clone_from(&held.pending);
            }
            change(lines) || held.is_some()
        });
        match result {
            Ok(lines) => {
                self.anchor.lines = lines;
                (self.anchor.unsaved, self.anchor_failed) = (false, false);
                Ok(())
            }
            #[cfg(test)]
            Err(anchor::Failure::Crash) => Err(super::super::SIMULATED_CRASH),
            Err(anchor::Failure::Newer) => {
                self.anchor.frozen = true;
                Err(anchor::ANCHOR_NEWER)
            }
            Err(_) => Err(ANCHOR_FAILED),
        }
    }
    /// The touched key of a Reauth (spec §5.3 step 3): S from `opened`,
    /// the key's output, and its own pair records opened (`pbad`, reach).
    /// None for a key file without security keys.
    pub(super) fn authorizer(
        &mut self,
        opened: &keyfile::Opened,
        touch: Option<&Touch>,
    ) -> Result<Option<Authorizer>> {
        let Some(h) = self
            .key_file
            .header()
            .filter(|h| !h.slots.is_empty())
            .cloned()
        else {
            return Ok(None);
        };
        let touch = touch.ok_or(SECURITY_KEY_NEEDED)?;
        let j = usize::from(opened.slot.ok_or(AUTH_ERROR)?);
        let slot = h.slots.get(j).ok_or(AUTH_ERROR)?;
        let out = touch
            .output_for(&slot.seed, &h.vault_id)
            .ok_or(fido::BAD_ANSWER)?;
        let s = Secret::of(opened).ok_or(AUTH_ERROR)?;
        let reach = self.own_pairs(&h, j, out);
        Ok(Some(Authorizer {
            s,
            h: super::super::boxed(out),
            credhash: slot.credhash,
            number: slot.number,
            reach,
            transport: touch.transport,
        }))
    }
    /// Spec §5.2 step 9(c): after an unlock, the pair records of the key it
    /// was touched with, opened with that key's `seal`.
    pub(in crate::vault) fn check_own_pairs(&mut self, touch: &Touch) {
        let Some(h) = self
            .key_file
            .header()
            .filter(|h| !h.slots.is_empty())
            .cloned()
        else {
            return;
        };
        let Some(j) = h.slots.iter().position(|s| s.cred_id == touch.cred_id) else {
            return;
        };
        if let Some(out) = touch.output_for(&h.slots[j].seed, &h.vault_id) {
            self.own_pairs(&h, j, out);
        }
    }
    /// Opens every pair record key `k` owns with its output `out` (at most
    /// 7 unwraps, no Argon2): the keys a write authorized by it reaches, as
    /// numbers, itself included. The records that do not open replace that
    /// key's entries in the anchor's `pbad`, when the confirmed line is this
    /// key file's state (round 2, finding 5); a Restore writes nothing.
    fn own_pairs(&mut self, h: &KeyHeader, k: usize, out: &[u8; 32]) -> Vec<u8> {
        let owner = &h.slots[k];
        let mut reach = vec![owner.number];
        let mut bad = Vec::new();
        for (t, ik) in self.key_file.open_pairs(out, k as u8) {
            let target = &h.slots[usize::from(t)];
            if ik.is_some() {
                reach.push(target.number);
            } else {
                bad.push((short(&owner.credhash), short(&target.credhash)));
            }
        }
        reach.sort_unstable();
        if self.restored {
            return reach;
        }
        let (state, mine) = (self.key_state, short(&owner.credhash));
        let _ = self.anchor_update(anchor::LOCK_WAIT, &mut |lines| {
            let Some(v) = lines
                .vault
                .as_mut()
                .filter(|v| v.state.key_state() == state)
            else {
                return false;
            };
            let mut pbad: Vec<([u8; 4], [u8; 4])> = v
                .state
                .pbad
                .iter()
                .filter(|(o, _)| *o != mine)
                .chain(bad.iter())
                .copied()
                .collect();
            pbad.sort_unstable();
            pbad.dedup();
            let mut old = v.state.pbad.clone();
            old.sort_unstable();
            if pbad == old {
                return false;
            }
            v.state.pbad = pbad;
            true
        });
        reach
    }
    /// The allow list of a ceremony of the keys numbered `numbers` with
    /// their current seeds: a Reauth's, or a pairing's or an extra touch's
    /// (spec §9.2a: the flow picks the keys its plan allows).
    pub fn key_request(&self, numbers: &[u8], owner: isize) -> Result<AssertRequest> {
        let h = self.key_file.header().ok_or(NOT_PLANNED)?;
        let allow = h
            .slots
            .iter()
            .filter(|s| numbers.contains(&s.number))
            .map(|s| (s.cred_id.clone(), salt(&h.vault_id, &s.seed), None))
            .collect();
        AssertRequest::new(owner, allow, h.pin())
    }
    /// The removal that never landed at this unlock, as [다시 하기]
    /// reopens it (S-REMOVE-UNDONE).
    pub fn redo(&self) -> Option<&Redo> {
        self.redo.as_ref()
    }
    /// A key change or adopt landed in this session: [다시 하기] is no
    /// longer offered (the UI only reads it until then).
    pub fn take_redo(&mut self) -> Option<Redo> {
        self.redo.take()
    }
    /// The allow list of an adopt's Reauth touch (spec §9.2 adopt step
    /// 2.4): this key file's live, non-suspended keys, each with a second
    /// salt where `other` registers the same credential under another seed
    /// (a re-seed on one branch, S45-1 #3), so one touch opens both files.
    pub fn adopt_request(&self, other: &KeyFile, owner: isize) -> Result<AssertRequest> {
        let h = self.key_file.header().ok_or(NOT_PLANNED)?;
        let theirs = other.header();
        let allow = h
            .slots
            .iter()
            .enumerate()
            .filter(|(j, _)| (h.suspended >> j) & 1 == 0)
            .map(|(_, s)| {
                let second = theirs
                    .and_then(|t| t.slots.iter().find(|o| o.cred_id == s.cred_id))
                    .filter(|o| o.seed != s.seed)
                    .zip(theirs)
                    .map(|(o, t)| salt(&t.vault_id, &o.seed));
                (s.cred_id.clone(), salt(&h.vault_id, &s.seed), second)
            })
            .collect();
        AssertRequest::new(owner, allow, h.pin())
    }
    /// The keys that open `other`: live and not suspended there, each as
    /// this PC names it (S-OTHERKEY-ONLY; spec §5.8 "Touch", §7.15a).
    pub fn opening_keys(&self, other: &KeyFile) -> Vec<(u8, bool)> {
        other.header().map_or_else(Vec::new, |t| {
            t.slots
                .iter()
                .enumerate()
                .filter(|(j, _)| (t.suspended >> j) & 1 == 0)
                .filter_map(|(_, s)| self.named(other, &s.credhash))
                .collect()
        })
    }
    /// How this PC names the key `credhash` of `other` or of an adopt's
    /// result (spec §7.15a display rule): its own number when this key file
    /// has the credential, else `other`'s number, marked new to this PC
    /// (true). None for a credential neither file has.
    pub fn named(&self, other: &KeyFile, credhash: &[u8; 16]) -> Option<(u8, bool)> {
        let own = self
            .key_file
            .header()
            .and_then(|h| h.slots.iter().find(|s| s.credhash == *credhash));
        if let Some(s) = own {
            return Some((s.number, false));
        }
        other
            .header()?
            .slots
            .iter()
            .find(|s| s.credhash == *credhash)
            .map(|s| (s.number, true))
    }
    /// The allow list of the single-salt touch that opens `other` when the
    /// Reauth touch of this key file's key `number` brought no `pbSecond`
    /// (S-TWOTOUCH; spec §8.3, §9.2 adopt step 2.6, S45-3 #10): the same
    /// credential with `other`'s seed.
    pub fn other_seed_request(
        &self,
        other: &KeyFile,
        number: u8,
        owner: isize,
    ) -> Result<AssertRequest> {
        let mine = self
            .key_file
            .header()
            .and_then(|h| h.slots.iter().find(|s| s.number == number))
            .ok_or(NOT_PLANNED)?;
        let t = other.header().ok_or(NOT_PLANNED)?;
        let s = t
            .slots
            .iter()
            .find(|s| s.cred_id == mine.cred_id)
            .ok_or(NOT_PLANNED)?;
        let allow = vec![(s.cred_id.clone(), salt(&t.vault_id, &s.seed), None)];
        AssertRequest::new(owner, allow, t.pin())
    }
    /// Whether this key file's key `number` opens `other` too: the same
    /// credential live and not suspended there (spec §9.2 adopt step 2.6).
    pub fn opens_other(&self, other: &KeyFile, number: u8) -> bool {
        let Some(mine) = self
            .key_file
            .header()
            .and_then(|h| h.slots.iter().find(|s| s.number == number))
        else {
            return false;
        };
        other.header().is_some_and(|t| {
            t.slots
                .iter()
                .enumerate()
                .any(|(j, s)| s.cred_id == mine.cred_id && (t.suspended >> j) & 1 == 0)
        })
    }
    /// The allow list of a touch for `other` alone (S-OTHERKEY-ONLY): its
    /// live, non-suspended keys with its own seeds.
    pub fn other_request(other: &KeyFile, owner: isize) -> Result<AssertRequest> {
        let t = other.header().ok_or(NOT_PLANNED)?;
        let allow = t
            .slots
            .iter()
            .enumerate()
            .filter(|(j, _)| (t.suspended >> j) & 1 == 0)
            .map(|(_, s)| (s.cred_id.clone(), salt(&t.vault_id, &s.seed), None))
            .collect();
        AssertRequest::new(owner, allow, t.pin())
    }
    /// The numbers `other` gives the credentials `hashes` (S-FORK-READMIT
    /// names the keys option 1 brings back).
    pub fn numbers_in(other: &KeyFile, hashes: &[[u8; 16]]) -> Vec<u8> {
        other.header().map_or_else(Vec::new, |t| {
            t.slots
                .iter()
                .filter(|s| hashes.contains(&s.credhash))
                .map(|s| s.number)
                .collect()
        })
    }
    /// A pairing or extra touch between ceremonies (spec §5.5, §8.3;
    /// S45-1 #14): the public checks against its own slot, then its own
    /// S-wrap must open to the Reauth's S, or, for a suspended key, one of
    /// its own pair records must open with its `seal` (else S-OLDSLOT).
    /// Returns its number.
    pub fn check_touch(&self, r: &Reauth, t: &Touch) -> Result<u8> {
        if r.session != self.serial {
            return Err(REAUTH_STALE);
        }
        let a = r.keys.as_ref().ok_or(NOT_PLANNED)?;
        let h = self
            .key_file
            .header()
            .filter(|h| !h.slots.is_empty())
            .ok_or(NOT_PLANNED)?;
        let j = h
            .slots
            .iter()
            .position(|s| s.cred_id == t.cred_id)
            .ok_or(fido::NOT_REGISTERED)?;
        let out = touch_output(t, &h.slots[j], h)?;
        let proved = if (h.suspended >> j) & 1 == 0 {
            self.key_file
                .open_own(j, out)
                .is_some_and(|s| ct_eq(s.as_slice(), a.s.bytes()))
        } else {
            self.key_file
                .open_pairs(out, j as u8)
                .iter()
                .any(|(_, ik)| ik.is_some())
        };
        if !proved {
            return Err(OLDSLOT);
        }
        Ok(h.slots[j].number)
    }
    /// A fresh seed for every live key (spec §5.5, §9.2 re-seed step 2). A
    /// suspended key that owns no pair record can never prove itself: it is
    /// refused before any ceremony, until it is removed.
    pub fn plan_reseed(&self) -> Result<ReSeedPlan> {
        let h = self
            .key_file
            .header()
            .filter(|h| !h.slots.is_empty())
            .ok_or(NOT_PLANNED)?;
        let mut keys = Vec::with_capacity(h.slots.len());
        for (j, slot) in h.slots.iter().enumerate() {
            let owns = h.pairs.iter().any(|(o, _)| usize::from(*o) == j);
            if (h.suspended >> j) & 1 != 0 && !owns {
                return Err(refuse(SUSPENDED_ORPHAN, vec![slot.number.to_string()]));
            }
            keys.push(Planned {
                number: slot.number,
                cred_id: slot.cred_id.clone(),
                seed: slot.seed,
                seed_new: *crypto::random::<32>()?,
                proved: false,
                h_new: None,
                second: false,
            });
        }
        Ok(ReSeedPlan {
            session: self.serial,
            vault_id: h.vault_id,
            pin: h.pin(),
            keys,
            confirmed: false,
        })
    }

    /// A key change of a key file with security keys, or one that turns
    /// them on (spec §5.5): R0's checks of this build, then W1-W10 in
    /// memory, then S0-S5. `r` passed the common checks of `rekey`.
    pub(super) fn rekey_keys(
        &mut self,
        r: Reauth,
        extra: Vec<Touch>,
        change: Change,
        consent: Consent,
    ) -> Result<Rekeyed> {
        if !self.key_on_disk()? {
            return Err(KEY_CHANGED);
        }
        // Every such change starts from or ends in a security-key state,
        // which the anchor must record (S45-1 #2): a rewrite of the
        // unchanged lines first.
        self.anchor_strict(&mut |_| true)?;
        let own = self.key_file.header().cloned();
        let hardware = own.as_ref().is_some_and(|h| !h.slots.is_empty());
        // W1: a key file with keys is changed only with a touched live key
        // that is not suspended (the open refused one), and a key file
        // without keys with none.
        if hardware != r.keys.is_some() {
            return Err(if hardware {
                SECURITY_KEY_NEEDED
            } else {
                NOT_PLANNED
            });
        }
        // W2: for a GOYOKS01 result also above the server's file this PC
        // holds or the cut's floor, each within its bound (spec §5.5).
        let ks01 = match &change {
            Change::KeySyncOn | Change::Supersede { .. } => true,
            Change::KeySyncOff | Change::KeysOff | Change::KeysOn { .. } => false,
            _ => own.as_ref().is_some_and(|h| h.magic == Magic::Ks01),
        };
        let server = if ks01 { self.server_epoch() } else { 0 };
        // A supersede lands above its candidate (it passed rule A).
        let above = match &change {
            Change::Supersede { epoch, .. } => *epoch,
            _ => 0,
        };
        let epoch = self
            .max_epoch
            .max(server)
            .max(above)
            .checked_add(1)
            .filter(|e| *e <= EPOCH_MAX)
            .ok_or(EPOCH_LIMIT)?;
        // W3: the touches of this flow, each proved against its own slot.
        let mut touched: Vec<([u8; 16], Box<Key>)> = Vec::new();
        if let Some(a) = &r.keys {
            touched.push((a.credhash, super::super::boxed(&a.h)));
        }
        if let Some(h) = own.as_ref().filter(|_| !extra.is_empty()) {
            for t in &extra {
                let number = self.check_touch(&r, t)?;
                let slot = h
                    .slots
                    .iter()
                    .find(|s| s.number == number)
                    .ok_or(NOT_PLANNED)?;
                if touched.iter().any(|(c, _)| *c == slot.credhash) {
                    return Err(NOT_PLANNED);
                }
                let out = t
                    .output_for(&slot.seed, &h.vault_id)
                    .ok_or(fido::BAD_ANSWER)?;
                touched.push((slot.credhash, super::super::boxed(out)));
            }
        } else if !extra.is_empty() {
            return Err(NOT_PLANNED);
        }
        let new_pw = |password: &Zeroizing<String>| -> Result<()> {
            password_policy(password)?;
            if ct_eq(password.as_bytes(), r.password.as_bytes()) {
                return Err(SAMEPASS);
            }
            Ok(())
        };
        let target = match (change, own.as_ref()) {
            // Keys off writes no S-wrap: no other touch.
            (Change::KeysOff, Some(_)) if !extra.is_empty() => return Err(NOT_PLANNED),
            (Change::KeysOff, Some(h)) if hardware => return self.keys_off(r, h, epoch),
            (
                Change::KeysOn {
                    pin,
                    keys,
                    new_password,
                },
                h,
            ) if !hardware => {
                if !extra.is_empty() || keys.is_empty() || keys.len() > 8 {
                    return Err(NOT_PLANNED);
                }
                if let Some(p) = &new_password {
                    new_pw(p)?;
                }
                let (slots, next) = new_slots(&keys, h, pin, epoch)?;
                let present = keys
                    .iter()
                    .zip(&slots)
                    .map(|(k, s)| (s.credhash, super::super::boxed(&k.output)))
                    .collect();
                let authorizer = slots[0].credhash;
                let typed = new_password.is_some();
                Target {
                    kind: Kind::KeysOn,
                    rotate: true,
                    password: new_password.unwrap_or_else(|| r.password.clone()),
                    new_password: typed,
                    fresh_pw_id: h.is_none(),
                    sync: false,
                    pin,
                    slots,
                    present,
                    authorizer,
                    tombstones: h.map(|h| h.tombstones.clone()).unwrap_or_default(),
                    next,
                    loss: 0,
                    suspends: false,
                    lost: false,
                    landing: Landing::default(),
                    src: anchor::Src::Other,
                }
            }
            (change, Some(h)) if hardware => {
                let a = r.keys.as_ref().ok_or(SECURITY_KEY_NEEDED)?;
                let mut t = Target {
                    kind: Kind::Password,
                    rotate: false,
                    password: r.password.clone(),
                    new_password: false,
                    fresh_pw_id: false,
                    sync: h.magic == Magic::Ks01,
                    pin: h.pin(),
                    slots: h.slots.clone(),
                    present: touched,
                    authorizer: a.credhash,
                    tombstones: h.tombstones.clone(),
                    next: h.next,
                    loss: 0,
                    suspends: false,
                    lost: false,
                    landing: Landing::default(),
                    src: anchor::Src::Other,
                };
                match change {
                    Change::Password(password) => {
                        new_pw(&password)?;
                        (t.kind, t.rotate, t.password, t.new_password) =
                            (Kind::Password, true, password, true);
                    }
                    Change::AddKey(key) => {
                        if h.slots.len() >= 8 {
                            return Err(NOT_PLANNED);
                        }
                        let pin = h.pin() || h.magic == Magic::Ks01;
                        let (mut slots, next) =
                            new_slots(std::slice::from_ref(&key), Some(h), pin, epoch)?;
                        let slot = slots.remove(0);
                        t.present
                            .push((slot.credhash, super::super::boxed(&key.output)));
                        t.slots.push(slot);
                        t.slots.sort_unstable_by_key(|s| s.number);
                        (t.kind, t.next) = (Kind::AddKey, next);
                    }
                    Change::Remove {
                        remove,
                        new_password,
                        loss,
                        over,
                    } => {
                        let mut picked: Vec<&SlotPublic> = Vec::new();
                        for n in &remove {
                            let slot =
                                h.slots.iter().find(|s| s.number == *n).ok_or(NOT_PLANNED)?;
                            if picked.iter().any(|p| p.number == *n) {
                                return Err(NOT_PLANNED);
                            }
                            picked.push(slot);
                        }
                        // A key never authorizes its own removal, nor does
                        // a touched key that goes; one key at least stays.
                        let gone = |c: &[u8; 16]| picked.iter().any(|p| p.credhash == *c);
                        if over.is_some()
                            || picked.is_empty()
                            || picked.len() >= h.slots.len()
                            || t.present.iter().any(|(c, _)| gone(c))
                        {
                            return Err(NOT_PLANNED);
                        }
                        if h.tombstones.len() + picked.len() > TOMB_MAX {
                            return Err(TOMBSTONES_FULL);
                        }
                        if let Some(p) = &new_password {
                            new_pw(p)?;
                        }
                        let mark = loss.as_ref().map_or(0, LossReport::mark);
                        for p in &picked {
                            t.tombstones.push(Tombstone {
                                credhash: p.credhash,
                                removed: epoch | mark << 48,
                            });
                        }
                        t.landing.removed = picked.iter().map(|p| (p.number, p.credhash)).collect();
                        t.slots.retain(|s| !gone(&s.credhash));
                        if let Some(l) = &loss {
                            t.loss = l.header();
                            t.landing.loss = Some(match l.date {
                                Some(d) => fido::stamp(d)[..8].to_owned(),
                                None => "unknown".into(),
                            });
                            t.landing.exp = Some(match l.exposure {
                                Exposure::Yes => b'y',
                                Exposure::No => b'n',
                                Exposure::Unsure => b'u',
                            });
                            if l.exposure != Exposure::No {
                                t.landing.clone = l
                                    .shared_pin
                                    .iter()
                                    .copied()
                                    .filter(|n| t.slots.iter().any(|s| s.number == *n))
                                    .collect();
                            }
                        }
                        let typed = new_password.is_some();
                        if let Some(p) = new_password {
                            t.password = p;
                        }
                        (t.kind, t.rotate, t.new_password) = (Kind::Remove, true, typed);
                        (t.suspends, t.lost) = (true, loss.is_some());
                        t.src = if loss.is_some() {
                            anchor::Src::Lost
                        } else {
                            anchor::Src::Retire
                        };
                    }
                    Change::Pair => {
                        if t.present.len() < 2 {
                            return Err(NOT_PLANNED);
                        }
                        t.kind = Kind::Pair;
                    }
                    // Key-file sync on, or the re-upload after a cut (spec
                    // §7.9): R0 is §7.9's preconditions in their order, the
                    // transport the Reauth's touch stated; the same keyset
                    // and data key, `ks = on.<seq>`.
                    Change::KeySyncOn => {
                        if !extra.is_empty() {
                            return Err(NOT_PLANNED);
                        }
                        let floor = self.keysync_on_check()?;
                        if a.transport.is_none() {
                            return Err(super::super::keysync::KEYSYNC_NOTRANSPORT);
                        }
                        if epoch <= floor {
                            return Err(super::super::keysync::KEYSYNC_FLOOR);
                        }
                        t.landing.ks = Some(self.on_ks()?);
                        (t.kind, t.sync, t.pin) = (Kind::SyncOn, true, true);
                    }
                    // The supersede (spec §7.15a): this PC's keyset and data
                    // key again above the candidate, with its tombstones
                    // too; on a GOYOKH01 session key-file sync turns on
                    // here, under the transport precondition.
                    Change::Supersede { epoch: e, tag } => {
                        if !extra.is_empty() {
                            return Err(NOT_PLANNED);
                        }
                        let named = keyfile::KeyState { epoch: e, tag };
                        let (theirs, sup) = self.supersede_check(named)?;
                        if h.magic != Magic::Ks01 {
                            if a.transport.is_none() {
                                return Err(super::super::keysync::KEYSYNC_NOTRANSPORT);
                            }
                            t.landing.ks = Some(self.on_ks()?);
                        }
                        t.tombstones = super::adopt::joined_tombs(&h.tombstones, &theirs);
                        if t.tombstones.len() > TOMB_MAX {
                            return Err(TOMBSTONES_FULL);
                        }
                        (t.landing.merged, t.landing.supersede) = (Some((e, tag)), true);
                        t.landing.sup = sup;
                        (t.kind, t.sync, t.pin) = (Kind::SyncOn, true, true);
                        t.src = anchor::Src::Supersede;
                    }
                    // Key-file sync off (spec §7.16): GOYOKH01 under a new
                    // data key; `kreq` and `kview` deleted first, the S0
                    // entry carries the snapshot's `ks` and clears a pending
                    // gate.
                    Change::KeySyncOff => {
                        if h.magic != Magic::Ks01 || !extra.is_empty() {
                            return Err(super::super::keysync::KEYSYNC_NOT_ON);
                        }
                        let ks = self.off_snapshot();
                        self.off_delete();
                        (t.landing.ks, t.landing.clear_gate) = (Some(ks), true);
                        (t.kind, t.rotate, t.sync) = (Kind::SyncOff, true, false);
                    }
                    Change::ReSeed(keys) => {
                        if !extra.is_empty()
                            || keys.len() != h.slots.len()
                            || !h
                                .slots
                                .iter()
                                .all(|s| keys.iter().filter(|k| k.number == s.number).count() == 1)
                            || !keys.iter().any(|k| k.number == a.number)
                        {
                            return Err(NOT_PLANNED);
                        }
                        t.present.clear();
                        for slot in &mut t.slots {
                            let k = keys
                                .iter()
                                .find(|k| k.number == slot.number)
                                .ok_or(NOT_PLANNED)?;
                            slot.seed = k.seed_new;
                            t.present
                                .push((slot.credhash, super::super::boxed(&k.h_new)));
                        }
                        (t.kind, t.rotate) = (Kind::ReSeed, true);
                    }
                    _ => return Err(NOT_PLANNED),
                }
                t
            }
            _ => return Err(NOT_PLANNED),
        };
        self.write_keys(r, target, &consent, epoch)
    }

    /// W4-W10, R3 and S0-S5 of `t` (spec §5.5).
    fn write_keys(
        &mut self,
        r: Reauth,
        t: Target,
        consent: &Consent,
        epoch: u64,
    ) -> Result<Rekeyed> {
        let Target {
            kind,
            rotate,
            password,
            new_password,
            fresh_pw_id: converted,
            sync,
            pin,
            mut slots,
            present,
            mut authorizer,
            tombstones,
            next,
            loss,
            suspends,
            lost,
            mut landing,
            src,
        } = t;
        let id = self.id;
        let own = self.key_file.header().cloned();
        let own_slots: &[SlotPublic] = own.as_ref().map_or(&[], |h| &h.slots);
        let own_index = |c: &[u8; 16]| own_slots.iter().position(|s| s.credhash == *c);
        let own_suspended = |c: &[u8; 16]| {
            own_index(c).is_some_and(|j| own.as_ref().is_some_and(|h| (h.suspended >> j) & 1 != 0))
        };
        let slot = |c: &[u8; 16]| slots.iter().find(|s| s.credhash == *c);
        let output = |c: &[u8; 16]| present.iter().find(|(x, _)| x == c).map(|(_, h)| &***h);
        // The same seed here and in the source: a record between two such
        // keys is carried as it is; a re-seed carries none.
        let kept = |c: &[u8; 16]| matches!((own_index(c), slot(c)), (Some(j), Some(s)) if own_slots[j].seed == s.seed);
        // W4 and W5: the records each present key of the source owns,
        // opened with its `seal`.
        let records: Vec<([u8; 16], Records)> = present
            .iter()
            .filter(|(c, _)| kept(c))
            .filter_map(|(c, h)| {
                let j = own_index(c)?;
                let records = self
                    .key_file
                    .open_pairs(h, j as u8)
                    .into_iter()
                    .map(|(t, ik)| (own_slots[usize::from(t)].credhash, ik))
                    .collect();
                Some((*c, records))
            })
            .collect();
        let record_of = |o: &[u8; 16], t: &[u8; 16]| {
            records
                .iter()
                .find(|(c, _)| c == o)
                .and_then(|(_, records)| records.iter().find(|(x, _)| x == t))
                .and_then(|(_, ik)| ik.as_deref())
        };
        // W5: every record between two staying keys is carried, but for one
        // a present owner cannot open, or that carries a value other than
        // its present target's inbox key: rewritten when both keys are here,
        // else carried and recorded as broken.
        let mut pairs: Vec<PairPlan> = Vec::new();
        let mut repaired: Vec<([u8; 16], [u8; 16])> = Vec::new();
        let carried = if own_slots.is_empty() {
            Vec::new()
        } else {
            self.key_file.carried_pairs()
        };
        for p in carried {
            let PairPlan::Copy { owner, target, .. } = &p else {
                continue;
            };
            let (o, tt) = (*owner, *target);
            if !(kept(&o) && kept(&tt)) {
                continue;
            }
            if output(&o).is_some() {
                match (record_of(&o, &tt), slot(&o), slot(&tt), output(&tt)) {
                    (None, _, _, Some(_)) => {
                        repaired.push((o, tt));
                        continue;
                    }
                    (None, _, _, None) => landing.broken.push((short(&o), short(&tt))),
                    (Some(v), Some(so), Some(st), Some(h_t)) => {
                        let want = inbox_key(&id, st, h_t, so);
                        if !ct_eq(v.as_slice(), want.as_slice()) {
                            repaired.push((o, tt));
                            continue;
                        }
                    }
                    _ => {}
                }
            }
            pairs.push(p);
        }
        for (o, _) in &present {
            for (tt, _) in &present {
                let has = pairs.iter().any(|p| match p {
                    PairPlan::Copy { owner, target, .. } | PairPlan::New { owner, target } => {
                        owner == o && target == tt
                    }
                });
                if o != tt && !has {
                    pairs.push(PairPlan::New {
                        owner: *o,
                        target: *tt,
                    });
                    landing.fixed.push((short(o), short(tt)));
                }
            }
        }
        let absent: Vec<[u8; 16]> = slots
            .iter()
            .map(|s| s.credhash)
            .filter(|c| output(c).is_none())
            .collect();
        // The repairing write's authorizer (S45-3 #6): another PC takes a
        // rewritten record only from a file its owner or target authorized.
        let foreign: Vec<([u8; 16], [u8; 16])> = repaired
            .iter()
            .filter(|(o, tt)| *o != authorizer && *tt != authorizer)
            .copied()
            .collect();
        if kind != Kind::ReSeed && !foreign.is_empty() {
            let reaches = |k: &[u8; 16]| {
                absent
                    .iter()
                    .filter(|c| !own_suspended(c))
                    .all(|c| record_of(k, c).is_some())
            };
            let mut candidates: Vec<[u8; 16]> = foreign.iter().map(|(o, _)| *o).collect();
            candidates.extend(foreign.iter().map(|(_, tt)| *tt));
            let found = candidates.into_iter().find(|k| {
                output(k).is_some() && foreign.iter().all(|(o, tt)| k == o || k == tt) && reaches(k)
            });
            match found {
                Some(k) => authorizer = k,
                // This PC's protection comes first.
                None if lost => {}
                None => {
                    let (o, tt) = foreign[0];
                    let number = |c: &[u8; 16]| slot(c).map_or(0, |s| s.number).to_string();
                    let (o, tt) = (number(&o), number(&tt));
                    return Err(refuse(
                        REPAIR_AUTH,
                        vec![o.clone(), tt.clone(), o.clone(), tt.clone(), o, tt],
                    ));
                }
            }
        }
        // W6: each absent key gets an S-wrap through the authorizer's record
        // that W4 opened; a key suspended in the source stays so; any other
        // is unreachable.
        let mut inbox: Vec<([u8; 16], &Key)> = Vec::new();
        let mut suspended: Vec<[u8; 16]> = Vec::new();
        let mut unreached: Vec<u8> = Vec::new();
        for c in &absent {
            let has_record = pairs.iter().any(|p| {
                matches!(p, PairPlan::Copy { owner, target, .. } if *owner == authorizer && target == c)
            });
            match record_of(&authorizer, c).filter(|_| has_record) {
                Some(ik) => inbox.push((*c, ik)),
                None if own_suspended(c) => suspended.push(*c),
                None => {
                    suspended.push(*c);
                    unreached.push(slot(c).map_or(0, |s| s.number));
                }
            }
        }
        if !unreached.is_empty() {
            unreached.sort_unstable();
            if !suspends {
                return Err(refuse(UNREACHABLE, vec![listed(&unreached)]));
            }
            if !unreached.iter().all(|n| consent.suspend.contains(n)) {
                return Err(refuse(REACH_CHANGED, vec![listed(&unreached)]));
            }
        }
        // A key added now names its authorizer.
        if kind == Kind::AddKey {
            for s in slots.iter_mut().filter(|s| s.added_epoch == epoch) {
                s.added_by = authorizer;
            }
        }
        // R1: the probe, the keys and the spec.
        let probe = if rotate { Some(self.encode()?) } else { None };
        let resume = probe.as_deref().map_or([0; 32], super::super::sha256);
        let pw_id = match &own {
            Some(h) if !new_password && !converted => h.pw_id,
            _ => fresh_pw_id()?,
        };
        let keys = if rotate {
            let mut dk: Box<Key> = Box::default();
            crypto::random_into(dk.as_mut_slice())?;
            rotated(&dk, self.keys.keys())
        } else {
            Zeroizing::new(self.keys.keys().to_vec())
        };
        let bundle = Bundle::new(&keys, self.keys.otp()).ok_or(AUTH_ERROR)?;
        let spec = Spec {
            vault_id: id,
            epoch,
            kind,
            next,
            pw_id,
            loss,
            tombstones,
            resume,
        };
        // W7-W9.
        let index = |c: &[u8; 16]| slots.iter().position(|s| s.credhash == *c);
        let mask = |cs: &[[u8; 16]]| cs.iter().filter_map(&index).fold(0u8, |m, j| m | 1 << j);
        let keys_present: Vec<[u8; 16]> = present.iter().map(|(c, _)| *c).collect();
        let (present_mask, suspended_mask) = (mask(&keys_present), mask(&suspended));
        let a = index(&authorizer).ok_or(NOT_PLANNED)?;
        let s = Secret::random()?;
        let plan = keyfile::KeysPlan {
            sync,
            pin,
            s: &s,
            slots: slots.clone(),
            authorizer: a as u8,
            present: present_mask,
            suspended: suspended_mask,
            pairs,
            outputs: present
                .iter()
                .filter_map(|(c, h)| Some((index(c)? as u8, &***h)))
                .collect(),
            inbox: inbox
                .iter()
                .filter_map(|(c, ik)| Some((index(c)? as u8, &***ik)))
                .collect(),
        };
        let (bytes, writer) = keyfile::seal(&spec, &bundle, &password, Plan::Keys(&plan))?;
        // R2 (W10): as any reader parses it, every S-wrap and new record
        // with bases derived again, the body with the writer's factors.
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut bytes = bytes;
        #[cfg(test)]
        super::corrupt("K", &mut bytes);
        let file = KeyFile::from_bytes(&self.key_path, bytes).map_err(|_| NOT_VERIFIED)?;
        let kh = file.header().ok_or(NOT_VERIFIED)?.clone();
        let opened = file.verify_keys(&writer, &plan).map_err(|_| NOT_VERIFIED)?;
        drop(writer);
        let mut sorted = spec.tombstones.clone();
        sorted.sort_unstable_by_key(|t| (t.epoch(), t.credhash));
        let ids: Vec<[u8; 16]> = bundle.keys().iter().map(|k| key_id(&id, k)).collect();
        let magic = if sync { Magic::Ks01 } else { Magic::Kh01 };
        if kh.magic != magic
            || kh.spec()
                != (Spec {
                    tombstones: sorted,
                    ..spec
                })
            || kh.key_ids != ids
            || kh.otp() != self.uses_otp()
            || kh.pin() != pin
            || kh.authorizer != Some(a as u8)
            || (kh.present, kh.suspended) != (present_mask, suspended_mask)
            || !opened.bundle.same(&bundle)
            || kh.key_ids.last() != Some(&key_id(&id, self.keys.id_key()))
        {
            return Err(NOT_VERIFIED);
        }
        drop(plan);
        // R3, then S0-S5.
        let mut built: Built = self.with_vault(file, kh, opened.bundle, probe)?;
        landing.strict = true;
        built.landing = landing;
        let pw = new_password.then_some(anchor::Pw::New);
        // The Reauth holds the key file's lock until the write is done.
        let rekeyed = self.land(built, src, pw);
        drop(r);
        rekeyed
    }

    /// Keys off (spec §5.5): GOYOKE03 under a new data key, every former
    /// slot tombstoned at the new epoch, sealed with the current password.
    /// A GOYOKS01 key file goes through the off sequence of key-file sync
    /// (§7.16): `kreq` and `kview` deleted first, the S0 entry with the
    /// snapshot's `ks`, a pending gate cleared.
    fn keys_off(&mut self, r: Reauth, h: &KeyHeader, epoch: u64) -> Result<Rekeyed> {
        let synced = h.magic == Magic::Ks01;
        if h.tombstones.len() + h.slots.len() > TOMB_MAX {
            return Err(TOMBSTONES_FULL);
        }
        let probe = self.encode()?;
        let resume = super::super::sha256(&probe);
        let mut dk: Box<Key> = Box::default();
        crypto::random_into(dk.as_mut_slice())?;
        let keys = rotated(&dk, self.keys.keys());
        let bundle = Bundle::new(&keys, self.keys.otp()).ok_or(AUTH_ERROR)?;
        let mut tombstones = h.tombstones.clone();
        tombstones.extend(h.slots.iter().map(|s| Tombstone {
            credhash: s.credhash,
            removed: epoch,
        }));
        let spec = Spec {
            vault_id: self.id,
            epoch,
            kind: Kind::KeysOff,
            next: h.next,
            pw_id: h.pw_id,
            loss: 0,
            tombstones,
            resume,
        };
        let (bytes, writer) = keyfile::seal(&spec, &bundle, &r.password, Plan::PasswordOnly)?;
        let mut built = self.built(bytes, &writer, &spec, &bundle, Some(probe))?;
        drop(writer);
        let ks = synced.then(|| self.off_snapshot());
        if synced {
            self.off_delete();
        }
        built.landing = Landing {
            strict: true,
            removed: h.slots.iter().map(|s| (s.number, s.credhash)).collect(),
            ks,
            clear_gate: synced,
            ..Landing::default()
        };
        let rekeyed = self.land(built, anchor::Src::Other, None);
        drop(r);
        rekeyed
    }
}

/// A union of more than eight keys (spec §5.8).
pub const UNION_FULL: &str =
    "보안 키는 8개까지 등록할 수 있습니다. 두 열쇠 파일을 합치면 8개를 넘어 받지 않았습니다.";

/// How an adopt's union joins the two files (spec §5.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Join {
    /// A file that descends from this PC's state, with a carry: its seeds
    /// and its magic, this PC's keys and records it lacks added.
    Chained,
    /// Fork option 2, "둘 다 합치기": both, this PC's removals kept.
    Both,
    /// Fork option 1, "다른 PC 쪽 사용": the other branch's content, the
    /// removals `readmit` names (taken here from other files) dropped.
    TakeOther,
}
/// The touched key of an adopt in the other file (spec §5.8 "Touch"): its
/// output for its seed there, and the records it owns there that did not
/// open but are this PC's own byte for byte (they go to `pbad`).
/// Zeroized on drop.
pub(in crate::vault) struct Touched {
    credhash: [u8; 16],
    output: Box<Key>,
    broken: Vec<([u8; 4], [u8; 4])>,
    /// The transport the touch stated (USB or NFC), or None.
    pub(super) transport: Option<u32>,
}
/// A union planned in memory (spec §5.8), for the preview and the write.
pub(super) struct UnionPlan {
    /// The result's live keys, ascending by number.
    slots: Vec<SlotPublic>,
    pairs: Vec<PairPlan>,
    present: Vec<([u8; 16], Box<Key>)>,
    authorizer: [u8; 16],
    inbox: Vec<([u8; 16], Box<Key>)>,
    suspended: Vec<[u8; 16]>,
    tombstones: Vec<Tombstone>,
    next: u8,
    pub(super) sync: bool,
    pin: bool,
    /// This PC's keys whose number the other file took: (old, new)
    /// (S-ADOPT-RENUMBER).
    pub renumbered: Vec<(u8, u8)>,
    /// Keys that are no PIN slots of a result in PIN mode, by number
    /// (S-ADOPT-DROPPED-UV).
    pub dropped_uv: Vec<u8>,
    /// Keys that nothing touched reaches, by the result's number: suspended
    /// only with consent (S-SUSPEND).
    pub unreached: Vec<u8>,
    /// The same keys by credential, for S-SUSPEND's names and its extra
    /// touches (spec §7.15a: this PC names them by its own numbers).
    pub unreached_keys: Vec<[u8; 16]>,
    pub(super) landing: Landing,
}
impl UnionPlan {
    /// Keys the result leaves suspended, by number.
    pub(super) fn suspended(&self) -> Vec<u8> {
        let number = |c: &[u8; 16]| {
            self.slots
                .iter()
                .find(|s| s.credhash == *c)
                .map(|s| s.number)
        };
        self.suspended.iter().filter_map(number).collect()
    }
    /// No key survives: the result is password-only (S-ADOPT-PWONLY).
    pub(super) fn password_only(&self) -> bool {
        self.slots.is_empty()
    }
}

impl Session {
    /// The touched key's records in the other file `other`, which `opened`
    /// opened with `touch` (spec §5.8): every one must open with its
    /// `seal`, but for one byte-identical to this PC's own record, which
    /// the other file only copied (round 3, findings 3 and 15).
    pub(super) fn touched_in(
        &self,
        other: &KeyFile,
        opened: &keyfile::Opened,
        touch: &Touch,
    ) -> Result<Touched> {
        let h = other.header().ok_or(AUTH_ERROR)?;
        let j = usize::from(opened.slot.ok_or(AUTH_ERROR)?);
        let slot = h.slots.get(j).ok_or(AUTH_ERROR)?;
        let out = touch_output(touch, slot, h)?;
        let own = self.key_file.carried_pairs();
        let theirs = other.carried_pairs();
        let mut broken = Vec::new();
        for (t, ik) in other.open_pairs(out, j as u8) {
            if ik.is_some() {
                continue;
            }
            let target = h.slots[usize::from(t)].credhash;
            let copied = theirs.iter().any(|p| {
                let ours = matches!(p, PairPlan::Copy { owner, target: x, .. }
                    if *owner == slot.credhash && *x == target);
                ours && own.contains(p)
            });
            if !copied {
                return Err(refuse(
                    super::ADOPT_REFUSED,
                    vec![super::super::gate::PAIR_BROKEN.to_owned()],
                ));
            }
            broken.push((short(&slot.credhash), short(&target)));
        }
        Ok(Touched {
            credhash: slot.credhash,
            output: super::super::boxed(out),
            broken,
            transport: touch.transport,
        })
    }
    /// The successor re-seal of a key file with security keys (spec §5.8):
    /// `[0, W)` byte for byte with the S that opened it, this PC's seal
    /// block. Read back with that S; the state must stay the other file's.
    pub(super) fn reseal_keys(
        &self,
        other: &KeyFile,
        opened: &keyfile::Opened,
        password: &str,
        touched: Option<&Touched>,
    ) -> Result<Built> {
        let h = other.header().ok_or(AUTH_ERROR)?;
        let bundle = &opened.bundle;
        let probe = if ct_eq(bundle.current(), self.keys.current()) {
            None
        } else {
            Some(self.encode()?)
        };
        let mut spec = h.spec();
        spec.resume = probe.as_deref().map_or([0; 32], super::super::sha256);
        let plan = Plan::Reseal {
            source: other,
            opened,
        };
        let (bytes, writer) = keyfile::seal(&spec, bundle, password, plan)?;
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut bytes = bytes;
        #[cfg(test)]
        super::corrupt("K", &mut bytes);
        let file = KeyFile::from_bytes(&self.key_path, bytes).map_err(|_| NOT_VERIFIED)?;
        let kh = file.header().ok_or(NOT_VERIFIED)?.clone();
        let read = file.open_written(&writer).map_err(|_| NOT_VERIFIED)?;
        drop(writer);
        let mut sorted = spec.tombstones.clone();
        sorted.sort_unstable_by_key(|t| (t.epoch(), t.credhash));
        if kh.state() != h.state()
            || kh.spec()
                != (Spec {
                    tombstones: sorted,
                    ..spec
                })
            || !read.bundle.same(bundle)
        {
            return Err(NOT_VERIFIED);
        }
        let mut built = self.with_vault(file, kh, read.bundle, probe)?;
        built.landing = Landing {
            strict: true,
            broken: touched.map(|t| t.broken.clone()).unwrap_or_default(),
            ..Landing::default()
        };
        Ok(built)
    }
    /// [이 금고의 기록 지우고 다시 확인…] in gate-pending mode (spec §5.10,
    /// round 4, finding 13): the Reauth verified the factors in place of
    /// the unlock, so the session now runs as a bootstrap, with this
    /// vault's lines ignored in memory: the changed key file's gate is
    /// dropped and TOFU (G1, or S-TOFU-NOPC) takes its place. Nothing of
    /// the record is written here; the TOFU pass alone removes this
    /// vault's lines, so a lock before it leaves every line as it was.
    pub fn forget_record(&mut self, r: Reauth) -> Result<()> {
        if r.session != self.serial
            || r.age() > super::REAUTH_MAX
            || (self.uses_otp() && r.otp_step.is_none())
        {
            return Err(REAUTH_STALE);
        }
        if self.gate_login.is_none() {
            return Err(super::super::gate::GATE_NOT_PENDING);
        }
        self.gate_login = None;
        self.tofu = true;
        self.forgotten = true;
        self.held_unconfirmed = false;
        self.g2_spent.set(false);
        Ok(())
    }
    /// S-FORK-HINT's key (spec §5.8 "Order and display", round 1, finding
    /// 19): the number, in this PC's own key file, of a key that authorized
    /// a state of this PC's history since the state it shares with `other`
    /// and that `other` tombstones. None when there is none, or when the
    /// history does not reach the shared state. Local facts only: the UI
    /// shows it in the preview, after the gate, never before.
    pub fn fork_hint(&self, other: &KeyFile) -> Option<u8> {
        let theirs = other.header()?;
        let own = self.key_file.header()?;
        let state = &self.anchor.lines.vault.as_ref()?.state;
        let shared = state.shared(&theirs.key_ids)?;
        let removed: Vec<[u8; 16]> = theirs.tombstones.iter().map(|t| t.credhash).collect();
        state.hist[..shared]
            .iter()
            .filter(|e| e.auth != [0; 16] && removed.contains(&e.auth))
            .find_map(|e| {
                own.slots
                    .iter()
                    .find(|s| s.credhash == e.auth)
                    .map(|s| s.number)
            })
    }
    /// Whether this PC re-seeded since the state it shares with `other`
    /// (spec §5.8 "Seeds that differ"): a kind-8 state in its history after
    /// the newest one whose current key `other` holds. With no such shared
    /// state, this PC's seeds are kept as well.
    fn reseeded_since(&self, other: &KeyHeader) -> bool {
        let Some(line) = self.anchor.lines.vault.as_ref() else {
            return true;
        };
        match line.state.shared(&other.key_ids) {
            Some(shared) => line.state.hist[..shared].iter().any(|e| e.kind == 8),
            None => true,
        }
    }
    /// Plans the union of this PC's key file with `other` (spec §5.8), in
    /// memory: the live keys (the other file's numbers kept, this PC's
    /// renumbered where they collide; a result in PIN mode keeps PIN slots
    /// only), the seeds by `join`, the pair records of both whose keys stay
    /// with those seeds (two that differ: the other's when this PC's is in
    /// `pbad`, else neither), new records between the keys touched, and
    /// W6 for every other key through the authorizer's records. `a` is the
    /// Reauth's key, `touched` the key that opened the other file, `extra`
    /// further touches with their outputs for this PC's seeds.
    pub(super) fn plan_union(
        &self,
        a: Option<&Authorizer>,
        other: &KeyFile,
        touched: Option<&Touched>,
        extra: &[([u8; 16], Box<Key>)],
        join: Join,
        readmit: &[[u8; 16]],
    ) -> Result<UnionPlan> {
        let id = self.id;
        let t = other.header().ok_or(AUTH_ERROR)?;
        let own = self.key_file.header();
        let o_slots: &[SlotPublic] = own.map_or(&[], |h| &h.slots);
        let o_tombs: &[Tombstone] = own.map_or(&[], |h| &h.tombstones);
        let own_dead =
            |c: &[u8; 16]| o_tombs.iter().any(|x| x.credhash == *c) && !readmit.contains(c);
        let oth_dead = |c: &[u8; 16]| t.tombstones.iter().any(|x| x.credhash == *c);
        let in_other = |c: &[u8; 16]| t.slots.iter().any(|s| s.credhash == *c);
        let own_slot = |c: &[u8; 16]| o_slots.iter().find(|s| s.credhash == *c);
        let keep_own_seed = join == Join::Both && self.reseeded_since(t);
        // The other file's keys, with their numbers.
        let mut slots: Vec<SlotPublic> = Vec::new();
        for s in t.slots.iter().filter(|s| !own_dead(&s.credhash)) {
            let mut s = s.clone();
            if keep_own_seed && let Some(mine) = own_slot(&s.credhash) {
                s.seed = mine.seed;
            }
            slots.push(s);
        }
        // This PC's keys the other file lacks with no removal (M), but in
        // option 1, where they leave without one.
        let mut renumbered = Vec::new();
        let mut next = own.map_or(1, |h| h.next).max(t.next);
        if join != Join::TakeOther {
            let mine: Vec<&SlotPublic> = o_slots
                .iter()
                .filter(|s| !oth_dead(&s.credhash) && !in_other(&s.credhash))
                .collect();
            for s in &mine {
                let mut s = (*s).clone();
                if slots.iter().any(|x| x.number == s.number) {
                    let used: Vec<u8> = slots
                        .iter()
                        .chain(mine.iter().copied())
                        .map(|x| x.number)
                        .collect();
                    let (n, after) = new_number(next, &used).ok_or(UNION_FULL)?;
                    renumbered.push((s.number, n));
                    (s.number, next) = (n, after);
                }
                slots.push(s);
            }
        }
        let pin = t.pin() || (join != Join::TakeOther && own.is_some_and(KeyHeader::pin));
        let mut dropped_uv = Vec::new();
        if pin {
            slots.retain(|s| {
                if !s.pin() {
                    dropped_uv.push(s.number);
                }
                s.pin()
            });
        }
        if slots.len() > 8 {
            return Err(UNION_FULL);
        }
        slots.sort_unstable_by_key(|s| s.number);
        let result = |c: &[u8; 16]| slots.iter().find(|s| s.credhash == *c);
        // The keys touched in this flow, with their outputs for the seeds
        // the result keeps.
        let mut present: Vec<([u8; 16], Box<Key>)> = Vec::new();
        let mut take = |c: &[u8; 16], seed: Option<[u8; 32]>, out: &[u8; 32]| {
            if seed.is_some()
                && result(c).map(|s| s.seed) == seed
                && !present.iter().any(|(x, _)| x == c)
            {
                present.push((*c, super::super::boxed(out)));
            }
        };
        if let Some(a) = a {
            take(&a.credhash, own_slot(&a.credhash).map(|s| s.seed), &a.h);
        }
        if let Some(k) = touched {
            let seed = t
                .slots
                .iter()
                .find(|s| s.credhash == k.credhash)
                .map(|s| s.seed);
            take(&k.credhash, seed, &k.output);
        }
        for (c, out) in extra {
            take(c, own_slot(c).map(|s| s.seed), out);
        }
        let output = |c: &[u8; 16]| present.iter().find(|(x, _)| x == c).map(|(_, h)| &***h);
        // The authorizer: the Reauth's key, else the one that opened the
        // other file; live and present in the result.
        let authorizer = a
            .map(|a| a.credhash)
            .filter(|c| output(c).is_some())
            .or_else(|| touched.map(|k| k.credhash).filter(|c| output(c).is_some()));
        // The pair records of both files whose two keys stay with the seeds
        // they were written under.
        let usable = |h: &[SlotPublic], o: &[u8; 16], x: &[u8; 16]| {
            let seed = |c: &[u8; 16]| h.iter().find(|s| s.credhash == *c).map(|s| s.seed);
            seed(o).is_some()
                && seed(o) == result(o).map(|s| s.seed)
                && seed(x).is_some()
                && seed(x) == result(x).map(|s| s.seed)
        };
        let records = |f: &KeyFile, h: &[SlotPublic]| -> Vec<PairPlan> {
            f.carried_pairs()
                .into_iter()
                .filter(|p| {
                    matches!(p, PairPlan::Copy { owner, target, .. } if usable(h, owner, target))
                })
                .collect()
        };
        let mine = if own.is_some() {
            records(&self.key_file, o_slots)
        } else {
            Vec::new()
        };
        let theirs = records(other, &t.slots);
        let pbad = self
            .anchor
            .lines
            .vault
            .as_ref()
            .map(|l| l.state.pbad.clone())
            .unwrap_or_default();
        let keys_of = |p: &PairPlan| match p {
            PairPlan::Copy { owner, target, .. } | PairPlan::New { owner, target } => {
                (*owner, *target)
            }
        };
        let mut pairs: Vec<PairPlan> = Vec::new();
        for p in theirs.iter().chain(&mine) {
            let k = keys_of(p);
            if pairs.iter().any(|q| keys_of(q) == k) {
                continue;
            }
            let x = mine.iter().find(|q| keys_of(q) == k);
            let y = theirs.iter().find(|q| keys_of(q) == k);
            match (x, y) {
                (Some(x), Some(y)) if x == y => pairs.push(x.clone()),
                (Some(_), Some(y)) => {
                    if join == Join::TakeOther || pbad.contains(&(short(&k.0), short(&k.1))) {
                        pairs.push(y.clone());
                    }
                }
                (Some(x), None) => pairs.push(x.clone()),
                (None, Some(y)) => pairs.push(y.clone()),
                (None, None) => {}
            }
        }
        // Between two keys touched here a record must carry the right inbox
        // key; one that does not is written again, and every missing one
        // is new.
        let mut landing = Landing {
            strict: true,
            broken: touched.map(|k| k.broken.clone()).unwrap_or_default(),
            opt: match join {
                Join::TakeOther => Some(1),
                Join::Both => Some(2),
                Join::Chained => None,
            },
            ..Landing::default()
        };
        pairs.retain(|p| {
            let (o, x) = keys_of(p);
            let (Some(h_o), Some(h_x), Some(so), Some(sx)) =
                (output(&o), output(&x), result(&o), result(&x))
            else {
                return true;
            };
            let PairPlan::Copy { wrap, .. } = p else {
                return true;
            };
            let want = inbox_key(&id, sx, h_x, so);
            keyfile::inbox::open_record(&id, so, sx, h_o, wrap)
                .is_some_and(|ik| ct_eq(ik.as_slice(), want.as_slice()))
        });
        for (o, _) in &present {
            for (x, _) in &present {
                if o != x && !pairs.iter().any(|p| keys_of(p) == (*o, *x)) {
                    pairs.push(PairPlan::New {
                        owner: *o,
                        target: *x,
                    });
                    landing.fixed.push((short(o), short(x)));
                }
            }
        }
        // W6: every key not touched gets S through the authorizer's record;
        // one nothing reaches stays suspended where this PC suspended it,
        // else only with consent.
        let own_suspended = |c: &[u8; 16]| {
            own.is_some_and(|h| {
                h.slots
                    .iter()
                    .position(|s| s.credhash == *c)
                    .is_some_and(|j| (h.suspended >> j) & 1 != 0)
            })
        };
        let mut inbox = Vec::new();
        let mut suspended = Vec::new();
        let mut unreached = Vec::new();
        let mut unreached_keys = Vec::new();
        if !slots.is_empty() {
            let a = authorizer.ok_or(NOT_PLANNED)?;
            let (sa, h_a) = (
                result(&a).ok_or(NOT_PLANNED)?,
                output(&a).ok_or(NOT_PLANNED)?,
            );
            for s in slots.iter().filter(|s| output(&s.credhash).is_none()) {
                let record = pairs.iter().find_map(|p| match p {
                    PairPlan::Copy {
                        owner,
                        target,
                        wrap,
                    } if *owner == a && *target == s.credhash => Some(wrap),
                    _ => None,
                });
                match record.and_then(|w| keyfile::inbox::open_record(&id, sa, s, h_a, w)) {
                    Some(ik) => inbox.push((s.credhash, ik)),
                    None => {
                        suspended.push(s.credhash);
                        if !own_suspended(&s.credhash) {
                            unreached.push(s.number);
                            unreached_keys.push(s.credhash);
                        }
                    }
                }
            }
        }
        let mut tombstones = super::adopt::joined_tombs(o_tombs, &t.tombstones);
        tombstones.retain(|x| !readmit.contains(&x.credhash));
        let sync = match join {
            Join::Chained | Join::TakeOther => t.magic == Magic::Ks01,
            Join::Both => {
                t.magic == Magic::Ks01
                    && own.is_some_and(|h| h.magic == Magic::Ks01)
                    && slots.iter().all(SlotPublic::pin)
            }
        };
        Ok(UnionPlan {
            authorizer: authorizer.unwrap_or_default(),
            slots,
            pairs,
            present,
            inbox,
            suspended,
            tombstones,
            next,
            sync,
            pin,
            renumbered,
            dropped_uv,
            unreached,
            unreached_keys,
            landing,
        })
    }
    /// Writes a planned union (spec §5.8, W7-W10, then S0-S5): a fresh S and
    /// data key, `keys` the union's keyring, sealed with `password` and
    /// `pw_id`. Keys nothing reaches are suspended only with `consent`. No
    /// key surviving gives a password-only file, every former key of this
    /// PC removed at the result's epoch ("keys off wins").
    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_union(
        &mut self,
        r: Reauth,
        plan: UnionPlan,
        keys: Zeroizing<Vec<[u8; 32]>>,
        password: &str,
        pw_id: [u8; 16],
        epoch: u64,
        consent: &Consent,
        pw: Option<anchor::Pw>,
    ) -> Result<Rekeyed> {
        if !plan.unreached.iter().all(|n| consent.suspend.contains(n)) {
            return Err(refuse(REACH_CHANGED, vec![listed(&plan.unreached)]));
        }
        let id = self.id;
        let probe = self.encode()?;
        let resume = super::super::sha256(&probe);
        let bundle = Bundle::new(&keys, self.keys.otp()).ok_or(AUTH_ERROR)?;
        let mut spec = Spec {
            vault_id: id,
            epoch,
            kind: Kind::Union,
            next: plan.next,
            pw_id,
            loss: 0,
            tombstones: plan.tombstones.clone(),
            resume,
        };
        if plan.slots.is_empty() {
            // Keys off wins: every key of this PC that does not survive is
            // removed at this epoch.
            for s in self.key_file.header().map_or(&[][..], |h| &h.slots) {
                if !spec.tombstones.iter().any(|x| x.credhash == s.credhash) {
                    spec.tombstones.push(Tombstone {
                        credhash: s.credhash,
                        removed: epoch,
                    });
                }
            }
            if spec.tombstones.len() > TOMB_MAX {
                return Err(TOMBSTONES_FULL);
            }
            let (bytes, writer) = keyfile::seal(&spec, &bundle, password, Plan::PasswordOnly)?;
            let mut built = self.built(bytes, &writer, &spec, &bundle, Some(probe))?;
            drop(writer);
            built.landing = Landing {
                strict: true,
                opt: plan.landing.opt,
                ks: plan.landing.ks,
                clear_gate: plan.landing.clear_gate,
                merged: plan.landing.merged,
                trusted: plan.landing.trusted,
                ..Landing::default()
            };
            let rekeyed = self.land(built, anchor::Src::Adopt, pw);
            drop(r);
            return rekeyed;
        }
        if spec.tombstones.len() > TOMB_MAX {
            return Err(TOMBSTONES_FULL);
        }
        let index = |c: &[u8; 16]| plan.slots.iter().position(|s| s.credhash == *c);
        let mask = |cs: &[[u8; 16]]| cs.iter().filter_map(&index).fold(0u8, |m, j| m | 1 << j);
        let present: Vec<[u8; 16]> = plan.present.iter().map(|(c, _)| *c).collect();
        let (present_mask, suspended_mask) = (mask(&present), mask(&plan.suspended));
        let a = index(&plan.authorizer).ok_or(NOT_PLANNED)?;
        let s = Secret::random()?;
        let keys_plan = keyfile::KeysPlan {
            sync: plan.sync,
            pin: plan.pin,
            s: &s,
            slots: plan.slots.clone(),
            authorizer: a as u8,
            present: present_mask,
            suspended: suspended_mask,
            pairs: plan.pairs.clone(),
            outputs: plan
                .present
                .iter()
                .filter_map(|(c, h)| Some((index(c)? as u8, &***h)))
                .collect(),
            inbox: plan
                .inbox
                .iter()
                .filter_map(|(c, ik)| Some((index(c)? as u8, &***ik)))
                .collect(),
        };
        let (bytes, writer) = keyfile::seal(&spec, &bundle, password, Plan::Keys(&keys_plan))?;
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut bytes = bytes;
        #[cfg(test)]
        super::corrupt("K", &mut bytes);
        let file = KeyFile::from_bytes(&self.key_path, bytes).map_err(|_| NOT_VERIFIED)?;
        let kh = file.header().ok_or(NOT_VERIFIED)?.clone();
        let opened = file
            .verify_keys(&writer, &keys_plan)
            .map_err(|_| NOT_VERIFIED)?;
        drop(writer);
        let mut sorted = spec.tombstones.clone();
        sorted.sort_unstable_by_key(|t| (t.epoch(), t.credhash));
        let ids: Vec<[u8; 16]> = bundle.keys().iter().map(|k| key_id(&id, k)).collect();
        let magic = if plan.sync { Magic::Ks01 } else { Magic::Kh01 };
        if kh.magic != magic
            || kh.spec()
                != (Spec {
                    tombstones: sorted,
                    ..spec
                })
            || kh.key_ids != ids
            || kh.otp() != self.uses_otp()
            || kh.pin() != plan.pin
            || kh.authorizer != Some(a as u8)
            || (kh.present, kh.suspended) != (present_mask, suspended_mask)
            || !opened.bundle.same(&bundle)
            || kh.key_ids.last() != Some(&key_id(&id, self.keys.id_key()))
        {
            return Err(NOT_VERIFIED);
        }
        drop(keys_plan);
        let mut built = self.with_vault(file, kh, opened.bundle, Some(probe))?;
        built.landing = plan.landing;
        let rekeyed = self.land(built, anchor::Src::Adopt, pw);
        drop(r);
        rekeyed
    }
    /// The outputs of an adopt's extra touches for this PC's seeds, each
    /// proved against its own slot (W3).
    pub(super) fn extra_outputs(
        &self,
        r: &Reauth,
        extra: &[Touch],
    ) -> Result<Vec<([u8; 16], Box<Key>)>> {
        let mut out: Vec<([u8; 16], Box<Key>)> = Vec::new();
        let Some(h) = self.key_file.header() else {
            return if extra.is_empty() {
                Ok(out)
            } else {
                Err(NOT_PLANNED)
            };
        };
        for t in extra {
            let number = self.check_touch(r, t)?;
            let slot = h
                .slots
                .iter()
                .find(|s| s.number == number)
                .ok_or(NOT_PLANNED)?;
            if out.iter().any(|(c, _)| *c == slot.credhash)
                || r.keys.as_ref().is_some_and(|a| a.credhash == slot.credhash)
            {
                return Err(NOT_PLANNED);
            }
            let o = t
                .output_for(&slot.seed, &h.vault_id)
                .ok_or(fido::BAD_ANSWER)?;
            out.push((slot.credhash, super::super::boxed(o)));
        }
        Ok(out)
    }
}

/// The security-key changes, their crash matrix and their refusals (spec
/// §14.3-§14.5), on the fake authenticator with the Test KDF profile.
#[cfg(test)]
mod tests {
    use super::super::super::{
        CRASH, KeyNotice, SIMULATED_CRASH, THEN,
        anchor::{Ks, Origin},
        decode_data,
        keyfile::parse,
        not_a_failure, prepare, prepare_restore, refusal_values,
    };
    use super::super::tests::{
        Codes, GAPS, LANDED, NEW, OLD, POINTS, Pc, anchor_doc, consistent, entry, files, login,
        notices, secrets, set_before, setup,
    };
    use super::super::{CORRUPT, GATE_STALE};
    use super::*;
    use crate::{
        crypto::{KdfProfile, derive_count, set_kdf_profile},
        fido::{
            Authenticator, FidoError, check_assertion,
            fake::{Device, Fake, Fault},
            register,
        },
        otp, syncfile,
        vault::keyfile::inbox,
    };
    use std::{cell::RefCell, fs, path::Path, rc::Rc};

    /// The day of a recorded loss (2025-12-31), in Unix seconds.
    const LOSS: u64 = 1_767_139_200;

    /// Security keys plugged into one fake authenticator, by number.
    struct Keys {
        fake: Fake,
        plugged: Vec<(u8, usize)>,
    }
    impl Keys {
        fn new() -> Self {
            Self {
                fake: Fake::new(None),
                plugged: Vec::new(),
            }
        }
        /// Key `number` of vault `id`, registered on a fake key of its own.
        fn register(&mut self, id: &[u8; 16], number: u8, pin: bool) -> NewKey {
            let device = if pin {
                Device::with_pin()
            } else {
                Device::default()
            };
            let i = self.fake.plug(device);
            self.fake.touch(Some(i));
            self.plugged.retain(|(n, _)| *n != number);
            self.plugged.push((number, i));
            let now = otp::now().unwrap();
            register(&self.fake, id, number, now, pin, Vec::new()).unwrap()
        }
        fn device(&self, number: u8) -> usize {
            self.plugged.iter().find(|(n, _)| *n == number).unwrap().1
        }
        /// Key `number` touched for `req`, checked as the app's ceremony
        /// checks it.
        fn touch(&self, number: u8, req: &AssertRequest) -> std::result::Result<Touch, FidoError> {
            self.fake.touch(Some(self.device(number)));
            let raw = self.fake.get_assertion(req, &self.fake.new_cancel()?)?;
            check_assertion(raw, req, false)
        }
    }
    /// A vault of `pc` made with keys 1 to `n`, registered together, two
    /// entries and the password OLD; with `sync`, linked to a sync folder
    /// the helper made.
    fn create(pc: &Pc, n: u8, with_otp: bool, sync: bool) -> (Session, Codes, Keys) {
        create_with(pc, n, with_otp, sync, false)
    }
    /// The same in PIN mode with `pin`: every key registered with its PIN.
    fn create_with(
        pc: &Pc,
        n: u8,
        with_otp: bool,
        sync: bool,
        pin: bool,
    ) -> (Session, Codes, Keys) {
        set_kdf_profile(KdfProfile::Test);
        let p = Provision::new().unwrap();
        let mut keys = Keys::new();
        let new: Vec<NewKey> = (1..=n).map(|i| keys.register(&p.id, i, pin)).collect();
        let step = with_otp.then(|| {
            let now = otp::now().unwrap();
            let code = format!("{:06}", otp::code(p.otp.as_slice(), now / 30, 6));
            p.check_otp(&code, now).unwrap()
        });
        pc.here();
        let mut s = p
            .finish_with_keys(&pc.vault(), &pc.key(), OLD, step, pin, new)
            .unwrap();
        // As if made minutes ago, so that every step of the window is left.
        s.last = 0;
        s.save().unwrap();
        s.put(None, entry("one")).unwrap();
        s.put(None, entry("two")).unwrap();
        if sync {
            let dir = syncfile::sync_dir(&pc.vault()).unwrap();
            fs::create_dir(&dir).unwrap();
            let now = otp::now().unwrap();
            let status = syncfile::render_status(now, now, syncfile::SyncState::Ok);
            syncfile::replace_file(&dir.join(syncfile::STATUS), &status).unwrap();
            s.enable_sync().unwrap();
        }
        let codes = Codes {
            secret: with_otp.then(|| **p.otp),
            at: otp::now().unwrap() - 150,
        };
        (s, codes, keys)
    }
    /// A login with `password` and, for a key file with keys, a touch of
    /// key `number`.
    fn open(
        pc: &Pc,
        password: &str,
        codes: &mut Codes,
        keys: &Keys,
        number: u8,
    ) -> Result<Session> {
        pc.here();
        let prepared = prepare(&pc.vault(), &pc.key())?;
        let (code, typed) = codes.next();
        match prepared.unlock_request(0) {
            Some(req) => {
                let t = keys.touch(number, &req).map_err(FidoError::text)?;
                Session::login_with(prepared, password, &code, typed, None, &t)
            }
            None => Session::login(prepared, password, &code, typed, None),
        }
    }
    /// A Reauth with `password` and a touch of key `number`.
    fn reauth(
        s: &mut Session,
        password: &str,
        codes: &mut Codes,
        keys: &Keys,
        number: u8,
    ) -> Result<Reauth> {
        let req = s.key_request(&[number], 0)?;
        let t = keys.touch(number, &req).map_err(FidoError::text)?;
        let (code, typed) = codes.next();
        s.reauth(password, Some((&code, typed)), Some(&t))
    }
    /// One touch of each key numbered `numbers`, as extra touches.
    fn touches(s: &Session, keys: &Keys, numbers: &[u8]) -> Vec<Touch> {
        numbers
            .iter()
            .map(|n| keys.touch(*n, &s.key_request(&[*n], 0).unwrap()).unwrap())
            .collect()
    }
    fn header(pc: &Pc) -> KeyHeader {
        parse(&fs::read(pc.key()).unwrap()).unwrap()
    }
    fn numbers(h: &KeyHeader) -> Vec<u8> {
        h.slots.iter().map(|s| s.number).collect()
    }
    fn credhash(h: &KeyHeader, number: u8) -> [u8; 16] {
        h.slots
            .iter()
            .find(|s| s.number == number)
            .unwrap()
            .credhash
    }
    /// Every pair record of a key file: its keys' numbers and its wrap.
    fn records(bytes: &[u8]) -> Vec<((u8, u8), Vec<u8>)> {
        let f = KeyFile::from_bytes(Path::new("k.goyokey"), bytes.to_vec()).unwrap();
        let h = f.header().unwrap();
        let number = |c: &[u8; 16]| h.slots.iter().find(|s| s.credhash == *c).unwrap().number;
        f.carried_pairs()
            .into_iter()
            .map(|p| match p {
                PairPlan::Copy {
                    owner,
                    target,
                    wrap,
                } => ((number(&owner), number(&target)), wrap.to_vec()),
                PairPlan::New { .. } => panic!("a parsed record is carried"),
            })
            .collect()
    }
    /// Key file `bytes` opened with `password` and a touch of key `number`
    /// (none for a file without keys).
    fn opened(bytes: &[u8], password: &str, keys: &Keys, number: u8) -> keyfile::Opened {
        let f = KeyFile::from_bytes(Path::new("k.goyokey"), bytes.to_vec()).unwrap();
        let Some(h) = f.header().filter(|h| !h.slots.is_empty()) else {
            return f.open(password, None).unwrap();
        };
        let allow = h
            .slots
            .iter()
            .map(|s| (s.cred_id.clone(), salt(&h.vault_id, &s.seed), None))
            .collect();
        let req = AssertRequest::new(0, allow, h.pin()).unwrap();
        f.open(password, Some(&keys.touch(number, &req).unwrap()))
            .unwrap()
    }
    fn remove(numbers: &[u8], loss: Option<LossReport>, password: Option<&str>) -> Change {
        Change::Remove {
            remove: numbers.to_vec(),
            new_password: password.map(|p| Zeroizing::new(p.to_owned())),
            loss,
            over: None,
        }
    }
    fn consent(numbers: &[u8]) -> Consent {
        Consent {
            suspend: numbers.to_vec(),
        }
    }
    fn password(p: &str) -> Change {
        Change::Password(Zeroizing::new(p.to_owned()))
    }

    /// Spec §5.9 and §14.3: a vault made with 1, 2 and 4 keys holds every
    /// ordered pair of them, its anchor line written by this PC, and opens
    /// and restores with each key; a wrong password with a right key fails
    /// after one Argon2; a key of another vault gets no answer.
    #[test]
    fn a_vault_made_with_keys_opens_with_each_of_them() {
        for (n, with_otp) in [(1, false), (2, true), (4, false)] {
            let pc = Pc::new();
            let (s, mut codes, mut keys) = create(&pc, n, with_otp, false);
            let id = s.id;
            let h = header(&pc);
            assert_eq!(
                (h.magic, h.kind, h.epoch, h.next),
                (Magic::Kh01, Kind::KeysOn, 1, n + 1)
            );
            assert_eq!(numbers(&h), (1..=n).collect::<Vec<_>>());
            assert_eq!(h.pairs.len(), usize::from(n * (n - 1)));
            assert_eq!(
                (h.present, h.suspended, h.authorizer),
                (all(usize::from(n)), 0, Some(0))
            );
            assert!(
                h.slots
                    .iter()
                    .all(|s| s.added_epoch == 1 && s.added_by == [0; 16])
            );
            let lines = pc.lines(&id);
            assert!(lines.pending.is_none());
            let line = lines.vault.unwrap();
            assert_eq!(line.state.key_state(), h.state());
            assert!(line.state.flags.t);
            assert_eq!(line.state.slots.len(), usize::from(n));
            assert_eq!(line.vkey, Some(h.current_key_id()));
            drop(s);
            for k in 1..=n {
                let mut s = open(&pc, OLD, &mut codes, &keys, k).unwrap();
                assert_eq!(s.unlocked_with(), Some(k));
                assert_eq!(secrets(&s), ["one", "two"]);
                assert!(notices(&mut s).is_empty());
            }
            let derived = derive_count();
            assert_eq!(open(&pc, NEW, &mut codes, &keys, n).err(), Some(AUTH_ERROR));
            assert_eq!(derive_count(), derived + 1);
            keys.register(&[9; 16], 9, false);
            let req = prepare(&pc.vault(), &pc.key())
                .unwrap()
                .unlock_request(0)
                .unwrap();
            assert_eq!(keys.touch(9, &req).err(), Some(FidoError::Cancelled));
            let dest = pc.file("restored.goyo");
            let prepared = prepare_restore(&pc.vault(), &pc.key()).unwrap();
            let t = keys.touch(1, &prepared.unlock_request(0).unwrap()).unwrap();
            let (code, typed) = codes.next();
            let r = Session::restore_with(prepared, &dest, OLD, &code, typed, &t).unwrap();
            assert_eq!(secrets(&r), ["one", "two"]);
            assert!(dest.exists());
        }
        set_kdf_profile(KdfProfile::Real);
    }

    /// Spec §5.9, S45-2 #7 and crash row C16: an anchor that cannot be
    /// written stops the vault before any file, and a crash after the key
    /// and vault files leaves the line the next unlock promotes: written by
    /// this PC, with no question.
    #[test]
    fn a_vault_made_with_keys_writes_its_anchor_line_first() {
        set_kdf_profile(KdfProfile::Test);
        let pc = Pc::new();
        fs::write(pc.anchor_dir(), b"not a folder").unwrap();
        pc.here();
        let p = Provision::new().unwrap();
        assert_eq!(p.check_anchor(), Err(ANCHOR_FAILED));
        let mut keys = Keys::new();
        let new = vec![keys.register(&p.id, 1, false)];
        let made = p.finish_with_keys(&pc.vault(), &pc.key(), OLD, None, false, new);
        assert_eq!(made.err(), Some(ANCHOR_FAILED));
        assert!(!pc.vault().exists() && !pc.key().exists());
        fs::remove_file(pc.anchor_dir()).unwrap();
        assert_eq!(p.check_anchor(), Ok(()));
        for point in [
            "S0",
            "S0.tmp_synced",
            "S2.tmp_synced",
            "S2.renamed",
            "S2v",
            "S3.tmp_synced",
            "S3.renamed",
            "S3v",
            "S5.tmp_synced",
            "S5",
        ] {
            let pc = Pc::new();
            let p = Provision::new().unwrap();
            let mut keys = Keys::new();
            let new = vec![
                keys.register(&p.id, 1, false),
                keys.register(&p.id, 2, false),
            ];
            CRASH.with(|c| c.set(Some(point)));
            let made = p.finish_with_keys(&pc.vault(), &pc.key(), OLD, None, false, new);
            assert_eq!(made.err(), Some(SIMULATED_CRASH), "{point}");
            assert_eq!(CRASH.with(|c| c.get()), None, "{point}");
            // Before the vault file (or its temp file): a vault made
            // halfway, as in 0.8.
            if point.starts_with("S0") || point.starts_with("S2") {
                assert!(!pc.vault().exists(), "{point}");
                continue;
            }
            let mut codes = Codes {
                secret: None,
                at: 0,
            };
            let mut s = open(&pc, OLD, &mut codes, &keys, 2).unwrap();
            assert!(notices(&mut s).is_empty(), "{point}");
            assert!(secrets(&s).is_empty());
            let lines = pc.lines(&p.id);
            assert!(lines.pending.is_none(), "{point}");
            let line = lines.vault.unwrap();
            assert!(line.state.flags.t, "{point}");
            assert_eq!(line.state.key_state(), s.key_state(), "{point}");
            assert_eq!(line.vkey, Some(header(&pc).current_key_id()), "{point}");
        }
        // S5 fails with no crash (another process holds the anchor's lock):
        // the promoted line stays in memory and lands with the next write
        // of the anchor, a key change's R0 probe here, before that change
        // fails with nothing written (E-S2a: the key file cannot be
        // replaced). The next login is this PC's own state, no bootstrap.
        let pc = Pc::new();
        pc.here();
        let p = Provision::new().unwrap();
        let mut keys = Keys::new();
        let new = vec![
            keys.register(&p.id, 1, false),
            keys.register(&p.id, 2, false),
        ];
        let lock = Rc::new(RefCell::new(None));
        let hold = lock.clone();
        let dir = pc.anchor_dir();
        set_before("S5", move || {
            *hold.borrow_mut() = Some(anchor::hold_lock(&dir))
        });
        let mut s = p
            .finish_with_keys(&pc.vault(), &pc.key(), OLD, None, false, new)
            .unwrap();
        drop(lock.borrow_mut().take());
        assert_eq!(s.take_key_notices(), [KeyNotice::AnchorFailed]);
        assert!(pc.lines(&p.id).vault.is_none());
        assert_eq!(s.change_gate(&password(NEW)).err(), Some(ANCHOR_FAILED));
        s.save().unwrap();
        let mut perms = fs::metadata(pc.key()).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(pc.key(), perms.clone()).unwrap();
        let mut codes = Codes {
            secret: None,
            at: 0,
        };
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        let changed = s.rekey(r, Vec::new(), password(NEW), Consent::default(), false);
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(pc.key(), perms).unwrap();
        assert_eq!(changed.err(), Some(super::super::KEY_NOT_SAVED));
        drop(s);
        let lines = pc.lines(&p.id);
        assert!(lines.pending.is_none());
        assert!(lines.vault.unwrap().state.flags.t);
        let s = open(&pc, OLD, &mut codes, &keys, 1).unwrap();
        assert!(!s.tofu() && !s.gate_pending());
        set_kdf_profile(KdfProfile::Real);
    }

    /// The core of D5 and walkthrough §7.21-17 (spec §14.4-6): four keys
    /// registered together, two at each site; key 1 is lost at A and removed
    /// with one touch of key 2. Keys 3 and 4 at B open the result with no key
    /// carried and no touch of theirs during the write; nothing derivable
    /// from key 1's output opens it, and the old data keys open no vault
    /// file it seals. The pending line records the user's removal and the
    /// flow's answers.
    #[test]
    fn a_lost_key_is_removed_with_one_touch_and_no_key_carried() {
        let pc = Pc::new();
        let (mut s, mut codes, keys) = create(&pc, 4, false, false);
        let id = s.id;
        let old_bytes = fs::read(pc.key()).unwrap();
        let old = header(&pc);
        let old_records = records(&old_bytes);
        let t1 = keys.touch(1, &s.key_request(&[1], 0).unwrap()).unwrap();
        let h1 = *t1.output_for(&old.slots[0].seed, &id).unwrap();
        let before = opened(&old_bytes, OLD, &keys, 1);
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        assert_eq!((r.reach(), r.key()), (&[1, 2, 3, 4][..], Some(2)));
        let seen = Rc::new(RefCell::new(None));
        let (held, dir) = (seen.clone(), pc.anchor_dir());
        set_before("S3", move || {
            if let Ok(anchor::Parsed::Doc(doc)) = anchor::read(&dir) {
                *held.borrow_mut() = doc.lines(&id).pending;
            }
        });
        let loss = LossReport {
            date: Some(LOSS),
            exposure: Exposure::Unsure,
            shared_pin: vec![3, 1],
        };
        let change = remove(&[1], Some(loss), Some(NEW));
        assert_eq!(
            s.rekey(r, Vec::new(), change, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!(
            (h.kind, h.epoch, numbers(&h)),
            (Kind::Remove, 2, vec![2, 3, 4])
        );
        assert_eq!(h.wraps, [(0, 0), (1, 0), (2, 0)]);
        assert_eq!((h.present, h.suspended, h.authorizer), (0b001, 0, Some(0)));
        assert_ne!((h.pw_id, h.ks_id), (old.pw_id, old.ks_id));
        assert_eq!(h.loss, LOSS);
        let mark = LOSS / 86_400 + 2;
        assert_eq!(
            h.tombstones,
            [Tombstone {
                credhash: old.slots[0].credhash,
                removed: 2 | mark << 48,
            }]
        );
        // Every record between staying keys carried byte for byte, none of
        // key 1's.
        let kept: Vec<_> = old_records
            .iter()
            .filter(|((o, t), _)| *o != 1 && *t != 1)
            .cloned()
            .collect();
        assert_eq!(records(&fs::read(pc.key()).unwrap()), kept);
        let pending = seen.borrow_mut().take().expect("the pending line");
        assert_eq!(pending.rm, [(1, Origin::Own)]);
        assert_eq!(
            (pending.loss.as_deref(), pending.exp, pending.clone.clone()),
            (Some("20251231"), Some(b'u'), vec![3])
        );
        assert_eq!(
            (pending.src, pending.pw),
            (anchor::Src::Lost, Some(anchor::Pw::New))
        );
        let lines = pc.lines(&id);
        let line = lines.vault.unwrap();
        let tomb = &line.state.tombs[0];
        assert_eq!(
            (tomb.credhash, tomb.origin),
            (old.slots[0].credhash, Origin::Own)
        );
        assert_eq!(tomb.keyid, h.current_key_id());
        assert!(line.state.flags.t && lines.pending.is_none());
        drop(s);
        for k in [3, 4, 2] {
            let s = open(&pc, NEW, &mut codes, &keys, k).unwrap();
            assert_eq!(s.unlocked_with(), Some(k));
        }
        assert_eq!(open(&pc, OLD, &mut codes, &keys, 3).err(), Some(AUTH_ERROR));
        let req = prepare(&pc.vault(), &pc.key())
            .unwrap()
            .unlock_request(0)
            .unwrap();
        assert_eq!(keys.touch(1, &req).err(), Some(FidoError::Cancelled));
        // The removed-key simulator: key 1's output opens no S-wrap and no
        // pair record of the result, and the old data keys no vault file.
        let f = KeyFile::read(&pc.key()).unwrap();
        for j in 0..3 {
            assert!(f.open_own(j, &h1).is_none());
            assert!(
                f.open_pairs(&h1, j as u8)
                    .iter()
                    .all(|(_, ik)| ik.is_none())
            );
        }
        let v = fs::read(pc.vault()).unwrap();
        let b = &before.bundle;
        assert!(
            b.keys()
                .iter()
                .all(|k| decode_data(&id, k, b.id_key(), &v).is_err())
        );
        let after = opened(&fs::read(pc.key()).unwrap(), NEW, &keys, 3);
        assert_ne!(before.s, after.s);
        set_kdf_profile(KdfProfile::Real);
    }

    /// Walkthroughs §7.21-17 and -24 (spec §14.4-14): a replacement key 5
    /// added at A with key 2 is paired with key 2 alone and opens at once.
    /// Before its pairing visit a password change authorized by key 3 at B
    /// refuses (S-UNREACHABLE), and a second loss there suspends key 5, only
    /// with consent. Key 5 then fails before Argon2 until a pairing with key
    /// 2 brings it back; a later change by key 4 still needs key 5 touched,
    /// which pairs them.
    #[test]
    fn a_replacement_key_and_a_second_loss_before_its_pairing_visit() {
        let pc = Pc::new();
        let (mut s, mut codes, mut keys) = create(&pc, 4, false, false);
        let id = s.id;
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        let change = remove(&[1], None, None);
        assert_eq!(
            s.rekey(r, Vec::new(), change, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        // The replacement, added with key 2 alone.
        let key5 = keys.register(&id, 5, false);
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        let dk = *s.keys.current();
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                Change::AddKey(key5),
                Consent::default(),
                false
            ),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!((h.kind, numbers(&h)), (Kind::AddKey, vec![2, 3, 4, 5]));
        let five = h.slots.iter().find(|s| s.number == 5).unwrap();
        assert_eq!(
            (five.added_epoch, five.added_by),
            (h.epoch, credhash(&h, 2))
        );
        assert_eq!(h.reach(5), [2, 5]);
        assert_eq!(*s.keys.current(), dk, "an added key keeps the data key");
        drop(s);
        let s5 = open(&pc, OLD, &mut codes, &keys, 5).unwrap();
        assert_eq!(s5.unlocked_with(), Some(5));
        drop(s5);
        // At B, before the visit: key 3 does not reach key 5.
        let mut s = open(&pc, OLD, &mut codes, &keys, 3).unwrap();
        let start = files(&pc);
        let r = reauth(&mut s, OLD, &mut codes, &keys, 3).unwrap();
        assert_eq!(r.reach(), [2, 3, 4]);
        let refused = s.rekey(r, Vec::new(), password(NEW), Consent::default(), false);
        assert_eq!(refused, Err(UNREACHABLE));
        assert_eq!(refusal_values(UNREACHABLE), Some(vec!["5".into()]));
        assert_eq!(files(&pc), start);
        // Key 3 is lost there: the removal by key 4 suspends key 5 only
        // with consent.
        let r = reauth(&mut s, OLD, &mut codes, &keys, 4).unwrap();
        let refused = s.rekey(r, Vec::new(), remove(&[3], None, None), consent(&[]), false);
        assert_eq!(refused, Err(REACH_CHANGED));
        assert_eq!(refusal_values(REACH_CHANGED), Some(vec!["5".into()]));
        assert_eq!(files(&pc), start);
        let r = reauth(&mut s, OLD, &mut codes, &keys, 4).unwrap();
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                remove(&[3], None, None),
                consent(&[5]),
                false
            ),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!(numbers(&h), [2, 4, 5]);
        assert_eq!((h.suspended, h.present), (0b100, 0b010));
        assert!(h.wraps.iter().all(|(j, _)| *j != 2));
        assert_eq!(h.tombstones.iter().map(|t| t.loss_mark()).max(), Some(0));
        drop(s);
        // At A key 5 fails before Argon2.
        let derived = derive_count();
        assert_eq!(
            open(&pc, OLD, &mut codes, &keys, 5).err(),
            Some(keyfile::SUSPENDED_KEY)
        );
        assert_eq!(
            refusal_values(keyfile::SUSPENDED_KEY),
            Some(vec!["5".into()])
        );
        assert!(not_a_failure(keyfile::SUSPENDED_KEY));
        assert_eq!(derive_count(), derived);
        // Pairing keys 2 and 5 brings it back: a suspended key proves itself
        // with its own pair record.
        let mut s = open(&pc, OLD, &mut codes, &keys, 2).unwrap();
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        let extra = touches(&s, &keys, &[5]);
        assert_eq!(s.check_touch(&r, &extra[0]), Ok(5));
        assert_eq!(
            s.rekey(r, extra, Change::Pair, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!((h.kind, h.suspended, h.present), (Kind::Pair, 0, 0b101));
        drop(s);
        let s5 = open(&pc, OLD, &mut codes, &keys, 5).unwrap();
        assert_eq!(s5.unlocked_with(), Some(5));
        drop(s5);
        // Key 4 still does not reach key 5; touched together it does, and
        // the write pairs them.
        let mut s = open(&pc, OLD, &mut codes, &keys, 4).unwrap();
        let r = reauth(&mut s, OLD, &mut codes, &keys, 4).unwrap();
        assert_eq!(
            s.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
            Err(UNREACHABLE)
        );
        let r = reauth(&mut s, OLD, &mut codes, &keys, 4).unwrap();
        let extra = touches(&s, &keys, &[5]);
        assert_eq!(
            s.rekey(r, extra, password(NEW), Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!((h.reach(4), h.reach(5)), (vec![2, 4, 5], vec![2, 4, 5]));
        set_kdf_profile(KdfProfile::Real);
    }

    /// Spec §14.4-7 and -15: an added key is paired with exactly the keys
    /// touched in its flow, every record it does not touch is carried byte
    /// for byte, and a later pairing writes only the missing records. The
    /// data key stays; S is fresh for every write.
    #[test]
    fn an_added_key_is_paired_with_the_touched_keys_only() {
        let pc = Pc::new();
        let (mut s, mut codes, mut keys) = create(&pc, 2, false, true);
        let id = s.id;
        let start = fs::read(pc.key()).unwrap();
        let dk = *s.keys.current();
        // Key 3 with key 1 alone.
        let key3 = keys.register(&id, 3, false);
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                Change::AddKey(key3),
                Consent::default(),
                true
            ),
            Ok(Rekeyed::Done)
        );
        let after3 = fs::read(pc.key()).unwrap();
        assert_ne!(header(&pc).ks_id, parse(&start).unwrap().ks_id);
        let pairs: Vec<(u8, u8)> = records(&after3).into_iter().map(|(p, _)| p).collect();
        assert_eq!(pairs, [(1, 2), (1, 3), (2, 1), (3, 1)]);
        for record in records(&start) {
            assert!(records(&after3).contains(&record));
        }
        assert_eq!(*s.keys.current(), dk);
        consistent(&pc, &s);
        // Key 4 with keys 1 and 2.
        let key4 = keys.register(&id, 4, false);
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        let extra = touches(&s, &keys, &[2]);
        assert_eq!(
            s.rekey(r, extra, Change::AddKey(key4), Consent::default(), true),
            Ok(Rekeyed::Done)
        );
        let after4 = fs::read(pc.key()).unwrap();
        let h = header(&pc);
        assert_eq!((h.reach(4), h.reach(3)), (vec![1, 2, 4], vec![1, 3]));
        let four = h.slots.iter().find(|s| s.number == 4).unwrap();
        assert_eq!(four.added_by, credhash(&h, 1));
        // Pairing keys 2 and 3: only their two records are new.
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        let extra = touches(&s, &keys, &[3]);
        assert_eq!(
            s.rekey(r, extra, Change::Pair, Consent::default(), true),
            Ok(Rekeyed::Done)
        );
        let paired = records(&fs::read(pc.key()).unwrap());
        let new: Vec<(u8, u8)> = paired
            .iter()
            .filter(|r| !records(&after4).contains(r))
            .map(|(p, _)| *p)
            .collect();
        assert_eq!(new, [(2, 3), (3, 2)]);
        assert_eq!(paired.len(), records(&after4).len() + 2);
        assert_eq!(*s.keys.current(), dk);
        consistent(&pc, &s);
        drop(s);
        for k in 1..=4 {
            let s = open(&pc, OLD, &mut codes, &keys, k).unwrap();
            assert_eq!(s.unlocked_with(), Some(k));
        }
        set_kdf_profile(KdfProfile::Real);
    }

    /// Spec §5.10 (AnchorFailed): a key change of a security-key session
    /// whose S5 cannot reach the anchor (its lock held by another process)
    /// keeps the promotion in memory and says S-ANCHOR-FAILED; until a save
    /// or poll writes it, key changes are refused and nothing goes up.
    #[test]
    fn an_anchor_that_cannot_be_written_holds_a_security_key_session() {
        let pc = Pc::new();
        let (mut s, mut codes, keys) = create(&pc, 2, false, true);
        let id = s.id;
        let outgoing = syncfile::sync_dir(&pc.vault())
            .unwrap()
            .join(syncfile::OUTGOING);
        let lock = Rc::new(RefCell::new(None));
        let hold = lock.clone();
        let dir = pc.anchor_dir();
        set_before("S3", move || {
            *hold.borrow_mut() = Some(anchor::hold_lock(&dir))
        });
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        assert_eq!(
            s.rekey(r, Vec::new(), password(NEW), Consent::default(), true),
            Ok(Rekeyed::Done)
        );
        assert_eq!(s.take_key_notices(), [KeyNotice::AnchorFailed]);
        assert_eq!(s.change_gate(&password(OLD)).err(), Some(ANCHOR_FAILED));
        let sent = fs::read(&outgoing).ok();
        s.put(None, entry("three")).unwrap();
        assert_eq!(fs::read(&outgoing).ok(), sent);
        assert!(pc.lines(&id).pending.is_some());
        drop(lock.borrow_mut().take());
        let _ = s.poll_sync();
        let lines = pc.lines(&id);
        assert!(lines.pending.is_none());
        assert_eq!(lines.vault.unwrap().state.key_state(), s.key_state());
        assert!(s.change_gate(&password(OLD)).is_ok());
        s.put(None, entry("four")).unwrap();
        assert_ne!(fs::read(&outgoing).ok(), sent);
        set_kdf_profile(KdfProfile::Real);
    }

    /// Spec §5.5 S5, §5.10 (S45-2 #10): a removal for a loss answered 예
    /// flags the keys that share the exposed PIN "possibly cloned" when it
    /// lands, each with its seed's hash; a re-seed retires the flag in the
    /// same write of the confirmed line.
    #[test]
    fn possibly_cloned_flags_land_with_the_removal_and_go_with_a_reseed() {
        let pc = Pc::new();
        let (mut s, mut codes, keys) = create(&pc, 3, false, false);
        let id = s.id;
        let three = credhash(&header(&pc), 3);
        let loss = LossReport {
            date: Some(LOSS),
            exposure: Exposure::Yes,
            shared_pin: vec![3],
        };
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        let change = remove(&[1], Some(loss), None);
        assert_eq!(
            s.rekey(r, Vec::new(), change, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        let seed = header(&pc)
            .slots
            .iter()
            .find(|x| x.number == 3)
            .unwrap()
            .seed;
        let flags = pc.lines(&id).clones;
        assert_eq!(
            flags,
            [(three, anchor::slot_of(&header(&pc).slots[1]).seedhash)]
        );
        assert_eq!(
            anchor::prefix::<16>(&crate::vault::sha256(&seed)),
            flags[0].1
        );
        let mut plan = s.plan_reseed().unwrap();
        let t = keys.touch(2, &plan.request(0).unwrap()).unwrap();
        let (code, typed) = codes.next();
        let r = s.reauth(OLD, Some((&code, typed)), Some(&t)).unwrap();
        plan.take(&s, &r, &t).unwrap();
        let t = keys.touch(3, &plan.request(0).unwrap()).unwrap();
        plan.take(&s, &r, &t).unwrap();
        let t = keys.touch(3, &plan.second_request(3, 0).unwrap()).unwrap();
        plan.confirm(&t).unwrap();
        let change = Change::ReSeed(plan.finish().unwrap());
        assert_eq!(
            s.rekey(r, Vec::new(), change, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        assert!(pc.lines(&id).clones.is_empty());
        set_kdf_profile(KdfProfile::Real);
    }

    /// The re-seed's first touch is its Reauth (spec §9.2 re-seed step 3,
    /// §9.2a): its allow list holds only the keys the flow names as live
    /// and not suspended; every later one holds every key not yet proved.
    #[test]
    fn a_reseeds_first_touch_lists_only_active_keys() {
        let pc = Pc::new();
        let (s, _codes, keys) = create(&pc, 2, false, false);
        let plan = s.plan_reseed().unwrap();
        let first = plan.first_request(&[2], 0).unwrap();
        let two = header(&pc).slots[1].cred_id.clone();
        assert_eq!(first.allow.len(), 1);
        assert_eq!(first.allow[0].0, two);
        assert!(first.allow[0].2.is_some(), "two salts");
        assert_eq!(plan.request(0).unwrap().allow.len(), 2);
        drop(keys);
    }

    /// Spec §14.4-8: a re-seed gives every key a new seed, rewrites every
    /// pair record, draws a new S and data key; an output captured before
    /// opens nothing in the new file. The 2-touch fallback needs no
    /// confirmation; a confirmation that differs is S-NONDETERMINISTIC; a
    /// swapped answer fails its key's proof (S-OLDSLOT).
    #[test]
    fn a_reseed_gives_every_key_a_new_seed() {
        for no_second in [false, true] {
            let pc = Pc::new();
            let (mut s, mut codes, keys) = create(&pc, 2, false, false);
            let id = s.id;
            let start = fs::read(pc.key()).unwrap();
            let old = header(&pc);
            let dk = *s.keys.current();
            if no_second {
                for k in [1, 2] {
                    keys.fake
                        .device(keys.device(k), |d| d.fault = Fault::NoSecond);
                }
            }
            let mut plan = s.plan_reseed().unwrap();
            let t = keys.touch(1, &plan.request(0).unwrap()).unwrap();
            let captured = *t.output_for(&old.slots[0].seed, &id).unwrap();
            let r = s.reauth(OLD, Some(("", 0)), Some(&t)).unwrap();
            assert_eq!(plan.take(&s, &r, &t), Ok(1));
            let t = keys.touch(2, &plan.request(0).unwrap()).unwrap();
            assert_eq!(plan.take(&s, &r, &t), Ok(2));
            if no_second {
                for k in [1, 2] {
                    let t = keys.touch(k, &plan.second_request(k, 0).unwrap()).unwrap();
                    assert_eq!(plan.take_second(&s, &r, &t), Ok(k));
                }
            } else {
                let t = keys.touch(2, &plan.second_request(2, 0).unwrap()).unwrap();
                plan.confirm(&t).unwrap();
            }
            let change = Change::ReSeed(plan.finish().unwrap());
            assert_eq!(
                s.rekey(r, Vec::new(), change, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let h = header(&pc);
            assert_eq!((h.kind, h.present, h.suspended), (Kind::ReSeed, 0b11, 0));
            for (a, b) in old.slots.iter().zip(&h.slots) {
                assert_eq!((a.credhash, a.number), (b.credhash, b.number));
                assert_ne!(a.seed, b.seed);
            }
            let (before, after) = (records(&start), records(&fs::read(pc.key()).unwrap()));
            assert_eq!(after.len(), 2);
            assert!(after.iter().all(|r| !before.contains(r)));
            assert_ne!(*s.keys.current(), dk);
            let f = KeyFile::read(&pc.key()).unwrap();
            assert!((0..2).all(|j| f.open_own(j, &captured).is_none()));
            assert!(
                f.open_pairs(&captured, 0)
                    .iter()
                    .all(|(_, ik)| ik.is_none())
            );
            // The anchor records the re-seed as kind 8 with the new seeds.
            let line = pc.lines(&id).vault.unwrap();
            assert_eq!(line.state.hist[0].kind, 8);
            drop(s);
            for k in [1, 2] {
                let s = open(&pc, OLD, &mut codes, &keys, k).unwrap();
                assert_eq!(s.unlocked_with(), Some(k));
            }
        }
        // A confirmation that does not repeat the recorded output, and an
        // answer whose outputs Windows swapped.
        let pc = Pc::new();
        let (s, _codes, keys) = create(&pc, 2, false, false);
        let mut s = s;
        let mut plan = s.plan_reseed().unwrap();
        let t = keys.touch(1, &plan.request(0).unwrap()).unwrap();
        let r = s.reauth(OLD, Some(("", 0)), Some(&t)).unwrap();
        plan.take(&s, &r, &t).unwrap();
        keys.fake
            .device(keys.device(2), |d| d.fault = Fault::Swapped);
        let t = keys.touch(2, &plan.request(0).unwrap()).unwrap();
        assert_eq!(plan.take(&s, &r, &t), Err(OLDSLOT));
        keys.fake.device(keys.device(2), |d| d.fault = Fault::None);
        let t = keys.touch(2, &plan.request(0).unwrap()).unwrap();
        plan.take(&s, &r, &t).unwrap();
        // The key got its PIN at registration: every touch verifies it, so
        // its with-UV output is the one that changes.
        keys.fake.device(keys.device(1), |d| {
            d.credentials[0].random_uv[0] ^= 1;
        });
        let t = keys.touch(1, &plan.second_request(1, 0).unwrap()).unwrap();
        assert_eq!(plan.confirm(&t), Err(fido::NONDETERMINISTIC));
        assert_eq!(plan.finish().err(), Some(NOT_PLANNED));
        set_kdf_profile(KdfProfile::Real);
    }

    /// Spec §14.4 KeysOn and §14.4-9: keys on from a password-only key file,
    /// with "비밀번호도 바꾸기" and without; keys off back to GOYOKE03 with
    /// every former slot tombstoned by this PC, which a later keys on never
    /// lists again.
    #[test]
    fn keys_go_on_and_off() {
        for (n, new_password) in [(1, false), (2, true), (4, true)] {
            let pc = Pc::new();
            let (mut s, mut codes) = setup(&pc, true, false, false);
            let id = s.id;
            let old = header(&pc);
            let mut keys = Keys::new();
            let new: Vec<NewKey> = (1..=n).map(|k| keys.register(&id, k, false)).collect();
            let r = s.reauth(OLD, Some(("", 0)), None).unwrap();
            let change = Change::KeysOn {
                pin: false,
                keys: new,
                new_password: new_password.then(|| Zeroizing::new(NEW.to_owned())),
            };
            assert_eq!(
                s.rekey(r, Vec::new(), change, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let h = header(&pc);
            assert_eq!(
                (h.magic, h.kind, h.epoch),
                (Magic::Kh01, Kind::KeysOn, old.epoch + 1)
            );
            assert_eq!(numbers(&h), (1..=n).collect::<Vec<_>>());
            assert_eq!(h.pairs.len(), usize::from(n * (n - 1)));
            assert_eq!(h.pw_id == old.pw_id, !new_password);
            let line = pc.lines(&id).vault.unwrap();
            assert!(line.state.hardware() && line.state.flags.t);
            drop(s);
            let (right, wrong) = if new_password { (NEW, OLD) } else { (OLD, NEW) };
            assert_eq!(
                open(&pc, wrong, &mut codes, &keys, 1).err(),
                Some(AUTH_ERROR)
            );
            let mut s = open(&pc, right, &mut codes, &keys, n).unwrap();
            assert!(notices(&mut s).is_empty());
            // Keys off: every slot tombstoned at the new epoch.
            let epoch = h.epoch + 1;
            let r = reauth(&mut s, right, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                s.rekey(r, Vec::new(), Change::KeysOff, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let off = header(&pc);
            assert_eq!(
                (off.magic, off.kind, off.epoch),
                (Magic::Ke03, Kind::KeysOff, epoch)
            );
            let dead: Vec<[u8; 16]> = off.tombstones.iter().map(|t| t.credhash).collect();
            assert!(h.slots.iter().all(|s| dead.contains(&s.credhash)));
            assert!(
                off.tombstones
                    .iter()
                    .all(|t| t.epoch() == epoch && t.loss_mark() == 0)
            );
            let line = pc.lines(&id).vault.unwrap();
            assert!(!line.state.hardware());
            assert!(line.state.tombs.iter().all(|t| t.origin == Origin::Own));
            drop(s);
            let mut s = open(&pc, right, &mut codes, &keys, 1).unwrap();
            assert!(notices(&mut s).is_empty());
            // A credential of a removed slot never comes back.
            let back = NewKey {
                cred_id: h.slots[0].cred_id.clone(),
                seed: h.slots[0].seed,
                uv: false,
                cp3: false,
                output: Box::new(Zeroizing::new([7; 32])),
                registered: 1,
            };
            let r = s.reauth(right, Some(("", 0)), None).unwrap();
            let change = Change::KeysOn {
                pin: false,
                keys: vec![back],
                new_password: None,
            };
            assert_eq!(
                s.rekey(r, Vec::new(), change, Consent::default(), false),
                Err(fido::EXISTS)
            );
        }
        set_kdf_profile(KdfProfile::Real);
    }

    /// A vault made without security keys that turns them on later (spec
    /// §5.5 keys on, §14.5): from a 0.8 pair (GOYOKE01 or GOYOKE02 with
    /// GOYOVA01/02, never changed) and from a GOYOKE03 after a password
    /// change, with and without an OTP, the password kept or changed. The
    /// entries, the OTP secret, the vault ID and the ID key stay; the data
    /// key changes, so the key file from before opens nothing written after
    /// it; the new key file asks for a key and opens with either one. Keys
    /// off then brings it back to password-only (GOYOKE03) with every
    /// entry, the one added while keys were on too.
    #[test]
    fn a_vault_made_without_keys_turns_keys_on_and_off_again() {
        for kf2 in [false, true] {
            for with_otp in [false, true] {
                for new_password in [false, true] {
                    keys_on_later(kf2, with_otp, new_password);
                }
            }
        }
        set_kdf_profile(KdfProfile::Real);
    }
    fn keys_on_later(kf2: bool, with_otp: bool, new_password: bool) {
        let case = format!("kf2={kf2} otp={with_otp} new_password={new_password}");
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, kf2, with_otp, false);
        let id = s.id;
        let id_key = *s.keys.id_key();
        let before = secrets(&s);
        let old_key = fs::read(pc.key()).unwrap();
        let old_vault = fs::read(pc.vault()).unwrap();
        // What the user had: a 0.8 pair, or GOYOKE03 after a change.
        let (key_magic, vault_magics): (&[u8], [&[u8]; 2]) = match (kf2, with_otp) {
            (false, true) => (b"GOYOKE01", [b"GOYOVA01", b"GOYOVA02"]),
            (false, false) => (b"GOYOKE02", [b"GOYOVA01", b"GOYOVA02"]),
            (true, _) => (b"GOYOKE03", [b"GOYOVA03", b"GOYOVA04"]),
        };
        assert_eq!(&old_key[..8], key_magic, "{case}");
        assert!(vault_magics.contains(&&old_vault[..8]), "{case}");
        assert!(s.key_file.header().is_none_or(|h| h.slots.is_empty()));
        // Each step types new OTP codes, minutes apart.
        let later = |codes: &mut Codes| {
            otp::shift(180);
            codes.at = codes.at.max(otp::now().unwrap() - 150);
        };
        let mut keys = Keys::new();
        let new: Vec<NewKey> = (1..=2).map(|k| keys.register(&id, k, false)).collect();
        later(&mut codes);
        let (code, typed) = codes.next();
        let r = s.reauth(OLD, Some((&code, typed)), None).unwrap();
        let change = Change::KeysOn {
            pin: false,
            keys: new,
            new_password: new_password.then(|| Zeroizing::new(NEW.to_owned())),
        };
        assert_eq!(
            s.rekey(r, Vec::new(), change, Consent::default(), false),
            Ok(Rekeyed::Done),
            "{case}"
        );
        let on = header(&pc);
        assert_eq!((on.magic, on.kind), (Magic::Kh01, Kind::KeysOn), "{case}");
        assert_eq!(numbers(&on), [1, 2], "{case}");
        assert_eq!(on.vault_id, id, "{case}");
        let vault = fs::read(pc.vault()).unwrap();
        assert!(
            [&b"GOYOVA03"[..], b"GOYOVA04"].contains(&&vault[..8]),
            "{case}"
        );
        assert_eq!(secrets(&s), before, "{case}");
        assert_eq!(s.keys.id_key(), &id_key, "{case}");
        assert_eq!(s.uses_otp(), with_otp, "{case}");
        let line = pc.lines(&id).vault.unwrap();
        assert!(line.state.hardware() && line.state.flags.t, "{case}");
        consistent(&pc, &s);
        drop(s);
        // The old key file opens nothing written now (I4).
        let old_opens = |vault: &[u8]| {
            let b = opened(&old_key, OLD, &keys, 1).bundle;
            b.keys()
                .iter()
                .any(|dk| decode_data(&id, dk, b.id_key(), vault).is_ok())
        };
        assert!(old_opens(&old_vault), "{case}");
        assert!(!old_opens(&vault), "{case}");
        // The new pair asks for a key; the old password fails when it
        // changed; either key opens it.
        let (right, wrong) = if new_password { (NEW, OLD) } else { (OLD, NEW) };
        later(&mut codes);
        assert_eq!(
            open(&pc, wrong, &mut codes, &keys, 1).err(),
            Some(AUTH_ERROR),
            "{case}"
        );
        pc.here();
        let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
        assert!(prepared.unlock_request(0).is_some(), "{case}: no key asked");
        drop(prepared);
        for number in [2, 1] {
            let mut s = open(&pc, right, &mut codes, &keys, number)
                .unwrap_or_else(|e| panic!("{case}: key {number}: {e}"));
            assert!(notices(&mut s).is_empty(), "{case}");
            assert_eq!(secrets(&s), before, "{case}");
            assert_eq!(s.id, id, "{case}");
        }
        // Used with keys on: an entry added.
        later(&mut codes);
        let mut s = open(&pc, right, &mut codes, &keys, 1).unwrap();
        s.put(None, entry("three")).unwrap();
        let with_three = secrets(&s);
        // Keys off: password-only again (GOYOKE03), every entry kept.
        let r = reauth(&mut s, right, &mut codes, &keys, 2).unwrap();
        assert_eq!(
            s.rekey(r, Vec::new(), Change::KeysOff, Consent::default(), false),
            Ok(Rekeyed::Done),
            "{case}"
        );
        let off = header(&pc);
        assert_eq!(
            (off.magic, off.kind, off.epoch),
            (Magic::Ke03, Kind::KeysOff, on.epoch + 1),
            "{case}"
        );
        assert!(off.slots.is_empty() && off.tombstones.len() == 2, "{case}");
        assert_eq!(secrets(&s), with_three, "{case}");
        assert_eq!(s.keys.id_key(), &id_key, "{case}");
        assert!(!pc.lines(&id).vault.unwrap().state.hardware(), "{case}");
        let keyed = fs::read(pc.key()).unwrap();
        drop(s);
        // Opens with the password alone (no key asked), the OTP kept.
        later(&mut codes);
        pc.here();
        let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
        assert!(prepared.unlock_request(0).is_none(), "{case}");
        drop(prepared);
        let mut s = login(&pc, right, &mut codes).unwrap_or_else(|e| panic!("{case}: {e}"));
        assert!(notices(&mut s).is_empty(), "{case}");
        assert_eq!(secrets(&s), with_three, "{case}");
        assert_eq!(s.uses_otp(), with_otp, "{case}");
        assert_eq!(s.keys.id_key(), &id_key, "{case}");
        assert_eq!(fs::read(pc.key()).unwrap(), keyed, "{case}");
        drop(s);
        // The key file from before keys on opens nothing keys off wrote.
        assert!(!old_opens(&fs::read(pc.vault()).unwrap()), "{case}");
    }

    /// Plants in place of `s`'s key file (three keys) one at the next epoch
    /// whose pair record PR(2,3) is garbage: what a no-gate file another PC
    /// took could carry (spec §14.4-19). Same keys, password and S-wraps
    /// through key 1.
    fn plant_broken_record(pc: &Pc, s: Session, keys: &Keys) {
        let id = s.id;
        let f = KeyFile::read(&pc.key()).unwrap();
        let h = f.header().unwrap().clone();
        let t1 = keys.touch(1, &s.key_request(&[1], 0).unwrap()).unwrap();
        drop(s);
        let o = f.open(OLD, Some(&t1)).unwrap();
        let h1 = *t1.output_for(&h.slots[0].seed, &id).unwrap();
        let secret = Secret::of(&o).unwrap();
        let iks: Vec<(u8, Box<Key>)> = f
            .open_pairs(&h1, 0)
            .into_iter()
            .map(|(t, ik)| (t, ik.unwrap()))
            .collect();
        let broken = (h.slots[1].credhash, h.slots[2].credhash);
        let pairs = f
            .carried_pairs()
            .into_iter()
            .map(|p| match p {
                PairPlan::Copy { owner, target, .. } if (owner, target) == broken => {
                    PairPlan::Copy {
                        owner,
                        target,
                        wrap: [0x5a; 104],
                    }
                }
                p => p,
            })
            .collect();
        let plan = keyfile::KeysPlan {
            sync: false,
            pin: false,
            s: &secret,
            slots: h.slots.clone(),
            authorizer: 0,
            present: 0b001,
            suspended: 0,
            pairs,
            outputs: vec![(0, &h1)],
            inbox: iks.iter().map(|(t, ik)| (*t, &***ik)).collect(),
        };
        let spec = Spec {
            epoch: h.epoch + 1,
            kind: Kind::Password,
            ..h.spec()
        };
        let (planted, _) = keyfile::seal(&spec, &o.bundle, OLD, Plan::Keys(&plan)).unwrap();
        fs::write(pc.key(), planted).unwrap();
    }

    /// Spec §14.4-15 and -19 (S45-2 #6, S45-3 #6): a broken record PR(2,3)
    /// of a key this PC was never unlocked with is found by the unlock or
    /// the Reauth with key 2 (`pbad`, `Reauth.reach`): a change that must
    /// reach key 3 through key 2 refuses (S-UNREACHABLE), a retirement
    /// suspends key 3 with consent and copies the record, still broken, and
    /// a pairing of keys 2 and 3 rewrites it and brings key 3 back. A
    /// pairing started with key 1 that repairs it is authorized by key 2.
    #[test]
    fn a_broken_pair_record_is_found_and_repaired() {
        let pc = Pc::new();
        let (s, mut codes, mut keys) = create(&pc, 3, false, false);
        let id = s.id;
        let h = header(&pc);
        let broken = [(
            anchor::prefix(&h.slots[1].credhash),
            anchor::prefix(&h.slots[2].credhash),
        )];
        plant_broken_record(&pc, s, &keys);
        // Unlocked with key 1, the record is not seen; the Reauth with key 2
        // records it, and its reach lacks key 3.
        let mut s = open(&pc, OLD, &mut codes, &keys, 1).unwrap();
        assert!(pc.lines(&id).vault.unwrap().state.pbad.is_empty());
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        assert_eq!(r.reach(), [1, 2]);
        assert_eq!(pc.lines(&id).vault.unwrap().state.pbad, broken);
        let key4 = keys.register(&id, 4, false);
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                Change::AddKey(key4),
                Consent::default(),
                false
            ),
            Err(UNREACHABLE)
        );
        assert_eq!(refusal_values(UNREACHABLE), Some(vec!["3".into()]));
        // The unlock with key 2 records it too.
        drop(s);
        let mut s = open(&pc, OLD, &mut codes, &keys, 2).unwrap();
        assert_eq!(pc.lines(&id).vault.unwrap().state.pbad, broken);
        // "키 빼기" of key 1 touched with key 2: key 3 suspended with consent;
        // the broken record is carried and stays recorded.
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                remove(&[1], None, None),
                consent(&[3]),
                false
            ),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!((numbers(&h), h.suspended), (vec![2, 3], 0b10));
        assert_eq!(pc.lines(&id).vault.unwrap().state.pbad, broken);
        // A pairing of keys 2 and 3 rewrites it.
        let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
        let extra = touches(&s, &keys, &[3]);
        assert_eq!(
            s.rekey(r, extra, Change::Pair, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!(
            (h.suspended, h.reach(2), h.reach(3)),
            (0, vec![2, 3], vec![2, 3])
        );
        assert!(pc.lines(&id).vault.unwrap().state.pbad.is_empty());
        drop(s);
        let s3 = open(&pc, OLD, &mut codes, &keys, 3).unwrap();
        assert_eq!(s3.unlocked_with(), Some(3));
        drop(s3);
        // The repairing write's authorizer: a pairing of all three keys
        // started with key 1 is authorized by key 2, the record's owner.
        let pc = Pc::new();
        let (s, mut codes, keys) = create(&pc, 3, false, false);
        let id = s.id;
        plant_broken_record(&pc, s, &keys);
        let mut s = open(&pc, OLD, &mut codes, &keys, 1).unwrap();
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        let extra = touches(&s, &keys, &[2, 3]);
        assert_eq!(
            s.rekey(r, extra, Change::Pair, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!((h.authorizer, h.present), (Some(1), 0b111));
        assert_eq!(h.reach(2), [1, 2, 3]);
        assert!(pc.lines(&id).vault.unwrap().state.pbad.is_empty());
        set_kdf_profile(KdfProfile::Real);
    }

    /// PIN mode (spec §5.9, §5.5 R0): every slot a PIN slot, every touch
    /// verified; a key registered without a PIN is not added, and the slot
    /// numbers go on from `next` after a removal.
    #[test]
    fn pin_mode_takes_pin_slots_only() {
        set_kdf_profile(KdfProfile::Test);
        let pc = Pc::new();
        let p = Provision::new().unwrap();
        let mut keys = Keys::new();
        let new = vec![keys.register(&p.id, 1, true), keys.register(&p.id, 2, true)];
        pc.here();
        let made = p.finish_with_keys(&pc.vault(), &pc.key(), OLD, None, true, new);
        let mut s = made.unwrap();
        let h = header(&pc);
        assert!(h.pin() && h.slots.iter().all(|s| s.flags == 3));
        let plain = keys.register(&p.id, 3, false);
        let mut codes = Codes {
            secret: None,
            at: 0,
        };
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                Change::AddKey(plain),
                Consent::default(),
                false
            ),
            Err(NOT_PLANNED)
        );
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                remove(&[2], None, None),
                Consent::default(),
                false
            ),
            Ok(Rekeyed::Done)
        );
        let pinned = keys.register(&p.id, 3, true);
        let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
        assert_eq!(
            s.rekey(
                r,
                Vec::new(),
                Change::AddKey(pinned),
                Consent::default(),
                false
            ),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!((numbers(&h), h.next), (vec![1, 3], 4));
        assert!(h.slots.iter().all(|s| s.flags == 3));
        drop(s);
        let s = open(&pc, OLD, &mut codes, &keys, 3).unwrap();
        assert_eq!(s.unlocked_with(), Some(3));
        set_kdf_profile(KdfProfile::Real);
    }

    /// A change by key `by` with the extra touches of `extra` that must be
    /// refused with nothing written: its error.
    fn refused(
        pc: &Pc,
        s: &mut Session,
        codes: &mut Codes,
        keys: &Keys,
        (by, extra): (u8, &[u8]),
        change: Change,
    ) -> Option<&'static str> {
        let start = files(pc);
        let r = reauth(s, OLD, codes, keys, by).unwrap();
        let extra = touches(s, keys, extra);
        let e = s.rekey(r, extra, change, Consent::default(), false).err();
        assert_eq!(files(pc), start);
        e
    }

    /// Spec §5.5 R0 and §14.4-4, -7, -13: refusals before anything is
    /// written. A key never authorizes its own removal, a removal keeps a
    /// key, the password differs, a key touched twice, a pairing touch that
    /// does not prove its key (S-OLDSLOT), the epoch limit, an anchor that
    /// cannot be written, a flipped byte of the new files, and W10's
    /// per-key checks of a wrong base or record. A question holds a
    /// retirement, never a removal for a loss.
    #[test]
    fn changes_with_keys_are_refused_before_anything_is_written() {
        let pc = Pc::new();
        let (mut s, mut codes, mut keys) = create(&pc, 3, false, false);
        let id = s.id;
        let c = &mut codes;
        for (by, extra, change, error) in [
            (1, &[][..], remove(&[1], None, None), NOT_PLANNED),
            (2, &[3][..], remove(&[3], None, None), NOT_PLANNED),
            (1, &[][..], remove(&[2, 3, 1], None, None), NOT_PLANNED),
            (1, &[][..], remove(&[], None, None), NOT_PLANNED),
            (1, &[][..], remove(&[9], None, None), NOT_PLANNED),
            (1, &[][..], password(OLD), SAMEPASS),
            (1, &[1][..], Change::Pair, NOT_PLANNED),
            (1, &[][..], Change::Pair, NOT_PLANNED),
        ] {
            let e = refused(&pc, &mut s, c, &keys, (by, extra), change);
            assert_eq!(e, Some(error), "key {by}, extra {extra:?}");
        }
        // A key that answers with another output under its credential (its
        // with-UV one: the key got its PIN at registration).
        let start = files(&pc);
        let r = reauth(&mut s, OLD, c, &keys, 1).unwrap();
        let flip = |d: &mut Device| d.credentials[0].random_uv[0] ^= 1;
        keys.fake.device(keys.device(2), flip);
        let t = touches(&s, &keys, &[2]).remove(0);
        assert_eq!(s.check_touch(&r, &t), Err(OLDSLOT));
        assert_eq!(
            s.rekey(r, vec![t], Change::Pair, Consent::default(), false),
            Err(OLDSLOT)
        );
        keys.fake.device(keys.device(2), flip);
        // The epoch limit.
        let max = s.max_epoch;
        s.max_epoch = EPOCH_MAX;
        let r = reauth(&mut s, OLD, c, &keys, 1).unwrap();
        assert_eq!(
            s.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
            Err(EPOCH_LIMIT)
        );
        s.max_epoch = max;
        assert_eq!(files(&pc), start);
        // An anchor that cannot be written: refused, with no fallback.
        fs::rename(pc.anchor_dir(), pc.file("anchor.away")).unwrap();
        fs::write(pc.anchor_dir(), b"not a folder").unwrap();
        let r = reauth(&mut s, OLD, c, &keys, 1).unwrap();
        assert_eq!(
            s.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
            Err(ANCHOR_FAILED)
        );
        fs::remove_file(pc.anchor_dir()).unwrap();
        fs::rename(pc.file("anchor.away"), pc.anchor_dir()).unwrap();
        assert_eq!(files(&pc), start);
        // A flipped byte of the new key file or vault file, and W10's
        // per-key checks: a present key's S-wrap or an absent key's under
        // another base, a new record around another inbox key.
        for which in ["K", "V"] {
            CORRUPT.with(|c| c.set(Some(which)));
            let key = keys.register(&id, 4, false);
            let e = refused(&pc, &mut s, c, &keys, (1, &[]), Change::AddKey(key));
            assert_eq!(e, Some(NOT_VERIFIED), "{which}");
        }
        for fault in [
            inbox::Fault::PresentBase,
            inbox::Fault::AbsentBase,
            inbox::Fault::PairValue,
        ] {
            inbox::FAULT.with(|f| f.set(Some(fault)));
            let key = keys.register(&id, 4, false);
            let e = refused(&pc, &mut s, c, &keys, (1, &[]), Change::AddKey(key));
            assert_eq!(e, Some(NOT_VERIFIED), "{fault:?}");
            assert_eq!(inbox::FAULT.with(|f| f.get()), None, "{fault:?}");
        }
        // A question holds a retirement, never a removal for a loss.
        s.stale_key_file = true;
        let e = refused(&pc, &mut s, c, &keys, (1, &[]), remove(&[3], None, None));
        assert_eq!(e, Some(GATE_STALE));
        let loss = LossReport {
            date: None,
            exposure: Exposure::No,
            shared_pin: vec![2],
        };
        let r = reauth(&mut s, OLD, c, &keys, 1).unwrap();
        let change = remove(&[3], Some(loss), None);
        assert_eq!(
            s.rekey(r, Vec::new(), change, Consent::default(), false),
            Ok(Rekeyed::Done)
        );
        let h = header(&pc);
        assert_eq!((h.loss, h.tombstones[0].loss_mark()), (1, 1));
        set_kdf_profile(KdfProfile::Real);
    }

    /// The changes of the crash matrix (spec §14.5).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum What {
        Password,
        /// Keys on from a GOYOKE03 key file (a password change made it).
        KeysOn,
        /// Keys on from a 0.8 pair (GOYOKE01/02 and GOYOVA01/02).
        KeysOn08,
        AddKey,
        /// An added key paired with the Reauth's key alone.
        AddKeyAlone,
        Remove,
        /// Two keys lost at once.
        RemoveTwo,
        /// A retirement ("키 빼기"): no loss, the password kept.
        Retire,
        Pair,
        ReSeed,
        KeysOff,
        /// Key-file sync turned on (PIN keys, a server view of nothing).
        KeySyncOn,
        /// Key-file sync turned off, and keys off, of a GOYOKS01 key file
        /// whose record (1) is the server's top.
        KeySyncOff,
        KeysOffKs,
    }
    impl What {
        /// The change sets the password NEW.
        fn new_password(self) -> bool {
            matches!(
                self,
                Self::Password | Self::KeysOn | Self::KeysOn08 | Self::Remove | Self::RemoveTwo
            )
        }
        /// The change keeps the data key: no V_probe, no S1.
        fn keeps(self) -> bool {
            matches!(
                self,
                Self::AddKey | Self::AddKeyAlone | Self::Pair | Self::KeySyncOn
            )
        }
        /// A key-file sync row: PIN keys, sync on and a server view.
        fn keysync(self) -> bool {
            matches!(self, Self::KeySyncOn | Self::KeySyncOff | Self::KeysOffKs)
        }
        /// The keys a removal takes out, by number.
        fn removes(self) -> &'static [u8] {
            match self {
                Self::Remove | Self::Retire => &[1],
                Self::RemoveTwo => &[1, 3],
                _ => &[],
            }
        }
        /// A removal for a loss: its review is due.
        fn lost(self) -> bool {
            matches!(self, Self::Remove | Self::RemoveTwo)
        }
    }
    /// `what` of `s` (three keys, or none for keys on) prepared up to its
    /// write: the Reauth, the extra touches and the change.
    fn planned(
        what: What,
        s: &mut Session,
        codes: &mut Codes,
        keys: &mut Keys,
    ) -> (Reauth, Vec<Touch>, Change) {
        let id = s.id;
        match what {
            What::Password => (
                reauth(s, OLD, codes, keys, 1).unwrap(),
                Vec::new(),
                password(NEW),
            ),
            What::KeysOn | What::KeysOn08 => {
                let new_keys = vec![keys.register(&id, 1, false), keys.register(&id, 2, false)];
                let (code, typed) = codes.next();
                let r = s.reauth(OLD, Some((&code, typed)), None).unwrap();
                let change = Change::KeysOn {
                    pin: false,
                    keys: new_keys,
                    new_password: Some(Zeroizing::new(NEW.to_owned())),
                };
                (r, Vec::new(), change)
            }
            What::AddKey | What::AddKeyAlone => {
                let key = keys.register(&id, 4, false);
                let r = reauth(s, OLD, codes, keys, 1).unwrap();
                let extra = if what == What::AddKey {
                    touches(s, keys, &[2])
                } else {
                    Vec::new()
                };
                (r, extra, Change::AddKey(key))
            }
            What::Remove | What::RemoveTwo => {
                let loss = LossReport {
                    date: Some(LOSS),
                    exposure: Exposure::Yes,
                    shared_pin: vec![3],
                };
                let r = reauth(s, OLD, codes, keys, 2).unwrap();
                (r, Vec::new(), remove(what.removes(), Some(loss), Some(NEW)))
            }
            What::Retire => {
                let r = reauth(s, OLD, codes, keys, 2).unwrap();
                (r, Vec::new(), remove(&[1], None, None))
            }
            What::Pair => {
                let r = reauth(s, OLD, codes, keys, 1).unwrap();
                (r, touches(s, keys, &[3]), Change::Pair)
            }
            What::ReSeed => {
                let mut plan = s.plan_reseed().unwrap();
                let t = keys.touch(1, &plan.request(0).unwrap()).unwrap();
                let (code, typed) = codes.next();
                let r = s.reauth(OLD, Some((&code, typed)), Some(&t)).unwrap();
                plan.take(s, &r, &t).unwrap();
                for k in [2, 3] {
                    let t = keys.touch(k, &plan.request(0).unwrap()).unwrap();
                    plan.take(s, &r, &t).unwrap();
                }
                let t = keys.touch(3, &plan.second_request(3, 0).unwrap()).unwrap();
                plan.confirm(&t).unwrap();
                (r, Vec::new(), Change::ReSeed(plan.finish().unwrap()))
            }
            What::KeysOff | What::KeysOffKs => (
                reauth(s, OLD, codes, keys, 1).unwrap(),
                Vec::new(),
                Change::KeysOff,
            ),
            What::KeySyncOn => (
                reauth(s, OLD, codes, keys, 1).unwrap(),
                Vec::new(),
                Change::KeySyncOn,
            ),
            What::KeySyncOff => (
                reauth(s, OLD, codes, keys, 1).unwrap(),
                Vec::new(),
                Change::KeySyncOff,
            ),
        }
    }
    /// `kview` as goyo-sync writes it: `seq` with its record, and the
    /// request it answered.
    fn plant_view(pc: &Pc, seq: u64, record: Vec<u8>, answered: Option<[u8; 32]>) {
        let dir = syncfile::sync_dir(&pc.vault()).unwrap();
        let view = syncfile::KeyView {
            seq,
            record,
            answered,
            outcome: if answered.is_some() {
                syncfile::KeyOutcome::Applied
            } else {
                syncfile::KeyOutcome::None
            },
            ..syncfile::KeyView::default()
        };
        fs::write(
            dir.join(syncfile::KEY_VIEW),
            syncfile::render_key_view(&view),
        )
        .unwrap();
    }
    /// A key-file sync row's state before its change: a server view of no
    /// record; for an off, key-file sync turned on and its record landed
    /// (record 1, this PC's own: Equal).
    fn keysync_setup(what: What, pc: &Pc, s: &mut Session, codes: &mut Codes, keys: &Keys) {
        plant_view(pc, 0, Vec::new(), None);
        s.poll_sync();
        if what == What::KeySyncOn {
            return;
        }
        let r = reauth(s, OLD, codes, keys, 1).unwrap();
        let on = s.rekey(r, Vec::new(), Change::KeySyncOn, Consent::default(), true);
        assert_eq!(on, Ok(Rekeyed::Done));
        let dir = syncfile::sync_dir(&pc.vault()).unwrap();
        let req = fs::read(dir.join(syncfile::KEY_REQUEST)).unwrap();
        let file = fs::read(pc.key()).unwrap();
        let epoch = header(pc).epoch;
        let mut record =
            syncfile::render_record_header(syncfile::RecordKind::Key, false, 0, epoch).to_vec();
        record.extend_from_slice(&file);
        plant_view(pc, 1, record, Some(super::super::super::sha256(&req)));
        for _ in 0..3 {
            s.poll_sync();
        }
        assert_eq!(s.server_class(), Some(super::super::super::KeyClass::Equal));
        assert!(!dir.join(syncfile::KEY_REQUEST).exists());
    }
    /// A change with keys killed at `point`, then unlocked again (spec §5.6,
    /// §14.5): I1 to I6, I15 and I16.
    fn crash(what: What, point: &'static str, with_otp: bool, sync: bool) {
        let case = format!("{what:?} {point} otp={with_otp} sync={sync}");
        let pc = Pc::new();
        let (mut s, mut codes, mut keys) = if matches!(what, What::KeysOn | What::KeysOn08) {
            let (s, codes) = setup(&pc, what == What::KeysOn, with_otp, sync);
            (s, codes, Keys::new())
        } else if what.keysync() {
            create_with(&pc, 3, with_otp, sync, true)
        } else {
            create(&pc, 3, with_otp, sync)
        };
        let id = s.id;
        if what.keysync() {
            keysync_setup(what, &pc, &mut s, &mut codes, &keys);
        }
        let before = secrets(&s);
        let old_key = fs::read(pc.key()).unwrap();
        // Keys on rewrites the anchor's lines before S0 (S45-1 #2): a 0.8
        // pair's first anchor write is not its pending line's either.
        let had_anchor = !pc.anchor().is_empty() || what == What::KeysOn08;
        let (r, extra, change) = planned(what, &mut s, &mut codes, &mut keys);
        let last = s.last;
        let gap = GAPS
            .iter()
            .find(|(g, _)| *g == point)
            .map(|(_, then)| *then);
        THEN.with(|t| t.set(gap));
        CRASH.with(|c| c.set(Some(point)));
        let result = s.rekey(r, extra, change, Consent::default(), true);
        assert_eq!(result.map(|_| ()), Err(SIMULATED_CRASH), "{case}");
        assert_eq!(CRASH.with(|c| c.get()), None, "{case}: point not reached");
        assert_eq!(THEN.with(|t| t.take()), None, "{case}: gap not reached");
        assert_eq!(pc.anchor().is_empty(), !had_anchor, "{case}");
        drop(s);
        let landed = LANDED.contains(&point) || matches!(point, "S2.gap" | "S3.gap");
        let (right, wrong) = if landed && what.new_password() {
            (NEW, OLD)
        } else {
            (OLD, NEW)
        };
        // A key that stays; a key file without keys needs none.
        let key = if what.removes().is_empty() { 1 } else { 2 };
        // I1: the other password fails.
        if what.new_password() {
            let e = open(&pc, wrong, &mut codes, &keys, key).err();
            assert_eq!(e, Some(AUTH_ERROR), "{case}");
        }
        // The recovery unlock: a change that never landed is dropped and
        // said once; a landed one completes silently.
        let mut s =
            open(&pc, right, &mut codes, &keys, key).unwrap_or_else(|e| panic!("{case}: {e}"));
        let said = notices(&mut s);
        let pending_seen = point != "S0.tmp_synced" || !had_anchor;
        let not_finished = !landed && (pending_seen || point == "S2.tmp_synced");
        // A removal that never landed names its keys (S-REMOVE-UNDONE, C0b
        // to C3); any other change is S-NOTFINISHED.
        let removal = !what.removes().is_empty();
        let count = |n: &KeyNotice| said.iter().filter(|x| *x == n).count();
        assert_eq!(
            count(&KeyNotice::NotFinished),
            usize::from(not_finished && !removal),
            "{case}: {said:?}"
        );
        assert_eq!(
            count(&KeyNotice::RemoveUndone(what.removes().to_vec())),
            usize::from(not_finished && removal),
            "{case}: {said:?}"
        );
        // I16: no rollback, refusal or fallback for this PC's own write.
        assert!(
            said.iter().all(|n| matches!(
                n,
                KeyNotice::NotFinished | KeyNotice::RemoveUndone(_) | KeyNotice::Resumed
            )),
            "{case}: {said:?}"
        );
        // I14 (its lib part): the lost-key removal's review is due from its
        // `R` line on (S0r, after S0), landed or not; nothing else makes one.
        assert_eq!(
            s.review_due().is_some(),
            what.lost() && !point.starts_with("S0"),
            "{case}"
        );
        // Neither TOFU nor gate-pending mode for this PC's own write.
        assert!(!s.tofu() && !s.gate_pending(), "{case}");
        assert_eq!(
            s.take_recovery().vault,
            matches!(point, "S1.gap" | "S3.gap"),
            "{case}"
        );
        // I2 and I3.
        assert_eq!(secrets(&s), before, "{case}");
        assert!(s.last >= last, "{case}");
        consistent(&pc, &s);
        assert!(pc.temps(&pc.key()).is_empty(), "{case}");
        assert!(pc.temps(&pc.vault()).is_empty(), "{case}");
        // A 0.8 pair whose keys on never landed keeps its 0.8 key file,
        // which has no header.
        let k = KeyFile::read(&pc.key()).unwrap().header().cloned();
        assert_eq!(k.is_none(), what == What::KeysOn08 && !landed, "{case}");
        assert_eq!(fs::read(pc.key()).unwrap() != old_key, landed, "{case}");
        let lines = pc.lines(&id);
        assert!(lines.pending.is_none(), "{case}");
        match &k {
            Some(k) => {
                let line = lines.vault.clone().expect("a confirmed line");
                assert_eq!(line.state.key_state(), s.key_state(), "{case}");
                assert_eq!(line.vkey, Some(k.current_key_id()), "{case}");
                assert_eq!(line.state.hardware(), !k.slots.is_empty(), "{case}");
            }
            // Back to the 0.8 pair as it was: as in 0.8, no line.
            None => assert!(lines.vault.is_none(), "{case}: a 0.8 session wrote a line"),
        }
        assert!(anchor_doc(&pc).is_clean(), "{case}");
        // C-Q, C10, C12 and I10 (spec §5.6, §14.5): key-file sync's `ks`
        // and `kreq` after the recovery unlock and its first poll.
        if what.keysync() {
            let k = k.as_ref().expect("a key file with keys");
            s.poll_sync();
            let dir = syncfile::sync_dir(&pc.vault()).unwrap();
            let req = fs::read(dir.join(syncfile::KEY_REQUEST)).ok();
            let req = req
                .as_deref()
                .map(|b| syncfile::parse_key_request(b, &id).unwrap());
            let ks = pc.lines(&id).vault.unwrap().state.ks;
            let on = what == What::KeySyncOn;
            match (on, landed) {
                // C12: the PUT on the view's record (0), the `p` flag.
                (true, true) => {
                    assert_eq!(k.magic, Magic::Ks01, "{case}");
                    assert_eq!(ks, Ks::On(0), "{case}");
                    let req = req.expect("the PUT");
                    assert_eq!((req.op, req.base), (syncfile::KeyOp::Put, 0), "{case}");
                    assert!(pc.lines(&id).vault.unwrap().state.flags.p, "{case}");
                }
                (true, false) => {
                    assert_eq!(k.magic, Magic::Kh01, "{case}");
                    assert_eq!((ks, req.is_none()), (Ks::None, true), "{case}");
                }
                // C10: CUT(L) of the record the view showed.
                (false, true) => {
                    assert_ne!(k.magic, Magic::Ks01, "{case}");
                    assert_eq!(ks, Ks::Off(1), "{case}");
                    let req = req.expect("the CUT");
                    assert_eq!((req.op, req.base), (syncfile::KeyOp::Cut, 1), "{case}");
                }
                // C-Q: all or nothing; no CUT for an off that never landed.
                (false, false) => {
                    assert_eq!(k.magic, Magic::Ks01, "{case}");
                    assert_eq!(ks, Ks::None, "{case}");
                    assert!(req.is_none_or(|r| r.op != syncfile::KeyOp::Cut), "{case}");
                }
            }
        }
        // I4: a landed change of the data key leaves the old key file with
        // its old factors unable to open the vault file.
        if landed && !what.keeps() {
            let b = opened(&old_key, OLD, &keys, key).bundle;
            let v = fs::read(pc.vault()).unwrap();
            assert!(
                b.keys()
                    .iter()
                    .all(|dk| decode_data(&id, dk, b.id_key(), &v).is_err()),
                "{case}"
            );
        }
        // I5: an outgoing copy is under the current key.
        if sync {
            let dir = syncfile::sync_dir(&pc.vault()).unwrap();
            if let Ok(bytes) = fs::read(dir.join(syncfile::OUTGOING)) {
                let (_, blob) = syncfile::parse_outgoing(&bytes).unwrap();
                let current = (s.keys.current(), s.keys.id_key());
                let (_, read, _) = decode_data(&id, current.0, current.1, blob).unwrap();
                assert_eq!(read, s.header(), "{case}");
            }
        }
        drop(s);
        // I15: every live key that is not suspended opens the key file.
        if !with_otp && let Some(k) = &k {
            for (j, slot) in k.slots.iter().enumerate() {
                if (k.suspended >> j) & 1 == 0 {
                    let s = open(&pc, right, &mut codes, &keys, slot.number);
                    assert!(s.is_ok(), "{case}: key {}", slot.number);
                }
            }
        }
        // I6: a second unlock writes nothing but, with an OTP, the code's
        // step into the vault file.
        let kept = (fs::read(pc.key()).unwrap(), pc.anchor());
        let v = fs::read(pc.vault()).unwrap();
        let mut s = open(&pc, right, &mut codes, &keys, key).unwrap();
        assert!(notices(&mut s).is_empty(), "{case}");
        assert_eq!((fs::read(pc.key()).unwrap(), pc.anchor()), kept, "{case}");
        if !with_otp {
            assert_eq!(fs::read(pc.vault()).unwrap(), v, "{case}");
        }
    }
    /// Every crash point of every change with keys (spec §5.6, §14.5): a
    /// pair that opens, this PC's own write recognized with nothing asked,
    /// a removal that never landed named; with and without an OTP, and with
    /// and without vault sync. The changes that keep the data key have no
    /// S1.
    #[test]
    fn every_crash_point_of_a_change_with_keys_leaves_a_pair_that_opens() {
        for what in [
            What::Password,
            What::KeysOn,
            What::KeysOn08,
            What::AddKey,
            What::AddKeyAlone,
            What::Remove,
            What::RemoveTwo,
            What::Retire,
            What::Pair,
            What::ReSeed,
            What::KeysOff,
            What::KeySyncOn,
            What::KeySyncOff,
            What::KeysOffKs,
        ] {
            for with_otp in [false, true] {
                for sync in [false, true] {
                    // Key-file sync needs vault sync.
                    if what.keysync() && !sync {
                        continue;
                    }
                    for point in POINTS {
                        if what.keeps() && point.starts_with("S1") {
                            continue;
                        }
                        crash(what, point, with_otp, sync);
                    }
                }
            }
        }
        set_kdf_profile(KdfProfile::Real);
    }

    /// P-INV through the write engine (spec §3.2, §14.1-11): random key
    /// changes of a vault with keys, each written by `rekey`: a key added, a
    /// lost key removed, a pairing of every key, new seeds, a password
    /// change. After each write, against every output the fake ever gave for
    /// every seed a key ever had: an S-wrap opens only with its recipient's
    /// current output, a pair record only with its owner's, and only its
    /// target's output gives the inbox key it carries; no old S and no data
    /// key opens either, and S is new. After a removal of X nothing
    /// derivable from X's outputs (its own bases, every inbox key X could
    /// read or derive) opens an S-wrap of any later file; a re-seed's old
    /// outputs are in the first set.
    #[test]
    fn p_inv_holds_through_the_write_engine() {
        for start in [0x5eed_u64, 0x9e37_79b9, 0x2545_f491] {
            let mut rng = start;
            let mut below = |n: usize| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                (rng % n as u64) as usize
            };
            let pc = Pc::new();
            let (mut s, mut codes, mut keys) = create(&pc, 3, false, false);
            let id = s.id;
            let mut pass = OLD;
            let same =
                |a: &SlotPublic, b: &SlotPublic| a.credhash == b.credhash && a.seed == b.seed;
            // Every output the fake gave, with the slot record it was for.
            let mut seen: Vec<(SlotPublic, [u8; 32])> = Vec::new();
            // Every S and data key so far, and the removed keys.
            let mut known: Vec<[u8; 32]> = Vec::new();
            let mut removed: Vec<[u8; 16]> = Vec::new();
            for _ in 0..7 {
                let h = header(&pc);
                for slot in &h.slots {
                    if !seen.iter().any(|(s, _)| same(s, slot)) {
                        let allow = vec![(slot.cred_id.clone(), salt(&id, &slot.seed), None)];
                        let req = AssertRequest::new(0, allow, false).unwrap();
                        let t = keys.touch(slot.number, &req).unwrap();
                        seen.push((slot.clone(), *t.output_for(&slot.seed, &id).unwrap()));
                    }
                }
                let o = opened(&fs::read(pc.key()).unwrap(), pass, &keys, h.slots[0].number);
                known.push(***o.s.as_ref().unwrap());
                known.extend_from_slice(o.bundle.keys());
                let live = numbers(&h);
                let by = live.iter().copied().find(|n| h.reach(*n) == live);
                let done = match (below(5), by) {
                    (0, Some(by)) if live.len() < 6 => {
                        let new = keys.register(&id, h.next, false);
                        let r = reauth(&mut s, pass, &mut codes, &keys, by).unwrap();
                        s.rekey(
                            r,
                            Vec::new(),
                            Change::AddKey(new),
                            Consent::default(),
                            false,
                        )
                    }
                    (1, Some(by)) if live.len() > 2 => {
                        let others: Vec<u8> = live.iter().copied().filter(|n| *n != by).collect();
                        let x = others[below(others.len())];
                        removed.push(credhash(&h, x));
                        let r = reauth(&mut s, pass, &mut codes, &keys, by).unwrap();
                        let loss = LossReport {
                            date: None,
                            exposure: Exposure::No,
                            shared_pin: Vec::new(),
                        };
                        let change = remove(&[x], Some(loss), None);
                        s.rekey(r, Vec::new(), change, Consent::default(), false)
                    }
                    (3, _) => {
                        let mut plan = s.plan_reseed().unwrap();
                        let mut reauthed = None;
                        for k in &live {
                            let t = keys.touch(*k, &plan.request(0).unwrap()).unwrap();
                            let r = reauthed.get_or_insert_with(|| {
                                s.reauth(pass, Some(("", 0)), Some(&t)).unwrap()
                            });
                            assert_eq!(plan.take(&s, r, &t), Ok(*k));
                        }
                        let last = *live.last().unwrap();
                        let t = keys
                            .touch(last, &plan.second_request(last, 0).unwrap())
                            .unwrap();
                        plan.confirm(&t).unwrap();
                        let change = Change::ReSeed(plan.finish().unwrap());
                        s.rekey(
                            reauthed.unwrap(),
                            Vec::new(),
                            change,
                            Consent::default(),
                            false,
                        )
                    }
                    (4, Some(by)) => {
                        let next = if pass == OLD { NEW } else { OLD };
                        let r = reauth(&mut s, pass, &mut codes, &keys, by).unwrap();
                        let done =
                            s.rekey(r, Vec::new(), password(next), Consent::default(), false);
                        pass = next;
                        done
                    }
                    _ => {
                        let r = reauth(&mut s, pass, &mut codes, &keys, live[0]).unwrap();
                        let extra = touches(&s, &keys, &live[1..]);
                        s.rekey(r, extra, Change::Pair, Consent::default(), false)
                    }
                };
                assert_eq!(done, Ok(Rekeyed::Done));
                let bytes = fs::read(pc.key()).unwrap();
                let f = KeyFile::from_bytes(Path::new("k.goyokey"), bytes.clone()).unwrap();
                let h = f.header().unwrap();
                let now = opened(&bytes, pass, &keys, h.slots[0].number);
                assert!(!known.contains(&***now.s.as_ref().unwrap()), "a fresh S");
                for (i, (j, _)) in h.wraps.iter().enumerate() {
                    let slot = &h.slots[usize::from(*j)];
                    for (other, out) in &seen {
                        let opens = f.open_own(usize::from(*j), out).is_some();
                        assert_eq!(opens, same(other, slot));
                    }
                    for base in &known {
                        assert!(f.open_s_wrap_with(i, base).is_none());
                        assert!(f.open_own(usize::from(*j), base).is_none());
                    }
                }
                for (p, (o, t)) in f.carried_pairs().iter().zip(&h.pairs) {
                    let PairPlan::Copy { wrap, .. } = p else {
                        unreachable!("a parsed record is carried")
                    };
                    let (owner, target) = (&h.slots[usize::from(*o)], &h.slots[usize::from(*t)]);
                    for (other, out) in &seen {
                        let ik = inbox::open_record(&id, owner, target, out, wrap);
                        assert_eq!(ik.is_some(), same(other, owner));
                        let Some(ik) = ik else { continue };
                        for (any, out) in &seen {
                            let again = inbox::inbox_key(&id, target, out, owner);
                            assert_eq!(ct_eq(&**ik, &**again), same(any, target));
                        }
                    }
                    for base in &known {
                        assert!(inbox::open_record(&id, owner, target, base, wrap).is_none());
                    }
                }
                // What a removed key's holder derives from each of its outputs.
                for (x, h_x) in seen.iter().filter(|(s, _)| removed.contains(&s.credhash)) {
                    let mut bases = vec![
                        **inbox::own_base(&id, x, h_x),
                        **inbox::pair_seal(&id, x, h_x),
                        *h_x,
                    ];
                    for (t, h_t) in &seen {
                        bases.push(**inbox::inbox_key(&id, t, h_t, x));
                        bases.push(**inbox::inbox_key(&id, x, h_x, t));
                    }
                    for i in 0..h.wraps.len() {
                        assert!(bases.iter().all(|b| f.open_s_wrap_with(i, b).is_none()));
                    }
                }
            }
        }
        set_kdf_profile(KdfProfile::Real);
    }

    /// The gate, the anchor's security-key rules and adopt with keys (spec
    /// §5.8, §5.10, §7.14, §7.15a, §7.17; §14.3 and §14.4-10), between PCs
    /// that share the physical keys, each with its own anchor.
    mod gates {
        use super::super::super::super::{
            ANCHOR_DOWNGRADE, ANCHOR_FORK, ANCHOR_RELIST, AdoptCheck, AdoptClass, Adopted,
            AnchorClass, GatePass, Preview, Source, UnionPassword, VaultClass,
            gate::{
                ANCHOR_PINNED, ANCHOR_RELIST_KEYS, Base, GATE_CODE_WRONG, GATE_G2FAIL,
                GATE_G2FAIL_DISK, GATE_HELD, GATE_NOT_PENDING, GateAnswer, GateKind, Gates,
                LACKS_REMOVAL, PAIR_CHANGED, RELISTED, REMOVED_AUTHORIZER, SLOT_CHANGED,
                TOFU_ADOPT, TOFU_HELD, UNEXPLAINED, parse_code,
            },
            keyfile::{Code, key_code},
            rotate::{ADOPT_REFUSED, Acks, ForkOption},
        };
        use super::super::super::adopt::{ADOPT_STALE, NOT_THIS_VAULT};
        use super::*;
        mod keysync;

        /// A second PC with copies of `a`'s vault file and key file. Its
        /// first unlock (with key `number`) is a bootstrap, confirmed with
        /// the key file's own code as another PC shows it (spec §7.17).
        fn second_pc(a: &Pc, codes: &mut Codes, keys: &Keys, number: u8) -> Pc {
            let b = Pc::new();
            carry(a, &b);
            let mut s = open(&b, OLD, codes, keys, number).unwrap();
            assert!(s.tofu());
            let code = key_code(&s.id, s.keys.current(), s.key_state());
            s.tofu_confirm(Some(&code)).unwrap();
            assert!(!s.tofu());
            drop(s);
            b
        }
        /// `from`'s vault file and key file copied to `to`, as on a shared
        /// stick or folder.
        fn carry(from: &Pc, to: &Pc) {
            fs::copy(from.vault(), to.vault()).unwrap();
            fs::copy(from.key(), to.key()).unwrap();
        }
        fn code_of(s: &Session) -> Code {
            key_code(&s.id, s.keys.current(), s.key_state())
        }
        fn lost() -> LossReport {
            LossReport {
                date: None,
                exposure: Exposure::No,
                shared_pin: Vec::new(),
            }
        }
        /// Key `number` of `a`'s key file removed for a loss with a touch of
        /// key `by`.
        fn remove_lost(s: &mut Session, codes: &mut Codes, keys: &Keys, number: u8, by: u8) {
            let r = reauth(s, OLD, codes, keys, by).unwrap();
            let change = remove(&[number], Some(lost()), None);
            assert_eq!(
                s.rekey(r, Vec::new(), change, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
        }
        fn file(bytes: &[u8]) -> KeyFile {
            KeyFile::from_bytes(Path::new("other.goyokey"), bytes.to_vec()).unwrap()
        }
        fn check(s: &Session, bytes: &[u8]) -> Result<AdoptCheck> {
            let f = file(bytes);
            s.adopt_check(&f, Source::File(f.path().to_owned()))
        }
        fn acks(p: &Preview, option: ForkOption) -> Acks {
            Acks {
                password_only: p.password_only,
                union_password: match p.own_pass {
                    Some(true) => UnionPassword::Own,
                    _ => UnionPassword::Other,
                },
                both_passwords: p.both_passwords,
                fork_option: option,
                keysync_on: p.keysync_on,
            }
        }
        /// The whole adopt of `other` with keys as the flow runs it (spec
        /// §9.2): the checks, a Reauth with `mine` touched with key
        /// `number`, the open with a touch of that key for the other file,
        /// the gate answered by `gate`, the preview of `option` and the
        /// write.
        #[allow(clippy::too_many_arguments)]
        fn take(
            s: &mut Session,
            codes: &mut Codes,
            keys: &Keys,
            (mine, number): (&str, u8),
            other: &[u8],
            option: ForkOption,
            gate: impl FnOnce(&AdoptCheck, &Session) -> GatePass,
            consent: Consent,
        ) -> Result<Adopted> {
            let f = file(other);
            let check = s.adopt_check(&f, Source::File(f.path().to_owned()))?;
            let r = reauth(s, mine, codes, keys, number)?;
            let t = touch_other(&f, keys, number);
            let opened = s.adopt_open_with(&r, &f, None, Some(&t))?;
            let pass = gate(&check, s);
            let plan = s.adopt_preview_with(&r, &f, opened, &check, pass, option)?;
            let acks = acks(plan.preview(), option);
            s.adopt(r, plan, Vec::new(), acks, consent, false)
        }
        /// A touch of key `number` for the other file's seeds.
        fn touch_other(f: &KeyFile, keys: &Keys, number: u8) -> Touch {
            let h = f.header().unwrap();
            let allow = h
                .slots
                .iter()
                .filter(|s| s.number == number)
                .map(|s| (s.cred_id.clone(), salt(&h.vault_id, &s.seed), None))
                .collect();
            keys.touch(number, &AssertRequest::new(0, allow, h.pin()).unwrap())
                .unwrap()
        }
        fn none(c: &AdoptCheck, _: &Session) -> GatePass {
            GatePass::none(c)
        }
        fn pick(numbers: &'static [u8]) -> impl FnOnce(&AdoptCheck, &Session) -> GatePass {
            move |c, s| {
                let h = s.key_file.header().unwrap();
                GatePass::G2Passed {
                    pick: numbers.iter().map(|n| credhash(h, *n)).collect(),
                    epoch: c.other.epoch,
                    tag: c.other.tag,
                }
            }
        }
        fn code(code: Code) -> impl FnOnce(&AdoptCheck, &Session) -> GatePass {
            move |c, _| GatePass::G1Passed {
                code,
                epoch: c.other.epoch,
                tag: c.other.tag,
            }
        }

        /// Spec §5.2, §5.10, §7.15a (§14.3 gate rows): another PC removed a
        /// lost key on a shared stick; this PC's next unlock opens in
        /// gate-pending mode: nothing is edited or written, the pick lists
        /// this PC's own keys from its record, a wrong pick turns G2 off
        /// for this vault, a wrong code may be typed again, and the code
        /// confirms the file with its removal taken (`t`). On another PC the
        /// right pick passes.
        #[test]
        fn a_changed_key_file_at_login_waits_for_its_gate() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let id = sa.id;
            let start = (fs::read(a.vault()).unwrap(), fs::read(a.key()).unwrap());
            let b = second_pc(&a, &mut codes, &keys, 3);
            let one = credhash(&header(&a), 1);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            drop(sa);
            carry(&a, &b);
            let before = files(&b);
            let mut s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            assert!(s.gate_pending() && !s.tofu());
            assert_eq!(s.login_gate(), Some(GateKind::G2));
            // The pick lists this PC's own keys, from its record.
            let numbers: Vec<u8> = s.gate_choices().iter().map(|c| c.number).collect();
            assert_eq!(numbers, [1, 2, 3, 4]);
            let of = |n: u8| s.gate_choices()[usize::from(n) - 1].credhash;
            let (c1, c2) = (of(1), of(2));
            assert_eq!(c1, one);
            assert_eq!(s.put(None, entry("three")).err(), Some(GATE_HELD));
            assert_eq!(s.change_gate(&password(NEW)).err(), Some(GATE_HELD));
            assert_eq!(files(&b), before);
            // A wrong pick: G2 is off for this vault from now on.
            assert_eq!(
                s.pass_login_gate(GateAnswer::Pick(vec![c2])).err(),
                Some(GATE_G2FAIL_DISK)
            );
            assert_eq!(s.login_gate(), Some(GateKind::G1));
            let gate = b.lines(&id).gate.unwrap();
            assert!(!gate.g2 && gate.state == anchor::GateState::None);
            assert_eq!(
                s.pass_login_gate(GateAnswer::Pick(vec![c1])).err(),
                Some(GATE_NOT_PENDING)
            );
            assert_eq!(
                s.pass_login_gate(GateAnswer::Code(Code([0; 8]))).err(),
                Some(GATE_CODE_WRONG)
            );
            assert!(s.gate_pending());
            // The code as the other PC shows it.
            let shown = code_of(&s).show(s.key_state().epoch);
            let typed = parse_code(&shown.to_lowercase()).unwrap();
            s.pass_login_gate(GateAnswer::Code(typed)).unwrap();
            assert!(!s.gate_pending());
            let lines = b.lines(&id);
            let line = lines.vault.unwrap();
            assert_eq!(line.state.key_state(), s.key_state());
            assert!(line.state.flags.t);
            assert_eq!(line.state.gated, s.key_state().epoch);
            assert_eq!(
                (line.state.tombs[0].credhash, line.state.tombs[0].origin),
                (one, Origin::Taken)
            );
            assert!(lines.gate.is_none());
            s.put(None, entry("three")).unwrap();
            drop(s);
            let s = open(&b, OLD, &mut codes, &keys, 4).unwrap();
            assert!(!s.gate_pending());
            drop(s);
            // On a third PC that had the first state, the right pick passes.
            let c = Pc::new();
            fs::write(c.vault(), &start.0).unwrap();
            fs::write(c.key(), &start.1).unwrap();
            let mut s = open(&c, OLD, &mut codes, &keys, 4).unwrap();
            let code = code_of(&s);
            s.tofu_confirm(Some(&code)).unwrap();
            drop(s);
            carry(&a, &c);
            let mut s = open(&c, OLD, &mut codes, &keys, 4).unwrap();
            assert_eq!(s.login_gate(), Some(GateKind::G2));
            s.pass_login_gate(GateAnswer::Pick(vec![one])).unwrap();
            assert!(!s.gate_pending());
            assert!(c.lines(&id).vault.unwrap().state.flags.t);
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.2 step 8, §2.8 #40: a synced PC that got another PC's
        /// removal on a shared stick (the key file alone) opens in
        /// gate-pending mode with its vault file under the older data key.
        /// A server copy under that older key is not pushed over before the
        /// gate passes, so the vault file stays under the key of the file
        /// this PC confirmed, nor is the head override offered; the pass
        /// judges the copy again and pushes over it then.
        #[test]
        fn a_gate_pending_poll_writes_no_vault_file() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let b = second_pc(&a, &mut codes, &keys, 3);
            let dir = syncfile::sync_dir(&b.vault()).unwrap();
            fs::create_dir(&dir).unwrap();
            let now = otp::now().unwrap();
            let status = syncfile::render_status(now, now, syncfile::SyncState::Ok);
            syncfile::replace_file(&dir.join(syncfile::STATUS), &status).unwrap();
            // B's copy under the first data key, as the server holds it.
            let mut s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            s.enable_sync().unwrap();
            s.put(None, entry("from b")).unwrap();
            let out = fs::read(dir.join(syncfile::OUTGOING)).unwrap();
            let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
            let incoming = syncfile::render_incoming(1, copy).unwrap();
            drop(s);
            fs::remove_file(dir.join(syncfile::OUTGOING)).unwrap();
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            drop(sa);
            fs::copy(a.key(), b.key()).unwrap();
            syncfile::replace_file(&dir.join(syncfile::INCOMING), &incoming).unwrap();
            let vault = fs::read(b.vault()).unwrap();
            let mut s = login_older(&b, &mut codes, &keys, 3);
            assert!(s.gate_pending());
            let generation = s.generation;
            for _ in 0..3 {
                let _ = s.poll_sync();
            }
            assert_eq!(
                fs::read(b.vault()).unwrap(),
                vault,
                "written before the gate"
            );
            assert_eq!(s.generation, generation);
            assert!(!dir.join(syncfile::OUTGOING).exists());
            assert_eq!(s.head_to_override().err(), Some(GATE_HELD));
            let typed = parse_code(&code_of(&s).show(s.key_state().epoch)).unwrap();
            s.pass_login_gate(GateAnswer::Code(typed)).unwrap();
            let _ = s.poll_sync();
            assert!(s.generation > generation, "not judged again after the pass");
            assert_ne!(fs::read(b.vault()).unwrap(), vault);
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §7.15a (one-shot G2): a wrong pick while the anchor cannot be
        /// written (its lock held by another process) is the anchor's error,
        /// and G2 stays off for the session all the same, at login and at a
        /// USB adopt; nothing is written, and only the code takes the file.
        #[test]
        fn a_wrong_pick_turns_g2_off_when_the_anchor_is_busy() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let c = second_pc(&a, &mut codes, &keys, 3);
            let one = credhash(&header(&a), 1);
            let two = credhash(&header(&a), 2);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let ka = fs::read(a.key()).unwrap();
            drop(sa);
            // At login.
            carry(&a, &b);
            let mut s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            assert_eq!(s.login_gate(), Some(GateKind::G2));
            let held = anchor::hold_lock(&b.anchor_dir());
            assert_eq!(
                s.pass_login_gate(GateAnswer::Pick(vec![two])).err(),
                Some(ANCHOR_FAILED)
            );
            drop(held);
            assert_eq!(s.login_gate(), Some(GateKind::G1));
            assert_eq!(
                s.pass_login_gate(GateAnswer::Pick(vec![one])).err(),
                Some(GATE_NOT_PENDING)
            );
            assert!(s.gate_pending() && b.lines(&id).gate.is_none());
            let code = code_of(&s);
            s.pass_login_gate(GateAnswer::Code(code)).unwrap();
            drop(s);
            // At a USB adopt.
            let mut s = open(&c, OLD, &mut codes, &keys, 3).unwrap();
            assert_eq!(check(&s, &ka).unwrap().keys.gate, Some(GateKind::G2));
            let held = anchor::hold_lock(&c.anchor_dir());
            let taken = take(
                &mut s,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[2]),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(ANCHOR_FAILED));
            drop(held);
            assert!(c.lines(&id).gate.is_none());
            assert_eq!(check(&s, &ka).unwrap().keys.gate, Some(GateKind::G1));
            let taken = take(
                &mut s,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[1]),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(ADOPT_STALE));
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.13 (the review's core, S0r, S45-2 #11, S45-3 #4): a
        /// removal for a loss makes the post-removal review due on every
        /// path that lands it, the lost-key flow here, a gate passed at
        /// login and a USB adopt there, in the merge log first and in the
        /// anchor with the confirmed line; the vault outgoing waits for it
        /// (a copy under the old key goes); it stays due after the anchor
        /// is deleted; [확인함] ends it. A retirement makes none.
        #[test]
        fn a_removal_for_a_loss_makes_its_review_due_on_every_path() {
            use super::super::super::super::review;
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, true);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let c = second_pc(&a, &mut codes, &keys, 3);
            let one = credhash(&header(&a), 1);
            let outgoing = syncfile::sync_dir(&a.vault())
                .unwrap()
                .join(syncfile::OUTGOING);
            assert!(outgoing.exists());
            let loss = LossReport {
                date: Some(LOSS),
                exposure: Exposure::No,
                shared_pin: Vec::new(),
            };
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 2).unwrap();
            let change = remove(&[1], Some(loss), None);
            assert_eq!(
                sa.rekey(r, Vec::new(), change, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            assert_eq!(sa.review_due(), Some("20251231"));
            assert!(!outgoing.exists());
            sa.put(None, entry("three")).unwrap();
            assert!(!outgoing.exists());
            let due = |pc: &Pc| {
                let r = pc.lines(&id).review.filter(|r| r.due).map(|r| r.loss);
                (r, review::due(&pc.anchor_dir(), &id))
            };
            let both = || (Some("20251231".to_owned()), Some("20251231".to_owned()));
            assert_eq!(due(&a), both());
            drop(sa);
            let ka = fs::read(a.key()).unwrap();
            // A gate passed at login on a shared stick.
            carry(&a, &b);
            let mut s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            assert_eq!(s.review_due(), None);
            s.pass_login_gate(GateAnswer::Pick(vec![one])).unwrap();
            assert_eq!(s.review_due(), Some("20251231"));
            assert_eq!(due(&b), both());
            drop(s);
            // Due is durable: B's anchor gone, its next unlock is a
            // bootstrap, and the review is still due from the merge log.
            fs::remove_file(b.anchor_dir().join("goyo-vault.keys")).unwrap();
            let s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            assert!(s.tofu());
            assert_eq!(s.review_due(), Some("20251231"));
            drop(s);
            // A USB adopt: the entry records the removal as taken, and the
            // review is due.
            let mut s = open(&c, OLD, &mut codes, &keys, 3).unwrap();
            take(
                &mut s,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[1]),
                Consent::default(),
            )
            .unwrap();
            assert_eq!(s.review_due(), Some("20251231"));
            assert_eq!(due(&c), both());
            drop(s);
            // [확인함] at A: the outgoing goes up, and the review stays done.
            let mut s = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            assert_eq!(s.review_due(), Some("20251231"));
            assert!(!outgoing.exists());
            s.review_done().unwrap();
            assert!(s.review_due().is_none() && outgoing.exists());
            assert_eq!(due(&a), (None, None));
            // A retirement makes no review.
            let r = reauth(&mut s, OLD, &mut codes, &keys, 2).unwrap();
            assert_eq!(
                s.rekey(
                    r,
                    Vec::new(),
                    remove(&[3], None, None),
                    Consent::default(),
                    true
                ),
                Ok(Rekeyed::Done)
            );
            assert!(s.review_due().is_none());
            drop(s);
            assert!(
                open(&a, OLD, &mut codes, &keys, 2)
                    .unwrap()
                    .review_due()
                    .is_none()
            );
            set_kdf_profile(KdfProfile::Real);
        }
        /// Spec §5.2 step 8 (stage 4): an OTP vault that opens in
        /// gate-pending mode still keeps its code from being used again,
        /// writing the vault file again under the key and header it was
        /// read with only.
        #[test]
        fn a_gate_pending_login_keeps_its_otp_code_used() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, true, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            drop(sa);
            carry(&a, &b);
            let v = fs::read(b.vault()).unwrap();
            use crate::vault::read_header;
            let (_, read) = read_header(&v).unwrap();
            let (code, typed) = codes.next();
            let login = |code: &str, typed: u64| {
                b.here();
                let prepared = prepare(&b.vault(), &b.key()).unwrap();
                let t = keys.touch(3, &prepared.unlock_request(0).unwrap()).unwrap();
                Session::login_with(prepared, OLD, code, typed, None, &t)
            };
            let s = login(&code, typed).unwrap();
            assert!(s.gate_pending());
            drop(s);
            let after = fs::read(b.vault()).unwrap();
            assert_ne!(after, v);
            assert_eq!(read_header(&after).unwrap().1, read);
            assert_eq!(login(&code, typed).err(), Some(AUTH_ERROR));
            let mut s = login(&codes.next().0, codes.at - 30).unwrap();
            let code = code_of(&s);
            s.pass_login_gate(GateAnswer::Code(code)).unwrap();
            drop(s);
            assert!(b.lines(&id).vault.unwrap().state.flags.t);
            set_kdf_profile(KdfProfile::Real);
        }
        /// Spec §5.2 step 7, §5.6 C0b-C3, §5.13: a lost-key removal cut off
        /// right after its `R` line is told as S-REMOVE-UNDONE naming the
        /// key, and its review stays due; an adopt that removed this PC's
        /// key and was cut off is told the same way.
        #[test]
        fn a_removal_that_never_landed_is_named_and_its_review_stays_due() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 3, false, false);
            let b = second_pc(&a, &mut codes, &keys, 3);
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 2).unwrap();
            CRASH.with(|c| c.set(Some("review-stored")));
            let change = remove(&[1], Some(lost()), None);
            assert_eq!(
                sa.rekey(r, Vec::new(), change, Consent::default(), false)
                    .err(),
                Some(SIMULATED_CRASH)
            );
            drop(sa);
            let mut sa = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            assert_eq!(notices(&mut sa), [KeyNotice::RemoveUndone(vec![1])]);
            assert_eq!(sa.review_due(), Some("unknown"));
            assert_eq!(header(&a).slots.len(), 3);
            // [다시 하기] reopens the lost-key flow with its answers (I14).
            let redo = Redo {
                flow: RedoFlow::Lost,
                remove: vec![1],
                loss: Some(lost()),
            };
            assert_eq!(sa.redo(), Some(&redo));
            assert_eq!(sa.take_redo(), Some(redo));
            assert_eq!(sa.redo(), None);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let ka = fs::read(a.key()).unwrap();
            drop(sa);
            // At B, an adopt of A's removal cut off before its key file.
            let mut s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            CRASH.with(|c| c.set(Some("S2.tmp_synced")));
            let taken = take(
                &mut s,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[1]),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(SIMULATED_CRASH));
            drop(s);
            let mut s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            assert_eq!(notices(&mut s), [KeyNotice::RemoveUndone(vec![1])]);
            assert_eq!(s.review_due(), Some("unknown"));
            // A dropped adopt reopens "새 열쇠 파일 받기", never a removal of
            // this PC's own (round 2, finding 20).
            assert_eq!(s.redo().map(|r| r.flow), Some(RedoFlow::Adopt));
            assert_eq!(s.redo().and_then(|r| r.loss.clone()), None);
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §7.17 (§14.3 TOFU rows): a key file with security keys and
        /// no record of its vault on this PC opens as a bootstrap; nothing
        /// is edited, no key changes and nothing is written until the code
        /// another PC shows is typed (a wrong one may be typed again), or
        /// S-TOFU-NOPC's yes. A password-only key file of a vault that shows
        /// security keys (keys turned off elsewhere) is one too.
        #[test]
        fn a_key_file_with_keys_and_no_record_is_a_bootstrap() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 2, false, false);
            let id = sa.id;
            let b = Pc::new();
            carry(&a, &b);
            let mut s = open(&b, OLD, &mut codes, &keys, 2).unwrap();
            assert!(s.tofu() && !s.gate_pending());
            assert_eq!(s.put(None, entry("three")).err(), Some(TOFU_HELD));
            assert_eq!(s.enable_sync().err(), Some(TOFU_HELD));
            assert_eq!(s.change_gate(&password(NEW)).err(), Some(TOFU_HELD));
            assert!(b.anchor().is_empty());
            assert_eq!(
                s.tofu_confirm(Some(&Code([0; 8]))).err(),
                Some(GATE_CODE_WRONG)
            );
            let code = code_of(&sa);
            s.tofu_confirm(Some(&code)).unwrap();
            assert!(!s.tofu());
            let lines = b.lines(&id);
            let line = lines.vault.unwrap();
            assert!(line.state.flags.t && lines.pending.is_none());
            assert_eq!(
                (line.state.key_state(), line.state.gated),
                (s.key_state(), 1)
            );
            assert_eq!(line.vkey, Some(header(&b).current_key_id()));
            s.put(None, entry("three")).unwrap();
            drop(s);
            assert!(!open(&b, OLD, &mut codes, &keys, 1).unwrap().tofu());
            // S-TOFU-NOPC: no other PC to read a code from.
            let c = Pc::new();
            carry(&a, &c);
            let mut s = open(&c, OLD, &mut codes, &keys, 1).unwrap();
            s.tofu_confirm(None).unwrap();
            assert!(c.lines(&id).vault.unwrap().state.flags.t);
            drop(s);
            // Keys off at A: a password-only key file whose removals show
            // that keys were on.
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sa.rekey(r, Vec::new(), Change::KeysOff, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            drop(sa);
            let d = Pc::new();
            carry(&a, &d);
            let mut s = open(&d, OLD, &mut codes, &keys, 1).unwrap();
            assert!(s.tofu());
            assert_eq!(s.put(None, entry("three")).err(), Some(TOFU_HELD));
            let code = code_of(&s);
            s.tofu_confirm(Some(&code)).unwrap();
            s.put(None, entry("three")).unwrap();
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.10 (§14.3 anchor rows): before any touch or Argon2, a key
        /// file that lists live a key this PC removed is refused
        /// (S-ANCHOR-RELIST-SK), so is one that lacks a key this PC added
        /// (S-ANCHOR-FORK); a Restore with a key file a login would gate
        /// runs held, asks nothing and writes no anchor.
        #[test]
        fn the_anchor_refuses_removed_keys_and_missed_additions() {
            let a = Pc::new();
            let (mut sa, mut codes, mut keys) = create(&a, 3, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            // B changes the password with key 1 still live; A removes key 1.
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sb.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            drop(sb);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let anchor = a.anchor();
            let derived = derive_count();
            a.here();
            assert_eq!(
                prepare(&a.vault(), &b.key()).err(),
                Some(ANCHOR_RELIST_KEYS)
            );
            assert!(not_a_failure(ANCHOR_RELIST_KEYS) && not_a_failure(ANCHOR_PINNED));
            assert_eq!(derive_count(), derived);
            assert_eq!(a.anchor(), anchor);
            // A adds key 4 with key 2 (the data key stays); B, behind, then
            // changes its password twice: above A, holding A's data key,
            // without key 4.
            let c = Pc::new();
            carry(&a, &c);
            let mut sc = open(&c, OLD, &mut codes, &keys, 3).unwrap();
            let code = code_of(&sa);
            sc.tofu_confirm(Some(&code)).unwrap();
            let key4 = keys.register(&id, 4, false);
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 2).unwrap();
            assert_eq!(
                sa.rekey(
                    r,
                    Vec::new(),
                    Change::AddKey(key4),
                    Consent::default(),
                    false
                ),
                Ok(Rekeyed::Done)
            );
            drop(sa);
            for p in [NEW, OLD] {
                let r = reauth(
                    &mut sc,
                    if p == NEW { OLD } else { NEW },
                    &mut codes,
                    &keys,
                    3,
                );
                let r = r.unwrap();
                assert_eq!(
                    sc.rekey(r, Vec::new(), password(p), Consent::default(), false),
                    Ok(Rekeyed::Done)
                );
            }
            drop(sc);
            let anchor = a.anchor();
            a.here();
            assert_eq!(prepare(&a.vault(), &c.key()).err(), Some(ANCHOR_FORK));
            assert_eq!(a.anchor(), anchor);
            // A Restore of A's own file with the gated key file of a PC
            // behind: held, no gate, nothing written to its anchor.
            let d = second_pc(&a, &mut codes, &keys, 2);
            let mut sa = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            remove_lost(&mut sa, &mut codes, &keys, 3, 2);
            drop(sa);
            let anchor = d.anchor();
            d.here();
            let prepared = prepare_restore(&a.vault(), &a.key()).unwrap();
            let t = keys.touch(4, &prepared.unlock_request(0).unwrap()).unwrap();
            let dest = d.file("restored.goyo");
            let r = Session::restore_with(prepared, &dest, OLD, "", 0, &t).unwrap();
            assert!(r.restore_held() && r.local_rollback() && !r.gate_pending() && !r.tofu());
            assert_eq!(d.anchor(), anchor);
            set_kdf_profile(KdfProfile::Real);
        }

        /// The gate's arithmetic on public bytes (spec §7.15a): R, Δ, T_new,
        /// M, a slot change and a silent jump each need their gate; a record
        /// of a key both know that changed in more than its number and seed
        /// is refused (slot pinning); a pick passes only as R exactly.
        #[test]
        fn the_gate_counts_every_change_as_a_whole() {
            let a = Pc::new();
            let (sa, _codes, _keys) = create(&a, 3, false, false);
            let h = header(&a);
            let base = Base::of_header(&h);
            let gates = |other: &KeyHeader, gated| Gates::between(&base, other, gated);
            assert_eq!(gates(&h, Some(1)).unwrap().needed(), None);
            // A silent jump, and no `gated` epoch at all.
            assert_eq!(gates(&h, None).unwrap().needed(), Some(GateKind::G1));
            let mut far = h.clone();
            far.epoch = 1 + keyfile::EPOCH_SILENT + 1;
            assert!(gates(&far, Some(1)).unwrap().jump);
            // R: a removal of a key of this PC.
            let mut removed = h.clone();
            let gone = removed.slots.remove(0);
            removed.tombstones.push(Tombstone {
                credhash: gone.credhash,
                removed: 2,
            });
            let g = gates(&removed, Some(1)).unwrap();
            assert_eq!(
                (g.needed(), &g.removed),
                (Some(GateKind::G2), &vec![gone.credhash])
            );
            assert!(g.pick_matches(&[gone.credhash]));
            assert!(!g.pick_matches(&[gone.credhash, gone.credhash]));
            assert!(!g.pick_matches(&[gone.credhash, h.slots[1].credhash]));
            assert!(!g.pick_matches(&[]));
            // M: a key the file lacks with no removal is kept, no gate.
            let mut lacks = h.clone();
            lacks.slots.remove(0);
            let g = gates(&lacks, Some(1)).unwrap();
            assert_eq!((g.needed(), g.kept.len()), (None, 1));
            // Δ and T_new.
            let mut added = h.clone();
            added.slots[0].credhash = [0x99; 16];
            added.slots[0].cred_id = vec![9; 16];
            let g = gates(&added, Some(1)).unwrap();
            assert_eq!(g.needed(), Some(GateKind::G1));
            assert_eq!(g.added, vec![[0x99; 16]]);
            let mut unknown = h.clone();
            unknown.tombstones.push(Tombstone {
                credhash: [0x98; 16],
                removed: 2,
            });
            assert_eq!(gates(&unknown, Some(1)).unwrap().unknown, vec![[0x98; 16]]);
            // A slot change (number or seed) is G1; any other change of a
            // known key's record is refused.
            let mut renumbered = h.clone();
            renumbered.slots[2].number = 9;
            assert!(gates(&renumbered, Some(1)).unwrap().slot);
            let mut reseeded = h.clone();
            reseeded.slots[2].seed[0] ^= 1;
            assert_eq!(
                gates(&reseeded, Some(1)).unwrap().needed(),
                Some(GateKind::G1)
            );
            let mut forged = h.clone();
            forged.slots[2].registered += 1;
            assert_eq!(gates(&forged, Some(1)).err(), Some(SLOT_CHANGED));
            // A policy change: PIN mode, key-file sync.
            let mut pin = h.clone();
            pin.flags |= 2;
            assert!(gates(&pin, Some(1)).unwrap().policy);
            let mut ks = h.clone();
            ks.magic = Magic::Ks01;
            assert!(gates(&ks, Some(1)).unwrap().policy);
            // The code as typed: case, the epoch and the separators.
            let code = code_of(&sa);
            let shown = code.show(1);
            assert_eq!(parse_code(&shown), Some(code));
            assert_eq!(parse_code(&shown.replace(['-', ' '], "")), Some(code));
            assert_eq!(parse_code(&shown.replace('-', "")[..20]), None);
            let bare: String = shown.split('·').nth(1).unwrap().into();
            assert_eq!(parse_code(&bare.to_lowercase()), Some(code));
            assert_eq!(parse_code("1234-5678"), None);
            assert_eq!(parse_code("X1 · 0000-0000-0000-0000"), None);
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.8 and §14.4-10: another PC's removal is a successor here
        /// behind G2, with every check before any touch; a wrong pick turns
        /// G2 off for this vault, after which only the code takes it; a
        /// gate answered for another file is refused. The re-seal keeps the
        /// other file's `[0, W)`, state and code; the removal is taken
        /// (`t`) and this PC's key file opens with the staying keys.
        #[test]
        fn another_pcs_removal_is_taken_behind_its_gate() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let one = credhash(&header(&a), 1);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let ka = fs::read(a.key()).unwrap();
            let code_a = code_of(&sa);
            drop(sa);
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let c = check(&sb, &ka).unwrap();
            assert_eq!(
                (c.class, c.keys.gate),
                (AdoptClass::Successor, Some(GateKind::G2))
            );
            assert_eq!(c.keys.checked.gates.removed, vec![one]);
            let start = files(&b);
            // Answered for another file: refused, nothing written.
            let other = |c: &AdoptCheck, _: &Session| GatePass::G1Passed {
                code: code_a,
                epoch: c.other.epoch,
                tag: [0x5a; 16],
            };
            // The preview refuses it already (and the write again).
            let previewed = planned_adopt(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                None,
                ForkOption::Both,
                other,
            );
            assert_eq!(previewed.err(), Some(ADOPT_STALE));
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                other,
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(ADOPT_STALE));
            // A wrong pick: G2 off, only G1 from now on.
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[2]),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(GATE_G2FAIL));
            assert_eq!(check(&sb, &ka).unwrap().keys.gate, Some(GateKind::G1));
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[1]),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(ADOPT_STALE));
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                code(Code([1; 8])),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(GATE_CODE_WRONG));
            assert_eq!((files(&b).0, files(&b).1), (start.0, start.1));
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                code(code_a),
                Consent::default(),
            )
            .unwrap();
            // The same state and code; this PC's own seal block.
            assert_eq!(
                (taken.state, taken.code),
                (parse(&ka).unwrap().state(), code_a)
            );
            let kb = fs::read(b.key()).unwrap();
            assert_eq!(parse(&kb).unwrap().state(), parse(&ka).unwrap().state());
            assert_ne!(kb, ka);
            let lines = b.lines(&id);
            let line = lines.vault.unwrap();
            assert!(line.state.flags.t);
            assert_eq!(line.state.tombs[0].origin, Origin::Taken);
            assert!(lines.gate.is_none(), "a gate passed turns G2 on again");
            drop(sb);
            for k in [2, 3, 4] {
                assert!(open(&b, OLD, &mut codes, &keys, k).is_ok());
            }
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.8 and §14.4-10: two PCs changed the password apart from
        /// one state; B joins A's file with option 2 (no keyset change, no
        /// gate): a union under a fresh data key and S, every key and pair
        /// record kept, the touched key its authorizer; A then takes B's
        /// union as a successor. Fork option 1 is offered behind G2 or G1.
        #[test]
        fn a_fork_is_joined_with_its_pair_records() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 3, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sa.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sb.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            drop(sb);
            drop(sa);
            let ka = fs::read(a.key()).unwrap();
            let dka = keys_of_bytes(&ka, &keys);
            let mut sb = open(&b, NEW, &mut codes, &keys, 2).unwrap();
            let c = check(&sb, &ka).unwrap();
            assert_eq!((c.class, c.fork), (AdoptClass::Union, true));
            assert_eq!(c.keys.gate, None);
            assert!(c.keys.both && c.keys.take_other_offered);
            assert_eq!(c.keys.take_other, Some(GateKind::G1));
            let before = header(&b);
            let union = take(
                &mut sb,
                &mut codes,
                &keys,
                (NEW, 2),
                &ka,
                ForkOption::Both,
                none,
                Consent::default(),
            )
            .unwrap_or_else(|e| panic!("{e}"));
            let h = header(&b);
            assert_eq!((h.kind, h.epoch, h.magic), (Kind::Union, 3, Magic::Kh01));
            assert_eq!(numbers(&h), [1, 2, 3]);
            assert_eq!(h.pairs.len(), 6);
            assert_eq!(h.authorizer, Some(1));
            assert_ne!(h.ks_id, before.ks_id);
            // A fresh data key; A's is kept for reading.
            assert_ne!(h.key_ids[0], keyfile::key_id(&id, &dka));
            assert!(h.key_ids.contains(&keyfile::key_id(&id, &dka)));
            assert_eq!(h.key_ids.last(), before.key_ids.last());
            assert!(union.suspended.is_empty() && union.renumbered.is_empty());
            let line = b.lines(&id).vault.unwrap();
            assert!(line.state.flags.t);
            drop(sb);
            for k in 1..=3 {
                assert!(open(&b, NEW, &mut codes, &keys, k).is_ok(), "key {k}");
            }
            // A takes B's union as a successor: it holds A's data key.
            let kb = fs::read(b.key()).unwrap();
            let mut sa = open(&a, NEW, &mut codes, &keys, 1).unwrap();
            let c = check(&sa, &kb).unwrap();
            assert_eq!((c.class, c.keys.gate), (AdoptClass::Successor, None));
            let r = reauth(&mut sa, NEW, &mut codes, &keys, 1).unwrap();
            let f = file(&kb);
            let t = touch_other(&f, &keys, 1);
            let opened = sa.adopt_open_with(&r, &f, None, Some(&t)).unwrap();
            let plan = sa
                .adopt_preview_with(&r, &f, opened, &c, GatePass::none(&c), ForkOption::Both)
                .unwrap();
            let acks = acks(plan.preview(), ForkOption::Both);
            let taken = sa
                .adopt(r, plan, Vec::new(), acks, Consent::default(), false)
                .unwrap();
            assert_eq!(taken.state, parse(&kb).unwrap().state());
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.8 and §14.4-10: keys turned off on another PC reach this
        /// PC as a password-only file chained under its data key: never a
        /// successor; G1 and S-ADOPT-PWONLY; declining writes nothing, and
        /// the union is password-only under a fresh data key with every
        /// former key removed.
        #[test]
        fn keys_off_elsewhere_needs_its_code_and_a_yes() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 2, false, false);
            let b = second_pc(&a, &mut codes, &keys, 2);
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sa.rekey(r, Vec::new(), Change::KeysOff, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let ka = fs::read(a.key()).unwrap();
            let (dka, code_a) = (*sa.keys.current(), code_of(&sa));
            drop(sa);
            let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
            let c = check(&sb, &ka).unwrap();
            assert_eq!(
                (c.class, c.keys.gate),
                (AdoptClass::Union, Some(GateKind::G1))
            );
            assert!(c.keys.checked.gates.policy);
            let f = file(&ka);
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 2).unwrap();
            let opened = sb.adopt_open_with(&r, &f, None, None).unwrap();
            let pass = code(code_a)(&c, &sb);
            let plan = sb
                .adopt_preview_with(&r, &f, opened, &c, pass, ForkOption::Both)
                .unwrap();
            assert!(plan.preview().password_only);
            let start = files(&b);
            let mut no = acks(plan.preview(), ForkOption::Both);
            no.password_only = false;
            assert_eq!(
                sb.adopt(r, plan, Vec::new(), no, Consent::default(), false)
                    .err(),
                Some(ADOPT_STALE)
            );
            assert_eq!(files(&b), start);
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 2).unwrap();
            let opened = sb.adopt_open_with(&r, &f, None, None).unwrap();
            let pass = code(code_a)(&c, &sb);
            let plan = sb
                .adopt_preview_with(&r, &f, opened, &c, pass, ForkOption::Both)
                .unwrap();
            let yes = acks(plan.preview(), ForkOption::Both);
            sb.adopt(r, plan, Vec::new(), yes, Consent::default(), false)
                .unwrap();
            let h = header(&b);
            assert_eq!((h.magic, h.kind), (Magic::Ke03, Kind::Union));
            assert!(h.slots.is_empty() && h.tombstones.len() == 2);
            assert_ne!(h.key_ids[0], keyfile::key_id(&sb.id, &dka));
            assert_ne!(*sb.keys.current(), dka);
            set_kdf_profile(KdfProfile::Real);
        }

        /// E5 (spec §5.8, §14.4-10): a successor that claims a password
        /// change but opens with this PC's password is refused
        /// ("설명되지 않는 변경"): here A changed the password and back.
        #[test]
        fn a_password_change_that_keeps_the_password_is_refused() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 2, false, false);
            let b = second_pc(&a, &mut codes, &keys, 2);
            for (from, to) in [(OLD, NEW), (NEW, OLD)] {
                let r = reauth(&mut sa, from, &mut codes, &keys, 1).unwrap();
                assert_eq!(
                    sa.rekey(r, Vec::new(), password(to), Consent::default(), false),
                    Ok(Rekeyed::Done)
                );
            }
            let ka = fs::read(a.key()).unwrap();
            drop(sa);
            let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
            assert_eq!(check(&sb, &ka).unwrap().class, AdoptClass::Successor);
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 2),
                &ka,
                ForkOption::Both,
                none,
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(ADOPT_REFUSED));
            assert_eq!(
                refusal_values(ADOPT_REFUSED),
                Some(vec![UNEXPLAINED.to_owned()])
            );
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.8, round 4, finding 1: before G1 only a successor
        /// confirmed by its own code is taken; it ends the bootstrap.
        #[test]
        fn a_bootstrap_takes_only_a_successor_with_its_code() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 2, false, false);
            let b = Pc::new();
            carry(&a, &b);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let ka = fs::read(a.key()).unwrap();
            let code_a = code_of(&sa);
            drop(sa);
            let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
            assert!(sb.tofu());
            let c = check(&sb, &ka).unwrap();
            assert_eq!(
                (c.class, c.keys.gate),
                (AdoptClass::Successor, Some(GateKind::G1))
            );
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 2),
                &ka,
                ForkOption::Both,
                pick(&[1]),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(ADOPT_STALE));
            take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 2),
                &ka,
                ForkOption::Both,
                code(code_a),
                Consent::default(),
            )
            .unwrap();
            assert!(!sb.tofu());
            assert!(b.lines(&sb.id).vault.unwrap().state.flags.t);
            sb.put(None, entry("three")).unwrap();
            // A fork is no way out of a bootstrap: B's password change,
            // carried to a new PC E, against A's own.
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 2).unwrap();
            assert_eq!(
                sb.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            drop(sb);
            let e = Pc::new();
            carry(&b, &e);
            let mut sa = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 2).unwrap();
            assert_eq!(
                sa.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let fork = fs::read(a.key()).unwrap();
            drop(sa);
            let se = open(&e, NEW, &mut codes, &keys, 2).unwrap();
            assert!(se.tofu());
            assert_eq!(check(&se, &fork).err(), Some(TOFU_ADOPT));
            set_kdf_profile(KdfProfile::Real);
        }
        /// Spec §5.8, §7.15a, §7.17: a PC with a 0.8 key file takes a file
        /// with keys chained under its ID key only behind G1 (a policy
        /// change, every key in it Δ), and in TOFU (a bootstrap after a
        /// forget) only behind G1 too, whatever else the checks found.
        #[test]
        fn a_pc_with_a_0_8_key_file_takes_keys_only_with_the_code() {
            let a = Pc::new();
            let (mut sa, mut codes) = setup(&a, false, false, false);
            let mut keys = Keys::new();
            let id = sa.id;
            let (b, c) = (Pc::new(), Pc::new());
            carry(&a, &b);
            carry(&a, &c);
            let k08 = fs::read(a.key()).unwrap();
            let new_keys = vec![keys.register(&id, 1, false), keys.register(&id, 2, false)];
            let (otp, typed) = codes.next();
            let r = sa.reauth(OLD, Some((&otp, typed)), None).unwrap();
            let on = Change::KeysOn {
                pin: false,
                keys: new_keys,
                new_password: None,
            };
            assert_eq!(
                sa.rekey(r, Vec::new(), on, Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let ka = fs::read(a.key()).unwrap();
            let code_a = code_of(&sa);
            drop(sa);
            let f = file(&ka);
            for (pc, forget) in [(&b, false), (&c, true)] {
                pc.here();
                let prepared = if forget {
                    super::super::super::super::prepare_forgotten(&pc.vault(), &pc.key())
                } else {
                    prepare(&pc.vault(), &pc.key())
                };
                let (otp, typed) = codes.next();
                let mut s = Session::login(prepared.unwrap(), OLD, &otp, typed, None).unwrap();
                assert!(s.key_file.header().is_none());
                assert_eq!(s.tofu(), forget);
                let check = check(&s, &ka).unwrap();
                assert_eq!(
                    (check.class, check.keys.gate),
                    (AdoptClass::Successor, Some(GateKind::G1)),
                    "forget={forget}"
                );
                if !forget {
                    assert!(check.keys.checked.gates.policy);
                    assert_eq!(check.keys.checked.gates.added.len(), 2);
                }
                let before = files(pc);
                let preview = |s: &mut Session, codes: &mut Codes, pass: GatePass| {
                    let (otp, typed) = codes.next();
                    let r = s.reauth(OLD, Some((&otp, typed)), None)?;
                    let t = touch_other(&f, &keys, 1);
                    let opened = s.adopt_open_with(&r, &f, None, Some(&t))?;
                    let plan =
                        s.adopt_preview_with(&r, &f, opened, &check, pass, ForkOption::Both)?;
                    let acks = acks(plan.preview(), ForkOption::Both);
                    s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
                };
                let none = GatePass::none(&check);
                assert_eq!(
                    preview(&mut s, &mut codes, none).err(),
                    Some(ADOPT_STALE),
                    "forget={forget}"
                );
                assert_eq!(files(pc), before);
                let pass = GatePass::G1Passed {
                    code: code_a,
                    epoch: check.other.epoch,
                    tag: check.other.tag,
                };
                preview(&mut s, &mut codes, pass).unwrap();
                assert!(!s.tofu());
                assert_eq!(s.key_state(), check.other);
                // The 0.8 file back is no change to take: its one key is the
                // ID key (never a union planned without its header).
                let back = self::check(&s, &k08).map(|c| c.class);
                assert!(
                    !matches!(back, Ok(AdoptClass::Union | AdoptClass::Successor)),
                    "{back:?}"
                );
                assert!(pc.lines(&id).vault.unwrap().state.flags.t);
            }
            set_kdf_profile(KdfProfile::Real);
        }
        /// Spec §7.4, §7.15a (a vault made without keys, synced on two
        /// PCs): A turns security keys on. B's next poll finds the server
        /// copy under a key it does not hold and halts with the USB advice
        /// (KeyChanged), its own edit kept on B; B takes A's key file by
        /// USB ("새 열쇠 파일 받기") behind A's code (G1), then the halted
        /// copy merges, B's edit goes up, and both PCs hold the same
        /// entries and check code; B then opens only with a key. From a
        /// 0.8 pair and from a GOYOKE03.
        #[test]
        fn a_synced_pc_without_keys_halts_and_takes_keys_on_by_usb() {
            for kf2 in [false, true] {
                synced_keys_on_by_usb(kf2);
            }
            set_kdf_profile(KdfProfile::Real);
        }
        fn synced_keys_on_by_usb(kf2: bool) {
            use crate::vault::SyncNotice as Notice;
            let case = format!("kf2={kf2}");
            let polls = |s: &mut Session| -> Vec<Notice> {
                (0..5)
                    .filter_map(|_| s.poll_sync().and_then(|e| e.notice))
                    .collect()
            };
            let deliver = |from: &Pc, to: &Pc, version: u64| {
                let out = fs::read(sync_dir(from).join(syncfile::OUTGOING)).unwrap();
                let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
                let incoming = syncfile::render_incoming(version, copy).unwrap();
                syncfile::replace_file(&sync_dir(to).join(syncfile::INCOMING), &incoming).unwrap();
            };
            let a = Pc::new();
            let (mut sa, mut codes) = setup(&a, kf2, false, true);
            let id = sa.id;
            let k_before = fs::read(a.key()).unwrap();
            // B: copies of A's pair, with its own sync folder.
            let b = Pc::new();
            carry(&a, &b);
            fs::create_dir(sync_dir(&b)).unwrap();
            let now = otp::now().unwrap();
            let status = syncfile::render_status(now, now, syncfile::SyncState::Ok);
            syncfile::replace_file(&sync_dir(&b).join(syncfile::STATUS), &status).unwrap();
            let mut sb = login(&b, OLD, &mut codes).unwrap();
            assert!(!sb.tofu(), "{case}");
            sb.enable_sync().unwrap();
            polls(&mut sb);
            drop(sb);

            // A: keys on, then an edit, uploaded under the new data key.
            a.here();
            let mut keys = Keys::new();
            let new_keys = vec![keys.register(&id, 1, false), keys.register(&id, 2, false)];
            let (otp, typed) = codes.next();
            let r = sa.reauth(OLD, Some((&otp, typed)), None).unwrap();
            let on = Change::KeysOn {
                pin: false,
                keys: new_keys,
                new_password: None,
            };
            // Its gate question (the server not seen yet) answered yes.
            assert_eq!(
                sa.rekey(r, Vec::new(), on, Consent::default(), true),
                Ok(Rekeyed::Done),
                "{case}"
            );
            sa.put(None, entry("from a")).unwrap();
            let ka = fs::read(a.key()).unwrap();
            deliver(&a, &b, 2);

            // B: halted with the USB advice; its edit stays on B.
            // The unlock found the copy: told once, by the unlock.
            let mut sb = login(&b, OLD, &mut codes).unwrap();
            let mut told: Vec<Notice> = sb.take_unlock_notice().into_iter().collect();
            told.extend(polls(&mut sb));
            assert!(sb.halted_head().is_some(), "{case}");
            assert!(
                told.contains(&Notice::KeyChanged { hardware: false }),
                "{case}: {told:?}"
            );
            // A 0.8 PC keeps no record of its key file, so a copy with keys
            // makes its unlock a bootstrap (round 2, finding 10): no edit
            // before the code. A GOYOKE03 PC has its line: it edits on, and
            // nothing goes up while halted.
            assert_eq!(sb.tofu(), !kf2, "{case}");
            let _ = fs::remove_file(sync_dir(&b).join(syncfile::OUTGOING));
            if kf2 {
                sb.put(None, entry("from b")).unwrap();
            } else {
                assert_eq!(
                    sb.put(None, entry("from b")).err(),
                    Some(TOFU_HELD),
                    "{case}"
                );
            }
            polls(&mut sb);
            assert!(
                !sync_dir(&b).join(syncfile::OUTGOING).exists(),
                "{case}: uploaded while halted"
            );
            assert!(!secrets(&sb).contains(&"from a".to_owned()), "{case}");
            // The old key file is no way into A's copy.
            let old = file(&k_before).open(OLD, None).unwrap();
            let out = fs::read(sync_dir(&a).join(syncfile::OUTGOING)).unwrap();
            let (_, copy) = syncfile::parse_outgoing(&out).unwrap();
            assert!(
                old.bundle
                    .keys()
                    .iter()
                    .all(|dk| decode_data(&id, dk, old.bundle.id_key(), copy).is_err()),
                "{case}"
            );

            // "새 열쇠 파일 받기" with A's key file: G1, A's code.
            let f = file(&ka);
            let check = check(&sb, &ka).unwrap();
            assert_eq!(
                (check.class, check.keys.gate),
                (AdoptClass::Successor, Some(GateKind::G1)),
                "{case}"
            );
            let (otp, typed) = codes.next();
            let r = sb.reauth(OLD, Some((&otp, typed)), None).unwrap();
            let t = touch_other(&f, &keys, 2);
            let opened = sb.adopt_open_with(&r, &f, None, Some(&t)).unwrap();
            let pass = GatePass::G1Passed {
                code: code_of(&sa),
                epoch: check.other.epoch,
                tag: check.other.tag,
            };
            let plan = sb
                .adopt_preview_with(&r, &f, opened, &check, pass, ForkOption::Both)
                .unwrap();
            let acks = acks(plan.preview(), ForkOption::Both);
            sb.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
                .unwrap();
            assert_eq!(header(&b).state(), header(&a).state(), "{case}");
            assert_eq!(sb.key_state(), sa.key_state(), "{case}");
            assert!(b.lines(&id).vault.unwrap().state.hardware(), "{case}");
            assert!(!sb.tofu(), "{case}");
            if !kf2 {
                sb.put(None, entry("from b")).unwrap();
            }

            // The halt lifts: A's copy merges and B's state goes up.
            deliver(&a, &b, 2);
            let told = polls(&mut sb);
            assert!(
                !told
                    .iter()
                    .any(|n| matches!(n, Notice::KeyChanged { .. } | Notice::KeyFork)),
                "{case}: {told:?}"
            );
            for title in ["one", "two", "from a", "from b"] {
                assert!(secrets(&sb).contains(&title.to_owned()), "{case}: {title}");
            }
            assert!(sync_dir(&b).join(syncfile::OUTGOING).exists(), "{case}");
            deliver(&b, &a, 3);
            a.here();
            polls(&mut sa);
            let sorted = |s: &Session| {
                let mut v = secrets(s);
                v.sort();
                v
            };
            assert_eq!(sorted(&sa), sorted(&sb), "{case}");
            assert_eq!(sa.check_code(), sb.check_code(), "{case}");
            drop(sa);
            drop(sb);
            // B's pair now needs a key; either opens it.
            b.here();
            let prepared = prepare(&b.vault(), &b.key()).unwrap();
            assert!(prepared.unlock_request(0).is_some(), "{case}");
            drop(prepared);
            for number in [1, 2] {
                let s = open(&b, OLD, &mut codes, &keys, number).unwrap();
                assert!(secrets(&s).contains(&"from b".to_owned()), "{case}");
            }
        }
        fn sync_dir(pc: &Pc) -> std::path::PathBuf {
            syncfile::sync_dir(&pc.vault()).unwrap()
        }
        /// Spec §5.8 and §14.4-10: a file that descends from this PC's state
        /// but lacks a key this PC added (M) is a successor with a carry: a
        /// union behind the removal's gate (G2) that keeps the added key and
        /// its pair records; the other PC then takes it behind G1 (a key new
        /// to it).
        #[test]
        fn a_successor_with_a_carry_keeps_this_pcs_added_key() {
            let a = Pc::new();
            let (mut sa, mut codes, mut keys) = create(&a, 4, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let one = credhash(&header(&a), 1);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let ka = fs::read(a.key()).unwrap();
            drop(sa);
            // B adds key 5 with key 3 before it sees A's removal.
            let key5 = keys.register(&id, 5, false);
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 3).unwrap();
            assert_eq!(
                sb.rekey(
                    r,
                    Vec::new(),
                    Change::AddKey(key5),
                    Consent::default(),
                    false
                ),
                Ok(Rekeyed::Done)
            );
            let c = check(&sb, &ka).unwrap();
            assert_eq!((c.class, c.fork), (AdoptClass::Union, false));
            assert_eq!(c.keys.gate, Some(GateKind::G2));
            assert_eq!(c.keys.checked.gates.kept.len(), 1);
            let union = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[1]),
                Consent::default(),
            )
            .unwrap();
            assert!(union.suspended.is_empty() && union.renumbered.is_empty());
            let h = header(&b);
            assert_eq!((h.kind, numbers(&h)), (Kind::Union, vec![2, 3, 4, 5]));
            assert_eq!(h.reach(3), [2, 3, 4, 5]);
            assert_eq!(h.tombstones.len(), 1);
            assert_eq!(h.tombstones[0].credhash, one);
            drop(sb);
            for k in [2, 3, 4, 5] {
                assert!(open(&b, OLD, &mut codes, &keys, k).is_ok(), "key {k}");
            }
            // A takes B's union: it holds A's data key; key 5 is new there.
            let kb = fs::read(b.key()).unwrap();
            let mut sa = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            let c = check(&sa, &kb).unwrap();
            assert_eq!(
                (c.class, c.keys.gate),
                (AdoptClass::Successor, Some(GateKind::G1))
            );
            assert_eq!(c.keys.checked.gates.added.len(), 1);
            let code_b = {
                let opened = opened(&kb, OLD, &keys, 2);
                key_code(&id, opened.bundle.current(), parse(&kb).unwrap().state())
            };
            take(
                &mut sa,
                &mut codes,
                &keys,
                (OLD, 2),
                &kb,
                ForkOption::Both,
                code(code_b),
                Consent::default(),
            )
            .unwrap();
            assert_eq!(header(&a).state(), parse(&kb).unwrap().state());
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.8 (W6 for a union; §14.4-20's lib part): a fork union
        /// whose authorizer reaches no record of a key the other branch
        /// added is refused without consent, nothing written, and with it
        /// writes that key suspended; touching the key too suspends
        /// nothing.
        #[test]
        fn a_union_suspends_only_with_consent() {
            {
                let a = Pc::new();
                let (mut sa, mut codes, mut keys) = create(&a, 3, false, false);
                let id = sa.id;
                let b = second_pc(&a, &mut codes, &keys, 3);
                // B adds key 4 with key 2 alone; A changes its password.
                let key4 = keys.register(&id, 4, false);
                let mut sb = open(&b, OLD, &mut codes, &keys, 2).unwrap();
                let r = reauth(&mut sb, OLD, &mut codes, &keys, 2).unwrap();
                assert_eq!(
                    sb.rekey(
                        r,
                        Vec::new(),
                        Change::AddKey(key4),
                        Consent::default(),
                        false
                    ),
                    Ok(Rekeyed::Done)
                );
                let code_b = code_of(&sb);
                let kb = fs::read(b.key()).unwrap();
                drop(sb);
                let r = reauth(&mut sa, OLD, &mut codes, &keys, 1).unwrap();
                assert_eq!(
                    sa.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                    Ok(Rekeyed::Done)
                );
                let c = check(&sa, &kb).unwrap();
                assert_eq!((c.class, c.fork), (AdoptClass::Union, true));
                assert_eq!(c.keys.gate, Some(GateKind::G1));
                assert_eq!(c.keys.checked.gates.added.len(), 1);
                // The union, authorized by key 1, which no record joins to
                // key 4 (and key 4 touched as well, the second time).
                let f = file(&kb);
                let plan = |s: &mut Session, codes: &mut Codes| {
                    let r = reauth(s, NEW, codes, &keys, 1).unwrap();
                    let t = touch_other(&f, &keys, 1);
                    let opened = s.adopt_open_with(&r, &f, Some(OLD), Some(&t)).unwrap();
                    let pass = code(code_b)(&c, s);
                    let plan = s
                        .adopt_preview_with(&r, &f, opened, &c, pass, ForkOption::Both)
                        .unwrap();
                    (r, plan)
                };
                let start = files(&a);
                let (r, p) = plan(&mut sa, &mut codes);
                assert_eq!(p.preview().suspend, [4]);
                let answers = acks(p.preview(), ForkOption::Both);
                let refused = sa.adopt(r, p, Vec::new(), answers, Consent::default(), false);
                assert_eq!(refused.err(), Some(REACH_CHANGED));
                assert_eq!(files(&a), start);
                let (r, p) = plan(&mut sa, &mut codes);
                let answers = acks(p.preview(), ForkOption::Both);
                let adopted = sa
                    .adopt(r, p, Vec::new(), answers, consent(&[4]), false)
                    .unwrap();
                assert_eq!(adopted.suspended, [4]);
                let h = header(&a);
                assert_eq!((h.kind, numbers(&h)), (Kind::Union, vec![1, 2, 3, 4]));
                assert_eq!(h.suspended, 0b1000);
                drop(sa);
                // This PC's password stays (it alone changed it since the
                // fork), and key 4 waits for a pairing.
                assert_eq!(
                    open(&a, NEW, &mut codes, &keys, 4).err(),
                    Some(keyfile::SUSPENDED_KEY)
                );
                assert!(open(&a, NEW, &mut codes, &keys, 2).is_ok());
            }
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.8 "Forks", §7.14 and §14.10-5: a branch authorized by a
        /// key this PC's user removed (`o`) is refused before any touch:
        /// option 2 takes no file whose authorizer is removed here, and
        /// option 1 never brings back a removal made on this PC. At a PC
        /// that took the removal from another file (`t`) only option 1 is
        /// offered, behind G1; option 2 is not.
        #[test]
        fn a_branch_of_a_removed_key_gets_no_option() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 3, false, false);
            let b = second_pc(&a, &mut codes, &keys, 3);
            let c = second_pc(&a, &mut codes, &keys, 3);
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sb.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            let kb = fs::read(b.key()).unwrap();
            let code_b = code_of(&sb);
            drop(sb);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let (ka, code_a) = (fs::read(a.key()).unwrap(), code_of(&sa));
            let (derived, seen) = (derive_count(), keys.fake.seen().len());
            assert_eq!(check(&sa, &kb).err(), Some(ADOPT_REFUSED));
            assert_eq!(
                refusal_values(ADOPT_REFUSED),
                Some(vec![REMOVED_AUTHORIZER.to_owned()])
            );
            assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
            drop(sa);
            // C takes A's removal (`t`); B's branch is then a fork with
            // option 1 alone, behind G1: A's code is not B's file's.
            let mut sc = open(&c, OLD, &mut codes, &keys, 3).unwrap();
            let none = Consent::default();
            take(
                &mut sc,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                pick(&[1]),
                none,
            )
            .unwrap();
            let check_c = check(&sc, &kb).unwrap();
            assert_eq!((check_c.class, check_c.fork), (AdoptClass::Union, true));
            assert!(!check_c.keys.both && check_c.keys.take_other_offered);
            assert_eq!(check_c.keys.take_other, Some(GateKind::G1));
            assert_eq!(check_c.keys.readmit, [credhash(&parse(&kb).unwrap(), 1)]);
            let start = files(&c);
            let f = file(&kb);
            let r = reauth(&mut sc, OLD, &mut codes, &keys, 2).unwrap();
            let t = touch_other(&f, &keys, 2);
            for (option, gate, refused) in [
                (ForkOption::Both, code(code_b), NOT_PLANNED),
                (ForkOption::TakeOther, code(code_a), GATE_CODE_WRONG),
            ] {
                let opened = sc.adopt_open_with(&r, &f, Some(NEW), Some(&t)).unwrap();
                let pass = gate(&check_c, &sc);
                assert_eq!(
                    sc.adopt_preview_with(&r, &f, opened, &check_c, pass, option)
                        .err(),
                    Some(refused)
                );
            }
            assert_eq!(files(&c), start);
            set_kdf_profile(KdfProfile::Real);
        }
        /// Spec §5.10, round 4, finding 13 and S45-2 #2: after a refusal the
        /// user may forget this vault's record: the login ignores the lines
        /// and opens as a bootstrap, whatever the key file; nothing is
        /// removed until the code confirms it, so a lock before leaves the
        /// record as it was; the pass then replaces this vault's lines and
        /// leaves every other vault's as they were.
        #[test]
        fn a_forgotten_record_stays_until_the_code() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 3, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            // Another vault's line on A, which no forget touches.
            let other = [0x0f; 16];
            let elsewhere = anchor::line_of(&header(&a), None);
            anchor::update(&a.anchor_dir(), &other, anchor::LOCK_WAIT, &mut |lines| {
                lines.vault = Some(elsewhere.clone());
                true
            })
            .unwrap();
            // B changes the password with key 1, which A then removes: B's
            // file is refused at A.
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let r = reauth(&mut sb, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sb.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            drop(sb);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            drop(sa);
            carry(&b, &a);
            a.here();
            assert_eq!(
                prepare(&a.vault(), &a.key()).err(),
                Some(ANCHOR_RELIST_KEYS)
            );
            let anchor = a.anchor();
            let login = |codes: &mut Codes| {
                a.here();
                let prepared =
                    super::super::super::super::prepare_forgotten(&a.vault(), &a.key()).unwrap();
                let t = keys.touch(3, &prepared.unlock_request(0).unwrap()).unwrap();
                let (code, typed) = codes.next();
                Session::login_with(prepared, NEW, &code, typed, None, &t).unwrap()
            };
            let s = login(&mut codes);
            assert!(s.tofu() && s.key_code().is_none());
            drop(s);
            // A lock before the code: the record is as it was.
            assert_eq!(a.anchor(), anchor);
            let mut s = login(&mut codes);
            assert_eq!(s.put(None, entry("three")).err(), Some(TOFU_HELD));
            let code = code_of(&s);
            s.tofu_confirm(Some(&code)).unwrap();
            assert!(s.key_code().is_some());
            let lines = a.lines(&id);
            let line = lines.vault.unwrap();
            assert_eq!(line.state.key_state(), s.key_state());
            assert!(line.state.flags.t && line.state.tombs.is_empty());
            assert!(lines.pending.is_none() && lines.gate.is_none());
            assert_eq!(a.lines(&other).vault, Some(elsewhere));
            s.put(None, entry("three")).unwrap();
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.2, §7.17: a Restore with a key file with security keys
        /// that this PC has no record of runs read-only: no destination
        /// file and no anchor line until the code; the TOFU pass then
        /// writes both. In gate-pending mode and TOFU the key code is never
        /// shown.
        #[test]
        fn a_bootstrap_restore_writes_nothing_before_the_code() {
            let a = Pc::new();
            let (sa, mut codes, keys) = create(&a, 2, false, false);
            let code = code_of(&sa);
            drop(sa);
            let b = Pc::new();
            let dest = b.file("restored.goyo");
            let prepared = prepare_restore(&a.vault(), &a.key()).unwrap();
            let t = keys.touch(2, &prepared.unlock_request(0).unwrap()).unwrap();
            let (otp, typed) = codes.next();
            let mut s = Session::restore_with(prepared, &dest, OLD, &otp, typed, &t).unwrap();
            assert!(s.tofu() && !s.restore_held() && s.key_code().is_none());
            assert!(!dest.exists() && b.anchor().is_empty());
            assert_eq!(secrets(&s), ["one", "two"]);
            assert_eq!(s.put(None, entry("three")).err(), Some(TOFU_HELD));
            s.tofu_confirm(Some(&code)).unwrap();
            assert!(dest.exists());
            assert!(b.lines(&s.id).vault.unwrap().state.flags.t);
            s.put(None, entry("three")).unwrap();
            drop(s);
            // The restored file now opens as this vault's, with no gate.
            b.here();
            let prepared = prepare(&dest, &a.key()).unwrap();
            let t = keys.touch(1, &prepared.unlock_request(0).unwrap()).unwrap();
            let (otp, typed) = codes.next();
            let s = Session::login_with(prepared, OLD, &otp, typed, None, &t).unwrap();
            assert!(!s.tofu() && !s.gate_pending());
            assert_eq!(secrets(&s), ["one", "two", "three"]);
            set_kdf_profile(KdfProfile::Real);
        }
        /// Spec §5.2 step 9(a), S45-3 #2 (§14.3 rows): a held session whose
        /// confirmed line lacks `t` is no TOFU session, and keeps TOFU's
        /// refusals on top of the hold: a `Rollback` login edits nothing
        /// and changes no key until [이 열쇠 파일이 맞습니다], after which
        /// it is a bootstrap; a Restore held by a pending line with no
        /// `vault` line writes no `dest`.
        #[test]
        fn a_held_session_this_pc_never_confirmed_edits_nothing() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 2, false, false);
            let id = sa.id;
            let (v1, k1) = (fs::read(a.vault()).unwrap(), fs::read(a.key()).unwrap());
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 1).unwrap();
            assert_eq!(
                sa.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                Ok(Rekeyed::Done)
            );
            drop(sa);
            // The confirmed line lost its `t` (another install's record).
            anchor::update(&a.anchor_dir(), &id, anchor::LOCK_WAIT, &mut |lines| {
                lines.vault.as_mut().unwrap().state.flags.t = false;
                true
            })
            .unwrap();
            fs::write(a.vault(), &v1).unwrap();
            fs::write(a.key(), &k1).unwrap();
            let mut s = open(&a, OLD, &mut codes, &keys, 1).unwrap();
            assert!(s.local_rollback() && !s.tofu() && !s.gate_pending());
            let before = files(&a);
            assert_eq!(s.put(None, entry("three")).err(), Some(TOFU_HELD));
            assert_eq!(s.change_gate(&password(NEW)).err(), Some(TOFU_HELD));
            assert_eq!(files(&a), before);
            let r = reauth(&mut s, OLD, &mut codes, &keys, 1).unwrap();
            s.confirm_key_file(r).unwrap();
            assert!(s.tofu() && !s.local_rollback());
            assert_eq!(s.put(None, entry("three")).err(), Some(TOFU_HELD));
            drop(s);
            // A Restore held by a pending line, with no `vault` line.
            let b = Pc::new();
            let h = header(&a);
            anchor::update(&b.anchor_dir(), &id, anchor::LOCK_WAIT, &mut |lines| {
                lines.pending = Some(anchor::pending_of(&h, None, None, None));
                true
            })
            .unwrap();
            let dest = b.file("restored.goyo");
            b.here();
            let prepared = prepare_restore(&a.vault(), &a.key()).unwrap();
            let t = keys.touch(2, &prepared.unlock_request(0).unwrap()).unwrap();
            let (otp, typed) = codes.next();
            let mut s = Session::restore_with(prepared, &dest, OLD, &otp, typed, &t).unwrap();
            assert!(s.restore_held() && !s.tofu());
            assert!(!dest.exists());
            assert_eq!(s.put(None, entry("three")).err(), Some(TOFU_HELD));
            assert!(!dest.exists());
            set_kdf_profile(KdfProfile::Real);
        }
        /// The data key of a key file of this vault, opened with key 1.
        fn keys_of_bytes(bytes: &[u8], keys: &Keys) -> [u8; 32] {
            *opened(bytes, NEW, keys, 1).bundle.current()
        }

        /// The removed-key simulator (spec §14.10-5): an attacker with key
        /// `x` (its hmac outputs and its PIN), the password and every old
        /// file with its S and data keys, who reads `IK(·←x)` from the pair
        /// records x owns there. From the old file `base` it writes whatever
        /// file it likes, under a fresh data key chained under every old one.
        struct Forger<'k> {
            keys: &'k Keys,
            base: Vec<u8>,
            x: u8,
        }
        /// What a forgery states: the base file's but for the edit, at the
        /// next epoch, as a password change that keeps the password.
        struct Forgery {
            spec: Spec,
            slots: Vec<SlotPublic>,
            sync: bool,
            pin: bool,
            pairs: Vec<PairPlan>,
            otp: bool,
            /// The key the file names as its authorizer: x, unless it poses
            /// as another key, whose output and inbox keys it makes up.
            authorizer: [u8; 16],
        }
        impl Forger<'_> {
            fn forge(&self, edit: impl FnOnce(&mut Forgery)) -> Vec<u8> {
                let f = file(&self.base);
                let h = f.header().unwrap().clone();
                let id = h.vault_id;
                let i = h.slots.iter().position(|s| s.number == self.x).unwrap();
                let x = h.slots[i].clone();
                let opened = f
                    .open(OLD, Some(&touch_other(&f, self.keys, self.x)))
                    .unwrap();
                let h_x = self.output(&id, &x, &x.seed, h.pin());
                // IK(t←x) of every record x owns, from x's output alone.
                let iks: Vec<([u8; 16], [u8; 32])> = f
                    .open_pairs(&h_x, i as u8)
                    .into_iter()
                    .filter_map(|(t, ik)| Some((h.slots[usize::from(t)].credhash, ***ik.as_ref()?)))
                    .collect();
                let mut forgery = Forgery {
                    spec: Spec {
                        epoch: h.epoch + 1,
                        kind: Kind::Password,
                        ..h.spec()
                    },
                    slots: h.slots.clone(),
                    sync: h.magic == Magic::Ks01,
                    pin: h.pin(),
                    pairs: f.carried_pairs(),
                    otp: h.otp(),
                    authorizer: x.credhash,
                };
                edit(&mut forgery);
                let slots = forgery.slots;
                let index = |c: &[u8; 16]| slots.iter().position(|s| s.credhash == *c);
                let a = index(&forgery.authorizer).unwrap();
                let xi = index(&x.credhash);
                let h_now = xi.map(|j| self.output(&id, &x, &slots[j].seed, h.pin()));
                let made_up = || *crypto::random::<32>().unwrap();
                let output = if xi == Some(a) {
                    h_now.unwrap()
                } else {
                    made_up()
                };
                let pairs: Vec<PairPlan> = forgery
                    .pairs
                    .into_iter()
                    .filter(|p| {
                        let (PairPlan::Copy { owner, target, .. }
                        | PairPlan::New { owner, target }) = p;
                        index(owner).is_some() && index(target).is_some()
                    })
                    .collect();
                let mut inbox: Vec<(u8, [u8; 32])> = Vec::new();
                let mut suspended = 0u8;
                for j in (0..slots.len()).filter(|j| *j != a) {
                    let record = pairs.iter().any(|p| {
                        matches!(p, PairPlan::Copy { owner, target, .. }
                            if *owner == slots[a].credhash && *target == slots[j].credhash)
                    });
                    let known = if xi == Some(a) {
                        iks.iter()
                            .find(|(c, _)| *c == slots[j].credhash)
                            .map(|(_, ik)| *ik)
                    } else if xi == Some(j) {
                        // IK(x←a): x derives its own inbox key from any writer.
                        h_now.map(|out| **inbox::inbox_key(&id, &slots[j], &out, &slots[a]))
                    } else {
                        Some(made_up())
                    };
                    match known.filter(|_| record) {
                        Some(ik) => inbox.push((j as u8, ik)),
                        None => suspended |= 1 << j,
                    }
                }
                let s = Secret::random().unwrap();
                let plan = keyfile::KeysPlan {
                    sync: forgery.sync,
                    pin: forgery.pin,
                    s: &s,
                    slots: slots.clone(),
                    authorizer: a as u8,
                    present: 1 << a,
                    suspended,
                    pairs,
                    outputs: vec![(a as u8, &output)],
                    inbox: inbox.iter().map(|(j, ik)| (*j, ik)).collect(),
                };
                let mut dks = vec![made_up()];
                dks.extend_from_slice(opened.bundle.keys());
                let otp = opened.bundle.otp().filter(|_| forgery.otp);
                let bundle = Bundle::new(&dks, otp).unwrap();
                let spec = forgery.spec;
                keyfile::seal(&spec, &bundle, OLD, Plan::Keys(&plan))
                    .unwrap()
                    .0
            }
            /// Key x's output for `seed`, as its holder reads it.
            fn output(
                &self,
                id: &[u8; 16],
                x: &SlotPublic,
                seed: &[u8; 32],
                pin: bool,
            ) -> [u8; 32] {
                let allow = vec![(x.cred_id.clone(), salt(id, seed), None)];
                let req = AssertRequest::new(0, allow, pin).unwrap();
                *self
                    .keys
                    .touch(self.x, &req)
                    .unwrap()
                    .output_for(seed, id)
                    .unwrap()
            }
        }
        /// A change the lib itself writes on the attacker's own PC: the old
        /// files, confirmed there with no code (S-TOFU-NOPC), and each change
        /// authorized by key `x` with the password given. The key file it
        /// wrote last.
        fn written_by(
            old: &(Vec<u8>, Vec<u8>),
            codes: &mut Codes,
            keys: &Keys,
            x: u8,
            changes: Vec<(&str, Change)>,
        ) -> Vec<u8> {
            let e = Pc::new();
            fs::write(e.vault(), &old.0).unwrap();
            fs::write(e.key(), &old.1).unwrap();
            let mut s = open(&e, OLD, codes, keys, x).unwrap();
            s.tofu_confirm(None).unwrap();
            for (password, change) in changes {
                let r = reauth(&mut s, password, codes, keys, x).unwrap();
                assert_eq!(
                    s.rekey(r, Vec::new(), change, Consent::default(), false),
                    Ok(Rekeyed::Done)
                );
            }
            fs::read(e.key()).unwrap()
        }
        /// A login with a key file put in place alone, under an older key of
        /// which the vault file is: the user confirms that vault file.
        fn login_older(pc: &Pc, codes: &mut Codes, keys: &Keys, number: u8) -> Session {
            pc.here();
            let prepared = prepare(&pc.vault(), &pc.key()).unwrap();
            let older = match prepared.check().vault {
                VaultClass::Older { sha } => Some(sha),
                _ => None,
            };
            let t = keys
                .touch(number, &prepared.unlock_request(0).unwrap())
                .unwrap();
            let (code, typed) = codes.next();
            Session::login_with(prepared, OLD, &code, typed, older, &t).unwrap()
        }
        /// Walkthrough §7.21-5's start: keys X = 1, Y = 2 and Z = 3; B
        /// confirmed the first state and stays there; A then removes X for
        /// a loss with a touch of Y. The files X forged from the first state
        /// before (by name), and A's genuine file with the code A shows.
        struct Behind {
            a: Pc,
            b: Pc,
            codes: Codes,
            keys: Keys,
            forged: Vec<(&'static str, Vec<u8>)>,
            genuine: (Vec<u8>, Code),
        }
        fn behind() -> Behind {
            let a = Pc::new();
            let (mut sa, mut codes, mut keys) = create(&a, 3, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let old = (fs::read(a.vault()).unwrap(), fs::read(a.key()).unwrap());
            let y = header(&a).slots[1].credhash;
            let new_key = keys.register(&id, 4, false);
            let mut forged = vec![
                (
                    "mirror",
                    written_by(
                        &old,
                        &mut codes,
                        &keys,
                        1,
                        vec![(OLD, remove(&[2], Some(lost()), None))],
                    ),
                ),
                (
                    "mirror2",
                    written_by(
                        &old,
                        &mut codes,
                        &keys,
                        1,
                        vec![(OLD, remove(&[3], Some(lost()), None))],
                    ),
                ),
                (
                    "added",
                    written_by(
                        &old,
                        &mut codes,
                        &keys,
                        1,
                        vec![(OLD, Change::AddKey(new_key))],
                    ),
                ),
                (
                    "off",
                    written_by(&old, &mut codes, &keys, 1, vec![(OLD, Change::KeysOff)]),
                ),
                (
                    "samepass",
                    written_by(
                        &old,
                        &mut codes,
                        &keys,
                        1,
                        vec![(OLD, password(NEW)), (NEW, password(OLD))],
                    ),
                ),
            ];
            let forger = Forger {
                keys: &keys,
                base: old.1.clone(),
                x: 1,
            };
            // X labelled "보안 키 2" and Y "보안 키 1" (critic N2), and the
            // same with Y removed: "key 1 removed".
            forged.push((
                "swapped",
                forger.forge(|f| {
                    (f.slots[0].number, f.slots[1].number) = (2, 1);
                    f.slots.swap(0, 1);
                }),
            ));
            forged.push((
                "swapped_removal",
                forger.forge(|f| {
                    f.slots.remove(1);
                    f.slots[0].number = 2;
                    f.spec.kind = Kind::Remove;
                    f.spec.tombstones.push(Tombstone {
                        credhash: y,
                        removed: 2,
                    });
                }),
            ));
            // A no-change file that names Y as its authorizer.
            forged.push(("posing", forger.forge(|f| f.authorizer = y)));
            // A record of a key B knows changed: Z's registration day; a
            // pair record of two staying keys, PR(Y, Z), made garbage.
            let z = header(&a).slots[2].clone();
            forged.push(("slot", forger.forge(|f| f.slots[2].registered += 86_400)));
            forged.push((
                "record",
                forger.forge(|f| {
                    for p in &mut f.pairs {
                        if let PairPlan::Copy {
                            owner,
                            target,
                            wrap,
                        } = p
                            && (*owner, *target) == (y, z.credhash)
                        {
                            *wrap = [0x5a; 104];
                        }
                    }
                }),
            ));
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let genuine = (fs::read(a.key()).unwrap(), code_of(&sa));
            drop(sa);
            Behind {
                a,
                b,
                codes,
                keys,
                forged,
                genuine,
            }
        }

        /// The removed-key simulator on the USB path (spec §14.10-5,
        /// walkthrough §7.21-5): B never saw X's removal. The number swap
        /// needs G1 (pinning); the mirror image "X removes Y" fails G2 with
        /// the user's pick of X, reveals nothing, and then G1 with A's code
        /// fails, and the next forged candidate gets no G2; a forged add and
        /// keys off fail G1; a same-password "password change" fails E5. A
        /// file that names Y as its authorizer opens for no staying key.
        /// Nothing is written, every check runs before any touch, and the
        /// genuine removal is still taken.
        #[test]
        fn the_removed_key_forges_nothing_a_pc_behind_takes() {
            let Behind {
                b,
                mut codes,
                keys,
                forged,
                genuine,
                ..
            } = behind();
            let get = |name: &str| forged.iter().find(|(n, _)| *n == name).unwrap().1.clone();
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let start = files(&b);
            let (derived, seen) = (derive_count(), keys.fake.seen().len());
            for name in ["swapped", "swapped_removal"] {
                let c = check(&sb, &get(name)).unwrap();
                assert_eq!(
                    (c.class, c.keys.gate),
                    (AdoptClass::Successor, Some(GateKind::G1)),
                    "{name}"
                );
                assert!(c.keys.checked.gates.slot, "{name}");
            }
            let c = check(&sb, &get("mirror")).unwrap();
            assert_eq!(
                (c.class, c.keys.gate),
                (AdoptClass::Successor, Some(GateKind::G2))
            );
            assert_eq!(
                check(&sb, &get("added")).unwrap().keys.gate,
                Some(GateKind::G1)
            );
            let c = check(&sb, &get("off")).unwrap();
            assert_eq!(
                (c.class, c.keys.gate),
                (AdoptClass::Union, Some(GateKind::G1))
            );
            assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
            let mut try_take =
                |s: &mut Session, name: &str, gate: &dyn Fn(&AdoptCheck, &Session) -> GatePass| {
                    take(
                        s,
                        &mut codes,
                        &keys,
                        (OLD, 3),
                        &get(name),
                        ForkOption::Both,
                        |c, s| gate(c, s),
                        Consent::default(),
                    )
                    .err()
                };
            let pick_x = |c: &AdoptCheck, s: &Session| pick(&[1])(c, s);
            let genuine_code = |c: &AdoptCheck, s: &Session| code(genuine.1)(c, s);
            for name in ["swapped", "swapped_removal"] {
                assert_eq!(
                    try_take(&mut sb, name, &pick_x),
                    Some(ADOPT_STALE),
                    "{name}"
                );
                assert_eq!(
                    try_take(&mut sb, name, &genuine_code),
                    Some(GATE_CODE_WRONG),
                    "{name}"
                );
            }
            // The mirror image: the user picks X, the key it lost.
            assert_eq!(try_take(&mut sb, "mirror", &pick_x), Some(GATE_G2FAIL));
            assert_eq!(refusal_values(GATE_G2FAIL), None);
            assert_eq!(
                check(&sb, &get("mirror")).unwrap().keys.gate,
                Some(GateKind::G1)
            );
            assert_eq!(
                try_take(&mut sb, "mirror", &genuine_code),
                Some(GATE_CODE_WRONG)
            );
            // One-shot G2: the next forged candidate gets G1 only.
            assert_eq!(
                check(&sb, &get("mirror2")).unwrap().keys.gate,
                Some(GateKind::G1)
            );
            assert_eq!(
                try_take(&mut sb, "added", &genuine_code),
                Some(GATE_CODE_WRONG)
            );
            assert_eq!(
                try_take(&mut sb, "samepass", &|c, _| GatePass::none(c)),
                Some(ADOPT_REFUSED)
            );
            assert_eq!(
                refusal_values(ADOPT_REFUSED),
                Some(vec![UNEXPLAINED.to_owned()])
            );
            // Keys off: password-only, so opened with the password alone.
            {
                let off = file(&get("off"));
                let c = check(&sb, off.bytes()).unwrap();
                let r = reauth(&mut sb, OLD, &mut codes, &keys, 3).unwrap();
                let opened = sb.adopt_open_with(&r, &off, None, None).unwrap();
                let plan = sb.adopt_preview_with(
                    &r,
                    &off,
                    opened,
                    &c,
                    code(genuine.1)(&c, &sb),
                    ForkOption::Both,
                );
                assert_eq!(plan.err(), Some(GATE_CODE_WRONG));
            }
            // Posing as Y: no staying key opens it.
            let posing = file(&get("posing"));
            let c = check(&sb, posing.bytes()).unwrap();
            assert_eq!((c.class, c.keys.gate), (AdoptClass::Successor, None));
            for k in [2, 3] {
                let r = reauth(&mut sb, OLD, &mut codes, &keys, k).unwrap();
                let t = touch_other(&posing, &keys, k);
                assert_eq!(
                    sb.adopt_open_with(&r, &posing, None, Some(&t)).err(),
                    Some(AUTH_ERROR)
                );
            }
            // The vault and key files as they were; the anchor holds G2 off.
            let now = files(&b);
            assert_eq!((now.0, now.1), (start.0, start.1));
            // The genuine removal: G1 now, with A's code.
            take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &genuine.0,
                ForkOption::Both,
                code(genuine.1),
                Consent::default(),
            )
            .unwrap();
            assert_eq!(header(&b).state(), parse(&genuine.0).unwrap().state());
            set_kdf_profile(KdfProfile::Real);
        }

        /// The same on the login path (spec §14.10-5, §5.10): each forged
        /// file put in place of B's key file opens in gate-pending mode, or
        /// is refused before any touch (keys off: S-ANCHOR-DOWNGRADE). The
        /// pick lists B's own numbers, never the file's; the mirror image's
        /// pick of X fails and G2 stays off; A's code confirms none of them.
        /// A new PC with a forged file stays in TOFU: no code another PC
        /// shows confirms it. B's own key file then opens as before.
        #[test]
        fn the_removed_key_forges_nothing_a_pc_behind_opens_at_login() {
            let Behind {
                a,
                b,
                mut codes,
                keys,
                forged,
                genuine,
            } = behind();
            let get = |name: &str| forged.iter().find(|(n, _)| *n == name).unwrap().1.clone();
            let id = header(&b).vault_id;
            let own = fs::read(b.key()).unwrap();
            let own_choices: Vec<(u8, [u8; 16])> = parse(&own)
                .unwrap()
                .slots
                .iter()
                .map(|s| (s.number, s.credhash))
                .collect();
            let wrong = |s: &mut Session| {
                assert_eq!(
                    s.pass_login_gate(GateAnswer::Code(genuine.1)).err(),
                    Some(GATE_CODE_WRONG)
                );
                assert_eq!(s.put(None, entry("three")).err(), Some(GATE_HELD));
                assert!(s.gate_pending() && s.key_code().is_none());
            };
            for (name, gate) in [
                ("swapped", GateKind::G1),
                ("swapped_removal", GateKind::G1),
                ("mirror", GateKind::G2),
                ("mirror2", GateKind::G1),
                ("added", GateKind::G1),
            ] {
                fs::write(b.key(), get(name)).unwrap();
                // Z, or Y where the file removes Z.
                let number = if name == "mirror2" { 2 } else { 3 };
                let mut s = login_older(&b, &mut codes, &keys, number);
                assert_eq!(s.login_gate(), Some(gate), "{name}");
                let choices: Vec<(u8, [u8; 16])> = s
                    .gate_choices()
                    .iter()
                    .map(|c| (c.number, c.credhash))
                    .collect();
                assert_eq!(choices, own_choices, "{name}");
                let x = own_choices[0].1;
                let picked = s.pass_login_gate(GateAnswer::Pick(vec![x])).err();
                match gate {
                    GateKind::G2 => assert_eq!(picked, Some(GATE_G2FAIL_DISK)),
                    GateKind::G1 => assert_eq!(picked, Some(GATE_NOT_PENDING), "{name}"),
                }
                assert_eq!(s.login_gate(), Some(GateKind::G1), "{name}");
                wrong(&mut s);
            }
            // Keys off for a vault pinned as hardware: refused before any
            // touch or Argon2.
            fs::write(b.key(), get("off")).unwrap();
            let (derived, seen) = (derive_count(), keys.fake.seen().len());
            b.here();
            assert_eq!(prepare(&b.vault(), &b.key()).err(), Some(ANCHOR_DOWNGRADE));
            assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
            // Posing as Y: no staying key opens it, X does.
            fs::write(b.key(), get("posing")).unwrap();
            for k in [2, 3] {
                assert_eq!(open(&b, OLD, &mut codes, &keys, k).err(), Some(AUTH_ERROR));
            }
            assert_eq!(opened(&get("posing"), OLD, &keys, 1).slot, Some(0));
            // A bootstrap with a forged file: neither A's code nor the one B
            // shows for its own state confirms it.
            let d = Pc::new();
            fs::copy(b.vault(), d.vault()).unwrap();
            fs::write(d.key(), get("mirror")).unwrap();
            let mut s = login_older(&d, &mut codes, &keys, 3);
            assert!(s.tofu());
            let code_b = key_code(
                &id,
                opened(&own, OLD, &keys, 3).bundle.current(),
                parse(&own).unwrap().state(),
            );
            for c in [genuine.1, code_b] {
                assert_eq!(s.tofu_confirm(Some(&c)).err(), Some(GATE_CODE_WRONG));
            }
            assert!(s.tofu() && d.anchor().is_empty());
            drop(s);
            // B's own key file opens as before, and the genuine removal is
            // still taken at login with A's code (G2 stayed off).
            fs::write(b.key(), &own).unwrap();
            let s = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            assert!(!s.gate_pending());
            assert_eq!(secrets(&s), ["one", "two"]);
            drop(s);
            fs::copy(a.key(), b.key()).unwrap();
            let mut s = login_older(&b, &mut codes, &keys, 3);
            assert_eq!(s.login_gate(), Some(GateKind::G1));
            s.pass_login_gate(GateAnswer::Code(genuine.1)).unwrap();
            assert!(!s.gate_pending());
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §14.10-5: at a PC that has seen X's removal every file X
        /// writes is refused before any touch or Argon2: at login by the
        /// anchor (S-ANCHOR-RELIST-SK; keys off as a downgrade), and by a USB
        /// adopt at the PC whose user removed X (P4, "제거된 보안 키가
        /// 승인함"). At a PC that took the removal from A (`t`), a USB adopt
        /// offers fork option 1 alone, behind G1.
        #[test]
        fn every_file_the_removed_key_writes_is_refused_before_any_touch() {
            let Behind {
                a,
                b,
                mut codes,
                keys,
                forged,
                genuine,
            } = behind();
            let named = [
                "mirror",
                "mirror2",
                "added",
                "samepass",
                "swapped",
                "swapped_removal",
                "slot",
                "record",
            ];
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &genuine.0,
                ForkOption::Both,
                pick(&[1]),
                Consent::default(),
            )
            .unwrap();
            drop(sb);
            for pc in [&a, &b] {
                let own = fs::read(pc.key()).unwrap();
                let anchor = pc.anchor();
                let (derived, seen) = (derive_count(), keys.fake.seen().len());
                for (name, bytes) in &forged {
                    fs::write(pc.key(), bytes).unwrap();
                    pc.here();
                    let refused = if *name == "off" {
                        ANCHOR_DOWNGRADE
                    } else {
                        ANCHOR_RELIST_KEYS
                    };
                    assert_eq!(
                        prepare(&pc.vault(), &pc.key()).err(),
                        Some(refused),
                        "{name}"
                    );
                }
                assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
                assert_eq!(pc.anchor(), anchor);
                fs::write(pc.key(), &own).unwrap();
            }
            let sa = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            let sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let (derived, seen) = (derive_count(), keys.fake.seen().len());
            for (name, bytes) in forged.iter().filter(|(n, _)| named.contains(n)) {
                assert_eq!(check(&sa, bytes).err(), Some(ADOPT_REFUSED), "{name}");
                assert_eq!(
                    refusal_values(ADOPT_REFUSED),
                    Some(vec![REMOVED_AUTHORIZER.to_owned()]),
                    "{name}"
                );
                if *name == "slot" {
                    assert_eq!(check(&sb, bytes).err(), Some(ADOPT_REFUSED));
                    assert_eq!(
                        refusal_values(ADOPT_REFUSED),
                        Some(vec![SLOT_CHANGED.to_owned()])
                    );
                    continue;
                }
                let c = check(&sb, bytes).unwrap();
                assert_eq!((c.class, c.fork), (AdoptClass::Union, true), "{name}");
                assert!(!c.keys.both && c.keys.take_other_offered, "{name}");
                assert_eq!(c.keys.take_other, Some(GateKind::G1), "{name}");
            }
            assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
            set_kdf_profile(KdfProfile::Real);
        }

        /// Slot and pair-record pinning (spec §7.14; critic N2, round 2,
        /// finding 5): a forged file that changes a known key's record in
        /// more than its number and seed is refused before any touch, at a
        /// USB adopt ("보안 키 기록이 바뀜") and at login (S-ANCHOR-PINNED);
        /// one that changes a pair record of two staying keys is refused at
        /// a USB adopt ("짝 기록이 바뀜").
        #[test]
        fn a_forged_file_changes_no_record_of_a_known_key() {
            let Behind {
                b,
                mut codes,
                keys,
                forged,
                ..
            } = behind();
            let get = |name: &str| forged.iter().find(|(n, _)| *n == name).unwrap().1.clone();
            let sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let derived = derive_count();
            for (name, reason) in [("slot", SLOT_CHANGED), ("record", PAIR_CHANGED)] {
                assert_eq!(check(&sb, &get(name)).err(), Some(ADOPT_REFUSED), "{name}");
                assert_eq!(refusal_values(ADOPT_REFUSED), Some(vec![reason.to_owned()]));
            }
            drop(sb);
            fs::write(b.key(), get("slot")).unwrap();
            b.here();
            assert_eq!(prepare(&b.vault(), &b.key()).err(), Some(ANCHOR_PINNED));
            assert_eq!(derive_count(), derived);
            set_kdf_profile(KdfProfile::Real);
        }

        /// The gate's G1 triggers against a forger at a PC behind (spec
        /// §7.15a, critic N2, N5; round 2, finding 4; round 3, finding 16),
        /// on a vault in PIN mode with OTP: a renumbering, a re-seed of X,
        /// PIN mode turned off, removals of keys the PC never knew and a
        /// silent jump each need G1, at a USB adopt and at login, and A's
        /// code is no file's; a file without the OTP is refused (E1). All
        /// before any touch.
        #[test]
        fn a_forged_renumbering_reseed_or_policy_change_needs_the_code() {
            let a = Pc::new();
            let (sa, mut codes, keys) = create_with(&a, 3, true, false, true);
            let b = second_pc(&a, &mut codes, &keys, 3);
            let code_a = code_of(&sa);
            drop(sa);
            let forger = Forger {
                keys: &keys,
                base: fs::read(a.key()).unwrap(),
                x: 1,
            };
            let forged: Vec<(&str, Vec<u8>)> = vec![
                (
                    "swapped",
                    forger.forge(|f| {
                        (f.slots[0].number, f.slots[1].number) = (2, 1);
                        f.slots.swap(0, 1);
                    }),
                ),
                ("reseed", forger.forge(|f| f.slots[0].seed = [0x77; 32])),
                ("pin_off", forger.forge(|f| f.pin = false)),
                (
                    "unknown",
                    forger.forge(|f| {
                        f.spec.tombstones.push(Tombstone {
                            credhash: [0x98; 16],
                            removed: 2,
                        })
                    }),
                ),
                (
                    "jump",
                    forger.forge(|f| f.spec.epoch = 1 + keyfile::EPOCH_SILENT + 1),
                ),
            ];
            let no_otp = forger.forge(|f| f.otp = false);
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let own = fs::read(b.key()).unwrap();
            let (derived, seen) = (derive_count(), keys.fake.seen().len());
            for (name, bytes) in &forged {
                let c = check(&sb, bytes).unwrap();
                assert_eq!(
                    (c.class, c.keys.gate),
                    (AdoptClass::Successor, Some(GateKind::G1)),
                    "{name}"
                );
            }
            assert_eq!(check(&sb, &no_otp).err(), Some(NOT_THIS_VAULT));
            assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
            let jump = &forged.iter().find(|(n, _)| *n == "jump").unwrap().1;
            let taken = take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                jump,
                ForkOption::Both,
                code(code_a),
                Consent::default(),
            );
            assert_eq!(taken.err(), Some(GATE_CODE_WRONG));
            drop(sb);
            // An OTP vault's Reauth saves its vault file; the key file stays.
            assert_eq!(fs::read(b.key()).unwrap(), own);
            // At login, the precheck already asks G1, before any touch.
            for (name, bytes) in &forged {
                fs::write(b.key(), bytes).unwrap();
                b.here();
                let prepared = prepare(&b.vault(), &b.key()).unwrap();
                assert_eq!(
                    prepared.check().anchor,
                    AnchorClass::Gated(GateKind::G1),
                    "{name}"
                );
            }
            // A file without the OTP is E1 at login too: refused before any
            // touch or Argon2, not a failed attempt (spec §7.14).
            fs::write(b.key(), &no_otp).unwrap();
            let (anchor, derived, seen) = (b.anchor(), derive_count(), keys.fake.seen().len());
            b.here();
            assert_eq!(
                prepare(&b.vault(), &b.key()).err(),
                Some(super::super::super::super::gate::ANCHOR_OTP)
            );
            assert!(not_a_failure(super::super::super::super::gate::ANCHOR_OTP));
            assert_eq!((derive_count(), keys.fake.seen().len()), (derived, seen));
            assert_eq!(b.anchor(), anchor);
            fs::write(b.key(), own).unwrap();
            set_kdf_profile(KdfProfile::Real);
        }

        /// P3 against a forger at a PC that saw an earlier removal (spec
        /// §7.14, §5.10): W = key 1 was removed everywhere; X = key 2 writes
        /// from that state a file that drops W's removal ("제거 기록이
        /// 빠짐"; at login S-ANCHOR-RELIST) and one that lists W live again
        /// ("뺀 보안 키가 다시 들어 있음"; at login S-ANCHOR-RELIST-SK). Both
        /// are refused before any touch or Argon2.
        #[test]
        fn a_forged_file_that_drops_or_relists_an_old_removal_is_refused() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let w = header(&a).slots[0].clone();
            remove_lost(&mut sa, &mut codes, &keys, 1, 3);
            drop(sa);
            let b = second_pc(&a, &mut codes, &keys, 4);
            let forger = Forger {
                keys: &keys,
                base: fs::read(b.key()).unwrap(),
                x: 2,
            };
            let dropped = forger.forge(|f| f.spec.tombstones.clear());
            let relisted = forger.forge(|f| {
                f.spec.tombstones.clear();
                f.slots.insert(0, w.clone());
            });
            let sb = open(&b, OLD, &mut codes, &keys, 4).unwrap();
            let derived = derive_count();
            for (bytes, reason) in [(&dropped, LACKS_REMOVAL), (&relisted, RELISTED)] {
                assert_eq!(check(&sb, bytes).err(), Some(ADOPT_REFUSED));
                assert_eq!(refusal_values(ADOPT_REFUSED), Some(vec![reason.to_owned()]));
            }
            drop(sb);
            for (bytes, refused) in [(&dropped, ANCHOR_RELIST), (&relisted, ANCHOR_RELIST_KEYS)] {
                fs::write(b.key(), bytes).unwrap();
                b.here();
                assert_eq!(prepare(&b.vault(), &b.key()).err(), Some(refused));
            }
            assert_eq!(derive_count(), derived);
            set_kdf_profile(KdfProfile::Real);
        }

        /// Spec §5.8, §9.2: the second site takes another PC's removal with
        /// one touch, reused for the Reauth and the open (the seeds are the
        /// same in both files).
        #[test]
        fn a_successor_is_taken_with_one_touch() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let b = second_pc(&a, &mut codes, &keys, 3);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let ka = fs::read(a.key()).unwrap();
            drop(sa);
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            let f = file(&ka);
            let c = check(&sb, &ka).unwrap();
            let seen = keys.fake.seen().len();
            let t = keys.touch(3, &sb.key_request(&[3], 0).unwrap()).unwrap();
            let (otp, typed) = codes.next();
            let r = sb.reauth(OLD, Some((&otp, typed)), Some(&t)).unwrap();
            let opened = sb.adopt_open_with(&r, &f, None, Some(&t)).unwrap();
            let pass = pick(&[1])(&c, &sb);
            let plan = sb
                .adopt_preview_with(&r, &f, opened, &c, pass, ForkOption::Both)
                .unwrap();
            let acks = acks(plan.preview(), ForkOption::Both);
            let taken = sb
                .adopt(r, plan, Vec::new(), acks, Consent::default(), false)
                .unwrap();
            assert_eq!(taken.state, parse(&ka).unwrap().state());
            assert_eq!(keys.fake.seen().len(), seen + 1);
            set_kdf_profile(KdfProfile::Real);
        }
        /// Walkthrough §7.7-14's core (USB mode): both sites ran the
        /// lost-key flow for the same key, each with its own key; the two
        /// branches are a fork that joins with no gate (nothing of either
        /// PC's is removed by the other), keeping both removals, and the
        /// union then reaches the first site as a successor.
        #[test]
        fn both_sites_removing_the_same_lost_key_join() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let b = second_pc(&a, &mut codes, &keys, 3);
            let one = credhash(&header(&a), 1);
            remove_lost(&mut sa, &mut codes, &keys, 1, 2);
            let ka = fs::read(a.key()).unwrap();
            drop(sa);
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            remove_lost(&mut sb, &mut codes, &keys, 1, 3);
            let c = check(&sb, &ka).unwrap();
            assert_eq!(
                (c.class, c.fork, c.keys.gate),
                (AdoptClass::Union, true, None)
            );
            take(
                &mut sb,
                &mut codes,
                &keys,
                (OLD, 3),
                &ka,
                ForkOption::Both,
                none,
                Consent::default(),
            )
            .unwrap();
            let h = header(&b);
            assert_eq!(numbers(&h), [2, 3, 4]);
            assert!(h.tombstones.iter().any(|t| t.credhash == one));
            let kb = fs::read(b.key()).unwrap();
            drop(sb);
            let mut sa = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            let c = check(&sa, &kb).unwrap();
            assert_eq!((c.class, c.keys.gate), (AdoptClass::Successor, None));
            take(
                &mut sa,
                &mut codes,
                &keys,
                (OLD, 2),
                &kb,
                ForkOption::Both,
                none,
                Consent::default(),
            )
            .unwrap();
            assert_eq!(header(&a).state(), parse(&kb).unwrap().state());
            drop(sa);
            for k in [2, 3, 4] {
                assert!(open(&a, OLD, &mut codes, &keys, k).is_ok(), "key {k}");
            }
            set_kdf_profile(KdfProfile::Real);
        }
        /// Spec §5.2 (S45-2 #5, round 3, finding 17): on a shared stick this
        /// PC's own lost-key removal landed but crashed before S5, and
        /// another PC wrote a gated change on top. The login promotes the
        /// own entry in gate-pending mode (no S-REMOVE-UNDONE, the review
        /// due), and the pass builds on it: the own removal keeps its `o`,
        /// the other's is taken (`t`).
        #[test]
        fn an_own_landed_removal_under_a_gated_change_is_kept() {
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 4, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let h = header(&a);
            let (one, four) = (credhash(&h, 1), credhash(&h, 4));
            let r = reauth(&mut sa, OLD, &mut codes, &keys, 2).unwrap();
            CRASH.with(|c| c.set(Some("S4")));
            let change = remove(&[1], Some(lost()), None);
            assert_eq!(
                sa.rekey(r, Vec::new(), change, Consent::default(), false)
                    .err(),
                Some(SIMULATED_CRASH)
            );
            drop(sa);
            assert!(a.lines(&id).pending.is_some());
            carry(&a, &b);
            let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
            sb.pass_login_gate(GateAnswer::Pick(vec![one])).unwrap();
            remove_lost(&mut sb, &mut codes, &keys, 4, 3);
            drop(sb);
            carry(&b, &a);
            let mut s = open(&a, OLD, &mut codes, &keys, 2).unwrap();
            assert!(s.gate_pending());
            assert_eq!(notices(&mut s), []);
            assert_eq!(s.review_due(), Some("unknown"));
            let lines = a.lines(&id);
            assert!(lines.pending.is_none());
            let origin = |l: &anchor::VaultLine, c: &[u8; 16]| {
                l.state
                    .tombs
                    .iter()
                    .find(|t| t.credhash == *c)
                    .map(|t| t.origin)
            };
            assert_eq!(
                origin(lines.vault.as_ref().unwrap(), &one),
                Some(Origin::Own)
            );
            assert_eq!(s.login_gate(), Some(GateKind::G2));
            s.pass_login_gate(GateAnswer::Pick(vec![four])).unwrap();
            let line = a.lines(&id).vault.unwrap();
            assert_eq!(line.state.key_state(), s.key_state());
            assert_eq!(origin(&line, &one), Some(Origin::Own));
            assert_eq!(origin(&line, &four), Some(Origin::Taken));
            set_kdf_profile(KdfProfile::Real);
        }
        /// The adopts of the crash matrix with keys (spec §14.5): another
        /// PC's lost-key removal taken as a successor with its code after a
        /// wrong pick (C0-C7 for an adopt, I13), a fork joined by option 2
        /// (C13), and option 1 that re-admits a key whose removal this PC
        /// took from another file (C15).
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Taking {
            Successor,
            Union,
            TakeOther,
        }
        /// The plan of an adopt as the flow makes it, up to [받기]: the
        /// checks, a Reauth with `mine` and key `number`, the open with
        /// `other_pw` (None: this PC's), the gate and the preview.
        #[allow(clippy::too_many_arguments)]
        fn planned_adopt(
            s: &mut Session,
            codes: &mut Codes,
            keys: &Keys,
            (mine, number): (&str, u8),
            other: &[u8],
            other_pw: Option<&str>,
            option: ForkOption,
            gate: impl FnOnce(&AdoptCheck, &Session) -> GatePass,
        ) -> Result<(Reauth, super::super::super::super::AdoptPlan)> {
            let f = file(other);
            let check = s.adopt_check(&f, Source::File(f.path().to_owned()))?;
            let r = reauth(s, mine, codes, keys, number)?;
            let t = touch_other(&f, keys, number);
            let opened = s.adopt_open_with(&r, &f, other_pw, Some(&t))?;
            let pass = gate(&check, s);
            let plan = s.adopt_preview_with(&r, &f, opened, &check, pass, option)?;
            Ok((r, plan))
        }
        /// `kind` killed at `point`, then unlocked again (spec §5.6, §14.5):
        /// I1-I3, I13, I15 and I16, the removal's review and the re-admitted
        /// key.
        fn crash_adopt(kind: Taking, point: &'static str) {
            let case = format!("{kind:?} {point}");
            let a = Pc::new();
            let (mut sa, mut codes, keys) = create(&a, 3, false, false);
            let id = sa.id;
            let b = second_pc(&a, &mut codes, &keys, 3);
            let c = second_pc(&a, &mut codes, &keys, 3);
            let one = credhash(&header(&a), 1);
            // The PC that adopts, its passwords before and after, the key
            // it unlocks with, and whether the adopt removes its key 1.
            let (pc, (before, after), key, removal) = match kind {
                Taking::Successor => {
                    remove_lost(&mut sa, &mut codes, &keys, 1, 2);
                    (&b, (OLD, OLD), 3, true)
                }
                Taking::Union => {
                    let r = reauth(&mut sa, OLD, &mut codes, &keys, 1).unwrap();
                    let change = password(NEW);
                    assert_eq!(
                        sa.rekey(r, Vec::new(), change, Consent::default(), false),
                        Ok(Rekeyed::Done)
                    );
                    let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
                    let r = reauth(&mut sb, OLD, &mut codes, &keys, 1).unwrap();
                    assert_eq!(
                        sb.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                        Ok(Rekeyed::Done)
                    );
                    (&b, (NEW, NEW), 2, false)
                }
                Taking::TakeOther => {
                    let mut sb = open(&b, OLD, &mut codes, &keys, 3).unwrap();
                    let r = reauth(&mut sb, OLD, &mut codes, &keys, 1).unwrap();
                    assert_eq!(
                        sb.rekey(r, Vec::new(), password(NEW), Consent::default(), false),
                        Ok(Rekeyed::Done)
                    );
                    // C takes A's removal (`t`); B's branch then re-admits
                    // key 1 by option 1 alone.
                    remove_lost(&mut sa, &mut codes, &keys, 1, 2);
                    let ka = fs::read(a.key()).unwrap();
                    let mut sc = open(&c, OLD, &mut codes, &keys, 3).unwrap();
                    take(
                        &mut sc,
                        &mut codes,
                        &keys,
                        (OLD, 3),
                        &ka,
                        ForkOption::Both,
                        pick(&[1]),
                        Consent::default(),
                    )
                    .unwrap();
                    (&c, (OLD, NEW), 2, false)
                }
            };
            let theirs = match kind {
                Taking::TakeOther => fs::read(b.key()).unwrap(),
                _ => fs::read(a.key()).unwrap(),
            };
            let code_theirs = match kind {
                Taking::TakeOther => code_of(&open(&b, NEW, &mut codes, &keys, 3).unwrap()),
                _ => code_of(&sa),
            };
            drop(sa);
            let mut s = open(pc, before, &mut codes, &keys, key).unwrap();
            let start = (secrets(&s), fs::read(pc.key()).unwrap());
            // I13: a wrong pick first turns G2 off.
            if kind == Taking::Successor {
                let wrong = planned_adopt(
                    &mut s,
                    &mut codes,
                    &keys,
                    (before, key),
                    &theirs,
                    None,
                    ForkOption::Both,
                    pick(&[2]),
                );
                assert_eq!(wrong.err(), Some(GATE_G2FAIL), "{case}");
            }
            let (option, other_pw) = match kind {
                Taking::TakeOther => (ForkOption::TakeOther, Some(NEW)),
                _ => (ForkOption::Both, None),
            };
            let gate = |c: &AdoptCheck, s: &Session| match kind {
                Taking::Union => GatePass::none(c),
                _ => code(code_theirs)(c, s),
            };
            let (r, plan) = planned_adopt(
                &mut s,
                &mut codes,
                &keys,
                (before, key),
                &theirs,
                other_pw,
                option,
                gate,
            )
            .unwrap_or_else(|e| panic!("{case}: {e}"));
            let acks = acks(plan.preview(), option);
            let gap = GAPS
                .iter()
                .find(|(g, _)| *g == point)
                .map(|(_, then)| *then);
            THEN.with(|t| t.set(gap));
            CRASH.with(|c| c.set(Some(point)));
            let result = s.adopt(r, plan, Vec::new(), acks, Consent::default(), false);
            assert_eq!(result.map(|_| ()), Err(SIMULATED_CRASH), "{case}");
            assert_eq!(CRASH.with(|c| c.get()), None, "{case}: point not reached");
            assert_eq!(THEN.with(|t| t.take()), None, "{case}: gap not reached");
            drop(s);
            let landed = LANDED.contains(&point) || matches!(point, "S2.gap" | "S3.gap");
            let (right, wrong) = if landed {
                (after, before)
            } else {
                (before, after)
            };
            if right != wrong {
                let e = open(pc, wrong, &mut codes, &keys, key).err();
                assert_eq!(e, Some(AUTH_ERROR), "{case}");
            }
            let mut s =
                open(pc, right, &mut codes, &keys, key).unwrap_or_else(|e| panic!("{case}: {e}"));
            let said = notices(&mut s);
            // The anchor existed: a pending line cut off in its own write
            // was never seen.
            let not_finished = !landed && point != "S0.tmp_synced";
            let count = |n: &KeyNotice| said.iter().filter(|x| *x == n).count();
            assert_eq!(
                count(&KeyNotice::RemoveUndone(vec![1])),
                usize::from(not_finished && removal),
                "{case}: {said:?}"
            );
            assert_eq!(
                count(&KeyNotice::NotFinished),
                usize::from(not_finished && !removal),
                "{case}: {said:?}"
            );
            assert!(
                said.iter().all(|n| matches!(
                    n,
                    KeyNotice::NotFinished | KeyNotice::RemoveUndone(_) | KeyNotice::Resumed
                )),
                "{case}: {said:?}"
            );
            assert!(!s.tofu() && !s.gate_pending(), "{case}");
            if kind == Taking::Successor {
                assert_eq!(s.review_due().is_some(), !point.starts_with("S0"), "{case}");
            }
            // I2, I3.
            assert_eq!(secrets(&s), start.0, "{case}");
            consistent(pc, &s);
            assert!(pc.temps(&pc.key()).is_empty(), "{case}");
            assert!(pc.temps(&pc.vault()).is_empty(), "{case}");
            assert_eq!(fs::read(pc.key()).unwrap() != start.1, landed, "{case}");
            let k = header(pc);
            if landed && kind == Taking::Successor {
                assert_eq!(k.state(), parse(&theirs).unwrap().state(), "{case}");
            }
            let lines = pc.lines(&id);
            assert!(lines.pending.is_none(), "{case}");
            let line = lines.vault.clone().expect("a confirmed line");
            assert!(line.state.flags.t, "{case}");
            assert_eq!(line.state.key_state(), s.key_state(), "{case}");
            // I13: G2 stays off until a change lands; nothing is pending.
            if kind == Taking::Successor {
                let gate = lines.gate.clone();
                if landed {
                    assert!(gate.is_none(), "{case}: {gate:?}");
                } else {
                    let gate = gate.expect("the g2=off line");
                    assert!(!gate.g2 && gate.state == anchor::GateState::None, "{case}");
                }
            }
            // C15: the re-admitted key is live, and its tombstone left the
            // anchor once the union landed.
            if kind == Taking::TakeOther {
                let live = k.slots.iter().any(|x| x.credhash == one);
                let dead = line.state.tombs.iter().any(|t| t.credhash == one);
                assert_eq!((live, dead), (landed, !landed), "{case}");
            }
            drop(s);
            // I15: every live key that is not suspended opens the key file.
            for (j, slot) in k.slots.iter().enumerate() {
                if (k.suspended >> j) & 1 == 0 {
                    let s = open(pc, right, &mut codes, &keys, slot.number);
                    assert!(s.is_ok(), "{case}: key {}", slot.number);
                }
            }
        }
        /// Every crash point of every adopt with keys (spec §5.6 C13, C15,
        /// §14.5): a pair that opens, this PC's own write recognized with
        /// nothing asked, a dropped removal named.
        #[test]
        fn every_crash_point_of_an_adopt_with_keys_leaves_a_pair_that_opens() {
            for kind in [Taking::Successor, Taking::Union, Taking::TakeOther] {
                for point in POINTS {
                    crash_adopt(kind, point);
                }
            }
            set_kdf_profile(KdfProfile::Real);
        }
    }
}
