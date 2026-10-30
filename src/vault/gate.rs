//! The pre-adoption gate and the public checks of a key file (spec v3
//! §7.14, §7.15a; feature `security-key`). Whatever this PC would install or
//! adopt is compared, on public bytes and before any touch, with the state
//! this PC knows: its own opened key file (a USB adopt) or the anchor's
//! confirmed line (a changed key file at login, a bootstrap).
//!
//! The public checks refuse what no honest writer produces: a key this PC
//! removed live again or authorizing (P3, P4), a removal it recorded missing
//! (P3), a known key's record changed but for its number and seed (slot
//! pinning), a pair record changed outside the repairs that pinning allows.
//! The gate then guards every keyset and policy change: G2 is the user's
//! pick of exactly the keys a file removes, G1 the key code that only a
//! holder of the file's data key can show, on another PC. Nothing about a
//! change, its keys, its authorizer or its code, is shown before its gate
//! passed (the display rule): the pick lists this PC's own keys only.
use super::{
    KeyNotice, Session,
    anchor::{self, GateLine, GateState, Lines, Slot, State, VaultLine},
    keyfile::{Code, EPOCH_SILENT, KeyFile, KeyHeader, KeyState, PairPlan, Tombstone, key_code},
};
use crate::crypto::{AUTH_ERROR, Result, ct_eq};

/// Why a file is refused (KeyFileRefused, S-ADOPT-REFUSED; spec §7.4,
/// §7.14). A removal this PC recorded: the other file lists that key live.
pub const RELISTED: &str = "뺀 보안 키가 다시 들어 있음";
/// It lacks the removal.
pub const LACKS_REMOVAL: &str = "제거 기록이 빠짐";
/// Its authorizer is a key this PC removed (P4).
pub const REMOVED_AUTHORIZER: &str = "제거된 보안 키가 승인함";
/// A key both know has another record (slot pinning).
pub const SLOT_CHANGED: &str = "보안 키 기록이 바뀜";
/// A pair record this PC has, changed (pair-record pinning).
pub const PAIR_CHANGED: &str = "짝 기록이 바뀜";
/// A pair record of the touched key that does not open.
pub const PAIR_BROKEN: &str = "짝 기록이 손상됨";
/// A password change that keeps the password (E5), or another OTP flag.
pub const UNEXPLAINED: &str = "설명되지 않는 변경";
/// S-ANCHOR-RELIST-SK: a key file at login that lists live, or is
/// authorized by, a key this PC removed. It names no key.
pub const ANCHOR_RELIST_KEYS: &str = "이 열쇠 파일에는 이 PC에서 이미 뺀 보안 키가 들어 있거나, 그 키가 승인한 변경이 들어 있습니다. 예전 열쇠 파일로 되돌려졌거나 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC, 서버)을 쓰세요. 다른 PC의 열쇠 파일이라면 이 PC의 원래 열쇠 파일로 연 뒤 '새 열쇠 파일 받기'로 받으세요.";
/// A key file at login whose record of a key this PC knows changed in more
/// than its number and seed: no honest writer changes one.
pub const ANCHOR_PINNED: &str = "이 열쇠 파일의 보안 키 기록이 이 PC가 기록해 둔 것과 다릅니다. 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요.";
/// A key file at login whose OTP flag is not the one this PC recorded (E1,
/// spec §7.14): no writer changes it, so it is refused before any touch.
pub const ANCHOR_OTP: &str = "이 열쇠 파일의 OTP 설정이 이 PC가 기록해 둔 것과 다릅니다(설명되지 않는 변경). 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요.";
/// S-GATE-G2FAIL: a pick that is not exactly the removed keys, at an adopt.
pub const GATE_G2FAIL: &str = "고른 키가 받은 변경과 맞지 않아 받지 않았습니다. 이 변경은 이제 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력해야만 받을 수 있습니다. 키를 잃어버린 것이 확실하면 코드를 기다리지 말고 이 PC에서 '잃어버린 키 제거'를 하세요.";
/// S-GATE-G2FAIL-DISK: the same for a changed key file at login.
pub const GATE_G2FAIL_DISK: &str = "고른 키가 바뀐 열쇠 파일과 맞지 않아 받지 않았습니다. 이 열쇠 파일은 이제 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력해야만 받을 수 있습니다. 그런 변경을 한 적이 없다면 이전 열쇠 파일(열쇠 백업)로 바꿔 놓으세요. 그때까지 이 PC는 항목을 고치거나 저장하거나 올리지 않습니다.";
/// S-GATE-CODE-WRONG: a code that is not the file's; retries are allowed.
pub const GATE_CODE_WRONG: &str = "입력한 코드가 이 열쇠 파일과 맞지 않습니다. 다른 PC의 '열쇠 관리'에 지금 보이는 코드를 다시 확인하세요.";
/// S-TOFU-ADOPT: before G1, only a successor confirmed by its own code is
/// taken (round 4, finding 1).
pub const TOFU_ADOPT: &str = "이 PC는 이 금고의 열쇠 파일을 아직 확인하지 않았습니다. 확인 전에는 다른 PC의 열쇠 확인 코드로 확인하는 새 버전만 받을 수 있습니다. 먼저 이 PC의 열쇠 파일을 코드로 확인하거나, 새 열쇠 파일로 복원하세요.";
/// What an unconfirmed key file holds (spec §7.17): no edit, key change or
/// upload before G1.
pub const TOFU_HELD: &str = "이 PC는 이 열쇠 파일을 아직 확인하지 않았습니다. 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력하기 전에는 항목을 고치거나 열쇠를 바꾸거나 서버에 올리지 않습니다.";
/// What gate-pending mode holds (spec §5.2): a changed key file at login
/// whose gate has not passed.
pub const GATE_HELD: &str = "이 PC의 열쇠 파일이 바뀌었습니다. 잃어버린 키를 고르거나 다른 PC의 열쇠 확인 코드를 입력하기 전에는 항목을 고치거나 저장하거나 올리지 않습니다.";
/// A gate answer for a key file other than the one this session waits for.
pub const GATE_NOT_PENDING: &str =
    "확인할 열쇠 파일이 없거나 그 사이에 바뀌었습니다. 처음부터 다시 하세요.";

/// Which gate a change needs (spec §7.15a).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateKind {
    /// The user picks exactly the keys the change removes (S-LOSTPICK).
    G2,
    /// The key code another PC shows for the file (S-GATE-CODE).
    G1,
}

/// A key-file state as this PC knows it, for the gate: its live slots as
/// the anchor records them, its removals, magic and policy byte.
pub(super) struct Base {
    magic: [u8; 8],
    policy: u8,
    slots: Vec<Slot>,
    tombs: Vec<[u8; 16]>,
}
impl Base {
    /// The anchor's confirmed state (a changed key file at login).
    pub fn of_line(line: &VaultLine) -> Self {
        Self::of_state(&line.state)
    }
    fn of_state(s: &State) -> Self {
        Self {
            magic: s.magic,
            policy: s.policy,
            slots: s.slots.clone(),
            tombs: s.tombs.iter().map(|t| t.credhash).collect(),
        }
    }
    /// This PC's opened key file (a USB adopt).
    pub fn of_header(h: &KeyHeader) -> Self {
        Self {
            magic: *h.magic.bytes(),
            policy: h.flags,
            slots: h.slots.iter().map(anchor::slot_of).collect(),
            tombs: h.tombstones.iter().map(|t| t.credhash).collect(),
        }
    }
    /// A 0.8 key file of this PC (spec §4.5): its magic and OTP flag, as
    /// the anchor's line of a 0.8 state records them; no keys, no removals.
    pub fn of_legacy(own: &KeyFile) -> Option<Self> {
        Some(Self {
            magic: *own.magic()?.bytes(),
            policy: u8::from(own.uses_otp()),
            slots: Vec::new(),
            tombs: Vec::new(),
        })
    }
}

/// What a change makes of this PC's keys (spec §7.15a), over own → other as
/// a whole, never step by step. Credhashes, in the other file's order or
/// own's.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Gates {
    /// R: own live keys the file removes.
    pub removed: Vec<[u8; 16]>,
    /// Δ: live keys of the file this PC has neither live nor removed.
    pub added: Vec<[u8; 16]>,
    /// T_new: removals of keys this PC never knew.
    pub unknown: Vec<[u8; 16]>,
    /// M: own live keys the file lacks with no removal (carried, never a
    /// reason for a gate).
    pub kept: Vec<[u8; 16]>,
    /// The magic or the policy byte differs.
    pub policy: bool,
    /// A key both know has another number or seed.
    pub slot: bool,
    /// More than EPOCH_SILENT above the last state this PC wrote or
    /// confirmed, or no such state (round 3, finding 16).
    pub jump: bool,
}
impl Gates {
    /// The gate of `other` against `own`; `gated` is the confirmed line's
    /// `gated` epoch (None in a bootstrap). Err when a key both know has
    /// another record than its number and seed (slot pinning).
    pub(super) fn between(own: &Base, other: &KeyHeader, gated: Option<u64>) -> Result<Self> {
        let theirs: Vec<Slot> = other.slots.iter().map(anchor::slot_of).collect();
        let dead = |c: &[u8; 16]| other.tombstones.iter().any(|t| t.credhash == *c);
        let live = |c: &[u8; 16]| theirs.iter().any(|s| s.credhash == *c);
        let known =
            |c: &[u8; 16]| own.slots.iter().any(|s| s.credhash == *c) || own.tombs.contains(c);
        let mut slot = false;
        for a in &own.slots {
            if let Some(b) = theirs.iter().find(|b| b.credhash == a.credhash) {
                if a.idhash != b.idhash {
                    return Err(SLOT_CHANGED);
                }
                slot |= a.number != b.number || a.seedhash != b.seedhash;
            }
        }
        Ok(Self {
            removed: own
                .slots
                .iter()
                .map(|s| s.credhash)
                .filter(|c| dead(c))
                .collect(),
            added: theirs
                .iter()
                .map(|s| s.credhash)
                .filter(|c| !known(c))
                .collect(),
            unknown: other
                .tombstones
                .iter()
                .map(|t| t.credhash)
                .filter(|c| !known(c))
                .collect(),
            kept: own
                .slots
                .iter()
                .map(|s| s.credhash)
                .filter(|c| !live(c) && !dead(c))
                .collect(),
            // Security keys on or off, key-file sync, PIN mode; between two
            // password-only formats (0.8 and KF2) the magic is no policy.
            policy: own.policy != other.flags
                || (own.magic != *other.magic.bytes()
                    && (other.magic.hardware() || hardware(&own.magic))),
            slot,
            jump: gated.is_none_or(|g| other.epoch > g.saturating_add(EPOCH_SILENT)),
        })
    }
    /// The gate this change needs: G1 for an addition, a removal of a key
    /// this PC never knew, a policy or slot change and a silent jump; G2
    /// for removals of this PC's keys alone; none otherwise.
    pub fn needed(&self) -> Option<GateKind> {
        if !self.added.is_empty()
            || !self.unknown.is_empty()
            || self.policy
            || self.slot
            || self.jump
        {
            Some(GateKind::G1)
        } else if !self.removed.is_empty() {
            Some(GateKind::G2)
        } else {
            None
        }
    }
    /// G2 (spec §7.15a): the picked keys are exactly R, none twice. The
    /// caller asks G2 only where the change needs nothing more. Never tells
    /// how a pick differs.
    pub fn pick_matches(&self, pick: &[[u8; 16]]) -> bool {
        let mut pick = pick.to_vec();
        pick.sort_unstable();
        let mut removed = self.removed.clone();
        removed.sort_unstable();
        !removed.is_empty() && pick.windows(2).all(|w| w[0] != w[1]) && pick == removed
    }
}

/// Whether a magic is a security-key one (GOYOKH*, GOYOKS*).
fn hardware(magic: &[u8; 8]) -> bool {
    magic.starts_with(b"GOYOKH") || magic.starts_with(b"GOYOKS")
}
/// G1 (spec §7.15a): the typed code is the file's own key code, which only
/// a holder of its data key computes; compared in constant time.
pub fn code_matches(typed: &Code, vault_id: &[u8; 16], dk: &[u8; 32], state: KeyState) -> bool {
    ct_eq(&typed.0, &key_code(vault_id, dk, state).0)
}

/// Reads a key code as the user types it from another PC's screen: the 16
/// hex digits of `E{epoch} · XXXX-XXXX-XXXX-XXXX`, the epoch and separators
/// optional, either case. None for anything else.
pub fn parse_code(typed: &str) -> Option<Code> {
    let text = typed.trim();
    let text = match text.split_once('·') {
        Some((epoch, rest)) if epoch.trim().starts_with(['E', 'e']) => rest,
        Some(_) => return None,
        None => text,
    };
    let digits: Vec<u8> = text.bytes().filter(|b| !matches!(b, b'-' | b' ')).collect();
    if digits.len() != 16 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut code = [0; 8];
    for (i, byte) in code.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&digits[2 * i..2 * i + 2]).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(Code(code))
}

/// P3 (a) and P4 against the anchor (spec §5.10, at any epoch): a key the
/// confirmed state removed is live in `h`, or authorized it.
pub(super) fn relisted(h: &KeyHeader, c: &State) -> bool {
    let removed = |cred: &[u8; 16]| c.tombs.iter().any(|t| t.credhash == *cred);
    h.slots.iter().any(|s| removed(&s.credhash))
        || h.authorizer
            .and_then(|a| h.slots.get(usize::from(a)))
            .is_some_and(|s| removed(&s.credhash))
}

/// A key of S-LOSTPICK's list (spec §7.15a): this PC's own number and
/// registration day for one of its live keys; the credhash a pick names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GateChoice {
    pub number: u8,
    /// yyyymmdd.
    pub date: [u8; 8],
    pub credhash: [u8; 16],
}
/// The keys a pick offers: this PC's own live keys only, so nothing of the
/// change shows before its gate.
pub(super) fn choices(slots: &[Slot]) -> Vec<GateChoice> {
    slots
        .iter()
        .map(|s| GateChoice {
            number: s.number,
            date: s.date,
            credhash: s.credhash,
        })
        .collect()
}

/// What the public checks let through (spec §7.14, §5.8) besides a clean
/// file: removals of this PC that a fork's branch lacks, lists live or has
/// as its authorizer, each made since the fork; this PC's pair records the
/// file lacks (P_M, a carry); and the gate.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Checked {
    /// Own removals the other file lacks.
    pub lacking: Vec<[u8; 16]>,
    /// Own removals the other file lists live.
    pub relisted: Vec<[u8; 16]>,
    /// The other file's authorizer, when this PC removed it.
    pub removed_authorizer: Option<[u8; 16]>,
    /// Own pair records, by (owner, target), whose keys are live in the
    /// other file with the same seeds and that it lacks.
    pub missing_pairs: Vec<([u8; 16], [u8; 16])>,
    pub gates: Gates,
}
impl Checked {
    /// Every check passed unrelaxed.
    pub fn clean(&self) -> bool {
        self.lacking.is_empty() && self.relisted.is_empty() && self.removed_authorizer.is_none()
    }
}
/// The public checks of `other` against this PC's key file `own` and its
/// confirmed line (spec §7.14, §5.8), before any touch. A file that is no
/// `fork` is held to them all; for a fork, failures that concern only this
/// PC's removals made since the fork are reported, for the union to keep
/// them and fork option 1 to decide. Pair records are pinned for a file
/// `chained` under this PC's current data key. A 0.8 key file of this PC
/// has no keys, removals or records: only the gate applies to it, so a
/// file with keys is a policy change and every key in it Δ. Err: the
/// reason it is refused.
pub(super) fn public_checks(
    own: &KeyFile,
    line: Option<&VaultLine>,
    other: &KeyFile,
    fork: bool,
    chained: bool,
    gated: Option<u64>,
) -> std::result::Result<Checked, &'static str> {
    let Some(t) = other.header() else {
        return Err(UNEXPLAINED);
    };
    let o = own.header();
    let (o_tombs, base): (&[Tombstone], Base) = match o {
        Some(o) => (&o.tombstones, Base::of_header(o)),
        None => (&[], Base::of_legacy(own).ok_or(UNEXPLAINED)?),
    };
    // A removal made since the fork: the first state on this PC that
    // carried it holds a key the other branch never listed.
    let since_fork = |c: &[u8; 16]| {
        fork && line
            .and_then(|l| l.state.tombs.iter().find(|x| x.credhash == *c))
            .is_some_and(|x| x.keyid != [0; 4] && !t.key_ids.iter().any(|i| i[..4] == x.keyid))
    };
    let mut checked = Checked::default();
    // P3 (a).
    for s in &t.slots {
        if o_tombs.iter().any(|x| x.credhash == s.credhash) {
            if !since_fork(&s.credhash) {
                return Err(RELISTED);
            }
            checked.relisted.push(s.credhash);
        }
    }
    // P3 (b).
    for x in o_tombs {
        if !t.tombstones.iter().any(|y| y.credhash == x.credhash)
            && !checked.relisted.contains(&x.credhash)
        {
            if !since_fork(&x.credhash) {
                return Err(LACKS_REMOVAL);
            }
            checked.lacking.push(x.credhash);
        }
    }
    // P4: the authorizer is live, present and not suspended in the file
    // (the parse holds it to the via rules) and not removed here. Only fork
    // option 1 takes a file whose authorizer this PC removed since the
    // fork, and only a removal it took from another file (`t`): a removal
    // this PC's user made (`o`) is refused before any touch (spec §7.14,
    // §5.8, §14.10-5).
    if !t.slots.is_empty() {
        let a = t.authorizer.map(usize::from).ok_or(REMOVED_AUTHORIZER)?;
        let slot = t.slots.get(a).ok_or(REMOVED_AUTHORIZER)?;
        if (t.present >> a) & 1 == 0 || (t.suspended >> a) & 1 != 0 {
            return Err(REMOVED_AUTHORIZER);
        }
        if o_tombs.iter().any(|x| x.credhash == slot.credhash) {
            let taken = line
                .and_then(|l| l.state.tombs.iter().find(|x| x.credhash == slot.credhash))
                .is_some_and(|x| x.origin == anchor::Origin::Taken);
            if !since_fork(&slot.credhash) || !taken {
                return Err(REMOVED_AUTHORIZER);
            }
            checked.removed_authorizer = Some(slot.credhash);
        }
    }
    // Slot pinning, and the gate.
    checked.gates = Gates::between(&base, t, gated)?;
    // Pair-record pinning (a chained file), and the records it lacks.
    let seed = |h: Option<&KeyHeader>, c: &[u8; 16]| {
        h?.slots.iter().find(|s| s.credhash == *c).map(|s| s.seed)
    };
    let theirs = other.carried_pairs();
    let pbad = line.map(|l| l.state.pbad.clone()).unwrap_or_default();
    let index = |c: &[u8; 16]| t.slots.iter().position(|s| s.credhash == *c);
    let present = |c: &[u8; 16]| index(c).is_some_and(|j| (t.present >> j) & 1 != 0);
    let authorizer = t
        .authorizer
        .and_then(|a| t.slots.get(usize::from(a)))
        .map(|s| s.credhash);
    for p in own.carried_pairs() {
        let PairPlan::Copy {
            owner,
            target,
            wrap,
        } = p
        else {
            continue;
        };
        let same = |c: &[u8; 16]| seed(o, c).is_some() && seed(o, c) == seed(Some(t), c);
        if !(same(&owner) && same(&target)) {
            continue;
        }
        let found = theirs.iter().find_map(|q| match q {
            PairPlan::Copy {
                owner: a,
                target: b,
                wrap: w,
            } if *a == owner && *b == target => Some(w),
            _ => None,
        });
        let Some(w) = found else {
            checked.missing_pairs.push((owner, target));
            continue;
        };
        if !chained || ct_eq(w, &wrap) {
            continue;
        }
        // The three repairs pinning takes (round 3, findings 3, 15, 26;
        // round 4, finding 3): a record this PC found broken; one rewritten
        // with both its keys present by one of them; one its present owner
        // copied with the target absent.
        let broken = pbad.contains(&(anchor::prefix(&owner), anchor::prefix(&target)));
        let rewritten = authorizer.is_some_and(|a| a == owner || a == target)
            && present(&owner)
            && present(&target);
        let copied = authorizer == Some(owner) && present(&owner) && !present(&target);
        if !(broken || rewritten || copied) {
            return Err(PAIR_CHANGED);
        }
    }
    Ok(checked)
}
/// E5 (spec §7.14, §5.8): for a hardware key file of this PC, a file that
/// claims a password change but opens with this PC's password is refused.
/// `same`: the password that opened the other file is this PC's (the
/// Reauth verified it opens this PC's key file).
pub(super) fn e5(
    own: &KeyHeader,
    other: &KeyHeader,
    same: bool,
) -> std::result::Result<(), &'static str> {
    if own.magic.hardware() && !ct_eq(&own.pw_id, &other.pw_id) && same {
        return Err(UNEXPLAINED);
    }
    Ok(())
}

/// What a gate passed, bound to the file it was asked for (spec §5.8,
/// round 2, finding 8); built by the flow from the user's answer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GateAnswer {
    /// S-LOSTPICK: the picked keys' credhashes.
    Pick(Vec<[u8; 16]>),
    /// S-GATE-CODE: the typed code.
    Code(Code),
}

/// The gate of a changed key file at login, while gate-pending mode holds
/// (spec §5.2): K's state and the gate it needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct GateLogin {
    pub state: KeyState,
    pub kind: GateKind,
}
/// What an unlock in gate-pending mode or TOFU left for the pass (spec
/// §5.2 steps 8-9): the vault file re-save and the seal of a current one.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(super) struct Deferred {
    /// Step 8: the vault file is to be saved under the current key.
    pub resave: bool,
    /// The vault file read was current under K's current key: `vkey` and
    /// `consumed` once K is confirmed.
    pub seal: bool,
}

/// G2 is still allowed for this vault on this PC (spec §7.15a): no failed
/// pick since a gate last passed or the user started a key change.
pub(super) fn g2_allowed(lines: &Lines) -> bool {
    lines.gate.as_ref().is_none_or(|g| g.g2)
}
/// Records a failed pick for the file in `state` (S45-2 #8): `g2=off` in
/// the vault's gate line, a line that holds nothing when none was pending.
pub(super) fn g2_failed(lines: &mut Lines, state: KeyState, now: u64) {
    match lines.gate.as_mut() {
        Some(g) => g.g2 = false,
        None => {
            lines.gate = Some(GateLine {
                epoch: state.epoch,
                tag: state.tag,
                state: GateState::None,
                g2: false,
                since: now,
            })
        }
    }
}

impl Session {
    /// The gate a changed key file waits for at login (gate-pending mode,
    /// spec §5.2): G2 while it is allowed, else G1. None outside that mode.
    pub fn login_gate(&self) -> Option<GateKind> {
        let g = self.gate_login?;
        Some(match g.kind {
            GateKind::G2 if g2_allowed(&self.anchor.lines) && !self.g2_spent.get() => GateKind::G2,
            _ => GateKind::G1,
        })
    }
    /// The keys S-LOSTPICK offers in gate-pending mode: from the anchor's
    /// confirmed state, never the changed key file (spec §5.10 "Gate-pending
    /// mode shows only the anchor").
    pub fn gate_choices(&self) -> Vec<GateChoice> {
        self.anchor
            .lines
            .vault
            .as_ref()
            .map(|v| choices(&v.state.slots))
            .unwrap_or_default()
    }
    /// Whether this session is in gate-pending mode: no edit, no write and
    /// no upload until the changed key file's gate passes.
    pub fn gate_pending(&self) -> bool {
        self.gate_login.is_some()
    }
    /// Whether this session runs in TOFU (spec §7.17): the key file's state
    /// is not confirmed on this PC; no edit, key change or upload before G1.
    pub fn tofu(&self) -> bool {
        self.tofu
    }
    /// The refusal of an edit in TOFU or gate-pending mode, and in a held
    /// session whose confirmed line lacks `t` (spec §5.2 step 9(a)).
    pub(super) fn edit_held(&self) -> Result<()> {
        if self.gate_login.is_some() {
            return Err(GATE_HELD);
        }
        if self.fetched && !self.tofu {
            return Err(super::FETCHED_UNSAVED);
        }
        if self.unconfirmed() {
            return Err(TOFU_HELD);
        }
        Ok(())
    }
    /// TOFU's refusals apply: a TOFU session, or a held one whose key file
    /// state this PC never confirmed.
    pub(super) fn unconfirmed(&self) -> bool {
        self.tofu || self.held_unconfirmed || self.fetched
    }
    /// Passes the gate of a changed key file at login (spec §5.2, S45-1 #5):
    /// the answer is judged against the session's own key file and the
    /// anchor's confirmed state. A pass writes, in one locked rename, the
    /// confirmed line for the key file (with `t`, `gated` its epoch; the
    /// removals the line already had keep their origin, new ones are taken
    /// from the file), the vault file's seal when it was read current, and
    /// the gate line cleared; then the unlock's deferred re-save and the
    /// outgoing copy. A wrong pick turns G2 off for this vault
    /// (S-GATE-G2FAIL-DISK), for this session at once and in the anchor;
    /// when the anchor cannot be written, the error is the anchor's and G2
    /// stays off for the session. A wrong code may be typed again.
    pub fn pass_login_gate(&mut self, answer: GateAnswer) -> Result<()> {
        let g = self.gate_login.ok_or(GATE_NOT_PENDING)?;
        let h = self.key_file.header().cloned().ok_or(GATE_NOT_PENDING)?;
        if h.state() != g.state || self.key_state != g.state {
            return Err(GATE_NOT_PENDING);
        }
        let line = self.anchor.lines.vault.clone().ok_or(GATE_NOT_PENDING)?;
        let gated = (line.state.flags.t || !line.state.hardware()).then_some(line.state.gated);
        let gates = Gates::between(&Base::of_line(&line), &h, gated)?;
        match answer {
            GateAnswer::Pick(pick) => {
                if self.login_gate() != Some(GateKind::G2) {
                    return Err(GATE_NOT_PENDING);
                }
                if !gates.pick_matches(&pick) {
                    self.g2_spent.set(true);
                    let now = crate::otp::now()?;
                    self.anchor_strict(&mut |lines| {
                        g2_failed(lines, g.state, now);
                        true
                    })?;
                    return Err(GATE_G2FAIL_DISK);
                }
            }
            GateAnswer::Code(code) => {
                if !code_matches(&code, &self.id, self.keys.current(), g.state) {
                    return Err(GATE_CODE_WRONG);
                }
            }
        }
        // Step 2: K removed keys of this PC for a loss: the review is due,
        // in the merge log first (spec §5.2, §5.13).
        let review = match super::review::loss_of(&gates.removed, &h.tombstones) {
            Some(loss) => Some(self.review_store(&loss)?),
            None => None,
        };
        let deferred = self.deferred;
        let (state, current_id) = (g.state, h.current_key_id());
        self.anchor_strict(&mut |lines| {
            let mut v = anchor::line_of(&h, lines.vault.as_ref());
            v.state.flags.t = true;
            v.state.gated = state.epoch;
            if deferred.seal {
                v.vkey = Some(current_id);
                if h.resume != [0; 32] {
                    v.state.consumed = Some(h.resume);
                }
            }
            lines.vault = Some(v);
            lines.gate = None;
            if let Some(date) = &review {
                anchor::review_due(lines, date, state.epoch);
            }
            true
        })?;
        self.gate_login = None;
        self.tofu = false;
        self.g2_spent.set(false);
        // The server copy the gate held is judged again at the next poll,
        // against the key file now confirmed.
        self.relink();
        // The review holds the vault outgoing before anything is flushed.
        if let Some(date) = &review {
            self.review_now(date);
        }
        self.finish_deferred();
        Ok(())
    }
    /// The TOFU pass (spec §7.17), with the code another PC shows for this
    /// key file's state (G1), or with none after S-TOFU-NOPC's yes: the
    /// pending entry for this state with `t` (`src=tofu`), then the entry
    /// promoted to confirmed with `gated` = its epoch and its removals of
    /// unknown origin. After a forget the first rename also drops the
    /// vault's other lines. A 0.8 key file has no code: only S-TOFU-NOPC
    /// confirms it, as the 0.8 state.
    pub fn tofu_confirm(&mut self, code: Option<&Code>) -> Result<()> {
        // A key file from the server's key view is saved first (tofu_save).
        if !self.tofu || self.fetched {
            return Err(GATE_NOT_PENDING);
        }
        let h = self.key_file.header().cloned();
        if let Some(code) = code
            && (h.is_none() || !code_matches(code, &self.id, self.keys.current(), self.key_state))
        {
            return Err(GATE_CODE_WRONG);
        }
        let (state, deferred, forgotten) = (self.key_state, self.deferred, self.forgotten);
        let current = super::keyfile::key_id(&self.id, self.keys.current());
        let seal = |v: &mut VaultLine, resume: [u8; 32]| {
            if deferred.seal {
                v.vkey = Some(current);
                if resume != [0; 32] {
                    v.state.consumed = Some(resume);
                }
            }
        };
        match &h {
            Some(h) => {
                let mut p = anchor::pending_of(h, None, None, anchor::kpath_of(&self.key_path));
                (p.src, p.pw) = (anchor::Src::Tofu, None);
                p.state.flags.t = true;
                let mut made = None;
                self.anchor_strict(&mut |lines| {
                    let mut p = p.clone();
                    p.base = if forgotten {
                        (lines.vault, lines.gate, lines.forget) = (None, None, true);
                        None
                    } else {
                        lines.vault.as_ref().map(|c| (c.state.epoch, c.state.tag))
                    };
                    made = Some(p.clone());
                    lines.pending = Some(p);
                    true
                })?;
                let p = made.ok_or(AUTH_ERROR)?;
                let mut v = p.promoted(None);
                seal(&mut v, h.resume);
                self.anchor_strict(&mut |lines| {
                    if lines.pending.as_ref() == Some(&p) {
                        lines.pending = None;
                    }
                    lines.vault = Some(v.clone());
                    true
                })?;
            }
            None => {
                let magic = self.key_file.magic().ok_or(AUTH_ERROR)?;
                let mut v = anchor::legacy_line(state, magic, self.uses_otp(), &current, None);
                v.state.flags.t = true;
                seal(&mut v, [0; 32]);
                self.anchor_strict(&mut |lines| {
                    if forgotten {
                        (lines.pending, lines.gate, lines.forget) = (None, None, true);
                    }
                    lines.vault = Some(v.clone());
                    true
                })?;
            }
        }
        self.tofu = false;
        self.forgotten = false;
        self.g2_spent.set(false);
        self.finish_deferred();
        Ok(())
    }
    /// Steps 8 and 9 of the unlock that waited for the gate (spec §5.2):
    /// the vault file saved under the current key when it was due, and the
    /// outgoing copy.
    pub(super) fn finish_deferred(&mut self) {
        let deferred = std::mem::take(&mut self.deferred);
        if deferred.resave {
            match self.encode() {
                Ok(data) => {
                    if self.write(&data).is_err() && !self.gap_kept {
                        self.resave_due = true;
                        self.key_notices.push(KeyNotice::ResavePending);
                    }
                }
                Err(_) => self.resave_due = true,
            }
        }
        if let Some(link) = self.sync.as_mut() {
            link.mark_due();
        }
        self.flush_outgoing();
    }
}
