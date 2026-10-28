//! The security-key part of a KF2 key file (spec v3 §3.2-§3.4): the
//! per-key derivations from a key's hmac-secret output, the committing
//! wrap, pair records and S-wraps, and the seal and open of GOYOKH01 and
//! GOYOKS01 files. Only the security-key build compiles it; the strict
//! parse of these files is keyfile.rs's, the same in every build.
//!
//! Who can open what (invariant P-INV): an S-wrap of key j opens with
//! `self_j` or `IK(j←v)`, both functions of j's own output `H_j`; a pair
//! record `PR(o,t)` opens with `seal_o`, a function of `H_o`, and carries
//! `IK(t←o)`, a function of `H_t` that binds both keys' seeds. No third
//! key, no password, no data key and no server can produce either.
use super::{
    Bundle, KeyFile, KeyHeader, Magic, NOT_SEALED, Opened, SlotPublic, Spec, Tombstone, WRAP,
    failed_at_body, key_id, ks_id, need, sha256,
};
use crate::{
    crypto::{self, AUTH_ERROR, Key, Result, ct_eq, hkdf_expand, hkdf_extract},
    fido::{self, Touch},
    vault::refuse,
};
use subtle::{Choice, ConditionallySelectable};

/// An open of a security-key file without a touch.
pub const SECURITY_KEY_NEEDED: &str = "이 열쇠 파일은 보안 키가 필요합니다.";
/// S-SUSPENDED-KEY, filled with the key's number.
pub const SUSPENDED_KEY: &str = "보안 키 {N}은(는) 이 열쇠 파일에서 일시 정지되어 있습니다. 다른 보안 키로 연 뒤 '짝 맺기'로 이 키를 다시 쓰게 하세요.";
/// S-SUSPENDED-ORPHAN: suspended and owning no pair record, so no pairing
/// can bring it back.
pub const SUSPENDED_ORPHAN: &str = "보안 키 {N}은(는) 이 열쇠 파일에서 일시 정지되었고 짝 기록이 없어 다시 쓸 수 없습니다. 다른 보안 키로 연 뒤 이 키를 빼고 다시 등록하세요.";
/// S-AUTH-KEYS: what the app adds to AUTH_ERROR for a file with keys.
pub const AUTH_KEYS: &str = "비밀번호가 맞다면 이 보안 키가 초기화되었거나 PIN 설정이 바뀌었을 수 있습니다. 다른 등록 키로 열어 보세요.";
/// The size of an S-wrap: recipient, via and the wrap.
const S_WRAP: usize = 2 + WRAP;
/// The size of a pair record: owner, target, two reserved bytes, the wrap.
const PAIR: usize = 4 + WRAP;

/// Whether an open's error came before any secret was used (spec §3.4 step
/// 2, §8.7): the app starts no retry delay for it.
pub fn not_a_failure(e: &str) -> bool {
    [
        SECURITY_KEY_NEEDED,
        SUSPENDED_KEY,
        SUSPENDED_ORPHAN,
        fido::BAD_ANSWER,
        fido::UNVERIFIABLE,
        fido::SYNCED_PASSKEY,
        fido::TRANSPORT,
    ]
    .contains(&e)
}

/// The keyset secret S of a security-key file (spec §3.2). Never all zero,
/// so no such file can carry the password-only body key. Zeroized on drop.
pub struct Secret(Box<Key>);
impl Secret {
    /// A fresh S, for every authored write.
    pub fn random() -> Result<Self> {
        let mut s: Box<Key> = Box::default();
        crypto::random_into(s.as_mut_slice())?;
        assert!(!ct_eq(s.as_slice(), &[0; 32]), "a zero keyset secret");
        Ok(Self(s))
    }
    /// The S an open of a security-key file recovered (it checked it).
    pub fn of(opened: &Opened) -> Option<Self> {
        let s = opened.s.as_ref()?;
        (!ct_eq(s.as_slice(), &[0; 32])).then(|| Self(super::boxed(s)))
    }
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// The keyset part of the body key (spec §3.2): all zero without security
/// keys, S with them. A write with keys takes only `Keyset`, so nothing
/// falls back to zero under a hardware magic.
pub enum BodySecret<'a> {
    PasswordOnly,
    Keyset(&'a Secret),
}
impl BodySecret<'_> {
    pub(super) fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::PasswordOnly => &[0; 32],
            Self::Keyset(s) => s.bytes(),
        }
    }
}

/// `PRK_j` from key j's output.
fn key_root(h: &[u8; 32]) -> Box<Key> {
    hkdf_extract(b"goyo-vault/v2/key", &[h])
}
fn expand(prk: &[u8; 32], info: &[&[u8]]) -> Box<Key> {
    let mut out: Box<Key> = Box::default();
    hkdf_expand(prk, info, out.as_mut_slice());
    out
}
/// `self_j`: the base of j's S-wrap when j is touched in a write.
pub(crate) fn own_base(vault_id: &[u8; 16], slot: &SlotPublic, h: &[u8; 32]) -> Box<Key> {
    expand(
        &key_root(h),
        &[b"self\0", vault_id, &slot.credhash, &slot.seed],
    )
}
/// `seal_j`: the base of the pair records j owns.
pub(crate) fn pair_seal(vault_id: &[u8; 16], slot: &SlotPublic, h: &[u8; 32]) -> Box<Key> {
    expand(
        &key_root(h),
        &[b"pair-seal\0", vault_id, &slot.credhash, &slot.seed],
    )
}
/// `IK(target←writer)`, from the target's output: the writer never derives
/// it, it reads it from its pair record. Both seeds are bound, so a
/// re-seed of either key retires it (S45-2 #1).
pub(crate) fn inbox_key(
    vault_id: &[u8; 16],
    target: &SlotPublic,
    h_target: &[u8; 32],
    writer: &SlotPublic,
) -> Box<Key> {
    expand(
        &key_root(h_target),
        &[
            b"inbox\0",
            vault_id,
            &target.credhash,
            &target.seed,
            &writer.credhash,
            &writer.seed,
        ],
    )
}
/// `ctx_pr`: vault ID, both credhashes and both seeds; no index and no
/// epoch, so a record is carried unchanged while both keys stay.
fn pair_ctx(vault_id: &[u8; 16], owner: &SlotPublic, target: &SlotPublic) -> Vec<u8> {
    [
        &vault_id[..],
        &owner.credhash,
        &target.credhash,
        &owner.seed,
        &target.seed,
    ]
    .concat()
}
/// `ctx_sw`: vault ID, epoch, recipient, deliverer and `H(file[0 .. H))`.
fn wrap_ctx(
    vault_id: &[u8; 16],
    epoch: u64,
    recipient: &SlotPublic,
    via: &SlotPublic,
    head: &[u8; 32],
) -> Vec<u8> {
    [
        &vault_id[..],
        &epoch.to_le_bytes(),
        &recipient.credhash,
        &via.credhash,
        head,
    ]
    .concat()
}

/// The two uses of the committing wrap.
#[derive(Clone, Copy)]
enum Use {
    Pair,
    SWrap,
}
impl Use {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Pair => b"goyo-vault/v2/pair",
            Self::SWrap => b"goyo-vault/v2/s-wrap",
        }
    }
    fn aad(self, ctx: &[u8]) -> Vec<u8> {
        let label: &[u8] = match self {
            Self::Pair => b"goyo-vault/v2/pair-aad\0",
            Self::SWrap => b"goyo-vault/v2/s-wrap-aad\0",
        };
        [label, ctx].concat()
    }
}
/// A wrap's KEK and commitment.
fn wrap_keys(base: &[u8; 32], use_: Use, ctx: &[u8]) -> (Box<Key>, [u8; 32]) {
    let prk = hkdf_extract(use_.label(), &[base]);
    let kek = expand(&prk, &[b"key\0", ctx]);
    let mut commit = [0; 32];
    hkdf_expand(&prk, &[b"commit\0", ctx], &mut commit);
    (kek, commit)
}
/// `nonce ‖ C ‖ AEAD(KEK, nonce, AAD, plain)`, 104 bytes.
fn wrap_with(
    base: &[u8; 32],
    use_: Use,
    ctx: &[u8],
    plain: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<[u8; WRAP]> {
    let (kek, commit) = wrap_keys(base, use_, ctx);
    let sealed = crypto::seal(&kek, nonce, &use_.aad(ctx), plain)?;
    let mut out = [0; WRAP];
    out[..24].copy_from_slice(nonce);
    out[24..56].copy_from_slice(&commit);
    out[56..].copy_from_slice(&sealed);
    Ok(out)
}
fn wrap(base: &[u8; 32], use_: Use, ctx: &[u8], plain: &[u8; 32]) -> Result<[u8; WRAP]> {
    let nonce = crypto::random::<24>()?;
    wrap_with(base, use_, ctx, plain, &nonce)
}
/// The writer's unwrap: the commitment first, and the AEAD only when it
/// matches, so a wrong base fails deterministically before any AEAD.
fn unwrap(base: &[u8; 32], use_: Use, ctx: &[u8], record: &[u8]) -> Option<Box<Key>> {
    let (kek, commit) = wrap_keys(base, use_, ctx);
    #[cfg(test)]
    crypto::note(crypto::Event::WrapCommit);
    if !ct_eq(&commit, &record[24..56]) {
        return None;
    }
    aead(&kek, use_, ctx, record)
}
/// The reader's unwrap (an open, spec §3.4 step 4): the commitment check
/// and the AEAD both run whatever the first says, so every open does the
/// same work; any failure clears `ok` and gives zeros.
fn unwrap_read(base: &[u8; 32], use_: Use, ctx: &[u8], record: &[u8], ok: &mut Choice) -> Box<Key> {
    let (kek, commit) = wrap_keys(base, use_, ctx);
    #[cfg(test)]
    crypto::note(crypto::Event::WrapCommit);
    *ok &= Choice::from(u8::from(ct_eq(&commit, &record[24..56])));
    match aead(&kek, use_, ctx, record) {
        Some(plain) => plain,
        None => {
            *ok &= Choice::from(0);
            Box::default()
        }
    }
}
fn aead(kek: &[u8; 32], use_: Use, ctx: &[u8], record: &[u8]) -> Option<Box<Key>> {
    #[cfg(test)]
    crypto::note(crypto::Event::WrapAead);
    let nonce: &[u8; 24] = record[..24].try_into().ok()?;
    let plain = crypto::open(kek, nonce, &use_.aad(ctx), &record[56..]).ok()?;
    let plain: &[u8; 32] = plain.as_slice().try_into().ok()?;
    Some(super::boxed(plain))
}

impl KeyHeader {
    /// H: where the S-wraps start, the end of the pair records.
    fn h(&self) -> usize {
        self.w - S_WRAP * self.wraps.len()
    }
}
/// The wrap of the `i`-th pair record of a parsed file.
fn pair_wrap<'a>(bytes: &'a [u8], h: &KeyHeader, i: usize) -> &'a [u8] {
    let at = h.h() - PAIR * (h.pairs.len() - i) + 4;
    &bytes[at..at + WRAP]
}
/// The wrap of the `i`-th S-wrap of a parsed file.
fn s_wrap<'a>(bytes: &'a [u8], h: &KeyHeader, i: usize) -> &'a [u8] {
    let at = h.h() + S_WRAP * i + 2;
    &bytes[at..at + WRAP]
}

/// The output of a touch for slot `slot` of `h`, after the public checks
/// of spec §3.4 step 2: no secret is used, so none of them is an oracle.
pub(crate) fn touch_output<'t>(
    touch: &'t Touch,
    slot: &SlotPublic,
    h: &KeyHeader,
) -> Result<&'t [u8; 32]> {
    let output = touch
        .output_for(&slot.seed, &h.vault_id)
        .ok_or(fido::BAD_ANSWER)?;
    if ct_eq(output, &[0; 32]) {
        return Err(fido::BAD_ANSWER);
    }
    if touch.flags & fido::UP == 0 {
        return Err(fido::UNVERIFIABLE);
    }
    if touch.flags & (fido::BE | fido::BS) != 0 {
        return Err(fido::SYNCED_PASSKEY);
    }
    if touch
        .transport
        .is_some_and(|t| !matches!(t, fido::USB | fido::NFC))
    {
        return Err(fido::TRANSPORT);
    }
    if touch.uv != (slot.flags & 1 != 0) || (h.pin() && !touch.uv) {
        return Err(fido::UV_CHANGED);
    }
    Ok(output)
}

/// Spec §3.4 for a file with security keys. The public checks first (a
/// touch, of a live key that is not suspended, with a sound answer), then
/// one Argon2 always, one S-wrap commitment check and one S-wrap AEAD
/// always, then the body under S, or under zeros when anything failed: a
/// wrong password and a wrong key end at the same step with the same error
/// and the same work.
pub(super) fn open(
    file: &KeyFile,
    h: &KeyHeader,
    password: &str,
    touch: Option<&Touch>,
) -> Result<Opened> {
    let touch = touch.ok_or(SECURITY_KEY_NEEDED)?;
    let j = h
        .slots
        .iter()
        .position(|s| s.cred_id == touch.cred_id)
        .ok_or(fido::NOT_REGISTERED)?;
    let slot = &h.slots[j];
    if (h.suspended >> j) & 1 != 0 {
        let owns = h.pairs.iter().any(|(o, _)| usize::from(*o) == j);
        let text = if owns {
            SUSPENDED_KEY
        } else {
            SUSPENDED_ORPHAN
        };
        return Err(refuse(text, vec![slot.number.to_string()]));
    }
    let output = touch_output(touch, slot, h)?;
    // Step 3.
    let bytes = file.bytes();
    let salt: &[u8; 32] = bytes[h.w + 32..h.w + 64]
        .try_into()
        .map_err(|_| AUTH_ERROR)?;
    let pw_key = crypto::derive(password.as_bytes(), salt)?;
    // Step 4: the parse placed exactly one S-wrap for j.
    let i = h
        .wraps
        .iter()
        .position(|(r, _)| usize::from(*r) == j)
        .ok_or(AUTH_ERROR)?;
    let via = &h.slots[usize::from(h.wraps[i].1)];
    let base = if usize::from(h.wraps[i].1) == j {
        own_base(&h.vault_id, slot, output)
    } else {
        inbox_key(&h.vault_id, slot, output, via)
    };
    let ctx = wrap_ctx(&h.vault_id, h.epoch, slot, via, &sha256(&[&bytes[..h.h()]]));
    let mut ok = Choice::from(1);
    let s = unwrap_read(&base, Use::SWrap, &ctx, s_wrap(bytes, h, i), &mut ok);
    ok &= Choice::from(u8::from(ct_eq(&ks_id(&h.vault_id, &s), &h.ks_id)));
    ok &= !Choice::from(u8::from(ct_eq(s.as_slice(), &[0; 32])));
    // S' = S when every check passed, else zeros: the body then fails its
    // commitment like a wrong password's.
    let mut kept: Box<Key> = Box::default();
    for (out, byte) in kept.iter_mut().zip(s.iter()) {
        *out = u8::conditional_select(&0, byte, ok);
    }
    // Step 5: whatever came before, and a body that somehow opens under
    // zeros (sealed so by someone with the password) still fails.
    let ok = bool::from(ok);
    let mut opened = failed_at_body(file.body(h, &pw_key, &kept).and_then(|o| {
        need(ok)?;
        Ok(o)
    }))?;
    opened.slot = Some(j as u8);
    opened.s = Some(kept);
    Ok(opened)
}

/// The read-back of a file `seal` just wrote with keys (spec §5.5 W10, the
/// writer's part): every S-wrap opens with the base it was made with and
/// gives the writer's S, and the body opens with the writer's factors, with
/// no second Argon2 and no touch.
pub(super) fn open_written(
    file: &KeyFile,
    h: &KeyHeader,
    w: &super::WriterSecrets,
) -> Result<Opened> {
    let written = w.keys.as_ref().ok_or(AUTH_ERROR)?;
    let bytes = file.bytes();
    let head = sha256(&[&bytes[..h.h()]]);
    let mut ok = ct_eq(&ks_id(&h.vault_id, written.s.bytes()), &h.ks_id);
    let bases = written.bases.as_deref().unwrap_or_default();
    ok &= written.bases.is_none() || bases.len() == h.wraps.len();
    for (i, (r, v)) in h.wraps.iter().enumerate() {
        if written.bases.is_none() {
            break;
        }
        let Some((_, base)) = bases.iter().find(|(j, _)| j == r) else {
            ok = false;
            continue;
        };
        let (r, v) = (&h.slots[usize::from(*r)], &h.slots[usize::from(*v)]);
        let ctx = wrap_ctx(&h.vault_id, h.epoch, r, v, &head);
        ok &= unwrap(base, Use::SWrap, &ctx, s_wrap(bytes, h, i))
            .is_some_and(|s| ct_eq(s.as_slice(), written.s.bytes()));
    }
    need(ok)?;
    let mut opened = failed_at_body(file.body(h, &w.pw_key, written.s.bytes()))?;
    opened.s = Some(super::boxed(written.s.bytes()));
    Ok(opened)
}

/// W10 of spec §5.5 for a file `seal` just wrote from `plan`: every S-wrap
/// opens to the plan's S with a base derived again here, through each
/// present key's own output or the inbox key W4 opened for an absent one
/// (never the base the writer recorded); every new pair record opens with
/// its owner's `seal` around the inbox key its target's output gives; every
/// carried one is the source's wrap byte for byte; and the body opens with
/// the writer's factors. No Argon2, no touch.
pub(super) fn verify(
    file: &KeyFile,
    h: &KeyHeader,
    w: &super::WriterSecrets,
    plan: &KeysPlan,
) -> Result<Opened> {
    let bytes = file.bytes();
    let id = &h.vault_id;
    let s = plan.s.bytes();
    let head = sha256(&[&bytes[..h.h()]]);
    let mut ok = ct_eq(&ks_id(id, s), &h.ks_id)
        && h.slots == plan.slots
        && h.pairs.len() == plan.pairs.len();
    for (i, (r, v)) in h.wraps.iter().enumerate() {
        let (j, v) = (usize::from(*r), usize::from(*v));
        let base = if v == j {
            plan.output(j).map(|out| own_base(id, &h.slots[j], out))
        } else {
            let ik = plan.inbox.iter().find(|(t, _)| usize::from(*t) == j);
            ik.map(|(_, ik)| super::boxed(ik))
        };
        let Some(base) = base else {
            ok = false;
            continue;
        };
        let ctx = wrap_ctx(id, h.epoch, &h.slots[j], &h.slots[v], &head);
        ok &= unwrap(&base, Use::SWrap, &ctx, s_wrap(bytes, h, i))
            .is_some_and(|got| ct_eq(got.as_slice(), s));
    }
    for (i, (o, t)) in h.pairs.iter().enumerate() {
        let (o, t) = (usize::from(*o), usize::from(*t));
        let (owner, target) = (&h.slots[o], &h.slots[t]);
        let record = pair_wrap(bytes, h, i);
        match plan
            .pairs
            .iter()
            .find(|p| p.keys() == (owner.credhash, target.credhash))
        {
            Some(PairPlan::Copy { wrap, .. }) => ok &= ct_eq(wrap, record),
            Some(PairPlan::New { .. }) => {
                let (Some(h_o), Some(h_t)) = (plan.output(o), plan.output(t)) else {
                    ok = false;
                    continue;
                };
                let want = inbox_key(id, target, h_t, owner);
                let ctx = pair_ctx(id, owner, target);
                ok &= unwrap(&pair_seal(id, owner, h_o), Use::Pair, &ctx, record)
                    .is_some_and(|ik| ct_eq(ik.as_slice(), want.as_slice()));
            }
            None => ok = false,
        }
    }
    need(ok)?;
    let mut opened = failed_at_body(file.body(h, &w.pw_key, s))?;
    opened.s = Some(super::boxed(s));
    Ok(opened)
}

/// What a test makes `head` write wrong, once (spec §14.4-7): the S-wrap
/// of the first present key, or of the first absent one, under another
/// base, or the first new pair record around another inbox key.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Fault {
    PresentBase,
    AbsentBase,
    PairValue,
}
#[cfg(test)]
thread_local! {
    pub(crate) static FAULT: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
}
/// Whether a test asked for `fault` here; it fires once.
fn faulty(fault: &'static str) -> bool {
    #[cfg(test)]
    {
        let want = match fault {
            "present" => Fault::PresentBase,
            "absent" => Fault::AbsentBase,
            _ => Fault::PairValue,
        };
        if FAULT.with(|f| f.get()) == Some(want) {
            FAULT.with(|f| f.set(None));
            return true;
        }
    }
    let _ = fault;
    false
}

/// A pair record of a write (spec §3.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PairPlan {
    /// Carried from the verified source file: its wrap verbatim, under the
    /// owner's and the target's indexes in the new file's slot order.
    Copy {
        owner: [u8; 16],
        target: [u8; 16],
        wrap: [u8; WRAP],
    },
    /// Made in this write; both keys are present.
    New { owner: [u8; 16], target: [u8; 16] },
}
impl PairPlan {
    fn keys(&self) -> ([u8; 16], [u8; 16]) {
        match self {
            Self::Copy { owner, target, .. } | Self::New { owner, target } => (*owner, *target),
        }
    }
}
/// What a write with security keys seals (spec §3.3 `Keys`).
pub struct KeysPlan<'a> {
    /// GOYOKS01 (key-file sync on) instead of GOYOKH01.
    pub sync: bool,
    /// PIN mode: every slot a PIN slot.
    pub pin: bool,
    /// Fresh for every authored write.
    pub s: &'a Secret,
    /// The live keys, ascending by number.
    pub slots: Vec<SlotPublic>,
    /// The slot index of the key that authorized the write.
    pub authorizer: u8,
    /// Bit i: slot i touched in this write. Bit i of `suspended`: live
    /// with no S-wrap.
    pub present: u8,
    pub suspended: u8,
    pub pairs: Vec<PairPlan>,
    /// The output of every present key for its seed, by slot index.
    pub outputs: Vec<(u8, &'a [u8; 32])>,
    /// `IK(j←authorizer)` of every absent, live key that is not suspended,
    /// by slot index, as `open_pairs` read it from the source file.
    pub inbox: Vec<(u8, &'a [u8; 32])>,
}
impl KeysPlan<'_> {
    fn output(&self, j: usize) -> Option<&[u8; 32]> {
        let mut found = self.outputs.iter().filter(|(i, _)| usize::from(*i) == j);
        match (found.next(), found.next()) {
            (Some((_, h)), None) => Some(h),
            _ => None,
        }
    }
    fn index(&self, credhash: &[u8; 16]) -> Option<usize> {
        self.slots.iter().position(|s| s.credhash == *credhash)
    }
}
/// What a write with keys knows of its own file: S and every S-wrap's
/// base, for the read-back. Zeroized on drop.
pub(super) struct Written {
    s: Secret,
    /// None for a re-seal, whose S-wraps came byte for byte from a file
    /// that opened with this S.
    bases: Option<Vec<(u8, Box<Key>)>>,
}
impl Written {
    pub(super) fn copied(s: &[u8; 32]) -> Self {
        Self {
            s: Secret(super::boxed(s)),
            bases: None,
        }
    }
}

/// Refuses a plan the strict parse would refuse or that lacks a factor,
/// before any draw or Argon2.
pub(super) fn check(plan: &KeysPlan) -> Result<()> {
    let sealable = |ok: bool| if ok { Ok(()) } else { Err(NOT_SEALED) };
    let n = plan.slots.len();
    sealable((1..=8).contains(&n))?;
    let all = ((1u16 << n) - 1) as u8;
    sealable(
        plan.present & !all == 0
            && plan.suspended & !all == 0
            && plan.present & plan.suspended == 0
            && usize::from(plan.authorizer) < n
            && (plan.present >> plan.authorizer) & 1 != 0
            && plan
                .slots
                .iter()
                .all(|s| s.credhash == super::credhash(&s.cred_id)),
    )?;
    for j in 0..n {
        let present = (plan.present >> j) & 1 != 0;
        let suspended = (plan.suspended >> j) & 1 != 0;
        sealable(present == plan.output(j).is_some())?;
        let inbox = plan
            .inbox
            .iter()
            .filter(|(i, _)| usize::from(*i) == j)
            .count();
        sealable(inbox == usize::from(!present && !suspended))?;
    }
    for pair in &plan.pairs {
        let (owner, target) = pair.keys();
        let (o, t) = (plan.index(&owner), plan.index(&target));
        sealable(o.is_some() && t.is_some() && o != t)?;
        if let PairPlan::New { .. } = pair {
            sealable(
                plan.output(o.unwrap_or(0)).is_some() && plan.output(t.unwrap_or(0)).is_some(),
            )?;
        }
    }
    Ok(())
}
/// Steps 2 and 3 of spec §3.3 for a file with keys: `[0, W)`, with the
/// nonce of every new pair record drawn in file order, then of every
/// S-wrap in slot order. No S-wrap is made before `[0, H)` is complete.
pub(super) fn head(
    spec: &Spec,
    bundle: &Bundle,
    plan: &KeysPlan,
    written: u64,
) -> Result<(Vec<u8>, Written)> {
    let id = &spec.vault_id;
    let magic = if plan.sync { Magic::Ks01 } else { Magic::Kh01 };
    let mut tombstones = spec.tombstones.clone();
    tombstones.sort_unstable_by_key(Tombstone::order);
    let mut pairs: Vec<(u8, u8, &PairPlan)> = Vec::with_capacity(plan.pairs.len());
    for pair in &plan.pairs {
        let (owner, target) = pair.keys();
        let o = plan.index(&owner).ok_or(NOT_SEALED)?;
        let t = plan.index(&target).ok_or(NOT_SEALED)?;
        pairs.push((o as u8, t as u8, pair));
    }
    pairs.sort_unstable_by_key(|(o, t, _)| (*o, *t));
    let otp = bundle.otp().is_some();
    let mut out = Vec::new();
    out.extend_from_slice(magic.bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&spec.epoch.to_le_bytes());
    out.extend_from_slice(&[
        u8::from(otp) | u8::from(plan.pin) << 1,
        bundle.keys().len() as u8,
        plan.slots.len() as u8,
        spec.next,
    ]);
    out.extend_from_slice(&(tombstones.len() as u16).to_le_bytes());
    out.extend_from_slice(&[
        spec.kind as u8,
        plan.authorizer,
        plan.present,
        plan.suspended,
        pairs.len() as u8,
        0,
        0,
        0,
        0,
        0,
    ]);
    out.extend_from_slice(&ks_id(id, plan.s.bytes()));
    out.extend_from_slice(&spec.pw_id);
    out.extend_from_slice(&written.to_le_bytes());
    out.extend_from_slice(&spec.loss.to_le_bytes());
    for key in bundle.keys() {
        out.extend_from_slice(&key_id(id, key));
    }
    for t in &tombstones {
        out.extend_from_slice(&t.credhash);
        out.extend_from_slice(&t.removed.to_le_bytes());
    }
    for s in &plan.slots {
        out.extend_from_slice(&[1, s.flags, s.number, 0]);
        out.extend_from_slice(&s.registered.to_le_bytes());
        out.extend_from_slice(&s.added_epoch.to_le_bytes());
        out.extend_from_slice(&s.added_by);
        out.extend_from_slice(&s.seed);
        out.extend_from_slice(&(s.cred_id.len() as u16).to_le_bytes());
        out.extend_from_slice(&s.cred_id);
    }
    for (o, t, pair) in pairs {
        out.extend_from_slice(&[o, t, 0, 0]);
        let record = match pair {
            PairPlan::Copy { wrap, .. } => *wrap,
            PairPlan::New { .. } => {
                let (owner, target) = (&plan.slots[usize::from(o)], &plan.slots[usize::from(t)]);
                let h_o = plan.output(usize::from(o)).ok_or(NOT_SEALED)?;
                let h_t = plan.output(usize::from(t)).ok_or(NOT_SEALED)?;
                let mut ik = inbox_key(id, target, h_t, owner);
                if faulty("pair") {
                    ik[0] ^= 1;
                }
                let ctx = pair_ctx(id, owner, target);
                wrap(&pair_seal(id, owner, h_o), Use::Pair, &ctx, &ik)?
            }
        };
        out.extend_from_slice(&record);
    }
    // Step 3: [0, H) is complete; every S-wrap binds it.
    let head = sha256(&[&out]);
    let a = usize::from(plan.authorizer);
    let mut bases = Vec::with_capacity(plan.slots.len());
    for (j, slot) in plan.slots.iter().enumerate() {
        if (plan.suspended >> j) & 1 != 0 {
            continue;
        }
        let present = (plan.present >> j) & 1 != 0;
        let (via, mut base) = if present {
            let h_j = plan.output(j).ok_or(NOT_SEALED)?;
            (j, own_base(id, slot, h_j))
        } else {
            let ik = plan.inbox.iter().find(|(i, _)| usize::from(*i) == j);
            (a, super::boxed(ik.ok_or(NOT_SEALED)?.1))
        };
        if faulty(if present { "present" } else { "absent" }) {
            base[0] ^= 1;
        }
        let ctx = wrap_ctx(id, spec.epoch, slot, &plan.slots[via], &head);
        out.extend_from_slice(&[j as u8, via as u8]);
        out.extend_from_slice(&wrap(&base, Use::SWrap, &ctx, plan.s.bytes())?);
        bases.push((j as u8, base));
    }
    let s = Secret(super::boxed(plan.s.bytes()));
    let bases = Some(bases);
    Ok((out, Written { s, bases }))
}

impl KeyFile {
    /// W10 for a file with keys that `seal` wrote from `plan` with the
    /// factors `w` (see `verify`). Anything else is AUTH_ERROR.
    pub fn verify_keys(&self, w: &super::WriterSecrets, plan: &KeysPlan) -> Result<Opened> {
        match self.header() {
            Some(h) if !h.slots.is_empty() => verify(self, h, w, plan),
            _ => Err(AUTH_ERROR),
        }
    }
    /// S, from the S-wrap of slot `j` opened with that key's output `h_j`
    /// (the writer's unwrap: the commitment first): what proves a pairing
    /// or re-seed touch (spec §8.3). None when it does not open, or `j` has
    /// no S-wrap.
    pub fn open_own(&self, j: usize, h_j: &[u8; 32]) -> Option<Box<Key>> {
        let h = self.header()?;
        let i = h.wraps.iter().position(|(r, _)| usize::from(*r) == j)?;
        let v = usize::from(h.wraps[i].1);
        let slot = &h.slots[j];
        let base = if v == j {
            own_base(&h.vault_id, slot, h_j)
        } else {
            inbox_key(&h.vault_id, slot, h_j, &h.slots[v])
        };
        let head = sha256(&[&self.bytes()[..h.h()]]);
        let ctx = wrap_ctx(&h.vault_id, h.epoch, slot, &h.slots[v], &head);
        let s = unwrap(&base, Use::SWrap, &ctx, s_wrap(self.bytes(), h, i))?;
        ct_eq(&ks_id(&h.vault_id, &s), &h.ks_id).then_some(s)
    }
    /// Opens every pair record `PR(o, t)` with `seal_o`, from key o's output
    /// `h_o` (spec §3.4): `(t, IK(t←o))` for each, None for a record that
    /// does not open, which makes t unreachable from o (spec §5.5 W6) and
    /// never fails a read. Writers only; empty for a password-only file.
    pub fn open_pairs(&self, h_o: &[u8; 32], o: u8) -> Vec<(u8, Option<Box<Key>>)> {
        let Some(h) = self.header() else {
            return Vec::new();
        };
        let Some(owner) = h.slots.get(usize::from(o)) else {
            return Vec::new();
        };
        let seal = pair_seal(&h.vault_id, owner, h_o);
        h.pairs
            .iter()
            .enumerate()
            .filter(|(_, (owner, _))| *owner == o)
            .map(|(i, (_, t))| {
                let ctx = pair_ctx(&h.vault_id, owner, &h.slots[usize::from(*t)]);
                (
                    *t,
                    unwrap(&seal, Use::Pair, &ctx, pair_wrap(self.bytes(), h, i)),
                )
            })
            .collect()
    }
    /// The S-wrap at index `i` opened with any 32-byte `base` in place of its
    /// recipient's: what the removed-key simulator tries (spec §14.10-5).
    #[cfg(test)]
    pub(crate) fn open_s_wrap_with(&self, i: usize, base: &[u8; 32]) -> Option<Box<Key>> {
        let h = self.header()?;
        let (j, v) = *h.wraps.get(i)?;
        let (j, v) = (h.slots.get(usize::from(j))?, h.slots.get(usize::from(v))?);
        let head = sha256(&[&self.bytes()[..h.h()]]);
        let ctx = wrap_ctx(&h.vault_id, h.epoch, j, v, &head);
        unwrap(base, Use::SWrap, &ctx, s_wrap(self.bytes(), h, i))
    }
    /// Every pair record of this file as a record to carry (spec §3.3).
    pub fn carried_pairs(&self) -> Vec<PairPlan> {
        let Some(h) = self.header() else {
            return Vec::new();
        };
        h.pairs
            .iter()
            .enumerate()
            .map(|(i, (o, t))| {
                let mut wrap = [0; WRAP];
                wrap.copy_from_slice(pair_wrap(self.bytes(), h, i));
                PairPlan::Copy {
                    owner: h.slots[usize::from(*o)].credhash,
                    target: h.slots[usize::from(*t)].credhash,
                    wrap,
                }
            })
            .collect()
    }
}

/// Opens one pair record's wrap `PR(owner, target)` with the owner's output
/// `h_o` (the writer's unwrap): `IK(target←owner)`, or None. A record binds
/// both keys' credhashes and seeds but no index and no file, so a union
/// opens a record carried from either file under the slots it keeps.
pub(crate) fn open_record(
    vault_id: &[u8; 16],
    owner: &SlotPublic,
    target: &SlotPublic,
    h_o: &[u8; 32],
    wrap: &[u8; WRAP],
) -> Option<Box<Key>> {
    let ctx = pair_ctx(vault_id, owner, target);
    unwrap(&pair_seal(vault_id, owner, h_o), Use::Pair, &ctx, wrap)
}

/// The security-key vectors of spec §14.1-2, pinned from an independent
/// Python implementation (hashlib and hmac; the AEAD of
/// scripts/make_key_fixtures.py): `PRK`, `self`, `seal`, `IK` for two
/// ordered pairs and a third whose only change is the writer's seed, `Wrap`
/// for both uses (KEK, C, AAD), and a pair record and an S-wrap with fixed
/// nonces. No Argon2.
pub(crate) fn self_test() -> bool {
    fn seq<const N: usize>(start: u8) -> [u8; N] {
        std::array::from_fn(|i| start.wrapping_add(i as u8))
    }
    let mut ok = Choice::from(1);
    let mut check = |got: &[u8], want: &str| {
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        ok &= Choice::from(u8::from(ct_eq(hex.as_bytes(), want.as_bytes())));
    };
    let id: [u8; 16] = seq(0x00);
    let (h_a, h_b): ([u8; 32], [u8; 32]) = (seq(0x90), seq(0xb0));
    let a = SlotPublic::new(0, 1, 0, 1, [0; 16], seq(0x20), seq::<48>(0x80).to_vec());
    let b = SlotPublic::new(0, 2, 0, 1, [0; 16], seq(0x50), seq::<20>(0xc0).to_vec());
    let a2 = SlotPublic {
        seed: seq(0x21),
        ..a.clone()
    };
    check(
        key_root(&h_a).as_slice(),
        "132e503d21d32ddee5d0b21a2829025802a07568573f296f1eec0e9cc4a1d139",
    );
    check(
        own_base(&id, &a, &h_a).as_slice(),
        "0a035a628d7b7bfd95026b11e33e310ddaad6d4e474a8c40728cd10770fa21bf",
    );
    let seal_a = pair_seal(&id, &a, &h_a);
    check(
        seal_a.as_slice(),
        "f0d9456c2141ecdbb41e7e1f87fbc4386c39e4a697bb83336453e11c6b63de98",
    );
    let ik = inbox_key(&id, &b, &h_b, &a);
    check(
        ik.as_slice(),
        "a96407b839b1e09e4d256099ac361b64cafa49426e3db636f214908acd968519",
    );
    check(
        inbox_key(&id, &a, &h_a, &b).as_slice(),
        "aa1434b99cd1312f14d57775f33009815291d67c1f552bdf760c2a057ec4e3a7",
    );
    check(
        inbox_key(&id, &b, &h_b, &a2).as_slice(),
        "84f30bf1057dde4c145a64936eaa1dbb48d6a2ddb76cca01c4c7e41480aa609e",
    );
    let ctx = pair_ctx(&id, &a, &b);
    let (kek, commit) = wrap_keys(&seal_a, Use::Pair, &ctx);
    check(
        kek.as_slice(),
        "c91ef27c687f8ef5970ede4dd93819006c442ab0723aa866de10339475624502",
    );
    check(
        &commit,
        "6727bd3911abbeded6af068cd368033030c7d19728f8e77824c8a612ec2efc36",
    );
    check(
        &sha256(&[&Use::Pair.aad(&ctx)]),
        "aac52af3caa83ed9f59961529b1306f44d5f31dbdc4fae783f1400d925117d9a",
    );
    match wrap_with(&seal_a, Use::Pair, &ctx, &ik, &seq(0x70)) {
        Ok(record) => check(
            &record,
            "707172737475767778797a7b7c7d7e7f80818283848586876727bd3911abbeded6af068cd368033030c7d19728f8e77824c8a612ec2efc36b3dd27f6f84705792421d987d1a3c1380c6e5069767af936f16691d94a60446cbf525ff8ac808050894bdcd857f85052",
        ),
        Err(_) => check(b"", "sealed"),
    }
    let head = sha256(&[b"goyo self-test: file[0..H)"]);
    let ctx = wrap_ctx(&id, 7, &b, &a, &head);
    let (kek, commit) = wrap_keys(&ik, Use::SWrap, &ctx);
    check(
        kek.as_slice(),
        "0232aa5c08ad15bdd4214a1294def7d1700c4aa2dd0e02513e115f011586f55a",
    );
    check(
        &commit,
        "4b6ced517a0716da357fcde4e425ea1e5747cc3ad38e3247ac960535d55d02d0",
    );
    check(
        &sha256(&[&Use::SWrap.aad(&ctx)]),
        "ffe710d1f70b8ffa06009a5c1e050a19678c8b21954fd3c7d1a2524636d03415",
    );
    match wrap_with(&ik, Use::SWrap, &ctx, &seq(0xd0), &seq(0x78)) {
        Ok(record) => check(
            &record,
            "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f4b6ced517a0716da357fcde4e425ea1e5747cc3ad38e3247ac960535d55d02d0433f4be87ad869c2b419fdc8d864b82528148fb64da3981434ec34492a01dd8717914c3b8f2573fa06cf2fb7e9e8ddae",
        ),
        Err(_) => check(b"", "sealed"),
    }
    bool::from(ok)
}

#[cfg(test)]
pub(in crate::vault) mod tests {
    use super::super::{
        BODY_AEADS, FAILED_AT, Kind, NEWER_KEY_FORMAT, Plan, SECURITY_KEY_FIXTURES, Step,
        TOO_LARGE, body_keys, chain_mac, credhash, key_code, ks_id_zero, never_replaced, parse,
        seal,
        tests::{kh, ks},
    };
    use super::*;
    use crate::{
        crypto::{
            Event, KdfProfile, derive_count, queue_random, queued_random, set_kdf_profile,
            set_test_now, take_events,
        },
        fido::{AssertRequest, Authenticator, check_assertion, fake::Fake, salt},
        vault::refusal_values,
    };
    use std::path::Path;

    const WRITTEN: u64 = 1_767_225_600;
    const DAY: u64 = 86_400;
    /// The day of the recorded loss (2025-12-31) as a tombstone's loss mark.
    const LOSS: u64 = 1_767_139_200;
    const LOSS_MARK: u64 = LOSS / DAY + 2;

    fn seq<const N: usize>(start: u8) -> [u8; N] {
        std::array::from_fn(|i| start.wrapping_add(i as u8))
    }
    fn run(start: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| start.wrapping_add(i as u8)).collect()
    }
    fn mixed<const N: usize>(byte: u8) -> [u8; N] {
        std::array::from_fn(|i| byte ^ i as u8)
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn file(bytes: &[u8]) -> Result<KeyFile> {
        KeyFile::from_bytes(Path::new("test.goyokey"), bytes.to_vec())
    }
    fn take_failed_at() -> Option<Step> {
        FAILED_AT.with(|s| s.take())
    }
    fn body_aeads() -> u32 {
        BODY_AEADS.with(std::cell::Cell::get)
    }

    /// A registered key of a pinned fixture, as hw_fixtures.json records it:
    /// its slot record and the fake authenticator behind it.
    struct RecordedKey {
        number: u8,
        flags: u8,
        added_epoch: u64,
        added_by: Option<usize>,
        seed: [u8; 32],
        cred_id: Vec<u8>,
        random_uv: [u8; 32],
        random_nouv: [u8; 32],
        registered: u64,
    }
    /// A GOYOKH01 or GOYOKS01 that scripts/make_key_fixtures.py wrote, and
    /// every value it derives from (hw_fixtures.json), built from the same
    /// seq/mixed patterns as there.
    pub(in crate::vault) struct Recorded {
        pub(in crate::vault) bytes: &'static [u8],
        pub(in crate::vault) password: &'static str,
        sync: bool,
        pin: bool,
        spec: Spec,
        keys: Vec<[u8; 32]>,
        pub(in crate::vault) otp: Option<[u8; 20]>,
        s: [u8; 32],
        slots: Vec<RecordedKey>,
        authorizer: u8,
        present: u8,
        suspended: u8,
        /// Owner, target, and the nonce of a record new in this write.
        pairs: Vec<(u8, u8, Option<[u8; 24]>)>,
        wrap_nonces: Vec<[u8; 24]>,
        salt: [u8; 32],
        body_nonce: [u8; 24],
        written: u64,
        tag: &'static str,
        pub(in crate::vault) code: &'static str,
    }
    /// Two keys without PIN mode, both touched to remove a lost third.
    pub(in crate::vault) fn recorded_kh() -> Recorded {
        Recorded {
            bytes: SECURITY_KEY_FIXTURES[0].1,
            password: "goyo security-key fixture, KH",
            sync: false,
            pin: false,
            spec: Spec {
                vault_id: seq(0x31),
                epoch: 6,
                kind: Kind::Remove,
                next: 4,
                pw_id: seq(0x51),
                loss: LOSS,
                tombstones: vec![
                    Tombstone {
                        credhash: credhash(&run(0x40, 24)),
                        removed: 6 | LOSS_MARK << 48,
                    },
                    Tombstone {
                        credhash: credhash(&run(0x60, 20)),
                        removed: 3,
                    },
                ],
                resume: seq(0x71),
            },
            keys: vec![seq(0xa1), seq(0xc1)],
            otp: Some(seq(0x91)),
            s: mixed(0x3d),
            slots: vec![
                RecordedKey {
                    number: 1,
                    flags: 1,
                    added_epoch: 1,
                    added_by: None,
                    seed: mixed(0x13),
                    cred_id: run(0x02, 16),
                    random_uv: mixed(0x41),
                    random_nouv: mixed(0x42),
                    registered: WRITTEN - 90 * DAY,
                },
                RecordedKey {
                    number: 3,
                    flags: 0,
                    added_epoch: 4,
                    added_by: Some(0),
                    seed: mixed(0x17),
                    cred_id: run(0x80, 64),
                    random_uv: mixed(0x43),
                    random_nouv: mixed(0x44),
                    registered: WRITTEN - 30 * DAY,
                },
            ],
            authorizer: 1,
            present: 0b11,
            suspended: 0,
            pairs: vec![(0, 1, Some(mixed(0x55))), (1, 0, Some(mixed(0x56)))],
            wrap_nonces: vec![mixed(0x57), mixed(0x58)],
            salt: mixed(0x59),
            body_nonce: mixed(0x5b),
            written: WRITTEN + 2,
            tag: "19494017d49db47de81486e542944ce6",
            code: "e21eb8b5a94673fe",
        }
    }
    /// Four keys in PIN mode: keys 2 and 4 touched and paired, key 5
    /// reached through the authorizer's pair record, key 6 suspended.
    pub(in crate::vault) fn recorded_ks() -> Recorded {
        let key = |number, added_epoch, added_by, n: u8, cred: (u8, usize), days| RecordedKey {
            number,
            flags: 3,
            added_epoch,
            added_by,
            seed: mixed(0x20 + n),
            cred_id: run(cred.0, cred.1),
            random_uv: mixed(0x5f + 2 * n),
            random_nouv: mixed(0x60 + 2 * n),
            registered: WRITTEN - days * DAY,
        };
        Recorded {
            bytes: SECURITY_KEY_FIXTURES[1].1,
            password: "goyo security-key fixture, KS",
            sync: true,
            pin: true,
            spec: Spec {
                vault_id: seq(0x3a),
                epoch: 9,
                kind: Kind::Pair,
                next: 7,
                pw_id: seq(0x5a),
                loss: 0,
                tombstones: vec![
                    Tombstone {
                        credhash: credhash(&run(0xd0, 16)),
                        removed: 2,
                    },
                    Tombstone {
                        credhash: credhash(&run(0xe0, 16)),
                        removed: 8 | 1 << 48,
                    },
                    Tombstone {
                        credhash: credhash(&run(0xf0, 16)),
                        removed: 8 | LOSS_MARK << 48,
                    },
                ],
                resume: [0; 32],
            },
            keys: vec![seq(0x0b), seq(0x2b), seq(0x4b)],
            otp: None,
            s: mixed(0x6d),
            slots: vec![
                key(2, 1, None, 1, (0x10, 32), 120),
                key(4, 3, Some(0), 2, (0x30, 48), 100),
                key(5, 5, Some(0), 3, (0x60, 64), 60),
                key(6, 7, Some(1), 4, (0xa0, 80), 20),
            ],
            authorizer: 0,
            present: 0b0011,
            suspended: 0b1000,
            pairs: vec![
                (0, 1, Some(mixed(0x71))),
                (0, 2, None),
                (1, 0, Some(mixed(0x73))),
                (2, 0, None),
                (3, 0, None),
            ],
            wrap_nonces: vec![mixed(0x76), mixed(0x77), mixed(0x78)],
            salt: mixed(0x79),
            body_nonce: mixed(0x7b),
            written: WRITTEN + 3,
            tag: "cbff366c4a88b06a41f3a56507400e22",
            code: "0698b8e1319a8a3e",
        }
    }
    impl Recorded {
        fn id(&self) -> [u8; 16] {
            self.spec.vault_id
        }
        /// How many keys the file lists.
        pub(in crate::vault) fn key_count(&self) -> usize {
            self.slots.len()
        }
        fn slots(&self) -> Vec<SlotPublic> {
            self.slots
                .iter()
                .map(|k| {
                    let added_by = k
                        .added_by
                        .map_or([0; 16], |i| credhash(&self.slots[i].cred_id));
                    SlotPublic::new(
                        k.flags,
                        k.number,
                        k.registered,
                        k.added_epoch,
                        added_by,
                        k.seed,
                        k.cred_id.clone(),
                    )
                })
                .collect()
        }
        fn bundle(&self) -> Bundle {
            Bundle::new(&self.keys, self.otp.as_ref()).unwrap()
        }
        fn file(&self) -> KeyFile {
            file(self.bytes).unwrap()
        }
        /// A fake key per slot, holding the recorded credential (§8.9
        /// import), or with `reset` other CredRandoms under the same
        /// credential ID: what a forged or reset key answers.
        pub(in crate::vault) fn fake(&self, reset: bool) -> Fake {
            let fake = Fake::new(None);
            for k in &self.slots {
                let i = fake.plug(Default::default());
                let (uv, nouv) = if reset {
                    (mixed(0xee), mixed(0xef))
                } else {
                    (k.random_uv, k.random_nouv)
                };
                let protect = if k.flags & 2 != 0 { 3 } else { 1 };
                fake.import_credential(i, &k.cred_id, &uv, &nouv, protect, k.flags & 1 != 0);
            }
            fake
        }
        /// The unlock's allow list: every live slot, suspended ones too.
        fn allow(&self) -> AssertRequest {
            let allow = self
                .slots
                .iter()
                .map(|k| (k.cred_id.clone(), salt(&self.id(), &k.seed), None))
                .collect();
            AssertRequest::new(0, allow, self.pin).unwrap()
        }
        /// Key `j` touched.
        fn touch(&self, fake: &Fake, j: usize) -> Touch {
            fake.touch(Some(j));
            let req = self.allow();
            let raw = fake
                .get_assertion(&req, &fake.new_cancel().unwrap())
                .unwrap();
            check_assertion(raw, &req, false).unwrap()
        }
        fn present(&self, j: usize) -> bool {
            (self.present >> j) & 1 != 0
        }
        pub(in crate::vault) fn suspended(&self, j: usize) -> bool {
            (self.suspended >> j) & 1 != 0
        }
    }
    /// The plan that wrote `r`, with the outputs of its touched keys, the
    /// inbox keys its authorizer reads from `r`'s own records, and its
    /// carried records. `pairs` picks the records to keep.
    /// The touches of a write's present keys, and the inbox keys of its
    /// absent ones, by slot index.
    type Parts = (Vec<(u8, Touch)>, Vec<(u8, Box<Key>)>);
    fn plan_parts(r: &Recorded, fake: &Fake) -> Parts {
        let touches: Vec<(u8, Touch)> = (0..r.slots.len())
            .filter(|j| r.present(*j))
            .map(|j| (j as u8, r.touch(fake, j)))
            .collect();
        let slots = r.slots();
        let a = usize::from(r.authorizer);
        let h_a = touches
            .iter()
            .find(|(j, _)| usize::from(*j) == a)
            .and_then(|(_, t)| t.output_for(&slots[a].seed, &r.id()))
            .unwrap();
        let opened = r.file().open_pairs(h_a, r.authorizer);
        let inbox = (0..r.slots.len())
            .filter(|j| !r.present(*j) && !r.suspended(*j))
            .map(|j| {
                let (_, ik) = opened.iter().find(|(t, _)| usize::from(*t) == j).unwrap();
                (j as u8, super::super::boxed::<32>(ik.as_deref().unwrap()))
            })
            .collect();
        (touches, inbox)
    }
    fn outputs<'t>(r: &Recorded, touches: &'t [(u8, Touch)]) -> Vec<(u8, &'t [u8; 32])> {
        touches
            .iter()
            .map(|(j, t)| {
                (
                    *j,
                    t.output_for(&r.slots[usize::from(*j)].seed, &r.id())
                        .unwrap(),
                )
            })
            .collect()
    }
    fn pair_plans(r: &Recorded, keep: impl Fn(u8, u8) -> bool) -> Vec<PairPlan> {
        let carried = r.file().carried_pairs();
        let slots = r.slots();
        r.pairs
            .iter()
            .filter(|(o, t, _)| keep(*o, *t))
            .map(|(o, t, nonce)| {
                let (owner, target) = (
                    slots[usize::from(*o)].credhash,
                    slots[usize::from(*t)].credhash,
                );
                match nonce {
                    Some(_) => PairPlan::New { owner, target },
                    None => carried
                        .iter()
                        .find(|p| p.keys() == (owner, target))
                        .unwrap()
                        .clone(),
                }
            })
            .collect()
    }

    /// The feature build's cross-check of the stage-2 fixtures (spec §11.4,
    /// §14.1-3, S23-1 #25): the fake imports each recorded credential, every
    /// key with an S-wrap opens the file to the recorded bundle and S, the
    /// suspended key is refused before any Argon2, and `seal`, fed the
    /// recorded draws and time and the recorded inputs (the new records'
    /// keys touched, the carried ones copied, the absent key's inbox key
    /// read through the authorizer's record), writes the same bytes.
    #[test]
    fn the_pinned_fixtures_open_and_reproduce_byte_for_byte() {
        set_kdf_profile(KdfProfile::Test);
        for r in [recorded_kh(), recorded_ks()] {
            let source = r.file();
            let h = source.header().unwrap().clone();
            assert!(source.needs_security_key() && source.refusal().is_none());
            assert_eq!((hex(&h.tag).as_str(), h.written), (r.tag, r.written));
            let code = key_code(&r.id(), &r.keys[0], h.state());
            assert_eq!(hex(&code.0), r.code);
            let fake = r.fake(false);
            for (j, k) in r.slots.iter().enumerate() {
                let touch = r.touch(&fake, j);
                let derives = derive_count();
                let opened = source.open(r.password, Some(&touch));
                if r.suspended(j) {
                    assert_eq!(opened.err(), Some(SUSPENDED_KEY));
                    assert_eq!(
                        refusal_values(SUSPENDED_KEY),
                        Some(vec![k.number.to_string()])
                    );
                    assert_eq!(derive_count(), derives);
                    continue;
                }
                let opened = opened.unwrap();
                assert_eq!(derive_count(), derives + 1);
                assert!(opened.bundle.same(&r.bundle()));
                assert_eq!(opened.s.as_deref().map(|s| **s), Some(r.s));
                assert_eq!(
                    (opened.slot, opened.state, opened.pw_id),
                    (Some(j as u8), h.state(), r.spec.pw_id)
                );
            }
            // The same bytes from the recorded inputs.
            let (touches, inbox) = plan_parts(&r, &fake);
            let s = Secret(super::super::boxed(&r.s));
            let plan = KeysPlan {
                sync: r.sync,
                pin: r.pin,
                s: &s,
                slots: r.slots(),
                authorizer: r.authorizer,
                present: r.present,
                suspended: r.suspended,
                pairs: pair_plans(&r, |_, _| true),
                outputs: outputs(&r, &touches),
                inbox: inbox.iter().map(|(j, ik)| (*j, &***ik)).collect(),
            };
            let mut draws: Vec<&[u8]> = vec![&r.salt, &r.body_nonce];
            draws.extend(
                r.pairs
                    .iter()
                    .filter_map(|(_, _, n)| n.as_ref().map(|n| &n[..])),
            );
            draws.extend(r.wrap_nonces.iter().map(|n| &n[..]));
            queue_random(&draws);
            set_test_now(Some(r.written));
            let sealed = seal(&r.spec, &r.bundle(), r.password, Plan::Keys(&plan));
            set_test_now(None);
            assert_eq!(queued_random(), 0, "seal draws exactly the recorded values");
            let (bytes, writer) = sealed.unwrap();
            assert_eq!(hex(&bytes), hex(r.bytes));
            // The writer's read-back: every S-wrap with its base, then the
            // body, with no Argon2.
            let derives = derive_count();
            let opened = source.open_written(&writer).unwrap();
            assert!(opened.bundle.same(&r.bundle()));
            assert_eq!(derive_count(), derives);
        }
    }

    /// The same-epoch re-seal of a security-key file (spec §3.3, §14.1-3):
    /// `[0, W)` byte for byte, so S, every S-wrap and the state tag stay,
    /// under the S that opening it gave; a new seal block, body and chain.
    #[test]
    fn a_reseal_keeps_every_s_wrap_and_the_state_tag() {
        set_kdf_profile(KdfProfile::Test);
        let r = recorded_ks();
        let fake = r.fake(false);
        let source = r.file();
        let h = source.header().unwrap().clone();
        let opened = source.open(r.password, Some(&r.touch(&fake, 1))).unwrap();
        let mut spec = h.spec();
        spec.resume = [0xab; 32];
        let plan = Plan::Reseal {
            source: &source,
            opened: &opened,
        };
        let (bytes, writer) = seal(&spec, &r.bundle(), r.password, plan).unwrap();
        assert_eq!(bytes[..h.w], r.bytes[..h.w]);
        assert_ne!(bytes[h.w..], r.bytes[h.w..]);
        let copy = file(&bytes).unwrap();
        let c = copy.header().unwrap();
        assert_eq!((c.tag, c.resume, c.written), (h.tag, [0xab; 32], h.written));
        assert!(copy.open_written(&writer).unwrap().bundle.same(&r.bundle()));
        for j in [0, 2] {
            let again = copy.open(r.password, Some(&r.touch(&fake, j))).unwrap();
            assert_eq!(again.s.as_deref().map(|s| **s), Some(r.s));
        }
        // Without its S (a password-only open gives none) or with another
        // file's, nothing is sealed.
        let kh = recorded_kh();
        let other = kh
            .file()
            .open(kh.password, Some(&kh.touch(&kh.fake(false), 0)))
            .unwrap();
        let plan = Plan::Reseal {
            source: &source,
            opened: &other,
        };
        assert_eq!(
            seal(&spec, &r.bundle(), r.password, plan).err(),
            Some(NOT_SEALED)
        );
    }

    /// Condition 2 (spec §3.4 step 5, §14.1-4), with the real Argon2: a
    /// wrong password, a wrong key's output (for an S-wrap through the key
    /// itself and for one through the authorizer) and both fail with the
    /// same error at the same step after the same work, in the same order:
    /// one Argon2, one S-wrap commitment check, one S-wrap AEAD, the body
    /// commitment, and no body AEAD.
    #[test]
    fn a_wrong_password_and_a_wrong_key_fail_at_the_same_step() {
        set_kdf_profile(KdfProfile::Test);
        let r = recorded_ks();
        let fake = r.fake(false);
        let source = r.file();
        let opened = source.open(r.password, Some(&r.touch(&fake, 0))).unwrap();
        // The same state, its body under the real profile.
        set_kdf_profile(KdfProfile::Real);
        let plan = Plan::Reseal {
            source: &source,
            opened: &opened,
        };
        let spec = source.header().unwrap().spec();
        let (bytes, _) = seal(&spec, &r.bundle(), r.password, plan).unwrap();
        let real = file(&bytes).unwrap();
        let reset = r.fake(true);
        let cases = [
            ("a wrong password", "not the password", r.touch(&fake, 0)),
            ("a wrong key", r.password, r.touch(&reset, 0)),
            (
                "a wrong key via the authorizer",
                r.password,
                r.touch(&reset, 2),
            ),
            ("both wrong", "not the password", r.touch(&reset, 1)),
        ];
        for (name, password, touch) in cases {
            take_events();
            take_failed_at();
            let (derives, aeads) = (derive_count(), body_aeads());
            assert_eq!(
                real.open(password, Some(&touch)).err(),
                Some(AUTH_ERROR),
                "{name}"
            );
            assert_eq!(take_failed_at(), Some(Step::Body), "{name}");
            assert_eq!(derive_count(), derives + 1, "{name}");
            assert_eq!(body_aeads(), aeads, "{name}");
            assert_eq!(
                take_events(),
                [
                    Event::Argon2,
                    Event::WrapCommit,
                    Event::WrapAead,
                    Event::BodyCommit
                ],
                "{name}"
            );
        }
        // The right password and key through the authorizer's record.
        let opened = real.open(r.password, Some(&r.touch(&fake, 2))).unwrap();
        assert!(opened.bundle.same(&r.bundle()));
        assert_eq!(
            take_events(),
            [
                Event::Argon2,
                Event::WrapCommit,
                Event::WrapAead,
                Event::BodyCommit,
                Event::BodyAead
            ]
        );
        set_kdf_profile(KdfProfile::Test);
    }

    /// The public checks of spec §3.4 step 2, each before any secret is
    /// used: no Argon2, and only an unregistered credential or a changed UV
    /// state counts as a failed attempt (§8.7).
    #[test]
    fn an_open_checks_the_touch_before_any_secret() {
        set_kdf_profile(KdfProfile::Test);
        let (kh, ks) = (recorded_kh(), recorded_ks());
        let fake = ks.fake(false);
        let source = ks.file();
        let good = ks.touch(&fake, 0);
        let derives = derive_count();
        assert_eq!(
            source.open(ks.password, None).err(),
            Some(SECURITY_KEY_NEEDED)
        );
        // A credential of another vault: Windows answers only for a listed
        // one, so only a fault gets here.
        let other = fake.plug(crate::fido::fake::Device::with_pin());
        fake.touch(Some(other));
        let new = crate::fido::register(&fake, &[9; 16], 1, 0, true, vec![]).unwrap();
        let req = AssertRequest::new(
            0,
            vec![(new.cred_id.clone(), salt(&ks.id(), &[1; 32]), None)],
            true,
        )
        .unwrap();
        let raw = fake
            .get_assertion(&req, &fake.new_cancel().unwrap())
            .unwrap();
        let stranger = check_assertion(raw, &req, false).unwrap();
        // An answer for another seed of the right credential.
        let req = AssertRequest::new(
            0,
            vec![(ks.slots[0].cred_id.clone(), salt(&ks.id(), &[1; 32]), None)],
            true,
        )
        .unwrap();
        fake.touch(Some(0));
        let raw = fake
            .get_assertion(&req, &fake.new_cancel().unwrap())
            .unwrap();
        let other_seed = check_assertion(raw, &req, false).unwrap();
        let changed = |f: fn(&mut Touch)| {
            let mut t = ks.touch(&fake, 0);
            f(&mut t);
            t
        };
        let cases = [
            (stranger, fido::NOT_REGISTERED),
            (other_seed, fido::BAD_ANSWER),
            (ks.touch(&fake, 3), SUSPENDED_KEY),
            (changed(|t| **t.first = [0; 32]), fido::BAD_ANSWER),
            (changed(|t| t.flags &= !fido::UP), fido::UNVERIFIABLE),
            (changed(|t| t.flags |= fido::BE), fido::SYNCED_PASSKEY),
            (changed(|t| t.flags |= fido::BS), fido::SYNCED_PASSKEY),
            (
                changed(|t| t.transport = Some(fido::HYBRID)),
                fido::TRANSPORT,
            ),
            (changed(|t| t.uv = false), fido::UV_CHANGED),
        ];
        for (touch, error) in cases {
            assert_eq!(source.open(ks.password, Some(&touch)).err(), Some(error));
            let delays = matches!(error, fido::NOT_REGISTERED | fido::UV_CHANGED);
            assert_eq!(not_a_failure(error), !delays, "{error}");
        }
        assert!(not_a_failure(SECURITY_KEY_NEEDED) && !not_a_failure(AUTH_ERROR));
        // A key registered without UV that now verifies (a PIN set later).
        let kh_fake = kh.fake(false);
        let mut t = kh.touch(&kh_fake, 1);
        assert!(!t.uv);
        t.uv = true;
        assert_eq!(
            kh.file().open(kh.password, Some(&t)).err(),
            Some(fido::UV_CHANGED)
        );
        assert_eq!(derive_count(), derives);
        assert!(source.open(ks.password, Some(&good)).is_ok());
    }

    /// A suspended key that owns no pair record can never come back
    /// (S-SUSPENDED-ORPHAN): the KS fixture without key 6's record.
    #[test]
    fn a_suspended_key_without_a_record_is_an_orphan() {
        set_kdf_profile(KdfProfile::Test);
        let r = recorded_ks();
        let fake = r.fake(false);
        let (touches, inbox) = plan_parts(&r, &fake);
        let s = Secret::random().unwrap();
        let plan = KeysPlan {
            sync: true,
            pin: true,
            s: &s,
            slots: r.slots(),
            authorizer: 0,
            present: r.present,
            suspended: r.suspended,
            pairs: pair_plans(&r, |o, _| o != 3),
            outputs: outputs(&r, &touches),
            inbox: inbox.iter().map(|(j, ik)| (*j, &***ik)).collect(),
        };
        let (bytes, _) = seal(&r.spec, &r.bundle(), "orphan", Plan::Keys(&plan)).unwrap();
        let f = file(&bytes).unwrap();
        let derives = derive_count();
        assert_eq!(
            f.open("orphan", Some(&r.touch(&fake, 3))).err(),
            Some(SUSPENDED_ORPHAN)
        );
        assert_eq!(refusal_values(SUSPENDED_ORPHAN), Some(vec!["6".into()]));
        assert_eq!(derive_count(), derives);
        for j in [0, 1, 2] {
            let opened = f.open("orphan", Some(&r.touch(&fake, j))).unwrap();
            assert!(ct_eq(opened.s.as_deref().unwrap().as_slice(), s.bytes()));
        }
    }

    /// The tail of a file after `[0, W)`: what `seal` appends, under any S,
    /// so a test can build what only someone holding the password and a
    /// key's output could.
    fn sealed_after(head: &[u8], r: &Recorded, s: &[u8; 32]) -> KeyFile {
        let pw_key = crypto::derive(r.password.as_bytes(), &r.salt).unwrap();
        let mut out = head.to_vec();
        out.extend_from_slice(&r.spec.resume);
        out.extend_from_slice(&r.salt);
        out.extend_from_slice(&r.body_nonce);
        let (k_body, c_body) = body_keys(&pw_key, s, &sha256(&[&out]));
        out.extend_from_slice(&c_body);
        let body = crypto::seal(&k_body, &r.body_nonce, &out, &r.bundle().plain()).unwrap();
        out.extend_from_slice(&body);
        let end = sha256(&[&out]);
        for key in &r.keys {
            out.extend_from_slice(&chain_mac(&r.id(), key, &end));
        }
        file(&out).unwrap()
    }
    /// `[0, W)` of `r` with every S-wrap rewrapping `s` under its true base.
    fn rewrapped(r: &Recorded, fake: &Fake, s: &[u8; 32]) -> Vec<u8> {
        let h = parse(r.bytes).unwrap();
        let slots = r.slots();
        let mut head = r.bytes[..h.w].to_vec();
        let head_hash = sha256(&[&r.bytes[..h.h()]]);
        for (i, (j, v)) in h.wraps.iter().enumerate() {
            let (j, v) = (usize::from(*j), usize::from(*v));
            let touch = r.touch(fake, j);
            let out = touch.output_for(&slots[j].seed, &r.id()).unwrap();
            let base = if j == v {
                own_base(&r.id(), &slots[j], out)
            } else {
                inbox_key(&r.id(), &slots[j], out, &slots[v])
            };
            let ctx = wrap_ctx(&r.id(), h.epoch, &slots[j], &slots[v], &head_hash);
            let record = wrap_with(&base, Use::SWrap, &ctx, s, &[7; 24]).unwrap();
            let at = h.h() + S_WRAP * i + 2;
            head[at..at + WRAP].copy_from_slice(&record);
        }
        head
    }

    /// An S-wrap that opens (the test holds every output) to an S whose
    /// keyset ID is not the file's fails the open even when the body was
    /// sealed under that S (spec §14.1-6); one that opens to zeros fails
    /// even when the body was sealed under zeros, which is how a holder of
    /// the password alone would seal it, and a zero keyset ID never parses
    /// (spec §3.2, §14.1-9).
    #[test]
    fn only_the_committed_nonzero_s_opens_the_body() {
        set_kdf_profile(KdfProfile::Test);
        let r = recorded_kh();
        let fake = r.fake(false);
        let other: [u8; 32] = mixed(0x77);
        let forged = sealed_after(&rewrapped(&r, &fake, &other), &r, &other);
        let zero = sealed_after(&rewrapped(&r, &fake, &[0; 32]), &r, &[0; 32]);
        for (f, body_aeads) in [(&forged, 0), (&zero, 1)] {
            for j in [0, 1] {
                take_events();
                take_failed_at();
                let touch = r.touch(&fake, j);
                assert_eq!(f.open(r.password, Some(&touch)).err(), Some(AUTH_ERROR));
                assert_eq!(take_failed_at(), Some(Step::Body));
                let events = take_events();
                assert_eq!(
                    events[..4],
                    [
                        Event::Argon2,
                        Event::WrapCommit,
                        Event::WrapAead,
                        Event::BodyCommit
                    ]
                );
                assert_eq!(events.len(), 4 + body_aeads);
            }
        }
        // The header's keyset ID of a zero S never parses.
        let mut bytes = r.bytes.to_vec();
        bytes[48..64].copy_from_slice(&ks_id_zero(&r.id()));
        assert_eq!(file(&bytes).err(), Some(AUTH_ERROR));
        assert!(
            Secret::of(&r.file().open(r.password, Some(&r.touch(&fake, 0))).unwrap()).is_some()
        );
    }
    #[test]
    #[should_panic(expected = "a zero keyset secret")]
    fn a_zero_keyset_secret_is_never_drawn() {
        queue_random(&[&[0; 32]]);
        let _ = Secret::random();
    }

    /// The committing wraps on a writer's path (spec §14.1-12): a wrong
    /// base fails at the commitment with no AEAD; the right base on a
    /// changed ciphertext fails at the AEAD; the right one gives the target
    /// key's inbox key, which only the target's output reproduces.
    #[test]
    fn a_wrong_base_fails_at_the_commitment() {
        let r = recorded_kh();
        let fake = r.fake(false);
        let slots = r.slots();
        let outs: Vec<Box<Key>> = (0..2)
            .map(|j| {
                super::super::boxed::<32>(
                    r.touch(&fake, j)
                        .output_for(&slots[j].seed, &r.id())
                        .unwrap(),
                )
            })
            .collect();
        take_events();
        let opened = r.file().open_pairs(&outs[0], 0);
        assert_eq!(take_events(), [Event::WrapCommit, Event::WrapAead]);
        let (t, ik) = &opened[0];
        assert_eq!(*t, 1);
        let ik = ik.as_deref().unwrap();
        assert_eq!(**ik, **inbox_key(&r.id(), &slots[1], &outs[1], &slots[0]));
        assert_ne!(**ik, **inbox_key(&r.id(), &slots[1], &outs[0], &slots[0]));
        // Key 3's output is not key 1's.
        let opened = r.file().open_pairs(&outs[1], 0);
        assert!(opened.iter().all(|(_, ik)| ik.is_none()));
        assert_eq!(take_events(), [Event::WrapCommit]);
        // A flipped ciphertext byte of record (0, 1).
        let h = parse(r.bytes).unwrap();
        let mut bytes = r.bytes.to_vec();
        let at = h.h() - 2 * PAIR + 4 + 60;
        bytes[at] ^= 1;
        let flipped = file(&bytes).unwrap();
        assert!(flipped.open_pairs(&outs[0], 0)[0].1.is_none());
        assert_eq!(take_events(), [Event::WrapCommit, Event::WrapAead]);
        // Out of range or without keys: nothing.
        assert!(r.file().open_pairs(&outs[0], 5).is_empty());
    }

    /// A small deterministic generator for the property tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn bytes<const N: usize>(&mut self) -> [u8; N] {
            std::array::from_fn(|_| self.next() as u8)
        }
    }
    /// A keyset of `n` keys, as their slots and outputs.
    struct Keyset {
        id: [u8; 16],
        slots: Vec<SlotPublic>,
        outputs: Vec<[u8; 32]>,
    }
    fn keyset(rng: &mut Rng, n: usize) -> Keyset {
        let id = rng.bytes();
        let slots = (0..n)
            .map(|j| {
                let cred = rng.bytes::<24>().to_vec();
                SlotPublic::new(1, j as u8 + 1, WRITTEN, 1, [0; 16], rng.bytes(), cred)
            })
            .collect();
        let outputs = (0..n).map(|_| rng.bytes()).collect();
        Keyset { id, slots, outputs }
    }
    /// A record `PR(o,t)` as an earlier write made it.
    fn record(k: &Keyset, o: usize, t: usize) -> PairPlan {
        let ik = inbox_key(&k.id, &k.slots[t], &k.outputs[t], &k.slots[o]);
        let ctx = pair_ctx(&k.id, &k.slots[o], &k.slots[t]);
        let wrap = wrap(
            &pair_seal(&k.id, &k.slots[o], &k.outputs[o]),
            Use::Pair,
            &ctx,
            &ik,
        )
        .unwrap();
        PairPlan::Copy {
            owner: k.slots[o].credhash,
            target: k.slots[t].credhash,
            wrap,
        }
    }
    /// A write of keyset `k` authorized by `a` with the keys of `present`
    /// touched: new records between present keys, the other records of
    /// `pairs` carried, each absent key reached through `a`'s record or
    /// suspended.
    fn write(
        k: &Keyset,
        a: usize,
        present: u8,
        pairs: &[(usize, usize)],
        epoch: u64,
    ) -> (Vec<u8>, Secret, u8) {
        let n = k.slots.len();
        let is = |j: usize| (present >> j) & 1 != 0;
        let suspended = (0..n)
            .filter(|j| !is(*j) && !pairs.contains(&(a, *j)))
            .fold(0u8, |m, j| m | 1 << j);
        let inbox: Vec<(u8, Box<Key>)> = (0..n)
            .filter(|j| !is(*j) && (suspended >> j) & 1 == 0)
            .map(|j| {
                (
                    j as u8,
                    inbox_key(&k.id, &k.slots[j], &k.outputs[j], &k.slots[a]),
                )
            })
            .collect();
        let plans = pairs
            .iter()
            .map(|(o, t)| {
                if is(*o) && is(*t) {
                    PairPlan::New {
                        owner: k.slots[*o].credhash,
                        target: k.slots[*t].credhash,
                    }
                } else {
                    record(k, *o, *t)
                }
            })
            .collect();
        let s = Secret::random().unwrap();
        let plan = KeysPlan {
            sync: false,
            pin: false,
            s: &s,
            slots: k.slots.clone(),
            authorizer: a as u8,
            present,
            suspended,
            pairs: plans,
            outputs: (0..n)
                .filter(|j| is(*j))
                .map(|j| (j as u8, &k.outputs[j]))
                .collect(),
            inbox: inbox.iter().map(|(j, ik)| (*j, &***ik)).collect(),
        };
        let spec = Spec {
            vault_id: k.id,
            epoch,
            kind: Kind::Password,
            next: n as u8 + 1,
            pw_id: [1; 16],
            loss: 0,
            tombstones: Vec::new(),
            resume: [0; 32],
        };
        let bundle = Bundle::new(&[[epoch as u8; 32]], None).unwrap();
        let (bytes, _) = seal(&spec, &bundle, "p", Plan::Keys(&plan)).unwrap();
        (bytes, s, suspended)
    }
    /// Every base an output `x` could give for slot `j`'s S-wrap through
    /// `v`, and whether it opens.
    fn opens_s_wrap(k: &Keyset, bytes: &[u8], i: usize, x: &[u8; 32]) -> bool {
        let h = parse(bytes).unwrap();
        let (j, v) = h.wraps[i];
        let (j, v) = (usize::from(j), usize::from(v));
        let head = sha256(&[&bytes[..h.h()]]);
        let ctx = wrap_ctx(&k.id, h.epoch, &k.slots[j], &k.slots[v], &head);
        let record = s_wrap(bytes, &h, i);
        // As the recipient's own base, as its inbox key from any writer.
        let mut bases = vec![own_base(&k.id, &k.slots[j], x)];
        bases.extend(k.slots.iter().map(|w| inbox_key(&k.id, &k.slots[j], x, w)));
        bases
            .iter()
            .any(|base| unwrap(base, Use::SWrap, &ctx, record).is_some())
    }

    /// P-INV (spec §3.2, §14.1-11) over random key sets, pairings and
    /// writes: a pair record opens only with its owner's output and carries
    /// what only its target's output reproduces; an S-wrap opens only with
    /// its recipient's output, also for an adversary that knows S, the data
    /// key and the password; after a removal no value derivable from the
    /// removed key's output opens anything of the result; after a re-seed
    /// the old output's values open nothing of a later file. Every file
    /// also opens through each key it gives an S-wrap (§14.2-1 round trips
    /// over n = 1..8 and the masks).
    #[test]
    fn p_inv_holds_for_random_key_sets_and_writes() {
        set_kdf_profile(KdfProfile::Test);
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for round in 0..24 {
            let n = 1 + round % 8;
            let k = keyset(&mut rng, n);
            let mut pairs: Vec<(usize, usize)> = (0..n)
                .flat_map(|o| (0..n).map(move |t| (o, t)))
                .filter(|(o, t)| o != t && rng.below(3) != 0)
                .collect();
            pairs.sort_unstable();
            let a = rng.below(n as u64) as usize;
            let present = (0..n)
                .filter(|_| rng.below(2) == 0)
                .fold(1u8 << a, |m, j| m | 1 << j);
            let (bytes, s, suspended) = write(&k, a, present, &pairs, 3);
            let h = parse(&bytes).unwrap();
            assert_eq!((h.present, h.suspended), (present, suspended));
            let f = file(&bytes).unwrap();
            // Pair records: only the owner's output opens one; only the
            // target's output reproduces what it carries.
            for (o, t) in h
                .pairs
                .iter()
                .map(|(o, t)| (usize::from(*o), usize::from(*t)))
            {
                for (x, out) in k.outputs.iter().enumerate() {
                    let opened = f.open_pairs(out, o as u8);
                    let ik = opened.iter().find(|(tt, _)| usize::from(*tt) == t).unwrap();
                    assert_eq!(ik.1.is_some(), x == o, "PR({o},{t}) with key {x}");
                    if let Some(ik) = &ik.1 {
                        for (y, out_t) in k.outputs.iter().enumerate() {
                            let again = inbox_key(&k.id, &k.slots[t], out_t, &k.slots[o]);
                            assert_eq!(***ik == **again, y == t);
                        }
                    }
                }
            }
            // S-wraps: only the recipient's output, and only that key's
            // touch opens the file.
            for (i, (j, _)) in h.wraps.iter().enumerate() {
                for (x, out) in k.outputs.iter().enumerate() {
                    assert_eq!(opens_s_wrap(&k, &bytes, i, out), x == usize::from(*j));
                }
            }
            // Round trip: every key with an S-wrap opens it.
            let pw_key =
                crypto::derive(b"p", bytes[h.w + 32..h.w + 64].try_into().unwrap()).unwrap();
            for (j, _) in h.wraps.iter() {
                let opened_s =
                    open_with_output(&f, &h, usize::from(*j), &k.outputs[usize::from(*j)]);
                assert!(ct_eq(opened_s.as_slice(), s.bytes()));
                assert!(f.body(&h, &pw_key, &opened_s).is_ok());
            }
            // The same with S, the data key and the password's key added to
            // what the adversary knows: none of them, taken as a key's
            // output or as a wrap's base, opens an S-wrap or a pair record.
            let head = sha256(&[&bytes[..h.h()]]);
            for x in [*s.bytes(), [3; 32], *pw_key] {
                for (i, (j, v)) in h.wraps.iter().enumerate() {
                    let (j, v) = (&k.slots[usize::from(*j)], &k.slots[usize::from(*v)]);
                    let ctx = wrap_ctx(&k.id, 3, j, v, &head);
                    assert!(unwrap(&x, Use::SWrap, &ctx, s_wrap(&bytes, &h, i)).is_none());
                    assert!(!opens_s_wrap(&k, &bytes, i, &x));
                }
                for o in 0..n {
                    assert!(f.open_pairs(&x, o as u8).iter().all(|(_, ik)| ik.is_none()));
                }
            }
            // A removal of X: the next write keeps every other key and
            // drops X's records; nothing of it opens with X's output or
            // with any inbox key X ever knew.
            if n >= 2 {
                let x = (a + 1) % n;
                let others: Vec<usize> = (0..n).filter(|j| *j != x).collect();
                let rest = Keyset {
                    id: k.id,
                    slots: others.iter().map(|j| k.slots[*j].clone()).collect(),
                    outputs: others.iter().map(|j| k.outputs[*j]).collect(),
                };
                let index = |j: usize| others.iter().position(|o| *o == j).unwrap();
                let kept: Vec<(usize, usize)> = pairs
                    .iter()
                    .filter(|(o, t)| *o != x && *t != x)
                    .map(|(o, t)| (index(*o), index(*t)))
                    .collect();
                let a2 = index(a);
                let (after, _, _) = write(&rest, a2, 1 << a2, &kept, 4);
                let h2 = parse(&after).unwrap();
                let known: Vec<Box<Key>> = k
                    .slots
                    .iter()
                    .enumerate()
                    .flat_map(|(j, slot)| {
                        [
                            inbox_key(&k.id, slot, &k.outputs[j], &k.slots[x]),
                            inbox_key(&k.id, &k.slots[x], &k.outputs[x], slot),
                            own_base(&k.id, &k.slots[x], &k.outputs[x]),
                            pair_seal(&k.id, &k.slots[x], &k.outputs[x]),
                        ]
                    })
                    .collect();
                let head = sha256(&[&after[..h2.h()]]);
                for (i, (j, v)) in h2.wraps.iter().enumerate() {
                    assert!(!opens_s_wrap(&rest, &after, i, &k.outputs[x]));
                    let (j, v) = (&rest.slots[usize::from(*j)], &rest.slots[usize::from(*v)]);
                    let ctx = wrap_ctx(&k.id, 4, j, v, &head);
                    for base in &known {
                        assert!(unwrap(base, Use::SWrap, &ctx, s_wrap(&after, &h2, i)).is_none());
                    }
                }
                let f2 = file(&after).unwrap();
                for o in 0..rest.slots.len() {
                    assert!(
                        f2.open_pairs(&k.outputs[x], o as u8)
                            .iter()
                            .all(|(_, ik)| ik.is_none())
                    );
                }
            }
        }
        // A re-seed of o (S45-2 #1): t keeps its seed; a clone of o's old
        // output reads IK(t←o) from the old record PR(o,t), and that value
        // opens no S-wrap of t that o delivers after the re-seed.
        let k = keyset(&mut rng, 2);
        let (old, _, _) = write(&k, 0, 0b01, &[(0, 1)], 3);
        let stolen = file(&old)
            .unwrap()
            .open_pairs(&k.outputs[0], 0)
            .remove(0)
            .1
            .unwrap();
        let mut reseeded = Keyset {
            id: k.id,
            slots: k.slots.clone(),
            outputs: k.outputs.clone(),
        };
        reseeded.slots[0].seed = rng.bytes();
        reseeded.outputs[0] = rng.bytes();
        let (later, _, _) = write(&reseeded, 0, 0b01, &[(0, 1)], 5);
        let h = parse(&later).unwrap();
        assert_eq!(h.wraps[1], (1, 0));
        let head = sha256(&[&later[..h.h()]]);
        let ctx = wrap_ctx(&k.id, 5, &reseeded.slots[1], &reseeded.slots[0], &head);
        assert!(unwrap(&stolen, Use::SWrap, &ctx, s_wrap(&later, &h, 1)).is_none());
        let fresh = inbox_key(&k.id, &reseeded.slots[1], &k.outputs[1], &reseeded.slots[0]);
        assert!(unwrap(&fresh, Use::SWrap, &ctx, s_wrap(&later, &h, 1)).is_some());
        assert!(
            file(&later).unwrap().open_pairs(&k.outputs[0], 0)[0]
                .1
                .is_none()
        );
    }
    /// The S an open with key `j`'s output would recover (the test holds
    /// the output, so no fake is needed).
    fn open_with_output(f: &KeyFile, h: &KeyHeader, j: usize, out: &[u8; 32]) -> Box<Key> {
        let i = h
            .wraps
            .iter()
            .position(|(r, _)| usize::from(*r) == j)
            .unwrap();
        let v = usize::from(h.wraps[i].1);
        let base = if v == j {
            own_base(&h.vault_id, &h.slots[j], out)
        } else {
            inbox_key(&h.vault_id, &h.slots[j], out, &h.slots[v])
        };
        let head = sha256(&[&f.bytes()[..h.h()]]);
        let ctx = wrap_ctx(&h.vault_id, h.epoch, &h.slots[j], &h.slots[v], &head);
        unwrap(&base, Use::SWrap, &ctx, s_wrap(f.bytes(), h, i)).unwrap()
    }

    /// No hardware-free oracle (spec §14.1-8): someone with the password
    /// and every public byte of three honest files of one vault recombines
    /// their parts (the header up to H, the S-wraps, the seal block, the
    /// body and the chain), all at once and at random cut points; nothing
    /// but an original file opens for any key.
    #[test]
    fn recombined_files_never_open() {
        set_kdf_profile(KdfProfile::Test);
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let k = keyset(&mut rng, 2);
        let files: Vec<Vec<u8>> = (0..3)
            .map(|e| write(&k, 0, 0b11, &[(0, 1), (1, 0)], 2 + e).0)
            .collect();
        let h = parse(&files[0]).unwrap();
        let cuts = [0, h.h(), h.w, h.b, h.e, files[0].len()];
        let try_open = |bytes: &[u8]| {
            let Ok(f) = file(bytes) else {
                return false;
            };
            let Some(h) = f.header() else {
                return false;
            };
            (0..2).any(|j| {
                let i = h
                    .wraps
                    .iter()
                    .position(|(r, _)| usize::from(*r) == j)
                    .unwrap();
                let v = usize::from(h.wraps[i].1);
                let out = &k.outputs[j];
                let base = if v == j {
                    own_base(&k.id, &h.slots[j], out)
                } else {
                    inbox_key(&k.id, &h.slots[j], out, &h.slots[v])
                };
                let head = sha256(&[&bytes[..h.h()]]);
                let ctx = wrap_ctx(&k.id, h.epoch, &h.slots[j], &h.slots[v], &head);
                let Some(s) = unwrap(&base, Use::SWrap, &ctx, s_wrap(bytes, h, i)) else {
                    return false;
                };
                let pw_key =
                    crypto::derive(b"p", bytes[h.w + 32..h.w + 64].try_into().unwrap()).unwrap();
                f.body(h, &pw_key, &s).is_ok()
            })
        };
        let mut tried = 0;
        for combo in 0..3usize.pow(5) {
            let parts: Vec<usize> = (0..5).map(|i| combo / 3usize.pow(i) % 3).collect();
            let mut bytes = Vec::new();
            for (i, from) in parts.iter().enumerate() {
                bytes.extend_from_slice(&files[*from][cuts[i]..cuts[i + 1]]);
            }
            let original = parts.iter().all(|p| *p == parts[0]);
            assert_eq!(try_open(&bytes), original, "{parts:?}");
            tried += 1;
        }
        while tried < 10_000 {
            let (a, b) = (rng.below(3) as usize, rng.below(3) as usize);
            let at = rng.below(files[0].len() as u64) as usize;
            let to = at + rng.below((files[0].len() - at) as u64) as usize;
            let mut bytes = files[a].clone();
            bytes[at..to].copy_from_slice(&files[b][at..to]);
            if bytes != files[a] && bytes != files[b] {
                assert!(!try_open(&bytes), "{a} {b} {at}..{to}");
            }
            tried += 1;
        }
    }

    /// Every single-byte flip of a GOYOKH01 and a GOYOKS01, in the pair
    /// records, the S-wraps, the seal block and the chain included, is
    /// refused: by the parse, the public checks or AUTH (spec §14.2-2).
    #[test]
    fn every_byte_flip_of_a_security_key_file_is_refused() {
        set_kdf_profile(KdfProfile::Test);
        for r in [recorded_kh(), recorded_ks()] {
            let fake = r.fake(false);
            let touch = r.touch(&fake, 0);
            assert!(r.file().open(r.password, Some(&touch)).is_ok());
            for i in 0..r.bytes.len() {
                let mut bytes = r.bytes.to_vec();
                bytes[i] ^= 0x01;
                if let Ok(f) = file(&bytes) {
                    assert!(f.open(r.password, Some(&touch)).is_err(), "byte {i}");
                }
            }
        }
    }

    /// The security-key build's counterpart of the default build's magic
    /// family test (spec §4.6, §14.2-4): GOYOKH01 and GOYOKS01 parse in full
    /// and need a touch, a damaged one is AUTH_ERROR like any damaged file,
    /// GOYOKH02 and GOYOKS02 are newer, and no relabel opens.
    #[test]
    fn security_key_files_parse_in_full_and_need_a_touch() {
        set_kdf_profile(KdfProfile::Test);
        let derives = derive_count();
        for d in [kh(), ks()] {
            let f = file(&d.bytes()).unwrap();
            assert!(f.needs_security_key() && f.refusal().is_none());
            assert_eq!(f.vault_id(), Some(seq(0x10)));
            assert_eq!(
                f.open("any password", None).err(),
                Some(SECURITY_KEY_NEEDED)
            );
        }
        assert!(file(&ks().bytes()).unwrap().uses_otp());
        assert_eq!(take_failed_at(), None);
        for magic in [
            b"GOYOKH02",
            b"GOYOKS02",
            b"GOYOKH10",
            b"GOYOKE04",
            b"GOYOKX01",
        ] {
            let bytes = [magic.as_slice(), &kh().bytes()[8..]].concat();
            assert_eq!(file(&bytes).err(), Some(NEWER_KEY_FORMAT));
            assert!(never_replaced(&bytes));
        }
        let mut flipped = kh().bytes();
        flipped[38] = 10;
        for bytes in [
            kh().bytes()[..100].to_vec(),
            flipped,
            [b"GOYOKHzz".as_slice(), &kh().bytes()[8..]].concat(),
            [b"GOYOKH00".as_slice(), &kh().bytes()[8..]].concat(),
            b"GOYOKS01".to_vec(),
        ] {
            assert_eq!(file(&bytes).err(), Some(AUTH_ERROR));
            assert!(!never_replaced(&bytes));
        }
        let mut over = kh().bytes();
        over.resize(super::super::KEY_FILE_LIMIT + 1, 0);
        assert_eq!(file(&over).err(), Some(TOO_LARGE));
        assert_eq!(derive_count(), derives);
        // The relabels between the two hardware magics: a GOYOKH01 without
        // PIN mode is no GOYOKS01, and a GOYOKS01 read as GOYOKH01 opens
        // for no key (the magic is in every S-wrap's context and the body's).
        let (kh_r, ks_r) = (recorded_kh(), recorded_ks());
        let relabelled = [b"GOYOKS01".as_slice(), &kh_r.bytes[8..]].concat();
        assert_eq!(file(&relabelled).err(), Some(AUTH_ERROR));
        let relabelled = [b"GOYOKH01".as_slice(), &ks_r.bytes[8..]].concat();
        let f = file(&relabelled).unwrap();
        let fake = ks_r.fake(false);
        for j in [0, 1, 2] {
            assert_eq!(
                f.open(ks_r.password, Some(&ks_r.touch(&fake, j))).err(),
                Some(AUTH_ERROR)
            );
        }
        // A hardware file relabelled GOYOKE03 breaks its grammar.
        let relabelled = [b"GOYOKE03".as_slice(), &ks_r.bytes[8..]].concat();
        assert_eq!(file(&relabelled).err(), Some(AUTH_ERROR));
    }

    /// A plan the parse would refuse, or one missing a factor, is refused
    /// before any draw or Argon2.
    #[test]
    fn seal_refuses_a_plan_without_its_factors() {
        set_kdf_profile(KdfProfile::Test);
        let r = recorded_kh();
        let fake = r.fake(false);
        let (touches, _) = plan_parts(&r, &fake);
        let s = Secret::random().unwrap();
        let base = || KeysPlan {
            sync: false,
            pin: false,
            s: &s,
            slots: r.slots(),
            authorizer: 1,
            present: 0b11,
            suspended: 0,
            pairs: pair_plans(&r, |_, _| true),
            outputs: outputs(&r, &touches),
            inbox: Vec::new(),
        };
        let derives = derive_count();
        let bad: [fn(&mut KeysPlan); 9] = [
            |p| p.slots.clear(),
            |p| p.authorizer = 2,
            |p| p.authorizer = 9,
            |p| p.present = 0b01,
            |p| p.suspended = 0b10,
            |p| p.present = 0b111,
            |p| {
                p.outputs.pop();
            },
            |p| p.slots[0].credhash = [0; 16],
            |p| {
                p.pairs.push(PairPlan::New {
                    owner: [1; 16],
                    target: [2; 16],
                })
            },
        ];
        for (i, change) in bad.into_iter().enumerate() {
            let mut plan = base();
            change(&mut plan);
            assert_eq!(
                seal(&r.spec, &r.bundle(), "p", Plan::Keys(&plan)).err(),
                Some(NOT_SEALED),
                "case {i}"
            );
        }
        assert_eq!(derive_count(), derives);
        // An absent key needs its inbox key, and a present one none.
        let mut plan = base();
        plan.present = 0b10;
        assert_eq!(
            seal(&r.spec, &r.bundle(), "p", Plan::Keys(&plan)).err(),
            Some(NOT_SEALED)
        );
        let plan = base();
        assert!(seal(&r.spec, &r.bundle(), "p", Plan::Keys(&plan)).is_ok());
    }
}
