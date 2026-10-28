//! Adopt, "새 열쇠 파일 받기" (spec §5.8): another PC's key file of this
//! vault, taken in after a re-authentication. A file that descends from this
//! PC's key file is taken as it is (the successor re-seal: its state and key
//! code stay, only the seal block is this PC's); any other file that passes
//! the checks is joined with this PC's into a union (kind 9) under a fresh
//! data key, so no data key of the other file's choice ever becomes current.
//! Both write through the key-change engine (S0-S5), so a crash anywhere
//! leaves a pair that opens. This build adopts password-only key files: the
//! gate, the fork options and the security-key rules join with the
//! security-key build.
use super::{
    super::{
        ANCHOR_DOWNGRADE, Session, anchor,
        keyfile::{
            self, Bundle, Code, EPOCH_LIMIT, EPOCH_MAX, EPOCH_WINDOW, KeyFile, KeyHeader, KeyState,
            Kind, MAX_KEYS, Opened, Plan, Spec, TOMB_MAX, TOMBSTONES_FULL, Tombstone, Touch,
            key_code, key_id,
        },
        refuse, sha256,
    },
    Built, Consent, KEY_CHANGED, NOT_VERIFIED, REAUTH_MAX, REAUTH_STALE, Reauth, Rekeyed,
    fresh_pw_id,
};
use crate::crypto::{self, AUTH_ERROR, Key, Result, ct_eq};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// The other file is this PC's key file already: nothing is written.
pub const ADOPT_EQUAL: &str = "이미 같은 열쇠 파일입니다.";
/// The other file is an earlier state of this PC's.
pub const ADOPT_OLDER: &str = "이 열쇠 파일은 이 PC의 열쇠 파일보다 오래되었습니다.";
/// Everything the other file holds, this PC's holds too: nothing is written.
pub const ADOPT_CONTAINED: &str = "이 PC의 열쇠 파일에 이미 모두 들어 있습니다.";
/// Another vault's key file, or one whose ID key, OTP flag or TOTP secret
/// is not this vault's.
pub const NOT_THIS_VAULT: &str = "이 열쇠 파일은 이 금고의 것이 아닙니다.";
/// S-ADOPT-REFUSED, filled with one of the reasons below.
pub const ADOPT_REFUSED: &str = "이 열쇠 파일은 받지 않았습니다({reason}). 이 PC의 열쇠 파일과 맞지 않는 변경이 들어 있어 손상되었거나 위조되었을 수 있습니다. 다른 PC에서 바꾼 것이 맞다면 그 PC의 최신 열쇠 파일을 다시 가져오세요.";
/// More than EPOCH_WINDOW above what this PC's files prove.
const TOO_FAR: &str = "수정 번호가 너무 큼";
/// A removal this PC's key file carries is missing, outside the removals a
/// fork's branch never saw.
const LACKS_REMOVAL: &str = "제거 기록이 빠짐";
/// S-ADOPT-ROLLBACK, filled with the confirmed epoch: during a local
/// rollback only a file that descends from the confirmed state is taken.
pub const ADOPT_ROLLBACK: &str = "이 PC는 지금 이 PC가 전에 쓴 것(수정 {old})보다 오래된 열쇠 파일로 열려 있어, 그 최신 열쇠 파일에서 이어지지 않은 열쇠 파일은 받지 않았습니다. 이 PC가 전에 쓴 최신 열쇠 파일(열쇠 백업)로 다시 연 뒤 받으세요. 지금 열쇠 파일이 맞다면 먼저 '열쇠 관리'에서 [이 열쇠 파일이 맞습니다]를 누르세요.";
/// What was checked and previewed is not what the write found.
const ADOPT_STALE: &str = "받을 열쇠 파일을 확인한 뒤에 이 PC의 열쇠 파일이나 그 파일이 바뀌었습니다. 처음부터 다시 하세요.";

/// Where the other key file comes from. The server's file and the login's
/// join with key-file sync.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Source {
    File(PathBuf),
}
/// The gate an adopt passed (spec §7.15a), bound to the file it was asked
/// for: the preview and the write refuse any other file. This build has no
/// gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GatePass {
    NotNeeded { epoch: u64, tag: [u8; 16] },
}
impl GatePass {
    /// The pass of a file that needs no gate.
    pub fn none(check: &AdoptCheck) -> Self {
        Self::NotNeeded {
            epoch: check.other.epoch,
            tag: check.other.tag,
        }
    }
}
/// Which password a union keeps (spec §5.8): the other file's (the default)
/// or this PC's ("이 PC의 비밀번호 쓰기").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnionPassword {
    Other,
    Own,
}
/// The removal the lost-key flow adds to a union (security-key build);
/// none exists in this one.
pub enum LostKeyAddOn {}
/// What the user answered before [받기] (spec §5.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Acks {
    /// S-ADOPT-PWONLY: a vault with security keys made password-only. Never
    /// asked here.
    pub password_only: bool,
    pub union_password: UnionPassword,
    /// S-ADOPT-BOTHPASS answered yes, where the preview asks it.
    pub both_passwords: bool,
}
/// How the other file stands against this PC's (spec §5.8). Older and every
/// refusal are errors of `adopt_check`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdoptClass {
    /// The same state: nothing to write.
    Equal,
    /// Nothing this PC's key file lacks: nothing to write.
    Contained,
    /// A later state of this PC's: taken as it is.
    Successor,
    /// Joined with this PC's under a fresh data key (kind 9).
    Union,
}
/// What the public checks found (spec §5.8), before any password.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AdoptCheck {
    pub class: AdoptClass,
    /// The other file's state.
    pub other: KeyState,
    /// The two files split from a shared state (a fork).
    pub fork: bool,
    /// For a fork: whether this PC and the other side changed the password
    /// since the shared state; None when the shared state is not in this
    /// PC's history.
    pub changed_pw: Option<(bool, bool)>,
    /// The result's epoch: the other file's for a successor, above both
    /// files and this PC's floor for a union.
    pub epoch: u64,
}
/// The other file, opened (spec §5.8 "Opening the other file"): its keys
/// and the password that opened it. Built only by `adopt_open`. Zeroized on
/// drop.
pub struct OtherOpened {
    opened: Opened,
    password: Zeroizing<String>,
    /// SHA-256 of the bytes it opened.
    sha: [u8; 32],
}
/// What the preview shows (spec §9.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Preview {
    pub class: AdoptClass,
    /// The result's epoch.
    pub epoch: u64,
    /// The result's key code: a successor's only, which is the other file's
    /// (a union's exists only once it is written, S23-2 #13).
    pub code: Option<Code>,
    /// A union's check box "이 PC의 비밀번호 쓰기" and whether it starts
    /// ticked; None where there is nothing to choose (the two passwords are
    /// the same, or the other file descends from this PC's, whose password
    /// change must not be undone).
    pub own_pass: Option<bool>,
    /// [받기] asks S-ADOPT-BOTHPASS first: both sides changed the password
    /// since the shared state, or that state is not in this PC's history.
    pub both_passwords: bool,
}
/// An adopt checked, opened and previewed, for `adopt` to write. Bound to
/// its session and screen like the Reauth (spec §5.3).
pub struct AdoptPlan {
    check: AdoptCheck,
    gate: GatePass,
    /// The other file as it was checked and opened: what is written.
    path: PathBuf,
    bytes: Vec<u8>,
    other: OtherOpened,
    /// The two passwords are the same.
    equal: bool,
    preview: Preview,
    session: u64,
    app_serial: u64,
}
impl AdoptPlan {
    pub fn preview(&self) -> &Preview {
        &self.preview
    }
}
/// Which password opens the vault from now on (S-ADOPT-PASS-OWN, -OTHER).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PassInForce {
    Own,
    Other,
}
/// What an adopt wrote (spec §5.8).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Adopted {
    pub state: KeyState,
    /// The key code of the result (S-ADOPT-CODE).
    pub code: Code,
    pub password: PassInForce,
    /// The vault file could not be saved under the new key yet
    /// (S-VPENDING).
    pub vault_pending: bool,
    /// S3 ended in a replace gap: the app locks, as after a password change
    /// (S-GAP-CHANGED).
    pub gap_kept: bool,
}

/// What a key file states before it opens, for the checks of an adopt: its
/// state, its key IDs (the current key first, the ID key last), its
/// removals, its `pw_id` and its next key number. A 0.8 key file states
/// none of them: its one key is the vault's ID key, so they follow from
/// this PC's.
struct Public {
    state: KeyState,
    ids: Vec<[u8; 16]>,
    tombs: Vec<Tombstone>,
    pw_id: Option<[u8; 16]>,
    next: u8,
}
impl Public {
    fn of(h: &KeyHeader) -> Self {
        Self {
            state: h.state(),
            ids: h.key_ids.clone(),
            tombs: h.tombstones.clone(),
            pw_id: Some(h.pw_id),
            next: h.next,
        }
    }
}

impl Session {
    /// The public checks of an adopt (spec §5.8), before any password: the
    /// other file's class and the result's epoch, or why it is refused.
    /// Equal and Contained write nothing; Older is refused.
    pub fn adopt_check(&self, other: &KeyFile, source: Source) -> Result<AdoptCheck> {
        let Source::File(_) = source;
        self.held()?;
        let own = self.own_public();
        let theirs = self.other_public(other)?;
        let line = self.anchor.lines.vault.as_ref();
        // A vault this PC pins as hardware takes a password-only file only
        // through the security-key build's gate.
        if line.is_some_and(|l| l.state.hardware()) {
            return Err(ANCHOR_DOWNGRADE);
        }
        let a = line.map_or(0, |l| l.state.epoch);
        let check = |class, fork, changed_pw, epoch| AdoptCheck {
            class,
            other: theirs.state,
            fork,
            changed_pw,
            epoch,
        };
        if theirs.state == own.state {
            return Ok(check(AdoptClass::Equal, false, None, own.state.epoch));
        }
        let lists = |set: &[Tombstone], c: &[u8; 16]| set.iter().any(|t| t.credhash == *c);
        let removals_known = theirs.tombs.iter().all(|t| lists(&own.tombs, &t.credhash));
        // A state of this PC's history, with a key this PC still holds.
        if theirs.state.epoch < own.state.epoch
            && line.is_some_and(|l| l.state.had(theirs.state))
            && own.ids[1..].contains(&theirs.ids[0])
            && removals_known
        {
            return Err(ADOPT_OLDER);
        }
        if theirs.state.epoch <= own.state.epoch
            && theirs.ids.iter().all(|i| own.ids.contains(i))
            && removals_known
        {
            return Ok(check(AdoptClass::Contained, false, None, own.state.epoch));
        }
        // Written by a holder of this PC's current data key: a descendant,
        // unless it is a sibling at or below this PC's epoch.
        let chained = other.chain_ok(self.keys.current());
        let fork = !chained
            || theirs.state.epoch < own.state.epoch
            || (theirs.state.epoch == own.state.epoch && theirs.ids[0] == own.ids[0]);
        // Never below what this PC's files prove, nor below the state it
        // confirmed (S23-2 #4).
        let successor = !fork && theirs.state.epoch >= self.max_epoch && theirs.state.epoch >= a;
        // During a local rollback only the confirmed state, or a file above
        // it that holds its current key, is taken; the open proves the key
        // (S23-3 #4). A union is never written then.
        if self.local_rollback {
            let descends = line.is_some_and(|l| {
                theirs.state == l.state.key_state()
                    || (theirs.state.epoch > a && theirs.ids.contains(&l.state.keyid))
            });
            if !descends || !successor {
                return Err(refuse(ADOPT_ROLLBACK, vec![a.to_string()]));
            }
        }
        if theirs.state.epoch > self.max_epoch.saturating_add(EPOCH_WINDOW) {
            return Err(refuse(ADOPT_REFUSED, vec![TOO_FAR.to_owned()]));
        }
        // P3 (b): every removal this PC's key file carries, but in a fork
        // the ones made since it split, which its branch never saw: their
        // recorded key ID is not in its list (spec §5.8 "Forks").
        let since_fork = |t: &Tombstone| {
            line.and_then(|l| l.state.tombs.iter().find(|x| x.credhash == t.credhash))
                .is_some_and(|x| x.keyid != [0; 4] && !theirs.ids.iter().any(|i| i[..4] == x.keyid))
        };
        if !own
            .tombs
            .iter()
            .filter(|t| !lists(&theirs.tombs, &t.credhash))
            .all(|t| fork && since_fork(t))
        {
            return Err(refuse(ADOPT_REFUSED, vec![LACKS_REMOVAL.to_owned()]));
        }
        if successor {
            return Ok(check(
                AdoptClass::Successor,
                false,
                None,
                theirs.state.epoch,
            ));
        }
        // A union: above both files, this PC's floor and its confirmed
        // state, with every removal of both.
        let epoch = own
            .state
            .epoch
            .max(theirs.state.epoch)
            .max(self.max_epoch)
            .max(a)
            .checked_add(1)
            .filter(|e| *e <= EPOCH_MAX)
            .ok_or(EPOCH_LIMIT)?;
        if joined_tombs(&own.tombs, &theirs.tombs).len() > TOMB_MAX {
            return Err(TOMBSTONES_FULL);
        }
        // The shared state of a fork: the newest state of this PC's history
        // whose current key the other file holds. A side changed the
        // password since when its `pw_id` differs from that state's.
        let changed_pw = fork
            .then(|| {
                let shared = line?
                    .state
                    .hist
                    .iter()
                    .find(|h| theirs.ids.iter().any(|i| i[..4] == h.keyid))?;
                let changed = |pw_id: Option<[u8; 16]>| {
                    anchor::prefix::<4>(&pw_id.unwrap_or_default()) != shared.pwid
                };
                Some((changed(own.pw_id), changed(theirs.pw_id)))
            })
            .flatten();
        Ok(check(AdoptClass::Union, fork, changed_pw, epoch))
    }
    /// Opens the other file (spec §5.8): with this PC's password from the
    /// Reauth (`password` None), else with the one the user typed for it
    /// (S-NEWPASS-OTHER). AUTH_ERROR when it does not open; then the same
    /// ID key and the same TOTP secret, compared in constant time.
    pub fn adopt_open(
        &self,
        r: &Reauth,
        other: &KeyFile,
        password: Option<&str>,
    ) -> Result<OtherOpened> {
        if r.session != self.serial || r.created.elapsed() > REAUTH_MAX {
            return Err(REAUTH_STALE);
        }
        let password = password.unwrap_or(&r.password);
        if password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        let opened = other.open(password, None)?;
        let otp = match (opened.bundle.otp(), self.keys.otp()) {
            (Some(a), Some(b)) => ct_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        };
        if !ct_eq(opened.bundle.id_key(), self.keys.id_key()) || !otp {
            return Err(NOT_THIS_VAULT);
        }
        Ok(OtherOpened {
            opened,
            password: Zeroizing::new(password.to_owned()),
            sha: sha256(other.bytes()),
        })
    }
    /// The preview of an adopt (spec §5.8): the checks again for exactly the
    /// file `gate` names and `opened` opened, the successor's key code, and
    /// which password a union offers. Nothing is written.
    pub fn adopt_preview(
        &self,
        r: &Reauth,
        other: &KeyFile,
        opened: OtherOpened,
        check: &AdoptCheck,
        gate: GatePass,
        lost: Option<LostKeyAddOn>,
    ) -> Result<AdoptPlan> {
        if let Some(lost) = lost {
            match lost {}
        }
        if r.session != self.serial || r.created.elapsed() > REAUTH_MAX {
            return Err(REAUTH_STALE);
        }
        let GatePass::NotNeeded { epoch, tag } = gate;
        let now = self.adopt_check(other, Source::File(other.path().to_owned()))?;
        if (KeyState { epoch, tag }) != now.other
            || now != *check
            || opened.sha != sha256(other.bytes())
        {
            return Err(ADOPT_STALE);
        }
        let equal = ct_eq(r.password.as_bytes(), opened.password.as_bytes());
        let (code, own_pass, both_passwords) = match check.class {
            AdoptClass::Equal => return Err(ADOPT_EQUAL),
            AdoptClass::Contained => return Err(ADOPT_CONTAINED),
            AdoptClass::Successor => (
                Some(key_code(
                    &self.id,
                    opened.opened.bundle.current(),
                    now.other,
                )),
                None,
                false,
            ),
            // The same password, or a file that descends from this PC's: the
            // other file's password (spec §5.8 rule (2)).
            AdoptClass::Union if equal || !check.fork => (None, None, false),
            // A fork: the password of the side that changed it since the
            // shared state (rule (3)), else the other file's (rule (4)).
            AdoptClass::Union => match check.changed_pw {
                Some((true, false)) => (None, Some(true), false),
                Some((false, _)) => (None, Some(false), false),
                _ => (None, Some(false), true),
            },
        };
        Ok(AdoptPlan {
            check: now,
            gate,
            path: other.path().to_owned(),
            bytes: other.bytes().to_vec(),
            other: opened,
            equal,
            preview: Preview {
                class: check.class,
                epoch: check.epoch,
                code,
                own_pass,
                both_passwords,
            },
            session: self.serial,
            app_serial: r.app_serial,
        })
    }
    /// Writes the adopt `plan` (spec §5.8) through the key-change engine:
    /// the successor re-sealed with this PC's seal block, or the union. The
    /// checks run again first; anything changed since the preview writes
    /// nothing. `extra` and `consent` belong to the security-key build, and
    /// no gate holds an adopt here.
    pub fn adopt(
        &mut self,
        r: Reauth,
        plan: AdoptPlan,
        extra: Vec<Touch>,
        acks: Acks,
        consent: Consent,
        override_gate: bool,
    ) -> Result<Adopted> {
        let _ = override_gate;
        if r.session != self.serial
            || plan.session != self.serial
            || r.app_serial != plan.app_serial
            || r.created.elapsed() > REAUTH_MAX
            || (self.uses_otp() && r.otp_step.is_none())
        {
            return Err(REAUTH_STALE);
        }
        if !extra.is_empty() || !consent.suspend.is_empty() || acks.password_only {
            return Err(AUTH_ERROR);
        }
        let other = KeyFile::from_bytes(&plan.path, plan.bytes.clone())?;
        let GatePass::NotNeeded { epoch, tag } = plan.gate;
        if self.adopt_check(&other, Source::File(plan.path.clone()))? != plan.check
            || (KeyState { epoch, tag }) != plan.check.other
        {
            return Err(ADOPT_STALE);
        }
        if !self.key_on_disk()? {
            return Err(KEY_CHANGED);
        }
        // Where the preview asked S-ADOPT-BOTHPASS, only a yes writes.
        if plan.preview.both_passwords && !acks.both_passwords {
            return Err(ADOPT_STALE);
        }
        let keep_own = plan.preview.own_pass.is_some() && acks.union_password == UnionPassword::Own;
        let same = plan.equal || keep_own;
        let built = match plan.check.class {
            AdoptClass::Successor => self.successor_of(&other, &plan.other)?,
            AdoptClass::Union => {
                let password: &str = if keep_own {
                    &r.password
                } else {
                    &plan.other.password
                };
                let keep = (keep_own, plan.equal);
                self.union_with(&other, &plan.other, plan.check.epoch, password, keep)?
            }
            AdoptClass::Equal => return Err(ADOPT_EQUAL),
            AdoptClass::Contained => return Err(ADOPT_CONTAINED),
        };
        let rekeyed = self.land(
            built,
            anchor::Src::Adopt,
            (!same).then_some(anchor::Pw::Other),
        )?;
        drop(r);
        Ok(Adopted {
            state: self.key_state,
            code: key_code(&self.id, self.keys.current(), self.key_state),
            password: if same {
                PassInForce::Own
            } else {
                PassInForce::Other
            },
            vault_pending: rekeyed == Rekeyed::VaultPending,
            gap_kept: rekeyed == Rekeyed::GapKept,
        })
    }
    /// The successor re-seal (spec §5.8): the other file's `[0, W)` byte for
    /// byte, so its state and key code stay; this PC's seal block, which
    /// names V_probe when the data key changes. Sealed with the password
    /// that opened it.
    fn successor_of(&self, other: &KeyFile, opened: &OtherOpened) -> Result<Built> {
        let h = other.header().ok_or(AUTH_ERROR)?;
        let bundle = &opened.opened.bundle;
        let probe = if ct_eq(bundle.current(), self.keys.current()) {
            None
        } else {
            Some(self.encode()?)
        };
        let mut spec = h.spec();
        spec.resume = probe.as_deref().map_or([0; 32], sha256);
        let plan = Plan::Reseal {
            source: other,
            opened: &opened.opened,
        };
        let (bytes, writer) = keyfile::seal(&spec, bundle, &opened.password, plan)?;
        let built = self.built(bytes, &writer, &spec, bundle, probe)?;
        // I9: the state stays the other file's.
        if built.kh.state() != h.state() {
            return Err(NOT_VERIFIED);
        }
        Ok(built)
    }
    /// The union (kind 9, spec §5.8): a fresh data key first, then this
    /// PC's keys, then the other file's that this PC lacks, and the ID key
    /// last; every removal of both files; sealed with `password`, the other
    /// file's or this PC's (`keep_own`), with the other file's `pw_id` when
    /// the two passwords are the same (`equal`).
    fn union_with(
        &self,
        other: &KeyFile,
        opened: &OtherOpened,
        epoch: u64,
        password: &str,
        (keep_own, equal): (bool, bool),
    ) -> Result<Built> {
        let own = self.own_public();
        let theirs = self.other_public(other)?;
        let probe = self.encode()?;
        let resume = sha256(&probe);
        let id = &self.id;
        let ours = self.keys.keys();
        let others = opened.opened.bundle.keys();
        let known: Vec<[u8; 16]> = ours.iter().chain(others).map(|k| key_id(id, k)).collect();
        // Never a data key either file ever held.
        let mut dk: Box<Key> = Box::default();
        loop {
            crypto::random_into(dk.as_mut_slice())?;
            if !known.contains(&key_id(id, &dk)) {
                break;
            }
        }
        // Sized up front: a growing Vec would free unwiped copies.
        let mut keys = Zeroizing::new(Vec::with_capacity(ours.len() + others.len() + 1));
        keys.push(**dk);
        keys.extend_from_slice(&ours[..ours.len() - 1]);
        let mine = &known[..ours.len()];
        for key in &others[..others.len() - 1] {
            if !mine.contains(&key_id(id, key)) {
                keys.push(*key);
            }
        }
        keys.push(*self.keys.id_key());
        // At most MAX_KEYS: the middle part's last entry goes first (the
        // other file's oldest, then this PC's), never the fresh key, either
        // current key or the ID key.
        let mut ids: Vec<[u8; 16]> = keys.iter().map(|k| key_id(id, k)).collect();
        let kept = [ids[0], own.ids[0], theirs.ids[0], ids[ids.len() - 1]];
        while keys.len() > MAX_KEYS {
            let at = (1..keys.len() - 1)
                .rev()
                .find(|i| !kept.contains(&ids[*i]))
                .ok_or(AUTH_ERROR)?;
            keys.remove(at);
            ids.remove(at);
        }
        let bundle = Bundle::new(&keys, self.keys.otp()).ok_or(AUTH_ERROR)?;
        // The same password takes the other file's `pw_id`, so neither PC
        // sees a password change; a 0.8 file has none to keep.
        let pw_id = match (equal, keep_own) {
            (true, _) => theirs.pw_id.or(own.pw_id),
            (false, true) => own.pw_id,
            (false, false) => theirs.pw_id,
        };
        let spec = Spec {
            vault_id: *id,
            epoch,
            kind: Kind::Union,
            next: own.next.max(theirs.next),
            pw_id: match pw_id {
                Some(pw_id) => pw_id,
                None => fresh_pw_id()?,
            },
            loss: 0,
            tombstones: joined_tombs(&own.tombs, &theirs.tombs),
            resume,
        };
        let (bytes, writer) = keyfile::seal(&spec, &bundle, password, Plan::PasswordOnly)?;
        self.built(bytes, &writer, &spec, &bundle, Some(probe))
    }
    /// What this PC's key file states, for the checks of an adopt.
    fn own_public(&self) -> Public {
        match self.key_file.header() {
            Some(h) => Public::of(h),
            None => Public {
                state: self.key_state,
                ids: vec![key_id(&self.id, self.keys.id_key())],
                tombs: Vec::new(),
                pw_id: None,
                next: 1,
            },
        }
    }
    /// What the other file states (spec §5.8, before any touch): a file of
    /// this vault with the same OTP flag (E1), which this build can open. A
    /// 0.8 file's state follows from this vault's ID key, which the open
    /// then proves it holds.
    fn other_public(&self, other: &KeyFile) -> Result<Public> {
        if let Some(refusal) = other.refusal() {
            return Err(refusal);
        }
        if other.vault_id() != Some(self.id) || other.uses_otp() != self.uses_otp() {
            return Err(NOT_THIS_VAULT);
        }
        Ok(match other.header() {
            Some(h) => Public::of(h),
            None => {
                let id_key = self.keys.id_key();
                Public {
                    state: other.legacy_state(id_key).ok_or(NOT_THIS_VAULT)?,
                    ids: vec![key_id(&self.id, id_key)],
                    tombs: Vec::new(),
                    pw_id: None,
                    next: 1,
                }
            }
        })
    }
}
/// The removals of two key files, one per credential (spec §5.8): the
/// earliest epoch, and the loss mark of either, the earlier date when both
/// have one (1, a loss on an unknown date, counts as the earliest).
fn joined_tombs(a: &[Tombstone], b: &[Tombstone]) -> Vec<Tombstone> {
    let mut out = a.to_vec();
    for t in b {
        match out.iter_mut().find(|x| x.credhash == t.credhash) {
            Some(x) => {
                let mark = match (x.loss_mark(), t.loss_mark()) {
                    (0, m) | (m, 0) => m,
                    (m, n) => m.min(n),
                };
                x.removed = x.epoch().min(t.epoch()) | u64::from(mark) << 48;
            }
            None => out.push(*t),
        }
    }
    out
}

/// Adopts of password-only key files (spec §14.4-10, the default build's
/// rows): each PC with its own anchor folder and the Test KDF profile.
#[cfg(test)]
mod tests {
    use super::super::super::{
        CRASH, GAP_KEPT, GAP_NOT_CHANGED, KeyNotice, PENDING_ELSEWHERE, RESTORE_OLDKEY,
        RESTORE_PENDING, SIMULATED_CRASH, encode_key, keyfile::NO_SECURITY_KEY_SUPPORT,
        read_header, refusal_values,
    };
    use super::super::CORRUPT;
    use super::super::tests::{
        Codes, NEW, OLD, Pc, THIRD, What, change, entry, keys_of, login, notices, other_of, sealed,
        sealed_with, secrets, set_before, setup, vault_of,
    };
    use super::*;
    use crate::otp;
    use std::{cell::RefCell, fs, path::Path, rc::Rc};

    fn file(bytes: &[u8]) -> KeyFile {
        KeyFile::from_bytes(Path::new("other.goyokey"), bytes.to_vec()).unwrap()
    }
    fn classify(s: &Session, bytes: &[u8]) -> Result<AdoptCheck> {
        let f = file(bytes);
        s.adopt_check(&f, Source::File(f.path().to_owned()))
    }
    /// The answers that take the preview's defaults, and yes to
    /// S-ADOPT-BOTHPASS where it is asked.
    fn defaults(p: &Preview) -> Acks {
        Acks {
            password_only: false,
            union_password: UnionPassword::Other,
            both_passwords: p.both_passwords,
        }
    }
    /// The whole adopt of `other` as the flow runs it (spec §9.2): the
    /// checks, a Reauth with this PC's password `mine`, the open with `mine`
    /// first and then `theirs` (S-NEWPASS-OTHER), the preview, and the
    /// write with what `answer` makes of the preview.
    fn take(
        s: &mut Session,
        codes: &mut Codes,
        mine: &str,
        other: &[u8],
        theirs: &str,
        answer: impl FnOnce(&Preview) -> Acks,
    ) -> Result<Adopted> {
        let f = file(other);
        let check = s.adopt_check(&f, Source::File(f.path().to_owned()))?;
        let (code, typed) = codes.next();
        let r = s.reauth(mine, Some((&code, typed)), None)?;
        let opened = match s.adopt_open(&r, &f, None) {
            Err(e) if e == AUTH_ERROR => s.adopt_open(&r, &f, Some(theirs))?,
            opened => opened?,
        };
        let plan = s.adopt_preview(&r, &f, opened, &check, GatePass::none(&check), None)?;
        let acks = answer(plan.preview());
        s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
    }
    /// The key file and the anchor of `pc`: what an adopt that writes
    /// nothing leaves as it was (a Reauth of an OTP vault saves the vault
    /// file with the code's step).
    fn key_and_anchor(pc: &Pc) -> (Vec<u8>, Vec<u8>) {
        (fs::read(pc.key()).unwrap(), pc.anchor())
    }
    /// A second PC with copies of `a`'s vault file and key file.
    fn copy_of(a: &Pc) -> Pc {
        let b = Pc::new();
        fs::copy(a.vault(), b.vault()).unwrap();
        fs::copy(a.key(), b.key()).unwrap();
        b
    }
    fn key_ids(id: &[u8; 16], keys: &[[u8; 32]]) -> Vec<[u8; 16]> {
        keys.iter().map(|k| key_id(id, k)).collect()
    }

    /// Only this vault's key files are taken (spec §5.8): another vault ID,
    /// another OTP flag (E1) and a security-key file are refused before any
    /// key derivation; another ID key or TOTP secret once the file opens.
    /// Nothing is written.
    #[test]
    fn only_this_vaults_key_files_are_taken() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, true, false);
        let id = s.id;
        let secret = *s.keys.otp().unwrap();
        let keys = s.keys.keys().to_vec();
        let before = key_and_anchor(&pc);
        let (another, _) = sealed_with([0x11; 16], &[[0x51; 32]], Some(&secret), 2, &[], NEW);
        let later = [&[[0x53; 32]][..], &keys].concat();
        let (no_otp, _) = sealed_with(id, &later, None, 2, &[], NEW);
        let hardware = keyfile::hardware_draft(false);
        let derived = crypto::derive_count();
        assert_eq!(classify(&s, &another).err(), Some(NOT_THIS_VAULT));
        assert_eq!(classify(&s, &no_otp).err(), Some(NOT_THIS_VAULT));
        assert_eq!(classify(&s, &hardware).err(), Some(NO_SECURITY_KEY_SUPPORT));
        assert_eq!(crypto::derive_count(), derived);
        let (other_id_key, _) =
            sealed_with(id, &[[0x54; 32], [0x55; 32]], Some(&secret), 2, &[], NEW);
        let (other_secret, _) = sealed_with(id, &later, Some(&[0x77; 20]), 2, &[], NEW);
        for other in [other_id_key, other_secret] {
            assert!(classify(&s, &other).is_ok());
            let taken = take(&mut s, &mut codes, OLD, &other, NEW, defaults);
            assert_eq!(taken.err(), Some(NOT_THIS_VAULT));
        }
        assert_eq!(key_and_anchor(&pc), before);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// An earlier state of this PC is Older, refused; the same state and a
    /// file whose every key and removal this PC holds write nothing (spec
    /// §5.8). Decided before any key derivation.
    #[test]
    fn older_equal_and_contained_files_write_nothing() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, false, false);
        let id = s.id;
        let k1 = fs::read(pc.key()).unwrap();
        let k0 = encode_key(&id, s.keys.id_key(), None, "synthetic first password").unwrap();
        assert_eq!(change(&mut s, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
        let k2 = fs::read(pc.key()).unwrap();
        let keys2 = s.keys.keys().to_vec();
        let (k1x, _) = sealed(id, &keys2[1..], 1, &[], THIRD);
        let before = super::super::tests::files(&pc);
        let derived = crypto::derive_count();
        assert_eq!(classify(&s, &k1).err(), Some(ADOPT_OLDER));
        assert_eq!(classify(&s, &k0).err(), Some(ADOPT_OLDER));
        assert_eq!(classify(&s, &k2).map(|c| c.class), Ok(AdoptClass::Equal));
        assert_eq!(
            classify(&s, &k1x).map(|c| c.class),
            Ok(AdoptClass::Contained)
        );
        assert_eq!(crypto::derive_count(), derived);
        let equal = take(&mut s, &mut codes, NEW, &k2, NEW, defaults);
        assert_eq!(equal.err(), Some(ADOPT_EQUAL));
        let contained = take(&mut s, &mut codes, NEW, &k1x, THIRD, defaults);
        assert_eq!(contained.err(), Some(ADOPT_CONTAINED));
        assert_eq!(super::super::tests::files(&pc), before);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A successor (another PC's password change of the shared key file) is
    /// re-sealed at the same epoch (spec §5.8): the same state and key code,
    /// which the preview shows, and this PC's own resume digest. The other
    /// file's password opens the vault from then on; the vault's identity
    /// (its ID key, the entry IDs) stays.
    #[test]
    fn a_successor_is_taken_as_it_is() {
        let a = Pc::new();
        let (mut s, mut codes) = setup(&a, true, false, false);
        let id = s.id;
        let id_key = *s.keys.id_key();
        let ids: Vec<[u8; 16]> = s.entries.iter().map(|e| e.id()).collect();
        let b = copy_of(&a);
        let mut sb = login(&b, OLD, &mut codes).unwrap();
        assert_eq!(change(&mut sb, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
        drop(sb);
        let kb = fs::read(b.key()).unwrap();
        let hb = keyfile::parse(&kb).unwrap();
        let dkb = keys_of(&kb, NEW)[0];
        a.here();
        let f = file(&kb);
        let check = s
            .adopt_check(&f, Source::File(f.path().to_owned()))
            .unwrap();
        assert_eq!(
            (check.class, check.epoch, check.fork),
            (AdoptClass::Successor, 2, false)
        );
        let r = s
            .reauth(OLD, Some(("", otp::now().unwrap())), None)
            .unwrap();
        assert_eq!(s.adopt_open(&r, &f, None).err(), Some(AUTH_ERROR));
        let opened = s.adopt_open(&r, &f, Some(NEW)).unwrap();
        let plan = s
            .adopt_preview(&r, &f, opened, &check, GatePass::none(&check), None)
            .unwrap();
        let code = key_code(&id, &dkb, hb.state());
        assert_eq!(plan.preview().code, Some(code));
        assert_eq!(plan.preview().own_pass, None);
        let probe = Rc::new(RefCell::new(None));
        let held = probe.clone();
        let vault = a.vault();
        set_before("S2", move || *held.borrow_mut() = fs::read(&vault).ok());
        let acks = defaults(plan.preview());
        let adopted = s
            .adopt(r, plan, Vec::new(), acks, Consent::default(), false)
            .unwrap();
        assert_eq!(
            adopted,
            Adopted {
                state: hb.state(),
                code,
                password: PassInForce::Other,
                vault_pending: false,
                gap_kept: false,
            }
        );
        // The same state, and so the same key code; this PC's seal block.
        let ka = fs::read(a.key()).unwrap();
        let ha = keyfile::parse(&ka).unwrap();
        assert_eq!((ha.state(), &ha.key_ids), (hb.state(), &hb.key_ids));
        assert_ne!(ka, kb);
        assert_eq!(ha.resume, sha256(probe.borrow().as_ref().unwrap()));
        assert_ne!(ha.resume, hb.resume);
        assert_eq!(*s.keys.id_key(), id_key);
        assert_eq!(s.entries.iter().map(|e| e.id()).collect::<Vec<_>>(), ids);
        let line = a.lines(&id).vault.unwrap();
        assert_eq!(line.state.key_state(), hb.state());
        assert_eq!(line.state.gated, 2);
        drop(s);
        // The other file's password opens it now; this PC's old one does
        // not, and is told which one does only while the change waits.
        let mut s = login(&a, NEW, &mut codes).unwrap();
        assert_eq!(notices(&mut s), []);
        assert_eq!(secrets(&s), ["one", "two"]);
        drop(s);
        let refused = super::super::tests::refused(&a, OLD, &codes);
        assert_eq!(refused, None);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A file at this PC's epoch that holds this PC's current key under
    /// another current one is a successor (spec §5.8), taken at that epoch;
    /// one with this PC's current key as its own is a fork, joined above it.
    #[test]
    fn a_sibling_at_the_same_epoch_that_holds_this_pcs_key_is_a_successor() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, false, false);
        let id = s.id;
        let keys = s.keys.keys().to_vec();
        let (past, state) = sealed(id, &[&[[0x5e; 32]][..], &keys].concat(), 1, &[], NEW);
        let (same_key, _) = sealed(id, &[keys[0], [0x5f; 32], keys[1]], 1, &[], NEW);
        let fork = classify(&s, &same_key).unwrap();
        assert_eq!(
            (fork.class, fork.fork, fork.epoch),
            (AdoptClass::Union, true, 2)
        );
        let adopted = take(&mut s, &mut codes, OLD, &past, NEW, defaults).unwrap();
        assert_eq!((adopted.state, s.max_epoch()), (state, 1));
        drop(s);
        let mut s = login(&pc, NEW, &mut codes).unwrap();
        assert_eq!(notices(&mut s), []);
        assert_eq!(pc.lines(&id).vault.unwrap().state.key_state(), state);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A successor that keeps this PC's data key (spec §5.8): no V_probe,
    /// no resume; the vault file is saved again with the new state, and a
    /// crash before that leaves it to the next unlock (spec §5.6).
    #[test]
    fn a_successor_that_keeps_the_data_key_saves_the_vault_file_again() {
        for crash in [false, true] {
            let pc = Pc::new();
            let (mut s, mut codes) = setup(&pc, true, false, false);
            let id = s.id;
            let (k2, state2) = sealed(id, s.keys.keys(), 2, &[], NEW);
            if crash {
                CRASH.with(|c| c.set(Some("S2v")));
                let taken = take(&mut s, &mut codes, OLD, &k2, NEW, defaults);
                assert_eq!(taken.err(), Some(SIMULATED_CRASH));
                drop(s);
                s = login(&pc, NEW, &mut codes).unwrap();
                assert_eq!(notices(&mut s), []);
            } else {
                let taken = take(&mut s, &mut codes, OLD, &k2, NEW, defaults).unwrap();
                assert!(!taken.vault_pending);
            }
            let h = keyfile::parse(&fs::read(pc.key()).unwrap()).unwrap();
            assert_eq!((h.state(), h.resume), (state2, [0; 32]));
            let (_, header) = read_header(&fs::read(pc.vault()).unwrap()).unwrap();
            assert_eq!(header, s.header());
            let line = pc.lines(&id).vault.unwrap();
            assert_eq!(line.state.key_state(), state2);
            assert!(pc.lines(&id).pending.is_none());
            assert_eq!(secrets(&s), ["one", "two"]);
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// Two PCs that each changed the password from the same 0.8 key file
    /// have forked; B joins A's file in a union (spec §5.8, S23-1 #1):
    /// `[DK_u, DK_B, DK_A, ID]` under a fresh key, the ID key last, sealed
    /// with the password B chose. A takes the union as a successor, and the
    /// 0.8 backup still restores with it on both PCs.
    #[test]
    fn a_fork_is_joined_under_a_fresh_key_and_taken_back_as_a_successor() {
        for keep_own in [false, true] {
            let a = Pc::new();
            let (mut sa, mut codes) = setup(&a, false, false, false);
            let id = sa.id;
            let id_key = *sa.keys.id_key();
            let backup = a.file("backup-08.goyo");
            sa.backup(&backup).unwrap();
            let b = copy_of(&a);
            assert_eq!(change(&mut sa, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
            let ka = fs::read(a.key()).unwrap();
            let dka = *sa.keys.current();
            drop(sa);
            let mut sb = login(&b, OLD, &mut codes).unwrap();
            assert_eq!(change(&mut sb, &mut codes, OLD, THIRD), Ok(Rekeyed::Done));
            let dkb = *sb.keys.current();
            let check = classify(&sb, &ka).unwrap();
            assert_eq!(
                (check.class, check.fork, check.changed_pw, check.epoch),
                (AdoptClass::Union, true, Some((true, true)), 2)
            );
            let mut asked = None;
            let adopted = take(&mut sb, &mut codes, THIRD, &ka, NEW, |p| {
                asked = Some(p.clone());
                Acks {
                    union_password: if keep_own {
                        UnionPassword::Own
                    } else {
                        UnionPassword::Other
                    },
                    ..defaults(p)
                }
            })
            .unwrap();
            let asked = asked.unwrap();
            assert_eq!(
                (asked.code, asked.own_pass, asked.both_passwords),
                (None, Some(false), true)
            );
            let (pass, in_force) = if keep_own {
                (THIRD, PassInForce::Own)
            } else {
                (NEW, PassInForce::Other)
            };
            assert_eq!(adopted.password, in_force);
            let ku = fs::read(b.key()).unwrap();
            let hu = keyfile::parse(&ku).unwrap();
            assert_eq!((hu.kind, hu.epoch), (Kind::Union, 2));
            let keys = keys_of(&ku, pass);
            assert_eq!(&keys[1..], [dkb, dka, id_key]);
            assert!(![dka, dkb, id_key].contains(&keys[0]));
            assert_eq!(adopted.code, key_code(&id, &keys[0], hu.state()));
            let pw_id = |bytes: &[u8]| keyfile::parse(bytes).unwrap().pw_id;
            if !keep_own {
                assert_eq!(hu.pw_id, pw_id(&ka));
            }
            drop(sb);
            // A takes B's union as a successor: the same keys and state.
            let mut sa = login(&a, NEW, &mut codes).unwrap();
            let check = classify(&sa, &ku).unwrap();
            assert_eq!(check.class, AdoptClass::Successor);
            let adopted = take(&mut sa, &mut codes, NEW, &ku, pass, defaults).unwrap();
            assert_eq!(adopted.state, hu.state());
            assert_eq!(sa.keys.keys(), &keys[..]);
            drop(sa);
            // The 0.8 backup restores with the union on both PCs.
            for (pc, key) in [(&a, a.key()), (&b, b.key())] {
                pc.here();
                let dest = pc.file("restored.goyo");
                let r = Session::restore(&backup, &key, &dest, pass, "").unwrap();
                assert_eq!(secrets(&r), ["one", "two"]);
            }
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E5 runs only for a security-key own (S23-1 #5): a password that went
    /// back (P1 → P2 → P1) is a successor like any other, and two branches
    /// that set the same password are joined with no question, the union
    /// taking the other file's `pw_id`, so neither PC sees a password
    /// change.
    #[test]
    fn equal_passwords_need_no_choice() {
        // A 0.8 B takes A's file after P1 → P2 → P1.
        let a = Pc::new();
        let (mut sa, mut codes) = setup(&a, false, false, false);
        let b = copy_of(&a);
        assert_eq!(change(&mut sa, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
        assert_eq!(change(&mut sa, &mut codes, NEW, OLD), Ok(Rekeyed::Done));
        drop(sa);
        let ka = fs::read(a.key()).unwrap();
        let mut sb = login(&b, OLD, &mut codes).unwrap();
        let adopted = take(&mut sb, &mut codes, OLD, &ka, OLD, defaults).unwrap();
        assert_eq!(adopted.password, PassInForce::Own);
        assert_eq!(adopted.state, keyfile::parse(&ka).unwrap().state());
        drop(sb);
        // Both branches set NEW: a union with A's `pw_id`, and A takes it.
        let a = Pc::new();
        let (mut sa, mut codes) = setup(&a, false, false, false);
        let b = copy_of(&a);
        assert_eq!(change(&mut sa, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
        drop(sa);
        let ka = fs::read(a.key()).unwrap();
        let mut sb = login(&b, OLD, &mut codes).unwrap();
        assert_eq!(change(&mut sb, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
        let mut asked = None;
        let adopted = take(&mut sb, &mut codes, NEW, &ka, NEW, |p| {
            asked = Some(p.clone());
            defaults(p)
        })
        .unwrap();
        let asked = asked.unwrap();
        assert_eq!((asked.own_pass, asked.both_passwords), (None, false));
        assert_eq!(adopted.password, PassInForce::Own);
        let ku = fs::read(b.key()).unwrap();
        let pw_id = |bytes: &[u8]| keyfile::parse(bytes).unwrap().pw_id;
        assert_eq!(pw_id(&ku), pw_id(&ka));
        drop(sb);
        let mut sa = login(&a, NEW, &mut codes).unwrap();
        assert_eq!(
            classify(&sa, &ku).map(|c| c.class),
            Ok(AdoptClass::Successor)
        );
        let adopted = take(&mut sa, &mut codes, NEW, &ku, NEW, defaults).unwrap();
        assert_eq!(adopted.password, PassInForce::Own);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// The union's password (spec §5.8 rules (3) and (4)): the side that
    /// changed it since the shared state wins by default, this PC's
    /// pre-ticked when only this PC changed it; with both changed, nothing
    /// is written without S-ADOPT-BOTHPASS answered.
    #[test]
    fn a_union_keeps_the_password_of_the_side_that_changed_it() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, false, false);
        let id = s.id;
        let keys1 = s.keys.keys().to_vec();
        let pw1 = s.key_file.header().unwrap().pw_id;
        // Another PC's write from K1 that kept its password: a union with a
        // third file, say. This PC then changed its own.
        let spec = |epoch, pw_id| Spec {
            vault_id: id,
            epoch,
            kind: Kind::Union,
            next: 1,
            pw_id,
            loss: 0,
            tombstones: Vec::new(),
            resume: [0; 32],
        };
        let kept = [&[[0x61; 32]][..], &keys1].concat();
        let bundle = Bundle::new(&kept, None).unwrap();
        let (f, _) = keyfile::seal(&spec(2, pw1), &bundle, OLD, Plan::PasswordOnly).unwrap();
        assert_eq!(change(&mut s, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
        let pw2 = s.key_file.header().unwrap().pw_id;
        let check = classify(&s, &f).unwrap();
        assert_eq!(
            (check.class, check.fork, check.changed_pw),
            (AdoptClass::Union, true, Some((true, false)))
        );
        let mut asked = None;
        let adopted = take(&mut s, &mut codes, NEW, &f, OLD, |p| {
            asked = Some(p.clone());
            Acks {
                union_password: UnionPassword::Own,
                ..defaults(p)
            }
        })
        .unwrap();
        assert_eq!(
            asked.map(|p| (p.own_pass, p.both_passwords)),
            Some((Some(true), false))
        );
        assert_eq!(adopted.password, PassInForce::Own);
        let ku = fs::read(pc.key()).unwrap();
        assert_eq!(keyfile::parse(&ku).unwrap().pw_id, pw2);
        let keys2 = keys_of(&ku, NEW);
        // A file from K2 with a new password: only the other side changed
        // it since (this PC's union kept K2's), so its password is the
        // default.
        let changed = [&[[0x62; 32]][..], &keys2[1..]].concat();
        let (g, _) = sealed(id, &changed, 3, &[], THIRD);
        let check = classify(&s, &g).unwrap();
        assert_eq!(
            (check.class, check.changed_pw),
            (AdoptClass::Union, Some((false, true)))
        );
        let mut asked = None;
        let adopted = take(&mut s, &mut codes, NEW, &g, THIRD, |p| {
            asked = Some(p.clone());
            defaults(p)
        })
        .unwrap();
        assert_eq!(
            asked.map(|p| (p.own_pass, p.both_passwords)),
            Some((Some(false), false))
        );
        assert_eq!(adopted.password, PassInForce::Other);
        drop(s);
        let mut s = login(&pc, THIRD, &mut codes).unwrap();
        assert_eq!(notices(&mut s), []);
        // Both sides changed it: S-ADOPT-BOTHPASS, and without its yes
        // nothing is written.
        let other = other_of(&s, What::Union);
        let before = key_and_anchor(&pc);
        let taken = take(&mut s, &mut codes, THIRD, &other, NEW, |p| {
            assert!(p.both_passwords);
            Acks {
                both_passwords: false,
                ..defaults(p)
            }
        });
        assert_eq!(taken.err(), Some(ADOPT_STALE));
        assert_eq!(key_and_anchor(&pc), before);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    const P2: &str = "synthetic password number two";
    const P3: &str = "synthetic password number three";
    const P4: &str = "synthetic password number four";
    const P5: &str = "synthetic password number five";
    const P6: &str = "synthetic password number six";
    const PB: &str = "synthetic password of the b side";

    /// No successor below the confirmed state, and during a local rollback
    /// only a file that descends from it (S23-2 #4, S23-3 #4): this PC wrote
    /// e4 and e5; K3 + V3 put back are held. Another PC's change from 3, a
    /// file above 5 under a key of its maker's choice and an honest sibling
    /// with three changes from 3 are refused before any key derivation; a
    /// file that lists e5's key without holding it fails the open. This
    /// PC's own K5 lifts the hold, so does a K6 written on top of it; after
    /// [이 열쇠 파일이 맞습니다] the change from 3 is an ordinary successor;
    /// a Restore with K3 takes no key file.
    #[test]
    fn during_a_local_rollback_only_a_descendant_is_taken() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, false, false);
        let id = s.id;
        assert_eq!(change(&mut s, &mut codes, OLD, P2), Ok(Rekeyed::Done));
        assert_eq!(change(&mut s, &mut codes, P2, P3), Ok(Rekeyed::Done));
        let (k3, v3) = (pc.file("k3.goyokey"), pc.file("v3.goyo"));
        fs::copy(pc.key(), &k3).unwrap();
        fs::copy(pc.vault(), &v3).unwrap();
        let keys3 = s.keys.keys().to_vec();
        assert_eq!(change(&mut s, &mut codes, P3, P4), Ok(Rekeyed::Done));
        assert_eq!(change(&mut s, &mut codes, P4, P5), Ok(Rekeyed::Done));
        let k5 = fs::read(pc.key()).unwrap();
        let keys5 = s.keys.keys().to_vec();
        drop(s);
        let put_back = |codes: &mut Codes| {
            fs::copy(&k3, pc.key()).unwrap();
            fs::copy(&v3, pc.vault()).unwrap();
            let mut s = login(&pc, P3, codes).unwrap();
            assert!(s.local_rollback());
            s.take_key_notices();
            s
        };
        let mut s = put_back(&mut codes);
        let (k4b, state4b) = sealed(id, &[&[[0xb4; 32]][..], &keys3].concat(), 4, &[], PB);
        let (fx, _) = sealed(id, &[&[[0xf6; 32]][..], &keys3].concat(), 6, &[], P3);
        let sibling = [&[[0xa6; 32], [0xa5; 32], [0xa4; 32]][..], &keys3].concat();
        let (k6s, _) = sealed(id, &sibling, 6, &[], PB);
        let before = super::super::tests::files(&pc);
        let derived = crypto::derive_count();
        for other in [&k4b, &fx, &k6s] {
            assert_eq!(classify(&s, other).err(), Some(ADOPT_ROLLBACK));
            assert_eq!(refusal_values(ADOPT_ROLLBACK), Some(vec!["5".into()]));
        }
        assert_eq!(crypto::derive_count(), derived);
        // Listing e5's key without holding it: the open proves it.
        let claim = [&[[0xf6; 32], [0xc5; 32]][..], &keys3].concat();
        let mut ids = key_ids(&id, &claim);
        ids[1] = key_id(&id, &keys5[0]);
        let spec = Spec {
            vault_id: id,
            epoch: 6,
            kind: Kind::Password,
            next: 1,
            pw_id: [0x33; 16],
            loss: 0,
            tombstones: Vec::new(),
            resume: [0; 32],
        };
        let bundle = Bundle::new(&claim, None).unwrap();
        let claimed = keyfile::seal_claiming(&spec, &bundle, P3, &ids);
        assert_eq!(
            classify(&s, &claimed).map(|c| c.class),
            Ok(AdoptClass::Successor)
        );
        let taken = take(&mut s, &mut codes, P3, &claimed, P3, defaults);
        assert_eq!(taken.err(), Some(AUTH_ERROR));
        assert_eq!(super::super::tests::files(&pc), before);
        assert!(s.local_rollback());
        // This PC's own K5, from a key backup: taken, and the hold lifts.
        let adopted = take(&mut s, &mut codes, P3, &k5, P5, defaults).unwrap();
        assert_eq!(adopted.state, keyfile::parse(&k5).unwrap().state());
        assert!(!s.local_rollback());
        assert_eq!(
            pc.lines(&id).vault.unwrap().state.key_state(),
            adopted.state
        );
        drop(s);
        let mut s = login(&pc, P5, &mut codes).unwrap();
        assert_eq!(notices(&mut s), []);
        drop(s);
        // Another PC's K6 on top of K5: it holds e5's key.
        let mut s = put_back(&mut codes);
        let (k6, state6) = sealed(id, &[&[[0x66; 32]][..], &keys5].concat(), 6, &[], P6);
        let adopted = take(&mut s, &mut codes, P3, &k6, P6, defaults).unwrap();
        assert_eq!(adopted.state, state6);
        assert!(!s.local_rollback());
        drop(s);
        // Confirmed by the user, K3 is this PC's state: the change from 3
        // is an ordinary successor.
        let mut s = put_back(&mut codes);
        let r = s.reauth(P3, Some(("", otp::now().unwrap())), None).unwrap();
        s.confirm_key_file(r).unwrap();
        assert_eq!(
            classify(&s, &k4b).map(|c| c.class),
            Ok(AdoptClass::Successor)
        );
        let adopted = take(&mut s, &mut codes, P3, &k4b, PB, defaults).unwrap();
        assert_eq!(adopted.state, state4b);
        drop(s);
        // A Restore with K3 takes no key file.
        pc.here();
        let dest = pc.file("restored.goyo");
        let r = Session::restore(&v3, &k3, &dest, P3, "").unwrap();
        assert!(r.restore_held());
        let anchor = pc.anchor();
        assert_eq!(classify(&r, &k6).err(), Some(RESTORE_OLDKEY));
        assert_eq!(pc.anchor(), anchor);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A Restore while a key change of this PC waits for a login, and a
    /// session whose change may have landed in a key file it cannot read,
    /// take no key file either (spec §5.1, §5.5 R0): nothing is written.
    #[test]
    fn a_held_session_takes_no_key_file() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, false, false);
        let (k1, v1) = (pc.file("k1.goyokey"), pc.file("v1.goyo"));
        fs::copy(pc.key(), &k1).unwrap();
        fs::copy(pc.vault(), &v1).unwrap();
        let other = other_of(&s, What::Successor);
        CRASH.with(|c| c.set(Some("S2v")));
        assert_eq!(change(&mut s, &mut codes, OLD, NEW), Err(SIMULATED_CRASH));
        drop(s);
        pc.here();
        let anchor = pc.anchor();
        let r = Session::restore(&v1, &k1, &pc.file("r.goyo"), OLD, "").unwrap();
        assert_eq!(classify(&r, &other).err(), Some(RESTORE_PENDING));
        drop(r);
        // The landed key file is away: the change waits for it.
        let away = pc.file("away.goyokey");
        fs::rename(pc.key(), &away).unwrap();
        let prepared = super::super::super::prepare(&pc.vault(), &k1).unwrap();
        let s = Session::login(prepared, OLD, "", otp::now().unwrap(), None).unwrap();
        assert!(s.pending_elsewhere().is_some());
        assert_eq!(classify(&s, &other).err(), Some(PENDING_ELSEWHERE));
        assert_eq!(pc.anchor(), anchor);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// The epoch bounds of a file from a USB stick (spec §5.8): more than
    /// EPOCH_WINDOW above what this PC's files prove is refused before any
    /// key derivation; this build, which has no gate, takes a successor
    /// further ahead than EPOCH_SILENT silently, as its login does.
    #[test]
    fn a_file_far_ahead_is_refused() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, false, false);
        let id = s.id;
        let keys = s.keys.keys().to_vec();
        let later = |n: u8, epoch| sealed(id, &[&[[n; 32]][..], &keys].concat(), epoch, &[], NEW);
        let (far, _) = later(0xfa, 1 + EPOCH_WINDOW + 1);
        let before = key_and_anchor(&pc);
        let derived = crypto::derive_count();
        assert_eq!(classify(&s, &far).err(), Some(ADOPT_REFUSED));
        assert_eq!(
            refusal_values(ADOPT_REFUSED),
            Some(vec![TOO_FAR.to_owned()])
        );
        assert_eq!(crypto::derive_count(), derived);
        assert_eq!(key_and_anchor(&pc), before);
        let silent = 1 + keyfile::EPOCH_SILENT + 44;
        let (ahead, state) = later(0xfb, silent);
        let adopted = take(&mut s, &mut codes, OLD, &ahead, NEW, defaults).unwrap();
        assert_eq!(adopted.state, state);
        assert_eq!(s.max_epoch(), silent);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// A removal this PC's key file carries is never dropped (P3, spec
    /// §5.8): a successor that lacks it, and a fork whose branch saw the
    /// state that carried it, are refused before any key derivation; a fork
    /// that split before it is joined with the removal kept. A union past
    /// 480 removals is refused.
    #[test]
    fn a_removal_this_pc_carries_is_never_dropped() {
        let pc = Pc::new();
        let (s, mut codes) = setup(&pc, true, false, false);
        let id = s.id;
        let keys1 = s.keys.keys().to_vec();
        // A GOYOKE03 with a removal, taken silently at login.
        let dk2 = [0x72; 32];
        let keys2 = [&[dk2][..], &keys1].concat();
        let (k2, state2) = sealed(id, &keys2, 2, &[([0x77; 16], 2)], NEW);
        fs::write(pc.key(), &k2).unwrap();
        fs::write(pc.vault(), vault_of(&s, &dk2, state2)).unwrap();
        drop(s);
        let mut s = login(&pc, NEW, &mut codes).unwrap();
        assert_eq!(notices(&mut s), []);
        let lacking = |n: u8, keys: &[[u8; 32]], epoch| {
            sealed(id, &[&[[n; 32]][..], keys].concat(), epoch, &[], THIRD).0
        };
        // A successor without it, and a fork that holds the key of the
        // state that carried it.
        let successor = lacking(0x73, &keys2, 3);
        let saw = lacking(0x74, &keys2, 1);
        // Stuffed with removals past the limit.
        let stuffed: Vec<([u8; 16], u64)> = (0..480u32)
            .map(|i| {
                let mut credhash = [0xee; 16];
                credhash[..4].copy_from_slice(&i.to_le_bytes());
                (credhash, 1)
            })
            .collect();
        let (full, _) = sealed(id, &[[0x75; 32], keys1[1]], 2, &stuffed, THIRD);
        let derived = crypto::derive_count();
        assert_eq!(classify(&s, &successor).err(), Some(ADOPT_REFUSED));
        assert_eq!(
            refusal_values(ADOPT_REFUSED),
            Some(vec![LACKS_REMOVAL.to_owned()])
        );
        assert_eq!(classify(&s, &saw).err(), Some(ADOPT_REFUSED));
        assert_eq!(classify(&s, &full).err(), Some(TOMBSTONES_FULL));
        assert_eq!(crypto::derive_count(), derived);
        // A fork from before it: joined, the removal kept.
        let before = lacking(0x76, &keys1[1..], 2);
        let adopted = take(&mut s, &mut codes, NEW, &before, THIRD, defaults).unwrap();
        let h = keyfile::parse(&fs::read(pc.key()).unwrap()).unwrap();
        assert_eq!(h.state(), adopted.state);
        assert_eq!(h.tombstones.len(), 1);
        assert_eq!(h.tombstones[0].credhash, [0x77; 16]);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// 70 password changes on each of two branches from the same 0.8 key
    /// file, then the union (spec §14.4-10 "the union keyring"): 64 keys,
    /// the fresh one first, this PC's newest next, the other branch's
    /// current one kept and its oldest extra keys dropped first, the ID key
    /// last. The other PC takes it as a successor.
    #[test]
    fn seventy_changes_on_each_branch_keep_both_current_keys() {
        let a = Pc::new();
        let (mut sa, mut codes) = setup(&a, false, false, false);
        let id = sa.id;
        let id_key = *sa.keys.id_key();
        let b = copy_of(&a);
        let run = |s: &mut Session, codes: &mut Codes, tag: &str| {
            let mut password = OLD.to_owned();
            for n in 0..70 {
                let next = format!("synthetic {tag} password {n}");
                assert_eq!(change(s, codes, &password, &next), Ok(Rekeyed::Done));
                password = next;
            }
            password
        };
        let pa = run(&mut sa, &mut codes, "branch a");
        let keys_a = sa.keys.keys().to_vec();
        drop(sa);
        let ka = fs::read(a.key()).unwrap();
        let mut sb = login(&b, OLD, &mut codes).unwrap();
        let pb = run(&mut sb, &mut codes, "branch b");
        let keys_b = sb.keys.keys().to_vec();
        assert_eq!((keys_a.len(), keys_b.len()), (MAX_KEYS, MAX_KEYS));
        let adopted = take(&mut sb, &mut codes, &pb, &ka, &pa, defaults).unwrap();
        assert_eq!(adopted.state.epoch, 71);
        let keys = sb.keys.keys().to_vec();
        assert_eq!(keys.len(), MAX_KEYS);
        assert!(!keys_a.contains(&keys[0]) && !keys_b.contains(&keys[0]));
        assert_eq!(&keys[1..62], &keys_b[..61]);
        assert_eq!((keys[62], keys[63]), (keys_a[0], id_key));
        let ku = fs::read(b.key()).unwrap();
        assert_eq!(keyfile::parse(&ku).unwrap().key_ids, key_ids(&id, &keys));
        drop(sb);
        let mut sa = login(&a, &pa, &mut codes).unwrap();
        let adopted = take(&mut sa, &mut codes, &pa, &ku, &pa, defaults).unwrap();
        assert_eq!(adopted.state, keyfile::parse(&ku).unwrap().state());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// The preview and the write take exactly the file that was checked
    /// (spec §5.8 "Binding"): a pass for another state, a bundle opened from
    /// another file, a plan changed since, another session's plan; each is
    /// refused with nothing written.
    #[test]
    fn a_plan_is_bound_to_its_file_and_session() {
        let pc = Pc::new();
        let (mut s, _codes) = setup(&pc, true, false, false);
        let before = key_and_anchor(&pc);
        let bytes = other_of(&s, What::Successor);
        let elsewhere = other_of(&s, What::Union);
        let (f, g) = (file(&bytes), file(&elsewhere));
        let check = classify(&s, &bytes).unwrap();
        let reauth = |s: &mut Session| s.reauth(OLD, Some(("", otp::now().unwrap())), None);
        let r = reauth(&mut s).unwrap();
        let another = GatePass::NotNeeded {
            epoch: check.other.epoch,
            tag: [0x5a; 16],
        };
        let opened = s.adopt_open(&r, &f, Some(NEW)).unwrap();
        let preview = s.adopt_preview(&r, &f, opened, &check, another, None);
        assert_eq!(preview.err(), Some(ADOPT_STALE));
        let opened = s.adopt_open(&r, &g, Some(NEW)).unwrap();
        let pass = GatePass::none(&check);
        let preview = s.adopt_preview(&r, &f, opened, &check, pass, None);
        assert_eq!(preview.err(), Some(ADOPT_STALE));
        let plan = |s: &Session, r: &Reauth| {
            let opened = s.adopt_open(r, &f, Some(NEW)).unwrap();
            s.adopt_preview(r, &f, opened, &check, pass, None).unwrap()
        };
        let acks = Acks {
            password_only: false,
            union_password: UnionPassword::Other,
            both_passwords: false,
        };
        let mut changed = plan(&s, &r);
        changed.gate = another;
        let adopt = |s: &mut Session, r, plan| {
            s.adopt(r, plan, Vec::new(), acks, Consent::default(), false)
        };
        assert_eq!(adopt(&mut s, r, changed).err(), Some(ADOPT_STALE));
        let r = reauth(&mut s).unwrap();
        let mut changed = plan(&s, &r);
        changed.check.epoch += 1;
        assert_eq!(adopt(&mut s, r, changed).err(), Some(ADOPT_STALE));
        let r = reauth(&mut s).unwrap();
        let mut foreign = plan(&s, &r);
        foreign.session ^= 1;
        assert_eq!(adopt(&mut s, r, foreign).err(), Some(REAUTH_STALE));
        assert_eq!(key_and_anchor(&pc), before);
        // The checked plan itself is taken.
        let r = reauth(&mut s).unwrap();
        let ok = plan(&s, &r);
        assert!(adopt(&mut s, r, ok).is_ok());
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// An adopt whose new key file or vault file does not verify in memory
    /// writes nothing (spec §14.4-13); one whose first vault file write hits
    /// the replace gap changed nothing (E-S1g), and one whose last does keeps
    /// the change (E-S3g): the next unlock takes the vault file back.
    #[test]
    fn an_adopt_that_does_not_verify_or_hits_a_gap() {
        for what in [What::Successor, What::Union] {
            let pc = Pc::new();
            let (mut s, mut codes) = setup(&pc, true, false, false);
            let other = other_of(&s, what);
            let before = super::super::tests::files(&pc);
            for which in ["K", "V"] {
                CORRUPT.with(|c| c.set(Some(which)));
                let taken = take(&mut s, &mut codes, OLD, &other, NEW, defaults);
                assert_eq!(taken.err(), Some(NOT_VERIFIED), "{what:?} {which}");
                assert_eq!(super::super::tests::files(&pc), before, "{what:?} {which}");
            }
            CRASH.with(|c| c.set(Some("S1.gap")));
            let taken = take(&mut s, &mut codes, OLD, &other, NEW, defaults);
            assert_eq!(taken.err(), Some(GAP_NOT_CHANGED), "{what:?}");
            assert_eq!(s.put(None, entry("lost")), Err(GAP_KEPT));
            drop(s);
            let mut s = login(&pc, OLD, &mut codes).unwrap();
            assert!(s.take_recovery().vault);
            assert_eq!(notices(&mut s), [], "{what:?}");
            CRASH.with(|c| c.set(Some("S3.gap")));
            let adopted = take(&mut s, &mut codes, OLD, &other, NEW, defaults).unwrap();
            assert!(adopted.gap_kept && s.gap_kept(), "{what:?}");
            drop(s);
            let mut s = login(&pc, NEW, &mut codes).unwrap();
            assert!(s.take_recovery().vault);
            assert_eq!(notices(&mut s), [], "{what:?}");
            assert_eq!(s.key_state(), adopted.state);
            assert_eq!(secrets(&s), ["one", "two"]);
        }
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }

    /// E-SIDE (S23-3 #10): a password change whose promotion (S5) cannot be
    /// written leaves the entry in memory; an adopt in the same session
    /// still runs and writes the held promotion first. After a lock and a
    /// login with the anchor still locked, the landed entry is promoted in
    /// memory, and an adopt runs again.
    #[test]
    fn an_adopt_runs_while_a_promotion_waits_in_memory() {
        let pc = Pc::new();
        let (mut s, mut codes) = setup(&pc, true, false, false);
        let id = s.id;
        let lock = Rc::new(RefCell::new(None));
        let hold = lock.clone();
        let dir = pc.anchor_dir();
        set_before("S3", move || {
            *hold.borrow_mut() = Some(anchor::hold_lock(&dir))
        });
        assert_eq!(change(&mut s, &mut codes, OLD, NEW), Ok(Rekeyed::Done));
        assert_eq!(s.take_key_notices(), [KeyNotice::SidecarFailed]);
        assert_eq!(
            pc.lines(&id).pending.unwrap().state.key_state(),
            s.key_state()
        );
        drop(lock.borrow_mut().take());
        let other = other_of(&s, What::Successor);
        let adopted = take(&mut s, &mut codes, NEW, &other, NEW, defaults).unwrap();
        let lines = pc.lines(&id);
        assert!(lines.pending.is_none());
        assert_eq!(lines.vault.unwrap().state.key_state(), adopted.state);
        // The promotion of a change that landed, with the lock held at the
        // next login: kept in memory, and an adopt still runs.
        let dir = pc.anchor_dir();
        let hold = lock.clone();
        set_before("S3", move || {
            *hold.borrow_mut() = Some(anchor::hold_lock(&dir))
        });
        assert_eq!(change(&mut s, &mut codes, NEW, THIRD), Ok(Rekeyed::Done));
        drop(s);
        let mut s = login(&pc, THIRD, &mut codes).unwrap();
        assert!(s.take_key_notices().contains(&KeyNotice::SidecarFailed));
        let other = other_of(&s, What::Union);
        let adopted = take(&mut s, &mut codes, THIRD, &other, NEW, defaults).unwrap();
        assert_eq!(s.key_state(), adopted.state);
        drop(lock.borrow_mut().take());
        let _ = s.poll_sync();
        let lines = pc.lines(&id);
        assert!(lines.pending.is_none());
        assert_eq!(lines.vault.unwrap().state.key_state(), adopted.state);
        drop(s);
        let mut s = login(&pc, NEW, &mut codes).unwrap();
        assert_eq!(notices(&mut s), []);
        crypto::set_kdf_profile(crypto::KdfProfile::Real);
    }
}
