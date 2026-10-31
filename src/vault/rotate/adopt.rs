//! Adopt, "새 열쇠 파일 받기" (spec §5.8): another PC's key file of this
//! vault, taken in after a re-authentication. A file that descends from this
//! PC's key file is taken as it is (the successor re-seal: its state and key
//! code stay, only the seal block is this PC's); any other file that passes
//! the checks is joined with this PC's into a union (kind 9) under a fresh
//! data key, so no data key of the other file's choice ever becomes current.
//! Both write through the key-change engine (S0-S5), so a crash anywhere
//! leaves a pair that opens. The default build adopts password-only key
//! files; the security-key build adds files with security keys, the public
//! checks and the gate before any touch (`gate`), the fork options, and the
//! union of slots and pair records (`hw`).
#[cfg(feature = "security-key")]
use super::{
    super::gate::{self, Checked, GateKind},
    hw::{Join, Touched},
};
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
pub(super) const ADOPT_STALE: &str = "받을 열쇠 파일을 확인한 뒤에 이 PC의 열쇠 파일이나 그 파일이 바뀌었습니다. 처음부터 다시 하세요.";

/// Where the other key file comes from: a file, or (security-key build)
/// the server's key file in the key view, by its record number (spec
/// §7.15).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Source {
    File(PathBuf),
    #[cfg(feature = "security-key")]
    Server {
        seq: u64,
    },
}
/// The gate an adopt passed (spec §7.15a), bound to the file it was asked
/// for: the preview and the write refuse any other file. The default build
/// has no gate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GatePass {
    NotNeeded {
        epoch: u64,
        tag: [u8; 16],
    },
    /// S-LOSTPICK: the credhashes of the picked keys.
    #[cfg(feature = "security-key")]
    G2Passed {
        pick: Vec<[u8; 16]>,
        epoch: u64,
        tag: [u8; 16],
    },
    /// S-GATE-CODE: the code typed, compared once the file is open.
    #[cfg(feature = "security-key")]
    G1Passed {
        code: Code,
        epoch: u64,
        tag: [u8; 16],
    },
    /// "열쇠 변경 자동 적용 (이 서버를 믿음)" (spec §2.30): no question was
    /// asked; the preview takes it only where `Session::trusts` holds.
    #[cfg(feature = "security-key")]
    Trusted {
        epoch: u64,
        tag: [u8; 16],
    },
}
impl GatePass {
    /// The pass of a file that needs no gate.
    pub fn none(check: &AdoptCheck) -> Self {
        Self::NotNeeded {
            epoch: check.other.epoch,
            tag: check.other.tag,
        }
    }
    /// The file it was answered for.
    fn state(&self) -> KeyState {
        match self {
            Self::NotNeeded { epoch, tag } => KeyState {
                epoch: *epoch,
                tag: *tag,
            },
            #[cfg(feature = "security-key")]
            Self::G2Passed { epoch, tag, .. }
            | Self::G1Passed { epoch, tag, .. }
            | Self::Trusted { epoch, tag } => KeyState {
                epoch: *epoch,
                tag: *tag,
            },
        }
    }
}
/// Which fork option the user chose (spec §5.8 "Forks").
#[cfg(feature = "security-key")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForkOption {
    /// Option 1, "다른 PC 쪽 사용": the other branch's content.
    TakeOther,
    /// Option 2, "둘 다 합치기": both, this PC's removals kept.
    Both,
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
    /// S-ADOPT-PWONLY: a vault with security keys made password-only. The
    /// default build never asks it (and refuses a yes); the security-key
    /// build requires it where the preview sets `password_only`.
    pub password_only: bool,
    pub union_password: UnionPassword,
    /// S-ADOPT-BOTHPASS answered yes, where the preview asks it.
    pub both_passwords: bool,
    /// The fork option the plan was made for.
    #[cfg(feature = "security-key")]
    pub fork_option: ForkOption,
    /// S-KEYSYNC-ON answered yes, where the preview turns key-file sync on
    /// here (spec §7.16 "Every consented on").
    #[cfg(feature = "security-key")]
    pub keysync_on: bool,
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
    /// The public checks, R, M, Δ, T_new, the policy and slot changes, and
    /// the gate of each way to take the file (security-key build).
    #[cfg(feature = "security-key")]
    pub keys: KeyGates,
    /// Where the file came from: every later check reads it again from
    /// the same place.
    #[cfg(feature = "security-key")]
    pub source: Source,
}
/// What the security-key build found before any touch (spec §5.8, §7.15a).
#[cfg(feature = "security-key")]
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct KeyGates {
    pub checked: Checked,
    /// The gate of a successor or a union, and for a fork of option 2; None
    /// needs none.
    pub gate: Option<GateKind>,
    /// A fork whose option 2 ("둘 다 합치기") is offered: not when its
    /// authorizer is a key this PC removed.
    pub both: bool,
    /// A fork whose option 1 ("다른 PC 쪽 사용") is offered, and its gate:
    /// never when it would bring back a key this PC's user removed (`o`).
    pub take_other_offered: bool,
    pub take_other: Option<GateKind>,
    /// The keys option 1 brings back: removals this PC took from another
    /// file (`t`), by credhash (S-FORK-READMIT).
    pub readmit: Vec<[u8; 16]>,
}
/// The other file, opened (spec §5.8 "Opening the other file"): its keys
/// and the password that opened it. Built only by `adopt_open`. Zeroized on
/// drop.
pub struct OtherOpened {
    opened: Opened,
    password: Zeroizing<String>,
    /// SHA-256 of the bytes it opened.
    sha: [u8; 32],
    /// The key whose touch opened a file with security keys.
    #[cfg(feature = "security-key")]
    touched: Option<Touched>,
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
    /// A union's keys (security-key build): renumbered (old, new), dropped
    /// for want of a PIN, and those it would suspend without a touch.
    #[cfg(feature = "security-key")]
    pub renumbered: Vec<(u8, u8)>,
    #[cfg(feature = "security-key")]
    pub dropped_uv: Vec<u8>,
    /// Keys nothing touched reaches: written only with S-SUSPEND's consent.
    #[cfg(feature = "security-key")]
    pub suspend: Vec<u8>,
    /// The same keys by credential, which S-SUSPEND names as this PC does
    /// (`Session::named`) and its extra touches ask for.
    #[cfg(feature = "security-key")]
    pub suspend_keys: Vec<[u8; 16]>,
    /// The result is password-only for a vault with keys: [받기] asks
    /// S-ADOPT-PWONLY first.
    #[cfg(feature = "security-key")]
    pub password_only: bool,
    /// The result is GOYOKS01 while this PC's key file is not: [받기] asks
    /// S-KEYSYNC-ON first, under the transport precondition (spec §7.16).
    #[cfg(feature = "security-key")]
    pub keysync_on: bool,
    /// The result leaves key-file sync (S-KEYSYNC-OFF-JOIN), and whether
    /// its `ks` asks the server to delete its key file (S6R2 #22).
    #[cfg(feature = "security-key")]
    pub keysync_off: Option<bool>,
    /// What the change makes of this PC's keys and password (the notice of
    /// an auto-applied take, spec §2.30), known once the gate passed.
    #[cfg(feature = "security-key")]
    pub change: KeyChange,
}
/// What a change makes of this PC's keys and password, as the notice of a
/// take that trusted the server names it (spec §2.30), from this PC's own
/// state where it can: this PC's numbers of the keys the file removes, the
/// file's numbers of the keys new to this PC, whether its password differs
/// from this PC's, and any other change of keys or settings.
#[cfg(feature = "security-key")]
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct KeyChange {
    pub removed: Vec<u8>,
    pub added: Vec<u8>,
    pub password: bool,
    pub other: bool,
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
    /// The fork option it was made for.
    #[cfg(feature = "security-key")]
    option: ForkOption,
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
    /// Security-key build: this PC's keys renumbered (old, new), keys
    /// dropped for want of a PIN, and keys left suspended, by number.
    #[cfg(feature = "security-key")]
    pub renumbered: Vec<(u8, u8)>,
    #[cfg(feature = "security-key")]
    pub dropped_uv: Vec<u8>,
    #[cfg(feature = "security-key")]
    pub suspended: Vec<u8>,
    /// The take trusted the server in place of its gate (spec §2.30), and
    /// what it changed, for the notice.
    #[cfg(feature = "security-key")]
    pub trusted: bool,
    #[cfg(feature = "security-key")]
    pub change: KeyChange,
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
    /// Equal and Contained write nothing; Older is refused. The
    /// security-key build adds P3, P4, slot and pair-record pinning, and
    /// the gate of each way to take the file, all before any touch.
    pub fn adopt_check(&self, other: &KeyFile, source: Source) -> Result<AdoptCheck> {
        #[cfg(not(feature = "security-key"))]
        let Source::File(_) = source;
        self.held()?;
        let own = self.own_public();
        let theirs = self.other_public(other)?;
        let line = self.anchor.lines.vault.as_ref();
        // A vault this PC pins as hardware is open only with a key file
        // with security keys; a password-only file for it is the
        // security-key build's policy change, behind G1.
        if line.is_some_and(|l| l.state.hardware()) && !self.key_file.needs_security_key() {
            return Err(ANCHOR_DOWNGRADE);
        }
        let a = line.map_or(0, |l| l.state.epoch);
        let check = |class, fork, changed_pw, epoch| AdoptCheck {
            class,
            other: theirs.state,
            fork,
            changed_pw,
            epoch,
            #[cfg(feature = "security-key")]
            keys: KeyGates::default(),
            #[cfg(feature = "security-key")]
            source: source.clone(),
        };
        if theirs.state == own.state {
            return Ok(check(AdoptClass::Equal, false, None, own.state.epoch));
        }
        let lists = |set: &[Tombstone], c: &[u8; 16]| set.iter().any(|t| t.credhash == *c);
        let removals_known = theirs.tombs.iter().all(|t| lists(&own.tombs, &t.credhash));
        // Every key of the other file is one this PC has live or removed,
        // and its records between keys live here are this PC's.
        #[cfg(feature = "security-key")]
        let (keys_known, pairs_known) = self.keys_known(other);
        #[cfg(not(feature = "security-key"))]
        let (keys_known, pairs_known) = (true, true);
        // A state of this PC's history, with a key this PC still holds.
        if theirs.state.epoch < own.state.epoch
            && line.is_some_and(|l| l.state.had(theirs.state))
            && own.ids[1..].contains(&theirs.ids[0])
            && removals_known
            && keys_known
        {
            return Err(ADOPT_OLDER);
        }
        // The server's file at this PC's own epoch (two changes that kept
        // the data key, such as two KeySyncOn from one state) is a fork the
        // key channel holds on, even when it holds nothing this PC lacks:
        // only a union above both lands on its record (spec §7.21-7, -33
        // (d)). So is a USB copy of that same file (KeyFork-SK names this
        // route). Any other file from elsewhere that adds nothing needs no
        // write.
        #[cfg(feature = "security-key")]
        let sibling = (matches!(source, Source::Server { .. }) || self.server_top_is(theirs.state))
            && theirs.state.epoch == own.state.epoch;
        #[cfg(not(feature = "security-key"))]
        let sibling = false;
        if theirs.state.epoch <= own.state.epoch
            && !sibling
            && theirs.ids.iter().all(|i| own.ids.contains(i))
            && removals_known
            && keys_known
            && pairs_known
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
        // The public checks of a KF2 file (spec §7.14), also against a 0.8
        // key file of this PC, whose gate counts every key of the other file
        // and its policy: their failures, but for a fork's removals made
        // since it split, are refusals. A 0.8 other file is never more than
        // Contained (its one key is the ID key), so none run for it.
        #[cfg(feature = "security-key")]
        let checked = match other.header() {
            Some(_) => {
                let checked =
                    gate::public_checks(&self.key_file, line, other, fork, chained, self.gated())
                        .map_err(|reason| refuse(ADOPT_REFUSED, vec![reason.to_owned()]))?;
                Some(checked)
            }
            None => None,
        };
        #[cfg(not(feature = "security-key"))]
        let checked: Option<()> = None;
        // P3 (b): every removal this PC's key file carries, but in a fork
        // the ones made since it split, which its branch never saw: their
        // recorded key ID is not in its list (spec §5.8 "Forks").
        let since_fork = |t: &Tombstone| {
            line.and_then(|l| l.state.tombs.iter().find(|x| x.credhash == t.credhash))
                .is_some_and(|x| x.keyid != [0; 4] && !theirs.ids.iter().any(|i| i[..4] == x.keyid))
        };
        if checked.is_none()
            && !own
                .tombs
                .iter()
                .filter(|t| !lists(&theirs.tombs, &t.credhash))
                .all(|t| fork && since_fork(t))
        {
            return Err(refuse(ADOPT_REFUSED, vec![LACKS_REMOVAL.to_owned()]));
        }
        // A successor carries nothing of this PC's (no carry), passed every
        // check unrelaxed, and never makes a vault with keys password-only.
        #[cfg(feature = "security-key")]
        let successor = successor
            && checked
                .as_ref()
                .is_none_or(|c| c.clean() && c.missing_pairs.is_empty() && c.gates.kept.is_empty())
            && !(self.key_file.needs_security_key() && !other.needs_security_key());
        // Before G1 only a successor confirmed by its own code is taken
        // (round 4, finding 1), also in a held session whose confirmed line
        // lacks `t` (S45-3 #2).
        #[cfg(feature = "security-key")]
        if self.unconfirmed() && !successor {
            return Err(gate::TOFU_ADOPT);
        }
        if successor {
            #[allow(unused_mut)]
            let mut c = check(AdoptClass::Successor, false, None, theirs.state.epoch);
            // In TOFU a successor is taken only with its own code (G1),
            // whatever the checks found.
            #[cfg(feature = "security-key")]
            {
                let gate = if self.unconfirmed() {
                    Some(GateKind::G1)
                } else {
                    checked.as_ref().and_then(|c| self.ask(c.gates.needed()))
                };
                c.keys = KeyGates {
                    checked: checked.unwrap_or_default(),
                    gate,
                    both: true,
                    ..KeyGates::default()
                };
            }
            return Ok(c);
        }
        // A union: above both files, this PC's floor and its confirmed
        // state, with every removal of both; a GOYOKS01 result also above
        // the server's file or cut within their bounds (spec §5.5 W2).
        #[cfg(feature = "security-key")]
        let server = if other.magic() == Some(keyfile::Magic::Ks01) {
            self.server_epoch()
        } else {
            0
        };
        #[cfg(not(feature = "security-key"))]
        let server = 0;
        let epoch = own
            .state
            .epoch
            .max(theirs.state.epoch)
            .max(self.max_epoch)
            .max(a)
            .max(server)
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
        #[allow(unused_mut)]
        let mut c = check(AdoptClass::Union, fork, changed_pw, epoch);
        #[cfg(feature = "security-key")]
        if let Some(checked) = checked {
            c.keys = self.union_gates(checked, fork);
        }
        Ok(c)
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
        self.open_other(r, other, password, None)
    }
    /// The same for a file with security keys, with `touch`: the Reauth's
    /// own touch when its key is live and not suspended in the other file
    /// (2-salt when the two files' seeds for it differ), else a touch of a
    /// key the other file registers. The touched key's pair records there
    /// must open, but one this PC has byte for byte (spec §5.8).
    #[cfg(feature = "security-key")]
    pub fn adopt_open_with(
        &self,
        r: &Reauth,
        other: &KeyFile,
        password: Option<&str>,
        touch: Option<&Touch>,
    ) -> Result<OtherOpened> {
        self.open_other(r, other, password, touch)
    }
    fn open_other(
        &self,
        r: &Reauth,
        other: &KeyFile,
        password: Option<&str>,
        touch: Option<&Touch>,
    ) -> Result<OtherOpened> {
        if r.session != self.serial || r.age() > REAUTH_MAX {
            return Err(REAUTH_STALE);
        }
        let password = password.unwrap_or(&r.password);
        if password.len() > 1024 {
            return Err(AUTH_ERROR);
        }
        let opened = other.open(password, touch)?;
        self.other_opened(other, opened, password, touch)
    }
    /// The other file as `opened` opened it with `password` (and `touch`):
    /// the same ID key and TOTP secret, and the touched key's records. The
    /// login of the second entry point (spec §5.2) opened it already.
    pub(in crate::vault) fn other_opened(
        &self,
        other: &KeyFile,
        opened: Opened,
        password: &str,
        #[cfg_attr(not(feature = "security-key"), allow(unused_variables))] touch: Option<&Touch>,
    ) -> Result<OtherOpened> {
        let otp = match (opened.bundle.otp(), self.keys.otp()) {
            (Some(a), Some(b)) => ct_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        };
        if !ct_eq(opened.bundle.id_key(), self.keys.id_key()) || !otp {
            return Err(NOT_THIS_VAULT);
        }
        #[cfg(feature = "security-key")]
        let touched = match touch {
            Some(t) if other.needs_security_key() => Some(self.touched_in(other, &opened, t)?),
            _ => None,
        };
        Ok(OtherOpened {
            opened,
            password: Zeroizing::new(password.to_owned()),
            sha: sha256(other.bytes()),
            #[cfg(feature = "security-key")]
            touched,
        })
    }
    /// The preview of an adopt (spec §5.8): the checks again for exactly the
    /// file `gate` names and `opened` opened, the successor's key code, and
    /// which password a union offers. Nothing is written. A fork's option
    /// is option 2 here; see `adopt_preview_with`.
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
            #[cfg(not(feature = "security-key"))]
            match lost {}
            #[cfg(feature = "security-key")]
            let _ = lost;
            #[cfg(feature = "security-key")]
            return Err(super::NOT_PLANNED);
        }
        #[cfg(feature = "security-key")]
        return self.preview_of(r, other, opened, check, gate, ForkOption::Both);
        #[cfg(not(feature = "security-key"))]
        self.preview_of(r, other, opened, check, gate)
    }
    /// The preview of a fork's chosen option (spec §5.8 "Forks"), once its
    /// gate was answered: the gate judged against exactly this file (a
    /// wrong pick turns G2 off for this vault, S-GATE-G2FAIL; a wrong code
    /// may be typed again), E5 for a file whose password a successor or a
    /// chained union takes, and a union's keys planned.
    #[cfg(feature = "security-key")]
    pub fn adopt_preview_with(
        &self,
        r: &Reauth,
        other: &KeyFile,
        opened: OtherOpened,
        check: &AdoptCheck,
        gate: GatePass,
        option: ForkOption,
    ) -> Result<AdoptPlan> {
        self.preview_of(r, other, opened, check, gate, option)
    }
    fn preview_of(
        &self,
        r: &Reauth,
        other: &KeyFile,
        opened: OtherOpened,
        check: &AdoptCheck,
        gate: GatePass,
        #[cfg(feature = "security-key")] option: ForkOption,
    ) -> Result<AdoptPlan> {
        if r.session != self.serial || r.age() > REAUTH_MAX {
            return Err(REAUTH_STALE);
        }
        let now = self.adopt_check(other, source_of(check, other.path()))?;
        if gate.state() != now.other || now != *check || opened.sha != sha256(other.bytes()) {
            return Err(ADOPT_STALE);
        }
        #[cfg(not(feature = "security-key"))]
        let GatePass::NotNeeded { .. } = gate;
        #[cfg(feature = "security-key")]
        self.judge_gate(check, &gate, option, &opened)?;
        // The second entry point's password opened only the other file, so
        // it is never this PC's (spec §7.15 step 4: E5 holds trivially).
        let equal = r.own_password && ct_eq(r.password.as_bytes(), opened.password.as_bytes());
        // E5 (spec §5.8): a successor, or a union that takes the other
        // file's password as it is, must not claim a password change that
        // keeps this PC's password.
        #[cfg(feature = "security-key")]
        if let (Some(own), Some(theirs)) = (self.key_file.header(), other.header())
            && (check.class == AdoptClass::Successor || !check.fork)
        {
            gate::e5(own, theirs, equal)
                .map_err(|reason| refuse(ADOPT_REFUSED, vec![reason.to_owned()]))?;
        }
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
            // Option 1 takes the other branch's password with its content.
            #[cfg(feature = "security-key")]
            AdoptClass::Union if option == ForkOption::TakeOther => (None, None, false),
            // A fork: the password of the side that changed it since the
            // shared state (rule (3)), else the other file's (rule (4)).
            AdoptClass::Union => match check.changed_pw {
                Some((true, false)) => (None, Some(true), false),
                Some((false, _)) => (None, Some(false), false),
                _ => (None, Some(false), true),
            },
        };
        #[allow(unused_mut)]
        let mut preview = Preview {
            class: check.class,
            epoch: check.epoch,
            code,
            own_pass,
            both_passwords,
            #[cfg(feature = "security-key")]
            renumbered: Vec::new(),
            #[cfg(feature = "security-key")]
            dropped_uv: Vec::new(),
            #[cfg(feature = "security-key")]
            suspend: Vec::new(),
            #[cfg(feature = "security-key")]
            suspend_keys: Vec::new(),
            #[cfg(feature = "security-key")]
            password_only: false,
            #[cfg(feature = "security-key")]
            keysync_on: false,
            #[cfg(feature = "security-key")]
            keysync_off: None,
            #[cfg(feature = "security-key")]
            change: self.key_change(check, other),
        };
        // A union with security keys, planned now with the touches so far:
        // what it renumbers, drops and would suspend.
        #[cfg(feature = "security-key")]
        if check.class == AdoptClass::Union
            && (self.key_file.needs_security_key() || other.needs_security_key())
        {
            let join = self.join_of(check, option);
            let readmit = self.readmit_of(check, join);
            let plan = self.plan_union(
                r.keys.as_ref(),
                other,
                opened.touched.as_ref(),
                &[],
                join,
                &readmit,
            )?;
            preview.renumbered = plan.renumbered.clone();
            preview.dropped_uv = plan.dropped_uv.clone();
            preview.suspend = plan.unreached.clone();
            preview.suspend_keys = plan.unreached_keys.clone();
            preview.password_only = self.key_file.needs_security_key() && plan.password_only();
            preview.keysync_on = plan.sync;
        }
        // Key-file sync turned on here, or left (spec §7.16).
        #[cfg(feature = "security-key")]
        {
            if check.class == AdoptClass::Successor {
                preview.keysync_on = other.magic() == Some(keyfile::Magic::Ks01);
            }
            // `keysync_on` says here whether the result is GOYOKS01.
            let result = preview.keysync_on;
            preview.keysync_on = result && !self.ks01();
            if !result {
                preview.keysync_off = self
                    .take_ks(check)
                    .map(|ks| !matches!(ks, anchor::Ks::None));
            }
        }
        Ok(AdoptPlan {
            check: now,
            gate,
            path: other.path().to_owned(),
            bytes: other.bytes().to_vec(),
            other: opened,
            equal,
            preview,
            session: self.serial,
            app_serial: r.app_serial,
            #[cfg(feature = "security-key")]
            option,
        })
    }
    /// Writes the adopt `plan` (spec §5.8) through the key-change engine:
    /// the successor re-sealed with this PC's seal block, or the union. The
    /// checks run again first; anything changed since the preview writes
    /// nothing. With security keys, `extra` are touches offered so that no
    /// key is suspended, and `consent` the keys S-SUSPEND named; the
    /// default build has neither, and no gate holds an adopt there.
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
            || r.age() > REAUTH_MAX
            || (self.uses_otp() && r.otp_step.is_none())
        {
            return Err(REAUTH_STALE);
        }
        #[cfg(not(feature = "security-key"))]
        if !extra.is_empty() || !consent.suspend.is_empty() || acks.password_only {
            return Err(AUTH_ERROR);
        }
        let other = KeyFile::from_bytes(&plan.path, plan.bytes.clone())?;
        if self.adopt_check(&other, source_of(&plan.check, &plan.path))? != plan.check
            || plan.gate.state() != plan.check.other
        {
            return Err(ADOPT_STALE);
        }
        // A take that trusted the server (spec §2.30) is judged again at
        // the write, like the checks: the setting turned off, or the
        // server's view moved on, since the preview writes nothing.
        #[cfg(feature = "security-key")]
        if matches!(plan.gate, GatePass::Trusted { .. }) && !self.trusts(&plan.check) {
            return Err(gate::NOT_TRUSTED);
        }
        // Key-file sync turned on here only with S-KEYSYNC-ON's yes, a
        // touch that stated its transport, and no off of this PC pending;
        // the `ks` and `merged` this write records (spec §7.16).
        #[cfg(feature = "security-key")]
        let landing = {
            if plan.preview.keysync_on && (!acks.keysync_on || r.transport().is_none()) {
                return Err(if acks.keysync_on {
                    super::super::keysync::KEYSYNC_NOTRANSPORT
                } else {
                    super::NOT_PLANNED
                });
            }
            let ks = if plan.preview.keysync_on {
                Some(self.on_ks()?)
            } else {
                plan.preview.keysync_off.and(self.take_ks(&plan.check))
            };
            let (merged, clear_gate) = self.take_marks(&plan.check);
            let trusted = matches!(plan.gate, GatePass::Trusted { .. });
            (ks, merged, clear_gate, trusted)
        };
        if !self.key_on_disk()? {
            return Err(KEY_CHANGED);
        }
        // Where the preview asked S-ADOPT-BOTHPASS, only a yes writes; so
        // with S-ADOPT-PWONLY, and with the fork option it was made for.
        if plan.preview.both_passwords && !acks.both_passwords {
            return Err(ADOPT_STALE);
        }
        #[cfg(feature = "security-key")]
        if (plan.preview.password_only && !acks.password_only)
            || (plan.check.fork && acks.fork_option != plan.option)
        {
            return Err(ADOPT_STALE);
        }
        #[cfg(feature = "security-key")]
        let take_other = plan.check.fork && plan.option == ForkOption::TakeOther;
        #[cfg(not(feature = "security-key"))]
        let take_other = false;
        let keep_own = plan.preview.own_pass.is_some()
            && acks.union_password == UnionPassword::Own
            && !take_other;
        let same = plan.equal || keep_own;
        #[cfg(feature = "security-key")]
        let mut report = (Vec::new(), Vec::new(), Vec::new());
        #[cfg(feature = "security-key")]
        let (plan_gate, plan_change) = (plan.gate.clone(), plan.preview.change.clone());
        let rekeyed = match plan.check.class {
            #[cfg(feature = "security-key")]
            AdoptClass::Successor if other.needs_security_key() => {
                let touched = plan.other.touched.as_ref();
                let mut built =
                    self.reseal_keys(&other, &plan.other.opened, &plan.other.password, touched)?;
                (
                    built.landing.ks,
                    built.landing.merged,
                    built.landing.clear_gate,
                    built.landing.trusted,
                ) = landing;
                self.land(
                    built,
                    anchor::Src::Adopt,
                    (!same).then_some(anchor::Pw::Other),
                )?
            }
            AdoptClass::Successor => {
                let built = self.successor_of(&other, &plan.other)?;
                self.land(
                    built,
                    anchor::Src::Adopt,
                    (!same).then_some(anchor::Pw::Other),
                )?
            }
            #[cfg(feature = "security-key")]
            AdoptClass::Union
                if self.key_file.needs_security_key() || other.needs_security_key() =>
            {
                let join = self.join_of(&plan.check, plan.option);
                let readmit = self.readmit_of(&plan.check, join);
                let extra = self.extra_outputs(&r, &extra)?;
                let mut union = self.plan_union(
                    r.keys.as_ref(),
                    &other,
                    plan.other.touched.as_ref(),
                    &extra,
                    join,
                    &readmit,
                )?;
                if union.sync && !self.ks01() && !plan.preview.keysync_on {
                    return Err(ADOPT_STALE);
                }
                (
                    union.landing.ks,
                    union.landing.merged,
                    union.landing.clear_gate,
                    union.landing.trusted,
                ) = landing;
                report = (
                    union.renumbered.clone(),
                    union.dropped_uv.clone(),
                    union.suspended(),
                );
                let keys = self.union_ring(&other, &plan.other, take_other)?;
                let password: Zeroizing<String> = if keep_own {
                    r.password.clone()
                } else {
                    plan.other.password.clone()
                };
                let theirs = other.header().map(|h| h.pw_id);
                let mine = self.key_file.header().map(|h| h.pw_id);
                let pw_id = match (plan.equal, keep_own) {
                    (true, _) => theirs.or(mine),
                    (false, true) => mine,
                    (false, false) => theirs,
                };
                let pw_id = match pw_id {
                    Some(pw_id) => pw_id,
                    None => fresh_pw_id()?,
                };
                let pw = (!same).then_some(anchor::Pw::Other);
                let epoch = plan.check.epoch;
                let (trusted, change) = (
                    matches!(plan_gate, GatePass::Trusted { .. }),
                    plan.preview.change.clone(),
                );
                return self
                    .write_union(r, union, keys, &password, pw_id, epoch, &consent, pw)
                    .map(|rekeyed| Adopted {
                        trusted,
                        change,
                        ..self.adopted(rekeyed, same, report)
                    });
            }
            AdoptClass::Union => {
                #[cfg(feature = "security-key")]
                if !extra.is_empty() || !consent.suspend.is_empty() || acks.password_only {
                    return Err(AUTH_ERROR);
                }
                let password: &str = if keep_own {
                    &r.password
                } else {
                    &plan.other.password
                };
                let keep = (keep_own, plan.equal);
                let built =
                    self.union_with(&other, &plan.other, plan.check.epoch, password, keep)?;
                self.land(
                    built,
                    anchor::Src::Adopt,
                    (!same).then_some(anchor::Pw::Other),
                )?
            }
            AdoptClass::Equal => return Err(ADOPT_EQUAL),
            AdoptClass::Contained => return Err(ADOPT_CONTAINED),
        };
        drop(r);
        // A successor taken with its own code ends a bootstrap (spec §7.17):
        // its S0 entry wrote `t` for it. A gate passed allows G2 again; a
        // take that trusted the server asked no gate (spec §2.30).
        #[cfg(feature = "security-key")]
        {
            (self.tofu, self.held_unconfirmed) = (false, false);
            if !matches!(plan_gate, GatePass::Trusted { .. }) {
                self.g2_spent.set(false);
            }
        }
        #[allow(unused_mut)]
        let mut adopted = self.adopted(
            rekeyed,
            same,
            #[cfg(feature = "security-key")]
            report,
        );
        #[cfg(feature = "security-key")]
        {
            adopted.trusted = matches!(plan_gate, GatePass::Trusted { .. });
            adopted.change = plan_change;
        }
        Ok(adopted)
    }
    /// What an adopt wrote, for the status (spec §5.8).
    fn adopted(
        &self,
        rekeyed: Rekeyed,
        same: bool,
        #[cfg(feature = "security-key")] report: (Vec<(u8, u8)>, Vec<u8>, Vec<u8>),
    ) -> Adopted {
        #[cfg(feature = "security-key")]
        let (renumbered, dropped_uv, suspended) = report;
        Adopted {
            state: self.key_state,
            code: key_code(&self.id, self.keys.current(), self.key_state),
            password: if same {
                PassInForce::Own
            } else {
                PassInForce::Other
            },
            vault_pending: rekeyed == Rekeyed::VaultPending,
            gap_kept: rekeyed == Rekeyed::GapKept,
            #[cfg(feature = "security-key")]
            renumbered,
            #[cfg(feature = "security-key")]
            dropped_uv,
            #[cfg(feature = "security-key")]
            suspended,
            #[cfg(feature = "security-key")]
            trusted: false,
            #[cfg(feature = "security-key")]
            change: KeyChange::default(),
        }
    }
    /// What `other` changes of this PC's keys and password (spec §2.30):
    /// R by this PC's numbers, Δ by the file's, the password by `pw_id`,
    /// and T_new, a policy or a slot change as "other".
    #[cfg(feature = "security-key")]
    fn key_change(&self, check: &AdoptCheck, other: &KeyFile) -> KeyChange {
        let (Some(own), Some(theirs)) = (self.key_file.header(), other.header()) else {
            return KeyChange::default();
        };
        let g = &check.keys.checked.gates;
        let number = |h: &KeyHeader, c: &[u8; 16]| {
            h.slots.iter().find(|s| s.credhash == *c).map(|s| s.number)
        };
        KeyChange {
            removed: g.removed.iter().filter_map(|c| number(own, c)).collect(),
            added: g.added.iter().filter_map(|c| number(theirs, c)).collect(),
            password: !ct_eq(&own.pw_id, &theirs.pw_id),
            other: !g.unknown.is_empty() || g.policy || g.slot,
        }
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
    /// A union's keyring (spec §5.8): a fresh data key first, then this
    /// PC's keys, then the other file's that this PC lacks, and the ID key
    /// last (fork option 1: the other file's keys first, then this PC's);
    /// past MAX_KEYS the middle part's last entry goes first, never the
    /// fresh key, either current key or the ID key. The fresh key is one
    /// neither file ever held.
    fn union_ring(
        &self,
        other: &KeyFile,
        opened: &OtherOpened,
        take_other: bool,
    ) -> Result<Zeroizing<Vec<[u8; 32]>>> {
        let own = self.own_public();
        let theirs = self.other_public(other)?;
        let id = &self.id;
        let ours = self.keys.keys();
        let others = opened.opened.bundle.keys();
        let known: Vec<[u8; 16]> = ours.iter().chain(others).map(|k| key_id(id, k)).collect();
        let mut dk: Box<Key> = Box::default();
        loop {
            crypto::random_into(dk.as_mut_slice())?;
            if !known.contains(&key_id(id, &dk)) {
                break;
            }
        }
        let (first, second) = if take_other {
            (others, ours)
        } else {
            (ours, others)
        };
        // Sized up front: a growing Vec would free unwiped copies.
        let mut keys = Zeroizing::new(Vec::with_capacity(ours.len() + others.len() + 1));
        keys.push(**dk);
        keys.extend_from_slice(&first[..first.len() - 1]);
        let taken: Vec<[u8; 16]> = first.iter().map(|k| key_id(id, k)).collect();
        for key in &second[..second.len() - 1] {
            if !taken.contains(&key_id(id, key)) {
                keys.push(*key);
            }
        }
        keys.push(*self.keys.id_key());
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
        Ok(keys)
    }
    /// The union (kind 9, spec §5.8) of two password-only key files under a
    /// fresh data key, with every removal of both; sealed with `password`,
    /// the other file's or this PC's (`keep_own`), with the other file's
    /// `pw_id` when the two passwords are the same (`equal`).
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
        let keys = self.union_ring(other, opened, false)?;
        let bundle = Bundle::new(&keys, self.keys.otp()).ok_or(AUTH_ERROR)?;
        // The same password takes the other file's `pw_id`, so neither PC
        // sees a password change; a 0.8 file has none to keep.
        let pw_id = match (equal, keep_own) {
            (true, _) => theirs.pw_id.or(own.pw_id),
            (false, true) => own.pw_id,
            (false, false) => theirs.pw_id,
        };
        let spec = Spec {
            vault_id: self.id,
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

/// The security-key parts of an adopt (spec §5.8, §7.15a).
#[cfg(feature = "security-key")]
impl Session {
    /// The `gated` epoch an adopt's silent jump counts from (round 3,
    /// finding 16): the confirmed line's, unless that line is a security-key
    /// state this PC never confirmed, or there is none in a TOFU session.
    fn gated(&self) -> Option<u64> {
        match self.anchor.lines.vault.as_ref() {
            Some(l) if l.state.flags.t || !l.state.hardware() => Some(l.state.gated),
            Some(_) => None,
            None if self.unconfirmed() || self.key_file.needs_security_key() => None,
            None => Some(self.max_epoch),
        }
    }
    /// G2 while it is allowed on this PC for this vault, else G1 (spec
    /// §7.15a: one wrong pick turns it off until a gate passes).
    fn ask(&self, kind: Option<GateKind>) -> Option<GateKind> {
        match kind {
            Some(GateKind::G2) if !self.g2_allowed() => Some(GateKind::G1),
            kind => kind,
        }
    }
    /// Whether G2 is still allowed: no pick failed in this session, and
    /// none in the anchor as it is now.
    fn g2_allowed(&self) -> bool {
        if self.g2_spent.get() {
            return false;
        }
        let lines = match self.anchor.dir.as_deref().map(anchor::read) {
            Some(Ok(anchor::Parsed::Doc(doc))) => doc.lines(&self.id),
            _ => self.anchor.lines.clone(),
        };
        gate::g2_allowed(&lines)
    }
    /// Whether every key of `other` is live or removed here, and every pair
    /// record of `other` between two keys live here is one this PC has (spec
    /// §5.8 Older and Contained).
    fn keys_known(&self, other: &KeyFile) -> (bool, bool) {
        let (Some(o), Some(t)) = (self.key_file.header(), other.header()) else {
            return (other.header().is_none_or(|t| t.slots.is_empty()), true);
        };
        let known = |c: &[u8; 16]| {
            o.slots.iter().any(|s| s.credhash == *c)
                || o.tombstones.iter().any(|x| x.credhash == *c)
        };
        let live = |c: &[u8; 16]| o.slots.iter().any(|s| s.credhash == *c);
        let mine = self.key_file.carried_pairs();
        let pairs = other.carried_pairs().iter().all(|p| match p {
            keyfile::PairPlan::Copy { owner, target, .. } if live(owner) && live(target) => {
                mine.contains(p)
            }
            _ => true,
        });
        (t.slots.iter().all(|s| known(&s.credhash)), pairs)
    }
    /// The gates of a union (spec §5.8): G1 for an addition, a removal of a
    /// key this PC never knew, a policy or slot change (and for a file that
    /// descends from this PC's state, a silent jump); G2 for removals of
    /// this PC's keys; none otherwise. For a fork, also option 1: offered
    /// only when every key it brings back was removed by another file
    /// (`t`), behind G1 when it brings any back, else as option 2 but G1
    /// also for no removal at all.
    fn union_gates(&self, checked: Checked, fork: bool) -> KeyGates {
        let g = &checked.gates;
        let g1 = !g.added.is_empty() || !g.unknown.is_empty() || g.policy || g.slot;
        let gate = self.ask(if g1 || (!fork && g.jump) {
            Some(GateKind::G1)
        } else if !g.removed.is_empty() {
            Some(GateKind::G2)
        } else {
            None
        });
        if !fork {
            return KeyGates {
                checked,
                gate,
                both: true,
                ..KeyGates::default()
            };
        }
        let line = self.anchor.lines.vault.as_ref();
        let origin = |c: &[u8; 16]| {
            line.and_then(|l| l.state.tombs.iter().find(|t| t.credhash == *c))
                .map(|t| t.origin)
        };
        let mut readmit: Vec<[u8; 16]> = checked.relisted.clone();
        readmit.extend(checked.removed_authorizer);
        readmit.dedup();
        let take_other_offered = readmit
            .iter()
            .all(|c| origin(c) == Some(anchor::Origin::Taken));
        let take_other = if !readmit.is_empty() || g1 || g.removed.is_empty() {
            GateKind::G1
        } else {
            self.ask(Some(GateKind::G2)).unwrap_or(GateKind::G1)
        };
        KeyGates {
            both: checked.removed_authorizer.is_none(),
            gate,
            take_other_offered,
            take_other: Some(take_other),
            readmit,
            checked,
        }
    }
    /// The way a union joins the files.
    fn join_of(&self, check: &AdoptCheck, option: ForkOption) -> Join {
        match (check.fork, option) {
            (false, _) => Join::Chained,
            (true, ForkOption::TakeOther) => Join::TakeOther,
            (true, ForkOption::Both) => Join::Both,
        }
    }
    /// The removals option 1 drops.
    fn readmit_of(&self, check: &AdoptCheck, join: Join) -> Vec<[u8; 16]> {
        if join == Join::TakeOther {
            check.keys.readmit.clone()
        } else {
            Vec::new()
        }
    }
    /// Judges the gate answered for `check` and the way chosen (spec §5.8
    /// "Binding"): exactly the file it was asked for; a pick equal to R; a
    /// code equal to the opened file's own key code. A wrong pick turns G2
    /// off for this vault (S-GATE-G2FAIL); in TOFU only G1 takes anything.
    fn judge_gate(
        &self,
        check: &AdoptCheck,
        answer: &GatePass,
        option: ForkOption,
        opened: &OtherOpened,
    ) -> Result<()> {
        let keys = &check.keys;
        let needed = match (check.class, check.fork, option) {
            (AdoptClass::Union, true, ForkOption::TakeOther) if !keys.take_other_offered => {
                return Err(super::NOT_PLANNED);
            }
            (AdoptClass::Union, true, ForkOption::TakeOther) => keys.take_other,
            (AdoptClass::Union, true, ForkOption::Both) if !keys.both => {
                return Err(super::NOT_PLANNED);
            }
            _ => keys.gate,
        };
        match (answer, needed) {
            (GatePass::NotNeeded { .. }, None) => Ok(()),
            (GatePass::G2Passed { pick, .. }, Some(GateKind::G2)) => {
                if keys.checked.gates.pick_matches(pick) {
                    return Ok(());
                }
                // Turned off for this vault until a gate passes or the user
                // starts a key change (S45-2 #8): for this session at once,
                // and in the anchor. An anchor that cannot be written says
                // so; G2 stays off for the session.
                self.g2_spent.set(true);
                let dir = self.anchor.dir.as_deref().ok_or(super::ANCHOR_FAILED)?;
                let (state, now) = (check.other, crate::otp::now()?);
                match anchor::update(dir, &self.id, anchor::LOCK_WAIT, &mut |lines| {
                    gate::g2_failed(lines, state, now);
                    true
                }) {
                    Ok(_) => Err(gate::GATE_G2FAIL),
                    #[cfg(test)]
                    Err(anchor::Failure::Crash) => Err(super::super::SIMULATED_CRASH),
                    Err(anchor::Failure::Newer) => Err(anchor::ANCHOR_NEWER),
                    Err(_) => Err(super::ANCHOR_FAILED),
                }
            }
            (GatePass::G1Passed { code, .. }, Some(_)) => {
                let dk = opened.opened.bundle.current();
                if gate::code_matches(code, &self.id, dk, check.other) {
                    Ok(())
                } else {
                    Err(gate::GATE_CODE_WRONG)
                }
            }
            // Auto-apply (spec §2.30): the server channel only, a file that
            // descends from this PC's, never in TOFU; everything above (the
            // public checks again, the open, rule D) and below (E5, the
            // write's checks) still holds.
            (GatePass::Trusted { .. }, Some(_)) if self.trusts(check) => Ok(()),
            (GatePass::Trusted { .. }, Some(_)) => Err(gate::NOT_TRUSTED),
            _ => Err(ADOPT_STALE),
        }
    }
}
/// The source an adopt checks the file from again: the one it was checked
/// from (a server file is judged as the server's in every check).
fn source_of(check: &AdoptCheck, path: &std::path::Path) -> Source {
    #[cfg(feature = "security-key")]
    {
        let _ = path;
        check.source.clone()
    }
    #[cfg(not(feature = "security-key"))]
    {
        let _ = check;
        Source::File(path.to_owned())
    }
}
/// The removals of two key files, one per credential (spec §5.8): the
/// earliest epoch, and the loss mark of either, the earlier date when both
/// have one (1, a loss on an unknown date, counts as the earliest).
pub(super) fn joined_tombs(a: &[Tombstone], b: &[Tombstone]) -> Vec<Tombstone> {
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
        RESTORE_PENDING, SIMULATED_CRASH, encode_key, read_header, refusal_values,
    };
    use super::super::CORRUPT;
    use super::super::tests::{
        Codes, NEW, OLD, Pc, THIRD, What, change, entry, keys_of, login, notices, other_of,
        pass_gate, sealed, sealed_with, secrets, set_before, setup, vault_of,
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
            #[cfg(feature = "security-key")]
            fork_option: ForkOption::Both,
            #[cfg(feature = "security-key")]
            keysync_on: false,
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
        take_with(s, codes, mine, other, theirs, GatePass::none, answer)
    }
    /// The same with the gate answered by `gate`.
    fn take_with(
        s: &mut Session,
        codes: &mut Codes,
        mine: &str,
        other: &[u8],
        theirs: &str,
        gate: impl FnOnce(&AdoptCheck) -> GatePass,
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
        let plan = s.adopt_preview(&r, &f, opened, &check, gate(&check), None)?;
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
        // The security-key build reads it, and it is another vault's.
        #[cfg(not(feature = "security-key"))]
        let refusal = keyfile::NO_SECURITY_KEY_SUPPORT;
        #[cfg(feature = "security-key")]
        let refusal = NOT_THIS_VAULT;
        assert_eq!(classify(&s, &hardware).err(), Some(refusal));
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
                #[cfg(feature = "security-key")]
                renumbered: Vec::new(),
                #[cfg(feature = "security-key")]
                dropped_uv: Vec::new(),
                #[cfg(feature = "security-key")]
                suspended: Vec::new(),
                // A password change, asked no gate (spec §2.30).
                #[cfg(feature = "security-key")]
                trusted: false,
                #[cfg(feature = "security-key")]
                change: KeyChange {
                    password: true,
                    ..KeyChange::default()
                },
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
        // More than EPOCH_SILENT above the last state this PC wrote: the
        // security-key build takes it only with its code (G1; round 3,
        // finding 16), the default build silently.
        #[cfg(feature = "security-key")]
        {
            let check = classify(&s, &ahead).unwrap();
            assert_eq!(check.keys.gate, Some(GateKind::G1));
            assert!(check.keys.checked.gates.jump);
            let f = file(&ahead);
            let (code, typed) = codes.next();
            let r = s.reauth(OLD, Some((&code, typed)), None).unwrap();
            let opened = s.adopt_open(&r, &f, Some(NEW)).unwrap();
            let none = GatePass::none(&check);
            assert_eq!(
                s.adopt_preview(&r, &f, opened, &check, none, None).err(),
                Some(ADOPT_STALE)
            );
        }
        #[cfg(feature = "security-key")]
        let adopted = {
            let dk = keys_of(&ahead, NEW)[0];
            let code = key_code(&id, &dk, state);
            let gate = |c: &AdoptCheck| GatePass::G1Passed {
                code,
                epoch: c.other.epoch,
                tag: c.other.tag,
            };
            take_with(&mut s, &mut codes, OLD, &ahead, NEW, gate, defaults).unwrap()
        };
        #[cfg(not(feature = "security-key"))]
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
        pass_gate(&mut s);
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
        let preview = s.adopt_preview(&r, &f, opened, &check, another.clone(), None);
        assert_eq!(preview.err(), Some(ADOPT_STALE));
        let opened = s.adopt_open(&r, &g, Some(NEW)).unwrap();
        let pass = GatePass::none(&check);
        let preview = s.adopt_preview(&r, &f, opened, &check, pass.clone(), None);
        assert_eq!(preview.err(), Some(ADOPT_STALE));
        let plan = |s: &Session, r: &Reauth| {
            let opened = s.adopt_open(r, &f, Some(NEW)).unwrap();
            s.adopt_preview(r, &f, opened, &check, pass.clone(), None)
                .unwrap()
        };
        let acks = Acks {
            password_only: false,
            union_password: UnionPassword::Other,
            both_passwords: false,
            #[cfg(feature = "security-key")]
            fork_option: ForkOption::Both,
            #[cfg(feature = "security-key")]
            keysync_on: false,
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
