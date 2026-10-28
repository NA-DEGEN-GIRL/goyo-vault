"""Mutation tests (spec v3 §14.11): each row removes one rule from a copy of
the tree and runs the tests that must catch it. A row passes when at least
one of its tests fails in every build it runs in; a row whose tests all
pass, whose snippet does not occur exactly once, or whose mutant does not
build fails the run. For a P+G rule the catching test is a forger test that
then passes. Standard library only; not shipped.

    python -X utf8 scripts/mutate.py            every row
    python -X utf8 scripts/mutate.py --check    the snippets only, no build
    python -X utf8 scripts/mutate.py --list     the rows
    python -X utf8 scripts/mutate.py TEXT...    the rows whose name holds a TEXT

A row: its name, the stage that added the rule, the builds it runs in
('feature': --features security-key; 'default'; 'both': code that both
builds compile, so each build must catch it), the test target ('lib' or
'bin': the goyo-vault binary), the file, the exact snippet and its
replacement, and the full paths of the tests that catch it (one list for
every build, or one per build). Only those tests run, each by its exact
path (a stricter test than the whole suite: the named test itself must
fail). Before the mutants, the named tests of each build and target run
unmutated and must pass. A test run that ends after TIMEOUT seconds counts
as failed (a mutant that loops forever is caught; a baseline that does is a
failure). The copy lives in a temporary folder; the builds reuse
target/mutate under the tree's root. run_checks.py --mutate runs this.
"""
import os, pathlib, re, shutil, subprocess, sys, tempfile

root = pathlib.Path(__file__).resolve().parents[1]
GATE = 'src/vault/gate.rs'
ADOPT = 'src/vault/rotate/adopt.rs'
ANCHOR = 'src/vault/anchor.rs'
ROTATE = 'src/vault/rotate.rs'
HWRS = 'src/vault/rotate/hw.rs'
SYNC = 'src/vault/sync.rs'
VAULT = 'src/vault.rs'
REVIEW = 'src/vault/review.rs'
KEYFILE = 'src/vault/keyfile.rs'
INBOX = 'src/vault/keyfile/inbox.rs'
FIDO = 'src/fido.rs'
MAIN = 'src/main.rs'
TIMEOUT = 1800

HW = 'vault::rotate::hw::tests::'
GATES = HW + 'gates::'
TAKES = GATES + 'the_removed_key_forges_nothing_a_pc_behind_takes'
AT_LOGIN = GATES + 'the_removed_key_forges_nothing_a_pc_behind_opens_at_login'
UP_TO_DATE = GATES + 'every_file_the_removed_key_writes_is_refused_before_any_touch'
RECORDS = GATES + 'a_forged_file_changes_no_record_of_a_known_key'
G1_TRIGGERS = GATES + 'a_forged_renumbering_reseed_or_policy_change_needs_the_code'
OLD_REMOVAL = GATES + 'a_forged_file_that_drops_or_relists_an_old_removal_is_refused'
NO_OPTION = GATES + 'a_branch_of_a_removed_key_gets_no_option'
BOOTSTRAP = GATES + 'a_bootstrap_takes_only_a_successor_with_its_code'
SAME_PASSWORD = GATES + 'a_password_change_that_keeps_the_password_is_refused'
ARITHMETIC = GATES + 'the_gate_counts_every_change_as_a_whole'
ADOPT_GATE = GATES + 'another_pcs_removal_is_taken_behind_its_gate'
LOGIN_GATE = GATES + 'a_changed_key_file_at_login_waits_for_its_gate'
TOFU = GATES + 'a_key_file_with_keys_and_no_record_is_a_bootstrap'
LEGACY_OWN = GATES + 'a_pc_with_a_0_8_key_file_takes_keys_only_with_the_code'
BUSY_ANCHOR = GATES + 'a_wrong_pick_turns_g2_off_when_the_anchor_is_busy'
HELD = GATES + 'a_held_session_this_pc_never_confirmed_edits_nothing'
ANCHOR_RULES = GATES + 'the_anchor_refuses_removed_keys_and_missed_additions'
KEYS_OFF = GATES + 'keys_off_elsewhere_needs_its_code_and_a_yes'
CONSENT = GATES + 'a_union_suspends_only_with_consent'
REVIEW_PATHS = GATES + 'a_removal_for_a_loss_makes_its_review_due_on_every_path'
UNDONE = GATES + 'a_removal_that_never_landed_is_named_and_its_review_stays_due'
OTP_PENDING = GATES + 'a_gate_pending_login_keeps_its_otp_code_used'
REFUSED_FIRST = HW + 'changes_with_keys_are_refused_before_anything_is_written'
CREATE_ANCHOR = HW + 'a_vault_made_with_keys_writes_its_anchor_line_first'
SECOND_LOSS = HW + 'a_replacement_key_and_a_second_loss_before_its_pairing_visit'
LOG = 'vault::review::tests::the_window_only_grows_and_a_d_line_ends_it'
ANCHOR_HELD = HW + 'an_anchor_that_cannot_be_written_holds_a_security_key_session'
CLONED = HW + 'possibly_cloned_flags_land_with_the_removal_and_go_with_a_reseed'
INBOX_T = 'vault::keyfile::inbox::tests::'
KEYFILE_T = 'vault::keyfile::tests::'
ANCHOR_T = 'vault::anchor::tests::'
ROTATE_T = 'vault::rotate::tests::'
ADOPT_T = 'vault::rotate::adopt::tests::'
SYNC_T = 'vault::sync::tests::'
VAULT_T = 'vault::tests::'
WORKFLOW_T = 'vault::workflow_tests::'
FIDO_T = 'fido::tests::'
FAKE_T = 'fido::fake::tests::'
BIN_T = 'tests::'

ROWS = [
    # Stage 4: the public checks, the gate and E5 (§14.11; forger tests of
    # the removed-key simulator, §14.10-5).
    ('P3 (a): a removed key listed live', 4, 'feature', 'lib', GATE,
     '        if o_tombs.iter().any(|x| x.credhash == s.credhash) {',
     '        if false && o_tombs.iter().any(|x| x.credhash == s.credhash) {',
     [OLD_REMOVAL]),
    ('P3 (b): a removal missing', 4, 'feature', 'lib', GATE,
     '                return Err(LACKS_REMOVAL);',
     '                continue;',
     [OLD_REMOVAL]),
    ('P4: an authorizer removed here', 4, 'feature', 'lib', GATE,
     '            if !since_fork(&slot.credhash) || !taken {',
     '            if false && !taken {',
     [UP_TO_DATE, NO_OPTION]),
    ('P4: relaxed only for a removal taken from another file', 4, 'feature', 'lib', GATE,
     '            if !since_fork(&slot.credhash) || !taken {',
     '            if !since_fork(&slot.credhash) {',
     [UP_TO_DATE, NO_OPTION]),
    ('P3 (a) and P4 against the anchor (S-ANCHOR-RELIST-SK)', 4, 'feature', 'lib', ANCHOR,
     '    if super::gate::relisted(h, c) {',
     '    if false && super::gate::relisted(h, c) {',
     [UP_TO_DATE, OLD_REMOVAL]),
    ('E1 against the anchor at login', 4, 'feature', 'lib', ANCHOR,
     '    if (h.flags ^ c.policy) & 1 != 0 {',
     '    if false && (h.flags ^ c.policy) & 1 != 0 {',
     [G1_TRIGGERS]),
    ('slot pinning: a known key\'s record', 4, 'feature', 'lib', GATE,
     '                if a.idhash != b.idhash {',
     '                if false && a.idhash != b.idhash {',
     [RECORDS]),
    ('slot pinning: a number or seed change is a slot change', 4, 'feature', 'lib', GATE,
     '                slot |= a.number != b.number || a.seedhash != b.seedhash;',
     '                let _ = (a.number, b.number, &a.seedhash, &b.seedhash);',
     [TAKES, G1_TRIGGERS]),
    ('pair-record pinning', 4, 'feature', 'lib', GATE,
     '        if !(broken || rewritten || copied) {',
     '        if false && !(broken || rewritten || copied) {',
     [RECORDS]),
    ('G1 for an addition (Δ)', 4, 'feature', 'lib', GATE,
     '        if !self.added.is_empty()\n            || !self.unknown.is_empty()',
     '        if !self.unknown.is_empty()',
     [TAKES, AT_LOGIN]),
    ('G1 for removals of unknown keys (T_new)', 4, 'feature', 'lib', GATE,
     '            || !self.unknown.is_empty()\n            || self.policy',
     '            || self.policy',
     [G1_TRIGGERS]),
    ('G1 for a policy change', 4, 'feature', 'lib', GATE,
     '            || self.policy\n            || self.slot',
     '            || self.slot',
     [G1_TRIGGERS]),
    ('G1 for a slot change', 4, 'feature', 'lib', GATE,
     '            || self.slot\n            || self.jump',
     '            || self.jump',
     [TAKES, G1_TRIGGERS]),
    ('G1 for a silent jump', 4, 'feature', 'lib', GATE,
     '            || self.jump\n        {',
     '        {',
     [G1_TRIGGERS]),
    ('the gate of a 0.8 key file of this PC', 4, 'feature', 'lib', ADOPT,
     '        let checked = match other.header() {\n            Some(_) => {',
     '        let checked = match other.header().filter(|_| self.key_file.header().is_some()) {\n            Some(_) => {',
     [LEGACY_OWN]),
    ('G1 at an adopt: the keyed code compare', 4, 'feature', 'lib', ADOPT,
     '                if gate::code_matches(code, &self.id, dk, check.other) {',
     '                if true || gate::code_matches(code, &self.id, dk, check.other) {',
     [TAKES, ADOPT_GATE]),
    ('G1 at login: the keyed code compare', 4, 'feature', 'lib', GATE,
     '                if !code_matches(&code, &self.id, self.keys.current(), g.state) {',
     '                if false && !code_matches(&code, &self.id, self.keys.current(), g.state) {',
     [AT_LOGIN, LOGIN_GATE]),
    ('G1 in TOFU: the keyed code compare', 4, 'feature', 'lib', GATE,
     '            && (h.is_none() || !code_matches(code, &self.id, self.keys.current(), self.key_state))',
     '            && h.is_none()',
     [AT_LOGIN, TOFU]),
    ('G2: exactly R', 4, 'feature', 'lib', GATE,
     '        !removed.is_empty() && pick.windows(2).all(|w| w[0] != w[1]) && pick == removed',
     '        !removed.is_empty() && !pick.is_empty()',
     [TAKES, AT_LOGIN, ARITHMETIC]),
    ('one-shot G2 at an adopt', 4, 'feature', 'lib', ADOPT,
     '            Some(GateKind::G2) if !self.g2_allowed() => Some(GateKind::G1),',
     '            Some(GateKind::G2) if false && !self.g2_allowed() => Some(GateKind::G1),',
     [TAKES, ADOPT_GATE]),
    ('one-shot G2 at login, from the anchor', 4, 'feature', 'lib', GATE,
     '            GateKind::G2 if g2_allowed(&self.anchor.lines) && !self.g2_spent.get() => GateKind::G2,',
     '            GateKind::G2 if !self.g2_spent.get() => GateKind::G2,',
     [AT_LOGIN, LOGIN_GATE]),
    ('one-shot G2 at login, for the session', 4, 'feature', 'lib', GATE,
     '            GateKind::G2 if g2_allowed(&self.anchor.lines) && !self.g2_spent.get() => GateKind::G2,',
     '            GateKind::G2 if g2_allowed(&self.anchor.lines) => GateKind::G2,',
     [BUSY_ANCHOR]),
    ('one-shot G2 kept in the anchor', 4, 'feature', 'lib', GATE,
     'pub(super) fn g2_failed(lines: &mut Lines, state: KeyState, now: u64) {\n',
     'pub(super) fn g2_failed(lines: &mut Lines, state: KeyState, now: u64) {\n    return;\n',
     [TAKES, AT_LOGIN]),
    ('one-shot G2 fails closed at an adopt', 4, 'feature', 'lib', ADOPT,
     '                self.g2_spent.set(true);\n                let dir',
     '                let dir',
     [BUSY_ANCHOR]),
    ('one-shot G2 fails closed at login', 4, 'feature', 'lib', GATE,
     '                    self.g2_spent.set(true);\n                    let now',
     '                    let now',
     [BUSY_ANCHOR]),
    ('the display rule: the pick lists this PC\'s own keys', 4, 'feature', 'lib', GATE,
     '        self.anchor\n            .lines\n            .vault\n            .as_ref()\n            .map(|v| choices(&v.state.slots))',
     '        self.key_file\n            .header()\n            .map(|h| choices(&h.slots.iter().map(anchor::slot_of).collect::<Vec<_>>()))',
     [AT_LOGIN]),
    # (A successor's G1 in TOFU is no row of its own: a bootstrap has no
    # `gated` epoch, so the silent-jump rule asks G1 there as well.)
    ('in TOFU only a successor is taken', 4, 'feature', 'lib', ADOPT,
     '        if self.unconfirmed() && !successor {',
     '        if false && self.unconfirmed() && !successor {',
     [BOOTSTRAP]),
    ('E5: a password change that keeps the password', 4, 'feature', 'lib', GATE,
     '    if own.magic.hardware() && !ct_eq(&own.pw_id, &other.pw_id) && same {',
     '    if false && own.magic.hardware() && !ct_eq(&own.pw_id, &other.pw_id) && same {',
     [TAKES, SAME_PASSWORD]),
    ('the GatePass binding', 4, 'feature', 'lib', ADOPT,
     '        if gate.state() != now.other || now != *check || opened.sha != sha256(other.bytes()) {',
     '        if now != *check || opened.sha != sha256(other.bytes()) {',
     [ADOPT_GATE]),
    ('password-only is never a successor of a hardware file', 4, 'feature', 'lib', ADOPT,
     '            && !(self.key_file.needs_security_key() && !other.needs_security_key());',
     '            && true;',
     [KEYS_OFF]),
    ('S-ADOPT-PWONLY', 4, 'feature', 'lib', ADOPT,
     '        if (plan.preview.password_only && !acks.password_only)',
     '        if (false && plan.preview.password_only && !acks.password_only)',
     [KEYS_OFF]),
    # Stage 4: TOFU, gate-pending mode and the held sessions.
    ('a held session is never TOFU', 4, 'feature', 'lib', VAULT,
     '            s.tofu = unconfirmed && !s.local_rollback;',
     '            s.tofu = unconfirmed;',
     [HELD, ANCHOR_RULES]),
    ('a held session keeps TOFU\'s refusals', 4, 'feature', 'lib', VAULT,
     '            s.held_unconfirmed = unconfirmed && s.local_rollback;',
     '            s.held_unconfirmed = false;',
     [HELD]),
    ('gate-pending mode edits nothing', 4, 'feature', 'lib', GATE,
     '        if self.gate_login.is_some() {\n            return Err(GATE_HELD);\n        }\n        if self.unconfirmed() {',
     '        if self.unconfirmed() {',
     [LOGIN_GATE]),
    ('the OTP code used in gate-pending mode', 4, 'feature', 'lib', VAULT,
     '        if !merged && gated.is_some() && otp {',
     '        if !merged && gated.is_some() && otp && false {',
     [OTP_PENDING]),
    # Stage 4: the review's core (§5.13) and S-REMOVE-UNDONE.
    ('S0r: the review in the merge log first', 4, 'feature', 'lib', ROTATE,
     '        let review = match pending.loss.as_deref() {',
     '        let review = match None::<&str> {',
     [UNDONE]),
    ('the review of a removal taken at a login gate', 4, 'feature', 'lib', GATE,
     '        let review = match super::review::loss_of(&gates.removed, &h.tombstones) {',
     '        let review = match None::<String> {',
     [REVIEW_PATHS]),
    ('the review of a removal taken by an adopt', 4, 'feature', 'lib', HWRS,
     '                .or_else(|| super::super::review::loss_of(&removed, &kh.tombstones));',
     '                .or_else(|| removed.first().map(|_| None).unwrap_or(None));',
     [REVIEW_PATHS, UNDONE]),
    ('the review holds the vault outgoing', 4, 'feature', 'lib', SYNC,
     '        if self.review_due.is_some() {\n            let path = link.dir.join(OUTGOING);',
     '        if false && self.review_due.is_some() {\n            let path = link.dir.join(OUTGOING);',
     [REVIEW_PATHS]),
    ('the merge log returns the earliest R date', 4, 'feature', 'lib', REVIEW,
     '                due = Some(due.map_or(date, |d| earlier(d, date)));',
     '                due = Some(date);',
     [LOG]),
    ('an R line carries the earlier date of a due review', 4, 'feature', 'lib', REVIEW,
     '            date = earlier(&due, &date).to_owned();',
     '            let _ = (due, &date);',
     [LOG]),
    ('S-REMOVE-UNDONE names a dropped removal', 4, 'feature', 'lib', VAULT,
     '                    Some(numbers) => KeyNotice::RemoveUndone(numbers),\n                    None => KeyNotice::NotFinished,',
     '                    Some(_) | None => KeyNotice::NotFinished,',
     [UNDONE]),
    ('create keeps its promoted line when S5 fails', 4, 'feature', 'lib', HWRS,
     '        session.anchor_update(anchor::LOCK_WAIT, &mut |lines| {\n            if lines.pending.as_ref() == Some(&pending) {\n                lines.pending = None;\n            }\n            lines.vault = Some(line.clone());\n            true\n        })?;',
     '        let _ = session.anchor_strict(&mut |lines| {\n            if lines.pending.as_ref() == Some(&pending) {\n                lines.pending = None;\n            }\n            lines.vault = Some(line.clone());\n            true\n        });\n        session.key_notices.push(super::super::KeyNotice::SidecarFailed);',
     [CREATE_ANCHOR]),
    ('AnchorFailed holds a security-key session', 4, 'feature', 'lib', VAULT,
     '            self.anchor_failed |= hardware && self.anchor.unsaved;',
     '            let _ = self.anchor.unsaved;',
     [ANCHOR_HELD]),
    ('the "possibly cloned" flags land with their removal', 4, 'feature', 'lib', ROTATE,
     '                    anchor::apply_clone(lines, &pending);\n',
     '',
     [CLONED]),
    ('a re-seed retires a "possibly cloned" flag', 4, 'feature', 'lib', ANCHOR,
     '        lines.clones.retain(live);',
     '        let _ = live;',
     [CLONED]),
    # Stage 4: the write engine (§5.5) and the opens (§3.4).
    ('a key never authorizes its own removal (a ∉ removed)', 4, 'feature', 'lib', HWRS,
     '                            || t.present.iter().any(|(c, _)| gone(c))\n',
     '\n',
     [REFUSED_FIRST]),
    ('W6: a removal suspends only with consent', 4, 'feature', 'lib', HWRS,
     '            if !unreached.iter().all(|n| consent.suspend.contains(n)) {',
     '            if false && !unreached.iter().all(|n| consent.suspend.contains(n)) {',
     [SECOND_LOSS]),
    ('W6: a union suspends only with consent', 4, 'feature', 'lib', HWRS,
     '        if !plan.unreached.iter().all(|n| consent.suspend.contains(n)) {',
     '        if false && !plan.unreached.iter().all(|n| consent.suspend.contains(n)) {',
     [CONSENT]),
    ('W10: every S-wrap opens with its base', 4, 'feature', 'lib', INBOX,
     '        ok &= unwrap(&base, Use::SWrap, &ctx, s_wrap(bytes, h, i))\n            .is_some_and(|got| ct_eq(got.as_slice(), s));',
     '        let _ = (&base, &ctx);',
     [REFUSED_FIRST]),
    ('W10: every new pair record carries its inbox key', 4, 'feature', 'lib', INBOX,
     '                ok &= unwrap(&pair_seal(id, owner, h_o), Use::Pair, &ctx, record)\n                    .is_some_and(|ik| ct_eq(ik.as_slice(), want.as_slice()));',
     '                let _ = (h_o, &want, &ctx, record);',
     [REFUSED_FIRST]),
    ('Argon2 before the S-wrap step (cond. 2)', 4, 'feature', 'lib', INBOX,
     '    let pw_key = crypto::derive(password.as_bytes(), salt)?;\n    // Step 4: the parse placed exactly one S-wrap for j.\n    let i = h\n        .wraps\n        .iter()\n        .position(|(r, _)| usize::from(*r) == j)\n        .ok_or(AUTH_ERROR)?;\n    let via = &h.slots[usize::from(h.wraps[i].1)];\n    let base = if usize::from(h.wraps[i].1) == j {\n        own_base(&h.vault_id, slot, output)\n    } else {\n        inbox_key(&h.vault_id, slot, output, via)\n    };\n    let ctx = wrap_ctx(&h.vault_id, h.epoch, slot, via, &sha256(&[&bytes[..h.h()]]));\n    let mut ok = Choice::from(1);\n    let s = unwrap_read(&base, Use::SWrap, &ctx, s_wrap(bytes, h, i), &mut ok);\n    ok &= Choice::from(u8::from(ct_eq(&ks_id(&h.vault_id, &s), &h.ks_id)));\n',
     '    // Step 4: the parse placed exactly one S-wrap for j.\n    let i = h\n        .wraps\n        .iter()\n        .position(|(r, _)| usize::from(*r) == j)\n        .ok_or(AUTH_ERROR)?;\n    let via = &h.slots[usize::from(h.wraps[i].1)];\n    let base = if usize::from(h.wraps[i].1) == j {\n        own_base(&h.vault_id, slot, output)\n    } else {\n        inbox_key(&h.vault_id, slot, output, via)\n    };\n    let ctx = wrap_ctx(&h.vault_id, h.epoch, slot, via, &sha256(&[&bytes[..h.h()]]));\n    let mut ok = Choice::from(1);\n    let s = unwrap_read(&base, Use::SWrap, &ctx, s_wrap(bytes, h, i), &mut ok);\n    ok &= Choice::from(u8::from(ct_eq(&ks_id(&h.vault_id, &s), &h.ks_id)));\n    let pw_key = crypto::derive(password.as_bytes(), salt)?;\n',
     {'feature': [INBOX_T + 'a_wrong_password_and_a_wrong_key_fail_at_the_same_step']},
     ),
    ('the ks_id check of S', 4, 'feature', 'lib', INBOX,
     '    ok &= Choice::from(u8::from(ct_eq(&ks_id(&h.vault_id, &s), &h.ks_id)));',
     '',
     [INBOX_T + 'only_the_committed_nonzero_s_opens_the_body']),
    ('the writer checks a wrap\'s commitment first', 4, 'feature', 'lib', INBOX,
     '    if !ct_eq(&commit, &record[24..56]) {\n        return None;\n    }\n    aead(&kek, use_, ctx, record)',
     '    aead(&kek, use_, ctx, record)',
     [INBOX_T + 'a_wrong_base_fails_at_the_commitment']),
    ('uv equals the slot\'s UV bit, and uv in PIN mode', 4, 'feature', 'lib', INBOX,
     '    if touch.uv != (slot.flags & 1 != 0) || (h.pin() && !touch.uv) {',
     '    if false {',
     [INBOX_T + 'an_open_checks_the_touch_before_any_secret']),
    ('the transport of a v4+ assertion', 4, 'feature', 'lib', FIDO,
     '            Some(t @ (USB | NFC)) => Some(t),\n            _ => return Err(FidoError::Transport),\n',
     '            t => t,\n',
     [FIDO_T + 'assertions_are_checked_field_by_field']),
    ('the transport at a registration', 4, 'feature', 'lib', FIDO,
     '    if raw.version >= 3 && !matches!(raw.transport, Some(USB | NFC)) {',
     '    if false && raw.version >= 3 && !matches!(raw.transport, Some(USB | NFC)) {',
     [FIDO_T + 'credentials_are_checked_field_by_field']),
    ('UP and the rpIdHash of an assertion', 4, 'feature', 'lib', FIDO,
     '    if auth_data.len() < 37 || auth_data[..32] != rp_id_hash() || auth_data[32] & UP == 0 {',
     '    if auth_data.len() < 37 {',
     [FIDO_T + 'assertions_are_checked_field_by_field']),
    ('a registration\'s GA #2 equals GA #1', 4, 'feature', 'lib', FIDO,
     '        if !ct_eq(first.as_slice(), touch.first.as_slice()) || uv != touch.uv {',
     '        if uv != touch.uv {',
     [FAKE_T + 'credprotect_pin_and_flags_behave_as_ctap_and_windows']),
    # Stage 3's rules, caught here by a forger test of stage 4 and by a
    # test of the default build.
    ('E1: the same OTP flag', 3, 'both', 'lib', ADOPT,
     '        if other.vault_id() != Some(self.id) || other.uses_otp() != self.uses_otp() {',
     '        if other.vault_id() != Some(self.id) {',
     {'feature': [G1_TRIGGERS], 'default': [ADOPT_T + 'only_this_vaults_key_files_are_taken']}),
    ('P3 (b) against the anchor (S-ANCHOR-RELIST)', 3, 'both', 'lib', ANCHOR,
     '    if lacks && !had {\n        return Err(Refusal::Relist);',
     '    if false && lacks && !had {\n        return Err(Refusal::Relist);',
     {'feature': [OLD_REMOVAL],
      'default': [ANCHOR_T + 'key_files_compare_with_the_confirmed_line']}),
    # Stages 1-3's rules (S45-2 #18), in both builds.
    ('S-ANCHOR-DOWNGRADE', 3, 'both', 'lib', ANCHOR,
     '    if c.hardware() && !h.magic.hardware() {\n        return Err(Refusal::Downgrade);',
     '    if false && c.hardware() && !h.magic.hardware() {\n        return Err(Refusal::Downgrade);',
     [ANCHOR_T + 'key_files_compare_with_the_confirmed_line']),
    ('the anchor\'s epoch window (S-ANCHOR-EPOCH)', 3, 'both', 'lib', ANCHOR,
     '        if h.epoch - c.epoch > EPOCH_WINDOW {',
     '        if false && h.epoch - c.epoch > EPOCH_WINDOW {',
     [ANCHOR_T + 'key_files_compare_with_the_confirmed_line']),
    ('the anchor\'s fork refusal (S-ANCHOR-FORK)', 3, 'both', 'lib', ANCHOR,
     '        if !h.key_ids.contains(&c.keyid) {\n            return Err(Refusal::Fork);',
     '        if false && !h.key_ids.contains(&c.keyid) {\n            return Err(Refusal::Fork);',
     [ANCHOR_T + 'key_files_compare_with_the_confirmed_line']),
    ('a pending entry built on needs its current key', 3, 'both', 'lib', ANCHOR,
     '    if h.epoch <= s.epoch || !h.key_ids.contains(&s.keyid) {\n        return false;',
     '    if h.epoch <= s.epoch {\n        return false;',
     [ANCHOR_T + 'a_pending_write_is_recognized_when_it_landed_or_is_built_on']),
    ('the anchor lock', 3, 'both', 'lib', ANCHOR,
     '    let _lock = lock(dir, wait)?;\n    let main = dir.join(NAME);',
     '    let _lock = lock(dir, wait).ok();\n    let main = dir.join(NAME);',
     [ANCHOR_T + 'two_writers_lose_no_line']),
    ('a cut-off anchor write is taken back from its temp file', 3, 'both', 'lib', ANCHOR,
     '            Some((temp, doc)) => {\n                publish(&temp, &main, false).map_err(|_| Failure::Io)?;\n                flush(&main);\n                Parsed::Doc(doc)\n            }\n            None => Parsed::Doc(Anchor::default()),',
     '            Some(_) | None => Parsed::Doc(Anchor::default()),',
     [ANCHOR_T + 'a_write_cut_off_before_its_rename_is_taken_back']),
    ('the 0.8 state in `hist`', 3, 'both', 'lib', ANCHOR,
     '    if c.epoch == 0 || c.hist.iter().any(|h| h.kind == 0) {',
     '    if c.epoch == 0 {',
     [ROTATE_T + 'the_08_pair_from_before_the_first_change_is_a_rollback']),
    ('EPOCH_MAX in the parse', 2, 'both', 'lib', KEYFILE,
     '        (1..=EPOCH_MAX).contains(&epoch)\n            && flags & !3 == 0',
     '        (1..=u64::MAX).contains(&epoch)\n            && flags & !3 == 0',
     [KEYFILE_T + 'each_parse_rule_fails_on_its_own']),
    ('KS_ID_ZERO in the parse', 2, 'both', 'lib', KEYFILE,
     '                && ks_id != ks_id_zero(&vault_id),',
     '                && ks_id != [0xa5; 16],',
     [KEYFILE_T + 'each_parse_rule_fails_on_its_own']),
    ('the tombstone cap', 2, 'both', 'lib', KEYFILE,
     '            && count <= TOMB_MAX\n',
     '            && count <= 65_535\n',
     [KEYFILE_T + 'each_count_stops_at_its_limit']),
    ('the magic family decides first', 2, 'default', 'lib', KEYFILE,
     '    if magic.starts_with(b"GOYOKH") || magic.starts_with(b"GOYOKS") {\n        return Family::SecurityKey;',
     '    if false && magic.starts_with(b"GOYOKH") || magic.starts_with(b"GOYOKS") {\n        return Family::SecurityKey;',
     [KEYFILE_T + 'the_magic_family_decides_first']),
    ('the format overhead in the 8 MiB limit', 2, 'both', 'lib', VAULT,
     '    if size + header.overhead() > MAX_FILE {',
     '    if size > MAX_FILE {',
     [VAULT_T + 'the_8_mib_limit_takes_the_header_overhead']),
    ('a consumed resume digest completes nothing again', 3, 'both', 'lib', VAULT,
     '            if kf2.is_some_and(|h| h.resume == sha) && consumed != Some(sha) {',
     '            if kf2.is_some_and(|h| h.resume == sha) {',
     [ROTATE_T + 'a_completed_change_refuses_its_probe_at_once']),
    ('max_epoch: a vault header counts up to EPOCH_SILENT', 2, 'both', 'lib', VAULT,
     '                        .min(key_state.epoch.saturating_add(EPOCH_SILENT)),',
     '                        .min(u64::MAX),',
     [WORKFLOW_T + 'vault_header_epochs_and_the_resave_at_unlock']),
    ('OlderKey: pushed over above the copy it replaces', 3, 'both', 'lib', SYNC,
     '            Verdict::OlderKey(theirs, adds) => {\n                let generation = pushed_over(self.generation, theirs);',
     '            Verdict::OlderKey(theirs, adds) => {\n                let generation = self.generation.max(theirs);',
     [SYNC_T + 'a_push_over_counts_above_the_copy_it_replaces']),
    ('the head override takes only the version it showed', 3, 'both', 'lib', SYNC,
     '        if version != head.version || sha256(blob) != head.sha || halted != Some(head) {',
     '        if sha256(blob) != head.sha || halted != Some(head) {',
     [SYNC_T + 'the_pc_that_changed_the_keys_is_gone']),
    # Stage 3's review fixes (§2.18), in both builds.
    ('F6 OTP guard', 3, 'both', 'lib', ROTATE,
     '    pub fn confirm_key_file(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.created.elapsed() > REAUTH_MAX\n            || (self.uses_otp() && r.otp_step.is_none())\n        {',
     '    pub fn confirm_key_file(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.created.elapsed() > REAUTH_MAX\n        {',
     [ROTATE_T + 'the_hold_buttons_of_an_otp_vault_need_its_code']),
    ('F6 OTP guard (forget)', 3, 'both', 'lib', ROTATE,
     '    pub fn forget_pending(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.created.elapsed() > REAUTH_MAX\n            || (self.uses_otp() && r.otp_step.is_none())\n        {',
     '    pub fn forget_pending(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.created.elapsed() > REAUTH_MAX\n        {',
     [ROTATE_T + 'the_hold_buttons_of_an_otp_vault_need_its_code']),
    ('F15 hardware notice', 3, 'both', 'lib', SYNC,
     '            Self::UnknownKey { hardware: true, .. } => SyncNotice::KeyChanged { hardware: true },\n            Self::UnknownKey { newer: true, .. } => SyncNotice::KeyChanged { hardware: false },',
     '            Self::UnknownKey { newer: true, hardware } => SyncNotice::KeyChanged { hardware },',
     [SYNC_T + 'copies_are_judged_by_their_key_first']),
    ('F12 override by bytes', 3, 'both', 'lib', SYNC,
     '            Verdict::Halt(_, head) if link.override_head.as_ref() == Some(&head) => {',
     '            Verdict::Halt(_, head) if link.override_head.as_ref().map(|h| h.version) == Some(head.version) => {',
     [SYNC_T + 'the_pc_that_changed_the_keys_is_gone']),
    ('F13 damaged head keeps the halt', 3, 'both', 'lib', SYNC,
     '            Verdict::Damaged => {\n                (link.warned, link.verified) = (true, false);\n                link.lift();',
     '            Verdict::Damaged => {\n                (link.warned, link.verified) = (true, false);',
     [SYNC_T + 'a_halt_ends_with_its_head']),
    ('F13 reset keeps the halt', 3, 'both', 'lib', SYNC,
     '                (link.verified, link.outgoing_due) = (false, true);\n                // No copy is left to halt on.\n                link.lift();',
     '                (link.verified, link.outgoing_due) = (false, true);',
     [SYNC_T + 'a_halt_ends_with_its_head']),
    ('F10 told once per session', 3, 'both', 'lib', SYNC,
     '        if self.halt.take().is_some() {\n            self.key_changed_told = false;\n        }',
     '        self.halt = None;',
     [SYNC_T + 'a_second_key_change_is_told_again']),
    ('F9 notice by version', 3, 'both', 'lib', SYNC,
     '                if adds {\n                    offer(notice, SyncNotice::OldKeyReplaced);\n                }',
     '                let _ = adds;\n                if version != link.merged_version {\n                    offer(notice, SyncNotice::OldKeyReplaced);\n                }',
     [SYNC_T + 'this_pcs_own_older_key_copy_is_replaced_without_a_word']),
    ('F14 login offers at once', 3, 'both', 'lib', SYNC,
     '                Some(Fetched::Missing) => link.incoming_gone = true,',
     '                Some(Fetched::Missing) => link.outgoing_due = true,',
     [SYNC_T + 'an_unlock_without_incoming_waits_for_a_second_look']),
    ('F2 hint for a confirmed 0.8 state', 3, 'both', 'lib', VAULT,
     '                    || confirmed_08\n',
     '                    || (confirmed_08 && false)\n',
     [ROTATE_T + 'the_08_pair_from_before_the_first_change_is_a_rollback']),
    ('F3 S5 consumes the resume', 3, 'both', 'lib', ROTATE,
     '                promoted.state.consumed = Some(resume);',
     '                let _ = resume;',
     [ROTATE_T + 'a_completed_change_refuses_its_probe_at_once']),
    ('F4 S1.gapped point', 3, 'both', 'lib', ROTATE,
     '                    point("S1.gapped")?;',
     '',
     [ROTATE_T + 'every_crash_point_leaves_a_pair_that_opens']),
    ('F1 restored sessions hold', 3, 'both', 'lib', ROTATE,
     '        if self.restored {\n            return Err(RESTORE_KEYS);\n        }',
     '        let _ = RESTORE_KEYS;',
     [ROTATE_T + 'a_restored_vault_never_changes_the_shared_key_file']),
    ('F7 unlock trusts the locked read', 3, 'both', 'lib', VAULT,
     '        if differed {\n            return Err(ANCHOR_REREAD);\n        }',
     '        let _ = differed;',
     [ROTATE_T + 'an_anchor_unread_at_precheck_is_not_trusted']),
    ('F7 S0 floor at the same epoch', 3, 'both', 'lib', ROTATE,
     '                v.state.epoch > kh.epoch\n                    || (v.state.epoch == kh.epoch\n                        && v.state.key_state() != kh.state()\n                        && !kh.key_ids.contains(&v.state.keyid))',
     '                v.state.epoch > kh.epoch',
     [ROTATE_T + 'an_anchor_unread_at_precheck_is_not_trusted']),
    ('F7 S0 floor keeps a same-epoch successor', 3, 'both', 'lib', ROTATE,
     '                        && v.state.key_state() != kh.state()\n                        && !kh.key_ids.contains(&v.state.keyid))',
     '                        && v.state.key_state() != kh.state())',
     [ADOPT_T + 'a_sibling_at_the_same_epoch_that_holds_this_pcs_key_is_a_successor']),
    ('F7 S0 floor keeps an adopt of the confirmed state', 3, 'both', 'lib', ROTATE,
     '                v.state.epoch > kh.epoch\n                    || (v.state.epoch == kh.epoch\n                        && v.state.key_state() != kh.state()\n                        && !kh.key_ids.contains(&v.state.keyid))',
     '                v.state.epoch >= kh.epoch',
     [ADOPT_T + 'during_a_local_rollback_only_a_descendant_is_taken']),
    ('F5 bounded read', 3, 'both', 'lib', ROTATE,
     '    let mut bytes = Vec::new();\n    let read = fs::File::open(path)\n        .and_then(|f| f.take(KEY_FILE_LIMIT as u64 + 1).read_to_end(&mut bytes));\n    match read {\n        Ok(_) => Some(bytes == want),',
     '    match fs::read(path) {\n        Ok(bytes) => Some(bytes == want),',
     [ROTATE_T + 'a_key_file_far_over_the_limit_is_read_no_further']),
    ('F11 synced confirm wording', 3, 'both', 'bin', MAIN,
     '                let question = if s.badge().is_some() {\n                    vault::LOCAL_OK_CONFIRM_SYNCED\n                } else {\n                    vault::LOCAL_OK_CONFIRM\n                };',
     '                let question = vault::LOCAL_OK_CONFIRM;',
     [BIN_T + 'confirming_a_synced_put_back_key_file_says_what_follows']),
    ('F16 gate asked again', 3, 'both', 'bin', MAIN,
     '    fn gate_now(&mut self, flow: &Flow) -> crypto::Result<Option<vault::Gate>> {\n        if',
     '    fn gate_now(&mut self, flow: &Flow) -> crypto::Result<Option<vault::Gate>> {\n        #[allow(unreachable_code)]\n        return Ok(None);\n        if',
     [BIN_T + 'a_gate_that_comes_up_during_a_question_is_asked_first']),
]

FEATURE = ['--features', 'security-key']


def builds_of(row):
    return ['default', 'feature'] if row[2] == 'both' else [row[2]]


def tests_of(row, build):
    tests = row[7]
    return tests[build] if isinstance(tests, dict) else tests


def snippet_count(tree, row):
    return (tree / row[4]).read_text(encoding='utf-8').count(row[5])


def cargo(tree, build, target, names):
    args = ['cargo', 'test', '--locked', *(FEATURE if build == 'feature' else [])]
    args += ['--lib'] if target == 'lib' else ['--bin', 'goyo-vault']
    args += ['--', '--exact', *names]
    # The binary's tests drive windows on their thread: one at a time.
    if target == 'bin':
        args.append('--test-threads=1')
    env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target' / 'mutate'))
    try:
        p = subprocess.run(args, cwd=tree, env=env, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=TIMEOUT)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or '') if isinstance(e.stdout, str) else ''
        return True, len(names), True, out + f'\nTIMEOUT after {TIMEOUT} s'
    out = p.stdout + p.stderr
    ran = sum(int(n) for n in re.findall(r'running (\d+) tests?', out))
    built = 'could not compile' not in out and ran > 0
    # A test binary that ends without its summary (an abort in a window
    # procedure, say) failed as well: cargo says so.
    failed = 'test result: FAILED' in out or 'error: test failed' in out
    return built, ran, failed, out


def main():
    args = sys.argv[1:]
    if '--list' in args:
        for name, stage, build, target, path, *_ in ROWS:
            print(f'stage {stage}  {build:7}  {target}  {path}  {name}')
        return 0
    if shutil.which('python') is None:
        sys.exit('mutate.py needs python on the path (the server selftest runs through it).')
    only = [a for a in args if not a.startswith('--')]
    rows = [r for r in ROWS if not only or any(o in r[0] for o in only)]
    bad = [r[0] for r in rows if snippet_count(root, r) != 1]
    for name in bad:
        print(f'SNIPPET NOT FOUND EXACTLY ONCE: {name}', flush=True)
    if '--check' in args or bad:
        return 1 if bad else 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix='goyo-mutate-'))
    tree = tmp / 'tree'
    skip = shutil.ignore_patterns('target', '.git', 'dist', '__pycache__', '*.pyc')
    # Fresh times on every copied file: a build that target/mutate holds
    # from an earlier run's mutant must never count as up to date.
    shutil.copytree(root, tree, ignore=skip, copy_function=shutil.copy)
    failures = []
    runs = 0
    try:
        # The named tests pass unmutated, in each build and target.
        groups = {}
        for r in rows:
            for build in builds_of(r):
                groups.setdefault((build, r[3]), set()).update(tests_of(r, build))
        for (build, target), names in sorted(groups.items()):
            built, ran, failed, out = cargo(tree, build, target, sorted(names))
            ok = built and not failed and ran >= len(names)
            print(f'baseline {build} {target}: {"ok" if ok else "FAILED"} ({ran} tests)', flush=True)
            if not ok:
                failures.append(f'baseline {build} {target}')
                print(out[-3000:])
        for row in rows:
            name, stage, _, target, path, old, new, _ = row
            file = tree / path
            text = file.read_text(encoding='utf-8')
            file.write_text(text.replace(old, new), encoding='utf-8', newline='')
            try:
                for build in builds_of(row):
                    runs += 1
                    built, ran, failed, out = cargo(tree, build, target, tests_of(row, build))
                    if 'could not compile' in out:
                        verdict = 'DOES NOT BUILD'
                    elif ran == 0:
                        verdict = 'NO TEST RAN'
                    elif 'TIMEOUT after' in out:
                        verdict = 'caught (timeout)'
                    else:
                        verdict = 'caught' if failed else 'NOT CAUGHT'
                    print(f'stage {stage} {build:7} {verdict:16} {name}', flush=True)
                    if not verdict.startswith('caught'):
                        failures.append(f'{name} ({build})')
                        if not built:
                            print('\n'.join(l for l in out.splitlines() if l.startswith('error'))[:2000])
            finally:
                file.write_text(text, encoding='utf-8', newline='')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        print(f'FAILED: {len(failures)} of {runs} runs ({len(rows)} rows): {failures}')
        return 1
    print(f'PASS: {len(rows)} mutations caught in {runs} runs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
