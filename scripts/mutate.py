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
builds compile, so each build must catch it), the test target ('lib',
'bin': the goyo-vault binary, or 'sync': the goyo-sync binary, whose
server_selftest_passes runs the server script's selftest), the file, the
exact snippet and its replacement, and the full paths of the tests that
catch it (one list for every build, or one per build). Only those tests run, each by its exact
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
WEBAUTHN = 'src/webauthn.rs'
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
WEBAUTHN_T = 'webauthn::tests::'
MAKE_OPTIONS = WEBAUTHN_T + 'make_options_are_built_field_by_field'
ASSERT_OPTIONS = WEBAUTHN_T + 'assert_options_are_built_field_by_field'
CEREMONY_T = BIN_T + 'ceremonies::'
RUNS = CEREMONY_T + 'a_ceremony_runs_on_its_worker_while_the_app_stays_free'
LOCKED = CEREMONY_T + 'a_lock_before_the_call_is_cancelled_again_until_the_worker_ends'
BEFORE = CEREMONY_T + 'a_cancel_before_the_call_makes_none'
CAPPED = CEREMONY_T + 'the_cap_ends_a_ceremony_and_a_stuck_worker_is_left_after_10_s'
CLOSED = CEREMONY_T + 'a_close_or_quit_during_a_ceremony_waits_for_its_end'
LATE = CEREMONY_T + 'an_answer_after_a_lock_is_dropped'
TOUCH_LOGIN = CEREMONY_T + 'unlock_with_a_touch'
PICK_DIALOG = BIN_T + 'input_dialog_pick_and_code_ignore_other_programs'
CREATE_KEYS = CEREMONY_T + 'create_with_keys'
GATE_DIALOGS = CEREMONY_T + 'gate_dialogs_and_tofu'
KEYS_FLOWS = CEREMONY_T + 'keys_on_add_pair_reseed_and_off'
LOST_FLOWS = CEREMONY_T + 'lost_key_and_retire_flows'
SITES = CEREMONY_T + 'four_keys_two_sites_lost_key_walkthrough'
FORK_FLOW = CEREMONY_T + 'fork_options_come_first_and_join_both_removals'
FULL_QUIT = CEREMONY_T + 'a_failed_registration_names_a_full_store_and_a_quit_ends_it'
PASSWORD_SK = CEREMONY_T + 'a_password_change_with_keys_takes_a_touch'
EXTRA = CEREMONY_T + 'a_key_paired_with_one_key_is_kept_with_an_extra_touch'
HALTED = CEREMONY_T + 'a_halted_pc_can_still_remove_a_lost_key'
FORGET = CEREMONY_T + 'an_anchor_refusal_offers_the_per_vault_forget'
COLLIDE = CEREMONY_T + 'colliding_additions_renumber_and_name_new_keys'
TWOTOUCH = CEREMONY_T + 'an_adopt_touches_twice_when_windows_gives_one_output'
ROUTED = BIN_T + 'restore_and_otp_backup_submit_run_as_flows'
RESTORE_T = CEREMONY_T + 'restore_and_otp_backup_take_a_touch'
HOLD_T = CEREMONY_T + 'a_hold_button_takes_a_touch'
REAUTH_T = CEREMONY_T + 'a_reauth_too_old_is_taken_again_in_the_flow'
PLAN_UI = CEREMONY_T + 'the_plan_asks_for_more_touches_and_proposes_a_repair'
HINT_T = CEREMONY_T + 'the_fork_hint_shows_in_the_preview_and_back_returns_to_the_options'
FORGET_HELD = CEREMONY_T + 'the_forget_in_gate_pending_mode_starts_a_bootstrap'
REAUTH_AGE = ROTATE_T + 'a_password_change_is_refused_before_anything_is_written'
UI_SK_T = 'keys_ui::tests::'
PLAN_T = UI_SK_T + 'plan_names_only_paired_keys_and_who_may_touch'
DATE_T = UI_SK_T + 'a_loss_date_after_today_is_refused'
TEXTS_T = UI_SK_T + 'texts_follow_what_is_offered_and_counted'
MERGE_LOG = 'vault::review::tests::merges_are_logged_by_id_and_content'
LOG_CAP = 'vault::review::tests::the_log_is_capped_outside_the_window_first'
UI_SK = 'src/keys_ui.rs'
SYNC = 'src/vault/sync.rs'
WIN = 'src/win.rs'
SERVER = 'server/goyo-sync-server.py'
SELFTEST = BIN_T + 'server_selftest_passes'
# Stage 6, the helper's key steps and the wire (goyo-sync bin tests).
HELPER_KEYS = 'src/bin/goyo-sync/engine/keys.rs'
ENGINE = 'src/bin/goyo-sync/engine.rs'
SYNCFILE_KEYS = 'src/syncfile/keys.rs'
SYNCWIRE = 'src/syncwire.rs'
KEYSYNC = 'src/vault/keysync.rs'
KEYS_T = BIN_T + 'keys::'
GATE_2 = KEYS_T + 'gate_2_takes_only_this_vaults_key_requests'
KR_FIRST = KEYS_T + 'kr_and_kg_run_before_the_vault_steps'
KR_RETRY = KEYS_T + 'kr_retries_like_push'
KEY_DUE = KEYS_T + 'due_lists_the_key_files_and_opens_neither'
NO_KEY_BYTES = KEYS_T + 'no_key_record_comes_back_while_an_off_waits'
KEY_ANSWERS = KEYS_T + 'answers_and_planted_files'
BEHIND_VIEW = KEYS_T + 'key_behind_waits_for_the_key_view'
NOKEYS = KEYS_T + 'a_line_without_key_ops_shows_nokeys'
KG_CADENCE = KEYS_T + 'kg_runs_where_p5_runs_and_before_every_upload'
KP = KEYS_T + 'prune_requests_wait_for_the_head'
KEY_REPLIES = 'syncwire::tests::keys::key_replies_follow_the_answer_rules'
KEY_VIEWS = 'syncfile::keys::tests::key_views_are_strict'
KS_T = 'vault::rotate::hw::tests::gates::keysync::'
KS_ON_OFF = KS_T + 'key_file_sync_goes_on_and_off_between_two_pcs'
KS_TABLE = KS_T + 'the_request_table_writes_only_what_it_derives'
KS_PIN = KS_T + 'an_off_with_no_view_waits_for_its_pin'
KS_HEAL = KS_T + 'the_self_heal_ends_this_pcs_own_record'
KS_OFF_GATE = KS_T + 'an_off_from_gate_pending_clears_the_gate'
KS_REQ_DUE = KS_T + 'a_failed_kreq_write_is_retried_at_the_next_poll'
KS_LAGGING = KS_T + 'a_lagging_join_leaves_another_pcs_re_enable'
KS_MERGED = KS_T + 'a_join_that_clears_a_gate_names_its_candidate'
KS_UNLOCK_HOLD = KS_T + 'a_gated_candidate_holds_the_copy_from_the_unlock_on'
KS_NONE_LINE = KS_T + 'a_failed_pick_then_the_same_file_from_the_server_is_pending'
KS_JOIN = KS_T + 'two_ons_at_once_are_joined_and_ask_no_prune'
KS_STALE_GATE = KS_T + 'a_pending_gate_without_its_candidate_can_be_dropped'
CRASH_KEYS = HW + 'every_crash_point_of_a_change_with_keys_leaves_a_pair_that_opens'
KG_AFTER = KEYS_T + 'a_fetched_copy_waits_for_a_getkey_after_it'
REFUSAL_TOP = KEYS_T + 'a_refusal_over_no_view_is_written_with_the_top'
VIEW_STUCK = KEYS_T + 'an_unwritable_key_view_shows_and_does_not_stop_the_vault'
# Stage 6, end to end: the app, the helper and the real server script (the
# goyo-sync bin's e2e tests, security-key build).
E2E = 'e2e::keys::'
E2E_SITES = E2E + 'key_file_sync_between_two_sites'
E2E_THREE = E2E + 'three_pcs_change_keys_at_once'
E2E_HOSTILE = E2E + 'a_hostile_server_gets_nothing_taken_without_its_gate'
E2E_GATE = E2E + 'the_gate_over_the_server_channel'
E2E_CYCLES = E2E + 'off_and_on_cycles_with_the_real_server'

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
     '    pub fn confirm_key_file(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.age() > REAUTH_MAX\n            || (self.uses_otp() && r.otp_step.is_none())\n        {',
     '    pub fn confirm_key_file(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.age() > REAUTH_MAX\n        {',
     [ROTATE_T + 'the_hold_buttons_of_an_otp_vault_need_its_code']),
    ('F6 OTP guard (forget)', 3, 'both', 'lib', ROTATE,
     '    pub fn forget_pending(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.age() > REAUTH_MAX\n            || (self.uses_otp() && r.otp_step.is_none())\n        {',
     '    pub fn forget_pending(&mut self, r: Reauth) -> Result<()> {\n        if r.session != self.serial\n            || r.age() > REAUTH_MAX\n        {',
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
    # Stage 4's anchor grammar of S6R2 #13 (landed with stage 5a): `ks`
    # and `sup` carried to every line this PC writes.
    ('anchor ks kept by every write', 4, 'both', 'lib', ANCHOR,
     '            ks: old.map_or(Ks::None, |o| o.state.ks),\n            keyid: h.current_key_id(),',
     '            ks: Ks::None,\n            keyid: h.current_key_id(),',
     [ANCHOR_T + 'sup_and_ks_round_trip_and_are_kept']),
    # Stage 5 (§14.11, S45-3 #11, #13, #17): the request builders of
    # webauthn.rs, field by field, and the ceremony runner's rules.
    ('S5 options versions per API', 5, 'feature', 'bin', WEBAUTHN,
     '        6..=8 => (api, api),',
     '        6..=8 => (6, 6),',
     [WEBAUTHN_T + 'the_layout_is_the_recorded_table', MAKE_OPTIONS, ASSERT_OPTIONS]),
    ('S5 GetAssertion options version at API 4-5', 5, 'feature', 'bin', WEBAUTHN,
     '    let version = versions(api).1;',
     '    let version = versions(api).0;',
     [ASSERT_OPTIONS]),
    ('S5 HMAC_SECRET_VALUES_FLAG on every assertion', 5, 'feature', 'bin', WEBAUTHN,
     '        dwFlags: fido::HMAC_SECRET_VALUES_FLAG,',
     '        dwFlags: 0,',
     [ASSERT_OPTIONS]),
    ('S5 one salt entry per allowed credential', 5, 'feature', 'bin', WEBAUTHN,
     '        cCredWithHmacSecretSaltList: n,',
     '        cCredWithHmacSecretSaltList: n - 1,',
     [ASSERT_OPTIONS]),
    ('S5 the allow list in pAllowCredentialList', 5, 'feature', 'bin', WEBAUTHN,
     '        pAllowCredentialList: allow,',
     '        pAllowCredentialList: null(),',
     [ASSERT_OPTIONS]),
    ('S5 credProtect required in PIN mode', 5, 'feature', 'bin', WEBAUTHN,
     '        bRequireCredProtect: Bool::from(required),',
     '        bRequireCredProtect: 0,',
     [MAKE_OPTIONS]),
    ('S5 hmac-secret on at a registration', 5, 'feature', 'bin', WEBAUTHN,
     'keep.hmac_secret.insert(Box::new(1))',
     'keep.hmac_secret.insert(Box::new(0))',
     [MAKE_OPTIONS]),
    ('S5 a resident credential', 5, 'feature', 'bin', WEBAUTHN,
     '        bRequireResidentKey: 1,',
     '        bRequireResidentKey: 0,',
     [MAKE_OPTIONS]),
    ('S5 pCancellationId', 5, 'feature', 'bin', WEBAUTHN,
     '        &**self.cancel.insert(Box::new(*cancel))',
     '        let _ = self.cancel.insert(Box::new(*cancel));\n        null()',
     [MAKE_OPTIONS, ASSERT_OPTIONS]),
    ('S5 hints only from version 8', 5, 'feature', 'bin', WEBAUTHN,
     '        if version < 8 {',
     '        if version < 5 {',
     [MAKE_OPTIONS, ASSERT_OPTIONS]),
    ('S5 USB and NFC on every listed credential', 5, 'feature', 'bin', WEBAUTHN,
     '                dwTransports: TRANSPORTS,',
     '                dwTransports: fido::USB,',
     [MAKE_OPTIONS, ASSERT_OPTIONS]),
    ('S5 the owner window in the options', 5, 'feature', 'bin', WEBAUTHN,
     '    MakeOptions {\n        owner: r.owner,',
     '    MakeOptions {\n        owner: 0,',
     [MAKE_OPTIONS]),
    ('S5 the main window owns the unlock\'s dialog', 5, 'feature', 'bin', MAIN,
     '.and_then(|p| p.unlock_request(h))',
     '.and_then(|p| p.unlock_request(0))',
     [TOUCH_LOGIN]),
    ('S5 the worker\'s pre-call check', 5, 'feature', 'bin', FIDO,
     '        if self.is_cancelled() {\n            return Err(FidoError::Cancelled);\n        }\n        Ok(())',
     '        Ok(())',
     [BEFORE]),
    ('S5 the pump cancels again at every round', 5, 'feature', 'bin', MAIN,
     '        if requested || now.saturating_sub(started) > CEREMONY_CAP {\n            cancelled_at.get_or_insert(now);',
     '        if (requested || now.saturating_sub(started) > CEREMONY_CAP) && cancelled_at.is_none() {\n            cancelled_at.get_or_insert(now);',
     [LOCKED]),
    ('S5 a lock or scrub cancels the ceremony', 5, 'feature', 'bin', MAIN,
     '            active.cancel_requested = true;\n            active.token.cancel();',
     '',
     [LOCKED]),
    ('S5 in_modal() during the pump', 5, 'feature', 'bin', MAIN,
     'modal(|| pump(h, &worker, &*auth, &token, started))',
     'pump(h, &worker, &*auth, &token, started)',
     [RUNS]),
    ('S5 the timer returns early during a ceremony', 5, 'feature', 'bin', MAIN,
     '            ceremony_overdue();\n            return;\n        }',
     '            ceremony_overdue();\n        }',
     [CAPPED]),
    ('S5 the idle time starts again after an answered ceremony', 5, 'feature', 'bin', MAIN,
     '            if !unattended {\n                a.activity = now;\n            }',
     '            let _ = unattended;',
     [RUNS]),
    ('S5 a ceremony the cap ended keeps the idle time', 5, 'feature', 'bin', MAIN,
     '    let unattended = spent > CEREMONY_CAP\n        || (matches!(result, Err(FidoError::Cancelled))\n            && spent >= u64::from(goyo_vault::fido::TIMEOUT_MS));',
     '    let unattended = false;\n    let _ = spent;',
     [CAPPED]),
    ('S5 DestroyWindow deferred: WM_CLOSE', 5, 'feature', 'bin', MAIN,
     '                if app.clipboard.is_none() && !in_ceremony() {',
     '                if app.clipboard.is_none() {',
     [CLOSED]),
    ('S5 DestroyWindow deferred: drain_pending', 5, 'feature', 'bin', MAIN,
     '            if a.closing && a.clipboard.is_none() && !in_ceremony() {',
     '            if a.closing && a.clipboard.is_none() {',
     [CLOSED]),
    ('S5 DestroyWindow deferred: the timer', 5, 'feature', 'bin', MAIN,
     '        if self.closing && self.clipboard.is_none() && !in_ceremony() {',
     '        if self.closing && self.clipboard.is_none() {',
     [CLOSED]),
    ('S5 an answer after the app\'s cancel is dropped', 5, 'feature', 'bin', MAIN,
     '    if by_app || token.is_cancelled() {',
     '    if false {',
     [LATE]),
    # Stage 5, step 5b: the guarded pick, the gate dialogs, Create and the
    # Keys flows.
    ('S5 a pick item takes input only from this thread', 5, 'both', 'bin', WIN,
     '                ok &= guard(item);',
     '                ok &= item != 0;',
     [PICK_DIALOG]),
    ('S5 the login asks a changed key file\'s gate first', 5, 'feature', 'bin', MAIN,
     '            keys_ui::ask_gate(h, kind, &choices, None, epoch, None).map(|answer| (answer, epoch))',
     '            { let _ = (kind, choices, epoch); None }',
     [GATE_DIALOGS]),
    ('S5 the login gate is judged after the unlock', 5, 'feature', 'bin', MAIN,
     '        Some((answer, epoch)) if opened_session() => keys_ui::judge_login_gate(h, answer, epoch),',
     '        Some(_) if opened_session() => {}',
     [GATE_DIALOGS]),
    ('S5 a later key\'s failure keeps the keys so far', 5, 'feature', 'bin', UI_SK,
     '            Err(Some(_)) if !keys.is_empty() => {}',
     '            Err(Some(_)) if !keys.is_empty() => return None,',
     [CREATE_KEYS]),
    ('S5 S-ONEKEY in red after Create', 5, 'feature', 'bin', UI_SK,
     '            lines.push(ONEKEY);\n            a.status_tone = TONE_DANGER;',
     '            lines.push(ONEKEY);',
     [CREATE_KEYS]),
    ('S5 a write that removes nothing reaches every key not suspended', 5, 'feature', 'bin', UI_SK,
     '            .filter(|r| r.suspended)\n            .map(|r| r.number)\n            .collect()\n    };\n    let (mut consent, mut planned) = (kept.clone(), Vec::new());',
     '            .filter(|_| true)\n            .map(|r| r.number)\n            .collect()\n    };\n    let (mut consent, mut planned) = (kept.clone(), Vec::new());',
     [PLAN_UI]),
    # Stage 5, step 5c: the removals, the review and the adopt with keys.
    ('S5 a removal\'s allow list holds only staying keys', 5, 'feature', 'bin', UI_SK,
     '        .filter(|n| !remove.contains(n))\n        .collect();',
     '        .collect();',
     [LOST_FLOWS, SITES]),
    ('S5 the lost-key flow asks the exposure first', 5, 'feature', 'bin', UI_SK,
     '            let exposure = a.toggles.exposure.ok_or(EXPOSE_NEEDED)?;',
     '            let exposure = a.toggles.exposure.unwrap_or(Exposure::No);',
     [LOST_FLOWS]),
    ('S5 예 and 모름 tick the password change', 5, 'feature', 'bin', UI_SK,
     '                    self.toggles.pwchange = true;',
     '                    self.toggles.pwchange = false;',
     [LOST_FLOWS]),
    ('S5 unticking the password change asks S-LOST-PWUNTICK', 5, 'feature', 'bin', UI_SK,
     '                || (id == LOSS_PWCHANGE && a.screen == Screen::LostKey && a.toggles.pwchange)',
     '                || false',
     [LOST_FLOWS]),
    ('S5 a removal for a loss carries its report', 5, 'feature', 'bin', UI_SK,
     '        loss: loss.clone(),\n        over: None,',
     '        loss: None,\n        over: None,',
     [LOST_FLOWS, SITES]),
    ('S5 the review screen follows a removal for a loss', 5, 'feature', 'bin', UI_SK,
     '        if s.review_list(day).rows.is_empty() {',
     '        if true {',
     [SITES]),
    ('S5 [확인함] marks the review done', 5, 'feature', 'bin', UI_SK,
     '        s.review_done()?;',
     '        let _ = &s;',
     [SITES]),
    ('S5 the adopt asks the gate before the touch', 5, 'feature', 'bin', UI_SK,
     '        pass = match ask_gate(h, kind, &choices, opened_with, epoch, None) {\n            Some(GateAnswer::Pick(pick)) => GatePass::G2Passed { pick, epoch, tag },',
     '        pass = match ask_gate(h, kind, &choices, opened_with, epoch, None) {\n            Some(GateAnswer::Pick(_)) => GatePass::none(&check),',
     [SITES]),
    ('S5 the fork option is asked before anything else', 5, 'feature', 'bin', UI_SK,
     '    let fork_options = check.fork && hardware;',
     '    let fork_options = false && hardware;',
     [FORK_FLOW]),
    ('S5 a merge is logged before it is saved', 5, 'feature', 'bin', SYNC,
     '                    self.log_merge(version, &brought)?;',
     '                    let _ = (version, &brought);',
     [SITES]),
    ('S5 a merge logs other text under a local ID', 5, 'feature', 'lib', REVIEW,
     '            out.push(Brought::Replaced(e.id, moved));',
     '            let _ = moved;',
     [MERGE_LOG]),
    ('S5 the cap drops lines outside the window first', 5, 'feature', 'lib', REVIEW,
     '                .filter(|(t, _)| inside || *t < start)',
     '                .filter(|_| true)',
     [LOG_CAP]),
    ('S5 the cap says when lines inside the window went', 5, 'feature', 'lib', REVIEW,
     '        all.push(format!("{now} ! {before}").into_bytes());',
     '        let _ = (now, before);',
     [LOG_CAP]),
    # Stage 5, the review of 5a-5c (spec §2.26 rows 48-).
    ('S5 no ceremony after a lock between steps', 5, 'feature', 'bin', MAIN,
     '    standing?;',
     '    let _ = standing;',
     [GATE_DIALOGS]),
    ('S5 a quit seen by the pump voids the flow', 5, 'feature', 'bin', MAIN,
     '        QUIT_SEEN.with(|q| q.set(true));',
     '',
     [FULL_QUIT]),
    ('S5 an unknown MakeCredential code adds S-KEYSTORE-FULL', 5, 'feature', 'bin', UI_SK,
     '        FidoError::Other(_) => format!("{}\\r\\n{}", failure(e, false, false), fido::KEYSTORE_FULL),',
     '        FidoError::Other(_) => failure(e, false, false),',
     [FULL_QUIT, TEXTS_T]),
    ('S5 a halt keeps the security-key section', 5, 'feature', 'bin', MAIN,
     '        let hardware = matches!(view.hold, Hold::None) || halted_keys;',
     '        let hardware = matches!(view.hold, Hold::None);',
     [HALTED]),
    ('S5 a password change of a key file with keys takes a touch', 5, 'feature', 'bin', UI_SK,
     '        Screen::Password => {\n            matches!(id, 1 | SUBMIT)',
     '        Screen::Password => {\n            false && matches!(id, 1 | SUBMIT)',
     [PASSWORD_SK]),
    ('S5 gate-pending mode shows no line of the changed key file', 5, 'feature', 'bin', UI_SK,
     '    if s.gate_pending() {\n        return;\n    }',
     '',
     [GATE_DIALOGS]),
    ('S5 Enter in the TOFU banner confirms', 5, 'feature', 'bin', UI_SK,
     '        (Some(Screen::Vault), 1 | SUBMIT) => tofu_flow(h, TOFU_OK),\n',
     '',
     [GATE_DIALOGS]),
    ('S5 a cancelled optional pairing keeps the new key', 5, 'feature', 'bin', UI_SK,
     '            if !standing(t.screen, t.serial) {\n                return Ok(());\n            }\n            continue;',
     '            return Ok(());',
     [EXTRA]),
    ('S5 the plan\'s keys paired only with the removed ones', 5, 'feature', 'bin', UI_SK,
     'others.iter().all(|a| !reaches(*a, *k))',
     'others.iter().any(|a| !reaches(*a, *k))',
     [PLAN_T, EXTRA]),
    ('S5 the plan\'s touch needs consent for its cut', 5, 'feature', 'bin', UI_SK,
     '        .filter(|(u, _)| u.iter().all(|k| consent.contains(k)))',
     '        .filter(|_| true)',
     [PLAN_T, EXTRA]),
    ('S5 a loss date after today is refused', 5, 'feature', 'bin', UI_SK,
     '    if day > now + 14 * 3600 {',
     '    if false {',
     [DATE_T]),
    ('S5 an adopt names a key new to this PC', 5, 'feature', 'bin', UI_SK,
     '            .map(|(c, n)| s.named(&other, c).unwrap_or((*n, true)))',
     '            .map(|(c, n)| (*n, c.is_empty()))',
     [COLLIDE]),
    ('S5 S-ADOPT-RENUMBER after a union', 5, 'feature', 'bin', UI_SK,
     '        let mut changed = adopted_lines(&adopted.renumbered, &adopted.dropped_uv);',
     '        let mut changed: Vec<String> = Vec::new();',
     [COLLIDE]),
    ('S5 an adopt touches again for a missing second output', 5, 'feature', 'bin', UI_SK,
     '            (Some(true), Some(touch)) if touch.second_missing() => {',
     '            (Some(true), Some(touch)) if false && touch.second_missing() => {',
     [TWOTOUCH]),
    ('S5 an anchor refusal offers the per-vault forget', 5, 'feature', 'bin', MAIN,
     '        keys_ui::offer_forget(e);',
     '        let _ = e;',
     [FORGET]),
    ('S5 the login note counts the confirmed keys', 5, 'feature', 'bin', VAULT,
     '        (Some(c), Some((state, n, pin))) if c.state.key_state() == state => keys(n, pin),',
     '        (Some(_), Some((_, n, pin))) => keys(n, pin),',
     [FORGET]),
    # Stage 5, what §15 row 5 still asked of it (spec §2.26 rows 83-).
    ('S5 Restore SUBMIT runs as a flow', 5, 'both', 'bin', MAIN,
     '                | Screen::Create\n                | Screen::Restore => matches!(id, 1 | SUBMIT),',
     '                | Screen::Create => matches!(id, 1 | SUBMIT),',
     [ROUTED]),
    ('S5 OtpBackup SUBMIT runs as a flow', 5, 'both', 'bin', MAIN,
     '                Screen::OtpBackup => matches!(id, 1 | SUBMIT) && a.otp_setup.is_none(),',
     '                Screen::OtpBackup => false,',
     [ROUTED]),
    ('S5 a Restore of a key file with keys takes the unlock touch', 5, 'feature', 'bin', UI_SK,
     '        let request = prepared.unlock_request(h);',
     '        let request = prepared.unlock_request(h).filter(|_| false);',
     [RESTORE_T]),
    ('S5 an OTP backup of a key file with keys takes a touch', 5, 'feature', 'bin', UI_SK,
     '        let Some(keys) = keys.filter(|_| a.otp_setup.is_none()) else {',
     '        let Some(keys) = keys.filter(|_| false) else {',
     [RESTORE_T]),
    ('S5 a hold button of a key file with keys takes a touch', 5, 'feature', 'bin', MAIN,
     '                Some(s.key_request(&keys.active(), h)?)',
     '                { let _ = (&keys, h); None }',
     [HOLD_T]),
    ('S5 a Reauth too old for the next step is taken again', 5, 'feature', 'bin', UI_SK,
     '    if r.remaining() >= need {',
     '    if true {',
     [REAUTH_T]),
    ('S5 the Reauth ages on the clock a test moves', 5, 'both', 'lib', ROTATE,
     '        Duration::from_millis(crate::crypto::now_ms().saturating_sub(self.created))',
     '        Duration::ZERO',
     [REAUTH_AGE]),
    ('S5 a broken record between two staying keys is proposed for repair', 5, 'feature', 'bin', UI_SK,
     '    if let Some((x, y)) = broken_between(keys, &p.stay) {',
     '    if let Some((x, y)) = None::<(u8, u8)> {',
     [PLAN_UI]),
    ('S5 an accepted repair touches the key that reaches the others', 5, 'feature', 'bin', UI_SK,
     '                        p.touch.retain(|k| *k == a);',
     '',
     [PLAN_UI]),
    ('S5 a declined repair is named after the write', 5, 'feature', 'bin', UI_SK,
     '        let mut done = Done::of(vec![tr(PASSWORD_CHANGED).to_owned()]);\n        done.more.extend(unrepaired_line(unrepaired));',
     '        let done = Done::of(vec![tr(PASSWORD_CHANGED).to_owned()]);\n        let _ = unrepaired;',
     [PLAN_UI]),
    ('S5 S-MUSTTOUCH for a write that removes nothing', 5, 'feature', 'bin', UI_SK,
     '            ask_touch_too(h, &named)',
     '            ask_suspend(h, keys, &named, &full, false)',
     [PLAN_UI]),
    ('S5 S-FORK-HINT in the preview', 5, 'feature', 'bin', UI_SK,
     '                .then(|| s.fork_hint(&other))',
     '                .then(|| None::<u8>)',
     [HINT_T]),
    ('S5 the hint names a writer the other file removed', 5, 'feature', 'bin', HWRS,
     '            .filter(|e| e.auth != [0; 4] && removed.contains(&e.auth))',
     '            .filter(|_| false)',
     [HINT_T]),
    ('S5 [뒤로] returns to the fork options', 5, 'feature', 'bin', UI_SK,
     '            InputAnswer::Switch(PREVIEW_BACK) => {}',
     '            InputAnswer::Switch(PREVIEW_BACK) => return Ok(()),',
     [HINT_T]),
    ('S5 a passed G1 covers the other fork option', 5, 'feature', 'bin', UI_SK,
     '            (Some(_), passed @ GatePass::G1Passed { .. }) if option != chosen => passed,\n',
     '',
     [HINT_T]),
    ('S5 the forget in gate-pending mode makes a bootstrap', 5, 'feature', 'bin', UI_SK,
     '        s.forget_record(r)?;',
     '        let _ = r;',
     [FORGET_HELD]),
    # Stage 6: the server's key namespace (spec v3 §7.13, §2.23-§2.25).
    # The script is the same in both builds; its selftest catches each row
    # through the goyo-sync bin test server_selftest_passes.
    ('S6 server: key ops only for a vault --key-sync names', 6, 'default', 'sync', SERVER,
     '    if op in KEY_OPS and vid not in store.key_sync:\n',
     '    if False and op in KEY_OPS and vid not in store.key_sync:\n',
     [SELFTEST]),
    ('S6 server: the vault lock is exclusive', 6, 'default', 'sync', SERVER,
     '            while not try_lock(fd):\n',
     '            while False and not try_lock(fd):\n',
     [SELFTEST]),
    ('S6 server: PUTKEY runs under the vault lock', 6, 'default', 'sync', SERVER,
     "        self.step('locking')\n        with self.vault_lock(vid):\n"
     '            vault, keys, exists = self.key_folder(vid)\n            state = self.read_state(vid, keys, exists)\n',
     "        self.step('locking')\n        with contextlib.nullcontext():\n"
     '            vault, keys, exists = self.key_folder(vid)\n            state = self.read_state(vid, keys, exists)\n',
     [SELFTEST]),
    ('S6 server: GETKEY runs under the vault lock', 6, 'default', 'sync', SERVER,
     "            return EMPTY, 0, b''  # no lock\n        with self.vault_lock(vid):\n",
     "            return EMPTY, 0, b''  # no lock\n        with contextlib.nullcontext():\n",
     [SELFTEST]),
    ('S6 server: CUTKEY runs under the vault lock', 6, 'default', 'sync', SERVER,
     "        self.step('locking')\n        with self.vault_lock(vid):\n"
     '            vault, keys, exists = self.key_folder(vid)\n            if not exists:\n',
     "        self.step('locking')\n        with contextlib.nullcontext():\n"
     '            vault, keys, exists = self.key_folder(vid)\n            if not exists:\n',
     [SELFTEST]),
    ('S6 server: the floor is checked under the vault lock', 6, 'default', 'sync', SERVER,
     '            with self.vault_lock(vid) if keyed else contextlib.nullcontext():\n',
     '            with contextlib.nullcontext():\n',
     [SELFTEST]),
    ('S6 server: the floor binds every connection once k/ exists', 6, 'default', 'sync', SERVER,
     "        keyed = os.path.lexists(os.path.join(vault, 'k'))\n",
     '        keyed = False\n',
     [SELFTEST]),
    ('S6 server: the floor checks the epoch', 6, 'default', 'sync', SERVER,
     "blob[40:48] == struct.pack('<Q', top.floor)",
     'True',
     [SELFTEST]),
    ('S6 server: the floor checks the key ID', 6, 'default', 'sync', SERVER,
     'blob[24:40] == top.syntax.key_id',
     'True',
     [SELFTEST]),
    ('S6 server: the floor checks the state tag', 6, 'default', 'sync', SERVER,
     'blob[48:64] == state_tag(payload[:top.syntax.w])',
     'True',
     [SELFTEST]),
    ('S6 server: no GOYOVA02 below a cut', 6, 'default', 'sync', SERVER,
     "            ok = blob[:8] == b'GOYOVA04'\n",
     '            ok = True\n',
     [SELFTEST]),
    ('S6 server: no floor after a cut', 6, 'default', 'sync', SERVER,
     "            ok = blob[:8] == b'GOYOVA04'\n",
     "            ok = blob[:8] == b'GOYOVA04' and top.damaged\n",
     [SELFTEST]),
    ('S6 server: the record CAS', 6, 'default', 'sync', SERVER,
     '            if number != base:\n                return CONFLICT, number, top.served\n',
     '            if False:\n                return CONFLICT, number, top.served\n',
     [SELFTEST]),
    ('S6 server: EMPTY without k/ creates nothing', 6, 'default', 'sync', SERVER,
     "        if not exists and base != 0:\n            return EMPTY, 0, b''  # nothing created, no lock\n",
     "        if False:\n            return EMPTY, 0, b''  # nothing created, no lock\n",
     [SELFTEST]),
    ('S6 server: EMPTY on an empty k/, no reseed', 6, 'default', 'sync', SERVER,
     "            if number == 0 and base != 0:\n                return EMPTY, 0, b''\n",
     "            if False:\n                return EMPTY, 0, b''\n",
     [SELFTEST]),
    ('S6 server: the PUTKEY window above the floor', 6, 'default', 'sync', SERVER,
     '            if not floor < new.epoch <= floor + EPOCH_WINDOW:\n',
     '            if not new.epoch <= floor + EPOCH_WINDOW:\n',
     [SELFTEST]),
    ('S6 server: the PUTKEY window bound', 6, 'default', 'sync', SERVER,
     '            if not floor < new.epoch <= floor + EPOCH_WINDOW:\n',
     '            if not floor < new.epoch:\n',
     [SELFTEST]),
    ('S6 server: the honest-server tombstone check', 6, 'default', 'sync', SERVER,
     '    return tombs <= new.tombs and not tombs & set(new.live)',
     '    return not tombs & set(new.live)',
     [SELFTEST]),
    ('S6 server: above a cut the honest checks use k/tombs', 6, 'default', 'sync', SERVER,
     '            if top and not honest(new, top.syntax.tombs if top.kind == KEY_RECORD else self.read_tombs(keys)):',
     '            if top and top.kind == KEY_RECORD and not honest(new, top.syntax.tombs):',
     [SELFTEST]),
    ("S6 server: CUTKEY keeps the ended file's tombstones", 6, 'default', 'sync', SERVER,
     '                self.write_tombs(keys, top.syntax.tombs)',
     '                pass',
     [SELFTEST]),
    ("S6 server: a CUT leaves a later generation", 6, 'default', 'sync', SERVER,
     '(top.number > base if top.kind == CUT else top.gen > base)',
     '(top.number > base if top.kind == CUT else False)',
     [SELFTEST]),
    ('S6 server: a CUT below a cut changes nothing', 6, 'default', 'sync', SERVER,
     '(top.number > base if top.kind == CUT else top.gen > base)',
     '(False if top.kind == CUT else top.gen > base)',
     [SELFTEST]),
    ('S6 server: the fence on the cut numbered base', 6, 'default', 'sync', SERVER,
     '(top.number > base if top.kind == CUT else top.gen > base)',
     '(top.number >= base if top.kind == CUT else top.gen > base)',
     [SELFTEST]),
    ('S6 server: a CUT on a damaged top appends a real cut', 6, 'default', 'sync', SERVER,
     '            if top and not top.damaged and (',
     '            if top and (',
     [SELFTEST]),
    ('S6 server: CUTKEY makes a missing vault folder', 6, 'default', 'sync', SERVER,
     '        vault = self.key_folder(vid)[0]\n        self.make_vault(vault)\n',
     '        vault = self.key_folder(vid)[0]\n',
     [SELFTEST]),
    ("S6 server: a damaged top keeps the floor in its name", 6, 'default', 'sync', SERVER,
     '            record = Record(number, CUT, number, floor, record_header(CUT, number, floor, True), damaged=True)',
     '            record = Record(number, CUT, number, 0, record_header(CUT, number, 0, True), damaged=True)',
     [SELFTEST]),
    ('S6 server: a damaged top is noted once per op', 6, 'default', 'sync', SERVER,
     "            self.note = 'damaged key record read as a cut'\n",
     '            pass\n',
     [SELFTEST]),
    ('S6 server: SERVER_ERROR on a read error that is not damage', 6, 'default', 'sync', SERVER,
     "            raise Refused(SERVER_ERROR, 'cannot read the top key record (%s)' % type(e).__name__)\n",
     '            top = Record(records[-1][0], CUT, records[-1][0], records[-1][1],\n'
     '                         record_header(CUT, records[-1][0], records[-1][1], True), damaged=True)\n',
     [SELFTEST]),
    ('S6 server: tidy() never removes the top', 6, 'default', 'sync', SERVER,
     '        kept = {state.records[-1][2]} if state.records else set()\n',
     '        kept = set()\n',
     [SELFTEST]),
    ('S6 server: tidy() keeps the previous key file of one generation only', 6, 'default', 'sync', SERVER,
     '            keep = below is not None and below.kind == KEY_RECORD and below.gen == top.gen\n',
     '            keep = below is not None\n',
     [SELFTEST]),
    ('S6 server: a record with a second name is refused', 6, 'default', 'sync', SERVER,
     '                    or regular and info.st_nlink - 1 != inodes.get((info.st_dev, info.st_ino), 0)):',
     '                    or False):',
     [SELFTEST]),
    ('S6 server: a lock file with a second name is refused', 6, 'default', 'sync', SERVER,
     'stat.S_ISREG(named.st_mode) and info.st_nlink == 1\n',
     'stat.S_ISREG(named.st_mode)\n',
     [SELFTEST]),
    ('S6 server: gate 3 takes GOYOKS01 only', 6, 'default', 'sync', SERVER,
     '    if blob[:8] != KEY_MAGIC or not MIN_KEY_FILE',
     '    if not MIN_KEY_FILE',
     [SELFTEST]),
    ("S6 server: gate 3 takes this vault's files only", 6, 'default', 'sync', SERVER,
     'len(blob) <= MAX_KEY_FILE or blob[8:24] != vid:',
     'len(blob) <= MAX_KEY_FILE:',
     [SELFTEST]),
    ('S6 server: gate 3 EPOCH_MAX', 6, 'default', 'sync', SERVER,
     '    if not (1 <= epoch <= EPOCH_MAX and flags in (2, 3)',
     '    if not (1 <= epoch and flags in (2, 3)',
     [SELFTEST]),
    ('S6 server: gate 3 PIN mode', 6, 'default', 'sync', SERVER,
     'flags in (2, 3) and 1 <= k',
     'flags in (0, 1, 2, 3) and 1 <= k',
     [SELFTEST]),
    ('S6 server: gate 3 tombstone cap', 6, 'default', 'sync', SERVER,
     '            and count <= TOMB_MAX and kind in KEY_KINDS',
     '            and kind in KEY_KINDS',
     [SELFTEST]),
    ('S6 server: gate 3 kinds', 6, 'default', 'sync', SERVER,
     'and kind in KEY_KINDS and',
     'and 1 <= kind <= 10 and',
     [SELFTEST]),
    ('S6 server: gate 3 reserved bytes', 6, 'default', 'sync', SERVER,
     'and reserved == bytes(5) and pw_id != bytes(16)',
     'and pw_id != bytes(16)',
     [SELFTEST]),
    ('S6 server: gate 3 KS_ID_ZERO', 6, 'default', 'sync', SERVER,
     '            and ks_id != bytes(16) and ks_id != ks_id_zero(vid)):',
     '            and ks_id != bytes(16)):',
     [SELFTEST]),
    ('S6 server: gate 3 the authorizer is present', 6, 'default', 'sync', SERVER,
     'and authorizer < n and present >> authorizer & 1',
     'and authorizer < n',
     [SELFTEST]),
    ('S6 server: gate 3 tombstone order', 6, 'default', 'sync', SERVER,
     'any(a >= b for a, b in zip(order, order[1:]))',
     'False',
     [SELFTEST]),
    ('S6 server: gate 3 no tombstoned key live', 6, 'default', 'sync', SERVER,
     'len(hashes) != n or hashes & dead:',
     'len(hashes) != n:',
     [SELFTEST]),
    ('S6 server: gate 3 kind 3 added by its authorizer', 6, 'default', 'sync', SERVER,
     'slots[authorizer][4] == slots[new[0]][2]',
     'True',
     [SELFTEST]),
    ('S6 server: gate 3 the via rule', 6, 'default', 'sync', SERVER,
     'via == authorizer and (authorizer, j) in pairs',
     'via == authorizer',
     [SELFTEST]),
    ('S6 server: gate 3 the exact length', 6, 'default', 'sync', SERVER,
     '    if r.at != len(blob):\n        return None\n',
     '    if False:\n        return None\n',
     [SELFTEST]),
    # Stage 6, the helper (spec v3 §7.12) and the wire's answer rules of
    # ops 6-9 (§7.13): the security-key build only.
    ("S6 helper: gate 2's magic", 6, 'feature', 'sync', SYNCFILE_KEYS,
     '        || &bytes[..8] != KEY_REQUEST_MAGIC\n',
     '        || bytes[..8].is_empty()\n',
     [GATE_2]),
    ("S6 helper: gate 2's epoch above floor", 6, 'feature', 'sync', SYNCFILE_KEYS,
     'Some(syntax) if syntax.epoch > floor =>',
     'Some(_) =>',
     [GATE_2]),
    ('S6 helper: KR sends an answered request only at its retry', 6, 'feature', 'sync', HELPER_KEYS,
     '        let skip = if k.view.answered == Some(g.sha) {',
     '        let skip = if false {',
     [KEY_ANSWERS]),
    ('S6 helper: KR resends outcomes 3 and 4 only every 10 minutes', 6, 'feature', 'sync', HELPER_KEYS,
     '                && passed(k.kr_retry, self.now, KEY_RETRY);',
     ';',
     [KR_RETRY]),
    ('S6 helper: KR holds LIMIT', 6, 'feature', 'sync', HELPER_KEYS,
     '            !fresh && self.waiting() || k.limited(&g.sha, self.now)',
     '            !fresh && self.waiting()',
     [KR_RETRY]),
    ("S6 helper: KR checks PUTKEY OK's epoch", 6, 'feature', 'sync', HELPER_KEYS,
     'Some((RecordKind::Key, _, _, floor)) if floor == g.epoch => {}',
     'Some(_) => {}',
     [KEY_ANSWERS]),
    ("S6 helper: due() takes an answered request as answered", 6, 'feature', 'sync', HELPER_KEYS,
     '            Some((_, Req::Ok(g))) if k.view.answered == Some(g.sha) => match k.view.outcome {',
     '            Some((_, Req::Ok(g))) if false => match k.view.outcome {',
     [KEY_DUE]),
    ('S6 helper: due() decides a changed listing', 6, 'feature', 'sync', HELPER_KEYS,
     '    if listed != (seen.req, seen.view) {',
     '    if listed != listed {',
     [KEY_DUE]),
    ('S6 helper: KG waits while a CUT is unanswered', 6, 'feature', 'sync', HELPER_KEYS,
     '        if !wanted || k.cut_waiting() {',
     '        if !wanted {',
     [KG_CADENCE]),
    ('S6 helper: KG on a line without key ops only every 10 minutes', 6, 'feature', 'sync', HELPER_KEYS,
     '        if line_off && !passed(k.kg_retry, self.now, KEY_RETRY) {',
     '        if false {',
     [NOKEYS]),
    ('S6 helper: P4 and P5 wait for KG (the order rule)', 6, 'feature', 'sync', ENGINE,
     '            if go {',
     '            if go || !go {',
     [KR_FIRST]),
    ("S6 helper: kview rule (b), no key record while an off waits", 6, 'feature', 'sync', HELPER_KEYS,
     '        if fetched_key && cut_unanswered(&dir, id, &view) {',
     '        if fetched_key && false {',
     [NO_KEY_BYTES]),
    ("S6 helper: kview rule (c), a queued view only over its own content", 6, 'feature', 'sync', HELPER_KEYS,
     '            if q.against == disk {',
     '            if q.against == q.against {',
     [NO_KEY_BYTES]),
    ('S6 helper: a KEY_BEHIND upload waits for the key view', 6, 'feature', 'sync', ENGINE,
     '        if self.view.is_some() {\n            return false; // released when the key view changes\n',
     '        if self.view.is_some() && false {\n            return false; // released when the key view changes\n',
     [BEHIND_VIEW]),
    ('S6 helper: nokeys on a line without key ops', 6, 'feature', 'sync', HELPER_KEYS,
     '        if nokeys {',
     '        if false {',
     [NOKEYS]),
    ("S6 helper: KP waits for the vault head's epoch", 6, 'feature', 'sync', HELPER_KEYS,
     '        if head_epoch(&dir).is_none_or(|head| head < epoch) {',
     '        if head_epoch(&dir).is_none() {',
     [KP]),
    ('S6 wire: PUTKEY OK is the record after base', 6, 'feature', 'lib', SYNCWIRE,
     '(Op::PutKey, Status::Ok) => have.checked_add(1) == Some(version) && version <= EPOCH_MAX,',
     '(Op::PutKey, Status::Ok) => version >= 1,',
     [KEY_REPLIES]),
    ('S6 wire: CUTKEY OK ends the generation asked for', 6, 'feature', 'lib', SYNCWIRE,
     'let ended = record.kind == RecordKind::Cut || record.generation > have;',
     'let ended = true;',
     [KEY_REPLIES]),
    ("S6 wire: PUTKEY OK's header names a record below its number", 6, 'feature', 'lib', SYNCWIRE,
     'if blob.len() == RECORD_HEADER && generation < version => {}',
     'if blob.len() == RECORD_HEADER => {}',
     [KEY_REPLIES]),
    ('S6 wire: kview names its answer exactly with an outcome', 6, 'feature', 'lib', SYNCFILE_KEYS,
     'let consistent = (outcome == KeyOutcome::None) == answered.is_none();',
     'let consistent = true;',
     [KEY_VIEWS]),
    # Stage 6, the app (§7.11, §7.16, §7.20; §14.10): the request table,
    # `ks` and the holds of the key channel.
    ('S6 app: the pin of off.? to the record on top', 6, 'feature', 'lib', KEYSYNC,
     '                Top::Key { .. } | Top::Cut { damaged: true, .. } => Ks::Off(v.seq),\n                _ => Ks::None,',
     '                Top::Key { .. } | Top::Cut { damaged: true, .. } => Ks::None,\n                _ => Ks::None,',
     [KS_PIN]),
    ('S6 app: a ks that no longer waits is dropped', 6, 'feature', 'lib', KEYSYNC,
     'Ks::On(_) | Ks::Off(_) if !ks_pending(ks, Some(&v), top) => Ks::None,',
     'Ks::On(_) | Ks::Off(_) if false && !ks_pending(ks, Some(&v), top) => Ks::None,',
     [KS_ON_OFF]),
    ('S6 app: row 2 deletes kreq on a session that is not GOYOKS01', 6, 'feature', 'lib', KEYSYNC,
     '        let Some(own) = self.key_file.header().filter(|_| self.ks01()) else {\n            return (Want::Delete, false);',
     '        let Some(own) = self.key_file.header().filter(|_| self.ks01()) else {\n            return (Want::Keep, false);',
     [KS_TABLE]),
    ('S6 app: row 4 deletes a CUT it otherwise leaves', 6, 'feature', 'lib', KEYSYNC,
     '        let Some(v) = view.filter(|v| v.line == 0) else {\n            return (Want::KeepNoCut, false);',
     '        let Some(v) = view.filter(|v| v.line == 0) else {\n            return (Want::Keep, false);',
     [KS_TABLE]),
    ('S6 app: row 6 builds on the record the view shows', 6, 'feature', 'lib', KEYSYNC,
     'KeyClass::Stale => (put(v.seq, state.epoch), false),',
     'KeyClass::Stale => (put(0, state.epoch), false),',
     [KS_ON_OFF]),
    ('S6 app: the KeySyncGone and GatePending holds', 6, 'feature', 'lib', KEYSYNC,
     'if gate || self.gone_with(link, ks) {',
     'if false {',
     [KS_ON_OFF]),
    ('S6 app: the off deletes kview before it rotates', 6, 'feature', 'lib', KEYSYNC,
     'for name in [KEY_REQUEST, KEY_VIEW] {',
     'for name in [KEY_REQUEST] {',
     [KS_ON_OFF]),
    # Stage 6 review (§14.11 targets that had no row, and the review's
    # fixes): each caught by its named test.
    ("S6 app: the self-heal ends this PC's own record", 6, 'feature', 'lib', KEYSYNC,
     '            Ks::None if !self.ks01() => match top {',
     '            Ks::None if false && !self.ks01() => match top {',
     [KS_HEAL]),
    ('S6 app: KeySyncOff clears a pending gate (clears=g)', 6, 'feature', 'lib', HWRS,
     '(t.landing.ks, t.landing.clear_gate) = (Some(ks), true);\n                        (t.kind, t.rotate, t.sync) = (Kind::SyncOff',
     '(t.landing.ks, t.landing.clear_gate) = (Some(ks), false);\n                        (t.kind, t.rotate, t.sync) = (Kind::SyncOff',
     [KS_OFF_GATE]),
    ('S6 app: key_req_due retries a failed kreq write', 6, 'feature', 'lib', KEYSYNC,
     'link.keys.due = !ok;',
     'link.keys.due = false;',
     [KS_REQ_DUE]),
    ("S6 app: a join ends only a record of this PC's own", 6, 'feature', 'lib', KEYSYNC,
     'let own = matches!(class, KeyClass::Equal | KeyClass::Stale);',
     'let own = true;',
     [KS_LAGGING]),
    ("S6 app: merged names the candidate of a cleared gate", 6, 'feature', 'lib', KEYSYNC,
     '} else if clear && gate.is_some() && top == gate && gate != Some(check.other) {',
     '} else if false && clear && gate.is_some() && top == gate && gate != Some(check.other) {',
     [KS_MERGED]),
    ('S6 app: a gated successor holds by its class', 6, 'feature', 'lib', KEYSYNC,
     '                    | KeyClass::Refused(_)\n                    | KeyClass::Successor { gate: Some(_), .. },\n',
     '                    | KeyClass::Refused(_),\n',
     [KS_UNLOCK_HOLD]),
    ("S6 app: a none gate line of the same file turns pending", 6, 'feature', 'lib', KEYSYNC,
     '(g.epoch, g.tag) == (state.epoch, state.tag) && g.state != GateState::None',
     '(g.epoch, g.tag) == (state.epoch, state.tag)',
     [KS_NONE_LINE]),
    ('S6 app: S-PRUNE only after a write that added a tombstone', 6, 'feature', 'lib', KEYSYNC,
     '            && self.tombs_added\n',
     '',
     [KS_JOIN]),
    ('S6 app: a pending gate off the top is shown', 6, 'feature', 'lib', KEYSYNC,
     '            v.stale_gate = self.pending_gate().map(|g| g.epoch);',
     '            let _ = 0;',
     [KS_STALE_GATE]),
    ("S6 crash: KeySyncOff's S0 entry carries its ks (C10)", 6, 'feature', 'lib', HWRS,
     '(t.landing.ks, t.landing.clear_gate) = (Some(ks), true);',
     '(t.landing.ks, t.landing.clear_gate) = (None, true);',
     [CRASH_KEYS]),
    ("S6 crash: KeySyncOn's S0 entry carries on.c (C12)", 6, 'feature', 'lib', HWRS,
     't.landing.ks = Some(self.on_ks()?);',
     'let _ = self.on_ks()?;',
     [CRASH_KEYS]),
    ('S6 helper: a fetched copy waits for a GETKEY after it', 6, 'feature', 'sync', ENGINE,
     '            self.keys_after_fetch(&id);\n',
     '',
     [KG_AFTER]),
    ('S6 helper: a refusal over no view carries the top', 6, 'feature', 'sync', HELPER_KEYS,
     'let (top, fetched_key) = if self.v.keys.present {',
     'let (top, fetched_key) = if true {',
     [REFUSAL_TOP]),
    ('S6 helper: an unwritable kview shows config', 6, 'feature', 'sync', HELPER_KEYS,
     '        if self.v.keys.stuck >= VIEW_STUCK {\n            self.set(SyncState::Config);',
     '        if false {\n            self.set(SyncState::Config);',
     [VIEW_STUCK]),
    ('S6 helper: no view on disk does not stop P4 and P5', 6, 'feature', 'sync', HELPER_KEYS,
     'Wrote::Queued => matches!(self.v.keys.disk, Disk::Missing | Disk::Junk),',
     'Wrote::Queued => false,',
     [VIEW_STUCK]),
    ('S6 UI: [받기…] joins a fork of the key channel', 6, 'feature', 'bin', UI_SK,
     '        Some(vault::KeyClass::Successor { .. } | vault::KeyClass::KeyFork)',
     '        Some(vault::KeyClass::Successor { .. })',
     [UI_SK_T + 'key_sync_buttons_reach_every_way_out']),
    ('S6 UI: [받지 않기…] for a pending gate off the top', 6, 'feature', 'bin', UI_SK,
     '    if stale_gate.is_some() {\n        buttons.push((GATE_DROP, DROP_BUTTON));',
     '    if false {\n        buttons.push((GATE_DROP, DROP_BUTTON));',
     [UI_SK_T + 'key_sync_buttons_reach_every_way_out']),
    # Stage 6, end to end over the server channel (§14.10-1, -5, -6, -11,
    # -12, walkthroughs 1, 2, 4, 7, 9, 17 and 33): each caught by an e2e
    # test with the real helper and server script.
    ('S6 e2e: the holds at S4 follow the committed entry', 6, 'feature', 'sync', KEYSYNC,
     'let held = self.key_hold_with(&link, p.state.ks, gate);',
     'let held = { let _ = gate; self.key_hold(&link) };',
     [E2E_SITES, E2E_CYCLES]),
    ("S6 e2e: the server's file at this PC's own epoch is joined, not Contained", 6, 'feature', 'sync', ADOPT,
     '            && theirs.state.epoch == own.state.epoch;\n        #[cfg(not(feature = "security-key"))]',
     '            && false;\n        #[cfg(not(feature = "security-key"))]',
     [E2E_THREE]),
    ("S6 app: a USB copy of the server's top at own epoch is joined too", 6, 'feature', 'lib', ADOPT,
     '(matches!(source, Source::Server { .. }) || self.server_top_is(theirs.state))',
     'matches!(source, Source::Server { .. })',
     [KS_T + 'two_ons_at_once_are_joined_by_usb_too']),
    ('S6 e2e: a failed pick judges the waiting candidate again', 6, 'feature', 'sync', KEYSYNC,
     'if link.keys.read && stamp == link.keys.stamp && g2 == link.keys.g2 {',
     'if link.keys.read && stamp == link.keys.stamp {',
     [E2E_HOSTILE, E2E_GATE]),
    ('S6 e2e: the key channel classifies by the chain (rule D)', 6, 'feature', 'sync', KEYSYNC,
     '        let chained = other.chain_ok(self.keys.current());',
     '        let chained = true;',
     [E2E_HOSTILE]),
    ('S6 e2e: P4 on the key channel, an authorizer removed here', 6, 'feature', 'sync', KEYSYNC,
     '        if checked.removed_authorizer.is_some() {',
     '        if false && checked.removed_authorizer.is_some() {',
     [E2E_GATE]),
    ('S6 e2e: a gated server candidate is stored as pending', 6, 'feature', 'sync', KEYSYNC,
     '        self.store_gate(link);\n',
     '        if false {\n            self.store_gate(link);\n        }\n',
     [E2E_SITES, E2E_GATE]),
    ('S6 e2e: KeySyncGone holds a GOYOKS01 PC at a cut', 6, 'feature', 'sync', KEYSYNC,
     '            && matches!(link.keys.top, Top::Cut { .. } | Top::Empty)\n            && !matches!(ks, Ks::On(c) if c == v.seq)',
     '            && false\n            && !matches!(ks, Ks::On(c) if c == v.seq)',
     [E2E_HOSTILE, E2E_SITES, E2E_CYCLES]),
    ("S6 e2e: an 'on' waits for this PC's pending off", 6, 'feature', 'sync', KEYSYNC,
     '        matches!(ks, Ks::Off(_) | Ks::OffUnknown) && ks_pending(ks, view, top)',
     '        false && matches!(ks, Ks::Off(_) | Ks::OffUnknown) && ks_pending(ks, view, top)',
     [E2E_CYCLES]),
    ('S6 e2e: a dropped candidate stays refused', 6, 'feature', 'sync', KEYSYNC,
     '            && g.state == GateState::Dropped\n',
     '            && false\n',
     [E2E_HOSTILE, E2E_GATE]),
    ('S6 e2e: one-shot G2 on the key channel', 6, 'feature', 'sync', KEYSYNC,
     '            Some(GateKind::G2) if !self.g2_open() => Some(GateKind::G1),',
     '            Some(GateKind::G2) if false && !self.g2_open() => Some(GateKind::G1),',
     [E2E_HOSTILE, E2E_GATE]),
    ('S6 e2e: one-shot G2 at the accept of a server file', 6, 'feature', 'sync', ADOPT,
     '            Some(GateKind::G2) if !self.g2_allowed() => Some(GateKind::G1),',
     '            Some(GateKind::G2) if false && !self.g2_allowed() => Some(GateKind::G1),',
     [E2E_GATE]),
    ('S6 e2e: G1 at the accept of a server file', 6, 'feature', 'sync', ADOPT,
     '                if gate::code_matches(code, &self.id, dk, check.other) {',
     '                if true || gate::code_matches(code, &self.id, dk, check.other) {',
     [E2E_SITES, E2E_HOSTILE]),
    ('S6 e2e: G2 is exactly R at the accept of a server file', 6, 'feature', 'sync', GATE,
     '        !removed.is_empty() && pick.windows(2).all(|w| w[0] != w[1]) && pick == removed',
     '        !removed.is_empty() && !pick.is_empty()',
     [E2E_GATE, E2E_HOSTILE]),
    ('S6 e2e: G1 in TOFU for a new PC that syncs', 6, 'feature', 'sync', GATE,
     '            && (h.is_none() || !code_matches(code, &self.id, self.keys.current(), self.key_state))',
     '            && h.is_none()',
     [E2E_SITES]),
    ('S6 e2e: E5 on a server candidate', 6, 'feature', 'sync', GATE,
     '    if own.magic.hardware() && !ct_eq(&own.pw_id, &other.pw_id) && same {',
     '    if false && own.magic.hardware() && !ct_eq(&own.pw_id, &other.pw_id) && same {',
     [E2E_HOSTILE]),
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
    args += {'lib': ['--lib'], 'bin': ['--bin', 'goyo-vault'], 'sync': ['--bin', 'goyo-sync']}[target]
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
