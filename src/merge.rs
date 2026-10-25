//! Merging a synced copy of the vault into this one. It is a join: the live
//! entries are both sides' minus both sides' tombstones, the tombstones are
//! the union and the OTP watermark is the larger one. A replayed, old, forked
//! or duplicated copy can therefore delay changes but never delete or roll
//! back anything here: only a tombstone removes an entry, and only a user's
//! delete or edit makes one. Every PC gets the same result, whichever side is
//! local, so the copies converge and stop uploading.
use crate::vault::{
    Contents, DataRef, Entry, EntryId, Format, MAX_ENTRIES, MAX_FILE, MAX_TOMBSTONES, derived_id,
    plain_size,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

const NO_ID: EntryId = [0; 16];
/// Moves of texts that met other text under an ID, per merge. Each text
/// leaves each ID of its chain at most once and IDs are HMAC outputs, so a
/// merge of two files of at most 1000 entries makes fewer than this.
const MAX_MOVES: usize = 4 * MAX_ENTRIES;

pub(crate) struct MergeReport {
    /// Entries under IDs this PC did not hold, from the remote copy or moved
    /// there from an ID that kept other text.
    pub added: usize,
    /// Local entries gone from the result: removed by the remote copy's
    /// tombstones, or pushed off their ID by other text and kept nowhere.
    pub removed: usize,
    /// Entries edited on two PCs, each counted once: when the second edit
    /// arrives. Also texts pushed off their ID by other text and kept under
    /// a derived ID, so that both versions are there.
    pub conflicts: usize,
    /// The remote copy is older than one this PC already merged: the server
    /// went back. Nothing was lost; the merged state is uploaded again.
    pub rollback: bool,
    /// The result differs from the local state and must be saved.
    pub changed: bool,
    /// The result differs from the remote copy and must be uploaded.
    pub needs_push: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MergeError {
    /// The result would exceed MAX_ENTRIES, MAX_FILE or MAX_TOMBSTONES (or
    /// the counter its range). Nothing changes; the remote copy is kept for
    /// a later try.
    TooLarge,
}

/// Merges the authenticated `remote` copy into `local`. `remote.seen` is
/// ignored: it is the other PC's. `now_step` is the current OTP time step.
pub(crate) fn merge(
    key: &[u8; 32],
    local: DataRef,
    remote: Contents,
    now_step: u64,
) -> Result<(Contents, MergeReport), MergeError> {
    let Contents {
        last: remote_last,
        generation: remote_generation,
        entries: remote_entries,
        tombstones: remote_tombstones,
        ..
    } = remote;
    let local_dead: BTreeSet<EntryId> = local.tombstones.iter().copied().collect();
    let remote_dead: BTreeSet<EntryId> = remote_tombstones.iter().copied().collect();
    // Local order first, then what only the remote side has.
    let mut dead = BTreeSet::new();
    let mut tombstones = Vec::new();
    for t in local.tombstones.iter().chain(&remote_tombstones) {
        if dead.insert(*t) {
            tombstones.push(*t);
        }
    }
    if tombstones.len() > MAX_TOMBSTONES {
        return Err(MergeError::TooLarge);
    }

    let mut out: Vec<Entry> = Vec::with_capacity(local.entries.len() + remote_entries.len());
    let mut removed = 0;
    for e in local.entries {
        if dead.contains(&e.id()) {
            removed += 1;
        } else {
            out.push(e.clone());
        }
    }
    let local_ids: BTreeSet<EntryId> = local.entries.iter().map(Entry::id).collect();
    let remote_ids: BTreeSet<EntryId> = remote_entries.iter().map(Entry::id).collect();
    let mut index: BTreeMap<EntryId, usize> =
        out.iter().enumerate().map(|(i, e)| (e.id(), i)).collect();
    let mut moves = 0;
    for r in &remote_entries {
        let mut next = Some(r.clone());
        while let Some(mut e) = next.take() {
            let id = e.id();
            // Never brought back; a text moved here is lost.
            if dead.contains(&id) {
                continue;
            }
            let Some(&i) = index.get(&id) else {
                index.insert(id, out.len());
                out.push(e);
                continue;
            };
            if out[i].same_content(&e) {
                continue;
            }
            // Other text under the same ID: only a faulty client or a key
            // holder writes this. The smaller text keeps the ID and the
            // other moves to an ID derived from both, as an edit of it, where
            // the same rule applies again. Each text thus takes the first ID
            // of its own chain that no smaller text holds, whatever the order
            // of arrival, so every PC gets the same result and it converges.
            if e.fields() < out[i].fields() {
                std::mem::swap(&mut out[i], &mut e);
            }
            moves += 1;
            if moves > MAX_MOVES {
                return Err(MergeError::TooLarge);
            }
            let id2 = derived_id(key, b"goyo dup\0", &id, e.fields());
            e.set_ids(id2, id);
            next = Some(e);
        }
    }
    if out.len() > MAX_ENTRIES || plain_size(Format::V2, &out, tombstones.len()) + 64 > MAX_FILE {
        return Err(MergeError::TooLarge);
    }
    let out_ids: BTreeSet<EntryId> = out.iter().map(Entry::id).collect();
    let arrived: BTreeSet<EntryId> = out_ids.difference(&local_ids).copied().collect();
    // Whether the result holds `e` itself: its ID with its text.
    let holds = |e: &Entry| index.get(&e.id()).is_some_and(|&i| out[i].same_content(e));
    // Other text under an ID that `side` holds: that side must take the result.
    let replaced = |side: &[Entry]| side.iter().any(|e| out_ids.contains(&e.id()) && !holds(e));
    // A text that lost its ID either went to a derived ID, and both versions
    // are kept, or was dropped there, and it is a removal. Texts are
    // borrowed: counting copies no secret.
    let texts: BTreeSet<[&str; 4]> = out.iter().map(Entry::fields).collect();
    let local_texts: BTreeSet<[&str; 4]> = local.entries.iter().map(Entry::fields).collect();
    let mut duplicates = 0;
    for e in local.entries {
        if !dead.contains(&e.id()) && !holds(e) {
            if texts.contains(&e.fields()) {
                duplicates += 1;
            } else {
                removed += 1;
            }
        }
    }
    // A remote text kept only as a new entry next to this PC's.
    duplicates += remote_entries
        .iter()
        .filter(|r| out_ids.contains(&r.id()) && !holds(r))
        .filter(|r| texts.contains(&r.fields()) && !local_texts.contains(&r.fields()))
        .count();
    let (remote_replaced, local_replaced) = (replaced(&remote_entries), replaced(local.entries));

    // An entry edited on two PCs leaves two live entries whose parent is the
    // same deleted ID. Reported when one of them has just arrived.
    let mut groups: BTreeMap<EntryId, (usize, bool)> = BTreeMap::new();
    for e in &out {
        let parent = e.parent();
        if parent != NO_ID && dead.contains(&parent) {
            let group = groups.entry(parent).or_insert((0, false));
            group.0 += 1;
            group.1 |= arrived.contains(&e.id());
        }
    }
    let edited_twice = groups
        .values()
        .filter(|(live, new)| *live >= 2 && *new)
        .count();

    // A replay never lowers the watermark; a PC with a fast clock cannot
    // lock the others out.
    let last = local.last.max(remote_last.min(now_step.saturating_add(1)));
    // The watermark alone is never uploaded: unlock times stay off the server.
    let needs_push = remote_replaced || out_ids != remote_ids || dead != remote_dead;
    let highest = local.generation.max(remote_generation);
    // An upload always counts above the copy it replaces, so a lower count
    // later can only mean the server went back.
    let generation = if needs_push {
        highest.checked_add(1).ok_or(MergeError::TooLarge)?
    } else {
        highest
    };
    let changed = local_replaced
        || out_ids != local_ids
        || dead != local_dead
        || last != local.last
        || generation != local.generation;
    let report = MergeReport {
        added: arrived.len(),
        removed,
        conflicts: edited_twice + duplicates,
        rollback: remote_generation < local.seen,
        changed,
        needs_push,
    };
    let merged = Contents {
        last,
        generation,
        // Rides along; a higher `seen` alone never makes a save.
        seen: local.seen.max(remote_generation),
        entries: out,
        tombstones,
    };
    Ok((merged, report))
}

/// Code over the live entries, each by its ID and a hash of its four
/// fields, and over the tombstones, shown as XXXX-XXXX-XXXX-XXXX. Two PCs
/// show the same code only for the same entries, text included, and the
/// same deletions; a fork shows different ones. It is keyed with the data
/// key, so it reveals nothing about the entries, and 64 bits, so not even a
/// key holder can make other contents match a given code. The OTP watermark
/// is left out because OTP-only changes are not synced.
pub(crate) fn check_code(key: &[u8; 32], entries: &[Entry], tombstones: &[EntryId]) -> String {
    let live: BTreeMap<EntryId, &Entry> = entries.iter().map(|e| (e.id(), e)).collect();
    let dead: BTreeSet<&EntryId> = tombstones.iter().collect();
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(b"goyo sync check\0");
    for (id, e) in &live {
        let mut text = Sha256::new();
        for field in e.fields() {
            text.update((field.len() as u32).to_le_bytes());
            text.update(field.as_bytes());
        }
        let mut text = text.finalize();
        mac.update(id);
        mac.update(&text);
        text.as_mut_slice().zeroize();
    }
    mac.update(&[0xFF; 16]);
    for id in dead {
        mac.update(id);
    }
    let d = mac.finalize().into_bytes();
    format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MAX_TEXT;

    const KEY: [u8; 32] = [7; 32];
    const NOW: u64 = 1_000_000;

    fn view(c: &Contents) -> DataRef<'_> {
        DataRef {
            last: c.last,
            generation: c.generation,
            seen: c.seen,
            entries: &c.entries,
            tombstones: &c.tombstones,
        }
    }
    fn entry(id: EntryId, parent: EntryId, title: &str, secret: &str) -> Entry {
        let mut e = Entry::new(title.into(), String::new(), secret.into(), String::new()).unwrap();
        e.set_ids(id, parent);
        e
    }
    fn contents(entries: Vec<Entry>, tombstones: Vec<EntryId>, generation: u64) -> Contents {
        Contents {
            last: 0,
            generation,
            seen: 0,
            entries,
            tombstones,
        }
    }
    fn ids(c: &Contents) -> BTreeSet<EntryId> {
        c.entries.iter().map(Entry::id).collect()
    }
    fn dead(c: &Contents) -> BTreeSet<EntryId> {
        c.tombstones.iter().copied().collect()
    }
    /// (live IDs, tombstones): what merging must agree on.
    fn state(c: &Contents) -> (BTreeSet<EntryId>, BTreeSet<EntryId>) {
        (ids(c), dead(c))
    }
    fn run(local: &Contents, remote: &Contents) -> (Contents, MergeReport) {
        merge(&KEY, view(local), remote.clone(), NOW).unwrap()
    }
    fn text(c: &Contents, id: EntryId) -> Option<String> {
        let e = c.entries.iter().find(|e| e.id() == id)?;
        Some(e.fields().concat())
    }

    /// Every row of the case table, from both sides.
    #[test]
    fn case_table() {
        let (x, y, z) = ([1; 16], [2; 16], [3; 16]);
        let base = || {
            contents(
                vec![entry(x, NO_ID, "x", "1"), entry(y, NO_ID, "y", "2")],
                vec![],
                1,
            )
        };
        // B added Z.
        let mut b = base();
        b.entries.push(entry(z, NO_ID, "z", "3"));
        b.generation = 2;
        let (m, r) = run(&base(), &b);
        assert_eq!(ids(&m), [x, y, z].into());
        assert!(r.added == 1 && r.removed == 0 && r.changed && !r.needs_push);
        assert_eq!(m.generation, 2);
        // B deleted X.
        let b = contents(vec![entry(y, NO_ID, "y", "2")], vec![x], 2);
        let (m, r) = run(&base(), &b);
        assert_eq!(state(&m), ([y].into(), [x].into()));
        assert!(r.removed == 1 && r.changed && !r.needs_push);
        // A edited X, B did nothing: A's version, uploaded with a higher count.
        let xa = [4; 16];
        let a = contents(
            vec![entry(xa, x, "x", "edited"), entry(y, NO_ID, "y", "2")],
            vec![x],
            2,
        );
        let (m, r) = run(&a, &base());
        assert_eq!(state(&m), state(&a));
        assert!(r.needs_push && r.conflicts == 0 && r.added == 0);
        assert_eq!(m.generation, 3);
        // A and B both edited X: both kept, one conflict on each PC.
        let xb = [5; 16];
        let b = contents(
            vec![entry(xb, x, "x", "other edit"), entry(y, NO_ID, "y", "2")],
            vec![x],
            2,
        );
        let (m, r) = run(&a, &b);
        assert_eq!(state(&m), ([xa, y, xb].into(), [x].into()));
        assert_eq!(r.conflicts, 1);
        let (n, r) = run(&b, &a);
        assert_eq!(state(&n), state(&m));
        assert_eq!(r.conflicts, 1);
        // Reported once: merging the upload of the other side is quiet.
        let (_, r) = run(&m, &n);
        assert!(r.conflicts == 0 && !r.needs_push);
        // A edited X, B deleted X: A's edit is kept.
        let b = contents(vec![entry(y, NO_ID, "y", "2")], vec![x], 2);
        for (m, _) in [run(&a, &b), run(&b, &a)] {
            assert_eq!(state(&m), ([xa, y].into(), [x].into()));
        }
        // Both deleted X.
        let (m, r) = run(&b, &b);
        assert_eq!(state(&m), state(&b));
        assert!(!r.changed && !r.needs_push);
        // Both added the same text on their own: two entries, no conflict.
        let (n1, n2) = ([6; 16], [7; 16]);
        let mut a = base();
        a.entries.push(entry(n1, NO_ID, "same", "text"));
        let mut b = base();
        b.entries.push(entry(n2, NO_ID, "same", "text"));
        let (m, r) = run(&a, &b);
        assert_eq!(ids(&m), [x, y, n1, n2].into());
        assert!(r.conflicts == 0 && r.needs_push);
        // A replayed old copy changes nothing; it warns only below `seen`.
        let mut a = m;
        a.seen = 5;
        a.generation = 6;
        let (m, r) = run(&a, &base());
        assert_eq!(state(&m), state(&a));
        assert!(r.rollback && r.needs_push && r.added == 0 && r.removed == 0);
        let mut old = base();
        old.generation = 5;
        let (_, r) = run(&a, &old);
        assert!(!r.rollback && r.needs_push);
    }

    /// Same ID, other text: the smaller text keeps the ID, the other gets a
    /// derived ID, and both orders agree.
    #[test]
    fn duplicate_id_converges() {
        let x = [1; 16];
        let a = contents(vec![entry(x, NO_ID, "x", "a")], vec![], 3);
        let b = contents(vec![entry(x, NO_ID, "x", "b")], vec![], 3);
        let (ma, ra) = run(&a, &b);
        let (mb, rb) = run(&b, &a);
        for (m, r) in [(&ma, &ra), (&mb, &rb)] {
            assert_eq!(m.entries.len(), 2);
            assert_eq!(text(m, x).unwrap(), "xa");
            // Both texts are kept: a conflict, not a removal.
            assert!(r.conflicts == 1 && r.removed == 0 && r.added == 1);
            assert!(r.needs_push && r.changed);
        }
        assert_eq!(state(&ma), state(&mb));
        let id2 = *ids(&ma).iter().find(|i| **i != x).unwrap();
        // Every PC must derive the same ID: vector from Python's hmac.
        let hex: String = id2.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "d14b4fcb68534a21c5a5cf96f488f8bd");
        assert_eq!(text(&ma, id2).unwrap(), "xb");
        assert_eq!(text(&mb, id2).unwrap(), "xb");
        let moved = ma.entries.iter().find(|e| e.id() == id2).unwrap();
        assert_eq!(moved.parent(), x);
        // Converged: nothing more to save or upload, no second notice.
        let (m, r) = run(&ma, &mb);
        assert_eq!(state(&m), state(&ma));
        assert!(!r.changed && !r.needs_push && r.conflicts == 0);
        // The side that still holds the larger text adopts the smaller one.
        // Its own text moves to id2, which the remote copy also holds: one
        // entry, not two with the same ID (a file that could not be saved).
        let (m, r) = run(&b, &ma);
        assert_eq!(text(&m, x).unwrap(), "xa");
        assert!(r.changed && !r.needs_push);
        assert!(r.conflicts == 1 && r.removed == 0);
        assert_eq!(m.entries.len(), 2);
        assert_eq!(state(&m), state(&ma));
        // Once the user deleted the moved copy, it does not come back.
        let mut gone = ma.clone();
        gone.entries.retain(|e| e.id() != id2);
        gone.tombstones.push(id2);
        let (m, _) = run(&gone, &b);
        assert_eq!(state(&m), state(&gone));
        assert_eq!(text(&m, x).unwrap(), "xa");
        // Equal IDs and tombstones but other text under one ID: the side
        // holding the smaller text uploads it and the other side saves it,
        // or the server copy would differ forever.
        let stale = contents(vec![entry(x, NO_ID, "x", "b")], vec![id2], 3);
        let (m, r) = run(&gone, &stale);
        assert_eq!(state(&m), state(&gone));
        assert_eq!(text(&m, x).unwrap(), "xa");
        assert!(r.needs_push && m.generation > gone.generation.max(stale.generation));
        let (m, r) = run(&stale, &gone);
        assert_eq!(text(&m, x).unwrap(), "xa");
        assert!(r.changed && !r.needs_push);
        // Its own text is dropped at the deleted id2: a removal there, not
        // "both versions kept".
        assert!(r.removed == 1 && r.conflicts == 0 && r.added == 0);
    }

    /// A key holder writes smaller text under every live ID of this PC.
    /// Whatever it puts at the IDs the displaced texts move to, a text it
    /// drops counts as removed, never as kept, and a text it does not drop
    /// is kept. Both orders agree.
    #[test]
    fn takeover_under_the_same_ids() {
        let numbered = |n: usize| -> EntryId {
            let mut id = [9; 16];
            id[..8].copy_from_slice(&(n as u64).to_le_bytes());
            id
        };
        let local = contents(
            (0..10)
                .map(|n| entry(numbered(n), NO_ID, &format!("entry {n}"), "secret"))
                .collect(),
            vec![],
            4,
        );
        let id2 = |e: &Entry| derived_id(&KEY, b"goyo dup\0", &e.id(), e.fields());
        let fake = |e: &Entry| entry(e.id(), NO_ID, "!", "x");
        let texts = |c: &Contents| -> BTreeSet<(EntryId, String)> {
            c.entries
                .iter()
                .map(|e| (e.id(), e.fields().concat()))
                .collect()
        };
        let commutes = |remote: &Contents, m: &Contents| {
            let (n, _) = run(remote, &local);
            assert_eq!(texts(&n), texts(m));
            let (again, r) = run(m, m);
            assert!(!r.changed && !r.needs_push && texts(&again) == texts(m));
        };
        let originals = |m: &Contents| {
            let held: BTreeSet<String> = m.entries.iter().map(|e| e.fields().concat()).collect();
            local
                .entries
                .iter()
                .filter(|e| held.contains(&e.fields().concat()))
                .count()
        };

        // Each displaced text's ID is deleted: all ten are gone.
        let killed = contents(
            local.entries.iter().map(fake).collect(),
            local.entries.iter().map(id2).collect(),
            5,
        );
        let (m, r) = run(&local, &killed);
        assert!(m.entries.iter().all(|e| e.fields().concat() == "!x"));
        assert_eq!(ids(&m), ids(&local));
        assert!(r.removed == 10 && r.conflicts == 0 && r.added == 0);
        assert!(r.changed && !r.needs_push);
        commutes(&killed, &m);

        // Smaller junk holds each of those IDs: the texts move on and stay.
        let mut junk = contents(local.entries.iter().map(fake).collect(), vec![], 5);
        for e in &local.entries {
            junk.entries.push(entry(id2(e), NO_ID, "#", "y"));
        }
        let (m, r) = run(&local, &junk);
        assert_eq!(originals(&m), 10);
        assert_eq!(m.entries.len(), 30);
        assert!(r.removed == 0 && r.conflicts == 10 && r.added == 20);
        assert!(r.needs_push);
        commutes(&junk, &m);

        // Larger junk there: the texts take those IDs, the junk moves on.
        let mut junk = contents(local.entries.iter().map(fake).collect(), vec![], 5);
        for e in &local.entries {
            junk.entries.push(entry(id2(e), NO_ID, "zz", "y"));
        }
        let (m, r) = run(&local, &junk);
        assert_eq!(originals(&m), 10);
        for e in &local.entries {
            assert_eq!(text(&m, id2(e)), Some(e.fields().concat()));
        }
        // The junk was pushed off its IDs as well, and is kept as well.
        assert!(r.removed == 0 && r.conflicts == 20 && r.added == 20);
        commutes(&junk, &m);
    }

    #[test]
    fn otp_watermark_rules() {
        let x = [1; 16];
        let at = |last: u64| Contents {
            last,
            ..contents(vec![entry(x, NO_ID, "x", "1")], vec![], 1)
        };
        // Never lowered, and a lower remote is nothing to upload.
        let (m, r) = run(&at(100), &at(50));
        assert_eq!(m.last, 100);
        assert!(!r.changed && !r.needs_push);
        // A higher remote is taken, and is still nothing to upload.
        let (m, r) = run(&at(100), &at(200));
        assert_eq!(m.last, 200);
        assert!(r.changed && !r.needs_push);
        assert_eq!(m.generation, 1);
        // A remote clock far ahead is clamped to the next step.
        let (m, _) = run(&at(100), &at(NOW + 1000));
        assert_eq!(m.last, NOW + 1);
        let (m, _) = run(&at(NOW + 5), &at(NOW + 1000));
        assert_eq!(m.last, NOW + 5);
    }

    #[test]
    fn generation_and_rollback() {
        let x = [1; 16];
        let mine = Contents {
            seen: 3,
            ..contents(vec![entry(x, NO_ID, "x", "1")], vec![], 5)
        };
        // This PC's own upload comes back: no warning, nothing to save.
        let mut uploaded = mine.clone();
        uploaded.seen = 0;
        let (m, r) = run(&mine, &uploaded);
        assert!(!r.rollback && !r.changed && !r.needs_push);
        assert_eq!((m.generation, m.seen), (5, 5));
        // A new PC restored from the server copy (whose `seen` is another
        // PC's) sees the same head: no warning.
        let restored = Contents {
            seen: 4,
            ..uploaded.clone()
        };
        let (_, r) = run(&restored, &uploaded);
        assert!(!r.rollback);
        // Only a copy below `seen` warns.
        let mut later = m;
        later.seen = 6;
        later.generation = 6;
        assert!(run(&later, &uploaded).1.rollback);
        let mut equal = uploaded.clone();
        equal.generation = 6;
        assert!(!run(&later, &equal).1.rollback);
    }

    #[test]
    fn too_large_changes_nothing() {
        let numbered = |n: usize, tag: u8| -> EntryId {
            let mut id = [tag; 16];
            id[..8].copy_from_slice(&(n as u64).to_le_bytes());
            id
        };
        let many = |count: usize, tag: u8| {
            (0..count)
                .map(|n| entry(numbered(n, tag), NO_ID, "x", "1"))
                .collect::<Vec<_>>()
        };
        let check = |local: Contents, remote: Contents| {
            let before = (state(&local), local.generation, local.last);
            assert_eq!(
                merge(&KEY, view(&local), remote, NOW).err(),
                Some(MergeError::TooLarge)
            );
            assert_eq!((state(&local), local.generation, local.last), before);
        };
        // 1001 entries.
        check(
            contents(many(600, 1), vec![], 1),
            contents(many(401, 2), vec![], 1),
        );
        // More than 8 MiB.
        let big = |count: usize, tag: u8| {
            (0..count)
                .map(|n| {
                    let mut e = Entry::new(
                        "t".repeat(256),
                        "k".repeat(64),
                        "s".repeat(MAX_TEXT),
                        "n".repeat(MAX_TEXT),
                    )
                    .unwrap();
                    e.set_ids(numbered(n, tag), NO_ID);
                    e
                })
                .collect::<Vec<_>>()
        };
        check(
            contents(big(300, 1), vec![], 1),
            contents(big(250, 2), vec![], 1),
        );
        // More than 65,536 tombstones.
        let buried = |count: usize, tag: u8| -> Vec<EntryId> {
            (0..count).map(|n| numbered(n, tag)).collect()
        };
        check(
            contents(vec![], buried(40_000, 1), 1),
            contents(vec![], buried(30_000, 2), 1),
        );
        // The counter at its end.
        check(
            contents(many(1, 1), vec![], u64::MAX),
            contents(many(1, 2), vec![], 1),
        );
    }

    #[test]
    fn check_code_covers_ids_and_text() {
        let (x, y) = ([1; 16], [2; 16]);
        let a = Contents {
            last: 5,
            ..contents(
                vec![entry(x, NO_ID, "x", "1"), entry(y, NO_ID, "y", "2")],
                vec![[3; 16], [4; 16]],
                1,
            )
        };
        // Order, the OTP watermark and the counters do not count.
        let b = Contents {
            last: 9,
            ..contents(
                vec![entry(y, NO_ID, "y", "2"), entry(x, NO_ID, "x", "1")],
                vec![[4; 16], [3; 16]],
                7,
            )
        };
        let code = check_code(&KEY, &a.entries, &a.tombstones);
        assert_eq!(code, check_code(&KEY, &b.entries, &b.tombstones));
        assert_eq!(code.len(), 19);
        // Every PC must show the same code: vector from Python's hmac.
        assert_eq!(
            check_code(&KEY, &a.entries, &[[3; 16]]),
            "A694-933F-6829-CF9C"
        );
        // Other text under the same IDs, even in one field, is another code.
        let mut swapped = b.clone();
        swapped.entries[0] = entry(y, NO_ID, "y", "3");
        assert_ne!(code, check_code(&KEY, &swapped.entries, &b.tombstones));
        let mut noted = b.clone();
        *noted.entries[1].notes = "n".into();
        assert_ne!(code, check_code(&KEY, &noted.entries, &b.tombstones));
        // Field boundaries count: "x" + "1" is not "x1" + "".
        let mut shifted = b.clone();
        *shifted.entries[1].title = "x1".into();
        shifted.entries[1].secret.clear();
        assert_ne!(code, check_code(&KEY, &shifted.entries, &b.tombstones));
        // A live ID moved to the tombstones is a different state.
        assert_ne!(
            code,
            check_code(&KEY, &a.entries[..1], &[[3; 16], [4; 16], y])
        );
        assert_ne!(code, check_code(&KEY, &a.entries, &a.tombstones[..1]));
        // Another vault's key gives another code for the same contents.
        assert_ne!(code, check_code(&[8; 32], &a.entries, &a.tombstones));
    }

    /// Fixed-seed xorshift64*: repeatable, no RNG crate, no OS randomness.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn id(&mut self) -> EntryId {
            let mut id = [0; 16];
            id[..8].copy_from_slice(&self.next().to_le_bytes());
            id[8..].copy_from_slice(&self.next().to_le_bytes());
            id[0] |= 1; // never zero
            id
        }
        fn entry(&mut self, id: EntryId, parent: EntryId) -> Entry {
            // A small alphabet, so equal text under different IDs is common.
            let title = ["mail", "bank", "wallet"][self.below(3)];
            entry(id, parent, title, &format!("s{}", self.below(4)))
        }
    }
    struct Replica {
        now: Contents,
        /// Earlier states, oldest first.
        history: Vec<Contents>,
    }

    /// The merge laws over one merge: join, no loss, watermark, counters and
    /// symmetry, idempotence and replay safety.
    fn check_merge(
        local: &Contents,
        remote: &Contents,
        older: &Contents,
        deleted: &BTreeSet<EntryId>,
    ) -> Contents {
        let (m, r) = merge(&KEY, view(local), remote.clone(), NOW).unwrap();
        let (mine, theirs, merged) = (state(local), state(remote), state(&m));
        // Tombstones are the union; live entries all others of both sides.
        let all_dead: BTreeSet<EntryId> = mine.1.union(&theirs.1).copied().collect();
        assert_eq!(merged.1, all_dead);
        let survivors: BTreeSet<EntryId> = mine
            .0
            .union(&theirs.0)
            .filter(|id| !all_dead.contains(*id))
            .copied()
            .collect();
        assert_eq!(merged.0, survivors);
        assert!(mine.0.difference(&merged.0).all(|id| deleted.contains(id)));
        assert_eq!(r.removed, mine.0.difference(&merged.0).count());
        assert_eq!(r.added, merged.0.difference(&mine.0).count());
        for e in &m.entries {
            let id = e.id();
            assert!(text(local, id).or(text(remote, id)) == Some(e.fields().concat()));
        }
        assert!(m.last >= local.last);
        assert!(m.generation >= m.seen && m.generation >= local.generation);
        assert!(!r.needs_push || m.generation > remote.generation);
        assert_eq!(r.rollback, remote.generation < local.seen);
        assert_eq!(r.needs_push, merged != theirs);
        assert_eq!(
            r.changed,
            merged != mine || m.last != local.last || m.generation != local.generation
        );
        // Commutative.
        assert_eq!(state(&run(remote, local).0), merged);
        // Idempotent.
        let (again, r) = run(&m, &m);
        assert!(!r.changed && !r.needs_push && state(&again) == merged);
        // Replay safe: what was merged, or an older copy of it, changes nothing.
        assert_eq!(state(&run(&m, remote).0), merged);
        assert_eq!(state(&run(&m, older).0), merged);
        m
    }

    /// Three replicas, 2000 random operations each, merging random earlier
    /// copies of each other, then a full exchange.
    #[test]
    fn random_replicas_converge() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let empty = || contents(vec![], vec![], 0);
        let mut replicas: Vec<Replica> = (0..3)
            .map(|_| Replica {
                now: empty(),
                history: vec![empty()],
            })
            .collect();
        let mut created = BTreeSet::new();
        let mut deleted = BTreeSet::new();
        let mut step = 0u64;
        for round in 0..2000 {
            step += 1;
            for n in 0..3 {
                let len = replicas[n].now.entries.len();
                let mut op = rng.below(100);
                if len >= 60 && op < 30 {
                    op = 50; // keep the size moderate: delete instead
                }
                if len == 0 && (30..62).contains(&op) {
                    op = 0;
                }
                let c = &mut replicas[n].now;
                match op {
                    // Add.
                    0..30 => {
                        let id = rng.id();
                        c.entries.push(rng.entry(id, NO_ID));
                        created.insert(id);
                        c.generation += 1;
                    }
                    // Edit: a new ID whose parent is the old one.
                    30..50 => {
                        let i = rng.below(len);
                        let old = c.entries[i].id();
                        let id = rng.id();
                        let new = rng.entry(id, old);
                        if !new.same_content(&c.entries[i]) {
                            created.insert(new.id());
                            c.entries[i] = new;
                            c.tombstones.push(old);
                            deleted.insert(old);
                            c.generation += 1;
                        }
                    }
                    // Delete.
                    50..62 => {
                        let old = c.entries.remove(rng.below(len)).id();
                        c.tombstones.push(old);
                        deleted.insert(old);
                        c.generation += 1;
                    }
                    // An unlock with an OTP code.
                    62..67 => c.last = c.last.max(step),
                    // Merge a random earlier copy of a random replica.
                    _ => {
                        let from = &replicas[rng.below(3)].history;
                        let k = rng.below(from.len());
                        let (remote, older) = (from[k].clone(), from[rng.below(k + 1)].clone());
                        let m = check_merge(&replicas[n].now, &remote, &older, &deleted);
                        replicas[n].now = m;
                    }
                }
                let r = &mut replicas[n];
                assert!(r.now.generation >= r.now.seen);
                r.history.push(r.now.clone());
                if r.history.len() > 40 {
                    let drop = rng.below(r.history.len() - 1);
                    r.history.remove(drop);
                }
            }
            // Associative, on random earlier copies.
            if round % 20 == 0 {
                let mut pick = || {
                    let h = &replicas[rng.below(3)].history;
                    h[rng.below(h.len())].clone()
                };
                let (a, b, c) = (pick(), pick(), pick());
                let left = run(&run(&a, &b).0, &c).0;
                let right = run(&a, &run(&b, &c).0).0;
                assert_eq!(state(&left), state(&right));
            }
        }
        // Full exchange: everything reaches everyone.
        let last_of = |r: &Replica| r.now.clone();
        let (r1, r2) = (last_of(&replicas[1]), last_of(&replicas[2]));
        let m = run(&replicas[0].now, &r1).0;
        replicas[0].now = run(&m, &r2).0;
        let all = replicas[0].now.clone();
        for r in &mut replicas[1..] {
            r.now = run(&r.now, &all).0;
        }
        let expected: BTreeSet<EntryId> = created.difference(&deleted).copied().collect();
        for a in &replicas {
            assert_eq!(state(&a.now), (expected.clone(), deleted.clone()));
            assert!(a.now.generation >= a.now.seen);
            for b in &replicas {
                let (m, r) = run(&a.now, &b.now);
                assert!(!r.needs_push && !r.changed, "no ping-pong");
                for e in &m.entries {
                    assert_eq!(text(&b.now, e.id()), Some(e.fields().concat()));
                }
            }
        }
        assert!(expected.len() > 10 && deleted.len() > 1000);
    }

    /// Faulty clients writing other text under live IDs, and key holders
    /// writing at the IDs moved texts go to, at random: every merge result
    /// can still be saved, every merge is commutative and idempotent, and
    /// the copies still converge, text included, without uploading forever.
    #[test]
    fn duplicate_ids_converge_at_random() {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        // The ID rules of a v2 file; decode_data refuses any other.
        let writable = |c: &Contents| {
            let live = ids(c);
            assert_eq!(live.len(), c.entries.len());
            assert_eq!(dead(c).len(), c.tombstones.len());
            assert!(!live.contains(&NO_ID) && !dead(c).contains(&NO_ID));
            assert!(live.is_disjoint(&dead(c)));
        };
        let texts = |c: &Contents| -> BTreeSet<(EntryId, String)> {
            c.entries
                .iter()
                .map(|e| (e.id(), e.fields().concat()))
                .collect()
        };
        let mut conflicts = 0;
        for _ in 0..300 {
            let mut replicas: Vec<Contents> = (0..3).map(|_| contents(vec![], vec![], 0)).collect();
            for _ in 0..80 {
                let n = rng.below(3);
                let len = replicas[n].entries.len();
                let c = &mut replicas[n];
                match rng.below(10) {
                    // Few possible IDs, so the replicas reuse each other's.
                    0..3 => {
                        let mut id = [0; 16];
                        id[0] = 1 + rng.below(6) as u8;
                        if ids(c).contains(&id) || dead(c).contains(&id) {
                            continue;
                        }
                        c.entries.push(rng.entry(id, NO_ID));
                        c.generation += 1;
                    }
                    3..5 if len > 0 => {
                        let i = rng.below(len);
                        let (id, parent) = (c.entries[i].id(), c.entries[i].parent());
                        c.entries[i] = rng.entry(id, parent);
                    }
                    5 if len > 0 => {
                        let old = c.entries.remove(rng.below(len)).id();
                        c.tombstones.push(old);
                        c.generation += 1;
                    }
                    // A key holder writes or deletes the ID that a text
                    // would move to from a live ID, so moves meet again.
                    6 if len > 0 => {
                        let id = c.entries[rng.below(len)].id();
                        let moving = rng.entry(id, NO_ID);
                        let id2 = derived_id(&KEY, b"goyo dup\0", &id, moving.fields());
                        if ids(c).contains(&id2) || dead(c).contains(&id2) {
                            continue;
                        }
                        if rng.below(2) == 0 {
                            c.entries.push(rng.entry(id2, id));
                        } else {
                            c.tombstones.push(id2);
                        }
                        c.generation += 1;
                    }
                    _ => {
                        let remote = replicas[rng.below(3)].clone();
                        let (m, r) = run(&replicas[n], &remote);
                        writable(&m);
                        // Text included: commutative and idempotent.
                        assert_eq!(texts(&run(&remote, &replicas[n]).0), texts(&m));
                        let (again, twice) = run(&m, &m);
                        assert!(!twice.changed && texts(&again) == texts(&m));
                        conflicts += r.conflicts;
                        replicas[n] = m;
                    }
                }
            }
            for _ in 0..3 {
                for a in 0..3 {
                    for b in 0..3 {
                        let remote = replicas[b].clone();
                        replicas[a] = run(&replicas[a], &remote).0;
                    }
                }
            }
            for a in &replicas {
                writable(a);
                assert_eq!(texts(a), texts(&replicas[0]));
                for b in &replicas {
                    let (_, r) = run(a, b);
                    assert!(!r.changed && !r.needs_push, "no ping-pong");
                }
            }
        }
        assert!(conflicts > 1000);
    }
}
