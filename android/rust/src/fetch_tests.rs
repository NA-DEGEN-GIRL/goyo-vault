//! "서버에서 가져오기" against the real server script over pipes (the
//! harness of engine_tests.rs): the server list with each vault's key
//! file as this phone's line lets it see, the fetch of a vault's head
//! version as a new file, and its key file put into the sync folder as the
//! key view the lib's "서버에서 가져온 금고" steps read. No network.
use crate::{
    engine_tests::{Device, KS, PASSWORD, Pipe, Temp, entry, python},
    fetch::{self, Fetched, KeyGot, ServerKey},
};
use goyo_vault::{
    syncengine::Log,
    syncfile::{self, KEY_REQUEST, KeyRequest, OUTGOING, SyncState, render_key_request},
    vault::{self, Provision, Session, keyfile::is_sync_key_file},
};
use std::fs;

#[test]
fn the_phone_lists_and_fetches_a_vault_and_its_key_file() {
    if !python() {
        return;
    }
    let anchor = Temp::new("fetch-anchor");
    vault::set_anchor_dir(Some(anchor.0.clone()));
    let store = Temp::new("fetch-server");
    let root = store.0.join("data");
    let log = Log::new(None);

    // A PC's password-only vault, synced to the server.
    let mut pc = Device::new("fetch-pc", &root, &[]);
    let mut spc = Provision::new()
        .unwrap()
        .finish(&pc.vault, &pc.key, PASSWORD)
        .unwrap();
    spc.put(None, entry("mail", "first")).unwrap();
    let _ = pc.pass();
    spc.enable_sync().unwrap();
    assert_eq!(pc.pass().state, SyncState::Ok);
    let pc_id: [u8; 16] = fs::read(&pc.vault).unwrap()[8..24].try_into().unwrap();

    // A GOYOKS01 vault whose key file another device put on the server
    // (the fixture: vault 3a3b…, epoch 9), with a vault copy at that state.
    let ks_id: [u8; 16] = KS[8..24].try_into().unwrap();
    let syntax = is_sync_key_file(KS, &ks_id).unwrap();
    let mut v = Vec::from(*b"GOYOVA04");
    v.extend_from_slice(&ks_id);
    v.resize(300, 7);
    v[24..40].copy_from_slice(&syntax.current_key_id);
    v[40..48].copy_from_slice(&syntax.epoch.to_le_bytes());
    v[48..64].copy_from_slice(&syntax.tag);
    v[64..68].copy_from_slice(&[3, 0, 0, 0]);
    let mut other = Device::new("fetch-other", &root, &[ks_id]);
    fs::write(&other.vault, b"never read by the engine").unwrap();
    fs::create_dir(&other.dir).unwrap();
    let put = render_key_request(&KeyRequest::put(0, 0, KS));
    syncfile::replace_file(&other.dir.join(KEY_REQUEST), &put).unwrap();
    let up = syncfile::render_outgoing(0, &v).unwrap();
    syncfile::replace_file(&other.dir.join(OUTGOING), &up).unwrap();
    assert_eq!(other.pass().state, SyncState::Ok);

    // The phone's line names the GOYOKS01 vault (as 'Android 기기 추가'
    // puts the PC's list into it), not the PC's password-only one.
    let mut wire = Pipe {
        root: root.clone(),
        key_sync: vec![ks_id],
    };
    let mut rows = fetch::list(&mut wire, &log).unwrap();
    rows.sort_by_key(|(e, _)| e.id);
    assert_eq!(rows.len(), 2);
    for (e, key) in &rows {
        assert_eq!(e.head, 1);
        if e.id == ks_id {
            assert_eq!(*key, ServerKey::Held);
            assert_eq!(e.size, 300);
        } else {
            assert_eq!(e.id, pc_id);
            // Its line has no --key-sync for this vault.
            assert_eq!(*key, ServerKey::NotAllowed);
        }
    }

    // The PC's vault: the head as a new file, which opens with the PC's
    // key file (the key file came by USB: the server has none for it).
    let phone = Temp::new("fetch-phone");
    let path = phone.0.join("vault").join("vault.goyo");
    let got = fetch::fetch_vault(&mut wire, &log, pc_id, &path);
    let Fetched::Saved { version, bytes } = got else {
        panic!("{got:?}")
    };
    assert_eq!(
        (version, bytes as u64),
        (1, fs::metadata(&path).unwrap().len())
    );
    assert_eq!(vault::vault_tag(&path), Some(fetch::tag(&pc_id)));
    assert_eq!(
        fetch::fetch_key(&mut wire, &log, pc_id, &path),
        KeyGot::NoKeys
    );
    assert!(vault::fetched_key(&path).is_none());
    let s = Session::unlock(&path, &pc.key, PASSWORD).unwrap();
    assert_eq!(s.entries[0].title.as_str(), "mail");
    drop(s);
    // Never over a file; an ID the server does not hold.
    assert_eq!(
        fetch::fetch_vault(&mut wire, &log, pc_id, &path),
        Fetched::Exists
    );
    let gone = phone.0.join("gone.goyo");
    assert_eq!(
        fetch::fetch_vault(&mut wire, &log, [0x5a; 16], &gone),
        Fetched::NotFound
    );
    assert!(!gone.exists());
    // With a line that serves key ops for it, the server holds none.
    let mut both = Pipe {
        root: root.clone(),
        key_sync: vec![ks_id, pc_id],
    };
    assert_eq!(
        fetch::fetch_key(&mut both, &log, pc_id, &path),
        KeyGot::Empty
    );

    // The GOYOKS01 vault: the vault file and, in its sync folder, the
    // server's key file as the key view the vault app's steps read.
    let path = phone.0.join("ks").join("vault.goyo");
    assert!(matches!(
        fetch::fetch_vault(&mut wire, &log, ks_id, &path),
        Fetched::Saved {
            version: 1,
            bytes: 300
        }
    ));
    assert_eq!(fs::read(&path).unwrap(), v);
    assert_eq!(
        fetch::fetch_key(&mut wire, &log, ks_id, &path),
        KeyGot::Written
    );
    assert!(vault::fetched_key(&path).is_some());
    let info = vault::fetched_key_info(&path).unwrap();
    assert!(info.needs_security_key);
    // A sync folder left at a path is refused as the file is.
    fs::remove_file(&path).unwrap();
    assert_eq!(
        fetch::fetch_vault(&mut wire, &log, ks_id, &path),
        Fetched::Exists
    );
    vault::set_anchor_dir(None);
}

#[test]
fn vault_ids_are_parsed_strictly() {
    let id = [0xab; 16];
    assert_eq!(fetch::parse_id(&syncfile::hex(&id)), Some(id));
    assert_eq!(
        fetch::parse_id(&syncfile::hex(&id).to_uppercase()),
        Some(id)
    );
    assert_eq!(fetch::parse_id(&"0".repeat(32)), None);
    assert_eq!(fetch::parse_id("abc"), None);
    assert_eq!(fetch::parse_id(&"g".repeat(32)), None);
    assert_eq!(
        fetch::tag(&[0x3f, 0xa2, 0xc1, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        "3FA2-C1D0"
    );
}

#[test]
fn a_lost_key_pick_names_this_devices_keys_once() {
    let choices = vec![
        vault::GateChoice {
            number: 1,
            date: *b"20261101",
            credhash: [1; 16],
        },
        vault::GateChoice {
            number: 3,
            date: *b"20261102",
            credhash: [3; 16],
        },
    ];
    use crate::jni_keys::pick_of;
    assert_eq!(pick_of(&choices, &[3]).unwrap(), vec![[3; 16]]);
    assert_eq!(pick_of(&choices, &[1, 3]).unwrap(), vec![[1; 16], [3; 16]]);
    assert!(pick_of(&choices, &[]).is_err());
    assert!(pick_of(&choices, &[2]).is_err());
    assert!(pick_of(&choices, &[1, 1]).is_err());
}
