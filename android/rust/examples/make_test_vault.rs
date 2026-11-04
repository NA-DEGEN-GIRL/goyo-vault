//! Writes a password-only TEST vault for the app's instrumented test
//! (app/src/androidTest): `vault.goyo` and `vault.goyokey` with a synthetic
//! password and two synthetic entries, in the folder given (default
//! ../app/build/testVault). Run on the PC from android/rust:
//!
//!     cargo run --release --example make_test_vault
//!
//! The PC's own anchor (%LOCALAPPDATA%\GoyoVault) is never touched: this
//! program's anchor lives in `<folder>/anchor`. Nothing here is a real
//! secret; the files are git-ignored build output.
use goyo_vault::vault::{self, Entry, Provision};
use std::path::PathBuf;

/// Also in VaultTest.kt.
const PASSWORD: &str = "android stage one test password";

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../app/build/testVault"));
    std::fs::create_dir_all(&dir).expect("folder");
    let dir = dir.canonicalize().expect("folder");
    vault::set_anchor_root(&dir.join("anchor")).expect("anchor root");
    let (v, k) = (dir.join("vault.goyo"), dir.join("vault.goyokey"));
    for f in [&v, &k] {
        let _ = std::fs::remove_file(f);
    }
    let p = Provision::new().expect("rng");
    let mut s = p.finish(&v, &k, PASSWORD).expect("create");
    for (title, kind, secret, notes) in [
        ("테스트 항목 1", "웹", "synthetic-secret-1", "메모 1"),
        ("Test entry 2", "", "synthetic-secret-2", ""),
    ] {
        let e = Entry::new(title.into(), kind.into(), secret.into(), notes.into()).expect("entry");
        s.put(None, e).expect("put");
    }
    drop(s);
    println!("{} {}", p.tag(), dir.display());
}
