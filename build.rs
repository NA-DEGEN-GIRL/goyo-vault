//! Embeds assets/goyo.ico as the executable icon (group icon ID 1).
//! Writes a compiled .res directly so no resource compiler or extra crate
//! is needed; MSVC link.exe accepts .res files as input.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=assets/goyo.ico");
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    let ico = fs::read("assets/goyo.ico").expect("assets/goyo.ico");
    let u16_at = |i: usize| u16::from_le_bytes([ico[i], ico[i + 1]]);
    let u32_at = |i: usize| u32::from_le_bytes(ico[i..i + 4].try_into().unwrap());
    assert!(u16_at(0) == 0 && u16_at(2) == 1, "not an .ico file");
    let count = u16_at(4) as usize;

    let mut res = Vec::new();
    // A .res file starts with an empty entry.
    entry(&mut res, 0, 0, &[]);
    let mut group = Vec::new();
    group.extend_from_slice(&[0, 0, 1, 0]);
    group.extend_from_slice(&(count as u16).to_le_bytes());
    for i in 0..count {
        let e = 6 + 16 * i;
        let (size, offset) = (u32_at(e + 8) as usize, u32_at(e + 12) as usize);
        let id = i as u16 + 1;
        entry(&mut res, 3, id, &ico[offset..offset + size]); // RT_ICON
        group.extend_from_slice(&ico[e..e + 12]); // size, colours, planes, bits, bytes
        group.extend_from_slice(&id.to_le_bytes());
    }
    entry(&mut res, 14, 1, &group); // RT_GROUP_ICON

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("goyo.res");
    fs::write(&out, res).unwrap();
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

/// RESOURCEHEADER with numeric type and name, then DWORD-aligned data.
fn entry(res: &mut Vec<u8>, kind: u16, name: u16, data: &[u8]) {
    res.extend_from_slice(&(data.len() as u32).to_le_bytes());
    res.extend_from_slice(&32u32.to_le_bytes());
    for ordinal in [kind, name] {
        res.extend_from_slice(&0xffffu16.to_le_bytes());
        res.extend_from_slice(&ordinal.to_le_bytes());
    }
    res.extend_from_slice(&0u32.to_le_bytes()); // data version
    let flags: u16 = if kind == 0 { 0 } else { 0x1010 };
    res.extend_from_slice(&flags.to_le_bytes());
    res.extend_from_slice(&0u16.to_le_bytes()); // language neutral
    res.extend_from_slice(&0u32.to_le_bytes()); // version
    res.extend_from_slice(&0u32.to_le_bytes()); // characteristics
    res.extend_from_slice(data);
    while !res.len().is_multiple_of(4) {
        res.push(0);
    }
}
