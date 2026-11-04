//! Registering a YubiKey on the phone (stage 4, spec §8.3): the lib's
//! `fido::Registration` states the MakeCredential request (fresh seed and
//! user ID, `goyo-<TAG>-<N>-<STAMP>` names, PIN required, credProtect 3
//! required, resident, the exclude list); Kotlin runs it on the YubiKey
//! with yubikit and hands back the authenticator data exactly as the key
//! returned it. Here the credential ID is read out of that data (never
//! taken from Kotlin), the extensions the key reports are held to
//! hmac-secret and credProtect 3 (what Windows' `bRequireCredProtect`
//! enforces on a PC), and `fido::check_credential` runs the core's own
//! checks (rpIdHash, UP, BE/BS, the transport). The check GetAssertion
//! that follows goes through the same `fido::check_assertion` as a login.
use goyo_vault::fido::{self, MakeRequest, RawCredential, Uv};

/// The MakeCredential request's wire format version (see `encode_make`).
pub const MAKE_VERSION: u8 = 1;

/// The request for Kotlin, big-endian:
/// version u8 | rp id length u8 | rp id | rp name length u8 | rp name |
/// user id [32] | name length u8 | name | display length u8 | display |
/// clientDataHash [32] | uv u8 (1 required) | credProtect u8 |
/// required u8 | exclude count u8 | per credential: length u16 | id.
pub fn encode_make(r: &MakeRequest) -> Result<Vec<u8>, &'static str> {
    use sha2::{Digest, Sha256};
    let short = |s: &str| u8::try_from(s.len()).map_err(|_| "요청이 너무 깁니다.");
    let mut out = vec![MAKE_VERSION];
    out.push(short(fido::RP_ID)?);
    out.extend_from_slice(fido::RP_ID.as_bytes());
    out.push(short(fido::RP_NAME)?);
    out.extend_from_slice(fido::RP_NAME.as_bytes());
    out.extend_from_slice(&r.user_id);
    out.push(short(&r.name)?);
    out.extend_from_slice(r.name.as_bytes());
    out.push(short(&r.display_name)?);
    out.extend_from_slice(r.display_name.as_bytes());
    out.extend_from_slice(&Sha256::digest(&r.client_data));
    out.push(u8::from(r.uv == Uv::Required));
    out.push(u8::try_from(r.cred_protect.0).map_err(|_| "credProtect")?);
    out.push(u8::from(r.cred_protect.1));
    out.push(u8::try_from(r.exclude.len()).map_err(|_| "보안 키가 너무 많습니다.")?);
    for id in &r.exclude {
        out.extend_from_slice(
            &u16::try_from(id.len())
                .map_err(|_| "자격 증명 ID가 너무 깁니다.")?
                .to_be_bytes(),
        );
        out.extend_from_slice(id);
    }
    Ok(out)
}

/// The authenticator data flag "extension data included".
const ED: u8 = 0x80;

/// MakeCredential's authenticator data as the key returned it, read into
/// the core's `RawCredential` (version 3: the transport is stated, USB or
/// NFC): the credential ID from the attested credential data, and the
/// extensions held to hmac-secret true and credProtect 3. Err with the
/// text for the user. The core's `check_credential` runs after this
/// (rpIdHash, UP, BE/BS, transport).
pub fn made(auth_data: &[u8], transport: u32) -> Result<RawCredential, &'static str> {
    let bad = fido::UNVERIFIABLE;
    if auth_data.len() < 37 + 18 {
        return Err(bad);
    }
    let flags = auth_data[32];
    if flags & fido::AT == 0 {
        return Err(bad);
    }
    let mut pos = 37 + 16; // rpIdHash, flags, signCount, AAGUID
    let len = usize::from(u16::from_be_bytes([auth_data[pos], auth_data[pos + 1]]));
    pos += 2;
    if !(1..=1023).contains(&len) || auth_data.len() < pos + len {
        return Err(bad);
    }
    let cred_id = auth_data[pos..pos + len].to_vec();
    pos += len;
    // The credential's public key (COSE), not used here: skipped.
    pos = cbor::skip(auth_data, pos, 0).ok_or(bad)?;
    if flags & ED == 0 {
        return Err(fido::NO_HMAC_SECRET);
    }
    let (ext, end) = cbor::extensions(auth_data, pos).ok_or(bad)?;
    if end != auth_data.len() {
        return Err(bad);
    }
    if !ext.hmac_secret {
        return Err(fido::NO_HMAC_SECRET);
    }
    if ext.cred_protect != Some(3) {
        return Err(fido::NO_CRED_PROTECT);
    }
    Ok(RawCredential {
        version: 3,
        cred_id,
        auth_data: auth_data.to_vec(),
        transport: Some(transport),
    })
}

/// The little CBOR (RFC 8949) this needs: skipping one item and reading
/// the extensions map of authenticator data. Definite lengths only (CTAP2
/// canonical CBOR has no other), nesting bounded.
pub mod cbor {
    const MAX_DEPTH: usize = 8;

    /// The head at `pos`: major type, argument, the position after it.
    fn head(b: &[u8], pos: usize) -> Option<(u8, u64, usize)> {
        let first = *b.get(pos)?;
        let (major, info) = (first >> 5, first & 0x1f);
        let (value, next) = match info {
            0..=23 => (u64::from(info), pos + 1),
            24 => (u64::from(*b.get(pos + 1)?), pos + 2),
            25 => (
                u64::from(u16::from_be_bytes(
                    b.get(pos + 1..pos + 3)?.try_into().ok()?,
                )),
                pos + 3,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    b.get(pos + 1..pos + 5)?.try_into().ok()?,
                )),
                pos + 5,
            ),
            27 => (
                u64::from_be_bytes(b.get(pos + 1..pos + 9)?.try_into().ok()?),
                pos + 9,
            ),
            _ => return None,
        };
        Some((major, value, next))
    }
    /// The position after the item at `pos`.
    pub fn skip(b: &[u8], pos: usize, depth: usize) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (major, value, next) = head(b, pos)?;
        match major {
            0 | 1 | 7 => Some(next),
            2 | 3 => {
                let end = next.checked_add(usize::try_from(value).ok()?)?;
                (end <= b.len()).then_some(end)
            }
            4 | 5 => {
                let n = usize::try_from(value)
                    .ok()?
                    .checked_mul(if major == 5 { 2 } else { 1 })?;
                if n > b.len() {
                    return None;
                }
                let mut p = next;
                for _ in 0..n {
                    p = skip(b, p, depth + 1)?;
                }
                Some(p)
            }
            6 => skip(b, next, depth + 1),
            _ => None,
        }
    }
    /// What a MakeCredential's extension outputs say.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Extensions {
        pub hmac_secret: bool,
        pub cred_protect: Option<u64>,
    }
    /// The extensions map at `pos` and the position after it. A key named
    /// twice, or a value of another type than CTAP2 gives, is refused.
    pub fn extensions(b: &[u8], pos: usize) -> Option<(Extensions, usize)> {
        let (major, n, mut p) = head(b, pos)?;
        if major != 5 || n > 32 {
            return None;
        }
        let mut out = Extensions::default();
        let mut seen: Vec<&[u8]> = Vec::new();
        for _ in 0..n {
            let (kmajor, klen, kstart) = head(b, p)?;
            if kmajor != 3 {
                return None;
            }
            let kend = kstart.checked_add(usize::try_from(klen).ok()?)?;
            let key = b.get(kstart..kend)?;
            if seen.contains(&key) {
                return None;
            }
            seen.push(key);
            match key {
                b"hmac-secret" => {
                    let (vmajor, v, next) = head(b, kend)?;
                    if vmajor != 7 || !(v == 20 || v == 21) {
                        return None;
                    }
                    out.hmac_secret = v == 21;
                    p = next;
                }
                b"credProtect" => {
                    let (vmajor, v, next) = head(b, kend)?;
                    if vmajor != 0 {
                        return None;
                    }
                    out.cred_protect = Some(v);
                    p = next;
                }
                _ => p = skip(b, kend, 1)?,
            }
        }
        Some((out, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goyo_vault::fido::{BE, UP, UV, rp_id_hash};

    /// A COSE ES256 key as YubiKeys send it (the coordinates are filler).
    fn cose() -> Vec<u8> {
        let mut k = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        k.extend_from_slice(&[0x11; 32]);
        k.extend_from_slice(&[0x22, 0x58, 0x20]);
        k.extend_from_slice(&[0x33; 32]);
        k
    }
    fn ext(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut m = vec![0xa0 | entries.len() as u8];
        for (k, v) in entries {
            m.push(0x60 | k.len() as u8);
            m.extend_from_slice(k.as_bytes());
            m.extend_from_slice(v);
        }
        m
    }
    fn auth_data(flags: u8, cred: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut a = rp_id_hash().to_vec();
        a.push(flags);
        a.extend_from_slice(&[0, 0, 0, 7]);
        a.extend_from_slice(&[0xaa; 16]);
        a.extend_from_slice(&(cred.len() as u16).to_be_bytes());
        a.extend_from_slice(cred);
        a.extend_from_slice(&cose());
        a.extend_from_slice(extensions);
        a
    }
    const TRUE: &[u8] = &[0xf5];
    const FALSE: &[u8] = &[0xf4];
    const THREE: &[u8] = &[0x03];

    #[test]
    fn a_yubikey_registration_reads_its_credential_and_extensions() {
        let cred = [0x42u8; 64];
        let good = ext(&[("credProtect", THREE), ("hmac-secret", TRUE)]);
        let a = auth_data(UP | UV | fido::AT | ED, &cred, &good);
        let raw = made(&a, fido::NFC).unwrap();
        assert_eq!(raw.cred_id, cred);
        assert_eq!(raw.auth_data, a);
        assert_eq!(raw.transport, Some(fido::NFC));
        assert_eq!(raw.version, 3);
        assert!(fido::check_credential(&raw).is_ok());
        // An unknown extension is skipped, in any order.
        let more = ext(&[
            ("hmac-secret", TRUE),
            ("credBlob", &[0x43, 1, 2, 3]),
            ("credProtect", THREE),
        ]);
        assert!(made(&auth_data(UP | fido::AT | ED, &cred, &more), fido::USB).is_ok());
    }

    #[test]
    fn a_registration_without_the_protections_is_refused() {
        let cred = [7u8; 16];
        let flags = UP | UV | fido::AT | ED;
        let cases: [(Vec<u8>, &str); 6] = [
            (ext(&[("credProtect", THREE)]), fido::NO_HMAC_SECRET),
            (
                ext(&[("credProtect", THREE), ("hmac-secret", FALSE)]),
                fido::NO_HMAC_SECRET,
            ),
            (ext(&[("hmac-secret", TRUE)]), fido::NO_CRED_PROTECT),
            (
                ext(&[("credProtect", &[0x02]), ("hmac-secret", TRUE)]),
                fido::NO_CRED_PROTECT,
            ),
            // A key named twice, a value of the wrong type.
            (
                ext(&[("hmac-secret", TRUE), ("hmac-secret", TRUE)]),
                fido::UNVERIFIABLE,
            ),
            (
                ext(&[
                    ("credProtect", &[0x63, b'a', b'b', b'c']),
                    ("hmac-secret", TRUE),
                ]),
                fido::UNVERIFIABLE,
            ),
        ];
        for (e, want) in cases {
            assert_eq!(
                made(&auth_data(flags, &cred, &e), fido::USB).err(),
                Some(want)
            );
        }
        let good = ext(&[("credProtect", THREE), ("hmac-secret", TRUE)]);
        // No extensions at all; no attested credential; trailing bytes.
        assert_eq!(
            made(&auth_data(UP | fido::AT, &cred, &[]), fido::USB).err(),
            Some(fido::NO_HMAC_SECRET)
        );
        assert!(made(&auth_data(UP | ED, &cred, &good), fido::USB).is_err());
        let mut long = auth_data(flags, &cred, &good);
        long.push(0);
        assert!(made(&long, fido::USB).is_err());
        // Cut anywhere: refused, never a panic.
        let a = auth_data(flags, &cred, &good);
        for n in 0..a.len() {
            assert!(made(&a[..n], fido::USB).is_err(), "{n}");
        }
        // The core's own checks follow: a synced passkey (BE) is refused there.
        let raw = made(&auth_data(flags | BE, &cred, &good), fido::USB).unwrap();
        assert!(fido::check_credential(&raw).is_err());
    }

    #[test]
    fn the_make_request_wire_holds_what_the_lib_asks() {
        let (_, make) = fido::Registration::new(
            &[0x3a; 16],
            2,
            1_790_000_000,
            vec![vec![9; 20], vec![8; 3]],
            0,
        )
        .unwrap();
        let w = encode_make(&make).unwrap();
        assert_eq!(w[0], MAKE_VERSION);
        let mut p = 1;
        let mut take = |n: usize| {
            let s = w[p..p + n].to_vec();
            p += n;
            s
        };
        let n = take(1)[0] as usize;
        assert_eq!(take(n), fido::RP_ID.as_bytes());
        let n = take(1)[0] as usize;
        assert_eq!(take(n), fido::RP_NAME.as_bytes());
        assert_eq!(take(32), make.user_id);
        let n = take(1)[0] as usize;
        assert_eq!(String::from_utf8(take(n)).unwrap(), make.name);
        assert!(make.name.starts_with("goyo-3A3A3A3A-2-"));
        let n = take(1)[0] as usize;
        assert_eq!(String::from_utf8(take(n)).unwrap(), make.display_name);
        use sha2::{Digest, Sha256};
        assert_eq!(take(32), Sha256::digest(&make.client_data).to_vec());
        assert_eq!(take(4), [1, 3, 1, 2]); // UV required, credProtect 3 required, 2 excluded
        assert_eq!(take(2), [0, 20]);
        assert_eq!(take(20), [9; 20]);
        assert_eq!(take(2), [0, 3]);
        assert_eq!(take(3), [8; 3]);
        assert_eq!(p, w.len());
    }

    #[test]
    fn cbor_skips_nested_items_and_refuses_cut_or_deep_ones() {
        let item = [0xa1, 0x61, b'k', 0x82, 0x01, 0xc1, 0x1a, 0, 0, 0, 1];
        assert_eq!(cbor::skip(&item, 0, 0), Some(item.len()));
        assert_eq!(cbor::skip(&item[..item.len() - 1], 0, 0), None);
        let deep = [0x81; 20];
        assert_eq!(cbor::skip(&deep, 0, 0), None);
        // Indefinite lengths are no CTAP2 canonical CBOR.
        assert_eq!(cbor::skip(&[0x9f, 0xff], 0, 0), None);
        // A length beyond the data.
        assert_eq!(cbor::skip(&[0x5a, 0xff, 0xff, 0xff, 0xff], 0, 0), None);
    }
}
