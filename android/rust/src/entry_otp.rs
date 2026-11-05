//! An entry's OTP secret (0.12.0) as the app sees it: its names, the code
//! of the moment and the seconds it has left, all made here. The secret
//! itself leaves Rust only for the two things the user asks for by name:
//! "시크릿 복사" (its Base32 text) and "QR 보기" (the modules of the QR code
//! of its otpauth URI, made by the lib's own encoder). The editor's text
//! (a Base32 key or a whole otpauth URI) is parsed here too.
use goyo_vault::{otp::Otp, qr, vault::Entry};
use zeroize::Zeroizing;

pub const NO_OTP: &str = "이 항목에는 OTP 시크릿이 없습니다.";

/// What the entry view shows besides the code: the issuer, the account
/// and how the code is made when that is not the usual SHA-1, 6 digits,
/// 30 seconds (else empty). None for an entry without an OTP secret.
pub fn info(e: &Entry) -> Option<[String; 3]> {
    let o = e.otp()?;
    let params = if o.is_default() {
        String::new()
    } else {
        format!("{} · {}자리 · {}초", o.algorithm.name(), o.digits, o.period)
    };
    Some([o.issuer.to_string(), o.account.to_string(), params])
}

/// The code at Unix time `now` and the seconds until it changes.
pub fn code(e: &Entry, now: u64) -> Result<(Zeroizing<String>, u64), &'static str> {
    let o = e.otp().ok_or(NO_OTP)?;
    Ok((o.code(now), o.remaining(now)))
}

/// The secret in Base32 without padding, as authenticator apps take it.
pub fn secret(e: &Entry) -> Result<Zeroizing<String>, &'static str> {
    Ok(e.otp().ok_or(NO_OTP)?.secret_base32())
}

/// The QR code of the entry's otpauth URI (`Otp::uri`; an empty account
/// is the entry's title): the side in modules as u16 big-endian, then one
/// byte per module, row-major, 1 dark. No quiet zone.
pub fn qr_modules(e: &Entry) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let o = e.otp().ok_or(NO_OTP)?;
    let uri = o.uri(&e.title);
    let code = qr::encode(uri.as_bytes())?;
    let n = code.size;
    let mut out = Zeroizing::new(Vec::with_capacity(2 + n * n));
    out.extend_from_slice(&(n as u16).to_be_bytes());
    for y in 0..n {
        for x in 0..n {
            out.push(u8::from(code.dark(x, y)));
        }
    }
    Ok(out)
}

/// The 비밀정보 the entry view and the editor get: none for an OTP entry
/// (0.12.1), whose secret field holds the marker or 0.12.0's dummy.
pub fn shown_secret(e: &Entry) -> &str {
    e.shown_secret()
}

/// The entry the editor saves. `otp_field` is what the user typed in the
/// OTP field: a Base32 key or an otpauth URI replaces the secret; empty
/// keeps the edited entry's secret (`old`), or drops it when `remove`.
/// The secret kept is never sent to the editor. The OTP kind needs an OTP
/// secret (typed or kept) and stores the marker for 비밀정보 (the lib's
/// `Entry::new_with_otp`).
pub fn edited(
    old: Option<&Entry>,
    fields: [String; 4],
    otp_field: &str,
    remove: bool,
) -> Result<Entry, &'static str> {
    let otp = match Otp::parse(otp_field)? {
        Some(o) => Some(o),
        None if remove => None,
        None => match old {
            Some(e) if e.has_otp() => Some(e.otp().ok_or(NO_OTP)?),
            _ => None,
        },
    };
    let [title, kind, secret, notes] = fields;
    Entry::new_with_otp(title, kind, secret, notes, otp.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's SHA-1 key ("12345678901234567890").
    const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn entry(otp: &str) -> Entry {
        edited(None, fields("Bank"), otp, false).unwrap()
    }
    fn fields(title: &str) -> [String; 4] {
        [title.into(), "web".into(), "pw".into(), String::new()]
    }

    #[test]
    fn the_code_and_its_seconds_come_from_rust() {
        let e = entry(RFC_KEY);
        // RFC 6238 appendix B, SHA-1, 8 digits at T = 59 is 94287082: the
        // usual 6 digits are its last six.
        assert_eq!(
            code(&e, 59).map(|(c, l)| (c.to_string(), l)),
            Ok(("287082".into(), 1))
        );
        assert_eq!(code(&e, 60).unwrap().1, 30);
        let uri = format!("otpauth://totp/x?secret={RFC_KEY}&digits=8");
        assert_eq!(code(&entry(&uri), 59).unwrap().0.as_str(), "94287082");
        let none = edited(None, fields("Mail"), "", false).unwrap();
        assert_eq!(code(&none, 59).err(), Some(NO_OTP));
        assert_eq!(secret(&none).err(), Some(NO_OTP));
        assert!(qr_modules(&none).is_err());
        assert_eq!(info(&none), None);
    }

    #[test]
    fn info_names_the_issuer_account_and_unusual_settings() {
        let e = entry("otpauth://totp/Bank:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Bank");
        assert_eq!(
            info(&e),
            Some(["Bank".into(), "me@example.com".into(), String::new()])
        );
        let e =
            entry("otpauth://totp/?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60");
        assert_eq!(
            info(&e),
            Some([String::new(), String::new(), "SHA256 · 8자리 · 60초".into()])
        );
        assert_eq!(secret(&e).unwrap().as_str(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn the_editor_keeps_replaces_or_removes_the_secret() {
        let old = entry("otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=Bank");
        // Empty field: the old secret stays, names and all.
        let kept = edited(Some(&old), fields("Bank 2"), "  ", false).unwrap();
        assert_eq!(kept.otp(), old.otp());
        assert_eq!(&*kept.title, "Bank 2");
        // Remove.
        let gone = edited(Some(&old), fields("Bank"), "", true).unwrap();
        assert!(!gone.has_otp());
        // A typed key replaces it (even with remove set).
        let new = edited(Some(&old), fields("Bank"), "jbsw y3dp ehpk 3pxq", true).unwrap();
        assert_eq!(secret(&new).unwrap().as_str(), "JBSWY3DPEHPK3PXQ");
        // A new entry with an empty field has none.
        assert!(!edited(None, fields("x"), "", false).unwrap().has_otp());
        // The lib's refusals come through as they are.
        assert!(edited(None, fields("x"), "not base32!", false).is_err());
        assert!(
            edited(
                None,
                fields("x"),
                "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
                false
            )
            .is_err()
        );
    }

    /// The OTP kind (0.12.1) through the editor's call: the OTP secret is
    /// needed (typed, or kept by an empty field when the entry has one),
    /// the 비밀정보 sent is dropped for the marker, and the view and the
    /// editor never get an OTP entry's secret field.
    #[test]
    fn the_otp_kind_needs_the_otp_secret_and_keeps_no_secret() {
        use goyo_vault::vault::{OTP_MARKER, OTP_REQUIRED};
        let otp_fields = |title: &str, secret: &str| -> [String; 4] {
            [title.into(), "OTP".into(), secret.into(), "memo".into()]
        };
        // A new OTP entry: no OTP secret, refused, whatever 비밀정보 says.
        for secret in ["", "typed"] {
            let refused = edited(None, otp_fields("Bank", secret), "", false);
            assert_eq!(refused.err(), Some(OTP_REQUIRED));
        }
        let e = edited(None, otp_fields("Bank", "typed"), RFC_KEY, false).unwrap();
        assert_eq!(&*e.secret, OTP_MARKER);
        assert!(e.is_otp_entry() && shown_secret(&e).is_empty());
        assert_eq!(secret(&e).unwrap().as_str(), RFC_KEY);
        // Edited with the field left empty: its OTP secret stays.
        let kept = edited(Some(&e), otp_fields("Bank 2", ""), "", false).unwrap();
        assert_eq!(kept.otp(), e.otp());
        assert_eq!(&*kept.secret, OTP_MARKER);
        // Removing it would leave an OTP entry without one.
        let removed = edited(Some(&e), otp_fields("Bank", ""), "", true);
        assert_eq!(removed.err(), Some(OTP_REQUIRED));
        // Another kind needs 비밀정보 again, and keeps the OTP secret.
        let mut back = fields("Bank");
        back[2] = String::new();
        assert!(edited(Some(&e), back.clone(), "", false).is_err());
        back[2] = "pw".into();
        let back = edited(Some(&e), back, "", false).unwrap();
        assert!(!back.is_otp_entry() && shown_secret(&back) == "pw");
        assert_eq!(back.otp(), e.otp());
        // A 0.12.0 entry typed "OTP" with a dummy: never shown, and saving
        // puts the marker in its place.
        let mut legacy = edited(None, fields("Mail"), RFC_KEY, false).unwrap();
        legacy.kind = zeroize::Zeroizing::new("OTP".into());
        assert!(legacy.is_otp_entry() && shown_secret(&legacy).is_empty());
        let saved = edited(Some(&legacy), otp_fields("Mail", ""), "", false).unwrap();
        assert_eq!(&*saved.secret, OTP_MARKER);
        assert_eq!(saved.otp(), legacy.otp());
        // An ordinary entry shows its 비밀정보 as before.
        assert_eq!(shown_secret(&entry(RFC_KEY)), "pw");
    }

    #[test]
    fn the_qr_modules_read_back_as_the_libs_symbol() {
        let e = entry("otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=Bank");
        let m = qr_modules(&e).unwrap();
        let n = u16::from_be_bytes([m[0], m[1]]) as usize;
        assert_eq!(m.len(), 2 + n * n);
        assert!(n >= 21 && (n - 17).is_multiple_of(4));
        let o = e.otp().unwrap();
        let want = qr::encode(o.uri(&e.title).as_bytes()).unwrap();
        assert_eq!(want.size, n);
        for y in 0..n {
            for x in 0..n {
                assert_eq!(m[2 + y * n + x], u8::from(want.dark(x, y)), "{x},{y}");
            }
        }
        // The finder pattern's dark corner and light separator.
        assert_eq!((m[2], m[2 + 7]), (1, 0));
        assert!(m[2..].iter().all(|&b| b <= 1));
    }
}
