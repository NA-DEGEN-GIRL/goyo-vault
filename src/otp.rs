//! An entry's TOTP secret (RFC 6238): the secret and its parameters as a
//! site's "secret key" or `otpauth://totp/…` URI gives them, the code of
//! the moment, and the URI an authenticator app scans as a QR code.
//!
//! An entry stores it as one canonical blob (`Otp::encode`), sealed with
//! the entry like its other fields (docs/FORMAT.md, "OTP 시크릿").
use crate::crypto::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// The longest secret, in bytes (a 512-bit key; 103 Base32 characters).
pub const MAX_SECRET: usize = 64;
/// The longest issuer or account name, in UTF-8 bytes.
pub const MAX_LABEL: usize = 64;
/// The longest period, in seconds.
pub const MAX_PERIOD: u32 = 3600;
/// The largest blob `Otp::encode` writes: the header, the three lengths and
/// their longest values.
pub const MAX_BLOB: usize = 6 + 12 + MAX_SECRET + 2 * MAX_LABEL;
/// The longest text the editor's OTP field takes: a whole URI whose labels
/// are percent-encoded twice over (label and `issuer=`), with room to spare.
pub const MAX_INPUT: usize = 2048;

/// The HMAC of the code. SHA-1 unless the URI names another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}
impl Algorithm {
    fn byte(self) -> u8 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
            Self::Sha512 => 3,
        }
    }
    fn of_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            3 => Some(Self::Sha512),
            _ => None,
        }
    }
    /// The URI's `algorithm=` value.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// One entry's TOTP secret and how its codes are made. Every copy of the
/// secret and the labels is zeroized when dropped.
#[derive(Clone)]
pub struct Otp {
    pub secret: Zeroizing<Vec<u8>>,
    pub issuer: Zeroizing<String>,
    pub account: Zeroizing<String>,
    pub algorithm: Algorithm,
    /// 6, 7 or 8.
    pub digits: u8,
    /// Seconds, 1 to MAX_PERIOD.
    pub period: u32,
}
impl PartialEq for Otp {
    fn eq(&self, o: &Self) -> bool {
        *self.encode() == *o.encode()
    }
}
impl std::fmt::Debug for Otp {
    /// Never prints the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Otp")
            .field("issuer", &self.issuer.as_str())
            .field("account", &self.account.as_str())
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

const NOT_BASE32: &str =
    "OTP 시크릿은 Base32 문자(A-Z, 2-7)이거나 otpauth://totp/ 주소여야 합니다.";
const BAD_URI: &str =
    "otpauth 주소를 읽을 수 없습니다. 사이트가 보여 준 주소나 시크릿 키를 그대로 붙여넣으세요.";
const NOT_TOTP: &str = "시간 기반 OTP(otpauth://totp/)만 지원합니다.";
const BAD_PARAMS: &str =
    "OTP 설정이 지원 범위 밖입니다(알고리즘 SHA1/SHA256/SHA512, 6~8자리, 주기 1~3600초).";
const TOO_LONG: &str = "OTP 시크릿이나 발급자·계정 이름이 너무 깁니다.";
const BAD_LABEL: &str = "발급자·계정 이름에는 ':'나 제어 문자를 쓸 수 없습니다.";

impl Otp {
    /// A secret with the defaults: SHA-1, 6 digits, 30 seconds.
    pub fn new(secret: Vec<u8>, issuer: &str, account: &str) -> Result<Self> {
        let otp = Self {
            secret: Zeroizing::new(secret),
            issuer: Zeroizing::new(issuer.trim().to_owned()),
            account: Zeroizing::new(account.trim().to_owned()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        otp.validate()?;
        Ok(otp)
    }
    /// What the editor's field holds: empty (no OTP, None), a Base32 secret
    /// (spaces, dashes, `=` padding and lowercase are fine) or a whole
    /// `otpauth://totp/…` URI with its labels and parameters.
    pub fn parse(input: &str) -> Result<Option<Self>> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(None);
        }
        if input.len() > MAX_INPUT {
            return Err(TOO_LONG);
        }
        let otp = if is_uri(input) {
            parse_uri(input)?
        } else {
            Self::new(base32_decode(input)?.to_vec(), "", "")?
        };
        Ok(Some(otp))
    }
    fn validate(&self) -> Result<()> {
        if self.secret.is_empty() {
            return Err(NOT_BASE32);
        }
        if self.secret.len() > MAX_SECRET
            || self.issuer.len() > MAX_LABEL
            || self.account.len() > MAX_LABEL
        {
            return Err(TOO_LONG);
        }
        if !(6..=8).contains(&self.digits) || !(1..=MAX_PERIOD).contains(&self.period) {
            return Err(BAD_PARAMS);
        }
        let bad = |s: &str| s.chars().any(|c| c == ':' || c.is_control());
        if bad(&self.issuer) || bad(&self.account) || self.issuer.trim() != *self.issuer {
            return Err(BAD_LABEL);
        }
        if self.account.trim() != *self.account {
            return Err(BAD_LABEL);
        }
        Ok(())
    }
    /// Whether the code is made the usual way (SHA-1, 6 digits, 30 s).
    pub fn is_default(&self) -> bool {
        self.algorithm == Algorithm::Sha1 && self.digits == 6 && self.period == 30
    }
    /// The blob an entry stores (docs/FORMAT.md): algorithm (1 SHA-1,
    /// 2 SHA-256, 3 SHA-512) · digits · period:u32 · then the secret, the
    /// issuer and the account, each as len:u32 · bytes. Little endian.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            18 + self.secret.len() + self.issuer.len() + self.account.len(),
        ));
        out.push(self.algorithm.byte());
        out.push(self.digits);
        out.extend_from_slice(&self.period.to_le_bytes());
        for part in [
            &self.secret[..],
            self.issuer.as_bytes(),
            self.account.as_bytes(),
        ] {
            out.extend_from_slice(&(part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }
    /// The blob back, only in the exact form `encode` writes: anything else
    /// (a trailing byte, a value out of range) is refused.
    pub fn decode(blob: &[u8]) -> Result<Self> {
        let mut r = Bytes(blob);
        let head = r.take(6)?;
        let algorithm = Algorithm::of_byte(head[0]).ok_or(BAD_PARAMS)?;
        let digits = head[1];
        let period = u32::from_le_bytes(head[2..6].try_into().unwrap());
        let secret = Zeroizing::new(r.part(MAX_SECRET)?.to_vec());
        let issuer = r.text()?;
        let account = r.text()?;
        if !r.0.is_empty() {
            return Err(BAD_PARAMS);
        }
        let otp = Self {
            secret,
            issuer,
            account,
            algorithm,
            digits,
            period,
        };
        otp.validate()?;
        Ok(otp)
    }
    /// The code at Unix time `time` (RFC 6238 over RFC 4226), zero-padded
    /// to `digits`.
    pub fn code(&self, time: u64) -> Zeroizing<String> {
        let counter = (time / self.period as u64).to_be_bytes();
        let mut hash: Zeroizing<Vec<u8>> = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => mac::<Hmac<Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => mac::<Hmac<Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => mac::<Hmac<Sha512>>(&self.secret, &counter),
        });
        let i = (hash[hash.len() - 1] & 15) as usize;
        let mut value = u32::from_be_bytes(hash[i..i + 4].try_into().unwrap()) & 0x7fff_ffff;
        hash.zeroize();
        let mut code = value % 10u32.pow(self.digits as u32);
        value.zeroize();
        let out = Zeroizing::new(format!("{code:0width$}", width = self.digits as usize));
        code.zeroize();
        out
    }
    /// Seconds until the code at `time` changes: 1 to `period`.
    pub fn remaining(&self, time: u64) -> u64 {
        self.period as u64 - time % self.period as u64
    }
    /// The secret in Base32 without padding, as authenticator apps take it.
    pub fn secret_base32(&self) -> Zeroizing<String> {
        base32(&self.secret)
    }
    /// The secret in Base32 in groups of four, for reading it out.
    pub fn secret_grouped(&self) -> Zeroizing<String> {
        let plain = self.secret_base32();
        let mut out = Zeroizing::new(String::with_capacity(plain.len() * 5 / 4 + 1));
        for (i, c) in plain.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }
    /// What the editor's field shows for this secret: the Base32 secret, or,
    /// when the code is not made the usual way, a URI without labels (the
    /// editor keeps those in their own fields).
    pub fn editor_text(&self) -> Zeroizing<String> {
        if self.is_default() {
            return self.secret_base32();
        }
        let mut out = Zeroizing::new(String::from("otpauth://totp/?secret="));
        out.push_str(&self.secret_base32());
        self.push_params(&mut out);
        out
    }
    fn push_params(&self, out: &mut String) {
        if self.algorithm != Algorithm::Sha1 {
            out.push_str("&algorithm=");
            out.push_str(self.algorithm.name());
        }
        if self.digits != 6 {
            out.push_str(&format!("&digits={}", self.digits));
        }
        if self.period != 30 {
            out.push_str(&format!("&period={}", self.period));
        }
    }
    /// The key URI an authenticator app scans (Google Authenticator's Key
    /// Uri Format): `otpauth://totp/<issuer>:<account>?secret=…&issuer=…`,
    /// then `algorithm`, `digits` and `period` when they are not the
    /// defaults. An empty account is `title`, the entry's name, so the app
    /// has a name to show.
    pub fn uri(&self, title: &str) -> Zeroizing<String> {
        let account = if self.account.is_empty() {
            title.trim()
        } else {
            self.account.as_str()
        };
        let mut out = Zeroizing::new(String::from("otpauth://totp/"));
        if !self.issuer.is_empty() {
            percent(&mut out, &self.issuer);
            out.push(':');
        }
        percent(&mut out, account);
        out.push_str("?secret=");
        out.push_str(&self.secret_base32());
        if !self.issuer.is_empty() {
            out.push_str("&issuer=");
            percent(&mut out, &self.issuer);
        }
        self.push_params(&mut out);
        out
    }
}

/// A blob being read (see Otp::decode).
struct Bytes<'a>(&'a [u8]);
impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(BAD_PARAMS);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    /// len:u32 · bytes, at most `limit` bytes.
    fn part(&mut self, limit: usize) -> Result<&'a [u8]> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if n > limit {
            return Err(TOO_LONG);
        }
        self.take(n)
    }
    fn text(&mut self) -> Result<Zeroizing<String>> {
        let b = self.part(MAX_LABEL)?;
        let s = std::str::from_utf8(b).map_err(|_| BAD_LABEL)?;
        Ok(Zeroizing::new(s.to_owned()))
    }
}

/// HMAC of `msg` under `key`, as a plain byte vector for the caller to wipe.
fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key size");
    m.update(msg);
    let mut hash = m.finalize().into_bytes();
    let out = hash.to_vec();
    hash.as_mut_slice().zeroize();
    out
}

/// Whether `s` starts like an otpauth URI (any case).
pub fn is_uri(s: &str) -> bool {
    s.trim_start()
        .get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
}

fn parse_uri(input: &str) -> Result<Otp> {
    let rest = &input[10..];
    let (kind, rest) = rest.split_once('/').ok_or(BAD_URI)?;
    if kind.eq_ignore_ascii_case("hotp") {
        return Err(NOT_TOTP);
    }
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(BAD_URI);
    }
    let rest = rest.split_once('#').map_or(rest, |(a, _)| a);
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = unpercent(label, false)?;
    // "Issuer:account", the colon literal or %3A, spaces allowed after it.
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim(), a.trim()),
        None => ("", label.trim()),
    };
    let (mut secret, mut issuer) = (None, None);
    let (mut algorithm, mut digits, mut period) = (Algorithm::Sha1, 6u8, 30u32);
    let mut seen = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = key.to_ascii_lowercase();
        if seen.contains(&key) {
            return Err(BAD_URI);
        }
        seen.push(key.clone());
        let value = unpercent(value, true)?;
        match key.as_str() {
            "secret" => secret = Some(base32_decode(&value)?),
            "issuer" => issuer = Some(value),
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(BAD_PARAMS),
                }
            }
            "digits" => digits = value.trim().parse().map_err(|_| BAD_PARAMS)?,
            "period" => period = value.trim().parse().map_err(|_| BAD_PARAMS)?,
            // `image`, `counter` and the like say nothing about the code.
            _ => {}
        }
    }
    let secret = secret.ok_or(BAD_URI)?;
    // The `issuer` parameter wins over the label's prefix, as the format
    // recommends.
    let issuer = issuer.as_ref().map_or(label_issuer, |i| i.trim());
    let otp = Otp {
        secret: Zeroizing::new(secret.to_vec()),
        issuer: Zeroizing::new(issuer.to_owned()),
        account: Zeroizing::new(account.to_owned()),
        algorithm,
        digits,
        period,
    };
    otp.validate()?;
    Ok(otp)
}

/// Percent-decodes `s` to UTF-8; in a query value `+` is a space too.
fn unpercent(s: &str, query: bool) -> Result<Zeroizing<String>> {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3).ok_or(BAD_URI)?;
                let hex = std::str::from_utf8(hex).map_err(|_| BAD_URI)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| BAD_URI)?);
                i += 3;
            }
            b'+' if query => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    let text = std::str::from_utf8(&out).map_err(|_| BAD_URI)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Percent-encodes `s` onto `out`: RFC 3986's unreserved characters stay,
/// every other byte is %XX.
fn percent(out: &mut String, s: &str) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
}

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 Base32 without padding.
pub fn base32(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity((bytes.len() * 8).div_ceil(5)));
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    acc.zeroize();
    out
}

/// Base32 as sites show it: any case, spaces and dashes between groups,
/// `=` padding at the end. Bits left over after the last whole byte are
/// dropped, as authenticator apps do.
pub fn base32_decode(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let s = s.trim_end_matches(|c: char| c == '=' || c.is_whitespace());
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        if !c.is_ascii() {
            acc.zeroize();
            return Err(NOT_BASE32);
        }
        let c = c.to_ascii_uppercase() as u8;
        let Some(v) = ALPHABET.iter().position(|&a| a == c) else {
            acc.zeroize();
            return Err(NOT_BASE32);
        };
        let v = v as u32;
        acc = ((acc << 5) | v) & 0xFFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        if out.len() > MAX_SECRET {
            acc.zeroize();
            return Err(TOO_LONG);
        }
    }
    acc.zeroize();
    if out.is_empty() {
        return Err(NOT_BASE32);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(secret: &[u8], algorithm: Algorithm, digits: u8) -> Otp {
        Otp {
            secret: Zeroizing::new(secret.to_vec()),
            issuer: Zeroizing::new(String::new()),
            account: Zeroizing::new(String::new()),
            algorithm,
            digits,
            period: 30,
        }
    }

    /// RFC 6238 Appendix B: the three seeds (the ASCII digits repeated to
    /// 20, 32 and 64 bytes), 8 digits, 30 s.
    #[test]
    fn rfc6238_appendix_b() {
        let seed = |n: usize| b"1234567890".repeat(7)[..n].to_vec();
        let table: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        let sha1 = with(&seed(20), Algorithm::Sha1, 8);
        let sha256 = with(&seed(32), Algorithm::Sha256, 8);
        let sha512 = with(&seed(64), Algorithm::Sha512, 8);
        for (time, a, b, c) in table {
            assert_eq!(*sha1.code(time), a, "SHA1 {time}");
            assert_eq!(*sha256.code(time), b, "SHA256 {time}");
            assert_eq!(*sha512.code(time), c, "SHA512 {time}");
        }
        // Six digits are the last six; zero-padding is kept.
        let six = with(&seed(20), Algorithm::Sha1, 6);
        assert_eq!(*six.code(59), "287082");
        assert_eq!(*six.code(1111111109), "081804");
        let seven = with(&seed(20), Algorithm::Sha1, 7);
        assert_eq!(*seven.code(1111111109), "7081804");
        // The countdown and another period.
        assert_eq!(six.remaining(59), 1);
        assert_eq!(six.remaining(60), 30);
        let mut minute = six.clone();
        minute.period = 60;
        assert_eq!(minute.remaining(61), 59);
        assert_eq!(*minute.code(59), *six.code(0));
    }

    #[test]
    fn base32_both_ways() {
        // RFC 4648 §10.
        for (plain, coded) in [
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(*base32(plain.as_bytes()), coded);
            assert_eq!(&**base32_decode(coded).unwrap(), plain.as_bytes());
        }
        // As sites show it: lowercase, groups, padding.
        let want = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        for shown in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "jbsw-y3dp-ehpk-3pxp",
            "JBSWY3DPEHPK3PXP====",
            "  JBSWY3DP EHPK3PXP\t",
        ] {
            assert_eq!(*base32_decode(shown).unwrap(), *want, "{shown}");
        }
        assert_eq!(&**want, b"Hello!\xde\xad\xbe\xef");
        for bad in [
            "", "   ", "====", "JBSW1", "JBSW8", "JBSWÜ", "JBSWŁ", "otp:",
        ] {
            assert!(base32_decode(bad).is_err(), "{bad}");
        }
        assert!(base32_decode(&"A".repeat(103)).is_ok());
        assert_eq!(base32_decode(&"A".repeat(110)).err(), Some(TOO_LONG));
    }

    #[test]
    fn the_field_takes_a_secret_or_a_uri() {
        assert!(Otp::parse("").unwrap().is_none());
        assert!(Otp::parse(" \t ").unwrap().is_none());
        let plain = Otp::parse("jbsw y3dp ehpk 3pxp").unwrap().unwrap();
        assert!(plain.is_default());
        assert_eq!((plain.issuer.as_str(), plain.account.as_str()), ("", ""));
        assert_eq!(*plain.secret_base32(), "JBSWY3DPEHPK3PXP");
        assert_eq!(*plain.secret_grouped(), "JBSW Y3DP EHPK 3PXP");
        // Google's example, and every parameter.
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let g = Otp::parse(uri).unwrap().unwrap();
        assert_eq!(
            (g.issuer.as_str(), g.account.as_str()),
            ("Example", "alice@google.com")
        );
        assert!(g.is_default());
        let full = Otp::parse(
            "OTPAUTH://TOTP/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60&image=x",
        )
        .unwrap()
        .unwrap();
        assert_eq!(full.issuer.as_str(), "ACME Co");
        assert_eq!(full.account.as_str(), "john.doe@email.com");
        assert_eq!(
            (full.algorithm, full.digits, full.period),
            (Algorithm::Sha256, 8, 60)
        );
        // The issuer parameter wins over the label; %3A and spaces after
        // the colon; `+` is a space in a query value; Korean labels.
        let ko = Otp::parse(
            "otpauth://totp/%EC%9D%80%ED%96%89%3A%20%ED%99%8D%EA%B8%B8%EB%8F%99?secret=jbswy3dpehpk3pxp&issuer=%EA%B3%A0%EC%9A%94+%EC%9D%80%ED%96%89",
        )
        .unwrap()
        .unwrap();
        assert_eq!(ko.issuer.as_str(), "고요 은행");
        assert_eq!(ko.account.as_str(), "홍길동");
        // A label without an issuer, and none at all.
        let bare = Otp::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
            .unwrap()
            .unwrap();
        assert_eq!((bare.issuer.as_str(), bare.account.as_str()), ("", "alice"));
        let none = Otp::parse("otpauth://totp/?secret=JBSWY3DPEHPK3PXP&digits=7")
            .unwrap()
            .unwrap();
        assert_eq!((none.account.as_str(), none.digits), ("", 7));
        // Refusals, each with its reason.
        for (bad, why) in [
            (
                "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
                NOT_TOTP,
            ),
            ("otpauth://totp/x?issuer=a", BAD_URI),
            ("otpauth://totp/x?secret=JBSW&secret=JBSW", BAD_URI),
            ("otpauth://totp/x?secret=JBSWY3DP%", BAD_URI),
            ("otpauth://totp/x%FF?secret=JBSWY3DP", BAD_URI),
            ("otpauth://totpx?secret=JBSWY3DP", BAD_URI),
            ("otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5", BAD_PARAMS),
            ("otpauth://totp/x?secret=JBSWY3DP&digits=5", BAD_PARAMS),
            ("otpauth://totp/x?secret=JBSWY3DP&digits=9", BAD_PARAMS),
            ("otpauth://totp/x?secret=JBSWY3DP&period=0", BAD_PARAMS),
            ("otpauth://totp/x?secret=JBSWY3DP&period=3601", BAD_PARAMS),
            ("otpauth://totp/x?secret=1234", NOT_BASE32),
            ("otpauth://totp/a:b:c?secret=JBSWY3DP", BAD_LABEL),
            ("otpauth://totp/a%0Ab?secret=JBSWY3DP", BAD_LABEL),
            ("123456", NOT_BASE32),
        ] {
            assert_eq!(Otp::parse(bad).err(), Some(why), "{bad}");
        }
        let long = format!("otpauth://totp/{}?secret=JBSWY3DP", "a".repeat(65));
        assert_eq!(Otp::parse(&long).err(), Some(TOO_LONG));
        assert_eq!(Otp::parse(&"A".repeat(MAX_INPUT + 1)).err(), Some(TOO_LONG));
        assert!(Otp::new(vec![1], "a:b", "").is_err());
        assert!(Otp::new(vec![], "", "").is_err());
    }

    #[test]
    fn the_uri_names_issuer_account_and_only_changed_parameters() {
        let mut o = Otp::new(
            b"Hello!\xde\xad\xbe\xef".to_vec(),
            "Example",
            "alice@google.com",
        )
        .unwrap();
        assert_eq!(
            *o.uri("ignored"),
            "otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        );
        o.issuer = Zeroizing::new("고요 은행".into());
        o.account = Zeroizing::new(String::new());
        o.algorithm = Algorithm::Sha512;
        o.digits = 8;
        o.period = 60;
        let uri = o.uri(" My entry ");
        assert_eq!(
            *uri,
            "otpauth://totp/%EA%B3%A0%EC%9A%94%20%EC%9D%80%ED%96%89:My%20entry?secret=JBSWY3DPEHPK3PXP&issuer=%EA%B3%A0%EC%9A%94%20%EC%9D%80%ED%96%89&algorithm=SHA512&digits=8&period=60"
        );
        // It reads back as itself, with the title as the account.
        let back = Otp::parse(&uri).unwrap().unwrap();
        assert_eq!(back.account.as_str(), "My entry");
        assert_eq!(
            (back.algorithm, back.digits, back.period),
            (Algorithm::Sha512, 8, 60)
        );
        assert_eq!(*back.secret, *o.secret);
        // No issuer: no prefix and no parameter.
        let plain = Otp::new(b"Hello!\xde\xad\xbe\xef".to_vec(), "", "bob").unwrap();
        assert_eq!(
            *plain.uri("x"),
            "otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP"
        );
        // The editor's text: the secret, or a label-less URI.
        assert_eq!(*plain.editor_text(), "JBSWY3DPEHPK3PXP");
        assert_eq!(
            *o.editor_text(),
            "otpauth://totp/?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60"
        );
        let again = Otp::parse(&o.editor_text()).unwrap().unwrap();
        assert_eq!(
            (again.algorithm, again.digits, again.period),
            (Algorithm::Sha512, 8, 60)
        );
    }

    #[test]
    fn the_blob_is_canonical() {
        let o = Otp::parse(
            "otpauth://totp/ACME:jo?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap()
        .unwrap();
        let blob = o.encode();
        assert_eq!(&blob[..6], &[2, 8, 60, 0, 0, 0]);
        assert_eq!(&blob[6..10], &20u32.to_le_bytes());
        assert_eq!(blob.len(), 6 + 4 + 20 + 4 + 4 + 4 + 2);
        let back = Otp::decode(&blob).unwrap();
        assert_eq!(back, o);
        assert_eq!(*back.encode(), *blob);
        // A byte more or less, or any field out of range, is refused.
        assert!(Otp::decode(&blob[..blob.len() - 1]).is_err());
        let mut longer = blob.to_vec();
        longer.push(0);
        assert!(Otp::decode(&longer).is_err());
        for (at, value) in [(0, 0), (0, 4), (1, 5), (1, 9), (2, 0)] {
            let mut bad = blob.to_vec();
            bad[at] = value;
            assert!(Otp::decode(&bad).is_err(), "{at} {value}");
        }
        let mut empty = blob.to_vec();
        empty.splice(6..30, 0u32.to_le_bytes());
        assert!(Otp::decode(&empty).is_err());
        let mut colon = blob.to_vec();
        let n = colon.len();
        colon[n - 1] = b':';
        assert!(Otp::decode(&colon).is_err());
        assert!(
            MAX_BLOB
                >= Otp::new(vec![7; MAX_SECRET], &"i".repeat(64), &"a".repeat(64))
                    .unwrap()
                    .encode()
                    .len()
        );
        // Debug never shows the secret.
        assert!(!format!("{o:?}").contains("HXDM"));
    }
}
