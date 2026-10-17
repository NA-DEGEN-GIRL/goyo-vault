//! RFC 6238 / Google Authenticator: SHA-1, 6 digits, 30 seconds.
use crate::crypto::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "시스템 시간을 확인하세요.")?
        .as_secs())
}
pub fn code(secret: &[u8], step: u64, digits: u32) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&step.to_be_bytes());
    let mut hash = mac.finalize().into_bytes();
    let i = (hash[19] & 15) as usize;
    let result =
        (u32::from_be_bytes(hash[i..i + 4].try_into().unwrap()) & 0x7fff_ffff) % 10u32.pow(digits);
    hash.as_mut_slice().zeroize();
    result
}
pub fn verify(secret: &[u8], input: &str, time: u64, last: Option<u64>) -> Result<u64> {
    if input.len() != 6 || !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err("OTP는 숫자 6자리입니다.");
    }
    let step = time / 30;
    let mut found = None;
    for candidate in [step.saturating_sub(1), step, step.saturating_add(1)] {
        let expected = Zeroizing::new(format!("{:06}", code(secret, candidate, 6)));
        if bool::from(expected.as_bytes().ct_eq(input.as_bytes()))
            && last.is_none_or(|v| candidate > v)
        {
            found = Some(candidate);
        }
    }
    found.ok_or(
        "OTP가 틀렸거나 이미 사용되었습니다. 휴대폰·PC 시간을 확인하고 새 번호를 입력하세요.",
    )
}
pub fn base32(bytes: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_vectors() {
        for (time, want) in [
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            assert_eq!(code(b"12345678901234567890", time / 30, 8), want);
        }
    }
    #[test]
    fn replay_and_format() {
        let s = b"12345678901234567890";
        assert_eq!(verify(s, "287082", 59, None).unwrap(), 1);
        assert!(verify(s, "287082", 59, Some(1)).is_err());
        assert!(verify(s, " 87082", 59, None).is_err());
        assert!(verify(s, "287082", 159, None).is_err());
        assert_eq!(&*base32(b"foobar"), "MZXW6YTBOI");
    }
}
