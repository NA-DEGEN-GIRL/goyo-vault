//! RustCrypto primitives. No OS cryptography, OS RNG, clock-seeded PRNG or network.
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub type Result<T> = std::result::Result<T, &'static str>;
pub type Key = Zeroizing<[u8; 32]>;
pub const KDF_MEMORY_KIB: u32 = 262_144;
pub const KDF_PASSES: u32 = 3;
pub const AUTH_ERROR: &str =
    "인증 실패: 비밀번호·열쇠·새 OTP·시스템 시간과 파일 상태를 확인하세요.";

pub fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0; N]);
    for chunk in out.chunks_mut(64) {
        // Collect 1024 raw hardware bits per conditioned 512-bit block. This
        // does not create entropy: CPU/microcode and the machine remain trusted.
        let mut raw = Zeroizing::new([0u8; 128]);
        let mut previous = None;
        for part in raw.as_chunks_mut::<8>().0 {
            let mut value = rdseed()?;
            if value == 0 || value == u64::MAX || previous == Some(value) {
                value.zeroize();
                return Err("CPU 난수 검사가 실패했습니다. 작업을 중단했습니다.");
            }
            previous = Some(value);
            part.copy_from_slice(&value.to_le_bytes());
            value.zeroize();
        }
        let mut digest = Sha512::digest(raw.as_slice());
        chunk.copy_from_slice(&digest[..chunk.len()]);
        digest.as_mut_slice().zeroize();
        previous.zeroize();
    }
    Ok(out)
}

#[cfg(target_arch = "x86_64")]
fn rdseed() -> Result<u64> {
    if !std::is_x86_feature_detected!("rdseed") {
        return Err("RDSEED를 지원하는 x64 CPU가 필요합니다. 약한 난수로 대체하지 않습니다.");
    }
    for _ in 0..2048 {
        let mut value = 0;
        // SAFETY: CPUID checked above; intrinsic writes only the supplied u64.
        if unsafe { std::arch::x86_64::_rdseed64_step(&mut value) } == 1 {
            return Ok(value);
        }
        std::hint::spin_loop();
    }
    Err("CPU 난수 공급을 사용할 수 없습니다. 잠시 후 다시 시도하세요.")
}
#[cfg(not(target_arch = "x86_64"))]
fn rdseed() -> Result<u64> {
    Err("x64 CPU만 지원합니다.")
}

pub fn derive(password: &[u8], salt: &[u8; 32]) -> Result<Key> {
    let params =
        Params::new(KDF_MEMORY_KIB, KDF_PASSES, 1, Some(32)).map_err(|_| "KDF 설정 오류")?;
    let blocks = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Zeroizing::new(vec![Block::default(); blocks]);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into_with_memory(password, salt, key.as_mut(), memory.as_mut_slice())
        .map_err(|_| "비밀번호 키 생성 실패")?;
    Ok(key)
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    // Allocate final capacity before copying plaintext, to avoid reallocating secrets.
    let mut buf = Zeroizing::new(Vec::with_capacity(plain.len() + 16));
    buf.extend_from_slice(plain);
    cipher
        .encrypt_in_place(XNonce::from_slice(nonce), aad, &mut *buf)
        .map_err(|_| "암호화 실패")?;
    Ok(std::mem::take(&mut *buf))
}

pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(XNonce::from_slice(nonce), aad, &mut *buf)
        .map_err(|_| AUTH_ERROR)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn independent_implementation_vectors() {
        // Cross-checked with Python cryptography Argon2id and libsodium/PyNaCl.
        let salt = std::array::from_fn(|i| i as u8);
        let key = derive(b"Goyo compatibility test password", &salt).unwrap();
        assert_eq!(
            key.as_slice(),
            hex("c6924d3354b21dcfcdba9a1bfb1a903f46c11f9a6a12e13634818a65d9c6c772")
        );
        let nonce = std::array::from_fn(|i| i as u8);
        let result = seal(
            &salt,
            &nonce,
            b"GOYOVA01 fixture",
            b"Goyo fixed interoperability test",
        )
        .unwrap();
        assert_eq!(
            result,
            hex(
                "d9ad7610b0b4e4d6562006a7a526cd9a24374dd79cb47487166e469649c8862d7e8408d638ce9acb22e5d911d30700fc"
            )
        );
    }
    #[test]
    fn authentication_and_tampering() {
        let c = seal(&[7; 32], &[2; 24], b"header", b"private secret").unwrap();
        assert_eq!(
            &**open(&[7; 32], &[2; 24], b"header", &c).unwrap(),
            b"private secret"
        );
        assert!(open(&[8; 32], &[2; 24], b"header", &c).is_err());
        assert!(open(&[7; 32], &[2; 24], b"tamper", &c).is_err());
        for i in 0..c.len() {
            let mut bad = c.clone();
            bad[i] ^= 1;
            assert!(open(&[7; 32], &[2; 24], b"header", &bad).is_err());
        }
    }
    #[test]
    fn hardware_entropy_available() {
        assert_ne!(*random::<32>().unwrap(), *random::<32>().unwrap());
    }
}
