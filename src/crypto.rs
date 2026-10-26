//! RustCrypto primitives. No OS cryptography, OS RNG, clock-seeded PRNG or network.
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use hmac::{Hmac, Mac, digest::FixedOutput};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub type Result<T> = std::result::Result<T, &'static str>;
pub type Key = Zeroizing<[u8; 32]>;
pub const KDF_MEMORY_KIB: u32 = 262_144;
pub const KDF_PASSES: u32 = 3;
pub const AUTH_ERROR: &str =
    "인증 실패: 비밀번호·열쇠·새 OTP·시스템 시간과 파일 상태를 확인하세요.";

/// Argon2 settings for `derive`. Only builds with debug assertions (the
/// tests) can pick the cheap ones; a release build has the constants alone.
#[cfg(debug_assertions)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KdfProfile {
    /// KDF_MEMORY_KIB and KDF_PASSES, as in a release build.
    Real,
    /// 64 KiB and one pass, for tests that derive many keys.
    Test,
}
/// Marks the test KDF hook: package_release.py refuses an exe holding it.
#[cfg(debug_assertions)]
const TEST_KDF_MARKER: &str = "goyo-test-kdf";
#[cfg(debug_assertions)]
thread_local! {
    static KDF_PROFILE: std::cell::Cell<KdfProfile> =
        const { std::cell::Cell::new(KdfProfile::Real) };
    /// Calls of `derive` on this thread (the "derive counter" of the tests).
    static DERIVES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
/// Sets this thread's KDF profile; returns the one it replaces.
#[cfg(debug_assertions)]
pub fn set_kdf_profile(profile: KdfProfile) -> KdfProfile {
    KDF_PROFILE.with(|p| p.replace(profile))
}
/// How often `derive` ran on this thread.
#[cfg(debug_assertions)]
pub fn derive_count() -> u64 {
    DERIVES.with(std::cell::Cell::get)
}
/// The Argon2id memory (KiB) and passes `derive` uses on this thread.
pub fn kdf_params() -> (u32, u32) {
    #[cfg(debug_assertions)]
    if KDF_PROFILE.with(std::cell::Cell::get) == KdfProfile::Test {
        std::hint::black_box(TEST_KDF_MARKER);
        return (64, 1);
    }
    (KDF_MEMORY_KIB, KDF_PASSES)
}

pub fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0; N]);
    random_into(out.as_mut_slice())?;
    Ok(out)
}
/// Fills `out` in place. Long-lived secrets use this so the bytes are never
/// moved through a return value, which leaves unwiped copies on the stack.
pub fn random_into(out: &mut [u8]) -> Result<()> {
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
    Ok(())
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
    #[cfg(debug_assertions)]
    DERIVES.with(|n| n.set(n.get() + 1));
    let (memory, passes) = kdf_params();
    let params = Params::new(memory, passes, 1, Some(32)).map_err(|_| "KDF 설정 오류")?;
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

fn hmac(key: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key size")
}
/// HKDF-SHA256 extract (RFC 5869 §2.2): HMAC under `salt` over the parts of
/// `ikm` in order. The result is written straight into its heap buffer.
pub fn hkdf_extract(salt: &[u8], ikm: &[&[u8]]) -> Box<Zeroizing<[u8; 32]>> {
    let mut mac = hmac(salt);
    for part in ikm {
        mac.update(part);
    }
    let mut prk = Box::new(Zeroizing::new([0u8; 32]));
    mac.finalize_into(prk.as_mut_slice().into());
    prk
}
/// HKDF-SHA256 expand (RFC 5869 §2.3) of `prk` with the parts of `info` in
/// order, filling `out` (at most 255 blocks). Every block is wiped.
pub fn hkdf_expand(prk: &[u8; 32], info: &[&[u8]], out: &mut [u8]) {
    assert!(out.len() <= 255 * 32, "HKDF output too long");
    let mut block = Zeroizing::new([0u8; 32]);
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut mac = hmac(prk);
        if i > 0 {
            mac.update(block.as_slice());
        }
        for part in info {
            mac.update(part);
        }
        mac.update(&[i as u8 + 1]);
        mac.finalize_into(block.as_mut_slice().into());
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}
/// Equal contents, compared in constant time; the lengths are public.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
/// RFC 5869 test cases 1-3 and the constructions of the vault formats
/// (labels, input order, lengths), pinned from an independent Python
/// implementation that uses hashlib and hmac only. No Argon2, so it is
/// fast; `--self-check` runs it too.
pub fn self_test() -> Result<()> {
    const FAILED: &str = "암호 자체 시험(HKDF)에 실패했습니다.";
    fn expand<const N: usize>(prk: &[u8; 32], info: &[&[u8]]) -> [u8; N] {
        let mut out = [0; N];
        hkdf_expand(prk, info, &mut out);
        out
    }
    fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut m = hmac(key);
        for part in parts {
            m.update(part);
        }
        m.finalize_fixed().into()
    }
    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().into()
    }
    let mut ok = true;
    let mut check = |got: &[u8], want: &str| {
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        ok &= ct_eq(hex.as_bytes(), want.as_bytes());
    };
    let range = |from: u8, to: u16| (from as u16..to).map(|b| b as u8).collect::<Vec<u8>>();
    // RFC 5869 A.1-A.3: (IKM, salt, info, PRK, OKM).
    let cases = [
        (
            vec![0x0b; 22],
            range(0x00, 0x0d),
            range(0xf0, 0xfa),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            range(0x00, 0x50),
            range(0x60, 0xb0),
            range(0xb0, 0x100),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            vec![0x0b; 22],
            vec![],
            vec![],
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ];
    for (ikm, salt, info, prk, okm) in &cases {
        // The parts of a split input count as one string.
        let (a, b) = ikm.split_at(ikm.len() / 2);
        let key = hkdf_extract(salt, &[a, b]);
        check(key.as_slice(), prk);
        let mut out = vec![0; okm.len() / 2];
        let (a, b) = info.split_at(info.len() / 3);
        hkdf_expand(&key, &[a, b], &mut out);
        check(&out, okm);
    }
    // The constructions, on fixed synthetic inputs.
    let id: [u8; 16] = std::array::from_fn(|i| i as u8);
    let other_id: [u8; 16] = std::array::from_fn(|i| 0xf0 + i as u8);
    let s: [u8; 32] = std::array::from_fn(|i| 0x20 + i as u8);
    let dk: [u8; 32] = std::array::from_fn(|i| 0x40 + i as u8);
    let pw_key: [u8; 32] = std::array::from_fn(|i| 0x60 + i as u8);
    let cred = range(0x80, 0xb0);
    let header = sha256(&[b"goyo self-test: file[0..B)"]);
    let ks_id = |s: &[u8; 32], id: &[u8; 16]| {
        expand::<16>(&hkdf_extract(b"goyo-vault/v2/ks-id", &[s]), &[id])
    };
    check(&ks_id(&s, &id), "c4681032763f8363886cff15a4aa5db9");
    check(&ks_id(&[0; 32], &id), "00e05758b26ba1020e4917c0f09cde46");
    check(
        &ks_id(&[0; 32], &other_id),
        "05dbbff54e112a43163cfd3043607e99",
    );
    let key_id = expand::<16>(&hkdf_extract(b"goyo-vault/v2/key-id", &[&dk]), &[&id]);
    check(&key_id, "e8a35551018cd7f203358a34f4d4ce11");
    let credhash = sha256(&[b"goyo-vault/v2/cred\0", &cred]);
    check(&credhash[..16], "eae7075189d482632efecaea800c1751");
    let body = hkdf_extract(b"goyo-vault/v2/body", &[&pw_key, &s]);
    check(
        &expand::<32>(&body, &[b"key\0", &header]),
        "3eb7c4357aa110ac681e1efef18258f9cd2031b79711286ec7275f0abc1186f1",
    );
    check(
        &expand::<32>(&body, &[b"commit\0", &header]),
        "342931f2dcdfa681c7436d171865dea78fc1add85afb8d9f0377bfd0a83ec978",
    );
    // Without keys the keyset part is all zero.
    let body = hkdf_extract(b"goyo-vault/v2/body", &[&pw_key, &[0; 32]]);
    check(
        &expand::<32>(&body, &[b"key\0", &header]),
        "ff41d4f12b5014376f124f6d622e89365fc91dab5dd86b876bc5e1acf3178668",
    );
    let chain_key = expand::<32>(&hkdf_extract(b"goyo-vault/v2/chain", &[&dk]), &[&id]);
    check(
        &chain_key,
        "b9a4178f5b6a65f8da8031b2410bd6d87bdc47f807524b6ad50510de4408b016",
    );
    let body_end = sha256(&[b"goyo self-test: file[0..E)"]);
    check(
        &mac(&chain_key, &[b"goyo-vault/v2/chain-msg\0", &body_end]),
        "de51f3d425d54f72473348c64778f35d8467aad6c443209865d7dd2e62b78ae1",
    );
    let written = sha256(&[b"goyo self-test: file[0..W)"]);
    let tag = sha256(&[b"goyo-vault/v2/state\0", &written]);
    check(&tag[..16], "3d2aa8812e6c57811402bce76d161dcd");
    let legacy = sha256(&[
        b"goyo-vault/v2/state-legacy\0",
        b"GOYOKE01",
        &id,
        &[1],
        &key_id,
    ]);
    check(&legacy[..16], "6587b8d02709169936da046237e83509");
    let code_key = expand::<32>(&hkdf_extract(b"goyo-vault/v2/key-code", &[&dk]), &[&id]);
    let code = mac(
        &code_key,
        &[b"goyo key state\0", &7u64.to_le_bytes(), &tag[..16]],
    );
    check(&code[..8], "cd8acfb3a5e496f0");
    if ok { Ok(()) } else { Err(FAILED) }
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
        set_kdf_profile(KdfProfile::Real);
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
    #[test]
    fn hkdf_and_construction_vectors() {
        self_test().unwrap();
        // Shorter outputs are prefixes of longer ones, and split inputs
        // count as their concatenation.
        let prk = hkdf_extract(b"salt", &[b"input key"]);
        assert_eq!(*prk, *hkdf_extract(b"salt", &[b"input", b" ", b"key"]));
        assert_ne!(*prk, *hkdf_extract(b"other salt", &[b"input key"]));
        let mut long = [0; 100];
        hkdf_expand(&prk, &[b"info"], &mut long);
        let mut short = [0; 16];
        hkdf_expand(&prk, &[b"in", b"fo"], &mut short);
        assert_eq!(short, long[..16]);
        let mut other = [0; 16];
        hkdf_expand(&prk, &[b"inf"], &mut other);
        assert_ne!(short, other);
        // The longest output RFC 5869 allows.
        let mut most = vec![0; 255 * 32];
        hkdf_expand(&prk, &[], &mut most);
        assert!(most[255 * 32 - 32..].iter().any(|b| *b != 0));
    }
    #[test]
    #[should_panic(expected = "HKDF output too long")]
    fn hkdf_expand_refuses_more_than_255_blocks() {
        hkdf_expand(&[1; 32], &[], &mut vec![0; 255 * 32 + 1]);
    }
    #[test]
    fn constant_time_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"same bytes", b"same bytes"));
        assert!(!ct_eq(b"same bytes", b"same bytez"));
        assert!(!ct_eq(b"Same bytes", b"same bytes"));
        // Lengths are public: a prefix is not equal.
        assert!(!ct_eq(b"same", b"same bytes"));
        assert!(!ct_eq(b"", b"x"));
    }
    #[test]
    fn test_kdf_profile_is_cheap_and_counted() {
        let start = derive_count();
        assert_eq!(kdf_params(), (KDF_MEMORY_KIB, KDF_PASSES));
        assert_eq!(set_kdf_profile(KdfProfile::Test), KdfProfile::Real);
        assert_eq!(kdf_params(), (64, 1));
        let salt = [7; 32];
        let cheap = derive(b"synthetic password", &salt).unwrap();
        assert_eq!(*cheap, *derive(b"synthetic password", &salt).unwrap());
        assert_eq!(derive_count(), start + 2);
        // Another thread keeps the real settings and its own count.
        std::thread::spawn(|| {
            assert_eq!(kdf_params(), (KDF_MEMORY_KIB, KDF_PASSES));
            assert_eq!(derive_count(), 0);
        })
        .join()
        .unwrap();
        assert_eq!(set_kdf_profile(KdfProfile::Real), KdfProfile::Test);
        let real = derive(b"synthetic password", &salt).unwrap();
        assert_ne!(*cheap, *real);
        assert_eq!(derive_count(), start + 3);
    }
}
