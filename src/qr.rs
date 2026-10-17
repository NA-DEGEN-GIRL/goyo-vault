//! Minimal QR Code encoder for the OTP enrollment URI: byte mode, version 6
//! (41x41), error correction level M. Written in-house so every buffer that
//! holds the TOTP secret (codewords, ECC, module matrix) is zeroized; the
//! layout follows ISO/IEC 18004 and is cross-checked against an independent
//! implementation in the tests.
use crate::crypto::Result;
use zeroize::Zeroizing;

const VERSION: usize = 6;
pub const SIZE: usize = VERSION * 4 + 17;
const BLOCKS: usize = 4;
const DATA_PER_BLOCK: usize = 27;
const ECC_PER_BLOCK: usize = 16;
/// Byte-mode capacity of 6-M.
pub const CAPACITY: usize = 106;
const ALIGNMENT: [usize; 2] = [6, 34];

pub struct Qr {
    /// Row-major; 1 = dark.
    modules: Zeroizing<Vec<u8>>,
    function: Vec<bool>,
}
impl Qr {
    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * SIZE + x] != 0
    }
    fn set(&mut self, x: usize, y: usize, dark: bool) {
        self.modules[y * SIZE + x] = dark.into();
    }
    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        self.set(x, y, dark);
        self.function[y * SIZE + x] = true;
    }
}

/// Encodes `data` with the mask that has the lowest penalty score.
pub fn encode(data: &[u8]) -> Result<Qr> {
    let codewords = codewords(data)?;
    let mut best: Option<(i32, Qr)> = None;
    for mask in 0..8 {
        let qr = build(&codewords, mask);
        let score = penalty(&qr);
        if best.as_ref().is_none_or(|(s, _)| score < *s) {
            best = Some((score, qr));
        }
    }
    Ok(best.expect("eight masks").1)
}

#[cfg(test)]
fn encode_with_mask(data: &[u8], mask: u8) -> Qr {
    build(&codewords(data).unwrap(), mask)
}

/// Data plus error correction codewords, interleaved by block.
fn codewords(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() > CAPACITY {
        return Err("QR 데이터가 너무 깁니다.");
    }
    let capacity = BLOCKS * DATA_PER_BLOCK;
    let mut bits = Zeroizing::new(Vec::with_capacity(capacity * 8));
    fn push(bits: &mut Vec<u8>, value: usize, count: usize) {
        for i in (0..count).rev() {
            bits.push(((value >> i) & 1) as u8);
        }
    }
    push(&mut bits, 0b0100, 4); // byte mode
    push(&mut bits, data.len(), 8); // character count, versions 1 to 9
    for &b in data {
        push(&mut bits, b as usize, 8);
    }
    let terminator = (capacity * 8 - bits.len()).min(4);
    push(&mut bits, 0, terminator);
    let align = (8 - bits.len() % 8) % 8;
    push(&mut bits, 0, align);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    for chunk in bits.chunks(8) {
        bytes.push(chunk.iter().fold(0u8, |acc, b| (acc << 1) | b));
    }
    for pad in [0xec, 0x11].into_iter().cycle() {
        if bytes.len() == capacity {
            break;
        }
        bytes.push(pad);
    }
    let divisor = rs_divisor(ECC_PER_BLOCK);
    let mut ecc = Zeroizing::new(Vec::with_capacity(BLOCKS * ECC_PER_BLOCK));
    for block in bytes.chunks(DATA_PER_BLOCK) {
        ecc.extend_from_slice(&rs_remainder(block, &divisor));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(
        BLOCKS * (DATA_PER_BLOCK + ECC_PER_BLOCK),
    ));
    for i in 0..DATA_PER_BLOCK {
        for b in 0..BLOCKS {
            out.push(bytes[b * DATA_PER_BLOCK + i]);
        }
    }
    for i in 0..ECC_PER_BLOCK {
        for b in 0..BLOCKS {
            out.push(ecc[b * ECC_PER_BLOCK + i]);
        }
    }
    Ok(out)
}

fn build(codewords: &[u8], mask: u8) -> Qr {
    let mut qr = Qr {
        modules: Zeroizing::new(vec![0; SIZE * SIZE]),
        function: vec![false; SIZE * SIZE],
    };
    // Timing patterns, then finders and alignment over them.
    for i in 0..SIZE {
        qr.set_function(6, i, i % 2 == 0);
        qr.set_function(i, 6, i % 2 == 0);
    }
    for (cx, cy) in [(3, 3), (SIZE - 4, 3), (3, SIZE - 4)] {
        for dy in -4i32..=4 {
            for dx in -4i32..=4 {
                let (x, y) = (cx as i32 + dx, cy as i32 + dy);
                if (0..SIZE as i32).contains(&x) && (0..SIZE as i32).contains(&y) {
                    let d = dx.abs().max(dy.abs());
                    qr.set_function(x as usize, y as usize, d != 2 && d != 4);
                }
            }
        }
    }
    for &cy in &ALIGNMENT {
        for &cx in &ALIGNMENT {
            let corner = (cx == 6 && cy == 6) || (cx == 6 && cy == 34) || (cx == 34 && cy == 6);
            if corner {
                continue;
            }
            for dy in -2i32..=2 {
                for dx in -2i32..=2 {
                    let d = dx.abs().max(dy.abs());
                    let (x, y) = ((cx as i32 + dx) as usize, (cy as i32 + dy) as usize);
                    qr.set_function(x, y, d != 1);
                }
            }
        }
    }
    draw_format(&mut qr, mask); // reserves the format areas and the dark module

    // Zigzag placement from the bottom-right, two columns at a time.
    let mut i = 0;
    let mut right = SIZE as i32 - 1;
    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for vert in 0..SIZE {
            for j in 0..2 {
                let x = (right - j) as usize;
                let upward = (right + 1) & 2 == 0;
                let y = if upward { SIZE - 1 - vert } else { vert };
                if !qr.function[y * SIZE + x] && i < codewords.len() * 8 {
                    qr.set(x, y, (codewords[i >> 3] >> (7 - (i & 7))) & 1 != 0);
                    i += 1;
                }
            }
        }
        right -= 2;
    }
    // Remainder bits stay light.
    for y in 0..SIZE {
        for x in 0..SIZE {
            if !qr.function[y * SIZE + x] && masked(mask, x, y) {
                qr.modules[y * SIZE + x] ^= 1;
            }
        }
    }
    qr
}

#[allow(clippy::manual_is_multiple_of)] // Formulas as written in ISO/IEC 18004.
fn masked(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (x / 3 + y / 2) % 2 == 0,
        5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3) % 2 == 0,
        _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
    }
}

/// Format information: level M (00) and mask, BCH(15,5), XOR 0x5412.
fn draw_format(qr: &mut Qr, mask: u8) {
    let data = mask as u32; // level M is 0b00
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    let bits = ((data << 10) | rem) ^ 0x5412;
    let bit = |i: usize| (bits >> i) & 1 != 0;
    for i in 0..6 {
        qr.set_function(8, i, bit(i));
    }
    qr.set_function(8, 7, bit(6));
    qr.set_function(8, 8, bit(7));
    qr.set_function(7, 8, bit(8));
    for i in 9..15 {
        qr.set_function(14 - i, 8, bit(i));
    }
    for i in 0..8 {
        qr.set_function(SIZE - 1 - i, 8, bit(i));
    }
    for i in 8..15 {
        qr.set_function(8, SIZE - 15 + i, bit(i));
    }
    qr.set_function(8, SIZE - 8, true);
}

fn rs_multiply(x: u8, y: u8) -> u8 {
    let mut z = 0u8;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * 0x1d);
        z ^= ((y >> i) & 1) * x;
    }
    z
}
fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut result = vec![0u8; degree];
    result[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            result[j] = rs_multiply(result[j], root);
            if j + 1 < degree {
                result[j] ^= result[j + 1];
            }
        }
        root = rs_multiply(root, 0x02);
    }
    result
}
fn rs_remainder(data: &[u8], divisor: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut result = Zeroizing::new(vec![0u8; divisor.len()]);
    for &b in data {
        let factor = b ^ result[0];
        result.rotate_left(1);
        let last = result.len() - 1;
        result[last] = 0;
        for (r, &d) in result.iter_mut().zip(divisor) {
            *r ^= rs_multiply(d, factor);
        }
    }
    result
}

/// ISO/IEC 18004 mask penalty (N1 = 3, N2 = 3, N3 = 40, N4 = 10).
fn penalty(qr: &Qr) -> i32 {
    let mut score = 0;
    for transpose in [false, true] {
        for a in 0..SIZE {
            let module = |b: usize| {
                if transpose {
                    qr.dark(a, b)
                } else {
                    qr.dark(b, a)
                }
            };
            let (mut color, mut run) = (false, 0i32);
            let mut history = Finder::default();
            for b in 0..SIZE {
                if module(b) == color {
                    run += 1;
                    if run == 5 {
                        score += 3;
                    } else if run > 5 {
                        score += 1;
                    }
                } else {
                    history.add(run);
                    if !color {
                        score += history.count() * 40;
                    }
                    color = module(b);
                    run = 1;
                }
            }
            score += history.finish(color, run) * 40;
        }
    }
    for y in 0..SIZE - 1 {
        for x in 0..SIZE - 1 {
            let c = qr.dark(x, y);
            if c == qr.dark(x + 1, y) && c == qr.dark(x, y + 1) && c == qr.dark(x + 1, y + 1) {
                score += 3;
            }
        }
    }
    let dark = qr.modules.iter().map(|&m| m as i32).sum::<i32>();
    let total = (SIZE * SIZE) as i32;
    let k = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
    score + k * 10
}
/// Run-length history for the finder-like 1:1:3:1:1 pattern rule.
#[derive(Default)]
struct Finder([i32; 7]);
impl Finder {
    fn add(&mut self, mut run: i32) {
        if self.0[0] == 0 {
            run += SIZE as i32; // light border before the first run
        }
        self.0.copy_within(0..6, 1);
        self.0[0] = run;
    }
    fn count(&self) -> i32 {
        let h = &self.0;
        let n = h[1];
        let core = n > 0 && h[2] == n && h[3] == n * 3 && h[4] == n && h[5] == n;
        i32::from(core && h[0] >= n * 4 && h[6] >= n)
            + i32::from(core && h[6] >= n * 4 && h[0] >= n)
    }
    fn finish(mut self, color: bool, mut run: i32) -> i32 {
        if color {
            self.add(run);
            run = 0;
        }
        self.add(run + SIZE as i32); // light border after the last run
        self.count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const URI: &[u8] =
        b"otpauth://totp/Goyo%20Vault?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Goyo%20Vault";

    fn digest(qr: &Qr) -> String {
        let rows: Vec<u8> = (0..SIZE)
            .flat_map(|y| (0..SIZE).map(move |x| (x, y)))
            .map(|(x, y)| if qr.dark(x, y) { b'1' } else { b'0' })
            .collect();
        Sha256::digest(&rows)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn matches_independent_encoder() {
        // SHA-256 of the 41x41 module rows ('1' dark) produced by python-qrcode 8.2:
        // QRCode(version=6, error_correction=M, border=0, mask_pattern=m), 8-bit byte mode.
        // segno 1.6.6 agrees on function patterns, format and data but inserts one
        // extra 0x00 before the pad codewords; ISO/IEC 18004 pads directly after an
        // aligned terminator, as python-qrcode and this encoder do.
        let expected = [
            "4c3db405bacbfa7dfcae6e995b4a0f82de0a46855b2b572d67193323ae030692",
            "ae8d4686830aa09d8958a38a0289d1b3948ec52bd770b311431fa38e1682da93",
            "fcd45211b5d2790b580e59846b310b261abc7f0263113657c5cdf5f484466f63",
            "ad003c999479b31af4c7b9a6c33a8e5f35c100a158ad667d0bdee84813065bff",
            "f52784ac999c301dc959e99d40c17241dd60ecf69af35a886f96b0891288a1c1",
            "5de935706affd0931429de4fe0cf4fd8e89250963837613c63c5da6c871196f6",
            "dd726990751819d8aba0b81067760e7a5220b9e6c1b12a4648fe80dcb2f8d7d1",
            "566e5db531df7fb3d49479e0c3d6ddb99fcc10500555f6583f4d52fef899efa4",
        ];
        for (mask, want) in expected.iter().enumerate() {
            assert_eq!(
                digest(&encode_with_mask(URI, mask as u8)),
                *want,
                "mask {mask}"
            );
        }
        // Libraries weigh the penalty rules differently; any of the eight is valid.
        assert!(expected.contains(&digest(&encode(URI).unwrap()).as_str()));
    }

    #[test]
    fn capacity_and_structure() {
        assert_eq!(URI.len(), 87);
        assert!(codewords(&[b'a'; CAPACITY]).is_ok());
        assert!(codewords(&[b'a'; CAPACITY + 1]).is_err());
        let qr = encode(URI).unwrap();
        // Finder corners and the fixed dark module.
        assert!(qr.dark(0, 0) && qr.dark(SIZE - 1, 0) && qr.dark(0, SIZE - 1));
        assert!(!qr.dark(7, 7) && qr.dark(8, SIZE - 8));
        assert!(qr.dark(34, 34) && !qr.dark(33, 34)); // alignment centre and ring
    }
}
