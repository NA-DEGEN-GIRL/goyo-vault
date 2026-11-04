//! QR Code encoder for an entry's `otpauth://` URI: byte mode, error
//! correction level M (L when that gives a smaller symbol from version 10
//! up), versions 1 to 40. Written in-house so every buffer that holds the
//! TOTP secret (bits, codewords, error correction, the module matrix) is
//! zeroized; the layout follows ISO/IEC 18004. The tests check it against
//! an independent encoder (version 6-M, as 0.8 did), against the
//! standard's capacity tables, format and version information, and by
//! reading every symbol back through its own structure.
use crate::crypto::Result;
use zeroize::Zeroizing;

/// The error correction level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    /// About 7 % of the codewords may be lost.
    L,
    /// About 15 %.
    M,
}
impl Level {
    /// The two format bits (ISO/IEC 18004 table 12).
    fn bits(self) -> u32 {
        match self {
            Self::L => 1,
            Self::M => 0,
        }
    }
    fn row(self) -> usize {
        match self {
            Self::L => 0,
            Self::M => 1,
        }
    }
}
/// Error correction codewords per block, by level and version.
const ECC_PER_BLOCK: [[u8; 41]; 2] = [
    [
        0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28,
        30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ],
];
/// Error correction blocks, by level and version.
const BLOCKS: [[u8; 41]; 2] = [
    [
        0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13,
        14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ],
    [
        0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21,
        23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ],
];
pub const MAX_VERSION: usize = 40;

/// A symbol: its modules, row-major, 1 = dark. No quiet zone; the caller
/// draws four light modules around it.
pub struct Qr {
    pub version: usize,
    pub level: Level,
    pub size: usize,
    modules: Zeroizing<Vec<u8>>,
    function: Vec<bool>,
}
impl Qr {
    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x] != 0
    }
    fn set(&mut self, x: usize, y: usize, dark: bool) {
        self.modules[y * self.size + x] = dark.into();
    }
    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        self.set(x, y, dark);
        self.function[y * self.size + x] = true;
    }
}

/// Modules of a version-`v` symbol that hold data and error correction
/// (everything but the function patterns and format and version areas).
fn raw_modules(v: usize) -> usize {
    let mut n = (16 * v + 128) * v + 64;
    if v >= 2 {
        let align = v / 7 + 2;
        n -= (25 * align - 10) * align - 55;
        if v >= 7 {
            n -= 36;
        }
    }
    n
}
/// Data codewords of version `v` at `level`.
fn data_codewords(v: usize, level: Level) -> usize {
    let l = level.row();
    raw_modules(v) / 8 - ECC_PER_BLOCK[l][v] as usize * BLOCKS[l][v] as usize
}
/// The bits of a byte-mode segment of `len` bytes in version `v`.
fn segment_bits(v: usize, len: usize) -> usize {
    4 + if v < 10 { 8 } else { 16 } + 8 * len
}
/// Bytes a byte-mode symbol of version `v` at `level` holds.
pub fn capacity(v: usize, level: Level) -> usize {
    (data_codewords(v, level) * 8 - segment_bits(v, 0)) / 8
}
/// The smallest version that holds `len` bytes at `level`.
fn version_for(len: usize, level: Level) -> Option<usize> {
    (1..=MAX_VERSION).find(|&v| capacity(v, level) >= len)
}
/// Level M in the smallest version that holds `data`; L instead when M
/// needs version 10 or more and L fits a smaller one, so a long URI stays
/// as coarse as it can for a phone camera.
fn choose(len: usize) -> Option<(usize, Level)> {
    let m = version_for(len, Level::M);
    let l = version_for(len, Level::L);
    match (m, l) {
        (Some(m), Some(l)) if m >= 10 && l < m => Some((l, Level::L)),
        (Some(m), _) => Some((m, Level::M)),
        (None, Some(l)) => Some((l, Level::L)),
        (None, None) => None,
    }
}

/// Encodes `data` with the mask that has the lowest penalty score.
pub fn encode(data: &[u8]) -> Result<Qr> {
    let (version, level) = choose(data.len()).ok_or("QR 데이터가 너무 깁니다.")?;
    let codewords = codewords(data, version, level);
    let mut best: Option<(i32, Qr)> = None;
    for mask in 0..8 {
        let qr = build(&codewords, version, level, mask);
        let score = penalty(&qr);
        if best.as_ref().is_none_or(|(s, _)| score < *s) {
            best = Some((score, qr));
        }
    }
    Ok(best.expect("eight masks").1)
}

/// Data plus error correction codewords, interleaved by block.
fn codewords(data: &[u8], version: usize, level: Level) -> Zeroizing<Vec<u8>> {
    let capacity = data_codewords(version, level);
    let mut bits = Zeroizing::new(Vec::with_capacity(capacity * 8));
    fn push(bits: &mut Vec<u8>, value: usize, count: usize) {
        for i in (0..count).rev() {
            bits.push(((value >> i) & 1) as u8);
        }
    }
    push(&mut bits, 0b0100, 4); // byte mode
    push(&mut bits, data.len(), if version < 10 { 8 } else { 16 });
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
    interleave(&bytes, version, level)
}

/// Splits the data codewords into blocks (the short ones first), adds each
/// block's error correction and interleaves them (ISO/IEC 18004 §7.6).
fn interleave(data: &[u8], version: usize, level: Level) -> Zeroizing<Vec<u8>> {
    let l = level.row();
    let blocks = BLOCKS[l][version] as usize;
    let ecc_len = ECC_PER_BLOCK[l][version] as usize;
    let raw = raw_modules(version) / 8;
    let short = blocks - raw % blocks;
    let short_data = raw / blocks - ecc_len;
    let divisor = rs_divisor(ecc_len);
    // Each block's data and its error correction.
    let mut parts: Vec<[Zeroizing<Vec<u8>>; 2]> = Vec::with_capacity(blocks);
    let mut at = 0;
    for b in 0..blocks {
        let n = short_data + usize::from(b >= short);
        let block = Zeroizing::new(data[at..at + n].to_vec());
        at += n;
        let ecc = rs_remainder(&block, &divisor);
        parts.push([block, ecc]);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(raw));
    for i in 0..=short_data {
        for [block, _] in &parts {
            if let Some(&b) = block.get(i) {
                out.push(b);
            }
        }
    }
    for i in 0..ecc_len {
        for [_, ecc] in &parts {
            out.push(ecc[i]);
        }
    }
    out
}

/// The centres of the alignment patterns along one axis.
fn alignment(version: usize) -> Vec<usize> {
    if version == 1 {
        return vec![];
    }
    let n = version / 7 + 2;
    let size = version * 4 + 17;
    let step = if version == 32 {
        26
    } else {
        (version * 4 + n * 2 + 1) / (n * 2 - 2) * 2
    };
    let mut out = vec![6];
    for i in (0..n - 1).rev() {
        out.push(size - 7 - i * step);
    }
    out
}

fn build(codewords: &[u8], version: usize, level: Level, mask: u8) -> Qr {
    let size = version * 4 + 17;
    let mut qr = Qr {
        version,
        level,
        size,
        modules: Zeroizing::new(vec![0; size * size]),
        function: vec![false; size * size],
    };
    // Timing patterns, then finders and alignment over them.
    for i in 0..size {
        qr.set_function(6, i, i % 2 == 0);
        qr.set_function(i, 6, i % 2 == 0);
    }
    for (cx, cy) in [(3, 3), (size - 4, 3), (3, size - 4)] {
        for dy in -4i32..=4 {
            for dx in -4i32..=4 {
                let (x, y) = (cx as i32 + dx, cy as i32 + dy);
                if (0..size as i32).contains(&x) && (0..size as i32).contains(&y) {
                    let d = dx.abs().max(dy.abs());
                    qr.set_function(x as usize, y as usize, d != 2 && d != 4);
                }
            }
        }
    }
    let centres = alignment(version);
    let last = centres.len().saturating_sub(1);
    for (i, &cy) in centres.iter().enumerate() {
        for (j, &cx) in centres.iter().enumerate() {
            // Not over the three finders.
            if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
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
    draw_version(&mut qr);

    // Zigzag placement from the bottom-right, two columns at a time.
    let mut i = 0;
    let mut right = size as i32 - 1;
    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for vert in 0..size {
            for j in 0..2 {
                let x = (right - j) as usize;
                let upward = (right + 1) & 2 == 0;
                let y = if upward { size - 1 - vert } else { vert };
                if !qr.function[y * size + x] && i < codewords.len() * 8 {
                    qr.set(x, y, (codewords[i >> 3] >> (7 - (i & 7))) & 1 != 0);
                    i += 1;
                }
            }
        }
        right -= 2;
    }
    // Remainder bits stay light, then the mask goes over every data module.
    for y in 0..size {
        for x in 0..size {
            if !qr.function[y * size + x] && masked(mask, x, y) {
                qr.modules[y * size + x] ^= 1;
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

/// The 15 format bits: level and mask, BCH(15,5), XOR 0x5412.
fn format_bits(level: Level, mask: u8) -> u32 {
    let data = (level.bits() << 3) | mask as u32;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}
fn draw_format(qr: &mut Qr, mask: u8) {
    let bits = format_bits(qr.level, mask);
    let bit = |i: usize| (bits >> i) & 1 != 0;
    let size = qr.size;
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
        qr.set_function(size - 1 - i, 8, bit(i));
    }
    for i in 8..15 {
        qr.set_function(8, size - 15 + i, bit(i));
    }
    qr.set_function(8, size - 8, true);
}
/// The 18 version bits from version 7 up: BCH(18,6), generator 0x1F25.
fn version_bits(version: usize) -> u32 {
    let mut rem = version as u32;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    ((version as u32) << 12) | rem
}
/// The two 6×3 version blocks, by the top-right and bottom-left finders.
fn draw_version(qr: &mut Qr) {
    if qr.version < 7 {
        return;
    }
    let bits = version_bits(qr.version);
    for i in 0..18 {
        let dark = (bits >> i) & 1 != 0;
        let (a, b) = (qr.size - 11 + i % 3, i / 3);
        qr.set_function(a, b, dark);
        qr.set_function(b, a, dark);
    }
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
    let size = qr.size;
    let mut score = 0;
    for transpose in [false, true] {
        for a in 0..size {
            let module = |b: usize| {
                if transpose {
                    qr.dark(a, b)
                } else {
                    qr.dark(b, a)
                }
            };
            let (mut color, mut run) = (false, 0i32);
            let mut history = Finder::new(size);
            for b in 0..size {
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
    for y in 0..size - 1 {
        for x in 0..size - 1 {
            let c = qr.dark(x, y);
            if c == qr.dark(x + 1, y) && c == qr.dark(x, y + 1) && c == qr.dark(x + 1, y + 1) {
                score += 3;
            }
        }
    }
    let dark = qr.modules.iter().map(|&m| m as i32).sum::<i32>();
    let total = (size * size) as i32;
    let k = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
    score + k * 10
}
/// Run-length history for the finder-like 1:1:3:1:1 pattern rule.
struct Finder {
    runs: [i32; 7],
    size: i32,
}
impl Finder {
    fn new(size: usize) -> Self {
        Self {
            runs: [0; 7],
            size: size as i32,
        }
    }
    fn add(&mut self, mut run: i32) {
        if self.runs[0] == 0 {
            run += self.size; // light border before the first run
        }
        self.runs.copy_within(0..6, 1);
        self.runs[0] = run;
    }
    fn count(&self) -> i32 {
        let h = &self.runs;
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
        let size = self.size;
        self.add(run + size); // light border after the last run
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
        let rows: Vec<u8> = (0..qr.size)
            .flat_map(|y| (0..qr.size).map(move |x| (x, y)))
            .map(|(x, y)| if qr.dark(x, y) { b'1' } else { b'0' })
            .collect();
        Sha256::digest(&rows)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The 0.8 encoder's vectors: version 6-M, each mask.
    #[test]
    fn matches_independent_encoder() {
        // SHA-256 of the 41x41 module rows ('1' dark) produced by python-qrcode 8.2:
        // QRCode(version=6, error_correction=M, border=0, mask_pattern=m), 8-bit byte mode.
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
        let words = codewords(URI, 6, Level::M);
        for (mask, want) in expected.iter().enumerate() {
            assert_eq!(
                digest(&build(&words, 6, Level::M, mask as u8)),
                *want,
                "mask {mask}"
            );
        }
        // 87 bytes: 5-M holds 84, so 6-M is the smallest.
        let qr = encode(URI).unwrap();
        assert_eq!((qr.version, qr.level, qr.size), (6, Level::M, 41));
        // Libraries weigh the penalty rules differently; any of the eight is valid.
        assert!(expected.contains(&digest(&qr).as_str()));
    }

    /// Byte-mode capacities of ISO/IEC 18004 table 7, levels L and M.
    #[test]
    fn capacities_match_the_standard() {
        let l = [
            17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520, 586, 644, 718,
            792, 858, 929, 1003, 1091, 1171, 1273, 1367, 1465, 1528, 1628, 1732, 1840, 1952, 2068,
            2188, 2303, 2431, 2563, 2699, 2809, 2953,
        ];
        let m = [
            14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331, 362, 412, 450, 504, 560,
            624, 666, 711, 779, 857, 911, 997, 1059, 1125, 1190, 1264, 1370, 1452, 1538, 1628,
            1722, 1809, 1911, 1989, 2099, 2213, 2331,
        ];
        for v in 1..=MAX_VERSION {
            assert_eq!(capacity(v, Level::L), l[v - 1], "{v}-L");
            assert_eq!(capacity(v, Level::M), m[v - 1], "{v}-M");
        }
        // The total codewords of table 9 (the raw modules / 8).
        for (v, total) in [
            (1, 26),
            (6, 172),
            (7, 196),
            (10, 346),
            (20, 1085),
            (40, 3706),
        ] {
            assert_eq!(raw_modules(v) / 8, total, "{v}");
        }
        // The level and version picked.
        assert_eq!(choose(14), Some((1, Level::M)));
        assert_eq!(choose(15), Some((2, Level::M)));
        assert_eq!(choose(180), Some((9, Level::M)));
        // 181 bytes need 10-M; 8-L holds 192.
        assert_eq!(choose(181), Some((8, Level::L)));
        // 213 fit 10-M, and 9-L (230) is smaller.
        assert_eq!(choose(213), Some((9, Level::L)));
        assert_eq!(choose(2331), Some((36, Level::L)));
        assert_eq!(choose(2953), Some((40, Level::L)));
        assert_eq!(choose(2954), None);
        assert!(encode(&[b'a'; 2954]).is_err());
    }

    /// Alignment centres of ISO/IEC 18004 annex E, format information of
    /// table C.1 and version information of table D.1.
    #[test]
    fn function_patterns_match_the_standard() {
        assert_eq!(alignment(1), Vec::<usize>::new());
        assert_eq!(alignment(2), [6, 18]);
        assert_eq!(alignment(7), [6, 22, 38]);
        assert_eq!(alignment(10), [6, 28, 50]);
        assert_eq!(alignment(14), [6, 26, 46, 66]);
        assert_eq!(alignment(22), [6, 26, 50, 74, 98]);
        assert_eq!(alignment(32), [6, 34, 60, 86, 112, 138]);
        assert_eq!(alignment(36), [6, 24, 50, 76, 102, 128, 154]);
        assert_eq!(alignment(40), [6, 30, 58, 86, 114, 142, 170]);
        // Level M, mask 0..7 and level L, mask 0 and 7.
        let m = [
            0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
        ];
        for (mask, want) in m.iter().enumerate() {
            assert_eq!(format_bits(Level::M, mask as u8), *want, "M{mask}");
        }
        assert_eq!(format_bits(Level::L, 0), 0x77C4);
        assert_eq!(format_bits(Level::L, 7), 0x6976);
        assert_eq!(version_bits(7), 0x07C94);
        assert_eq!(version_bits(8), 0x085BC);
        assert_eq!(version_bits(21), 0x15683);
        assert_eq!(version_bits(40), 0x28C69);
    }

    /// Reads the format information from both of its copies.
    fn read_format(qr: &Qr) -> (u32, u32) {
        let s = qr.size;
        let bit = |x: usize, y: usize| u32::from(qr.dark(x, y));
        let mut a = 0;
        for i in 0..6 {
            a |= bit(8, i) << i;
        }
        a |= bit(8, 7) << 6 | bit(8, 8) << 7 | bit(7, 8) << 8;
        for i in 9..15 {
            a |= bit(14 - i, 8) << i;
        }
        let mut b = 0;
        for i in 0..8 {
            b |= bit(s - 1 - i, 8) << i;
        }
        for i in 8..15 {
            b |= bit(8, s - 15 + i) << i;
        }
        (a, b)
    }

    /// Reads a symbol back through its own structure: format information,
    /// unmasking, the zigzag, the blocks (each one's Reed-Solomon syndromes
    /// must be zero) and the byte segment. Function patterns are checked
    /// module by module on the way.
    fn read_back(qr: &Qr) -> Vec<u8> {
        let s = qr.size;
        // Finders, separators and timing.
        for (cx, cy) in [(3, 3), (s - 4, 3), (3, s - 4)] {
            for dy in -3i32..=3 {
                for dx in -3i32..=3 {
                    let d = dx.abs().max(dy.abs());
                    let (x, y) = ((cx as i32 + dx) as usize, (cy as i32 + dy) as usize);
                    assert_eq!(qr.dark(x, y), d != 2, "finder at {x},{y}");
                }
            }
        }
        for i in 8..s - 8 {
            assert_eq!(qr.dark(6, i), i % 2 == 0, "timing column {i}");
            assert_eq!(qr.dark(i, 6), i % 2 == 0, "timing row {i}");
        }
        assert!(qr.dark(8, s - 8), "dark module");
        // Format: both copies agree, and name this level.
        let (a, b) = read_format(qr);
        assert_eq!(a, b);
        let mask = (0..8)
            .find(|&m| format_bits(qr.level, m) == a)
            .expect("format bits of this level");
        // Version: both blocks, from 7 up.
        if qr.version >= 7 {
            let (mut top, mut left) = (0, 0);
            for i in 0..18 {
                let (p, q) = (s - 11 + i % 3, i / 3);
                top |= u32::from(qr.dark(p, q)) << i;
                left |= u32::from(qr.dark(q, p)) << i;
            }
            assert_eq!(
                (top, left),
                (version_bits(qr.version), version_bits(qr.version))
            );
        }
        // The data modules in zigzag order, unmasked.
        let mut bits = vec![];
        let mut right = s as i32 - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..s {
                for j in 0..2 {
                    let x = (right - j) as usize;
                    let y = if (right + 1) & 2 == 0 {
                        s - 1 - vert
                    } else {
                        vert
                    };
                    if !qr.function[y * s + x] {
                        bits.push(qr.dark(x, y) ^ masked(mask, x, y));
                    }
                }
            }
            right -= 2;
        }
        assert_eq!(bits.len(), raw_modules(qr.version));
        let bytes: Vec<u8> = bits
            .chunks(8)
            .filter(|c| c.len() == 8)
            .map(|c| c.iter().fold(0, |acc, &b| (acc << 1) | u8::from(b)))
            .collect();
        // De-interleave: short blocks first, each one data byte shorter.
        let l = qr.level.row();
        let (n, ecc) = (
            BLOCKS[l][qr.version] as usize,
            ECC_PER_BLOCK[l][qr.version] as usize,
        );
        let raw = raw_modules(qr.version) / 8;
        let short = n - raw % n;
        let lens: Vec<usize> = (0..n)
            .map(|b| raw / n - ecc + usize::from(b >= short))
            .collect();
        let mut blocks = vec![vec![]; n];
        let mut it = bytes.iter();
        for i in 0..*lens.iter().max().unwrap() {
            for b in 0..n {
                if i < lens[b] {
                    blocks[b].push(*it.next().unwrap());
                }
            }
        }
        for _ in 0..ecc {
            for block in &mut blocks {
                block.push(*it.next().unwrap());
            }
        }
        // Every block is a codeword: its syndromes at α^0..α^(ecc-1) vanish.
        let mut data = vec![];
        for block in &blocks {
            let mut alpha = 1u8;
            for _ in 0..ecc {
                let syndrome = block
                    .iter()
                    .fold(0u8, |acc, &c| rs_multiply(acc, alpha) ^ c);
                assert_eq!(syndrome, 0, "a block's syndrome");
                alpha = rs_multiply(alpha, 2);
            }
            data.extend_from_slice(&block[..block.len() - ecc]);
        }
        // The byte segment.
        let bit = |i: usize| (data[i / 8] >> (7 - i % 8)) & 1;
        let read =
            |at: usize, n: usize| (at..at + n).fold(0usize, |acc, i| (acc << 1) | bit(i) as usize);
        assert_eq!(read(0, 4), 0b0100);
        let count_bits = if qr.version < 10 { 8 } else { 16 };
        let len = read(4, count_bits);
        let start = 4 + count_bits;
        (0..len).map(|i| read(start + 8 * i, 8) as u8).collect()
    }

    #[test]
    fn every_size_reads_back() {
        // Lengths at each edge of a version, both levels, every mask.
        let mut lengths = vec![
            0, 1, 14, 15, 87, 106, 107, 122, 123, 152, 180, 181, 200, 213, 230, 231,
        ];
        lengths.extend([400, 1000, 2331, 2953]);
        for len in lengths {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let qr = encode(&data).unwrap();
            assert_eq!((qr.version, qr.level), choose(len).unwrap(), "{len}");
            assert_eq!(qr.size, qr.version * 4 + 17);
            assert_eq!(read_back(&qr), data, "{len} bytes");
        }
        for (version, level) in [(7, Level::M), (8, Level::M), (8, Level::L), (21, Level::L)] {
            let data = vec![0xA5; capacity(version, level)];
            let words = codewords(&data, version, level);
            for mask in 0..8 {
                let qr = build(&words, version, level, mask);
                assert_eq!(read_back(&qr), data, "{version}-{level:?} mask {mask}");
            }
        }
    }

    #[test]
    fn a_typical_uri_is_small() {
        // Base32 of 20 bytes, an issuer and an e-mail account.
        let uri = b"otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example";
        let qr = encode(uri).unwrap();
        assert!(qr.version <= 6 && qr.level == Level::M, "{}", qr.version);
        assert_eq!(read_back(&qr), uri);
        // Finder corners and the fixed dark module.
        let s = qr.size;
        assert!(qr.dark(0, 0) && qr.dark(s - 1, 0) && qr.dark(0, s - 1));
        assert!(!qr.dark(7, 7) && qr.dark(8, s - 8));
    }
}
