//! The server's host key on the phone: trust on first use behind an
//! explicit confirmation of its SHA256 fingerprint, then pinned. A pinned
//! host is only ever reached with exactly the pinned key; a different key
//! refuses the connection, and nothing in the normal flow accepts it (the
//! settings' "forget pinned key" with a confirmation is the only way out,
//! as `ssh-keygen -R` is on a PC). The Windows helper does the same with
//! OpenSSH's `StrictHostKeyChecking=yes` and known_hosts.
//!
//! The pin names the host and port it was made for: after the settings
//! name another server, that server is unknown again.
use std::{fs, path::Path};

const HEADER: &str = "goyo-host-key 1";
/// Larger than any pin file this code writes.
const MAX_PIN: u64 = 4096;
/// The host key algorithms a pin may hold (the client offers no other).
const ALGORITHMS: [&str; 4] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

/// A pinned host key: the server it is for and the key's wire encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub blob: Vec<u8>,
}
/// What a presented host key is, against the pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The pinned key of this host and port.
    Match,
    /// No pin for this host and port: ask the user (TOFU).
    Unknown,
    /// This host and port are pinned to another key: refused, never asked.
    Changed,
}
/// The verdict on `blob`, presented by `host`:`port`.
pub fn judge(pin: Option<&Pin>, host: &str, port: u16, blob: &[u8]) -> Verdict {
    match pin {
        Some(p) if p.host.eq_ignore_ascii_case(host) && p.port == port => {
            if p.blob == blob {
                Verdict::Match
            } else {
                Verdict::Changed
            }
        }
        _ => Verdict::Unknown,
    }
}

/// `SHA256:` and the unpadded base64 of the SHA-256 of the key's wire
/// encoding: what `ssh-keygen -l` and OpenSSH's prompts show.
pub fn fingerprint(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(blob);
    format!("SHA256:{}", base64(&digest, false))
}
/// Standard base64; `pad` adds the `=` padding.
pub fn base64(bytes: &[u8], pad: bool) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= n {
                out.push(ABC[(v >> (18 - 6 * i)) as usize & 63] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}
/// Decodes standard padded base64; None for anything else.
pub fn unbase64(text: &str) -> Option<Vec<u8>> {
    let s = text.as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for (i, quad) in s.chunks(4).enumerate() {
        let last = i == s.len() / 4 - 1;
        let pads = quad.iter().rev().take_while(|c| **c == b'=').count();
        if pads > 2 || (pads > 0 && !last) {
            return None;
        }
        let mut v = 0u32;
        for (j, c) in quad.iter().enumerate() {
            let d = if j >= 4 - pads { 0 } else { value(*c)? };
            v = (v << 6) | d;
        }
        let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
        out.extend_from_slice(&bytes[..3 - pads]);
    }
    // Canonical only: the encoding of what was decoded is the input.
    (base64(&out, true) == text).then_some(out)
}

/// The algorithm name inside a key's wire encoding (its first string).
pub fn algorithm(blob: &[u8]) -> Option<&str> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    std::str::from_utf8(blob.get(4..4 + len)?).ok()
}

pub fn render(pin: &Pin) -> String {
    format!(
        "{HEADER}\nhost={}\nport={}\nkey={} {}\n",
        pin.host,
        pin.port,
        pin.algorithm,
        base64(&pin.blob, true)
    )
}
/// Strict: the header, then host, port and key in that order; the key's
/// algorithm one this client offers and named inside its encoding too.
pub fn parse(text: &str) -> Option<Pin> {
    let mut lines = text.strip_suffix('\n')?.split('\n');
    if lines.next()? != HEADER {
        return None;
    }
    let host = lines.next()?.strip_prefix("host=")?.to_owned();
    let port: u16 = lines.next()?.strip_prefix("port=")?.parse().ok()?;
    let (algorithm, encoded) = lines.next()?.strip_prefix("key=")?.split_once(' ')?;
    if lines.next().is_some() || port == 0 || !crate::line::host(&host) {
        return None;
    }
    let blob = unbase64(encoded)?;
    if !ALGORITHMS.contains(&algorithm) || self::algorithm(&blob) != Some(algorithm) {
        return None;
    }
    Some(Pin {
        host,
        port,
        algorithm: algorithm.to_owned(),
        blob,
    })
}
/// The pin in `path`; None when there is none or it is damaged (a damaged
/// pin is no pin: the next connection asks again, it never connects
/// blindly).
pub fn load(path: &Path) -> Option<Pin> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_PIN {
        return None;
    }
    parse(&fs::read_to_string(path).ok()?)
}
/// A pin for `blob`, if its algorithm is one a pin may hold.
pub fn pin_for(host: &str, port: u16, blob: &[u8]) -> Option<Pin> {
    let algorithm = algorithm(blob).filter(|a| ALGORITHMS.contains(a))?;
    Some(Pin {
        host: host.to_owned(),
        port,
        algorithm: algorithm.to_owned(),
        blob: blob.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ed25519 public key's wire encoding with key bytes 0..32.
    fn ed25519(fill: u8) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&11u32.to_be_bytes());
        b.extend_from_slice(b"ssh-ed25519");
        b.extend_from_slice(&32u32.to_be_bytes());
        b.extend((0..32u8).map(|i| i ^ fill));
        b
    }

    #[test]
    fn fingerprint_is_openssh_s() {
        // As russh's own ssh-key formats it, which is OpenSSH's format.
        let blob = ed25519(0);
        let key = russh::keys::PublicKey::from_bytes(&blob).unwrap();
        assert_eq!(
            fingerprint(&blob),
            key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
        );
        assert!(fingerprint(&blob).starts_with("SHA256:"));
        assert_eq!(fingerprint(&blob).len(), 7 + 43);
        assert_eq!(
            base64(b"any carnal pleas", true),
            "YW55IGNhcm5hbCBwbGVhcw=="
        );
        assert_eq!(base64(b"any carnal pleas", false), "YW55IGNhcm5hbCBwbGVhcw");
        assert_eq!(
            unbase64("YW55IGNhcm5hbCBwbGVhcw==").unwrap(),
            b"any carnal pleas"
        );
        assert_eq!(unbase64("YW55IGNhcm5hbCBwbGVhcw"), None);
        assert_eq!(unbase64("YW5=IGNh"), None);
        assert_eq!(unbase64("YW55IGNhcm5hbCBwbGVhcx=="), None); // not canonical
    }

    #[test]
    fn a_pin_matches_only_its_key_on_its_host() {
        let pin = pin_for("box.tail1234.ts.net", 22, &ed25519(0)).unwrap();
        assert_eq!(pin.algorithm, "ssh-ed25519");
        let host = "box.tail1234.ts.net";
        assert_eq!(judge(Some(&pin), host, 22, &ed25519(0)), Verdict::Match);
        assert_eq!(
            judge(Some(&pin), "BOX.tail1234.ts.net", 22, &ed25519(0)),
            Verdict::Match
        );
        // Another key on the pinned host: refused, never asked.
        assert_eq!(judge(Some(&pin), host, 22, &ed25519(1)), Verdict::Changed);
        // A pin is for one host and port.
        assert_eq!(judge(Some(&pin), host, 2222, &ed25519(0)), Verdict::Unknown);
        assert_eq!(
            judge(Some(&pin), "other.ts.net", 22, &ed25519(1)),
            Verdict::Unknown
        );
        assert_eq!(judge(None, host, 22, &ed25519(0)), Verdict::Unknown);
    }

    #[test]
    fn the_pin_file_round_trips_and_refuses_junk() {
        let pin = pin_for("100.101.102.103", 22, &ed25519(7)).unwrap();
        let text = render(&pin);
        assert_eq!(parse(&text), Some(pin.clone()));
        assert_eq!(
            parse(&text.replace("goyo-host-key 1", "goyo-host-key 2")),
            None
        );
        assert_eq!(parse(&text.replace("port=22", "port=0")), None);
        assert_eq!(parse(&text.replace("ssh-ed25519 ", "ssh-rsa ")), None);
        assert_eq!(parse(&format!("{text}extra\n")), None);
        assert_eq!(parse(text.trim_end()), None);
        // The algorithm named outside must be the one inside.
        let lie = text.replacen("key=ssh-ed25519", "key=ecdsa-sha2-nistp256", 1);
        assert_eq!(parse(&lie), None);
        // An RSA key is never pinned (the client does not offer RSA).
        let mut rsa = Vec::new();
        rsa.extend_from_slice(&7u32.to_be_bytes());
        rsa.extend_from_slice(b"ssh-rsa");
        assert_eq!(pin_for("h", 22, &rsa), None);
        assert_eq!(pin_for("h", 22, b"\0\0"), None);
    }
}
