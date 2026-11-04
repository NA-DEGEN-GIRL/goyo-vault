//! The phone's sync settings and the server line for its key. Every value
//! that reaches the remote command is checked against the same character
//! sets as goyo-sync.conf on Windows (src/bin/goyo-sync/config.rs and
//! setup::install_command), so no setting can become a second remote
//! command or a shell construct; the server script's `authorize` checks
//! the line again with the same rules.
use std::fmt::Write as _;

pub const DEFAULT_REMOTE: &str = ".local/share/goyo-sync/goyo-sync-server.py";
pub const DEFAULT_PYTHON: &str = "python3";
pub const DEFAULT_PORT: u16 = 22;
/// The Windows defaults (goyo-sync.conf `interval`, `timeout`).
pub const DEFAULT_INTERVAL: u64 = 60;
pub const DEFAULT_TIMEOUT: u64 = 120;
/// At most this many vault IDs in `--key-sync=` (goyo-sync's MAX_VAULTS).
pub const MAX_IDS: usize = 8;

/// ASCII letters, digits and `extra`; 1 to `max` bytes; no leading `-`.
pub fn word(s: &str, max: usize, extra: &[u8]) -> bool {
    (1..=max).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}
/// The server: a DNS name (`box.tail1234.ts.net`), an IPv4 address, or an
/// IPv6 address without brackets. No user part (that is its own field),
/// no leading `-`.
pub fn host(s: &str) -> bool {
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    (1..=253).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
/// The login name on the server.
pub fn user(s: &str) -> bool {
    word(s, 64, b"._-")
}
/// The server script's path, as goyo-sync.conf's `remote` and the install
/// take it: a word of `. _ / ~ + -`, no `.` or `..` segment, and a file
/// name at the end without `~`.
pub fn remote(s: &str) -> bool {
    let name = s.rsplit('/').next().unwrap_or(s);
    word(s, 256, b"._/~+-")
        && s.split('/').all(|seg| seg != "." && seg != "..")
        && !name.is_empty()
        && !name.contains('~')
}
/// The server's Python command.
pub fn python(s: &str) -> bool {
    word(s, 64, b"._/+-")
}

/// The remote command of every exchange: what the Windows helper puts
/// after ssh's `--` (`<python> -I <remote> serve`). A forced command on
/// the server replaces it.
pub fn serve_command(python: &str, remote: &str) -> Option<String> {
    (self::python(python) && self::remote(remote)).then(|| format!("{python} -I {remote} serve"))
}
/// The line's comment: `goyo-sync android-<model>`, the model reduced to
/// `A-Z a-z 0-9 . _ -` and the name to 63 characters, as the server's
/// `authorize` takes it.
pub fn comment(model: &str) -> String {
    let model: String = model
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    let name: String = format!("android-{model}").chars().take(63).collect();
    let name = name.trim_end_matches('-');
    format!("goyo-sync {name}")
}
/// The phone's authorized_keys line, in the format of the Windows
/// helper's (keysetup::server_line): the forced command with
/// `--key-sync=` for each vault ID, the key, the comment.
pub fn forced_line(
    python: &str,
    remote: &str,
    ids: &[[u8; 16]],
    blob: &str,
    model: &str,
) -> Option<String> {
    let mut serve = serve_command(python, remote)?;
    if ids.len() > MAX_IDS || !public_blob(blob) {
        return None;
    }
    if !ids.is_empty() {
        let named: Vec<String> = ids.iter().map(|i| hex(i)).collect();
        let _ = write!(serve, " --key-sync={}", named.join(","));
    }
    Some(format!(
        "restrict,command=\"{serve}\" ssh-ed25519 {blob} {}",
        comment(model)
    ))
}
/// The base64 of an ed25519 public key's wire encoding: 68 characters
/// that start with the type name and the 32-byte length.
pub fn public_blob(blob: &str) -> bool {
    blob.len() == 68
        && blob.starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI")
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}
/// The wire encoding of the ed25519 public key `pk`, base64: what goes
/// after `ssh-ed25519` in the line.
pub fn public_blob_of(pk: &[u8; 32]) -> String {
    let mut wire = Vec::with_capacity(51);
    wire.extend_from_slice(&11u32.to_be_bytes());
    wire.extend_from_slice(b"ssh-ed25519");
    wire.extend_from_slice(&32u32.to_be_bytes());
    wire.extend_from_slice(pk);
    crate::hostkey::base64(&wire, true)
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    #[test]
    fn the_line_is_the_windows_format() {
        let pk: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(public_blob_of(&pk), BLOB);
        assert!(public_blob(BLOB));
        let id: [u8; 16] = std::array::from_fn(|i| (i * 17) as u8);
        let line = forced_line(DEFAULT_PYTHON, DEFAULT_REMOTE, &[id], BLOB, "LM-G710N").unwrap();
        assert_eq!(
            line,
            format!(
                "restrict,command=\"python3 -I .local/share/goyo-sync/goyo-sync-server.py serve \
                 --key-sync=00112233445566778899aabbccddeeff\" ssh-ed25519 {BLOB} goyo-sync android-LM-G710N"
            )
        );
        // Without vault IDs: no --key-sync at all.
        assert_eq!(
            forced_line("/usr/bin/python3", "s.py", &[], BLOB, "Pixel 8").unwrap(),
            format!(
                "restrict,command=\"/usr/bin/python3 -I s.py serve\" ssh-ed25519 {BLOB} goyo-sync android-Pixel8"
            )
        );
        let two = forced_line("python3", "s.py", &[id, [1; 16]], BLOB, "x").unwrap();
        assert!(two.contains(
            "--key-sync=00112233445566778899aabbccddeeff,01010101010101010101010101010101\""
        ));
        assert_eq!(
            forced_line("python3", "s.py", &[[0; 16]; 9], BLOB, "x"),
            None
        );
    }

    #[test]
    fn the_line_refuses_what_authorize_refuses() {
        assert_eq!(
            forced_line("python3;id", DEFAULT_REMOTE, &[], BLOB, "m"),
            None
        );
        assert_eq!(forced_line("-c", DEFAULT_REMOTE, &[], BLOB, "m"), None);
        assert_eq!(forced_line("python3", "a/../s.py", &[], BLOB, "m"), None);
        assert_eq!(forced_line("python3", "s.py\" x", &[], BLOB, "m"), None);
        assert_eq!(forced_line("python3", "dir/", &[], BLOB, "m"), None);
        assert_eq!(forced_line("python3", "~", &[], BLOB, "m"), None);
        assert_eq!(forced_line("python3", "s.py", &[], &BLOB[1..], "m"), None);
        assert_eq!(
            forced_line("python3", "s.py", &[], &BLOB.replace('A', "-"), "m"),
            None
        );
    }

    #[test]
    fn the_comment_is_plain_and_short() {
        assert_eq!(comment("LM-G710N"), "goyo-sync android-LM-G710N");
        assert_eq!(
            comment("Galaxy S24 Ultra"),
            "goyo-sync android-GalaxyS24Ultra"
        );
        assert_eq!(comment("\"; rm -rf ~"), "goyo-sync android-rm-rf");
        assert_eq!(comment(""), "goyo-sync android");
        let long = comment(&"x".repeat(200));
        assert_eq!(long.len(), "goyo-sync ".len() + 63);
    }

    #[test]
    fn settings_words() {
        assert!(host("box.tail1234.ts.net"));
        assert!(host("100.101.102.103"));
        assert!(host("fd7a:115c:a1e0::1"));
        assert!(!host("-oProxyCommand=x"));
        assert!(!host("user@box"));
        assert!(!host("box name"));
        assert!(!host(""));
        assert!(user("me"));
        assert!(user("first.last_2"));
        assert!(!user("-me"));
        assert!(!user("me@x"));
        assert!(!user(""));
        assert!(remote(DEFAULT_REMOTE));
        assert!(remote("/opt/goyo/s.py"));
        assert!(!remote("./s.py"));
        assert!(python("/usr/bin/python3.12"));
        assert!(!python("python3 -c"));
    }
}
