//! The user's rule for sync on the phone: only over Tailscale. Before any
//! connection the configured host is resolved once, and every address it
//! gave must be a Tailscale address; the connection then goes to exactly
//! those addresses (never resolved again), and the socket's own local end
//! must be a Tailscale address too. Otherwise nothing is sent.
//!
//! Tailscale gives each device an address in 100.64.0.0/10 (the IPv4
//! shared address space, RFC 6598) and in fd7a:115c:a1e0::/48 (its own
//! IPv6 ULA prefix); MagicDNS names (`*.ts.net`) resolve into those.
//! 100.64.0.0/10 is also what carrier-grade NAT uses, so the check alone
//! cannot tell Tailscale from a carrier's network: the pinned host key does
//! (docs/ANDROID.md). The app also checks that a VPN network (Tailscale)
//! is up before it starts a run.
use std::net::{IpAddr, SocketAddr};

/// Whether `ip` is a Tailscale address: 100.64.0.0/10 or
/// fd7a:115c:a1e0::/48. An IPv4-mapped IPv6 address counts as its IPv4
/// address.
pub fn is_tailscale(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == 100 && (64..=127).contains(&b)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_tailscale(IpAddr::V4(v4)),
            None => {
                let s = v6.segments();
                s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
            }
        },
    }
}

/// Why a host is refused before any connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The name resolved to nothing (Tailscale off, MagicDNS off, a typo).
    Unresolved,
    /// At least one address is not a Tailscale address: all of them, for
    /// the message.
    NotTailscale(Vec<IpAddr>),
}
/// The addresses to connect to: all of `resolved`, in order, when every one
/// is a Tailscale address; else why not. Duplicates are dropped.
pub fn admit(resolved: &[SocketAddr]) -> Result<Vec<SocketAddr>, Refusal> {
    if resolved.is_empty() {
        return Err(Refusal::Unresolved);
    }
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in resolved {
        if !out.contains(a) {
            out.push(*a);
        }
    }
    if out.iter().all(|a| is_tailscale(a.ip())) {
        Ok(out)
    } else {
        Err(Refusal::NotTailscale(out.iter().map(|a| a.ip()).collect()))
    }
}
impl Refusal {
    /// The Korean text the app shows.
    pub fn text(&self, host: &str) -> String {
        match self {
            Refusal::Unresolved => format!(
                "'{host}'의 주소를 찾지 못했습니다. 휴대폰에서 Tailscale이 켜져 있는지(MagicDNS 포함) 확인하세요. 동기화는 Tailscale로만 합니다."
            ),
            Refusal::NotTailscale(ips) => {
                let list: Vec<String> = ips.iter().map(ToString::to_string).collect();
                format!(
                    "'{host}'의 주소({})에 Tailscale 주소(100.64.0.0/10, fd7a:115c:a1e0::/48)가 아닌 것이 있어 연결하지 않았습니다. 동기화는 Tailscale로만 합니다. 서버 칸에 Tailscale 이름(…ts.net)이나 100.x 주소를 적으세요.",
                    list.join(", ")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn ipv4_edges_of_100_64_slash_10() {
        assert!(!is_tailscale(v4("100.63.255.255")));
        assert!(is_tailscale(v4("100.64.0.0")));
        assert!(is_tailscale(v4("100.64.0.1")));
        assert!(is_tailscale(v4("100.100.100.100")));
        assert!(is_tailscale(v4("100.127.255.255")));
        assert!(!is_tailscale(v4("100.128.0.0")));
        assert!(!is_tailscale(v4("99.64.0.1")));
        assert!(!is_tailscale(v4("101.64.0.1")));
        assert!(!is_tailscale(v4("192.168.0.10")));
        assert!(!is_tailscale(v4("10.0.0.1")));
        assert!(!is_tailscale(v4("127.0.0.1")));
        assert!(!is_tailscale(v4("0.0.0.0")));
    }

    #[test]
    fn ipv6_only_fd7a_115c_a1e0_slash_48() {
        assert!(is_tailscale(v6("fd7a:115c:a1e0::1")));
        assert!(is_tailscale(v6("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240")));
        assert!(is_tailscale(v6("fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff")));
        assert!(!is_tailscale(v6("fd7a:115c:a1e1::1")));
        assert!(!is_tailscale(v6("fd7a:115c:a1df:ffff::1")));
        assert!(!is_tailscale(v6("fd7a:115d:a1e0::1")));
        assert!(!is_tailscale(v6("fd7b:115c:a1e0::1")));
        assert!(!is_tailscale(v6("fd00::1")));
        assert!(!is_tailscale(v6("2001:db8::1")));
        assert!(!is_tailscale(v6("::1")));
        assert!(!is_tailscale(v6("::")));
        // An IPv4-mapped address is judged as its IPv4 address.
        assert!(is_tailscale(v6("::ffff:100.64.0.1")));
        assert!(!is_tailscale(v6("::ffff:100.128.0.1")));
        assert!(!is_tailscale(v6("::ffff:192.168.1.1")));
    }

    #[test]
    fn every_address_must_be_tailscale() {
        let ts = SocketAddr::new(v4("100.101.102.103"), 22);
        let ts6 = SocketAddr::new(v6("fd7a:115c:a1e0::5"), 22);
        let lan = SocketAddr::new(v4("192.168.1.20"), 22);
        assert_eq!(admit(&[ts, ts6]), Ok(vec![ts, ts6]));
        assert_eq!(admit(&[ts, ts]), Ok(vec![ts]));
        assert_eq!(
            admit(&[ts, lan]),
            Err(Refusal::NotTailscale(vec![ts.ip(), lan.ip()]))
        );
        assert_eq!(
            admit(&[lan, ts6]),
            Err(Refusal::NotTailscale(vec![lan.ip(), ts6.ip()]))
        );
        assert_eq!(admit(&[]), Err(Refusal::Unresolved));
        assert!(Refusal::Unresolved.text("box").contains("Tailscale"));
        assert!(
            Refusal::NotTailscale(vec![lan.ip()])
                .text("box")
                .contains("192.168.1.20")
        );
    }
}
