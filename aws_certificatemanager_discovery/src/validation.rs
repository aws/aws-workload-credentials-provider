//! Probe target and SNI validation.

use std::net::{IpAddr, Ipv4Addr};

/// Returns whether an IP address identifies a connectable unicast endpoint.
pub fn is_connectable(ip: &IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(address) if *address == Ipv4Addr::BROADCAST)
}

/// Normalizes a DNS presentation trailing dot and validates the SNI hostname.
pub(crate) fn normalize_sni(sni: &str) -> Option<&str> {
    // DNS presentation syntax permits a trailing dot, but the TLS HostName
    // representation omits it.
    let sni = sni.strip_suffix('.').unwrap_or(sni);

    if sni.is_empty()
        || sni.len() > 253
        || sni.chars().any(char::is_whitespace)
        || sni.contains('\0')
        || sni.parse::<IpAddr>().is_ok()
    {
        return None;
    }

    let tld = sni.rsplit_once('.').map_or(sni, |(_, tld)| tld);

    if tld.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    sni.split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .then_some(sni)
}

/// Returns whether a value is a valid DNS hostname for SNI.
///
/// A single DNS presentation trailing dot is accepted and ignored.
pub fn is_valid_sni(sni: &str) -> bool {
    normalize_sni(sni).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connectability_rejects_non_connectable_addresses_and_accepts_other_addresses() {
        let cases = [
            ("0.0.0.0", false),
            ("::", false),
            ("255.255.255.255", false),
            ("224.0.0.1", false),
            ("ff02::1", false),
            ("127.0.0.1", true),
            ("::1", true),
            ("10.0.1.5", true),
            ("192.168.1.1", true),
            ("8.8.8.8", true),
        ];

        for (address, expected) in cases {
            let ip = address.parse::<IpAddr>().expect("test address is valid");

            assert_eq!(is_connectable(&ip), expected, "address: {address}");
        }
    }

    #[test]
    fn sni_label_length_boundaries_are_enforced() {
        assert!(is_valid_sni(&format!("{}.com", "a".repeat(63))));
        assert!(!is_valid_sni(&format!("{}.com", "a".repeat(64))));
    }

    #[test]
    fn sni_trailing_dot_is_normalized_before_validation() {
        assert_eq!(normalize_sni("amazon.com."), Some("amazon.com"));
        assert!(is_valid_sni("amazon.com."));
        assert_eq!(normalize_sni("."), None);
        assert_eq!(normalize_sni("amazon.com.."), None);
    }

    #[test]
    fn sni_hostname_length_boundaries_are_enforced() {
        let hostname_253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let hostname_254 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert_eq!(hostname_253.len(), 253);
        assert!(is_valid_sni(&hostname_253));
        assert_eq!(hostname_254.len(), 254);
        assert!(!is_valid_sni(&hostname_254));
    }
}
