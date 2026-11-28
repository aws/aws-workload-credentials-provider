//! Inputs and results of a single TLS port probe.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rustls::pki_types::{DnsName, InvalidDnsNameError, ServerName};

use crate::PROBE_TIMEOUT;

/// A network endpoint and optional TLS identity to probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    /// The primary IP address to connect to.
    pub address: IpAddr,
    /// The TCP port to connect to.
    pub port: u16,
    /// The DNS name sent as SNI, or `None` to suppress the SNI extension.
    pub sni: Option<ServerName<'static>>,
    /// An address attempted only when the primary connection is refused.
    pub fallback_address: Option<IpAddr>,
}

impl ProbeTarget {
    /// Creates an IPv4 loopback target for `port`.
    pub fn ipv4_loopback(port: u16) -> Self {
        Self::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// Creates an IPv6 loopback target for `port`.
    pub fn ipv6_loopback(port: u16) -> Self {
        Self::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
    }

    /// Creates a target without SNI or a fallback address.
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self {
            address,
            port,
            sni: None,
            fallback_address: None,
        }
    }

    /// Sets the address attempted after a primary connection refusal.
    pub fn with_fallback_address(mut self, fallback_address: IpAddr) -> Self {
        self.fallback_address = Some(fallback_address);
        self
    }

    /// Sets the SNI DNS name, normalizing a DNS presentation trailing dot.
    ///
    /// Returns an error when `sni` is not accepted as a DNS name by rustls.
    pub fn with_sni(mut self, sni: impl Into<String>) -> Result<Self, InvalidDnsNameError> {
        let sni = sni.into();
        let sni = sni.strip_suffix('.').unwrap_or(&sni).to_owned();
        self.sni = Some(ServerName::DnsName(DnsName::try_from(sni)?));
        Ok(self)
    }

    /// Returns the primary IP address and port as a socket address.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

impl fmt::Display for ProbeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.socket_addr())?;
        match &self.sni {
            Some(ServerName::DnsName(sni)) => write!(f, " (sni={})", sni.as_ref()),
            Some(sni) => write!(f, " (sni={sni:?})"),
            None => f.write_str(" (no sni)"),
        }
    }
}

/// Runtime settings for one probe attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeConfig {
    /// Maximum duration for the primary and optional fallback attempts together.
    pub timeout: Duration,
}

impl ProbeConfig {
    /// Creates probe settings with the supplied end-to-end timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout: PROBE_TIMEOUT,
        }
    }
}

/// The certificate chain and mTLS signal captured from a successful probe.
#[derive(Clone, PartialEq, Eq)]
pub struct ProbeSuccess {
    /// The end-entity certificate in DER encoding.
    pub leaf_der: Vec<u8>,
    /// Intermediate certificates in server-provided order and DER encoding.
    pub chain_der: Vec<Vec<u8>>,
    /// Whether the server sent a TLS client certificate request.
    pub mtls_detected: bool,
    /// Negotiated TLS protocol version (e.g. `TLSv1_3`).
    pub tls_version: Option<String>,
    /// Negotiated cipher suite name (e.g. `TLS_AES_256_GCM_SHA384`).
    pub cipher_suite: Option<String>,
    /// Signature scheme used to verify the server's handshake signature
    /// (e.g. `ECDSA_NISTP256_SHA256`).
    pub handshake_signature_scheme: Option<String>,
}

impl fmt::Debug for ProbeSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeSuccess")
            .field("leaf_der_len", &self.leaf_der.len())
            .field(
                "chain_der_lens",
                &self.chain_der.iter().map(Vec::len).collect::<Vec<_>>(),
            )
            .field("mtls_detected", &self.mtls_detected)
            .field("tls_version", &self.tls_version)
            .field("cipher_suite", &self.cipher_suite)
            .field(
                "handshake_signature_scheme",
                &self.handshake_signature_scheme,
            )
            .finish()
    }
}

/// The terminal classification of a probe attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeOutcome {
    /// A certificate chain was captured.
    Success(ProbeSuccess),
    /// The peer refused the TCP connection.
    ConnectionRefused,
    /// The TCP connection failed for another reason.
    ConnectionError(String),
    /// The end-to-end probe budget elapsed.
    Timeout,
    /// The peer response was not a TLS record.
    NotTls,
    /// TLS negotiation failed or completed without presenting a certificate.
    HandshakeError(String),
    /// Local target or TLS client configuration was invalid.
    ConfigError(String),
}

impl ProbeOutcome {
    /// Returns the stable lower-case label used for logs and metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Success(_) => "success",
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectionError(_) => "connection_error",
            Self::Timeout => "timeout",
            Self::NotTls => "not_tls",
            Self::HandshakeError(_) => "handshake_error",
            Self::ConfigError(_) => "config_error",
        }
    }

    /// Returns whether the probe captured a certificate chain.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Returns the captured certificate chain for a successful probe.
    pub fn success(&self) -> Option<&ProbeSuccess> {
        match self {
            Self::Success(success) => Some(success),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success() -> ProbeSuccess {
        ProbeSuccess {
            leaf_der: vec![0x30, 0x82, 0x01],
            chain_der: vec![vec![0x30, 0x82], vec![0x30]],
            mtls_detected: true,
            tls_version: None,
            cipher_suite: None,
            handshake_signature_scheme: None,
        }
    }

    #[test]
    fn the_loopback_constructors_pin_the_address_family_and_set_no_sni() {
        let v4 = ProbeTarget::ipv4_loopback(8443);
        let v6 = ProbeTarget::ipv6_loopback(8443);

        assert_eq!(v4.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(v6.address, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!((v4.port, v6.port), (8443, 8443));
        assert_eq!(
            (v4.sni, v4.fallback_address, v6.sni, v6.fallback_address),
            (None, None, None, None)
        );
    }

    #[test]
    fn with_fallback_address_preserves_the_primary_address() {
        let target =
            ProbeTarget::ipv4_loopback(443).with_fallback_address(IpAddr::V6(Ipv6Addr::LOCALHOST));

        assert_eq!(target.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            target.fallback_address,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn with_sni_sets_the_hostname() {
        let target = ProbeTarget::ipv4_loopback(443)
            .with_sni("example.com")
            .expect("valid sni");

        assert!(matches!(
            target.sni,
            Some(ServerName::DnsName(ref name)) if name.as_ref() == "example.com"
        ));
    }

    #[test]
    fn with_sni_normalizes_a_trailing_dot() {
        let target = ProbeTarget::ipv4_loopback(443)
            .with_sni("example.com.")
            .expect("fully qualified dns name is valid");

        assert!(matches!(
            target.sni,
            Some(ServerName::DnsName(ref name)) if name.as_ref() == "example.com"
        ));
    }

    #[test]
    fn with_sni_replaces_a_previous_hostname() {
        let target = ProbeTarget::ipv4_loopback(443)
            .with_sni("first.example.com")
            .expect("valid sni")
            .with_sni("second.example.com")
            .expect("valid sni");

        assert!(matches!(
            target.sni,
            Some(ServerName::DnsName(ref name)) if name.as_ref() == "second.example.com"
        ));
    }

    #[test]
    fn with_sni_rejects_an_invalid_hostname() {
        assert!(ProbeTarget::ipv4_loopback(443)
            .with_sni("not a hostname")
            .is_err());
    }

    #[test]
    fn socket_addr_pairs_the_address_with_the_port() {
        assert_eq!(
            ProbeTarget::ipv4_loopback(8443).socket_addr(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
        );
        assert_eq!(
            ProbeTarget::ipv6_loopback(8443).socket_addr(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443)
        );
    }

    #[test]
    fn display_brackets_ipv6_and_reports_sni() {
        let cases = [
            (ProbeTarget::ipv4_loopback(443), "127.0.0.1:443 (no sni)"),
            (ProbeTarget::ipv6_loopback(443), "[::1]:443 (no sni)"),
            (
                ProbeTarget::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9443)
                    .with_sni("sni.example.com")
                    .expect("valid sni"),
                "10.0.0.1:9443 (sni=sni.example.com)",
            ),
            (
                ProbeTarget::ipv6_loopback(9443)
                    .with_sni("sni.example.com")
                    .expect("valid sni"),
                "[::1]:9443 (sni=sni.example.com)",
            ),
        ];

        for (target, expected) in cases {
            assert_eq!(target.to_string(), expected);
        }
    }

    #[test]
    fn default_config_uses_the_probe_timeout_constant() {
        assert_eq!(ProbeConfig::default().timeout, PROBE_TIMEOUT);
    }

    #[test]
    fn with_timeout_overrides_the_default() {
        let config = ProbeConfig::with_timeout(Duration::from_millis(250));

        assert_eq!(config.timeout, Duration::from_millis(250));
        assert_ne!(config, ProbeConfig::default());
    }

    #[test]
    fn labels_cover_every_outcome() {
        let cases = [
            (ProbeOutcome::Success(success()), "success"),
            (ProbeOutcome::ConnectionRefused, "connection_refused"),
            (
                ProbeOutcome::ConnectionError("host unreachable".into()),
                "connection_error",
            ),
            (ProbeOutcome::Timeout, "timeout"),
            (ProbeOutcome::NotTls, "not_tls"),
            (
                ProbeOutcome::HandshakeError("bad record mac".into()),
                "handshake_error",
            ),
            (
                ProbeOutcome::ConfigError("invalid target".into()),
                "config_error",
            ),
        ];

        for (outcome, expected) in cases {
            assert_eq!(outcome.label(), expected);
        }
    }

    #[test]
    fn only_success_reports_certificates_and_mtls_detection() {
        let outcome = ProbeOutcome::Success(success());

        assert!(outcome.is_success());
        let extracted = outcome.success().expect("success carries certificates");
        assert_eq!(extracted.leaf_der, vec![0x30, 0x82, 0x01]);
        assert_eq!(extracted.chain_der.len(), 2);
        assert!(extracted.mtls_detected);
    }

    #[test]
    fn failure_outcomes_report_no_certificates() {
        for outcome in [
            ProbeOutcome::ConnectionRefused,
            ProbeOutcome::ConnectionError("host unreachable".into()),
            ProbeOutcome::Timeout,
            ProbeOutcome::NotTls,
            ProbeOutcome::HandshakeError("protocol version".into()),
            ProbeOutcome::ConfigError("invalid target".into()),
        ] {
            assert!(
                !outcome.is_success(),
                "{} is not a success",
                outcome.label()
            );
            assert!(outcome.success().is_none());
        }
    }

    #[test]
    fn debug_reports_certificate_sizes_not_der() {
        let rendered = format!("{:?}", success());

        assert!(
            rendered.contains("leaf_der_len: 3") && rendered.contains("chain_der_lens: [2, 1]"),
            "unexpected debug output: {rendered}"
        );
    }
}
