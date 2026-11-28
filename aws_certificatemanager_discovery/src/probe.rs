//! The TLS port probe and its outcome classification.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use log::debug;
use rustls::pki_types::ServerName;
use rustls::{
    CipherSuite, ClientConfig, InvalidMessage, ProtocolVersion, SupportedProtocolVersion,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::types::{ProbeConfig, ProbeOutcome, ProbeTarget};
use crate::validation::is_connectable;
use crate::verifier::{CapturingCertVerifier, CapturingClientCertResolver, ProbeObservations};

const PROBE_TLS_VERSIONS: &[&SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

impl ProbeTarget {
    /// Probes the target within `config.timeout` and captures its certificate chain.
    ///
    /// A fallback address is attempted only when the primary TCP connection is refused.
    pub async fn probe(&self, config: &ProbeConfig) -> ProbeOutcome {
        if !is_connectable(&self.address) {
            return ProbeOutcome::ConfigError(format!(
                "target address is not connectable: {}",
                self.address
            ));
        }
        if let Some(fallback_address) = self
            .fallback_address
            .filter(|address| !is_connectable(address))
        {
            return ProbeOutcome::ConfigError(format!(
                "fallback target address is not connectable: {fallback_address}"
            ));
        }

        let observations = ProbeObservations::default();

        let outcome = timeout(config.timeout, async {
            let primary = self.attempt(self.address, &observations).await;
            if let Some(fallback_address) = self.fallback_address_for(&primary) {
                return self.attempt(fallback_address, &observations).await;
            }
            primary
        })
        .await;

        if let Some(success) = observations.captured() {
            return ProbeOutcome::Success(success);
        }

        match outcome {
            Ok(outcome) => outcome,
            Err(_elapsed) => {
                debug!("{self}: probe exceeded its {:?} budget", config.timeout);
                ProbeOutcome::Timeout
            }
        }
    }

    fn fallback_address_for(&self, outcome: &ProbeOutcome) -> Option<IpAddr> {
        match outcome {
            ProbeOutcome::ConnectionRefused => self.fallback_address,
            _ => None,
        }
    }

    async fn attempt(&self, address: IpAddr, observations: &ProbeObservations) -> ProbeOutcome {
        let socket_address = SocketAddr::new(address, self.port);

        match TcpStream::connect(socket_address).await {
            Ok(stream) => self.handshake(stream, address, observations).await,
            Err(error) => {
                debug!("{self}: tcp connect to {socket_address} failed: {error}");
                classify_tcp_connect_failure(&error)
            }
        }
    }

    async fn handshake(
        &self,
        stream: TcpStream,
        address: IpAddr,
        observations: &ProbeObservations,
    ) -> ProbeOutcome {
        let client_config = match build_client_config(observations) {
            Ok(client_config) => client_config,
            Err(error) => return config_failure(error),
        };

        let connector = TlsConnector::from(Arc::new(client_config));

        match connector.connect(self.server_name(address), stream).await {
            Ok(mut tls_stream) => {
                // Extract connection metadata before closing.  Use explicit
                // stable strings rather than Debug format, which is not a
                // rustls API contract and may change across versions.
                let conn = tls_stream.get_ref().1;
                let tls_version = conn.protocol_version().map(format_tls_version);
                let cipher_suite = conn
                    .negotiated_cipher_suite()
                    .map(|cs| format_cipher_suite(cs.suite()));
                observations.record_connection_metadata(tls_version, cipher_suite);
                let _ = tls_stream.shutdown().await;
                completed_handshake_without_certificate()
            }
            Err(error) => classify_handshake_failure(&error),
        }
    }

    fn server_name(&self, address: IpAddr) -> ServerName<'static> {
        self.sni
            .clone()
            .unwrap_or_else(|| ServerName::from(address))
    }
}

fn completed_handshake_without_certificate() -> ProbeOutcome {
    ProbeOutcome::HandshakeError("handshake completed with no server certificate".into())
}

fn classify_tcp_connect_failure(error: &io::Error) -> ProbeOutcome {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ProbeOutcome::ConnectionRefused,
        _ => ProbeOutcome::ConnectionError(error.to_string()),
    }
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();

    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())))
}

fn build_client_config(observations: &ProbeObservations) -> Result<ClientConfig, rustls::Error> {
    build_client_config_with_versions(observations, PROBE_TLS_VERSIONS)
}

fn build_client_config_with_versions(
    observations: &ProbeObservations,
    versions: &[&'static SupportedProtocolVersion],
) -> Result<ClientConfig, rustls::Error> {
    let provider = crypto_provider();
    let verifier = CapturingCertVerifier::new(
        observations.clone(),
        provider.signature_verification_algorithms,
    );

    let client_cert_resolver = CapturingClientCertResolver::new(observations.clone());

    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(client_cert_resolver)))
}

fn config_failure(error: rustls::Error) -> ProbeOutcome {
    ProbeOutcome::ConfigError(format!("tls client config: {error}"))
}

fn classify_handshake_failure(error: &io::Error) -> ProbeOutcome {
    let rustls_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());

    match rustls_error {
        Some(rustls::Error::InvalidMessage(
            InvalidMessage::InvalidContentType | InvalidMessage::UnknownProtocolVersion,
        )) => ProbeOutcome::NotTls,
        _ => ProbeOutcome::HandshakeError(error.to_string()),
    }
}

/// Maps a rustls `ProtocolVersion` to its standard name.
/// Explicit match avoids relying on the `Debug` impl, which is not a stable API.
fn format_tls_version(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => "TLSv1.3",
        ProtocolVersion::TLSv1_2 => "TLSv1.2",
        _ => return format!("unknown(0x{:04x})", u16::from(version)),
    }
    .to_string()
}

/// Maps a rustls `CipherSuite` to its IANA registered name.
fn format_cipher_suite(suite: CipherSuite) -> String {
    match suite {
        // TLS 1.3 suites
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        // TLS 1.2 suites (aws-lc-rs defaults)
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        _ => return format!("unknown(0x{:04x})", u16::from(suite)),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    use rustls::{AlertDescription, ProtocolVersion};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    #[tokio::test]
    async fn a_non_connectable_target_is_rejected_before_the_timeout() {
        let target = ProbeTarget::new("0.0.0.0".parse().expect("valid address"), 443);
        let config = ProbeConfig::with_timeout(Duration::ZERO);

        assert_eq!(
            target.probe(&config).await,
            ProbeOutcome::ConfigError("target address is not connectable: 0.0.0.0".into())
        );
    }

    #[tokio::test]
    async fn a_non_connectable_fallback_is_rejected_before_the_timeout() {
        let target = ProbeTarget::new(V4, 443)
            .with_fallback_address("0.0.0.0".parse().expect("valid address"));
        let config = ProbeConfig::with_timeout(Duration::ZERO);

        assert_eq!(
            target.probe(&config).await,
            ProbeOutcome::ConfigError("fallback target address is not connectable: 0.0.0.0".into())
        );
    }

    fn quick() -> ProbeConfig {
        ProbeConfig::with_timeout(Duration::from_millis(250))
    }

    fn connection_failure_budget() -> ProbeConfig {
        // Winsock retries refused nonblocking connections before reporting
        // WSAECONNREFUSED, so this must outlast that operating-system delay.
        ProbeConfig::with_timeout(Duration::from_secs(5))
    }

    async fn listener(address: IpAddr) -> io::Result<(TcpListener, u16)> {
        let listener = TcpListener::bind(SocketAddr::new(address, 0)).await?;
        let port = listener.local_addr()?.port();
        Ok((listener, port))
    }

    fn closed_port() -> u16 {
        let listener =
            std::net::TcpListener::bind(SocketAddr::new(V4, 0)).expect("loopback bind succeeds");
        let port = listener
            .local_addr()
            .expect("listener has an address")
            .port();
        drop(listener);
        port
    }

    #[test]
    fn a_connection_refused_error_is_classified_as_refused() {
        let error = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");

        assert_eq!(
            classify_tcp_connect_failure(&error),
            ProbeOutcome::ConnectionRefused
        );
    }

    #[test]
    fn non_refusal_connection_errors_preserve_their_detail() {
        for kind in [
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::PermissionDenied,
        ] {
            let error = io::Error::new(kind, "tcp connect failed");

            assert_eq!(
                classify_tcp_connect_failure(&error),
                ProbeOutcome::ConnectionError("tcp connect failed".into()),
                "{kind:?} must not be reported as connection refused"
            );
        }
    }

    #[test]
    fn a_connection_error_does_not_select_the_fallback_address() {
        let target = ProbeTarget::new(V4, 443).with_fallback_address(V6);
        let outcome = ProbeOutcome::ConnectionError("host unreachable".into());

        assert_eq!(target.fallback_address_for(&outcome), None);
    }

    #[tokio::test]
    async fn a_closed_port_is_reported_as_refused() {
        let target = ProbeTarget::new(V4, closed_port());

        assert_eq!(
            target.probe(&connection_failure_budget()).await,
            ProbeOutcome::ConnectionRefused
        );
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn a_primary_connection_refusal_tries_the_fallback_address() {
        let (listener, port) = listener(V4).await.expect("loopback bind succeeds");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("fallback probe connects");
            drop(stream);
        });

        let target = ProbeTarget::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port)
            .with_fallback_address(V4);

        match target.probe(&connection_failure_budget()).await {
            ProbeOutcome::HandshakeError(_) => {}
            other => panic!("the fallback listener should have been reached, got {other:?}"),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn two_closed_addresses_are_reported_as_refused() {
        let target = ProbeTarget::new(V4, closed_port())
            .with_fallback_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));

        assert_eq!(
            target.probe(&connection_failure_budget()).await,
            ProbeOutcome::ConnectionRefused
        );
    }

    #[tokio::test]
    async fn a_non_tls_primary_does_not_use_the_fallback_address() {
        let (listener, port) = listener(V4).await.expect("loopback bind succeeds");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("probe connects");
            let mut first_client_hello_byte = [0];
            stream
                .read_exact(&mut first_client_hello_byte)
                .await
                .expect("probe sends a client hello");
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .expect("non-tls response is written");
            stream.shutdown().await.expect("response is shut down");

            // Drain the ClientHello before closing so Windows does not replace
            // the response with WSAECONNRESET because unread data remains.
            let mut remaining_client_hello = Vec::new();
            let _ = stream.read_to_end(&mut remaining_client_hello).await;
        });

        let target = ProbeTarget::new(V4, port)
            .with_fallback_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));

        assert_eq!(target.probe(&quick()).await, ProbeOutcome::NotTls);
        server.await.expect("non-tls server task succeeds");
    }

    #[tokio::test]
    async fn a_peer_that_hangs_up_is_reported_as_a_handshake_error() {
        let (listener, port) = listener(V4).await.expect("loopback bind succeeds");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("probe connects");
            drop(stream);
        });

        let target = ProbeTarget::new(V4, port);

        match target.probe(&quick()).await {
            ProbeOutcome::HandshakeError(_) => {}
            other => panic!("expected a handshake error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_peer_that_never_answers_is_reported_as_timed_out() {
        let (listener, port) = listener(V4).await.expect("loopback bind succeeds");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("probe connects");
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });

        let target = ProbeTarget::new(V4, port);

        assert_eq!(target.probe(&quick()).await, ProbeOutcome::Timeout);
    }

    #[tokio::test]
    async fn an_ipv6_target_is_reached_on_its_own_address() {
        let Ok((listener, port)) = listener(V6).await else {
            return;
        };
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("probe connects");
            drop(stream);
        });

        let target = ProbeTarget::new(V6, port);

        match target.probe(&quick()).await {
            ProbeOutcome::HandshakeError(_) => {}
            other => panic!(
                "the ipv6 listener should have been reached and failed its handshake, got {other:?}"
            ),
        }
    }

    #[test]
    fn a_completed_handshake_without_a_certificate_is_a_handshake_error() {
        assert_eq!(
            completed_handshake_without_certificate(),
            ProbeOutcome::HandshakeError("handshake completed with no server certificate".into())
        );
    }

    #[test]
    fn a_reply_that_is_not_a_tls_record_is_classified_as_not_tls() {
        for message in [
            InvalidMessage::InvalidContentType,
            InvalidMessage::UnknownProtocolVersion,
        ] {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::InvalidMessage(message),
            );

            assert_eq!(
                classify_handshake_failure(&error),
                ProbeOutcome::NotTls,
                "{message:?} means the reply was not a tls record"
            );
        }
    }

    #[test]
    fn a_malformed_tls_message_is_classified_as_a_handshake_error() {
        for message in [
            InvalidMessage::DuplicateExtension(0),
            InvalidMessage::CertificatePayloadTooLarge,
            InvalidMessage::UnexpectedMessage("ServerHello"),
            InvalidMessage::MessageTooLarge,
            InvalidMessage::TrailingData("ClientHello"),
        ] {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::InvalidMessage(message),
            );

            match classify_handshake_failure(&error) {
                ProbeOutcome::HandshakeError(detail) => assert!(
                    !detail.is_empty(),
                    "{message:?} should carry its detail for diagnosis"
                ),
                other => panic!("expected a handshake error for {message:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_hung_up_peer_is_classified_as_a_handshake_error() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            let error = io::Error::new(kind, "peer went away");

            assert_eq!(
                classify_handshake_failure(&error),
                ProbeOutcome::HandshakeError("peer went away".into()),
                "{kind:?} is ambiguous and must not be reported as not_tls"
            );
        }
    }

    #[test]
    fn a_tls_alert_is_classified_as_a_handshake_error_with_detail() {
        let alert = rustls::Error::AlertReceived(AlertDescription::UnrecognisedName);
        let error = io::Error::new(io::ErrorKind::InvalidData, alert);

        match classify_handshake_failure(&error) {
            ProbeOutcome::HandshakeError(detail) => assert!(
                detail.to_lowercase().contains("name"),
                "the alert should be preserved for diagnosis, got: {detail}"
            ),
            other => panic!("expected a handshake error, got {other:?}"),
        }
    }

    #[test]
    fn an_unrelated_io_error_is_classified_as_a_handshake_error() {
        let error = io::Error::other("something else entirely");

        assert_eq!(
            classify_handshake_failure(&error),
            ProbeOutcome::HandshakeError("something else entirely".into())
        );
    }

    #[test]
    fn a_requested_sni_hostname_is_sent_as_a_dns_name() {
        let target = ProbeTarget::ipv4_loopback(443)
            .with_sni("example.com")
            .expect("valid sni");

        let name = target.server_name(target.address);

        assert_eq!(name, ServerName::try_from("example.com").expect("valid"));
        assert!(matches!(name, ServerName::DnsName(_)));
    }

    #[test]
    fn no_requested_sni_names_the_peer_by_address() {
        let target = ProbeTarget::ipv4_loopback(443);

        let name = target.server_name(target.address);

        assert!(
            matches!(name, ServerName::IpAddress(_)),
            "an address-named peer suppresses the sni extension"
        );
    }

    #[test]
    fn no_requested_sni_names_a_fallback_peer_by_its_attempted_address() {
        let target = ProbeTarget::ipv4_loopback(443).with_fallback_address(V6);

        let name = target.server_name(V6);

        assert_eq!(name, ServerName::from(V6));
    }

    #[test]
    fn an_invalid_tls_client_configuration_is_a_config_error() {
        let error = build_client_config_with_versions(&ProbeObservations::default(), &[])
            .expect_err("an empty protocol version list is invalid");

        match config_failure(error) {
            ProbeOutcome::ConfigError(detail) => assert!(
                detail.starts_with("tls client config: "),
                "unexpected detail: {detail}"
            ),
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    #[test]
    fn the_probe_advertises_tls13_and_tls12_newest_first() {
        let versions: Vec<ProtocolVersion> = PROBE_TLS_VERSIONS
            .iter()
            .map(|version| version.version)
            .collect();

        assert_eq!(
            versions,
            vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
        );
    }

    #[test]
    fn probes_share_the_crypto_provider() {
        assert!(Arc::ptr_eq(&crypto_provider(), &crypto_provider()));
    }

    #[test]
    fn the_client_config_offers_the_providers_default_suites() {
        let config =
            build_client_config(&ProbeObservations::default()).expect("the probe config is valid");

        assert_eq!(
            config.crypto_provider().cipher_suites,
            rustls::crypto::aws_lc_rs::DEFAULT_CIPHER_SUITES.to_vec(),
            "the probe offers the default suites, not every suite the provider implements"
        );
    }
}
