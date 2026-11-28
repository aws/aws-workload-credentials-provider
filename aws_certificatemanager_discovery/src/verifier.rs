//! rustls callbacks that capture the certificate chain a handshake presents.

use std::sync::{Arc, Mutex, MutexGuard};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::ProbeSuccess;

#[derive(Debug, Default)]
struct Observed {
    leaf: Option<Vec<u8>>,
    chain: Vec<Vec<u8>>,
    mtls_detected: bool,
    handshake_signature_scheme: Option<SignatureScheme>,
    tls_version: Option<String>,
    cipher_suite: Option<String>,
}

/// Certificate observations shared between a probe and its rustls callbacks.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProbeObservations {
    inner: Arc<Mutex<Observed>>,
}

impl ProbeObservations {
    fn record_chain(&self, leaf: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) {
        let mut observed = self.observed();
        observed.leaf = Some(leaf.as_ref().to_vec());
        observed.chain = intermediates
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect();
    }

    fn record_client_auth_request(&self) {
        self.observed().mtls_detected = true;
    }

    fn record_signature_scheme(&self, scheme: SignatureScheme) {
        self.observed().handshake_signature_scheme = Some(scheme);
    }

    /// Records the negotiated TLS version and cipher suite, to be merged
    /// into `ProbeSuccess` when `captured()` is called.
    pub(crate) fn record_connection_metadata(
        &self,
        tls_version: Option<String>,
        cipher_suite: Option<String>,
    ) {
        let mut observed = self.observed();
        observed.tls_version = tls_version;
        observed.cipher_suite = cipher_suite;
    }

    /// Returns the most recently captured certificate chain and mTLS signal.
    pub(crate) fn captured(&self) -> Option<ProbeSuccess> {
        let observed = self.observed();

        Some(ProbeSuccess {
            leaf_der: observed.leaf.clone()?,
            chain_der: observed.chain.clone(),
            mtls_detected: observed.mtls_detected,
            tls_version: observed.tls_version.clone(),
            cipher_suite: observed.cipher_suite.clone(),
            handshake_signature_scheme: observed
                .handshake_signature_scheme
                .map(format_signature_scheme),
        })
    }

    fn observed(&self) -> MutexGuard<'_, Observed> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Client certificate resolver that records a server CertificateRequest.
#[derive(Debug)]
pub(crate) struct CapturingClientCertResolver {
    observations: ProbeObservations,
}

impl CapturingClientCertResolver {
    pub(crate) fn new(observations: ProbeObservations) -> Self {
        Self { observations }
    }
}

impl ResolvesClientCert for CapturingClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.observations.record_client_auth_request();
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

/// rustls verifier that records the presented chain without trust validation.
#[derive(Debug)]
pub(crate) struct CapturingCertVerifier {
    observations: ProbeObservations,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl CapturingCertVerifier {
    /// Creates a verifier backed by per-probe observations and provider algorithms.
    pub(crate) fn new(
        observations: ProbeObservations,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            observations,
            supported_algs,
        }
    }
}

impl ServerCertVerifier for CapturingCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.observations.record_chain(end_entity, intermediates);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.observations.record_signature_scheme(dss.scheme);
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.observations.record_signature_scheme(dss.scheme);
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Maps a rustls `SignatureScheme` to its IANA registered name.
fn format_signature_scheme(scheme: SignatureScheme) -> String {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => "rsa_pkcs1_sha256",
        SignatureScheme::RSA_PKCS1_SHA384 => "rsa_pkcs1_sha384",
        SignatureScheme::RSA_PKCS1_SHA512 => "rsa_pkcs1_sha512",
        SignatureScheme::ECDSA_NISTP256_SHA256 => "ecdsa_secp256r1_sha256",
        SignatureScheme::ECDSA_NISTP384_SHA384 => "ecdsa_secp384r1_sha384",
        SignatureScheme::ECDSA_NISTP521_SHA512 => "ecdsa_secp521r1_sha512",
        SignatureScheme::RSA_PSS_SHA256 => "rsa_pss_rsae_sha256",
        SignatureScheme::RSA_PSS_SHA384 => "rsa_pss_rsae_sha384",
        SignatureScheme::RSA_PSS_SHA512 => "rsa_pss_rsae_sha512",
        SignatureScheme::ED25519 => "ed25519",
        SignatureScheme::ED448 => "ed448",
        _ => return format!("unknown(0x{:04x})", u16::from(scheme)),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::internal::msgs::codec::{Codec, Reader};

    fn supported_algs() -> WebPkiSupportedAlgorithms {
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
    }

    fn capturing_verifier(observations: ProbeObservations) -> CapturingCertVerifier {
        CapturingCertVerifier::new(observations, supported_algs())
    }

    fn der(bytes: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(bytes.to_vec())
    }

    fn bogus_signature(scheme: SignatureScheme) -> DigitallySignedStruct {
        let mut encoded = Vec::new();
        scheme.encode(&mut encoded);
        encoded.extend_from_slice(&4u16.to_be_bytes());
        encoded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        DigitallySignedStruct::read(&mut Reader::init(&encoded))
            .expect("hand-encoded DigitallySignedStruct is well formed")
    }

    fn verify(verifier: &CapturingCertVerifier, leaf: &[u8], intermediates: &[&[u8]]) {
        let intermediates: Vec<CertificateDer<'static>> =
            intermediates.iter().map(|bytes| der(bytes)).collect();

        verifier
            .verify_server_cert(
                &der(leaf),
                &intermediates,
                &ServerName::try_from("example.com").expect("valid dns name"),
                &[],
                UnixTime::now(),
            )
            .expect("the probe verifier accepts every certificate");
    }

    #[test]
    fn verifier_captures_leaf_and_chain() {
        let observations = ProbeObservations::default();
        let verifier = capturing_verifier(observations.clone());

        verify(&verifier, &[0xAA, 0xBB], &[&[0xCC], &[0xDD, 0xEE]]);

        let success = observations
            .captured()
            .expect("a verified certificate is captured");
        assert_eq!(success.leaf_der, vec![0xAA, 0xBB]);
        assert_eq!(success.chain_der, vec![vec![0xCC], vec![0xDD, 0xEE]]);
    }

    #[test]
    fn verifier_captures_a_leaf_with_no_intermediates() {
        let observations = ProbeObservations::default();
        let verifier = capturing_verifier(observations.clone());

        verify(&verifier, &[0x01], &[]);

        let success = observations.captured().expect("leaf is captured");
        assert_eq!(success.leaf_der, vec![0x01]);
        assert!(success.chain_der.is_empty());
    }

    #[test]
    fn last_observed_chain_wins() {
        let observations = ProbeObservations::default();
        let verifier = capturing_verifier(observations.clone());

        verify(&verifier, &[0x01], &[&[0x02]]);
        verify(&verifier, &[0x03], &[]);

        let success = observations.captured().expect("leaf is captured");
        assert_eq!(success.leaf_der, vec![0x03]);
        assert!(
            success.chain_der.is_empty(),
            "the second observation must not inherit the first chain"
        );
    }

    #[test]
    fn no_certificate_observed_yields_no_success() {
        assert!(ProbeObservations::default().captured().is_none());
    }

    #[test]
    fn client_certificate_resolver_records_a_certificate_request() {
        let observations = ProbeObservations::default();
        observations.record_chain(&der(&[0x01]), &[]);
        let resolver = CapturingClientCertResolver::new(observations.clone());

        assert!(!resolver.has_certs());
        assert!(resolver
            .resolve(&[], &[SignatureScheme::ECDSA_NISTP256_SHA256])
            .is_none());

        let success = observations.captured().expect("leaf is captured");
        assert!(success.mtls_detected);
    }

    #[test]
    fn handshake_signatures_are_asserted_without_checking() {
        let verifier = capturing_verifier(ProbeObservations::default());
        let bogus = bogus_signature(SignatureScheme::ED25519);

        assert!(verifier
            .verify_tls12_signature(b"transcript", &der(&[0x01]), &bogus)
            .is_ok());
        assert!(verifier
            .verify_tls13_signature(b"transcript", &der(&[0x01]), &bogus)
            .is_ok());
    }

    #[test]
    fn advertised_schemes_are_the_providers_defaults() {
        let expected = supported_algs().supported_schemes();
        assert!(
            !expected.is_empty(),
            "the provider must advertise at least one scheme for this assertion to mean anything"
        );

        let verifier = capturing_verifier(ProbeObservations::default());

        assert_eq!(verifier.supported_verify_schemes(), expected);
    }
}
