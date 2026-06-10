//! Internal ACM Manager for calling AWS ACM APIs.

use crate::error::{classify_export_error, AcmManagerError};
use crate::traits::AcmCertificateExporter;
use crate::utils;
use crate::utils::AcmUserAgentInterceptor;
use aws_lc_rs::rand;
use aws_sdk_acm::Client as AcmClient;
use aws_smithy_types::Blob;
use base64ct::{Base64, Encoding};
use pkcs8::der::pem::LineEnding;
use pkcs8::{DecodePrivateKey, SecretDocument};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Manages interactions with the AWS ACM service.
///
/// All role-based clients are built upfront at construction, so
/// `export_certificate` takes `&self` and is safe to call concurrently
/// from multiple tasks without locking. Credential resolution is deferred
/// to the first API call per role. Callers must reconstruct this manager
/// when the configuration changes (e.g. on SIGHUP) to pick up new role ARNs.
#[derive(Debug)]
pub(crate) struct AcmManager {
    /// ACM clients keyed by role ARN, built once at construction.
    role_clients: HashMap<String, AcmClient>,
}

/// Exported certificate components that the CertificateStore can write to the filesystem.
/// `Debug` is manually implemented to redact the private key from logs.
pub(crate) struct ExportedCertificate {
    /// PEM encoded certificate data
    pub certificate: String,
    /// PEM encoded certificate chain data
    pub certificate_chain: String,
    /// PEM encoded private key data
    pub private_key: Zeroizing<String>,
}

impl std::fmt::Debug for ExportedCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportedCertificate")
            .field("certificate", &self.certificate)
            .field("certificate_chain", &self.certificate_chain)
            .field("private_key", &"** redacted **")
            .finish()
    }
}

impl AcmCertificateExporter for AcmManager {
    async fn export_certificate(
        &self,
        certificate_arn: &str,
        role_arn: &str,
    ) -> Result<ExportedCertificate, AcmManagerError> {
        self.export_certificate(certificate_arn, role_arn).await
    }
}

impl AcmManager {
    /// Builds role clients from the unique role ARNs in the given iterator.
    ///
    /// Clients are built unconditionally for every unique role. Credential
    /// failures surface lazily through `export_certificate` →
    /// `classify_export_error`, which correctly classifies STS errors as
    /// transient vs non-transient.
    pub(crate) async fn new(
        base_sdk_config: &aws_config::SdkConfig,
        role_arns: impl Iterator<Item = &str>,
    ) -> Self {
        let mut role_clients = HashMap::new();
        for role_arn in role_arns {
            if role_clients.contains_key(role_arn) {
                continue;
            }
            let provider = utils::build_credentials_provider(base_sdk_config, role_arn).await;
            let config = aws_sdk_acm::config::Builder::from(base_sdk_config)
                .credentials_provider(provider)
                .interceptor(AcmUserAgentInterceptor)
                .build();
            role_clients.insert(role_arn.to_string(), AcmClient::from_conf(config));
        }
        Self { role_clients }
    }

    /// Creates an ACM Manager from a pre-built client for testing.
    #[cfg(test)]
    fn from_client(role_arn: &str, client: AcmClient) -> Self {
        let mut role_clients = HashMap::new();
        role_clients.insert(role_arn.to_string(), client);
        Self { role_clients }
    }

    /// Exports a certificate from ACM using the pre-built client for the given role ARN.
    pub(crate) async fn export_certificate(
        &self,
        certificate_arn: &str,
        role_arn: &str,
    ) -> Result<ExportedCertificate, AcmManagerError> {
        let client = self.role_clients.get(role_arn).ok_or_else(|| {
            AcmManagerError::InternalFailure(format!("no client for role {}", role_arn))
        })?;

        let passphrase = Passphrase::generate()?;
        let response = client
            .export_certificate()
            .certificate_arn(certificate_arn)
            .passphrase(Blob::new(passphrase.as_slice()))
            .send()
            .await
            .map_err(classify_export_error)?;

        Self::build_exported_certificate(response, &passphrase)
    }

    /// Builds an ExportedCertificate from the API response.
    fn build_exported_certificate(
        response: aws_sdk_acm::operation::export_certificate::ExportCertificateOutput,
        passphrase: &Passphrase,
    ) -> Result<ExportedCertificate, AcmManagerError> {
        let encrypted_private_key =
            response
                .private_key
                .ok_or(AcmManagerError::InternalFailure(
                    "missing private key field".into(),
                ))?;

        let decrypted_private_key = passphrase.decrypt_private_key(&encrypted_private_key)?;

        Ok(ExportedCertificate {
            certificate: response
                .certificate
                .ok_or(AcmManagerError::InternalFailure(
                    "missing certificate field".into(),
                ))?,
            certificate_chain: response.certificate_chain.ok_or(
                AcmManagerError::InternalFailure("missing certificate chain field".into()),
            )?,
            private_key: decrypted_private_key,
        })
    }
}

/// A cryptographically random passphrase that is zeroized on drop.
struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    /// Generates a new cryptographically random ASCII passphrase.
    ///
    /// ACM expects an ASCII passphrase (excluding #, $, %). We generate 32 random
    /// bytes and encode them as base64 to produce a 44 byte ASCII passphrase.
    fn generate() -> Result<Self, AcmManagerError> {
        let mut raw = Zeroizing::new(vec![0u8; 32]);
        rand::fill(raw.as_mut_slice()).map_err(|_| {
            AcmManagerError::InternalFailure("failed to generate random bytes".into())
        })?;
        Ok(Self(Zeroizing::new(
            Base64::encode_string(&raw).into_bytes(),
        )))
    }

    /// Returns the passphrase as a byte slice.
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Decrypts an encrypted PEM private key using this passphrase.
    /// Returns the decrypted private key as a PEM-encoded `Zeroizing<String>`.
    #[cfg(not(feature = "fips"))]
    fn decrypt_private_key(
        &self,
        encrypted_pem: &str,
    ) -> Result<Zeroizing<String>, AcmManagerError> {
        let decrypted_key =
            SecretDocument::from_pkcs8_encrypted_pem(encrypted_pem, self.as_slice()).map_err(
                |e| AcmManagerError::InternalFailure(format!("failed to decrypt private key: {e}")),
            )?;
        let pem = decrypted_key
            .to_pem("PRIVATE KEY", LineEnding::default())
            .map_err(|e| {
                AcmManagerError::InternalFailure(format!("failed to encode decrypted key: {e}"))
            })?;
        Ok(pem)
    }

    /// Decrypts an encrypted PEM private key using FIPS-validated cryptography.
    ///
    /// Uses RustCrypto (`pkcs8`/`pkcs5`) for ASN.1/PEM parsing only, then delegates
    /// the actual cryptographic operations (PBKDF2 key derivation + AES-CBC decryption)
    /// to `aws-lc-rs` which provides FIPS 140-3 validated implementations.
    #[cfg(feature = "fips")]
    fn decrypt_private_key(
        &self,
        encrypted_pem: &str,
    ) -> Result<Zeroizing<String>, AcmManagerError> {
        use aws_lc_rs::{cipher, pbkdf2};
        use pkcs5::pbes2;
        use pkcs8::der::Decode;
        use pkcs8::EncryptedPrivateKeyInfo;
        use std::num::NonZeroU32;

        // Step 1: Parse PEM and ASN.1 structure (non-crypto, just data format handling)
        let (label, der_bytes) = pkcs8::der::pem::decode_vec(encrypted_pem.as_bytes())
            .map_err(|e| AcmManagerError::InternalFailure(format!("failed to decode PEM: {e}")))?;
        if label != "ENCRYPTED PRIVATE KEY" {
            return Err(AcmManagerError::InternalFailure(format!(
                "unexpected PEM label: {label}"
            )));
        }

        let encrypted_pk_info = EncryptedPrivateKeyInfo::from_der(&der_bytes).map_err(|e| {
            AcmManagerError::InternalFailure(format!("failed to parse PKCS#8: {e}"))
        })?;

        // Extract PBES2 parameters
        let scheme = encrypted_pk_info.encryption_algorithm;
        let pbes2_params = scheme.pbes2().ok_or_else(|| {
            AcmManagerError::InternalFailure("unsupported encryption scheme: not PBES2".into())
        })?;

        // Extract KDF parameters (PBKDF2)
        let (salt, iterations, key_len, pbkdf2_prf) = match &pbes2_params.kdf {
            pbes2::Kdf::Pbkdf2(params) => {
                let key_len = params.key_length.unwrap_or(match &pbes2_params.encryption {
                    pbes2::EncryptionScheme::Aes128Cbc { .. } => 16,
                    pbes2::EncryptionScheme::Aes256Cbc { .. } => 32,
                    _ => {
                        return Err(AcmManagerError::InternalFailure(
                            "unsupported encryption algorithm".into(),
                        ))
                    }
                });
                (
                    params.salt,
                    params.iteration_count,
                    key_len as usize,
                    params.prf,
                )
            }
            _ => {
                return Err(AcmManagerError::InternalFailure(
                    "unsupported KDF: only PBKDF2 is supported".into(),
                ))
            }
        };

        // Extract IV and ciphertext
        let iv = match &pbes2_params.encryption {
            pbes2::EncryptionScheme::Aes128Cbc { iv } => iv.as_slice(),
            pbes2::EncryptionScheme::Aes256Cbc { iv } => iv.as_slice(),
            _ => {
                return Err(AcmManagerError::InternalFailure(
                    "unsupported cipher: only AES-CBC is supported".into(),
                ))
            }
        };

        // Step 2: PBKDF2 key derivation (aws-lc-rs FIPS)
        let pbkdf2_alg = match pbkdf2_prf {
            pbes2::Pbkdf2Prf::HmacWithSha1 => pbkdf2::PBKDF2_HMAC_SHA1,
            pbes2::Pbkdf2Prf::HmacWithSha256 => pbkdf2::PBKDF2_HMAC_SHA256,
            pbes2::Pbkdf2Prf::HmacWithSha384 => pbkdf2::PBKDF2_HMAC_SHA384,
            pbes2::Pbkdf2Prf::HmacWithSha512 => pbkdf2::PBKDF2_HMAC_SHA512,
            _ => {
                return Err(AcmManagerError::InternalFailure(
                    "unsupported PBKDF2 PRF".into(),
                ))
            }
        };
        let mut derived_key = Zeroizing::new(vec![0u8; key_len]);
        pbkdf2::derive(
            pbkdf2_alg,
            NonZeroU32::new(iterations).ok_or_else(|| {
                AcmManagerError::InternalFailure("invalid iteration count".into())
            })?,
            salt,
            self.as_slice(),
            derived_key.as_mut_slice(),
        );

        // Step 3: AES-CBC decryption (aws-lc-rs FIPS)
        let cipher_alg = match key_len {
            16 => &cipher::AES_128,
            32 => &cipher::AES_256,
            _ => {
                return Err(AcmManagerError::InternalFailure(format!(
                    "unsupported key length: {key_len}"
                )))
            }
        };

        let key = cipher::UnboundCipherKey::new(cipher_alg, &derived_key).map_err(|e| {
            AcmManagerError::InternalFailure(format!("failed to create cipher key: {e}"))
        })?;
        let decrypting_key = cipher::PaddedBlockDecryptingKey::cbc_pkcs7(key).map_err(|e| {
            AcmManagerError::InternalFailure(format!("failed to create decrypting key: {e}"))
        })?;

        let mut ciphertext = Zeroizing::new(encrypted_pk_info.encrypted_data.to_vec());
        let decrypt_ctx = cipher::DecryptionContext::Iv128(
            iv.try_into()
                .map_err(|_| AcmManagerError::InternalFailure("invalid IV length".into()))?,
        );

        let plaintext = decrypting_key
            .decrypt(&mut ciphertext, decrypt_ctx)
            .map_err(|e| {
                AcmManagerError::InternalFailure(format!("AES-CBC decryption failed: {e}"))
            })?;

        // Step 4: Encode decrypted DER as PEM
        let pem = pkcs8::der::pem::encode_string("PRIVATE KEY", LineEnding::default(), plaintext)
            .map_err(|e| {
            AcmManagerError::InternalFailure(format!("failed to encode decrypted key: {e}"))
        })?;
        Ok(Zeroizing::new(pem))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_acm::operation::export_certificate::{
        ExportCertificateError, ExportCertificateOutput,
    };
    use aws_sdk_acm::types::error::{
        InvalidArnException, RequestInProgressException, ResourceNotFoundException,
    };
    use aws_sdk_acm::Client;
    use aws_smithy_mocks::{mock, mock_client};
    use pkcs8::PrivateKeyInfo;

    const FAKE_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIFAKE\n-----END CERTIFICATE-----";
    const FAKE_CHAIN: &str = "-----BEGIN CERTIFICATE-----\nMIIFAKECHAIN\n-----END CERTIFICATE-----";

    /// Creates a real encrypted PKCS#8 PEM from a test EC private key.
    fn make_encrypted_pem(passphrase: &[u8]) -> String {
        // Test PKCS#8 DER for an EC P-256 private key (generated via openssl)
        let pki_der: &[u8] = &[
            0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
            0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x9a, 0x56, 0xf6, 0xa6, 0x2f, 0x80,
            0x1a, 0x33, 0x3c, 0x3d, 0x9d, 0x6c, 0x1c, 0xa2, 0xdc, 0x00, 0x07, 0xe4, 0x1e, 0x7b,
            0x3a, 0x67, 0x73, 0x13, 0xdb, 0xfa, 0xfa, 0xc9, 0x33, 0xb3, 0xc4, 0xf6, 0xa1, 0x44,
            0x03, 0x42, 0x00, 0x04, 0x5c, 0xaa, 0xc1, 0x82, 0x94, 0xd2, 0x85, 0xc7, 0x6c, 0x6e,
            0x17, 0xe4, 0x0b, 0x71, 0x48, 0x39, 0x3a, 0xfa, 0xad, 0x9a, 0xb0, 0xe6, 0x9f, 0xcb,
            0xe3, 0x01, 0x40, 0xbf, 0x92, 0x0d, 0xbb, 0xdd, 0x27, 0x66, 0x27, 0xd3, 0x77, 0x71,
            0x93, 0x9e, 0x90, 0x03, 0xe7, 0x8b, 0xee, 0x65, 0xe9, 0x20, 0xee, 0x08, 0x7c, 0x8d,
            0x9e, 0x4d, 0x5d, 0xfc, 0x34, 0xc8, 0xee, 0x6b, 0x02, 0x9f, 0xa0, 0x58,
        ];
        let pki = PrivateKeyInfo::try_from(pki_der).unwrap();

        // Use PBKDF2-SHA256-AES256 for FIPS builds (matches ACM production behavior).
        // Default encrypt() uses scrypt which is not FIPS-approved.
        #[cfg(feature = "fips")]
        {
            use pkcs8::pkcs5::pbes2;
            use rand_core::RngCore;
            let mut salt = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut salt);
            let mut iv = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut iv);
            let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(1, &salt, &iv).unwrap();
            let encrypted = pki.encrypt_with_params(params, passphrase).unwrap();
            encrypted
                .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
                .unwrap()
                .to_string()
        }

        #[cfg(not(feature = "fips"))]
        {
            let encrypted = pki.encrypt(rand_core::OsRng, passphrase).unwrap();
            encrypted
                .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
                .unwrap()
                .to_string()
        }
    }

    fn make_mock_client() -> AcmClient {
        let rule = mock!(Client::export_certificate).then_compute_output(|req| {
            let passphrase = req.passphrase().unwrap().as_ref();
            let encrypted_pem = make_encrypted_pem(passphrase);
            ExportCertificateOutput::builder()
                .certificate(FAKE_CERT)
                .certificate_chain(FAKE_CHAIN)
                .private_key(encrypted_pem)
                .build()
        });
        mock_client!(aws_sdk_acm, [&rule])
    }

    #[test]
    fn test_generate_passphrase_returns_valid_base64() {
        let passphrase = Passphrase::generate().unwrap();
        assert_eq!(passphrase.as_slice().len(), 44); // base64 of 32 bytes
        assert!(passphrase.as_slice().is_ascii());
    }

    #[test]
    fn test_generate_passphrase_is_unique() {
        let p1 = Passphrase::generate().unwrap();
        let p2 = Passphrase::generate().unwrap();
        assert_ne!(p1.as_slice(), p2.as_slice());
    }

    #[test]
    fn test_generate_passphrase_is_not_all_zeros() {
        let passphrase = Passphrase::generate().unwrap();
        assert!(passphrase.as_slice().iter().any(|&b| b != 0));
    }

    #[test]
    fn test_decrypt_private_key_success() {
        let raw_passphrase = b"test-passphrase";
        let encrypted_pem = make_encrypted_pem(raw_passphrase);
        let passphrase = Passphrase(Zeroizing::new(raw_passphrase.to_vec()));
        let decrypted = passphrase.decrypt_private_key(&encrypted_pem).unwrap();
        assert!(SecretDocument::from_pkcs8_pem(&decrypted).is_ok());
    }

    #[test]
    fn test_decrypt_private_key_wrong_passphrase() {
        let encrypted_pem = make_encrypted_pem(b"correct-passphrase");
        let passphrase = Passphrase(Zeroizing::new(b"wrong-passphrase".to_vec()));
        let result = passphrase.decrypt_private_key(&encrypted_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_private_key_invalid_pem() {
        let passphrase = Passphrase(Zeroizing::new(b"passphrase".to_vec()));
        let result = passphrase.decrypt_private_key("not a pem");
        assert!(result.is_err());
    }

    const TEST_ROLE: &str = "arn:aws:iam::123456789012:role/TestRole";

    #[tokio::test]
    async fn test_export_certificate_success() {
        let client = make_mock_client();
        let manager = AcmManager::from_client(TEST_ROLE, client);

        let result = manager
            .export_certificate(
                "arn:aws:acm:us-west-2:123456789012:certificate/abc123",
                TEST_ROLE,
            )
            .await;

        assert!(result.is_ok());
        let cert = result.unwrap();
        assert_eq!(cert.certificate, FAKE_CERT);
        assert_eq!(cert.certificate_chain, FAKE_CHAIN);
        assert!(SecretDocument::from_pkcs8_pem(&cert.private_key).is_ok());
    }

    #[tokio::test]
    async fn test_export_certificate_resource_not_found() {
        let rule = mock!(Client::export_certificate).then_error(|| {
            ExportCertificateError::ResourceNotFoundException(
                ResourceNotFoundException::builder().build(),
            )
        });
        let client = mock_client!(aws_sdk_acm, [&rule]);
        let manager = AcmManager::from_client(TEST_ROLE, client);

        let result = manager
            .export_certificate(
                "arn:aws:acm:us-west-2:123456789012:certificate/nonexistent",
                TEST_ROLE,
            )
            .await;

        assert!(matches!(result, Err(AcmManagerError::NonTransient(_))));
    }

    #[tokio::test]
    async fn test_export_certificate_request_in_progress_is_transient() {
        let rule = mock!(Client::export_certificate).then_error(|| {
            ExportCertificateError::RequestInProgressException(
                RequestInProgressException::builder().build(),
            )
        });
        let client = mock_client!(aws_sdk_acm, [&rule]);
        let manager = AcmManager::from_client(TEST_ROLE, client);

        let result = manager
            .export_certificate(
                "arn:aws:acm:us-west-2:123456789012:certificate/abc123",
                TEST_ROLE,
            )
            .await;

        assert!(matches!(result, Err(AcmManagerError::Transient(_))));
    }

    #[tokio::test]
    async fn test_export_certificate_invalid_arn() {
        let rule = mock!(Client::export_certificate).then_error(|| {
            ExportCertificateError::InvalidArnException(InvalidArnException::builder().build())
        });
        let client = mock_client!(aws_sdk_acm, [&rule]);
        let manager = AcmManager::from_client(TEST_ROLE, client);

        let result = manager.export_certificate("invalid-arn", TEST_ROLE).await;

        assert!(matches!(result, Err(AcmManagerError::NonTransient(_))));
    }

    #[tokio::test]
    async fn test_export_certificate_unknown_role() {
        let manager = AcmManager::from_client(TEST_ROLE, make_mock_client());

        let result = manager
            .export_certificate(
                "arn:aws:acm:us-west-2:123456789012:certificate/abc123",
                "arn:aws:iam::123456789012:role/UnknownRole",
            )
            .await;

        assert!(matches!(
            result,
            Err(AcmManagerError::InternalFailure(msg)) if msg.contains("no client for role")
        ));
    }

    #[test]
    fn test_build_exported_certificate_missing_private_key() {
        let response = ExportCertificateOutput::builder()
            .certificate(FAKE_CERT)
            .certificate_chain(FAKE_CHAIN)
            .build();

        let passphrase = Passphrase(Zeroizing::new(b"unused".to_vec()));
        let result = AcmManager::build_exported_certificate(response, &passphrase);
        assert!(matches!(
            result,
            Err(AcmManagerError::InternalFailure(msg)) if msg.contains("missing private key")
        ));
    }

    #[test]
    fn test_build_exported_certificate_missing_certificate() {
        let raw = b"test-passphrase";
        let encrypted_pem = make_encrypted_pem(raw);
        let passphrase = Passphrase(Zeroizing::new(raw.to_vec()));

        let response = ExportCertificateOutput::builder()
            .private_key(encrypted_pem)
            .certificate_chain(FAKE_CHAIN)
            .build();

        let result = AcmManager::build_exported_certificate(response, &passphrase);
        assert!(matches!(
            result,
            Err(AcmManagerError::InternalFailure(msg)) if msg.contains("missing certificate field")
        ));
    }

    #[test]
    fn test_build_exported_certificate_missing_chain() {
        let raw = b"test-passphrase";
        let encrypted_pem = make_encrypted_pem(raw);
        let passphrase = Passphrase(Zeroizing::new(raw.to_vec()));

        let response = ExportCertificateOutput::builder()
            .certificate(FAKE_CERT)
            .private_key(encrypted_pem)
            .build();

        let result = AcmManager::build_exported_certificate(response, &passphrase);
        assert!(matches!(
            result,
            Err(AcmManagerError::InternalFailure(msg)) if msg.contains("missing certificate chain")
        ));
    }

    #[test]
    fn test_exported_certificate_debug_redacts_private_key() {
        let cert = ExportedCertificate {
            certificate: FAKE_CERT.to_string(),
            certificate_chain: FAKE_CHAIN.to_string(),
            private_key: Zeroizing::new("SECRET_KEY_DATA".to_string()),
        };
        let debug_output = format!("{:?}", cert);
        assert!(debug_output.contains(&FAKE_CERT.escape_debug().to_string()));
        assert!(debug_output.contains(&FAKE_CHAIN.escape_debug().to_string()));
        assert!(debug_output.contains("** redacted **"));
        assert!(!debug_output.contains("SECRET_KEY_DATA"));
    }

    #[cfg(feature = "fips")]
    mod fips_error_paths {
        use super::*;

        #[test]
        fn rejects_wrong_pem_label() {
            // Valid base64, but wrong label (not "ENCRYPTED PRIVATE KEY")
            let pem = "-----BEGIN FAKE CERTIFICATE-----\nMIIBkTCB+wIJAL2p0v4AAAAAMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMTBnRl\nc3RjYTAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEwMDAwMDBaMBExDzANBgNVBAMT\nBnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAAwtAMD0CIQD+r00B\n-----END FAKE CERTIFICATE-----";
            let passphrase = Passphrase(Zeroizing::new(b"pass".to_vec()));
            let result = passphrase.decrypt_private_key(pem);
            assert!(
                matches!(result, Err(AcmManagerError::InternalFailure(msg)) if msg.contains("unexpected PEM label"))
            );
        }

        #[test]
        fn rejects_invalid_pem() {
            let passphrase = Passphrase(Zeroizing::new(b"pass".to_vec()));
            let result = passphrase.decrypt_private_key("not valid pem at all");
            assert!(
                matches!(result, Err(AcmManagerError::InternalFailure(msg)) if msg.contains("failed to decode PEM"))
            );
        }
    }
}
