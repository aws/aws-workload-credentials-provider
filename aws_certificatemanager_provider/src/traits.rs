//! Traits and types for the ACM Scheduler.

use crate::acm_manager::ExportedCertificate;
use crate::error::AcmManagerError;
use std::future::Future;

/// Interface for ACM certificate export operations.
///
/// Signature matches `AcmManager::export_certificate`.
pub(crate) trait AcmCertificateExporter: Send + Sync {
    fn export_certificate(
        &self,
        certificate_arn: &str,
        role_arn: &str,
    ) -> impl Future<Output = Result<ExportedCertificate, AcmManagerError>> + Send;
}
