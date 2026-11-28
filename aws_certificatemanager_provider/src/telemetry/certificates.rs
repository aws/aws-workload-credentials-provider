//! A record's certificates as the telemetry request carries them: DER, within
//! the service model's limits. The request is rejected whole for one
//! certificate outside a limit, so the records drop what doesn't fit instead.

use aws_workload_credentials_provider_common::telemetry::request::MAX_CERTIFICATE_BYTES;
use aws_workload_credentials_provider_common::telemetry::Blob;
use base64ct::{Base64, Encoding};

/// Decoded length of padded standard base64, without decoding it.
pub(crate) fn der_len(base64: &str) -> usize {
    let padding = base64.bytes().rev().take_while(|&b| b == b'=').count();
    (base64.len() / 4 * 3).saturating_sub(padding)
}

/// Whether the base64 certificate is over [`MAX_CERTIFICATE_BYTES`].
fn is_oversized(base64: &str) -> bool {
    der_len(base64) > MAX_CERTIFICATE_BYTES
}

/// Whether the request can carry the base64 certificate: 1 to
/// [`MAX_CERTIFICATE_BYTES`] bytes of valid base64.
pub(crate) fn is_sendable(base64: &str) -> bool {
    sendable(base64).is_some()
}

/// The leaf and chain as DER. A leaf the request can't carry (over the limit,
/// empty, or not valid base64) sends neither. The chain keeps the
/// certificates closest to the leaf and ends before the first one the request
/// can't carry; the request keeps at most its first 5. Neither an empty nor
/// an undecodable certificate can come from the agent's own encoding.
pub(crate) fn certificates(
    leaf: Option<&str>,
    chain: Option<&[String]>,
) -> (Option<Blob>, Option<Vec<Blob>>) {
    let leaf = match leaf.map(sendable) {
        None => None,
        Some(None) => return (None, None),
        Some(leaf) => leaf,
    };
    let chain = chain.map(|chain| chain.iter().map_while(|der| sendable(der)).collect());
    (leaf, chain)
}

/// The certificate as DER, if it is 1 to [`MAX_CERTIFICATE_BYTES`] bytes of
/// valid base64.
fn sendable(base64: &str) -> Option<Blob> {
    if is_oversized(base64) {
        return None;
    }
    Base64::decode_vec(base64)
        .ok()
        .filter(|der| !der.is_empty())
        .map(Blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_der(len: usize) -> String {
        Base64::encode_string(&vec![0x30; len])
    }

    fn lens(chain: &Option<Vec<Blob>>) -> Option<Vec<usize>> {
        chain
            .as_ref()
            .map(|chain| chain.iter().map(|der| der.0.len()).collect())
    }

    /// Validates the decoded length of padded base64 with zero, one and two
    /// padding characters, around the limit.
    #[test]
    fn der_len_is_the_decoded_length() {
        for len in [0, 1, 2, 3, 16_383, 16_384, 16_385] {
            assert_eq!(der_len(&base64_der(len)), len, "{len}");
        }
    }

    /// Validates each shape: a leaf at the limit is kept; a leaf over it,
    /// empty, or undecodable sends neither certificate; the chain ends before
    /// its first oversized, empty or undecodable certificate.
    #[test]
    fn certificates_follow_the_model_limits() {
        let over = MAX_CERTIFICATE_BYTES + 1;
        // Leaf, chain, then the leaf and chain lengths sent.
        type Row = (String, Vec<String>, Option<usize>, Option<Vec<usize>>);
        let rows: [Row; 7] = [
            (
                base64_der(MAX_CERTIFICATE_BYTES),
                vec![base64_der(1), base64_der(2)],
                Some(MAX_CERTIFICATE_BYTES),
                Some(vec![1, 2]),
            ),
            (
                base64_der(1),
                vec![base64_der(1), base64_der(over), base64_der(3)],
                Some(1),
                Some(vec![1]),
            ),
            (
                base64_der(1),
                vec![base64_der(1), "@@@@".to_string(), base64_der(3)],
                Some(1),
                Some(vec![1]),
            ),
            (
                base64_der(1),
                vec![base64_der(1), String::new(), base64_der(3)],
                Some(1),
                Some(vec![1]),
            ),
            (base64_der(over), vec![base64_der(1)], None, None),
            ("@@@@".to_string(), vec![base64_der(1)], None, None),
            (String::new(), vec![base64_der(1)], None, None),
        ];
        for (row, (leaf, chain, expected_leaf, expected_chain)) in rows.into_iter().enumerate() {
            let (sent_leaf, sent_chain) = certificates(Some(&leaf), Some(&chain));
            assert_eq!(sent_leaf.map(|der| der.0.len()), expected_leaf, "row {row}");
            assert_eq!(lens(&sent_chain), expected_chain, "row {row}");
        }
    }

    /// Validates that absent certificates stay absent, and that a chain
    /// without a leaf is still sent.
    #[test]
    fn absent_certificates_stay_absent() {
        assert_eq!(certificates(None, None), (None, None));
        assert_eq!(
            lens(&certificates(None, Some(&[base64_der(2)])).1),
            Some(vec![2])
        );
    }
}
