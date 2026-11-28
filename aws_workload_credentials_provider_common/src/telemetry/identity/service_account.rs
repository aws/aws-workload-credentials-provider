//! Decodes, without verifying, the claims of the pod's service account tokens.
//! A token is a credential: it never leaves this module and is never logged.

use std::fs::File;
use std::io::{self, Read};

use base64ct::{Base64UrlUnpadded, Encoding};
use log::debug;

/// The default, IRSA and Pod Identity tokens. The last two are mounted even
/// with `automountServiceAccountToken: false`.
const TOKENS: [&str; 3] = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token",
];

/// Windows mounts these on `C:`, not the current drive.
#[cfg(windows)]
const ROOT: &str = "C:";
#[cfg(not(windows))]
const ROOT: &str = "";

/// Real tokens are a few KB.
const MAX_TOKEN: u64 = 64 * 1024;

/// Each token's claims JSON, in order, read lazily.
pub(super) fn claims() -> impl Iterator<Item = String> {
    claims_under(ROOT)
}

fn claims_under(root: &str) -> impl Iterator<Item = String> + '_ {
    TOKENS.into_iter().filter_map(move |path| {
        let path = format!("{root}{path}");
        let token = read(&path)
            .map_err(|error| debug!("EKS service account token {path}: {error}"))
            .ok()?;
        payload(&token)
    })
}

fn read(path: &str) -> io::Result<String> {
    let mut token = String::new();
    File::open(path)?
        .take(MAX_TOKEN + 1)
        .read_to_string(&mut token)?;
    if token.len() as u64 > MAX_TOKEN {
        return Err(io::Error::other("larger than a token"));
    }
    Ok(token)
}

fn payload(token: &str) -> Option<String> {
    let segment = token.split('.').nth(1)?;
    String::from_utf8(Base64UrlUnpadded::decode_vec(segment).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_the_decoded_middle_segment() {
        let json = r#"{"iss":"https://oidc.eks.us-east-2.amazonaws.com/id/D43CF17C27A865933144EA99A26FB128"}"#;
        let token = format!(
            "e30.{}.c2ln",
            Base64UrlUnpadded::encode_string(json.as_bytes())
        );
        assert_eq!(payload(&token).as_deref(), Some(json));
    }

    #[test]
    fn claims_skip_missing_tokens_and_read_lazily() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let write = |path: &str, claims: &str| {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let encoded = Base64UrlUnpadded::encode_string(claims.as_bytes());
            std::fs::write(path, format!("e30.{encoded}.c2ln")).unwrap();
        };
        write(
            "var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            "irsa",
        );
        let mut claims = claims_under(root);
        assert_eq!(claims.next().as_deref(), Some("irsa"));
        write(
            "var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token",
            "pod identity",
        );
        assert_eq!(claims.next().as_deref(), Some("pod identity"));
        assert_eq!(claims.next(), None);
        write(
            "var/run/secrets/kubernetes.io/serviceaccount/token",
            "default",
        );
        assert_eq!(claims_under(root).next().as_deref(), Some("default"));
    }

    #[test]
    fn read_rejects_a_file_larger_than_a_token() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        std::fs::write(path, vec![b'e'; MAX_TOKEN as usize]).unwrap();
        assert!(read(path).is_ok());
        // Non-UTF-8 past the cap: only an uncapped read sees it.
        let mut big = vec![b'e'; MAX_TOKEN as usize + 1];
        big.push(0xFF);
        std::fs::write(path, big).unwrap();
        assert_eq!(read(path).unwrap_err().kind(), io::ErrorKind::Other);
    }

    #[test]
    fn payload_rejects_non_jwt() {
        for token in ["", "e30.!!!.c2ln", "e30._w.c2ln"] {
            assert_eq!(payload(token), None, "{token}");
        }
    }
}
