/// Platform-specific file permission descriptor.
///
/// On Unix, wraps a mode bitmask (e.g. `0o600`).
/// On Windows, wraps an access-mask / trustee pair for DACL manipulation.
///
/// Usage:
/// unix:
///     owner_rw = PathPermission{ mode: 0o600 }
///     world_read = PathPermission{ mode: 0o644 }
///
/// windows:
///    add_world_read = PathPermission {
///        trustee_type: TrusteeType::Group,
///        trustee_name: "Everyone",
///        rights: Rights::Read,
///    }
///
/// The types `TrusteeType` and `Rights` and the windows PathPermission need the `Deserialize` trait
///  as they are used directly in the PermissionConfig type in the validation logic.
#[cfg(windows)]
use serde::Deserialize;

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq)]
pub struct PathPermission {
    pub mode: u32,
}

#[cfg(windows)]
#[derive(Clone, Deserialize, Debug, PartialEq)]
pub enum TrusteeType {
    #[serde(alias = "group", alias = "GROUP")]
    Group,
    #[serde(alias = "user", alias = "USER")]
    User,
}

/// Configured rights that map to windows ACE entry created for given trustee configurations
#[cfg(windows)]
#[derive(Clone, Deserialize, Debug, PartialEq)]
pub enum Rights {
    #[serde(alias = "read", alias = "READ")]
    Read, // Maps to setting Allow GENERIC_READ permission for the resource
}

/// This type should only be used to hold permissions that have passed validation
/// Same as PermissionConfig type in config/types.rs (derived traits notwithstanding)
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq)]
pub struct PathPermission {
    pub trustee_type: TrusteeType,
    pub trustee_name: String,
    pub rights: Rights,
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde::Deserialize;

    /// Helper struct to deserialize a PermissionConfig-like payload.
    /// Needed for testing on unix
    #[derive(Deserialize, Debug, PartialEq)]
    struct TestPermission {
        trustee_type: TrusteeType,
        trustee_name: String,
        rights: Rights,
    }

    // ── Full PermissionConfig-style payload ────────────────────────

    #[test]
    fn full_config_lowercase_variants() {
        let json = r#"{
            "trustee_type": "group",
            "trustee_name": "Everyone",
            "rights": "read"
        }"#;
        let cfg: TestPermission = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.trustee_type, TrusteeType::Group);
        assert_eq!(cfg.rights, Rights::Read);
    }

    #[test]
    fn full_config_uppercase_variants() {
        let json = r#"{
            "trustee_type": "GROUP",
            "trustee_name": "Administrators",
            "rights": "READ"
        }"#;
        let cfg: TestPermission = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.trustee_type, TrusteeType::Group);
        assert_eq!(cfg.rights, Rights::Read);
    }

    #[test]
    fn full_config_mixed_case_rights_rejected() {
        let json = r#"{
            "trustee_type": "Group",
            "trustee_name": "Everyone",
            "rights": "rEAD"
        }"#;
        let result: Result<TestPermission, _> = serde_json::from_str(json);
        assert!(result.is_err(), "mixed-case 'rEAD' in rights should fail");
    }
}
