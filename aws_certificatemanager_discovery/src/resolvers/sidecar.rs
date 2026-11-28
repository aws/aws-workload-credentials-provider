//! Discovery target resolution for sidecars colocated with container workloads.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::resolvers::{expand_discovery_targets, DiscoveryTargetResolver};
use crate::types::ProbeTarget;

/// Resolves sidecar discovery targets through the shared container network namespace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SidecarResolver;

impl SidecarResolver {
    /// Creates a sidecar resolver.
    pub fn new() -> Self {
        Self
    }
}

impl DiscoveryTargetResolver for SidecarResolver {
    fn resolve_targets(
        &self,
        discovery_targets: &HashMap<u16, Vec<String>>,
        _timeout: Duration,
    ) -> Vec<ProbeTarget> {
        expand_discovery_targets(
            discovery_targets,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            self.fallback_address(),
        )
    }

    fn supports_sni(&self) -> bool {
        true
    }

    fn fallback_address(&self) -> Option<IpAddr> {
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::resolvers::{discovery_targets, loopback_target};

    const IPV4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const IPV6_LOOPBACK: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    /// Validates that the constructor returns the derived default resolver.
    #[test]
    fn new_matches_the_derived_default() {
        assert_eq!(SidecarResolver::new(), SidecarResolver);
    }

    /// Validates that configured ports resolve to IPv4 loopback targets with
    /// an IPv6 fallback and one SNI target for the valid hostname.
    #[test]
    fn configured_ports_resolve_to_ipv4_loopback_with_ipv6_fallback() {
        let discovery_targets =
            discovery_targets([(8443, &[][..]), (443, &["api.example.com"][..])]);

        let targets =
            SidecarResolver::new().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(
            targets,
            vec![
                loopback_target(443),
                loopback_target(443)
                    .with_sni("api.example.com")
                    .expect("valid sni"),
                loopback_target(8443),
            ]
        );
        assert!(targets.iter().all(|target| {
            target.address == IPV4_LOOPBACK && target.fallback_address == Some(IPV6_LOOPBACK)
        }));
    }

    /// Validates that each valid SNI value adds a target and invalid values
    /// are skipped while the bare target remains.
    #[test]
    fn each_valid_sni_adds_a_target_and_invalid_values_are_skipped() {
        let discovery_targets = discovery_targets([(
            443,
            &[
                "api.example.com",
                "bad host.example",
                "web.example.com.",
                "127.0.0.1",
            ][..],
        )]);

        let targets =
            SidecarResolver::new().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(
            targets,
            vec![
                loopback_target(443),
                loopback_target(443)
                    .with_sni("api.example.com")
                    .expect("valid sni"),
                loopback_target(443)
                    .with_sni("web.example.com")
                    .expect("valid sni"),
            ]
        );
    }

    /// Validates that port zero is skipped while the other configured port
    /// still resolves.
    #[test]
    fn port_zero_is_skipped_without_affecting_other_ports() {
        let discovery_targets =
            discovery_targets([(0, &["ignored.example.com"][..]), (443, &[][..])]);

        let targets =
            SidecarResolver::new().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(targets, vec![loopback_target(443)]);
    }

    /// Validates that an empty discovery target map resolves to no targets.
    #[test]
    fn no_discovery_targets_yields_no_targets() {
        assert!(SidecarResolver::new()
            .resolve_targets(&HashMap::new(), Duration::from_secs(300))
            .is_empty());
    }

    /// Validates that the sidecar resolver reports SNI support and its IPv6
    /// loopback fallback address.
    #[test]
    fn sidecar_capabilities_report_sni_and_ipv6_fallback() {
        let resolver = SidecarResolver::new();

        assert!(resolver.supports_sni());
        assert_eq!(resolver.fallback_address(), Some(IPV6_LOOPBACK));
    }
}
