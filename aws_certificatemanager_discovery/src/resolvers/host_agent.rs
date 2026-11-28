//! Discovery target resolution for the EC2 host agent.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::resolvers::{expand_discovery_targets, DiscoveryTargetResolver};
use crate::types::ProbeTarget;
use crate::validation::is_connectable;

/// Resolves host-agent discovery targets against a primary host address and optional fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAgentResolver {
    address: IpAddr,
    fallback_address: Option<IpAddr>,
}

/// An invalid network address supplied to [`HostAgentResolver::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAgentResolverError {
    /// The primary address cannot identify a unicast connection target.
    PrimaryNotConnectable(IpAddr),
    /// The fallback address cannot identify a unicast connection target.
    FallbackNotConnectable(IpAddr),
}

impl fmt::Display for HostAgentResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimaryNotConnectable(address) => {
                write!(f, "host-agent address is not connectable: {address}")
            }
            Self::FallbackNotConnectable(address) => {
                write!(
                    f,
                    "host-agent fallback address is not connectable: {address}"
                )
            }
        }
    }
}

impl Error for HostAgentResolverError {}

impl HostAgentResolver {
    /// Creates a resolver after validating the primary and fallback addresses.
    ///
    /// Returns an error when either address is unspecified, multicast, or broadcast.
    pub fn new(
        address: IpAddr,
        fallback_address: Option<IpAddr>,
    ) -> Result<Self, HostAgentResolverError> {
        if !is_connectable(&address) {
            return Err(HostAgentResolverError::PrimaryNotConnectable(address));
        }
        if let Some(fallback_address) =
            fallback_address.filter(|fallback_address| !is_connectable(fallback_address))
        {
            return Err(HostAgentResolverError::FallbackNotConnectable(
                fallback_address,
            ));
        }

        Ok(Self {
            address,
            fallback_address,
        })
    }
}

impl DiscoveryTargetResolver for HostAgentResolver {
    fn resolve_targets(
        &self,
        discovery_targets: &HashMap<u16, Vec<String>>,
        _timeout: Duration,
    ) -> Vec<ProbeTarget> {
        expand_discovery_targets(discovery_targets, self.address, self.fallback_address())
    }

    fn supports_sni(&self) -> bool {
        true
    }

    fn fallback_address(&self) -> Option<IpAddr> {
        self.fallback_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::resolvers::{discovery_targets, loopback_target};
    use crate::validation::is_connectable;

    const IPV4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const IPV6_LOOPBACK: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    fn loopback_resolver() -> HostAgentResolver {
        HostAgentResolver::new(IPV4_LOOPBACK, Some(IPV6_LOOPBACK))
            .expect("loopback addresses are connectable")
    }

    /// Validates that a configured port produces one bare target followed by
    /// one target for each valid SNI hostname.
    #[test]
    fn a_port_with_sni_entries_yields_one_bare_target_plus_one_per_hostname() {
        let discovery_targets =
            discovery_targets([(443, &["api.example.com", "web.example.com"][..])]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

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

    /// Validates that an empty SNI list produces only the bare target and
    /// leaves its SNI unset.
    #[test]
    fn a_port_mapped_to_an_empty_sni_list_yields_only_the_bare_target() {
        let discovery_targets = discovery_targets([(8443, &[][..])]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(targets, vec![loopback_target(8443)]);
        assert!(targets[0].sni.is_none());
    }

    /// Validates that ports expand independently in ascending order, with
    /// each port's SNI entries following its bare target.
    #[test]
    fn ports_are_expanded_independently_and_in_ascending_order() {
        let discovery_targets = discovery_targets([
            (9443, &[][..]),
            (8443, &[][..]),
            (443, &["api.example.com"][..]),
        ]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(
            targets,
            vec![
                loopback_target(443),
                loopback_target(443)
                    .with_sni("api.example.com")
                    .expect("valid sni"),
                loopback_target(8443),
                loopback_target(9443),
            ]
        );
    }

    /// Validates that port zero and its SNI values are skipped while another
    /// configured port still produces a target.
    #[test]
    fn port_zero_is_skipped_without_affecting_other_ports() {
        let discovery_targets =
            discovery_targets([(0, &["ignored.example.com"][..]), (443, &[][..])]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(targets, vec![loopback_target(443)]);
    }

    /// Validates that invalid SNI values are skipped and the bare target is
    /// retained.
    #[test]
    fn invalid_sni_values_are_skipped() {
        let invalid_sni = [
            "",
            "has whitespace.example",
            "null\0byte.example",
            "192.0.2.1",
            "2001:db8::1",
            "-leading.example",
            "trailing-.example",
            "bad_name.example",
            "double..example",
            "example.123",
        ];
        let discovery_targets = discovery_targets([(443, &invalid_sni)]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(targets, vec![loopback_target(443)]);
    }

    /// Validates that valid SNI values are added as targets, including a
    /// trailing-dot hostname after normalization and an uppercase hostname.
    #[test]
    fn valid_sni_values_pass_through() {
        let discovery_targets =
            discovery_targets([(443, &["example.com", "api-1.example.com.", "LOCALHOST"][..])]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(
            targets,
            vec![
                loopback_target(443),
                loopback_target(443)
                    .with_sni("example.com")
                    .expect("valid sni"),
                loopback_target(443)
                    .with_sni("api-1.example.com")
                    .expect("valid sni"),
                loopback_target(443)
                    .with_sni("LOCALHOST")
                    .expect("valid sni"),
            ]
        );
    }

    /// Validates that mixed SNI values produce the bare target and only the
    /// valid hostname targets.
    #[test]
    fn mixed_sni_values_keep_only_valid_entries() {
        let discovery_targets = discovery_targets([(
            443,
            &[
                "api.example.com",
                "",
                "bad host.example",
                "web.example.com",
                "127.0.0.1",
            ][..],
        )]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

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

    /// Validates that every resolved target uses the connectable primary and
    /// fallback addresses supplied by the resolver.
    #[test]
    fn all_resolved_targets_use_connectable_ipv4_primary_and_ipv6_fallback_addresses() {
        let discovery_targets =
            discovery_targets([(443, &["api.example.com"][..]), (8443, &[][..])]);

        let targets =
            loopback_resolver().resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|target| {
            target.address == IPV4_LOOPBACK
                && target.fallback_address == Some(IPV6_LOOPBACK)
                && is_connectable(&target.address)
                && target
                    .fallback_address
                    .is_some_and(|address| is_connectable(&address))
        }));
    }

    /// Validates that caller-provided primary and fallback addresses appear
    /// on every resolved target.
    #[test]
    fn caller_provided_addresses_are_used_for_every_target() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let fallback_address = IpAddr::V6("2001:db8::10".parse().expect("valid address"));
        let discovery_targets = discovery_targets([(443, &["api.example.com"][..])]);

        let targets = HostAgentResolver::new(address, Some(fallback_address))
            .expect("test addresses are connectable")
            .resolve_targets(&discovery_targets, Duration::from_secs(300));

        assert_eq!(targets.len(), 2);
        assert!(targets.iter().all(|target| {
            target.address == address && target.fallback_address == Some(fallback_address)
        }));
    }

    /// Validates that unspecified and multicast primary or fallback
    /// addresses are rejected with the corresponding errors and messages.
    #[test]
    fn non_connectable_addresses_are_rejected_at_construction() {
        let unspecified = "0.0.0.0".parse().expect("valid address");
        let multicast = "ff02::1".parse().expect("valid address");

        let primary_error = HostAgentResolver::new(unspecified, Some(IPV6_LOOPBACK))
            .expect_err("unspecified primary address must be rejected");
        let fallback_error = HostAgentResolver::new(IPV4_LOOPBACK, Some(multicast))
            .expect_err("multicast fallback address must be rejected");

        assert_eq!(
            primary_error,
            HostAgentResolverError::PrimaryNotConnectable(unspecified)
        );
        assert_eq!(
            primary_error.to_string(),
            "host-agent address is not connectable: 0.0.0.0"
        );
        assert_eq!(
            fallback_error,
            HostAgentResolverError::FallbackNotConnectable(multicast)
        );
        assert_eq!(
            fallback_error.to_string(),
            "host-agent fallback address is not connectable: ff02::1"
        );
    }

    /// Validates that an empty discovery target map resolves to no targets.
    #[test]
    fn no_discovery_targets_yields_no_targets() {
        assert!(loopback_resolver()
            .resolve_targets(&HashMap::new(), Duration::from_secs(300))
            .is_empty());
    }

    /// Validates that the host-agent resolver reports SNI support and its
    /// configured IPv6 fallback address.
    #[test]
    fn sni_probes_are_supported() {
        let resolver = loopback_resolver();

        assert!(resolver.supports_sni());
        assert_eq!(resolver.fallback_address(), Some(IPV6_LOOPBACK));
    }
}
