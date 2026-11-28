//! The discovery target resolution trait, implemented once per deployment mode.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use log::warn;

use crate::types::ProbeTarget;
use crate::validation::normalize_sni;

mod host_agent;
mod sidecar;

pub use host_agent::{HostAgentResolver, HostAgentResolverError};
pub use sidecar::SidecarResolver;

pub(crate) fn sni_target(base: &ProbeTarget, sni: &str, port: u16) -> Option<ProbeTarget> {
    base.clone()
        .with_sni(sni)
        .map_err(|error| {
            warn!("ignoring invalid SNI {sni:?} for port {port}: {error}");
        })
        .ok()
}

pub(crate) fn expand_discovery_targets(
    discovery_targets: &HashMap<u16, Vec<String>>,
    primary_address: IpAddr,
    fallback_address: Option<IpAddr>,
) -> Vec<ProbeTarget> {
    let mut targets = Vec::new();
    let mut ports: Vec<u16> = discovery_targets.keys().copied().collect();
    ports.sort_unstable();

    for port in ports.into_iter().filter(|port| *port != 0) {
        let mut base = ProbeTarget::new(primary_address, port);
        if let Some(fallback_address) = fallback_address {
            base = base.with_fallback_address(fallback_address);
        }
        targets.push(base.clone());

        for configured_sni in &discovery_targets[&port] {
            let Some(sni) = normalize_sni(configured_sni) else {
                warn!(
                    "ignoring invalid SNI {configured_sni:?} for port {port}: not a valid DNS hostname"
                );
                continue;
            };

            if let Some(target) = sni_target(&base, sni, port) {
                targets.push(target);
            }
        }
    }

    targets
}

#[cfg(test)]
fn discovery_targets<const N: usize>(entries: [(u16, &[&str]); N]) -> HashMap<u16, Vec<String>> {
    entries
        .into_iter()
        .map(|(port, hosts)| (port, hosts.iter().map(|host| host.to_string()).collect()))
        .collect()
}

#[cfg(test)]
fn loopback_target(port: u16) -> ProbeTarget {
    ProbeTarget::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
        .with_fallback_address(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
}

/// Resolves configured discovery targets into deployment-specific probe targets.
pub trait DiscoveryTargetResolver: Send + Sync {
    /// Expands each configured port and SNI list into targets for this deployment mode.
    fn resolve_targets(
        &self,
        discovery_targets: &HashMap<u16, Vec<String>>,
        timeout: Duration,
    ) -> Vec<ProbeTarget>;

    /// Reports whether this deployment mode can send configured SNI names.
    fn supports_sni(&self) -> bool;

    /// Returns the address used after a primary connection refusal, when configured.
    fn fallback_address(&self) -> Option<IpAddr>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::validation::is_connectable;

    struct FixedResolver;

    impl DiscoveryTargetResolver for FixedResolver {
        fn resolve_targets(
            &self,
            discovery_targets: &HashMap<u16, Vec<String>>,
            _timeout: Duration,
        ) -> Vec<ProbeTarget> {
            discovery_targets
                .keys()
                .copied()
                .map(ProbeTarget::ipv4_loopback)
                .filter(|target| is_connectable(&target.address))
                .collect()
        }

        fn supports_sni(&self) -> bool {
            false
        }

        fn fallback_address(&self) -> Option<IpAddr> {
            None
        }
    }

    /// Validates ascending port expansion, skips port zero, and copies the
    /// fallback address to every bare and SNI target.
    #[test]
    fn expand_discovery_targets_orders_ports_skips_zero_and_propagates_fallback() {
        let primary = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let fallback = IpAddr::V6("2001:db8::10".parse().expect("valid address"));
        let discovery_targets = discovery_targets([
            (0, &["ignored.example.com"][..]),
            (8443, &[][..]),
            (443, &["api.example.com"][..]),
        ]);

        let targets = expand_discovery_targets(&discovery_targets, primary, Some(fallback));

        assert_eq!(
            targets,
            vec![
                ProbeTarget::new(primary, 443).with_fallback_address(fallback),
                ProbeTarget::new(primary, 443)
                    .with_fallback_address(fallback)
                    .with_sni("api.example.com")
                    .expect("valid sni"),
                ProbeTarget::new(primary, 8443).with_fallback_address(fallback),
            ]
        );
        assert!(targets
            .iter()
            .all(|target| target.fallback_address == Some(fallback)));
    }

    /// Validates that expanded targets leave the fallback address unset when
    /// no fallback is provided.
    #[test]
    fn expand_discovery_targets_without_fallback_leaves_fallback_unset() {
        let primary = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let discovery_targets = discovery_targets([(443, &["api.example.com"][..])]);

        let targets = expand_discovery_targets(&discovery_targets, primary, None);

        assert_eq!(
            targets,
            vec![
                ProbeTarget::new(primary, 443),
                ProbeTarget::new(primary, 443)
                    .with_sni("api.example.com")
                    .expect("valid sni"),
            ]
        );
        assert!(targets
            .iter()
            .all(|target| target.fallback_address.is_none()));
    }

    /// Validates that the resolver trait can be used through a trait object
    /// and that its methods return the expected fixed-resolver values.
    #[test]
    fn the_trait_is_object_safe() {
        let resolver: Box<dyn DiscoveryTargetResolver> = Box::new(FixedResolver);

        let targets = resolver.resolve_targets(
            &HashMap::from([(443, Vec::new())]),
            Duration::from_secs(300),
        );

        assert_eq!(targets, vec![ProbeTarget::ipv4_loopback(443)]);
        assert_eq!(targets[0].address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(!resolver.supports_sni());
        assert_eq!(resolver.fallback_address(), None);
    }

    /// Validates that an accepted SNI name is attached to a cloned probe
    /// target.
    #[test]
    fn sni_target_sets_the_hostname_on_a_name_rustls_accepts() {
        let base = ProbeTarget::ipv4_loopback(443);

        let target = sni_target(&base, "api.example.com", 443).expect("rustls accepts the name");

        assert_eq!(target, base.with_sni("api.example.com").expect("valid sni"));
    }

    /// Validates that rejected SNI names produce no target.
    #[test]
    fn sni_target_skips_names_rustls_rejects() {
        let base = ProbeTarget::ipv4_loopback(443);

        for rejected in ["", "api..example.com", &"a".repeat(64)] {
            assert_eq!(
                sni_target(&base, rejected, 443),
                None,
                "expected rustls to reject {rejected:?}"
            );
        }
    }
}
