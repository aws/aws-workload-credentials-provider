//! Discovery target resolution and TLS port probing for certificate discovery.

use std::time::Duration;

mod probe;
mod resolvers;
mod types;
mod validation;
mod verifier;

pub use resolvers::{
    DiscoveryTargetResolver, HostAgentResolver, HostAgentResolverError, SidecarResolver,
};
pub use types::{ProbeConfig, ProbeOutcome, ProbeSuccess, ProbeTarget};
pub use validation::{is_connectable, is_valid_sni};

/// Default budget for TCP connection and TLS handshake together.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
