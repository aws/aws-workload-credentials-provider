# AWS Certificate Manager certificate discovery

`aws_certificatemanager_discovery` discovers TLS certificates presented by
configured endpoints. It resolves configured listener ports into probe targets,
opens a TLS connection to each target, and records the certificate chain that
the listener presents.

## TLS probing

The probe supports TLS 1.2 and TLS 1.3. It observes certificates rather than
validating trust, so expired, self-signed, and otherwise untrusted certificates
are still reported.

Each target can include an optional Server Name Indication (SNI) hostname. When
SNI names are configured for a port, resolvers emit a probe without SNI and one
probe for each valid hostname. A DNS presentation trailing dot is accepted but
omitted from the TLS HostName value. A target without a hostname is named by its
IP address, which suppresses the TLS SNI extension.

`SidecarResolver` probes IPv4 loopback first and retries IPv6 loopback when the
IPv4 connection is refused. It reaches only listeners that share its own network
namespace, so sidecar mode requires the platform to place the sidecar and the
application container in one namespace: ECS tasks in `awsvpc` mode, EKS pods, or
Docker containers started with `--network container:<app>` on Linux. Where each
container instead gets its own namespace, such as ECS on Windows EC2 in the
default NAT network mode, loopback does not reach the application container and
sidecar mode does not apply. Successful probes report the leaf certificate,
server-provided chain, and whether the server requested a client certificate.

## Workspace integration

This library separates endpoint resolution and TLS probing from the sibling
certificate-management components in this workspace. Callers:

1. Select the resolver for their deployment mode and provide its network
   addresses.
2. Pass configured ports and SNI hostnames to `resolve_targets`.
3. Call `ProbeTarget::probe` on each returned target with a `ProbeConfig`.
4. Consume the resulting `ProbeOutcome` and any captured certificate chain.

`HostAgentResolver` implements EC2 host-agent target resolution.
`SidecarResolver` is the only container resolver and implements colocated
loopback resolution for container workloads that share a network namespace with
the sidecar, under the conditions described in TLS probing above.
