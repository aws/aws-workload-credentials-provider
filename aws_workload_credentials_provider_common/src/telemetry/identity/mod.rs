//! Agent identity for telemetry. Compute types are tried in the order Lambda,
//! ECS, EKS, EC2. IMDS is last because inside a container on EC2 it answers
//! with the host's identity, not the container's. A container signal never
//! falls through to IMDS: a failed ECS fetch, ECS v3 only, and a pod without
//! an EKS token all fail closed.

use std::fmt;
use std::future::Future;

use log::debug;
use serde::Deserialize;

use super::payload::DeploymentType;

mod imds;
mod service_account;
mod task_metadata;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    /// The agent's identifier.
    pub host_id: String,
    /// Which AWS compute this process runs on.
    pub deployment_type: DeploymentType,
    /// Region the compute reports itself running in.
    pub region: String,
    /// Tells apart two runs on the same host, since `batch_sequence` restarts at zero.
    pub boot_nonce: String,
    /// The ECS task's network mode (`awsvpc`, `bridge`, `host` or `none`), as
    /// its task metadata reports it. `None` off ECS, and on ECS unless every
    /// container network in the task reports the same `NetworkMode`.
    pub ecs_network_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    NoIdentityFound,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::NoIdentityFound => f.write_str(
                "Cannot determine host identity, telemetry disabled. \
                 Ensure IMDS is accessible or running on supported AWS compute.",
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

impl AgentIdentity {
    /// Call once per process, off the startup path; may take a few seconds
    /// when IMDS or the ECS agent is unreachable.
    pub async fn detect() -> Result<Self, IdentityError> {
        let env = |key: &str| std::env::var(key).ok();
        Self::detect_with(
            &env,
            task_metadata::task(&env),
            service_account::claims(),
            imds::instance_identity_document(&env),
        )
        .await
    }

    async fn detect_with(
        env: &impl Fn(&str) -> Option<String>,
        fetch_ecs_task: impl Future<Output = Option<String>>,
        eks_claims: impl IntoIterator<Item = String>,
        fetch_ec2_document: impl Future<Output = Option<String>>,
    ) -> Result<Self, IdentityError> {
        if let Some(compute) = lambda(env) {
            return Ok(Self::new(compute));
        }
        if env(task_metadata::URI_V4).is_some() {
            return fetch_ecs_task
                .await
                .as_deref()
                .and_then(ecs)
                .map(Self::new)
                .ok_or(IdentityError::NoIdentityFound);
        }
        if env("ECS_CONTAINER_METADATA_URI").is_some() {
            return Err(IdentityError::NoIdentityFound);
        }
        if env("KUBERNETES_SERVICE_HOST").is_some() {
            let compute = eks_claims.into_iter().find_map(|claims| eks(&claims));
            if compute.is_none() {
                debug!("EKS: no service account token is from an EKS pod");
            }
            return compute.map(Self::new).ok_or(IdentityError::NoIdentityFound);
        }
        fetch_ec2_document
            .await
            .as_deref()
            .and_then(ec2)
            .map(Self::new)
            .ok_or(IdentityError::NoIdentityFound)
    }

    fn new(compute: Compute) -> Self {
        Self {
            host_id: compute.host_id,
            deployment_type: compute.deployment_type,
            region: compute.region,
            boot_nonce: uuid::Uuid::new_v4().to_string(),
            ecs_network_mode: compute.ecs_network_mode,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Compute {
    host_id: String,
    deployment_type: DeploymentType,
    region: String,
    ecs_network_mode: Option<String>,
}

/// All concurrent instances of a function share this `host_id`; only
/// `boot_nonce` tells them apart.
fn lambda(env: &impl Fn(&str) -> Option<String>) -> Option<Compute> {
    let name = env("AWS_LAMBDA_FUNCTION_NAME")?;
    let version = env("AWS_LAMBDA_FUNCTION_VERSION")?;
    let region = env("AWS_REGION")?;
    if name.is_empty() || version.is_empty() || region.is_empty() {
        return None;
    }
    Some(Compute {
        host_id: format!("{name}:{version}"),
        deployment_type: DeploymentType::Lambda,
        region,
        ecs_network_mode: None,
    })
}

/// Every container in a task shares this `host_id`: the `TaskARN` as the task
/// metadata endpoint gives it, which carries the account ID and the
/// customer-chosen cluster name. `None` unless it is an `ecs` ARN with a
/// region whose resource starts with `task/` and ends in a non-empty task ID;
/// nothing else in it is checked.
fn ecs(body: &str) -> Option<Compute> {
    #[derive(Deserialize)]
    struct Task {
        #[serde(rename = "TaskARN")]
        task_arn: String,
        /// Kept untyped so an unexpected `Containers` shape loses only the
        /// network mode, not the identity.
        #[serde(rename = "Containers", default)]
        containers: serde_json::Value,
    }
    let task: Task = serde_json::from_str(body).ok()?;
    let arn: Vec<&str> = task.task_arn.splitn(6, ':').collect();
    let ["arn", _, "ecs", region, _, resource] = arn[..] else {
        return None;
    };
    let task_id = resource.strip_prefix("task/")?.rsplit('/').next()?;
    if region.is_empty() || task_id.is_empty() {
        return None;
    }
    let region = region.to_string();
    Some(Compute {
        host_id: task.task_arn,
        deployment_type: DeploymentType::Ecs,
        region,
        ecs_network_mode: ecs_network_mode(&task.containers),
    })
}

/// The `NetworkMode` shared by every container network in the task. All
/// containers of a task share one mode, so a missing mode, two different
/// modes, or a `Containers` value that is missing or not an array gives `None`.
fn ecs_network_mode(containers: &serde_json::Value) -> Option<String> {
    let mut modes = containers
        .as_array()?
        .iter()
        .filter_map(|container| container.get("Networks")?.as_array())
        .flatten()
        .map(|network| {
            network
                .get("NetworkMode")
                .and_then(serde_json::Value::as_str)
        });
    let first = modes.next()??;
    modes
        .all(|mode| mode == Some(first))
        .then(|| first.to_string())
}

/// EKS issuer hosts, `<prefix><region><suffix>`. ISO partitions fail closed.
const EKS_ISSUERS: [(&str, &str); 6] = [
    ("oidc.eks.", ".amazonaws.com"),
    ("oidc.eks.", ".amazonaws.com.cn"),
    ("oidc.eks.", ".amazonaws.eu"),
    ("oidc-eks.", ".api.aws"),
    ("oidc-eks.", ".api.amazonwebservices.com.cn"),
    ("oidc-eks.", ".api.amazonwebservices.eu"), // not publicly documented
];

/// The region in an `EKS_ISSUERS` host.
fn eks_region(host: &str) -> Option<&str> {
    for (prefix, suffix) in EKS_ISSUERS {
        let region_and_suffix = host.strip_prefix(prefix);
        if let Some(region) = region_and_suffix.and_then(|s| s.strip_suffix(suffix)) {
            if is_region(region) {
                return Some(region);
            }
        }
    }
    None
}

/// Shaped like a region such as `us-east-2`.
pub(crate) fn is_region(name: &str) -> bool {
    name.ends_with(|c: char| c.is_ascii_digit())
        && name
            .chars()
            .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
}

/// Every container in a pod shares this `host_id`: `namespace/pod name/pod UID`.
fn eks(body: &str) -> Option<Compute> {
    let claims: serde_json::Value = serde_json::from_str(body).ok()?;
    let namespace = claims
        .pointer("/kubernetes.io/namespace")?
        .as_str()
        .filter(|s| !s.is_empty())?;
    let pod = claims
        .pointer("/kubernetes.io/pod/name")?
        .as_str()
        .filter(|s| !s.is_empty())?;
    let uid = claims.pointer("/kubernetes.io/pod/uid")?.as_str()?;
    let iss = claims["iss"].as_str()?;
    let (host, id) = iss.strip_prefix("https://")?.split_once("/id/")?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let region = eks_region(host)?;
    Some(Compute {
        host_id: format!("{namespace}/{pod}/{}", uuid::Uuid::try_parse(uid).ok()?),
        deployment_type: DeploymentType::Eks,
        region: region.to_string(),
        ecs_network_mode: None,
    })
}

fn ec2(body: &str) -> Option<Compute> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Document {
        instance_id: String,
        region: String,
    }
    let document: Document = serde_json::from_str(body).ok()?;
    if document.instance_id.is_empty() || document.region.is_empty() {
        return None;
    }
    Some(Compute {
        host_id: document.instance_id,
        deployment_type: DeploymentType::Ec2,
        region: document.region,
        ecs_network_mode: None,
    })
}

#[cfg(test)]
mod tests {
    use std::future::{poll_fn, ready};

    use super::*;
    use crate::telemetry::payload::{Capability, PayloadEnvelope, PayloadType};

    const LAMBDA_ENV: &[(&str, &str)] = &[
        ("AWS_LAMBDA_FUNCTION_NAME", "my-function"),
        ("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST"),
        ("AWS_REGION", "us-east-2"),
    ];

    const ECS_ENV: &[(&str, &str)] = &[
        (
            "ECS_CONTAINER_METADATA_URI",
            "http://169.254.170.2/v3/a1b2c3d4-5678-90ab-cdef-EXAMPLEaaaaa",
        ),
        (
            "ECS_CONTAINER_METADATA_URI_V4",
            "http://169.254.170.2/v4/a1b2c3d4-5678-90ab-cdef-EXAMPLEaaaaa",
        ),
    ];

    const EC2_DOCUMENT: &str = r#"{
        "devpayProductCodes" : null,
        "marketplaceProductCodes" : [ "1abc2defghijklm3nopqrs4tu" ],
        "availabilityZone" : "us-west-2b",
        "privateIp" : "10.24.34.30",
        "version" : "2017-09-30",
        "instanceId" : "i-1234567890abcdef0",
        "billingProducts" : null,
        "instanceType" : "t2.micro",
        "accountId" : "123456789012",
        "imageId" : "ami-1234567890abcdef0",
        "pendingTime" : "2016-11-19T16:32:11Z",
        "architecture" : "x86_64",
        "kernelId" : null,
        "ramdiskId" : null,
        "region" : "us-west-2"
    }"#;

    const ECS_TASK: &str = r#"{
        "Cluster": "MyCluster",
        "TaskARN": "arn:aws:ecs:us-east-2:111122223333:task/MyCluster/1234567890abcdef1234567890abcdef",
        "Family": "MyTaskFamily",
        "Revision": "1",
        "DesiredStatus": "RUNNING",
        "KnownStatus": "RUNNING",
        "Limits": { "CPU": 0.25, "Memory": 512 },
        "AvailabilityZone": "us-east-2a",
        "LaunchType": "EC2",
        "Containers": [{
            "DockerId": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "Name": "app",
            "Image": "111122223333.dkr.ecr.us-east-2.amazonaws.com/my-repository:latest",
            "Labels": {
                "com.amazonaws.ecs.cluster": "MyCluster",
                "com.amazonaws.ecs.task-arn": "arn:aws:ecs:us-east-2:111122223333:task/MyCluster/1234567890abcdef1234567890abcdef"
            },
            "Limits": { "CPU": 2, "Memory": 0 },
            "Type": "NORMAL",
            "ContainerARN": "arn:aws:ecs:us-east-2:111122223333:container/MyCluster/1234567890abcdef1234567890abcdef/a1b2c3d4-5678-90ab-cdef-EXAMPLE22222",
            "Networks": [{ "NetworkMode": "bridge", "IPv4Addresses": ["10.24.34.10"] }]
        }],
        "VPCID": "vpc-1234567890abcdef0",
        "AvailabilityZoneID": "use2-az1"
    }"#;

    const KUBERNETES_ENV: &[(&str, &str)] = &[("KUBERNETES_SERVICE_HOST", "172.20.0.1")];

    const EKS_CLAIMS: &str = r#"{
        "aud": ["https://kubernetes.default.svc"],
        "exp": 1790975273,
        "iat": 1790888873,
        "iss": "https://oidc.eks.us-east-2.amazonaws.com/id/D43CF17C27A865933144EA99A26FB128",
        "jti": "a1b2c3d4-5678-90ab-cdef-EXAMPLE33333",
        "kubernetes.io": {
            "namespace": "my-namespace",
            "node": { "name": "ip-192-0-2-10.us-east-2.compute.internal", "uid": "a1b2c3d4-5678-90ab-cdef-EXAMPLE44444" },
            "pod": { "name": "my-app-5d7f8b9c6d-abcde", "uid": "a1b2c3d4-5678-90ab-cdef-1234567890ab" },
            "serviceaccount": { "name": "my-service-account", "uid": "a1b2c3d4-5678-90ab-cdef-EXAMPLE55555" },
            "warnafter": 1790892480
        },
        "nbf": 1790888873,
        "sub": "system:serviceaccount:my-namespace:my-service-account"
    }"#;

    const POD_UID: &str = "a1b2c3d4-5678-90ab-cdef-1234567890ab";
    const POD_HOST_ID: &str =
        "my-namespace/my-app-5d7f8b9c6d-abcde/a1b2c3d4-5678-90ab-cdef-1234567890ab";

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            vars.iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.to_string())
        }
    }

    fn must_not_be_probed(endpoint: &'static str) -> impl Future<Output = Option<String>> {
        poll_fn(move |_| panic!("{endpoint} was probed"))
    }

    fn must_not_be_read() -> impl Iterator<Item = String> {
        std::iter::from_fn(|| panic!("service account token was read"))
    }

    fn token_claims(iss: &str, uid: &str) -> String {
        format!(
            r#"{{"iss":"{iss}","kubernetes.io":{{"namespace":"my-namespace","pod":{{"name":"my-app-5d7f8b9c6d-abcde","uid":"{uid}"}}}}}}"#
        )
    }

    const OIDC_ID: &str = "D43CF17C27A865933144EA99A26FB128";
    const EKS_HOST: &str = "oidc.eks.us-east-2.amazonaws.com";

    /// A `POD_HOST_ID` token issued by `host`.
    fn issued_by(host: &str) -> String {
        token_claims(&format!("https://{host}/id/{OIDC_ID}"), POD_UID)
    }

    fn eks_identity(region: &str) -> Option<Compute> {
        Some(Compute {
            host_id: POD_HOST_ID.to_string(),
            deployment_type: DeploymentType::Eks,
            region: region.to_string(),
            ecs_network_mode: None,
        })
    }

    fn ecs_identity(task_arn: &str, region: &str, network_mode: Option<&str>) -> Option<Compute> {
        Some(Compute {
            host_id: task_arn.to_string(),
            deployment_type: DeploymentType::Ecs,
            region: region.to_string(),
            ecs_network_mode: network_mode.map(str::to_string),
        })
    }

    #[tokio::test]
    async fn ecs_v3_only_fails_closed_without_probing_imds() {
        let v3_only = &ECS_ENV[..1];
        assert_eq!(
            AgentIdentity::detect_with(
                &env(v3_only),
                must_not_be_probed("task metadata"),
                must_not_be_read(),
                must_not_be_probed("IMDS"),
            )
            .await,
            Err(IdentityError::NoIdentityFound)
        );
    }

    #[tokio::test]
    async fn ecs_env_is_ecs_without_probing_imds() {
        let identity = AgentIdentity::detect_with(
            &env(ECS_ENV),
            ready(Some(ECS_TASK.to_string())),
            must_not_be_read(),
            must_not_be_probed("IMDS"),
        )
        .await
        .unwrap();
        assert_eq!(identity.deployment_type, DeploymentType::Ecs);
    }

    #[tokio::test]
    async fn unreachable_task_metadata_fails_closed_without_probing_imds() {
        assert_eq!(
            AgentIdentity::detect_with(
                &env(ECS_ENV),
                ready(None),
                must_not_be_read(),
                must_not_be_probed("IMDS"),
            )
            .await,
            Err(IdentityError::NoIdentityFound)
        );
    }

    /// ECS task metadata yields the task ARN, region and `bridge` network mode.
    #[test]
    fn ecs_task_is_task_arn_region_and_network_mode() {
        assert_eq!(
            ecs(ECS_TASK),
            ecs_identity(
                "arn:aws:ecs:us-east-2:111122223333:task/MyCluster/1234567890abcdef1234567890abcdef",
                "us-east-2",
                Some("bridge")
            )
        );
    }

    /// The older task ARN format, without a cluster name, yields that task ARN
    /// and region, with no network mode.
    #[test]
    fn ecs_task_arn_without_cluster_is_task_arn() {
        let old_format = r#"{"TaskARN":"arn:aws:ecs:us-east-2:111122223333:task/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"}"#;
        assert_eq!(
            ecs(old_format),
            ecs_identity(
                "arn:aws:ecs:us-east-2:111122223333:task/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                "us-east-2",
                None
            )
        );
    }

    /// A `TaskARN` that isn't an ECS task ARN with a region and a task ID
    /// yields no identity.
    #[test]
    fn malformed_ecs_task_arn_is_no_identity() {
        for task_arn in [
            "",
            "1234567890abcdef1234567890abcdef",
            "arn:aws:ecs:us-east-2:111122223333",
            "arn:aws:ec2:us-east-2:111122223333:task/MyCluster/abc",
            "arn:aws:ecs::111122223333:task/MyCluster/abc",
            "arn:aws:ecs:us-east-2:111122223333:container/MyCluster/abc",
            "arn:aws:ecs:us-east-2:111122223333:task/",
            "arn:aws:ecs:us-east-2:111122223333:task/MyCluster/",
        ] {
            let body = format!(r#"{{"TaskARN":"{task_arn}"}}"#);
            assert_eq!(ecs(&body), None, "{task_arn}");
        }
    }

    /// `detect` carries the task's network mode into the identity.
    #[tokio::test]
    async fn ecs_identity_carries_the_network_mode() {
        let identity = AgentIdentity::detect_with(
            &env(ECS_ENV),
            ready(Some(ECS_TASK.to_string())),
            must_not_be_read(),
            must_not_be_probed("IMDS"),
        )
        .await
        .unwrap();
        assert_eq!(identity.ecs_network_mode.as_deref(), Some("bridge"));
    }

    /// A mode shared by every container network is the task's mode; otherwise `None`.
    #[test]
    fn ecs_network_mode_is_the_mode_every_container_reports() {
        let rows = [
            (
                r#"[{"Networks":[{"NetworkMode":"awsvpc"}]},{"Networks":[{"NetworkMode":"awsvpc"}]}]"#,
                Some("awsvpc"),
            ),
            (
                r#"[{"Name":"app"},{"Networks":[{"NetworkMode":"host"}]}]"#,
                Some("host"),
            ),
            ("[]", None),
            (r#"[{"Networks":[]}]"#, None),
            (r#"[{"Networks":[{"IPv4Addresses":["10.0.0.1"]}]}]"#, None),
            (
                r#"[{"Networks":[{"NetworkMode":"awsvpc"}]},{"Networks":[{"NetworkMode":"bridge"}]}]"#,
                None,
            ),
            (
                r#"[{"Networks":[{"NetworkMode":"awsvpc"},{"IPv4Addresses":[]}]}]"#,
                None,
            ),
        ];
        for (containers, expected) in rows {
            let containers: serde_json::Value =
                serde_json::from_str(containers).expect("valid fixture");
            assert_eq!(
                ecs_network_mode(&containers).as_deref(),
                expected,
                "{containers:?}"
            );
        }
    }

    /// An unexpected `Containers` shape loses only the network mode, not the identity.
    #[test]
    fn malformed_containers_keep_the_ecs_identity() {
        for containers in [
            r#"null"#,
            r#"{"Networks":[]}"#,
            r#"[{"Networks":"awsvpc"},7]"#,
        ] {
            let body = format!(
                r#"{{"TaskARN":"arn:aws:ecs:us-east-2:111122223333:task/c/abc","Containers":{containers}}}"#
            );
            assert_eq!(
                ecs(&body),
                ecs_identity(
                    "arn:aws:ecs:us-east-2:111122223333:task/c/abc",
                    "us-east-2",
                    None
                ),
                "{containers}"
            );
        }
    }

    #[tokio::test]
    async fn no_eks_token_fails_closed_without_probing_imds() {
        let non_eks = token_claims("https://kubernetes.default.svc.cluster.local", POD_UID);
        for claims in [vec![], vec![non_eks]] {
            assert_eq!(
                AgentIdentity::detect_with(
                    &env(KUBERNETES_ENV),
                    must_not_be_probed("task metadata"),
                    claims,
                    must_not_be_probed("IMDS"),
                )
                .await,
                Err(IdentityError::NoIdentityFound)
            );
        }
    }

    #[tokio::test]
    async fn eks_falls_back_to_the_next_token() {
        let identity = AgentIdentity::detect_with(
            &env(KUBERNETES_ENV),
            must_not_be_probed("task metadata"),
            ["<html>".to_string(), EKS_CLAIMS.to_string()],
            must_not_be_probed("IMDS"),
        )
        .await
        .unwrap();
        assert_eq!(identity.host_id, POD_HOST_ID);
    }

    #[tokio::test]
    async fn eks_reads_no_token_after_an_identity() {
        let claims = std::iter::once(EKS_CLAIMS.to_string()).chain(must_not_be_read());
        let identity = AgentIdentity::detect_with(
            &env(KUBERNETES_ENV),
            must_not_be_probed("task metadata"),
            claims,
            must_not_be_probed("IMDS"),
        )
        .await;
        assert!(identity.is_ok());
    }

    #[test]
    fn eks_claims_are_namespace_pod_uid_and_region() {
        assert_eq!(eks(EKS_CLAIMS), eks_identity("us-east-2"));
        for (host, region) in [
            ("oidc.eks.cn-north-1.amazonaws.com.cn", "cn-north-1"),
            ("oidc.eks.eusc-de-east-1.amazonaws.eu", "eusc-de-east-1"),
            ("oidc-eks.us-east-2.api.aws", "us-east-2"),
            (
                "oidc-eks.cn-north-1.api.amazonwebservices.com.cn",
                "cn-north-1",
            ),
            (
                "oidc-eks.eusc-de-east-1.api.amazonwebservices.eu",
                "eusc-de-east-1",
            ),
        ] {
            assert_eq!(eks(&issued_by(host)), eks_identity(region), "{host}");
        }
    }

    #[test]
    fn eks_rejects_non_eks_claims() {
        let iss = format!("https://{EKS_HOST}/id/{OIDC_ID}");
        let rows = [
            format!(r#"{{"iss":"{iss}","kubernetes.io/serviceaccount/namespace":"default"}}"#),
            issued_by("us-east-2.amazonaws.com"),
            issued_by("oidc.eks.foo.s3.us-east-1.amazonaws.com"),
            issued_by("oidc.eks.acme-payments-prod.amazonaws.com"),
            issued_by("oidc.eks.US-EAST-2.amazonaws.com"),
            token_claims(&format!("https://{EKS_HOST}/id/"), POD_UID),
            token_claims(&format!("https://{EKS_HOST}/id/nothex"), POD_UID),
            token_claims(&format!("https://{EKS_HOST}"), POD_UID),
            token_claims(&format!("http://{EKS_HOST}/id/{OIDC_ID}"), POD_UID),
            token_claims(&iss, "my-pod"),
            format!(
                r#"{{"iss":"{iss}","kubernetes.io":{{"pod":{{"name":"my-app","uid":"{POD_UID}"}}}}}}"#
            ),
            format!(
                r#"{{"iss":"{iss}","kubernetes.io":{{"namespace":"my-namespace","pod":{{"uid":"{POD_UID}"}}}}}}"#
            ),
            format!(
                r#"{{"iss":"{iss}","kubernetes.io":{{"namespace":"","pod":{{"name":"my-app","uid":"{POD_UID}"}}}}}}"#
            ),
            format!(
                r#"{{"iss":"{iss}","kubernetes.io":{{"namespace":"my-namespace","pod":{{"name":"","uid":"{POD_UID}"}}}}}}"#
            ),
        ];
        for row in rows {
            assert_eq!(eks(&row), None, "{row}");
        }
    }

    #[tokio::test]
    async fn ec2_document_is_instance_id_and_region() {
        let identity = AgentIdentity::detect_with(
            &env(&[]),
            must_not_be_probed("task metadata"),
            must_not_be_read(),
            ready(Some(EC2_DOCUMENT.to_string())),
        )
        .await
        .unwrap();
        assert_eq!(identity.deployment_type, DeploymentType::Ec2);
        assert_eq!(identity.host_id, "i-1234567890abcdef0");
        assert_eq!(identity.region, "us-west-2");
    }

    #[test]
    fn ec2_rejects_non_document() {
        assert_eq!(ec2("<html>"), None);
    }

    #[test]
    fn ec2_rejects_empty_instance_id() {
        assert_eq!(ec2(r#"{"instanceId":"","region":"us-west-2"}"#), None);
    }

    /// Lambda environment variables yield the function name, version and region.
    #[test]
    fn lambda_env_is_function_name_version_and_region() {
        assert_eq!(
            lambda(&env(LAMBDA_ENV)),
            Some(Compute {
                host_id: "my-function:$LATEST".to_string(),
                deployment_type: DeploymentType::Lambda,
                region: "us-east-2".to_string(),
                ecs_network_mode: None,
            })
        );
    }

    #[test]
    fn empty_lambda_value_is_no_identity() {
        let empty_name = env(&[
            ("AWS_LAMBDA_FUNCTION_NAME", ""),
            ("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST"),
            ("AWS_REGION", "us-east-2"),
        ]);
        assert_eq!(lambda(&empty_name), None);
    }

    #[tokio::test]
    async fn region_without_lambda_is_no_identity() {
        let region_only = env(&[("AWS_REGION", "us-east-2")]);
        assert_eq!(
            AgentIdentity::detect_with(
                &region_only,
                must_not_be_probed("task metadata"),
                must_not_be_read(),
                ready(None),
            )
            .await,
            Err(IdentityError::NoIdentityFound)
        );
    }

    #[tokio::test]
    async fn identity_satisfies_the_envelope_contract() {
        let identity = AgentIdentity::detect_with(
            &env(LAMBDA_ENV),
            must_not_be_probed("task metadata"),
            must_not_be_read(),
            must_not_be_probed("IMDS"),
        )
        .await
        .unwrap();
        let envelope = PayloadEnvelope::new(
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            0,
            0,
            identity.host_id.clone(),
            identity.boot_nonce,
            "3.1.1",
            identity.region,
            identity.deployment_type,
        )
        .expect("identity output is a valid envelope input");
        assert!(envelope
            .idempotency_key
            .starts_with(&format!("{}:", identity.host_id)));
    }

    /// The serialized envelope, with the `host_id` value removed, contains none
    /// of `leaks`: account IDs, IP addresses, customer-chosen names or ARNs.
    fn assert_envelope_omits(identity: AgentIdentity, leaks: &[&str]) {
        let envelope = PayloadEnvelope::new(
            Capability::SecretsManager,
            PayloadType::MetricsBatch,
            0,
            0,
            identity.host_id.clone(),
            identity.boot_nonce,
            "3.1.1",
            identity.region,
            identity.deployment_type,
        )
        .unwrap();
        let json = serde_json::to_string(&envelope)
            .unwrap()
            .replace(&identity.host_id, "");
        for leak in leaks {
            assert!(!json.contains(leak), "{leak} in {json}");
        }
    }

    #[tokio::test]
    async fn ec2_envelope_carries_no_identifiers() {
        let identity = AgentIdentity::detect_with(
            &env(&[]),
            must_not_be_probed("task metadata"),
            must_not_be_read(),
            ready(Some(EC2_DOCUMENT.to_string())),
        )
        .await
        .unwrap();
        assert_envelope_omits(identity, &["123456789012", "10.24.34.30", "arn:"]);
    }

    /// The task ARN, with its account ID and cluster name, is in `host_id` on
    /// purpose. Validates that the envelope carries the account ID, the cluster
    /// name, an ARN, the IP address, the task family and the repository nowhere
    /// outside the `host_id` value.
    #[tokio::test]
    async fn ecs_envelope_carries_no_other_identifiers() {
        let identity = AgentIdentity::detect_with(
            &env(ECS_ENV),
            ready(Some(ECS_TASK.to_string())),
            must_not_be_read(),
            must_not_be_probed("IMDS"),
        )
        .await
        .unwrap();
        let leaks = [
            "111122223333",
            "10.24.34.10",
            "arn:",
            "container/",
            "MyCluster",
            "MyTaskFamily",
            "my-repository",
        ];
        assert_envelope_omits(identity, &leaks);
    }

    /// The namespace and pod name are in `host_id` on purpose; nothing else from the token is.
    #[tokio::test]
    async fn eks_envelope_carries_no_other_identifiers() {
        let identity = AgentIdentity::detect_with(
            &env(KUBERNETES_ENV),
            must_not_be_probed("task metadata"),
            [EKS_CLAIMS.to_string()],
            must_not_be_probed("IMDS"),
        )
        .await
        .unwrap();
        let leaks = [
            "D43CF17C27A865933144EA99A26FB128",
            "my-service-account",
            "192-0-2-10",
        ];
        assert_envelope_omits(identity, &leaks);
    }
}
