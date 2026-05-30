# Interfaces

## HTTP API

The agent exposes a localhost-only HTTP/1.1 API on a configurable port (default 2773). All endpoints require a valid SSRF token header except `/ping`.

### Endpoints

#### GET /secretsmanager/get (Query-Based)

Retrieves a secret value using query parameters.

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `secretId` | Yes | String | Secret name or ARN |
| `versionId` | No | String | Specific version UUID |
| `versionStage` | No | String | Version stage label (default: AWSCURRENT) |
| `refreshNow` | No | Boolean | `true`/`false`/`1`/`0` — bypass cache (default: false) |

```
GET /secretsmanager/get?secretId=MySecret&versionStage=AWSCURRENT HTTP/1.1
Host: localhost:2773
X-Aws-Parameters-Secrets-Token: <token>
```

#### GET /v1/{secretId} (Path-Based)

Retrieves a secret value using path-based routing. The prefix `/v1/` is configurable via `path_prefix`.

```
GET /v1/MySecret?versionStage=AWSCURRENT&refreshNow=true HTTP/1.1
Host: localhost:2773
X-Aws-Parameters-Secrets-Token: <token>
```

Query parameters (`versionId`, `versionStage`, `refreshNow`) are still passed as query strings.

#### GET /ping

Health check endpoint. Returns `healthy` with HTTP 200. Does not require SSRF token.

```
GET /ping HTTP/1.1
Host: localhost:2773
```

### Response Format

Successful responses return the same JSON structure as the AWS `GetSecretValue` API:

```json
{
  "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:MySecret-abc123",
  "Name": "MySecret",
  "VersionId": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
  "SecretString": "{\"username\":\"admin\",\"password\":\"secret\"}",
  "VersionStages": ["AWSCURRENT"],
  "CreatedDate": "1699900000.000"
}
```

For binary secrets, `SecretBinary` (base64-encoded) replaces `SecretString`.

### Error Responses

| HTTP Status | Condition |
|-------------|-----------|
| 400 | Missing `secretId`, unknown parameter, invalid `refreshNow` value |
| 403 | Invalid/missing SSRF token, `AccessDeniedException` from AWS |
| 404 | `ResourceNotFoundException` from AWS |
| 405 | Non-GET method |
| 500 | Internal error, unexpected SDK error |

### Required Headers

| Header | Default Names | Source |
|--------|--------------|--------|
| SSRF Token | `X-Aws-Parameters-Secrets-Token`, `X-Vault-Token` | Configurable via `ssrf_headers` |

Requests with `X-Forwarded-For` header are rejected (SSRF protection).

---

## Internal Rust Interfaces

### SecretStore Trait

```rust
pub trait SecretStore: Debug + Send + Sync {
    fn get_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
    ) -> Result<GetSecretValueOutputDef, SecretStoreError>;

    fn write_secret_value(
        &mut self,
        secret_id: String,
        version_id: Option<String>,
        version_stage: Option<String>,
        data: GetSecretValueOutputDef,
    ) -> Result<(), SecretStoreError>;
}
```

Located in `aws_secretsmanager_caching/src/secret_store/mod.rs`. The only implementation is `MemoryStore`. The trait is `Send + Sync` to support concurrent access via `RwLock`.

### SecretsManagerCachingClient

```rust
pub struct SecretsManagerCachingClient {
    asm_client: SecretsManagerClient,
    store: RwLock<Box<dyn SecretStore>>,
    ignore_transient_errors: bool,
}
```

Public API:
- `new(client, max_size, ttl, ignore_transient_errors)` → `Result<Self, Error>`
- `get_secret_value(secret_id, version_id, version_stage, refresh_now)` → `Result<GetSecretValueOutputDef, Error>`

### CacheManager

```rust
pub struct CacheManager(SecretsManagerCachingClient);
```

Public API:
- `new(cfg)` → `Result<Self, Error>`
- `fetch(name, version, label, refresh_now)` → `Result<String, (u16, String)>`

Translates `SecretsManagerCachingClient` results into HTTP-friendly `(status_code, body)` tuples.

---

## AWS SDK Integration

### APIs Called

| API | Purpose | When |
|-----|---------|------|
| `GetSecretValue` | Retrieve secret content | Cache miss, TTL expired + stale, refreshNow |
| `DescribeSecret` | Check version metadata for staleness | TTL expired (before deciding to re-fetch) |
| `GetCallerIdentity` (STS) | Validate credentials on startup | When `validate_credentials` is true |

### User-Agent Modification

Two interceptors append to the SDK User-Agent string:
- `AgentModifierInterceptor`: Adds `aws-secrets-manager-agent`
- `CachingLibraryInterceptor`: Adds `aws-secrets-manager-caching-rust`

### Credential Chain

Uses the standard AWS SDK default credential provider chain. Supports:
- Environment variables
- IAM roles (EC2 instance profile, ECS task role, Lambda execution role)
- Shared credentials file
- SSO
