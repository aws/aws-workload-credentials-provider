# Components

## aws_secretsmanager_agent (Binary Crate)

### main.rs (918 LOC)
Entry point for the agent. Parses CLI arguments (`--config`, `--help`), initializes config, binds TCP listener, creates `Server`, and runs the event loop. Uses callback injection for testability — `report` callback for startup notification, `end` callback for shutdown signaling. Contains extensive unit tests that spin up the full server with mock AWS clients.

Key functions:
- `main()` → `run()` → `init()` → `Server::new()` → event loop
- `init()`: Parses args, loads config, binds to `127.0.0.1:{port}`
- `run()`: Orchestrates initialization and server lifecycle

### server.rs (264 LOC)
HTTP request handler. Accepts TCP connections, validates SSRF tokens, enforces GET-only methods, enforces max connection limits, parses requests into `GSVQuery`, delegates to `CacheManager`, and returns responses.

| Struct | Purpose |
|--------|---------|
| `Server` | Holds listener, cache manager, SSRF token, config. Processes requests in separate tokio tasks. |

Key validations:
- `validate_token()`: Checks SSRF token against configured headers
- `validate_method()`: Rejects non-GET requests
- `validate_max_conn()`: Enforces connection limit (default 800)
- Request timeout: 61 seconds (`MAX_REQ_TIME_SEC`)
- Max body size: 321 KB (`MAX_BUF_BYTES`)

### parse.rs (262 LOC)
Parses HTTP request URIs into `GSVQuery` structs. Supports two URL formats:
- Query-based: `/secretsmanager/get?secretId=X&versionId=Y&versionStage=Z&refreshNow=true`
- Path-based: `/v1/{secretId}?versionId=Y&versionStage=Z&refreshNow=true`

Rejects unknown parameters with HTTP 400.

### config.rs (661 LOC)
TOML configuration parsing and validation. Loads from file via `--config` flag, falls back to defaults. Uses the `config` crate for deserialization. Validates all ranges and formats.

| Parameter | Default | Range/Values |
|-----------|---------|-------------|
| `log_level` | INFO | DEBUG, INFO, WARN, ERROR, NONE |
| `log_to_file` | true | boolean |
| `http_port` | 2773 | 1024–65535 |
| `ttl_seconds` | 300 | 0–3600 |
| `cache_size` | 1000 | 1–1000 |
| `ssrf_headers` | X-Aws-Parameters-Secrets-Token, X-Vault-Token | non-empty list |
| `ssrf_env_variables` | AWS_TOKEN, AWS_SESSION_TOKEN, AWS_CONTAINER_AUTHORIZATION_TOKEN | non-empty list |
| `path_prefix` | /v1/ | must start with / |
| `max_conn` | 800 | 1–1000 |
| `region` | None (SDK default) | AWS region string |
| `ignore_transient_errors` | true | boolean |
| `validate_credentials` | true | boolean |

### cache_manager.rs (347 LOC)
Thin wrapper around `SecretsManagerCachingClient`. Translates SDK errors into HTTP error codes. Uses conditional compilation to swap real AWS client for mock in tests.

Error mapping:
- `AccessDeniedException` → 403
- `ResourceNotFoundException` → 404
- `InvalidParameterException`, `InvalidRequestException` → 400
- Other SDK errors → 500

### utils.rs (336 LOC)
Utility functions:
- `get_token()`: Reads SSRF token from environment variables or files (supports `file:///path` syntax)
- `err_response()`: Formats HTTP error responses
- `validate_and_create_asm_client()`: Creates AWS SDK client with optional STS credential validation
- `AgentModifierInterceptor`: Adds `aws-secrets-manager-agent` to User-Agent header

### logging.rs (165 LOC)
Initializes logging based on config. File logging uses log4rs with 10 MB rotation and 5 file retention. Console logging uses pretty_env_logger.

### constants.rs (27 LOC)
Application-wide constants: app name, version, default max connections (800), max request time (61s), max buffer size (321 KB).

### error.rs (20 LOC)
`HttpError(u16, String)` — simple HTTP status code + message tuple struct.

---

## aws_secretsmanager_caching (Library Crate)

### lib.rs (1069 LOC)
Core caching client. `SecretsManagerCachingClient` manages the lifecycle of cached secrets with TTL-based expiration and staleness detection.

Key behaviors:
- **Cache hit (fresh)**: Returns cached value immediately
- **Cache miss**: Calls `GetSecretValue` API, stores result
- **Cache expired**: Calls `DescribeSecret` to check if version changed, then `GetSecretValue` if stale
- **refreshNow=true**: Bypasses cache, calls `GetSecretValue` directly, updates cache
- **Transient errors**: If `ignore_transient_errors` is true, serves stale cached data on transient refresh failures

Debug-only `CacheMetrics` tracks hits, misses, and refreshes via `AtomicU32`.

### secret_store/mod.rs (48 LOC)
Defines the `SecretStore` trait and `SecretStoreError` enum. Any struct implementing `SecretStore` can be used as the backing store.

### secret_store/memory_store/mod.rs (278 LOC)
`MemoryStore` — default `SecretStore` implementation. Uses a custom `Cache` (LRU) keyed by `(secret_name, version_stage_or_id)`. Entries include a timestamp for TTL checking.

### secret_store/memory_store/cache.rs (116 LOC)
`Cache<K, V>` — generic LRU cache backed by `LinkedHashMap`. Evicts oldest entry when max size is reached. Used by `MemoryStore`.

### output.rs (134 LOC)
`GetSecretValueOutputDef` — serializable mirror of the AWS SDK's `GetSecretValueOutput`. Needed because the SDK type is `#[non_exhaustive]` and doesn't implement serde traits. Handles `Blob` (base64) and `DateTime` (epoch seconds) serialization.

### error.rs (22 LOC)
`is_transient_error()` — determines if an SDK error is transient (timeout, throttling) vs permanent (access denied, not found).

### utils.rs (35 LOC)
`CachingLibraryInterceptor` — adds `aws-secrets-manager-caching-rust` to User-Agent header for SDK calls.

---

## integration-tests (Test Crate)

### common.rs (498 LOC)
Test harness shared across all integration test modules:
- `AgentProcess`: Spawns the agent binary as a child process, manages lifecycle
- `TestSecrets`: Creates real AWS secrets, cleans up on drop
- `AgentQuery` / `SecretType`: Builder pattern for constructing test queries
- Helper functions for making HTTP requests with/without tokens, XFF headers, etc.

### Test Modules

| Module | Tests | Coverage |
|--------|-------|----------|
| `secret_retrieval.rs` (258 LOC) | 7 tests | Name/ARN lookup, binary secrets, large secrets (200KB), version stage/id, nonexistent secret |
| `cache_behavior.rs` (197 LOC) | 3 tests | TTL expiration + refresh, refreshNow on updated secret, TTL=0 disables caching |
| `security.rs` (81 LOC) | 2 tests | SSRF token validation (missing/invalid), X-Forwarded-For rejection |
| `version_management.rs` (128 LOC) | 1 test | Version stage transitions (AWSCURRENT → AWSPREVIOUS) |
| `configuration.rs` (74 LOC) | 2 tests | Ping/health check endpoint, path-based requests (/v1/) |

---

## Supporting Files

### configuration/ (Install Scripts)
- `install`: Bash script creating systemd services, user (`awssmauser`), group (`awssmatokenreader`), token file
- `uninstall`: Removes services and user
- `awssmaseedtoken`: Generates random SSRF token to `/var/run/awssmatoken`
- `*.service`: systemd unit files for token seeding and agent startup

### examples/example-lambda-extension/
- `secrets-manager-agent-extension.sh` (111 LOC): Shell script to run the agent as a Lambda extension, handles registration, lifecycle events, and graceful shutdown

### Dockerfile
Multi-stage build: `rust:alpine` builder → `scratch` runtime. Copies only the binary and CA certificates.

### test-local.sh
Convenience script to build and run integration tests with `--test-threads=1`.
