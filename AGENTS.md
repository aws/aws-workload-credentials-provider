# AGENTS.md — AI Assistant Guide for AWS Secrets Manager Agent

> This file is optimized for AI coding assistants. It provides project context, directory structure, coding patterns, and development guidance not covered in README.md or CONTRIBUTING.md. For detailed documentation, see `.agents/summary/index.md`.

## Project Overview

Rust-based localhost HTTP service that caches AWS Secrets Manager secrets in memory. Applications query `localhost:2773` instead of calling the AWS API directly.

- **Language**: Rust (edition 2021)
- **Version**: 2.0.0
- **License**: Apache-2.0
- **Crates**: 3 (binary agent, caching library, integration tests)
- **~6,200 LOC** across 90 files

## Directory Structure

```
aws-secretsmanager-agent/
├── Cargo.toml                          # Workspace definition (3 members)
├── Cargo.lock
├── deny.toml                           # License compliance (cargo-deny)
├── Dockerfile                          # Multi-stage: rust:alpine → scratch
├── test-local.sh                       # Integration test runner
├── README.md                           # User-facing documentation
├── CONTRIBUTING.md                     # Contribution guidelines
│
├── aws_secretsmanager_agent/           # Binary crate — HTTP server
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs                     # Entry point, CLI args, server lifecycle
│   │   ├── server.rs                   # HTTP handler, SSRF validation, connection mgmt
│   │   ├── parse.rs                    # URI → GSVQuery parsing (query + path formats)
│   │   ├── config.rs                   # TOML config loading and validation
│   │   ├── cache_manager.rs            # Bridges server to caching library
│   │   ├── utils.rs                    # SSRF token resolution, AWS client creation
│   │   ├── logging.rs                  # File (log4rs) and console logging setup
│   │   ├── constants.rs                # App-wide constants (port, timeouts, limits)
│   │   └── error.rs                    # HttpError(status_code, message)
│   ├── configuration/                  # EC2 install/uninstall scripts, systemd units
│   ├── examples/
│   │   └── example-lambda-extension/   # Lambda extension wrapper script
│   └── tests/resources/                # Test config files
│
├── aws_secretsmanager_caching/         # Library crate — caching logic
│   ├── Cargo.toml
│   ├── README.md                       # Library-specific docs
│   ├── src/
│   │   ├── lib.rs                      # SecretsManagerCachingClient (TTL, staleness, refreshNow)
│   │   ├── output.rs                   # GetSecretValueOutputDef (serde-compatible SDK mirror)
│   │   ├── error.rs                    # Transient error detection
│   │   ├── utils.rs                    # CachingLibraryInterceptor (User-Agent)
│   │   └── secret_store/
│   │       ├── mod.rs                  # SecretStore trait, SecretStoreError enum
│   │       └── memory_store/
│   │           ├── mod.rs              # MemoryStore (default SecretStore impl)
│   │           └── cache.rs            # Generic LRU Cache<K,V> via LinkedHashMap
│   └── benches/
│       └── benchmark.rs                # Criterion benchmarks (cache hit, eviction)
│
├── integration-tests/                  # E2E tests against real AWS
│   ├── Cargo.toml
│   ├── src/lib.rs
│   └── tests/
│       ├── common.rs                   # Test harness (AgentProcess, TestSecrets)
│       ├── secret_retrieval.rs         # Name/ARN/binary/large secret tests
│       ├── cache_behavior.rs           # TTL, refreshNow, TTL=0 tests
│       ├── security.rs                 # SSRF token, XFF rejection tests
│       ├── version_management.rs       # Version stage transition tests
│       └── configuration.rs            # Ping, path-based request tests
│
├── .github/
│   ├── workflows/
│   │   ├── rust.yml                    # Main CI: build, test, lint, coverage
│   │   ├── codeql.yml                  # Security analysis
│   │   ├── integration-tests.yml       # E2E tests (requires AWS creds)
│   │   ├── benchmarks.yml              # Performance benchmarks
│   │   └── docker.yml                  # Docker build verification
│   └── ...
│
└── .agents/summary/                    # Generated documentation (this system)
    ├── index.md                        # Documentation entry point
    ├── codebase_info.md                # Build, CI, tech stack
    ├── architecture.md                 # System design, patterns
    ├── components.md                   # File-by-file breakdown
    ├── interfaces.md                   # HTTP API, traits, SDK integration
    ├── data_models.md                  # All structs and enums
    ├── workflows.md                    # Request flows, caching logic
    ├── dependencies.md                 # All dependencies with purposes
    └── review_notes.md                 # Documentation gaps and issues
```

## Architecture Quick Reference

```
HTTP Request → Server (SSRF check, method check, connection limit)
            → GSVQuery Parser (extract secretId, version, refreshNow)
            → CacheManager → SecretsManagerCachingClient
                           → MemoryStore (LRU cache with TTL)
                           → AWS SDK (GetSecretValue / DescribeSecret)
            → JSON Response
```

Three crates:
- `aws_secretsmanager_agent` depends on `aws_secretsmanager_caching`
- `integration-tests` tests the agent binary as a child process
- `aws_secretsmanager_caching` is independently usable as a library

## Coding Patterns

### Conditional Compilation for Testing
`cache_manager.rs` swaps the real AWS client for a mock in tests:
```rust
#[cfg(not(test))]
use crate::utils::validate_and_create_asm_client as asm_client;
#[cfg(test)]
use tests::init_client as asm_client;
```

### Callback Injection for Testability
`main.rs` uses callbacks so unit tests can control the server lifecycle:
```rust
async fn run<S: FnMut(&SocketAddr), E: FnMut() -> bool>(
    args: impl IntoIterator<Item = String>,
    mut report: S,  // Called with bound address
    mut end: E,     // Returns true to shut down
) -> Result<(), Box<dyn std::error::Error>>
```

### Trait-Based Storage Abstraction
`SecretStore` trait in `secret_store/mod.rs` allows alternative cache implementations:
```rust
pub trait SecretStore: Debug + Send + Sync {
    fn get_secret_value(&self, ...) -> Result<GetSecretValueOutputDef, SecretStoreError>;
    fn write_secret_value(&mut self, ...) -> Result<(), SecretStoreError>;
}
```

### Error Mapping Pattern
`CacheManager` translates SDK errors to HTTP status codes:
- `AccessDeniedException` → 403
- `ResourceNotFoundException` → 404
- `InvalidParameterException` / `InvalidRequestException` → 400
- Other → 500

### Stale-While-Revalidate
When `ignore_transient_errors` is true and a cache refresh fails with a transient error (timeout, throttling), the client serves the stale cached value instead of returning an error.

## Building and Testing

```bash
# Build
cargo build --release

# Run all unit tests (excludes integration tests)
cargo test --all-features --workspace --exclude integration-tests

# Run with FIPS
cargo build --release --features fips

# Run integration tests (requires AWS credentials)
cd integration-tests && cargo test -- --test-threads=1

# Benchmarks
cd aws_secretsmanager_caching && cargo bench

# Lint
cargo fmt --all -- --check
cargo clippy --all-targets --all-features

# License check
cargo deny check licenses
```

### Unit Test Patterns
- Agent crate tests are in `main.rs` — they spin up the full server with mock AWS clients using `one_shot()` helper
- Caching crate tests are in `lib.rs` — they use `aws-smithy-mocks` for SDK response mocking
- Memory store tests are in `memory_store/mod.rs` — pure unit tests for cache behavior

### Integration Test Patterns
- Tests spawn the real agent binary via `AgentProcess` (in `common.rs`)
- `TestSecrets` creates real AWS secrets and cleans up on `Drop`
- Tests use `reqwest` to make HTTP requests to the spawned agent
- Must run with `--test-threads=1` (shared port)

## Configuration Reference

| Parameter | Default | Range | Notes |
|-----------|---------|-------|-------|
| `log_level` | INFO | DEBUG/INFO/WARN/ERROR/NONE | |
| `log_to_file` | true | boolean | false → stdout/stderr |
| `http_port` | 2773 | 1024–65535 | |
| `ttl_seconds` | 300 | 0–3600 | 0 disables caching |
| `cache_size` | 1000 | 1–1000 | Max secrets in cache |
| `ssrf_headers` | X-Aws-Parameters-Secrets-Token, X-Vault-Token | non-empty list | |
| `ssrf_env_variables` | AWS_TOKEN, AWS_SESSION_TOKEN, AWS_CONTAINER_AUTHORIZATION_TOKEN | non-empty list | Checked in order |
| `path_prefix` | /v1/ | must start with / | |
| `max_conn` | 800 | 1–1000 | |
| `region` | None | AWS region | Falls back to SDK default |

## HTTP API Quick Reference

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /secretsmanager/get?secretId=X` | SSRF token required | Query-based secret retrieval |
| `GET /v1/{secretId}` | SSRF token required | Path-based secret retrieval |
| `GET /ping` | No auth | Health check (returns "healthy") |

Optional query params: `versionId`, `versionStage`, `refreshNow` (true/false)

## Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| `APPNAME` | aws-secrets-manager-agent | constants.rs |
| `DEFAULT_MAX_CONNECTIONS` | 800 | constants.rs |
| `MAX_REQ_TIME_SEC` | 61 seconds | constants.rs |
| `MAX_BUF_BYTES` | 321 KB | constants.rs |

## Detailed Documentation

For deeper information, consult `.agents/summary/index.md` which provides a quick-reference table mapping questions to the appropriate documentation file.
