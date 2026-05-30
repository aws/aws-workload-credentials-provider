# Codebase Information

## Project

- **Name**: AWS Secrets Manager Agent
- **Version**: 2.0.0
- **License**: Apache-2.0
- **Repository**: https://github.com/aws/aws-secretsmanager-agent
- **Language**: Rust (edition 2021)
- **Build Toolchain**: Cargo (nightly for CI, stable for builds)

## Description

A client-side HTTP service that caches secrets from AWS Secrets Manager in memory. Applications fetch secrets from localhost instead of calling Secrets Manager directly. Supports EC2, ECS, EKS, and Lambda deployment targets.

## Workspace Structure

Cargo workspace with 3 crates:

| Crate | Type | Version | LOC | Purpose |
|-------|------|---------|-----|---------|
| `aws_secretsmanager_agent` | Binary | 2.0.0 | ~2,700 | HTTP server, config, request handling |
| `aws_secretsmanager_caching` | Library | 2.0.0 | ~1,700 | Caching client, secret store, serialization |
| `integration-tests` | Test | 0.1.0 | ~1,200 | End-to-end tests against real AWS |

Total: ~6,200 lines of code across 90 files (26 prioritized source files).

## Technology Stack

- **Runtime**: Tokio (async multi-threaded)
- **HTTP**: Hyper 1.x (HTTP/1.1 server)
- **AWS SDK**: aws-sdk-secretsmanager 1.x, aws-config 1.x
- **TLS**: rustls (with optional FIPS mode)
- **Serialization**: serde / serde_json
- **Logging**: log + log4rs (file) / pretty_env_logger (console)
- **Config**: config crate (TOML parsing)
- **Benchmarks**: criterion

## Feature Flags

- `fips`: Restricts TLS cipher suites to FIPS-approved ciphers only (propagates to `rustls/fips`)

## CI/CD

- **Platform**: GitHub Actions
- **Matrix**: ubuntu-latest, windows-latest, macos-latest
- **Toolchain**: Rust nightly
- **Checks**: build, test (all features), cargo-deny (license audit), cargo-fmt, clippy, cargo-llvm-cov (codecov)
- **License allow-list**: MIT, Apache-2.0, Unicode-3.0, ISC, BSD-3-Clause, OpenSSL, 0BSD, CDLA-Permissive-2.0
- **Additional workflows**: CodeQL, Docker build, benchmarks, integration tests

## Build & Run

```bash
# Build
cargo build --release

# Run with default config
./target/release/aws_secretsmanager_agent

# Run with custom config
./target/release/aws_secretsmanager_agent --config config.toml

# Run tests (excludes integration tests)
cargo test --all-features --workspace --exclude integration-tests

# Run integration tests (requires AWS credentials)
cd integration-tests && cargo test -- --test-threads=1

# Build with FIPS
cargo build --release --features fips
```
