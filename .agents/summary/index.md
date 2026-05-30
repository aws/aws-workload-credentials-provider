# AWS Secrets Manager Agent — Documentation Index

> **For AI Assistants**: This file is the primary entry point for understanding the codebase. Read this file first to determine which detailed documentation files to consult for specific questions. Each section below summarizes a file's content and when to reference it.

## Project Summary

The AWS Secrets Manager Agent is a Rust-based localhost HTTP service that caches secrets from AWS Secrets Manager in memory. Applications query `localhost:2773` instead of calling the AWS API directly. It supports EC2, ECS/EKS (sidecar), and Lambda (extension) deployments.

- **Language**: Rust (edition 2021, Cargo workspace)
- **Version**: 2.0.0
- **Crates**: 3 (binary agent, caching library, integration tests)
- **Total LOC**: ~6,200 across 90 files

## Documentation Files

### [codebase_info.md](codebase_info.md)
**When to consult**: Project metadata, version info, build commands, CI setup, feature flags, technology stack.

Contains: Project name/version/license, workspace structure with LOC counts, technology stack listing, feature flags (`fips`), CI/CD configuration, build/run/test commands.

### [architecture.md](architecture.md)
**When to consult**: Understanding the overall system design, crate relationships, design patterns, deployment models.

Contains: Layered architecture diagram (HTTP → CacheManager → CachingClient → AWS SDK), crate dependency graph, design patterns (trait-based abstraction, configuration-driven, security by default, testability via callback injection), deployment architecture for EC2/ECS/Lambda/Docker.

### [components.md](components.md)
**When to consult**: Understanding what a specific file does, finding where functionality lives, understanding module responsibilities.

Contains: Detailed breakdown of every source file across all three crates — purpose, key structs/functions, LOC counts, configuration parameter table with defaults and ranges, test module coverage summary, supporting files (install scripts, Lambda extension, Dockerfile).

### [interfaces.md](interfaces.md)
**When to consult**: HTTP API details, request/response formats, error codes, internal Rust trait definitions, AWS SDK integration points.

Contains: Full HTTP API documentation (3 endpoints with parameters, headers, response format, error codes), `SecretStore` trait definition, `SecretsManagerCachingClient` and `CacheManager` public APIs, AWS APIs called (GetSecretValue, DescribeSecret, GetCallerIdentity), User-Agent interceptors, credential chain.

### [data_models.md](data_models.md)
**When to consult**: Understanding data structures, struct fields, enum variants, type relationships, serialization details.

Contains: Every struct and enum in the codebase with field definitions and source file locations — GSVQuery, Config, ConfigFile, LogLevel, HttpError, Server, CacheManager, GetSecretValueOutputDef, BlobDef, DateTimeDef, SecretStoreError, MemoryStore, Key, GSVValue, Cache, CacheMetrics. Data flow diagram.

### [workflows.md](workflows.md)
**When to consult**: Understanding request processing, startup sequence, caching logic, security validation, installation procedures.

Contains: Sequence and flowchart diagrams for — secret retrieval flow (with all cache states), agent startup flow, cache TTL and staleness check logic, SSRF token validation, SSRF token resolution order, EC2 installation flow, Lambda extension lifecycle.

### [dependencies.md](dependencies.md)
**When to consult**: Understanding external dependencies, adding new dependencies, license compliance, dependency relationships.

Contains: Complete dependency tables for all three crates (runtime + dev), build/CI tool dependencies, dependency graph diagram, license compliance configuration (deny.toml allow-list).

### [review_notes.md](review_notes.md)
**When to consult**: Known documentation gaps, areas needing improvement, consistency issues.

Contains: Results of consistency and completeness checks across all documentation files.

## Quick Reference

| Question | File(s) to consult |
|----------|-------------------|
| How do I build/run/test? | codebase_info.md |
| What's the overall architecture? | architecture.md |
| What does file X do? | components.md |
| What are the HTTP endpoints? | interfaces.md |
| What fields does struct X have? | data_models.md |
| How does caching work? | workflows.md |
| What dependencies are used? | dependencies.md |
| How is the agent deployed? | architecture.md, workflows.md |
| What config options exist? | components.md (config.rs section) |
| How does SSRF protection work? | workflows.md, interfaces.md |
| How do I add a new secret store? | interfaces.md (SecretStore trait) |
| What errors can the API return? | interfaces.md (Error Responses) |
