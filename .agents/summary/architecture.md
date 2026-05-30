# Architecture

## Overview

The AWS Secrets Manager Agent follows a layered architecture where an HTTP server accepts localhost requests, validates them for security, and delegates to a caching layer that manages secret retrieval and TTL-based caching against the AWS Secrets Manager service.

```mermaid
graph TB
    subgraph Client["Client Application"]
        APP[Application Code]
    end

    subgraph Agent["aws_secretsmanager_agent (binary)"]
        SRV[Server<br/>HTTP request handling]
        PARSE[GSVQuery Parser<br/>Query/path parameter extraction]
        CFG[Config<br/>TOML configuration]
        UTIL[Utils<br/>SSRF token, error responses]
        LOG[Logging<br/>File or stdout/stderr]
    end

    subgraph Cache["aws_secretsmanager_caching (library)"]
        CM[CacheManager<br/>Wrapper around caching client]
        CC[SecretsManagerCachingClient<br/>TTL cache + staleness checks]
        STORE[MemoryStore<br/>LRU in-memory cache]
    end

    subgraph AWS["AWS Cloud"]
        ASM[AWS Secrets Manager]
    end

    APP -->|HTTP GET localhost:2773| SRV
    SRV -->|Validate SSRF token| UTIL
    SRV -->|Parse request| PARSE
    SRV -->|Fetch secret| CM
    CM --> CC
    CC -->|Cache miss/expired/refreshNow| ASM
    CC -->|Cache hit| STORE
    CC -->|Write| STORE
    CFG -.->|Configure| SRV
    CFG -.->|Configure| CM
    LOG -.->|Log| SRV
```

## Crate Dependency Graph

```mermaid
graph LR
    AGENT[aws_secretsmanager_agent<br/>Binary crate]
    CACHING[aws_secretsmanager_caching<br/>Library crate]
    INTEG[integration-tests<br/>Test crate]
    SDK[aws-sdk-secretsmanager]

    AGENT -->|depends on| CACHING
    CACHING -->|depends on| SDK
    AGENT -->|depends on| SDK
    INTEG -->|tests against| AGENT
    INTEG -->|depends on| SDK
```

## Design Patterns

### Layered Architecture
- **Presentation layer**: HTTP server (`server.rs`) handles connections, validates requests
- **Application layer**: `CacheManager` bridges HTTP to caching, `GSVQuery` parser extracts parameters
- **Domain layer**: `SecretsManagerCachingClient` implements caching logic with TTL, staleness detection
- **Data layer**: `SecretStore` trait with `MemoryStore` implementation, LRU eviction

### Trait-Based Abstraction
The `SecretStore` trait (`secret_store/mod.rs`) defines the storage interface. `MemoryStore` is the default implementation. This allows alternative store implementations without changing the caching client.

### Configuration-Driven Behavior
All runtime behavior is configurable via TOML: port, TTL, cache size, SSRF headers, logging, region, max connections, path prefix. Defaults are sensible for production use.

### Security by Default
- SSRF token validation on every request (except `/ping`)
- Rejects `X-Forwarded-For` headers (proxy protection)
- Localhost-only binding
- Post-quantum ML-KEM key exchange as highest priority by default

### Testability
- `CacheManager` swaps the real AWS client for a mock in unit tests via conditional compilation (`#[cfg(test)]`)
- `main.rs` uses callback injection (`report` and `end` functions) to make the server testable
- Integration tests spawn the real agent binary as a child process

## Deployment Architecture

```mermaid
graph TB
    subgraph Compute["Compute Environment"]
        subgraph Host["Host / Container / Lambda"]
            APP[Application]
            AGENT[Secrets Manager Agent<br/>localhost:2773]
            TOKEN[SSRF Token<br/>/var/run/awssmatoken]
        end
    end

    subgraph AWS["AWS"]
        IAM[IAM Role / Credentials]
        ASM[Secrets Manager]
    end

    APP -->|HTTP GET + SSRF token| AGENT
    AGENT -->|GetSecretValue / DescribeSecret| ASM
    IAM -.->|Credentials| AGENT
    TOKEN -.->|Read token| APP
```

Supported deployment targets:
- **EC2**: Install script creates systemd services (`awssmaseedtoken.service`, `awssmastartup.service`)
- **ECS/EKS**: Sidecar container sharing network namespace with application container
- **Lambda**: Packaged as Lambda extension layer
- **Docker**: Multi-stage build (rust:alpine → scratch)
