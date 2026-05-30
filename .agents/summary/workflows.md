# Workflows

## Secret Retrieval Flow

The primary workflow — an application requests a secret from the agent.

```mermaid
sequenceDiagram
    participant App as Application
    participant Srv as Server
    participant Parse as GSVQuery Parser
    participant CM as CacheManager
    participant CC as CachingClient
    participant Store as MemoryStore
    participant AWS as Secrets Manager

    App->>Srv: GET /secretsmanager/get?secretId=X
    Srv->>Srv: Validate method (GET only)
    Srv->>Srv: Validate SSRF token
    Srv->>Srv: Check max connections
    Srv->>Srv: Reject X-Forwarded-For
    Srv->>Parse: Parse URI → GSVQuery
    Srv->>CM: fetch(name, version, stage, refreshNow)
    CM->>CC: get_secret_value(...)

    alt refreshNow = true
        CC->>AWS: GetSecretValue
        AWS-->>CC: Secret data
        CC->>Store: write_secret_value()
        CC-->>CM: GetSecretValueOutputDef
    else Cache hit (within TTL)
        CC->>Store: get_secret_value()
        Store-->>CC: Cached value
        CC-->>CM: GetSecretValueOutputDef
    else Cache expired
        CC->>AWS: DescribeSecret
        alt Version unchanged
            CC->>Store: Refresh timestamp
            CC-->>CM: Cached value
        else Version changed
            CC->>AWS: GetSecretValue
            AWS-->>CC: Fresh data
            CC->>Store: write_secret_value()
            CC-->>CM: GetSecretValueOutputDef
        end
    else Cache miss
        CC->>AWS: GetSecretValue
        AWS-->>CC: Secret data
        CC->>Store: write_secret_value()
        CC-->>CM: GetSecretValueOutputDef
    end

    CM-->>Srv: JSON string
    Srv-->>App: HTTP 200 + JSON body
```

## Agent Startup Flow

```mermaid
sequenceDiagram
    participant CLI as Command Line
    participant Main as main()
    participant Cfg as Config
    participant Log as Logger
    participant Srv as Server
    participant CM as CacheManager
    participant STS as AWS STS

    CLI->>Main: ./aws_secretsmanager_agent --config config.toml
    Main->>Cfg: Parse args, load TOML
    Cfg->>Cfg: Validate all parameters
    Main->>Log: init_logger(log_level, log_to_file)
    Main->>Main: Bind TcpListener to 127.0.0.1:{port}
    Main->>Srv: Server::new(listener, config)
    Srv->>CM: CacheManager::new(config)
    CM->>CM: Create AWS SDK client

    alt validate_credentials = true
        CM->>STS: GetCallerIdentity
        STS-->>CM: Identity confirmed
    end

    CM->>CM: Create SecretsManagerCachingClient
    Srv->>Srv: Read SSRF token from env/file
    Main->>Main: Report startup (port, version)
    Main->>Srv: Accept connections loop
```

## Cache TTL and Staleness Check

```mermaid
flowchart TD
    REQ[get_secret_value request] --> CHECK{In cache?}
    CHECK -->|No| MISS[Call GetSecretValue API]
    MISS --> WRITE[Write to MemoryStore]
    WRITE --> RETURN[Return value]

    CHECK -->|Yes| TTL{TTL expired?}
    TTL -->|No| HIT[Return cached value]

    TTL -->|Yes| DESC[Call DescribeSecret API]
    DESC --> STALE{Version changed?}

    STALE -->|No| REFRESH_TS[Refresh cache timestamp]
    REFRESH_TS --> HIT

    STALE -->|Yes| FETCH[Call GetSecretValue API]
    FETCH --> WRITE

    DESC -->|Error| TRANSIENT{Transient error?}
    TRANSIENT -->|Yes, ignore_transient=true| HIT
    TRANSIENT -->|No| ERROR[Return error]
```

## SSRF Token Validation

```mermaid
flowchart TD
    REQ[Incoming request] --> PING{Path = /ping?}
    PING -->|Yes| OK[Return 200 healthy]
    PING -->|No| XFF{X-Forwarded-For present?}
    XFF -->|Yes| REJECT[Return 403]
    XFF -->|No| HEADERS{Check configured SSRF headers}
    HEADERS --> MATCH{Token matches?}
    MATCH -->|Yes| PROCESS[Process request]
    MATCH -->|No| REJECT
```

## SSRF Token Resolution

On startup, the agent resolves the SSRF token by checking environment variables in order:

```mermaid
flowchart TD
    START[Resolve SSRF token] --> ENV1{AWS_TOKEN set?}
    ENV1 -->|Yes| FILE1{Starts with file://?}
    FILE1 -->|Yes| READ1[Read file contents]
    FILE1 -->|No| USE1[Use env value directly]
    ENV1 -->|No| ENV2{AWS_SESSION_TOKEN set?}
    ENV2 -->|Yes| USE2[Use env value]
    ENV2 -->|No| ENV3{AWS_CONTAINER_AUTHORIZATION_TOKEN set?}
    ENV3 -->|Yes| USE3[Use env value]
    ENV3 -->|No| FAIL[Error: no token found]
```

## EC2 Installation Flow

```mermaid
sequenceDiagram
    participant Admin as Administrator
    participant Script as install script
    participant OS as Linux OS
    participant Systemd as systemd

    Admin->>Script: sudo ./install
    Script->>OS: groupadd awssmatokenreader
    Script->>OS: useradd awssmauser
    Script->>OS: Install binary to /opt/aws/secretsmanageragent/bin/
    Script->>OS: Install token seed script
    Script->>Systemd: Enable + start awssmaseedtoken.service
    Note over Systemd: Generates random token → /var/run/awssmatoken
    Script->>Systemd: Enable + start awssmastartup.service
    Note over Systemd: Starts agent as awssmauser
    Admin->>OS: usermod -aG awssmatokenreader APP_USER
```

## Lambda Extension Lifecycle

```mermaid
sequenceDiagram
    participant Lambda as Lambda Runtime
    participant Ext as Extension Script
    participant Agent as SMA Binary

    Lambda->>Ext: Extension init
    Ext->>Agent: Start agent (background)
    Ext->>Lambda: Register extension (INVOKE, SHUTDOWN)

    loop Each invocation
        Lambda->>Ext: INVOKE event
        Ext->>Ext: Process event (no-op)
        Note over Lambda,Agent: Function code queries localhost:2773
    end

    Lambda->>Ext: SHUTDOWN event
    Ext->>Agent: SIGTERM
    Ext->>Ext: Wait for agent exit
```
