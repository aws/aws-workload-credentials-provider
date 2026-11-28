# AWS Workload Credentials Provider

The AWS Workload Credentials Provider (formerly the AWS Secrets Manager Agent) is a client\-side solution that helps you standardize how you consume credentials from AWS services across your compute environments\. It includes the following capabilities:

- **Secrets Manager** — An HTTP interface for retrieving and caching secrets from AWS Secrets Manager\. Supported on AWS Lambda, Amazon ECS, Amazon EKS, and Amazon EC2\. Enabled by default\.
- **Certificate Management** — Automatic export and refresh of certificates from AWS Certificate Manager to the local filesystem\. Supported on Amazon EC2, on\-premise hosts, and container environments \(Docker on Amazon EC2, Amazon ECS, Amazon EKS\)\. Opt\-in via [configuration](#certificate-management-configuration)\. Includes optional [certificate discovery and telemetry](#workload-credentials-provider-discovery), which reports the TLS certificates your workloads present and the result of each certificate refresh\.

## Secrets Manager capability

The Workload Credentials Provider retrieves and caches secrets in memory so that your applications can consume secrets from localhost instead of making direct calls to Secrets Manager\. It can only read secrets \- it can't modify them\.

The Workload Credentials Provider uses the AWS credentials you provide in your environment to make calls to Secrets Manager\. The Workload Credentials Provider offers protection against Server Side Request Forgery \(SSRF\) to help improve secret security\. It also uses the post-quantum ML-KEM key exchange as the highest-priority key exchange by default\. You can configure the Workload Credentials Provider by setting the maximum number of connections, the time to live \(TTL\), the localhost HTTP port, and the cache size\.

Because the Workload Credentials Provider uses an in\-memory cache, it resets when the Workload Credentials Provider restarts\. The Workload Credentials Provider periodically refreshes the cached secret value\. The refresh happens when you try to read a secret from the Workload Credentials Provider after the TTL has expired\. The default refresh frequency \(TTL\) is 300 seconds, and you can change it by using a [Configuration file](#workload-credentials-provider-config) which you pass to the Workload Credentials Provider using the `sm start --config /path/to/config.toml` command line argument\. The Workload Credentials Provider does not include cache invalidation\. For example, if a secret rotates before the cache entry expires, the Workload Credentials Provider might return a stale secret value\. 

The Workload Credentials Provider returns secret values in the same format as the response of `GetSecretValue`\. Secret values are not encrypted in the cache\.

## Certificate Management capability

The Workload Credentials Provider exports certificates from AWS Certificate Manager (ACM) and writes them as PEM files to the local filesystem\. It automatically checks for updated certificates every 24 hours and optionally runs a user\-configured command after each successful refresh (for example, to reload a web server)\. You can configure up to 50 certificates\. Each certificate is managed by an independent background task, providing fault isolation so that one certificate's failure does not affect others\.

The Certificate Management capability supports Linux and Windows, and works with web servers such as NGINX and Apache\.

When a certificate uses a WCP watcher, the provider and watcher share the configured requests directory\. The watcher owns `<requests_dir>/<watcher_id>/outbox`: it creates and validates `inbox/`, `pending/`, and `outbox/` at startup, writes status records atomically to `outbox/`, and the provider consumes and deletes those records\. The shared volume must allow both processes to access `outbox/`; a missing or unsafe directory causes the watcher to refuse startup rather than silently lose status records\.

The Workload Credentials Provider uses the AWS credentials you provide in your environment to assume the role you have configured for each certificate, and then calls ACM to export the certificate\.

**Important**  
The Certificate Management capability requires elevated permissions for the provider to write certificate files and execute refresh commands\. The `install` script (Linux) or `install.ps1` script (Windows) configures these permissions automatically and is the recommended setup path for Amazon EC2 and on\-premise hosts; container deployments are the exception and do not use the `install` / `install.ps1` script \(see [Running as a Certificate Manager Sidecar](#-running-as-a-certificate-manager-sidecar-)\)\. On Linux, if you need to manage specific permissions yourself, use the `--no-privileges` or `--no-sudoers` flags rather than bypassing the install script entirely\. For details on what permissions are configured, see [Security considerations](#workload-credentials-provider-security)\.

You can provide a custom configuration by passing `--config /path/to/config.toml` on startup or on reload while the provider is running\. On Windows, use `-Config C:\path\to\config.toml` when invoking the PowerShell scripts and `--Config C:\path\to\config.toml` when executing the binary command\. The reload re\-applies permissions and restarts the ACM service\.

For full configuration details, see [Configure the Workload Credentials Provider](#workload-credentials-provider-config)\.

The Certificate Management capability also includes optional certificate discovery and telemetry\. For details, see [Step 5: Turn on certificate discovery and telemetry](#workload-credentials-provider-discovery)\.

To download the source code, see [https://github\.com/aws/aws\-workload\-credentials\-provider](https://github.com/aws/aws-workload-credentials-provider) on GitHub\.

**Topics**
- [AWS Workload Credentials Provider](#aws-workload-credentials-provider)
  - [Secrets Manager capability](#secrets-manager-capability)
  - [Certificate Management capability](#certificate-management-capability)
  - [Quick install](#quick-install)
      - [\[ Linux quick install \]](#-linux-quick-install-)
      - [\[ Windows quick install \]](#-windows-quick-install-)
  - [Step 1: Build the Workload Credentials Provider binary](#step-1-build-the-workload-credentials-provider-binary)
      - [\[ RPM-based systems \]](#-rpm-based-systems-)
      - [\[ Debian-based systems \]](#-debian-based-systems-)
      - [\[ Windows \]](#-windows-)
      - [\[ Cross-compile natively \]](#-cross-compile-natively-)
  - [Step 2: Install the Workload Credentials Provider](#step-2-install-the-workload-credentials-provider)
      - [\[ Amazon EC2 (Linux) \]](#-amazon-ec2-linux-)
      - [\[ Windows EC2 \]](#-windows-ec2-)
      - [\[ Running as a Secrets Manager Sidecar \]](#-running-as-a-secrets-manager-sidecar-)
      - [\[ Running as a Certificate Manager Sidecar \]](#-running-as-a-certificate-manager-sidecar-)
      - [\[ AWS Lambda \]](#-aws-lambda-)
  - [Step 3: Retrieve secrets with the Workload Credentials Provider](#step-3-retrieve-secrets-with-the-workload-credentials-provider)
      - [\[ curl \]](#-curl-)
      - [\[ Python \]](#-python-)
  - [`refreshNow` parameter behavior](#refreshnow-parameter-behavior)
  - [Using the refreshNow parameter](#using-the-refreshnow-parameter)
    - [Example - Workload Credentials Provider GET request with refreshNow parameter](#example---workload-credentials-provider-get-request-with-refreshnow-parameter)
      - [\[ curl \]](#-curl--1)
      - [\[ Python \]](#-python--1)
  - [Role chaining (cross-account access)](#role-chaining-cross-account-access)
  - [Pre-fetching](#pre-fetching)
  - [Region failover](#region-failover)
  - [Step 4: Retrieve certificates with the Workload Credentials Provider](#step-4-retrieve-certificates-with-the-workload-credentials-provider)
  - [Step 5: Turn on certificate discovery and telemetry](#step-5-turn-on-certificate-discovery-and-telemetry)
    - [Benefits](#benefits)
    - [How certificate discovery works](#how-certificate-discovery-works)
    - [What telemetry is sent](#what-telemetry-is-sent)
    - [Set up certificate discovery and telemetry](#set-up-certificate-discovery-and-telemetry)
    - [Troubleshoot certificate discovery](#troubleshoot-certificate-discovery)
  - [Configure the Workload Credentials Provider](#configure-the-workload-credentials-provider)
  - [File-based credentials](#file-based-credentials)
  - [Optional features](#optional-features)
  - [Logging](#logging)
  - [Security considerations](#security-considerations)
  - [Running Integration Tests Locally](#running-integration-tests-locally)
    - [Prerequisites](#prerequisites)
    - [Required AWS Permissions](#required-aws-permissions)
    - [Required IAM Roles (for role chaining tests)](#required-iam-roles-for-role-chaining-tests)
    - [Running Tests](#running-tests)
      - [Option 1: Using the test script](#option-1-using-the-test-script)
      - [Option 2: Manual execution](#option-2-manual-execution)
    - [Test Organization](#test-organization)

## Quick install<a name="workload-credentials-provider-quick-install"></a>

The bootstrap installers download a released binary and the matching configuration directory, then run the install script for you\. Use them unless you need to build from source, in which case follow Step 1 and Step 2 instead\.

------
#### [ Linux quick install ]

```sh
installer=$(mktemp) && trap 'rm -f "$installer"' EXIT &&
  curl --proto '=https' --tlsv1.2 -fsSL -o "$installer" \
    https://raw.githubusercontent.com/aws/aws-workload-credentials-provider/HEAD/install.sh &&
  sudo AWCP_VERSION=4.0.0 bash "$installer" --config /path/to/config.toml
```

`AWCP_VERSION` is required and must name a released, tagged version\. The script downloads the binary for your architecture from the artifact host and the service units and install scripts from the `v$AWCP_VERSION` tag, then hands off to the `install` script described in [Step 2](#workload-credentials-provider-install)\. It also accepts `--dry-run`, which downloads everything, keeps it, and prints where, without installing\.

Download to a file rather than piping into a shell: `bash -c "$(curl …)"` exits 0 when the download fails, because the substitution is simply empty, so a failed install reads as a successful one\. If you do use that form, options must go after a `--`, since the shell would otherwise consume the first one as `$0`\.

As with Step 2, add the user account that your application runs under to the `aws-wcp-token` group so it can read the SSRF token file\.

------
#### [ Windows quick install ]

Run the following in an Administrator PowerShell session\. If the download fails on an older host, run `[Net.ServicePointManager]::SecurityProtocol = 'Tls12'` first\.

```powershell
$installer = Join-Path $env:TEMP "awcp-install.ps1"
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/aws/aws-workload-credentials-provider/HEAD/install.ps1 -OutFile $installer
& $installer -Version 4.0.0 -Config C:\path\to\config.toml
Remove-Item $installer
```

Download to a file rather than running the response directly: `[scriptblock]::Create()` on an empty body produces a script block that does nothing and reports success, so a truncated or empty download would read as a completed install\.

If your execution policy refuses to run the file, or refuses the unsigned install scripts it downloads, run it as `powershell.exe -ExecutionPolicy Bypass -File $installer -Version 4.0.0 -Config C:\path\to\config.toml`\. The script checks the policy before downloading anything and tells you the same thing\.

The script verifies the Authenticode signature on the binary and passes `-Config` and `-NoStart` through to the `install.ps1` script described in [Step 2](#workload-credentials-provider-install)\. It also accepts the following parameters:
- `-Version <x.y.z>` — Version to install; required, and may also be given as the `AWCP_VERSION` environment variable
- `-Force` — \(Optional\) Stop running provider services before installing
- `-DryRun` — \(Optional\) Download and verify, then stop without installing

Version 3\.1\.2 and later stop if administrators don't control the provider folder or `C:\ProgramData\AWS`, with or without `-Config`\. Without `-Config`, they also only use an existing config if administrators control it\. See the Windows EC2 tab in [Step 2](#workload-credentials-provider-install) for details and how to continue\.

------

## Step 1: Build the Workload Credentials Provider binary<a name="workload-credentials-provider-build"></a>

To build the Workload Credentials Provider binary natively, you need the standard development tools and the Rust tools\. Alternatively, you can cross\-compile for systems that support it, or you can use Rust cross to cross\-compile\.

------

**NOTE:** To ensure a stable experience, use a specific git tag when building from source code. You can find a list of version tags [here](https://github.com/aws/aws-workload-credentials-provider/tags). Tags are in the pattern `/v\d+\.\d+\.\d+/` and follow [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html).

Example: `git clone --branch <git tag> https://github.com/aws/aws-workload-credentials-provider.git`

**NOTE:** Building the provider with the `fips` feature enabled on macOS currently requires the following workaround:

- Create an environment variable called `SDKROOT` which is set to the result of running `xcrun --show-sdk-path`

#### [ RPM\-based systems ]

1. On RPM\-based systems such as AL2023, you can install the development tools by using the Development Tools group\.

   ```sh
   sudo yum -y groupinstall "Development Tools"
   ```

1. Follow the instructions at [Install Rust](https://www.rust-lang.org/tools/install) in the *Rust documentation*\.

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh # Follow the on-screen instructions
   . "$HOME/.cargo/env"
   ```

1. Build the provider using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws-workload-credentials-provider`\.

------
#### [ Debian\-based systems ]

1. On Debian\-based systems such as Ubuntu, you can install the developer tools using the build\-essential package\.

   ```sh
   sudo apt install build-essential
   ```

1. Follow the instructions at [Install Rust](https://www.rust-lang.org/tools/install) in the *Rust documentation*\.

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh # Follow the on-screen instructions
   . "$HOME/.cargo/env"
   ```

1. Build the provider using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws-workload-credentials-provider`\.

------
#### [ Windows ]

To build on Windows, follow the instructions at [Set up your dev environment on Windows for Rust](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup) in the *Microsoft Windows documentation*\.

1. Build the provider using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws-workload-credentials-provider.exe`\.

------
#### [ Cross\-compile natively ]

You can cross\-compile for Windows from Linux using `cargo-xwin`\.

```sh
# Install clang
sudo yum install -y clang

# Install cargo-xwin
cargo install cargo-xwin

# Install the Rust build target
rustup target add x86_64-pc-windows-msvc

# Cross compile for Windows
cargo xwin build --release --target x86_64-pc-windows-msvc
```

You will find the executable at `target/x86_64-pc-windows-msvc/release/aws-workload-credentials-provider.exe`\.

------

## Step 2: Install the Workload Credentials Provider<a name="workload-credentials-provider-install"></a>

Based on the type of compute, you have several options for installing the Workload Credentials Provider\. The install script sets up both the Secrets Manager and Certificate Management capabilities\.

------
#### [ Amazon EC2 (Linux) ]

**To install the Workload Credentials Provider**

1. `cd aws_workload_credentials_provider_common/configuration`
1. Run the `install` script provided in the repository\. 

   ```sh
   sudo ./install --config /path/to/config.toml
   ```

   The script accepts the following options:
   - `--config <file>` — (Optional) Bootstrap config to copy to the configuration directory
   - `--no-start` — (Optional) Install but don't start services
   - `--no-privileges` — (Optional) Skip Linux capabilities on ACM service
   - `--no-sudoers` — (Optional) Skip sudoers generation

   The script generates a random SSRF token on startup and stores it in the file `/var/run/awssmatoken`\. The token is readable by the `aws-wcp-token` group that the install script creates\.

   **Upgrading:** the install script starts services that aren't running and leaves running ones as they are, so after an upgrade restart the services, or the host, to run the new version\. Restarting the token service creates a new token and also restarts the Secrets Manager service, which requires it; applications that keep the token must then read the file again\.

   ```sh
   sudo systemctl restart aws-workload-credentials-provider-token aws-workload-credentials-provider-acm
   ``` 

1. To allow your application to read the token file, you need to add the user account that your application runs under to the `aws-wcp-token` group\. For example, you can grant permissions for your application to read the token file with the following usermod command, where *<APP\_USER>* is the user ID under which your application runs\.

   ```sh
   sudo usermod -aG aws-wcp-token <APP_USER>
   ```

------
#### [ Windows EC2 ]

**To install the Workload Credentials Provider**

1. `cd aws_workload_credentials_provider_common\configuration`
1. Run the `install.ps1` script as Administrator\.

   ```powershell
   .\install.ps1 -Config C:\path\to\config.toml
   ```

   The script accepts the following parameters:
   - `-Config <file>` — (Optional) Bootstrap config to use
   - `-NoStart` — (Optional) Install but don't start services

   If you don't pass `-Config` and `C:\ProgramData\AWS\WorkloadCredentialsProvider\config.toml` already exists, the script uses it only if an administrator owns it and no account other than an administrator has a write grant on it\. The same rule applies to the `WorkloadCredentialsProvider` folder on every install, and `acmReloadConfig.ps1` follows it too\. `C:\ProgramData\AWS` must be owned by an administrator and must not let other accounts delete, rename, or change permissions on what is in it\. Otherwise the script stops and names the folder or file it didn't use\. Stop both services first; they start again after a restart\. If you can't open the config or the folder, take ownership of it and give administrators access first\. For the config, re\-run with `-Config` and a reviewed copy\. For the `WorkloadCredentialsProvider` folder, back up the logs and the config if there is one, delete the folder, and re\-run, with `-Config` if there was a config\. If the folder, or anything in it, is a junction or symbolic link, delete only the link\. Deleting the folder also removes the token file, so grant your application read access to the new token file again \(see the next step\)\. For `C:\ProgramData\AWS`, fix its owner and permissions, or replace it with a real folder if it is a junction or symbolic link\. In every case, review the config, including every `refresh_command`, and remove renewal tasks \(`AWSWorkloadCredentialsProvider-Reload-*`\) it no longer needs\. Start both services again afterwards if they are not running\. This can also happen when an older version installed the config under an account that is an administrator only through a domain group, or under an account that has since been deleted\. New installs make the Administrators group the owner\.

   The script generates a random SSRF token on startup and stores it in the file `C:\ProgramData\AWS\WorkloadCredentialsProvider\awssmatoken`\. The token is readable by the Secrets Manager service account (`NT SERVICE\AWSWorkloadCredentialsProvider-SecretsManager`) that the install script configures\.

   **Upgrading:** the install script makes no changes while either provider service is running, so stop both services first, then run it again\. It replaces the token file, so then grant your application read access again, as in the next step\.

   ```powershell
   Stop-Service AWSWorkloadCredentialsProvider-SecretsManager, AWSWorkloadCredentialsProvider-ACM
   .\install.ps1
   ```

1. To allow your application to read the token file, you need to grant read access to the user account that your application runs under\. For example, you can grant permissions for your application to read the token file with the following icacls command, where *<APP\_USER>* is the user account under which your application runs\. The install script creates a new token file each time it runs, so run this command again after every install\.

   ```powershell
   icacls "C:\ProgramData\AWS\WorkloadCredentialsProvider\awssmatoken" /grant "<APP_USER>:(R)"
   ```

   **Note:** When using the install script, the provider reads the SSRF token from file via `AWS_TOKEN=file://C:\ProgramData\AWS\WorkloadCredentialsProvider\awssmatoken` set on the service\. Your application must also read the token from this path and pass it in the `X-Aws-Parameters-Secrets-Token` header\. If you were previously setting `AWS_TOKEN` as an environment variable with a literal token value or a custom file path, update your application to read from the new token file path instead\.

------
#### [ Running as a Secrets Manager Sidecar ]

You can run the Workload Credentials Provider as a sidecar container alongside your application by using Docker\. Then your application can retrieve secrets from the local HTTP server the Workload Credentials Provider provides\. For information about Docker, see the [Docker documentation](https://docs.docker.com)\. 

**Note:** For Certificate Manager sidecar deployment , see [Running as a Certificate Manager Sidecar](#-running-as-a-certificate-manager-sidecar-)\.

**To create a sidecar container for the Workload Credentials Provider with Docker**

1. Create a Dockerfile for the Workload Credentials Provider sidecar container\. The following example creates a Docker container with the Workload Credentials Provider binary\.

   ```dockerfile
   # Use the latest Debian image as the base
   FROM debian:latest
   
   # Set the working directory inside the container
   WORKDIR /app 
   
   # Copy the Workload Credentials Provider binary to the container
   COPY aws-workload-credentials-provider . 
   
   # Install any necessary dependencies
   RUN apt-get update && apt-get install -y ca-certificates 
   
   # Set the entry point to run the Workload Credentials Provider binary
   ENTRYPOINT ["./aws-workload-credentials-provider", "sm", "start"]
   ```

   Windows: `Dockerfile.provider` must import current root CA certificates from Windows Update, or the provider can't make TLS connections to AWS. The `# escape` parser directive must be the first line of the Dockerfile, and the `RUN` step needs a PowerShell `SHELL`:

   ```dockerfile
   # escape=`
   SHELL ["powershell", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop';"]
   RUN certutil -generateSSTFromWU C:\roots.sst | Out-Null; `
       $certs = Import-Certificate -FilePath C:\roots.sst -CertStoreLocation Cert:\LocalMachine\Root; `
       Remove-Item -Force C:\roots.sst; `
       Write-Host ('[trust] imported ' + $certs.Count + ' root CA certificate(s)')
   ```

1. Create a Dockerfile for your client application\.

1. Create a Docker Compose file to run both containers, being sure that they use the same network interface\. This is necessary because the Workload Credentials Provider does not accept requests from outside the localhost interface\. The following example shows a Docker Compose file where the `network_mode` key attaches the `workload-credentials-provider` container to the network namespace of the `client-application` container, which allows them to share the same network interface\.

    **Important**

    You must load AWS credentials and the SSRF token for the application to be able to use the Workload Credentials Provider\. For EKS and ECS, see the following:  
    * [Manage access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-auth.html) in the *Amazon Elastic Kubernetes Service User Guide*
    * [Amazon ECS task IAM role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html) in the *Amazon Elastic Container Service Developer Guide*


   ```yaml
   services:
     client-application:
       container_name: client-application
       build:
         context: .
         dockerfile: Dockerfile.client
       command: tail -f /dev/null  # Keep the container running

     workload-credentials-provider:
       container_name: workload-credentials-provider
       build:
         context: .
         dockerfile: Dockerfile.provider
       network_mode: "container:client-application"  # Attach to the client-application container's network
       depends_on:
         - client-application
   ```

1. Copy the `aws-workload-credentials-provider` binary to the same directory that contains your Dockerfiles and Docker Compose file\.

1. Build and run the containers based on the provided Dockerfiles by using the following [https://docs.docker.com/reference/cli/docker/compose/](https://docs.docker.com/reference/cli/docker/compose/) command\.

   ```sh
   docker compose up --build
   ```

1. In your client container, you can now use the Workload Credentials Provider to retrieve secrets\. For more information, see [Step 3: Retrieve secrets with the Workload Credentials Provider](#workload-credentials-provider-call)\.

------
#### [ Running as a Certificate Manager Sidecar ]

You can run the Workload Credentials Provider as a sidecar container that runs `acm start`, exports your ACM certificates to a shared volume, and (optionally) drives a reload of your TLS server when a certificate rotates. Linux and Windows containers are supported on Docker on Amazon EC2 (Compose), Amazon ECS, and Amazon EKS. The steps are the same across platforms. Only the volume and identity wiring differs, and Windows differences are noted inline.

**How it works.** The provider runs in its own container and exports each certificate's PEM files to a shared volume. For a TLS server that does not reload its certificate files on its own, `wcp-watcher` — a small companion binary that runs inside the TLS container, reads only local files, and needs no AWS credentials or SDK — performs the reload. For each certificate that sets `watcher_id`, the provider writes a per-watcher config (`<watcher_config_dir>/<watcher_id>/watcher.config.toml`) mapping the certificate ARN to its `refresh_command`. After writing a renewed certificate and key, the provider drops a refresh request naming that ARN into the watcher's request directory, and the watcher runs the configured command.

The provider correlates each watcher status with the request and waits for that status before completing the certificate refresh or emitting certificate automation telemetry\. A successful watcher command reports `DEPLOYED` when the attempt replaced certificate files and `RELOADED` when it did not\. Watcher failure, not-found, and superseded outcomes report stage `RELOAD` with code `CommandFailed`\. A reload command that runs out its time, on the watcher or the direct path, and a watcher that does not answer in time report stage `RELOAD` with code `TimeoutError`\. A watcher that predates status reports \(it has an `inbox/` but no `outbox/`\) is not waited for: the provider reports `WRITTEN_NOT_RELOADED` when the attempt replaced files and `UNCHANGED` when it did not\. Failure telemetry reports `filesOnDisk` as `REPLACED` only when that attempt wrote files, and as `NOT_REPLACED` otherwise\. Watcher ID, command ID, exit code, timestamps, and error detail stay in bounded local logs and are not sent in telemetry\. Status correlation is kept in memory and is reset when the provider restarts\. The provider waits up to 2,130 seconds for a status, longer than the 15-minute command timeout: a request can wait behind a reload that is already running, then run its own, and a starting watcher can hold requests for up to 5 minutes\.

**Choose your path.** Pick one before you start; each is followable on its own.
- **Self-reloading TLS server** — Envoy, Traefik, Caddy, or any server that reloads its certificate and key files on its own. Omit `watcher_id` and `refresh_command` from the config, mount only the certificate-and-key volume into the TLS container, and skip the watcher entirely: no `wcp-watcher` in `Dockerfile.tls`, no `WCP_WATCHER_ID` env var, no watcher-requests volume, and no watcher line in the TLS entrypoint. You deploy only the provider container writing the cert volume (Certificate Management Sidecar step 1 without the watcher keys, and step 2).
- **Non-reloading TLS server** — nginx, Apache, HAProxy, or similar. Follow Certificate Management Sidecar steps 1–4 to run `wcp-watcher` in the TLS container so it reloads the server when a certificate rotates.

**Note:** The container path does not use the `install` / `install.ps1` script or sudoers; the provider runs its binary directly as its container's user and the reload runs inside the TLS container via `wcp-watcher`.

**Obtaining the binaries.** The release bundle contains the watcher at `watcher/wcp-watcher` for Linux and `watcher\wcp-watcher.exe` for Windows. Copy both binaries into the Docker build directory before `docker build`. Alternatively, a single `cargo build --release` compiles both executables to `target/release/` (cross-compiled builds under `target/<target-triple>/release/`, e.g. `wcp-watcher.exe` on Windows).

**Shared volumes** (three mounts; at startup on Linux, the provider and watcher check the modes of the two watcher mounts):

- **Certificate and key** — Linux `/shared/certs`, Windows `C:\shared\certs`. Provider RW, watcher RO.
- **Watcher config** — Linux `/shared/wcp-watchers/config`, Windows `C:\shared\wcp-watchers\config`. Provider RW, watcher RO (Linux watcher refuses to start if not RO; Windows check skipped but RO still required).
- **Watcher requests** — Linux `/shared/wcp-watchers/requests`, Windows `C:\shared\wcp-watchers\requests`. Provider RW, watcher RW.

Override with the `watcher_config_dir` / `watcher_requests_dir` config keys for the provider config, and the `WCP_WATCHER_CONFIG_DIR` / `WCP_WATCHER_REQUESTS_DIR` env vars for the watcher.

<a name="acm-sidecar-region"></a>**AWS Region (required).** The ACM capability has no region setting in `config.toml`. The provider calls ACM and AWS STS in the Region it gets from the AWS SDK default chain: the `AWS_REGION` environment variable, then `AWS_DEFAULT_REGION`, then the shared config file, then Amazon EC2 instance metadata (IMDS). That Region must be the Region in each `certificate_arn`. One provider exports certificates from one Region; to export certificates from another Region, run another provider.

| Platform | Region set automatically? | What to do |
| --- | --- | --- |
| Docker on Amazon EC2 | Only from IMDS, if the container can reach it (IMDSv2 needs a hop limit of 2 or more) | Set `AWS_REGION` (recommended) |
| Amazon ECS on AWS Fargate | Yes, Fargate sets `AWS_REGION` to the task's Region | Set `AWS_REGION` only if the certificate is in another Region |
| Amazon ECS on Amazon EC2 | No; only from IMDS, if the task can reach it | Set `AWS_REGION` |
| Amazon EKS with IRSA (EC2 nodes or Fargate) | Yes, the pod identity webhook sets `AWS_REGION` | Set `AWS_REGION` only if the certificate is in another Region |
| Amazon EKS Pod Identity (EC2 nodes only) | No; only from IMDS (hop limit 2 or more) | Set `AWS_REGION` |

We recommend setting `AWS_REGION` explicitly on the provider container in every deployment, to the Region in your `certificate_arn`.

If the Region is missing, the provider writes no certificate files and logs `Certificate export failed for <arn>: failed to construct request`. If it doesn't match the certificate's Region, ACM rejects the export with an error such as `ResourceNotFoundException`. In both cases the provider logs `This may require configuration changes to resolve. Will retry next cycle.`, keeps running, and retries only on the next 24-hour cycle. On a first deployment, the TLS container in these examples waits for the certificate files and doesn't start serving. If the certificate volume already holds files from an earlier export (for example, a Docker Compose named volume), the server keeps serving that certificate until it expires. After you fix the Region, restart the provider container to export immediately.

**Certificate Management Sidecar step 1 — `config.toml`:**

```toml
[logging]
log_to_file = false

[capabilities.acm]
enabled = true

[[capabilities.acm.certificates]]
certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/EXAMPLE"
certificate_path = "/shared/certs/fullchain.pem"   # chain appended when chain_path omitted
private_key_path = "/shared/certs/privkey.pem"
role_arn = "arn:aws:iam::123456789012:role/EXAMPLE-ExportRole"
watcher_id = "nginx"
refresh_command = "/usr/sbin/nginx -s reload"
```

Set `log_to_file = false` so provider logs go to stdout, where `docker logs` and `kubectl logs` show them (and CloudWatch Logs, if the ECS task uses the `awslogs` log driver). The default is `true`; see [Common configuration](#common-configuration).

**Important**

`refresh_command` validation. On Linux `refresh_command` must be an absolute path (element 0 begins with `/`), may use only `a-z A-Z 0-9 / _ - . = + @` and space, and runs with no shell (no `$(...)`, pipes, `;`, `&`, bare names) — enforced at `acm start` and again when the watcher loads its config. In a container on Windows, `wcp-watcher` runs `refresh_command` through PowerShell, so a PowerShell refresh command for your server can be used; shell combinators/redirects/variable expansion/globs are rejected. Host installs on Windows reload differently — see `refresh_command` under [Certificate Management configuration](#certificate-management-configuration).

Passing examples:

- **nginx** — `/usr/sbin/nginx -s reload`
- **Apache (official `httpd` image)** — `/usr/local/apache2/bin/apachectl -k graceful`
- **Apache (distro package)** — `/usr/sbin/apachectl -k graceful`
- **HAProxy** — an absolute-path reload script you provide, e.g. `/usr/local/bin/haproxy-reload`

`watcher_id` format: `^[a-z0-9][a-z0-9._-]{0,63}$` (single path segment; Windows forbids reserved device names or a trailing period).

**Certificate Management Sidecar step 2 — `Dockerfile.provider`:**

```dockerfile
FROM debian:latest

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 aws-workload-credentials-provider /usr/local/bin/aws-workload-credentials-provider
COPY config.toml /etc/aws-workload-credentials-provider/config.toml

ENTRYPOINT ["aws-workload-credentials-provider", "acm", "start", "--config", "/etc/aws-workload-credentials-provider/config.toml"]
```

This example copies a prebuilt release binary into a Debian image and runs as root, so it works as written with the release bundle. It differs from the `Dockerfile.acm` in the repository, which builds the provider from source, runs on a `scratch` image as the non-root user 65532 so it works with `runAsNonRoot`, and takes the configuration file at build time with `--build-arg CONFIG=<path-to-config.toml>`. To run as non-root with this example, see the non-root note under the ECS and EKS deployments.

Windows: `Dockerfile.provider` must import current root CA certificates from Windows Update, or the provider can't make TLS connections to AWS. The `# escape` parser directive must be the first line of the Dockerfile, and the `RUN` step needs a PowerShell `SHELL`:

```dockerfile
# escape=`
SHELL ["powershell", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop';"]
RUN certutil -generateSSTFromWU C:\roots.sst | Out-Null; `
    $certs = Import-Certificate -FilePath C:\roots.sst -CertStoreLocation Cert:\LocalMachine\Root; `
    Remove-Item -Force C:\roots.sst; `
    Write-Host ('[trust] imported ' + $certs.Count + ' root CA certificate(s)')
```

**Certificate Management Sidecar step 3 — `Dockerfile.tls`:**

```dockerfile
FROM <your-tls-server-base-image>

COPY --chmod=0755 wcp-watcher /usr/local/bin/wcp-watcher
# nginx only — for another TLS server, copy its config instead
COPY tls.conf /etc/nginx/conf.d/tls.conf

# Required, no default — must match the certificate's watcher_id in config.toml
ENV WCP_WATCHER_ID=nginx

COPY tls-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["bash", "/entrypoint.sh"]
```

`COPY --chmod` requires BuildKit (the default builder in Docker Engine 23.0 and later; set `DOCKER_BUILDKIT=1` on older versions). On Windows images, omit `--chmod`.

On Linux, the entrypoint runs under `bash` and uses `wait -n`, so the TLS base image needs bash: the official Debian-based `nginx` image has it, but `nginx:alpine` does not, so install bash or use a Debian-based image.

For nginx, add this `tls.conf` file:

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /shared/certs/fullchain.pem;
    ssl_certificate_key /shared/certs/privkey.pem;
}
```

For another TLS server, configure it to serve those two files on the mapped port.

Windows: set `WCP_WATCHER_ID` to the certificate's `watcher_id`, copy `wcp-watcher.exe`, use a PowerShell entrypoint, and the `C:\` default directories.

Windows note: The watcher runs the refresh command under PowerShell, which is not included in the Windows Nano Server image but is included in Server Core.

**Certificate Management Sidecar step 4 — `tls-entrypoint.sh`:**

```bash
#!/usr/bin/env bash
set -eu

until [ -f "/shared/wcp-watchers/config/${WCP_WATCHER_ID}/watcher.config.toml" ]; do
  sleep 1
done

wcp-watcher &

until [ -f /shared/certs/fullchain.pem ] && [ -f /shared/certs/privkey.pem ]; do
  sleep 1
done

nginx -g 'daemon off;' &

wait -n
```

**Note:** the watcher holds refresh requests for a 30-second startup window (`WCP_WATCHER_STARTUP_HOLD_MS`, default `30000`) so a reload is not issued before the TLS server is listening. Windows: PowerShell equivalent.

**Note:** The TLS container runs two processes (the watcher and your TLS server). For background on running multiple processes in one container, see Docker's guide: https://docs.docker.com/engine/containers/multi-service_container/

**Deploy with Docker Compose (Amazon EC2):**

```yaml
services:
  tls:
    build:
      context: .
      dockerfile: Dockerfile.tls
    init: true
    restart: unless-stopped
    volumes:
      - certs:/shared/certs:ro
      - watcher-config:/shared/wcp-watchers/config:ro
      - watcher-requests:/shared/wcp-watchers/requests
    ports:
      - "443:443"
    healthcheck:
      test: ["CMD", "sh", "-c", "test -f /shared/certs/fullchain.pem && test -f /shared/certs/privkey.pem"]
      interval: 10s
      timeout: 5s
      retries: 5

  workload-credentials-provider:
    build:
      context: .
      dockerfile: Dockerfile.provider
    volumes:
      - certs:/shared/certs
      - watcher-config:/shared/wcp-watchers/config
      - watcher-requests:/shared/wcp-watchers/requests
    environment:
      # Required: the Region in certificate_arn (see "AWS Region (required)")
      - AWS_REGION=us-east-1
    # ACM needs no shared network namespace with the TLS container: the provider
    # binds no socket, and provider<->watcher coordination is via the shared
    # volumes above. (network_mode: "service:tls" is only needed for the
    # Secrets Manager localhost HTTP server model, not for ACM.)

volumes:
  certs:
  watcher-config:
  watcher-requests:
```

Provide AWS credentials via the standard SDK credential chain. Then run `docker compose up --build`.

**Deploy on Amazon ECS:**

First build the `Dockerfile.provider` and `Dockerfile.tls` images (Certificate Management Sidecar steps 2–3) and push them to a registry your task can pull (for example Amazon ECR); the `image` fields below reference those pushed images.

Both containers run in one task definition sharing the three volumes.

```json
{
  "family": "wcp-acm-sidecar",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "taskRoleArn": "arn:aws:iam::123456789012:role/wcp-acm-task-role",
  "executionRoleArn": "arn:aws:iam::123456789012:role/wcp-acm-execution-role",
  "volumes": [
    { "name": "certs", "host": {} },
    { "name": "watcher-config", "host": {} },
    { "name": "watcher-requests", "host": {} }
  ],
  "containerDefinitions": [
    {
      "name": "workload-credentials-provider",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/wcp-provider:latest",
      "essential": true,
      "environment": [{ "name": "AWS_REGION", "value": "us-east-1" }],
      "mountPoints": [
        { "sourceVolume": "certs", "containerPath": "/shared/certs", "readOnly": false },
        { "sourceVolume": "watcher-config", "containerPath": "/shared/wcp-watchers/config", "readOnly": false },
        { "sourceVolume": "watcher-requests", "containerPath": "/shared/wcp-watchers/requests", "readOnly": false }
      ]
    },
    {
      "name": "tls",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/wcp-tls:latest",
      "essential": true,
      "environment": [{ "name": "WCP_WATCHER_ID", "value": "nginx" }],
      "portMappings": [{ "containerPort": 443, "protocol": "tcp" }],
      "mountPoints": [
        { "sourceVolume": "certs", "containerPath": "/shared/certs", "readOnly": true },
        { "sourceVolume": "watcher-config", "containerPath": "/shared/wcp-watchers/config", "readOnly": true },
        { "sourceVolume": "watcher-requests", "containerPath": "/shared/wcp-watchers/requests", "readOnly": false }
      ]
    }
  ]
}
```

Notes:
- `AWS_REGION` must be the Region in each `certificate_arn`. Fargate sets it automatically to the task's Region; the EC2 launch type doesn't, so keep it in the task definition. See [AWS Region (required)](#acm-sidecar-region).
- `taskRoleArn` is shared by every container in the task. Grant the task role `sts:AssumeRole` on each certificate's `role_arn`, and add the task role's ARN as a principal in each export role's trust policy; see the trust-policy example below. `acm:ExportCertificate` belongs on the `role_arn`'s own policy (the assumed role), not on `taskRoleArn`. Scope each export role to one workload.
- `readOnly` on the cert and watcher-config mounts preserves the mount boundary described above.
- `essential: true` on the provider: if the provider exits, ECS stops the whole task, including the TLS container, so the TLS server can't keep running with a certificate that is no longer renewed. ECS doesn't restart a standalone task; run the task in an ECS service so ECS starts a replacement.
- To run the containers as a non-root user, see the note below.
- Network mode: this example uses Fargate, which requires `awsvpc`. On the EC2 launch type you can use other network modes, as long as the provider can reach the ACM and STS endpoints and get its task role. See [Amazon ECS task networking](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking.html) and [Amazon ECS task IAM role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html).
- Windows ECS: use the `C:\` default paths and a PowerShell `refresh_command` for your server.

**Deploy on Amazon EKS:**

As with ECS, first build the `Dockerfile.provider` and `Dockerfile.tls` images (Certificate Management Sidecar steps 2–3) and push them to a registry your Pod can pull (for example Amazon ECR); the `image` fields below reference those pushed images.

Both containers run in one Pod sharing `emptyDir` volumes.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wcp-acm-sidecar
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wcp-acm-sidecar
  template:
    metadata:
      labels:
        app: wcp-acm-sidecar
    spec:
      serviceAccountName: wcp-acm
      volumes:
        - name: certs
          emptyDir: {}
        - name: watcher-config
          emptyDir: {}
        - name: watcher-requests
          emptyDir: {}
      containers:
        - name: workload-credentials-provider
          image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/wcp-provider:latest
          env:
            # Required: the Region in certificate_arn (see "AWS Region (required)")
            - name: AWS_REGION
              value: us-east-1
          volumeMounts:
            - name: certs
              mountPath: /shared/certs
            - name: watcher-config
              mountPath: /shared/wcp-watchers/config
            - name: watcher-requests
              mountPath: /shared/wcp-watchers/requests
        - name: tls
          image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/wcp-tls:latest
          env:
            - name: WCP_WATCHER_ID
              value: nginx
          ports:
            - containerPort: 443
          volumeMounts:
            - name: certs
              mountPath: /shared/certs
              readOnly: true
            - name: watcher-config
              mountPath: /shared/wcp-watchers/config
              readOnly: true
            - name: watcher-requests
              mountPath: /shared/wcp-watchers/requests
```

Notes:
- The `wcp-acm` service account must exist and be linked to an IAM role through [IAM roles for service accounts (IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) or [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html). For IRSA, grant the service-account role `sts:AssumeRole` on each certificate's `role_arn`, and add that role's ARN as a principal in each export role's trust policy; for EKS Pod Identity, grant the pod role both `sts:AssumeRole` and `sts:TagSession` on each `role_arn`, add the pod role's ARN as a principal in each export role's trust policy, and allow both actions there because Pod Identity credentials carry session tags. See the trust-policy example below. `acm:ExportCertificate` belongs on the `role_arn`'s own policy (the assumed role), not on the service-account role.
- With IRSA, on EC2 nodes or Fargate, the pod identity webhook sets `AWS_REGION` to the cluster's Region. EKS Pod Identity doesn't set it and runs only on EC2 nodes, where the only fallback is IMDS, so set `AWS_REGION` in the pod spec. In every case it must be the Region in each `certificate_arn`. See [AWS Region (required)](#acm-sidecar-region).
- `readOnly: true` on the cert and watcher-config mounts preserves the mount boundary.
- To run the containers as a non-root user, see the note below.

**Note:** These examples run both containers as the image's default user (root in most images) so they work as written. AWS recommends running containers as a non-root user ([Amazon ECS best practices](https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security-tasks-containers.html), [Amazon EKS best practices](https://docs.aws.amazon.com/eks/latest/best-practices/pod-security.html)), and clusters that enforce the Kubernetes restricted Pod Security Standard reject pods that run as root. You can run the containers as any user that fits your requirements. If you do:
- Run both containers with the same UID, because the provider writes the certificate and private key readable only by their owner. Otherwise use the permission fallback below.
- Make sure the provider can write the shared volumes. On Amazon EKS, set `fsGroup` in the pod `securityContext`. On Amazon ECS, task volumes start out owned by root, so change their ownership first, for example with a short init container that the other containers wait on through `dependsOn`.
- Make sure the TLS server can listen on its port. A non-root process usually can't bind ports below 1024, so have the server listen on a high port such as `8443` and map `443` to it, or use an image built for non-root such as `nginxinc/nginx-unprivileged`.

**IAM permissions:** The provider identity needs `sts:AssumeRole` on each `role_arn`; each `role_arn` needs `acm:ExportCertificate` and a trust policy allowing the provider identity. With EKS Pod Identity, the provider identity also needs `sts:TagSession` on each `role_arn`, and the export role's trust policy must allow `sts:TagSession`, because Pod Identity credentials carry session tags. The watcher needs no AWS permissions. Apply this trust policy to each export role, replacing the placeholder with the ECS task role, the EKS service-account role, or (Docker Compose on Amazon EC2) the instance profile role ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/<task-or-service-account-role>" },
    "Action": "sts:AssumeRole"
  }]
}
```

For EKS Pod Identity, use `"Action": ["sts:AssumeRole", "sts:TagSession"]`.

**Permission fallback.** Where a same-UID setup isn't practical, certificate and key files default to `0600`. Add these two keys inside the existing `[[capabilities.acm.certificates]]` entry from Certificate Management Sidecar step 1, after `private_key_path` (do not add a second `[[capabilities.acm.certificates]]` header):

```toml
certificate_and_chain_permission = { mode = "0644" }
key_permission = { mode = "0640" }
```

The key file takes the provider's group, so run the provider with the shared group as its primary GID (on Amazon EKS, `fsGroup` sets this on the shared volume) and add the TLS server user to that group. Prefer the same-UID path above when you can — it keeps the key owner-only (`0600`). If you use the `0640` fallback, the shared group **must be a dedicated group** created for this purpose: any process in that group, now or later, can read the private key.

------
#### [ Running ACM as a Discovery-Only Container Sidecar ]

You can run the Certificate Management \(ACM\) capability as a sidecar container alongside your application on Amazon ECS or Amazon EKS\. The sidecar runs `acm start` in its own container, separate from the Secrets Manager sidecar, so a failure in one does not stop the other\. In a container, the ACM capability supports certificate discovery\. You build the image with `Dockerfile.acm` and pass your configuration file with the `CONFIG` build argument\. The build copies the file into the image at `/etc/aws-workload-credentials-provider/config.toml`, which `acm start` reads at startup\. To change the configuration, rebuild the image\.

**Note:** This sidecar does certificate discovery only\. Do not configure certificates in its configuration\. To export certificates to a shared volume and reload a TLS server when they rotate, use [Running as a Certificate Manager Sidecar](#-running-as-a-certificate-manager-sidecar-) instead\.

**To create an ACM sidecar container**

1. Create a configuration file inside the Workload Credentials Provider source directory, for example `config.toml`\. The file must be inside the Docker build context\. Set `log_to_file = false` so the container runtime collects the logs\. For the discovery options, see [Certificate discovery configuration](#certificate-discovery-configuration)\.

   ```toml
   [logging]
   log_to_file = false

   [capabilities.acm]
   enabled = true

   [capabilities.acm.discovery]
   enabled = true

   [capabilities.acm.discovery.discovery_targets]
   443 = ["api.example.com"]
   8443 = []
   ```

1. Build the image, passing the path to your configuration file\. The build fails if `CONFIG` is not set\.

   ```sh
   docker build -f Dockerfile.acm --build-arg CONFIG=config.toml -t workload-credentials-provider-acm .
   ```

1. Push the image to a registry your tasks or nodes can pull from, such as an Amazon ECR repository in your account\.

1. Run the image next to your application, following these network requirements\. Discovery reaches your application only through loopback, so the ACM container must share your application's network namespace\.

   + On Amazon ECS, add the ACM container to your application's task definition and use the `awsvpc` network mode\. The provider reads the network mode from the task metadata, and in any other mode it logs a warning and discovery does not start: with `bridge` mode discovery would reach only the ACM container itself, and with `host` mode every service listening on the host's loopback\.
   + On Amazon EKS, add the ACM container to your application's pod\. Do not set `hostNetwork: true`: discovery would then reach every service listening on the host's loopback and report them under the pod's identity\. The provider does not check `hostNetwork`\. A separate pod or a DaemonSet cannot reach your application through loopback\.
   + The ACM container opens no listener, so it needs no port mapping, Kubernetes Service, or inbound security group rule\.
   + The image runs as the non-root user `65532`, so it starts in pods that require `runAsNonRoot`\.
   + The provider detects the compute it runs on to choose the discovery mode\. On Amazon ECS it reads the task metadata endpoint that the ECS agent provides\. On Amazon EKS it needs a service account token in the pod: the default token, or an IAM Roles for Service Accounts \(IRSA\) or EKS Pod Identity token\. Without one, discovery does not start and the provider logs a warning\.

   The following Amazon ECS task definition runs your application and the ACM container in one task\. Replace the placeholders with your values\. With `"essential": false`, the task keeps running your application if the ACM container stops\.

   ```json
   {
     "family": "my-application",
     "networkMode": "awsvpc",
     "requiresCompatibilities": ["FARGATE"],
     "cpu": "256",
     "memory": "512",
     "executionRoleArn": "arn:aws:iam::<ACCOUNT_ID>:role/<TASK_EXECUTION_ROLE>",
     "containerDefinitions": [
       {
         "name": "client-application",
         "image": "<APPLICATION_IMAGE>",
         "essential": true
       },
       {
         "name": "workload-credentials-provider-acm",
         "image": "<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/workload-credentials-provider-acm:latest",
         "essential": false,
         "dependsOn": [{ "containerName": "client-application", "condition": "START" }],
         "logConfiguration": {
           "logDriver": "awslogs",
           "options": {
             "awslogs-group": "<LOG_GROUP>",
             "awslogs-region": "<REGION>",
             "awslogs-stream-prefix": "acm"
           }
         }
       }
     ]
   }
   ```

   The following Amazon EKS pod runs your application and the ACM container in one pod\. In a Deployment, add the ACM container to the pod template the same way\.

   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: client-application
   spec:
     containers:
       - name: client-application
         image: <APPLICATION_IMAGE>
       - name: workload-credentials-provider-acm
         image: <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/workload-credentials-provider-acm:latest
   ```

   With Docker Compose, attach the ACM container to your application's network namespace\. Docker Compose works only on Amazon EC2: outside Amazon ECS and Amazon EKS, the provider identifies the compute through the EC2 instance metadata service \(IMDS\), so on other hosts discovery does not start\. The provider uses IMDSv2, which a container reaches only when the instance's metadata response hop limit is 2 or more\. For more information, see [Configure instance metadata options for existing instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html) in the *Amazon EC2 User Guide*\.

   ```yaml
   services:
       client-application:
           container_name: client-application
           build:
               context: .
               dockerfile: Dockerfile.client

       workload-credentials-provider-acm:
           container_name: workload-credentials-provider-acm
           image: workload-credentials-provider-acm
           network_mode: "container:client-application"  # Share the application's network namespace
           depends_on:
               - client-application
   ```

1. Check the ACM container logs for `Certificate discovery starting`\. On Amazon ECS, the logs are in the CloudWatch Logs group from the task definition\. On Amazon EKS, run `kubectl logs <pod> -c workload-credentials-provider-acm`\. The provider logs this line after it identifies the compute, which takes at most a few seconds\. The first discovery cycle starts within 5 minutes of that line and then repeats about once every 24 hours\.

------
#### [ AWS Lambda ]

You can [package the Workload Credentials Provider as an AWS Lambda extension](https://docs.aws.amazon.com/lambda/latest/dg/packaging-layers.html)\. Then you can [add it to your Lambda function as a layer](https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html) and call the Workload Credentials Provider from your Lambda function to get secrets\. 

**Note:** The Certificate Management capability is not supported on AWS Lambda\.

The following instructions show how to get a secret named *MyTest* by using the example script `secrets-manager-provider-extension.sh` in [https://github\.com/aws/aws\-workload\-credentials\-provider](https://github.com/aws/aws-workload-credentials-provider) to install the Workload Credentials Provider as a Lambda extension\.

**To create a Lambda extension that packages the Workload Credentials Provider**

1. Package the provider as a layer. From the root of the Workload Credentials Provider code package, run the following example commands\:

   ```sh
   AWS_ACCOUNT_ID=<AWS_ACCOUNT_ID>
   LAMBDA_ARN=<LAMBDA_ARN>
   
   # Build the release binary 
   cargo build --release --target=x86_64-unknown-linux-gnu
   
   # Copy the release binary into the `bin` folder
   mkdir -p ./bin
   cp ./target/x86_64-unknown-linux-gnu/release/aws-workload-credentials-provider ./bin/aws-workload-credentials-provider
   
   # Copy the `secrets-manager-provider-extension.sh` example script into the `extensions` folder.
   mkdir -p ./extensions
   cp aws_secretsmanager_provider/examples/example-lambda-extension/secrets-manager-provider-extension.sh ./extensions
   
   # Zip the extension shell script and the binary 
   zip secrets-manager-provider-extension.zip bin/* extensions/*
   
   # Publish the layer version
   LAYER_VERSION_ARN=$(aws lambda publish-layer-version \
       --layer-name secrets-manager-provider-extension \
       --zip-file "fileb://secrets-manager-provider-extension.zip" | jq -r '.LayerVersionArn')
   ```

2. The default configuration of the provider will automatically set the SSRF token to the value set in the pre-set `AWS_SESSION_TOKEN` or `AWS_CONTAINER_AUTHORIZATION_TOKEN` environment variables (the latter variable for Lambda functions with SnapStart enabled). Alternatively, you can define the `AWS_TOKEN` environment variable with an arbitrary value for your Lambda function instead as this variable takes precedence over the other two. If you choose to use the `AWS_TOKEN` environment variable, you must set that environment variable with a `lambda:UpdateFunctionConfiguration` call\.


3. Attach the layer version  to your Lambda function:
   ```sh
   # Attach the layer version to the Lambda function
   aws lambda update-function-configuration \
       --function-name $LAMBDA_ARN \
       --layers "$LAYER_VERSION_ARN"
   ```
4. Update your Lambda function to query `http://localhost:2773/secretsmanager/get?secretId=MyTest` with the `X-Aws-Parameters-Secrets-Token` header value set to the value of the SSRF token sourced from one the environment variables mentioned above to retrieve the secret. Be sure to implement retry logic in your application code to accommodate delays in initialization and registration of the Lambda extension\.


5. Invoke the Lambda function to verify that the secret is being correctly fetched\. 

------

## Step 3: Retrieve secrets with the Workload Credentials Provider<a name="workload-credentials-provider-call"></a>

**The following sections describe how to use the Secrets Manager capability\.**

To retrieve a secret, you call the local Workload Credentials Provider endpoint and include the name or ARN of the secret as a query parameter\. By default, the Workload Credentials Provider retrieves the `AWSCURRENT` version of the secret\. To retrieve a different version, you can set `versionStage` or `versionId`\. To retrieve a secret using a different IAM role, you can set `roleArn`\. For more information, see [Role chaining \(cross\-account access\)](#role-chaining-cross-account-access)\. To retry a request in a second AWS region when the primary region is unavailable, you can set `failoverRegion` or configure failover\. For more information, see [Region failover](#region-failover)\.

To help protect the Workload Credentials Provider, you must include a SSRF token header as part of each request: `X-Aws-Parameters-Secrets-Token`\. The Workload Credentials Provider denies requests that don't have this header or that have an invalid SSRF token\. You can customize the SSRF header name in the [Configuration file](#workload-credentials-provider-config)\.

The Workload Credentials Provider uses the AWS SDK for Rust, which uses the [https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html)\. The identity of these IAM credentials determines the permissions the Workload Credentials Provider has to retrieve secrets\. 

**Required permissions: **
+ `secretsmanager:DescribeSecret`
+ `secretsmanager:GetSecretValue`

For more information, see [Permissions reference](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_iam-policies.html)\.

**Important**  
After the secret value is pulled into the Workload Credentials Provider, any user with access to the compute environment and SSRF token can access the secret from the Workload Credentials Provider cache\. For more information, see [Security considerations](#workload-credentials-provider-security)\.

------
#### [ curl ]

The following curl example shows how to get a secret from the Workload Credentials Provider\. The example relies on the SSRF being present in a file, which is where it is stored by the install script\.

```sh
curl -v -H \
    "X-Aws-Parameters-Secrets-Token: $(</var/run/awssmatoken)" \
    'http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>'; \
    echo
```

------
#### [ Python ]

The following Python example shows how to get a secret from the Workload Credentials Provider\. The example relies on the SSRF being present in a file, which is where it is stored by the install script\.

```python
import requests

# Function that fetches the secret from Workload Credentials Provider for the provided secret id. 
def get_secret():
    # Construct the URL for the GET request
    url = f"http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>"

    # Get the SSRF token from the token file
    with open('/var/run/awssmatoken') as fp:
        token = fp.read() 

    headers = {
        "X-Aws-Parameters-Secrets-Token": token.strip()
    }

    try:
        # Send the GET request with headers
        response = requests.get(url, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            # Return the secret value
            return response.text
        else:
            # Handle error cases
            raise Exception(f"Status code {response.status_code} - {response.text}")

    except Exception as e:
        # Handle network errors
        raise Exception(f"Error: {e}")
```
------

**Force-refresh secrets with `RefreshNow`**

Learn how to use the refreshNow parameter to force the Workload Credentials Provider to refresh secret values.

Workload Credentials Provider uses an in-memory cache to store secret values, which it refreshes periodically. By default, this refresh occurs when you request a secret after the Time to Live (TTL) has expired, typically every 300 seconds. However, this approach can sometimes result in stale secret values, especially if a secret rotates before the cache entry expires.

To address this limitation, Workload Credentials Provider supports a parameter called `refreshNow` in the URL. You can use this parameter to force an immediate refresh of a secret's value, bypassing the cache and ensuring you have the most up-to-date information.

Default behavior (without `refreshNow`):
- Uses cached values until TTL expires
- Refreshes secrets only after TTL (default 300 seconds)
- May return stale values if secrets rotate before the cache expires

Behavior with `refreshNow=true`:
- Bypasses the cache entirely
- Retrieves the latest secret value directly from Secrets Manager
- Updates the cache with the fresh value and resets the TTL
- Ensures you always get the most current secret value

By using the `refreshNow` parameter, you can ensure that you're always working with the most current secret values, even in scenarios where frequent secret rotation is necessary.

## `refreshNow` parameter behavior

`refreshNow` set to `true`:
- If Workload Credentials Provider can't retrieve the secret from Secrets Manager, it returns an error and does not update the cache.

`refreshNow` set to `false` or not specified:
- Workload Credentials Provider follows its default behavior:
  - If the cached value is fresher than the TTL, Workload Credentials Provider returns the cached value.
  - If the cached value is older than the TTL, Workload Credentials Provider makes a call to Secrets Manager.

## Using the refreshNow parameter

To use the `refreshNow` parameter, include it in the URL for the Workload Credentials Provider GET request.

### Example - Workload Credentials Provider GET request with refreshNow parameter

> **Important**: The default value of `refreshNow` is `false`. When set to `true`, it overrides the TTL specified in the Workload Credentials Provider configuration file and makes an API call to Secrets Manager.

#### [ curl ]

The following curl example shows how force Workload Credentials Provider to refresh the secret. The example relies on the SSRF being present in a file, which is where it is stored by the install script.

```bash
curl -v -H \
"X-Aws-Parameters-Secrets-Token: $(</var/run/awssmatoken)" \
'http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>&refreshNow=true' \
echo
```

#### [ Python ]

The following Python example shows how to get a secret from the Workload Credentials Provider. The example relies on the SSRF being present in a file, which is where it is stored by the install script.

```python
import requests

# Function that fetches the secret from Workload Credentials Provider for the provided secret id. 
def get_secret():
    # Construct the URL for the GET request
    url = f"http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>&refreshNow=true"

    # Get the SSRF token from the token file
    with open('/var/run/awssmatoken') as fp:
        token = fp.read() 

    headers = {
        "X-Aws-Parameters-Secrets-Token": token.strip()
    }

    try:
        # Send the GET request with headers
        response = requests.get(url, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            # Return the secret value
            return response.text
        else:
            # Handle error cases
            raise Exception(f"Status code {response.status_code} - {response.text}")

    except Exception as e:
        # Handle network errors
        raise Exception(f"Error: {e}")
```
------

## Role chaining \(cross\-account access\)<a name="role-chaining-cross-account-access"></a>

The Workload Credentials Provider supports retrieving secrets using IAM role assumption \(role chaining\)\. This allows you to access secrets in other AWS accounts or with different IAM permissions without running separate provider instances\.

To retrieve a secret using a different IAM role, include the `roleArn` query parameter in your request\. The Workload Credentials Provider uses STS `AssumeRole` to obtain temporary credentials for the specified role and then retrieves the secret with those credentials\.

The Workload Credentials Provider creates and caches a separate caching client for each unique role ARN\. Role clients are created lazily on first request and reused for subsequent requests with the same role ARN\. Each role client maintains its own independent cache, so the same secret fetched with different roles will have separate cache entries\.

**Required permissions: **
+ `sts:AssumeRole` on the target role ARN
+ The target role must have `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` permissions

**Error responses: **
+ `400` – If the `roleArn` format is invalid or the maximum number of assumed roles has been reached\.
+ `403` – If the STS `AssumeRole` call fails \(for example, the trust policy does not allow the provider's identity to assume the role\)\.

You can configure the maximum number of simultaneous assumed roles with the `max_roles` option in the [Configuration file](#workload-credentials-provider-config)\. The default is 20\.

**Note:** Assumed roles are not evicted from the provider's role cache\. Once the maximum number of roles has been reached, requests with new role ARNs will be rejected with a `400` error until the provider is restarted\.

------
#### [ curl ]

The following curl example shows how to retrieve a secret using a different IAM role\.

```sh
curl -v -H \
    "X-Aws-Parameters-Secrets-Token: $(</var/run/awssmatoken)" \
    'http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>&roleArn=arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>'; \
    echo
```

------
#### [ Python ]

The following Python example shows how to retrieve a secret using a different IAM role\.

```python
import requests

def get_secret_cross_account():
    role_arn = "arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>"
    url = f"http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>&roleArn={role_arn}"

    with open('/var/run/awssmatoken') as fp:
        token = fp.read()

    headers = {
        "X-Aws-Parameters-Secrets-Token": token.strip()
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.text
        else:
            raise Exception(f"Status code {response.status_code} - {response.text}")

    except Exception as e:
        raise Exception(f"Error: {e}")
```

------

## Pre\-fetching<a name="pre-fetching"></a>

The Workload Credentials Provider supports pre\-fetching secrets into the cache at startup\. This allows your application to read secrets from the cache immediately without waiting for the first request to trigger a cache miss and network call\.

To enable pre\-fetching, add a `[capabilities.secrets_manager.prefetch]` section to your [Configuration file](#workload-credentials-provider-config)\. You can specify secrets to pre\-fetch in two ways:

+ **Explicit secrets** – List specific secret IDs or ARNs using `[[capabilities.secrets_manager.prefetch.secrets]]` entries\.
+ **Tag\-based discovery** – Discover secrets by tag key using `[[capabilities.secrets_manager.prefetch.filter_tags]]` entries\. The provider calls `BatchGetSecretValue` with tag key filters to find and cache all secrets that have the specified tag key, regardless of the tag's value\.

You can use both methods together\. Each entry optionally accepts a `role_arn` field for cross\-account pre\-fetching via [role chaining](#role-chaining-cross-account-access)\.

**Required permissions: **
+ `secretsmanager:BatchGetSecretValue` – Required for all pre\-fetching operations\.
+ `secretsmanager:ListSecrets` – Required when using tag\-based discovery \(`filter_tags`\)\.

**Pre\-fetch configuration options: **
+ **cache\_buffer\_ratio** – The maximum fraction of the cache to fill per caching client during pre\-fetch, in the range 0\.1 to 1\.0\. The default is 0\.8\.
+ **max\_jitter\_seconds** – The maximum random delay in seconds before starting the pre\-fetch task, in the range 0 to 10\. The default is 0 \(no jitter\)\. Use this to prevent fleet\-wide synchronized API calls\.

### Example \- Pre\-fetch with explicit secrets

```toml
[[capabilities.secrets_manager.prefetch.secrets]]
secret_id = "arn:aws:secretsmanager:us-west-2:123456789012:secret:MySecret-AbCdEf"

[[capabilities.secrets_manager.prefetch.secrets]]
secret_id = "cross-account-secret"
role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole"
```

### Example \- Pre\-fetch with explicit secrets \(inline syntax\)

```toml
[capabilities.secrets_manager.prefetch]
max_jitter_seconds = 5
cache_buffer_ratio = 0.9
secrets = [
  { secret_id = "arn:aws:secretsmanager:us-west-2:123456789012:secret:MySecret-AbCdEf" },
  { secret_id = "cross-account-secret", role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole" },
]
filter_tags = [
  { key = "Environment" },
  { key = "Team", role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole" },
]
```

### Example \- Pre\-fetch with tag\-based discovery

```toml
[[capabilities.secrets_manager.prefetch.filter_tags]]
key = "Environment"

[[capabilities.secrets_manager.prefetch.filter_tags]]
key = "Team"
role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole"
```

### Example \- Full configuration with pre\-fetching

```toml
[logging]
log_level = "info"

[capabilities.secrets_manager]
http_port = 2773
region = "us-east-1"
max_roles = 5

[capabilities.secrets_manager.cache]
ttl_seconds = 300

[capabilities.secrets_manager.prefetch]
cache_buffer_ratio = 0.6
max_jitter_seconds = 5

[[capabilities.secrets_manager.prefetch.secrets]]
secret_id = "arn:aws:secretsmanager:us-west-2:123456789012:secret:MySecret-AbCdEf"

[[capabilities.secrets_manager.prefetch.secrets]]
secret_id = "arn:aws:secretsmanager:us-east-1:987654321098:secret:CrossAccount-AbCdEf"
role_arn = "arn:aws:iam::987654321098:role/SecretAccessRole"

[[capabilities.secrets_manager.prefetch.filter_tags]]
key = "Environment"

[[capabilities.secrets_manager.prefetch.filter_tags]]
key = "Team"
role_arn = "arn:aws:iam::987654321098:role/TagRole"
```

## Region failover<a name="region-failover"></a>

By default, the Workload Credentials Provider reads secrets from a single AWS region\. With region failover, when Secrets Manager in the primary region returns a server error, times out, can't be reached, or throttles the request, the provider retries the request in a failover region\.

Failover is opt\-in\. If you don't configure failover and don't use the `failoverRegion` query parameter, the provider behaves as before\.

Before you use failover:
+ The secret must exist in the failover region under the same name, with the same value\. [Multi\-region secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/replicate-secrets.html) keep the replica in sync for you\. If you replicate secrets yourself, you must keep them in sync\.
+ The provider's credentials, and any role you pass in `roleArn`, need `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` in the failover region\. For [credential failover](#region-failover-credentials), they also need the same STS permissions in `default_failover_region` as in the primary region\.

### How the failover region is chosen

Each request uses at most one failover region\. The provider picks it in this order:

1. The `failoverRegion` query parameter on the request\. It works even when failover isn't configured\.
1. The `secret_to_region_map` entry for the secret\.
1. `default_failover_region`\.

If none of these is set, the request doesn't fail over\.

`secret_to_region_map` keys are secret ARNs and must match the request's `secretId` exactly\. A request by friendly name doesn't match an ARN key, so it uses `default_failover_region` instead\. Request secrets that have a map entry by their ARN\.

### When the provider fails over

The provider fails over on server errors \(5XX\), timeouts, connection failures, and throttling\. It doesn't fail over on errors that would fail the same way in every region, such as `AccessDeniedException` or `ResourceNotFoundException`\.

If the failover region fails too, by default the provider returns the cached value if it has one, or the primary region's error\. With `refreshNow=true`, it returns the error\.

`operation_timeout_ms` sets the number of milliseconds the provider waits for the primary region before it fails over\. The default is 3000 milliseconds\. It applies only to requests that have a failover region\. Other requests keep their current timeouts\. If your failover region is far from the primary region, consider raising `operation_timeout_ms`\.

### Credential failover \(STS\)<a name="region-failover-credentials"></a>

**Important**  
Only `default_failover_region` turns on credential failover\. With only `secret_to_region_map` or the `failoverRegion` query parameter, requests can fail when credentials need to be refreshed while STS in the primary region is down\. We recommend setting `default_failover_region`\.

When `default_failover_region` is set and STS in the primary region is down, the provider gets credentials from STS in `default_failover_region` for:
+ Roles in `roleArn`\.
+ The provider's own credentials, if they come from STS\. This is the case with [IAM roles for service accounts \(IRSA\)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) on Amazon EKS, and with an AWS profile that sets `role_arn`\. Other credential sources, such as Amazon EC2 instance metadata, Amazon ECS and EKS Pod Identity credentials, access keys, `credential_process`, IAM Identity Center \(SSO\), and `credentials_file_path`, don't call STS and don't fail over\.

If credentials can't be loaded in either region, the request can fail even when the secret is cached\.

**Throttling** – If a primary STS call is still being retried after throttling when its time runs out, the provider fails over\. If throttling causes frequent failovers, raise `operation_timeout_ms`\.

**Profiles with `role_arn` and a `credential_process` or SSO `source_profile`** – The `source_profile` helper must finish within the STS call's time, which is half of `operation_timeout_ms`, up to 5 seconds\. A slower helper, such as an IAM Roles Anywhere `credential_process`, causes a failover on every credential refresh even when STS is healthy\. Raise `operation_timeout_ms` so the helper fits\.

### Logging<a name="region-failover-logging"></a>

Every failover writes a `WARN` log line that starts with `failover=true`, including throttled STS calls that fail over\. We recommend alarming on repeated failover lines\.

```
failover=true operation=GetSecretValue secret_id=MySecret primary_region=us-east-1 primary_error="dispatch failure: io error: ..." failover_region=us-west-2 result=ok version_id=EXAMPLE1-90ab-cdef-fedc-ba987EXAMPLE
```

### Limitations

+ An endpoint set with `AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_SECRETS_MANAGER` or `AWS_ENDPOINT_URL_STS` overrides the region, so failover doesn't reach another region\. `AWS_ENDPOINT_URL_STS` affects only credential failover\.
+ Secrets with a different name in each region aren't supported\.
+ Failover applies to the Secrets Manager capability only, not to Certificate Management\.
+ On AWS Lambda, a failover can take longer than the default function timeout of 3 seconds\. Set the function timeout to more than `operation_timeout_ms` plus a few seconds, for example 10 seconds at the default `operation_timeout_ms`\.

### Example \- Failover configuration

Setting `default_failover_region` or `secret_to_region_map` turns on failover for Secrets Manager calls\. Only `default_failover_region` also turns on [credential failover](#region-failover-credentials)\. For each option, see [Secrets Manager configuration](#secrets-manager-configuration)\.

```toml
[capabilities.secrets_manager]
region = "us-east-1"

[capabilities.secrets_manager.failover]
default_failover_region = "us-west-2"
operation_timeout_ms = 3000

[capabilities.secrets_manager.failover.secret_to_region_map]
"arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-1-AbCdEf" = "eu-west-1"
"arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-2-GhIjKl" = "ap-northeast-1"
```

### The `failoverRegion` query parameter

Add `failoverRegion` to a query\-based or path\-based request to set its failover region\. It takes precedence over the configuration\. The value must have the format of a region code, such as `us-west-2`, or the provider returns `400`\.

```sh
curl -v -H \
    "X-Aws-Parameters-Secrets-Token: $(</var/run/awssmatoken)" \
    'http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>&failoverRegion=us-west-2'; \
    echo
```

## Step 4: Retrieve certificates with the Workload Credentials Provider<a name="workload-credentials-provider-acm"></a>

**The following sections describe how to use the Certificate Management capability\.**

To enable the Certificate Management capability, add a `[capabilities.acm]` section to your configuration file with `enabled = true` and one or more certificate entries\. The provider will automatically export and refresh configured certificates every 24 hours\.

**Required permissions:**
+ `sts:AssumeRole` — Required on the provider's environment credentials to assume the configured role for each certificate
+ `acm:ExportCertificate` — Required on the target role (`role_arn`) to export the certificate and private key from ACM

**Important**  
After certificates are written to the filesystem, any user with read access to the certificate and private key files can access them\. Use the `certificate_and_chain_permission` and `key_permission` configuration options to restrict file access\. Certificate paths, refresh commands, and file permissions are customer\-configured\. Validate your configuration before applying it to ensure paths are correct and refresh commands are trusted\. For more information, see [Security considerations](#workload-credentials-provider-security)\.

For full configuration details, see [Configure the Workload Credentials Provider](#workload-credentials-provider-config)\.

## Step 5: Turn on certificate discovery and telemetry<a name="workload-credentials-provider-discovery"></a>

**The following sections describe certificate discovery and telemetry, optional features of the Certificate Management capability\.**

Certificate discovery reports the TLS certificates that your workloads present on the local ports you configure, including certificates that ACM doesn't issue or manage\. Telemetry sends the discovery results, and the result of each ACM certificate export and refresh, to AWS\.

With the AWS Certificate Manager enterprise premium plan, these results populate your certificate inventory in ACM\. You can then see the certificates discovered across your workloads in one place, whichever certificate authority issued them\.

Both features are off by default\. Discovery works whether or not you configure any certificates for export, but the Certificate Management capability must be enabled\.

Discovery and telemetry run on Amazon EC2, Amazon ECS, and Amazon EKS, where the provider can identify the compute it runs on\. On on\-premise hosts, AWS Lambda, and other compute that the provider can't identify, the provider sends no telemetry and doesn't run discovery\. Certificate export and refresh still work there\.

**Required permissions:**
+ `workload-telemetry:PutCertificateTelemetry` — Required on the provider's own AWS credentials: the Amazon EC2 instance profile, the Amazon ECS task role, or the Amazon EKS service account or Pod Identity role\. It isn't needed on the certificate's `role_arn`\. For an example policy, see [Telemetry configuration](#telemetry-configuration)\.

**Important**  
Discovery reports the public certificate of every TLS server listening on the configured ports, not only certificates from ACM\. Review the data with `[telemetry] dry_run = true` before you send it\. Telemetry never contains private keys\.

### Benefits

+ **Find certificates on your configured ports** – Discovery reports the certificate each configured local port and SNI hostname presents, including certificates from other certificate authorities and self\-signed certificates\.
+ **Find certificates that are close to expiring** – Each reported certificate includes its chain and validity dates, so you can renew certificates before they cause an outage\.
+ **See the TLS settings of each connection** – Each observation includes the TLS version, cipher suite, and signature scheme negotiated for that handshake, and whether the server asked for a client certificate\. Discovery records one handshake per port and hostname\. It doesn't list every version or cipher a server accepts, so it isn't a full TLS configuration audit\. Discovery offers only TLS 1\.2 and TLS 1\.3: a server that accepts only older versions fails the handshake and appears only in the failed\-probe count\.
+ **Confirm ACM certificate deployment** – Export and refresh results show, for each configured ACM certificate, whether the new certificate was deployed or unchanged, or at which step it failed: export, write to disk, or the refresh command\.
+ **No extra software** – Discovery runs inside the provider you already deploy for certificate export\. It connects only to the local loopback address and reads only what any TLS client sees\.

### How certificate discovery works

When discovery is on, the provider:

1. Identifies the compute it runs on: an Amazon EC2 instance, an Amazon ECS task, or an Amazon EKS pod\.
1. Within 5 minutes of starting, and then every 24 hours plus up to 5 minutes, connects over TLS to each configured local port, once without a server name \(SNI\) and once for each configured hostname\. It connects only to loopback \(`127.0.0.1`, then `::1`\), completes the handshake without sending a client certificate, and records the certificate the server presents\.
1. Sends the results to the AWS workload telemetry service\. Ports that refuse the connection, don't use TLS, or fail the handshake are counted in the scan summary but not reported individually\.

Discovery doesn't read private keys or certificate files from disk, and it doesn't send application data to the servers it probes\. It finds only certificates served on the configured ports in its own network namespace\. It doesn't reach other hosts, load balancers, or unconfigured ports\.

On Amazon ECS and Amazon EKS, the provider runs as a sidecar and must share a network namespace with the application container\. For the requirements, see [Certificate discovery configuration](#certificate-discovery-configuration)\.

### What telemetry is sent

The provider sends each kind of telemetry only when you turn it on:

+ **Discovery results** – Sent when you turn on certificate discovery\. Turning on discovery is your consent to send its results\.
+ **Export and refresh results** – Sent when you set `enabled = true` under `[telemetry.acm]`\.

Telemetry is best effort\. Records are held in memory, and some can be lost if the provider is stopped abruptly, its queue fills, or AWS can't be reached\. Don't use telemetry as an audit log\. Certificate export and refresh never wait for telemetry\. For the full list of fields, the endpoint, and retries, see [Telemetry configuration](#telemetry-configuration)\.

### Set up certificate discovery and telemetry

1. Grant the provider's credentials `workload-telemetry:PutCertificateTelemetry` \(see [Required permissions](#workload-credentials-provider-discovery)\)\.
1. In your configuration file, enable the Certificate Management capability, turn on discovery, and list the ports your TLS servers listen on and the hostnames they serve:

   ```toml
   [capabilities.acm]
   enabled = true

   [capabilities.acm.discovery]
   enabled = true

   [capabilities.acm.discovery.discovery_targets]
   443 = ["api.example.com", "www.example.com"]
   8443 = []
   ```

1. \(Recommended\) Review the data before you send it\. Set `dry_run = true` under `[telemetry]` and apply the configuration\. Each request is written as JSON to `logs/acm_provider_telemetry_dryrun.log`, or to the container's console output when `log_to_file = false`\. A dry run still needs AWS credentials and a Region, but not the IAM permission\. Discovery requests appear after each scan; export and refresh results appear when the queue is flushed, about once an hour, and when the provider stops\. When you are ready to send, set `dry_run = false`\.
1. \(Optional\) To also send export and refresh results for your ACM certificates, add the following:

   ```toml
   [telemetry.acm]
   enabled = true
   ```

1. Apply the configuration\. On Amazon EC2 and on\-premise hosts, run `acm reload` \(see [Configuration reload](#configuration-reload-certificate-management)\)\. In a container deployment, update the configuration and restart the provider container\.
1. Check the provider log, `logs/acm_provider.log`, or the container's console output\. After a successful scan, it contains lines like the following:

   ```
   Certificate discovery starting: 2 ports, timeout 300s
   Discovery cycle completed: 4 observations in 412ms (4 targets, 0 failed)
   Discovery: submitted 1 batch(es) for cycle <cycle-id>
   ```

1. Confirm that the data is being sent\. `Discovery: submitted ...` means the provider handed the batch to its sender, not that AWS received it\. Check that the log has no `Telemetry is off:`, `Telemetry (stub):`, or `Telemetry dry run for` lines\. To confirm that AWS accepted a request, set `log_level = "debug"` under `[logging]`\. Each accepted request then logs `Telemetry: request <id> sent on attempt <n> of 3`\.

### Troubleshoot certificate discovery

+ **A target failed** – The summary line counts failed targets but doesn't name them\. With `log_level = "debug"`, each probe logs `<address>:<port> (sni=<hostname>): probe completed with <outcome>`, where the outcome is, for example, `connection_refused`, `not_tls`, `timeout`, or `handshake_error`\.
+ **`Discovery: identity detection failed`** – The provider couldn't identify its compute, so discovery doesn't run\. On Amazon EC2, check that the instance metadata service is reachable\.
+ **`Discovery disabled: ...`** – The compute isn't supported for discovery, for example AWS Lambda, or an Amazon ECS task that doesn't use the `awsvpc` network mode\. The message gives the reason\.
+ **`Telemetry is off: the AWS SDK config has no credentials or region`** – The provider found no AWS credentials or Region, so it sends nothing\. Set the Region, for example with `AWS_REGION`\.
+ **`Discovery: failed to submit batch ...`** – AWS didn't accept the request after three attempts\. Check the permission and network access to `https://workload-telemetry.<region>.api.aws`\.

For all options, see [Certificate discovery configuration](#certificate-discovery-configuration) and [Telemetry configuration](#telemetry-configuration)\.

## Configure the Workload Credentials Provider<a name="workload-credentials-provider-config"></a>

To start the Workload Credentials Provider with a custom configuration, create a [TOML](https://toml.io/en/) config file, and then run `./aws-workload-credentials-provider sm start --config /path/to/config.toml` for Secrets Manager or `./aws-workload-credentials-provider acm start --config /path/to/config.toml` for Certificate Management\.

The following sections describe the configuration options available for the Workload Credentials Provider\.

**Note:** Previous flat configuration keys for Secrets Manager (e.g., `http_port = 2773` at the root level) are still supported for backward compatibility\. We recommend using the nested configuration format documented below\. A file can't mix the two formats: if it has nested sections, a root\-level key or section, such as `[prefetch]` or `[failover]`, fails validation\.

### Common configuration

These options apply to all capabilities\.

```toml
[logging]
log_level = "INFO"
log_to_file = true
```

+ **log\_level** – The level of detail reported in logs: DEBUG, INFO, WARN, ERROR, or NONE\. The default is INFO\.
+ **log\_to\_file** – Whether to log to a file or stdout/stderr: `true` or `false`\. The default is `true`\.

### Secrets Manager configuration

These options go under `[capabilities.secrets_manager]`\.

```toml
[capabilities.secrets_manager]
enabled = true
http_port = 2773
region = "us-east-1"
path_prefix = "/v1/"
max_conn = 800
max_roles = 20
ignore_transient_errors = true

[capabilities.secrets_manager.cache]
ttl_seconds = 300
cache_size = 1000

[capabilities.secrets_manager.security]
ssrf_headers = ["X-Aws-Parameters-Secrets-Token", "X-Vault-Token"]
ssrf_env_variables = ["AWS_TOKEN", "AWS_SESSION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN"]

[capabilities.secrets_manager.prefetch]
cache_buffer_ratio = 0.8
max_jitter_seconds = 5
secrets = [
  { secret_id = "arn:aws:secretsmanager:us-west-2:123456789012:secret:MySecret-AbCdEf" },
]

[capabilities.secrets_manager.failover]
default_failover_region = "us-west-2"
operation_timeout_ms = 3000
secret_to_region_map = { "arn:aws:secretsmanager:us-east-1:123456789012:secret:MySecret-AbCdEf" = "eu-west-1" }
```

+ **enabled** – Whether the Secrets Manager capability is active: `true` or `false`\. The default is `true`\.
+ **http\_port** – The port for the local HTTP server, in the range 1024 to 65535\. The default is 2773\.
+ **region** – The AWS Region to use for requests\. If no Region is specified, the Workload Credentials Provider determines the Region from the SDK\. For more information, see [Specify your credentials and default Region](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html) in the *AWS SDK for Rust Developer Guide*\.
+ **path\_prefix** – The URI prefix used to determine if the request is a path based request\. The default is "/v1/"\.
+ **max\_conn** – The maximum number of connections from HTTP clients that the Workload Credentials Provider allows, in the range 1 to 1000\. The default is 800\.
+ **max\_roles** – The maximum number of IAM roles the Workload Credentials Provider can assume simultaneously for cross\-account access, in the range 1 to 20\. The default is 20\. For more information, see [Role chaining \(cross\-account access\)](#role-chaining-cross-account-access)\.
+ **ignore\_transient\_errors** – Whether to return the cached value when a refresh fails with a transient error \(a 5XX error, timeout, connection failure, or throttling\): `true` or `false`\. The default is `true`\. While the errors last, the cached value's TTL is renewed, so a rotated secret isn't picked up until Secrets Manager recovers\.
+ **ttl\_seconds** – The TTL in seconds for the cached items, in the range 0 to 3600\. The default is 300\. 0 indicates that there is no caching\.
+ **cache\_size** – The maximum number of secrets that can be stored in the cache, in the range 1 to 1000\. The default is 1000\.
+ **ssrf\_headers** – A list of header names the Workload Credentials Provider checks for the SSRF token\. The default is "X\-Aws\-Parameters\-Secrets\-Token, X\-Vault\-Token"\.
+ **ssrf\_env\_variables** – A list of environment variable names the Workload Credentials Provider checks in sequential order for the SSRF token\. The environment variable can contain the token or a reference to the token file as in: `AWS_TOKEN=file:///var/run/awssmatoken`\. The first variable that is set is used; if it is empty, or refers to an empty file, the provider doesn't start\. In the file, white space around the token is dropped, along with any byte order mark in it\. The default is "AWS\_TOKEN, AWS\_SESSION\_TOKEN, AWS\_CONTAINER\_AUTHORIZATION\_TOKEN"\.
+ **credentials\_file\_path** – The path to a file containing AWS credentials in the standard AWS credentials file format\. When set, the provider reads credentials from this file instead of using the default SDK credential provider chain\. The provider automatically reloads credentials when the file changes, making it compatible with credential rotation systems such as [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) that deliver refreshed credentials to the filesystem\. This parameter is optional\.
+ **default\_failover\_region** – The AWS region to fail over to for secrets without a `secret_to_region_map` entry\. It can't be empty or equal to `region`\. This is the only option that turns on [credential failover](#region-failover-credentials)\. There is no default\. For more information, see [Region failover](#region-failover)\.
+ **operation\_timeout\_ms** – The longest a primary call can take, in milliseconds, before the provider fails over, in the range 2000 to 25000\. The default is 3000\. Applies only to requests that have a failover region\.
+ **secret\_to\_region\_map** – Per\-secret failover regions, keyed by secret ARN\. An entry replaces `default_failover_region` for that secret\. Each region can't be empty or equal to `region`\.

### Certificate Management configuration

These options go under `[capabilities.acm]`\.

#### Example \- Linux

```toml
[capabilities.acm]
enabled = true

[[capabilities.acm.certificates]]
certificate_arn = "arn:aws:acm:us-west-2:123456789012:certificate/abc12345-1234-1234-1234-123456789012"
certificate_path = "/etc/ssl/certs/my-cert.pem"
private_key_path = "/etc/ssl/private/my-key.pem"
chain_path = "/etc/ssl/certs/my-chain.pem"
role_arn = "arn:aws:iam::123456789012:role/CertExportRole"
refresh_command = "/usr/sbin/nginx -s reload"
certificate_and_chain_permission = { mode = "0644" }
key_permission = { mode = "0600" }
```

#### Example \- Fullchain mode

When `chain_path` is omitted, the certificate chain is appended to the certificate file\.

```toml
[[capabilities.acm.certificates]]
certificate_arn = "arn:aws:acm:us-west-2:123456789012:certificate/abc12345-1234-1234-1234-123456789012"
certificate_path = "/etc/ssl/certs/my-fullchain.pem" # bundled cert and chain
private_key_path = "/etc/ssl/private/my-key.pem"
role_arn = "arn:aws:iam::123456789012:role/CertExportRole"
```

#### Example \- Windows

```toml
[capabilities.acm]
enabled = true

[[capabilities.acm.certificates]]
certificate_arn = "arn:aws:acm:us-west-2:123456789012:certificate/abc12345-1234-1234-1234-123456789012"
certificate_path = "C:\\ssl\\certs\\my-cert.pem"
private_key_path = "C:\\ssl\\private\\my-key.pem"
chain_path = "C:\\ssl\\certs\\my-chain.pem"
role_arn = "arn:aws:iam::123456789012:role/CertExportRole"
refresh_command = "C:\\nginx-1.31.1\\nginx.exe -s reload"
certificate_and_chain_permission = { trustee_type = "User", trustee_name = "NT SERVICE\\MyWebServer", rights = "Read" }
key_permission = { trustee_type = "User", trustee_name = "NT SERVICE\\MyWebServer", rights = "Read" }
```

**Note:** On Windows, certificate and key file permissions are inherited from parent directories\. Even when `certificate_and_chain_permission` or `key_permission` is specified, the configured permission is added on top of inherited permissions\. Ensure parent directories are appropriately locked down\.

+ **enabled** – Whether the Certificate Management capability is active: `true` or `false`\. The default is `false`\.
+ **certificate\_arn** – The ARN of the ACM certificate to export\. The provider exports it in the AWS Region resolved by the AWS SDK default chain (`AWS_REGION`, `AWS_DEFAULT_REGION`, shared config file, or IMDS), not the Region in the ARN, so that Region must match the ARN's Region\. There is no region setting for this capability\. See [AWS Region (required)](#acm-sidecar-region)\.
+ **certificate\_path** – Absolute path where the certificate PEM file will be written\.
+ **private\_key\_path** – Absolute path where the private key PEM file will be written\.
+ **chain\_path** – (Optional) Absolute path where the certificate chain will be written\. If omitted, the chain is appended to the certificate file (fullchain mode)\.
+ **role\_arn** – IAM role to assume when exporting the certificate\.
+ **refresh\_command** – (Optional) Command to run after a successful certificate refresh\. On a Linux host the provider runs it directly via `sudo`\. On a Windows host, the install scripts register it as a per\-certificate scheduled task (named from the certificate ARN, run as SYSTEM via PowerShell) and on refresh the provider triggers that task by its ARN\-derived name rather than running the string itself — put the reload command itself here, not a `scheduled-task:` prefix\. In a container it runs via `wcp-watcher` (see [Running as a Certificate Manager Sidecar](#-running-as-a-certificate-manager-sidecar-))\.
+ **certificate\_and\_chain\_permission** – (Optional) File permissions for the certificate and chain files\. On Linux, specify as `{ mode = "<octal>" }` (e.g., `{ mode = "0644" }`)\. On Windows, specify as `{ trustee_type, trustee_name, rights }`\. Default: `0600` on Linux\. On Windows, creating user, Administrators, and SYSTEM, plus any permissions inherited from the parent directory\.
+ **key\_permission** – (Optional) File permissions for the private key file\. Same format and defaults as `certificate_and_chain_permission`\.
+ **watcher\_id** – (Optional) ID of the `wcp-watcher` that runs this certificate's `refresh_command` in a container deployment\. When set, `refresh_command` is required and is carried into that watcher's config rather than run by the provider\. Must match `^[a-z0-9][a-z0-9._-]{0,63}$`\. On Windows it can't be a reserved device name (such as `con`, `nul`, or `com1`) or end with a period\. See [Running as a Certificate Manager Sidecar](#-running-as-a-certificate-manager-sidecar-)\.
+ **watcher\_config\_dir** – (Optional, ACM\-level under `[capabilities.acm]`) Directory the provider writes generated per\-watcher `watcher.config.toml` files to, shared read\-only with the watcher's container\. Default `/shared/wcp-watchers/config` (Linux), `C:\shared\wcp-watchers\config` (Windows)\.
+ **watcher\_requests\_dir** – (Optional, ACM\-level) Directory holding the per\-watcher refresh\-request queue, shared read\-write with the watcher's container\. Default `/shared/wcp-watchers/requests` (Linux), `C:\shared\wcp-watchers\requests` (Windows)\.

### Certificate discovery configuration

Certificate discovery is part of the Certificate Management capability\. When enabled, the provider identifies the compute it runs on, which takes at most a few seconds, then connects to local TLS ports within 5 minutes and then about once every 24 hours, and records the certificate each port presents\. These options go under `[capabilities.acm.discovery]`\.

```toml
[capabilities.acm.discovery]
enabled = true
timeout_secs_override = 300

[capabilities.acm.discovery.discovery_targets]
443 = ["api.example.com", "www.example.com"]
8443 = []
```

+ **enabled** – Whether certificate discovery is active: `true` or `false`\. The default is `false`\.
+ **timeout\_secs\_override** – (Optional) The maximum time in seconds for one discovery cycle, at least 60\. The default is 300\.
+ **discovery\_targets** – (Optional) A map from port to SNI hostnames\. Each port is probed once without SNI, then once per hostname\. Up to 32 ports and 32 hostnames per port\. If omitted or empty, ports 443, 8443, and 4443 are probed without SNI\.

The provider detects the compute it runs on and selects the discovery mode from it:

| Compute | Discovery mode | Addresses probed |
| ------- | --------- | ---------------- |
| Amazon EC2 | Host agent | `127.0.0.1`, then `::1` if the connection is refused |
| Amazon ECS, Amazon EKS | Sidecar | `127.0.0.1`, then `::1` if the connection is refused |
| AWS Lambda, or compute that cannot be identified | None | Discovery does not start |

**Important**  
In sidecar mode, the provider container must share a network namespace with the application container, because it reaches the application only through loopback\. On Amazon ECS, use the `awsvpc` network mode and run both containers in the same task\. The provider reads the task's network mode from the task metadata and, in any mode other than `awsvpc`, logs a warning and does not start discovery\. On Amazon EKS, run both containers in the same pod without `hostNetwork: true`\. The provider does not check `hostNetwork`: with `hostNetwork: true`, discovery reaches every service listening on the host's loopback and reports them under the provider's own identity\.

### Telemetry configuration

These options control what the Certificate Management capability sends to the AWS workload telemetry service\. For an overview, see [Certificate discovery and telemetry](#workload-credentials-provider-discovery)\.

```toml
[telemetry]
dry_run = false

[telemetry.acm]
enabled = true
```

+ **dry\_run** – (Optional) When `true`, the provider sends nothing\. Instead it writes each request, with the same fields it would send, as JSON to `logs/acm_provider_telemetry_dryrun.log`, or to stdout when `log_to_file` is `false`\. Use it to review the data before you turn on sending\. Live requests carry the same fields in CBOR\. The default is `false`\.
+ **\[telemetry\.acm\] enabled** – (Optional) Whether to send the results of certificate export and refresh: `true` or `false`\. The default is `false`\. This option doesn't affect discovery results, which are sent whenever discovery is on\.

Each request identifies the compute and describes the provider's environment:

+ **Compute** – The compute type \(Amazon EC2, Amazon ECS, or Amazon EKS\) and its ID: the EC2 instance ID, the ECS task ARN, or the EKS pod's namespace, name, and UID\.
+ **Environment** – The operating system, the CPU architecture, and a random ID generated each time the provider starts, so the service can tell restarts apart\.

Discovery results contain, for each port and SNI hostname probed: the certificate and chain the server presented \(public certificates only, never private keys\), the negotiated TLS version and cipher suite, the handshake signature scheme, and whether the server asked for a client certificate\. Each scan also reports how many targets it probed, how many succeeded and failed, and how many certificates are configured for export\. Ports that refuse the connection, don't speak TLS, or fail the handshake are counted but not reported individually\.

Export and refresh results contain, for each certificate: its ARN, the time, whether the export, write, and refresh command succeeded or at which step it failed, the deployed certificate and chain, how long the refresh took, and how many times in a row it has failed\.

The provider signs requests with the AWS credentials from its environment \(the instance profile, task role, or service account role\), the same credentials it uses to assume each certificate's role, not the certificate's `role_arn`, and sends them to `https://workload-telemetry.<region>.api.aws` in the Region from its AWS configuration \(for example, `AWS_REGION`\)\. When the AWS configuration asks for FIPS endpoints \(for example, `AWS_USE_FIPS_ENDPOINT=true`\), it sends them to `https://workload-telemetry-fips.<region>.api.aws` instead\. The credentials need permission for `workload-telemetry:PutCertificateTelemetry`\. If the provider has no credentials or Region, it logs a warning and sends nothing\. Discovery results are sent at the end of each scan\. Export and refresh results are queued and sent about once an hour and when the provider stops\. Each request is tried up to three times\. Telemetry failures never stop certificate export or refresh\. Delivery is best effort: queued export and refresh results are dropped, oldest first, when the in\-memory queue is full, and can be lost if the provider is stopped abruptly\. Requests honor the `HTTPS_PROXY` and `NO_PROXY` environment variables\.

The following example IAM policy allows the provider's credentials to send telemetry\.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "workload-telemetry:PutCertificateTelemetry",
      "Resource": "*"
    }
  ]
}
```

### Configuration reload (Certificate Management)

You can apply a new configuration to the Certificate Management capability without manually stopping and restarting the service\. The reload command validates the new configuration, re\-applies permissions, and restarts the ACM service\. It does not affect the Secrets Manager process or configuration\.

```sh
# Linux
sudo ./aws-workload-credentials-provider acm reload --config /path/to/config.toml

# Windows
.\aws-workload-credentials-provider.exe acm reload --Config C:\path\to\config.toml
```


## File-based credentials

By default, the Workload Credentials Provider uses the [AWS SDK default credential provider chain](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credproviders.html) to authenticate with Secrets Manager\. In this default mode, the SDK obtains credentials from the environment on its own \(IMDS on EC2, container credentials on ECS/EKS, environment variables, etc\.\)\.

For environments where credentials are delivered to the filesystem — such as on\-premises or multicloud hosts using [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) — the provider supports an alternative model: **it reads credentials from a file and supplies them to the AWS SDK**, rather than relying on the SDK's built\-in credential resolution\. The IAM Roles Anywhere credential helper's `update` command writes rotating temporary credentials to the standard AWS credentials file, and the provider automatically picks up refreshed credentials without requiring a restart\.

The credential flow is:

```
Credentials file (on disk) → Workload Credentials Provider → AWS SDK → Secrets Manager
```

This differs from the default SDK behavior where the SDK resolves credentials on its own\. Here, the SDK delegates credential resolution to the Workload Credentials Provider's file\-based credential provider, which monitors the file for changes and handles renewal\.

### Credentials file format

The credentials file must use the standard AWS credentials file format with a `[default]` profile and must include a session token \(temporary credentials\):

```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2Vj...
```

**Important:** The provider enforces a session token gate — credentials without an `aws_session_token` are rejected\. This ensures only temporary credentials \(such as those issued by IAM Roles Anywhere or STS\) can be used via the file path, preventing accidental use of long\-term IAM User access keys\. IAM Roles Anywhere credentials always include a session token\.

### Configuration

Set the `credentials_file_path` parameter in your configuration file:

```toml
[capabilities.secrets_manager]
region = "us-east-1"
credentials_file_path = "/path/to/credentials"
```

Or in the legacy flat format:

```toml
region = "us-east-1"
credentials_file_path = "/path/to/credentials"
```

### Credential refresh behavior

The provider automatically detects and re\-reads updated credentials from the file:

+ The provider checks the credentials file for changes every 5 minutes\.
+ When the file's modification time changes, the provider reloads the credentials\.
+ After every load or reload, the provider validates that `aws_session_token` is present\. If absent, the credentials are rejected and previously cached valid credentials are retained\.
+ If the file is missing or malformed during a reload, the provider continues using the previously cached credentials and retries on the next cycle\.
+ Each time the AWS SDK needs credentials to sign a request to Secrets Manager, it calls back into the file\-based credential provider, which returns the latest valid credentials loaded from disk\. The provider attaches a 10\-minute expiry to these credentials, ensuring the SDK does not cache them indefinitely and periodically re\-requests them — picking up any rotated credentials that were reloaded from the file\.

### Startup behavior

The provider is designed to start successfully regardless of the credentials file state:

+ If the file exists and contains valid temporary credentials, the provider loads them immediately\.
+ If the file is missing, empty, or malformed, the provider starts without credentials and the background reload task will pick up valid credentials when they appear\.
+ When file\-based credentials are configured, the provider skips the STS credential validation check at startup, since the credentials file may not yet exist\.
+ Calls to Secrets Manager will fail until valid credentials are available\. The provider process itself remains running and will begin serving requests once credentials appear in the file\.

### Security

The session token gate ensures that only temporary credentials can be used via the file path\.

On Unix systems, the provider logs a warning if the credentials file has permissions more permissive than owner\-only \(`0600`\)\. Consider restricting file permissions:

```sh
chmod 600 /path/to/credentials
```

## Optional features<a name="workload-credentials-provider-features"></a>

The Workload Credentials Provider can be built with optional features by passing the `--features` flag to `cargo build`. The available features are:

* `fips`: restricts the cipher suites used by the provider to only FIPS-approved ciphers

## Logging<a name="workload-credentials-provider-log"></a>

The Workload Credentials Provider logs locally to the following files, or to stdout/stderr depending on the `log_to_file` config variable:
+ **Secrets Manager:** `logs/secrets_manager_provider.log`
+ **Certificate Management:** `logs/acm_provider.log`
+ **Telemetry dry run \(Certificate Management\):** `logs/acm_provider_telemetry_dryrun.log`, one JSON request per line, when `[telemetry] dry_run = true`

When your application calls the Workload Credentials Provider to get a secret, those calls appear in the local log\. When the provider exports a certificate, writes it to disk, and runs a refresh command, those actions also appear in the local log\. They do not appear in the CloudTrail logs\.

The Workload Credentials Provider creates a new log file when the file reaches 10 MB, and it stores up to five log files per capability\. 

The provider itself doesn't send logs to Secrets Manager, ACM, CloudTrail, or CloudWatch\. Telemetry, when you turn it on, is separate from the logs; see [Certificate discovery and telemetry](#workload-credentials-provider-discovery)\. In a container with `log_to_file = false`, logs go to stdout and follow your container's log driver; for example, they reach CloudWatch Logs when an ECS task uses the `awslogs` driver\. When the Workload Credentials Provider makes a call to Secrets Manager or ACM, that call is recorded in CloudTrail with a user agent string containing `aws-workload-credentials-provider`\. 

You can configure logging in the [Configuration file](#workload-credentials-provider-config)\. 

Region failover writes a `WARN` line that starts with `failover=true` each time it fails over\. For an example, see [Region failover logging](#region-failover-logging)\.

## Security considerations<a name="workload-credentials-provider-security"></a>

For a local provider architecture, the domain of trust is where the provider endpoint, SSRF token, and credential outputs (such as certificate files) are accessible, which is usually the entire host\. The domain of trust for the Workload Credentials Provider should match the domain where the AWS credentials are available in order to maintain the same security posture\. For example, on Amazon EC2 the domain of trust for the Workload Credentials Provider would be the same as the domain of the credentials when using roles for Amazon EC2\.

Security conscious applications that are not already using a similar solution with the Secrets Manager credentials locked down to the application should consider using the language\-specific AWS SDKs or caching solutions\. For more information, see [Get secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html)\.

With [region failover](#region-failover), any local caller that holds the SSRF token can send the provider's signed Secrets Manager calls to any region by setting `failoverRegion`\. This is the same trust boundary that already lets that caller read any secret the provider can access\. To keep calls in approved regions, use IAM conditions such as `aws:RequestedRegion`\.

For the Certificate Management capability, the provider runs as a dedicated system user with no login shell\. On Linux, it uses `CAP_DAC_OVERRIDE` to write certificate files without requiring root, and executes refresh commands via `sudo -n` with a generated sudoers entry that permits only the exact configured commands\. Private key files are written with `0600` permissions by default\. All configured paths must be absolute, and paths containing symlinks or traversal components are rejected\. The provider's base credentials only need `sts:AssumeRole`, while `acm:ExportCertificate` is scoped to a separate role\. For environments where elevated privileges are not acceptable, the install script supports `--no-privileges` and `--no-sudoers` modes\.

In a container deployment, the Certificate Management capability uses no install script or sudoers entry. The trust boundary is the shared volumes: any container that mounts the certificate volume can read the certificate, and the private key is protected by running the provider and TLS containers with the same UID, or with a dedicated group if you use the permission fallback (see [Running as a Certificate Manager Sidecar](#-running-as-a-certificate-manager-sidecar-))\.

Certificate discovery connects only to loopback addresses and reads only what any TLS client sees during a handshake\. It doesn't send a client certificate, read files, or send data to the servers it probes\. Discovery results include the public certificates of every local TLS server on the configured ports, not only certificates from ACM\. Review the data with `[telemetry] dry_run = true` before you turn on discovery on hosts whose certificates you don't want to report\. Telemetry requests never contain private keys\.

## Running Integration Tests Locally<a name="integration-tests-local"></a>

The AWS Workload Credentials Provider includes a comprehensive integration test suite that validates functionality against real AWS Secrets Manager. These tests cover caching behavior, security features, configuration options, version management, and error handling scenarios.

### Prerequisites

- AWS credentials with permissions to create, read, update, and delete secrets in AWS Secrets Manager
- Rust toolchain installed
- Access to an AWS account for testing
- (For ACM tests) An exportable ACM certificate and IAM role with export permissions\. Use usable least-privilege AWS credentials and set:
  - `ACM_TEST_CERTIFICATE_ARN` — ARN of the certificate to export
  - `ACM_TEST_ROLE_ARN` — IAM role the provider assumes when exporting, requires `acm:ExportCertificate` permission
  - `AWS_REGION` — Region containing `ACM_TEST_CERTIFICATE_ARN`
- (For the real provider-plus-watcher test) Build both debug binaries with `cargo build` before running the test\. On Linux, the host must permit an unprivileged user and mount namespace so the fixture can bind-mount the watcher configuration read-only\. A host that lacks this support reports the test as skipped; set `WCP_WATCHER_E2E_REQUIRE_MOUNTS=1` to require it instead\.

The provider-plus-watcher test is conditional because it exports the configured real certificate\. With all prerequisites available, run it serially from the workspace root:

```sh
cargo test -p integration-tests --test provider_watcher -- --test-threads=1
```

To compile this test without AWS access or host namespace setup, use:

```sh
cargo test -p integration-tests --test provider_watcher --no-run
```

### Required AWS Permissions

Your AWS credentials must have the following permissions:
- `secretsmanager:CreateSecret`
- `secretsmanager:GetSecretValue`
- `secretsmanager:DescribeSecret`
- `secretsmanager:UpdateSecret`
- `secretsmanager:UpdateSecretVersionStage`
- `secretsmanager:PutSecretValue`
- `secretsmanager:DeleteSecret`
- `secretsmanager:BatchGetSecretValue`
- `secretsmanager:ListSecrets`
- `sts:AssumeRole`

### Required IAM Roles (for role chaining tests)

The role chaining and region failover integration tests require two IAM roles in the same account:

1. **`asm-role-chaining-role`** — Must be assumable by the test runner's identity and have `secretsmanager:GetSecretValue`, `secretsmanager:DescribeSecret`, and `secretsmanager:BatchGetSecretValue` permissions.

2. **`provider-no-access-role`** — Must be assumable by the test runner's identity but have *no* Secrets Manager permissions. Used to verify access-denied behavior.

Both roles must have a trust policy that allows the identity running the tests to call `sts:AssumeRole`. The account ID is discovered automatically via `sts:GetCallerIdentity`.

The region failover tests need no second region set up. They start the provider with its primary region set to `us-fake-1`, a region that doesn't exist, so every primary call fails, and the test runner's own region serves as the failover region.

### Running Tests

#### Option 1: Using the test script

1. Configure your AWS credentials with appropriate permissions

2. Run the test script:
   ```sh
   ./test-local.sh
   ```

#### Option 2: Manual execution

1. Configure your AWS credentials with appropriate permissions

2. Build the provider binary:
   ```sh
   cargo build
   ```

3. Run the integration tests:
   ```sh
   cd integration-tests
   cargo test -- --test-threads=1
   ```

### Test Organization

The integration tests are organized into the following modules:

- **`secret_retrieval.rs`** - Tests core secret retrieval functionality including name/ARN lookup, binary secrets, large secrets, and error handling
- **`cache_behavior.rs`** - Tests caching mechanisms including TTL expiration, refreshNow parameter, and cache bypass (TTL=0)
- **`security.rs`** - Tests security features including SSRF token validation and X-Forwarded-For header rejection
- **`version_management.rs`** - Tests secret version transitions and rotation scenarios
- **`configuration.rs`** - Tests configuration parameters including health checks and path-based requests
- **`role_chaining.rs`** - Tests cross\-account secret retrieval via IAM role assumption, including invalid role ARN handling, access denied scenarios, refreshNow with role chaining, and separate per\-role cache isolation
- **`prefetch.rs`** - Tests pre\-fetching secrets into the cache at startup, including explicit secrets, tag\-based discovery, inline TOML syntax, cross\-account pre\-fetching via role chaining, and resilience to nonexistent secrets
- **`certificate_provider.rs`** - Tests the Certificate Management capability including certificate export, file writing, fullchain mode, refresh command execution, and file permission configuration
- **`discovery.rs`** - Tests certificate discovery against local TLS and plain TCP listeners, with a mock instance metadata service and the telemetry dry run: the reported certificate, SNI, mTLS, TLS version and cipher suite, failed probes, identity detection, and unsupported compute. No AWS credentials are needed\. Set `DISCOVERY_INTEG_REAL_IMDS=1` to use the real instance metadata service on Amazon EC2\.
- **`file_credentials.rs`** - Tests file\-based credential loading including valid/invalid/missing credentials, session token gate enforcement \(rejecting credentials that lack `aws_session_token` to prevent use of long\-term IAM User keys\), self\-healing \(credentials appearing after startup\), and credential rotation
- **`sm_failover.rs`** - Tests Secrets Manager region failover, including failover on a cache miss, a cache refresh, and `refreshNow`, the `failoverRegion` query parameter and its format check, `secret_to_region_map`, no failover when failover isn't configured or the secret isn't found, both regions down with and without `refreshNow`, pre\-fetch while the primary region is down, failover of the provider's own credentials from STS, and no failover for a slow `credential_process` while the primary region is healthy
- **`role_failover.rs`** - Tests role credential failover for `roleArn` requests, including STS and Secrets Manager failing over together, no failover when failover isn't configured, both STS regions down, no failover on access denied or a healthy primary, a failover region that denies the secret read, file\-based credentials, a configured `region` that differs from the SDK region, ARN rewriting, serving the cached value when every region is down, and no STS failover with only the query parameter or `secret_to_region_map`
