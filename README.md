# AWS Workload Credentials Provider

The AWS Workload Credentials Provider (formerly the AWS Secrets Manager Agent) is a client\-side solution that helps you standardize how you consume credentials from AWS services across your compute environments\. It includes the following capabilities:

- **Secrets Manager** — An HTTP interface for retrieving and caching secrets from AWS Secrets Manager\. Supported on AWS Lambda, Amazon ECS, Amazon EKS, and Amazon EC2\. Enabled by default\.
- **Certificate Management** — Automatic export and refresh of certificates from AWS Certificate Manager to the local filesystem\. Supported on Amazon EC2 and on\-premise hosts\. Opt\-in via [configuration](#certificate-management-configuration)\.

## Secrets Manager capability

The Workload Credentials Provider retrieves and caches secrets in memory so that your applications can consume secrets from localhost instead of making direct calls to Secrets Manager\. It can only read secrets \- it can't modify them\.

The Workload Credentials Provider uses the AWS credentials you provide in your environment to make calls to Secrets Manager\. The Workload Credentials Provider offers protection against Server Side Request Forgery \(SSRF\) to help improve secret security\. It also uses the post-quantum ML-KEM key exchange as the highest-priority key exchange by default\. You can configure the Workload Credentials Provider by setting the maximum number of connections, the time to live \(TTL\), the localhost HTTP port, and the cache size\.

Because the Workload Credentials Provider uses an in\-memory cache, it resets when the Workload Credentials Provider restarts\. The Workload Credentials Provider periodically refreshes the cached secret value\. The refresh happens when you try to read a secret from the Workload Credentials Provider after the TTL has expired\. The default refresh frequency \(TTL\) is 300 seconds, and you can change it by using a [Configuration file](#workload-credentials-provider-config) which you pass to the Workload Credentials Provider using the `sm start --config /path/to/config.toml` command line argument\. The Workload Credentials Provider does not include cache invalidation\. For example, if a secret rotates before the cache entry expires, the Workload Credentials Provider might return a stale secret value\. 

The Workload Credentials Provider returns secret values in the same format as the response of `GetSecretValue`\. Secret values are not encrypted in the cache\.

## Certificate Management capability

The Workload Credentials Provider exports certificates from AWS Certificate Manager (ACM) and writes them as PEM files to the local filesystem\. It automatically checks for updated certificates every 24 hours and optionally runs a user\-configured command after each successful refresh (for example, to reload a web server)\. You can configure up to 50 certificates\. Each certificate is managed by an independent background task, providing fault isolation so that one certificate's failure does not affect others\.

The Certificate Management capability supports Linux and Windows, and works with web servers such as NGINX and Apache\.

The Workload Credentials Provider uses the AWS credentials you provide in your environment to assume the role you have configured for each certificate, and then calls ACM to export the certificate\. The install script sets up the necessary permissions for the provider process to write certificate files to customer\-specified directories and execute refresh commands\.

You can provide a custom configuration by passing `--config /path/to/config.toml` on startup or on reload while the provider is running\. On Windows, use `-Config C:\path\to\config.toml` when invoking the PowerShell scripts and `--Config C:\path\to\config.toml` when executing the binary command\. The reload re\-applies permissions and restarts the ACM service\.

For full configuration details, see [Configure the Workload Credentials Provider](#workload-credentials-provider-config)\.

To download the source code, see [https://github\.com/aws/aws\-workload\-credentials\-provider](https://github.com/aws/aws-workload-credentials-provider) on GitHub\.

**Topics**
- [AWS Workload Credentials Provider](#aws-workload-credentials-provider)
  - [Secrets Manager capability](#secrets-manager-capability)
  - [Certificate Management capability](#certificate-management-capability)
  - [Step 1: Build the Workload Credentials Provider binary](#step-1-build-the-workload-credentials-provider-binary)
      - [\[ RPM-based systems \]](#-rpm-based-systems-)
      - [\[ Debian-based systems \]](#-debian-based-systems-)
      - [\[ Windows \]](#-windows-)
      - [\[ Cross-compile natively \]](#-cross-compile-natively-)
  - [Step 2: Install the Workload Credentials Provider](#step-2-install-the-workload-credentials-provider)
      - [\[ Amazon EC2 (Linux) \]](#-amazon-ec2-linux-)
      - [\[ Windows EC2 \]](#-windows-ec2-)
      - [\[ Running as a Container Sidecar \]](#-running-as-a-container-sidecar-)
      - [\[ AWS Lambda \]](#-aws-lambda-)
  - [Step 3: Retrieve secrets with the Workload Credentials Provider](#step-3-retrieve-secrets-with-the-workload-credentials-provider)
      - [\[ curl \]](#-curl-)
      - [\[ Python \]](#-python-)
  - [`refreshNow` parameter behavior](#refreshnow-parameter-behavior)
  - [Using the refreshNow parameter](#using-the-refreshnow-parameter)
    - [Example - GET request with refreshNow parameter](#example---get-request-with-refreshnow-parameter)
      - [\[ curl \]](#-curl--1)
      - [\[ Python \]](#-python--1)
  - [Role chaining (cross-account access)](#role-chaining-cross-account-access)
  - [Pre-fetching](#pre-fetching)
  - [Step 4: Retrieve certificates with the Workload Credentials Provider](#step-4-retrieve-certificates-with-the-workload-credentials-provider)
  - [Configure the Workload Credentials Provider](#configure-the-workload-credentials-provider)
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

   The script generates a random SSRF token on startup and stores it in the file `C:\ProgramData\AWS\WorkloadCredentialsProvider\awssmatoken`\. The token is readable by the Secrets Manager service account (`NT SERVICE\AWSWorkloadCredentialsProvider-SecretsManager`) that the install script configures\.

1. To allow your application to read the token file, you need to grant read access to the user account that your application runs under\. For example, you can grant permissions for your application to read the token file with the following icacls command, where *<APP\_USER>* is the user account under which your application runs\.

   ```powershell
   icacls "C:\ProgramData\AWS\WorkloadCredentialsProvider\awssmatoken" /grant "<APP_USER>:(R)"
   ```

   **Note:** When using the install script, the provider reads the SSRF token from file via `AWS_TOKEN=file://C:\ProgramData\AWS\WorkloadCredentialsProvider\awssmatoken` set on the service\. Your application must also read the token from this path and pass it in the `X-Aws-Parameters-Secrets-Token` header\. If you were previously setting `AWS_TOKEN` as an environment variable with a literal token value or a custom file path, update your application to read from the new token file path instead\.

------
#### [ Running as a Container Sidecar ]

You can run the Workload Credentials Provider as a sidecar container alongside your application by using Docker\. Then your application can retrieve secrets from the local HTTP server the Workload Credentials Provider provides\. For information about Docker, see the [Docker documentation](https://docs.docker.com)\. 

**Note:** The Certificate Management capability is not supported in container environments\.

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

1. Create a Dockerfile for your client application\.

1. Create a Docker Compose file to run both containers, being sure that they use the same network interface\. This is necessary because the Workload Credentials Provider does not accept requests from outside the localhost interface\. The following example shows a Docker Compose file where the `network_mode` key attaches the `workload-credentials-provider` container to the network namespace of the `client-application` container, which allows them to share the same network interface\.

    **Important**

    You must load AWS credentials and the SSRF token for the application to be able to use the Workload Credentials Provider\. For EKS and ECS, see the following:  
    * [Manage access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-auth.html) in the *Amazon Elastic Kubernetes Service User Guide*
    * [Amazon ECS task IAM role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html) in the *Amazon Elastic Container Service Developer Guide*


   ```yaml
   version: '3'
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
   docker-compose up --build
   ```

1. In your client container, you can now use the Workload Credentials Provider to retrieve secrets\. For more information, see [Step 3: Retrieve secrets with the Workload Credentials Provider](#workload-credentials-provider-call)\.

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

To retrieve a secret, you call the local Workload Credentials Provider endpoint and include the name or ARN of the secret as a query parameter\. By default, the Workload Credentials Provider retrieves the `AWSCURRENT` version of the secret\. To retrieve a different version, you can set `versionStage` or `versionId`\. To retrieve a secret using a different IAM role, you can set `roleArn`\. For more information, see [Role chaining \(cross\-account access\)](#role-chaining-cross-account-access)\.

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

## Step 4: Retrieve certificates with the Workload Credentials Provider<a name="workload-credentials-provider-acm"></a>

**The following sections describe how to use the Certificate Management capability\.**

To enable the Certificate Management capability, add a `[capabilities.acm]` section to your configuration file with `enabled = true` and one or more certificate entries\. The provider will automatically export and refresh configured certificates every 24 hours\.

**Required permissions:**
+ `sts:AssumeRole` — Required on the provider's environment credentials to assume the configured role for each certificate
+ `acm:ExportCertificate` — Required on the target role (`role_arn`) to export the certificate and private key from ACM

**Important**  
After certificates are written to the filesystem, any user with read access to the certificate and private key files can access them\. Use the `certificate_and_chain_permission` and `key_permission` configuration options to restrict file access\. Certificate paths, refresh commands, and file permissions are customer\-configured\. Validate your configuration before applying it to ensure paths are correct and refresh commands are trusted\. For more information, see [Security considerations](#workload-credentials-provider-security)\.

For full configuration details, see [Configure the Workload Credentials Provider](#workload-credentials-provider-config)\.

## Configure the Workload Credentials Provider<a name="workload-credentials-provider-config"></a>

To start the Workload Credentials Provider with a custom configuration, create a [TOML](https://toml.io/en/) config file, and then run `./aws-workload-credentials-provider sm start --config /path/to/config.toml`\.

The following sections describe the configuration options available for the Workload Credentials Provider\.

**Note:** Previous flat configuration keys for Secrets Manager (e.g., `http_port = 2773` at the root level) are still supported for backward compatibility\. We recommend using the nested configuration format documented below\.

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
```

+ **enabled** – Whether the Secrets Manager capability is active: `true` or `false`\. The default is `true`\.
+ **http\_port** – The port for the local HTTP server, in the range 1024 to 65535\. The default is 2773\.
+ **region** – The AWS Region to use for requests\. If no Region is specified, the Workload Credentials Provider determines the Region from the SDK\. For more information, see [Specify your credentials and default Region](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html) in the *AWS SDK for Rust Developer Guide*\.
+ **path\_prefix** – The URI prefix used to determine if the request is a path based request\. The default is "/v1/"\.
+ **max\_conn** – The maximum number of connections from HTTP clients that the Workload Credentials Provider allows, in the range 1 to 1000\. The default is 800\.
+ **max\_roles** – The maximum number of IAM roles the Workload Credentials Provider can assume simultaneously for cross\-account access, in the range 1 to 20\. The default is 20\. For more information, see [Role chaining \(cross\-account access\)](#role-chaining-cross-account-access)\.
+ **ttl\_seconds** – The TTL in seconds for the cached items, in the range 0 to 3600\. The default is 300\. 0 indicates that there is no caching\.
+ **cache\_size** – The maximum number of secrets that can be stored in the cache, in the range 1 to 1000\. The default is 1000\.
+ **ssrf\_headers** – A list of header names the Workload Credentials Provider checks for the SSRF token\. The default is "X\-Aws\-Parameters\-Secrets\-Token, X\-Vault\-Token"\.
+ **ssrf\_env\_variables** – A list of environment variable names the Workload Credentials Provider checks in sequential order for the SSRF token\. The environment variable can contain the token or a reference to the token file as in: `AWS_TOKEN=file:///var/run/awssmatoken`\. The default is "AWS\_TOKEN, AWS\_SESSION\_TOKEN, AWS\_CONTAINER\_AUTHORIZATION\_TOKEN"\.
+ **credentials\_file\_path** – The path to a file containing AWS credentials in the standard AWS credentials file format\. When set, the provider reads credentials from this file instead of using the default SDK credential provider chain\. The provider automatically reloads credentials when the file changes, making it compatible with credential rotation systems such as [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) that deliver refreshed credentials to the filesystem\. This parameter is optional\.

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
+ **certificate\_arn** – The ARN of the ACM certificate to export\.
+ **certificate\_path** – Absolute path where the certificate PEM file will be written\.
+ **private\_key\_path** – Absolute path where the private key PEM file will be written\.
+ **chain\_path** – (Optional) Absolute path where the certificate chain will be written\. If omitted, the chain is appended to the certificate file (fullchain mode)\.
+ **role\_arn** – IAM role to assume when exporting the certificate\.
+ **refresh\_command** – (Optional) Command to run after a successful certificate refresh\. On Windows, use the `scheduled-task:` prefix to trigger a pre\-registered scheduled task\.
+ **certificate\_and\_chain\_permission** – (Optional) File permissions for the certificate and chain files\. On Linux, specify as `{ mode = "<octal>" }` (e.g., `{ mode = "0644" }`)\. On Windows, specify as `{ trustee_type, trustee_name, rights }`\. Default: `0600` on Linux\. On Windows, creating user, Administrators, and SYSTEM, plus any permissions inherited from the parent directory\.
+ **key\_permission** – (Optional) File permissions for the private key file\. Same format and defaults as `certificate_and_chain_permission`\.

### Configuration reload (Certificate Management)

You can apply a new configuration to the Certificate Management capability without manually stopping and restarting the service\. The reload command validates the new configuration, re\-applies permissions, and restarts the ACM service\. It does not affect the Secrets Manager process or configuration\.

```sh
# Linux
sudo ./aws-workload-credentials-provider acm reload --config /path/to/config.toml

# Windows
.\aws-workload-credentials-provider.exe acm reload --Config C:\path\to\config.toml
```


## File-based credentials

By default, the Workload Credentials Provider uses the [AWS SDK default credential provider chain](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credproviders.html) to authenticate with Secrets Manager\. This works well on Amazon EC2 \(via IMDS\), Lambda, and ECS/EKS \(via container credentials\)\.

For environments where credentials are delivered to the filesystem — such as on\-premises or multicloud hosts using [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) — you can configure the provider to read credentials from a file\. The IAM Roles Anywhere credential helper's `update` command writes rotating temporary credentials to the standard AWS credentials file, and the provider automatically picks up refreshed credentials without requiring a restart\.

### Credentials file format

The credentials file must use the standard AWS credentials file format and must include a session token \(temporary credentials\):

```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2Vj...
```

**Important:** The provider enforces a session token gate — credentials without an `aws_session_token` are rejected\. This prevents use of long\-term IAM User credentials\. IAM Roles Anywhere credentials always include a session token, so legitimate use cases are unaffected\.

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
+ Credentials are served to the AWS SDK with a 10\-minute expiry window, ensuring the SDK periodically requests fresh credentials from the provider\.

### Startup behavior

The provider is designed to start successfully regardless of the credentials file state:

+ If the file exists and contains valid temporary credentials, the provider loads them immediately\.
+ If the file is missing, empty, or malformed, the provider starts without credentials and the background reload task will pick up valid credentials when they appear\.
+ When file\-based credentials are configured, the provider skips the STS credential validation check at startup, since the credentials file may not yet exist\.
+ Calls to Secrets Manager will fail until valid credentials are available\. The provider process itself remains running and will begin serving requests once credentials appear in the file\.

### Security

The session token gate ensures that only temporary credentials can be used via the file path\. This is strictly more restrictive than the existing default SDK credential chain, which already accepts static credentials via environment variables without validation\.

On Unix systems, the provider logs a warning if the credentials file has permissions more permissive than owner\-only \(`0600`\)\. Consider restricting file permissions:

```sh
chmod 600 /path/to/credentials
```

## File-based credentials

By default, the Workload Credentials Provider uses the [AWS SDK default credential provider chain](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credproviders.html) to authenticate with Secrets Manager\. This works well on Amazon EC2 \(via IMDS\), Lambda, and ECS/EKS \(via container credentials\)\.

For environments where credentials are delivered to the filesystem — such as on\-premises or multicloud hosts using [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) — you can configure the provider to read credentials from a file\. The IAM Roles Anywhere credential helper's `update` command writes rotating temporary credentials to the standard AWS credentials file, and the provider automatically picks up refreshed credentials without requiring a restart\.

### Credentials file format

The credentials file must use the standard AWS credentials file format and must include a session token \(temporary credentials\):

```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2Vj...
```

**Important:** The provider enforces a session token gate — credentials without an `aws_session_token` are rejected\. This prevents use of long\-term IAM User credentials\. IAM Roles Anywhere credentials always include a session token, so legitimate use cases are unaffected\.

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
+ Credentials are served to the AWS SDK with a 10\-minute expiry window, ensuring the SDK periodically requests fresh credentials from the provider\.

### Startup behavior

The provider is designed to start successfully regardless of the credentials file state:

+ If the file exists and contains valid temporary credentials, the provider loads them immediately\.
+ If the file is missing, empty, or malformed, the provider starts without credentials and the background reload task will pick up valid credentials when they appear\.
+ When file\-based credentials are configured, the provider skips the STS credential validation check at startup, since the credentials file may not yet exist\.
+ Calls to Secrets Manager will fail until valid credentials are available\. The provider process itself remains running and will begin serving requests once credentials appear in the file\.

### Security

The session token gate ensures that only temporary credentials can be used via the file path\. This is strictly more restrictive than the existing default SDK credential chain, which already accepts static credentials via environment variables without validation\.

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

When your application calls the Workload Credentials Provider to get a secret, those calls appear in the local log\. When the provider exports a certificate, writes it to disk, and runs a refresh command, those actions also appear in the local log\. They do not appear in the CloudTrail logs\.

The Workload Credentials Provider creates a new log file when the file reaches 10 MB, and it stores up to five log files per capability\. 

The log does not go to Secrets Manager, ACM, CloudTrail, or CloudWatch\. When the Workload Credentials Provider makes a call to Secrets Manager or ACM, that call is recorded in CloudTrail with a user agent string containing `aws-workload-credentials-provider`\. 

You can configure logging in the [Configuration file](#workload-credentials-provider-config)\. 

## Security considerations<a name="workload-credentials-provider-security"></a>

For a local provider architecture, the domain of trust is where the provider endpoint, SSRF token, and credential outputs (such as certificate files) are accessible, which is usually the entire host\. The domain of trust for the Workload Credentials Provider should match the domain where the AWS credentials are available in order to maintain the same security posture\. For example, on Amazon EC2 the domain of trust for the Workload Credentials Provider would be the same as the domain of the credentials when using roles for Amazon EC2\.

Security conscious applications that are not already using a similar solution with the Secrets Manager credentials locked down to the application should consider using the language\-specific AWS SDKs or caching solutions\. For more information, see [Get secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html)\.

For the Certificate Management capability, the provider runs as a dedicated system user with no login shell\. On Linux, it uses `CAP_DAC_OVERRIDE` to write certificate files without requiring root, and executes refresh commands via `sudo -n` with a generated sudoers entry that permits only the exact configured commands\. Private key files are written with `0600` permissions by default\. All configured paths must be absolute, and paths containing symlinks or traversal components are rejected\. The provider's base credentials only need `sts:AssumeRole`, while `acm:ExportCertificate` is scoped to a separate role\. For environments where elevated privileges are not acceptable, the install script supports `--no-privileges` and `--no-sudoers` modes\.

## Running Integration Tests Locally<a name="integration-tests-local"></a>

The AWS Workload Credentials Provider includes a comprehensive integration test suite that validates functionality against real AWS Secrets Manager. These tests cover caching behavior, security features, configuration options, version management, and error handling scenarios.

### Prerequisites

- AWS credentials with permissions to create, read, update, and delete secrets in AWS Secrets Manager
- Rust toolchain installed
- Access to an AWS account for testing
- (For ACM tests) An exportable ACM certificate and IAM role with export permissions\. Set the following environment variables:
  - `ACM_TEST_CERTIFICATE_ARN` — ARN of the certificate to export
  - `ACM_TEST_ROLE_ARN` — IAM role the provider assumes when exporting, requires `acm:ExportCertificate` permission

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

The role chaining integration tests require two IAM roles in the same account:

1. **`asm-role-chaining-role`** — Must be assumable by the test runner's identity and have `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` permissions.

2. **`provider-no-access-role`** — Must be assumable by the test runner's identity but have *no* Secrets Manager permissions. Used to verify access-denied behavior.

Both roles must have a trust policy that allows the identity running the tests to call `sts:AssumeRole`. The account ID is discovered automatically via `sts:GetCallerIdentity`.

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
- **`file_credentials.rs`** - Tests file\-based credential loading including valid/invalid/missing credentials, session token gate enforcement, self\-healing \(credentials appearing after startup\), and credential rotation
