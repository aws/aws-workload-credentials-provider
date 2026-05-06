# AWS Secrets Manager Agent

The AWS Secrets Manager Agent is a client\-side HTTP service that you can use to standardize consumption of secrets from Secrets Manager across environments such as AWS Lambda, Amazon Elastic Container Service, Amazon Elastic Kubernetes Service, and Amazon Elastic Compute Cloud\. The Secrets Manager Agent can retrieve and cache secrets in memory so that your applications can consume secrets directly from the cache\. That means you can fetch the secrets your application needs from the localhost instead of making calls to Secrets Manager\. The Secrets Manager Agent can only make read requests to Secrets Manager \- it can't modify secrets\. 

The Secrets Manager Agent uses the AWS credentials you provide in your environment to make calls to Secrets Manager\. The Secrets Manager Agent offers protection against Server Side Request Forgery \(SSRF\) to help improve secret security\. The Agent also uses the post-quantum ML-KEM key exchange as the highest-priority key exchange by default\. You can configure the Secrets Manager Agent by setting the maximum number of connections, the time to live \(TTL\), the localhost HTTP port, and the cache size\.

Because the Secrets Manager Agent uses an in\-memory cache, it resets when the Secrets Manager Agent restarts\. The Secrets Manager Agent periodically refreshes the cached secret value\. The refresh happens when you try to read a secret from the Secrets Manager Agent after the TTL has expired\. The default refresh frequency \(TTL\) is 300 seconds, and you can change it by using a [Configuration file](#secrets-manager-agent-config) which you pass to the Secrets Manager Agent using the `--config` command line argument\. The Secrets Manager Agent does not include cache invalidation\. For example, if a secret rotates before the cache entry expires, the Secrets Manager Agent might return a stale secret value\. 

The Secrets Manager Agent returns secret values in the same format as the response of `GetSecretValue`\. Secret values are not encrypted in the cache\.

To download the source code, see [https://github\.com/aws/aws\-secretsmanager\-agent](https://github.com/aws/aws-secretsmanager-agent) on GitHub\.

**Topics**
- [AWS Secrets Manager Agent](#aws-secrets-manager-agent)
  - [Step 1: Build the Secrets Manager Agent binary](#step-1-build-the-secrets-manager-agent-binary)
      - [\[ RPM-based systems \]](#-rpm-based-systems-)
      - [\[ Debian-based systems \]](#-debian-based-systems-)
      - [\[ Windows \]](#-windows-)
      - [\[ Cross-compile natively \]](#-cross-compile-natively-)
      - [\[ Cross compile with Rust cross \]](#-cross-compile-with-rust-cross-)
  - [Step 2: Install the Secrets Manager Agent](#step-2-install-the-secrets-manager-agent)
      - [\[ Amazon EC2 \]](#-amazon-ec2-)
      - [\[ Running as a Container Sidecar \]](#-running-as-a-container-sidecar-)
      - [\[ AWS Lambda \]](#-aws-lambda-)
  - [Step 3: Retrieve secrets with the Secrets Manager Agent](#step-3-retrieve-secrets-with-the-secrets-manager-agent)
      - [\[ curl \]](#-curl-)
      - [\[ Python \]](#-python-)
  - [`refreshNow` parameter behavior](#refreshnow-parameter-behavior)
  - [Using the refreshNow parameter](#using-the-refreshnow-parameter)
    - [Example - Secrets Manager Agent GET request with refreshNow parameter](#example---secrets-manager-agent-get-request-with-refreshnow-parameter)
      - [\[ curl \]](#-curl--1)
      - [\[ Python \]](#-python--1)
  - [Configure the Secrets Manager Agent](#configure-the-secrets-manager-agent)
  - [Optional features](#optional-features)
  - [File-based credentials](#file-based-credentials)
  - [Logging](#logging)
  - [Security considerations](#security-considerations)
  - [Running Integration Tests Locally](#running-integration-tests-locally)
    - [Prerequisites](#prerequisites)
    - [Required AWS Permissions](#required-aws-permissions)
    - [Running Tests](#running-tests)
      - [Option 1: Using the test script](#option-1-using-the-test-script)
      - [Option 2: Manual execution](#option-2-manual-execution)
    - [Test Organization](#test-organization)

## Step 1: Build the Secrets Manager Agent binary<a name="secrets-manager-agent-build"></a>

To build the Secrets Manager Agent binary natively, you need the standard development tools and the Rust tools\. Alternatively, you can cross\-compile for systems that support it, or you can use Rust cross to cross\-compile\.

------

**NOTE:** To ensure a stable experience, use a specific git tag when building from source code. You can find a list of version tags [here](https://github.com/aws/aws-secretsmanager-agent/tags). Tags are in the pattern `/v\d+\.\d+\.\d+/` and follow [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html).

Example: `git clone --branch <git tag> https://github.com/aws/aws-secretsmanager-agent.git`

**NOTE:** Building the agent with the `fips` feature enabled on macOS currently requires the following workaround:

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

1. Build the agent using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws_secretsmanager_agent`\.

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

1. Build the agent using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws_secretsmanager_agent`\.

------
#### [ Windows ]

To build on Windows, follow the instructions at [Set up your dev environment on Windows for Rust](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup) in the *Microsoft Windows documentation*\.

1. Build the agent using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws_secretsmanager_agent.exe`\.

------
#### [ Cross\-compile natively ]

On distributions where the mingw\-w64 package is available such as Ubuntu, you can cross compile natively\.

```sh
# Install the cross compile tool chain
sudo add-apt-repository universe
sudo apt install -y mingw-w64
    
# Install the rust build targets
rustup target add x86_64-pc-windows-gnu
    
# Cross compile the agent for Windows
cargo build --release --target x86_64-pc-windows-gnu
```

You will find the executable at `target/x86_64-pc-windows-gnu/release/aws_secretsmanager_agent.exe`\.

------
#### [ Cross compile with Rust cross ]

If the cross compile tools are not available natively on the system, you can use the Rust cross project\. For more information, see [https://github\.com/cross\-rs/cross](https://github.com/cross-rs/cross)\.

**Important**  
We recommend 32GB disk space for the build environment\.

```sh
# Install and start docker
sudo yum -y install docker
sudo systemctl start docker
sudo systemctl enable docker # Make docker start after reboot
    
# Give ourselves permission to run the docker images without sudo
sudo usermod -aG docker $USER
newgrp docker
    
# Install cross and cross compile the executable
cargo install cross
cross build --release --target x86_64-pc-windows-gnu
```

------

## Step 2: Install the Secrets Manager Agent<a name="secrets-manager-agent-install"></a>

Based on the type of compute, you have several options for installing the Secrets Manager Agent\.

------
#### [ Amazon EC2 ]

**To install the Secrets Manager Agent**

1. `cd aws_secretsmanager_agent/configuration`
1. Run the `install` script provided in the repository\. 

   The script generates a random SSRF token on startup and stores it in the file `/var/run/awssmatoken`\. The token is readable by the `awssmatokenreader` group that the install script creates\. 

1. To allow your application to read the token file, you need to add the user account that your application runs under to the `awssmatokenreader` group\. For example, you can grant permissions for your application to read the token file with the following usermod command, where *<APP\_USER>* is the user ID under which your application runs\.

   ```sh
   sudo usermod -aG awssmatokenreader <APP_USER>
   ```

------
#### [ Running as a Container Sidecar ]

You can run the Secrets Manager Agent as a sidecar container alongside your application by using Docker\. Then your application can retrieve secrets from the local HTTP server the Secrets Manager Agent provides\. For information about Docker, see the [Docker documentation](https://docs.docker.com)\. 

**To create a sidecar container for the Secrets Manager Agent with Docker**

1. Create a Dockerfile for the Secrets Manager Agent sidecar container\. The following example creates a Docker container with the Secrets Manager Agent binary\.

   ```dockerfile
   # Use the latest Debian image as the base
   FROM debian:latest
   
   # Set the working directory inside the container
   WORKDIR /app 
   
   # Copy the Secrets Manager Agent binary to the container
   COPY secrets-manager-agent . 
   
   # Install any necessary dependencies
   RUN apt-get update && apt-get install -y ca-certificates 
   
   # Set the entry point to run the Secrets Manager Agent binary
   ENTRYPOINT ["./secrets-manager-agent"]
   ```

1. Create a Dockerfile for your client application\.

1. Create a Docker Compose file to run both containers, being sure that they use the same network interface\. This is necessary because the Secrets Manager Agent does not accept requests from outside the localhost interface\. The following example shows a Docker Compose file where the `network_mode` key attaches the `secrets-manager-agent` container to the network namespace of the `client-application` container, which allows them to share the same network interface\.

    **Important**

    You must load AWS credentials and the SSRF token for the application to be able to use the Secrets Manager Agent\. For EKS and ECS, see the following:  
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
       
   
       secrets-manager-agent:
       container_name: secrets-manager-agent
       build:
           context: .
           dockerfile: Dockerfile.agent
       network_mode: "container:client-application"  # Attach to the client-application container's network
       depends_on:
           - client-application
   ```

1. Copy the `secrets-manager-agent` binary to the same directory that contains your Dockerfiles and Docker Compose file\.

1. Build and run the containers based on the provided Dockerfiles by using the following [https://docs.docker.com/reference/cli/docker/compose/](https://docs.docker.com/reference/cli/docker/compose/) command\.

   ```sh
   docker-compose up --build
   ```

1. In your client container, you can now use the Secrets Manager Agent to retrieve secrets\. For more information, see [Step 3: Retrieve secrets with the Secrets Manager Agent](#secrets-manager-agent-call)\.

------
#### [ AWS Lambda ]

You can [package the Secrets Manager Agent as an AWS Lambda extension](https://docs.aws.amazon.com/lambda/latest/dg/packaging-layers.html)\. Then you can [add it to your Lambda function as a layer](https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html) and call the Secrets Manager Agent from your Lambda function to get secrets\. 

The following instructions show how to get a secret named *MyTest* by using the example script `secrets-manager-agent-extension.sh` in [https://github\.com/aws/aws\-secretsmanager\-agent](https://github.com/aws/aws-secretsmanager-agent) to install the Secrets Manager Agent as a Lambda extension\.

**To create a Lambda extension that packages the Secrets Manager Agent**

1. Package the agent as a layer. From the root of the Secrets Manager Agent code package, run the following example commands\:

   ```sh
   AWS_ACCOUNT_ID=<AWS_ACCOUNT_ID>
   LAMBDA_ARN=<LAMBDA_ARN>
   
   # Build the release binary 
   cargo build --release --target=x86_64-unknown-linux-gnu
   
   # Copy the release binary into the `bin` folder
   mkdir -p ./bin
   cp ./target/x86_64-unknown-linux-gnu/release/aws_secretsmanager_agent ./bin/secrets-manager-agent
   
   # Copy the `secrets-manager-agent-extension.sh` example script into the `extensions` folder.
   mkdir -p ./extensions
   cp aws_secretsmanager_agent/examples/example-lambda-extension/secrets-manager-agent-extension.sh ./extensions
   
   # Zip the extension shell script and the binary 
   zip secrets-manager-agent-extension.zip bin/* extensions/*
   
   # Publish the layer version
   LAYER_VERSION_ARN=$(aws lambda publish-layer-version \
       --layer-name secrets-manager-agent-extension \
       --zip-file "fileb://secrets-manager-agent-extension.zip" | jq -r '.LayerVersionArn')
   ```

2. The default configuration of the agent will automatically set the SSRF token to the value set in the pre-set `AWS_SESSION_TOKEN` or `AWS_CONTAINER_AUTHORIZATION_TOKEN` environment variables (the latter variable for Lambda functions with SnapStart enabled). Alternatively, you can define the `AWS_TOKEN` environment variable with an arbitrary value for your Lambda function instead as this variable takes precedence over the other two. If you choose to use the `AWS_TOKEN` environment variable, you must set that environment variable with a `lambda:UpdateFunctionConfiguration` call\.


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

## Step 3: Retrieve secrets with the Secrets Manager Agent<a name="secrets-manager-agent-call"></a>

To use the agent, you call the local Secrets Manager Agent endpoint and include the name or ARN of the secret as a query parameter\. By default, the Secrets Manager Agent retrieves the `AWSCURRENT` version of the secret\. To retrieve a different version, you can set `versionStage` or `versionId`\.

To help protect the Secrets Manager Agent, you must include a SSRF token header as part of each request: `X-Aws-Parameters-Secrets-Token`\. The Secrets Manager Agent denies requests that don't have this header or that have an invalid SSRF token\. You can customize the SSRF header name in the [Configuration file](#secrets-manager-agent-config)\.

The Secrets Manager Agent uses the AWS SDK for Rust, which uses the [https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html)\. The identity of these IAM credentials determines the permissions the Secrets Manager Agent has to retrieve secrets\. 

**Required permissions: **
+ `secretsmanager:DescribeSecret`
+ `secretsmanager:GetSecretValue`

For more information, see [Permissions reference](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_iam-policies.html)\.

**Important**  
After the secret value is pulled into the Secrets Manager Agent, any user with access to the compute environment and SSRF token can access the secret from the Secrets Manager Agent cache\. For more information, see [Security considerations](#secrets-manager-agent-security)\.

------
#### [ curl ]

The following curl example shows how to get a secret from the Secrets Manager Agent\. The example relies on the SSRF being present in a file, which is where it is stored by the install script\.

```sh
curl -v -H \
    "X-Aws-Parameters-Secrets-Token: $(</var/run/awssmatoken)" \
    'http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>'; \
    echo
```

------
#### [ Python ]

The following Python example shows how to get a secret from the Secrets Manager Agent\. The example relies on the SSRF being present in a file, which is where it is stored by the install script\.

```python
import requests
import json

# Function that fetches the secret from Secrets Manager Agent for the provided secret id. 
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

Learn how to use the refreshNow parameter to force the Secrets Manager Agent (SMA) to refresh secret values.

Secrets Manager Agent uses an in-memory cache to store secret values, which it refreshes periodically. By default, this refresh occurs when you request a secret after the Time to Live (TTL) has expired, typically every 300 seconds. However, this approach can sometimes result in stale secret values, especially if a secret rotates before the cache entry expires.

To address this limitation, Secrets Manager Agent supports a parameter called `refreshNow` in the URL. You can use this parameter to force an immediate refresh of a secret's value, bypassing the cache and ensuring you have the most up-to-date information.

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
- If Secrets Manager Agent can't retrieve the secret from Secrets Manager, it returns an error and does not update the cache.

`refreshNow` set to `false` or not specified:
- Secrets Manager Agent follows its default behavior:
  - If the cached value is fresher than the TTL, Secrets Manager Agent returns the cached value.
  - If the cached value is older than the TTL, Secrets Manager Agent makes a call to Secrets Manager.

## Using the refreshNow parameter

To use the `refreshNow` parameter, include it in the URL for the Secrets Manager Agent GET request.

### Example - Secrets Manager Agent GET request with refreshNow parameter

> **Important**: The default value of `refreshNow` is `false`. When set to `true`, it overrides the TTL specified in the Secrets Manager Agent configuration file and makes an API call to Secrets Manager.

#### [ curl ]

The following curl example shows how force Secrets Manager Agent to refresh the secret. The example relies on the SSRF being present in a file, which is where it is stored by the install script.

```bash
curl -v -H \
"X-Aws-Parameters-Secrets-Token: $(</var/run/awssmatoken)" \
'http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>&refreshNow=true' \
echo
```

#### [ Python ]

The following Python example shows how to get a secret from the Secrets Manager Agent. The example relies on the SSRF being present in a file, which is where it is stored by the install script.

```python
import requests
import json

# Function that fetches the secret from Secrets Manager Agent for the provided secret id. 
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

## Configure the Secrets Manager Agent<a name="secrets-manager-agent-config"></a>

To change the configuration of the Secrets Manager Agent, create a [TOML](https://toml.io/en/) config file, and then call `./aws_secretsmanager_agent --config config.toml`\.

The following list shows the options you can configure for the Secrets Manager Agent\.
+ **log\_level** – The level of detail reported in logs for the Secrets Manager Agent: DEBUG, INFO, WARN, ERROR, or NONE\. The default is INFO\.
+ **log\_to\_file** - Whether to log to a file or stdout/stderr: `true` or `false`. The default is `true`.
+ **http\_port** – The port for the local HTTP server, in the range 1024 to 65535\. The default is 2773\.
+ **region** – The AWS Region to use for requests\. If no Region is specified, the Secrets Manager Agent determines the Region from the SDK\. For more information, see [Specify your credentials and default Region](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html) in the *AWS SDK for Rust Developer Guide*\.
+ **ttl\_seconds** – The TTL in seconds for the cached items, in the range 0 to 3600\. The default is 300\. 0 indicates that there is no caching\.
+ **cache\_size** – The maximum number of secrets that can be stored in the cache, in the range 1 to 1000\. The default is 1000\. 
+ **ssrf\_headers** – A list of header names the Secrets Manager Agent checks for the SSRF token\. The default is "X\-Aws\-Parameters\-Secrets\-Token, X\-Vault\-Token"\. 
+ **ssrf\_env\_variables** – A list of environment variable names the Secrets Manager Agent checks in sequential order for the SSRF token\. The environment variable can contain the token or a reference to the token file as in: `AWS_TOKEN=file:///var/run/awssmatoken`\. The default is "AWS\_TOKEN, AWS\_SESSION\_TOKEN, AWS\_CONTAINER\_AUTHORIZATION\_TOKEN\".
+ **path\_prefix** – The URI prefix used to determine if the request is a path based request\. The default is "/v1/"\.
+ **max\_conn** – The maximum number of connections from HTTP clients that the Secrets Manager Agent allows, in the range 1 to 1000\. The default is 800\.
+ **credentials\_file\_path** – The path to a file containing AWS credentials in the standard AWS credentials file format. When set, the agent reads credentials from this file instead of using the default SDK credential provider chain. The agent automatically reloads credentials when the file changes, making it compatible with credential rotation systems that deliver refreshed credentials to the filesystem. This parameter is optional.

## Optional features<a name="secrets-manager-agent-features"></a>

The Secrets Manager Agent can be built with optional features by passing the `--features` flag to `cargo build`. The available features are:

* `fips`: restricts the cipher suites used by the agent to only FIPS-approved ciphers

## File-based credentials

By default, the Secrets Manager Agent uses the [AWS SDK default credential provider chain](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credproviders.html) to authenticate with Secrets Manager. This works well on Amazon EC2 (via IMDS), Lambda, and ECS/EKS (via container credentials).

For environments where credentials are delivered to the filesystem — such as on-premises hosts using [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) or other credential management systems — you can configure the agent to read credentials from a file.

### Credentials file format

The credentials file must use the standard AWS credentials file format:

```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = IQoJb3JpZ2luX2Vj...
```

### Configuration

Set the `credentials_file_path` parameter in your configuration file:

```toml
region = "us-east-1"
credentials_file_path = "/path/to/credentials"
```

### Credential refresh behavior

The agent automatically detects and re-reads updated credentials from the file:

+ The agent checks the credentials file for changes every 5 minutes.
+ When the file's modification time changes, the agent reloads the credentials.
+ If the file is missing or malformed during a reload, the agent continues using the previously cached credentials and retries on the next cycle.
+ Credentials are served to the AWS SDK with a 10-minute expiry window, ensuring the SDK periodically requests fresh credentials from the provider.

### Startup behavior

The agent is designed to start successfully regardless of the credentials file state:

+ If the file exists and contains valid credentials, the agent loads them immediately.
+ If the file is missing, empty, or malformed, the agent starts without credentials and the background reload task will pick up valid credentials when they appear.
+ When file-based credentials are configured, the agent skips the STS credential validation check at startup, since the credentials file may not yet exist. The `validate_credentials` setting continues to apply for non-file-based credential sources.
+ Calls to Secrets Manager will fail until valid credentials are available. The agent process itself remains running and will begin serving requests once credentials appear in the file.

### Security

On Unix systems, the agent logs a warning if the credentials file has permissions more permissive than owner-only (`0600`). Consider restricting file permissions:

```sh
chmod 600 /path/to/credentials
```


## Logging<a name="secrets-manager-agent-log"></a>

The Secrets Manager Agent logs errors locally to the file `logs/secrets_manager_agent.log` or to stdout/stderr depending on the `log_to_file` config variable\. When your application calls the Secrets Manager Agent to get a secret, those calls appear in the local log\. They do not appear in the CloudTrail logs\. 

The Secrets Manager Agent creates a new log file when the file reaches 10 MB, and it stores up to five log files total\. 

The log does not go to Secrets Manager, CloudTrail, or CloudWatch\. Requests to get secrets from the Secrets Manager Agent do not appear in those logs\. When the Secrets Manager Agent makes a call to Secrets Manager to get a secret, that call is recorded in CloudTrail with a user agent string containing `aws-secrets-manager-agent`\. 

You can configure logging in the [Configuration file](#secrets-manager-agent-config)\. 

## Security considerations<a name="secrets-manager-agent-security"></a>

For an agent architecture, the domain of trust is where the agent endpoint and SSRF token are accessible, which is usually the entire host\. The domain of trust for the Secrets Manager Agent should match the domain where the Secrets Manager credentials are available in order to maintain the same security posture\. For example, on Amazon EC2 the domain of trust for the Secrets Manager Agent would be the same as the domain of the credentials when using roles for Amazon EC2\.

Security conscious applications that are not already using an agent solution with the Secrets Manager credentials locked down to the application should consider using the language\-specific AWS SDKs or caching solutions\. For more information, see [Get secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html)\.

## Running Integration Tests Locally<a name="integration-tests-local"></a>

The AWS Secrets Manager Agent includes a comprehensive integration test suite that validates functionality against real AWS Secrets Manager. These tests cover caching behavior, security features, configuration options, version management, and error handling scenarios.

### Prerequisites

- AWS credentials with permissions to create, read, update, and delete secrets in AWS Secrets Manager
- Rust toolchain installed
- Access to an AWS account for testing

### Required AWS Permissions

Your AWS credentials must have the following permissions:
- `secretsmanager:CreateSecret`
- `secretsmanager:GetSecretValue`
- `secretsmanager:DescribeSecret`
- `secretsmanager:UpdateSecret`
- `secretsmanager:UpdateSecretVersionStage`
- `secretsmanager:PutSecretValue`
- `secretsmanager:DeleteSecret`

### Running Tests

#### Option 1: Using the test script

1. Configure your AWS credentials with appropriate permissions

2. Run the test script:
   ```sh
   ./test-local.sh
   ```

#### Option 2: Manual execution

1. Configure your AWS credentials with appropriate permissions

2. Build the agent binary:
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
- **`file_credentials.rs`** - Tests file-based credential loading including valid/invalid/missing credentials, self-healing (credentials appearing after startup), and credential rotation
