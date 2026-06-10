# AWS Secrets Manager Rust Caching Client

The AWS Secrets Manager Rust Caching Client enables in-process caching of secrets for Rust applications.

## Getting Started

### Required Prerequisites

To use this client you must have:

* A Rust 2021 development environment. If you do not have one, go to [Rust Getting Started](https://www.rust-lang.org/learn/get-started) on the Rust Programming Language website, then download and install Rust.
* An Amazon Web Services (AWS) account to access secrets stored in AWS Secrets Manager.
  * **To create an AWS account**, go to [Sign In or Create an AWS Account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html) and then choose **I am a new user.** Follow the instructions to create an AWS account.
  * **To create a secret in AWS Secrets Manager**, go to [Creating Secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_create-basic-secret.html) and follow the instructions on that page.

### Get Started

The following code sample demonstrates how to get started:

1. Instantiate the caching client.
2. Request secret.

```sh
cargo add tokio -F rt-multi-thread,net,macros
cargo add aws_secretsmanager_caching
```

```rust
use aws_secretsmanager_caching::SecretsManagerCachingClient;
use std::num::NonZeroUsize;
use std::time::Duration;

let client = match SecretsManagerCachingClient::default(
    NonZeroUsize::new(1000).unwrap(),
    Duration::from_secs(300),
)
.await
{
    Ok(c) => c,
    Err(_) => panic!("Handle this error"),
};

let secret_string = match client.get_secret_value("MyTest", None, None).await {
    Ok(s) => s.secret_string.unwrap(),
    Err(_) => panic!("Handle this error"),
};

// Your code here
```

### Cache Configuration

* `max_size: NonZeroUsize`: The maximum number of cached secrets to maintain before evicting secrets that have not been accessed recently.
* `ttl: Duration`: The duration a cached item is considered valid before requiring a refresh of the secret state.

### Instantiating Cache with a custom Config and a custom Client

```sh
cargo add aws_sdk_secretsmanager aws_config
```

```rust
let config = aws_config::load_defaults(BehaviorVersion::latest())
    .await
    .into_builder()
    .region(Region::from_static("us-west-2"))
    .build();

let asm_builder = aws_sdk_secretsmanager::config::Builder::from(&config);

let client = match SecretsManagerCachingClient::from_builder(
    asm_builder,
    NonZeroUsize::new(1000).unwrap(),
    Duration::from_secs(300),
    false
)
.await
{
    Ok(c) => c,
    Err(_) => panic!("Handle this error"),
};

let secret_string = client
    .get_secret_value("MyTest", None, None)
    .await 
    {
        Ok(c) => c.secret_string.unwrap(),
        Err(_) => panic!("Handle this error"),
    };

// Your code here
```

### Getting Help

Please use these community resources for getting help:

* Ask a question on [Stack Overflow](https://stackoverflow.com/) and tag it with [aws-secrets-manager](https://stackoverflow.com/questions/tagged/aws-secrets-manager).
* Open a support ticket with [AWS Support](https://console.aws.amazon.com/support/home#/)
* If it turns out that you may have found a bug, or have a feature request, please [open an issue](https://github.com/aws/aws-workload-credentials-provider/issues/new/choose).
