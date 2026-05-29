use std::num::NonZeroUsize;
use std::time::Duration;

use aws_sdk_secretsmanager::operation::describe_secret;
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueOutput;
use aws_secretsmanager_caching::SecretsManagerCachingClient;
use aws_smithy_mocks::{mock, mock_client, RuleMode};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::distr::{Alphabetic, SampleString};

fn random_string(len: usize) -> String {
    Alphabetic.sample_string(&mut rand::rng(), len)
}

/// Benchmark cache hits by retrieving the same secret over and over.
fn cache_hit(c: &mut Criterion) {
    const CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

    let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value).then_output(move || {
        GetSecretValueOutput::builder()
            .name("secretid")
            .arn("somearn")
            .secret_string("hunter2")
            .version_id("thisisaversionid")
            .build()
    });

    let describe_secret =
        mock!(aws_sdk_secretsmanager::Client::describe_secret).then_output(move || {
            describe_secret::DescribeSecretOutput::builder()
                .name("secretid")
                .arn("somearn")
                .version_ids_to_stages("thisisaversionid", vec!["AWSCURRENT".to_string()])
                .build()
        });

    let asm = mock_client!(
        aws_sdk_secretsmanager,
        RuleMode::MatchAny,
        [&gsv, &describe_secret]
    );

    let cache = SecretsManagerCachingClient::new(asm, CACHE_SIZE, Duration::MAX, true).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Warm up the cache.
    rt.block_on(cache.get_secret_value("secretid", None, None, false))
        .unwrap();

    c.bench_function("CacheHit", |b| {
        b.to_async(&rt).iter(async || {
            cache
                .get_secret_value("secretid", None, None, false)
                .await
                .unwrap();
        });
    });
}

/// Benchmark cache eviction using a very small cache
fn cache_eviction(c: &mut Criterion) {
    const CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1).unwrap();

    let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value).then_output(move || {
        GetSecretValueOutput::builder()
            .name("secretid")
            .arn("somearn")
            .secret_string("hunter2")
            .version_id("thisisaversionid")
            .build()
    });

    let describe_secret =
        mock!(aws_sdk_secretsmanager::Client::describe_secret).then_output(move || {
            describe_secret::DescribeSecretOutput::builder()
                .name("secretid")
                .arn("somearn")
                .version_ids_to_stages("thisisaversionid", vec!["AWSCURRENT".to_string()])
                .build()
        });

    let asm = mock_client!(
        aws_sdk_secretsmanager,
        RuleMode::MatchAny,
        [&gsv, &describe_secret]
    );

    let cache = SecretsManagerCachingClient::new(asm, CACHE_SIZE, Duration::MAX, true).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    c.bench_function("CacheEviction", |b| {
        b.to_async(&rt).iter(async || {
            cache
                .get_secret_value(&random_string(10), None, None, false)
                .await
                .unwrap();
        });
    });
}

criterion_group!(benches, cache_hit, cache_eviction);
criterion_main!(benches);
