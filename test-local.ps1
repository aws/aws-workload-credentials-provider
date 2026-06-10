<#
.SYNOPSIS
    Local integration test runner (Windows).

.DESCRIPTION
    Runs the full integration test suite (ASM + ACM). The ACM tests run the
    agent against a pre-existing certificate owned by the test operator and
    require:

      ACM_TEST_CERTIFICATE_ARN
      ACM_TEST_ROLE_ARN

    On Windows, the ACM refresh executor calls `schtasks /Run` against a
    scheduled task whose name is derived from the cert ARN. The tests
    register a per-cert scheduled task as the current user with Interactive
    logon — no admin privileges required.
#>

$ErrorActionPreference = "Stop"

Write-Host "Setting up local integration test environment..."

if (-not $env:AWS_REGION) {
    $env:AWS_REGION = "us-east-1"
}
Write-Host "Using region: $env:AWS_REGION"

$acmEnabled = $env:ACM_TEST_CERTIFICATE_ARN -and $env:ACM_TEST_ROLE_ARN
if ($acmEnabled) {
    Write-Host "ACM tests enabled (ACM_TEST_CERTIFICATE_ARN and ACM_TEST_ROLE_ARN are set)"
} else {
    Write-Host "ACM tests skipped (set ACM_TEST_CERTIFICATE_ARN and ACM_TEST_ROLE_ARN to enable)"
}

Write-Host "Building agent..."
cargo build
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

Write-Host "Running integration tests..."
Push-Location integration-tests
try {
    # Run integration tests sequentially (matches CI behavior).
    # Tests handle their own setup and cleanup.
    if ($acmEnabled) {
        cargo test -- --test-threads=1
    } else {
        cargo test -- --test-threads=1 --skip certificate_provider
    }
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }
} finally {
    Pop-Location
}

Write-Host "Local integration tests completed!" -ForegroundColor Green
