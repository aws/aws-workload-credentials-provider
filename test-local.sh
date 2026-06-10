#!/bin/bash
set -e

# Local integration test runner.
#
# Runs the full integration test suite (ASM + ACM). The ACM tests run the
# provider against a pre-existing certificate owned by the test operator and
# require:
#
#   ACM_TEST_CERTIFICATE_ARN
#   ACM_TEST_ROLE_ARN
#
# `DefaultRefreshExecutor` invokes `sudo -n` for refresh commands, so the
# happy-path ACM test must run as root. When ACM env vars are present and the
# current user is not root, this script re-execs itself under sudo. AWS
# credentials are preserved via `sudo -E`.
#
# Cargo writes to target/ during both build and test, so post-re-exec runs
# leave root-owned artifacts. We restore ownership on exit via a trap so the
# next non-root cargo invocation isn't blocked by permission errors.

echo "Setting up local integration test environment..."

export AWS_REGION="${AWS_REGION:-us-east-1}"
echo "Using region: $AWS_REGION"

# Capture the original user and an absolute workspace root before any sudo
# re-exec or `cd` so the EXIT trap can chown the right paths regardless of
# CWD when the script exits (e.g., after a `cd integration-tests` that never
# got an undoing `cd ..` because `cargo test` failed under `set -e`).
ORIG_USER="${SUDO_USER:-$(whoami)}"
ROOT_DIR="$(pwd)"
trap '[[ "$EUID" -eq 0 ]] && chown -R "$ORIG_USER" "$ROOT_DIR/target/" "$ROOT_DIR/integration-tests/target/" 2>/dev/null || true' EXIT

ACM_ENABLED=false
if [[ -n "${ACM_TEST_CERTIFICATE_ARN:-}" && -n "${ACM_TEST_ROLE_ARN:-}" ]]; then
    ACM_ENABLED=true
fi

# Re-exec under sudo when ACM tests are requested and we're not root.
# PATH is forwarded explicitly because sudo always overrides it with
# `secure_path` from /etc/sudoers, which typically lacks ~/.cargo/bin.
#
# The re-exec happens BEFORE `cargo build` so we don't build twice (once as
# the user, then again as root after exec).
if [[ "$ACM_ENABLED" == "true" && "$EUID" -ne 0 ]]; then
    echo "ACM tests requested; re-execing under sudo to allow DefaultRefreshExecutor's sudo -n calls..."
    exec sudo -E "PATH=$PATH" "$0" "$@"
fi

echo "Building provider..."
cargo build

# Run integration tests from the integration-tests crate
echo "Running integration tests..."

cd integration-tests

# Run integration tests sequentially (matches CI behavior)
# Tests handle their own setup and cleanup
if [[ "$ACM_ENABLED" == "true" ]]; then
    cargo test -- --test-threads=1
else
    echo "ACM tests skipped (set ACM_TEST_CERTIFICATE_ARN and ACM_TEST_ROLE_ARN to enable)"
    cargo test -- --test-threads=1 --skip certificate_provider
fi
cd ..

echo "Local integration tests completed!"