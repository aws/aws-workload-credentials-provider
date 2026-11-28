# Common variables for install/uninstall scripts

PROVIDER_DIR=/opt/aws/workload-credentials-provider
CONFIG_DIR=/etc/aws-workload-credentials-provider
SYSTEMD_FILES=/etc/systemd/system

PROVIDER_GROUP=awscreds
TOKEN_GROUP=aws-wcp-token
PROVIDER_USER=aws-wcp

TOKEN_SCRIPT=aws-workload-credentials-provider-token
SM_SERVICE=aws-workload-credentials-provider-sm
ACM_SERVICE=aws-workload-credentials-provider-acm
PROVIDER_BIN=aws-workload-credentials-provider
# Directory holding the built provider binary. Defaults to the cargo release
# output of this checkout; set WCP_PROVIDER_SOURCE_DIR for any other layout.
if [ -n "${WCP_PROVIDER_SOURCE_DIR:-}" ]; then
    if [ ! -d "${WCP_PROVIDER_SOURCE_DIR}" ]; then
        echo "WCP_PROVIDER_SOURCE_DIR is not a directory: ${WCP_PROVIDER_SOURCE_DIR}" >&2
        exit 1
    fi
    PROVIDER_SOURCE_DIR="$(realpath -e "${WCP_PROVIDER_SOURCE_DIR}")"
else
    PROVIDER_SOURCE_DIR="../../target/release"
fi
ACM_DROPIN_DIR="${SYSTEMD_FILES}/${ACM_SERVICE}.service.d"
SUDOERS_FILE="/etc/sudoers.d/${PROVIDER_BIN}"
