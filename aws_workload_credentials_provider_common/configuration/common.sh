# Common variables for install/uninstall scripts

PROVIDER_DIR=/opt/aws/workload-credentials-provider
CONFIG_DIR=/etc/aws-workload-credentials-provider
SYSTEMD_FILES=/etc/systemd/system

PROVIDER_GROUP=awscreds
TOKEN_GROUP=aws-workload-credentials-provider-token
PROVIDER_USER=aws-workload-credentials-provider

TOKEN_SCRIPT=aws-workload-credentials-provider-token
SM_SERVICE=aws-workload-credentials-provider-sm
ACM_SERVICE=aws-workload-credentials-provider-acm
PROVIDER_BIN=aws-workload-credentials-provider
PROVIDER_SOURCE_DIR=../../target/release
