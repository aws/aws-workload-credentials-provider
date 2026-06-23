#!/bin/bash -e
#
# AWS Workload Credentials Provider - Permissions Setup
# Sets up user, group, and directory permissions.
#

PATH=/bin:/usr/bin:/sbin:/usr/sbin
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "${SCRIPT_DIR}/common.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

#
# User and group setup
#

groupadd -f "${PROVIDER_GROUP}"
groupadd -f "${TOKEN_GROUP}"
# useradd exits with code 9 if the user already exists — ignore that, but fail on any other error
useradd -r -M -d "${PROVIDER_DIR}" -s /sbin/nologin -g "${PROVIDER_GROUP}" -G "${TOKEN_GROUP}" "${PROVIDER_USER}" || [ $? -eq 9 ]

#
# Directory permissions
#

mkdir -p "${PROVIDER_DIR}"
chmod 755 "${PROVIDER_DIR}"
chown "${PROVIDER_USER}" "${PROVIDER_DIR}"

echo "Permissions setup complete."
