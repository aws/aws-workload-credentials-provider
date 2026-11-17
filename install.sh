#!/bin/sh
# Bootstrap installer for the AWS Workload Credentials Provider on Linux.
#
#   installer=$(mktemp) && trap 'rm -f "$installer"' EXIT &&
#     curl --proto '=https' --tlsv1.2 -fsSL -o "$installer" \
#       https://raw.githubusercontent.com/aws/aws-workload-credentials-provider/HEAD/install.sh &&
#     sudo AWCP_VERSION=3.2.0 bash "$installer" --config /path/to/config.toml
#
# Downloaded to a file rather than piped into a shell, because `bash -c "$(curl
# ...)"` exits 0 when the download fails: the substitution is empty and nothing
# runs. That form still works, with the options after a --.
#
# Downloads the release binary and the matching configuration directory, then
# runs the install script from it. Options other than --dry-run are passed
# through to that script.
#
# The version is explicit: the binary comes from the artifact host and the
# service units and install scripts come from the repository at tag v$AWCP_VERSION,
# so both halves are pinned to the same release.
#
# Environment:
#   AWCP_VERSION   Version to install, in the pattern x.y.z. Required.
#   AWCP_BASE_URL  Artifact host.
#   AWCP_REPO_URL  Repository the configuration directory is fetched from.
#
# Everything runs from main, called on the last line, so a download truncated
# mid-transfer can't execute a partial install.

set -eu

BASE_URL="${AWCP_BASE_URL:-https://artifacts.awcp.global.on.aws}"
REPO_URL="${AWCP_REPO_URL:-https://github.com/aws/aws-workload-credentials-provider}"
BIN=aws-workload-credentials-provider

die() {
    echo "install.sh: $*" >&2
    exit 1
}

fetch() {
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" -- "$1" ||
        die "download failed: $1"
}

main() {
    # `bash -c <script> [name [args...]]` assigns the first word after the
    # script to $0, so an operator who omits the `--` loses their first option
    # silently. Refuse rather than install something they didn't ask for.
    case "$0" in
        --) ;;
        -*) die "unexpected \$0 '$0': put -- before the options, as in 'sh -s -- --dry-run'" ;;
    esac

    [ "$(id -u)" -eq 0 ] || die "must run as root"
    [ "$(uname -s)" = Linux ] || die "unsupported OS: $(uname -s). This installer is Linux only"

    case "$(uname -m)" in
        x86_64 | amd64) target=x86_64-unknown-linux-gnu ;;
        aarch64 | arm64) target=aarch64-unknown-linux-gnu ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac

    # Commands this script uses itself, resolved the way it will call them.
    for cmd in curl mktemp od tar; do
        command -v "$cmd" >/dev/null || die "required command not found: $cmd"
    done

    # Commands the install script and the token unit need, resolved against the
    # PATH those pin rather than this shell's, so a useradd in /usr/local/sbin
    # doesn't pass here and go missing at use time. Checked up front, since a
    # host missing sha256sum installs cleanly and then serves 403s, and one
    # missing bash dies after the whole binary has been downloaded.
    for cmd in bash cat chgrp chmod chown cut dd grep groupadd id install mkdir \
        rm sha256sum sleep systemctl touch useradd; do
        PATH=/bin:/usr/bin:/sbin:/usr/sbin command -v "$cmd" >/dev/null ||
            die "required command not found on the install script's PATH: $cmd"
    done

    version="${AWCP_VERSION:-}"
    [ -n "$version" ] ||
        die "set AWCP_VERSION to the version to install, as in 'sudo AWCP_VERSION=3.2.0 ...'"
    # Pattern-matched rather than piped through grep: ^ and $ anchor each line,
    # not the whole value, and sh builtins that expand \n would let a second
    # line ride along behind a valid first one.
    case "$version" in
        *[!0-9.]* | *..* | .* | *.) die "not a valid version: $version" ;;
        *.*.*.*) die "not a valid version: $version" ;;
        *.*.*) ;;
        *) die "not a valid version: $version" ;;
    esac

    # `bash -c <script> -- <options>` consumes the -- as $0, but running the
    # file directly leaves it as the first argument, so drop it here to make
    # both invocations behave the same.
    if [ "${1:-}" = "--" ]; then
        shift
    fi

    # Strip --dry-run and leave the rest in "$@" for the install script.
    # Rotating through "$@" keeps arguments containing spaces intact.
    dry_run=false
    config_next=false
    remaining=$#
    while [ "$remaining" -gt 0 ]; do
        arg=$1
        shift
        if [ "$config_next" = true ]; then
            config_next=false
            # Made absolute here: the install script cds to its own directory
            # before it copies the config, so a relative path would resolve
            # against the staging directory instead of the caller's, and the
            # copy would fail with users, units and the binary already on disk.
            case $arg in
                /*) ;;
                *) arg="$PWD/$arg" ;;
            esac
            [ -f "$arg" ] || die "cannot find config file: $arg"
            set -- "$@" "$arg"
        elif [ "$arg" = --dry-run ]; then
            dry_run=true
        else
            if [ "$arg" = --config ]; then
                config_next=true
            fi
            set -- "$@" "$arg"
        fi
        remaining=$((remaining - 1))
    done

    # The install script runs setup-permissions.sh directly rather than through
    # bash, so the staging filesystem has to allow exec. Hardened hosts mount
    # /tmp noexec and often /var/tmp with it, so the choice is probed rather
    # than assumed, and TMPDIR is ignored so it can't point somewhere noexec.
    tmp=""
    for base in /var/tmp /var/lib /opt; do
        candidate=$(mktemp -d "$base/awcp-install.XXXXXX" 2> /dev/null) || continue
        probe="$candidate/exec-probe"
        if (printf '#!/bin/sh\n' > "$probe" && chmod 755 "$probe" && "$probe") 2> /dev/null; then
            rm -f "$probe"
            tmp=$candidate
            break
        fi
        rm -rf "$candidate"
    done
    [ -n "$tmp" ] ||
        die "no exec-capable staging directory: tried /var/tmp /var/lib /opt, all rejected exec"
    trap 'rm -rf "$tmp"' EXIT
    # A signal handler returns to the next command, so these have to exit
    # themselves or the script would carry on with its work directory deleted.
    trap 'rm -rf "$tmp"; exit 130' HUP INT TERM
    mkdir "$tmp/repo"

    echo "Installing $BIN $version ($target)"

    # The tag is what ties the units and scripts to the release. A missing tag
    # means the version was published without being tagged. Fetched before the
    # binary so a bad version fails on 200 KB rather than tens of megabytes.
    archive="$REPO_URL/archive/refs/tags/v$version.tar.gz"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/repo.tar.gz" -- "$archive" ||
        die "cannot fetch $archive; is v$version tagged?"
    # --strip-components drops the top directory GitHub names after the
    # repository and tag, so the paths below don't have to rediscover it.
    tar --no-same-owner --strip-components=1 -xzf "$tmp/repo.tar.gz" -C "$tmp/repo"
    configuration="$tmp/repo/aws_workload_credentials_provider_common/configuration"
    [ -f "$configuration/install" ] || die "no install script in $archive"

    # The install script installs the binary itself, from ../../target/release
    # relative to its own location, which is where a source build leaves it. So
    # download straight there and let it do the rest: it owns the destination,
    # its ownership, and the order things are created in. Downloaded after the
    # archive is extracted, so no archive member can stand in for the binary.
    source_dir="$configuration/../../target/release"
    mkdir -p "$source_dir"
    fetch "$BASE_URL/$version/$target/$BIN" "$source_dir/$BIN"
    # A proxy or a misconfigured object can answer 200 with an HTML error page,
    # which curl -f accepts. The magic number is not integrity checking, but it
    # turns that into a clear failure here rather than an exec-format error after
    # the users, units and binary are on disk.
    magic=$(od -An -tx1 -N4 "$source_dir/$BIN" | tr -d ' \n')
    [ "$magic" = 7f454c46 ] ||
        die "$BASE_URL/$version/$target/$BIN is not an ELF binary; got magic $magic"
    chmod 755 "$source_dir/$BIN"

    if [ "$dry_run" = true ]; then
        # Kept, so the operator can read the units and check the binary before
        # committing to an install. Theirs to remove afterwards.
        trap - EXIT HUP INT TERM
        echo "Downloaded $BIN $version and the v$version configuration to $tmp"
        echo "Install skipped (--dry-run). Remove $tmp when you are done."
        return 0
    fi

    # Run through bash rather than exec'ing the file, so a noexec staging
    # directory doesn't block the install. -e is explicit because `bash <file>`
    # drops the shebang's flags, and released install scripts take errexit from
    # the shebang alone: without it the installer runs past a rejected config and
    # reports success.
    bash -e "$configuration/install" "$@"
}

main "$@"
