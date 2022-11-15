#!/usr/bin/env bash

set -eu

DEFAULT_VERSION="${NATS_ACCOUNT_SERVER_VERSION:-1.0.1}"
NATS_ACCOUNT_SERVER_BIN_DIR="${NATS_ACCOUNT_SERVER_BIN_DIR:-$HOME/.local/bin}"

#
# Find host platform
#
function platform {
    case $(arch) in
        x86_64)
            echo "amd64"
            ;;
        aarch64)
            echo "arm64"
            ;;
        armv6l)
            echo "armv6"
            ;;
        armv7l)
            echo "armv7"
            ;;
        i386)
            echo "386"
            ;;
        *)
            >&2 echo "Architecture not supported: $(arch)"
            exit 1
            ;;
    esac
}

#
# Download nats-account-server
#
function download {
    VERSION="$1"
    PLATFORM="$(platform)"
    
    NATS_ACCOUNT_SERVER_SRC_DIR="nats-account-server-v$VERSION-linux-$PLATFORM"
    TMP_DIR="/tmp/$NATS_ACCOUNT_SERVER_SRC_DIR"
    URL="https://github.com/nats-io/nats-account-server/releases/download/v$VERSION/$NATS_ACCOUNT_SERVER_SRC_DIR.zip"

    mkdir -p "$TMP_DIR"
    echo -e "Downloading nats-account-server from $URL"
    wget -q $URL -O "$TMP_DIR/$NATS_ACCOUNT_SERVER_SRC_DIR.zip"
    echo -e "Extracting archive $TMP_DIR/$NATS_ACCOUNT_SERVER_SRC_DIR.zip"
    unzip "$TMP_DIR/$NATS_ACCOUNT_SERVER_SRC_DIR.zip" -d "$TMP_DIR" > /dev/null
    echo -e "Copying nats-account-server binary to $NATS_ACCOUNT_SERVER_BIN_DIR/nats-account-server"
    mv "$TMP_DIR/$NATS_ACCOUNT_SERVER_SRC_DIR/nats-account-server" $NATS_ACCOUNT_SERVER_BIN_DIR/nats-account-server
    echo -e "Cleaning up temporary directory $TMP_DIR"
    rm -rf "$TMP_DIR"
}

# Execute download function using default version when not specified
download "${1:-$DEFAULT_VERSION}"
