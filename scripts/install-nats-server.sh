#!/usr/bin/env bash

set -eu

DEFAULT_VERSION="${NATS_VERSION:-2.9.6}"
NATS_BIN_DIR="${NATS_BIN_DIR:-$HOME/.local/bin}"

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
            echo "arm6"
            ;;
        armv7l)
            echo "arm7"
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
# Download NATS server
#
function download {
    VERSION="$1"
    PLATFORM="$(platform)"
    NATS_SRC_DIR="nats-server-v$VERSION-linux-$PLATFORM"
    TMP_DIR="/tmp/$NATS_SRC_DIR"
    URL="https://github.com/nats-io/nats-server/releases/download/v$VERSION/$NATS_SRC_DIR.zip"

    mkdir -p "$TMP_DIR"
    echo -e "Downloading nats-server from $URL"
    wget -q $URL -O "$TMP_DIR/$NATS_SRC_DIR.zip"
    echo -e "Extracting archive $TMP_DIR/$NATS_SRC_DIR.zip"
    unzip "$TMP_DIR/$NATS_SRC_DIR.zip" -d "$TMP_DIR" > /dev/null
    echo -e "Copying nats-server binary to $NATS_BIN_DIR/nats-server"
    mv "$TMP_DIR/$NATS_SRC_DIR/nats-server" $NATS_BIN_DIR/nats-server
    echo -e "Cleaning up temporary directory $TMP_DIR"
    rm -rf "$TMP_DIR"
}

# Execute download function using default version when not specified
download "${1:-$DEFAULT_VERSION}"
