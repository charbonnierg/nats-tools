#!/usr/bin/env bash

set -eu

DEFAULT_VERSION="${NATSCLI_VERSION:-0.0.35}"
NATSCLI_BIN_DIR="${NATSCLI_BIN_DIR:-$HOME/.local/bin}"

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
# Download NATS CLI
#
function download {
    VERSION="$1"
    PLATFORM="$(platform)"
    
    NATSCLI_SRC_DIR="nats-$VERSION-linux-$PLATFORM"
    TMP_DIR="/tmp/$NATSCLI_SRC_DIR"
    URL="https://github.com/nats-io/natscli/releases/download/v$VERSION/$NATSCLI_SRC_DIR.zip"

    mkdir -p "$TMP_DIR"
    echo -e "Downloading nats CLI from $URL"
    wget -q $URL -O "$TMP_DIR/$NATSCLI_SRC_DIR.zip"
    echo -e "Extracting archive $TMP_DIR/$NATSCLI_SRC_DIR.zip"
    unzip "$TMP_DIR/$NATSCLI_SRC_DIR.zip" -d "$TMP_DIR" > /dev/null
    echo -e "Copying nats CLI binary to $NATSCLI_BIN_DIR/nats"
    mv "$TMP_DIR/$NATSCLI_SRC_DIR/nats" $NATSCLI_BIN_DIR/nats
    echo -e "Cleaning up temporary directory $TMP_DIR"
    rm -rf "$TMP_DIR"
}

# Execute download function using default version when not specified
download "${1:-$DEFAULT_VERSION}"
