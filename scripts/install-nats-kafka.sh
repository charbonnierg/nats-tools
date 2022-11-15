#!/usr/bin/env bash

set -eu

DEFAULT_VERSION="${NATS_VERSION:-1.3.0}"
NATSKAFKA_BIN_DIR="${NATSKAFKA_BIN_DIR:-$HOME/.local/bin}"

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
# Download nats-kafka
#
function download {
    VERSION="$1"
    PLATFORM="$(platform)"
    NATSKAFKA_SRC_DIR="nats-kafka-v$VERSION-linux-$PLATFORM"
    TMP_DIR="/tmp/$NATSKAFKA_SRC_DIR"
    URL="https://github.com/nats-io/nats-kafka/releases/download/v$VERSION/$NATSKAFKA_SRC_DIR.zip"

    mkdir -p "$TMP_DIR"
    echo -e "Downloading nats-kafka from $URL"
    wget -q $URL -O "$TMP_DIR/$NATSKAFKA_SRC_DIR.zip"
    echo -e "Extracting archive $TMP_DIR/$NATSKAFKA_SRC_DIR.zip"
    unzip "$TMP_DIR/$NATSKAFKA_SRC_DIR.zip" -d "$TMP_DIR" > /dev/null
    echo -e "Copying nats-kafka binary to $NATSKAFKA_BIN_DIR/nats-kafka"
    mv "$TMP_DIR/$NATSKAFKA_SRC_DIR/nats-kafka" $NATSKAFKA_BIN_DIR/nats-kafka
    echo -e "Cleaning up temporary directory $TMP_DIR"
    rm -rf "$TMP_DIR"
}

# Execute download function using default version when not specified
download "${1:-$DEFAULT_VERSION}"
