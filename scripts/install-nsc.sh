#!/usr/bin/env bash

set -eu

DEFAULT_VERSION="${NATSCLI_VERSION:-2.7.3}"
NSC_BIN_DIR="${NSC_BIN_DIR:-$HOME/.local/bin}"

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
# Download NSC
#
function download {
    VERSION="$1"
    PLATFORM="$(platform)"
    NSC_SRC_DIR="nsc-linux-$PLATFORM"
    TMP_DIR="/tmp/$NSC_SRC_DIR"
    URL="https://github.com/nats-io/nsc/releases/download/$VERSION/$NSC_SRC_DIR.zip"

    mkdir -p "$TMP_DIR"
    echo -e "Downloading nsc from $URL"
    wget -q $URL -O "$TMP_DIR/$NSC_SRC_DIR.zip"
    echo -e "Extracting archive $TMP_DIR/$NSC_SRC_DIR.zip"
    unzip "$TMP_DIR/$NSC_SRC_DIR.zip" -d "$TMP_DIR" > /dev/null
    echo -e "Copying nsc binary to $NSC_BIN_DIR/nsc"
    mv "$TMP_DIR/nsc" $NSC_BIN_DIR/nsc
    echo -e "Cleaning up temporary directory $TMP_DIR"
    rm -rf "$TMP_DIR"
}

# Execute download function using default version when not specified
download "${1:-$DEFAULT_VERSION}"
