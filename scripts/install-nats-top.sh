#!/usr/bin/env bash

set -eu

DEFAULT_VERSION="${NATSCLI_VERSION:-0.5.3}"
NATSTOP_BIN_DIR="${NATSTOP_BIN_DIR:-$HOME/.local/bin}"

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

    NATSTOP_SRC_DIR="nats-top_${VERSION}_linux_${PLATFORM}"
    TMP_DIR="/tmp/$NATSTOP_SRC_DIR"
    URL="https://github.com/nats-io/nats-top/releases/download/v${VERSION}/${NATSTOP_SRC_DIR}.tar.gz"

    mkdir -p "${TMP_DIR}"
    echo -e "Downloading nats-top from $URL"
    wget -q "${URL}" -O "${TMP_DIR}/${NATSTOP_SRC_DIR}.tar.gz"
    echo -e "Extracting archive ${TMP_DIR}/${NATSTOP_SRC_DIR}.tar.gz"
    tar -xzf "${TMP_DIR}/${NATSTOP_SRC_DIR}.tar.gz" -C "${TMP_DIR}" > /dev/null
    echo -e "Copying nats-top binary to ${NATSTOP_BIN_DIR}/nats-top"
    mv "${TMP_DIR}/nats-top" ${NATSTOP_BIN_DIR}/nats-top
    echo -e "Cleaning up temporary directory ${TMP_DIR}"
    rm -rf "${TMP_DIR}"
}

# Execute download function using default version when not specified
download "${1:-$DEFAULT_VERSION}"
