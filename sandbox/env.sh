#!/usr/bin/env bash

function badUsage {
    >&2 echo "Script must be sourced, not executed"
    exit 1
}

[[ $0 != $BASH_SOURCE ]] || badUsage

PARENTDIR="$(dirname "$BASH_SOURCE")"

export NSC_HOME=$PARENTDIR/nsc
export NKEYS_PATH=$PARENTDIR/nsc/nkeys

nsc env -s $PARENTDIR/nsc/store
