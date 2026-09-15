#!/bin/sh
# Ensure the data directory has an identity before running the requested
# command. The image holds no keys beyond those generated locally.
set -eu
DATA="${KEEPSTONE_DATA:-/data}"
mkdir -p "$DATA"
if [ ! -f "$DATA/identity.txt" ]; then
    keepstone --data-dir "$DATA" keygen >/dev/null
    echo "keepstone: generated identity in $DATA"
fi
exec "$@"
