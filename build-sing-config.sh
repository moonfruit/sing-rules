#!/usr/bin/env bash
set -euo pipefail
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

if [[ -z $1 ]]; then
    echo "Usage: $0 <token>" >&2
    exit 1
fi
TOKEN="$1"

cd "$BIN"
./clash-to-sing.py -c config/config.json -drw -s preflight/saved-countries.json -t "$TOKEN" |
    sing-box format -c /dev/stdin >private/config.json

TEMP="${RUNNER_TEMP:-/tmp}/config"
mkdir -p "$TEMP"
cp config/iphone/* "$TEMP"
sed -i'' "s|\$TOKEN|$TOKEN|g" "$TEMP"/*
cat private/config.json | ./copy-config.py >"$TEMP/zoo.json"
sing-box merge -C "$TEMP" private/config-iphone.json
