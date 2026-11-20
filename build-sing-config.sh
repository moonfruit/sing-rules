#!/usr/bin/env bash
set -euo pipefail
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

if [[ -z $1 ]]; then
    echo "Usage: $0 <token>" >&2
    exit 1
fi
TOKEN="$1"

cd "$BIN"
./clash-to-sing.py -c config/config.json -rw -s preflight/saved-countries.json -t "$TOKEN" |
    sing-box format -c /dev/stdin |
    ./fix-format.py >private/config.json

TEMP=$(mktemp -d "${RUNNER_TEMP:-/tmp}/sing-config.XXXXXXXX")
trap 'rm -rf "$TEMP"' EXIT
cp config/iphone/* "$TEMP"
sed -i'' "s|\$TOKEN|$TOKEN|g" "$TEMP"/*
cp private/config.json "$TEMP/zoo.json"
sing-box merge -C "$TEMP" "$TEMP/merged.tmp"
./copy-config.py <"$TEMP/merged.tmp" >private/config-iphone.json

cat private/config-iphone.json | ./prune-config.py >private/config-appletv.json
