#!/usr/bin/env bash
set -e
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

if [[ -n $1 ]]; then
    TOKEN=(-t "$1")
else
    TOKEN=()
fi

cd "$BIN"
./clash-to-sing.py -c config/config.json -drw -s preflight/saved-countries.json "${TOKEN[@]}" |
    sing-box format -c /dev/stdin >private/config.json

TEMP="${RUNNER_TEMP:-/tmp}/config"
mkdir -p "$TEMP"
cp config/iphone/* "$TEMP"
./clash-to-sing.py -c config/config.json -r -s preflight/saved-countries.json "${TOKEN[@]}" |
    sing-box format -c /dev/stdin >"$TEMP/zoo.json"
sing-box merge -C "$TEMP" private/config-iphone.json
