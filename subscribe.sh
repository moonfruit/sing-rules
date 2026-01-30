#!/usr/bin/env bash
set -euo pipefail

URL="$1"
OUTPUT="$2"
CLIENT="${3:-sing-box}"

if [[ -z $URL || -z $OUTPUT ]]; then
    echo "Usage: $0 <url> <output> [client]" >&2
    exit 1
fi

OPTS=(-fL -H "User-Agent: $CLIENT/*" -w '%header{subscription-userinfo}' -o "$OUTPUT")

USERINFO=$(curl "${OPTS[@]}" "$URL") || exit
if [[ -n "$USERINFO" ]]; then
    echo
    echo "$USERINFO" | tee "$OUTPUT.info"
fi
