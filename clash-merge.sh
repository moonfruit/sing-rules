#!/usr/bin/env bash
set -euo pipefail

if [[ "$1" = "--enable-process" ]]; then
    OPTIONS=("--enable-process")
    shift
else
    OPTIONS=()
fi

BIN=$(dirname "${BASH_SOURCE[0]}")
for LIST in "$1"/*.list; do
    BASENAME="${LIST##*/}"
    BASENAME="${BASENAME%.*}"
    echo "Merging $BASENAME.json from $LIST"
    "$BIN/clash-to-sing-rules.py" "${OPTIONS[@]}" "$LIST" "$BASENAME.json"
    if [[ -r "$1/$BASENAME.exclude" ]]; then
        echo "Excluding $BASENAME.json from $1/$BASENAME.exclude"
        grep -f "$1/$BASENAME.exclude" "$BASENAME.json"
        grep -vf "$1/$BASENAME.exclude" "$BASENAME.json" >"$BASENAME.json.new"
        mv "$BASENAME.json.new" "$BASENAME.json"
    fi
done
