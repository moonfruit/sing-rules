#!/usr/bin/env bash

BIN=$(dirname "${BASH_SOURCE[0]}")
for LIST in "$1"/*.list; do
    BASENAME="${LIST##*/}"
    BASENAME="${BASENAME%.*}"
    echo "Merging $BASENAME.json from $LIST"
    "$BIN/clash-to-sing-rules.py" "$LIST" "$BASENAME.json"
done
