#!/usr/bin/env bash

BIN=$(dirname "${BASH_SOURCE[0]}")
for LIST in "$1"/*.list; do
    BASENAME="${LIST##*/}"
    BASENAME="${BASENAME%.*}"
    echo clash2sing.py "$LIST" "$BASENAME.json"
    "$BIN/clash2sing.py" "$LIST" "$BASENAME.json"
done
