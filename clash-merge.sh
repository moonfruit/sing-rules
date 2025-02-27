#!/usr/bin/env bash

BIN=$(dirname "${BASH_SOURCE[0]}")
for LIST in "$1"/*.list; do
    BASENAME="${LIST##*/}"
    BASENAME="${BASENAME%.*}"
    echo "Merging $BASENAME.json from $LIST"
    "$BIN/clash-to-sing-rules.py" "$LIST" "$BASENAME.json"
    if [[ -r "$1/$BASENAME.exclude" ]]; then
        echo "Excluding $BASENAME.json from $1/$BASENAME.exclude"
        grep -f "$1/$BASENAME.exclude" "$BASENAME.json"
        grep -vf "$1/$BASENAME.exclude" "$BASENAME.json" | sponge "$BASENAME.json"
    fi
done
