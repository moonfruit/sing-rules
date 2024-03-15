#!/usr/bin/env bash

download-files() {
    if [[ -n $OUTPUT ]]; then
        echo "--- $OUTPUT ---"
        for FILE in "${FILES[@]}"; do
            echo "<< $FILE"
        done
        curl -fL "${FILES[@]}" | sed 's/#.*//;/^$/d' | sort -u >"$OUTPUT"
    fi
}

while read -ra LINE; do
    CURRENT="${LINE[0]}"
    if [[ $CURRENT != *.list ]]; then
        CURRENT="$CURRENT.list"
    fi

    if [[ $OUTPUT == "$CURRENT" ]]; then
        FILES+=("${LINE[1]}")
    else
        download-files
        OUTPUT=$CURRENT
        FILES=("${LINE[1]}")
    fi
done <"$1"
download-files
