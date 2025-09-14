#!/usr/bin/env bash

DIR=preflight
V2RAY_RULES_COMMIT=$DIR/v2ray-rules-dat.commit

TEMP=$(mktemp)
mkdir -p "$DIR"

check-v2ray-rules() {
    echo -n "Loyalsoldier/v2ray-rules-dat: "
    git -C dat rev-parse HEAD | tee "$TEMP"
    if diff "$TEMP" "$V2RAY_RULES_COMMIT"; then
        echo "Loyalsoldier/v2ray-rules-dat is not changed"
        return 1
    else
        mv "$TEMP" "$V2RAY_RULES_COMMIT"
    fi
}

check-config() {
    echo -n "$1: "
    sha1sum "dat/$1" | awk '{print $1}' | tee "$TEMP"
    if diff "$TEMP" "$DIR/$1.sha1"; then
        echo "$1 is not changed"
        return 1
    else
        mv "$TEMP" "$DIR/$1.sha1"
    fi
}

check-all-config() {
    local result=1
    for name in "$@"; do
        if check-config "$name"; then
            result=0
        fi
    done
    return $result
}

RESULT=()
if check-v2ray-rules >&2; then
    RESULT+=(BUILD_RULES)
fi
echo "--------" >&2
if (($#)); then
    if check-all-config "$@" >&2; then
        RESULT+=(BUILD_CONFIG)
    fi
fi
if ((${#RESULT[@]})); then
    echo "--------" >&2
    for KEY in "${RESULT[@]}"; do
        echo "$KEY=1"
    done
else
    exit 1
fi
