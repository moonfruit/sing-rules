#!/usr/bin/env bash

DIR=preflight
V2RAY_RULES_COMMIT=$DIR/v2ray-rules-dat.commit
CLASS_CONFIG_SHA1=$DIR/clash-config.sha1

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

check-clash-url() {
    echo -n "clash-config: "
    sha1sum dat/clash-config.yaml | awk '{print $1}' | tee "$TEMP"
    if diff "$TEMP" "$CLASS_CONFIG_SHA1"; then
        echo "clash-config is not changed"
        return 1
    else
        mv "$TEMP" "$CLASS_CONFIG_SHA1"
    fi
}

RESULT=()
if check-v2ray-rules >&2; then
    RESULT+=(BUILD_RULES)
fi
echo "--------" >&2
if check-clash-url >&2; then
    RESULT+=(BUILD_CONFIG)
fi
if (( ${#RESULT[@]} > 0 )); then
    echo "--------" >&2
    for KEY in "${RESULT[@]}"; do
        echo "$KEY=1"
    done
else
    exit 1
fi
