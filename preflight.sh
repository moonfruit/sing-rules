#!/usr/bin/env bash
TEMP=$(mktemp)

V2RAY_RULES_COMMIT=preflight/v2ray-rules-dat.commit
CLASS_CONFIG_SHA1=preflight/clash-config.sha1

check-v2ray-rules() {
    echo -n "Loyalsoldier/v2ray-rules-dat: "
    git -C dat rev-parse HEAD | tee "$TEMP"
    if diff "$TEMP" "$V2RAY_RULES_COMMIT"; then
        echo "Loyalsoldier/v2ray-rules-dat is not changed" >&2
        return 1
    else
        mv "$TEMP" "$V2RAY_RULES_COMMIT"
    fi
}

check-clash-url() {
    echo -n "clash-config: "
    sha1sum dat/clash-config.yaml | awk '{print $1}' | tee "$TEMP"
    if diff "$TEMP" "$CLASS_CONFIG_SHA1"; then
        echo "clash-config is not changed" >&2
        return 1
    else
        mv "$TEMP" "$CLASS_CONFIG_SHA1"
    fi
}

check-v2ray-rules || check-clash-url
