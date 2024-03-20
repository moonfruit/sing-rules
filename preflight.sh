#!/usr/bin/env bash
if [[ ! -d dat ]]; then
    echo "Loyalsoldier/v2ray-rules-dat does not exists" >&2
    exit 1
fi

TEMP=$(mktemp)
git -C dat rev-parse HEAD | tee "$TEMP"
if diff "$TEMP" v2ray-rules-dat.commit; then
    echo "Loyalsoldier/v2ray-rules-dat is not changed" >&2
    exit 1
else
    mv "$TEMP" v2ray-rules-dat.commit
fi
