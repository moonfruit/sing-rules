#!/usr/bin/env bash

DIR=preflight
V2RAY_RULES_COMMIT=$DIR/v2ray-rules-dat.commit
BT_TRACKERS_URL=https://raw.githubusercontent.com/XIU2/TrackersListCollection/refs/heads/master/best.txt
BT_TRACKERS_FILE=dat/bt-trackers.txt
BT_TRACKERS_SHA1=$DIR/bt-trackers.txt.sha1

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

check-bt-trackers() {
    echo "Downloading bt-trackers from $BT_TRACKERS_URL"
    if ! curl -fsSL "$BT_TRACKERS_URL" -o "$BT_TRACKERS_FILE"; then
        echo "bt-trackers.txt download failed"
        return 1
    fi
    echo "Downloaded $(wc -l < "$BT_TRACKERS_FILE") lines to $BT_TRACKERS_FILE"

    echo -n "bt-trackers.txt: "
    sha1sum "$BT_TRACKERS_FILE" | awk '{print $1}' | tee "$TEMP"
    if diff "$TEMP" "$BT_TRACKERS_SHA1"; then
        echo "bt-trackers.txt is not changed"
        return 1
    else
        mv "$TEMP" "$BT_TRACKERS_SHA1"
    fi
}

# push 事件中 config/ 下的 .list/.exclude 变更时触发规则集构建
check-config-list() {
    [ "$GITHUB_EVENT_NAME" = "push" ] || return 1
    [ -n "$GITHUB_EVENT_PATH" ] && [ -n "$GITHUB_SHA" ] || return 1

    local before
    before=$(jq -r '.before // empty' "$GITHUB_EVENT_PATH")
    [ -n "$before" ] || return 1
    # 全零表示无父提交（首次推送/新分支），跳过
    case "$before" in *[!0]*) ;; *) return 1 ;; esac

    echo -n "config list/exclude: "
    if git diff --name-only "$before" "$GITHUB_SHA" 2>/dev/null \
        | grep -E '^config/.*\.(list|exclude)$'; then
        return 0
    else
        echo "not changed"
        return 1
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

build_rules=0
if check-v2ray-rules >&2; then
    build_rules=1
fi
echo "--------" >&2
if check-bt-trackers >&2; then
    build_rules=1
fi
echo "--------" >&2
if check-config-list >&2; then
    build_rules=1
fi
echo "--------" >&2

RESULT=()
((build_rules)) && RESULT+=(BUILD_RULES)
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
