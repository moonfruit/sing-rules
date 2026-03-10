#!/usr/bin/env bash
set -euo pipefail
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

usage() {
    echo "Usage: $0 <url>"
    echo "  url  URL to download fake_ip_filter.list"
    echo "Outputs lan.json and fakeip-bypass.json in the current directory."
    exit 1
}

title() {
    local title="* $1 *"
    # shellcheck disable=SC2155
    local line=$(printf "%.s*" $(seq ${#title}))
    echo "$line"
    echo "$title"
    echo "$line"
}

[[ $# -lt 1 ]] && usage

URL="$1"

TEMP=$(mktemp)
trap 'rm -f "$TEMP"' EXIT

title "Downloading fake_ip_filter.list"
echo ">>> $URL"
curl -fsSL "$URL" -o "$TEMP"
echo "Downloaded $(wc -l < "$TEMP") lines"

# 拆分：#LAN 块（从 #LAN 到下一个 # 注释之前）为 LAN 部分，其余为 fakeip-bypass 部分
LAN_LIST=$(mktemp)
BYPASS_LIST=$(mktemp)
trap 'rm -f "$TEMP" "$LAN_LIST" "$BYPASS_LIST"' EXIT

title "Splitting into LAN and fakeip-bypass sections"
awk '
    /^#LAN$/ { in_lan=1; next }
    /^#/     { in_lan=0 }
    in_lan   { print > "'"$LAN_LIST"'"; next }
             { print > "'"$BYPASS_LIST"'" }
' "$TEMP"
echo "          LAN entries: $(grep -c . "$LAN_LIST" || true)"
echo "fakeip-bypass entries: $(grep -c . "$BYPASS_LIST" || true)"

title "Generating lan.json"
"$BIN/filter-to-sing-rules.py" "$LAN_LIST" -o lan.json
echo ">>> lan.json"

title "Generating fakeip-bypass.json"
"$BIN/filter-to-sing-rules.py" "$BYPASS_LIST" -o fakeip-bypass.json
echo ">>> fakeip-bypass.json"
