#!/usr/bin/env bash
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

title() {
    local title="* $1 *"
    # shellcheck disable=SC2155
    local line=$(printf "%.s*" $(seq ${#title}))
    echo "$line"
    echo "$title"
    echo "$line"
}

title "Cleaning working directory"
rm -fv ./*.db ./*.json ./*.srs

echo
title "Converting geo from v2ray to sing"
geo convert ip -i v2ray -o sing -f geoip.db "$BIN/dat/geoip.dat"
geo convert site -i v2ray -o sing -f geosite.db "$BIN/dat/geosite.dat"

echo
title "Exporting geo as sing rule sets"
"$BIN/geo-to-sing-rules.py"

echo
title "Downloading clash rules"
CLASH=$(mktemp -d)
mkdir -p "$CLASH"
echo ">>> $CLASH"
(cd "$CLASH" && "$BIN/clash-download.sh" "$BIN/clash-list.txt")

title "Merging clash rules to sing rule sets"
"$BIN/clash-merge.sh" "$BIN/base"
"$BIN/clash-merge.sh" "$CLASH"

title "Compile sing rule sets"
for JSON in *.json; do
    echo "Compiling $JSON"
    sing-box rule-set compile "$JSON"
done
