#!/usr/bin/env bash
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

echo --- Cleaning working directory ---
rm -fv ./*.db ./*.json ./*.srs

echo --- Converting geo from v2ray to sing ---
geo convert ip -i v2ray -o sing -f geoip.db "$BIN/dat/geoip.dat"
geo convert site -i v2ray -o sing -f geosite.db "$BIN/dat/geosite.dat"

echo --- Exporting geo as sing rule sets ---
"$BIN/geo-to-sing-rules.py"

echo --- Downloding clash rules ---
CLASH=$(mktemp -d)
mkdir -p "$CLASH"
cd "$CLASH" && "$BIN/clash-download.sh" "$BIN/clash-list.txt"

echo -- Merging clash rules to sing rule sets ---
"$BIN/clash-merge.sh" "$BIN/base"
"$BIN/clash-merge.sh" "$BIN/clash"

echo -- Compile sing rule sets ---
for JSON in *.json; do
    sing-box rule-set compile "$JSON"
done
