#!/usr/bin/env bash
set -e
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

(($# >= 2))

cd "$BIN"
rm -fr private
git clone "https://$1:$2@gitee.com/moonfruit/private.git"

cd private
"$BIN/clash-to-sing.py" ../dat/clash-config.yaml | sing-box format -c /dev/stdin >config.json

"$BIN/commit-and-push.sh" "Update config" || true
