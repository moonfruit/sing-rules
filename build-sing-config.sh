#!/usr/bin/env bash
set -e
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

(($# >= 3))

cd "$BIN"
rm -fr private
git clone "https://$1:$2@gitee.com/moonfruit/private.git"

cd private
curl "$3" | "$BIN/clash-to-sing.py" | sing-box format -c /dev/stdin >config.json

"$BIN/commit-and-push.sh" "Update config" || true
