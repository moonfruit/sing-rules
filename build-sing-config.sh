#!/usr/bin/env bash
set -e
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

if (($# < 3)); then
    echo "$0: user token config" >&2
    exit 1
fi

CONFIG=$(realpath "$3")

cd "$BIN"
rm -fr private
git clone "https://$1:$2@gitee.com/moonfruit/private.git"

cd private
"$BIN/clash-to-sing.py" -c "$CONFIG" | sing-box format -c /dev/stdin >config.json

"$BIN/commit-and-push.sh" "Update config" || true
