#!/usr/bin/env bash
set -e
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

if (($# < 3)); then
    echo "$0: user token config..." >&2
    exit 1
fi

USER=$1
TOKEN=$2
shift 2
CONFIG=()
for NAME in "$@"; do
    CONFIG+=("$(realpath "$NAME")")
done

cd "$BIN"
rm -fr private
git clone "https://$USER:$TOKEN@gitee.com/moonfruit/private.git"

cd private
"$BIN/clash-to-sing.py" "${CONFIG[@]}" - | sing-box format -c /dev/stdin >config.json

"$BIN/commit-and-push.sh" "Update config" || true
