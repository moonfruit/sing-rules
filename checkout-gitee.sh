#!/usr/bin/env bash
set -e
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

if (($# < 2)); then
    echo "$0: user token" >&2
    exit 1
fi

cd "$BIN"
rm -fr private
git clone "https://$1:$2@gitee.com/moonfruit/private.git"
