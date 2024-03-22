#!/usr/bin/env bash
set -e
BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

(($# >= 3))

cd "$BIN"
rm -fr private
git clone "https://$1:$2@gitee.com/moonfruit/private.git"

cd private
curl "$3" | ../clash-to-sing.py >config.json

git config user.name 'github-actions[bot]'
git config user.email 'github-actions[bot]@users.noreply.github.com'

STATUS=$(git status --porcelain)
if [[ -n $STATUS ]]; then
    git add .
    git commit -m "Update config"
    git push
fi
