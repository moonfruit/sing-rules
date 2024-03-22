#!/usr/bin/env bash
set -e

(($# >= 1))

git config user.name 'github-actions[bot]'
git config user.email 'github-actions[bot]@users.noreply.github.com'

STATUS=$(git status --porcelain)
if [[ -z $STATUS ]]; then
    exit 1
fi

git add .
git commit -m "$1"
if [[ -n $2 ]]; then
    git tag "$2"
fi
git push --follow-tags
