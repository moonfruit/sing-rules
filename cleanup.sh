#!/usr/bin/env bash
bfg -D "*.{commit,json,srs,db}"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --prune-empty --force
git reflog expire --expire=now --all
git gc --prune=now --aggressive
