#!/usr/bin/env bash
bfg -D "*.{commit,json,srs,db}"
git reflog expire --expire=now --all
git gc --prune=now --aggressive
