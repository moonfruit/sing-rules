#!/usr/bin/env bash

if [[ -z $1 ]]; then
    echo "No version"
    exit 1
fi

cat >package.json <<END
{
  "name": "sing-rules",
  "version": "$1",
  "description": "sing-box rule sets base on Loyalsoldier/v2ray-rules-dat",
  "homepage": "https://github.com/moonfruit/sing-rules#readme",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/moonfruit/sing-rules.git"
  },
  "license": "GPL-3.0-or-later",
  "files": [
    "rules/*"
  ]
}
END

npm publish
