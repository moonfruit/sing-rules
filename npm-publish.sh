#!/usr/bin/env bash

if [[ $1 =~ ^([0-9]{4})([0-9]{4})([0-9]{4})$ ]]; then
    VERSION=${BASH_REMATCH[1]}.${BASH_REMATCH[2]#0}.${BASH_REMATCH[3]#0}
elif [[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    VERSION=$1
else
    echo "Invalid version: '$1'"
    exit 1
fi

cat >package.json <<END
{
  "name": "sing-rules",
  "version": "$VERSION",
  "description": "sing-box rule sets base on Loyalsoldier/v2ray-rules-dat",
  "license": "GPL-3.0-or-later",
  "homepage": "https://github.com/moonfruit/sing-rules#readme",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/moonfruit/sing-rules.git"
  },
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "files": [
    "rules/*"
  ]
}
END

npm publish
