#!/usr/bin/env bash

VERSION=$1
if [[ -z $VERSION ]]; then
    echo "No version defined"
    exit 1
fi

if [[ $VERSION =~ ([0-9]{8})([0-9]{4}) ]]; then
    VERSION=1.${BASH_REMATCH[1]}.${BASH_REMATCH[2]#0}
else
    VERSION=1.$VERSION.0
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
