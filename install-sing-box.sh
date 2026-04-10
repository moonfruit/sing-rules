#!/usr/bin/env bash
set -euo pipefail

SING_BOX_URL=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases \
  | jq -r '.[0].assets[] | select(.name | test("linux_amd64\\.deb$")) | .browser_download_url')

echo "Downloading: $SING_BOX_URL"
curl -fsSL -o sing-box.deb "$SING_BOX_URL"
sudo dpkg -i sing-box.deb
rm sing-box.deb
