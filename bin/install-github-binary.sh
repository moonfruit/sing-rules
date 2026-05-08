#!/usr/bin/env bash
# Usage: bin/install-github-binary.sh [--prerelease] <owner/repo> <asset-regex> <install-name>
#
# Resolve the latest release of <owner/repo>, find the asset whose name matches
# <asset-regex> (jq test, PCRE-like), download it, and install as <install-name>
# into $INSTALL_BIN_DIR (default /usr/local/bin). For .tar.gz/.tgz/.zip archives
# the inner file matching <install-name> is extracted and installed.
#
# Flags:
#   --prerelease  Include pre-releases (picks the most recent release of any kind).
#                 Without this flag, latest stable release is used.
#
# Env:
#   GH_TOKEN          Optional GitHub token for higher API rate limits.
#   INSTALL_BIN_DIR   Override install destination (default /usr/local/bin).
set -euo pipefail

PRERELEASE=0
if [[ ${1:-} == --prerelease ]]; then
    PRERELEASE=1
    shift
fi

if (($# != 3)); then
    echo "Usage: $0 [--prerelease] <owner/repo> <asset-regex> <install-name>" >&2
    exit 2
fi

REPO="$1"
PATTERN="$2"
NAME="$3"
DEST="${INSTALL_BIN_DIR:-/usr/local/bin}"

CURL=(curl -fsSL)
[[ -n "${GH_TOKEN:-}" ]] && CURL+=(-H "Authorization: Bearer ${GH_TOKEN}")

if ((PRERELEASE)); then
    JSON=$("${CURL[@]}" "https://api.github.com/repos/${REPO}/releases?per_page=1" | jq '.[0]')
else
    JSON=$("${CURL[@]}" "https://api.github.com/repos/${REPO}/releases/latest")
fi

TAG=$(jq -r '.tag_name' <<<"$JSON")
URL=$(jq -r --arg pat "$PATTERN" '.assets[] | select(.name | test($pat)) | .browser_download_url' <<<"$JSON" | head -1)

if [[ -z "$URL" || "$URL" == null ]]; then
    echo "Error: no asset matching /$PATTERN/ in $REPO@$TAG" >&2
    exit 1
fi

echo ">>> Installing $NAME from $REPO@$TAG"
echo "    $URL"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ASSET="$WORK/$(basename "$URL")"
curl -fsSLo "$ASSET" "$URL"

case "$ASSET" in
    *.tar.gz | *.tgz)
        tar -xzf "$ASSET" -C "$WORK"
        BINARY=$(find "$WORK" -type f -name "$NAME" | head -1)
        ;;
    *.zip)
        unzip -q "$ASSET" -d "$WORK"
        BINARY=$(find "$WORK" -type f -name "$NAME" | head -1)
        ;;
    *)
        BINARY="$ASSET"
        ;;
esac

if [[ -z "${BINARY:-}" ]]; then
    echo "Error: $NAME not found inside archive" >&2
    exit 1
fi

if [[ -w "$DEST" ]]; then
    install -m 0755 "$BINARY" "$DEST/$NAME"
else
    sudo install -m 0755 "$BINARY" "$DEST/$NAME"
fi
