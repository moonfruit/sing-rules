#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 一站式构建脚本
# 对应 .github/workflows/build.yaml 的全部流程
# 跳过：环境配置/工具安装、npm 发布
# ============================================================

BIN=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
cd "$BIN"

# ---- 拉取远程更新 ----
echo ">>> 拉取主工程远程更新"
git pull --rebase || true

# ---- 激活 Python venv ----
# shellcheck disable=SC1091
source venv/bin/activate
pip install -qr requirements.txt

# ---- 读取订阅地址 ----
CLASH_TXT="config/clash.txt"
if [[ ! -f $CLASH_TXT ]]; then
    echo "错误: 未找到 $CLASH_TXT" >&2
    exit 1
fi

# ---- 检查 private 目录 ----
PRIVATE_DIR=$(realpath private)
if [[ ! -d $PRIVATE_DIR ]]; then
    echo "错误: 未找到 private 目录" >&2
    exit 1
fi
echo ">>> 拉取 private 远程更新"
git -C "$PRIVATE_DIR" pull --rebase || true

# ---- 创建临时工作区 ----
WORKDIR=$(mktemp -d)
echo ">>> 临时工作区: $WORKDIR"

cleanup() {
    echo ">>> 清理临时工作区"
    rm -rf "$WORKDIR"
    rm -f dat geo
}
trap cleanup EXIT

# ---- 变量 ----
TAG=$(env TZ=Asia/Shanghai date +%Y%m%d%H%M)

# ---- Checkout v2ray-rules-dat ----
echo ">>> Checkout Loyalsoldier/v2ray-rules-dat (release)"
git clone --depth 1 -b release https://github.com/Loyalsoldier/v2ray-rules-dat.git "$WORKDIR/dat"
ln -sfn "$WORKDIR/dat" dat

# ---- 下载订阅 ----
echo ">>> 下载订阅"
while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] && continue
    read -r name url client <<<"$line"
    echo "  下载 $name (client=$client)"
    ./subscribe.sh "$url" "dat/$name" "$client"
done <"$CLASH_TXT"

# ---- Preflight ----
echo ">>> Preflight"
PREFLIGHT_ARGS=()
while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] && continue
    read -r name _ _ <<<"$line"
    PREFLIGHT_ARGS+=("$name" "$name.info")
done <"$CLASH_TXT"

BUILD_RULES=0
BUILD_CONFIG=0
if PREFLIGHT_OUTPUT=$(set -o pipefail; ./preflight.sh "${PREFLIGHT_ARGS[@]}"); then
    while IFS='=' read -r key value; do
        case "$key" in
            BUILD_RULES) BUILD_RULES="$value" ;;
            BUILD_CONFIG) BUILD_CONFIG="$value" ;;
        esac
    done <<<"$PREFLIGHT_OUTPUT"
fi

echo "  BUILD_RULES=$BUILD_RULES BUILD_CONFIG=$BUILD_CONFIG"

# ---- Checkout geo ----
if ((BUILD_RULES)); then
    echo ">>> Checkout MetaCubeX/geo"
    git clone --depth 1 https://github.com/MetaCubeX/geo.git "$WORKDIR/geo"
    ln -sfn "$WORKDIR/geo" geo
fi

# ---- 读取 Gitee token ----
SECRETS_TXT="config/secrets.txt"
GITEE_TOKEN=""
if [[ -f $SECRETS_TXT ]]; then
    while IFS='=' read -r key value; do
        [[ -z $key || $key == \#* ]] && continue
        if [[ $key == GITEE_TOKEN ]]; then
            GITEE_TOKEN="$value"
            break
        fi
    done <"$SECRETS_TXT"
fi

# ---- Build config ----
if ((BUILD_CONFIG)); then
    echo ">>> 构建 sing-box 配置"
    ./build-sing-config.sh "$GITEE_TOKEN"
fi

# ---- Build rule sets ----
if ((BUILD_RULES)); then
    echo ">>> 构建规则集"
    ./build-sing-rules.sh
fi

# ---- Commit and Push (private) ----
echo ">>> 提交 private"
(
    cd "$PRIVATE_DIR"
    if [[ -n $(git status --porcelain) ]]; then
        git add .
        git commit -m "Update config"
        git push
    else
        echo "  private: 无变更"
    fi
)

# ---- Commit and Push (main) ----
echo ">>> 提交主仓库"
if [[ -n $(git status --porcelain) ]]; then
    git add .
    git commit -m "Update rules"
    git tag "$TAG"
    git push --follow-tags
else
    echo "  主仓库: 无变更"
fi

# ---- Cleanup old tags ----
echo ">>> 清理旧标签"
./cleanup-old-tags.sh

# ---- Release ----
if ((BUILD_RULES)); then
    echo ">>> 创建 GitHub Release: $TAG"
    gh release create "$TAG" rules/* --title "$TAG"
fi

echo ">>> 完成!"
