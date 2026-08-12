#!/usr/bin/env bash
#
# trim-history.sh - 精简 git 仓库历史以控制体积
#
# 当仓库提交数达到阈值时，把历史重建为「孤儿根提交 + 最近 N 天的提交」，
# 校验内容完全一致后强制推送。用于 private 这类只存放构建产物、
# 每次提交都产生大量无法 delta 压缩的二进制差异的仓库。
#
# 用法:
#   ./trim-history.sh [--threshold N] [--keep-days D] [--dry-run] <repo-dir>
#
#   --threshold N   提交数达到 N 才触发精简，默认 250
#   --keep-days D   保留最近 D 天的提交，默认 30
#   --dry-run       只打印将要执行的动作，不做任何改动

set -euo pipefail

THRESHOLD=250
KEEP_DAYS=30
DRY_RUN=false
REPO=""
BRANCH="main"

# 自带 git 身份：CI 中 commit-and-push.sh 在「无变更」时提前退出，
# 那一步的 git config 不会执行到，而 commit-tree 需要身份。
GIT_ID=(
    -c "user.name=github-actions[bot]"
    -c "user.email=github-actions[bot]@users.noreply.github.com"
)

usage() {
    echo "用法: $0 [--threshold N] [--keep-days D] [--dry-run] <repo-dir>" >&2
}

die() {
    echo "$0: $1" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
    --threshold)
        THRESHOLD="${2:-}"
        shift 2
        ;;
    --keep-days)
        # shellcheck disable=SC2034
        KEEP_DAYS="${2:-}"
        shift 2
        ;;
    --dry-run)
        # shellcheck disable=SC2034
        DRY_RUN=true
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    -*)
        usage
        die "未知参数: $1"
        ;;
    *)
        REPO="$1"
        shift
        ;;
    esac
done

if [[ -z $REPO ]]; then
    usage
    exit 1
fi

# 在目标仓库中执行 git，并附带自带身份
g() {
    command git -C "$REPO" "${GIT_ID[@]}" "$@"
}

# ---- ① 前置检查 ----
[[ -d $REPO ]] || die "目录不存在: $REPO"
g rev-parse --git-dir >/dev/null 2>&1 || die "不是 git 仓库: $REPO"
[[ -z $(g status --porcelain) ]] || die "工作区不干净，跳过精简"

current=$(g symbolic-ref --short HEAD 2>/dev/null || echo "")
[[ $current == "$BRANCH" ]] || die "当前分支为 '$current'，只支持 $BRANCH"

g fetch --quiet origin "$BRANCH" || die "fetch 失败"
read -r ahead behind < <(g rev-list --left-right --count "$BRANCH...origin/$BRANCH")
((ahead == 0 && behind == 0)) || die "与 origin/$BRANCH 不同步（领先 ${ahead}，落后 ${behind}）"

# ---- ② 阈值判断 ----
count=$(g rev-list --count "$BRANCH")
if ((count < THRESHOLD)); then
    echo "提交数 $count 未达阈值 ${THRESHOLD}，跳过精简"
    exit 0
fi
