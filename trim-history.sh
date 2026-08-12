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
        KEEP_DAYS="${2:-}"
        shift 2
        ;;
    --dry-run)
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

# ---- ③ 定位基线 ----
# 注意：git rev-list --since 过滤的是提交者日期（committer date），
# 重放时用 --committer-date-is-author-date 保证两者一致，窗口语义才稳定。
oldest_keep=$(g rev-list --since="$KEEP_DAYS days ago" "$BRANCH" | tail -1)
if [[ -z $oldest_keep ]]; then
    echo "最近 $KEEP_DAYS 天内无提交，跳过精简"
    echo "警告: 提交数 ${count} 已达阈值 ${THRESHOLD}，但精简未执行——最近 ${KEEP_DAYS} 天窗口内没有任何提交。" >&2
    echo "      rev-list --since 按提交者(committer)日期过滤；若历史曾被批量改写导致 committer 日期停滞在某一时刻，" >&2
    echo "      窗口会持续判定为空、仓库无限增长，请检查提交的 committer 日期分布。" >&2
    exit 0
fi

if ! base=$(g rev-parse --verify --quiet "$oldest_keep^"); then
    echo "全部提交都在最近 $KEEP_DAYS 天内，无可裁剪，跳过精简"
    echo "警告: 提交数 ${count} 已达阈值 ${THRESHOLD}，但精简未执行——全部提交都落在最近 ${KEEP_DAYS} 天窗口内，无可裁剪。" >&2
    echo "      若这并非预期，请检查提交的 committer 日期是否被批量改写过（窗口按 committer 日期过滤）。" >&2
    exit 0
fi

# BEGIN merge-preflight
# 窗口内含合并提交时，rebase 会把它们展平成普通提交，破坏分支结构；
# 提前发现并跳过，避免落到 ⑥ 的提交数护栏才发现、还要靠日志排查原因。
merge_count=$(g rev-list --merges --count "$base..$BRANCH")
if ((merge_count > 0)); then
    echo "警告: 提交数 ${count} 已达阈值 ${THRESHOLD}，但精简未执行——窗口 ${base}..${BRANCH} 内含 ${merge_count} 个合并提交。" >&2
    echo "      git rebase 会展平合并提交，可能触发提交数护栏或悄悄丢失分支结构，需人工处理该窗口后再重试。" >&2
    exit 0
fi
# END merge-preflight

keep_count=$(g rev-list --count "$base..$BRANCH")
old_head=$(g rev-parse "$BRANCH")
reduction=$((count - keep_count - 1))

echo "当前提交数: $count"
echo "保留最近 $KEEP_DAYS 天的 $keep_count 个提交 + 1 个新根提交"
echo "削减: ${reduction} 个提交"
echo "基线提交: $(g log -1 --format='%h %ad %s' --date=short "$base")"

if ((reduction <= 0)); then
    echo "警告: 提交数 ${count} 已达阈值 ${THRESHOLD}，但窗口外已无可裁剪的提交（削减量为 ${reduction}），跳过精简。" >&2
    echo "      这通常发生在刚精简完成后又被再次触发，属正常现象，无需处理。" >&2
    exit 0
fi

if $DRY_RUN; then
    echo "(--dry-run) 未执行任何改动。"
    exit 0
fi

# ---- ④ 创建孤儿根提交 ----
# 用子 shell 隔离日期环境变量，避免泄漏到后续的 rebase
base_date=$(g log -1 --format=%aI "$base")
new_root=$(
    export GIT_AUTHOR_DATE="$base_date" GIT_COMMITTER_DATE="$base_date"
    g commit-tree "$base^{tree}" -m "Initial commit"
)

# ---- ⑤ 在临时分支上重放 ----
tmp_branch="trim-history-tmp"
g branch -f "$tmp_branch" "$BRANCH"

rollback() {
    g rebase --abort >/dev/null 2>&1 || true
    g checkout -q "$BRANCH" >/dev/null 2>&1 || true
    g reset --hard --quiet "$old_head"
    g branch -D "$tmp_branch" >/dev/null 2>&1 || true
}

if ! g rebase --quiet --committer-date-is-author-date \
    --onto "$new_root" "$base" "$tmp_branch"; then
    rollback
    die "重放失败，已回滚到 $old_head"
fi

# ---- ⑥ 护栏校验 ----
new_head=$(g rev-parse "$tmp_branch")
new_count=$(g rev-list --count "$tmp_branch")

[[ $(g rev-parse "${old_head}^{tree}") == $(g rev-parse "${new_head}^{tree}") ]] || {
    rollback
    die "内容校验失败：新旧历史的工作树不一致，已回滚"
}

if ((new_count != keep_count + 1)); then
    rollback
    die "提交数校验失败：期望 $((keep_count + 1)) 个，实际 ${new_count} 个，已回滚到 ${old_head}；常见原因是窗口 ${base}..${BRANCH} 内含被 rebase 展平的合并提交，请检查该区间的提交结构"
fi

# ---- ⑦ 强制推送 ----
g checkout -q "$BRANCH"
g reset --hard --quiet "$new_head"

if ! g push --force-with-lease origin "$BRANCH"; then
    g reset --hard --quiet "$old_head"
    g branch -D "$tmp_branch" >/dev/null
    die "推送失败，已回滚到 $old_head"
fi

g branch -D "$tmp_branch" >/dev/null

echo "精简完成: ${count} -> ${new_count} 个提交（${old_head:0:10} -> ${new_head:0:10}），已强制推送到 origin/${BRANCH}"

# ---- ⑧ 本地瘦身 ----
# 这会丢弃本地 reflog 中的旧历史。此时推送已成功且内容校验已通过，
# 旧历史没有保留价值，回收磁盘才是目的。推送已经完成，这两步失败不应
# 倒推成「精简失败」，因此只报警、不影响脚本的退出码。
g reflog expire --expire=now --all || echo "警告: reflog expire 失败，已忽略（推送已成功，不影响结果）" >&2
g gc --prune=now --quiet || echo "警告: git gc 失败，已忽略（推送已成功，不影响结果）" >&2
