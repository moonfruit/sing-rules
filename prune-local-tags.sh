#!/usr/bin/env bash
#
# prune-local-tags.sh - 清除所有远程仓库不存在的本地标签
#
# 用法:
#   ./prune-local-tags.sh [remote] [--dry-run]
#
#   remote      远程仓库名称，默认为 origin
#   --dry-run   仅打印将被删除的标签，不实际删除

set -euo pipefail

remote="origin"
dry_run=false

for arg in "$@"; do
	case "$arg" in
	--dry-run)
		dry_run=true
		;;
	*)
		remote="$arg"
		;;
	esac
done

# 获取远程仓库的标签列表（去掉 ^{} 解引用项，仅保留标签名）
remote_tags="$(git ls-remote --tags "$remote" | grep -v '\^{}$' | sed 's#.*refs/tags/##')"

# 找出本地存在但远程不存在的标签
stale_tags="$(comm -23 <(git tag | sort) <(printf '%s\n' "$remote_tags" | sort))"

if [[ -z "$stale_tags" ]]; then
	echo "没有需要清除的本地标签，所有本地标签都存在于远程 '$remote'。"
	exit 0
fi

count="$(printf '%s\n' "$stale_tags" | wc -l | tr -d ' ')"
echo "发现 $count 个远程 '$remote' 不存在的本地标签："
printf '%s\n' "$stale_tags"

if $dry_run; then
	echo "(--dry-run) 未执行删除。"
	exit 0
fi

printf '%s\n' "$stale_tags" | xargs git tag -d
echo "已删除 $count 个本地标签。"
