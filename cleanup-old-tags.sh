#!/usr/bin/env bash
set -e

# 计算30天前的日期（格式：YYYYMMDDHHmm）
CUTOFF_DATE=$(env TZ=Asia/Shanghai date -d '30 days ago' +%Y%m%d%H%M)
echo "Cutoff date: $CUTOFF_DATE"

# 获取所有 tag 并删除早于30天的 tag
git fetch --tags

for tag in $(git tag); do
  # 检查 tag 是否符合日期格式（12位数字）
  if [[ $tag =~ ^[0-9]{12}$ ]]; then
    if [[ $tag -lt $CUTOFF_DATE ]]; then
      echo "Deleting old tag: $tag"
      git push --delete origin "$tag" || true
    fi
  fi
done

echo "Cleanup completed"
