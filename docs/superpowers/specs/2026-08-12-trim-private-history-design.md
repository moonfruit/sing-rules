# private 仓库历史自动精简

日期：2026-08-12

## 背景

`private`（gitee.com/moonfruit/private）存放 `build-sing-config.sh` 与 `build-sing-rules.sh`
生成的构建产物：`config.json`、`config-iphone.json`、`config-appletv.json` 以及 `rules/` 下的
全部 `.json` / `.srs`。这些文件每次构建都变，且 `.srs` 是二进制、`block.json` 有 10 MB，
几乎无法 delta 压缩，导致仓库体积持续膨胀。

2026-08-12 精简前的实测数据：

| 指标 | 数值 |
|------|------|
| 精简前 291 提交（本地 pack） | 591 MiB |
| 精简后 22 提交（远端全新克隆） | 51 MB |
| 单次提交增量（本地最优压缩） | 约 0.7 MiB |
| 单个完整快照（根提交） | 约 6.8 MiB |
| CI 频率 | 每日 2 次定时 + push 触发，实测约 3 提交/天 |
| 累积速度 | 约 150 MB/月（服务端），约 3 个月撑满 Gitee 500 MB 配额 |

历史印证：上一次手动 squash 在 2026-05-09，本次在 2026-08-12，正好三个月一轮。
此前一直靠手动执行，本设计将其自动化。

## 目标

在构建流程中自动控制 `private` 仓库体积，无需人工介入，同时保留足够的历史用于回滚排查。

## 非目标

- 不改变 `private` 存放构建产物的方式（不迁移到 release 附件或其他存储）。
- 不处理主仓库 `sing-rules` 的历史（GitHub 配额宽松，且 `cleanup-old-tags.sh` 已覆盖标签清理）。
- 不追求「仓库永远最小」。见下方「为什么不是每次都精简」。

## 为什么不是每次都精简

重写历史后所有对象 ID 都会改变，强推需要上传**完整快照**（约 7 MiB），而非增量的
0.7 MiB。同时服务端旧对象在 GC 之前不会消失。因此推送频率越高，重写越亏：
每次都重写会让上传量涨约 10 倍，且在服务端 GC 之前仓库反而更胖。

结论：采用**低频、阈值触发**策略。

## 两种收益需要区分

- **克隆体积 / CI 提速**：强推后立即生效。`checkout-gitee.sh` 每次 CI 都做全量
  `git clone`，本次精简后全新克隆已从 500 MB 量级降到 51 MB。这部分收益已验证。
- **Gitee 存储配额释放**：取决于 Gitee 服务端何时执行 GC，无法从客户端验证。
  需要人工观察 Gitee 仓库容量显示来确认。这是本方案唯一的未知项，
  但即便配额不释放，克隆提速的收益依然成立。

## 方案

### 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--threshold` | 250 | 提交数达到此值才触发精简 |
| `--keep-days` | 30 | 保留最近多少天的提交 |

按 3 提交/天估算：从当前的 22 提交起算，首次约 76 天后触发；
此后每轮从约 90 提交（30 天）涨到 250 提交，约 53 天一次。
服务端体积在 51 MB ↔ 400 MB 之间循环，对 500 MB 配额保有余量。

分支名 `main` 在脚本内硬编码，不作为参数——`private` 只有这一个受管理的分支
（远端另有 `binary` 分支，本方案不触碰）。

### 新增脚本 `trim-history.sh`

```
./trim-history.sh [--threshold N] [--keep-days D] [--dry-run] <repo-dir>
```

职责单一：给定 git 仓库目录，若提交数超过阈值，则将历史重建为
「孤儿根提交 + 最近 N 天提交」，校验通过后强制推送。

**不并入 `commit-and-push.sh`**：该脚本被主仓库和 `private` 共用，
private 特有的历史策略不应污染它。

### 执行流程

1. **前置检查**：目录是 git 仓库；工作区干净；当前分支为 `main`；
   `git fetch` 后本地与 `origin/main` 完全同步（`git rev-list --left-right --count`
   两侧均为 0）。任一不满足则退出非 0。
2. **阈值判断**：`git rev-list --count HEAD` 小于 `--threshold` 则退出 0，不做任何改动。
   绝大多数运行走这条路径。
3. **定位基线**：`OLDEST_KEEP` = `--keep-days` 窗口内最老的提交，
   `BASE` = `OLDEST_KEEP` 的父提交。
4. **造新根**：用 `BASE` 的树通过 `git commit-tree` 创建无父提交，
   message 为 `Initial commit`，`GIT_AUTHOR_DATE` / `GIT_COMMITTER_DATE` 沿用 `BASE` 的时间。
5. **重放**：在临时分支上执行 `git rebase --onto <新根> <BASE>`，
   把窗口内的提交原样重放到新根之上（作者日期保留）。校验通过后才把 `main` 指向它。
6. **护栏校验**：新旧 HEAD 的树必须完全一致（`git diff --quiet <旧HEAD> <新HEAD>`），
   且新提交数等于「窗口内提交数 + 1」（+1 为新根）。
7. **强制推送**：`git push --force-with-lease origin main`。
8. **本地瘦身**：`git reflog expire --expire=now --all && git gc --prune=now`。
   在 CI 中无实际作用（runner 是临时的），在本地 `build-all.sh` 场景有效。

### 安全设计

自动化重写历史一旦边界算错就是不可恢复的远端破坏，因此护栏内建于脚本，不依赖调用方：

- **第 6 步的内容一致性校验是硬门槛**。新旧 HEAD 的树必须逐字节相同，
  否则中止、把 `main` 恢复到旧 HEAD、退出非 0。
- **使用 `--force-with-lease` 而非 `--force`**：远端在此期间被改动过则拒绝推送。
- **任何一步失败都回滚到旧 HEAD**，退出码非 0 仅作告警，
  不影响已经完成的正常增量推送。
- **不向远端推送备份分支或 tag**：那会让旧对象保持可达，直接抵消精简的意义。
  备份只存在于本地 reflog 中（`gc` 之前）。

### 边界情况

| 情况 | 处理 |
|------|------|
| 窗口内提交数为 0（长期未构建） | 退出 0，不做改动 |
| 全部提交都在窗口内（`BASE` 不存在） | 退出 0，无可裁剪 |
| 工作区有未提交改动 | 退出非 0，不做改动 |
| 本地与 `origin/main` 不同步 | 退出非 0，不做改动 |

### 已识别的坑

- **git identity**：`git commit-tree` 需要 `user.name` / `user.email`。
  CI 中 `commit-and-push.sh` 在「无变更」时提前 `exit 1`，那一步的 `git config` 不会执行到。
  脚本使用 `git -c user.name=... -c user.email=...` 自带身份，不依赖外部配置。
- **CI 凭据**：`checkout-gitee.sh` 克隆时 URL 已内嵌 token，且是全量 clone（非 shallow），
  强推可用。

## 接入点

精简只在 `private` 确实产生了新提交并推送成功后执行。无变更时提交数不会增长，
跨过阈值必然发生在「有变更」的那一次，因此这个约束不会漏掉触发时机，
还省掉一次无谓的 `git fetch`。

### `.github/workflows/build.yaml`

给 private 推送步骤加 `id`，新增 trim 步骤挂在其成功之后：

```yaml
- name: Commit and Push (private)
  id: commit_push_private        # 新增
  continue-on-error: true
  run: ../commit-and-push.sh "Update config"
  working-directory: private

- name: Trim private history      # 新增
  if: steps.commit_push_private.outcome == 'success'
  continue-on-error: true
  run: ./trim-history.sh private
```

### `build-all.sh`

调用放进「有变更」分支内，紧跟 `git push` 之后：

```bash
if [[ -n $(git status --porcelain) ]]; then
    git add .
    git commit -m "Update config"
    git push
    "$BIN/trim-history.sh" "$PRIVATE_DIR"   # 新增
else
    echo "  private: 无变更"
fi
```

## 验证方式

- `--dry-run` 输出将要执行的动作（当前提交数、基线提交、保留数量、预计削减量），
  不改动任何东西。
- 接入 CI 之前，先在 `private` 的一个临时 clone 上跑通完整流程，
  确认内容一致性校验通过、强推成功、提交数符合预期。
- 阈值路径（提交数不足时直接退出）需单独验证，因为这是实际运行中最常走的分支。
