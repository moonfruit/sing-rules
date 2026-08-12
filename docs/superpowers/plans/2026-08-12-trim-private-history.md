# private 仓库历史自动精简 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 `trim-history.sh`，在 `private` 仓库提交数达到阈值时自动把历史重建为「孤儿根提交 + 最近 30 天提交」并强制推送，接入 CI 与 `build-all.sh`。

**Architecture:** 单个独立 bash 脚本，接收仓库目录作为参数。绝大多数运行在阈值判断处提前退出，零副作用。触发时在临时分支上 rebase，通过「新旧 HEAD 树必须完全一致」的硬校验后才把 `main` 指向新历史并 `--force-with-lease` 推送；任何环节失败都回滚到旧 HEAD。测试用 stdlib `unittest` 驱动真实的本地 bare 远端 + 克隆夹具，不引入新依赖。

**Tech Stack:** bash 5、git 2.55、Python stdlib `unittest`（仓库现有测试方式）、shellcheck

设计依据：`docs/superpowers/specs/2026-08-12-trim-private-history-design.md`

## Global Constraints

- 脚本首行 `#!/usr/bin/env bash`，紧接 `set -euo pipefail`（与仓库其他脚本一致）
- 缩进 4 空格（仓库 15 个 shell 脚本中 14 个用空格）
- 注释与用户可见输出用简体中文（与 `prune-local-tags.sh`、`build-all.sh` 一致）
- 参数默认值：`--threshold 250`、`--keep-days 30`
- 分支名 `main` 硬编码，不作为参数
- git 身份硬编码为 `github-actions[bot]` / `github-actions[bot]@users.noreply.github.com`，通过 `git -c` 传入，不依赖仓库或全局配置
- 不新增 Python 依赖：测试用 stdlib `unittest`，运行方式 `venv/bin/python -m unittest`
- `shellcheck trim-history.sh` 必须零警告
- 新脚本需 `chmod +x`（仓库所有 `.sh` 均可执行）

## 测试运行方式

```bash
# 全部测试
venv/bin/python -m unittest discover -s tests -v

# 单个测试
venv/bin/python -m unittest tests.test_trim_history.PreflightTest.test_below_threshold_exits_zero -v
```

现有 17 个测试必须始终保持通过。

---

### Task 1: 脚本骨架 —— 参数解析、前置检查、阈值判断

这一步交付一个「永远只会跳过」的脚本：能解析参数、拒绝不安全的仓库状态、在提交数不足时干净退出。不含任何历史重写逻辑。

**Files:**
- Create: `trim-history.sh`
- Test: `tests/test_trim_history.py`

**Interfaces:**
- Produces: 命令行接口 `trim-history.sh [--threshold N] [--keep-days D] [--dry-run] <repo-dir>`；退出码 0 = 无需动作或成功，非 0 = 中止（调用方按告警处理，不影响已完成的推送）
- Produces: 测试夹具函数 `make_repo(base, count, oldest_days, newest_days=0) -> (work, remote)`、`run_script(repo, *args) -> CompletedProcess`、`git(repo, *args) -> CompletedProcess`、`head(repo) -> str`、`count_commits(repo) -> int`、`tree_of(repo, rev) -> str`，供 Task 2、Task 3 复用

- [ ] **Step 1: 写测试文件（含夹具与第一批失败测试）**

创建 `tests/test_trim_history.py`：

```python
"""trim-history.sh 的行为测试。

每个测试都建一个真实的本地 bare 远端 + 工作区克隆作为夹具，
用 GIT_CONFIG_GLOBAL=/dev/null 模拟 CI 中没有全局 git 身份的环境。
"""

import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "trim-history.sh"

# 干净的 git 环境：不读用户全局/系统配置，确保脚本自带身份
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
}

# 夹具提交用的身份，与被测脚本自带的身份无关
FIXTURE_ID = ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.com"]


def git(repo, *args, check=True, env=None):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=check,
        env={**GIT_ENV, **(env or {})},
    )


def make_repo(base: Path, count: int, oldest_days: float, newest_days: float = 0):
    """建立 bare 远端 + 工作区克隆，生成 count 个提交。

    最老的提交在 oldest_days 天前，最新的在 newest_days 天前，时间均匀分布。
    返回 (工作区路径, 远端路径)。
    """
    remote = base / "remote.git"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(remote)],
        check=True,
        capture_output=True,
        env=GIT_ENV,
    )
    work = base / "work"
    subprocess.run(
        ["git", "clone", str(remote), str(work)],
        check=True,
        capture_output=True,
        env=GIT_ENV,
    )

    now = datetime.now(timezone.utc)
    span = oldest_days - newest_days
    for i in range(count):
        age = newest_days + span * (count - 1 - i) / max(count - 1, 1)
        stamp = (now - timedelta(days=age)).isoformat()
        (work / "payload.txt").write_text(f"commit {i}\n")
        git(work, "add", ".")
        git(
            work,
            *FIXTURE_ID,
            "commit",
            "-m",
            f"c{i}",
            env={"GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp},
        )
    git(work, "push", "-q", "origin", "main")
    return work, remote


def run_script(repo, *args):
    return subprocess.run(
        ["bash", str(SCRIPT), *args, str(repo)],
        capture_output=True,
        text=True,
        env=GIT_ENV,
    )


def head(repo, rev="main"):
    return git(repo, "rev-parse", rev).stdout.strip()


def count_commits(repo, rev="main"):
    return int(git(repo, "rev-list", "--count", rev).stdout.strip())


def tree_of(repo, rev="main"):
    return git(repo, "rev-parse", f"{rev}^{{tree}}").stdout.strip()


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_below_threshold_exits_zero(self):
        work, _ = make_repo(self.base, count=10, oldest_days=60)
        before = head(work)
        result = run_script(work, "--threshold", "250")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("跳过", result.stdout)
        self.assertEqual(head(work), before)

    def test_dirty_worktree_aborts(self):
        work, _ = make_repo(self.base, count=10, oldest_days=60)
        before = head(work)
        (work / "payload.txt").write_text("dirty\n")
        result = run_script(work, "--threshold", "5")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("工作区", result.stderr)
        self.assertEqual(head(work), before)

    def test_ahead_of_remote_aborts(self):
        work, _ = make_repo(self.base, count=10, oldest_days=60)
        (work / "payload.txt").write_text("local only\n")
        git(work, "add", ".")
        git(work, *FIXTURE_ID, "commit", "-m", "unpushed")
        before = head(work)
        result = run_script(work, "--threshold", "5")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("同步", result.stderr)
        self.assertEqual(head(work), before)

    def test_missing_repo_argument_aborts(self):
        result = subprocess.run(
            ["bash", str(SCRIPT)], capture_output=True, text=True, env=GIT_ENV
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("用法", result.stderr)

    def test_not_a_git_repo_aborts(self):
        plain = self.base / "plain"
        plain.mkdir()
        result = run_script(plain)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行测试确认失败**

Run: `venv/bin/python -m unittest tests.test_trim_history -v`
Expected: 5 个测试全部 FAIL（`trim-history.sh` 不存在，bash 报 `No such file or directory`，退出码 127）

- [ ] **Step 3: 写脚本骨架**

创建 `trim-history.sh`：

```bash
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
((ahead == 0 && behind == 0)) || die "与 origin/$BRANCH 不同步（领先 $ahead，落后 $behind）"

# ---- ② 阈值判断 ----
count=$(g rev-list --count "$BRANCH")
if ((count < THRESHOLD)); then
    echo "提交数 $count 未达阈值 $THRESHOLD，跳过精简"
    exit 0
fi
```

- [ ] **Step 4: 赋予可执行权限并运行 shellcheck**

```bash
chmod +x trim-history.sh
shellcheck trim-history.sh
```
Expected: 无输出（零警告）

- [ ] **Step 5: 运行测试确认通过**

Run: `venv/bin/python -m unittest tests.test_trim_history -v`
Expected: 5 个测试全部 PASS

- [ ] **Step 6: 确认现有测试未受影响**

Run: `venv/bin/python -m unittest discover -s tests -v 2>&1 | tail -3`
Expected: `Ran 22 tests` / `OK`

- [ ] **Step 7: 提交**

```bash
git add trim-history.sh tests/test_trim_history.py
git commit -m "Add trim-history.sh skeleton with preflight checks"
```

---

### Task 2: 基线定位与 --dry-run

在骨架之上加入「哪些提交要保留、哪个提交作为新根」的计算，以及两个边界的提前退出。`--dry-run` 把计算结果打印出来但不做改动，这是后续任何真实改动的观察窗口。

**Files:**
- Modify: `trim-history.sh`（在 Task 1 的 ② 阈值判断之后追加）
- Modify: `tests/test_trim_history.py`（追加 `BaselineTest`）

**Interfaces:**
- Consumes: Task 1 的 `g()` 函数、`$THRESHOLD` / `$KEEP_DAYS` / `$DRY_RUN` / `$BRANCH` 变量、`die()`
- Produces: shell 变量 `oldest_keep`（窗口内最老提交）、`base`（其父提交，作为新根的树来源）、`keep_count`（窗口内提交数）、`old_head`，供 Task 3 使用

- [ ] **Step 1: 写失败测试**

在 `tests/test_trim_history.py` 的 `PreflightTest` 之后追加：

```python
class BaselineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_dry_run_reports_plan_and_changes_nothing(self):
        # 20 个提交跨 60 天，30 天窗口内约有一半
        work, remote = make_repo(self.base, count=20, oldest_days=60)
        before_head = head(work)
        before_remote = head(remote)
        result = run_script(work, "--threshold", "5", "--keep-days", "30", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("当前提交数: 20", result.stdout)
        self.assertIn("保留", result.stdout)
        self.assertIn("削减", result.stdout)
        # dry-run 不得改动本地或远端
        self.assertEqual(head(work), before_head)
        self.assertEqual(head(remote), before_remote)
        self.assertEqual(count_commits(work), 20)

    def test_all_commits_within_window_skips(self):
        # 全部提交都在 10 天内，30 天窗口无可裁剪
        work, _ = make_repo(self.base, count=20, oldest_days=10)
        before = head(work)
        result = run_script(work, "--threshold", "5", "--keep-days", "30")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("无可裁剪", result.stdout)
        self.assertEqual(head(work), before)

    def test_no_commits_within_window_skips(self):
        # 全部提交都在 100~200 天前，30 天窗口内一个都没有
        work, _ = make_repo(self.base, count=20, oldest_days=200, newest_days=100)
        before = head(work)
        result = run_script(work, "--threshold", "5", "--keep-days", "30")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("无提交", result.stdout)
        self.assertEqual(head(work), before)
```

- [ ] **Step 2: 运行测试确认失败**

Run: `venv/bin/python -m unittest tests.test_trim_history.BaselineTest -v`
Expected: 3 个 FAIL。`test_dry_run_...` 因输出里没有 "当前提交数: 20" 而失败；另两个因输出里没有 "无可裁剪" / "无提交" 而失败（脚本此时在阈值判断后就直接结束了）

- [ ] **Step 3: 追加基线定位与 dry-run 输出**

在 `trim-history.sh` 末尾追加：

```bash
# ---- ③ 定位基线 ----
# 注意：git rev-list --since 过滤的是提交者日期（committer date），
# 重放时用 --committer-date-is-author-date 保证两者一致，窗口语义才稳定。
oldest_keep=$(g rev-list --since="$KEEP_DAYS days ago" "$BRANCH" | tail -1)
if [[ -z $oldest_keep ]]; then
    echo "最近 $KEEP_DAYS 天内无提交，跳过精简"
    exit 0
fi

if ! base=$(g rev-parse --verify --quiet "$oldest_keep^"); then
    echo "全部提交都在最近 $KEEP_DAYS 天内，无可裁剪，跳过精简"
    exit 0
fi

keep_count=$(g rev-list --count "$base..$BRANCH")
old_head=$(g rev-parse "$BRANCH")

echo "当前提交数: $count"
echo "保留最近 $KEEP_DAYS 天的 $keep_count 个提交 + 1 个新根提交"
echo "削减: $((count - keep_count - 1)) 个提交"
echo "基线提交: $(g log -1 --format='%h %ad %s' --date=short "$base")"

if $DRY_RUN; then
    echo "(--dry-run) 未执行任何改动。"
    exit 0
fi
```

- [ ] **Step 4: 运行测试确认通过**

Run: `venv/bin/python -m unittest tests.test_trim_history -v`
Expected: 8 个测试全部 PASS

注：非 dry-run 的两个边界测试之所以此时就通过，是因为它们在真实重写逻辑之前就退出了；`test_dry_run_...` 之外没有别的测试会走到脚本末尾。

- [ ] **Step 5: shellcheck**

Run: `shellcheck trim-history.sh`
Expected: 无输出

- [ ] **Step 6: 提交**

```bash
git add trim-history.sh tests/test_trim_history.py
git commit -m "Add baseline detection and dry-run output to trim-history.sh"
```

---

### Task 3: 历史重写、护栏校验与强制推送

核心逻辑。在临时分支上重放，通过两道校验后才让 `main` 指向新历史并推送，任何失败都回滚。

**Files:**
- Modify: `trim-history.sh`（在 Task 2 的 dry-run 出口之后追加）
- Modify: `tests/test_trim_history.py`（追加 `TrimTest`）

**Interfaces:**
- Consumes: Task 2 产出的 `base`、`keep_count`、`old_head`、`count`，Task 1 的 `g()`、`die()`、`$BRANCH`
- Produces: 无（终端行为）

- [ ] **Step 1: 写失败测试**

在 `tests/test_trim_history.py` 末尾（`if __name__` 之前）追加：

```python
class TrimTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        # 20 个提交跨 60 天，30 天窗口内约 10 个
        self.work, self.remote = make_repo(self.base, count=20, oldest_days=60)
        self.before_tree = tree_of(self.work)
        self.expected_keep = len(
            git(self.work, "rev-list", "--since=30 days ago", "main")
            .stdout.strip()
            .splitlines()
        )

    def trim(self):
        result = run_script(self.work, "--threshold", "5", "--keep-days", "30")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_history_is_rebuilt_to_expected_length(self):
        self.trim()
        self.assertEqual(count_commits(self.work), self.expected_keep + 1)

    def test_worktree_content_is_identical(self):
        self.trim()
        self.assertEqual(tree_of(self.work), self.before_tree)

    def test_root_commit_is_orphan_with_fixed_message(self):
        self.trim()
        root = git(self.work, "rev-list", "--max-parents=0", "main").stdout.strip()
        self.assertEqual(len(root.splitlines()), 1)
        msg = git(self.work, "log", "-1", "--format=%s", root).stdout.strip()
        self.assertEqual(msg, "Initial commit")

    def test_remote_is_force_updated(self):
        self.trim()
        self.assertEqual(head(self.remote), head(self.work))
        fresh = self.base / "fresh"
        subprocess.run(
            ["git", "clone", "-q", str(self.remote), str(fresh)],
            check=True,
            capture_output=True,
            env=GIT_ENV,
        )
        self.assertEqual(count_commits(fresh), self.expected_keep + 1)
        self.assertEqual(tree_of(fresh), self.before_tree)

    def test_committer_dates_match_author_dates(self):
        # 保证窗口语义在多轮精简后依然稳定
        self.trim()
        pairs = git(
            self.work, "log", "--format=%aI %cI", "main"
        ).stdout.strip().splitlines()
        for line in pairs:
            author, committer = line.split()
            self.assertEqual(author, committer, f"日期不一致: {line}")

    def test_original_author_dates_are_preserved(self):
        before = git(
            self.work, "log", "--format=%aI", "--since=30 days ago", "main"
        ).stdout.strip().splitlines()
        self.trim()
        after = git(
            self.work, "log", "--format=%aI", "main"
        ).stdout.strip().splitlines()
        # after 比 before 多一个新根提交
        self.assertEqual(after[: len(before)], before)

    def test_no_leftover_temp_branch(self):
        self.trim()
        branches = git(self.work, "branch", "--format=%(refname:short)").stdout.split()
        self.assertEqual(branches, ["main"])

    def test_works_without_configured_git_identity(self):
        # 夹具从未写入 user.name/user.email，全局配置也被屏蔽
        probe = git(self.work, "config", "--get", "user.name", check=False)
        self.assertNotEqual(probe.returncode, 0, "夹具不应配置 user.name")
        self.trim()
        author = git(self.work, "log", "-1", "--format=%an", "main").stdout.strip()
        self.assertEqual(author, "github-actions[bot]")
```

- [ ] **Step 2: 运行测试确认失败**

Run: `venv/bin/python -m unittest tests.test_trim_history.TrimTest -v`
Expected: 8 个 FAIL —— 脚本在 dry-run 出口之后就结束了，`main` 仍是 20 个提交，`count_commits` 断言失败

- [ ] **Step 3: 追加重写逻辑**

在 `trim-history.sh` 末尾追加：

```bash
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

if ! g diff --quiet "$old_head" "$new_head"; then
    rollback
    die "内容校验失败：新旧历史的工作树不一致，已回滚"
fi

if ((new_count != keep_count + 1)); then
    rollback
    die "提交数校验失败：期望 $((keep_count + 1)) 个，实际 $new_count 个，已回滚"
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

# ---- ⑧ 本地瘦身 ----
# 这会丢弃本地 reflog 中的旧历史。此时推送已成功且内容校验已通过，
# 旧历史没有保留价值，回收磁盘才是目的。
g reflog expire --expire=now --all
g gc --prune=now --quiet

echo "精简完成: $count -> $new_count 个提交，已强制推送到 origin/$BRANCH"
```

- [ ] **Step 4: 运行测试确认通过**

Run: `venv/bin/python -m unittest tests.test_trim_history -v`
Expected: 16 个测试全部 PASS

- [ ] **Step 5: shellcheck**

Run: `shellcheck trim-history.sh`
Expected: 无输出

- [ ] **Step 6: 对真实 private 仓库跑 dry-run 冒烟测试**

```bash
./trim-history.sh --dry-run private
```
Expected: 输出 `提交数 22 未达阈值 250，跳过精简`，退出码 0，`git -C private log --oneline | wc -l` 仍为 22

```bash
./trim-history.sh --dry-run --threshold 5 --keep-days 3 private
```
Expected: 打印当前提交数、保留数、削减数与基线提交，末行 `(--dry-run) 未执行任何改动。`，`private` 的 HEAD 不变

- [ ] **Step 7: 确认现有测试未受影响**

Run: `venv/bin/python -m unittest discover -s tests -v 2>&1 | tail -3`
Expected: `Ran 33 tests` / `OK`

- [ ] **Step 8: 提交**

```bash
git add trim-history.sh tests/test_trim_history.py
git commit -m "Implement history rewrite, guard checks and force push in trim-history.sh"
```

---

### Task 4: 接入 build-all.sh 与 CI

把脚本挂到两个调用点。精简只在 `private` 确实产生新提交并推送成功后执行。

**Files:**
- Modify: `build-all.sh`（「提交 private」代码块，约在「提交主仓库」之前）
- Modify: `.github/workflows/build.yaml:122-125`（`Commit and Push (private)` 步骤）

**Interfaces:**
- Consumes: Task 1-3 完成的 `trim-history.sh` 命令行接口

- [ ] **Step 1: 修改 build-all.sh**

把「提交 private」代码块改成：

```bash
# ---- Commit and Push (private) ----
echo ">>> 提交 private"
(
    cd "$PRIVATE_DIR"
    if [[ -n $(git status --porcelain) ]]; then
        git add .
        git commit -m "Update config"
        git push
        echo ">>> 检查 private 历史体积"
        "$BIN/trim-history.sh" "$PRIVATE_DIR" || echo "  private: 历史精简跳过或失败（不影响构建）"
    else
        echo "  private: 无变更"
    fi
)
```

注：`trim-history.sh` 内部用 `git -C "$REPO"`，不依赖调用时的工作目录，所以在子 shell 的 `cd` 之后调用也安全。失败时用 `||` 吞掉退出码，与脚本 `set -e` 共存，保证精简失败不会中断后续的主仓库提交与 Release。

- [ ] **Step 2: 验证 build-all.sh 语法与 shellcheck**

```bash
bash -n build-all.sh
shellcheck build-all.sh
```
Expected: 两条命令均无输出。`build-all.sh` 修改前的 shellcheck 基线是干净的（已确认），所以修改后必须保持零告警。

- [ ] **Step 3: 修改 CI workflow**

把 `.github/workflows/build.yaml` 中的 private 推送步骤改为：

```yaml
      - name: Commit and Push (private)
        id: commit_push_private
        continue-on-error: true
        run: ../commit-and-push.sh "Update config"
        working-directory: private

      - name: Trim private history
        if: steps.commit_push_private.outcome == 'success'
        continue-on-error: true
        run: ./trim-history.sh private
```

`Trim private history` 步骤在仓库根目录运行（不设 `working-directory`），与 `Build rule sets` 等步骤一致。

- [ ] **Step 4: 校验 workflow YAML 合法**

```bash
yq '.jobs.*.steps[] | select(.name == "Trim private history")' .github/workflows/build.yaml
```
Expected: 输出该步骤的完整 YAML，包含 `if: steps.commit_push_private.outcome == 'success'`

```bash
yq '.jobs.*.steps[] | select(.id == "commit_push_private") | .name' .github/workflows/build.yaml
```
Expected: `Commit and Push (private)`

- [ ] **Step 5: 提交**

```bash
git add build-all.sh .github/workflows/build.yaml
git commit -m "Wire trim-history.sh into build-all.sh and CI"
```

- [ ] **Step 6: 更新 CLAUDE.md 脚本表**

在「关键脚本」表格中 `commit-and-push.sh` 一行之后插入：

```markdown
| `trim-history.sh [--threshold N] [--keep-days D] [--dry-run] <dir>` | 提交数超阈值时精简 git 历史并强制推送（默认 250 提交 / 保留 30 天） |
```

- [ ] **Step 7: 提交文档更新**

```bash
git add CLAUDE.md
git commit -m "Document trim-history.sh in CLAUDE.md"
```

---

## 完成后的验收

```bash
venv/bin/python -m unittest discover -s tests -v 2>&1 | tail -3
shellcheck trim-history.sh build-all.sh
./trim-history.sh --dry-run private
```

预期：33 个测试通过；shellcheck 零新增告警；对真实 `private` 的 dry-run 报告「未达阈值，跳过精简」。

首次真实触发预计在约 76 天后（当前 22 提交，约 3 提交/天）。届时应人工确认一次 CI 日志中的 `精简完成: N -> M 个提交`，并观察 Gitee 仓库容量是否随之下降——服务端 GC 行为是本方案唯一无法从客户端验证的环节。
