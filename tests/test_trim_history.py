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


if __name__ == "__main__":
    unittest.main()
