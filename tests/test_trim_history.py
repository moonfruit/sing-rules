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
        encoding="utf-8",
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
        encoding="utf-8",
        env=GIT_ENV,
    )
    work = base / "work"
    subprocess.run(
        ["git", "clone", str(remote), str(work)],
        check=True,
        capture_output=True,
        encoding="utf-8",
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
    git(work, "push", "-q", "origin", "main", check=True)
    return work, remote


def run_script(repo, *args):
    result = subprocess.run(
        ["bash", str(SCRIPT), *args, str(repo)],
        capture_output=True,
        env=GIT_ENV,
    )
    # Decode manually with surrogateescape to handle any encoding issues
    return subprocess.CompletedProcess(
        args=result.args,
        returncode=result.returncode,
        stdout=result.stdout.decode("utf-8", errors="surrogateescape"),
        stderr=result.stderr.decode("utf-8", errors="surrogateescape"),
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
            ["bash", str(SCRIPT)], capture_output=True, text=True, encoding="utf-8", env=GIT_ENV
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
