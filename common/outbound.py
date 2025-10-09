"""
代理服务器出口国家检测工具

该模块提供了通过 sing-box 代理服务器检测出口 IP 所在国家的功能。
"""

import atexit
import json
import socket
import subprocess
import time

import requests


def get_available_port() -> int:
    """获取一个可用的本地端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float = 10.0) -> bool:
    """
    等待指定端口可用

    Args:
        port: 要检查的端口
        timeout: 超时时间（秒）

    Returns:
        端口是否在超时时间内变为可用
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                s.connect(("127.0.0.1", port))
                time.sleep(0.1)
                return True
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(0.1)
    return False


def get_country(port: int) -> str:
    response = requests.get(
        "https://ipinfo.io",
        proxies={
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        },
        timeout=10,
        verify=True,
    )
    response.raise_for_status()

    data = response.json()
    return data.get("country")


def find_country(outbound: dict, log_level: str = "warn") -> str:
    """
    通过 sing-box 代理检测出口 IP 的国家代码

    Args:
        outbound: sing-box outbound 配置
        log_level: sing-box 日志级别

    Returns:
        两字母的国家代码，如果失败则返回 None

    Raises:
        Exception: 当检测过程中发生错误时
    """
    port = get_available_port()
    process = None

    # 构建 sing-box 配置
    config = {
        "log": {"level": log_level},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound],
    }

    cleanup = None
    try:
        # 启动 sing-box 进程
        process = subprocess.Popen(
            ["sing-box", "run", "-c", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,  # 忽略标准输出
            stderr=None,  # 继承父进程的标准错误
            text=True,
        )

        # 注册清理函数
        def cleanup():
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        atexit.register(cleanup)

        # 发送配置到 sing-box
        process.stdin.write(json.dumps(config))
        process.stdin.close()

        # 等待 sing-box 启动
        if not wait_for_port(port):
            raise TimeoutError(f"sing-box failed to start on port {port}")

        # 通过代理请求 ipinfo.io
        return get_country(port)

    finally:
        if cleanup:
            cleanup()
            atexit.unregister(cleanup)


# noinspection PyBroadException
def safe_find_country(outbound: dict, log_level: str = "warn") -> str | None:
    try:
        return find_country(outbound, log_level)
    except Exception:
        return None
