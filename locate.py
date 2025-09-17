#!/usr/bin/env python3
import json
import sys

from common.outbound import find_country


def main():
    """命令行入口函数"""
    # 从标准输入读取 outbound 配置
    outbound = sys.stdin.read()
    if not outbound.strip():
        raise ValueError("No outbound provided")

    outbound_config = json.loads(outbound)

    # 检测国家代码
    country = find_country(outbound_config)

    if country:
        # 只输出国家代码到标准输出
        print(country)
        sys.exit(0)
    else:
        # 失败时不输出任何内容
        sys.exit(1)


if __name__ == "__main__":
    main()
