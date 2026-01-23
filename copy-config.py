#!/usr/bin/env python
"""
生成 config.json 的副本，但移除 route.rules[] 数组中的前三个元素
"""

import json
import sys


def main():
    config = json.load(sys.stdin)

    if "route" in config and "rules" in config["route"]:
        config["route"]["rules"] = config["route"]["rules"][3:]

    json.dump(config, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
