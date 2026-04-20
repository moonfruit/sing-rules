#!/usr/bin/env python
"""
生成 config.json 的副本，但移除 route.rules[] 数组中的前三个元素，
以及 Block 相关的规则和 rule_set 引用
"""

import json
import sys
from enum import Enum


class Action(Enum):
    REMOVE = 1
    REPLACED = 2
    KEEP = 3


def main():
    config = json.load(sys.stdin)

    if "route" in config:
        route = config["route"]
        if "rules" in route:
            rules = []
            for rule in route["rules"][3:]:
                action, value = _is_block_rule(rule)
                if action == Action.REMOVE:
                    continue
                if action == Action.REPLACED:
                    rule["rule_set"] = value
                rules.append(rule)
            route["rules"] = rules

        if "rule_set" in route:
            route["rule_set"] = [rs for rs in route["rule_set"] if rs.get("tag") != "Block"]

    json.dump(config, sys.stdout, ensure_ascii=False, indent=2)
    print()


def _is_block_rule(rule) -> tuple[Action, list[str] | None]:
    """检查规则是否应完全移除或需要从中删除 Block"""
    rs = rule.get("rule_set")
    if rs == "Block":
        return Action.REMOVE, None
    if isinstance(rs, list):
        if rs == ["Block"]:
            return Action.REMOVE, None
        if "Block" in rs:
            return Action.REPLACED, [x for x in rs if x != "Block"]
    return Action.KEEP, None


if __name__ == "__main__":
    main()
