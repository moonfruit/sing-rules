#!/usr/bin/env python
"""
生成 config.json 的副本，但移除 route.rules[] 数组中的前三个元素，
以及 Block 相关的规则和 rule_set 引用，并移除 outbounds 中的 "全球拦截"。
"""

import json
import sys
from enum import Enum
from typing import Any

BLOCK_OUTBOUND = "全球拦截"


class Action(Enum):
    REMOVE = 1
    REPLACED = 2
    KEEP = 3


def filter_rules(rules) -> list[Any]:
    filtered = []
    for rule in rules:
        action, value = _is_block_rule(rule)
        if action == Action.REMOVE:
            continue
        if action == Action.REPLACED:
            rule["rule_set"] = value
        filtered.append(rule)
    return filtered


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


def filter_rule_sets(rule_sets) -> list[Any]:
    filtered = []
    for rs in rule_sets:
        if rs.get("tag") == "Block":
            continue
        rs.pop("download_detour", None)
        filtered.append(rs)
    return filtered


def _is_block_outbound(tag) -> bool:
    return isinstance(tag, str) and BLOCK_OUTBOUND in tag


def filter_outbounds(outbounds) -> list[Any]:
    filtered = []
    for ob in outbounds:
        if _is_block_outbound(ob.get("tag")):
            continue
        if isinstance(ob.get("outbounds"), list):
            ob["outbounds"] = [
                t for t in ob["outbounds"] if not _is_block_outbound(t)
            ]
        filtered.append(ob)
    return filtered


def main():
    config = json.load(sys.stdin)

    if "route" in config:
        route = config["route"]
        if "rules" in route:
            route["rules"] = filter_rules(route["rules"][3:])
        if "rule_set" in route:
            route["rule_set"] = filter_rule_sets(route["rule_set"])

    if "outbounds" in config:
        config["outbounds"] = filter_outbounds(config["outbounds"])

    json.dump(config, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
