#!/usr/bin/env python
"""
生成 config.json 的副本，但移除 route.rules[] 数组中的前三个元素，
以及 Block 相关的规则和 rule_set 引用，并移除 outbounds 中的 "全球拦截"。

同时裁剪 outbound：
  1. 删除以 '👍' / '🛢️' 结尾的 outbound 及其引用
  2. 删除白名单以外的 urltest outbound 及其引用
     (白名单: 自动选择 / 省流节点 / 高级节点 / 自然选择 / 以 🎬 结尾)
  3. 剩余 urltest 中 interval < 3m 时移除该字段
"""

import json
import re
import sys
from enum import Enum
from typing import Any

from common.config import remove_outbounds

BLOCK_OUTBOUND = "全球拦截"

PRUNE_SUFFIXES = ("👍", "🛢️")

URLTEST_KEEP_KEYWORDS = ("自动选择", "省流节点", "高级节点", "自然选择")
URLTEST_KEEP_SUFFIX = "🎬"

INTERVAL_THRESHOLD_SECONDS = 180


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


def _block_outbound_tags(outbounds) -> set[str]:
    return {
        ob["tag"]
        for ob in outbounds
        if isinstance(ob.get("tag"), str) and BLOCK_OUTBOUND in ob["tag"]
    }


def _suffix_outbound_tags(outbounds) -> set[str]:
    return {
        ob["tag"]
        for ob in outbounds
        if isinstance(ob.get("tag"), str) and ob["tag"].endswith(PRUNE_SUFFIXES)
    }


def _is_kept_urltest(tag: str) -> bool:
    if tag.endswith(URLTEST_KEEP_SUFFIX):
        return True
    return any(kw in tag for kw in URLTEST_KEEP_KEYWORDS)


def _urltest_tags_to_remove(outbounds) -> set[str]:
    return {
        ob["tag"]
        for ob in outbounds
        if ob.get("type") == "urltest"
        and isinstance(ob.get("tag"), str)
        and not _is_kept_urltest(ob["tag"])
    }


_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([a-zµμ]+)")
_UNIT_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "μs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}


def _parse_duration_seconds(value: Any) -> float | None:
    """解析 Go time.Duration 风格字符串，失败返回 None。"""
    if not isinstance(value, str) or not value:
        return None
    total = 0.0
    pos = 0
    for m in _DURATION_RE.finditer(value):
        if m.start() != pos:
            return None
        unit = m.group(2)
        if unit not in _UNIT_SECONDS:
            return None
        total += float(m.group(1)) * _UNIT_SECONDS[unit]
        pos = m.end()
    if pos != len(value):
        return None
    return total


def _trim_short_intervals(outbounds, threshold_seconds: float) -> None:
    for ob in outbounds:
        if ob.get("type") != "urltest":
            continue
        seconds = _parse_duration_seconds(ob.get("interval"))
        if seconds is not None and seconds < threshold_seconds:
            ob.pop("interval", None)


def main():
    config = json.load(sys.stdin)

    if "route" in config:
        route = config["route"]
        if "rules" in route:
            route["rules"] = filter_rules(route["rules"][3:])
        if "rule_set" in route:
            route["rule_set"] = filter_rule_sets(route["rule_set"])

    outbounds = config.get("outbounds")
    if isinstance(outbounds, list):
        tags_to_remove = (
            _block_outbound_tags(outbounds)
            | _suffix_outbound_tags(outbounds)
            | _urltest_tags_to_remove(outbounds)
        )
        remove_outbounds(config, tags_to_remove)
        _trim_short_intervals(config["outbounds"], INTERVAL_THRESHOLD_SECONDS)

    json.dump(config, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
