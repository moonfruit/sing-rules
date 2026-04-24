#!/usr/bin/env python
"""从标准输入读取 sing-box 配置 JSON，裁剪 rule_set / rules / outbounds 后写入标准输出。

保留的 rule_set:
  GeoSites@!CN, Lan, FakeIpBypass, Direct, GFW, GeoIP@CN, GeoSites@CN, Private, Proxy

处理流程:
  1. 仅保留白名单中的 rule_set，记录被移除的 rule_set
  2. 扫描 route.rules：凡引用被移除 rule_set 的顶层规则一并删除，记录这些规则的 outbound
  3. 再扫描 route.rules：若规则的 outbound 落在记录集合中且该规则未引用保留的 rule_set，
     则同样删除（清理 AI/ChatGPT 这类依附出口的探测规则）
  4. 基于最终剩余规则重新统计引用，从 outbounds 中删除不再被引用的目标出口；
     同时清理其他 selector/urltest 的 outbounds 引用
"""

from __future__ import annotations

import json
import sys

KEEP_RULE_SETS = {
    "GeoSites@!CN",
    "Lan",
    "FakeIpBypass",
    "Direct",
    "GFW",
    "GeoIP@CN",
    "GeoSites@CN",
    "Private",
    "Proxy",
}


def rule_set_tags(rule: dict) -> list[str]:
    rs = rule.get("rule_set")
    if isinstance(rs, str):
        return [rs]
    if isinstance(rs, list):
        return [x for x in rs if isinstance(x, str)]
    return []


def rule_refs_any(rule: dict, targets: set[str]) -> bool:
    if any(t in targets for t in rule_set_tags(rule)):
        return True
    for nested in rule.get("rules", []) or []:
        if isinstance(nested, dict) and rule_refs_any(nested, targets):
            return True
    return False


def main() -> None:
    config = json.load(sys.stdin)

    route = config.get("route", {})
    rule_sets = route.get("rule_set", []) or []
    kept_sets = [rs for rs in rule_sets if rs.get("tag") in KEEP_RULE_SETS]
    removed_sets = sorted(
        {rs.get("tag") for rs in rule_sets if rs.get("tag") not in KEEP_RULE_SETS}
    )
    route["rule_set"] = kept_sets
    removed_set_tags = set(removed_sets)
    kept_set_tags = set(KEEP_RULE_SETS)

    # Pass 1: 移除引用被删 rule_set 的规则
    removed_outbounds: set[str] = set()
    rules = route.get("rules", []) or []
    after_pass1 = []
    for r in rules:
        if isinstance(r, dict) and rule_refs_any(r, removed_set_tags):
            ob = r.get("outbound")
            if isinstance(ob, str):
                removed_outbounds.add(ob)
            continue
        after_pass1.append(r)

    # Pass 2: 级联移除——outbound 命中 removed_outbounds 且规则未引用任何保留的 rule_set
    after_pass2 = []
    cascaded = 0
    for r in after_pass1:
        if isinstance(r, dict):
            ob = r.get("outbound")
            if (
                isinstance(ob, str)
                and ob in removed_outbounds
                and not rule_refs_any(r, kept_set_tags)
            ):
                cascaded += 1
                continue
        after_pass2.append(r)
    route["rules"] = after_pass2

    # 基于最终剩余规则，决定哪些 outbound 可以真正删除
    still_referenced: set[str] = set()

    def collect_refs(items: list) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            target = item.get("outbound")
            if isinstance(target, str):
                still_referenced.add(target)
            if isinstance(item.get("rules"), list):
                collect_refs(item["rules"])

    collect_refs(after_pass2)
    outbounds_to_remove = removed_outbounds - still_referenced

    outbounds = config.get("outbounds", []) or []
    config["outbounds"] = [
        o for o in outbounds if o.get("tag") not in outbounds_to_remove
    ]
    for o in config["outbounds"]:
        if isinstance(o.get("outbounds"), list):
            o["outbounds"] = [
                t for t in o["outbounds"] if t not in outbounds_to_remove
            ]

    print("Removed rule_sets:", ", ".join(removed_sets) or "(none)", file=sys.stderr)
    print(
        f"Cascade removed rules (outbound 命中移除集且未引用保留 rule_set): {cascaded}",
        file=sys.stderr,
    )
    print(
        "Removed outbounds:",
        ", ".join(sorted(outbounds_to_remove)) or "(none)",
        file=sys.stderr,
    )
    kept_but_shared = removed_outbounds & still_referenced
    if kept_but_shared:
        print(
            "Kept (still referenced by kept rules):",
            ", ".join(sorted(kept_but_shared)),
            file=sys.stderr,
        )

    json.dump(config, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
