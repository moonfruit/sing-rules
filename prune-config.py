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
  5. 计算所有 outbound 的可达集合（route.rules.outbound / route.final /
     dns.servers[].detour 作为根，沿 selector/urltest 的 outbounds 字段做闭包），
     删除不可达的 outbound，并清理残留引用
"""

from __future__ import annotations

import json
import sys

from common.config import remove_outbounds

KEEP_OUTBOUND_KEYWORDS = ("NanoCloud", "Ash")

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

    # Pass 1: 标记引用被删 rule_set 的规则
    removed_outbounds: set[str] = set()
    rules = route.get("rules", []) or []
    pass1_remove = [False] * len(rules)
    for i, r in enumerate(rules):
        if isinstance(r, dict) and rule_refs_any(r, removed_set_tags):
            ob = r.get("outbound")
            if isinstance(ob, str):
                removed_outbounds.add(ob)
            pass1_remove[i] = True

    # Pass 2: 级联移除——outbound 命中 removed_outbounds 且规则未引用任何保留的 rule_set
    removed_flags = list(pass1_remove)
    for i, r in enumerate(rules):
        if removed_flags[i] or not isinstance(r, dict):
            continue
        ob = r.get("outbound")
        if (
            isinstance(ob, str)
            and ob in removed_outbounds
            and not rule_refs_any(r, kept_set_tags)
        ):
            removed_flags[i] = True

    removed_rules = [r for r, rm in zip(rules, removed_flags) if rm]
    after_pass2 = [r for r, rm in zip(rules, removed_flags) if not rm]
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

    remove_outbounds(config, outbounds_to_remove)

    # Pass 3: 基于规则/route.final/dns detour 做可达性分析，剔除孤立 outbound
    roots: set[str] = set()
    for r in after_pass2:
        if isinstance(r, dict):
            ob = r.get("outbound")
            if isinstance(ob, str):
                roots.add(ob)
    final_ob = route.get("final")
    if isinstance(final_ob, str):
        roots.add(final_ob)
    for srv in (config.get("dns", {}) or {}).get("servers", []) or []:
        if isinstance(srv, dict):
            detour = srv.get("detour")
            if isinstance(detour, str):
                roots.add(detour)

    by_tag = {
        o["tag"]: o
        for o in config["outbounds"]
        if isinstance(o, dict) and isinstance(o.get("tag"), str)
    }
    reachable: set[str] = set()
    stack = [t for t in roots if t in by_tag]
    while stack:
        tag = stack.pop()
        if tag in reachable:
            continue
        reachable.add(tag)
        node = by_tag.get(tag)
        if not node:
            continue
        for child in node.get("outbounds", []) or []:
            if isinstance(child, str) and child not in reachable and child in by_tag:
                stack.append(child)

    orphan_outbounds = {
        tag
        for tag in by_tag
        if tag not in reachable
        and not any(kw in tag for kw in KEEP_OUTBOUND_KEYWORDS)
    }
    remove_outbounds(config, orphan_outbounds)

    print("Removed rule_sets:", ", ".join(removed_sets) or "(none)", file=sys.stderr)
    print(f"Removed rules ({len(removed_rules)}):", file=sys.stderr)
    for r in removed_rules:
        print(json.dumps(r, ensure_ascii=False), file=sys.stderr)
    print(
        "Removed outbounds:",
        ", ".join(sorted(outbounds_to_remove)) or "(none)",
        file=sys.stderr,
    )
    print(
        "Removed orphan outbounds:",
        ", ".join(sorted(orphan_outbounds)) or "(none)",
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
