"""sing-box 配置 dict 操作工具。"""

from collections.abc import Iterable


def generated_node_group_tags(outbounds: list[dict]) -> set[str]:
    """识别生成器的测速分组，兼容单节点 selector 和原有 urltest。"""
    # 地区和订阅组都挂在默认出口下。手动切换、自由切换也可能恰好只有一个节点。
    default = next((ob for ob in outbounds if ob.get("tag") == "🔰 默认出口"), {})
    candidates = set(default.get("outbounds", [])) - {"🚀 手动切换", "🍑 自由切换", "🔍 调试出口", "DIRECT"}
    tags = set()
    for ob in outbounds:
        tag = ob.get("tag")
        if not isinstance(tag, str):
            continue
        if ob.get("type") == "urltest":
            tags.add(tag)
        elif ob.get("type") == "selector" and len(ob.get("outbounds", [])) == 1:
            if tag in candidates or tag.startswith("🤖 自然选择 ") or tag.endswith(" 🎬"):
                tags.add(tag)
    return tags


def remove_outbounds(config: dict, tags: Iterable[str]) -> None:
    """从 config 中移除 tag 命中 tags 的 outbound，并清理 selector/urltest 的 outbounds 引用。"""
    tags = set(tags)
    if not tags:
        return
    outbounds = config.get("outbounds") or []
    config["outbounds"] = [o for o in outbounds if o.get("tag") not in tags]
    for o in config["outbounds"]:
        refs = o.get("outbounds")
        if isinstance(refs, list):
            o["outbounds"] = [t for t in refs if t not in tags]


def _dialer_refs(options: dict):
    yield options, "detour"
    for key in ("http_client", "external_ui_http_client", "override_dialer", "control_dialer", "tunnel_dialer"):
        child = options.get(key)
        if isinstance(child, dict):
            yield child, "detour"


def outbound_refs(outbound: dict):
    """一个出站对其他出站的引用。"""
    yield from _dialer_refs(outbound)
    if outbound.get("type") in ("selector", "urltest"):
        yield outbound, "outbounds"
        yield outbound, "default"


def _rule_outbound_refs(rules: list):
    for rule in rules:
        yield rule, "outbound"
        yield from _rule_outbound_refs(rule.get("rules", []))


def root_outbound_refs(config: dict):
    """从配置入口直接引用出站的字段，与 DNS tag、入站 detour 分开处理。"""
    route = config.get("route", {})
    dns = config.get("dns", {})
    yield route, "final"
    yield from _rule_outbound_refs(route.get("rules", []))
    yield from _rule_outbound_refs(dns.get("rules", []))
    for source in [*route.get("rule_set", []), *config.get("providers", [])]:
        yield source, "download_detour"
        yield from _dialer_refs(source)
    for dialer in [*dns.get("servers", []), *config.get("http_clients", []), *config.get("endpoints", [])]:
        yield from _dialer_refs(dialer)
    yield from _dialer_refs(config.get("ntp", {}))
    experimental = config.get("experimental", {})
    clash_api = experimental.get("clash_api", {})
    yield clash_api, "external_ui_download_detour"
    yield from _dialer_refs(clash_api)
    yield experimental.get("v2ray_api", {}).get("stats", {}), "outbounds"


def referenced_tags(fields: Iterable[tuple[dict, str]]):
    for options, key in fields:
        value = options.get(key)
        if isinstance(value, str):
            yield value
        elif isinstance(value, list):
            yield from value
