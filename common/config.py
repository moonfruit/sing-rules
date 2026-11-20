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
