"""sing-box 配置 dict 操作工具。"""

from collections.abc import Iterable


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
