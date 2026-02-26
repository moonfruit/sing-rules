#!/opt/homebrew/bin/python3
"""
将 sing-box config.json 中的 outbounds 拆分到不同 JSON 文件。

用法：
    python3 split-outbounds.py <config.json>

输出：
    groups.json  —— urltest 类型中符合条件的分组（tag -> outbounds 列表）
    proxies.json —— 非 selector 类型中符合条件的代理节点（tag -> 完整 item）
"""

import json
from pathlib import Path

import typer

URLTEST_EXCLUDE = ("自动选择", "美国节点", "欧洲节点")
PROXY_EXCLUDE = ("LazyCat",)


def split_tag(s: str) -> tuple[str, str]:
    """将 'emoji label' 拆分为 ('emoji', 'label')，无空格时返回 ('', s)。"""
    emoji, _, label = s.partition(" ")
    return (emoji, label) if label else ("", s)


def write_json(path: Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main(input_file: Path = typer.Argument(..., exists=True, help="sing-box config.json 路径")):
    with input_file.open(encoding="utf-8") as f:
        config = json.load(f)

    outbounds = config.get("outbounds", [])
    groups: dict = {}
    tag_to_country: dict[str, str] = {}
    proxies: dict = {}

    for item in outbounds:
        tag = item.get("tag", "")
        item_type = item.get("type", "")

        if item_type == "urltest":
            if tag.endswith("节点") and "欧洲节点" not in tag:
                for t in item.get("outbounds", []):
                    tag_to_country[t] = tag
            elif not any(kw in tag for kw in URLTEST_EXCLUDE):
                groups[tag] = item.get("outbounds", [])

        if item_type != "selector":
            if not any(kw in tag for kw in PROXY_EXCLUDE):
                proxies[tag] = item

    providers: dict[str, dict] = {}

    for group_name, tags in groups.items():
        _, group_label = split_tag(group_name)  # '🌸 NanoCloud' -> 'NanoCloud'

        for tag in tags:
            country_name = tag_to_country.get(tag)
            proxy = proxies.get(tag)
            if country_name is None or proxy is None:
                continue

            country_emoji, _ = split_tag(country_name)  # '🏳️‍🌈 动态节点' -> '🏳️‍🌈'
            _, new_tag = split_tag(tag)  # '🏳️‍🌈 白羊座-AGP(通用)' -> '白羊座-AGP(通用)'
            provider = f"{country_emoji} {group_label}"

            proxy_copy = {**proxy, "tag": new_tag}
            providers.setdefault(provider, {"outbounds": []})["outbounds"].append(proxy_copy)

    out_dir = input_file.parent

    write_json(out_dir / "providers.json", providers)

    print(f"providers: {len(providers)} 个")
    for provider, node in providers.items():
        print(f"  {provider}: {len(node['outbounds'])} 条")


if __name__ == "__main__":
    typer.run(main)
