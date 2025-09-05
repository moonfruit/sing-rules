#!/usr/bin/env python
import ipaddress
import json
import re
from pathlib import Path
from typing import Annotated

import typer
from attrs import define
from cattrs import structure

from common import Object, SimpleObject, get_list, yaml
from common.io import open_path

__FLAG_MAP = {
    "EU": "🇪🇺",
    "HK": "🇭🇰",
    "ID": "🇮🇩",
    "JP": "🇯🇵",
    "KR": "🇰🇷",
    "MY": "🇲🇾",
    "SG": "🇸🇬",
    "TW": "🇨🇳",
    "UK": "🇬🇧",
    "US": "🇺🇸",
    "VN": "🇻🇳",
}

__TAG_GROUP = [
    ("SG", re.compile(r"去除\s*\d\s*条不合适线路")),
]

__GROUP_ALIAS = {
    "ID": "印尼",
    "JP": "日本",
    "KR": "韩国",
    "MY": "马来西亚",
    "SG": "新加坡",
    "TW": "台湾",
    "US": "美国",
}

__GROUP_MAP = {
    "EU": "🇪🇺 欧洲节点",
    "HK": "🇭🇰 香港节点",
    "ID": "🇮🇩 印度尼西亚",
    "JP": "🇯🇵 日本节点",
    "KR": "🇰🇷 韩国节点",
    "MY": "🇲🇾 马来西亚",
    "SG": "🇸🇬 新加坡节点",
    "TW": "🇨🇳 台湾节点",
    "UK": "🇬🇧 英国节点",
    "US": "🇺🇸 美国节点",
    "VN": "🇻🇳 越南节点",
}


def __find_group(tag: str) -> str | None:
    match = re.match(r"(?:IPLC)?([A-Z]{2})\w*(?:-([A-Z]{2}))?\b", tag)
    if match:
        groups = match.groups()
        return groups[1] if groups[1] in __FLAG_MAP else groups[0]
    return None


def __fix_tag(tag: str, length: int) -> str:
    if len(tag) > length and tag[length] != " ":
        return tag[:length] + " " + tag[length:]
    return tag


def find_group(tag: str) -> tuple[str, str]:
    for group, pattern in __TAG_GROUP:
        if pattern.match(tag):
            return group, tag
    for group, flag in __FLAG_MAP.items():
        if tag.startswith(flag):
            return group, tag[len(flag) :].lstrip()
    for group, alias in __GROUP_ALIAS.items():
        if tag.startswith(alias):
            return group, __fix_tag(tag, len(alias))
    return __find_group(tag), tag


def find_cost(tag: str, cost: float = 1) -> float:
    match = re.match(r".*\s(?:\(\s*)?(\d+(?:\.\d+)?)x(?:\s*\))?\s*$", tag)
    return float(match.group(1)) if match else cost


def proxy_to_outbound(clash: SimpleObject) -> tuple[str, float, SimpleObject]:
    name = clash["name"].strip()
    group, name = find_group(name)
    cost = find_cost(name, clash.get("cost", 1))
    tag = f"{__FLAG_MAP.get(group, "🏳️")} {name}"
    outbound: Object = {}
    match clash["type"]:
        case "hysteria2":
            outbound = {
                "type": "hysteria2",
                "tag": tag,
                "server": clash["server"],
            }
            if "ports" in clash:
                outbound["server_ports"] = [
                    p.replace("-", ":") if "-" in p else f"{p}:{p}" for p in clash["ports"].split(",")
                ]
            else:
                outbound["server_port"] = clash["port"]
            outbound.update(password=clash["password"], tls={"enabled": True})
            if clash.get("skip-cert-verify", False):
                outbound["tls"]["insecure"] = True
        case "ss":
            outbound = {
                "type": "shadowsocks",
                "tag": tag,
                "server": clash["server"],
                "server_port": clash["port"],
                "method": clash["cipher"],
                "password": clash["password"],
            }
        case "trojan":
            outbound = {
                "type": "trojan",
                "tag": tag,
                "server": clash["server"],
                "server_port": clash["port"],
                "password": clash["password"],
                "tls": {
                    "enabled": True,
                },
            }
            if clash.get("skip-cert-verify", False):
                outbound["tls"]["insecure"] = True
        case "vmess":
            outbound = {
                "type": "vmess",
                "tag": tag,
                "server": clash["server"],
                "server_port": clash["port"],
                "uuid": clash["uuid"],
                "security": clash["cipher"],
                "alter_id": clash["alterId"],
            }
        case _:
            raise ValueError(f"Unknown type '{clash['type']}'")
    return group, cost, outbound


def selector(tag: str, nodes: list[str]) -> Object:
    return {"type": "selector", "tag": tag, "outbounds": nodes}


def urltest(tag: str, costs: dict[str, float], nodes: list[str]) -> Object:
    nodes = sorted(nodes, key=lambda node: costs.get(node, 1))
    return {"type": "urltest", "tag": tag, "outbounds": nodes, "interval": "10m0s"}


def is_cheap(cost):
    return cost < 1.5


def is_expansive(cost):
    return cost > 1


def add_to_group(groups: dict[str, list[str]], group: str, tag: str, cost: float = None):
    get_list(groups, group).append(tag)
    if cost:
        if is_cheap(cost):
            get_list(groups, f"{group} 🛢️").append(tag)
        elif is_expansive(cost):
            get_list(groups, f"{group} 👍").append(tag)


def remove_duple_keys(d: dict) -> dict:
    keys_to_remove = []
    for key in d:
        new_key = key + " 🛢️"
        if new_key in d and d[key] == d[new_key]:
            keys_to_remove.append(new_key)
    for key in keys_to_remove:
        del d[key]
    return d


def is_ipv4_address(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False


def proxies_to_outbound(local: bool, proxies: list[SimpleObject]) -> tuple[list[SimpleObject], set[str], set[str]]:
    outbounds = []
    domains = set()
    ips = set()
    costs: dict[str, float] = {}

    all_nodes = []
    cheap_nodes = []
    expansive_nodes = []
    other_nodes = []
    groups = {}

    if local:
        outbounds = [
            {"type": "http", "tag": "⛰️ Gingkoo", "server": "10.1.2.12", "server_port": 8118},
            {"type": "socks", "tag": "🧅 Tor Browser", "server": "127.0.0.1", "server_port": 9150},
        ]
        costs = {"⛰️ Gingkoo": 0, "🧅 Tor Browser": 0}

        all_nodes = ["⛰️ Gingkoo", "🧅 Tor Browser"]
        cheap_nodes = ["⛰️ Gingkoo", "🧅 Tor Browser"]
        other_nodes = ["🧅 Tor Browser"]
        groups = {
            "🇺🇸 美国节点": ["⛰️ Gingkoo"],
            "🇺🇸 美国节点 🛢️": ["⛰️ Gingkoo"],
            "🇺🇸 美国节点 👍": ["⛰️ Gingkoo"],
        }

    outbounds.append({"type": "http", "tag": "🐱 LazyCat", "server": "127.0.0.1", "server_port": 31085})
    outbounds.append({"type": "socks", "tag": "🐱 LazyCat(S)", "server": "127.0.0.1", "server_port": 31086})

    providers = {}

    for proxy in proxies:
        server = proxy["server"]
        if server == "None":
            continue
        group, cost, outbound = proxy_to_outbound(proxy)
        outbounds.append(outbound)
        if is_ipv4_address(server):
            ips.add(server + "/32")
        else:
            domains.add(server)

        tag = outbound["tag"]
        costs[tag] = cost
        all_nodes.append(tag)

        if is_cheap(cost):
            cheap_nodes.append(tag)
        elif is_expansive(cost):
            expansive_nodes.append(tag)

        if group in __GROUP_MAP:
            if group == "US":
                add_to_group(groups, __GROUP_MAP[group], tag, cost)
            else:
                if group == "UK":
                    add_to_group(groups, __GROUP_MAP["EU"], tag)
                add_to_group(groups, __GROUP_MAP[group], tag)
        else:
            other_nodes.append(tag)

        if "provider" in proxy:
            provider = proxy["provider"]
            add_to_group(providers, provider, tag, cost)

    if other_nodes:
        groups["🏳️ 其它节点"] = other_nodes
    remove_duple_keys(providers)
    group_tags = ["🍑 自由切换", *providers, *groups]

    outbounds.append(
        selector("🔰 默认出口", ["🛢️ 省流节点", "👍 高级节点", "♻️ 自动选择", "🚀 手动切换", *group_tags, "DIRECT"])
    )

    outbounds.append(urltest("♻️ 自动选择", costs, all_nodes))
    outbounds.append(selector("🚀 手动切换", all_nodes))
    outbounds.append(selector("🍑 自由切换", all_nodes))
    outbounds.append(urltest("🛢️ 省流节点", costs, cheap_nodes))
    if expansive_nodes:
        outbounds.append(urltest("👍 高级节点", costs, expansive_nodes))
    else:
        outbounds.append(selector("👍 高级节点", ["♻️ 自动选择"]))

    if "🇺🇸 美国节点" in group_tags:
        us_tags = [tag for tag in group_tags if tag.startswith("🇺🇸 美国节点")]
        not_us_tags = [tag for tag in group_tags if not tag.startswith("🇺🇸 美国节点")]
        ai_tags = [*us_tags, "🔰 默认出口", "👍 高级节点", *not_us_tags, "DIRECT"]
    else:
        ai_tags = ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]

    outbounds.append(selector("🤖 人工智能", ai_tags))
    outbounds.append(selector("🐱 懒猫微服", ["DIRECT", "🐱 LazyCat", "🐱 LazyCat(S)"]))
    outbounds.append(selector("🍎 苹果服务", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("Ⓜ️ 微软服务", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("⚙️ 软件开发", ["🔰 默认出口", "DIRECT", "👍 高级节点", *group_tags]))
    outbounds.append(selector("📦 软件仓库", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 Nintendo", ["🔰 默认出口", "DIRECT", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 Nintendo@CN", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 PlayStation", ["🔰 默认出口", "DIRECT", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 PlayStation@CN", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 Steam", ["🔰 默认出口", "DIRECT", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 Steam@CN", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 Games", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 Games@CN", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎥 Disney+", ["🔰 默认出口", "👍 高级节点", "DIRECT", *group_tags]))
    outbounds.append(selector("🎥 Netflix", ["🔰 默认出口", "👍 高级节点", "DIRECT", *group_tags]))
    outbounds.append(selector("🎥 TikTok", ["🔰 默认出口", "👍 高级节点", "DIRECT", *group_tags]))
    outbounds.append(selector("🎥 YouTube", ["🔰 默认出口", "👍 高级节点", "DIRECT", *group_tags]))

    outbounds.append(selector("🎯 全球直连", ["DIRECT", "🔰 默认出口"]))
    outbounds.append(selector("🛑 全球拦截", ["REJECT", "🔰 默认出口", "DIRECT"]))
    outbounds.append(selector("👻 透明代理", ["DIRECT", "🔰 默认出口", "REJECT"]))
    outbounds.append(selector("🐟 漏网之鱼", ["🔰 默认出口", "DIRECT", "REJECT"]))

    for tag, nodes in providers.items():
        outbounds.append(urltest(tag, costs, nodes))

    for tag, nodes in groups.items():
        outbounds.append(urltest(tag, costs, nodes))

    outbounds.append(selector("GLOBAL", [*all_nodes]))

    return outbounds, domains, ips


def as_tuple(ip):
    parts = ip.split("/", maxsplit=1)
    return *(int(n) for n in parts[0].split(".")), int(parts[1])


def build_direct_rules(domains, ips):
    direct: Object = {
        "ip_is_private": True,
        "outbound": "DIRECT",
    }
    if domains:
        direct["domain"] = sorted(domains)
    if ips:
        direct["ip_cidr"] = sorted(ips, key=as_tuple)
    return direct


def build_local_rules(local: bool):
    if not local:
        return []
    return [{"rule_set": "AI:Process", "outbound": "🤖 人工智能"}]


def build_local_rule_sets(local: bool):
    if not local:
        return []
    return [rule_set("AI:Process", "sing-rules/rules/ai-proc.srs")]


__CDN = "cdn.jsdelivr.net"
# __CDN = "fastly.jsdelivr.net"
# __CDN = "cdn.jsdmirror.com"


def rule_set(tag: str, url: str):
    # noinspection HttpUrlsUsage
    if url.startswith("http://") or url.startswith("https://"):
        url_to_use = url
    else:
        url_to_use = f"https://{__CDN}/npm/{url}"

    if url.endswith(".json"):
        format_to_use = "source"
    else:
        format_to_use = "binary"

    return {
        "type": "remote",
        "tag": tag,
        "format": format_to_use,
        "url": url_to_use,
        "download_detour": "DIRECT",
    }


def to_sing(local: bool, proxies: list[SimpleObject]) -> Object:
    outbounds, domains, ips = proxies_to_outbound(local, proxies)
    return {
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"domain": "connectivitycheck.gstatic.com", "outbound": "🐟 漏网之鱼"},
                {"domain": ["api.ip.sb", "api.ipapi.is"], "outbound": "🔰 默认出口"},
                {"domain_suffix": ["heiyu.space", "lazycat.cloud"], "outbound": "🐱 懒猫微服"},
                build_direct_rules(domains, ips),
                {"rule_set": "Private", "outbound": "🎯 全球直连"},
                {"rule_set": "Block", "outbound": "🛑 全球拦截"},
                *build_local_rules(local),
                {"rule_set": "AI", "outbound": "🤖 人工智能"},
                {"rule_set": "Apple", "outbound": "🍎 苹果服务"},
                {"rule_set": "Microsoft", "outbound": "Ⓜ️ 微软服务"},
                {"rule_set": "Development@CN", "outbound": "🎯 全球直连"},
                {"rule_set": "Development", "outbound": "⚙️ 软件开发"},
                {"rule_set": "Sources", "outbound": "📦 软件仓库"},
                {"rule_set": "Disney+", "outbound": "🎥 Disney+"},
                {"rule_set": "Netflix", "outbound": "🎥 Netflix"},
                {"rule_set": "TikTok", "outbound": "🎥 TikTok"},
                {"rule_set": "YouTube", "outbound": "🎥 YouTube"},
                {"rule_set": "Nintendo@CN", "outbound": "🎮 Nintendo@CN"},
                {"rule_set": "Nintendo", "outbound": "🎮 Nintendo"},
                {"rule_set": "PlayStation@CN", "outbound": "🎮 PlayStation@CN"},
                {"rule_set": "PlayStation", "outbound": "🎮 PlayStation"},
                {"rule_set": "Steam@CN", "outbound": "🎮 Steam@CN"},
                {"rule_set": "Steam", "outbound": "🎮 Steam"},
                {"rule_set": "Games@CN", "outbound": "🎮 Games@CN"},
                {"rule_set": "Games", "outbound": "🎮 Games"},
                {"rule_set": "Minecraft", "outbound": "🎮 Steam"},
                {"rule_set": ["GFW", "Porn"], "outbound": "🔰 默认出口"},
                {"rule_set": "Direct", "outbound": "🎯 全球直连"},
                {"rule_set": "Proxy", "outbound": "🔰 默认出口"},
                {"inbound": "direct-in", "outbound": "🎯 全球直连"},
                {"inbound": ["redirect-in", "tproxy-in", "tun-in"], "outbound": "👻 透明代理"},
            ],
            "rule_set": [
                rule_set("AI", "sing-rules/rules/ai.srs"),
                rule_set("Apple", "sing-rules/rules/apple.srs"),
                rule_set("Block", "sing-rules/rules/block.srs"),
                rule_set("Development", "sing-rules/rules/dev.srs"),
                rule_set("Development@CN", "sing-rules/rules/dev-cn.srs"),
                rule_set("Direct", "sing-rules/rules/direct.srs"),
                rule_set("Disney+", "sing-rules/rules/disney-plus.srs"),
                rule_set("Games", "sing-rules/rules/games.srs"),
                rule_set("Games@CN", "sing-rules/rules/games-cn.srs"),
                rule_set("GFW", "sing-rules/rules/gfw.srs"),
                rule_set("Microsoft", "sing-rules/rules/microsoft.srs"),
                rule_set("Minecraft", "sing-rules/rules/minecraft.srs"),
                rule_set("Netflix", "sing-rules/rules/netflix.srs"),
                rule_set("Nintendo", "sing-rules/rules/nintendo.srs"),
                rule_set("Nintendo@CN", "sing-rules/rules/nintendo-cn.srs"),
                rule_set("PlayStation", "sing-rules/rules/playstation.srs"),
                rule_set("PlayStation@CN", "sing-rules/rules/playstation-cn.srs"),
                rule_set("Porn", "sing-rules/rules/porn.srs"),
                rule_set("Private", "sing-rules/rules/private.srs"),
                rule_set("Proxy", "sing-rules/rules/proxy.srs"),
                rule_set("Sources", "sing-rules/rules/sources.srs"),
                rule_set("Steam", "sing-rules/rules/steam.srs"),
                rule_set("Steam@CN", "sing-rules/rules/steam-cn.srs"),
                rule_set("TikTok", "sing-rules/rules/tiktok.srs"),
                rule_set("YouTube", "sing-rules/rules/youtube.srs"),
                *build_local_rule_sets(local),
            ],
            "final": "🐟 漏网之鱼",
        },
    }


@define
class ConfigFile:
    path: Path
    name: str = None
    cost: float = 1


def load_config_files(path: Path) -> list[ConfigFile]:
    with open_path(path) as f:
        configs = json.load(f)
    return structure(configs, list[ConfigFile])


def load_proxies(config: ConfigFile) -> list[SimpleObject]:
    if config.cost <= 0:
        return []
    with open_path(config.path) as f:
        clash = yaml.load(f)
    if "proxies" not in clash:
        return []
    proxies = clash["proxies"]
    for proxy in proxies:
        if config.name:
            proxy["provider"] = config.name
        proxy["cost"] = config.cost
    return proxies


def main(
    filenames: Annotated[
        list[Path], typer.Argument(show_default=False, exists=True, dir_okay=False, readable=True)
    ] = None,
    configs: Annotated[
        list[Path], typer.Option("--config", "-c", show_default=False, exists=True, dir_okay=False, readable=True)
    ] = None,
    output: Annotated[Path, typer.Option("--output", "-o", dir_okay=False, writable=True)] = "-",
    local: Annotated[bool, typer.Option("--local", "-l")] = False,
):
    config_files = [ConfigFile(f) for f in filenames] if filenames else []
    if configs:
        for config in configs:
            config_files.extend(load_config_files(config))
    proxies = sum([load_proxies(config) for config in config_files], start=[])
    if not proxies:
        raise ValueError("No proxies found")

    sing = to_sing(local, proxies)
    with open_path(output, "w") as f:
        # noinspection PyTypeChecker
        json.dump(sing, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    typer.run(main)
