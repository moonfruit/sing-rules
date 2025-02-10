#!/usr/bin/env python
import json
import re
from pathlib import Path
from typing import Annotated

import typer
from attrs import define
from cattrs import structure

from common import Object, SimpleObject, get_list, yaml
from common.io import open_path


def inbound(tag: str, type_: str, listen: str, port: int, **extra) -> Object:
    return {
        "type": type_,
        "tag": tag,
        "listen": listen,
        "listen_port": port,
        "sniff": True,
        **extra,
    }


def dns(tag: str = "dns-in", port: int = 53) -> Object:
    return inbound(tag, "direct", "127.0.0.1", port, udp_fragment=True)


def localhost(tag: str, port: int = 7890) -> Object:
    return inbound(tag, "mixed", "127.0.0.1", port, tcp_fast_open=True)


def anyone(tag: str, port: int) -> Object:
    from common.keychain import get_proxy_user

    user = get_proxy_user()
    return inbound(tag, "mixed", "::", port, tcp_fast_open=True, users=[user])


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


def __find_group(tag: str) -> str:
    match = re.match(r"(?:IPLC)?([A-Z]{2})\w*(?:-([A-Z]{2}))?\b", tag)
    if match:
        groups = match.groups()
        return groups[1] if groups[1] in __FLAG_MAP else groups[0]


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


__COST_LINE = 1.5


def add_to_group(groups: dict[str, list[str]], group: str, tag: str, cost: float = None):
    get_list(groups, group).append(tag)
    if cost and cost < __COST_LINE:
        get_list(groups, f"{group} 🛢️").append(tag)


def remove_duple_keys(d: dict) -> dict:
    keys_to_remove = []
    for key in d:
        new_key = key + " 🛢️"
        if new_key in d and d[key] == d[new_key]:
            keys_to_remove.append(new_key)
    for key in keys_to_remove:
        del d[key]
    return d


def proxies_to_outbound(proxies: list[SimpleObject]) -> list[SimpleObject]:
    outbounds = [
        {"type": "direct", "tag": "DIRECT"},
        {"type": "block", "tag": "REJECT"},
        {"type": "dns", "tag": "dns-out"},
        {"type": "http", "tag": "⛰️ Gingkoo", "server": "10.1.2.12", "server_port": 8118},
        {"type": "socks", "tag": "🧅 Tor Browser", "server": "127.0.0.1", "server_port": 9150},
    ]

    costs = {"⛰️ Gingkoo": 0, "🧅 Tor Browser": 0}
    all_nodes = ["⛰️ Gingkoo", "🧅 Tor Browser"]
    cheap_nodes = ["⛰️ Gingkoo", "🧅 Tor Browser"]
    expansive_nodes = []
    other_nodes = ["🧅 Tor Browser"]
    groups = {
        "🇺🇸 美国节点": ["⛰️ Gingkoo"],
        "🇺🇸 美国节点 🛢️": ["⛰️ Gingkoo"],
    }
    providers = {}

    for proxy in proxies:
        if proxy["server"] == "None":
            continue
        group, cost, outbound = proxy_to_outbound(proxy)
        outbounds.append(outbound)

        tag = outbound["tag"]
        costs[tag] = cost
        all_nodes.append(tag)

        if cost <= __COST_LINE:
            cheap_nodes.append(tag)
        else:
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

    groups["🏳️ 其它节点"] = other_nodes
    remove_duple_keys(providers)
    group_tags = [*providers, *groups]

    outbounds.append(
        selector("🔰 默认出口", ["🛢️ 省流节点", "👍 高级节点", "♻️ 自动选择", "🚀 手动切换", *group_tags, "DIRECT"])
    )

    outbounds.append(selector("🚀 手动切换", all_nodes))
    outbounds.append(urltest("♻️ 自动选择", costs, all_nodes))
    outbounds.append(urltest("🛢️ 省流节点", costs, cheap_nodes))
    if expansive_nodes:
        outbounds.append(urltest("👍 高级节点", costs, expansive_nodes))
    else:
        outbounds.append(selector("👍 高级节点", ["♻️ 自动选择"]))

    outbounds.append(selector("🤖 人工智能", ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]))
    outbounds.append(selector("🎥 Disney+", ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]))
    outbounds.append(selector("🎥 Netflix", ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]))
    outbounds.append(selector("🎥 TikTok", ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]))
    outbounds.append(selector("🎥 YouTube", ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]))
    outbounds.append(selector("🎮 PlayStation", ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]))
    outbounds.append(selector("🎮 PlayStation@CN", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))
    outbounds.append(selector("🎮 Steam", ["🔰 默认出口", "👍 高级节点", *group_tags, "DIRECT"]))
    outbounds.append(selector("🎮 Steam@CN", ["DIRECT", "🔰 默认出口", "👍 高级节点", *group_tags]))

    outbounds.append(selector("🎯 全球直连", ["DIRECT", "🔰 默认出口"]))
    outbounds.append(selector("🛑 全球拦截", ["REJECT", "🔰 默认出口", "DIRECT"]))
    outbounds.append(selector("🐟 漏网之鱼", ["DIRECT", "🔰 默认出口", "REJECT"]))

    for tag, nodes in providers.items():
        outbounds.append(urltest(tag, costs, nodes))

    for tag, nodes in groups.items():
        outbounds.append(urltest(tag, costs, nodes))

    outbounds.append(selector("GLOBAL", ["DIRECT", "REJECT", *all_nodes]))

    return outbounds


def to_sing(proxies: list[SimpleObject]) -> Object:
    return {
        "log": {
            "level": "trace",
            "timestamp": True,
        },
        "dns": {
            "servers": [
                {"tag": "dns-resolver", "address": "223.5.5.5", "detour": "DIRECT"},
                {
                    "tag": "dns-direct",
                    "address": "h3://dns.alidns.com/dns-query",
                    "address_resolver": "dns-resolver",
                    "detour": "DIRECT",
                },
                {
                    "tag": "dot-direct",
                    "address": "tls://dns.alidns.com",
                    "address_resolver": "dns-resolver",
                    "detour": "DIRECT",
                },
                {
                    "tag": "doh-direct",
                    "address": "https://dns.alidns.com/dns-query",
                    "address_resolver": "dns-resolver",
                    "detour": "DIRECT",
                },
                {"tag": "dot-proxy", "address": "tls://1.1.1.1"},
                {"tag": "doh-proxy", "address": "https://1.1.1.1/dns-query", "detour": "🔰 默认出口"},
                {"tag": "dns-gingkoo", "address": "tcp://10.1.2.59", "detour": "DIRECT"},
                {"tag": "dns-home", "address": "192.168.50.1", "detour": "DIRECT"},
                {"tag": "dns-system", "address": "local", "detour": "DIRECT"},
            ],
            "rules": [
                {"domain_suffix": "server.gingkoo", "server": "dns-gingkoo"},
                {"domain": ["asusrouter.com", "router.asus.com", "www.asusrouter.com"], "server": "dns-home"},
                {"rule_set": "Proxy", "server": "doh-proxy"},
            ],
            "final": "doh-direct",
            "reverse_mapping": True,
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            dns(),
            localhost("mixed-in"),
            localhost("direct-in", 7891),
            localhost("global-in", 7892),
            anyone("protected-in", 9999),
        ],
        "outbounds": proxies_to_outbound(proxies),
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"clash_mode": "Direct", "outbound": "DIRECT"},
                {"clash_mode": "Global", "outbound": "GLOBAL"},
                {"inbound": "global-in", "outbound": "GLOBAL"},
                {"domain": "connectivitycheck.gstatic.com", "outbound": "🐟 漏网之鱼"},
                {"rule_set": "Private", "outbound": "🎯 全球直连"},
                {"rule_set": "Block", "outbound": "🛑 全球拦截"},
                {"rule_set": "AI", "outbound": "🤖 人工智能"},
                {"rule_set": "Disney+", "outbound": "🎥 Disney+"},
                {"rule_set": "Netflix", "outbound": "🎥 Netflix"},
                {"rule_set": "TikTok", "outbound": "🎥 TikTok"},
                {"rule_set": "YouTube", "outbound": "🎥 YouTube"},
                {"rule_set": "PlayStation@CN", "outbound": "🎮 PlayStation@CN"},
                {"rule_set": "PlayStation", "outbound": "🎮 PlayStation"},
                {"rule_set": "Steam@CN", "outbound": "🎮 Steam@CN"},
                {"rule_set": "Steam", "outbound": "🎮 Steam"},
                {"rule_set": "GFW", "outbound": "🔰 默认出口"},
                {"rule_set": "Direct", "outbound": "🎯 全球直连"},
                {"rule_set": "Proxy", "outbound": "🔰 默认出口"},
                {"inbound": "direct-in", "outbound": "🎯 全球直连"},
            ],
            "rule_set": [
                {
                    "type": "remote",
                    "tag": "AI",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/ai.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Disney+",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/disney-plus.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Netflix",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/netflix.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "TikTok",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/tiktok.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "YouTube",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/youtube.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "PlayStation",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/playstation.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "PlayStation@CN",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/playstation-cn.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Steam",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/steam.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Steam@CN",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/steam-cn.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Block",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/block.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Direct",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/direct.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "GFW",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/gfw.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Private",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/private.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Proxy",
                    "format": "binary",
                    "url": "https://cdn.jsdmirror.com/npm/sing-rules/rules/proxy.srs",
                    "download_detour": "DIRECT",
                },
            ],
            "final": "🐟 漏网之鱼",
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
            },
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
            },
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
):
    config_files = [ConfigFile(f) for f in filenames] if filenames else []
    if configs:
        for config in configs:
            config_files.extend(load_config_files(config))
    proxies = sum([load_proxies(config) for config in config_files], start=[])
    if not proxies:
        raise ValueError("No proxies found")

    sing = to_sing(proxies)
    with open_path(output, "w") as f:
        # noinspection PyTypeChecker
        json.dump(sing, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    typer.run(main)
