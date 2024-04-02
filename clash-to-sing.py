#!/usr/bin/env python
import json
import re
import sys
from typing import TextIO

from common import Object, SimpleObject, get_list, yaml


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
    "US": "🇺🇸",
    "UK": "🇬🇧",
    "EU": "🇪🇺",
    "HK": "🇭🇰",
    "TW": "🇨🇳",
    "JP": "🇯🇵",
    "VN": "🇻🇳",
    "SG": "🇸🇬",
}

__GROUP_MAP = {
    "US": "🇺🇸 美国节点",
    "UK": "🇬🇧 英国节点",
    "EU": "🇪🇺 欧洲节点",
    "HK": "🇭🇰 香港节点",
    "TW": "🇨🇳 台湾节点",
    "JP": "🇯🇵 日本节点",
    "VN": "🇻🇳 越南节点",
    "SG": "🇸🇬 新加坡节点",
}


def __find_group(tag: str) -> str:
    match = re.match(r"(?:IPLC)?([A-Z]{2})\w*(?:-([A-Z]{2}))?\b", tag)
    if match:
        groups = match.groups()
        return groups[1] if groups[1] in __FLAG_MAP else groups[0]


def find_group(tag: str) -> tuple[str, str]:
    for group, flag in __FLAG_MAP.items():
        if tag.startswith(flag):
            return group, tag[len(flag):].lstrip()
    return __find_group(tag), tag


def find_cost(tag: str) -> float:
    match = re.match(r".*\s(?:\(\s*)?(\d+(?:\.\d+)?)x(?:\s*\))?\s*$", tag)
    return float(match.group(1)) if match else 1


def proxy_to_outbound(clash: SimpleObject) -> tuple[str, float, SimpleObject]:
    name = clash["name"].strip()
    group, name = find_group(name)
    cost = find_cost(name)
    tag = f"{__FLAG_MAP.get(group, "🏳️")} {name}"
    match clash["type"]:
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
        case "ss":
            outbound = {
                "type": "shadowsocks",
                "tag": tag,
                "server": clash["server"],
                "server_port": clash["port"],
                "method": clash["cipher"],
                "password": clash["password"],
            }
        case _:
            raise ValueError(f"Unknown type '{clash['type']}'")
    return group, cost, outbound


def selector(tag: str, nodes: list[str]) -> Object:
    return {"type": "selector", "tag": tag, "outbounds": nodes}


def urltest(tag: str, costs: dict[str, float], nodes: list[str]) -> Object:
    nodes = sorted(nodes, key=lambda node: costs.get(node, 1))
    return {"type": "urltest", "tag": tag, "outbounds": nodes, "interval": "10m0s"}


__COST_LINE = 1


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

    for proxy in proxies:
        if proxy["server"] == "None":
            continue
        group, cost, outbound = proxy_to_outbound(proxy)
        outbounds.append(outbound)

        tag_ = outbound["tag"]
        costs[tag_] = cost
        all_nodes.append(tag_)

        if cost <= __COST_LINE:
            cheap_nodes.append(tag_)
        else:
            expansive_nodes.append(tag_)

        if group in __GROUP_MAP:
            get_list(groups, __GROUP_MAP[group]).append(tag_)
            if group == "US" and cost <= __COST_LINE:
                get_list(groups, "🇺🇸 美国节点 🛢️").append(tag_)
            elif group == "UK":
                get_list(groups, "🇪🇺 欧洲节点").append(tag_)
        else:
            other_nodes.append(tag_)
    groups["🏳️ 其它节点"] = other_nodes

    outbounds.append(selector("🔰 默认出口",
                              ["🛢️ 省流节点", "👍 高级节点", "♻️ 自动选择", "🚀 手动切换", *groups, "DIRECT"]))

    outbounds.append(selector("🚀 手动切换", all_nodes))
    outbounds.append(urltest("♻️ 自动选择", costs, all_nodes))
    outbounds.append(urltest("🛢️ 省流节点", costs, cheap_nodes))
    outbounds.append(urltest("👍 高级节点", costs, expansive_nodes))

    outbounds.append(selector("🤖 人工智能", ["🔰 默认出口", "👍 高级节点", *groups, "DIRECT"]))
    outbounds.append(selector("🎥 Disney+", ["🔰 默认出口", "👍 高级节点", *groups, "DIRECT"]))
    outbounds.append(selector("🎥 Netflix", ["🔰 默认出口", "👍 高级节点", *groups, "DIRECT"]))
    outbounds.append(selector("🎥 TikTok", ["🔰 默认出口", "👍 高级节点", *groups, "DIRECT"]))
    outbounds.append(selector("🎥 YouTube", ["🔰 默认出口", "👍 高级节点", *groups, "DIRECT"]))

    outbounds.append(selector("🎯 全球直连", ["DIRECT", "🔰 默认出口"]))
    outbounds.append(selector("🛑 全球拦截", ["REJECT", "🔰 默认出口", "DIRECT"]))
    outbounds.append(selector("🐟 漏网之鱼", ["DIRECT", "🔰 默认出口", "REJECT"]))

    for tag, nodes in groups.items():
        outbounds.append(urltest(tag, costs, nodes))

    outbounds.append(selector("GLOBAL", ["DIRECT", "REJECT", *all_nodes]))

    return outbounds


def to_sing(clash: Object) -> Object:
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
                {"tag": "dns-proxy", "address": "tls://1.1.1.1"},
                {"tag": "dns-gingkoo", "address": "tcp://10.1.2.59", "detour": "DIRECT"},
                {"tag": "dns-home", "address": "192.168.50.1", "detour": "DIRECT"},
                {"tag": "dns-system", "address": "local", "detour": "Direct"},
            ],
            "rules": [
                {"domain_suffix": "server.gingkoo", "server": "dns-gingkoo"},
                {"domain": ["asusrouter.com", "router.asus.com", "www.asusrouter.com"], "server": "dns-home"},
                {"rule_set": "Proxy", "server": "dns-proxy"},
            ],
            "final": "dns-direct",
            "reverse_mapping": True,
            "strategy": "prefer_ipv4",
            "independent_cache": True,
        },
        "inbounds": [
            dns(),
            localhost("mixed-in"),
            localhost("direct-in", 7891),
            localhost("global-in", 7892),
            anyone("protected-in", 9999),
        ],
        "outbounds": proxies_to_outbound(clash["proxies"]),
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
                {"rule_set": "Proxy", "outbound": "🔰 默认出口"},
                {"rule_set": "Direct", "outbound": "🎯 全球直连"},
                {"inbound": "direct-in", "outbound": "🎯 全球直连"},
            ],
            "rule_set": [
                {
                    "type": "remote",
                    "tag": "AI",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/ai.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Disney+",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/disney-plus.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Netflix",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/netflix.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "TikTok",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/tiktok.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "YouTube",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/youtube.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Block",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/block.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Direct",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/direct.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Private",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/private.srs",
                    "download_detour": "DIRECT",
                },
                {
                    "type": "remote",
                    "tag": "Proxy",
                    "format": "binary",
                    "url": "https://jsd.cdn.zzko.cn/npm/sing-rules/rules/proxy.srs",
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


def main(clash_config: TextIO, sing_config: TextIO) -> None:
    clash = yaml.load(clash_config)
    sing = to_sing(clash)
    json.dump(sing, sing_config, ensure_ascii=False, indent=2)


def open_in(filename: str) -> TextIO:
    if filename == "-":
        return sys.stdin
    else:
        return open(filename)


def open_out(filename: str) -> TextIO:
    if filename == "-":
        return sys.stdout
    else:
        return open(filename, "w")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        main(sys.stdin, sys.stdout)
    elif len(sys.argv) == 2:
        main(open_in(sys.argv[1]), sys.stdout)
    elif len(sys.argv) > 2:
        main(open_in(sys.argv[1]), open_out(sys.argv[2]))
