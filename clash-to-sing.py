#!/usr/bin/env python
import base64
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

import typer
from attrs import define
from cattrs import structure

from common import (
    Object,
    SimpleObject,
    apply_to,
    compute_if_absent,
    domain_sort_key,
    get_list,
    re_match,
    simplify_dict,
    yaml,
)
from common.io import open_path
from common.object import as_hashable, copy_without_tag
from common.outbound import safe_find_country

__FLAG_MAP = {
    "AR": "🇦🇷",
    "DE": "🇩🇪",
    "EU": "🇪🇺",
    "FR": "🇫🇷",
    "HK": "🇭🇰",
    "ID": "🇮🇩",
    "IN": "🇮🇳",
    "JP": "🇯🇵",
    "KR": "🇰🇷",
    "LT": "🇱🇹",
    "MO": "🇲🇴",
    "MY": "🇲🇾",
    "NL": "🇳🇱",
    "SG": "🇸🇬",
    "TW": ["🇨🇳", "🇹🇼"],
    "UK": "🇬🇧",
    "US": "🇺🇸",
    "VN": "🇻🇳",
    "GP": ["🏳️‍🌈", "❇️"],
    "UN": "🌏",
}

__GROUP_ALIAS = {
    "HK": "香港",
    "ID": "印尼",
    "JP": "日本",
    "KR": "韩国",
    "MY": "马来西亚",
    "SG": "新加坡",
    "TW": "台湾",
    "US": "美国",
}

__GROUP_MAP = {
    "AR": "🇦🇷 阿根廷节点",
    "DE": "🇩🇪 德国节点",
    "EU": "🇪🇺 欧洲节点",
    "FR": "🇫🇷 法国节点",
    "HK": "🇭🇰 香港节点",
    "ID": "🇮🇩 印度尼西亚节点",
    "IN": "🇮🇳 印度节点",
    "JP": "🇯🇵 日本节点",
    "KR": "🇰🇷 韩国节点",
    "LT": "🇱🇹 立陶宛节点",
    "MO": "🇲🇴 澳门节点",
    "MY": "🇲🇾 马来西亚节点",
    "NL": "🇳🇱 荷兰节点",
    "SG": "🇸🇬 新加坡节点",
    "TW": "🇨🇳 台湾节点",
    "UK": "🇬🇧 英国节点",
    "US": "🇺🇸 美国节点",
    "VN": "🇻🇳 越南节点",
    "GP": "🏳️‍🌈 动态节点",
}


def __find_group(tag: str) -> str:
    if match := re.match(r"(?:IPLC)?([A-Z]{2})\w*(?:-([A-Z]{2}))?\b", tag):
        groups = match.groups()
        return groups[1] if groups[1] in __FLAG_MAP else groups[0]
    return ""


def __fix_tag(tag: str, length: int) -> str:
    if len(tag) > length and tag[length] != " ":
        return tag[:length] + " " + tag[length:]
    return tag


def find_group(tag: str) -> tuple[str, str]:
    for group, flag in __FLAG_MAP.items():
        if isinstance(flag, list):
            for f in flag:
                if tag.startswith(f):
                    return group, tag[len(flag) :].lstrip()
        elif tag.startswith(flag):
            return group, tag[len(flag) :].lstrip()
    for group, alias in __GROUP_ALIAS.items():
        if tag.startswith(alias):
            return group, __fix_tag(tag, len(alias))
    return __find_group(tag), tag


def find_cost(tag: str, cost: float = 1) -> float:
    if tag.endswith("-Direct"):
        return 0.5
    if match := re.match(r".*\s(?:\(\s*)?(\d+(?:\.\d+)?)x(?:\s*\))?\s*$", tag):
        return float(match.group(1))
    if match := re.match(r".*×(\d+(?:\.\d+)?)\s*$", tag):
        return float(match.group(1))
    return cost


def get_flag(group: str) -> str:
    flag = __FLAG_MAP.get(group, "🏳️")
    if isinstance(flag, list):
        return flag[0]
    return flag


def proxy_to_outbound(
    proxy: Object, seen: set, saved_countries: dict[str, str] | None, overwrite_country: bool
) -> tuple[bool, str, float, Object]:
    name = proxy["name"].strip().lstrip("🔴")
    group, name = find_group(name)
    cost = find_cost(name, proxy.get("cost", 1))
    tag = f"{get_flag(group)} {name}"

    outbound = {}
    match proxy["format"]:
        case "clash":
            outbound = clash_proxy_to_outbound(proxy, tag)
        case "shadowrocket":
            outbound = shadowrocket_proxy_to_outbound(proxy, tag)
        case "sing-box":
            outbound = sing_box_proxy_to_outbound(proxy, tag)
        case _:
            raise ValueError(f"Unknown proxy format: {proxy['format']}")
    patch_outbound(outbound)

    seen_key = as_hashable(copy_without_tag(outbound))
    dup = seen_key in seen
    if dup:
        return dup, group, cost, outbound
    seen.add(seen_key)

    if saved_countries is not None and (not group or group == "UN"):
        if (detected := safe_find_country(outbound)) and detected != "UN":
            group = detected
            if overwrite_country or name not in saved_countries:
                saved_countries[name] = group
            outbound["tag"] = f"{get_flag(group)} {name}"
        elif name in saved_countries:
            group = saved_countries[name]
            outbound["tag"] = f"{get_flag(group)} {name}"

    return dup, group, cost, outbound


def patch_outbound(outbound: Object):
    outbound.pop("domain_resolver", None)
    if (utls := outbound.get("tls", {}).get("utls")) and "fingerprint" in utls:
        utls["fingerprint"] = "random"


def clash_proxy_to_outbound(clash: Object, tag: str) -> Object:
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
            if "sni" in clash:
                outbound["tls"]["server_name"] = clash["sni"]
            match clash.get("network", None):
                case None:
                    pass
                case "ws":
                    transport = {
                        "type": "ws",
                    }
                    if opts := clash.get("ws-opts", {}):
                        if "path" in opts:
                            transport["path"] = opts["path"]
                        if "headers" in opts:
                            transport["headers"] = opts["headers"]
                    outbound["transport"] = transport
                case _:
                    raise ValueError(f"Unknown network '{clash['network']}'")
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
    return outbound


def shadowrocket_proxy_to_outbound(clash: Object, tag: str) -> Object:
    query: Object = clash["query"]
    struct = clash["struct"]

    def is_truthy(v) -> bool:
        return str(v).lower() in ("1", "true", "yes")

    outbound: Object = {}
    match clash["type"]:
        case "vless":
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": clash["server"],
                "server_port": clash["port"],
                "uuid": struct.username,
            }
            if "flow" in query:
                outbound["flow"] = query["flow"]
            security = query.get("security", "")
            tls: Object = {"enabled": True}
            if "sni" in query:
                tls["server_name"] = query["sni"]
            if is_truthy(query.get("insecure", 0)) or is_truthy(query.get("allowInsecure", 0)):
                tls["insecure"] = True
            if "fp" in query:
                tls["utls"] = {"enabled": True, "fingerprint": query["fp"]}
            if security == "reality":
                reality: Object = {"enabled": True}
                if "pbk" in query:
                    reality["public_key"] = query["pbk"]
                if "sid" in query:
                    reality["short_id"] = query["sid"]
                tls["reality"] = reality
            if security or "sni" in query or "fp" in query:
                outbound["tls"] = tls
            network = query.get("type", "tcp")
            if network == "ws":
                transport: Object = {"type": "ws"}
                if "path" in query:
                    transport["path"] = query["path"]
                if "host" in query and query["host"]:
                    transport["headers"] = {"Host": query["host"]}
                outbound["transport"] = transport
            elif network == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": query.get("serviceName", ""),
                }
            outbound["packet_encoding"] = "xudp"
        case "trojan":
            outbound = {
                "type": "trojan",
                "tag": tag,
                "server": clash["server"],
                "server_port": clash["port"],
                "password": struct.username,
                "tls": {"enabled": True},
            }
            sni = query.get("sni") or query.get("peer")
            if sni:
                outbound["tls"]["server_name"] = sni
            if is_truthy(query.get("allowInsecure", 0)) or is_truthy(query.get("insecure", 0)):
                outbound["tls"]["insecure"] = True
            network = query.get("type", "tcp")
            if network == "ws":
                transport: Object = {"type": "ws"}
                if "path" in query:
                    transport["path"] = query["path"]
                if "host" in query and query["host"]:
                    transport["headers"] = {"Host": query["host"]}
                outbound["transport"] = transport
        case "anytls":
            outbound = {
                "type": "anytls",
                "tag": tag,
                "server": clash["server"],
                "server_port": clash["port"],
                "password": struct.username,
                "tls": {"enabled": True},
            }
            if "sni" in query:
                outbound["tls"]["server_name"] = query["sni"]
            if is_truthy(query.get("insecure", 0)) or is_truthy(query.get("allowInsecure", 0)):
                outbound["tls"]["insecure"] = True
            if "fp" in query:
                outbound["tls"]["utls"] = {"enabled": True, "fingerprint": query["fp"]}
        case _:
            raise ValueError(f"Unknown type '{clash['type']}'")
    return outbound


def sing_box_proxy_to_outbound(sing: Object, tag: str) -> Object:
    outbound = sing["outbound"]
    outbound["tag"] = tag
    return outbound


def extract_provider_info(name: str) -> dict[str, Any] | None:
    # region ---- Ash ----
    if remaining := re_match(r"剩余流量：(\d+(?:\.\d+)?)", name):
        return {"remaining": float(remaining)}
    if reset := re_match(r"距离下次重置剩余：(\d+)", name):
        return {"reset": int(reset)}
    if expired := re_match(r"套餐到期：(\d{4}-\d{2}-\d{2})", name):
        return {"expired": datetime.fromisoformat(expired)}
    # endregion
    return None


def format_provider_info(info: dict[str, Any]) -> str:
    result = []
    flag = "🟢"

    if "reset" in info:
        reset = info["reset"]
    else:
        reset = 0

    if "expired" in info:
        expired: datetime = info["expired"]
        countdown = (expired - datetime.now()).days
    else:
        expired = None
        countdown = 0

    if "remaining" in info:
        remaining = info["remaining"]
        if remaining <= 3:
            flag = "🔴"
        elif remaining <= (2 * reset if reset else (2 * countdown if countdown and countdown <= 30 else 10)):
            flag = "🟡"
        result.append(f"{remaining:.1f}G")

    if reset:
        result.append(f"{reset}d")

    if expired:
        if countdown <= 3:
            flag = "🔴"
        elif countdown <= 7:
            flag = "🟡"
        result.append(expired.date().isoformat())

    return f"{flag} ({', '.join(result)})"


def selector(tag: str, nodes: list[str]) -> Object:
    return {"type": "selector", "tag": tag, "outbounds": nodes}


# __TEST_URL = "https://cp.cloudflare.com/generate_204"
# __TEST_URL = "https://www.apple.com/library/test/success.html"


def urltest(tag: str, costs: dict[str, float], nodes: list[str], url: str = None) -> Object:
    nodes = sorted(nodes, key=lambda node: costs.get(node, 1))
    outbound = {"type": "urltest", "tag": tag, "outbounds": nodes}
    if url:
        outbound["url"] = url
    return outbound


def is_cheap(cost):
    return cost < 1.5


def is_expansive(cost):
    return cost < 0 or cost > 1


def group_tag_adder(groups: dict[str, list[str]], tag: str, *, prepend: bool = False) -> Callable[[str], None]:
    if prepend:
        return lambda g: apply_to(groups, g, lambda l: l.insert(0, tag))
    else:
        return lambda g: get_list(groups, g).append(tag)


def add_to_group(
    groups: dict[str, list[str]],
    group: str,
    tag: str,
    *,
    prepend: bool = False,
    cost: float = None,
    protocol: str = None,
):
    add_tag = group_tag_adder(groups, tag, prepend=prepend)

    add_tag(group)
    if cost is not None:
        if is_cheap(cost):
            add_tag(f"{group} 🛢️")
        if is_expansive(cost):
            add_tag(f"{group} 👍")
    if protocol:
        match protocol:
            case "anytls":
                add_tag(f"{group} 🐍")
            case "hysteria2":
                add_tag(f"{group} 🌪️")
            case "shadowsocks":
                add_tag(f"{group} 🚀")
            case "trojan":
                add_tag(f"{group} 🐴")
            case "tuic":
                add_tag(f"{group} 🦬")
            case "vless":
                add_tag(f"{group} 🦢")
            case "vmess":
                add_tag(f"{group} 🐙")


def clean_keys(d: dict[str, Any]) -> dict[str, Any]:
    keys_to_remove = []
    for key, value in d.items():
        if not value:
            keys_to_remove.append(key)
        for icon in (" 🛢️", " 👍", " 🌪️", " 🚀", " 🐴", " 🦬", " 🪶", " 🎯"):
            if key.endswith(icon):
                break
            if (new_key := key + icon) in d and value == d[new_key]:
                keys_to_remove.append(new_key)
    for key in keys_to_remove:
        del d[key]
    return d


def as_ip(hostname):
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def proxies_to_outbound(
    local: bool, proxies: list[Object], saved_countries: dict[str, str] | None, overwrite_country: bool
) -> tuple[list[SimpleObject], set[str], set[str], Object]:
    outbounds = []
    domains = set()
    ips = set()
    costs: dict[str, float] = {}

    all_nodes = []
    cheap_nodes = []
    expansive_nodes = []
    other_nodes = []
    groups: dict[str, list[str]] = {
        "🇺🇸 美国节点": [],
        "🇺🇸 美国节点 👍": [],
        "🇺🇸 美国节点 🛢️": [],
        "🇺🇸 美国节点 🌪️": [],
        "🇺🇸 美国节点 🚀": [],
        "🇺🇸 美国节点 🐴": [],
        "🇺🇸 美国节点 🦬": [],
        "🇺🇸 美国节点 🪶": [],
        "🇺🇸 美国节点 🎯": [],
    }

    if local:
        outbounds = [
            {"type": "http", "tag": "⛰️ Gingkoo", "server": "10.1.2.12", "server_port": 8118},
            {"type": "socks", "tag": "🧅 Tor Browser", "server": "127.0.0.1", "server_port": 9150},
        ]
        costs = {"⛰️ Gingkoo": 0, "🧅 Tor Browser": 0}

    outbounds.append({"type": "http", "tag": "🐱 LazyCat", "server": "127.0.0.1", "server_port": 31085})
    outbounds.append({"type": "http", "tag": "💻 中间人", "server": "127.0.0.1", "server_port": 7899})
    outbounds.append({"type": "http", "tag": "🏢 中间人", "server": "10.2.20.248", "server_port": 7899})
    outbounds.append({"type": "http", "tag": "🏠 中间人 Wi-Fi", "server": "192.168.50.78", "server_port": 7899})
    outbounds.append({"type": "http", "tag": "🏠 中间人 Wired", "server": "192.168.50.80", "server_port": 7899})

    seen = set()
    providers = {}
    provider_info_dict = {}
    embies = {}

    for proxy in proxies:
        server = proxy["server"]
        if server == "None":
            continue

        if "provider" in proxy:
            provider: dict = proxy["provider"]
            provider_name = provider["name"]

            if (info := provider["info"]) and provider_name not in provider_info_dict:
                provider_info_dict[provider_name] = info.as_provider_info()

            if extracted := extract_provider_info(proxy["name"]):
                provider_info = compute_if_absent(provider_info_dict, provider_name, lambda: {})
                provider_info.update(extracted)
                continue
        else:
            provider = {}
            provider_name = ""

        dup, group, cost, outbound = proxy_to_outbound(proxy, seen, saved_countries, overwrite_country)
        if dup:
            continue

        outbounds.append(outbound)
        ip = as_ip(server)
        if isinstance(ip, ipaddress.IPv4Address):
            ips.add(server + "/32")
        elif isinstance(ip, ipaddress.IPv6Address):
            ips.add(server + "/128")
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
            if group in ("DE", "FR", "LT", "NL", "UK"):
                add_to_group(groups, __GROUP_MAP["EU"], tag, cost=cost)
            add_to_group(groups, __GROUP_MAP[group], tag, cost=cost)
        else:
            other_nodes.append(tag)

        if provider:
            add_to_group(providers, provider_name, tag, cost=cost)

            if (emby := provider["emby"]) and provider_name not in embies:
                embies[provider_name] = {"name": emby_name(provider_name), "config": emby}

    if other_nodes:
        groups["🏳️ 其它节点"] = other_nodes
    clean_keys(groups)
    clean_keys(providers)
    groups = reorder(groups)
    group_tags = ["🍑 自由切换", *providers, *groups, "🔍 调试出口"]

    if cheap_nodes and cheap_nodes != all_nodes:
        cheap_tag = ["🛢️ 省流节点"]
        if local:
            cheap_nodes[0:0] = ["⛰️ Gingkoo", "🧅 Tor Browser"]
    else:
        cheap_tag = []

    if expansive_nodes and expansive_nodes != all_nodes:
        expansive_tag = ["👍 高级节点"]
        if local:
            expansive_nodes[0:0] = ["⛰️ Gingkoo"]
    else:
        expansive_tag = []

    auto_nodes = all_nodes
    if local:
        auto_nodes = ["⛰️ Gingkoo", *auto_nodes]
        all_nodes[0:0] = ["⛰️ Gingkoo", "🧅 Tor Browser"]
        add_to_group(groups, __GROUP_MAP["US"], "⛰️ Gingkoo", prepend=True, cost=-1)

    outbounds.append(
        selector("🔰 默认出口", [*cheap_tag, *expansive_tag, "♻️ 自动选择", "🚀 手动切换", *group_tags, "DIRECT"])
    )

    outbounds.append(urltest("♻️ 自动选择", costs, auto_nodes))
    outbounds.append(selector("🚀 手动切换", all_nodes))
    outbounds.append(selector("🍑 自由切换", all_nodes))
    count = 0
    if cheap_tag:
        outbounds.append(urltest(cheap_tag[0], costs, cheap_nodes))
        count += 1
    if expansive_tag:
        outbounds.append(urltest(expansive_tag[0], costs, expansive_nodes))
        count += 1

    for tag, provider_info in provider_info_dict.items():
        outbounds.append(selector(f"{tag} {format_provider_info(provider_info)}", [tag]))
    count += len(provider_info_dict)

    emby_groups: dict[str, Object] = {}
    for provider_name, emby in embies.items():
        emby_tag = f"{provider_name} 🎬"
        filtered_tags = emby_filter(provider_name, emby, group_tags)
        emby_nodes: list[str] = []
        seen_nodes: set[str] = set()
        for tag in filtered_tags:
            for node in groups.get(tag) or []:
                if node not in seen_nodes and is_cheap(costs[node]):
                    seen_nodes.add(node)
                    emby_nodes.append(node)
        emby_url = emby["config"].test_url()
        emby_groups[provider_name] = urltest(emby_tag, costs, emby_nodes, url=emby_url)
        outbounds.append(
            selector(
                emby["name"],
                [
                    emby_tag,
                    "🔰 默认出口",
                    "DIRECT",
                    *expansive_tag,
                    *filtered_tags,
                ],
            )
        )
    count += len(embies)

    if count % 2 == 0:
        outbounds.append(selector("⬛ --------", ["🔰 默认出口"]))
        # outbounds.append(selector("⬜ --------", ["🔰 默认出口"]))

    direct_tags = ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]
    proxy_tags = ["🔰 默认出口", "DIRECT", *expansive_tag, *group_tags]

    ai_tags = prioritize(proxy_tags, "🇺🇸 美国节点")
    playstation_tags = prioritize(proxy_tags, "🇭🇰 香港节点")

    lazycat_tags = ["DIRECT", "🐱 LazyCat"]
    mitm_tags = ["DIRECT", "💻 中间人", "🏢 中间人", "🏠 中间人 Wi-Fi", "🏠 中间人 Wired"]

    outbounds.append(selector("🤖 AI", ai_tags))
    outbounds.append(selector("🤖 Claude", ["🤖 自然选择 Claude", *ai_tags]))
    outbounds.append(selector("🤖 ChatGPT", ["🤖 自然选择 ChatGPT", *ai_tags]))

    outbounds.append(selector("🍎 Apple", direct_tags))
    outbounds.append(selector("Ⓜ️ Microsoft", direct_tags))
    outbounds.append(selector("⚙️ Development", proxy_tags))
    outbounds.append(selector("📦 Sources", direct_tags))

    outbounds.append(selector("🎮 Nintendo", proxy_tags))
    outbounds.append(selector("🎮 Nintendo@CN", direct_tags))
    outbounds.append(selector("🎮 PlayStation", playstation_tags))
    outbounds.append(selector("🎮 PlayStation@CN", direct_tags))
    outbounds.append(selector("🎮 Steam", proxy_tags))
    outbounds.append(selector("🎮 Steam@CN", direct_tags))
    outbounds.append(selector("🎮 Xbox", proxy_tags))
    outbounds.append(selector("🎮 Xbox@CN", direct_tags))
    outbounds.append(selector("🎮 Games", proxy_tags))
    outbounds.append(selector("🎮 Games@CN", direct_tags))
    outbounds.append(selector("🎥 Disney+", proxy_tags))
    outbounds.append(selector("🎥 Netflix", proxy_tags))
    outbounds.append(selector("🎥 TikTok", ai_tags))
    outbounds.append(selector("🎥 YouTube", proxy_tags))

    outbounds.append(selector("🐱 懒猫微服", lazycat_tags))
    outbounds.append(selector("🔍 调试出口", mitm_tags))

    outbounds.append(selector("🎯 全球直连", ["DIRECT", "🔰 默认出口"]))
    outbounds.append(selector("🛑 全球拦截", ["REJECT", "🔰 默认出口", "DIRECT"]))
    outbounds.append(selector("👻 透明代理", ["DIRECT", "🔰 默认出口", "REJECT"]))
    outbounds.append(selector("🐟 漏网之鱼", ["🔰 默认出口", "DIRECT", "REJECT"]))

    outbounds.append(urltest("🤖 自然选择 Claude", costs, groups["🇺🇸 美国节点"], "https://api.anthropic.com/"))
    outbounds.append(urltest("🤖 自然选择 ChatGPT", costs, groups["🇺🇸 美国节点"], "https://api.openai.com/"))

    emitted_providers: set[str] = set()
    for tag, nodes in providers.items():
        if tag in emitted_providers:
            continue
        outbounds.append(urltest(tag, costs, nodes))
        emitted_providers.add(tag)
        for suffix in (" 🛢️", " 👍"):
            variant = tag + suffix
            if variant in providers and variant not in emitted_providers:
                outbounds.append(urltest(variant, costs, providers[variant]))
                emitted_providers.add(variant)
        if tag in emby_groups:
            outbounds.append(emby_groups[tag])

    for tag, nodes in groups.items():
        outbounds.append(urltest(tag, costs, nodes))

    outbounds.append(selector("GLOBAL", [*all_nodes]))

    return outbounds, domains, ips, embies


def prioritize(tags, prefix, *prepend):
    head = [x for x in tags if x.startswith(prefix)]
    tail = [x for x in tags if not x.startswith(prefix)]
    return [*prepend, *head, *tail]


def emby_name(name):
    if len(name) > 2 and name[0] != " " and name[1] == " ":
        return "🎬 Emby " + name[2:]
    return "🎬 Emby " + name


def emby_filter(name, emby, tags):
    return [tag for tag in tags if all(e not in tag for e in emby["config"].exclude)]


def reorder(groups: dict[str, list[str]]) -> dict[str, list[str]]:
    result_groups = {}
    other_tags = []
    other_groups = {}
    last_groups = {}
    for k, v in groups.items():
        if k.startswith("🇺🇸 美国节点"):
            result_groups[k] = v
        elif k == "🏳️ 其它节点":
            last_groups[k] = v
        else:
            other_tags.append(k)
            other_groups[k] = v
    for k in sorted(other_tags):
        result_groups[k] = other_groups[k]
    result_groups.update(last_groups)
    return result_groups


def as_tuple(ip):
    network = ipaddress.ip_network(ip, strict=False)
    return network.version, network.network_address.packed, network.prefixlen


def build_emby_ipcheck(embies, index=1):
    rules = []
    for _, emby in embies.items():
        rules.append({"domain": f"ptest-{index}.ipcheck.ing", "outbound": emby["name"]})
        if (index := index + 1) > 8:
            break
    return rules


def build_direct_rules(direct: bool):
    if direct:
        return [
            {"network": "icmp", "outbound": "DIRECT"},
            {"protocol": ["bittorrent", "ntp", "stun"], "outbound": "DIRECT"},
            {"ip_is_private": True, "outbound": "DIRECT"},
        ]
    else:
        return []


def build_proxies_rules(domains, ips):
    rules = []
    if domains or ips:
        direct: Object = {
            "outbound": "DIRECT",
        }
        if domains:
            direct["domain"] = sorted(domains, key=domain_sort_key)
        if ips:
            direct["ip_cidr"] = sorted(ips, key=as_tuple)
        rules.append(direct)
    return rules


def build_local_rules(local: bool):
    if not local:
        return []
    return [
        {"rule_set": "AI:Direct", "outbound": "DIRECT"},
        {"rule_set": "AI:Process", "outbound": "🤖 人工智能"},
    ]


def build_emby_rules(embies):
    rules = []
    for _, emby in embies.items():
        rules.append({"domain": emby["config"].domain, "outbound": emby["name"]})
    return rules


def build_local_rule_sets(local: bool, gitee_token: str | None):
    if not local:
        return []
    return [
        rule_set(local, gitee_token, "AI:Direct", "rules/ai-direct.srs"),
        rule_set(local, gitee_token, "AI:Process", "rules/ai-proc.srs"),
    ]


# __CDN = "cdn.jsdelivr.net"
__CDN = "fastly.jsdelivr.net"
# __CDN = "cdn.jsdmirror.com"
# __CDN = "cdn.jsdmirror.cn"


def rule_set(local: bool, gitee_token: str | None, tag: str, url: str):
    # noinspection HttpUrlsUsage
    if url.startswith("http://") or url.startswith("https://"):
        url_to_use = url
    elif gitee_token:
        url_to_use = f"https://gitee.com/api/v5/repos/moonfruit/private/raw/{url}?access_token={gitee_token}&ref=main"
    else:
        url_to_use = f"https://{__CDN}/npm/sing-rules/{url}"

    if url.endswith(".json"):
        format_to_use = "source"
    else:
        format_to_use = "binary"

    if local:
        options = {}
    else:
        options = {"download_detour": "DIRECT"}

    return {
        "type": "remote",
        "tag": tag,
        "format": format_to_use,
        "url": url_to_use,
        **options,
    }


def to_sing(
    proxies: list[SimpleObject],
    local: bool,
    direct: bool,
    saved_countries: dict[str, str] | None,
    overwrite_country: bool,
    gitee_token: str | None,
) -> Object:
    outbounds, domains, ips, embies = proxies_to_outbound(local, proxies, saved_countries, overwrite_country)
    return {
        "outbounds": outbounds,
        "route": {
            "rules": [
                *build_direct_rules(direct),
                {"domain": "connectivitycheck.gstatic.com", "outbound": "🐟 漏网之鱼"},
                {"domain": ["4.ipcheck.ing", "6.ipcheck.ing"], "outbound": "DIRECT"},
                {
                    "domain": ["api.ip.sb", "api.ipapi.is"],
                    "ip_cidr": ["1.0.0.2/32", "2606:4700:4700::1111/128"],
                    "outbound": "🔰 默认出口",
                },
                {"domain": "ptest-1.ipcheck.ing", "outbound": "🤖 AI"},
                {"domain": "ptest-2.ipcheck.ing", "outbound": "🤖 Claude"},
                {"domain": "ptest-3.ipcheck.ing", "outbound": "🤖 ChatGPT"},
                *build_emby_ipcheck(embies, 4),
                {"domain_suffix": ["heiyu.space", "lazycat.cloud"], "outbound": "🐱 懒猫微服"},
                *build_proxies_rules(domains, ips),
                {"rule_set": "Private", "outbound": "🎯 全球直连"},
                {"rule_set": "Block", "outbound": "🛑 全球拦截"},
                # *build_local_rules(local),
                {"rule_set": "Anthropic", "outbound": "🤖 Claude"},
                {"rule_set": "OpenAI", "outbound": "🤖 ChatGPT"},
                {"rule_set": "AI", "outbound": "🤖 AI"},
                {"rule_set": "Apple", "outbound": "🍎 Apple"},
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {"rule_set": "Microsoft"},
                        {"rule_set": ["AI", "Development", "Sources", "Xbox"], "invert": True},
                    ],
                    "outbound": "Ⓜ️ Microsoft",
                },
                {"rule_set": "Development@CN", "outbound": "🎯 全球直连"},
                {"rule_set": "Development", "outbound": "⚙️ Development"},
                {"rule_set": "Sources", "outbound": "📦 Sources"},
                {"rule_set": "Nintendo@CN", "outbound": "🎮 Nintendo@CN"},
                {"rule_set": "Nintendo", "outbound": "🎮 Nintendo"},
                {"rule_set": "PlayStation@CN", "outbound": "🎮 PlayStation@CN"},
                {"rule_set": "PlayStation", "outbound": "🎮 PlayStation"},
                {"rule_set": "Steam@CN", "outbound": "🎮 Steam@CN"},
                {"rule_set": "Steam", "outbound": "🎮 Steam"},
                {"rule_set": "Xbox@CN", "outbound": "🎮 Xbox@CN"},
                {"rule_set": "Xbox", "outbound": "🎮 Xbox"},
                {"rule_set": "Games@CN", "outbound": "🎮 Games@CN"},
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [{"rule_set": "Games"}, {"rule_set": ["GFW", "Proxy"]}],
                    "outbound": "🎮 Games",
                },
                {"rule_set": "Disney+", "outbound": "🎥 Disney+"},
                {"rule_set": "Netflix", "outbound": "🎥 Netflix"},
                {"rule_set": "TikTok", "outbound": "🎥 TikTok"},
                {"rule_set": "YouTube", "outbound": "🎥 YouTube"},
                *build_emby_rules(embies),
                {"rule_set": "GFW", "outbound": "🔰 默认出口"},
                {"rule_set": ["Direct", "GeoIP@CN", "GeoSites@CN"], "outbound": "🎯 全球直连"},
                {"rule_set": "Proxy", "outbound": "🔰 默认出口"},
                {"inbound": ["direct-in", "redirect-in", "tproxy-in", "tun-in"], "outbound": "👻 透明代理"},
            ],
            "rule_set": [
                rule_set(local, gitee_token, "AI", "rules/ai.srs"),
                rule_set(local, gitee_token, "Anthropic", "rules/anthropic.srs"),
                rule_set(local, gitee_token, "Apple", "rules/apple.srs"),
                rule_set(local, gitee_token, "Block", "rules/block.srs"),
                rule_set(local, gitee_token, "Development", "rules/dev.srs"),
                rule_set(local, gitee_token, "Development@CN", "rules/dev-cn.srs"),
                rule_set(local, gitee_token, "Direct", "rules/direct.srs"),
                rule_set(local, gitee_token, "Disney+", "rules/disney-plus.srs"),
                rule_set(local, gitee_token, "GFW", "rules/gfw.srs"),
                rule_set(local, gitee_token, "Games", "rules/games.srs"),
                rule_set(local, gitee_token, "Games@CN", "rules/games-cn.srs"),
                rule_set(local, gitee_token, "GeoIP@CN", "rules/geoip-cn.srs"),
                rule_set(local, gitee_token, "GeoSites@CN", "rules/geosites-cn.srs"),
                rule_set(local, gitee_token, "Microsoft", "rules/microsoft.srs"),
                rule_set(local, gitee_token, "Netflix", "rules/netflix.srs"),
                rule_set(local, gitee_token, "Nintendo", "rules/nintendo.srs"),
                rule_set(local, gitee_token, "Nintendo@CN", "rules/nintendo-cn.srs"),
                rule_set(local, gitee_token, "OpenAI", "rules/openai.srs"),
                rule_set(local, gitee_token, "PlayStation", "rules/playstation.srs"),
                rule_set(local, gitee_token, "PlayStation@CN", "rules/playstation-cn.srs"),
                rule_set(local, gitee_token, "Private", "rules/private.srs"),
                rule_set(local, gitee_token, "Proxy", "rules/proxy.srs"),
                rule_set(local, gitee_token, "Sources", "rules/sources.srs"),
                rule_set(local, gitee_token, "Steam", "rules/steam.srs"),
                rule_set(local, gitee_token, "Steam@CN", "rules/steam-cn.srs"),
                rule_set(local, gitee_token, "TikTok", "rules/tiktok.srs"),
                rule_set(local, gitee_token, "Xbox", "rules/xbox.srs"),
                rule_set(local, gitee_token, "Xbox@CN", "rules/xbox-cn.srs"),
                rule_set(local, gitee_token, "YouTube", "rules/youtube.srs"),
                # *build_local_rule_sets(local, gitee_token),
            ],
            "final": "🐟 漏网之鱼",
        },
    }


@define(frozen=True)
class ConfigEmby:
    domain: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    url: str = ""

    def test_url(self) -> str | None:
        if self.url:
            return self.url
        if self.domain:
            return f"https://{self.domain[0]}/"
        return None


@define(frozen=True)
class ConfigInfo:
    upload: int
    download: int
    total: int
    expire: int

    def as_provider_info(self):
        result = {}
        if self.total > 0:
            result["remaining"] = (self.total - self.upload - self.download) / 1024 / 1024 / 1024
        if self.expire > 0:
            result["expired"] = datetime.fromtimestamp(self.expire)
        return result


@define
class ConfigFile:
    path: Path
    name: str = None
    cost: float = 1
    format: str = "clash"
    info: ConfigInfo = None
    emby: ConfigEmby = None


def load_config_files(path: Path) -> list[ConfigFile]:
    with open_path(path) as f:
        configs = json.load(f)
    result = structure(configs, list[ConfigFile])
    for config in result:
        if config.info is None:
            config.info = load_config_info(config.path)
    return result


def load_config_info(path: Path) -> ConfigInfo | None:
    info_path = path.with_name(f"{path.name}.info")
    if not info_path.is_file():
        return None
    with open(info_path) as f:
        text = f.read().strip()
    data = {}
    for part in text.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            data[key.strip()] = int(value.strip())
    return ConfigInfo(
        upload=data.get("upload", 0),
        download=data.get("download", 0),
        total=data.get("total", 0),
        expire=data.get("expire", 0),
    )


def load_clash_proxies(path: Path) -> list[SimpleObject]:
    with open_path(path) as f:
        clash = yaml.load(f)
    if "proxies" not in clash:
        return []
    return clash["proxies"]


def load_shadowrocket_proxies(path: Path) -> list[SimpleObject]:
    with open_path(path) as f:
        data = f.read()
    lines = base64.b64decode(data).decode().splitlines()
    proxies = []
    for index, line in enumerate(lines):
        if line.startswith("STATUS="):
            continue
        if "#" in line:
            url, name = line.split("#", 1)
            name = unquote(name)
        else:
            url = line
            name = "Line#{}".format(index)
        parsed = urlparse(url)
        proxies.append(
            {
                "url": line,
                "name": name,
                "type": parsed.scheme,
                "server": parsed.hostname,
                "port": parsed.port,
                "query": simplify_dict(parse_qs(parsed.query)),
                "struct": parsed,
            }
        )
    return proxies


def load_sing_box_proxies(path: Path) -> list[Object]:
    with open_path(path) as f:
        config = json.load(f)
    if "outbounds" not in config:
        return []
    return [
        {"name": outbound["tag"], "server": outbound["server"], "outbound": outbound}
        for outbound in config["outbounds"]
        if outbound["type"] not in ("direct", "selector", "urltest")
    ]


def load_proxies(config: ConfigFile) -> list[Object]:
    if config.cost <= 0:
        return []
    proxies: list[Object] = []
    match config.format:
        case "clash":
            proxies = load_clash_proxies(config.path)
        case "shadowrocket":
            proxies = load_shadowrocket_proxies(config.path)
        case "sing-box":
            proxies = load_sing_box_proxies(config.path)
        case _:
            raise ValueError(f"Unknown format: {config.format}")
    for proxy in proxies:
        if config.name:
            proxy["provider"] = {
                "name": config.name,
                "info": config.info,
                "emby": config.emby,
            }
        proxy["cost"] = config.cost
        proxy["format"] = config.format
    return proxies


def load_countries(saved_country: Path | None) -> dict[str, str]:
    if saved_country and saved_country.exists():
        with saved_country.open() as f:
            return json.load(f)
    return {}


def save_countries(saved_country: Path | None, saved_countries):
    if saved_country:
        with saved_country.open("w") as f:
            json.dump(saved_countries, f, ensure_ascii=False, indent=2, sort_keys=True)


def main(
    filenames: Annotated[
        list[Path], typer.Argument(show_default=False, exists=True, dir_okay=False, readable=True)
    ] = None,
    configs: Annotated[
        list[Path], typer.Option("--config", "-c", show_default=False, exists=True, dir_okay=False, readable=True)
    ] = None,
    output: Annotated[Path, typer.Option("--output", "-o", dir_okay=False, writable=True)] = Path("-"),
    local: Annotated[bool, typer.Option("--local", "-l")] = False,
    direct: Annotated[bool, typer.Option("--direct", "-d")] = False,
    resolve_country: Annotated[bool, typer.Option("--resolve-country", "-r")] = False,
    saved_country: Annotated[Path, typer.Option("--saved-country", "-s")] = None,
    overwrite_country: Annotated[bool, typer.Option("--overwrite-country", "-w")] = False,
    gitee_token: Annotated[str, typer.Option("--gitee-token", "-t")] = None,
):
    config_files = [ConfigFile(f) for f in filenames] if filenames else []
    if configs:
        for config in configs:
            config_files.extend(load_config_files(config))
    proxies = sum([load_proxies(config) for config in config_files], start=[])
    if not proxies:
        raise ValueError("No proxies found")

    saved_countries = load_countries(saved_country) if resolve_country else None

    if local:
        direct = False
    sing = to_sing(proxies, local, direct, saved_countries, overwrite_country, gitee_token)
    with open_path(output, "w") as f:
        # noinspection PyTypeChecker
        json.dump(sing, f, ensure_ascii=False, indent=2)

    if resolve_country:
        save_countries(saved_country, saved_countries)


if __name__ == "__main__":
    typer.run(main)
