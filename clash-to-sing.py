#!/usr/bin/env python
import base64
import ipaddress
import json
import re
from pathlib import Path
from typing import Annotated, Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

import typer
from attrs import define
from cattrs import structure

from common import Object, SimpleObject, apply_to, get_list, simplify_dict, yaml
from common.io import open_path
from common.outbound import safe_find_country

__FLAG_MAP = {
    "AR": "🇦🇷",
    "EU": "🇪🇺",
    "HK": "🇭🇰",
    "ID": "🇮🇩",
    "JP": "🇯🇵",
    "KR": "🇰🇷",
    "MY": "🇲🇾",
    "SG": "🇸🇬",
    "TW": ["🇨🇳", "🇹🇼"],
    "UK": "🇬🇧",
    "US": "🇺🇸",
    "VN": "🇻🇳",
    "UN": "❇️",
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
    "AR": "🇦🇷 阿根廷节点",
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
    match = re.match(r".*\s(?:\(\s*)?(\d+(?:\.\d+)?)x(?:\s*\))?\s*$", tag)
    return float(match.group(1)) if match else cost


def get_flag(group: str) -> str:
    flag = __FLAG_MAP.get(group, "🏳️")
    return isinstance(flag, list) and flag[0] or flag


def proxy_to_outbound(proxy: Object, resolve_country: bool | None) -> tuple[str, float, Object]:
    name = proxy["name"].strip()
    group, name = find_group(name)
    cost = find_cost(name, proxy.get("cost", 1))
    tag = f"{get_flag(group)} {name}"

    outbound = {}
    match proxy["format"]:
        case "clash":
            outbound = clash_proxy_to_outbound(proxy, tag)
        case "sing-box":
            outbound = sing_box_proxy_to_outbound(proxy, tag)
        case _:
            raise ValueError(f"Unknown proxy format: {proxy['format']}")

    if resolve_country and (not group or group == "UN"):
        # noinspection PyBroadException
        group = safe_find_country(outbound)
        if group != "UN":
            outbound["tag"] = f"{get_flag(group)} {name}"

    return group, cost, outbound


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
                    opts = clash.get("ws-opts", {})
                    if opts:
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


def sing_box_proxy_to_outbound(sing: Object, tag: str) -> Object:
    outbound = sing["outbound"]
    outbound["tag"] = tag
    return outbound


def selector(tag: str, nodes: list[str]) -> Object:
    return {"type": "selector", "tag": tag, "outbounds": nodes}


def urltest(tag: str, costs: dict[str, float], nodes: list[str]) -> Object:
    nodes = sorted(nodes, key=lambda node: costs.get(node, 1))
    return {"type": "urltest", "tag": tag, "outbounds": nodes, "interval": "10m0s"}


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
            case "hysteria2":
                add_tag(f"{group} 🌪️")
            case "shadowsocks":
                add_tag(f"{group} 🚀")
            case "trojan":
                add_tag(f"{group} 🐴")
            case "vmess":
                add_tag(f"{group} 🎯")


def clean_keys(d: dict[str, Any]) -> dict[str, Any]:
    keys_to_remove = []
    for key, value in d.items():
        if not value:
            keys_to_remove.append(key)
        for icon in (" 🛢️", " 👍", " 🌪️", " 🚀", " 🐴", " 🎯"):
            if key.endswith(icon):
                break
            new_key = key + icon
            if new_key in d and value == d[new_key]:
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


def proxies_to_outbound(
    local: bool, proxies: list[SimpleObject], resolve_country: bool | None
) -> tuple[list[SimpleObject], set[str], set[str]]:

    outbounds = []
    domains = set()
    ips = set()
    costs: dict[str, float] = {}

    all_nodes = []
    cheap_nodes = []
    expansive_nodes = []
    other_nodes = []
    groups = {
        "🇺🇸 美国节点": [],
        "🇺🇸 美国节点 🛢️": [],
        "🇺🇸 美国节点 👍": [],
        "🇺🇸 美国节点 🌪️": [],
        "🇺🇸 美国节点 🚀": [],
        "🇺🇸 美国节点 🐴": [],
        "🇺🇸 美国节点 🎯": [],
    }

    if local:
        outbounds = [
            {"type": "http", "tag": "⛰️ Gingkoo", "server": "10.1.2.12", "server_port": 8118},
            {"type": "socks", "tag": "🧅 Tor Browser", "server": "127.0.0.1", "server_port": 9150},
        ]
        costs = {"⛰️ Gingkoo": 0, "🧅 Tor Browser": 0}

    outbounds.append({"type": "http", "tag": "🐱 LazyCat", "server": "127.0.0.1", "server_port": 31085})
    outbounds.append({"type": "socks", "tag": "🐱 LazyCat(S)", "server": "127.0.0.1", "server_port": 31086})

    providers = {}

    for proxy in proxies:
        server = proxy["server"]
        if server == "None":
            continue
        group, cost, outbound = proxy_to_outbound(proxy, resolve_country)
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
                add_to_group(groups, __GROUP_MAP[group], tag, cost=cost, protocol=outbound["type"])
            else:
                if group == "UK":
                    add_to_group(groups, __GROUP_MAP["EU"], tag)
                add_to_group(groups, __GROUP_MAP[group], tag)
        else:
            other_nodes.append(tag)

        if "provider" in proxy:
            provider = proxy["provider"]
            add_to_group(providers, provider, tag, cost=cost)

    if other_nodes:
        groups["🏳️ 其它节点"] = other_nodes
    clean_keys(groups)
    clean_keys(providers)
    group_tags = ["🍑 自由切换", *providers, *groups]

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

    if local:
        all_nodes[0:0] = ["⛰️ Gingkoo", "🧅 Tor Browser"]
        other_nodes[0:0] = ["🧅 Tor Browser"]
        add_to_group(groups, __GROUP_MAP["US"], "⛰️ Gingkoo", prepend=True, cost=-1)

    outbounds.append(
        selector("🔰 默认出口", [*cheap_tag, *expansive_tag, "♻️ 自动选择", "🚀 手动切换", *group_tags, "DIRECT"])
    )

    outbounds.append(urltest("♻️ 自动选择", costs, all_nodes))
    outbounds.append(selector("🚀 手动切换", all_nodes))
    outbounds.append(selector("🍑 自由切换", all_nodes))
    if cheap_tag:
        outbounds.append(urltest(cheap_tag[0], costs, cheap_nodes))
    if expansive_tag:
        outbounds.append(urltest(expansive_tag[0], costs, expansive_nodes))

    if "🇺🇸 美国节点" in group_tags:
        us_tags = [tag for tag in group_tags if tag.startswith("🇺🇸 美国节点")]
        not_us_tags = [tag for tag in group_tags if not tag.startswith("🇺🇸 美国节点")]
        ai_tags = [*us_tags, "🔰 默认出口", *expansive_tag, *not_us_tags, "DIRECT"]
    else:
        ai_tags = ["🔰 默认出口", *expansive_tag, *group_tags, "DIRECT"]

    outbounds.append(selector("🤖 人工智能", ai_tags))
    outbounds.append(selector("🐱 懒猫微服", ["DIRECT", "🐱 LazyCat", "🐱 LazyCat(S)"]))
    outbounds.append(selector("🍎 苹果服务", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("Ⓜ️ 微软服务", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("⚙️ 软件开发", ["🔰 默认出口", "DIRECT", *expansive_tag, *group_tags]))
    outbounds.append(selector("📦 软件仓库", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 Nintendo", ["🔰 默认出口", "DIRECT", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 Nintendo@CN", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 PlayStation", ["🔰 默认出口", "DIRECT", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 PlayStation@CN", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 Steam", ["🔰 默认出口", "DIRECT", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 Steam@CN", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 Games", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎮 Games@CN", ["DIRECT", "🔰 默认出口", *expansive_tag, *group_tags]))
    outbounds.append(selector("🎥 Disney+", ["🔰 默认出口", *expansive_tag, "DIRECT", *group_tags]))
    outbounds.append(selector("🎥 Netflix", ["🔰 默认出口", *expansive_tag, "DIRECT", *group_tags]))
    outbounds.append(selector("🎥 TikTok", ["🔰 默认出口", *expansive_tag, "DIRECT", *group_tags]))
    outbounds.append(selector("🎥 YouTube", ["🔰 默认出口", *expansive_tag, "DIRECT", *group_tags]))

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
    rules = [{"ip_is_private": True, "outbound": "DIRECT"}]
    if domains or ips:
        direct: Object = {
            "outbound": "DIRECT",
        }
        if domains:
            direct["domain"] = sorted(domains)
        if ips:
            direct["ip_cidr"] = sorted(ips, key=as_tuple)
        rules.append(direct)
    return rules


def build_local_rules(local: bool):
    if not local:
        return []
    return [{"rule_set": "AI:Process", "outbound": "🤖 人工智能"}]


def build_local_rule_sets(local: bool, gitee_token: str | None):
    if not local:
        return []
    return [rule_set(gitee_token, "AI:Process", "rules/ai-proc.srs")]


# __CDN = "cdn.jsdelivr.net"
__CDN = "fastly.jsdelivr.net"
# __CDN = "cdn.jsdmirror.com"
# __CDN = "cdn.jsdmirror.cn"


def rule_set(gitee_token: str | None, tag: str, url: str):
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

    return {
        "type": "remote",
        "tag": tag,
        "format": format_to_use,
        "url": url_to_use,
        "download_detour": "DIRECT",
    }


def to_sing(proxies: list[SimpleObject], local: bool, resolve_country: bool | None, gitee_token: str | None) -> Object:
    outbounds, domains, ips = proxies_to_outbound(local, proxies, resolve_country)
    return {
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"domain": "connectivitycheck.gstatic.com", "outbound": "🐟 漏网之鱼"},
                {"domain": ["api.ip.sb", "api.ipapi.is"], "outbound": "🔰 默认出口"},
                {"domain_suffix": ["heiyu.space", "lazycat.cloud"], "outbound": "🐱 懒猫微服"},
                *build_direct_rules(domains, ips),
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
                {"inbound": ["direct-in", "redirect-in", "tproxy-in", "tun-in"], "outbound": "👻 透明代理"},
            ],
            "rule_set": [
                rule_set(gitee_token, "AI", "rules/ai.srs"),
                rule_set(gitee_token, "Apple", "rules/apple.srs"),
                rule_set(gitee_token, "Block", "rules/block.srs"),
                rule_set(gitee_token, "Development", "rules/dev.srs"),
                rule_set(gitee_token, "Development@CN", "rules/dev-cn.srs"),
                rule_set(gitee_token, "Direct", "rules/direct.srs"),
                rule_set(gitee_token, "Disney+", "rules/disney-plus.srs"),
                rule_set(gitee_token, "Games", "rules/games.srs"),
                rule_set(gitee_token, "Games@CN", "rules/games-cn.srs"),
                rule_set(gitee_token, "GFW", "rules/gfw.srs"),
                rule_set(gitee_token, "Microsoft", "rules/microsoft.srs"),
                rule_set(gitee_token, "Minecraft", "rules/minecraft.srs"),
                rule_set(gitee_token, "Netflix", "rules/netflix.srs"),
                rule_set(gitee_token, "Nintendo", "rules/nintendo.srs"),
                rule_set(gitee_token, "Nintendo@CN", "rules/nintendo-cn.srs"),
                rule_set(gitee_token, "PlayStation", "rules/playstation.srs"),
                rule_set(gitee_token, "PlayStation@CN", "rules/playstation-cn.srs"),
                rule_set(gitee_token, "Porn", "rules/porn.srs"),
                rule_set(gitee_token, "Private", "rules/private.srs"),
                rule_set(gitee_token, "Proxy", "rules/proxy.srs"),
                rule_set(gitee_token, "Sources", "rules/sources.srs"),
                rule_set(gitee_token, "Steam", "rules/steam.srs"),
                rule_set(gitee_token, "Steam@CN", "rules/steam-cn.srs"),
                rule_set(gitee_token, "TikTok", "rules/tiktok.srs"),
                rule_set(gitee_token, "YouTube", "rules/youtube.srs"),
                *build_local_rule_sets(local, gitee_token),
            ],
            "final": "🐟 漏网之鱼",
        },
    }


@define
class ConfigFile:
    path: Path
    name: str = None
    cost: float = 1
    format: str = "clash"


def load_config_files(path: Path) -> list[ConfigFile]:
    with open_path(path) as f:
        configs = json.load(f)
    return structure(configs, list[ConfigFile])


def load_clash_proxies(path: Path) -> list[SimpleObject]:
    with open_path(path) as f:
        clash = yaml.load(f)
    if "proxies" not in clash:
        return []
    return clash["proxies"]


def load_shadow_rocket_proxies(path: Path) -> list[SimpleObject]:
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


def load_sing_box_proxies(path: Path) -> list[SimpleObject]:
    with open_path(path) as f:
        config = json.load(f)
    if "outbounds" not in config:
        return []
    return [
        {"name": outbound["tag"], "server": outbound["server"], "outbound": outbound}
        for outbound in config["outbounds"]
        if outbound["type"] not in ("direct", "selector", "urltest")
    ]


def load_proxies(config: ConfigFile) -> list[SimpleObject]:
    if config.cost <= 0:
        return []
    proxies = []
    match config.format:
        case "clash":
            proxies = load_clash_proxies(config.path)
        case "shadow-rocket":
            proxies = load_shadow_rocket_proxies(config.path)
        case "sing-box":
            proxies = load_sing_box_proxies(config.path)
        case _:
            raise ValueError(f"Unknown format: {config.format}")
    for proxy in proxies:
        if config.name:
            proxy["provider"] = config.name
        proxy["cost"] = config.cost
        proxy["format"] = config.format
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
    resolve_country: Annotated[bool, typer.Option("--resolve-country", "-r")] = False,
    gitee_token: Annotated[str, typer.Option("--gitee-token", "-t")] = None,
):
    config_files = [ConfigFile(f) for f in filenames] if filenames else []
    if configs:
        for config in configs:
            config_files.extend(load_config_files(config))
    proxies = sum([load_proxies(config) for config in config_files], start=[])
    if not proxies:
        raise ValueError("No proxies found")

    sing = to_sing(proxies, local, resolve_country, gitee_token)
    with open_path(output, "w") as f:
        # noinspection PyTypeChecker
        json.dump(sing, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    typer.run(main)
