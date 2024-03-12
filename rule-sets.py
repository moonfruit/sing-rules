#!/usr/bin/env python
import ipaddress
import json
import subprocess
import tempfile
from typing import Any


def geoip(name):
    return export("geoip", name)


def geosite(name):
    return export("geosite", name)


def export(geo, name):
    with tempfile.NamedTemporaryFile() as temp:
        subprocess.run(("sing-box", geo, "export", name, "-o", temp.name), check=True)
        return json.load(temp)


__IP_RULE_KEYS = frozenset(["ip_cidr"])

__SITE_RULE_KEYS = frozenset(["domain", "domain_suffix", "domain_keyword", "domain_regex"])


def as_set(items: str | list[str] | None) -> set[str]:
    if items is None:
        return set()
    if isinstance(items, str):
        return {items}
    else:
        return set(items)


def as_list(items: set[str], *, key=None) -> str | list[str]:
    if len(items) == 1:
        return next(iter(items))
    else:
        return sorted(items, key=key)


def network_key(ip: str) -> (int, Any):
    network = ipaddress.ip_network(ip)
    if isinstance(network, ipaddress.IPv4Network):
        return 4, network
    elif isinstance(network, ipaddress.IPv6Network):
        return 6, network
    else:
        raise ValueError(f"Unknown type {type(network)}")


def domain_key(domain: str) -> list[str]:
    return domain.split(".")


def merge(rules: list[dict[str, str | list[str]]]) -> list[dict[str, list[str]]]:
    ip_cidr = set()
    domain = set()
    domain_suffix = set()
    domain_keyword = set()
    domain_regex = set()
    extra = []

    for rule in rules:
        if not rule:
            continue
        if rule.keys() == __IP_RULE_KEYS:
            ip_cidr |= as_set(rule["ip_cidr"])
        elif rule.keys() <= __SITE_RULE_KEYS:
            domain |= as_set(rule.get("domain", None))
            domain_suffix |= as_set(rule.get("domain_suffix", None))
            domain_keyword |= as_set(rule.get("domain_keyword", None))
            domain_regex |= as_set(rule.get("domain_regex", None))
        else:
            extra.append(rule)

    results = []
    if ip_cidr:
        results.append({
            "ip_cidr": as_list(ip_cidr, key=network_key)
        })

    domain_rule = {}
    if domain:
        domain_rule["domain"] = as_list(domain, key=domain_key)
    if domain_suffix:
        domain_rule["domain_suffix"] = as_list(domain_suffix, key=domain_key)
    if domain_keyword:
        domain_rule["domain_keyword"] = as_list(domain_keyword)
    if domain_regex:
        domain_rule["domain_regex"] = as_list(domain_regex)
    if domain_rule:
        results.append(domain_rule)

    return results + extra


def combine(output, geoip_names, geosite_names):
    rules = []
    for name in geoip_names:
        item = geoip(name)
        rules += item["rules"]
    for name in geosite_names:
        item = geosite(name)
        rules += item["rules"]
    json.dump({"version": 1, "rules": merge(rules)}, output, indent=2)


def main():
    with open("private.json", "w") as f:
        combine(f, ["private"], ["private"])
    with open("block.json", "w") as f:
        combine(f, [], ["category-ads-all"])
    with open("disney.json", "w") as f:
        combine(f, [], ["disney"])
    with open("netflix.json", "w") as f:
        combine(f, ["netflix"], ["netflix"])
    with open("youtube.json", "w") as f:
        combine(f, [], ["youtube"])
    with open("proxy.json", "w") as f:
        combine(f, ["telegram"], ["bytedance@!cn", "gfw", "telegram"])
    with open("direct.json", "w") as f:
        combine(f, ["cn"], ["cn", "apple-cn", "google-cn", "tld-cn", "category-games@cn"])
    with open("ai.json", "w") as f:
        combine(f, [], ["anthropic", "bing", "jetbrains-ai", "openai", "perplexity"])


if __name__ == "__main__":
    main()
