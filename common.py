import ipaddress
from typing import Any

__IP_RULE_KEYS = frozenset(["ip_cidr"])

__SITE_RULE_KEYS = frozenset(["domain", "domain_suffix", "domain_keyword", "domain_regex"])


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
