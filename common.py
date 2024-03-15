import ipaddress
from collections.abc import Callable

__SITE_RULE_KEYS = frozenset(["domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"])


def get_list[V](d: dict[str, list[V]], key: str) -> list[V]:
    return compute_if_absent(d, key, lambda: [])


def get_set[V](d: dict[str, set[V]], key: str) -> set[V]:
    return compute_if_absent(d, key, lambda: set())


def compute_if_absent[K, V](d: dict[K, V], key: K, func: Callable[[], V]) -> V:
    if key in d:
        return d[key]
    value = d[key] = func()
    return value


def as_rule(rule: dict[str, set[str]]) -> dict[str, str | list[str]]:
    return {key: as_sorted_list(key, values) for key, values in rule.items()}


def merge(rules: list[dict[str, str | list[str]]]) -> list[dict[str, str | list[str]]]:
    results = []
    merged = {}

    for rule in rules:
        if not rule:
            continue
        if rule.keys() <= __SITE_RULE_KEYS:
            for key, values in rule.items():
                get_set(merged, key).update(as_set(values))
        else:
            results.append(rule)

    if merged:
        results.insert(0, as_rule(merged))

    return results


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


def network_key(ip: str) -> (int, str | ipaddress.IPv4Network | ipaddress.IPv6Network):
    network = ipaddress.ip_network(ip, strict=False)
    if isinstance(network, ipaddress.IPv4Network):
        return 4, network
    elif isinstance(network, ipaddress.IPv6Network):
        return 6, network
    else:
        raise ValueError(f"Unknown type {type(network)}")


def domain_key(domain: str) -> list[str]:
    return domain.split(".")


__KEY_FUNCTIONS = {
    "ip_cidr": network_key,
    "domain": domain_key,
    "domain_suffix": domain_key,
}


def as_sorted_list(key, items: set[str]) -> str | list[str]:
    return as_list(items, key=__KEY_FUNCTIONS.get(key, None))
