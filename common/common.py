import ipaddress
from collections.abc import Callable, Collection, Iterable

type Scalar = str | float | int
type ScalarCollections = list[Scalar] | set[Scalar] | dict[str, Scalar]
type Object = dict[str, Scalar | ScalarCollections | Object | ObjectCollections]
type ObjectCollections = list[Object] | set[Object] | dict[str, Object]
type SimpleObject = dict[str, Scalar]

type RelaxedIterable[V] = V | Iterable[V]
type RelaxedList[V] = V | list[V]
type RelaxedStrings = RelaxedList[str]
type Rule = dict[str, RelaxedStrings]


def get_list[V](d: dict[str, list[V]], key: str) -> list[V]:
    return compute_if_absent(d, key, lambda: [])


def get_set[V](d: dict[str, set[V]], key: str) -> set[V]:
    return compute_if_absent(d, key, lambda: set())


def compute_if_absent[K, V](d: dict[K, V], key: K, func: Callable[[], V]) -> V:
    if key in d:
        return d[key]
    value = d[key] = func()
    return value


def as_rule(rule: dict[str, Collection[str]]) -> Rule:
    return {key: as_sorted_list(key, values) for key, values in rule.items()}


__RULES_GROUP_ = [
    frozenset(["domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "ip_is_private"]),
    frozenset(["port", "port_range"]),
    frozenset(["source_geoip", "source_ip_cidr", "source_ip_is_private"]),
    frozenset(["source_port", "source_port_range"]),
]


def split(rule: Rule) -> list[Rule]:
    result = []
    used_keys = set()

    # 先按 group 分配
    for group in __RULES_GROUP_:
        sub_dict = {k: v for k, v in rule.items() if k in group}
        if sub_dict:
            result.append(as_rule(sub_dict))
            used_keys.update(sub_dict.keys())

    # 把剩余的 key 单独放入 dict
    for k, v in rule.items():
        if k not in used_keys:
            result.append(as_rule({k: v}))

    return result


def merge(rules: list[Rule]) -> list[Rule]:
    merged = {}
    for rule in rules:
        for key, values in rule.items():
            get_set(merged, key).update(as_set(values))
    return split(merged)


def as_set(items: RelaxedIterable[str] | None) -> set[str]:
    if items is None:
        return set()
    elif isinstance(items, set):
        return items
    elif isinstance(items, str):
        return {items}
    else:
        return set(items)


def as_list(items: Collection[str], *, key=None) -> RelaxedStrings:
    if len(items) == 1:
        return next(iter(items))
    else:
        return sorted(items, key=key)


def network_key(ip: str) -> tuple[int, ipaddress.IPv4Network | ipaddress.IPv6Network]:
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


def as_sorted_list(key, items: Collection[str]) -> RelaxedStrings:
    return as_list(items, key=__KEY_FUNCTIONS.get(key, None))
