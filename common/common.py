import functools
import ipaddress
import re
import time
from collections.abc import Callable, Collection, Iterable

import tldextract

type Scalar = str | float | int
type ScalarCollections = list[Scalar] | set[Scalar] | dict[str, Scalar]
type Object = dict[str, Scalar | ScalarCollections | Object | ObjectCollections]
type ObjectCollections = list[Object] | set[Object] | dict[str, Object]
type SimpleObject = dict[str, Scalar]

type RelaxedIterable[V] = V | Iterable[V]
type RelaxedList[V] = V | list[V]
type RelaxedStrings = RelaxedList[str]
type Rule = dict[str, RelaxedStrings]


def domain_sort_key(domain):
    ext = tldextract.extract(domain)
    return ext.suffix, ext.domain, ext.subdomain


def re_match(pattern: str, string: str) -> str | None:
    import re

    match = re.match(pattern, string)
    if match:
        return match.group(1)
    return None


def retry(max_attempts=3, delay=1):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # noinspection PyInconsistentReturns
            for attempt in range(max_attempts):
                # noinspection PyBroadException
                try:
                    return func(*args, **kwargs)
                except Exception:
                    if attempt == max_attempts - 1:
                        raise
                    time.sleep(delay)

        return wrapper

    return decorator


def simplify_dict(d: dict) -> dict:
    """
    将字典中只包含一个元素的列表转换为该元素本身

    Args:
        d: 输入字典

    Returns:
        处理后的字典
    """
    result = {}
    for key, value in d.items():
        if isinstance(value, list) and len(value) == 1:
            result[key] = value[0]
        else:
            result[key] = value
    return result


def apply_to[V, R](d: dict[str, V], key: str, callback: Callable[[V], R]) -> R | None:
    if key in d:
        return callback(d[key])
    return None


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


DOMAIN_KEYS = frozenset(["domain", "domain_suffix", "domain_keyword", "domain_regex"])


def suffix_core(suffix: str) -> str:
    """去掉 domain_suffix 的前导点，得到域名主体。"""
    return suffix[1:] if suffix.startswith(".") else suffix


def domain_parents(domain: str) -> list[str]:
    """domain 的所有真祖先（按标签边界逐级去掉最左标签），不含自身。"""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts))]


def _domain_matcher(exclude_rules: list[Rule]):
    exact: set[str] = set()
    bare: set[str] = set()  # 无前导点后缀的 core：匹配 apex + 子域
    dot: set[str] = set()  # 有前导点后缀的 core：仅匹配子域
    keywords: set[str] = set()
    regex_strings: set[str] = set()
    for rule in exclude_rules:
        for key, values in rule.items():
            if key == "domain":
                exact |= as_set(values)
            elif key == "domain_suffix":
                for suffix in as_set(values):
                    (dot if suffix.startswith(".") else bare).add(suffix_core(suffix))
            elif key == "domain_keyword":
                keywords |= as_set(values)
            elif key == "domain_regex":
                regex_strings |= as_set(values)
    return exact, bare, dot, keywords, regex_strings


def merge(rules: list[Rule], exclude_rules: list[Rule] | None = None) -> list[Rule]:
    merged = {}
    for rule in rules:
        for key, values in rule.items():
            get_set(merged, key).update(as_set(values))

    if exclude_rules:
        exact, bare, dot, keywords, regex_strings = _domain_matcher(exclude_rules)
        regexes = [re.compile(r) for r in regex_strings]
        # 真祖先命中无点/有点任一后缀 core 即被覆盖；apex 仅由无点后缀覆盖。
        any_parent = bare | dot

        # 非域名 key 保持原字面相减
        literal = {}
        for rule in exclude_rules:
            for key, values in rule.items():
                if key not in DOMAIN_KEYS:
                    get_set(literal, key).update(as_set(values))

        def suffix_hits_domain(d: str) -> bool:
            # exclude 后缀是否命中具体域名 d（祖先链查表，O(标签数)）
            if d in bare:  # 无点后缀匹配 apex 自身
                return True
            return any(p in any_parent for p in domain_parents(d))

        def domain_covered(d: str) -> bool:
            return (
                d in exact
                or suffix_hits_domain(d)
                or any(k in d for k in keywords)
                or any(r.search(d) for r in regexes)
            )

        def suffix_covered(s: str) -> bool:
            m = suffix_core(s)
            if s.startswith("."):
                # 仅子域：m 或其真祖先落在任一后缀 core 内即被完全覆盖
                if m in any_parent or any(p in any_parent for p in domain_parents(m)):
                    return True
            elif suffix_hits_domain(m):  # 含 apex：exclude 需匹配 apex m
                return True
            return any(k in m for k in keywords)  # keyword 吃后缀

        for key, values in merged.items():
            if key == "domain":
                merged[key] = {d for d in values if not domain_covered(d)}
            elif key == "domain_suffix":
                merged[key] = {s for s in values if not suffix_covered(s)}
            elif key == "domain_keyword":
                merged[key] = {k for k in values if not any(ek in k for ek in keywords)}
            elif key == "domain_regex":
                merged[key] = values - regex_strings
            elif key in literal:
                merged[key] = values - literal[key]

    # 丢弃被清空的 key，避免输出空数组
    merged = {key: values for key, values in merged.items() if values}
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
