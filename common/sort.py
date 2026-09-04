import re
from collections.abc import Callable, Iterable


def sort_by_variant[T](
    items: Iterable[T],
    pattern: str | re.Pattern[str],
    *,
    key: Callable[[T], str] | None = None,
) -> list[T]:
    """按名称中的 base/variant 稳定重排，把同一节点的各个变种排在一起。

    `pattern` 必须包含命名捕获组 `base`（决定「同一节点」），可选命名捕获组
    `variant`（决定变种，如入口线路）。base 按首次出现的次序排列；每个 base 下
    没有变种的本体排在最前，其余变种按 variant 首次出现的次序排列。
    匹配不上的项以整个名称作为 base，其相对位置不受影响。
    """
    regex = re.compile(pattern)
    if "base" not in regex.groupindex:
        raise ValueError(f"pattern must contain a named group 'base': {regex.pattern!r}")

    get_name = key if key else lambda item: item
    items = list(items)
    bases: dict[str, int] = {}
    variants: dict[str, int] = {}
    keys: list[tuple[int, int, int]] = []

    for item in items:
        name = get_name(item)
        if match := regex.match(name):
            base = match.group("base")
            variant = match.groupdict().get("variant")
        else:
            base, variant = name, None
        base_index = bases.setdefault(base, len(bases))
        if variant is None:
            keys.append((base_index, 0, 0))
        else:
            keys.append((base_index, 1, variants.setdefault(variant, len(variants))))

    return [items[i] for i in sorted(range(len(items)), key=lambda i: keys[i])]
