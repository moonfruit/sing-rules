import copy
from collections.abc import Hashable


def as_hashable(obj):
    """将对象转换为可哈希的规范化表示"""
    if obj is None or isinstance(obj, (bool, int, float, str, bytes, Hashable)):
        return type(obj).__name__, obj
    elif isinstance(obj, complex):
        return "complex", obj.real, obj.imag
    elif isinstance(obj, (list, tuple)):
        return type(obj).__name__, tuple(as_hashable(item) for item in obj)
    elif isinstance(obj, (set, frozenset)):
        # 集合无序，需要排序以保证一致性
        return type(obj).__name__, tuple(sorted(as_hashable(item) for item in obj))
    elif isinstance(obj, dict):
        # 字典按 key 排序
        return "dict", tuple(sorted((as_hashable(k), as_hashable(v)) for k, v in obj.items()))
    elif isinstance(obj, bytearray):
        return "bytearray", bytes(obj)
    elif isinstance(obj, range):
        return "range", obj.start, obj.stop, obj.step
    else:
        raise TypeError(f"Not support: {type(obj)}")


def dedup(objects):
    """对一组对象去重，保持原始顺序"""
    seen = set()
    result = []
    for obj in objects:
        key = as_hashable(obj)
        if key not in seen:
            seen.add(key)
            result.append(obj)
    return result


def copy_without_tag(d: dict):
    result = copy.deepcopy(d)
    del result["tag"]
    return result
