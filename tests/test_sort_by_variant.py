import unittest

from common.sort import sort_by_variant

# Ash 订阅的命名风格：基础节点 + " · 入口" 变种
ASH_PATTERN = r"^(?P<base>.+?)(?: · (?P<variant>.+))?$"


def names(items):
    return [item["name"] for item in items]


def proxies(*tags):
    return [{"name": tag} for tag in tags]


class SortByVariantTest(unittest.TestCase):
    def test_variants_are_grouped_after_their_base(self):
        result = sort_by_variant(
            proxies("HK-01", "HK-02", "HK-01 · GCP", "HK-02 · GCP", "HK-01 · AWS2", "HK-02 · AWS2"),
            ASH_PATTERN,
            key=lambda p: p["name"],
        )
        self.assertEqual(
            ["HK-01", "HK-01 · GCP", "HK-01 · AWS2", "HK-02", "HK-02 · GCP", "HK-02 · AWS2"],
            names(result),
        )

    def test_base_order_follows_first_appearance(self):
        # US-01 先于 HK-01 出现，重排后仍应在前
        result = sort_by_variant(
            proxies("US-01", "HK-01", "HK-01 · GCP", "US-01 · GCP"),
            ASH_PATTERN,
            key=lambda p: p["name"],
        )
        self.assertEqual(["US-01", "US-01 · GCP", "HK-01", "HK-01 · GCP"], names(result))

    def test_variant_order_follows_first_appearance(self):
        # AWS2 块整体先于 GCP 块出现，则每个 base 内 AWS2 也在 GCP 前
        result = sort_by_variant(
            proxies("HK-01", "HK-02", "HK-01 · AWS2", "HK-02 · AWS2", "HK-01 · GCP", "HK-02 · GCP"),
            ASH_PATTERN,
            key=lambda p: p["name"],
        )
        self.assertEqual(
            ["HK-01", "HK-01 · AWS2", "HK-01 · GCP", "HK-02", "HK-02 · AWS2", "HK-02 · GCP"],
            names(result),
        )

    def test_base_without_variant_keeps_relative_position(self):
        # 没有任何变种的节点，相对次序不变
        tags = ("HK-01", "TW-Direct", "MO-01")
        self.assertEqual(list(tags), names(sort_by_variant(proxies(*tags), ASH_PATTERN, key=lambda p: p["name"])))

    def test_distinct_base_is_not_merged(self):
        # HK-06[Max]×3 与 HK-01 是不同节点，不应被并到一起
        result = sort_by_variant(
            proxies("HK-01", "MY-02", "HK-06[Max]×3", "HK-01 · GCP"),
            ASH_PATTERN,
            key=lambda p: p["name"],
        )
        self.assertEqual(["HK-01", "HK-01 · GCP", "MY-02", "HK-06[Max]×3"], names(result))

    def test_unmatched_item_is_kept(self):
        # 正则匹配不上的项按整个名字作 base，不丢失
        result = sort_by_variant(
            proxies("HK-01", "", "HK-01 · GCP"),
            ASH_PATTERN,
            key=lambda p: p["name"],
        )
        self.assertEqual(["HK-01", "HK-01 · GCP", ""], names(result))

    def test_duplicate_variant_keeps_input_order(self):
        result = sort_by_variant(
            proxies("HK-01 · GCP", "HK-01", "HK-01 · GCP"),
            ASH_PATTERN,
            key=lambda p: p["name"],
        )
        self.assertEqual(["HK-01", "HK-01 · GCP", "HK-01 · GCP"], names(result))

    def test_only_first_separator_splits(self):
        # 只按第一个分隔符切分，变种为 "GCP · v2"；无变种的本体排在变种之前
        result = sort_by_variant(
            proxies("HK-01 · GCP · v2", "HK-01"),
            ASH_PATTERN,
            key=lambda p: p["name"],
        )
        self.assertEqual(["HK-01", "HK-01 · GCP · v2"], names(result))

    def test_pattern_without_base_group_raises(self):
        with self.assertRaises(ValueError):
            sort_by_variant(proxies("HK-01"), r"^(?P<variant>.+)$", key=lambda p: p["name"])

    def test_default_key_is_identity(self):
        self.assertEqual(
            ["HK-01", "HK-01 · GCP", "HK-02", "HK-02 · GCP"],
            sort_by_variant(["HK-01", "HK-02", "HK-01 · GCP", "HK-02 · GCP"], ASH_PATTERN),
        )

    def test_empty_input(self):
        self.assertEqual([], sort_by_variant([], ASH_PATTERN))


if __name__ == "__main__":
    unittest.main()
