import unittest

from common import merge


def collect(result, key):
    """收集 merge 结果中某 key 的所有值（值可能是 str 或 list）。"""
    values = set()
    for rule in result:
        if key in rule:
            v = rule[key]
            values.update(v if isinstance(v, list) else [v])
    return values


class SuffixDotSemanticsTest(unittest.TestCase):
    def test_leading_dot_suffix_excludes_subdomain(self):
        result = merge(
            [{"domain": ["dns.alidns.com", "example.org"]}],
            [{"domain_suffix": ".alidns.com"}],
        )
        domains = collect(result, "domain")
        self.assertNotIn("dns.alidns.com", domains)
        self.assertIn("example.org", domains)

    def test_leading_dot_suffix_keeps_apex(self):
        # ".alidns.com" 只匹配子域，不应删掉父域 apex
        result = merge([{"domain": ["alidns.com"]}], [{"domain_suffix": ".alidns.com"}])
        self.assertIn("alidns.com", collect(result, "domain"))

    def test_bare_suffix_excludes_apex_and_subdomain(self):
        # 无前导点 "alidns.com" 匹配父域 + 子域
        result = merge(
            [{"domain": ["alidns.com", "dns.alidns.com", "notalidns.com"]}],
            [{"domain_suffix": "alidns.com"}],
        )
        domains = collect(result, "domain")
        self.assertNotIn("alidns.com", domains)
        self.assertNotIn("dns.alidns.com", domains)
        self.assertIn("notalidns.com", domains)  # 非子域边界，不误删


class DomainMatcherTest(unittest.TestCase):
    def test_exact_domain_exclude(self):
        result = merge(
            [{"domain": ["a.com", "b.com"]}], [{"domain": "a.com"}]
        )
        self.assertEqual(collect(result, "domain"), {"b.com"})

    def test_keyword_excludes_domain(self):
        result = merge(
            [{"domain": ["ad.example.com", "www.example.com"]}],
            [{"domain_keyword": "ad."}],
        )
        self.assertEqual(collect(result, "domain"), {"www.example.com"})

    def test_regex_search_excludes_domain(self):
        # search 语义：正则只要能在域名中部分匹配即命中
        result = merge(
            [{"domain": ["x.awsdns-cn-01.net", "x.awsdns-us-01.net"]}],
            [{"domain_regex": r"awsdns-cn-\d\d"}],
        )
        self.assertNotIn("x.awsdns-cn-01.net", collect(result, "domain"))
        self.assertIn("x.awsdns-us-01.net", collect(result, "domain"))


class RuleCoversRuleTest(unittest.TestCase):
    def test_wide_suffix_eats_narrow_suffix(self):
        result = merge(
            [{"domain_suffix": [".foo.alidns.com", ".other.com"]}],
            [{"domain_suffix": ".alidns.com"}],
        )
        suffixes = collect(result, "domain_suffix")
        self.assertNotIn(".foo.alidns.com", suffixes)
        self.assertIn(".other.com", suffixes)

    def test_dot_suffix_keeps_apex_suffix(self):
        # exclude ".alidns.com" 不覆盖含 apex 的 main "alidns.com"(无点)
        result = merge(
            [{"domain_suffix": ["alidns.com"]}], [{"domain_suffix": ".alidns.com"}]
        )
        self.assertIn("alidns.com", collect(result, "domain_suffix"))

    def test_keyword_eats_suffix(self):
        result = merge(
            [{"domain_suffix": [".alidns.com", ".keepme.com"]}],
            [{"domain_keyword": "alidns"}],
        )
        suffixes = collect(result, "domain_suffix")
        self.assertNotIn(".alidns.com", suffixes)
        self.assertIn(".keepme.com", suffixes)

    def test_short_keyword_eats_long_keyword(self):
        result = merge(
            [{"domain_keyword": ["alidns", "google"]}],
            [{"domain_keyword": "ali"}],
        )
        self.assertEqual(collect(result, "domain_keyword"), {"google"})

    def test_regex_only_exact_match(self):
        result = merge(
            [{"domain_regex": [r"a\.com", r"b\.com"]}],
            [{"domain_regex": r"a\.com"}],
        )
        self.assertEqual(collect(result, "domain_regex"), {r"b\.com"})


class NonDomainKeyTest(unittest.TestCase):
    def test_ip_cidr_literal_subtraction_preserved(self):
        result = merge(
            [{"ip_cidr": ["1.1.1.0/24", "2.2.2.0/24"]}],
            [{"ip_cidr": "1.1.1.0/24"}],
        )
        self.assertEqual(collect(result, "ip_cidr"), {"2.2.2.0/24"})

    def test_ip_cidr_subnet_not_semantically_removed(self):
        # 范围外：IP 子网不做语义包含判断，仅字面相减
        result = merge(
            [{"ip_cidr": ["1.1.1.0/24"]}], [{"ip_cidr": "1.0.0.0/8"}]
        )
        self.assertIn("1.1.1.0/24", collect(result, "ip_cidr"))

    def test_unknown_field_literal_exclude(self):
        # 任意未知字段仍保留按字面值 exclude 的能力
        result = merge(
            [{"process_name": ["a.exe", "b.exe"]}],
            [{"process_name": "a.exe"}],
        )
        self.assertEqual(collect(result, "process_name"), {"b.exe"})

    def test_unknown_field_kept_when_not_in_exclude(self):
        # exclude 未涉及的字段原样保留
        result = merge(
            [{"process_name": ["a.exe"]}], [{"domain": "x.com"}]
        )
        self.assertEqual(collect(result, "process_name"), {"a.exe"})


class HousekeepingTest(unittest.TestCase):
    def test_emptied_key_dropped(self):
        result = merge([{"domain": ["a.com"]}], [{"domain": "a.com"}])
        # 全部删空后不应残留 {"domain": []}
        for rule in result:
            self.assertNotIn("domain", rule)

    def test_no_exclude_unchanged(self):
        result = merge([{"domain": ["a.com", "b.com"]}])
        self.assertEqual(collect(result, "domain"), {"a.com", "b.com"})


if __name__ == "__main__":
    unittest.main()
