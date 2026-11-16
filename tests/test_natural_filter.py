import json
import runpy
import tempfile
import unittest
from pathlib import Path


converter = runpy.run_path(str(Path(__file__).resolve().parents[1] / "clash-to-sing.py"))


class NaturalFilterTest(unittest.TestCase):
    def test_filter_matching(self):
        for options, name, expected in [
            ({}, "US 普通", True),
            ({"include": (), "exclude": ()}, "US 普通", True),
            ({"include": ("US", "JP")}, "JP 普通", True),
            ({"include": ("US", "JP")}, "HK 普通", False),
            ({"exclude": ("动态", "备用")}, "US 备用", False),
            ({"include": ("US",), "exclude": ("动态",)}, "US 动态", False),
            ({"include": ("US",), "exclude": ("动态",)}, "US 普通", True),
            ({"include": ("US",)}, "us 普通", False),
            ({"include": ("US.*",)}, "US 普通", False),
        ]:
            with self.subTest(options=options, name=name):
                self.assertEqual(converter["ConfigNaturalFilter"](**options).matches(name), expected)

    def test_config_loading_and_group_isolation(self):
        names = ["US 普通", "US 动态", "JP 普通", "HK 普通"]
        with tempfile.TemporaryDirectory() as directory:
            subscription = Path(directory) / "subscription.json"
            subscription.write_text(json.dumps({"outbounds": [
                {"type": "trojan", "tag": name, "server": f"node{index}.example.com",
                 "server_port": 443, "password": "test"}
                for index, name in enumerate(names)
            ]}))
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps([{
                "path": str(subscription), "format": "sing-box",
                "natural": [
                    "AI",
                    {"name": "Claude", "filter": {"include": ["普通"], "exclude": ["动态"]}},
                    {"name": "ChatGPT", "filter": {"exclude": ["动态"]}},
                ],
            }, {"path": str(subscription), "format": "sing-box"}, {
                "path": str(subscription), "format": "sing-box", "natural": [{"name": "AI"}],
            }]))
            config, omitted, unfiltered = converter["load_config_files"](config_path)
            proxies = converter["load_proxies"](config)
            self.assertEqual([proxy["name"] for proxy in proxies], names)
            self.assertEqual(proxies[1]["natural"], ("AI",))
            self.assertTrue(all(not p["natural"] for p in converter["load_proxies"](omitted)))
            self.assertTrue(all(p["natural"] == ("AI",) for p in converter["load_proxies"](unfiltered)))
            outbounds, *_ = converter["proxies_to_outbound"](False, proxies, None, False)
            groups = {outbound["tag"]: outbound for outbound in outbounds}
            for service, expected in [("AI", names[:3]), ("Claude", names[:1]),
                                      ("ChatGPT", [names[0], names[2]])]:
                tags = groups[f"🤖 自然选择 {service}"]["outbounds"]
                self.assertEqual(len(tags), len(expected))
                for name in expected:
                    self.assertTrue(any(name in tag for tag in tags), (name, tags))
            self.assertEqual(len(groups["🍑 自由切换"]["outbounds"]), len(names))
