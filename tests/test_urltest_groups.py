import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
converter = runpy.run_path(str(ROOT / "clash-to-sing.py"))


def mobile_config(config):
    output = subprocess.check_output([sys.executable, ROOT / "copy-config.py"], input=json.dumps(config).encode())
    return json.loads(output)


class UrltestGroupTest(unittest.TestCase):
    def test_single_member_skips_test_options(self):
        urltest = converter["urltest"]
        options = {"url": "https://example.com/", "tolerance": 100}
        self.assertEqual(urltest("group", {}, ["only"], **options), {
            "type": "selector", "tag": "group", "outbounds": ["only"],
        })
        self.assertEqual(urltest("group", {"expensive": 2}, ["expensive", "cheap"], **options), {
            "type": "urltest", "tag": "group", "outbounds": ["cheap", "expensive"], **options,
        })

    def test_mobile_cost_and_region_groups(self):
        tags = ["👍 高级节点", "🛢️ 省流节点", "🇮🇳 印度节点", "🇸🇬 新加坡节点", "🇸🇬 新加坡节点 👍"]
        for nodes, kept in [(["one"], tags), (["one", "two"], ["🇸🇬 新加坡节点"])]:
            with self.subTest(nodes=nodes):
                config = mobile_config({"outbounds": [
                    converter["selector"]("🔰 默认出口", tags),
                    *(converter["urltest"](tag, {}, nodes) for tag in tags),
                    *({"type": "direct", "tag": node} for node in nodes),
                ]})
                groups = {ob["tag"]: ob for ob in config["outbounds"]}
                self.assertEqual(set(groups), {"🔰 默认出口", *kept, *nodes})
                self.assertEqual(groups["🔰 默认出口"]["outbounds"], kept)

    def test_mobile_merges_equal_natural_groups_and_redirects_references(self):
        ai, chatgpt = "🤖 自然选择 AI", "🤖 自然选择 ChatGPT"
        target = converter["urltest"](chatgpt, {}, ["b", "a"], url="https://api.openai.com/")
        result = mobile_config({
            "outbounds": [
                converter["urltest"](ai, {}, ["a", "b"], url="https://gemini.google/"), target,
                {"type": "selector", "tag": "🤖 AI", "outbounds": [ai, "a", chatgpt], "default": ai},
                {"type": "direct", "tag": "a", "detour": ai}, {"type": "direct", "tag": "b"},
            ],
            "route": {"final": ai, "rules": [{"outbound": ai}, {"rules": [{"outbound": ai}]}]},
            "dns": {"final": ai, "servers": [{"tag": ai, "detour": ai}], "rules": [{"outbound": [ai, chatgpt]}]},
            "http_clients": [{"tag": "client", "detour": ai}],
            "ntp": {"detour": ai},
            "experimental": {"v2ray_api": {"stats": {"outbounds": [ai, chatgpt]}}},
            "inbounds": [{"tag": "in", "detour": ai}],
        })
        groups = {ob["tag"]: ob for ob in result["outbounds"]}
        self.assertNotIn(ai, groups)
        self.assertEqual(groups[chatgpt], target)
        self.assertEqual(groups["🤖 AI"]["outbounds"], [chatgpt, "a"])
        self.assertEqual(groups["🤖 AI"]["default"], chatgpt)
        self.assertEqual(groups["a"]["detour"], chatgpt)
        self.assertEqual(result["route"], {"final": chatgpt, "rules": [
            {"outbound": chatgpt}, {"rules": [{"outbound": chatgpt}]},
        ]})
        self.assertEqual(result["dns"], {"final": ai, "servers": [{"tag": ai, "detour": chatgpt}],
                                         "rules": [{"outbound": [chatgpt]}]})
        self.assertEqual(result["http_clients"][0]["detour"], chatgpt)
        self.assertEqual(result["ntp"]["detour"], chatgpt)
        self.assertEqual(result["experimental"]["v2ray_api"]["stats"]["outbounds"], [chatgpt])
        self.assertEqual(result["inbounds"][0]["detour"], ai)

    def test_mobile_keeps_distinct_or_missing_natural_groups(self):
        ai, chatgpt = "🤖 自然选择 AI", "🤖 自然选择 ChatGPT"
        source = converter["urltest"](ai, {}, ["a", "b"])
        target = converter["urltest"](chatgpt, {}, ["a", "c"])
        for groups in [[source, target], [source], [target]]:
            with self.subTest(groups=groups):
                config = {"outbounds": groups, "route": {"final": groups[0]["tag"]}}
                self.assertEqual(mobile_config(config), config)

    def test_appletv_keeps_redirected_http_client_detour(self):
        ai, chatgpt = "🤖 自然选择 AI", "🤖 自然选择 ChatGPT"
        mobile = mobile_config({
            "http_clients": [{"tag": "client", "detour": ai}],
            "outbounds": [
                converter["selector"](ai, ["node"]), converter["selector"](chatgpt, ["node"]),
                {"type": "direct", "tag": "node"},
            ],
        })
        output = subprocess.run([sys.executable, ROOT / "prune-config.py"], input=json.dumps(mobile).encode(),
                                check=True, capture_output=True)
        tv = json.loads(output.stdout)
        self.assertEqual(tv["http_clients"][0]["detour"], chatgpt)
        self.assertEqual([ob["tag"] for ob in tv["outbounds"]], [chatgpt, "node"])

    def test_single_node_subscription_through_generation_and_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            subscription = directory / "subscription.json"
            config = directory / "config.json"
            output = directory / "generated.json"
            config.write_text(json.dumps([{
                "name": "🌸 Test", "path": str(subscription), "format": "sing-box",
                "natural": ["AI", "Claude", "ChatGPT"],
            }]))
            for code, region in [("US", "🇺🇸 美国节点"), ("JP", "🇯🇵 日本节点")]:
                with self.subTest(region=region):
                    subscription.write_text(json.dumps({"outbounds": [{
                        "type": "trojan", "tag": f"{code} Test", "server": "192.0.2.1",
                        "server_port": 443, "password": "test",
                    }]}))
                    subprocess.run([sys.executable, ROOT / "clash-to-sing.py", "-c", config, "-o", output], check=True)
                    generated = json.loads(output.read_bytes())
                    groups = {ob["tag"]: ob for ob in generated["outbounds"]}
                    node, = groups["🍑 自由切换"]["outbounds"]
                    for tag in ["♻️ 自动选择", "🤖 自然选择 AI", "🌸 Test", region]:
                        self.assertEqual(groups[tag], {"type": "selector", "tag": tag, "outbounds": [node]})
                    self.assertIn(region, groups["🔰 默认出口"]["outbounds"])

                    mobile = subprocess.check_output([sys.executable, ROOT / "copy-config.py"], input=output.read_bytes())
                    mobile_tags = {ob["tag"] for ob in json.loads(mobile)["outbounds"]}
                    self.assertIn("🌸 Test", mobile_tags)
                    self.assertIn(region, mobile_tags)
                    self.assertNotIn("🤖 自然选择 AI", mobile_tags)
                    self.assertTrue({"♻️ 自动选择", "🤖 自然选择 ChatGPT", "🍑 自由切换", "🚀 手动切换", "GLOBAL"} <= mobile_tags)

                    subprocess.run([sys.executable, ROOT / "split-outbounds.py", output], check=True, capture_output=True)
                    providers = json.loads((directory / "providers.json").read_bytes())
                    flag = region.split()[0]
                    self.assertEqual(providers[f"{flag} Test"]["outbounds"][0]["tag"], f"{code} Test")
                    self.assertNotIn(f"{flag} 手动切换", providers)
