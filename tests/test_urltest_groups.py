import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
converter = runpy.run_path(str(ROOT / "clash-to-sing.py"))


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
                    self.assertNotIn("🌸 Test", mobile_tags)
                    self.assertEqual(region in mobile_tags, code == "US")
                    self.assertTrue({"♻️ 自动选择", "🤖 自然选择 AI", "🍑 自由切换", "🚀 手动切换", "GLOBAL"} <= mobile_tags)

                    subprocess.run([sys.executable, ROOT / "split-outbounds.py", output], check=True, capture_output=True)
                    providers = json.loads((directory / "providers.json").read_bytes())
                    flag = region.split()[0]
                    self.assertEqual(providers[f"{flag} Test"]["outbounds"][0]["tag"], f"{code} Test")
                    self.assertNotIn(f"{flag} 手动切换", providers)
