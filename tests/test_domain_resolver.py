import json
import runpy
import tempfile
import unittest
from pathlib import Path


converter = runpy.run_path(str(Path(__file__).resolve().parents[1] / "clash-to-sing.py"))


class DomainResolverTest(unittest.TestCase):
    def test_subscription_resolver_survives_conversion_and_affects_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subscription.json"
            path.write_text(json.dumps({"outbounds": [{
                "type": "trojan", "tag": "US Test", "server": "node.staticlane.org",
                "server_port": 443, "password": "test", "domain_resolver": "untrusted-dns",
            }]}))
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps([
                {"path": str(path), "format": "sing-box", "domain_resolver": "dns-ash"},
                {"path": str(path), "format": "sing-box"},
            ]))
            configs = converter["load_config_files"](config_path)
            seen = set()
            results = []
            for config in configs:
                proxy, = converter["load_proxies"](config)
                results.append(converter["proxy_to_outbound"](proxy, seen, False, None, False))
            self.assertEqual("dns-ash", results[0][3].get("domain_resolver"))
            self.assertNotIn("domain_resolver", results[1][3])
            self.assertFalse(results[1][0])
