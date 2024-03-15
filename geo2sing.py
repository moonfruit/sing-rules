#!/usr/bin/env python
import json
import subprocess
import tempfile

from common import merge


def geoip(name):
    return export("geoip", name)


def geosite(name):
    return export("geosite", name)


def export(geo, name):
    with tempfile.NamedTemporaryFile() as temp:
        subprocess.run(("sing-box", geo, "export", name, "-o", temp.name), check=True)
        return json.load(temp)


def combine(output, geoip_names, geosite_names):
    rules = []
    for name in geoip_names:
        item = geoip(name)
        rules += item["rules"]
    for name in geosite_names:
        item = geosite(name)
        rules += item["rules"]
    json.dump({"version": 1, "rules": merge(rules)}, output, indent=2)


def combinef(filename, geoip_names, geosite_names):
    print(f"Combining {filename} with {geoip_names} and {geosite_names}")
    with open(filename, "w") as f:
        combine(f, geoip_names, geosite_names)


def main():
    combinef("ai.json", [], ["anthropic", "bing", "jetbrains-ai", "openai", "perplexity"])
    combinef("disney.json", [], ["disney"])
    combinef("netflix.json", ["netflix"], ["netflix"])
    combinef("youtube.json", [], ["youtube"])

    combinef("private.json", ["private"], ["private"])
    combinef("block.json", [], ["category-ads-all"])
    combinef("proxy.json", ["telegram"], ["category-dev", "bytedance@!cn", "gfw", "steam", "telegram", "x"])
    combinef(
        "direct.json",
        ["cn"],
        ["cn", "apple-cn", "google-cn", "tld-cn", "category-dev@cn", "category-games@cn"],
    )


if __name__ == "__main__":
    main()
