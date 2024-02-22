#!/usr/bin/env python
import json
import subprocess
import tempfile


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
    json.dump({"version": 1, "rules": rules}, output)


def main():
    with open("private.json", "w") as f:
        combine(f, ["private"], ["private"])
    with open("block.json", "w") as f:
        combine(f, [], ["category-ads-all"])
    with open("proxy.json", "w") as f:
        combine(f, ["telegram"], ["gfw", "telegram"])
    with open("direct.json", "w") as f:
        combine(f, ["cn"], ["cn", "apple-cn", "google-cn", "tld-cn", "category-games@cn"])
    with open("ai.json", "w") as f:
        combine(f, [], ["bing", "jetbrains-ai", "openai", "perplexity"])


if __name__ == "__main__":
    main()
