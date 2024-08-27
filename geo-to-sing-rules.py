#!/usr/bin/env python
import json
import subprocess
import tempfile
from typing import TextIO

from common import RelaxedStrings, as_set, merge


def export_geoip(name: str):
    return export("geoip", name)


def export_geosite(name: str):
    return export("geosite", name)


def export(geo: str, name: str):
    with tempfile.NamedTemporaryFile() as temp:
        subprocess.run(("sing-box", geo, "export", name, "-o", temp.name), check=True)
        return json.load(temp)


def combine(output: TextIO, geosite: set[str], geoip: set[str]):
    rules = []
    for name in geosite:
        item = export_geosite(name)
        rules += item["rules"]
    for name in geoip:
        item = export_geoip(name)
        rules += item["rules"]
    json.dump({"version": 1, "rules": merge(rules)}, output, indent=2)


def simply(geosite: RelaxedStrings | None = None, geoip: RelaxedStrings | None = None):
    geosite_set = as_set(geosite)
    geoip_set = as_set(geoip)

    texts = []
    if geosite_set:
        texts.append(f"{geosite=}")
    if geoip_set:
        texts.append(f"{geoip=}")
    text = ", ".join(texts)

    return geosite_set, geoip_set, text


def generate(filename: str, *, geosite: RelaxedStrings | None = None, geoip: RelaxedStrings | None = None):
    geosite_set, geoip_set, text = simply(geosite, geoip)
    print(f"Generating {filename} from {text}")

    with open(filename, "w") as f:
        combine(f, geosite_set, geoip_set)


def main():
    generate("ai.json", geosite=["anthropic", "bing", "jetbrains-ai", "openai", "perplexity"])
    generate("netflix.json", geosite="netflix", geoip="netflix")
    generate("tiktok.json", geosite="bytedance@!cn")
    generate("youtube.json", geosite="youtube")
    generate("private.json", geosite="private", geoip="private")
    generate("dev.json", geosite="category-dev")
    generate("dev-cn.json", geosite=["category-dev@cn", "category-dev-cn"])
    generate("games.json", geosite="category-games")
    generate("games-cn.json", geosite="category-games@cn")
    generate("porn.json", geosite="category-porn")
    generate("block.json", geosite="category-ads-all")
    generate("gfw.json", geosite=["gfw", "telegram", "x",], geoip="telegram")
    generate("direct.json", geosite=[
        "cn", "apple-cn", "google-cn", "tld-cn", "geolocation-cn", "china-list",
        "category-dev-cn", "category-dev@cn", "category-games@cn",
    ], geoip="cn")
    generate("proxy.json", geosite=["category-dev", "ea", "epicgames", "firefox",  "origin", "steam"])


if __name__ == "__main__":
    main()
