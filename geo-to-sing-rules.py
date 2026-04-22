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


def combine_rules(geosite: set[str] | None, geoip: set[str] | None):
    rules = []
    if geosite:
        for name in geosite:
            item = export_geosite(name)
            rules += item["rules"]
    if geoip:
        for name in geoip:
            item = export_geoip(name)
            rules += item["rules"]
    return rules


def combine(
    output: TextIO,
    geosite: set[str],
    geoip: set[str],
    exclude_geosite: set[str] | None = None,
    exclude_geoip: set[str] | None = None,
):
    rules = combine_rules(geosite, geoip)
    exclude_rules = combine_rules(exclude_geosite, exclude_geoip)
    json.dump({"version": 1, "rules": merge(rules, exclude_rules)}, output, indent=2)


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


def generate(
    filename: str,
    *,
    geosite: RelaxedStrings | None = None,
    geoip: RelaxedStrings | None = None,
    excluded_geosite: RelaxedStrings | None = None,
    excluded_geoip: RelaxedStrings | None = None,
):
    geosite_set, geoip_set, text = simply(geosite, geoip)

    excluded_geosite_set, excluded_geoip_set, excluded_text = simply(excluded_geosite, excluded_geoip)

    if excluded_text:
        text = f"{text} - {excluded_text}"
    print(f"Generating {filename} from {text}")

    with open(filename, "w") as f:
        combine(f, geosite_set, geoip_set, excluded_geosite_set or None, excluded_geoip_set or None)


def main():
    generate("geoip-cn.json", geoip="cn")
    generate("geosites-cn.json", geosite=["cn", "geolocation-cn", "geolocation-cn@cn"])
    generate("geosites-not-cn.json", geosite="geolocation-!cn")

    generate(
        "ai.json",
        geosite=[
            "category-ai-!cn",
            "category-ai-chat-!cn",
            "anthropic",
            "jetbrains-ai",
            "openai",
            "perplexity",
            "github-copilot",
        ],
        excluded_geosite="google-gemini",
    )
    generate("sources.json", geosite=["github", "gitlab", "sourceforge"])
    generate("nintendo.json", geosite="nintendo")
    generate("nintendo-cn.json", geosite="nintendo@cn")
    generate("playstation.json", geosite="playstation")
    generate("steam.json", geosite="steam")
    generate("steam-cn.json", geosite="steam@cn")
    generate("xbox.json", geosite="xbox")
    generate("xbox-cn.json", geosite="xbox@cn")
    generate("netflix.json", geosite="netflix", geoip="netflix")
    generate("tiktok.json", geosite="bytedance@!cn")
    generate("youtube.json", geosite="youtube")

    generate("dev.json", geosite="category-dev")
    generate("dev-cn.json", geosite=["category-dev-cn", "category-dev@cn"])
    generate("games.json", geosite="category-games")
    generate(
        "games-cn.json",
        geosite=[
            "category-games-!cn@cn",
            "category-games-cn",
            "category-games-cn@cn",
            "category-games@cn",
        ],
    )
    generate("porn.json", geosite="category-porn")

    generate("private.json", geosite="private", geoip="private")
    generate("block.json", geosite="category-ads-all")
    generate("gfw.json", geosite=["gfw", "telegram", "twitter", "x"], geoip=["telegram", "twitter"])
    generate(
        "direct.json",
        geosite=["china-list", "google-cn", "tld-cn"],
        excluded_geosite=["cn", "geolocation-cn", "geolocation-cn@cn"],
    )
    generate("proxy.json", geosite=["firefox"])


if __name__ == "__main__":
    main()
