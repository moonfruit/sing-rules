#!/usr/bin/env python
"""Remove unnecessary fields from sing-box config outbounds."""

import json
import sys


def fix_outbound(outbound: dict) -> dict:
    """Remove unnecessary fields from an outbound definition."""
    # Remove zero-value window fields
    if outbound.get("connection_receive_window") == 0:
        outbound.pop("connection_receive_window")
    if outbound.get("stream_receive_window") == 0:
        outbound.pop("stream_receive_window")
    return outbound


def main():
    config = json.load(sys.stdin)
    if "outbounds" in config:
        config["outbounds"] = [fix_outbound(o) for o in config["outbounds"]]
    json.dump(config, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
