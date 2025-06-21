#!/usr/bin/env python
import json
from typing import TextIO

from common import Rule, as_rule, get_list, get_set, merge


def load_rules(rule_set_file: str) -> list[Rule]:
    try:
        with open(rule_set_file, "r") as f:
            return get_list(json.load(f), "rules")
    except FileNotFoundError:
        return []


def to_rules(f: TextIO) -> list[Rule]:
    rule = {}
    for line in f:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        values = line.split(",")
        match values[0]:
            case "DOMAIN":
                get_set(rule, "domain").add(values[1].lower())
            case "DOMAIN-SUFFIX":
                domain_suffix = values[1].lower()
                if domain_suffix.startswith("."):
                    get_set(rule, "domain_suffix").add(domain_suffix)
                else:
                    get_set(rule, "domain").add(domain_suffix)
                    get_set(rule, "domain_suffix").add("." + domain_suffix)
            case "DOMAIN-KEYWORD":
                get_set(rule, "domain_keyword").add(values[1].lower())
            case "DOMAIN-REGEX":
                get_set(rule, "domain_regex").add(values[1])
            case "IP-CIDR" | "IP-CIDR6":
                if values[2] != "no-resolve":
                    raise ValueError(f"Invalid rule: {line}")
                get_set(rule, "ip_cidr").add(values[1])
            case "PROCESS-NAME" | "URL-REGEX" | "USER-AGENT":
                pass
            case _:
                raise ValueError(f"Unknown rule method: {line}")

    if not rule:
        return []

    return [as_rule(rule)]


def main(list_file: str, rule_set_file: str) -> None:
    rules = load_rules(rule_set_file)

    with open(list_file, "r") as f:
        rules.extend(to_rules(f))

    with open(rule_set_file, "w") as f:
        json.dump({"version": 1, "rules": merge(rules)}, f, indent=2)


if __name__ == "__main__":
    import sys

    main(sys.argv[1], sys.argv[2])
