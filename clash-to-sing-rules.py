#!/usr/bin/env python
import json
from pathlib import Path
from typing import Annotated, TextIO

import typer

from common import Rule, as_rule, get_list, get_set, merge


def load_rules(rule_set_file: Path) -> list[Rule]:
    if rule_set_file.exists():
        with rule_set_file.open("r") as f:
            return get_list(json.load(f), "rules")
    return []


def to_rules(f: TextIO, enable_process=False) -> list[Rule]:
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
            case "PROCESS-NAME":
                if enable_process:
                    get_set(rule, "process_name").add(values[1])
            case "PROCESS-PATH":
                if enable_process:
                    get_set(rule, "process_path").add(values[1])
            case "PROCESS-PATH-REGEX":
                if enable_process:
                    get_set(rule, "process_path_regex").add(values[1])
            case "URL-REGEX" | "USER-AGENT":
                pass
            case _:
                raise ValueError(f"Unknown rule method: {line}")

    if not rule:
        return []

    return [as_rule(rule)]


def main(
    list_file: Annotated[Path, typer.Argument(show_default=False, exists=True, dir_okay=False)],
    rule_set_file: Annotated[Path, typer.Argument(show_default=False, dir_okay=False, writable=True)],
    enable_process: Annotated[bool, typer.Option("--enable-process", "-p")] = False,
):
    rules = load_rules(rule_set_file)

    with list_file.open("r") as f:
        rules.extend(to_rules(f, enable_process))

    with rule_set_file.open("w") as f:
        json.dump({"version": 1, "rules": merge(rules)}, f, indent=2)


if __name__ == "__main__":
    typer.run(main)
