#!/usr/bin/env python
import json

import yaml


def to_sing(clash):
    return clash


def main(filename: str, output_filename: str) -> None:
    with open(filename) as f:
        clash = yaml.load(f, yaml.Loader)
    sing = to_sing(clash)
    with open(output_filename, "w") as f:
        json.dump(sing, f)


if __name__ == "__main__":
    import sys

    main(sys.argv[1], sys.argv[2])
