import sys
from pathlib import Path
from typing import Any, IO, TextIO


def open_path(path: Path, mode="r", **kwargs) -> IO[Any]:
    if str(path) == "-":
        match mode:
            case "r":
                return sys.stdin
            case "w":
                return sys.stdout
            case _:
                raise ValueError(f"invalid mode: {mode!r}")
    else:
        return path.open(mode, **kwargs)
