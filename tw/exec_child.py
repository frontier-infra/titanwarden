"""Child-side file descriptor remapping followed by an immediate exec."""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 4 or arguments[0] != "--map" or "--" not in arguments:
        return 64
    separator = arguments.index("--")
    mapping_text = arguments[1]
    command = arguments[separator + 1 :]
    if not command:
        return 64
    mappings: list[tuple[int, int]] = []
    try:
        for item in mapping_text.split(","):
            source, target = item.split(":", 1)
            mappings.append((int(source), int(target)))
    except (TypeError, ValueError):
        return 64
    for source, target in mappings:
        if target < 3:
            return 64
        if source != target:
            os.dup2(source, target, inheritable=True)
    targets = {target for _source, target in mappings}
    for source, _target in mappings:
        if source not in targets:
            os.close(source)
    os.execve(command[0], command, os.environ)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
