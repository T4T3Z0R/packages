#!/usr/bin/env python3
"""Validate namcap reports for the noctalia-custom candidate."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

# Verified in Actions run 44843354454. Preserve the raw report as evidence.
_ALLOWED_DIAGNOSTIC = re.compile(
    r"^noctalia-custom E: ELF file \('usr/libexec/noctalia/noctalia-pam-helper'\) "
    r"outside of a valid path\.$"
)


def is_allowed_diagnostic(line: str) -> bool:
    return _ALLOWED_DIAGNOSTIC.fullmatch(line.rstrip("\r\n")) is not None


def find_errors(paths: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if not path.is_file():
            errors.append(f"Missing expected namcap report: {path}")
            continue
        for line in path.read_text(errors="replace").splitlines():
            if " E: " in line and not is_allowed_diagnostic(line):
                errors.append(f"{path}: {line}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()

    errors = find_errors(args.reports)
    if errors:
        print("Namcap validation failed:")
        print("\n".join(errors))
        return 1

    for report in args.reports:
        for line in report.read_text(errors="replace").splitlines():
            if is_allowed_diagnostic(line):
                print(f"Allowed verified Noctalia helper diagnostic (retained in report): {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
