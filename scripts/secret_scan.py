#!/usr/bin/env python3
"""Scan source-controlled and explicitly supplied evidence without opening ignored files."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys


PATTERNS = {
    "Tailscale key": re.compile("tskey-" + r"(?:auth|client|api)-[A-Za-z0-9_-]{8,}", re.IGNORECASE),
    "AWS access key": re.compile("AKIA" + r"[0-9A-Z]{16}"),
    "private key": re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "OAuth client secret value": re.compile(r'(?i)oauth_client_secret\s*[=:]\s*["\'](?!\$|<|\[REDACTED)[^"\']{8,}["\']'),
}


def repository_paths(root: pathlib.Path) -> list[pathlib.Path]:
    output = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return [root / value.decode() for value in output.split(b"\0") if value]


def scan(paths: list[pathlib.Path]) -> list[tuple[pathlib.Path, str]]:
    failures: list[tuple[pathlib.Path, str]] = []
    for path in paths:
        try:
            data = path.read_bytes()
        except (OSError, IsADirectoryError):
            continue
        if b"\0" in data:
            continue
        text = data.decode(errors="replace")
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                failures.append((path, name))
        if path.suffix == ".tf" and re.search(r'variable\s+"tailscale_auth_key"', text):
            failures.append((path, "prohibited Terraform plaintext-key variable"))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--extra", action="append", type=pathlib.Path, default=[])
    args = parser.parse_args()
    root = args.root.resolve()
    paths = repository_paths(root) + [path.resolve() for path in args.extra]
    failures = scan(paths)
    if failures:
        for path, reason in failures:
            try:
                display = path.relative_to(root)
            except ValueError:
                display = path
            print(f"secret scan failed: {display}: {reason}", file=sys.stderr)
        return 1
    print(f"secret scan passed for {len(paths)} non-ignored/explicit file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
