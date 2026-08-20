#!/usr/bin/env python3
"""Validate a static Linux ELF artifact without executing the target binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys


MACHINES = {62: "amd64", 183: "arm64"}


def go_build_info(path: pathlib.Path, excluded_environment: tuple[str, ...] = ()) -> dict[str, object]:
    env = os.environ.copy()
    for name in excluded_environment:
        env.pop(name, None)
    try:
        output = subprocess.run(
            ["go", "version", "-m", str(path.resolve())],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("artifact has no readable Go build provenance") from error
    lines = output.splitlines()
    if not lines or ": " not in lines[0]:
        raise ValueError("artifact Go toolchain metadata is missing")
    go_version = lines[0].rsplit(": ", 1)[1].strip()
    settings: dict[str, str] = {}
    for line in lines[1:]:
        match = re.match(r"^\s*build\s+([^=]+)=(.*)$", line)
        if match:
            settings[match.group(1)] = match.group(2)
    required = ("GOOS", "GOARCH", "vcs.revision", "vcs.modified")
    if any(not settings.get(key) for key in required):
        raise ValueError("artifact Go build settings omit OS, architecture, or VCS identity")
    return {"go_version": go_version, "settings": settings}


def inspect(
    path: pathlib.Path,
    *,
    expected_architecture: str | None = None,
    expected_sha256: str | None = None,
    expected_revision: str | None = None,
    expected_modified: bool | None = None,
    expected_go_version: str | None = None,
    expected_version: str | None = None,
    excluded_environment: tuple[str, ...] = (),
) -> dict[str, object]:
    path = path.resolve()
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("artifact is not an ELF binary")
    if data[4] != 2:
        raise ValueError("artifact is not a 64-bit ELF binary")
    if data[5] not in (1, 2):
        raise ValueError("artifact has an unsupported ELF byte order")
    endian = "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    architecture = MACHINES.get(machine)
    if architecture is None:
        raise ValueError(f"unsupported ELF machine {machine}")
    program_offset = struct.unpack_from(endian + "Q", data, 32)[0]
    entry_size = struct.unpack_from(endian + "H", data, 54)[0]
    entry_count = struct.unpack_from(endian + "H", data, 56)[0]
    if entry_size < 56 or program_offset + entry_size * entry_count > len(data):
        raise ValueError("artifact has an invalid ELF program-header table")
    for index in range(entry_count):
        header = program_offset + index * entry_size
        segment_type = struct.unpack_from(endian + "I", data, header)[0]
        if segment_type == 3:
            raise ValueError("artifact has a dynamic program interpreter")
    build = go_build_info(path, excluded_environment)
    settings = build["settings"]
    result = {
        "architecture": architecture,
        "format": "elf64-linux",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "static": True,
        "go_version": build["go_version"],
        "goos": settings["GOOS"],
        "goarch": settings["GOARCH"],
        "vcs_revision": settings["vcs.revision"],
        "vcs_modified": settings["vcs.modified"] == "true",
    }
    if result["goos"] != "linux" or result["goarch"] != architecture:
        raise ValueError("artifact Go OS/architecture disagrees with its ELF identity")
    if expected_architecture and architecture != expected_architecture:
        raise ValueError(f"artifact architecture {architecture} does not match {expected_architecture}")
    if expected_sha256 and result["sha256"] != expected_sha256.lower():
        raise ValueError("artifact SHA-256 does not match the reviewed digest")
    if expected_revision and result["vcs_revision"] != expected_revision:
        raise ValueError("artifact VCS revision does not match the reviewed revision")
    if expected_modified is not None and result["vcs_modified"] is not expected_modified:
        raise ValueError("artifact VCS modified flag does not match the reviewed source state")
    if expected_go_version and result["go_version"] != expected_go_version:
        raise ValueError("artifact Go toolchain does not match the reviewed toolchain")
    if expected_version and expected_version.encode() not in data:
        raise ValueError("artifact does not contain the reviewed application version")
    if expected_revision and expected_revision.encode() not in data:
        raise ValueError("artifact does not contain its reviewed source revision")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=pathlib.Path)
    parser.add_argument("--expect-architecture", choices=("amd64", "arm64"))
    parser.add_argument("--expect-sha256")
    parser.add_argument("--expect-revision")
    parser.add_argument("--expect-modified", choices=("true", "false"))
    parser.add_argument("--expect-go-version")
    parser.add_argument("--expect-version")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect(
            args.artifact,
            expected_architecture=args.expect_architecture,
            expected_sha256=args.expect_sha256,
            expected_revision=args.expect_revision,
            expected_modified=None if args.expect_modified is None else args.expect_modified == "true",
            expected_go_version=args.expect_go_version,
            expected_version=args.expect_version,
        )
    except (OSError, ValueError) as error:
        print(f"artifact validation failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
