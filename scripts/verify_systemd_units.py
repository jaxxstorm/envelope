#!/usr/bin/env python3
"""Extract cloud-init systemd units and verify them in a disposable Linux image."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "example/terraform/cloud-init/bootstrap.sh.tftpl"


def extract_units(text: str) -> dict[str, str]:
    pattern = re.compile(
        r"cat >/etc/systemd/system/(?P<name>[a-z0-9-]+\.service) <<'(?P<marker>[A-Z_]+)'\n(?P<body>.*?)\n(?P=marker)",
        re.DOTALL,
    )
    units = {match.group("name"): match.group("body") + "\n" for match in pattern.finditer(text)}
    expected = {"envelope-host-network.service", "envelope.service"}
    if set(units) != expected:
        raise RuntimeError(f"expected units {sorted(expected)}, found {sorted(units)}")
    return units


def verify_privilege_contract(text: str, units: dict[str, str]) -> None:
    scripts = {}
    for name, marker in (("host", "HOST_NETWORK"), ("preflight", "PREFLIGHT")):
        match = re.search(rf"cat >/usr/local/sbin/[^ ]+ <<'{marker}'\n(.*?)\n{marker}", text, re.DOTALL)
        if not match:
            raise RuntimeError(f"cannot extract {name} script")
        scripts[name] = match.group(1)
    host = scripts["host"]
    preflight = scripts["preflight"]
    for required in (
        "/usr/sbin/sysctl -p /etc/sysctl.d/90-envelope.conf",
        "sysctl -q -w",
        "nft flush ruleset",
        '"$binary" -A',
    ):
        if required not in host:
            raise RuntimeError(f"root host-network script omits mutation contract: {required}")
    if "sysctl --system" in host:
        raise RuntimeError("root host-network script must not load unowned sysctl configuration")
    for prohibited in ("sysctl --system", "sysctl -q -w", "nft flush ruleset", "/usr/local/sbin/envelope-host-network"):
        if prohibited in preflight:
            raise RuntimeError(f"unprivileged ExecStartPre contains mutation path: {prohibited}")
    host_unit = units["envelope-host-network.service"]
    service_unit = units["envelope.service"]
    if "User=root" not in host_unit or "Before=envelope.service" not in host_unit:
        raise RuntimeError("host-network mutations must run in the ordered root oneshot")
    required_service = (
        "User=envelope",
        "ExecStartPre=/usr/local/sbin/envelope-preflight",
        "ProtectKernelTunables=yes",
        "Requires=envelope-host-network.service",
    )
    if any(value not in service_unit for value in required_service):
        raise RuntimeError("Envelope unit does not enforce the read-only unprivileged preflight boundary")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="ubuntu:24.04")
    args = parser.parse_args()
    template = TEMPLATE.read_text()
    units = extract_units(template)
    verify_privilege_contract(template, units)
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        for name, content in units.items():
            (directory / name).write_text(content)
        command = [
            "docker",
            "run",
            "--rm",
            "--volume",
            f"{directory}:/units:ro",
            args.image,
            "bash",
            "-euc",
            """
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq systemd >/dev/null
install -d /usr/local/bin /usr/local/sbin /etc/envelope
for executable in /usr/local/bin/envelope /usr/local/sbin/envelope-preflight /usr/local/sbin/envelope-host-network; do
  printf '#!/bin/sh\\nexit 0\\n' >"$executable"
  chmod 0755 "$executable"
done
touch /etc/envelope/site.env /etc/envelope/artifact.env
cp /units/*.service /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/envelope-host-network.service /etc/systemd/system/envelope.service
""",
        ]
        subprocess.run(command, check=True)
    print("systemd unit verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
