#!/usr/bin/env python3
"""Statically verify the standalone controller systemd security boundary."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
UNIT_PATH = ROOT / "deploy" / "systemd" / "envelope-controller.service"
EXPECTED_EXEC_START = "/usr/local/bin/envelope-controller"


def parse_unit(text: str) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
            continue
        if current is None or "=" not in raw_line:
            raise ValueError(f"invalid unit syntax on line {line_number}")
        name, value = raw_line.split("=", 1)
        if not name or name != name.strip():
            raise ValueError(f"invalid directive on line {line_number}")
        current.setdefault(name, []).append(value)
    return sections


class ControllerSystemdSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = UNIT_PATH.read_text()
        cls.sections = parse_unit(cls.text)
        cls.unit = cls.sections["Unit"]
        cls.service = cls.sections["Service"]

    def assert_service_value(self, name: str, value: str) -> None:
        self.assertEqual(self.service.get(name), [value], name)

    def test_exec_start_invokes_controller_binary_directly(self) -> None:
        self.assert_service_value("ExecStart", EXPECTED_EXEC_START)
        self.assertEqual(self.service["ExecStart"], ["/usr/local/bin/envelope-controller"])
        self.assertEqual(
            {name: value for name, value in self.service.items() if name.startswith("Exec")},
            {"ExecStart": [EXPECTED_EXEC_START]},
        )
        self.assertNotIn("ExecStartPre", self.service)
        self.assertNotIn("ExecStartPost", self.service)
        for forbidden in ("/bin/sh", "/bin/bash", "sh -c", ".sh", "/scripts/"):
            self.assertNotIn(forbidden, self.service["ExecStart"][0])

    def test_configuration_and_listener_are_fixed(self) -> None:
        self.assert_service_value("EnvironmentFile", "/etc/envelope/controller.env")
        self.assertNotIn("--", self.service["ExecStart"][0])
        self.assertNotIn("$", self.service["ExecStart"][0])
        for wildcard in ("0.0.0.0", "[::]", "*:9091"):
            self.assertNotIn(wildcard, self.text)

    def test_process_has_no_packet_or_administration_privilege(self) -> None:
        self.assert_service_value("User", "envelope-controller")
        self.assert_service_value("Group", "envelope-controller")
        self.assert_service_value("AmbientCapabilities", "")
        self.assert_service_value("CapabilityBoundingSet", "")
        self.assert_service_value("NoNewPrivileges", "yes")
        self.assertNotIn("User=root", self.text)
        for forbidden in ("CAP_NET_ADMIN", "CAP_NET_RAW", "AF_PACKET"):
            self.assertNotIn(forbidden, self.text)

    def test_state_and_runtime_writes_are_private_and_scoped(self) -> None:
        self.assertEqual(
            self.unit.get("RequiresMountsFor"), ["/var/lib/envelope-controller"]
        )
        expected = {
            "RuntimeDirectory": "envelope-controller",
            "RuntimeDirectoryMode": "0700",
            "StateDirectory": "envelope-controller",
            "StateDirectoryMode": "0700",
            "ReadWritePaths": "/run/envelope-controller /var/lib/envelope-controller",
            "ReadOnlyPaths": "/etc/envelope",
            "WorkingDirectory": "/var/lib/envelope-controller",
            "UMask": "0077",
        }
        for name, value in expected.items():
            self.assert_service_value(name, value)
        self.assertEqual(
            self.service["Environment"],
            [
                "HOME=/var/lib/envelope-controller",
                "TMPDIR=/run/envelope-controller",
            ],
        )

    def test_filesystem_device_kernel_and_syscall_hardening(self) -> None:
        expected = {
            "DevicePolicy": "closed",
            "PrivateDevices": "yes",
            "PrivateTmp": "yes",
            "ProtectClock": "yes",
            "ProtectControlGroups": "yes",
            "ProtectHome": "yes",
            "ProtectHostname": "yes",
            "ProtectKernelLogs": "yes",
            "ProtectKernelModules": "yes",
            "ProtectKernelTunables": "yes",
            "ProtectProc": "invisible",
            "ProtectSystem": "strict",
            "RemoveIPC": "yes",
            "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            "RestrictNamespaces": "yes",
            "RestrictRealtime": "yes",
            "RestrictSUIDSGID": "yes",
            "LockPersonality": "yes",
            "MemoryDenyWriteExecute": "yes",
            "SystemCallArchitectures": "native",
            "SystemCallErrorNumber": "EPERM",
            "SystemCallFilter": "@system-service",
            "KeyringMode": "private",
            "LimitCORE": "0",
            "TasksMax": "512",
        }
        for name, value in expected.items():
            self.assert_service_value(name, value)

    def test_start_stop_and_restart_are_bounded(self) -> None:
        self.assertEqual(self.unit.get("StartLimitIntervalSec"), ["120s"])
        self.assertEqual(self.unit.get("StartLimitBurst"), ["5"])
        expected = {
            "Restart": "on-failure",
            "RestartSec": "5s",
            "TimeoutStartSec": "30s",
            "TimeoutStopSec": "15s",
            "KillMode": "control-group",
            "KillSignal": "SIGTERM",
            "FinalKillSignal": "SIGKILL",
            "SendSIGKILL": "yes",
        }
        for name, value in expected.items():
            self.assert_service_value(name, value)


if __name__ == "__main__":
    unittest.main()
