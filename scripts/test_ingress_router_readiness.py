#!/usr/bin/env python3

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ingress_router_readiness as readiness  # noqa: E402


LOCAL = ["10.10.0.0/16", "10.11.0.0/16"]
REMOTE = ["10.20.0.0/16", "10.21.0.0/16"]
GWLBE = "vpce-0123456789abcdef0"


def status_fixture() -> dict:
    return {
        "BackendState": "Running",
        "TUN": True,
        "Self": {
            "AdvertisedRoutes": list(LOCAL),
            "AcceptedRoutes": list(REMOTE),
            "NoSNAT": True,
        },
    }


def route_fixture() -> dict:
    return {
        "Routes": [
            {"DestinationCidrBlock": prefix, "VpcEndpointId": GWLBE, "State": "active"}
            for prefix in LOCAL
        ]
    }


class IngressRouterReadinessTest(unittest.TestCase):
    def test_ready_router_requires_only_sanitized_fixture_inputs(self) -> None:
        result = readiness.validate_readiness(status_fixture(), route_fixture(), LOCAL, REMOTE, GWLBE)

        self.assertTrue(result["ready"])
        self.assertEqual(result["local_gwlbe"], GWLBE)
        self.assertEqual(result["local_site_cidrs"], LOCAL)

    def test_rejects_non_running_userspace_or_missing_kernel_tun(self) -> None:
        for field, value, message in (
            ("BackendState", "Stopped", "not Running"),
            ("TUN", False, "kernel TUN"),
        ):
            with self.subTest(field=field):
                status = status_fixture()
                status[field] = value
                with self.assertRaisesRegex(readiness.ReadinessError, message):
                    readiness.validate_readiness(status, route_fixture(), LOCAL, REMOTE, GWLBE)

    def test_local_advertisements_must_be_exact_and_without_snat(self) -> None:
        cases = {
            "missing": [LOCAL[0]],
            "broader": ["10.10.0.0/15", LOCAL[1]],
            "extra": [*LOCAL, "10.12.0.0/16"],
            "duplicate": [LOCAL[0], LOCAL[0], LOCAL[1]],
        }
        for name, advertised in cases.items():
            with self.subTest(name=name):
                status = status_fixture()
                status["Self"]["AdvertisedRoutes"] = advertised
                with self.assertRaisesRegex(readiness.ReadinessError, "advertisements|duplicate"):
                    readiness.validate_readiness(status, route_fixture(), LOCAL, REMOTE, GWLBE)

        status = status_fixture()
        status["Self"]["NoSNAT"] = False
        with self.assertRaisesRegex(readiness.ReadinessError, "SNAT"):
            readiness.validate_readiness(status, route_fixture(), LOCAL, REMOTE, GWLBE)

    def test_required_remote_routes_must_be_accepted(self) -> None:
        status = status_fixture()
        status["Self"]["AcceptedRoutes"] = [REMOTE[0]]

        with self.assertRaisesRegex(readiness.ReadinessError, "required remote routes.*10.21.0.0/16"):
            readiness.validate_readiness(status, route_fixture(), LOCAL, REMOTE, GWLBE)

    def test_each_local_prefix_needs_an_active_exact_gwlbe_route(self) -> None:
        cases = []
        missing = route_fixture()
        missing["Routes"].pop()
        cases.append(("missing", missing, "one exact"))
        wrong_target = route_fixture()
        wrong_target["Routes"][0]["VpcEndpointId"] = "vpce-other"
        cases.append(("wrong target", wrong_target, "does not select"))
        inactive = route_fixture()
        inactive["Routes"][0]["State"] = "blackhole"
        cases.append(("inactive", inactive, "not active"))
        bypass = route_fixture()
        bypass["Routes"].append(
            {"DestinationCidrBlock": "10.10.1.0/24", "GatewayId": "local", "State": "active"}
        )
        cases.append(("more specific bypass", bypass, "more-specific"))
        for name, routes, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(readiness.ReadinessError, message):
                    readiness.validate_readiness(status_fixture(), routes, LOCAL, REMOTE, GWLBE)

    def test_cli_reads_bounded_local_fixtures_without_cloud_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            status_path = directory / "status.json"
            routes_path = directory / "routes.json"
            status_path.write_text(json.dumps(status_fixture()))
            routes_path.write_text(json.dumps(route_fixture()))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/ingress_router_readiness.py"),
                    "--status-file",
                    str(status_path),
                    "--vpc-routes-file",
                    str(routes_path),
                    "--local-site-cidr",
                    LOCAL[0],
                    "--local-site-cidr",
                    LOCAL[1],
                    "--remote-site-cidr",
                    REMOTE[0],
                    "--remote-site-cidr",
                    REMOTE[1],
                    "--local-gwlbe",
                    GWLBE,
                ],
                text=True,
                capture_output=True,
                check=False,
                env={},
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["ready"], True)

    def test_input_size_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "oversized.json"
            path.write_bytes(b" " * (readiness.MAX_INPUT_BYTES + 1))
            with self.assertRaisesRegex(readiness.ReadinessError, "input limit"):
                readiness.load_json(path)


if __name__ == "__main__":
    unittest.main()
