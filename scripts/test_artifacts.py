#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("inspect_artifact", ROOT / "scripts" / "inspect_artifact.py")
assert SPEC and SPEC.loader
INSPECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECTOR)


class ArtifactBuildTest(unittest.TestCase):
    def test_build_info_child_environment_excludes_oauth_values(self) -> None:
        completed = mock.Mock(
            stdout=(
                "/fixture: go1.26.2\n"
                "\tbuild\tGOOS=linux\n"
                "\tbuild\tGOARCH=amd64\n"
                f"\tbuild\tvcs.revision={'a' * 40}\n"
                "\tbuild\tvcs.modified=false\n"
            )
        )
        with mock.patch.dict(os.environ, {"CUSTOM_TS_SECRET": "secret"}), mock.patch.object(
            INSPECTOR.subprocess, "run", return_value=completed
        ) as run:
            INSPECTOR.go_build_info(pathlib.Path("/fixture"), ("CUSTOM_TS_SECRET",))
        self.assertNotIn("CUSTOM_TS_SECRET", run.call_args.kwargs["env"])

    def test_reproducible_static_linux_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for output in (first, second):
                subprocess.run(
                    [
                        str(ROOT / "scripts" / "build_artifacts.sh"),
                        "--output-dir",
                        output,
                        "--version",
                        "test.1",
                        "--allow-dirty",
                    ],
                    cwd=ROOT,
                    check=True,
                    text=True,
                    capture_output=True,
                )
            manifests = [json.loads((pathlib.Path(output) / "manifest.json").read_text()) for output in (first, second)]
            self.assertEqual(manifests[0], manifests[1])
            self.assertIsInstance(manifests[0]["source_dirty"], bool)
            self.assertEqual(
                manifests[0]["go_version"],
                (ROOT / "scripts" / "reviewed-go-toolchain.txt").read_text().strip(),
            )
            self.assertEqual([entry["architecture"] for entry in manifests[0]["artifacts"]], ["amd64", "arm64"])
            for entry in manifests[0]["artifacts"]:
                artifact = pathlib.Path(first) / entry["file"]
                inspected = INSPECTOR.inspect(artifact)
                self.assertTrue(inspected["static"])
                self.assertEqual(inspected["architecture"], entry["architecture"])
                self.assertEqual(inspected["sha256"], entry["sha256"])
                self.assertEqual(inspected["goos"], entry["goos"])
                self.assertEqual(inspected["goarch"], entry["goarch"])
                self.assertEqual(inspected["go_version"], entry["go_version"])
                self.assertEqual(inspected["vcs_revision"], manifests[0]["revision"])
                self.assertEqual(inspected["vcs_modified"], manifests[0]["source_dirty"])
                self.assertEqual(entry["version"], manifests[0]["version"])
                metadata = subprocess.run(
                    ["go", "version", "-m", str(artifact)],
                    check=True,
                    text=True,
                    capture_output=True,
                ).stdout
                self.assertIn("GOOS=linux", metadata)
                self.assertIn(f"GOARCH={entry['architecture']}", metadata)
                self.assertIn("vcs.revision=", metadata)

    def test_rejects_architecture_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            subprocess.run(
                [
                    str(ROOT / "scripts" / "build_artifacts.sh"),
                    "--output-dir",
                    output,
                    "--architectures",
                    "amd64",
                    "--allow-dirty",
                ],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            )
            result = subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts" / "inspect_artifact.py"),
                    str(pathlib.Path(output) / "envelope-linux-amd64"),
                    "--expect-architecture",
                    "arm64",
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("sha256", result.stderr.lower())

    def test_rejects_build_provenance_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            subprocess.run(
                [
                    str(ROOT / "scripts" / "build_artifacts.sh"),
                    "--output-dir",
                    output,
                    "--architectures",
                    "amd64",
                    "--version",
                    "test.1",
                    "--allow-dirty",
                ],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            )
            manifest = json.loads((pathlib.Path(output) / "manifest.json").read_text())
            artifact = pathlib.Path(output) / "envelope-linux-amd64"
            cases = {
                "revision": {"expected_revision": "0" * 40},
                "modified": {"expected_modified": not manifest["source_dirty"]},
                "toolchain": {"expected_go_version": "go0.0.0"},
                "version": {"expected_version": "missing-version"},
                "digest": {"expected_sha256": "0" * 64},
            }
            for name, arguments in cases.items():
                with self.subTest(name=name), self.assertRaises(ValueError):
                    INSPECTOR.inspect(artifact, **arguments)


if __name__ == "__main__":
    unittest.main()
