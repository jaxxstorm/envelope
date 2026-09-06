#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_controller_artifacts.sh"
MANIFEST_NAME = "controller-manifest.json"
COMPONENT = "envelope-controller"
TOPOLOGY_COMPONENT = "envelope-controller-topology"
DEPLOY_COMPONENT = "envelope-controller-deploy"
ATTESTOR_COMPONENT = "envelope-router-attestor"
PACKET_MANIFEST_FIXTURE = '{"schema":1,"component":"envelope"}\n'
SPEC = importlib.util.spec_from_file_location(
    "inspect_artifact", ROOT / "scripts" / "inspect_artifact.py"
)
assert SPEC and SPEC.loader
INSPECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECTOR)


class ControllerArtifactBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = BUILDER.read_text()
        cls._temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._temporary.cleanup)
        workspace = pathlib.Path(cls._temporary.name)
        cls.outputs = (workspace / "first", workspace / "second")
        for output in cls.outputs:
            output.mkdir()
            (output / "manifest.json").write_text(PACKET_MANIFEST_FIXTURE)
            subprocess.run(
                [
                    str(BUILDER),
                    "--output-dir",
                    str(output),
                    "--version",
                    "test.1",
                    "--allow-dirty",
                ],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            )
        cls.manifests = tuple(
            json.loads((output / MANIFEST_NAME).read_text()) for output in cls.outputs
        )

    def test_reproducible_controller_artifacts(self) -> None:
        self.assertEqual(self.manifests[0], self.manifests[1])
        for entry in self.manifests[0]["artifacts"]:
            self.assertEqual(
                (self.outputs[0] / entry["file"]).read_bytes(),
                (self.outputs[1] / entry["file"]).read_bytes(),
            )

    def test_controller_artifacts_are_static_linux_binaries(self) -> None:
        for entry in self.manifests[0]["artifacts"]:
            artifact = self.outputs[0] / entry["file"]
            inspected = INSPECTOR.inspect(artifact)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o755)
            self.assertTrue(inspected["static"])
            self.assertEqual(inspected["architecture"], entry["architecture"])
            self.assertEqual(inspected["goos"], "linux")
            self.assertEqual(inspected["goarch"], entry["goarch"])
            self.assertEqual(inspected["sha256"], entry["sha256"])
            self.assertEqual(inspected["size"], entry["size"])

    def test_controller_artifact_metadata_matches_source(self) -> None:
        manifest = self.manifests[0]
        revision = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        source_date_epoch = int(
            subprocess.run(
                ["git", "show", "-s", "--format=%ct", "HEAD"],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
        )
        reviewed_go_version = (
            (ROOT / "scripts" / "reviewed-go-toolchain.txt").read_text().strip()
        )

        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["version"], "test.1")
        self.assertEqual(manifest["revision"], revision)
        self.assertEqual(manifest["source_date_epoch"], source_date_epoch)
        self.assertIsInstance(manifest["source_dirty"], bool)
        self.assertEqual(manifest["go_version"], reviewed_go_version)
        for entry in manifest["artifacts"]:
            artifact = self.outputs[0] / entry["file"]
            inspected = INSPECTOR.inspect(
                artifact,
                expected_architecture=entry["architecture"],
                expected_sha256=entry["sha256"],
                expected_revision=revision,
                expected_modified=manifest["source_dirty"],
                expected_go_version=reviewed_go_version,
                expected_version="test.1",
            )
            self.assertEqual(inspected["vcs_revision"], entry["vcs_revision"])
            self.assertEqual(inspected["vcs_modified"], entry["vcs_modified"])
            metadata = subprocess.run(
                ["go", "version", "-m", str(artifact)],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            self.assertIn("GOOS=linux", metadata)
            self.assertIn(f"GOARCH={entry['architecture']}", metadata)
            self.assertIn(f"vcs.revision={revision}", metadata)
            self.assertIn(
                f"vcs.modified={str(manifest['source_dirty']).lower()}", metadata
            )

    def test_rejects_controller_architecture_mismatch(self) -> None:
        artifact = self.outputs[0] / "envelope-controller-linux-amd64"
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts" / "inspect_artifact.py"),
                str(artifact),
                "--expect-architecture",
                "arm64",
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("architecture amd64 does not match arm64", result.stderr)

    def test_controller_manifest_identity_is_unambiguous(self) -> None:
        manifest = self.manifests[0]
        entries = manifest["artifacts"]
        self.assertEqual(manifest["component"], COMPONENT)
        self.assertEqual(
            [entry["architecture"] for entry in entries],
            ["amd64"] * 4 + ["arm64"] * 4,
        )
        self.assertEqual(
            [entry["file"] for entry in entries],
            [
                "envelope-controller-linux-amd64",
                "envelope-controller-topology-linux-amd64",
                "envelope-controller-deploy-linux-amd64",
                "envelope-router-attestor-linux-amd64",
                "envelope-controller-linux-arm64",
                "envelope-controller-topology-linux-arm64",
                "envelope-controller-deploy-linux-arm64",
                "envelope-router-attestor-linux-arm64",
            ],
        )
        identities = {(entry["component"], entry["architecture"]) for entry in entries}
        self.assertEqual(
            identities,
            {
                (COMPONENT, "amd64"),
                (COMPONENT, "arm64"),
                (TOPOLOGY_COMPONENT, "amd64"),
                (TOPOLOGY_COMPONENT, "arm64"),
                (DEPLOY_COMPONENT, "amd64"),
                (DEPLOY_COMPONENT, "arm64"),
                (ATTESTOR_COMPONENT, "amd64"),
                (ATTESTOR_COMPONENT, "arm64"),
            },
        )
        self.assertEqual(len({entry["file"] for entry in entries}), len(entries))
        for architecture in ("amd64", "arm64"):
            selected = {
                entry["component"]: entry
                for entry in entries
                if entry["architecture"] == architecture
            }
            self.assertEqual(
                set(selected),
                {COMPONENT, TOPOLOGY_COMPONENT, DEPLOY_COMPONENT, ATTESTOR_COMPONENT},
            )
            self.assertEqual(
                selected[COMPONENT]["ec2_architecture"],
                "x86_64" if architecture == "amd64" else "arm64",
            )
            self.assertEqual(
                selected[TOPOLOGY_COMPONENT]["ec2_architecture"],
                selected[COMPONENT]["ec2_architecture"],
            )
        for output in self.outputs:
            self.assertTrue((output / MANIFEST_NAME).is_file())
            self.assertEqual(
                (output / "manifest.json").read_text(), PACKET_MANIFEST_FIXTURE
            )

    def test_release_builder_records_and_rejects_unreviewed_dirty_state(self) -> None:
        self.assertIn("refusing a release artifact from a dirty worktree", self.builder)
        self.assertIn('\\"vcs_modified\\":$source_dirty', self.builder)
        manifest = self.manifests[0]
        self.assertTrue(
            all(
                entry["vcs_modified"] is manifest["source_dirty"]
                for entry in manifest["artifacts"]
            )
        )


if __name__ == "__main__":
    unittest.main()
