#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


class DocsContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = (DOCS / "index.html").read_text()
        cls.sidebar = (DOCS / "_sidebar.md").read_text()
        cls.home = (DOCS / "README.md").read_text()
        cls.getting_started = (DOCS / "getting-started.md").read_text()
        cls.terraform_example = (DOCS / "terraform-example.md").read_text()
        cls.appliance_runbook = (DOCS / "aws-appliance-runbook.md").read_text()
        cls.e2e_runbook = (DOCS / "aws-two-region-e2e-runbook.md").read_text()
        cls.root_readme = (ROOT / "README.md").read_text()
        cls.all_docs = {
            path.relative_to(ROOT).as_posix(): path.read_text()
            for path in [cls.root_readme_path(), *sorted(DOCS.glob("*.md"))]
        }
        cls.all_content = "\n".join(cls.all_docs.values())

    @staticmethod
    def root_readme_path() -> pathlib.Path:
        return ROOT / "README.md"

    def test_docsify_entrypoint_is_bounded_and_loads_local_content(self) -> None:
        self.assertIn('id="app"', self.index)
        self.assertIn("docsify@4.13.1", self.index)
        self.assertIn("loadSidebar: true", self.index)
        self.assertNotIn("data:text", self.index.lower())

    def test_sidebar_targets_resolve(self) -> None:
        targets = re.findall(r"\[[^]]+\]\(([^)#]+)(?:#[^)]*)?\)", self.sidebar)
        self.assertTrue(targets)
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue((DOCS / target).resolve().is_file())

    def test_documentation_requires_symmetric_two_site_topology(self) -> None:
        required = (
            "symmetric inline",
            "local-site-cidrs",
            "remote-site-cidrs",
            "tailscale ingress routers",
            "at least two",
            "gwlbe",
            "no nat",
            "breaking",
        )
        content = self.all_content.lower()
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, content)

        for content, required_values in (
            (self.home, ("GENEVE", "envelope0", "tailscale0", "Linux-only", "not hitless")),
            (self.getting_started, ("go build", "component_wire_smoke.sh", "CAP_NET_ADMIN", "protected")),
            (self.terraform_example, ("illustrative input shape", '"version": 2', "target_az_keys", "ingress_router_az_keys")),
            (self.appliance_runbook, ("Target Readiness", "Security Boundary", "bounded")),
            (self.e2e_runbook, ("Evidence Expectations", "not hitless", "fresh approved run identity")),
        ):
            for value in required_values:
                with self.subTest(document=content[:30], value=value):
                    self.assertIn(value, content)

    def test_docs_reject_obsolete_configuration_and_production_claims(self) -> None:
        obsolete_patterns = (
            r"(?i)gwlb[-_]return[-_]cidrs",
            r"(?i)local[-_]delivery[-_]cidrs",
            r"(?i)remote[-_]tailnet[-_]cidrs",
            r"(?i)--flow-(?:capacity|timeout)",
            r"(?i)appliance_az_key",
            r"(?i)CAP_NET_RAW",
            r"(?i)raw (?:IPv4|UDP).{0,40}GENEVE",
            r"(?i)return traffic.{0,80}re-encapsulat",
            r"(?i)(?:one|single) GWLBE",
            r"(?i)(?:one|single) GWLB target",
            r"(?i)sole process",
            r"(?i)(?:production|supported|live)[^.]{0,100}directional",
        )
        for pattern in obsolete_patterns:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)

        self.assertNotIn("terraform apply", self.all_content.lower())
        self.assertNotIn("aws_appliance.py", self.all_content)
        self.assertNotIn("aws_two_region_e2e.py", self.all_content)

    def test_docs_reject_raw_credentials_and_hitless_claims(self) -> None:
        credential_patterns = (
            r"(?i)tskey-(?:auth|client|api)-[a-z0-9_-]{8,}",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"(?i)oauth_client_secret\s*[=:]\s*[\"'][^<\"'][^\"']{7,}[\"']",
        )
        for pattern in credential_patterns:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)

        self.assertRegex(self.all_content.lower(), r"\b(?:not hitless|no hitless guarantee)\b")
        self.assertNotRegex(
            self.all_content,
            r"(?i)(?<!not )\b(?:promises?|guarantees?|provides?)\s+(?:\w+\s+){0,2}hitless\b",
        )


if __name__ == "__main__":
    unittest.main()
