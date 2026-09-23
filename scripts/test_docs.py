#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import unittest
from urllib.parse import unquote, urlsplit


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
DEVELOPER_DOCS = DOCS / "developer"

USER_PAGES = (
    "README.md",
    "architecture.md",
    "components.md",
    "deployment.md",
    "getting-started.md",
    "operations.md",
    "troubleshooting.md",
    "best-practices.md",
    "production-controller.md",
    "application-resilience.md",
    "terraform-example.md",
)
DEVELOPER_PAGES = (
    "README.md",
    "e2e-acceptance.md",
    "controller-e2e-acceptance.md",
    "aws-appliance-runbook.md",
    "aws-two-region-e2e-runbook.md",
)
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")


class DocsContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = (DOCS / "index.html").read_text()
        cls.sidebar = (DOCS / "_sidebar.md").read_text()
        cls.home = (DOCS / "README.md").read_text()
        cls.architecture = (DOCS / "architecture.md").read_text()
        cls.components = (DOCS / "components.md").read_text()
        cls.getting_started = (DOCS / "getting-started.md").read_text()
        cls.operations = (DOCS / "operations.md").read_text()
        cls.deployment = (DOCS / "deployment.md").read_text()
        cls.terraform_example = (DOCS / "terraform-example.md").read_text()
        cls.production_controller = (DOCS / "production-controller.md").read_text()
        cls.application_resilience = (DOCS / "application-resilience.md").read_text()
        cls.developer_home = (DEVELOPER_DOCS / "README.md").read_text()
        cls.e2e_acceptance = (DEVELOPER_DOCS / "e2e-acceptance.md").read_text()
        cls.controller_e2e_acceptance = (
            DEVELOPER_DOCS / "controller-e2e-acceptance.md"
        ).read_text()
        cls.appliance_runbook = (DEVELOPER_DOCS / "aws-appliance-runbook.md").read_text()
        cls.e2e_runbook = (DEVELOPER_DOCS / "aws-two-region-e2e-runbook.md").read_text()
        cls.root_readme = (ROOT / "README.md").read_text()
        cls.wire_wrapper = (ROOT / "scripts" / "component_wire_smoke.sh").read_text()
        cls.wire_smoke = (ROOT / "scripts" / "component_wire_smoke.py").read_text()
        paths = [ROOT / "README.md", *sorted(DOCS.rglob("*.md"))]
        cls.all_docs = {
            path.relative_to(ROOT).as_posix(): path.read_text() for path in paths
        }
        cls.all_content = "\n".join(cls.all_docs.values())

    def assert_contains_all(
        self, document: str, required: tuple[str, ...], *, case_sensitive: bool = False
    ) -> None:
        content = document if case_sensitive else document.lower()
        for value in required:
            expected = value if case_sensitive else value.lower()
            with self.subTest(value=value):
                self.assertIn(expected, content)

    def assert_patterns_in_order(
        self, document: str, patterns: tuple[str, ...]
    ) -> None:
        cursor = 0
        for pattern in patterns:
            match = re.search(pattern, document[cursor:], re.IGNORECASE | re.DOTALL)
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(
                    match,
                    f"ordered documentation pattern not found after offset {cursor}: {pattern}",
                )
            if match is None:
                return
            cursor += match.end()

    def test_docsify_entrypoint_is_bounded_and_loads_local_content(self) -> None:
        self.assertIn('id="app"', self.index)
        self.assertIn("docsify@4.13.1", self.index)
        self.assertIn("loadSidebar: true", self.index)
        self.assertNotIn("data:text", self.index.lower())

    def test_required_pages_are_in_the_restructured_locations(self) -> None:
        for page in USER_PAGES:
            with self.subTest(page=f"docs/{page}"):
                self.assertTrue((DOCS / page).is_file())
        for page in DEVELOPER_PAGES:
            with self.subTest(page=f"docs/developer/{page}"):
                self.assertTrue((DEVELOPER_DOCS / page).is_file())

    def test_root_readme_explains_the_product_and_deployment_path(self) -> None:
        self.assert_contains_all(
            self.root_readme,
            (
                "Envelope",
                "Experimental",
                "site-to-site",
                "Tailscale",
                "GWLB",
                "EC2",
                "production controller",
                "docs/deployment.md",
                "docs/architecture.md",
                "docs/getting-started.md",
            ),
            case_sensitive=True,
        )

    def test_sidebar_has_distinct_user_and_developer_sections(self) -> None:
        developer_heading = "## Developer E2E Documentation"
        developer_start = self.sidebar.index(developer_heading)
        user_targets = (
            "README.md",
            "architecture.md",
            "components.md",
            "deployment.md",
            "getting-started.md",
            "operations.md",
            "troubleshooting.md",
            "best-practices.md",
            "production-controller.md",
            "application-resilience.md",
            "terraform-example.md",
        )
        developer_targets = (
            "developer/e2e-acceptance.md",
            "developer/controller-e2e-acceptance.md",
            "developer/aws-appliance-runbook.md",
            "developer/aws-two-region-e2e-runbook.md",
        )
        for target in user_targets:
            with self.subTest(section="user", target=target):
                self.assertLess(self.sidebar.index(target), developer_start)
        for target in developer_targets:
            with self.subTest(section="developer", target=target):
                self.assertGreater(self.sidebar.index(target), developer_start)

    def test_markdown_links_resolve_relative_to_each_document(self) -> None:
        for name in self.all_docs:
            source = ROOT / name
            for raw_target in MARKDOWN_LINK.findall(self.all_docs[name]):
                target = raw_target.strip("<>")
                parsed = urlsplit(target)
                if not parsed.path or parsed.scheme or parsed.netloc or target.startswith("#"):
                    continue
                relative_path = pathlib.Path(unquote(parsed.path))
                resolved = (
                    ROOT / relative_path.relative_to("/")
                    if relative_path.is_absolute()
                    else source.parent / relative_path
                )
                with self.subTest(source=name, target=target):
                    self.assertTrue(
                        resolved.resolve().is_file(),
                        f"broken repository-relative Markdown link: {target}",
                    )

    def test_sidebar_targets_resolve(self) -> None:
        targets = re.findall(r"\[[^]]+\]\(([^)#]+)(?:#[^)]*)?\)", self.sidebar)
        self.assertTrue(targets)
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue((DOCS / target).resolve().is_file())

    def test_user_docs_explain_deployment_and_local_testing_boundaries(self) -> None:
        self.assert_contains_all(
            self.home,
            (
                "site-to-site network",
                "Tailscale",
                "GWLB",
                "Envelope targets",
                "Production controller",
                "Deployment Guide",
            ),
            case_sensitive=True,
        )
        self.assert_contains_all(
            self.getting_started,
            ("go build", "CAP_NET_RAW", "does not need `CAP_NET_ADMIN`", "not an AWS"),
            case_sensitive=True,
        )
        self.assert_contains_all(
            self.operations,
            (
                "read-only diagnosis",
                "Deployment Guide",
                "short-lived credentials",
                "cost review",
                "clean up",
            ),
            case_sensitive=True,
        )

    def test_deployment_guide_documents_the_real_terraform_phase_order(self) -> None:
        self.assert_contains_all(
            self.deployment,
            (
                "Build The Target Artifact",
                "Deploy The Appliance Topology",
                "Enroll Production Routers",
                "Deploy Controller Replicas",
                "Initialize And Activate Route Control",
                "Manual Deployment Order",
                "Rollback And Cleanup",
                "symmetric_topology.version = 3",
                "router_attestations",
                "deployment_lifecycle_role_arn",
            ),
            case_sensitive=True,
        )
        for root in (
            "example/terraform",
            "deploy/terraform/router-attestor",
            "deploy/terraform/envelope-controller",
        ):
            with self.subTest(root=root):
                self.assertIn(f"terraform -chdir={root} plan", self.deployment)
                self.assertIn(f"terraform -chdir={root} apply", self.deployment)
        self.assertNotRegex(self.deployment, r"(?im)^\s*aws\s+")
        self.assertNotRegex(self.deployment, r"(?im)^\s*tailscale\s+up\b")

    def test_architecture_explains_the_site_to_site_product(self) -> None:
        self.assertIn("```mermaid", self.architecture)
        self.assert_contains_all(
            self.architecture,
            (
                "site-to-site",
                "Tailscale",
                "Gateway Load Balancer",
                "Envelope target",
                "transport router",
                "production controller",
                "Deployment Guide",
            ),
        )

    def test_appliance_docs_define_the_ec2_only_staged_tailnet_contract(self) -> None:
        self.assert_contains_all(
            self.architecture,
            (
                "packet-scoped EC2 service",
                "does not create a TUN device",
                "target-side Tailscale enrollment",
                "ECS",
                "infrastructure",
                "intentionally empty",
                "no direct workload or router fallback route",
            ),
        )
        self.assert_contains_all(
            self.terraform_example,
            (
                "terraform-aws-modules/vpc/aws",
                "v6.7.2",
                "deployment_phase",
                "infrastructure",
                "targets",
                "HTTP `/healthz`",
                "UDP `6081`",
                "tagOwners",
                "autoApprovers",
                "172.16.4.0/24",
                "172.17.5.0/24",
                "reusable, preauthorized bootstrap keys",
                "regional encrypted SecureString",
                "v0.0.12",
                "checksum-pinned package installer",
                "pre-setup gate",
                "SOURCE.sha256",
            ),
            case_sensitive=True,
        )
        self.assertEqual(self.terraform_example.count('"action": "accept"'), 2)
        self.assertEqual(self.terraform_example.count('"tag:REVIEWED-ROUTER-TAG"'), 5)
        self.assert_contains_all(
            self.components,
            (
                "Envelope target",
                "Transport router",
                "Router attestor",
                "Production controller",
                "Deployment Order",
            ),
        )

    def test_developer_docs_describe_the_protected_boundary(self) -> None:
        self.assert_contains_all(
            self.developer_home,
            ("protected E2E acceptance", "historical run material", "does not authorize"),
        )
        self.assert_contains_all(
            self.e2e_acceptance,
            (
                "approved protected environment",
                "short-lived credentials",
                "cost review",
                "explicit expiry",
                "cleanup authority",
                "Do not use a raw Terraform apply to execute the protected failure workflow",
            ),
            case_sensitive=True,
        )
        self.assert_contains_all(
            self.controller_e2e_acceptance,
            ("Task 9.5", "remains unapproved and unexecuted", "None of these results authorizes a live run"),
            case_sensitive=True,
        )

    def test_production_controller_architecture_contract_is_complete(self) -> None:
        self.assert_contains_all(
            self.production_controller,
            (
                "standalone control-plane process",
                "at least three disposable replicas",
                "outside Envelope packet-target and Tailscale transport-router instances",
                "pinned `tsnet` observer",
                "overlapping exact local workload prefixes",
                "Native Tailscale HA",
                "strongly consistent DynamoDB",
                "monotonically increasing fencing terms",
                "regional authority",
                "Strict-majority fresh",
                "`ReplaceRoute`",
                "complete authoritative route snapshot",
                "before-snapshot",
                "durable `stable` state",
                "Automatic failback",
                "longer stability window",
                "durable fail-closed `degraded` state",
                "Security And Authority",
                "Availability Boundary",
            ),
            case_sensitive=True,
        )
        self.assert_contains_all(
            self.production_controller,
            (
                "does not use repository test scripts",
                "Python or shell orchestration, SSM",
                "router-side control agent",
                "read-only Go router attestor",
                "exposes no mutation API",
                "does not use embedded Raft",
                "Observation TTL removes stale observations only",
                "never decides lease correctness",
            ),
        )

    def test_controller_topology_deployment_health_and_iam_are_explicit(self) -> None:
        self.assert_contains_all(
            self.production_controller,
            (
                "private persistent state",
                "immutable topology",
                "AWS workload identity",
                "Tailnet credential references",
                "read-only",
                "GET /healthz",
                "GET /readyz",
                "GET /metrics",
                "DynamoDB",
                "DynamoDB conditional writes",
                "record versions",
                "fencing terms",
                "`ReplaceRoute`",
                "break-glass",
            ),
            case_sensitive=True,
        )
        self.assertRegex(
            self.production_controller,
            r"(?is)packet targets and transport routers retain no.{0,100}route-mutation permission",
        )

    def test_application_resilience_contract_covers_tcp_and_retryable_udp(self) -> None:
        self.assert_contains_all(
            self.application_resilience,
            (
                "does not transparently repair an established flow",
                "application responsibilities",
                "fresh TCP connections",
                "idempotency key",
                "same key and request body on every reconnect",
                "bounded context",
                "exponential backoff with jitter",
                "135-second deadline",
                "`net.Conn`",
                "net.Dialer",
                "IdempotencyKey",
                "transactional boundary",
                "MessageID",
                "Sequence",
                "ACK",
                "(ClientID, MessageID)",
                "deduplication window",
                "retransmission horizon",
                "durable outbox",
                "drop the first ACK",
                "one side effect",
                "not prove Envelope route convergence",
            ),
        )

    def test_local_validation_documents_current_packet_wire_smoke(self) -> None:
        self.assertIn("./scripts/component_wire_smoke.sh", self.getting_started)
        self.assertIn("python3 ./scripts/component_wire_smoke.py", self.wire_wrapper)
        for snapshot in ("forwarding_before", "routes_before", "interfaces_before"):
            self.assertGreaterEqual(self.wire_wrapper.count(snapshot), 2)
        self.assertIn("CAP_NET_RAW", self.wire_wrapper)
        self.assertNotIn("CAP_NET_ADMIN", self.wire_wrapper)
        self.assertIn("packet-turnaround", self.wire_smoke)
        self.assertIn("data != packet", self.wire_smoke)

    def test_moved_runbooks_keep_transfer_and_evidence_contracts(self) -> None:
        forward = (
            r"graceful and abrupt.{0,180}one durable CAS/lease transaction",
            r"persist the authorized transaction",
            r"temporarily expand the alternate",
            r"withdraw or stop the current",
            r"every opposite-site observer",
            r"replace every affected exact",
            r"(?:run the new-flow probe|probe new TCP and UDP flows)",
        )
        restoration = (
            r"restoration.{0,180}(?:same|that) transaction.{0,180}(?:this|the) order",
            r"restart the original owner.{0,160}alternate still covers",
            r"(?:return the alternate.{0,160}removing|remove the transferred prefix from the alternate)",
            r"(?:original|baseline) owner graph",
            r"restore (?:every|all) affected route",
            r"quiet verification window",
        )
        for name, document in (
            ("docs/developer/aws-appliance-runbook.md", self.appliance_runbook),
            ("docs/developer/aws-two-region-e2e-runbook.md", self.e2e_runbook),
        ):
            with self.subTest(page=name, phase="forward"):
                self.assert_patterns_in_order(document, forward)
            with self.subTest(page=name, phase="restoration"):
                self.assert_patterns_in_order(document, restoration)
            with self.subTest(page=name, phase="evidence"):
                self.assert_contains_all(
                    document,
                    (
                        "source prefix",
                        "fenced forward and restore generations",
                        "stable-node hashes",
                        "protected instance IDs",
                        "before/transferred/restored owner graphs",
                        "every opposite-site observer",
                        "absence of same-site local Tailnet routes and claims",
                        "current-to-alternate-to-original ENI transitions",
                        "restoration of advertisements, ownership, and routes",
                    ),
                )

    def test_docs_reject_unsafe_controller_and_continuity_claims(self) -> None:
        forbidden = (
            r"(?i)\bcontrollers?\s+(?:uses?|runs?|embeds?|requires?|depends?\s+on|is backed by)\s+(?:an?\s+)?(?:embedded\s+)?Raft\b",
            r"(?i)\b(?:Envelope\s+)?(?:packet\s+)?targets?\s+(?:run|runs|host|hosts|embed|embeds)\s+(?:an?\s+|the\s+)?(?:production\s+)?(?:failover\s+)?controller\b",
            r"(?i)\bcontrollers?\s+(?:is|are)\s+(?:run|hosted|embedded)\s+(?:inside|on)\s+(?:an?\s+|the\s+)?(?:Envelope\s+)?(?:packet\s+)?targets?\b",
            r"(?i)\b(?:Envelope\s+)?(?:packet\s+)?targets?\s+(?:has|have|receive|receives|retain|retains)\s+(?:AWS\s+|EC2\s+)?route[- ]mutation authority\b",
            r"(?i)\b(?:production\s+)?controllers?\s+(?:requires?|depends?\s+on|invokes?|executes?|uses?)\s+(?:the\s+)?(?:protected|acceptance|test)[- ]runner\b",
            r"(?i)\b(?:production\s+)?controllers?\s+(?:requires?|depends?\s+on|invokes?|executes?|uses?)\s+.{0,80}(?:repository\s+)?(?:Python|shell|test) scripts?\b",
            r"(?i)\b(?:production\s+)?controllers?\s+(?:requires?|depends?\s+on|invokes?|executes?|uses?)\s+.{0,80}SSM(?:\s+commands?)?\b",
            r"(?i)\b(?:production\s+)?runtime\s+requires?\s+.{0,100}router[- ]side (?:Envelope\s+)?agents?\b",
            r"(?i)\b(?:Envelope|controller|failover|recovery|topology)\s+(?:is|are|provides?|guarantees?|promises?|achieves?|delivers?)\s+(?:fully\s+)?hitless\b",
            r"(?i)\bUDP\s+(?:is|remains|will be)\s+lossless\b",
            r"(?i)\b(?:Envelope|controller|failover|recovery)\s+(?:has|guarantees?|provides?|promises?|ensures?|achieves?|delivers?)\s+(?:zero|no)\s+(?:packet|UDP|datagram)?[- ]?loss\b",
            r"(?i)\bEnvelope\s+(?:transparently\s+)?(?:repairs?|restores?|preserves?)\s+(?:established\s+)?flows?\b",
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)

    def test_docs_reject_raw_credentials_and_obsolete_configuration_claims(self) -> None:
        credential_patterns = (
            r"(?i)tskey-(?:auth|client|api)-[a-z0-9_-]{8,}",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"(?i)oauth_client_secret\s*[=:]\s*[\"'][^<\"'][^\"']{7,}[\"']",
        )
        obsolete_identifiers = (
            r"(?i)gwlb[-_]return[-_]cidrs",
            r"(?i)local[-_]delivery[-_]cidrs",
            r"(?i)remote[-_]tailnet[-_]cidrs",
            r"(?i)--flow-(?:capacity|timeout)",
            r"(?i)appliance_az_key",
        )
        for pattern in (*credential_patterns, *obsolete_identifiers):
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)
        self.assertNotRegex(
            self.all_content,
            r"(?i)(?<!not )\b(?:promises?|guarantees?|provides?)\s+(?:\w+\s+){0,2}hitless\b",
        )


if __name__ == "__main__":
    unittest.main()
