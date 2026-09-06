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
        cls.production_controller = (DOCS / "production-controller.md").read_text()
        cls.application_resilience = (DOCS / "application-resilience.md").read_text()
        cls.root_readme = (ROOT / "README.md").read_text()
        cls.wire_wrapper = (ROOT / "scripts" / "component_wire_smoke.sh").read_text()
        cls.wire_smoke = (ROOT / "scripts" / "component_wire_smoke.py").read_text()
        cls.all_docs = {
            path.relative_to(ROOT).as_posix(): path.read_text()
            for path in [ROOT / "README.md", *sorted(DOCS.glob("*.md"))]
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

    def test_sidebar_targets_resolve(self) -> None:
        targets = re.findall(r"\[[^]]+\]\(([^)#]+)(?:#[^)]*)?\)", self.sidebar)
        self.assertTrue(targets)
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue((DOCS / target).resolve().is_file())

    def test_production_guides_are_linked_from_navigation_and_onboarding(self) -> None:
        self.assert_contains_all(
            self.sidebar,
            (
                "production-controller.md",
                "application-resilience.md",
                "Controller Architecture and Operations",
                "Application Resilience",
            ),
            case_sensitive=True,
        )
        for name, document in (
            ("README.md", self.root_readme),
            ("docs/README.md", self.home),
            ("docs/getting-started.md", self.getting_started),
        ):
            with self.subTest(page=name):
                self.assertIn("production-controller.md", document)
                self.assertIn("application-resilience.md", document)
        self.assert_contains_all(
            self.home,
            (
                "runner-coordinated singleton advertisements",
                "overlapping exact-prefix native Tailscale HA",
                "controller-owned protected evidence is still pending",
                "packet targets: packet turnaround only",
                "transport routers:",
                "controllers:",
            ),
        )

    def test_production_controller_architecture_contract_is_complete(self) -> None:
        self.assert_contains_all(
            self.production_controller,
            (
                "standalone control-plane process",
                "at least three disposable replicas",
                "outside Envelope packet-target instances",
                "outside Tailscale transport-router instances",
                "embedded, pinned `tsnet` observer",
                "overlapping exact-prefix advertisements",
                "native Tailscale HA",
                "strongly consistent DynamoDB",
                "monotonically increasing fencing terms",
                "regional authority",
                "strict-majority quorum",
                "Health Hysteresis",
                "`ReplaceRoute`",
                "complete before-snapshot",
                "ordered route progress",
                "authoritatively",
                "durable `stable` state",
                "Automatic failback",
                "longer `failback_stability`",
                "`degraded` is fail-closed",
                "IAM And Secrets",
                "Rollback",
                "Regional Authority Limit",
            ),
            case_sensitive=True,
        )
        self.assert_contains_all(
            self.production_controller,
            (
                "does not require or invoke repository test scripts",
                "SSM commands",
                "acceptance manifests",
                "router-side control agent",
                "read-only Go router attestor",
                "no remote mutation HTTP endpoint",
                "does not use embedded Raft",
                "TTL applies only to stale observation garbage collection",
                "never decides lease correctness",
            ),
        )

    def test_controller_checkpoint_separates_offline_implementation_from_live_approval(self) -> None:
        self.assert_contains_all(
            self.production_controller,
            (
                "Task 7.5 has a complete native inspection and immutable enrollment path",
                "split acceptance implementation includes mocked phase integration",
                "Task 7.6 has implemented, tested lifecycle operations",
                "Live billable execution has not been approved or performed",
                "active reconciliation no longer initializes missing journals",
                "legacy iptables",
                "Exact-instance enrollment uses configured public-key authority",
                "CAP_NET_ADMIN",
                "configuration_sha256",
                "boot-only Go enrollment",
                "Initialization grants no activation",
                "separately labeled simulated evidence",
                "Do not enable the old runner by changing unavailable capabilities to true",
            ),
        )
        self.assertRegex(
            self.production_controller,
            r"(?is)persist the transaction ID.{0,240}before any external mutation",
        )
        self.assertRegex(
            self.production_controller,
            r"(?is)alternate becomes normal durable `stable` state.{0,300}"
            r"new transaction.{0,240}longer `failback_stability`",
        )

    def test_split_acceptance_external_iam_and_retained_lock_runbook(self) -> None:
        runbook = (ROOT / "deploy/terraform/controller-acceptance/README.md").read_text()
        self.assert_contains_all(runbook, (
            "Task 9.5 remains", "include_claim_keys", "run_attempt",
            "envelope-production-deployment", "envelope-production-observation",
            "acceptance-boundary", "observer_sessions_until", "unconditional",
            "same account", "ExternalId", "TF_DATA_DIR", "two consecutive",
            "non-expiring", "no automatic adoption", "claim version last",
            "Manual recovery", "not a deployable configuration",
        ))

    def test_controller_topology_deployment_health_and_iam_are_explicit(self) -> None:
        self.assert_contains_all(
            self.production_controller,
            (
                "`schema_version`",
                "`deployment_id`",
                "`controller_ids[]`",
                "`policy`",
                "`dynamodb`",
                "`tailnet`",
                "`sites[]`",
                "`routers[]`",
                "`domains[]`",
                "canonical document hash",
                "private persistent `tsnet` state",
                "--read-only",
                "--dry-run",
                "GET /healthz",
                "GET /readyz",
                "GET /metrics",
                "DynamoDB",
                "`GetItem`",
                "conditional `PutItem`",
                "one bounded read per configured observer partition",
                "No shared-partition `Query` is granted",
                "exact table/account encryption context",
                "`DescribeInstances`",
                "`DescribeInstanceStatus`",
                "`DescribeNetworkInterfaces`",
                "`DescribeRouteTables`",
                "`ReplaceRoute`",
                "break-glass",
                "one full lease duration",
            ),
            case_sensitive=True,
        )
        self.assertRegex(
            self.production_controller,
            r"(?is)packet-target and transport-router roles.{0,100}"
            r"no route-mutation permission",
        )
        self.assertRegex(
            self.production_controller,
            r"(?is)rollback is a quiescent ownership transfer.{0,1200}"
            r"revoke the controller's `ReplaceRoute` authority",
        )

    def test_protected_controller_conformance_runbook_is_fail_closed(self) -> None:
        self.assert_contains_all(
            self.production_controller,
            (
                "Protected Controller Conformance",
                "envelope-production-deployment",
                "envelope-production-observation",
                "private endpoint reachability",
                "ENVELOPE_PRODUCTION_CONTROLLER_SPLIT_CONFIG_TEMPLATE_B64",
                "two consecutive zero-residual audits",
                "Do not dispatch the workflow without separate task 9.5 approval",
                "external IAM setup and inspected recovery runbook",
                "scripts/test_controller_acceptance_phases.py",
                "ENVELOPE_PRODUCTION_CONTROLLER_CONFIG_TEMPLATE_B64",
                "scripts/aws_production_controller_e2e.py",
                "explicit legacy-v2 runner",
                "explicitly denies every route and route-table-association actuator",
                "ENVELOPE_RUNNER_ROUTE_MUTATION_DENIED=true",
                "ENVELOPE_CONTROLLER_TSNET_AUTH_KEY",
                "ENVELOPE_CONTROLLER_ADMIN_API_KEY",
                "invocation-tagged run-owned SecureString parameters",
                "bounded stable invocation-tagged visibility",
                "temporary AWS session credential",
                "Scanner-rejected evidence is never written or uploaded",
                "Remote SSM commands are allowlisted to the dedicated workload instances",
                "read-only mode",
                "at most 32 domains",
                "higher fence",
                "durable alternate",
                "stability-gated failback",
                "aws-production-controller-v3",
                "zero-residual",
                "task 9.5",
                "--hard-timeout-seconds 10800",
                "must not add a competing destroy trap",
                "stop at capability preflight",
                "cannot produce passing task 9.5 evidence",
                "separate deployment, observation, quiescence, and cleanup jobs",
                "automatically recoverable",
                "single exact object version",
                "repeated exact reads prove the instance running",
                "forensic state",
                "six-hour role session",
                "Only after sanitized evidence upload succeeds",
                "independently require the exact cleanup sequence",
            ),
            case_sensitive=True,
        )
        self.assertRegex(
            self.production_controller,
            r"(?is)rolls active controllers back to read-only.{0,700}"
            r"only then deletes both backend state keys",
        )

    def test_proposed_controller_slo_clocks_are_separate_and_unproven(self) -> None:
        self.assertGreaterEqual(
            self.production_controller.lower().count(
                "initial objectives pending protected controller evidence"
            ),
            2,
        )
        self.assert_contains_all(
            self.production_controller,
            (
                "not current production SLOs",
                "is not evidence for this controller profile",
                "Measure per failover domain at p99",
                "Failure detection",
                "15 seconds",
                "Native ownership",
                "45 seconds",
                "Exact route convergence",
                "30 seconds",
                "Fresh-flow recovery",
                "composite detection-to-recovery",
                "105 seconds",
                "Established TCP outcome",
                "0% minimum",
                "100% may require reconnect",
                "Permitted raw UDP loss",
                "100% of unacknowledged datagrams",
                "no lossless UDP objective",
                "separate clocks",
            ),
            case_sensitive=True,
        )
        self.assert_patterns_in_order(
            self.production_controller,
            (
                r"Failure detection.{0,300}15 seconds",
                r"Native ownership.{0,300}45 seconds",
                r"Exact route convergence.{0,300}30 seconds",
                r"Fresh-flow recovery.{0,360}105 seconds",
                r"Established TCP outcome.{0,360}0% minimum",
                r"Permitted raw UDP loss.{0,360}100% of unacknowledged datagrams",
            ),
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
        self.assertRegex(
            self.application_resilience,
            r"(?is)for attempt := 0; attempt < 32; attempt\+\+.{0,1800}"
            r"DialContext.{0,1800}waitContext\(ctx, jitter\(backoff\)\)",
        )
        self.assertRegex(
            self.application_resilience,
            r"(?is)for attempt in 1\.\.32:.{0,1200}frame\.kind == ACK.{0,1000}"
            r"rto = min\(2 \* rto, 5s\)",
        )
        self.assertRegex(
            self.application_resilience,
            r"(?is)prior = lookup\(client_id, message_id\).{0,900}"
            r"store dedup record and ack.{0,300}authenticate_and_send\(ack\)",
        )

    def test_docs_reject_unsafe_controller_and_continuity_claims(self) -> None:
        forbidden = (
            r"(?i)\bcontrollers?\s+(?:uses?|runs?|embeds?|requires?|"
            r"depends?\s+on|is backed by)\s+(?:an?\s+)?(?:embedded\s+)?Raft\b",
            r"(?i)\b(?:Envelope\s+)?(?:packet\s+)?targets?\s+"
            r"(?:run|runs|host|hosts|embed|embeds)\s+(?:an?\s+|the\s+)?"
            r"(?:production\s+)?(?:failover\s+)?controller\b",
            r"(?i)\bcontrollers?\s+(?:is|are)\s+"
            r"(?:run|hosted|embedded)\s+(?:inside|on)\s+(?:an?\s+|the\s+)?"
            r"(?:Envelope\s+)?(?:packet\s+)?targets?\b",
            r"(?i)\b(?:Envelope\s+)?(?:packet\s+)?targets?\s+"
            r"(?:has|have|receive|receives|retain|retains)\s+(?:AWS\s+|EC2\s+)?"
            r"route[- ]mutation authority\b",
            r"(?i)\b(?:production\s+)?controllers?\s+"
            r"(?:requires?|depends?\s+on|invokes?|executes?|uses?)\s+(?:the\s+)?"
            r"(?:protected|acceptance|test)[- ]runner\b",
            r"(?i)\b(?:production\s+)?controllers?\s+"
            r"(?:requires?|depends?\s+on|invokes?|executes?|uses?)\s+.{0,80}"
            r"(?:repository\s+)?(?:Python|shell|test) scripts?\b",
            r"(?i)\b(?:production\s+)?controllers?\s+"
            r"(?:requires?|depends?\s+on|invokes?|executes?|uses?)\s+.{0,80}"
            r"SSM(?:\s+commands?)?\b",
            r"(?i)\b(?:production\s+)?runtime\s+requires?\s+.{0,100}"
            r"router[- ]side (?:Envelope\s+)?agents?\b",
            r"(?i)\b(?:Envelope|controller|failover|recovery|topology)\s+"
            r"(?:is|are|provides?|guarantees?|promises?|achieves?|delivers?)\s+"
            r"(?:fully\s+)?hitless\b",
            r"(?i)\bUDP\s+(?:is|remains|will be)\s+lossless\b",
            r"(?i)\b(?:Envelope|controller|failover|recovery)\s+"
            r"(?:has|guarantees?|provides?|promises?|ensures?|achieves?|delivers?)\s+"
            r"(?:zero|no)\s+"
            r"(?:packet|UDP|datagram)?[- ]?loss\b",
            r"(?i)\bEnvelope\s+(?:transparently\s+)?"
            r"(?:repairs?|restores?|preserves?)\s+(?:established\s+)?flows?\b",
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)

    def test_local_validation_documents_current_packet_wire_smoke(self) -> None:
        documented_commands = (
            "python3 scripts/component_wire_smoke.py",
            "python3 ./scripts/component_wire_smoke.py",
            "./scripts/component_wire_smoke.sh",
            "bash scripts/component_wire_smoke.sh",
        )
        command = next(
            (
                value
                for value in documented_commands
                if value in self.getting_started
            ),
            None,
        )
        self.assertIsNotNone(
            command,
            "getting-started must run component_wire_smoke.py or its current wrapper",
        )
        if command and command.endswith("component_wire_smoke.sh"):
            self.assertIn(
                "python3 ./scripts/component_wire_smoke.py", self.wire_wrapper
            )
            for snapshot in (
                "forwarding_before",
                "routes_before",
                "interfaces_before",
            ):
                self.assertGreaterEqual(self.wire_wrapper.count(snapshot), 2)
            self.assertIn("CAP_NET_RAW", self.wire_wrapper)
            self.assertNotIn("CAP_NET_ADMIN", self.wire_wrapper)
            self.assertNotRegex(
                self.wire_wrapper,
                r"(?i)\b(?:ip\s+tuntap|envelope0|--tun(?:-name)?|create(?:s|d)?\s+(?:a\s+)?tun)\b",
            )
        self.assertIn("packet-turnaround", self.wire_smoke)
        self.assertIn("data != packet", self.wire_smoke)
        self.assertNotIn("tun_rx_packets", self.wire_smoke.split("forbidden =", 1)[0])

    def test_docs_define_packet_turnaround_and_post_inspection_routing(self) -> None:
        self.assert_contains_all(
            self.all_content,
            (
                "version-2",
                "packet-turnaround",
                "gwlbe post-inspection",
                "transport router",
                "source addresses",
                "no nat",
                "source/destination checks",
            ),
        )
        self.assert_contains_all(
            self.home,
            (
                "packet-turnaround",
                "gwlbe post-inspection route",
                "transport-router eni",
                "without nat",
                "not hitless",
            ),
        )
        self.assert_contains_all(
            self.appliance_runbook,
            (
                "packet turnaround",
                "post-inspection",
                "runner-owned eni failover",
                "not hitless",
                "cost",
            ),
        )
        self.assertRegex(self.appliance_runbook.lower(), r"\brestor(?:e|es|ed|ation)\b")
        self.assert_contains_all(
            self.e2e_runbook,
            (
                "post-inspection route",
                "eni route exercise",
                "restore",
                "not hitless",
                "cost boundary",
            ),
        )
        self.assertRegex(
            self.e2e_runbook.lower(),
            r"\b(?:packet|target)[- ]turnaround(?:s)?\b",
        )

    def test_key_pages_keep_local_and_protected_boundaries(self) -> None:
        for document, required in (
            (
                self.home,
                ("GENEVE", "Linux-only", "packet-turnaround", "not hitless"),
            ),
            (
                self.getting_started,
                ("go build", "CAP_NET_RAW", "packet-turnaround", "protected"),
            ),
            (
                self.terraform_example,
                ("illustrative input shape", '"version": 2', "target_az_keys"),
            ),
            (
                self.appliance_runbook,
                ("Target Readiness", "Security Boundary", "bounded"),
            ),
            (
                self.e2e_runbook,
                ("Evidence Expectations", "fresh approved run identity", "not hitless"),
            ),
        ):
            self.assert_contains_all(document, required, case_sensitive=True)

    def test_docs_use_exact_version_2_transport_schema_names(self) -> None:
        self.assertIn('"version": 2', self.terraform_example)
        for field in (
            "local_site_cidrs",
            "remote_site_cidrs",
            "workload_subnet_cidrs",
            "transport_subnet_cidrs",
            "gwlbe_subnet_cidrs",
            "gwlb_subnet_cidrs",
            "target_subnet_cidrs",
            "management_subnet_cidr",
            "target_az_keys",
            "transport_router_az_keys",
        ):
            self.assertEqual(self.terraform_example.count(f'"{field}"'), 2)
        for stale_name in (
            "ingress_subnet_cidrs",
            "ingress_router_az_keys",
            "ingress_router_fleet",
            "tailnet_ingress",
        ):
            self.assertNotIn(stale_name, self.all_content)
        self.assert_contains_all(
            self.terraform_example,
            (
                "exactly two sites",
                "two enabled azs per site",
                "non-empty",
                "pairwise disjoint",
                "exactly cover",
                "exactly match",
                "disjoint from the local set",
            ),
        )

    def test_pages_define_deterministic_source_prefix_baseline(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
            "docs/terraform-example.md": self.terraform_example,
            "docs/getting-started.md": self.getting_started,
        }
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assert_contains_all(
                    document,
                    (
                        "exactly one",
                        "non-empty",
                        "pairwise disjoint",
                        "exactly cover",
                        "forwarding-capable",
                        "bounded takeover",
                        "all local prefixes",
                    ),
                )
                self.assertRegex(document.lower(), r"workload[- ]prefix")

    def test_pages_define_destination_prefix_endpoint_symmetry(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
            "docs/terraform-example.md": self.terraform_example,
            "docs/getting-started.md": self.getting_started,
        }
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assert_contains_all(
                    document,
                    (
                        "destination workload prefix's AZ GWLBE",
                        "independent of the receiving router AZ",
                    ),
                )

    def test_pages_separate_route_mutation_and_recovery_proof_deadlines(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
            "docs/terraform-example.md": self.terraform_example,
            "docs/getting-started.md": self.getting_started,
        }
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assert_contains_all(
                    document,
                    (
                        "mutation_timeout_seconds",
                        "recovery_timeout_seconds",
                        "sequential TCP and UDP",
                    ),
                    case_sensitive=True,
                )
                self.assertRegex(document.lower(), r"route (?:mutation and )?convergence")

    def test_pages_define_controlled_continuity_completion(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
            "docs/terraform-example.md": self.terraform_example,
            "docs/getting-started.md": self.getting_started,
        }
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assert_contains_all(
                    document,
                    (
                        "full durable transaction reservation",
                        "600-second paired-control allowance",
                        "runner-controlled completion",
                        "at least 20",
                        "final post-mutation marker",
                        "successful-send completion timestamp",
                        "target-process streams",
                    ),
                )

    def test_pages_define_same_az_map_as_the_only_owner_assignment(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
            "docs/terraform-example.md": self.terraform_example,
        }
        invalid_cross_az = re.compile(
            r"(?i)(?:no (?:valid )?cross-AZ initial mapping|"
            r"cross-AZ initial mapping (?:is )?(?:invalid|rejected)|"
            r"no cross-AZ initial mapping is valid)"
        )
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assert_contains_all(
                    document,
                    (
                        "initial_transport_router_az_by_gwlbe_az",
                        "same-AZ key equality",
                        "advertised_prefix",
                        "source_workload_prefix",
                        "separate owner input",
                        "primary ENI",
                    ),
                    case_sensitive=True,
                )
                self.assertRegex(document, invalid_cross_az)
                self.assertRegex(document, r"(?i)(?:there is no|no) separate owner input")

    def test_pages_define_remote_only_tailnet_and_local_underlay(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
            "docs/terraform-example.md": self.terraform_example,
            "docs/getting-started.md": self.getting_started,
        }
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assert_contains_all(
                    document,
                    (
                        "opposite-site observer",
                        "configured stable-node",
                        "protected remote prefix",
                        "table 52 contains exactly",
                        "no local-site prefix",
                        "no same-site observer",
                        "protected local `PrimaryRoutes` claim",
                        "self- or sibling-owned",
                        "`main` and the VPC underlay",
                        "`iif tailscale0`",
                        "singleton advertisements",
                        "control-plane stable identities",
                        "opposite-site observations",
                        "ENI",
                    ),
                )
                self.assertRegex(
                    document,
                    r"(?is)(?:each|every) opposite-site observer.{0,160}"
                    r"select.{0,100}protected remote prefix.{0,100}"
                    r"configured stable[- ]node",
                )
                self.assertRegex(
                    document,
                    r"(?is)table 52 contains exactly.{0,160}opposite site.{0,160}"
                    r"no local-site prefix",
                )
                self.assertRegex(
                    document,
                    r"(?is)no same-site observer.{0,120}protected local "
                    r"`PrimaryRoutes` claim",
                )
                self.assertRegex(
                    document,
                    r"(?is)every local prefix.{0,160}self-.{0,40}sibling-owned"
                    r".{0,160}`main`.{0,80}VPC underlay",
                )
                self.assertRegex(
                    document,
                    r"(?is)`iif tailscale0`.{0,240}all local prefixes.{0,160}"
                    r"normal and takeover paths",
                )
                self.assertRegex(
                    document,
                    r"(?is)source-prefix owner/ENI coupling.{0,160}derived from"
                    r".{0,160}singleton advertisements.{0,160}"
                    r"control-plane stable identities.{0,160}"
                    r"opposite-site observations",
                )

    def test_pages_record_ha25_contract_correction_without_acceptance(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
            "docs/terraform-example.md": self.terraform_example,
            "docs/getting-started.md": self.getting_started,
        }
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assertRegex(
                    document,
                    r"(?is)ha25.{0,240}exactly the two opposite-site workload routes"
                    r".{0,180}only opposite-site serving paths",
                )
                self.assertRegex(
                    document,
                    r"(?is)(?:failed protected run `ha25`|protected run `ha25` failed)"
                    r".{0,360}(?:did not (?:complete|pass)|not a passing)",
                )

    def test_runbooks_order_one_durable_failover_and_restoration_transaction(self) -> None:
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
            r"(?:return the alternate.{0,160}removing|"
            r"remove the transferred prefix from the alternate)",
            r"(?:original|baseline) owner graph",
            r"restore (?:every|all) affected route",
            r"quiet verification window",
        )
        for name, document in (
            ("docs/aws-appliance-runbook.md", self.appliance_runbook),
            ("docs/aws-two-region-e2e-runbook.md", self.e2e_runbook),
        ):
            with self.subTest(page=name, phase="forward"):
                self.assert_patterns_in_order(document, forward)
            with self.subTest(page=name, phase="restoration"):
                self.assert_patterns_in_order(document, restoration)
            with self.subTest(page=name, phase="durability"):
                self.assert_contains_all(
                    document,
                    (
                        "unaffected",
                        "normal",
                        "overlap",
                        "forbidden",
                        "temporary overlap",
                        "only",
                        "terminal result",
                        "cleanup handoff",
                        "lease expiry",
                        "successor",
                        "CAS recovery claim",
                    ),
                )
                self.assertRegex(
                    document,
                    r"(?is)unaffected owner.{0,60}(?:stay|stays|remain|remains) fixed",
                )
                self.assertRegex(
                    document,
                    r"(?is)normal.{0,120}(?:overlap|duplicate).{0,120}forbidden",
                )
                self.assertRegex(
                    document,
                    r"(?is)temporary overlap.{0,180}only.{0,100}(?:durable|persisted) transfer",
                )
                self.assertRegex(
                    document,
                    r"(?is)terminal result.{0,120}cleanup handoff.{0,180}unrestored",
                )
                self.assertRegex(
                    document,
                    r"(?is)lease expiry.{0,100}successor.{0,100}CAS recovery claim",
                )

    def test_runbooks_define_complete_transfer_evidence(self) -> None:
        for name, document in (
            ("docs/aws-appliance-runbook.md", self.appliance_runbook),
            ("docs/aws-two-region-e2e-runbook.md", self.e2e_runbook),
        ):
            with self.subTest(page=name):
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

    def test_headscale_harness_does_not_claim_protected_ownership_or_recovery(self) -> None:
        self.assert_contains_all(
            self.getting_started,
            (
                "Headscale",
                "credentialed stable-node ownership",
                "stable-node-to-protected-instance binding",
                "GWLBE owner-ENI coupling",
                "AWS route replacement",
                "durable CAS/lease recovery",
                "cannot prove the protected ownership or recovery contract",
            ),
            case_sensitive=True,
        )

    def test_docs_separate_target_and_transport_capabilities(self) -> None:
        paragraphs = re.split(r"\n\s*\n", self.all_content)
        target_capability = [
            paragraph
            for paragraph in paragraphs
            if re.search(r"(?i)\btargets?\b", paragraph)
            and "CAP_NET_RAW" in paragraph
        ]
        self.assertTrue(target_capability, "target CAP_NET_RAW requirement is undocumented")
        self.assertTrue(
            any(
                re.search(
                    r"(?is)(?:only.{0,80}CAP_NET_RAW|"
                    r"(?:does not require|without|not)\s+`?CAP_NET_ADMIN`?)",
                    paragraph,
                )
                for paragraph in target_capability
            ),
            "target capability text must make CAP_NET_RAW-only isolation explicit",
        )
        transport_capability = [
            paragraph
            for paragraph in paragraphs
            if re.search(
                r"(?is)transport[- ]router(?:s|\s+host-network\s+unit)?"
                r".{0,180}(?:requires?|receives?|uses?|is granted|capabilit)"
                r".{0,100}CAP_NET_ADMIN",
                paragraph,
            )
        ]
        self.assertTrue(
            transport_capability,
            "transport-router CAP_NET_ADMIN requirement is undocumented",
        )
        self.assertTrue(
            any("CAP_NET_RAW" in paragraph for paragraph in transport_capability),
            "transport host-network capability set must document CAP_NET_ADMIN and CAP_NET_RAW",
        )

    def test_pages_define_non_hitless_guidance_and_cost_boundaries(self) -> None:
        pages = {
            "README.md": self.root_readme,
            "docs/README.md": self.home,
            "docs/aws-appliance-runbook.md": self.appliance_runbook,
            "docs/aws-two-region-e2e-runbook.md": self.e2e_runbook,
        }
        for name, document in pages.items():
            with self.subTest(page=name):
                self.assertRegex(document.lower(), r"\bnot hitless\b")
                self.assertRegex(document.lower(), r"\bnot atomic\b")
                self.assertIn("established TCP", document)
                self.assertRegex(document, r"\bUDP\b.{0,80}\b(?:loss|lose)\b|\blose\b.{0,40}\bUDP\b")
                self.assertRegex(document.lower(), r"\bretr(?:y|ies)\b")
                self.assertIn("$4.00/hour", document)
                self.assertIn("$5.00/hour", document)
                self.assertRegex(
                    document,
                    r"(?is)(?:(?:exclude|omit).{0,350}(?:processing|transfer)|(?:processing|transfer).{0,350}outside)",
                )
                self.assertRegex(
                    document,
                    r"(?is)(?:current|fresh).{0,160}pric",
                )

    def test_docs_reject_obsolete_configuration_and_affirmative_path_claims(self) -> None:
        obsolete_identifiers = (
            r"(?i)gwlb[-_]return[-_]cidrs",
            r"(?i)local[-_]delivery[-_]cidrs",
            r"(?i)remote[-_]tailnet[-_]cidrs",
            r"(?i)--flow-(?:capacity|timeout)",
            r"(?i)appliance_az_key",
        )
        obsolete_affirmative_claims = (
            r"(?i)\b(?:supports?|provides?|offers?|enables?)\s+(?:backward\s+)?compatibility\b",
            r"(?i)\bcompatibility (?:mode|adapter|parser|layer)\s+is\s+(?:available|enabled|supported)\b",
            r"(?i)\b(?:backward[- ]compatibility|compatibility (?:behavior|configuration|fields?))\s+(?:is|are|remains?)\s+(?:accepted|available|enabled|supported)\b",
            r"(?i)\b(?:uses?|requires?|supports?|implements?|provides?)\s+(?:an?\s+)?directional(?:[- ]lane|[- ]routing|\s+topology)",
            r"(?i)\bdirectional(?:[- ]lanes?|[- ]routing|\s+topology)\s+(?:is|are|remains?)\s+(?:enabled|required|supported)\b",
            r"(?i)\btargets?\s+(?:now\s+|also\s+)?(?:create|creates|use|uses|join|joins|has|have|depends?\s+on)\s+(?:an?\s+)?(?:tun|tailscale)\b",
            r"(?i)\btargets?\s+(?:now\s+|also\s+)?(?:inject|injects|forward|forwards|route|routes)\s+(?:the\s+)?(?:decapsulated\s+|inner\s+|site\s+)(?:packet|traffic)",
            r"(?i)\btargets?\s+(?:send|sends|forward|forwards)\s+(?:inner\s+)?traffic\s+(?:directly\s+)?to\s+(?:the\s+)?(?:vpc|tailscale)",
            r"(?i)\bdirect[- ]forwarding\s+(?:is|remains)\s+(?:enabled|required|supported|used)\b",
            r"(?i)raw (?:IPv4|UDP).{0,40}GENEVE",
            r"(?i)return traffic.{0,80}re-encapsulat",
            r"(?i)(?:one|single) GWLBE",
            r"(?i)(?:one|single) GWLB target",
            r"(?i)sole process",
        )
        for pattern in (*obsolete_identifiers, *obsolete_affirmative_claims):
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)

        stale_ownership_claims = (
            r"(?i)each (?:ready )?router advertises every exact local-site CIDR",
            r"(?i)routers advertise the same exact local-site CIDRs",
            r"(?i)local(?:-site)? prefix may (?:have|select) zero or one",
            r"(?i)optional (?:exact )?local table-52",
            r"(?i)\b(?:configured|same-site).{0,40}\bsibling owner\b",
            r"(?i)\b(?:non-self|sibling-owned) local prefix.{0,120}"
            r"\b(?:has|must have|shall have|requires)\b.{0,120}"
            r"\b(?:owner|table[- ]52)\b",
            r"(?i)\brequired (?:non-self )?local table[- ]52",
            r"(?i)\blocal(?:-site)? prefix.{0,120}matching exact table[- ]52",
            r"(?i)\btable 52 (?:shall|must) contain.{0,120}"
            r"\blocal(?:-site)? prefix",
            r"(?i)(?:choice|selection) among (?:duplicate|overlapping) local-site advertisements",
            r"(?i)same-AZ (?:values|selection|mappings) (?:are|is) preferred.{0,100}cross-AZ",
            r"(?i)explicit (?:same-site )?cross-AZ (?:value|mapping|selection).{0,50}(?:is valid|remains valid)",
            r"(?i)\b(?:a|an) (?:reviewed |explicit )?(?:same-site )?cross-AZ (?:initial )?(?:mapping|value|selection) (?:is|remains) (?:valid|allowed|permitted|supported)",
            r"(?i)Tailnet (?:choice|ownership).{0,100}independent of the GWLBE.{0,80}ENI",
        )
        for pattern in stale_ownership_claims:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)

        self.assertNotIn("terraform apply", self.all_content.lower())
        self.assertNotIn("aws_appliance.py", self.all_content)
        self.assertNotIn("aws_two_region_e2e.py", self.all_content)

    def test_docs_reject_raw_credentials_and_hitless_promises(self) -> None:
        credential_patterns = (
            r"(?i)tskey-(?:auth|client|api)-[a-z0-9_-]{8,}",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"(?i)oauth_client_secret\s*[=:]\s*[\"'][^<\"'][^\"']{7,}[\"']",
        )
        for pattern in credential_patterns:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.all_content, pattern)
        self.assertNotRegex(
            self.all_content,
            r"(?i)(?<!not )\b(?:promises?|guarantees?|provides?)\s+(?:\w+\s+){0,2}hitless\b",
        )


if __name__ == "__main__":
    unittest.main()
