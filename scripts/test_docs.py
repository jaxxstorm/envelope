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
