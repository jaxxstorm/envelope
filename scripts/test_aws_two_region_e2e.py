#!/usr/bin/env python3

from __future__ import annotations

import base64
import contextlib
import copy
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import queue
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from types import SimpleNamespace
from typing import Any, Mapping, Sequence


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_two_region_e2e as e2e  # noqa: E402

AGENT_PATH = ROOT / "example" / "terraform" / "cloud-init" / "envelope-e2e-agent.py"
AGENT_SPEC = importlib.util.spec_from_file_location("envelope_e2e_agent", AGENT_PATH)
assert AGENT_SPEC and AGENT_SPEC.loader
AGENT = importlib.util.module_from_spec(AGENT_SPEC)
sys.modules[AGENT_SPEC.name] = AGENT
AGENT_SPEC.loader.exec_module(AGENT)


def deployment_value() -> dict[str, Any]:
    return {
        "west": {
            "region": "us-west-2",
            "initiator": {
                "instance_id": "i-0123456789abcdef0",
                "private_ip": "10.10.1.10",
            },
            "responder": {
                "instance_id": "i-1123456789abcdef0",
                "private_ip": "10.10.1.11",
            },
        },
        "east": {
            "region": "us-east-1",
            "initiator": {
                "instance_id": "i-2123456789abcdef0",
                "private_ip": "10.20.1.10",
            },
            "responder": {
                "instance_id": "i-3123456789abcdef0",
                "private_ip": "10.20.1.11",
            },
        },
    }


def terraform_output() -> dict[str, Any]:
    return {
        "workloads": {
            "sensitive": False,
            "type": ["object", {}],
            "value": deployment_value(),
        }
    }


def parsed_deployment() -> e2e.Deployment:
    return e2e.parse_deployment_output(terraform_output())


def protected_output() -> dict[str, Any]:
    value = deployment_value()
    identities = {
        ("west", "initiator"): (
            "a",
            "us-west-2a",
            "subnet-0123456789abcdef0",
            "10.10.1.0/24",
            "rtb-0123456789abcdef0",
        ),
        ("west", "responder"): (
            "b",
            "us-west-2b",
            "subnet-1123456789abcdef0",
            "10.10.2.0/24",
            "rtb-1123456789abcdef0",
        ),
        ("east", "initiator"): (
            "a",
            "us-east-1a",
            "subnet-2123456789abcdef0",
            "10.20.1.0/24",
            "rtb-2123456789abcdef0",
        ),
        ("east", "responder"): (
            "b",
            "us-east-1b",
            "subnet-3123456789abcdef0",
            "10.20.2.0/24",
            "rtb-3123456789abcdef0",
        ),
    }
    value["west"]["responder"]["private_ip"] = "10.10.2.11"
    value["east"]["responder"]["private_ip"] = "10.20.2.11"
    for site in ("west", "east"):
        value[site].pop("region")
        for role in ("initiator", "responder"):
            az_key, availability_zone, subnet_id, cidr, route_table_id = identities[(site, role)]
            value[site][role].update(
                {
                    "az_key": az_key,
                    "availability_zone": availability_zone,
                    "subnet_id": subnet_id,
                    "cidr": cidr,
                    "route_table_id": route_table_id,
                }
            )
    artifact_sha = "a" * 64
    revision = "b" * 40
    runtime = {}
    for site, peer in (("west", "east"), ("east", "west")):
        runtime[site] = {
            "routing_mode": "manage",
            "tun_name": "envelope0",
            "underlay_interface": "ens5",
            "tailscale_iface": "tailscale0",
            "gwlb_return_cidrs": [identities[(site, "initiator")][3]],
            "local_delivery_cidrs": [identities[(site, "responder")][3]],
            "remote_tailnet_cidrs": [
                identities[(peer, "initiator")][3],
                identities[(peer, "responder")][3],
            ],
            "routing_table_id": 100,
            "routing_rule_priority": 100,
            "artifact_sha256": artifact_sha,
            "artifact_revision": revision,
        }
    return {
        "instance_ids": {
            "value": {"west": "i-4123456789abcdef0", "east": "i-5123456789abcdef0"}
        },
        "workload_instances": {"value": value},
        "vpc_ids": {"value": {"west": "vpc-0123456789abcdef0", "east": "vpc-1123456789abcdef0"}},
        "gwlb_target_group_arns": {
            "value": {
                "west": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/run-west/0123456789abcdef",
                "east": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/run-east/1123456789abcdef",
            }
        },
        "gwlb_endpoint_ids": {
            "value": {
                "west": {"a": "vpce-0123456789abcdef0", "b": "vpce-1123456789abcdef0"},
                "east": {"a": "vpce-2123456789abcdef0", "b": "vpce-3123456789abcdef0"},
            }
        },
        "flow_log_evidence": {
            "value": {
                "west": {
                    "flow_log_id": "fl-0123456789abcdef0",
                    "log_group_arn": "arn:aws:logs:us-west-2:123456789012:log-group:/aws/vpc-flow-logs/fixture/west",
                    "region": "us-west-2",
                },
                "east": {
                    "flow_log_id": "fl-1123456789abcdef0",
                    "log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc-flow-logs/fixture/east",
                    "region": "us-east-1",
                },
            }
        },
        "envelope_runtime_config": {"value": runtime},
        "e2e_load_profile": {
            "value": {
                "profile_id": "fixture-load-v1",
                "approved_at": "2026-08-20T10:00:00Z",
                "safe_inner_mtu": 1280,
                "maximum_tcp_mss": 1240,
                "sustained_tcp_duration_seconds": 3,
                "minimum_sustained_tcp_bytes": 1024,
                "iperf_duration_seconds": 3,
                "minimum_throughput_mbps": 1.0,
                "concurrent_duration_seconds": 3,
                "concurrent_tcp_flows": 2,
                "concurrent_udp_flows": 2,
                "maximum_udp_loss_percent": 1.0,
                "maximum_p99_latency_ms": 100.0,
            }
        },
        "cost_profile": {
            "value": {
                "profile": "directional-lane-acceptance",
                "resource_counts": {
                    "appliance_instances": 2,
                    "workload_instances": 4,
                    "vpc_flow_logs": 2,
                    "cloudwatch_log_groups": 2,
                    "flow_log_iam_roles": 1,
                    "regional_targets": {"west": 1, "east": 1},
                },
            }
        },
    }


def ready_lifecycle_manifest(deployment: Mapping[str, Any]) -> dict[str, Any]:
    source = {
        "revision": "b" * 40,
        "repository_path": str(ROOT),
        "sha256": "c" * 64,
    }
    return {
        "schema": 2,
        "run_id": "fixture-live",
        "phase": "ready",
        "terraform_source": {**source, "files": {"main.tf": "dGVycmFmb3JtIHt9Cg=="}},
        "saved_plan": {
            "path": "/protected-run/apply.tfplan",
            "sha256": "d" * 64,
            "replacement": None,
            "source": source,
            "apply_started": True,
            "applied": True,
            "applied_at": "2026-08-20T11:00:00Z",
        },
        "deployment": copy.deepcopy(deployment),
        "tailnet": {
            "name": "fixture.example",
            "tag": "tag:envelope-ci",
            "auth_key_description": "Envelope acceptance fixture-live",
            "auth_key_id": "key-id",
            "key_generation": 1,
            "pending_revoke_key_ids": [],
            "expected_hostnames": ["fixture-live-west", "fixture-live-east"],
            "nodes_expected": True,
            "device_ids": {"west": "device-west", "east": "device-east"},
        },
    }


class DurableManifestStore:
    def __init__(self, manifest: Mapping[str, Any]) -> None:
        self.value = copy.deepcopy(manifest)
        self.remote_etag: str | None = '"fixture-etag-0"'
        self.recover_count = 0
        self.recover_hook: Any = None
        self.write_hook: Any = None
        self.writes: list[tuple[dict[str, Any], str | None]] = []

    def recover(self) -> dict[str, Any]:
        self.recover_count += 1
        if self.recover_hook is not None:
            self.recover_hook(self)
        return copy.deepcopy(self.value)

    def commit(self, value: dict[str, Any], if_match: str | None) -> None:
        expected = self.remote_etag
        if if_match is not None and if_match != expected:
            raise e2e.LifecycleError("fixture durable manifest compare-and-swap rejected")
        self.value = copy.deepcopy(value)
        self.writes.append((copy.deepcopy(value), if_match))
        self.remote_etag = f'"fixture-etag-{len(self.writes)}"'

    def write(self, value: dict[str, Any], *, if_match: str | None = None) -> None:
        if self.write_hook is not None:
            self.write_hook(self, value, if_match)
            return
        self.commit(value, if_match)


class DeploymentParsingTest(unittest.TestCase):
    def test_parses_wrapped_role_aware_shape(self) -> None:
        deployment = parsed_deployment()

        self.assertEqual(deployment.target("west", "initiator").region, "us-west-2")
        self.assertEqual(deployment.target("east", "responder").private_ip, "10.20.1.11")
        self.assertEqual(
            [(target.site, target.role) for target in deployment.targets],
            [
                ("west", "initiator"),
                ("west", "responder"),
                ("east", "initiator"),
                ("east", "responder"),
            ],
        )
        self.assertEqual(e2e.parse_deployment_output(deployment.as_dict()), deployment)

    def test_accepts_role_regions_and_an_unambiguous_named_output(self) -> None:
        value = deployment_value()
        for site in ("west", "east"):
            region = value[site].pop("region")
            for role in ("initiator", "responder"):
                value[site][role]["region"] = region
        deployment = e2e.parse_deployment_output({"future_workload_output": {"value": value}})
        self.assertEqual(deployment.west.responder.region, "us-west-2")

    def test_parses_complete_workload_instances_network_identity(self) -> None:
        value = deployment_value()
        identity = {
            ("west", "initiator"): ("a", "us-west-2a", "subnet-0123456789abcdef0", "10.10.1.0/24", "rtb-0123456789abcdef0"),
            ("west", "responder"): ("b", "us-west-2b", "subnet-1123456789abcdef0", "10.10.1.0/24", "rtb-1123456789abcdef0"),
            ("east", "initiator"): ("a", "us-east-1a", "subnet-2123456789abcdef0", "10.20.1.0/24", "rtb-2123456789abcdef0"),
            ("east", "responder"): ("b", "us-east-1b", "subnet-3123456789abcdef0", "10.20.1.0/24", "rtb-3123456789abcdef0"),
        }
        for site in ("west", "east"):
            value[site].pop("region")
            for role in ("initiator", "responder"):
                az_key, availability_zone, subnet_id, cidr, route_table_id = identity[(site, role)]
                value[site][role].update(
                    {
                        "az_key": az_key,
                        "availability_zone": availability_zone,
                        "subnet_id": subnet_id,
                        "cidr": cidr,
                        "route_table_id": route_table_id,
                    }
                )

        deployment = e2e.parse_deployment_output({"workload_instances": {"value": value}})

        self.assertEqual(deployment.west.initiator.region, "us-west-2")
        self.assertEqual(deployment.east.responder.az_key, "b")
        self.assertEqual(deployment.east.responder.route_table_id, "rtb-3123456789abcdef0")
        self.assertEqual(e2e.parse_deployment_output(deployment.as_dict()), deployment)

    def test_rejects_missing_or_contradictory_roles_and_duplicate_targets(self) -> None:
        missing = terraform_output()
        del missing["workloads"]["value"]["west"]["responder"]
        with self.assertRaisesRegex(e2e.DeploymentError, "initiator and responder"):
            e2e.parse_deployment_output(missing)

        contradictory = terraform_output()
        contradictory["workloads"]["value"]["east"]["initiator"]["role"] = "responder"
        with self.assertRaisesRegex(e2e.DeploymentError, "contradicts"):
            e2e.parse_deployment_output(contradictory)

        duplicate = terraform_output()
        duplicate["workloads"]["value"]["east"]["responder"]["instance_id"] = "i-0123456789abcdef0"
        with self.assertRaisesRegex(e2e.DeploymentError, "unique instance_id"):
            e2e.parse_deployment_output(duplicate)


class ProtectedDeploymentParsingTest(unittest.TestCase):
    def test_parses_complete_exact_directional_topology(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())

        self.assertEqual(len(deployment.appliances), 2)
        self.assertEqual(len(deployment.workloads.targets), 4)
        self.assertEqual(deployment.west_runtime.gwlb_return_cidrs, ("10.10.1.0/24",))
        self.assertEqual(deployment.east_runtime.local_delivery_cidrs, ("10.20.2.0/24",))
        self.assertEqual(deployment.endpoint_ids["west"]["a"], "vpce-0123456789abcdef0")
        self.assertEqual(deployment.load_profile.safe_inner_mtu, 1280)
        self.assertRegex(deployment.load_profile.sha256, r"^[0-9a-f]{64}$")

    def test_load_profile_is_required_and_strictly_bounded(self) -> None:
        missing = protected_output()
        del missing["e2e_load_profile"]
        with self.assertRaisesRegex(e2e.DeploymentError, "e2e_load_profile"):
            e2e.parse_protected_deployment_output(missing)

        unsafe_mss = protected_output()
        unsafe_mss["e2e_load_profile"]["value"]["maximum_tcp_mss"] = 1241
        with self.assertRaisesRegex(e2e.LoadProfileError, "MSS"):
            e2e.parse_protected_deployment_output(unsafe_mss)

        unapproved_shape = protected_output()
        unapproved_shape["e2e_load_profile"]["value"]["invented_threshold"] = 1
        with self.assertRaisesRegex(e2e.DeploymentError, "unsupported"):
            e2e.parse_protected_deployment_output(unapproved_shape)

    def test_rejects_role_overlap_missing_endpoint_and_wrong_resource_count(self) -> None:
        overlap = protected_output()
        overlap["envelope_runtime_config"]["value"]["west"]["local_delivery_cidrs"] = ["10.10.1.0/24"]
        with self.assertRaisesRegex(e2e.DeploymentError, "local-delivery"):
            e2e.parse_protected_deployment_output(overlap)

        endpoint = protected_output()
        del endpoint["gwlb_endpoint_ids"]["value"]["west"]["a"]
        with self.assertRaisesRegex(e2e.DeploymentError, "same-AZ"):
            e2e.parse_protected_deployment_output(endpoint)

        count = protected_output()
        count["cost_profile"]["value"]["resource_counts"]["workload_instances"] = 3
        with self.assertRaisesRegex(e2e.DeploymentError, "two appliances, four workloads"):
            e2e.parse_protected_deployment_output(count)

        flow_log = protected_output()
        flow_log["flow_log_evidence"]["value"]["east"]["region"] = "us-west-2"
        with self.assertRaisesRegex(e2e.DeploymentError, "differs from the workload region"):
            e2e.parse_protected_deployment_output(flow_log)

    def test_managed_flow_log_capture_is_read_only_and_preserves_lifecycle_ownership(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())

        class FlowLogAWS:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], str | None]] = []

            def json(self, args: list[str], *, region: str | None = None) -> dict[str, Any]:
                self.calls.append((list(args), region))
                operation = args[1]
                site = "west" if region == "us-west-2" else "east"
                target = deployment.flow_logs[site]
                if operation == "describe-flow-logs":
                    return {
                        "FlowLogs": [
                            {
                                "FlowLogId": target.flow_log_id,
                                "ResourceId": deployment.appliance(site).vpc_id,
                                "FlowLogStatus": "ACTIVE",
                                "DeliverLogsStatus": "SUCCESS",
                                "LogDestinationType": "cloud-watch-logs",
                                "LogDestination": target.log_group_arn,
                            }
                        ]
                    }
                if operation == "describe-log-groups":
                    return {
                        "logGroups": [
                            {
                                "logGroupName": target.log_group_name,
                                "arn": target.log_group_arn + ":*",
                                "retentionInDays": 7,
                            }
                        ]
                    }
                raise AssertionError(f"unexpected operation {operation}")

        aws = FlowLogAWS()
        config = SimpleNamespace(run_id="fixture-live", sites={})
        with tempfile.TemporaryDirectory() as temporary:
            operations = e2e.AwsLiveOperations(config, aws, pathlib.Path(temporary))
            handle = operations.start_flow_logs(deployment, timeout_seconds=5)
            closed = operations.stop_flow_logs(handle, timeout_seconds=5)

        self.assertTrue(closed["ownership_preserved"])
        called_operations = [args[1] for args, _region in aws.calls]
        self.assertNotIn("create-flow-logs", called_operations)
        self.assertNotIn("delete-flow-logs", called_operations)
        self.assertNotIn("put-bucket-policy", called_operations)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class InvocationMissing(Exception):
    def __init__(self) -> None:
        super().__init__("eventual consistency")
        self.response = {"Error": {"Code": "InvocationDoesNotExist"}}


class ScriptedAWS:
    def __init__(self, polls: list[object], *, cancellation_polls: list[object] | None = None) -> None:
        self.polls = list(polls)
        self.cancellation_polls = list(cancellation_polls or [])
        self.cancellation_requested = False
        self.calls: list[tuple[list[str], str | None]] = []

    def json(self, args: list[str], *, region: str | None = None) -> dict[str, Any]:
        self.calls.append((list(args), region))
        operation = args[1]
        if operation == "send-command":
            return {"Command": {"CommandId": "11111111-2222-3333-4444-555555555555"}}
        if operation == "get-command-invocation":
            selected = self.cancellation_polls if self.cancellation_requested else self.polls
            value = selected.pop(0) if selected else {"Status": "InProgress", "ResponseCode": -1}
            if isinstance(value, BaseException):
                raise value
            assert isinstance(value, dict)
            return value
        if operation == "cancel-command":
            self.cancellation_requested = True
            return {}
        raise AssertionError(f"unexpected fake operation: {operation}")


class SSMRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.target = parsed_deployment().west.initiator
        self.command = e2e.SSMCommand(self.target, ("/opt/envelope/e2e-agent probe",), timeout_seconds=2)

    def test_invocation_does_not_exist_is_retried_and_output_is_redacted(self) -> None:
        access_key = "ASIA" + "ABCDEFGHIJKLMNOP"
        aws = ScriptedAWS(
            [
                InvocationMissing(),
                {
                    "Status": "Success",
                    "ResponseCode": 0,
                    "StandardOutputContent": "token=very-secret-value",
                    "StandardErrorContent": access_key,
                },
            ]
        )
        clock = FakeClock()
        runner = e2e.SSMRunner(aws, clock=clock, sleep=clock.sleep, poll_interval_seconds=0.1)

        result = runner.execute(self.command, wait_timeout_seconds=1)

        self.assertTrue(result.succeeded)
        self.assertNotIn("very-secret-value", result.stdout)
        self.assertNotIn(access_key, result.stderr)
        self.assertNotIn("commands", repr(self.command))
        self.assertEqual([call[0][1] for call in aws.calls], ["send-command", "get-command-invocation", "get-command-invocation"])
        self.assertTrue(all(region == "us-west-2" for _args, region in aws.calls))

    def test_send_command_bounds_delivery_and_remote_execution_independently(self) -> None:
        aws = ScriptedAWS([])
        runner = e2e.SSMRunner(aws)

        command_id = runner.send(self.command, timeout_seconds=0.5)

        self.assertEqual(command_id, "11111111-2222-3333-4444-555555555555")
        send_args = aws.calls[0][0]
        timeout_index = send_args.index("--timeout-seconds")
        self.assertEqual(send_args[timeout_index + 1], "30")
        parameters = json.loads(send_args[send_args.index("--parameters") + 1])
        self.assertEqual(parameters["executionTimeout"], ["2"])
        self.assertEqual(parameters["commands"], list(self.command.commands))
        self.assertEqual(self.command.timeout_seconds, 2)

        maximum = e2e.SSMCommand(self.target, ("true",), timeout_seconds=3600)
        runner.send(maximum, timeout_seconds=0.5)
        maximum_args = aws.calls[1][0]
        self.assertEqual(maximum_args[maximum_args.index("--timeout-seconds") + 1], "3600")
        maximum_parameters = json.loads(maximum_args[maximum_args.index("--parameters") + 1])
        self.assertEqual(maximum_parameters["executionTimeout"], ["3600"])

    def test_wait_timeout_requests_bounded_cancellation(self) -> None:
        aws = ScriptedAWS(
            [InvocationMissing(), {"Status": "InProgress", "ResponseCode": -1}],
            cancellation_polls=[{"Status": "Cancelled", "ResponseCode": -1}],
        )
        clock = FakeClock()
        runner = e2e.SSMRunner(
            aws,
            clock=clock,
            sleep=clock.sleep,
            poll_interval_seconds=0.25,
            api_timeout_seconds=0.5,
        )

        with self.assertRaisesRegex(e2e.SSMTimeout, "terminal state Cancelled confirmed"):
            runner.execute(
                self.command,
                send_timeout_seconds=0.5,
                wait_timeout_seconds=1.0,
                cancel_timeout_seconds=0.5,
            )

        operations = [args[1] for args, _region in aws.calls]
        self.assertEqual(operations[0], "send-command")
        self.assertEqual(operations[-2:], ["cancel-command", "get-command-invocation"])
        self.assertGreaterEqual(operations.count("get-command-invocation"), 2)
        cancel_args = next(args for args, _region in aws.calls if args[1] == "cancel-command")
        self.assertIn(self.target.instance_id, cancel_args)

    def test_unknown_status_and_poll_api_error_cancel_and_confirm_terminal_state(self) -> None:
        cases = {
            "unknown": {"Status": "FutureStatus", "ResponseCode": -1},
            "api-error": RuntimeError("poll API unavailable"),
        }
        for name, failure in cases.items():
            with self.subTest(name=name):
                aws = ScriptedAWS(
                    [failure],
                    cancellation_polls=[{"Status": "Cancelled", "ResponseCode": -1}],
                )
                runner = e2e.SSMRunner(aws, poll_interval_seconds=0.01, api_timeout_seconds=0.5)

                with self.assertRaisesRegex(e2e.SSMError, "terminal state Cancelled confirmed"):
                    runner.execute(
                        self.command,
                        send_timeout_seconds=0.5,
                        wait_timeout_seconds=0.5,
                        cancel_timeout_seconds=0.5,
                    )

                self.assertEqual(
                    [args[1] for args, _region in aws.calls],
                    ["send-command", "get-command-invocation", "cancel-command", "get-command-invocation"],
                )

    def test_unconfirmed_cancellation_is_reported_after_a_bounded_poll(self) -> None:
        clock = FakeClock()
        aws = ScriptedAWS(
            [{"Status": "FutureStatus", "ResponseCode": -1}],
            cancellation_polls=[{"Status": "InProgress", "ResponseCode": -1}],
        )
        runner = e2e.SSMRunner(
            aws,
            clock=clock,
            sleep=clock.sleep,
            poll_interval_seconds=0.25,
            api_timeout_seconds=0.5,
        )

        with self.assertRaisesRegex(e2e.SSMError, "terminal state unconfirmed"):
            runner.execute(
                self.command,
                send_timeout_seconds=0.5,
                wait_timeout_seconds=0.5,
                cancel_timeout_seconds=0.5,
            )

        self.assertEqual(clock.value, 0.5)

    def test_send_call_itself_is_bounded(self) -> None:
        release = threading.Event()

        class HangingAWS:
            def json(inner, args: list[str], *, region: str | None = None) -> dict[str, Any]:
                release.wait(1)
                return {"Command": {"CommandId": "late"}}

        runner = e2e.SSMRunner(HangingAWS(), api_timeout_seconds=0.02)
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(e2e.SSMTimeout, "send-command"):
                runner.send(self.command, timeout_seconds=0.02)
        finally:
            release.set()
        self.assertLess(time.monotonic() - started, 0.5)


class FlowLedgerTest(unittest.TestCase):
    def test_icmp_flow_uses_no_synthetic_ports_and_does_not_consume_one(self) -> None:
        deployment = parsed_deployment()
        ledger = e2e.FlowLedger("fixture-icmp", first_source_port=41_000, last_source_port=41_001)
        generation = ledger.begin_generation("west-envelope")

        icmp = ledger.allocate(
            "icmp",
            deployment.west.initiator,
            deployment.east.responder,
            destination_port=None,
            generation=generation,
        )
        tcp = ledger.allocate(
            "tcp",
            deployment.west.initiator,
            deployment.east.responder,
            destination_port=5201,
            generation=generation,
        )

        self.assertIsNone(icmp.source_port)
        self.assertIsNone(icmp.destination_port)
        self.assertEqual(icmp.tuple_dict(), {
            "source_ip": "10.10.1.10",
            "destination_ip": "10.20.1.11",
            "protocol": "icmp",
        })
        self.assertEqual(tcp.source_port, 41_000)
        with self.assertRaisesRegex(e2e.E2EError, "synthetic transport ports"):
            e2e.FlowRecord(
                "fixture-icmp-bad",
                3,
                "icmp",
                deployment.west.initiator,
                deployment.east.responder,
                41_001,
                5201,
                generation.label,
            )

    def test_ports_flow_ids_and_generation_labels_are_unique_and_deterministic(self) -> None:
        deployment = parsed_deployment()

        def allocate() -> tuple[e2e.FlowLedger, list[e2e.FlowRecord]]:
            ledger = e2e.FlowLedger("fixture-e2e", first_source_port=41_000, last_source_port=41_010)
            generation_one = ledger.begin_generation("west-envelope")
            generation_two = ledger.begin_generation("west-envelope")
            records = [
                ledger.allocate(
                    "tcp",
                    deployment.west.initiator,
                    deployment.east.responder,
                    destination_port=5201,
                    generation=generation_one,
                ),
                ledger.allocate(
                    "udp",
                    deployment.east.initiator,
                    deployment.west.responder,
                    destination_port=5201,
                    generation=generation_two,
                ),
            ]
            return ledger, records

        first_ledger, first = allocate()
        second_ledger, second = allocate()

        self.assertEqual([record.source_port for record in first], [41_000, 41_001])
        self.assertEqual([record.flow_id for record in first], ["fixture-e2e-tcp-0001", "fixture-e2e-udp-0002"])
        self.assertEqual(
            [record.process_generation for record in first],
            ["west-envelope-g0001", "west-envelope-g0002"],
        )
        self.assertEqual([record.as_dict() for record in first], [record.as_dict() for record in second])
        self.assertEqual(first_ledger.records, tuple(first))
        self.assertEqual(second_ledger.records, tuple(second))

    def test_source_port_exhaustion_is_explicit(self) -> None:
        deployment = parsed_deployment()
        ledger = e2e.FlowLedger("fixture-e2e", first_source_port=41_000, last_source_port=41_000)
        generation = ledger.begin_generation("west-envelope")
        ledger.allocate(
            "tcp",
            deployment.west.initiator,
            deployment.east.responder,
            destination_port=5201,
            generation=generation,
        )
        with self.assertRaisesRegex(e2e.E2EError, "exhausted"):
            ledger.allocate(
                "udp",
                deployment.west.initiator,
                deployment.east.responder,
                destination_port=5201,
                generation=generation,
            )

    def test_vpc_flow_log_parser_filters_the_exact_forward_and_reverse_tuple(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-flow-log")
        flow = ledger.allocate(
            "udp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=5201,
            generation=ledger.begin_generation("west-envelope"),
        )
        operations = FakeLiveOperations()
        identities = {
            f"{site}-{role}": operations.workload_identity(deployment, site, role)
            for site in e2e.SITES
            for role in e2e.WORKLOAD_ROLES
        }

        def record(path: str, identity: Mapping[str, Any], direction: str, reverse: bool) -> dict[str, Any]:
            source = flow.destination.private_ip if reverse else flow.source.private_ip
            destination = flow.source.private_ip if reverse else flow.destination.private_ip
            source_port = flow.destination_port if reverse else flow.source_port
            destination_port = flow.source_port if reverse else flow.destination_port
            region = deployment.appliance(identity["site"]).region
            line = (
                f"2 123456789012 {identity['interface_id']} {source} {destination} {source_port} {destination_port} "
                f"17 3 300 100 105 ACCEPT OK {deployment.appliance(identity['site']).vpc_id} "
                f"{identity['subnet_id']} {identity['instance_id']} {region} fixture-az {direction} 2 {source} {destination}"
            )
            parsed = e2e.AwsLiveOperations._parse_cloudwatch_flow_log_text(line)[0]
            parsed["site"] = identity["site"]
            parsed["fixture_path"] = path
            return parsed

        records = [
            record("source-egress", identities["west-initiator"], "egress", False),
            record("destination-ingress", identities["east-responder"], "ingress", False),
            record("responder-egress", identities["east-responder"], "egress", True),
            record("initiator-ingress", identities["west-initiator"], "ingress", True),
        ]
        summary = e2e.AwsLiveOperations._flow_log_summary(
            flow,
            records,
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["forward_matches"], 2)
        self.assertEqual(summary["reverse_matches"], 2)
        self.assertEqual(summary["packet_count"], 12)
        self.assertEqual(summary["byte_count"], 1200)
        self.assertEqual([value["path"] for value in summary["path_evidence"]], [
            "source-egress",
            "destination-ingress",
            "responder-egress",
            "initiator-ingress",
        ])

        too_early = copy.deepcopy(records)
        for value in too_early:
            value["start_epoch"] = 1
            value["end_epoch"] = 2
        self.assertIsNone(
            e2e.AwsLiveOperations._flow_log_summary(
                flow,
                too_early,
                window={"start_epoch": 100, "end_epoch": 110},
                workload_identities=identities,
            )
        )

        drop_flow = e2e.FlowRecord(
            flow.flow_id,
            flow.ordinal,
            flow.protocol,
            flow.source,
            flow.destination,
            flow.source_port,
            flow.destination_port,
            flow.process_generation,
            purpose="mtu-oversized",
            expected_result="mtu-drop",
        )
        drop_summary = e2e.AwsLiveOperations._flow_log_summary(
            drop_flow,
            [records[0]],
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )
        self.assertIsNotNone(drop_summary)
        assert drop_summary is not None
        self.assertEqual([value["path"] for value in drop_summary["path_evidence"]], ["source-egress"])
        self.assertEqual(drop_summary["reverse_matches"], 0)
        self.assertIsNone(
            e2e.AwsLiveOperations._flow_log_summary(
                drop_flow,
                [records[0], records[2]],
                window={"start_epoch": 100, "end_epoch": 110},
                workload_identities=identities,
            )
        )
        with self.assertRaisesRegex(e2e.FlowLogError, "all four"):
            e2e.AwsLiveOperations._flow_log_summary(
                flow,
                records,
                window={"start_epoch": 100, "end_epoch": 110},
                workload_identities={key: value for key, value in identities.items() if key != "east-responder"},
            )

    def test_vpc_flow_log_parser_matches_icmp_without_invented_ports(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-flow-log-icmp")
        flow = ledger.allocate(
            "icmp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=None,
            generation=ledger.begin_generation("west-envelope"),
        )
        operations = FakeLiveOperations()
        identities = {
            f"{site}-{role}": operations.workload_identity(deployment, site, role)
            for site in e2e.SITES
            for role in e2e.WORKLOAD_ROLES
        }

        def record(identity: Mapping[str, Any], direction: str, reverse: bool) -> dict[str, Any]:
            source = flow.destination.private_ip if reverse else flow.source.private_ip
            destination = flow.source.private_ip if reverse else flow.destination.private_ip
            region = deployment.appliance(identity["site"]).region
            line = (
                f"2 123456789012 {identity['interface_id']} {source} {destination} - - 1 1 84 100 105 ACCEPT OK "
                f"{deployment.appliance(identity['site']).vpc_id} {identity['subnet_id']} {identity['instance_id']} "
                f"{region} fixture-az {direction} 2 {source} {destination}"
            )
            parsed = e2e.AwsLiveOperations._parse_cloudwatch_flow_log_text(line)[0]
            parsed["site"] = identity["site"]
            return parsed

        records = [
            record(identities["west-initiator"], "egress", False),
            record(identities["east-responder"], "ingress", False),
            record(identities["east-responder"], "egress", True),
            record(identities["west-initiator"], "ingress", True),
        ]
        summary = e2e.AwsLiveOperations._flow_log_summary(
            flow,
            records,
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["flow_tuple"], flow.tuple_dict())
        self.assertNotIn("source_port", summary["flow_tuple"])
        self.assertEqual(summary["reverse_matches"], 2)
        self.assertEqual(summary["correlation_mode"], "icmp-lane-window")
        self.assertFalse(summary["flow_logs_uniquely_identify_flow"])

        oversized = e2e.FlowRecord(
            flow.flow_id,
            flow.ordinal,
            flow.protocol,
            flow.source,
            flow.destination,
            flow.source_port,
            flow.destination_port,
            flow.process_generation,
            purpose="mtu-oversized-icmp",
            expected_result="mtu-drop",
        )
        oversized_summary = e2e.AwsLiveOperations._flow_log_summary(
            oversized,
            records,
            window={"start_epoch": 100, "end_epoch": 110},
            workload_identities=identities,
        )
        self.assertIsNotNone(oversized_summary)
        assert oversized_summary is not None
        self.assertEqual(
            [value["path"] for value in oversized_summary["path_evidence"]],
            ["source-egress"],
        )
        self.assertEqual(oversized_summary["forward_matches"], 1)
        self.assertEqual(oversized_summary["reverse_matches"], 0)
        self.assertEqual(oversized_summary["aggregation_overlap_path_matches"], 3)
        self.assertEqual(oversized_summary["unexpected_path_matches"], 0)
        self.assertFalse(oversized_summary["flow_logs_uniquely_identify_flow"])
        e2e._validate_flow_log_evidence(oversized.as_dict(), oversized_summary, identities)

    def test_table_52_route_validator_allows_peer_hosts_but_rejects_lane_ambiguity(self) -> None:
        expected = ["10.20.1.0/24"]

        def validate(routes: list[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, "-c", e2e.TAILSCALE_ROUTE_VALIDATOR_SOURCE, json.dumps(expected), "tailscale0"],
                input=json.dumps(routes),
                text=True,
                capture_output=True,
                check=False,
            )

        valid = [
            {"dst": "10.20.1.0/24", "dev": "tailscale0"},
            {"dst": "10.20.1.7/32", "dev": "tailscale0"},
            {"dst": "100.64.0.2/32", "dev": "tailscale0"},
        ]
        self.assertEqual(validate(valid).returncode, 0)
        invalid = {
            "missing": valid[1:],
            "wrong device": [{"dst": "10.20.1.0/24", "dev": "eth0"}],
            "ambiguous": [valid[0], dict(valid[0])],
            "broader overlap": [valid[0], {"dst": "10.20.0.0/16", "dev": "tailscale0"}],
        }
        for name, routes in invalid.items():
            with self.subTest(name=name):
                self.assertNotEqual(validate(routes).returncode, 0)

    def test_tailscale_routes_are_scoped_to_one_expected_appliance_peer(self) -> None:
        expected_hostname = "fixture-live-east"
        expected_routes = ["10.20.1.0/24", "10.20.2.0/24"]

        def validate(status: Mapping[str, Any]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable,
                    "-c",
                    e2e.TAILSCALE_PEER_ROUTE_VALIDATOR_SOURCE,
                    expected_hostname,
                    json.dumps(expected_routes),
                ],
                input=json.dumps(status),
                text=True,
                capture_output=True,
                check=False,
            )

        valid = {
            "Peer": {
                "expected": {"HostName": expected_hostname, "PrimaryRoutes": list(reversed(expected_routes))},
                "sandbox": {"HostName": "unrelated-peer", "PrimaryRoutes": ["10.99.0.0/16"]},
            }
        }
        self.assertEqual(validate(valid).returncode, 0)

        invalid = {
            "missing": {"Peer": {"sandbox": valid["Peer"]["sandbox"]}},
            "ambiguous": {
                "Peer": {
                    "first": valid["Peer"]["expected"],
                    "second": dict(valid["Peer"]["expected"]),
                }
            },
            "wrong routes": {
                "Peer": {
                    "expected": {"HostName": expected_hostname, "PrimaryRoutes": [expected_routes[0]]},
                }
            },
        }
        for name, status in invalid.items():
            with self.subTest(name=name):
                self.assertNotEqual(validate(status).returncode, 0)

    def test_tcp_mss_capture_is_one_full_exact_outbound_syn(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-syn")
        flow = ledger.allocate(
            "tcp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=5201,
            generation=ledger.begin_generation("west-mss"),
        )

        command = e2e.AwsLiveOperations._tcp_syn_capture_command(
            flow,
            interface="tailscale0",
            capture_path="/run/envelope-e2e-capture/fixture-syn.pcap",
            duration_seconds=10,
        )

        self.assertIn("tcpdump -U -n", command)
        self.assertIn("-s 0 -c 1", command)
        self.assertIn(f"src host {flow.source.private_ip}", command)
        self.assertIn(f"dst host {flow.destination.private_ip}", command)
        self.assertIn(f"src port {flow.source_port}", command)
        self.assertIn(f"dst port {flow.destination_port}", command)
        self.assertIn("tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn", command)
        self.assertNotIn("-c 8", command)
        subprocess.run(["bash", "-n", "-c", command], check=True, capture_output=True, text=True)

    def test_oversized_icmp_capture_is_one_exact_sized_request(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-icmp-capture")
        flow = ledger.allocate(
            "icmp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=None,
            generation=ledger.begin_generation("west-mtu"),
            purpose="mtu-oversized-icmp",
            expected_result="mtu-drop",
        )

        command = e2e.AwsLiveOperations._icmp_drop_capture_command(
            flow,
            interface="ens5",
            capture_path="/run/envelope-e2e-capture/fixture-icmp.pcap",
            timeout_seconds=20,
        )

        self.assertIn("tcpdump -U -n", command)
        self.assertIn("-s 0 -c 1", command)
        self.assertIn("udp and dst port 6081", command)
        subprocess.run(["bash", "-n", "-c", command], check=True, capture_output=True, text=True)

        client = e2e.AwsLiveOperations._icmp_client_command(
            flow,
            payload_bytes=1253,
            timeout_seconds=20,
            expect_timeout=True,
        )
        self.assertIn("e2e-live-observer icmp-client", client)
        self.assertIn("--payload-bytes 1253", client)
        self.assertIn("--expect-timeout", client)
        self.assertNotIn(" ping ", client)
        subprocess.run(["bash", "-n", "-c", client], check=True, capture_output=True, text=True)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum((data[index] << 8) | data[index + 1] for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_bytes(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    source_bytes = socket.inet_aton(source)
    destination_bytes = socket.inet_aton(destination)
    header = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            7,
            0,
            64,
            protocol,
            0,
            source_bytes,
            destination_bytes,
        )
    )
    struct.pack_into("!H", header, 10, internet_checksum(bytes(header)))
    return bytes(header) + payload


def udp_bytes(source: str, destination: str, source_port: int, destination_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = bytearray(struct.pack("!HHHH", source_port, destination_port, length, 0))
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + b"\0\x11" + struct.pack("!H", length)
    checksum = internet_checksum(pseudo + bytes(header) + payload)
    struct.pack_into("!H", header, 6, checksum or 0xFFFF)
    return bytes(header) + payload


def ethernet_ipv4(packet: bytes) -> bytes:
    return bytes.fromhex("0200000000020200000000010800") + packet


def icmp_bytes(kind: int, identifier: int, sequence: int, payload: bytes = b"icmp-fixture") -> bytes:
    value = bytearray(struct.pack("!BBHHH", kind, 0, 0, identifier, sequence) + payload)
    struct.pack_into("!H", value, 2, internet_checksum(bytes(value)))
    return bytes(value)


def pcap_bytes(frames: list[bytes]) -> bytes:
    value = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        value.extend(struct.pack("<IIII", index + 1, 0, len(frame), len(frame)))
        value.extend(frame)
    return bytes(value)


def geneve_options(cookie: bytes = b"\xde\xad\xbe\xef") -> bytes:
    vpce = struct.pack("!HBB", 0x0108, 1, 2) + bytes.fromhex("1122334455667788")
    flow_cookie = struct.pack("!HBB", 0x0108, 3, 1) + cookie
    return vpce + flow_cookie


def geneve_packet(inner: bytes, *, options: bytes | None = None, vni: int = 0) -> bytes:
    selected = geneve_options() if options is None else options
    return bytes([len(selected) // 4, 0]) + struct.pack("!H", 0x0800) + vni.to_bytes(3, "big") + b"\0" + selected + inner


def directional_capture_fixture(
    flow: e2e.FlowRecord,
    *,
    return_source_port: int = 40_000,
    return_destination_port: int = 6081,
    return_cookie: bytes = b"\xde\xad\xbe\xef",
) -> dict[str, Any]:
    assert flow.source_port is not None and flow.destination_port is not None
    forward_inner_udp = udp_bytes(
        flow.source.private_ip,
        flow.destination.private_ip,
        flow.source_port,
        flow.destination_port,
        b"request",
    )
    reverse_inner_udp = udp_bytes(
        flow.destination.private_ip,
        flow.source.private_ip,
        flow.destination_port,
        flow.source_port,
        b"response",
    )
    forward_inner = ipv4_bytes(flow.source.private_ip, flow.destination.private_ip, 17, forward_inner_udp)
    reverse_inner = ipv4_bytes(flow.destination.private_ip, flow.source.private_ip, 17, reverse_inner_udp)
    forward_outer_payload = geneve_packet(forward_inner)
    return_outer_payload = geneve_packet(reverse_inner, options=geneve_options(return_cookie))
    forward_outer = ipv4_bytes(
        "192.0.2.10",
        "198.51.100.20",
        17,
        udp_bytes("192.0.2.10", "198.51.100.20", 40_000, 6081, forward_outer_payload),
    )
    return_outer = ipv4_bytes(
        "198.51.100.20",
        "192.0.2.10",
        17,
        udp_bytes(
            "198.51.100.20",
            "192.0.2.10",
            return_source_port,
            return_destination_port,
            return_outer_payload,
        ),
    )
    inner_capture = e2e.parse_packet_capture(
        pcap_bytes([ethernet_ipv4(forward_inner), ethernet_ipv4(reverse_inner)])
    )
    empty_capture = e2e.parse_packet_capture(pcap_bytes([]))
    source_underlay = e2e.parse_packet_capture(
        pcap_bytes([ethernet_ipv4(forward_outer), ethernet_ipv4(return_outer)])
    )
    source_site = flow.source.site
    destination_site = flow.destination.site
    return {
        source_site: {
            "underlay": source_underlay,
            "envelope0": copy.deepcopy(inner_capture),
            "tailscale0": copy.deepcopy(inner_capture),
        },
        destination_site: {
            "underlay": copy.deepcopy(empty_capture),
            "envelope0": copy.deepcopy(empty_capture),
            "tailscale0": copy.deepcopy(inner_capture),
        },
    }


def icmp_capture_fixture(flow: e2e.FlowRecord, *, return_identifier: int = 1234) -> dict[str, Any]:
    forward_inner = ipv4_bytes(
        flow.source.private_ip,
        flow.destination.private_ip,
        1,
        icmp_bytes(8, 1234, 1),
    )
    reverse_inner = ipv4_bytes(
        flow.destination.private_ip,
        flow.source.private_ip,
        1,
        icmp_bytes(0, return_identifier, 1),
    )
    forward_geneve = geneve_packet(forward_inner)
    reverse_geneve = geneve_packet(reverse_inner)
    forward_outer = ipv4_bytes(
        "192.0.2.10",
        "198.51.100.20",
        17,
        udp_bytes("192.0.2.10", "198.51.100.20", 40_001, 6081, forward_geneve),
    )
    reverse_outer = ipv4_bytes(
        "198.51.100.20",
        "192.0.2.10",
        17,
        udp_bytes("198.51.100.20", "192.0.2.10", 40_001, 6081, reverse_geneve),
    )
    inner = e2e.parse_packet_capture(pcap_bytes([ethernet_ipv4(forward_inner), ethernet_ipv4(reverse_inner)]))
    empty = e2e.parse_packet_capture(pcap_bytes([]))
    return {
        flow.source.site: {
            "underlay": e2e.parse_packet_capture(
                pcap_bytes([ethernet_ipv4(forward_outer), ethernet_ipv4(reverse_outer)])
            ),
            "envelope0": copy.deepcopy(inner),
            "tailscale0": copy.deepcopy(inner),
        },
        flow.destination.site: {
            "underlay": copy.deepcopy(empty),
            "envelope0": copy.deepcopy(empty),
            "tailscale0": copy.deepcopy(inner),
        },
    }


class PacketCaptureAssertionTest(unittest.TestCase):
    def setUp(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-wire")
        self.flow = ledger.allocate(
            "udp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=5201,
            generation=ledger.begin_generation("west-cold"),
            purpose="cold",
        )

    def test_binary_packet_fixture_proves_the_aws_return_contract(self) -> None:
        captures = directional_capture_fixture(self.flow)

        summary = e2e.assert_directional_wire_captures("west", [self.flow], captures, raw_deleted=True)

        self.assertTrue(summary["capture_bounded"])
        self.assertTrue(summary["raw_pcaps_deleted"])
        self.assertEqual(len(summary["interfaces"]), 6)
        self.assertEqual(summary["flows"][0]["return_udp_source_port"], 40_000)
        self.assertEqual(summary["flows"][0]["return_udp_destination_port"], 6081)
        self.assertEqual(e2e.scan_evidence(summary), [])

    def test_reversed_udp_ports_and_changed_ordered_options_fail(self) -> None:
        reversed_ports = directional_capture_fixture(
            self.flow,
            return_source_port=6081,
            return_destination_port=40_000,
        )
        with self.assertRaisesRegex(e2e.WireAssertionError, "orientation"):
            e2e.assert_directional_wire_captures("west", [self.flow], reversed_ports, raw_deleted=True)

        changed_options = directional_capture_fixture(self.flow, return_cookie=b"\x00\x00\x00\x01")
        with self.assertRaisesRegex(e2e.WireAssertionError, "options|cookie"):
            e2e.assert_directional_wire_captures("west", [self.flow], changed_options, raw_deleted=True)

    def test_icmp_binary_fixture_has_no_ports_and_requires_one_request_identity(self) -> None:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        ledger = e2e.FlowLedger("fixture-wire-icmp")
        flow = ledger.allocate(
            "icmp",
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            destination_port=None,
            generation=ledger.begin_generation("west-cold"),
            purpose="cold",
        )

        summary = e2e.assert_directional_wire_captures(
            "west", [flow], icmp_capture_fixture(flow), raw_deleted=True
        )
        self.assertTrue(summary["flows"][0]["inner_flow_identity_verified"])
        self.assertIsNone(flow.source_port)

        with self.assertRaisesRegex(e2e.WireAssertionError, "ICMP request/reply identity"):
            e2e.assert_directional_wire_captures(
                "west",
                [flow],
                icmp_capture_fixture(flow, return_identifier=999),
                raw_deleted=True,
            )

        source_capture = icmp_capture_fixture(flow)[flow.source.site]["envelope0"]
        source_summary = e2e.summarize_source_workload_capture(
            "west", [flow], source_capture, interface="ens5", raw_deleted=True
        )
        self.assertEqual(source_summary["request_packets"], 1)
        self.assertEqual(source_summary["reply_packets"], 1)
        self.assertTrue(source_summary["raw_pcap_deleted"])

        with self.assertRaisesRegex(e2e.WireAssertionError, "deletion"):
            e2e.summarize_source_workload_capture(
                "west", [flow], source_capture, interface="ens5", raw_deleted=False
            )

    def test_parser_rejects_bad_ipv4_udp_lengths_checksums_and_vni(self) -> None:
        captures = directional_capture_fixture(self.flow)
        # Reconstruct one valid outer frame from the fixture inputs for byte-level mutations.
        assert self.flow.source_port is not None and self.flow.destination_port is not None
        inner_udp = udp_bytes(
            self.flow.source.private_ip,
            self.flow.destination.private_ip,
            self.flow.source_port,
            self.flow.destination_port,
            b"request",
        )
        inner = ipv4_bytes(self.flow.source.private_ip, self.flow.destination.private_ip, 17, inner_udp)
        outer_payload = geneve_packet(inner)
        outer = ipv4_bytes(
            "192.0.2.10",
            "198.51.100.20",
            17,
            udp_bytes("192.0.2.10", "198.51.100.20", 40_000, 6081, outer_payload),
        )
        frame = bytearray(ethernet_ipv4(outer))

        bad_ip = bytearray(frame)
        bad_ip[24] ^= 0x01
        with self.assertRaisesRegex(e2e.WireAssertionError, "IPv4 checksum"):
            e2e.parse_packet_capture(pcap_bytes([bytes(bad_ip)]))

        bad_udp = bytearray(frame)
        bad_udp[40] ^= 0x01
        with self.assertRaisesRegex(e2e.WireAssertionError, "UDP checksum|UDP length"):
            e2e.parse_packet_capture(pcap_bytes([bytes(bad_udp)]))

        nonzero_vni_payload = geneve_packet(inner, vni=1)
        nonzero_vni = ipv4_bytes(
            "192.0.2.10",
            "198.51.100.20",
            17,
            udp_bytes("192.0.2.10", "198.51.100.20", 40_000, 6081, nonzero_vni_payload),
        )
        with self.assertRaisesRegex(e2e.WireAssertionError, "VNI"):
            e2e.parse_packet_capture(pcap_bytes([ethernet_ipv4(nonzero_vni)]))

        with self.assertRaisesRegex(e2e.WireAssertionError, "deletion"):
            e2e.assert_directional_wire_captures("west", [self.flow], captures, raw_deleted=False)


class CaptureControllerTest(unittest.TestCase):
    class FakeSSM:
        def __init__(self, *, fail_inspection: bool = False, malformed_summary: bool = False) -> None:
            self.fail_inspection = fail_inspection
            self.malformed_summary = malformed_summary
            self.sent: list[e2e.SSMCommand] = []
            self.executed: list[e2e.SSMCommand] = []

        def send(self, command: e2e.SSMCommand, *, timeout_seconds: float = 10.0) -> str:
            self.sent.append(command)
            return f"capture-{len(self.sent)}"

        def wait(self, target: e2e.RemoteTarget, command_id: str, *, timeout_seconds: float) -> e2e.SSMResult:
            return e2e.SSMResult(target, command_id, "Success", 0)

        def cancel(self, target: e2e.RemoteTarget, command_id: str, *, timeout_seconds: float = 5.0) -> bool:
            return True

        def execute(
            self,
            command: e2e.SSMCommand,
            *,
            send_timeout_seconds: float = 10.0,
            wait_timeout_seconds: float | None = None,
            cancel_timeout_seconds: float = 5.0,
        ) -> e2e.SSMResult:
            self.executed.append(command)
            if command.comment == "Envelope E2E capture readiness":
                output = '{"capture_ready":true,"success":true}\n'
            elif command.comment == "Envelope E2E inspect sanitized capture":
                if self.fail_inspection:
                    return e2e.SSMResult(command.target, "inspect", "Failed", 2, stderr="fixture parse failure")
                payload = (
                    b"{not-json"
                    if self.malformed_summary
                    else json.dumps(
                        {
                            "file_sha256": "a" * 64,
                            "frame_count": 0,
                            "frames": [],
                            "link_type": 1,
                            "success": True,
                        }
                    ).encode()
                )
                output = base64.b64encode(gzip.compress(payload, mtime=0)).decode()
            elif command.comment == "Envelope E2E delete raw captures":
                output = '{"deleted":true,"success":true}\n'
            elif command.comment == "Envelope E2E explicit appliance readiness":
                output = '{"pid":123,"success":true}\n'
            elif command.comment == "Envelope E2E appliance readiness":
                output = '{"pid":123,"ready":true,"success":true}\n'
            elif command.comment == "Envelope E2E explicit workload readiness":
                output = '{"success":true}\n'
            else:
                output = ""
            return e2e.SSMResult(command.target, f"execute-{len(self.executed)}", "Success", 0, stdout=output)

    def fixture(self, fake: "CaptureControllerTest.FakeSSM") -> tuple[e2e.AwsLiveOperations, e2e.ProtectedDeployment, list[e2e.FlowRecord]]:
        deployment = e2e.parse_protected_deployment_output(protected_output())
        operations = e2e.AwsLiveOperations(
            SimpleNamespace(run_id="fixture-live", sites={}),
            SimpleNamespace(),
            pathlib.Path("/tmp/not-used"),
            ssm=fake,
            sleep=lambda _seconds: None,
            monotonic=lambda: 0.0,
        )
        ledger = e2e.FlowLedger("fixture-capture")
        generation = ledger.begin_generation("west-cold")
        flows = [
            ledger.allocate(
                protocol,
                deployment.workloads.west.initiator,
                deployment.workloads.east.responder,
                destination_port=None if protocol == "icmp" else 5201,
                generation=generation,
                purpose="cold",
            )
            for protocol in e2e.PROTOCOLS
        ]
        return operations, deployment, flows

    def test_controller_bounds_all_six_captures_and_deletes_raw_files(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)

        handle = operations._start_directional_captures(deployment, "west", flows, timeout_seconds=60)
        result = operations._finish_directional_captures(deployment, handle, inspect=True)

        self.assertTrue(result["raw_deleted"])
        self.assertIsNotNone(result["source_capture"])
        self.assertEqual(result["source_interface"], "ens5")
        self.assertEqual(len(fake.sent), 3)
        for site_paths in handle.paths.values():
            for path in site_paths.values():
                self.assertRegex(
                    path,
                    r"^/run/envelope-e2e-capture/[a-z0-9-]{1,80}-(west|east)-(underlay|envelope0|tailscale0)\.pcap$",
                )
                self.assertNotIn("..", pathlib.PurePosixPath(path).parts)
        self.assertRegex(
            str(handle.source_path),
            r"^/run/envelope-e2e-capture/[a-z0-9-]{1,80}-west-source-icmp\.pcap$",
        )
        for command in fake.sent:
            rendered = command.commands[0]
            expected_count = 1 if "source workload capture" in command.comment else 3
            self.assertEqual(rendered.count("tcpdump"), expected_count)
            self.assertEqual(rendered.count("-c 8"), 1 if expected_count == 1 else 0)
            self.assertEqual(rendered.count("-c 48"), 0 if expected_count == 1 else 3)
            self.assertEqual(
                rendered.count("timeout --signal=TERM --kill-after=2 60s tcpdump"), expected_count
            )
            self.assertNotIn("watchdog_pid", rendered)
            self.assertNotIn('kill -INT "$capture_pid"', rendered)
            self.assertLessEqual(command.timeout_seconds, 315)
        for command in [*fake.sent, *fake.executed]:
            for rendered in command.commands:
                subprocess.run(["bash", "-n", "-c", rendered], check=True, capture_output=True, text=True)
        self.assertEqual(
            sum(command.comment == "Envelope E2E delete raw captures" for command in fake.executed),
            3,
        )

    def test_cold_failure_reports_source_workload_packet_counts(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, flows = self.fixture(fake)

        with (
            mock.patch.object(operations, "_restart_envelope", return_value={"west": 101, "east": 202}),
            mock.patch.object(operations, "_metric_snapshots", return_value={}),
            mock.patch.object(operations, "_run_icmp_probe", side_effect=e2e.ProbeError("fixture timeout")),
        ):
            with self.assertRaisesRegex(
                e2e.WireAssertionError,
                r"source workload capture observed 0 ICMP request packet\(s\) and 0 reply packet\(s\)",
            ):
                operations.run_cold_direction(deployment, "west", flows, timeout_seconds=60)

        self.assertEqual(len(operations.capture_diagnostic_events), 1)
        self.assertEqual(operations.capture_diagnostic_events[0]["interface"], "ens5")
        self.assertEqual(operations.capture_diagnostic_events[0]["request_packets"], 0)

    def test_wire_inspector_installer_creates_parent_directory_before_writing(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)

        operations._install_wire_inspector(deployment.appliance("west"))

        self.assertEqual(len(fake.executed), 1)
        command = fake.executed[0]
        self.assertEqual(command.comment, "Envelope E2E install bounded wire inspector")
        rendered = command.commands[0]
        directory_install = "install -d -o root -g root -m 0755 /opt/envelope"
        temporary_write = "> /opt/envelope/e2e-wire-inspector.tmp"
        self.assertIn(directory_install, rendered)
        self.assertIn(temporary_write, rendered)
        self.assertLess(rendered.index(directory_install), rendered.index(temporary_write))
        subprocess.run(["bash", "-n", "-c", rendered], check=True, capture_output=True, text=True)

    def test_appliance_readiness_command_has_balanced_shell_syntax(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)

        result = operations._appliance_readiness_details(deployment, "west", timeout_seconds=60)

        self.assertEqual(result["pid"], 123)
        command = fake.executed[-1]
        self.assertEqual(command.comment, "Envelope E2E explicit appliance readiness")
        self.assertIn("for unit in tailscaled.service envelope-host-network.service envelope.service", command.commands[0])
        self.assertIn("for tool in tcpdump timeout python3 sha256sum gzip base64", command.commands[0])
        subprocess.run(["bash", "-n", "-c", command.commands[0]], check=True, capture_output=True, text=True)

    def test_all_readiness_commands_require_each_managed_service(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)

        operations._wait_appliance_ready(deployment.appliance("west"), timeout_seconds=60)
        operations._workload_readiness_details(
            deployment.workloads.west.initiator,
            deployment.workloads.east.responder,
            interface="ens5",
            timeout_seconds=60,
        )

        appliance, workload = fake.executed[-2:]
        self.assertIn("for unit in tailscaled.service envelope-host-network.service envelope.service", appliance.commands[0])
        self.assertIn(
            "for unit in amazon-ssm-agent.service envelope-e2e-agent-tcp.service envelope-e2e-agent-udp.service",
            workload.commands[0],
        )
        self.assertIn("failed_check=source-route", workload.commands[0])
        self.assertIn(".[0].from // .[0].prefsrc // .[0].src", workload.commands[0])
        self.assertIn(".[0].dev == $interface", workload.commands[0])
        self.assertIn("tcpdump sha256sum gzip base64", workload.commands[0])
        for command in (appliance, workload):
            subprocess.run(["bash", "-n", "-c", command.commands[0]], check=True, capture_output=True, text=True)

    def test_workload_source_route_filter_accepts_al2023_from_field(self) -> None:
        route = json.dumps(
            [{"dst": "198.51.100.20", "from": "192.0.2.10", "gateway": "192.0.2.1", "dev": "ens5"}]
        )

        result = subprocess.run(
            [
                "jq",
                "-e",
                "--arg",
                "source",
                "192.0.2.10",
                "--arg",
                "interface",
                "ens5",
                e2e.WORKLOAD_SOURCE_ROUTE_JQ,
            ],
            input=route,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_gwlbe_stabilization_waits_from_the_newest_endpoint_creation(self) -> None:
        clock = {"monotonic": 100.0, "wall": 2_000_000_000.0}
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock["monotonic"] += seconds
            clock["wall"] += seconds

        operations = e2e.AwsLiveOperations(
            SimpleNamespace(run_id="fixture-live", sites={}),
            SimpleNamespace(),
            pathlib.Path("/tmp/not-used"),
            ssm=self.FakeSSM(),
            sleep=sleep,
            monotonic=lambda: clock["monotonic"],
            wall_time=lambda: clock["wall"],
        )
        created = dt.datetime.fromtimestamp(clock["wall"] - 240, tz=dt.timezone.utc).isoformat()

        age = operations._wait_for_gwlbe_stability(
            "west",
            [{"CreationTimestamp": created}],
            deadline=clock["monotonic"] + 120,
        )

        self.assertEqual(sleeps, [60.0])
        self.assertEqual(age, e2e.GWLBE_STABILIZATION_SECONDS)

        with self.assertRaisesRegex(e2e.ReadinessError, "readiness deadline"):
            operations._wait_for_gwlbe_stability(
                "west",
                [{"CreationTimestamp": dt.datetime.fromtimestamp(clock["wall"], tz=dt.timezone.utc).isoformat()}],
                deadline=clock["monotonic"] + 30,
            )

    def test_emergency_return_rule_accepts_concurrent_reconciliation(self) -> None:
        fake = self.FakeSSM()
        operations, deployment, _flows = self.fixture(fake)
        restored = {"priority": 100, "protocol": "186", "table": "100"}

        with (
            mock.patch.object(operations, "_return_rule_snapshot", side_effect=[[], [restored]]),
            mock.patch.object(operations, "_execute", side_effect=e2e.SSMError("rule already exists")),
        ):
            operations._ensure_return_rule(deployment, "west")

    def test_inspector_failure_still_deletes_every_raw_capture(self) -> None:
        fake = self.FakeSSM(fail_inspection=True)
        operations, deployment, flows = self.fixture(fake)
        handle = operations._start_directional_captures(deployment, "west", flows, timeout_seconds=60)

        with self.assertRaises(e2e.WireAssertionError):
            operations._finish_directional_captures(deployment, handle, inspect=True)

        self.assertTrue(handle.stopped)
        self.assertTrue(handle.raw_deleted)
        self.assertEqual(
            sum(command.comment == "Envelope E2E delete raw captures" for command in fake.executed),
            3,
        )

    def test_summary_parse_failure_still_deletes_every_raw_capture(self) -> None:
        fake = self.FakeSSM(malformed_summary=True)
        operations, deployment, flows = self.fixture(fake)
        handle = operations._start_directional_captures(deployment, "west", flows, timeout_seconds=60)

        with self.assertRaisesRegex(e2e.WireAssertionError, "capture field summary is invalid"):
            operations._finish_directional_captures(deployment, handle, inspect=True)

        self.assertTrue(handle.stopped)
        self.assertTrue(handle.raw_deleted)
        self.assertEqual(
            sum(command.comment == "Envelope E2E delete raw captures" for command in fake.executed),
            3,
        )

    def test_flow_id_cannot_escape_capture_directory(self) -> None:
        _operations, _deployment, flows = self.fixture(self.FakeSSM())
        flow = flows[0]

        with self.assertRaisesRegex(e2e.E2EError, "path-safe"):
            e2e.FlowRecord(
                flow_id="../../tmp/capture",
                ordinal=flow.ordinal,
                protocol=flow.protocol,
                source=flow.source,
                destination=flow.destination,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                process_generation=flow.process_generation,
                purpose=flow.purpose,
                expected_result=flow.expected_result,
            )


class PrometheusMetricTest(unittest.TestCase):
    def test_parser_and_delta_assertions(self) -> None:
        before = e2e.parse_prometheus_metrics(
            """
            # HELP envelope_packets_total Processed packets.
            envelope_packets_total{protocol="tcp",path="west\\\\east"} 2
            envelope_packets_total{protocol="udp",path="west\\\\east"} 4 1234
            """,
            generation="west-envelope-g0001",
        )
        after = e2e.parse_prometheus_metrics(
            """
            envelope_packets_total{path="west\\\\east",protocol="tcp"} 5
            envelope_packets_total{protocol="udp",path="west\\\\east"} 8
            """,
            generation="west-envelope-g0001",
        )

        self.assertEqual(
            e2e.assert_metric_delta(
                before,
                after,
                "envelope_packets_total",
                labels={"protocol": "tcp"},
                expected=3,
            ),
            3,
        )
        self.assertEqual(e2e.assert_metric_delta(before, after, "envelope_packets_total", minimum=7), 7)

    def test_process_generation_boundary_and_counter_reset_are_rejected(self) -> None:
        before = e2e.parse_prometheus("counter_total 10\n", generation="envelope-g0001")
        restarted = e2e.parse_prometheus("counter_total 1\n", generation="envelope-g0002")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "generation boundary"):
            e2e.metric_delta(before, restarted, "counter_total")

        reset = e2e.parse_prometheus("counter_total 1\n", generation="envelope-g0001")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "decreased"):
            e2e.metric_delta(before, reset, "counter_total")

    def test_duplicate_series_and_malformed_lines_are_rejected(self) -> None:
        with self.assertRaisesRegex(e2e.MetricError, "duplicate series"):
            e2e.parse_prometheus("counter 1\ncounter 2\n", generation="envelope-g0001")
        with self.assertRaisesRegex(e2e.MetricError, "label"):
            e2e.parse_prometheus('counter{bad="unterminated} 1\n', generation="envelope-g0001")

    @staticmethod
    def flow_metrics(
        packet_value: int,
        byte_value: int,
        *,
        drops: int = 0,
        mtu_drops: int = 0,
        mtu_direction: str = "ingress",
        mtu_family: str = "ipv4",
        overrides: dict[str, int] | None = None,
    ) -> str:
        values: dict[str, int] = {name: packet_value for name in e2e._PACKET_METRICS}
        values.update({name: byte_value for name in e2e._BYTE_METRICS})
        for name in e2e._UNEXPECTED_FLOW_METRICS:
            if name not in {
                "geneve_options_validation_errors",
                "gwlb_profile_rejections_total",
                "gwlb_receive_drops_total",
                "gwlb_unsupported_inner_total",
                "gwlb_mtu_drops_total",
            }:
                values.setdefault(name, 0)
        values["drops"] = drops
        values.update(overrides or {})
        lines = [f"{name} {value}" for name, value in sorted(values.items())]
        lines.extend(
            [
                'geneve_options_validation_errors{reason="structural"} 0',
                'gwlb_profile_rejections_total{reason="decode"} 0',
                'gwlb_receive_drops_total{reason="packet_info"} 0',
                'gwlb_unsupported_inner_total{reason="malformed"} 0',
                *[
                    f'gwlb_mtu_drops_total{{direction="{direction}",family="{family}"}} '
                    f'{mtu_drops if (direction, family) == (mtu_direction, mtu_family) else 0}'
                    for direction in ("ingress", "egress")
                    for family in ("ipv4", "ipv6")
                ],
            ]
        )
        return "\n".join(lines) + "\n"

    def test_complete_flow_metric_contract_and_unexpected_growth(self) -> None:
        before = {
            site: e2e.parse_prometheus(self.flow_metrics(0, 0), generation=f"{site}-pid1")
            for site in e2e.SITES
        }
        after = {
            "west": e2e.parse_prometheus(self.flow_metrics(2, 256), generation="west-pid1"),
            "east": e2e.parse_prometheus(self.flow_metrics(0, 0), generation="east-pid1"),
        }

        summary = e2e.assert_flow_metric_contract(before, after, initiator_site="west", receiver_sessions=1)

        self.assertFalse(summary["unexpected_growth"])
        self.assertEqual(summary["session"]["receiver_sessions"], 1)
        self.assertEqual(summary["malformed_deltas"], {"west": 0, "east": 0})

        bad = dict(after)
        bad["west"] = e2e.parse_prometheus(self.flow_metrics(2, 256, drops=1), generation="west-pid1")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "drops"):
            e2e.assert_flow_metric_contract(before, bad, initiator_site="west", receiver_sessions=1)

    def test_context_expiration_may_grow_but_eviction_remains_an_error(self) -> None:
        before = {
            site: e2e.parse_prometheus(
                self.flow_metrics(0, 0, overrides={"gwlb_context_expirations_total": 4}),
                generation=f"{site}-pid1",
            )
            for site in e2e.SITES
        }
        after = {
            "west": e2e.parse_prometheus(
                self.flow_metrics(2, 256, overrides={"gwlb_context_expirations_total": 5}),
                generation="west-pid1",
            ),
            "east": e2e.parse_prometheus(
                self.flow_metrics(0, 0, overrides={"gwlb_context_expirations_total": 4}),
                generation="east-pid1",
            ),
        }

        summary = e2e.assert_flow_metric_contract(before, after, initiator_site="west", receiver_sessions=1)

        self.assertFalse(summary["unexpected_growth"])
        self.assertNotIn("gwlb_context_expirations_total", summary["unexpected_deltas"]["west"])
        evicted = dict(after)
        evicted["west"] = e2e.parse_prometheus(
            self.flow_metrics(
                2,
                256,
                overrides={"gwlb_context_expirations_total": 5, "gwlb_context_evictions_total": 1},
            ),
            generation="west-pid1",
        )
        with self.assertRaisesRegex(e2e.MetricAssertionError, "evictions"):
            e2e.assert_flow_metric_contract(before, evicted, initiator_site="west", receiver_sessions=1)

    def test_approved_load_still_rejects_generic_drop_growth(self) -> None:
        before = {
            site: e2e.parse_prometheus(self.flow_metrics(0, 0), generation=f"{site}-pid1")
            for site in e2e.SITES
        }
        after = {
            site: e2e.parse_prometheus(self.flow_metrics(2, 256), generation=f"{site}-pid1")
            for site in e2e.SITES
        }

        summary = e2e.assert_bidirectional_metric_contract(before, after)

        self.assertFalse(summary["unexpected_growth"])
        bad = dict(after)
        bad["west"] = e2e.parse_prometheus(self.flow_metrics(2, 256, drops=1), generation="west-pid1")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "drops"):
            e2e.assert_bidirectional_metric_contract(before, bad)

    def test_exact_generic_and_mtu_specific_pair_is_required_for_an_oversized_flow(self) -> None:
        before = {
            site: e2e.parse_prometheus(self.flow_metrics(0, 0), generation=f"{site}-pid1")
            for site in e2e.SITES
        }
        after = {
            "west": e2e.parse_prometheus(
                self.flow_metrics(
                    0,
                    0,
                    drops=1,
                    mtu_drops=1,
                    overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128},
                ),
                generation="west-pid1",
            ),
            "east": e2e.parse_prometheus(self.flow_metrics(0, 0), generation="east-pid1"),
        }

        summary = e2e.assert_mtu_drop_metric_contract(before, after, initiator_site="west")

        self.assertEqual(
            summary["intentional_mtu_drop"],
            {
                "site": "west",
                "generic_drops_delta": 1,
                "mtu_specific": {
                    "metric": "gwlb_mtu_drops_total",
                    "delta": 1,
                    "direction": "ingress",
                    "family": "ipv4",
                },
            },
        )
        self.assertFalse(summary["unexpected_growth"])

        invalid_cases = {
            "missing generic drop": self.flow_metrics(
                0, 0, mtu_drops=1, overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128}
            ),
            "extra generic drop": self.flow_metrics(
                0, 0, drops=2, mtu_drops=1, overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128}
            ),
            "wrong MTU label": self.flow_metrics(
                0,
                0,
                drops=1,
                mtu_drops=1,
                mtu_direction="egress",
                overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128},
            ),
            "other error": self.flow_metrics(
                0,
                0,
                drops=1,
                mtu_drops=1,
                overrides={"geneve_rx_packets": 1, "geneve_rx_bytes": 128, "gwlb_send_failures_total": 1},
            ),
        }
        for name, west_metrics in invalid_cases.items():
            candidate = {
                "west": e2e.parse_prometheus(west_metrics, generation="west-pid1"),
                "east": after["east"],
            }
            with self.subTest(name=name), self.assertRaises(e2e.MetricAssertionError):
                e2e.assert_mtu_drop_metric_contract(before, candidate, initiator_site="west")

        peer_growth = dict(after)
        peer_growth["east"] = e2e.parse_prometheus(self.flow_metrics(0, 0, drops=1), generation="east-pid1")
        with self.assertRaisesRegex(e2e.MetricAssertionError, "drops"):
            e2e.assert_mtu_drop_metric_contract(before, peer_growth, initiator_site="west")


def marker(sequence: int, sent: int, received: int, *, connection: str = "flow:c0001") -> e2e.StreamMarker:
    return e2e.StreamMarker(
        flow_id="flow-0001",
        connection_id=connection,
        sequence=sequence,
        sent_monotonic_ns=sent,
        received_monotonic_ns=received,
    )


class StreamAnalyzerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mutation = e2e.MutationInterval(100, 200, "restart-west")

    def test_one_socket_with_bounded_mutation_loss_succeeds(self) -> None:
        markers = [
            marker(0, 40, 45),
            marker(1, 80, 90),
            marker(4, 205, 210),
            marker(5, 240, 245),
        ]

        analysis = e2e.analyze_stream_markers(
            markers,
            self.mutation,
            maximum_loss_ns=150,
            expected_first_sequence=0,
            expected_last_sequence=5,
        )

        self.assertEqual(analysis.missing_sequences, (2, 3))
        self.assertEqual(len(analysis.loss_windows), 1)
        self.assertEqual(analysis.loss_windows[0].duration_ns, 120)
        self.assertEqual(analysis.connection_id, "flow:c0001")

    def test_loss_outside_interval_or_over_bound_fails(self) -> None:
        outside = [
            marker(0, 40, 45),
            marker(1, 205, 210),
            marker(4, 240, 245),
            marker(5, 260, 265),
        ]
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "outside"):
            e2e.analyze_stream_markers(outside, self.mutation, maximum_loss_ns=100)

        over_bound = [
            marker(0, 40, 45),
            marker(1, 80, 90),
            marker(4, 205, 210),
            marker(5, 240, 245),
        ]
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "exceeds"):
            e2e.analyze_stream_markers(over_bound, self.mutation, maximum_loss_ns=100)

    def test_socket_change_is_rejected(self) -> None:
        markers = [marker(0, 40, 45), marker(1, 210, 215, connection="flow:c0002")]
        with self.assertRaisesRegex(e2e.StreamAnalysisError, "one long-lived socket"):
            e2e.analyze_stream_markers(markers, self.mutation, maximum_loss_ns=200)


def evidence_fixture() -> dict[str, Any]:
    deployment = parsed_deployment()
    ledger = e2e.FlowLedger("fixture-e2e", first_source_port=42_000, last_source_port=42_010)
    generation = ledger.begin_generation("west-envelope")
    ledger.allocate(
        "tcp",
        deployment.west.initiator,
        deployment.east.responder,
        destination_port=5201,
        generation=generation,
    )
    analysis = e2e.analyze_stream_markers(
        [marker(0, 40, 45), marker(1, 210, 215)],
        e2e.MutationInterval(100, 200, "restart-west"),
        maximum_loss_ns=200,
        expected_first_sequence=0,
        expected_last_sequence=1,
    )
    return e2e.evidence_document(
        "fixture-e2e",
        deployment,
        ledger.records,
        [{"name": "cross-region-tcp", "passed": True, "summary": "probe acknowledged"}],
        generated_at="2026-08-20T12:00:00Z",
        metrics=[{"delta": 2, "generation": generation.label, "name": "envelope_packets_total"}],
        streams=[analysis],
        metadata={"suite": "offline-core"},
    )


class EvidenceTest(unittest.TestCase):
    def test_atomic_writer_validator_and_cli(self) -> None:
        document = evidence_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "nested" / "evidence.json"
            returned = e2e.write_evidence(path, document)

            self.assertEqual(returned, path)
            self.assertEqual(e2e.load_evidence(path), document)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "aws_two_region_e2e.py"), "validate-evidence", str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)["valid"])

    def test_credentials_and_raw_material_are_rejected_without_overwriting(self) -> None:
        document = evidence_fixture()
        secret = "ASIA" + "ABCDEFGHIJKLMNOP"
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "evidence.json"
            e2e.write_evidence(path, document)
            original = path.read_bytes()

            credential = copy.deepcopy(document)
            credential["metadata"] = {"token": secret}
            with self.assertRaises(e2e.EvidenceError) as raised:
                e2e.write_evidence(path, credential)
            self.assertNotIn(secret, str(raised.exception))
            self.assertEqual(path.read_bytes(), original)

            for key in ("packet_payload", "terraform_state", "user-data"):
                unsafe = copy.deepcopy(document)
                unsafe["metadata"] = {key: {}}
                with self.subTest(key=key), self.assertRaisesRegex(e2e.EvidenceError, "raw packet/state/user-data"):
                    e2e.validate_evidence(unsafe)

    def test_scanner_reports_paths_but_not_secret_values(self) -> None:
        secret = "AKIA" + "ABCDEFGHIJKLMNOP"
        findings = e2e.scan_evidence(
            {"safe": [{"value": secret}], "payload": "bytes", "AWS_SECRET_ACCESS_KEY": "forty-character-value"}
        )
        rendered = " ".join(findings)
        self.assertIn("$.safe[0].value", rendered)
        self.assertIn("$.payload", rendered)
        self.assertIn("$.AWS_SECRET_ACCESS_KEY", rendered)
        self.assertNotIn(secret, rendered)


class FakeProtectedLifecycle:
    def __init__(self, failure: str | None = None) -> None:
        self.failure = failure
        self.calls: list[str] = []
        self.cleanup_calls = 0

    def claim(
        self, raw_deployment: dict[str, Any], deployment: e2e.ProtectedDeployment
    ) -> dict[str, Any]:
        self.calls.append("claim")
        if self.failure == "claim":
            raise e2e.ConcurrentRunError("another durable E2E claim is active")
        if self.failure == "claim-persistence":
            raise e2e.ClaimPersistenceError(
                "durable E2E claim was not committed; deployment cleanup remains authorized"
            )
        if self.failure == "claim-ambiguous":
            raise e2e.AmbiguousOwnershipError(
                "durable E2E ownership is ambiguous after bounded recovery; cleanup is prohibited"
            )
        return {
            "manifest_phase": "ready",
            "saved_plan_applied_once": True,
            "load_profile_approved_before_apply": True,
        }

    def verify_no_drift(self, stage: str) -> dict[str, Any]:
        self.calls.append(f"drift-{stage}")
        if self.failure == f"drift-{stage}":
            raise e2e.DriftError(f"{stage} drift")
        return {"clean": True, "stage": stage}

    def finish(self, passed: bool) -> dict[str, Any]:
        self.calls.append(f"finish-{passed}")
        if self.failure == "finish":
            raise e2e.LifecycleError("durable finish rejected")
        if self.failure == "finish-persistence":
            raise e2e.ClaimPersistenceError(
                "durable E2E result was not committed; owned-claim cleanup handoff remains authorized"
            )
        if self.failure == "finish-ambiguous":
            raise e2e.AmbiguousOwnershipError(
                "durable E2E ownership is ambiguous after bounded recovery; cleanup is prohibited"
            )
        return {"finish": "persisted"}

    def cleanup(self) -> dict[str, Any]:
        self.calls.append("cleanup")
        self.cleanup_calls += 1
        if self.failure == "cleanup":
            raise e2e.LifecycleError("protected cleanup failed")
        return {"removed": True}


class FakeLiveOperations:
    def __init__(self, failure: str | None = None) -> None:
        self.failure = failure
        self.calls: list[str] = []
        self.stop_calls = 0
        self.flow_windows: dict[str, dict[str, int]] = {}

    def record_flow_windows(self, flows: Sequence[e2e.FlowRecord]) -> None:
        now = int(time.time())
        for flow in flows:
            self.flow_windows[flow.flow_id] = {"start_epoch": now, "end_epoch": now}

    @staticmethod
    def workload_identity(deployment: e2e.ProtectedDeployment, site: str, role: str) -> dict[str, Any]:
        target = deployment.workloads.target(site, role)
        identity_index = e2e.SITES.index(site) * 2 + e2e.WORKLOAD_ROLES.index(role)
        return {
            "site": site,
            "role": role,
            "private_ip": target.private_ip,
            "instance_id": target.instance_id,
            "interface_id": f"eni-{identity_index}123456789abcdef0",
            "subnet_id": target.subnet_id,
            "flow_directions": ["egress", "ingress"],
        }

    @staticmethod
    def probe(flow: e2e.FlowRecord) -> dict[str, Any]:
        digest = hashlib.sha256(flow.flow_id.encode()).hexdigest()
        if flow.protocol == "icmp":
            return {
                "flow_id": flow.flow_id,
                "protocol": "icmp",
                "source_ip": flow.source.private_ip,
                "source_port": None,
                "destination_ip": flow.destination.private_ip,
                "destination_port": None,
                "payload_sha256": digest,
                "payload_bytes": 56,
                "icmp_request_type": 8,
                "icmp_reply_type": 0,
                "response_timeout_seconds": 30,
                "receiver": {
                    "reply_source_ip": flow.destination.private_ip,
                    "source_identity_verified": True,
                },
                "success": True,
            }
        return {
            "flow_id": flow.flow_id,
            "protocol": flow.protocol,
            "source_ip": flow.source.private_ip,
            "source_port": flow.source_port,
            "destination_ip": flow.destination.private_ip,
            "destination_port": flow.destination_port,
            "payload_sha256": digest,
            "payload_bytes": 64,
            "response_timeout_seconds": 30,
            "receiver": {
                "flow_id": flow.flow_id,
                "payload_sha256": digest,
                "source_ip": flow.source.private_ip,
                "source_port": flow.source_port,
                "receives": 1,
                "duplicates": 0,
                "sessions": 1,
            },
            "success": True,
        }

    @staticmethod
    def metrics(flow: e2e.FlowRecord, mode: str = "normal") -> dict[str, Any]:
        if mode == "bidirectional":
            return {
                "packet_deltas": {
                    site: {name: 20 for name in e2e._PACKET_METRICS} for site in e2e.SITES
                },
                "byte_deltas": {
                    site: {name: 4096 for name in e2e._BYTE_METRICS} for site in e2e.SITES
                },
                "unexpected_deltas": {
                    site: {name: 0 for name in e2e._UNEXPECTED_FLOW_METRICS} for site in e2e.SITES
                },
                "unexpected_growth": False,
            }
        packet = {name: 2 for name in e2e._PACKET_METRICS}
        byte = {name: 128 for name in e2e._BYTE_METRICS}
        unexpected = {
            site: {name: 0 for name in e2e._UNEXPECTED_FLOW_METRICS} for site in e2e.SITES
        }
        sessions: int | None = None if flow.protocol == "icmp" else 1
        intentional: dict[str, Any] = {}
        if mode == "mtu-drop":
            packet = {name: (2 if name == "geneve_rx_packets" else 0) for name in e2e._PACKET_METRICS}
            byte = {name: (128 if name == "geneve_rx_bytes" else 0) for name in e2e._BYTE_METRICS}
            sessions = 0
            unexpected[flow.source.site]["drops"] = 1
            unexpected[flow.source.site]["gwlb_mtu_drops_total"] = 1
            intentional = {
                "intentional_mtu_drop": {
                    "site": flow.source.site,
                    "generic_drops_delta": 1,
                    "mtu_specific": {
                        "metric": "gwlb_mtu_drops_total",
                        "delta": 1,
                        "direction": "ingress",
                        "family": "ipv4",
                    },
                }
            }
        return {
            "initiator_site": flow.source.site,
            "packet_deltas": packet,
            "byte_deltas": byte,
            "session": {
                "receiver_sessions": sessions,
                "receiver_identity_verified": True,
                "integrity_metric_deltas": {name: 0 for name in e2e._SESSION_INTEGRITY_METRICS},
            },
            "malformed_deltas": {"west": 0, "east": 0},
            "unexpected_deltas": unexpected,
            "unexpected_growth": False,
            **intentional,
        }

    def verify_readiness_and_topology(
        self, deployment: e2e.ProtectedDeployment, *, timeout_seconds: int
    ) -> dict[str, Any]:
        self.calls.append("readiness")
        appliance_checks: dict[str, dict[str, Any]] = {}
        workload_checks: dict[str, dict[str, Any]] = {}
        for site in e2e.SITES:
            runtime = deployment.runtime(site)
            appliance_checks[site] = {
                gate: True for gate in e2e._APPLIANCE_READINESS_GATES
            }
            appliance_checks[site].update(
                {
                    "advertised_routes": sorted((*runtime.gwlb_return_cidrs, *runtime.local_delivery_cidrs)),
                    "accepted_routes": sorted(runtime.remote_tailnet_cidrs),
                    "accepted_route_peer": f"fixture-live-{'east' if site == 'west' else 'west'}",
                    "links": [runtime.underlay_interface, runtime.tailscale_iface, runtime.tun_name],
                    "target_status": "healthy",
                    "gwlbe_endpoint_age_seconds": e2e.GWLBE_STABILIZATION_SECONDS,
                }
            )
            for role in e2e.WORKLOAD_ROLES:
                workload_checks[f"{site}-{role}"] = {
                    gate: True for gate in e2e._WORKLOAD_READINESS_GATES
                }
                workload_checks[f"{site}-{role}"].update(self.workload_identity(deployment, site, role))
        if self.failure == "readiness":
            appliance_checks["west"]["cloud_init_complete"] = False
        if self.failure and self.failure.startswith("readiness-appliance-"):
            appliance_checks["west"][self.failure.removeprefix("readiness-appliance-")] = False
        if self.failure and self.failure.startswith("readiness-workload-"):
            workload_checks["west-initiator"][self.failure.removeprefix("readiness-workload-")] = False
        return {
            "appliance_count": 2,
            "workload_count": 4,
            "all_hosts_ready": True,
            "directional_routes_exact": True,
            "lane_routes": [{"exact": True}] * 4,
            "appliance_checks": appliance_checks,
            "workload_checks": workload_checks,
        }

    def start_flow_logs(
        self, deployment: e2e.ProtectedDeployment, *, timeout_seconds: int
    ) -> object:
        self.calls.append("flow-start")
        if self.failure == "flow-start":
            raise e2e.FlowLogError("flow log startup rejected")
        return object()

    def run_cold_direction(
        self,
        deployment: e2e.ProtectedDeployment,
        source_site: str,
        flows: tuple[e2e.FlowRecord, ...] | list[e2e.FlowRecord],
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.calls.append(f"cold-{source_site}")
        self.record_flow_windows(flows)
        if self.failure == "interrupt":
            raise KeyboardInterrupt("simulated runner interruption")
        if self.failure == "acceptance-timeout":
            raise TimeoutError("simulated active acceptance timer")
        if self.failure == "active-interrupt":
            raise InterruptedError("simulated active acceptance interruption")
        results = []
        for flow in flows:
            probe = self.probe(flow)
            metrics = self.metrics(flow)
            if self.failure == "probe-duplicates" and flow.protocol == "udp":
                probe["receiver"]["duplicates"] = 1
                probe["receiver"]["receives"] = 2
            if self.failure == "icmp-identity" and flow.protocol == "icmp":
                probe["receiver"]["reply_source_ip"] = "10.0.0.1"
            if self.failure == "metrics":
                metrics["unexpected_growth"] = True
            results.append({"flow_id": flow.flow_id, "probe": probe, "metrics": metrics})
        wire_flows = [
            {
                "flow_id": flow.flow_id,
                "outer_ipv4_checksums": "valid",
                "outer_udp_checksums": ["valid", "valid"],
                "outer_ips_swapped": True,
                "original_gwlb_source_port": 40000 + flow.ordinal,
                "return_udp_source_port": 40000 + flow.ordinal,
                "return_udp_destination_port": 6081,
                "return_source_port_preserved": True,
                "inner_flow_identity_verified": True,
                "vni": 0,
                "ordered_options_sha256": "a" * 64,
                "flow_cookie_sha256": "b" * 64,
                "ordered_options_identical": True,
                "path_packet_counts": {
                    f"{source_site}:envelope0": 2,
                    f"{source_site}:tailscale0": 2,
                    f"{'east' if source_site == 'west' else 'west'}:envelope0": 0,
                    f"{'east' if source_site == 'west' else 'west'}:tailscale0": 2,
                },
                "responder_gwlb_matching_packets": 0,
            }
            for flow in flows
        ]
        if self.failure == "wire-port":
            wire_flows[0]["return_udp_destination_port"] = 40000
        if self.failure == "wire-options":
            wire_flows[0]["ordered_options_identical"] = False
        if self.failure == "wire-checksum":
            wire_flows[0]["outer_ipv4_checksums"] = "invalid"
        return {
            "context": {
                "both_processes_restarted": True,
                "matching_return_context_before_first_packet": self.failure == "cold-context",
                "matching_flow_ids_absent_before": [flow.flow_id for flow in flows],
                "allocation_unique_in_generation": True,
                "targets_healthy_before_first_packet": True,
                "process_ids": {"west": 101, "east": 202},
                "empty_context_proof": "new-process-generations-have-no-process-local-return-contexts",
            },
            "results": results,
            "wire": {
                "direction": f"{source_site}-to-{'east' if source_site == 'west' else 'west'}",
                "source_site": source_site,
                "destination_site": "east" if source_site == "west" else "west",
                "capture_bounded": True,
                "raw_pcaps_deleted": self.failure != "wire-cleanup",
                "raw_pcaps_retained": False,
                "interfaces": [
                    {"site": site, "interface": interface, "file_sha256": "c" * 64, "frame_count": 2}
                    for site in e2e.SITES
                    for interface in ("envelope0", "tailscale0", "underlay")
                ],
                "flows": wire_flows,
            },
        }

    def run_mtu_transport(
        self,
        deployment: e2e.ProtectedDeployment,
        profile: e2e.ApprovedLoadProfile,
        flows: tuple[e2e.FlowRecord, ...] | list[e2e.FlowRecord],
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.calls.append("mtu")
        self.record_flow_windows(flows)
        selected = flows[:-1] if self.failure == "mtu-missing" else flows
        results = []
        for flow in selected:
            mode = "mtu-drop" if flow.expected_result == "mtu-drop" else "normal"
            metrics = self.metrics(flow, mode)
            if self.failure == "mtu-drop-metric" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["gwlb_mtu_drops_total"] = 0
            if self.failure == "mtu-generic-drop-metric" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["drops"] = 0
            if self.failure == "mtu-extra-generic-drop" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["drops"] = 2
            if self.failure == "mtu-peer-drop" and mode == "mtu-drop":
                peer = "east" if flow.source.site == "west" else "west"
                metrics["unexpected_deltas"][peer]["drops"] = 1
            if self.failure == "mtu-other-error" and mode == "mtu-drop":
                metrics["unexpected_deltas"][flow.source.site]["gwlb_send_failures_total"] = 1
            value: dict[str, Any] = {"flow_id": flow.flow_id, "metrics": metrics}
            if flow.expected_result == "mtu-drop":
                value.update(
                    {
                        "reply_received": self.failure == "mtu-oversized-reply",
                        "pmtu_icmp_expected": False,
                    }
                )
                if flow.protocol == "icmp":
                    value["capture"] = {
                        "interface": deployment.runtime(flow.source.site).underlay_interface,
                        "file_sha256": "f" * 64,
                        "icmp_checksum": "valid",
                        "raw_pcap_deleted": True,
                        "request_count": 1,
                        "inner_bytes": profile.safe_inner_mtu + 1,
                        "payload_bytes": profile.safe_inner_mtu - 27,
                        "payload_sha256": "a" * 64,
                    }
                    if self.failure == "mtu-icmp-capture":
                        value["capture"]["request_count"] = 2
            elif flow.protocol in {"icmp", "udp"}:
                value["probe"] = self.probe(flow)
                value["probe"]["payload_bytes"] = profile.safe_inner_mtu - 28
            else:
                value["transport"] = {"completed": True}
            results.append(value)
        directions = [
            {
                "source_site": site,
                "destination_site": "east" if site == "west" else "west",
                "inner_mtu": 1280,
                "safe_icmp_inner_bytes": 1280,
                "safe_udp_inner_bytes": 1280,
                "oversized_icmp_inner_bytes": 1281,
                "oversized_udp_inner_bytes": 1281,
                "tcp_mss": 1300 if self.failure == "mtu-mss" else 1240,
                "tcp_mss_maximum": 1240,
                "tcp_syn_capture_sha256": "e" * 64,
                "tcp_syn_raw_pcap_deleted": True,
                "sustained_tcp_bytes": profile.minimum_sustained_tcp_bytes,
                "sustained_tcp_duration_seconds": profile.sustained_tcp_duration_seconds,
                "pmtu_icmp_expected": False,
                "flow_ids": [flow.flow_id for flow in flows if flow.source.site == site],
            }
            for site in e2e.SITES
        ]
        if self.failure == "mtu-safe":
            directions[0]["safe_udp_inner_bytes"] = 1279
        return {"results": results, "directions": directions}

    def run_approved_load(
        self,
        deployment: e2e.ProtectedDeployment,
        profile: e2e.ApprovedLoadProfile,
        flows: tuple[e2e.FlowRecord, ...] | list[e2e.FlowRecord],
        *,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.calls.append("load")
        self.record_flow_windows(flows)
        iperf = [
            {
                "flow_id": flow.flow_id,
                "completed": True,
                "throughput_mbps": 0.5 if self.failure == "load-throughput" else profile.minimum_throughput_mbps,
                "duration_seconds": profile.iperf_duration_seconds,
                "bytes": profile.minimum_sustained_tcp_bytes,
                "syn_mss": profile.maximum_tcp_mss,
                "syn_capture_sha256": "d" * 64,
                "raw_pcap_deleted": True,
            }
            for flow in flows
            if flow.purpose == "iperf3"
        ]
        concurrent = [
            {
                "flow_id": flow.flow_id,
                "completed": True,
                "duration_seconds": profile.concurrent_duration_seconds,
                "loss_percent": 2.0 if self.failure == "load-loss" else 0.0,
                "p99_latency_ms": 200.0 if self.failure == "load-latency" else 1.0,
                "protocol": flow.protocol,
                "source_port": flow.source_port,
                "sent": 10,
                "received": 10 if self.failure != "load-loss" else 9,
            }
            for flow in flows
            if flow.purpose.startswith("concurrent-")
        ]
        metrics = self.metrics(flows[0], "bidirectional")
        if self.failure == "load-metrics":
            metrics["unexpected_deltas"]["west"]["drops"] = 1
        return {
            "profile_sha256": "0" * 64 if self.failure == "load-profile" else profile.sha256,
            "iperf3": iperf,
            "concurrent": concurrent,
            "metrics": metrics,
        }

    @staticmethod
    def continuity() -> dict[str, Any]:
        return {"bounded": True, "maximum_loss_ns": 1_000_000_000, "missing_markers": 0}

    def run_route_mutation(
        self,
        deployment: e2e.ProtectedDeployment,
        flow: e2e.FlowRecord,
        *,
        timeout_seconds: int,
        maximum_loss_ns: int,
    ) -> dict[str, Any]:
        self.calls.append("route")
        self.record_flow_windows((flow,))
        if self.failure == "route":
            raise e2e.ResilienceError("route restoration differs")
        observed = self.failure != "route-readiness"
        repair_delta = 0 if self.failure in {"route-readiness", "route-zero-repair"} else 1
        return {
            "passed": True,
            "restored": True,
            "continuity": self.continuity(),
            "stream": {"flow_id": flow.flow_id, "bounded": True},
            "readiness_during_drift": {
                "before_repair": True,
                "exact_rule_missing": True,
                "drift_observed": observed,
                "unhealthy": False,
                "host_preflight_failed": observed,
                "routing_drift_repairs_delta": repair_delta,
                "missing_cidr": deployment.workloads.west.initiator.cidr,
                "reason": "owned-return-rule-missing",
            },
            "repair_metric_delta": repair_delta,
            "metrics": self.metrics(flow),
        }

    def run_service_stop(
        self, deployment: e2e.ProtectedDeployment, flow: e2e.FlowRecord, *, timeout_seconds: int
    ) -> dict[str, Any]:
        self.calls.append("service")
        self.record_flow_windows((flow,))
        value = {
            "passed": True,
            "restored": True,
            "recovery": {"new_cold_flow": True},
            "probe": self.probe(flow),
            "metrics": self.metrics(flow),
            "target_transition": ["healthy", "unhealthy", "healthy"],
            "process_generation_changed": True,
        }
        if self.failure == "service":
            value["recovery"] = {"new_cold_flow": False}
        return value

    def run_ec2_reboot(
        self, deployment: e2e.ProtectedDeployment, site: str, flow: e2e.FlowRecord, *, timeout_seconds: int
    ) -> dict[str, Any]:
        self.calls.append(f"reboot-{site}")
        self.record_flow_windows((flow,))
        if self.failure in {"reboot", f"reboot-{site}"}:
            raise e2e.ResilienceError("boot generation unchanged")
        return {
            "passed": True,
            "restored": True,
            "recovery": {"new_cold_flow": True},
            "probe": self.probe(flow),
            "site": site,
            "metrics": self.metrics(flow),
            "boot_generation_changed": True,
            "process_generation_changed": True,
            "target_recovered_healthy": True,
            "persistent_configuration_recovered": True,
        }

    def run_tailscale_withdrawal(
        self,
        deployment: e2e.ProtectedDeployment,
        flow: e2e.FlowRecord,
        *,
        timeout_seconds: int,
        maximum_loss_ns: int,
    ) -> dict[str, Any]:
        self.calls.append("tailscale")
        self.record_flow_windows((flow,))
        return {
            "passed": True,
            "restored": True,
            "continuity": self.continuity(),
            "credential_rotation": self.failure == "tailscale-rotation",
            "exact_routes_withdrawn": self.failure != "tailscale-routes",
            "withdrawn_cidrs": sorted(deployment.runtime("west").remote_tailnet_cidrs),
            "restored_cidrs": sorted(deployment.runtime("west").remote_tailnet_cidrs),
            "stream": {"flow_id": flow.flow_id, "bounded": True},
            "metrics": self.metrics(flow),
        }

    def capture_flow_logs(
        self,
        handle: object,
        deployment: e2e.ProtectedDeployment,
        flows: tuple[e2e.FlowRecord, ...],
        *,
        timeout_seconds: int,
    ) -> list[dict[str, Any]]:
        self.calls.append("flow-capture")
        selected = flows[:-1] if self.failure == "flow-missing" else flows
        values: list[dict[str, Any]] = []
        for flow in selected:
            icmp_drop = flow.protocol == "icmp" and flow.expected_result == "mtu-drop"
            source = self.workload_identity(deployment, flow.source.site, flow.source.role)
            destination = self.workload_identity(deployment, flow.destination.site, flow.destination.role)
            specs = (
                [("source-egress", source, "egress")]
                if flow.expected_result == "mtu-drop"
                else [
                    ("source-egress", source, "egress"),
                    ("destination-ingress", destination, "ingress"),
                    ("responder-egress", destination, "egress"),
                    ("initiator-ingress", source, "ingress"),
                ]
            )
            paths = [
                {
                    "path": name,
                    "site": identity["site"],
                    "role": identity["role"],
                    "flow_direction": direction,
                    "instance_id": identity["instance_id"],
                    "interface_id": identity["interface_id"],
                    "subnet_id": identity["subnet_id"],
                    "matches": 1,
                    "packet_count": 1,
                    "byte_count": 64,
                }
                for name, identity, direction in specs
            ]
            values.append({
                "flow_id": flow.flow_id,
                "accepted": True,
                "flow_tuple": flow.tuple_dict(),
                "forward_matches": 1 if flow.expected_result == "mtu-drop" else 2,
                "reverse_matches": 0 if flow.expected_result == "mtu-drop" else 2,
                "reverse_required": flow.expected_result == "success",
                "packet_count": len(paths),
                "byte_count": 64 * len(paths),
                "phase": e2e._flow_phase(flow.as_dict()).value,
                "window": {
                    "start_epoch": self.flow_windows[flow.flow_id]["start_epoch"],
                    "end_epoch": self.flow_windows[flow.flow_id]["end_epoch"],
                    "aggregation_allowance_seconds": 60,
                },
                "path_evidence": paths,
                "unexpected_path_matches": 0,
                "aggregation_overlap_path_matches": 3 if icmp_drop else 0,
                "correlation_mode": "icmp-lane-window" if flow.protocol == "icmp" else "transport-5-tuple-window",
                "flow_logs_uniquely_identify_flow": flow.protocol != "icmp",
                "aws_aggregation_limitation": (
                    "icmp-records-omit-ports-and-may-aggregate-repeated-tuples"
                    if flow.protocol == "icmp"
                    else None
                ),
                "process_generation": flow.process_generation,
                "unique_identity_evidence": (
                    ["process-generation", "mtu-request-capture", "failed-application-reply", "mtu-drop-metrics"]
                    if icmp_drop
                    else ["process-generation", "application-reply"]
                    if flow.protocol == "icmp"
                    else ["transport-ports", "process-generation"]
                ),
            })
        if values and self.failure == "flow-wrong-eni":
            values[0]["path_evidence"][0]["interface_id"] = "eni-fffffffffffffffff"
        if values and self.failure == "flow-wrong-direction":
            values[0]["path_evidence"][0]["flow_direction"] = "ingress"
        if values and self.failure == "flow-window":
            values[0]["window"]["end_epoch"] = values[0]["window"]["start_epoch"] + 7201
        if self.failure == "flow-false-reverse":
            dropped = next(value for value in values if value["reverse_required"] is False)
            dropped["unexpected_path_matches"] = 1
        if self.failure == "flow-icmp-unique":
            icmp = next(
                value
                for value in values
                if value["correlation_mode"] == "icmp-lane-window"
            )
            icmp["flow_logs_uniquely_identify_flow"] = True
        return values

    def stop_flow_logs(self, handle: object, *, timeout_seconds: int) -> dict[str, Any]:
        self.calls.append("flow-stop")
        self.stop_calls += 1
        if self.failure == "flow-stop":
            raise e2e.FlowLogError("temporary flow log rollback failed")
        return {"stopped": True, "ownership_preserved": True}

    def collect_diagnostics(self, deployment: e2e.ProtectedDeployment | None) -> dict[str, Any]:
        self.calls.append("diagnostics")
        return {"collection": "complete", "hosts": 6}


class ReadinessGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.deployment = e2e.parse_protected_deployment_output(protected_output())
        self.operations = FakeLiveOperations()
        self.summary = self.operations.verify_readiness_and_topology(self.deployment, timeout_seconds=30)

    def test_every_appliance_and_workload_component_is_required(self) -> None:
        e2e._validate_readiness_summary(self.deployment, self.summary, run_id="fixture-live")
        for gate in e2e._APPLIANCE_READINESS_GATES:
            candidate = copy.deepcopy(self.summary)
            candidate["appliance_checks"]["west"][gate] = False
            with self.subTest(kind="appliance", gate=gate), self.assertRaises(e2e.ReadinessError):
                e2e._validate_readiness_summary(self.deployment, candidate, run_id="fixture-live")
        for gate in e2e._WORKLOAD_READINESS_GATES:
            candidate = copy.deepcopy(self.summary)
            candidate["workload_checks"]["east-responder"][gate] = False
            with self.subTest(kind="workload", gate=gate), self.assertRaises(e2e.ReadinessError):
                e2e._validate_readiness_summary(self.deployment, candidate, run_id="fixture-live")

    def test_exact_routes_links_target_and_source_identity_are_required(self) -> None:
        mutations = []
        advertised = copy.deepcopy(self.summary)
        advertised["appliance_checks"]["west"]["advertised_routes"].append("10.99.0.0/24")
        mutations.append(advertised)
        accepted = copy.deepcopy(self.summary)
        accepted["appliance_checks"]["east"]["accepted_routes"] = []
        mutations.append(accepted)
        peer = copy.deepcopy(self.summary)
        peer["appliance_checks"]["west"]["accepted_route_peer"] = "unrelated-peer"
        mutations.append(peer)
        links = copy.deepcopy(self.summary)
        links["appliance_checks"]["west"]["links"] = ["ens5", "tailscale0"]
        mutations.append(links)
        target = copy.deepcopy(self.summary)
        target["appliance_checks"]["east"]["target_status"] = "initial"
        mutations.append(target)
        source = copy.deepcopy(self.summary)
        source["workload_checks"]["west-initiator"]["private_ip"] = "10.10.1.99"
        mutations.append(source)
        missing_eni = copy.deepcopy(self.summary)
        missing_eni["workload_checks"]["east-responder"].pop("interface_id")
        mutations.append(missing_eni)
        duplicate_eni = copy.deepcopy(self.summary)
        duplicate_eni["workload_checks"]["east-responder"]["interface_id"] = duplicate_eni["workload_checks"]["west-initiator"]["interface_id"]
        mutations.append(duplicate_eni)
        young_endpoint = copy.deepcopy(self.summary)
        young_endpoint["appliance_checks"]["west"]["gwlbe_endpoint_age_seconds"] = (
            e2e.GWLBE_STABILIZATION_SECONDS - 1
        )
        mutations.append(young_endpoint)
        for index, candidate in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(e2e.ReadinessError):
                e2e._validate_readiness_summary(self.deployment, candidate, run_id="fixture-live")

    def test_ec2_route_response_uses_gateway_id_for_gwlbe_targets(self) -> None:
        endpoint_id = "vpce-0123456789abcdef0"
        endpoint_route = {
            "DestinationCidrBlock": "172.17.0.0/24",
            "GatewayId": endpoint_id,
            "Origin": "CreateRoute",
            "State": "active",
        }
        self.assertTrue(
            e2e.AwsLiveOperations._route_selects_only_target(
                endpoint_route, "GatewayId", endpoint_id
            )
        )
        wrong_field = {**endpoint_route, "GatewayId": None, "VpcEndpointId": endpoint_id}
        self.assertFalse(
            e2e.AwsLiveOperations._route_selects_only_target(wrong_field, "GatewayId", endpoint_id)
        )
        extra_target = {**endpoint_route, "NetworkInterfaceId": "eni-0123456789abcdef0"}
        self.assertFalse(
            e2e.AwsLiveOperations._route_selects_only_target(extra_target, "GatewayId", endpoint_id)
        )


class LiveRunnerTest(unittest.TestCase):
    def run_fixture(
        self, temporary: str, *, lifecycle_failure: str | None = None, operation_failure: str | None = None
    ) -> tuple[e2e.LiveRunResult, FakeProtectedLifecycle, FakeLiveOperations]:
        lifecycle = FakeProtectedLifecycle(lifecycle_failure)
        operations = FakeLiveOperations(operation_failure)
        result = e2e.TwoRegionE2ERunner(
            run_id="fixture-live",
            raw_deployment=protected_output(),
            site_regions={"west": "us-west-2", "east": "us-east-1"},
            lifecycle=lifecycle,
            operations=operations,
            evidence_path=pathlib.Path(temporary) / "evidence.json",
            monotonic=lambda: 0.0,
        ).run()
        return result, lifecycle, operations

    def test_preclaim_contract_failure_still_cleans_up_owned_run(self) -> None:
        raw = protected_output()
        del raw["e2e_load_profile"]
        lifecycle = FakeProtectedLifecycle()
        operations = FakeLiveOperations()
        with tempfile.TemporaryDirectory() as temporary:
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=lifecycle,
                operations=operations,
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_CONTRACT_ERROR)
        self.assertEqual(lifecycle.cleanup_calls, 1)
        self.assertNotIn("claim", lifecycle.calls)
        cleanup = next(phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value)
        self.assertEqual(cleanup["status"], "passed")

    def test_run_live_cleanup_has_one_separate_bounded_timer(self) -> None:
        cleanup_timeouts: list[int] = []

        @contextlib.contextmanager
        def cleanup_timeout(seconds: int) -> Any:
            cleanup_timeouts.append(seconds)
            yield

        with tempfile.TemporaryDirectory() as temporary:
            lifecycle = FakeProtectedLifecycle()
            bounded = e2e._BoundedCleanupLifecycleProxy(lifecycle, cleanup_timeout)
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=bounded,
                operations=FakeLiveOperations("acceptance-timeout"),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(lifecycle.cleanup_calls, 1)
        self.assertEqual(cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])
        bounded.cleanup()
        self.assertEqual(lifecycle.cleanup_calls, 1)

    def test_active_limit_skips_stuck_diagnostics_and_preserves_cleanup_reservation(self) -> None:
        cleanup_timeouts: list[int] = []

        @contextlib.contextmanager
        def cleanup_timeout(seconds: int) -> Any:
            cleanup_timeouts.append(seconds)
            yield

        class StuckDiagnosticOperations(FakeLiveOperations):
            def __init__(self, failure: str) -> None:
                super().__init__(failure)
                self.diagnostics_started = False

            def collect_diagnostics(self, deployment: e2e.ProtectedDeployment | None) -> dict[str, Any]:
                self.diagnostics_started = True
                threading.Event().wait(1)
                raise AssertionError("stuck diagnostics consumed the cleanup reservation")

        for failure, category in (("acceptance-timeout", "TimeoutError"), ("active-interrupt", "InterruptedError")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                lifecycle = FakeProtectedLifecycle()
                bounded = e2e._BoundedCleanupLifecycleProxy(lifecycle, cleanup_timeout)
                operations = StuckDiagnosticOperations(failure)
                result = e2e.TwoRegionE2ERunner(
                    run_id="fixture-live",
                    raw_deployment=protected_output(),
                    site_regions={"west": "us-west-2", "east": "us-east-1"},
                    lifecycle=bounded,
                    operations=operations,
                    evidence_path=pathlib.Path(temporary) / "evidence.json",
                    monotonic=lambda: 0.0,
                ).run()

                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(result.evidence["diagnostics"]["collection"], "skipped")
                self.assertFalse(operations.diagnostics_started)
                self.assertEqual(lifecycle.cleanup_calls, 1)
                self.assertNotIn("finish", lifecycle.calls)

        self.assertEqual(cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup] * 2)

    def test_run_live_cleanup_timeout_is_exit_three_without_retry(self) -> None:
        @contextlib.contextmanager
        def cleanup_timeout(_seconds: int) -> Any:
            yield
            raise TimeoutError("cleanup reservation expired")

        with tempfile.TemporaryDirectory() as temporary:
            lifecycle = FakeProtectedLifecycle()
            bounded = e2e._BoundedCleanupLifecycleProxy(lifecycle, cleanup_timeout)
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=protected_output(),
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=bounded,
                operations=FakeLiveOperations(),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(lifecycle.cleanup_calls, 1)
        self.assertTrue(bounded.cleanup_attempted)

    def test_complete_success_bundle_strictly_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, lifecycle, operations = self.run_fixture(temporary)

            self.assertEqual(result.exit_code, e2e.EXIT_OK)
            self.assertTrue(result.passed)
            verified = e2e.verify_live_evidence(result.evidence)
            self.assertEqual(verified["status"], "passed")
            self.assertEqual([phase["name"] for phase in verified["phases"]], [phase.value for phase in e2e.LIVE_PHASES])
            self.assertEqual(len(verified["flows"]), 31)
            self.assertEqual(len(verified["flow_logs"]), 31)
            self.assertEqual(len(verified["probes"]), 13)
            self.assertEqual(len(verified["wire"]), 2)
            self.assertEqual(len(verified["transport"]), 2)
            self.assertEqual(len(verified["resilience"]), 5)
            self.assertEqual(lifecycle.cleanup_calls, 1)
            self.assertEqual(operations.stop_calls, 1)
            self.assertEqual(stat.S_IMODE(result.evidence_path.stat().st_mode), 0o600)

    def test_every_live_gate_fails_closed_and_claimed_runs_cleanup(self) -> None:
        cases = {
            "concurrent claim": ("claim", None, e2e.EXIT_ACCEPTANCE_FAILED, 0),
            "claim not committed": ("claim-persistence", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "claim ownership ambiguous": ("claim-ambiguous", None, e2e.EXIT_ACCEPTANCE_FAILED, 0),
            "pre-test drift": ("drift-before", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "readiness": (None, "readiness", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "appliance readiness component": (None, "readiness-appliance-firewall_mss_ready", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "workload readiness component": (None, "readiness-workload-tools_ready", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow log start": (None, "flow-start", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "cold context existed": (None, "cold-context", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "icmp identity": (None, "icmp-identity", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "receiver duplicate": (None, "probe-duplicates", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "runner interruption": (None, "interrupt", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "metric growth": (None, "metrics", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire UDP orientation": (None, "wire-port", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire options changed": (None, "wire-options", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire checksum": (None, "wire-checksum", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wire cleanup": (None, "wire-cleanup", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU matrix missing": (None, "mtu-missing", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU safe boundary": (None, "mtu-safe", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU-specific drop missing": (None, "mtu-drop-metric", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "generic MTU drop missing": (None, "mtu-generic-drop-metric", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "generic MTU drop duplicated": (None, "mtu-extra-generic-drop", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "peer MTU drop": (None, "mtu-peer-drop", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "other MTU error": (None, "mtu-other-error", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU oversized reply": (None, "mtu-oversized-reply", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "MTU ICMP capture": (None, "mtu-icmp-capture", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "TCP MSS": (None, "mtu-mss", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load profile binding": (None, "load-profile", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load throughput": (None, "load-throughput", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load loss": (None, "load-loss", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load latency": (None, "load-latency", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "load metrics": (None, "load-metrics", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route restoration": (None, "route", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route readiness drift": (None, "route-readiness", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route repair metric": (None, "route-zero-repair", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "service recovery": (None, "service", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "west reboot recovery": (None, "reboot-west", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "east reboot recovery": (None, "reboot-east", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "credential rotation": (None, "tailscale-rotation", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "route acceptance exactness": (None, "tailscale-routes", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow tuple missing": (None, "flow-missing", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow wrong ENI": (None, "flow-wrong-eni", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow wrong direction": (None, "flow-wrong-direction", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow window": (None, "flow-window", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow false reverse": (None, "flow-false-reverse", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "ICMP flow uniqueness": (None, "flow-icmp-unique", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "flow log rollback": (None, "flow-stop", e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "post-test drift": ("drift-after", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "durable finish": ("finish", None, e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "cleanup": ("cleanup", None, e2e.EXIT_CLEANUP_FAILED, 1),
        }
        for name, (lifecycle_failure, operation_failure, exit_code, cleanup_calls) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                result, lifecycle, operations = self.run_fixture(
                    temporary,
                    lifecycle_failure=lifecycle_failure,
                    operation_failure=operation_failure,
                )
                self.assertEqual(result.exit_code, exit_code)
                self.assertEqual(result.evidence["status"], "failed")
                self.assertEqual(lifecycle.cleanup_calls, cleanup_calls)
                if lifecycle_failure in {"claim", "claim-persistence", "claim-ambiguous"}:
                    self.assertEqual(
                        result.evidence["lifecycle"]["ownership_resolution"],
                        {
                            "claim": "competing-claim",
                            "claim-persistence": "not-committed",
                            "claim-ambiguous": "ambiguous-ownership",
                        }[lifecycle_failure],
                    )
                self.assertEqual(e2e.validate_evidence(result.evidence), result.evidence)
                with self.assertRaises(e2e.EvidenceVerificationError):
                    e2e.verify_live_evidence(result.evidence)
                if operation_failure not in (
                    None,
                    "readiness",
                    "readiness-appliance-firewall_mss_ready",
                    "readiness-workload-tools_ready",
                    "flow-start",
                    "interrupt",
                ):
                    self.assertGreaterEqual(operations.stop_calls, 1)
                if operation_failure and operation_failure.startswith("readiness"):
                    self.assertFalse(any(call.startswith("cold-") for call in operations.calls))

    def test_finish_ownership_blocker_overrides_prior_failure_but_noncommit_does_not(self) -> None:
        cases = {
            "finish-persistence": ("MetricAssertionError", "not-committed", 1),
            "finish-ambiguous": ("AmbiguousOwnershipError", "ambiguous-ownership", 0),
        }
        for lifecycle_failure, (category, resolution, cleanup_calls) in cases.items():
            with self.subTest(failure=lifecycle_failure), tempfile.TemporaryDirectory() as temporary:
                result, lifecycle, _operations = self.run_fixture(
                    temporary,
                    lifecycle_failure=lifecycle_failure,
                    operation_failure="metrics",
                )

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(result.evidence["lifecycle"]["ownership_resolution"], resolution)
                self.assertEqual(lifecycle.cleanup_calls, cleanup_calls)
                cleanup = next(
                    phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value
                )
                self.assertEqual(cleanup["status"], "passed" if cleanup_calls else "skipped")

    def test_strict_verifier_rejects_tampered_flow_and_cli_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, _lifecycle, _operations = self.run_fixture(temporary)
            tampered = copy.deepcopy(result.evidence)
            tampered["flow_logs"].pop()
            path = pathlib.Path(temporary) / "tampered.json"
            e2e.write_evidence(path, tampered)

            with self.assertRaisesRegex(e2e.EvidenceVerificationError, "declared flow"):
                e2e.verify_live_evidence(tampered)
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "aws_two_region_e2e.py"), "verify-evidence", str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, e2e.EXIT_ACCEPTANCE_FAILED)

    def test_strict_verifier_rejects_each_new_evidence_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, _lifecycle, _operations = self.run_fixture(temporary)
            baseline = result.evidence

            def cold_context(document: dict[str, Any]) -> None:
                phase = next(
                    value for value in document["phases"] if value["name"] == e2e.Phase.COLD_WEST_EAST.value
                )
                phase["summary"]["context"]["matching_return_context_before_first_packet"] = True

            def metric_collision(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "normal")
                metric["unexpected_deltas"]["west"]["gwlb_context_collisions_total"] = 1

            def metric_type(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "normal")
                metric["packet_deltas"]["geneve_rx_packets"] = "not-a-number"

            def mtu_generic_missing(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "mtu-drop")
                site = metric["intentional_mtu_drop"]["site"]
                metric["unexpected_deltas"][site]["drops"] = 0

            def mtu_label_changed(document: dict[str, Any]) -> None:
                metric = next(value for value in document["metrics"] if value["mode"] == "mtu-drop")
                metric["intentional_mtu_drop"]["mtu_specific"]["direction"] = "egress"

            def flow_log_eni_changed(document: dict[str, Any]) -> None:
                document["flow_logs"][0]["path_evidence"][0]["interface_id"] = "eni-fffffffffffffffff"

            def flow_log_window_changed(document: dict[str, Any]) -> None:
                document["flow_logs"][0]["window"]["end_epoch"] += 7201

            def icmp_flow_log_claims_uniqueness(document: dict[str, Any]) -> None:
                value = next(
                    item for item in document["flow_logs"] if item["correlation_mode"] == "icmp-lane-window"
                )
                value["flow_logs_uniquely_identify_flow"] = True

            def icmp_drop_capture_changed(document: dict[str, Any]) -> None:
                metric = next(
                    value
                    for value in document["metrics"]
                    if value["mode"] == "mtu-drop" and value["drop_proof"]["protocol"] == "icmp"
                )
                metric["drop_proof"]["capture"]["request_count"] = 2

            def udp_drop_allows_overlap(document: dict[str, Any]) -> None:
                flow_by_id = {flow["flow_id"]: flow for flow in document["flows"]}
                value = next(
                    item
                    for item in document["flow_logs"]
                    if flow_by_id[item["flow_id"]]["protocol"] == "udp"
                    and flow_by_id[item["flow_id"]]["expected_result"] == "mtu-drop"
                )
                value["aggregation_overlap_path_matches"] = 1

            def route_drift_hardcoded(document: dict[str, Any]) -> None:
                drill = next(
                    value for value in document["resilience"] if value["name"] == e2e.Phase.ROUTE_MUTATION.value
                )
                drill["repair_metric_delta"] = 0
                drill["readiness_during_drift"].update(
                    {
                        "host_preflight_failed": True,
                        "unhealthy": False,
                        "routing_drift_repairs_delta": 0,
                        "drift_observed": True,
                    }
                )

            mutations: dict[str, Any] = {
                "readiness": lambda value: value["topology"]["appliance_checks"]["west"].update(
                    {"tailscale_backend_running": False}
                ),
                "cold context": cold_context,
                "wire": lambda value: value["wire"][0]["flows"][0].update({"outer_ips_swapped": False}),
                "MTU": lambda value: value["transport"][0].update({"tcp_mss": 1241}),
                "load profile": lambda value: value["load_profile"].update({"immutable": False}),
                "load result": lambda value: value["load"]["iperf3"][0].update({"throughput_mbps": 0}),
                "unexpected metric": metric_collision,
                "metric type": metric_type,
                "MTU generic metric": mtu_generic_missing,
                "MTU label": mtu_label_changed,
                "Flow Log ENI": flow_log_eni_changed,
                "Flow Log window": flow_log_window_changed,
                "ICMP Flow Log uniqueness": icmp_flow_log_claims_uniqueness,
                "ICMP drop capture": icmp_drop_capture_changed,
                "UDP drop overlap": udp_drop_allows_overlap,
                "route drift observation": route_drift_hardcoded,
                "west/east reboot": lambda value: value["resilience"].pop(3),
                "flow log": lambda value: value["flow_logs"].pop(),
                "cleanup": lambda value: value["lifecycle"].update({"cleanup": "failed"}),
            }
            for name, mutate in mutations.items():
                candidate = copy.deepcopy(baseline)
                mutate(candidate)
                with self.subTest(name=name), self.assertRaises(e2e.E2EError):
                    e2e.verify_live_evidence(candidate)

            synthetic_port = copy.deepcopy(baseline)
            icmp = next(flow for flow in synthetic_port["flows"] if flow["protocol"] == "icmp")
            icmp["source_port"] = 40000
            with self.assertRaisesRegex(e2e.EvidenceError, "synthetic ports"):
                e2e.verify_live_evidence(synthetic_port)


class FakeRunAllLifecycle:
    def claim(self, raw_deployment: Mapping[str, Any], deployment: e2e.ProtectedDeployment) -> Mapping[str, Any]:
        return {"claimed": True}

    def verify_no_drift(self, stage: str) -> Mapping[str, Any]:
        return {"clean": True, "stage": stage}

    def finish(self, passed: bool) -> Mapping[str, Any]:
        return {"acceptance": "passed" if passed else "failed"}

    def cleanup(self) -> Mapping[str, Any]:
        raise AssertionError("run-all must route cleanup through its one-attempt coordinator")


class FakeRunAllOperations:
    def __init__(self, root: pathlib.Path, failure: str | None = None) -> None:
        self.root = root
        self.failure = failure
        self.calls: list[str] = []
        self.cleanup_calls = 0

    def _stage(self, name: str) -> None:
        self.calls.append(name)
        if self.failure == name and name != "e2e":
            if name == "wait":
                diagnostics = self.root / "fixture-run" / "diagnostics.json"
                diagnostics.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                diagnostics.write_text('{"collection":"bounded","safe":true}\n')
                diagnostics.chmod(0o600)
            raise e2e.LifecycleError(f"injected {name} failure")
        if name == "prepare" and self.failure == "prepare-concurrent":
            raise e2e.ConcurrentLifecycleError("another lifecycle writer owns preparation")
        if name == "wait" and self.failure == "timeout":
            raise TimeoutError("injected whole-run timeout")
        if name == "wait" and self.failure == "signal":
            raise InterruptedError("injected SIGTERM")

    def build(self) -> Mapping[str, Any]:
        self._stage("build")
        return {"architecture": "amd64", "allow_dirty": False}

    def preflight(self) -> Mapping[str, Any]:
        self._stage("preflight")
        return {"read_only": True}

    def prepare(self) -> Mapping[str, Any]:
        self._stage("prepare")
        return {"manifest_phase": "prepared", "published": True}

    def plan(self) -> pathlib.Path:
        self._stage("plan")
        return self.root / "apply.tfplan"

    def apply(self, plan_path: pathlib.Path) -> Mapping[str, Any]:
        self._stage("apply")
        self.asserted_plan = plan_path
        return protected_output()

    def wait_ready(self, deployment: Mapping[str, Any], *, timeout_seconds: int) -> Mapping[str, Any]:
        self._stage("wait")
        self.asserted_deployment = deployment
        self.asserted_wait_timeout = timeout_seconds
        return {"deployment_matches": True, "manifest_phase": "ready"}

    def run_e2e(
        self,
        deployment: Mapping[str, Any],
        lifecycle: e2e.ProtectedLifecycleAPI,
        evidence_path: pathlib.Path,
        budgets: e2e.TimeoutBudgets,
    ) -> e2e.LiveRunResult:
        self._stage("e2e")
        evidence_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.failure in {"e2e-concurrent", "e2e-ambiguous", "e2e-concurrent-inexact"}:
            ambiguous = self.failure == "e2e-ambiguous"
            resolution = "ambiguous-ownership" if ambiguous else "competing-claim"
            evidence = {
                "schema": e2e.LIVE_EVIDENCE_SCHEMA,
                "kind": e2e.LIVE_EVIDENCE_KIND,
                "run_id": "fixture-run" if self.failure == "e2e-concurrent" else "other-run",
                "status": "failed",
                "failure": {
                    "phase": e2e.Phase.EVIDENCE.value if ambiguous else e2e.Phase.CONSUME_DEPLOYMENT.value,
                    "category": "AmbiguousOwnershipError" if ambiguous else "ConcurrentRunError",
                    "message": "durable E2E ownership blocks cleanup",
                },
                "lifecycle": {
                    "claimed": ambiguous,
                    "ownership_resolution": resolution,
                },
                "phases": [
                    {
                        "name": e2e.Phase.CLEANUP.value,
                        "status": "skipped",
                        "summary": {
                            "reason": "destructive cleanup suppressed by durable ownership resolution",
                            "ownership_resolution": resolution,
                        },
                    }
                ],
            }
            if ambiguous:
                evidence["run_id"] = "fixture-run"
            evidence_path.write_text(json.dumps(evidence) + "\n")
            return e2e.LiveRunResult(
                e2e.EXIT_ACCEPTANCE_FAILED,
                evidence_path,
                evidence,
                "durable E2E ownership blocks cleanup",
            )
        if self.failure == "e2e-persistence":
            evidence = {
                "schema": e2e.LIVE_EVIDENCE_SCHEMA,
                "kind": e2e.LIVE_EVIDENCE_KIND,
                "run_id": "fixture-run",
                "status": "failed",
                "failure": {
                    "phase": e2e.Phase.CONSUME_DEPLOYMENT.value,
                    "category": "ClaimPersistenceError",
                    "message": "durable E2E claim was not committed",
                },
                "lifecycle": {"ownership_resolution": "not-committed"},
                "phases": [
                    {
                        "name": e2e.Phase.CLEANUP.value,
                        "status": "skipped",
                        "summary": {"ownership_resolution": "not-committed"},
                    }
                ],
            }
            evidence_path.write_text(json.dumps(evidence) + "\n")
            return e2e.LiveRunResult(
                e2e.EXIT_ACCEPTANCE_FAILED,
                evidence_path,
                evidence,
                "durable E2E claim was not committed",
            )
        lifecycle.cleanup()
        if self.failure == "e2e":
            evidence_path.write_text('{"status":"failed"}\n')
            return e2e.LiveRunResult(
                e2e.EXIT_ACCEPTANCE_FAILED,
                evidence_path,
                {"status": "failed"},
                "injected E2E failure",
            )
        evidence_path.write_text('{"status":"passed"}\n')
        return e2e.LiveRunResult(e2e.EXIT_OK, evidence_path, {"status": "passed"})

    def cleanup(self) -> Mapping[str, Any]:
        self.calls.append("cleanup")
        self.cleanup_calls += 1
        if self.failure == "cleanup":
            raise e2e.LifecycleError("injected cleanup failure")
        return {"destroyed": True, "residual_audit": "clean"}


class RunAllCoordinatorTest(unittest.TestCase):
    class Contexts:
        def __init__(self) -> None:
            self.locks: list[pathlib.Path] = []
            self.active_timeouts: list[int] = []
            self.cleanup_timeouts: list[int] = []

        @contextlib.contextmanager
        def lock(self, path: pathlib.Path) -> Any:
            self.locks.append(path)
            yield

        @contextlib.contextmanager
        def timeout(self, seconds: int) -> Any:
            self.active_timeouts.append(seconds)
            yield

        @contextlib.contextmanager
        def cleanup_timeout(self, seconds: int) -> Any:
            self.cleanup_timeouts.append(seconds)
            yield

    def run_coordinator(
        self, temporary: str, failure: str | None = None
    ) -> tuple[e2e.RunAllResult, FakeRunAllOperations, "RunAllCoordinatorTest.Contexts"]:
        root = pathlib.Path(temporary).resolve()
        run_dir = root / "fixture-run"
        config = SimpleNamespace(
            run_id="fixture-run",
            architecture="amd64",
            artifact_manifest=(root / "artifacts" / "manifest.json").resolve(),
        )
        operations = FakeRunAllOperations(root, failure)
        contexts = self.Contexts()
        result = e2e.RunAllCoordinator(
            config=config,
            run_dir=run_dir,
            evidence_path=run_dir / "aws-two-region-e2e-evidence.json",
            lifecycle=FakeRunAllLifecycle(),
            operations=operations,
            hard_timeout_seconds=1200,
            readiness_timeout_seconds=300,
            lock_factory=contexts.lock,
            timeout_factory=contexts.timeout,
            cleanup_timeout_factory=contexts.cleanup_timeout,
        ).run()
        return result, operations, contexts

    def test_nested_cleanup_timer_rearms_the_paused_active_timer(self) -> None:
        alarms: list[int] = []
        current_alarm = 0
        handlers: dict[int, Any] = {
            e2e.signal.SIGALRM: "original-alarm-handler",
            e2e.signal.SIGTERM: "original-term-handler",
        }

        def alarm(seconds: int) -> int:
            nonlocal current_alarm
            previous = current_alarm
            current_alarm = seconds
            alarms.append(seconds)
            return previous

        def install(signum: int, handler: Any) -> Any:
            previous = handlers[signum]
            handlers[signum] = handler
            return previous

        with (
            mock.patch.object(e2e.signal, "alarm", side_effect=alarm),
            mock.patch.object(e2e.signal, "getsignal", side_effect=lambda signum: handlers[signum]),
            mock.patch.object(e2e.signal, "signal", side_effect=install),
            e2e.run_all_hard_timeout(120),
        ):
            self.assertEqual(current_alarm, 120)
            with e2e.cleanup_hard_timeout(30):
                self.assertEqual(current_alarm, 30)
            self.assertEqual(current_alarm, 120)

        self.assertEqual(current_alarm, 0)
        self.assertEqual(alarms, [0, 120, 0, 30, 0, 120, 0])

    def test_success_uses_one_lock_ordered_stages_and_exactly_one_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, operations, contexts = self.run_coordinator(temporary)

            self.assertEqual(result.exit_code, e2e.EXIT_OK)
            self.assertEqual(
                operations.calls,
                ["build", "preflight", "prepare", "plan", "apply", "wait", "e2e", "cleanup"],
            )
            self.assertEqual(operations.cleanup_calls, 1)
            self.assertEqual(contexts.locks, [pathlib.Path(temporary).resolve() / "fixture-run"])
            self.assertEqual(contexts.active_timeouts, [1200])
            self.assertEqual(contexts.cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])
            self.assertNotIn("whole_timeout_seconds", result.record)
            self.assertEqual([record["name"] for record in result.record["stages"]], list(e2e.RUN_ALL_STAGES))
            self.assertTrue(all(record["status"] == "passed" for record in result.record["stages"]))
            self.assertEqual(result.record["cleanup"], {
                "authorized": True,
                "attempted": True,
                "attempts": 1,
                "status": "passed",
            })
            self.assertEqual(
                result.record["artifacts"],
                {
                    "run_all_result": {"path": str(result.record_path), "exists": True},
                    "evidence": {"path": str(result.evidence_path), "exists": True},
                    "diagnostics": {
                        "path": str(pathlib.Path(temporary).resolve() / "fixture-run" / "diagnostics.json"),
                        "exists": False,
                    },
                },
            )
            self.assertEqual(json.loads(result.record_path.read_text()), result.record)
            self.assertEqual(stat.S_IMODE(result.record_path.stat().st_mode), 0o600)

    def test_each_stage_failure_has_deterministic_exit_and_cleanup_authority(self) -> None:
        cases = {
            "build": (e2e.RUN_ALL_STAGES[0], e2e.EXIT_CONTRACT_ERROR, 0),
            "preflight": (e2e.RUN_ALL_STAGES[1], e2e.EXIT_CONTRACT_ERROR, 0),
            "prepare": (e2e.RUN_ALL_STAGES[2], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "plan": (e2e.RUN_ALL_STAGES[3], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "apply": (e2e.RUN_ALL_STAGES[4], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "wait": (e2e.RUN_ALL_STAGES[5], e2e.EXIT_ACCEPTANCE_FAILED, 1),
            "e2e": (e2e.RUN_ALL_STAGES[6], e2e.EXIT_ACCEPTANCE_FAILED, 1),
        }
        operation_order = ["build", "preflight", "prepare", "plan", "apply", "wait", "e2e"]
        for failure, (stage, exit_code, cleanup_calls) in cases.items():
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, exit_code)
                self.assertEqual(result.record["failure"]["stage"], stage)
                self.assertEqual(next(value for value in result.record["stages"] if value["name"] == stage)["status"], "failed")
                self.assertEqual(operations.cleanup_calls, cleanup_calls)
                expected_calls = operation_order[: operation_order.index(failure) + 1]
                if cleanup_calls:
                    expected_calls.append("cleanup")
                self.assertEqual(operations.calls, expected_calls)
                self.assertEqual(result.record["cleanup"]["attempts"], cleanup_calls)
                self.assertEqual(
                    result.record["cleanup"]["status"],
                    "passed" if cleanup_calls else "skipped",
                )
                self.assertEqual(len(contexts.locks), 1)
                self.assertEqual(contexts.active_timeouts, [1200])
                self.assertEqual(
                    contexts.cleanup_timeouts,
                    [e2e.DEFAULT_TIMEOUTS.cleanup] if cleanup_calls else [],
                )
                diagnostics = result.record["artifacts"]["diagnostics"]
                self.assertEqual(diagnostics["exists"], failure == "wait")
                if failure == "wait":
                    self.assertIn(
                        {"kind": "diagnostics", **diagnostics},
                        result.record["failure"]["artifacts"],
                    )

    def test_timeout_and_signal_enter_reserved_cleanup_once(self) -> None:
        for failure, category in (("timeout", "TimeoutError"), ("signal", "InterruptedError")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.record["failure"]["stage"], e2e.RUN_ALL_STAGES[5])
                self.assertEqual(result.record["failure"]["category"], category)
                self.assertEqual(operations.cleanup_calls, 1)
                self.assertEqual(contexts.active_timeouts, [1200])
                self.assertEqual(contexts.cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])

    def test_concurrent_or_ambiguous_ownership_never_destroys_the_winner(self) -> None:
        cases = {
            "prepare-concurrent": (e2e.RUN_ALL_STAGES[2], "ConcurrentLifecycleError"),
            "e2e-concurrent": (e2e.RUN_ALL_STAGES[6], "ConcurrentRunError"),
            "e2e-ambiguous": (e2e.RUN_ALL_STAGES[6], "AmbiguousOwnershipError"),
        }
        for failure, (expected_stage, expected_category) in cases.items():
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.record["failure"]["stage"], expected_stage)
                self.assertEqual(result.record["failure"]["category"], expected_category)
                self.assertEqual(operations.cleanup_calls, 0)
                self.assertNotIn("cleanup", operations.calls)
                self.assertFalse(result.record["cleanup"]["authorized"])
                self.assertEqual(result.record["cleanup"]["attempts"], 0)
                self.assertEqual(result.record["cleanup"]["status"], "skipped")
                self.assertIn("ownership", result.record["cleanup"]["reason"])
                self.assertEqual(contexts.cleanup_timeouts, [])

    def test_nonblocking_or_inexact_inner_metadata_does_not_revoke_cleanup_authority(self) -> None:
        for failure in ("e2e-persistence", "e2e-concurrent-inexact"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, operations, contexts = self.run_coordinator(temporary, failure)

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(operations.cleanup_calls, 1)
                self.assertEqual(operations.calls[-1], "cleanup")
                self.assertTrue(result.record["cleanup"]["authorized"])
                self.assertEqual(result.record["cleanup"]["status"], "passed")
                self.assertEqual(contexts.cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup])

    def test_cleanup_failure_is_not_retried_and_overrides_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, operations, _contexts = self.run_coordinator(temporary, "cleanup")

            self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
            self.assertEqual(operations.cleanup_calls, 1)
            self.assertEqual(result.record["cleanup"]["attempts"], 1)
            self.assertEqual(result.record["cleanup"]["status"], "failed")
            self.assertEqual(result.record["failure"]["stage"], e2e.RUN_ALL_STAGES[-1])

    def test_build_command_uses_only_config_architecture_and_exact_manifest_parent(self) -> None:
        class RecordingRunner:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], pathlib.Path | None]] = []

            def run(
                self,
                args: list[str],
                *,
                env: dict[str, str] | None = None,
                cwd: pathlib.Path | None = None,
                input_text: str | None = None,
            ) -> str:
                self.calls.append((args, cwd))
                output = pathlib.Path(args[args.index("--output-dir") + 1])
                output.mkdir(parents=True)
                (output / "manifest.json").write_text("{}\n")
                (output / "envelope-linux-arm64").write_bytes(b"fixture")
                return "built fixture"

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            output = root / "artifacts"
            config = SimpleNamespace(architecture="arm64", artifact_manifest=output / "manifest.json")
            command_runner = RecordingRunner()
            operations = e2e.AwsRunAllOperations(
                config,
                SimpleNamespace(),
                command_runner,
                root / "run",
                ROOT / "example" / "terraform",
                SimpleNamespace(cleanup=lambda: {"complete": True}),
            )

            summary = operations.build()

            self.assertEqual(
                command_runner.calls,
                [
                    (
                        [
                            str(ROOT / "scripts" / "build_artifacts.sh"),
                            "--output-dir",
                            str(output),
                            "--architectures",
                            "arm64",
                        ],
                        ROOT,
                    )
                ],
            )
            self.assertNotIn("--allow-dirty", command_runner.calls[0][0])
            self.assertEqual(summary["manifest"], str(output / "manifest.json"))
            self.assertEqual(summary["architecture"], "arm64")

            bad_config = SimpleNamespace(architecture="arm64", artifact_manifest=output / "other.json")
            bad_operations = e2e.AwsRunAllOperations(
                bad_config,
                SimpleNamespace(),
                command_runner,
                root / "run",
                ROOT / "example" / "terraform",
                SimpleNamespace(cleanup=lambda: {"complete": True}),
            )
            with self.assertRaisesRegex(e2e.E2EError, "manifest.json"):
                bad_operations.build()
            self.assertEqual(len(command_runner.calls), 1)

    def test_preflight_rejects_an_unsupported_terraform_before_aws_preflight(self) -> None:
        class VersionRunner:
            def __init__(self, version: str) -> None:
                self.version = version
                self.calls: list[list[str]] = []

            def run(
                self,
                args: list[str],
                *,
                env: dict[str, str] | None = None,
                cwd: pathlib.Path | None = None,
                input_text: str | None = None,
            ) -> str:
                self.calls.append(args)
                if args != ["terraform", "version", "-json"]:
                    raise AssertionError(f"unexpected command: {args!r}")
                return json.dumps({"terraform_version": self.version})

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config = SimpleNamespace(architecture="amd64", artifact_manifest=root / "manifest.json")
            runner = VersionRunner("1.9.0")
            operations = e2e.AwsRunAllOperations(
                config,
                SimpleNamespace(),
                runner,
                root / "run",
                ROOT / "example" / "terraform",
                SimpleNamespace(cleanup=lambda: {"complete": True}),
            )

            with mock.patch.object(e2e, "run_preflight", side_effect=AssertionError("AWS preflight ran")):
                with self.assertRaisesRegex(e2e.E2EError, "requires Terraform 1.10.5; selected version is '1.9.0'"):
                    operations.preflight()

            self.assertEqual(runner.calls, [["terraform", "version", "-json"]])

    def test_run_all_cli_defaults_preserve_run_live_as_separate_entry_point(self) -> None:
        args = e2e.build_parser().parse_args(["run-all", "--config", "config.json"])
        self.assertEqual(args.subcommand, "run-all")
        self.assertEqual(args.hard_timeout_seconds, 5400)
        self.assertEqual(args.readiness_timeout_seconds, 900)
        live = e2e.build_parser().parse_args(
            ["run-live", "--config", "config.json", "--deployment", "deployment.json"]
        )
        self.assertEqual(live.subcommand, "run-live")

    def test_authorized_run_all_bootstrap_failures_write_only_a_minimal_private_record(self) -> None:
        approved = "fixture-run"
        trusted_environment = {
            "ENVELOPE_E2E_APPROVED_RUN_ID": approved,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
        }

        def config(run_id: str = approved, *, ttl_seconds: int = 10_000) -> Any:
            return SimpleNamespace(
                run_id=run_id,
                expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl_seconds))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                oauth_environment_names=(),
            )

        cases = {
            "config-load": (e2e.LifecycleError("raw-user-payload-must-not-be-retained"), []),
            "run-id-match": (config("another-run"), []),
            "ttl": (config(ttl_seconds=60), []),
            "timeout-arguments": (config(), ["--hard-timeout-seconds", "0"]),
            "readiness-timeout": (config(), ["--readiness-timeout-seconds", "6000"]),
            "evidence-path": (config(), ["--evidence", "OUTSIDE"]),
        }
        for expected_gate, (loaded, extra) in cases.items():
            with self.subTest(gate=expected_gate), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                run_root = root / "ignored-runs"
                selected_extra = [str(root / "outside" / "evidence.json") if value == "OUTSIDE" else value for value in extra]
                argv = [
                    "run-all",
                    "--config",
                    str(root / "operator-private-config.json"),
                    "--run-root",
                    str(run_root),
                    *selected_extra,
                ]
                load = mock.Mock(side_effect=loaded) if isinstance(loaded, BaseException) else mock.Mock(return_value=loaded)
                with (
                    mock.patch.object(e2e.RunConfig, "load", load),
                    mock.patch.dict(e2e.os.environ, trusted_environment, clear=True),
                    mock.patch.object(e2e, "SubprocessRunner", side_effect=AssertionError("resource authority acquired")),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = e2e.main(argv)

                self.assertEqual(exit_code, e2e.EXIT_CONTRACT_ERROR)
                load.assert_called_once_with(root / "operator-private-config.json", enforce_future_expiry=False)
                record_path = run_root / approved / "run-all-result.json"
                self.assertTrue(record_path.is_file())
                self.assertEqual(stat.S_IMODE(record_path.stat().st_mode), 0o600)
                record = json.loads(record_path.read_text())
                self.assertEqual(
                    set(record),
                    {
                        "schema",
                        "kind",
                        "run_id",
                        "status",
                        "exit_code",
                        "bootstrap",
                        "resource_authority",
                        "cleanup",
                        "failure",
                    },
                )
                self.assertEqual(record["run_id"], approved)
                self.assertEqual(record["status"], "failed")
                self.assertEqual(record["exit_code"], e2e.EXIT_CONTRACT_ERROR)
                self.assertTrue(record["bootstrap"])
                self.assertFalse(record["resource_authority"])
                self.assertEqual(
                    record["cleanup"],
                    {
                        "authorized": False,
                        "attempted": False,
                        "attempts": 0,
                        "status": "skipped",
                    },
                )
                gate = "timeout-arguments" if expected_gate == "readiness-timeout" else expected_gate
                self.assertEqual(record["failure"]["gate"], gate)
                self.assertEqual(record["failure"]["exit_code"], e2e.EXIT_CONTRACT_ERROR)
                serialized = json.dumps(record, sort_keys=True)
                self.assertNotIn("raw-user-payload", serialized)
                self.assertNotIn("another-run", serialized)
                self.assertNotIn("operator-private-config", serialized)
                self.assertNotIn(str(root / "outside"), serialized)
                self.assertFalse((run_root / "another-run").exists())

    def test_invalid_or_untrusted_run_all_approval_writes_no_bootstrap_artifact(self) -> None:
        environments = {
            "missing": {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            "invalid": {
                "ENVELOPE_E2E_APPROVED_RUN_ID": "../escape",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
            },
            "untrusted": {
                "ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-run",
                "GITHUB_EVENT_NAME": "pull_request",
            },
        }
        for name, environment in environments.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                run_root = pathlib.Path(temporary).resolve() / "ignored-runs"
                with (
                    mock.patch.dict(e2e.os.environ, environment, clear=True),
                    mock.patch.object(e2e.RunConfig, "load", side_effect=AssertionError("config was read")),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = e2e.main(
                        [
                            "run-all",
                            "--config",
                            "operator-private-config.json",
                            "--run-root",
                            str(run_root),
                        ]
                    )

                self.assertEqual(exit_code, e2e.EXIT_CONTRACT_ERROR)
                self.assertFalse(run_root.exists())

    def test_run_all_rejects_untrusted_context_before_credentials_or_build(self) -> None:
        args = e2e.build_parser().parse_args(["run-all", "--config", "config.json"])
        config = SimpleNamespace(run_id="fixture-run")
        environment = {
            "ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-run",
            "GITHUB_EVENT_NAME": "pull_request",
        }
        with (
            mock.patch.object(e2e.RunConfig, "load", return_value=config),
            mock.patch.dict(e2e.os.environ, environment, clear=True),
            mock.patch.object(e2e, "SubprocessRunner", side_effect=AssertionError("credentials constructed")),
            self.assertRaisesRegex(e2e.E2EError, "prohibited"),
        ):
            e2e._run_all_cli(args)


class ProtectedExecutionTest(unittest.TestCase):
    def protected_adapter(
        self, temporary: str
    ) -> tuple[dict[str, Any], DurableManifestStore, e2e.ProtectedLifecycleAdapter]:
        raw = protected_output()
        store = DurableManifestStore(ready_lifecycle_manifest(raw))
        adapter = object.__new__(e2e.ProtectedLifecycleAdapter)
        adapter.store = store
        adapter.config = SimpleNamespace(
            sites={"west": {"region": "us-west-2"}, "east": {"region": "us-east-1"}}
        )
        adapter.aws = SimpleNamespace()
        adapter.runner = SimpleNamespace()
        adapter.run_dir = pathlib.Path(temporary).resolve()
        adapter.terraform_dir = ROOT / "example" / "terraform"
        adapter.manifest = None
        adapter._ownership_state = "unclaimed"
        adapter._claim_etag = None
        adapter._claim_original_manifest = None
        adapter._claim_original_etag = None
        adapter._last_persistence_resolution = "none"
        adapter.verify_no_drift = lambda stage: {"clean": True, "stage": stage}
        return raw, store, adapter

    def run_adapter_failure(
        self,
        temporary: str,
        failure: str,
        *,
        cleanup_timeout: Any,
        recover_hook: Any = None,
    ) -> tuple[e2e.LiveRunResult, DurableManifestStore, e2e.ProtectedLifecycleAdapter, list[str]]:
        raw, store, adapter = self.protected_adapter(temporary)
        store.recover_hook = recover_hook
        protected_calls: list[str] = []

        def protected(*_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
            protected_calls.append("cleanup")
            self.assertEqual(store.value["phase"], "e2e_failed")
            self.assertFalse(store.value["e2e"]["passed"])
            return {"destroyed": True}

        bounded = e2e._BoundedCleanupLifecycleProxy(adapter, cleanup_timeout)
        with (
            mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
            mock.patch.object(e2e, "protected_cleanup", side_effect=protected),
        ):
            result = e2e.TwoRegionE2ERunner(
                run_id="fixture-live",
                raw_deployment=raw,
                site_regions={"west": "us-west-2", "east": "us-east-1"},
                lifecycle=bounded,
                operations=FakeLiveOperations(failure),
                evidence_path=pathlib.Path(temporary) / "evidence.json",
                monotonic=lambda: 0.0,
            ).run()
        return result, store, adapter, protected_calls

    def test_requires_exact_approval_and_rejects_untrusted_ci(self) -> None:
        with self.assertRaisesRegex(e2e.E2EError, "exactly match"):
            e2e.validate_protected_execution("fixture-live", {})
        with self.assertRaisesRegex(e2e.E2EError, "prohibited"):
            e2e.validate_protected_execution(
                "fixture-live",
                {"ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-live", "GITHUB_EVENT_NAME": "pull_request"},
            )
        e2e.validate_protected_execution(
            "fixture-live", {"ENVELOPE_E2E_APPROVED_RUN_ID": "fixture-live", "GITHUB_EVENT_NAME": "workflow_dispatch"}
        )

    def test_timeout_and_sigterm_atomically_handoff_only_the_owned_claim(self) -> None:
        cleanup_timeouts: list[int] = []

        @contextlib.contextmanager
        def cleanup_timeout(seconds: int) -> Any:
            cleanup_timeouts.append(seconds)
            yield

        for failure, category in (("acceptance-timeout", "TimeoutError"), ("active-interrupt", "InterruptedError")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                result, store, adapter, protected_calls = self.run_adapter_failure(
                    temporary,
                    failure,
                    cleanup_timeout=cleanup_timeout,
                )

                self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(protected_calls, ["cleanup"])
                self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])
                self.assertEqual(store.writes[1][1], '"fixture-etag-1"')
                self.assertEqual(adapter.manifest, store.value)
                self.assertEqual(store.value["phase"], "e2e_failed")
                self.assertEqual(
                    set(store.value["e2e"]),
                    {"claim_id", "output_sha256", "started_at", "finished_at", "passed"},
                )
                cleanup = next(
                    phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value
                )
                self.assertEqual(cleanup["summary"]["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
                self.assertTrue(cleanup["summary"]["e2e_claim_handoff"]["claim_identity_preserved"])

        self.assertEqual(cleanup_timeouts, [e2e.DEFAULT_TIMEOUTS.cleanup] * 2)

    def test_keyboard_interrupt_after_committed_claim_reserves_cleanup_and_redacts_write_error(self) -> None:
        sensitive = "private-provider-response-must-not-reach-evidence"
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            protected_calls: list[str] = []

            def commit_then_interrupt(
                target: DurableManifestStore, value: dict[str, Any], if_match: str | None
            ) -> None:
                target.commit(value, if_match)
                if value["phase"] == "e2e_running":
                    raise KeyboardInterrupt(sensitive)

            def protected(*_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
                protected_calls.append("cleanup")
                return {"destroyed": True}

            store.write_hook = commit_then_interrupt
            operations = FakeLiveOperations()
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", side_effect=protected),
            ):
                result = e2e.TwoRegionE2ERunner(
                    run_id="fixture-live",
                    raw_deployment=raw,
                    site_regions={"west": "us-west-2", "east": "us-east-1"},
                    lifecycle=adapter,
                    operations=operations,
                    evidence_path=pathlib.Path(temporary) / "evidence.json",
                    monotonic=lambda: 0.0,
                ).run()

        self.assertEqual(result.exit_code, e2e.EXIT_ACCEPTANCE_FAILED)
        self.assertEqual(result.evidence["failure"]["category"], "KeyboardInterrupt")
        self.assertNotIn(sensitive, json.dumps(result.evidence))
        self.assertEqual(result.evidence["diagnostics"]["collection"], "skipped")
        self.assertNotIn("diagnostics", operations.calls)
        self.assertEqual(protected_calls, ["cleanup"])
        self.assertEqual(store.value["phase"], "e2e_failed")

    def test_cleanup_handoff_rejects_changed_missing_claim_and_etag(self) -> None:
        @contextlib.contextmanager
        def cleanup_timeout(_seconds: int) -> Any:
            yield

        def mutation(kind: str) -> Any:
            def mutate(store: DurableManifestStore) -> None:
                if store.recover_count != 2:
                    return
                if kind == "changed-claim":
                    store.value["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                elif kind == "missing-claim":
                    store.value.pop("e2e")
                else:
                    store.remote_etag = '"another-writer-etag"'

            return mutate

        for kind, category, resolution, message in (
            (
                "changed-claim",
                "ConcurrentRunError",
                "competing-claim",
                "owned by another runner",
            ),
            (
                "missing-claim",
                "AmbiguousOwnershipError",
                "ambiguous-ownership",
                "ownership is ambiguous",
            ),
            (
                "changed-etag",
                "AmbiguousOwnershipError",
                "ambiguous-ownership",
                "ownership is ambiguous",
            ),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                result, store, adapter, protected_calls = self.run_adapter_failure(
                    temporary,
                    "acceptance-timeout",
                    cleanup_timeout=cleanup_timeout,
                    recover_hook=mutation(kind),
                )

                self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
                self.assertEqual(protected_calls, [])
                self.assertEqual(len(store.writes), 1)
                self.assertEqual(adapter.manifest["phase"], "e2e_running")
                cleanup = next(
                    phase for phase in result.evidence["phases"] if phase["name"] == e2e.Phase.CLEANUP.value
                )
                self.assertEqual(cleanup["status"], "failed")
                self.assertEqual(result.evidence["failure"]["category"], category)
                self.assertEqual(result.evidence["lifecycle"]["ownership_resolution"], resolution)
                self.assertIn(message, result.error or "")

    def test_cleanup_timeout_occurs_after_terminal_claim_handoff_without_retry(self) -> None:
        @contextlib.contextmanager
        def cleanup_timeout(_seconds: int) -> Any:
            yield
            raise TimeoutError("cleanup reservation expired")

        with tempfile.TemporaryDirectory() as temporary:
            result, store, adapter, protected_calls = self.run_adapter_failure(
                temporary,
                "acceptance-timeout",
                cleanup_timeout=cleanup_timeout,
            )

        self.assertEqual(result.exit_code, e2e.EXIT_CLEANUP_FAILED)
        self.assertEqual(protected_calls, ["cleanup"])
        self.assertEqual(store.value["phase"], "e2e_failed")
        self.assertEqual(adapter.manifest, store.value)
        self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])

    def test_normal_finish_remains_the_only_terminal_write_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            adapter.finish(False)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}),
            ):
                cleanup = adapter.cleanup()

        self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])
        self.assertEqual(store.recover_count, 2)
        self.assertNotIn("e2e_claim_handoff", cleanup)

    def test_claim_write_reconciliation_distinguishes_durable_outcomes(self) -> None:
        sensitive = "raw-provider-error-with-private-request-body"

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            store.write_hook = lambda *_args: (_ for _ in ()).throw(e2e.LifecycleError(sensitive))

            with self.assertRaises(e2e.ClaimPersistenceError) as raised:
                adapter.claim(raw, deployment)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "unclaimed")
            self.assertEqual(adapter._last_persistence_resolution, "claim-not-committed")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            store.write_hook = None
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                adapter.cleanup()
            cleanup.assert_called_once()

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)

            def commit_then_error(
                target: DurableManifestStore, value: dict[str, Any], if_match: str | None
            ) -> None:
                target.commit(value, if_match)
                raise e2e.LifecycleError(sensitive)

            store.write_hook = commit_then_error
            summary = adapter.claim(raw, deployment)

            self.assertEqual(summary["claim_persistence"], "recovered-owned-claim")
            self.assertEqual(adapter._ownership_state, "running-owned")
            self.assertEqual(adapter.manifest, store.value)
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)

            def lose_compare_and_swap(
                target: DurableManifestStore, value: dict[str, Any], _if_match: str | None
            ) -> None:
                competitor = copy.deepcopy(value)
                competitor["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                target.value = competitor
                target.remote_etag = '"competitor-etag"'
                raise e2e.LifecycleError(sensitive)

            store.write_hook = lose_compare_and_swap
            with self.assertRaises(e2e.ConcurrentRunError) as raised:
                adapter.claim(raw, deployment)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "competing")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.ConcurrentRunError),
            ):
                adapter.cleanup()
            cleanup.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            store.write_hook = lambda *_args: (_ for _ in ()).throw(e2e.LifecycleError(sensitive))

            def fail_recovery(target: DurableManifestStore) -> None:
                if target.recover_count > 1:
                    raise e2e.LifecycleError(sensitive)

            store.recover_hook = fail_recovery
            with self.assertRaises(e2e.AmbiguousOwnershipError) as raised:
                adapter.claim(raw, deployment)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "ambiguous")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.AmbiguousOwnershipError),
            ):
                adapter.cleanup()
            cleanup.assert_not_called()

    def test_committed_claim_interrupts_propagate_with_cleanup_authority(self) -> None:
        sensitive = "private-provider-response-must-not-reach-evidence"
        for write_error in (TimeoutError(sensitive), KeyboardInterrupt(sensitive)):
            with self.subTest(category=type(write_error).__name__), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)

                def commit_then_interrupt(
                    target: DurableManifestStore,
                    value: dict[str, Any],
                    if_match: str | None,
                    error: BaseException = write_error,
                ) -> None:
                    target.commit(value, if_match)
                    raise error

                store.write_hook = commit_then_interrupt
                with self.assertRaises(type(write_error)) as raised:
                    adapter.claim(raw, deployment)

                self.assertNotIn(sensitive, str(raised.exception))
                self.assertEqual(adapter._ownership_state, "running-owned")
                self.assertEqual(adapter.manifest, store.value)
                store.write_hook = None
                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
                ):
                    result = adapter.cleanup()

                cleanup.assert_called_once()
                self.assertEqual(result["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
                self.assertEqual(store.value["phase"], "e2e_failed")

    def test_interrupt_after_every_pending_claim_assignment_keeps_ready_cleanup_authorized(self) -> None:
        assignments = (
            "_claim_original_manifest",
            "_claim_original_etag",
            "_claim_etag",
            "_ownership_state",
            "manifest",
            "_last_persistence_resolution",
        )
        for index, field in enumerate(assignments):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)
                write_hook = mock.Mock(side_effect=AssertionError("store.write must not be entered"))
                store.write_hook = write_hook

                def interrupt_after_assignment(target: Any, name: str, value: Any) -> None:
                    object.__setattr__(target, name, value)
                    if target is adapter and name == field:
                        raise KeyboardInterrupt(f"interrupt after {field}")

                with (
                    mock.patch.object(
                        e2e.ProtectedLifecycleAdapter,
                        "__setattr__",
                        new=interrupt_after_assignment,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    adapter.claim(raw, deployment)

                write_hook.assert_not_called()
                self.assertEqual(
                    adapter._ownership_state,
                    "claim-pending" if index >= assignments.index("_ownership_state") else "unclaimed",
                )
                self.assertEqual(isinstance(adapter.manifest, dict), index >= assignments.index("manifest"))
                store.write_hook = None
                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
                ):
                    result = adapter.cleanup()

                cleanup.assert_called_once()
                self.assertTrue(cleanup.call_args.kwargs["recover"])
                self.assertEqual(adapter._ownership_state, "unclaimed")
                self.assertIsNone(adapter.manifest)
                self.assertIsNone(adapter._claim_etag)
                self.assertIsNone(adapter._claim_original_manifest)
                self.assertIsNone(adapter._claim_original_etag)
                self.assertNotIn("e2e_claim_handoff", result)
                self.assertEqual(store.writes, [])
                if index >= assignments.index("_ownership_state"):
                    self.assertEqual(adapter._last_persistence_resolution, "claim-not-committed")

    def test_pending_claim_without_candidate_suppresses_a_competitor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            write_hook = mock.Mock(side_effect=AssertionError("store.write must not be entered"))
            store.write_hook = write_hook

            def interrupt_after_pending_state(target: Any, name: str, value: Any) -> None:
                object.__setattr__(target, name, value)
                if target is adapter and name == "_ownership_state":
                    raise KeyboardInterrupt("interrupt before pending candidate assignment")

            with (
                mock.patch.object(
                    e2e.ProtectedLifecycleAdapter,
                    "__setattr__",
                    new=interrupt_after_pending_state,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                adapter.claim(raw, deployment)

            write_hook.assert_not_called()
            self.assertEqual(adapter._ownership_state, "claim-pending")
            self.assertIsNone(adapter.manifest)
            competitor = copy.deepcopy(store.value)
            competitor["phase"] = "e2e_running"
            competitor["e2e"] = {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "f" * 64,
                "started_at": "2026-08-20T12:00:00Z",
            }
            store.value = competitor
            store.remote_etag = '"competitor-etag"'
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.ConcurrentRunError),
            ):
                adapter.cleanup()

            cleanup.assert_not_called()
            self.assertEqual(adapter._ownership_state, "competing")
            self.assertIsNone(adapter._claim_original_manifest)
            self.assertIsNone(adapter._claim_original_etag)

    def test_interrupt_after_pending_candidate_assignment_reconciles_before_cleanup(self) -> None:
        for outcome in ("not-committed", "competing", "own-commit", "ambiguous"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)
                write_hook = mock.Mock(side_effect=AssertionError("store.write must not be entered"))
                store.write_hook = write_hook

                def interrupt_after_candidate_assignment(target: Any, name: str, value: Any) -> None:
                    object.__setattr__(target, name, value)
                    if target is adapter and name == "manifest":
                        raise KeyboardInterrupt("interrupt after pending candidate assignment")

                with (
                    mock.patch.object(
                        e2e.ProtectedLifecycleAdapter,
                        "__setattr__",
                        new=interrupt_after_candidate_assignment,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    adapter.claim(raw, deployment)

                write_hook.assert_not_called()
                self.assertEqual(adapter._ownership_state, "claim-pending")
                self.assertEqual(adapter._claim_original_manifest, store.value)
                self.assertEqual(adapter._claim_original_etag, store.remote_etag)
                candidate = copy.deepcopy(adapter.manifest)
                original_etag = adapter._claim_original_etag
                self.assertIsInstance(candidate, dict)
                self.assertIsInstance(original_etag, str)
                store.write_hook = None

                if outcome == "competing":
                    store.value = copy.deepcopy(candidate)
                    store.value["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                    store.remote_etag = '"competitor-etag"'
                elif outcome == "own-commit":
                    store.commit(candidate, original_etag)
                elif outcome == "ambiguous":
                    store.remote_etag = '"unexplained-etag"'

                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
                ):
                    if outcome == "competing":
                        with self.assertRaises(e2e.ConcurrentRunError):
                            adapter.cleanup()
                    elif outcome == "ambiguous":
                        with self.assertRaises(e2e.AmbiguousOwnershipError):
                            adapter.cleanup()
                    else:
                        result = adapter.cleanup()

                self.assertIsNone(adapter._claim_original_manifest)
                self.assertIsNone(adapter._claim_original_etag)
                if outcome == "not-committed":
                    cleanup.assert_called_once()
                    self.assertTrue(cleanup.call_args.kwargs["recover"])
                    self.assertEqual(adapter._ownership_state, "unclaimed")
                    self.assertEqual(adapter._last_persistence_resolution, "claim-not-committed")
                    self.assertIsNone(adapter.manifest)
                    self.assertNotIn("e2e_claim_handoff", result)
                    self.assertEqual(store.writes, [])
                elif outcome == "own-commit":
                    cleanup.assert_called_once()
                    self.assertTrue(cleanup.call_args.kwargs["recover"])
                    self.assertEqual(adapter._ownership_state, "terminal-owned")
                    self.assertEqual(result["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
                    self.assertEqual(
                        [value[0]["phase"] for value in store.writes],
                        ["e2e_running", "e2e_failed"],
                    )
                else:
                    cleanup.assert_not_called()
                    self.assertEqual(
                        adapter._ownership_state,
                        "competing" if outcome == "competing" else "ambiguous",
                    )

    def test_interrupt_after_claim_write_return_keeps_pending_candidate_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            committed = adapter._set_owned

            def interrupt_before_assignment(
                _manifest: Mapping[str, Any], _etag: str, *, terminal: bool
            ) -> None:
                self.assertFalse(terminal)
                raise KeyboardInterrupt("interrupt after store.write returned")

            with (
                mock.patch.object(adapter, "_set_owned", side_effect=interrupt_before_assignment),
                self.assertRaises(KeyboardInterrupt),
            ):
                adapter.claim(raw, deployment)

            self.assertEqual(adapter._ownership_state, "claim-pending")
            self.assertEqual(adapter.manifest, store.value)
            self.assertEqual(store.value["phase"], "e2e_running")
            self.assertIs(adapter._set_owned.__func__, committed.__func__)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                result = adapter.cleanup()

            cleanup.assert_called_once()
            self.assertEqual(result["e2e_claim_handoff"]["manifest_phase"], "e2e_failed")
            self.assertEqual(adapter._ownership_state, "terminal-owned")

    def test_finish_write_reconciliation_handles_commit_noncommit_and_ownership_change(self) -> None:
        sensitive = "private-finish-provider-response"

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)

            def commit_then_error(
                target: DurableManifestStore, value: dict[str, Any], if_match: str | None
            ) -> None:
                target.commit(value, if_match)
                raise e2e.LifecycleError(sensitive)

            store.write_hook = commit_then_error
            result = adapter.finish(False)
            self.assertEqual(result["result_persistence"], "recovered-owned-result")
            self.assertEqual(adapter._ownership_state, "terminal-owned")
            store.write_hook = None
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                adapter.cleanup()
            cleanup.assert_called_once()
            self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)

            def interrupt_before_terminal_assignment(
                _manifest: Mapping[str, Any], _etag: str, *, terminal: bool
            ) -> None:
                self.assertTrue(terminal)
                raise KeyboardInterrupt("interrupt after terminal write returned")

            with (
                mock.patch.object(adapter, "_set_owned", side_effect=interrupt_before_terminal_assignment),
                self.assertRaises(KeyboardInterrupt),
            ):
                adapter.finish(False)

            self.assertEqual(adapter._ownership_state, "terminal-pending")
            self.assertEqual(adapter.manifest, store.value)
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                adapter.cleanup()
            cleanup.assert_called_once()
            self.assertEqual([value[0]["phase"] for value in store.writes], ["e2e_running", "e2e_failed"])

        with tempfile.TemporaryDirectory() as temporary:
            raw, store, adapter = self.protected_adapter(temporary)
            deployment = e2e.parse_protected_deployment_output(raw)
            adapter.claim(raw, deployment)
            store.write_hook = lambda *_args: (_ for _ in ()).throw(e2e.LifecycleError(sensitive))

            with self.assertRaises(e2e.ClaimPersistenceError) as raised:
                adapter.finish(False)

            self.assertNotIn(sensitive, str(raised.exception))
            self.assertEqual(adapter._ownership_state, "running-owned")
            store.write_hook = None
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", return_value={"destroyed": True}) as cleanup,
            ):
                handoff = adapter.cleanup()
            cleanup.assert_called_once()
            self.assertEqual(handoff["e2e_claim_handoff"]["persistence"], "conditional-write")

        for ownership_change, expected in (
            ("competing", e2e.ConcurrentRunError),
            ("ambiguous", e2e.AmbiguousOwnershipError),
        ):
            with self.subTest(ownership_change=ownership_change), tempfile.TemporaryDirectory() as temporary:
                raw, store, adapter = self.protected_adapter(temporary)
                deployment = e2e.parse_protected_deployment_output(raw)
                adapter.claim(raw, deployment)

                def change_ownership(
                    target: DurableManifestStore,
                    _value: dict[str, Any],
                    _if_match: str | None,
                    mode: str = ownership_change,
                ) -> None:
                    if mode == "competing":
                        target.value["e2e"]["claim_id"] = "11111111-2222-4333-8444-555555555555"
                    else:
                        target.value["tailnet"]["key_generation"] = 2
                    target.remote_etag = '"changed-finish-etag"'
                    raise e2e.LifecycleError(sensitive)

                store.write_hook = change_ownership
                with self.assertRaises(expected) as raised:
                    adapter.finish(False)

                self.assertNotIn(sensitive, str(raised.exception))
                with (
                    mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                    mock.patch.object(e2e, "protected_cleanup") as cleanup,
                    self.assertRaises(expected),
                ):
                    adapter.cleanup()
                cleanup.assert_not_called()

    def test_late_competitor_is_still_rejected_by_protected_cleanup_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _raw, store, adapter = self.protected_adapter(temporary)
            store.value["phase"] = "e2e_running"
            store.value["e2e"] = {
                "claim_id": "11111111-2222-4333-8444-555555555555",
                "output_sha256": "f" * 64,
                "started_at": "2026-08-20T12:00:00Z",
            }
            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup") as cleanup,
                self.assertRaises(e2e.ConcurrentRunError),
            ):
                adapter.cleanup()
            cleanup.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            _raw, store, adapter = self.protected_adapter(temporary)

            def guarded_cleanup(*_args: Any, **kwargs: Any) -> Mapping[str, Any]:
                self.assertEqual(store.recover_count, 1)
                self.assertTrue(kwargs["recover"])
                competitor = copy.deepcopy(store.value)
                competitor["phase"] = "e2e_running"
                competitor["e2e"] = {
                    "claim_id": "11111111-2222-4333-8444-555555555555",
                    "output_sha256": "f" * 64,
                    "started_at": "2026-08-20T12:00:00Z",
                }
                store.value = competitor
                store.remote_etag = '"late-competitor-etag"'
                self.assertEqual(store.recover()["phase"], "e2e_running")
                self.assertEqual(store.recover_count, 2)
                raise e2e.ConcurrentLifecycleError("protected cleanup refused the active E2E claim")

            with (
                mock.patch.object(e2e, "build_tailscale", return_value=SimpleNamespace()),
                mock.patch.object(e2e, "protected_cleanup", side_effect=guarded_cleanup) as cleanup,
                self.assertRaises(e2e.ConcurrentLifecycleError),
            ):
                adapter.cleanup()

            cleanup.assert_called_once()
            self.assertEqual(store.value["phase"], "e2e_running")
            self.assertEqual(store.writes, [])

    def test_embedded_remote_agent_is_valid_python_and_bounded_for_ssm(self) -> None:
        compile(e2e.REMOTE_AGENT_SOURCE, "<remote-agent>", "exec")
        self.assertIn('stream.add_argument("--ready-path", required=True)', e2e.REMOTE_AGENT_SOURCE)
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", e2e.REMOTE_AGENT_SOURCE)
        compressed = gzip.compress(e2e.REMOTE_AGENT_SOURCE.encode("utf-8"), mtime=0)
        self.assertLess(len(base64.b64encode(compressed)), 12_000)
        compile(e2e.WIRE_INSPECTOR_SOURCE, "<wire-inspector>", "exec")
        wire_compressed = gzip.compress(e2e.WIRE_INSPECTOR_SOURCE.encode("utf-8"), mtime=0)
        self.assertLess(len(base64.b64encode(wire_compressed)), 12_000)

    def test_embedded_icmp_sender_preserves_every_payload_byte(self) -> None:
        namespace: dict[str, Any] = {"__name__": "remote_agent_fixture"}
        exec(e2e.REMOTE_AGENT_SOURCE, namespace)

        class FakeRawSocket:
            def __init__(self) -> None:
                self.packet = b""
                self.reply = b""

            def bind(self, _address: tuple[str, int]) -> None:
                pass

            def setsockopt(self, _level: int, _option: int, _value: int) -> None:
                pass

            def settimeout(self, _seconds: float) -> None:
                pass

            def sendto(self, packet: bytes, target: tuple[str, int]) -> None:
                self.packet = packet
                _request_type, _code, _checksum, identifier, sequence = struct.unpack("!BBHHH", packet[:8])
                payload = packet[8:]
                header = struct.pack("!BBHHH", 0, 0, 0, identifier, sequence)
                checksum = namespace["internet_checksum"](header + payload)
                response = struct.pack("!BBHHH", 0, 0, checksum, identifier, sequence) + payload
                ipv4 = bytearray(20)
                ipv4[0] = 0x45
                ipv4[9] = socket.IPPROTO_ICMP
                ipv4[12:16] = socket.inet_aton(target[0])
                ipv4[16:20] = socket.inet_aton("192.0.2.10")
                self.reply = bytes(ipv4) + response

            def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
                return self.reply, ("198.51.100.20", 0)

            def close(self) -> None:
                pass

        raw_socket = FakeRawSocket()
        namespace["socket"] = SimpleNamespace(
            AF_INET=socket.AF_INET,
            SOCK_RAW=socket.SOCK_RAW,
            IPPROTO_ICMP=socket.IPPROTO_ICMP,
            IPPROTO_IP=socket.IPPROTO_IP,
            timeout=socket.timeout,
            inet_ntoa=socket.inet_ntoa,
            socket=lambda *_args: raw_socket,
        )
        output = io.StringIO()
        args = SimpleNamespace(
            expect_timeout=False,
            flow_id="fixture-icmp",
            host="198.51.100.20",
            payload_bytes=1253,
            source_ip="192.0.2.10",
            timeout=1.0,
        )

        with contextlib.redirect_stdout(output):
            namespace["icmp_client"](args)

        result = json.loads(output.getvalue())
        self.assertTrue(result["reply_received"])
        self.assertEqual(raw_socket.packet[8:], b"\xa5" * 1253)
        self.assertEqual(namespace["internet_checksum"](raw_socket.packet), 0)

    def test_durable_claim_proves_load_thresholds_predate_apply(self) -> None:
        raw = protected_output()
        deployment = e2e.parse_protected_deployment_output(raw)

        class Store:
            remote_etag = "fixture-etag"

            def __init__(self, manifest: Mapping[str, Any]) -> None:
                self.value = copy.deepcopy(manifest)

            def recover(self) -> dict[str, Any]:
                return copy.deepcopy(self.value)

            def write(self, value: dict[str, Any], *, if_match: str | None = None) -> None:
                self.value = copy.deepcopy(value)

        def adapter(manifest: Mapping[str, Any]) -> e2e.ProtectedLifecycleAdapter:
            value = object.__new__(e2e.ProtectedLifecycleAdapter)
            value.store = Store(manifest)
            value.config = SimpleNamespace(
                sites={"west": {"region": "us-west-2"}, "east": {"region": "us-east-1"}}
            )
            value.manifest = None
            return value

        manifest = ready_lifecycle_manifest(raw)
        self.assertNotIn("apply_claimed_at", manifest)
        claim = adapter(manifest).claim(raw, deployment)
        self.assertTrue(claim["load_profile_approved_before_apply"])

        invalid_timestamps = {
            "missing": None,
            "malformed": "2026-13-20T11:00:00Z",
            "noncanonical": "2026-08-20T11:00:00+00:00",
        }
        for name, timestamp in invalid_timestamps.items():
            candidate = ready_lifecycle_manifest(raw)
            if timestamp is None:
                candidate["saved_plan"].pop("applied_at")
            else:
                candidate["saved_plan"]["applied_at"] = timestamp
            with self.subTest(name=name), self.assertRaisesRegex(e2e.LoadProfileError, "saved_plan.applied_at"):
                adapter(candidate).claim(raw, deployment)

        stale_claim = ready_lifecycle_manifest(raw)
        stale_claim["apply_claimed_at"] = "2026-08-20T11:00:00Z"
        with self.assertRaisesRegex(e2e.DeploymentError, "stale active apply claim"):
            adapter(stale_claim).claim(raw, deployment)

        post_apply_profile = protected_output()
        post_apply_profile["e2e_load_profile"]["value"]["approved_at"] = "2026-08-20T12:00:00Z"
        post_apply_deployment = e2e.parse_protected_deployment_output(post_apply_profile)
        with self.assertRaisesRegex(e2e.LoadProfileError, "before"):
            adapter(ready_lifecycle_manifest(post_apply_profile)).claim(post_apply_profile, post_apply_deployment)

        equal_profile = protected_output()
        equal_profile["e2e_load_profile"]["value"]["approved_at"] = "2026-08-20T11:00:00Z"
        equal_deployment = e2e.parse_protected_deployment_output(equal_profile)
        with self.assertRaisesRegex(e2e.LoadProfileError, "before"):
            adapter(ready_lifecycle_manifest(equal_profile)).claim(equal_profile, equal_deployment)


def unused_source_port(sock_type: int) -> int:
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_agent_server(protocol: str, messages: int) -> tuple[threading.Thread, int, queue.Queue[object]]:
    ready: queue.Queue[int] = queue.Queue(maxsize=1)
    completed: queue.Queue[object] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            completed.put(
                AGENT.serve(
                    protocol,
                    "127.0.0.1",
                    0,
                    timeout=3,
                    max_messages=messages,
                    ready=ready.put,
                )
            )
        except BaseException as error:
            completed.put(error)

    thread = threading.Thread(target=run, name=f"test-agent-{protocol}", daemon=True)
    thread.start()
    return thread, ready.get(timeout=1), completed


class WorkloadAgentProtocolTest(unittest.TestCase):
    def test_agent_typing_is_compatible_with_al2023_python(self) -> None:
        self.assertNotIn("TypeAlias", AGENT_PATH.read_text())

    def _server_result(self, thread: threading.Thread, completed: queue.Queue[object]) -> dict[str, Any]:
        result = completed.get(timeout=4)
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        if isinstance(result, BaseException):
            raise result
        self.assertIsInstance(result, dict)
        return result

    def test_tcp_stream_uses_one_socket_and_monotonic_markers(self) -> None:
        thread, port, completed = start_agent_server("tcp", 4)
        source_port = unused_source_port(socket.SOCK_STREAM)

        result = AGENT.stream(
            "tcp",
            "127.0.0.1",
            port,
            source_ip="127.0.0.1",
            source_port=source_port,
            flow_id="fixture-tcp-0001",
            count=4,
            interval=0.002,
            timeout=2,
        )
        server = self._server_result(thread, completed)

        self.assertEqual(result["socket_count"], 1)
        self.assertEqual(result["source_port"], source_port)
        self.assertEqual([value["sequence"] for value in result["markers"]], [0, 1, 2, 3])
        self.assertEqual(len({value["connection_id"] for value in result["markers"]}), 1)
        self.assertEqual(server["connections"], 1)
        self.assertEqual(server["messages"], 4)
        e2e_markers = [e2e.StreamMarker.from_value(value) for value in result["markers"]]
        self.assertTrue(
            all(
                current.received_monotonic_ns < following.received_monotonic_ns
                for current, following in zip(e2e_markers, e2e_markers[1:])
            )
        )

    def test_udp_probe_honors_source_bind_and_flow_identity(self) -> None:
        thread, port, completed = start_agent_server("udp", 1)
        source_port = unused_source_port(socket.SOCK_DGRAM)

        result = AGENT.probe(
            "udp",
            "127.0.0.1",
            port,
            source_ip="127.0.0.1",
            source_port=source_port,
            flow_id="fixture-udp-0001",
            timeout=2,
        )
        server = self._server_result(thread, completed)

        self.assertTrue(result["success"])
        self.assertEqual(result["source_port"], source_port)
        self.assertEqual(result["flow_id"], "fixture-udp-0001")
        self.assertEqual(server["flow_ids"], ["fixture-udp-0001"])
        self.assertEqual(server["messages"], 1)

    def test_agent_rejects_invalid_flow_ids_without_opening_a_socket(self) -> None:
        with self.assertRaisesRegex(AGENT.AgentError, "flow_id"):
            AGENT.probe(
                "tcp",
                "127.0.0.1",
                1,
                source_ip="127.0.0.1",
                source_port=0,
                flow_id="not a valid flow",
                timeout=1,
            )


if __name__ == "__main__":
    unittest.main()
