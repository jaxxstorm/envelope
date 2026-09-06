"""Versioned process/ownership and live-only evidence contracts.

No deployment credentials, Terraform state, or runtime mechanism is accepted by
the measured process. This module is also usable offline by evidence auditors.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import os
import pathlib
import re
from collections.abc import Mapping
from typing import Any

import aws_production_controller_e2e as legacy

Error = legacy.ContractError
SCHEMA = 3
KIND = "aws-production-controller-live"
LIVE_STAGES = (
    "active-baseline", "lease-renewal", "router-failover", "leader-handoff",
    "durable-alternate", "failback-gate", "failback-stable",
)
INTEGRATION_TESTS = {
    "observer-disagreement": "TestConformanceObserverDisagreement",
    "stale-fence-rejection": "TestConformanceRejectsPausedStaleOperationAfterTakeover",
    "ambiguous-response": "TestConformanceAmbiguousAPIAfterCommitSettlesWithoutReplay",
    "crash-checkpoints": "TestConformanceLeadershipFencingAndCrashRecovery",
}
PHASE_ENVIRONMENTS = {
    "deploy": "envelope-controller-deployment",
    "observe": "envelope-controller-observation",
    "quiesce": "envelope-controller-quiescence",
    "cleanup": "envelope-controller-cleanup",
}
SHA = re.compile(r"[0-9a-f]{64}")
ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]+)")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Error(reason)


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    result = legacy._mapping(value, label)
    legacy._exact_keys(result, keys, label)
    return result


def digest(value: Any) -> str:
    return legacy.canonical_sha256(value)


def timestamp(value: Any) -> dt.datetime:
    return legacy.parse_runtime_timestamp(value, "bounded UTC timestamp")


def execution_context(environment: Mapping[str, str] = os.environ) -> dict[str, str]:
    result = {
        "repository": environment.get("GITHUB_REPOSITORY", ""),
        "ref": environment.get("GITHUB_REF", ""),
        "revision": environment.get("GITHUB_SHA", ""),
        "workflow_run_id": environment.get("GITHUB_RUN_ID", ""),
        "attempt": environment.get("GITHUB_RUN_ATTEMPT", ""),
    }
    require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", result["repository"])), "invalid protected repository")
    require(result["ref"].startswith("refs/heads/") and ":" not in result["ref"], "invalid protected ref")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", result["revision"])), "invalid protected revision")
    require(all(re.fullmatch(r"[1-9][0-9]*", result[k]) for k in ("workflow_run_id", "attempt")), "invalid workflow invocation")
    return result


def subject(context: Mapping[str, str], phase: str, *, wildcard: bool = False) -> str:
    require(phase in PHASE_ENVIRONMENTS, "invalid credential phase")
    run = "*" if wildcard else context["workflow_run_id"]
    attempt = "*" if wildcard else context["attempt"]
    return (
        f"repo:{context['repository']}:environment:{PHASE_ENVIRONMENTS[phase]}:"
        f"workflow_ref:{context['repository']}/.github/workflows/aws-two-region-e2e-live.yml@{context['ref']}:"
        f"run_id:{run}:run_attempt:{attempt}"
    )


def validate_reference(value: Any, label: str) -> dict[str, Any]:
    ref = exact(value, {"bucket", "key", "region", "version_id", "sha256"}, label)
    for name in ref:
        legacy._string(ref[name], f"{label} {name}")
    require(bool(SHA.fullmatch(ref["sha256"])) and ref["version_id"] != "null", "unversioned or unhashed object")
    require(".." not in ref["key"] and not ref["key"].startswith("/") and not any(c in ref["key"] for c in "*?"), "unsafe object authority")
    return ref


def validate_handoff(value: Any, *, now: dt.datetime | None = None, context: Mapping[str, str] | None = None) -> dict[str, Any]:
    h = exact(value, {
        "schema", "kind", "run_id", "invocation_id", "context", "issued_at", "expires_at",
        "claim", "claim_body", "configuration_sha256", "topology", "topology_identity",
        "actors", "workloads", "controller", "router_nodes", "attestation_trust",
        "dependencies", "roles", "revocation", "private_state", "evidence_store", "authority_kms_key_arn", "observer_issuance_until", "observer_sessions_until",
    }, "acceptance handoff")
    require(h["schema"] == 1 and h["kind"] == "production-controller-handoff", "unsupported handoff schema")
    legacy._string(h["run_id"], "run ID", pattern=legacy._RUN_RE)
    legacy._string(h["invocation_id"], "invocation", pattern=SHA)
    legacy._string(h["configuration_sha256"], "configuration hash", pattern=SHA)
    ctx = exact(h["context"], {"repository", "ref", "revision", "workflow_run_id", "attempt"}, "handoff invocation")
    require(context is None or ctx == dict(context), "handoff belongs to another workflow invocation")
    issued, expires = timestamp(h["issued_at"]), timestamp(h["expires_at"])
    require(issued < expires and (expires - issued).total_seconds() <= 86400, "handoff lifetime is invalid")
    require(issued < timestamp(h["observer_issuance_until"]) <= issued + dt.timedelta(minutes=15) and timestamp(h["observer_sessions_until"]) == timestamp(h["observer_issuance_until"]) + dt.timedelta(hours=1) and timestamp(h["observer_sessions_until"]) < expires, "observer credential drain bound is invalid")
    if now is not None:
        require(issued <= now < expires, "handoff is future-dated or expired")
    claim = validate_reference(h["claim"], "claim")
    require(claim["key"] == f"runs/{h['run_id']}/production-controller-run.claim.json", "claim key is not run-owned")
    body = exact(h["claim_body"], {"schema", "kind", "run_id", "configuration_sha256", "principal_arn_sha256", "invocation_id_sha256", "created_at", "nonce_sha256"}, "claim body")
    require(body["schema"] == 1 and body["kind"] == "aws-production-controller-run-claim" and body["run_id"] == h["run_id"] and body["configuration_sha256"] == h["configuration_sha256"] and body["invocation_id_sha256"] == legacy.hash_identity(h["invocation_id"]), "claim ownership differs from handoff")
    require(digest(body) == claim["sha256"], "claim body hash differs")
    topology = legacy._mapping(h["topology"], "topology")
    identity = legacy.validate_topology_identity(h["topology_identity"], topology)
    require(topology["deployment_id"] == h["run_id"], "topology deployment differs")
    controller = exact(h["controller"], {"region", "vpc_id", "controller_ids", "metrics_port", "policy_seconds", "timeouts", "instances"}, "controller authority")
    require(controller["controller_ids"] == topology["controller_ids"] and controller["region"] == topology["dynamodb"]["region"], "controller scope differs from topology")
    require(set(controller["instances"]) == set(controller["controller_ids"]), "controller instance set differs")
    expected_policy = {k: legacy.parse_duration(v, k) for k, v in topology["policy"].items() if k not in {"replica_count", "observation_quorum"}}
    require(controller["policy_seconds"] == expected_policy, "handoff timing differs from topology")
    legacy._integer(controller["metrics_port"], "metrics port", 1024, 65535)
    for name in ("readiness_seconds", "transition_seconds", "cleanup_seconds"):
        legacy._integer(controller["timeouts"][name], name, 30, 7200)
    require(isinstance(h["actors"], list) and h["actors"], "actor authority is absent")
    stripped = []
    actor_ids = set()
    for actor in h["actors"]:
        a = exact(actor, {"actor_type", "actor_id", "instance_id", "region", "vpc_id", "subnet_id", "availability_zone", "private_ip", "expected_tags"}, "actor")
        require(a["actor_id"] not in actor_ids, "duplicate actor ID")
        actor_ids.add(a["actor_id"])
        require(a["expected_tags"].get("EnvelopeRun") == h["run_id"] and a["expected_tags"].get("EnvelopeInvocation") == h["invocation_id"], "actor lacks exact invocation ownership")
        expected_role = {"controller": "envelope-controller", "router": "transport-router"}.get(a["actor_type"], a["actor_id"].split("-", 1)[-1])
        require(a["expected_tags"].get("Role") == expected_role and all(isinstance(k, str) and isinstance(v, str) and len(v) <= 256 for k, v in a["expected_tags"].items()), "actor role ownership is invalid")
        stripped.append({k: v for k, v in a.items() if k != "expected_tags"})
    legacy.validate_actor_summary({"instances": stripped})
    by_id = {a["actor_id"]: a for a in h["actors"]}
    routers = {r["id"]: r for r in topology["routers"]}
    require(set(h["router_nodes"]) == set(routers), "router node authority differs")
    for rid, router in routers.items():
        require(rid in by_id and by_id[rid]["actor_type"] == "router", "router actor absent")
        require(all(by_id[rid][k] == router[k] for k in ("instance_id", "region", "vpc_id", "subnet_id", "availability_zone")), "router actor identity differs")
        require(h["router_nodes"][rid]["stable_node_id"] == router["stable_node_id"], "stable router identity differs")
    for cid, instance in controller["instances"].items():
        require(cid in by_id and by_id[cid]["actor_type"] == "controller", "controller actor absent")
        require(all(by_id[cid][k] == instance[k] for k in ("instance_id", "private_ip", "subnet_id", "availability_zone")), "controller actor identity differs")
    for site, workloads in h["workloads"].items():
        require(set(workloads) == {"initiator", "responder"}, "workload roles differ")
        for role, workload in workloads.items():
            actor = by_id.get(f"{site}-{role}", {})
            require(actor.get("actor_type") == "workload" and all(actor.get(k) == workload[k] for k in ("instance_id", "private_ip", "vpc_id", "subnet_id", "availability_zone", "region")), "workload ownership differs")
    trust = exact(h["attestation_trust"], {"schema_version", "deployment_id", "topology_hash", "routers"}, "attestation trust")
    require(trust["schema_version"] == 1 and trust["deployment_id"] == h["run_id"] and trust["topology_hash"] == identity["canonical_sha256"] and {r["router_id"] for r in trust["routers"]} == set(routers), "attestor authority differs")
    keys = []
    for item in trust["routers"]:
        row = exact(item, {"router_id", "ed25519_public_key", "configuration_sha256", "url"}, "attestor")
        require(bool(SHA.fullmatch(row["ed25519_public_key"])) and bool(SHA.fullmatch(row["configuration_sha256"])) and row["url"].startswith("https://"), "invalid enrolled attestor")
        keys.append(row["ed25519_public_key"])
    require(len(set(keys)) == len(keys) == len(routers), "shared attestor key")
    deps = exact(h["dependencies"], {"artifacts", "lifecycle", "enrollment_verified"}, "production dependencies")
    require(deps["enrollment_verified"] is True, "enrollment was not verified by production readiness")
    require({x["component"] for x in deps["artifacts"]} == {"envelope", "envelope-controller", "envelope-controller-topology", "envelope-controller-deploy", "envelope-router-attestor"}, "production artifacts missing")
    for artifact in deps["artifacts"]:
        require(artifact["revision"] == ctx["revision"] and artifact["source_dirty"] is False and bool(SHA.fullmatch(artifact["sha256"])), "unreviewed production dependency")
    lifecycle = deps["lifecycle"]
    require([x["operation"] for x in lifecycle] == ["initialize"] * len(topology["domains"]) + ["rollout"] * 3 + ["activate"] * len(topology["domains"]), "production lifecycle ordering is incomplete")
    require(all(x["complete"] is True and bool(SHA.fullmatch(x["receipt_sha256"])) for x in lifecycle), "production lifecycle receipt is incomplete")
    roles = exact(h["roles"], {"observe", "quiesce", "cleanup"}, "phase roles")
    for phase, role in roles.items():
        exact(role, {"arn", "subject", "policy_sha256"}, "phase role")
        require(bool(ROLE.fullmatch(role["arn"])) and role["subject"] == subject(ctx, phase) and bool(SHA.fullmatch(role["policy_sha256"])), "phase role is not invocation-bound")
        if phase in {"observe", "quiesce"}:
            require(role["arn"].endswith(f"/{h['run_id']}-{h['invocation_id'][:12]}-{phase}"), "narrow role name belongs to another invocation")
    rev = exact(h["revocation"], {"role_arn", "lifecycle_role_arn", "subject", "cutoff", "policy_name", "trust_sid", "session_arn", "session_expires_at"}, "deployment revocation")
    require(bool(ROLE.fullmatch(rev["lifecycle_role_arn"])), "lifecycle role is not explicit")
    require(bool(ROLE.fullmatch(rev["role_arn"])) and rev["subject"] == subject(ctx, "deploy") and timestamp(rev["cutoff"]) >= timestamp(body["created_at"]), "invalid deployment revocation boundary")
    require(body["principal_arn_sha256"] == legacy.hash_identity(rev["session_arn"]), "claim publisher differs from deployment session")
    require(len({rev["role_arn"], *(r["arn"] for r in roles.values())}) == 4, "credential identities overlap")
    private = validate_reference(h["private_state"], "private recovery state")
    require(private["key"].startswith(f"runs/{h['run_id']}/private/{h['invocation_id']}/"), "private recovery state is not invocation-owned")
    exact(h["evidence_store"], {"bucket", "region", "prefix"}, "evidence store")
    require(h["evidence_store"]["prefix"] == f"runs/{h['run_id']}/evidence/{h['invocation_id']}/", "evidence namespace differs")
    return h


def validate_integration(value: Any, revision: str) -> dict[str, Any]:
    result = exact(value, {"schema", "kind", "revision", "package", "results", "output_sha256"}, "integration evidence")
    require(result["schema"] == 1 and result["kind"] == "controller-integration-simulation" and result["revision"] == revision and result["package"] == "github.com/jaxxstorm/envelope/internal/controller/integration", "integration evidence provenance differs")
    require(result["results"] == {name: {"test": test, "result": "pass", "scope": "integration-only"} for name, test in INTEGRATION_TESTS.items()}, "deterministic coverage is missing or labeled live")
    require(bool(SHA.fullmatch(result["output_sha256"])), "integration output digest absent")
    return result


def record_integration(payload: bytes, revision: str) -> dict[str, Any]:
    require(len(payload) <= 16 * 1024 * 1024, "integration output is unbounded")
    events = [legacy.strict_json_loads(line) for line in payload.splitlines() if line]
    package = "github.com/jaxxstorm/envelope/internal/controller/integration"
    require(not any(e.get("Action") == "fail" for e in events), "integration run failed")
    require(any(e.get("Package") == package and "Test" not in e and e.get("Action") == "pass" for e in events), "integration package did not complete")
    for test in INTEGRATION_TESTS.values():
        require(any(e.get("Package") == package and e.get("Test") == test and e.get("Action") == "pass" for e in events), "required integration test did not pass")
    return {"schema": 1, "kind": "controller-integration-simulation", "revision": revision, "package": package, "results": {name: {"test": test, "result": "pass", "scope": "integration-only"} for name, test in INTEGRATION_TESTS.items()}, "output_sha256": hashlib.sha256(payload).hexdigest()}


def validate_live_evidence(value: Any, handoff: Any, *, passing: bool = False) -> dict[str, Any]:
    h = validate_handoff(handoff)
    e = exact(value, {"schema", "kind", "run_id", "invocation_id", "handoff_sha256", "status", "started_at", "completed_at", "credential", "selection", "faults", "observations", "fresh_flows", "established_flows", "mutation_audit", "failure", "restoration"}, "live evidence")
    require(e["schema"] == SCHEMA and e["kind"] == KIND and e["run_id"] == h["run_id"] and e["invocation_id"] == h["invocation_id"] and e["handoff_sha256"] == digest(h), "live evidence identity differs")
    require(e["status"] in {"passed", "failed"}, "invalid live outcome")
    require(timestamp(h["issued_at"]) <= timestamp(e["started_at"]) <= timestamp(e["completed_at"]), "live window is reordered")
    credential = exact(e["credential"], {"role_arn", "principal_arn_sha256", "expires_at", "subject_sha256"}, "measured credential")
    require(credential["role_arn"] == h["roles"]["observe"]["arn"] and credential["subject_sha256"] == legacy.hash_identity(h["roles"]["observe"]["subject"]), "wrong observation credentials")
    account, role_name = ROLE.fullmatch(credential["role_arn"]).groups()
    principal = f"arn:aws:sts::{account}:assumed-role/{role_name.rsplit('/', 1)[-1]}/envelope-observe-{h['context']['workflow_run_id']}-{h['context']['attempt']}"
    require(credential["principal_arn_sha256"] == legacy.hash_identity(principal), "measured session principal differs from invocation")
    require(isinstance(e["observations"], list) and len(e["observations"]) <= 4096, "unbounded live observations")
    domains = {d["id"]: d for d in h["topology"]["domains"]}
    routers = {r["id"]: r for r in h["topology"]["routers"]}
    for wrapped in e["observations"]:
        w = exact(wrapped, {"scope", "activated", "item_sha256", "observation", "instance_states"}, "live observation")
        require(set(w["instance_states"]) == {a["actor_id"] for a in h["actors"] if a["actor_type"] in {"router", "controller"}} and all(state in {"pending", "running", "stopping", "stopped"} for state in w["instance_states"].values()), "live instance state coverage differs")
        require(w["scope"] == "live" and isinstance(w["activated"], bool) and bool(SHA.fullmatch(w["item_sha256"])), "observation is not live durable evidence")
        o = legacy.validate_observation(w["observation"])
        require(o["stage"] in LIVE_STAGES and o["domain_id"] in domains, "simulated stage or unknown domain in live evidence")
        d = domains[o["domain_id"]]
        table = o["aws_route_table"]
        require(all(table[k] == d[k] for k in ("route_table_id", "gwlbe_subnet_id", "route_table_association_id")), "live route authority differs")
        require({r["destination_prefix"] for r in o["aws_routes"]} == set(d["remote_prefixes"]), "live route set differs")
        for route in o["aws_routes"]:
            router = routers.get(route["target_router_id"], {})
            require(router.get("eni_id") == route["target_eni_id"] and router.get("site_id") == d["site_id"] and route["state"] == "active" and route["origin"] == "CreateRoute", "live route escaped eligible owner scope")
        for endpoint in o["controller_endpoints"]:
            instance = h["controller"]["instances"].get(endpoint["controller_id"], {})
            require(endpoint["instance_id"] == instance.get("instance_id") and endpoint["private_ip"] == instance.get("private_ip"), "controller endpoint ownership differs")
        if o["tailnet"]["agreement"]:
            owner = routers.get(o["tailnet"]["owner_router_id"], {})
            require(owner.get("site_id") == d["site_id"] and o["tailnet"]["owner_node_sha256"] == legacy.hash_identity(owner["stable_node_id"]), "native owner stable identity differs")
            contributors = o["tailnet"]["contributors"]
            require(len({c["controller_id"] for c in contributors}) == len(contributors) and all(c["controller_id"] in h["controller"]["controller_ids"] for c in contributors), "duplicate or unconfigured observer votes")
            fresh = [c for c in contributors if c["fresh"] and c["backend_healthy"] and c["sole_primary"] and c["owner_healthy"] and c["owner_node_sha256"] == o["tailnet"]["owner_node_sha256"] and timestamp(c["captured_at"]) <= timestamp(o["captured_at"]) < timestamp(c["expires_at"]) and (timestamp(o["captured_at"]) - timestamp(c["captured_at"])).total_seconds() < h["controller"]["policy_seconds"]["observation_freshness"]]
            require(len(fresh) >= h["topology"]["policy"]["observation_quorum"], "claimed live quorum is stale or unauthenticated")
        require(timestamp(e["started_at"]) <= timestamp(o["captured_at"]) <= timestamp(e["completed_at"]), "observation outside measurement")
    for flow in e["fresh_flows"]:
        legacy.validate_flow(flow)
        actors = {a["actor_id"]: a for a in h["actors"] if a["actor_type"] == "workload"}
        require(flow["source_instance_id"] == actors.get(flow["source_workload"], {}).get("instance_id") and flow["destination_instance_id"] == actors.get(flow["destination_workload"], {}).get("instance_id"), "flow actor escaped handoff scope")
    for flow in e["established_flows"]:
        legacy.validate_established_flow(flow)
    audit = e["mutation_audit"]
    require(audit["runner_identity"]["principal_arn_sha256"] == credential["principal_arn_sha256"], "mutation audit came from another principal")
    require(audit["route_mutation_calls"] == 0 and audit["advertisement_mutation_calls"] == 0 and audit["denied_attempts"] == [] and audit["remote_execution"]["target_calls"] == 0 and audit["remote_execution"]["router_calls"] == 0, "measurement attempted a prohibited mutation")
    if passing or e["status"] == "passed":
        require(timestamp(e["completed_at"]) < timestamp(h["expires_at"]) and timestamp(credential["expires_at"]) > timestamp(e["completed_at"]), "passing measurement used expired authority")
        require(e["status"] == "passed" and e["failure"] is None and e["restoration"]["complete"] is True, "live acceptance did not finish safely")
        selection = exact(e["selection"], {"domain_id", "router_id", "alternate_router_id"}, "selection")
        require(selection["domain_id"] in domains and selection["router_id"] == domains[selection["domain_id"]]["preferred_owner"] and selection["alternate_router_id"] in routers, "invalid live selection")
        selected: dict[str, dict[str, Any]] = {}
        previous = timestamp(e["started_at"])
        for stage in LIVE_STAGES:
            rows = [w for w in e["observations"] if w["observation"]["stage"] == stage]
            require(len(rows) == len(domains) and {w["observation"]["domain_id"] for w in rows} == set(domains), "live stage omitted domains")
            require(all(w["activated"] for w in rows), "live controller was not activated")
            current = next(w["observation"] for w in rows if w["observation"]["domain_id"] == selection["domain_id"])
            require(timestamp(current["captured_at"]) >= previous, "live stages are reordered")
            previous = timestamp(current["captured_at"])
            selected[stage] = current
            require(current["tailnet"]["observer_quorum"] >= h["topology"]["policy"]["observation_quorum"] and current["tailnet"]["agreement"] is True, "live stage lacks owner quorum")
            if stage != "failback-gate":
                require(current["route_agreement"] is True and current["dynamodb"]["phase"] == "stable", "live stage lacks stable route agreement")
        baseline, renewal = selected["active-baseline"]["dynamodb"], selected["lease-renewal"]["dynamodb"]
        require(renewal["lease_holder"] == baseline["lease_holder"] and renewal["fence_term"] == baseline["fence_term"] and renewal["lease_record_version"] > baseline["lease_record_version"], "lease renewal was not demonstrated")
        faults = exact(e["faults"], {"router", "leader"}, "live faults")
        router_fault, leader_fault = faults["router"], faults["leader"]
        exact(router_fault, {"domain_id", "router_id", "alternate_router_id", "instance_id", "injected_at", "restored_at", "method"}, "router fault")
        exact(leader_fault, {"domain_id", "previous_controller_id", "new_controller_id", "instance_id", "previous_fence", "new_fence", "injected_at", "restored_at", "method", "checkpoint_phase"}, "leader fault")
        require(router_fault["method"] == "ec2-stop-instance" and router_fault["instance_id"] == routers[selection["router_id"]]["instance_id"], "router fault differs from owner")
        require(timestamp(router_fault["injected_at"]) >= timestamp(selected["lease-renewal"]["captured_at"]), "router failed before baseline")
        require(timestamp(router_fault["injected_at"]) <= timestamp(selected["router-failover"]["captured_at"]) <= timestamp(leader_fault["injected_at"]) <= timestamp(selected["leader-handoff"]["captured_at"]), "fault and handoff ordering differs")
        require(timestamp(leader_fault["restored_at"]) <= timestamp(e["completed_at"]) and timestamp(router_fault["restored_at"]) <= timestamp(selected["failback-gate"]["captured_at"]), "real fault recovery is absent")
        require(timestamp(selected["durable-alternate"]["captured_at"]) <= timestamp(router_fault["restored_at"]), "router recovered before alternate retention was measured")
        for stage in ("router-failover", "leader-handoff", "durable-alternate"):
            require(selected[stage]["dynamodb"]["stable_owner"] == selection["alternate_router_id"], "alternate was not retained")
        require(leader_fault["method"] == "ec2-stop-instance" and leader_fault["checkpoint_phase"] == "stable", "live evidence claimed a deterministic crash barrier")
        require(leader_fault["instance_id"] == h["controller"]["instances"][leader_fault["previous_controller_id"]]["instance_id"], "leader fault actor differs")
        stopped = next(w for w in e["observations"] if w["observation"]["stage"] == "leader-handoff" and w["observation"]["domain_id"] == selection["domain_id"])
        require(stopped["instance_states"][leader_fault["previous_controller_id"]] == "stopped" and stopped["instance_states"][selection["router_id"]] == "stopped", "real stopped fault actors were not observed")
        require(leader_fault["previous_controller_id"] == selected["router-failover"]["dynamodb"]["lease_holder"] and leader_fault["previous_fence"] == selected["router-failover"]["dynamodb"]["fence_term"], "leader fault did not target observed leadership")
        handoff_state = selected["leader-handoff"]["dynamodb"]
        require(handoff_state["lease_holder"] != leader_fault["previous_controller_id"] and handoff_state["fence_term"] > leader_fault["previous_fence"] and leader_fault["new_fence"] == handoff_state["fence_term"] and leader_fault["new_controller_id"] == handoff_state["lease_holder"], "higher-fence leader handoff absent")
        gate, final = selected["failback-gate"], selected["failback-stable"]
        require(gate["dynamodb"]["stable_owner"] == selection["alternate_router_id"] and gate["tailnet"]["owner_router_id"] == selection["router_id"] and all(r["target_router_id"] == selection["alternate_router_id"] for r in gate["aws_routes"]), "failback gate did not retain alternate routes")
        require(final["dynamodb"]["stable_owner"] == selection["router_id"] and timestamp(final["captured_at"]) >= timestamp(gate["dynamodb"]["cooldown_until"]) and (timestamp(final["captured_at"]) - timestamp(gate["dynamodb"]["owner_observed_at"])).total_seconds() >= h["controller"]["policy_seconds"]["failback_stability"], "failback stability/cooldown was bypassed")
        require({(f["stage"], f["protocol"]) for f in e["fresh_flows"]} == {(s, p) for s in ("router-failover", "failback-stable") for p in ("tcp", "udp")} and len(e["fresh_flows"]) == 4 and all(f["success"] is True and f["responder_acknowledged"] is True for f in e["fresh_flows"]), "fresh TCP/UDP recovery incomplete")
        require(len(e["established_flows"]) == 2 and {f["protocol"] for f in e["established_flows"]} == {"tcp", "udp"}, "established outcomes missing")
        require(e["restoration"]["actors"] == {a["actor_id"]: "running" for a in h["actors"] if a["actor_type"] in {"router", "controller"}}, "fault recovery did not cover all owned actors")
        for flow in e["fresh_flows"]:
            require(flow["convergence_at"] == selected[flow["stage"]]["captured_at"] and timestamp(flow["started_at"]) >= timestamp(flow["convergence_at"]) and timestamp(flow["completed_at"]) <= timestamp(e["completed_at"]), "fresh flow was not observed after authoritative convergence")
            require(flow["event_at"] == (router_fault["injected_at"] if flow["stage"] == "router-failover" else router_fault["restored_at"]), "flow recovery clock differs from its real fault")
        for flow in e["established_flows"]:
            require(flow["fault_injected_at"] == router_fault["injected_at"] and flow["convergence_at"] == selected["router-failover"]["captured_at"] and timestamp(e["started_at"]) <= timestamp(flow["sampled_at"]) < timestamp(router_fault["injected_at"]) and timestamp(flow["classified_at"]) <= timestamp(e["completed_at"]), "established outcome timing differs from live fault")
    require(not legacy.scan_evidence(e), "evidence contains credential material")
    return copy.deepcopy(e)


def read_json(path: pathlib.Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "input must be a regular non-symlink file")
    return legacy._mapping(legacy.strict_json_loads(path.read_bytes()), "JSON document")
