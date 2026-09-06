"""Measured observer/fault process. It constructs no deployment/runtime tools."""
from __future__ import annotations

import copy
import datetime as dt
import pathlib
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import aws_production_controller_e2e as legacy
import controller_acceptance_contract as contract
from controller_acceptance_io import AWS, Commands, Session, publish_object, verify_claim, verify_phase_identity


class LiveObserver(legacy.AwsProductionAdapter):
    # Only the mature bounded read/fault/workload primitives are reused. The
    # parent constructor (Terraform, Tailnet OAuth, deployment state) is not run.
    def __init__(self, h: dict[str, Any], session: Session, directory: pathlib.Path):
        self.handoff = contract.validate_handoff(h)
        self.session, self.run_dir = session, directory
        self.protected_secrets = session.secrets()
        self.command = Commands(session, directory)
        self.aws = AWS(self.command)
        self.ledger = legacy.MutationLedger(session_deny=True)
        self.runner_identity = {"account_id": session.role_arn.split(":")[4], "principal_arn": session.principal_arn, "session_name": session.principal_arn.rsplit("/", 1)[-1]}
        controller = copy.deepcopy(h["controller"])
        controller["policy"] = copy.deepcopy(h["topology"]["policy"])
        controller["placements"] = {cid: {k: row[k] for k in ("subnet_id", "availability_zone")} for cid, row in controller["instances"].items()}
        self.config = SimpleNamespace(run_id=h["run_id"], controller=SimpleNamespace(**controller))
        self.topology, self.topology_identity = h["topology"], h["topology_identity"]
        self.router_nodes = h["router_nodes"]
        sites = {s["id"]: s for s in self.topology["sites"]}
        routers = tuple({**r, "expected_hostname": next(a["expected_tags"]["Name"] for a in h["actors"] if a["actor_id"] == r["id"])} for r in self.topology["routers"])
        seed = legacy.TopologySeed(h["run_id"], sites, routers, tuple(self.topology["domains"]))
        self.deployment = legacy.ApplianceDeployment({}, contract.digest(h["actors"]), session.role_arn.split(":")[4], "", h["workloads"], seed)
        self.controller_output = {"controller_instances": {"value": controller["instances"]}}
        self.controller_mode = "active"
        self.failed_router_id = self.failed_router_instance = self.router_restoration_phase = None
        self.failed_controller_id = self.failed_controller_instance = self.controller_restoration_phase = None
        self.established_commands: dict[str, tuple[str, str]] = {}
        self.sleep, self.monotonic = time.sleep, time.monotonic
        self.wall_clock = lambda: dt.datetime.now(dt.timezone.utc)
        self.items: dict[str, dict[str, Any]] = {}
        self.fault_journal: list[dict[str, Any]] = []

    def _instance_actors(self, controller_output: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        return [{k: v for k, v in a.items() if k != "expected_tags"} for a in self.handoff["actors"]]

    @staticmethod
    def _http_get(url: str) -> tuple[int, str]:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(urllib.request.Request(url, method="GET"), timeout=5) as response:
                payload = response.read(4 * 1024 * 1024 + 1)
                contract.require(len(payload) <= 4 * 1024 * 1024, "controller response exceeded its bound")
                return response.status, payload.decode("utf-8")
        except urllib.error.HTTPError as error:
            return error.code, error.read(4096).decode("utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return 0, "unavailable"

    def _expected_instance_actor(self, instance_id: str, region: str) -> dict[str, Any]:
        matches = [a for a in self.handoff["actors"] if a["instance_id"] == instance_id and a["region"] == region]
        contract.require(len(matches) == 1, "fault target is outside exact handoff ownership")
        return copy.deepcopy(matches[0])

    def _dynamo_item(self, partition: str, sort_key: str) -> dict[str, Any] | None:
        import json
        response = self.aws.json(["dynamodb", "get-item", "--table-name", self.topology["dynamodb"]["table"], "--consistent-read", "--key", json.dumps({"pk": {"S": partition}, "sk": {"S": sort_key}}, separators=(",", ":"))], region=self.config.controller.region)
        item = response.get("Item")
        if not item:
            return None
        contract.require(item.get("pk") == {"S": partition} and item.get("sk") == {"S": sort_key}, "DynamoDB read returned another key")
        payload = legacy._mapping(legacy.strict_json_loads(item.get("payload", {}).get("S", "")), "durable payload")
        require_hash = self.topology_identity["canonical_sha256"]
        contract.require(item.get("topology_hash") == {"S": require_hash}, "durable metadata topology mismatch")
        if partition.startswith("observations#"):
            cid = sort_key.removeprefix("controller#")
            contract.require(payload.get("controller_id") == cid and payload.get("topology_hash") == require_hash and item.get("controller_id") == {"S": cid} and item.get("sequence") == {"N": str(payload.get("sequence"))}, "observation publisher metadata mismatch")
            contract.require(contract.timestamp(payload["captured_at"]) <= self.wall_clock(), "future observer publication")
        else:
            contract.require(item.get("record_type") == {"S": "domain"} and item.get("document_revision") == {"N": str(payload.get("revision"))} and item.get("fence_term") == {"N": str(payload.get("fence_term"))}, "journal metadata differs from payload")
            contract.require(isinstance(payload.get("activated"), bool), "activation state missing")
            lease = payload.get("lease")
            if lease is not None:
                contract.require(item.get("lease_holder") == {"S": lease.get("holder_id")} and item.get("lease_record_version") == {"N": str(lease.get("record_version"))}, "lease metadata differs from payload")
            self.items[sort_key.removeprefix("domain#")] = {"payload": payload, "hash": contract.digest(item)}
        return payload

    def snapshot(self, stage: str) -> list[dict[str, Any]]:
        endpoints = self._controller_endpoint_snapshots()
        states = {}
        for a in self.handoff["actors"]:
            if a["actor_type"] in {"controller", "router"}:
                _, states[a["actor_id"]] = self._describe_instance_actor(a["instance_id"], a["region"])
        by_eni = {r["eni_id"]: r["id"] for r in self.topology["routers"]}
        result = []
        for domain in self.deployment.seed.domains:
            did = domain["id"]
            table, routes = self._observe_route_table(domain, by_eni)
            payload = self._dynamo_item(f"deployment#{self.config.run_id}", f"domain#{did}")
            durable = self._durable_evidence(payload, domain, by_eni)
            consensus = self._tailnet_consensus(did)
            actors = []
            for cid in self.config.controller.controller_ids:
                endpoint = endpoints[cid]
                metrics = endpoint["metrics"]
                mode = self._active_metric_label(metrics, "envelope_controller_domain_mode", did, "mode")
                role = self._active_metric_label(metrics, "envelope_controller_domain_role", did, "role")
                phase = self._active_metric_label(metrics, "envelope_controller_domain_phase", did, "phase")
                fences = [v for labels, v in self._prometheus_labels(metrics, "envelope_controller_lease_fence_term") if labels.get("domain") == did]
                actors.append({"controller_id": cid, **{k: endpoint[k] for k in ("instance_id", "private_ip", "health_status", "ready_status", "ready_reason", "metrics_sha256")}, "mode": mode, "role": role, "phase": phase, "fence_term": int(fences[0]) if len(fences) == 1 else 0})
            owner = durable["stable_owner"]
            observation = {"stage": stage, "captured_at": legacy.utc_now(), "domain_id": did, "preferred_owner": domain["preferred_owner"], "dynamodb": durable, "controller_endpoints": actors, "tailnet": {**consensus, "failed_router_online": None}, "aws_route_table": table, "aws_routes": routes, "route_agreement": owner is not None and consensus["owner_router_id"] == owner and all(r["target_router_id"] == owner for r in routes)}
            legacy.validate_observation(observation)
            result.append({"scope": "live", "activated": bool(payload and payload.get("activated") is True), "item_sha256": self.items.get(did, {}).get("hash", contract.digest({})), "instance_states": dict(states), "observation": observation})
        return result

    def wait_live(self, stage: str, context: Mapping[str, Any]) -> list[dict[str, Any]]:
        deadline = self.monotonic() + self.config.controller.timeouts["transition_seconds"]
        while self.monotonic() < deadline:
            values = self.snapshot(stage)
            observations = [v["observation"] for v in values]
            selected = next((v for v in values if v["observation"]["domain_id"] == context.get("domain_id")), None)
            match = False
            if stage == "router-failover" and selected is not None:
                o = selected["observation"]
                match = o["route_agreement"] and o["dynamodb"]["phase"] == "stable" and o["dynamodb"]["stable_owner"] == context["alternate_router_id"] and selected["instance_states"][context["router_id"]] == "stopped"
            else:
                match = self._observation_matches(stage, observations, context)
            if stage == "active-baseline":
                match = match and all(all(e["ready_status"] == 200 for e in v["observation"]["controller_endpoints"]) for v in values)
            if stage == "leader-handoff" and selected is not None:
                match = match and selected["instance_states"][context["leader_fault"]["previous_controller_id"]] == "stopped"
            if match and all(v["activated"] for v in values):
                return values
            self.sleep(min(2, self.config.controller.policy_seconds["observation_interval"]))
        raise contract.Error(f"live stage did not converge: {stage}")

    def _set_fault_restoration_phase(self, kind: str, phase: str) -> None:
        super()._set_fault_restoration_phase(kind, phase)
        self.fault_journal.append({"kind": kind, "phase": phase, "at": legacy.utc_now()})
        path = self.run_dir / f"fault-{len(self.fault_journal):04d}.json"
        legacy.write_private_json(path, {"schema": 1, "run_id": self.handoff["run_id"], "invocation_id": self.handoff["invocation_id"], "events": self.fault_journal})

    def stop_leader(self, selection: Mapping[str, str], observed: Mapping[str, Any]) -> dict[str, Any]:
        durable = observed["dynamodb"]
        contract.require(durable["phase"] == "stable" and durable["transaction"] is None, "live leader fault requires stable production state, not a test barrier")
        cid = durable["lease_holder"]
        current = self._dynamo_item(f"deployment#{self.config.run_id}", f"domain#{selection['domain_id']}")
        contract.require(current is not None and current.get("activated") is True and current.get("phase") == "stable" and current.get("lease", {}).get("holder_id") == cid and current.get("fence_term") == durable["fence_term"] and contract.timestamp(current["lease"]["expires_at"]) > self.wall_clock() + dt.timedelta(seconds=self.config.controller.policy_seconds["api_timeout"]), "leadership changed before fault injection")
        instance = self.handoff["controller"]["instances"][cid]["instance_id"]
        actor = self._validate_instance_actor(instance, self.config.controller.region, "ec2:StopInstances")
        contract.require(actor["actor_type"] == "controller" and actor["actor_id"] == cid, "leader ownership mismatch")
        self.failed_controller_id, self.failed_controller_instance = cid, instance
        self._set_fault_restoration_phase("controller", legacy.EC2_FAULT_STOP_CALL_ARMED)
        at = legacy.utc_now()
        self._instance_fault("stop", instance, self.config.controller.region, validated_actor=actor)
        return {"domain_id": selection["domain_id"], "previous_controller_id": cid, "instance_id": instance, "previous_fence": durable["fence_term"], "new_controller_id": None, "new_fence": 0, "injected_at": at, "restored_at": None, "method": "ec2-stop-instance", "checkpoint_phase": "stable"}


def run_live(observer: LiveObserver, begin_cleanup: Any = lambda: None) -> dict[str, Any]:
    h, session = observer.handoff, observer.session
    verify_phase_identity(observer.aws, session, h, "observe", observer.run_dir)
    session.require_lifetime(3300)
    for a in h["actors"]:
        _, state = observer._describe_instance_actor(a["instance_id"], a["region"])
        contract.require(state == "running", "handoff actor is not running")
    e = {"schema": contract.SCHEMA, "kind": contract.KIND, "run_id": h["run_id"], "invocation_id": h["invocation_id"], "handoff_sha256": contract.digest(h), "status": "failed", "started_at": legacy.utc_now(), "completed_at": legacy.utc_now(), "credential": session.receipt(), "selection": None, "faults": {"router": None, "leader": None}, "observations": [], "fresh_flows": [], "established_flows": [], "mutation_audit": {}, "failure": None, "restoration": {"complete": False, "actors": {}}}
    stage = "baseline"
    handle = None
    try:
        baseline = observer.wait_live("active-baseline", {})
        e["observations"].extend(baseline)
        selection = dict(observer.select_domain([v["observation"] for v in baseline]))
        e["selection"] = selection
        renewal = observer.wait_live("lease-renewal", {**selection, "baseline": [v["observation"] for v in baseline]})
        e["observations"].extend(renewal)
        handle = observer.start_established_flows(selection)
        # An immutable intent survives abrupt observer loss. Quiescence can
        # restore every exact initially-running actor without adopting a claim.
        publish_object(observer.aws, {"schema": 1, "kind": "live-fault-intent", "run_id": h["run_id"], "invocation_id": h["invocation_id"], "handoff_sha256": contract.digest(h), "selection": selection, "actors": h["actors"]}, bucket=h["evidence_store"]["bucket"], key=h["evidence_store"]["prefix"] + "fault-journal.json", region=h["evidence_store"]["region"], directory=observer.run_dir)
        stage = "router-fault"
        verify_claim(observer.aws, h, observer.run_dir)
        injected = legacy.utc_now()
        router_fault = dict(observer.inject_router_failure(selection))
        router_fault["injected_at"] = injected
        e["faults"]["router"] = router_fault
        failover = observer.wait_live("router-failover", selection)
        e["observations"].extend(failover)
        selected_failover = next(v["observation"] for v in failover if v["observation"]["domain_id"] == selection["domain_id"])
        e["fresh_flows"].extend(observer.probe_fresh_flows("router-failover", selection, {"event_at": injected, "convergence_at": selected_failover["captured_at"]}))
        stage = "leader-fault"
        leader_fault = observer.stop_leader(selection, selected_failover)
        e["faults"]["leader"] = leader_fault
        handoff = observer.wait_live("leader-handoff", {**selection, "leader_fault": leader_fault})
        e["observations"].extend(handoff)
        successor = next(v["observation"] for v in handoff if v["observation"]["domain_id"] == selection["domain_id"])
        leader_fault["new_controller_id"], leader_fault["new_fence"] = successor["dynamodb"]["lease_holder"], successor["dynamodb"]["fence_term"]
        e["established_flows"].extend(observer.finish_established_flows(handle, {"fault_injected_at": injected, "convergence_at": selected_failover["captured_at"]}))
        handle = None
        observer.sleep(observer.config.controller.policy_seconds["lease_renew_interval"])
        e["observations"].extend(observer.wait_live("durable-alternate", selection))
        stage = "recovery"
        observer._restore_instance_fault(leader_fault["instance_id"], observer.config.controller.region, "controller")
        leader_fault["restored_at"] = legacy.utc_now()
        restoration = observer.restore_router(router_fault)
        router_fault["restored_at"] = restoration["restored_at"]
        gate = observer.wait_live("failback-gate", {**selection, "restoration": restoration})
        e["observations"].extend(gate)
        final = observer.wait_live("failback-stable", {**selection, "gate": [v["observation"] for v in gate]})
        e["observations"].extend(final)
        selected_final = next(v["observation"] for v in final if v["observation"]["domain_id"] == selection["domain_id"])
        e["fresh_flows"].extend(observer.probe_fresh_flows("failback-stable", selection, {"event_at": restoration["restored_at"], "convergence_at": selected_final["captured_at"]}))
        e["status"] = "passed"
    except BaseException as error:
        e["failure"] = {"stage": stage, "category": type(error).__name__, "message": "live acceptance failed; exact fault intent and claim retained"}
    finally:
        begin_cleanup()
        try:
            observer.restore_faults_for_cleanup()
            states = {}
            for actor in h["actors"]:
                if actor["actor_type"] in {"router", "controller"}:
                    _, states[actor["actor_id"]] = observer._describe_instance_actor(actor["instance_id"], actor["region"])
            contract.require(all(s == "running" for s in states.values()), "fault recovery remains uncertain")
            e["restoration"] = {"complete": True, "actors": states}
        except BaseException:
            e["status"] = "failed"
            e["failure"] = e["failure"] or {"stage": "fault-restoration", "category": "UncertainRestoration", "message": "fault restoration incomplete; quiescence identity required"}
        e["completed_at"] = legacy.utc_now()
        e["mutation_audit"] = observer.ledger.evidence(observer.runner_identity)
        contract.require(not legacy.scan_evidence(e, session.secrets()), "refusing credential-bearing live evidence")
        legacy.write_private_json(observer.run_dir / "live.json", e)
    return contract.validate_live_evidence(e, h)
